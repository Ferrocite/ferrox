//! The native `Psiphon` lane: a signed server list, the SSH/OSSH transport in
//! [`crate::psiphon_ssh`], and the loopback SOCKS edge the proxy dials.

use crate::json::{self, Json};
use crate::psiphon_ssh::{Channel, Proxy, Server, Session};
use crate::socks::{Credential, Destination, Version};
use flate2::read::ZlibDecoder;
use ring::signature;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

const SPONSOR_ID: &str = "FFFFFFFFFFFFFFFF";
const UDPGW_HOST: &str = "127.0.0.1";
const UDPGW_PORT: u16 = 7300;
const UDPGW_FLAG_KEEPALIVE: u8 = 1;
const UDPGW_FLAG_REBIND: u8 = 2;
const UDPGW_FLAG_IPV6: u8 = 8;
const UDPGW_MAX_PAYLOAD: usize = 32_768;
const UDPGW_MAX_MESSAGE: usize = 32_768 + 23;
const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
const RELAY_BUFFER: usize = 32 * 1024;
const MAX_REQUEST: usize = 16 * 1024;
const DIAL_ATTEMPTS: usize = 64;
const DIAL_WORKERS: usize = 10;
const DIAL_TIMEOUT: Duration = Duration::from_secs(12);
const FLOW_STACK: usize = 128 * 1024;

static NO_CREDENTIAL: Credential = Credential {
    user: String::new(),
    pass: String::new(),
};

/// The outbound as a flow sees it: a native tunnel and the loopback SOCKS edge over it.
#[derive(Clone)]
pub(crate) struct PsiphonOut {
    inner: Option<Arc<Inner>>,
    endpoint: SocketAddr,
    credential: Arc<Credential>,
    version: Version,
    loopback: bool,
}

struct Inner {
    settings: Settings,
    entries: Vec<Server>,
    sessions: Mutex<Vec<Arc<Session>>>,
    next_session: AtomicUsize,
    connecting: Mutex<()>,
    session_id: String,
    stopping: AtomicBool,
    endpoint: SocketAddr,
    http_endpoint: Option<SocketAddr>,
    udpgw: Mutex<Option<Arc<UdpGateway>>>,
}

struct Settings {
    state: PathBuf,
    listen: SocketAddr,
    http_listen: Option<u16>,
    region: Option<String>,
    ready: Duration,
    entries: Option<PathBuf>,
    target: Option<String>,
    protocols: Vec<String>,
    initial_protocols: Vec<String>,
    initial_count: usize,
    pool: usize,
    latency: f64,
    establish: Option<Duration>,
    workers: usize,
    stagger: Duration,
    relay_buffer: usize,
    server_lists: Vec<String>,
    server_lists_explicit: bool,
    remote_fetch_disabled: bool,
    server_list_key: String,
    headers: Vec<(String, String)>,
    proxy: Option<Proxy>,
    sponsor: String,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    raw: Option<Json>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for PsiphonOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsiphonOut")
            .field("endpoint", &self.endpoint)
            .field("version", &self.version)
            .field("loopback", &self.loopback)
            .field("connected", &self.inner.is_some())
            .finish()
    }
}

impl PsiphonOut {
    /// Start the native tunnel and its loopback SOCKS edge.
    pub(crate) fn new(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        warn_ignored(settings.raw.as_ref());
        let endpoint = settings.listen;
        let listener = TcpListener::bind(endpoint)
            .map_err(|error| format!("psiphon: listen {endpoint}: {error}"))?;
        let endpoint = listener
            .local_addr()
            .map_err(|error| format!("psiphon: listen address: {error}"))?;
        let entries = load_entries(&settings)?;
        if entries.is_empty() {
            return Err("psiphon: the server list holds no SSH entries".to_owned());
        }
        let http = settings
            .http_listen
            .map(|port| {
                TcpListener::bind(SocketAddr::new(endpoint.ip(), port))
                    .map_err(|error| format!("psiphon: http listen {port}: {error}"))
            })
            .transpose()?;
        let http_endpoint = http
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()
            .map_err(|error| format!("psiphon: http listen address: {error}"))?;
        let inner = Arc::new(Inner {
            session_id: hex(&random::<16>()),
            settings,
            entries,
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint,
            http_endpoint,
            udpgw: Mutex::new(None),
        });
        // The edge binds before a tunnel exists, so a refusal is retried, never a lane that exits.
        let weak = Arc::downgrade(&inner);
        thread::Builder::new()
            .name("psiphon-tunnel".to_owned())
            .spawn(move || warm_tunnel(&weak))
            .map_err(|error| format!("psiphon: tunnel thread: {error}"))?;
        if let Some(http) = http {
            let weak = Arc::downgrade(&inner);
            thread::Builder::new()
                .name("psiphon-http".to_owned())
                .spawn(move || accept_http(http, weak))
                .map_err(|error| format!("psiphon: http listener thread: {error}"))?;
        }
        let credential = Arc::new(Credential {
            user: inner.settings.proxy_user.clone().unwrap_or_default(),
            pass: inner.settings.proxy_pass.clone().unwrap_or_default(),
        });
        let loopback = endpoint.ip().is_loopback();
        let weak = Arc::downgrade(&inner);
        thread::Builder::new()
            .name("psiphon-socks".to_owned())
            .spawn(move || accept_loop(listener, weak))
            .map_err(|error| format!("psiphon: listener thread: {error}"))?;
        Ok(Self {
            inner: Some(inner),
            endpoint,
            credential,
            version: Version::V5,
            loopback,
        })
    }

    /// Validate the settings without opening a socket or downloading a list.
    pub(crate) fn validate(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        warn_ignored(settings.raw.as_ref());
        let endpoint = settings.listen;
        Ok(Self {
            inner: None,
            endpoint,
            credential: Arc::new(Credential {
                user: settings.proxy_user.unwrap_or_default(),
                pass: settings.proxy_pass.unwrap_or_default(),
            }),
            version: Version::V5,
            loopback: endpoint.ip().is_loopback(),
        })
    }

    /// The local SOCKS credential: a loopback edge that names none needs none.
    pub(crate) fn credential(&self) -> &Credential {
        if self.loopback && self.credential.user.is_empty() {
            &NO_CREDENTIAL
        } else {
            &self.credential
        }
    }

    /// The handshake a flow pays: SOCKS4 only where the edge demands nothing and the target fits.
    pub(crate) fn session(&self, target: &Destination<'_>) -> (Version, &Credential) {
        if self.loopback
            && self.credential.user.is_empty()
            && !matches!(target, Destination::V6(..))
        {
            (Version::V4, &NO_CREDENTIAL)
        } else {
            (Version::V5, self.credential())
        }
    }

    #[must_use]
    pub(crate) fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect(wake_address(self.endpoint));
        if let Some(http) = self.http_endpoint {
            let _ = TcpStream::connect(wake_address(http));
        }
        if let Some(gateway) = lock(&self.udpgw).take() {
            gateway.close();
        }
        for session in lock(&self.sessions).drain(..) {
            session.close();
        }
    }
}

/// A listener on the wildcard address is woken through the loopback it also covers.
fn wake_address(endpoint: SocketAddr) -> SocketAddr {
    let ip = match endpoint.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, endpoint.port())
}

impl Inner {
    /// Live sessions, with dead ones retired before any count is read.
    fn live(&self) -> usize {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| !session.is_closed());
        sessions.len()
    }

    /// Spread flows over the pool round-robin, so one tunnel's window is not a global cap.
    fn pick(&self) -> Option<Arc<Session>> {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| !session.is_closed());
        if sessions.is_empty() {
            return None;
        }
        let at = self.next_session.fetch_add(1, Ordering::Relaxed) % sessions.len();
        Some(Arc::clone(&sessions[at]))
    }

    /// Dial and add one tunnel; the caller holds the `connecting` lock.
    fn connect_locked(&self) -> Result<Arc<Session>, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        let entries = &self.entries;
        if entries.is_empty() {
            return Err("psiphon: the server list holds no SSH entries".to_owned());
        }
        let start = usize::from(random::<1>()[0]) % entries.len();
        let deadline = Instant::now() + self.settings.ready;
        let limit = entries.len().min(DIAL_ATTEMPTS);
        let timeout = self.settings.dial_timeout();
        let mut last = String::new();
        let mut offset = 0;
        while offset < limit {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let width = self.settings.workers.min(limit - offset);
            if width == 0 {
                break;
            }
            let batch: Vec<Server> = (0..width)
                .map(|step| entries[(start + offset + step) % entries.len()].clone())
                .collect();
            offset += width;
            let last_delay = self
                .settings
                .stagger
                .saturating_mul(u32::try_from(width - 1).unwrap_or(u32::MAX));
            let stagger = if last_delay.saturating_add(timeout) <= remaining {
                self.settings.stagger
            } else {
                Duration::ZERO
            };
            let budget = if stagger.is_zero() {
                remaining.min(timeout)
            } else {
                last_delay.saturating_add(timeout).min(remaining)
            };
            let session_id = self.session_id.clone();
            let sponsor = self.settings.sponsor.clone();
            let proxy = self.settings.proxy.clone();
            let attempt = move |server: &Server| {
                Session::connect(server, &session_id, &sponsor, timeout, proxy.as_ref())
            };
            match race(batch, attempt, budget, stagger) {
                Ok(session) => {
                    if self.stopping.load(Ordering::Acquire) {
                        session.close();
                        return Err("psiphon: the lane is stopping".to_owned());
                    }
                    let session = Arc::new(session);
                    eprintln!(
                        "psiphon: tunnel up via {} {}",
                        session.server(),
                        session.protocol()
                    );
                    let mut sessions = lock(&self.sessions);
                    sessions.retain(|session| !session.is_closed());
                    if sessions.len() >= self.settings.pool {
                        let at = self.next_session.fetch_add(1, Ordering::Relaxed) % sessions.len();
                        let existing = Arc::clone(&sessions[at]);
                        drop(sessions);
                        session.close();
                        return Ok(existing);
                    }
                    sessions.push(Arc::clone(&session));
                    return Ok(session);
                }
                Err(why) => last = why,
            }
        }
        Err(format!("psiphon: no server accepted the tunnel: {last}"))
    }

    fn udp(&self) -> Result<Arc<UdpGateway>, String> {
        if let Some(gateway) = lock(&self.udpgw).as_ref() {
            if !gateway.is_closed() {
                return Ok(Arc::clone(gateway));
            }
        }
        let channel = self.dial(UDPGW_HOST, UDPGW_PORT)?;
        let mut slot = lock(&self.udpgw);
        if let Some(gateway) = slot.as_ref() {
            if !gateway.is_closed() {
                channel.close();
                return Ok(Arc::clone(gateway));
            }
        }
        let gateway = UdpGateway::start(channel);
        *slot = Some(Arc::clone(&gateway));
        Ok(gateway)
    }

    fn dial(&self, host: &str, port: u16) -> Result<Channel, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        for _ in 0..2 {
            let session = self.ensure()?;
            match session.open(host, port) {
                Ok(channel) => return Ok(channel),
                // A refused target says nothing about the tunnel; a dead one is replaced and retried.
                Err(why) if !session.is_closed() => return Err(why),
                Err(_) => {
                    session.close();
                    lock(&self.sessions).retain(|current| !Arc::ptr_eq(current, &session));
                }
            }
        }
        Err(format!("psiphon: {host}:{port} was not reachable"))
    }

    /// A live tunnel, dialing at most one beside any other caller.
    fn ensure(&self) -> Result<Arc<Session>, String> {
        if let Some(session) = self.pick() {
            return Ok(session);
        }
        let _connecting = lock(&self.connecting);
        if let Some(session) = self.pick() {
            return Ok(session);
        }
        self.connect_locked()
    }

    /// Fill the configured pool one tunnel at a time, stopping on the first refusal.
    fn fill(&self) -> Result<(), String> {
        loop {
            if self.stopping.load(Ordering::Acquire) {
                return Err("psiphon: the lane is stopping".to_owned());
            }
            if self.live() >= self.settings.pool {
                return Ok(());
            }
            let _connecting = lock(&self.connecting);
            if self.live() >= self.settings.pool {
                return Ok(());
            }
            self.connect_locked()?;
        }
    }
}

/// Keep the pool warm beside the edge: a refused dial is a retry, not an exit.
fn warm_tunnel(lane: &Weak<Inner>) {
    let mut logged: Option<Instant> = None;
    loop {
        let Some(inner) = lane.upgrade() else {
            return;
        };
        if inner.stopping.load(Ordering::Acquire) {
            return;
        }
        let outcome = inner.fill();
        drop(inner);
        match outcome {
            Ok(()) => {
                thread::sleep(Duration::from_secs(10));
                continue;
            }
            Err(why) => {
                let now = Instant::now();
                // One line per cycle at most, so an instantly refused list cannot flood the log.
                if logged.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10)) {
                    eprintln!("psiphon: {why}; retrying");
                    logged = Some(now);
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}

#[allow(clippy::needless_pass_by_value)]
fn accept_loop(listener: TcpListener, inner: Weak<Inner>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        let Some(inner) = inner.upgrade() else { break };
        if inner.stopping.load(Ordering::Acquire) {
            break;
        }
        let _ = thread::Builder::new()
            .name("psiphon-flow".to_owned())
            .stack_size(FLOW_STACK)
            .spawn(move || serve(stream, &inner));
    }
}

fn serve(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let Some((version, ask)) = read_request(&mut client, inner) else {
        return;
    };
    match ask {
        Ask::Connect(host, port) => match inner.dial(&host, port) {
            Ok(channel) => {
                trace_flow(&channel);
                if !ask_reply(&mut client, version, Ok(())) {
                    channel.close();
                    return;
                }
                let _ = client.set_read_timeout(None);
                let _ = client.set_write_timeout(None);
                relay(client, channel, inner.settings.relay_buffer);
            }
            Err(why) => {
                eprintln!("psiphon: {why}");
                let _ = ask_reply(&mut client, version, Err(5));
            }
        },
        Ask::Udp => serve_udp(client, inner),
    }
}

enum Ask {
    Connect(String, u16),
    Udp,
}

fn read_request(client: &mut TcpStream, inner: &Inner) -> Option<(Version, Ask)> {
    let mut first = [0u8; 1];
    client.read_exact(&mut first).ok()?;
    match first[0] {
        // SOCKS4 carries no credential exchange, so a credentialed edge refuses it instead of serving it open.
        4 if inner.settings.proxy_user.is_none() => read_v4(client).map(|ask| (Version::V4, ask)),
        4 => {
            let _ = client.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]);
            None
        }
        5 => read_v5(client, inner).map(|ask| (Version::V5, ask)),
        _ => None,
    }
}

fn read_v4(client: &mut TcpStream) -> Option<Ask> {
    let mut head = [0u8; 7];
    client.read_exact(&mut head).ok()?;
    if head[0] != 1 {
        return None;
    }
    let port = u16::from_be_bytes([head[1], head[2]]);
    let address = Ipv4Addr::new(head[3], head[4], head[5], head[6]);
    let mut user = Vec::new();
    read_nul(client, &mut user)?;
    let host = if address.octets()[..3] == [0, 0, 0] && address.octets()[3] != 0 {
        let mut name = Vec::new();
        read_nul(client, &mut name)?;
        String::from_utf8(name).ok()?
    } else {
        address.to_string()
    };
    Some(Ask::Connect(host, port))
}

fn read_v5(client: &mut TcpStream, inner: &Inner) -> Option<Ask> {
    let mut count = [0u8; 1];
    client.read_exact(&mut count).ok()?;
    let mut methods = vec![0u8; usize::from(count[0])];
    client.read_exact(&mut methods).ok()?;
    let auth = inner.settings.proxy_user.is_some();
    if auth {
        if !methods.contains(&2) {
            client.write_all(&[5, 0xff]).ok()?;
            return None;
        }
        client.write_all(&[5, 2]).ok()?;
        read_auth(client, inner)?;
    } else {
        if !methods.contains(&0) {
            client.write_all(&[5, 0xff]).ok()?;
            return None;
        }
        client.write_all(&[5, 0]).ok()?;
    }

    let mut request = [0u8; 4];
    client.read_exact(&mut request).ok()?;
    if request[0] != 5 {
        return None;
    }
    let host = match request[3] {
        1 => {
            let mut address = [0u8; 4];
            client.read_exact(&mut address).ok()?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name).ok()?;
            String::from_utf8(name).ok()?
        }
        4 => {
            let mut address = [0u8; 16];
            client.read_exact(&mut address).ok()?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).ok()?;
    let port = u16::from_be_bytes(port);
    match request[1] {
        1 => Some(Ask::Connect(host, port)),
        3 => Some(Ask::Udp),
        _ => None,
    }
}

fn read_auth(client: &mut TcpStream, inner: &Inner) -> Option<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).ok()?;
    if head[0] != 1 {
        return None;
    }
    let mut user = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut user).ok()?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).ok()?;
    let mut pass = vec![0u8; usize::from(plen[0])];
    client.read_exact(&mut pass).ok()?;
    let expected_user = inner
        .settings
        .proxy_user
        .as_deref()
        .unwrap_or("")
        .as_bytes();
    let expected_pass = inner
        .settings
        .proxy_pass
        .as_deref()
        .unwrap_or("")
        .as_bytes();
    let user_ok = constant_time_eq(&user, expected_user);
    let pass_ok = constant_time_eq(&pass, expected_pass);
    if user_ok && pass_ok {
        client.write_all(&[1, 0]).ok()?;
        Some(())
    } else {
        client.write_all(&[1, 1]).ok()?;
        None
    }
}

fn read_nul(client: &mut TcpStream, out: &mut Vec<u8>) -> Option<()> {
    loop {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).ok()?;
        if byte[0] == 0 {
            return Some(());
        }
        if out.len() >= 255 {
            return None;
        }
        out.push(byte[0]);
    }
}

fn ask_reply(client: &mut TcpStream, version: Version, result: Result<(), u8>) -> bool {
    match version {
        Version::V4 => {
            let reply = if result.is_ok() {
                [0, 90, 0, 0, 0, 0, 0, 0]
            } else {
                [0, 91, 0, 0, 0, 0, 0, 0]
            };
            client.write_all(&reply).is_ok()
        }
        Version::V5 => {
            let reply = match result {
                Ok(()) => [5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                Err(code) => [5, code, 0, 1, 0, 0, 0, 0, 0, 0],
            };
            client.write_all(&reply).is_ok()
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn relay(mut client: TcpStream, channel: Channel, buffer: usize) {
    let Ok(mut client_read) = client.try_clone() else {
        channel.close();
        return;
    };
    let mut channel_write = channel.clone();
    let forward = thread::Builder::new()
        .name("psiphon-flow-forward".to_owned())
        .stack_size(FLOW_STACK)
        .spawn(move || {
            pump_out(&mut client_read, &mut channel_write, buffer);
            channel_write.shutdown();
        })
        .ok();
    let mut channel_read = channel.clone();
    pump_channel(&mut channel_read, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    if let Some(forward) = forward {
        let _ = forward.join();
    }
    channel.close();
}

fn trace_flow(channel: &Channel) {
    if std::env::var_os("AETHER_PSIPHON_TRACE_FLOWS").is_some() {
        eprintln!(
            "psiphon: flow via session {} {}",
            channel.session_id(),
            channel.server()
        );
    }
}

/// The download half writes each received packet straight from the SSH buffer,
/// so a relayed byte is copied by the kernel and never staged in userspace.
fn pump_channel(channel: &mut Channel, sink: &mut impl Write) {
    loop {
        match channel.next_chunk() {
            Ok(Some(chunk)) => {
                let wrote = sink.write_all(chunk.data()).is_ok();
                channel.recycle_chunk(chunk);
                if !wrote {
                    return;
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// The client-to-tunnel side encrypts the read buffer in place, so the payload is not copied into a packet.
fn pump_out(source: &mut impl Read, sink: &mut Channel, buffer: usize) {
    let mut buffer = vec![0u8; buffer];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        // A window or a smaller remote packet can take less than the read, so the remainder leaves next packet.
        let mut at = 0;
        while at < read {
            match sink.write_in_place(&mut buffer[at..read]) {
                Ok(0) => return,
                Ok(written) => at += written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn accept_http(listener: TcpListener, inner: Weak<Inner>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        let Some(inner) = inner.upgrade() else { break };
        if inner.stopping.load(Ordering::Acquire) {
            break;
        }
        let _ = thread::Builder::new()
            .name("psiphon-http-flow".to_owned())
            .stack_size(FLOW_STACK)
            .spawn(move || serve_http(stream, &inner));
    }
}

/// `LocalHttpProxyPort` serves CONNECT only: a plain-response request has no tunnel to carry it.
fn serve_http(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let mut head = [0u8; MAX_REQUEST];
    let mut filled = 0;
    while filled < head.len() {
        match client.read(&mut head[filled..]) {
            Ok(0) => return,
            Ok(read) => {
                filled += read;
                if head[..filled]
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
                {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
    let Some(end) = head[..filled]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    else {
        let _ = client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n");
        return;
    };
    let text = String::from_utf8_lossy(&head[..end]);
    // Bytes a client pipelined behind its CONNECT headers are the stream's first bytes.
    let early = &head[end + 4..filled];
    let mut lines = text.split("\r\n");
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("");
    let authority = request.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = client.write_all(
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    // A shared edge names a credential, and the HTTP front answers it the way the SOCKS front does.
    if inner.settings.proxy_user.as_deref().is_some_and(|user| {
        let pass = inner.settings.proxy_pass.as_deref().unwrap_or("");
        !http_authorized(&text, user, pass)
    }) {
        let _ = client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"psiphon\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|bare| bare.strip_suffix(']'))
        .unwrap_or(host);
    let Ok(port) = port.parse::<u16>() else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    match inner.dial(host, port) {
        Ok(mut channel) => {
            trace_flow(&channel);
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
                || (!early.is_empty() && channel.write_all(early).is_err())
            {
                channel.close();
                return;
            }
            let _ = client.set_read_timeout(None);
            let _ = client.set_write_timeout(None);
            relay(client, channel, inner.settings.relay_buffer);
        }
        Err(why) => {
            eprintln!("psiphon: {why}");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        }
    }
}

/// No early exit, so the compare's time follows the length and not the first differing byte.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

/// A `Proxy-Authorization: Basic` header carries the same `user:pass` the SOCKS front takes.
fn http_authorized(head: &str, user: &str, pass: &str) -> bool {
    let mut expected = Vec::with_capacity(user.len() + pass.len() + 1);
    expected.extend_from_slice(user.as_bytes());
    expected.push(b':');
    expected.extend_from_slice(pass.as_bytes());
    let expected = ferrox_core::b64::encode(&expected);
    head.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
                return false;
            }
            let Some((scheme, token)) = value.trim().split_once(' ') else {
                return false;
            };
            scheme.eq_ignore_ascii_case("basic")
                && constant_time_eq(token.trim().as_bytes(), expected.as_bytes())
        })
    })
}

impl Settings {
    #[allow(clippy::too_many_lines)]
    fn from_json(settings: Option<&Json>) -> Result<Self, String> {
        let raw = settings.cloned();
        let listen = listen_address(settings)?;
        let region = match text(settings, "region")
            .or_else(|| text(settings, "egressRegion"))
            .or_else(|| text(settings, "EgressRegion"))
            .or_else(|| env("AETHER_PSIPHON_REGION"))
        {
            Some(code) => Some(ferrox_core::psiphon::region(&code).ok_or_else(|| {
                format!("psiphon: region {code:?} is not a two-letter country code")
            })?),
            None => None,
        };
        if flag(settings, "disableTunnels", "AETHER_PSIPHON_DISABLE_TUNNELS") {
            return Err(
                "psiphon: disableTunnels opens no tunnel, so this lane would carry nothing"
                    .to_owned(),
            );
        }
        let ready = text(settings, "readySeconds")
            .or_else(|| {
                settings
                    .and_then(|settings| settings.get("readySeconds"))
                    .and_then(Json::as_u32)
                    .map(|value| value.to_string())
            })
            .or_else(|| env("AETHER_PSIPHON_READY_SECS"))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map_or(ferrox_core::psiphon::READY_SECS, |value| value.min(86_400));
        let mut server_lists = json_list(settings, "serverListURLs");
        for key in [
            "remoteServerListURLs",
            "RemoteServerListURLs",
            "RemoteServerListUrl",
            "remoteServerListUrl",
            "serverListUrls",
        ] {
            if server_lists.is_empty() {
                server_lists = json_list(settings, key);
            }
        }
        if server_lists.is_empty() {
            server_lists.extend(text(settings, "serverListURL"));
        }
        if server_lists.is_empty() {
            server_lists = env_list("AETHER_PSIPHON_SERVER_LIST");
        }
        let server_lists_explicit = !server_lists.is_empty();
        if server_lists.is_empty() {
            server_lists.push(ferrox_core::psiphon::SERVER_LIST_URL.to_owned());
        }
        let proxy_user = text(settings, "localProxyUsername")
            .or_else(|| text(settings, "shareProxyOnNetworkUsername"))
            .or_else(|| env("AETHER_PSIPHON_PROXY_USER"))
            .filter(|user| !user.is_empty());
        let proxy_pass = text(settings, "localProxyPassword")
            .or_else(|| text(settings, "shareProxyOnNetworkPassword"))
            .or_else(|| env("AETHER_PSIPHON_PROXY_PASS"))
            .filter(|pass| !pass.is_empty());
        if proxy_user.is_some() != proxy_pass.is_some() {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must be named together"
                    .to_owned(),
            );
        }
        if proxy_user.as_ref().is_some_and(|user| user.len() > 255)
            || proxy_pass.as_ref().is_some_and(|pass| pass.len() > 255)
        {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must each be at most 255 bytes"
                    .to_owned(),
            );
        }
        if let Some(selection) = text(settings, "protocolSelection") {
            match selection.to_ascii_lowercase().as_str() {
                "auto" | "direct" => {}
                "cdn_fronting" => eprintln!(
                    "psiphon: protocolSelection cdn_fronting needs fronted-meek; using SSH/OSSH"
                ),
                "conduit" => eprintln!(
                    "psiphon: protocolSelection conduit needs volunteer relays; using SSH/OSSH"
                ),
                other => eprintln!("psiphon: protocolSelection {other:?} is not a known mode"),
            }
        }
        let proxy = text(settings, "upstreamProxy")
            .or_else(|| text(settings, "upstream"))
            .or_else(|| text(settings, "UpstreamProxyURL"))
            .or_else(|| env("AETHER_PSIPHON_UPSTREAM"))
            .map(|url| Proxy::parse(&url))
            .transpose()?;
        let http_listen = if flag(
            settings,
            "DisableLocalHTTPProxy",
            "AETHER_PSIPHON_DISABLE_HTTP_PROXY",
        ) {
            None
        } else {
            port_number(settings, "LocalHttpProxyPort")
                .or_else(|| port_number(settings, "shareProxyOnNetworkHttpPort"))
                .or_else(|| {
                    env("AETHER_PSIPHON_HTTP_PROXY_PORT")
                        .and_then(|value| value.parse::<u16>().ok())
                })
        };
        let target =
            text(settings, "TargetServerEntry").or_else(|| env("AETHER_PSIPHON_TARGET_ENTRY"));
        // The reference pins a targeted entry to one tunnel, and so does this lane.
        let pool = if target.is_some() {
            1
        } else {
            number(settings, "TunnelPoolSize")
                .or_else(|| number(settings, "tunnelPoolSize"))
                .or_else(|| env("AETHER_PSIPHON_TUNNEL_POOL").and_then(|value| value.parse().ok()))
                .unwrap_or(1)
                .clamp(1, 32) as usize
        };
        let latency = decimal(settings, "NetworkLatencyMultiplier")
            .or_else(|| env("AETHER_PSIPHON_LATENCY").and_then(|value| value.parse().ok()))
            .filter(|multiplier| *multiplier >= 1.0)
            .unwrap_or(1.0)
            .min(60.0);
        let establish = number(settings, "EstablishTunnelTimeoutSeconds")
            .map(|seconds| Duration::from_secs(seconds.clamp(1, 600)));
        let initial_protocols = protocol_list_named(settings, "InitialLimitTunnelProtocols");
        let initial_count = number(settings, "InitialLimitTunnelProtocolsCandidateCount")
            .or_else(|| {
                env("AETHER_PSIPHON_INITIAL_PROTOCOL_COUNT").and_then(|value| value.parse().ok())
            })
            .unwrap_or(0) as usize;
        let aggressive = flag(settings, "beastMode", "AETHER_PSIPHON_BEAST")
            || flag(
                settings,
                "AggressiveEstablishment",
                "AETHER_PSIPHON_AGGRESSIVE",
            );
        let workers = number(settings, "ConnectionWorkerPoolSize")
            .or_else(|| env("AETHER_PSIPHON_WORKERS").and_then(|value| value.parse().ok()))
            .unwrap_or(DIAL_WORKERS as u64)
            .clamp(1, 32) as usize;
        let worker_cap = number(settings, "ConnectionWorkerPoolMaxSize")
            .unwrap_or(32)
            .clamp(1, 32) as usize;
        let workers = if target.is_some() {
            1
        } else if aggressive {
            workers.max(30).min(worker_cap)
        } else {
            workers.min(worker_cap)
        };
        let workers = if flag(
            settings,
            "DisableConnectionWorkerPool",
            "AETHER_PSIPHON_DISABLE_WORKERS",
        ) {
            1
        } else {
            workers
        };
        let stagger = Duration::from_millis(
            number(settings, "StaggerConnectionWorkersMilliseconds")
                .or_else(|| env("AETHER_PSIPHON_STAGGER_MS").and_then(|value| value.parse().ok()))
                .unwrap_or(0)
                .min(60_000),
        );
        let relay_buffer = if flag(
            settings,
            "LimitRelayBufferSizes",
            "AETHER_PSIPHON_SMALL_RELAY",
        ) {
            16 * 1024
        } else {
            RELAY_BUFFER
        };
        Ok(Self {
            state: text(settings, "state")
                .or_else(|| text(settings, "dataRootDirectory"))
                .or_else(|| text(settings, "DataRootDirectory"))
                .or_else(|| text(settings, "dataDirectory"))
                .or_else(|| env("AETHER_PSIPHON_DIR"))
                .or_else(|| env("AETHER_PSIPHON_STATE"))
                .map_or_else(default_state, PathBuf::from),
            listen,
            http_listen,
            region,
            ready: Duration::from_secs(ready),
            entries: server_entries(settings),
            target,
            protocols: protocol_list(settings),
            initial_protocols,
            initial_count,
            pool,
            latency,
            establish,
            workers,
            stagger,
            relay_buffer,
            server_lists,
            server_lists_explicit,
            remote_fetch_disabled: flag(
                settings,
                "DisableRemoteServerListFetcher",
                "AETHER_PSIPHON_DISABLE_REMOTE_LIST",
            ),
            server_list_key: text(settings, "serverListSignaturePublicKey")
                .or_else(|| text(settings, "RemoteServerListSignaturePublicKey"))
                .or_else(|| text(settings, "remoteServerListSignaturePublicKey"))
                .or_else(|| env("AETHER_PSIPHON_SERVER_LIST_KEY"))
                .unwrap_or_else(|| ferrox_core::psiphon::SERVER_LIST_SIGNATURE_KEY.to_owned()),
            headers: custom_headers(settings),
            proxy,
            sponsor: text(settings, "sponsorId")
                .or_else(|| text(settings, "SponsorId"))
                .or_else(|| text(settings, "SponsorID"))
                .or_else(|| env("AETHER_PSIPHON_SPONSOR_ID"))
                .unwrap_or_else(|| SPONSOR_ID.to_owned()),
            proxy_user,
            proxy_pass,
            raw,
        })
    }
}

impl Settings {
    /// The reference scales every network budget by `NetworkLatencyMultiplier`.
    fn dial_timeout(&self) -> Duration {
        self.establish
            .unwrap_or(DIAL_TIMEOUT)
            .mul_f64(self.latency)
            .min(Duration::from_secs(600))
    }
}

fn port_number(settings: Option<&Json>, key: &str) -> Option<u16> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_port()
        .or_else(|| value.as_u32().and_then(|port| u16::try_from(port).ok()))
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        .filter(|port| *port > 0)
}

fn number(settings: Option<&Json>, key: &str) -> Option<u64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_u32()
        .map(u64::from)
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

fn decimal(settings: Option<&Json>, key: &str) -> Option<f64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    match value {
        Json::Num(number) => Some(*number),
        Json::Str(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn protocol_list_named(settings: Option<&Json>, key: &str) -> Vec<String> {
    string_list(settings, key)
        .into_iter()
        .map(|protocol| protocol.to_ascii_uppercase())
        .collect()
}

fn protocol_list(settings: Option<&Json>) -> Vec<String> {
    let mut protocols = string_list(settings, "LimitTunnelProtocols");
    if protocols.is_empty() {
        protocols = string_list(settings, "limitTunnelProtocols");
    }
    if protocols.is_empty() {
        if let Some(single) = text(settings, "TunnelProtocol")
            .or_else(|| text(settings, "tunnelProtocol"))
            .or_else(|| text(settings, "tunnelProtocols"))
        {
            protocols = split_list(&single);
        }
    }
    protocols
        .into_iter()
        .map(|protocol| protocol.to_ascii_uppercase())
        .collect()
}

fn string_list(settings: Option<&Json>, key: &str) -> Vec<String> {
    let listed = settings.and_then(|settings| settings.get(key));
    if let Some(items) = listed.and_then(Json::as_arr) {
        return items
            .iter()
            .filter_map(Json::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(text) = listed.and_then(Json::as_str) {
        return split_list(text);
    }
    Vec::new()
}

fn custom_headers(settings: Option<&Json>) -> Vec<(String, String)> {
    let Some(Json::Obj(fields)) = settings.and_then(|settings| {
        settings
            .get("CustomHeaders")
            .or_else(|| settings.get("customHeaders"))
    }) else {
        return Vec::new();
    };
    fields
        .iter()
        .flat_map(|(name, value)| match value {
            Json::Str(text) => vec![(name.clone(), text.clone())],
            Json::Arr(items) => items
                .iter()
                .filter_map(Json::as_str)
                .map(|text| (name.clone(), text.to_owned()))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

fn warn_ignored(settings: Option<&Json>) {
    let Some(Json::Obj(fields)) = settings else {
        return;
    };
    let known = [
        "listen",
        "shareProxyOnNetwork",
        "shareProxyOnNetworkSocksPort",
        "region",
        "egressRegion",
        "readySeconds",
        "serverList",
        "serverEntries",
        "state",
        "dataRootDirectory",
        "dataDirectory",
        "serverListURL",
        "serverListURLs",
        "serverListUrls",
        "remoteServerListURLs",
        "RemoteServerListURLs",
        "RemoteServerListUrl",
        "remoteServerListUrl",
        "serverListSignaturePublicKey",
        "remoteServerListSignaturePublicKey",
        "RemoteServerListSignaturePublicKey",
        "DisableRemoteServerListFetcher",
        "LocalSocksProxyPort",
        "LocalHttpProxyPort",
        "shareProxyOnNetworkHttpPort",
        "DisableLocalHTTPProxy",
        "EgressRegion",
        "DataRootDirectory",
        "SponsorId",
        "SponsorID",
        "sponsorId",
        "localProxyUsername",
        "shareProxyOnNetworkUsername",
        "localProxyPassword",
        "shareProxyOnNetworkPassword",
        "disableTunnels",
        "upstreamProxy",
        "upstream",
        "UpstreamProxyURL",
        "protocolSelection",
        "beastMode",
        "AggressiveEstablishment",
        "TunnelPoolSize",
        "tunnelPoolSize",
        "ConnectionWorkerPoolSize",
        "ConnectionWorkerPoolMaxSize",
        "DisableConnectionWorkerPool",
        "EstablishTunnelTimeoutSeconds",
        "StaggerConnectionWorkersMilliseconds",
        "LimitRelayBufferSizes",
        "NetworkLatencyMultiplier",
        "InitialLimitTunnelProtocols",
        "InitialLimitTunnelProtocolsCandidateCount",
        "LimitTunnelProtocols",
        "limitTunnelProtocols",
        "TunnelProtocol",
        "tunnelProtocol",
        "tunnelProtocols",
        "TargetServerEntry",
        "CustomHeaders",
        "customHeaders",
    ];
    let ignored: Vec<&str> = fields
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, _)| key.as_str())
        .collect();
    if !ignored.is_empty() {
        eprintln!("psiphon: native engine ignores {}", ignored.join(", "));
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var_os(name)
        .and_then(|value| value.into_string().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn text(settings: Option<&Json>, key: &str) -> Option<String> {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn json_list(settings: Option<&Json>, key: &str) -> Vec<String> {
    let listed = settings.and_then(|settings| settings.get(key));
    if let Some(items) = listed.and_then(Json::as_arr) {
        return items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .or_else(|| item.get("URL").and_then(Json::as_str))
                    .or_else(|| item.get("url").and_then(Json::as_str))
            })
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(list_url)
            .collect();
    }
    if let Some(text) = listed.and_then(Json::as_str) {
        return split_list(text)
            .into_iter()
            .map(|url| list_url(&url))
            .collect();
    }
    Vec::new()
}

/// A list entry is a plain URL or, as the reference writes it, the base64 of one.
fn list_url(item: &str) -> String {
    if item.starts_with("http://") || item.starts_with("https://") {
        return item.to_owned();
    }
    ferrox_core::b64::decode(item.as_bytes())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .map_or_else(|| item.to_owned(), |url| url.trim().to_owned())
}

fn env_list(environment: &str) -> Vec<String> {
    env(environment)
        .map(|text| split_list(&text))
        .unwrap_or_default()
}

fn split_list(text: &str) -> Vec<String> {
    text.split([',', ' ', '\t', '\n', '\r', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn flag(settings: Option<&Json>, key: &str, environment: &str) -> bool {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_bool)
        .or_else(|| {
            env(environment).map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
        })
        .unwrap_or(false)
}

fn server_entries(settings: Option<&Json>) -> Option<PathBuf> {
    let path = text(settings, "serverList")
        .or_else(|| text(settings, "serverEntries"))
        .or_else(|| env("AETHER_PSIPHON_SERVER_ENTRIES"))
        .map(PathBuf::from)?;
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("psiphon: server entries {} are not a file", path.display());
        None
    }
}

fn default_state() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(dir).join("ferrox/psiphon");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/state/ferrox/psiphon");
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("ferrox-psiphon-{uid}"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("ferrox-psiphon")
    }
}

fn listen_address(settings: Option<&Json>) -> Result<SocketAddr, String> {
    let share = flag(settings, "shareProxyOnNetwork", "AETHER_PSIPHON_SHARE");
    let text = text(settings, "listen")
        .or_else(|| env("AETHER_PSIPHON_BIND"))
        .or_else(|| {
            text(settings, "shareProxyOnNetworkSocksPort")
                .or_else(|| {
                    settings
                        .and_then(|settings| settings.get("shareProxyOnNetworkSocksPort"))
                        .and_then(Json::as_u32)
                        .map(|port| port.to_string())
                })
                .or_else(|| {
                    settings
                        .and_then(|settings| settings.get("LocalSocksProxyPort"))
                        .and_then(Json::as_u32)
                        .map(|port| port.to_string())
                })
                .map(|port| {
                    let ip = if share { "0.0.0.0" } else { "127.0.0.1" };
                    format!("{ip}:{port}")
                })
        })
        .unwrap_or_else(|| {
            if share {
                format!(
                    "0.0.0.0:{}",
                    ferrox_core::psiphon::DEFAULT_BIND
                        .rsplit_once(':')
                        .map_or("1821", |(_, port)| port)
                )
            } else {
                ferrox_core::psiphon::DEFAULT_BIND.to_owned()
            }
        });
    let address = text
        .parse::<SocketAddr>()
        .map_err(|_| format!("psiphon: listen {text:?} is not an address and a port"))?;
    Ok(if address.port() == 0 {
        SocketAddr::new(address.ip(), free_port(address.ip())?)
    } else {
        address
    })
}

fn free_port(ip: IpAddr) -> Result<u16, String> {
    let socket = TcpListener::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("psiphon: no local port on {ip}: {error}"))?;
    socket
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("psiphon: the local port did not read back: {error}"))
}

fn load_entries(settings: &Settings) -> Result<Vec<Server>, String> {
    if let Some(target) = settings.target.as_deref() {
        let Some(server) = decode_entry(target.trim()) else {
            return Err("psiphon: TargetServerEntry is not a valid server entry".to_owned());
        };
        let (limits, label, filter) = target_protocol_filter(settings);
        if let Some(shape) = filter {
            if !matches_shape(&server, shape) {
                let protocol = if server.obfuscated() { "OSSH" } else { "SSH" };
                return Err(format!(
                    "psiphon: TargetServerEntry is {protocol} but {label} ({}) leaves it out",
                    limits.join(",")
                ));
            }
        }
        return Ok(vec![server]);
    }
    let mut servers = Vec::new();
    let mut seen = HashSet::new();
    if let Some(path) = settings.entries.as_deref() {
        match std::fs::read_to_string(path) {
            Ok(text) => absorb(&text, &mut servers, &mut seen),
            Err(error) => eprintln!("psiphon: server entries {}: {error}", path.display()),
        }
    }
    let fetch_remote =
        !settings.remote_fetch_disabled && (settings.server_lists_explicit || servers.is_empty());
    for url in settings.server_lists.iter().filter(|_| fetch_remote) {
        match fetch_list(url, &settings.server_list_key, &settings.headers) {
            Ok(text) => {
                absorb(&text, &mut servers, &mut seen);
                save_cache(settings, &text);
            }
            Err(why) => eprintln!("psiphon: {why}"),
        }
    }
    if servers.is_empty() && state_is_ours(&settings.state) {
        if let Ok(text) = std::fs::read_to_string(cache_path(settings)) {
            absorb(&text, &mut servers, &mut seen);
        }
    }
    servers = select_protocols(
        servers,
        &settings.protocols,
        &settings.initial_protocols,
        settings.initial_count,
    );
    if let Some(region) = settings.region.as_deref() {
        let regional: Vec<Server> = servers
            .iter()
            .filter(|server| server.region.as_deref() == Some(region))
            .cloned()
            .collect();
        if regional.is_empty() {
            eprintln!("psiphon: no server is in region {region}, using the whole list");
        } else {
            servers = regional;
        }
    }
    if servers.is_empty() {
        return Err("psiphon: no usable server entries".to_owned());
    }
    Ok(servers)
}

/// The shapes a protocol list names; `None` means the list asks for no restriction.
fn shape_filter(protocols: &[String], label: &str) -> Option<(bool, bool)> {
    if protocols.is_empty() {
        return None;
    }
    let mut wants_plain = false;
    let mut wants_obfuscated = false;
    let mut unsupported = Vec::new();
    for protocol in protocols {
        match protocol.as_str() {
            "SSH" | "UNFRONTED-SSH" => wants_plain = true,
            "OSSH" | "UNFRONTED-OSSH" => wants_obfuscated = true,
            other => unsupported.push(other),
        }
    }
    if !unsupported.is_empty() {
        eprintln!("psiphon: {label} ignores {}", unsupported.join(","));
    }
    if !wants_plain && !wants_obfuscated {
        eprintln!("psiphon: {label} names no SSH or OSSH shape; using the whole list");
        return None;
    }
    Some((wants_plain, wants_obfuscated))
}

fn matches_shape(server: &Server, (plain, obfuscated): (bool, bool)) -> bool {
    if server.obfuscated() {
        obfuscated
    } else {
        plain
    }
}

fn target_protocol_filter(settings: &Settings) -> (&[String], &'static str, Option<(bool, bool)>) {
    if settings.initial_count > 0 && !settings.initial_protocols.is_empty() {
        let shape = shape_filter(&settings.initial_protocols, "InitialLimitTunnelProtocols");
        if shape.is_some() {
            return (
                &settings.initial_protocols,
                "InitialLimitTunnelProtocols",
                shape,
            );
        }
    }
    (
        &settings.protocols,
        "LimitTunnelProtocols",
        shape_filter(&settings.protocols, "LimitTunnelProtocols"),
    )
}

/// Plain SSH and unfronted OSSH are the shapes this transport dials; a limit naming neither keeps the full list.
fn select_protocols(
    servers: Vec<Server>,
    protocols: &[String],
    initial_protocols: &[String],
    initial_count: usize,
) -> Vec<Server> {
    let normal = shape_filter(protocols, "LimitTunnelProtocols");
    let initial_active = initial_count > 0 && !initial_protocols.is_empty();
    let initial = shape_filter(initial_protocols, "InitialLimitTunnelProtocols");
    if normal.is_none() && !initial_active {
        return servers;
    }
    let mut selected = Vec::new();
    let mut rest = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        if initial_active
            && selected.len() < initial_count
            && initial.is_some_and(|filter| matches_shape(server, filter))
        {
            selected.push(index);
        } else {
            rest.push(index);
        }
    }
    selected.extend(
        rest.into_iter()
            .filter(|index| normal.is_none_or(|filter| matches_shape(&servers[*index], filter))),
    );
    if selected.is_empty() {
        eprintln!(
            "psiphon: no server matches LimitTunnelProtocols ({}); using the whole list",
            protocols.join(",")
        );
        return servers;
    }
    selected
        .into_iter()
        .map(|index| servers[index].clone())
        .collect()
}

fn cache_path(settings: &Settings) -> PathBuf {
    settings.state.join("server_entries.txt")
}

#[cfg(unix)]
fn state_is_ours(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|meta| {
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0
    })
}

#[cfg(not(unix))]
fn state_is_ours(_: &Path) -> bool {
    true
}

fn save_cache(settings: &Settings, text: &str) {
    let path = cache_path(settings);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if state_is_ours(&settings.state) {
        let _ = std::fs::write(path, text);
    }
}

fn absorb(text: &str, servers: &mut Vec<Server>, seen: &mut HashSet<(IpAddr, u16)>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(server) = decode_entry(line) {
            if seen.insert((server.address, server.port)) {
                servers.push(server);
            }
        }
    }
}

fn decode_entry(line: &str) -> Option<Server> {
    let decoded = hex_decode(line)?;
    let parts: Vec<&[u8]> = decoded.splitn(5, |byte| *byte == b' ').collect();
    if parts.len() != 5 {
        return None;
    }
    let entry = json::parse(&String::from_utf8_lossy(parts[4])).ok()?;
    let host = entry.get("ipAddress").and_then(Json::as_str)?;
    let address = host.parse::<IpAddr>().ok()?;
    let host = host.to_owned();
    let host_key =
        ferrox_core::b64::decode(entry.get("sshHostKey").and_then(Json::as_str)?.as_bytes())?;
    let user = entry
        .get("sshUsername")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let password = entry
        .get("sshPassword")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let obfuscated_port = entry
        .get("sshObfuscatedPort")
        .and_then(Json::as_port)
        .filter(|port| *port > 0);
    let obfuscated_key = entry
        .get("sshObfuscatedKey")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .filter(|key| !key.is_empty());
    let ssh_port = entry
        .get("sshPort")
        .and_then(Json::as_port)
        .filter(|port| *port > 0);
    let (port, obfuscation_key) = match (obfuscated_port, ssh_port) {
        (Some(port), _) if obfuscated_key.is_some() => (port, obfuscated_key),
        (_, Some(port)) => (port, None),
        _ => return None,
    };
    let region = entry
        .get("region")
        .and_then(Json::as_str)
        .map(str::to_owned);
    Some(Server {
        host,
        address,
        port,
        user,
        password,
        host_key,
        obfuscation_key,
        region,
    })
}

fn fetch_list(url: &str, public_key: &str, custom: &[(String, String)]) -> Result<String, String> {
    let endpoint = crate::foxy_account::Endpoint::parse(url, crate::quic::system_roots())
        .ok_or_else(|| format!("psiphon: server list {url} is not https"))?;
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(custom.len() + 1);
    headers.push(("Accept", "*/*"));
    headers.extend(
        custom
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let reply = crate::foxy_account::ask(&endpoint, "GET", &endpoint.url(""), &headers, &[])?;
    if reply.status != 200 {
        return Err(format!("psiphon: server list {url}: HTTP {}", reply.status));
    }
    unpack(&reply.body, public_key)
}

fn unpack(body: &[u8], public_key: &str) -> Result<String, String> {
    let mut decompressed = Vec::new();
    let too_large = ZlibDecoder::new(body)
        .take(MAX_LIST_BYTES + 1)
        .read_to_end(&mut decompressed)
        .is_err()
        || decompressed.len() as u64 > MAX_LIST_BYTES;
    if too_large {
        decompressed = body.to_vec();
    }
    let text = String::from_utf8_lossy(&decompressed);
    let package = json::parse(&text)
        .map_err(|_| "psiphon: server list is not a signed package".to_owned())?;
    let data = package.get("data").and_then(Json::as_str);
    let digest = package
        .get("signingPublicKeyDigest")
        .and_then(Json::as_str)
        .and_then(|value| ferrox_core::b64::decode(value.as_bytes()));
    let signature = package
        .get("signature")
        .and_then(Json::as_str)
        .and_then(|value| ferrox_core::b64::decode(value.as_bytes()));
    let (Some(data), Some(digest), Some(signature)) = (data, digest, signature) else {
        return Err("psiphon: server list package is incomplete".to_owned());
    };
    let expected = Sha256::digest(public_key.as_bytes());
    if digest != expected.as_slice() {
        return Err("psiphon: server list key digest does not match".to_owned());
    }
    let der = ferrox_core::b64::decode(public_key.as_bytes())
        .ok_or_else(|| "psiphon: server list key is not base64".to_owned())?;
    let pkcs1 =
        spki_to_pkcs1(&der).ok_or_else(|| "psiphon: server list key is not RSA".to_owned())?;
    signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pkcs1)
        .verify(data.as_bytes(), &signature)
        .map_err(|_| "psiphon: server list signature is invalid".to_owned())?;
    Ok(data.to_owned())
}

fn spki_to_pkcs1(der: &[u8]) -> Option<Vec<u8>> {
    let (tag, outer, _) = der_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, _, algorithm) = der_tlv(outer)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, bit_string, _) = der_tlv(outer.get(algorithm..)?)?;
    if tag != 0x03 || bit_string.first().copied()? != 0 {
        return None;
    }
    Some(bit_string[1..].to_vec())
}

fn der_tlv(der: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *der.first()?;
    let mut at = 1;
    let first = *der.get(at)?;
    at += 1;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = (length << 8) | usize::from(*der.get(at)?);
            at += 1;
        }
        length
    };
    let end = at.checked_add(length)?;
    Some((tag, der.get(at..end)?, end))
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("psiphon: system entropy");
    bytes
}

/// Dial a batch at once and hand back the first answer inside the budget, so a
/// server that stalls costs its own attempt instead of the batch's.
fn race<T: Send + 'static>(
    batch: Vec<Server>,
    attempt: impl Fn(&Server) -> Result<T, String> + Send + Sync + 'static,
    budget: Duration,
    stagger: Duration,
) -> Result<T, String> {
    let attempt = Arc::new(attempt);
    let done = Arc::new(AtomicBool::new(false));
    let (sender, answers) = std::sync::mpsc::channel();
    for (index, server) in batch.into_iter().enumerate() {
        let sender = sender.clone();
        let attempt = Arc::clone(&attempt);
        let done = Arc::clone(&done);
        let delay = stagger.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
        let _ = thread::Builder::new()
            .name("psiphon-dial".to_owned())
            .spawn(move || {
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                if done.load(Ordering::Acquire) {
                    return;
                }
                let result = attempt(&server);
                if result.is_ok() {
                    done.store(true, Ordering::Release);
                }
                let _ = sender.send(result);
            });
    }
    drop(sender);
    let deadline = Instant::now() + budget;
    let mut last = String::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match answers.recv_timeout(left) {
            Ok(Ok(value)) => {
                done.store(true, Ordering::Release);
                return Ok(value);
            }
            Ok(Err(why)) => last = why,
            Err(_) => break,
        }
    }
    done.store(true, Ordering::Release);
    if last.is_empty() {
        "no server answered inside the attempt budget".clone_into(&mut last);
    }
    Err(last)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

const fn hex_table() -> [u8; 256] {
    let mut table = [0xff; 256];
    let mut digit = 0;
    while digit < 10 {
        table[b'0' as usize + digit] = digit as u8;
        digit += 1;
    }
    let mut letter = 0;
    while letter < 6 {
        table[b'a' as usize + letter] = 10 + letter as u8;
        table[b'A' as usize + letter] = 10 + letter as u8;
        letter += 1;
    }
    table
}

static HEX: [u8; 256] = hex_table();

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().as_chunks::<2>().0 {
        let high = HEX[usize::from(pair[0])];
        let low = HEX[usize::from(pair[1])];
        if high | low == 0xff {
            return None;
        }
        out.push((high << 4) | low);
    }
    Some(out)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

type UdpFlows = Arc<Mutex<HashMap<(IpAddr, u16), Arc<UdpFlow>>>>;

struct UdpGateway {
    writer: Mutex<Channel>,
    frame: Mutex<Vec<u8>>,
    flows: Mutex<HashMap<u16, Weak<UdpFlow>>>,
    next_id: AtomicU16,
    closed: AtomicBool,
}

struct UdpFlow {
    gateway: Arc<UdpGateway>,
    id: u16,
    ip: IpAddr,
    port: u16,
    packets: Mutex<VecDeque<Vec<u8>>>,
    ready: Condvar,
    closed: AtomicBool,
    first_write: AtomicBool,
}

impl UdpGateway {
    fn start(channel: Channel) -> Arc<Self> {
        let gateway = Arc::new(Self {
            writer: Mutex::new(channel.clone()),
            frame: Mutex::new(Vec::with_capacity(UDPGW_MAX_MESSAGE + 2)),
            flows: Mutex::new(HashMap::new()),
            next_id: AtomicU16::new(0),
            closed: AtomicBool::new(false),
        });
        let reader = Arc::clone(&gateway);
        let _ = thread::Builder::new()
            .name("psiphon-udpgw".to_owned())
            .spawn(move || udpgw_reader(reader, channel));
        gateway
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let flows: Vec<Arc<UdpFlow>> = lock(&self.flows)
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for flow in flows {
            flow.close();
        }
        lock(&self.writer).close();
    }

    fn open_flow(self: &Arc<Self>, ip: IpAddr, port: u16) -> Result<Arc<UdpFlow>, String> {
        if self.is_closed() {
            return Err("psiphon: udpgw channel is closed".to_owned());
        }
        let mut flows = lock(&self.flows);
        flows.retain(|_, flow| flow.strong_count() > 0);
        let mut id = self.next_id.load(Ordering::Relaxed);
        let mut found = None;
        for _ in 0..=u16::MAX {
            if !flows.contains_key(&id) {
                found = Some(id);
                break;
            }
            id = id.wrapping_add(1);
        }
        let Some(id) = found else {
            return Err("psiphon: udpgw has no free flow id".to_owned());
        };
        self.next_id.store(id.wrapping_add(1), Ordering::Relaxed);
        let flow = Arc::new(UdpFlow {
            gateway: Arc::clone(self),
            id,
            ip,
            port,
            packets: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
            first_write: AtomicBool::new(true),
        });
        flows.insert(id, Arc::downgrade(&flow));
        Ok(flow)
    }

    fn send(
        &self,
        id: u16,
        ip: IpAddr,
        port: u16,
        payload: &[u8],
        rebind: bool,
    ) -> Result<(), String> {
        if self.is_closed() {
            return Err("psiphon: udpgw channel is closed".to_owned());
        }
        if payload.len() > UDPGW_MAX_PAYLOAD {
            return Err("psiphon: udpgw payload is too large".to_owned());
        }
        let mut frame = lock(&self.frame);
        udpgw_frame_into(&mut frame, id, ip, port, payload, rebind);
        lock(&self.writer)
            .write_all(&frame)
            .map_err(|error| format!("psiphon: udpgw write: {error}"))
    }
}

impl UdpFlow {
    fn send(&self, payload: &[u8]) -> Result<(), String> {
        if self.closed.load(Ordering::Acquire) {
            return Err("psiphon: udpgw flow is closed".to_owned());
        }
        let rebind = self.first_write.swap(false, Ordering::AcqRel);
        self.gateway
            .send(self.id, self.ip, self.port, payload, rebind)
    }

    fn push(&self, packet: Vec<u8>) {
        let mut packets = lock(&self.packets);
        if packets.len() < 64 {
            packets.push_back(packet);
            self.ready.notify_one();
        }
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut packets = lock(&self.packets);
        loop {
            if let Some(packet) = packets.pop_front() {
                return Some(packet);
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            packets = self
                .ready
                .wait(packets)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }
}

fn udpgw_frame_into(
    frame: &mut Vec<u8>,
    id: u16,
    ip: IpAddr,
    port: u16,
    payload: &[u8],
    rebind: bool,
) {
    let address_len = match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    };
    let size = (5 + address_len + payload.len()) as u16;
    frame.clear();
    frame.extend_from_slice(&size.to_le_bytes());
    let mut flags = if rebind { UDPGW_FLAG_REBIND } else { 0 };
    if ip.is_ipv6() {
        flags |= UDPGW_FLAG_IPV6;
    }
    frame.push(flags);
    frame.extend_from_slice(&id.to_le_bytes());
    match ip {
        IpAddr::V4(address) => frame.extend_from_slice(&address.octets()),
        IpAddr::V6(address) => frame.extend_from_slice(&address.octets()),
    }
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(payload);
}

#[allow(clippy::needless_pass_by_value)]
fn udpgw_reader(gateway: Arc<UdpGateway>, mut channel: Channel) {
    let mut body = vec![0u8; UDPGW_MAX_MESSAGE];
    loop {
        let mut size = [0u8; 2];
        if channel.read_exact(&mut size).is_err() {
            break;
        }
        let size = usize::from(u16::from_le_bytes(size));
        if !(3..=UDPGW_MAX_MESSAGE).contains(&size) {
            break;
        }
        if channel.read_exact(&mut body[..size]).is_err() {
            break;
        }
        let flags = body[0];
        let id = u16::from_le_bytes([body[1], body[2]]);
        if flags & UDPGW_FLAG_KEEPALIVE != 0 {
            continue;
        }
        let (ip, port, start) = if flags & UDPGW_FLAG_IPV6 != 0 {
            if size < 21 {
                break;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[3..19]);
            (
                IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                u16::from_be_bytes([body[19], body[20]]),
                21,
            )
        } else {
            if size < 9 {
                break;
            }
            let octets = [body[3], body[4], body[5], body[6]];
            (
                IpAddr::V4(Ipv4Addr::from(octets)),
                u16::from_be_bytes([body[7], body[8]]),
                9,
            )
        };
        let flow = lock(&gateway.flows).get(&id).and_then(Weak::upgrade);
        if let Some(flow) = flow {
            if flow.ip == ip && flow.port == port {
                flow.push(body[start..size].to_vec());
            }
        }
    }
    gateway.close();
}

fn serve_udp(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let Ok(local) = client.local_addr() else {
        return;
    };
    let Ok(client_ip) = client.peer_addr().map(|peer| peer.ip()) else {
        return;
    };
    let Ok(relay) = UdpSocket::bind(SocketAddr::new(local.ip(), 0)) else {
        let _ = ask_reply(&mut client, Version::V5, Err(1));
        return;
    };
    let Ok(relay_address) = relay.local_addr() else {
        return;
    };
    let Ok(gateway) = inner.udp() else {
        let _ = ask_reply(&mut client, Version::V5, Err(1));
        return;
    };
    if !ask_reply_bound(&mut client, relay_address) {
        return;
    }
    let _ = client.set_read_timeout(None);
    let relay = Arc::new(relay);
    let source = Arc::new(Mutex::new(None));
    let flows: UdpFlows = Arc::new(Mutex::new(HashMap::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let request_relay = Arc::clone(&relay);
    let request_source = Arc::clone(&source);
    let request_flows = Arc::clone(&flows);
    let request_stop = Arc::clone(&stop);
    let request_gateway = Arc::clone(&gateway);
    let _ = thread::Builder::new()
        .name("psiphon-udp".to_owned())
        .spawn(move || {
            udp_requests(
                &request_relay,
                &request_gateway,
                &request_flows,
                &request_source,
                &request_stop,
                client_ip,
            );
        });
    let mut control = [0u8; 32];
    while matches!(client.read(&mut control), Ok(read) if read > 0) {}
    stop.store(true, Ordering::Release);
    for flow in lock(&flows).values() {
        flow.close();
    }
}

fn udp_requests(
    relay: &Arc<UdpSocket>,
    gateway: &Arc<UdpGateway>,
    flows: &UdpFlows,
    source: &Arc<Mutex<Option<SocketAddr>>>,
    stop: &AtomicBool,
    client_ip: IpAddr,
) {
    let _ = relay.set_read_timeout(Some(Duration::from_secs(1)));
    let mut buffer = vec![0u8; 65_535];
    while !stop.load(Ordering::Acquire) {
        let (read, peer) = match relay.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        if peer.ip() != client_ip {
            continue;
        }
        {
            let mut source = lock(source);
            match *source {
                None => *source = Some(peer),
                Some(expected) if expected == peer => {}
                Some(_) => continue,
            }
        }
        let Some((target, payload)) = parse_udp_frame(&buffer[..read]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        let (ip, port) = (target.ip(), target.port());
        let flow = {
            let mut flows = lock(flows);
            if let Some(flow) = flows.get(&(ip, port)) {
                Arc::clone(flow)
            } else {
                let Ok(flow) = gateway.open_flow(ip, port) else {
                    continue;
                };
                flows.insert((ip, port), Arc::clone(&flow));
                spawn_udp_reader(Arc::clone(relay), Arc::clone(source), Arc::clone(&flow));
                flow
            }
        };
        let _ = flow.send(payload);
    }
}

fn spawn_udp_reader(
    relay: Arc<UdpSocket>,
    source: Arc<Mutex<Option<SocketAddr>>>,
    flow: Arc<UdpFlow>,
) {
    let _ = thread::Builder::new()
        .name("psiphon-udp-flow".to_owned())
        .spawn(move || {
            let mut frame = Vec::with_capacity(4 + 16 + 2 + UDPGW_MAX_PAYLOAD);
            while let Some(packet) = flow.recv() {
                let Some(peer) = *lock(&source) else {
                    continue;
                };
                socks_udp_frame_into(&mut frame, flow.ip, flow.port, &packet);
                if relay.send_to(&frame, peer).is_err() {
                    break;
                }
            }
        });
}

fn parse_udp_frame(frame: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if frame.len() < 4 || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 {
        return None;
    }
    let mut at = 4;
    let target = match frame[3] {
        1 => {
            let address = frame.get(at..at + 4)?;
            at += 4;
            let port = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
            at += 2;
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    address[0], address[1], address[2], address[3],
                )),
                port,
            )
        }
        4 => {
            let address = frame.get(at..at + 16)?;
            at += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(address);
            let port = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
            at += 2;
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
        }
        // Any other target, including a SOCKS name, is dropped: a local lookup would send the name in cleartext outside the tunnel, and udpgw carries an address, not a name.
        _ => return None,
    };
    Some((target, frame.get(at..)?))
}

fn socks_udp_frame_into(frame: &mut Vec<u8>, ip: IpAddr, port: u16, payload: &[u8]) {
    frame.clear();
    frame.extend_from_slice(&[0, 0, 0]);
    match ip {
        IpAddr::V4(address) => {
            frame.push(1);
            frame.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            frame.push(4);
            frame.extend_from_slice(&address.octets());
        }
    }
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(payload);
}

fn ask_reply_bound(client: &mut TcpStream, relay: SocketAddr) -> bool {
    let mut reply = vec![5, 0, 0];
    match relay.ip() {
        IpAddr::V4(address) => {
            reply.push(1);
            reply.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            reply.push(4);
            reply.extend_from_slice(&address.octets());
        }
    }
    reply.extend_from_slice(&relay.port().to_be_bytes());
    client.write_all(&reply).is_ok()
}

/// The first outbound is `psiphon`, built and started. A config that names another protocol answers `None`.
pub(crate) fn psiphon_outbound(root: &Json, test: bool) -> Result<Option<PsiphonOut>, String> {
    let Some(outbound) = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .and_then(|outbounds| outbounds.first())
    else {
        return Ok(None);
    };
    if outbound.get("protocol").and_then(Json::as_str) != Some("psiphon") {
        return Ok(None);
    }
    let settings = outbound.get("settings");
    if test {
        PsiphonOut::validate(settings).map(Some)
    } else {
        PsiphonOut::new(settings).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_five_fields_with_json_last() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshUsername":"u","sshPassword":"p","sshHostKey":"AAAA","region":"US"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(server.host, "192.0.2.1");
        assert_eq!(server.port, 22);
        assert_eq!(server.region.as_deref(), Some("US"));
    }

    #[test]
    fn custom_headers_accept_a_string_and_an_array() {
        let settings =
            json::parse(r#"{"CustomHeaders":{"X-One":"a","X-Two":["b","c"]}}"#).expect("settings");
        let headers = custom_headers(Some(&settings));
        let got: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(got, [("X-One", "a"), ("X-Two", "b"), ("X-Two", "c")]);
    }

    #[test]
    fn an_obfuscated_port_wins_when_it_has_a_key() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(server.port, 443);
        assert!(server.obfuscated());
    }

    fn test_server(obfuscated: bool) -> Server {
        Server {
            host: "192.0.2.1".to_owned(),
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 22,
            user: String::new(),
            password: String::new(),
            host_key: Vec::new(),
            obfuscation_key: obfuscated.then(|| "k".to_owned()),
            region: None,
        }
    }

    #[test]
    fn a_protocol_limit_keeps_only_the_named_ssh_shape() {
        let servers = || vec![test_server(false), test_server(true)];
        let shapes = |selected: Vec<Server>| {
            selected
                .into_iter()
                .map(|server| server.obfuscated())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            shapes(select_protocols(servers(), &["SSH".to_owned()], &[], 0)),
            [false]
        );
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["UNFRONTED-OSSH".to_owned()],
                &[],
                0
            )),
            [true]
        );
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned(), "OSSH".to_owned()],
                &[],
                0
            )),
            [false, true]
        );
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["TLS-OSSH".to_owned()],
                &[],
                0
            )),
            [false, true]
        );
    }

    #[test]
    fn an_initial_protocol_limit_applies_to_its_first_candidates() {
        let servers = || {
            vec![
                test_server(false),
                test_server(true),
                test_server(false),
                test_server(true),
            ]
        };
        let shapes = |selected: Vec<Server>| {
            selected
                .into_iter()
                .map(|server| server.obfuscated())
                .collect::<Vec<_>>()
        };
        // The first two OSSH candidates lead; the normal limit keeps every plain entry after them.
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned()],
                &["OSSH".to_owned()],
                2
            )),
            [true, true, false, false]
        );
        // An entry the initial phase skips is not lost while it matches the normal limit.
        let servers = || vec![test_server(false), test_server(true), test_server(false)];
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned()],
                &["OSSH".to_owned()],
                1
            )),
            [true, false, false]
        );
        // No initial phase leaves the normal limit in force from the first entry.
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned()],
                &["OSSH".to_owned()],
                0
            )),
            [false, false]
        );
    }

    #[test]
    fn a_target_entry_still_honors_the_protocol_limit() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshHostKey":"AAAA"}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = |protocol| {
            let text = format!(
                r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["{protocol}"]}}"#
            );
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings")
        };
        assert!(load_entries(&settings("OSSH")).is_err());
        let selected = load_entries(&settings("SSH")).expect("plain SSH is named");
        assert_eq!(selected.len(), 1);
        assert!(!selected[0].obfuscated());
    }

    #[test]
    fn a_target_uses_the_initial_limit_only_when_it_names_a_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = |initial| {
            let text = format!(
                r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["SSH"],"InitialLimitTunnelProtocols":["{initial}"],"InitialLimitTunnelProtocolsCandidateCount":1}}"#
            );
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings")
        };
        assert!(
            load_entries(&settings("TLS-OSSH")).is_err(),
            "an unsupported initial list must fall back to the normal limit"
        );
        let selected = load_entries(&settings("OSSH")).expect("the initial list names OSSH");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].obfuscated());
    }

    #[test]
    fn a_protocol_limit_is_not_read_as_base64() {
        let settings =
            json::parse(r#"{"LimitTunnelProtocols":["AAAA","ossh"]}"#).expect("settings");
        assert_eq!(protocol_list(Some(&settings)), ["AAAA", "OSSH"]);
    }

    #[test]
    fn a_tunnel_pool_is_read_and_clamped_to_the_reference_ceiling() {
        let settings = json::parse(r#"{"TunnelPoolSize":99}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings)).expect("settings").pool,
            32
        );
        let settings = json::parse(r#"{"TunnelPoolSize":0}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings)).expect("settings").pool,
            1
        );
    }

    #[test]
    fn a_targeted_entry_pins_the_pool_to_one_tunnel() {
        let settings = json::parse(
            r#"{"TunnelPoolSize":8,"ConnectionWorkerPoolSize":8,"TargetServerEntry":"entry"}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.pool, 1);
        assert_eq!(settings.workers, 1);
    }

    #[test]
    fn a_limited_relay_buffer_and_stagger_are_read() {
        let settings = json::parse(
            r#"{"LimitRelayBufferSizes":true,"StaggerConnectionWorkersMilliseconds":250}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.relay_buffer, 16 * 1024);
        assert_eq!(settings.stagger, Duration::from_millis(250));
    }

    #[test]
    fn aggressive_establishment_widens_the_race() {
        let settings = json::parse(r#"{"AggressiveEstablishment":true}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .workers,
            30
        );
        let settings = json::parse(r#"{"ConnectionWorkerPoolSize":32}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .workers,
            32
        );
        let settings =
            json::parse(r#"{"AggressiveEstablishment":true,"ConnectionWorkerPoolMaxSize":8}"#)
                .expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .workers,
            8
        );
    }

    #[test]
    fn a_latency_multiplier_scales_the_dial_budget() {
        let settings = json::parse(r#"{"NetworkLatencyMultiplier":2}"#).expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.dial_timeout(), DIAL_TIMEOUT * 2);
        let settings = json::parse(r#"{"NetworkLatencyMultiplier":1.5}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .dial_timeout(),
            DIAL_TIMEOUT.mul_f64(1.5)
        );
        let settings = json::parse(r#"{"NetworkLatencyMultiplier":0.5}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .dial_timeout(),
            DIAL_TIMEOUT
        );
        let settings =
            json::parse(r#"{"EstablishTunnelTimeoutSeconds":30,"NetworkLatencyMultiplier":2}"#)
                .expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .dial_timeout(),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn a_shared_lane_listens_on_every_interface() {
        let settings = json::parse(r#"{"shareProxyOnNetwork":true}"#).expect("settings");
        assert_eq!(
            listen_address(Some(&settings)).expect("listen").to_string(),
            "0.0.0.0:1821"
        );
    }

    #[test]
    fn a_lane_whose_servers_refuse_still_binds_its_edge() {
        let entry = r#"{"ipAddress":"127.0.0.1","sshPort":1,"sshUsername":"u","sshPassword":"p","sshHostKey":"AAAA"}"#;
        let settings = json::parse(&format!(
            r#"{{"listen":"127.0.0.1:0","TargetServerEntry":"{}","DisableRemoteServerListFetcher":true}}"#,
            hex(format!("0 0 0 0 {entry}").as_bytes())
        ))
        .expect("settings");
        let lane = PsiphonOut::new(Some(&settings)).expect("a refused dial is not a refused start");
        assert_ne!(lane.endpoint().port(), 0);
        TcpStream::connect(lane.endpoint()).expect("the edge answers before a tunnel exists");
    }

    #[test]
    fn a_socks5_greeting_reads_its_method_count() {
        let settings =
            Settings::from_json(Some(&json::parse("{}").expect("settings"))).expect("settings");
        let inner = Inner {
            session_id: String::new(),
            settings,
            entries: Vec::new(),
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
            http_endpoint: None,
            udpgw: Mutex::new(None),
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().expect("addr");
        let client = thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).expect("connect");
            sock.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            sock.write_all(&[5, 1, 0]).expect("greeting");
            let mut chosen = [0u8; 2];
            sock.read_exact(&mut chosen).expect("method");
            assert_eq!(chosen, [5, 0]);
            sock.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .expect("request");
        });
        let (mut server, _) = listener.accept().expect("accept");
        match read_request(&mut server, &inner) {
            Some((Version::V5, Ask::Connect(host, port))) => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 80);
            }
            _ => panic!("one method then a target is a SOCKS5 connect"),
        }
        client.join().expect("client");
    }

    #[test]
    fn a_credentialed_edge_refuses_socks4() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"localProxyUsername":"user","localProxyPassword":"pass"}"#)
                .expect("settings"),
        ))
        .expect("settings");
        let inner = Inner {
            session_id: String::new(),
            settings,
            entries: Vec::new(),
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
            http_endpoint: None,
            udpgw: Mutex::new(None),
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().expect("addr");
        let client = thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).expect("connect");
            sock.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            sock.write_all(&[4, 1, 0, 80, 127, 0, 0, 1, 0])
                .expect("request");
            let mut reply = [0u8; 8];
            sock.read_exact(&mut reply).expect("refusal");
            assert_eq!(reply, [0, 91, 0, 0, 0, 0, 0, 0]);
        });
        let (mut server, _) = listener.accept().expect("accept");
        assert!(read_request(&mut server, &inner).is_none());
        client.join().expect("client");
    }

    #[test]
    fn an_http_proxy_edge_needs_the_named_credential() {
        let bare = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert!(!http_authorized(bare, "user", "pass"));
        let token = ferrox_core::b64::encode(b"user:pass");
        let named = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        assert!(http_authorized(&named, "user", "pass"));
        let bearer = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
        );
        assert!(!http_authorized(&bearer, "user", "pass"));
        assert!(!http_authorized(&named, "user", "wrong"));
        assert!(!http_authorized(&named, "other", "pass"));
        let lower = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nproxy-authorization: basic {token}\r\n\r\n"
        );
        assert!(http_authorized(&lower, "user", "pass"));
    }

    #[test]
    fn a_stalled_server_does_not_hold_the_one_that_answers() {
        let servers: Vec<Server> = ["stalled", "answers"]
            .into_iter()
            .map(|name| Server {
                host: name.to_owned(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 22,
                user: String::new(),
                password: String::new(),
                host_key: Vec::new(),
                obfuscation_key: None,
                region: None,
            })
            .collect();
        let began = Instant::now();
        let winner = race(
            servers,
            |server| {
                if server.host == "stalled" {
                    thread::sleep(Duration::from_secs(5));
                    return Err("stalled".to_owned());
                }
                Ok(server.host.clone())
            },
            Duration::from_secs(2),
            Duration::ZERO,
        )
        .expect("the answering server wins");
        assert_eq!(winner, "answers");
        let elapsed = began.elapsed();
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn a_stalled_batch_is_cut_at_its_budget() {
        let servers: Vec<Server> = (0..4)
            .map(|index| Server {
                host: format!("stalled-{index}"),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 22,
                user: String::new(),
                password: String::new(),
                host_key: Vec::new(),
                obfuscation_key: None,
                region: None,
            })
            .collect();
        let began = Instant::now();
        let outcome: Result<String, String> = race(
            servers,
            |_| {
                thread::sleep(Duration::from_secs(5));
                Err("stalled".to_owned())
            },
            Duration::from_millis(100),
            Duration::ZERO,
        );
        assert!(outcome.is_err());
        let elapsed = began.elapsed();
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn a_spki_key_unwraps_to_pkcs1() {
        let der = [
            0x30, 0x0e, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x03, 0x05, 0x00, 0x30, 0x02,
            0x05, 0x00,
        ];
        assert_eq!(spki_to_pkcs1(&der), Some(vec![0x30, 0x02, 0x05, 0x00]));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0x7f, 0x80, 0xff];
        assert_eq!(hex_decode(&hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn a_list_without_a_package_is_refused() {
        assert!(unpack(b"not json", "key").is_err());
    }

    #[test]
    fn a_flow_clone_shares_the_credential_words() {
        let out = PsiphonOut::validate(None).expect("settings");
        let (copy, counts) = ferrox_core::alloc_count::measure(|| out.clone());
        assert_eq!(counts.allocs, 0);
        assert!(std::ptr::eq(
            Arc::as_ptr(&out.credential),
            Arc::as_ptr(&copy.credential)
        ));
    }

    #[test]
    fn a_socks_udp_frame_keeps_its_target_and_payload() {
        let mut frame = Vec::new();
        socks_udp_frame_into(
            &mut frame,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            5300,
            b"hello",
        );
        let (target, payload) = parse_udp_frame(&frame).expect("frame");
        assert_eq!(
            target,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 5300)
        );
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn a_socks_udp_name_is_not_resolved_outside_the_tunnel() {
        let name = b"example.com";
        let mut frame = vec![0, 0, 0, 3, name.len() as u8];
        frame.extend_from_slice(name);
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(b"dns");
        assert!(parse_udp_frame(&frame).is_none());
    }

    #[test]
    fn a_udpgw_frame_carries_the_preamble_and_payload() {
        let mut frame = Vec::new();
        udpgw_frame_into(
            &mut frame,
            7,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            53,
            b"hi",
            true,
        );
        assert_eq!(u16::from_le_bytes([frame[0], frame[1]]), 11);
        assert_eq!(frame[2], UDPGW_FLAG_REBIND);
        assert_eq!(u16::from_le_bytes([frame[3], frame[4]]), 7);
        assert_eq!(&frame[5..9], &[192, 0, 2, 1]);
        assert_eq!(u16::from_be_bytes([frame[9], frame[10]]), 53);
        assert_eq!(&frame[11..], b"hi");
    }

    #[test]
    fn an_ipv6_udpgw_frame_names_its_flag() {
        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let address = IpAddr::V6(std::net::Ipv6Addr::from(octets));
        let mut frame = Vec::new();
        udpgw_frame_into(&mut frame, 7, address, 53, b"hi", false);
        assert_eq!(u16::from_le_bytes([frame[0], frame[1]]), 23);
        assert_eq!(frame[2], UDPGW_FLAG_IPV6);
        assert_eq!(&frame[5..21], &octets);
        assert_eq!(u16::from_be_bytes([frame[21], frame[22]]), 53);
        assert_eq!(&frame[23..], b"hi");
    }

    #[test]
    fn a_reused_udp_frame_buffer_holds_no_stale_bytes() {
        let mut frame = Vec::new();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        udpgw_frame_into(&mut frame, 7, address, 53, b"a-longer-payload", false);
        udpgw_frame_into(&mut frame, 8, address, 53, b"hi", true);
        assert_eq!(frame.len(), 13);
        assert_eq!(&frame[11..], b"hi");
        socks_udp_frame_into(&mut frame, address, 5300, b"x");
        assert_eq!(frame.len(), 11);
        assert_eq!(&frame[10..], b"x");
    }
}
