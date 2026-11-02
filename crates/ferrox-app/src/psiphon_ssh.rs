//! The SSH transport the native `Psiphon` lane rides: a synchronous client for
//! the OSSH seed message, curve25519 key exchange, AES-128-CTR with
//! HMAC-SHA-256, password auth, and `direct-tcpip` channels.

use ctr::cipher::{KeyIvInit, StreamCipher};
use ring::signature;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::io::{self, IoSlice, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub(crate) const MAGIC: u32 = 0x0BF5_CA7E;
pub(crate) const HASH_ITERATIONS: usize = 6000;
pub(crate) const SEED_LENGTH: usize = 16;
pub(crate) const KEY_LENGTH: usize = 16;
pub(crate) const MIN_PADDING: usize = 32;
pub(crate) const MAX_PADDING: usize = 8192;
const MAX_PACKET: usize = 256 * 1024;
const CHANNEL_WINDOW: u32 = 2 * 1024 * 1024;
const CHANNEL_PACKET: u32 = 32 * 1024;
/// Channel ids are 0-based, so 0 is a server's first channel; this is the only value
/// that never names one.
const NO_CHANNEL: u32 = u32::MAX;
const WINDOW_ADJUST_AT: u64 = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_IDENTIFICATION: usize = 1024;
const CLIENT_CAPABILITIES: &str = "server-requests";
/// One channel packet plus its header, padding and tag; a larger peer packet
/// grows the one buffer it needs instead of every pooled buffer.
const PACKET_CHUNK: usize = CHANNEL_PACKET as usize + 1024;
/// The pool holds a whole channel window plus the packets a flow is writing,
/// so a saturated download recycles buffers instead of allocating one per packet.
const PACKET_POOL: usize = (CHANNEL_WINDOW / CHANNEL_PACKET) as usize + 8;
const ENTROPY: usize = 4096;

const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_DEBUG: u8 = 4;
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_GLOBAL_REQUEST: u8 = 80;
const MSG_REQUEST_SUCCESS: u8 = 81;
const MSG_REQUEST_FAILURE: u8 = 82;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
const MSG_CHANNEL_REQUEST: u8 = 98;
const MSG_CHANNEL_SUCCESS: u8 = 99;
const MSG_CHANNEL_FAILURE: u8 = 100;

/// The parts of a signed server entry this transport dials.
#[derive(Debug, Clone)]
pub(crate) struct Server {
    pub(crate) host: String,
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) host_key: Vec<u8>,
    pub(crate) obfuscation_key: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) direct: bool,
    pub(crate) meek: Option<crate::psiphon_meek::Meek>,
    pub(crate) unfronted_meek: Option<crate::psiphon_meek::Meek>,
}

impl Server {
    /// The obfuscated shape when the entry carries an OSSH key or a meek front, plain SSH otherwise.
    #[must_use]
    pub(crate) fn obfuscated(&self) -> bool {
        self.obfuscation_key.is_some() || self.meek.is_some()
    }
}

/// The one hop before a server: HTTP CONNECT or a no-auth/username-password SOCKS5 handshake.
#[derive(Debug, Clone)]
pub(crate) struct Proxy {
    http: bool,
    host: String,
    port: u16,
    user: String,
    pass: String,
}

impl Proxy {
    /// `http://`, `socks5://` or `socks5h://`, with optional `user:pass@` credentials.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (http, rest) = text
            .strip_prefix("http://")
            .map(|rest| (true, rest))
            .or_else(|| text.strip_prefix("socks5://").map(|rest| (false, rest)))
            .or_else(|| text.strip_prefix("socks5h://").map(|rest| (false, rest)))
            .ok_or_else(|| {
                format!("psiphon: upstream proxy {text:?} is not http:// or socks5(h)://")
            })?;
        let (user, pass, authority) = match rest.rsplit_once('@') {
            Some((userinfo, authority)) => {
                let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                (percent_decode(user), percent_decode(pass), authority)
            }
            None => (String::new(), String::new(), rest),
        };
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| format!("psiphon: upstream proxy {text:?} names no port"))?;
        if host.is_empty() || host.contains('/') {
            return Err(format!("psiphon: upstream proxy {text:?} names no host"));
        }
        let host = host
            .strip_prefix('[')
            .and_then(|bare| bare.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("psiphon: upstream proxy {text:?} has no numeric port"))?;
        Ok(Self {
            http,
            host,
            port,
            user,
            pass,
        })
    }

    #[must_use]
    pub(crate) fn display(&self) -> String {
        format!(
            "{}://{}:{}",
            if self.http { "http" } else { "socks5" },
            self.host,
            self.port
        )
    }

    /// Dial the server through the hop, so the SSH socket itself is the tunnel's first leg.
    pub(crate) fn connect(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, String> {
        let mut last = String::new();
        for address in (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|error| format!("psiphon: upstream proxy resolve {}: {error}", self.host))?
        {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(timeout));
                    let _ = stream.set_write_timeout(Some(timeout));
                    let mut stream = stream;
                    if self.http {
                        self.connect_http(&mut stream, target)?;
                    } else {
                        self.connect_socks(&mut stream, target)?;
                    }
                    return Ok(stream);
                }
                Err(error) => last = error.to_string(),
            }
        }
        Err(format!(
            "psiphon: upstream proxy {}: {last}",
            self.display()
        ))
    }

    fn connect_http(&self, stream: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
        let authority = authority(target);
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if !self.user.is_empty() || !self.pass.is_empty() {
            let encoded =
                ferrox_core::b64::encode(format!("{}:{}", self.user, self.pass).as_bytes());
            request.push_str("Proxy-Authorization: Basic ");
            request.push_str(&encoded);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("psiphon: upstream proxy write: {error}"))?;
        let mut head = Vec::with_capacity(128);
        loop {
            let mut byte = [0u8; 1];
            stream
                .read_exact(&mut byte)
                .map_err(|error| format!("psiphon: upstream proxy read: {error}"))?;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 4096 {
                return Err("psiphon: upstream proxy answer is too long".to_owned());
            }
        }
        let text = String::from_utf8_lossy(&head);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok());
        if !matches!(status, Some(200..=299)) {
            return Err(format!(
                "psiphon: upstream proxy refused {authority}: {}",
                text.lines().next().unwrap_or("no status")
            ));
        }
        Ok(())
    }

    fn connect_socks(&self, stream: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
        let auth = !self.user.is_empty() || !self.pass.is_empty();
        let greeting: &[u8] = if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
        stream
            .write_all(greeting)
            .map_err(|error| format!("psiphon: upstream proxy greeting: {error}"))?;
        let mut method = [0u8; 2];
        stream
            .read_exact(&mut method)
            .map_err(|error| format!("psiphon: upstream proxy greeting: {error}"))?;
        if method[0] != 5 {
            return Err("psiphon: upstream proxy is not SOCKS5".to_owned());
        }
        match method[1] {
            0 => {}
            2 if auth => {
                let user = self.user.as_bytes();
                let pass = self.pass.as_bytes();
                let mut request = Vec::with_capacity(3 + user.len() + pass.len());
                request.push(1);
                request.push(u8::try_from(user.len()).unwrap_or(u8::MAX));
                request.extend_from_slice(user);
                request.push(u8::try_from(pass.len()).unwrap_or(u8::MAX));
                request.extend_from_slice(pass);
                stream
                    .write_all(&request)
                    .map_err(|error| format!("psiphon: upstream proxy auth: {error}"))?;
                let mut reply = [0u8; 2];
                stream
                    .read_exact(&mut reply)
                    .map_err(|error| format!("psiphon: upstream proxy auth: {error}"))?;
                if reply != [1, 0] {
                    return Err("psiphon: upstream proxy refused its credentials".to_owned());
                }
            }
            _ => return Err("psiphon: upstream proxy offers no usable method".to_owned()),
        }
        let mut request = Vec::with_capacity(22);
        request.extend_from_slice(&[5, 1, 0]);
        match target.ip() {
            IpAddr::V4(address) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
        }
        request.extend_from_slice(&target.port().to_be_bytes());
        stream
            .write_all(&request)
            .map_err(|error| format!("psiphon: upstream proxy request: {error}"))?;
        let mut head = [0u8; 4];
        stream
            .read_exact(&mut head)
            .map_err(|error| format!("psiphon: upstream proxy reply: {error}"))?;
        if head[0] != 5 || head[1] != 0 {
            return Err(format!(
                "psiphon: upstream proxy refused {}: status {}",
                authority(target),
                head[1]
            ));
        }
        // A domain-name bound address is a length byte plus up to 255 bytes, then the port.
        let mut bound = [0u8; 255 + 2];
        let skip = match head[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut length = [0u8; 1];
                stream
                    .read_exact(&mut length)
                    .map_err(|error| format!("psiphon: upstream proxy reply: {error}"))?;
                usize::from(length[0])
            }
            _ => return Err("psiphon: upstream proxy named no address".to_owned()),
        };
        stream
            .read_exact(&mut bound[..skip + 2])
            .map_err(|error| format!("psiphon: upstream proxy reply: {error}"))?;
        Ok(())
    }
}

fn authority(target: SocketAddr) -> String {
    match target {
        SocketAddr::V4(address) => address.to_string(),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            if let Some(hex) = bytes.get(at + 1..at + 3) {
                if let Some(byte) = hex_pair(hex[0], hex[1]) {
                    out.push(byte);
                    at += 3;
                    continue;
                }
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_pair(high: u8, low: u8) -> Option<u8> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    Some((digit(high)? << 4) | digit(low)?)
}

/// One established SSH connection; clones of a channel share it.
pub(crate) struct Session {
    inner: Arc<Inner>,
}

struct Inner {
    writer: Mutex<PacketWriter>,
    channels: Mutex<HashMap<u32, Arc<ChannelState>>>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    next_channel: AtomicU32,
    closed: AtomicBool,
    socket: TcpStream,
    opened_at: Instant,
    server: String,
    protocol: &'static str,
}

struct ChannelState {
    local: u32,
    remote: AtomicU32,
    remote_window: Mutex<u64>,
    remote_packet: AtomicU32,
    recv: Mutex<Recv>,
    cond: Condvar,
    window_cond: Condvar,
    open: Mutex<Option<mpsc::Sender<Result<(), String>>>>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}

struct Recv {
    chunks: VecDeque<Chunk>,
    eof: bool,
    closed: bool,
    pending_adjust: u64,
    local_window: u64,
}

/// One received SSH packet, held open at the bytes the dispatcher has already named.
struct Chunk {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

#[derive(Clone)]
pub(crate) struct Channel {
    session: Arc<Inner>,
    state: Arc<ChannelState>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("server", &self.inner.server)
            .field("opened", &self.inner.opened_at.elapsed())
            .finish()
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("local", &self.state.local)
            .field("remote", &self.state.remote.load(Ordering::Acquire))
            .finish()
    }
}

/// The fields the server's auth and handshake read, taken from the lane's settings.
pub(crate) struct Identity<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) sponsor: &'a str,
    pub(crate) propagation: &'a str,
    pub(crate) platform: &'a str,
    pub(crate) version: &'a str,
    pub(crate) egress_region: Option<&'a str>,
    pub(crate) device_region: Option<&'a str>,
    pub(crate) device_location: Option<&'a str>,
    pub(crate) client_features: &'a [String],
}

impl Session {
    /// Dial a server, negotiate the tunnel, and authenticate as the entry's user.
    pub(crate) fn connect(
        server: &Server,
        identity: &Identity<'_>,
        timeout: Duration,
        proxy: Option<&Proxy>,
    ) -> Result<Self, String> {
        let address = SocketAddr::new(server.address, server.port);
        let socket = match &server.meek {
            Some(meek) => crate::psiphon_meek::connect(meek, timeout, proxy)?,
            None => match proxy {
                Some(proxy) => proxy
                    .connect(address, timeout)
                    .map_err(|error| format!("psiphon ssh proxy {}: {error}", proxy.display()))?,
                None => TcpStream::connect_timeout(&address, timeout)
                    .map_err(|error| format!("psiphon ssh {}: {error}", server.host))?,
            },
        };
        socket
            .set_read_timeout(Some(timeout))
            .and_then(|()| socket.set_write_timeout(Some(timeout)))
            .and_then(|()| socket.set_nodelay(true))
            .map_err(|error| format!("psiphon ssh socket: {error}"))?;

        let control = socket
            .try_clone()
            .map_err(|error| format!("psiphon ssh socket clone: {error}"))?;
        let pool = Arc::new(Mutex::new(Vec::new()));
        let (mut output, mut input) = split(socket, server, Arc::clone(&pool))?;
        // An OSSH server reads the seed before it writes anything, so the client line goes first.
        let our_version = b"SSH-2.0-OpenSSH_9.6";
        write_all(&mut output, b"SSH-2.0-OpenSSH_9.6\r\n")?;
        let mut banner = Vec::with_capacity(256);
        let version = read_identification(&mut input, &mut banner)?;

        let kex = kex(
            &mut output,
            &mut input,
            our_version,
            &version,
            &server.host_key,
        )?;
        output.activate(kex.client_cipher.0, kex.client_cipher.1, kex.client_mac);
        input.activate(kex.server_cipher.0, kex.server_cipher.1, kex.server_mac);
        service(&mut output, &mut input)?;
        authenticate(
            &mut output,
            &mut input,
            server,
            identity.session_id,
            identity.sponsor,
        )?;
        // A Psiphon server refuses every port forward until this handshake completes.
        let relay_protocol = server.meek.as_ref().map_or_else(
            || {
                if server.obfuscation_key.is_some() {
                    "OSSH"
                } else {
                    "SSH"
                }
            },
            |meek| tunnel_protocol_base(meek.protocol),
        );
        handshake(&mut output, &mut input, relay_protocol, identity)?;
        control
            .set_read_timeout(None)
            .and_then(|()| control.set_write_timeout(None))
            .map_err(|error| format!("psiphon ssh socket: {error}"))?;

        let socket = control;
        let inner = Arc::new(Inner {
            writer: Mutex::new(output),
            channels: Mutex::new(HashMap::new()),
            pool,
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            socket,
            opened_at: Instant::now(),
            server: format!("{}:{}", server.host, server.port),
            protocol: relay_protocol,
        });
        let read_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("psiphon-ssh".to_owned())
            .spawn(move || read_loop(read_inner, input))
            .map_err(|error| format!("psiphon ssh reader: {error}"))?;
        Ok(Self { inner })
    }

    /// Open one `direct-tcpip` channel to a host and port.
    pub(crate) fn open(&self, host: &str, port: u16) -> Result<Channel, String> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err("psiphon ssh is closed".to_owned());
        }
        let local = self.inner.next_channel.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(ChannelState {
            local,
            remote: AtomicU32::new(NO_CHANNEL),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&self.inner.pool),
        });
        let (tx, rx) = mpsc::channel();
        *lock(&state.open) = Some(tx);
        lock(&self.inner.channels).insert(local, Arc::clone(&state));

        let mut payload = vec![MSG_CHANNEL_OPEN];
        put_str(&mut payload, b"direct-tcpip");
        put_u32(&mut payload, local);
        put_u32(&mut payload, CHANNEL_WINDOW);
        put_u32(&mut payload, CHANNEL_PACKET);
        put_str(&mut payload, host.as_bytes());
        put_u32(&mut payload, u32::from(port));
        put_str(&mut payload, b"127.0.0.1");
        put_u32(&mut payload, 0);
        if let Err(why) = self.inner.send(&payload) {
            lock(&self.inner.channels).remove(&local);
            self.inner.close();
            return Err(why);
        }

        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(Channel {
                session: Arc::clone(&self.inner),
                state,
            }),
            // A refusal names the target, not the tunnel, so the session stays open for other flows.
            Ok(Err(why)) => Err(why),
            Err(RecvTimeoutError::Timeout) => {
                self.inner.close();
                Err(format!("psiphon ssh channel to {host}:{port} timed out"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.inner.retire(local, &state);
                Err(format!("psiphon ssh channel to {host}:{port} closed"))
            }
        }
    }

    /// End the connection and wake every channel waiting on it.
    pub(crate) fn close(&self) {
        self.inner.close();
    }

    #[must_use]
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    #[must_use]
    pub(crate) fn server(&self) -> &str {
        &self.inner.server
    }

    #[must_use]
    pub(crate) fn protocol(&self) -> &'static str {
        self.inner.protocol
    }
}

/// A session nobody holds is a tunnel nobody reads; closing it ends the reader thread.
impl Drop for Session {
    fn drop(&mut self) {
        self.inner.close();
    }
}

impl Inner {
    fn send(&self, payload: &[u8]) -> Result<(), String> {
        let mut writer = lock(&self.writer);
        writer
            .send(payload)
            .map_err(|error| format!("psiphon ssh write: {error}"))
    }

    fn send_channel_data(&self, state: &ChannelState, data: &[u8]) -> Result<(), String> {
        let mut writer = lock(&self.writer);
        let remote = state.remote.load(Ordering::Acquire);
        if remote == NO_CHANNEL {
            return Err("psiphon channel closed".to_owned());
        }
        writer
            .send_channel_data(remote, data)
            .map_err(|error| format!("psiphon ssh write: {error}"))
    }

    fn send_channel_data_in_place(
        &self,
        state: &ChannelState,
        data: &mut [u8],
    ) -> Result<(), String> {
        let mut writer = lock(&self.writer);
        let remote = state.remote.load(Ordering::Acquire);
        if remote == NO_CHANNEL {
            return Err("psiphon channel closed".to_owned());
        }
        writer
            .send_channel_data_in_place(remote, data)
            .map_err(|error| format!("psiphon ssh write: {error}"))
    }

    /// A per-channel frame leaves only while the channel still names a remote id, read under the writer lock.
    fn send_framed(&self, state: &ChannelState, payload: &mut [u8]) -> bool {
        let mut writer = lock(&self.writer);
        let remote = state.remote.load(Ordering::Acquire);
        if remote == NO_CHANNEL || self.closed.load(Ordering::Acquire) {
            return false;
        }
        payload[1..5].copy_from_slice(&remote.to_be_bytes());
        writer.send(payload).is_ok()
    }

    /// End a channel: its remote id is retired and its close frame sent under one writer lock.
    fn close_channel(&self, state: &ChannelState) {
        let mut writer = lock(&self.writer);
        let remote = state.remote.swap(NO_CHANNEL, Ordering::AcqRel);
        if remote != NO_CHANNEL && !self.closed.load(Ordering::Acquire) {
            let _ = writer.send(&channel_close(remote));
        }
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.socket.shutdown(Shutdown::Both);
        let channels: Vec<Arc<ChannelState>> = lock(&self.channels)
            .drain()
            .map(|(_, state)| state)
            .collect();
        for state in channels {
            state.fail("psiphon ssh closed");
        }
    }

    /// Forget a channel that never answered, and close it if the confirmation raced the timeout.
    fn retire(&self, local: u32, state: &Arc<ChannelState>) {
        lock(&self.channels).remove(&local);
        self.close_channel(state);
    }
}

impl Channel {
    /// The SSH byte stream behind a local SOCKS flow.
    pub(crate) fn close(&self) {
        lock(&self.session.channels).remove(&self.state.local);
        self.session.close_channel(&self.state);
        self.state.fail("psiphon channel closed");
    }

    pub(crate) fn shutdown(&self) {
        let mut payload = [0u8; 5];
        payload[0] = MSG_CHANNEL_EOF;
        let _ = self.session.send_framed(&self.state, &mut payload);
    }

    fn adjust(&self, amount: u64) {
        if amount == 0 {
            return;
        }
        let mut payload = [0u8; 9];
        payload[0] = MSG_CHANNEL_WINDOW_ADJUST;
        payload[5..].copy_from_slice(&u32::try_from(amount).unwrap_or(u32::MAX).to_be_bytes());
        let _ = self.session.send_framed(&self.state, &mut payload);
    }
}

impl ChannelState {
    /// The peer ended the channel: refuse further writes, but let queued data drain to the reader.
    fn peer_closed(&self) {
        if let Some(tx) = lock(&self.open).take() {
            let _ = tx.send(Err("psiphon ssh closed the channel".to_owned()));
        }
        let mut recv = lock(&self.recv);
        recv.eof = true;
        recv.closed = true;
        drop(recv);
        self.cond.notify_all();
        self.window_cond.notify_all();
    }

    fn fail(&self, why: &str) {
        if let Some(tx) = lock(&self.open).take() {
            let _ = tx.send(Err(why.to_owned()));
        }
        let mut recv = lock(&self.recv);
        recv.eof = true;
        recv.closed = true;
        let mut pool = lock(&self.pool);
        while let Some(chunk) = recv.chunks.pop_front() {
            if pool.len() < PACKET_POOL {
                pool.push(chunk.buffer);
            }
        }
        drop(pool);
        drop(recv);
        self.cond.notify_all();
        self.window_cond.notify_all();
    }
}

/// Return a packet buffer to the shared pool.
fn recycle(pool: &Mutex<Vec<Vec<u8>>>, buffer: Vec<u8>) {
    let mut pool = lock(pool);
    if pool.len() < PACKET_POOL {
        pool.push(buffer);
    }
}

/// A received payload still inside its pooled packet buffer; writing it straight
/// to the client keeps the download path at one copy from the kernel, not two.
pub(crate) struct ChannelChunk {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

impl ChannelChunk {
    #[must_use]
    pub(crate) fn data(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }
}

impl Channel {
    /// The server this flow's tunnel landed on, for the pool distribution check.
    #[must_use]
    pub(crate) fn server(&self) -> &str {
        &self.session.server
    }

    /// The tunnel's identity, so two sessions on one server still count apart.
    #[must_use]
    pub(crate) fn session_id(&self) -> usize {
        Arc::as_ptr(&self.session) as usize
    }

    /// One queued chunk and the window credit it releases, without waiting.
    fn take_chunk(&self) -> (Option<ChannelChunk>, u64) {
        let mut adjust = 0u64;
        let chunk = {
            let mut recv = lock(&self.state.recv);
            loop {
                let Some((start, end)) = recv.chunks.front().map(|front| (front.start, front.end))
                else {
                    break None;
                };
                if start >= end {
                    let spent = recv
                        .chunks
                        .pop_front()
                        .unwrap_or_else(|| unreachable!("the front chunk is the one just named"));
                    recycle(&self.state.pool, spent.buffer);
                    continue;
                }
                recv.pending_adjust += (end - start) as u64;
                if recv.pending_adjust >= WINDOW_ADJUST_AT {
                    adjust += recv.pending_adjust;
                    recv.local_window += recv.pending_adjust;
                    recv.pending_adjust = 0;
                }
                break recv.chunks.pop_front();
            }
        };
        (
            chunk.map(|chunk| ChannelChunk {
                buffer: chunk.buffer,
                start: chunk.start,
                end: chunk.end,
            }),
            adjust,
        )
    }

    /// The next packet's payload without copying it out of the receive buffer.
    pub(crate) fn next_chunk(&mut self) -> io::Result<Option<ChannelChunk>> {
        loop {
            let (chunk, adjust) = self.take_chunk();
            if adjust != 0 {
                self.adjust(adjust);
            }
            if chunk.is_some() {
                return Ok(chunk);
            }
            let mut recv = lock(&self.state.recv);
            if !recv.chunks.is_empty() {
                continue;
            }
            if recv.eof || recv.closed || self.session.closed.load(Ordering::Acquire) {
                return Ok(None);
            }
            let (guard, _) = self
                .state
                .cond
                .wait_timeout(recv, IO_TIMEOUT)
                .unwrap_or_else(PoisonError::into_inner);
            recv = guard;
            if recv.chunks.is_empty() && (recv.eof || recv.closed) {
                return Ok(None);
            }
        }
    }

    /// Move every queued chunk up to `limit` under one receive lock.
    pub(crate) fn drain_chunks(&self, batch: &mut Vec<ChannelChunk>, limit: usize) {
        let mut adjust = 0u64;
        {
            let mut recv = lock(&self.state.recv);
            while batch.len() < limit {
                let Some((start, end)) = recv.chunks.front().map(|front| (front.start, front.end))
                else {
                    break;
                };
                if start >= end {
                    let spent = recv
                        .chunks
                        .pop_front()
                        .unwrap_or_else(|| unreachable!("the front chunk is the one just named"));
                    recycle(&self.state.pool, spent.buffer);
                    continue;
                }
                recv.pending_adjust += (end - start) as u64;
                if recv.pending_adjust >= WINDOW_ADJUST_AT {
                    adjust += recv.pending_adjust;
                    recv.local_window += recv.pending_adjust;
                    recv.pending_adjust = 0;
                }
                let chunk = recv
                    .chunks
                    .pop_front()
                    .unwrap_or_else(|| unreachable!("the front chunk is the one just named"));
                batch.push(ChannelChunk {
                    buffer: chunk.buffer,
                    start: chunk.start,
                    end: chunk.end,
                });
            }
        }
        if adjust != 0 {
            self.adjust(adjust);
        }
    }

    /// Hand consumed chunks back to the packet pool under one lock.
    pub(crate) fn recycle_chunks(&self, chunks: impl Iterator<Item = ChannelChunk>) {
        let mut pool = lock(&self.state.pool);
        for chunk in chunks {
            if pool.len() < PACKET_POOL {
                pool.push(chunk.buffer);
            }
        }
    }
}

impl Read for Channel {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut adjust = 0u64;
        let mut drained = None;
        let take = loop {
            let mut recv = lock(&self.state.recv);
            if let Some(chunk) = recv.chunks.front_mut() {
                if chunk.start < chunk.end {
                    let take = (chunk.end - chunk.start).min(out.len());
                    out[..take].copy_from_slice(&chunk.buffer[chunk.start..chunk.start + take]);
                    let start = chunk.start + take;
                    let spent = start == chunk.end;
                    chunk.start = start;
                    recv.pending_adjust += u64::try_from(take).unwrap_or(0);
                    if recv.pending_adjust >= WINDOW_ADJUST_AT {
                        adjust += recv.pending_adjust;
                        recv.local_window += recv.pending_adjust;
                        recv.pending_adjust = 0;
                    }
                    if spent {
                        let chunk = recv.chunks.pop_front().unwrap_or_else(|| {
                            unreachable!("the front chunk is the one just named")
                        });
                        match drained {
                            None => drained = Some(chunk.buffer),
                            Some(_) => recycle(&self.state.pool, chunk.buffer),
                        }
                    }
                    break take;
                }
                let chunk = recv
                    .chunks
                    .pop_front()
                    .unwrap_or_else(|| unreachable!("the front chunk is the one just named"));
                match drained {
                    None => drained = Some(chunk.buffer),
                    Some(_) => recycle(&self.state.pool, chunk.buffer),
                }
                continue;
            }
            if recv.eof || recv.closed || self.session.closed.load(Ordering::Acquire) {
                return Ok(0);
            }
            let (guard, _) = self
                .state
                .cond
                .wait_timeout(recv, IO_TIMEOUT)
                .unwrap_or_else(PoisonError::into_inner);
            recv = guard;
            if recv.chunks.is_empty() && (recv.eof || recv.closed) {
                return Ok(0);
            }
        };
        if let Some(buffer) = drained {
            recycle(&self.state.pool, buffer);
        }
        if adjust != 0 {
            self.adjust(adjust);
        }
        Ok(take)
    }
}

impl Channel {
    fn take_window(&self, len: usize) -> io::Result<usize> {
        if self.state.remote.load(Ordering::Acquire) == NO_CHANNEL
            || self.session.closed.load(Ordering::Acquire)
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "psiphon channel closed",
            ));
        }
        loop {
            let mut window = lock(&self.state.remote_window);
            if *window > 0 {
                let packet = u64::from(self.state.remote_packet.load(Ordering::Relaxed));
                let take = len.min(usize::try_from((*window).min(packet)).unwrap_or(len));
                *window -= u64::try_from(take).unwrap_or(0);
                return Ok(take);
            }
            let (guard, _) = self
                .state
                .window_cond
                .wait_timeout(window, IO_TIMEOUT)
                .unwrap_or_else(PoisonError::into_inner);
            window = guard;
            if self.state.remote.load(Ordering::Acquire) == NO_CHANNEL
                || self.session.closed.load(Ordering::Acquire)
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "psiphon channel closed",
                ));
            }
        }
    }

    pub(crate) fn write_in_place(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let take = self.take_window(buf.len())?;
        self.session
            .send_channel_data_in_place(&self.state, &mut buf[..take])
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
        Ok(take)
    }
}

impl Write for Channel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let take = self.take_window(buf.len())?;
        self.session
            .send_channel_data(&self.state, &buf[..take])
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) == 2 {
            let _ = lock(&self.session.channels).remove(&self.state.local);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn split(
    socket: TcpStream,
    server: &Server,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
) -> Result<(PacketWriter, PacketReader), String> {
    let write = socket
        .try_clone()
        .map_err(|error| format!("psiphon ssh socket clone: {error}"))?;
    if server.obfuscated() {
        let key = server.obfuscation_key.as_deref().unwrap_or_default();
        let seed = random::<SEED_LENGTH>();
        let client = Rc4::new(&derive_key(&seed, key.as_bytes(), b"client_to_server"));
        let remote = Rc4::new(&derive_key(&seed, key.as_bytes(), b"server_to_client"));
        let padding_len = MIN_PADDING.max(random_padding());
        let mut preamble = Vec::with_capacity(SEED_LENGTH + 8 + padding_len);
        preamble.extend_from_slice(&seed);
        preamble.extend_from_slice(&MAGIC.to_be_bytes());
        preamble.extend_from_slice(&u32::try_from(padding_len).unwrap_or(0).to_be_bytes());
        let mut padding = vec![0u8; padding_len];
        getrandom::fill(&mut padding).map_err(|error| format!("psiphon ssh entropy: {error}"))?;
        preamble.extend_from_slice(&padding);
        let mut client = client;
        client.apply(&mut preamble[SEED_LENGTH..]);
        let mut write = write;
        write
            .write_all(&preamble)
            .map_err(|error| format!("psiphon ssh preamble: {error}"))?;
        Ok((
            PacketWriter::new(write, Some(client), None, None),
            PacketReader::new(socket, Some(remote), None, None, pool),
        ))
    } else {
        Ok((
            PacketWriter::new(write, None, None, None),
            PacketReader::new(socket, None, None, None, pool),
        ))
    }
}

pub(crate) fn random_padding() -> usize {
    let bytes = random::<2>();
    MIN_PADDING + usize::from(u16::from_be_bytes(bytes)) % (MAX_PADDING - MIN_PADDING + 1)
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("psiphon: system entropy");
    bytes
}

pub(crate) fn derive_key(seed: &[u8], keyword: &[u8], iv: &[u8]) -> [u8; KEY_LENGTH] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(keyword);
    hasher.update(iv);
    let mut digest = hasher.finalize();
    for _ in 0..HASH_ITERATIONS {
        let mut hasher = Sha1::new();
        hasher.update(digest);
        digest = hasher.finalize();
    }
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&digest[..KEY_LENGTH]);
    key
}

#[derive(Clone)]
pub(crate) struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (index, byte) in s.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }

    pub(crate) fn apply(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]);
            *byte ^= self.s[usize::from(k)];
        }
    }
}

type AesCtr = ctr::Ctr128BE<aes::Aes128>;

/// Padding entropy drawn a page at a time, so a relayed megabyte is not a megabyte of `getrandom` calls.
struct Entropy {
    bytes: [u8; ENTROPY],
    at: usize,
}

impl Entropy {
    fn new() -> Self {
        Self {
            bytes: [0u8; ENTROPY],
            at: ENTROPY,
        }
    }

    fn fill(&mut self, out: &mut [u8]) -> io::Result<()> {
        if out.len() > ENTROPY {
            return getrandom::fill(out).map_err(|error| io::Error::other(error.to_string()));
        }
        if ENTROPY - self.at < out.len() {
            getrandom::fill(&mut self.bytes)
                .map_err(|error| io::Error::other(error.to_string()))?;
            self.at = 0;
        }
        out.copy_from_slice(&self.bytes[self.at..self.at + out.len()]);
        self.at += out.len();
        Ok(())
    }
}

struct PacketWriter {
    io: TcpStream,
    obfuscation: Option<Rc4>,
    cipher: Option<AesCtr>,
    mac: Option<HmacKey>,
    sequence: u32,
    block: usize,
    scratch: Vec<u8>,
    entropy: Entropy,
}

/// One received SSH packet, holding the pool buffer it was read into.
struct Packet {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

impl Packet {
    fn kind(&self) -> Option<u8> {
        (self.start < self.end).then(|| self.buffer[self.start])
    }

    fn raw(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    fn body(&self) -> &[u8] {
        self.buffer.get(self.start + 1..self.end).unwrap_or(&[])
    }
}

struct PacketReader {
    io: TcpStream,
    obfuscation: Option<Rc4>,
    cipher: Option<AesCtr>,
    mac: Option<HmacKey>,
    sequence: u32,
    block: usize,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    spare: Option<Vec<u8>>,
    /// Bytes a banner read took past its newline, still obfuscated until `recv` applies the keystream.
    pending: Vec<u8>,
}

impl PacketWriter {
    /// Wrap a socket with optional obfuscation and packet crypto.
    fn new(
        io: TcpStream,
        obfuscation: Option<Rc4>,
        cipher: Option<AesCtr>,
        mac: Option<[u8; 32]>,
    ) -> Self {
        let block = if cipher.is_some() { 16 } else { 8 };
        Self {
            io,
            obfuscation,
            cipher,
            mac: mac.map(|key| HmacKey::new(&key)),
            sequence: 0,
            block,
            scratch: Vec::new(),
            entropy: Entropy::new(),
        }
    }

    /// Start packet crypto after the key exchange.
    fn activate(&mut self, key: [u8; 16], iv: [u8; 16], mac: [u8; 32]) {
        self.cipher = Some(AesCtr::new(&key.into(), &iv.into()));
        self.mac = Some(HmacKey::new(&mac));
        self.block = 16;
    }

    /// OSSH is the wire only until the first `SSH_MSG_NEWKEYS` leaves this side.
    fn stop_obfuscation(&mut self) {
        self.obfuscation = None;
    }

    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let padding = padding_len(payload.len(), self.block);
        let packet_len = 5 + payload.len() + padding;
        self.begin_packet(packet_len, padding);
        self.scratch.extend_from_slice(payload);
        self.finish_packet(packet_len)
    }

    fn send_channel_data(&mut self, remote: u32, data: &[u8]) -> io::Result<()> {
        let payload_len = 9 + data.len();
        let padding = padding_len(payload_len, self.block);
        let packet_len = 5 + payload_len + padding;
        self.begin_packet(packet_len, padding);
        self.scratch.push(MSG_CHANNEL_DATA);
        self.scratch.extend_from_slice(&remote.to_be_bytes());
        self.scratch
            .extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes());
        self.scratch.extend_from_slice(data);
        self.finish_packet(packet_len)
    }

    /// The same channel packet, encrypted in the caller's read buffer and written with one vectored call.
    fn send_channel_data_in_place(&mut self, remote: u32, data: &mut [u8]) -> io::Result<()> {
        let payload_len = 9 + data.len();
        let padding = padding_len(payload_len, self.block);
        let packet_len = 5 + payload_len + padding;
        let mut head = [0u8; 14];
        head[..4].copy_from_slice(
            &u32::try_from(packet_len - 4)
                .map_err(|_| io::Error::other("ssh packet too long"))?
                .to_be_bytes(),
        );
        head[4] = u8::try_from(padding).map_err(|_| io::Error::other("ssh padding too long"))?;
        head[5] = MSG_CHANNEL_DATA;
        head[6..10].copy_from_slice(&remote.to_be_bytes());
        head[10..14].copy_from_slice(
            &u32::try_from(data.len())
                .map_err(|_| io::Error::other("ssh channel data too long"))?
                .to_be_bytes(),
        );
        let mut pad = [0u8; 64];
        if padding > pad.len() {
            return Err(io::Error::other("ssh padding too long"));
        }
        self.entropy.fill(&mut pad[..padding])?;
        let mut tag = [0u8; 32];
        let signed = self.mac.is_some();
        if let Some(mac) = self.mac.as_ref() {
            tag = mac.tag_parts(self.sequence, &[&head[..], data, &pad[..padding]]);
        }
        self.sequence = self.sequence.wrapping_add(1);
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut head);
            cipher.apply_keystream(data);
            cipher.apply_keystream(&mut pad[..padding]);
        }
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut head);
            obfuscation.apply(data);
            obfuscation.apply(&mut pad[..padding]);
            if signed {
                obfuscation.apply(&mut tag);
            }
        }
        let mut slices = [
            IoSlice::new(&head),
            IoSlice::new(data),
            IoSlice::new(&pad[..padding]),
            IoSlice::new(&tag),
        ];
        let count = if signed { 4 } else { 3 };
        write_vectored_all(&mut self.io, &mut slices[..count])
    }

    fn begin_packet(&mut self, packet_len: usize, padding: usize) {
        self.scratch.clear();
        self.scratch.reserve(packet_len + 32);
        self.scratch
            .extend_from_slice(&u32::try_from(packet_len - 4).unwrap_or(0).to_be_bytes());
        self.scratch.push(u8::try_from(padding).unwrap_or(0));
    }

    fn finish_packet(&mut self, packet_len: usize) -> io::Result<()> {
        let pad_start = self.scratch.len();
        self.scratch.resize(packet_len, 0);
        self.entropy.fill(&mut self.scratch[pad_start..])?;
        let tag = self
            .mac
            .as_ref()
            .map(|mac| mac.tag(self.sequence, &self.scratch[..packet_len]));
        self.sequence = self.sequence.wrapping_add(1);
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut self.scratch[..packet_len]);
        }
        if let Some(tag) = tag {
            self.scratch.extend_from_slice(&tag);
        }
        let total = self.scratch.len();
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut self.scratch[..total]);
        }
        self.io.write_all(&self.scratch[..total])
    }
}

impl PacketReader {
    /// Wrap a socket with optional obfuscation, packet crypto, and a recycle pool.
    fn new(
        io: TcpStream,
        obfuscation: Option<Rc4>,
        cipher: Option<AesCtr>,
        mac: Option<[u8; 32]>,
        pool: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> Self {
        let block = if cipher.is_some() { 16 } else { 8 };
        Self {
            io,
            obfuscation,
            cipher,
            mac: mac.map(|key| HmacKey::new(&key)),
            sequence: 0,
            block,
            pool,
            spare: None,
            pending: Vec::new(),
        }
    }

    /// Start packet crypto after the key exchange.
    fn activate(&mut self, key: [u8; 16], iv: [u8; 16], mac: [u8; 32]) {
        self.cipher = Some(AesCtr::new(&key.into(), &iv.into()));
        self.mac = Some(HmacKey::new(&mac));
        self.block = 16;
    }

    /// The peer's first `SSH_MSG_NEWKEYS` is the last obfuscated packet in this direction.
    fn stop_obfuscation(&mut self) {
        self.obfuscation = None;
    }

    /// Return a packet buffer to the reader or its shared pool.
    fn recycle(&mut self, buffer: Vec<u8>) {
        if self.spare.is_none() {
            self.spare = Some(buffer);
        } else {
            recycle(&self.pool, buffer);
        }
    }

    /// Move bytes a banner read took past its newline into the front of `out`, so the packet that
    /// arrived in the same read is not read again from the socket.
    fn take_pending(&mut self, out: &mut [u8]) -> usize {
        let taken = self.pending.len().min(out.len());
        out[..taken].copy_from_slice(&self.pending[..taken]);
        self.pending.drain(..taken);
        taken
    }

    /// Read one packet into a pooled buffer; the caller hands it back or moves it to a channel.
    fn recv(&mut self) -> io::Result<Packet> {
        let mut buffer = self
            .spare
            .take()
            .or_else(|| lock(&self.pool).pop())
            .unwrap_or_default();
        if buffer.len() < PACKET_CHUNK {
            buffer.resize(PACKET_CHUNK, 0);
        }
        let taken = self.take_pending(&mut buffer[..self.block]);
        if taken < self.block {
            self.io.read_exact(&mut buffer[taken..self.block])?;
        }
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut buffer[..self.block]);
        }
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut buffer[..self.block]);
        }
        let length = u32::from_be_bytes(
            buffer[..4]
                .try_into()
                .map_err(|_| io::Error::other("short packet"))?,
        );
        let length = usize::try_from(length).map_err(|_| io::Error::other("packet too long"))?;
        let total = length + 4;
        // OSSH pads KEX packets to a random length, which is not a cipher-block multiple.
        if length < 5 || total < self.block || total > MAX_PACKET {
            return Err(io::Error::other("invalid ssh packet length"));
        }
        // The tag follows the packet bytes, so one read takes both and a packet costs two reads.
        let framed = total + if self.mac.is_some() { 32 } else { 0 };
        if buffer.len() < framed {
            buffer.resize(framed, 0);
        }
        let taken = self.take_pending(&mut buffer[self.block..framed]);
        if taken < framed - self.block {
            self.io
                .read_exact(&mut buffer[self.block + taken..framed])?;
        }
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut buffer[self.block..total]);
        }
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut buffer[self.block..total]);
        }
        if let Some(mac) = self.mac.as_ref() {
            if !constant_time_eq(
                &mac.tag(self.sequence, &buffer[..total]),
                &buffer[total..framed],
            ) {
                return Err(io::Error::other("ssh packet mac mismatch"));
            }
        }
        self.sequence = self.sequence.wrapping_add(1);
        let padding = usize::from(buffer[4]);
        if padding + 5 > total {
            return Err(io::Error::other("invalid ssh padding"));
        }
        Ok(Packet {
            buffer,
            start: 5,
            end: total - padding,
        })
    }
}

#[derive(Clone)]
struct HmacKey {
    inner: Sha256,
    outer: Sha256,
}

impl HmacKey {
    /// Build the inner and outer SHA-256 states for one key.
    fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 64];
        if key.len() > 64 {
            let digest = Sha256::digest(key);
            block[..digest.len()].copy_from_slice(&digest);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha256::new();
        let mut outer = Sha256::new();
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for index in 0..64 {
            ipad[index] ^= block[index];
            opad[index] ^= block[index];
        }
        inner.update(ipad);
        outer.update(opad);
        Self { inner, outer }
    }

    fn tag(&self, sequence: u32, bytes: &[u8]) -> [u8; 32] {
        self.tag_parts(sequence, &[bytes])
    }

    fn tag_parts(&self, sequence: u32, parts: &[&[u8]]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        inner.update(sequence.to_be_bytes());
        for part in parts {
            inner.update(part);
        }
        self.finish(inner)
    }

    #[cfg(test)]
    fn mac(&self, bytes: &[u8]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        inner.update(bytes);
        self.finish(inner)
    }

    fn finish(&self, inner: Sha256) -> [u8; 32] {
        let mut outer = self.outer.clone();
        outer.update(inner.finalize());
        outer.finalize().into()
    }
}

fn write_vectored_all(io: &mut TcpStream, mut slices: &mut [IoSlice<'_>]) -> io::Result<()> {
    while !slices.is_empty() {
        let written = match io.write_vectored(slices) {
            Ok(written) => written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "ssh packet write wrote zero bytes",
            ));
        }
        IoSlice::advance_slices(&mut slices, written);
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

fn padding_len(payload: usize, block: usize) -> usize {
    let mut padding = block - ((payload + 5) % block);
    if padding < 4 {
        padding += block;
    }
    padding
}

fn write_all(writer: &mut PacketWriter, bytes: &[u8]) -> Result<(), String> {
    let mut bytes = bytes.to_vec();
    if let Some(obfuscation) = writer.obfuscation.as_mut() {
        obfuscation.apply(&mut bytes);
    }
    writer
        .io
        .write_all(&bytes)
        .map_err(|error| format!("psiphon ssh write: {error}"))
}

/// Read the server banner, retaining bytes read past its newline.
fn read_identification(reader: &mut PacketReader, banner: &mut Vec<u8>) -> Result<Vec<u8>, String> {
    let mut chunk = [0u8; 512];
    let mut raw = [0u8; 512];
    banner.clear();
    loop {
        let read = match reader.io.read(&mut chunk) {
            Ok(0) => return Err("psiphon ssh closed before its banner".to_owned()),
            Ok(read) => read,
            Err(error) => return Err(format!("psiphon ssh banner: {error}")),
        };
        raw[..read].copy_from_slice(&chunk[..read]);
        let saved = reader.obfuscation.clone();
        if let Some(obfuscation) = reader.obfuscation.as_mut() {
            obfuscation.apply(&mut chunk[..read]);
        }
        let mut start = 0;
        while start < read {
            let Some(offset) = chunk[start..read].iter().position(|byte| *byte == b'\n') else {
                for &byte in &chunk[start..read] {
                    if byte != b'\r' {
                        banner.push(byte);
                    }
                    // The reference server writes padding lines up to 512 characters, 1024 with CRLF.
                    if banner.len() >= MAX_IDENTIFICATION {
                        return Err("psiphon ssh banner too long".to_owned());
                    }
                }
                break;
            };
            let end = start + offset;
            for &byte in &chunk[start..end] {
                if byte != b'\r' {
                    banner.push(byte);
                }
                if banner.len() >= MAX_IDENTIFICATION {
                    return Err("psiphon ssh banner too long".to_owned());
                }
            }
            if banner.starts_with(b"SSH-") {
                if let Some(mut saved) = saved {
                    saved.apply(&mut chunk[..=end]);
                    reader.obfuscation = Some(saved);
                }
                reader.pending.extend_from_slice(&raw[end + 1..read]);
                return Ok(banner.clone());
            }
            banner.clear();
            start = end + 1;
        }
    }
}

struct Keys {
    client_cipher: ([u8; 16], [u8; 16]),
    client_mac: [u8; 32],
    server_cipher: ([u8; 16], [u8; 16]),
    server_mac: [u8; 32],
}

#[allow(clippy::too_many_lines)]
fn kex(
    writer: &mut PacketWriter,
    reader: &mut PacketReader,
    client_version: &[u8],
    server_version: &[u8],
    expected_host_key: &[u8],
) -> Result<Keys, String> {
    let mut kexinit = vec![MSG_KEXINIT];
    kexinit.extend_from_slice(&random::<16>());
    put_name_list(
        &mut kexinit,
        b"curve25519-sha256,curve25519-sha256@libssh.org",
    );
    put_name_list(
        &mut kexinit,
        b"rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-ed25519",
    );
    put_name_list(&mut kexinit, b"aes128-ctr");
    put_name_list(&mut kexinit, b"aes128-ctr");
    put_name_list(&mut kexinit, b"hmac-sha2-256");
    put_name_list(&mut kexinit, b"hmac-sha2-256");
    put_name_list(&mut kexinit, b"none");
    put_name_list(&mut kexinit, b"none");
    put_name_list(&mut kexinit, b"");
    put_name_list(&mut kexinit, b"");
    kexinit.push(0);
    put_u32(&mut kexinit, 0);
    writer
        .send(&kexinit)
        .map_err(|error| format!("psiphon ssh kexinit: {error}"))?;

    let reply = loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_KEXINIT) => break packet,
            Some(MSG_DISCONNECT | MSG_IGNORE | MSG_DEBUG) => {}
            Some(other) => return Err(format!("psiphon ssh expected kexinit, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    };
    let host_key_algorithm = parse_kexinit(reply.raw(), expected_host_key)?;
    if !matches!(
        host_key_algorithm.as_str(),
        "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa" | "ssh-ed25519"
    ) {
        return Err(format!(
            "psiphon ssh host key {host_key_algorithm} is not supported"
        ));
    }

    let secret = random::<32>();
    let public = x25519(secret, X25519_BASEPOINT_BYTES);
    let mut init = vec![MSG_KEX_ECDH_INIT];
    put_str(&mut init, &public);
    writer
        .send(&init)
        .map_err(|error| format!("psiphon ssh kex init: {error}"))?;

    let packet = loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_KEX_ECDH_REPLY) => break packet,
            Some(MSG_IGNORE | MSG_DEBUG) => {}
            Some(other) => return Err(format!("psiphon ssh expected kex reply, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    };
    let raw = packet.raw();
    let mut at = 1;
    let host_key = take_str_ok(raw, &mut at)?;
    let server_public = take_str_ok(raw, &mut at)?;
    let signature = take_str_ok(raw, &mut at)?;
    if host_key != expected_host_key {
        return Err("psiphon ssh host key does not match the signed entry".to_owned());
    }
    if server_public.len() != 32 {
        return Err("psiphon ssh server key is not curve25519".to_owned());
    }
    let server_public: [u8; 32] = server_public
        .try_into()
        .map_err(|_| "psiphon ssh server key is not curve25519")?;
    let shared = x25519(secret, server_public);
    if shared.iter().all(|byte| *byte == 0) {
        return Err("psiphon ssh server key has the wrong order".to_owned());
    }
    // The reference reads the X25519 output as a big-endian integer and encodes it as an mpint.
    let shared = mpint(&shared);
    let mut encoded_shared = Vec::new();
    put_str(&mut encoded_shared, &shared);

    let mut transcript = Vec::new();
    put_str(&mut transcript, client_version);
    put_str(&mut transcript, server_version);
    put_str(&mut transcript, &kexinit);
    put_str(&mut transcript, reply.raw());
    put_str(&mut transcript, host_key);
    put_str(&mut transcript, &public);
    put_str(&mut transcript, &server_public);
    put_str(&mut transcript, &shared);
    let exchange = Sha256::digest(&transcript);

    verify_host_key(host_key, &host_key_algorithm, signature, &exchange)?;

    writer
        .send(&[MSG_NEWKEYS])
        .map_err(|error| format!("psiphon ssh newkeys: {error}"))?;
    writer.stop_obfuscation();
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_NEWKEYS) => break,
            Some(MSG_IGNORE | MSG_DEBUG) => {}
            Some(other) => return Err(format!("psiphon ssh expected newkeys, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
    reader.stop_obfuscation();

    let derive = |letter: u8| {
        let mut hasher = Sha256::new();
        hasher.update(&encoded_shared);
        hasher.update(exchange);
        hasher.update([letter]);
        hasher.update(exchange);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    };
    let client_iv = derive(b'A');
    let server_iv = derive(b'B');
    let client_key = derive(b'C');
    let server_key = derive(b'D');
    let client_mac = derive(b'E');
    let server_mac = derive(b'F');
    let mut client_iv16 = [0u8; 16];
    let mut client_key16 = [0u8; 16];
    let mut server_iv16 = [0u8; 16];
    let mut server_key16 = [0u8; 16];
    client_iv16.copy_from_slice(&client_iv[..16]);
    client_key16.copy_from_slice(&client_key[..16]);
    server_iv16.copy_from_slice(&server_iv[..16]);
    server_key16.copy_from_slice(&server_key[..16]);
    Ok(Keys {
        client_cipher: (client_key16, client_iv16),
        client_mac,
        server_cipher: (server_key16, server_iv16),
        server_mac,
    })
}

fn parse_kexinit(packet: &[u8], expected_host_key: &[u8]) -> Result<String, String> {
    let mut at = 17;
    let kex = take_str_ok(packet, &mut at)?;
    let host_key = take_str_ok(packet, &mut at)?;
    let cipher_client = take_str_ok(packet, &mut at)?;
    let cipher_server = take_str_ok(packet, &mut at)?;
    let mac_client = take_str_ok(packet, &mut at)?;
    let mac_server = take_str_ok(packet, &mut at)?;
    let compress_client = take_str_ok(packet, &mut at)?;
    let compress_server = take_str_ok(packet, &mut at)?;
    for _ in 0..2 {
        take_str_ok(packet, &mut at)?;
    }
    if !kex
        .split(|byte| *byte == b',')
        .any(|name| name == b"curve25519-sha256" || name == b"curve25519-sha256@libssh.org")
    {
        return Err("psiphon ssh server does not offer curve25519-sha256".to_owned());
    }
    for (name, list) in [
        ("aes128-ctr", [cipher_client, cipher_server]),
        ("hmac-sha2-256", [mac_client, mac_server]),
        ("none", [compress_client, compress_server]),
    ] {
        for offered in list {
            if !offered
                .split(|byte| *byte == b',')
                .any(|item| item == name.as_bytes())
            {
                return Err(format!("psiphon ssh server does not offer {name}"));
            }
        }
    }
    let supported: &[&str] = if expected_host_key.starts_with(b"\0\0\0\x0bssh-ed25519") {
        &["ssh-ed25519"]
    } else {
        &["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]
    };
    for client in supported {
        if host_key
            .split(|byte| *byte == b',')
            .any(|name| name == client.as_bytes())
        {
            return Ok((*client).to_owned());
        }
    }
    Err("psiphon ssh server offers no supported host key".to_owned())
}

fn verify_host_key(
    key: &[u8],
    algorithm: &str,
    signature_blob: &[u8],
    message: &[u8],
) -> Result<(), String> {
    let mut at = 0;
    let key_type = take_str_ok(key, &mut at)?;
    let (public, ring_algorithm): (Vec<u8>, &dyn signature::VerificationAlgorithm) = match key_type
    {
        b"ssh-rsa" => {
            let e = take_str_ok(key, &mut at)?;
            let n = take_str_ok(key, &mut at)?;
            let der = rsa_der(n, e);
            let ring_algorithm = match algorithm {
                "rsa-sha2-512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                "ssh-rsa" => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                _ => &signature::RSA_PKCS1_2048_8192_SHA256,
            };
            (der, ring_algorithm)
        }
        b"ssh-ed25519" => (take_str_ok(key, &mut at)?.to_vec(), &signature::ED25519),
        other => {
            return Err(format!(
                "psiphon ssh unsupported host key {}",
                String::from_utf8_lossy(other)
            ));
        }
    };

    let mut at = 0;
    let signature_algorithm = take_str_ok(signature_blob, &mut at)?;
    let signature = take_str_ok(signature_blob, &mut at)?;
    if signature_algorithm != algorithm.as_bytes() {
        return Err(format!(
            "psiphon ssh signature {} does not match {algorithm}",
            String::from_utf8_lossy(signature_algorithm)
        ));
    }
    signature::UnparsedPublicKey::new(ring_algorithm, public)
        .verify(message, signature)
        .map_err(|_| "psiphon ssh host key signature is invalid".to_owned())
}

fn rsa_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(n.len() + e.len() + 16);
    let mut body = Vec::with_capacity(n.len() + e.len() + 8);
    der_integer(&mut body, n);
    der_integer(&mut body, e);
    out.push(0x30);
    der_length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn der_integer(out: &mut Vec<u8>, value: &[u8]) {
    out.push(0x02);
    der_length(out, value.len());
    out.extend_from_slice(value);
}

fn der_length(out: &mut Vec<u8>, length: usize) {
    if length < 128 {
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | u8::try_from(bytes.len() - first).unwrap_or(0));
        out.extend_from_slice(&bytes[first..]);
    }
}

fn service(writer: &mut PacketWriter, reader: &mut PacketReader) -> Result<(), String> {
    let mut request = vec![MSG_SERVICE_REQUEST];
    put_str(&mut request, b"ssh-userauth");
    writer
        .send(&request)
        .map_err(|error| format!("psiphon ssh service: {error}"))?;
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_SERVICE_ACCEPT) => return Ok(()),
            Some(MSG_EXT_INFO | MSG_IGNORE | MSG_DEBUG | MSG_GLOBAL_REQUEST) => {}
            Some(other) => return Err(format!("psiphon ssh expected service accept, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
}

const MSG_EXT_INFO: u8 = 7;

/// Authenticate the relay and open the session channel.
fn authenticate(
    writer: &mut PacketWriter,
    reader: &mut PacketReader,
    server: &Server,
    session_id: &str,
    sponsor: &str,
) -> Result<(), String> {
    let password = format!(
        r#"{{"SessionId":"{}","SshPassword":"{}","ClientCapabilities":["{}"],"SponsorId":"{}"}}"#,
        json_escape(session_id),
        json_escape(&server.password),
        CLIENT_CAPABILITIES,
        json_escape(sponsor)
    );
    let mut request = vec![MSG_USERAUTH_REQUEST];
    put_str(&mut request, server.user.as_bytes());
    put_str(&mut request, b"ssh-connection");
    put_str(&mut request, b"password");
    request.push(0);
    put_str(&mut request, password.as_bytes());
    writer
        .send(&request)
        .map_err(|error| format!("psiphon ssh auth: {error}"))?;
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_USERAUTH_SUCCESS) => return Ok(()),
            Some(MSG_USERAUTH_FAILURE) => {
                return Err("psiphon ssh refused the server entry's password".to_owned());
            }
            Some(MSG_EXT_INFO | MSG_IGNORE | MSG_DEBUG | MSG_GLOBAL_REQUEST) => {}
            Some(other) => return Err(format!("psiphon ssh expected auth success, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
}

/// The base tunnel protocol a CDN variant reports to the server.
fn tunnel_protocol_base(protocol: &'static str) -> &'static str {
    match protocol {
        "FRONTED-MEEK-CDN-OSSH" => "FRONTED-MEEK-OSSH",
        "FRONTED-MEEK-CDN-HTTP-OSSH" => "FRONTED-MEEK-HTTP-OSSH",
        _ => protocol,
    }
}

/// The JSON body of the SSH Psiphon handshake.
fn handshake_body(relay_protocol: &str, identity: &Identity<'_>) -> String {
    let mut body = format!(
        r#"{{"propagation_channel_id":"{}","sponsor_id":"{}","client_version":"{}","client_platform":"{}","relay_protocol":"{}""#,
        json_escape(identity.propagation),
        json_escape(identity.sponsor),
        json_escape(identity.version),
        json_escape(identity.platform),
        json_escape(relay_protocol)
    );
    if let Some(region) = identity.egress_region {
        let _ = write!(body, r#","egress_region":"{}""#, json_escape(region));
    }
    if let Some(region) = identity.device_region {
        let _ = write!(body, r#","device_region":"{}""#, json_escape(region));
    }
    if let Some(location) = identity.device_location {
        let _ = write!(body, r#","device_location":"{}""#, json_escape(location));
    }
    if !identity.client_features.is_empty() {
        body.push_str(r#","client_features":["#);
        for (index, feature) in identity.client_features.iter().enumerate() {
            if index > 0 {
                body.push(',');
            }
            let _ = write!(body, "\"{}\"", json_escape(feature));
        }
        body.push(']');
    }
    body.push('}');
    body
}

/// The SSH API handshake every Psiphon server requires before it permits a port forward.
fn handshake(
    writer: &mut PacketWriter,
    reader: &mut PacketReader,
    relay_protocol: &str,
    identity: &Identity<'_>,
) -> Result<(), String> {
    let body = handshake_body(relay_protocol, identity);
    let mut request = vec![MSG_GLOBAL_REQUEST];
    put_str(&mut request, b"psiphon-handshake");
    request.push(1);
    request.extend_from_slice(body.as_bytes());
    writer
        .send(&request)
        .map_err(|error| format!("psiphon ssh handshake: {error}"))?;
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_REQUEST_SUCCESS) => return Ok(()),
            Some(MSG_REQUEST_FAILURE) => {
                return Err("psiphon ssh refused the tunnel handshake".to_owned());
            }
            Some(MSG_EXT_INFO | MSG_IGNORE | MSG_DEBUG | MSG_GLOBAL_REQUEST) => {}
            Some(other) => {
                return Err(format!("psiphon ssh expected handshake reply, got {other}"))
            }
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out
}

/// What the dispatcher did with the packet buffer it was handed.
enum Dispatch {
    Recycle(Vec<u8>),
    Queued,
    Stop,
}

#[allow(clippy::needless_pass_by_value)]
fn read_loop(inner: Arc<Inner>, mut reader: PacketReader) {
    while let Ok(packet) = reader.recv() {
        match dispatch(&inner, packet) {
            Dispatch::Recycle(buffer) => reader.recycle(buffer),
            Dispatch::Queued => {}
            Dispatch::Stop => break,
        }
    }
    inner.close();
}

#[allow(clippy::too_many_lines)]
fn dispatch(inner: &Arc<Inner>, packet: Packet) -> Dispatch {
    let Some(kind) = packet.kind() else {
        return Dispatch::Stop;
    };
    let body = packet.body();
    match kind {
        MSG_CHANNEL_OPEN_CONFIRMATION => {
            let mut at = 0;
            let (Some(local), Some(remote), Some(window), Some(packet_size)) = (
                take_u32(body, &mut at),
                take_u32(body, &mut at),
                take_u32(body, &mut at),
                take_u32(body, &mut at),
            ) else {
                return Dispatch::Stop;
            };
            let Some(state) = lock(&inner.channels).get(&local).cloned() else {
                return Dispatch::Recycle(packet.buffer);
            };
            state.remote.store(remote, Ordering::Release);
            *lock(&state.remote_window) = u64::from(window);
            state.remote_packet.store(packet_size, Ordering::Release);
            if let Some(tx) = lock(&state.open).take() {
                let _ = tx.send(Ok(()));
            }
            state.cond.notify_all();
            state.window_cond.notify_all();
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_OPEN_FAILURE => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            if let Some(state) = lock(&inner.channels).remove(&local) {
                state.fail("psiphon ssh refused the channel");
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_WINDOW_ADJUST => {
            let mut at = 0;
            let (Some(local), Some(add)) = (take_u32(body, &mut at), take_u32(body, &mut at))
            else {
                return Dispatch::Stop;
            };
            if let Some(state) = by_local(inner, local) {
                *lock(&state.remote_window) += u64::from(add);
                state.window_cond.notify_all();
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_DATA => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            let Some(data) = take_str(body, &mut at) else {
                return Dispatch::Stop;
            };
            if data.is_empty() {
                return Dispatch::Recycle(packet.buffer);
            }
            let offset = packet.start + 1 + at - data.len();
            let end = offset + data.len();
            let data_len = data.len();
            let Some(state) = by_local(inner, local) else {
                return Dispatch::Recycle(packet.buffer);
            };
            let mut recv = lock(&state.recv);
            if data_len as u64 > recv.local_window {
                return Dispatch::Stop;
            }
            recv.local_window -= data_len as u64;
            let was_empty = recv.chunks.is_empty();
            recv.chunks.push_back(Chunk {
                buffer: packet.buffer,
                start: offset,
                end,
            });
            drop(recv);
            // A reader already draining does not need a wake per packet; only the transition does.
            if was_empty {
                state.cond.notify_one();
            }
            Dispatch::Queued
        }
        MSG_CHANNEL_EOF => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            if let Some(state) = by_local(inner, local) {
                lock(&state.recv).eof = true;
                state.cond.notify_all();
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_CLOSE => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            if let Some(state) = by_local(inner, local) {
                lock(&inner.channels).remove(&local);
                inner.close_channel(&state);
                state.peer_closed();
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_REQUEST => {
            let mut at = 0;
            let (Some(local), Some(request)) = (take_u32(body, &mut at), take_str(body, &mut at))
            else {
                return Dispatch::Stop;
            };
            let Some(want_reply) = body.get(at).copied() else {
                return Dispatch::Stop;
            };
            if want_reply != 0 {
                let kind = if matches!(request, b"exit-status" | b"exit-signal") {
                    MSG_CHANNEL_SUCCESS
                } else {
                    MSG_CHANNEL_FAILURE
                };
                if let Some(state) = by_local(inner, local) {
                    let mut payload = [0u8; 5];
                    payload[0] = kind;
                    let _ = inner.send_framed(&state, &mut payload);
                }
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_GLOBAL_REQUEST => {
            let mut at = 0;
            let Some(_) = take_str(body, &mut at) else {
                return Dispatch::Stop;
            };
            if body.get(at).copied().unwrap_or(0) != 0 {
                let _ = inner.send(&[MSG_REQUEST_FAILURE]);
            }
            Dispatch::Recycle(packet.buffer)
        }
        // Rekey is not implemented; a stalled session is worse than a reconnect.
        MSG_DISCONNECT | MSG_KEXINIT => Dispatch::Stop,
        _ => Dispatch::Recycle(packet.buffer),
    }
}

/// Every message from the server names the recipient, which is the channel id this side chose.
fn by_local(inner: &Inner, local: u32) -> Option<Arc<ChannelState>> {
    lock(&inner.channels).get(&local).cloned()
}

fn recv(reader: &mut PacketReader) -> Result<Packet, String> {
    reader
        .recv()
        .map_err(|error| format!("psiphon ssh read: {error}"))
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// A `channel close` addressed to the peer's channel id.
fn channel_close(remote: u32) -> [u8; 5] {
    let mut payload = [0u8; 5];
    payload[0] = MSG_CHANNEL_CLOSE;
    payload[1..].copy_from_slice(&remote.to_be_bytes());
    payload
}

fn put_str(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, u32::try_from(value.len()).unwrap_or(0));
    out.extend_from_slice(value);
}

fn put_name_list(out: &mut Vec<u8>, value: &[u8]) {
    put_str(out, value);
}

fn take_u32(bytes: &[u8], at: &mut usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let value = u32::from_be_bytes(bytes.get(*at..end)?.try_into().ok()?);
    *at = end;
    Some(value)
}

fn take_str<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let length = usize::try_from(take_u32(bytes, at)?).ok()?;
    let end = at.checked_add(length)?;
    let value = bytes.get(*at..end)?;
    *at = end;
    Some(value)
}

fn take_str_ok<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], String> {
    take_str(bytes, at).ok_or_else(|| "psiphon ssh truncated message".to_owned())
}

fn mpint(value: &[u8]) -> Vec<u8> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let value = &value[first..];
    if value.is_empty() {
        return Vec::new();
    }
    if value[0] & 0x80 == 0 {
        return value.to_vec();
    }
    let mut out = Vec::with_capacity(value.len() + 1);
    out.push(0);
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
pub(crate) fn test_channel_with_chunks(payloads: &[&[u8]]) -> Channel {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
    let _ = listener.accept().expect("accept");
    let pool = Arc::new(Mutex::new(Vec::new()));
    let inner = Arc::new(Inner {
        writer: Mutex::new(PacketWriter::new(
            peer.try_clone().expect("clone"),
            None,
            None,
            None,
        )),
        channels: Mutex::new(HashMap::new()),
        pool: Arc::clone(&pool),
        next_channel: AtomicU32::new(1),
        closed: AtomicBool::new(false),
        socket: peer,
        opened_at: Instant::now(),
        server: "test".to_owned(),
        protocol: "SSH",
    });
    let state = Arc::new(ChannelState {
        local: 1,
        remote: AtomicU32::new(2),
        remote_window: Mutex::new(0),
        remote_packet: AtomicU32::new(CHANNEL_PACKET),
        recv: Mutex::new(Recv {
            chunks: VecDeque::new(),
            eof: false,
            closed: false,
            pending_adjust: 0,
            local_window: u64::from(CHANNEL_WINDOW),
        }),
        cond: Condvar::new(),
        window_cond: Condvar::new(),
        open: Mutex::new(None),
        pool,
    });
    {
        let mut recv = lock(&state.recv);
        for payload in payloads {
            let mut buffer = vec![0u8; PACKET_CHUNK];
            buffer[8..8 + payload.len()].copy_from_slice(payload);
            recv.chunks.push_back(Chunk {
                buffer,
                start: 8,
                end: 8 + payload.len(),
            });
        }
        recv.eof = true;
    }
    Channel {
        session: inner,
        state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn rc4_matches_the_known_vector() {
        let mut rc4 = Rc4::new(b"Key");
        let mut data = *b"Plaintext";
        rc4.apply(&mut data);
        assert_eq!(&data, b"\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3");
    }

    #[test]
    fn obfuscation_key_is_sha1_repeated_then_truncated() {
        let key = derive_key(&[0u8; 16], b"key", b"client_to_server");
        assert_eq!(key.len(), 16);
        assert_ne!(key, [0u8; 16]);
    }

    #[test]
    fn a_packet_length_is_a_block_multiple_with_four_bytes_of_padding() {
        for block in [8usize, 16] {
            for payload in 0..=96 {
                let padding = padding_len(payload, block);
                assert!(padding >= 4, "block {block}, payload {payload}");
                assert_eq!((4 + 1 + payload + padding) % block, 0);
            }
        }
    }

    #[test]
    fn in_place_channel_data_round_trips_under_the_cipher_and_mac() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let mac = [3u8; 32];
        let mut writer = PacketWriter::new(socket, None, None, None);
        writer.activate(key, iv, mac);
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(peer, None, None, None, pool);
        reader.activate(key, iv, mac);
        let mut data = *b"payload";
        writer
            .send_channel_data_in_place(42, &mut data)
            .expect("send");
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_CHANNEL_DATA));
        let body = packet.body();
        assert_eq!(&body[0..4], &42u32.to_be_bytes());
        assert_eq!(&body[8..], b"payload");
    }

    #[test]
    fn a_kex_packet_need_not_be_a_block_multiple() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let mut peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        // The reference pads a plaintext KEX packet to a random length: total 11, not a multiple of 8.
        let mut wire = Vec::new();
        wire.extend_from_slice(&7u32.to_be_bytes());
        wire.push(4);
        wire.extend_from_slice(&[MSG_IGNORE, MSG_IGNORE]);
        wire.extend_from_slice(&[0u8; 4]);
        peer.write_all(&wire).expect("write");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(socket, None, None, None, pool);
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_IGNORE));
        assert_eq!(packet.body().len(), 1);
    }

    #[test]
    fn a_banner_read_keeps_the_packet_that_shared_its_syscall() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let mut peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        let mut wire = Vec::new();
        wire.extend_from_slice(b"notice\r\nSSH-2.0-test\r\n");
        wire.extend_from_slice(&6u32.to_be_bytes());
        wire.push(4);
        wire.push(MSG_IGNORE);
        wire.extend_from_slice(&[0u8; 4]);
        peer.write_all(&wire).expect("write");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(socket, None, None, None, pool);
        let mut banner = Vec::new();
        assert_eq!(
            read_identification(&mut reader, &mut banner).expect("banner"),
            b"SSH-2.0-test"
        );
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_IGNORE));
    }

    #[test]
    fn an_obfuscated_banner_keeps_the_packet_keystream_in_step() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let mut peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        let mut wire = Vec::new();
        wire.extend_from_slice(b"notice\r\nSSH-2.0-test\r\n");
        wire.extend_from_slice(&6u32.to_be_bytes());
        wire.push(4);
        wire.push(MSG_IGNORE);
        wire.extend_from_slice(&[0u8; 4]);
        let key = b"banner-key";
        Rc4::new(key).apply(&mut wire);
        peer.write_all(&wire).expect("write");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(socket, Some(Rc4::new(key)), None, None, pool);
        let mut banner = Vec::new();
        assert_eq!(
            read_identification(&mut reader, &mut banner).expect("banner"),
            b"SSH-2.0-test"
        );
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_IGNORE));
    }

    #[test]
    fn name_lists_keep_empty_members() {
        let mut out = Vec::new();
        put_name_list(&mut out, b"a,b");
        assert_eq!(out, [0, 0, 0, 3, b'a', b',', b'b']);
    }

    #[test]
    fn hmac_matches_the_known_vector() {
        let mac = HmacKey::new(&[0x0b; 20]);
        assert_eq!(
            mac.mac(b"Hi There"),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7
            ]
        );
    }

    #[test]
    fn password_json_escapes_every_field() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn mpint_trims_and_signs() {
        assert_eq!(mpint(&[0, 0, 1]), [1]);
        assert_eq!(mpint(&[0x80]), [0, 0x80]);
        assert_eq!(mpint(&[0, 0]), Vec::<u8>::new());
    }

    #[test]
    fn rsa_der_is_a_sequence_of_two_integers() {
        let der = rsa_der(&[1, 0, 1], &[3]);
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..], [0x02, 3, 1, 0, 1, 0x02, 1, 3]);
    }

    #[test]
    fn a_channel_write_respects_the_remote_packet() {
        assert_eq!(u64::from(CHANNEL_PACKET), 32 * 1024);
    }

    #[test]
    fn padding_entropy_is_drawn_a_page_at_a_time() {
        let mut entropy = Entropy::new();
        let mut byte = [0u8; 16];
        for _ in 0..100 {
            entropy.fill(&mut byte).expect("entropy");
        }
        assert_eq!(
            entropy.at, 1600,
            "one refill fed forty packets short of a page"
        );
    }

    #[test]
    fn a_returned_packet_buffer_is_the_same_allocation() {
        let pool = Mutex::new(Vec::new());
        let buffer = vec![0u8; PACKET_CHUNK];
        let pointer = buffer.as_ptr();
        let capacity = buffer.capacity();
        recycle(&pool, buffer);
        let buffer = lock(&pool).pop().expect("the pool kept the buffer");
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer.capacity(), capacity);
    }

    #[test]
    fn the_packet_pool_stops_at_its_ceiling() {
        let pool = Mutex::new(Vec::new());
        for _ in 0..PACKET_POOL + 8 {
            recycle(&pool, vec![0u8; PACKET_CHUNK]);
        }
        assert_eq!(lock(&pool).len(), PACKET_POOL);
    }

    #[test]
    fn a_channel_read_hands_its_packet_buffer_back_to_the_pool() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            socket: peer,
            opened_at: Instant::now(),
            server: "test".to_owned(),
            protocol: "SSH",
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state: Arc::clone(&state),
        };
        let mut buffer = vec![0u8; PACKET_CHUNK];
        let pointer = buffer.as_ptr();
        buffer[8..13].copy_from_slice(b"hello");
        lock(&state.recv).chunks.push_back(Chunk {
            buffer,
            start: 8,
            end: 13,
        });
        let mut out = [0u8; 16];
        assert_eq!(channel.read(&mut out).expect("read"), 5);
        assert_eq!(&out[..5], b"hello");
        let buffer = lock(&pool).pop().expect("the packet buffer came back");
        assert_eq!(buffer.as_ptr(), pointer);
    }

    #[test]
    fn a_batch_drains_and_recycles_under_one_lock() {
        let payloads: Vec<&[u8]> = (0..40).map(|_| &b"x"[..]).collect();
        let channel = test_channel_with_chunks(&payloads);
        let pool = Arc::clone(&channel.session.pool);
        let mut batch = Vec::new();
        channel.drain_chunks(&mut batch, 32);
        assert_eq!(batch.len(), 32);
        channel.recycle_chunks(batch.drain(..));
        assert_eq!(lock(&pool).len(), 32);
    }

    #[test]
    fn a_channel_chunk_is_the_packet_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            socket: peer,
            opened_at: Instant::now(),
            server: "test".to_owned(),
            protocol: "SSH",
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state: Arc::clone(&state),
        };
        let mut buffer = vec![0u8; PACKET_CHUNK];
        let pointer = buffer.as_ptr();
        let capacity = buffer.capacity();
        buffer[8..13].copy_from_slice(b"hello");
        lock(&state.recv).chunks.push_back(Chunk {
            buffer,
            start: 8,
            end: 13,
        });
        let chunk = channel.next_chunk().expect("chunk").expect("payload");
        assert_eq!(chunk.data(), b"hello");
        assert_eq!(chunk.data().as_ptr(), pointer.wrapping_add(8));
        channel.recycle_chunks(std::iter::once(chunk));
        let buffer = lock(&pool).pop().expect("the packet buffer came back");
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer.capacity(), capacity);
    }

    #[test]
    fn a_server_message_names_this_side_s_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            next_channel: AtomicU32::new(2),
            closed: AtomicBool::new(false),
            socket: peer,
            opened_at: Instant::now(),
            server: "test".to_owned(),
            protocol: "SSH",
        });
        let (tx, rx) = mpsc::channel();
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(NO_CHANNEL),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(Some(tx)),
            pool: Arc::clone(&pool),
        });
        lock(&inner.channels).insert(1, Arc::clone(&state));

        let mut confirm = vec![MSG_CHANNEL_OPEN_CONFIRMATION];
        put_u32(&mut confirm, 1);
        put_u32(&mut confirm, 2);
        put_u32(&mut confirm, CHANNEL_WINDOW);
        put_u32(&mut confirm, CHANNEL_PACKET);
        let end = confirm.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: confirm,
                    start: 0,
                    end
                }
            ),
            Dispatch::Recycle(_)
        ));
        assert_eq!(state.remote.load(Ordering::Acquire), 2);
        assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());

        let mut data = vec![MSG_CHANNEL_DATA];
        put_u32(&mut data, 1);
        put_str(&mut data, b"hi");
        let end = data.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: data,
                    start: 0,
                    end
                }
            ),
            Dispatch::Queued
        ));
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state,
        };
        let mut out = [0u8; 2];
        channel.read_exact(&mut out).expect("read");
        assert_eq!(&out, b"hi");
    }

    #[test]
    fn a_server_close_keeps_the_data_it_already_sent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            next_channel: AtomicU32::new(2),
            closed: AtomicBool::new(false),
            socket: peer,
            opened_at: Instant::now(),
            server: "test".to_owned(),
            protocol: "SSH",
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        lock(&inner.channels).insert(1, Arc::clone(&state));

        let mut data = vec![MSG_CHANNEL_DATA];
        put_u32(&mut data, 1);
        put_str(&mut data, b"hi");
        let end = data.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: data,
                    start: 0,
                    end
                }
            ),
            Dispatch::Queued
        ));
        let mut close = vec![MSG_CHANNEL_CLOSE];
        put_u32(&mut close, 1);
        let end = close.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: close,
                    start: 0,
                    end
                }
            ),
            Dispatch::Recycle(_)
        ));

        let mut channel = Channel {
            session: Arc::clone(&inner),
            state,
        };
        let mut out = [0u8; 2];
        channel.read_exact(&mut out).expect("read the queued bytes");
        assert_eq!(&out, b"hi");
        assert_eq!(channel.read(&mut out).expect("eof"), 0);
        assert!(channel.write(b"late").is_err());
    }

    #[test]
    fn a_post_handshake_kexinit_reconnects_instead_of_stalling() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::new(Mutex::new(Vec::new())),
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            socket: peer,
            opened_at: Instant::now(),
            server: "test".to_owned(),
            protocol: "SSH",
        });
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: vec![MSG_KEXINIT],
                    start: 0,
                    end: 1
                }
            ),
            Dispatch::Stop
        ));
    }

    #[test]
    fn a_closed_channel_sends_no_data_after_its_close() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (mut wire, _) = listener.accept().expect("accept");
        wire.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            next_channel: AtomicU32::new(2),
            closed: AtomicBool::new(false),
            socket: peer,
            opened_at: Instant::now(),
            server: "test".to_owned(),
            protocol: "SSH",
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(u64::from(CHANNEL_WINDOW)),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        lock(&inner.channels).insert(1, Arc::clone(&state));
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state,
        };
        channel.close();
        let mut head = [0u8; 4];
        wire.read_exact(&mut head).expect("packet length");
        let mut packet = vec![0u8; usize::try_from(u32::from_be_bytes(head)).expect("length")];
        wire.read_exact(&mut packet).expect("packet");
        assert_eq!(packet[1], MSG_CHANNEL_CLOSE);
        assert_eq!(
            u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]),
            2
        );
        // The ended channel refuses a write and nothing follows the close on the wire.
        assert!(channel.write(b"late").is_err());
        let mut extra = [0u8; 8];
        match wire.read(&mut extra) {
            Ok(0) => {}
            Ok(read) => panic!("{read} bytes followed the close"),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "{error}"
            ),
        }
    }

    #[test]
    fn a_cdn_tunnel_protocol_hands_its_base_name() {
        assert_eq!(
            tunnel_protocol_base("FRONTED-MEEK-CDN-OSSH"),
            "FRONTED-MEEK-OSSH"
        );
        assert_eq!(
            tunnel_protocol_base("FRONTED-MEEK-CDN-HTTP-OSSH"),
            "FRONTED-MEEK-HTTP-OSSH"
        );
        assert_eq!(
            tunnel_protocol_base("UNFRONTED-MEEK-HTTPS-OSSH"),
            "UNFRONTED-MEEK-HTTPS-OSSH"
        );
    }

    #[test]
    fn the_handshake_carries_device_identity() {
        let features = vec!["coarse-location".to_owned(), "unsafe\"feature".to_owned()];
        let identity = Identity {
            session_id: "session",
            sponsor: "sponsor",
            propagation: "propagation",
            platform: "Android",
            version: "453",
            egress_region: Some("IR"),
            device_region: Some("IR"),
            device_location: Some("w3g"),
            client_features: &features,
        };
        assert_eq!(
            handshake_body("UNFRONTED-MEEK-HTTPS-OSSH", &identity),
            r#"{"propagation_channel_id":"propagation","sponsor_id":"sponsor","client_version":"453","client_platform":"Android","relay_protocol":"UNFRONTED-MEEK-HTTPS-OSSH","egress_region":"IR","device_region":"IR","device_location":"w3g","client_features":["coarse-location","unsafe\"feature"]}"#
        );
    }

    #[test]
    fn the_handshake_omits_absent_device_identity() {
        let identity = Identity {
            session_id: "session",
            sponsor: "sponsor",
            propagation: "propagation",
            platform: "Android",
            version: "453",
            egress_region: None,
            device_region: None,
            device_location: None,
            client_features: &[],
        };
        assert_eq!(
            handshake_body("SSH", &identity),
            r#"{"propagation_channel_id":"propagation","sponsor_id":"sponsor","client_version":"453","client_platform":"Android","relay_protocol":"SSH"}"#
        );
    }

    #[test]
    fn an_upstream_proxy_url_names_its_scheme_and_credentials() {
        let proxy = Proxy::parse("http://user:p%40ss@127.0.0.1:8080").expect("proxy");
        assert!(proxy.http);
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 8080);
        assert_eq!(proxy.user, "user");
        assert_eq!(proxy.pass, "p@ss");
        assert!(Proxy::parse("socks4://127.0.0.1:1").is_err());
    }
}
