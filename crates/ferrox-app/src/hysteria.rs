use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::frames;
use ferrox_core::hysteria::{self, Defrag, UdpMessage};

use crate::conn::Connection;
use crate::quic::{Unfilled, MAX_DATAGRAM};

const AUTH_STREAM: u64 = 0;

const FIRST_FLOW_STREAM: u64 = 4;

const HEAD_CAP: usize = 16 * 1024;

const ROUTE_POLL: Duration = Duration::from_millis(100);

const STREAM_POLL: Duration = Duration::from_millis(5);

const SCID_LEN: usize = 16;

/// How long a QUIC datagram lane may sit without traffic before its association is reaped, matching the reference's `udp_idle_timeout`.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// The reader's socket poll, matching the reference's one-second cleanup tick: it bounds how long a reaped association's thread lives, since a UDP socket has no shutdown to wake a blocked read.
const UDP_POLL: Duration = Duration::from_secs(1);

/// A target reply is a whole UDP datagram, so one buffer of the wire's UDP ceiling holds any single response the association reads.
const UDP_TARGET_BUF: usize = hysteria::MAX_UDP_PAYLOAD;

pub(crate) struct Dial {
    pub(crate) host: String,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) config: hysteria::Config,
    pub(crate) roots: Option<Vec<Vec<u8>>>,
}

#[derive(Clone)]
pub(crate) struct Session {
    shared: Arc<Mutex<quiche::Connection>>,
    sock: Arc<crate::quic::Datagram>,
    local: SocketAddr,
    // Written once by `connect` from the auth response and read by the UDP dial that follows: a server that skips the lane header still carries TCP flows, so the flag gates datagrams only, never the connection.
    udp_supported: bool,
}

fn send_all(session: &Session, stream: u64, mut buf: &[u8], fin: bool) -> bool {
    let deadline = Instant::now() + crate::quic::SEND_WAIT;
    loop {
        let last = buf.is_empty();
        if last && !fin {
            return true;
        }
        let Ok(mut conn) = session.shared.lock() else {
            return false;
        };
        match conn.stream_send(stream, buf, fin && last) {
            Ok(written) => {
                buf = &buf[written..];
                crate::quic::flush_egress(&mut conn, &session.sock);
                if buf.is_empty() && (!fin || last) {
                    return true;
                }
                if written == 0 && Instant::now() >= deadline {
                    return false;
                }
            }
            Err(quiche::Error::Done) => {
                if Instant::now() >= deadline {
                    return false;
                }
            }
            Err(_) => return false,
        }
        drop(conn);
        std::thread::sleep(STREAM_POLL);
    }
}

/// One turn of the quiche wheel with the lock held for quiche calls only, never for the socket wait between them — the shape the pool's pump takes, so a writer's one `send_all` is never starved by a reader's polling.
fn drive_once(session: &Session, wait: Duration, applied: &mut Option<Duration>) -> bool {
    let timeout = {
        let Ok(conn) = session.shared.lock() else {
            return false;
        };
        if conn.is_closed() {
            return false;
        }
        conn.timeout()
            .map_or(wait, |left| left.min(wait))
            .max(Duration::from_millis(1))
    };
    if !crate::proxy::refresh_read_timeout(&session.sock, timeout, applied) {
        return false;
    }
    let mut room = Unfilled::<MAX_DATAGRAM>::new();
    let incoming = match session.sock.recv_from(room.as_mut()) {
        Ok(found) => Some(found),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(_) => {
            std::thread::sleep(wait);
            return false;
        }
    };
    let Ok(mut conn) = session.shared.lock() else {
        return false;
    };
    if conn.is_closed() {
        return false;
    }
    match incoming {
        Some((n, from)) => {
            let info = quiche::RecvInfo {
                from,
                to: session.local,
            };
            let _ = conn.recv(&mut room.as_mut()[..n], info);
        }
        None => conn.on_timeout(),
    }
    crate::quic::flush_egress(&mut conn, &session.sock);
    true
}

/// The two-byte `[0, 0]` acknowledgement every flow stream opens with, read into the caller's own buffer rather than a `Vec` per flow.
fn recv_reply(session: &Session, stream: u64, deadline: Instant) -> Option<[u8; 2]> {
    let mut room = Unfilled::<2>::new();
    let mut got = 0usize;
    let mut applied = None;
    while got < 2 {
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, &mut room.as_mut()[got..]) {
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        if let Some(n) = read {
            got += n;
        } else {
            if Instant::now() >= deadline {
                return None;
            }
            let _ = drive_once(session, STREAM_POLL, &mut applied);
        }
    }
    let reply = room.as_mut();
    Some([reply[0], reply[1]])
}

fn read_headers_block(session: &Session, stream: u64, deadline: Instant) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(128);
    let mut room = Unfilled::<4096>::new();
    let mut applied = None;
    loop {
        if head.len() >= HEAD_CAP || Instant::now() >= deadline {
            return None;
        }
        let mut at = 0usize;
        if let Some(frame) = frames::h3_frame(&head, &mut at) {
            if frame.kind != frames::H3_HEADERS {
                return None;
            }
            let len = frame.length as usize;
            if head.len() >= at + len {
                head.drain(..at);
                head.truncate(len);
                return Some(head);
            }
        }
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&room.as_mut()[..n]);
        } else {
            let _ = drive_once(session, STREAM_POLL, &mut applied);
        }
    }
}

fn control_settings(session: &Session) -> bool {
    let mut settings = Vec::new();
    frames::quic_varint(&mut settings, 0x04);
    frames::quic_varint(&mut settings, 0);
    send_all(session, 2, &settings, true)
}

fn post_auth(session: &Session, host: &str, auth: &str) -> Option<bool> {
    let mut block = Vec::with_capacity(64 + host.len() + auth.len());
    hysteria::build_auth_request(host, auth, &mut block);
    let mut frame = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut frame, frames::H3_HEADERS);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    if !send_all(session, AUTH_STREAM, &frame, true) {
        return None;
    }
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let body = read_headers_block(session, AUTH_STREAM, deadline)?;
    hysteria::read_auth_response(&body)
}

/// The handshakes this process has paid; a test watches a reused connection leave it untouched.
#[cfg(test)]
pub(crate) static HANDSHAKES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn connect(dial: &Dial) -> Option<Session> {
    #[cfg(test)]
    HANDSHAKES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let (sock, peer, local) = crate::quic::udp_to_server(&dial.address, dial.port)?;
    let mut scid = [0u8; SCID_LEN];
    getrandom::getrandom(&mut scid).ok()?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config = crate::quic::quiche_config(roots, Some(dial.config.cc.quiche_name()))?;
    // The client enables the datagram lane exactly as the served connection does: advertising it changes no stream byte of a TCP-only flow, and it is what lets `dgram_max_writable_len` answer for a UDP dial on this connection.
    config.enable_dgram(true, 1024, 1024);
    let Ok(mut conn) = quiche::connect(Some(&dial.host), &cid, local, peer, &mut config) else {
        return None;
    };
    let sock = match hysteria::Salamander::new(&dial.config.obfs_password) {
        Some(obfs) => crate::quic::Datagram::obfuscated(sock, obfs),
        None => crate::quic::Datagram::plain(sock),
    };
    crate::quic::drive_handshake(&mut conn, &sock, local)?;
    let mut session = Session {
        shared: Arc::new(Mutex::new(conn)),
        sock: Arc::new(sock),
        local,
        udp_supported: false,
    };
    if !control_settings(&session) {
        return None;
    }
    let udp = post_auth(&session, &dial.host, &dial.config.auth)?;
    session.udp_supported = udp;
    Some(session)
}

#[derive(Clone)]
pub(crate) struct Flow {
    session: Session,
    stream: u64,
    backlog: Vec<u8>,
    at: usize,
    /// Whether `read` may drive the socket itself: a flow on the server's routed socket must not, because `serve_loop` reads every datagram and routes it, and a second reader steals packets the router must see.
    drive: bool,
}

impl Flow {
    pub(crate) fn from_parts(
        shared: Arc<Mutex<quiche::Connection>>,
        sock: Arc<crate::quic::Datagram>,
        local: SocketAddr,
        stream: u64,
        backlog: Vec<u8>,
        drive: bool,
    ) -> Self {
        Self {
            session: Session {
                shared,
                sock,
                local,
                udp_supported: false,
            },
            stream,
            backlog,
            at: 0,
            drive,
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut conn) = self.session.shared.lock() {
            let _ = conn.stream_send(self.stream, &[], true);
            crate::quic::flush_egress(&mut conn, &self.session.sock);
        }
    }
}

fn broken() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::BrokenPipe)
}

impl Read for Flow {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.at < self.backlog.len() {
            let n = (self.backlog.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.backlog[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        let mut applied = None;
        loop {
            let read = {
                let Ok(mut conn) = self.session.shared.lock() else {
                    return Err(broken());
                };
                if conn.is_closed() {
                    return Ok(0);
                }
                match conn.stream_recv(self.stream, buf) {
                    Ok((n, _)) => Some(n),
                    Err(quiche::Error::Done) => None,
                    Err(_) => return Err(broken()),
                }
            };
            if let Some(n) = read {
                return Ok(n);
            }
            if self.drive {
                let _ = drive_once(&self.session, STREAM_POLL, &mut applied);
                continue;
            }
            {
                let Ok(conn) = self.session.shared.lock() else {
                    return Err(broken());
                };
                if conn.is_closed() {
                    return Ok(0);
                }
            }
            std::thread::sleep(STREAM_POLL);
        }
    }
}

impl Write for Flow {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if send_all(&self.session, self.stream, buf, false) {
            Ok(buf.len())
        } else {
            Err(broken())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn open_flow(session: &Session, stream: u64, header: &[u8]) -> Option<Flow> {
    let mut prefix = Vec::with_capacity(2 + header.len());
    hysteria::tcp_prefix(&mut prefix);
    prefix.extend_from_slice(header);
    if !send_all(session, stream, &prefix, false) {
        return None;
    }
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    if recv_reply(session, stream, deadline)? != [0, 0] {
        return None;
    }
    Some(Flow {
        session: session.clone(),
        stream,
        backlog: Vec::new(),
        at: 0,
        drive: true,
    })
}

/// Reads a Hysteria v2 TCP request body whose `0x401` frame type is already consumed, leaving any payload that followed it in the backlog.
pub(crate) fn read_request(flow: &mut Flow, deadline: Instant) -> Option<String> {
    flow.backlog.drain(..flow.at);
    flow.at = 0;
    let mut head = std::mem::take(&mut flow.backlog);
    let mut room = Unfilled::<4096>::new();
    loop {
        match hysteria::decode_tcp_request_body(&head) {
            Ok((address, used)) => {
                let address = address.to_owned();
                flow.backlog = head;
                flow.at = used;
                return Some(address);
            }
            Err(hysteria::RequestError::Invalid) => return None,
            Err(hysteria::RequestError::Incomplete) => {
                if head.len() >= HEAD_CAP || Instant::now() >= deadline {
                    return None;
                }
                let n = flow.read(room.as_mut()).ok()?;
                if n == 0 {
                    return None;
                }
                head.extend_from_slice(&room.as_mut()[..n]);
            }
        }
    }
}

/// One authenticated connection and the next flow stream it can open: the pinned client multiplexes every TCP flow this way, and the server already serves them.
struct Pooled {
    session: Session,
    next_stream: u64,
    used: Instant,
}

/// What a pooled connection is a connection to, keyed the way the quic carrier keys its pool: a different credential or CA set is a different connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Server {
    host: String,
    address: String,
    port: u16,
    cc: &'static str,
    auth: String,
    roots: Option<Vec<Vec<u8>>>,
}

/// How long an unused connection may sit before a dial pays a fresh handshake: half of quiche's idle timeout, so a reuse always lands before either side closes it.
const REUSE_WINDOW: Duration = Duration::from_millis(crate::quic::IDLE_TIMEOUT_MS / 2);

static POOL: std::sync::OnceLock<Mutex<HashMap<Server, Vec<Pooled>>>> = std::sync::OnceLock::new();

fn pool() -> &'static Mutex<HashMap<Server, Vec<Pooled>>> {
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn server_of(dial: &Dial) -> Server {
    Server {
        host: dial.host.clone(),
        address: dial.address.clone(),
        port: dial.port,
        cc: dial.config.cc.quiche_name(),
        auth: dial.config.auth.clone(),
        roots: dial.roots.clone(),
    }
}

/// Whether a pooled connection can still open a flow: quiche takes no new application data once a connection is closed, draining, or carrying a close in either direction.
fn usable(conn: &quiche::Connection) -> bool {
    !conn.is_closed()
        && !conn.is_draining()
        && conn.local_error().is_none()
        && conn.peer_error().is_none()
}

/// The connections a flow may ride, each with the stream id reserved to it; closed or stale entries are dropped here, so a dead handle never blocks a dial.
fn candidates(dial: &Dial) -> Vec<(Session, u64)> {
    let Ok(mut pool) = pool().lock() else {
        return Vec::new();
    };
    let Some(entries) = pool.get_mut(&server_of(dial)) else {
        return Vec::new();
    };
    let now = Instant::now();
    entries.retain(|entry| {
        entry.next_stream / 4 < crate::quic::MAX_STREAMS
            && now.saturating_duration_since(entry.used) < REUSE_WINDOW
            && entry.session.shared.lock().is_ok_and(|conn| usable(&conn))
    });
    entries
        .iter_mut()
        .map(|entry| {
            let stream = entry.next_stream;
            entry.next_stream += 4;
            entry.used = now;
            (entry.session.clone(), stream)
        })
        .collect()
}

fn evict(dial: &Dial, session: &Session) {
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    let Some(entries) = pool.get_mut(&server_of(dial)) else {
        return;
    };
    entries.retain(|entry| !Arc::ptr_eq(&entry.session.shared, &session.shared));
}

fn keep(dial: &Dial, session: Session, next_stream: u64) {
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    pool.entry(server_of(dial)).or_default().push(Pooled {
        session,
        next_stream,
        used: Instant::now(),
    });
}

#[cfg(test)]
pub(crate) fn handshake_count() -> usize {
    HANDSHAKES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Closes every pooled connection so a test can watch the next dial pay a fresh handshake.
#[cfg(test)]
pub(crate) fn close_pooled() {
    let Ok(pool) = pool().lock() else {
        return;
    };
    for entry in pool.values().flatten() {
        if let Ok(mut conn) = entry.session.shared.lock() {
            let _ = conn.close(false, 0, b"pool closed by test");
        }
    }
}

/// A flow over the outbound's live connection when a stream opens on it, a fresh handshake otherwise; a pooled connection that stopped opening is dropped where it is found.
fn open_pooled(dial: &Dial, header: &[u8]) -> Option<Flow> {
    for (session, stream) in candidates(dial) {
        if let Some(flow) = open_flow(&session, stream, header) {
            return Some(flow);
        }
        if session.shared.lock().is_ok_and(|conn| !usable(&conn)) {
            evict(dial, &session);
        }
    }
    let session = connect(dial)?;
    let flow = open_flow(&session, FIRST_FLOW_STREAM, header)?;
    keep(dial, session, FIRST_FLOW_STREAM + 4);
    Some(flow)
}

pub(crate) fn dial_vless(
    client: &Connection,
    dial: &Dial,
    id: &[u8; 16],
    target: &crate::proxy::Destination,
) {
    let header = crate::proxy::vless_header(id, 1, target);
    let Some(flow) = open_pooled(dial, &header) else {
        return;
    };
    relay(client, &flow);
}

pub(crate) fn relay(tcp: &Connection, flow: &Flow) {
    let Ok(tcp_read) = tcp.try_clone() else {
        return;
    };
    let Ok(mut tcp_write) = tcp.try_clone() else {
        return;
    };
    let up = flow.clone();
    let done = std::thread::spawn(move || {
        let mut tcp_read = tcp_read;
        let mut up = up;
        let mut buf = crate::proxy::RelayBuf::new();
        loop {
            match tcp_read.read(buf.as_mut()) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.write_all(&buf.as_mut()[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        up.close();
    });
    let mut back = flow.clone();
    let mut buf = crate::proxy::RelayBuf::new();
    loop {
        match back.read(buf.as_mut()) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tcp_write.write_all(&buf.as_mut()[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = tcp_write.shutdown(Shutdown::Write);
    let _ = done.join();
    flow.close();
}

pub(crate) fn server_config(
    cert_path: &str,
    key_path: &str,
    cc: hysteria::Congestion,
) -> Option<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
    config.set_application_protos(&[crate::quic::ALPN]).ok()?;
    config.set_cc_algorithm_name(cc.quiche_name()).ok()?;
    // A served connection always carries an auth validator, and the reference enables the datagram lane exactly when one is present, so the lane is on unconditionally here; the depths are the peer's unsent-datagram queue, matching `udpMessageChanSize`.
    config.enable_dgram(true, 1024, 1024);
    config.set_max_idle_timeout(crate::quic::IDLE_TIMEOUT_MS);
    config.set_initial_max_data(crate::quic::MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
    config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
    config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
    config.load_cert_chain_from_pem_file(cert_path).ok()?;
    config.load_priv_key_from_pem_file(key_path).ok()?;
    Some(config)
}

pub(crate) type Serve = Arc<dyn Fn(Flow) + Send + Sync>;

struct Inbound {
    conn: Arc<Mutex<quiche::Connection>>,
    client_cid: Vec<u8>,
    authed: bool,
    settings_sent: bool,
    settings_done: bool,
    auth_buf: Vec<u8>,
    served: HashSet<u64>,
    udp: HashMap<u32, UdpFlow>,
}

/// One datagram association: the connected target socket the router relays through, the reassembly its inbound fragments run through, the last activity the idle reap watches, and the flag that tells its reader thread to end. A UDP socket cannot be shut down to wake a blocked read, so the reader polls on the timeout and watches the flag the reap sets.
struct UdpFlow {
    target: Arc<UdpSocket>,
    defrag: Defrag,
    last: Instant,
    stop: Arc<AtomicBool>,
}

fn answer_auth(conn: &mut quiche::Connection, ok: bool) -> bool {
    let mut block = Vec::with_capacity(32);
    if ok {
        hysteria::build_auth_response(true, &mut block);
    } else {
        ferrox_core::foxy::hpack::qpack_literal_many(&[(":status", "404")], &mut block);
    }
    let mut frame = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut frame, frames::H3_HEADERS);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    conn.stream_send(AUTH_STREAM, &frame, true).is_ok()
}

/// Drains the client's HTTP/3 SETTINGS so the unread bytes never hold flow control, and reports the stream's FIN so the caller stops paying the call per packet.
fn drain_settings(conn: &mut quiche::Connection) -> bool {
    let mut room = Unfilled::<128>::new();
    loop {
        match conn.stream_recv(2, room.as_mut()) {
            Ok((0, _)) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

fn serve_stream(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    local: SocketAddr,
    stream: u64,
    serve: &Serve,
) {
    let mut head = Vec::with_capacity(8);
    let mut room = Unfilled::<64>::new();
    let prefix = loop {
        if head.len() >= 8 {
            return;
        }
        let read = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((0, _)) | Err(quiche::Error::Done) => None,
                Ok((n, _)) => Some(n),
                Err(_) => return,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&room.as_mut()[..n]);
        } else {
            {
                let Ok(conn) = shared.lock() else {
                    return;
                };
                if conn.is_closed() {
                    return;
                }
            }
            std::thread::sleep(STREAM_POLL);
            continue;
        }
        if head.is_empty() {
            continue;
        }
        let want = 1usize << usize::from(head[0] >> 6);
        if head.len() >= want {
            let Some(consumed) = hysteria::read_tcp_prefix(&head) else {
                return;
            };
            break consumed;
        }
    };
    let mut flow = Flow::from_parts(
        Arc::clone(shared),
        Arc::clone(sock),
        local,
        stream,
        head,
        false,
    );
    // The prefix stays in the buffer and the cursor steps over it, so no payload byte is moved.
    flow.at = prefix;
    serve(flow);
}

/// Bring one datagram association up: resolve the address the client named, connect a target socket of the matching family, and hand a reader thread the same socket so its replies return over the lane. `None` when the address is unresolvable or no socket can be raised, and the datagram is then dropped.
fn open_udp(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    session: u32,
    address: &str,
) -> Option<UdpFlow> {
    let peer = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())?;
    let bind = if peer.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let target = UdpSocket::bind(bind).ok()?;
    target.connect(peer).ok()?;
    target.set_read_timeout(Some(UDP_POLL)).ok()?;
    let target = Arc::new(target);
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::spawn({
        let shared = Arc::clone(shared);
        let sock = Arc::clone(sock);
        let target = Arc::clone(&target);
        let stop = Arc::clone(&stop);
        let address = address.to_owned();
        move || udp_reader(&shared, &sock, &target, &stop, session, &address)
    });
    Some(UdpFlow {
        target,
        defrag: Defrag::new(),
        last: Instant::now(),
        stop,
    })
}

/// Read the target socket and put every reply back on the lane, fragmenting to the peer's writable datagram size so a large response still arrives: one packet id per reply, its fragments sharing it, exactly as the client sends to us. A read that only timed out checks whether the reap or the closed connection told it to stop, so the thread lives no longer than one poll past its association.
fn udp_reader(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    target: &Arc<UdpSocket>,
    stop: &AtomicBool,
    session: u32,
    address: &str,
) {
    // One buffer for a whole target reply and one for the wire, both kept at capacity across the association's life so a steady relay never reallocates; the fragments view `buf`, so they are rebuilt each read rather than carried.
    let mut buf = vec![0u8; UDP_TARGET_BUF];
    let mut wire = Vec::new();
    let mut out = Unfilled::<MAX_DATAGRAM>::new();
    let mut packet = 0u16;
    loop {
        let n = match target.recv(&mut buf) {
            Ok(n) => n,
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let closed = shared.lock().map_or(true, |conn| conn.is_closed());
                if closed || stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        let Ok(mut conn) = shared.lock() else {
            break;
        };
        if conn.is_closed() {
            break;
        }
        let Some(max) = conn.dgram_max_writable_len() else {
            break;
        };
        packet = packet.wrapping_add(1);
        let message = UdpMessage {
            session,
            packet,
            frag: 0,
            frags: 1,
            address,
            payload: &buf[..n],
        };
        let mut frags = Vec::new();
        if hysteria::fragment_udp(&message, max, &mut frags).is_err() {
            break;
        }
        for frag in &frags {
            wire.clear();
            if hysteria::encode_udp(frag, &mut wire).is_ok() {
                let _ = conn.dgram_send(&wire);
            }
        }
        flush(sock, &mut conn, out.as_mut());
    }
}

/// The one datagram flow a client association currently relays: the session id its datagrams carry (never reused on the connection, so a late server packet cannot misroute to a new flow) and the destination the socks front asked for, which is what a reply is re-wrapped with.
struct Association {
    session_id: u32,
    destination: SocketAddr,
}

/// What the writer and the reader of one client association share: the flow now relayed, the reassembly its fragments feed, and the client address the relay last sent from. Only the writer rotates a flow, and only after the connection lock is held, so the reader never relays against a half-applied change and a retired flow's late datagrams land on the floor rather than on the new association.
struct Lane {
    flow: Mutex<Option<Association>>,
    defrag: Mutex<Defrag>,
    source: Mutex<Option<SocketAddr>>,
}

/// The client's UDP uplink over the hysteria carrier: read the relay socket, put every datagram on the connection's datagram lane, and let a companion thread drive the connection and carry replies back. One destination at a time — a change rotates the association, stamping a fresh session id that the connection has never used, over a connection of its own: the pool is a TCP instrument, its staleness caught by a flow's reply deadline a datagram send has no answer to, so a lane dials fresh and is live from the first packet. The relay's read timeout, `budgets::udp_idle()`, is already armed where the front was raised, so silence ends the loop and retires the association with its reader; a server that refused the lane in auth is answered in silence, as the references do. Salamander obfuscation, when the outbound names it, is already wrapped at the `quic::Datagram` seam by `connect`, so no byte of this path changes when the password is set.
pub(crate) fn serve_udp(relay: &UdpSocket, dial: &Dial) {
    let Some(session) = connect(dial) else {
        return;
    };
    if !session.udp_supported {
        return;
    }
    // The reader answers through its own handle on the same relay socket; a clone that fails means the front is already gone.
    let Ok(reply) = relay.try_clone() else {
        return;
    };
    let lane = Arc::new(Lane {
        flow: Mutex::new(None),
        defrag: Mutex::new(Defrag::new()),
        source: Mutex::new(None),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let reader = std::thread::spawn({
        let session = session.clone();
        let lane = Arc::clone(&lane);
        let stop = Arc::clone(&stop);
        move || client_reader(&session, &lane, &stop, &reply)
    });
    let mut buf = vec![0u8; UDP_TARGET_BUF];
    // One wire buffer and one packet buffer, kept at capacity across the association's life so a steady relay never reallocates. The fragment list is born in the loop because its messages borrow the message's own bytes.
    let mut wire = Vec::with_capacity(UDP_TARGET_BUF + 64);
    let mut out = Unfilled::<MAX_DATAGRAM>::new();
    let mut packet = 0u16;
    // Ids the lane stamps, taken in order and never reused on this connection, so a late reply to a retired flow cannot land on a new one.
    let mut next_id = 1u32;
    // The flow now relayed, cached off the rotation: the id it stamps, the destination compared per packet, and the string the wire's address field borrows — so no steady packet re-formats the address or takes the flow lock.
    let mut relayed: Option<(u32, SocketAddr, String)> = None;
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        let Ok(mut conn) = session.shared.lock() else {
            break;
        };
        if conn.is_closed() {
            break;
        }
        // A connection that takes no datagrams cannot carry the lane.
        let Some(max) = conn.dgram_max_writable_len() else {
            break;
        };
        if let Ok(mut slot) = lane.source.lock() {
            *slot = Some(src);
        }
        if relayed.as_ref().is_none_or(|(_, held, _)| *held != dest) {
            let id = next_id;
            next_id += 1;
            let address = dest.to_string();
            if let Ok(mut slot) = lane.flow.lock() {
                *slot = Some(Association {
                    session_id: id,
                    destination: dest,
                });
            }
            if let Ok(mut reassembly) = lane.defrag.lock() {
                *reassembly = Defrag::new();
            }
            relayed = Some((id, dest, address));
        }
        let Some((session_id, _, address)) = &relayed else {
            continue;
        };
        let session_id = *session_id;
        packet = packet.wrapping_add(1);
        let message = UdpMessage {
            session: session_id,
            packet,
            frag: 0,
            frags: 1,
            address,
            payload,
        };
        let mut frags = Vec::new();
        if hysteria::fragment_udp(&message, max, &mut frags).is_err() {
            continue;
        }
        for frag in &frags {
            wire.clear();
            if hysteria::encode_udp(frag, &mut wire).is_ok() {
                let _ = conn.dgram_send(&wire);
            }
        }
        flush(&session.sock, &mut conn, out.as_mut());
    }
    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();
}

/// Drive the connection and hand every whole datagram of the flow being relayed back to the relay socket, re-wrapped in the socks5 UDP frame the client sent its first packet in. The drive stays `drive_once`'s, shared with the TCP pump, so writer and reader take the connection lock in the same one-turn shape and neither holds it across a socket wait; the `UDP_POLL` bound is how long a stop flag outlives the reader, since a UDP socket has no shutdown to wake a blocked read.
fn client_reader(session: &Session, lane: &Lane, stop: &AtomicBool, relay: &UdpSocket) {
    let mut applied = None;
    let mut reply = Vec::with_capacity(3 + 25 + UDP_TARGET_BUF);
    loop {
        if stop.load(Ordering::Relaxed) || !drive_once(session, UDP_POLL, &mut applied) {
            break;
        }
        let Ok(mut conn) = session.shared.lock() else {
            break;
        };
        while let Ok(data) = conn.dgram_recv_buf() {
            let Ok(message) = hysteria::decode_udp(&data) else {
                continue;
            };
            let Ok(held) = lane.flow.lock() else {
                break;
            };
            let Some(association) = held.as_ref() else {
                continue;
            };
            if message.session != association.session_id {
                continue;
            }
            let destination = association.destination;
            drop(held);
            let Some((_address, payload)) = lane
                .defrag
                .lock()
                .ok()
                .and_then(|mut reassembly| reassembly.feed(&message).ok().flatten())
            else {
                continue;
            };
            let Some(src) = lane.source.lock().ok().and_then(|slot| *slot) else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            crate::proxy::push_socks_addr(&mut reply, &destination);
            reply.extend_from_slice(&payload);
            let _ = relay.send_to(&reply, src);
        }
    }
}

/// Fold every datagram that arrived on this connection into its session's reassembly and relay the whole messages to their target sockets, raising an association on a session's first datagram. A datagram before auth is not for the lane yet, and a reassembly that rejects a forged fragment retires its session.
fn relay_datagrams(
    routes: &mut HashMap<Vec<u8>, Inbound>,
    sock: &Arc<crate::quic::Datagram>,
    shared: &Arc<Mutex<quiche::Connection>>,
    dcid: &[u8],
    conn: &mut quiche::Connection,
) {
    while let Ok(data) = conn.dgram_recv_buf() {
        let Ok(message) = hysteria::decode_udp(&data) else {
            continue;
        };
        let Some(inbound) = routes.get_mut(dcid) else {
            return;
        };
        if !inbound.authed {
            continue;
        }
        let session = message.session;
        let flow = match inbound.udp.entry(session) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(vacant) => {
                let Some(opened) = open_udp(shared, sock, session, message.address) else {
                    continue;
                };
                vacant.insert(opened)
            }
        };
        let whole = flow.defrag.feed(&message);
        flow.last = Instant::now();
        let forged = whole.is_err();
        match whole {
            Ok(Some((_address, payload))) => {
                let _ = flow.target.send(&payload);
            }
            Ok(None) => {}
            Err(_) => flow.stop.store(true, Ordering::Relaxed),
        }
        if forged {
            inbound.udp.remove(&session);
        }
    }
}

struct Router<'a> {
    sock: Arc<crate::quic::Datagram>,
    local: SocketAddr,
    out: Unfilled<MAX_DATAGRAM>,
    auths: &'a [String],
    serve: &'a Serve,
    routes: HashMap<Vec<u8>, Inbound>,
}

fn flush(sock: &crate::quic::Datagram, conn: &mut quiche::Connection, out: &mut [u8]) {
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

fn auth_exchange(
    sock: &crate::quic::Datagram,
    out: &mut [u8],
    conn: &mut quiche::Connection,
    auths: &[String],
    inbound: &mut Inbound,
) -> Option<bool> {
    let mut room = Unfilled::<4096>::new();
    loop {
        match conn.stream_recv(AUTH_STREAM, room.as_mut()) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => inbound.auth_buf.extend_from_slice(&room.as_mut()[..n]),
        }
    }
    if inbound.auth_buf.len() >= HEAD_CAP {
        return Some(false);
    }
    let mut at = 0usize;
    let body = frames::h3_frame(&inbound.auth_buf, &mut at)
        .filter(|frame| frame.kind == frames::H3_HEADERS)
        .and_then(|frame| inbound.auth_buf.get(at..at + frame.length as usize))?;
    let ok = auths
        .iter()
        .any(|auth| hysteria::verify_auth_request(body, auth));
    if !answer_auth(conn, ok) {
        return None;
    }
    flush(sock, conn, out);
    inbound.auth_buf.clear();
    inbound.authed = true;
    Some(ok)
}

impl Router<'_> {
    fn accept(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        template: &mut quiche::Config,
        client_cid: &[u8],
    ) {
        let mut scid = [0u8; SCID_LEN];
        if getrandom::getrandom(&mut scid).is_err() {
            return;
        }
        let cid = quiche::ConnectionId::from_ref(&scid);
        let Ok(mut conn) = quiche::accept(&cid, None, self.local, from, template) else {
            return;
        };
        let info = quiche::RecvInfo {
            from,
            to: self.local,
        };
        if conn.recv(packet, info).is_err() {
            return;
        }
        flush(&self.sock, &mut conn, self.out.as_mut());
        self.routes.insert(
            scid.to_vec(),
            Inbound {
                conn: Arc::new(Mutex::new(conn)),
                client_cid: client_cid.to_vec(),
                authed: false,
                settings_sent: false,
                settings_done: false,
                auth_buf: Vec::new(),
                served: HashSet::new(),
                udp: HashMap::new(),
            },
        );
    }

    fn drive(&mut self, dcid: &[u8], packet: &mut [u8], from: SocketAddr) {
        let Self {
            routes,
            sock,
            out,
            auths,
            serve,
            local,
        } = self;
        let Some(shared) = routes.get(dcid).map(|i| Arc::clone(&i.conn)) else {
            return;
        };
        let info = quiche::RecvInfo { from, to: *local };
        {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.recv(packet, info).is_err() {
                return;
            }
            flush(sock, &mut conn, out.as_mut());
            if !conn.is_established() || conn.is_closed() {
                return;
            }
            let Some((mut settings_done, settings_sent, authed)) = routes
                .get(dcid)
                .map(|i| (i.settings_done, i.settings_sent, i.authed))
            else {
                return;
            };
            if !settings_done {
                settings_done = drain_settings(&mut conn);
                if settings_done {
                    if let Some(inbound) = routes.get_mut(dcid) {
                        inbound.settings_done = true;
                    }
                }
            }
            // The server's SETTINGS go out before its auth answer: a client whose H3 stack waits for them, as the pinned one does, posts its auth only after they arrive.
            if !settings_sent {
                let mut settings = Vec::new();
                frames::quic_varint(&mut settings, 0x04);
                frames::quic_varint(&mut settings, 0);
                let _ = conn.stream_send(3, &settings, true);
                flush(sock, &mut conn, out.as_mut());
                if let Some(inbound) = routes.get_mut(dcid) {
                    inbound.settings_sent = true;
                }
            }
            if !authed {
                let Some(inbound) = routes.get_mut(dcid) else {
                    return;
                };
                let Some(ok) = auth_exchange(sock, out.as_mut(), &mut conn, auths, inbound) else {
                    return;
                };
                if !ok {
                    let _ = conn.close(false, 0, b"refused");
                    flush(sock, &mut conn, out.as_mut());
                    return;
                }
            }
            for id in conn.readable() {
                if id < FIRST_FLOW_STREAM || id % 4 != 0 {
                    continue;
                }
                let Some(inbound) = routes.get_mut(dcid) else {
                    return;
                };
                if inbound.served.contains(&id) {
                    continue;
                }
                inbound.served.insert(id);
                let thread_shared = Arc::clone(&shared);
                let thread_sock = Arc::clone(sock);
                let thread_serve = Arc::clone(serve);
                let local = *local;
                std::thread::spawn(move || {
                    serve_stream(&thread_shared, &thread_sock, local, id, &thread_serve);
                });
            }
            relay_datagrams(routes, sock, &shared, dcid, &mut conn);
            flush(sock, &mut conn, out.as_mut());
        }
    }

    fn idle(&mut self) {
        let Self {
            routes, sock, out, ..
        } = self;
        let now = Instant::now();
        // One pass, one lock per route: the dead are dropped where they are found, the living take their turn of the wheel, and a datagram association idle past the timeout is told to stop so its reader ends within one poll.
        routes.retain(|_, inbound| {
            let Ok(mut conn) = inbound.conn.lock() else {
                return true;
            };
            if conn.is_closed() {
                for flow in inbound.udp.values() {
                    flow.stop.store(true, Ordering::Relaxed);
                }
                inbound.udp.clear();
                return false;
            }
            conn.on_timeout();
            flush(sock, &mut conn, out.as_mut());
            inbound.udp.retain(|_, flow| {
                if now.duration_since(flow.last) > UDP_IDLE {
                    flow.stop.store(true, Ordering::Relaxed);
                    false
                } else {
                    true
                }
            });
            true
        });
    }
}

pub(crate) fn serve_loop(
    address: &str,
    auths: &[String],
    cc: hysteria::Congestion,
    cert_path: &str,
    key_path: &str,
    obfs_password: &str,
    serve: &Serve,
) {
    let Some(bound) = address.to_socket_addrs().ok().and_then(|mut it| it.next()) else {
        return;
    };
    let Ok(sock) = crate::quic::bind_datagram(address) else {
        return;
    };
    let local = sock.local_addr().unwrap_or(bound);
    let Some(mut template) = server_config(cert_path, key_path, cc) else {
        return;
    };
    let sock = match hysteria::Salamander::new(obfs_password) {
        Some(obfs) => crate::quic::Datagram::obfuscated(sock, obfs),
        None => crate::quic::Datagram::plain(sock),
    };
    let mut router = Router {
        sock: Arc::new(sock),
        local,
        out: Unfilled::<MAX_DATAGRAM>::new(),
        auths,
        serve,
        routes: HashMap::new(),
    };
    let mut buf = Unfilled::<MAX_DATAGRAM>::new();
    if router.sock.set_read_timeout(Some(ROUTE_POLL)).is_err() {
        return;
    }
    loop {
        match router.sock.recv_from(buf.as_mut()) {
            Ok((n, from)) => {
                let packet = buf.as_mut();
                let Ok(header) = quiche::Header::from_slice(&mut packet[..n], SCID_LEN) else {
                    continue;
                };
                if header.ty != quiche::Type::Short && header.version != quiche::PROTOCOL_VERSION {
                    continue;
                }
                let initial = header.ty == quiche::Type::Initial;
                let dcid = header.dcid.as_ref();
                let peer_cid = header.scid.as_ref();
                if dcid.len() > 20 || peer_cid.len() > 20 {
                    continue;
                }
                let mut dcid_buf = [0u8; 20];
                dcid_buf[..dcid.len()].copy_from_slice(dcid);
                let mut peer_buf = [0u8; 20];
                peer_buf[..peer_cid.len()].copy_from_slice(peer_cid);
                let dcid = &dcid_buf[..dcid.len()];
                let peer_cid = &peer_buf[..peer_cid.len()];
                if initial {
                    if let Some(key) = router.routes.iter().find_map(|(key, inbound)| {
                        (inbound.client_cid.as_slice() == peer_cid).then(|| key.clone())
                    }) {
                        router.drive(&key, &mut packet[..n], from);
                    } else if !router.routes.contains_key(dcid) {
                        router.accept(&mut packet[..n], from, &mut template, peer_cid);
                    } else {
                        router.drive(dcid, &mut packet[..n], from);
                    }
                } else {
                    router.drive(dcid, &mut packet[..n], from);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                router.idle();
            }
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_refuses_without_a_chain_it_can_read() {
        let cc = hysteria::Congestion::Bbr;
        assert!(server_config("/nonexistent.crt", "/nonexistent.key", cc).is_none());
    }

    fn idle_session() -> Session {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        let scid = [7u8; SCID_LEN];
        let cid = quiche::ConnectionId::from_ref(&scid);
        let local = "127.0.0.1:0".parse().expect("addr");
        let peer = "127.0.0.1:1".parse().expect("addr");
        let conn = quiche::connect(None, &cid, local, peer, &mut config).expect("connects");
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
        Session {
            shared: Arc::new(Mutex::new(conn)),
            sock: Arc::new(crate::quic::Datagram::plain(sock)),
            local,
            udp_supported: false,
        }
    }

    #[test]
    fn a_parsed_request_leaves_its_payload_where_it_landed() {
        let session = idle_session();
        let mut head = Vec::new();
        hysteria::encode_tcp_request("127.0.0.1:8080", &[9, 9], &mut head);
        head.extend_from_slice(b"vless-bytes-behind-the-request");
        let mut flow = Flow::from_parts(
            Arc::clone(&session.shared),
            Arc::clone(&session.sock),
            session.local,
            FIRST_FLOW_STREAM,
            head,
            true,
        );
        // The state serve_stream hands over: the frame type stepped over, nothing moved.
        flow.at = hysteria::read_tcp_prefix(&flow.backlog).expect("prefix");
        let base = flow.backlog.as_ptr();
        let room = flow.backlog.capacity();
        let deadline = Instant::now() + Duration::from_secs(1);
        let address = read_request(&mut flow, deadline).expect("parses");
        assert_eq!(address, "127.0.0.1:8080");
        assert_eq!(flow.backlog.as_ptr(), base, "the payload never moved");
        assert_eq!(flow.backlog.capacity(), room, "no reallocation");
        assert_eq!(&flow.backlog[flow.at..], b"vless-bytes-behind-the-request");
    }
}
