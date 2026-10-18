use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::frames;
use ferrox_core::hysteria::{self, Defrag, Masquerade, UdpMessage};

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
    let obfs = hysteria::Salamander::new(&dial.config.obfs_password);
    // A hop plan rotates the server port over a fresh socket per stay; salamander still seals each datagram, so only the destination and socket move, never a frame above.
    let sock = match dial
        .config
        .hop
        .as_ref()
        .filter(|hop| !hop.ranges.is_empty())
    {
        Some(hop) => {
            let bind = if peer.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            crate::quic::Datagram::hopped(peer, hop.ports(), hop.interval_ms, bind, &sock, obfs)
                .ok()?
        }
        None => match obfs {
            Some(obfs) => crate::quic::Datagram::obfuscated(sock, obfs),
            None => crate::quic::Datagram::plain(sock),
        },
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
    /// A hop plan is its own connection: a hopped dial never reuses a plain one to the
    /// same address, nor the reverse, since the two move the server port differently.
    hop: Option<hysteria::Hop>,
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
        hop: dial.config.hop.clone(),
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
    peer: SocketAddr,
    masq: &Masquerade,
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
                // Not a hysteria flow prefix. A stream opening with an HTTP/3 frame type is a browser asking for a page in a flow's slot: answer it as the cover site. Any other prefix is dropped, exactly as an unreadable flow was.
                if matches!(
                    frames::quic_read(&head, &mut 0usize),
                    Some(kind) if kind == frames::H3_HEADERS || kind == frames::H3_DATA
                ) {
                    serve_masquerade_stream(shared, sock, stream, head, peer, masq);
                }
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

/// How long a masquerade origin may take to answer before the cover gives up and answers the bad-gateway line.
const ORIGIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The most bytes a masquerade origin's reply may grow to before the reader stops, so a cover page never buffers without bound; the wire's own single-datagram ceiling is the natural cap.
const MASQ_BODY_CAP: usize = hysteria::MAX_UDP_PAYLOAD;

/// Answers a browser request that arrived on a flow slot: read the whole request off the stream, build the cover response, and finish the stream with it so the browser sees a complete reply while the connection stays up for its next request.
fn serve_masquerade_stream(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    stream: u64,
    seed: Vec<u8>,
    peer: SocketAddr,
    masq: &Masquerade,
) {
    let Some(request) = read_h3_request(shared, stream, seed) else {
        return;
    };
    let peer = peer.to_string();
    let mut reply = Vec::new();
    masq_bytes(masq, &request, Some(&peer), &mut reply);
    let Ok(mut conn) = shared.lock() else {
        return;
    };
    if conn.is_closed() {
        return;
    }
    let _ = conn.stream_send(stream, &reply, true);
    crate::quic::flush_egress(&mut conn, sock);
}

/// Reads a browser's HTTP/3 request off a stream the router has already begun: the bytes in `buf` first, then whatever still arrives. A request whose headers are whole and which declares no body returns at once, so a keep-alive stream the browser leaves open never blocks the cover; a body is drained only until its declared length or the stream's finish.
fn read_h3_request(
    shared: &Arc<Mutex<quiche::Connection>>,
    stream: u64,
    mut buf: Vec<u8>,
) -> Option<hysteria::H3Request> {
    let mut room = Unfilled::<4096>::new();
    loop {
        if let Some(request) = assemble_request(&buf) {
            let declares_body = request.headers.iter().any(|(name, _)| {
                name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
            });
            if !declares_body || !request.body.is_empty() {
                return Some(request);
            }
        }
        if buf.len() >= HEAD_CAP {
            return assemble_request(&buf);
        }
        let fin = {
            let Ok(mut conn) = shared.lock() else {
                return assemble_request(&buf);
            };
            if conn.is_closed() {
                return assemble_request(&buf);
            }
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((0, _)) | Err(quiche::Error::Done) => false,
                Ok((n, fin)) => {
                    buf.extend_from_slice(&room.as_mut()[..n]);
                    fin
                }
                Err(_) => return assemble_request(&buf),
            }
        };
        if fin {
            return assemble_request(&buf);
        }
        std::thread::sleep(STREAM_POLL);
    }
}

/// Walks a request stream's HTTP/3 frames once: the first `HEADERS` block becomes the request line and fields, and every `DATA` payload that follows becomes the body. `None` while any frame is still incomplete, so the reader keeps waiting rather than answering a half request.
fn assemble_request(bytes: &[u8]) -> Option<hysteria::H3Request> {
    let mut at = 0usize;
    let mut request: Option<hysteria::H3Request> = None;
    while let Some(frame) = frames::h3_frame(bytes, &mut at) {
        let end = at + frame.length as usize;
        let payload = bytes.get(at..end)?;
        match frame.kind {
            frames::H3_HEADERS if request.is_none() => {
                request = hysteria::parse_h3_request(payload);
            }
            frames::H3_DATA => {
                if let Some(request) = request.as_mut() {
                    request.body.extend_from_slice(payload);
                }
            }
            _ => {}
        }
        at = end;
    }
    request
}

/// Builds the HTTP/3 cover response for one request, dispatching on the configured masquerade type: a not-found, a canned line, a static file, or a reverse-proxied origin. The caller finishes the stream with these bytes.
fn masq_bytes(
    masq: &Masquerade,
    request: &hysteria::H3Request,
    peer: Option<&str>,
    out: &mut Vec<u8>,
) {
    match masq {
        Masquerade::NotFound => not_found(out),
        Masquerade::Response {
            status,
            headers,
            body,
        } => {
            let fields: Vec<(&str, &str)> = headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            hysteria::encode_h3_response(*status, &fields, body, out);
        }
        Masquerade::File { dir } => serve_file(dir, request, out),
        Masquerade::Proxy {
            url,
            rewrite_host,
            x_forwarded,
            insecure,
        } => serve_proxy(
            url,
            *rewrite_host,
            *x_forwarded,
            *insecure,
            request,
            peer,
            out,
        ),
    }
}

/// The plain not-found line the reference cover answers with, reused as the miss for a static file and the default type.
fn not_found(out: &mut Vec<u8>) {
    hysteria::encode_h3_response(
        404,
        &[("content-type", "text/plain; charset=utf-8")],
        b"404 page not found\n",
        out,
    );
}

/// Serves one static file under `dir` to a browser request, refusing any path that steps out of the root. A directory yields its `index.html`, else a minimal listing; an escaping, missing, or unreadable path yields the not-found.
fn serve_file(dir: &str, request: &hysteria::H3Request, out: &mut Vec<u8>) {
    let Some(path) = safe_path(dir, &request.path) else {
        return not_found(out);
    };
    if path.is_dir() {
        let index = path.join("index.html");
        if let Ok(bytes) = std::fs::read(&index) {
            let kind = hysteria::content_type(&index.to_string_lossy());
            return hysteria::encode_h3_response(200, &[("content-type", kind)], &bytes, out);
        }
        let listing = directory_listing(&path);
        return hysteria::encode_h3_response(
            200,
            &[("content-type", "text/html; charset=utf-8")],
            listing.as_bytes(),
            out,
        );
    }
    let kind = hysteria::content_type(&path.to_string_lossy());
    match std::fs::read(&path) {
        Ok(bytes) => hysteria::encode_h3_response(200, &[("content-type", kind)], &bytes, out),
        Err(_) => not_found(out),
    }
}

/// Resolves a browser `:path` to a file under `root`, percent-decoding it and rejecting any `..` step, so the served path never climbs above the masquerade directory. A leading slash names the directory's own root, not the filesystem's.
fn safe_path(root: &str, path: &str) -> Option<std::path::PathBuf> {
    let trimmed = path.split(['?', '#']).next().unwrap_or(path);
    let decoded = percent_decode(trimmed)?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let mut joined = std::path::PathBuf::from(root);
    for segment in text.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            other => {
                if other.contains('\\') || other.contains('\0') {
                    return None;
                }
                joined.push(other);
            }
        }
    }
    Some(joined)
}

/// A minimal HTML directory listing, used only when a masquerade directory has no `index.html`: enough of a page to pass as a static site's index.
fn directory_listing(dir: &std::path::Path) -> String {
    let name = dir.to_string_lossy();
    let mut html = format!("<!doctype html><html><head><title>Index of {name}</title></head><body><h1>Index of {name}</h1><ul>");
    let Ok(entries) = std::fs::read_dir(dir) else {
        html.push_str("</ul></body></html>");
        return html;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for entry in names {
        let esc = html_escape(&entry);
        html.push_str("<li><a href=\"");
        html.push_str(&esc);
        html.push_str("\">");
        html.push_str(&esc);
        html.push_str("</a></li>");
    }
    html.push_str("</ul></body></html>");
    html
}

/// The characters that must not leak raw into a listing's HTML, so a crafted filename cannot inject markup into the cover page.
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

/// Percent-decodes a URL path; a `%` not followed by two hex digits is not valid and rejects the whole path, so a half-decoded traversal never slips through.
fn percent_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex_val(*bytes.get(i + 1)?)?;
                let lo = hex_val(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Forwards a browser request to a masquerade origin over a hand-written HTTP/1.1 exchange and re-emits the reply as HTTP/3, dropping the origin's hop-by-hop headers. One connection per request, closed on the origin's `connection: close`; any failure to reach or parse the origin answers the bad-gateway line.
fn serve_proxy(
    url: &str,
    rewrite_host: bool,
    x_forwarded: bool,
    _insecure: bool,
    request: &hysteria::H3Request,
    peer: Option<&str>,
    out: &mut Vec<u8>,
) {
    match fetch_origin(url, request, rewrite_host, x_forwarded, peer) {
        Some(origin) => {
            let fields: Vec<(&str, &str)> = origin
                .headers
                .iter()
                .filter(|(name, _)| !is_hop_by_hop(name))
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            hysteria::encode_h3_response(origin.status, &fields, &origin.body, out);
        }
        None => hysteria::encode_h3_response(
            502,
            &[("content-type", "text/plain; charset=utf-8")],
            b"502 Bad Gateway\n",
            out,
        ),
    }
}

/// Dials the origin `url` names and runs one HTTP/1.1 exchange: `unix` connects a socket at the path, `http` resolves host and port, and `https` is a named ceiling the origin client does not carry, so it returns `None` and the caller answers bad-gateway.
fn fetch_origin(
    url: &str,
    request: &hysteria::H3Request,
    rewrite_host: bool,
    x_forwarded: bool,
    peer: Option<&str>,
) -> Option<hysteria::OriginResponse> {
    let (scheme, rest) = url.split_once("://")?;
    let head = origin_request(request, rest, rewrite_host, x_forwarded, peer);
    match scheme {
        "unix" => exchange_socket(rest, &head),
        "http" => exchange_tcp(rest, 80, &head),
        _ => None,
    }
}

/// Rebuilds the browser request as an HTTP/1.1 exchange line: the method and path, a `Host` from the origin or the request's own authority, the request's ordinary headers minus the hop-by-hop ones, and the forwarded headers when asked. The body follows its copied `content-length`.
fn origin_request(
    request: &hysteria::H3Request,
    authority: &str,
    rewrite_host: bool,
    x_forwarded: bool,
    peer: Option<&str>,
) -> Vec<u8> {
    let host = if rewrite_host || request.authority.is_empty() {
        authority
    } else {
        &request.authority
    };
    let target = if request.path.is_empty() {
        "/"
    } else {
        request.path.as_str()
    };
    let method = if request.method.is_empty() {
        "GET"
    } else {
        request.method.as_str()
    };
    let mut head = Vec::with_capacity(256 + request.body.len());
    let _ = write!(&mut head, "{method} {target} HTTP/1.1\r\n");
    let _ = write!(&mut head, "Host: {host}\r\n");
    for (name, value) in &request.headers {
        if is_hop_by_hop(name) {
            continue;
        }
        let _ = write!(&mut head, "{name}: {value}\r\n");
    }
    if x_forwarded {
        if let Some(for_ip) = peer {
            let _ = write!(&mut head, "X-Forwarded-For: {for_ip}\r\n");
        }
        let _ = write!(&mut head, "X-Forwarded-Proto: https\r\n");
    }
    let _ = write!(&mut head, "Connection: close\r\n");
    head.extend_from_slice(b"\r\n");
    head.extend_from_slice(&request.body);
    head
}

/// A header that belongs to one hop only and must not be copied onto an origin request or back to the browser.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Dials an origin over TCP and runs one closed exchange, defaulting the port the scheme implies when the authority omits one.
fn exchange_tcp(
    authority: &str,
    default_port: u16,
    head: &[u8],
) -> Option<hysteria::OriginResponse> {
    let host = authority.split('/').next().unwrap_or(authority);
    let (host_only, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (host, default_port),
    };
    let mut stream = TcpStream::connect((host_only, port)).ok()?;
    let _ = stream.set_read_timeout(Some(ORIGIN_TIMEOUT));
    stream.write_all(head).ok()?;
    stream.flush().ok()?;
    read_origin(&mut stream)
}

/// Dials an origin over a Unix socket and runs one closed exchange, with the pseudo authority the socket implies.
#[cfg(unix)]
fn exchange_socket(path: &str, head: &[u8]) -> Option<hysteria::OriginResponse> {
    let mut stream = UnixStream::connect(path).ok()?;
    let _ = stream.set_read_timeout(Some(ORIGIN_TIMEOUT));
    stream.write_all(head).ok()?;
    stream.flush().ok()?;
    read_origin(&mut stream)
}

/// On a platform with no Unix socket, the `unix` origin scheme is simply unreachable and answers bad-gateway.
#[cfg(not(unix))]
fn exchange_socket(_path: &str, _head: &[u8]) -> Option<hysteria::OriginResponse> {
    None
}

/// Reads an origin's whole HTTP/1.1 reply to its close, then reduces it to status, headers, and body; the buffered bytes stop at the cover's cap so a runaway origin never exhausts memory.
fn read_origin<R: Read>(stream: &mut R) -> Option<hysteria::OriginResponse> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() >= MASQ_BODY_CAP {
                    break;
                }
            }
        }
    }
    hysteria::parse_origin_response(&raw)
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
    masq: Arc<Masquerade>,
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
    peer: SocketAddr,
    masq: &Masquerade,
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
    // A request that is not the hysteria handshake shape is a browser: it is answered as the cover site on this very stream — the plain not-found when no richer cover is configured — and the connection is kept for its later requests. A right-shape, wrong-password handshake still falls through below and refuses exactly as a plain hysteria server would.
    if !hysteria::is_hysteria_auth_shape(body) {
        let request = hysteria::parse_h3_request(body).unwrap_or_default();
        inbound.auth_buf.clear();
        inbound.authed = true;
        let peer = peer.to_string();
        let mut reply = Vec::new();
        masq_bytes(masq, &request, Some(&peer), &mut reply);
        if conn.stream_send(AUTH_STREAM, &reply, true).is_err() {
            return None;
        }
        flush(sock, conn, out);
        return Some(true);
    }
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
            masq,
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
                let Some(ok) =
                    auth_exchange(sock, out.as_mut(), &mut conn, auths, inbound, from, masq)
                else {
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
                let thread_masq = Arc::clone(masq);
                let local = *local;
                let peer = from;
                std::thread::spawn(move || {
                    serve_stream(
                        &thread_shared,
                        &thread_sock,
                        local,
                        id,
                        &thread_serve,
                        peer,
                        &thread_masq,
                    );
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn serve_loop(
    address: &str,
    auths: &[String],
    cc: hysteria::Congestion,
    cert_path: &str,
    key_path: &str,
    obfs_password: &str,
    masq: &Masquerade,
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
        masq: Arc::from(masq.clone()),
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

    #[test]
    fn a_hop_plan_is_its_own_pool_key() {
        // The same address dialed with and without a hop plan is two connections: a hopped flow moves its server port and a plain one does not, so neither may ride the other's pooled socket.
        let dial = |hop: Option<hysteria::Hop>| Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 443,
            config: hysteria::Config {
                auth: "a".to_owned(),
                cc: hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                hop,
            },
            roots: None,
        };
        let plan = hysteria::Hop {
            ranges: vec![hysteria::PortRange {
                start: 443,
                end: 444,
            }],
            interval_ms: (5_000, 5_000),
        };
        assert_eq!(
            server_of(&dial(None)),
            server_of(&dial(None)),
            "plain reuses plain"
        );
        assert_eq!(
            server_of(&dial(Some(plan.clone()))),
            server_of(&dial(Some(plan.clone()))),
            "a plan reuses itself"
        );
        assert_ne!(
            server_of(&dial(None)),
            server_of(&dial(Some(plan))),
            "a hop never rides a plain connection"
        );
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
