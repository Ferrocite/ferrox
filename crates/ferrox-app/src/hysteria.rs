use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::frames;
use ferrox_core::hysteria;

use crate::quic::{Unfilled, MAX_DATAGRAM};

const AUTH_STREAM: u64 = 0;

const FIRST_FLOW_STREAM: u64 = 4;

const HEAD_CAP: usize = 16 * 1024;

const ROUTE_POLL: Duration = Duration::from_millis(100);

const STREAM_POLL: Duration = Duration::from_millis(5);

const SCID_LEN: usize = 16;

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

fn post_auth(session: &Session, host: &str, auth: &str) -> bool {
    let mut block = Vec::with_capacity(64 + host.len() + auth.len());
    hysteria::build_auth_request(host, auth, &mut block);
    let mut frame = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut frame, frames::H3_HEADERS);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    if !send_all(session, AUTH_STREAM, &frame, true) {
        return false;
    }
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let Some(body) = read_headers_block(session, AUTH_STREAM, deadline) else {
        return false;
    };
    hysteria::verify_auth_response(&body)
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
    let Ok(mut conn) = quiche::connect(Some(&dial.host), &cid, local, peer, &mut config) else {
        return None;
    };
    let sock = crate::quic::Datagram::plain(sock);
    crate::quic::drive_handshake(&mut conn, &sock, local)?;
    let session = Session {
        shared: Arc::new(Mutex::new(conn)),
        sock: Arc::new(sock),
        local,
    };
    if !control_settings(&session) {
        return None;
    }
    if !post_auth(&session, &dial.host, &dial.config.auth) {
        return None;
    }
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
    client: &TcpStream,
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

pub(crate) fn relay(tcp: &TcpStream, flow: &Flow) {
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
}

fn answer_auth(conn: &mut quiche::Connection, ok: bool) -> bool {
    let mut block = Vec::with_capacity(32);
    if ok {
        hysteria::build_auth_response(&mut block);
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
        }
    }

    fn idle(&mut self) {
        let Self {
            routes, sock, out, ..
        } = self;
        // One pass, one lock per route: the dead are dropped where they are found, and the living take their turn of the wheel.
        routes.retain(|_, inbound| {
            let Ok(mut conn) = inbound.conn.lock() else {
                return true;
            };
            if conn.is_closed() {
                return false;
            }
            conn.on_timeout();
            flush(sock, &mut conn, out.as_mut());
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
    let mut router = Router {
        sock: Arc::new(crate::quic::Datagram::plain(sock)),
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
