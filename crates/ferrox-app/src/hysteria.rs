use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::frames;
use ferrox_core::hysteria;

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
    let mut buf = [0u8; crate::quic::MAX_DATAGRAM];
    let incoming = match session.sock.recv_from(&mut buf) {
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
            let _ = conn.recv(&mut buf[..n], info);
        }
        None => conn.on_timeout(),
    }
    crate::quic::flush_egress(&mut conn, &session.sock);
    true
}

fn recv_exact(session: &Session, stream: u64, want: usize, deadline: Instant) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(want);
    let mut chunk = [0u8; 8192];
    let mut applied = None;
    while out.len() < want {
        let end = (want - out.len()).min(chunk.len());
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, &mut chunk[..end]) {
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        if let Some(n) = read {
            out.extend_from_slice(&chunk[..n]);
        } else {
            if Instant::now() >= deadline {
                return None;
            }
            let _ = drive_once(session, STREAM_POLL, &mut applied);
        }
    }
    (out.len() == want).then_some(out)
}

fn read_headers_block(session: &Session, stream: u64, deadline: Instant) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(128);
    let mut chunk = [0u8; 4096];
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
            if let Some(body) = head.get(at..at + frame.length as usize) {
                return Some(body.to_vec());
            }
        }
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, &mut chunk) {
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&chunk[..n]);
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

pub(crate) fn connect(dial: &Dial) -> Option<Session> {
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

pub(crate) fn open_flow(session: &Session, header: &[u8]) -> Option<Flow> {
    let mut prefix = Vec::with_capacity(2 + header.len());
    hysteria::tcp_prefix(&mut prefix);
    prefix.extend_from_slice(header);
    if !send_all(session, FIRST_FLOW_STREAM, &prefix, false) {
        return None;
    }
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let reply = recv_exact(session, FIRST_FLOW_STREAM, 2, deadline)?;
    if reply.as_slice() != [0, 0] {
        return None;
    }
    Some(Flow {
        session: session.clone(),
        stream: FIRST_FLOW_STREAM,
        backlog: Vec::new(),
        at: 0,
        drive: true,
    })
}

/// Reads a Hysteria v2 TCP request body whose `0x401` frame type is already consumed, leaving any payload that followed it in the backlog.
pub(crate) fn read_request(flow: &mut Flow, deadline: Instant) -> Option<String> {
    let mut head: Vec<u8> = flow.backlog.split_off(flow.at);
    flow.backlog.clear();
    flow.at = 0;
    let mut chunk = [0u8; 4096];
    loop {
        match hysteria::decode_tcp_request_body(&head) {
            Ok((address, used)) => {
                flow.backlog = head[used..].to_vec();
                return Some(address.to_owned());
            }
            Err(hysteria::RequestError::Invalid) => return None,
            Err(hysteria::RequestError::Incomplete) => {
                if head.len() >= HEAD_CAP || Instant::now() >= deadline {
                    return None;
                }
                let n = flow.read(&mut chunk).ok()?;
                if n == 0 {
                    return None;
                }
                head.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

pub(crate) fn dial_vless(client: &TcpStream, dial: &Dial, id: &[u8; 16], target: &SocketAddr) {
    let Some(session) = connect(dial) else {
        return;
    };
    let header = crate::proxy::vless_header(id, 1, target);
    let Some(flow) = open_flow(&session, &header) else {
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

fn drain_settings(conn: &mut quiche::Connection) {
    let mut junk = [0u8; 128];
    while let Ok((n, _)) = conn.stream_recv(2, &mut junk) {
        if n == 0 {
            break;
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
    let mut chunk = [0u8; 64];
    let prefix = loop {
        if head.len() >= 8 {
            return;
        }
        let read = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            match conn.stream_recv(stream, &mut chunk) {
                Ok((0, _)) | Err(quiche::Error::Done) => None,
                Ok((n, _)) => Some(n),
                Err(_) => return,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&chunk[..n]);
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
    serve(Flow::from_parts(
        Arc::clone(shared),
        Arc::clone(sock),
        local,
        stream,
        head[prefix..].to_vec(),
        false,
    ));
}

struct Router<'a> {
    sock: Arc<crate::quic::Datagram>,
    local: SocketAddr,
    out: [u8; 1350],
    auths: &'a [String],
    serve: &'a Serve,
    routes: HashMap<Vec<u8>, Inbound>,
}

fn flush(sock: &crate::quic::Datagram, conn: &mut quiche::Connection, out: &mut [u8; 1350]) {
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

fn auth_exchange(
    sock: &crate::quic::Datagram,
    out: &mut [u8; 1350],
    conn: &mut quiche::Connection,
    auths: &[String],
    inbound: &mut Inbound,
) -> Option<bool> {
    let mut chunk = [0u8; 4096];
    loop {
        match conn.stream_recv(AUTH_STREAM, &mut chunk) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => inbound.auth_buf.extend_from_slice(&chunk[..n]),
        }
    }
    if inbound.auth_buf.len() >= HEAD_CAP {
        return Some(false);
    }
    let mut at = 0usize;
    let ready = frames::h3_frame(&inbound.auth_buf, &mut at)
        .filter(|frame| frame.kind == frames::H3_HEADERS)
        .and_then(|frame| inbound.auth_buf.get(at..at + frame.length as usize))
        .map(<[u8]>::to_vec);
    let body = ready?;
    let ok = auths
        .iter()
        .any(|auth| hysteria::verify_auth_request(&body, auth));
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
        flush(&self.sock, &mut conn, &mut self.out);
        self.routes.insert(
            scid.to_vec(),
            Inbound {
                conn: Arc::new(Mutex::new(conn)),
                client_cid: client_cid.to_vec(),
                authed: false,
                settings_sent: false,
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
            flush(sock, &mut conn, out);
            if !conn.is_established() || conn.is_closed() {
                return;
            }
            drain_settings(&mut conn);
            // The server's SETTINGS go out before its auth answer: a client whose H3 stack waits for them, as the pinned one does, posts its auth only after they arrive.
            if routes.get(dcid).is_some_and(|i| !i.settings_sent) {
                let mut settings = Vec::new();
                frames::quic_varint(&mut settings, 0x04);
                frames::quic_varint(&mut settings, 0);
                let _ = conn.stream_send(3, &settings, true);
                flush(sock, &mut conn, out);
                if let Some(inbound) = routes.get_mut(dcid) {
                    inbound.settings_sent = true;
                }
            }
            let authed = routes.get(dcid).is_some_and(|i| i.authed);
            if !authed {
                let Some(inbound) = routes.get_mut(dcid) else {
                    return;
                };
                let Some(ok) = auth_exchange(sock, out, &mut conn, auths, inbound) else {
                    return;
                };
                if !ok {
                    let _ = conn.close(false, 0, b"refused");
                    flush(sock, &mut conn, out);
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
        let dead: Vec<Vec<u8>> = routes
            .iter()
            .filter(|(_, inbound)| inbound.conn.lock().is_ok_and(|conn| conn.is_closed()))
            .map(|(id, _)| id.clone())
            .collect();
        for id in dead {
            routes.remove(&id);
        }
        for inbound in routes.values() {
            let Ok(mut conn) = inbound.conn.lock() else {
                continue;
            };
            conn.on_timeout();
            flush(sock, &mut conn, out);
        }
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
        out: [0u8; 1350],
        auths,
        serve,
        routes: HashMap::new(),
    };
    let mut buf = [0u8; 1350];
    if router.sock.set_read_timeout(Some(ROUTE_POLL)).is_err() {
        return;
    }
    loop {
        match router.sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let Ok(header) = quiche::Header::from_slice(&mut buf[..n], SCID_LEN) else {
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
                        router.drive(&key, &mut buf[..n], from);
                    } else if !router.routes.contains_key(dcid) {
                        router.accept(&mut buf[..n], from, &mut template, peer_cid);
                    } else {
                        router.drive(dcid, &mut buf[..n], from);
                    }
                } else {
                    router.drive(dcid, &mut buf[..n], from);
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
}
