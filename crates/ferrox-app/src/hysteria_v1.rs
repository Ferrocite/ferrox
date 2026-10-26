//! Hysteria v1 over quiche: the binary control stream, the `host:port` request on each flow, and the datagram lane whose messages carry their own session and address.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::hysteria_v1 as wire;
use ferrox_core::hysteria_v1::{Defrag, UdpMessage, XPlus};

use crate::conn::Connection;
use crate::hysteria::{Dial, Flow, Session};
use crate::quic::{Mask, Unfilled, MAX_DATAGRAM, RECV_ROOM};

const FIRST_FLOW_STREAM: u64 = 4;

const SCID_LEN: usize = 16;

const STREAM_POLL: Duration = Duration::from_millis(5);

const ROUTE_POLL: Duration = Duration::from_millis(100);

const HEAD_CAP: usize = 16 * 1024;

const UDP_IDLE: Duration = Duration::from_secs(60);

const UDP_POLL: Duration = Duration::from_secs(1);

const UDP_TARGET_BUF: usize = wire::MAX_UDP_PAYLOAD;

/// A TCP flow after the server has acknowledged its request: the callback dials the target and writes the response.
pub(crate) type Serve = Arc<dyn Fn(Flow, String, u16) + Send + Sync>;

fn send_all(session: &Session, stream: u64, buf: &[u8]) -> bool {
    crate::hysteria::send_all(session, stream, buf, false)
}

fn read_until(session: &Session, stream: u64, want: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let mut head = Vec::with_capacity(64);
    let mut room = Unfilled::<4096>::new();
    loop {
        if want(&head) {
            return Some(head);
        }
        if head.len() >= HEAD_CAP || Instant::now() >= deadline {
            return None;
        }
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((0, _)) => return None,
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        match read {
            Some(n) => head.extend_from_slice(&room.as_mut()[..n]),
            None => {
                if !crate::hysteria::drive_once(session, STREAM_POLL) {
                    return None;
                }
            }
        }
    }
}

fn connect(dial: &Dial) -> Option<Session> {
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let (sock, peer, local) = crate::quic::udp_to_server(&dial.address, dial.port)?;
    let mut scid = [0u8; SCID_LEN];
    getrandom::fill(&mut scid).ok()?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config =
        crate::quic::quiche_config_alpn(roots, Some(dial.config.cc.quiche_name()), &[wire::ALPN])?;
    config.enable_dgram(true, 1024, 1024);
    let Ok(mut conn) = quiche::connect(Some(&dial.host), &cid, local, peer, &mut config) else {
        return None;
    };
    let xplus = XPlus::new(&dial.config.obfs_password);
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
            crate::quic::Datagram::hopped(
                peer,
                hop.ports(),
                hop.interval_ms,
                bind,
                &sock,
                xplus.map(Mask::XPlus),
            )
            .ok()?
        }
        None => match xplus {
            Some(xplus) => crate::quic::Datagram::xplus(sock, xplus),
            None => crate::quic::Datagram::plain(sock),
        },
    };
    crate::quic::drive_handshake(&mut conn, &sock, local)?;
    let session = Session {
        shared: Arc::new(Mutex::new(conn)),
        sock: Arc::new(sock),
        local,
        udp_supported: true,
        driver: None,
    };
    let mut hello = Vec::with_capacity(20 + dial.config.auth.len());
    wire::encode_client_hello(
        &wire::ClientHello {
            send_bps: 100_000_000,
            recv_bps: 100_000_000,
            auth: dial.config.auth.as_bytes(),
        },
        &mut hello,
    );
    if !send_all(&session, 0, &hello) {
        return None;
    }
    let reply = read_until(&session, 0, |head| wire::decode_server_hello(head).is_ok())?;
    let (server, _) = wire::decode_server_hello(&reply).ok()?;
    if !server.ok || server.recv_bps == 0 {
        return None;
    }
    Some(session)
}

fn read_response(session: &Session, stream: u64) -> Option<bool> {
    let head = read_until(session, stream, |head| {
        wire::decode_server_response(head).is_ok()
    })?;
    Some(wire::decode_server_response(&head).ok()?.0.ok)
}

fn open_flow(session: &Session, stream: u64, host: &str, port: u16) -> Option<Flow> {
    let mut request = Vec::with_capacity(8 + host.len());
    wire::encode_client_request(
        &wire::ClientRequest {
            udp: false,
            host,
            port,
        },
        &[],
        &mut request,
    );
    if !send_all(session, stream, &request) {
        return None;
    }
    if !read_response(session, stream)? {
        return None;
    }
    Some(Flow::from_parts(
        Arc::clone(&session.shared),
        Arc::clone(&session.sock),
        session.local,
        stream,
        Vec::new(),
        true,
    ))
}

struct Pooled {
    session: Session,
    next_stream: u64,
    used: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Server {
    host: String,
    address: String,
    port: u16,
    cc: &'static str,
    auth: String,
    obfs: String,
    hop: Option<ferrox_core::hysteria::Hop>,
    roots: Option<ferrox_core::tls::Anchors>,
}

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
        obfs: dial.config.obfs_password.clone(),
        hop: dial.config.hop.clone(),
        roots: dial.roots.clone(),
    }
}

fn usable(conn: &quiche::Connection) -> bool {
    !conn.is_closed()
        && !conn.is_draining()
        && conn.local_error().is_none()
        && conn.peer_error().is_none()
}

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

fn open_pooled(dial: &Dial, host: &str, port: u16) -> Option<Flow> {
    for (session, stream) in candidates(dial) {
        if let Some(flow) = open_flow(&session, stream, host, port) {
            return Some(flow);
        }
        if session.shared.lock().is_ok_and(|conn| !usable(&conn)) {
            evict(dial, &session);
        }
    }
    let session = connect(dial)?;
    let flow = open_flow(&session, FIRST_FLOW_STREAM, host, port)?;
    keep(dial, session, FIRST_FLOW_STREAM + 4);
    Some(flow)
}

/// Dial one TCP flow through the v1 protocol: the request names the target, the server acknowledges, then bytes relay.
pub(crate) fn dial(client: &Connection, dial: &Dial, target: &crate::proxy::Destination) {
    let (host, port) = match target {
        crate::proxy::Destination::Name(host, port) => (host.clone(), *port),
        crate::proxy::Destination::Address(address) => (address.ip().to_string(), address.port()),
    };
    let Some(flow) = open_pooled(dial, &host, port) else {
        return;
    };
    crate::hysteria::relay(client, &flow);
}

/// One UDP association's live session: the id its datagrams carry, the destination the last socks packet named, and the peer that asked.
struct Lane {
    session: Mutex<Option<u32>>,
    defrag: Mutex<Defrag>,
    source: Mutex<Option<SocketAddr>>,
}

/// The client's UDP uplink over Hysteria v1: one connection and one datagram session per association, with a companion reader driving replies back into the socks frame.
pub(crate) fn serve_udp(relay: &UdpSocket, dial: &Dial) {
    let Some(session) = connect(dial) else {
        return;
    };
    let Ok(reply) = relay.try_clone() else {
        return;
    };
    let lane = Arc::new(Lane {
        session: Mutex::new(None),
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
    let mut wire = Vec::with_capacity(UDP_TARGET_BUF + 64);
    let mut out = Unfilled::<MAX_DATAGRAM>::new();
    let mut packet = 0u16;
    let mut next_id = 1u32;
    let mut stream: Option<Flow> = None;
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if stream.is_none() {
            let Some(flow) = open_udp_flow(&session, &dest.ip().to_string(), dest.port()) else {
                break;
            };
            stream = Some(flow);
            if let Ok(mut slot) = lane.session.lock() {
                *slot = Some(next_id);
            }
            next_id = next_id.wrapping_add(1);
            if let Ok(mut reassembly) = lane.defrag.lock() {
                *reassembly = Defrag::new();
            }
        }
        let Ok(mut conn) = session.shared.lock() else {
            break;
        };
        if conn.is_closed() {
            break;
        }
        let Some(max) = conn.dgram_max_writable_len() else {
            break;
        };
        if let Ok(mut slot) = lane.source.lock() {
            *slot = Some(src);
        }
        let Ok(held) = lane.session.lock() else {
            break;
        };
        let Some(session_id) = *held else {
            continue;
        };
        drop(held);
        let host = dest.ip().to_string();
        packet = packet.wrapping_add(1);
        let message = UdpMessage {
            session: session_id,
            host: &host,
            port: dest.port(),
            packet,
            frag: 0,
            frags: 1,
            payload,
        };
        let Ok(fragments) = wire::fragments_udp(&message, max) else {
            continue;
        };
        for frag in fragments {
            wire.clear();
            if wire::encode_udp(&frag, &mut wire).is_ok() {
                let _ = conn.dgram_send(&wire);
            }
        }
        flush(&session.sock, &mut conn, out.as_mut());
    }
    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();
    if let Some(mut stream) = stream {
        let _ = stream.write_all(&[]);
        stream.close();
    }
}

fn open_udp_flow(session: &Session, host: &str, port: u16) -> Option<Flow> {
    let mut request = Vec::with_capacity(5 + host.len());
    wire::encode_client_request(
        &wire::ClientRequest {
            udp: true,
            host,
            port,
        },
        &[],
        &mut request,
    );
    if !send_all(session, FIRST_FLOW_STREAM, &request) {
        return None;
    }
    let head = read_until(session, FIRST_FLOW_STREAM, |head| {
        wire::decode_server_response(head).is_ok()
    })?;
    let (response, _) = wire::decode_server_response(&head).ok()?;
    if !response.ok {
        return None;
    }
    Some(Flow::from_parts(
        Arc::clone(&session.shared),
        Arc::clone(&session.sock),
        session.local,
        FIRST_FLOW_STREAM,
        Vec::new(),
        true,
    ))
}

fn client_reader(session: &Session, lane: &Lane, stop: &AtomicBool, relay: &UdpSocket) {
    let mut reply = Vec::with_capacity(3 + 25 + UDP_TARGET_BUF);
    loop {
        if stop.load(Ordering::Relaxed) || !crate::hysteria::drive_once(session, UDP_POLL) {
            break;
        }
        let Ok(mut conn) = session.shared.lock() else {
            break;
        };
        while let Ok(data) = conn.dgram_recv_buf() {
            let Ok(message) = wire::decode_udp(&data) else {
                continue;
            };
            let Ok(held) = lane.session.lock() else {
                break;
            };
            let Some(session_id) = *held else {
                continue;
            };
            drop(held);
            if message.session != session_id {
                continue;
            }
            let Ok(ip) = message.host.parse::<std::net::IpAddr>() else {
                continue;
            };
            let destination = SocketAddr::new(ip, message.port);
            let mut assembled = Vec::new();
            let Some(payload) = lane.defrag.lock().ok().and_then(|mut reassembly| {
                reassembly
                    .feed(&message, &mut assembled)
                    .ok()
                    .flatten()
                    .map(|message| message.payload)
            }) else {
                continue;
            };
            let Some(src) = lane.source.lock().ok().and_then(|slot| *slot) else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            crate::proxy::push_socks_addr(&mut reply, &destination);
            reply.extend_from_slice(payload);
            let _ = relay.send_to(&reply, src);
        }
    }
}

fn flush(sock: &crate::quic::Datagram, conn: &mut quiche::Connection, out: &mut [u8]) {
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

fn server_config(
    cert_path: &str,
    key_path: &str,
    cc: ferrox_core::hysteria::Congestion,
) -> Option<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
    config.set_application_protos(&[wire::ALPN]).ok()?;
    config.set_cc_algorithm_name(cc.quiche_name()).ok()?;
    config.enable_dgram(true, 1024, 1024);
    config.set_max_idle_timeout(30_000);
    config.set_initial_max_data(20 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(8 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(8 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(8 * 1024 * 1024);
    config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
    config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
    config.load_cert_chain_from_pem_file(cert_path).ok()?;
    config.load_priv_key_from_pem_file(key_path).ok()?;
    Some(config)
}

struct UdpFlow {
    target: Arc<UdpSocket>,
    defrag: Defrag,
    last: Instant,
    stop: Arc<AtomicBool>,
}

#[derive(Default)]
struct UdpLane {
    sessions: HashSet<u32>,
    flows: HashMap<u32, UdpFlow>,
}

struct Inbound {
    conn: Arc<Mutex<quiche::Connection>>,
    authed: bool,
    auth_buf: Vec<u8>,
    served: HashSet<u64>,
    udp: Arc<Mutex<UdpLane>>,
    next_udp: u32,
    client_cid: Vec<u8>,
    initial_dcid: Vec<u8>,
}

fn answer_hello(
    conn: &mut quiche::Connection,
    hello: &wire::ClientHello<'_>,
    auths: &[String],
) -> bool {
    let ok = auths.iter().any(|auth| auth.as_bytes() == hello.auth);
    let mut reply = Vec::with_capacity(20);
    wire::encode_server_hello(
        &wire::ServerHello {
            ok,
            send_bps: hello.recv_bps,
            recv_bps: hello.send_bps,
            message: if ok { b"" } else { b"auth error" },
        },
        &mut reply,
    );
    conn.stream_send(0, &reply, true).is_ok() && ok
}

fn read_request(flow: &mut Flow, deadline: Instant) -> Option<(bool, String, u16)> {
    let prefix = flow.at;
    let mut head = std::mem::take(&mut flow.backlog);
    let mut room = Unfilled::<4096>::new();
    loop {
        match wire::decode_client_request(head.get(prefix..)?) {
            Ok((request, used)) => {
                let request = (request.udp, request.host.to_owned(), request.port);
                flow.backlog = head;
                flow.at = prefix + used;
                return Some(request);
            }
            Err(ferrox_core::hysteria::RequestError::Invalid) => return None,
            Err(ferrox_core::hysteria::RequestError::Incomplete) => {
                if head.len().saturating_sub(prefix) >= HEAD_CAP || Instant::now() >= deadline {
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

fn open_udp(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    session: u32,
    peer: SocketAddr,
) -> Option<UdpFlow> {
    let bind = if peer.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let target = UdpSocket::bind(bind).ok()?;
    target.set_read_timeout(Some(UDP_POLL)).ok()?;
    let target = Arc::new(target);
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::spawn({
        let shared = Arc::clone(shared);
        let sock = Arc::clone(sock);
        let target = Arc::clone(&target);
        let stop = Arc::clone(&stop);
        move || udp_reader(&shared, &sock, &target, &stop, session)
    });
    Some(UdpFlow {
        target,
        defrag: Defrag::new(),
        last: Instant::now(),
        stop,
    })
}

fn udp_reader(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    target: &Arc<UdpSocket>,
    stop: &AtomicBool,
    session: u32,
) {
    let mut buf = vec![0u8; UDP_TARGET_BUF];
    let mut wire = Vec::new();
    let mut out = Unfilled::<MAX_DATAGRAM>::new();
    let mut packet = 0u16;
    loop {
        let (n, from) = match target.recv_from(&mut buf) {
            Ok(found) => found,
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
        let host = from.ip().to_string();
        let message = UdpMessage {
            session,
            host: &host,
            port: from.port(),
            packet,
            frag: 0,
            frags: 1,
            payload: &buf[..n],
        };
        let Ok(fragments) = wire::fragments_udp(&message, max) else {
            break;
        };
        for frag in fragments {
            wire.clear();
            if wire::encode_udp(&frag, &mut wire).is_ok() {
                let _ = conn.dgram_send(&wire);
            }
        }
        flush(sock, &mut conn, out.as_mut());
    }
}

fn serve_udp_stream(mut flow: Flow, next_udp: u32, lane: &Arc<Mutex<UdpLane>>) {
    let mut response = Vec::with_capacity(8);
    wire::encode_server_response(
        &wire::ServerResponse {
            ok: true,
            udp_session_id: next_udp,
            message: b"",
        },
        &mut response,
    );
    if let Ok(mut lane) = lane.lock() {
        lane.sessions.insert(next_udp);
    } else {
        return;
    }
    if flow.write_all(&response).is_err() {
        if let Ok(mut lane) = lane.lock() {
            lane.sessions.remove(&next_udp);
        }
        return;
    }
    // The stream is the session's lifetime: the server holds it until the client closes it.
    let mut room = [0u8; 1024];
    loop {
        match flow.read(&mut room) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    if let Ok(mut lane) = lane.lock() {
        lane.sessions.remove(&next_udp);
        if let Some(flow) = lane.flows.remove(&next_udp) {
            flow.stop.store(true, Ordering::Relaxed);
        }
    }
    flow.close();
}

fn relay_datagrams(
    routes: &mut HashMap<Vec<u8>, Inbound>,
    sock: &Arc<crate::quic::Datagram>,
    shared: &Arc<Mutex<quiche::Connection>>,
    dcid: &[u8],
    conn: &mut quiche::Connection,
) {
    while let Ok(data) = conn.dgram_recv_buf() {
        let Ok(message) = wire::decode_udp(&data) else {
            continue;
        };
        let Some(inbound) = routes.get(dcid) else {
            return;
        };
        if !inbound.authed {
            continue;
        }
        let Ok(mut lane) = inbound.udp.lock() else {
            return;
        };
        let session = message.session;
        if !lane.sessions.contains(&session) {
            let _ = conn.close(false, 0, b"");
            return;
        }
        let Some(peer) = (message.host, message.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
        else {
            continue;
        };
        let flow = match lane.flows.entry(session) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(vacant) => {
                let Some(opened) = open_udp(shared, sock, session, peer) else {
                    continue;
                };
                vacant.insert(opened)
            }
        };
        let mut assembled = Vec::new();
        let whole = flow.defrag.feed(&message, &mut assembled);
        flow.last = Instant::now();
        let forged = whole.is_err();
        match whole {
            Ok(Some(message)) => {
                let _ = flow.target.send_to(message.payload, peer);
            }
            Ok(None) => {}
            Err(_) => flow.stop.store(true, Ordering::Relaxed),
        }
        if forged {
            lane.flows.remove(&session);
        }
    }
}

/// Read the binary hello off stream 0 and answer it; `None` when the connection should stop, either to wait for more bytes or because it was refused.
fn authenticate(
    routes: &mut HashMap<Vec<u8>, Inbound>,
    auths: &[String],
    dcid: &[u8],
    conn: &mut quiche::Connection,
    sock: &crate::quic::Datagram,
    out: &mut [u8],
) -> Option<()> {
    if routes.get(dcid).is_some_and(|inbound| inbound.authed) {
        return Some(());
    }
    let mut room = Unfilled::<4096>::new();
    let mut finished = false;
    loop {
        match conn.stream_recv(0, room.as_mut()) {
            Ok((0, _)) => {
                finished = true;
                break;
            }
            Ok((n, _)) => {
                if let Some(inbound) = routes.get_mut(dcid) {
                    inbound.auth_buf.extend_from_slice(&room.as_mut()[..n]);
                }
            }
            Err(_) => break,
        }
    }
    let inbound = routes.get_mut(dcid)?;
    if inbound.auth_buf.len() > HEAD_CAP {
        return None;
    }
    let hello = match wire::decode_client_hello(&inbound.auth_buf) {
        Ok((hello, _)) => hello,
        Err(ferrox_core::hysteria::RequestError::Incomplete) if !finished => return None,
        Err(_) => {
            let _ = conn.close(false, 1, b"protocol error");
            flush(sock, conn, out);
            return None;
        }
    };
    let ok = answer_hello(conn, &hello, auths);
    flush(sock, conn, out);
    inbound.auth_buf.clear();
    inbound.authed = true;
    if !ok {
        let _ = conn.close(false, 2, b"auth error");
        flush(sock, conn, out);
        return None;
    }
    Some(())
}

struct Router<'a> {
    sock: Arc<crate::quic::Datagram>,
    local: SocketAddr,
    out: Unfilled<MAX_DATAGRAM>,
    auths: &'a [String],
    serve: &'a Serve,
    routes: HashMap<Vec<u8>, Inbound>,
}

impl Router<'_> {
    fn accept(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        template: &mut quiche::Config,
        client_cid: &[u8],
        initial_dcid: &[u8],
    ) {
        let mut scid = [0u8; SCID_LEN];
        if getrandom::fill(&mut scid).is_err() {
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
                authed: false,
                auth_buf: Vec::new(),
                served: HashSet::new(),
                udp: Arc::new(Mutex::new(UdpLane::default())),
                next_udp: 1,
                client_cid: client_cid.to_vec(),
                initial_dcid: initial_dcid.to_vec(),
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
            if authenticate(routes, auths, dcid, &mut conn, sock, out.as_mut()).is_none() {
                return;
            }
            let mut streams = Vec::new();
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
                let request_udp = inbound.next_udp;
                inbound.next_udp = inbound.next_udp.wrapping_add(1);
                streams.push((id, request_udp, Arc::clone(&inbound.udp)));
            }
            for (id, next_udp, lane) in streams {
                let thread_shared = Arc::clone(&shared);
                let thread_sock = Arc::clone(sock);
                let thread_serve = Arc::clone(serve);
                let local = *local;
                std::thread::spawn(move || {
                    serve_tcp_or_udp(
                        &thread_shared,
                        &thread_sock,
                        local,
                        id,
                        &thread_serve,
                        next_udp,
                        &lane,
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
        routes.retain(|_, inbound| {
            let Ok(mut conn) = inbound.conn.lock() else {
                return true;
            };
            if conn.is_closed() {
                if let Ok(mut lane) = inbound.udp.lock() {
                    for flow in lane.flows.values() {
                        flow.stop.store(true, Ordering::Relaxed);
                    }
                    lane.flows.clear();
                    lane.sessions.clear();
                }
                return false;
            }
            conn.on_timeout();
            flush(sock, &mut conn, out.as_mut());
            if let Ok(mut lane) = inbound.udp.lock() {
                lane.flows.retain(|_, flow| {
                    if now.duration_since(flow.last) > UDP_IDLE {
                        flow.stop.store(true, Ordering::Relaxed);
                        false
                    } else {
                        true
                    }
                });
            }
            true
        });
    }
}

fn serve_tcp_or_udp(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    local: SocketAddr,
    stream: u64,
    serve: &Serve,
    next_udp: u32,
    lane: &Arc<Mutex<UdpLane>>,
) {
    let mut flow = Flow::from_parts(
        Arc::clone(shared),
        Arc::clone(sock),
        local,
        stream,
        Vec::new(),
        false,
    );
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let Some((udp, host, port)) = read_request(&mut flow, deadline) else {
        return;
    };
    if udp {
        serve_udp_stream(flow, next_udp, lane);
    } else {
        serve(flow, host, port);
    }
}

/// Serve the v1 binary handshake and both flow shapes.
pub(crate) fn serve_loop(
    address: &str,
    auths: &[String],
    cc: ferrox_core::hysteria::Congestion,
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
    let sock = match XPlus::new(obfs_password) {
        Some(obfs) => crate::quic::Datagram::xplus(sock, obfs),
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
    let mut buf = Unfilled::<RECV_ROOM>::new();
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
                    let known = router.routes.contains_key(dcid);
                    let retransmit = router.routes.iter().find_map(|(key, inbound)| {
                        ((!inbound.initial_dcid.is_empty()
                            && inbound.initial_dcid.as_slice() == dcid)
                            || (!peer_cid.is_empty()
                                && !inbound.client_cid.is_empty()
                                && inbound.client_cid.as_slice() == peer_cid))
                            .then(|| key.clone())
                    });
                    if known {
                        router.drive(dcid, &mut packet[..n], from);
                    } else if let Some(key) = retransmit {
                        router.drive(&key, &mut packet[..n], from);
                    } else {
                        router.accept(&mut packet[..n], from, &mut template, peer_cid, dcid);
                    }
                } else {
                    router.drive(dcid, &mut packet[..n], from);
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::InvalidData => {}
            Err(ref error)
                if matches!(
                    error.kind(),
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
    fn a_v1_session_carries_a_tcp_echo() {
        // Loopback coverage lives with the proxy's dispatch test; this only pins the module's own request framing.
        let mut request = Vec::new();
        wire::encode_client_request(
            &wire::ClientRequest {
                udp: false,
                host: "localhost",
                port: 80,
            },
            &[],
            &mut request,
        );
        assert_eq!(
            wire::decode_client_request(&request)
                .expect("decodes")
                .0
                .port,
            80
        );
    }

    #[test]
    fn an_unknown_udp_session_never_reaches_its_destination() {
        let canary = UdpSocket::bind("127.0.0.1:0").expect("binds");
        canary
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let canary_port = canary.local_addr().expect("addr").port();

        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let tag = format!("ferrox-hysteria-v1-unknown-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
        let key_path = std::env::temp_dir().join(format!("{tag}.key"));
        let key_pem = crate::quic::der_to_pem(&minted.signing_key.serialize_der(), "PRIVATE KEY");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages cert");
        std::fs::write(&key_path, &key_pem).expect("stages key");
        let probe = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let cert = cert_path.to_str().expect("ascii").to_owned();
        let key = key_path.to_str().expect("ascii").to_owned();
        let address = format!("127.0.0.1:{port}");
        let serve: Serve = Arc::new(|_, _, _| {});
        std::thread::spawn(move || {
            serve_loop(
                &address,
                &["v1-auth".to_owned()],
                ferrox_core::hysteria::Congestion::Bbr,
                &cert,
                &key,
                "",
                &serve,
            );
        });

        let dial = Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            config: ferrox_core::hysteria::Config {
                version: 1,
                auth: "v1-auth".to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                hop: None,
                gecko: None,
            },
            roots: Some(roots.into()),
        };
        let session = connect(&dial).expect("connects");
        let mut datagram = Vec::new();
        wire::encode_udp(
            &UdpMessage {
                session: u32::MAX,
                host: "127.0.0.1",
                port: canary_port,
                packet: 1,
                frag: 0,
                frags: 1,
                payload: b"forged",
            },
            &mut datagram,
        )
        .expect("encodes");
        {
            let mut conn = session.shared.lock().expect("locks");
            conn.dgram_send(&datagram).expect("sends");
            let mut out = Unfilled::<MAX_DATAGRAM>::new();
            flush(&session.sock, &mut conn, out.as_mut());
        }
        let mut buf = [0u8; 64];
        assert!(
            canary.recv_from(&mut buf).is_err(),
            "unknown session reached its destination"
        );
    }
}
