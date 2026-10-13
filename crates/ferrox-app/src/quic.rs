use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub(crate) struct QuicDial {
    pub(crate) id: [u8; 16],
    pub(crate) host: String,
    pub(crate) address: String,
    pub(crate) port: u16,
    /// A pooled connection through a hop is its own connection, never reused for a direct dial.
    pub(crate) upstream: Option<crate::foxy::UpstreamProxy>,
    pub(crate) roots: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QuicServer {
    address: String,
    port: u16,
    host: String,
    upstream: Option<crate::foxy::UpstreamProxy>,
    roots: Option<Vec<Vec<u8>>>,
}

struct PooledState {
    sessions: HashMap<u64, TcpStream>,
    opening: HashSet<u64>,
    next_id: u64,
}

/// The shared connection a flow rides, its socket, its local address, and the bidirectional stream id it opened.
pub(crate) type PooledStream = (
    Arc<Mutex<quiche::Connection>>,
    Arc<Datagram>,
    SocketAddr,
    u64,
);

#[derive(Clone)]
struct PooledConn {
    conn: Arc<Mutex<quiche::Connection>>,
    table: Arc<Mutex<PooledState>>,
    sock: Arc<Datagram>,
    key: Arc<QuicServer>,
}

struct QuicPool {
    inner: Mutex<HashMap<QuicServer, PooledConn>>,
}

impl QuicPool {
    /// The connection already open to this edge, if there is one.
    fn stream(&self, dial: &QuicDial) -> Option<PooledConn> {
        let key = QuicServer {
            address: dial.address.clone(),
            port: dial.port,
            host: dial.host.clone(),
            upstream: dial.upstream.clone(),
            roots: dial.roots.clone(),
        };
        self.inner.lock().ok()?.get(&key).cloned()
    }
}

static QUIC_POOL: OnceLock<QuicPool> = OnceLock::new();

fn pool() -> &'static QuicPool {
    QUIC_POOL.get_or_init(|| QuicPool {
        inner: Mutex::new(HashMap::new()),
    })
}

pub(crate) const ALPN: &[u8] = b"h3";

const SCID_LEN: usize = 16;

pub(crate) const MAX_DATAGRAM: usize = 1350;

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) const IDLE_TIMEOUT_MS: u64 = 300_000;

pub(crate) const MAX_DATA: u64 = 10_000_000;
pub(crate) const MAX_STREAM_DATA: u64 = 1_000_000;
pub(crate) const MAX_STREAMS: u64 = 100;

const PUMP_POLL: Duration = Duration::from_millis(500);

pub(crate) const SEND_WAIT: Duration = Duration::from_secs(10);

static TRUST_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) static QSTAGES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn qstage(ev: String) {
    if let Ok(mut log) = QSTAGES.lock() {
        log.push(ev);
    }
}

/// A loopback edge's wait for the next packet before quiche runs timers; it keeps an idle test connection alive.
#[cfg(test)]
pub(crate) const SERVER_POLL: Duration = Duration::from_millis(100);

#[cfg(test)]
pub(crate) fn qms() -> u128 {
    static QT0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    QT0.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn b64_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut i = 0usize;
    while i < 64 {
        table[B64[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const B64_TABLE: [u8; 256] = b64_table();

fn base64_encode_block(out: &mut [u8; 64], bytes: &[u8]) -> usize {
    assert!(bytes.len() <= 48, "base64 lines are 48 input bytes");
    let mut written = 0;
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for byte in chunk {
            word = (word << 8) | u32::from(*byte);
        }
        word <<= 8 * (3 - chunk.len());
        let pad = 3 - chunk.len();
        for slot in 0..4 {
            if slot < 4 - pad {
                out[written] = B64[((word >> (18 - 6 * slot)) & 63) as usize];
            } else {
                out[written] = b'=';
            }
            written += 1;
        }
    }
    written
}

fn base64_value(byte: u8) -> Option<u8> {
    let v = B64_TABLE[byte as usize];
    if v == 255 {
        None
    } else {
        Some(v)
    }
}

fn base64_decode(text: &[u8], out: &mut Vec<u8>) -> bool {
    let mut word = 0u32;
    let mut slots = 0;
    let mut pads = 0;
    for byte in text {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if *byte == b'=' {
            pads += 1;
            word <<= 6;
        } else {
            if pads > 0 {
                return false;
            }
            let Some(digit) = base64_value(*byte) else {
                return false;
            };
            word = (word << 6) | u32::from(digit);
        }
        slots += 1;
        if slots == 4 {
            if pads > 2 {
                return false;
            }
            out.push((word >> 16) as u8);
            if pads < 2 {
                out.push((word >> 8) as u8);
            }
            if pads == 0 {
                out.push(word as u8);
            }
            word = 0;
            slots = 0;
            pads = 0;
        }
    }
    slots == 0
}

pub(crate) fn der_to_pem(der: &[u8], label: &str) -> Vec<u8> {
    let mut pem = Vec::new();
    pem.extend_from_slice(b"-----BEGIN ");
    pem.extend_from_slice(label.as_bytes());
    pem.extend_from_slice(b"-----\n");
    let mut block = [0u8; 64];
    for line in der.chunks(48) {
        let n = base64_encode_block(&mut block, line);
        pem.extend_from_slice(&block[..n]);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END ");
    pem.extend_from_slice(label.as_bytes());
    pem.extend_from_slice(b"-----\n");
    pem
}

pub(crate) fn parse_ca_pem(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.windows(BEGIN.len()).position(|w| w == BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.windows(END.len()).position(|w| w == END) else {
            return Vec::new();
        };
        let mut der = Vec::new();
        if !base64_decode(&after[..end], &mut der) {
            return Vec::new();
        }
        certs.push(der);
        rest = &after[end + END.len()..];
    }
    certs
}

// create_new is O_EXCL, so a name already in a shared tmp fails instead of being followed or truncated.
fn stage_trust_file(bundle: &[u8]) -> Option<(std::path::PathBuf, String)> {
    let name = format!(
        "ferrox-quic-roots-{}-{}.pem",
        std::process::id(),
        TRUST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    stage_at(&std::env::temp_dir().join(name), bundle)
}

fn stage_at(path: &std::path::Path, bundle: &[u8]) -> Option<(std::path::PathBuf, String)> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    std::io::Write::write_all(&mut file, bundle).ok()?;
    let text = path.to_str()?.to_owned();
    Some((path.to_path_buf(), text))
}

pub(crate) fn quiche_config(roots: &[Vec<u8>], cc: Option<&str>) -> Option<quiche::Config> {
    if roots.is_empty() {
        return None;
    }
    let mut bundle = Vec::new();
    for root in roots {
        bundle.extend_from_slice(&der_to_pem(root, "CERTIFICATE"));
    }
    let (path, path_text) = stage_trust_file(&bundle)?;
    let config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .ok()
        .and_then(|mut config| {
            config.verify_peer(true);
            config.set_application_protos(&[ALPN]).ok()?;
            if let Some(name) = cc {
                config.set_cc_algorithm_name(name).ok()?;
            }
            config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
            config.set_initial_max_data(MAX_DATA);
            config.set_initial_max_stream_data_bidi_local(MAX_STREAM_DATA);
            config.set_initial_max_stream_data_bidi_remote(MAX_STREAM_DATA);
            config.set_initial_max_stream_data_uni(MAX_STREAM_DATA);
            config.set_initial_max_streams_bidi(MAX_STREAMS);
            config.set_initial_max_streams_uni(MAX_STREAMS);
            config.load_verify_locations_from_file(&path_text).ok()?;
            Some(config)
        });
    let _ = std::fs::remove_file(&path);
    config
}

pub(crate) fn flush_egress(conn: &mut quiche::Connection, sock: &Datagram) {
    let mut out = [0u8; MAX_DATAGRAM];
    while let Ok((written, info)) = conn.send(&mut out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

/// The HTTP/3 opening, carried exactly once per connection: a second control stream is a connection error.
pub(crate) fn send_h3_opening(conn: &mut quiche::Connection, sock: &Datagram) -> bool {
    for (stream, payload) in crate::foxy::H3::h3_opening() {
        let mut rest = &payload[..];
        while !rest.is_empty() {
            match conn.stream_send(stream, rest, false) {
                Ok(0) | Err(_) => return false,
                Ok(wrote) => rest = &rest[wrote..],
            }
        }
    }
    flush_egress(conn, sock);
    true
}

pub(crate) fn pump_once(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    wait: Duration,
) -> bool {
    let timer = conn.timeout().map_or(wait, |left| left.min(wait));
    if sock
        .set_read_timeout(Some(timer.max(Duration::from_millis(1))))
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; MAX_DATAGRAM];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => {
            let info = quiche::RecvInfo { from, to: local };
            let _ = conn.recv(&mut buf[..n], info);
            flush_egress(conn, sock);
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            conn.on_timeout();
            flush_egress(conn, sock);
        }
        Err(_) => return false,
    }
    true
}

pub(crate) fn drive_handshake(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
) -> Option<()> {
    drive_handshake_by(conn, sock, local, HANDSHAKE_TIMEOUT)
}

/// The handshake loop under the caller's budget: only the deadline differs, and a probe chooses a smaller one.
pub(crate) fn drive_handshake_by(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    budget: Duration,
) -> Option<()> {
    let deadline = Instant::now() + budget;
    while !conn.is_established() {
        if conn.is_closed() || Instant::now() >= deadline {
            return None;
        }
        flush_egress(conn, sock);
        let left = deadline.saturating_duration_since(Instant::now());
        if !pump_once(conn, sock, local, left) {
            return None;
        }
    }
    Some(())
}

pub(crate) fn stream_send_all(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    stream: u64,
    mut buf: &[u8],
    fin: bool,
    deadline: Instant,
) -> bool {
    while !buf.is_empty() || fin {
        match conn.stream_send(stream, buf, fin && buf.is_empty()) {
            Ok(written) => {
                buf = &buf[written..];
                if buf.is_empty() {
                    flush_egress(conn, sock);
                    return true;
                }
                if written == 0 {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    flush_egress(conn, sock);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Err(quiche::Error::Done) => {
                if Instant::now() >= deadline {
                    return false;
                }
                flush_egress(conn, sock);
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return false,
        }
    }
    flush_egress(conn, sock);
    true
}

pub(crate) fn stream_recv_exact(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    stream: u64,
    want: usize,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(want);
    let mut chunk = [0u8; 8192];
    while out.len() < want {
        let end = (want - out.len()).min(chunk.len());
        match conn.stream_recv(stream, &mut chunk[..end]) {
            Ok((0, _)) | Err(quiche::Error::Done) => {
                if conn.is_closed() || Instant::now() >= deadline {
                    return None;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if !pump_once(conn, sock, local, left) {
                    return None;
                }
            }
            Ok((n, fin)) => {
                out.extend_from_slice(&chunk[..n]);
                if fin {
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    (out.len() == want).then_some(out)
}

/// Platform CA bundle fallback layouts; an empty root store is trust-nothing, not "trust the platform".
const BUNDLES: [&str; 10] = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
    "C:/Program Files/Git/mingw64/ssl/certs/ca-bundle.crt",
    "C:/Program Files/Git/usr/ssl/certs/ca-bundle.crt",
    "C:/msys64/mingw64/ssl/certs/ca-bundle.crt",
    "C:/msys64/usr/ssl/certs/ca-bundle.crt",
];

pub(crate) fn system_roots() -> Vec<Vec<u8>> {
    // Platform store first: macOS bundle files hold a handful of roots, so bundle-first answers unknown issuer.
    let native = rustls_native_certs::load_native_certs();
    let roots: Vec<Vec<u8>> = native
        .certs
        .into_iter()
        .map(|cert| cert.to_vec())
        .filter(|der| !der.is_empty())
        .collect();
    if !roots.is_empty() {
        return roots;
    }
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        if let Ok(pem) = std::fs::read(&path) {
            let roots = parse_ca_pem(&pem);
            if !roots.is_empty() {
                return roots;
            }
        }
    }
    for path in BUNDLES {
        if let Ok(pem) = std::fs::read(path) {
            let roots = parse_ca_pem(&pem);
            if !roots.is_empty() {
                return roots;
            }
        }
    }
    // Android keeps one file per CA under this directory rather than a bundle; PEM or DER halves are accepted.
    if let Ok(entries) = std::fs::read_dir("/system/etc/security/cacerts") {
        let mut roots = Vec::new();
        for entry in entries.flatten() {
            let Ok(bytes) = std::fs::read(entry.path()) else {
                continue;
            };
            if bytes.starts_with(b"-----BEGIN") {
                roots.extend(parse_ca_pem(&bytes));
            } else if !bytes.is_empty() {
                roots.push(bytes);
            }
        }
        if !roots.is_empty() {
            return roots;
        }
    }
    Vec::new()
}

/// A socket read one packet at a time: Linux coalesces loopback skbs, so GRO is switched off per socket.
pub(crate) fn bind_datagram(address: &str) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(address)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let off: libc::c_int = 0;
        // SAFETY: `off` outlives the call, and the size is its own.
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_UDP,
                libc::UDP_GRO,
                std::ptr::addr_of!(off).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                    .unwrap_or(libc::socklen_t::MAX),
            );
        }
    }
    Ok(sock)
}

/// One datagram socket: a relay below changes no handshake, frame or stream above, so the hop lives here.
pub(crate) struct Datagram {
    sock: UdpSocket,
    relay: Option<Relay>,
}

/// Where datagrams go. The association's control connection is held, never read: dropping it ends it.
#[derive(Clone)]
struct Relay {
    via: SocketAddr,
    _control: Arc<TcpStream>,
}

/// The most one datagram costs in headers: two reserved bytes, one flag byte, the longest address and the port.
const RELAY_HEADER: usize = 22;

impl Datagram {
    pub(crate) fn plain(sock: UdpSocket) -> Self {
        Self { sock, relay: None }
    }

    pub(crate) fn relayed(sock: UdpSocket, via: SocketAddr, control: Arc<TcpStream>) -> Self {
        Self {
            sock,
            relay: Some(Relay {
                via,
                _control: control,
            }),
        }
    }

    pub(crate) fn send_to(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        let Some(relay) = self.relay.as_ref() else {
            return self.sock.send_to(buf, to);
        };
        // The header carries the real target; the socket itself is addressed to the hop.
        let mut framed = [0u8; RELAY_HEADER + MAX_DATAGRAM];
        let Some(into) = framed.get_mut(..RELAY_HEADER + buf.len()) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        let header = match to {
            SocketAddr::V4(addr) => {
                into[3] = 1;
                into[4..8].copy_from_slice(&addr.ip().octets());
                into[8..10].copy_from_slice(&addr.port().to_be_bytes());
                10
            }
            SocketAddr::V6(addr) => {
                into[3] = 4;
                into[4..20].copy_from_slice(&addr.ip().octets());
                into[20..22].copy_from_slice(&addr.port().to_be_bytes());
                22
            }
        };
        into[header..header + buf.len()].copy_from_slice(buf);
        self.sock.send_to(&framed[..header + buf.len()], relay.via)
    }

    pub(crate) fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let Some(relay) = self.relay.as_ref() else {
            return self.sock.recv_from(buf);
        };
        let (found, from) = self.sock.recv_from(buf)?;
        if from != relay.via {
            // A datagram from anywhere but the hop is not for this association.
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let Some((header, peer)) = relay_inbound(&buf[..found]) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        };
        buf.copy_within(header..found, 0);
        Ok((found - header, peer))
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            sock: self.sock.try_clone()?,
            relay: self.relay.clone(),
        })
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }
}

/// A relayed datagram's header and target address; fragments are never reassembled, so they do not read.
fn relay_inbound(head: &[u8]) -> Option<(usize, SocketAddr)> {
    let [_, _, 0, kind] = *head.get(..4)? else {
        return None;
    };
    let (raw, width) = match kind {
        1 => (head.get(4..8)?, 4),
        4 => (head.get(4..20)?, 16),
        _ => return None,
    };
    let port = head.get(4 + width..6 + width)?;
    let ip = if width == 4 {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(raw);
        std::net::IpAddr::from(octets)
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(raw);
        std::net::IpAddr::from(octets)
    };
    Some((
        6 + width,
        SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]])),
    ))
}

pub(crate) fn udp_to_server(
    address: &str,
    port: u16,
) -> Option<(UdpSocket, SocketAddr, SocketAddr)> {
    let peer = format!("{address}:{port}").to_socket_addrs().ok()?.next()?;
    let sock = if peer.is_ipv6() {
        bind_datagram("[::]:0").ok()?
    } else {
        bind_datagram("0.0.0.0:0").ok()?
    };
    let local = sock.local_addr().ok()?;
    Some((sock, peer, local))
}

/// Handshake under the caller's budget: a probe pays it once for silence, a named carrier gets the full budget.
pub(crate) fn handshake_within(
    sock: &Datagram,
    peer: SocketAddr,
    local: SocketAddr,
    server_name: &str,
    roots: &[Vec<u8>],
    budget: Duration,
) -> Option<quiche::Connection> {
    let mut scid = [0u8; SCID_LEN];
    getrandom::getrandom(&mut scid).ok()?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config = quiche_config(roots, None)?;
    let mut conn = quiche::connect(Some(server_name), &cid, local, peer, &mut config).ok()?;
    drive_handshake_by(&mut conn, sock, local, budget)?;
    Some(conn)
}

fn pump(
    shared: &Arc<Mutex<quiche::Connection>>,
    table: &Arc<Mutex<PooledState>>,
    sock: &Datagram,
    local: SocketAddr,
) {
    let mut ready: Vec<(u64, TcpStream)> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut buf = [0u8; MAX_DATAGRAM];
    let mut applied: Option<Duration> = None;
    loop {
        // The lock covers quiche calls only: a stalled peer must not stall the sessions sharing the connection.
        let timeout = {
            let Ok(conn) = shared.lock() else {
                return;
            };
            if conn.is_closed() {
                return;
            }
            conn.timeout()
                .map_or(PUMP_POLL, |left| left.min(PUMP_POLL))
                .max(Duration::from_millis(1))
        };
        if !crate::proxy::refresh_read_timeout(sock, timeout, &mut applied) {
            return;
        }
        let incoming = match sock.recv_from(&mut buf) {
            Ok(found) => Some(found),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(_) => return,
        };
        ready.clear();
        {
            #[cfg(test)]
            let took = Instant::now();
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            #[cfg(test)]
            qstage(format!("pump-lock {}ms", took.elapsed().as_millis()));
            if conn.is_closed() {
                return;
            }
            match incoming {
                Some((n, from)) => {
                    let info = quiche::RecvInfo { from, to: local };
                    let _ = conn.recv(&mut buf[..n], info);
                }
                None => conn.on_timeout(),
            }
            flush_egress(&mut conn, sock);
            for id in conn.readable() {
                let half = {
                    let Ok(table) = table.lock() else {
                        break;
                    };
                    if table.opening.contains(&id) {
                        continue;
                    }
                    table
                        .sessions
                        .get(&id)
                        .and_then(|half| half.try_clone().ok())
                };
                if half.is_none() {
                    while let Ok((n, _)) = conn.stream_recv(id, &mut chunk) {
                        if n == 0 {
                            break;
                        }
                    }
                    continue;
                }
                ready.push((id, half.expect("cloned")));
            }
            if conn.is_closed() {
                return;
            }
        }
        for (id, mut up) in ready.drain(..) {
            loop {
                let (n, fin) = {
                    let Ok(mut conn) = shared.lock() else {
                        return;
                    };
                    match conn.stream_recv(id, &mut chunk) {
                        Ok((0, _)) | Err(_) => break,
                        Ok(found) => found,
                    }
                };
                if up.write_all(&chunk[..n]).is_err() {
                    break;
                }
                if fin {
                    let _ = up.shutdown(Shutdown::Write);
                    break;
                }
            }
        }
    }
}

fn leave_session(
    shared: &Arc<Mutex<quiche::Connection>>,
    table: &Arc<Mutex<PooledState>>,
    flush_sock: &Datagram,
    pool: &'static QuicPool,
    key: &QuicServer,
    id: u64,
) {
    let last = match table.lock() {
        Ok(mut table) => {
            table.sessions.remove(&id);
            table.opening.remove(&id);
            table.sessions.is_empty() && table.opening.is_empty()
        }
        Err(_) => false,
    };
    if !last {
        return;
    }
    if let Ok(mut conn) = shared.lock() {
        let _ = conn.close(false, 0, b"done");
        flush_egress(&mut conn, flush_sock);
    }
    if let Ok(mut pool) = pool.inner.lock() {
        pool.remove(key);
    }
}

fn open_session(pooled: &PooledConn, key: &QuicServer, client: &TcpStream) -> Option<u64> {
    let Ok(conn) = pooled.conn.lock() else {
        return None;
    };
    if conn.is_closed() {
        drop(conn);
        if let Ok(mut pool) = pool().inner.lock() {
            pool.remove(key);
        }
        return None;
    }
    let Ok(mut table) = pooled.table.lock() else {
        return None;
    };
    if table.sessions.len() >= MAX_STREAMS as usize {
        return None;
    }
    let id = table.next_id;
    table.next_id += 4;
    let Ok(up) = client.try_clone() else {
        return None;
    };
    table.sessions.insert(id, up);
    table.opening.insert(id);
    Some(id)
}

fn uplink_stream(pooled: &PooledConn, key: &QuicServer, id: u64, client: &TcpStream) {
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), key, id);
        return;
    };
    let Ok(mut plain) = client.try_clone() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), key, id);
        return;
    };
    let mut chunk = [0u8; 8192];
    loop {
        #[cfg(test)]
        let read_at = Instant::now();
        match plain.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                #[cfg(test)]
                qstage(format!(
                    "{} t={} up-read {id} {n} waited {}ms",
                    key.port,
                    qms(),
                    read_at.elapsed().as_millis()
                ));
                let mut rest = &chunk[..n];
                let deadline = Instant::now() + SEND_WAIT;
                let sent = loop {
                    #[cfg(test)]
                    let waited = Instant::now();
                    let Ok(mut conn) = pooled.conn.lock() else {
                        #[cfg(test)]
                        qstage(format!("{} t={} up-lock-none {id}", key.port, qms()));
                        break false;
                    };
                    #[cfg(test)]
                    qstage(format!(
                        "{} t={} up-lock {id} {}ms",
                        key.port,
                        qms(),
                        waited.elapsed().as_millis()
                    ));
                    if conn.is_closed() {
                        #[cfg(test)]
                        qstage(format!("{} t={} up-closed {id}", key.port, qms()));
                        break false;
                    }
                    match conn.stream_send(id, rest, false) {
                        Ok(written) => {
                            rest = &rest[written..];
                            flush_egress(&mut conn, &flush_sock);
                            if rest.is_empty() {
                                break true;
                            }
                            if written == 0 {
                                if Instant::now() >= deadline {
                                    #[cfg(test)]
                                    qstage(format!("{} t={} up-stall {id}", key.port, qms()));
                                    break false;
                                }
                                drop(conn);
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                        Err(quiche::Error::Done) => {
                            if Instant::now() >= deadline {
                                #[cfg(test)]
                                qstage(format!("{} t={} up-done-timeout {id}", key.port, qms()));
                                break false;
                            }
                            drop(conn);
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => {
                            #[cfg(test)]
                            qstage(format!("{} t={} up-err {id}", key.port, qms()));
                            break false;
                        }
                    }
                };
                if !sent {
                    #[cfg(test)]
                    qstage(format!("{} t={} up-unsent {id}", key.port, qms()));
                    break;
                }
                #[cfg(test)]
                qstage(format!("{} t={} up {id} {n}", key.port, qms()));
            }
        }
    }
    if let Ok(mut conn) = pooled.conn.lock() {
        let _ = conn.stream_send(id, &[], true);
    }
    #[cfg(test)]
    qstage(format!("{} t={} uplink-end {id}", key.port, qms()));
    leave_session(&pooled.conn, &pooled.table, &flush_sock, pool(), key, id);
}

pub(crate) fn dial_pooled(client: &TcpStream, dial: &QuicDial, target: &SocketAddr) {
    let key = QuicServer {
        address: dial.address.clone(),
        port: dial.port,
        host: dial.host.clone(),
        upstream: dial.upstream.clone(),
        roots: dial.roots.clone(),
    };
    let pooled = if let Ok(pool) = pool().inner.lock() {
        pool.get(&key).cloned()
    } else {
        None
    };
    #[cfg(test)]
    qstage(format!(
        "{} t={} lookup hit={}",
        dial.port,
        qms(),
        pooled.is_some()
    ));
    let Some(pooled) = pooled.or_else(|| {
        let fresh = build_pooled(dial)?;
        #[cfg(test)]
        qstage(format!("{} t={} built", dial.port, qms()));
        let Ok(mut pool) = pool().inner.lock() else {
            return Some(fresh);
        };
        if let Some(live) = pool.get(&key) {
            if let Ok(mut conn) = fresh.conn.lock() {
                let _ = conn.close(false, 0, b"superseded");
            }
            Some(live.clone())
        } else {
            pool.insert(key.clone(), fresh.clone());
            Some(fresh)
        }
    }) else {
        #[cfg(test)]
        qstage(format!("{} t={} build-none", dial.port, qms()));
        return;
    };
    let Some(id) = open_session(&pooled, &key, client) else {
        #[cfg(test)]
        qstage(format!("{} t={} open-none", dial.port, qms()));
        return;
    };
    #[cfg(test)]
    qstage(format!("{} t={} opened {id}", dial.port, qms()));
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
        return;
    };
    let Ok(local) = pooled.sock.local_addr() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
        return;
    };
    let header = crate::proxy::vless_header(&dial.id, 1, target);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let opened = {
        let Ok(mut conn) = pooled.conn.lock() else {
            leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
            return;
        };
        stream_send_all(&mut conn, &flush_sock, id, &header, false, deadline)
            && stream_recv_exact(&mut conn, &flush_sock, local, id, 2, deadline).as_deref()
                == Some(&[0, 0])
    };
    #[cfg(test)]
    qstage(format!("{} t={} header {id} {opened}", dial.port, qms()));
    if !opened {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
        return;
    }
    if let Ok(mut table) = pooled.table.lock() {
        table.opening.remove(&id);
    }
    #[cfg(test)]
    qstage(format!("{} t={} graduated {id}", dial.port, qms()));
    uplink_stream(&pooled, &key, id, client);
}

/// A stream on the pooled connection under the named budget; a connection the budget missed is never pooled.
pub(crate) fn pooled_stream_within(dial: &QuicDial, budget: Duration) -> Option<PooledStream> {
    let pooled = pool().stream(dial).or_else(|| {
        let fresh = build_pooled_within(dial, budget)?;
        let Ok(mut pool) = pool().inner.lock() else {
            return Some(fresh);
        };
        if let Some(live) = pool.get(fresh.key.as_ref()) {
            return Some(live.clone());
        }
        pool.insert(fresh.key.as_ref().clone(), fresh.clone());
        Some(fresh)
    })?;
    let id = {
        let Ok(mut table) = pooled.table.lock() else {
            return None;
        };
        if table.opening.len() >= MAX_STREAMS as usize {
            return None;
        }
        let id = table.next_id;
        table.next_id += 4;
        table.opening.insert(id);
        id
    };
    let local = pooled.sock.local_addr().ok()?;
    Some((
        Arc::clone(&pooled.conn),
        Arc::clone(&pooled.sock),
        local,
        id,
    ))
}

/// Hands a stream back to the pool, and closes the connection when it was the last stream on it.
pub(crate) fn release_stream(dial: &QuicDial, id: u64) {
    let key = QuicServer {
        address: dial.address.clone(),
        port: dial.port,
        host: dial.host.clone(),
        upstream: dial.upstream.clone(),
        roots: dial.roots.clone(),
    };
    let pooled = pool().stream(dial);
    let Some(pooled) = pooled else { return };
    leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
}

fn build_pooled(dial: &QuicDial) -> Option<PooledConn> {
    build_pooled_within(dial, HANDSHAKE_TIMEOUT)
}

fn build_pooled_within(dial: &QuicDial, budget: Duration) -> Option<PooledConn> {
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    // One attempt per resolved address: the first answer is not always the reachable one.
    let peers: Vec<SocketAddr> = format!("{}:{}", dial.address, dial.port)
        .to_socket_addrs()
        .ok()?
        .collect();
    // One hop per connection, not per address. An HTTP hop is TCP-only: refusing beats bypassing the proxy.
    let relay = match dial.upstream.as_ref() {
        Some(proxy) if proxy.http() => return None,
        Some(proxy) => Some(crate::foxy::associate_udp(proxy)?),
        None => None,
    };
    for peer in peers {
        let Ok(sock) = (if peer.is_ipv6() {
            bind_datagram("[::]:0")
        } else {
            bind_datagram("0.0.0.0:0")
        }) else {
            continue;
        };
        let Ok(local) = sock.local_addr() else {
            continue;
        };
        let sock = match relay.as_ref() {
            Some((control, via)) => Datagram::relayed(sock, *via, Arc::clone(control)),
            None => Datagram::plain(sock),
        };
        let Some(mut conn) = handshake_within(&sock, peer, local, &dial.host, roots, budget) else {
            continue;
        };
        if !send_h3_opening(&mut conn, &sock) {
            continue;
        }
        let shared = Arc::new(Mutex::new(conn));
        let table = Arc::new(Mutex::new(PooledState {
            sessions: HashMap::new(),
            opening: HashSet::new(),
            next_id: 0,
        }));
        let task_shared = Arc::clone(&shared);
        let task_table = Arc::clone(&table);
        let Ok(pump_sock) = sock.try_clone() else {
            continue;
        };
        std::thread::spawn(move || pump(&task_shared, &task_table, &pump_sock, local));
        return Some(PooledConn {
            conn: shared,
            table,
            sock: Arc::new(sock),
            key: Arc::new(QuicServer {
                address: dial.address.clone(),
                port: dial.port,
                host: dial.host.clone(),
                roots: dial.roots.clone(),
                upstream: dial.upstream.clone(),
            }),
        });
    }
    None
}

/// One connection, one stream, no pool thread: which reader owns a shared connection must not decide the proof.
#[cfg(test)]
pub(crate) fn direct_stream(
    host: &str,
    address: &str,
    port: u16,
    roots: &[Vec<u8>],
) -> Option<PooledStream> {
    let (sock, peer, local) = udp_to_server(address, port)?;
    direct_stream_on(Datagram::plain(sock), peer, local, host, roots)
}

/// The same stream over a caller-framed socket: how a loopback proves a relayed dial.
#[cfg(test)]
pub(crate) fn direct_stream_on(
    sock: Datagram,
    peer: SocketAddr,
    local: SocketAddr,
    host: &str,
    roots: &[Vec<u8>],
) -> Option<PooledStream> {
    let mut conn = handshake_within(&sock, peer, local, host, roots, HANDSHAKE_TIMEOUT)?;
    if !send_h3_opening(&mut conn, &sock) {
        return None;
    }
    Some((
        std::sync::Arc::new(std::sync::Mutex::new(conn)),
        std::sync::Arc::new(sock),
        local,
        4,
    ))
}

/// One datagram off a loopback edge's socket, or nothing when none arrived.
#[cfg(test)]
pub(crate) fn server_poll(sock: &Datagram, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
    sock.set_read_timeout(Some(SERVER_POLL)).ok()?;
    match sock.recv_from(buf) {
        Ok(found) => Some(found),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(e) => panic!("loopback edge socket died: {e:?}"),
    }
}

/// Lets a waiting connection run its own timers and answer what it queued between packets.
#[cfg(test)]
pub(crate) fn server_idle(conn: &mut quiche::Connection, sock: &Datagram, out: &mut [u8]) {
    conn.on_timeout();
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

/// The loopback edge's half: its first Initial goes to quiche and the handshake is driven to completion.
#[cfg(test)]
pub(crate) fn server_accept(
    sock: &Datagram,
    local: SocketAddr,
    config: &mut quiche::Config,
) -> quiche::Connection {
    let mut buf = [0u8; MAX_DATAGRAM];
    let mut out = [0u8; MAX_DATAGRAM];
    let mut conn = loop {
        let Some((n, from)) = server_poll(sock, &mut buf) else {
            continue;
        };
        let Ok(header) = quiche::Header::from_slice(&mut buf[..n], 20) else {
            continue;
        };
        if header.ty != quiche::Type::Initial || header.version != quiche::PROTOCOL_VERSION {
            continue;
        }
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut fresh = quiche::accept(&cid, None, local, from, config).expect("accepts");
        let info = quiche::RecvInfo { from, to: local };
        fresh.recv(&mut buf[..n], info).expect("handshakes");
        while let Ok((written, info)) = fresh.send(&mut out) {
            let _ = sock.send_to(&out[..written], info.to);
        }
        break fresh;
    };
    while !conn.is_established() {
        if let Some((n, from)) = server_poll(sock, &mut buf) {
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        } else {
            server_idle(&mut conn, sock, &mut out);
        }
    }
    conn
}

/// The edge's ALPN, flow control and certificate settings, matching the lane's own so it is not a weaker peer.
#[cfg(test)]
pub(crate) fn server_config(alpn: &[u8]) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
    config.set_application_protos(&[alpn]).expect("negotiates");
    config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
    config.set_initial_max_data(MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_uni(MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(MAX_STREAMS);
    config.set_initial_max_streams_uni(MAX_STREAMS);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trust anchors come from the platform bundle, so a publicly trusted host is not trusted by nothing.
    #[test]
    fn the_platform_bundle_is_read_into_trust_anchors() {
        let roots = system_roots();
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert!(roots.len() > 50, "a bundle with {} anchors", roots.len());
        }
        assert_eq!(parse_ca_pem(b"not a pem at all"), Vec::<Vec<u8>>::new());
    }

    /// The read option is why the edge stops losing packets, so it is read back rather than assumed.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_quic_socket_is_bound_with_datagram_coalescing_off() {
        use std::os::fd::AsRawFd as _;
        let sock = bind_datagram("127.0.0.1:0").expect("binds");
        let mut on: libc::c_int = -1;
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
            .expect("size fits a socklen");
        // SAFETY: `on` and `len` describe the buffer the kernel writes into.
        let got = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_UDP,
                libc::UDP_GRO,
                std::ptr::addr_of_mut!(on).cast(),
                std::ptr::addr_of_mut!(len),
            )
        };
        assert_eq!(got, 0, "the kernel knows UDP_GRO");
        assert_eq!(on, 0, "one recv_from carries one packet");
        assert!(udp_to_server("127.0.0.1", 443).is_some(), "still dials");
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        let mut block = [0u8; 64];
        for (raw, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            let n = base64_encode_block(&mut block, raw.as_bytes());
            assert_eq!(&block[..n], text.as_bytes());
            let mut back = Vec::new();
            assert!(base64_decode(&block[..n], &mut back));
            assert_eq!(back, raw.as_bytes());
        }
        let mut garbage = Vec::new();
        assert!(!base64_decode(b"!!!", &mut garbage));
        assert!(!base64_decode(b"Zg=", &mut garbage));
        let long = vec![0xabu8; 50];
        let mut wrapped = Vec::new();
        for chunk in long.chunks(48) {
            let n = base64_encode_block(&mut block, chunk);
            wrapped.extend_from_slice(&block[..n]);
        }
        wrapped.insert(64, b'\n');
        let mut unwrapped = Vec::new();
        assert!(base64_decode(&wrapped, &mut unwrapped));
        assert_eq!(unwrapped, long);
    }

    #[test]
    fn pem_wraps_at_sixty_four_columns() {
        let pem = der_to_pem(&[0xabu8; 48], "CERTIFICATE");
        let text = std::str::from_utf8(&pem).expect("ascii");
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        for line in text.lines().skip(1) {
            if line.starts_with("-----END") {
                break;
            }
            assert_eq!(line.len(), 64);
        }
        assert_eq!(parse_ca_pem(&pem), vec![vec![0xabu8; 48]]);
    }

    #[test]
    fn corrupt_bundle_parses_to_nothing() {
        assert_eq!(parse_ca_pem(b"no blocks here"), Vec::<Vec<u8>>::new());
        let mut pem = der_to_pem(&[1u8; 32], "CERTIFICATE");
        pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n");
        assert_eq!(parse_ca_pem(&pem), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn the_base64_table_agrees_with_the_alphabet() {
        for byte in 0..=u8::MAX {
            let scanned = B64
                .iter()
                .position(|digit| *digit == byte)
                .map_or(u8::MAX, |slot| slot as u8);
            assert_eq!(B64_TABLE[usize::from(byte)], scanned, "byte {byte:#04x}");
        }
        for (slot, digit) in B64.iter().enumerate() {
            assert_eq!(base64_value(*digit), Some(slot as u8));
        }
        for byte in [b'=', b' ', b'\n', b'!', 0, 0xff] {
            assert_eq!(base64_value(byte), None);
        }
    }

    fn owned_staging_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ferrox-quic-test-{}-{tag}.pem", std::process::id()))
    }

    #[test]
    fn staging_refuses_a_name_something_else_already_holds() {
        let path = owned_staging_path("taken");
        std::fs::write(&path, b"planted").expect("plants");
        assert!(stage_at(&path, b"mine").is_none());
        assert_eq!(std::fs::read(&path).expect("reads"), b"planted");
        std::fs::remove_file(&path).expect("removes");
        let (back, text) = stage_at(&path, b"mine").expect("stages");
        assert_eq!(back, path);
        assert_eq!(text, path.to_string_lossy());
        assert_eq!(std::fs::read(&path).expect("reads"), b"mine");
        std::fs::remove_file(&path).expect("removes");
    }

    #[test]
    fn staging_returns_the_name_it_wrote_so_the_caller_can_remove_it() {
        let path = owned_staging_path("removable");
        let (back, text) = stage_at(&path, b"bundle").expect("stages");
        assert_eq!(back, path);
        assert_eq!(text, path.to_string_lossy());
        assert_eq!(std::fs::read(&path).expect("reads"), b"bundle");
        std::fs::remove_file(&path).expect("removes");
        assert!(!path.exists());
    }

    #[test]
    fn config_refuses_without_trust() {
        assert!(quiche_config(&[], None).is_none());
        assert!(quiche_config(&[vec![0u8; 16]], None).is_none());
    }

    #[test]
    fn config_loads_a_minted_anchor() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()]).expect("mints");
        let roots = parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        assert!(quiche_config(&roots, None).is_some());
        assert!(quiche_config(&roots, Some("bbr")).is_some());
        assert!(quiche_config(&roots, Some("no-such-cc")).is_none());
    }
}
