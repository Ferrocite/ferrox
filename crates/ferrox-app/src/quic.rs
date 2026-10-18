use crate::conn::Connection;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

impl QuicServer {
    /// What a dial shares with the connections it can ride: everything that changes which edge and which trust the connection belongs to.
    fn of(dial: &QuicDial) -> Self {
        Self {
            address: dial.address.clone(),
            port: dial.port,
            host: dial.host.clone(),
            upstream: dial.upstream.clone(),
            roots: dial.roots.clone(),
        }
    }
}

/// How many flows one lane lends before it is handed back for a fresh dial: reuse without a bound is the leak the lane was first closed for, and a stream id only comes back if the edge grants it.
pub(crate) const MAX_FLOWS_ON_LANE: u64 = 64;

struct PooledState {
    sessions: HashMap<u64, Connection>,
    opening: HashSet<u64>,
    next_id: u64,
    /// When the lane's pump parked with no lease on it, or none while a pump thread owns it: the thread follows the leases, so an idle edge pins no thread and the next flow rides the same handshake.
    parked: Option<Instant>,
}

/// The shared connection a flow rides, its socket, its local address, and the bidirectional stream id it opened.
pub(crate) struct PooledStream {
    pub(crate) conn: Arc<Mutex<quiche::Connection>>,
    pub(crate) sock: Arc<Datagram>,
    pub(crate) local: SocketAddr,
    pub(crate) id: u64,
    /// The pool entry the stream was taken from, or none when it was built outside the pool: dropping the stream is what hands the id back, so no path that ends a flow has to remember to.
    entry: Option<PooledConn>,
}

impl Drop for PooledStream {
    /// One owner, so a lane that finishes, an open that fails and a caller that returns early all pay the pool back; an id left on the table would be a stream the lane lent and never got back.
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            leave_session(&entry.table, self.id);
        }
    }
}

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
    /// The connection already open to this edge, if there is one a flow can still ride.
    fn stream(&self, dial: &QuicDial) -> Option<PooledConn> {
        let key = QuicServer::of(dial);
        let entry = self.inner.lock().ok()?.get(&key).cloned()?;
        // Spent or let go by the edge while parked: hand the lane back rather than ride it, and the caller's `or_else` dials the next one.
        if flow_credit(&entry) && lane_is_live(&entry) {
            return Some(entry);
        }
        self.retire(&key, &entry);
        None
    }

    /// Drop this lane and no other: a concurrent dial can have put a fresh connection under the same key while we were reading the old one.
    fn retire(&self, key: &QuicServer, entry: &PooledConn) {
        if let Ok(mut pool) = self.inner.lock() {
            if pool
                .get(key)
                .is_some_and(|live| Arc::ptr_eq(&live.conn, &entry.conn))
            {
                pool.remove(key);
            }
        }
        // A lane still carrying flows leaves the pool without a goodbye: a `done` frame here would end streams a flow is mid-write to. Its own last lease parks it, and the connection goes with the leases that held it.
        let Ok(mut conn) = entry.conn.lock() else {
            return;
        };
        if entry
            .table
            .lock()
            .is_ok_and(|table| table.sessions.is_empty() && table.opening.is_empty())
        {
            let _ = conn.close(false, 0, b"done");
            flush_egress(&mut conn, &entry.sock);
        }
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

/// A datagram buffer with no zero pass: the call the slice is handed to writes every byte it reports.
pub(crate) struct Unfilled<const N: usize>([std::mem::MaybeUninit<u8>; N]);

impl<const N: usize> Unfilled<N> {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self([std::mem::MaybeUninit::<u8>::uninit(); N])
    }

    #[must_use]
    pub(crate) fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: every byte read out of here was written by the call this slice was handed to.
        unsafe { std::slice::from_raw_parts_mut(self.0.as_mut_ptr().cast::<u8>(), N) }
    }
}

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
    // A PEM line is 48 input bytes except the last, so the full line is the hot case. Over it the group index is a fixed-range induction variable: bytes[gi*3..][..3] stays under 48 and out[gi*4..][..4] under 64 for every gi in 0..16, so the compiler proves every access in range and the line encodes as straight-line loads, shifts and stores with no bounds check and no per-group slice re-slicing.
    if bytes.len() == 48 {
        for gi in 0..16 {
            let (s, d) = (gi * 3, gi * 4);
            let word = (u32::from(bytes[s]) << 16)
                | (u32::from(bytes[s + 1]) << 8)
                | u32::from(bytes[s + 2]);
            out[d] = B64[(word >> 18) as usize];
            out[d + 1] = B64[((word >> 12) & 63) as usize];
            out[d + 2] = B64[((word >> 6) & 63) as usize];
            out[d + 3] = B64[(word & 63) as usize];
        }
        return 64;
    }
    let mut written = 0;
    let mut rest = bytes;
    // A full three-byte group needs no serial shift-and-or to build the word and no per-slot branch: the three bytes load straight into a 24-bit window at fixed shifts, and the four sextets are fixed shifts written as four stores. This is the whole 48-byte line sixteen times over; the padding case lands once, on the line's tail.
    while let Some(g) = rest.first_chunk::<3>() {
        let word = (u32::from(g[0]) << 16) | (u32::from(g[1]) << 8) | u32::from(g[2]);
        out[written] = B64[(word >> 18) as usize];
        out[written + 1] = B64[((word >> 12) & 63) as usize];
        out[written + 2] = B64[((word >> 6) & 63) as usize];
        out[written + 3] = B64[(word & 63) as usize];
        written += 4;
        rest = &rest[3..];
    }
    // The trailing one or two bytes, the only place a pad appears, reached once per line.
    match rest {
        [a] => {
            let w = u32::from(*a) << 16;
            out[written] = B64[(w >> 18) as usize];
            out[written + 1] = B64[((w >> 12) & 63) as usize];
            out[written + 2] = b'=';
            out[written + 3] = b'=';
            written += 4;
        }
        [a, b] => {
            let w = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            out[written] = B64[(w >> 18) as usize];
            out[written + 1] = B64[((w >> 12) & 63) as usize];
            out[written + 2] = B64[((w >> 6) & 63) as usize];
            out[written + 3] = b'=';
            written += 4;
        }
        _ => {}
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

/// The exact byte length `der_to_pem` writes: two header lines of `11 + label + 6` and `9 + label + 6`, plus one base64 line per 48 input bytes (64 chars full, `4 · ⌈rem/3⌉` partial) and its newline.
fn pem_capacity(der_len: usize, label_len: usize) -> usize {
    let full = der_len / 48;
    let rem = der_len % 48;
    let lines = full + usize::from(rem != 0);
    (11 + label_len + 6) + (full * 64 + rem.div_ceil(3) * 4) + lines + (9 + label_len + 6)
}

pub(crate) fn der_to_pem(der: &[u8], label: &str) -> Vec<u8> {
    let mut pem = Vec::with_capacity(pem_capacity(der.len(), label.len()));
    append_pem(&mut pem, der, label);
    pem
}

/// Append one PEM block into a buffer the caller has already reserved to `pem_capacity`, so the fill is memcpy into live capacity — no reallocation moves the bytes already there. The reservation is the caller's single job: `der_to_pem` opens the exact length and the chain and bundle open the summed length, so re-reserving per block would only recompute `pem_capacity`'s arithmetic and hit a no-op the callers already proved.
fn append_pem(pem: &mut Vec<u8>, der: &[u8], label: &str) {
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

/// One ALPN and one flow-control shape for the lane: a weaker peer negotiates down, never up.
pub(crate) fn tune(config: &mut quiche::Config, alpn: &[u8]) -> bool {
    if config.set_application_protos(&[alpn]).is_err() {
        return false;
    }
    config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
    config.set_initial_max_data(MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_uni(MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(MAX_STREAMS);
    config.set_initial_max_streams_uni(MAX_STREAMS);
    true
}

/// A serving identity: the lane's own tuning plus the certificate chain quiche reads at load time.
pub(crate) fn serve_config(identity: &ferrox_core::tls::TlsServerConfig) -> Option<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
    if !tune(&mut config, ALPN) {
        return None;
    }
    let label = match identity.key_kind {
        ferrox_core::tls::ServerKeyKind::Pkcs8 => "PRIVATE KEY",
        ferrox_core::tls::ServerKeyKind::Sec1 => "EC PRIVATE KEY",
        ferrox_core::tls::ServerKeyKind::Pkcs1 => "RSA PRIVATE KEY",
    };
    let mut chain = Vec::with_capacity(
        identity
            .cert_chain
            .iter()
            .map(|der| pem_capacity(der.len(), "CERTIFICATE".len()))
            .sum(),
    );
    for der in &identity.cert_chain {
        append_pem(&mut chain, der, "CERTIFICATE");
    }
    let key = der_to_pem(&identity.key_der, label);
    let (cert_path, cert_text) = stage_trust_file(&chain)?;
    let (key_path, key_text) = stage_trust_file(&key)?;
    let loaded = config
        .load_cert_chain_from_pem_file(&cert_text)
        .and(config.load_priv_key_from_pem_file(&key_text))
        .is_ok();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    loaded.then_some(config)
}

pub(crate) fn quiche_config(roots: &[Vec<u8>], cc: Option<&str>) -> Option<quiche::Config> {
    if roots.is_empty() {
        return None;
    }
    let mut bundle = Vec::with_capacity(
        roots
            .iter()
            .map(|der| pem_capacity(der.len(), "CERTIFICATE".len()))
            .sum(),
    );
    for root in roots {
        append_pem(&mut bundle, root, "CERTIFICATE");
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
    let mut room = Unfilled::<MAX_DATAGRAM>::new();
    let out = room.as_mut();
    while let Ok((written, info)) = conn.send(out) {
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
    let mut room = Unfilled::<MAX_DATAGRAM>::new();
    let buf = room.as_mut();
    match sock.recv_from(buf) {
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
                if written == 0 && !send_credit_wait(conn, sock, deadline) {
                    return false;
                }
            }
            Err(quiche::Error::Done) => {
                if !send_credit_wait(conn, sock, deadline) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    flush_egress(conn, sock);
    true
}

/// Flush, then read the socket before retrying a blocked send: sleeping deaf to it leaves the peer's
/// `MAX_STREAM_DATA` unread, so a send past the initial flow window never resumes.
fn send_credit_wait(conn: &mut quiche::Connection, sock: &Datagram, deadline: Instant) -> bool {
    flush_egress(conn, sock);
    if Instant::now() >= deadline {
        return false;
    }
    let Ok(local) = sock.local_addr() else {
        return false;
    };
    let left = deadline.saturating_duration_since(Instant::now());
    pump_once(conn, sock, local, left)
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

/// A socket read one packet at a time: Linux coalesces loopback skbs, so GRO is switched off per socket,
/// and every lane asks for a receive buffer before a first datagram can land on it.
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
    set_receive_buffer(&sock, DATAGRAM_RECV_BUF);
    Ok(sock)
}

/// The receive buffer a lane's socket asks for: the edge is granted a whole stream window of datagrams
/// at once (`MAX_STREAM_DATA`), so a socket holding a few of them turns every pause in the pump into
/// loss the lane pays for in retransmit timers rather than in packets.
const DATAGRAM_RECV_BUF: i32 = 1 << 20;

/// The least the ask has to land as for the lane to be worth reading back: a Linux default already clears it, a macOS and a Windows default do not, which is where the arm is observable.
#[cfg(test)]
const DATAGRAM_RECV_BUF_FLOOR: i32 = 1 << 18;

/// Ask the socket for `bytes` of receive buffer; a platform that caps the ask hands back what it granted.
#[cfg(unix)]
fn set_receive_buffer(sock: &UdpSocket, bytes: i32) {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `bytes` outlives the call, and the size is its own.
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(bytes).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                .unwrap_or(libc::socklen_t::MAX),
        );
    }
}

/// What the socket actually holds, as the kernel reports it.
#[cfg(all(test, unix))]
fn receive_buffer(sock: &UdpSocket) -> i32 {
    use std::os::fd::AsRawFd as _;
    let mut got: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `got` and `len` are the buffer and the length the kernel writes through.
    let ok = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of_mut!(got).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if ok == 0 {
        got
    } else {
        0
    }
}

/// Ask the socket for `bytes` of receive buffer; a platform that caps the ask hands back what it granted.
#[cfg(windows)]
fn set_receive_buffer(sock: &UdpSocket, bytes: i32) {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOL_SOCKET, SO_RCVBUF};
    // SAFETY: `bytes` outlives the call, the handle is the socket's own, and the length is that of the value pointed at.
    unsafe {
        setsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_RCVBUF,
            std::ptr::addr_of!(bytes).cast(),
            i32::try_from(std::mem::size_of::<i32>()).unwrap_or(i32::MAX),
        );
    }
}

/// What the socket actually holds, as the kernel reports it.
#[cfg(all(test, windows))]
fn receive_buffer(sock: &UdpSocket) -> i32 {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{getsockopt, SOL_SOCKET, SO_RCVBUF};
    let mut got: i32 = 0;
    let mut len = i32::try_from(std::mem::size_of::<i32>()).unwrap_or(i32::MAX);
    // SAFETY: `got` and `len` are the buffer and the length the kernel writes through, on the socket's own handle.
    let ok = unsafe {
        getsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_RCVBUF,
            std::ptr::addr_of_mut!(got).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if ok == 0 {
        got
    } else {
        0
    }
}

/// One datagram socket: a relay or an obfuscation below changes no handshake, frame or stream above, so the hops live here.
pub(crate) struct Datagram {
    sock: UdpSocket,
    relay: Option<Relay>,
    obfs: Option<ferrox_core::hysteria::Salamander>,
    /// A hopped client dial: the server port moves on a schedule and the socket
    /// with it, so a UDP flow keeps ending and a new one starting to a filter.
    /// Shared behind an `Arc` so a writer clone and a reader clone move together.
    hop: Option<Arc<Hopper>>,
}

/// Where datagrams go. The association's control connection is held, never read: dropping it ends it.
#[derive(Clone)]
struct Relay {
    via: SocketAddr,
    _control: Arc<Connection>,
}

/// The most one datagram costs in headers: two reserved bytes, one flag byte, the longest address and the port.
const RELAY_HEADER: usize = 22;

/// One obfuscated datagram is a salt ahead of the QUIC packet it masks, so the wire frame is a salt wider than the largest plain datagram.
const SALAMANDER_SALT: usize = ferrox_core::hysteria::SALAMANDER_SALT;

/// How long a socket the schedule just left stays readable, so a reply still in
/// flight on the old flow is not lost the instant the port moves. The reference
/// lingers the same ten seconds; a datagram that misses both windows is a real loss.
const HOP_LINGER: u64 = 10_000;

/// The moving part of a hopped dial: the socket the current stay reads and writes
/// through, the server port it is aimed at, when the stay ends, and — until its
/// linger expires — the socket the stay just left, still read for its replies.
struct HopState {
    current: Arc<UdpSocket>,
    port: u16,
    until: Instant,
    previous: Option<(Arc<UdpSocket>, Instant)>,
}

/// A client datagram socket that moves its server destination port among `ports`
/// every `interval_ms`, binding a fresh local socket on each move so a filter sees a
/// new flow rather than one long-lived one. Only the server's own port moves: a
/// datagram addressed elsewhere passes through on the same flow. A reply from any
/// hopped port is turned back to the nominal `server` port so QUIC above, which
/// named the connection by one peer, keeps accepting it. The rotation and the stay
/// come from the core's pure `pick_next`/`stay_ms`, fed one rng roll each, so nothing
/// here is left to prove by reading.
pub(crate) struct Hopper {
    server: SocketAddr,
    ports: Vec<u16>,
    interval_ms: (u64, u64),
    bind: &'static str,
    /// The socket the dial opened with, kept so a poisoned schedule lock — unreachable
    /// while the guarded sections panic-free — can still carry a fixed flow.
    anchor: Arc<UdpSocket>,
    timeout: Mutex<Option<Duration>>,
    state: Mutex<HopState>,
}

/// One 64-bit draw folded into the core's pure pick and stay. A failure yields 0,
/// which still names a valid port and stay, so the hop degrades to a fixed schedule
/// rather than failing the dial outright.
fn entropy() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).map_or(0, |()| u64::from_le_bytes(bytes))
}

impl Hopper {
    /// Begin a plan from `first`, the socket the dial opened to the nominal port: its
    /// clone is the first current socket, so a handshake named for `server` can finish
    /// before the schedule ever moves. The port and stay are drawn up front.
    fn open(
        server: SocketAddr,
        ports: Vec<u16>,
        interval_ms: (u64, u64),
        bind: &'static str,
        first: &UdpSocket,
    ) -> std::io::Result<Self> {
        let anchor = Arc::new(first.try_clone()?);
        let current = Arc::clone(&anchor);
        let port = ferrox_core::hysteria::pick_next(&ports, server.port(), entropy() as usize);
        let until = Instant::now()
            + Duration::from_millis(ferrox_core::hysteria::stay_ms(interval_ms, entropy()));
        Ok(Self {
            server,
            ports,
            interval_ms,
            bind,
            timeout: Mutex::new(None),
            anchor,
            state: Mutex::new(HopState {
                current,
                port,
                until,
                previous: None,
            }),
        })
    }

    /// Stamp the dial's current read timeout onto a freshly bound socket, so a
    /// timeout set before a rotation still bites the socket bound in between.
    fn apply_timeout(&self, sock: &UdpSocket) {
        if let Ok(timeout) = self.timeout.lock() {
            let _ = sock.set_read_timeout(*timeout);
        }
    }

    /// The socket and server port for now, moving the schedule first when the current
    /// stay has run out: a fresh socket is bound and the old one kept until its linger
    /// expires, a new port picked and a new stay armed. A bind failure keeps the
    /// current socket rather than stalling the flow, but still repicks and re-arms so
    /// the next attempt moves on. Called on both send and receive, so one clock drives
    /// the whole connection.
    fn current(&self) -> (Arc<UdpSocket>, u16) {
        let Ok(mut state) = self.state.lock() else {
            return (Arc::clone(&self.anchor), self.server.port());
        };
        let now = Instant::now();
        if now >= state.until {
            let port =
                ferrox_core::hysteria::pick_next(&self.ports, state.port, entropy() as usize);
            let stay =
                Duration::from_millis(ferrox_core::hysteria::stay_ms(self.interval_ms, entropy()));
            if let Ok(sock) = bind_datagram(self.bind) {
                self.apply_timeout(&sock);
                let linger = now + Duration::from_millis(HOP_LINGER);
                state.previous = Some((
                    std::mem::replace(&mut state.current, Arc::new(sock)),
                    linger,
                ));
            }
            state.port = port;
            state.until = now + stay;
        }
        (Arc::clone(&state.current), state.port)
    }

    /// The socket and destination for a datagram aimed at `to`: only the server's own
    /// port moves, so a datagram to any other target keeps its address and the flow.
    fn egress(&self, to: SocketAddr) -> (Arc<UdpSocket>, SocketAddr) {
        let (sock, port) = self.current();
        if to != self.server || port == self.server.port() {
            return (sock, to);
        }
        let mut dest = self.server;
        dest.set_port(port);
        (sock, dest)
    }

    /// Write one datagram on the current flow, salting it first when obfuscated. Only
    /// the server's own datagram has its port rewritten; anything else is passed on.
    fn send(
        &self,
        buf: &[u8],
        to: SocketAddr,
        obfs: Option<&ferrox_core::hysteria::Salamander>,
    ) -> std::io::Result<usize> {
        let (sock, dest) = self.egress(to);
        let Some(obfs) = obfs else {
            return sock.send_to(buf, dest);
        };
        let mut wire = Unfilled::<{ MAX_DATAGRAM + SALAMANDER_SALT }>::new();
        let sealed = obfs
            .seal_into(buf, wire.as_mut())
            .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        sock.send_to(&wire.as_mut()[..sealed], dest)
    }

    /// Read one datagram, advancing the schedule first so a reader sees the same
    /// rotation a writer would and the socket just left still lingers. The current
    /// flow is tried, then the lingering one; a hopped reply source is turned back to
    /// the nominal server port. No data on either is the same `WouldBlock` a plain
    /// socket returns, so the drive loop keeps its no-packet path.
    fn recv(
        &self,
        buf: &mut [u8],
        obfs: Option<&ferrox_core::hysteria::Salamander>,
    ) -> std::io::Result<(usize, SocketAddr)> {
        let (current, _) = self.current();
        let previous = match self.state.lock() {
            Ok(mut state) => {
                if state
                    .previous
                    .as_ref()
                    .is_some_and(|(_, linger)| Instant::now() >= *linger)
                {
                    state.previous = None;
                }
                state.previous.as_ref().map(|(sock, _)| Arc::clone(sock))
            }
            Err(_) => None,
        };
        for sock in [Some(current), previous].into_iter().flatten() {
            match Self::read_into(&sock, buf, obfs) {
                Ok((found, mut from)) => {
                    if from.ip() == self.server.ip()
                        && ferrox_core::hysteria::is_hop_port(
                            &self.ports,
                            self.server.port(),
                            from.port(),
                        )
                    {
                        from.set_port(self.server.port());
                    }
                    return Ok((found, from));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }

    /// Read one datagram off `sock`, unmasking it into the caller's buffer when the
    /// lane is obfuscated — the salt is a payload byte the caller was not sized for.
    fn read_into(
        sock: &UdpSocket,
        buf: &mut [u8],
        obfs: Option<&ferrox_core::hysteria::Salamander>,
    ) -> std::io::Result<(usize, SocketAddr)> {
        let Some(obfs) = obfs else {
            return sock.recv_from(buf);
        };
        let mut room = Unfilled::<{ MAX_DATAGRAM + SALAMANDER_SALT }>::new();
        let (found, from) = sock.recv_from(room.as_mut())?;
        let Some(plain) = obfs.deobfuscate_in_place(&mut room.as_mut()[..found]) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        };
        let Some(out) = buf.get_mut(..plain) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        out.copy_from_slice(&room.as_mut()[..plain]);
        Ok((plain, from))
    }

    /// The current flow's address, read without moving the schedule.
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let Ok(state) = self.state.lock() else {
            return self.anchor.local_addr();
        };
        state.current.local_addr()
    }

    /// Record the timeout for sockets bound by later moves, and stamp it on the one
    /// reads will use now.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        if let Ok(mut applied) = self.timeout.lock() {
            *applied = timeout;
        }
        let Ok(state) = self.state.lock() else {
            return Ok(());
        };
        state.current.set_read_timeout(timeout)
    }
}

impl Datagram {
    pub(crate) fn plain(sock: UdpSocket) -> Self {
        Self {
            sock,
            relay: None,
            obfs: None,
            hop: None,
        }
    }

    /// A socket whose every datagram is salamander-masked under `obfs`, the Hysteria v2 `obfs: salamander` lane.
    pub(crate) fn obfuscated(sock: UdpSocket, obfs: ferrox_core::hysteria::Salamander) -> Self {
        Self {
            sock,
            relay: None,
            obfs: Some(obfs),
            hop: None,
        }
    }

    pub(crate) fn relayed(sock: UdpSocket, via: SocketAddr, control: Arc<Connection>) -> Self {
        Self {
            sock,
            relay: Some(Relay {
                via,
                _control: control,
            }),
            obfs: None,
            hop: None,
        }
    }

    /// A client dial that moves its server port among `ports` every `interval_ms`,
    /// opening a fresh local socket on each move so NAT sees a distinct flow. `server`
    /// is the address QUIC above names the connection by (the nominal port); replies
    /// from any hopped port are turned back to it. `obfs` still seals each datagram.
    pub(crate) fn hopped(
        server: SocketAddr,
        ports: Vec<u16>,
        interval_ms: (u64, u64),
        bind: &'static str,
        first: &UdpSocket,
        obfs: Option<ferrox_core::hysteria::Salamander>,
    ) -> std::io::Result<Self> {
        let hopper = Hopper::open(server, ports, interval_ms, bind, first)?;
        Ok(Self {
            sock: first.try_clone()?,
            relay: None,
            obfs,
            hop: Some(Arc::new(hopper)),
        })
    }

    pub(crate) fn send_to(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        if let Some(hop) = self.hop.as_ref() {
            return hop.send(buf, to, self.obfs.as_ref());
        }
        if self.obfs.is_none() && self.relay.is_none() {
            return self.sock.send_to(buf, to);
        }
        let mut room = Unfilled::<{ RELAY_HEADER + MAX_DATAGRAM }>::new();
        let framed = room.as_mut();
        // The socket is addressed to the hop rather than the target whenever a relay frames the datagram.
        let target = self.relay.as_ref().map_or(to, |relay| relay.via);
        let plain = match self.relay.as_ref() {
            None => buf,
            Some(_) => relay_frame(buf, to, framed)
                .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
        };
        let Some(obfs) = self.obfs.as_ref() else {
            return self.sock.send_to(plain, target);
        };
        // A fresh salt masks whatever the hop above produced.
        let mut wire = Unfilled::<{ MAX_DATAGRAM + SALAMANDER_SALT }>::new();
        let sealed = obfs
            .seal_into(plain, wire.as_mut())
            .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.sock.send_to(&wire.as_mut()[..sealed], target)
    }

    pub(crate) fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        if let Some(hop) = self.hop.as_ref() {
            return hop.recv(buf, self.obfs.as_ref());
        }
        let Some(obfs) = self.obfs.as_ref() else {
            return self.raw_recv_from(buf);
        };
        // The salt on the wire is a payload byte the caller's buffer was not sized for, so an obfuscated read lands in a scratch a salt wider and unmasks in place before copying back.
        let mut room = Unfilled::<{ MAX_DATAGRAM + SALAMANDER_SALT }>::new();
        let (found, from) = self.raw_recv_from(room.as_mut())?;
        let Some(plain) = obfs.deobfuscate_in_place(&mut room.as_mut()[..found]) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        };
        let Some(out) = buf.get_mut(..plain) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        out.copy_from_slice(&room.as_mut()[..plain]);
        Ok((plain, from))
    }

    /// A read with no obfuscation on it: plain bytes straight from the socket, or the relay hop stripped.
    fn raw_recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
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
        match self.hop.as_ref() {
            Some(hop) => hop.local_addr(),
            None => self.sock.local_addr(),
        }
    }

    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            sock: self.sock.try_clone()?,
            relay: self.relay.clone(),
            obfs: self.obfs.clone(),
            hop: self.hop.clone(),
        })
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        if let Some(hop) = self.hop.as_ref() {
            return hop.set_read_timeout(timeout);
        }
        self.sock.set_read_timeout(timeout)
    }
}

/// Frame one datagram behind the relay header that carries its real target, returning the bytes for the hop; `None` when `into` has no room. The socket itself is addressed to the hop, not `to`.
fn relay_frame<'a>(buf: &[u8], to: SocketAddr, into: &'a mut [u8]) -> Option<&'a [u8]> {
    let into = into.get_mut(..RELAY_HEADER + buf.len())?;
    // The hop reads these three before the target, so they are filled rather than left as stack garbage.
    into[..3].fill(0);
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
    Some(&into[..header + buf.len()])
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

/// The leases a readable stream belongs to: a stream nobody rides is drained here, so its bytes do not sit on a connection waiting for a flow that already ended.
fn hand_off(
    conn: &mut quiche::Connection,
    table: &Arc<Mutex<PooledState>>,
    chunk: &mut [u8],
    ready: &mut Vec<(u64, Connection)>,
) {
    for id in conn.readable() {
        let Ok(leases) = table.lock() else {
            break;
        };
        if leases.opening.contains(&id) {
            continue;
        }
        let Some(half) = leases
            .sessions
            .get(&id)
            .and_then(|half| half.try_clone().ok())
        else {
            drop(leases);
            while let Ok((n, _)) = conn.stream_recv(id, chunk) {
                if n == 0 {
                    break;
                }
            }
            continue;
        };
        ready.push((id, half));
    }
}

fn pump(
    shared: &Arc<Mutex<quiche::Connection>>,
    table: &Arc<Mutex<PooledState>>,
    sock: &Datagram,
    local: SocketAddr,
) {
    let mut ready: Vec<(u64, Connection)> = Vec::new();
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
            hand_off(&mut conn, table, &mut chunk, &mut ready);
            if conn.is_closed() {
                return;
            }
            // A quiet socket and an empty lane ends the thread; the lease that follows it starts the next one on the same connection.
            if incoming.is_none() && park_if_idle(table) {
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

/// Whether the lane still has streams to lend: `next_id` moves one bidi id per lease, so it counts every flow the connection has carried.
fn flow_credit(entry: &PooledConn) -> bool {
    entry
        .table
        .lock()
        .is_ok_and(|table| table.next_id / 4 < MAX_FLOWS_ON_LANE)
}

/// Whether the edge still holds the lane: quiche's idle timer is an absolute instant, so one timeout call across a park gap is the peer's arithmetic, not a budget of ours.
fn lane_is_live(entry: &PooledConn) -> bool {
    let Ok(mut conn) = entry.conn.lock() else {
        return false;
    };
    conn.on_timeout();
    !conn.is_closed()
}

/// Take a stream on the lane, and put a pump behind a parked one in the same table lock: a thread leaving an empty lane and a lease landing on it cannot both win the flag, so no flow waits on a thread that already ended.
fn lend(pooled: &PooledConn, up: Option<Connection>) -> Option<u64> {
    let mut table = pooled.table.lock().ok()?;
    if table.sessions.len() + table.opening.len() >= MAX_STREAMS as usize {
        return None;
    }
    if table.parked.take().is_some() {
        let (Ok(pump_sock), Ok(local)) = (pooled.sock.try_clone(), pooled.sock.local_addr()) else {
            table.parked = Some(Instant::now());
            return None;
        };
        let (shared, leases) = (Arc::clone(&pooled.conn), Arc::clone(&pooled.table));
        std::thread::spawn(move || pump(&shared, &leases, &pump_sock, local));
    }
    let id = table.next_id;
    table.next_id += 4;
    if let Some(up) = up {
        table.sessions.insert(id, up);
    }
    table.opening.insert(id);
    Some(id)
}

/// Whether the pump in hand should end: a lane no lease rides parks with its thread gone, so an idle edge costs no thread and keeps its handshake.
fn park_if_idle(table: &Arc<Mutex<PooledState>>) -> bool {
    table.lock().is_ok_and(|mut state| {
        if !state.sessions.is_empty() || !state.opening.is_empty() {
            return false;
        }
        state.parked = Some(Instant::now());
        true
    })
}

/// Hand the stream id back: the lane stays, and the pump parks itself once nothing else rides it, so the next flow rides the same handshake instead of paying for a new one.
fn leave_session(table: &Arc<Mutex<PooledState>>, id: u64) {
    if let Ok(mut table) = table.lock() {
        table.sessions.remove(&id);
        table.opening.remove(&id);
    }
}

fn uplink_stream(pooled: &PooledConn, id: u64, client: &Connection) {
    #[cfg(test)]
    let port = pooled.key.port;
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.table, id);
        return;
    };
    let Ok(mut plain) = client.try_clone() else {
        leave_session(&pooled.table, id);
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
                    port,
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
                        qstage(format!("{} t={} up-lock-none {id}", port, qms()));
                        break false;
                    };
                    #[cfg(test)]
                    qstage(format!(
                        "{} t={} up-lock {id} {}ms",
                        port,
                        qms(),
                        waited.elapsed().as_millis()
                    ));
                    if conn.is_closed() {
                        #[cfg(test)]
                        qstage(format!("{} t={} up-closed {id}", port, qms()));
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
                                    qstage(format!("{} t={} up-stall {id}", port, qms()));
                                    break false;
                                }
                                drop(conn);
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                        Err(quiche::Error::Done) => {
                            if Instant::now() >= deadline {
                                #[cfg(test)]
                                qstage(format!("{} t={} up-done-timeout {id}", port, qms()));
                                break false;
                            }
                            drop(conn);
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => {
                            #[cfg(test)]
                            qstage(format!("{} t={} up-err {id}", port, qms()));
                            break false;
                        }
                    }
                };
                if !sent {
                    #[cfg(test)]
                    qstage(format!("{} t={} up-unsent {id}", port, qms()));
                    break;
                }
                #[cfg(test)]
                qstage(format!("{} t={} up {id} {n}", port, qms()));
            }
        }
    }
    if let Ok(mut conn) = pooled.conn.lock() {
        let _ = conn.stream_send(id, &[], true);
    }
    #[cfg(test)]
    qstage(format!("{} t={} uplink-end {id}", port, qms()));
    leave_session(&pooled.table, id);
}

pub(crate) fn dial_pooled(
    client: &Connection,
    dial: &QuicDial,
    target: &crate::proxy::Destination,
) {
    let pooled = pool().stream(dial);
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
        if let Some(live) = pool.get(fresh.key.as_ref()) {
            if let Ok(mut conn) = fresh.conn.lock() {
                let _ = conn.close(false, 0, b"superseded");
            }
            Some(live.clone())
        } else {
            pool.insert(fresh.key.as_ref().clone(), fresh.clone());
            Some(fresh)
        }
    }) else {
        #[cfg(test)]
        qstage(format!("{} t={} build-none", dial.port, qms()));
        return;
    };
    let Some(id) = lend(&pooled, client.try_clone().ok()) else {
        #[cfg(test)]
        qstage(format!("{} t={} open-none", dial.port, qms()));
        return;
    };
    #[cfg(test)]
    qstage(format!("{} t={} opened {id}", dial.port, qms()));
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.table, id);
        return;
    };
    let Ok(local) = pooled.sock.local_addr() else {
        leave_session(&pooled.table, id);
        return;
    };
    let header = crate::proxy::vless_header(&dial.id, 1, target);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let opened = {
        let Ok(mut conn) = pooled.conn.lock() else {
            leave_session(&pooled.table, id);
            return;
        };
        stream_send_all(&mut conn, &flush_sock, id, &header, false, deadline)
            && stream_recv_exact(&mut conn, &flush_sock, local, id, 2, deadline).as_deref()
                == Some(&[0, 0])
    };
    #[cfg(test)]
    qstage(format!("{} t={} header {id} {opened}", dial.port, qms()));
    if !opened {
        leave_session(&pooled.table, id);
        return;
    }
    if let Ok(mut table) = pooled.table.lock() {
        table.opening.remove(&id);
    }
    #[cfg(test)]
    qstage(format!("{} t={} graduated {id}", dial.port, qms()));
    uplink_stream(&pooled, id, client);
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
    // The address is read before the id is taken: a lease that cannot say where it is has no id to give back yet.
    let local = pooled.sock.local_addr().ok()?;
    let id = lend(&pooled, None)?;
    Some(PooledStream {
        conn: Arc::clone(&pooled.conn),
        sock: Arc::clone(&pooled.sock),
        local,
        id,
        entry: Some(pooled),
    })
}

/// Whether the pool still holds a connection for this dial: an entry that has lent its whole grant is still held until a lease looks at it.
#[cfg(test)]
pub(crate) fn pool_holds(dial: &QuicDial) -> bool {
    peek(dial).is_some()
}

/// Whether a held lane has no pump: the flag is the pump's own way of saying it left, so this is the witness that an idle edge costs no thread.
#[cfg(test)]
pub(crate) fn lane_parked(dial: &QuicDial) -> bool {
    peek(dial).is_some_and(|lane| lane.table.lock().is_ok_and(|table| table.parked.is_some()))
}

/// Whether a held lane has no stream left to lend: past the grant a lease looks at it, the lane is handed back for a fresh dial.
#[cfg(test)]
pub(crate) fn lane_spent(dial: &QuicDial) -> bool {
    peek(dial).is_some_and(|lane| !flow_credit(&lane))
}

/// Whether a lookup hands this lane back: the judgement the pool makes, run without taking a lease or dialling the next one, so the witness sees the hand-back rather than a fresh connection.
#[cfg(test)]
pub(crate) fn lane_handed_back(dial: &QuicDial) -> bool {
    pool().stream(dial).is_none()
}

/// The lane a dial would be handed, read without judging it: a witness that retired what it was looking at would hide the leak it names.
#[cfg(test)]
fn peek(dial: &QuicDial) -> Option<PooledConn> {
    let key = QuicServer::of(dial);
    pool()
        .inner
        .lock()
        .ok()
        .and_then(|pool| pool.get(&key).cloned())
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
        let table = Arc::new(Mutex::new(PooledState {
            sessions: HashMap::new(),
            opening: HashSet::new(),
            next_id: 0,
            // No thread yet: the first lease on the lane starts the pump, so a connection nobody rode costs none.
            parked: Some(Instant::now()),
        }));
        return Some(PooledConn {
            conn: Arc::new(Mutex::new(conn)),
            table,
            sock: Arc::new(sock),
            key: Arc::new(QuicServer::of(dial)),
        });
    }
    None
}

/// One VLESS session on a serving connection: stream bytes through the shared connection lock.
#[derive(Clone)]
pub(crate) struct QuicStream {
    conn: Arc<Mutex<quiche::Connection>>,
    sock: Arc<Datagram>,
    id: u64,
}

/// How long one stream read polls quiche before idling: FIN and close land inside the next quantum.
const STREAM_QUANTUM: Duration = Duration::from_millis(100);

/// Between polls of quiche state, so a waiting read never holds the connection lock.
const STREAM_POLL: Duration = Duration::from_millis(5);

impl Read for QuicStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + STREAM_QUANTUM;
        loop {
            match self.conn.lock() {
                Ok(mut conn) => {
                    if conn.is_closed() {
                        return Ok(0);
                    }
                    let (n, fin) = match conn.stream_recv(self.id, buf) {
                        Ok(got) => got,
                        Err(quiche::Error::Done) => (0, false),
                        Err(error) => {
                            return Err(std::io::Error::other(format!(
                                "quic stream read: {error:?}"
                            )));
                        }
                    };
                    if n > 0 {
                        return Ok(n);
                    }
                    if fin {
                        return Ok(0);
                    }
                }
                Err(_) => {
                    return Err(std::io::Error::other("quic connection lock poisoned"));
                }
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            std::thread::sleep(STREAM_POLL);
        }
    }
}

impl Write for QuicStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // The lock covers one send each: a flow-control wait must not hold it, or ACKs stop arriving.
        let deadline = Instant::now() + SEND_WAIT;
        let mut rest = buf;
        while !rest.is_empty() {
            match self.send_once(rest) {
                Ok(0) => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("quic stream send timed out"));
                    }
                    std::thread::sleep(STREAM_POLL);
                }
                Ok(n) => rest = &rest[n..],
                Err(error) => return Err(error),
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("quic connection lock poisoned"));
        };
        flush_egress(&mut conn, &self.sock);
        Ok(())
    }
}

impl QuicStream {
    /// One send flight without holding the lock across the wait behind it.
    fn send_once(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("quic connection lock poisoned"));
        };
        match conn.stream_send(self.id, buf, false) {
            Ok(n) => {
                flush_egress(&mut conn, &self.sock);
                Ok(n)
            }
            Err(quiche::Error::Done) => Ok(0),
            Err(error) => Err(std::io::Error::other(format!(
                "quic stream send: {error:?}"
            ))),
        }
    }

    /// Half-close our direction: the peer reads everything sent, then EOF.
    pub(crate) fn fin(&self) -> bool {
        let Ok(mut conn) = self.conn.lock() else {
            return false;
        };
        let deadline = Instant::now() + SEND_WAIT;
        let done = stream_send_all(&mut conn, &self.sock, self.id, &[], true, deadline);
        flush_egress(&mut conn, &self.sock);
        done
    }

    /// Stop the stream in both directions; the connection itself is untouched.
    pub(crate) fn close(&self) {
        if let Ok(mut conn) = self.conn.lock() {
            let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Write, 0);
            let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Read, 0);
            flush_egress(&mut conn, &self.sock);
        }
    }
}

/// One serving session: the QUIC connection behind one lock, the stream ids already handed out.
struct ServerConn {
    conn: Arc<Mutex<quiche::Connection>>,
    seen: Mutex<HashSet<u64>>,
}

/// The per-stream entry point a VLESS inbound serves: one stream, one session, no shared state.
pub(crate) type Serve = Arc<dyn Fn(QuicStream) + Send + Sync>;

/// The driver's two datagram scratch buffers, passed as one so routing stays within the argument budget.
struct Scratch {
    buf: [u8; MAX_DATAGRAM],
    out: [u8; MAX_DATAGRAM],
}

/// The driver: one UDP socket is read by this loop alone, so no packet is fed to the wrong connection.
pub(crate) fn serve_loop(
    sock: Datagram,
    config: &Arc<Mutex<quiche::Config>>,
    serve: &Serve,
    stop: &Arc<AtomicBool>,
) {
    let Ok(local) = sock.local_addr() else {
        return;
    };
    let sock = Arc::new(sock);
    let mut conns: HashMap<Vec<u8>, Arc<ServerConn>> = HashMap::new();
    let mut scratch = Scratch {
        buf: [0u8; MAX_DATAGRAM],
        out: [0u8; MAX_DATAGRAM],
    };
    let mut applied: Option<Duration> = None;
    while !stop.load(Ordering::Relaxed) {
        let start = Instant::now();
        let mut wait = Duration::from_millis(100);
        for state in conns.values() {
            let Ok(conn) = state.conn.lock() else {
                continue;
            };
            if let Some(left) = conn.timeout() {
                wait = wait.min(left);
            }
        }
        wait = wait.max(Duration::from_millis(1));
        if applied != Some(wait) {
            if sock.set_read_timeout(Some(wait)).is_err() {
                return;
            }
            applied = Some(wait);
        }
        match sock.recv_from(&mut scratch.buf) {
            Ok((n, from)) => route(&sock, local, config, &mut conns, &mut scratch, n, from),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                let elapsed = start.elapsed();
                for state in conns.values() {
                    let Ok(mut conn) = state.conn.lock() else {
                        continue;
                    };
                    if conn.timeout().is_none_or(|left| left <= elapsed) {
                        conn.on_timeout();
                        flush_egress(&mut conn, &sock);
                    }
                }
            }
            Err(_) => return,
        }
        reap(serve, &sock, &mut conns);
    }
}

/// Source IDs quiche issues mid-connection: any packet may carry one, so every new one routes.
fn learn_ids(
    conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>,
    state: &Arc<ServerConn>,
    conn: &quiche::Connection,
) {
    for id in conn.source_ids() {
        if !conns.contains_key(id.as_ref()) {
            conns.insert(id.as_ref().to_vec(), Arc::clone(state));
        }
    }
}

/// One packet to its connection, or to a new connection when it knocks with an Initial.
fn route(
    sock: &Datagram,
    local: SocketAddr,
    config: &Arc<Mutex<quiche::Config>>,
    conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>,
    scratch: &mut Scratch,
    n: usize,
    from: SocketAddr,
) {
    let Scratch { buf, out } = scratch;
    let Ok(header) = quiche::Header::from_slice(&mut buf[..n], quiche::MAX_CONN_ID_LEN) else {
        return;
    };
    if let Some(state) = conns.get(header.dcid.as_ref()).cloned() {
        let Ok(mut conn) = state.conn.lock() else {
            return;
        };
        let info = quiche::RecvInfo { from, to: local };
        let _ = conn.recv(&mut buf[..n], info);
        flush_egress(&mut conn, sock);
        learn_ids(conns, &state, &conn);
        return;
    }
    if header.ty != quiche::Type::Initial {
        return;
    }
    if !quiche::version_is_supported(header.version) {
        if let Ok(len) = quiche::negotiate_version(&header.scid, &header.dcid, out) {
            let _ = sock.send_to(&out[..len], from);
        }
        return;
    }
    // Server SCIDs are the parse length, so short-header DCIDs read exactly, not into payload.
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    if getrandom::getrandom(&mut scid).is_err() {
        return;
    }
    let cid = quiche::ConnectionId::from_ref(&scid);
    let Ok(mut guard) = config.lock() else {
        return;
    };
    let Ok(mut conn) = quiche::accept(&cid, None, local, from, &mut guard) else {
        return;
    };
    drop(guard);
    let info = quiche::RecvInfo { from, to: local };
    if conn.recv(&mut buf[..n], info).is_err() {
        return;
    }
    flush_egress(&mut conn, sock);
    let state = Arc::new(ServerConn {
        conn: Arc::new(Mutex::new(conn)),
        seen: Mutex::new(HashSet::new()),
    });
    conns.insert(scid.to_vec(), Arc::clone(&state));
    conns.insert(header.dcid.as_ref().to_vec(), state);
}

/// New peer streams to sessions, finished ones out of the table, dead connections dropped.
fn reap(serve: &Serve, sock: &Arc<Datagram>, conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>) {
    // Closed connections drop every key they hold, so no routing entry outlives its connection.
    conns.retain(|_, state| state.conn.lock().is_ok_and(|conn| !conn.is_closed()));
    // New source IDs first: a packet carrying one must route on the next datagram.
    for state in conns.values().cloned().collect::<Vec<_>>() {
        let Ok(conn) = state.conn.lock() else {
            continue;
        };
        learn_ids(conns, &state, &conn);
    }
    let mut fresh: Vec<(Arc<Mutex<quiche::Connection>>, u64)> = Vec::new();
    for state in conns.values() {
        let Ok(conn) = state.conn.lock() else {
            continue;
        };
        let readable: Vec<u64> = conn.readable().collect();
        if let Ok(mut seen) = state.seen.lock() {
            for stream in readable {
                // Client bidirectional streams only: the H3 opening rides unidirectional ones.
                if stream % 4 != 0 || !seen.insert(stream) {
                    continue;
                }
                fresh.push((Arc::clone(&state.conn), stream));
            }
            seen.retain(|stream| !conn.stream_finished(*stream));
        }
    }
    for (conn, stream) in fresh {
        let session = QuicStream {
            conn,
            sock: Arc::clone(sock),
            id: stream,
        };
        let serve = Arc::clone(serve);
        std::thread::spawn(move || serve(session));
    }
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
    Some(PooledStream {
        conn: std::sync::Arc::new(std::sync::Mutex::new(conn)),
        sock: std::sync::Arc::new(sock),
        local,
        id: 4,
        // Built outside the pool: nothing to hand back when the lane ends.
        entry: None,
    })
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
    assert!(tune(&mut config, alpn), "the lane tuning holds");
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

    /// The lane asks for a receive buffer before a first datagram can land on it, and the ask is read back rather than assumed: a parked lane holds whatever the edge sent while no pump owned the socket, and a default buffer would drop it.
    #[test]
    fn a_quic_socket_arms_its_receive_buffer() {
        let sock = bind_datagram("127.0.0.1:0").expect("binds");
        assert!(
            receive_buffer(&sock) >= DATAGRAM_RECV_BUF_FLOOR,
            "the lane asked for {} and holds {}",
            DATAGRAM_RECV_BUF,
            receive_buffer(&sock)
        );
    }

    #[test]
    fn a_relayed_datagram_frames_its_target_ahead_of_its_payload() {
        use crate::conn::Connection;
        let association = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let control = Connection::connect(association.local_addr().expect("addr")).expect("dials");
        let _ = association.accept().expect("accepts");
        let hop = bind_datagram("127.0.0.1:0").expect("binds");
        let target = bind_datagram("127.0.0.1:0").expect("binds");
        let lane = Datagram::relayed(
            bind_datagram("127.0.0.1:0").expect("binds"),
            hop.local_addr().expect("addr"),
            std::sync::Arc::new(control),
        );
        let SocketAddr::V4(target) = target.local_addr().expect("addr") else {
            panic!("a v4 target");
        };
        lane.send_to(b"ping", target.into())
            .expect("frames and sends");
        hop.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("times out");
        let mut got = [0u8; 32];
        let (n, _) = hop.recv_from(&mut got).expect("the hop reads it");
        let mut want = vec![0, 0, 0, 1];
        want.extend_from_slice(&target.ip().octets());
        want.extend_from_slice(&target.port().to_be_bytes());
        want.extend_from_slice(b"ping");
        assert_eq!(
            &got[..n],
            &want[..],
            "reserved, fragment, family, address, port, payload"
        );
    }

    #[test]
    fn an_obfuscated_lane_round_trips_a_full_datagram_over_loopback() {
        let obfs = || ferrox_core::hysteria::Salamander::new("hy2!").expect("four-byte key");
        let server = Datagram::obfuscated(bind_datagram("127.0.0.1:0").expect("binds"), obfs());
        let client = Datagram::obfuscated(bind_datagram("127.0.0.1:0").expect("binds"), obfs());
        let peer = server.local_addr().expect("addr");
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("times out");
        // A full-sized plain datagram is salt wider on the wire, so the send frame is one the caller buffer was never sized for.
        let plain = [0x5au8; MAX_DATAGRAM];
        client.send_to(&plain, peer).expect("seals and sends");
        let mut got = [0u8; MAX_DATAGRAM];
        let (n, from) = server.recv_from(&mut got).expect("reads a salted frame");
        assert_eq!(n, plain.len(), "the salt never reaches the caller");
        assert_eq!(&got[..n], &plain[..], "unmasked to the bytes that went in");
        assert_eq!(
            from,
            client.local_addr().expect("addr"),
            "the peer survives the hop"
        );
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

    /// The allocation claim, gated: a PEM buffer reserved to `pem_capacity` lands at exactly its length, so filling it never reallocates and copies what was already written.
    #[test]
    fn a_pem_buffer_is_reserved_to_its_exact_length() {
        for len in [0usize, 1, 2, 3, 46, 47, 48, 49, 96, 97, 143, 300] {
            let pem = der_to_pem(&vec![0x5au8; len], "CERTIFICATE");
            assert_eq!(
                pem.len(),
                pem.capacity(),
                "len {len}: a slack capacity means a reallocation copied the prefix"
            );
        }
    }

    /// Pointer identity witnesses the removed double buffer: appending a second block into a buffer reserved for both leaves the first block's address unmoved, and the bytes are the concatenation the old `extend_from_slice(&der_to_pem(..))` produced.
    #[test]
    fn appending_into_a_reserved_buffer_does_not_move_it() {
        let first = der_to_pem(&[7u8; 30], "CERTIFICATE");
        let second = der_to_pem(&[9u8; 50], "CERTIFICATE");
        let mut chain = Vec::with_capacity(first.len() + second.len());
        append_pem(&mut chain, &[7u8; 30], "CERTIFICATE");
        let base = chain.as_ptr();
        append_pem(&mut chain, &[9u8; 50], "CERTIFICATE");
        assert_eq!(
            base,
            chain.as_ptr(),
            "the second append reallocated away the first — a copy the reservation was meant to avoid"
        );
        let mut want = first;
        want.extend_from_slice(&second);
        assert_eq!(
            chain, want,
            "the appended bytes match the old double-buffer output"
        );
    }

    /// Bit-identity across the wrap and pad boundaries: the reservation changed where bytes land, never which bytes.
    #[test]
    fn pem_survives_the_pad_and_wrap_boundaries() {
        for len in [1usize, 2, 3, 4, 46, 47, 48, 49, 50, 51, 95, 96, 97] {
            let der: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i).expect("len < 256"))
                .collect();
            let pem = der_to_pem(&der, "CERTIFICATE");
            assert_eq!(parse_ca_pem(&pem), vec![der], "len {len}");
        }
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

    fn minted_identity() -> ferrox_core::tls::TlsServerConfig {
        let minted =
            rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()]).expect("mints");
        let roots = parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        ferrox_core::tls::TlsServerConfig {
            cert_chain: roots,
            key_der: minted.key_pair.serialize_der(),
            key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
            alpn: Vec::new(),
            send_tickets: true,
        }
    }

    #[test]
    fn serve_config_loads_a_minted_identity() {
        assert!(serve_config(&minted_identity()).is_some());
    }

    #[test]
    fn serve_config_refuses_without_a_chain_or_key() {
        let empty = ferrox_core::tls::TlsServerConfig {
            cert_chain: Vec::new(),
            key_der: Vec::new(),
            key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
            alpn: Vec::new(),
            send_tickets: true,
        };
        assert!(serve_config(&empty).is_none());
        let mut no_key = minted_identity();
        no_key.key_der = vec![0u8; 16];
        assert!(serve_config(&no_key).is_none());
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

    /// A handful of listeners stand in for the ports a firewall forwards to one
    /// server. A zero-millisecond stay forces the schedule to move on every send, so
    /// a burst aimed at the nominal address must spread over more than one port and
    /// every datagram must land on exactly one — a witness that the egress port is
    /// really rewritten and that the move opens a real, delivering socket.
    #[test]
    fn a_hopped_dial_spreads_its_datagrams_over_more_than_one_server_port() {
        let mut ports = Vec::new();
        let mut listeners = Vec::new();
        for _ in 0..4 {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
            ports.push(sock.local_addr().expect("addr").port());
            sock.set_read_timeout(Some(Duration::from_millis(20))).ok();
            listeners.push(sock);
        }
        let server: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse().expect("addr");
        let first = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let hop = Datagram::hopped(server, ports.clone(), (0, 0), "0.0.0.0:0", &first, None)
            .expect("hops");
        let sends = 200;
        for _ in 0..sends {
            hop.send_to(b"ping", server).expect("sends");
        }
        let mut received = 0usize;
        let mut touched = std::collections::HashSet::new();
        for listener in &listeners {
            let mut buf = [0u8; 64];
            while let Ok((n, _)) = listener.recv_from(&mut buf) {
                if n == 0 {
                    break;
                }
                received += 1;
                touched.insert(listener.local_addr().expect("addr").port());
            }
        }
        assert_eq!(received, sends, "every datagram reached exactly one port");
        assert!(
            touched.len() > 1,
            "the plan moved off the single dialed port"
        );
    }

    /// A long stay holds the schedule still, so one socket carries the flow. The
    /// opening pick is some port other than the nominal one; whichever listener
    /// receives the burst is the current port, and its reply must read back with the
    /// nominal server port so QUIC above, which named the peer by one address, still
    /// accepts it — the witness that a hopped reply source is turned back.
    #[test]
    fn a_reply_from_a_hopped_port_reads_back_as_the_nominal_server() {
        let mut ports = Vec::new();
        let mut listeners = Vec::new();
        for _ in 0..4 {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
            ports.push(sock.local_addr().expect("addr").port());
            sock.set_read_timeout(Some(Duration::from_millis(50))).ok();
            listeners.push(sock);
        }
        let server: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse().expect("addr");
        let first = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let still = u64::MAX / 4;
        let hop = Datagram::hopped(
            server,
            ports.clone(),
            (still, still),
            "0.0.0.0:0",
            &first,
            None,
        )
        .expect("hops");
        hop.send_to(b"ping", server).expect("sends");
        let mut landed = None;
        for listener in &listeners {
            let mut buf = [0u8; 64];
            if let Ok((n, src)) = listener.recv_from(&mut buf) {
                if n > 0 {
                    listener.send_to(b"pong", src).expect("replies");
                    landed = Some(listener.local_addr().expect("addr").port());
                    break;
                }
            }
        }
        let hop_port = landed.expect("the burst landed on a hopped port");
        assert_ne!(
            hop_port,
            server.port(),
            "the current port is not the nominal"
        );
        let mut buf = [0u8; 64];
        hop.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("timeout");
        let (n, from) = hop.recv_from(&mut buf).expect("reads the reply");
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(from.ip(), server.ip());
        assert_eq!(
            from.port(),
            server.port(),
            "the hopped source became the nominal"
        );
    }
}
