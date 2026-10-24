use crate::b64;
use std::fmt;

pub trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

/// The trust anchors a dial verifies with, as DER certificates behind one allocation: a config names them, it does not own a copy of them, so a dial costs a reference count rather than the whole platform store.
pub type Anchors = std::sync::Arc<[Vec<u8>]>;

#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub server_name: String,
    /// The `ALPN` list a client offers, behind one allocation: a config names it once, and the client's own cache keys on it, so a per-dial copy was a vector of vectors paid on every handshake.
    pub alpn: std::sync::Arc<[Vec<u8>]>,
    pub roots: Anchors,
    /// Leaf keys to accept: a chain that verified must still hold one, and a
    /// chain this device cannot build is verified against the pinned leaf as its
    /// own anchor. Empty pins nothing and refuses nothing, which is the default
    /// because a lane with no pins is the ordinary case.
    pub pins: crate::foxy::pin::Pins,
    /// The `cipher_suites` ids a client advertises, in `crypto/tls` order, from xray's
    /// `tlsSettings.cipherSuites`. Empty means the config named none, so the backend keeps
    /// its stock ordering; see `cipher_suites` for how a non-empty list is built.
    pub cipher_suites: Vec<u16>,
    /// Accept the peer chain as presented, keeping only the handshake signature that binds
    /// it to the key exchange: xray's `allowInsecure`, read by a masquerade cover's
    /// `masq_url_insecure` origin and by an outbound that names it. `false` is the default
    /// because verifying is the ordinary case, and an unchecked chain is a deliberate,
    /// bounded exception rather than a mode.
    pub insecure: bool,
    /// SHA-256 digests over whole certificates (`pinnedPeerCertSha256`): a digest matching
    /// the leaf's DER accepts the handshake on the pin alone, one matching an intermediate's
    /// verifies the chain with that certificate as the only root and the server name alongside.
    /// Empty pins nothing, so the ordinary chain verifier stands.
    pub cert_pins: std::sync::Arc<[[u8; 32]]>,
    /// The browser hello to shape, or `None` to keep the stock rustls hello.
    pub fingerprint: Option<shaped::Fingerprint>,
    /// The ECH config list a client encrypts its inner hello with, fetched or decoded
    /// before the dial; `None` keeps the hello plaintext.
    pub ech_config_list: Option<std::sync::Arc<[u8]>>,
    /// Whether the carrier is a WebSocket or `HTTPUpgrade`: xray's parrots then force
    /// the outer ALPN to `http/1.1` so the upgrade reads as an ordinary browser.
    pub websocket: bool,
}

pub trait TlsProvider: std::io::Read + std::io::Write {
    fn name() -> &'static str
    where
        Self: Sized;

    fn suites(&self) -> Vec<String>;

    fn handshake(&mut self) -> Result<(), TlsError>;

    fn alpn(&self) -> Option<&[u8]>;

    /// The leaf certificate the peer presented, once the handshake has
    /// completed. A provider that cannot reach it answers `None` rather than
    /// failing, because a lane with pins needs it and one without does not.
    fn peer_leaf(&self) -> Option<&[u8]> {
        None
    }

    /// The ciphertext the caller read from the transport is decrypted, and the plaintext comes
    /// out: the caller read the transport itself, so the wait for the peer's bytes happened
    /// outside this session's lock, and only the decryption is under it. The plaintext's length
    /// and the ciphertext's length come back together, because a session takes only what its
    /// own buffer has room for and the rest is the caller's to feed again. A provider that
    /// reads its own transport has no use for this and says so.
    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        let _ = (ciphertext, buf);
        Err(std::io::Error::other(
            "this provider reads its own transport",
        ))
    }

    /// The plaintext is encrypted under this session's lock into the caller's buffer, and the
    /// ciphertext leaves for the transport only after the lock is dropped: a peer that stopped
    /// draining this direction then parks that transport write alone instead of the decryption
    /// the other direction needs. A provider that writes its own transport falls back to `write`.
    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        let _ = out;
        std::io::Write::write(self, plaintext)
    }

    /// Several slices sealed in one call, so a caller's frame reaches the session as the
    /// segments it was handed rather than a copy staged into one buffer.
    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        for part in parts {
            let mut left = *part;
            while !left.is_empty() {
                let wrote = self.seal_into(left, out)?;
                if wrote == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
                }
                left = &left[wrote..];
            }
        }
        Ok(())
    }
}

/// Stops the socket reads behind a session at TLS record ends once Vision can go direct, so the unwrap finds every following byte still in the kernel.
pub trait RecordAlignment {
    fn engage_record_alignment(&mut self) {}

    /// Stops bounding and tracking reads: a session that never goes direct pays no per-read bookkeeping.
    fn disarm_record_alignment(&mut self) {}

    /// Write several slices in one completion, so the bytes go out together and the alignment read happens once.
    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()>
    where
        Self: std::io::Write,
    {
        for part in parts {
            std::io::Write::write_all(self, part)?;
        }
        Ok(())
    }
}

// A bare socket keeps every byte in the kernel, so there is nothing to bound.
impl RecordAlignment for std::net::TcpStream {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    Timeout,
    /// Why the chain was refused, carried by the kind: folding a variant into `Other` to hold a message erases the kind, and a caller that cannot match a refused chain cannot act on it — it cannot tell the user, and it cannot stop retrying an edge no retry will make trusted.
    BadCertificate(String),
    Closed,
    NoSharedCipher,
    /// The server refused the ECH offer and named the list to offer next.
    EchRetry(std::sync::Arc<[u8]>),
    Other(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("handshake timed out"),
            Self::BadCertificate(why) => write!(f, "certificate did not verify: {why}"),
            Self::Closed => f.write_str("connection closed by peer"),
            Self::NoSharedCipher => f.write_str("no shared cipher suite"),
            Self::EchRetry(_) => f.write_str("the server asked for another ECH config"),
            Self::Other(why) => write!(f, "backend error: {why}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl TlsError {
    /// Whether an I/O error is a timeout: the socket said so, or the stack behind it did.
    /// A `TlsError::Timeout` reaches a caller wrapped in an `io::Error` of another kind,
    /// so the kind alone does not answer it.
    #[must_use]
    pub fn is_timeout(error: &std::io::Error) -> bool {
        use std::io::ErrorKind::{TimedOut, WouldBlock};
        // A timed-out overlapped socket read surfaces as `ERROR_IO_PENDING` on Windows, not as `TimedOut`; a relay that read it as an end drops a live flow.
        let pending = cfg!(windows) && error.raw_os_error() == Some(997);
        matches!(error.kind(), TimedOut | WouldBlock)
            || pending
            || error
                .get_ref()
                .and_then(|source| source.downcast_ref::<TlsError>())
                .is_some_and(|mapped| matches!(mapped, TlsError::Timeout))
    }
}

#[test]
fn a_pending_overlapped_read_is_an_idle_wait_on_windows() {
    let pending = std::io::Error::from_raw_os_error(997);
    assert_eq!(TlsError::is_timeout(&pending), cfg!(windows));
}

/// Fills `buf` from `stream`: a `dyn Read` may answer short, and a poll quantum the
/// socket reports as a timeout is not an answer, so the loop asks again.
pub fn read_exact(stream: &mut dyn std::io::Read, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => buf = &mut buf[n..],
            Err(error) if TlsError::is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl From<TlsError> for std::io::Error {
    fn from(e: TlsError) -> Self {
        std::io::Error::other(e)
    }
}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::Timeout,
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => Self::Closed,
            _ => Self::Other(e.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    pub cert_chain: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub key_kind: ServerKeyKind,
    /// The protocols to offer, in preference order. Empty means no ALPN, which
    /// is what a server that only ever carries one protocol leaves it at.
    pub alpn: Vec<Vec<u8>>,
    /// Whether to send TLS 1.3 session tickets. REALITY declines them, as both
    /// references do, so an authenticated handshake is followed by no records.
    pub send_tickets: bool,
    /// Memoised server-config builds, one per identity kind.
    pub server_config_cache: crate::tls::rustls_backend::ServerConfigCache,
    /// ECH server keys as the xray TLV: `u16 key || u16 config`, repeated.
    pub ech_server_keys: Option<std::sync::Arc<[u8]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKeyKind {
    Pkcs8,
    Sec1,
    Pkcs1,
}

impl TlsServerConfig {
    /// The `rustls` server config for a plain TLS identity, built once per config.
    pub fn server_config(&self) -> Result<std::sync::Arc<rustls::ServerConfig>, TlsError> {
        crate::tls::rustls_backend::cached_server_config(self, false)
    }

    /// The `rustls` server config for a REALITY identity, built once per config.
    pub fn reality_server_config(&self) -> Result<std::sync::Arc<rustls::ServerConfig>, TlsError> {
        crate::tls::rustls_backend::cached_server_config(self, true)
    }

    /// The `BoringSSL` context an ECH listener answers with, unbuilt so a QUIC lane can hand it
    /// to quiche: both carry the same certificate, key and ECH key set.
    pub fn ech_server_context_builder(&self) -> Result<boring::ssl::SslContextBuilder, TlsError> {
        let keys = self
            .ech_server_keys
            .as_deref()
            .ok_or_else(|| TlsError::Other("ech server identity has no keys".to_owned()))?;
        crate::tls::rustls_backend::ech_server_context_builder(self, keys)
    }
}

pub fn parse_pem_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsServerConfig, TlsError> {
    let cert_chain = pem_blocks(cert_pem, "CERTIFICATE");
    if cert_chain.is_empty() {
        return Err(TlsError::Other(
            "tls certificate file holds no CERTIFICATE block".to_owned(),
        ));
    }
    // The label a key block carries is the writer's, not the key's: xray writes every minted key under `RSA PRIVATE KEY` whichever algorithm fed it, so the DER itself names the kind the parser takes.
    for label in ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"] {
        if let Some(key_der) = pem_blocks(key_pem, label).into_iter().next() {
            return Ok(TlsServerConfig {
                alpn: Vec::new(),
                cert_chain,
                key_kind: key_kind(&key_der).unwrap_or(ServerKeyKind::Pkcs1),
                key_der,
                send_tickets: true,
                server_config_cache: std::sync::Arc::default(),
                ech_server_keys: None,
            });
        }
    }
    Err(TlsError::Other(
        "tls key file holds no recognized private-key block".to_owned(),
    ))
}

/// The DER shape a key names: PKCS#8 is version `0` before an algorithm `SEQUENCE`, PKCS#1 is an
/// `INTEGER` modulus there, SEC 1 an `OCTET STRING` — the shapes these bytes carry whatever label
/// the writer chose.
fn key_kind(der: &[u8]) -> Option<ServerKeyKind> {
    /// One DER element past `at`, as its tag and the offset where it ends.
    fn element(der: &[u8], at: usize) -> Option<(u8, usize)> {
        let body = at + 2;
        let header = usize::from(*der.get(at + 1)?);
        let end = match header.checked_sub(0x80) {
            Some(count) if (1..8).contains(&count) => {
                let mut length = 0usize;
                for &byte in der.get(body..body + count)? {
                    length = length.checked_mul(256)?.checked_add(usize::from(byte))?;
                }
                body.checked_add(count)?.checked_add(length)?
            }
            _ => body.checked_add(header)?,
        };
        (end <= der.len()).then_some((*der.get(at)?, end))
    }
    if element(der, 0)?.0 != 0x30 {
        // A shape the probes do not name is rustls's to refuse, and the plain PKCS#1 slot is where that refusal reads.
        return Some(ServerKeyKind::Pkcs1);
    }
    Some(match element(der, element(der, 2)?.1)?.0 {
        0x04 => ServerKeyKind::Sec1,
        0x30 => ServerKeyKind::Pkcs8,
        _ => ServerKeyKind::Pkcs1,
    })
}

fn pem_blocks(pem: &[u8], label: &str) -> Vec<Vec<u8>> {
    let open = format!("-----BEGIN {label}-----");
    let shut = format!("-----END {label}-----");
    let Ok(text) = std::str::from_utf8(pem) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = text;
    while let Some((_, after)) = rest.split_once(open.as_str()) {
        let Some((body, tail)) = after.split_once(shut.as_str()) else {
            break;
        };
        let Some(der) = b64::decode(body.as_bytes()) else {
            rest = tail;
            continue;
        };
        out.push(der);
        rest = tail;
    }
    out
}

pub mod cipher_suites;
mod ech;
mod hpke;

/// The ECH config list a client config names, decoded from base64 or a PEM `ECH CONFIGS` block.
pub fn decode_ech_config(text: &str) -> Result<Vec<u8>, String> {
    ech::decode_source(text, "ECH CONFIGS")
}

/// A single ECH config wrapped as the one-entry list every client expects.
pub fn normalize_ech_config_list(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    ech::normalize_config_list(bytes)
}

/// The ECH server keys a listener config names, decoded from base64 or a PEM `ECH KEYS` block.
pub fn decode_ech_keys(text: &str) -> Result<Vec<u8>, String> {
    let bytes = ech::decode_source(text, "ECH KEYS")?;
    ech::parse_server_keys(&bytes)?;
    Ok(bytes)
}

mod rustls_backend;
pub use rustls_backend::{RustlsProvider, RustlsServerProvider};

pub mod shaped;
pub use shaped::Fingerprint;

/// The client session a config names: a shaped hello under its own record layer when
/// a fingerprint shapes it, the stock rustls connection otherwise.
pub enum ClientSession<S: Stream> {
    Stock(Box<RustlsProvider<S>>),
    Shaped(Box<shaped::Session<S>>),
}

impl<S: Stream> std::fmt::Debug for ClientSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stock(session) => std::fmt::Debug::fmt(session, f),
            Self::Shaped(session) => std::fmt::Debug::fmt(session, f),
        }
    }
}

impl<S: Stream> ClientSession<S> {
    pub fn get_ref(&self) -> &S {
        match self {
            Self::Stock(session) => session.get_ref(),
            Self::Shaped(session) => session.get_ref(),
        }
    }
}

impl<S: Stream> TlsProvider for ClientSession<S> {
    fn name() -> &'static str
    where
        Self: Sized,
    {
        "client"
    }

    fn suites(&self) -> Vec<String> {
        match self {
            Self::Stock(session) => session.suites(),
            Self::Shaped(session) => session.suites(),
        }
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        match self {
            Self::Stock(session) => session.handshake(),
            Self::Shaped(session) => session.handshake(),
        }
    }

    fn alpn(&self) -> Option<&[u8]> {
        match self {
            Self::Stock(session) => session.alpn(),
            Self::Shaped(session) => session.alpn(),
        }
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        match self {
            Self::Stock(session) => session.peer_leaf(),
            Self::Shaped(session) => session.peer_leaf(),
        }
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        match self {
            Self::Stock(session) => session.open(ciphertext, buf),
            Self::Shaped(session) => session.open(ciphertext, buf),
        }
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        match self {
            Self::Stock(session) => session.seal_into(plaintext, out),
            Self::Shaped(session) => session.seal_into(plaintext, out),
        }
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            Self::Stock(session) => session.seal_slices_into(parts, out),
            Self::Shaped(session) => session.seal_slices_into(parts, out),
        }
    }
}

impl<S: Stream + RecordAlignment> RecordAlignment for ClientSession<S> {
    fn engage_record_alignment(&mut self) {
        match self {
            Self::Stock(session) => session.engage_record_alignment(),
            Self::Shaped(session) => session.engage_record_alignment(),
        }
    }

    fn disarm_record_alignment(&mut self) {
        match self {
            Self::Stock(session) => session.disarm_record_alignment(),
            Self::Shaped(session) => session.disarm_record_alignment(),
        }
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        match self {
            Self::Stock(session) => session.write_all_slices(parts),
            Self::Shaped(session) => session.write_all_slices(parts),
        }
    }
}

impl<S: Stream> std::io::Read for ClientSession<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Stock(session) => session.read(buf),
            Self::Shaped(session) => session.read(buf),
        }
    }
}

impl<S: Stream> std::io::Write for ClientSession<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stock(session) => session.write(buf),
            Self::Shaped(session) => session.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stock(session) => session.flush(),
            Self::Shaped(session) => session.flush(),
        }
    }
}

pub mod reality;
pub use reality::{
    Edges, Proxied, RateLimit, RealityAccept, RealityClientConfig, RealityClientSession,
    RealityServer, RealityServerConfig,
};

pub fn connect<S: Stream + RecordAlignment>(
    cfg: &TlsConfig,
    io: S,
) -> Result<ClientSession<S>, TlsError> {
    match shaped::profile_of(cfg) {
        Some(_) => Ok(ClientSession::Shaped(Box::new(shaped::Session::connect(
            cfg, io,
        )?))),
        None => Ok(ClientSession::Stock(Box::new(RustlsProvider::connect(
            cfg, io,
        )?))),
    }
}

pub fn accept<S: Stream + Send>(
    cfg: &TlsServerConfig,
    io: S,
) -> Result<RustlsServerProvider<reality::RecordLimiter<S>>, TlsError> {
    RustlsServerProvider::accept(cfg.clone(), reality::RecordLimiter::new_open(io))
}

pub fn active_backends() -> &'static [&'static str] {
    &["rustls", "boring"]
}
