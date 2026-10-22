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
    /// it to the key exchange. Only a masquerade cover's `masq_url_insecure` origin names
    /// it; the proxied lane refuses `allowInsecure` outright, so this never trusts an edge
    /// the tunnel relays through. `false` is the default because verifying is the ordinary
    /// case, and an unchecked chain is a deliberate, bounded exception rather than a mode.
    pub insecure: bool,
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
    Other(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("handshake timed out"),
            Self::BadCertificate(why) => write!(f, "certificate did not verify: {why}"),
            Self::Closed => f.write_str("connection closed by peer"),
            Self::NoSharedCipher => f.write_str("no shared cipher suite"),
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
        matches!(error.kind(), TimedOut | WouldBlock)
            || error
                .get_ref()
                .and_then(|source| source.downcast_ref::<TlsError>())
                .is_some_and(|mapped| matches!(mapped, TlsError::Timeout))
    }
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKeyKind {
    Pkcs8,
    Sec1,
    Pkcs1,
}

pub fn parse_pem_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsServerConfig, TlsError> {
    let cert_chain = pem_blocks(cert_pem, "CERTIFICATE");
    if cert_chain.is_empty() {
        return Err(TlsError::Other(
            "tls certificate file holds no CERTIFICATE block".to_owned(),
        ));
    }
    let kinds = [
        ("PRIVATE KEY", ServerKeyKind::Pkcs8),
        ("EC PRIVATE KEY", ServerKeyKind::Sec1),
        ("RSA PRIVATE KEY", ServerKeyKind::Pkcs1),
    ];
    for (label, key_kind) in kinds {
        if let Some(key_der) = pem_blocks(key_pem, label).into_iter().next() {
            return Ok(TlsServerConfig {
                alpn: Vec::new(),
                cert_chain,
                key_der,
                key_kind,
                send_tickets: true,
            });
        }
    }
    Err(TlsError::Other(
        "tls key file holds no recognized private-key block".to_owned(),
    ))
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
mod rustls_backend;
pub use rustls_backend::{RustlsProvider, RustlsServerProvider};

pub mod reality;
pub use reality::{
    Edges, Proxied, RateLimit, RealityAccept, RealityClientConfig, RealityClientSession,
    RealityServer, RealityServerConfig,
};

pub fn connect<S: Stream + RecordAlignment>(
    cfg: &TlsConfig,
    io: S,
) -> Result<impl TlsProvider + RecordAlignment + use<S>, TlsError> {
    RustlsProvider::connect(cfg, io)
}

pub fn accept<S: Stream + Send>(
    cfg: &TlsServerConfig,
    io: S,
) -> Result<impl TlsProvider + RecordAlignment + Send + use<S>, TlsError> {
    RustlsServerProvider::accept(cfg.clone(), reality::RecordLimiter::new_open(io))
}

pub fn active_backends() -> &'static [&'static str] {
    &["rustls"]
}
