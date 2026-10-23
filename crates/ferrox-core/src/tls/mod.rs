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
    /// The browser hello to shape, or `None` to keep the stock rustls hello.
    pub fingerprint: Option<shaped::Fingerprint>,
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
    /// Memoised `rustls` server-config builds, one per identity kind.
    pub server_config_cache: crate::tls::rustls_backend::ServerConfigCache,
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
                server_config_cache: std::sync::Arc::default(),
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
    &["rustls"]
}
