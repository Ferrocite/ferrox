use super::{Stream, TlsConfig, TlsError, TlsProvider};
use std::io::{Read, Write};
use std::sync::Arc;

type RootStore = rustls::RootCertStore;

/// The ring provider every identity shares: building it spends two vectors.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: std::sync::OnceLock<Arc<rustls::crypto::CryptoProvider>> =
        std::sync::OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

pub struct RustlsProvider<S: Stream> {
    conn: rustls::ClientConnection,
    io: S,
}

impl<S: Stream> std::fmt::Debug for RustlsProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsProvider")
            .field("alpn", &self.conn.alpn_protocol())
            .field("is_handshaking", &self.conn.is_handshaking())
            .finish_non_exhaustive()
    }
}

/// The stock chain verifier with a leaf-pin check bolted on the end, so pinning
/// narrows what already verified rather than replacing it. `Debug` is derived
/// because the crate denies its absence.
#[derive(Debug)]
struct Pinned {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pins: crate::foxy::pin::Pins,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if self.pins.holds(end_entity) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

impl<S: Stream> RustlsProvider<S> {
    fn config(cfg: &TlsConfig) -> Result<Arc<rustls::ClientConfig>, TlsError> {
        let mut roots = RootStore::empty();
        for der in &cfg.roots {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.as_slice()))
                .map_err(|e| TlsError::BadCertificate.with_detail(format!("trust anchor: {e}")))?;
        }
        let roots = Arc::new(roots);

        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        config.alpn_protocols.clone_from(&cfg.alpn);
        if !cfg.pins.is_empty() {
            let verifier =
                rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider())
                    .build()
                    .map_err(|e| TlsError::BadCertificate.with_detail(format!("chain: {e}")))?;
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(Pinned {
                    inner: verifier,
                    pins: cfg.pins.clone(),
                }));
        }
        Ok(Arc::new(config))
    }

    pub fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| TlsError::Other(format!("rustls server name: {e}")))?;
        let conn =
            rustls::ClientConnection::new(Self::config(cfg)?, name).map_err(|e| map_error(&e))?;
        Ok(Self { conn, io })
    }

    /// A connection whose hello was fixed before the handshake: REALITY seals
    /// its tag into the session id, so the stock random hello cannot go out.
    pub fn from_connection(conn: rustls::ClientConnection, io: S) -> Self {
        Self { conn, io }
    }

    fn drive(&mut self) -> Result<(), TlsError> {
        while self.conn.is_handshaking() {
            if let Err(e) = self.conn.complete_io(&mut self.io) {
                return Err(recover(e));
            }
        }
        Ok(())
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// Writes two slices as one TLS record: the fragmenter sees `head` and `tail`
    /// in that order in one call, which is the record a concatenated write would
    /// have produced, so the payload's staging copy is spent rather than the
    /// record being split in two.
    pub fn write_parts(&mut self, head: &[u8], mut tail: &[u8]) -> std::io::Result<()> {
        self.drive()?;
        let mut head = head;
        let want = head.len() + tail.len();
        let mut written = 0usize;
        while written < want {
            let slices = [std::io::IoSlice::new(head), std::io::IoSlice::new(tail)];
            let wrote = std::io::Write::write_vectored(&mut self.conn.writer(), &slices)?;
            if wrote == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }
            written += wrote;
            let spent = wrote.min(head.len());
            head = &head[spent..];
            tail = &tail[wrote - spent..];
        }
        // The record goes out here, and an idle read is not a failed write: a socket with a read timeout set answers EAGAIN when nothing arrived, which is the same answer "nothing arrived" is.
        match self.conn.complete_io(&mut self.io) {
            Err(error) if !idle(&error) => return Err(recover(error).into()),
            _ => {}
        }
        Ok(())
    }
}

impl<S: Stream + super::RecordAlignment> super::RecordAlignment for RustlsProvider<S> {
    fn engage_record_alignment(&mut self) {
        self.io.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.io.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.drive()?;
        let mut writer = self.conn.writer();
        coalesce(&mut writer, parts)?;
        match self.conn.complete_io(&mut self.io) {
            Err(error) if !idle(&error) => return Err(recover(error).into()),
            _ => {}
        }
        Ok(())
    }
}

impl<S: Stream> TlsProvider for RustlsProvider<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        rustls::crypto::ring::ALL_CIPHER_SUITES
            .iter()
            .map(|cs| format!("{:?}", cs.suite()))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.drive()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        self.conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(rustls::pki_types::CertificateDer::as_ref)
    }
}

impl<S: Stream> Read for RustlsProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.drive()?;
            match self.conn.reader().read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Err(io_error) = self.conn.complete_io(&mut self.io) {
                        if matches!(
                            io_error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) {
                            return Err(io_error);
                        }
                        return Err(recover(io_error).into());
                    }
                }
                outcome => return outcome,
            }
        }
    }
}

impl<S: Stream> Write for RustlsProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.drive()?;
        let len = self.conn.writer().write(buf)?;
        let _ = self.conn.complete_io(&mut self.io);
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drive()?;
        self.conn.writer().flush()?;
        // complete_io reads as well as it writes, and an idle read is not a failed flush: the record this pushed went out either way.
        match self.conn.complete_io(&mut self.io) {
            Err(error) if !idle(&error) => return Err(recover(error).into()),
            _ => {}
        }
        Ok(())
    }
}

pub struct RustlsServerProvider<S: Stream> {
    conn: rustls::ServerConnection,
    io: S,
}

impl<S: Stream> std::fmt::Debug for RustlsServerProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsServerProvider")
            .field("alpn", &self.conn.alpn_protocol())
            .field("is_handshaking", &self.conn.is_handshaking())
            .finish_non_exhaustive()
    }
}

impl<S: Stream> RustlsServerProvider<S> {
    pub fn accept(cfg: super::TlsServerConfig, io: S) -> Result<Self, TlsError> {
        let conn = rustls::ServerConnection::new(std::sync::Arc::new(server_config(cfg)?))
            .map_err(|e| map_error(&e))?;
        Ok(Self { conn, io })
    }

    pub fn accept_reality(cfg: super::TlsServerConfig, io: S) -> Result<Self, TlsError> {
        let conn = rustls::ServerConnection::new(std::sync::Arc::new(reality_server_config(cfg)?))
            .map_err(|e| map_error(&e))?;
        Ok(Self { conn, io })
    }

    fn drive(&mut self) -> Result<(), TlsError> {
        while self.conn.is_handshaking() {
            if let Err(e) = self.conn.complete_io(&mut self.io) {
                return Err(recover(e));
            }
        }
        Ok(())
    }
}

impl<S: Stream + super::RecordAlignment> super::RecordAlignment for RustlsServerProvider<S> {
    fn engage_record_alignment(&mut self) {
        self.io.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.io.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.drive()?;
        let mut writer = self.conn.writer();
        coalesce(&mut writer, parts)?;
        match self.conn.complete_io(&mut self.io) {
            Err(error) if !idle(&error) => return Err(recover(error).into()),
            _ => {}
        }
        Ok(())
    }
}

/// Hand `parts` to a rustls writer in one `write_vectored` so the fragmenter sees one payload and emits one record; iterating `write_all` per part would emit one record per part.
fn coalesce<W: Write + ?Sized>(writer: &mut W, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut chunks: Vec<&[u8]> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
    while !chunks.is_empty() {
        let slices: Vec<std::io::IoSlice<'_>> =
            chunks.iter().copied().map(std::io::IoSlice::new).collect();
        let wrote = writer.write_vectored(&slices)?;
        if wrote == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        let mut left = wrote;
        for chunk in &mut chunks {
            if left == 0 {
                break;
            }
            if chunk.len() <= left {
                left -= chunk.len();
                *chunk = &[];
            } else {
                *chunk = &chunk[left..];
                left = 0;
            }
        }
        chunks.retain(|c| !c.is_empty());
    }
    Ok(())
}

/// The rustls config an identity produces, so tests pin wire behavior here.
pub(crate) fn server_config(cfg: super::TlsServerConfig) -> Result<rustls::ServerConfig, TlsError> {
    use super::ServerKeyKind as Kind;
    let certs: Vec<rustls::pki_types::CertificateDer<'_>> = cfg
        .cert_chain
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key = match cfg.key_kind {
        Kind::Pkcs8 => rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cfg.key_der),
        ),
        Kind::Sec1 => rustls::pki_types::PrivateKeyDer::Sec1(
            rustls::pki_types::PrivateSec1KeyDer::from(cfg.key_der),
        ),
        Kind::Pkcs1 => rustls::pki_types::PrivateKeyDer::Pkcs1(
            rustls::pki_types::PrivatePkcs1KeyDer::from(cfg.key_der),
        ),
    };
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?;
    config.alpn_protocols.clone_from(&cfg.alpn);
    // rustls sends two tickets by default; REALITY arrivals carry none.
    config.send_tls13_tickets = if cfg.send_tickets { 2 } else { 0 };
    Ok(config)
}

/// The signing key REALITY answers with: every reference forces `Ed25519` for
/// `CertificateVerify` without consulting the peer's offered schemes.
#[derive(Debug)]
pub(crate) struct RealitySigningKey {
    pub(crate) inner: Arc<dyn rustls::sign::SigningKey>,
}

impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.inner
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

/// The rustls config a REALITY identity produces: the same chain, key, `ALPN`
/// and ticket count as `server_config`, except the key always answers `Ed25519`.
pub(crate) fn reality_server_config(
    cfg: super::TlsServerConfig,
) -> Result<rustls::ServerConfig, TlsError> {
    use super::ServerKeyKind as Kind;
    let certs: Vec<rustls::pki_types::CertificateDer<'_>> = cfg
        .cert_chain
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key_der = match cfg.key_kind {
        Kind::Pkcs8 => rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cfg.key_der),
        ),
        Kind::Sec1 => rustls::pki_types::PrivateKeyDer::Sec1(
            rustls::pki_types::PrivateSec1KeyDer::from(cfg.key_der),
        ),
        Kind::Pkcs1 => rustls::pki_types::PrivateKeyDer::Pkcs1(
            rustls::pki_types::PrivatePkcs1KeyDer::from(cfg.key_der),
        ),
    };
    let inner = provider()
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?;
    let key = rustls::sign::CertifiedKey::new(certs, Arc::new(RealitySigningKey { inner }));
    key.keys_match()
        .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    config.alpn_protocols.clone_from(&cfg.alpn);
    // rustls sends two tickets by default; REALITY arrivals carry none.
    config.send_tls13_tickets = if cfg.send_tickets { 2 } else { 0 };
    Ok(config)
}

impl<S: Stream> TlsProvider for RustlsServerProvider<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        rustls::crypto::ring::ALL_CIPHER_SUITES
            .iter()
            .map(|cs| format!("{:?}", cs.suite()))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.drive()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }
}

impl<S: Stream> Read for RustlsServerProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.drive()?;
            match self.conn.reader().read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Err(io_error) = self.conn.complete_io(&mut self.io) {
                        if matches!(
                            io_error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) {
                            return Err(io_error);
                        }
                        return Err(recover(io_error).into());
                    }
                }
                outcome => return outcome,
            }
        }
    }
}

impl<S: Stream> Write for RustlsServerProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.drive()?;
        let len = self.conn.writer().write(buf)?;
        let _ = self.conn.complete_io(&mut self.io);
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drive()?;
        self.conn.writer().flush()?;
        // complete_io reads as well as it writes, and an idle read is not a failed flush: the record this pushed went out either way.
        match self.conn.complete_io(&mut self.io) {
            Err(error) if !idle(&error) => return Err(recover(error).into()),
            _ => {}
        }
        Ok(())
    }
}

/// Whether an error is the socket's poll grain expiring with nothing in it,
/// which `complete_io` reports because it reads as well as it writes.
fn idle(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    matches!(error.kind(), TimedOut | WouldBlock)
        || matches!(
            error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<TlsError>()),
            Some(TlsError::Timeout)
        )
}

fn recover(e: std::io::Error) -> TlsError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        if let Some(inner) = e.get_ref().and_then(|s| s.downcast_ref::<rustls::Error>()) {
            return map_error(inner);
        }
    }
    TlsError::from(e)
}

fn map_error(e: &rustls::Error) -> TlsError {
    use rustls::Error as E;
    match e {
        // An untrusted chain, a name that does not match and an expired certificate are three different problems and the caller can act on each; one variant with no detail is none of them.
        E::InvalidCertificate(why) => TlsError::BadCertificate.with_detail(format!("{why:?}")),
        E::InvalidCertRevocationList(why) => {
            TlsError::BadCertificate.with_detail(format!("{why:?}"))
        }
        E::NoCertificatesPresented => TlsError::BadCertificate.with_detail("no certificate"),
        E::UnsupportedNameType => TlsError::BadCertificate.with_detail("unsupported name type"),

        E::NoApplicationProtocol
        | E::AlertReceived(rustls::AlertDescription::NoApplicationProtocol)
        | E::PeerIncompatible(_)
        | E::PeerMisbehaved(_)
        | E::BadMaxFragmentSize => TlsError::NoSharedCipher,

        E::DecryptError
        | E::EncryptError
        | E::InvalidMessage(_)
        | E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. }
        | E::HandshakeNotComplete
        | E::PeerSentOversizedRecord
        | E::AlertReceived(rustls::AlertDescription::CloseNotify) => TlsError::Closed,

        E::AlertReceived(other) => TlsError::Other(format!("rustls alert: {other:?}")),

        E::FailedToGetCurrentTime
        | E::FailedToGetRandomBytes
        | E::InvalidEncryptedClientHello(_)
        | E::InconsistentKeys(_)
        | E::General(_)
        | E::Other(_) => TlsError::Other(format!("rustls: {e:?}")),

        _ => TlsError::Other(format!("rustls: unmapped error {e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    const ANCHOR: &[u8] = &[
        0x30, 0x82, 0x01, 0x6c, 0x30, 0x82, 0x01, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14,
        0x6d, 0x8e, 0xc2, 0xf5, 0x42, 0x91, 0xda, 0xdb, 0x05, 0xc9, 0xb2, 0x00, 0x71, 0x8b, 0xfb,
        0x6a, 0x20, 0xf4, 0xa1, 0xf8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
        0x74, 0x6c, 0x73, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31,
        0x30, 0x30, 0x33, 0x31, 0x32, 0x34, 0x38, 0x30, 0x32, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36,
        0x36, 0x30, 0x39, 0x32, 0x33, 0x31, 0x32, 0x34, 0x38, 0x30, 0x32, 0x5a, 0x30, 0x13, 0x31,
        0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x74, 0x6c, 0x73, 0x2e, 0x74,
        0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        0xe7, 0xc8, 0xba, 0x65, 0x0f, 0xe6, 0x76, 0xe9, 0x05, 0x43, 0xd0, 0x8a, 0x63, 0xd4, 0xc4,
        0xee, 0x19, 0x31, 0xbb, 0x2d, 0x39, 0xce, 0xd1, 0xb1, 0x9a, 0xc7, 0x5a, 0xf1, 0x34, 0x98,
        0x5e, 0xe4, 0x87, 0x83, 0xfe, 0x38, 0x68, 0x71, 0xbc, 0xef, 0xfa, 0x47, 0x67, 0x10, 0x69,
        0x58, 0x0b, 0x2c, 0xc5, 0xa5, 0xc8, 0xcf, 0xba, 0x0a, 0x7a, 0x8e, 0x14, 0x7d, 0x97, 0x3e,
        0xef, 0x18, 0x38, 0x94, 0xa3, 0x41, 0x30, 0x3f, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x1d, 0x11,
        0x04, 0x17, 0x30, 0x15, 0x82, 0x08, 0x74, 0x6c, 0x73, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x82,
        0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1d, 0x06, 0x03, 0x55,
        0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x04, 0x37, 0x6a, 0x70, 0x40, 0x98, 0x48, 0xaf, 0x75,
        0xc5, 0xa8, 0x24, 0x77, 0xca, 0xe1, 0x2c, 0x0d, 0xf1, 0xee, 0x5a, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21,
        0x00, 0xae, 0x33, 0xd8, 0x61, 0xdc, 0x06, 0xf9, 0x8b, 0x76, 0x18, 0xe9, 0xe7, 0x5d, 0xe2,
        0x57, 0x8e, 0x84, 0x33, 0x43, 0x0a, 0x43, 0x7b, 0x7b, 0xb9, 0x05, 0xa3, 0xd8, 0x27, 0xfd,
        0xa4, 0x51, 0x2e, 0x02, 0x21, 0x00, 0xda, 0x81, 0x2e, 0x43, 0x7c, 0xf6, 0xe8, 0x0a, 0x09,
        0x47, 0xb4, 0x81, 0x81, 0xa2, 0x38, 0x17, 0x55, 0x0f, 0xeb, 0x95, 0x8b, 0x66, 0x78, 0x21,
        0x05, 0x95, 0xb1, 0xf2, 0xe1, 0x67, 0x0d, 0x3e,
    ];

    const ANCHOR_KEY: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x32, 0x0d, 0x8c, 0x13, 0x2e, 0x2a, 0x61, 0x40, 0xf4,
        0x9c, 0x2b, 0xa1, 0x5a, 0x13, 0x8c, 0x28, 0xef, 0xcc, 0x66, 0x47, 0xde, 0xdd, 0x5a, 0x6d,
        0x60, 0x5e, 0x01, 0x73, 0xda, 0x6a, 0x21, 0x0a, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xe7,
        0xc8, 0xba, 0x65, 0x0f, 0xe6, 0x76, 0xe9, 0x05, 0x43, 0xd0, 0x8a, 0x63, 0xd4, 0xc4, 0xee,
        0x19, 0x31, 0xbb, 0x2d, 0x39, 0xce, 0xd1, 0xb1, 0x9a, 0xc7, 0x5a, 0xf1, 0x34, 0x98, 0x5e,
        0xe4, 0x87, 0x83, 0xfe, 0x38, 0x68, 0x71, 0xbc, 0xef, 0xfa, 0x47, 0x67, 0x10, 0x69, 0x58,
        0x0b, 0x2c, 0xc5, 0xa5, 0xc8, 0xcf, 0xba, 0x0a, 0x7a, 0x8e, 0x14, 0x7d, 0x97, 0x3e, 0xef,
        0x18, 0x38, 0x94,
    ];

    fn client(name: &str, alpn: &[&[u8]]) -> TlsConfig {
        TlsConfig {
            server_name: name.to_owned(),
            alpn: alpn.iter().map(|p| p.to_vec()).collect(),
            roots: vec![ANCHOR.to_vec()],
            pins: crate::foxy::pin::Pins::default(),
        }
    }

    fn serve(listener: &TcpListener) {
        let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
        config.alpn_protocols = vec![b"test-only".to_vec()];
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        let mut buf = [0u8; 4];
        if tls.read_exact(&mut buf).is_err() {
            return;
        }
        let _ = tls.write_all(&buf);
    }

    fn case(dial: impl FnOnce(TcpStream)) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| serve(&listener));
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            dial(stream);
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn handshake_connects_and_echoes() {
        case(|stream| {
            let mut client = crate::tls::connect(&client("tls.test", &[b"test-only"]), stream)
                .expect("configures");
            client.handshake().expect("handshakes");
            assert_eq!(client.alpn(), Some(b"test-only".as_slice()));
            assert!(client.suites().len() > 1);
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn mismatched_certificate_name_fails() {
        case(|stream| {
            let mut client = crate::tls::connect(&client("wrong.test", &[b"test-only"]), stream)
                .expect("configures");
            let err = client.handshake().expect_err("wrong name must fail");
            // The detail names which of the certificate problems this is.
            assert!(err.to_string().contains("bad certificate"), "{err}");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn refused_alpn_fails() {
        case(|stream| {
            let mut client =
                crate::tls::connect(&client("tls.test", &[b"nope"]), stream).expect("configures");
            let err = client.handshake().expect_err("refused ALPN must fail");
            assert!(
                matches!(err, TlsError::NoSharedCipher),
                "refused ALPN mapped to {err:?}"
            );
        });
    }

    fn anchor_pem(label: &str, der: &[u8]) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut body = String::new();
        for chunk in der.chunks(3) {
            let mut word = 0u32;
            for &byte in chunk {
                word = (word << 8) | u32::from(byte);
            }
            word <<= 8 * (3 - chunk.len());
            for i in 0..=chunk.len() {
                body.push(TABLE[((word >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
            for _ in chunk.len() + 1..4 {
                body.push('=');
            }
        }
        let mut pem = format!("-----BEGIN {label}-----\n");
        for line in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END ");
        pem.push_str(label);
        pem.push_str("-----\n");
        pem.into_bytes()
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn server_accepts_through_the_interface_and_echoes() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert_eq!(server.alpn(), None);
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client =
                crate::tls::connect(&client("tls.test", &[]), stream).expect("configures");
            client.handshake().expect("handshakes");
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_idle_peer_refuses_the_handshake_instead_of_spinning_it() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                    .expect("times out");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                let _ = done_tx.send(server.handshake());
            });
            // Silent past the old spin, which never ended: the refusal arrives first.
            let idle = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let refused = done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the handshake refuses an idle peer");
            assert!(
                matches!(refused, Err(TlsError::Timeout)),
                "idleness refuses as {refused:?}"
            );
            drop(idle);
        });
    }

    #[test]
    fn pem_identity_rejects_blocks_it_does_not_know() {
        assert!(crate::tls::parse_pem_identity(b"nothing here", b"nothing here").is_err());
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        assert!(crate::tls::parse_pem_identity(&cert_pem, b"nothing here").is_err());
    }
}
