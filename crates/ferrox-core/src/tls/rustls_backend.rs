use super::{Stream, TlsConfig, TlsError, TlsProvider};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};

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
/// narrows what already verified — and, when the store this device has cannot
/// build the chain of a key it does pin, stands in for that store with the leaf
/// as its own anchor. `Debug` is derived because the crate denies its absence.
#[derive(Debug)]
struct Pinned {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pins: crate::foxy::pin::Pins,
}

/// The leaf as the only trust anchor, so a pinned edge still gets the name and validity checks a chain this device cannot build would otherwise skip.
fn anchored(
    leaf: &rustls::pki_types::CertificateDer<'_>,
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, rustls::Error> {
    let mut roots = RootStore::empty();
    roots.add(leaf.clone())?;
    rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .map_err(|e| rustls::Error::General(format!("pinned anchor: {e}")))
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
        let pinned = self.pins.holds(end_entity);
        if let Err(error) = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            // The operator pinned this key, so the key is the authority a stale device store withholds; everything else about the certificate is still checked.
            if !pinned {
                return Err(error);
            }
            anchored(end_entity)?.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }
        if pinned {
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

/// The cover-site verifier a `masq_url_insecure` origin names: it trusts the peer chain
/// exactly as presented, which is what the reference's `allowInsecure` means — a
/// masquerade cover dials an arbitrary public site to look convincing and must not fail on
/// a store this edge cannot reach. It is the one bounded place a certificate is taken on
/// faith: the relayed lane refuses `allowInsecure` outright and so never reaches this type.
#[derive(Debug)]
struct Unverified;

impl rustls::client::danger::ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The expensive halves of a client config, shared by every dial that names the same trust anchors, pins, ALPN list and suite order: parsing an anchor and building a verifier are per-config work, not per-connection work.
struct Material {
    roots: Arc<RootStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Present only when the config pins: the `Pinned` wrapper around the chain verifier, holding the keys a verified chain must still carry.
    verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
}

/// The three config fields `build_material` reads. ALPN is not one of them because the anchors and the suite order do not depend on it, and the server name is not one either: it reaches the connection, not the config.
#[derive(Eq)]
struct MaterialKey {
    roots: crate::tls::Anchors,
    pins: crate::foxy::pin::Pins,
    cipher_suites: Vec<u16>,
}

/// Two anchor lists name the same trust when one allocation answers for both, which is what sharing them by reference makes the ordinary case; comparing their bytes is a walk of every certificate the platform trusts, and only a set read twice can reach it.
fn same_roots(ours: &crate::tls::Anchors, theirs: &crate::tls::Anchors) -> bool {
    Arc::ptr_eq(ours, theirs) || ours == theirs
}

impl PartialEq for MaterialKey {
    fn eq(&self, other: &Self) -> bool {
        same_roots(&self.roots, &other.roots)
            && self.pins == other.pins
            && self.cipher_suites == other.cipher_suites
    }
}

impl MaterialKey {
    fn of(cfg: &TlsConfig) -> Self {
        Self {
            roots: Arc::clone(&cfg.roots),
            pins: cfg.pins.clone(),
            cipher_suites: cfg.cipher_suites.clone(),
        }
    }
}

/// Every set of inputs this process has dialed with; a config comes from a config file, so the set is the number of remotes, and it is capped rather than trusted to stay small.
const MATERIALS_MAX: usize = 32;

/// A build, and the three inputs that select it.
type Materials = Vec<(MaterialKey, Arc<Material>)>;

static MATERIALS: OnceLock<Mutex<Materials>> = OnceLock::new();

/// Parses the anchors, orders the suites and builds the verifier a config named, once per set of inputs.
fn build_material(cfg: &TlsConfig) -> Result<Material, TlsError> {
    let mut roots = RootStore::empty();
    for der in cfg.roots.iter() {
        roots
            .add(rustls::pki_types::CertificateDer::from(der.as_slice()))
            .map_err(|e| TlsError::BadCertificate(format!("trust anchor: {e}")))?;
    }
    let roots = Arc::new(roots);

    let mut provider = (*provider()).clone();
    if !cfg.cipher_suites.is_empty() {
        // The ring backend's set is a subset of `crypto/tls`'s, so the sort only re-orders what is reachable.
        let order = &cfg.cipher_suites;
        provider.cipher_suites.sort_by_key(|cs| {
            let id = u16::from(cs.suite());
            order
                .iter()
                .position(|&want| want == id)
                .unwrap_or(usize::MAX)
        });
    }
    let provider = Arc::new(provider);

    let verifier = if cfg.pins.is_empty() {
        None
    } else {
        let chain = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::clone(&roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|e| TlsError::BadCertificate(format!("chain: {e}")))?;
        Some(Arc::new(Pinned {
            inner: chain,
            pins: cfg.pins.clone(),
        })
            as Arc<dyn rustls::client::danger::ServerCertVerifier>)
    };
    Ok(Material {
        roots,
        provider,
        verifier,
    })
}

/// What selects a cached client config: a material, the `ALPN` list the builder writes into it, and whether the verifier is the unverified one. The server name stays out — it reaches the connection, not the config.
#[derive(PartialEq, Eq)]
struct ConfigKey {
    material: MaterialKey,
    alpn: Vec<Vec<u8>>,
    insecure: bool,
}

type Configs = Vec<(ConfigKey, Arc<rustls::ClientConfig>)>;

static CONFIGS: OnceLock<Mutex<Configs>> = OnceLock::new();

/// The client config the cache above keeps one of: the material's provider and roots, the named `ALPN`, and the verifier the config forces.
fn build_config(cfg: &TlsConfig, built: &Material) -> Result<rustls::ClientConfig, TlsError> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&built.provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
        .with_root_certificates(Arc::clone(&built.roots))
        .with_no_client_auth();
    config.alpn_protocols.clone_from(&cfg.alpn);
    if cfg.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(Unverified));
    } else if let Some(verifier) = &built.verifier {
        config
            .dangerous()
            .set_certificate_verifier(Arc::clone(verifier));
    }
    Ok(config)
}

impl<S: Stream> RustlsProvider<S> {
    /// The parts a client config is built from, memoised per the anchors, pins and suite order a config names: the same three inputs get one build, whatever host or ALPN dials next. A pin-based verifier must keep its pointer across dials for rustls to resume, so a hit moves its entry to the back and the cap drops only the least-recently-used.
    fn material(cfg: &TlsConfig) -> Result<Arc<Material>, TlsError> {
        let key = MaterialKey::of(cfg);
        let all = MATERIALS.get_or_init(Default::default);
        let mut kept = all.lock().expect("one build at a time");
        let at = kept.iter().position(|(k, _)| *k == key);
        if let Some(at) = at {
            let entry = kept.remove(at);
            let hit = Arc::clone(&entry.1);
            kept.push(entry);
            return Ok(hit);
        }
        drop(kept);
        let built = Arc::new(build_material(cfg)?);
        let mut kept = all.lock().expect("one build at a time");
        if kept.len() == MATERIALS_MAX {
            kept.remove(0);
        }
        kept.push((key, Arc::clone(&built)));
        Ok(built)
    }

    /// One build per (material, alpn, `insecure`), kept for the life of the process: rustls resumes only under a pointer-equal certificate verifier, so a config rebuilt for each dial discards the ticket the last dial stored, and every flow after the first pays for a full handshake again. At the cap the least-recently-used entry goes, and a hit moves its entry to the back: clearing the whole cache would drop the stores holding every edge's ticket at once, which is the very loss this cache exists to prevent.
    fn config(cfg: &TlsConfig) -> Result<Arc<rustls::ClientConfig>, TlsError> {
        let key = ConfigKey {
            material: MaterialKey::of(cfg),
            alpn: cfg.alpn.clone(),
            insecure: cfg.insecure,
        };
        let all = CONFIGS.get_or_init(Default::default);
        let mut kept = all.lock().expect("one build at a time");
        let at = kept.iter().position(|(k, _)| *k == key);
        if let Some(at) = at {
            let entry = kept.remove(at);
            let hit = Arc::clone(&entry.1);
            kept.push(entry);
            return Ok(hit);
        }
        drop(kept);
        let material = Self::material(cfg)?;
        let built = Arc::new(build_config(cfg, &material)?);
        let mut kept = all.lock().expect("one build at a time");
        if kept.len() == MATERIALS_MAX {
            kept.remove(0);
        }
        kept.push((key, Arc::clone(&built)));
        Ok(built)
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

    #[cfg(test)]
    fn tls13_tickets(&self) -> u32 {
        self.conn.tls13_tickets_received()
    }

    /// Whether this session did a full handshake or rode a ticket: the only public witness of resumption, because rustls hands a resumed session its cached chain.
    #[cfg(test)]
    fn handshake_kind(&self) -> Option<rustls::HandshakeKind> {
        self.conn.handshake_kind()
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
///
/// The framer hands at most `uuid | head | payload | padding` — four segments — so they
/// are laid out on the stack like [`RustlsProvider::write_parts`] does its two, rather
/// than spending one heap `Vec<IoSlice>` on every framed write.
fn coalesce<W: Write + ?Sized>(writer: &mut W, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut stack = [
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
    ];
    if parts.len() <= stack.len() {
        let mut kept = 0;
        for part in parts.iter().copied().filter(|part| !part.is_empty()) {
            stack[kept] = std::io::IoSlice::new(part);
            kept += 1;
        }
        return write_segments(writer, &mut stack[..kept]);
    }
    // A provider handed more segments than the framer produces still goes out in one call.
    let mut heap: Vec<std::io::IoSlice<'_>> = parts
        .iter()
        .copied()
        .filter(|part| !part.is_empty())
        .map(std::io::IoSlice::new)
        .collect();
    write_segments(writer, heap.as_mut_slice())
}

/// Push the segments out in as few `write_vectored` calls as the writer will take,
/// advancing past each one the writer consumes whole.
fn write_segments<W: Write + ?Sized>(
    writer: &mut W,
    mut rest: &mut [std::io::IoSlice<'_>],
) -> std::io::Result<()> {
    while !rest.is_empty() {
        let wrote = writer.write_vectored(rest)?;
        if wrote == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        std::io::IoSlice::advance_slices(&mut rest, wrote);
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
        // An untrusted chain, a name that does not match and an expired certificate are three different problems and the caller can act on each; the why rides with the kind, so matching the kind does not cost the why.
        E::InvalidCertificate(why) => TlsError::BadCertificate(format!("{why:?}")),
        E::InvalidCertRevocationList(why) => TlsError::BadCertificate(format!("{why:?}")),
        E::NoCertificatesPresented => TlsError::BadCertificate("no certificate".to_owned()),
        E::UnsupportedNameType => TlsError::BadCertificate("unsupported name type".to_owned()),
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
            roots: vec![ANCHOR.to_vec()].into(),
            pins: crate::foxy::pin::Pins::default(),
            cipher_suites: Vec::new(),
            insecure: false,
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

    /// Two dialled sessions to the same server, each answered by its own `serve`: a lane that resumed across them would show it in what the second one was handed.
    fn twice(mut dial: impl FnMut(TcpStream, TcpStream)) {
        let first = TcpListener::bind("127.0.0.1:0").expect("binds");
        let second = TcpListener::bind("127.0.0.1:0").expect("binds");
        let (first_port, second_port) = (
            first.local_addr().expect("addr").port(),
            second.local_addr().expect("addr").port(),
        );
        thread::scope(|scope| {
            scope.spawn(|| serve(&first));
            scope.spawn(|| serve(&second));
            let a = TcpStream::connect(("127.0.0.1", first_port)).expect("connects");
            let b = TcpStream::connect(("127.0.0.1", second_port)).expect("connects");
            dial(a, b);
        });
    }

    /// The `cipher_suites` field of a captured `ClientHello` record: skip the 5-byte record and
    /// 4-byte handshake headers, the legacy version and random, then the session id, and read
    /// the length-prefixed suite list — the same span the Go oracle dumps.
    fn hello_cipher_suites(record: &[u8]) -> &[u8] {
        assert_eq!(record[0], 0x16, "handshake record");
        assert_eq!(record[5], 0x01, "ClientHello");
        let body = &record[9..];
        let sid_len = usize::from(body[2 + 32]);
        let at = 2 + 32 + 1 + sid_len;
        let cs_len = usize::from(body[at]) << 8 | usize::from(body[at + 1]);
        &body[at..at + 2 + cs_len]
    }

    #[cfg_attr(miri, ignore = "assembles a real hello through ring")]
    #[test]
    fn a_crafted_list_reorders_the_dialer_hello_to_the_reference() {
        // The reference TLS 1.3 field is `0x1301,0x1302,0x1303`; ring's stock provider offers `0x1302,0x1301,0x1303`.
        let preset =
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        let crafted = crate::tls::cipher_suites::hello_ids(
            &crate::tls::cipher_suites::parse(preset),
            0x0304,
            0x0304,
            true,
        );
        let mut cfg = client("tls.test", &[]);
        cfg.cipher_suites = crafted;
        let config = RustlsProvider::<TcpStream>::config(&cfg).expect("builds");
        let mut conn = rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from("tls.test").expect("name"),
        )
        .expect("session");
        let mut record = Vec::new();
        conn.write_tls(&mut record).expect("hello goes out");
        let got = hello_cipher_suites(&record);
        let want = crate::tls::cipher_suites::field_bytes(&[0x1301, 0x1302, 0x1303]);
        assert_eq!(
            got,
            want.as_slice(),
            "dialer hello matches the crypto/tls field"
        );
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

    /// Parsing an anchor and building a verifier is work a config names, not a connection needs: two dials naming the same anchors, pins and suite order share one build, and any input that differs gets its own.
    #[test]
    fn the_parts_a_config_is_built_from_are_built_once() {
        let built = RustlsProvider::<TcpStream>::material(&client("one.test", &[b"test-only"]))
            .expect("builds");
        let other_name =
            RustlsProvider::<TcpStream>::material(&client("two.test", &[b"nope"])).expect("builds");
        assert!(
            Arc::ptr_eq(&built, &other_name),
            "a new host or ALPN asks for no new anchors"
        );

        let mut pinned = client("one.test", &[b"test-only"]);
        pinned.pins = crate::foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        ]);
        let with_pin = RustlsProvider::<TcpStream>::material(&pinned).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &with_pin),
            "a pinned verifier is not an unpinned one"
        );

        let mut reordered = client("one.test", &[b"test-only"]);
        reordered.cipher_suites = vec![0x1302];
        let other_order = RustlsProvider::<TcpStream>::material(&reordered).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &other_order),
            "a named suite order is a different provider"
        );

        let mut no_anchor = client("one.test", &[b"test-only"]);
        no_anchor.roots = Vec::new().into();
        let empty = RustlsProvider::<TcpStream>::material(&no_anchor).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &empty),
            "a dial that names no anchor stores a different store"
        );
    }

    /// The shared parts do not invent a shared server: a ticket one listener left is unknown to the other, so the second dial here is handed a chain again — two listeners, not one edge, is what this shape keeps true.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_second_dial_with_the_same_config_still_fetches_the_chain() {
        let cfg = client("tls.test", &[b"test-only"]);
        twice(|first, second| {
            let mut echo = [0u8; 4];
            let mut a = crate::tls::connect(&cfg, first).expect("first configures");
            a.handshake().expect("handshakes");
            a.write_all(b"ping").expect("writes");
            a.flush().expect("flushes");
            a.read_exact(&mut echo).expect("echoes");
            let mut b = crate::tls::connect(&cfg, second).expect("second configures");
            b.handshake().expect("handshakes");
            b.write_all(b"ping").expect("writes");
            b.flush().expect("flushes");
            b.read_exact(&mut echo).expect("echoes");
            assert!(
                a.peer_leaf().is_some() && b.peer_leaf().is_some(),
                "both dials were handed a chain, so neither rode the other's session"
            );
        });
    }

    /// The test edge: a chain both dials trust, and a ticket maker that keeps nothing between them.
    fn edge_config() -> rustls::ServerConfig {
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
        // A builder's config tickets statefully through one shared store, and `take` spends a stored session at first use, so the second dial's offer would already be consumed: a stateless ticketer carries the secret inside the ticket itself.
        config.ticketer = rustls::crypto::ring::Ticketer::new().expect("edge ticketer");
        config
    }

    /// One dial to the edge on a config the caller holds: both dials of the resumption witness must ride one `Arc`, which is what rustls compares for its verifier and its store.
    fn dial(
        config: &Arc<rustls::ClientConfig>,
        name: &rustls::pki_types::ServerName<'static>,
        port: u16,
    ) -> RustlsProvider<TcpStream> {
        let io = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut tls = RustlsProvider::<TcpStream>::from_connection(
            rustls::ClientConnection::new(Arc::clone(config), name.clone()).expect("session"),
            io,
        );
        tls.handshake().expect("handshakes");
        tls.write_all(b"ping").expect("writes");
        tls.read_exact(&mut [0u8; 4]).expect("echoes");
        tls
    }

    /// One edge, two dials: a resumed TLS 1.3 handshake carries no certificate, which rustls reports as `HandshakeKind::Resumed` while still handing the session its cached chain.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_second_dial_to_one_edge_resumes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            // One ticket maker behind both accepts: only this listener can open the ticket the first dial left.
            let config = Arc::new(edge_config());
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut conn =
                    rustls::ServerConnection::new(Arc::clone(&config)).expect("server session");
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let mut buf = [0u8; 4];
                if tls.read_exact(&mut buf).is_ok() {
                    let _ = tls.write_all(&buf);
                }
            }
        });
        // "localhost" rather than the shared "tls.test": the session store keys on the name, and a ticket a parallel test's listener left would be handed to this second dial.
        let cfg = client("localhost", &[b"test-only"]);
        // Both dials ride one cached config: rustls gates resumption on the verifier and store a config holds, so a cache miss here sinks the whole witness.
        let kept = RustlsProvider::<TcpStream>::config(&cfg).expect("first config builds");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a dns name");
        let a = dial(&kept, &name, port);
        assert_eq!(
            a.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "the first dial had no ticket to offer"
        );
        assert!(a.peer_leaf().is_some(), "the first dial verified a chain");
        // The stock rustls server hands more than one ticket per session: the witness is that the first dial left the config's own store with one to lend.
        assert!(a.tls13_tickets() >= 1, "the first dial was handed a ticket");
        // A parallel suite could push the config cache to its cap between the dials; if this lapsed, the miss below is eviction's, not the resume path's.
        assert!(
            Arc::ptr_eq(
                &kept,
                &RustlsProvider::<TcpStream>::config(&cfg).expect("config after the first dial")
            ),
            "the cache held the first dial's config across that dial"
        );
        drop(a);
        let b = dial(&kept, &name, port);
        assert_eq!(
            b.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed),
            "the second dial carried no chain: it resumed"
        );
        assert!(
            b.peer_leaf().is_some(),
            "a resumed session keeps the chain it cached"
        );
        drop(b);
        server.join().expect("joins");
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
            // The kind carries the why: a caller matches a certificate refusal without losing which certificate problem it is.
            let TlsError::BadCertificate(why) = &err else {
                panic!("a name mismatch is a certificate refusal, not {err}");
            };
            assert!(why.contains("NotValidForName"), "{why}");
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

    /// Counts the segments a coalesced write reached the writer with, allocating nothing itself
    /// so it can sit inside the measurement window.
    struct SegmentRecorder {
        calls: usize,
        bytes: usize,
    }

    impl Write for SegmentRecorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes += buf.len();
            Ok(buf.len())
        }
        fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
            self.calls += 1;
            let n = bufs.iter().map(|slice| slice.len()).sum();
            self.bytes += n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The four segments the Vision framer hands go out in one record off the stack: no heap
    /// buffer per framed write, which is the allocation the old `collect::<Vec<_>>` paid for.
    #[test]
    fn the_framer_path_coalesces_without_a_heap_buffer() {
        let uuid = [0xabu8; 16];
        let head = [0u8; 5];
        let payload: Vec<u8> = (0..1400).map(|i| i as u8).collect();
        let padding = [0u8; 200];
        let parts: [&[u8]; 4] = [&uuid[..], &head[..], payload.as_slice(), &padding[..]];
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        // The parts are assembled outside the window; only `coalesce` runs inside it.
        let (result, counts) = crate::alloc_count::measure(|| coalesce(&mut recorder, &parts));
        result.expect("coalesces");
        assert_eq!(
            counts.allocs, 0,
            "four segments ride the stack, counted {counts:?}"
        );
        assert_eq!(recorder.calls, 1, "one `write_vectored`, so one record");
        assert_eq!(recorder.bytes, 16 + 5 + 1400 + 200);
    }

    /// Past the stack bound the same segments still go out in one call, and empty runs never
    /// reach the writer where a zero-length slice would stall `advance_slices`.
    #[test]
    fn a_wide_segment_list_and_empty_runs_still_coalesce_in_one_call() {
        let a = [1u8; 3];
        let b = [2u8; 4];
        let empty: [u8; 0] = [];
        let parts: [&[u8]; 6] = [&a[..], &empty[..], &b[..], &empty[..], &a[..], &b[..]];
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        coalesce(&mut recorder, &parts).expect("coalesces");
        assert_eq!(recorder.bytes, 3 + 4 + 3 + 4, "empty runs are dropped");
        assert_eq!(recorder.calls, 1, "one record even past the stack bound");
    }
}
