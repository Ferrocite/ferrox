use super::{Stream, TlsConfig, TlsError, TlsProvider};
use sha2::Digest;
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

/// The reference's `pinnedPeerCertSha256` verifier: a digest matching the leaf's DER accepts
/// the handshake on the pin alone, one matching an intermediate's stands the pinned
/// certificate in as the only trust root and the chain and server name still verify — the
/// same gate `verifyChain` draws, with the standard verifier skipped because the pin is the
/// whole contract.
#[derive(Debug)]
struct CertPinned {
    cert_pins: Arc<[[u8; 32]]>,
}

impl CertPinned {
    fn holds(&self, certificate: &rustls::pki_types::CertificateDer<'_>) -> bool {
        let digest: [u8; 32] = sha2::Sha256::digest(certificate.as_ref()).into();
        self.cert_pins.contains(&digest)
    }
}

impl rustls::client::danger::ServerCertVerifier for CertPinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.holds(end_entity) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        for intermediate in intermediates {
            if !self.holds(intermediate) {
                continue;
            }
            // The pinned certificate acts as the only root, exactly as the reference's pinned-CA path does; the chain and the name still check, and a certificate that cannot anchor is refused rather than retried.
            let anchor = anchored(intermediate)?;
            return anchor
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .or(Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )));
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    // A pin needs no anchor, so the provider's own algorithms answer the messages the webpki path does.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
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
    /// The plain chain verifier a shaped session checks against, built on the first shaped dial: a stock config reaches the same check through rustls's own lazy verifier.
    chain: OnceLock<Result<Arc<rustls::client::WebPkiServerVerifier>, String>>,
    /// Present only when the config pins: the `Pinned` wrapper around the chain verifier, holding the keys a verified chain must still carry.
    verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
}

/// The three config fields `build_material` reads. ALPN is not one of them because the anchors and the suite order do not depend on it, and the server name is not one either: it reaches the connection, not the config.
#[derive(Eq)]
struct MaterialKey {
    roots: crate::tls::Anchors,
    pins: crate::foxy::pin::Pins,
    cert_pins: Arc<[[u8; 32]]>,
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
            && self.cert_pins.as_ref() == other.cert_pins.as_ref()
            && self.cipher_suites == other.cipher_suites
    }
}

impl MaterialKey {
    fn of(cfg: &TlsConfig) -> Self {
        Self {
            roots: Arc::clone(&cfg.roots),
            pins: cfg.pins.clone(),
            cert_pins: Arc::clone(&cfg.cert_pins),
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

    let chain = OnceLock::new();
    let verifier = if !cfg.cert_pins.is_empty() {
        // No anchor work: a cert-pin verdict never needs the webpki chain builder.
        Some(Arc::new(CertPinned {
            cert_pins: Arc::clone(&cfg.cert_pins),
        })
            as Arc<dyn rustls::client::danger::ServerCertVerifier>)
    } else if !cfg.pins.is_empty() {
        let plain = build_chain(&roots, &provider)?;
        let _ = chain.set(Ok(Arc::clone(&plain)));
        Some(Arc::new(Pinned {
            inner: plain,
            pins: cfg.pins.clone(),
        })
            as Arc<dyn rustls::client::danger::ServerCertVerifier>)
    } else {
        None
    };
    Ok(Material {
        roots,
        provider,
        chain,
        verifier,
    })
}

/// What selects a cached client config: a material, the `ALPN` list the builder writes into it, and whether the verifier is the unverified one. The server name stays out — it reaches the connection, not the config.
#[derive(PartialEq, Eq)]
struct ConfigKey {
    material: MaterialKey,
    /// The `ALPN` list, shared rather than copied: the key is built on every dial, and copying the list into it allocated a vector of vectors per lookup for a list that never changes.
    alpn: std::sync::Arc<[Vec<u8>]>,
    insecure: bool,
    /// The ECH config list, which rustls bakes into the built config rather than reading per connection.
    ech: Option<std::sync::Arc<[u8]>>,
}

type Configs = Vec<(ConfigKey, Arc<rustls::ClientConfig>)>;

static CONFIGS: OnceLock<Mutex<Configs>> = OnceLock::new();

/// The client config the cache above keeps one of: the material's provider and roots, the named `ALPN`, and the verifier the config forces.
fn build_config(cfg: &TlsConfig, built: &Material) -> Result<rustls::ClientConfig, TlsError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&built.provider));
    let builder = match cfg.ech_config_list.as_ref() {
        Some(list) => {
            let ech = rustls::client::EchConfig::new(
                rustls::pki_types::EchConfigListBytes::from(list.as_ref()),
                &super::hpke::SUITES,
            )
            .map_err(|e| TlsError::Other(format!("ech config: {e}")))?;
            builder
                .with_ech(rustls::client::EchMode::Enable(ech))
                .map_err(|e| TlsError::Other(format!("ech: {e}")))?
        }
        None => builder
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?,
    };
    let mut config = builder
        .with_root_certificates(Arc::clone(&built.roots))
        .with_no_client_auth();
    config.alpn_protocols.clear();
    config.alpn_protocols.extend(cfg.alpn.iter().cloned());
    if let Some(verifier) = &built.verifier {
        config
            .dangerous()
            .set_certificate_verifier(Arc::clone(verifier));
    } else if cfg.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(Unverified));
    }
    Ok(config)
}

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
    // A dial that raced this build may have stored the same key first, and one key keeps one entry.
    if let Some(at) = kept.iter().position(|(k, _)| *k == key) {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    if kept.len() == MATERIALS_MAX {
        kept.remove(0);
    }
    kept.push((key, Arc::clone(&built)));
    Ok(built)
}

/// The verifier a shaped session checks a server against: the same `Unverified`, pinned or chain choice a stock config makes, without a `ClientConfig` around it.
pub(crate) fn verifier(
    cfg: &TlsConfig,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, TlsError> {
    // A certificate pin is the whole contract, so it outranks `allowInsecure`: the pin check runs and the skip is only what remains of it.
    let built = material(cfg)?;
    if let Some(verifier) = &built.verifier {
        return Ok(Arc::clone(verifier));
    }
    if cfg.insecure {
        return Ok(Arc::new(Unverified));
    }
    let chain = built.chain.get_or_init(|| {
        build_chain(&built.roots, &built.provider).map_err(|error| error.to_string())
    });
    match chain {
        Ok(chain) => Ok(Arc::clone(chain) as Arc<dyn rustls::client::danger::ServerCertVerifier>),
        Err(why) => Err(TlsError::BadCertificate(why.clone())),
    }
}

fn build_chain(
    roots: &Arc<RootStore>,
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, TlsError> {
    rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::clone(roots),
        Arc::clone(provider),
    )
    .build()
    .map_err(|e| TlsError::BadCertificate(format!("chain: {e}")))
}

/// One build per (material, alpn, `insecure`), kept for the life of the process: rustls resumes only under a pointer-equal certificate verifier, so a config rebuilt for each dial discards the ticket the last dial stored, and every flow after the first pays for a full handshake again. At the cap the least-recently-used entry goes, and a hit moves its entry to the back: clearing the whole cache would drop the stores holding every edge's ticket at once, which is the very loss this cache exists to prevent.
fn client_config(cfg: &TlsConfig) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let key = ConfigKey {
        material: MaterialKey::of(cfg),
        alpn: std::sync::Arc::clone(&cfg.alpn),
        insecure: cfg.insecure,
        ech: cfg.ech_config_list.clone(),
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
    let material = material(cfg)?;
    let built = Arc::new(build_config(cfg, &material)?);
    let mut kept = all.lock().expect("one build at a time");
    if let Some(at) = kept.iter().position(|(k, _)| *k == key) {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    if kept.len() == MATERIALS_MAX {
        kept.remove(0);
    }
    kept.push((key, Arc::clone(&built)));
    Ok(built)
}

impl<S: Stream> RustlsProvider<S> {
    pub fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| TlsError::Other(format!("rustls server name: {e}")))?;
        let conn =
            rustls::ClientConnection::new(client_config(cfg)?, name).map_err(|e| map_error(&e))?;
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

    /// Whether this session's only way to make progress is a socket read: `false` while a record's
    /// plaintext still sits in the layer, which a read takes without touching the socket.
    pub fn wants_read(&self) -> bool {
        self.conn.wants_read()
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
        // The record goes out here, and nothing is waited for: `send_pending` owns the idle answer.
        self.send_pending()?;
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
        self.send_pending()?;
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

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        self.drive()?;
        let len = self.conn.writer().write(plaintext)?;
        self.drain_into(out)?;
        Ok(len)
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        self.drive()?;
        coalesce(&mut self.conn.writer(), parts)?;
        self.drain_into(out)
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        // The plaintext the layer holds comes out first: its room is finite, and the ciphertext that follows waits for it.
        let plain = match self.conn.reader().read(buf) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
            outcome => outcome?,
        };
        if plain > 0 || ciphertext.is_empty() {
            return Ok((plain, 0));
        }
        // The layer is empty, so the ciphertext has room to be decrypted.
        let mut cursor = std::io::Cursor::new(ciphertext);
        let taken = self.conn.read_tls(&mut cursor).map_err(recover)?;
        self.conn
            .process_new_packets()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        // A peer's key update is answered into the queue here and leaves with the next seal: a read never writes the transport.
        let plain = match self.conn.reader().read(buf) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
            outcome => outcome?,
        };
        Ok((plain, taken))
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

impl<S: Stream> RustlsProvider<S> {
    /// Every record this session has queued goes into the caller's buffer, in wire order, so the
    /// caller sends them after the session's lock drops.
    fn drain_into(&mut self, out: &mut Vec<u8>) -> std::io::Result<()> {
        while self.conn.wants_write() {
            let wrote = self.conn.write_tls(out)?;
            if wrote == 0 {
                break;
            }
        }
        Ok(())
    }

    /// The ciphertext this session has queued goes out, and nothing comes in: `complete_io` reads as well as it writes, so a write that used it waited for a record the peer had not sent — a socket read per frame, up to the read quantum, under the relay's lock.
    fn flush_pending(&mut self) -> std::io::Result<()> {
        while self.conn.wants_write() {
            let wrote = self.conn.write_tls(&mut self.io)?;
            if wrote == 0 {
                break;
            }
        }
        self.io.flush()
    }

    /// A write's own ciphertext out, with the idle answer a peer that sent nothing is: the call is the write's, so a socket that answered EAGAIN is not its failure.
    fn send_pending(&mut self) -> std::io::Result<()> {
        match self.flush_pending() {
            Err(error) if !idle(&error) => Err(recover(error).into()),
            _ => Ok(()),
        }
    }
}

impl<S: Stream> Write for RustlsProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.drive()?;
        let len = self.conn.writer().write(buf)?;
        self.send_pending()?;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drive()?;
        self.conn.writer().flush()?;
        self.send_pending()?;
        Ok(())
    }
}

enum ServerInner<S: Stream> {
    Rustls {
        conn: Box<rustls::ServerConnection>,
        io: S,
    },
    Ech {
        handshake: Option<boring::ssl::MidHandshakeSslStream<S>>,
        stream: Option<boring::ssl::SslStream<S>>,
        failure: Option<String>,
    },
}

pub struct RustlsServerProvider<S: Stream> {
    inner: ServerInner<S>,
}

impl<S: Stream> std::fmt::Debug for RustlsServerProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            ServerInner::Rustls { conn, .. } => f
                .debug_struct("RustlsServerProvider")
                .field("alpn", &conn.alpn_protocol())
                .field("is_handshaking", &conn.is_handshaking())
                .finish_non_exhaustive(),
            ServerInner::Ech {
                stream, failure, ..
            } => {
                let alpn = stream
                    .as_ref()
                    .and_then(|stream| stream.ssl().selected_alpn_protocol());
                f.debug_struct("RustlsServerProvider")
                    .field("alpn", &alpn)
                    .field("is_handshaking", &stream.is_none())
                    .field("failure", failure)
                    .finish_non_exhaustive()
            }
        }
    }
}

impl<S: Stream> RustlsServerProvider<S> {
    #[allow(clippy::needless_pass_by_value)]
    pub fn accept(cfg: super::TlsServerConfig, io: S) -> Result<Self, TlsError> {
        if cfg.ech_server_keys.is_some() {
            let ctx = cached_ech_server_context(&cfg)?;
            let ssl = boring::ssl::Ssl::new(&ctx).map_err(|error| boring_error(&error))?;
            return Ok(Self {
                inner: ServerInner::Ech {
                    handshake: Some(ssl.setup_accept(io)),
                    stream: None,
                    failure: None,
                },
            });
        }
        let conn = Box::new(
            rustls::ServerConnection::new(cfg.server_config()?).map_err(|e| map_error(&e))?,
        );
        Ok(Self {
            inner: ServerInner::Rustls { conn, io },
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn accept_reality(cfg: super::TlsServerConfig, io: S) -> Result<Self, TlsError> {
        let conn = Box::new(
            rustls::ServerConnection::new(cfg.reality_server_config()?)
                .map_err(|e| map_error(&e))?,
        );
        Ok(Self {
            inner: ServerInner::Rustls { conn, io },
        })
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => {
                while conn.is_handshaking() {
                    if let Err(e) = conn.complete_io(io) {
                        return Err(recover(e));
                    }
                }
                Ok(())
            }
            ServerInner::Ech {
                handshake,
                stream,
                failure,
            } => {
                if let Some(why) = failure {
                    return Err(TlsError::Other(why.clone()));
                }
                if stream.is_some() {
                    return Ok(());
                }
                let Some(mid) = handshake.take() else {
                    return Ok(());
                };
                match mid.handshake() {
                    Ok(done) => {
                        *stream = Some(done);
                        Ok(())
                    }
                    Err(boring::ssl::HandshakeError::WouldBlock(mid)) => {
                        *handshake = Some(mid);
                        Err(TlsError::Timeout)
                    }
                    Err(boring::ssl::HandshakeError::Failure(mid)) => {
                        let why = format!("boring tls handshake: {}", mid.error());
                        *failure = Some(why.clone());
                        Err(TlsError::Other(why))
                    }
                    Err(boring::ssl::HandshakeError::SetupFailure(error)) => {
                        let why = format!("boring tls setup: {error}");
                        *failure = Some(why.clone());
                        Err(TlsError::Other(why))
                    }
                }
            }
        }
    }

    /// Whether this session is the `BoringSSL` path, which owns its transport.
    pub fn is_ech(&self) -> bool {
        matches!(self.inner, ServerInner::Ech { .. })
    }

    /// Whether the client offered ECH and the server accepted it.
    pub fn ech_accepted(&self) -> bool {
        match &self.inner {
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.ssl().ech_accepted(),
            _ => false,
        }
    }
}

impl<S: Stream + super::RecordAlignment> super::RecordAlignment for RustlsServerProvider<S> {
    fn engage_record_alignment(&mut self) {
        match &mut self.inner {
            ServerInner::Rustls { io, .. } => io.engage_record_alignment(),
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.get_mut().engage_record_alignment(),
            ServerInner::Ech {
                handshake: Some(handshake),
                ..
            } => handshake.get_mut().engage_record_alignment(),
            ServerInner::Ech { .. } => {}
        }
    }

    fn disarm_record_alignment(&mut self) {
        match &mut self.inner {
            ServerInner::Rustls { io, .. } => io.disarm_record_alignment(),
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.get_mut().disarm_record_alignment(),
            ServerInner::Ech {
                handshake: Some(handshake),
                ..
            } => handshake.get_mut().disarm_record_alignment(),
            ServerInner::Ech { .. } => {}
        }
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.handshake()?;
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => {
                coalesce(&mut conn.writer(), parts)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(&mut *io)?;
                    if wrote == 0 {
                        break;
                    }
                }
                match io.flush() {
                    Err(error) if !idle(&error) => Err(recover(error).into()),
                    _ => Ok(()),
                }
            }
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => {
                for part in parts {
                    stream.write_all(part)?;
                }
                stream.flush()
            }
            ServerInner::Ech { .. } => Err(std::io::Error::other("ech handshake is not complete")),
        }
    }
}

/// Hand `parts` to a rustls writer in one `write_vectored` so the fragmenter sees one payload and emits one record; iterating `write_all` per part would emit one record per part.
///
/// The framer hands at most `uuid | head | payload | padding` — four segments — the
/// camouflage head gather hands five, and a CONNECT request is seven runs of literal and
/// caller text, so they are laid out on the stack like [`RustlsProvider::write_parts`] does
/// its two, rather than spending one heap `Vec<IoSlice>` on every framed write.
fn coalesce<W: Write + ?Sized>(writer: &mut W, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut stack = [
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
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
#[derive(Default)]
pub struct ServerConfigCacheInner {
    pub plain: Option<std::sync::Arc<rustls::ServerConfig>>,
    pub reality: Option<std::sync::Arc<rustls::ServerConfig>>,
    pub ech: Option<std::sync::Arc<boring::ssl::SslContext>>,
}

impl std::fmt::Debug for ServerConfigCacheInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfigCacheInner")
            .finish_non_exhaustive()
    }
}

pub type ServerConfigCache = std::sync::Arc<std::sync::Mutex<ServerConfigCacheInner>>;

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
    config.alpn_protocols.clear();
    config.alpn_protocols.extend(cfg.alpn.iter().cloned());
    // rustls sends two tickets by default; REALITY arrivals carry none.
    config.send_tls13_tickets = if cfg.send_tickets { 2 } else { 0 };
    Ok(config)
}

pub(crate) fn cached_server_config(
    cfg: &super::TlsServerConfig,
    reality: bool,
) -> Result<std::sync::Arc<rustls::ServerConfig>, TlsError> {
    let mut guard = cfg
        .server_config_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = if reality {
        &mut guard.reality
    } else {
        &mut guard.plain
    };
    if let Some(cached) = slot.as_ref() {
        return Ok(std::sync::Arc::clone(cached));
    }
    let built = std::sync::Arc::new(if reality {
        reality_server_config(cfg.clone())?
    } else {
        server_config(cfg.clone())?
    });
    *slot = Some(std::sync::Arc::clone(&built));
    Ok(built)
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
    config.alpn_protocols.clear();
    config.alpn_protocols.extend(cfg.alpn.iter().cloned());
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
        self.handshake()
    }

    fn alpn(&self) -> Option<&[u8]> {
        match &self.inner {
            ServerInner::Rustls { conn, .. } => conn.alpn_protocol(),
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.ssl().selected_alpn_protocol(),
            ServerInner::Ech { .. } => None,
        }
    }

    fn sni(&self) -> Option<&[u8]> {
        match &self.inner {
            ServerInner::Rustls { conn, .. } => conn.server_name().map(str::as_bytes),
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream
                .ssl()
                .servername_raw(boring::ssl::NameType::HOST_NAME),
            ServerInner::Ech { .. } => None,
        }
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        match &mut self.inner {
            ServerInner::Rustls { conn, .. } => {
                let len = conn.writer().write(plaintext)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(out)?;
                    if wrote == 0 {
                        break;
                    }
                }
                Ok(len)
            }
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => {
                let len = std::io::Write::write(stream, plaintext)?;
                stream.flush()?;
                Ok(len)
            }
            ServerInner::Ech { .. } => Err(std::io::Error::other("ech handshake is not complete")),
        }
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        self.handshake()?;
        match &mut self.inner {
            ServerInner::Rustls { conn, .. } => {
                coalesce(&mut conn.writer(), parts)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(out)?;
                    if wrote == 0 {
                        break;
                    }
                }
                Ok(())
            }
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => {
                for part in parts {
                    stream.write_all(part)?;
                }
                stream.flush()
            }
            ServerInner::Ech { .. } => Err(std::io::Error::other("ech handshake is not complete")),
        }
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        match &mut self.inner {
            ServerInner::Rustls { conn, .. } => {
                let plain = match conn.reader().read(buf) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
                    outcome => outcome?,
                };
                if plain > 0 || ciphertext.is_empty() {
                    return Ok((plain, 0));
                }
                let mut cursor = std::io::Cursor::new(ciphertext);
                let taken = conn.read_tls(&mut cursor).map_err(recover)?;
                conn.process_new_packets()
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                // A key update waits for the next seal rather than a transport write under this lock.
                let plain = match conn.reader().read(buf) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
                    outcome => outcome?,
                };
                Ok((plain, taken))
            }
            ServerInner::Ech { .. } => {
                Err(std::io::Error::other("ech session reads its own transport"))
            }
        }
    }
}

impl<S: Stream> Read for RustlsServerProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.handshake()?;
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => loop {
                match conn.reader().read(buf) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if let Err(io_error) = conn.complete_io(&mut *io) {
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
            },
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.read(buf),
            ServerInner::Ech { .. } => Err(std::io::Error::other("ech handshake is not complete")),
        }
    }
}

impl<S: Stream> RustlsServerProvider<S> {
    /// The transport this session reads and writes, for a relay that would read it itself and hand the session only the ciphertext.
    pub fn get_ref(&self) -> &S {
        match &self.inner {
            ServerInner::Rustls { io, .. } => io,
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.get_ref(),
            ServerInner::Ech {
                handshake: Some(handshake),
                ..
            } => handshake.get_ref(),
            ServerInner::Ech { .. } => unreachable!("an ech session always owns a transport"),
        }
    }
}

impl<S: Stream> Write for RustlsServerProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.handshake()?;
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => {
                let len = conn.writer().write(buf)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(&mut *io)?;
                    if wrote == 0 {
                        break;
                    }
                }
                match io.flush() {
                    Err(error) if !idle(&error) => Err(recover(error).into()),
                    _ => Ok(len),
                }
            }
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.write(buf),
            ServerInner::Ech { .. } => Err(std::io::Error::other("ech handshake is not complete")),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.handshake()?;
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => {
                conn.writer().flush()?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(&mut *io)?;
                    if wrote == 0 {
                        break;
                    }
                }
                match io.flush() {
                    Err(error) if !idle(&error) => Err(recover(error).into()),
                    _ => Ok(()),
                }
            }
            ServerInner::Ech {
                stream: Some(stream),
                ..
            } => stream.flush(),
            ServerInner::Ech { .. } => Err(std::io::Error::other("ech handshake is not complete")),
        }
    }
}

fn boring_error(error: &boring::error::ErrorStack) -> TlsError {
    TlsError::Other(format!("boring tls: {error}"))
}

fn cached_ech_server_context(
    cfg: &super::TlsServerConfig,
) -> Result<Arc<boring::ssl::SslContext>, TlsError> {
    let mut guard = cfg
        .server_config_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(cached) = guard.ech.as_ref() {
        return Ok(Arc::clone(cached));
    }
    let keys = cfg
        .ech_server_keys
        .as_deref()
        .ok_or_else(|| TlsError::Other("ech server identity has no keys".to_owned()))?;
    let built = Arc::new(ech_server_context(cfg, keys)?);
    guard.ech = Some(Arc::clone(&built));
    Ok(built)
}

fn ech_server_context(
    cfg: &super::TlsServerConfig,
    keys: &[u8],
) -> Result<boring::ssl::SslContext, TlsError> {
    Ok(ech_server_context_builder(cfg, keys)?.build())
}

/// The builder behind an ECH-serving context: a TLS listener builds it, and a QUIC lane hands
/// it to quiche, so both answer the same key set and the same certificate.
pub(crate) fn ech_server_context_builder(
    cfg: &super::TlsServerConfig,
    keys: &[u8],
) -> Result<boring::ssl::SslContextBuilder, TlsError> {
    use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
    let mut chain = cfg.cert_chain.iter();
    let leaf = chain
        .next()
        .ok_or_else(|| TlsError::Other("ech server identity has no certificate".to_owned()))?;
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|error| boring_error(&error))?;
    builder.set_verify(SslVerifyMode::NONE);
    let leaf = boring::x509::X509::from_der(leaf).map_err(|error| boring_error(&error))?;
    builder
        .set_certificate(&leaf)
        .map_err(|error| boring_error(&error))?;
    for cert in chain {
        builder
            .add_extra_chain_cert(
                boring::x509::X509::from_der(cert).map_err(|error| boring_error(&error))?,
            )
            .map_err(|error| boring_error(&error))?;
    }
    let key = boring::pkey::PKey::private_key_from_der(&cfg.key_der)
        .map_err(|error| boring_error(&error))?;
    builder
        .set_private_key(&key)
        .map_err(|error| boring_error(&error))?;
    builder
        .check_private_key()
        .map_err(|error| boring_error(&error))?;
    if !cfg.alpn.is_empty() {
        let wanted = cfg.alpn.clone();
        builder.set_alpn_select_callback(move |_, client| {
            for want in &wanted {
                let mut at = 0;
                while at < client.len() {
                    let len = usize::from(client[at]);
                    let Some(protocol) = client.get(at + 1..at + 1 + len) else {
                        return Err(boring::ssl::AlpnError::NOACK);
                    };
                    if protocol == want.as_slice() {
                        return Ok(protocol);
                    }
                    at += 1 + len;
                }
            }
            Err(boring::ssl::AlpnError::NOACK)
        });
    }
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| boring_error(&error))?;
    if !cfg.send_tickets {
        builder.set_options(boring::ssl::SslOptions::NO_TICKET);
    }
    let parsed = crate::tls::ech::parse_server_keys(keys).map_err(TlsError::Other)?;
    let mut ech = boring::ssl::SslEchKeys::builder().map_err(|error| boring_error(&error))?;
    for key in parsed {
        let hpke = boring::hpke::HpkeKey::dhkem_p256_sha256(&key.private_key)
            .map_err(|error| boring_error(&error))?;
        // BoringSSL refuses a set with no retry config; every xray key can answer a rejected offer.
        ech.add_key(true, &key.config, hpke)
            .map_err(|error| boring_error(&error))?;
    }
    builder
        .set_ech_keys(&ech.build())
        .map_err(|error| boring_error(&error))?;
    Ok(builder)
}

/// Whether an error is the socket's poll grain expiring with nothing in it,
/// which `complete_io` reports because it reads as well as it writes.
fn idle(error: &std::io::Error) -> bool {
    TlsError::is_timeout(error)
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
    if let E::PeerIncompatible(rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(
        Some(configs),
    )) = e
    {
        if !configs.is_empty() {
            use rustls::internal::msgs::codec::Codec as _;
            let mut list = Vec::new();
            configs.encode(&mut list);
            return TlsError::EchRetry(list.into());
        }
    }
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
    use crate::tls::shaped::keys;
    use crate::tls::shaped::record;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    const HANDSHAKE: u8 = 22;
    const CCS: u8 = 20;
    const APPLICATION: u8 = 23;

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
            alpn: std::sync::Arc::from(alpn.iter().map(|p| p.to_vec()).collect::<Vec<_>>()),
            roots: vec![ANCHOR.to_vec()].into(),
            pins: crate::foxy::pin::Pins::default(),
            cert_pins: std::sync::Arc::default(),
            cipher_suites: Vec::new(),
            insecure: false,
            fingerprint: None,
            ech_config_list: None,
            websocket: false,
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

    /// A stock rustls server over one accepted stream that echoes `rounds` four-byte frames.
    fn echo_rounds(listener: &TcpListener, rounds: usize) {
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
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        for _ in 0..rounds {
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf)
                .unwrap_or_else(|e| panic!("server read: {e:?}"));
            tls.write_all(&buf).expect("writes");
        }
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

    fn hello_extensions(record: &[u8]) -> Vec<(u16, &[u8])> {
        assert_eq!(record[0], 0x16, "handshake record");
        let record_len = usize::from(record[3]) << 8 | usize::from(record[4]);
        let handshake = &record[5..5 + record_len];
        assert_eq!(handshake[0], 0x01, "ClientHello");
        let body_len = usize::from(handshake[1]) << 16
            | usize::from(handshake[2]) << 8
            | usize::from(handshake[3]);
        let body = &handshake[4..4 + body_len];
        let mut at = 2 + 32;
        at += 1 + usize::from(body[at]);
        at += 2 + (usize::from(body[at]) << 8 | usize::from(body[at + 1]));
        at += 1 + usize::from(body[at]);
        let ext_len = usize::from(body[at]) << 8 | usize::from(body[at + 1]);
        at += 2;
        let end = at + ext_len;
        let mut out = Vec::new();
        while at < end {
            let kind = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = usize::from(body[at + 2]) << 8 | usize::from(body[at + 3]);
            out.push((kind, &body[at + 4..at + 4 + len]));
            at += 4 + len;
        }
        out
    }

    #[cfg_attr(miri, ignore = "assembles a real hello through ring")]
    #[test]
    fn a_configured_ech_list_carries_the_inner_name_only_in_the_payload() {
        let (list, _keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let mut cfg = client("hidden.test", &[]);
        cfg.ech_config_list = Some(list.into());
        let config = client_config(&cfg).expect("builds");
        let mut conn = rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from("hidden.test").expect("name"),
        )
        .expect("session");
        let mut record = Vec::new();
        conn.write_tls(&mut record).expect("hello goes out");
        assert_eq!(conn.ech_status(), rustls::client::EchStatus::Offered);
        let extensions = hello_extensions(&record);
        let (_, ech) = extensions
            .iter()
            .find(|(kind, _)| *kind == 0xfe0d)
            .expect("ech extension");
        assert_eq!(ech[0], 0, "ClientHelloOuter");
        assert_eq!(ech[5], 3, "config id");
        assert_eq!(
            usize::from(ech[6]) << 8 | usize::from(ech[7]),
            32,
            "x25519 enc"
        );
        let (_, sni) = extensions
            .iter()
            .find(|(kind, _)| *kind == 0x0000)
            .expect("sni extension");
        assert!(
            sni.windows(b"public.test".len())
                .any(|window| window == b"public.test"),
            "the outer name is the public one"
        );
        assert!(
            !sni.windows(b"hidden.test".len())
                .any(|window| window == b"hidden.test"),
            "the inner name is not on the outside"
        );
    }

    #[test]
    fn a_malformed_ech_list_refuses_the_dial_instead_of_falling_back() {
        let mut cfg = client("hidden.test", &[]);
        cfg.ech_config_list = Some(vec![0, 1, 2].into());
        assert!(client_config(&cfg).is_err());
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
        let config = client_config(&cfg).expect("builds");
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
    fn a_shaped_chrome_handshake_reaches_a_stock_server() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
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
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf)
                .unwrap_or_else(|e| panic!("server read: {e:?}"));
            tls.write_all(&buf).expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        assert_eq!(session.alpn(), Some(b"http/1.1".as_slice()));
        session.write_all(b"ping").expect("writes");
        session.flush().expect("flushes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        server.join().expect("joins");
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_chrome_handshake_answers_a_client_certificate_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let mut roots = RootStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(ANCHOR.to_vec()))
                .expect("root");
            // Asks for a client certificate and accepts an anonymous client, Go's RequestCert policy.
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider(),
            )
            .allow_unauthenticated()
            .build()
            .expect("client verifier");
            let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
            );
            let mut config = rustls::ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("server versions")
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![cert], key)
                .expect("server cert");
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
            {
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf)
                    .unwrap_or_else(|e| panic!("server read: {e:?}"));
                tls.write_all(&buf).expect("writes");
                tls.flush().expect("flushes");
            }
            // Reading the ping means the dial's flight went through, with no certificate in it.
            assert!(conn.peer_certificates().is_none());
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        assert_eq!(session.alpn(), Some(b"http/1.1".as_slice()));
        session.write_all(b"ping").expect("writes");
        session.flush().expect("flushes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        server.join().expect("joins");
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_record_relays_without_allocating_once_the_handshake_is_done() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || echo_rounds(&listener, 3));
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        session.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        for _ in 0..2 {
            let ((), counts) = crate::alloc_count::measure(|| {
                session
                    .write_all(std::hint::black_box(b"ping"))
                    .expect("writes");
                let mut buf = [0u8; 4];
                session.read_exact(&mut buf).expect("reads");
                assert_eq!(&buf, b"ping");
            });
            assert_eq!(
                counts.allocs, 0,
                "a relayed record takes no heap once its buffers are warm: {counts:?}"
            );
        }
        server.join().expect("joins");
    }

    /// A carrier hands the session ciphertext and its own window: each record lands in that
    /// window directly, its plaintext neither staged nor reallocated, however many relay.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_carrier_record_lands_in_the_callers_window_without_a_stage() {
        const WARM: usize = 8;
        const MEASURED: usize = 8;
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || echo_rounds(&listener, WARM + MEASURED + 1));
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let crate::tls::ClientSession::Shaped(mut session) =
            crate::tls::connect(&cfg, stream).expect("dials")
        else {
            panic!("a fingerprint dials the shaped session");
        };
        session.handshake().expect("handshakes");
        let held = session.plain_buffer().to_vec();
        let capacity = session.plain_capacity();
        let mut sealed = Vec::new();
        let mut scratch = [0u8; 1024];
        let mut window = [0u8; 64];
        let mut relay = |session: &mut crate::tls::shaped::Session<TcpStream>,
                         sealed: &mut Vec<u8>| {
            sealed.clear();
            session.seal_into(b"ping", sealed).expect("seals");
            session
                .get_ref()
                .write_all(sealed)
                .expect("sends the record");
            let mut got = 0;
            while got < 4 {
                let read = session.get_ref().read(&mut scratch).expect("reads");
                assert!(read > 0, "the server answers every round");
                let (plain, consumed) = session
                    .open(&scratch[..read], &mut window[got..])
                    .expect("opens");
                assert_eq!(consumed, read, "a carrier chunk is consumed whole");
                got += plain;
            }
            assert_eq!(&window[..4], b"ping", "the caller's window hears the frame");
        };
        for _ in 0..WARM {
            relay(&mut session, &mut sealed);
        }
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..MEASURED {
                relay(&mut session, &mut sealed);
            }
        });
        assert_eq!(
            counts.allocs, 0,
            "a carrier record takes no heap once its buffers are warm: {counts:?}"
        );
        assert_eq!(
            session.plain_buffer(),
            held.as_slice(),
            "a carrier record with room in the window stages no plaintext"
        );
        assert_eq!(
            session.plain_capacity(),
            capacity,
            "the plaintext buffer does not grow with the relay"
        );
        sealed.clear();
        session.seal_into(b"ping", &mut sealed).expect("seals");
        session
            .get_ref()
            .write_all(&sealed)
            .expect("sends the record");
        let read = session.get_ref().read(&mut scratch).expect("reads");
        let (first, consumed) = session
            .open(&scratch[..read], &mut window[..2])
            .expect("opens");
        assert_eq!(
            (first, consumed),
            (2, read),
            "a window smaller than the record holds the rest"
        );
        let (second, consumed) = session.open(&[], &mut window[2..]).expect("opens");
        assert_eq!(
            (second, consumed),
            (2, 0),
            "the held half follows before any more ciphertext"
        );
        assert_eq!(&window[..4], b"ping", "the frame keeps its order");
        server.join().expect("joins");
    }

    /// A TLS 1.2 listener of our own, keyed to the suite its constructor names rather than only the
    /// AEAD rows rustls serves. It hashes the extended master secret only when the hello offered it,
    /// appends the `ClientKeyExchange` before hashing that transcript, and refuses a `Finished`
    /// that did not.
    struct Tls12Server {
        suite: u16,
        group: u16,
        ask_cert: bool,
        rng: ring::rand::SystemRandom,
        signing: ring::signature::EcdsaKeyPair,
        ephemeral: Option<keys::Share>,
        server_random: [u8; 32],
        client_random: [u8; 32],
        session_id: Vec<u8>,
        transcript: Vec<u8>,
        master: Vec<u8>,
        ems: bool,
        read_dir: Option<record::Direction>,
        write_dir: Option<record::Direction>,
        pending: Vec<u8>,
        feed: Vec<u8>,
    }

    impl Tls12Server {
        fn new(suite: u16, group: u16, ask_cert: bool) -> Self {
            let rng = ring::rand::SystemRandom::new();
            let signing = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                ANCHOR_KEY,
                &rng,
            )
            .expect("signing key");
            let mut ephemeral = keys::generate(&[group], false).expect("an ephemeral key");
            Self {
                suite,
                group,
                ask_cert,
                rng,
                signing,
                ephemeral: Some(ephemeral.pop().expect("one group")),
                server_random: [0x42; 32],
                client_random: [0u8; 32],
                session_id: Vec::new(),
                transcript: Vec::new(),
                master: Vec::new(),
                ems: false,
                read_dir: None,
                write_dir: None,
                pending: Vec::new(),
                feed: Vec::new(),
            }
        }

        fn process(&mut self) {
            let mut at = 0;
            while self.pending.len() - at >= 5 {
                let len = usize::from(u16::from_be_bytes([
                    self.pending[at + 3],
                    self.pending[at + 4],
                ]));
                if self.pending.len() - at - 5 < len {
                    break;
                }
                let kind = self.pending[at];
                let body = self.pending[at + 5..at + 5 + len].to_vec();
                at += 5 + len;
                self.record(kind, body);
            }
            self.pending.drain(..at);
        }

        fn record(&mut self, kind: u8, mut body: Vec<u8>) {
            match kind {
                CCS => {}
                HANDSHAKE if self.read_dir.is_some() => {
                    let (start, len) =
                        record::open12(self.read_dir.as_mut().expect("read keys"), kind, &mut body)
                            .expect("client record opens");
                    self.handshake(&body[start..start + len]);
                }
                HANDSHAKE => self.handshake(&body),
                APPLICATION => {
                    let (start, len) =
                        record::open12(self.read_dir.as_mut().expect("read keys"), kind, &mut body)
                            .expect("application record opens");
                    assert_eq!(
                        &body[start..start + len],
                        b"ping",
                        "the client's frame opens whole"
                    );
                    let mut out = Vec::new();
                    record::seal12(
                        self.write_dir.as_mut().expect("write keys"),
                        APPLICATION,
                        &body[start..start + len],
                        &mut out,
                    )
                    .expect("seals");
                    self.feed.extend_from_slice(&out);
                }
                other => panic!("unexpected record {other}"),
            }
        }

        fn handshake(&mut self, msg: &[u8]) {
            match msg[0] {
                1 => self.client_hello(msg),
                11 => self.transcript.extend_from_slice(msg),
                16 => self.client_key_exchange(msg),
                20 => self.client_finished(msg),
                other => panic!("unexpected handshake message {other}"),
            }
        }

        fn client_hello(&mut self, msg: &[u8]) {
            let mut c = Cursor::new(&msg[4..]);
            c.u16();
            self.client_random.copy_from_slice(c.take(32));
            self.session_id = c.vec8().to_vec();
            let suites = c.vec16();
            assert!(
                suites
                    .as_chunks::<2>()
                    .0
                    .contains(&self.suite.to_be_bytes()),
                "the hello offers the suite the server names"
            );
            c.vec8();
            let mut ems = false;
            let mut alpn = false;
            let mut ext = Cursor::new(c.vec16());
            while ext.at < ext.bytes.len() {
                let kind = ext.u16();
                let value = ext.vec16();
                match kind {
                    0x0017 => ems = true,
                    0x0010 => {
                        let mut list = Cursor::new(value);
                        let mut protos = Cursor::new(list.vec16());
                        while protos.at < protos.bytes.len() {
                            alpn |= protos.vec8() == b"http/1.1";
                        }
                    }
                    _ => {}
                }
            }
            assert!(alpn, "the hello offers http/1.1");
            self.ems = ems;
            self.transcript.extend_from_slice(msg);

            let mut hello = Vec::new();
            hello.extend_from_slice(&[0x03, 0x03]);
            hello.extend_from_slice(&self.server_random);
            hello.push(self.session_id.len() as u8);
            hello.extend_from_slice(&self.session_id);
            hello.extend_from_slice(&self.suite.to_be_bytes());
            hello.push(0);
            let mut ext = Vec::new();
            if self.ems {
                ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
            }
            ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08]);
            ext.extend_from_slice(b"http/1.1");
            hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            hello.extend_from_slice(&ext);
            let hello = hs_message(2, &hello);

            let mut cert = Vec::new();
            cert.extend_from_slice(&(ANCHOR.len() as u32).to_be_bytes()[1..]);
            cert.extend_from_slice(ANCHOR);
            let mut chain = Vec::new();
            chain.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            chain.extend_from_slice(&cert);
            let chain = hs_message(11, &chain);

            let params = {
                let share = self.ephemeral.as_ref().expect("one key exchange");
                let mut params = vec![3];
                params.extend_from_slice(&self.group.to_be_bytes());
                params.push(share.data.len() as u8);
                params.extend_from_slice(&share.data);
                params
            };
            let mut signed = Vec::with_capacity(64 + params.len());
            signed.extend_from_slice(&self.client_random);
            signed.extend_from_slice(&self.server_random);
            signed.extend_from_slice(&params);
            let signature = self.signing.sign(&self.rng, &signed).expect("signs");
            let mut exchange = params;
            exchange.extend_from_slice(&[0x04, 0x03]);
            exchange.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
            exchange.extend_from_slice(signature.as_ref());
            let exchange = hs_message(12, &exchange);
            let request = hs_message(13, &[0x01, 0x40, 0x00, 0x00]);
            let done = hs_message(14, &[]);

            let mut parts: Vec<&[u8]> = vec![&hello, &chain, &exchange];
            if self.ask_cert {
                parts.push(&request);
            }
            parts.push(&done);
            let mut flight = Vec::new();
            for part in parts {
                self.transcript.extend_from_slice(part);
                flight.extend_from_slice(part);
            }
            self.push_record(HANDSHAKE, &flight);
        }

        fn client_key_exchange(&mut self, msg: &[u8]) {
            let mut c = Cursor::new(&msg[4..]);
            let peer = c.vec8().to_vec();
            self.transcript.extend_from_slice(msg);
            let private = self.ephemeral.take().expect("one key exchange");
            let shared = private.agree(&peer).expect("agrees");
            let suite = record::Suite::from_id(self.suite).expect("suite");
            let session_hash = self.ems.then(|| suite.hash().hash(&self.transcript));
            let (master, directions) = crate::tls::shaped::tls12::keys(
                suite,
                &shared,
                &self.client_random,
                &self.server_random,
                session_hash.as_deref(),
            );
            self.read_dir = Some(directions.client);
            self.write_dir = Some(directions.server);
            self.master = master;
        }

        fn client_finished(&mut self, msg: &[u8]) {
            let suite = record::Suite::from_id(self.suite).expect("suite");
            let expected = crate::tls::shaped::tls12::finished(
                suite,
                &self.master,
                b"client finished",
                &self.transcript,
            );
            assert_eq!(
                &msg[4..],
                expected.as_slice(),
                "the client hashed its ClientKeyExchange into the extended master secret"
            );
            self.transcript.extend_from_slice(msg);
            let verify = crate::tls::shaped::tls12::finished(
                suite,
                &self.master,
                b"server finished",
                &self.transcript,
            );
            self.push_record(CCS, &[1]);
            let mut out = Vec::new();
            record::seal12(
                self.write_dir.as_mut().expect("write keys"),
                HANDSHAKE,
                &hs_message(20, &verify),
                &mut out,
            )
            .expect("seals");
            self.feed.extend_from_slice(&out);
        }

        fn push_record(&mut self, kind: u8, body: &[u8]) {
            self.feed.push(kind);
            self.feed.extend_from_slice(&[0x03, 0x03]);
            self.feed
                .extend_from_slice(&(body.len() as u16).to_be_bytes());
            self.feed.extend_from_slice(body);
        }
    }

    impl std::io::Read for Tls12Server {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.feed.len().min(buf.len());
            buf[..n].copy_from_slice(&self.feed[..n]);
            self.feed.drain(..n);
            Ok(n)
        }
    }

    impl std::io::Write for Tls12Server {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.pending.extend_from_slice(buf);
            self.process();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Frames one handshake message the way the shaped client's parser expects it.
    fn hs_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + body.len());
        out.push(kind);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    /// The fixture's own reader: the shaped client's is private to its module.
    struct Cursor<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl<'a> Cursor<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, at: 0 }
        }

        fn take(&mut self, n: usize) -> &'a [u8] {
            let end = self.at + n;
            assert!(end <= self.bytes.len(), "truncated handshake");
            let out = &self.bytes[self.at..end];
            self.at = end;
            out
        }

        fn u8(&mut self) -> u8 {
            self.take(1)[0]
        }

        fn u16(&mut self) -> u16 {
            let bytes = self.take(2);
            u16::from_be_bytes([bytes[0], bytes[1]])
        }

        fn vec8(&mut self) -> &'a [u8] {
            let len = usize::from(self.u8());
            self.take(len)
        }

        fn vec16(&mut self) -> &'a [u8] {
            let len = usize::from(self.u16());
            self.take(len)
        }
    }

    /// One shaped dial per TLS 1.2 record shape — an AEAD, a CBC block, an RC4 stream — each relayed
    /// one frame both ways. The RC4 preset carries no `key_share`, so its point is drawn at the
    /// curve the `ServerKeyExchange` names, from that hello's `supported_groups`, and the CBC dial
    /// also asks for a client certificate, which the walk answers with an empty one.
    #[cfg_attr(miri, ignore = "assembles real handshake bytes through ring")]
    #[test]
    fn a_shaped_dial_finishes_every_tls12_record_shape() {
        let shapes = [
            ("chrome", 0xc02bu16, keys::X25519, false),
            ("helloios_13", 0xc009, keys::X25519, true),
            ("360", 0xc007, keys::P256, false),
        ];
        for (preset, suite, group, ask_cert) in shapes {
            let mut cfg = client("tls.test", &[]);
            cfg.fingerprint =
                Some(crate::tls::Fingerprint::resolve(preset).expect("a preset name"));
            let mut session = crate::tls::shaped::Session::connect(
                &cfg,
                Tls12Server::new(suite, group, ask_cert),
            )
            .unwrap_or_else(|e| panic!("{preset} at {suite:#06x}: {e}"));
            session
                .handshake()
                .unwrap_or_else(|e| panic!("{preset} at {suite:#06x} did not finish: {e}"));
            assert_eq!(session.alpn(), Some(b"http/1.1".as_slice()));
            assert_eq!(session.peer_leaf(), Some(ANCHOR));
            session.write_all(b"ping").expect("writes");
            session.flush().expect("flushes");
            let mut buf = [0u8; 4];
            session
                .read_exact(&mut buf)
                .unwrap_or_else(|e| panic!("{preset} at {suite:#06x} could not open a frame: {e}"));
            assert_eq!(&buf, b"ping", "one frame each way behind {suite:#06x}");
        }
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
        let built = material(&client("one.test", &[b"test-only"])).expect("builds");
        let other_name = material(&client("two.test", &[b"nope"])).expect("builds");
        assert!(
            Arc::ptr_eq(&built, &other_name),
            "a new host or ALPN asks for no new anchors"
        );

        let mut pinned = client("one.test", &[b"test-only"]);
        pinned.pins = crate::foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        ]);
        let with_pin = material(&pinned).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &with_pin),
            "a pinned verifier is not an unpinned one"
        );

        let mut reordered = client("one.test", &[b"test-only"]);
        reordered.cipher_suites = vec![0x1302];
        let other_order = material(&reordered).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &other_order),
            "a named suite order is a different provider"
        );

        let mut no_anchor = client("one.test", &[b"test-only"]);
        no_anchor.roots = Vec::new().into();
        let empty = material(&no_anchor).expect("builds");
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
        let kept = client_config(&cfg).expect("first config builds");
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
                &client_config(&cfg).expect("config after the first dial")
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
    fn ech_server_accepts_the_offer_and_echoes() {
        let (list, keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let mut identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        identity.ech_server_keys = Some(keys.into());
        identity.alpn = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(server.ech_accepted(), "the offer was accepted");
                assert_eq!(
                    server.alpn(),
                    Some(&b"http/1.1"[..]),
                    "the server's list wins when the client offers both"
                );
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[b"h2", b"http/1.1"]);
            cfg.ech_config_list = Some(list.into());
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = crate::tls::connect(&cfg, stream).expect("configures");
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
    fn ech_server_accepts_an_aes_256_only_offer() {
        let (list, keys) = crate::tls::ech::generate_with_suites(
            "public.test",
            4,
            &[(
                crate::tls::ech::KDF_SHA256,
                crate::tls::ech::AEAD_AES_256_GCM,
            )],
        )
        .expect("generates");
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let mut identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        identity.ech_server_keys = Some(keys.into());
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(server.ech_accepted(), "the aes-256 offer was accepted");
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[]);
            cfg.ech_config_list = Some(list.into());
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = crate::tls::connect(&cfg, stream).expect("configures");
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
    fn ech_server_still_answers_a_client_that_does_not_offer_it() {
        let (_, keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let mut identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        identity.ech_server_keys = Some(keys.into());
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(!server.ech_accepted(), "no offer means no acceptance");
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

    /// A socket that counts the reads that reach it and the bytes each one carried.
    struct ReadCounter {
        inner: TcpStream,
        calls: Arc<AtomicUsize>,
        bytes: Arc<AtomicUsize>,
        sizes: Arc<Mutex<Vec<usize>>>,
    }

    impl Read for ReadCounter {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Counted before the call: a read that answers `WouldBlock` with nothing in it is the wait these rows name, and counting only reads that returned would hide it.
            self.calls.fetch_add(1, Ordering::Relaxed);
            let n = self.inner.read(buf)?;
            self.bytes.fetch_add(n, Ordering::Relaxed);
            self.sizes.lock().expect("locks").push(n);
            Ok(n)
        }
    }

    impl Write for ReadCounter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    impl super::super::RecordAlignment for ReadCounter {}

    /// A flush that also read waited for a record the peer had not sent, and the relay holds
    /// the session's lock through that wait. The count is exact: the peer never sends, so
    /// every read the session makes is one this tree asked for.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_flush_does_not_read_the_transport() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let calls = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let sizes = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                // The peer writes and nothing answers, so no record ever arrives here.
                let mut buf = [0u8; 64];
                loop {
                    match server.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let counter = ReadCounter {
                inner: stream,
                calls: Arc::clone(&calls),
                bytes: Arc::clone(&bytes),
                sizes: Arc::clone(&sizes),
            };
            let mut client =
                crate::tls::connect(&client("tls.test", &[]), counter).expect("configures");
            client.handshake().expect("handshakes");
            let before = calls.load(Ordering::Relaxed);
            client.write_all(b"payload").expect("writes");
            client.flush().expect("flushes");
            let after = calls.load(Ordering::Relaxed);
            assert_eq!(
                after - before,
                0,
                "the flush read the transport {after} times where it had read {before}"
            );
        });
    }

    /// The write's half of the same rule, and the zero-length write is its edge: a call that
    /// queues no record gives `complete_io` nothing to send, which is the state where it reads.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_write_does_not_read_the_transport() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let calls = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let sizes = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                // The peer never answers, so the only record on the wire is the client's own.
                let mut buf = [0u8; 64];
                loop {
                    match server.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let counter = ReadCounter {
                inner: stream,
                calls: Arc::clone(&calls),
                bytes: Arc::clone(&bytes),
                sizes: Arc::clone(&sizes),
            };
            let mut client =
                RustlsProvider::connect(&client("tls.test", &[]), counter).expect("configures");
            client.handshake().expect("handshakes");
            // The relay's own arm for a shared session, so a read inside the window costs one counted grain rather than a parked thread.
            client
                .io
                .inner
                .set_read_timeout(Some(std::time::Duration::from_millis(1)))
                .expect("arms a grain");
            let before = calls.load(Ordering::Relaxed);
            let wrote = client.write(b"payload").expect("writes");
            let empty = client.write(&[]).expect("an empty write shows nothing");
            let after = calls.load(Ordering::Relaxed);
            assert_eq!(wrote, 7);
            assert_eq!(empty, 0);
            assert_eq!(
                after - before,
                0,
                "the write read the transport {after} times where it had read {before}"
            );
        });
    }

    /// The answer's half of the write rule: a server session's write pushes the records it
    /// framed and leaves the request's bytes to whichever call is reading them. The count is
    /// exact: the peer answers nothing, so every read the session makes is one this tree asked for.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_server_answer_write_does_not_read_the_transport() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let calls = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let sizes = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let counter = ReadCounter {
                    inner: stream,
                    calls: Arc::clone(&calls),
                    bytes: Arc::clone(&bytes),
                    sizes: Arc::clone(&sizes),
                };
                let mut server = RustlsServerProvider::accept(identity.clone(), counter)
                    .expect("accepts a session");
                server.handshake().expect("handshakes");
                // The relay's own arm for a shared session, so a read inside the window costs one counted grain rather than a parked thread.
                server
                    .get_ref()
                    .inner
                    .set_read_timeout(Some(std::time::Duration::from_millis(1)))
                    .expect("arms a grain");
                let before = calls.load(Ordering::Relaxed);
                server.write_all(b"answer").expect("answers");
                server.flush().expect("flushes");
                let after = calls.load(Ordering::Relaxed);
                assert_eq!(
                    after - before,
                    0,
                    "the answer read the transport {after} times where it had read {before}"
                );
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = crate::tls::connect(&client("tls.test", &[]), stream).expect("dials");
            client.handshake().expect("handshakes");
            let mut sink = [0u8; 64];
            while matches!(client.read(&mut sink), Ok(read) if read > 0) {}
        });
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

    /// The camouflage head gather is one piece wider than the framer — `GET `, the path, the
    /// middle, the host, the trailer — and a repeated dial cycle still enters the allocator zero
    /// times: the fifth run rides the stack too, where it once bought a `Vec<IoSlice>` per dial.
    #[test]
    fn the_camouflage_gather_coalesces_without_a_heap_buffer() {
        let before = b"GET ";
        let path = "/camouflage";
        let middle = b" HTTP/1.1\r\nHost: ";
        let host = "oracle.example";
        let after = b"\r\nConnection: keep-alive\r\n\r\n";
        let parts: [&[u8]; 5] = [before, path.as_bytes(), middle, host.as_bytes(), after];
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        // Three dials' gathers inside one window: a reclaim that stopped firing would show as a rising count.
        let (result, counts) = crate::alloc_count::measure(|| {
            let mut last = Ok(());
            for _ in 0..3 {
                last = coalesce(&mut recorder, &parts);
            }
            last
        });
        result.expect("coalesces");
        assert_eq!(
            counts.allocs, 0,
            "five segments ride the stack over every dial, counted {counts:?}"
        );
        assert_eq!(
            recorder.calls, 3,
            "one `write_vectored` per gather, so one record each"
        );
        assert_eq!(
            recorder.bytes,
            3 * (before.len() + path.len() + middle.len() + host.len() + after.len())
        );
    }

    /// A CONNECT request is seven runs of literal and caller text — wider than the camouflage
    /// gather — and a repeated open still enters the allocator zero times: the request rides the
    /// stack into one `write_vectored`, so no buffer is built to hold it first.
    #[test]
    fn the_connect_request_gathers_without_a_heap_buffer() {
        let parts = crate::foxy::connect_request(
            "example.com:443",
            crate::foxy::BEARER_HEAD,
            "pass.jwt.value",
        );
        let want: usize = parts.iter().map(|part| part.len()).sum();
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        // Three opens inside one window: a reclaim that stopped firing would show as a rising count.
        let (result, counts) = crate::alloc_count::measure(|| {
            let mut last = Ok(());
            for _ in 0..3 {
                last = coalesce(&mut recorder, &parts);
            }
            last
        });
        result.expect("coalesces");
        assert_eq!(
            counts.allocs, 0,
            "seven segments ride the stack over every open, counted {counts:?}"
        );
        assert_eq!(
            recorder.calls, 3,
            "one `write_vectored` per request, so one record each"
        );
        assert_eq!(
            recorder.bytes,
            3 * want,
            "the bytes the concatenated request carried, unchanged"
        );
    }

    /// Past the stack bound the same segments still go out in one call, and empty runs never
    /// reach the writer where a zero-length slice would stall `advance_slices`.
    #[test]
    fn a_wide_segment_list_and_empty_runs_still_coalesce_in_one_call() {
        let a = [1u8; 3];
        let b = [2u8; 4];
        let empty: [u8; 0] = [];
        let parts: [&[u8]; 8] = [
            &a[..],
            &empty[..],
            &b[..],
            &empty[..],
            &a[..],
            &b[..],
            &a[..],
            &empty[..],
        ];
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        coalesce(&mut recorder, &parts).expect("coalesces");
        assert_eq!(recorder.bytes, 3 + 4 + 3 + 4 + 3, "empty runs are dropped");
        assert_eq!(recorder.calls, 1, "one record even past the stack bound");
    }
}
