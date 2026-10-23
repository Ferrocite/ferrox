// The shaped client handshake: a browser hello out, both TLS versions' flights back under keys this module owns.
use super::hello::{Hello, TLS12};
use super::kdf::{self, Hash};
use super::record::{self, Direction, Suite};
use super::{Fingerprint, Profile};
use crate::tls::{RecordAlignment, Stream, TlsConfig, TlsError, TlsProvider};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::sync::Arc;

const HANDSHAKE: u8 = 22;
const ALERT: u8 = 21;
const CCS: u8 = 20;
const APPLICATION: u8 = 23;
const MAX_RECORD: usize = 16384 + 256;
const MAX_HANDSHAKE: usize = 1 << 20;
const MAX_PLAINTEXT: usize = 16384;

/// The `HelloRetryRequest` random, which names the message without a new type.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    Tls13,
    Tls12,
}

/// One shaped client session: the same stream shape as every other TLS provider,
/// with the record keys and transcript in this type rather than a rustls connection.
pub struct Session<S: Stream> {
    io: S,
    verifier: Arc<dyn ServerCertVerifier>,
    server_name: ServerName<'static>,
    profile: &'static Profile,
    hello: Option<Hello>,
    client_random: [u8; 32],
    transcript: Vec<u8>,
    version: Option<Version>,
    suite: Option<Suite>,
    read_key: Option<Direction>,
    write_key: Option<Direction>,
    server12: Option<Direction>,
    client12: Option<Direction>,
    alpn: Option<Vec<u8>>,
    leaf: Option<Vec<u8>>,
    done: bool,
    eof: bool,
    ccs_sent: bool,
    hs: Vec<u8>,
    plain: Vec<u8>,
    plain_at: usize,
    plain_end: usize,
    inbuf: Vec<u8>,
    in_at: usize,
    reply: Vec<u8>,
    out: Vec<u8>,
}

impl<S: Stream> std::fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("profile", &self.profile.name)
            .field("alpn", &self.alpn)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S: Stream> Session<S> {
    /// Builds the shaped hello; the handshake that puts it on the wire runs when
    /// `handshake` is called, exactly as the stock provider's connection waits.
    pub(crate) fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let Some(profile) = cfg.fingerprint.and_then(Fingerprint::profile) else {
            return Err(TlsError::Other(
                "shaped: a stock fingerprint has no shaped session".to_owned(),
            ));
        };
        let hello = Hello::build(profile, &cfg.server_name, &cfg.alpn, cfg.websocket)?;
        let verifier = crate::tls::rustls_backend::verifier(cfg)?;
        Self::with_hello(profile, cfg.server_name.clone(), verifier, hello, io)
    }

    /// A session over a hello the caller built and sealed, as REALITY does.
    pub(crate) fn with_hello(
        profile: &'static Profile,
        server_name: String,
        verifier: Arc<dyn ServerCertVerifier>,
        hello: Hello,
        io: S,
    ) -> Result<Self, TlsError> {
        let server_name = ServerName::try_from(server_name)
            .map_err(|e| TlsError::Other(format!("tls server name: {e}")))?;
        Ok(Self {
            io,
            verifier,
            server_name,
            profile,
            hello: Some(hello),
            client_random: [0u8; 32],
            transcript: Vec::new(),
            version: None,
            suite: None,
            read_key: None,
            write_key: None,
            server12: None,
            client12: None,
            alpn: None,
            leaf: None,
            done: false,
            eof: false,
            ccs_sent: false,
            hs: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            plain_end: 0,
            inbuf: Vec::new(),
            in_at: 0,
            reply: Vec::new(),
            out: Vec::new(),
        })
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.io
    }

    /// The plaintext buffer, which a carrier record with room in the caller's window never stages into.
    #[cfg(test)]
    pub(crate) fn plain_buffer(&self) -> &[u8] {
        &self.plain
    }

    /// The plaintext buffer's capacity, which a relayed record must not grow.
    #[cfg(test)]
    pub(crate) fn plain_capacity(&self) -> usize {
        self.plain.capacity()
    }

    fn run(&mut self) -> Result<(), TlsError> {
        if self.done {
            return Ok(());
        }
        let mut hello = self
            .hello
            .take()
            .ok_or_else(|| TlsError::Other("shaped: handshake already ran".to_owned()))?;
        self.client_random = hello.random;
        self.send_plain(HANDSHAKE, &hello.msg, [0x03, 0x01])?;
        self.transcript.extend_from_slice(&hello.msg);
        let mut msg = self.next_handshake()?;
        if msg[0] != 2 {
            return Err(unexpected(msg[0]));
        }
        let mut sh = ServerHello::parse(&msg[4..])?;
        if sh.hrr {
            let suite = Suite::from_id(sh.suite)
                .filter(|suite| suite.is_tls13())
                .ok_or(TlsError::NoSharedCipher)?;
            let first = std::mem::take(&mut self.transcript);
            let hashed = suite.hash().hash(&first);
            let mut transcript = Vec::with_capacity(4 + hashed.len() + msg.len());
            transcript.push(254);
            transcript.extend_from_slice(&(hashed.len() as u32).to_be_bytes()[1..]);
            transcript.extend_from_slice(&hashed);
            transcript.extend_from_slice(&msg);
            self.transcript = transcript;
            let group = sh
                .hrr_group
                .ok_or_else(|| TlsError::Other("retry request names no group".to_owned()))?;
            self.send_ccs()?;
            hello = hello.retry(group, sh.cookie.as_deref())?;
            self.send_plain(HANDSHAKE, &hello.msg, [0x03, 0x03])?;
            self.transcript.extend_from_slice(&hello.msg);
            msg = self.next_handshake()?;
            if msg[0] != 2 {
                return Err(unexpected(msg[0]));
            }
            sh = ServerHello::parse(&msg[4..])?;
            if sh.hrr {
                return Err(TlsError::Other(
                    "a second retry request is not allowed".to_owned(),
                ));
            }
        }
        self.transcript.extend_from_slice(&msg);
        self.suite = Suite::from_id(sh.suite);
        match sh.version {
            0x0304 => self.run13(&mut hello, &mut sh),
            0x0303 => self.run12(&mut hello, &sh),
            _ => Err(TlsError::NoSharedCipher),
        }?;
        self.check_alpn(&hello, &sh)?;
        self.done = true;
        Ok(())
    }

    fn check_alpn(&mut self, hello: &Hello, sh: &ServerHello) -> Result<(), TlsError> {
        if let Some(pick) = &sh.alpn {
            if !hello.alpn_offered().iter().any(|proto| proto == pick) {
                return Err(TlsError::Other(
                    "server selected an ALPN protocol we did not offer".to_owned(),
                ));
            }
            self.alpn = Some(pick.clone());
        }
        Ok(())
    }

    fn run13(&mut self, hello: &mut Hello, sh: &mut ServerHello) -> Result<(), TlsError> {
        self.version = Some(Version::Tls13);
        let suite = Suite::from_id(sh.suite)
            .filter(|suite| suite.is_tls13())
            .ok_or(TlsError::NoSharedCipher)?;
        let (group, peer) = sh
            .share
            .as_ref()
            .ok_or_else(|| TlsError::Other("server hello carries no key share".to_owned()))?;
        let shared = hello.agree(*group, peer)?;
        let hash = suite.hash();
        let zeros = vec![0u8; hash.len()];
        let early = kdf::extract(hash, &zeros, &zeros);
        let derived = kdf::derive(hash, &early, b"derived", &[]);
        let handshake_secret = kdf::extract(hash, &derived, &shared);
        let client_hs = kdf::derive(hash, &handshake_secret, b"c hs traffic", &self.transcript);
        let server_hs = kdf::derive(hash, &handshake_secret, b"s hs traffic", &self.transcript);
        let derived2 = kdf::derive(hash, &handshake_secret, b"derived", &[]);
        let master = kdf::extract(hash, &derived2, &zeros);
        self.read_key = Some(Direction::tls13(suite, &server_hs));
        self.send_ccs()?;

        let msg = self.next_expect(8)?;
        self.transcript.extend_from_slice(&msg);
        sh.alpn = encrypted_extensions(&msg[4..])?;

        // A TLS 1.3 server interleaves its CertificateRequest ahead of its own Certificate.
        let mut asked = None;
        let mut msg = self.next_handshake()?;
        if msg[0] == 13 {
            asked = Some(request_context(&msg[4..])?);
            self.transcript.extend_from_slice(&msg);
            msg = self.next_expect(11)?;
        } else if msg[0] != 11 {
            return Err(unexpected(msg[0]));
        }
        let chain = certificates13(&msg[4..])?;
        self.verify_chain(&chain)?;
        self.transcript.extend_from_slice(&msg);

        let msg = self.next_expect(15)?;
        let signed = std::mem::take(&mut self.transcript);
        self.verify_certificate_verify(&msg[4..], &signed, true)?;
        self.transcript = signed;
        self.transcript.extend_from_slice(&msg);

        let msg = self.next_expect(20)?;
        let expected =
            kdf::verify_data(hash, &kdf::finished_key(hash, &server_hs), &self.transcript);
        if msg[4..] != expected[..] {
            return Err(TlsError::Other("server Finished did not verify".to_owned()));
        }
        self.transcript.extend_from_slice(&msg);

        // Both application secrets take the transcript only through the server's Finished.
        let server_ap = kdf::derive(hash, &master, b"s ap traffic", &self.transcript);
        let client_ap = kdf::derive(hash, &master, b"c ap traffic", &self.transcript);
        self.read_key = Some(Direction::tls13(suite, &server_ap));
        self.write_key = Some(Direction::tls13(suite, &client_hs));

        if let Some(context) = &asked {
            // The empty chain answers the request, and its bytes count in our own Finished hash.
            let answer = certificate_answer13(context);
            self.send_encrypted(HANDSHAKE, &answer)?;
            self.transcript.extend_from_slice(&answer);
        }

        let verify = kdf::verify_data(hash, &kdf::finished_key(hash, &client_hs), &self.transcript);
        let mut finished = Vec::with_capacity(4 + verify.len());
        finished.push(20);
        finished.extend_from_slice(&(verify.len() as u32).to_be_bytes()[1..]);
        finished.extend_from_slice(&verify);
        self.send_encrypted(HANDSHAKE, &finished)?;
        self.transcript.extend_from_slice(&finished);
        self.write_key = Some(Direction::tls13(suite, &client_ap));
        Ok(())
    }

    fn run12(&mut self, hello: &mut Hello, sh: &ServerHello) -> Result<(), TlsError> {
        self.version = Some(Version::Tls12);
        let suite = Suite::from_id(sh.suite)
            .filter(|suite| !suite.is_tls13())
            .ok_or(TlsError::NoSharedCipher)?;
        let msg = self.next_expect(11)?;
        let chain = certificates12(&msg[4..])?;
        self.verify_chain(&chain)?;
        self.transcript.extend_from_slice(&msg);

        // A static-RSA suite has no ServerKeyExchange: the leaf's own key carries the pre-master.
        let share = if suite.is_rsa() {
            None
        } else {
            let msg = self.next_expect(12)?;
            let (group, peer, signed_at) = server_key_exchange(&msg[4..])?;
            let mut signed = Vec::with_capacity(64 + signed_at);
            signed.extend_from_slice(&self.client_random);
            signed.extend_from_slice(&sh.random);
            signed.extend_from_slice(&msg[4..4 + signed_at]);
            self.verify_certificate_verify(&msg[4 + signed_at..], &signed, false)?;
            self.transcript.extend_from_slice(&msg);
            Some((group, peer))
        };
        let mut msg = self.next_handshake()?;
        let asked = msg[0] == 13;
        if asked {
            self.transcript.extend_from_slice(&msg);
            msg = self.next_handshake()?;
        }
        if msg[0] != 14 {
            return Err(unexpected(msg[0]));
        }
        self.transcript.extend_from_slice(&msg);
        if asked {
            // The empty certificate a client-auth request draws hashes after the flight's ServerHelloDone.
            let empty = certificate_empty();
            self.send_plain(HANDSHAKE, &empty, [0x03, 0x03])?;
            self.transcript.extend_from_slice(&empty);
        }

        let (pre_master, exchange) = match share {
            Some((group, peer)) => {
                let (public, shared) = match hello.share_public(group) {
                    Some(public) => (public.to_vec(), hello.agree(group, &peer)?),
                    None => hello.ephemeral(group, &peer)?,
                };
                let mut exchange = Vec::with_capacity(1 + public.len());
                exchange.push(public.len() as u8);
                exchange.extend_from_slice(&public);
                (shared, exchange)
            }
            None => rsa_exchange(
                self.leaf
                    .as_ref()
                    .ok_or_else(|| TlsError::BadCertificate("no leaf to key".to_owned()))?,
            )?,
        };
        let cke = message(16, &exchange);
        self.send_plain(HANDSHAKE, &cke, [0x03, 0x03])?;
        self.transcript.extend_from_slice(&cke);

        // RFC 7627 hashes the ClientKeyExchange into the EMS transcript, as Go does after writing it.
        let hash = suite.hash();
        let session_hash = sh.ems.then(|| hash.hash(&self.transcript));
        let (master, directions) = super::tls12::keys(
            suite,
            &pre_master,
            &self.client_random,
            &sh.random,
            session_hash.as_deref(),
        );

        self.client12 = Some(directions.client);
        self.server12 = Some(directions.server);
        self.send_ccs()?;
        self.write_key = self.client12.take();

        let verify = super::tls12::finished(suite, &master, b"client finished", &self.transcript);
        let finished = message(20, &verify);
        self.send_encrypted(HANDSHAKE, &finished)?;
        self.transcript.extend_from_slice(&finished);

        let mut msg = self.next_handshake()?;
        while msg[0] == 4 {
            self.transcript.extend_from_slice(&msg);
            msg = self.next_handshake()?;
        }
        if msg[0] != 20 {
            return Err(unexpected(msg[0]));
        }
        let expected = super::tls12::finished(suite, &master, b"server finished", &self.transcript);
        if msg[4..] != expected[..] {
            return Err(TlsError::Other("server Finished did not verify".to_owned()));
        }
        self.transcript.extend_from_slice(&msg);
        Ok(())
    }

    fn next_expect(&mut self, kind: u8) -> Result<Vec<u8>, TlsError> {
        let msg = self.next_handshake()?;
        if msg[0] != kind {
            return Err(unexpected(msg[0]));
        }
        Ok(msg)
    }

    fn send_ccs(&mut self) -> Result<(), TlsError> {
        if self.ccs_sent {
            return Ok(());
        }
        self.ccs_sent = true;
        self.send_plain(CCS, &[1], [0x03, 0x03])
    }

    fn send_plain(&mut self, kind: u8, body: &[u8], version: [u8; 2]) -> Result<(), TlsError> {
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(kind);
        out.extend_from_slice(&version);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        self.io.write_all(&out)?;
        Ok(())
    }

    fn send_encrypted(&mut self, kind: u8, body: &[u8]) -> Result<(), TlsError> {
        let mut out = Vec::with_capacity(5 + body.len() + 16);
        let tls12 = self.version == Some(Version::Tls12);
        let keys = self
            .write_key
            .as_mut()
            .ok_or_else(|| TlsError::Other("no write keys".to_owned()))?;
        if tls12 {
            record::seal12(keys, kind, body, &mut out)?;
        } else {
            record::seal13(keys, kind, body, &mut out)?;
        }
        self.io.write_all(&out)?;
        Ok(())
    }

    /// Reads one record's body into `plain`, decrypts it in place, and leaves its content pending there.
    fn read_record(&mut self) -> Result<u8, TlsError> {
        let mut header = [0u8; 5];
        exact(&mut self.io, &mut header)?;
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len > MAX_RECORD {
            return Err(TlsError::Other(
                "record exceeds the maximum length".to_owned(),
            ));
        }
        self.plain_at = 0;
        self.plain_end = 0;
        if self.plain.len() < len {
            self.plain.resize(len, 0);
        }
        exact(&mut self.io, &mut self.plain[..len])?;
        let Self {
            read_key,
            server12,
            version,
            plain,
            ..
        } = self;
        let (kind, start, bytes) =
            decrypt(read_key, server12, *version, header, &mut plain[..len])?;
        self.plain_at = start;
        self.plain_end = start + bytes;
        Ok(kind)
    }

    /// The pending plaintext, which every record and carrier chunk leaves in `plain`.
    fn pending(&self) -> &[u8] {
        &self.plain[self.plain_at..self.plain_end]
    }

    fn take_pending(&mut self) {
        self.plain_at = 0;
        self.plain_end = 0;
    }

    /// Copies pending plaintext into `buf` and moves the cursor, reclaiming the buffer when drained.
    fn deliver(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.plain_end - self.plain_at).min(buf.len());
        buf[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain_at += n;
        if self.plain_at == self.plain_end {
            self.take_pending();
        }
        n
    }

    fn next_handshake(&mut self) -> Result<Vec<u8>, TlsError> {
        loop {
            if self.hs.len() >= 4 {
                let len = u32::from_be_bytes([0, self.hs[1], self.hs[2], self.hs[3]]) as usize;
                if len > MAX_HANDSHAKE {
                    return Err(TlsError::Other("handshake message is too long".to_owned()));
                }
                if self.hs.len() >= 4 + len {
                    return Ok(self.hs.drain(..4 + len).collect());
                }
            }
            match self.read_record()? {
                HANDSHAKE => {
                    let (at, end) = (self.plain_at, self.plain_end);
                    self.hs.extend_from_slice(&self.plain[at..end]);
                    self.take_pending();
                }
                CCS => {}
                ALERT => return Err(alert(self.pending())),
                other => return Err(unexpected(other)),
            }
        }
    }

    fn verify_chain(&mut self, chain: &[&[u8]]) -> Result<(), TlsError> {
        let leaf = *chain
            .first()
            .ok_or_else(|| TlsError::BadCertificate("empty certificate chain".to_owned()))?;
        let intermediates: Vec<CertificateDer<'_>> = chain[1..]
            .iter()
            .copied()
            .map(CertificateDer::from)
            .collect();
        self.verifier
            .verify_server_cert(
                &CertificateDer::from(leaf),
                &intermediates,
                &self.server_name,
                &[],
                UnixTime::now(),
            )
            .map_err(|error| TlsError::BadCertificate(error.to_string()))?;
        self.leaf = Some(leaf.to_vec());
        Ok(())
    }

    /// Checks a `CertificateVerify` (TLS 1.3) or `ServerKeyExchange` signature (TLS 1.2)
    /// against the leaf's key, over bytes the caller names.
    fn verify_certificate_verify(
        &self,
        body: &[u8],
        signed: &[u8],
        tls13: bool,
    ) -> Result<(), TlsError> {
        let mut r = Reader::new(body);
        let scheme = r.u16()?;
        let signature = r.vec16()?;
        if tls13 && matches!(scheme, 0x0201 | 0x0401 | 0x0501 | 0x0601) {
            return Err(TlsError::BadCertificate(
                "TLS 1.3 forbids RSA PKCS#1 signatures".to_owned(),
            ));
        }
        let supported = self.verifier.supported_verify_schemes();
        if !supported
            .iter()
            .any(|offered| u16::from(*offered) == scheme)
        {
            return Err(TlsError::BadCertificate(format!(
                "server used an unoffered signature scheme {scheme:#06x}"
            )));
        }
        let leaf = self
            .leaf
            .as_deref()
            .ok_or_else(|| TlsError::BadCertificate("no leaf certificate".to_owned()))?;
        let content = if tls13 {
            let mut content = vec![0x20u8; 64];
            content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
            content.push(0);
            content.extend_from_slice(&self.suite.map_or(Hash::Sha256, Suite::hash).hash(signed));
            content
        } else {
            signed.to_vec()
        };
        verify_signature(leaf, scheme, &content, signature)
    }

    fn pump(&mut self) -> Result<(), TlsError> {
        loop {
            if self.plain_at < self.plain_end {
                return Ok(());
            }
            let kind = match self.read_record() {
                Ok(kind) => kind,
                Err(TlsError::Closed) => {
                    self.eof = true;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            match kind {
                APPLICATION => return Ok(()),
                HANDSHAKE => {
                    let (at, end) = (self.plain_at, self.plain_end);
                    self.hs.extend_from_slice(&self.plain[at..end]);
                    self.take_pending();
                    self.post_handshake()?;
                }
                ALERT => {
                    let error = alert(self.pending());
                    self.take_pending();
                    if error == TlsError::Closed {
                        self.eof = true;
                        return Ok(());
                    }
                    return Err(error);
                }
                CCS => self.take_pending(),
                other => return Err(unexpected(other)),
            }
        }
    }

    fn post_handshake(&mut self) -> Result<(), TlsError> {
        loop {
            if self.hs.len() < 4 {
                return Ok(());
            }
            let len = u32::from_be_bytes([0, self.hs[1], self.hs[2], self.hs[3]]) as usize;
            if len > MAX_HANDSHAKE {
                return Err(TlsError::Other("handshake message is too long".to_owned()));
            }
            if self.hs.len() < 4 + len {
                return Ok(());
            }
            let (kind, request) = (self.hs[0], self.hs.get(4).copied() == Some(1));
            // A ticket's body is dropped unread; a KeyUpdate reads one byte. Neither needs a copy.
            self.hs.drain(..4 + len);
            match kind {
                4 => {}
                24 => self.key_update(request)?,
                other => return Err(unexpected(other)),
            }
        }
    }

    fn key_update(&mut self, request: bool) -> Result<(), TlsError> {
        let Self {
            read_key,
            write_key,
            reply,
            ..
        } = self;
        read_key
            .as_mut()
            .ok_or_else(|| TlsError::Other("key update before keys".to_owned()))?
            .update();
        if request {
            let update = message(24, &[0]);
            let write = write_key
                .as_mut()
                .ok_or_else(|| TlsError::Other("key update before keys".to_owned()))?;
            write.update();
            record::seal13(write, HANDSHAKE, &update, reply)?;
        }
        Ok(())
    }

    /// Decrypts every whole record straight from the caller's chunk into the caller's window, so a
    /// roomy window costs one body copy and no staged ciphertext, and returns the bytes delivered.
    fn process_direct(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut at = 0usize;
        let mut filled = 0usize;
        loop {
            if ciphertext.len() - at < 5 {
                break;
            }
            let header: [u8; 5] = ciphertext[at..at + 5]
                .try_into()
                .expect("five-byte record header");
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if len > MAX_RECORD {
                return Err(TlsError::Other(
                    "record exceeds the maximum length".to_owned(),
                ));
            }
            if ciphertext.len() - at - 5 < len {
                break;
            }
            at += 5 + len;
            let body = &ciphertext[at - len..at];
            let (kind, bytes) = if header[0] == CCS {
                if self.version == Some(Version::Tls12) {
                    if let Some(keys) = self.server12.take() {
                        self.read_key = Some(keys);
                    }
                }
                (CCS, 0)
            } else {
                match self.read_key.as_mut() {
                    None => {
                        buf[filled..filled + len].copy_from_slice(body);
                        (header[0], len)
                    }
                    Some(keys) if self.version == Some(Version::Tls13) => {
                        if header[0] == ALERT {
                            buf[filled..filled + len].copy_from_slice(body);
                            (ALERT, len)
                        } else if header[0] != APPLICATION {
                            return Err(unexpected(header[0]));
                        } else {
                            record::open13_into(keys, header, body, &mut buf[filled..])?
                        }
                    }
                    Some(keys) => (
                        header[0],
                        record::open12_into(keys, header[0], body, &mut buf[filled..])?,
                    ),
                }
            };
            match kind {
                APPLICATION => filled += bytes,
                HANDSHAKE => {
                    self.hs.extend_from_slice(&buf[filled..filled + bytes]);
                    self.post_handshake()?;
                }
                ALERT => {
                    let error = alert(&buf[filled..filled + bytes]);
                    if error == TlsError::Closed {
                        self.eof = true;
                    } else {
                        return Err(error);
                    }
                }
                CCS => {}
                other => return Err(unexpected(other)),
            }
        }
        if at < ciphertext.len() {
            self.inbuf.extend_from_slice(&ciphertext[at..]);
        }
        Ok(filled)
    }

    /// Decrypts every whole record in `inbuf`, copying application data straight into `buf` and
    /// staging only what does not fit, and returns the bytes delivered.
    fn process_inbuf(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut filled = 0usize;
        loop {
            let at = self.in_at;
            if self.inbuf.len() - at < 5 {
                break;
            }
            let header: [u8; 5] = self.inbuf[at..at + 5]
                .try_into()
                .expect("five-byte record header");
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if len > MAX_RECORD {
                return Err(TlsError::Other(
                    "record exceeds the maximum length".to_owned(),
                ));
            }
            if self.inbuf.len() - at - 5 < len {
                break;
            }
            self.in_at = at + 5 + len;
            let Self {
                inbuf,
                read_key,
                server12,
                version,
                ..
            } = self;
            let (kind, start, bytes) = decrypt(
                read_key,
                server12,
                *version,
                header,
                &mut inbuf[at + 5..at + 5 + len],
            )?;
            let plain = &inbuf[at + 5 + start..at + 5 + start + bytes];
            match kind {
                APPLICATION => {
                    let room = buf.len() - filled;
                    let take = plain.len().min(room);
                    buf[filled..filled + take].copy_from_slice(&plain[..take]);
                    filled += take;
                    if take < plain.len() {
                        if self.plain_at == self.plain_end {
                            self.plain_at = 0;
                            self.plain_end = 0;
                        }
                        let begin = self.plain_end;
                        let end = begin + (plain.len() - take);
                        if self.plain.len() < end {
                            self.plain.resize(end, 0);
                        }
                        self.plain[begin..end].copy_from_slice(&plain[take..]);
                        self.plain_end = end;
                    }
                }
                HANDSHAKE => {
                    self.hs.extend_from_slice(plain);
                    self.post_handshake()?;
                }
                ALERT => {
                    if alert(plain) == TlsError::Closed {
                        self.eof = true;
                    } else {
                        return Err(alert(plain));
                    }
                }
                CCS => {}
                other => return Err(unexpected(other)),
            }
        }
        if self.in_at == self.inbuf.len() {
            self.inbuf.clear();
            self.in_at = 0;
        } else if self.in_at > 0 {
            self.inbuf.drain(..self.in_at);
            self.in_at = 0;
        }
        Ok(filled)
    }

    fn seal_parts(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), TlsError> {
        if !self.reply.is_empty() {
            out.append(&mut self.reply);
        }
        if !parts.is_empty()
            && parts.iter().all(|part| !part.is_empty())
            && parts.iter().map(|part| part.len()).sum::<usize>() <= MAX_PLAINTEXT
        {
            return self.seal_chunk(parts, out);
        }
        let mut chunk: Vec<&[u8]> = Vec::new();
        let mut held = 0usize;
        for part in parts {
            let mut rest = *part;
            while !rest.is_empty() {
                let room = MAX_PLAINTEXT - held;
                if rest.len() <= room {
                    chunk.push(rest);
                    held += rest.len();
                    if held == MAX_PLAINTEXT {
                        self.seal_chunk(&chunk, out)?;
                        chunk.clear();
                        held = 0;
                    }
                    break;
                }
                let (lead, tail) = rest.split_at(room);
                chunk.push(lead);
                self.seal_chunk(&chunk, out)?;
                chunk.clear();
                held = 0;
                rest = tail;
            }
        }
        if !chunk.is_empty() {
            self.seal_chunk(&chunk, out)?;
        }
        Ok(())
    }

    fn seal_chunk(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), TlsError> {
        let keys = self
            .write_key
            .as_mut()
            .ok_or_else(|| TlsError::Other("no write keys".to_owned()))?;
        match self.version {
            Some(Version::Tls12) => record::seal12_parts(keys, APPLICATION, parts, out),
            _ => record::seal13_parts(keys, APPLICATION, parts, out),
        }
    }

    fn flush_reply(&mut self) -> std::io::Result<()> {
        if !self.reply.is_empty() {
            self.io.write_all(&self.reply)?;
            self.reply.clear();
        }
        Ok(())
    }
}

impl<S: Stream> TlsProvider for Session<S> {
    fn name() -> &'static str {
        "utls"
    }

    fn suites(&self) -> Vec<String> {
        self.profile
            .ciphers
            .iter()
            .map(|id| format!("{id:#06x}"))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.run()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        self.leaf.as_deref()
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        if !self.done {
            return Err(std::io::Error::other("shaped: handshake incomplete"));
        }
        if self.plain_at < self.plain_end {
            return Ok((self.deliver(buf), 0));
        }
        if ciphertext.is_empty() {
            return Ok((0, 0));
        }
        if self.inbuf.is_empty() && buf.len() >= ciphertext.len() {
            let filled = self
                .process_direct(ciphertext, buf)
                .map_err(std::io::Error::other)?;
            return Ok((filled, ciphertext.len()));
        }
        self.inbuf.extend_from_slice(ciphertext);
        let filled = self.process_inbuf(buf).map_err(std::io::Error::other)?;
        Ok((filled, ciphertext.len()))
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        if !self.done {
            return Err(std::io::Error::other("shaped: handshake incomplete"));
        }
        self.seal_parts(&[plaintext], out)
            .map_err(std::io::Error::other)?;
        Ok(plaintext.len())
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        if !self.done {
            return Err(std::io::Error::other("shaped: handshake incomplete"));
        }
        self.seal_parts(parts, out).map_err(std::io::Error::other)
    }
}

impl<S: Stream + RecordAlignment> RecordAlignment for Session<S> {
    fn engage_record_alignment(&mut self) {
        self.io.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.io.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        if !self.done {
            self.run().map_err(std::io::Error::other)?;
        }
        self.flush_reply()?;
        let mut out = Vec::new();
        self.seal_parts(parts, &mut out)
            .map_err(std::io::Error::other)?;
        self.io.write_all(&out)
    }
}

impl<S: Stream> Read for Session<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.done {
            self.run().map_err(std::io::Error::other)?;
        }
        self.flush_reply()?;
        if self.plain_at >= self.plain_end {
            self.pump().map_err(std::io::Error::other)?;
        }
        Ok(self.deliver(buf))
    }
}

impl<S: Stream> Write for Session<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.done {
            self.run().map_err(std::io::Error::other)?;
        }
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        let sent = self
            .seal_parts(&[buf], &mut out)
            .map_err(std::io::Error::other)
            .and_then(|()| self.io.write_all(&out));
        self.out = out;
        sent?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

/// A server hello, both versions' fields in one parse.
struct ServerHello {
    random: [u8; 32],
    suite: u16,
    version: u16,
    share: Option<(u16, Vec<u8>)>,
    hrr_group: Option<u16>,
    cookie: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    ems: bool,
    hrr: bool,
}

impl ServerHello {
    fn parse(body: &[u8]) -> Result<Self, TlsError> {
        let mut r = Reader::new(body);
        let legacy = r.u16()?;
        let random: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| TlsError::Other("short server random".to_owned()))?;
        let _session_id = r.vec8()?;
        let suite = r.u16()?;
        let _compression = r.u8()?;
        let hrr = random == HRR_RANDOM;
        let mut out = Self {
            random,
            suite,
            version: legacy,
            share: None,
            hrr_group: None,
            cookie: None,
            alpn: None,
            ems: false,
            hrr,
        };
        if r.done() {
            return Ok(out);
        }
        let extensions = r.vec16()?;
        let mut ext = Reader::new(extensions);
        while !ext.done() {
            let kind = ext.u16()?;
            let value = ext.vec16()?;
            match kind {
                0x002b => {
                    let mut v = Reader::new(value);
                    out.version = v.u16()?;
                }
                0x0033 => {
                    let mut v = Reader::new(value);
                    if hrr {
                        out.hrr_group = Some(v.u16()?);
                    } else {
                        let group = v.u16()?;
                        out.share = Some((group, v.vec16()?.to_vec()));
                    }
                }
                0x002c => {
                    let mut v = Reader::new(value);
                    out.cookie = Some(v.vec16()?.to_vec());
                }
                0x0010 => {
                    let mut v = Reader::new(value);
                    let list = v.vec16()?;
                    let mut first = Reader::new(list);
                    out.alpn = Some(first.vec8()?.to_vec());
                }
                0x0017 => out.ems = true,
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The ALPN pick an encrypted extensions message carries, if any.
fn encrypted_extensions(body: &[u8]) -> Result<Option<Vec<u8>>, TlsError> {
    let mut r = Reader::new(body);
    let extensions = r.vec16()?;
    let mut ext = Reader::new(extensions);
    while !ext.done() {
        let kind = ext.u16()?;
        let value = ext.vec16()?;
        if kind == 0x0010 {
            let mut v = Reader::new(value);
            let mut first = Reader::new(v.vec16()?);
            return Ok(Some(first.vec8()?.to_vec()));
        }
    }
    Ok(None)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| TlsError::Other("truncated handshake".to_owned()))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<usize, TlsError> {
        let bytes = self.take(3)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize)
    }

    fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}

/// The chain a TLS 1.3 `Certificate` carries, each entry borrowed from `body`; TLS 1.3 wraps every entry
/// in its own extensions, which the walk reads past.
fn certificates13(body: &[u8]) -> Result<Vec<&[u8]>, TlsError> {
    let mut r = Reader::new(body);
    let context = r.u8()?;
    r.take(usize::from(context))?;
    let list = r.vec24()?;
    let mut list = Reader::new(list);
    let mut chain = Vec::new();
    while !list.done() {
        chain.push(list.vec24()?);
        let _extensions = list.vec16()?;
    }
    if chain.is_empty() {
        return Err(TlsError::BadCertificate(
            "server sent no certificate".to_owned(),
        ));
    }
    Ok(chain)
}

/// The chain a TLS 1.2 `Certificate` carries, borrowed the same way; TLS 1.2 has no per-entry extensions.
fn certificates12(body: &[u8]) -> Result<Vec<&[u8]>, TlsError> {
    let mut r = Reader::new(body);
    let list = r.vec24()?;
    let mut list = Reader::new(list);
    let mut chain = Vec::new();
    while !list.done() {
        chain.push(list.vec24()?);
    }
    if chain.is_empty() {
        return Err(TlsError::BadCertificate(
            "server sent no certificate".to_owned(),
        ));
    }
    Ok(chain)
}

fn server_key_exchange(body: &[u8]) -> Result<(u16, Vec<u8>, usize), TlsError> {
    let mut r = Reader::new(body);
    let curve_type = r.u8()?;
    if curve_type != 3 {
        return Err(TlsError::NoSharedCipher);
    }
    let group = r.u16()?;
    let peer = r.vec8()?.to_vec();
    let signed_at = r.at;
    Ok((group, peer, signed_at))
}

fn certificate_empty() -> Vec<u8> {
    message(11, &[0, 0, 0])
}

/// The `certificate_request_context` of a TLS 1.3 `CertificateRequest`, the bytes its answer echoes.
fn request_context(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    let truncated = || TlsError::Other("truncated CertificateRequest".to_owned());
    let (&len, rest) = body.split_first().ok_or_else(truncated)?;
    let len = usize::from(len);
    if rest.len() < len {
        return Err(truncated());
    }
    Ok(rest[..len].to_vec())
}

/// The TLS 1.3 answer to a `CertificateRequest` when `TlsConfig` carries no client certificate: the
/// request's own context ahead of a zero-length chain, so the server reads it as anonymous.
fn certificate_answer13(context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len());
    out.push(11);
    out.extend_from_slice(&((4 + context.len()) as u32).to_be_bytes()[1..]);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out.extend_from_slice(&[0, 0, 0]);
    out
}

/// Random bytes, shaped as the reference's padding reader asks for: the caller re-rolls what it rejects.
fn fill(buf: &mut [u8]) -> Result<(), TlsError> {
    getrandom::fill(buf).map_err(|e| TlsError::Other(format!("random: {e}")))
}

/// The static-RSA pre-master and the exchange that carries it: no `ServerKeyExchange` sends a share,
/// so the client draws the secret and encrypts it to the leaf's own key.
fn rsa_exchange(leaf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let key = subject_public_key(leaf)?;
    if key.algorithm != OID_RSA {
        return Err(TlsError::BadCertificate(
            "a static-RSA suite without an RSA leaf".to_owned(),
        ));
    }
    let (modulus, exponent) = super::rsa::public_key(key.key)
        .ok_or_else(|| TlsError::BadCertificate("malformed RSA key".to_owned()))?;
    // The pre-master repeats the hello's own version in its first two bytes, and the rest is random.
    let mut secret = vec![0u8; 48];
    secret[..2].copy_from_slice(&TLS12.to_be_bytes());
    fill(&mut secret[2..])?;
    let mut cipher = Vec::with_capacity(modulus.len());
    super::rsa::encrypt(modulus, exponent, &secret, &mut fill, &mut cipher)?;
    let mut exchange = Vec::with_capacity(2 + cipher.len());
    exchange.extend_from_slice(&(cipher.len() as u16).to_be_bytes());
    exchange.extend_from_slice(&cipher);
    Ok((secret, exchange))
}

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn unexpected(kind: u8) -> TlsError {
    TlsError::Other(format!("unexpected handshake message {kind}"))
}

/// Opens one record in place and returns its content type with the plaintext range inside `body`.
fn decrypt(
    read_key: &mut Option<Direction>,
    server12: &mut Option<Direction>,
    version: Option<Version>,
    header: [u8; 5],
    body: &mut [u8],
) -> Result<(u8, usize, usize), TlsError> {
    if header[0] == CCS {
        if version == Some(Version::Tls12) {
            if let Some(keys) = server12.take() {
                *read_key = Some(keys);
            }
        }
        return Ok((CCS, 0, 0));
    }
    let Some(keys) = read_key.as_mut() else {
        return Ok((header[0], 0, body.len()));
    };
    if version != Some(Version::Tls13) {
        return record::open12(keys, header[0], body)
            .map(|(start, bytes)| (header[0], start, bytes));
    }
    if header[0] == ALERT {
        return Ok((ALERT, 0, body.len()));
    }
    if header[0] != APPLICATION {
        return Err(unexpected(header[0]));
    }
    record::open13(keys, header, body).map(|(kind, bytes)| (kind, 0, bytes))
}

/// Fills `buf` from the transport, but a poll-quantum expiry is the caller's timeout and
/// not an answer: a handshake the socket does not feed must fail the dial, not spin on it.
fn exact<S: Read>(io: &mut S, mut buf: &mut [u8]) -> Result<(), TlsError> {
    while !buf.is_empty() {
        match io.read(buf) {
            Ok(0) => return Err(TlsError::Closed),
            Ok(n) => buf = &mut buf[n..],
            Err(error) if TlsError::is_timeout(&error) => return Err(TlsError::Timeout),
            Err(error) => return Err(TlsError::from(error)),
        }
    }
    Ok(())
}

fn alert(body: &[u8]) -> TlsError {
    match body.get(1) {
        Some(0) => TlsError::Closed,
        Some(description) => TlsError::Other(format!("peer alert {description}")),
        None => TlsError::Other("truncated alert".to_owned()),
    }
}

/// The leaf's `SubjectPublicKeyInfo`, reduced to what the signature schemes need.
struct PublicKey<'a> {
    algorithm: &'a [u8],
    key: &'a [u8],
}

fn subject_public_key(der: &[u8]) -> Result<PublicKey<'_>, TlsError> {
    let bad = || TlsError::BadCertificate("malformed certificate key".to_owned());
    let (tag, certificate, _) = tlv(der).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag, mut tbs, _) = tlv(certificate).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    if tbs.first() == Some(&0xa0) {
        tbs = tlv(tbs).ok_or_else(bad)?.2;
    }
    // serial, signature, issuer, validity, subject — the fields ahead of the key.
    for wanted in [0x02, 0x30, 0x30, 0x30, 0x30] {
        let (tag, _, rest) = tlv(tbs).ok_or_else(bad)?;
        if tag != wanted {
            return Err(bad());
        }
        tbs = rest;
    }
    let (tag, spki, _) = tlv(tbs).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag, algorithm, rest) = tlv(spki).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag, oid, _) = tlv(algorithm).ok_or_else(bad)?;
    if tag != 0x06 {
        return Err(bad());
    }
    let (tag, bits, _) = tlv(rest).ok_or_else(bad)?;
    if tag != 0x03 || bits.first() != Some(&0) {
        return Err(bad());
    }
    Ok(PublicKey {
        algorithm: oid,
        key: &bits[1..],
    })
}

pub(super) fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 3 {
            return None;
        }
        let mut len = 0usize;
        for byte in input.get(2..2 + count)? {
            len = (len << 8) | usize::from(*byte);
        }
        (len, 2 + count)
    };
    let value = input.get(header..header + len)?;
    Some((tag, value, &input[header + len..]))
}

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

fn verify_signature(
    leaf: &[u8],
    scheme: u16,
    content: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let key = subject_public_key(leaf)?;
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        0x0403 if key.algorithm == OID_EC => &ring::signature::ECDSA_P256_SHA256_ASN1,
        0x0503 if key.algorithm == OID_EC => &ring::signature::ECDSA_P384_SHA384_ASN1,
        0x0807 if key.algorithm == OID_ED25519 => &ring::signature::ED25519,
        0x0201 if key.algorithm == OID_RSA => {
            &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
        }
        0x0401 if key.algorithm == OID_RSA => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        0x0501 if key.algorithm == OID_RSA => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
        0x0601 if key.algorithm == OID_RSA => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        0x0804 if key.algorithm == OID_RSA => &ring::signature::RSA_PSS_2048_8192_SHA256,
        0x0805 if key.algorithm == OID_RSA => &ring::signature::RSA_PSS_2048_8192_SHA384,
        0x0806 if key.algorithm == OID_RSA => &ring::signature::RSA_PSS_2048_8192_SHA512,
        other => {
            return Err(TlsError::BadCertificate(format!(
                "unsupported signature scheme {other:#06x}"
            )))
        }
    };
    ring::signature::UnparsedPublicKey::new(algorithm, key.key)
        .verify(content, signature)
        .map_err(|_| TlsError::BadCertificate("handshake signature did not verify".to_owned()))
}

impl Reader<'_> {
    /// A three-byte length prefix, as a certificate list carries.
    fn vec24(&mut self) -> Result<&[u8], TlsError> {
        let len = self.u24()?;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::shaped::profiles;
    use std::io::{Read, Write};

    struct Sink;

    impl Read for Sink {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn session(version: Version, suite: Suite, read: Direction, write: Direction) -> Session<Sink> {
        let cfg = TlsConfig {
            insecure: true,
            ..TlsConfig::default()
        };
        Session {
            io: Sink,
            verifier: crate::tls::rustls_backend::verifier(&cfg).expect("verifier"),
            server_name: ServerName::try_from("tls.test".to_owned()).expect("name"),
            profile: profiles::profile("chrome").expect("chrome profile"),
            hello: None,
            client_random: [0; 32],
            transcript: Vec::new(),
            version: Some(version),
            suite: Some(suite),
            read_key: Some(read),
            write_key: Some(write),
            server12: None,
            client12: None,
            alpn: None,
            leaf: None,
            done: true,
            eof: false,
            ccs_sent: false,
            hs: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            plain_end: 0,
            inbuf: Vec::new(),
            in_at: 0,
            reply: Vec::new(),
            out: Vec::new(),
        }
    }

    #[test]
    fn a_roomy_tls13_chunk_lands_record_by_record_in_the_callers_window() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut session = session(
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"one", &mut wire).expect("seals");
        record::seal13(&mut sender, APPLICATION, b"two", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (6, wire.len()));
        assert_eq!(&window[..6], b"onetwo");
        assert_eq!(session.plain_buffer(), [], "a roomy window stages nothing");
    }

    #[test]
    fn a_tls13_record_split_across_chunks_is_staged_and_then_lands() {
        let suite = Suite::ChaCha20Sha256;
        let secret = [11u8; 32];
        let mut session = session(
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"three", &mut wire).expect("seals");
        let cut = wire.len() - 3;
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire[..cut], &mut window).expect("opens");
        assert_eq!((got, consumed), (0, cut));
        let (got, consumed) = session.open(&wire[cut..], &mut window).expect("opens");
        assert_eq!((got, consumed), (5, wire.len() - cut));
        assert_eq!(&window[..5], b"three");
        assert_eq!(session.plain_buffer(), []);
    }

    #[test]
    fn a_roomy_tls12_gcm_chunk_opens_behind_its_explicit_nonce() {
        let suite = Suite::EcdheAes128GcmSha256;
        let key = [3u8; 16];
        let iv = [5u8; 4];
        let mut session = session(
            Version::Tls12,
            suite,
            Direction::tls12(suite, &key, &[], &iv),
            Direction::tls12(suite, &key, &[], &iv),
        );
        let mut sender = Direction::tls12(suite, &key, &[], &iv);
        let mut wire = Vec::new();
        record::seal12(&mut sender, APPLICATION, b"one", &mut wire).expect("seals");
        record::seal12(&mut sender, APPLICATION, b"two", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (6, wire.len()));
        assert_eq!(&window[..6], b"onetwo");
        assert_eq!(session.plain_buffer(), []);
    }

    #[test]
    fn a_roomy_tls12_chacha_chunk_opens_without_an_explicit_nonce() {
        let suite = Suite::EcdheChaCha20Sha256;
        let key = [3u8; 32];
        let iv = [5u8; 12];
        let mut session = session(
            Version::Tls12,
            suite,
            Direction::tls12(suite, &key, &[], &iv),
            Direction::tls12(suite, &key, &[], &iv),
        );
        let mut sender = Direction::tls12(suite, &key, &[], &iv);
        let mut wire = Vec::new();
        record::seal12(&mut sender, APPLICATION, b"four", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (4, wire.len()));
        assert_eq!(&window[..4], b"four");
        assert_eq!(session.plain_buffer(), []);
    }

    #[test]
    fn a_roomy_tls12_cbc_chunk_opens_past_its_iv_and_mac() {
        let suite = Suite::EcdheAes128CbcSha;
        let (key, mac_key, iv) = ([3u8; 16], [4u8; 20], [0u8; 16]);
        let mut session = session(
            Version::Tls12,
            suite,
            Direction::tls12(suite, &key, &mac_key, &iv),
            Direction::tls12(suite, &key, &mac_key, &iv),
        );
        let mut sender = Direction::tls12(suite, &key, &mac_key, &iv);
        let mut wire = Vec::new();
        record::seal12(&mut sender, APPLICATION, b"one", &mut wire).expect("seals");
        record::seal12(&mut sender, APPLICATION, b"twoo", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (7, wire.len()));
        assert_eq!(&window[..7], b"onetwoo");
        assert_eq!(session.plain_buffer(), []);
    }

    /// A handshake flight past the handshake is walked where it lies and takes no heap: a ticket's
    /// body is dropped unread and a `KeyUpdate` reads its one byte, so nothing is copied out to be
    /// looked at.
    #[test]
    fn a_post_handshake_flight_is_read_where_it_lies() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut session = session(
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        session.hs = std::hint::black_box(message(4, &[7u8; 40]));
        let ((), counts) =
            crate::alloc_count::measure(|| session.post_handshake().expect("drops the ticket"));
        assert_eq!(session.hs.len(), 0, "the ticket is consumed");
        assert_eq!(session.reply.len(), 0, "a ticket asks for no answer");
        assert_eq!(
            counts.allocs, 0,
            "the flight is read where it lies: {counts:?}"
        );
    }

    /// A `Certificate`'s chain is walked where it lies: every entry the parse returns is the record's own
    /// byte range, so neither version copies a DER out to look at it.
    #[test]
    fn a_certificate_chain_is_read_where_the_record_lies() {
        let leaf = [1u8, 2, 3, 4, 5];
        let issuer = [6u8, 7, 8, 9, 10, 11, 12, 13, 14];
        let mut body = vec![0];
        body.extend_from_slice(&[0, 0, 24]);
        body.extend_from_slice(&[0, 0, 5]);
        body.extend_from_slice(&leaf);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&[0, 0, 9]);
        body.extend_from_slice(&issuer);
        body.extend_from_slice(&[0, 0]);
        let chain = certificates13(&body).expect("reads the chain");
        assert_eq!(chain.len(), 2, "both entries are there");
        assert_eq!(chain[0], leaf.as_slice(), "the leaf is first");
        assert_eq!(
            chain[0].as_ptr(),
            body[7..].as_ptr(),
            "the leaf is the record's own range"
        );
        assert_eq!(
            chain[1].as_ptr(),
            body[17..].as_ptr(),
            "the issuer is the record's own range"
        );

        let mut body12 = Vec::new();
        body12.extend_from_slice(&[0, 0, 20]);
        body12.extend_from_slice(&[0, 0, 5]);
        body12.extend_from_slice(&leaf);
        body12.extend_from_slice(&[0, 0, 9]);
        body12.extend_from_slice(&issuer);
        let chain = certificates12(&body12).expect("reads the chain");
        assert_eq!(chain[1], issuer.as_slice(), "1.2 needs no extensions");
        assert_eq!(
            chain[0].as_ptr(),
            body12[6..].as_ptr(),
            "1.2 reads in place too"
        );
        assert_eq!(
            chain[1].as_ptr(),
            body12[14..].as_ptr(),
            "and so does its issuer"
        );
    }
}
