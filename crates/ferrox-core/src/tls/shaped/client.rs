// The shaped client handshake: a browser hello out, both TLS versions' flights back under keys this module owns.
use super::hello::Hello;
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
    record: Vec<u8>,
    decoded: Vec<u8>,
    hs: Vec<u8>,
    plain: Vec<u8>,
    plain_at: usize,
    inbuf: Vec<u8>,
    in_at: usize,
    reply: Vec<u8>,
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
            record: Vec::new(),
            decoded: Vec::new(),
            hs: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            inbuf: Vec::new(),
            in_at: 0,
            reply: Vec::new(),
        })
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.io
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

        let msg = self.next_expect(11)?;
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

        let client_ap = kdf::derive(hash, &master, b"c ap traffic", &self.transcript);
        let server_ap = kdf::derive(hash, &master, b"s ap traffic", &self.transcript);
        self.read_key = Some(Direction::tls13(suite, &server_ap));

        let verify = kdf::verify_data(hash, &kdf::finished_key(hash, &client_hs), &self.transcript);
        let mut finished = Vec::with_capacity(4 + verify.len());
        finished.push(20);
        finished.extend_from_slice(&(verify.len() as u32).to_be_bytes()[1..]);
        finished.extend_from_slice(&verify);
        self.write_key = Some(Direction::tls13(suite, &client_hs));
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

        let msg = self.next_expect(12)?;
        let (group, peer, signed_at) = server_key_exchange(&msg[4..])?;
        let mut signed = Vec::with_capacity(64 + signed_at);
        signed.extend_from_slice(&self.client_random);
        signed.extend_from_slice(&sh.random);
        signed.extend_from_slice(&msg[4..4 + signed_at]);
        self.verify_certificate_verify(&msg[4 + signed_at..], &signed, false)?;
        self.transcript.extend_from_slice(&msg);
        let mut msg = self.next_handshake()?;
        if msg[0] == 13 {
            self.transcript.extend_from_slice(&msg);
            let empty = certificate_empty();
            self.send_plain(HANDSHAKE, &empty, [0x03, 0x03])?;
            self.transcript.extend_from_slice(&empty);
            msg = self.next_handshake()?;
        }
        if msg[0] != 14 {
            return Err(unexpected(msg[0]));
        }
        self.transcript.extend_from_slice(&msg);

        let public = hello
            .share_public(group)
            .ok_or(TlsError::NoSharedCipher)?
            .to_vec();
        let shared = hello.agree(group, &peer)?;

        let mut exchange = Vec::with_capacity(1 + public.len());
        exchange.push(public.len() as u8);
        exchange.extend_from_slice(&public);
        let cke = message(16, &exchange);
        self.send_plain(HANDSHAKE, &cke, [0x03, 0x03])?;
        self.transcript.extend_from_slice(&cke);

        // RFC 7627 hashes the ClientKeyExchange into the EMS transcript, as Go does after writing it.
        let hash = suite.hash();
        let session_hash = sh.ems.then(|| hash.hash(&self.transcript));
        let (master, block) = super::tls12::keys(
            suite,
            &shared,
            &self.client_random,
            &sh.random,
            session_hash.as_deref(),
        );

        self.client12 = Some(Direction::tls12(suite, &block.client_key, &block.client_iv));
        self.server12 = Some(Direction::tls12(suite, &block.server_key, &block.server_iv));
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

    /// Reads one record and leaves its plaintext in `decoded`, returning the content type.
    fn read_record(&mut self) -> Result<u8, TlsError> {
        let mut header = [0u8; 5];
        exact(&mut self.io, &mut header)?;
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len > MAX_RECORD {
            return Err(TlsError::Other(
                "record exceeds the maximum length".to_owned(),
            ));
        }
        self.record.clear();
        self.record.resize(len, 0);
        exact(&mut self.io, &mut self.record)?;
        let body = std::mem::take(&mut self.record);
        self.decrypt(header, body)
    }

    fn decrypt(&mut self, header: [u8; 5], body: Vec<u8>) -> Result<u8, TlsError> {
        self.decoded.clear();
        if header[0] == CCS {
            if self.version == Some(Version::Tls12) {
                if let Some(keys) = self.server12.take() {
                    self.read_key = Some(keys);
                }
            }
            return Ok(CCS);
        }
        let Self {
            read_key,
            decoded,
            version,
            ..
        } = self;
        if let Some(keys) = read_key.as_mut() {
            if *version == Some(Version::Tls13) {
                if header[0] == ALERT {
                    decoded.extend_from_slice(&body);
                    return Ok(ALERT);
                }
                if header[0] != APPLICATION {
                    return Err(unexpected(header[0]));
                }
                return record::open13(keys, header, body, decoded);
            }
            record::open12(keys, header[0], body, decoded)?;
            return Ok(header[0]);
        }
        decoded.extend_from_slice(&body);
        Ok(header[0])
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
                HANDSHAKE => self.hs.extend_from_slice(&self.decoded),
                CCS => {}
                ALERT => return Err(alert(&self.decoded)),
                other => return Err(unexpected(other)),
            }
        }
    }

    fn verify_chain(&mut self, chain: &[Vec<u8>]) -> Result<(), TlsError> {
        let leaf = chain
            .first()
            .ok_or_else(|| TlsError::BadCertificate("empty certificate chain".to_owned()))?;
        let intermediates: Vec<CertificateDer<'_>> = chain[1..]
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        self.verifier
            .verify_server_cert(
                &CertificateDer::from(leaf.as_slice()),
                &intermediates,
                &self.server_name,
                &[],
                UnixTime::now(),
            )
            .map_err(|error| TlsError::BadCertificate(error.to_string()))?;
        self.leaf = Some(leaf.clone());
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

    fn alert_error(&self) -> TlsError {
        alert(&self.decoded)
    }

    fn pump(&mut self) -> Result<(), TlsError> {
        loop {
            if self.plain_at < self.plain.len() {
                return Ok(());
            }
            self.plain.clear();
            self.plain_at = 0;
            let kind = match self.read_record() {
                Ok(kind) => kind,
                Err(TlsError::Closed) => {
                    self.eof = true;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            match kind {
                APPLICATION => {
                    std::mem::swap(&mut self.plain, &mut self.decoded);
                    return Ok(());
                }
                HANDSHAKE => self.post_handshake()?,
                ALERT => {
                    if self.alert_error() == TlsError::Closed {
                        self.eof = true;
                        return Ok(());
                    }
                    return Err(self.alert_error());
                }
                CCS => {}
                other => return Err(unexpected(other)),
            }
        }
    }

    fn post_handshake(&mut self) -> Result<(), TlsError> {
        self.hs.extend_from_slice(&self.decoded);
        self.decoded.clear();
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
            let msg: Vec<u8> = self.hs.drain(..4 + len).collect();
            match msg[0] {
                4 => {}
                24 => self.key_update(&msg[4..])?,
                other => return Err(unexpected(other)),
            }
        }
    }

    fn key_update(&mut self, body: &[u8]) -> Result<(), TlsError> {
        let request = body.first().copied().unwrap_or(0) == 1;
        let read = self
            .read_key
            .as_mut()
            .ok_or_else(|| TlsError::Other("key update before keys".to_owned()))?;
        read.update();
        if request {
            let update = message(24, &[0]);
            let mut out = Vec::new();
            let write = self
                .write_key
                .as_mut()
                .ok_or_else(|| TlsError::Other("key update before keys".to_owned()))?;
            write.update();
            record::seal13(write, HANDSHAKE, &update, &mut out)?;
            self.reply.extend_from_slice(&out);
        }
        Ok(())
    }

    fn process_inbuf(&mut self) -> Result<(), TlsError> {
        loop {
            let at = self.in_at;
            if self.inbuf.len() - at < 5 {
                break;
            }
            let header = [
                self.inbuf[at],
                self.inbuf[at + 1],
                self.inbuf[at + 2],
                self.inbuf[at + 3],
                self.inbuf[at + 4],
            ];
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if len > MAX_RECORD {
                return Err(TlsError::Other(
                    "record exceeds the maximum length".to_owned(),
                ));
            }
            if self.inbuf.len() - at - 5 < len {
                break;
            }
            let body = self.inbuf[at + 5..at + 5 + len].to_vec();
            self.in_at = at + 5 + len;
            match self.decrypt(header, body)? {
                APPLICATION => self.plain.extend_from_slice(&self.decoded),
                HANDSHAKE => self.post_handshake()?,
                ALERT => {
                    if self.alert_error() == TlsError::Closed {
                        self.eof = true;
                    } else {
                        return Err(self.alert_error());
                    }
                }
                CCS => {}
                other => return Err(unexpected(other)),
            }
        }
        if self.in_at > 0 {
            self.inbuf.drain(..self.in_at);
            self.in_at = 0;
        }
        Ok(())
    }

    fn seal_parts(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), TlsError> {
        if !self.reply.is_empty() {
            out.append(&mut self.reply);
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
        if self.plain_at < self.plain.len() {
            let avail = self.plain.len() - self.plain_at;
            let n = avail.min(buf.len());
            buf[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
            self.plain_at += n;
            return Ok((n, 0));
        }
        if ciphertext.is_empty() {
            return Ok((0, 0));
        }
        self.inbuf.extend_from_slice(ciphertext);
        self.process_inbuf().map_err(std::io::Error::other)?;
        let avail = self.plain.len() - self.plain_at;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain_at += n;
        Ok((n, ciphertext.len()))
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
        if self.plain_at >= self.plain.len() {
            self.pump().map_err(std::io::Error::other)?;
        }
        if self.plain_at >= self.plain.len() {
            return Ok(0);
        }
        let n = (self.plain.len() - self.plain_at).min(buf.len());
        buf[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain_at += n;
        Ok(n)
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
        let mut out = Vec::with_capacity(buf.len() + 5 + 16);
        self.seal_parts(&[buf], &mut out)
            .map_err(std::io::Error::other)?;
        self.io.write_all(&out)?;
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

fn certificates13(body: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    let mut r = Reader::new(body);
    let context = r.u8()?;
    r.take(usize::from(context))?;
    let list = r.vec24()?;
    let mut list = Reader::new(list);
    let mut chain = Vec::new();
    while !list.done() {
        chain.push(list.vec24()?.to_vec());
        let _extensions = list.vec16()?;
    }
    if chain.is_empty() {
        return Err(TlsError::BadCertificate(
            "server sent no certificate".to_owned(),
        ));
    }
    Ok(chain)
}

fn certificates12(body: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    let mut r = Reader::new(body);
    let list = r.vec24()?;
    let mut list = Reader::new(list);
    let mut chain = Vec::new();
    while !list.done() {
        chain.push(list.vec24()?.to_vec());
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

fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
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
