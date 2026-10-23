use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::conn::Connection;
use crate::proxy::{read_exact, under_handshake};

const AUTH_LEN: usize = 16;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 2;
const MAX_PLAIN: usize = 8192;
const FRAMES_PER_WRITE: usize = 16;
const READ_PLAIN: usize = MAX_PLAIN * FRAMES_PER_WRITE;
// The widest frame we seal: a full payload, its tag, and the padding the mask draw allows.
const MAX_WIRE: usize = MAX_PLAIN + TAG_LEN + 63;
const WIRE_LEN: usize = (FRAMES_PER_WRITE + 1) * (MAX_WIRE + HEADER_LEN);
const OPT_STREAM: u8 = 0x01;
const OPT_MASK: u8 = 0x04;
const OPT_PAD: u8 = 0x08;
const OPT_AUTH_LEN: u8 = 0x10;

/// A sealed size field: the two plain octets and their tag, what `AEADChunkSizeParser`
/// reads when the request asks for an authenticated length.
const SIZE_FIELD: usize = HEADER_LEN + TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    Auto,
    Aes,
    Chacha,
    None,
}

impl Cipher {
    pub(crate) fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Self::Chacha,
            "none" => Self::None,
            _ => Self::Auto,
        }
    }
    fn code(self) -> u8 {
        match self.resolve() {
            Self::Aes => 3,
            Self::None => 5,
            // A machine with no hardware AES has already become ChaCha here.
            Self::Auto | Self::Chacha => 4,
        }
    }
    /// Resolve the "auto" negotiation the way the reference does: AES-128-GCM where the machine has hardware for it, ChaCha20-Poly1305 where it does not; a concrete cipher is its own answer so this is idempotent, and the header byte and the payload flows both go through it and cannot diverge.
    fn resolve(self) -> Self {
        match self {
            Self::Auto if ferrox_core::aesgcm::has_hardware_support() => Self::Aes,
            Self::Auto => Self::Chacha,
            other => other,
        }
    }
    fn from_code(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::Aes),
            4 => Some(Self::Chacha),
            5 => Some(Self::None),
            _ => None,
        }
    }
}

/// An auth id is valid 120 s either side of the clock, so the window that refuses its replay has to outlast both halves of that span.
const REPLAY_SPAN: u64 = 240;

fn replay_seen(id: &[u8; AUTH_LEN]) -> bool {
    static WINDOW: OnceLock<Mutex<crate::proxy::Replay>> = OnceLock::new();
    let mut key = [0u8; 32];
    key[..AUTH_LEN].copy_from_slice(id);
    let mut guard = WINDOW
        .get_or_init(|| Mutex::new(crate::proxy::Replay::new(REPLAY_SPAN)))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.seen(&key, now_secs())
}

fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    use sha2::Digest as _;
    let mut flat = [0u8; 64];
    if key.len() > 64 {
        flat[..32].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        flat[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= flat[i];
        outer[i] ^= flat[i];
    }
    (inner, outer)
}

struct Hmac {
    inner: sha2::Sha256,
    outer: sha2::Sha256,
    fresh_inner: sha2::Sha256,
    fresh_outer: sha2::Sha256,
}

impl Hmac {
    fn fresh(key: &[u8]) -> Self {
        use sha2::Digest as _;
        let (ipad, opad) = hmac_pads(key);
        let mut inner = sha2::Sha256::new();
        let mut outer = sha2::Sha256::new();
        inner.update(ipad);
        outer.update(opad);
        Self {
            fresh_inner: inner.clone(),
            fresh_outer: outer.clone(),
            inner,
            outer,
        }
    }
    fn push(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.inner.update(data);
    }
    fn restart(&mut self) {
        self.inner = self.fresh_inner.clone();
        self.outer = self.fresh_outer.clone();
    }
    fn digest(&mut self) -> [u8; 32] {
        use sha2::Digest as _;
        let mid = self.inner.clone().finalize();
        let mut outer = self.outer.clone();
        outer.update(mid);
        outer.finalize().into()
    }
}

enum Kdf {
    Root(Box<Hmac>),
    Link {
        below: Box<Kdf>,
        seal_in: [u8; 64],
        seal_out: [u8; 64],
    },
}

impl Kdf {
    fn root() -> Self {
        Self::Root(Box::new(Hmac::fresh(b"VMess AEAD KDF")))
    }
    fn wrap(mut self, key: &[u8]) -> Self {
        let (seal_in, seal_out) = hmac_pads(key);
        self.push(&seal_in);
        Self::Link {
            below: Box::new(self),
            seal_in,
            seal_out,
        }
    }
    fn push(&mut self, data: &[u8]) {
        match self {
            Self::Root(h) => h.push(data),
            Self::Link { below, .. } => below.push(data),
        }
    }
    fn restart(&mut self) {
        match self {
            Self::Root(h) => h.restart(),
            Self::Link { below, seal_in, .. } => {
                below.restart();
                below.push(seal_in);
            }
        }
    }
    fn digest(&mut self) -> [u8; 32] {
        match self {
            Self::Root(h) => h.digest(),
            Self::Link {
                below, seal_out, ..
            } => {
                let mid = below.digest();
                below.restart();
                below.push(seal_out);
                below.push(&mid);
                below.digest()
            }
        }
    }
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut chain = Kdf::root();
    for layer in path {
        chain = chain.wrap(layer);
    }
    chain.push(key);
    chain.digest()
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

fn md5_two(first: &[u8], second: &[u8]) -> [u8; 16] {
    let mut input = [0u8; 52];
    let head = first.len().min(input.len());
    let tail = second.len().min(input.len() - head);
    input[..head].copy_from_slice(&first[..head]);
    input[head..head + tail].copy_from_slice(&second[..tail]);
    md5::compute(&input[..head + tail]).0
}

fn instruction_key(uuid: &[u8; 16]) -> [u8; 16] {
    md5_two(uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21")
}

fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5::compute(key).0;
    let second = md5::compute(first).0;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

// Linear over GF(2): eight bytes decompose into eight table-folded contributions.
const fn crc_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][i] = crc;
        i += 1;
    }
    let mut k = 1usize;
    while k < 8 {
        let mut i = 0usize;
        while i < 256 {
            let crc = tables[k - 1][i];
            tables[k][i] = tables[0][(crc & 0xff) as usize] ^ (crc >> 8);
            i += 1;
        }
        k += 1;
    }
    tables
}

const CRC_TABLES: [[u32; 256]; 8] = crc_tables();

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    let (groups, rest) = data.as_chunks::<8>();
    for chunk in groups {
        let low = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ crc;
        let high = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        crc = CRC_TABLES[7][(low & 0xff) as usize]
            ^ CRC_TABLES[6][((low >> 8) & 0xff) as usize]
            ^ CRC_TABLES[5][((low >> 16) & 0xff) as usize]
            ^ CRC_TABLES[4][(low >> 24) as usize]
            ^ CRC_TABLES[3][(high & 0xff) as usize]
            ^ CRC_TABLES[2][((high >> 8) & 0xff) as usize]
            ^ CRC_TABLES[1][((high >> 16) & 0xff) as usize]
            ^ CRC_TABLES[0][(high >> 24) as usize];
    }
    for &byte in rest {
        crc = (crc >> 8) ^ CRC_TABLES[0][((crc ^ u32::from(byte)) & 0xff) as usize];
    }
    !crc
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn random_into(buf: &mut [u8]) -> bool {
    getrandom::fill(buf).is_ok()
}

pub(crate) struct PadSource {
    buf: [u8; 2048],
    at: usize,
}

impl PadSource {
    pub(crate) fn fresh() -> Option<Self> {
        let mut buf = [0u8; 2048];
        if !random_into(&mut buf) {
            return None;
        }
        Some(Self { buf, at: 0 })
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        debug_assert!(n <= 64, "padding is at most 63 bytes");
        if self.at + n > self.buf.len() {
            if !random_into(&mut self.buf) {
                return None;
            }
            self.at = 0;
        }
        let bytes = &self.buf[self.at..self.at + n];
        self.at += n;
        Some(bytes)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Clone)]
struct AuthKey(aes::Aes128);

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthKey").finish_non_exhaustive()
    }
}

impl AuthKey {
    fn new(instruction: &[u8; 16]) -> Self {
        use aes::cipher::KeyInit as _;
        let bytes = kdf16(instruction, &[b"AES Auth ID Encryption"]);
        Self(aes::Aes128::new_from_slice(&bytes).expect("sixteen bytes is a key"))
    }

    fn seal(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockEncrypt as _;
        let cell = aes::cipher::generic_array::GenericArray::from_mut_slice(block.as_mut_slice());
        self.0.encrypt_block(cell);
    }

    fn open(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockDecrypt as _;
        let cell = aes::cipher::generic_array::GenericArray::from_mut_slice(block.as_mut_slice());
        self.0.decrypt_block(cell);
    }
}

type CachedUserKeys = ([u8; 16], AuthKey);

type UserKeyCache = std::collections::HashMap<[u8; 16], CachedUserKeys>;

fn cached_keys(uuid: &[u8; 16]) -> CachedUserKeys {
    static CACHE: OnceLock<Mutex<UserKeyCache>> = OnceLock::new();
    let mut guard = CACHE
        .get_or_init(|| Mutex::new(UserKeyCache::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(found) = guard.get(uuid) {
        return found.clone();
    }
    let instruction = instruction_key(uuid);
    let key = AuthKey::new(&instruction);
    let entry = (instruction, key);
    if guard.len() >= 64 {
        guard.clear();
    }
    guard.insert(*uuid, entry.clone());
    entry
}

fn seal_header(key: &[u8; 16], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let mut body = plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut body)
        .ok()?;
    body.extend_from_slice(&tag);
    Some(body)
}

fn open_header(key: &[u8; 16], nonce: &[u8; 12], sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    if sealed.len() < TAG_LEN {
        return None;
    }
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let split = sealed.len() - TAG_LEN;
    let mut body = sealed[..split].to_vec();
    cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(nonce),
            aad,
            &mut body,
            aes_gcm::Tag::from_slice(&sealed[split..]),
        )
        .ok()?;
    Some(body)
}

fn response_material(data_iv: &[u8; 16], data_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::Digest as _;
    let iv: [u8; 16] = sha2::Sha256::digest(data_iv)[..16].try_into().unwrap();
    let key: [u8; 16] = sha2::Sha256::digest(data_key)[..16].try_into().unwrap();
    (key, iv)
}

fn response_prefix(response_key: &[u8; 16], response_iv: &[u8; 16], auth: u8) -> Option<Vec<u8>> {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut out = seal_header(&len_key, &len_nonce, &[0, 4], &[])?;
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    out.extend_from_slice(&seal_header(&body_key, &body_nonce, &[auth, 0, 0, 0], &[])?);
    Some(out)
}

fn make_auth_id(key: &AuthKey) -> Option<[u8; 16]> {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&now_secs().to_be_bytes());
    if !random_into(&mut plain[8..12]) {
        return None;
    }
    let checksum = crc32(&plain[..12]).to_be_bytes();
    plain[12..].copy_from_slice(&checksum);
    key.seal(&mut plain);
    Some(plain)
}

fn valid_auth_id(key: &AuthKey, auth_id: &[u8; 16]) -> bool {
    let mut plain = *auth_id;
    key.open(&mut plain);
    if crc32(&plain[..12]) != u32::from_be_bytes(plain[12..].try_into().unwrap()) {
        return false;
    }
    u64::from_be_bytes(plain[..8].try_into().unwrap()).abs_diff(now_secs()) <= 120
}

struct Shake {
    reader: shake::Shake128Reader,
    padding: bool,
}

impl Shake {
    fn fresh(iv: &[u8; 16], padding: bool) -> Self {
        use sha3::digest::{ExtendableOutput as _, Update as _};
        let mut shake = shake::Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
            padding,
        }
    }
    fn draw(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        sha3::digest::XofReader::read(&mut self.reader, &mut buf);
        u16::from_be_bytes(buf)
    }
    #[cfg(test)]
    fn pad_len(&mut self) -> u16 {
        if self.padding {
            self.draw() % 64
        } else {
            0
        }
    }
    fn pad_and_mask(&mut self, wire: u16) -> (usize, u16) {
        if self.padding {
            let mut buf = [0u8; 4];
            sha3::digest::XofReader::read(&mut self.reader, &mut buf);
            let pad = usize::from(u16::from_be_bytes([buf[0], buf[1]]) % 64);
            let mask = u16::from_be_bytes([buf[2], buf[3]]);
            (pad, mask ^ wire)
        } else {
            (0, self.draw() ^ wire)
        }
    }
    fn draws(&mut self) -> (u16, u16) {
        if self.padding {
            let mut buf = [0u8; 4];
            sha3::digest::XofReader::read(&mut self.reader, &mut buf);
            (
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
            )
        } else {
            (0, self.draw())
        }
    }
}

/// The sealed size field's parser, where the mask draw would be: its key is
/// `KDF16(body_key, "auth_len")` (the same second AEAD per cipher the reference builds,
/// `proxy/vmess/encoding/server.go`), its nonce the body's shape with a counter of its own.
struct SizeAead {
    aes: Option<ferrox_core::aesgcm::Aes128Gcm>,
    chacha: Option<[u8; 32]>,
    /// The body IV's own tail: the size nonce is the body's shape with a counter of its own.
    iv: [u8; 10],
    counter: u16,
}

impl SizeAead {
    fn fresh(key: &[u8; 16], cipher: Cipher, iv: &[u8; 16]) -> Option<Self> {
        let len_key = kdf16(key, &[b"auth_len"]);
        let (aes, chacha) = match cipher {
            Cipher::Aes => (Some(ferrox_core::aesgcm::Aes128Gcm::new(&len_key)), None),
            Cipher::Chacha => (None, Some(chacha_key(&len_key))),
            // No cipher the reference seals a length with, so no authenticated length.
            _ => return None,
        };
        let mut tail = [0u8; 10];
        tail.copy_from_slice(&iv[2..12]);
        Some(Self {
            aes,
            chacha,
            iv: tail,
            counter: 0,
        })
    }
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv);
        nonce
    }
    /// The wire's 18 bytes open to the frame's total: the two plain octets are sealed here (`AEADChunkSizeParser::Decode`) and the overhead is added back.
    fn unseal_len(&mut self, sealed: &mut [u8; SIZE_FIELD]) -> Option<u16> {
        let (size, tag) = sealed.split_at_mut(HEADER_LEN);
        let tag: [u8; TAG_LEN] = <[u8; TAG_LEN]>::try_from(tag).ok()?;
        let plain = match (&self.aes, &self.chacha) {
            (Some(aes), None) => {
                aes.open_in_place(&self.nonce(), b"", size, &tag)?;
                size
            }
            (None, Some(key)) => {
                ferrox_core::aead::chacha20_poly1305_decrypt_in_place(
                    key,
                    &self.nonce(),
                    b"",
                    size,
                    &tag,
                )?;
                size
            }
            _ => return None,
        };
        self.counter = self.counter.wrapping_add(1);
        Some(u16::from_be_bytes([plain[0], plain[1]]).wrapping_add(TAG_LEN as u16))
    }
    /// The wire's 18 bytes seal the frame's body total less the tag, the shape the reference's encoder writes (`AEADChunkSizeParser::Encode`) and its nonce steps beside the body's.
    fn seal_len(&mut self, total: u16, sealed: &mut [u8; SIZE_FIELD]) {
        let mut plain = total.wrapping_sub(TAG_LEN as u16).to_be_bytes();
        let tag = match (&self.aes, &self.chacha) {
            (Some(aes), None) => aes.seal_in_place(&self.nonce(), b"", &mut plain),
            (None, Some(key)) => ferrox_core::aead::chacha20_poly1305_seal_in_place(
                key,
                &self.nonce(),
                b"",
                &mut plain,
            ),
            _ => return,
        };
        sealed[..HEADER_LEN].copy_from_slice(&plain);
        sealed[HEADER_LEN..].copy_from_slice(&tag);
        self.counter = self.counter.wrapping_add(1);
    }
}

pub(crate) struct Flow {
    cipher: Cipher,
    aes: Option<ferrox_core::aesgcm::Aes128Gcm>,
    chacha: Option<[u8; 32]>,
    iv: [u8; 16],
    counter: u16,
    shake: Option<Shake>,
    /// The sealed size field when the request asks for an authenticated length: the
    /// size parser leaves the mask draw for an AEAD of its own (`proxy/vmess/encoding/server.go`),
    /// its key derived `KDF16(key, "auth_len")` and its nonce counting beside the body's.
    len_seal: Option<SizeAead>,
}

impl Flow {
    /// The size field's plain octets, unsealed where the parser's own AEAD would put them.
    fn unseal_len(&mut self, sealed: &mut [u8; SIZE_FIELD]) -> Option<u16> {
        self.len_seal.as_mut()?.unseal_len(sealed)
    }
    fn fresh(
        cipher: Cipher,
        key: &[u8; 16],
        iv: &[u8; 16],
        options: u8,
        mask_seed: &[u8; 16],
    ) -> Option<Self> {
        let masking = options & OPT_MASK != 0 && options & OPT_AUTH_LEN == 0;
        let padding = options & OPT_PAD != 0 && options & OPT_AUTH_LEN == 0;
        let actual = cipher.resolve();
        let (aes, chacha) = match actual {
            Cipher::Aes => (Some(ferrox_core::aesgcm::Aes128Gcm::new(key)), None),
            Cipher::Chacha => (None, Some(chacha_key(key))),
            Cipher::None => (None, None),
            Cipher::Auto => return None,
        };
        let shake = masking.then(|| Shake::fresh(mask_seed, padding));
        Some(Self {
            cipher: actual,
            aes,
            chacha,
            iv: *iv,
            counter: 0,
            shake,
            len_seal: None,
        })
    }
    /// How many octets the next frame's size field takes on the wire.
    fn size_field(&self) -> usize {
        if self.len_seal.is_some() {
            SIZE_FIELD
        } else {
            HEADER_LEN
        }
    }
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        nonce
    }
    fn seal_onto(&mut self, plain: &[u8], out: &mut Vec<u8>) -> bool {
        let at = out.len();
        out.extend_from_slice(plain);
        let sealed = match (&self.aes, &self.chacha) {
            (Some(aes), None) => {
                let nonce = self.nonce();
                let tag = aes.seal_in_place(&nonce, b"", &mut out[at..]);
                out.extend_from_slice(&tag);
                true
            }
            (None, Some(key)) => {
                let nonce = self.nonce();
                let tag = ferrox_core::aead::chacha20_poly1305_seal_in_place(
                    key,
                    &nonce,
                    b"",
                    &mut out[at..],
                );
                out.extend_from_slice(&tag);
                true
            }
            (None, None) => true,
            _ => false,
        };
        if !sealed {
            out.truncate(at);
            return false;
        }
        // Wraps past 65535 like the reference's `GenerateChunkNonce`; see the method page.
        self.counter = self.counter.wrapping_add(1);
        true
    }
    fn open_chunk(&mut self, chunk: &mut [u8]) -> Option<usize> {
        let plain_len = match (&self.aes, &self.chacha) {
            (Some(aes), None) => {
                if chunk.len() < TAG_LEN {
                    return None;
                }
                let nonce = self.nonce();
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                let tag: &[u8; TAG_LEN] = <&[u8; TAG_LEN]>::try_from(&*tag).ok()?;
                aes.open_in_place(&nonce, b"", body, tag)?;
                split
            }
            (None, Some(key)) => {
                if chunk.len() < TAG_LEN {
                    return None;
                }
                let nonce = self.nonce();
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                let tag: &[u8; TAG_LEN] = <&[u8; TAG_LEN]>::try_from(&*tag).ok()?;
                ferrox_core::aead::chacha20_poly1305_decrypt_in_place(key, &nonce, b"", body, tag)?;
                split
            }
            (None, None) => chunk.len(),
            _ => return None,
        };
        self.counter = self.counter.wrapping_add(1);
        Some(plain_len)
    }
}

fn encode_target(out: &mut Vec<u8>, target: &crate::proxy::Destination) {
    out.extend_from_slice(&target.port().to_be_bytes());
    target.push_addr(out, 3, 2);
}

fn decode_target(header: &[u8], cursor: &mut usize) -> Option<SocketAddr> {
    let port = u16::from_be_bytes(header.get(*cursor..*cursor + 2)?.try_into().ok()?);
    let rest = &header[*cursor + 2..];
    let kind = match rest.first()? {
        1 => crate::proxy::AddrKind::V4,
        2 => crate::proxy::AddrKind::Domain,
        3 => crate::proxy::AddrKind::V6,
        _ => return None,
    };
    let (body, used) = crate::proxy::parse_addr_body(rest, kind)?;
    *cursor += 2 + used;
    Some(match body {
        crate::proxy::AddrBody::V4(ip) => SocketAddr::new(std::net::IpAddr::V4(ip.into()), port),
        crate::proxy::AddrBody::V6(ip) => SocketAddr::new(std::net::IpAddr::V6(ip.into()), port),
        crate::proxy::AddrBody::Domain(host) => crate::proxy::resolve_endpoint(host, port)?,
    })
}

type RequestParts = (Vec<u8>, [u8; 16], [u8; 16], u8);

fn request_bytes(
    uuid: &[u8; 16],
    cipher: Cipher,
    target: &crate::proxy::Destination,
    cmd: u8,
) -> Option<RequestParts> {
    let (instruction, auth_key) = cached_keys(uuid);
    let auth_id = make_auth_id(&auth_key)?;
    let mut rand = [0u8; 16 + 16 + 1 + 8 + 1];
    if !random_into(&mut rand) {
        return None;
    }
    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    data_iv.copy_from_slice(&rand[..16]);
    data_key.copy_from_slice(&rand[16..32]);
    let auth = [rand[32]];
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&rand[33..41]);
    let pad_len = usize::from(rand[41] % 16);
    let options = OPT_STREAM | OPT_MASK | OPT_PAD;
    let mut clear = Vec::with_capacity(64);
    clear.push(1);
    clear.extend_from_slice(&data_iv);
    clear.extend_from_slice(&data_key);
    clear.push(auth[0]);
    clear.push(options);
    clear.push((pad_len as u8) << 4 | cipher.code());
    clear.push(0);
    clear.push(cmd);
    encode_target(&mut clear, target);
    if pad_len > 0 {
        let mut pad = [0u8; 15];
        if !random_into(&mut pad[..pad_len]) {
            return None;
        }
        clear.extend_from_slice(&pad[..pad_len]);
    }
    clear.extend_from_slice(&fnv1a(&clear).to_be_bytes());
    let len_key = kdf16(
        &instruction,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let sealed_len = seal_header(
        &len_key,
        &len_nonce,
        &(clear.len() as u16).to_be_bytes(),
        &auth_id,
    )?;
    let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let head_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    let sealed_head = seal_header(&head_key, &head_nonce, &clear, &auth_id)?;
    let mut request = Vec::with_capacity(16 + 18 + 8 + sealed_head.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&sealed_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&sealed_head);
    Some((request, data_key, data_iv, auth[0]))
}

fn read_wire_len(stream: &mut dyn Read, recv: &mut Flow) -> Option<(usize, usize)> {
    if recv.len_seal.is_some() {
        let mut sealed = [0u8; SIZE_FIELD];
        read_exact(stream, &mut sealed).ok()?;
        return Some((usize::from(recv.unseal_len(&mut sealed)?), 0));
    }
    let mut prefix = [0u8; HEADER_LEN];
    read_exact(stream, &mut prefix).ok()?;
    Some(masked_len(recv, u16::from_be_bytes(prefix)))
}

/// A frame's total and padding from the length on the wire. The mask draw is once per frame,
/// so a pump that peeks a length has to be able to keep this answer.
fn masked_len(recv: &mut Flow, wire: u16) -> (usize, usize) {
    match recv.shake.as_mut() {
        None => (usize::from(wire), 0),
        Some(sizes) => {
            let (padding, total) = sizes.pad_and_mask(wire);
            (usize::from(total), padding)
        }
    }
}

/// One frame's sealed bytes in hand: drop the padding, open the rest in place, and say how
/// many plain bytes are left. Zero is the stream's end marker; `None` refuses the frame.
fn open_body(recv: &mut Flow, body: &mut [u8], padding: usize) -> Option<usize> {
    if body.len() <= padding {
        return Some(0);
    }
    let payload = body.len() - padding;
    if payload
        < match recv.cipher {
            Cipher::None => 0,
            _ => TAG_LEN,
        }
    {
        return None;
    }
    recv.open_chunk(&mut body[..payload])
}

pub(crate) fn write_frame(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    staging.clear();
    if !stage_frame(send, plain, staging, pad) {
        return false;
    }
    write_frames(stream, staging)
}

fn stage_frame(send: &mut Flow, plain: &[u8], staging: &mut Vec<u8>, pad: &mut PadSource) -> bool {
    let at = staging.len();
    let width = send.size_field();
    let body = at + width;
    staging.resize(at + width, 0);
    if !send.seal_onto(plain, staging) {
        staging.truncate(at);
        return false;
    }
    let encrypted = staging.len() - body;
    let (padding, mask_raw, masked) = match send.shake.as_mut() {
        None => (0, 0, false),
        Some(s) => {
            let (pad_raw, mask_raw) = s.draws();
            (usize::from(pad_raw % 64), mask_raw, true)
        }
    };
    let total = encrypted + padding;
    if total > u16::MAX as usize {
        staging.truncate(at);
        return false;
    }
    if let Some(seal) = send.len_seal.as_mut() {
        // The size field the sealed parser writes, in place of the two masked octets.
        let mut field = [0u8; SIZE_FIELD];
        seal.seal_len(total as u16, &mut field);
        staging[at..body].copy_from_slice(&field);
    } else {
        let wire = if masked {
            mask_raw ^ total as u16
        } else {
            total as u16
        };
        staging[at..body].copy_from_slice(&wire.to_be_bytes());
    }
    if padding > 0 {
        let Some(bytes) = pad.take(padding) else {
            staging.truncate(at);
            return false;
        };
        staging.extend_from_slice(bytes);
    }
    true
}

fn stage_frames(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    staging.clear();
    if plain.is_empty() {
        if !stage_frame(send, plain, staging, pad) {
            return false;
        }
    } else {
        let mut rest = plain;
        for _ in 0..FRAMES_PER_WRITE {
            let (frame, tail) = rest.split_at(MAX_PLAIN.min(rest.len()));
            if !stage_frame(send, frame, staging, pad) {
                return false;
            }
            rest = tail;
            if rest.is_empty() {
                break;
            }
        }
        // A read wider than FRAMES_PER_WRITE frames reaches here with bytes left: writing them would be a truncated frame stream on the wire, so refuse; `pump_relay` clamps to READ_PLAIN so nothing reaches it today, and a caller that did would rather close than corrupt.
        if !rest.is_empty() {
            return false;
        }
    }
    if staging.is_empty() {
        return true;
    }
    write_frames(stream, staging)
}

fn write_frames(stream: &mut dyn Write, staging: &[u8]) -> bool {
    if stream.write_all(staging).is_err() {
        return false;
    }
    stream.flush().is_ok()
}

pub(crate) fn read_frame<'a>(
    stream: &mut dyn Read,
    recv: &mut Flow,
    scratch: &'a mut Vec<u8>,
) -> Option<&'a [u8]> {
    let (total, padding) = read_wire_len(stream, recv)?;
    if total <= padding {
        let mut discard = [0u8; 64];
        let mut left = total;
        while left > 0 {
            let take = left.min(discard.len());
            read_exact(stream, &mut discard[..take]).ok()?;
            left -= take;
        }
        scratch.clear();
        return Some(&scratch[..0]);
    }
    if scratch.len() < total {
        scratch.resize(total, 0);
    }
    read_exact(stream, &mut scratch[..total]).ok()?;
    let len = open_body(recv, &mut scratch[..total], padding)?;
    Some(&scratch[..len])
}

/// What one decode step of a [`Wire`] did.
enum Frame {
    /// A frame opened, its plaintext gathered at the front of the buffer.
    Decoded,
    /// Nothing more can open without a wait; send the batch already gathered.
    Idle,
    /// The stream is over: its marker frame, an EOF, or a frame that will not open.
    Last,
}

/// The receive half of a relay. Sealed bytes and the plaintext gathered from them share one
/// buffer, so the pump can tell without asking the carrier that a batch of frames is already
/// here and leave the whole batch in one write — which a `BufReader` hides, and one frame per
/// `write` pays for in syscalls and in the segments the peer then has to deliver.
pub(crate) struct Wire<R> {
    carrier: R,
    held: Vec<u8>,
    /// The next frame's header.
    start: usize,
    /// One past the last sealed byte read.
    end: usize,
    /// The plaintext this batch has gathered at the front.
    plain: usize,
    /// A frame whose length is drawn but whose bytes have not all arrived.
    waiting: Option<(usize, usize)>,
    last: bool,
}

impl<R: Read> Wire<R> {
    fn new(carrier: R) -> Self {
        Self {
            carrier,
            held: crate::proxy::unfilled(WIRE_LEN),
            start: 0,
            end: 0,
            plain: 0,
            waiting: None,
            last: false,
        }
    }

    /// Open up to `FRAMES_PER_WRITE` frames, waiting only for the first, and hand back their
    /// plaintext as one slice. `None` ends the pump.
    fn batch(&mut self, recv: &mut Flow) -> Option<&[u8]> {
        if self.last {
            return None;
        }
        self.compact();
        self.plain = 0;
        let mut decoded = 0;
        while decoded < FRAMES_PER_WRITE {
            match self.frame(recv, decoded == 0) {
                Frame::Decoded => decoded += 1,
                Frame::Idle => break,
                Frame::Last => {
                    self.last = true;
                    break;
                }
            }
        }
        Some(&self.held[..self.plain])
    }

    fn buffered(&self) -> usize {
        self.end - self.start
    }

    /// Drop the frames the batch that just went out was made of.
    fn compact(&mut self) {
        if self.start > 0 {
            self.held.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// Read until `want` bytes are buffered. False when the carrier is not to be asked, or
    /// when it has said it has no more.
    #[allow(
        clippy::uninit_vec,
        reason = "the room past the old length is claimed, not written, and the read below writes every byte it reports"
    )]
    fn fill(&mut self, want: usize, block: bool) -> bool {
        if want > self.held.len() - self.start {
            // A peer that seals a wider chunk than we do gets one bigger buffer, not a refusal.
            self.held.reserve(self.start + want - self.held.len());
            // SAFETY: the room past the old length is claimed, not written, and the read below writes every byte it reports.
            unsafe { self.held.set_len(self.start + want) };
        }
        while self.buffered() < want {
            if !block {
                return false;
            }
            match self.carrier.read(&mut self.held[self.end..]) {
                Ok(0) => {
                    self.last = true;
                    return false;
                }
                Ok(read) => self.end += read,
                // A shared-session carrier sleeps the poll grain then returns a timeout; the wait is paid, so ask again.
                Err(ref error) if crate::proxy::is_timeout(error) => {}
                Err(_) => {
                    self.last = true;
                    return false;
                }
            }
        }
        true
    }

    fn frame(&mut self, recv: &mut Flow, block: bool) -> Frame {
        let width = recv.size_field();
        let (total, padding) = if let Some(sizes) = self.waiting {
            sizes
        } else {
            if self.buffered() < width && !self.fill(width, block) {
                return if self.last { Frame::Last } else { Frame::Idle };
            }
            let sizes = if width == SIZE_FIELD {
                let mut sealed = [0u8; SIZE_FIELD];
                sealed.copy_from_slice(&self.held[self.start..self.start + SIZE_FIELD]);
                recv.unseal_len(&mut sealed)
                    .map(|total| (usize::from(total), 0))
            } else {
                let mut prefix = [0u8; HEADER_LEN];
                prefix.copy_from_slice(&self.held[self.start..self.start + HEADER_LEN]);
                Some(masked_len(recv, u16::from_be_bytes(prefix)))
            };
            let Some(sizes) = sizes else {
                return Frame::Last;
            };
            self.waiting = Some(sizes);
            sizes
        };
        if self.buffered() < width + total && !self.fill(width + total, block) {
            return if self.last { Frame::Last } else { Frame::Idle };
        }
        self.waiting = None;
        let body = self.start + width;
        let Some(len) = open_body(recv, &mut self.held[body..body + total], padding) else {
            return Frame::Last;
        };
        self.start = body + total;
        if len == 0 {
            return Frame::Last;
        }
        // Every earlier frame left more bytes than it took, so gathering never reaches forward.
        self.held.copy_within(body..body + len, self.plain);
        self.plain += len;
        Frame::Decoded
    }
}

impl<R: Read> Read for Wire<R> {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        if self.buffered() > 0 {
            let take = self.buffered().min(dst.len());
            dst[..take].copy_from_slice(&self.held[self.start..self.start + take]);
            self.start += take;
            return Ok(take);
        }
        self.carrier.read(dst)
    }
}

pub(crate) type ClientSession = (Flow, Flow, [u8; 16], [u8; 16], u8);

pub(crate) type ClientRequest = (Vec<u8>, Flow, Flow, [u8; 16], [u8; 16], u8);

pub(crate) fn client_request(
    id: &[u8; 16],
    cipher: Cipher,
    target: &crate::proxy::Destination,
    cmd: u8,
) -> Option<ClientRequest> {
    let (request, data_key, data_iv, auth) = request_bytes(id, cipher, target, cmd)?;
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let options = OPT_STREAM | OPT_MASK | OPT_PAD;
    let actual = cipher.resolve();
    let send = Flow::fresh(actual, &data_key, &data_iv, options, &data_iv)?;
    let recv = Flow::fresh(actual, &response_key, &response_iv, options, &response_iv)?;
    Some((request, send, recv, response_key, response_iv, auth))
}

pub(crate) fn client_handshake(
    uplink: &mut Connection,
    id: &[u8; 16],
    cipher: Cipher,
    target: &crate::proxy::Destination,
) -> Option<ClientSession> {
    let (request, send, recv, response_key, response_iv, auth) =
        client_request(id, cipher, target, 1)?;
    if uplink.write_all(&request).is_err() {
        return None;
    }
    Some((send, recv, response_key, response_iv, auth))
}

pub(crate) fn read_response(
    stream: &mut dyn Read,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    auth: u8,
) -> bool {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    if read_exact(stream, &mut sealed_len).is_err() {
        return false;
    }
    let Some(clear_len) = open_header(&len_key, &len_nonce, &sealed_len, &[]) else {
        return false;
    };
    if clear_len.len() != 2 {
        return false;
    }
    let body_len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if body_len > 64 {
        return false;
    }
    let mut sealed_body = crate::proxy::unfilled(body_len + TAG_LEN);
    if read_exact(stream, &mut sealed_body).is_err() {
        return false;
    }
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    let Some(clear_body) = open_header(&body_key, &body_nonce, &sealed_body, &[]) else {
        return false;
    };
    if crate::proxy::echo_trace_on() {
        crate::proxy::echo_trace("response ok");
    }
    clear_body.len() == 4 && clear_body[0] == auth
}

fn read_open_header(
    stream: &mut dyn Read,
    instruction: &[u8; 16],
    auth_id: &[u8; AUTH_LEN],
) -> Option<Vec<u8>> {
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    read_exact(stream, &mut sealed_len).ok()?;
    let mut nonce = [0u8; 8];
    read_exact(stream, &mut nonce).ok()?;
    let len_key = kdf16(
        instruction,
        &[b"VMess Header AEAD Key_Length", auth_id, &nonce],
    );
    let len_full = kdf(
        instruction,
        &[b"VMess Header AEAD Nonce_Length", auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let clear_len = open_header(&len_key, &len_nonce, &sealed_len, auth_id)?;
    if clear_len.len() != 2 {
        return None;
    }
    let head_len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if !(38..=4096).contains(&head_len) {
        return None;
    }
    let mut sealed_head = crate::proxy::unfilled(head_len + TAG_LEN);
    read_exact(stream, &mut sealed_head).ok()?;
    let head_key = kdf16(instruction, &[b"VMess Header AEAD Key", auth_id, &nonce]);
    let head_full = kdf(instruction, &[b"VMess Header AEAD Nonce", auth_id, &nonce]);
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    open_header(&head_key, &head_nonce, &sealed_head, auth_id)
}
fn decode_header(header: &[u8]) -> Option<(SocketAddr, Flow, Flow, Vec<u8>, u8)> {
    if header.len() < 38 || header[0] != 1 || header[34] & OPT_STREAM == 0 {
        return None;
    }
    let cmd = header[37];
    if cmd != 1 && cmd != 2 {
        return None;
    }
    let cipher = Cipher::from_code(header[35] & 0x0f)?;
    let options = header[34];
    // Both together is no encoding the reference accepts: a padded reader needs a mask draw the sealed parser cannot give (`proxy/vmess/encoding/server.go`).
    if options & OPT_AUTH_LEN != 0 && options & OPT_PAD != 0 {
        return None;
    }
    // A body without a cipher leaves the sealed size with no key to seal against, and the reference refuses the option there (`proxy/vmess/encoding/server.go`).
    if options & OPT_AUTH_LEN != 0 && cipher.resolve() == Cipher::None {
        return None;
    }
    let mut cursor = 38;
    let target = decode_target(header, &mut cursor)?;
    let margin = usize::from(header[35] >> 4);
    if cursor + margin + 4 > header.len() {
        return None;
    }
    cursor += margin;
    if fnv1a(&header[..cursor])
        != u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap())
    {
        return None;
    }
    let data_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let data_key: [u8; 16] = header[17..33].try_into().unwrap();
    let auth = header[33];
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let prefix = response_prefix(&response_key, &response_iv, auth)?;
    let mut recv = Flow::fresh(cipher, &data_key, &data_iv, options, &data_iv)?;
    let mut send = Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)?;
    // The body AEAD rides the response material, the sealed size rides the request's keys (`proxy/vmess/encoding/server.go` `EncodeResponseBody`): both directions derive the size AEAD from the request body key and IV.
    if options & OPT_AUTH_LEN != 0 {
        let actual = cipher.resolve();
        recv.len_seal = SizeAead::fresh(&data_key, actual, &data_iv);
        send.len_seal = SizeAead::fresh(&data_key, actual, &data_iv);
    }
    Some((target, send, recv, prefix, cmd))
}
pub(crate) fn accept_request(
    stream: &mut dyn Read,
    id: &[u8; 16],
) -> Option<(SocketAddr, Flow, Flow, Vec<u8>, u8)> {
    let mut auth_id = [0u8; AUTH_LEN];
    read_exact(stream, &mut auth_id).ok()?;
    let (instruction, auth_key) = cached_keys(id);
    if !valid_auth_id(&auth_key, &auth_id) || replay_seen(&auth_id) {
        return None;
    }
    let header = read_open_header(stream, &instruction, &auth_id)?;
    decode_header(&header)
}

pub(crate) struct WsSink {
    writer: crate::ws::WsWriter,
    staged: Vec<u8>,
}

impl WsSink {
    pub(crate) fn carried(writer: crate::ws::WsWriter) -> Self {
        Self {
            writer,
            staged: Vec::with_capacity(READ_PLAIN + FRAMES_PER_WRITE * (TAG_LEN + 2 + 64)),
        }
    }
}

impl std::io::Write for WsSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.staged.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.staged.is_empty() {
            return Ok(());
        }
        let sent = self.writer.send(&self.staged);
        self.staged.clear();
        if sent {
            Ok(())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }
}

/// The relay leg's read window: a read fills every byte the leg reads, so the zero pass
/// in front of it was work generated and thrown away.
fn relay_window() -> Vec<u8> {
    crate::proxy::unfilled(READ_PLAIN)
}

pub(crate) fn pump_relay_carried<R, W>(
    plain: &Connection,
    reader: R,
    mut writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    send: Flow,
    recv: Flow,
    pending: Option<PendingResponse>,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut plain_write = plain_write;

    let mut send = send;
    let thread_close = std::sync::Arc::clone(close);
    let mut buf = relay_window();
    let done = thread::spawn(move || {
        let mut staging = Vec::with_capacity(FRAMES_PER_WRITE * (MAX_WIRE + HEADER_LEN));
        let Some(mut pad) = PadSource::fresh() else {
            return;
        };
        let mut first = true;
        while let Ok(read) = plain_read.read(&mut buf) {
            if read == 0 {
                let _ = write_frame(&mut writer, &mut send, &[], &mut staging, &mut pad);
                break;
            }
            let traced = crate::proxy::echo_trace_on() && first;
            if traced {
                crate::proxy::echo_trace("relay fwd first read");
            }
            let mut at = 0;
            let mut ok = true;
            while at < read {
                let end = (at + READ_PLAIN).min(read);
                if !stage_frames(
                    &mut writer,
                    &mut send,
                    &buf[at..end],
                    &mut staging,
                    &mut pad,
                ) {
                    ok = false;
                    break;
                }
                at = end;
            }
            if traced {
                crate::proxy::echo_trace(if ok {
                    "relay fwd first send ok"
                } else {
                    "relay fwd first send failed"
                });
                first = false;
            }
            if !ok {
                break;
            }
        }
        thread_close();
        let _ = plain_read.shutdown(Shutdown::Both);
    });

    let mut recv = recv;
    let mut reader = Wire::new(reader);
    // A lazy server sends the prefix with its first data, so the forward thread is already running here.
    if let Some((response_key, response_iv, auth)) = pending {
        if !read_response(&mut reader, &response_key, &response_iv, auth) {
            close();
            let _ = plain_write.shutdown(Shutdown::Both);
            let _ = done.join();
            return;
        }
    }
    let mut first = true;
    while let Some(chunk) = reader.batch(&mut recv) {
        if crate::proxy::echo_trace_on() && first {
            crate::proxy::echo_trace("relay bwd first read");
            first = false;
        }
        if plain_write.write_all(chunk).is_err() {
            break;
        }
    }
    close();
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

pub(crate) fn serve_ws(stream: Connection, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if !writer.send(&prefix) {
        return;
    }
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(
        &uplink,
        reader,
        WsSink::carried(writer),
        &close,
        send,
        recv,
        None,
    );
}

pub(crate) fn serve_grpc(stream: Connection, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, writer)) = crate::grpc::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) =
        under_handshake(&mut reader, |read| accept_request(read, id))
    else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if !writer.send(&prefix) {
        return;
    }
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv, None);
}

pub(crate) fn serve_xhttp(stream: Connection, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if !writer.send(&prefix) {
        return;
    }
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv, None);
}

pub(crate) fn serve_httpheader(stream: Connection, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, write)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    let Ok(down) = write.try_clone() else {
        return;
    };
    let mut down = down;
    if down.write_all(&prefix).is_err() {
        return;
    }
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, write, &close, send, recv, None);
}

pub(crate) fn serve_httpupgrade(stream: Connection, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, write)) = crate::httpupgrade::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    let Ok(down) = write.try_clone() else {
        return;
    };
    let mut down = down;
    if down.write_all(&prefix).is_err() {
        return;
    }
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, write, &close, send, recv, None);
}

pub(crate) fn serve_kcp<R, W>(
    mut reader: R,
    mut writer: W,
    id: &[u8; 16],
    freedom: bool,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if writer.write_all(&prefix).is_err() {
        return;
    }
    pump_relay_carried(&uplink, reader, writer, close, send, recv, None);
}

pub(crate) fn serve(mut stream: Connection, id: &[u8; 16], freedom: bool) {
    // Bound the opening request read like the raw VLESS handshake, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let request = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: &mut stream,
            until: std::time::Instant::now() + budget,
        };
        accept_request(&mut bounded, id)
    };
    let _ = stream.set_read_timeout(None);
    let Some((target, send, recv, prefix, cmd)) = request else {
        return;
    };
    if !freedom {
        return;
    }
    if cmd == 2 {
        return serve_vmess_udp(stream, &target, send, recv, &prefix);
    }
    if cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if stream.write_all(&prefix).is_err() {
        return;
    }
    pump_relay(&uplink, &stream, send, recv, None);
}

pub(crate) fn serve_vmess_udp(
    stream: Connection,
    target: &SocketAddr,
    send: Flow,
    recv: Flow,
    prefix: &[u8],
) {
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp) = UdpSocket::bind(bind) else {
        return;
    };
    if udp.connect(target).is_err() {
        return;
    }
    let mut stream = stream;
    if stream.write_all(prefix).is_err() {
        return;
    }
    crate::proxy::pump_vmess_udp(&stream, &udp, send, recv);
}

pub(crate) type PendingResponse = ([u8; 16], [u8; 16], u8);

pub(crate) fn pump_relay(
    plain: &Connection,
    sealed: &Connection,
    send: Flow,
    recv: Flow,
    pending: Option<PendingResponse>,
) {
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(sealed_write) = sealed.try_clone() else {
        return;
    };
    let Ok(sealed_read) = sealed.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut sealed_write = sealed_write;
    let mut plain_write = plain_write;
    let mut send = send;
    let mut buf = relay_window();
    let done = thread::spawn(move || {
        let mut staging = Vec::with_capacity(FRAMES_PER_WRITE * (MAX_WIRE + HEADER_LEN));
        let Some(mut pad) = PadSource::fresh() else {
            return;
        };
        while let Ok(read) = plain_read.read(&mut buf) {
            if read == 0 {
                let _ = write_frame(&mut sealed_write, &mut send, &[], &mut staging, &mut pad);
                break;
            }
            let mut at = 0;
            let mut ok = true;
            while at < read {
                let end = (at + READ_PLAIN).min(read);
                if !stage_frames(
                    &mut sealed_write,
                    &mut send,
                    &buf[at..end],
                    &mut staging,
                    &mut pad,
                ) {
                    ok = false;
                    break;
                }
                at = end;
            }
            if !ok {
                break;
            }
        }
        let _ = plain_read.shutdown(Shutdown::Both);
        let _ = sealed_write.shutdown(Shutdown::Both);
    });
    let mut recv = recv;
    let mut sealed_reader = Wire::new(sealed_read);
    if let Some((response_key, response_iv, auth)) = pending {
        if !read_response(&mut sealed_reader, &response_key, &response_iv, auth) {
            let _ = sealed.shutdown(Shutdown::Both);
            let _ = plain_write.shutdown(Shutdown::Both);
            let _ = done.join();
            return;
        }
    }
    while let Some(chunk) = sealed_reader.batch(&mut recv) {
        if plain_write.write_all(chunk).is_err() {
            break;
        }
    }
    let _ = sealed.shutdown(Shutdown::Both);
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_frame_coalesced_behind_its_header_still_arrives() {
        // The stall this guards against is silent on both ends: the server decodes the header and the dial waits for the echo while the ping frame sits in bytes a decode already consumed — no socket, no scheduler, so a loss here fails every run instead of one run in nine.
        let id = [0x77u8; 16];
        let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        let Some((request, mut send, _recv, _, _, _)) = client_request(
            &id,
            Cipher::Auto,
            &crate::proxy::Destination::from(target),
            1,
        ) else {
            panic!("builds a request");
        };
        let mut staging = Vec::with_capacity(16 * 1024);
        let mut pad = PadSource::fresh().expect("entropy");
        let mut frame = Vec::new();
        assert!(write_frame(
            &mut frame,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let mut cursor = Cursor::new([request, frame].concat());
        let Some((got, _send, mut take, _prefix, cmd)) = accept_request(&mut cursor, &id) else {
            panic!("decodes a header");
        };
        assert_eq!(cmd, 1);
        assert_eq!(got, target);
        let mut scratch = Vec::with_capacity(16 * 1024);
        let Some(back) = read_frame(&mut cursor, &mut take, &mut scratch) else {
            panic!("reads a coalesced frame");
        };
        assert_eq!(back, b"ping");
    }

    #[test]
    fn instruction_splits_uuid_and_magic() {
        let uuid = [0x11u8; 16];
        assert_ne!(instruction_key(&uuid), uuid);
        assert_eq!(instruction_key(&uuid), instruction_key(&uuid));
    }

    #[test]
    fn auth_ids_round_trip_and_reject_damage() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let key = AuthKey::new(&instruction);
        let id = make_auth_id(&key).expect("makes");
        assert!(valid_auth_id(&key, &id));
        let mut bad = id;
        bad[0] ^= 1;
        assert!(!valid_auth_id(&key, &bad));
    }

    #[test]
    fn headers_open_that_seal_sealed() {
        let key = [0x33u8; 16];
        let nonce = [0x44u8; 12];
        let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
        let back = open_header(&key, &nonce, &sealed, b"aad").expect("opens");
        assert_eq!(back, b"length-is-framing");
        let mut cut = sealed.clone();
        cut.pop();
        assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
    }

    #[test]
    fn frames_carry_an_echo_both_ways() {
        let cipher = Cipher::Chacha;
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(cipher, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(cipher, &key, &iv, options, &iv).expect("recvs");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut scratch = Vec::new();
            let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
            chunk.to_vec()
        });
        let mut reader = Connection::connect(("127.0.0.1", port)).expect("connects");
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(write_frame(
            &mut reader,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        assert_eq!(writer.join().expect("joins"), b"ping");
    }

    /// Silence past the budget is death, not scheduling: a peer that opens the connection and never sends must not pin the raw `VMess` handshake thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_a_raw_vmess_handshake() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x11u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, &id, true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn vmess_carries_over_the_ws_carrier_both_ways() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });

        let id = [0x5au8; 16];
        let path = "/vmess-ws";
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server_id = id;
        let server_path = path.to_string();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_ws(stream, &server_path, &server_id, true);
        });

        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) =
            crate::ws::connect(stream, &format!("127.0.0.1:{port}"), path, 0, &[])
                .expect("carries");

        let (request, data_key, data_iv, auth) = request_bytes(
            &id,
            Cipher::Chacha,
            &crate::proxy::Destination::from(target),
            1,
        )
        .expect("request");
        assert!(writer.send(&request), "request goes out as one message");

        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(
            read_response(&mut reader, &response_key, &response_iv, auth),
            "the server's response header opens over the carrier"
        );

        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");

        let mut sink = WsSink {
            writer: writer.clone(),
            staged: Vec::new(),
        };
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();

        assert!(
            write_frame(&mut sink, &mut send, b"ping", &mut staging, &mut pad),
            "a sealed frame goes out over the carrier"
        );
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping", "the echo came back through the carrier");
    }

    fn vmess_over_byte_carrier(
        path: &str,
        serve: impl FnOnce(Connection, [u8; 16]) + Send + 'static,
        connect: impl FnOnce(Connection) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>,
    ) {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });

        let id = [0x5au8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, id);
        });

        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) = connect(stream).expect("carries");

        let (request, data_key, data_iv, auth) = request_bytes(
            &id,
            Cipher::Chacha,
            &crate::proxy::Destination::from(target),
            1,
        )
        .expect("request");
        writer.write_all(&request).expect("requests");
        writer.flush().expect("flushes");

        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(
            read_response(&mut reader, &response_key, &response_iv, auth),
            "the server's response header opens over {path}"
        );

        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");

        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();
        assert!(
            write_frame(&mut writer, &mut send, b"ping", &mut staging, &mut pad),
            "a sealed frame goes out over {path}"
        );
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping", "the echo came back through {path}");
    }

    #[test]
    fn vmess_carries_over_the_xhttp_carrier_both_ways() {
        vmess_over_byte_carrier(
            "/vmess-xhttp",
            |stream, id| serve_xhttp(stream, "/vmess-xhttp", &id, true),
            |stream| {
                let (reader, writer) = crate::xhttp::connect(stream, "127.0.0.1", "/vmess-xhttp")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn vmess_carries_behind_the_http_camouflage_both_ways() {
        vmess_over_byte_carrier(
            "/vmess-camouflage",
            |stream, id| serve_httpheader(stream, "/vmess-camouflage", &id, true),
            |stream| {
                let (reader, writer) =
                    crate::httpheader::connect(stream, "127.0.0.1", "/vmess-camouflage")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    /// A vmess inbound over gRPC whose peer answers the head and never sends its first hunk releases the serve thread: the carrier puts its clock away with the head, so the auth id reads under its own.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_vmess_request() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x5bu8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(stream, "/p", &id, true);
            let _ = done_tx.send(());
        });
        let stream = Connection::connect(addr).expect("connects");
        let (_reader, _writer) = crate::grpc::connect(stream, "127.0.0.1", "/p").expect("dials");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn vmess_carries_over_the_grpc_tunnel_both_ways() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });
        let id = [0x5au8; 16];
        let path = "/TunnelService/Tun";
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(stream, path, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::grpc::connect(stream, "127.0.0.1", path).expect("carries");
        let (request, data_key, data_iv, auth) = request_bytes(
            &id,
            Cipher::Chacha,
            &crate::proxy::Destination::from(target),
            1,
        )
        .expect("request");
        assert!(writer.send(&request));
        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(read_response(
            &mut reader,
            &response_key,
            &response_iv,
            auth
        ));
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();
        assert!(write_frame(
            &mut writer,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn crc32_is_the_bit_at_a_time_loop_folded() {
        fn bit_at_a_time(data: &[u8]) -> u32 {
            let mut crc = !0u32;
            for &byte in data {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0xedb8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }

        for a in 0..=255u8 {
            assert_eq!(crc32(&[a]), bit_at_a_time(&[a]), "single byte {a}");
        }
        for len in 0..=40usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(97).wrapping_add(13))
                .collect();
            assert_eq!(crc32(&data), bit_at_a_time(&data), "length {len}");
        }
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    /// Counts `write` calls and keeps the bytes, so a syscall row is observed rather than inferred: a `Vec` sink cannot tell one write from four.
    #[derive(Default)]
    struct CountingWriter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_batch_on_the_wire_is_the_frames_written_one_at_a_time() {
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let key = [0x3cu8; 16];
        let iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        for &run_len in &[
            1usize,
            2,
            63,
            64,
            4096,
            MAX_PLAIN,
            MAX_PLAIN + 1,
            (FRAMES_PER_WRITE - 1) * MAX_PLAIN,
            FRAMES_PER_WRITE * MAX_PLAIN - 1,
            FRAMES_PER_WRITE * MAX_PLAIN,
            FRAMES_PER_WRITE * MAX_PLAIN + 1,
            READ_PLAIN,
        ] {
            let body: Vec<u8> = (0..run_len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();

            let chunks: Vec<&[u8]> = body.chunks(MAX_PLAIN).take(FRAMES_PER_WRITE).collect();
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut apart = Vec::new();
            for frame in &chunks {
                staging.clear();
                assert!(stage_frame(&mut send, frame, &mut staging, &mut pad));
                apart.extend_from_slice(&staging);
            }

            let mut batched = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut whole = Vec::new();
            let mut batch_pad = PadSource::fresh().expect("entropy");
            let mut sink = CountingWriter::default();
            let staged = stage_frames(&mut sink, &mut batched, &body, &mut whole, &mut batch_pad);
            if run_len > READ_PLAIN {
                assert!(!staged, "run of {run_len} is over the batch bound");
                assert_eq!(sink.writes, 0, "run of {run_len}: nothing reached the wire");
                continue;
            }
            assert!(staged, "run of {run_len} is inside the bound");
            let frames = chunks.len();
            assert_eq!(
                sink.writes,
                usize::from(frames > 0),
                "run of {run_len}: {frames} frames must cost exactly one write"
            );

            let mut mask = Shake::fresh(&iv, true);
            let (mut a, mut b) = (0usize, 0usize);
            for (frame, chunk) in chunks.iter().enumerate() {
                if run_len > READ_PLAIN {
                    break;
                }
                let padding = usize::from(mask.pad_len());
                let wire = u16::from_be_bytes([apart[a], apart[a + 1]]);
                assert_eq!(
                    wire,
                    u16::from_be_bytes([whole[b], whole[b + 1]]),
                    "run of {run_len}: frame {frame} length prefix"
                );
                let masked = usize::from(mask.draw() ^ wire);
                let sealed = masked - padding;
                assert_eq!(
                    chunk.len() + TAG_LEN,
                    sealed,
                    "run of {run_len}: frame {frame} sealed length"
                );
                assert_eq!(
                    &apart[a + 2..a + 2 + sealed],
                    &whole[b + 2..b + 2 + sealed],
                    "run of {run_len}: frame {frame} sealed body"
                );
                a += 2 + masked;
                b += 2 + masked;
            }
            assert_eq!(
                a,
                apart.len(),
                "the one-at-a-time run is exactly its frames"
            );
            assert_eq!(b, whole.len(), "the batch is exactly the same frames");
        }
    }

    /// `stage_frames` stages at most `FRAMES_PER_WRITE` frames: a wider read must refuse before any of the batch reaches the stream, because exiting the loop with bytes left and returning true would put a truncated frame sequence on the wire.
    #[test]
    fn a_read_wider_than_one_batch_is_refused_not_truncated() {
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let key = [0x3cu8; 16];
        let iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        for extra in [1usize, MAX_PLAIN] {
            let plain: Vec<u8> = (0..(READ_PLAIN + extra))
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut sink = CountingWriter::default();
            assert!(
                !stage_frames(&mut sink, &mut send, &plain, &mut staging, &mut pad),
                "a read of {} bytes must be refused, not truncated",
                plain.len()
            );
            assert_eq!(
                sink.writes, 0,
                "nothing of a refused batch may reach the wire"
            );
        }

        // and one byte under the bound still works, or the refusal is not a bound
        for len in [READ_PLAIN - 1, READ_PLAIN] {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut sink = CountingWriter::default();
            assert!(
                stage_frames(&mut sink, &mut send, &plain, &mut staging, &mut pad),
                "{len} bytes is exactly the bound and must stage"
            );
            assert_eq!(sink.writes, 1, "{len} bytes is one write");
        }
    }

    #[test]
    fn frames_reuse_the_callers_buffers() {
        let cipher = Cipher::Chacha;
        let key = [0x77u8; 16];
        let iv = [0x88u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(cipher, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(cipher, &key, &iv, options, &iv).expect("recvs");
        let lens = [1usize, 4, 63, 64, 65, 512, 1500, 4096];
        let payloads: Vec<Vec<u8>> = lens
            .iter()
            .map(|n| {
                (0..*n)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
                    .collect()
            })
            .collect();

        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut scratch = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 64);
            let addr = scratch.as_ptr() as usize;
            let cap = scratch.capacity();
            let mut got = Vec::new();
            for want in &lens {
                let was_at = scratch.as_ptr() as usize;
                let had = scratch.capacity();
                let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
                assert_eq!(chunk.len(), *want, "plaintext length");
                assert_eq!(
                    chunk.as_ptr() as usize,
                    was_at,
                    "the plaintext was copied out of the caller's buffer"
                );
                assert_eq!(was_at, addr, "the read buffer moved: read_frame allocated");
                assert_eq!(had, cap, "the read buffer grew: read_frame allocated");
                got.extend_from_slice(chunk);
            }
            got
        });

        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        let mut staging = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 2 + 64);
        let mut pad = PadSource::fresh().expect("entropy");
        let addr = staging.as_ptr() as usize;
        let cap = staging.capacity();
        let mut want = Vec::new();
        for plain in &payloads {
            assert!(write_frame(
                &mut uplink,
                &mut send,
                plain,
                &mut staging,
                &mut pad
            ));
            assert_eq!(
                staging.as_ptr() as usize,
                addr,
                "the write buffer moved: write_frame allocated"
            );
            assert_eq!(
                staging.capacity(),
                cap,
                "the write buffer grew: write_frame allocated"
            );
            want.extend_from_slice(plain);
        }
        assert_eq!(reader.join().expect("joins"), want);
    }

    #[test]
    fn kdf_is_stable_and_keyed() {
        let a = kdf(b"key", &[b"path"]);
        assert_eq!(a, kdf(b"key", &[b"path"]));
        assert_ne!(a, kdf(b"other", &[b"path"]));
        assert_ne!(a, kdf(b"key", &[b"other"]));
    }

    #[test]
    fn kdf_matches_the_oracle_vectors() {
        fn hex(bytes: &[u8]) -> String {
            let mut out = String::new();
            for b in bytes {
                out.push("0123456789abcdef".as_bytes()[(b >> 4) as usize] as char);
                out.push("0123456789abcdef".as_bytes()[(b & 15) as usize] as char);
            }
            out
        }
        assert_eq!(
            hex(&md5::compute(b"abc").0),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&kdf(b"key", &[b"path"])),
            "f5952ea326376193226ffe760d8aa2ad8587c6a0cc7c32efeda02eb0b5d430ed"
        );
        assert_eq!(
            hex(&kdf(
                b"key",
                &[
                    b"VMess Header AEAD Key_Length",
                    b"authid1234567890",
                    b"nonce123"
                ]
            )),
            "fa9ff42e922d36e727fe11148c5bfae1e57feb2a8bc5671be1014e8a5554c70a"
        );
        assert_eq!(
            hex(&kdf16(b"test-instruction-16", &[b"AES Auth ID Encryption"])),
            "a69474c1eddf8c94283389cc76ac64be"
        );
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        assert_eq!(
            hex(&instruction_key(&uuid)),
            "b50d916ac0cec067981af8e5f38a758f"
        );
    }

    #[test]
    fn handshake_relay_round_trips() {
        use std::io::{Read as _, Write as _};
        let id = [0xabu8; 16];
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            super::serve(stream, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut send, mut recv, response_key, response_iv, auth) = super::client_handshake(
            &mut uplink,
            &id,
            Cipher::Auto,
            &crate::proxy::Destination::from(target),
        )
        .expect("handshakes");
        assert!(super::read_response(
            &mut uplink,
            &response_key,
            &response_iv,
            auth
        ));
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(write_frame(
            &mut uplink,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let mut scratch = Vec::new();
        let back = read_frame(&mut uplink, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn response_prefix_is_stable() {
        let prefix = response_prefix(&[0x71u8; 16], &[0x72u8; 16], 0xAB).expect("prefixes");
        assert_eq!(prefix.len(), 38);
        assert_eq!(
            prefix,
            [
                0xab, 0xe4, 0x1f, 0x65, 0xdb, 0xa0, 0x80, 0xd4, 0xcc, 0x9d, 0x50, 0xd3, 0x0a, 0xda,
                0x8b, 0x09, 0xaa, 0x89, 0x82, 0xf9, 0xa8, 0xfe, 0x3d, 0xf3, 0x20, 0xc3, 0x7b, 0x61,
                0xcd, 0x45, 0x4e, 0x47, 0x98, 0x8d, 0x4a, 0xf9, 0x11, 0xd7,
            ]
        );
    }

    #[test]
    fn frames_seal_to_stable_bytes() {
        let cases = [
            (
                Cipher::Chacha,
                [
                    0x15, 0xe6, 0x71, 0x0e, 0x43, 0x79, 0x84, 0x37, 0x1c, 0xc5, 0xf6, 0x4d, 0xd4,
                    0x8f, 0x7c, 0xc4, 0x58, 0x69, 0xc8, 0xeb, 0xec,
                ],
            ),
            (
                Cipher::Aes,
                [
                    0xc9, 0x02, 0x32, 0x56, 0x14, 0x1e, 0xff, 0x1c, 0xe0, 0xfc, 0x09, 0xbf, 0x9f,
                    0xc1, 0xa9, 0x16, 0xfc, 0xeb, 0x35, 0xbd, 0x5a,
                ],
            ),
        ];
        for (cipher, golden) in cases {
            let mut flow = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let mut sealed = Vec::new();
            assert!(flow.seal_onto(b"hello", &mut sealed));
            assert_eq!(sealed, golden);
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let back = recv.open_chunk(&mut sealed).expect("opens");
            assert_eq!(&sealed[..back], b"hello");
        }
    }

    #[test]
    fn seal_open_round_trips_every_length_and_cipher() {
        let lens = [
            0, 1, 2, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1000, 1023, 1024, 4095,
            4096, 8191, 8192, 8193, 16383, 16384, 20000,
        ];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let tag = if cipher == Cipher::None { 0 } else { TAG_LEN };
            for &len in &lens {
                let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                let mut sealed = Vec::new();
                assert!(send.seal_onto(&plain, &mut sealed));
                assert_eq!(sealed.len(), plain.len() + tag);
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(back, plain.len());
                assert_eq!(&sealed[..back], &plain[..]);
            }
        }
    }

    #[test]
    fn masked_frames_carry_every_length() {
        let lens = [0, 1, 100, 8191, 8192, 8193, 20000];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let options = OPT_STREAM | OPT_MASK | OPT_PAD;
            let payloads: Vec<Vec<u8>> = lens
                .iter()
                .map(|&len| (0..len).map(|i| (i % 251) as u8).collect())
                .collect();
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let writer = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut recv =
                    Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                        .expect("recvs");
                let mut all = Vec::new();
                let mut scratch = Vec::new();
                for _ in &lens {
                    let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
                    all.extend_from_slice(chunk);
                }
                all
            });
            let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
            let mut send =
                Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                    .expect("sends");
            let mut want = Vec::new();
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            for plain in &payloads {
                assert!(write_frame(
                    &mut uplink,
                    &mut send,
                    plain,
                    &mut staging,
                    &mut pad
                ));
                want.extend_from_slice(plain);
            }
            assert_eq!(writer.join().expect("joins"), want);
        }
    }

    #[test]
    fn counters_advance_one_per_frame_at_any_offset() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            for &at in &[0u16, 1, 255, 256, 1000, 32767, 32768, 65533, 65534, 65535] {
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                send.counter = at;
                recv.counter = at;
                let mut first = [0u8; 12];
                first.copy_from_slice(&send.nonce());
                let mut sealed = Vec::new();
                assert!(send.seal_onto(b"ping", &mut sealed));
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(&sealed[..back], b"ping");
                assert_eq!(send.counter, at.wrapping_add(1));
                assert_eq!(recv.counter, at.wrapping_add(1));
                assert_ne!(send.nonce(), first);
            }
        }
    }

    #[test]
    fn counter_wrap_matches_the_reference() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            let mut send = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            send.counter = u16::MAX;
            recv.counter = u16::MAX;
            let mut sealed = Vec::new();
            assert!(send.seal_onto(b"ping", &mut sealed));
            assert_eq!(send.counter, 0);
            let back = recv.open_chunk(&mut sealed).expect("opens across the wrap");
            assert_eq!(&sealed[..back], b"ping");
            assert_eq!(recv.counter, 0);
            let mut sealed = Vec::new();
            assert!(send.seal_onto(b"pong", &mut sealed));
            let back = recv.open_chunk(&mut sealed).expect("opens after the wrap");
            assert_eq!(&sealed[..back], b"pong");
        }
    }

    #[test]
    fn wire_codes_and_security_words_map_exactly() {
        assert_eq!(Cipher::from_code(3), Some(Cipher::Aes));
        assert_eq!(Cipher::from_code(4), Some(Cipher::Chacha));
        assert_eq!(Cipher::from_code(5), Some(Cipher::None));
        for code in [0, 1, 2, 6, 7, 255] {
            assert!(Cipher::from_code(code).is_none());
        }
        assert_eq!(Cipher::parse("auto"), Cipher::Auto);
        assert_eq!(Cipher::parse("AUTO"), Cipher::Auto);
        assert_eq!(Cipher::parse("aes-128-gcm"), Cipher::Aes);
        assert_eq!(Cipher::parse("AES-128-GCM"), Cipher::Aes);
        assert_eq!(Cipher::parse("chacha20-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("chacha20-ietf-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("none"), Cipher::None);
        assert_eq!(Cipher::parse("NONE"), Cipher::None);
        assert_eq!(Cipher::parse("garbage"), Cipher::Auto);
        assert_eq!(Cipher::parse(""), Cipher::Auto);
    }

    /// The invariant the "auto" resolution must not break: whichever cipher a machine resolves for the header byte, the payload flows seal with the same one — a peer reads the byte and decrypts the body to match — and it holds whether this runner resolves "auto" to AES or to `ChaCha`.
    #[test]
    fn the_header_cipher_byte_matches_the_flow_cipher() {
        for cipher in [Cipher::Auto, Cipher::Aes, Cipher::Chacha] {
            let flow = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            assert_eq!(
                Cipher::from_code(cipher.code()),
                Some(flow.cipher),
                "{cipher:?} header byte and flow cipher disagree"
            );
        }
    }

    #[test]
    fn tampered_seals_do_not_open() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            let key = [0x33u8; 16];
            let nonce = [0x44u8; 12];
            let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
            for at in [0, sealed.len() / 2, sealed.len() - 1] {
                let mut cut = sealed.clone();
                cut[at] ^= 1;
                assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
            }
            assert!(open_header(&key, &nonce, &sealed, b"wrong").is_none());
            assert!(open_header(&[0x34u8; 16], &nonce, &sealed, b"aad").is_none());
            assert!(open_header(&key, &nonce, &sealed[..sealed.len() - 1], b"aad").is_none());
            let mut send = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("sends");
            let mut frame = Vec::new();
            assert!(send.seal_onto(b"ping", &mut frame));
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("recvs");
            frame[0] ^= 1;
            assert!(recv.open_chunk(&mut frame).is_none());
        }
    }

    #[test]
    fn expired_auth_ids_are_refused() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let key = AuthKey::new(&instruction);
        let seal = |ago: u64| {
            let mut plain = [0u8; 16];
            plain[..8].copy_from_slice(&now_secs().saturating_sub(ago).to_be_bytes());
            plain[8..12].copy_from_slice(&[9u8, 8, 7, 6]);
            let checksum = crc32(&plain[..12]).to_be_bytes();
            plain[12..].copy_from_slice(&checksum);
            key.seal(&mut plain);
            plain
        };
        assert!(valid_auth_id(&key, &seal(0)));
        assert!(valid_auth_id(&key, &seal(119)));
        assert!(!valid_auth_id(&key, &seal(121)));
        assert!(!valid_auth_id(&key, &seal(3600)));
    }

    #[test]
    fn replays_close_on_second_use() {
        let id = [0x77u8; AUTH_LEN];
        assert!(!replay_seen(&id));
        assert!(replay_seen(&id));
    }

    #[test]
    fn the_window_refuses_a_replay_for_its_span_and_forgets_after_two() {
        let mut window = crate::proxy::Replay::new(REPLAY_SPAN);
        let key = [0x5eu8; 32];
        assert!(
            !window.seen(&key, 10_000),
            "a first sighting is not a replay"
        );
        assert!(
            window.seen(&key, 10_000 + REPLAY_SPAN - 1),
            "the span the auth id is valid for is refused"
        );
        assert!(
            window.seen(&key, 10_000 + REPLAY_SPAN),
            "the rotation that moves the key out of the window is the one after it"
        );
        assert!(
            !window.seen(&key, 10_000 + 2 * REPLAY_SPAN),
            "two spans of quiet empty the window"
        );
    }

    #[test]
    fn the_window_holds_two_rotations_at_most() {
        let mut window = crate::proxy::Replay::new(REPLAY_SPAN);
        let first = [0u8; 32];
        assert!(!window.seen(&first, 5_000));
        for index in 1..=2 * crate::proxy::REPLAY_KEYS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(index as u64).to_be_bytes());
            window.seen(&key, 5_000);
            assert!(
                window.held() <= 2 * crate::proxy::REPLAY_KEYS,
                "{index} keys"
            );
        }
        assert!(
            !window.seen(&first, 5_000),
            "a flood rotates the oldest keys out without the clock moving"
        );
    }

    #[test]
    fn clear_headers_decode_and_reject() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let mut header = vec![1u8];
        header.extend_from_slice(&[0x01u8; 16]);
        header.extend_from_slice(&[0x02u8; 16]);
        header.push(0x03);
        header.push(OPT_STREAM | OPT_MASK | OPT_PAD);
        header.push(0x04);
        header.push(0);
        header.push(1);
        header.extend_from_slice(&target.port().to_be_bytes());
        header.push(1);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&fnv1a(&header).to_be_bytes());
        let (got, _send, _recv, prefix, cmd) = decode_header(&header).expect("decodes");
        assert_eq!(got, target);
        assert_eq!(cmd, 1);
        assert_eq!(prefix.len(), 38);
        let mut bad = header.clone();
        bad[0] = 2;
        assert!(decode_header(&bad).is_none());
        let mut udp = header.clone();
        udp[37] = 2;
        let cut = udp.len() - 4;
        let sum = fnv1a(&udp[..cut]);
        udp[cut..].copy_from_slice(&sum.to_be_bytes());
        let (got, _, _, _, cmd) = decode_header(&udp).expect("decodes udp");
        assert_eq!(got, target);
        assert_eq!(cmd, 2);
        let mut bad = header.clone();
        bad[37] = 5;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0x07;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[34] &= !OPT_STREAM;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0xF4;
        assert!(decode_header(&bad).is_none());
        assert!(decode_header(&header[..header.len() - 1]).is_none());
    }

    #[test]
    fn the_option_byte_has_four_named_bits() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let header = |cipher: u8, options: u8| {
            let mut header = vec![1u8];
            header.extend_from_slice(&[0x01u8; 16]);
            header.extend_from_slice(&[0x02u8; 16]);
            header.push(0x03);
            header.push(options);
            header.push(cipher);
            header.push(0);
            header.push(1);
            header.extend_from_slice(&target.port().to_be_bytes());
            header.push(1);
            header.extend_from_slice(&[127, 0, 0, 1]);
            header.extend_from_slice(&fnv1a(&header).to_be_bytes());
            header
        };
        // The bit names a framing both directions carry: a frame's size field is the sealed 18 octets, not the two masked ones.
        let (_, send, recv, _, _) =
            decode_header(&header(0x04, OPT_STREAM | OPT_AUTH_LEN | OPT_MASK)).expect("decodes");
        assert_eq!(send.size_field(), SIZE_FIELD);
        assert_eq!(recv.size_field(), SIZE_FIELD);
        // Padding needs a mask draw the sealed parser cannot give, and the reference refuses the pair.
        assert!(
            decode_header(&header(0x04, OPT_STREAM | OPT_AUTH_LEN | OPT_PAD)).is_none(),
            "padding with an authenticated length"
        );
        // A body without a cipher leaves the sealed size without a key, and the reference refuses the option there too.
        assert!(decode_header(&header(0x05, OPT_STREAM | OPT_AUTH_LEN)).is_none());
        // A 2-octet size field stays the way the bit has always framed it.
        let (_, send, recv, _, _) =
            decode_header(&header(0x04, OPT_STREAM | OPT_MASK | OPT_PAD)).expect("decodes");
        assert_eq!(send.size_field(), HEADER_LEN);
        assert_eq!(recv.size_field(), HEADER_LEN);
    }

    #[test]
    fn an_authenticated_length_peer_is_read_like_any_other() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let header = |cipher: u8, options: u8| {
            let mut header = vec![1u8];
            header.extend_from_slice(&[0x01u8; 16]);
            header.extend_from_slice(&[0x02u8; 16]);
            header.push(0x03);
            header.push(options);
            header.push(cipher);
            header.push(0);
            header.push(1);
            header.extend_from_slice(&target.port().to_be_bytes());
            header.push(1);
            header.extend_from_slice(&[127, 0, 0, 1]);
            header.extend_from_slice(&fnv1a(&header).to_be_bytes());
            header
        };
        let payload: Vec<u8> = (0..300).map(|k| k as u8).collect();
        for cipher in [Cipher::Aes, Cipher::Chacha] {
            let options = OPT_STREAM | OPT_AUTH_LEN;
            let mut send =
                Flow::fresh(cipher, &[0x02; 16], &[0x01; 16], options, &[0x01; 16]).expect("sends");
            send.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
            let mut sealed = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            assert!(
                stage_frame(&mut send, &payload, &mut sealed, &mut pad),
                "payload"
            );
            assert!(stage_frame(&mut send, &[], &mut sealed, &mut pad), "marker");
            let mut recv =
                Flow::fresh(cipher, &[0x02; 16], &[0x01; 16], options, &[0x01; 16]).expect("recvs");
            recv.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
            let mut read = &sealed[..];
            {
                let mut scratch = Vec::new();
                let opened = read_frame(&mut read, &mut recv, &mut scratch).expect("opens");
                assert_eq!(opened, &payload, "the plain bytes behind the sealed size");
                let marker = read_frame(&mut read, &mut recv, &mut scratch).expect("ends");
                assert!(marker.is_empty(), "the zero body is the end");
            }
            let carrier = Sealed {
                held: sealed.clone(),
                at: 0,
                grain: usize::MAX,
                reads: 0,
            };
            let (_writes, got) = drain(&mut Wire::new(carrier), &mut {
                let mut wire_recv =
                    Flow::fresh(cipher, &[0x02; 16], &[0x01; 16], options, &[0x01; 16])
                        .expect("recvs");
                wire_recv.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
                wire_recv
            });
            assert_eq!(got, payload, "the wire opens the same frames");

            // The staged framing is a server's response framing here: the body AEAD rides the response material while the sealed size rides the request's keys (`proxy/vmess/encoding/server.go` `EncodeResponseBody`), so a peer sealing the size with the wrong pair cannot open it.
            let head = header(cipher.code(), options);
            let (_, mut srv, _, _, _) = decode_header(&head).expect("decodes");
            let (response_key, response_iv) = response_material(&[0x01; 16], &[0x02; 16]);
            let mut peer = Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)
                .expect("peer");
            peer.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
            let mut staged = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            assert!(
                stage_frame(&mut srv, &payload, &mut staged, &mut pad),
                "staged"
            );
            let mut read = &staged[..];
            let mut scratch = Vec::new();
            let opened = read_frame(&mut read, &mut peer, &mut scratch).expect("opens");
            assert_eq!(
                opened, &payload,
                "the request's keys seal the response sizes"
            );
            let mut wrong = Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)
                .expect("peer");
            wrong.len_seal = SizeAead::fresh(&response_key, cipher, &response_iv);
            let mut read = &staged[..];
            assert!(
                read_frame(&mut read, &mut wrong, &mut Vec::new()).is_none(),
                "the size field will not open under the response pair"
            );
        }
    }

    #[test]
    fn requests_open_to_their_own_lengths_and_targets() {
        let uuid = [0xabu8; 16];
        let targets = [
            "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
            "[::1]:443".parse::<SocketAddr>().expect("addr"),
        ];
        for cipher in [Cipher::Auto, Cipher::Aes, Cipher::Chacha, Cipher::None] {
            for target in targets {
                let (request, _, _, _) =
                    request_bytes(&uuid, cipher, &crate::proxy::Destination::from(target), 1)
                        .expect("builds");
                assert!(request.len() > 42 + TAG_LEN);
                let instruction = instruction_key(&uuid);
                let auth_id: [u8; AUTH_LEN] = request[..AUTH_LEN].try_into().expect("auth");
                let nonce = &request[16 + 18..16 + 18 + 8];
                let len_key = kdf16(
                    &instruction,
                    &[b"VMess Header AEAD Key_Length", &auth_id, nonce],
                );
                let len_full = kdf(
                    &instruction,
                    &[b"VMess Header AEAD Nonce_Length", &auth_id, nonce],
                );
                let len_nonce: [u8; 12] = len_full[..12].try_into().expect("nonce");
                let clear_len =
                    open_header(&len_key, &len_nonce, &request[16..34], &auth_id).expect("opens");
                assert_eq!(
                    usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]])),
                    request.len() - 42 - TAG_LEN
                );
                let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, nonce]);
                let head_full = kdf(&instruction, &[b"VMess Header AEAD Nonce", &auth_id, nonce]);
                let head_nonce: [u8; 12] = head_full[..12].try_into().expect("nonce");
                let clear =
                    open_header(&head_key, &head_nonce, &request[42..], &auth_id).expect("opens");
                let (got, _, _, _, _) = decode_header(&clear).expect("decodes");
                assert_eq!(got, target);
            }
        }
    }

    #[test]
    fn garbage_short_and_wrong_user_close_fast() {
        let id = [0xabu8; 16];
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(3) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || super::serve(stream, &id, true));
            }
        });
        let mut refused = 0;
        for body in [
            vec![0u8; 16],
            request_bytes(
                &[0xccu8; 16],
                Cipher::Auto,
                &"127.0.0.1:1".parse().expect("addr"),
                1,
            )
            .expect("builds")
            .0,
            request_bytes(&id, Cipher::Auto, &"127.0.0.1:1".parse().expect("addr"), 1)
                .expect("builds")
                .0[..20]
                .to_vec(),
        ] {
            let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
            stream.write_all(&body).expect("writes");
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let mut back = [0u8; 1];
            match stream.read(&mut back) {
                Ok(0) | Err(_) => refused += 1,
                Ok(_) => {}
            }
        }
        assert_eq!(refused, 3);
    }

    #[test]
    fn the_chacha_data_frames_are_the_crate_it_replaced() {
        use chacha20poly1305::aead::AeadInPlace;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};

        let data_key = [0x3cu8; 16];
        let data_iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        let options = OPT_STREAM | OPT_MASK;

        let want_key: [u8; 32] = [
            0x8c, 0xad, 0xb9, 0xb0, 0x5f, 0xd7, 0x0f, 0x16, 0xab, 0x6b, 0xea, 0xd8, 0x48, 0x90,
            0x14, 0x5d, 0xf7, 0xa8, 0xe4, 0xab, 0xb4, 0x63, 0x92, 0x9f, 0x06, 0x32, 0x00, 0xed,
            0x60, 0x0b, 0xf6, 0xa5,
        ];
        assert_eq!(
            chacha_key(&data_key),
            want_key,
            "the data key is md5(key) then md5 of that, concatenated"
        );

        for len in (0..=40usize).chain([63, 64, 65, 127, 128, 129, 1024, 4096]) {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(61).wrapping_add(5))
                .collect();

            let mut flow = Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv)
                .expect("a chacha flow");
            let cipher = ChaCha20Poly1305::new_from_slice(&want_key).expect("crate key");

            for frame in 0..3u8 {
                let nonce = flow.nonce();
                let mut want_nonce = [0u8; 12];
                want_nonce[..2].copy_from_slice(&(frame as u16).to_be_bytes());
                want_nonce[2..].copy_from_slice(&data_iv[2..12]);
                assert_eq!(nonce, want_nonce, "frame {frame}: counter then the iv tail");
                let mut ours = Vec::new();
                assert!(flow.seal_onto(&plain, &mut ours), "seals frame {len}");

                let mut want = plain.clone();
                let want_tag = cipher
                    .encrypt_in_place_detached(Nonce::from_slice(&want_nonce), b"", &mut want)
                    .expect("crate seals");
                assert_eq!(
                    ours,
                    [want.as_slice(), want_tag.as_slice()].concat(),
                    "length {len} frame {frame} is the crate's bytes"
                );

                let mut recv = Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv)
                    .expect("a chacha flow");
                for _ in 0..frame {
                    recv.counter += 1;
                }
                let n = recv.open_chunk(&mut ours).expect("opens");
                assert_eq!(n, len, "length {len} frame {frame} opens to its own length");
                assert_eq!(recv.iv, data_iv, "opening does not disturb the iv");
            }
        }
    }

    /// A carrier that hands over what it holds, `grain` bytes per read, and counts the asks.
    /// An in-memory one, because over a socket the scheduler decides how many frames arrive
    /// together and a count there is a measurement of the machine, not of this code.
    struct Sealed {
        held: Vec<u8>,
        at: usize,
        grain: usize,
        reads: usize,
    }

    impl Read for Sealed {
        fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            let take = self.grain.min(self.held.len() - self.at).min(dst.len());
            dst[..take].copy_from_slice(&self.held[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    /// Frames sealed exactly as the write side seals them, with the plaintext they carry.
    fn frames(lens: &[usize]) -> (Vec<u8>, Vec<u8>, Flow) {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
        let mut pad = PadSource::fresh().expect("entropy");
        let mut sealed = Vec::new();
        let mut plain = Vec::new();
        for (i, &len) in lens.iter().enumerate() {
            let body: Vec<u8> = (0..len).map(|k| (k as u8).wrapping_add(i as u8)).collect();
            assert!(
                stage_frame(&mut send, &body, &mut sealed, &mut pad),
                "seals {i}"
            );
            plain.extend_from_slice(&body);
        }
        (sealed, plain, recv)
    }

    /// Drain a pump the way a relay does, counting the writes its batches would become.
    fn drain(wire: &mut Wire<Sealed>, recv: &mut Flow) -> (usize, Vec<u8>) {
        let mut writes = 0;
        let mut got = Vec::new();
        while let Some(batch) = wire.batch(recv) {
            if batch.is_empty() {
                continue;
            }
            writes += 1;
            got.extend_from_slice(batch);
        }
        (writes, got)
    }

    /// The flow's windows are not zeroed: the wire's receive window and the relay leg's
    /// read window are both read targets, so the zero pass in front of them was work
    /// generated and thrown away. The counting allocator's `zeroed` counter is the witness.
    #[test]
    fn the_flows_windows_are_not_zero_filled() {
        let (sealed, _plain, _recv) = frames(&[1000; 3]);
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let (wire, counts) = ferrox_core::alloc_count::measure(|| Wire::new(carrier));
        assert_eq!(counts.zeroed, 0, "the wire's window is not zeroed");
        assert_eq!(counts.allocs, 1, "the wire's window is the only allocation");
        assert_eq!(
            counts.bytes, WIRE_LEN,
            "and it is the window the wire reads into"
        );
        drop(wire);
        let (window, counts) = ferrox_core::alloc_count::measure(relay_window);
        assert_eq!(counts.zeroed, 0, "the relay leg's window is not zeroed");
        assert_eq!(
            counts.allocs, 1,
            "the relay leg's window is the only allocation"
        );
        assert_eq!(
            counts.bytes, READ_PLAIN,
            "and it is the window the leg reads into"
        );
        drop(window);
    }

    #[test]
    fn a_batch_of_frames_leaves_the_pump_in_one_write() {
        let (sealed, plain, mut recv) = frames(&vec![1000; FRAMES_PER_WRITE * 2 + 1]);
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let (writes, got) = drain(&mut wire, &mut recv);
        assert_eq!(
            writes, 3,
            "a batch takes at most FRAMES_PER_WRITE frames, so they leave as {FRAMES_PER_WRITE}, {FRAMES_PER_WRITE} and 1"
        );
        assert_eq!(got, plain, "and every byte of them, in order");
        assert_eq!(
            wire.carrier.reads, 2,
            "the stream is read once, plus the read that finds its end"
        );
    }

    #[test]
    fn a_dribbled_carrier_still_offers_one_frame_and_loses_nothing() {
        let (sealed, plain, mut recv) = frames(&[1000; 9]);
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: 3,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let (writes, got) = drain(&mut wire, &mut recv);
        assert_eq!(
            writes, 9,
            "a carrier that gives three bytes at a time never holds a second frame, so nothing waits"
        );
        assert_eq!(got, plain, "and the bytes are the same bytes");
    }

    #[test]
    fn the_pump_gathers_into_its_own_buffer_and_never_moves_it() {
        let (sealed, plain, mut recv) = frames(&[1000; 3]);
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let cap = wire.held.capacity();
        let mut batches = 0;
        let mut got = Vec::new();
        while let Some(batch) = wire.batch(&mut recv) {
            if batch.is_empty() {
                continue;
            }
            let (front, len) = (batch.as_ptr() as usize, batch.len());
            got.extend_from_slice(batch);
            assert_eq!(
                front,
                wire.held.as_ptr() as usize,
                "a batch is not the pump's own bytes gathered at its front"
            );
            assert_eq!(wire.held.capacity(), cap, "the pump grew its buffer");
            assert_eq!(got.len(), len, "and the whole batch was handed over");
            batches += 1;
        }
        assert_eq!(batches, 1, "three frames together are one write");
        assert_eq!(got, plain);
    }

    #[test]
    fn an_end_marker_mid_batch_sends_what_the_batch_already_holds() {
        let (mut sealed, plain, mut recv) = frames(&[1000, 1000]);
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(
            stage_frame(&mut send, &[], &mut sealed, &mut pad),
            "seals the marker"
        );
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let (writes, got) = drain(&mut wire, &mut recv);
        assert_eq!(
            writes, 1,
            "the two frames that came first are not lost to the marker"
        );
        assert_eq!(got, plain);
    }
}
