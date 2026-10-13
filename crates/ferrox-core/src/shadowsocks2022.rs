use crate::aead::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_seal_in_place};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const XNONCE_LEN: usize = 24;
pub const LENGTH_LEN: usize = 2;
pub const MAX_CHUNK: usize = 0xFFFF;
pub const BLOCK_LEN: usize = 16;
pub const TIMESTAMP_SKEW: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Method {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Self::Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Self::Aes256Gcm,
            "2022-blake3-chacha20-poly1305" => Self::Chacha20Poly1305,
            _ => return None,
        })
    }
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }
    #[must_use]
    pub const fn is_chacha(self) -> bool {
        matches!(self, Self::Chacha20Poly1305)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[must_use]
pub fn parse_psk(password: &str, key_len: usize) -> Option<Vec<u8>> {
    let clean = password.trim();
    if let Some(decoded) = crate::b64::decode(clean.as_bytes()) {
        if decoded.len() == key_len {
            return Some(decoded);
        }
    }
    let raw = clean.as_bytes();
    if raw.len() == key_len {
        return Some(raw.to_vec());
    }
    None
}

#[must_use]
pub fn parse_psk_list(password: &str, key_len: usize) -> Option<Vec<Vec<u8>>> {
    let parts: Vec<Vec<u8>> = password
        .split(':')
        .map(|p| parse_psk(p, key_len))
        .collect::<Option<Vec<_>>>()?;
    if parts.is_empty() {
        return None;
    }
    Some(parts)
}

fn derive32(context: &str, psk: &[u8], salt: &[u8]) -> Option<[u8; 32]> {
    if psk.len() + salt.len() > 64 {
        return None;
    }
    let mut material = [0u8; 64];
    material[..psk.len()].copy_from_slice(psk);
    material[psk.len()..psk.len() + salt.len()].copy_from_slice(salt);
    Some(blake3::derive_key(
        context,
        &material[..psk.len() + salt.len()],
    ))
}

#[must_use]
pub fn session_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    derive32("shadowsocks 2022 session subkey", psk, salt)
        .map_or_else(Vec::new, |full| full[..key_len].to_vec())
}

#[must_use]
pub fn identity_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    derive32("shadowsocks 2022 identity subkey", psk, salt)
        .map_or_else(Vec::new, |full| full[..key_len].to_vec())
}

#[must_use]
pub fn user_hash(psk: &[u8]) -> [u8; BLOCK_LEN] {
    let digest = blake3::hash(psk);
    let mut out = [0u8; BLOCK_LEN];
    out.copy_from_slice(&digest.as_bytes()[..BLOCK_LEN]);
    out
}

#[must_use]
pub fn block_encrypt(key: &[u8], block: &[u8; BLOCK_LEN]) -> Option<[u8; BLOCK_LEN]> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let mut out = (*block).into();
    match key.len() {
        16 => aes::Aes128::new_from_slice(key)
            .ok()?
            .encrypt_block(&mut out),
        32 => aes::Aes256::new_from_slice(key)
            .ok()?
            .encrypt_block(&mut out),
        _ => return None,
    }
    Some(out.into())
}

#[must_use]
pub fn block_decrypt(key: &[u8], block: &[u8; BLOCK_LEN]) -> Option<[u8; BLOCK_LEN]> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    let mut out = (*block).into();
    match key.len() {
        16 => aes::Aes128::new_from_slice(key)
            .ok()?
            .decrypt_block(&mut out),
        32 => aes::Aes256::new_from_slice(key)
            .ok()?
            .decrypt_block(&mut out),
        _ => return None,
    }
    Some(out.into())
}

#[must_use]
pub fn encrypt_eih(
    method: Method,
    identity_psk: &[u8],
    salt: &[u8],
    user_psk: &[u8],
) -> Option<[u8; BLOCK_LEN]> {
    if method.is_chacha() {
        return None;
    }
    let full = derive32("shadowsocks 2022 identity subkey", identity_psk, salt)?;
    block_encrypt(&full[..method.key_len()], &user_hash(user_psk))
}

#[must_use]
pub fn decrypt_eih(
    method: Method,
    identity_psk: &[u8],
    salt: &[u8],
    eih: &[u8; BLOCK_LEN],
) -> Option<[u8; BLOCK_LEN]> {
    if method.is_chacha() {
        return None;
    }
    let full = derive32("shadowsocks 2022 identity subkey", identity_psk, salt)?;
    block_decrypt(&full[..method.key_len()], eih)
}

#[must_use]
pub fn encrypt_udp_eih(
    master: &[u8],
    raw: &[u8; BLOCK_LEN],
    hash: &[u8; BLOCK_LEN],
) -> Option<[u8; BLOCK_LEN]> {
    let mut plain = [0u8; BLOCK_LEN];
    for (p, (h, r)) in plain.iter_mut().zip(hash.iter().zip(raw.iter())) {
        *p = h ^ r;
    }
    block_encrypt(master, &plain)
}

#[must_use]
pub fn decrypt_udp_eih(
    master: &[u8],
    raw: &[u8; BLOCK_LEN],
    eih: &[u8; BLOCK_LEN],
) -> Option<[u8; BLOCK_LEN]> {
    let mut plain = block_decrypt(master, eih)?;
    for (p, r) in plain.iter_mut().zip(raw.iter()) {
        *p ^= *r;
    }
    Some(plain)
}

#[derive(Debug)]
pub struct Cipher {
    method: Method,
    key: [u8; 32],
    counter: u64,
    aead: Aead,
}

enum Aead {
    Aes128(crate::aesgcm::Aes128Gcm),
    Aes256(crate::aesgcm::Aes256Gcm),
    ChaCha,
}

impl std::fmt::Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128(_) => "2022-blake3-aes-128-gcm",
            Self::Aes256(_) => "2022-blake3-aes-256-gcm",
            Self::ChaCha => "2022-blake3-chacha20-poly1305",
        })
    }
}

impl Cipher {
    #[must_use]
    pub fn from_psk(method: Method, psk: &[u8], salt: &[u8]) -> Option<Self> {
        if psk.len() != method.key_len() || salt.len() != method.key_len() {
            return None;
        }
        let full = derive32("shadowsocks 2022 session subkey", psk, salt)?;
        Self::from_subkey(method, &full[..method.key_len()])
    }
    #[must_use]
    pub fn from_subkey(method: Method, subkey: &[u8]) -> Option<Self> {
        if subkey.len() != method.key_len() {
            return None;
        }
        let mut key = [0u8; 32];
        key[..subkey.len()].copy_from_slice(subkey);
        let aead = match method {
            Method::Aes128Gcm => {
                Aead::Aes128(crate::aesgcm::Aes128Gcm::new(key[..16].try_into().ok()?))
            }
            Method::Aes256Gcm => {
                Aead::Aes256(crate::aesgcm::Aes256Gcm::new(key[..32].try_into().ok()?))
            }
            Method::Chacha20Poly1305 => Aead::ChaCha,
        };
        Some(Self {
            method,
            key,
            counter: 0,
            aead,
        })
    }
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }
    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Option<()> {
        let at = out.len();
        out.extend_from_slice(plaintext);
        self.seal_tail_in_place(out, at)
    }
    pub fn seal_tail_in_place(&mut self, out: &mut Vec<u8>, at: usize) -> Option<()> {
        let tag = self.seal_piece_in_place(&mut out[at..])?;
        out.extend_from_slice(&tag);
        Some(())
    }
    /// Seal one piece where it lies and hand back its tag, so a caller with
    /// no room for the tag (a full read buffer) can carry it beside the piece
    /// instead of staging the piece through a second buffer.
    pub fn seal_piece_in_place(&mut self, body: &mut [u8]) -> Option<[u8; TAG_LEN]> {
        let nonce = self.nonce();
        let tag = match &self.aead {
            Aead::Aes128(c) => c.seal_in_place(&nonce, b"", body),
            Aead::Aes256(c) => c.seal_in_place(&nonce, b"", body),
            Aead::ChaCha => chacha20_poly1305_seal_in_place(&self.key, &nonce, b"", body),
        };
        self.advance()?;
        Some(tag)
    }
    pub fn open_in_place(&mut self, chunk: &mut [u8]) -> Option<usize> {
        if chunk.len() < TAG_LEN {
            return None;
        }
        let nonce = self.nonce();
        let split = chunk.len() - TAG_LEN;
        let (body, tag) = chunk.split_at_mut(split);
        let tag: &[u8; TAG_LEN] = (&*tag).try_into().ok()?;
        let opened: Option<()> = match &mut self.aead {
            Aead::Aes128(c) => c.open_in_place(&nonce, b"", body, tag).map(|_| ()),
            Aead::Aes256(c) => c.open_in_place(&nonce, b"", body, tag).map(|_| ()),
            Aead::ChaCha => {
                chacha20_poly1305_decrypt_in_place(&self.key, &nonce, b"", body, tag).map(|_| ())
            }
        };
        opened?;
        self.advance()?;
        Some(split)
    }
    fn advance(&mut self) -> Option<()> {
        self.counter = self.counter.checked_add(1)?;
        Some(())
    }
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Option<()> {
        let at = out.len();
        out.extend_from_slice(plaintext);
        let body = &mut out[at..];
        let tag = match &self.aead {
            Aead::Aes128(c) => c.seal_in_place(nonce, b"", body),
            Aead::Aes256(c) => c.seal_in_place(nonce, b"", body),
            Aead::ChaCha => chacha20_poly1305_seal_in_place(&self.key, nonce, b"", body),
        };
        out.extend_from_slice(&tag);
        Some(())
    }
    pub fn seal_tail_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        out: &mut Vec<u8>,
        at: usize,
    ) -> Option<()> {
        let body = out.get_mut(at..)?;
        let tag = match &self.aead {
            Aead::Aes128(c) => c.seal_in_place(nonce, b"", body),
            Aead::Aes256(c) => c.seal_in_place(nonce, b"", body),
            Aead::ChaCha => chacha20_poly1305_seal_in_place(&self.key, nonce, b"", body),
        };
        out.extend_from_slice(&tag);
        Some(())
    }
    pub fn open_with_nonce(&self, nonce: &[u8; NONCE_LEN], chunk: &mut [u8]) -> Option<usize> {
        if chunk.len() < TAG_LEN {
            return None;
        }
        let split = chunk.len() - TAG_LEN;
        let (body, tag) = chunk.split_at_mut(split);
        let tag: &[u8; TAG_LEN] = (&*tag).try_into().ok()?;
        match &self.aead {
            Aead::Aes128(c) => c.open_in_place(nonce, b"", body, tag)?,
            Aead::Aes256(c) => c.open_in_place(nonce, b"", body, tag)?,
            Aead::ChaCha => chacha20_poly1305_decrypt_in_place(&self.key, nonce, b"", body, tag)?,
        };
        Some(split)
    }
    #[must_use]
    pub fn x_nonce(&self) -> [u8; XNONCE_LEN] {
        let mut nonce = [0u8; XNONCE_LEN];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }
}

#[must_use]
pub fn x_seal(
    psk: &[u8],
    nonce: &[u8; XNONCE_LEN],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Option<()> {
    if psk.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(psk);
    let sub = crate::chacha::hchacha(&key, &nonce[..16].try_into().ok()?);
    let mut inner = [0u8; NONCE_LEN];
    inner[4..].copy_from_slice(&nonce[16..]);
    let at = out.len();
    out.extend_from_slice(plaintext);
    let body = &mut out[at..];
    let tag = chacha20_poly1305_seal_in_place(&sub, &inner, b"", body);
    out.extend_from_slice(&tag);
    Some(())
}

#[must_use]
pub fn x_seal_tail(
    psk: &[u8],
    nonce: &[u8; XNONCE_LEN],
    out: &mut Vec<u8>,
    at: usize,
) -> Option<()> {
    if psk.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(psk);
    let sub = crate::chacha::hchacha(&key, nonce[..16].try_into().ok()?);
    let mut inner = [0u8; NONCE_LEN];
    inner[4..].copy_from_slice(&nonce[16..]);
    let body = out.get_mut(at..)?;
    let tag = chacha20_poly1305_seal_in_place(&sub, &inner, b"", body);
    out.extend_from_slice(&tag);
    Some(())
}

#[must_use]
pub fn x_open(psk: &[u8], nonce: &[u8; XNONCE_LEN], chunk: &mut [u8]) -> Option<usize> {
    if psk.len() != 32 || chunk.len() < TAG_LEN {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(psk);
    let sub = crate::chacha::hchacha(&key, &nonce[..16].try_into().ok()?);
    let mut inner = [0u8; NONCE_LEN];
    inner[4..].copy_from_slice(&nonce[16..]);
    let split = chunk.len() - TAG_LEN;
    let (body, tag) = chunk.split_at_mut(split);
    let tag: &[u8; TAG_LEN] = (&*tag).try_into().ok()?;
    chacha20_poly1305_decrypt_in_place(&sub, &inner, b"", body, tag)?;
    Some(split)
}

pub struct SlidingWindow {
    last: u64,
    ring: [u64; 128],
}

impl SlidingWindow {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: 0,
            ring: [0u64; 128],
        }
    }
    #[must_use]
    pub fn check(&self, id: u64) -> bool {
        if id > self.last {
            return true;
        }
        if self.last - id > 8128 {
            return false;
        }
        let block = ((id >> 6) & 127) as usize;
        let bit = id & 63;
        (self.ring[block] >> bit) & 1 == 0
    }
    pub fn add(&mut self, id: u64) {
        if id > self.last {
            let mut diff = (id >> 6).wrapping_sub(self.last >> 6);
            if diff > 128 {
                diff = 128;
            }
            let mut idx = self.last >> 6;
            for _ in 0..diff {
                idx = (idx + 1) & 127;
                self.ring[idx as usize] = 0;
            }
            self.last = id;
        }
        let block = ((id >> 6) & 127) as usize;
        self.ring[block] |= 1 << (id & 63);
    }
    #[must_use]
    pub fn check_and_add(&mut self, id: u64) -> bool {
        if !self.check(id) {
            return false;
        }
        self.add(id);
        true
    }
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SlidingWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlidingWindow")
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;

    #[test]
    fn the_method_table_is_the_2022_spellings() {
        for (name, want) in [
            ("2022-blake3-aes-128-gcm", Method::Aes128Gcm),
            ("2022-blake3-aes-256-gcm", Method::Aes256Gcm),
            ("2022-blake3-chacha20-poly1305", Method::Chacha20Poly1305),
        ] {
            assert_eq!(Method::parse(name), Some(want), "{name}");
            assert_eq!(
                Method::parse(&name.to_ascii_uppercase()),
                Some(want),
                "{name} shouted"
            );
        }
        for name in [
            "",
            "aes-128-gcm",
            "aes-256-gcm",
            "aes-192-gcm",
            "rc4-md5",
            "none",
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "chacha20-ietf",
            "xchacha20",
            "chacha20-ietf-poly1305",
            "xchacha20-ietf-poly1305",
        ] {
            assert_eq!(Method::parse(name), None, "{name}");
        }
    }

    #[test]
    fn psk_text_is_base64_or_raw_at_the_key_length() {
        let raw16 = "MDEyMzQ1Njc4OWFiY2RlZg==";
        assert_eq!(parse_psk(raw16, 16).expect("decodes").len(), 16);
        assert!(parse_psk("short", 16).is_none());
        assert_eq!(parse_psk("0123456789abcdef", 16).expect("raw").len(), 16);
        let list = parse_psk_list(&format!("{raw16}:{raw16}"), 16).expect("lists");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn every_method_round_trips_a_chunk_and_refuses_a_forged_tag() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let psk = vec![0x77u8; method.key_len()];
            let salt = vec![0x5au8; method.key_len()];
            let mut sender = Cipher::from_psk(method, &psk, &salt).expect("derives");
            let mut receiver = Cipher::from_psk(method, &psk, &salt).expect("derives");
            for len in [0usize, 1, 63, 64, 1024, MAX_CHUNK] {
                let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
                let mut wire = Vec::new();
                sender.seal_into(&plain, &mut wire).expect("seals");
                assert_eq!(wire.len(), plain.len() + TAG_LEN, "{method} len {len}");
                let opened = receiver.open_in_place(&mut wire).expect("opens");
                assert_eq!(&wire[..opened], &plain[..], "{method} len {len}");
                let mut forged = wire.clone();
                forged[0] ^= 1;
                let as_sent = forged.clone();
                assert!(
                    receiver.open_in_place(&mut forged).is_none(),
                    "{method} len {len}"
                );
                assert_eq!(
                    forged, as_sent,
                    "{method} len {len}: refused input stays sealed"
                );
            }
        }
    }

    #[test]
    fn seals_match_the_crates_they_replace() {
        let psk16 = [0x11u8; 16];
        let salt16 = [0x22u8; 16];
        let sub16 = session_subkey(&psk16, &salt16, 16);
        let reference = aes_gcm::Aes128Gcm::new_from_slice(&sub16).expect("key");
        let mut ours = Cipher::from_psk(Method::Aes128Gcm, &psk16, &salt16).expect("derives");
        let mut wire = Vec::new();
        ours.seal_into(b"ping", &mut wire).expect("seals");
        let (ct, tag) = wire.split_at(4);
        let mut want = b"ping".to_vec();
        let want_tag = reference
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&[0u8; 12]), b"", &mut want)
            .expect("seals");
        assert_eq!(ct, &want[..]);
        assert_eq!(tag, &want_tag[..]);
        let psk32 = [0x33u8; 32];
        let salt32 = [0x44u8; 32];
        let sub32 = session_subkey(&psk32, &salt32, 32);
        let reference = aes_gcm::Aes256Gcm::new_from_slice(&sub32).expect("key");
        let mut ours = Cipher::from_psk(Method::Aes256Gcm, &psk32, &salt32).expect("derives");
        let mut wire = Vec::new();
        ours.seal_into(b"ping", &mut wire).expect("seals");
        let (ct, tag) = wire.split_at(4);
        let mut want = b"ping".to_vec();
        let want_tag = reference
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&[0u8; 12]), b"", &mut want)
            .expect("seals");
        assert_eq!(ct, &want[..]);
        assert_eq!(tag, &want_tag[..]);
    }

    #[test]
    fn xchacha_udp_matches_the_crate_it_replaces() {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        let psk = [0x55u8; 32];
        let nonce = [0x66u8; 24];
        let reference = XChaCha20Poly1305::new_from_slice(&psk).expect("key");
        for len in [0usize, 1, 64, 300] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(41)).collect();
            let mut wire = Vec::new();
            x_seal(&psk, &nonce, &plain, &mut wire).expect("seals");
            let (ct, tag) = wire.split_at(len);
            let mut want = plain.clone();
            let want_tag = reference
                .encrypt_in_place_detached(XNonce::from_slice(&nonce), b"", &mut want)
                .expect("seals");
            assert_eq!(ct, &want[..], "len {len}");
            assert_eq!(tag, &want_tag[..], "len {len}");
            let mut opened = wire.clone();
            assert_eq!(x_open(&psk, &nonce, &mut opened), Some(len));
            assert_eq!(&opened[..len], &plain[..]);
        }
    }

    #[test]
    fn tail_seals_are_the_copies_they_replace() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let psk = vec![0x5au8; method.key_len()];
            let salt = vec![0x6au8; method.key_len()];
            let cipher = Cipher::from_psk(method, &psk, &salt).expect("derives");
            for len in [0usize, 1, 64, 300] {
                let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();
                let nonce = [0x77u8; NONCE_LEN];
                let mut copied = Vec::new();
                cipher
                    .seal_with_nonce(&nonce, &plain, &mut copied)
                    .expect("seals");
                let mut placed = vec![0x55u8; 7];
                let at = placed.len();
                placed.extend_from_slice(&plain);
                cipher
                    .seal_tail_with_nonce(&nonce, &mut placed, at)
                    .expect("seals");
                assert_eq!(placed[at..], copied[..], "{method} len {len}");
            }
        }
        let psk = [0x55u8; 32];
        let nonce = [0x66u8; XNONCE_LEN];
        for len in [0usize, 1, 64, 300] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(41)).collect();
            let mut copied = Vec::new();
            x_seal(&psk, &nonce, &plain, &mut copied).expect("seals");
            let mut placed = vec![0x55u8; 24];
            let at = placed.len();
            placed.extend_from_slice(&plain);
            x_seal_tail(&psk, &nonce, &mut placed, at).expect("seals");
            assert_eq!(placed[at..], copied[..], "xchacha len {len}");
        }
    }

    #[test]
    fn eih_round_trips_through_the_identity_subkey() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let master = vec![0x11u8; method.key_len()];
            let user = vec![0x22u8; method.key_len()];
            let salt = vec![0x33u8; method.key_len()];
            let eih = encrypt_eih(method, &master, &salt, &user).expect("seals");
            let back = decrypt_eih(method, &master, &salt, &eih).expect("opens");
            assert_eq!(back, user_hash(&user));
        }
        assert!(
            encrypt_eih(Method::Chacha20Poly1305, &[0u8; 32], &[0u8; 32], &[0u8; 32]).is_none()
        );
    }

    #[test]
    fn udp_eih_round_trips_through_the_raw_block() {
        for key_len in [16usize, 32] {
            let master = vec![0x11u8; key_len];
            let user = vec![0x22u8; key_len];
            let raw = [0x33u8; BLOCK_LEN];
            let eih = encrypt_udp_eih(&master, &raw, &user_hash(&user)).expect("seals");
            let back = decrypt_udp_eih(&master, &raw, &eih).expect("opens");
            assert_eq!(back, user_hash(&user));
        }
    }

    #[test]
    fn the_window_rejects_replays_and_far_behind_ids() {
        let mut window = SlidingWindow::new();
        assert!(window.check_and_add(1));
        assert!(!window.check_and_add(1));
        assert!(window.check_and_add(2));
        assert!(window.check_and_add(9000));
        assert!(!window.check(0));
        assert!(!window.check_and_add(9000));
    }

    #[test]
    fn a_cipher_holds_one_heap_buffer_for_aes_and_none_for_chacha() {
        for (method, buffers) in [
            (Method::Aes128Gcm, 1usize),
            (Method::Aes256Gcm, 1),
            (Method::Chacha20Poly1305, 0),
        ] {
            let psk = vec![0x11u8; method.key_len()];
            let salt = vec![0x22u8; method.key_len()];
            let (cipher, counts) =
                crate::alloc_count::measure(|| Cipher::from_psk(method, &psk, &salt));
            assert!(cipher.is_some(), "{method} derives");
            assert_eq!(
                counts.allocs, buffers,
                "{method} holds {buffers} buffer(s), got {counts:?}"
            );
        }
    }
}
