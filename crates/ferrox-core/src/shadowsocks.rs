use crate::aead::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_seal_in_place};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const XNONCE_LEN: usize = 24;
pub const LENGTH_LEN: usize = 2;
pub const MAX_CHUNK: usize = 0x3FFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    XChacha20Poly1305,
    Rc4Md5,
}

impl Method {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Self::Aes128Gcm,
            "aes-256-gcm" | "aead_aes_256_gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" | "chacha20-poly1305" => {
                Self::Chacha20Poly1305
            }
            "xchacha20-ietf-poly1305" | "aead_xchacha20_poly1305" => Self::XChacha20Poly1305,
            "rc4-md5" => Self::Rc4Md5,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Rc4Md5 => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 | Self::XChacha20Poly1305 => 32,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20Poly1305 => "chacha20-ietf-poly1305",
            Self::XChacha20Poly1305 => "xchacha20-ietf-poly1305",
            Self::Rc4Md5 => "rc4-md5",
        }
    }

    #[must_use]
    pub const fn is_stream(self) -> bool {
        matches!(self, Self::Rc4Md5)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug)]
pub struct Cipher {
    method: Method,
    key: Key,
    counter: u64,
    aead: Aead,
}

/// The `Aes` engines box their own key schedules and GHASH tables, so the enum
/// holds them by value: a second box around the same thing is one allocation
/// per connection and one per UDP datagram, for a pointer chase.
enum Aead {
    Aes128(crate::aesgcm::Aes128Gcm),
    Aes256(crate::aesgcm::Aes256Gcm),
    ChaCha,
    XChaCha,
}

impl std::fmt::Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128(_) => "aes-128-gcm",
            Self::Aes256(_) => "aes-256-gcm",
            Self::ChaCha => "chacha20-ietf-poly1305",
            Self::XChaCha => "xchacha20-ietf-poly1305",
        })
    }
}

type Key = [u8; 32];

impl Cipher {
    #[must_use]
    pub fn new(method: Method, password: &str, salt: &[u8]) -> Option<Self> {
        Self::from_master_key(method, &MasterKey::new(password, method.key_len()), salt)
    }

    #[must_use]
    pub fn from_master_key(method: Method, master: &MasterKey, salt: &[u8]) -> Option<Self> {
        let key_len = method.key_len();
        if master.as_bytes().len() != key_len {
            return None;
        }
        let mut key: Key = [0u8; 32];
        let hk = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), master.as_bytes());
        hk.expand(b"ss-subkey", &mut key[..key_len]).ok()?;
        let aead = match method {
            Method::Aes128Gcm => {
                Aead::Aes128(crate::aesgcm::Aes128Gcm::new(key[..16].try_into().ok()?))
            }
            Method::Aes256Gcm => Aead::Aes256(crate::aesgcm::Aes256Gcm::new(
                key[..key_len].try_into().ok()?,
            )),
            Method::Chacha20Poly1305 => Aead::ChaCha,
            Method::XChacha20Poly1305 => Aead::XChaCha,
            // A stream has no subkey, no counter and no tag: it lives in `Rc4`.
            Method::Rc4Md5 => return None,
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

    fn xnonce(&self) -> [u8; XNONCE_LEN] {
        let mut nonce = [0u8; XNONCE_LEN];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }

    fn xpair(&self) -> ([u8; 32], [u8; NONCE_LEN]) {
        let xnonce = self.xnonce();
        let subkey = crate::chacha::hchacha(
            &self.key,
            &xnonce[..16].try_into().expect("xnonce holds sixteen"),
        );
        let mut inner = [0u8; NONCE_LEN];
        inner[4..].copy_from_slice(&xnonce[16..]);
        (subkey, inner)
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
    /// no room for the tag (a full read buffer) can carry it beside the
    /// piece instead of staging the piece through a second buffer.
    pub fn seal_piece_in_place(&mut self, body: &mut [u8]) -> Option<[u8; TAG_LEN]> {
        let nonce = self.nonce();
        let tag = match &self.aead {
            Aead::Aes128(cipher) => cipher.seal_in_place(&nonce, b"", body),
            Aead::Aes256(cipher) => cipher.seal_in_place(&nonce, b"", body),
            Aead::ChaCha => chacha20_poly1305_seal_in_place(&self.key, &nonce, b"", body),
            Aead::XChaCha => {
                let (subkey, inner) = self.xpair();
                chacha20_poly1305_seal_in_place(&subkey, &inner, b"", body)
            }
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
            Aead::Aes128(cipher) => cipher.open_in_place(&nonce, b"", body, tag).map(|_| ()),
            Aead::Aes256(cipher) => cipher.open_in_place(&nonce, b"", body, tag).map(|_| ()),
            Aead::ChaCha => {
                chacha20_poly1305_decrypt_in_place(&self.key, &nonce, b"", body, tag).map(|_| ())
            }
            Aead::XChaCha => {
                let (subkey, inner) = self.xpair();
                chacha20_poly1305_decrypt_in_place(&subkey, &inner, b"", body, tag).map(|_| ())
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
}

/// The `rc4-md5` session key: one MD5 over the master key and the wire IV, so
/// every direction of every connection gets its own RC4 keystream.
#[must_use]
pub fn rc4_md5_key(master: &[u8], iv: &[u8; 16]) -> Option<[u8; 16]> {
    if master.len() != 16 {
        return None;
    }
    let mut input = [0u8; 32];
    input[..16].copy_from_slice(master);
    input[16..].copy_from_slice(iv);
    Some(md5::compute(input).0)
}

/// Keystream bytes per fold, wide enough that a block is two words.
const BLOCK: usize = 16;

/// RC4 as the stream ciphers use it: the state is the whole schedule, so a
/// direction costs 258 bytes on the stack, and crypting folds one keystream
/// block at a time over the caller's buffer with no heap buffer anywhere.
#[derive(Debug, Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    #[must_use]
    pub fn new(key: &[u8]) -> Option<Self> {
        if key.is_empty() || key.len() > 256 {
            return None;
        }
        let mut s = [0u8; 256];
        for (at, cell) in s.iter_mut().enumerate() {
            *cell = at as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        Some(Self { s, i: 0, j: 0 })
    }

    /// Sixteen PRGA steps at a time, into a block on this frame, then the block
    /// over the payload as two words: the state machine stays serial and the
    /// payload reads and writes leave it.
    pub fn crypt(&mut self, buf: &mut [u8]) {
        let (blocks, tail) = buf.as_chunks_mut::<BLOCK>();
        let mut block = [0u8; BLOCK];
        for chunk in blocks {
            self.keystream(&mut block);
            fold_keystream(chunk, &block);
        }
        for cell in &mut block[..tail.len()] {
            *cell = self.next_byte();
        }
        fold_keystream(tail, &block[..tail.len()]);
    }

    /// One PRGA step: three wrapping adds, two swaps and one table read.
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
        self.s.swap(usize::from(self.i), usize::from(self.j));
        let at = self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]);
        self.s[usize::from(at)]
    }

    /// The fill over a fixed array: the step count is in the type, so the walk
    /// of the state is straight-line code rather than a loop with its own trip.
    fn keystream<const N: usize>(&mut self, out: &mut [u8; N]) {
        for cell in out.iter_mut() {
            *cell = self.next_byte();
        }
    }
}

/// The block laid over the payload it belongs to, eight bytes at a time.
fn fold_keystream(dst: &mut [u8], key: &[u8]) {
    let (words, rest) = dst.as_chunks_mut::<8>();
    for (cell, block) in words.iter_mut().zip(key.as_chunks::<8>().0) {
        *cell = (u64::from_le_bytes(*cell) ^ u64::from_le_bytes(*block)).to_le_bytes();
    }
    let used = words.len() * 8;
    for (cell, &byte) in rest.iter_mut().zip(&key[used..]) {
        *cell ^= byte;
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MasterKey {
    bytes: Vec<u8>,
    rounds: usize,
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MasterKey({} bytes, {} rounds)",
            self.bytes.len(),
            self.rounds
        )
    }
}

impl MasterKey {
    #[must_use]
    pub fn new(password: &str, key_len: usize) -> Self {
        let rounds = key_len.div_ceil(16).max(1);
        let mut bytes = Vec::with_capacity(rounds * 16);
        let mut digest = md5::compute(password.as_bytes()).0;
        bytes.extend_from_slice(&digest);
        for _ in 1..rounds {
            let mut input = Vec::with_capacity(16 + password.len());
            input.extend_from_slice(&digest);
            input.extend_from_slice(password.as_bytes());
            digest = md5::compute(&input).0;
            bytes.extend_from_slice(&digest);
        }
        bytes.truncate(key_len);
        Self { bytes, rounds }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn rounds(&self) -> usize {
        self.rounds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    #[test]
    fn the_method_table_is_xrays_spelling_set() {
        for (name, want) in [
            ("aes-128-gcm", Method::Aes128Gcm),
            ("aead_aes_128_gcm", Method::Aes128Gcm),
            ("aes-256-gcm", Method::Aes256Gcm),
            ("aead_aes_256_gcm", Method::Aes256Gcm),
            ("chacha20-ietf-poly1305", Method::Chacha20Poly1305),
            ("aead_chacha20_poly1305", Method::Chacha20Poly1305),
            ("chacha20-poly1305", Method::Chacha20Poly1305),
            ("xchacha20-ietf-poly1305", Method::XChacha20Poly1305),
            ("aead_xchacha20_poly1305", Method::XChacha20Poly1305),
            ("  AES-256-GCM  ", Method::Aes256Gcm),
            ("rc4-md5", Method::Rc4Md5),
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
            "aes",
            "aes-192-gcm",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
            "chacha20",
            "none",
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "chacha20-ietf",
            "xchacha20",
        ] {
            assert_eq!(Method::parse(name), None, "{name}");
        }
    }

    #[test]
    fn the_master_key_is_the_md5_chain_and_no_longer() {
        let first = md5::compute(b"secret").0;
        let long = MasterKey::new("secret", 32);
        assert_eq!(long.rounds(), 2);
        assert_eq!(long.as_bytes()[..16], first);
        let mut input = Vec::new();
        input.extend_from_slice(&first);
        input.extend_from_slice(b"secret");
        assert_eq!(long.as_bytes()[16..], md5::compute(&input).0);

        let short = MasterKey::new("secret", 16);
        assert_eq!(short.rounds(), 1, "one MD5 covers one AES-128 key");
        assert_eq!(short.as_bytes(), &first[..], "and it is that first round");
        assert_eq!(
            short.as_bytes(),
            &long.as_bytes()[..16],
            "a truncated derivation is the shorter one"
        );
    }

    #[test]
    fn the_master_key_is_the_value_written_down() {
        assert_eq!(
            MasterKey::new("an-example-shared-password", 32).as_bytes(),
            b"\x5c\xb2\x9f\x91\x10\xb5\x40\xa6\xeb\x99\x5c\x35\x67\x1b\x75\x92\xa5\x07\xf5\
              \xdb\xe4\xac\x97\x7c\xae\x2f\x7b\x98\xde\xdc\x80\x22"
        );
        assert_eq!(
            MasterKey::new("an-example-shared-password", 16).as_bytes(),
            &MasterKey::new("an-example-shared-password", 32).as_bytes()[..16],
            "and the 16-byte key is that key's first half, not a shorter chain"
        );
    }

    #[test]
    fn the_nonce_is_a_little_endian_counter_in_the_first_eight_bytes() {
        let mut cipher = Cipher::new(Method::Aes256Gcm, "secret", &[0x5a; 32]).expect("derives");
        assert_eq!(cipher.nonce(), [0u8; NONCE_LEN], "chunk zero is all zero");
        for counter in [1u64, 255, 256, 257, u64::from(u32::MAX)] {
            cipher.counter = counter - 1;
            cipher.advance().expect("advances");
            assert_eq!(
                cipher.nonce(),
                {
                    let mut want = [0u8; NONCE_LEN];
                    want[..8].copy_from_slice(&counter.to_le_bytes());
                    want
                },
                "chunk {counter}"
            );
            assert_eq!(cipher.counter(), counter);
        }
        cipher.counter = 1;
        assert_eq!(&cipher.nonce()[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_ne!(&cipher.nonce()[..8], &1u64.to_be_bytes());
    }

    #[test]
    fn aes_gcm_refuses_the_other_methods_key_length() {
        let sixteen = [0x11u8; 16];
        let thirty_two = [0x11u8; 32];
        assert!(
            Aes256Gcm::new_from_slice(&sixteen).is_err(),
            "a 16-byte key is not an AES-256 key"
        );
        assert!(
            Aes128Gcm::new_from_slice(&thirty_two).is_err(),
            "a 32-byte key is not an AES-128 key"
        );
    }

    #[test]
    fn aes_128_is_its_own_cipher_and_not_a_widened_key() {
        let salt = [0x11u8; 32];
        let mut ours = Cipher::new(Method::Aes128Gcm, "secret", &salt).expect("derives");
        let narrow_key = ours.key[..16].to_vec();
        let mut mine = Vec::new();
        ours.seal_into(b"ping", &mut mine).expect("seals");

        let mut narrow = b"ping".to_vec();
        Aes128Gcm::new_from_slice(&narrow_key)
            .expect("takes 16 bytes")
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&[0u8; 12]), b"", &mut narrow)
            .expect("seals");
        assert_eq!(mine[..4], narrow[..4], "this is the 16-byte schedule");

        let other = Cipher::new(Method::Aes256Gcm, "secret", &salt).expect("derives");
        let mut widened = b"ping".to_vec();
        Aes256Gcm::new_from_slice(&other.key)
            .expect("takes 32 bytes")
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&[0u8; 12]), b"", &mut widened)
            .expect("seals");
        assert_ne!(
            mine[..4],
            widened[..4],
            "the 32-byte schedule is a different cipher, and a slice would pick it"
        );
    }

    #[test]
    fn every_method_round_trips_a_chunk_and_refuses_a_forged_tag() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
            Method::XChacha20Poly1305,
        ] {
            let salt = [0x77u8; 32];
            let mut sender = Cipher::new(method, "secret", &salt).expect("derives");
            let mut receiver = Cipher::new(method, "secret", &salt).expect("derives");
            assert_eq!(sender.method(), method);
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
                    "{method} len {len}: a forged tag is refused"
                );
                assert_eq!(
                    forged, as_sent,
                    "{method} len {len}: and a refused chunk is left exactly as it arrived"
                );
            }
        }
    }

    #[test]
    fn the_methods_are_not_interchangeable() {
        let salt = [0x5au8; 32];
        let mut sealed = Vec::new();
        Cipher::new(Method::Aes256Gcm, "secret", &salt)
            .expect("derives")
            .seal_into(b"ping", &mut sealed)
            .expect("seals");
        for method in [
            Method::Aes128Gcm,
            Method::Chacha20Poly1305,
            Method::XChacha20Poly1305,
        ] {
            assert!(
                Cipher::new(method, "secret", &salt)
                    .expect("derives")
                    .open_in_place(&mut sealed.clone())
                    .is_none(),
                "{method} cannot open an aes-256-gcm chunk"
            );
        }
        assert!(
            Cipher::new(Method::Aes256Gcm, "wrong", &salt)
                .expect("derives")
                .open_in_place(&mut sealed.clone())
                .is_none(),
            "and a wrong password cannot either"
        );
        let mut xsealed = Vec::new();
        Cipher::new(Method::XChacha20Poly1305, "secret", &salt)
            .expect("derives")
            .seal_into(b"ping", &mut xsealed)
            .expect("seals");
        assert!(
            Cipher::new(Method::Chacha20Poly1305, "secret", &salt)
                .expect("derives")
                .open_in_place(&mut xsealed.clone())
                .is_none(),
            "chacha cannot open an xchacha chunk"
        );
    }

    #[test]
    fn the_two_directions_count_independently() {
        let salt = [0x33u8; 32];
        let mut up = Cipher::new(Method::Chacha20Poly1305, "secret", &salt).expect("derives");
        let mut down = Cipher::new(Method::Chacha20Poly1305, "secret", &salt).expect("derives");
        let mut first = Vec::new();
        up.seal_into(b"a", &mut first).expect("seals");
        let mut second = Vec::new();
        down.seal_into(b"a", &mut second).expect("seals");
        assert_eq!(first, second, "both start at chunk zero");
        let mut third = Vec::new();
        up.seal_into(b"a", &mut third).expect("seals");
        let mut fourth = Vec::new();
        down.seal_into(b"a", &mut fourth).expect("seals");
        assert_eq!(third, fourth, "and both advance together");
    }

    /// One heap buffer per connection, not two: the `Aes` engines already box
    /// their key schedules and GHASH tables, so a box around the enum added a
    /// second allocation per connection and a second per UDP datagram, where
    /// `Datagrams::seal` and `open` build a `Cipher` from scratch.
    #[test]
    fn a_cipher_is_one_heap_buffer() {
        for (method, buffers) in [
            (Method::Aes128Gcm, 1usize),
            (Method::Aes256Gcm, 1),
            (Method::Chacha20Poly1305, 0),
            (Method::XChacha20Poly1305, 0),
        ] {
            let master = MasterKey::new("secret", method.key_len());
            let (cipher, counts) = crate::alloc_count::measure(|| {
                Cipher::from_master_key(method, &master, &[0x11; 32])
            });
            assert!(cipher.is_some(), "{method} derives");
            assert_eq!(
                counts.allocs, buffers,
                "{method} derives with {buffers} heap buffer(s), counted {counts:?}"
            );
        }
    }

    #[test]
    fn the_session_key_is_derived_at_the_methods_own_length() {
        for (method, len) in [
            (Method::Aes128Gcm, 16usize),
            (Method::Aes256Gcm, 32),
            (Method::Chacha20Poly1305, 32),
            (Method::XChacha20Poly1305, 32),
        ] {
            let salt = [0x09u8; 32];
            let cipher = Cipher::new(method, "secret", &salt).expect("derives");
            let master = MasterKey::new("secret", len);
            let mut want = [0u8; 32];
            hkdf::Hkdf::<sha1::Sha1>::new(Some(&salt), master.as_bytes())
                .expand(b"ss-subkey", &mut want[..len])
                .expect("expands");
            assert_eq!(&cipher.key[..len], &want[..len], "{method}");
        }
    }

    #[test]
    fn the_xnonce_is_a_little_endian_counter_in_the_first_eight_bytes() {
        let cipher =
            Cipher::new(Method::XChacha20Poly1305, "secret", &[0x5a; 32]).expect("derives");
        assert_eq!(cipher.xnonce(), [0u8; XNONCE_LEN], "chunk zero is all zero");
        let mut probe =
            Cipher::new(Method::XChacha20Poly1305, "secret", &[0x5a; 32]).expect("derives");
        for counter in [1u64, 255, 256, u64::from(u32::MAX)] {
            probe.counter = counter - 1;
            probe.advance().expect("advances");
            let mut want = [0u8; XNONCE_LEN];
            want[..8].copy_from_slice(&counter.to_le_bytes());
            assert_eq!(probe.xnonce(), want, "chunk {counter}");
        }
    }

    #[test]
    fn rc4_matches_the_published_vectors() {
        for (key, plain, cipher) in [
            (
                b"Key".as_slice(),
                b"Plaintext".as_slice(),
                &[0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3][..],
            ),
            (
                b"Wiki".as_slice(),
                b"pedia".as_slice(),
                &[0x10, 0x21, 0xBF, 0x04, 0x20][..],
            ),
        ] {
            let mut probe = plain.to_vec();
            Rc4::new(key)
                .expect("a short key schedules")
                .crypt(&mut probe);
            assert_eq!(&probe, cipher, "key {key:?}");
            let mut back = probe.clone();
            Rc4::new(key)
                .expect("a short key schedules")
                .crypt(&mut back);
            assert_eq!(&back, plain, "key {key:?}: the stream is its own inverse");
        }
        assert!(Rc4::new(&[]).is_none(), "an empty key schedules nothing");
        assert!(
            Rc4::new(&[0u8; 257]).is_none(),
            "a key past 256 bytes is refused"
        );
    }

    /// The PRGA written a second time, byte at a time, over its own table.
    /// `crypt` is only witnessed as bit-identical against a form that shares no
    /// code with it: a wrong keystream still round-trips itself, so no amount of
    /// encrypt-then-decrypt sees one.
    fn prga_bytes(key: &[u8], count: usize) -> Vec<u8> {
        let mut table = [0u8; 256];
        for (at, cell) in table.iter_mut().enumerate() {
            *cell = at as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(table[i]).wrapping_add(key[i % key.len()]);
            table.swap(i, usize::from(j));
        }
        let mut i = 0u8;
        let mut j = 0u8;
        (0..count)
            .map(|_| {
                i = i.wrapping_add(1);
                j = j.wrapping_add(table[usize::from(i)]);
                table.swap(usize::from(i), usize::from(j));
                let at = table[usize::from(i)].wrapping_add(table[usize::from(j)]);
                table[usize::from(at)]
            })
            .collect()
    }

    /// One keystream byte per payload byte, at the edges a block form can miss.
    #[test]
    fn the_keystream_is_the_prga_bytes_at_every_block_edge() {
        let stream = prga_bytes(b"ferrox-probe-key", 20_000);
        let plain: Vec<u8> = (0..20_000usize)
            .map(|i| (i as u8).wrapping_mul(37))
            .collect();

        let mut quiet = vec![0u8; 200];
        Rc4::new(b"ferrox-probe-key")
            .expect("schedules")
            .crypt(&mut quiet);
        assert_eq!(&quiet, &stream[..200], "an empty payload is the stream");

        for len in (0..=40usize).chain([
            63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4095, 4096, 8191, 16_383,
        ]) {
            let mut want = plain[..len].to_vec();
            for (cell, &byte) in want.iter_mut().zip(&stream) {
                *cell ^= byte;
            }
            let mut wire = plain[..len].to_vec();
            Rc4::new(b"ferrox-probe-key")
                .expect("schedules")
                .crypt(&mut wire);
            assert_eq!(wire, want, "one call of {len} bytes");
            let mut back = wire;
            Rc4::new(b"ferrox-probe-key")
                .expect("schedules")
                .crypt(&mut back);
            assert_eq!(back, plain[..len], "len {len}: the same stream decodes");
        }

        // A block filled past the payload would move a carried stream out of step.
        let mut carried = Rc4::new(b"ferrox-probe-key").expect("schedules");
        let mut off = 0usize;
        for len in [1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 3, 100usize] {
            let mut want = plain[off..off + len].to_vec();
            for (cell, byte) in want.iter_mut().zip(&stream[off..]) {
                *cell ^= *byte;
            }
            let mut chunk = plain[off..off + len].to_vec();
            carried.crypt(&mut chunk);
            assert_eq!(chunk, want, "call at {off} of {len} bytes");
            off += len;
        }
        assert!(off > 300, "the carried sweep should cross blocks");
    }

    /// The probe behind the `shadowsocks` ops row: `crypt` has no frame of its own once the release profile inlines it, so this frame is the 64 KiB stream and one fold over it, with no socket, no allocation and nothing else in the way.
    #[test]
    fn the_stream_cipher_costs_the_prga_loop_and_nothing_else() {
        let mut stream = Rc4::new(b"ferrox-probe-key").expect("a sixteen-byte key schedules");
        let mut buf = [0u8; 1024];
        let mut fold: u32 = 0;
        for _ in 0..64 {
            stream.crypt(&mut buf);
            for &byte in &buf {
                fold = fold.wrapping_mul(31).wrapping_add(u32::from(byte));
            }
        }
        assert_eq!(
            fold, 0x5ae1_42e5,
            "64 in-place calls over one buffer, folded after each"
        );
    }

    #[test]
    fn rc4_md5_round_trips_every_length_and_turns_on_its_key() {
        let master = MasterKey::new("secret", 16);
        let iv = [0x5au8; 16];
        let key = rc4_md5_key(master.as_bytes(), &iv).expect("derives");
        let mut joined = [0u8; 32];
        joined[..16].copy_from_slice(master.as_bytes());
        joined[16..].copy_from_slice(&iv);
        assert_eq!(
            key,
            md5::compute(joined).0,
            "the session key is MD5 of key then IV"
        );
        assert!(
            rc4_md5_key(&[0u8; 15], &iv).is_none(),
            "a short master derives nothing"
        );
        let mut checked = 0usize;
        for len in (0..=300usize).chain([511, 512, 1024, 4096]) {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let mut wire = plain.clone();
            Rc4::new(&key).expect("derives").crypt(&mut wire);
            if len > 0 {
                assert_ne!(wire, plain, "len {len}: the keystream does something");
            }
            let mut back = wire.clone();
            Rc4::new(&key).expect("derives").crypt(&mut back);
            assert_eq!(back, plain, "len {len}: round trips");
            if len > 0 {
                let mut wrong = wire.clone();
                let mut other_iv = iv;
                other_iv[0] ^= 1;
                let other = rc4_md5_key(master.as_bytes(), &other_iv).expect("derives");
                Rc4::new(&other).expect("derives").crypt(&mut wrong);
                assert_ne!(wrong, plain, "len {len}: one IV bit moves the stream");
            }
            checked += 1;
        }
        assert!(checked > 300, "the sweep should be dense, not a sample");
    }

    #[test]
    fn rc4_crypt_is_in_place_and_allocates_nothing() {
        let key = [0x11u8; 16];
        let mut buf: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let at = buf.as_ptr() as usize;
        let room = buf.capacity();
        Rc4::new(&key).expect("derives").crypt(&mut buf);
        Rc4::new(&key).expect("derives").crypt(&mut buf);
        assert_eq!(buf.as_ptr() as usize, at, "the buffer never moves");
        assert_eq!(buf.capacity(), room, "the buffer never grows");
        let (stream, counts) = crate::alloc_count::measure(|| Rc4::new(&key));
        assert!(stream.is_some(), "schedules");
        assert_eq!(
            counts.allocs, 0,
            "scheduling costs no heap buffer, counted {counts:?}"
        );
        let mut keystream = vec![0u8; 512];
        let ((), crypts) = crate::alloc_count::measure(|| {
            Rc4::new(&key).expect("derives").crypt(&mut keystream);
        });
        assert_eq!(
            crypts.allocs, 0,
            "crypting costs no heap buffer, counted {crypts:?}"
        );
    }

    #[test]
    fn xchacha_is_byte_identical_to_the_crate_it_replaces() {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        let salts = [[0x77u8; 32], [0x00u8; 32], [0xffu8; 32]];
        for salt in &salts {
            let sender = Cipher::new(Method::XChacha20Poly1305, "secret", salt).expect("derives");
            let session: [u8; 32] = sender.key;
            let reference = XChaCha20Poly1305::new_from_slice(&session).expect("key");
            for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 300, 1024] {
                let mut probe =
                    Cipher::new(Method::XChacha20Poly1305, "secret", salt).expect("derives");
                let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(41)).collect();
                let mut wire = Vec::new();
                probe.seal_into(&plain, &mut wire).expect("seals");
                let (ct, tag) = wire.split_at(len);
                let mut want_ct = plain.clone();
                let want_tag = reference
                    .encrypt_in_place_detached(
                        XNonce::from_slice(&[0u8; XNONCE_LEN]),
                        b"",
                        &mut want_ct,
                    )
                    .expect("seals");
                assert_eq!(ct, &want_ct[..], "ciphertext len {len}");
                assert_eq!(tag, &want_tag[..], "tag len {len}");
            }
        }
    }
}
