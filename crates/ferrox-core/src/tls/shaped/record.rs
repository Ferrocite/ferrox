// The shaped client's record layer: both versions' framing over ring's AEADs.
use super::kdf::{self, Hash};
use crate::tls::TlsError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

/// The six AEAD suites a shaped hello names, three for each version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Sha256,
    EcdheAes128GcmSha256,
    EcdheAes256GcmSha384,
    EcdheChaCha20Sha256,
}

impl Suite {
    pub(crate) fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            0x1301 => Self::Aes128GcmSha256,
            0x1302 => Self::Aes256GcmSha384,
            0x1303 => Self::ChaCha20Sha256,
            0xc02b | 0xc02f => Self::EcdheAes128GcmSha256,
            0xc02c | 0xc030 => Self::EcdheAes256GcmSha384,
            0xcca9 | 0xcca8 => Self::EcdheChaCha20Sha256,
            _ => return None,
        })
    }

    pub(crate) fn is_tls13(self) -> bool {
        matches!(
            self,
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 | Self::ChaCha20Sha256
        )
    }

    pub(crate) fn hash(self) -> Hash {
        match self {
            Self::Aes128GcmSha256
            | Self::ChaCha20Sha256
            | Self::EcdheAes128GcmSha256
            | Self::EcdheChaCha20Sha256 => Hash::Sha256,
            Self::Aes256GcmSha384 | Self::EcdheAes256GcmSha384 => Hash::Sha384,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::EcdheAes128GcmSha256 => 16,
            _ => 32,
        }
    }

    /// The fixed IV a TLS 1.2 key block carries: four bytes for GCM's explicit nonce, twelve for `ChaCha`'s XOR nonce.
    pub(crate) fn fixed_iv_len(self) -> usize {
        match self {
            Self::EcdheAes128GcmSha256 | Self::EcdheAes256GcmSha384 => 4,
            _ => 12,
        }
    }

    fn algorithm(self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 | Self::EcdheAes128GcmSha256 => &ring::aead::AES_128_GCM,
            Self::Aes256GcmSha384 | Self::EcdheAes256GcmSha384 => &ring::aead::AES_256_GCM,
            Self::ChaCha20Sha256 | Self::EcdheChaCha20Sha256 => &ring::aead::CHACHA20_POLY1305,
        }
    }

    fn gcm(self) -> bool {
        matches!(
            self,
            Self::Aes128GcmSha256
                | Self::Aes256GcmSha384
                | Self::EcdheAes128GcmSha256
                | Self::EcdheAes256GcmSha384
        )
    }
}

/// One direction's keys and record counter: a sequence number reused under one key loses the record layer's integrity.
pub(crate) struct Direction {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
    gcm: bool,
    tls13: bool,
    hash: Hash,
    secret: Vec<u8>,
}

impl Direction {
    /// TLS 1.3 keys from a traffic secret: `HKDF-Expand-Label(secret, "key"/"iv", "", ...)`.
    pub(crate) fn tls13(suite: Suite, secret: &[u8]) -> Self {
        let hash = suite.hash();
        let mut key = vec![0u8; suite.key_len()];
        kdf::expand_label(hash, secret, b"key", b"", &mut key);
        let mut iv = [0u8; 12];
        kdf::expand_label(hash, secret, b"iv", b"", &mut iv);
        Self {
            key: keyed(suite, &key),
            iv,
            seq: 0,
            gcm: true,
            tls13: true,
            hash,
            secret: secret.to_vec(),
        }
    }

    /// TLS 1.2 keys from the expanded key block.
    pub(crate) fn tls12(suite: Suite, key: &[u8], iv: &[u8]) -> Self {
        let mut fixed = [0u8; 12];
        fixed[..iv.len()].copy_from_slice(iv);
        Self {
            key: keyed(suite, key),
            iv: fixed,
            seq: 0,
            gcm: suite.gcm(),
            tls13: false,
            hash: suite.hash(),
            secret: Vec::new(),
        }
    }

    /// The next traffic secret of a TLS 1.3 direction, `HKDF-Expand-Label(secret, "traffic upd", "", ...)`.
    pub(crate) fn update(&mut self) {
        let mut next = vec![0u8; self.secret.len()];
        kdf::expand_label(self.hash, &self.secret, b"traffic upd", b"", &mut next);
        let suite = if next.len() == 48 {
            Suite::Aes256GcmSha384
        } else {
            Suite::Aes128GcmSha256
        };
        let mut key = vec![0u8; suite.key_len()];
        kdf::expand_label(self.hash, &next, b"key", b"", &mut key);
        let mut iv = [0u8; 12];
        kdf::expand_label(self.hash, &next, b"iv", b"", &mut iv);
        self.key = keyed(suite, &key);
        self.iv = iv;
        self.seq = 0;
        self.secret = next;
    }

    fn nonce(&self, seq: u64) -> [u8; 12] {
        let bytes = seq.to_be_bytes();
        let mut nonce = self.iv;
        if self.tls13 || !self.gcm {
            for (slot, byte) in nonce[4..].iter_mut().zip(bytes) {
                *slot ^= byte;
            }
        } else {
            nonce[4..].copy_from_slice(&bytes);
        }
        nonce
    }

    /// Seals `plain` in place at `out[at..]` and appends the tag.
    fn seal(&mut self, aad: &[u8], at: usize, out: &mut Vec<u8>) -> Result<(), TlsError> {
        let nonce = Nonce::assume_unique_for_key(self.nonce(self.seq));
        self.seq = self.seq.wrapping_add(1);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut out[at..])
            .map_err(|_| TlsError::Other("record seal failed".to_owned()))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn open<'a>(&mut self, aad: &[u8], body: &'a mut [u8]) -> Result<&'a mut [u8], TlsError> {
        let nonce = Nonce::assume_unique_for_key(self.nonce(self.seq));
        self.seq = self.seq.wrapping_add(1);
        self.key
            .open_in_place(nonce, Aad::from(aad), body)
            .map_err(|_| TlsError::Other("record failed authentication".to_owned()))
    }

    /// A TLS 1.2 GCM record: the sender picks the explicit nonce, so the wire bytes complete the IV.
    fn open_explicit<'a>(
        &mut self,
        aad: &[u8],
        explicit: [u8; 8],
        body: &'a mut [u8],
    ) -> Result<&'a mut [u8], TlsError> {
        let mut nonce = self.iv;
        nonce[4..].copy_from_slice(&explicit);
        let nonce = Nonce::assume_unique_for_key(nonce);
        self.seq = self.seq.wrapping_add(1);
        self.key
            .open_in_place(nonce, Aad::from(aad), body)
            .map_err(|_| TlsError::Other("record failed authentication".to_owned()))
    }
}

fn keyed(suite: Suite, key: &[u8]) -> LessSafeKey {
    let unbound =
        UnboundKey::new(suite.algorithm(), key).expect("the key block names its own length");
    LessSafeKey::new(unbound)
}

/// Frames and seals one TLS 1.3 record whose plaintext is `plain` with `kind` as its inner type.
pub(crate) fn seal13(
    keys: &mut Direction,
    kind: u8,
    plain: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    seal13_parts(keys, kind, &[plain], out)
}

/// The same record with the plaintext handed as segments, so a framed write never stages a copy.
pub(crate) fn seal13_parts(
    keys: &mut Direction,
    kind: u8,
    parts: &[&[u8]],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let at = out.len();
    out.push(23);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&((len + 1 + 16) as u16).to_be_bytes());
    for part in parts {
        out.extend_from_slice(part);
    }
    out.push(kind);
    let aad = [out[at], out[at + 1], out[at + 2], out[at + 3], out[at + 4]];
    keys.seal(&aad, at + 5, out)
}

/// Opens one TLS 1.3 record body, appending the plaintext to `out` and returning its inner type.
pub(crate) fn open13(
    keys: &mut Direction,
    header: [u8; 5],
    mut body: Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<u8, TlsError> {
    let plain = keys.open(&header, &mut body)?;
    let at = plain
        .iter()
        .rposition(|&byte| byte != 0)
        .ok_or_else(|| TlsError::Other("record has no inner type".to_owned()))?;
    out.extend_from_slice(&plain[..at]);
    Ok(plain[at])
}

/// Seals one TLS 1.2 AEAD record of `kind`.
pub(crate) fn seal12(
    keys: &mut Direction,
    kind: u8,
    plain: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    seal12_parts(keys, kind, &[plain], out)
}

pub(crate) fn seal12_parts(
    keys: &mut Direction,
    kind: u8,
    parts: &[&[u8]],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let seq = keys.seq.to_be_bytes();
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq);
    aad[8] = kind;
    aad[9..11].copy_from_slice(&[0x03, 0x03]);
    aad[11..].copy_from_slice(&(len as u16).to_be_bytes());
    let at = out.len();
    let explicit = if keys.gcm { 8 } else { 0 };
    out.push(kind);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&((len + explicit + 16) as u16).to_be_bytes());
    if explicit == 8 {
        out.extend_from_slice(&seq);
    }
    for part in parts {
        out.extend_from_slice(part);
    }
    keys.seal(&aad, at + 5 + explicit, out)
}

/// Opens one TLS 1.2 AEAD record body, appending the plaintext to `out`.
pub(crate) fn open12(
    keys: &mut Direction,
    kind: u8,
    mut body: Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    let seq = keys.seq.to_be_bytes();
    let explicit = if keys.gcm { 8 } else { 0 };
    if body.len() < explicit + 16 {
        return Err(TlsError::Other("short TLS 1.2 record".to_owned()));
    }
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq);
    aad[8] = kind;
    aad[9..11].copy_from_slice(&[0x03, 0x03]);
    aad[11..].copy_from_slice(&((body.len() - explicit - 16) as u16).to_be_bytes());
    let plain = if keys.gcm {
        let explicit: [u8; 8] = body[..8].try_into().expect("eight-byte explicit nonce");
        keys.open_explicit(&aad, explicit, &mut body[explicit.len()..])?
    } else {
        keys.open(&aad, &mut body[explicit..])?
    };
    out.extend_from_slice(plain);
    Ok(())
}
