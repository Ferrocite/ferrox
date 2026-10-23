// TLS 1.3's HKDF schedule and the transcript hashes both versions share.
use ring::{digest, hmac};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn digest(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
        }
    }

    pub(crate) fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
        }
    }

    pub(crate) fn hash(self, data: &[u8]) -> Vec<u8> {
        digest::digest(self.digest(), data).as_ref().to_vec()
    }
}

/// `HKDF-Extract(salt, IKM)`: an empty salt is a run of zero bytes, as RFC 8446 writes `0`.
pub(crate) fn extract(hash: Hash, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    if salt.is_empty() {
        let zeros = [0u8; 48];
        return mac(hash, &zeros[..hash.len()], &[ikm]);
    }
    mac(hash, salt, &[ikm])
}

/// `HKDF-Expand(PRK, info, L)` over the info pieces RFC 8446 §7.1 frames, joined without a buffer.
fn expand_parts(hash: Hash, prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    let key = hmac::Key::new(hash.hmac(), prk);
    let mut block = [0u8; 64];
    let mut block_len = 0usize;
    let mut at = 0;
    let mut counter = 1u8;
    while at < out.len() {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&block[..block_len]);
        for part in info {
            ctx.update(part);
        }
        ctx.update(&[counter]);
        let tag = ctx.sign();
        block[..tag.as_ref().len()].copy_from_slice(tag.as_ref());
        block_len = tag.as_ref().len();
        let take = block_len.min(out.len() - at);
        out[at..at + take].copy_from_slice(&block[..take]);
        at += take;
        counter = counter.wrapping_add(1);
    }
}

/// `HKDF-Expand-Label`: the length, a `tls13 `-prefixed label, and the context, as RFC 8446 §7.1 frames them.
pub(crate) fn expand_label(
    hash: Hash,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    let length = (out.len() as u16).to_be_bytes();
    let framed = [(label.len() + 6) as u8];
    let held = [context.len() as u8];
    expand_parts(
        hash,
        secret,
        &[&length, &framed, b"tls13 ", label, &held, context],
        out,
    );
}

/// `Derive-Secret`: the transcript hash under the label the schedule names.
pub(crate) fn derive(hash: Hash, secret: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; hash.len()];
    let digest = digest::digest(hash.digest(), transcript);
    expand_label(hash, secret, label, digest.as_ref(), &mut out);
    out
}

/// HMAC over the parts in order: one message the record layer splits rather than copies.
pub(crate) fn sign(key: &hmac::Key, parts: &[&[u8]]) -> hmac::Tag {
    let mut ctx = hmac::Context::with_key(key);
    for part in parts {
        ctx.update(part);
    }
    ctx.sign()
}

fn mac(hash: Hash, secret: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    sign(&hmac::Key::new(hash.hmac(), secret), parts)
        .as_ref()
        .to_vec()
}

/// TLS 1.2's PRF: `P_hash` over the seed with the two labels the version splits.
pub(crate) fn prf(hash: Hash, secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let key = hmac::Key::new(hash.hmac(), secret);
    let mut a = {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(label);
        ctx.update(seed);
        ctx.sign()
    };
    let mut at = 0;
    while at < out.len() {
        let block = {
            let mut ctx = hmac::Context::with_key(&key);
            ctx.update(a.as_ref());
            ctx.update(label);
            ctx.update(seed);
            ctx.sign()
        };
        let bytes = block.as_ref();
        let take = bytes.len().min(out.len() - at);
        out[at..at + take].copy_from_slice(&bytes[..take]);
        at += take;
        a = {
            let mut ctx = hmac::Context::with_key(&key);
            ctx.update(a.as_ref());
            ctx.sign()
        };
    }
}

/// The finished key of TLS 1.3 and the verify data it signs over a transcript.
pub(crate) fn finished_key(hash: Hash, traffic_secret: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; hash.len()];
    expand_label(hash, traffic_secret, b"finished", b"", &mut out);
    out
}

pub(crate) fn verify_data(hash: Hash, finished_key: &[u8], transcript: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hash.hmac(), finished_key);
    let digest = digest::digest(hash.digest(), transcript);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(digest.as_ref());
    ctx.sign().as_ref().to_vec()
}

/// The record MAC of a TLS 1.2 CBC suite. SHA-1 is what the `-SHA` identifiers name, and it
/// never reaches the PRF: only a suite's SHA384 flag moves that hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mac {
    Sha1,
    Sha256,
}

impl Mac {
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    fn algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
        }
    }

    pub(crate) fn key(self, secret: &[u8]) -> hmac::Key {
        hmac::Key::new(self.algorithm(), secret)
    }
}
