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
        let zeros = vec![0u8; hash.len()];
        return mac(hash, &zeros, &[ikm]);
    }
    mac(hash, salt, &[ikm])
}

/// `HKDF-Expand(PRK, info, L)`, built from HMAC so one shape serves both hashes.
pub(crate) fn expand(hash: Hash, prk: &[u8], info: &[u8], out: &mut [u8]) {
    let key = hmac::Key::new(hash.hmac(), prk);
    let mut block: Vec<u8> = Vec::new();
    let mut at = 0;
    let mut counter = 1u8;
    while at < out.len() {
        let mut input = Vec::with_capacity(block.len() + info.len() + 1);
        input.extend_from_slice(&block);
        input.extend_from_slice(info);
        input.push(counter);
        block = hmac::sign(&key, &input).as_ref().to_vec();
        let take = block.len().min(out.len() - at);
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
    let mut info = Vec::with_capacity(label.len() + context.len() + 7);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((label.len() + 6) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    expand(hash, secret, &info, out);
}

/// `Derive-Secret`: the transcript hash under the label the schedule names.
pub(crate) fn derive(hash: Hash, secret: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; hash.len()];
    expand_label(hash, secret, label, &hash.hash(transcript), &mut out);
    out
}

fn mac(hash: Hash, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let key = hmac::Key::new(hash.hmac(), key);
    let mut ctx = hmac::Context::with_key(&key);
    for part in parts {
        ctx.update(part);
    }
    ctx.sign().as_ref().to_vec()
}

/// TLS 1.2's PRF: `P_hash` over the seed with the two labels the version splits.
pub(crate) fn prf(hash: Hash, secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let key = hmac::Key::new(hash.hmac(), secret);
    let mut full_seed = Vec::with_capacity(label.len() + seed.len());
    full_seed.extend_from_slice(label);
    full_seed.extend_from_slice(seed);
    let mut a = hmac::sign(&key, &full_seed).as_ref().to_vec();
    let mut at = 0;
    while at < out.len() {
        let mut input = Vec::with_capacity(a.len() + full_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&full_seed);
        let block = hmac::sign(&key, &input);
        let take = block.as_ref().len().min(out.len() - at);
        out[at..at + take].copy_from_slice(&block.as_ref()[..take]);
        at += take;
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }
}

/// The finished key of TLS 1.3 and the verify data it signs over a transcript.
pub(crate) fn finished_key(hash: Hash, traffic_secret: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; hash.len()];
    expand_label(hash, traffic_secret, b"finished", b"", &mut out);
    out
}

pub(crate) fn verify_data(hash: Hash, finished_key: &[u8], transcript: &[u8]) -> Vec<u8> {
    mac(hash, finished_key, &[&hash.hash(transcript)])
}
