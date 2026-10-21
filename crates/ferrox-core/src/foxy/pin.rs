//! Leaf-key pinning, authoritative for the leaf it names: a pin is `sha256/` plus base64 of SHA-256 over the leaf's `SubjectPublicKeyInfo`, so a chain this device cannot build still verifies against that key; an empty set pins and refuses nothing.

use crate::b64;
use sha2::{Digest, Sha256};

/// The DER of the leaf's `SubjectPublicKeyInfo`, or `None` when the certificate is not the X.509 structure this walk expects.
#[must_use]
pub fn leaf_spki(leaf_der: &[u8]) -> Option<&[u8]> {
    let (tag, tbs, _) = element(leaf_der, 0)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = element(leaf_der, tbs)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut at = tbs;
    let (tag, _, after) = element(leaf_der, at)?;
    at = after;
    if tag == CONTEXT_0 {
        let (tag, _, after) = element(leaf_der, at)?;
        at = after;
        if tag != INTEGER {
            return None;
        }
    }
    for want in [SEQUENCE; 4] {
        let (tag, _, after) = element(leaf_der, at)?;
        if tag != want {
            return None;
        }
        at = after;
    }
    let start = at;
    let (tag, _, end) = element(leaf_der, at)?;
    if tag != SEQUENCE {
        return None;
    }
    Some(&leaf_der[start..end])
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const CONTEXT_0: u8 = 0xA0;

/// Returns the tag, the offset of the first content byte and the offset past this element, refusing any length that does not fit the buffer.
fn element(der: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(at)?;
    let first = *der.get(at + 1)?;
    let (len, body) = if first < 0x80 {
        (usize::from(first), at + 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 8 {
            return None;
        }
        let mut len = 0usize;
        for index in 0..count {
            len = len
                .checked_mul(256)?
                .checked_add(usize::from(*der.get(at + 2 + index)?))?;
        }
        (len, at + 2 + count)
    };
    let end = body.checked_add(len)?;
    if end > der.len() {
        return None;
    }
    Some((tag, body, end))
}

#[must_use]
pub fn digest(leaf_der: &[u8]) -> Option<[u8; 32]> {
    let spki = leaf_spki(leaf_der)?;
    Some(Sha256::digest(spki).into())
}

#[must_use]
pub fn spki_pin(leaf_der: &[u8]) -> Option<String> {
    Some(format!("sha256/{}", b64::encode(&digest(leaf_der)?)))
}

/// The leaf keys a lane accepts, behind one allocation: a config names them and never changes them, and a dial copies this set per flow, so a copy that shared the bytes costs a reference count rather than a buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pins {
    entries: std::sync::Arc<[[u8; 32]]>,
}

impl Pins {
    #[must_use]
    pub fn parse<I: IntoIterator<Item = String>>(pins: I) -> Self {
        let mut entries = Vec::new();
        for pin in pins {
            let Some(raw) = pin.strip_prefix("sha256/") else {
                continue;
            };
            if let Some(bytes) = b64::decode(raw.as_bytes()) {
                if let Ok(entry) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    entries.push(entry);
                }
            }
        }
        Self {
            entries: std::sync::Arc::from(entries),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn holds(&self, leaf_der: &[u8]) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        self.entries.contains(&digest(leaf_der).unwrap_or([0; 32]))
    }
}

#[cfg(test)]
pub(crate) mod build {
    pub(crate) fn length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            return vec![len as u8];
        }
        let bytes = len.to_be_bytes();
        let start = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let mut out = vec![0x80 | (bytes.len() - start) as u8];
        out.extend_from_slice(&bytes[start..]);
        out
    }

    pub(crate) fn element(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&length(body.len()));
        out.extend_from_slice(body);
        out
    }

    pub(crate) fn filler(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| (index as u8).wrapping_mul(37) ^ 0x5a)
            .collect()
    }

    /// A tbsCertificate with an optional version and five parts before the key, whose issuer width decides whether a long-form length is needed on the way in.
    pub(crate) fn certificate(issuer_width: usize) -> (Vec<u8>, Vec<u8>) {
        let spki = element(0x30, &filler(29));
        let mut body = element(0xA0, &element(0x02, &[2]));
        body.extend_from_slice(&element(0x02, &[5]));
        for width in [7, issuer_width, 9, 13] {
            body.extend_from_slice(&element(0x30, &filler(width)));
        }
        body.extend_from_slice(&spki);
        let tbs = element(0x30, &body);
        let mut cert = tbs.clone();
        cert.extend_from_slice(&element(0x30, &filler(7)));
        cert.extend_from_slice(&element(0x03, &filler(17)));
        (element(0x30, &cert), spki)
    }
}

#[cfg(test)]
mod tests {
    use super::build::certificate;
    use super::*;

    #[test]
    fn the_walk_finds_the_key_in_a_short_and_a_long_certificate() {
        for width in [11, 200] {
            let (leaf, spki) = certificate(width);
            assert_eq!(leaf_spki(&leaf), Some(spki.as_slice()), "issuer {width}");
        }
    }

    #[test]
    fn the_walk_ignores_what_follows_the_key() {
        let (leaf, spki) = certificate(11);
        let mut longer = leaf.clone();
        longer.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(leaf_spki(&leaf), Some(spki.as_slice()));
        assert_eq!(leaf_spki(&longer), Some(spki.as_slice()));
    }

    #[test]
    fn an_unparseable_certificate_yields_no_key_and_no_pin() {
        let (leaf, _) = certificate(11);
        for cut in 1..leaf.len() {
            assert!(digest(&leaf[..cut]).is_none(), "cut {cut} yielded a pin");
        }
        assert!(digest(&leaf).is_some());
    }

    #[test]
    fn two_certificates_with_one_key_pin_the_same_and_a_third_does_not() {
        let (a, _) = certificate(11);
        let (b, _) = certificate(200);
        let (mut c, spki) = certificate(11);
        let inside = c
            .windows(spki.len())
            .position(|window| window == spki.as_slice())
            .expect("the key is in the certificate");
        c[inside] ^= 0x01;
        assert_eq!(spki_pin(a.as_ref()), spki_pin(b.as_ref()));
        assert_ne!(spki_pin(a.as_ref()), spki_pin(c.as_ref()));
    }
}
