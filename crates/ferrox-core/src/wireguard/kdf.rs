//! `WireGuard`'s key derivation: HKDF (RFC 5869) with the extract-and-expand
//! loop specialised to a 32-byte output per step and the inner hash fixed to
//! BLAKE2s — not keyed BLAKE2s, but RFC 2104 HMAC over the unkeyed hash, the
//! construction the reference builds with Go's `hmac.New(blake2s.New256(nil))`.
//! The keyed primitive is a different thing (`blake2s::keyed`) and belongs to
//! the mac and cookie path, not here.
//!
//! One HMAC of BLAKE2s is two padding-XORs and four block compressions at the
//! shortest; the only room left is to drop the allocation-per-MAC the Go
//! `hash.Hash` interface imposes and keep the whole thing on the stack.

use crate::blake2s::{hash, Blake2s};
use zeroize::Zeroize as _;

const BLOCK: usize = 64;

/// RFC 2104 HMAC with unkeyed BLAKE2s-256 inside, over the concatenation of
/// `first` and `second`. A key longer than the 64-byte block is hashed first,
/// which BLAKE2s can never produce from a `WireGuard` key but the construction
/// promises anyway.
fn hmac(key: &[u8], first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&hash(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Blake2s::new(&[], 32);
    for byte in &mut block {
        *byte ^= 0x36;
    }
    inner.update(&block);
    inner.update(first);
    inner.update(second);
    let inner = inner.finalize();

    // `0x36 ^ 0x5c` is `0x6a`: one pass turns the ipad block into the opad one.
    for byte in &mut block {
        *byte ^= 0x6a;
    }
    let mut outer = Blake2s::new(&[], 32);
    outer.update(&block);
    outer.update(&inner);
    let result = outer.finalize();
    block.zeroize();
    result
}

/// HKDF expand at one output: `H(prk, 0x01)` after `prk = H(key, input)`.
#[must_use]
pub fn kdf1(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut prk = hmac(key, input, &[]);
    let output = hmac(&prk, &[1], &[]);
    prk.zeroize();
    output
}

/// Two outputs: the pair `(H(prk, 0x01), H(prk, t0 ‖ 0x02))`. The handshake's
/// `mixKey` takes the first alone; `BeginSymmetricSession` takes both, using
/// an empty `input` — the reference calls `KDF2(chainKey, nil)` there, and an
/// empty HMAC input is not the same digest as a zero-length key, so the empty
/// slice is load-bearing.
#[must_use]
pub fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut prk = hmac(key, input, &[]);
    let t0 = hmac(&prk, &[1], &[]);
    let t1 = hmac(&prk, &t0, &[2]);
    prk.zeroize();
    (t0, t1)
}

/// Three outputs: `(t0, t1, t2)`, the chain-key successor, the `tau` that goes
/// into the transcript hash, and the key that authenticates the response's
/// empty field.
#[must_use]
pub fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut prk = hmac(key, input, &[]);
    let t0 = hmac(&prk, &[1], &[]);
    let t1 = hmac(&prk, &t0, &[2]);
    let t2 = hmac(&prk, &t1, &[3]);
    prk.zeroize();
    (t0, t1, t2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(2 * bytes.len()), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    /// The published `WireGuard` KDF vectors: three `(key, input)` pairs and
    /// the `t0`, `t1`, `t2` every conforming implementation must derive. They
    /// cover a short key, an equal key-and-input, and the empty pair — which
    /// is the one that would silently pass if an empty input were confused
    /// with a zero key.
    const VECTORS: [(&str, &str, &str, &str, &str); 3] = [
        (
            "746573742d6b6579",
            "746573742d696e707574",
            "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
            "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
            "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24",
        ),
        (
            "776972656775617264",
            "776972656775617264",
            "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
            "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
            "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160",
        ),
        (
            "",
            "",
            "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
            "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
            "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e",
        ),
    ];

    #[test]
    fn the_published_kdf_triples_reproduce() {
        for (key, input, t0, t1, t2) in VECTORS {
            let (a, b, c) = kdf3(&bytes(key), &bytes(input));
            assert_eq!(hex(&a), t0, "t0 for key {key}");
            assert_eq!(hex(&b), t1, "t1 for key {key}");
            assert_eq!(hex(&c), t2, "t2 for key {key}");

            let (a, b) = kdf2(&bytes(key), &bytes(input));
            assert_eq!(hex(&a), t0, "kdf2 t0 for key {key}");
            assert_eq!(hex(&b), t1, "kdf2 t1 for key {key}");

            let a = kdf1(&bytes(key), &bytes(input));
            assert_eq!(hex(&a), t0, "kdf1 t0 for key {key}");
        }
    }
}
