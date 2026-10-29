//! A 32-byte keystream tiled over a datagram, the XOR both Hysteria masks share.

const WIDTH: usize = 32;
const STEP: usize = 16;

/// The sixteen bytes at `at`, little-endian, as one word.
#[inline]
fn wide(bytes: &[u8], at: usize) -> u128 {
    u128::from_le_bytes(bytes[at..at + STEP].try_into().unwrap())
}

/// Write `value` little-endian into the sixteen bytes at `at`.
#[inline]
fn store(bytes: &mut [u8], at: usize, value: u128) {
    bytes[at..at + STEP].copy_from_slice(&value.to_le_bytes());
}

/// The two sixteen-byte phases a step alternates between.
fn key_words(key: &[u8; WIDTH]) -> [u128; 2] {
    [wide(key, 0), wide(key, STEP)]
}

/// `dst = src ^ keystream`, sixteen bytes per step: the little-endian xor is the byte xor.
pub(crate) fn encrypt(dst: &mut [u8], src: &[u8], key: &[u8; WIDTH]) {
    debug_assert!(dst.len() >= src.len());
    let words = key_words(key);
    let mut at = 0usize;
    while at + STEP <= src.len() {
        store(dst, at, wide(src, at) ^ words[(at / STEP) & 1]);
        at += STEP;
    }
    while at < src.len() {
        dst[at] = src[at] ^ key[at & (WIDTH - 1)];
        at += 1;
    }
}

/// In-place `bytes ^= keystream`.
pub(crate) fn apply(bytes: &mut [u8], key: &[u8; WIDTH]) {
    let words = key_words(key);
    let mut at = 0usize;
    while at + STEP <= bytes.len() {
        store(bytes, at, wide(bytes, at) ^ words[(at / STEP) & 1]);
        at += STEP;
    }
    while at < bytes.len() {
        bytes[at] ^= key[at & (WIDTH - 1)];
        at += 1;
    }
}

/// Drop `shift` salt bytes and unmask the payload to the front, in place. A step loads its source
/// into a register before the store below it, and every later source starts past that store, so
/// `shift >= 8` needs no scratch.
pub(crate) fn unshift(datagram: &mut [u8], shift: usize, key: &[u8; WIDTH]) -> usize {
    debug_assert!((8..WIDTH).contains(&shift));
    let payload = datagram.len().saturating_sub(shift);
    let words = key_words(key);
    let mut at = 0usize;
    while at + STEP <= payload {
        let plain = wide(datagram, at + shift) ^ words[(at / STEP) & 1];
        store(datagram, at, plain);
        at += STEP;
    }
    while at < payload {
        datagram[at] = datagram[at + shift] ^ key[at & (WIDTH - 1)];
        at += 1;
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; WIDTH] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
    }

    #[test]
    fn every_length_unshifts_like_the_byte_walk() {
        let key = key();
        for shift in [8usize, 16] {
            for len in 0..=200usize {
                let mut datagram: Vec<u8> = (0..shift + len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(3))
                    .collect();
                let want: Vec<u8> = (0..len)
                    .map(|i| datagram[shift + i] ^ key[i & (WIDTH - 1)])
                    .collect();
                assert_eq!(unshift(&mut datagram, shift, &key), len);
                assert_eq!(&datagram[..len], &want[..], "shift {shift} length {len}");
            }
        }
    }

    #[test]
    fn encrypt_and_apply_agree_at_every_length() {
        let key = key();
        for len in 0..=200usize {
            let src: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();
            let want: Vec<u8> = (0..len).map(|i| src[i] ^ key[i & (WIDTH - 1)]).collect();
            let mut dst = vec![0u8; len];
            encrypt(&mut dst, &src, &key);
            assert_eq!(dst, want, "length {len}");
            let mut in_place = src.clone();
            apply(&mut in_place, &key);
            assert_eq!(in_place, want, "length {len}");
        }
    }
}
