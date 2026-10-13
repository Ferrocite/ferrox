#[cfg(any(test, feature = "bench-reference"))]
pub fn reference_xor(key: &[u8; 32], nonce: &[u8; 12], start: u32, buf: &mut [u8]) {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let mut c = chacha20::ChaCha20::new(key.into(), nonce.into());
    c.seek(u64::from(start) * 64);
    c.apply_keystream(buf);
}

#[cfg(any(test, feature = "bench-reference"))]
pub fn backend() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            "chacha20 0.9 / avx2, 4 blocks per iteration"
        } else if cfg!(target_feature = "sse2") {
            "chacha20 0.9 / sse2, 1 block per iteration"
        } else {
            "chacha20 0.9 / soft scalar, 1 block per iteration"
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        "chacha20 0.9 / soft scalar, 1 block per iteration (its NEON backend is gated behind a cfg nothing sets)"
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "chacha20 0.9 / soft scalar, 1 block per iteration"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rung_matches_the_reference() {
        let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let nonce: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));
        let key2: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29));
        let nonce2: [u8; 12] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(101).wrapping_add(61));

        for len in [
            0usize, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 383, 384, 447, 448, 511, 512, 513,
            575, 576, 639, 640, 767, 768, 769, 1023, 1024, 1025, 1087, 1088, 1089, 1535, 1536,
            1537, 1983, 1984, 1985, 2047, 2048, 2049, 4095, 4096, 4097, 8192,
        ] {
            for start in [0u32, 1, 2, 7, 64, 65_535] {
                for (k, n) in [(&key, &nonce), (&key2, &nonce2)] {
                    let mut want = vec![0u8; len];
                    let mut got = vec![0u8; len];
                    reference_xor(k, n, start, &mut want);
                    crate::record::fill_exact(k, n, start, &mut got);
                    assert_eq!(got, want, "len {len} start {start}");
                }
            }
        }
    }

    #[test]
    fn the_second_group_is_not_the_first_group() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut first = vec![0u8; 512];
        let mut second = vec![0u8; 512];
        crate::record::fill_exact(&key, &nonce, 0, &mut first);
        crate::record::fill_exact(&key, &nonce, 8, &mut second);
        assert_ne!(
            first, second,
            "block counter 0 and block counter 8 must not produce the same keystream"
        );
    }
}
