//! Sixteen blocks over `__m512i`: `vprold` makes each of the four rotations one instruction, and the transpose one gather per register per stage — sixty-four for sixteen blocks.

use super::wide::{wide_blocks, Wide16, IDX};
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::x86_64::*;

/// The lane increments: the pass's block `b` counts from `ctr + b`.
static LANES: [i32; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// One `zmm` register: sixteen blocks, one state word each.
#[derive(Clone, Copy)]
pub(crate) struct Z16(__m512i);

impl core::fmt::Debug for Z16 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = [0u32; 16];
        unsafe { _mm512_storeu_si512(v.as_mut_ptr().cast(), self.0) };
        f.debug_tuple("Z16").field(&v).finish()
    }
}

impl Wide16 for Z16 {
    #[inline]
    fn broadcast(word: u32) -> Self {
        Self(unsafe { _mm512_set1_epi32(super::as_i32_bits(word)) })
    }

    #[inline]
    fn lanes() -> Self {
        Self(unsafe { _mm512_loadu_si512(LANES.as_ptr().cast()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self(unsafe { _mm512_add_epi32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self(unsafe { _mm512_xor_si512(self.0, o.0) })
    }

    /// The four rotations are `avx512f`'s whole reason to be here: `vprold` is one instruction where `avx2` needs a shift, a shift and an or.
    #[inline]
    fn rotl16(self) -> Self {
        Self(unsafe { _mm512_rol_epi32::<16>(self.0) })
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(unsafe { _mm512_rol_epi32::<12>(self.0) })
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(unsafe { _mm512_rol_epi32::<8>(self.0) })
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(unsafe { _mm512_rol_epi32::<7>(self.0) })
    }

    #[inline]
    fn gather(self, high: Self, stage: usize, upper: usize) -> Self {
        unsafe {
            let idx = _mm512_loadu_si512(IDX[stage][upper].as_ptr().cast());
            Self(_mm512_permutex2var_epi32(self.0, idx, high.0))
        }
    }

    #[inline]
    fn xor_lo32(self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), 32, "the one-time key is two rows");
        unsafe {
            let p: *mut __m256i = dst.as_mut_ptr().cast();
            let low = _mm512_castsi512_si256(self.0);
            _mm256_storeu_si256(p, _mm256_xor_si256(_mm256_loadu_si256(p), low));
        }
    }

    #[inline]
    fn xor_store(self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), 64, "a block is sixteen words");
        unsafe {
            let p: *mut __m512i = dst.as_mut_ptr().cast();
            _mm512_storeu_si512(p, _mm512_xor_si512(_mm512_loadu_si512(p), self.0));
        }
    }

    #[inline]
    fn xor_store_from(self, src: &[u8], dst: &mut [u8]) {
        debug_assert_eq!(src.len(), 64, "a block is sixteen words");
        debug_assert_eq!(dst.len(), 64, "a block is sixteen words");
        unsafe {
            let s = _mm512_loadu_si512(src.as_ptr().cast());
            let p: *mut __m512i = dst.as_mut_ptr().cast();
            _mm512_storeu_si512(p, _mm512_xor_si512(s, self.0));
        }
    }
}

/// Whole passes take the sixteen-block pass, the rest the eight-block pass and the ladder; `avx512f` and `avx2` are both required because the head is written with two `ymm` registers.
#[target_feature(enable = "avx512f,avx2")]
pub(crate) unsafe fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    wide_blocks::<Z16>(
        key,
        nonce,
        start,
        head,
        buf,
        |k, n, ctr, head, buf| unsafe { super::avx2::xor_blocks(k, n, ctr, head, buf) },
    )
}

#[target_feature(enable = "avx512f,avx2")]
pub(crate) unsafe fn xor_blocks_from(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    src: &[u8],
    dst: &mut [u8],
) -> u32 {
    super::wide::wide_blocks_from::<Z16>(
        key,
        nonce,
        start,
        head,
        src,
        dst,
        |k, n, ctr, head, src, dst| unsafe {
            super::avx2::xor_blocks_from(k, n, ctr, head, src, dst)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{xor_blocks, Z16};
    use crate::chacha::wide::{wide_blocks, PASS_BYTES};
    use crate::chacha::{avx2, xor_ladder};

    /// The pass against the ladder at every boundary length and counter end, key and block count beside the ciphertext; `avx512f` gates this and `fill_exact`'s dispatch alike, and Miri interprets no SIMD intrinsics, so native CI runs it on every ISA.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn the_sixteen_block_pass_is_the_ladder_at_every_length() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe { the_pass_and_the_ladder_agree() }
    }

    #[target_feature(enable = "avx512f,avx2")]
    unsafe fn the_pass_and_the_ladder_agree() {
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        let mut lengths: Vec<usize> = (0..=(2 * PASS_BYTES + 8)).collect();
        lengths.extend([1023, 1024, 1025, 4095, 4096, 4097, 16_384]);

        for &len in &lengths {
            for start in [0u32, 1, 7, u32::MAX - 17] {
                let plain: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(251).wrapping_add(11))
                    .collect();
                let mut ours = plain.clone();
                let mut theirs = plain.clone();
                let mut our_key = [0u8; 32];
                let mut their_key = [0u8; 32];

                let our_blocks =
                    unsafe { xor_blocks(&key, &nonce, start, Some(&mut our_key), &mut ours) };
                let their_blocks =
                    xor_ladder::<avx2::A8>(&key, &nonce, start, Some(&mut their_key), &mut theirs);

                assert_eq!(ours, theirs, "ciphertext at {len} bytes from {start}");
                assert_eq!(
                    our_key, their_key,
                    "one-time key at {len} bytes from {start}"
                );
                assert_eq!(
                    our_blocks, their_blocks,
                    "blocks at {len} bytes from {start}"
                );
            }
        }
    }

    /// The pass over buffers it takes whole passes from, against the ladder with no pass in front; Miri interprets no SIMD intrinsics, so native CI runs this on every ISA.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn the_pass_body_is_the_ladder_without_a_head() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe { the_pass_body_agrees() }
    }

    #[target_feature(enable = "avx512f,avx2")]
    unsafe fn the_pass_body_agrees() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        for len in [PASS_BYTES, 2 * PASS_BYTES, 3 * PASS_BYTES] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut ours = plain.clone();
            let mut theirs = plain;
            // The remainder handler writes nothing, so a whole number of passes leaves the buffers comparable byte for byte.
            let our_blocks =
                wide_blocks::<Z16>(&key, &nonce, 0, None, &mut ours, |_, _, _, _, _| 0);
            let their_blocks = xor_ladder::<avx2::A8>(&key, &nonce, 0, None, &mut theirs);
            assert_eq!(ours, theirs, "the pass's own blocks at {len} bytes");
            assert_eq!(
                our_blocks, their_blocks,
                "the pass's own block count at {len} bytes"
            );
        }
    }
}
