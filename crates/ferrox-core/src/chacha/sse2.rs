use super::{as_i32_bits, Lanes};
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::x86_64::*;

#[derive(Clone, Copy)]
pub(crate) struct S4(pub(crate) __m128i);

impl core::fmt::Debug for S4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = [0u32; 4];
        unsafe { _mm_storeu_si128(v.as_mut_ptr().cast(), self.0) };
        f.debug_tuple("S4").field(&v).finish()
    }
}

impl Lanes for S4 {
    const LANES: usize = 4;

    #[inline]
    fn from_lanes(words: &[u32]) -> Self {
        Self(unsafe { _mm_loadu_si128(words.as_ptr().cast()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self(unsafe { _mm_add_epi32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self(unsafe { _mm_xor_si128(self.0, o.0) })
    }

    #[inline]
    fn rotl16(self) -> Self {
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<16>(self.0), _mm_srli_epi32::<16>(self.0)) })
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<12>(self.0), _mm_srli_epi32::<20>(self.0)) })
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<8>(self.0), _mm_srli_epi32::<24>(self.0)) })
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<7>(self.0), _mm_srli_epi32::<25>(self.0)) })
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        let v = unsafe {
            match n {
                1 => _mm_shuffle_epi32::<0b00_11_10_01>(self.0),
                2 => _mm_shuffle_epi32::<0b01_00_11_10>(self.0),
                _ => _mm_shuffle_epi32::<0b10_01_00_11>(self.0),
            }
        };
        Self(v)
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        unsafe {
            let keep = _mm_and_si128(self.0, _mm_set_epi32(-1, -1, -1, 0));
            Self(_mm_or_si128(keep, _mm_cvtsi32_si128(as_i32_bits(first))))
        }
    }

    #[inline]
    fn xor_chunk(self, _c: usize, dst: &mut [u8; 16]) {
        unsafe {
            let cur = _mm_loadu_si128(dst.as_ptr().cast());
            _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_xor_si128(cur, self.0));
        }
    }

    #[inline]
    fn xor_chunk_from(self, _c: usize, src: &[u8; 16], dst: &mut [u8; 16]) {
        unsafe {
            let cur = _mm_loadu_si128(src.as_ptr().cast());
            _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_xor_si128(cur, self.0));
        }
    }
}
