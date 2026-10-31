use super::Lanes;
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::aarch64::*;

#[derive(Clone, Copy)]
pub(crate) struct N4(pub(crate) uint32x4_t);

impl core::fmt::Debug for N4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = [0u32; 4];
        unsafe { vst1q_u32(v.as_mut_ptr(), self.0) };
        f.debug_tuple("N4").field(&v).finish()
    }
}

#[inline]
fn rotl16(v: uint32x4_t) -> uint32x4_t {
    unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v))) }
}

#[inline]
fn rotl8(v: uint32x4_t) -> uint32x4_t {
    unsafe {
        let mask: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
        let table = vld1q_u8(mask.as_ptr());
        vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), table))
    }
}

#[inline]
fn rotl_n<const SH: i32, const SHR: i32>(v: uint32x4_t) -> uint32x4_t {
    unsafe {
        let top = vshrq_n_u32::<SHR>(v);
        vsliq_n_u32::<SH>(top, v)
    }
}

#[inline]
fn rot_chunks<const N: i32>(v: uint32x4_t) -> uint32x4_t {
    unsafe { vextq_u32::<N>(v, v) }
}

impl Lanes for N4 {
    const LANES: usize = 4;

    fn from_lanes(words: &[u32]) -> Self {
        Self(unsafe { vld1q_u32(words.as_ptr()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self(unsafe { vaddq_u32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self(unsafe { veorq_u32(self.0, o.0) })
    }

    #[inline]
    fn rotl16(self) -> Self {
        Self(rotl16(self.0))
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(rotl_n::<12, 20>(self.0))
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(rotl8(self.0))
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(rotl_n::<7, 25>(self.0))
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        Self(match n {
            1 => rot_chunks::<1>(self.0),
            2 => rot_chunks::<2>(self.0),
            _ => rot_chunks::<3>(self.0),
        })
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        Self(unsafe { vsetq_lane_u32::<0>(first, self.0) })
    }

    #[inline]
    fn xor_chunk(self, _c: usize, dst: &mut [u8; 16]) {
        unsafe {
            let cur = vld1q_u8(dst.as_mut_ptr());
            vst1q_u8(
                dst.as_mut_ptr(),
                veorq_u8(cur, vreinterpretq_u8_u32(self.0)),
            );
        }
    }

    #[inline]
    fn xor_chunk_from(self, _c: usize, src: &[u8; 16], dst: &mut [u8; 16]) {
        unsafe {
            let cur = vld1q_u8(src.as_ptr());
            vst1q_u8(
                dst.as_mut_ptr(),
                veorq_u8(cur, vreinterpretq_u8_u32(self.0)),
            );
        }
    }
}
