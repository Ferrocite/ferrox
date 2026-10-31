use super::Lanes;

macro_rules! rols {
    ($($name:ident => $n:expr),* $(,)?) => {
        $(
            #[inline]
            fn $name(x: u32) -> u32 { x.rotate_left($n) }
        )*
    };
}
rols!(rotl16 => 16, rotl12 => 12, rotl8 => 8, rotl7 => 7);

#[derive(Clone, Copy)]
pub(crate) struct U4(pub(crate) [u32; 4]);

impl core::fmt::Debug for U4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("U4").field(&self.0).finish()
    }
}

impl Lanes for U4 {
    const LANES: usize = 4;

    fn from_lanes(words: &[u32]) -> Self {
        let w: [u32; 4] = words[..4].try_into().expect("U4 needs 4 lanes");
        Self(w)
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self([
            self.0[0].wrapping_add(o.0[0]),
            self.0[1].wrapping_add(o.0[1]),
            self.0[2].wrapping_add(o.0[2]),
            self.0[3].wrapping_add(o.0[3]),
        ])
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self([
            self.0[0] ^ o.0[0],
            self.0[1] ^ o.0[1],
            self.0[2] ^ o.0[2],
            self.0[3] ^ o.0[3],
        ])
    }

    #[inline]
    fn rotl16(self) -> Self {
        Self(self.0.map(rotl16))
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(self.0.map(rotl12))
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(self.0.map(rotl8))
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(self.0.map(rotl7))
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        let a = self.0;
        Self([a[n % 4], a[(n + 1) % 4], a[(n + 2) % 4], a[(n + 3) % 4]])
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        let mut w = self.0;
        w[0] = first;
        Self(w)
    }

    #[inline]
    fn xor_chunk(self, _c: usize, dst: &mut [u8; 16]) {
        let (words, _) = dst.as_chunks_mut::<4>();
        for (d, w) in words.iter_mut().zip(self.0) {
            *d = (u32::from_le_bytes(*d) ^ w).to_le_bytes();
        }
    }

    #[inline]
    fn xor_chunk_from(self, _c: usize, src: &[u8; 16], dst: &mut [u8; 16]) {
        let (sources, _) = src.as_chunks::<4>();
        let (words, _) = dst.as_chunks_mut::<4>();
        for ((src, dst), w) in sources.iter().zip(words.iter_mut()).zip(self.0) {
            *dst = (u32::from_le_bytes(*src) ^ w).to_le_bytes();
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn xor_block_impl<const FROM: bool>(
    state: &[u32; 16],
    counter: u32,
    src: &[u8],
    out: &mut [u8],
) -> u32 {
    let mut state = *state;
    state[12] = counter;

    let mut regs = [[U4([0; 4]); 4]; 1];
    for g in 0..4 {
        regs[0][g] = U4(state[4 * g..4 * g + 4].try_into().expect("4 words"));
    }
    let init = regs;

    super::rounds::<U4, 1>(&mut regs);

    for g in 0..4 {
        regs[0][g] = regs[0][g].add(init[0][g]);
    }

    let (chunks, tail) = out.as_chunks_mut::<16>();
    let (sources, src_tail) = src.as_chunks::<16>();
    for ((chunk, source), reg) in chunks
        .iter_mut()
        .zip(sources.iter().map(Some).chain(core::iter::repeat(None)))
        .zip(regs[0].iter())
    {
        if FROM {
            reg.xor_chunk_from(0, source.unwrap_or(&[0u8; 16]), chunk);
        } else {
            reg.xor_chunk(0, chunk);
        }
    }
    let rest = tail.len();
    for (i, word) in regs[0]
        .iter()
        .flat_map(|r| r.0.iter())
        .skip(chunks.len() * 4)
        .enumerate()
    {
        let off = i * 4;
        if off >= rest {
            break;
        }
        let ks = word.to_le_bytes();
        let n = 4.min(rest - off);
        for j in 0..n {
            let k = ks[j];
            tail[off + j] = if FROM {
                src_tail[off + j] ^ k
            } else {
                tail[off + j] ^ k
            };
        }
    }
    1
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub(crate) fn xor_block(state: &[u32; 16], counter: u32, out: &mut [u8]) -> u32 {
    xor_block_impl::<false>(state, counter, &[], out)
}

#[cfg(test)]
mod tests {
    use super::{Lanes, U4};

    /// The lane folds four keystream words into the caller's bytes, so a mid-record destination must match an aligned one; a `*mut u32` from a byte pointer is undefined at an odd offset and aligned tests pass either way, hence all sixteen alignments.
    #[test]
    fn every_destination_alignment_yields_the_same_stream() {
        let words = U4([0x0102_0304, 0xEFFF_7FFF, 0x8000_0001, 0xFFFF_FFFF]);
        let mut expected = [0u8; 16];
        Lanes::xor_chunk(words, 0, &mut expected);
        for offset in 0..16usize {
            let mut room = [0u8; 32];
            let tail = &mut room[offset..offset + 16];
            let dst: &mut [u8; 16] = tail.try_into().expect("sixteen bytes");
            Lanes::xor_chunk(words, 0, dst);
            assert_eq!(*dst, expected, "offset {offset} diverged");
        }
    }
}
