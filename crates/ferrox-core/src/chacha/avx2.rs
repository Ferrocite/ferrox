//! Eight blocks per pass, one state word per register with the blocks in the lanes: the pass's sixteen registers are the whole file, so shorter lengths and remainders go to the ladder.

use super::{as_i32_bits, base, base_state, xor_tail, xor_tail_from, Lanes};
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::x86_64::*;

#[derive(Clone, Copy)]
pub(crate) struct A8(pub(crate) __m256i);

impl core::fmt::Debug for A8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = [0u32; 8];
        unsafe { _mm256_storeu_si256(v.as_mut_ptr().cast(), self.0) };
        f.debug_tuple("A8").field(&v).finish()
    }
}

const ROTL16: [i32; 8] = [
    0x0100_0302,
    0x0504_0706,
    0x0908_0b0a,
    0x0d0c_0f0e,
    0x0100_0302,
    0x0504_0706,
    0x0908_0b0a,
    0x0d0c_0f0e,
];

const ROTL8: [i32; 8] = [
    0x0201_0003,
    0x0605_0407,
    0x0a09_080b,
    0x0e0d_0c0f,
    0x0201_0003,
    0x0605_0407,
    0x0a09_080b,
    0x0e0d_0c0f,
];

const fn rot_imm(n: i32) -> i32 {
    (n & 3) | (((n + 1) & 3) << 2) | (((n + 2) & 3) << 4) | (((n + 3) & 3) << 6)
}

const _: () = {
    assert!(rot_imm(1) == 0b00_11_10_01);
    assert!(rot_imm(2) == 0b01_00_11_10);
    assert!(rot_imm(3) == 0b10_01_00_11);
};

impl Lanes for A8 {
    const LANES: usize = 8;

    #[inline]
    fn from_lanes(words: &[u32]) -> Self {
        Self(unsafe { _mm256_loadu_si256(words.as_ptr().cast()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self(unsafe { _mm256_add_epi32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self(unsafe { _mm256_xor_si256(self.0, o.0) })
    }

    #[inline]
    fn rotl16(self) -> Self {
        // black-boxed so the mask is not a constant: LLVM otherwise reads this rotate as two lane swaps
        let mask = core::hint::black_box(ROTL16.as_ptr().cast::<i8>());
        Self(unsafe { _mm256_shuffle_epi8(self.0, _mm256_loadu_si256(mask.cast())) })
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(unsafe {
            _mm256_or_si256(
                _mm256_slli_epi32::<12>(self.0),
                _mm256_srli_epi32::<20>(self.0),
            )
        })
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(unsafe { _mm256_shuffle_epi8(self.0, _mm256_loadu_si256(ROTL8.as_ptr().cast())) })
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(unsafe {
            _mm256_or_si256(
                _mm256_slli_epi32::<7>(self.0),
                _mm256_srli_epi32::<25>(self.0),
            )
        })
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        let v = unsafe {
            match n {
                1 => _mm256_shuffle_epi32::<0b00_11_10_01>(self.0),
                2 => _mm256_shuffle_epi32::<0b01_00_11_10>(self.0),
                _ => _mm256_shuffle_epi32::<0b10_01_00_11>(self.0),
            }
        };
        Self(v)
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        unsafe {
            let lo = _mm256_insert_epi32::<0>(self.0, as_i32_bits(first));
            Self(_mm256_insert_epi32::<4>(
                lo,
                as_i32_bits(first.wrapping_add(Self::CHUNKS as u32 - 1)),
            ))
        }
    }

    #[inline]
    fn xor_chunk(self, c: usize, dst: &mut [u8; 16]) {
        unsafe {
            let cur = _mm_loadu_si128(dst.as_mut_ptr().cast());
            let ours = if c == 0 {
                _mm256_castsi256_si128(self.0)
            } else {
                _mm256_extracti128_si256::<1>(self.0)
            };
            _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_xor_si128(cur, ours));
        }
    }

    #[inline]
    fn xor_chunk_from(self, c: usize, src: &[u8; 16], dst: &mut [u8; 16]) {
        unsafe {
            let cur = _mm_loadu_si128(src.as_ptr().cast());
            let ours = if c == 0 {
                _mm256_castsi256_si128(self.0)
            } else {
                _mm256_extracti128_si256::<1>(self.0)
            };
            _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_xor_si128(cur, ours));
        }
    }
}

/// Blocks one pass covers: sixteen registers, one state word in each.
const PASS_BLOCKS: u32 = 8;

/// Bytes one pass covers.
const PASS_BYTES: usize = PASS_BLOCKS as usize * 64;

/// The lane increments: the pass's block `b` counts from `ctr + b`.
static LANES: [i32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

#[inline(always)]
fn rot16(x: __m256i, table: __m256i) -> __m256i {
    unsafe { _mm256_shuffle_epi8(x, table) }
}

#[inline(always)]
fn rot12(x: __m256i) -> __m256i {
    unsafe { _mm256_or_si256(_mm256_slli_epi32::<12>(x), _mm256_srli_epi32::<20>(x)) }
}

#[inline(always)]
fn rot8(x: __m256i, table: __m256i) -> __m256i {
    unsafe { _mm256_shuffle_epi8(x, table) }
}

#[inline(always)]
fn rot7(x: __m256i) -> __m256i {
    unsafe { _mm256_or_si256(_mm256_slli_epi32::<7>(x), _mm256_srli_epi32::<25>(x)) }
}

/// Quarter round over the four registers the caller names: the diagonal is a rename of them, since each register holds the same state word.
macro_rules! quarter {
    ($a:ident, $b:ident, $c:ident, $d:ident, $t16:ident, $t8:ident) => {
        $a = unsafe { _mm256_add_epi32($a, $b) };
        $d = rot16(unsafe { _mm256_xor_si256($d, $a) }, $t16);
        $c = unsafe { _mm256_add_epi32($c, $d) };
        $b = rot12(unsafe { _mm256_xor_si256($b, $c) });
        $a = unsafe { _mm256_add_epi32($a, $b) };
        $d = rot8(unsafe { _mm256_xor_si256($d, $a) }, $t8);
        $c = unsafe { _mm256_add_epi32($c, $d) };
        $b = rot7(unsafe { _mm256_xor_si256($b, $c) });
    };
}

/// One double round over the pass's sixteen registers: four columns, then the same registers renamed as the four diagonals.
macro_rules! double_round {
    (
        $v0:ident, $v1:ident, $v2:ident, $v3:ident, $v4:ident, $v5:ident, $v6:ident, $v7:ident,
        $v8:ident, $v9:ident, $v10:ident, $v11:ident, $v12:ident, $v13:ident, $v14:ident,
        $v15:ident, $t16:ident, $t8:ident
    ) => {
        quarter!($v0, $v4, $v8, $v12, $t16, $t8);
        quarter!($v1, $v5, $v9, $v13, $t16, $t8);
        quarter!($v2, $v6, $v10, $v14, $t16, $t8);
        quarter!($v3, $v7, $v11, $v15, $t16, $t8);
        quarter!($v0, $v5, $v10, $v15, $t16, $t8);
        quarter!($v1, $v6, $v11, $v12, $t16, $t8);
        quarter!($v2, $v7, $v8, $v13, $t16, $t8);
        quarter!($v3, $v4, $v9, $v14, $t16, $t8);
    };
}

/// The two 128-bit halves of `a` and `b` joined: `lo` puts the low halves first, which puts two rows of one block adjacent.
#[inline(always)]
fn join_lo(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_permute2x128_si256::<0x20>(a, b) }
}

#[inline(always)]
fn join_hi(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_permute2x128_si256::<0x31>(a, b) }
}

/// Four registers transposed: result element `b` is lane `b` of all four, one block's row across the registers, pairs sharing halves.
#[inline(always)]
fn transpose(w0: __m256i, w1: __m256i, w2: __m256i, w3: __m256i) -> [__m256i; 4] {
    unsafe {
        let t0 = _mm256_unpacklo_epi32(w0, w1);
        let t1 = _mm256_unpackhi_epi32(w0, w1);
        let t2 = _mm256_unpacklo_epi32(w2, w3);
        let t3 = _mm256_unpackhi_epi32(w2, w3);
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        [
            join_lo(u0, u1),
            join_lo(u2, u3),
            join_hi(u0, u1),
            join_hi(u2, u3),
        ]
    }
}

/// Xor thirty-two bytes of keystream into thirty-two output bytes.
#[inline(always)]
fn xor_y(dst: &mut [u8], v: __m256i) {
    debug_assert_eq!(dst.len(), 32, "a ymm row is two sixteen-byte rows");
    unsafe {
        let p = dst.as_mut_ptr();
        _mm256_storeu_si256(p.cast(), _mm256_xor_si256(_mm256_loadu_si256(p.cast()), v));
    }
}

#[inline(always)]
fn xor_y_from(src: &[u8], dst: &mut [u8], v: __m256i) {
    debug_assert_eq!(src.len(), 32, "half a block");
    debug_assert_eq!(dst.len(), 32, "half a block");
    unsafe {
        let s = _mm256_loadu_si256(src.as_ptr().cast());
        _mm256_storeu_si256(dst.as_mut_ptr().cast(), _mm256_xor_si256(s, v));
    }
}

/// One eight-block pass, the message xored in place: `out` is `PASS_BYTES` long, or sixty-four less with a `head` whose first thirty-two bytes take the one-time-key block and whose tail is dropped, over a nonce state with a zero counter.
#[allow(
    clippy::too_many_lines,
    reason = "the round's sixteen quarter rounds are written out because their register names are the diagonal, and the store follows those same names"
)]
#[inline(always)]
fn pass_impl<const FROM: bool>(
    state: &[u32; 16],
    ctr: u32,
    head: Option<&mut [u8; 32]>,
    src: &[u8],
    out: &mut [u8],
) {
    debug_assert_eq!(state[12], 0, "the counter register is only a base at zero");
    debug_assert_eq!(
        out.len(),
        if head.is_some() {
            PASS_BYTES - 64
        } else {
            PASS_BYTES
        },
        "a pass writes eight blocks, or seven beside a head"
    );

    // Black-boxed as in the lane: a constant mask here is read back as two lane swaps.
    let masked = core::hint::black_box(ROTL16.as_ptr().cast::<i8>());
    let t16 = unsafe { _mm256_loadu_si256(masked.cast()) };
    let t8 = unsafe { _mm256_loadu_si256(ROTL8.as_ptr().cast()) };
    let lanes = unsafe { _mm256_loadu_si256(LANES.as_ptr().cast()) };

    // Every register starts from the same broadcast state: only the counter differs between blocks.
    let mut v0 = unsafe { _mm256_set1_epi32(as_i32_bits(state[0])) };
    let mut v1 = unsafe { _mm256_set1_epi32(as_i32_bits(state[1])) };
    let mut v2 = unsafe { _mm256_set1_epi32(as_i32_bits(state[2])) };
    let mut v3 = unsafe { _mm256_set1_epi32(as_i32_bits(state[3])) };
    let mut v4 = unsafe { _mm256_set1_epi32(as_i32_bits(state[4])) };
    let mut v5 = unsafe { _mm256_set1_epi32(as_i32_bits(state[5])) };
    let mut v6 = unsafe { _mm256_set1_epi32(as_i32_bits(state[6])) };
    let mut v7 = unsafe { _mm256_set1_epi32(as_i32_bits(state[7])) };
    let mut v8 = unsafe { _mm256_set1_epi32(as_i32_bits(state[8])) };
    let mut v9 = unsafe { _mm256_set1_epi32(as_i32_bits(state[9])) };
    let mut v10 = unsafe { _mm256_set1_epi32(as_i32_bits(state[10])) };
    let mut v11 = unsafe { _mm256_set1_epi32(as_i32_bits(state[11])) };
    let mut v12 = unsafe { _mm256_add_epi32(_mm256_set1_epi32(as_i32_bits(ctr)), lanes) };
    let mut v13 = unsafe { _mm256_set1_epi32(as_i32_bits(state[13])) };
    let mut v14 = unsafe { _mm256_set1_epi32(as_i32_bits(state[14])) };
    let mut v15 = unsafe { _mm256_set1_epi32(as_i32_bits(state[15])) };

    for _ in 0..10 {
        double_round!(
            v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, t16, t8
        );
    }

    // The initial state reloads from memory instead of occupying sixteen more registers that do not exist; a broadcast load is a cycle.
    v0 = unsafe { _mm256_add_epi32(v0, _mm256_set1_epi32(as_i32_bits(state[0]))) };
    v1 = unsafe { _mm256_add_epi32(v1, _mm256_set1_epi32(as_i32_bits(state[1]))) };
    v2 = unsafe { _mm256_add_epi32(v2, _mm256_set1_epi32(as_i32_bits(state[2]))) };
    v3 = unsafe { _mm256_add_epi32(v3, _mm256_set1_epi32(as_i32_bits(state[3]))) };
    v4 = unsafe { _mm256_add_epi32(v4, _mm256_set1_epi32(as_i32_bits(state[4]))) };
    v5 = unsafe { _mm256_add_epi32(v5, _mm256_set1_epi32(as_i32_bits(state[5]))) };
    v6 = unsafe { _mm256_add_epi32(v6, _mm256_set1_epi32(as_i32_bits(state[6]))) };
    v7 = unsafe { _mm256_add_epi32(v7, _mm256_set1_epi32(as_i32_bits(state[7]))) };
    v8 = unsafe { _mm256_add_epi32(v8, _mm256_set1_epi32(as_i32_bits(state[8]))) };
    v9 = unsafe { _mm256_add_epi32(v9, _mm256_set1_epi32(as_i32_bits(state[9]))) };
    v10 = unsafe { _mm256_add_epi32(v10, _mm256_set1_epi32(as_i32_bits(state[10]))) };
    v11 = unsafe { _mm256_add_epi32(v11, _mm256_set1_epi32(as_i32_bits(state[11]))) };
    v12 = unsafe {
        _mm256_add_epi32(
            v12,
            _mm256_add_epi32(_mm256_set1_epi32(as_i32_bits(ctr)), lanes),
        )
    };
    v13 = unsafe { _mm256_add_epi32(v13, _mm256_set1_epi32(as_i32_bits(state[13]))) };
    v14 = unsafe { _mm256_add_epi32(v14, _mm256_set1_epi32(as_i32_bits(state[14]))) };
    v15 = unsafe { _mm256_add_epi32(v15, _mm256_set1_epi32(as_i32_bits(state[15]))) };

    let rows = [
        transpose(v0, v1, v2, v3),
        transpose(v4, v5, v6, v7),
        transpose(v8, v9, v10, v11),
        transpose(v12, v13, v14, v15),
    ];

    // The pass's first block is block zero: its first two rows are the one-time key, its last two are dropped, so the buffer starts at block one.
    let mut skip = false;
    if let Some(one_time) = head {
        xor_y(&mut one_time[..], join_lo(rows[0][0], rows[1][0]));
        skip = true;
    }
    let mut at = 0usize;
    for block in 0..PASS_BLOCKS as usize {
        if skip && block == 0 {
            continue;
        }
        // Block `b` shares register `b / 2` with its pair: even blocks are the transposes' low halves, odd blocks the high ones.
        let pair = block / 2;
        let (lo, hi) = if block % 2 == 0 {
            (
                join_lo(rows[0][pair], rows[1][pair]),
                join_lo(rows[2][pair], rows[3][pair]),
            )
        } else {
            (
                join_hi(rows[0][pair], rows[1][pair]),
                join_hi(rows[2][pair], rows[3][pair]),
            )
        };
        if FROM {
            xor_y_from(&src[at..at + 32], &mut out[at..at + 32], lo);
            xor_y_from(&src[at + 32..at + 64], &mut out[at + 32..at + 64], hi);
        } else {
            xor_y(&mut out[at..at + 32], lo);
            xor_y(&mut out[at + 32..at + 64], hi);
        }
        at += 64;
    }
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    let state = base_state(key, nonce);
    // The ladder's group loop is unreachable: the pass loop breaks below a pass, which is that loop's own budget, so the tail needs no second `base_state`.
    let rows = base::<A8>(&state);
    let mut ctr = start;
    let mut rest = buf;
    let mut blocks = 0u32;

    loop {
        // A headed pass consumes one of its blocks for thirty-two output bytes, so it writes seven.
        let take = if head.is_some() {
            PASS_BYTES - 64
        } else {
            PASS_BYTES
        };
        if rest.len() < take {
            break;
        }
        let (chunk, tail) = rest.split_at_mut(take);
        pass(&state, ctr, head.take(), chunk);
        blocks += PASS_BLOCKS;
        ctr = ctr.wrapping_add(PASS_BLOCKS);
        rest = tail;
    }

    blocks + xor_tail::<A8>(&state, &rows, ctr, head, rest)
}

#[inline(always)]
fn pass(state: &[u32; 16], ctr: u32, head: Option<&mut [u8; 32]>, out: &mut [u8]) {
    pass_impl::<false>(state, ctr, head, &[], out);
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn xor_blocks_from(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    src: &[u8],
    dst: &mut [u8],
) -> u32 {
    let state = base_state(key, nonce);
    let rows = base::<A8>(&state);
    let mut ctr = start;
    let mut src = src;
    let mut rest = dst;
    let mut blocks = 0u32;

    loop {
        let take = if head.is_some() {
            PASS_BYTES - 64
        } else {
            PASS_BYTES
        };
        if rest.len() < take {
            break;
        }
        let (chunk, tail) = rest.split_at_mut(take);
        let (chunk_src, tail_src) = src.split_at(take);
        pass_impl::<true>(&state, ctr, head.take(), chunk_src, chunk);
        blocks += PASS_BLOCKS;
        ctr = ctr.wrapping_add(PASS_BLOCKS);
        rest = tail;
        src = tail_src;
    }

    blocks + xor_tail_from::<A8>(&state, &rows, ctr, head, src, rest)
}

#[cfg(test)]
mod tests {
    use super::{xor_blocks, A8, PASS_BYTES};
    use crate::chacha::xor_ladder;

    /// The pass against the ladder it replaced, byte for byte, at every length around its boundaries and across the counter's ends; Miri interprets no SIMD intrinsics, so native CI runs this on every ISA.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn the_eight_block_pass_is_the_ladder_at_every_length() {
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        let mut lengths: Vec<usize> = (0..=(2 * PASS_BYTES + 8)).collect();
        lengths.extend([1023, 1024, 1025, 4095, 4096, 4097, 16_384]);

        for &len in &lengths {
            for start in [0u32, 1, 7, u32::MAX - 9] {
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
                    xor_ladder::<A8>(&key, &nonce, start, Some(&mut their_key), &mut theirs);

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

    /// Without a head, over the lengths where a pass does not divide; Miri interprets no SIMD intrinsics, so native CI runs this on every ISA.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn the_pass_matches_the_ladder_without_a_head() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        for len in [
            0,
            1,
            63,
            64,
            65,
            PASS_BYTES - 1,
            PASS_BYTES,
            PASS_BYTES + 1,
            2 * PASS_BYTES,
            2 * PASS_BYTES + 63,
            3 * PASS_BYTES - 1,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut ours = plain.clone();
            let mut theirs = plain;
            let our_blocks = unsafe { xor_blocks(&key, &nonce, 0, None, &mut ours) };
            let their_blocks = xor_ladder::<A8>(&key, &nonce, 0, None, &mut theirs);
            assert_eq!(ours, theirs, "ciphertext at {len} bytes");
            assert_eq!(our_blocks, their_blocks, "blocks at {len} bytes");
        }
    }
}
