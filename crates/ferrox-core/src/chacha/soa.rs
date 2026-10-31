//! Eight blocks per pass as two sets of four, one state word per register with the blocks in the lanes: a diagonal round is a register rename, and the second set supplies the eight chains a half round's barrier needs to fill.

use super::{base, base_state, xor_tail, xor_tail_from, Wide};
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::aarch64::*;

/// Blocks one pass covers: two sets of four.
const PASS_BLOCKS: u32 = 8;

/// Bytes one pass covers.
const PASS_BYTES: usize = PASS_BLOCKS as usize * 64;

/// The lane increments: the pass's block `b` counts from `ctr + b`.
static LANES: [u32; 4] = [0, 1, 2, 3];

/// Rotating a word eight bits left is a byte move, with the same table `chacha::neon` keeps inline.
static ROT8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];

#[inline(always)]
fn rot16(x: uint32x4_t) -> uint32x4_t {
    unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
}

#[inline(always)]
fn rot12(x: uint32x4_t) -> uint32x4_t {
    unsafe { vsliq_n_u32::<12>(vshrq_n_u32::<20>(x), x) }
}

#[inline(always)]
fn rot8(x: uint32x4_t, table: uint8x16_t) -> uint32x4_t {
    unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), table)) }
}

#[inline(always)]
fn rot7(x: uint32x4_t) -> uint32x4_t {
    unsafe { vsliq_n_u32::<7>(vshrq_n_u32::<25>(x), x) }
}

/// Quarter round over the four registers the caller names: which ones *is* the diagonal round, a rename that replaces the `vext` the row layout spends.
macro_rules! quarter {
    ($a:ident, $b:ident, $c:ident, $d:ident, $t:ident) => {
        $a = unsafe { vaddq_u32($a, $b) };
        $d = rot16(unsafe { veorq_u32($d, $a) });
        $c = unsafe { vaddq_u32($c, $d) };
        $b = rot12(unsafe { veorq_u32($b, $c) });
        $a = unsafe { vaddq_u32($a, $b) };
        $d = rot8(unsafe { veorq_u32($d, $a) }, $t);
        $c = unsafe { vaddq_u32($c, $d) };
        $b = rot7(unsafe { veorq_u32($b, $c) });
    };
}

/// One double round over one set of sixteen registers: the four columns, then the same registers renamed as the four diagonals.
macro_rules! double_round {
    (
        $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident, $a5:ident, $a6:ident, $a7:ident,
        $a8:ident, $a9:ident, $a10:ident, $a11:ident, $a12:ident, $a13:ident, $a14:ident, $a15:ident,
        $t:ident
    ) => {
        quarter!($a0, $a4, $a8, $a12, $t);
        quarter!($a1, $a5, $a9, $a13, $t);
        quarter!($a2, $a6, $a10, $a14, $t);
        quarter!($a3, $a7, $a11, $a15, $t);
        quarter!($a0, $a5, $a10, $a15, $t);
        quarter!($a1, $a6, $a11, $a12, $t);
        quarter!($a2, $a7, $a8, $a13, $t);
        quarter!($a3, $a4, $a9, $a14, $t);
    };
}

/// The u64 form of a zip, back as four words.
#[inline(always)]
fn join(v: uint64x2_t) -> uint32x4_t {
    unsafe { vreinterpretq_u32_u64(v) }
}

/// Four registers transposed: element `b` of the result is lane `b` of all four, the sixty-four bytes one block's row had across the registers.
#[inline(always)]
fn transpose(w0: uint32x4_t, w1: uint32x4_t, w2: uint32x4_t, w3: uint32x4_t) -> [uint32x4_t; 4] {
    unsafe {
        let lo01 = vtrn1q_u32(w0, w1);
        let hi01 = vtrn2q_u32(w0, w1);
        let lo23 = vtrn1q_u32(w2, w3);
        let hi23 = vtrn2q_u32(w2, w3);
        [
            join(vzip1q_u64(
                vreinterpretq_u64_u32(lo01),
                vreinterpretq_u64_u32(lo23),
            )),
            join(vzip1q_u64(
                vreinterpretq_u64_u32(hi01),
                vreinterpretq_u64_u32(hi23),
            )),
            join(vzip2q_u64(
                vreinterpretq_u64_u32(lo01),
                vreinterpretq_u64_u32(lo23),
            )),
            join(vzip2q_u64(
                vreinterpretq_u64_u32(hi01),
                vreinterpretq_u64_u32(hi23),
            )),
        ]
    }
}

/// Xor one sixteen-byte row of a block's keystream into sixteen output bytes.
#[inline(always)]
fn xor_row(dst: &mut [u8; 16], row: uint32x4_t) {
    unsafe {
        let p = dst.as_mut_ptr();
        vst1q_u8(p, veorq_u8(vld1q_u8(p), vreinterpretq_u8_u32(row)));
    }
}

/// Xor one block's keystream, four rows in order, into sixty-four output bytes.
#[inline(always)]
fn store_block(dst: &mut [u8], rows: [uint32x4_t; 4]) {
    for (chunk, row) in dst.as_chunks_mut::<16>().0.iter_mut().zip(rows) {
        xor_row(chunk, row);
    }
}

#[inline(always)]
fn xor_row_from(dst: &mut [u8; 16], src: &[u8; 16], row: uint32x4_t) {
    unsafe {
        vst1q_u8(
            dst.as_mut_ptr(),
            veorq_u8(vld1q_u8(src.as_ptr()), vreinterpretq_u8_u32(row)),
        );
    }
}

#[inline(always)]
fn store_block_from(dst: &mut [u8], src: &[u8], rows: [uint32x4_t; 4]) {
    for ((chunk, src), row) in dst
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(src.as_chunks::<16>().0)
        .zip(rows)
    {
        xor_row_from(chunk, src, row);
    }
}

/// One eight-block pass, the message xored in place: `out` is `PASS_BYTES` long, or sixty-four less with a `head` taking the first thirty-two bytes of the one-time-key block and dropping its tail, over a nonce state with a zero counter.
#[allow(
    clippy::too_many_lines,
    reason = "the round's sixteen quarter rounds are written out because their register names are the diagonal, and the store follows those same names"
)]
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

    let table: uint8x16_t = unsafe { vld1q_u8(ROT8.as_ptr()) };
    let lanes: uint32x4_t = unsafe { vld1q_u32(LANES.as_ptr()) };

    // Both sets start from the same broadcast state: only the counters differ.
    let mut v0 = unsafe { vld1q_dup_u32(state.as_ptr()) };
    let mut v1 = unsafe { vld1q_dup_u32(state.as_ptr().add(1)) };
    let mut v2 = unsafe { vld1q_dup_u32(state.as_ptr().add(2)) };
    let mut v3 = unsafe { vld1q_dup_u32(state.as_ptr().add(3)) };
    let mut v4 = unsafe { vld1q_dup_u32(state.as_ptr().add(4)) };
    let mut v5 = unsafe { vld1q_dup_u32(state.as_ptr().add(5)) };
    let mut v6 = unsafe { vld1q_dup_u32(state.as_ptr().add(6)) };
    let mut v7 = unsafe { vld1q_dup_u32(state.as_ptr().add(7)) };
    let mut v8 = unsafe { vld1q_dup_u32(state.as_ptr().add(8)) };
    let mut v9 = unsafe { vld1q_dup_u32(state.as_ptr().add(9)) };
    let mut v10 = unsafe { vld1q_dup_u32(state.as_ptr().add(10)) };
    let mut v11 = unsafe { vld1q_dup_u32(state.as_ptr().add(11)) };
    let mut v12 = unsafe { vaddq_u32(vdupq_n_u32(ctr), lanes) };
    let mut v13 = unsafe { vld1q_dup_u32(state.as_ptr().add(13)) };
    let mut v14 = unsafe { vld1q_dup_u32(state.as_ptr().add(14)) };
    let mut v15 = unsafe { vld1q_dup_u32(state.as_ptr().add(15)) };

    let mut w0 = v0;
    let mut w1 = v1;
    let mut w2 = v2;
    let mut w3 = v3;
    let mut w4 = v4;
    let mut w5 = v5;
    let mut w6 = v6;
    let mut w7 = v7;
    let mut w8 = v8;
    let mut w9 = v9;
    let mut w10 = v10;
    let mut w11 = v11;
    let mut w12 = unsafe { vaddq_u32(vdupq_n_u32(ctr.wrapping_add(4)), lanes) };
    let mut w13 = v13;
    let mut w14 = v14;
    let mut w15 = v15;

    // A loop, not ten written-out double rounds: the body holds both sets and thirty-two live registers leave the scheduler nothing.
    for _ in 0..10 {
        double_round!(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, table);
        double_round!(w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15, table);
    }

    // The initial state reloads from memory instead of thirty-two more registers that are not there to be had; a broadcast load is a cycle.
    unsafe {
        v0 = vaddq_u32(v0, vld1q_dup_u32(state.as_ptr()));
        v1 = vaddq_u32(v1, vld1q_dup_u32(state.as_ptr().add(1)));
        v2 = vaddq_u32(v2, vld1q_dup_u32(state.as_ptr().add(2)));
        v3 = vaddq_u32(v3, vld1q_dup_u32(state.as_ptr().add(3)));
        v4 = vaddq_u32(v4, vld1q_dup_u32(state.as_ptr().add(4)));
        v5 = vaddq_u32(v5, vld1q_dup_u32(state.as_ptr().add(5)));
        v6 = vaddq_u32(v6, vld1q_dup_u32(state.as_ptr().add(6)));
        v7 = vaddq_u32(v7, vld1q_dup_u32(state.as_ptr().add(7)));
        v8 = vaddq_u32(v8, vld1q_dup_u32(state.as_ptr().add(8)));
        v9 = vaddq_u32(v9, vld1q_dup_u32(state.as_ptr().add(9)));
        v10 = vaddq_u32(v10, vld1q_dup_u32(state.as_ptr().add(10)));
        v11 = vaddq_u32(v11, vld1q_dup_u32(state.as_ptr().add(11)));
        v12 = vaddq_u32(v12, vaddq_u32(vdupq_n_u32(ctr), lanes));
        v13 = vaddq_u32(v13, vld1q_dup_u32(state.as_ptr().add(13)));
        v14 = vaddq_u32(v14, vld1q_dup_u32(state.as_ptr().add(14)));
        v15 = vaddq_u32(v15, vld1q_dup_u32(state.as_ptr().add(15)));

        w0 = vaddq_u32(w0, vld1q_dup_u32(state.as_ptr()));
        w1 = vaddq_u32(w1, vld1q_dup_u32(state.as_ptr().add(1)));
        w2 = vaddq_u32(w2, vld1q_dup_u32(state.as_ptr().add(2)));
        w3 = vaddq_u32(w3, vld1q_dup_u32(state.as_ptr().add(3)));
        w4 = vaddq_u32(w4, vld1q_dup_u32(state.as_ptr().add(4)));
        w5 = vaddq_u32(w5, vld1q_dup_u32(state.as_ptr().add(5)));
        w6 = vaddq_u32(w6, vld1q_dup_u32(state.as_ptr().add(6)));
        w7 = vaddq_u32(w7, vld1q_dup_u32(state.as_ptr().add(7)));
        w8 = vaddq_u32(w8, vld1q_dup_u32(state.as_ptr().add(8)));
        w9 = vaddq_u32(w9, vld1q_dup_u32(state.as_ptr().add(9)));
        w10 = vaddq_u32(w10, vld1q_dup_u32(state.as_ptr().add(10)));
        w11 = vaddq_u32(w11, vld1q_dup_u32(state.as_ptr().add(11)));
        w12 = vaddq_u32(w12, vaddq_u32(vdupq_n_u32(ctr.wrapping_add(4)), lanes));
        w13 = vaddq_u32(w13, vld1q_dup_u32(state.as_ptr().add(13)));
        w14 = vaddq_u32(w14, vld1q_dup_u32(state.as_ptr().add(14)));
        w15 = vaddq_u32(w15, vld1q_dup_u32(state.as_ptr().add(15)));
    }

    let first = [
        transpose(v0, v1, v2, v3),
        transpose(v4, v5, v6, v7),
        transpose(v8, v9, v10, v11),
        transpose(v12, v13, v14, v15),
    ];
    let second = [
        transpose(w0, w1, w2, w3),
        transpose(w4, w5, w6, w7),
        transpose(w8, w9, w10, w11),
        transpose(w12, w13, w14, w15),
    ];

    // Block `b` is element `b` of all four row arrays, in row order.
    let slots: [[uint32x4_t; 4]; 4] =
        core::array::from_fn(|b| [first[0][b], first[1][b], first[2][b], first[3][b]]);
    let later: [[uint32x4_t; 4]; 4] =
        core::array::from_fn(|b| [second[0][b], second[1][b], second[2][b], second[3][b]]);

    // The pass's first block is block zero: its first two rows are the one-time key, its last two are dropped.
    let mut skip = 0usize;
    if let Some(one_time) = head {
        let (key_rows, _) = one_time.as_chunks_mut::<16>();
        xor_row(&mut key_rows[0], slots[0][0]);
        xor_row(&mut key_rows[1], slots[0][1]);
        skip = 1;
    }
    for (i, (block, slot)) in out
        .as_chunks_mut::<64>()
        .0
        .iter_mut()
        .zip(slots.into_iter().chain(later).skip(skip))
        .enumerate()
    {
        if FROM {
            store_block_from(block, &src[i * 64..i * 64 + 64], slot);
        } else {
            store_block(block, slot);
        }
    }
}

#[inline(always)]
fn pass(state: &[u32; 16], ctr: u32, head: Option<&mut [u8; 32]>, out: &mut [u8]) {
    pass_impl::<false>(state, ctr, head, &[], out);
}

/// The eight-block pass over whole passes, its tail straight to `xor_tail` with this state: a pass leaves fewer than `group_bytes` so the group loop never runs, and as in `chacha::xor_blocks` the head is block `start`'s keystream while the first byte encrypts under `start + 1`.
pub(crate) fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    let state = base_state(key, nonce);
    let rows = base::<Wide>(&state);
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

    blocks + xor_tail::<Wide>(&state, &rows, ctr, head, rest)
}

#[inline]
pub(crate) fn xor_blocks_from(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    src: &[u8],
    dst: &mut [u8],
) -> u32 {
    let state = base_state(key, nonce);
    let rows = base::<Wide>(&state);
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

    blocks + xor_tail_from::<Wide>(&state, &rows, ctr, head, src, rest)
}

#[cfg(test)]
mod tests {
    use super::{xor_blocks, PASS_BYTES};
    use crate::chacha::{xor_ladder, Wide};

    /// The pass against the ladder it replaced, byte for byte, at every length around its boundaries and across the counter's ends.
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

                let our_blocks = xor_blocks(&key, &nonce, start, Some(&mut our_key), &mut ours);
                let their_blocks =
                    xor_ladder::<Wide>(&key, &nonce, start, Some(&mut their_key), &mut theirs);

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

    /// Without a head, and over the lengths where a pass does not divide.
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
            let our_blocks = xor_blocks(&key, &nonce, 0, None, &mut ours);
            let their_blocks = xor_ladder::<Wide>(&key, &nonce, 0, None, &mut theirs);
            assert_eq!(ours, theirs, "ciphertext at {len} bytes");
            assert_eq!(our_blocks, their_blocks, "blocks at {len} bytes");
        }
    }
}
