//! Sixteen blocks per pass over thirty-two `avx512f` registers, one state word each: the body exists once over `Wide16`, shipped as `Z16` and replayed as portable `P16`, because AVX-512 is emulated nowhere this tree tests and the transpose is sixty-four gathers for sixteen blocks.

#![allow(
    clippy::inline_always,
    reason = "the pass is only sound inlined into its caller's target_feature function"
)]

/// Blocks one pass covers: sixteen lanes of one word each.
pub(crate) const PASS_BLOCKS: u32 = 16;

/// Bytes one pass covers.
pub(crate) const PASS_BYTES: usize = PASS_BLOCKS as usize * 64;

/// `IDX[k][upper]`: a transpose stage's index vector — element `idx & 0x0f` of the second register when `idx & 0x10` is set, else of the first; the eight are written out and `tests` checks them against that definition.
pub(crate) const IDX: [[[i32; 16]; 2]; 4] = [
    [
        [0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30],
        [1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31],
    ],
    [
        [0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29],
        [2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31],
    ],
    [
        [0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27],
        [4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31],
    ],
    [
        [0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23],
        [8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31],
    ],
];

/// The sixteen-lane operations one pass needs: lane `b` of the register answering to word `w` is word `w` of block `b`, so a diagonal quarter round renames registers and never touches a lane.
pub(crate) trait Wide16: Copy {
    fn broadcast(word: u32) -> Self;

    /// `[0, 1, …, 15]` — the block counter of each lane.
    fn lanes() -> Self;

    fn add(self, o: Self) -> Self;
    fn bitxor(self, o: Self) -> Self;

    fn rotl16(self) -> Self;
    fn rotl12(self) -> Self;
    fn rotl8(self) -> Self;
    fn rotl7(self) -> Self;

    /// One transpose stage over a pair: `self` is the register whose bit `k` is clear, `high` the set one, `upper` says which the result answers to.
    fn gather(self, high: Self, stage: usize, upper: usize) -> Self;

    /// Xor thirty-two bytes, the pass's first block's first two rows, into the caller's one-time key.
    fn xor_lo32(self, dst: &mut [u8]);

    /// Xor sixty-four bytes: one whole block.
    fn xor_store(self, dst: &mut [u8]);

    /// Xor a whole block's keystream with the source and write the destination.
    fn xor_store_from(self, src: &[u8], dst: &mut [u8]);
}

#[inline(always)]
fn quarter<V: Wide16>(a: &mut V, b: &mut V, c: &mut V, d: &mut V) {
    *a = a.add(*b);
    *d = d.bitxor(*a).rotl16();
    *c = c.add(*d);
    *b = b.bitxor(*c).rotl12();
    *a = a.add(*b);
    *d = d.bitxor(*a).rotl8();
    *c = c.add(*d);
    *b = b.bitxor(*c).rotl7();
}

/// One double round over the pass's sixteen registers: the four columns, then the same registers renamed as the four diagonals.
macro_rules! double_round {
    (
        $v0:ident, $v1:ident, $v2:ident, $v3:ident, $v4:ident, $v5:ident, $v6:ident, $v7:ident,
        $v8:ident, $v9:ident, $v10:ident, $v11:ident, $v12:ident, $v13:ident, $v14:ident,
        $v15:ident
    ) => {
        quarter(&mut $v0, &mut $v4, &mut $v8, &mut $v12);
        quarter(&mut $v1, &mut $v5, &mut $v9, &mut $v13);
        quarter(&mut $v2, &mut $v6, &mut $v10, &mut $v14);
        quarter(&mut $v3, &mut $v7, &mut $v11, &mut $v15);
        quarter(&mut $v0, &mut $v5, &mut $v10, &mut $v15);
        quarter(&mut $v1, &mut $v6, &mut $v11, &mut $v12);
        quarter(&mut $v2, &mut $v7, &mut $v8, &mut $v13);
        quarter(&mut $v3, &mut $v4, &mut $v9, &mut $v14);
    };
}

#[inline(always)]
fn transpose<V: Wide16>(m: &mut [V; 16]) {
    for stage in 0..4usize {
        let bit = 1usize << stage;
        for low in 0..16usize {
            if low & bit == 0 {
                let p = m[low];
                let q = m[low | bit];
                m[low] = p.gather(q, stage, 0);
                m[low | bit] = p.gather(q, stage, 1);
            }
        }
    }
}

/// One sixteen-block pass, the message xored in place: `out` is `PASS_BYTES` long, or sixty-four less with a `head` taking the first thirty-two bytes of the one-time-key block and dropping its tail, over a nonce state with a zero counter.
#[inline(always)]
#[allow(
    clippy::too_many_lines,
    reason = "the round's sixteen quarter rounds are written out because their register names are the diagonal, and the transpose and the store follow those same names"
)]
pub(crate) fn pass<V: Wide16>(
    state: &[u32; 16],
    ctr: u32,
    head: Option<&mut [u8; 32]>,
    out: &mut [u8],
) {
    pass_impl::<V, false>(state, ctr, head, &[], out);
}

#[inline(always)]
#[allow(
    clippy::too_many_lines,
    reason = "the round's sixteen quarter rounds are written out because their register names are the diagonal, and the transpose and the store follow those same names"
)]
pub(crate) fn pass_impl<V: Wide16, const FROM: bool>(
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
        "a pass writes sixteen blocks, or fifteen beside a head"
    );

    let lanes = V::lanes();

    // Every register starts from the same broadcast state: only the counter differs, and it is what makes one block another.
    let mut v0 = V::broadcast(state[0]);
    let mut v1 = V::broadcast(state[1]);
    let mut v2 = V::broadcast(state[2]);
    let mut v3 = V::broadcast(state[3]);
    let mut v4 = V::broadcast(state[4]);
    let mut v5 = V::broadcast(state[5]);
    let mut v6 = V::broadcast(state[6]);
    let mut v7 = V::broadcast(state[7]);
    let mut v8 = V::broadcast(state[8]);
    let mut v9 = V::broadcast(state[9]);
    let mut v10 = V::broadcast(state[10]);
    let mut v11 = V::broadcast(state[11]);
    let mut v12 = V::add(V::broadcast(ctr), lanes);
    let mut v13 = V::broadcast(state[13]);
    let mut v14 = V::broadcast(state[14]);
    let mut v15 = V::broadcast(state[15]);

    for _ in 0..10 {
        double_round!(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15);
    }

    // The initial state reloads from memory instead of sixteen more registers: a broadcast load is a cycle, and `state[12]` is zero.
    v0 = V::add(v0, V::broadcast(state[0]));
    v1 = V::add(v1, V::broadcast(state[1]));
    v2 = V::add(v2, V::broadcast(state[2]));
    v3 = V::add(v3, V::broadcast(state[3]));
    v4 = V::add(v4, V::broadcast(state[4]));
    v5 = V::add(v5, V::broadcast(state[5]));
    v6 = V::add(v6, V::broadcast(state[6]));
    v7 = V::add(v7, V::broadcast(state[7]));
    v8 = V::add(v8, V::broadcast(state[8]));
    v9 = V::add(v9, V::broadcast(state[9]));
    v10 = V::add(v10, V::broadcast(state[10]));
    v11 = V::add(v11, V::broadcast(state[11]));
    v12 = V::add(v12, V::add(V::broadcast(ctr), lanes));
    v13 = V::add(v13, V::broadcast(state[13]));
    v14 = V::add(v14, V::broadcast(state[14]));
    v15 = V::add(v15, V::broadcast(state[15]));

    let mut m = [
        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
    ];
    transpose(&mut m);

    // The pass's first block is block zero: its first two rows are the one-time key, its last two are dropped, so the buffer starts at block one.
    let mut skip = 0usize;
    if let Some(one_time) = head {
        m[0].xor_lo32(one_time);
        skip = 1;
    }
    for (i, (block, word)) in out
        .as_chunks_mut::<64>()
        .0
        .iter_mut()
        .zip(m.into_iter().skip(skip))
        .enumerate()
    {
        if FROM {
            word.xor_store_from(&src[i * 64..i * 64 + 64], block);
        } else {
            word.xor_store(block);
        }
    }
}

/// Whole passes take the pass, the rest the caller's remainder handler: as in `chacha::xor_blocks` the head is block `start`'s keystream while the buffer's first byte encrypts under block `start + 1`.
#[inline(always)]
pub(crate) fn wide_blocks<V: Wide16>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
    rest: impl FnOnce(&[u8; 32], &[u8; 12], u32, Option<&mut [u8; 32]>, &mut [u8]) -> u32,
) -> u32 {
    let state = crate::chacha::base_state(key, nonce);
    let mut ctr = start;
    let mut left = buf;
    let mut blocks = 0u32;

    loop {
        // A head is one of the pass's blocks, consumed with only its first two rows output, so a headed pass writes fifteen blocks.
        let take = if head.is_some() {
            PASS_BYTES - 64
        } else {
            PASS_BYTES
        };
        if left.len() < take {
            break;
        }
        let (chunk, tail) = left.split_at_mut(take);
        pass::<V>(&state, ctr, head.take(), chunk);
        blocks += PASS_BLOCKS;
        ctr = ctr.wrapping_add(PASS_BLOCKS);
        left = tail;
    }

    blocks + rest(key, nonce, ctr, head, left)
}

/// The same pass loop reading a source and writing a destination; the remainder handler is the destination's own fused tail.
#[cfg_attr(
    not(target_arch = "x86_64"),
    allow(
        dead_code,
        reason = "AVX-512 is the only caller; the portable checker uses it under test"
    )
)]
#[inline(always)]
pub(crate) fn wide_blocks_from<V: Wide16>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    src: &[u8],
    dst: &mut [u8],
    rest: impl FnOnce(&[u8; 32], &[u8; 12], u32, Option<&mut [u8; 32]>, &[u8], &mut [u8]) -> u32,
) -> u32 {
    let state = crate::chacha::base_state(key, nonce);
    let mut ctr = start;
    let mut src = src;
    let mut left = dst;
    let mut blocks = 0u32;

    loop {
        let take = if head.is_some() {
            PASS_BYTES - 64
        } else {
            PASS_BYTES
        };
        if left.len() < take {
            break;
        }
        let (chunk, tail) = left.split_at_mut(take);
        let (chunk_src, tail_src) = src.split_at(take);
        pass_impl::<V, true>(&state, ctr, head.take(), chunk_src, chunk);
        blocks += PASS_BLOCKS;
        ctr = ctr.wrapping_add(PASS_BLOCKS);
        left = tail;
        src = tail_src;
    }

    blocks + rest(key, nonce, ctr, head, src, left)
}

/// Sixteen `u32`: not a fallback — nothing dispatches to it — but the pass's checker, the same body in a form a machine without AVX-512 can execute.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct P16(pub(crate) [u32; 16]);

#[cfg(test)]
impl Wide16 for P16 {
    #[inline]
    fn broadcast(word: u32) -> Self {
        Self([word; 16])
    }

    #[inline]
    fn lanes() -> Self {
        Self(core::array::from_fn(|i| i as u32))
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self(core::array::from_fn(|i| self.0[i].wrapping_add(o.0[i])))
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self(core::array::from_fn(|i| self.0[i] ^ o.0[i]))
    }

    #[inline]
    fn rotl16(self) -> Self {
        Self(core::array::from_fn(|i| self.0[i].rotate_left(16)))
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(core::array::from_fn(|i| self.0[i].rotate_left(12)))
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(core::array::from_fn(|i| self.0[i].rotate_left(8)))
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(core::array::from_fn(|i| self.0[i].rotate_left(7)))
    }

    #[inline]
    fn gather(self, high: Self, stage: usize, upper: usize) -> Self {
        let idx = IDX[stage][upper];
        Self(core::array::from_fn(|i| {
            let at = idx[i];
            let source = if at & 0x10 == 0 { self.0 } else { high.0 };
            source[(at & 0x0f) as usize]
        }))
    }

    #[inline]
    fn xor_lo32(self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), 32, "the one-time key is two rows");
        xor_words(&self.0, dst);
    }

    #[inline]
    fn xor_store(self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), 64, "a block is sixteen words");
        xor_words(&self.0, dst);
    }

    #[inline]
    fn xor_store_from(self, src: &[u8], dst: &mut [u8]) {
        debug_assert_eq!(src.len(), 64, "a block is sixteen words");
        debug_assert_eq!(dst.len(), 64, "a block is sixteen words");
        for (word, (src, dst)) in self.0.iter().zip(
            src.as_chunks::<4>()
                .0
                .iter()
                .zip(dst.as_chunks_mut::<4>().0),
        ) {
            *dst = (u32::from_le_bytes(*src) ^ word).to_le_bytes();
        }
    }
}

#[cfg(test)]
fn xor_words(words: &[u32; 16], dst: &mut [u8]) {
    for (word, bytes) in words.iter().zip(dst.as_chunks_mut::<4>().0) {
        for (b, v) in bytes.iter_mut().zip(word.to_le_bytes()) {
            *b ^= v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{wide_blocks, wide_blocks_from, IDX, P16, PASS_BLOCKS, PASS_BYTES};
    use crate::chacha::{portable::U4, xor_ladder, xor_ladder_from};

    /// The index network replayed in scalar code: element `b` of register `j` after four stages must be element `j` of register `b` before them.
    #[test]
    fn the_four_stages_are_the_sixteen_by_sixteen_transpose() {
        let mut m: [[u32; 16]; 16] =
            core::array::from_fn(|w| core::array::from_fn(|b| (w * 16 + b) as u32));
        for stage in 0..4usize {
            let bit = 1usize << stage;
            let mut next = [[0u32; 16]; 16];
            for low in 0..16usize {
                if low & bit != 0 {
                    continue;
                }
                for upper in 0..2usize {
                    let idx = IDX[stage][upper];
                    let source = [m[low], m[low | bit]];
                    for lane in 0..16usize {
                        let at = idx[lane];
                        next[low | (upper << stage)][lane] =
                            source[usize::from(at & 0x10 != 0)][(at & 0x0f) as usize];
                    }
                }
            }
            m = next;
        }
        for (b, row) in m.iter().enumerate() {
            for (w, got) in row.iter().enumerate() {
                assert_eq!(
                    *got,
                    (w * 16 + b) as u32,
                    "register {b} lane {w} must be word {w} of block {b}"
                );
            }
        }
    }

    /// The pass against the ladder at every boundary length and counter end, portable instantiation against `portable::U4`.
    #[test]
    fn the_portable_pass_is_the_ladder_at_every_length() {
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        // Miri interprets every byte, so it walks the same boundaries as a sample; the dense sweep runs natively.
        let lengths: Vec<usize> = if cfg!(miri) {
            vec![
                0,
                1,
                63,
                64,
                65,
                255,
                256,
                257,
                1023,
                1024,
                1025,
                2047,
                2048,
                2049,
                2 * PASS_BYTES + 8,
            ]
        } else {
            (0..=(2 * PASS_BYTES + 8))
                .chain([1023, 1024, 1025, 4095, 4096, 4097, 16_384])
                .collect()
        };

        for &len in &lengths {
            for start in [0u32, 1, 7, u32::MAX - 17] {
                let plain: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(251).wrapping_add(11))
                    .collect();
                let mut ours = plain.clone();
                let mut theirs = plain.clone();
                let mut our_key = [0u8; 32];
                let mut their_key = [0u8; 32];

                let our_blocks = wide_blocks::<P16>(
                    &key,
                    &nonce,
                    start,
                    Some(&mut our_key),
                    &mut ours,
                    xor_ladder::<U4>,
                );
                let their_blocks =
                    xor_ladder::<U4>(&key, &nonce, start, Some(&mut their_key), &mut theirs);

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
    fn the_portable_pass_is_the_ladder_without_a_head() {
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
            let our_blocks = wide_blocks::<P16>(&key, &nonce, 0, None, &mut ours, xor_ladder::<U4>);
            let their_blocks = xor_ladder::<U4>(&key, &nonce, 0, None, &mut theirs);
            assert_eq!(ours, theirs, "ciphertext at {len} bytes");
            assert_eq!(our_blocks, their_blocks, "blocks at {len} bytes");
        }
    }

    /// A pass is sixteen blocks of counter however long the buffer is, and the head is the pass's own first block rather than one of its own.
    #[test]
    fn a_headed_pass_consumes_its_own_first_block() {
        let mut head = [0u8; 32];
        let mut buf = vec![0u8; PASS_BYTES - 64];
        let blocks = wide_blocks::<P16>(
            &[7u8; 32],
            &[9u8; 12],
            0,
            Some(&mut head),
            &mut buf,
            |_, _, _, _, _| 0,
        );
        assert_eq!(blocks, PASS_BLOCKS, "a headed pass is sixteen blocks");
        assert_ne!(head, [0u8; 32], "the head is written");

        let mut head = [0u8; 32];
        let mut buf = vec![0u8; PASS_BYTES - 65];
        let blocks = wide_blocks::<P16>(
            &[7u8; 32],
            &[9u8; 12],
            0,
            Some(&mut head),
            &mut buf,
            |_, _, _, head, buf| u32::from(head.is_some() || !buf.is_empty()),
        );
        assert_eq!(
            blocks, 1,
            "one byte short of a pass is no pass at all, and the head is left to the caller"
        );
        assert_eq!(head, [0u8; 32], "and the head is not written here");
    }

    /// Passing the whole buffer through leaves the counter and block count where the ladder would have them.
    #[test]
    fn two_passes_advance_the_counter_by_two_passes() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let mut buf = vec![0u8; 2 * PASS_BYTES];
        let mut want = vec![0u8; 2 * PASS_BYTES];
        let blocks = wide_blocks::<P16>(&key, &nonce, 0, None, &mut buf, |_, _, _, _, _| 0);
        assert_eq!(blocks, 2 * PASS_BLOCKS, "two whole passes");
        xor_ladder::<U4>(&key, &nonce, 0, None, &mut want[..PASS_BYTES]);
        xor_ladder::<U4>(&key, &nonce, PASS_BLOCKS, None, &mut want[PASS_BYTES..]);
        assert_eq!(buf, want, "the counter the second pass starts from");
    }
    #[test]
    fn the_from_pass_is_the_ladder_and_leaves_the_source_alone() {
        let key = [0x6du8; 32];
        let nonce = [0xc4u8; 12];
        for &len in &[
            0usize,
            1,
            63,
            64,
            65,
            PASS_BYTES - 1,
            PASS_BYTES,
            PASS_BYTES + 1,
            2 * PASS_BYTES,
        ] {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(181).wrapping_add(17))
                .collect();
            let original = plain.clone();
            let mut in_place = plain.clone();
            let mut dst = vec![0u8; len];
            let want = wide_blocks::<P16>(&key, &nonce, 3, None, &mut in_place, xor_ladder::<U4>);
            let got = wide_blocks_from::<P16>(
                &key,
                &nonce,
                3,
                None,
                &plain,
                &mut dst,
                xor_ladder_from::<U4>,
            );
            assert_eq!(got, want, "len {len}: block count");
            assert_eq!(dst, in_place, "len {len}: bytes");
            assert_eq!(plain, original, "len {len}: source moved");
        }
    }
}
