pub fn fill_exact(key: &[u8; 32], nonce: &[u8; 12], start_block: u32, buf: &mut [u8]) -> u64 {
    let blocks = blocks_for(buf.len());
    assert!(
        blocks <= u64::from(u32::MAX) - u64::from(start_block),
        "chacha20 block counter would wrap; a nonce's keystream would repeat"
    );

    u64::from(crate::chacha::xor_blocks(
        key,
        nonce,
        start_block,
        None,
        buf,
    ))
}

pub fn fill_exact_with_head(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start_block: u32,
    head: &mut [u8; 32],
    buf: &mut [u8],
) -> u64 {
    let blocks = blocks_for(buf.len() + 64);
    assert!(
        blocks <= u64::from(u32::MAX) - u64::from(start_block),
        "chacha20 block counter would wrap; a nonce's keystream would repeat"
    );
    u64::from(crate::chacha::xor_blocks(
        key,
        nonce,
        start_block,
        Some(head),
        buf,
    ))
}

pub const fn blocks_for(buf_len: usize) -> u64 {
    (buf_len as u64).div_ceil(64)
}

pub const fn blocks_with_head_match(buf_len: usize, generated: u64) -> bool {
    generated == blocks_for(buf_len + 64)
}

pub const fn blocks_match(buf_len: usize, generated: u64) -> bool {
    generated == blocks_for(buf_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SWEEP: ([u32; 3], [usize; 6]) = ([0, 1, 65_535], [0, 1, 63, 64, 65, 256]);

    #[test]
    fn the_ladder_reports_the_blocks_the_caller_asked_for() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &start_block in &SWEEP.0 {
            for &len in &SWEEP.1 {
                let mut buf = vec![0u8; len];
                let generated = fill_exact(&key, &nonce, start_block, &mut buf);
                assert!(
                    blocks_match(len, generated),
                    "start {start_block} len {len}: the ladder reported {generated} blocks for a \
                     buffer of {len} bytes, which needs {}",
                    blocks_for(len)
                );
            }
        }
    }

    #[test]
    fn the_head_is_the_references_own_first_block_and_the_rest_is_unshifted() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &start_block in &[0u32, 1, 8] {
            for &len in &[0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 256, 8192] {
                let plain: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                    .collect();

                let mut want_body = plain.clone();
                crate::reference::reference_xor(&key, &nonce, start_block + 1, &mut want_body);
                let mut head_block = [0u8; 64];
                crate::reference::reference_xor(&key, &nonce, start_block, &mut head_block);
                let want_head: [u8; 32] = head_block[..32].try_into().expect("32 bytes");

                let mut got_body = plain;
                let mut got_head = [0u8; 32];
                let generated =
                    fill_exact_with_head(&key, &nonce, start_block, &mut got_head, &mut got_body);

                assert_eq!(
                    got_body, want_body,
                    "body: start {start_block} len {len} must be block start+1 onward"
                );
                assert_eq!(
                    got_head, want_head,
                    "head: start {start_block} len {len} must be the first 32 of block {start_block}"
                );
                assert!(
                    blocks_with_head_match(len, generated),
                    "start {start_block} len {len}: reported {generated} blocks, needs {}",
                    blocks_for(len + 64)
                );
            }
        }
    }

    #[test]
    fn the_head_block_count_check_fails_when_the_count_is_wrong() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &len in &[0usize, 1, 63, 64, 65, 255, 256, 257, 8192] {
            let mut buf = vec![0u8; len];
            let mut head = [0u8; 32];
            let generated = fill_exact_with_head(&key, &nonce, 0, &mut head, &mut buf);
            assert!(
                blocks_with_head_match(len, generated),
                "len {len}: the real fused pass must match"
            );
            assert!(
                !blocks_with_head_match(len, generated + 1),
                "len {len}: one block too many must be rejected"
            );
            if generated > 0 {
                assert!(
                    !blocks_with_head_match(len, generated - 1),
                    "len {len}: one block too few must be rejected"
                );
            }
        }
    }

    #[test]
    fn a_head_with_an_empty_body_is_still_one_correct_block() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        let mut block = [0u8; 64];
        crate::reference::reference_xor(&key, &nonce, 0, &mut block);
        let want: [u8; 32] = block[..32].try_into().expect("32 bytes");

        let mut got = [0u8; 32];
        let generated = fill_exact_with_head(&key, &nonce, 0, &mut got, &mut []);
        assert_eq!(got, want, "the head of an empty body");
        assert_eq!(generated, 1, "an empty body plus a head is one block");
        assert!(blocks_with_head_match(0, generated));
    }

    #[test]
    fn the_head_refuses_a_wrapping_counter_too() {
        let mut buf = [0u8; 8];
        let mut head = [0u8; 32];
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_exact_with_head(&[0u8; 32], &[0u8; 12], u32::MAX, &mut head, &mut buf)
        }));
        assert!(r.is_err(), "a wrapping counter must be refused, not obeyed");
        assert_eq!(buf, [0u8; 8], "the guard must fire before any keystream");
        assert_eq!(head, [0u8; 32], "and before the head is written");
    }

    #[test]
    fn the_block_count_check_fails_when_the_count_is_wrong() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &len in &[0usize, 1, 63, 64, 65, 255, 256, 257, 512, 16384] {
            let mut buf = vec![0u8; len];
            let generated = fill_exact(&key, &nonce, 0, &mut buf);
            assert!(
                blocks_match(len, generated),
                "len {len}: the real ladder must match"
            );
            assert!(
                !blocks_match(len, generated + 1),
                "len {len}: one block too many must be rejected"
            );
            if generated > 0 {
                assert!(
                    !blocks_match(len, generated - 1),
                    "len {len}: one block too few must be rejected"
                );
            }
        }
    }

    #[test]
    fn replayed_first_group_fails_the_identity_check() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        let mut want = vec![0u8; 1024];
        crate::reference::reference_xor(&key, &nonce, 0, &mut want);

        let mut wrong = vec![0u8; 1024];
        fill_exact(&key, &nonce, 0, &mut wrong[..512]);
        fill_exact(&key, &nonce, 0, &mut wrong[512..]);
        assert_ne!(
            wrong, want,
            "start 0 len 1024: replaying the first 512 bytes must not match"
        );

        let mut right = vec![0u8; 1024];
        fill_exact(&key, &nonce, 0, &mut right[..512]);
        fill_exact(&key, &nonce, 8, &mut right[512..]);
        assert_eq!(right, want, "start 0 len 1024: advancing by 8 must match");
    }

    #[test]
    fn a_head_whose_tail_never_xored_its_last_block_fails_the_identity_check() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for len in 385..=447usize {
            let mut want = vec![0u8; len + 64];
            crate::reference::reference_xor(&key, &nonce, 0, &mut want);
            let (want_block, want_body) = want.split_at(64);
            let want_head = &want_block[..32];

            let mut got_body = vec![0u8; len];
            let mut got_head = [0u8; 32];
            fill_exact_with_head(&key, &nonce, 0, &mut got_head, &mut got_body);
            assert_eq!(got_head, want_head, "len {len}: head must match");
            assert_eq!(got_body, want_body, "len {len}: body must match");

            let mut wrong = vec![0u8; len];
            fill_exact(&key, &nonce, 1, &mut wrong[..len - 64]);
            let mut wrong_head = [0u8; 32];
            fill_exact(&key, &nonce, 0, &mut wrong_head);
            assert_ne!(
                (wrong_head.as_slice(), wrong.as_slice()),
                (want_head, want_body),
                "len {len}: a body whose last block was never xored must not match"
            );
        }
    }

    #[test]
    fn blocks_for_is_the_ceiling() {
        assert_eq!(blocks_for(65), 2);
        assert_eq!(blocks_for(64), 1);
        assert_eq!(blocks_for(128), 2);
        assert_eq!(blocks_for(129), 3);
        assert_eq!(blocks_for(0), 0);
    }

    #[test]
    fn refuses_a_wrapping_counter() {
        let mut buf = [0u8; 64];
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_exact(&[0u8; 32], &[0u8; 12], u32::MAX, &mut buf)
        }));
        assert!(r.is_err(), "a wrapping counter must be refused, not obeyed");
        assert_eq!(
            buf, [0u8; 64],
            "the guard must fire before any keystream is written"
        );
    }
}
