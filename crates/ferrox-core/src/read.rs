/// Grows `buf` to `target` while keeping every byte the read may touch initialised.
///
/// `init` is the first byte the buffer has not initialised yet; it may sit past `len`, where a
/// previous read left a zeroed tail. Only `init..target` is zeroed, and a reallocation resets
/// the tail because the allocator does not carry spare capacity across a move.
pub fn init_room(buf: &mut Vec<u8>, init: &mut usize, target: usize) {
    let len = buf.len();
    debug_assert!(target >= len, "a read room never shrinks the data");
    if *init < len || *init > buf.capacity() {
        *init = len;
    }
    let cap = buf.capacity();
    if target > cap {
        buf.reserve(target - len);
        if buf.capacity() != cap {
            *init = len;
        }
    }
    if target > *init {
        let start = *init - len;
        let end = target - len;
        for slot in &mut buf.spare_capacity_mut()[start..end] {
            slot.write(0);
        }
        *init = target;
    }
    // SAFETY: every byte below `target` is initialised — data to `len`, zeros or an earlier read to `init`, and `init..target` just written above.
    unsafe { buf.set_len(target) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reused_tail_keeps_its_allocation_and_stays_zeroed() {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"data");
        let mut init = 0;
        init_room(&mut buf, &mut init, 32);
        let base = buf.as_ptr();
        let cap = buf.capacity();
        assert_eq!(&buf[..4], b"data");
        assert!(buf[4..].iter().all(|&byte| byte == 0));
        buf[4..8].copy_from_slice(b"next");
        buf.truncate(8);
        init_room(&mut buf, &mut init, 32);
        assert_eq!(buf.as_ptr(), base, "the tail keeps the allocation");
        assert_eq!(buf.capacity(), cap, "and its capacity");
        assert_eq!(&buf[..8], b"datanext");
        assert!(buf[8..].iter().all(|&byte| byte == 0));
    }
}
