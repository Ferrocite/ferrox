use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

use super::segment::{
    write_data_header, AckSegment, DataSegment, OutgoingHeader, SegmentOption,
    DATA_SEGMENT_OVERHEAD,
};

/// The data-segment header the arena keeps in front of every payload.
const DATA_HEADER: usize = DATA_SEGMENT_OVERHEAD as usize;

/// One segment the sender still owes the wire. The payload is a half-open range
/// into `SendingWindow::arena` rather than an owned buffer: at the default
/// 1 332-byte MSS that was one `malloc` and one `free` per 1 332 bytes sent,
/// which at 100 Mbps is about 9 400 pairs a second per direction.
#[derive(Debug, Clone, Copy)]
struct Outgoing {
    header: OutgoingHeader,
    transmit: u32,
    timeout: u32,
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
pub struct SendingWindow {
    cache: VecDeque<Outgoing>,
    arena: Vec<u8>,
    total_in_flight: u32,
}

impl SendingWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> u32 {
        self.cache.len() as u32
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn push(&mut self, number: u32, payload: &[u8]) {
        // The payload keeps an 18-byte header gap before it, so the segment is contiguous in the arena and can be sent without copying the payload.
        let start = self.arena.len();
        self.arena.resize(start + DATA_HEADER, 0);
        self.arena.extend_from_slice(payload);
        self.cache.push_back(Outgoing {
            header: OutgoingHeader {
                conv: 0,
                option: SegmentOption::default(),
                timestamp: 0,
                number,
                sending_next: 0,
            },
            transmit: 0,
            timeout: 0,
            start,
            end: self.arena.len(),
        });
    }

    /// Drops the arena prefix no cached segment points into, once it is at least
    /// half the arena, so trimming is amortised rather than per segment.
    fn trim(&mut self) {
        // Nothing live means the whole arena is garbage; otherwise the oldest live range ends the dead prefix, whether or not the cache reaches empty between bursts.
        let Some(front) = self.cache.front() else {
            self.arena.clear();
            return;
        };
        let base = front.start;
        if base == 0 || base * 2 < self.arena.len() {
            return;
        }
        self.arena.drain(..base);
        for seg in &mut self.cache {
            seg.start -= base;
            seg.end -= base;
        }
    }

    #[must_use]
    pub fn arena_capacity(&self) -> usize {
        self.arena.capacity()
    }

    #[must_use]
    pub fn first_number(&self) -> u32 {
        self.cache.front().map_or(0, |s| s.header.number)
    }

    pub fn clear(&mut self, una: u32) {
        while let Some(seg) = self.cache.front() {
            if seg.header.number >= una {
                break;
            }
            self.cache.pop_front();
        }
        self.trim();
    }

    pub fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        let third = rto / 3;
        for seg in &mut self.cache {
            if seg.header.number == number || number.wrapping_sub(seg.header.number) > 0x7FFF_FFFF {
                return;
            }
            if seg.transmit > 0 && seg.timeout > third {
                seg.timeout -= third;
            }
        }
    }

    pub fn remove(&mut self, number: u32) -> bool {
        let Some(index) = self.cache.iter().position(|s| s.header.number >= number) else {
            return false;
        };
        if self.cache[index].header.number != number {
            return false;
        }
        if self.total_in_flight > 0 {
            self.total_in_flight -= 1;
        }
        self.cache.remove(index);
        self.trim();
        true
    }

    pub fn release(&mut self) {
        self.cache.clear();
        self.arena.clear();
        self.total_in_flight = 0;
    }

    // The clock, the window bound, the four header fields the wire needs, and the writer — every one is read per segment and none is derivable there.
    #[allow(
        clippy::too_many_arguments,
        reason = "one header build per segment, not an API surface"
    )]
    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        max_in_flight: u32,
        conv: u16,
        sending_next: u32,
        option: SegmentOption,
        write: &mut dyn FnMut(&[u8]),
    ) -> Option<u32> {
        let mut lost = 0u32;
        let mut in_flight = 0u32;
        // `self.cache` and `self.arena` are disjoint fields, so a segment's header is written into the arena and the whole range handed out while the entry it came from is still borrowed from the cache.
        for seg in &mut self.cache {
            if current.wrapping_sub(seg.timeout) >= 0x7FFF_FFFF {
                continue;
            }
            if seg.transmit == 0 {
                self.total_in_flight += 1;
            } else {
                lost += 1;
            }
            seg.timeout = current + rto;
            seg.transmit += 1;
            let start = seg.start;
            let end = seg.end;
            // Drop the fresh header into the gap, then hand the writer the whole arena range: the payload goes to the socket without a second copy.
            write_data_header(
                OutgoingHeader {
                    conv,
                    option,
                    timestamp: current,
                    number: seg.header.number,
                    sending_next,
                },
                (end - start - DATA_HEADER) as u16,
                &mut self.arena[start..start + DATA_HEADER],
            );
            write(&self.arena[start..end]);
            in_flight += 1;
            if in_flight >= max_in_flight {
                break;
            }
        }
        if in_flight > 0 && self.total_in_flight != 0 {
            Some(lost * 100 / self.total_in_flight)
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct ReceivingWindow {
    cache: HashMap<u32, DataSegment>,
}

impl ReceivingWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, id: u32, value: DataSegment) -> bool {
        match self.cache.entry(id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(value);
                true
            }
        }
    }

    #[must_use]
    pub fn has(&self, id: u32) -> bool {
        self.cache.contains_key(&id)
    }

    pub fn remove(&mut self, id: u32) -> Option<DataSegment> {
        self.cache.remove(&id)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AckEntry {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

// Upstream bounds an ack's number list and the deferred-candidate buffer separately, and they are separate limits that happen to share a value.
const FLUSH_CANDIDATES: usize = 128;

#[derive(Debug, Default)]
pub struct AckList {
    entries: Vec<AckEntry>,
    candidates: Vec<u32>,
    /// The ack segment this list is filling. Reused across the whole run of
    /// flushes and across every ack one flush emits, so its `numbers` list
    /// keeps one allocation instead of a fresh `Vec<u32>` per emitted ack.
    scratch: AckSegment,
    dirty: bool,
}

impl AckList {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, number: u32, timestamp: u32) {
        self.entries.push(AckEntry {
            number,
            timestamp,
            next_flush: 0,
        });
        self.dirty = true;
    }

    pub fn clear(&mut self, una: u32) {
        let mut kept = 0;
        for i in 0..self.entries.len() {
            if self.entries[i].number < una {
                continue;
            }
            if i != kept {
                self.entries[kept] = self.entries[i];
            }
            kept += 1;
        }
        if kept < self.entries.len() {
            self.entries.truncate(kept);
            self.dirty = true;
        }
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        limit: usize,
        write: &mut impl FnMut(&mut AckSegment),
    ) {
        // `entries`, `candidates`, `scratch` and `dirty` are disjoint fields, so the segment can be handed to the writer while its source entries are still borrowed from the same list.
        let AckList {
            entries,
            candidates,
            scratch,
            dirty,
        } = self;
        scratch.begin(limit);
        let timeout = (rto / 2).max(20);
        candidates.clear();
        for entry in entries {
            if entry.next_flush > current {
                if candidates.len() < FLUSH_CANDIDATES {
                    candidates.push(entry.number);
                }
                continue;
            }
            scratch.put_number(entry.number);
            scratch.put_timestamp(entry.timestamp);
            entry.next_flush = current + timeout;
            if scratch.is_full() {
                write(scratch);
                scratch.begin(limit);
                *dirty = false;
            }
        }
        if *dirty || !scratch.is_empty() {
            for number in &*candidates {
                if scratch.is_full() {
                    break;
                }
                scratch.put_number(*number);
            }
            write(scratch);
            *dirty = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_is_not_due_until_current_reaches_timeout() {
        let mut w = SendingWindow::new();
        w.push(1, b"hello");
        let mut emitted = Vec::new();
        w.flush(0, 100, 16, 0, 0, SegmentOption::NONE, &mut |s| {
            emitted.push(s.to_vec());
        });
        assert_eq!(emitted.len(), 1);
        emitted.clear();
        w.flush(50, 100, 16, 0, 0, SegmentOption::NONE, &mut |s| {
            emitted.push(s.to_vec());
        });
        assert_eq!(emitted.len(), 0);
        w.flush(100, 100, 16, 0, 0, SegmentOption::NONE, &mut |s| {
            emitted.push(s.to_vec());
        });
        assert_eq!(emitted.len(), 1);
    }

    fn seg_number(segment: &[u8]) -> u32 {
        u32::from_be_bytes(segment[8..12].try_into().unwrap())
    }

    fn seg_payload(segment: &[u8]) -> &[u8] {
        &segment[DATA_HEADER..]
    }

    #[test]
    fn fast_ack_cuts_the_timeout_of_earlier_segments() {
        let mut w = SendingWindow::new();
        w.push(1, b"a");
        w.push(2, b"b");
        let before = {
            let mut out = Vec::new();
            w.flush(0, 300, 16, 0, 0, SegmentOption::NONE, &mut |segment| {
                out.push(seg_number(segment));
            });
            w.cache.front().unwrap().timeout
        };
        w.handle_fast_ack(2, 300);
        assert_eq!(w.cache.front().unwrap().timeout, before - 100);
    }
    /// The claim this window makes: one buffer serves every segment, so a send
    /// costs no allocation per segment. Capacity is the witness — a per-segment
    /// `Vec` would need a fresh allocation every 1 332 bytes, and this never
    /// exceeds the high-water mark of its first few rounds.
    #[test]
    fn the_arena_serves_every_segment_without_growing() {
        let mut w = SendingWindow::new();
        let mut high = 0usize;
        for round in 0..64u32 {
            let base = round * 8;
            for n in base..base + 8 {
                w.push(n, &[n as u8; 1332]);
            }
            high = high.max(w.arena_capacity());
            assert_eq!(w.len(), 8, "round {round}");
            w.flush(100 + round, 200, 64, 0, 0, SegmentOption::NONE, &mut |_| {});
            w.clear(base + 8);
        }
        assert!(
            high <= 8 * 1332 * 3,
            "the arena reached {high} bytes for 8 live segments of 1332"
        );
        assert_eq!(w.len(), 0, "every round acknowledged its eight");
        // one buffer, reused: not one per segment, and not one that grows forever
        assert!(high >= 8 * 1332);

        // A real window never drains between reads: the new eight arrive while the last eight are still owed.
        let mut w = SendingWindow::new();
        let mut high = 0usize;
        for round in 0..64u32 {
            let base = round * 8;
            for n in base..base + 8 {
                w.push(n, &[n as u8; 1332]);
            }
            high = high.max(w.arena_capacity());
            w.flush(100 + round, 200, 64, 0, 0, SegmentOption::NONE, &mut |_| {});
            if round > 0 {
                w.clear(base);
            }
        }
        assert_eq!(w.len(), 8, "the live tail is the last round's eight");
        assert!(
            high <= 8 * 1332 * 3,
            "the live window's arena reached {high} bytes for 8 live segments of 1332"
        );
    }

    /// Trimming shifts every live range down by the trimmed prefix. If that
    /// arithmetic is wrong, a segment goes out carrying another segment's bytes,
    /// so every emitted payload must still be its own — at every offset.
    #[test]
    fn trimming_never_moves_a_live_payload() {
        for trim in [0u32, 1, 7, 8, 15, 16, 31] {
            let mut w = SendingWindow::new();
            for n in 0..32u32 {
                w.push(n, &[n as u8; 64]);
            }
            w.clear(trim);
            let mut live = Vec::new();
            w.flush(100, 200, 64, 0, 0, SegmentOption::NONE, &mut |segment| {
                live.push((seg_number(segment), seg_payload(segment).to_vec()));
            });
            assert_eq!(live.len(), (32 - trim) as usize, "trim {trim}");
            for (number, payload) in &live {
                assert_eq!(payload.len(), 64, "trim {trim}: segment {number}");
                assert!(
                    payload.iter().all(|&b| b == *number as u8),
                    "trim {trim}: segment {number} carries {:?}",
                    &payload[..8]
                );
            }
            if let Some((first, _)) = live.first() {
                assert_eq!(*first, trim, "trim {trim}: wrong first segment");
            }
        }
    }

    /// The wrapped case: numbers near `u32::MAX` must not collide in the arena.
    #[test]
    fn the_arena_does_not_confuse_wrapped_segment_numbers() {
        let mut w = SendingWindow::new();
        w.push(u32::MAX, &[0xAA; 16]);
        w.push(0, &[0xBB; 16]);
        w.clear(u32::MAX);
        let mut live = Vec::new();
        w.flush(10, 20, 8, 0, 0, SegmentOption::NONE, &mut |segment| {
            live.push((seg_number(segment), seg_payload(segment)[0]));
        });
        assert_eq!(live, vec![(u32::MAX, 0xAA), (0, 0xBB)]);
    }

    /// The emit path's copy claim, proved by pointer identity rather than by
    /// bytes: a byte test passes whether or not the payload was staged, because
    /// the staged bytes are identical. So the writer must see a slice whose base
    /// *is* the arena plus the segment's start, with the payload contiguous
    /// behind the header — no arena → staging → socket second copy.
    #[test]
    fn the_writer_gets_the_arena_range_and_not_a_copy_of_it() {
        let mut w = SendingWindow::new();
        w.push(7, &[0xA5u8; 900]);
        w.push(8, &[0x5A; 40]);
        // No push happens between here and the flush, so the base captured now is the allocation the writer's slices must live inside.
        let arena = w.arena.as_ptr();
        let mut seen = Vec::new();
        w.flush(100, 200, 16, 0x0102, 9, SegmentOption::NONE, &mut |s| {
            seen.push((s.as_ptr() as usize, s.as_ptr() as usize + s.len(), s.len()));
        });
        assert_eq!(seen.len(), 2);
        let live: Vec<(usize, usize)> = w.cache.iter().map(|seg| (seg.start, seg.end)).collect();
        for (slot, (start, end)) in seen.iter().zip(&live) {
            assert_eq!(
                slot.0,
                arena as usize + start,
                "the writer was handed a copy, not the arena range"
            );
            assert_eq!(slot.1, arena as usize + end, "the slice is not the range");
            assert!(
                slot.0 + slot.2 - DATA_HEADER >= arena as usize + start + DATA_HEADER,
                "the payload half must sit behind the header gap, inside the arena"
            );
        }
        // The gap is filled before the range goes out, or a zero-padded header would reach the wire at the arena's own address and pass a bytes test.
        assert_eq!(&w.arena[live[0].0..live[0].0 + 2], &[0x01, 0x02]);
        assert_eq!(w.cache.len(), 2);
    }

    #[test]
    fn release_empties_the_window_where_clear_at_the_wrap_would_not() {
        let mut w = SendingWindow::new();
        w.push(u32::MAX, b"last");
        w.push(0, b"first");
        w.clear(u32::MAX);
        assert_eq!(w.len(), 2);

        let mut w = SendingWindow::new();
        w.push(u32::MAX, b"last");
        w.push(0, b"first");
        w.release();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn removing_beyond_the_window_is_not_a_removal() {
        let mut w = SendingWindow::new();
        w.push(4, b"a");
        w.push(5, b"b");
        assert!(!w.remove(3));
        assert!(!w.remove(6));
        assert!(w.remove(5));
        assert!(!w.remove(5));
        assert!(w.remove(4));
        assert!(w.is_empty());
    }

    #[test]
    fn ack_list_clear_drops_the_acknowledged_prefix() {
        let mut l = AckList::new();
        l.add(5, 10);
        l.add(7, 20);
        l.clear(7);
        assert_eq!(
            l.entries.iter().map(|e| e.number).collect::<Vec<_>>(),
            vec![7]
        );
        assert_eq!(l.entries[0].timestamp, 20);
    }

    #[test]
    fn the_ack_list_reuses_its_scratch_across_flushes() {
        let mut l = AckList::new();
        l.add(1, 100);
        l.add(2, 110);
        l.flush(0, 100, 300, &mut |_: &mut AckSegment| {});
        for current in 1..50u32 {
            l.flush(current, 100, 300, &mut |_: &mut AckSegment| {});
            assert_eq!(l.candidates, vec![1, 2]);
        }
        l.flush(50, 100, 300, &mut |_: &mut AckSegment| {});
        let scratch = l.candidates.as_ptr();
        for current in 51..100u32 {
            l.flush(current, 100, 300, &mut |_: &mut AckSegment| {});
            assert_eq!(l.candidates, vec![1, 2]);
        }
        assert_eq!(l.candidates.as_ptr(), scratch);
        assert_eq!(l.entries.len(), 2);

        // The ack segment's own number list is reused too: once a flush has filled it past one segment, flushing again must not hand back a freshly allocated `Vec`. A byte test on the emitted ack cannot see this — the numbers are identical either way — so the witness is the allocation's identity: same base pointer, same capacity.
        let mut heavy = AckList::new();
        for n in 0..200u32 {
            heavy.add(n, n);
        }
        let mut emitted = 0usize;
        heavy.flush(0, 100, 128, &mut |a: &mut AckSegment| {
            assert!(!a.numbers.is_empty(), "a full ack carries numbers");
            emitted += 1;
        });
        assert!(emitted >= 2, "200 numbers over a limit of 128 is two acks");
        let numbers_ptr = heavy.scratch.numbers.as_ptr();
        let numbers_cap = heavy.scratch.numbers.capacity();
        assert!(!numbers_ptr.is_null(), "the scratch allocated its list");
        for current in 1..10u32 {
            heavy.flush(current, 100, 128, &mut |_: &mut AckSegment| {});
        }
        assert_eq!(
            heavy.scratch.numbers.as_ptr(),
            numbers_ptr,
            "a flush reallocated the ack segment's number list"
        );
        assert_eq!(heavy.scratch.numbers.capacity(), numbers_cap);
    }

    #[test]
    fn ack_list_flush_emits_every_known_number_on_the_first_round() {
        let mut l = AckList::new();
        l.add(1, 100);
        l.add(2, 110);
        let mut emitted = Vec::new();
        l.flush(0, 100, 300, &mut |seg: &mut AckSegment| {
            emitted.push(seg.clone());
        });
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].numbers, vec![1, 2]);
        assert_eq!(emitted[0].timestamp, 110);
    }
}
