//! The post-TLS TCP mask chain: what the pinned reference wraps around a stream *below* the TLS
//! layer (`transport/internet/finalmask`, `fragment/conn.go`), so the records a handshake emits
//! reach the wire as the pieces the config asked for.
//!
//! [`Fragment`] is the only TCP entry the chain carries here; `header-custom`, `sudoku` and `xmc`
//! are refused by name at config, never dialled unmasked. A fragment mask rewrites nothing: the
//! octets a session writes are the octets the peer reads, cut at different record ends. Splitting a
//! handshake record is legal TLS — a handshake message may span records — so the peer's own stack
//! reassembles it, which is what the pinned interop rows assert.
//!
//! Stages compose in config order on the write path: the first configured entry sees the session's
//! whole, and what it hands on is the next stage's whole, the last stage nearest the socket. That is
//! the reference's reverse-then-wrap order read from the other end.

use std::io::{self, Write};
use std::time::Duration;

/// The record type a handshake rides, and the width of a TLS record header.
const HANDSHAKE: u8 = 22;
const HEADER: usize = 5;

/// Draws served from one `getrandom` until the cache runs dry: a hello cut at random widths
/// needs a draw per bound, piece and delay, and a syscall each was the reference's, not a law.
/// A smaller draw could not feed the same modulo, so the draws are the same shape either way.
#[derive(Debug, Clone, Copy)]
struct Entropy {
    cache: [u64; 4],
    at: usize,
    #[cfg(test)]
    refills: usize,
}

impl Entropy {
    fn new() -> Self {
        Self {
            cache: [0; 4],
            at: 4,
            #[cfg(test)]
            refills: 0,
        }
    }

    /// The next draw, refilling the cache with one `getrandom` when dry.
    fn draw(&mut self) -> Option<u64> {
        if self.at == 4 {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).ok()?;
            let array = raw.as_chunks::<8>().0;
            self.cache = [
                u64::from_le_bytes(array[0]),
                u64::from_le_bytes(array[1]),
                u64::from_le_bytes(array[2]),
                u64::from_le_bytes(array[3]),
            ];
            self.at = 0;
            #[cfg(test)]
            {
                self.refills += 1;
            }
        }
        let draw = self.cache[self.at];
        self.at += 1;
        Some(draw)
    }
}

/// One `Int32Range` from the config, its ends already ordered by [`Range::ordered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub low: i64,
    pub high: i64,
}

impl Range {
    /// The reference's `ensureOrder`: a config may spell a range either way, and the reader puts it
    /// right before anything draws from it.
    pub fn ordered(low: i64, high: i64) -> Self {
        Self {
            low: low.min(high),
            high: low.max(high),
        }
    }

    /// The reference's `RandBetween`: a span of 0 or 1 always answers its low end, a wider span
    /// draws `min .. max` — the top of a range is never emitted, so `11-37` means thirty-six at
    /// most.
    pub fn pick(&self) -> Option<i64> {
        self.pick_from(&mut Entropy::new())
    }

    /// The same draw off a cached supply; the span test and the modulo are `pick`'s unchanged.
    fn pick_from(&self, ent: &mut Entropy) -> Option<i64> {
        let span = self.high - self.low;
        if span < 2 {
            return Some(self.low);
        }
        Some(self.low + i64::try_from(ent.draw()? % span as u64).ok()?)
    }
}

/// The `fragment` mask: `packets` picks which writes are cut, `lengths` the piece widths, `delays`
/// the waits between them, and `max_split` how many records one write may become.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub packets_from: u64,
    pub packets_to: u64,
    pub lengths: Vec<Range>,
    pub delays: Vec<Range>,
    pub max_split: Range,
    merged: Vec<u8>,
    ent: Entropy,
    count: u64,
}

impl Fragment {
    /// A mask the config can actually drive: an empty width or delay list cuts nothing, a negative
    /// width is a slice the reference cannot even form, and a last width entry of 0 is the one shape
    /// that never advances — every later segment clamps to it, so each piece would be empty forever.
    pub fn new(
        packets_from: u64,
        packets_to: u64,
        lengths: Vec<Range>,
        delays: Vec<Range>,
        max_split: Range,
    ) -> Option<Self> {
        if lengths.is_empty()
            || delays.is_empty()
            || lengths.iter().any(|width| width.low < 0)
            || lengths.last()?.low <= 0
        {
            return None;
        }
        Some(Self {
            packets_from,
            packets_to,
            lengths,
            delays,
            max_split,
            merged: Vec::new(),
            ent: Entropy::new(),
            count: 0,
        })
    }

    /// The write the chain hands this stage, answered with how much of it reached the wire.
    pub fn write<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        self.count += 1;
        if self.packets_from == 0 && self.packets_to == 1 {
            return self.write_hello(raw, p);
        }
        if self.packets_from != 0
            && (self.count < self.packets_from || self.count > self.packets_to)
        {
            return raw.write(p);
        }
        self.write_pieces(raw, p)
    }

    /// The segment's width, or the body's last octet once `max_split` has taken its bound: the run
    /// always ends on the whole, so a bounded hello is a short hello, never a lost one.
    fn cut(&mut self, segment: usize, from: usize, end: usize, bound: i64) -> Option<usize> {
        let width = self.lengths[segment.min(self.lengths.len() - 1)].pick_from(&mut self.ent)?;
        let last = bound > 0 && i64::try_from(segment).ok()? + 1 >= bound;
        let to = from.saturating_add(width as usize);
        Some(if last || to > end { end } else { to })
    }

    /// The reference parks between pieces when its delay range can answer above zero, and so does
    /// this: a mask that cut faster would look like a different schedule to anything watching the
    /// wire. One draw of the cached supply decides both the test and the duration.
    fn park(&mut self, delay: Range) {
        let Some(ms) = delay.pick_from(&mut self.ent).filter(|ms| *ms > 0) else {
            return;
        };
        std::thread::sleep(Duration::from_millis(ms as u64));
    }

    /// Why this write is not a hello the mask may cut: not the first write, too short for a header,
    /// not a handshake record, or a record whose body has not all arrived.
    fn hello_shape(&self, p: &[u8]) -> Option<usize> {
        if self.count != 1 || p.len() <= HEADER || p[0] != HANDSHAKE {
            return None;
        }
        let record_len = HEADER + usize::from(u16::from_be_bytes([p[3], p[4]]));
        (p.len() >= record_len).then_some(record_len)
    }

    /// The `tlshello` mode: the first write, when it holds a whole handshake record, becomes records
    /// of its own — the original type, version and this piece's width in the header. One draw of
    /// `max_split` bounds the run, and a single zero delay merges the records into one write, which
    /// is what makes the run a single burst on the socket.
    fn write_hello<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        let Some(record_len) = self.hello_shape(p) else {
            return raw.write(p);
        };
        let Some(bound) = self.max_split.pick_from(&mut self.ent) else {
            // No entropy for the bound: the hello goes out as the one record it was.
            return raw.write_all(p).map(|()| p.len());
        };
        let merged = self.delays.len() == 1 && self.delays[0].high == 0;
        self.merged.clear();
        if merged {
            // The bound is the only thing that can cut the run short, so the merge starts at its exact room.
            let extra = (bound.unsigned_abs().saturating_sub(1) as usize)
                .saturating_mul(HEADER)
                .min(p.len());
            self.merged.reserve(record_len + extra);
        }
        let mut from = HEADER;
        let mut segment = 0usize;
        while from < record_len {
            let Some(to) = self.cut(segment, from, record_len, bound) else {
                // No entropy for a width: the hello goes out as the one record it was.
                self.merged.clear();
                return raw.write_all(p).map(|()| p.len());
            };
            let head = [
                p[0],
                p[1],
                p[2],
                ((to - from) >> 8) as u8,
                (to - from) as u8,
            ];
            if merged {
                self.merged.extend_from_slice(&head);
                self.merged.extend_from_slice(&p[from..to]);
            } else {
                write_record(raw, &head, &p[from..to])?;
                let delay = self.delay_at(segment);
                self.park(delay);
            }
            from = to;
            segment += 1;
        }
        if merged && !self.merged.is_empty() {
            raw.write_all(&self.merged)?;
            self.merged.clear();
        }
        if p.len() == record_len {
            return Ok(p.len());
        }
        // A record that rode in behind the hello keeps its own write, whole or partial.
        Ok(record_len + raw.write(&p[record_len..])?)
    }

    fn delay_at(&self, segment: usize) -> Range {
        self.delays[segment.min(self.delays.len() - 1)]
    }

    /// The `packets` modes that are not `tlshello`: the whole goes out as pieces of the drawn
    /// widths, each advance measured by what the socket actually took.
    fn write_pieces<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        let Some(bound) = self.max_split.pick_from(&mut self.ent) else {
            return write_progress(raw, p);
        };
        let mut from = 0usize;
        let mut segment = 0usize;
        loop {
            let Some(to) = self.cut(segment, from, p.len(), bound) else {
                return write_progress(raw, &p[from..]).map(|written| from + written);
            };
            let written = match raw.write(&p[from..to]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => written,
                Err(error)
                    if from > 0
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                {
                    return Ok(from);
                }
                Err(error) => return Err(error),
            };
            from += written;
            let delay = self.delay_at(segment);
            self.park(delay);
            segment += 1;
            if from >= p.len() {
                return Ok(from);
            }
        }
    }
}

/// Write as much of `p` as a nonblocking sink will take in one call, answering the progress made
/// before it blocked so the caller drains exactly those octets rather than sending them twice.
fn write_progress<W: Write>(raw: &mut W, mut p: &[u8]) -> io::Result<usize> {
    let mut written = 0usize;
    while !p.is_empty() {
        match raw.write(p) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(taken) => {
                written += taken;
                p = &p[taken..];
            }
            Err(error)
                if written > 0
                    && matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                return Ok(written);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(written)
}

/// A record's header and its body go out as one gathered write, so the body never lands in a buffer
/// of its own the way the reference's scratch does. The list is rebuilt from what still has to go,
/// which is how a partial completion resumes without a copy.
fn write_record<W: Write>(raw: &mut W, head: &[u8], body: &[u8]) -> io::Result<()> {
    let mut parts = [head, body];
    let mut at = 0usize;
    while at < parts.len() {
        let iovecs = [io::IoSlice::new(parts[0]), io::IoSlice::new(parts[1])];
        let taken = raw.write_vectored(&iovecs[at..])?;
        if taken == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        let mut left = taken;
        while left > 0 && at < parts.len() {
            let run = left.min(parts[at].len());
            parts[at] = &parts[at][run..];
            left -= run;
            if !parts[at].is_empty() {
                break;
            }
            at += 1;
        }
    }
    Ok(())
}

/// The chain one TCP stream carries: the stages in config order, the first of which sees the
/// session's whole and the last of which is nearest the socket.
#[derive(Debug, Default, Clone)]
pub struct Chain {
    stages: Vec<Fragment>,
}

impl Chain {
    /// One more stage, appended in config order.
    pub fn push(&mut self, stage: Fragment) {
        self.stages.push(stage);
    }

    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// The write the stream was asked to make, answered with how much of it reached the wire.
    pub fn write<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        drive(&mut self.stages, raw, p)
    }
}

// The first stage sees the whole and hands its pieces to the next; the depth is the config's stage count.
fn drive<W: Write>(stages: &mut [Fragment], raw: &mut W, p: &[u8]) -> io::Result<usize> {
    let Some((first, rest)) = stages.split_first_mut() else {
        return raw.write(p);
    };
    if rest.is_empty() {
        return first.write(raw, p);
    }
    let mut pipe = Pipe { stages: rest, raw };
    first.write(&mut pipe, p)
}

struct Pipe<'a, W> {
    stages: &'a mut [Fragment],
    raw: &'a mut W,
}

impl<W: Write> Write for Pipe<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        drive(self.stages, &mut *self.raw, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.raw.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(min: i64, max: i64) -> Range {
        Range::ordered(min, max)
    }

    /// A handshake record of `body` octets, every one of them distinct.
    fn hello(body: usize) -> Vec<u8> {
        let mut p = vec![HANDSHAKE, 3, 1];
        p.extend_from_slice(&(body as u16).to_be_bytes());
        p.extend((0..body).map(|i| (i % 251) as u8));
        p
    }

    /// The wire as a peer sees it: every write call, the runs it was made of, and the octets.
    #[derive(Default)]
    struct Wire {
        calls: usize,
        widths: Vec<usize>,
        segments: Vec<(usize, usize)>,
        bytes: Vec<u8>,
        /// When set, each call takes at most this many octets, like a socket under buffer pressure.
        takes: usize,
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            let take = if self.takes == 0 {
                buf.len()
            } else {
                buf.len().min(self.takes)
            };
            self.widths.push(take);
            self.segments.push((buf.as_ptr() as usize, take));
            self.bytes.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
            self.calls += 1;
            let live: Vec<&[u8]> = bufs.iter().map(|part| &part[..]).collect();
            let whole: usize = live.iter().map(|part| part.len()).sum();
            let take = if self.takes == 0 {
                whole
            } else {
                whole.min(self.takes)
            };
            self.widths.push(take);
            let mut left = take;
            for part in live {
                let run = part.len().min(left);
                self.segments.push((part.as_ptr() as usize, run));
                self.bytes.extend_from_slice(&part[..run]);
                left -= run;
            }
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// What a peer's record walk finds: the widths of the records emitted, and the message between
    /// them. This is the loop the pinned interop observer runs.
    fn records(wire: &[u8]) -> (Vec<usize>, Vec<u8>) {
        let mut widths = Vec::new();
        let mut message = Vec::new();
        let mut at = 0;
        while at < wire.len() {
            assert_eq!(wire[at], HANDSHAKE, "every piece is a handshake record");
            let len = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
            widths.push(len);
            message.extend_from_slice(&wire[at + HEADER..at + HEADER + len]);
            at += HEADER + len;
        }
        (widths, message)
    }

    struct Stalling {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for Stalling {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.bytes.len() >= self.limit {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let take = buf.len().min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_blocked_piece_returns_the_octets_it_already_wrote() {
        let mut mask = Fragment::new(0, 0, vec![range(4, 4)], vec![range(0, 0)], range(24, 24))
            .expect("valid");
        let whole: Vec<u8> = (0..20).collect();
        let mut sink = Stalling {
            bytes: Vec::new(),
            limit: 6,
        };
        let written = mask.write(&mut sink, &whole).expect("progress");
        assert_eq!(
            written, 6,
            "the caller learns exactly what reached the sink"
        );
        assert_eq!(sink.bytes, whole[..6], "and only those octets were sent");
    }

    #[test]
    fn a_hello_record_is_cut_into_records_of_the_configured_widths() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37), range(40, 40)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(300);
        let mut wire = Wire::default();
        assert_eq!(
            mask.write(&mut wire, &whole).expect("writes"),
            whole.len(),
            "the mask answers the whole it was handed"
        );
        assert_eq!(
            wire.calls, 1,
            "one zero delay merges the run into a single write"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(
            widths,
            vec![11, 37, 40, 40, 40, 40, 40, 40, 12],
            "the drawn widths, the last clamped to the body's end"
        );
        assert_eq!(message, whole[HEADER..], "and the hello arrives whole");
        assert_eq!(
            wire.bytes.len(),
            whole.len() + (widths.len() - 1) * HEADER,
            "the hello's own header is reused, and only one is added per extra record"
        );
    }

    #[test]
    fn a_delayed_piece_hands_the_body_over_where_it_lies() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 1)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(48);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(
            wire.calls, 2,
            "a delay past zero emits each record on its own"
        );
        assert_eq!(
            wire.segments[1],
            (whole[HEADER..HEADER + 11].as_ptr() as usize, 11),
            "the first piece is the hello's own octets, not a copy of them"
        );
        assert_eq!(
            wire.segments[3],
            (whole[HEADER + 11..].as_ptr() as usize, 37),
            "and the second's"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(widths, vec![11, 37]);
        assert_eq!(message, whole[HEADER..]);
        assert_eq!(
            mask.ent.refills, 0,
            "a fixed config answers its low ends and never reaches the supply at all"
        );
    }

    #[test]
    fn a_random_piece_draws_once_from_the_cached_supply() {
        // The one random draw here is the first width, 11..20; the bound, second width and delay all answer their fixed low ends.
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 20), range(37, 37)],
            vec![range(0, 1)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(48);
        let mut wire = Wire::default();
        mask.write(&mut wire, &whole).expect("writes");
        assert_eq!(
            mask.ent.refills, 1,
            "the draw came from the supply, refilled once and never again"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(widths.len(), 2, "a cut and the clamped rest");
        assert!((11..20).contains(&widths[0]), "the drawn width");
        assert_eq!(message, whole[HEADER..]);
    }

    #[test]
    fn a_merged_first_hello_lands_in_room_it_drew_ahead_of() {
        let mut mask = Fragment::new(0, 1, vec![range(100, 100)], vec![range(0, 0)], range(5, 5))
            .expect("valid");
        let whole = hello(400);
        let mut wire = Wire::default();
        mask.write(&mut wire, &whole).expect("first");
        assert_eq!(
            mask.merged.capacity(),
            whole.len() + 4 * HEADER,
            "the reserve covered the run the bound allows in full, so nothing regrew mid-hello"
        );
        assert_eq!(
            mask.ent.refills, 0,
            "a fixed config answers its low ends and never draws at all"
        );
        wire.bytes.clear();
        mask.count = 0;
        mask.write(&mut wire, &whole).expect("second");
        assert_eq!(
            mask.merged.capacity(),
            whole.len() + 4 * HEADER,
            "and the second hello neither grew nor shrank it"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(widths, vec![100, 100, 100, 100]);
        assert_eq!(message, whole[HEADER..], "the run is the mask's own bytes");
    }

    #[test]
    fn a_random_merged_hello_draws_only_the_random_widths_from_the_supply() {
        // Two random widths, then a fixed 100 governs every later segment and the bound closes the run at ten records: only the two random segments reach the supply, and one getrandom feeds both.
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(50, 150), range(50, 150), range(100, 100)],
            vec![range(0, 0)],
            range(10, 10),
        )
        .expect("valid");
        let whole = hello(1000);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        let (widths, message) = records(&wire.bytes);
        assert_eq!(
            widths.len(),
            10,
            "the bound closed the run on exactly ten records"
        );
        assert!(
            (50..150).contains(&widths[0]) && (50..150).contains(&widths[1]),
            "the two random segments drew their width"
        );
        assert_eq!(
            &widths[2..9],
            &[100; 7],
            "the fixed width governs every later segment and never draws"
        );
        assert!(widths[9] > 0, "the last record carries the clamped rest");
        assert_eq!(message, whole[HEADER..], "and the hello arrives whole");
        assert_eq!(mask.ent.refills, 1, "two draws ride one getrandom, not two");
    }

    #[test]
    fn a_max_split_ends_the_run_on_the_whole_hello() {
        for bound in [1i64, 2, 5] {
            let mut mask = Fragment::new(
                0,
                1,
                vec![range(11, 11)],
                vec![range(0, 0)],
                range(bound, bound),
            )
            .expect("valid");
            let whole = hello(300);
            let mut wire = Wire::default();
            mask.write(&mut wire, &whole).expect("writes");
            let (widths, message) = records(&wire.bytes);
            assert_eq!(
                widths.len(),
                bound as usize,
                "a bound of {bound} emits exactly that many records"
            );
            assert_eq!(message, whole[HEADER..], "the last record carries the rest");
        }
    }

    #[test]
    fn the_last_configured_width_governs_every_later_segment() {
        let mut mask = Fragment::new(
            1,
            4,
            vec![range(3, 3), range(9, 9)],
            vec![range(0, 0)],
            range(0, 0),
        )
        .expect("valid");
        let mut wire = Wire {
            takes: 0,
            ..Wire::default()
        };
        let body = vec![1u8; 40];
        assert_eq!(mask.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(
            wire.widths,
            vec![3, 9, 9, 9, 9, 1],
            "the first segment is 3, then the last entry governs"
        );
        assert_eq!(wire.bytes, body);
    }

    #[test]
    fn a_timed_split_advances_only_by_what_the_socket_took() {
        let mut mask = Fragment::new(1, 1, vec![range(20, 20)], vec![range(0, 0)], range(0, 0))
            .expect("valid");
        let mut wire = Wire {
            takes: 7,
            ..Wire::default()
        };
        let body = vec![7u8; 50];
        assert_eq!(mask.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(wire.bytes, body, "the whole arrives, cut and refilled");
        assert_eq!(
            wire.calls, 8,
            "a 20-octet piece across a socket that takes seven at a time"
        );
    }

    #[test]
    fn a_write_the_mask_does_not_own_goes_out_as_it_came() {
        let mut mask = Fragment::new(0, 1, vec![range(11, 11)], vec![range(0, 0)], range(24, 24))
            .expect("valid");
        let mut wire = Wire::default();
        // Not a handshake record.
        let alert = vec![23u8, 3, 1, 0, 2, 1, 0];
        assert_eq!(mask.write(&mut wire, &alert).expect("writes"), alert.len());
        assert_eq!(wire.bytes, alert);
        wire.bytes.clear();
        // Too short to hold a header.
        let short = vec![HANDSHAKE, 3, 1];
        assert_eq!(mask.write(&mut wire, &short).expect("writes"), short.len());
        assert_eq!(wire.bytes, short);
        wire.bytes.clear();
        // A record whose body has not all arrived yet.
        let partial = hello(60)[..HEADER + 20].to_vec();
        assert_eq!(
            mask.write(&mut wire, &partial).expect("writes"),
            partial.len()
        );
        assert_eq!(wire.bytes, partial);
        wire.bytes.clear();
        // A later write is not the hello, whatever it holds.
        let again = hello(60);
        assert_eq!(mask.write(&mut wire, &again).expect("writes"), again.len());
        assert_eq!(wire.bytes, again, "only the first write is cut");
    }

    #[test]
    fn a_record_behind_the_hello_keeps_its_own_write_and_its_own_bytes() {
        let mut mask = Fragment::new(0, 1, vec![range(11, 11)], vec![range(0, 0)], range(24, 24))
            .expect("valid");
        let mut whole = hello(40);
        let next = vec![23u8, 3, 3, 0, 4, 1, 2, 3, 4];
        whole.extend_from_slice(&next);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        let hello_len = wire.bytes.len() - next.len();
        let (widths, message) = records(&wire.bytes[..hello_len]);
        assert_eq!(widths, vec![11, 11, 11, 7], "the hello's records");
        assert_eq!(message, whole[HEADER..HEADER + 40]);
        assert_eq!(
            &wire.bytes[hello_len..],
            next.as_slice(),
            "and the record behind it"
        );
    }

    #[test]
    fn writes_outside_the_packet_window_pass_through() {
        let mut mask =
            Fragment::new(2, 3, vec![range(4, 4)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut wire = Wire::default();
        let body = vec![9u8; 9];
        assert_eq!(mask.write(&mut wire, &body).expect("first"), body.len());
        assert_eq!(wire.widths, vec![9], "the first write is outside 2..3");
        wire.widths.clear();
        assert_eq!(
            mask.write(&mut wire, &[8u8; 9]).expect("second"),
            9,
            "inside the window"
        );
        assert_eq!(
            wire.widths,
            vec![4, 4, 1],
            "and cut at the configured width"
        );
        wire.widths.clear();
        assert_eq!(
            mask.write(&mut wire, &[7u8; 9]).expect("third"),
            9,
            "still inside"
        );
        assert_eq!(wire.widths, vec![4, 4, 1]);
        wire.widths.clear();
        assert_eq!(
            mask.write(&mut wire, &[6u8; 9]).expect("fourth"),
            9,
            "past the window again"
        );
        assert_eq!(wire.widths, vec![9]);
    }

    #[test]
    fn a_pick_never_answers_the_top_of_a_range() {
        for _ in 0..256 {
            let drawn = range(11, 37).pick().expect("entropy");
            assert!(
                (11..37).contains(&drawn),
                "the top of a half-open range is never drawn: {drawn}"
            );
        }
        assert_eq!(
            range(11, 12).pick(),
            Some(11),
            "a span of one is its low end"
        );
        assert_eq!(range(5, 5).pick(), Some(5));
        assert_eq!(
            Range::ordered(37, 11),
            range(11, 37),
            "a swapped pair is ordered"
        );
    }

    #[test]
    fn a_config_that_could_spin_is_refused() {
        assert!(Fragment::new(0, 1, vec![range(11, 11)], vec![range(0, 0)], range(1, 1)).is_some());
        assert!(
            Fragment::new(
                0,
                1,
                vec![range(11, 11), range(0, 9)],
                vec![range(0, 0)],
                range(0, 0)
            )
            .is_none(),
            "a last width entry of 0 never advances"
        );
        assert!(Fragment::new(0, 1, Vec::new(), vec![range(0, 0)], range(0, 0)).is_none());
        assert!(Fragment::new(0, 1, vec![range(11, 11)], Vec::new(), range(0, 0)).is_none());
        assert!(
            Fragment::new(
                0,
                1,
                vec![range(11, 11), range(-4, 4)],
                vec![range(0, 0)],
                range(0, 0)
            )
            .is_none(),
            "a width that can answer negative is a slice the reference cannot even form"
        );
    }

    #[test]
    fn a_chain_applies_its_stages_in_config_order() {
        let outer =
            Fragment::new(1, 2, vec![range(8, 8)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let inner =
            Fragment::new(1, 2, vec![range(3, 3)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut chain = Chain::default();
        chain.push(outer);
        chain.push(inner);
        let mut wire = Wire::default();
        let body = vec![5u8; 10];
        assert_eq!(chain.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(wire.bytes, body, "a chain adds nothing and loses nothing");
        assert_eq!(
            wire.widths,
            vec![3, 3, 2, 2],
            "the first stage cut the whole at 8, the last cut each of its pieces at 3"
        );
        assert_eq!(chain.stages[0].count, 1, "each stage counts its own writes");
        assert_eq!(chain.stages[1].count, 2);
    }

    #[test]
    fn an_empty_chain_writes_through() {
        let mut chain = Chain::default();
        assert!(chain.is_empty());
        let mut wire = Wire::default();
        let body = vec![3u8; 12];
        assert_eq!(chain.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(wire.widths, vec![12]);
    }

    #[test]
    fn the_merged_run_is_the_only_buffer_the_mask_owns() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let mut wire = Wire::default();
        mask.write(&mut wire, &hello(400)).expect("first");
        let capacity = mask.merged.capacity();
        let pointer = mask.merged.as_ptr() as usize;
        assert!(capacity >= 400, "the run grew to what one hello needs");
        wire.bytes.clear();
        mask.count = 0;
        mask.write(&mut wire, &hello(400)).expect("second");
        assert_eq!(mask.merged.capacity(), capacity, "a second hello reuses it");
        assert_eq!(
            mask.merged.as_ptr() as usize,
            pointer,
            "and never changes owner"
        );
        wire.bytes.clear();
        mask.count = 0;
        mask.write(&mut wire, &hello(120)).expect("smaller");
        assert_eq!(
            mask.merged.capacity(),
            capacity,
            "a smaller hello never shrinks it"
        );
    }

    #[test]
    fn a_delay_range_whose_top_is_zero_draws_zero() {
        let mut mask =
            Fragment::new(1, 2, vec![range(4, 4)], vec![range(0, 1)], range(0, 0)).expect("valid");
        let mut wire = Wire::default();
        mask.write(&mut wire, &[1u8; 40]).expect("writes");
        assert_eq!(wire.widths.len(), 10, "and the run really was cut");
        assert_eq!(
            range(0, 1).pick(),
            Some(0),
            "so every park draws zero, which is the span a stall detector would catch"
        );
    }
}
