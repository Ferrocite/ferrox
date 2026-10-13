pub const DATA_SEGMENT_OVERHEAD: u32 = 18;

pub const ACK_NUMBER_LIMIT: usize = 128;

const ACK_HEADER: usize = 17;
const CMD_HEADER: usize = 16;

fn be16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn be32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Ack,
    Data,
    Terminate,
    Ping,
}

impl Command {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            Self::Ack => 0,
            Self::Data => 1,
            Self::Terminate => 2,
            Self::Ping => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentOption(pub u8);

/// Hands out the buffer for the next inbound data-segment payload. The
/// socket thread supplies one; `ReceivingWorker::read` returns spent buffers to
/// the same place. A datagram's payloads then cost no allocation once the
/// window has been full once, which at the default 1 332-byte MSS is about
/// 9 400 malloc/free pairs a second per direction at 100 Mbps.
pub type TakePayload<'a> = dyn Fn() -> Vec<u8> + 'a;

impl SegmentOption {
    pub const NONE: Self = Self(0);
    pub const CLOSE: Self = Self(1);

    pub(crate) fn to_byte(self) -> u8 {
        self.0
    }

    #[must_use]
    pub fn is_close(self) -> bool {
        self.0 & 1 == 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataSegment {
    pub conv: u16,
    pub option: SegmentOption,
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
    pub payload: Vec<u8>,
    pub(crate) timeout: u32,
    pub(crate) transmit: u32,
}

impl DataSegment {
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.payload
    }

    fn parse<'a>(
        conv: u16,
        option: SegmentOption,
        buf: &'a [u8],
        take: &TakePayload<'_>,
    ) -> Option<(Self, &'a [u8])> {
        if buf.len() < 15 {
            return None;
        }
        let data_len = usize::from(be16(buf, 12));
        let body = buf.get(14..14 + data_len)?;
        let mut payload = take();
        payload.clear();
        payload.extend_from_slice(body);
        Some((
            Self {
                conv,
                option,
                timestamp: be32(buf, 0),
                number: be32(buf, 4),
                sending_next: be32(buf, 8),
                payload,
                timeout: 0,
                transmit: 0,
            },
            &buf[14 + data_len..],
        ))
    }

    pub(crate) fn byte_size(&self) -> usize {
        DATA_SEGMENT_OVERHEAD as usize + self.payload.len()
    }

    pub(crate) fn serialize(&self, out: &mut Vec<u8>) {
        serialize_data(
            OutgoingHeader {
                conv: self.conv,
                option: self.option,
                timestamp: self.timestamp,
                number: self.number,
                sending_next: self.sending_next,
            },
            &self.payload,
            out,
        );
    }
}

/// The five fields a data segment's wire header carries. Split out so the
/// sender can hand the header over by value while the payload stays a borrowed
/// slice of whatever buffer holds it — the sender's payload is a range into an
/// arena, not an owned `Vec` per segment.
#[derive(Debug, Clone, Copy)]
pub struct OutgoingHeader {
    pub conv: u16,
    pub option: SegmentOption,
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
}

/// Writes the 18 header bytes and then the payload, straight into `out`. The
/// header used to be staged in a stack array and copied; at 18 bytes per 1 332
/// that is one memcpy per segment the arena made unnecessary.
pub(crate) fn serialize_data(header: OutgoingHeader, payload: &[u8], out: &mut Vec<u8>) {
    out.reserve(DATA_SEGMENT_OVERHEAD as usize + payload.len());
    out.extend_from_slice(&header.conv.to_be_bytes());
    out.push(Command::Data.to_byte());
    out.push(header.option.to_byte());
    out.extend_from_slice(&header.timestamp.to_be_bytes());
    out.extend_from_slice(&header.number.to_be_bytes());
    out.extend_from_slice(&header.sending_next.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Writes the 18-byte data header into the front of `dst`, in the same order
/// and with the same bytes as `serialize_data`. The sender keeps an 18-byte
/// gap before each payload in the arena, drops the fresh header into that gap,
/// and sends the whole range as one datagram — so the payload is never copied
/// out of the arena on its way to the socket.
pub(crate) fn write_data_header(header: OutgoingHeader, payload_len: u16, dst: &mut [u8]) {
    dst[0..2].copy_from_slice(&header.conv.to_be_bytes());
    dst[2] = Command::Data.to_byte();
    dst[3] = header.option.to_byte();
    dst[4..8].copy_from_slice(&header.timestamp.to_be_bytes());
    dst[8..12].copy_from_slice(&header.number.to_be_bytes());
    dst[12..16].copy_from_slice(&header.sending_next.to_be_bytes());
    dst[16..18].copy_from_slice(&payload_len.to_be_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AckSegment {
    pub conv: u16,
    pub option: SegmentOption,
    pub receiving_window: u32,
    pub receiving_next: u32,
    pub timestamp: u32,
    pub numbers: Vec<u32>,
    limit: usize,
}

impl AckSegment {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            conv: 0,
            option: SegmentOption::NONE,
            receiving_window: 0,
            receiving_next: 0,
            timestamp: 0,
            numbers: Vec::new(),
            limit: limit.clamp(1, ACK_NUMBER_LIMIT),
        }
    }

    /// Reset for reuse as the next ack in a run, restoring every field a fresh
    /// `new` starts with and keeping the `numbers` allocation. Nothing on the
    /// wire reads a `Vec`'s capacity, so a reused list is bit-identical to a
    /// rebuilt one while skipping the malloc and the growth reallocs.
    pub(crate) fn restart(&mut self) {
        self.conv = 0;
        self.option = SegmentOption::NONE;
        self.receiving_window = 0;
        self.receiving_next = 0;
        self.timestamp = 0;
        self.numbers.clear();
    }

    /// `restart` plus the per-flush `limit`, so a scratch segment can serve a
    /// whole run of flushes without a fresh `AckSegment` per emitted ack.
    pub(crate) fn begin(&mut self, limit: usize) {
        self.restart();
        self.limit = limit.clamp(1, ACK_NUMBER_LIMIT);
    }

    pub fn put_number(&mut self, number: u32) {
        self.numbers.push(number);
    }

    pub fn put_timestamp(&mut self, timestamp: u32) {
        if timestamp.wrapping_sub(self.timestamp) < 0x7FFF_FFFF {
            self.timestamp = timestamp;
        }
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.numbers.len() == self.limit
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.numbers.is_empty()
    }

    pub(crate) fn byte_size(&self) -> usize {
        ACK_HEADER + self.numbers.len() * 4
    }

    fn parse(conv: u16, option: SegmentOption, buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 13 {
            return None;
        }
        let receiving_window = be32(buf, 0);
        let receiving_next = be32(buf, 4);
        let timestamp = be32(buf, 8);
        let count = usize::from(buf[12]);
        let tail = buf.get(13..13 + count.checked_mul(4)?)?;
        let (chunks, _) = tail.as_chunks::<4>();
        let numbers: Vec<u32> = chunks
            .iter()
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Some((
            Self {
                conv,
                option,
                receiving_window,
                receiving_next,
                timestamp,
                numbers,
                limit: ACK_NUMBER_LIMIT,
            },
            &buf[13 + count * 4..],
        ))
    }

    pub(crate) fn serialize(&self, out: &mut Vec<u8>) {
        // Written straight into `out`, the way `serialize_data` does it: the header bytes land where they go on the wire, not in a stack array that is then copied across.
        out.reserve(ACK_HEADER + self.numbers.len() * 4);
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(Command::Ack.to_byte());
        out.push(self.option.to_byte());
        out.extend_from_slice(&self.receiving_window.to_be_bytes());
        out.extend_from_slice(&self.receiving_next.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(self.numbers.len() as u8);
        for number in &self.numbers {
            out.extend_from_slice(&number.to_be_bytes());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmdOnlySegment {
    pub conv: u16,
    pub cmd: u8,
    pub option: SegmentOption,
    pub sending_next: u32,
    pub receiving_next: u32,
    pub peer_rto: u32,
}

impl CmdOnlySegment {
    #[must_use]
    pub fn new() -> Self {
        Self {
            conv: 0,
            cmd: Command::Ping.to_byte(),
            option: SegmentOption::NONE,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        }
    }

    #[must_use]
    pub fn kind(&self) -> Option<Command> {
        match self.cmd {
            0 => Some(Command::Ack),
            1 => Some(Command::Data),
            2 => Some(Command::Terminate),
            3 => Some(Command::Ping),
            _ => None,
        }
    }

    pub(crate) fn byte_size() -> usize {
        CMD_HEADER
    }

    fn parse(conv: u16, cmd: u8, option: SegmentOption, buf: &[u8]) -> Option<(Self, &[u8])> {
        let body = buf.get(..12)?;
        Some((
            Self {
                conv,
                cmd,
                option,
                sending_next: be32(body, 0),
                receiving_next: be32(body, 4),
                peer_rto: be32(body, 8),
            },
            &body[12..],
        ))
    }

    pub(crate) fn serialize(&self, out: &mut Vec<u8>) {
        out.reserve(CMD_HEADER);
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(self.cmd);
        out.push(self.option.to_byte());
        out.extend_from_slice(&self.sending_next.to_be_bytes());
        out.extend_from_slice(&self.receiving_next.to_be_bytes());
        out.extend_from_slice(&self.peer_rto.to_be_bytes());
    }
}

impl Default for CmdOnlySegment {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    CmdOnly(CmdOnlySegment),
}

impl Segment {
    #[must_use]
    pub fn conversation(&self) -> u16 {
        match self {
            Self::Data(s) => s.conv,
            Self::Ack(s) => s.conv,
            Self::CmdOnly(s) => s.conv,
        }
    }

    #[must_use]
    pub fn command(&self) -> Option<Command> {
        match self {
            Self::Data(_) => Some(Command::Data),
            Self::Ack(_) => Some(Command::Ack),
            Self::CmdOnly(s) => s.kind(),
        }
    }

    #[must_use]
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Data(s) => s.byte_size(),
            Self::Ack(s) => s.byte_size(),
            Self::CmdOnly(_) => CmdOnlySegment::byte_size(),
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            Self::Data(s) => s.serialize(out),
            Self::Ack(s) => s.serialize(out),
            Self::CmdOnly(s) => s.serialize(out),
        }
    }

    #[must_use]
    pub fn option(&self) -> SegmentOption {
        match self {
            Self::Data(s) => s.option,
            Self::Ack(s) => s.option,
            Self::CmdOnly(s) => s.option,
        }
    }
}

#[must_use]
pub fn read_segment<'a>(buf: &'a [u8], take: &TakePayload<'_>) -> Option<(Segment, &'a [u8])> {
    if buf.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes(buf[0..2].try_into().ok()?);
    let cmd_byte = buf[2];
    let opt = SegmentOption(buf[3]);
    let rest = &buf[4..];
    match cmd_byte {
        0 => {
            let (seg, tail) = AckSegment::parse(conv, opt, rest)?;
            Some((Segment::Ack(seg), tail))
        }
        1 => {
            let (seg, tail) = DataSegment::parse(conv, opt, rest, take)?;
            Some((Segment::Data(seg), tail))
        }
        _ => {
            let (seg, tail) = CmdOnlySegment::parse(conv, cmd_byte, opt, rest)?;
            Some((Segment::CmdOnly(seg), tail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse` fills the buffer it is lent instead of allocating: the payload's
    /// pointer is the lent buffer's and its capacity survives the fill, so a
    /// byte-level test passing either way cannot stand in for this one.
    #[test]
    fn a_data_segment_is_parsed_into_the_lent_buffer() {
        for len in [1usize, 100, 1332, 1400, 2048] {
            let seg = DataSegment {
                conv: 1,
                option: SegmentOption::NONE,
                timestamp: 3,
                number: 4,
                sending_next: 5,
                payload: vec![0x5Au8; len],
                timeout: 0,
                transmit: 0,
            };
            let mut buf = Vec::new();
            Segment::Data(seg).serialize(&mut buf);
            let slot = std::cell::RefCell::new(Some(Vec::with_capacity(2048)));
            let lent = slot.borrow().as_ref().expect("a lent buffer").as_ptr();
            let (got, rest) = read_segment(&buf, &|| {
                slot.borrow_mut().take().expect("one data segment")
            })
            .unwrap();
            assert_eq!(rest.len(), 0, "len {len}");
            let Segment::Data(got) = got else {
                panic!("len {len}: a data segment parses as data");
            };
            assert_eq!(
                got.payload.as_ptr(),
                lent,
                "len {len}: parse allocated instead of filling"
            );
            assert_eq!(
                got.payload.capacity(),
                2048,
                "len {len}: the fill grew the lent buffer"
            );
            assert_eq!(got.payload.len(), len, "len {len}");
            assert!(got.payload.iter().all(|&b| b == 0x5A), "len {len}");
        }
    }

    #[test]
    fn a_data_segment_round_trips() {
        let seg = DataSegment {
            conv: 1,
            option: SegmentOption::NONE,
            timestamp: 3,
            number: 4,
            sending_next: 5,
            payload: b"abcd".to_vec(),
            timeout: 0,
            transmit: 0,
        };
        let mut buf = Vec::new();
        Segment::Data(seg.clone()).serialize(&mut buf);
        assert_eq!(buf.len(), DATA_SEGMENT_OVERHEAD as usize + 4);
        let (got, rest) = read_segment(&buf, &|| Vec::new()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(got, Segment::Data(seg));
    }

    #[test]
    fn an_ack_segment_round_trips() {
        let mut seg = AckSegment::new(128);
        seg.conv = 7;
        seg.receiving_window = 100;
        seg.receiving_next = 42;
        seg.put_timestamp(999);
        seg.put_number(1);
        seg.put_number(2);
        let mut buf = Vec::new();
        Segment::Ack(seg.clone()).serialize(&mut buf);
        let (got, _) = read_segment(&buf, &|| Vec::new()).unwrap();
        match got {
            Segment::Ack(a) => {
                assert_eq!(a.numbers, vec![1, 2]);
                assert_eq!(a.receiving_window, 100);
                assert_eq!(a.receiving_next, 42);
                assert_eq!(a.timestamp, 999);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// The sender writes a data segment from a borrowed payload slice while the
    /// oracle and every segment test write it from an owned one. Both must put
    /// the same bytes on the wire at every length and offset, so the refactor
    /// that removed the per-segment allocation cannot have changed the framing.
    #[test]
    fn a_borrowed_payload_serialises_identically_to_an_owned_one() {
        let mut checked = 0usize;
        for len in [
            0usize, 1, 2, 15, 16, 17, 63, 64, 65, 127, 128, 1400, 8171, 8192,
        ] {
            for option in [SegmentOption::NONE, SegmentOption::CLOSE] {
                for (number, timestamp, sending_next) in
                    [(0u32, 0u32, 0u32), (1, 2, 3), (u32::MAX, 7, 11)]
                {
                    let payload: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x5A).collect();
                    let owned = DataSegment {
                        conv: 0xbeef,
                        option,
                        timestamp,
                        number,
                        sending_next,
                        payload: payload.clone(),
                        ..Default::default()
                    };
                    let mut from_owned = Vec::new();
                    Segment::Data(owned.clone()).serialize(&mut from_owned);
                    let mut from_slice = Vec::new();
                    serialize_data(
                        OutgoingHeader {
                            conv: owned.conv,
                            option: owned.option,
                            timestamp: owned.timestamp,
                            number: owned.number,
                            sending_next: owned.sending_next,
                        },
                        &owned.payload,
                        &mut from_slice,
                    );
                    assert_eq!(from_owned, from_slice, "len {len} {option:?}");
                    assert_eq!(
                        from_owned.len(),
                        DATA_SEGMENT_OVERHEAD as usize + len,
                        "len {len}: the header is still {DATA_SEGMENT_OVERHEAD} bytes"
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked >= 84,
            "the sweep should be dense, not a sample: {checked}"
        );
    }

    #[test]
    fn the_command_only_layout_is_sixteen_bytes() {
        let mut seg = CmdOnlySegment::new();
        seg.conv = 9;
        seg.cmd = Command::Terminate.to_byte();
        seg.sending_next = 1;
        seg.receiving_next = 2;
        seg.peer_rto = 3;
        let mut buf = Vec::new();
        Segment::CmdOnly(seg).serialize(&mut buf);
        assert_eq!(buf, [0, 9, 2, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    }

    #[test]
    fn unknown_command_bytes_round_trip_verbatim() {
        let mut raw = vec![0, 3, 250, 0];
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.extend_from_slice(&2u32.to_be_bytes());
        raw.extend_from_slice(&3u32.to_be_bytes());
        let (seg, _) = read_segment(&raw, &|| Vec::new()).unwrap();
        match seg {
            Segment::CmdOnly(c) => assert_eq!(c.cmd, 250),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn an_ack_segment_holds_no_more_than_the_limit_the_reference_allows() {
        let mut seg = AckSegment::new(0);
        seg.put_number(1);
        assert!(seg.is_full());
        let mut seg = AckSegment::new(1 << 20);
        for n in 0..ACK_NUMBER_LIMIT as u32 {
            seg.put_number(n);
        }
        assert!(seg.is_full());
        seg.put_number(999);
        assert_eq!(seg.numbers.len(), ACK_NUMBER_LIMIT + 1);
    }

    #[test]
    fn a_data_segment_round_trips_at_every_length_and_offset() {
        for len in 1..=64usize {
            for tail_len in 0..=8usize {
                let seg = DataSegment {
                    conv: 0x0102,
                    option: SegmentOption(0x7f),
                    timestamp: 0x0a0b_0c0d,
                    number: 0x1122_3344,
                    sending_next: 0x5566_7788,
                    payload: (0..len as u8).collect(),
                    timeout: 0,
                    transmit: 0,
                };
                let trailer: Vec<u8> = (0..tail_len as u8).collect();
                let mut buf = Vec::new();
                Segment::Data(seg.clone()).serialize(&mut buf);
                buf.extend_from_slice(&trailer);
                assert_eq!(buf.len(), DATA_SEGMENT_OVERHEAD as usize + len + tail_len);
                let (got, rest) = read_segment(&buf, &|| Vec::new()).expect("parses");
                assert_eq!(got, Segment::Data(seg));
                assert_eq!(rest, trailer);
            }
        }
    }

    #[test]
    fn a_data_segment_claiming_more_than_it_carries_is_refused() {
        let mut raw = vec![0, 1, 1, 0];
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.extend_from_slice(&2u32.to_be_bytes());
        raw.extend_from_slice(&3u32.to_be_bytes());
        raw.extend_from_slice(&9u16.to_be_bytes());
        raw.extend_from_slice(b"short");
        assert!(read_segment(&raw, &|| Vec::new()).is_none());
    }

    #[test]
    fn two_segments_in_one_datagram_split_at_the_second() {
        let first = DataSegment {
            conv: 3,
            option: SegmentOption::NONE,
            timestamp: 1,
            number: 0,
            sending_next: 0,
            payload: b"first".to_vec(),
            timeout: 0,
            transmit: 0,
        };
        let second = CmdOnlySegment {
            conv: 3,
            cmd: Command::Terminate.to_byte(),
            option: SegmentOption::CLOSE,
            sending_next: 7,
            receiving_next: 8,
            peer_rto: 9,
        };
        let mut buf = Vec::new();
        Segment::Data(first.clone()).serialize(&mut buf);
        Segment::CmdOnly(second).serialize(&mut buf);
        assert_eq!(buf.len(), 23 + CMD_HEADER);
        let (got, rest) = read_segment(&buf, &|| Vec::new()).expect("first parses");
        assert_eq!(got, Segment::Data(first));
        let (got, rest) = read_segment(rest, &|| Vec::new()).expect("second parses");
        assert!(matches!(got, Segment::CmdOnly(_)));
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn a_cmd_only_segment_round_trips_at_every_command_byte() {
        for cmd in 2..=255u8 {
            let seg = CmdOnlySegment {
                conv: 0xbeef,
                cmd,
                option: SegmentOption(0xa5),
                sending_next: 0xdead_beef,
                receiving_next: 0x0bad_f00d,
                peer_rto: 12_500,
            };
            let mut buf = Vec::new();
            Segment::CmdOnly(seg).serialize(&mut buf);
            assert_eq!(buf.len(), CMD_HEADER);
            let (got, rest) = read_segment(&buf, &|| Vec::new()).expect("parses");
            assert_eq!(got, Segment::CmdOnly(seg));
            assert_eq!(rest.len(), 0);
        }
    }

    #[test]
    fn a_command_zero_or_one_reads_back_as_an_ack_or_a_data_segment() {
        for cmd in [0u8, 1u8] {
            let mut buf = vec![0xbe, 0xef, cmd, 0xa5];
            buf.extend_from_slice(&[0u8; CMD_HEADER]);
            let (got, _) = read_segment(&buf, &|| Vec::new()).expect("parses");
            match (cmd, got) {
                (0, Segment::Ack(a)) => assert_eq!((a.conv, a.option.0), (0xbeef, 0xa5)),
                (1, Segment::Data(d)) => assert_eq!((d.conv, d.option.0), (0xbeef, 0xa5)),
                _ => panic!("command {cmd} read back as the wrong variant"),
            }
        }
    }

    #[test]
    fn an_ack_segment_round_trips_at_every_count() {
        for count in 0..=255usize {
            let mut seg = AckSegment::new(ACK_NUMBER_LIMIT);
            seg.conv = 0x0102;
            seg.receiving_window = u32::MAX;
            seg.receiving_next = 7;
            seg.put_timestamp(4242);
            for n in 0..count as u32 {
                seg.put_number(n.wrapping_mul(0x0101_0101));
            }
            let mut buf = Vec::new();
            Segment::Ack(seg.clone()).serialize(&mut buf);
            assert_eq!(buf.len(), ACK_HEADER + count * 4);
            let (got, rest) = read_segment(&buf, &|| Vec::new()).expect("parses");
            assert_eq!(got, Segment::Ack(seg));
            assert_eq!(rest.len(), 0);
        }
    }

    #[test]
    fn a_zero_length_payload_does_not_round_trip() {
        let mut raw = vec![0, 1, 1, 0];
        raw.extend_from_slice(&3u32.to_be_bytes());
        raw.extend_from_slice(&4u32.to_be_bytes());
        raw.extend_from_slice(&5u32.to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        assert!(read_segment(&raw, &|| Vec::new()).is_none());
    }
}
