//! The two carriers a Foxy CONNECT tunnel runs over, one frame codec each: an HTTP/2 frame is a nine-byte header (24-bit length, type, flags, 31-bit stream id) with the reserved bits masked off rather than trusted, an HTTP/3 frame two QUIC varints where the type takes no payload bits and so always its widest form.

/// The nine bytes every HTTP/2 frame starts with.
pub const H2_HEADER: usize = 9;

pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
pub const CONTINUATION: u8 = 0x9;
/// A HEADERS or CONTINUATION carrying this flag ends the header block; without it the block continues and a partial block is not parsed.
pub const END_HEADERS: u8 = 0x4;
pub const PUSH_PROMISE: u8 = 0x5;
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
pub const PING: u8 = 0x6;
pub const GOAWAY: u8 = 0x7;
pub const WINDOW_UPDATE: u8 = 0x8;

/// The flag a DATA or HEADERS frame carries when it is the stream's last.
pub const END_STREAM: u8 = 0x1;
pub const PADDED: u8 = 0x8;
const FLAG_ACK: u8 = 0x1;

/// The client preface, sent before the first settings and answered by any HTTP/2 server.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub length: u32,
}

impl H2Frame {
    /// Parses a frame header, refusing a stream id with its reserved bit set because every frame this lane exchanges leaves that bit clear.
    #[must_use]
    pub fn parse(header: &[u8; H2_HEADER]) -> Option<Self> {
        // Two wide loads bring in length, kind and stream; three reserved bits collapse to one mask plus one byte test.
        let head = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let flags = header[4];
        if head & 0x8000_0080 != 0 || flags & 0x80 != 0 {
            return None;
        }
        let stream = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        Some(Self {
            kind: head as u8,
            flags,
            stream,
            length: head >> 8,
        })
    }

    #[must_use]
    pub fn header(&self) -> [u8; H2_HEADER] {
        let length = self.length.to_be_bytes();
        let stream = self.stream.to_be_bytes();
        [
            length[1], length[2], length[3], self.kind, self.flags, stream[0], stream[1],
            stream[2], stream[3],
        ]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum H2Event<'a> {
    /// A DATA frame's payload, trimmed of its padding, and the frame's wire length: RFC
    /// 7540 6.9 puts the whole payload into the flow-control window, the Pad Length octet
    /// and the Padding included, so a credit is the wire length and not what the trim left.
    Data {
        payload: &'a [u8],
        end: bool,
        wire: usize,
    },
    Headers {
        block: &'a [u8],
        end: bool,
    },
    Reset {
        code: u32,
    },
    Window {
        stream: u32,
        increment: u32,
    },
    Settings {
        ack: bool,
        payload: &'a [u8],
    },
    Ping {
        ack: bool,
        payload: &'a [u8],
    },
    GoAway {
        code: u32,
    },
    Push,
    Other {
        kind: u8,
    },
}

/// A frame on a session that carries many streams: the same event, with the stream it belongs to still named.
///
/// `h2_event` drops the id of a frame that is not this lane's, because a lane that owns one stream has nowhere to put a second one. A session that carries many streams has to route by id, so this variant keeps it: the payload and the wire length are exactly what `h2_event` hands over, and the id is the only difference.
#[derive(Debug, PartialEq, Eq)]
pub enum H2Routed<'a> {
    /// A DATA frame's payload, trimmed of its padding, and the frame's wire length.
    Data {
        stream: u32,
        payload: &'a [u8],
        end: bool,
        wire: usize,
    },
    Headers {
        stream: u32,
        block: &'a [u8],
        /// The frame's `END_STREAM`: nothing follows this block on the stream.
        end: bool,
        /// The frame's `END_HEADERS`: this block is whole, or a CONTINUATION follows.
        end_headers: bool,
    },
    /// A CONTINUATION frame's block: it continues the header block of the stream it names, and `end` says that block is whole.
    Continuation {
        stream: u32,
        block: &'a [u8],
        end: bool,
    },
    Reset {
        stream: u32,
        code: u32,
    },
    Window {
        stream: u32,
        increment: u32,
    },
    Settings {
        ack: bool,
        payload: &'a [u8],
    },
    Ping {
        ack: bool,
        payload: &'a [u8],
    },
    GoAway {
        code: u32,
    },
    Push,
    Other {
        kind: u8,
    },
}

/// Reads a four-byte big-endian body, treating a short frame as zeroes.
#[must_use]
pub fn be32(payload: &[u8]) -> u32 {
    u32::from_be_bytes([
        payload.first().copied().unwrap_or(0),
        payload.get(1).copied().unwrap_or(0),
        payload.get(2).copied().unwrap_or(0),
        payload.get(3).copied().unwrap_or(0),
    ])
}

#[must_use]
pub fn be64(payload: &[u8]) -> u64 {
    let len = payload.len().min(8);
    let mut value = 0u64;
    for byte in &payload[..len] {
        value = (value << 8) | u64::from(*byte);
    }
    value
}

/// A padded frame's payload: the padding-length byte and trailing pad come off, and a frame whose own bytes do not add up has no payload.
#[must_use]
fn unpadded(payload: &[u8]) -> Option<&[u8]> {
    let pad = usize::from(*payload.first()?);
    payload.get(1..payload.len().checked_sub(pad)?)
}

/// Classifies one complete frame against `ours`, this lane's stream id, because DATA and HEADERS are per-stream and every other type it acts on is not.
#[must_use]
pub fn h2_event(frame: H2Frame, payload: &[u8], ours: u32) -> H2Event<'_> {
    let trimmed = if frame.flags & PADDED == 0 {
        Some(payload)
    } else {
        unpadded(payload)
    };
    match frame.kind {
        DATA if frame.stream == ours => match trimmed {
            Some(body) => H2Event::Data {
                payload: body,
                end: frame.flags & END_STREAM != 0,
                wire: payload.len(),
            },
            // A pad length that does not fit the frame has no payload to hand over, but its octets still spent the window.
            None => H2Event::Data {
                payload: &[],
                end: frame.flags & END_STREAM != 0,
                wire: payload.len(),
            },
        },
        HEADERS if frame.stream == ours => match trimmed {
            Some(body) => H2Event::Headers {
                block: body,
                end: frame.flags & END_STREAM != 0,
            },
            None => H2Event::Other { kind: frame.kind },
        },
        RST_STREAM if frame.stream == ours => H2Event::Reset {
            code: be32(payload),
        },
        WINDOW_UPDATE => H2Event::Window {
            stream: frame.stream,
            increment: be32(payload) & 0x7fff_ffff,
        },
        SETTINGS => H2Event::Settings {
            ack: frame.flags & FLAG_ACK != 0,
            payload: trimmed.unwrap_or_default(),
        },
        PING => H2Event::Ping {
            ack: frame.flags & FLAG_ACK != 0,
            payload: trimmed.unwrap_or_default(),
        },
        GOAWAY => H2Event::GoAway {
            code: be32(payload),
        },
        PUSH_PROMISE => H2Event::Push,
        _ => H2Event::Other { kind: frame.kind },
    }
}

/// Classifies one complete frame, keeping the stream it belongs to: a session that carries many streams routes by this id, and the payload and the wire length are the ones `h2_event` hands over.
#[must_use]
pub fn h2_routed(frame: H2Frame, payload: &[u8]) -> H2Routed<'_> {
    let trimmed = if frame.flags & PADDED == 0 {
        Some(payload)
    } else {
        unpadded(payload)
    };
    match frame.kind {
        DATA => match trimmed {
            Some(body) => H2Routed::Data {
                stream: frame.stream,
                payload: body,
                end: frame.flags & END_STREAM != 0,
                wire: payload.len(),
            },
            // A pad length that does not fit the frame has no payload to hand over, but its octets still spent the window.
            None => H2Routed::Data {
                stream: frame.stream,
                payload: &[],
                end: frame.flags & END_STREAM != 0,
                wire: payload.len(),
            },
        },
        HEADERS => match trimmed {
            Some(body) => H2Routed::Headers {
                stream: frame.stream,
                block: body,
                end: frame.flags & END_STREAM != 0,
                end_headers: frame.flags & END_HEADERS != 0,
            },
            None => H2Routed::Other { kind: frame.kind },
        },
        CONTINUATION => match trimmed {
            Some(body) => H2Routed::Continuation {
                stream: frame.stream,
                block: body,
                end: frame.flags & END_HEADERS != 0,
            },
            None => H2Routed::Other { kind: frame.kind },
        },
        RST_STREAM => H2Routed::Reset {
            stream: frame.stream,
            code: be32(payload),
        },
        WINDOW_UPDATE => H2Routed::Window {
            stream: frame.stream,
            increment: be32(payload) & 0x7fff_ffff,
        },
        SETTINGS => H2Routed::Settings {
            ack: frame.flags & FLAG_ACK != 0,
            payload: trimmed.unwrap_or_default(),
        },
        PING => H2Routed::Ping {
            ack: frame.flags & FLAG_ACK != 0,
            payload: trimmed.unwrap_or_default(),
        },
        GOAWAY => H2Routed::GoAway {
            code: be32(payload),
        },
        PUSH_PROMISE => H2Routed::Push,
        _ => H2Routed::Other { kind: frame.kind },
    }
}

/// The window a tunnel is not paced by: the reference's 16 MiB, its largest frame, and no push, which this lane never accepts.
pub const WINDOW: u32 = 16 * 1024 * 1024;

/// The protocol's own default, which every window starts at until the peer's settings or a `WINDOW_UPDATE` moves it.
pub const DEFAULT_WINDOW: u32 = 65_535;

/// The frame size the reference asks the edge to use.
pub const MAX_FRAME: u32 = 256 * 1024;

/// What a CONNECT lane asks for at the start: a window big enough that a tunnel is not paced by a round trip, the largest frame the edge may send, and no push. Every dial asks for the same eighteen octets, so they are written down once instead of built per open.
pub const CLIENT_SETTINGS: [u8; 24] = client_settings();

#[must_use]
pub const fn client_settings() -> [u8; 24] {
    // The fourth ask is a zero header table: this lane's HPACK reader keeps no dynamic table, so an edge that indexed a status into one would make the next response on a pooled session name an entry the lane never stored.
    let asks = [
        (4u16, WINDOW),
        (5u16, MAX_FRAME),
        (2u16, 0u32),
        (1u16, 0u32),
    ];
    let mut out = [0u8; 24];
    let mut at = 0;
    while at < asks.len() {
        let (id, value) = asks[at];
        let (id, value) = (id.to_be_bytes(), value.to_be_bytes());
        out[at * 6] = id[0];
        out[at * 6 + 1] = id[1];
        let written = at * 6 + 2;
        out[written] = value[0];
        out[written + 1] = value[1];
        out[written + 2] = value[2];
        out[written + 3] = value[3];
        at += 1;
    }
    out
}

#[must_use]
pub fn setting(payload: &[u8], at: usize) -> Option<(u16, u32)> {
    Some((
        u16::from_be_bytes([*payload.get(at)?, *payload.get(at + 1)?]),
        u32::from_be_bytes([
            *payload.get(at + 2)?,
            *payload.get(at + 3)?,
            *payload.get(at + 4)?,
            *payload.get(at + 5)?,
        ]),
    ))
}

/// A QUIC variable-length integer: two bits of the first byte say how many bytes follow, and the value is big-endian across them.
pub fn quic_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
        }
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// The bytes a QUIC varint takes, so a length can be named before the bytes it counts are written.
pub fn quic_varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// The same varint written into a fixed buffer, so a frame header travels beside a payload that already has a home instead of staging it: the first byte carries the length tag and the value's top six bits, every later byte a whole eight, as `quic_varint` writes. The buffer may be any length; the value's width decides how many bytes it fills.
pub fn quic_varint_into(out: &mut [u8], value: u64) -> usize {
    // The four forms mirror `quic_varint` op for op — same width, same tag `or` — so the bytes are identical by construction, each one `to_be_bytes` plus a fixed copy instead of a value-sized byte loop; `the_fixed_buffer_varint_is_the_vec_one` reads them against each other at every width.
    match value {
        0..=63 => {
            out[0] = value as u8;
            1
        }
        64..=16_383 => {
            out[..2].copy_from_slice(&((value as u16) | 0x4000).to_be_bytes());
            2
        }
        16_384..=1_073_741_823 => {
            out[..4].copy_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
            4
        }
        _ => {
            out[..8].copy_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
            8
        }
    }
}

/// An HTTP/3 DATA frame header written where it is read: the type varint — always one byte, since `H3_DATA` is below 64 — then the payload length varint, into a buffer of at least nine bytes. Returns the header's length. The type and length go straight to their own offsets, so a frame header costs two stores rather than a varint, a one-byte shift of it, and a rewrite of the byte just shifted.
#[must_use]
pub fn h3_data_header(head: &mut [u8; 9], length: u64) -> usize {
    head[0] = H3_DATA as u8;
    1 + quic_varint_into(&mut head[1..], length)
}

#[must_use]
pub fn quic_read(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let first = *bytes.get(*at)?;
    let count = 1usize << usize::from(first >> 6);
    let raw = bytes.get(*at..at.checked_add(count)?)?;
    *at += count;
    // One fixed-width big-endian load per form, not a shift-and-or loop whose trip count the peer chose: masking the tag byte to its low six bits is the value's top and the later bytes are whole.
    let value = match count {
        1 => u64::from(first & 0x3f),
        2 => u64::from(u16::from_be_bytes([first & 0x3f, raw[1]])),
        4 => u64::from(u32::from_be_bytes([first & 0x3f, raw[1], raw[2], raw[3]])),
        _ => u64::from_be_bytes([
            first & 0x3f,
            raw[1],
            raw[2],
            raw[3],
            raw[4],
            raw[5],
            raw[6],
            raw[7],
        ]),
    };
    Some(value)
}

/// On a request stream HEADERS is 0x1 and DATA is 0x0; on the control stream those numbers mean control and push, which is why neither name is reused for a control type here.
pub const H3_DATA: u64 = 0x00;
pub const H3_HEADERS: u64 = 0x01;
pub const H3_RESET: u64 = 0x03;
pub const H3_GOAWAY: u64 = 0x07;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H3Frame {
    pub kind: u64,
    pub length: u64,
}

#[must_use]
pub fn h3_frame(bytes: &[u8], at: &mut usize) -> Option<H3Frame> {
    Some(H3Frame {
        kind: quic_read(bytes, at)?,
        length: quic_read(bytes, at)?,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum H3Event<'a> {
    Headers { block: &'a [u8], end: bool },
    Data { payload: &'a [u8], end: bool },
    Reset { code: u64 },
    GoAway { code: u64 },
    Other { kind: u64 },
}

#[must_use]
pub fn h3_event(frame: H3Frame, payload: &[u8]) -> H3Event<'_> {
    match frame.kind {
        H3_HEADERS => H3Event::Headers {
            block: payload,
            end: true,
        },
        H3_DATA => H3Event::Data { payload, end: true },
        H3_RESET => H3Event::Reset {
            code: be64(payload),
        },
        H3_GOAWAY => H3Event::GoAway {
            code: be64(payload),
        },
        _ => H3Event::Other { kind: frame.kind },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed-buffer varint and the `Vec` one are the same bytes at every width: a header sent in two pieces must be the frame a single write would have been.
    #[test]
    fn the_fixed_buffer_varint_is_the_vec_one() {
        for value in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            65_535,
            1_234_567,
        ] {
            let mut vec = Vec::new();
            quic_varint(&mut vec, value);
            let mut fixed = [0u8; 9];
            let len = quic_varint_into(&mut fixed, value);
            assert_eq!(vec, fixed[..len], "{value}");
        }
    }

    /// The DATA frame header is the type byte then the length varint, at every varint width — the exact bytes the write-then-shift-then-rewrite shape produced, without the shift.
    #[test]
    fn the_h3_data_header_is_the_type_then_the_length_varint() {
        for length in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            20_000,
            1_073_741_823,
            1_073_741_824,
        ] {
            let mut head = [0u8; 9];
            let hl = h3_data_header(&mut head, length);
            let mut want = vec![H3_DATA as u8];
            quic_varint(&mut want, length);
            assert_eq!(&head[..hl], &want[..], "{length}");
        }
    }

    const END_HEADERS: u8 = 0x4;

    fn frame_of(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> (H2Frame, Vec<u8>) {
        let frame = H2Frame {
            kind,
            flags,
            stream,
            length: payload.len() as u32,
        };
        let mut out = frame.header().to_vec();
        out.extend_from_slice(payload);
        (frame, out)
    }

    #[test]
    fn a_frame_header_round_trips_through_all_three_length_bytes() {
        for (kind, flags, stream, length) in [
            (DATA, END_STREAM, 1u32, 0usize),
            (HEADERS, END_HEADERS, 3, 255),
            (DATA, 0, 65_535, 65_535),
            (DATA, 0, 1, 0),
            (DATA, 0, 1, 8_388_607),
        ] {
            let frame = H2Frame {
                kind,
                flags,
                stream,
                length: length as u32,
            };
            let parsed = H2Frame::parse(&frame.header()).expect("parses");
            assert_eq!(parsed, frame);
        }
    }

    #[test]
    fn a_reserved_bit_is_refused_rather_than_masked() {
        for slot in [0usize, 3, 4] {
            let frame = H2Frame {
                kind: DATA,
                flags: 0,
                stream: 1,
                length: 0,
            };
            let mut header = frame.header();
            header[slot] |= 0x80;
            assert!(H2Frame::parse(&header).is_none(), "slot {slot}");
        }
    }

    #[test]
    fn data_for_this_stream_is_data_and_data_for_another_is_not() {
        let (frame, raw) = frame_of(DATA, 0, 1, b"hello");
        let H2Event::Data { payload, end, .. } = h2_event(frame, &raw[H2_HEADER..], 1) else {
            panic!("not data");
        };
        assert_eq!(payload, b"hello");
        assert!(!end);
        let (frame, raw) = frame_of(DATA, END_STREAM, 3, b"hello");
        assert_eq!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Other { kind: DATA }
        );
    }

    /// The witness that an impossible pad hands over no payload yet still costs the window its whole body.
    #[test]
    fn padding_comes_off_both_ends_and_an_impossible_pad_has_no_payload() {
        let (frame, raw) = frame_of(DATA, PADDED, 1, &[3, b'a', b'b', b'c', 9, 9, 9]);
        let H2Event::Data { payload, .. } = h2_event(frame, &raw[H2_HEADER..], 1) else {
            panic!("not data");
        };
        assert_eq!(payload, b"abc");
        let (frame, raw) = frame_of(DATA, PADDED, 1, &[200]);
        let H2Event::Data { payload, wire, .. } = h2_event(frame, &raw[H2_HEADER..], 1) else {
            panic!("not data");
        };
        assert!(
            payload.is_empty(),
            "the pad byte names more than the frame holds"
        );
        assert_eq!(wire, 1, "the octet still spent the window");
        let (frame, raw) = frame_of(DATA, PADDED, 1, &[]);
        assert_eq!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Data {
                payload: &[],
                end: false,
                wire: 0
            }
        );
    }

    #[test]
    fn the_frames_a_lane_acts_on_are_each_named() {
        let (frame, raw) = frame_of(HEADERS, END_HEADERS, 1, b"\x88");
        assert!(matches!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Headers {
                block: b"\x88",
                end: false
            }
        ));
        let (frame, raw) = frame_of(RST_STREAM, 0, 1, &[0, 0, 0, 8]);
        assert!(matches!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Reset { code: 8 }
        ));
        let (frame, raw) = frame_of(WINDOW_UPDATE, 0, 0, &[0, 0x10, 0, 1]);
        assert!(matches!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Window {
                stream: 0,
                increment: 1_048_577
            }
        ));
        let (frame, raw) = frame_of(SETTINGS, FLAG_ACK, 0, &[]);
        assert!(matches!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Settings { ack: true, .. }
        ));
        let (frame, raw) = frame_of(PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(matches!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Ping { ack: false, payload } if payload.len() == 8
        ));
        let (frame, raw) = frame_of(GOAWAY, 0, 0, &[0, 0, 0, 2]);
        assert!(matches!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::GoAway { code: 2 }
        ));
        let (frame, raw) = frame_of(RST_STREAM, 0, 3, &[0, 0, 0, 8]);
        assert_eq!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Other { kind: RST_STREAM }
        );
        let (frame, raw) = frame_of(HEADERS, 0, 3, b"\x88");
        assert_eq!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Other { kind: HEADERS }
        );
    }

    /// The witness that a shared session can route by id: the classifier that keeps the id hands over the payload the one that drops it hands over, and names the stream the other one refuses.
    #[test]
    fn a_routed_frame_keeps_the_stream_the_lane_would_drop() {
        let (frame, raw) = frame_of(DATA, 0, 3, b"hello");
        assert_eq!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Other { kind: DATA }
        );
        assert_eq!(
            h2_routed(frame, &raw[H2_HEADER..]),
            H2Routed::Data {
                stream: 3,
                payload: b"hello",
                end: false,
                wire: 5
            }
        );
        let (frame, raw) = frame_of(HEADERS, END_STREAM, 5, b"\x88");
        assert_eq!(
            h2_routed(frame, &raw[H2_HEADER..]),
            H2Routed::Headers {
                stream: 5,
                block: b"\x88",
                end: true,
                end_headers: false
            }
        );
        let (frame, raw) = frame_of(HEADERS, END_HEADERS, 7, b"\x88");
        assert_eq!(
            h2_routed(frame, &raw[H2_HEADER..]),
            H2Routed::Headers {
                stream: 7,
                block: b"\x88",
                end: false,
                end_headers: true
            }
        );
        let (frame, raw) = frame_of(RST_STREAM, 0, 7, &[0, 0, 0, 8]);
        assert_eq!(
            h2_routed(frame, &raw[H2_HEADER..]),
            H2Routed::Reset { stream: 7, code: 8 }
        );
    }

    /// The pad comes off the payload and stays in the wire length, on the routed classifier as on the other one.
    #[test]
    fn a_routed_padded_frame_credits_its_whole_wire_payload() {
        let (frame, raw) = frame_of(DATA, PADDED, 1, &[3, b'a', b'b', b'c', 9, 9, 9]);
        assert_eq!(
            h2_routed(frame, &raw[H2_HEADER..]),
            H2Routed::Data {
                stream: 1,
                payload: b"abc",
                end: false,
                wire: 7
            }
        );
    }

    #[test]
    fn a_push_is_never_accepted() {
        let (frame, raw) = frame_of(PUSH_PROMISE, 0, 0, b"x");
        assert!(matches!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Push
        ));
        let (frame, raw) = frame_of(0x10, 0, 1, b"x");
        assert_eq!(
            h2_event(frame, &raw[H2_HEADER..], 1),
            H2Event::Other { kind: 0x10 }
        );
    }

    #[test]
    fn a_short_body_reads_as_zeroes_rather_than_panicking() {
        for (kind, stream) in [
            (RST_STREAM, 1u32),
            (GOAWAY, 0),
            (WINDOW_UPDATE, 0),
            (PING, 0),
        ] {
            let (frame, raw) = frame_of(kind, 0, stream, &[]);
            let _ = h2_event(frame, &raw[H2_HEADER..], 1);
        }
        assert_eq!(be32(&[]), 0);
        assert_eq!(be64(&[1, 2]), 0x0102);
        assert_eq!(be64(&[0; 9]), 0);
    }

    #[test]
    fn the_client_settings_ask_for_a_window_a_frame_no_push_and_no_header_table() {
        let settings = CLIENT_SETTINGS;
        assert_eq!(settings.len(), 24);
        let found: Vec<(u16, u32)> = (0..settings.len() / 6)
            .filter_map(|at| setting(&settings, at * 6))
            .collect();
        assert_eq!(
            found,
            [(4, WINDOW), (5, MAX_FRAME), (2, 0), (1, 0)],
            "a zero header table is what keeps the lane's stateless reader safe on a reused session"
        );
        assert!(setting(&settings, 24).is_none());
    }

    #[test]
    fn a_quic_varint_spans_every_form_and_reads_back() {
        for value in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            (1 << 62) - 1,
        ] {
            let mut out = Vec::new();
            quic_varint(&mut out, value);
            assert_eq!(out.len(), 1usize << usize::from(out[0] >> 6), "{value}");
            let mut at = 0;
            assert_eq!(quic_read(&out, &mut at), Some(value), "{value}");
            assert_eq!(at, out.len());
        }
    }

    #[test]
    fn a_truncated_quic_varint_is_refused() {
        for bytes in [&[][..], &[0x40][..], &[0x80, 0x01][..], &[0xc0, 0, 0][..]] {
            let mut at = 0;
            assert_eq!(quic_read(bytes, &mut at), None, "{bytes:?}");
        }
    }

    #[test]
    fn an_http3_headers_frame_reads_its_type_and_length() {
        let mut out = Vec::new();
        quic_varint(&mut out, H3_HEADERS);
        quic_varint(&mut out, 4);
        out.extend_from_slice(b"\x00\x00\x01\x07");
        let mut at = 0;
        let frame = h3_frame(&out, &mut at).expect("reads");
        assert_eq!(
            frame,
            H3Frame {
                kind: H3_HEADERS,
                length: 4
            }
        );
        assert_eq!(at, 2);
        assert!(matches!(
            h3_event(frame, &out[at..]),
            H3Event::Headers {
                block: b"\x00\x00\x01\x07",
                end: true
            }
        ));
    }

    #[test]
    fn an_http3_reset_goaway_and_data_are_read_and_a_push_is_not() {
        let mut at = 0;
        let frame = h3_frame(&[0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 9], &mut at).expect("reads");
        assert_eq!(
            h3_event(frame, &[0, 0, 0, 0, 0, 0, 0, 9]),
            H3Event::Reset { code: 9 }
        );
        at = 0;
        let frame = h3_frame(&[0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 7], &mut at).expect("reads");
        assert_eq!(
            h3_event(frame, &[0, 0, 0, 0, 0, 0, 0, 7]),
            H3Event::GoAway { code: 7 }
        );
        assert_eq!(
            h3_event(
                H3Frame {
                    kind: 0x21,
                    length: 0
                },
                &[]
            ),
            H3Event::Other { kind: 0x21 }
        );
        assert!(matches!(
            h3_event(
                H3Frame {
                    kind: H3_DATA,
                    length: 0
                },
                &[]
            ),
            H3Event::Data { end: true, .. }
        ));
    }
}
