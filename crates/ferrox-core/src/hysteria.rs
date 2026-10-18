//! Hysteria version 2 framing: the bytes around the QUIC streams and datagrams — every TCP flow is one bidirectional stream opening with the `0x401` type as a QUIC varint, the connection authenticates by HTTP/3 `POST /auth` answered with status `233`, and the UDP lane rides QUIC datagrams each carrying a `BE32` session id ahead of a packet id, fragment metadata, a varint address and its payload.

use crate::foxy::{frames, hpack};

pub const TCP_FRAME: u64 = 0x401;

pub const AUTH_STATUS: u16 = 233;

pub const AUTH_PATH: &str = "/auth";

pub const AUTH_HEADER: &str = "hysteria-auth";

pub const CC_RX_HEADER: &str = "hysteria-cc-rx";

pub const UDP_HEADER: &str = "hysteria-udp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    Reno,
    Bbr,
    Brutal,
}

impl Congestion {
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text {
            "reno" => Self::Reno,
            "brutal" | "force-brutal" => Self::Brutal,
            _ => Self::Bbr,
        }
    }

    #[must_use]
    pub fn quiche_name(self) -> &'static str {
        match self {
            Self::Reno => "reno",
            Self::Bbr | Self::Brutal => "bbr",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub auth: String,
    pub cc: Congestion,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: String::new(),
            cc: Congestion::Bbr,
        }
    }
}

pub fn tcp_prefix(out: &mut Vec<u8>) {
    frames::quic_varint(out, TCP_FRAME);
}

#[must_use]
pub fn read_tcp_prefix(packet: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    (frames::quic_read(packet, &mut at) == Some(TCP_FRAME)).then_some(at)
}

pub const MAX_ADDRESS_LENGTH: u64 = 2048;

pub const MAX_PADDING_LENGTH: u64 = 4096;

pub const MAX_MESSAGE_LENGTH: u64 = 2048;

/// A framed field is still arriving; anything else is a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    Incomplete,
    Invalid,
}

fn bounded<'a>(packet: &'a [u8], at: &mut usize, limit: u64) -> Result<&'a [u8], RequestError> {
    let len = frames::quic_read(packet, at).ok_or(RequestError::Incomplete)?;
    if len > limit {
        return Err(RequestError::Invalid);
    }
    let bytes = packet
        .get(*at..*at + len as usize)
        .ok_or(RequestError::Incomplete)?;
    *at += len as usize;
    Ok(bytes)
}

/// The body after the `0x401` frame type: a varint-string `host:port` and a varint-skip of padding, the shape `proxy/hysteria`'s `WriteTCPRequest` puts on every TCP stream.
pub fn decode_tcp_request_body(packet: &[u8]) -> Result<(&str, usize), RequestError> {
    let mut at = 0usize;
    let raw = bounded(packet, &mut at, MAX_ADDRESS_LENGTH)?;
    let address = std::str::from_utf8(raw).map_err(|_| RequestError::Invalid)?;
    if address.is_empty() {
        return Err(RequestError::Invalid);
    }
    bounded(packet, &mut at, MAX_PADDING_LENGTH)?;
    Ok((address, at))
}

/// The full stream head: frame type, then the body.
pub fn decode_tcp_request(packet: &[u8]) -> Result<(&str, usize), RequestError> {
    let mut at = 0usize;
    if frames::quic_read(packet, &mut at).ok_or(RequestError::Incomplete)? != TCP_FRAME {
        return Err(RequestError::Invalid);
    }
    let (address, used) = decode_tcp_request_body(&packet[at..])?;
    Ok((address, at + used))
}

pub fn encode_tcp_request(address: &str, padding: &[u8], out: &mut Vec<u8>) {
    frames::quic_varint(out, TCP_FRAME);
    frames::quic_varint(out, address.len() as u64);
    out.extend_from_slice(address.as_bytes());
    frames::quic_varint(out, padding.len() as u64);
    out.extend_from_slice(padding);
}

/// Status byte, then varint-framed message and padding; `ok` is the only status a client continues on, matching `WriteTCPResponse(w, true, "")`.
pub fn encode_tcp_response(ok: bool, message: &[u8], padding: &[u8], out: &mut Vec<u8>) {
    out.push(u8::from(!ok));
    frames::quic_varint(out, message.len() as u64);
    out.extend_from_slice(message);
    frames::quic_varint(out, padding.len() as u64);
    out.extend_from_slice(padding);
}

pub const MAX_UDP_PAYLOAD: usize = 65535;

/// One UDP message as it rides a QUIC datagram: `BE32 session || BE16 packet || frag id || frag count || varint address || address || data`, the exact shape `proxy/hysteria`'s `UDPMessage.Serialize` and `ParseUDPMessage` put on every datagram of the reliable lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpMessage<'a> {
    pub session: u32,
    pub packet: u16,
    pub frag: u8,
    pub frags: u8,
    pub address: &'a str,
    pub payload: &'a [u8],
}

impl UdpMessage<'_> {
    /// Bytes before the payload: the fixed eight-byte head plus the varint-framed address.
    #[must_use]
    pub fn header_len(&self) -> usize {
        8 + frames::quic_varint_len(self.address.len() as u64) + self.address.len()
    }

    /// The refusals encoder and parser make alike before any byte moves: an empty or over-long address, an empty or over-large payload, and a fragment id outside its count.
    fn validate(&self) -> Result<(), RequestError> {
        if self.address.is_empty() || self.address.len() > MAX_ADDRESS_LENGTH as usize {
            return Err(RequestError::Invalid);
        }
        if self.payload.is_empty() || self.payload.len() > MAX_UDP_PAYLOAD {
            return Err(RequestError::Invalid);
        }
        if self.frags == 0 || (self.frags > 1 && self.frag >= self.frags) {
            return Err(RequestError::Invalid);
        }
        Ok(())
    }
}

/// Append a whole UDP message to `out`; the session id is written here rather than left for the transport, so a datagram is self-describing.
pub fn encode_udp(message: &UdpMessage, out: &mut Vec<u8>) -> Result<(), RequestError> {
    message.validate()?;
    out.extend_from_slice(&message.session.to_be_bytes());
    out.extend_from_slice(&message.packet.to_be_bytes());
    out.push(message.frag);
    out.push(message.frags);
    frames::quic_varint(out, message.address.len() as u64);
    out.extend_from_slice(message.address.as_bytes());
    out.extend_from_slice(message.payload);
    Ok(())
}

/// Read one whole UDP message from a datagram; the payload is whatever follows the address, borrowed from the caller's buffer, so a relay never copies it to look at it.
pub fn decode_udp(packet: &[u8]) -> Result<UdpMessage<'_>, RequestError> {
    let head = packet.get(..8).ok_or(RequestError::Incomplete)?;
    let mut at = 8usize;
    let raw = bounded(packet, &mut at, MAX_ADDRESS_LENGTH)?;
    if raw.is_empty() {
        return Err(RequestError::Invalid);
    }
    let address = std::str::from_utf8(raw).map_err(|_| RequestError::Invalid)?;
    let message = UdpMessage {
        session: u32::from_be_bytes([head[0], head[1], head[2], head[3]]),
        packet: u16::from_be_bytes([head[4], head[5]]),
        frag: head[6],
        frags: head[7],
        address,
        payload: &packet[at..],
    };
    message.validate()?;
    Ok(message)
}

/// Split a whole message across datagrams no larger than `max` — the peer's writable datagram size — without copying its payload; a head already at or over `max` is refused rather than truncated.
pub fn fragment_udp<'a>(
    message: &UdpMessage<'a>,
    max: usize,
    out: &mut Vec<UdpMessage<'a>>,
) -> Result<(), RequestError> {
    message.validate()?;
    if message.frags != 1 {
        return Err(RequestError::Invalid);
    }
    let capacity = max
        .checked_sub(message.header_len())
        .filter(|room| *room > 0)
        .ok_or(RequestError::Invalid)?;
    let count = u8::try_from(message.payload.len().div_ceil(capacity))
        .map_err(|_| RequestError::Invalid)?;
    for (index, chunk) in message.payload.chunks(capacity).enumerate() {
        out.push(UdpMessage {
            frag: index as u8,
            frags: count,
            payload: chunk,
            ..*message
        });
    }
    Ok(())
}

/// The reassembly of one session's datagrams: at most one incomplete packet, a new packet id discarding the previous partial, fragments delivered in id order once every slot fills — the pinned `Defragger`'s contract, minus its byte budget and timer, which the relay's own idle reap replaces.
#[derive(Debug, Default)]
pub struct Defrag {
    packet: u16,
    address: String,
    slots: Vec<Option<Vec<u8>>>,
    have: usize,
    size: usize,
}

impl Defrag {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one message in; `Some((address, payload))` when a datagram is whole. A single fragment clears any partial and passes straight through, so an unfragmented datagram never waits on the state.
    pub fn feed(
        &mut self,
        message: &UdpMessage<'_>,
    ) -> Result<Option<(String, Vec<u8>)>, RequestError> {
        message.validate()?;
        if message.frags == 1 {
            *self = Self::default();
            return Ok(Some((message.address.to_owned(), message.payload.to_vec())));
        }
        if self.slots.is_empty() || self.packet != message.packet {
            self.packet = message.packet;
            message.address.clone_into(&mut self.address);
            self.slots = vec![None; usize::from(message.frags)];
            self.have = 0;
            self.size = 0;
        }
        if self.address != message.address || self.slots.len() != usize::from(message.frags) {
            *self = Self::default();
            return Err(RequestError::Invalid);
        }
        let slot = &mut self.slots[usize::from(message.frag)];
        if slot.is_some() {
            return Ok(None);
        }
        self.size += message.payload.len();
        *slot = Some(message.payload.to_vec());
        self.have += 1;
        if self.have != self.slots.len() {
            return Ok(None);
        }
        let address = std::mem::take(&mut self.address);
        let mut payload = Vec::with_capacity(self.size);
        for fragment in std::mem::take(&mut self.slots).into_iter().flatten() {
            payload.extend_from_slice(&fragment);
        }
        self.have = 0;
        self.size = 0;
        Ok(Some((address, payload)))
    }
}

pub fn build_auth_request(host: &str, auth: &str, out: &mut Vec<u8>) {
    hpack::qpack_literal_many(
        &[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", host),
            (":path", AUTH_PATH),
            (AUTH_HEADER, auth),
            (CC_RX_HEADER, "0"),
        ],
        out,
    );
}

pub fn build_auth_response(udp: bool, out: &mut Vec<u8>) {
    hpack::qpack_literal_many(
        &[
            (":status", "233"),
            (UDP_HEADER, if udp { "true" } else { "false" }),
            (CC_RX_HEADER, "0"),
        ],
        out,
    );
}

fn find<'a>(fields: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(key, _)| key == name.as_bytes())
        .map(|(_, value)| value.as_slice())
}

#[must_use]
pub fn verify_auth_request(block: &[u8], expected_auth: &str) -> bool {
    if expected_auth.is_empty() {
        return false;
    }
    let Some(fields) = hpack::qpack_fields(block) else {
        return false;
    };
    find(&fields, ":method") == Some(b"POST".as_slice())
        && find(&fields, ":path") == Some(AUTH_PATH.as_bytes())
        && find(&fields, AUTH_HEADER) == Some(expected_auth.as_bytes())
}

#[must_use]
pub fn verify_auth_response(block: &[u8]) -> bool {
    let Some(fields) = hpack::qpack_fields(block) else {
        return false;
    };
    find(&fields, ":status") == Some(b"233".as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tcp_frame_type_is_two_bytes_on_the_wire() {
        let mut out = Vec::new();
        tcp_prefix(&mut out);
        assert_eq!(out, vec![0x44, 0x01]);
        assert_eq!(read_tcp_prefix(&out), Some(2));
        assert_eq!(read_tcp_prefix(&[0x44]), None);
        assert_eq!(read_tcp_prefix(&[0x40, 0x01]), None);
        assert_eq!(read_tcp_prefix(&[0x44, 0x01, 0x00]), Some(2));
    }

    #[test]
    fn a_tcp_request_is_frame_address_padding_on_the_wire() {
        let mut out = Vec::new();
        encode_tcp_request("127.0.0.1:8080", &[0xAB; 3], &mut out);
        let mut want = vec![0x44, 0x01, 14];
        want.extend_from_slice(b"127.0.0.1:8080");
        want.extend_from_slice(&[3, 0xAB, 0xAB, 0xAB]);
        assert_eq!(out, want);
        assert_eq!(decode_tcp_request(&out), Ok(("127.0.0.1:8080", out.len())));
        assert_eq!(
            decode_tcp_request_body(&out[2..]),
            Ok(("127.0.0.1:8080", out.len() - 2))
        );
        assert_eq!(decode_tcp_request(&out[..5]), Err(RequestError::Incomplete));
        assert_eq!(decode_tcp_request(&out[..2]), Err(RequestError::Incomplete));
        assert_eq!(decode_tcp_request(&[0x44]), Err(RequestError::Incomplete));
        assert_eq!(
            decode_tcp_request(&[0x41, 0x00]),
            Err(RequestError::Invalid)
        );
        assert_eq!(
            decode_tcp_request_body(&[5, b'a', b'b']),
            Err(RequestError::Incomplete)
        );
        assert_eq!(decode_tcp_request_body(&[0]), Err(RequestError::Invalid));
        let mut too_long = Vec::new();
        frames::quic_varint(&mut too_long, MAX_ADDRESS_LENGTH + 1);
        assert_eq!(
            decode_tcp_request_body(&too_long),
            Err(RequestError::Invalid)
        );
    }

    #[test]
    fn a_tcp_response_is_status_message_padding_on_the_wire() {
        let mut out = Vec::new();
        encode_tcp_response(true, &[], &[], &mut out);
        assert_eq!(out, vec![0, 0, 0]);
        let mut refused = Vec::new();
        encode_tcp_response(false, b"no route", &[7; 2], &mut refused);
        assert_eq!(refused[0], 1);
        assert_eq!(&refused[2..10], b"no route");
        assert_eq!(&refused[10..], [2, 7, 7]);
    }

    #[test]
    fn a_udp_datagram_is_session_packet_frag_address_then_payload() {
        // A hand-computed vector of the pinned wire: BE32 session, BE16 packet, frag id, frag count, 1-byte varint address length, address, payload.
        let message = UdpMessage {
            session: 1,
            packet: 2,
            frag: 0,
            frags: 1,
            address: "127.0.0.1:80",
            payload: b"hi",
        };
        let mut out = Vec::new();
        encode_udp(&message, &mut out).expect("encodes");
        let mut want = vec![0, 0, 0, 1, 0, 2, 0, 1, 12];
        want.extend_from_slice(b"127.0.0.1:80");
        want.extend_from_slice(b"hi");
        assert_eq!(out, want);
        assert_eq!(message.header_len(), want.len() - 2);
        let back = decode_udp(&out).expect("decodes");
        assert_eq!(back, message);
        // The payload is borrowed, never copied: its base is the byte right after the head in the caller's own buffer.
        assert_eq!(back.payload.as_ptr(), out[message.header_len()..].as_ptr());
    }

    #[test]
    fn a_udp_datagram_refuses_the_same_shapes_on_both_ends() {
        // Too short for the fixed head.
        assert_eq!(decode_udp(&[0; 7]), Err(RequestError::Incomplete));
        // Empty address.
        assert_eq!(
            decode_udp(&[0, 0, 0, 1, 0, 2, 0, 1, 0, b'x']),
            Err(RequestError::Invalid)
        );
        // Address present but no payload byte, which the pinned parser rejects.
        assert_eq!(
            decode_udp(&[0, 0, 0, 1, 0, 2, 0, 1, 1, b'a']),
            Err(RequestError::Invalid)
        );
        // A fragment id outside its count is refused on encode and on decode alike.
        assert_eq!(
            encode_udp(
                &UdpMessage {
                    session: 1,
                    packet: 1,
                    frag: 3,
                    frags: 2,
                    address: "h:1",
                    payload: b"x",
                },
                &mut Vec::new(),
            ),
            Err(RequestError::Invalid)
        );
        // A length that cannot be a real address is refused before any slice is taken.
        let mut long = vec![0, 0, 0, 1, 0, 1, 0, 1];
        frames::quic_varint(&mut long, MAX_ADDRESS_LENGTH + 1);
        assert_eq!(decode_udp(&long), Err(RequestError::Invalid));
    }

    #[test]
    fn fragmenting_keeps_payload_whole_and_ids_sequential() {
        // A 10-byte payload behind a 12-byte head in a 16-byte datagram leaves four bytes a fragment, so three carry it.
        let message = UdpMessage {
            session: 7,
            packet: 42,
            frag: 0,
            frags: 1,
            address: "a:1",
            payload: b"0123456789",
        };
        // header_len is 8 + 1 varint + 3 address = 12, so capacity is 16 - 12 = 4 -> three fragments.
        let mut frags = Vec::new();
        fragment_udp(&message, 16, &mut frags).expect("fragments");
        assert_eq!(frags.len(), 3);
        assert!(frags.iter().all(|f| f.frags == 3));
        assert_eq!(frags[0].frag, 0);
        assert_eq!(frags[2].frag, 2);
        let joined: Vec<u8> = frags
            .iter()
            .flat_map(|f| f.payload.iter().copied())
            .collect();
        assert_eq!(joined, b"0123456789");
        // A capacity no larger than the head cannot carry even one byte.
        assert_eq!(
            fragment_udp(&message, 12, &mut Vec::new()),
            Err(RequestError::Invalid)
        );
        // Feeding fragments out of order still reassembles in id order.
        let mut defrag = Defrag::new();
        assert_eq!(defrag.feed(&frags[2]).expect("ok"), None);
        assert_eq!(defrag.feed(&frags[0]).expect("ok"), None);
        let whole = defrag.feed(&frags[1]).expect("ok").expect("complete");
        assert_eq!(whole.0, "a:1");
        assert_eq!(whole.1, b"0123456789");
    }

    #[test]
    fn a_new_packet_id_discards_the_partial_before_it() {
        let mut defrag = Defrag::new();
        let first = UdpMessage {
            session: 1,
            packet: 1,
            frag: 0,
            frags: 2,
            address: "a:1",
            payload: b"x",
        };
        assert_eq!(defrag.feed(&first).expect("ok"), None);
        // A new packet id on the same session drops the half-filled packet.
        let next = UdpMessage { packet: 2, ..first };
        assert_eq!(defrag.feed(&next).expect("ok"), None);
        let tail = UdpMessage {
            packet: 2,
            frag: 1,
            payload: b"y",
            ..first
        };
        let whole = defrag.feed(&tail).expect("ok").expect("complete");
        assert_eq!(whole.1, b"xy");
    }

    #[test]
    fn an_auth_request_carries_post_auth_and_no_brutal_cap() {
        let mut block = Vec::new();
        build_auth_request("edge.example:443", "s3cret", &mut block);
        assert!(verify_auth_request(&block, "s3cret"));
        assert!(!verify_auth_request(&block, "wrong"));
        assert!(!verify_auth_request(&block, ""));
        let fields = hpack::qpack_fields(&block).expect("reads");
        assert_eq!(fields.len(), 6);
        assert!(fields.contains(&(b":method".to_vec(), b"POST".to_vec())));
        assert!(fields.contains(&(b":path".to_vec(), b"/auth".to_vec())));
        assert!(fields.contains(&(b"hysteria-cc-rx".to_vec(), b"0".to_vec())));
    }

    #[test]
    fn an_auth_request_with_the_wrong_shape_is_refused() {
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "GET"),
                (":path", "/auth"),
                (AUTH_HEADER, "s3cret"),
            ],
            &mut block,
        );
        assert!(!verify_auth_request(&block, "s3cret"));
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "POST"),
                (":path", "/other"),
                (AUTH_HEADER, "s3cret"),
            ],
            &mut block,
        );
        assert!(!verify_auth_request(&block, "s3cret"));
        assert!(!verify_auth_request(&[0x01, 0x00], "s3cret"));
    }

    #[test]
    fn an_auth_response_is_status_233_and_advertises_the_udp_lane() {
        let mut block = Vec::new();
        build_auth_response(true, &mut block);
        assert!(verify_auth_response(&block));
        let fields = hpack::qpack_fields(&block).expect("reads");
        assert_eq!(find(&fields, UDP_HEADER), Some(b"true".as_slice()));
        let mut off = Vec::new();
        build_auth_response(false, &mut off);
        let fields = hpack::qpack_fields(&off).expect("reads");
        assert_eq!(find(&fields, UDP_HEADER), Some(b"false".as_slice()));
        let mut block = Vec::new();
        hpack::qpack_literal_many(&[(":status", "200")], &mut block);
        assert!(!verify_auth_response(&block));
        assert!(!verify_auth_response(&[0x00]));
    }

    #[test]
    fn a_decoded_datagram_leaves_its_payload_where_it_landed() {
        // The relay hands the decoded payload straight to the target socket, so the borrow is the copy removal: the returned slice's base has to lie inside the datagram that arrived, and the header parse must not grow or move that buffer.
        let mut wire = Vec::new();
        encode_udp(
            &UdpMessage {
                session: 4,
                packet: 9,
                frag: 0,
                frags: 1,
                address: "edge.example:443",
                payload: b"relay-bytes",
            },
            &mut wire,
        )
        .expect("encodes");
        let base = wire.as_ptr();
        let room = wire.capacity();
        let message = decode_udp(&wire).expect("decodes");
        assert!(
            wire.as_ptr_range().contains(&message.payload.as_ptr()),
            "the payload was never copied out of the datagram"
        );
        assert_eq!(wire.as_ptr(), base, "the buffer itself never moved");
        assert_eq!(wire.capacity(), room, "no reallocation in the parse");
        assert_eq!(message.payload, b"relay-bytes");
    }

    #[test]
    fn every_length_survives_fragment_then_defrag_intact() {
        // Sweep payload lengths that are and are not a multiple of the fragment capacity, at a window that carries only a few bytes per datagram, so the arithmetic a single echo never reaches is covered here: fragment count, the short last fragment, and reassembly back to the exact bytes.
        let address = "edge.example:443";
        for len in 1..=200usize {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let message = UdpMessage {
                session: 9,
                packet: 1,
                frag: 0,
                frags: 1,
                address,
                payload: &payload,
            };
            // A datagram of the head plus seven bytes carries seven payload bytes per fragment.
            let max = message.header_len() + 7;
            let mut frags = Vec::new();
            fragment_udp(&message, max, &mut frags).expect("fragments");
            assert_eq!(frags.len(), len.div_ceil(7));
            let mut defrag = Defrag::new();
            let mut whole = None;
            for frag in &frags {
                if let Some(done) = defrag.feed(frag).expect("feeds") {
                    assert!(whole.replace(done).is_none(), "assembles exactly once");
                }
            }
            let (got_address, got_payload) = whole.expect("reassembles");
            assert_eq!(got_address, address);
            assert_eq!(got_payload, payload);
        }
    }

    #[test]
    fn congestion_spellings_map_to_the_paced_default() {
        assert_eq!(Congestion::parse("reno"), Congestion::Reno);
        assert_eq!(Congestion::parse("bbr"), Congestion::Bbr);
        assert_eq!(Congestion::parse("brutal"), Congestion::Brutal);
        assert_eq!(Congestion::parse("force-brutal"), Congestion::Brutal);
        assert_eq!(Congestion::parse(""), Congestion::Bbr);
        assert_eq!(Congestion::parse("cubic"), Congestion::Bbr);
        assert_eq!(Congestion::Reno.quiche_name(), "reno");
        assert_eq!(Congestion::Bbr.quiche_name(), "bbr");
        assert_eq!(Congestion::Brutal.quiche_name(), "bbr");
    }
}
