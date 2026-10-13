//! MASQUE CONNECT-UDP over the HTTP/2 edge, one UDP target per stream: RFC 9298 §3.4 extended CONNECT with the default URI template, RFC 9297 §3.5 DATAGRAM capsules carrying RFC 9298 §5 payloads (context 0 plus the UDP bytes) — arithmetic only, nothing here opens a socket.

use super::frames::{quic_read, quic_varint, quic_varint_len};
use super::hpack::{integer, integer_into};

/// The default URI template, RFC 9298 §2, up to the target host.
const PREFIX: &[u8] = b"/.well-known/masque/udp/";
/// The scheme the pass is presented with, the shape the edge answers on both carriers.
const BEARER: &[u8] = b"Bearer ";

/// The default URI template's path for one target (RFC 9298 §2): only a colon is encoded, because of a DNS name, an IPv4 literal and an IPv6 literal only the last uses one.
pub fn udp_path(target_host: &str, target_port: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(PREFIX);
    for byte in target_host.bytes() {
        if byte == b':' {
            out.extend_from_slice(b"%3A");
        } else {
            out.push(byte);
        }
    }
    out.push(b'/');
    push_port(out, target_port);
    out.push(b'/');
}

/// The path's length, named before writing it: HTTP/2 and QPACK write a field's length ahead of its bytes, so staging the path first would cost a buffer per connection.
fn udp_path_len(target_host: &str, target_port: u16) -> usize {
    PREFIX.len()
        + target_host.len()
        + 2 * target_host.bytes().filter(|byte| *byte == b':').count()
        + 1
        + decimal_len(target_port)
        + 1
}

/// The port's digits, written lowest first into the end of the buffer: a division per digit is the whole cost, where a `format!` here is an allocation per path.
fn push_port(out: &mut Vec<u8>, port: u16) {
    let mut port = port;
    let mut digits = [0u8; 5];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (port % 10) as u8;
        port /= 10;
        if port == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
}

/// The digits a decimal number has, so its length can be known before it is written.
fn decimal_len(mut value: u16) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// One HTTP/2 literal field line: the new-name pattern, then the name with a 7-bit prefix and the value the same way.
fn field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x00);
    integer(out, 7, 0x00, name.len());
    out.extend_from_slice(name);
    integer(out, 7, 0x00, value.len());
    out.extend_from_slice(value);
}

/// The same field line under QPACK's `001` pattern: the never-indexed bit set and a three-bit name prefix continuing into the following bytes.
fn qpack_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x20);
    integer_into(out, 3, name.len());
    out.extend_from_slice(name);
    integer(out, 7, 0x00, value.len());
    out.extend_from_slice(value);
}

/// The `:path` field line for one target: its length is known before the path is written, so the path never sits in a buffer of its own.
fn path_field(out: &mut Vec<u8>, host: &str, port: u16) {
    out.push(0x00);
    integer(out, 7, 0x00, 5);
    out.extend_from_slice(b":path");
    integer(out, 7, 0x00, udp_path_len(host, port));
    udp_path(host, port, out);
}

/// The authorization field line, the pass behind the scheme: one length covers both halves and the bytes follow in place, because a `Bearer ` and a token are never more than a concatenation.
fn bearer_field(out: &mut Vec<u8>, bearer: &str) {
    out.push(0x00);
    integer(out, 7, 0x00, b"proxy-authorization".len());
    out.extend_from_slice(b"proxy-authorization");
    integer(out, 7, 0x00, BEARER.len() + bearer.len());
    out.extend_from_slice(BEARER);
    out.extend_from_slice(bearer.as_bytes());
}

/// One CONNECT-UDP request over HTTP/2: the extended-CONNECT fields in the RFC's own order, the edge as authority, the default template as path, and the account's pass as a `Bearer` token.
pub fn connect_udp(
    edge_authority: &str,
    target_host: &str,
    target_port: u16,
    bearer: &str,
    out: &mut Vec<u8>,
) {
    field(out, b":method", b"CONNECT");
    field(out, b":protocol", b"connect-udp");
    field(out, b":scheme", b"https");
    field(out, b":authority", edge_authority.as_bytes());
    path_field(out, target_host, target_port);
    bearer_field(out, bearer);
    field(out, b"capsule-protocol", b"?1");
}

/// The same seven fields as a QPACK block for HTTP/3: literal field lines, two zero prefix bytes naming no dynamic state, and no Huffman to compute on either side.
pub fn connect_udp_qpack(
    edge_authority: &str,
    target_host: &str,
    target_port: u16,
    bearer: &str,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&[0x00, 0x00]);
    qpack_field(out, b":method", b"CONNECT");
    qpack_field(out, b":protocol", b"connect-udp");
    qpack_field(out, b":scheme", b"https");
    qpack_field(out, b":authority", edge_authority.as_bytes());
    out.push(0x20);
    integer_into(out, 3, 5);
    out.extend_from_slice(b":path");
    integer(out, 7, 0x00, udp_path_len(target_host, target_port));
    udp_path(target_host, target_port, out);
    out.push(0x20);
    integer_into(out, 3, b"proxy-authorization".len());
    out.extend_from_slice(b"proxy-authorization");
    integer(out, 7, 0x00, BEARER.len() + bearer.len());
    out.extend_from_slice(BEARER);
    out.extend_from_slice(bearer.as_bytes());
    qpack_field(out, b"capsule-protocol", b"?1");
}

/// Bytes one DATAGRAM capsule takes for a payload of this length, so a caller frames it before building it: HTTP/3 writes its frame length ahead, and the capsule's varint sits inside that length.
pub fn datagram_len(payload: usize) -> usize {
    1 + quic_varint_len(1 + payload as u64) + 1 + payload
}

/// One UDP payload as one DATAGRAM capsule: type zero, the context byte zero, then the bytes unchanged.
pub fn datagram_encode(payload: &[u8], out: &mut Vec<u8>) {
    out.push(0x00);
    quic_varint(out, 1 + payload.len() as u64);
    out.push(0x00);
    out.extend_from_slice(payload);
}

/// The first complete DATAGRAM capsule in a stream buffer: bytes consumed and the payload, or `None` while it is not whole; unknown types and nonzero contexts are skipped rather than refused, since neither carries bytes this lane reads.
#[must_use]
pub fn datagram_split(buf: &[u8]) -> Option<(usize, &[u8])> {
    let mut at = 0usize;
    while at < buf.len() {
        let capsule = quic_read(buf, &mut at)?;
        let length = quic_read(buf, &mut at)? as usize;
        let end = at.checked_add(length)?;
        let value = buf.get(at..end)?;
        if capsule == 0 {
            let mut context_at = 0usize;
            if quic_read(value, &mut context_at) == Some(0) {
                return Some((end, &value[context_at..]));
            }
        }
        if end == at {
            return None;
        }
        at = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_path_names_its_target_and_encodes_only_colons() {
        let mut out = Vec::new();
        udp_path("example.com", 443, &mut out);
        assert_eq!(out, b"/.well-known/masque/udp/example.com/443/");
        out.clear();
        udp_path("192.0.2.6", 53, &mut out);
        assert_eq!(out, b"/.well-known/masque/udp/192.0.2.6/53/");
        out.clear();
        udp_path("2001:db8::42", 443, &mut out);
        assert_eq!(out, b"/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/");
    }

    #[test]
    fn a_connect_udp_block_carries_protocol_path_and_bearer() {
        let mut block = Vec::new();
        connect_udp(
            "edge.example:2499",
            "example.com",
            443,
            "the-pass",
            &mut block,
        );
        let text = String::from_utf8_lossy(&block);
        for field in [
            "CONNECT",
            "connect-udp",
            "https",
            "edge.example:2499",
            "/.well-known/masque/udp/example.com/443/",
            "Bearer the-pass",
            "capsule-protocol",
            "?1",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        assert_eq!(super::super::hpack::hpack_status(&block), None);
    }

    /// The two carriers write the same seven fields, one as a HPACK block and one as QPACK, so a reader walking literals either way is what compares them.
    #[test]
    fn both_carriers_carry_the_same_seven_fields_in_the_same_order() {
        let mut h2 = Vec::new();
        connect_udp("edge.example:2499", "example.com", 443, "the-pass", &mut h2);
        let mut q3 = Vec::new();
        connect_udp_qpack("edge.example:2499", "example.com", 443, "the-pass", &mut q3);
        assert_eq!(fields_of(&q3), fields_of_h2(&h2));

        let mut h2 = Vec::new();
        connect_udp(
            "[::1]:2499",
            "2001:db8::42",
            65535,
            "a.longer.pass",
            &mut h2,
        );
        let mut q3 = Vec::new();
        connect_udp_qpack(
            "[::1]:2499",
            "2001:db8::42",
            65535,
            "a.longer.pass",
            &mut q3,
        );
        assert_eq!(fields_of(&q3), fields_of_h2(&h2));
    }

    /// The QPACK block's fields, read with the reader this tree already has.
    fn fields_of(block: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        super::super::hpack::qpack_fields(block).expect("parses")
    }

    /// The HTTP/2 block's literal field lines, walked as a literal reader walks them: the new-name pattern, then the name and the value.
    fn fields_of_h2(block: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut fields = Vec::new();
        let mut at = 0usize;
        while at < block.len() {
            assert_eq!(block[at], 0x00, "the literal pattern");
            at += 1;
            let name = prefixed(block, &mut at, 7);
            let value = prefixed(block, &mut at, 7);
            fields.push((name, value));
        }
        fields
    }

    fn prefixed(block: &[u8], at: &mut usize, prefix: u8) -> Vec<u8> {
        let first = block[*at];
        *at += 1;
        let mut len = usize::from(first & ((1 << prefix) - 1));
        if len == (1 << prefix) - 1 {
            let mut shift = 0u32;
            loop {
                let byte = block[*at];
                *at += 1;
                len += usize::from(byte & 0x7f) << shift;
                shift += 7;
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        let out = block[*at..*at + len].to_vec();
        *at += len;
        out
    }

    /// The path's length is issued before the path is written, so it is a claim with a checker: the length the field line names is the length of the bytes that follow it, at every host and port length.
    #[test]
    fn a_named_path_length_is_the_length_of_the_bytes_that_follow() {
        for (host, port) in [
            ("a", 1),
            ("example.com", 443),
            ("192.0.2.6", 65535),
            ("2001:db8::42", 80),
            ("a-rather-longer-hostname.example", 8080),
        ] {
            for build in [connect_udp, connect_udp_qpack] {
                let mut block = Vec::new();
                build("edge.example:2499", host, port, "the-pass", &mut block);
                let mut path = Vec::new();
                udp_path(host, port, &mut path);
                let path = String::from_utf8(path).expect("ascii");
                let text = String::from_utf8_lossy(&block).into_owned();
                assert_eq!(
                    text.matches(&path).count(),
                    1,
                    "{host} writes its path once"
                );
            }
        }
        let mut path = Vec::new();
        udp_path("2001:db8::42", 65535, &mut path);
        assert_eq!(udp_path_len("2001:db8::42", 65535), path.len());
    }

    /// A frame length issued before the capsule is built is the length of the capsule built, at every payload width and both varint widths.
    #[test]
    fn a_named_capsule_length_is_the_length_of_the_capsule_built() {
        for payload in [0usize, 1, 63, 64, 16_383, 16_384, 70_000] {
            assert_eq!(datagram_len(payload), {
                let mut coded = Vec::new();
                datagram_encode(&vec![0u8; payload], &mut coded);
                coded.len()
            });
        }
    }

    #[test]
    fn a_datagram_round_trips_split_anywhere() {
        let payload: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let mut coded = Vec::new();
        datagram_encode(&payload, &mut coded);
        for cut in [1, 2, 3, 5, 10, 100] {
            let cut = cut.min(coded.len() - 1);
            assert_eq!(datagram_split(&coded[..cut]), None, "cut at {cut}");
        }
        let (used, back) = datagram_split(&coded).expect("whole");
        assert_eq!((used, back), (coded.len(), payload.as_slice()));
    }

    #[test]
    fn capsules_this_lane_does_not_read_are_skipped_not_refused() {
        let mut buf = Vec::new();
        buf.push(0x17);
        quic_varint(&mut buf, 3);
        buf.extend_from_slice(b"abc");
        buf.push(0x00);
        quic_varint(&mut buf, 3);
        buf.push(0x02);
        buf.extend_from_slice(b"xy");
        let mut good = Vec::new();
        datagram_encode(b"ok", &mut good);
        buf.extend_from_slice(&good);
        let (used, back) = datagram_split(&buf).expect("skips to the datagram");
        assert_eq!((used, back.len()), (buf.len(), 2));
        assert_eq!(back, b"ok");
    }
}
