//! MASQUE CONNECT-IP (RFC 9484) over CONNECT-UDP's two carriers: one `connect-ip` request with `capsule-protocol: ?1`, then `ADDRESS_ASSIGN` 1, `ADDRESS_REQUEST` 2 and `ROUTE_ADVERTISEMENT` 3 capsules decide what the stream carries, IP packets for every destination riding the type-0 DATAGRAM capsule with a zero context byte — arithmetic only, no socket, clock or heap.

use super::frames::{quic_read, quic_varint, quic_varint_len};
use super::hpack::{integer, integer_into};

/// The default URI template, RFC 9484 §3.2, up to the host the tunnel reaches.
const PREFIX: &[u8] = b"/.well-known/masque/ip/";
/// The scheme the pass is presented with, the shape the edge answers on both carriers.
const BEARER: &[u8] = b"Bearer ";

/// The capsule type numbers, RFC 9484 §4.
const ADDRESS_ASSIGN: u64 = 1;
const ADDRESS_REQUEST: u64 = 2;
const ROUTE_ADVERTISEMENT: u64 = 3;

/// What a proxy grants when it refuses an address request (RFC 9484 §4.2): the all-zeros address at its full prefix length, rather than an error.
const REFUSED_V4: [u8; 4] = [0, 0, 0, 0];
const REFUSED_V6: [u8; 16] = [0; 16];

/// One address a proxy granted, with the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assigned {
    /// Which request this answers, so an answer can name it back.
    pub request_id: u64,
    /// Version 4 or 6, the address and the prefix length — the RFC's own order, which is also an `ADDRESS_REQUEST`'s write order.
    pub version: u8,
    pub address: [u8; 16],
    pub prefix: u8,
}

impl Assigned {
    /// Whether this is the proxy refusing, which the RFC names as the all-zeros prefix at full length rather than as an error.
    #[must_use]
    pub fn refused(&self) -> bool {
        match self.version {
            4 => self.prefix == 32 && self.address[..4] == REFUSED_V4,
            6 => self.prefix == 128 && self.address == REFUSED_V6,
            _ => true,
        }
    }

    /// The granted address, truncated to the width its version names.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.address[..self.width()]
    }

    /// The bytes one address of this version occupies on the wire.
    #[must_use]
    pub const fn width(&self) -> usize {
        if self.version == 4 {
            4
        } else {
            16
        }
    }
}

/// One route a proxy advertised (RFC 9484 §4.3): the first and last address it carries and the IP protocol that range is limited to, where zero carries every protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub first: [u8; 16],
    pub last: [u8; 16],
    pub version: u8,
    pub protocol: u8,
}

impl Route {
    #[must_use]
    pub const fn width(&self) -> usize {
        if self.version == 4 {
            4
        } else {
            16
        }
    }
}

/// The default URI template's path for one target (RFC 9484 §3.2): only a colon is encoded, since of a DNS name, an IPv4 literal and an IPv6 literal only the last uses one.
pub fn ip_path(host: &str, port: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(PREFIX);
    for byte in host.bytes() {
        if byte == b':' {
            out.extend_from_slice(b"%3A");
        } else {
            out.push(byte);
        }
    }
    out.push(b'/');
    push_port(out, port);
    out.push(b'/');
}

/// The path's length, which a field line names before writing it: HTTP/2 and QPACK write a field's length ahead of its bytes, so staging the path first would spend a buffer per connection.
fn ip_path_len(host: &str, port: u16) -> usize {
    PREFIX.len()
        + host.len()
        + 2 * host.bytes().filter(|byte| *byte == b':').count()
        + 1
        + decimal_len(port)
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

/// One HTTP/2 literal field line: the new-name pattern, the name with a 7-bit prefix, then the value the same way.
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

/// The `:path` field line for one target, in either codec's own spelling: its length is known before the path is written, so the path never sits in a buffer of its own.
fn path_field(out: &mut Vec<u8>, host: &str, port: u16, qpack: bool) {
    if qpack {
        out.push(0x20);
        integer_into(out, 3, 5);
    } else {
        out.push(0x00);
        integer(out, 7, 0x00, 5);
    }
    out.extend_from_slice(b":path");
    integer(out, 7, 0x00, ip_path_len(host, port));
    ip_path(host, port, out);
}

/// The authorization field line, whose value is the pass behind the scheme: one length covers both halves and the bytes follow in place, because a `Bearer ` and a token are never more than a concatenation.
fn bearer_field(out: &mut Vec<u8>, bearer: &str, qpack: bool) {
    if qpack {
        out.push(0x20);
        integer_into(out, 3, b"proxy-authorization".len());
    } else {
        out.push(0x00);
        integer(out, 7, 0x00, b"proxy-authorization".len());
    }
    out.extend_from_slice(b"proxy-authorization");
    integer(out, 7, 0x00, BEARER.len() + bearer.len());
    out.extend_from_slice(BEARER);
    out.extend_from_slice(bearer.as_bytes());
}

/// One CONNECT-IP request over HTTP/2 (RFC 9484 §3.2): the `:protocol` naming the IP proxy rather than the UDP one, the template, the pass, and the capsule protocol the rest of the stream is written in.
pub fn connect_ip(edge_authority: &str, host: &str, port: u16, bearer: &str, out: &mut Vec<u8>) {
    field(out, b":method", b"CONNECT");
    field(out, b":protocol", b"connect-ip");
    field(out, b":scheme", b"https");
    field(out, b":authority", edge_authority.as_bytes());
    path_field(out, host, port, false);
    bearer_field(out, bearer, false);
    field(out, b"capsule-protocol", b"?1");
}

/// The same request as a QPACK block, which is how it rides HTTP/3.
pub fn connect_ip_qpack(
    edge_authority: &str,
    host: &str,
    port: u16,
    bearer: &str,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&[0x00, 0x00]);
    qpack_field(out, b":method", b"CONNECT");
    qpack_field(out, b":protocol", b"connect-ip");
    qpack_field(out, b":scheme", b"https");
    qpack_field(out, b":authority", edge_authority.as_bytes());
    path_field(out, host, port, true);
    bearer_field(out, bearer, true);
    qpack_field(out, b"capsule-protocol", b"?1");
}

/// One `ADDRESS_REQUEST` capsule (RFC 9484 §4.1): a request id that must not be zero, then the address wanted; a client with no preference asks for `0.0.0.0` or `::` and the proxy answers with what it picks.
pub fn address_request(id: u64, version: u8, address: &[u8], out: &mut Vec<u8>) {
    quic_varint(out, ADDRESS_REQUEST);
    quic_varint(out, (quic_varint_len(id) + 1 + address.len() + 1) as u64);
    quic_varint(out, id);
    out.push(version);
    out.extend_from_slice(address);
    out.push((address.len() as u8) * 8);
}

/// Bytes one DATAGRAM capsule takes for an IP packet of this length, so a caller frames it before building it: HTTP/3 writes its frame length ahead, and the capsule's own varint sits inside it.
pub fn packet_len(packet: usize) -> usize {
    1 + quic_varint_len(1 + packet as u64) + 1 + packet
}

/// One IP packet as one DATAGRAM capsule: type zero, the context byte zero, then the packet unchanged.
pub fn packet_encode(packet: &[u8], out: &mut Vec<u8>) {
    out.push(0x00);
    quic_varint(out, 1 + packet.len() as u64);
    out.push(0x00);
    out.extend_from_slice(packet);
}

/// What one capsule was, as far as this lane reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capsule<'a> {
    /// A DATAGRAM capsule with context zero, whose packet follows the context.
    Datagram(&'a [u8]),
    /// The proxy answering an address request, or refusing it.
    AddressAssign(&'a [u8]),
    /// A proxy asking the client for an address.
    AddressRequest(&'a [u8]),
    /// The proxy naming the ranges it will carry.
    RouteAdvert(&'a [u8]),
    /// A capsule number this lane does not read.
    Other(u64),
}

/// The first complete capsule in a stream buffer: bytes consumed and what it was, or `None` while the capsule is not whole; a capsule this lane does not read is *answered* and stepping over it is the caller's, because an advertised extension must not cost the tunnel its packets.
#[must_use]
pub fn capsule_split(buf: &[u8]) -> Option<(usize, Capsule<'_>)> {
    let mut at = 0usize;
    if at >= buf.len() {
        return None;
    }
    let kind = quic_read(buf, &mut at)?;
    let length = quic_read(buf, &mut at)? as usize;
    let end = at.checked_add(length)?;
    let value = buf.get(at..end)?;
    Some((
        end,
        match kind {
            0 => {
                let mut at_context = 0usize;
                if quic_read(value, &mut at_context) == Some(0) {
                    Capsule::Datagram(&value[at_context..])
                } else {
                    Capsule::Other(0)
                }
            }
            ADDRESS_ASSIGN => Capsule::AddressAssign(value),
            ADDRESS_REQUEST => Capsule::AddressRequest(value),
            ROUTE_ADVERTISEMENT => Capsule::RouteAdvert(value),
            other => Capsule::Other(other),
        },
    ))
}

/// The addresses one `ADDRESS_ASSIGN` capsule grants (RFC 9484 §4.2): host bits above the prefix are *not* required to be zero — a proxy hands out a `/64` and `2001:db8::1` inside it is the tunnel's address — while a request must zero them, which this lane's all-zeros-at-full-length request does by construction.
pub fn address_assign(body: &[u8], into: &mut Vec<Assigned>) -> Option<()> {
    into.clear();
    let mut at = 0usize;
    while at < body.len() {
        let request_id = quic_read(body, &mut at)?;
        let version = *body.get(at)?;
        at += 1;
        let width = match version {
            4 => 4usize,
            6 => 16,
            _ => return None,
        };
        let mut address = [0u8; 16];
        address[..width].copy_from_slice(body.get(at..at + width)?);
        at += width;
        let prefix = *body.get(at)?;
        at += 1;
        if usize::from(prefix) > width * 8 {
            return None;
        }
        into.push(Assigned {
            request_id,
            version,
            address,
            prefix,
        });
    }
    Some(())
}

/// The routes one `ROUTE_ADVERTISEMENT` capsule names, RFC 9484 §4.3.
pub fn route_advert(body: &[u8], into: &mut Vec<Route>) -> Option<()> {
    into.clear();
    let mut at = 0usize;
    while at < body.len() {
        let version = *body.get(at)?;
        at += 1;
        let width = match version {
            4 => 4usize,
            6 => 16,
            _ => return None,
        };
        let mut first = [0u8; 16];
        let mut last = [0u8; 16];
        first[..width].copy_from_slice(body.get(at..at + width)?);
        at += width;
        last[..width].copy_from_slice(body.get(at..at + width)?);
        at += width;
        let protocol = *body.get(at)?;
        at += 1;
        into.push(Route {
            first,
            last,
            version,
            protocol,
        });
    }
    Some(())
}
/// One IPv4 header read in place: this lane walks only the fields it needs, so a header it cannot walk is refused rather than repaired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Head {
    /// Total length, which includes this header.
    pub length: u16,
    /// The protocol this packet carries, where 17 is UDP.
    pub protocol: u8,
    /// Time to live, which a hop decrements and a zero refuses.
    pub hop: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

/// One IPv6 header, read in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Head {
    /// Payload length, which excludes this header.
    pub length: u16,
    /// The next header this packet carries, where 17 is UDP.
    pub next_header: u8,
    pub hop: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

/// The fixed header sizes, RFC 791 §3 and RFC 8200 §3.
pub const IPV4_HEADER: usize = 20;
pub const IPV6_HEADER: usize = 40;
/// The UDP header size, RFC 768.
pub const UDP_HEADER: usize = 8;
/// The protocol number UDP carries in both versions.
pub const PROTOCOL_UDP: u8 = 17;
/// The hop limit this lane writes, a reasonable default rather than a value a proxy asks for.
pub const HOP_LIMIT: u8 = 64;
/// The largest datagram this lane will build: a UDP length field is sixteen bits, so a longer one cannot be named in a header.
pub const MAX_DATAGRAM: usize = u16::MAX as usize - UDP_HEADER;

/// Walks an IPv4 header, or `None` when it is not one: the first nibble is the version, the second the header length in 32-bit words, and a header needing options or a total length past what arrived is refused because the payload would be read out of something else.
pub fn ipv4_head(packet: &[u8]) -> Option<(Ipv4Head, &[u8])> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header = usize::from(first & 0x0f) * 4;
    if header != IPV4_HEADER {
        return None;
    }
    let length = u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]);
    let total = usize::from(length);
    if total < header || total > packet.len() {
        return None;
    }
    let mut source = [0u8; 4];
    let mut destination = [0u8; 4];
    source.copy_from_slice(packet.get(12..16)?);
    destination.copy_from_slice(packet.get(16..20)?);
    Some((
        Ipv4Head {
            length,
            protocol: *packet.get(9)?,
            hop: *packet.get(8)?,
            source,
            destination,
        },
        &packet[header..total],
    ))
}

/// Walks an IPv6 header, or `None` when it is not one.
pub fn ipv6_head(packet: &[u8]) -> Option<(Ipv6Head, &[u8])> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let length = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]);
    if IPV6_HEADER + usize::from(length) > packet.len() {
        return None;
    }
    let mut source = [0u8; 16];
    let mut destination = [0u8; 16];
    source.copy_from_slice(packet.get(8..24)?);
    destination.copy_from_slice(packet.get(24..40)?);
    Some((
        Ipv6Head {
            length,
            next_header: *packet.get(6)?,
            hop: *packet.get(7)?,
            source,
            destination,
        },
        &packet[IPV6_HEADER..IPV6_HEADER + usize::from(length)],
    ))
}

/// One UDP header and its payload, read in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHead {
    pub source_port: u16,
    pub destination_port: u16,
    /// The UDP length, which includes this header and must match the body.
    pub length: u16,
}

/// Walks a UDP header, or `None` when it is not one: the length field names the header plus the payload, so a body that disagrees with it is refused.
pub fn udp_head(body: &[u8]) -> Option<(UdpHead, &[u8])> {
    let source_port = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
    let destination_port = u16::from_be_bytes([*body.get(2)?, *body.get(3)?]);
    let length = u16::from_be_bytes([*body.get(4)?, *body.get(5)?]);
    if usize::from(length) != body.len() {
        return None;
    }
    Some((
        UdpHead {
            source_port,
            destination_port,
            length,
        },
        body.get(UDP_HEADER..)?,
    ))
}

/// The one's-complement sum of bytes read as 16-bit big-endian words, the last zero-padded on an odd run, and eight bytes are one add rather than four: `0xffff = 2^16 - 1` makes `2^16` and `2^32` congruent to 1 mod `0xffff`, so a lane folded as `(hi32 + lo32)` lands in the same residue class as the four words it holds — witnessed by `the_word_fold_is_the_byte_at_a_time_sum` and `word_sum_is_the_word_at_a_time_sum_at_every_tail`.
fn word_sum(bytes: &[u8]) -> u32 {
    let (lanes, rem) = bytes.as_chunks::<8>();
    let mut acc = 0u64;
    for lane in lanes {
        let word = u64::from_be_bytes(*lane);
        acc += (word >> 32) + (word & 0xffff_ffff);
    }
    // The run left is shorter than a lane: every group taken here is even so pairs still begin on an even byte, and a lone trailing byte is the high half of a zero-padded word.
    let mut at = 0usize;
    if rem.len() - at >= 4 {
        acc += u64::from(u32::from_be_bytes(
            rem[at..at + 4].try_into().expect("four bytes"),
        ));
        at += 4;
    }
    if rem.len() - at >= 2 {
        acc += u64::from(u16::from_be_bytes(
            rem[at..at + 2].try_into().expect("two bytes"),
        ));
        at += 2;
    }
    if rem.len() - at == 1 {
        acc += u64::from(rem[at]) << 8;
    }
    // Fold the 64-bit residue into a 32-bit one (`2^32` is again congruent to `1`), then drain the carries twice: two steps bound any run past `0xffff` and callers fold once more.
    let mut sum = (acc >> 32) + (acc & 0xffff_ffff);
    sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    sum as u32
}

/// The fold a checksum ends with: add the halves until nothing is left to carry, at most two steps for a 32-bit accumulator.
fn fold(sum: u32) -> u16 {
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The one's complement of a byte run, which is what a checksum field holds.
pub fn checksum(bytes: &[u8]) -> u16 {
    !fold(word_sum(bytes))
}

/// The IPv4 header checksum of a header this lane builds: the complement of the sum over the header itself, which a receiver adds its own copy of the header into to read all ones.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    !fold(word_sum(header))
}

/// The pseudo-header a UDP checksum covers (RFC 768, RFC 8200 §8.1) summed without writing it: a one's-complement sum is position-independent, so the addresses contribute their word runs, the length its value (sixteen bits by construction, IPv6's wider field adding an unchanged zero word) and the protocol a lone word whose high half is zero — the same words the materialised header held, so both versions agree with no branch.
fn pseudo_sum(source: &[u8], destination: &[u8], payload: usize) -> u32 {
    let length = (UDP_HEADER + payload) as u32;
    let sum = word_sum(source) + word_sum(destination) + length + u32::from(PROTOCOL_UDP);
    (sum & 0xffff) + (sum >> 16)
}

/// The UDP checksum of a datagram this lane builds: header fields, pseudo-header and payload summed with the checksum field read as zero, complemented — and a zero answer is never written, because a receiver reads it as "not computed", so the protocol's illegal value goes instead and verifies at either version.
pub fn udp_checksum(
    source: &[u8],
    destination: &[u8],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> u16 {
    let mut sum =
        u32::from(source_port) + u32::from(destination_port) + (UDP_HEADER + payload.len()) as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum += pseudo_sum(source, destination, payload.len());
    sum = (sum & 0xffff) + (sum >> 16);
    sum += word_sum(payload);
    let answer = !fold(sum);
    if answer == 0 {
        0xffff
    } else {
        answer
    }
}

/// Whether an incoming datagram's checksum verifies: pseudo-header, the whole UDP header including its checksum field, and payload must sum to all ones; over IPv4 a zero field means "not computed" and is accepted, over IPv6 the field is mandatory and a zero is refused.
fn checksum_holds(
    source: &[u8],
    destination: &[u8],
    datagram: &[u8],
    optional: bool,
) -> Option<bool> {
    let field = u16::from_be_bytes([*datagram.get(6)?, *datagram.get(7)?]);
    if field == 0 && optional {
        return Some(true);
    }
    let mut sum = pseudo_sum(source, destination, datagram.len() - UDP_HEADER);
    sum = (sum & 0xffff) + (sum >> 16);
    sum += word_sum(datagram);
    Some(fold(sum) == 0xffff)
}

/// The headers one outgoing UDP datagram needs, in the order they are written: a reply shape — source the assigned tunnel address, destination the target, payload the caller's bytes — so everything else is derived and this is all a caller names.
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    /// The tunnel's own address, as the proxy assigned it.
    pub source: &'a [u8],
    pub destination: &'a [u8],
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

/// Whether a datagram of this payload can be named at all: a UDP length field is sixteen bits, so one past it cannot be written into a header.
#[must_use]
pub fn datagram_fits(payload: usize) -> bool {
    payload <= MAX_DATAGRAM
}

/// Writes one UDP datagram into `out` — IP header, UDP header, payload — taking the version from the tunnel address's width, so a v4-assigned lane writes v4 packets and a v6-assigned one v6, never mixed.
pub fn udp_datagram(datagram: &UdpDatagram<'_>, out: &mut Vec<u8>) -> bool {
    if !datagram_fits(datagram.payload.len()) {
        return false;
    }
    let payload = UDP_HEADER + datagram.payload.len();
    if datagram.source.len() == 4 {
        let mut header = [0u8; IPV4_HEADER];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&((IPV4_HEADER + payload) as u16).to_be_bytes());
        header[8] = HOP_LIMIT;
        header[9] = PROTOCOL_UDP;
        header[12..16].copy_from_slice(datagram.source);
        header[16..20].copy_from_slice(datagram.destination);
        let sum = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(&header);
    } else {
        let mut header = [0u8; IPV6_HEADER];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        header[6] = PROTOCOL_UDP;
        header[7] = HOP_LIMIT;
        header[8..24].copy_from_slice(datagram.source);
        header[24..40].copy_from_slice(datagram.destination);
        out.extend_from_slice(&header);
    }
    let sum = udp_checksum(
        datagram.source,
        datagram.destination,
        datagram.source_port,
        datagram.destination_port,
        datagram.payload,
    );
    let mut udp = [0u8; UDP_HEADER];
    udp[0..2].copy_from_slice(&datagram.source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&datagram.destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    out.extend_from_slice(&udp);
    out.extend_from_slice(datagram.payload);
    true
}

/// One UDP datagram read out of an IP packet with both of its ends borrowed from the packet: the header fields sit at fixed offsets, so walking a datagram costs no copy at all.
#[derive(Debug, Clone, Copy)]
pub struct Datagram<'a> {
    pub source: &'a [u8],
    pub destination: &'a [u8],
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
    /// Whether the packet's checksum held, which an IPv4 peer is allowed to have left out and an IPv6 peer is not.
    pub verified: bool,
}

/// Walks a UDP datagram out of an IP packet, or `None` when the packet is not a UDP datagram this lane can read.
pub fn udp_from_packet(packet: &[u8]) -> Option<Datagram<'_>> {
    let (source, destination, body, optional) = match packet.first()? >> 4 {
        4 => {
            let (head, body) = ipv4_head(packet)?;
            if head.protocol != PROTOCOL_UDP {
                return None;
            }
            (&packet[12..16], &packet[16..20], body, true)
        }
        6 => {
            let (head, body) = ipv6_head(packet)?;
            if head.next_header != PROTOCOL_UDP {
                return None;
            }
            (&packet[8..24], &packet[24..40], body, false)
        }
        _ => return None,
    };
    let (udp, payload) = udp_head(body)?;
    let verified = checksum_holds(source, destination, body, optional)?;
    Some(Datagram {
        source,
        destination,
        source_port: udp.source_port,
        destination_port: udp.destination_port,
        payload,
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A datagram this lane builds, or the panic a bool answer owes.
    trait DatagramBuilt {
        fn expect_datagram(self);
        fn expect_refused(self);
    }
    impl DatagramBuilt for bool {
        fn expect_datagram(self) {
            assert!(self, "the datagram was built");
        }
        fn expect_refused(self) {
            assert!(!self, "the datagram was refused");
        }
    }

    /// One assignment, byte for byte the way a proxy writes it: request id, a version, an address, a prefix length.
    fn assign(request_id: u64, version: u8, address: &[u8], prefix: u8) -> Option<Vec<Assigned>> {
        let mut body = Vec::new();
        quic_varint(&mut body, request_id);
        body.push(version);
        body.extend_from_slice(address);
        body.push(prefix);
        let mut into = Vec::new();
        address_assign(&body, &mut into).map(|()| into)
    }

    /// One request, byte for byte the way a client writes it.
    fn request(id: u64, version: u8, address: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        address_request(id, version, address, &mut out);
        out
    }

    const V4: [u8; 4] = [0, 0, 0, 0];
    const V6: [u8; 16] = [0; 16];

    /// The all-zeros prefix at full length is how a proxy refuses, and the reader has to say so rather than hand the lane a tunnel address of zero.
    #[test]
    fn a_refused_assignment_is_named_and_a_granted_one_is_not() {
        assert!(assign(1, 4, &V4, 32).expect("a refusal parses")[0].refused());
        assert!(assign(2, 6, &V6, 128).expect("a refusal parses")[0].refused());
        let granted = assign(1, 4, &[192, 0, 2, 7], 32).expect("a grant parses");
        assert!(!granted[0].refused(), "a real address is a grant");
        assert_eq!(granted[0].bytes(), &[192, 0, 2, 7]);
        assert_eq!(
            granted[0].request_id, 1,
            "it answers the request it was asked with"
        );
    }

    /// Host bits above an assignment's prefix are the tunnel's own address, so they read as granted: a proxy hands out a `/64` with an address inside it, and refusing that would leave the lane with no address; a prefix past the address is still refused at either version.
    #[test]
    fn the_host_bits_of_an_assignment_are_the_tunnels_own_address() {
        let granted = assign(
            1,
            6,
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        )
        .expect("a /64 grant parses");
        assert_eq!(granted.len(), 1);
        assert!(
            !granted[0].refused(),
            "an address inside its prefix is a grant"
        );
        assert_eq!(granted[0].prefix, 64);
        assert_eq!(granted[0].bytes().last(), Some(&1));
        assert!(assign(1, 4, &[10, 0, 0, 1], 33).is_none(), "33 bits of v4");
        assert!(
            assign(
                1,
                6,
                &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                129
            )
            .is_none(),
            "129 bits of v6"
        );
        assert!(
            assign(1, 5, &[0; 16], 64).is_none(),
            "version 5 does not exist"
        );
    }

    /// This lane's request carries zeroed host bits by construction — the all-zeros address at full length means "any address you like" — and is written in the shape an assignment is read in, so both directions agree without a second codec.
    #[test]
    fn a_request_is_the_shape_an_assignment_is_read_in() {
        assert_eq!(request(1, 4, &V4), [2, 7, 1, 4, 0, 0, 0, 0, 32]);
        let mut wide = vec![2, 19, 2, 6];
        wide.extend_from_slice(&V6);
        wide.push(128);
        assert_eq!(request(2, 6, &V6), wide);
    }

    /// The routes a proxy advertises read back as first, last and protocol, and a protocol of zero means every protocol.
    #[test]
    fn an_advertised_route_names_its_range_and_its_protocol() {
        let mut body = Vec::new();
        body.push(4);
        body.extend_from_slice(&[192, 0, 2, 0]);
        body.extend_from_slice(&[192, 0, 2, 255]);
        body.push(0);
        let mut routes = Vec::new();
        route_advert(&body, &mut routes).expect("parses");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].first[..4], [192, 0, 2, 0]);
        assert_eq!(routes[0].last[..4], [192, 0, 2, 255]);
        assert_eq!(routes[0].protocol, 0, "zero is every protocol");
        assert_eq!(
            route_advert(&[5, 0, 0], &mut routes),
            None,
            "a version with no address width is refused"
        );
    }

    /// A capsule this lane does not read is answered whole and stepping over it is the caller's, so a proxy advertising an extension must not cost the tunnel its packets.
    #[test]
    fn a_capsule_this_lane_does_not_read_is_answered_whole() {
        let mut buf = Vec::new();
        quic_varint(&mut buf, 0x1c);
        quic_varint(&mut buf, 3);
        buf.extend_from_slice(b"abc");
        packet_encode(b"\x45\x00", &mut buf);
        let (used, capsule) = capsule_split(&buf).expect("a capsule");
        assert_eq!(used, 5, "the first capsule is the answer");
        assert_eq!(capsule, Capsule::Other(0x1c));
        let (used, capsule) = capsule_split(&buf[used..]).expect("then the datagram");
        // The context byte is stripped, so what the caller reads is the packet.
        assert_eq!(capsule, Capsule::Datagram(&buf[8..]));
        assert_eq!(used, buf.len() - 5);
        assert_eq!(capsule_split(&buf[..2]), None, "half a capsule");
        assert_eq!(capsule_split(b""), None);
    }

    /// The IP/UDP header walk reads a datagram this lane builds without a copy, at both versions, and verifies what it read.
    #[test]
    fn a_datagram_built_is_a_datagram_walked() {
        let v6 = |head: &[u8]| {
            let mut wide = vec![0u8; 16];
            wide[..head.len()].copy_from_slice(head);
            wide
        };
        for (source, destination) in [
            (vec![192, 0, 2, 7], vec![203, 0, 113, 9]),
            (v6(&[0x20, 1]), v6(&[0x20, 2])),
        ] {
            let mut packet = Vec::new();
            udp_datagram(
                &UdpDatagram {
                    source: &source,
                    destination: &destination,
                    source_port: 1_000,
                    destination_port: 2_000,
                    payload: b"hello ip",
                },
                &mut packet,
            )
            .expect_datagram();
            let read = udp_from_packet(&packet).expect("walks");
            assert_eq!(read.source, source.as_slice());
            assert_eq!(read.destination, destination.as_slice());
            assert_eq!(read.source_port, 1_000);
            assert_eq!(read.destination_port, 2_000);
            assert_eq!(read.payload, b"hello ip");
            assert!(read.verified, "and its checksum holds");
        }
    }

    /// A datagram past the length field is refused rather than truncated.
    #[test]
    fn a_datagram_past_the_length_field_is_refused() {
        assert!(!datagram_fits(MAX_DATAGRAM + 1));
        let long = vec![0u8; MAX_DATAGRAM + 1];
        let mut out = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[10, 0, 0, 1],
                destination: &[10, 0, 0, 2],
                source_port: 1,
                destination_port: 2,
                payload: &long,
            },
            &mut out,
        )
        .expect_refused();
        assert!(out.is_empty(), "and nothing was written");
    }

    /// The IPv4 header checksum is the complement of the sum over the header, which a receiver adds its own copy of the header into to read all ones.
    #[test]
    fn an_ipv4_header_checksum_verifies_against_itself() {
        let mut header = [0u8; IPV4_HEADER];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&28u16.to_be_bytes());
        header[8] = HOP_LIMIT;
        header[9] = PROTOCOL_UDP;
        header[12..16].copy_from_slice(&[192, 0, 2, 7]);
        header[16..20].copy_from_slice(&[203, 0, 113, 9]);
        let written = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&written.to_be_bytes());
        assert_eq!(fold(word_sum(&header)), 0xffff);
    }

    /// The word-at-a-time fold is the byte-at-a-time sum it replaces, at every length that has a boundary inside it and past the point an accumulator wraps.
    #[test]
    fn the_word_fold_is_the_byte_at_a_time_sum() {
        // The definition: one's complement, complemented at the end.
        fn oracle(bytes: &[u8]) -> u16 {
            let mut sum = 0u32;
            let mut high = true;
            for byte in bytes {
                sum = sum.wrapping_add(if high {
                    u32::from(*byte) << 8
                } else {
                    u32::from(*byte)
                });
                high = !high;
            }
            let mut total = sum;
            while total >> 16 != 0 {
                total = (total & 0xffff) + (total >> 16);
            }
            !total as u16
        }
        for len in 0..=40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            assert_eq!(checksum(&bytes), oracle(&bytes), "len {len}");
        }
        let wide: Vec<u8> = (0..=200usize)
            .map(|i| (i as u8).wrapping_mul(101))
            .collect();
        assert_eq!(checksum(&wide), oracle(&wide));
        // The block fold must agree with the byte sum across a block boundary: one fold per 8192 words loses no carry, so sweep both sides of 16 KiB and several blocks deep, on even and odd runs.
        for len in [
            16_382, 16_383, 16_384, 16_385, 16_386, 32_767, 32_768, 32_769, 49_152, 49_153,
        ] {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect();
            assert_eq!(checksum(&bytes), oracle(&bytes), "block boundary len {len}");
        }
    }

    /// The eight-byte lane is the two-byte word walk it replaces, folded to the same residue at every length through several lanes and every remainder modulo eight — the sweep that catches a lost tail byte, a misaligned pair or a carry the lane swallowed.
    #[test]
    fn word_sum_is_the_word_at_a_time_sum_at_every_tail() {
        fn by_words(bytes: &[u8]) -> u32 {
            let (pairs, odd) = bytes.as_chunks::<2>();
            let mut sum = 0u32;
            for pair in pairs {
                sum += u32::from(u16::from_be_bytes(*pair));
            }
            if let [last] = odd {
                sum += u32::from(*last) << 8;
            }
            sum
        }
        let residue = |mut sum: u32| {
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum
        };
        for len in 0..=260usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect();
            assert_eq!(
                residue(word_sum(&bytes)),
                residue(by_words(&bytes)),
                "len {len}"
            );
        }
        // All-ones lanes stress the carry a folded lane could hide: eight `ff` bytes fold to `0xfffe`, and a run of them must still agree with words.
        for len in [8usize, 16, 24, 1000] {
            let bytes = vec![0xffu8; len];
            assert_eq!(
                residue(word_sum(&bytes)),
                residue(by_words(&bytes)),
                "all-ones len {len}"
            );
        }
    }

    /// The closed-form pseudo-header sum is the residue that materialising the twelve- or forty-byte header produced, at every address width and datagram length the codec can name; the comparison is at the canonical fold, since `word_sum` lands its residue in a lane as wide as it likes and only the folded number defines a checksum.
    #[test]
    fn the_pseudo_sum_is_the_materialised_header_words() {
        let materialised = |source: &[u8], destination: &[u8], payload: usize| -> u32 {
            let length = (UDP_HEADER + payload) as u32;
            if source.len() == 4 {
                let mut header = [0u8; 12];
                header[..4].copy_from_slice(source);
                header[4..8].copy_from_slice(destination);
                header[9] = PROTOCOL_UDP;
                header[10..12].copy_from_slice(&(length as u16).to_be_bytes());
                word_sum(&header)
            } else {
                let mut header = [0u8; 40];
                header[..16].copy_from_slice(source);
                header[16..32].copy_from_slice(destination);
                header[32..36].copy_from_slice(&length.to_be_bytes());
                header[39] = PROTOCOL_UDP;
                word_sum(&header)
            }
        };
        let v4 = || ([198u8, 51, 100, 7], [203u8, 0, 113, 9]);
        let v6 = || {
            (
                [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            )
        };
        for payload in [
            0,
            1,
            2,
            3,
            7,
            8,
            511,
            512,
            1000,
            MAX_DATAGRAM - 1,
            MAX_DATAGRAM,
        ] {
            let (src, dst) = v4();
            assert_eq!(
                fold(pseudo_sum(&src, &dst, payload)),
                fold(materialised(&src, &dst, payload)),
                "v4 payload {payload}"
            );
            let (src, dst) = v6();
            assert_eq!(
                fold(pseudo_sum(&src, &dst, payload)),
                fold(materialised(&src, &dst, payload)),
                "v6 payload {payload}"
            );
        }
    }

    /// A receiver of a datagram this lane builds sums the pseudo-header, the UDP header with the checksum in it, and the payload, and gets all ones — and a zero answer never goes on the wire.
    #[test]
    fn a_written_checksum_verifies_at_both_versions() {
        for (source, destination) in [
            (vec![192u8, 0, 2, 7], vec![203, 0, 113, 9]),
            (
                vec![0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                vec![0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            ),
        ] {
            let payload = b"a longer payload that spans words";
            let written = udp_checksum(&source, &destination, 1_000, 2_000, payload);
            assert_ne!(written, 0, "a zero answer is not written");
            let mut datagram = [0u8; UDP_HEADER];
            datagram[0..2].copy_from_slice(&1_000u16.to_be_bytes());
            datagram[2..4].copy_from_slice(&2_000u16.to_be_bytes());
            datagram[4..6].copy_from_slice(&((UDP_HEADER + payload.len()) as u16).to_be_bytes());
            datagram[6..8].copy_from_slice(&written.to_be_bytes());
            let mut sum = pseudo_sum(&source, &destination, payload.len());
            sum = (sum & 0xffff) + (sum >> 16);
            sum += word_sum(&datagram);
            sum = (sum & 0xffff) + (sum >> 16);
            sum += word_sum(payload);
            assert_eq!(fold(sum), 0xffff, "the written checksum verifies");
        }
    }

    /// A tampered datagram is refused rather than relayed, and a peer that left its checksum out is accepted wherever the protocol allows it.
    #[test]
    fn a_tampered_datagram_is_refused_and_an_unchecked_ipv4_one_is_not() {
        let mut packet = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[192, 0, 2, 7],
                destination: &[203, 0, 113, 9],
                source_port: 1_000,
                destination_port: 2_000,
                payload: b"hello ip",
            },
            &mut packet,
        )
        .expect_datagram();
        let flipped = packet.len() - 1;
        packet[flipped] ^= 0x01;
        assert!(
            !udp_from_packet(&packet).expect("still parses").verified,
            "a flipped byte must not verify"
        );
        packet[flipped] ^= 0x01;
        packet[26..28].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            udp_from_packet(&packet).expect("parses").verified,
            "an IPv4 peer may leave the checksum out"
        );

        let mut v6 = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                destination: &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                source_port: 53,
                destination_port: 53,
                payload: b"\x12\x34",
            },
            &mut v6,
        )
        .expect_datagram();
        v6[46..48].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            !udp_from_packet(&v6).expect("parses").verified,
            "an IPv6 checksum is not optional"
        );
    }

    /// A packet that is not UDP, or not a packet, is refused.
    #[test]
    fn a_packet_that_is_not_udp_is_refused() {
        let mut packet = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[192, 0, 2, 7],
                destination: &[203, 0, 113, 9],
                source_port: 1,
                destination_port: 2,
                payload: b"hi",
            },
            &mut packet,
        )
        .expect_datagram();
        packet[9] = 6;
        assert!(
            udp_from_packet(&packet).is_none(),
            "a TCP packet is not a datagram"
        );
        assert!(udp_from_packet(b"").is_none());
        assert!(
            udp_from_packet(b"\x45").is_none(),
            "a header with no header"
        );
    }

    /// The two carriers write the same request: a HPACK block and a QPACK block whose fields a reader walking literals either way sees as one, so a carrier is a spelling and not a second codec.
    #[test]
    fn both_carriers_carry_the_same_connect_ip_request() {
        let mut h2 = Vec::new();
        connect_ip("edge.example:2499", "example.com", 443, "the-pass", &mut h2);
        let mut q3 = Vec::new();
        connect_ip_qpack("edge.example:2499", "example.com", 443, "the-pass", &mut q3);
        let text = String::from_utf8_lossy(&h2);
        for field in [
            "CONNECT",
            "connect-ip",
            "https",
            "edge.example:2499",
            "/.well-known/masque/ip/example.com/443/",
            "Bearer the-pass",
            "capsule-protocol",
            "?1",
        ] {
            assert!(text.contains(field), "h2 is missing {field}");
        }
        let text = String::from_utf8_lossy(&q3);
        for field in [
            "CONNECT",
            "connect-ip",
            "/.well-known/masque/ip/example.com/443/",
            "Bearer the-pass",
        ] {
            assert!(text.contains(field), "qp3 is missing {field}");
        }
        assert_eq!(super::super::hpack::hpack_status(&h2), None);
        assert_eq!(
            super::super::hpack::qpack_status(&q3),
            None,
            "a request carries no status"
        );
    }
}
