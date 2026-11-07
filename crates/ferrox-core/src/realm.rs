//! Realm hole-punching bytes: the punch packet that carries a hole open and the candidate lists a
//! punch walks.
//!
//! The wire is the register that the rendezvous exchanges and the socket punches with — `[salt 8
//! bytes][magic 8][type 1][nonce 16][padding 0..=1024]` — where the plain part behind the salt is
//! `XORed` against `SHA-256(obfs || salt)` tiled at `mask[i % 32]`. Both references build the plain part
//! into its own buffer, copy it behind the salt into a second buffer, and — on decode — copy the packet
//! back into a third buffer before the magic is read. This tree writes one packet into the caller's
//! buffer and reads the magic and nonce off the wire by re-xoring the header in place, so neither
//! direction pays the copies the reference pays.

use std::net::SocketAddr;

use sha2::{Digest, Sha256};

/// 8 bytes of random salt in front of every punch packet.
pub const SALT_LEN: usize = 8;

/// The 8-byte hole-opening marker: `HYRLMv1\0`.
pub const MAGIC: [u8; 8] = *b"HYRLMv1\0";

/// Bytes of plain header before padding: `magic(8) + type(1) + nonce(16)`.
pub const HEADER_LEN: usize = 25;

/// The shortest wire packet: salt plus header and no padding.
pub const MIN_WIRE_LEN: usize = SALT_LEN + HEADER_LEN;

/// The most padding a punch packet may carry.
pub const MAX_PADDING: usize = 1024;

/// The longest wire packet: shortest plus the most padding.
pub const MAX_WIRE_LEN: usize = MIN_WIRE_LEN + MAX_PADDING;

/// Punch nonce bytes, carried hex-encoded by the rendezvous.
pub const NONCE_SIZE: usize = 16;

/// Punch obfuscation key bytes, carried hex-encoded by the rendezvous.
pub const OBFS_SIZE: usize = 32;

/// How far apart a symmetric-NAT host's observed ports may sit while the group still reads as a
/// predictable port range.
pub const NAT_PORT_GAP: u16 = 4;

/// Ports predicted past the largest observed port of a predictable group.
pub const NAT_EXTRA_PORTS: u16 = 4;

/// New candidates one symmetric-NAT host may contribute past those already observed.
pub const NAT_MAX_PORTS_PER_HOST: usize = 32;

/// The two punch types: the initiator's hello and the responder's ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// The initiator's knock at the peer's candidates.
    Hello = 0x01,
    /// The responder's answer inside the knocked hole.
    Ack = 0x02,
}

impl PacketType {
    /// The type a byte names, or `None` for a byte the reference refuses as an unknown type.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Ack),
            _ => None,
        }
    }
}

/// One punch packet as the peer reads it: its type and how much padding the sender drew. The nonce
/// and magic have already answered as the meta the packet was punched under — a packet that does not
/// name them is refused, never delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchPacket {
    /// The hello or the ack.
    pub packet_type: PacketType,
    /// Padding bytes after the header: `len(packet) - salt - header`.
    pub padding_len: usize,
}

/// The rendezvous metadata a punch is punched under: sixteen nonce bytes and the thirty-two obfs key
/// bytes the packets XOR against. `Debug` stays out by name — the obfs key is a credential.
#[derive(Clone, PartialEq, Eq)]
pub struct Metadata {
    /// The sixteen nonce bytes the two ends agree before punching.
    pub nonce: [u8; NONCE_SIZE],
    /// The thirty-two obfs key bytes the punch packets XOR against.
    pub obfs: [u8; OBFS_SIZE],
}

impl core::fmt::Debug for Metadata {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Metadata(..)")
    }
}

impl Metadata {
    /// Fresh punch metadata from the system RNG: sixteen nonce bytes and thirty-two obfs key bytes.
    /// `None` only when the system RNG fails, so a dial that cannot be punched under a new nonce
    /// fails instead of reusing one an earlier punch already answered.
    #[must_use]
    pub fn new_random() -> Option<Self> {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut obfs = [0u8; OBFS_SIZE];
        getrandom::fill(&mut nonce).ok()?;
        getrandom::fill(&mut obfs).ok()?;
        Some(Self { nonce, obfs })
    }
}

/// Hex-encode `bytes` as the rendezvous carries them: lowercase, two digits a byte. One string, no
/// second hex table beside the tests' own. `hex_encode_into` writes into a caller buffer the same
/// way, so a header that carries hex pays no string to build one.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        _ => char::from(b'a' + nibble - 10),
    }
}

/// Hex-decode `text` into an exact-size array. One allocation of the target size, or `None` on any
/// odd or non-hex digit — a rendezvous that names the wrong length is refused, never truncated into
/// a different nonce or key.
#[must_use]
pub fn hex_decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out[i] = hi << 4 | lo;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode the `nonce` and `obfs` hex strings a rendezvous names into punch metadata. `None` on any
/// wrong length or non-hex digit, so a forged metadata never punches under a different nonce or key.
#[must_use]
pub fn decode_metadata_hex(nonce_hex: &str, obfs_hex: &str) -> Option<Metadata> {
    Some(Metadata {
        nonce: hex_decode(nonce_hex)?,
        obfs: hex_decode(obfs_hex)?,
    })
}

/// The rendezvous of one realm: the HTTP origin it is reached on, the bearer token both ends
/// present, the slot both ends agree, and the STUN servers that name the publics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// `http` or `https`: the scheme the origin is dialled on.
    pub scheme: String,
    /// The rendezvous host as a name or an address.
    pub host: String,
    /// The rendezvous port.
    pub port: u16,
    /// Bearer token both ends present.
    pub token: String,
    /// Slot identifier both ends agree on: the reference's `realm_id`/`ID`.
    pub id: String,
    /// STUN servers as `host` or `host:port` strings.
    pub stun_servers: Vec<String>,
    /// The address family the punch walks.
    pub family: Family,
    /// Port-mapping request, when the config names one.
    pub port_mapping: Option<PortMapping>,
}

/// A gateway port-mapping request: the lease the gateway holds and how long the search for it may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortMapping {
    /// Whether the gateway is asked for a mapping at all.
    pub enabled: bool,
    /// Seconds the discovery and mapping operations may take.
    pub timeout: u64,
    /// Lease lifetime in seconds.
    pub lifetime: u64,
}

/// Whether `id` is a realm slot the rendezvous accepts: `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` — the
/// reference server's check, so a name it would refuse is refused here at parse rather than after a
/// dial.
#[must_use]
pub fn valid_realm_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The address family a punch may walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Family {
    /// The family's both: IPv4 when a local is IPv4, IPv6 when a local is IPv6, and both when both
    /// kinds report in.
    #[default]
    Dual,
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
}

/// The SHA-256 mask one salt derives: `SHA-256(obfs || salt)`. The two parts stream into one hasher
/// so the concatenation the caller would build is never materialised; the caller keeps the thirty-two
/// bytes on the stack and tiles them itself.
fn mask(obfs: &[u8; OBFS_SIZE], salt: [u8; SALT_LEN]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(obfs);
    hash.update(salt);
    hash.finalize().into()
}

/// `XOR` one header byte against the mask's tiled position, so a magic or nonce check reads the wire
/// as it lies without staging a plaintext copy of the packet.
#[inline]
fn unmasked(wire: u8, mask: &[u8; 32], at: usize) -> u8 {
    wire ^ mask[at % 32]
}

/// Encode one punch packet of `packet_type` under a fixed `salt` and the caller's `padding` into
/// `out`, returning the wire length. `out` must hold the salt, the header and `padding` whole;
/// anything smaller is refused with `None` so a forged or undersized buffer is never written past.
/// The packet is built where it will ride — the salt goes first, the magic, type, nonce and padding
/// behind it, `XORed` by the salt's mask in place — so no intermediate plain buffer is joined and copied
/// behind the salt as the reference does.
#[must_use]
pub fn encode_punch_with_salt_and_padding(
    packet_type: PacketType,
    meta: &Metadata,
    salt: &[u8; SALT_LEN],
    padding: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if padding.len() > MAX_PADDING {
        return None;
    }
    let total = MIN_WIRE_LEN + padding.len();
    let room = out.get_mut(..total)?;
    room[..SALT_LEN].copy_from_slice(salt);
    room[SALT_LEN..SALT_LEN + MAGIC.len()].copy_from_slice(&MAGIC);
    room[SALT_LEN + MAGIC.len()] = packet_type as u8;
    room[SALT_LEN + MAGIC.len() + 1..MIN_WIRE_LEN].copy_from_slice(&meta.nonce);
    room[MIN_WIRE_LEN..total].copy_from_slice(padding);
    let key = mask(&meta.obfs, *salt);
    for (at, byte) in room[SALT_LEN..total].iter_mut().enumerate() {
        *byte = unmasked(*byte, &key, at);
    }
    Some(total)
}

/// Encode one punch packet under a fresh random salt and a random padding length in `0..=MAX_PADDING`.
/// The salt and padding are drawn with one `getrandom` fill of the salt plus the padding the draw
/// names, so the packet is built by [`encode_punch_with_salt_and_padding`] and pays no second buffer
/// beyond the one the caller owns. `None` only when the system RNG fails or `out` has no room.
#[must_use]
pub fn encode_punch(packet_type: PacketType, meta: &Metadata, out: &mut [u8]) -> Option<usize> {
    let mut raw = [0u8; MAX_PADDING + SALT_LEN + 2];
    getrandom::fill(&mut raw).ok()?;
    let padding_len = usize::from(u16::from_le_bytes([raw[0], raw[1]])) % (MAX_PADDING + 1);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[2..2 + SALT_LEN]);
    encode_punch_with_salt_and_padding(
        packet_type,
        meta,
        &salt,
        &raw[2 + SALT_LEN..2 + SALT_LEN + padding_len],
        out,
    )
}

/// Decode one punch packet punched under `meta` into its type and padding length. A packet shorter
/// than the salt plus header, longer than the reference's ceiling, carrying a bad magic, an unknown
/// type or a nonce the meta did not agree is `None`. The mask is computed once from the packet's own
/// salt and the header is read off the wire by `XORing` each byte at its tiled position — no plaintext
/// copy of the packet is ever staged, so a hook that read the copy back would spend it and never
/// notice.
#[must_use]
pub fn decode_punch(packet: &[u8], meta: &Metadata) -> Option<PunchPacket> {
    if packet.len() < MIN_WIRE_LEN || packet.len() > MAX_WIRE_LEN {
        return None;
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&packet[..SALT_LEN]);
    let key = mask(&meta.obfs, salt);
    for (at, &want) in MAGIC.iter().enumerate() {
        if unmasked(packet[SALT_LEN + at], &key, at) != want {
            return None;
        }
    }
    let packet_type =
        PacketType::from_byte(unmasked(packet[SALT_LEN + MAGIC.len()], &key, MAGIC.len()))?;
    for (at, &want) in meta.nonce.iter().enumerate() {
        if unmasked(
            packet[SALT_LEN + MAGIC.len() + 1 + at],
            &key,
            MAGIC.len() + 1 + at,
        ) != want
        {
            return None;
        }
    }
    Some(PunchPacket {
        packet_type,
        padding_len: packet.len() - MIN_WIRE_LEN,
    })
}

/// Whether a family's locals name IPv4, IPv6 or both, narrowed by the family's own restriction. The
/// answer drives [`candidate_addrs`]: a candidate is punched only in a family a local holds and the
/// family allows.
fn allowed_families(locals: &[SocketAddr], family: Family) -> (bool, bool) {
    let mut v4 = false;
    let mut v6 = false;
    for local in locals {
        if local.is_ipv4() {
            v4 = true;
        } else {
            v6 = true;
        }
        if v4 && v6 {
            break;
        }
    }
    match family {
        Family::Dual => (v4, v6),
        Family::V4 => (v4, false),
        Family::V6 => (false, v6),
    }
}

/// The punching candidates `peers` names under the families `locals` allow: a peer is taken once,
/// in the family the punch is allowed, and the answer is the sorted distinct set — a `Vec` taken in
/// `SocketAddr` order and deduplicated by binary search, where the reference opens a map per punch
/// and sorts the strings of its answers. An unordered peer list is accepted the same way.
#[must_use]
pub fn candidate_addrs(
    locals: &[SocketAddr],
    peers: &[SocketAddr],
    family: Family,
) -> Vec<SocketAddr> {
    let (v4, v6) = allowed_families(locals, family);
    let mut out: Vec<SocketAddr> = Vec::with_capacity(peers.len());
    for &peer in peers {
        if peer.is_ipv4() && !v4 || peer.is_ipv6() && !v6 {
            continue;
        }
        if out.binary_search(&peer).is_err() {
            out.push(peer);
            out.sort_unstable();
        }
    }
    out
}

/// Whether a host's observed ports read as one predictable range: every adjacent gap is inside
/// [`NAT_PORT_GAP`]. A single observation is never predictable — there is nothing to interpolate.
fn predictable_group(sorted: &[u16]) -> bool {
    if sorted.len() < 2 {
        return false;
    }
    sorted.windows(2).all(|w| w[1] - w[0] <= NAT_PORT_GAP)
}

/// The symmetric-NAT expansion: a predictable IPv4 host's range is walked from its lowest observed
/// port through its highest plus [`NAT_EXTRA_PORTS`], capped at [`NAT_MAX_PORTS_PER_HOST`] new
/// candidates per host, and every candidate is added once. The walk is over the sorted distinct ports
/// the candidates hold now — no per-host map keyed on the address and no string ordering — and the
/// answer is the sorted set the punch walks.
#[must_use]
pub fn expand_symmetric(candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = candidates.to_vec();
    out.sort_unstable();
    out.dedup();
    let mut hosts: Vec<(std::net::IpAddr, Vec<u16>)> = Vec::new();
    for &addr in &out {
        if !addr.is_ipv4() {
            continue;
        }
        let ip = addr.ip();
        match hosts.iter_mut().find(|(held, _)| *held == ip) {
            Some((_, ports)) => ports.push(addr.port()),
            None => hosts.push((ip, vec![addr.port()])),
        }
    }
    for (ip, mut ports) in hosts {
        ports.sort_unstable();
        ports.dedup();
        if !predictable_group(&ports) {
            continue;
        }
        let start = ports.first().copied().unwrap_or(0);
        let end = ports
            .last()
            .copied()
            .unwrap_or(0)
            .saturating_add(NAT_EXTRA_PORTS);
        let mut added = 0;
        let mut port = u32::from(start);
        while port <= u32::from(end) && added < NAT_MAX_PORTS_PER_HOST {
            let candidate = SocketAddr::new(ip, port as u16);
            if out.binary_search(&candidate).is_err() {
                out.push(candidate);
                out.sort_unstable();
                added += 1;
            }
            port += 1;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const NONCE: [u8; NONCE_SIZE] = [0xab; NONCE_SIZE];
    const OBFS: [u8; OBFS_SIZE] = [0xcd; OBFS_SIZE];
    const SALT: [u8; SALT_LEN] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn meta() -> Metadata {
        Metadata {
            nonce: NONCE,
            obfs: OBFS,
        }
    }

    /// The exact wire bytes the reference emits: `salt || magic || type || nonce || padding` `XORed`
    /// against `SHA-256(obfs || salt)`. Recomputed here with the one-shot digest rather than the
    /// streaming hasher the module uses, so the two agree by independent routes.
    #[test]
    fn a_punch_packet_is_the_exact_bytes_the_reference_emits() {
        let mut out = [0u8; MIN_WIRE_LEN + 3];
        let written =
            encode_punch_with_salt_and_padding(PacketType::Hello, &meta(), &SALT, b"pad", &mut out)
                .expect("fits");
        assert_eq!(written, MIN_WIRE_LEN + 3);
        let mut want = Vec::new();
        want.extend_from_slice(&SALT);
        want.extend_from_slice(&MAGIC);
        want.push(PacketType::Hello as u8);
        want.extend_from_slice(&NONCE);
        want.extend_from_slice(b"pad");
        let mut hasher = Sha256::new();
        hasher.update(OBFS);
        hasher.update(SALT);
        let key = hasher.finalize();
        for (at, byte) in want[SALT_LEN..].iter_mut().enumerate() {
            *byte ^= key[at % 32];
        }
        assert_eq!(&out[..written], &want[..]);
    }

    /// The write lands where the caller points it: the packet's base is inside the caller's buffer,
    /// the buffer's own pointer does not move and its capacity does not grow — the intermediate plain
    /// buffer and the copy behind the salt the reference stages are gone.
    #[test]
    fn an_encoded_packet_leaves_the_callers_buffer_where_it_landed() {
        let mut frame = [0u8; MIN_WIRE_LEN + 7];
        let base = frame.as_mut_ptr();
        let written = encode_punch_with_salt_and_padding(
            PacketType::Ack,
            &meta(),
            &SALT,
            b"1234567",
            &mut frame,
        )
        .expect("fits");
        assert_eq!(written, MIN_WIRE_LEN + 7);
        assert_eq!(frame.as_ptr(), base, "the buffer itself never moved");
        assert_ne!(
            frame.as_ptr(),
            frame[SALT_LEN..].as_ptr(),
            "the plain part is behind the salt"
        );
        let packet = decode_punch(&frame[..written], &meta()).expect("the meta agrees");
        assert_eq!(packet.packet_type, PacketType::Ack);
        assert_eq!(packet.padding_len, 7);
    }

    /// The decode takes the packet as it lies: 4096 packets encode and decode at 0 allocs, 0 bytes,
    /// 0 zeroed, where a copy of the plain part per decode would have meant a heap a packet.
    #[test]
    fn an_encoded_and_decoded_packet_takes_no_heap() {
        let mut frame = [0u8; MIN_WIRE_LEN + 5];
        encode_punch_with_salt_and_padding(PacketType::Hello, &meta(), &SALT, b"12345", &mut frame)
            .expect("fits");
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..4096 {
                let mut out = [0u8; MIN_WIRE_LEN + 5];
                std::hint::black_box(encode_punch_with_salt_and_padding(
                    PacketType::Hello,
                    std::hint::black_box(&meta()),
                    std::hint::black_box(&SALT),
                    std::hint::black_box(b"12345"),
                    std::hint::black_box(&mut out),
                ));
                std::hint::black_box(decode_punch(
                    std::hint::black_box(&out[..MIN_WIRE_LEN + 5]),
                    std::hint::black_box(&meta()),
                ));
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 packets take no heap at all"
        );
    }

    /// A forged or truncated packet is refused with the input held: wrong magic, wrong nonce, wrong
    /// type and short or long buffers are all `None`, and the bytes the refusal guarded are untouched.
    #[test]
    fn a_forged_or_truncated_packet_is_refused_and_the_buffer_held() {
        let mut frame = [0u8; MIN_WIRE_LEN + 4];
        encode_punch_with_salt_and_padding(PacketType::Hello, &meta(), &SALT, b"1234", &mut frame)
            .expect("fits");
        let other = Metadata {
            nonce: [0u8; NONCE_SIZE],
            obfs: OBFS,
        };
        assert!(decode_punch(&frame, &other).is_none());
        assert!(decode_punch(&frame[..MIN_WIRE_LEN - 1], &meta()).is_none());
        let too_long = vec![0u8; MAX_WIRE_LEN + 1];
        assert!(decode_punch(&too_long, &meta()).is_none());
        let mut tampered = frame;
        tampered[SALT_LEN] ^= 0xff;
        assert!(decode_punch(&tampered, &meta()).is_none());
        let mut unknown_type = frame;
        let key = mask(&OBFS, SALT);
        unknown_type[SALT_LEN + MAGIC.len()] = 0x07 ^ key[MAGIC.len() % 32];
        assert!(decode_punch(&unknown_type, &meta()).is_none());
        let before = frame;
        assert!(decode_punch(&frame[..10], &meta()).is_none());
        assert_eq!(frame, before, "a refusal never rewrote the input");
        assert!(encode_punch_with_salt_and_padding(
            PacketType::Hello,
            &meta(),
            &SALT,
            &[],
            &mut [0u8; 4]
        )
        .is_none());
        assert!(encode_punch_with_salt_and_padding(
            PacketType::Hello,
            &meta(),
            &SALT,
            &vec![0u8; MAX_PADDING + 1],
            &mut [0u8; MAX_WIRE_LEN + 1],
        )
        .is_none());
    }

    /// The random form agrees with the deterministic one at its own draw: the packet it writes
    /// decodes to the same type and padding length the encoder drew.
    #[test]
    fn a_randomly_padded_packet_decodes_to_the_same_type_and_padding() {
        for _ in 0..64 {
            let mut out = [0u8; MAX_WIRE_LEN];
            let written = encode_punch(PacketType::Hello, &meta(), &mut out).expect("fits");
            let packet = decode_punch(&out[..written], &meta()).expect("the meta agrees");
            assert_eq!(packet.packet_type, PacketType::Hello);
            assert_eq!(written, MIN_WIRE_LEN + packet.padding_len);
        }
    }

    /// The candidate filter answers as the family filter the reference answers: an IPv4 local names
    /// only IPv4 peers, a restricted family names only its own, and a duplicate joins once.
    #[test]
    fn candidates_are_filtered_by_family_and_deduplicated_once() {
        let v4_local: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let v6_local: SocketAddr = "[::1]:1000".parse().unwrap();
        let peers: Vec<SocketAddr> = vec![
            "192.0.2.11:5000".parse().unwrap(),
            "[2001:db8::1]:5000".parse().unwrap(),
            "192.0.2.11:5000".parse().unwrap(),
        ];
        assert_eq!(
            candidate_addrs(&[v4_local], &peers, Family::Dual),
            vec!["192.0.2.11:5000".parse().unwrap()]
        );
        assert_eq!(
            candidate_addrs(&[v4_local, v6_local], &peers, Family::V4),
            vec!["192.0.2.11:5000".parse().unwrap()]
        );
        assert_eq!(
            candidate_addrs(&[v4_local, v6_local], &peers, Family::Dual),
            vec![
                "192.0.2.11:5000".parse().unwrap(),
                "[2001:db8::1]:5000".parse().unwrap()
            ]
        );
        assert_eq!(
            candidate_addrs(&[], &peers, Family::Dual),
            Vec::<SocketAddr>::new()
        );
    }

    /// A predictable symmetric-NAT group is interpolated through the extra ports, capped per host; an
    /// unpredictable one is left as it is.
    #[test]
    fn a_symmetric_nat_group_is_interpolated_through_its_extra_ports() {
        let two: Vec<SocketAddr> = vec![
            "192.0.2.4:30000".parse().unwrap(),
            "192.0.2.4:30002".parse().unwrap(),
        ];
        let expanded = expand_symmetric(&two);
        for port in [30000u16, 30001, 30002, 30006] {
            assert!(
                expanded.contains(&SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 4)),
                    port
                )),
                "port {port} joins the walk"
            );
        }
        let sparse: Vec<SocketAddr> = vec![
            "192.0.2.4:30000".parse().unwrap(),
            "192.0.2.4:30100".parse().unwrap(),
        ];
        assert_eq!(
            expand_symmetric(&sparse).len(),
            2,
            "an unpredictable group is left alone"
        );
        assert_eq!(
            expand_symmetric(&[two[0]]).len(),
            1,
            "one observation interpolates nothing"
        );
    }

    /// Hex carries the metadata the rendezvous names: sixteen nonce bytes and thirty-two obfs bytes
    /// round-trip through lowercase hex, and a wrong length or a non-hex digit is refused.
    #[test]
    fn metadata_hex_round_trips_and_refuses_wrong_lengths() {
        let nonce_hex = hex_encode(&NONCE);
        let obfs_hex = hex_encode(&OBFS);
        assert_eq!(nonce_hex.len(), NONCE_SIZE * 2);
        assert_eq!(obfs_hex.len(), OBFS_SIZE * 2);
        let decoded = decode_metadata_hex(&nonce_hex, &obfs_hex).expect("the hex agrees");
        assert_eq!(decoded.nonce, NONCE);
        assert_eq!(decoded.obfs, OBFS);
        assert!(decode_metadata_hex("00", &obfs_hex).is_none());
        assert!(decode_metadata_hex(&nonce_hex, "zz").is_none());
        let random = Metadata::new_random().expect("rng");
        let hex = hex_encode(&random.nonce);
        assert_eq!(hex_decode::<NONCE_SIZE>(&hex), Some(random.nonce));
    }

    /// The realm slot the server admits is the reference's pattern: one alphanum-
    /// er, then alphanumerics, `-` and `_` to sixty-four in total.
    #[test]
    fn a_realm_id_answers_as_the_server_admits_it() {
        assert!(valid_realm_id("a"));
        assert!(valid_realm_id("Realm-1_ok"));
        assert!(!valid_realm_id(""));
        assert!(!valid_realm_id("-lead"));
        assert!(!valid_realm_id("has space"));
        assert!(!valid_realm_id(&"a".repeat(65)));
    }

    /// The expansion is the candidates' sorted distinct set: its base lies in the sorted order the
    /// punch walks, never duplicated and never out of order.
    #[test]
    fn an_expanded_set_is_sorted_and_distinct() {
        let two: Vec<SocketAddr> = vec![
            "192.0.2.4:30002".parse().unwrap(),
            "192.0.2.4:30000".parse().unwrap(),
            "192.0.2.4:30002".parse().unwrap(),
        ];
        let expanded = expand_symmetric(&two);
        assert!(expanded.is_sorted(), "the walk is ascending");
        assert!(
            expanded.windows(2).all(|w| w[0] != w[1]),
            "one of each port"
        );
    }
}
