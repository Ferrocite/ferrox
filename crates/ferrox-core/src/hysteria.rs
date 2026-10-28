//! Hysteria version 2 framing: the bytes around the QUIC streams and datagrams — every TCP flow is one bidirectional stream opening with the `0x401` type as a QUIC varint, the connection authenticates by HTTP/3 `POST /auth` answered with status `233`, and the UDP lane rides QUIC datagrams each carrying a `BE32` session id ahead of a packet id, fragment metadata, a varint address and its payload.

use crate::foxy::{frames, head_end, hpack};
use std::time::Duration;

pub const TCP_FRAME: u64 = 0x401;

pub const AUTH_STATUS: u16 = 233;

pub const AUTH_AUTHORITY: &str = "hysteria";

pub const AUTH_PATH: &str = "/auth";

pub const AUTH_HEADER: &str = "hysteria-auth";

pub const CC_RX_HEADER: &str = "hysteria-cc-rx";

pub const UDP_HEADER: &str = "hysteria-udp";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Congestion {
    Reno,
    Bbr,
    Brutal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BbrProfile {
    Conservative,
    Standard,
    Aggressive,
}

/// The `finalmask.quicParams` a hysteria transport names. A zero field keeps the
/// carrier's own default; the reference fills the QUIC defaults only when the
/// block is present, so `Config::quic == None` is the byte-identical old path.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuicParams {
    pub congestion: Congestion,
    pub bbr_profile: BbrProfile,
    pub brutal_up: u64,
    pub brutal_down: u64,
    pub brutal_disable_loss_compensation: bool,
    pub init_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub init_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: Duration,
    pub keep_alive_period: Duration,
    pub disable_path_mtu_discovery: bool,
    pub disable_chrome_parrot: bool,
    pub disable_gso: bool,
    pub max_incoming_streams: u64,
    pub disable_stateless_reset: bool,
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

/// One inclusive `start..=end` span of server ports a hopped dial moves between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    #[must_use]
    pub fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    #[must_use]
    pub fn count(self) -> usize {
        usize::from(self.end - self.start) + 1
    }
}

/// A port-hopping plan: the server ports a client dial rotates between and the
/// window each stay lasts. Held apart from the socket that moves, so the rotation
/// is chosen — and proven — without a bound socket or a clock. `interval_ms` is
/// the inclusive low..=high range a stay is drawn from; a plan with no room
/// (`high <= low`) stays for exactly `low`. The dialed `Config` carries it; the
/// pool key does too, so a hopped connection is never handed to a plain dial.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hop {
    pub ranges: Vec<PortRange>,
    pub interval_ms: (u64, u64),
}

impl Hop {
    /// The distinct ports the plan covers, ascending, an overlap named once.
    /// Expanded once per dial so the rotation and the wire's source-port check
    /// share one view of the set.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        let mut set: Vec<u16> = Vec::new();
        for range in &self.ranges {
            for port in range.start..=range.end {
                if !set.contains(&port) {
                    set.push(port);
                }
            }
        }
        set.sort_unstable();
        set
    }
}

/// One of the ports a hop plan covers, never the one just left when another
/// exists: a single-port plan stays, an empty plan yields `avoid` unchanged.
/// `roll` is caller-supplied entropy folded in, so the choice is a pure function
/// of the port set, the port to avoid and one number — proven without a rng.
#[must_use]
pub fn pick_next(ports: &[u16], avoid: u16, roll: usize) -> u16 {
    let candidates = ports.iter().filter(|port| **port != avoid).count();
    if candidates == 0 {
        return ports.first().copied().unwrap_or(avoid);
    }
    let mut index = roll % candidates;
    for &port in ports.iter().filter(|port| **port != avoid) {
        if index == 0 {
            return port;
        }
        index -= 1;
    }
    avoid
}

/// The length of the next stay in milliseconds, drawn from `interval`'s inclusive
/// range: no room (`high <= low`) gives the low bound. `roll` is the entropy
/// folded in, so a stay is a pure function of the range and one number.
#[must_use]
pub fn stay_ms(interval: (u64, u64), roll: u64) -> u64 {
    let (low, high) = interval;
    if high <= low {
        return low;
    }
    low + roll % (high - low + 1)
}

/// Whether a reply's source port belongs to the hop: the nominal port the
/// connection was named for, or any port the plan moves between. The wire turns
/// such a source back to the nominal one so QUIC above sees one server.
#[must_use]
pub fn is_hop_port(ports: &[u16], nominal: u16, port: u16) -> bool {
    port == nominal || ports.contains(&port)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The wire version this config names: `1` for the binary control stream, `2` for the HTTP/3 handshake.
    pub version: u8,
    pub auth: String,
    pub cc: Congestion,
    pub obfs_password: String,
    /// The port-hopping plan this dial rotates server ports on, or `None` for a
    /// single fixed port. A plan joins the pool key, so reuse stays hop-faithful.
    pub hop: Option<Hop>,
    /// The `obfs: gecko` fragment window this dial pads its long-header packets
    /// into, or `None` for a plain salamander (or cleartext) lane. `obfs_password`
    /// still holds the key salamander masks each frame with.
    pub gecko: Option<Gecko>,
    /// The server's datagram-association idle window, `hysteriaSettings.udpIdleTimeout`, default 60 seconds.
    pub udp_idle: Duration,
    /// The `finalmask.quicParams` this transport names, or `None` to keep the carrier's own QUIC shape.
    pub quic: Option<QuicParams>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 2,
            auth: String::new(),
            cc: Congestion::Bbr,
            obfs_password: String::new(),
            hop: None,
            gecko: None,
            udp_idle: Duration::from_secs(60),
            quic: None,
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

/// One message's fragments, walked in order without a list: every payload chunk borrows
/// the message's own bytes, so a relay pays no allocation for the common one-fragment
/// datagram and none for a split one either.
#[derive(Debug)]
pub struct Fragments<'a> {
    message: UdpMessage<'a>,
    chunks: core::slice::Chunks<'a, u8>,
    next: u8,
    total: u8,
}

impl<'a> Iterator for Fragments<'a> {
    type Item = UdpMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let payload = self.chunks.next()?;
        let message = UdpMessage {
            frag: self.next,
            frags: self.total,
            payload,
            ..self.message
        };
        self.next += 1;
        Some(message)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.chunks.size_hint()
    }
}

/// Split a whole message across datagrams no larger than `max` — the peer's writable datagram size — without copying its payload; a head already at or over `max` is refused rather than truncated.
pub fn fragments_udp<'a>(
    message: &UdpMessage<'a>,
    max: usize,
) -> Result<Fragments<'a>, RequestError> {
    message.validate()?;
    if message.frags != 1 {
        return Err(RequestError::Invalid);
    }
    let capacity = max
        .checked_sub(message.header_len())
        .filter(|room| *room > 0)
        .ok_or(RequestError::Invalid)?;
    let total = u8::try_from(message.payload.len().div_ceil(capacity))
        .map_err(|_| RequestError::Invalid)?;
    Ok(Fragments {
        message: *message,
        chunks: message.payload.chunks(capacity),
        next: 0,
        total,
    })
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

    /// Fold one message in; `Some((address, payload))` when a datagram is whole. A single fragment clears any partial and passes straight through, so an unfragmented datagram never waits on the state — and never copies either: the answer is the caller's own datagram. Reassembly, the rare answer, writes into the buffer the caller lends.
    pub fn feed<'a>(
        &mut self,
        message: &UdpMessage<'a>,
        out: &'a mut Vec<u8>,
    ) -> Result<Option<(&'a str, &'a [u8])>, RequestError> {
        message.validate()?;
        if message.frags == 1 {
            *self = Self::default();
            return Ok(Some((message.address, message.payload)));
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
        let size = self.size;
        self.address.clear();
        out.clear();
        out.reserve(size);
        for fragment in std::mem::take(&mut self.slots).into_iter().flatten() {
            out.extend_from_slice(&fragment);
        }
        self.have = 0;
        self.size = 0;
        Ok(Some((message.address, out)))
    }
}

#[derive(Clone)]
/// Salamander, the UDP datagram obfuscation Hysteria v2 names `obfs: salamander`.
///
/// Every datagram on the wire becomes `salt (8 random bytes) || payload XORed against the keystream`, where the keystream is `BLAKE2b-256(password || salt)` tiled cyclically over the payload. A fresh salt per datagram makes each packet look like noise, so the QUIC header a filter would match never reaches the wire. This is obfuscation, not encryption: QUIC and TLS above still authenticate and protect the bytes, and a peer without the same password reads noise that QUIC then drops.
///
/// The construction is pinned to what the references emit: the salt is hashed *after* the password, so the key input is `password || salt`, and the mask is `key[i mod 32]`. Both `upstream/xray-core/transport/internet/finalmask/salamander` (Go) and `upstream/zeronet/crates/zero-transport/src/salamander.rs` (Rust) agree on that order, and the oracle vectors in the test are computed with Python `hashlib.blake2b` — independent of this code and of both references.
pub struct Salamander {
    password: Vec<u8>,
}

/// The password is a credential and stays out of any log a `Debug` reach would print.
impl core::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Salamander(..)")
    }
}

/// Bytes of random salt in front of every obfuscated datagram.
pub const SALAMANDER_SALT: usize = 8;

/// The shortest password a Hysteria v2 endpoint accepts.
pub const SALAMANDER_MIN_PASSWORD: usize = 4;

/// The BLAKE2b-256 keystream block, tiled cyclically over a payload.
const SALAMANDER_KEY: usize = 32;

impl Salamander {
    /// `None` when the password is shorter than a server accepts.
    #[must_use]
    pub fn new(password: &str) -> Option<Self> {
        if password.len() < SALAMANDER_MIN_PASSWORD {
            return None;
        }
        Some(Self {
            password: password.as_bytes().to_vec(),
        })
    }

    /// `BLAKE2b-256(password || salt)`, the password first then the salt. The two parts stream into one hasher so the concatenation the reference pre-allocates and copies is never materialised.
    fn keystream(&self, salt: [u8; SALAMANDER_SALT]) -> [u8; SALAMANDER_KEY] {
        use blake2::digest::consts::U32;
        use blake2::{Blake2b, Digest};
        let mut hash = Blake2b::<U32>::new();
        hash.update(&self.password);
        hash.update(salt);
        hash.finalize().into()
    }

    /// Prepend `salt`, then append `plain` masked by its keystream — the deterministic form the oracle vectors check.
    pub fn obfuscate_with_salt(
        &self,
        salt: &[u8; SALAMANDER_SALT],
        plain: &[u8],
        out: &mut Vec<u8>,
    ) {
        let key = self.keystream(*salt);
        let body = out.len() + SALAMANDER_SALT;
        out.reserve(SALAMANDER_SALT + plain.len());
        out.extend_from_slice(salt);
        out.extend_from_slice(plain);
        for dst in out[body..].chunks_mut(SALAMANDER_KEY) {
            for (byte, key) in dst.iter_mut().zip(key.iter()) {
                *byte ^= key;
            }
        }
    }

    /// Obfuscate `plain` under a fresh random salt appended to `out`; `None` only when the system RNG fails.
    pub fn obfuscate(&self, plain: &[u8], out: &mut Vec<u8>) -> Option<()> {
        let mut salt = [0u8; SALAMANDER_SALT];
        getrandom::fill(&mut salt).ok()?;
        self.obfuscate_with_salt(&salt, plain, out);
        Some(())
    }

    /// Write the masked `plain` behind `salt` into the front of `out` and return the total length; the caller must give `out` at least `SALAMANDER_SALT + plain.len()` bytes. This is the wire form, so a datagram is sealed into a stack scratch rather than an allocated `Vec`.
    #[must_use]
    pub fn obfuscate_into(
        &self,
        salt: &[u8; SALAMANDER_SALT],
        plain: &[u8],
        out: &mut [u8],
    ) -> usize {
        let key = self.keystream(*salt);
        out[..SALAMANDER_SALT].copy_from_slice(salt);
        let body = &mut out[SALAMANDER_SALT..SALAMANDER_SALT + plain.len()];
        // A keystream block is 32 bytes, so chunking both sides on it restarts the key where the modulo did and lets the XOR run a block at a time instead of a byte at a time.
        for (dst, src) in body
            .chunks_mut(SALAMANDER_KEY)
            .zip(plain.chunks(SALAMANDER_KEY))
        {
            for ((out, plain), key) in dst.iter_mut().zip(src).zip(key.iter()) {
                *out = plain ^ key;
            }
        }
        SALAMANDER_SALT + plain.len()
    }

    /// Seal one outgoing datagram: a fresh random salt then the masked payload, into `out`, returning the written length. `None` when `out` has no room for `plain` plus a salt, or the system RNG fails.
    pub fn seal_into(&self, plain: &[u8], out: &mut [u8]) -> Option<usize> {
        let need = plain.len().checked_add(SALAMANDER_SALT)?;
        if out.len() < need {
            return None;
        }
        let mut salt = [0u8; SALAMANDER_SALT];
        getrandom::fill(&mut salt).ok()?;
        Some(self.obfuscate_into(&salt, plain, out))
    }

    /// Undo [`Salamander::obfuscate`] on one whole datagram in place, moving the payload to the front; the length is returned, or `None` when the datagram is too short to hold a salt and one payload byte. The payload moves toward the front by the salt's length, so a block is read out before the block behind it is written: one pass, one block of scratch, no second buffer.
    pub fn deobfuscate_in_place(&self, datagram: &mut [u8]) -> Option<usize> {
        if datagram.len() <= SALAMANDER_SALT {
            return None;
        }
        let mut salt = [0u8; SALAMANDER_SALT];
        salt.copy_from_slice(&datagram[..SALAMANDER_SALT]);
        let key = self.keystream(salt);
        let payload = datagram.len() - SALAMANDER_SALT;
        let mut block = [0u8; SALAMANDER_KEY];
        let mut at = 0usize;
        while at < payload {
            let len = SALAMANDER_KEY.min(payload - at);
            let from = SALAMANDER_SALT + at;
            block[..len].copy_from_slice(&datagram[from..from + len]);
            let block = &block[..len];
            for ((out, src), key) in datagram[at..at + len]
                .iter_mut()
                .zip(block)
                .zip(&key[..len])
            {
                *out = *src ^ key;
            }
            at += len;
        }
        Some(payload)
    }
}

/// Gecko, the Hysteria v2 `obfs: gecko` lane: a fragment-and-pad layer that rides on
/// top of salamander. A QUIC long-header packet (its high bit `0x80` set) is split
/// into `2..=8` chunks, each wrapped in a five-byte frame header plus random padding
/// that drags the sealed datagram into a `[min, max]` size window, then masked; a
/// short-header packet is masked whole. This is the deterministic half of the lane —
/// the chunk count, pad lengths and message ids are random and drawn by the socket
/// above, exactly as the port-hop pick and stay are drawn by the dialer.
///
/// Wire layout of one frame, before salamander masks it:
/// - byte 0: `0x80` fragment marker, the low 7 bits reserved
/// - byte 1: message id
/// - byte 2: `chunk_idx` in the high nibble, `total_chunks` in the low nibble
/// - bytes 3-4: pad length, big-endian
/// - then `pad_len` random bytes, then the chunk payload
pub const GECKO_FLAG: u8 = 0x80;

/// A frame header: one flag byte, a message id, the chunk/total nibble, and a two
/// byte pad length.
pub const GECKO_HEADER: usize = 5;

/// A fragmented message spans at least this many chunks.
pub const GECKO_MIN_CHUNKS: usize = 2;

/// …and at most this many, so one nibble always holds both the count and the index.
pub const GECKO_MAX_CHUNKS: usize = 8;

/// A parsed gecko frame header; [`decode_gecko_frame`] returns it with a borrow of the
/// payload that followed the padding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GeckoFrame {
    pub msg_id: u8,
    pub chunk_idx: u8,
    pub total_chunks: u8,
    pub pad_len: u16,
}

impl GeckoFrame {
    /// `false` unless the chunk count is in `[2, 8]` and the index is below it — the
    /// two rules both the encoder and the decoder refuse a frame on.
    #[must_use]
    pub fn valid(self) -> bool {
        (GECKO_MIN_CHUNKS as u8..=GECKO_MAX_CHUNKS as u8).contains(&self.total_chunks)
            && self.chunk_idx < self.total_chunks
    }
}

/// Write one frame's header, then the caller-supplied `pad`, then `payload` into
/// `out`, returning the total length. `pad` must be exactly `frame.pad_len` long and
/// `out` must hold the whole frame; anything else is refused with `None` so a forged
/// or undersized buffer is never written past.
#[must_use]
pub fn encode_gecko_frame(
    frame: GeckoFrame,
    pad: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if !frame.valid() || usize::from(frame.pad_len) != pad.len() {
        return None;
    }
    let total = GECKO_HEADER + pad.len() + payload.len();
    let room = out.get_mut(..total)?;
    room[0] = GECKO_FLAG;
    room[1] = frame.msg_id;
    room[2] = frame.chunk_idx << 4 | frame.total_chunks & 0x0f;
    room[3..5].copy_from_slice(&frame.pad_len.to_be_bytes());
    room[GECKO_HEADER..GECKO_HEADER + pad.len()].copy_from_slice(pad);
    room[GECKO_HEADER + pad.len()..].copy_from_slice(payload);
    Some(total)
}

/// Parse a frame header and borrow its payload out of `input` with no copy. `None` on
/// a truncated buffer, a missing flag, an invalid chunk count or index, or a pad
/// length that would read past the buffer. The payload slice begins at exactly
/// `GECKO_HEADER + pad_len` inside `input`, so its base pointer witnesses the zero
/// copy rather than a refill.
#[must_use]
pub fn decode_gecko_frame(input: &[u8]) -> Option<(GeckoFrame, &[u8])> {
    let head = input.get(..GECKO_HEADER)?;
    if head[0] & GECKO_FLAG == 0 {
        return None;
    }
    let frame = GeckoFrame {
        msg_id: head[1],
        chunk_idx: head[2] >> 4,
        total_chunks: head[2] & 0x0f,
        pad_len: u16::from_be_bytes([head[3], head[4]]),
    };
    if !frame.valid() {
        return None;
    }
    input
        .get(GECKO_HEADER + usize::from(frame.pad_len)..)
        .map(|payload| (frame, payload))
}

/// The byte range `[start, end)` of chunk `idx` when `len` is split into `total`
/// chunks of `len / total` each and the last takes the remainder — the reference
/// fragmenter's rule, exposed pure so a test can witness reassembly order instead of
/// assuming it.
#[must_use]
pub fn gecko_chunk_range(len: usize, idx: usize, total: usize) -> Option<(usize, usize)> {
    if total == 0 || idx >= total {
        return None;
    }
    let size = len / total;
    let start = idx * size;
    let end = if idx + 1 == total { len } else { start + size };
    Some((start, end))
}

/// The padding a chunk of `chunk_len` plain bytes needs so the sealed datagram —
/// salt, frame header, padding, payload — lands inside the inclusive `[min, max]`
/// window. `base` is the salt+header+chunk already committed; when that alone is at
/// or over `max` there is no room and the pad is 0. Otherwise the low end is the
/// larger of `min` and `base`, and `roll` spreads the size across `[lo, max]`. Folded
/// pure so the socket draws the roll and a test pins the bounds with no RNG.
#[must_use]
pub fn gecko_pad_len(min: usize, max: usize, base: usize, roll: u64) -> u16 {
    let lo = min.max(base);
    if lo > max {
        return 0;
    }
    let span = max - lo + 1;
    let spread = if span <= 1 {
        0
    } else {
        usize::try_from(roll % span as u64).unwrap_or(0)
    };
    u16::try_from(lo - base + spread).unwrap_or(u16::MAX)
}

/// A `obfs: gecko` plan: the frame size window the socket pads into. It defaults to
/// `[512, 1200]` and caps the buffer at 2048, the reference's own bounds; a config
/// outside them is refused at parse rather than guessed at, so this type only ever
/// carries a valid window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gecko {
    pub min_pkt: u16,
    pub max_pkt: u16,
}

impl Gecko {
    /// The window a config that names neither bound gets.
    pub const DEFAULT_MIN: u16 = 512;
    pub const DEFAULT_MAX: u16 = 1200;
    /// The largest frame the reference sizes against; a bigger bound is refused.
    pub const MAX_BUFFER: u16 = 2048;

    /// A valid window, filling each absent bound with its default. `None` unless
    /// `0 < min <= max <= 2048`.
    #[must_use]
    pub fn new(min: u16, max: u16) -> Option<Self> {
        let min = if min == 0 { Self::DEFAULT_MIN } else { min };
        let max = if max == 0 { Self::DEFAULT_MAX } else { max };
        if min == 0 || min > max || max > Self::MAX_BUFFER {
            return None;
        }
        Some(Self {
            min_pkt: min,
            max_pkt: max,
        })
    }
}

pub fn build_auth_request(auth: &str, out: &mut Vec<u8>) {
    hpack::qpack_literal_many(
        &[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", AUTH_AUTHORITY),
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

/// Whether a request block carries the shape of a hysteria handshake — a `POST` to the auth path — whatever credential it names. The masquerade server uses it to keep a right-shape, wrong-password attempt refusing exactly as a plain hysteria server would, while any other request (`GET /`, a browser) is answered as the cover site instead.
#[must_use]
pub fn is_hysteria_auth_shape(block: &[u8]) -> bool {
    let Some(fields) = hpack::qpack_fields(block) else {
        return false;
    };
    find(&fields, ":method") == Some(b"POST".as_slice())
        && find(&fields, ":path") == Some(AUTH_PATH.as_bytes())
}

#[must_use]
pub fn verify_auth_response(block: &[u8]) -> bool {
    read_auth_response(block).is_some()
}

/// One parse for both signals the client reads off the auth response: `Some(true)` when the server accepted the credential and advertised the datagram lane, `Some(false)` when it accepted but only carries TCP streams, `None` when the credential was refused. The client caches the flag on the pooled session so a later UDP dial does not re-read the block.
#[must_use]
pub fn read_auth_response(block: &[u8]) -> Option<bool> {
    let fields = hpack::qpack_fields(block)?;
    if find(&fields, ":status")? != b"233" {
        return None;
    }
    Some(find(&fields, UDP_HEADER) == Some(b"true".as_slice()))
}

/// What a masquerade site answers a non-hysteria HTTP/3 request with, inbound only: a plain not-found, a canned line, a static directory, or a reverse proxy to an origin. The dialed `Config` never carries it, so the pool key a client connection is filed under stays untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Masquerade {
    #[default]
    NotFound,
    Response {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    File {
        dir: String,
    },
    Proxy {
        url: String,
        rewrite_host: bool,
        x_forwarded: bool,
        insecure: bool,
    },
}

/// The ordinary HTTP/3 request a browser left on the port: the pseudo-headers ferrox needs both to answer it and to rebuild an HTTP/1.1 request to a masquerade origin, plus the body the caller appended from the stream's `DATA` frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H3Request {
    pub method: String,
    pub path: String,
    pub authority: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A request stream opens with the `0x401` TCP type when hysteria named a destination and with an HTTP/3 frame when a browser asked for a page; the first varint is the whole difference, so the classifier is one read and shares its width math with `read_tcp_prefix`.
#[must_use]
pub fn is_hysteria_flow(bytes: &[u8]) -> bool {
    let mut at = 0usize;
    frames::quic_read(bytes, &mut at) == Some(TCP_FRAME)
}

/// The fields of a QPACK request block, split into the pseudo-headers a masquerade answer and an origin request both need and the ordinary headers copied onward. A block naming no `:method` is not a request; the body stays empty for the caller to fill from the `DATA` frame.
pub fn parse_h3_request(block: &[u8]) -> Option<H3Request> {
    let fields = hpack::qpack_fields(block)?;
    let text =
        |name: &str| -> Option<String> { String::from_utf8(find(&fields, name)?.to_vec()).ok() };
    let method = text(":method")?;
    let path = text(":path")?;
    let authority = text(":authority").unwrap_or_default();
    let headers = fields
        .iter()
        .filter(|(name, _)| !name.starts_with(b":"))
        .map(|(name, value)| {
            (
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            )
        })
        .collect();
    Some(H3Request {
        method,
        path,
        authority,
        headers,
        body: Vec::new(),
    })
}

/// An HTTP/3 response on a request stream: a `HEADERS` frame carrying `:status` ahead of the caller's fields, then a `DATA` frame only when the body is not empty, each length-prefixed the way the auth answer frames its headers. The caller sends the stream FIN.
pub fn encode_h3_response(status: u16, headers: &[(&str, &str)], body: &[u8], out: &mut Vec<u8>) {
    // The code's digits go into the end of a stack buffer: `to_string` is one allocation per answer, and a `fields` list to prepend them to is another.
    let mut code = [0u8; 5];
    let mut at = code.len();
    let mut rest = status;
    loop {
        at -= 1;
        code[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    let mut block = Vec::with_capacity(
        2 + hpack::qpack_field_len(7, code.len() - at)
            + headers
                .iter()
                .map(|(name, value)| hpack::qpack_field_len(name.len(), value.len()))
                .sum::<usize>(),
    );
    hpack::qpack_open(&mut block);
    hpack::qpack_field(&mut block, ":status", &code[at..]);
    for (name, value) in headers {
        hpack::qpack_field(&mut block, name, value.as_bytes());
    }
    frames::quic_varint(out, frames::H3_HEADERS);
    frames::quic_varint(out, block.len() as u64);
    out.extend_from_slice(&block);
    if !body.is_empty() {
        frames::quic_varint(out, frames::H3_DATA);
        frames::quic_varint(out, body.len() as u64);
        out.extend_from_slice(body);
    }
}

/// The `content-type` a static masquerade file answers with, guessed from the extension of the last path segment and falling back to the octet stream; a cover page is only convincing if a browser reads it as the kind of file it is.
#[must_use]
pub fn content_type(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let tail = match name.rfind('.') {
        Some(dot) => name[dot + 1..].split(['?', '#']).next().unwrap_or_default(),
        None => return "application/octet-stream",
    };
    match tail.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// One origin HTTP/1.1 response reduced to what ferrox re-emits as HTTP/3: the status code, every header as it arrived (the caller drops the hop-by-hop ones), and the body with any chunked framing or content-length tail already removed. The whole response, read to the origin's close, is the input; a head that never reaches its blank line is not a response.
pub fn parse_origin_response(raw: &[u8]) -> Option<OriginResponse> {
    let end = head_end(raw)?;
    let mut body = &raw[end + 4..];
    let mut lines = raw[..end].split(|&byte| byte == b'\n');
    let status = lines
        .next()?
        .split(|&byte| byte == b' ')
        .nth(1)
        .and_then(|code| std::str::from_utf8(code).ok())
        .and_then(|code| code.parse::<u16>().ok())?;
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, |&byte| byte == b':');
        let name = parts.next()?;
        let value = match parts.next() {
            Some(value) => value.strip_prefix(b" ").unwrap_or(value),
            None => continue,
        };
        let name = String::from_utf8_lossy(name).into_owned();
        let value = String::from_utf8_lossy(value).into_owned();
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().ok();
        }
        headers.push((name, value));
    }
    if chunked {
        return Some(OriginResponse {
            status,
            headers,
            body: dechunk(body)?,
        });
    }
    if let Some(want) = length {
        body = body.get(..want).unwrap_or(body);
    }
    Some(OriginResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

/// The parts ferrox re-emits from a reverse-proxied origin: kept apart from the HTTP/3 encoder so a chunked body is proven de-framed without a socket in the test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Strip the chunked transfer framing: each `hex-length\r\n data \r\n` run yields its data until a zero-length chunk closes the body. A short or malformed run is not a complete response.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|window| window == b"\r\n")?;
        let header = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(header.split(';').next()?.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        let start = line_end + 2;
        out.extend_from_slice(body.get(start..start + size)?);
        body = body.get(start + size + 2..)?;
    }
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
        let frags: Vec<_> = fragments_udp(&message, 16).expect("fragments").collect();
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
        assert!(fragments_udp(&message, 12).is_err());
        // Feeding fragments out of order still reassembles in id order.
        let mut defrag = Defrag::new();
        let mut assembled = Vec::new();
        assert_eq!(defrag.feed(&frags[2], &mut assembled).expect("ok"), None);
        assert_eq!(defrag.feed(&frags[0], &mut assembled).expect("ok"), None);
        let packet = defrag
            .feed(&frags[1], &mut assembled)
            .expect("ok")
            .expect("complete");
        assert_eq!(packet.0, "a:1");
        assert_eq!(packet.1, b"0123456789");
    }

    /// The fragment walk is an iterator over the message's own bytes: a relay pays no
    /// list for a one-fragment datagram and no list for a split one either.
    #[test]
    fn a_fragment_run_takes_no_heap() {
        let payload: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let message = UdpMessage {
            session: 7,
            packet: 42,
            frag: 0,
            frags: 1,
            address: "edge.example:443",
            payload: &payload,
        };
        let mut wire = Vec::with_capacity(1200);
        for frag in fragments_udp(&message, 1200).expect("fragments") {
            wire.clear();
            encode_udp(&frag, &mut wire).expect("encodes");
        }
        wire.clear();
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..4096 {
                for frag in fragments_udp(std::hint::black_box(&message), 1200).expect("fragments")
                {
                    wire.clear();
                    encode_udp(&frag, &mut wire).expect("encodes");
                    std::hint::black_box(&wire);
                }
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 fragment runs take no heap at all"
        );
    }

    #[test]
    fn a_new_packet_id_discards_the_partial_before_it() {
        let mut defrag = Defrag::new();
        let mut assembled = Vec::new();
        let first = UdpMessage {
            session: 1,
            packet: 1,
            frag: 0,
            frags: 2,
            address: "a:1",
            payload: b"x",
        };
        assert_eq!(defrag.feed(&first, &mut assembled).expect("ok"), None);
        // A new packet id on the same session drops the half-filled packet.
        let next = UdpMessage { packet: 2, ..first };
        assert_eq!(defrag.feed(&next, &mut assembled).expect("ok"), None);
        let tail = UdpMessage {
            packet: 2,
            frag: 1,
            payload: b"y",
            ..first
        };
        let packet = defrag
            .feed(&tail, &mut assembled)
            .expect("ok")
            .expect("complete");
        assert_eq!(packet.1, b"xy");
    }

    /// A whole datagram answers from the caller's own bytes: an unfragmented message needs no reassembly, so neither its address nor its payload is copied and no buffer is taken for it.
    #[test]
    fn an_unfragmented_datagram_is_handed_over_without_a_buffer() {
        let payload: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let message = UdpMessage {
            session: 1,
            packet: 7,
            frag: 0,
            frags: 1,
            address: "edge.example:443",
            payload: &payload,
        };
        let mut defrag = Defrag::new();
        let mut assembled = Vec::new();
        let (address, got) = defrag
            .feed(&message, &mut assembled)
            .expect("ok")
            .expect("whole");
        assert_eq!(
            address.as_ptr(),
            message.address.as_ptr(),
            "the address IS the datagram's own text, not a copy of it"
        );
        assert_eq!(
            got.as_ptr(),
            message.payload.as_ptr(),
            "the payload IS the datagram's own bytes, not a copy of them"
        );
        assert_eq!(assembled.capacity(), 0, "nothing was staged");
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..4096 {
                let mut assembled = Vec::new();
                std::hint::black_box(
                    defrag
                        .feed(std::hint::black_box(&message), &mut assembled)
                        .expect("ok"),
                );
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 whole datagrams take no heap at all"
        );
    }

    #[test]
    fn an_auth_request_carries_post_auth_and_no_brutal_cap() {
        let mut block = Vec::new();
        build_auth_request("s3cret", &mut block);
        assert!(verify_auth_request(&block, "s3cret"));
        assert!(!verify_auth_request(&block, "wrong"));
        assert!(!verify_auth_request(&block, ""));
        let fields = hpack::qpack_fields(&block).expect("reads");
        assert_eq!(fields.len(), 6);
        assert!(fields.contains(&(b":method".to_vec(), b"POST".to_vec())));
        assert!(fields.contains(&(b":authority".to_vec(), b"hysteria".to_vec())));
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
            let frags: Vec<_> = fragments_udp(&message, max).expect("fragments").collect();
            assert_eq!(frags.len(), len.div_ceil(7));
            let mut defrag = Defrag::new();
            let mut assembled = Vec::new();
            let mut whole = None;
            for frag in &frags {
                if let Some((address, payload)) = defrag.feed(frag, &mut assembled).expect("feeds")
                {
                    assert!(whole.is_none(), "assembles exactly once");
                    whole = Some((address.to_owned(), payload.to_owned()));
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

    fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(text, "{b:02x}");
        }
        text
    }

    #[test]
    fn the_salamander_mask_matches_an_independent_blake2b_computation() {
        // Each vector is `salt || payload ^ blake2b-256(password || salt)[i % 32]`, produced with Python's `hashlib.blake2b` — independent of this code, of the Go `finalmask/salamander` and of the Rust `zeronet` reference. v3_32 is the keystream itself (zero payload), v3_33 is the one byte past the 32-byte cycle that re-reads `key[0]`, and v4 is the shortest datagram that carries a payload byte.
        let cases = [
            (
                "gawrgura",
                [1u8, 2, 3, 4, 5, 6, 7, 8],
                (0..80u8).collect::<Vec<u8>>(),
                "0102030405060708dae43f03756d12dfa5973685c6f584d06d593f72a3f029111e05875d3c3f3434fac41f23554d32ff85b716a5e6d5a4f04d791f5283d009313e25a77d1c1f14149aa47f43352d529fe5d776c586b5c490",
            ),
            (
                "1234",
                [0u8, 1, 2, 3, 4, 5, 6, 7],
                (0..100u8).collect::<Vec<u8>>(),
                "00010203040506073be46821092f804a96cded73ec04ddb2d17aa4825be334d9bf53c40f822bcaaa1bc44801290fa06ab6edcd53cc24fd92f15a84a27bc314f99f73e42fa20bea8a7ba42861496fc00ad68dad33ac449df2913ae4c21ba37499ff13844fc26b8aea5b840841",
            ),
            (
                "quic",
                [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4],
                vec![0u8; 32],
                "deadbeef01020304b26c5d46200cda0b7db6ab26f5519932061a50a12328cdd3d2ab3e3a0ebb7b40",
            ),
            (
                "quic",
                [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4],
                vec![0xffu8; 33],
                "deadbeef010203044d93a2b9dff325f4824954d90aae66cdf9e5af5edcd7322c2d54c1c5f14484bf4d",
            ),
            (
                "hy2!",
                [9u8; 8],
                vec![0xa5],
                "090909090909090929",
            ),
        ];
        for (password, salt, plain, want) in cases {
            let salamander = Salamander::new(password).expect("password");
            let mut out = Vec::new();
            salamander.obfuscate_with_salt(&salt, &plain, &mut out);
            assert_eq!(hex(&out), want, "vector for {password:?}");
            // And the mask inverts exactly: the de-obfuscated datagram is the payload back.
            let n = salamander
                .deobfuscate_in_place(&mut out)
                .expect("round-trips");
            assert_eq!(&out[..n], &plain[..]);
        }
    }

    #[test]
    fn the_stack_seal_form_matches_the_vec_oracle_form() {
        // `seal_into`/`obfuscate_into` are the zero-allocation wire path; they must reach the same bytes as the `Vec` form the vectors pin, and `deobfuscate_in_place` inverts the stack-sealed datagram exactly.
        let salamander = Salamander::new("gawrgura").expect("password");
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        for len in [1usize, 32, 33, 1342] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 5 + 1) as u8).collect();
            let mut via_vec = Vec::new();
            salamander.obfuscate_with_salt(&salt, &plain, &mut via_vec);
            let mut via_stack = vec![0u8; SALAMANDER_SALT + len];
            let written = salamander.obfuscate_into(&salt, &plain, &mut via_stack);
            assert_eq!(written, SALAMANDER_SALT + len);
            assert_eq!(via_stack, via_vec, "slice form == vec form, len {len}");
            let n = salamander
                .deobfuscate_in_place(&mut via_stack)
                .expect("inverts");
            assert_eq!(&via_stack[..n], &plain[..]);
        }
        // A seal into a buffer with no room for the salt is refused, not truncated.
        let mut tiny = [0u8; SALAMANDER_SALT];
        assert!(salamander.seal_into(b"too big", &mut tiny).is_none());
    }

    #[test]
    fn salamander_round_trips_every_length_under_a_fresh_salt() {
        let salamander = Salamander::new("gawrgura").expect("password");
        for len in [1usize, 7, 31, 32, 33, 63, 64, 1200, 1342] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut first = Vec::new();
            let mut second = Vec::new();
            salamander.obfuscate(&plain, &mut first).expect("salt");
            salamander.obfuscate(&plain, &mut second).expect("salt");
            assert_eq!(
                first.len(),
                len + SALAMANDER_SALT,
                "salt grows each datagram"
            );
            assert_ne!(
                &first[..SALAMANDER_SALT],
                &second[..SALAMANDER_SALT],
                "a fresh salt per datagram"
            );
            let n = salamander
                .deobfuscate_in_place(&mut first)
                .expect("deobfuscates");
            assert_eq!(n, len);
            assert_eq!(&first[..n], &plain[..], "length {len}");
        }
    }

    #[test]
    fn a_wrong_password_gives_noise_and_short_datagrams_and_weak_keys_are_refused() {
        let right = Salamander::new("gawrgura").expect("password");
        let wrong = Salamander::new("another").expect("password");
        let plain = vec![0xc0u8; 100];
        let mut sealed = Vec::new();
        right.obfuscate(&plain, &mut sealed).expect("salt");
        let n = wrong.deobfuscate_in_place(&mut sealed).expect("length");
        assert_ne!(&sealed[..n], &plain[..], "wrong key is noise");
        // A datagram that cannot hold a salt and one byte de-obfuscates to nothing.
        assert!(right
            .deobfuscate_in_place(&mut [0u8; SALAMANDER_SALT])
            .is_none());
        assert!(right.deobfuscate_in_place(&mut []).is_none());
        // And a password below the floor the server accepts is refused at construction.
        assert!(Salamander::new("abc").is_none());
        assert!(Salamander::new("abcd").is_some());
    }

    #[test]
    fn a_sealed_datagram_never_touches_the_heap() {
        // The wire seal writes into the caller's frame: base and capacity held steady across a fresh salt, so no datagram is copied or reallocated on the way out.
        let salamander = Salamander::new("gawrgura").expect("password");
        let plain: Vec<u8> = (0..1342).map(|i| (i ^ 0x5a) as u8).collect();
        let mut frame = vec![0u8; SALAMANDER_SALT + 1342];
        let base = frame.as_ptr();
        let room = frame.capacity();
        let written = salamander
            .seal_into(&plain, &mut frame)
            .expect("room and salt");
        assert_eq!(written, SALAMANDER_SALT + plain.len());
        assert_eq!(frame.as_ptr(), base, "the frame never moved");
        assert_eq!(frame.capacity(), room, "no reallocation");
        assert_ne!(
            &frame[SALAMANDER_SALT..],
            &plain[..],
            "the payload is masked"
        );
        let n = salamander
            .deobfuscate_in_place(&mut frame[..written])
            .expect("inverts");
        assert_eq!(&frame[..n], &plain[..], "and unmasking returns the bytes");
    }

    #[test]
    fn the_flow_frame_tells_hysteria_from_a_browser_request() {
        let mut hysteria = Vec::new();
        tcp_prefix(&mut hysteria);
        assert!(is_hysteria_flow(&hysteria), "0x401 names a destination");
        assert!(
            !is_hysteria_flow(&[frames::H3_HEADERS as u8, 0]),
            "a HEADERS frame is a browser"
        );
        assert!(
            !is_hysteria_flow(&[frames::H3_DATA as u8, 0]),
            "and so is a DATA frame"
        );
    }

    #[test]
    fn an_h3_response_is_headers_then_data() {
        let mut out = Vec::new();
        encode_h3_response(200, &[("content-type", "text/plain")], b"hi", &mut out);
        let mut at = 0usize;
        let head = frames::h3_frame(&out, &mut at).expect("headers frame");
        assert_eq!(head.kind, frames::H3_HEADERS);
        let block = &out[at..at + head.length as usize];
        let fields = hpack::qpack_fields(block).expect("a qpack block");
        assert_eq!(find(&fields, ":status"), Some(b"200".as_slice()));
        assert_eq!(
            find(&fields, "content-type"),
            Some(b"text/plain".as_slice())
        );
        at += head.length as usize;
        let data = frames::h3_frame(&out, &mut at).expect("data frame");
        assert_eq!(data.kind, frames::H3_DATA);
        assert_eq!(data.length, 2);
        assert_eq!(&out[at..at + 2], b"hi");
    }

    /// One block buffer per answer, sized to the bytes it holds: the code's digits go on the wire from a stack array, no field list is joined ahead of them, and the caller's buffer is never grown by the answer.
    #[test]
    fn an_h3_answer_allocates_only_its_field_block() {
        let headers = [
            ("content-type", "text/html; charset=utf-8"),
            ("server", "nginx"),
        ];
        let need = 2
            + hpack::qpack_field_len(":status".len(), 3)
            + headers
                .iter()
                .map(|(name, value)| hpack::qpack_field_len(name.len(), value.len()))
                .sum::<usize>();
        let mut out = Vec::with_capacity(need + 16);
        encode_h3_response(200, &headers, b"cover", &mut out);
        let block = out.as_ptr();
        let capacity = out.capacity();
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..4096 {
                out.clear();
                encode_h3_response(200, &headers, b"cover", &mut out);
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (4096, 4096 * need, 0),
            "one block of {need} bytes per answer, and nothing joined or grown on the way"
        );
        assert_eq!(
            (out.as_ptr(), out.capacity()),
            (block, capacity),
            "the answer never moved or grew the caller's own buffer"
        );
    }

    #[test]
    fn a_bodyless_response_is_headers_alone() {
        let mut out = Vec::new();
        encode_h3_response(404, &[("content-type", "text/plain")], b"", &mut out);
        let mut at = 0usize;
        let head = frames::h3_frame(&out, &mut at).expect("headers frame");
        assert_eq!(head.kind, frames::H3_HEADERS);
        assert_eq!(
            at + head.length as usize,
            out.len(),
            "no DATA frame follows"
        );
    }

    #[test]
    fn a_browser_get_parses_to_method_path_and_authority() {
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", "/index.html"),
                ("user-agent", "curl/8"),
            ],
            &mut block,
        );
        let request = parse_h3_request(&block).expect("a request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/index.html");
        assert_eq!(request.authority, "example.com");
        assert_eq!(
            request.headers,
            vec![("user-agent".into(), "curl/8".into())]
        );
        assert!(
            request.body.is_empty(),
            "the DATA body is the caller's to append"
        );
        let mut not_a_request = Vec::new();
        hpack::qpack_literal_many(&[(":status", "200")], &mut not_a_request);
        assert!(
            parse_h3_request(&not_a_request).is_none(),
            "a response block names no :method"
        );
    }

    #[test]
    fn a_chunked_origin_body_defragments_to_its_bytes() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let response = parse_origin_response(raw).expect("a chunked response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello world");
        let plain = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabctrailing";
        let response = parse_origin_response(plain).expect("a lengthed response");
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"abc", "content-length bounds the body");
        assert!(
            parse_origin_response(b"HTTP/1.1 200 OK\r\n").is_none(),
            "a head that never reaches its blank line is not a response"
        );
    }

    #[test]
    fn content_type_maps_the_common_extensions() {
        assert_eq!(content_type("/index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("/a/b.PNG"), "image/png");
        assert_eq!(content_type("/app.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("page.html?v=2"), "text/html; charset=utf-8");
        assert_eq!(content_type("/noextension"), "application/octet-stream");
        assert_eq!(content_type("/file.unknown"), "application/octet-stream");
    }

    #[test]
    fn a_hop_never_lands_back_on_the_port_it_just_left() {
        let ports = [1000u16, 1001, 1002, 1003];
        for roll in 0..200 {
            let next = pick_next(&ports, 1001, roll);
            assert!(ports.contains(&next) && next != 1001, "moved to {next}");
        }
        // A single port has nowhere else to go, so the plan stays on it.
        assert_eq!(pick_next(&[443], 443, 7), 443);
        // An empty plan yields the port to avoid, unchanged.
        assert_eq!(pick_next(&[], 443, 7), 443);
    }

    #[test]
    fn a_stay_is_drawn_inside_its_range() {
        for roll in 0..200 {
            let stay = stay_ms((5000, 10_000), roll);
            assert!((5000..=10_000).contains(&stay), "stay {stay}");
        }
        // No room in the window: the stay is exactly the low bound.
        assert_eq!(stay_ms((3000, 3000), 999), 3000);
    }

    #[test]
    fn the_plan_expands_overlapping_ranges_into_one_sorted_set() {
        let hop = Hop {
            ranges: vec![
                PortRange {
                    start: 9000,
                    end: 9001,
                },
                PortRange {
                    start: 9001,
                    end: 9002,
                },
                PortRange {
                    start: 443,
                    end: 443,
                },
            ],
            interval_ms: (5000, 5000),
        };
        assert_eq!(hop.ports(), vec![443, 9000, 9001, 9002]);
        assert!(is_hop_port(&hop.ports(), 9, 9001));
        assert!(is_hop_port(&hop.ports(), 443, 443));
        assert!(!is_hop_port(&hop.ports(), 443, 50000));
    }

    #[test]
    fn a_gecko_frame_is_the_exact_bytes_the_reference_emits() {
        let frame = GeckoFrame {
            msg_id: 7,
            chunk_idx: 2,
            total_chunks: 6,
            pad_len: 3,
        };
        let mut out = [0u8; 16];
        let written =
            encode_gecko_frame(frame, b"pad", b"hi", &mut out).expect("a well-sized frame");
        // flag, msg, chunk<<4|total, pad_len big-endian, the three pad bytes, then payload.
        assert_eq!(
            &out[..written],
            [0x80, 7, 0x26, 0, 3, b'p', b'a', b'd', b'h', b'i']
        );
        assert_eq!(written, GECKO_HEADER + 3 + 2);
    }

    #[test]
    fn a_gecko_frame_decodes_its_payload_without_a_copy() {
        let frame = GeckoFrame {
            msg_id: 1,
            chunk_idx: 0,
            total_chunks: GECKO_MIN_CHUNKS as u8,
            pad_len: 4,
        };
        let mut buf = vec![0u8; GECKO_HEADER + 4 + 5];
        encode_gecko_frame(frame, b"abcd", b"hello", &mut buf).expect("room");
        let (got, payload) = decode_gecko_frame(&buf).expect("a valid frame");
        assert_eq!(got, frame);
        assert_eq!(payload, b"hello");
        // The zero-copy witness: the payload borrows the frame buffer, so its base sits at exactly `GECKO_HEADER + pad_len` inside it.
        let base = buf.as_ptr() as usize;
        let at = payload.as_ptr() as usize;
        assert_eq!(at, base + GECKO_HEADER + 4);
        assert!(at > base && at + payload.len() <= base + buf.len());
    }

    #[test]
    fn a_forged_or_truncated_frame_is_refused_and_the_buffer_held() {
        // A valid header would be idx 2 of 3 (`0x23`), pad length read from bytes 3-4.
        let mut frame = [GECKO_FLAG, 0, 0x23, 0, 0, b'x'];
        // A chunk index not below the total is refused.
        frame[2] = 0x22;
        assert!(decode_gecko_frame(&frame).is_none());
        // A total under the two-chunk minimum is refused.
        frame[2] = 0x11;
        assert!(decode_gecko_frame(&frame).is_none());
        // A cleared fragment marker is a short-header packet, not a frame.
        frame[0] = 0x00;
        assert!(decode_gecko_frame(&frame).is_none());
        frame[0] = GECKO_FLAG;
        // A pad length that fits the buffer parses, with the payload empty at the end.
        frame[2] = 0x23;
        frame[4] = 1;
        assert!(decode_gecko_frame(&frame).is_some());
        // A pad length reaching past the buffer is refused, and the bytes are held.
        frame[4] = 200;
        let before = frame;
        assert!(decode_gecko_frame(&frame).is_none());
        assert_eq!(frame, before, "a refusal never rewrote the input");
        // A buffer too short to even hold a header is refused.
        assert!(decode_gecko_frame(&frame[..GECKO_HEADER - 1]).is_none());
    }

    #[test]
    fn a_fragmented_long_header_packet_reassembles_bit_identical() {
        // A QUIC long-header packet (byte 0 high bit set) at a length the chunk count does not divide, so the last chunk takes a real remainder.
        let mut packet: Vec<u8> = (0u8..=255).cycle().take(1234).collect();
        packet[0] |= GECKO_FLAG;
        let total = 3usize;
        let mut frames = Vec::new();
        for idx in 0..total {
            let (start, end) = gecko_chunk_range(packet.len(), idx, total).expect("a chunk");
            let payload = &packet[start..end];
            let mut buf = vec![0u8; GECKO_HEADER + payload.len()];
            encode_gecko_frame(
                GeckoFrame {
                    msg_id: 42,
                    chunk_idx: idx as u8,
                    total_chunks: total as u8,
                    pad_len: 0,
                },
                b"",
                payload,
                &mut buf,
            )
            .expect("room");
            frames.push(buf);
        }
        let mut out = Vec::new();
        for buf in &frames {
            let (frame, payload) = decode_gecko_frame(buf).expect("valid");
            out.extend_from_slice(payload);
            assert_eq!(frame.msg_id, 42);
        }
        assert_eq!(out, packet, "the chunks rebuild the packet exactly");
    }

    #[test]
    fn a_pad_lands_the_sealed_datagram_inside_its_window() {
        let (min, max) = (512usize, 1200usize);
        let salt_head = SALAMANDER_SALT + GECKO_HEADER;
        // A small chunk: the pad drags the sealed size into [min, max] for every roll.
        let base = salt_head + 40;
        for roll in 0..64u64 {
            let pad = gecko_pad_len(min, max, base, roll) as usize;
            let sealed = base + pad;
            assert!(
                (min..=max).contains(&sealed),
                "a padded datagram fits the window"
            );
        }
        // A chunk already past max gets no pad rather than a negative one.
        assert_eq!(gecko_pad_len(min, max, salt_head + 2000, 7), 0);
    }

    #[test]
    fn a_chunk_range_partitions_a_packet_without_gaps() {
        for len in [1usize, 7, 1500, 1501] {
            for total in [2usize, 5, 8] {
                let mut cursor = 0;
                for idx in 0..total {
                    let (start, end) = gecko_chunk_range(len, idx, total).expect("valid");
                    assert_eq!(start, cursor, "chunks are contiguous");
                    assert!(end <= len);
                    cursor = end;
                }
                assert_eq!(cursor, len, "the last chunk took the remainder");
            }
        }
        assert!(gecko_chunk_range(10, 0, 0).is_none());
        assert!(gecko_chunk_range(10, 3, 3).is_none());
    }
}
