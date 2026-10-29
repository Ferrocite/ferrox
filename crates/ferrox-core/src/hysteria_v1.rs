//! Hysteria version 1 framing: the bytes around the QUIC streams and datagrams — a binary control stream carries the version, rates and credential; every TCP flow is one bidirectional stream opening with a `udp` flag and a `host:port`; and the UDP lane rides QUIC datagrams each carrying a session id, an address and fragment metadata.

use crate::hysteria::RequestError;

/// The version byte that opens the control stream; a peer naming any other refuses the connection.
pub const PROTOCOL_VERSION: u8 = 3;

/// The ALPN every Hysteria v1 connection names.
pub const ALPN: &[u8] = b"hysteria";

/// The largest credential a hello may carry: the length field's own ceiling.
pub const MAX_AUTH: usize = u16::MAX as usize;

/// The largest address a request or datagram may name: the length field's own ceiling.
pub const MAX_ADDRESS: usize = u16::MAX as usize;

/// The largest UDP payload one datagram may carry.
pub const MAX_UDP_PAYLOAD: usize = 65535;

/// Bytes of random salt in front of every xplus-obfuscated datagram.
pub const XPLUS_SALT: usize = 16;

/// The SHA-256 keystream block, tiled cyclically over a payload.
const XPLUS_KEY: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello<'a> {
    pub send_bps: u64,
    pub recv_bps: u64,
    pub auth: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello<'a> {
    pub ok: bool,
    pub send_bps: u64,
    pub recv_bps: u64,
    pub message: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRequest<'a> {
    pub udp: bool,
    pub host: &'a str,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerResponse<'a> {
    pub ok: bool,
    pub udp_session_id: u32,
    pub message: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpMessage<'a> {
    pub session: u32,
    pub host: &'a str,
    pub port: u16,
    pub packet: u16,
    pub frag: u8,
    pub frags: u8,
    pub payload: &'a [u8],
}

impl UdpMessage<'_> {
    #[must_use]
    pub fn header_len(&self) -> usize {
        14 + self.host.len()
    }

    #[must_use]
    pub fn validate(&self) -> bool {
        !self.host.is_empty()
            && self.host.len() <= MAX_ADDRESS
            && !self.payload.is_empty()
            && self.payload.len() <= MAX_UDP_PAYLOAD
            && self.frags != 0
            && (self.frags == 1 || (self.packet != 0 && self.frag < self.frags))
    }
}

fn take<'a>(packet: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8], RequestError> {
    let end = at.checked_add(len).ok_or(RequestError::Invalid)?;
    let bytes = packet.get(*at..end).ok_or(RequestError::Incomplete)?;
    *at = end;
    Ok(bytes)
}

fn take_u8(packet: &[u8], at: &mut usize) -> Result<u8, RequestError> {
    Ok(take(packet, at, 1)?[0])
}

fn take_u16(packet: &[u8], at: &mut usize) -> Result<u16, RequestError> {
    let bytes = take(packet, at, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_u32(packet: &[u8], at: &mut usize) -> Result<u32, RequestError> {
    let bytes = take(packet, at, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn take_u64(packet: &[u8], at: &mut usize) -> Result<u64, RequestError> {
    let bytes = take(packet, at, 8)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub fn encode_client_hello(hello: &ClientHello<'_>, out: &mut Vec<u8>) {
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(&hello.send_bps.to_be_bytes());
    out.extend_from_slice(&hello.recv_bps.to_be_bytes());
    out.extend_from_slice(&(hello.auth.len() as u16).to_be_bytes());
    out.extend_from_slice(hello.auth);
}

/// Read the version byte, the rates and the credential; `used` is the bytes consumed, so a caller can hand the rest of the stream to the flow that follows.
pub fn decode_client_hello(packet: &[u8]) -> Result<(ClientHello<'_>, usize), RequestError> {
    let mut at = 0usize;
    let version = take_u8(packet, &mut at)?;
    if version != PROTOCOL_VERSION {
        return Err(RequestError::Invalid);
    }
    let send_bps = take_u64(packet, &mut at)?;
    let recv_bps = take_u64(packet, &mut at)?;
    if send_bps == 0 || recv_bps == 0 {
        return Err(RequestError::Invalid);
    }
    let auth_len = usize::from(take_u16(packet, &mut at)?);
    if auth_len > MAX_AUTH {
        return Err(RequestError::Invalid);
    }
    let auth = take(packet, &mut at, auth_len)?;
    Ok((
        ClientHello {
            send_bps,
            recv_bps,
            auth,
        },
        at,
    ))
}

pub fn encode_server_hello(hello: &ServerHello<'_>, out: &mut Vec<u8>) {
    out.push(u8::from(hello.ok));
    out.extend_from_slice(&hello.send_bps.to_be_bytes());
    out.extend_from_slice(&hello.recv_bps.to_be_bytes());
    out.extend_from_slice(&(hello.message.len() as u16).to_be_bytes());
    out.extend_from_slice(hello.message);
}

pub fn decode_server_hello(packet: &[u8]) -> Result<(ServerHello<'_>, usize), RequestError> {
    let mut at = 0usize;
    let ok = take_u8(packet, &mut at)? != 0;
    let send_bps = take_u64(packet, &mut at)?;
    let recv_bps = take_u64(packet, &mut at)?;
    let message_len = usize::from(take_u16(packet, &mut at)?);
    if message_len > MAX_AUTH {
        return Err(RequestError::Invalid);
    }
    let message = take(packet, &mut at, message_len)?;
    Ok((
        ServerHello {
            ok,
            send_bps,
            recv_bps,
            message,
        },
        at,
    ))
}

pub fn encode_client_request(request: &ClientRequest<'_>, payload: &[u8], out: &mut Vec<u8>) {
    out.push(u8::from(request.udp));
    out.extend_from_slice(&(request.host.len() as u16).to_be_bytes());
    out.extend_from_slice(request.host.as_bytes());
    out.extend_from_slice(&request.port.to_be_bytes());
    out.extend_from_slice(payload);
}

/// Read a request and report how many bytes it took; the stream payload follows it untouched.
pub fn decode_client_request(packet: &[u8]) -> Result<(ClientRequest<'_>, usize), RequestError> {
    let mut at = 0usize;
    let udp = take_u8(packet, &mut at)? != 0;
    let host_len = usize::from(take_u16(packet, &mut at)?);
    if host_len > MAX_ADDRESS {
        return Err(RequestError::Invalid);
    }
    let raw = take(packet, &mut at, host_len)?;
    let host = std::str::from_utf8(raw).map_err(|_| RequestError::Invalid)?;
    let port = take_u16(packet, &mut at)?;
    if !udp && host.is_empty() {
        return Err(RequestError::Invalid);
    }
    Ok((ClientRequest { udp, host, port }, at))
}

pub fn encode_server_response(response: &ServerResponse<'_>, out: &mut Vec<u8>) {
    out.push(u8::from(response.ok));
    out.extend_from_slice(&response.udp_session_id.to_be_bytes());
    out.extend_from_slice(&(response.message.len() as u16).to_be_bytes());
    out.extend_from_slice(response.message);
}

pub fn decode_server_response(packet: &[u8]) -> Result<(ServerResponse<'_>, usize), RequestError> {
    let mut at = 0usize;
    let ok = take_u8(packet, &mut at)? != 0;
    let udp_session_id = take_u32(packet, &mut at)?;
    let message_len = usize::from(take_u16(packet, &mut at)?);
    if message_len > MAX_AUTH {
        return Err(RequestError::Invalid);
    }
    let message = take(packet, &mut at, message_len)?;
    Ok((
        ServerResponse {
            ok,
            udp_session_id,
            message,
        },
        at,
    ))
}

pub fn encode_udp(message: &UdpMessage<'_>, out: &mut Vec<u8>) -> Result<(), RequestError> {
    if !message.validate() {
        return Err(RequestError::Invalid);
    }
    out.extend_from_slice(&message.session.to_be_bytes());
    out.extend_from_slice(&(message.host.len() as u16).to_be_bytes());
    out.extend_from_slice(message.host.as_bytes());
    out.extend_from_slice(&message.port.to_be_bytes());
    out.extend_from_slice(&message.packet.to_be_bytes());
    out.push(message.frag);
    out.push(message.frags);
    out.extend_from_slice(&(message.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(message.payload);
    Ok(())
}

pub fn decode_udp(packet: &[u8]) -> Result<UdpMessage<'_>, RequestError> {
    let mut at = 0usize;
    let session = take_u32(packet, &mut at)?;
    let host_len = usize::from(take_u16(packet, &mut at)?);
    if host_len > MAX_ADDRESS {
        return Err(RequestError::Invalid);
    }
    let raw = take(packet, &mut at, host_len)?;
    let host = std::str::from_utf8(raw).map_err(|_| RequestError::Invalid)?;
    let port = take_u16(packet, &mut at)?;
    let packet_id = take_u16(packet, &mut at)?;
    let frag = take_u8(packet, &mut at)?;
    let frags = take_u8(packet, &mut at)?;
    let data_len = usize::from(take_u16(packet, &mut at)?);
    let payload = take(packet, &mut at, data_len)?;
    if at != packet.len() {
        return Err(RequestError::Invalid);
    }
    let message = UdpMessage {
        session,
        host,
        port,
        packet: packet_id,
        frag,
        frags,
        payload,
    };
    if !message.validate() {
        return Err(RequestError::Invalid);
    }
    Ok(message)
}

/// One message's fragments, walked in order without a list: every payload chunk borrows the message's own bytes.
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

pub fn fragments_udp<'a>(
    message: &UdpMessage<'a>,
    max: usize,
) -> Result<Fragments<'a>, RequestError> {
    if !message.validate() || message.frags != 1 {
        return Err(RequestError::Invalid);
    }
    let capacity = max
        .checked_sub(message.header_len())
        .filter(|room| *room > 0)
        .ok_or(RequestError::Invalid)?;
    let total = u8::try_from(message.payload.len().div_ceil(capacity))
        .map_err(|_| RequestError::Invalid)?;
    if total > 1 && message.packet == 0 {
        return Err(RequestError::Invalid);
    }
    Ok(Fragments {
        message: *message,
        chunks: message.payload.chunks(capacity),
        next: 0,
        total,
    })
}

/// Reassembly of one session's datagrams: at most one incomplete packet, a new packet id discarding the previous partial, fragments delivered in id order once every slot fills.
#[derive(Debug, Default)]
pub struct Defrag {
    session: u32,
    packet: u16,
    host: String,
    port: u16,
    slots: Vec<Option<Vec<u8>>>,
    have: usize,
    size: usize,
}

impl Defrag {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one message in; `Some(message)` when a datagram is whole. A single fragment passes straight through, borrowing the caller's datagram.
    pub fn feed<'a>(
        &mut self,
        message: &UdpMessage<'a>,
        out: &'a mut Vec<u8>,
    ) -> Result<Option<UdpMessage<'a>>, RequestError> {
        if !message.validate() {
            return Err(RequestError::Invalid);
        }
        if message.frags == 1 {
            *self = Self::default();
            return Ok(Some(*message));
        }
        if self.slots.is_empty() || self.packet != message.packet || self.session != message.session
        {
            self.packet = message.packet;
            self.session = message.session;
            message.host.clone_into(&mut self.host);
            self.port = message.port;
            self.slots = vec![None; usize::from(message.frags)];
            self.have = 0;
            self.size = 0;
        }
        if self.host != message.host
            || self.port != message.port
            || self.slots.len() != usize::from(message.frags)
        {
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
        self.host.clear();
        out.clear();
        out.reserve(size);
        for fragment in std::mem::take(&mut self.slots).into_iter().flatten() {
            out.extend_from_slice(&fragment);
        }
        self.have = 0;
        self.size = 0;
        Ok(Some(UdpMessage {
            session: message.session,
            host: message.host,
            port: message.port,
            packet: message.packet,
            frag: 0,
            frags: 1,
            payload: out,
        }))
    }
}

/// `XPlus`, the Hysteria v1 datagram obfuscation.
///
/// Every datagram on the wire becomes `salt (16 random bytes) || payload XORed against the keystream`, where the keystream is `SHA-256(password || salt)` tiled cyclically over the payload.
#[derive(Clone)]
pub struct XPlus {
    key: Vec<u8>,
}

impl core::fmt::Debug for XPlus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XPlus(..)")
    }
}

impl XPlus {
    /// `None` when the password is empty, which the references treat as no obfuscation rather than a key.
    #[must_use]
    pub fn new(password: &str) -> Option<Self> {
        if password.is_empty() {
            return None;
        }
        Some(Self {
            key: password.as_bytes().to_vec(),
        })
    }

    fn keystream(&self, salt: [u8; XPLUS_SALT]) -> [u8; XPLUS_KEY] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(&self.key);
        hash.update(salt);
        hash.finalize().into()
    }

    /// Prepend `salt`, then append `plain` masked by its keystream.
    pub fn obfuscate_with_salt(&self, salt: &[u8; XPLUS_SALT], plain: &[u8], out: &mut Vec<u8>) {
        let key = self.keystream(*salt);
        let body = out.len() + XPLUS_SALT;
        out.reserve(XPLUS_SALT + plain.len());
        out.extend_from_slice(salt);
        out.extend_from_slice(plain);
        crate::keystream::apply(&mut out[body..], &key);
    }

    /// Obfuscate `plain` under a fresh random salt appended to `out`; `None` only when the system RNG fails.
    pub fn obfuscate(&self, plain: &[u8], out: &mut Vec<u8>) -> Option<()> {
        let mut salt = [0u8; XPLUS_SALT];
        getrandom::fill(&mut salt).ok()?;
        self.obfuscate_with_salt(&salt, plain, out);
        Some(())
    }

    /// Write the masked `plain` behind `salt` into the front of `out` and return the total length.
    #[must_use]
    pub fn obfuscate_into(&self, salt: &[u8; XPLUS_SALT], plain: &[u8], out: &mut [u8]) -> usize {
        let key = self.keystream(*salt);
        out[..XPLUS_SALT].copy_from_slice(salt);
        let body = &mut out[XPLUS_SALT..XPLUS_SALT + plain.len()];
        crate::keystream::encrypt(body, plain, &key);
        XPLUS_SALT + plain.len()
    }

    /// Seal one outgoing datagram into `out`, returning the written length.
    pub fn seal_into(&self, plain: &[u8], out: &mut [u8]) -> Option<usize> {
        let need = plain.len().checked_add(XPLUS_SALT)?;
        if out.len() < need {
            return None;
        }
        let mut salt = [0u8; XPLUS_SALT];
        getrandom::fill(&mut salt).ok()?;
        Some(self.obfuscate_into(&salt, plain, out))
    }

    /// Undo [`XPlus::obfuscate`] on one whole datagram in place, moving the payload to the front.
    pub fn deobfuscate_in_place(&self, datagram: &mut [u8]) -> Option<usize> {
        if datagram.len() <= XPLUS_SALT {
            return None;
        }
        let mut salt = [0u8; XPLUS_SALT];
        salt.copy_from_slice(&datagram[..XPLUS_SALT]);
        let key = self.keystream(salt);
        Some(crate::keystream::unshift(datagram, XPLUS_SALT, &key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_hello_is_the_exact_bytes_the_reference_emits() {
        let mut out = Vec::new();
        encode_client_hello(
            &ClientHello {
                send_bps: 0x0102_0304_0506_0708,
                recv_bps: 0x1112_1314_1516_1718,
                auth: b"pw",
            },
            &mut out,
        );
        assert_eq!(
            out,
            [
                3, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0, 2,
                b'p', b'w'
            ]
        );
        let (hello, used) = decode_client_hello(&out).expect("decodes");
        assert_eq!(used, out.len());
        assert_eq!(hello.auth, b"pw");
        assert_eq!(hello.send_bps, 0x0102_0304_0506_0708);
        assert_eq!(hello.recv_bps, 0x1112_1314_1516_1718);
    }

    #[test]
    fn a_server_hello_and_response_are_the_exact_bytes_the_reference_emits() {
        let mut hello = Vec::new();
        encode_server_hello(
            &ServerHello {
                ok: true,
                send_bps: 7,
                recv_bps: 9,
                message: b"",
            },
            &mut hello,
        );
        assert_eq!(
            hello,
            [1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0]
        );
        let mut response = Vec::new();
        encode_server_response(
            &ServerResponse {
                ok: true,
                udp_session_id: 0x0102_0304,
                message: b"",
            },
            &mut response,
        );
        assert_eq!(response, [1, 1, 2, 3, 4, 0, 0]);
    }

    #[test]
    fn a_client_request_is_the_exact_bytes_the_reference_emits() {
        let mut tcp = Vec::new();
        encode_client_request(
            &ClientRequest {
                udp: false,
                host: "example.org",
                port: 443,
            },
            b"",
            &mut tcp,
        );
        assert_eq!(
            tcp,
            [0, 0, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g', 1, 187]
        );
        let (request, used) = decode_client_request(&tcp).expect("decodes");
        assert_eq!(used, tcp.len());
        assert!(!request.udp);
        assert_eq!(request.host, "example.org");
        assert_eq!(request.port, 443);
        let mut udp = Vec::new();
        encode_client_request(
            &ClientRequest {
                udp: true,
                host: "",
                port: 0,
            },
            b"",
            &mut udp,
        );
        assert_eq!(udp, [1, 0, 0, 0, 0]);
        assert!(decode_client_request(&udp).expect("decodes").0.udp);
    }

    #[test]
    fn a_udp_message_is_the_exact_bytes_the_reference_emits() {
        let message = UdpMessage {
            session: 0x0102_0304,
            host: "a",
            port: 53,
            packet: 0,
            frag: 0,
            frags: 1,
            payload: b"hi",
        };
        let mut out = Vec::new();
        encode_udp(&message, &mut out).expect("encodes");
        assert_eq!(
            out,
            [1, 2, 3, 4, 0, 1, b'a', 0, 53, 0, 0, 0, 1, 0, 2, b'h', b'i']
        );
        let decoded = decode_udp(&out).expect("decodes");
        assert_eq!(decoded, message);
    }

    #[test]
    fn every_length_survives_fragment_then_defrag_intact() {
        for len in 1..=200usize {
            let payload = vec![len as u8; len];
            let message = UdpMessage {
                session: 9,
                host: "example.org",
                port: 443,
                packet: 7,
                frag: 0,
                frags: 1,
                payload: &payload,
            };
            let mut defrag = Defrag::new();
            let mut out = Vec::new();
            let mut seen = 0usize;
            for fragment in fragments_udp(&message, 40).expect("fragments") {
                let mut wire = Vec::new();
                encode_udp(&fragment, &mut wire).expect("encodes");
                let decoded = decode_udp(&wire).expect("decodes");
                seen += decoded.payload.len();
                if let Some(whole) = defrag.feed(&decoded, &mut out).expect("feeds") {
                    assert_eq!(whole.payload, payload.as_slice());
                }
            }
            assert_eq!(seen, len);
        }
    }

    #[test]
    fn a_decoded_datagram_leaves_its_payload_where_it_landed() {
        let mut wire = Vec::new();
        let message = UdpMessage {
            session: 1,
            host: "example.org",
            port: 443,
            packet: 0,
            frag: 0,
            frags: 1,
            payload: b"payload",
        };
        encode_udp(&message, &mut wire).expect("encodes");
        let base = wire.as_ptr();
        let decoded = decode_udp(&wire).expect("decodes");
        assert_eq!(
            decoded.payload.as_ptr(),
            base.wrapping_add(decoded.header_len())
        );
    }

    #[test]
    fn the_xplus_mask_wraps_every_phase_identically() {
        let xplus = XPlus::new("Vaundy").expect("key");
        let salt: [u8; XPLUS_SALT] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let key = xplus.keystream(salt);
        for len in 1..=160usize {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let mut want = salt.to_vec();
            want.extend((0..len).map(|i| plain[i] ^ key[i % XPLUS_KEY]));
            let mut out = Vec::new();
            xplus.obfuscate_with_salt(&salt, &plain, &mut out);
            assert_eq!(out, want, "vec form at {len}");
            let mut stack = vec![0u8; XPLUS_SALT + len];
            assert_eq!(xplus.obfuscate_into(&salt, &plain, &mut stack), want.len());
            assert_eq!(stack, want, "stack form at {len}");
            let n = xplus.deobfuscate_in_place(&mut out).expect("unmasks");
            assert_eq!(&out[..n], &plain[..], "round trip at {len}");
        }
    }

    #[test]
    fn the_xplus_mask_matches_an_independent_sha256_computation() {
        let xplus = XPlus::new("Vaundy").expect("key");
        let salt: [u8; XPLUS_SALT] = core::array::from_fn(|i| i as u8);
        let mut out = Vec::new();
        xplus.obfuscate_with_salt(&salt, b"HelloWorld", &mut out);
        assert_eq!(
            out,
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x79, 0x80, 0x9b, 0x32, 0xab,
                0x70, 0x83, 0xbd, 0x7d, 0x9b
            ]
        );
        let mut wire = out;
        let plain = xplus.deobfuscate_in_place(&mut wire).expect("unmasks");
        assert_eq!(&wire[..plain], b"HelloWorld");
    }
}
