use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::addr::Addr;
use crate::policy::UnsafeOptIn;
use crate::transport::{Security, Support, TransportKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessLink {
    pub uuid: String,
    uuid_bytes: [u8; 16],
    pub host: String,
    pub port: u16,
    params: BTreeMap<String, String>,
    /// The flow the link was parsed with, decided once: the header encoder asks this
    /// every time it writes, and a map lookup per header is a tree walk per header.
    vision: bool,
    pub name: String,
}

impl VlessLink {
    pub fn parse(link: &str) -> Result<Self, VlessError> {
        let rest = link.strip_prefix("vless://").ok_or(VlessError::Scheme)?;
        let (before_hash, name_enc) = match rest.split_once('#') {
            Some((a, b)) => (a, b),
            None => (rest, ""),
        };
        let (before_q, query) = match before_hash.split_once('?') {
            Some((a, b)) => (a, b),
            None => (before_hash, ""),
        };
        let (uuid, hostport) = before_q.split_once('@').ok_or(VlessError::Shape)?;
        validate_uuid(uuid)?;
        let (host, port_str) = hostport.rsplit_once(':').ok_or(VlessError::Shape)?;
        if host.is_empty() {
            return Err(VlessError::Shape);
        }
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let port: u16 = port_str.parse().map_err(|_| VlessError::Port)?;
        let mut params = BTreeMap::new();
        if !query.is_empty() {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                params.insert(percent_decode(k), percent_decode(v));
            }
        }
        let uuid_lower = uuid.to_ascii_lowercase();
        let uuid_bytes_val = uuid_bytes(&uuid_lower);
        let vision = params
            .get("flow")
            .is_some_and(|flow| is_vision_name(flow.as_str()));
        Ok(Self {
            uuid: uuid_lower,
            uuid_bytes: uuid_bytes_val,
            host: host.to_string(),
            port,
            params,
            vision,
            name: percent_decode(name_enc),
        })
    }

    /// Sets one query parameter. The flow decides what the header writes, so a link
    /// that changes its flow changes that too.
    pub fn set_param(&mut self, key: &str, value: &str) {
        self.params.insert(key.to_owned(), value.to_owned());
        if key == "flow" {
            self.vision = is_vision_name(value);
        }
    }

    #[must_use]
    pub fn param(&self, key: &str) -> &str {
        self.params.get(key).map_or("", String::as_str)
    }

    #[must_use]
    pub fn transport_kind(&self) -> TransportKind {
        TransportKind::from_link(self.param("type"))
    }

    #[must_use]
    pub fn security(&self) -> Security {
        Security::from_link(self.param("security"), &self.host)
    }

    #[must_use]
    pub fn flow(&self) -> &str {
        let f = self.param("flow");
        if f.is_empty() {
            "none"
        } else {
            f
        }
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        self.param("fp")
    }

    #[must_use]
    pub fn wants_unsafe_fingerprint(&self) -> bool {
        self.fingerprint().starts_with("unsafe-") || self.param("allowUnsafeFp") == "1"
    }

    #[must_use]
    pub fn reality_pbk(&self) -> &str {
        self.param("pbk")
    }

    #[must_use]
    pub fn reality_sid(&self) -> &str {
        self.param("sid")
    }

    #[must_use]
    pub fn sni(&self) -> &str {
        self.param("sni")
    }

    #[must_use]
    pub fn encryption(&self) -> &str {
        let e = self.param("encryption");
        if e.is_empty() {
            "none"
        } else {
            e
        }
    }

    #[must_use]
    pub fn has_encryption(&self) -> bool {
        self.encryption() != "none"
    }

    #[must_use]
    pub fn is_first_method(&self) -> bool {
        self.transport_kind() == TransportKind::Tcp
            && matches!(self.security(), Security::Reality)
            && self.param("encryption") == "none"
            && self.is_vision_flow()
    }

    /// The plain TCP `security=none`, `encryption=none`, `flow=none` session, judged on a security
    /// the caller has already resolved — the public destination is a policy gate, not a different
    /// set of bytes, so the classification reads the same for `None` and a consented `NoneToPublic`.
    #[must_use]
    fn is_none_method_for(&self, security: Security) -> bool {
        self.transport_kind() == TransportKind::Tcp
            && security == Security::None
            && self.param("encryption") == "none"
            && self.flow() == "none"
    }

    #[must_use]
    pub fn is_none_private_method(&self) -> bool {
        self.is_none_method_for(self.security())
    }

    /// The verdict under no unsafe consent: what a bare link is worth to a default-configured operator.
    #[must_use]
    pub fn support(&self) -> Support {
        self.support_opted(UnsafeOptIn::none())
    }

    /// The verdict given an operator's out-of-band consent. Two vetoes a bare link raises become
    /// diallable only when the matching consent is present: an `unsafe-*` fingerprint, because this
    /// tree dials the stock stdlib hello under any fingerprint (`PattNG`: unsafe means Go
    /// `crypto/tls`, not uTLS, so there is nothing to spoof); and `security=none` to a public
    /// address, because a cleartext credential reaching the internet is a leak the default operator
    /// never asks for. The two consents are independent — clearing one leaves the other's veto.
    /// A consented cleartext session is byte-for-byte the private one, so every rung below reads it
    /// as `Security::None` and reports the method the private link reports.
    #[must_use]
    pub fn support_opted(&self, opt_in: UnsafeOptIn) -> Support {
        if self.has_encryption() {
            if self.transport_kind() == TransportKind::Tcp
                && crate::vless_encryption::ClientConfig::parse(self.encryption()).is_ok()
            {
                let method = match self.security() {
                    Security::None | Security::NoneToPublic => "vless-tcp-encryption",
                    Security::Tls => "vless-tcp-tls-encryption",
                    Security::Reality => "vless-tcp-reality-encryption",
                    Security::Other => {
                        return Support::Planned {
                            reason: "vless-encryption: unsupported security",
                        };
                    }
                };
                return Support::Implemented { method };
            }
            return Support::Planned {
                reason: "vless-encryption: unsupported carrier or malformed mlkem768x25519plus key",
            };
        }
        if self.is_first_method() {
            if self.wants_unsafe_fingerprint() && !opt_in.unsafe_fingerprint() {
                return Support::UnsafeRequiresOptIn {
                    reason: "unsafe fingerprint requested: re-run with explicit opt-in",
                };
            }
            return Support::Implemented {
                method: "vless-tcp-reality-vision",
            };
        }
        let security = match self.security() {
            Security::NoneToPublic if opt_in.plaintext_to_public() => Security::None,
            Security::NoneToPublic => {
                return Support::UnsafeRequiresOptIn {
                    reason:
                        "security=none to a public address (`PattNG` extension): explicit opt-in required",
                };
            }
            other => other,
        };
        if self.is_none_method_for(security) {
            if self.wants_unsafe_fingerprint() && !opt_in.unsafe_fingerprint() {
                return Support::UnsafeRequiresOptIn {
                    reason: "unsafe fingerprint requested: re-run with explicit opt-in",
                };
            }
            return Support::Implemented {
                method: "vless-tcp-none",
            };
        }
        let session = security == Security::None
            && self.param("encryption") == "none"
            && self.flow() == "none";
        if session {
            if let Some(method) = carrier_method(self.transport_kind()) {
                return Support::Implemented { method };
            }
        }
        if self.transport_kind() == TransportKind::Tcp && security == Security::Tls {
            if self.is_vision_flow() {
                return Support::Implemented {
                    method: "vless-tcp-tls-vision",
                };
            }
            if matches!(self.flow(), "" | "none") {
                return Support::Implemented {
                    method: "vless-tcp-tls",
                };
            }
        }
        if security == Security::Tls && matches!(self.flow(), "" | "none") {
            let method = match self.transport_kind() {
                TransportKind::Ws => Some("vless-ws-tls"),
                TransportKind::Xhttp => Some("vless-xhttp-tls"),
                TransportKind::Grpc => Some("vless-grpc-tls"),
                TransportKind::HttpUpgrade => Some("vless-httpupgrade-tls"),
                _ => None,
            };
            if let Some(method) = method {
                return Support::Implemented { method };
            }
        }
        Support::Planned {
            reason: planned_reason(self, security),
        }
    }

    #[must_use]
    pub fn request_command_len(&self, command: Command, target_host: &str) -> usize {
        let head = 1 + 16 + self.addons_len() + 1;
        if carries_address(command) {
            head + 2 + Addr::of(target_host).wire_len()
        } else {
            head
        }
    }

    #[must_use]
    pub fn request_header_len(&self, target_host: &str) -> usize {
        self.request_command_len(Command::Tcp, target_host)
    }

    #[must_use]
    pub fn is_vision_flow(&self) -> bool {
        self.vision
    }

    fn is_vision(&self) -> bool {
        self.is_vision_flow()
    }

    #[inline]
    fn addons_len(&self) -> usize {
        if self.is_vision() {
            19
        } else {
            1
        }
    }

    #[inline]
    pub fn encode_into(&self, target_host: &str, target_port: u16, out: &mut [u8]) -> usize {
        self.encode_request_into(Command::Tcp, target_host, target_port, out)
    }

    #[inline]
    pub fn encode_request_into(
        &self,
        command: Command,
        target_host: &str,
        target_port: u16,
        out: &mut [u8],
    ) -> usize {
        let addr = carries_address(command).then(|| Addr::of(target_host));
        let vision = self.is_vision();
        let tail = addr.map_or(0, |a| 2 + a.wire_len());
        // The flow is already decided above; `addons_len` would re-look it up in the params map.
        let addons = if vision { VISION_ADDONS.len() + 1 } else { 1 };
        let need = 1 + 16 + addons + 1 + tail;
        assert!(out.len() >= need, "vless header buffer too short");

        out[0] = 0;
        out[1..17].copy_from_slice(&self.uuid_bytes);
        let mut o = 17;
        if vision {
            out[o] = VISION_ADDONS.len() as u8;
            o += 1;
            out[o..o + VISION_ADDONS.len()].copy_from_slice(&VISION_ADDONS);
            o += VISION_ADDONS.len();
        } else {
            out[o] = 0;
            o += 1;
        }
        out[o] = command.byte();
        o += 1;
        if let Some(addr) = addr {
            out[o..o + 2].copy_from_slice(&target_port.to_be_bytes());
            o += 2;
            o += addr.encode_into(&mut out[o..]);
        }
        debug_assert_eq!(o, need);
        o
    }

    #[allow(
        clippy::uninit_vec,
        reason = "the header is written into the room below before the vector is read"
    )]
    #[must_use]
    pub fn encode_request_header(&self, target_host: &str, target_port: u16) -> Vec<u8> {
        let len = self.request_header_len(target_host);
        let mut out = Vec::with_capacity(len);
        out.reserve_exact(len);
        // SAFETY: `encode_into` writes every byte of the header, and the vector is not read before it does.
        unsafe { out.set_len(len) };
        let n = self.encode_into(target_host, target_port, &mut out);
        debug_assert_eq!(n, out.len());
        out
    }

    pub fn decode_response_header(buf: &[u8]) -> Result<usize, VlessError> {
        let &[version, len, ..] = buf else {
            return Err(VlessError::Response);
        };
        if version != 0 {
            return Err(VlessError::Response);
        }
        let need = 2 + usize::from(len);
        if buf.len() < need {
            return Err(VlessError::Response);
        }
        Ok(need)
    }
}

const VISION_ADDONS: [u8; 18] = *b"\x0A\x10xtls-rprx-vision";

/// The flow the Vision framing speaks.
pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// The flow names the Vision framing answers to, and the one UDP variant that rides it.
#[must_use]
pub fn is_vision_name(flow: &str) -> bool {
    matches!(flow.len(), 16 | 23) && (flow == VISION_FLOW || flow == "xtls-rprx-vision-udp443")
}

/// The longest request header the wire can carry: the head, the add-ons, the command.
/// The port, the family byte and the address follow the command and are read after it.
pub const REQUEST_MAX: usize = 18 + 255 + 1;

/// The flow a request header's add-ons named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// No flow, or an add-on this tree does not read.
    None,
    /// The flow the Vision framing speaks.
    Vision,
    /// A flow that is not the Vision one.
    Other,
}

/// The target a request names: an address on the wire, or a name to look up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    Ip(IpAddr),
    Name(&'a str),
}

/// A decoded VLESS request header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    pub id: [u8; 16],
    pub flow: Flow,
    pub command: u8,
    pub port: u16,
    /// The target the command names; a mux request carries none.
    pub target: Option<Target<'a>>,
}

/// Reads a request header off the wire into the caller's buffer and names what it says.
///
/// The header is read in four reads — the head, the add-ons with the command, the port
/// with the family byte, and the address — and every byte the header holds is left where
/// it landed: a name is borrowed from `scratch`, so the parse allocates nothing and copies
/// nothing but the id.
pub fn decode_request<'a>(
    stream: &mut dyn Read,
    scratch: &'a mut [u8; REQUEST_MAX],
) -> Option<Request<'a>> {
    crate::tls::read_exact(stream, &mut scratch[..18]).ok()?;
    if scratch[0] != 0 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&scratch[1..17]);
    let addons = usize::from(scratch[17]);
    crate::tls::read_exact(stream, &mut scratch[18..19 + addons]).ok()?;
    let command = scratch[18 + addons];
    let flow = flow_of(&scratch[18..18 + addons]);
    if command == Command::Mux.byte() || command == Command::Reverse.byte() {
        return Some(Request {
            id,
            flow,
            command,
            port: 0,
            target: None,
        });
    }
    // The port, the family and the body's first byte are the same four bytes for every family.
    crate::tls::read_exact(stream, &mut scratch[..4]).ok()?;
    let port = u16::from_be_bytes([scratch[0], scratch[1]]);
    let family = scratch[2];
    let first = scratch[3];
    let body = match family {
        crate::addr::IPV4 => {
            crate::tls::read_exact(stream, &mut scratch[4..7]).ok()?;
            Body::V4
        }
        crate::addr::DOMAIN => {
            let n = usize::from(first);
            crate::tls::read_exact(stream, &mut scratch[4..4 + n]).ok()?;
            Body::Name(n)
        }
        crate::addr::IPV6 => {
            crate::tls::read_exact(stream, &mut scratch[4..19]).ok()?;
            Body::V6
        }
        _ => return None,
    };
    // The bytes are in place; the name borrows them where they landed.
    let bytes: &'a [u8; REQUEST_MAX] = &*scratch;
    let target = match body {
        Body::V4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&bytes[3..7]);
            Target::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        Body::V6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[3..19]);
            Target::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        Body::Name(n) => Target::Name(std::str::from_utf8(&bytes[4..4 + n]).ok()?),
    };
    Some(Request {
        id,
        flow,
        command,
        port,
        target: Some(target),
    })
}

/// Which body the family byte asked for, so the address is read before it is named.
enum Body {
    V4,
    V6,
    Name(usize),
}

/// The flow the add-ons named, read out of the protobuf without building a string for it.
fn flow_of(body: &[u8]) -> Flow {
    let mut at = 0;
    while at < body.len() {
        let tag = body[at];
        at += 1;
        let (field, wire) = (tag >> 3, tag & 0x07);
        let Some(len) = read_varint(body, &mut at) else {
            return Flow::None;
        };
        let len = len as usize;
        match (field, wire) {
            (1, 2) => {
                let Some(bytes) = body.get(at..at.saturating_add(len)) else {
                    return Flow::None;
                };
                return match std::str::from_utf8(bytes) {
                    Ok("") | Err(_) => Flow::None,
                    Ok(flow) if flow == VISION_FLOW => Flow::Vision,
                    Ok(_) => Flow::Other,
                };
            }
            (0, _) | (1, 0) | (_, 2) => at += len,
            (_, 5) => at += 4,
            (_, 1) => at += 8,
            _ => return Flow::None,
        }
    }
    Flow::None
}

fn read_varint(body: &[u8], at: &mut usize) -> Option<u32> {
    let mut word = 0u32;
    for shift in (0..32).step_by(7) {
        let byte = *body.get(*at)?;
        *at += 1;
        word |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(word);
        }
    }
    None
}

const RECORD_CAP: usize = 8192;
const RECORD_OVERHEAD: usize = 21;
const LONG_MIN: usize = 900;
const LONG_SPAN: usize = 500;
const SHORT_SPAN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionCommand {
    Continue = 0x00,
    End = 0x01,
    Direct = 0x02,
}

impl VisionCommand {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Continue),
            0x01 => Some(Self::End),
            0x02 => Some(Self::Direct),
            _ => None,
        }
    }

    #[must_use]
    pub fn byte(self) -> u8 {
        self as u8
    }
}

#[must_use]
pub fn seal_len(content_len: usize, pad_len: usize, uuid_first: bool) -> usize {
    (if uuid_first { 16 } else { 0 }) + 5 + content_len + pad_len
}

#[derive(Debug, Clone)]
pub struct VisionSeal {
    key: [u8; 32],
    nonce: [u8; 12],
    block: u32,
    pool: [u8; 64],
    used: usize,
    uuid: Option<[u8; 16]>,
}

impl VisionSeal {
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], uuid: &[u8; 16]) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
            block: 0,
            pool: [0u8; 64],
            used: 64,
            uuid: Some(*uuid),
        }
    }

    #[must_use]
    pub fn blocks_used(&self) -> u32 {
        self.block
    }

    #[inline]
    fn draw(&mut self) -> u32 {
        if self.used + 4 > self.pool.len() {
            let made =
                crate::record::fill_exact(&self.key, &self.nonce, self.block, &mut self.pool);
            debug_assert_eq!(made, 1);
            self.block += 1;
            self.used = 0;
        }
        let idx = self.used;
        self.used += 4;
        u32::from_le_bytes([
            self.pool[idx],
            self.pool[idx + 1],
            self.pool[idx + 2],
            self.pool[idx + 3],
        ])
    }

    #[inline]
    fn pad_len(&mut self, content_len: usize, long: bool) -> usize {
        let raw = if long && content_len < LONG_MIN {
            LONG_MIN + self.draw() as usize % LONG_SPAN - content_len
        } else {
            self.draw() as usize % SHORT_SPAN
        };
        raw.min(RECORD_CAP - RECORD_OVERHEAD - content_len)
    }

    #[inline]
    pub fn seal(
        &mut self,
        out: &mut [u8],
        content: &[u8],
        command: VisionCommand,
        long: bool,
    ) -> usize {
        assert!(
            content.len() <= RECORD_CAP - RECORD_OVERHEAD,
            "vision content exceeds one record"
        );
        let pad = self.pad_len(content.len(), long);
        let uuid_first = self.uuid.is_some();
        let need = seal_len(content.len(), pad, uuid_first);
        assert!(out.len() >= need, "vision record buffer too short");
        let mut o = 0;
        if let Some(uuid) = self.uuid.take() {
            out[o..o + 16].copy_from_slice(&uuid);
            o += 16;
        }
        out[o] = command.byte();
        o += 1;
        out[o..o + 2].copy_from_slice(&(content.len() as u16).to_be_bytes());
        o += 2;
        out[o..o + 2].copy_from_slice(&(pad as u16).to_be_bytes());
        o += 2;
        out[o..o + content.len()].copy_from_slice(content);
        o += content.len();
        out[o..o + pad].fill(0);
        o += pad;
        debug_assert_eq!(o, need);
        o
    }
}

#[derive(Debug, Clone)]
pub struct VisionOpen {
    id: [u8; 16],
    command: i32,
    content: i32,
    padding: i32,
    current: u8,
}

impl VisionOpen {
    #[must_use]
    pub fn new(id: &[u8; 16]) -> Self {
        Self {
            id: *id,
            command: -1,
            content: -1,
            padding: -1,
            current: 0,
        }
    }

    #[inline]
    pub fn open(&mut self, buf: &[u8], out: &mut [u8]) -> (usize, Option<VisionCommand>) {
        assert!(out.len() >= buf.len(), "vision open buffer too short");
        let mut pos = 0;
        let mut written = 0;
        let mut completed = None;
        if self.command == -1 && self.content == -1 && self.padding == -1 {
            if buf.len() >= 21 && buf[..16] == self.id {
                pos = 16;
                self.command = 5;
            } else {
                out[..buf.len()].copy_from_slice(buf);
                return (buf.len(), None);
            }
        }
        while pos < buf.len() {
            if self.command == 5 && buf.len() - pos >= 5 {
                // Five header iterations with no observable in between read as one load.
                self.current = buf[pos];
                self.content = i32::from(buf[pos + 1]) << 8 | i32::from(buf[pos + 2]);
                self.padding = i32::from(buf[pos + 3]) << 8 | i32::from(buf[pos + 4]);
                completed = VisionCommand::from_byte(self.current);
                pos += 5;
                self.command = 0;
            } else if self.command > 0 {
                let byte = buf[pos];
                pos += 1;
                match self.command {
                    5 => self.current = byte,
                    4 => self.content = i32::from(byte) << 8,
                    3 => self.content |= i32::from(byte),
                    2 => self.padding = i32::from(byte) << 8,
                    _ => {
                        self.padding |= i32::from(byte);
                        completed = VisionCommand::from_byte(self.current);
                    }
                }
                self.command -= 1;
            } else if self.content > 0 {
                let n = (self.content as usize).min(buf.len() - pos);
                out[written..written + n].copy_from_slice(&buf[pos..pos + n]);
                written += n;
                pos += n;
                self.content -= i32::try_from(n).expect("record chunk fits i32");
            } else {
                let n = (self.padding as usize).min(buf.len() - pos);
                pos += n;
                self.padding -= i32::try_from(n).expect("record chunk fits i32");
            }
            if self.command <= 0 && self.content <= 0 && self.padding <= 0 {
                if self.current == 0 {
                    self.command = 5;
                } else {
                    self.command = -1;
                    self.content = -1;
                    self.padding = -1;
                    out[written..written + buf.len() - pos].copy_from_slice(&buf[pos..]);
                    written += buf.len() - pos;
                    break;
                }
            }
        }
        (written, completed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
    Reverse = 0x04,
}

impl Command {
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            0x03 => Some(Self::Mux),
            0x04 => Some(Self::Reverse),
            _ => None,
        }
    }

    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }
}

#[must_use]
pub const fn carries_address(command: Command) -> bool {
    matches!(command, Command::Tcp | Command::Udp)
}

fn planned_reason(link: &VlessLink, security: Security) -> &'static str {
    let kind = link.transport_kind();
    match kind {
        TransportKind::Tcp => match security {
            // Only a flow the link names is left here: the plain and vision dials returned above.
            Security::Tls => "vless-tcp-tls: parses, the flow it names is not one this tree dials",
            // A consented public cleartext link reaches here as `Security::None`; the unconsented gate already returned, so the same reason fits.
            Security::None | Security::NoneToPublic => {
                "vless-tcp-none without encryption=none and no flow: parses, unsupported combination"
            }
            Security::Reality => "vless-tcp-reality without vision: parses, vision rung first",
            Security::Other => "unknown security: parses, transport not scheduled",
        },
        TransportKind::Ws => "vless-ws: carrier dials; the security above is what is missing",
        TransportKind::Xhttp => "vless-xhttp: carrier dials; the security above is what is missing",
        TransportKind::Grpc => "vless-grpc: carrier dials; the security above is what is missing",
        TransportKind::Quic => "vless-quic: carrier dials; the security above is what is missing",
        TransportKind::HttpUpgrade => {
            "vless-httpupgrade: carrier dials; the security above is what is missing"
        }
        TransportKind::Kcp => "vless-kcp: carrier dials; the security above is what is missing",
        TransportKind::Http => {
            "http/h2/h3: removed by Xray-core in favour of xhttp; parses, no transport"
        }
        TransportKind::Hysteria => {
            "vless-hysteria: the transport dials and carries UDP, salamander, masquerade and port-hop; a bare link query expresses none of those options"
        }
        TransportKind::Masque => {
            "vless-masque: CONNECT-IP dials on the Foxy HTTP/3 lane; VLESS over a MASQUE outbound not wired"
        }
        TransportKind::Xdrive => "vless-xdrive: parses, transport not scheduled",
        TransportKind::Other => "unknown type: parses, transport not scheduled",
    }
}

fn carrier_method(kind: TransportKind) -> Option<&'static str> {
    if !kind.is_dialled() {
        return None;
    }
    Some(match kind {
        TransportKind::Ws => "vless-ws",
        TransportKind::Xhttp => "vless-xhttp",
        TransportKind::Grpc => "vless-grpc",
        TransportKind::Quic => "vless-quic",
        TransportKind::HttpUpgrade => "vless-httpupgrade",
        TransportKind::Kcp => "vless-kcp",
        TransportKind::Hysteria => "vless-hysteria",
        _ => return None,
    })
}

fn validate_uuid(uuid: &str) -> Result<(), VlessError> {
    let b = uuid.as_bytes();
    if b.len() != 36 || b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return Err(VlessError::Uuid);
    }
    if !b.iter().all(|c| *c == b'-' || c.is_ascii_hexdigit()) {
        return Err(VlessError::Uuid);
    }
    Ok(())
}

const fn hex_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    let mut c = 0usize;
    while c < 256 {
        t[c] = match c as u8 {
            b'0'..=b'9' => c as u8 - b'0',
            b'a'..=b'f' => c as u8 - b'a' + 10,
            b'A'..=b'F' => c as u8 - b'A' + 10,
            _ => 0xFF,
        };
        c += 1;
    }
    t
}
const HEX: [u8; 256] = hex_table();

const UUID_HI: [usize; 16] = [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];

const UUID_LOW: [usize; 16] = [1, 3, 5, 7, 10, 12, 15, 17, 20, 22, 25, 27, 29, 31, 33, 35];

#[inline]
fn uuid_bytes(uuid: &str) -> [u8; 16] {
    let b = uuid.as_bytes();
    let mut out = [0u8; 16];
    // Fast path for canonical UUID format
    if b.len() == 36 && b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-' {
        // Unroll for speed - 16 pairs total
        let mut i = 0;
        while i < 16 {
            let hi = UUID_HI[i];
            let lo = UUID_LOW[i];
            // Safe: positions are valid for canonical UUID
            let bh = unsafe { *b.get_unchecked(hi) } as usize;
            let bl = unsafe { *b.get_unchecked(lo) } as usize;
            let h = unsafe { *HEX.get_unchecked(bh) };
            let l = unsafe { *HEX.get_unchecked(bl) };
            out[i] = if h < 16 && l < 16 { (h << 4) | l } else { 0 };
            i += 1;
        }
        return out;
    }
    let mut idx = 0usize;
    let mut have_hi = false;
    let mut hi_val = 0u8;
    let mut hi_ok = false;
    let mut i = 0;
    while i < b.len() && idx < 16 {
        let c = b[i];
        if c == b'-' {
            i += 1;
            continue;
        }
        let v = HEX[c as usize];
        let ok = v != 0xFF;
        let v = if ok { v } else { 0 };
        if have_hi {
            if hi_ok && ok {
                out[idx] = (hi_val << 4) | v;
            } else {
                out[idx] = 0;
            }
            idx += 1;
            have_hi = false;
        } else {
            hi_val = v;
            hi_ok = ok;
            have_hi = true;
        }
        i += 1;
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessError {
    Scheme,
    Shape,
    Uuid,
    Port,
    Response,
}

impl fmt::Display for VlessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => write!(f, "link must start with vless://"),
            Self::Shape => write!(f, "link must look like vless://uuid@host:port?..."),
            Self::Uuid => write!(f, "uuid must be 8-4-4-4-12 hex"),
            Self::Port => write!(f, "port must be 0-65535"),
            Self::Response => write!(f, "response header is truncated or versioned wrong"),
        }
    }
}

impl std::error::Error for VlessError {}

#[cfg(test)]
mod tests {
    use super::*;

    const BRIEF_LINK: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#reality-vision-test";

    /// The header the dial carries is not zeroed: `encode_into` writes every byte of it,
    /// so the zero pass in front of it was work generated and thrown away. The counting
    /// allocator's `zeroed` counter is the witness.
    #[test]
    fn the_request_header_is_not_zero_filled() {
        let link = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("a link");
        let (header, counts) =
            crate::alloc_count::measure(|| link.encode_request_header("example.com", 443));
        assert_eq!(counts.zeroed, 0, "the header is not zeroed");
        assert_eq!(counts.allocs, 1, "the header is one buffer");
        assert_eq!(header.len(), link.request_header_len("example.com"));
    }

    #[test]
    fn parses_the_brief_link() {
        let l = VlessLink::parse(BRIEF_LINK).expect("brief link parses");
        assert_eq!(l.uuid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(l.host, "192.0.2.1");
        assert_eq!(l.port, 443);
        assert_eq!(l.param("security"), "reality");
        assert_eq!(l.param("encryption"), "none");
        assert_eq!(l.param("flow"), "xtls-rprx-vision");
        assert_eq!(l.param("type"), "tcp");
        assert_eq!(l.param("fp"), "firefox");
        assert_eq!(l.sni(), "example.com");
        assert_eq!(
            l.reality_pbk(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(l.reality_sid(), "a8");
        assert!(l.is_first_method());
        assert_eq!(
            l.support(),
            Support::Implemented {
                method: "vless-tcp-reality-vision"
            }
        );
    }

    #[test]
    fn first_method_header_is_stable() {
        let l = VlessLink::parse(BRIEF_LINK).expect("parses");
        let hdr = l.encode_request_header("192.0.2.53", 80);
        assert_eq!(hdr.len(), 44);
        assert_eq!(hdr[0], 0); // version
        assert_eq!(
            &hdr[1..17],
            &[
                0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee
            ]
        );
        assert_eq!(uuid_bytes(&l.uuid), hdr[1..17]);
        assert_eq!(hdr[17], 18); // addon length: fixed protobuf below
        assert_eq!(&hdr[18..36], b"\x0A\x10xtls-rprx-vision" as &[u8]);
        assert_eq!(hdr[36], 1); // TCP
        assert_eq!(&hdr[37..39], &[0, 80]);
        assert_eq!(hdr[39], 1); // IPv4
        assert_eq!(&hdr[40..44], &[192, 0, 2, 53]);
        let mut buf = vec![0u8; l.request_header_len("192.0.2.53")];
        let n = l.encode_into("192.0.2.53", 80, &mut buf);
        assert_eq!(&buf[..n], &hdr[..]);
    }

    #[test]
    fn header_address_families_encode_stably() {
        let l = VlessLink::parse(BRIEF_LINK).expect("parses");
        let v4 = l.encode_request_header("192.0.2.53", 80);
        assert_eq!(v4[39], 1);
        assert_eq!(&v4[40..44], &[192, 0, 2, 53]);
        assert_eq!(v4.len(), l.request_header_len("192.0.2.53"));

        let v6 = l.encode_request_header("2001:db8::1", 443);
        assert_eq!(v6[39], 3);
        assert_eq!(
            &v6[40..56],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(v6.len(), l.request_header_len("2001:db8::1"));

        let name = l.encode_request_header("example.com", 443);
        assert_eq!(name[39], 2);
        assert_eq!(name[40], 11);
        assert_eq!(&name[41..52], b"example.com");
        assert_eq!(name.len(), l.request_header_len("example.com"));

        for (host, port) in [
            ("192.0.2.53", 80),
            ("2001:db8::1", 443),
            ("example.com", 443),
        ] {
            let expect = l.encode_request_header(host, port);
            let mut buf = vec![0u8; l.request_header_len(host)];
            let n = l.encode_into(host, port, &mut buf);
            assert_eq!(&buf[..n], &expect[..], "family {host}");
        }
    }

    #[test]
    fn non_vision_header_carries_empty_addons() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.53:80?security=tls&encryption=none&type=tcp#tls",
        )
        .expect("parses");
        let hdr = l.encode_request_header("192.0.2.53", 80);
        assert_eq!(hdr.len(), 26);
        assert_eq!(hdr[17], 0);
        assert_eq!(hdr[18], 1); // TCP
        assert_eq!(&hdr[19..21], &[0, 80]);
        assert_eq!(&hdr[21..26], &[1, 192, 0, 2, 53]);
    }

    #[test]
    fn the_multiplexing_commands_write_no_address() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.53:80?security=reality&encryption=none&type=tcp#mux",
        )
        .expect("parses");
        assert_eq!(l.request_command_len(Command::Mux, "192.0.2.53"), 19);
        for (command, byte) in [(Command::Mux, 3u8), (Command::Reverse, 4)] {
            assert!(!carries_address(command), "{command:?} names no target");
            let mut buf = [0u8; 64];
            let n = l.encode_request_into(command, "192.0.2.53", 80, &mut buf);
            assert_eq!(n, 19, "{command:?}");
            assert_eq!(buf[18], byte, "{command:?}");
            assert_eq!(Command::from_byte(byte), Some(command));
            let mut other = [0u8; 64];
            let m = l.encode_request_into(command, "2001:db8::1", 443, &mut other);
            assert_eq!(m, n, "{command:?}");
            assert_eq!(other[..n], buf[..n], "{command:?}");
        }
        assert_eq!(
            l.request_command_len(Command::Tcp, "192.0.2.53"),
            l.request_header_len("192.0.2.53")
        );
        let mut shorthand = [0u8; 64];
        let mut general = [0u8; 64];
        assert_eq!(l.encode_into("192.0.2.53", 80, &mut shorthand), 26);
        assert_eq!(
            l.encode_request_into(Command::Tcp, "192.0.2.53", 80, &mut general),
            26
        );
        assert_eq!(
            shorthand, general,
            "the TCP shorthand and the general form are the same bytes"
        );
    }

    #[test]
    fn response_header_decodes() {
        assert_eq!(VlessLink::decode_response_header(&[0, 0]), Ok(2));
        let mut vision = vec![0u8, 18];
        vision.extend_from_slice(b"\x0A\x10xtls-rprx-vision");
        assert_eq!(VlessLink::decode_response_header(&vision), Ok(20));
        assert_eq!(
            VlessLink::decode_response_header(&[1, 0]).unwrap_err(),
            VlessError::Response
        );
        assert_eq!(
            VlessLink::decode_response_header(&[0]).unwrap_err(),
            VlessError::Response
        );
        assert_eq!(
            VlessLink::decode_response_header(&[0, 5, 1, 2]).unwrap_err(),
            VlessError::Response
        );
    }

    #[test]
    fn unknown_transports_parse_but_stay_planned() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=reality&type=ws&path=%2Fws#ws",
        )
        .expect("parses");
        assert!(matches!(l.support(), Support::Planned { .. }));
        assert!(!l.is_first_method());
    }

    #[test]
    fn carried_tls_without_vision_is_implemented() {
        for (query, method) in [
            ("security=tls&type=ws&path=%2Fws", "vless-ws-tls"),
            ("security=tls&type=xhttp&path=%2Fshare", "vless-xhttp-tls"),
            ("security=tls&type=grpc&serviceName=svc", "vless-grpc-tls"),
            (
                "security=tls&type=httpupgrade&path=%2Fu",
                "vless-httpupgrade-tls",
            ),
        ] {
            let link =
                format!("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:443?{query}#tls");
            let l = VlessLink::parse(&link).expect("parses");
            assert_eq!(l.support(), Support::Implemented { method }, "{query}");
            let vision = VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?{query}&flow=xtls-rprx-vision#tls-vision"
            ))
            .expect("parses");
            assert!(
                matches!(vision.support(), Support::Planned { .. }),
                "{query} with vision"
            );
        }
    }

    #[test]
    fn raw_link_matches_tcp() {
        let raw = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type=raw#plain",
        )
        .expect("parses");
        assert_eq!(raw.transport_kind(), TransportKind::Tcp);
        assert!(raw.is_none_private_method());
        assert_eq!(
            raw.support(),
            Support::Implemented {
                method: "vless-tcp-none"
            }
        );
        let vision = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&type=raw&flow=xtls-rprx-vision&sni=example.com&sid=a8#x",
        )
        .expect("parses");
        assert!(vision.is_first_method());
    }

    #[test]
    fn percent_decode_keeps_lossy_bytes() {
        assert_eq!(percent_decode("%2F"), "/");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%FF"), "\u{FFFD}");
    }

    #[test]
    fn no_tcp_link_reports_the_bare_tcp_method() {
        for link in [
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type=tcp#plain",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type=raw#plain",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:80?security=none&encryption=none&type=tcp#public",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:443?security=tls&type=tcp#tls",
            BRIEF_LINK,
        ] {
            let l = VlessLink::parse(link).expect("parses");
            assert_ne!(
                l.support(),
                Support::Implemented { method: "vless-tcp" },
                "{link}"
            );
        }
    }

    #[test]
    fn tcp_tls_without_vision_is_implemented() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:443?security=tls&type=tcp#tls",
        )
        .expect("parses");
        assert_eq!(
            l.support(),
            Support::Implemented {
                method: "vless-tcp-tls"
            }
        );
        let vision = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:443?security=tls&type=tcp&flow=xtls-rprx-vision#tls-vision",
        )
        .expect("parses");
        assert_eq!(
            vision.support(),
            Support::Implemented {
                method: "vless-tcp-tls-vision"
            }
        );
        let unknown = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=tls&type=tcp&flow=xtls-rprx-flow#unknown-flow",
        )
        .expect("parses");
        assert!(matches!(unknown.support(), Support::Planned { .. }));
    }

    #[test]
    fn pattng_plaintext_to_public_needs_opt_in_and_adds_no_byte() {
        let public = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:80?security=none&encryption=none&type=tcp#plain",
        )
        .expect("parses");
        // A bare link vetoes a cleartext credential reaching a public address.
        assert!(matches!(
            public.support(),
            Support::UnsafeRequiresOptIn { .. }
        ));
        // The operator's out-of-band consent clears the veto; the session is the private none dial.
        assert_eq!(
            public.support_opted(UnsafeOptIn::none().allow_plaintext_to_public()),
            Support::Implemented {
                method: "vless-tcp-none"
            },
        );
        // The consent gates a policy and changes no byte: the same session to a private host encodes the identical request header, and the consented public link matches it.
        let private = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type=tcp#plain",
        )
        .expect("parses");
        assert_eq!(
            public.encode_request_header("example.com", 443),
            private.encode_request_header("example.com", 443),
            "a plaintext-to-public consent adds no VLESS byte"
        );
    }

    #[test]
    fn the_two_unsafe_consents_are_independent() {
        // A public cleartext link that also asks for an unsafe fingerprint needs BOTH consents; each alone leaves the other veto standing.
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:80?security=none&encryption=none&type=tcp&fp=unsafe-chrome#plain",
        )
        .expect("parses");
        assert!(matches!(l.support(), Support::UnsafeRequiresOptIn { .. }));
        assert!(matches!(
            l.support_opted(UnsafeOptIn::none().allow_plaintext_to_public()),
            Support::UnsafeRequiresOptIn { .. }
        ));
        assert!(matches!(
            l.support_opted(UnsafeOptIn::none().allow_unsafe_fingerprint()),
            Support::UnsafeRequiresOptIn { .. }
        ));
        assert_eq!(
            l.support_opted(
                UnsafeOptIn::none()
                    .allow_plaintext_to_public()
                    .allow_unsafe_fingerprint()
            ),
            Support::Implemented {
                method: "vless-tcp-none"
            },
        );
    }

    #[test]
    fn a_consented_public_cleartext_rides_a_carrier() {
        // The gate is carrier-indifferent: a consented public `security=none` reaches the same cleartext session the private link reports; unconsented it stays vetoed.
        for (transport, method) in [("ws", "vless-ws"), ("xhttp", "vless-xhttp")] {
            let link = format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type={transport}#plain"
            );
            let l = VlessLink::parse(&link).expect("parses");
            assert!(
                matches!(l.support(), Support::UnsafeRequiresOptIn { .. }),
                "{transport}"
            );
            assert_eq!(
                l.support_opted(UnsafeOptIn::none().allow_plaintext_to_public()),
                Support::Implemented { method },
                "{transport}"
            );
        }
    }

    #[test]
    fn pattng_unsafe_fingerprint_needs_opt_in() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=k&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8&fp=unsafe-chrome#x",
        )
        .expect("parses");
        assert!(matches!(l.support(), Support::UnsafeRequiresOptIn { .. }));
        // The operator's out-of-band consent clears the veto: the stock-hello dial is PattNG's unsafe.
        assert_eq!(
            l.support_opted(UnsafeOptIn::none().allow_unsafe_fingerprint()),
            Support::Implemented {
                method: "vless-tcp-reality-vision"
            },
        );
    }

    #[test]
    fn an_unsafe_fingerprint_adds_no_header_byte() {
        let header = |fp: &str| {
            let tail = if fp.is_empty() {
                String::new()
            } else {
                format!("&fp={fp}")
            };
            VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=k&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8{tail}#x"
            ))
            .expect("parses")
            .encode_request_header("example.com", 443)
        };
        // The fingerprint shapes the TLS hello, never a VLESS byte: an unsafe one adds nothing.
        assert_eq!(
            header(""),
            header("chrome"),
            "a preset fingerprint is not a header byte"
        );
        assert_eq!(
            header(""),
            header("unsafe-chrome"),
            "an unsafe fingerprint adds no VLESS header byte"
        );
    }

    #[test]
    fn plaintext_to_private_is_implemented() {
        for host in ["127.0.0.1", "10.0.0.8", "192.168.1.20", "localhost"] {
            let link = format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@{host}:80?security=none&encryption=none&type=tcp#plain"
            );
            let l = VlessLink::parse(&link).expect("parses");
            assert!(l.is_none_private_method(), "{host}");
            assert_eq!(
                l.support(),
                Support::Implemented {
                    method: "vless-tcp-none"
                },
                "{host}"
            );
        }
    }

    #[test]
    fn plaintext_stays_planned_without_none_and_no_flow() {
        for link in [
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&type=tcp#no-encryption",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=aes&type=tcp#bad-encryption",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type=tcp&flow=xtls-rprx-vision#vision-without-reality",
        ] {
            let l = VlessLink::parse(link).expect("parses");
            assert!(!l.is_none_private_method(), "{link}");
            assert!(!matches!(l.support(), Support::Implemented { .. }), "{link}");
        }
        let unsafe_private = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type=tcp&fp=unsafe-chrome#unsafe",
        )
        .expect("parses");
        assert!(matches!(
            unsafe_private.support(),
            Support::UnsafeRequiresOptIn { .. }
        ));
        assert_eq!(
            unsafe_private.support_opted(UnsafeOptIn::none().allow_unsafe_fingerprint()),
            Support::Implemented {
                method: "vless-tcp-none"
            },
        );
    }

    #[test]
    fn the_uuid_fast_path_agrees_with_the_scan() {
        fn scan(uuid: &str) -> [u8; 16] {
            let mut out = [0u8; 16];
            let mut idx = 0usize;
            let mut hi: Option<(u8, bool)> = None;
            for c in uuid.bytes() {
                if c == b'-' {
                    continue;
                }
                let (v, ok) = match c {
                    b'0'..=b'9' => (c - b'0', true),
                    b'a'..=b'f' => (c - b'a' + 10, true),
                    b'A'..=b'F' => (c - b'A' + 10, true),
                    _ => (0, false),
                };
                if let Some((h, hok)) = hi.take() {
                    if idx < 16 {
                        out[idx] = if hok && ok { (h << 4) | v } else { 0 };
                        idx += 1;
                    }
                } else {
                    hi = Some((v, ok));
                }
                if idx >= 16 {
                    break;
                }
            }
            out
        }
        let canonical = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        assert_eq!(uuid_bytes(canonical), scan(canonical), "the fast path");
        for pos in 0..canonical.len() {
            if canonical.as_bytes()[pos] == b'-' {
                continue;
            }
            for digit in b"0123456789abcdefABCDEF".iter().copied() {
                let mut bytes = canonical.as_bytes().to_vec();
                bytes[pos] = digit;
                let text = std::str::from_utf8(&bytes).expect("ascii");
                assert_eq!(uuid_bytes(text), scan(text), "pos {pos} digit {digit}");
            }
        }
        for (a, b) in [(0usize, 1usize), (5, 6), (20, 21), (34, 35)] {
            let mut bytes = canonical.as_bytes().to_vec();
            bytes.swap(a, b);
            let text = std::str::from_utf8(&bytes).expect("ascii");
            assert_eq!(uuid_bytes(text), scan(text), "bytes {a} and {b} swapped");
        }
        for short in ["", "a", "aaaaaaaa-bbbb", &canonical[..35], &canonical[1..]] {
            assert_eq!(uuid_bytes(short), scan(short), "{short:?}");
        }
    }

    #[test]
    fn rejects_bad_links() {
        assert_eq!(
            VlessLink::parse("http://x").unwrap_err(),
            VlessError::Scheme
        );
        assert_eq!(
            VlessLink::parse("vless://not-a-uuid@example.com:443").unwrap_err(),
            VlessError::Uuid
        );
        assert_eq!(
            VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:notaport")
                .unwrap_err(),
            VlessError::Port
        );
    }

    const SEAL_KEY: [u8; 32] = [0x5au8; 32];
    const SEAL_NONCE: [u8; 12] = [0xa7u8; 12];
    const SEAL_UUID: [u8; 16] = [0xabu8; 16];

    /// The request header as the wire carries it, so the parse is read against the bytes
    /// and not against a description of them.
    fn request_wire(id: &[u8; 16], addons: &[u8], cmd: u8, tail: &[u8]) -> Vec<u8> {
        let mut wire = vec![0u8];
        wire.extend_from_slice(id);
        wire.push(addons.len() as u8);
        wire.extend_from_slice(addons);
        wire.push(cmd);
        wire.extend_from_slice(tail);
        wire
    }

    /// A reader that answers exactly what it is asked, so the read count is exact.
    struct Counting<'a> {
        at: usize,
        wire: &'a [u8],
        reads: usize,
    }

    impl Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            let n = (self.wire.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.wire[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    const REQUEST_ID: [u8; 16] = [0x11u8; 16];

    /// The header is read in four reads for every address family, and two for a mux one.
    #[test]
    fn the_request_header_costs_four_reads_for_every_family() {
        let port = 80u16.to_be_bytes();
        let cases = [
            (
                "ipv4",
                request_wire(
                    &REQUEST_ID,
                    &[],
                    1,
                    &[port.as_slice(), &[1, 192, 0, 2, 53]].concat(),
                ),
                4,
            ),
            (
                "ipv6",
                request_wire(
                    &REQUEST_ID,
                    &[],
                    1,
                    &[
                        port.as_slice(),
                        &[3, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
                    ]
                    .concat(),
                ),
                4,
            ),
            (
                "domain",
                request_wire(
                    &REQUEST_ID,
                    &[],
                    1,
                    &[port.as_slice(), b"\x02\x09localhost"].concat(),
                ),
                4,
            ),
            (
                "addons",
                request_wire(
                    &REQUEST_ID,
                    b"\x0a\x00",
                    1,
                    &[port.as_slice(), &[1, 192, 0, 2, 53]].concat(),
                ),
                4,
            ),
        ];
        for (label, wire, want) in cases {
            let mut reader = Counting {
                at: 0,
                wire: &wire,
                reads: 0,
            };
            let mut scratch = [0u8; REQUEST_MAX];
            let request = decode_request(&mut reader, &mut scratch).expect("decodes");
            assert_eq!(request.id, REQUEST_ID, "{label}");
            assert_eq!(request.command, 1, "{label}");
            assert_eq!(request.port, 80, "{label}");
            assert_eq!(reader.reads, want, "{label}");
        }

        let mux = request_wire(&REQUEST_ID, &[], 3, &[]);
        let mut reader = Counting {
            at: 0,
            wire: &mux,
            reads: 0,
        };
        let mut scratch = [0u8; REQUEST_MAX];
        let request = decode_request(&mut reader, &mut scratch).expect("decodes a mux request");
        assert_eq!(request.command, 3);
        assert_eq!(request.target, None, "a mux request names no target");
        assert_eq!(reader.reads, 2, "a mux request stops at the command byte");
    }

    /// The parse reads the header and names it; it builds no buffer of its own and copies
    /// no byte but the id, so the name it hands over is the name that arrived.
    #[test]
    fn the_request_parse_allocates_nothing_and_borrows_the_name() {
        let wire = request_wire(
            &REQUEST_ID,
            &[],
            1,
            &[80u16.to_be_bytes().as_slice(), b"\x02\x09localhost"].concat(),
        );
        let mut scratch = [0u8; REQUEST_MAX];
        let base = scratch.as_ptr();
        let ((), counts) = crate::alloc_count::measure(|| {
            let mut reader = Counting {
                at: 0,
                wire: &wire,
                reads: 0,
            };
            let request = decode_request(&mut reader, &mut scratch).expect("decodes");
            let Some(Target::Name(name)) = request.target else {
                panic!("a domain target is a name");
            };
            assert_eq!(name, "localhost");
            let at = name.as_ptr() as usize;
            let lo = base as usize;
            assert!(
                at >= lo && at < lo + REQUEST_MAX,
                "the name is the name that arrived, not a copy of it"
            );
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "the request parse builds no buffer of its own"
        );
        assert_eq!(scratch.as_ptr(), base, "the caller's buffer did not move");
    }

    /// The request parser alone: one header, read again and again from a fixed buffer,
    /// with the fold outside the read so the frame holds the parse and nothing else.
    #[test]
    fn the_request_parse_probe_costs_the_read_and_nothing_else() {
        let wire = request_wire(
            &REQUEST_ID,
            b"\x0a\x10xtls-rprx-vision",
            1,
            &[80u16.to_be_bytes().as_slice(), &[1, 192, 0, 2, 53]].concat(),
        );
        let mut scratch = [0u8; REQUEST_MAX];
        let mut ids = 0usize;
        for _ in 0..64 {
            let mut reader = std::io::Cursor::new(&wire[..]);
            let request = decode_request(&mut reader, &mut scratch).expect("decodes");
            ids += usize::from(request.id == REQUEST_ID);
        }
        assert_eq!(ids, 64, "every parse named the id");
    }

    /// The flow decision alone: the add-ons, read again and again, with the fold outside
    /// the walk so the frame holds the decision and nothing else.
    #[test]
    fn the_flow_decision_probe_costs_the_walk_and_nothing_else() {
        let addons = b"\x0a\x10xtls-rprx-vision";
        let mut vision = 0usize;
        for _ in 0..64 {
            vision += usize::from(flow_of(addons) == Flow::Vision);
        }
        assert_eq!(vision, 64, "every walk named the vision flow");
    }

    /// The command validator accepts exactly the three commands the reference knows and
    /// refuses every other byte: checking costs one match, and it is paid on every frame.
    #[test]
    fn the_command_validator_accepts_three_commands() {
        let accepted: Vec<u8> = (0..=u8::MAX)
            .filter(|byte| VisionCommand::from_byte(*byte).is_some())
            .collect();
        assert_eq!(
            accepted,
            vec![0, 1, 2],
            "the three commands the reference knows"
        );
        for byte in 3..=u8::MAX {
            assert_eq!(VisionCommand::from_byte(byte), None, "byte {byte}");
        }
    }

    /// The validator alone: the 256 command bytes, read again and again, with the fold
    /// outside the call so the frame holds the match and nothing else.
    #[test]
    fn the_command_validator_probe_costs_the_match_and_nothing_else() {
        let mut accepted = 0usize;
        for _ in 0..64 {
            for byte in 0..=u8::MAX {
                accepted += usize::from(VisionCommand::from_byte(byte).is_some());
            }
        }
        assert_eq!(accepted, 64 * 3, "the validator accepts three commands");
    }

    /// The add-ons name a flow; the parse says which without building a string for it.
    #[test]
    fn the_flow_is_named_without_building_a_string() {
        let cases: [(&[u8], Flow); 5] = [
            (&[], Flow::None),
            (&b"\x0a\x00"[..], Flow::None),
            (&b"\x0a\x10xtls-rprx-vision"[..], Flow::Vision),
            (&b"\x0a\x17xtls-rprx-vision-udp443"[..], Flow::Other),
            (&b"\x0a\x04none"[..], Flow::Other),
        ];
        for (addons, want) in cases {
            assert_eq!(flow_of(addons), want, "{addons:?}");
        }
    }

    fn is_fresh(open: &VisionOpen) -> bool {
        open.command == -1 && open.content == -1 && open.padding == -1
    }

    fn first_draw() -> u32 {
        let mut scratch = [0u8; 64];
        crate::record::fill_exact(&SEAL_KEY, &SEAL_NONCE, 0, &mut scratch);
        u32::from_le_bytes([scratch[0], scratch[1], scratch[2], scratch[3]])
    }

    #[test]
    fn seal_structure_matches_the_format() {
        let mut seal = VisionSeal::new(&SEAL_KEY, &SEAL_NONCE, &SEAL_UUID);
        let content = b"abc";
        let pad = (first_draw() as usize % SHORT_SPAN).min(RECORD_CAP - RECORD_OVERHEAD - 3);
        let mut out = vec![0u8; seal_len(content.len(), pad, true)];
        let n = seal.seal(&mut out, content, VisionCommand::End, false);
        assert_eq!(n, out.len());
        assert_eq!(&out[..16], &SEAL_UUID);
        assert_eq!(out[16], 0x01);
        assert_eq!(&out[17..19], &[0x00, 0x03]);
        assert_eq!(&out[19..21], &(pad as u16).to_be_bytes());
        assert_eq!(&out[21..24], b"abc");
        assert!(out[24..].iter().all(|&b| b == 0));
        assert_eq!(seal.blocks_used(), 1);
        let mut out2 = vec![0u8; 512];
        let n2 = seal.seal(&mut out2, content, VisionCommand::Continue, false);
        assert_eq!(out2[0], 0x00);
        assert_eq!(n2, seal_len(content.len(), n2 - 5 - content.len(), false));
    }

    #[test]
    fn seal_open_round_trips_every_length() {
        for &len in &[
            0usize, 1, 15, 16, 17, 63, 64, 65, 255, 256, 899, 900, 901, 4096, 8171,
        ] {
            for &long in &[false, true] {
                for command in [
                    VisionCommand::Continue,
                    VisionCommand::End,
                    VisionCommand::Direct,
                ] {
                    let mut seal = VisionSeal::new(&SEAL_KEY, &SEAL_NONCE, &SEAL_UUID);
                    let mut open = VisionOpen::new(&SEAL_UUID);
                    let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                    let mut sealed = vec![0u8; seal_len(len, 8192, true)];
                    let n = seal.seal(&mut sealed, &content, command, long);
                    assert!(n <= RECORD_CAP, "len {len}: sealed record exceeds the cap");
                    let mut plain = vec![0u8; n];
                    let (written, completed) = open.open(&sealed[..n], &mut plain);
                    assert_eq!(&plain[..written], &content[..], "len {len}: round trip");
                    assert_eq!(completed, Some(command), "len {len}: command reported");
                }
            }
        }
    }

    #[test]
    fn open_accepts_hand_built_records() {
        let id = [0x11u8; 16];
        let mut buf = Vec::new();
        buf.extend_from_slice(&id);
        buf.extend_from_slice(&[0x00, 0x00, 0x02, 0x00, 0x01]);
        buf.extend_from_slice(b"hi");
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00]);
        buf.extend_from_slice(b"!");
        let mut open = VisionOpen::new(&id);
        let mut out = vec![0u8; buf.len()];
        let (written, completed) = open.open(&buf, &mut out);
        assert_eq!(&out[..written], b"hi!");
        assert_eq!(completed, Some(VisionCommand::Continue));
        let mut buf2 = Vec::new();
        buf2.extend_from_slice(&id);
        buf2.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x02, b'z', 0x00, 0x00]);
        buf2.extend_from_slice(b"RAW");
        let mut open2 = VisionOpen::new(&id);
        let mut out2 = vec![0u8; buf2.len()];
        let (written2, completed2) = open2.open(&buf2, &mut out2);
        assert_eq!(&out2[..written2], b"zRAW");
        assert_eq!(completed2, Some(VisionCommand::End));
        assert!(is_fresh(&open2));
        let (written3, completed3) = open2.open(b"more", &mut out2);
        assert_eq!(&out2[..written3], b"more");
        assert_eq!(completed3, None);
    }

    #[test]
    fn open_mirrors_the_passthrough_quirks() {
        let id = [0x11u8; 16];
        let mut open = VisionOpen::new(&id);
        let mut out = vec![0u8; 20];
        let (written, completed) = open.open(b"0123456789abcdef0123", &mut out);
        assert_eq!(&out[..written], b"0123456789abcdef0123");
        assert_eq!(completed, None);
        let mut short = Vec::new();
        short.extend_from_slice(&id[..10]);
        let mut open2 = VisionOpen::new(&id);
        let mut out2 = vec![0u8; 10];
        let (written2, completed2) = open2.open(&short, &mut out2);
        assert_eq!(&out2[..written2], &short[..]);
        assert_eq!(completed2, None);
        let mut buf = Vec::new();
        buf.extend_from_slice(&id);
        buf.extend_from_slice(&[0x07, 0x00, 0x01, 0x00, 0x00, b'q']);
        let mut open3 = VisionOpen::new(&id);
        let mut out3 = vec![0u8; buf.len()];
        let (written3, completed3) = open3.open(&buf, &mut out3);
        assert_eq!(&out3[..written3], b"q");
        assert_eq!(completed3, None);
        assert!(is_fresh(&open3));
    }

    #[test]
    fn open_split_feeds_match_whole_feeds() {
        let id = [0x22u8; 16];
        let content: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let mut seal = VisionSeal::new(&SEAL_KEY, &SEAL_NONCE, &id);
        let mut sealed = vec![0u8; seal_len(content.len(), 8192, true)];
        let n = seal.seal(&mut sealed, &content, VisionCommand::Continue, true);
        for chunk in 1..9 {
            let mut open = VisionOpen::new(&id);
            let mut got = Vec::new();
            for piece in sealed[..n].chunks(chunk) {
                let mut out = vec![0u8; piece.len()];
                let (written, _) = open.open(piece, &mut out);
                got.extend_from_slice(&out[..written]);
            }
            assert_eq!(
                got,
                sealed[..n],
                "chunk {chunk}: short first read passes through"
            );
        }
        for chunk in [21, 22, 30] {
            let mut open = VisionOpen::new(&id);
            let mut got = Vec::new();
            let mut last = None;
            for piece in sealed[..n].chunks(chunk) {
                let mut out = vec![0u8; piece.len()];
                let (written, completed) = open.open(piece, &mut out);
                got.extend_from_slice(&out[..written]);
                if completed.is_some() {
                    last = completed;
                }
            }
            assert_eq!(got, content, "chunk {chunk}: split feed");
            assert_eq!(
                last,
                Some(VisionCommand::Continue),
                "chunk {chunk}: command"
            );
        }
    }

    fn prng_next(state: &mut u32) -> u32 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *state = x;
        x
    }

    #[test]
    fn open_seeded_splits_match_whole_feeds() {
        let id = [0x33u8; 16];
        let first: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
        let mut seal = VisionSeal::new(&SEAL_KEY, &SEAL_NONCE, &id);
        let mut sealed = vec![0u8; seal_len(first.len(), 8192, true) + 64];
        let mut n = seal.seal(&mut sealed, &first, VisionCommand::Continue, true);
        n += seal.seal(&mut sealed[n..], b"second!", VisionCommand::End, false);
        sealed.truncate(n);
        sealed.extend_from_slice(b"raw tail");
        let mut whole_out = vec![0u8; sealed.len()];
        let mut whole = VisionOpen::new(&id);
        let (written, completed) = whole.open(&sealed, &mut whole_out);
        // Thirty-two seeded chunkings, seed printed so a red run replays anywhere.
        let mut seed = 0x1234_5678u32;
        for _ in 0..32 {
            let mut open = VisionOpen::new(&id);
            let mut got = Vec::new();
            let mut last = None;
            let mut at = 0;
            while at < sealed.len() {
                // Chunkings start framed: short of a UUID prefix the first read passes through.
                let take = (prng_next(&mut seed) as usize % 48 + 21).min(sealed.len() - at);
                let mut out = vec![0u8; take];
                let (w, c) = open.open(&sealed[at..at + take], &mut out);
                got.extend_from_slice(&out[..w]);
                if c.is_some() {
                    last = c;
                }
                at += take;
            }
            assert_eq!(got, &whole_out[..written], "seed {seed:#x}");
            assert_eq!(last, completed, "seed {seed:#x}");
        }
    }

    #[test]
    fn blocks_are_exactly_the_draws_taken() {
        let mut seal = VisionSeal::new(&SEAL_KEY, &SEAL_NONCE, &SEAL_UUID);
        let mut out = vec![0u8; 512];
        seal.seal(&mut out, b"x", VisionCommand::Continue, false);
        assert_eq!(seal.blocks_used(), 1);
        for _ in 0..15 {
            seal.seal(&mut out, b"x", VisionCommand::Continue, false);
        }
        assert_eq!(seal.blocks_used(), 1);
        seal.seal(&mut out, b"x", VisionCommand::Continue, false);
        assert_eq!(seal.blocks_used(), 2);
    }

    #[test]
    fn seal_len_is_exact() {
        let mut seal = VisionSeal::new(&SEAL_KEY, &SEAL_NONCE, &SEAL_UUID);
        for &(len, uuid_first) in &[(0usize, true), (1, false), (64, false), (8171, false)] {
            let mut out = vec![0u8; seal_len(len, 8192, uuid_first)];
            let content = vec![0xabu8; len];
            let n = seal.seal(&mut out, &content, VisionCommand::End, true);
            let base = if uuid_first { 16 } else { 0 } + 5 + len;
            assert_eq!(n, seal_len(len, n - base, uuid_first));
        }
    }
}
