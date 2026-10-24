//! Trojan as a share link and as the request header it speaks: the password's SHA-224 in hex, then the command and its destination.

use std::collections::BTreeMap;
use std::fmt;

use crate::addr::{Addr, MAX_DOMAIN};
use crate::policy::UnsafeOptIn;
use crate::transport::{Security, Support, TransportKind};

pub const SCHEME: &str = "trojan://";

/// The command byte after the password: what the association carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Connect = 1,
    Udp = 3,
}

impl Command {
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Connect),
            3 => Some(Self::Udp),
            _ => None,
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The 56 lowercase hex digits of the password's SHA-224: what the wire carries instead of the password.
#[must_use]
pub fn key(password: &str) -> [u8; 56] {
    use sha2::Digest as _;
    let digest = sha2::Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    for (slot, byte) in out.as_chunks_mut::<2>().0.iter_mut().zip(digest.iter()) {
        slot[0] = HEX[usize::from(byte >> 4)];
        slot[1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanLink {
    password: String,
    key: [u8; 56],
    pub host: String,
    pub port: u16,
    params: BTreeMap<String, String>,
    pub name: String,
}

impl TrojanLink {
    pub fn parse(link: &str) -> Result<Self, TrojanError> {
        let rest = link.strip_prefix(SCHEME).ok_or(TrojanError::Scheme)?;
        let (before_hash, name_enc) = rest.split_once('#').unwrap_or((rest, ""));
        let (authority, query) = before_hash.split_once('?').unwrap_or((before_hash, ""));
        let (credential, host_port) = authority.rsplit_once('@').ok_or(TrojanError::Shape)?;
        // Most panels emit `host:port/?query`; the path carries nothing (the transport path travels in the query) and must not reach the port.
        let host_port = host_port
            .split_once('/')
            .map_or(host_port, |(head, _)| head);
        let (host, port) = split_host_port(host_port).ok_or(TrojanError::Shape)?;
        let password = percent_decode(credential);
        if password.is_empty() {
            return Err(TrojanError::Password);
        }
        let mut params = BTreeMap::new();
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = percent_decode(raw_key).to_ascii_lowercase();
            let mut value = percent_decode(raw_value);
            // Xray lower-cases these names; panels emit `type=Tcp` or `fp=Chrome`.
            if matches!(name.as_str(), "type" | "security" | "fp" | "headertype") {
                value.make_ascii_lowercase();
            }
            params.insert(name, value);
        }
        let key = key(&password);
        Ok(Self {
            password,
            key,
            host: host.to_owned(),
            port,
            params,
            name: percent_decode(name_enc),
        })
    }

    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    #[must_use]
    pub fn key(&self) -> &[u8; 56] {
        &self.key
    }

    /// A query value under any spelling: the parser lower-cases the keys it stores, and a caller's camelCase finds them here.
    #[must_use]
    pub fn param(&self, key: &str) -> &str {
        self.params
            .iter()
            .find(|(stored, _)| stored.eq_ignore_ascii_case(key))
            .map_or("", |(_, value)| value)
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
    pub fn header_type(&self) -> &str {
        self.param("headertype")
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        self.param("fp")
    }

    #[must_use]
    pub fn wants_unsafe_fingerprint(&self) -> bool {
        self.fingerprint().starts_with("unsafe-") || self.param("allowUnsafeFp") == "1"
    }

    /// The verdict under no unsafe consent: what a bare link is worth to a default-configured operator.
    #[must_use]
    pub fn support(&self) -> Support {
        self.support_opted(UnsafeOptIn::none())
    }

    /// A cleartext credential on a public address is the same leak here as on the VLESS row, so the same consent clears it.
    #[must_use]
    pub fn support_opted(&self, opt_in: UnsafeOptIn) -> Support {
        let security = match self.security() {
            Security::NoneToPublic if opt_in.plaintext_to_public() => Security::None,
            Security::NoneToPublic => {
                return Support::UnsafeRequiresOptIn {
                    reason: "security=none to a public address: explicit opt-in required",
                };
            }
            other => other,
        };
        if self.wants_unsafe_fingerprint() && !opt_in.unsafe_fingerprint() {
            return Support::UnsafeRequiresOptIn {
                reason: "unsafe fingerprint requested: re-run with explicit opt-in",
            };
        }
        let (plain, tls) = match self.transport_kind() {
            TransportKind::Tcp if self.header_type() == "http" => {
                ("trojan-httpheader", "trojan-httpheader-tls")
            }
            TransportKind::Tcp => ("trojan-tcp", "trojan-tcp-tls"),
            TransportKind::Ws => ("trojan-ws", "trojan-ws-tls"),
            TransportKind::HttpUpgrade => ("trojan-httpupgrade", "trojan-httpupgrade-tls"),
            TransportKind::Grpc => ("trojan-grpc", "trojan-grpc-tls"),
            TransportKind::Xhttp => ("trojan-xhttp", "trojan-xhttp-tls"),
            TransportKind::Kcp => ("trojan-kcp", "trojan-kcp-tls"),
            other => {
                return Support::Planned {
                    reason: planned_reason(other),
                }
            }
        };
        match security {
            Security::None => Support::Implemented { method: plain },
            Security::Tls => Support::Implemented { method: tls },
            Security::Reality => Support::Planned {
                reason: "trojan reality: refused rather than served as a plaintext session",
            },
            _ => Support::Planned {
                reason: "unknown security: parses, not dialled",
            },
        }
    }

    /// The header's length for this destination: the key, the CRLF, the command, the family byte and body, the port, the closing CRLF.
    #[must_use]
    pub fn header_len(&self, target_host: &str) -> usize {
        56 + 2 + 1 + Addr::of(target_host).wire_len() + 2 + 2
    }

    #[inline]
    pub fn encode_into(
        &self,
        command: Command,
        target_host: &str,
        target_port: u16,
        out: &mut [u8],
    ) -> usize {
        let addr = Addr::of(target_host);
        let need = 56 + 2 + 1 + addr.wire_len() + 2 + 2;
        assert!(out.len() >= need, "trojan header buffer too short");
        out[..56].copy_from_slice(&self.key);
        out[56..58].copy_from_slice(b"\r\n");
        out[58] = command.byte();
        let mut at = 59;
        // Trojan numbers the families the SOCKS way, which is not the VLESS numbering `Addr` writes.
        match addr {
            Addr::V4(octets) => {
                out[at] = 1;
                out[at + 1..at + 5].copy_from_slice(&octets);
                at += 5;
            }
            Addr::V6(octets) => {
                out[at] = 4;
                out[at + 1..at + 17].copy_from_slice(&octets);
                at += 17;
            }
            Addr::Name(name) => {
                out[at] = 3;
                out[at + 1] = name.len() as u8;
                out[at + 2..at + 2 + name.len()].copy_from_slice(name);
                at += 2 + name.len();
            }
        }
        out[at..at + 2].copy_from_slice(&target_port.to_be_bytes());
        at += 2;
        out[at..at + 2].copy_from_slice(b"\r\n");
        at + 2
    }

    #[must_use]
    pub fn encode_header(&self, command: Command, target_host: &str, target_port: u16) -> Vec<u8> {
        let len = self.header_len(target_host);
        let mut out = vec![0u8; len];
        let written = self.encode_into(command, target_host, target_port, &mut out);
        debug_assert_eq!(written, len);
        out
    }
}

/// The longest header the wire can carry: a full-length name is what `Addr` truncates at.
pub const HEADER_MAX: usize = 56 + 2 + 1 + (1 + 1 + MAX_DOMAIN) + 2 + 2;

fn planned_reason(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Quic => "trojan-quic: parses, the carrier is not wired for trojan",
        TransportKind::Http => {
            "http/h2/h3: removed by Xray-core in favour of xhttp; parses, no transport"
        }
        TransportKind::Hysteria => {
            "trojan-hysteria: the carrier's options are not expressible in a bare link query"
        }
        TransportKind::Masque => "trojan-masque: parses, transport not scheduled",
        TransportKind::Xdrive => "trojan-xdrive: parses, transport not scheduled",
        TransportKind::Other => "unknown type: parses, transport not scheduled",
        // Every carrier this tree dials returned above.
        _ => "trojan: parses, transport not scheduled",
    }
}

/// `[v6]:port`, `host:port`; a bare IPv6 literal has several colons and no port, so it is refused as the reference refuses it.
fn split_host_port(text: &str) -> Option<(&str, u16)> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = text.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host, port.parse().ok()?))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    if !bytes.contains(&b'%') {
        return text.to_owned();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[at + 1]), hex(bytes[at + 2])) {
                out.push(hi << 4 | lo);
                at += 3;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanError {
    Scheme,
    Shape,
    Password,
}

impl fmt::Display for TrojanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => write!(f, "link must start with trojan://"),
            Self::Shape => write!(f, "link must look like trojan://password@host:port?..."),
            Self::Password => write!(f, "trojan link has an empty password"),
        }
    }
}

impl std::error::Error for TrojanError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_the_hex_sha224_the_references_speak() {
        assert_eq!(
            key("an-example-shared-password"),
            *b"73317e3bf920a459723610d27b71cadc07061d8f0d8587e041944896"
        );
        assert_eq!(
            key("password"),
            *b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert!(key("").iter().all(u8::is_ascii_hexdigit));
        assert_eq!(key("").len(), 56);
    }

    #[test]
    fn a_share_link_keeps_the_authority_and_lower_cases_what_xray_does() {
        let link = TrojanLink::parse(
            "trojan://p%40ss@EXAMPLE.invalid:443/?type=WS&security=TLS&path=%2Fws&sni=front.example&headertype=HTTP#a%20name",
        )
        .expect("parses");
        assert_eq!(link.password(), "p@ss");
        assert_eq!(link.host, "EXAMPLE.invalid");
        assert_eq!(link.port, 443);
        assert_eq!(link.name, "a name");
        assert_eq!(link.transport_kind(), TransportKind::Ws);
        assert_eq!(link.security(), Security::Tls);
        assert_eq!(link.header_type(), "http");
        assert_eq!(link.param("headerType"), "http");
        assert_eq!(link.param("sni"), "front.example");
        assert_eq!(link.param("path"), "/ws");
    }

    #[test]
    fn the_link_shapes_panels_and_sing_box_emit_parse() {
        for (text, host, port) in [
            ("trojan://pw@example.com:443", "example.com", 443),
            (
                "trojan://pw@example.com:8443/?security=tls",
                "example.com",
                8443,
            ),
            ("trojan://pw@[::1]:443?type=grpc", "::1", 443),
            (
                "trojan://pw@sub.example.test:443#frag",
                "sub.example.test",
                443,
            ),
            ("trojan://pw@localhost:1080", "localhost", 1080),
        ] {
            let link = TrojanLink::parse(text).expect(text);
            assert_eq!((link.host.as_str(), link.port), (host, port), "{text}");
        }
    }

    #[test]
    fn a_malformed_link_is_refused_by_name() {
        assert_eq!(
            TrojanLink::parse("vless://pw@host:443"),
            Err(TrojanError::Scheme)
        );
        assert_eq!(
            TrojanLink::parse("trojan://pw@host/"),
            Err(TrojanError::Shape)
        );
        assert_eq!(
            TrojanLink::parse("trojan://pw@:443"),
            Err(TrojanError::Shape)
        );
        assert_eq!(
            TrojanLink::parse("trojan://pw@[::1]/"),
            Err(TrojanError::Shape)
        );
        assert_eq!(
            TrojanLink::parse("trojan://@host:443"),
            Err(TrojanError::Password)
        );
        assert_eq!(
            TrojanLink::parse("trojan://host:443"),
            Err(TrojanError::Shape)
        );
    }

    #[test]
    fn the_header_is_the_key_command_address_and_port_the_wire_defines() {
        let link = TrojanLink::parse("trojan://pw@example.com:443").expect("parses");
        let mut want = link.key().to_vec();
        want.extend_from_slice(b"\r\n\x01\x03\x0fwww.example.com");
        want.extend_from_slice(&8443u16.to_be_bytes());
        want.extend_from_slice(b"\r\n");
        assert_eq!(
            link.encode_header(Command::Connect, "www.example.com", 8443),
            want
        );
        assert_eq!(link.header_len("www.example.com"), want.len());

        let key = link.key().to_vec();
        for (host, port, body) in [
            ("192.0.2.53", 8080u16, vec![1, 192, 0, 2, 53]),
            ("2001:db8::1", 443, {
                let mut body = vec![4];
                body.extend_from_slice(
                    &"2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                body
            }),
        ] {
            let mut want = key.clone();
            want.extend_from_slice(b"\r\n\x03");
            want.extend_from_slice(&body);
            want.extend_from_slice(&port.to_be_bytes());
            want.extend_from_slice(b"\r\n");
            assert_eq!(link.encode_header(Command::Udp, host, port), want, "{host}");
        }
    }

    #[test]
    fn the_encoder_writes_into_the_caller_buffer_and_allocates_nothing() {
        let link = TrojanLink::parse("trojan://pw@example.com:443").expect("parses");
        let mut buf = [0u8; HEADER_MAX];
        let (written, counts) = crate::alloc_count::measure(|| {
            link.encode_into(Command::Connect, "www.example.com", 8443, &mut buf)
        });
        assert_eq!(counts.allocs, 0, "{counts:?}");
        assert_eq!(written, link.header_len("www.example.com"));
        assert_eq!(
            &buf[..written],
            link.encode_header(Command::Connect, "www.example.com", 8443)
        );
        let longest = "a".repeat(MAX_DOMAIN);
        assert!(link.header_len(&longest) <= HEADER_MAX);
    }

    #[test]
    fn the_support_verdict_reads_the_state_cell() {
        for (text, method) in [
            ("trojan://pw@example.com:443?security=tls", "trojan-tcp-tls"),
            ("trojan://pw@127.0.0.1:443", "trojan-tcp"),
            (
                "trojan://pw@example.com:443?security=tls&type=ws",
                "trojan-ws-tls",
            ),
            ("trojan://pw@127.0.0.1:443?type=ws", "trojan-ws"),
            (
                "trojan://pw@example.com:443?security=tls&type=httpupgrade",
                "trojan-httpupgrade-tls",
            ),
            (
                "trojan://pw@example.com:443?security=tls&type=grpc",
                "trojan-grpc-tls",
            ),
            ("trojan://pw@127.0.0.1:443?type=xhttp", "trojan-xhttp"),
            (
                "trojan://pw@example.com:443?security=tls&type=kcp",
                "trojan-kcp-tls",
            ),
            ("trojan://pw@127.0.0.1:443?type=kcp", "trojan-kcp"),
            (
                "trojan://pw@example.com:443?security=tls&headerType=http",
                "trojan-httpheader-tls",
            ),
            (
                "trojan://pw@127.0.0.1:443?headerType=http",
                "trojan-httpheader",
            ),
        ] {
            assert_eq!(
                TrojanLink::parse(text).expect(text).support(),
                Support::Implemented { method },
                "{text}"
            );
        }
        for (text, want) in [
            (
                "trojan://pw@example.com:443?security=tls&type=quic",
                Support::Planned {
                    reason: "trojan-quic: parses, the carrier is not wired for trojan",
                },
            ),
            (
                "trojan://pw@127.0.0.1:443?security=reality",
                Support::Planned {
                    reason: "trojan reality: refused rather than served as a plaintext session",
                },
            ),
            (
                "trojan://pw@198.51.100.3:443",
                Support::UnsafeRequiresOptIn {
                    reason: "security=none to a public address: explicit opt-in required",
                },
            ),
            (
                "trojan://pw@example.com:443?security=tls&fp=unsafe-chrome",
                Support::UnsafeRequiresOptIn {
                    reason: "unsafe fingerprint requested: re-run with explicit opt-in",
                },
            ),
        ] {
            assert_eq!(
                TrojanLink::parse(text).expect(text).support(),
                want,
                "{text}"
            );
        }
    }

    #[test]
    fn each_consent_clears_only_its_own_veto() {
        let plain = TrojanLink::parse("trojan://pw@198.51.100.3:443").expect("parses");
        let fp = TrojanLink::parse("trojan://pw@example.com:443?security=tls&fp=unsafe-chrome")
            .expect("parses");
        assert_eq!(
            plain.support_opted(UnsafeOptIn::none().allow_plaintext_to_public()),
            Support::Implemented {
                method: "trojan-tcp"
            }
        );
        assert!(matches!(
            fp.support_opted(UnsafeOptIn::none().allow_plaintext_to_public()),
            Support::UnsafeRequiresOptIn { .. }
        ));
        assert_eq!(
            fp.support_opted(UnsafeOptIn::none().allow_unsafe_fingerprint()),
            Support::Implemented {
                method: "trojan-tcp-tls"
            }
        );
        // A link that names no fingerprint has no fingerprint veto for the other consent to leave standing.
        assert!(matches!(
            plain.support_opted(UnsafeOptIn::none().allow_unsafe_fingerprint()),
            Support::UnsafeRequiresOptIn { .. }
        ));
    }

    #[test]
    fn the_command_byte_round_trips() {
        assert_eq!(Command::Connect.byte(), 1);
        assert_eq!(Command::Udp.byte(), 3);
        assert_eq!(Command::from_byte(1), Some(Command::Connect));
        assert_eq!(Command::from_byte(3), Some(Command::Udp));
        assert_eq!(Command::from_byte(2), None);
    }
}
