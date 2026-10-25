use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::json::Json;
use crate::proxy::Destination;
use crate::router::{self, DomainMatcher, IpMatcher, Network};

const SNIFF_WAIT: Duration = Duration::from_millis(200);
const SNIFF_LIMIT: usize = 32 * 1024;

static CONFIGS: OnceLock<Mutex<HashMap<String, Arc<Sniffing>>>> = OnceLock::new();
thread_local! {
    static CURRENT: std::cell::RefCell<Option<Arc<Sniffing>>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn register(address: &str, config: Option<Arc<Sniffing>>) {
    if let Ok(mut configs) = CONFIGS.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        match config {
            Some(config) => {
                configs.insert(address.to_owned(), config);
            }
            None => {
                configs.remove(address);
            }
        }
    }
}

pub(crate) fn for_listener(local: Option<SocketAddr>, address: &str) -> Option<Arc<Sniffing>> {
    let configs = CONFIGS.get()?.lock().ok()?;
    local
        .and_then(|local| configs.get(&local.to_string()))
        .or_else(|| configs.get(address))
        .cloned()
}

pub(crate) fn install_current(config: Option<Arc<Sniffing>>) {
    CURRENT.with(|current| {
        *current.borrow_mut() = config;
    });
}

pub(crate) fn current() -> Option<Arc<Sniffing>> {
    CURRENT.with(|current| current.borrow().clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Http,
    Tls,
    Quic,
    Bittorrent,
    FakeDns,
}

#[derive(Debug)]
pub(crate) struct Sniffing {
    enabled: bool,
    protocols: Vec<Protocol>,
    domains_excluded: Option<DomainMatcher>,
    ips_excluded: Option<IpMatcher>,
    metadata_only: bool,
    route_only: bool,
}

#[derive(Debug)]
pub(crate) struct Sniffed {
    pub(crate) protocol: &'static str,
    pub(crate) domain: String,
    pub(crate) override_destination: bool,
    pub(crate) fake_ip: bool,
}

impl Sniffing {
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn should_dial_override(&self, found: &Sniffed) -> bool {
        found.override_destination && (!self.route_only || found.fake_ip)
    }

    pub(crate) fn inspect(
        &self,
        asked: &Destination,
        network: Network,
        client: &crate::conn::Connection,
    ) -> Option<Sniffed> {
        if !self.enabled || network != Network::Tcp {
            return None;
        }
        let fake = match asked {
            Destination::Address(address) => {
                crate::dnsapp::installed().and_then(|resolver| resolver.domain_of(address.ip()))
            }
            Destination::Name(_, _) => None,
        };
        if let Some(domain) = fake {
            return Some(self.result(asked, "fakedns", domain, true));
        }
        if self.metadata_only {
            return None;
        }
        let _ = client.set_read_timeout(Some(SNIFF_WAIT));
        let mut buffer = vec![0u8; SNIFF_LIMIT];
        let deadline = Instant::now() + SNIFF_WAIT;
        let found = loop {
            match client.peek(&mut buffer) {
                Ok(0) => break None,
                Ok(n) => {
                    if let Some(found) = self.sniff_bytes(asked, &buffer[..n]) {
                        break Some(found);
                    }
                    if n == buffer.len() || Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break None,
            }
        };
        let _ = client.set_read_timeout(None);
        found
    }

    fn sniff_bytes(&self, asked: &Destination, bytes: &[u8]) -> Option<Sniffed> {
        if let Some((protocol, domain)) = sniff_http(bytes) {
            return Some(self.result(asked, protocol, domain, false));
        }
        if let Some(domain) = sniff_tls(bytes) {
            return Some(self.result(asked, "tls", domain, false));
        }
        if sniff_bittorrent(bytes) {
            return Some(self.result(asked, "bittorrent", String::new(), false));
        }
        None
    }

    pub(crate) fn inspect_udp(&self, asked: &Destination, bytes: &[u8]) -> Option<Sniffed> {
        if !self.enabled {
            return None;
        }
        if let Destination::Address(address) = asked {
            if let Some(domain) =
                crate::dnsapp::installed().and_then(|resolver| resolver.domain_of(address.ip()))
            {
                return Some(self.result(asked, "fakedns", domain, true));
            }
        }
        if self.metadata_only {
            return None;
        }
        if sniff_bittorrent(bytes) || sniff_utp(bytes) {
            return Some(self.result(asked, "bittorrent", String::new(), false));
        }
        if let Some(domain) = sniff_quic(bytes) {
            return Some(self.result(asked, "quic", domain, false));
        }
        None
    }

    fn result(
        &self,
        asked: &Destination,
        protocol: &'static str,
        domain: String,
        fake_ip: bool,
    ) -> Sniffed {
        let mut override_destination = !domain.is_empty() && self.permits(protocol);
        if override_destination {
            if let Some(domains) = &self.domains_excluded {
                let lower = domain.to_ascii_lowercase();
                override_destination = !domains.matches(&lower, &lower);
            }
        }
        if override_destination {
            if let (Destination::Address(address), Some(ips)) = (asked, &self.ips_excluded) {
                override_destination = !ips.matches(address.ip());
            }
        }
        Sniffed {
            protocol,
            domain,
            override_destination,
            fake_ip,
        }
    }

    fn permits(&self, protocol: &'static str) -> bool {
        self.protocols.iter().any(|listed| {
            let listed = match listed {
                Protocol::Http => "http",
                Protocol::Tls => "tls",
                Protocol::Quic => "quic",
                Protocol::Bittorrent => "bittorrent",
                Protocol::FakeDns => "fakedns",
            };
            protocol.starts_with(listed) || listed.starts_with(protocol)
        })
    }
}

fn strings(value: &Json, field: &str) -> Result<Option<Vec<String>>, String> {
    if matches!(value, Json::Null) {
        return Ok(None);
    }
    let items = if let Some(text) = value.as_str() {
        text.split(',').map(str::to_owned).collect()
    } else if let Some(items) = value.as_arr() {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            out.push(
                item.as_str()
                    .ok_or_else(|| format!("sniffing {field} has a value that is not a string"))?
                    .to_owned(),
            );
        }
        out
    } else {
        return Err(format!("sniffing {field} is not a string or array"));
    };
    Ok((!items.is_empty()).then_some(items))
}

pub(crate) fn parse(value: Option<&Json>) -> Result<Option<Arc<Sniffing>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if matches!(value, Json::Null) {
        return Ok(None);
    }
    let Json::Obj(pairs) = value else {
        return Err("sniffing is not an object".into());
    };
    let mut enabled = false;
    let mut protocols = Vec::new();
    let mut domains_value = None;
    let mut ips_value = None;
    let mut metadata_only = false;
    let mut route_only = false;
    for (key, field) in pairs {
        match key.as_str() {
            "enabled" => {
                enabled = field
                    .as_bool()
                    .ok_or_else(|| "sniffing enabled is not a boolean".to_owned())?;
            }
            "destOverride" | "destinationOverride" => {
                let Some(list) = strings(field, "destOverride")? else {
                    continue;
                };
                for item in list {
                    match item.to_ascii_lowercase().as_str() {
                        "http" => protocols.push(Protocol::Http),
                        "tls" | "https" | "ssl" => protocols.push(Protocol::Tls),
                        "quic" => protocols.push(Protocol::Quic),
                        "bittorrent" => protocols.push(Protocol::Bittorrent),
                        "fakedns" | "fakedns+others" => protocols.push(Protocol::FakeDns),
                        other => {
                            return Err(format!(
                                "sniffing destOverride `{other}` is not http, tls, quic, bittorrent, fakedns or fakedns+others"
                            ))
                        }
                    }
                }
            }
            "domainsExcluded" => domains_value = Some(field),
            "ipsExcluded" => ips_value = Some(field),
            "metadataOnly" => {
                metadata_only = field
                    .as_bool()
                    .ok_or_else(|| "sniffing metadataOnly is not a boolean".to_owned())?;
            }
            "routeOnly" => {
                route_only = field
                    .as_bool()
                    .ok_or_else(|| "sniffing routeOnly is not a boolean".to_owned())?;
            }
            _ => {}
        }
    }
    let mut assets = router::Assets::new(router::asset_dirs());
    let domains_excluded = match domains_value {
        Some(value) => match strings(value, "domainsExcluded")? {
            Some(items) => {
                let mut matcher = DomainMatcher::new();
                for item in items {
                    router::add_domain(&mut matcher, &item, &mut assets)?;
                }
                matcher.finish()?;
                Some(matcher)
            }
            None => None,
        },
        None => None,
    };
    let ips_excluded = match ips_value {
        Some(value) => {
            let items = strings(value, "ipsExcluded")?.unwrap_or_default();
            if items.is_empty() {
                None
            } else {
                let json = Json::Arr(items.into_iter().map(Json::Str).collect());
                Some(router::ip_matcher(
                    &json,
                    &mut assets,
                    "sniffing ipsExcluded",
                )?)
            }
        }
        None => None,
    };
    Ok(Some(Arc::new(Sniffing {
        enabled,
        protocols,
        domains_excluded,
        ips_excluded,
        metadata_only,
        route_only,
    })))
}

fn sniff_http(bytes: &[u8]) -> Option<(&'static str, String)> {
    let end = bytes.iter().position(|byte| *byte == b'\n')?;
    let first = &bytes[..end];
    let method = first.split(|byte| *byte == b' ').next()?;
    let known = [
        b"GET".as_slice(),
        b"POST",
        b"HEAD",
        b"PUT",
        b"DELETE",
        b"OPTIONS",
        b"CONNECT",
    ];
    if !known.iter().any(|name| method.eq_ignore_ascii_case(name)) {
        return None;
    }
    let mut at = end + 1;
    while at < bytes.len() {
        let Some(line_end) = bytes[at..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let line = &bytes[at..at + line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            if line[..colon].eq_ignore_ascii_case(b"host") {
                let value = std::str::from_utf8(&line[colon + 1..]).ok()?.trim();
                return Some(("http1", http_host(value)?.to_ascii_lowercase()));
            }
        }
        at += line_end + 1;
    }
    None
}

fn http_host(value: &str) -> Option<&str> {
    if value.is_empty() || value.starts_with('/') {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        return Some(&rest[..rest.find(']')?]);
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Some(value);
    };
    if host.contains(':') || (!port.is_empty() && port.parse::<u16>().is_err()) {
        return None;
    }
    Some(host)
}

fn sniff_tls(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 || bytes[0] != 0x16 || bytes[1] != 3 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if bytes.len() < 5 + length {
        return None;
    }
    sniff_client_hello(&bytes[5..5 + length])
}

fn sniff_client_hello(body: &[u8]) -> Option<String> {
    if body.first().copied()? != 0x01 {
        return None;
    }
    if body.len() < 4 {
        return None;
    }
    let hello_len = usize::from(body[1]) << 16 | usize::from(body[2]) << 8 | usize::from(body[3]);
    if body.len() < 4 + hello_len {
        return None;
    }
    let hello = &body[4..4 + hello_len];
    if hello.len() < 34 {
        return None;
    }
    let mut at = 34;
    let session = usize::from(*hello.get(at)?);
    at += 1 + session;
    let suites = usize::from(u16::from_be_bytes([*hello.get(at)?, *hello.get(at + 1)?]));
    at += 2 + suites;
    let compression = usize::from(*hello.get(at)?);
    at += 1 + compression;
    let extensions = usize::from(u16::from_be_bytes([*hello.get(at)?, *hello.get(at + 1)?]));
    at += 2;
    if hello.len() < at + extensions {
        return None;
    }
    let mut data = &hello[at..at + extensions];
    while !data.is_empty() {
        if data.len() < 4 {
            return None;
        }
        let kind = u16::from_be_bytes([data[0], data[1]]);
        let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
        data = &data[4..];
        if data.len() < length {
            return None;
        }
        if kind == 0 {
            let extension = &data[..length];
            if extension.len() < 2 {
                return None;
            }
            let names_len = usize::from(u16::from_be_bytes([extension[0], extension[1]]));
            let mut names = extension.get(2..2 + names_len)?;
            if names.len() != names_len {
                return None;
            }
            while !names.is_empty() {
                if names.len() < 3 {
                    return None;
                }
                let kind = names[0];
                let length = usize::from(u16::from_be_bytes([names[1], names[2]]));
                names = &names[3..];
                if names.len() < length {
                    return None;
                }
                if kind == 0 {
                    let name = std::str::from_utf8(&names[..length]).ok()?;
                    if name.is_empty()
                        || name.ends_with('.')
                        || name.bytes().any(|byte| byte <= b' ')
                    {
                        return None;
                    }
                    return Some(name.to_owned());
                }
                names = &names[length..];
            }
        }
        data = &data[length..];
    }
    None
}

fn sniff_bittorrent(bytes: &[u8]) -> bool {
    bytes.len() >= 20 && bytes[0] == 19 && &bytes[1..20] == b"BitTorrent protocol"
}

fn sniff_utp(bytes: &[u8]) -> bool {
    if bytes.len() < 20 || bytes[0] != 0x41 || bytes[8..12] != [0, 0, 0, 0] {
        return false;
    }
    let mut extension = bytes[1];
    let mut at = 20;
    while extension != 0 {
        let Some(kind) = bytes.get(at) else {
            return false;
        };
        if *kind == 0 {
            at += 1;
            break;
        }
        let Some(length) = bytes.get(at + 1).copied() else {
            return false;
        };
        let length = usize::from(length);
        match extension {
            1 if length >= 4 && length % 4 == 0 => {}
            2 if length == 8 => {}
            _ => return false,
        }
        at += 2 + length;
        if bytes.len() < at {
            return false;
        }
        extension = *kind;
    }
    at == bytes.len()
}

struct QuicVersion {
    number: u32,
    initial: u8,
    salt: [u8; 20],
    label: &'static str,
}

const QUIC_VERSIONS: [QuicVersion; 3] = [
    QuicVersion {
        number: 0x0000_0001,
        initial: 0,
        salt: [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ],
        label: "quic",
    },
    QuicVersion {
        number: 0x6b33_43cf,
        initial: 1,
        salt: [
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
            0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ],
        label: "quicv2",
    },
    QuicVersion {
        number: 0xff00_001d,
        initial: 0,
        salt: [
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
            0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
        ],
        label: "quic",
    },
];

fn sniff_quic(mut bytes: &[u8]) -> Option<String> {
    while !bytes.is_empty() {
        let first = *bytes.first()?;
        if first & 0xc0 != 0xc0 {
            return None;
        }
        let version = u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?);
        let spec = QUIC_VERSIONS.iter().find(|spec| spec.number == version)?;
        let mut at = 5;
        let dcid_len = usize::from(*bytes.get(at)?);
        at += 1;
        let dcid = bytes.get(at..at + dcid_len)?;
        at += dcid_len;
        let scid_len = usize::from(*bytes.get(at)?);
        at += 1;
        at += scid_len;
        if at > bytes.len() {
            return None;
        }
        let packet_type = (first & 0x30) >> 4;
        if packet_type != spec.initial {
            let (length, used) = quic_varint(bytes, at)?;
            bytes = bytes.get(at + used + usize::try_from(length).ok()?..)?;
            continue;
        }
        let (token_len, used) = quic_varint(bytes, at)?;
        at += used;
        at += usize::try_from(token_len).ok()?;
        let (length, used) = quic_varint(bytes, at)?;
        at += used;
        let length = usize::try_from(length).ok()?;
        let packet_end = at.checked_add(length)?;
        if length < 4 || packet_end > bytes.len() {
            return None;
        }
        let sample = bytes.get(at + 4..at + 20)?;
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&spec.salt), dcid);
        let secret = hkdf_label(prk.as_slice(), "client in", 32)?;
        let hp_key = hkdf_label(&secret, &format!("{} hp", spec.label), 16)?;
        let mut header = bytes[..packet_end].to_vec();
        let mut block = aes::Block::clone_from_slice(sample);
        aes::Aes128::new_from_slice(&hp_key)
            .ok()?
            .encrypt_block(&mut block);
        header[0] ^= block[0] & 0x0f;
        let packet_number_len = usize::from(header[0] & 0x03) + 1;
        for index in 0..packet_number_len {
            header[at + index] ^= block[index + 1];
        }
        let pn = &header[at..at + packet_number_len];
        let key = hkdf_label(&secret, &format!("{} key", spec.label), 16)?;
        let iv = hkdf_label(&secret, &format!("{} iv", spec.label), 12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv);
        for (index, byte) in pn.iter().enumerate() {
            nonce[12 - packet_number_len + index] ^= byte;
        }
        let cipher = Aes128Gcm::new_from_slice(&key).ok()?;
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &header[at + packet_number_len..],
                    aad: &header[..at + packet_number_len],
                },
            )
            .ok()?;
        if let Some(domain) = quic_crypto_domain(&plain) {
            return Some(domain);
        }
        bytes = bytes.get(packet_end..)?;
    }
    None
}

fn hkdf_label(secret: &[u8], label: &str, length: usize) -> Option<Vec<u8>> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&u16::try_from(length).ok()?.to_be_bytes());
    info.push(u8::try_from(6 + label.len()).ok()?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    let mut out = vec![0u8; length];
    Hkdf::<Sha256>::from_prk(secret)
        .ok()?
        .expand(&info, &mut out)
        .ok()?;
    Some(out)
}

fn quic_varint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(at)?;
    let length = 1usize << (first >> 6);
    if at + length > bytes.len() {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[at + 1..at + length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

fn quic_crypto_domain(plain: &[u8]) -> Option<String> {
    let mut at = 0;
    while at < plain.len() {
        let frame = plain[at];
        at += 1;
        match frame {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                for _ in 0..3 {
                    let (_, used) = quic_varint(plain, at)?;
                    at += used;
                }
                let (_, used) = quic_varint(plain, at)?;
                at += used;
                let (ranges, used) = quic_varint(plain, at)?;
                at += used;
                for _ in 0..ranges {
                    for _ in 0..2 {
                        let (_, used) = quic_varint(plain, at)?;
                        at += used;
                    }
                }
                if frame == 0x03 {
                    for _ in 0..3 {
                        let (_, used) = quic_varint(plain, at)?;
                        at += used;
                    }
                }
            }
            0x06 => {
                let (offset, used) = quic_varint(plain, at)?;
                at += used;
                let (length, used) = quic_varint(plain, at)?;
                at += used;
                let data = plain.get(at..at + usize::try_from(length).ok()?)?;
                if offset == 0 {
                    if let Some(domain) = sniff_client_hello(data) {
                        return Some(domain);
                    }
                }
                at += usize::try_from(length).ok()?;
            }
            0x1c => {
                for _ in 0..2 {
                    let (_, used) = quic_varint(plain, at)?;
                    at += used;
                }
                let (length, used) = quic_varint(plain, at)?;
                at += used;
                at += usize::try_from(length).ok()?;
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls_hello(server_name: &str) -> Vec<u8> {
        let name = server_name.as_bytes();
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0, 0]);
        let extension_len = 2 + 1 + 2 + name.len();
        extensions.extend_from_slice(&(extension_len as u16).to_be_bytes());
        extensions.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(name);
        let mut hello = Vec::new();
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut handshake = vec![1];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);
        let mut record = vec![0x16, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap();
                let lo = (pair[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }

    #[test]
    fn reads_bittorrent_and_utp() {
        assert!(sniff_bittorrent(b"\x13BitTorrent protocol"));
        assert!(!sniff_bittorrent(b"GET / HTTP/1.1\r\n"));
        assert!(sniff_utp(&[
            0x41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0
        ]));
        assert!(!sniff_utp(&[0x41; 20]));
    }

    #[test]
    fn reads_a_quic_initial_sni() {
        assert_eq!(
            sniff_quic(&unhex("cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b")).as_deref(),
            Some("www.google.com")
        );
        assert!(sniff_quic(b"not quic").is_none());
    }

    #[test]
    fn parses_the_fields_xray_names() {
        let value = crate::json::parse(
            r#"{"enabled":true,"destOverride":["tls","fakedns+others"],"domainsExcluded":["full:excluded.test"],"ipsExcluded":["127.0.0.0/8"],"metadataOnly":true,"routeOnly":true}"#,
        )
        .unwrap();
        let sniffing = parse(Some(&value)).unwrap().unwrap();
        assert!(sniffing.enabled);
        assert!(sniffing.metadata_only);
        assert!(sniffing.route_only);
        assert!(sniffing.domains_excluded.is_some());
        assert!(sniffing.ips_excluded.is_some());
    }

    #[test]
    fn exclusions_keep_the_original_destination() {
        let asked = Destination::Address("127.0.0.1:443".parse().unwrap());
        let value = crate::json::parse(
            r#"{"enabled":true,"destOverride":["http"],"domainsExcluded":["full:example.test"]}"#,
        )
        .unwrap();
        let sniffing = parse(Some(&value)).unwrap().unwrap();
        let found = sniffing
            .sniff_bytes(&asked, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        assert_eq!(found.protocol, "http1");
        assert!(!found.override_destination);

        let value = crate::json::parse(
            r#"{"enabled":true,"destOverride":["http"],"ipsExcluded":["127.0.0.1/32"]}"#,
        )
        .unwrap();
        let sniffing = parse(Some(&value)).unwrap().unwrap();
        let found = sniffing
            .sniff_bytes(&asked, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        assert!(!found.override_destination);
    }

    #[test]
    fn reads_http_host_and_tls_sni() {
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nHost: Example.Test\r\n\r\n").unwrap(),
            ("http1", "example.test".to_owned())
        );
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nHost: Example.Test:8443\r\n\r\n").unwrap(),
            ("http1", "example.test".to_owned())
        );
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n").unwrap(),
            ("http1", "::1".to_owned())
        );
        assert_eq!(
            sniff_tls(&tls_hello("example.test")).unwrap(),
            "example.test"
        );
        assert!(sniff_tls(&tls_hello("example.test")[..20]).is_none());
    }
}
