use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

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
        None
    }

    fn result(
        &self,
        asked: &Destination,
        protocol: &'static str,
        domain: String,
        fake_ip: bool,
    ) -> Sniffed {
        let mut override_destination = self.permits(protocol);
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
                        "fakedns" | "fakedns+others" => protocols.push(Protocol::FakeDns),
                        other => {
                            return Err(format!(
                                "sniffing destOverride `{other}` is not http, tls, quic, fakedns or fakedns+others"
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
                if value.is_empty() || value.starts_with('/') {
                    return None;
                }
                return Some(("http1", value.to_ascii_lowercase()));
            }
        }
        at += line_end + 1;
    }
    None
}

fn sniff_tls(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 || bytes[0] != 0x16 || bytes[1] != 3 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if bytes.len() < 5 + length {
        return None;
    }
    let body = &bytes[5..5 + length];
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
            sniff_tls(&tls_hello("example.test")).unwrap(),
            "example.test"
        );
        assert!(sniff_tls(&tls_hello("example.test")[..20]).is_none());
    }
}
