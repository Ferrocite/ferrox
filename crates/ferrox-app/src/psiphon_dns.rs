//! A tiny synchronous DNS fallback with the reference's client knobs: alternate
//! and preferred servers, per-server attempts, EDNS0, 0x20 QNAME casing, a
//! TTL cache, and preresolved CIDR answers.
//!
//! The system resolver is still asked first when nothing says otherwise, so the
//! ordinary path pays no query. Every knob is opt-in; the defaults reproduce
//! the previous behaviour byte for byte.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REPLY: usize = 4096;
const CACHE_LIMIT: usize = 4096;
const REPEAT_MAX: usize = 4096;
const REPLACEMENT_MAX: usize = 65_536;

#[derive(Clone, Debug)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires: Instant,
}

#[derive(Debug)]
struct SteeringEntry {
    address: IpAddr,
    expires: Instant,
    active: bool,
}

#[derive(Clone, Debug)]
enum Node {
    Literal(Vec<u8>),
    Class(Vec<(u8, u8)>),
    Any,
    Concat(Vec<Node>),
    Alternate(Vec<Node>),
    Repeat(Box<Node>, usize, usize),
}

#[derive(Clone, Debug)]
struct Transform {
    find: regex::bytes::Regex,
    replacement: Node,
}

/// The reference's protocol transforms: named replacement generators selected
/// by the DNS server IP, or by the empty scope.
#[derive(Clone, Debug, Default)]
pub(crate) struct Transforms {
    specs: HashMap<String, Arc<Vec<Transform>>>,
    scoped: HashMap<String, Vec<String>>,
}

impl Transforms {
    /// Compile the configured specs and their scopes, dropping an invalid pair
    /// with one line rather than refusing the lane.
    pub(crate) fn new(
        specs: Vec<(String, Vec<(String, String)>)>,
        scoped: Vec<(String, Vec<String>)>,
    ) -> Self {
        let mut compiled = HashMap::new();
        for (name, transforms) in specs {
            let mut items = Vec::new();
            for (find, replacement) in transforms {
                let Ok(find) = regex::bytes::Regex::new(&find) else {
                    eprintln!("psiphon: ignoring DNS transform {name}: bad regex");
                    continue;
                };
                let Ok(replacement) = Node::parse(replacement.as_bytes()) else {
                    eprintln!("psiphon: ignoring DNS transform {name}: bad replacement");
                    continue;
                };
                items.push(Transform { find, replacement });
            }
            if !items.is_empty() {
                compiled.insert(name, Arc::new(items));
            }
        }
        let mut scopes = HashMap::new();
        for (scope, names) in scoped {
            let mut kept = Vec::new();
            for name in names {
                if compiled.contains_key(&name) {
                    kept.push(name);
                } else {
                    eprintln!("psiphon: ignoring DNS transform scope {scope}: undefined {name}");
                }
            }
            scopes.insert(scope, kept);
        }
        Self {
            specs: compiled,
            scoped: scopes,
        }
    }

    /// Pick a spec by scope, falling back to the empty scope.
    fn select(&self, scope: &str) -> Option<Arc<Vec<Transform>>> {
        let names = if scope.is_empty() {
            self.scoped.get("")?
        } else {
            match self.scoped.get(scope) {
                Some(names) if names.is_empty() => return None,
                Some(names) => names,
                None => self.scoped.get("")?,
            }
        };
        if names.is_empty() {
            return None;
        }
        let index = usize::try_from(random_below(u64::try_from(names.len()).unwrap_or(u64::MAX)))
            .unwrap_or(0);
        self.specs.get(&names[index]).cloned()
    }
}

impl Node {
    fn parse(pattern: &[u8]) -> Result<Self, String> {
        let mut parser = Parser { pattern, at: 0 };
        let node = parser.alternate()?;
        if parser.at != pattern.len() {
            return Err("unexpected ')'".to_owned());
        }
        Ok(node)
    }
}

struct Parser<'a> {
    pattern: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.pattern.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    fn alternate(&mut self) -> Result<Node, String> {
        let mut branches = vec![self.concat()?];
        while self.peek() == Some(b'|') {
            self.at += 1;
            branches.push(self.concat()?);
        }
        if branches.len() == 1 {
            Ok(branches.remove(0))
        } else {
            Ok(Node::Alternate(branches))
        }
    }

    fn concat(&mut self) -> Result<Node, String> {
        let mut nodes = Vec::new();
        while let Some(byte) = self.peek() {
            if byte == b'|' || byte == b')' {
                break;
            }
            nodes.push(self.repeat()?);
        }
        if nodes.len() == 1 {
            Ok(nodes.remove(0))
        } else {
            Ok(Node::Concat(nodes))
        }
    }

    fn repeat(&mut self) -> Result<Node, String> {
        let atom = self.atom()?;
        let (min, max) = match self.peek() {
            Some(b'?') => {
                self.at += 1;
                (0, 1)
            }
            Some(b'*') => {
                self.at += 1;
                (0, REPEAT_MAX)
            }
            Some(b'+') => {
                self.at += 1;
                (1, REPEAT_MAX)
            }
            Some(b'{') => self.braces()?,
            _ => return Ok(atom),
        };
        if min > max {
            return Err("bad repeat".to_owned());
        }
        Ok(Node::Repeat(Box::new(atom), min, max))
    }

    fn braces(&mut self) -> Result<(usize, usize), String> {
        self.at += 1;
        let min = self.number()?;
        let max = if self.peek() == Some(b',') {
            self.at += 1;
            if self.peek() == Some(b'}') {
                REPEAT_MAX
            } else {
                self.number()?
            }
        } else {
            min
        };
        if self.peek() != Some(b'}') {
            return Err("unterminated repeat".to_owned());
        }
        self.at += 1;
        Ok((min, max))
    }

    fn number(&mut self) -> Result<usize, String> {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        if self.at == start {
            return Err("expected a number".to_owned());
        }
        std::str::from_utf8(&self.pattern[start..self.at])
            .map_err(|_| "bad number".to_owned())?
            .parse()
            .map_err(|_| "bad number".to_owned())
    }

    fn atom(&mut self) -> Result<Node, String> {
        let byte = self.next().ok_or_else(|| "unexpected end".to_owned())?;
        match byte {
            b'(' => {
                let node = self.alternate()?;
                if self.next() != Some(b')') {
                    return Err("unterminated group".to_owned());
                }
                Ok(node)
            }
            b'[' => self.class(),
            b'\\' => self.escape(),
            b'.' => Ok(Node::Any),
            b'^' | b'$' => Ok(Node::Literal(Vec::new())),
            b'*' | b'+' | b'?' | b'{' | b'}' => Err("misplaced repeat".to_owned()),
            _ => Ok(Node::Literal(vec![byte])),
        }
    }

    fn class(&mut self) -> Result<Node, String> {
        if self.peek() == Some(b'^') {
            return Err("negated class".to_owned());
        }
        let mut ranges = Vec::new();
        while let Some(byte) = self.next() {
            if byte == b']' {
                if ranges.is_empty() {
                    return Err("empty class".to_owned());
                }
                return Ok(Node::Class(ranges));
            }
            let start = if byte == b'\\' {
                self.class_escape()?
            } else {
                byte
            };
            if self.peek() == Some(b'-')
                && self
                    .pattern
                    .get(self.at + 1)
                    .is_some_and(|next| *next != b']')
            {
                self.at += 1;
                let byte = self.next().ok_or_else(|| "unterminated class".to_owned())?;
                let end = if byte == b'\\' {
                    self.class_escape()?
                } else {
                    byte
                };
                if start > end {
                    return Err("bad class range".to_owned());
                }
                ranges.push((start, end));
            } else {
                ranges.push((start, start));
            }
        }
        Err("unterminated class".to_owned())
    }

    fn class_escape(&mut self) -> Result<u8, String> {
        match self
            .next()
            .ok_or_else(|| "unterminated escape".to_owned())?
        {
            b'x' => {
                let high = self.hex()?;
                let low = self.hex()?;
                Ok(high << 4 | low)
            }
            b'n' => Ok(b'\n'),
            b'r' => Ok(b'\r'),
            b't' => Ok(b'\t'),
            other => Ok(other),
        }
    }

    fn escape(&mut self) -> Result<Node, String> {
        match self
            .next()
            .ok_or_else(|| "unterminated escape".to_owned())?
        {
            b'd' => Ok(Node::Class(vec![(b'0', b'9')])),
            b'w' => Ok(Node::Class(vec![
                (b'0', b'9'),
                (b'A', b'Z'),
                (b'a', b'z'),
                (b'_', b'_'),
            ])),
            b's' => Ok(Node::Class(vec![
                (b' ', b' '),
                (b'\t', b'\t'),
                (b'\n', b'\n'),
                (b'\r', b'\r'),
            ])),
            b'x' => {
                let high = self.hex()?;
                let low = self.hex()?;
                Ok(Node::Literal(vec![high << 4 | low]))
            }
            b'n' => Ok(Node::Literal(vec![b'\n'])),
            b'r' => Ok(Node::Literal(vec![b'\r'])),
            b't' => Ok(Node::Literal(vec![b'\t'])),
            other => Ok(Node::Literal(vec![other])),
        }
    }

    fn hex(&mut self) -> Result<u8, String> {
        let byte = self.next().ok_or_else(|| "short escape".to_owned())?;
        hex_digit(byte).ok_or_else(|| "bad hex escape".to_owned())
    }
}

fn generate(node: &Node, out: &mut Vec<u8>) -> Result<(), String> {
    match node {
        Node::Literal(bytes) => {
            for byte in bytes {
                push(out, *byte)?;
            }
        }
        Node::Class(ranges) => {
            let total: usize = ranges
                .iter()
                .map(|(start, end)| usize::from(*end - *start) + 1)
                .sum();
            let mut pick = usize::try_from(random_below(u64::try_from(total).unwrap_or(u64::MAX)))
                .unwrap_or(0);
            for (start, end) in ranges {
                let span = usize::from(*end - *start) + 1;
                if pick < span {
                    push(out, *start + u8::try_from(pick).unwrap_or(0))?;
                    break;
                }
                pick -= span;
            }
        }
        Node::Any => push(out, crate::psiphon_ssh::random::<1>()[0])?,
        Node::Concat(nodes) => {
            for child in nodes {
                generate(child, out)?;
            }
        }
        Node::Alternate(branches) => {
            let index = usize::try_from(random_below(
                u64::try_from(branches.len()).unwrap_or(u64::MAX),
            ))
            .unwrap_or(0);
            generate(&branches[index.min(branches.len().saturating_sub(1))], out)?;
        }
        Node::Repeat(child, min, max) => {
            let span = u64::try_from(max.saturating_sub(*min)).unwrap_or(0) + 1;
            let count = min.saturating_add(usize::try_from(random_below(span)).unwrap_or(0));
            for _ in 0..count {
                generate(child, out)?;
            }
        }
    }
    Ok(())
}

fn push(out: &mut Vec<u8>, byte: u8) -> Result<(), String> {
    if out.len() >= REPLACEMENT_MAX {
        return Err("replacement too long".to_owned());
    }
    out.push(byte);
    Ok(())
}

fn expand(replacement: &[u8], captures: &regex::bytes::Captures<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(replacement.len());
    let mut at = 0;
    while at < replacement.len() {
        let byte = replacement[at];
        if byte != b'$' {
            out.push(byte);
            at += 1;
            continue;
        }
        at += 1;
        if replacement.get(at) == Some(&b'$') {
            out.push(b'$');
            at += 1;
            continue;
        }
        let (name, next) = if replacement.get(at) == Some(&b'{') {
            let start = at + 1;
            let Some(end) = replacement[start..]
                .iter()
                .position(|byte| *byte == b'}')
                .map(|index| start + index)
            else {
                out.push(b'$');
                continue;
            };
            (&replacement[start..end], end + 1)
        } else {
            let start = at;
            while replacement
                .get(at)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                at += 1;
            }
            if start == at {
                out.push(b'$');
                continue;
            }
            (&replacement[start..at], at)
        };
        let name = std::str::from_utf8(name).unwrap_or("");
        let found = name
            .parse::<usize>()
            .ok()
            .and_then(|index| captures.get(index))
            .or_else(|| captures.name(name));
        if let Some(found) = found {
            out.extend_from_slice(found.as_bytes());
        }
        at = next;
    }
    out
}

fn apply_transform(transforms: &[Transform], packet: &[u8]) -> io::Result<Vec<u8>> {
    let mut value = hex_encode(packet).into_bytes();
    for transform in transforms {
        let mut replacement = Vec::new();
        generate(&transform.replacement, &mut replacement).map_err(|why| {
            io::Error::new(io::ErrorKind::InvalidData, format!("DNS transform: {why}"))
        })?;
        value = transform
            .find
            .replace_all(&value, |captures| expand(&replacement, captures))
            .into_owned();
    }
    hex_decode(&value).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS transform produced invalid hex",
        )
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.chunks_exact(2) {
        out.push(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?);
    }
    Some(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The client DNS knobs; every default keeps the previous fallback behaviour.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) servers: Vec<SocketAddr>,
    pub(crate) preferred: Vec<SocketAddr>,
    pub(crate) attempts_per_server: usize,
    pub(crate) attempts_per_preferred: usize,
    pub(crate) request_timeout: Duration,
    pub(crate) await_timeout: Duration,
    pub(crate) prefer_alternate_probability: f64,
    pub(crate) edns0_probability: f64,
    pub(crate) qname_casing_probability: f64,
    pub(crate) cache_extension: Duration,
    pub(crate) cache_extension_verified: Duration,
    pub(crate) transform_probability: f64,
    pub(crate) qname_must_match_probability: f64,
    pub(crate) transforms: Arc<Transforms>,
    pub(crate) preresolved_labels: HashMap<String, Vec<(IpAddr, u8)>>,
    pub(crate) preresolved_probability: f64,
    pub(crate) steering_ttl: Duration,
    pub(crate) steering_probability: f64,
    pub(crate) steering_max: usize,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    steering: Arc<Mutex<HashMap<String, SteeringEntry>>>,
}

impl Config {
    /// A config with the given alternate servers and reference defaults.
    pub(crate) fn from_servers(servers: &[SocketAddr]) -> Self {
        Self {
            servers: servers.to_vec(),
            preferred: Vec::new(),
            attempts_per_server: 2,
            attempts_per_preferred: 1,
            request_timeout: DEFAULT_TIMEOUT,
            await_timeout: Duration::from_millis(10),
            prefer_alternate_probability: 0.0,
            edns0_probability: 0.0,
            qname_casing_probability: 0.0,
            cache_extension: Duration::ZERO,
            cache_extension_verified: Duration::ZERO,
            transform_probability: 0.0,
            qname_must_match_probability: 0.0,
            transforms: Arc::new(Transforms::default()),
            preresolved_labels: HashMap::new(),
            preresolved_probability: 0.0,
            steering_ttl: Duration::from_secs(3600),
            steering_probability: 1.0,
            steering_max: 65_536,
            cache: Arc::new(Mutex::new(HashMap::new())),
            steering: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Cache a handshake steering IP for a fronting provider, keeping an entry
    /// already in use active across a replacement.
    pub(crate) fn remember_steering(&self, provider: &str, address: IpAddr) {
        if provider.is_empty() {
            return;
        }
        let Ok(mut cache) = self.steering.lock() else {
            return;
        };
        if cache.len() >= self.steering_max && !cache.contains_key(provider) {
            cache.retain(|_, entry| entry.expires > Instant::now());
            if cache.len() >= self.steering_max {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires)
                    .map(|(key, _)| key.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        let active = cache.get(provider).is_some_and(|entry| entry.active);
        cache.insert(
            provider.to_owned(),
            SteeringEntry {
                address,
                expires: Instant::now() + self.steering_ttl.max(Duration::from_secs(1)),
                active,
            },
        );
    }

    /// A live steering IP for a fronting provider, dropping an expired entry and
    /// drawing the probability only until the provider is in use.
    fn steering_get(&self, provider: &str) -> Option<IpAddr> {
        let mut cache = self.steering.lock().ok()?;
        let entry = cache.get_mut(provider)?;
        if entry.expires <= Instant::now() {
            cache.remove(provider);
            return None;
        }
        if !entry.active {
            if !coin(self.steering_probability) {
                return None;
            }
            entry.active = true;
        }
        Some(entry.address)
    }

    /// Parse a CIDR list into networks; a bare address is a full-length prefix.
    pub(crate) fn cidrs(texts: &[String]) -> Vec<(IpAddr, u8)> {
        let mut networks = Vec::new();
        for text in texts {
            let text = text.trim();
            let (address, prefix) = match text.split_once('/') {
                Some((address, prefix)) => (address, Some(prefix)),
                None => (text, None),
            };
            let Ok(address) = address.parse::<IpAddr>() else {
                continue;
            };
            let full = if address.is_ipv4() { 32 } else { 128 };
            let Ok(prefix) = prefix.map_or(Ok(full), str::parse::<u8>) else {
                continue;
            };
            if prefix > full {
                continue;
            }
            networks.push((address, prefix));
        }
        networks
    }

    /// A live cached answer, dropping an expired entry.
    fn cache_get(&self, host: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().ok()?;
        let entry = cache.get(host)?;
        if entry.expires <= Instant::now() {
            cache.remove(host);
            return None;
        }
        Some(entry.addresses.clone())
    }

    /// Cache an answer for its TTL, evicting expired entries at the limit.
    fn cache_put(&self, host: &str, addresses: Vec<IpAddr>, ttl: Duration) {
        if addresses.is_empty() {
            return;
        }
        let ttl = ttl.saturating_add(self.cache_extension);
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= CACHE_LIMIT {
            cache.retain(|_, entry| entry.expires > Instant::now());
            if cache.len() >= CACHE_LIMIT {
                cache.clear();
            }
        }
        cache.insert(
            host.to_owned(),
            CacheEntry {
                addresses,
                expires: Instant::now() + ttl.max(Duration::from_secs(1)),
            },
        );
    }

    /// Extend a live cached answer after a successful dial proves the address.
    pub(crate) fn verify_cache_extension(&self, host: &str) {
        if self.cache_extension_verified.is_zero() || host.parse::<IpAddr>().is_ok() {
            return;
        }
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let Some(entry) = cache.get_mut(&name) else {
            return;
        };
        let now = Instant::now();
        if entry.expires <= now {
            cache.remove(&name);
            return;
        }
        let extended = now + self.cache_extension_verified;
        if entry.expires < extended {
            entry.expires = extended;
        }
    }

    /// A random address from a matching preresolved CIDR for one record family.
    fn preresolve(&self, provider: Option<&str>, host: &str, want_v4: bool) -> Option<IpAddr> {
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        let networks = provider
            .and_then(|provider| self.preresolved_labels.get(&provider.to_ascii_lowercase()))
            .or_else(|| self.preresolved_labels.get(&name))
            .or_else(|| self.preresolved_labels.get(""))?;
        if networks.is_empty() {
            return None;
        }
        let candidates: Vec<&(IpAddr, u8)> = networks
            .iter()
            .filter(|(address, _)| address.is_ipv4() == want_v4)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let index = usize::try_from(random_below(
            u64::try_from(candidates.len()).unwrap_or(u64::MAX),
        ))
        .unwrap_or(0);
        let (address, prefix) = *candidates[index];
        Some(random_in(address, prefix))
    }
}

/// Resolve with an explicit config, used by the lane's settings and by tests.
#[allow(clippy::too_many_lines)]
pub(crate) fn resolve_with(config: &Config, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(addresses) = config.cache_get(&name) {
        return Ok(with_port(addresses, port));
    }
    let prefer_alternate = coin(config.prefer_alternate_probability);
    if !prefer_alternate {
        if let Ok(addresses) = (host, port).to_socket_addrs() {
            let addresses: Vec<SocketAddr> = addresses.collect();
            if !addresses.is_empty() {
                return Ok(addresses);
            }
        }
    }
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no alternate DNS server");
    let servers = alternate_servers(config);
    let transform = if coin(config.transform_probability) {
        let scope = if prefer_alternate {
            servers
                .first()
                .map(|server| server.ip().to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        config.transforms.select(&scope)
    } else {
        None
    };
    let must_match = coin(config.qname_must_match_probability);
    let mut first = true;
    for server in &servers {
        let attempts = if config.preferred.iter().any(|preferred| preferred == server) {
            config.attempts_per_preferred.max(1)
        } else {
            config.attempts_per_server.max(1)
        };
        for _ in 0..attempts {
            let first_attempt = first;
            first = false;
            let use_transform = if first_attempt {
                transform.clone()
            } else {
                None
            };
            match query(
                &name,
                *server,
                config,
                use_transform,
                first_attempt && must_match,
            ) {
                Ok((addresses, ttl)) if !addresses.is_empty() => {
                    config.cache_put(&name, addresses.clone(), ttl);
                    return Ok(with_port(addresses, port));
                }
                Ok(_) => {
                    last = io::Error::new(
                        io::ErrorKind::NotFound,
                        "alternate DNS answered no address",
                    );
                }
                Err(error) => last = error,
            }
        }
    }
    if prefer_alternate {
        if let Ok(addresses) = (host, port).to_socket_addrs() {
            let addresses: Vec<SocketAddr> = addresses.collect();
            if !addresses.is_empty() {
                return Ok(addresses);
            }
        }
    }
    Err(last)
}

/// Resolve a fronting dial domain, using its provider's preresolved CIDRs when one is selected.
pub(crate) fn resolve_fronting(
    config: &Config,
    provider: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(address) = provider.and_then(|provider| config.steering_get(provider)) {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let mut addresses = Vec::new();
    if coin(config.preresolved_probability) {
        if let Some(address) = config.preresolve(provider, host, true) {
            addresses.push(address);
        }
        if let Some(address) = config.preresolve(provider, host, false) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        resolve_with(config, host, port)
    } else {
        Ok(with_port(addresses, port))
    }
}

/// Preferred servers first when the coin lands, then the configured alternates.
fn alternate_servers(config: &Config) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    servers.extend(config.preferred.iter().copied());
    for server in &config.servers {
        if !servers.contains(server) {
            servers.push(*server);
        }
    }
    servers
}

/// Pair every address with the requested port.
fn with_port(addresses: Vec<IpAddr>, port: u16) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .map(|address| SocketAddr::new(address, port))
        .collect()
}

/// One random coin with the given probability, never consuming entropy for a certain result.
fn coin(probability: f64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    f64::from(u16::from_be_bytes(crate::psiphon_ssh::random::<2>())) / 65_536.0 < probability
}

/// A random value in `0..bound`.
fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    u64::from_be_bytes(crate::psiphon_ssh::random::<8>()) % bound
}

/// A random host in `address/prefix`, so a preresolved CIDR answers without a query.
fn random_in(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let host = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix.min(32)))
            };
            let span = if prefix >= 32 { 0 } else { u32::MAX >> prefix };
            let offset = u32::try_from(random_below(u64::from(span) + 1)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from((host & mask) | offset))
        }
        IpAddr::V6(address) => {
            let mut octets = address.octets();
            let mut keep = usize::from(prefix.min(128));
            for octet in &mut octets {
                if keep >= 8 {
                    keep -= 8;
                } else if keep > 0 {
                    let host_mask = 0xffu8 >> keep;
                    *octet &= !host_mask;
                    *octet |= crate::psiphon_ssh::random::<1>()[0] & host_mask;
                    keep = 0;
                } else {
                    *octet = crate::psiphon_ssh::random::<1>()[0];
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// Ask one server for A and AAAA in parallel, returning the addresses and the smallest TTL.
fn query(
    host: &str,
    server: SocketAddr,
    config: &Config,
    transform: Option<Arc<Vec<Transform>>>,
    must_match: bool,
) -> io::Result<(Vec<IpAddr>, Duration)> {
    let (sender, receiver) = mpsc::channel();
    for record in [1u16, 28] {
        let sender = sender.clone();
        let name = host.to_owned();
        let config = config.clone();
        let transform = transform.clone();
        thread::Builder::new()
            .name(format!("psiphon-dns-{record}"))
            .spawn(move || {
                let _ = sender.send((
                    record,
                    query_one(
                        &name,
                        server,
                        record,
                        &config,
                        transform.as_ref().map(Vec::as_slice),
                        must_match,
                    ),
                ));
            })
            .map_err(|error| io::Error::other(format!("psiphon DNS thread: {error}")))?;
    }
    drop(sender);
    let mut addresses = Vec::new();
    let mut ttl = Duration::ZERO;
    let mut error = io::Error::new(io::ErrorKind::NotFound, "no DNS answer");
    let mut answered = false;
    for _ in 0..2 {
        let reply = if answered {
            receiver.recv_timeout(config.await_timeout)
        } else {
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        };
        let Ok((record, result)) = reply else {
            break;
        };
        match result {
            Ok((found, found_ttl)) if !found.is_empty() => {
                answered = true;
                ttl = if ttl.is_zero() {
                    found_ttl
                } else {
                    ttl.min(found_ttl)
                };
                addresses.extend(found);
            }
            Ok(_) => {
                error = io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "alternate DNS answered no {} record",
                        if record == 1 { "A" } else { "AAAA" }
                    ),
                );
            }
            Err(failure) => error = failure,
        }
    }
    if addresses.is_empty() {
        Err(error)
    } else {
        Ok((addresses, ttl))
    }
}

/// Send one record query and parse the reply from this server.
fn query_one(
    host: &str,
    server: SocketAddr,
    record: u16,
    config: &Config,
    transform: Option<&[Transform]>,
    must_match: bool,
) -> io::Result<(Vec<IpAddr>, Duration)> {
    let bind = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(config.request_timeout))?;
    let id = crate::psiphon_ssh::random::<2>();
    let edns0 = coin(config.edns0_probability);
    let casing = coin(config.qname_casing_probability);
    let (mut request, sent_name) = query_packet(id, host, record, edns0, casing)?;
    if let Some(transforms) = transform {
        request = apply_transform(transforms, &request)?;
    }
    socket.send(&request)?;
    let mut reply = [0u8; MAX_REPLY];
    let count = socket.recv(&mut reply)?;
    parse_reply(
        id,
        &reply[..count],
        record,
        sent_name.as_deref(),
        casing,
        must_match,
    )
}

/// Build the query, optionally with EDNS0 and randomized QNAME casing.
fn query_packet(
    id: [u8; 2],
    host: &str,
    record: u16,
    edns0: bool,
    casing: bool,
) -> io::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let name = host.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad DNS name"));
    }
    let mut packet = Vec::with_capacity(12 + name.len() + 6 + 11);
    packet.extend_from_slice(&id);
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns0)]);
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS label too long"))?;
        if label.is_empty() || length > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad DNS label"));
        }
        packet.push(length);
        if casing {
            for byte in label.bytes() {
                let upper = crate::psiphon_ssh::random::<1>()[0] & 1 == 0;
                packet.push(if upper {
                    byte.to_ascii_uppercase()
                } else {
                    byte.to_ascii_lowercase()
                });
            }
        } else {
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0);
    let name_bytes = packet[12..packet.len()].to_vec();
    packet.extend_from_slice(&record.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    if edns0 {
        packet.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
    }
    Ok((packet, Some(name_bytes)))
}

/// Parse a reply, checking the ID, question echo, and answer record type.
fn parse_reply(
    id: [u8; 2],
    reply: &[u8],
    record: u16,
    sent_name: Option<&[u8]>,
    exact: bool,
    must_match: bool,
) -> io::Result<(Vec<IpAddr>, Duration)> {
    if reply.len() < 12 || reply[..2] != id[..] || reply[2] & 0x80 == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS reply"));
    }
    if reply[3] & 0x0f != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS error"));
    }
    let questions = usize::from(u16::from_be_bytes([reply[4], reply[5]]));
    let answers = usize::from(u16::from_be_bytes([reply[6], reply[7]]));
    let mut at = 12;
    for index in 0..questions {
        let start = at;
        skip_name(reply, &mut at)?;
        if index == 0 && must_match {
            if let Some(sent) = sent_name {
                let echo = &reply[start..at];
                let matched = if exact {
                    echo == sent
                } else {
                    echo.eq_ignore_ascii_case(sent)
                };
                if !matched {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS question changed",
                    ));
                }
            }
        }
        at = at
            .checked_add(4)
            .filter(|at| *at <= reply.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS question"))?;
    }
    let mut addresses = Vec::new();
    let mut ttl = Duration::MAX;
    for _ in 0..answers {
        skip_name(reply, &mut at)?;
        let head = reply
            .get(at..at + 10)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS answer"))?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let class = u16::from_be_bytes([head[2], head[3]]);
        let seconds = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let length = usize::from(u16::from_be_bytes([head[8], head[9]]));
        at += 10;
        let data = reply
            .get(at..at + length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS record"))?;
        at += length;
        if kind != record || class != 1 {
            continue;
        }
        ttl = ttl.min(Duration::from_secs(u64::from(seconds)));
        match (kind, data) {
            (1, [a, b, c, d]) => addresses.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
            (28, bytes) if bytes.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }
    let ttl = if ttl == Duration::MAX {
        Duration::ZERO
    } else {
        ttl
    };
    Ok((addresses, ttl))
}

fn skip_name(reply: &[u8], at: &mut usize) -> io::Result<()> {
    loop {
        let length = usize::from(
            *reply
                .get(*at)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS name"))?,
        );
        *at += 1;
        match length & 0xc0 {
            0xc0 => {
                *at += 1;
                return Ok(());
            }
            0 => {
                if length == 0 {
                    return Ok(());
                }
                *at = (*at)
                    .checked_add(length)
                    .filter(|at| *at <= reply.len())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS label"))?;
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS name")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_fronting, resolve_with, Config};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::thread;

    #[test]
    fn a_literal_address_needs_no_query() {
        let addresses =
            resolve_with(&Config::from_servers(&[]), "192.0.2.7", 443).expect("literal");
        assert_eq!(addresses, [SocketAddr::from(([192, 0, 2, 7], 443))]);
    }

    /// Answer one query with a record of the type the client asked for.
    fn responder(socket: &UdpSocket) {
        let mut request = [0u8; 512];
        let (count, peer) = socket.recv_from(&mut request).expect("query");
        let request = &request[..count];
        let question_end = 12
            + request[12..]
                .iter()
                .position(|byte| *byte == 0)
                .expect("question")
            + 5;
        let record = u16::from_be_bytes([request[question_end - 4], request[question_end - 3]]);
        let mut reply = Vec::new();
        reply.extend_from_slice(&request[..2]);
        reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        reply.extend_from_slice(&request[12..question_end]);
        reply.extend_from_slice(&[0xc0, 0x0c]);
        reply.extend_from_slice(&record.to_be_bytes());
        reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        if record == 28 {
            reply.extend_from_slice(&[0, 16]);
            reply.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        } else {
            reply.extend_from_slice(&[0, 4, 203, 0, 113, 7]);
        }
        socket.send_to(&reply, peer).expect("reply");
    }

    #[test]
    fn an_alternate_server_answers_a_record() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let server = socket.local_addr().expect("address");
        let responder = thread::spawn(move || responder(&socket));
        let config = Config::from_servers(&[server]);
        let (addresses, _) =
            super::query_one("psiphon.test", server, 1, &config, None, false).expect("alternate");
        responder.join().expect("responder");
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]);
    }

    #[test]
    /// The cache answers a repeated name without opening a socket.
    fn the_cache_answers_the_second_query_without_a_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let server = socket.local_addr().expect("address");
        let responder = thread::spawn(move || responder(&socket));
        let mut config = Config::from_servers(&[server]);
        config.prefer_alternate_probability = 1.0;
        config.request_timeout = std::time::Duration::from_millis(50);
        let first = resolve_with(&config, "psiphon.test", 443).expect("first");
        responder.join().expect("responder");
        let second = resolve_with(&config, "psiphon.test", 443).expect("cached");
        assert_eq!(first, second);
    }

    #[test]
    /// A preresolved CIDR answers without a query.
    fn a_preresolved_cidr_answers_without_a_query() {
        let mut config = Config::from_servers(&[]);
        config.preresolved_labels =
            HashMap::from([(String::new(), Config::cidrs(&["203.0.113.0/24".to_owned()]))]);
        config.preresolved_probability = 1.0;
        let addresses = resolve_fronting(&config, None, "psiphon.test", 443).expect("preresolved");
        assert_eq!(addresses.len(), 1);
        match addresses[0].ip() {
            IpAddr::V4(address) => assert_eq!(address.octets()[..3], [203, 0, 113]),
            IpAddr::V6(_) => panic!("wrong family"),
        }
    }

    #[test]
    /// Invalid CIDR entries are dropped while valid ones stay.
    fn a_cidr_parses_bad_entries_away() {
        assert_eq!(
            Config::cidrs(&[
                "10.0.0.0/8".to_owned(),
                "nope".to_owned(),
                "10.0.0.0/nope".to_owned(),
                "10.0.0.0/33".to_owned(),
                "2001:db8::/129".to_owned(),
            ]),
            vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)]
        );
    }

    #[test]
    /// A labelled preresolved CIDR only answers that provider.
    fn a_preresolved_label_only_answers_its_provider() {
        let mut config = Config::from_servers(&[]);
        config.preresolved_labels = HashMap::from([(
            "provider-a".to_owned(),
            Config::cidrs(&["203.0.113.0/24".to_owned()]),
        )]);
        config.preresolved_probability = 1.0;
        assert!(config
            .preresolve(Some("provider-b"), "psiphon.test", true)
            .is_none());
        assert!(config
            .preresolve(Some("provider-a"), "psiphon.test", true)
            .is_some());
    }

    #[test]
    /// A full-length prefix keeps the whole address.
    fn a_full_host_prefix_keeps_every_bit() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(super::random_in(v4, 32), v4);
        let v6: IpAddr = "2001:db8::1".parse().expect("address");
        assert_eq!(super::random_in(v6, 128), v6);
        match super::random_in(v6, 32) {
            IpAddr::V6(address) => {
                assert_eq!(&address.octets()[..4], &[0x20, 0x01, 0x0d, 0xb8]);
            }
            IpAddr::V4(_) => panic!("wrong family"),
        }
    }

    #[test]
    /// An empty answer does not reset the smallest TTL.
    fn an_empty_record_does_not_zero_the_ttl() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let server = socket.local_addr().expect("address");
        let responder = thread::spawn(move || responder(&socket));
        let mut config = Config::from_servers(&[server]);
        config.request_timeout = std::time::Duration::from_millis(50);
        let (addresses, ttl) =
            super::query("psiphon.test", server, &config, None, false).expect("query");
        responder.join().expect("responder");
        assert_eq!(addresses.len(), 1);
        assert_eq!(ttl, std::time::Duration::from_secs(60));
    }

    #[test]
    /// A reply whose question echo changed case is refused.
    fn a_changed_question_echo_is_refused_when_casing_was_sent() {
        let id = [0x12, 0x34];
        let sent = b"\x07PSIPHON\x04TEST\x00";
        let echo = b"\x07psiphon\x04test\x00";
        let mut reply = Vec::new();
        reply.extend_from_slice(&id);
        reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
        reply.extend_from_slice(echo);
        reply.extend_from_slice(&[0, 1, 0, 1]);
        assert!(super::parse_reply(id, &reply, 1, Some(&sent[..]), false, true).is_ok());
        assert!(super::parse_reply(id, &reply, 1, Some(&sent[..]), true, true).is_err());
        assert!(super::parse_reply(id, &reply, 1, Some(&sent[..]), true, false).is_ok());
    }

    #[test]
    /// A cached steering IP answers the fronting dial without a resolver query.
    fn a_steering_ip_answers_a_fronting_dial() {
        let config = Config::from_servers(&[]);
        config.remember_steering("provider", "192.0.2.10".parse().expect("address"));
        let addresses = super::resolve_fronting(&config, Some("provider"), "front.example", 443)
            .expect("resolve");
        assert_eq!(addresses, vec!["192.0.2.10:443".parse().expect("address")]);
    }

    #[test]
    /// A zero probability keeps a cached steering IP unused until a draw starts it.
    fn a_zero_probability_does_not_use_a_cached_steering_ip() {
        let mut config = Config::from_servers(&[]);
        config.steering_probability = 0.0;
        config.remember_steering("provider", "192.0.2.10".parse().expect("address"));
        assert!(config.steering_get("provider").is_none());
        config.steering_probability = 1.0;
        assert_eq!(
            config.steering_get("provider"),
            Some("192.0.2.10".parse().expect("address"))
        );
        config.steering_probability = 0.0;
        assert_eq!(
            config.steering_get("provider"),
            Some("192.0.2.10".parse().expect("address"))
        );
    }

    #[test]
    /// Escaped replacement text generates the subgroup reference the reference expects.
    fn a_replacement_pattern_keeps_its_subgroup_reference() {
        let node = super::Node::parse(r"\$\{1\}0140").expect("pattern");
        let mut out = Vec::new();
        super::generate(&node, &mut out).expect("generate");
        assert_eq!(out, b"${1}0140");
    }

    #[test]
    /// A transform rewrites the hex packet and expands its subgroup references.
    fn a_transform_rewrites_the_hex_packet() {
        let find = regex::bytes::Regex::new("(12)(34)").expect("regex");
        let replacement = super::Node::parse(r"\$\{2\}\$\{1\}").expect("pattern");
        let transform = super::Transform { find, replacement };
        let packet =
            super::apply_transform(&[transform], &[0x12, 0x34, 0xab, 0xcd]).expect("transform");
        assert_eq!(packet, [0x34, 0x12, 0xab, 0xcd]);
    }

    #[test]
    /// An undefined scope falls back to the empty scope, while an empty one selects nothing.
    fn a_transform_scope_selects_or_refuses() {
        let transforms = super::Transforms::new(
            vec![("any".to_owned(), vec![("^12".to_owned(), "ef".to_owned())])],
            vec![
                (String::new(), vec!["any".to_owned()]),
                ("192.0.2.1".to_owned(), Vec::new()),
            ],
        );
        assert!(transforms.select("").is_some());
        assert!(transforms.select("192.0.2.2").is_some());
        assert!(transforms.select("192.0.2.1").is_none());
    }

    #[test]
    /// A verified dial extends a live cached answer but never a literal address.
    fn a_verified_dial_extends_the_cache() {
        let mut config = Config::from_servers(&[]);
        config.cache_extension_verified = std::time::Duration::from_secs(60);
        config.cache_put(
            "psiphon.test",
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))],
            std::time::Duration::from_secs(1),
        );
        let before = config
            .cache
            .lock()
            .expect("cache")
            .get("psiphon.test")
            .expect("entry")
            .expires;
        config.verify_cache_extension("psiphon.test");
        let after = config
            .cache
            .lock()
            .expect("cache")
            .get("psiphon.test")
            .expect("entry")
            .expires;
        assert!(after > before);
        config.verify_cache_extension("203.0.113.7");
    }
}
