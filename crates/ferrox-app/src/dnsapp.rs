//! The built-in DNS resolver: the configured name servers in rule order, the
//! static hosts, the per-server cache, and the `FakeDNS` pools.
//!
//! The reference's `app/dns` resolves names itself. This module carries the
//! same shape: a name is matched against each server's domain rules, the first
//! server that answers wins, the remaining servers are the fallback, and a
//! server's cache is its own. The transports are `dnsnet`'s.

use crate::json::Json;
use crate::router::{add_domain, asset_dirs, ip_matcher, Assets, DomainMatcher, IpMatcher};
use ferrox_core::dns::{build_query, parse_answer, Edns};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_TTL: u32 = 300;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);
const HOSTS_TTL: u32 = 10;
const RESOLVE_CACHE_CAP: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strategy {
    Both,
    V4,
    V6,
    System,
}

impl Strategy {
    fn families(self) -> (bool, bool) {
        match self {
            Self::V4 => (true, false),
            Self::V6 => (false, true),
            Self::Both | Self::System => (true, true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
    Tls,
    Doh { cleartext: bool },
    Doq,
    Local,
    Fake,
}

#[derive(Debug)]
struct Endpoint {
    host: String,
    port: u16,
}

#[derive(Debug)]
struct CachePolicy {
    disable: bool,
    serve_stale: bool,
    serve_expired: Duration,
}

#[allow(clippy::struct_excessive_bools)]
struct Server {
    transport: Transport,
    endpoint: Option<Endpoint>,
    path: String,
    matcher: Option<DomainMatcher>,
    implicit_local: bool,
    local_dial: bool,
    skip_fallback: bool,
    final_query: bool,
    policy_id: u32,
    tag: Option<String>,
    id: String,
    timeout: Duration,
    cache: CachePolicy,
    client_ip: Option<IpAddr>,
    expected: Option<IpMatcher>,
    unexpected: Option<IpMatcher>,
    act_prior: bool,
    act_unprior: bool,
    v4: bool,
    v6: bool,
    req_id: AtomicU16,
}

impl Server {
    fn matches(&self, name: &str, lower: &str) -> bool {
        if self.implicit_local && local_name(lower) {
            return true;
        }
        self.matcher
            .as_ref()
            .is_some_and(|matcher| matcher.matches(name, lower))
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn local_name(name: &str) -> bool {
    !name.contains('.')
        || name == "localhost"
        || name.ends_with(".local")
        || name.ends_with(".localdomain")
        || name.ends_with(".lan")
        || name.ends_with(".home.arpa")
        || name.ends_with(".example")
        || name.ends_with(".invalid")
        || name.ends_with(".test")
}

#[derive(Debug)]
struct CacheRecord {
    ips: Vec<IpAddr>,
    rcode: u16,
    expires: Instant,
}

impl CacheRecord {
    fn answer(&self) -> Lookup {
        if self.rcode != 0 {
            return Lookup::Rcode(self.rcode);
        }
        if self.ips.is_empty() {
            return Lookup::Empty;
        }
        let ttl = self
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(1) as u32;
        Lookup::Records(self.ips.clone(), ttl)
    }
}

#[derive(Default)]
struct CacheEntry {
    a: Option<CacheRecord>,
    aaaa: Option<CacheRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Family {
    A,
    Aaaa,
}

impl Family {
    fn qtype(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }

    fn width(self) -> usize {
        match self {
            Self::A => 4,
            Self::Aaaa => 16,
        }
    }

    fn cached(self, entry: &CacheEntry) -> Option<&CacheRecord> {
        match self {
            Self::A => entry.a.as_ref(),
            Self::Aaaa => entry.aaaa.as_ref(),
        }
    }

    fn store(self, entry: &mut CacheEntry, record: CacheRecord) {
        match self {
            Self::A => entry.a = Some(record),
            Self::Aaaa => entry.aaaa = Some(record),
        }
    }
}

#[derive(Debug)]
enum HostTarget {
    Ips(Vec<IpAddr>),
    Domain(String),
    Rcode(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lookup {
    Records(Vec<IpAddr>, u32),
    Empty,
    Rcode(u16),
    Failed,
}

impl Lookup {
    fn records(self) -> Option<(Vec<IpAddr>, u32)> {
        match self {
            Self::Records(ips, ttl) => Some((ips, ttl)),
            Self::Empty | Self::Rcode(_) | Self::Failed => None,
        }
    }
}

struct HostRule {
    matcher: DomainMatcher,
    target: HostTarget,
}

pub(crate) struct Resolver {
    servers: Vec<Server>,
    hosts: Vec<HostRule>,
    strategy: Strategy,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
    parallel: bool,
    cache: Vec<Mutex<HashMap<String, CacheEntry>>>,
    fake: Option<FakePools>,
}

impl Resolver {
    /// The built resolver a root config names, or `None` when the config has
    /// no `dns` block. A block with no servers is the reference's localhost
    /// resolver, not an empty one.
    pub(crate) fn from_root(root: &Json) -> Result<Option<Self>, String> {
        let Some(dns) = root.get("dns").filter(|dns| !matches!(dns, Json::Null)) else {
            return Ok(None);
        };
        if !matches!(dns, Json::Obj(_)) {
            return Err("dns is not an object".into());
        }
        let strategy = parse_strategy(dns.get("queryStrategy").and_then(Json::as_str));
        let client_ip = parse_ip(dns.get("clientIp").and_then(Json::as_str))?;
        let disable_cache = flag(dns, "disableCache");
        let serve_stale = flag(dns, "serveStale");
        let serve_expired = Duration::from_secs(
            dns.get("serveExpiredTTL")
                .and_then(Json::as_u32)
                .unwrap_or(0) as u64,
        );
        let disable_fallback = flag(dns, "disableFallback");
        let disable_fallback_if_match = flag(dns, "disableFallbackIfMatch");
        let parallel = flag(dns, "enableParallelQuery");
        let tag = dns
            .get("tag")
            .and_then(Json::as_str)
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned);
        warn_unsupported(dns);
        let mut assets = Assets::new(asset_dirs());
        let mut policies = PolicyIds::default();
        let mut servers = Vec::new();
        if let Some(list) = dns.get("servers").and_then(Json::as_arr) {
            for item in list {
                servers.push(parse_server(
                    item,
                    strategy,
                    client_ip,
                    disable_cache,
                    serve_stale,
                    serve_expired,
                    tag.as_deref(),
                    &mut assets,
                    &mut policies,
                )?);
            }
        }
        if servers.is_empty() {
            servers.push(Server {
                transport: Transport::Local,
                endpoint: None,
                path: String::new(),
                matcher: None,
                implicit_local: true,
                local_dial: true,
                skip_fallback: false,
                final_query: false,
                policy_id: 0,
                tag: tag.clone(),
                id: "localhost".to_owned(),
                timeout: DEFAULT_TIMEOUT,
                cache: CachePolicy {
                    disable: disable_cache,
                    serve_stale,
                    serve_expired,
                },
                client_ip,
                expected: None,
                unexpected: None,
                act_prior: false,
                act_unprior: false,
                v4: true,
                v6: true,
                req_id: AtomicU16::new(0),
            });
        }
        let mut hosts = parse_hosts(dns.get("hosts"))?;
        if dns
            .get("useSystemHosts")
            .and_then(Json::as_bool)
            .unwrap_or(false)
        {
            hosts.extend(system_hosts()?);
        }
        let fake_needed = servers
            .iter()
            .any(|server| server.transport == Transport::Fake);
        let fake = parse_fake(root.get("fakeDns"), fake_needed, strategy)?;
        if fake.is_none() && fake_needed {
            return Err("fakedns nameserver without a fakeDns pool".into());
        }
        let cache = (0..servers.len())
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Ok(Some(Self {
            servers,
            hosts,
            strategy,
            disable_fallback,
            disable_fallback_if_match,
            parallel,
            cache,
            fake,
        }))
    }

    pub(crate) fn lookup(self: &Arc<Self>, name: &str) -> Option<(Vec<IpAddr>, u32)> {
        self.lookup_inner(name, false, false).records()
    }

    /// The relay's own outbound addresses resolve through the local dial: a routed DNS query
    /// for the proxy's own name would ask the proxy it is trying to open.
    pub(crate) fn lookup_local(self: &Arc<Self>, name: &str) -> Option<(Vec<IpAddr>, u32)> {
        self.lookup_inner(name, false, true).records()
    }

    /// The same lookup with the answer's kind kept: the DNS lane answers an empty
    /// response and an rcode as themselves instead of calling both a hard error.
    pub(crate) fn lookup_result(self: &Arc<Self>, name: &str) -> Lookup {
        self.lookup_inner(name, false, false)
    }

    pub(crate) fn lookup_families(
        self: &Arc<Self>,
        name: &str,
        v4: bool,
        v6: bool,
        fake: bool,
    ) -> Option<(Vec<IpAddr>, u32)> {
        self.lookup_with(name, v4, v6, fake, false).records()
    }

    pub(crate) fn script_servers(&self) -> Vec<(String, usize)> {
        self.servers
            .iter()
            .enumerate()
            .map(|(at, server)| (server.id.clone(), at))
            .collect()
    }

    pub(crate) fn script_query(
        &self,
        index: usize,
        name: &str,
        v4: bool,
        v6: bool,
        fake: bool,
    ) -> Lookup {
        self.query_server(index, name, v4, v6, fake, false)
    }

    #[allow(dead_code)]
    pub(crate) fn domain_of(&self, ip: IpAddr) -> Option<String> {
        self.fake.as_ref().and_then(|fake| fake.domain_of(ip))
    }

    fn lookup_inner(self: &Arc<Self>, name: &str, fake_enabled: bool, force_local: bool) -> Lookup {
        let (v4, v6) = self.strategy.families();
        self.lookup_with(name, v4, v6, fake_enabled, force_local)
    }

    fn lookup_with(
        self: &Arc<Self>,
        name: &str,
        v4: bool,
        v6: bool,
        fake_enabled: bool,
        force_local: bool,
    ) -> Lookup {
        if !v4 && !v6 {
            return Lookup::Empty;
        }
        let mut name = Cow::Borrowed(name.trim_end_matches('.'));
        if name.is_empty() {
            return Lookup::Failed;
        }
        let mut followed = 0u8;
        loop {
            match self.host_lookup(&name, v4, v6) {
                Some(HostAnswer::Ips(ips)) if ips.is_empty() => return Lookup::Empty,
                Some(HostAnswer::Ips(ips)) => return Lookup::Records(ips, HOSTS_TTL),
                Some(HostAnswer::Rcode(0)) => return Lookup::Empty,
                Some(HostAnswer::Rcode(code)) => return Lookup::Rcode(code),
                Some(HostAnswer::Alias(next)) if followed < 5 && !next.is_empty() => {
                    name = Cow::Owned(next);
                    followed += 1;
                }
                Some(HostAnswer::Alias(_)) | None => break,
            }
        }
        if self.strategy == Strategy::System && !fake_enabled {
            return system_lookup(&name, v4, v6);
        }
        let needs_lower = !self.hosts.is_empty()
            || self
                .servers
                .iter()
                .any(|server| server.implicit_local || server.matcher.is_some());
        let lower = if needs_lower {
            name.to_ascii_lowercase()
        } else {
            String::new()
        };
        let mut used = vec![false; self.servers.len()];
        let mut order = Vec::new();
        let mut matched = false;
        for (index, server) in self.servers.iter().enumerate() {
            if server.matches(&name, &lower) {
                used[index] = true;
                matched = true;
                order.push(index);
                if server.final_query {
                    return self.ask(&order, &name, v4, v6, fake_enabled, force_local);
                }
            }
        }
        if !(self.disable_fallback || (self.disable_fallback_if_match && matched)) {
            for (index, server) in self.servers.iter().enumerate() {
                if used[index] || server.skip_fallback {
                    continue;
                }
                used[index] = true;
                order.push(index);
                if server.final_query {
                    break;
                }
            }
        }
        if order.is_empty() {
            order.push(0);
        }
        self.ask(&order, &name, v4, v6, fake_enabled, force_local)
    }

    #[allow(clippy::fn_params_excessive_bools)]
    fn ask(
        self: &Arc<Self>,
        order: &[usize],
        name: &str,
        v4: bool,
        v6: bool,
        fake_enabled: bool,
        force_local: bool,
    ) -> Lookup {
        if self.parallel {
            self.ask_parallel(order, name, v4, v6, fake_enabled, force_local)
        } else {
            self.ask_serial(order, name, v4, v6, fake_enabled, force_local)
        }
    }

    #[allow(clippy::fn_params_excessive_bools)]
    fn ask_serial(
        &self,
        order: &[usize],
        name: &str,
        v4: bool,
        v6: bool,
        fake_enabled: bool,
        force_local: bool,
    ) -> Lookup {
        let mut last_rcode = None;
        let mut empty = false;
        for &index in order {
            match self.query_server(index, name, v4, v6, fake_enabled, force_local) {
                Lookup::Records(ips, ttl) if !ips.is_empty() => return Lookup::Records(ips, ttl),
                Lookup::Records(_, _) | Lookup::Empty => empty = true,
                Lookup::Rcode(code) => last_rcode = Some(code),
                Lookup::Failed => {}
            }
        }
        last_rcode
            .map(Lookup::Rcode)
            .unwrap_or(if empty { Lookup::Empty } else { Lookup::Failed })
    }

    /// Every group starts together; one group's answer wins and the next group is consulted
    /// only when every server before it failed. The reference groups adjacent servers by `policyID`.
    #[allow(clippy::fn_params_excessive_bools)]
    fn ask_parallel(
        self: &Arc<Self>,
        order: &[usize],
        name: &str,
        v4: bool,
        v6: bool,
        fake_enabled: bool,
        force_local: bool,
    ) -> Lookup {
        let (sender, receiver) = mpsc::channel();
        for (slot, &index) in order.iter().enumerate() {
            let resolver = Arc::clone(self);
            let name = name.to_owned();
            let sender = sender.clone();
            thread::spawn(move || {
                let result = resolver.query_server(index, &name, v4, v6, fake_enabled, force_local);
                let _ = sender.send((slot, result));
            });
        }
        drop(sender);
        let mut results: Vec<Option<Lookup>> = (0..order.len()).map(|_| None).collect();
        let mut last_rcode = None;
        let mut empty = false;
        let mut start = 0;
        while start < order.len() {
            let mut end = start + 1;
            while end < order.len()
                && self.servers[order[end]].policy_id == self.servers[order[start]].policy_id
            {
                end += 1;
            }
            loop {
                if let Some(slot) = (start..end).find(|&slot| {
                    matches!(
                        results[slot].as_ref(),
                        Some(Lookup::Records(ips, _)) if !ips.is_empty()
                    )
                }) {
                    if let Some(Lookup::Records(ips, ttl)) = results[slot].take() {
                        return Lookup::Records(ips, ttl);
                    }
                }
                if results[start..end].iter().all(Option::is_some) {
                    break;
                }
                let Ok((slot, result)) = receiver.recv() else {
                    break;
                };
                results[slot] = Some(result);
            }
            for result in results[start..end].iter().flatten() {
                match result {
                    Lookup::Records(_, _) | Lookup::Empty => empty = true,
                    Lookup::Rcode(code) => last_rcode = Some(*code),
                    Lookup::Failed => {}
                }
            }
            start = end;
        }
        last_rcode
            .map(Lookup::Rcode)
            .unwrap_or(if empty { Lookup::Empty } else { Lookup::Failed })
    }

    #[allow(clippy::fn_params_excessive_bools)]
    fn query_server(
        &self,
        index: usize,
        name: &str,
        v4: bool,
        v6: bool,
        fake_enabled: bool,
        force_local: bool,
    ) -> Lookup {
        let server = &self.servers[index];
        if server.transport == Transport::Fake && !fake_enabled {
            return Lookup::Empty;
        }
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        let mut families = 0u8;
        let mut rcode = None;
        let mut empty = false;
        if v4 && server.v4 {
            match self.family(index, name, Family::A, force_local) {
                Lookup::Records(mut found, found_ttl) => {
                    ttl = ttl.min(found_ttl);
                    ips.append(&mut found);
                    families += 1;
                }
                Lookup::Rcode(code) => rcode = Some(code),
                Lookup::Empty => empty = true,
                Lookup::Failed => {}
            }
        }
        if v6 && server.v6 {
            match self.family(index, name, Family::Aaaa, force_local) {
                Lookup::Records(mut found, found_ttl) => {
                    ttl = ttl.min(found_ttl);
                    ips.append(&mut found);
                    families += 1;
                }
                Lookup::Rcode(code) => rcode = Some(code),
                Lookup::Empty => empty = true,
                Lookup::Failed => {}
            }
        }
        if !ips.is_empty() {
            let ips = self.filter(index, ips);
            if !ips.is_empty() {
                let ttl = if families > 1 {
                    ttl.min(DEFAULT_TTL)
                } else {
                    ttl
                };
                return Lookup::Records(ips, ttl);
            }
        }
        if let Some(code) = rcode {
            return Lookup::Rcode(code);
        }
        if empty {
            Lookup::Empty
        } else {
            Lookup::Failed
        }
    }

    fn filter(&self, index: usize, mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
        let server = &self.servers[index];
        if let Some(expected) = server.expected.as_ref().filter(|_| !server.act_prior) {
            ips.retain(|ip| expected.matches(*ip));
            if ips.is_empty() {
                return ips;
            }
        }
        if let Some(unexpected) = server.unexpected.as_ref().filter(|_| !server.act_unprior) {
            ips.retain(|ip| !unexpected.matches(*ip));
            if ips.is_empty() {
                return ips;
            }
        }
        if let Some(expected) = server.expected.as_ref().filter(|_| server.act_prior) {
            let matched: Vec<IpAddr> = ips
                .iter()
                .copied()
                .filter(|ip| expected.matches(*ip))
                .collect();
            if !matched.is_empty() {
                ips = matched;
            }
        }
        if let Some(unexpected) = server.unexpected.as_ref().filter(|_| server.act_unprior) {
            let unmatched: Vec<IpAddr> = ips
                .iter()
                .copied()
                .filter(|ip| !unexpected.matches(*ip))
                .collect();
            if !unmatched.is_empty() {
                ips = unmatched;
            }
        }
        ips
    }

    fn family(&self, index: usize, name: &str, family: Family, force_local: bool) -> Lookup {
        let server = &self.servers[index];
        if server.transport == Transport::Fake {
            return match self
                .fake
                .as_ref()
                .and_then(|fake| fake.allocate(name, family))
            {
                Some((ips, ttl)) => Lookup::Records(ips, ttl),
                None => Lookup::Failed,
            };
        }
        let mut stale = None;
        if !server.cache.disable {
            let Ok(held) = self.cache[index].lock() else {
                return Lookup::Failed;
            };
            if let Some(entry) = held.get(name) {
                if let Some(record) = family.cached(entry) {
                    if record.expires > Instant::now() {
                        return record.answer();
                    }
                    if server.cache.serve_stale
                        && (server.cache.serve_expired.is_zero()
                            || record.expires + server.cache.serve_expired > Instant::now())
                    {
                        stale = Some(record.answer());
                    }
                }
            }
        }
        let fetched = self.fetch(index, name, family, force_local);
        let cacheable = match &fetched {
            Lookup::Records(ips, ttl) => Some((ips.clone(), 0, *ttl)),
            Lookup::Rcode(code) => Some((Vec::new(), *code, DEFAULT_TTL)),
            Lookup::Empty => Some((Vec::new(), 0, DEFAULT_TTL)),
            Lookup::Failed => None,
        };
        if let Some((ips, rcode, ttl)) = cacheable {
            if !server.cache.disable {
                if let Ok(mut held) = self.cache[index].lock() {
                    if held.len() >= RESOLVE_CACHE_CAP {
                        held.clear();
                    }
                    let entry = held.entry(name.to_owned()).or_default();
                    family.store(
                        entry,
                        CacheRecord {
                            ips,
                            rcode,
                            expires: Instant::now() + Duration::from_secs(u64::from(ttl.max(1))),
                        },
                    );
                }
            }
            fetched
        } else {
            stale.unwrap_or(Lookup::Failed)
        }
    }

    #[allow(clippy::too_many_lines)]
    fn fetch(&self, index: usize, name: &str, family: Family, force_local: bool) -> Lookup {
        let server = &self.servers[index];
        if server.transport == Transport::Local {
            return match family {
                Family::A => system_lookup(name, true, false),
                Family::Aaaa => system_lookup(name, false, true),
            };
        }
        let Some(endpoint) = server.endpoint.as_ref() else {
            return Lookup::Failed;
        };
        let qtype = family.qtype();
        let id = match server.transport {
            Transport::Doh { .. } | Transport::Doq => 0,
            _ => server
                .req_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1),
        };
        let padding = match server.transport {
            Transport::Doh { .. } => random_padding(),
            _ => 0,
        };
        let edns = Edns {
            client_ip: server.client_ip,
            padding,
        };
        let name = fqdn(name);
        let Some(query) = build_query(id, name.as_bytes(), qtype, Some(edns)) else {
            return Lookup::Failed;
        };
        let response = match &server.transport {
            Transport::Udp => {
                let Ok(answer) = crate::dnsnet::udp(
                    &endpoint.host,
                    endpoint.port,
                    &query,
                    server.tag.as_deref(),
                    None,
                    server.timeout,
                    server.local_dial || force_local,
                ) else {
                    return Lookup::Failed;
                };
                if parse_answer(&answer).is_some_and(|answer| answer.truncated) {
                    let Ok(answer) = crate::dnsnet::tcp(
                        &endpoint.host,
                        endpoint.port,
                        &query,
                        server.tag.as_deref(),
                        None,
                        server.timeout,
                        server.local_dial || force_local,
                    ) else {
                        return Lookup::Failed;
                    };
                    answer
                } else {
                    answer
                }
            }
            Transport::Tcp => {
                match crate::dnsnet::tcp(
                    &endpoint.host,
                    endpoint.port,
                    &query,
                    server.tag.as_deref(),
                    None,
                    server.timeout,
                    server.local_dial || force_local,
                ) {
                    Ok(answer) => answer,
                    Err(_) => return Lookup::Failed,
                }
            }
            Transport::Tls => {
                match crate::dnsnet::tls(
                    &endpoint.host,
                    endpoint.port,
                    &query,
                    server.tag.as_deref(),
                    None,
                    server.timeout,
                    server.local_dial || force_local,
                ) {
                    Ok(answer) => answer,
                    Err(_) => return Lookup::Failed,
                }
            }
            Transport::Doh { cleartext } => match crate::dnsnet::doh(
                &endpoint.host,
                endpoint.port,
                &server.path,
                *cleartext,
                &query,
                server.tag.as_deref(),
                None,
                server.timeout,
                server.local_dial || force_local,
            ) {
                Ok(answer) => answer,
                Err(_) => return Lookup::Failed,
            },
            Transport::Doq => {
                match crate::dnsnet::doq(&endpoint.host, endpoint.port, &query, server.timeout) {
                    Ok(answer) => answer,
                    Err(_) => return Lookup::Failed,
                }
            }
            Transport::Local | Transport::Fake => return Lookup::Failed,
        };
        let Some(answer) = parse_answer(&response) else {
            return Lookup::Failed;
        };
        if id != 0 && answer.id != id {
            return Lookup::Failed;
        }
        if answer.rcode != 0 {
            return Lookup::Rcode(answer.rcode);
        }
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        for record in &answer.records {
            if record.kind != qtype || record.rdata.len() != family.width() {
                continue;
            }
            let ip = match family {
                Family::A => IpAddr::V4(Ipv4Addr::new(
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                )),
                Family::Aaaa => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&record.rdata);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
            };
            ips.push(ip);
            ttl = ttl.min(record.ttl.max(1));
        }
        if ips.is_empty() {
            Lookup::Empty
        } else {
            Lookup::Records(ips, if ttl == u32::MAX { DEFAULT_TTL } else { ttl })
        }
    }

    fn host_lookup(&self, name: &str, v4: bool, v6: bool) -> Option<HostAnswer> {
        if self.hosts.is_empty() {
            return None;
        }
        let lower = name.to_ascii_lowercase();
        let mut ips = Vec::new();
        let mut domain = None;
        let mut found = false;
        for rule in &self.hosts {
            if !rule.matcher.matches(name, &lower) {
                continue;
            }
            found = true;
            match &rule.target {
                HostTarget::Ips(held) => ips.extend(held.iter().copied()),
                HostTarget::Domain(to) => domain = Some(to.clone()),
                HostTarget::Rcode(0) => return Some(HostAnswer::Ips(Vec::new())),
                HostTarget::Rcode(code) => return Some(HostAnswer::Rcode(*code)),
            }
        }
        if !found {
            return None;
        }
        if let Some(domain) = domain.filter(|_| ips.is_empty()) {
            return Some(HostAnswer::Alias(domain));
        }
        ips.retain(|ip| (ip.is_ipv4() && v4) || (ip.is_ipv6() && v6));
        ips.sort_unstable();
        ips.dedup();
        Some(HostAnswer::Ips(ips))
    }
}

#[derive(Debug)]
enum HostAnswer {
    Ips(Vec<IpAddr>),
    Alias(String),
    Rcode(u16),
}

fn system_lookup(name: &str, v4: bool, v6: bool) -> Lookup {
    let Ok(addrs) = (name, 0u16).to_socket_addrs() else {
        return Lookup::Failed;
    };
    let mut ips: Vec<IpAddr> = addrs
        .map(|addr| addr.ip())
        .filter(|ip| (ip.is_ipv4() && v4) || (ip.is_ipv6() && v6))
        .collect();
    ips.sort_unstable();
    ips.dedup();
    if ips.is_empty() {
        Lookup::Empty
    } else {
        Lookup::Records(ips, DEFAULT_TTL)
    }
}

fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

fn parse_strategy(text: Option<&str>) -> Strategy {
    match text.map(str::to_ascii_lowercase).as_deref() {
        Some(
            "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4" | "use-ipv4"
            | "use-ip-v4",
        ) => Strategy::V4,
        Some(
            "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6" | "use-ipv6"
            | "use-ip-v6",
        ) => Strategy::V6,
        Some("usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys" | "use-system") => {
            Strategy::System
        }
        _ => Strategy::Both,
    }
}

fn flag(dns: &Json, key: &str) -> bool {
    dns.get(key).and_then(Json::as_bool).unwrap_or(false)
}

fn warn_unsupported(dns: &Json) {
    if dns
        .get("script")
        .and_then(Json::as_str)
        .is_some_and(|script| !script.is_empty())
    {
        eprintln!("dns: the script is not carried; querying the configured servers");
    }
}

fn empty_filter(value: &Json) -> bool {
    match value {
        Json::Null => true,
        Json::Str(text) => text.trim().is_empty(),
        Json::Arr(items) => items.is_empty(),
        _ => false,
    }
}

fn parse_ip_filter(
    value: Option<&Json>,
    assets: &mut Assets,
    field: &str,
) -> Result<(Option<IpMatcher>, bool), String> {
    let Some(value) = value.filter(|value| !empty_filter(value)) else {
        return Ok((None, false));
    };
    let items: Vec<String> = match value {
        Json::Str(text) => text.split(',').map(|item| item.trim().to_owned()).collect(),
        Json::Arr(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::trim)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{field} is not a string"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(format!("{field} is not a string or array")),
    };
    let mut rules = Vec::new();
    let mut prior = false;
    for item in items {
        if item == "*" {
            prior = true;
        } else if !item.is_empty() {
            rules.push(Json::Str(item));
        }
    }
    if rules.is_empty() {
        return Ok((None, prior));
    }
    let matcher = ip_matcher(&Json::Arr(rules), assets, field)?;
    Ok((Some(matcher), prior))
}

fn parse_ip(text: Option<&str>) -> Result<Option<IpAddr>, String> {
    match text {
        None => Ok(None),
        Some(text) => text
            .parse()
            .map(Some)
            .map_err(|_| format!("dns: `{text}` is not an IP address")),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn parse_server(
    item: &Json,
    strategy: Strategy,
    client_ip: Option<IpAddr>,
    disable_cache: bool,
    serve_stale: bool,
    serve_expired: Duration,
    default_tag: Option<&str>,
    assets: &mut Assets,
    policies: &mut PolicyIds,
) -> Result<Server, String> {
    let (
        address,
        port,
        domains,
        skip_fallback,
        final_query,
        policy_id,
        own_strategy,
        own_client,
        timeout,
        own_cache,
        own_stale,
        own_expired,
    ) = match item {
        Json::Str(address) => (
            address.as_str(),
            None,
            None,
            false,
            false,
            policies.get(item),
            strategy,
            client_ip,
            DEFAULT_TIMEOUT,
            disable_cache,
            serve_stale,
            serve_expired,
        ),
        Json::Obj(_) => {
            let address = item
                .get("address")
                .and_then(Json::as_str)
                .ok_or_else(|| "dns: nameserver has no address".to_owned())?;
            (
                address,
                item.get("port").and_then(Json::as_port),
                item.get("domains"),
                item.get("skipFallback")
                    .and_then(Json::as_bool)
                    .unwrap_or(false),
                item.get("finalQuery")
                    .and_then(Json::as_bool)
                    .unwrap_or(false),
                item.get("policyID")
                    .and_then(Json::as_u32)
                    .unwrap_or_else(|| policies.get(item)),
                parse_strategy(item.get("queryStrategy").and_then(Json::as_str)),
                parse_ip(item.get("clientIp").and_then(Json::as_str))?.or(client_ip),
                Duration::from_millis(
                    item.get("timeoutMs").and_then(Json::as_u32).unwrap_or(4000) as u64
                ),
                item.get("disableCache")
                    .and_then(Json::as_bool)
                    .unwrap_or(disable_cache),
                item.get("serveStale")
                    .and_then(Json::as_bool)
                    .unwrap_or(serve_stale),
                Duration::from_secs(
                    item.get("serveExpiredTTL")
                        .and_then(Json::as_u32)
                        .unwrap_or(serve_expired.as_secs() as u32) as u64,
                ),
            )
        }
        _ => return Err("dns: nameserver is not a string or object".into()),
    };
    let (transport, endpoint, path, implicit_local, local_dial) = parse_address(address, port)?;
    let tag = item
        .get("tag")
        .and_then(Json::as_str)
        .filter(|tag| !tag.is_empty())
        .or(default_tag)
        .map(str::to_owned);
    let mut matcher = DomainMatcher::new();
    let any_domain = parse_domains(domains, &mut matcher, assets)?;
    let (own_v4, own_v6) = own_strategy.families();
    let (global_v4, global_v6) = strategy.families();
    let expected_value = item
        .get("expectedIPs")
        .filter(|value| !empty_filter(value))
        .or_else(|| item.get("expectIPs"));
    let unexpected_value = item.get("unexpectedIPs");
    let (expected, act_prior) = parse_ip_filter(expected_value, assets, "dns expectedIPs")?;
    let (unexpected, act_unprior) = parse_ip_filter(unexpected_value, assets, "dns unexpectedIPs")?;
    Ok(Server {
        transport,
        endpoint,
        path,
        matcher: any_domain.then_some(matcher),
        implicit_local,
        local_dial,
        skip_fallback,
        final_query,
        policy_id,
        tag,
        id: item
            .get("id")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_owned(),
        timeout,
        cache: CachePolicy {
            disable: own_cache,
            serve_stale: own_stale,
            serve_expired: own_expired,
        },
        client_ip: own_client,
        expected,
        unexpected,
        act_prior,
        act_unprior,
        v4: own_v4 && global_v4,
        v6: own_v6 && global_v6,
        req_id: AtomicU16::new(0),
    })
}

#[derive(Default)]
struct PolicyIds {
    ids: HashMap<String, u32>,
    next: u32,
}

impl PolicyIds {
    /// The reference groups servers whose policy fields agree, in first-seen order starting at 1.
    fn get(&mut self, item: &Json) -> u32 {
        let mut key = String::new();
        key.push_str("client=");
        key.push_str(
            item.get("clientIp")
                .and_then(Json::as_str)
                .unwrap_or("none")
                .trim(),
        );
        key.push_str(if flag(item, "skipFallback") {
            "|skip=1|"
        } else {
            "|skip=0|"
        });
        key.push_str("qs=");
        key.push_str(
            &item
                .get("queryStrategy")
                .and_then(Json::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase(),
        );
        key.push_str("|tag=");
        key.push_str(
            &item
                .get("tag")
                .and_then(Json::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase(),
        );
        for (name, value) in [
            ("domains", item.get("domains")),
            ("expected", item.get("expectedIPs")),
            ("expect", item.get("expectIPs")),
            ("unexpected", item.get("unexpectedIPs")),
        ] {
            key.push('|');
            key.push_str(name);
            key.push('=');
            let mut list: Vec<String> = match value {
                Some(Json::Str(text)) => text
                    .split(',')
                    .map(|part| part.trim().to_ascii_lowercase())
                    .collect(),
                Some(Json::Arr(items)) => items
                    .iter()
                    .filter_map(Json::as_str)
                    .map(|part| part.trim().to_ascii_lowercase())
                    .collect(),
                _ => Vec::new(),
            };
            list.sort();
            if list.is_empty() {
                key.push_str("[]");
            } else {
                key.push_str(&list.join(","));
            }
        }
        if let Some(id) = self.ids.get(&key) {
            return *id;
        }
        self.next += 1;
        self.ids.insert(key, self.next);
        self.next
    }
}

type AddressParts = (Transport, Option<Endpoint>, String, bool, bool);

fn parse_domains(
    domains: Option<&Json>,
    matcher: &mut DomainMatcher,
    assets: &mut Assets,
) -> Result<bool, String> {
    let Some(list) = domains.filter(|list| !matches!(list, Json::Null)) else {
        return Ok(false);
    };
    let items: Vec<&str> = match list {
        Json::Str(text) => text.split(',').collect(),
        Json::Arr(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| "dns: domain is not a string".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("dns: domains is not a string or array".into()),
    };
    for item in items {
        add_domain(matcher, item.trim(), assets)?;
    }
    matcher.finish()?;
    Ok(true)
}

fn parse_address(address: &str, port: Option<u16>) -> Result<AddressParts, String> {
    let lower = address.to_ascii_lowercase();
    if lower == "localhost" {
        return Ok((Transport::Local, None, String::new(), true, true));
    }
    if lower == "fakedns" {
        return Ok((Transport::Fake, None, String::new(), false, true));
    }
    let (scheme, rest) = match address.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => {
            return Ok((
                Transport::Udp,
                Some(Endpoint {
                    host: address.to_owned(),
                    port: port.unwrap_or(53),
                }),
                String::new(),
                false,
                false,
            ))
        }
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, String::new()),
    };
    let (host, default_port, transport, path) = match scheme.as_str() {
        "https" | "https+local" => (authority, 443, Transport::Doh { cleartext: false }, path),
        "h2c" | "h2c+local" => (authority, 80, Transport::Doh { cleartext: true }, path),
        "quic" | "quic+local" => (authority, 853, Transport::Doq, String::new()),
        "tls" | "tls+local" => (authority, 853, Transport::Tls, String::new()),
        "tcp" | "tcp+local" => (authority, 53, Transport::Tcp, String::new()),
        "udp" | "udp+local" => (authority, 53, Transport::Udp, String::new()),
        other => {
            return Err(format!(
                "dns: no available name server could be created from `{other}://{rest}`"
            ))
        }
    };
    // The local spellings and DoQ are the reference's direct dials; every other form is routed.
    let local_dial = scheme.ends_with("+local") || matches!(transport, Transport::Doq);
    let (host, embed) = split_host_port(host);
    let port = embed.or(port).unwrap_or(default_port);
    if host.is_empty() {
        return Err(format!("dns: `{address}` names no host"));
    }
    Ok((
        transport,
        Some(Endpoint {
            host: host.to_owned(),
            port,
        }),
        path,
        false,
        local_dial,
    ))
}

fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|port| port.parse().ok());
            return (host, port);
        }
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        _ => (authority, None),
    }
}

fn parse_hosts(value: Option<&Json>) -> Result<Vec<HostRule>, String> {
    let Some(Json::Obj(entries)) = value.filter(|value| !matches!(value, Json::Null)) else {
        return Ok(Vec::new());
    };
    let mut assets = Assets::new(asset_dirs());
    let mut rules = Vec::new();
    for (pattern, value) in entries {
        let mut matcher = DomainMatcher::new();
        let pattern = if pattern.contains(':') {
            pattern.clone()
        } else {
            format!("full:{pattern}")
        };
        add_domain(&mut matcher, &pattern, &mut assets)?;
        matcher.finish()?;
        let target = match value {
            Json::Str(text) if text.starts_with('#') => {
                let code = text[1..]
                    .parse::<u16>()
                    .map_err(|_| format!("dns: hosts `{pattern}` has rcode `{text}`"))?;
                HostTarget::Rcode(code)
            }
            Json::Str(text) => match text.parse() {
                Ok(ip) => HostTarget::Ips(vec![ip]),
                Err(_) => HostTarget::Domain(text.clone()),
            },
            Json::Arr(items) => {
                let mut ips = Vec::new();
                let mut domain = None;
                for item in items {
                    let text = item
                        .as_str()
                        .ok_or_else(|| "dns: hosts value is not a string".to_owned())?;
                    match text.parse() {
                        Ok(ip) => ips.push(ip),
                        Err(_) => {
                            domain.get_or_insert_with(|| text.to_owned());
                        }
                    }
                }
                match domain {
                    Some(domain) => HostTarget::Domain(domain),
                    None => HostTarget::Ips(ips),
                }
            }
            _ => return Err("dns: hosts value is not a string or array".into()),
        };
        rules.push(HostRule { matcher, target });
    }
    Ok(rules)
}

fn system_hosts() -> Result<Vec<HostRule>, String> {
    let path = if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
        format!("{root}\\System32\\drivers\\etc\\hosts")
    } else {
        "/etc/hosts".to_owned()
    };
    let text = std::fs::read_to_string(&path).map_err(|error| format!("dns: {path}: {error}"))?;
    let mut assets = Assets::new(asset_dirs());
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let Some(ip) = fields.next() else { continue };
        let Ok(ip) = ip.parse::<IpAddr>() else {
            continue;
        };
        for name in fields {
            let mut matcher = DomainMatcher::new();
            add_domain(&mut matcher, &format!("full:{name}"), &mut assets)?;
            matcher.finish()?;
            rules.push(HostRule {
                matcher,
                target: HostTarget::Ips(vec![ip]),
            });
        }
    }
    Ok(rules)
}

fn random_padding() -> usize {
    let mut raw = [0u8; 2];
    getrandom::fill(&mut raw).map_or(0, |()| (usize::from(u16::from_be_bytes(raw)) % 201) + 100)
}

#[derive(Debug)]
struct FakePools {
    pools: Vec<Mutex<FakePool>>,
}

impl FakePools {
    fn allocate(&self, name: &str, family: Family) -> Option<(Vec<IpAddr>, u32)> {
        for pool in &self.pools {
            let mut pool = pool.lock().ok()?;
            if pool.family == family {
                return Some((vec![pool.allocate(name)?], 1));
            }
        }
        None
    }

    #[allow(dead_code)]
    fn domain_of(&self, ip: IpAddr) -> Option<String> {
        for pool in &self.pools {
            let Ok(mut pool) = pool.lock() else {
                continue;
            };
            if let Some(name) = pool.by_ip.get(&ip) {
                let name = name.clone();
                pool.touch(&name);
                return Some(name);
            }
        }
        None
    }
}

#[derive(Debug)]
struct FakePool {
    family: Family,
    base: u128,
    rooms: u32,
    lru_size: usize,
    by_name: HashMap<String, IpAddr>,
    by_ip: HashMap<IpAddr, String>,
    order: VecDeque<String>,
}

impl FakePool {
    fn allocate(&mut self, name: &str) -> Option<IpAddr> {
        if let Some(ip) = self.by_name.get(name).copied() {
            self.touch(name);
            return Some(ip);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis();
        let span = 1u128.checked_shl(self.rooms).unwrap_or(u128::MAX);
        let mut candidate = self.base.wrapping_add(now % span);
        for _ in 0..span {
            let ip = self.ip(candidate);
            if !self.by_ip.contains_key(&ip) {
                if self.order.len() >= self.lru_size {
                    if let Some(old) = self.order.pop_front() {
                        if let Some(ip) = self.by_name.remove(&old) {
                            self.by_ip.remove(&ip);
                        }
                    }
                }
                self.by_name.insert(name.to_owned(), ip);
                self.by_ip.insert(ip, name.to_owned());
                self.order.push_back(name.to_owned());
                return Some(ip);
            }
            candidate = candidate.wrapping_add(1);
            if candidate >= self.base.wrapping_add(span) {
                candidate = self.base;
            }
        }
        None
    }

    fn ip(&self, value: u128) -> IpAddr {
        match self.family {
            Family::A => IpAddr::V4(Ipv4Addr::from(value as u32)),
            Family::Aaaa => IpAddr::V6(Ipv6Addr::from(value)),
        }
    }

    fn touch(&mut self, name: &str) {
        if let Some(at) = self.order.iter().position(|held| held == name) {
            self.order.remove(at);
        }
        self.order.push_back(name.to_owned());
    }
}

fn parse_fake(
    value: Option<&Json>,
    needed: bool,
    strategy: Strategy,
) -> Result<Option<FakePools>, String> {
    let value = value.filter(|value| !matches!(value, Json::Null));
    if value.is_none() && !needed {
        return Ok(None);
    }
    let (default_v4, default_v6) = match strategy {
        Strategy::V4 => (true, false),
        Strategy::V6 => (false, true),
        Strategy::Both | Strategy::System => (true, true),
    };
    let mut wanted = Vec::new();
    match value {
        Some(Json::Obj(_)) => wanted.push(value.expect("checked")),
        Some(Json::Arr(items)) => wanted.extend(items.iter()),
        Some(_) => return Err("dns: fakeDns is not an object or array".into()),
        None => {}
    }
    if wanted.is_empty() {
        if default_v4 {
            wanted.push(&Json::Null);
        }
        if default_v6 {
            wanted.push(&Json::Null);
        }
    }
    let mut pools = Vec::new();
    let mut only_v4 = false;
    let mut only_v6 = false;
    for item in wanted {
        let (pool, size) = match item {
            Json::Null => {
                let single = default_v4 != default_v6;
                let (pool, size) = if default_v4 && !only_v4 {
                    only_v4 = true;
                    ("198.18.0.0/15", if single { 65535 } else { 32768 })
                } else if default_v6 && !only_v6 {
                    only_v6 = true;
                    ("2001:2::/48", if single { 65535 } else { 32768 })
                } else {
                    ("198.18.0.0/15", 32768)
                };
                (pool.to_owned(), size)
            }
            Json::Obj(_) => (
                item.get("ipPool")
                    .and_then(Json::as_str)
                    .unwrap_or("198.18.0.0/15")
                    .to_owned(),
                item.get("poolSize").and_then(Json::as_u32).unwrap_or(65535) as usize,
            ),
            _ => return Err("dns: fakeDns pool is not an object".into()),
        };
        if size == 0 {
            return Err(format!("dns: fakeDns pool `{pool}` has no size"));
        }
        let (base, prefix) = parse_cidr(&pool)?;
        let bits = if base.is_ipv4() { 32 } else { 128 };
        let rooms = bits - prefix;
        if rooms < 128 && (size as u128) >= (1u128 << rooms) {
            return Err(format!(
                "dns: fakeDns LRU size is bigger than subnet `{pool}`"
            ));
        }
        pools.push(Mutex::new(FakePool {
            family: if base.is_ipv4() {
                Family::A
            } else {
                Family::Aaaa
            },
            base: match base {
                IpAddr::V4(ip) => u32::from(ip) as u128,
                IpAddr::V6(ip) => u128::from(ip),
            },
            rooms,
            lru_size: size,
            by_name: HashMap::new(),
            by_ip: HashMap::new(),
            order: VecDeque::new(),
        }));
    }
    Ok(Some(FakePools { pools }))
}

fn parse_cidr(text: &str) -> Result<(IpAddr, u32), String> {
    let (address, prefix) = text
        .split_once('/')
        .ok_or_else(|| format!("dns: `{text}` is not a CIDR"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("dns: `{text}` is not a CIDR"))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| format!("dns: `{text}` is not a CIDR"))?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    if prefix > bits {
        return Err(format!("dns: `{text}` prefix is past {bits}"));
    }
    let base = match address {
        IpAddr::V4(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
        }
        IpAddr::V6(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
    };
    Ok((base, prefix))
}

static INSTALLED: Mutex<Option<Arc<Resolver>>> = Mutex::new(None);

/// Build the resolver a root config names and make it the one the relay's own
/// name lookups use. Called before the first inbound opens.
pub(crate) fn install(root: &Json) -> Result<(), String> {
    let resolver = Resolver::from_root(root)?.map(Arc::new);
    *INSTALLED
        .lock()
        .map_err(|_| "dns: the resolver lock is poisoned".to_owned())? = resolver;
    Ok(())
}

pub(crate) fn installed() -> Option<Arc<Resolver>> {
    INSTALLED.lock().ok().and_then(|held| held.clone())
}

#[cfg(test)]
mod resolver_tests {
    use super::*;
    use ferrox_core::dns::{ip_answer, parse_query};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn root(text: &str) -> Json {
        crate::json::parse(text).expect("config")
    }

    #[test]
    fn udp_answers_are_cached_per_family() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        let seen = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).expect("query");
                count.fetch_add(1, Ordering::SeqCst);
                let question = parse_query(&buf[..len]).expect("question");
                let records = match question.qtype {
                    28 => vec![vec![
                        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]],
                    _ => vec![vec![192, 0, 2, 1]],
                };
                let answer = ip_answer(&question, 0, 120, &records).expect("answer");
                socket.send_to(&answer, peer).expect("reply");
            }
        });
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"servers":["udp://127.0.0.1:{port}"]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        let (first, ttl) = resolver.lookup("example.com").expect("first");
        assert_eq!(ttl, 120);
        assert_eq!(first.len(), 2);
        let (second, _) = resolver.lookup("example.com").expect("cached");
        assert_eq!(second, first);
        assert_eq!(seen.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_script_server_answers_from_that_server_alone() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).expect("query");
            let question = parse_query(&buf[..len]).expect("question");
            let answer = ip_answer(&question, 0, 60, &[vec![192, 0, 2, 9]]).expect("answer");
            socket.send_to(&answer, peer).expect("reply");
        });
        let resolver = Resolver::from_root(&root(&format!(
            r#"{{"dns":{{"servers":[{{"address":"udp://127.0.0.1:{port}","id":"primary"}}]}}}}"#
        )))
        .expect("resolver")
        .expect("configured");
        assert_eq!(
            resolver.script_query(0, "example.com", true, false, false),
            Lookup::Records(vec!["192.0.2.9".parse().unwrap()], 60)
        );
    }

    #[test]
    fn a_cache_hit_copies_only_the_answer_vector() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).expect("query");
            let question = parse_query(&buf[..len]).expect("question");
            let answer = ip_answer(&question, 0, 120, &[vec![192, 0, 2, 1]]).expect("answer");
            socket.send_to(&answer, peer).expect("reply");
        });
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"queryStrategy":"UseIP4","servers":["udp://127.0.0.1:{port}"]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        resolver.lookup("example.com").expect("warm");
        let (answer, counts) = ferrox_core::alloc_count::measure(|| resolver.lookup("example.com"));
        assert_eq!(
            answer.expect("cached").0,
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            counts.allocs, 4,
            "the focus and order vectors and the answer; the key is borrowed"
        );
    }

    #[test]
    fn hosts_answer_without_a_network_query() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
            r#"{"dns":{"servers":["localhost"],"hosts":{"example.com":["10.0.0.1","2001:db8::1"]}}}"#,
        ))
                .expect("resolver")
                .expect("configured"),
        );
        let (ips, ttl) = resolver.lookup("example.com").expect("hosts");
        assert_eq!(ttl, 10);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn a_script_query_asks_only_for_the_families_it_names() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
                r#"{"dns":{"servers":["localhost"],"hosts":{"example.com":["10.0.0.1","2001:db8::1"]}}}"#,
            ))
            .expect("resolver")
            .expect("configured"),
        );
        assert_eq!(
            resolver
                .lookup_families("example.com", false, true, false)
                .unwrap()
                .0,
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            resolver
                .lookup_families("example.com", true, false, false)
                .unwrap()
                .0,
            vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert!(resolver
            .lookup_families("example.com", false, false, false)
            .is_none());
    }

    #[test]
    fn fake_pools_allocate_and_reverse_both_families() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
            r#"{"dns":{"servers":["fakedns"],"queryStrategy":"UseIP"},"fakeDns":{"ipPool":"198.18.0.0/15","poolSize":32768}}"#,
        ))
                .expect("resolver")
                .expect("configured"),
        );
        let (ips, ttl) = resolver
            .lookup_families("example.com", true, true, true)
            .expect("fake");
        assert_eq!(ttl, 1);
        assert!(ips.iter().all(std::net::IpAddr::is_ipv4));
        assert_eq!(resolver.domain_of(ips[0]).as_deref(), Some("example.com"));
        let again = resolver
            .lookup_families("example.com", true, true, true)
            .expect("stable");
        assert_eq!(again.0, ips);
    }

    #[test]
    fn hosts_rcode_is_an_answer_and_is_not_sent_to_a_server() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
            r##"{"dns":{"servers":["localhost"],"hosts":{"blocked.test":"#3","empty.test":"#0"}}}"##,
        ))
                .expect("resolver")
                .expect("configured"),
        );
        assert_eq!(resolver.lookup_result("blocked.test"), Lookup::Rcode(3));
        assert_eq!(resolver.lookup_result("empty.test"), Lookup::Empty);
        assert!(resolver.lookup("blocked.test").is_none());
    }

    #[test]
    fn hosts_replace_a_domain_then_answer_its_ips() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
            r#"{"dns":{"servers":["localhost"],"hosts":{"alias.test":"target.test","target.test":["10.0.0.9"]}}}"#,
        ))
                .expect("resolver")
                .expect("configured"),
        );
        let (ips, ttl) = resolver.lookup("alias.test").expect("alias");
        assert_eq!(ttl, 10);
        assert_eq!(ips, vec!["10.0.0.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn expected_ips_filter_an_answer_and_fall_to_the_next_server() {
        let first = std::net::UdpSocket::bind("127.0.0.1:0").expect("first bind");
        let second = std::net::UdpSocket::bind("127.0.0.1:0").expect("second bind");
        for (socket, ip) in [
            (first.try_clone().expect("first clone"), [192, 0, 2, 1]),
            (second.try_clone().expect("second clone"), [198, 51, 100, 1]),
        ] {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            std::thread::spawn(move || {
                let mut buf = [0u8; 512];
                let (len, peer) = socket.recv_from(&mut buf).expect("query");
                let question = parse_query(&buf[..len]).expect("question");
                let answer = ip_answer(&question, 0, 60, &[ip.to_vec()]).expect("answer");
                socket.send_to(&answer, peer).expect("reply");
            });
        }
        let first_port = first.local_addr().expect("first addr").port();
        let second_port = second.local_addr().expect("second addr").port();
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"queryStrategy":"UseIP4","servers":[
                {{"address":"udp://127.0.0.1:{first_port}","expectedIPs":["198.51.100.0/24"]}},
                {{"address":"udp://127.0.0.1:{second_port}","expectedIPs":["198.51.100.0/24"]}}
            ]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        let (ips, _) = resolver.lookup("example.com").expect("filtered");
        assert_eq!(ips, vec!["198.51.100.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn an_expected_star_narrows_to_the_matching_addresses_first() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).expect("query");
            let question = parse_query(&buf[..len]).expect("question");
            let answer = ip_answer(
                &question,
                0,
                60,
                &[vec![198, 51, 100, 1], vec![192, 0, 2, 1]],
            )
            .expect("answer");
            socket.send_to(&answer, peer).expect("reply");
        });
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"queryStrategy":"UseIP4","servers":[
                {{"address":"udp://127.0.0.1:{port}","expectedIPs":["*","198.51.100.0/24"]}}
            ]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        let (ips, _) = resolver.lookup("example.com").expect("prior");
        assert_eq!(ips, vec!["198.51.100.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn a_server_rcode_is_cached_as_an_answer() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        let seen = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).expect("query");
            count.fetch_add(1, Ordering::SeqCst);
            let question = parse_query(&buf[..len]).expect("question");
            let answer = ip_answer(&question, 3, 60, &[]).expect("answer");
            socket.send_to(&answer, peer).expect("reply");
        });
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"queryStrategy":"UseIP4","servers":["udp://127.0.0.1:{port}"]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        assert_eq!(resolver.lookup_result("missing.test"), Lookup::Rcode(3));
        assert_eq!(resolver.lookup_result("missing.test"), Lookup::Rcode(3));
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn hosts_plain_keys_are_full_and_tagged_keys_reach_subdomains() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
            r#"{"dns":{"servers":["localhost"],"hosts":{"example.com":["10.0.0.2"],"domain:sub.test":["10.0.0.3"]}}}"#,
        ))
                .expect("resolver")
                .expect("configured"),
        );
        assert!(resolver.lookup("example.com").is_some());
        assert!(resolver
            .host_lookup("www.example.com", true, true)
            .is_none());
        assert!(resolver.lookup("a.sub.test").is_some());
    }

    fn answer_ip(socket: &std::net::UdpSocket, ip: [u8; 4]) {
        let mut buf = [0u8; 512];
        let (len, peer) = socket.recv_from(&mut buf).expect("query");
        let question = parse_query(&buf[..len]).expect("question");
        let answer = ip_answer(&question, 0, 60, &[ip.to_vec()]).expect("answer");
        socket.send_to(&answer, peer).expect("reply");
    }

    #[test]
    fn an_rcode_falls_through_to_the_next_server() {
        let first = std::net::UdpSocket::bind("127.0.0.1:0").expect("first bind");
        let second = std::net::UdpSocket::bind("127.0.0.1:0").expect("second bind");
        let first_port = first.local_addr().expect("first addr").port();
        let second_port = second.local_addr().expect("second addr").port();
        let first_server = first.try_clone().expect("first clone");
        let second_server = second.try_clone().expect("second clone");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = first_server.recv_from(&mut buf).expect("query");
            let question = parse_query(&buf[..len]).expect("question");
            let answer = ip_answer(&question, 3, 60, &[]).expect("answer");
            first_server.send_to(&answer, peer).expect("reply");
        });
        std::thread::spawn(move || answer_ip(&second_server, [198, 51, 100, 1]));
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"queryStrategy":"UseIP4","servers":[
                    "udp://127.0.0.1:{first_port}",
                    "udp://127.0.0.1:{second_port}"
                ]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        assert_eq!(
            resolver.lookup("example.com"),
            Some((vec!["198.51.100.1".parse().unwrap()], 60))
        );
    }

    #[test]
    fn a_parallel_query_takes_the_first_answer() {
        let slow = std::net::UdpSocket::bind("127.0.0.1:0").expect("slow bind");
        let fast = std::net::UdpSocket::bind("127.0.0.1:0").expect("fast bind");
        let slow_port = slow.local_addr().expect("slow addr").port();
        let fast_port = fast.local_addr().expect("fast addr").port();
        let slow_server = slow.try_clone().expect("slow clone");
        let fast_server = fast.try_clone().expect("fast clone");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = slow_server.recv_from(&mut buf).expect("query");
            std::thread::sleep(Duration::from_secs(1));
            let question = parse_query(&buf[..len]).expect("question");
            let answer = ip_answer(&question, 0, 60, &[vec![192, 0, 2, 1]]).expect("answer");
            slow_server.send_to(&answer, peer).expect("reply");
        });
        std::thread::spawn(move || answer_ip(&fast_server, [198, 51, 100, 1]));
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"enableParallelQuery":true,"queryStrategy":"UseIP4","servers":[
                    "udp://127.0.0.1:{slow_port}",
                    "udp://127.0.0.1:{fast_port}"
                ]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        assert_eq!(
            resolver.lookup("example.com"),
            Some((vec!["198.51.100.1".parse().unwrap()], 60))
        );
    }

    #[test]
    fn a_later_policy_waits_for_the_group_before_it() {
        let first = std::net::UdpSocket::bind("127.0.0.1:0").expect("first bind");
        let second = std::net::UdpSocket::bind("127.0.0.1:0").expect("second bind");
        let first_port = first.local_addr().expect("first addr").port();
        let second_port = second.local_addr().expect("second addr").port();
        let first_server = first.try_clone().expect("first clone");
        let second_server = second.try_clone().expect("second clone");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = first_server.recv_from(&mut buf).expect("query");
            std::thread::sleep(Duration::from_millis(300));
            let question = parse_query(&buf[..len]).expect("question");
            let answer = ip_answer(&question, 0, 60, &[vec![192, 0, 2, 1]]).expect("answer");
            first_server.send_to(&answer, peer).expect("reply");
        });
        std::thread::spawn(move || answer_ip(&second_server, [198, 51, 100, 1]));
        let resolver = Arc::new(
            Resolver::from_root(&root(&format!(
                r#"{{"dns":{{"enableParallelQuery":true,"queryStrategy":"UseIP4","servers":[
                    {{"address":"udp://127.0.0.1:{first_port}","policyID":1}},
                    {{"address":"udp://127.0.0.1:{second_port}","policyID":2}}
                ]}}}}"#
            )))
            .expect("resolver")
            .expect("configured"),
        );
        assert_eq!(
            resolver.lookup("example.com"),
            Some((vec!["192.0.2.1".parse().unwrap()], 60))
        );
    }

    #[test]
    fn a_json_policy_is_the_reference_key() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
                r#"{"dns":{"servers":[
                    {"address":"udp://192.0.2.1","tag":"same"},
                    {"address":"udp://192.0.2.2","tag":"same"},
                    {"address":"udp://192.0.2.3","tag":"other"},
                    "udp://192.0.2.4"
                ]}}"#,
            ))
            .expect("resolver")
            .expect("configured"),
        );
        let ids: Vec<u32> = resolver
            .servers
            .iter()
            .map(|server| server.policy_id)
            .collect();
        assert_eq!(ids, [1, 1, 2, 3]);
    }

    #[test]
    fn a_nameserver_tag_overrides_the_config_tag() {
        let resolver = Arc::new(
            Resolver::from_root(&root(
                r#"{"dns":{"tag":"dns-in","servers":[
                    {"address":"udp://192.0.2.1","tag":"server-in"},
                    {"address":"udp://192.0.2.2"}
                ]}}"#,
            ))
            .expect("resolver")
            .expect("configured"),
        );
        assert_eq!(resolver.servers[0].tag.as_deref(), Some("server-in"));
        assert_eq!(resolver.servers[1].tag.as_deref(), Some("dns-in"));
    }

    #[test]
    fn a_nameserver_id_is_what_the_script_table_exposes() {
        let resolver = Resolver::from_root(&root(
            r#"{"dns":{"servers":[
                {"address":"udp://192.0.2.1","id":"primary","tag":"server-in"},
                {"address":"udp://192.0.2.2"}
            ]}}"#,
        ))
        .expect("resolver")
        .expect("configured");
        assert_eq!(
            resolver.script_servers(),
            [("primary".to_owned(), 0), (String::new(), 1)]
        );
    }

    #[test]
    fn the_local_spellings_and_doq_keep_the_direct_dial() {
        for address in ["tcp+local://192.0.2.1", "https+local://192.0.2.1"] {
            let (_, _, _, _, local) = parse_address(address, None).expect("address");
            assert!(local, "{address} is a local dial");
        }
        for address in ["tcp://192.0.2.1", "https://192.0.2.1"] {
            let (_, _, _, _, local) = parse_address(address, None).expect("address");
            assert!(!local, "{address} rides the route");
        }
        for address in ["quic://192.0.2.1", "quic+local://192.0.2.1"] {
            let (_, _, _, _, local) = parse_address(address, None).expect("address");
            assert!(local, "{address} is the reference's direct DoQ dial");
        }
    }
}
