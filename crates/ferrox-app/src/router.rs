//! Routing rules and the geosite/geoip assets they name.
//!
//! A rule is a set of selectors that must all hold and one outbound tag the first match decides. The
//! asset containers are xray's protobuf `GeoSiteList` and `GeoIPList`, read here rather than linked,
//! so a config that names a code this host cannot find fails at start with the file and code named.

use crate::json::Json;
use crate::xray_pb::Reader;
use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Network {
    Tcp,
    Udp,
}

impl Network {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

/// One connection as the rules see it: absent fields match no rule, which is what keeps a selector
/// from turning into an unconditional match on a front that cannot answer it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Flow<'a> {
    pub(crate) network: Network,
    pub(crate) domain: Option<&'a str>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) port: Option<u16>,
    pub(crate) source: Option<SocketAddr>,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) inbound_tag: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainStrategy {
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

/// What a matching rule names: an outbound, or a balancer that picks one per flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteTarget<'a> {
    Outbound(&'a str),
    Balancer(&'a str),
}

impl<'a> RouteTarget<'a> {
    pub(crate) fn tag(self) -> &'a str {
        match self {
            Self::Outbound(tag) | Self::Balancer(tag) => tag,
        }
    }
}

fn rule_target(rule: &Rule) -> RouteTarget<'_> {
    if rule.balancer {
        RouteTarget::Balancer(&rule.target)
    } else {
        RouteTarget::Outbound(&rule.target)
    }
}

#[derive(Debug)]
pub(crate) struct Routing {
    strategy: DomainStrategy,
    rules: Vec<Rule>,
    balancers: Vec<Balancer>,
    has_domains: bool,
}

/// One `balancers` entry: a tag a rule may name, the outbound-tag prefixes it draws from, and the
/// strategy that picks one per flow. Xray selects candidates with `strings.HasPrefix`, not a regex.
#[derive(Debug)]
pub(crate) struct Balancer {
    tag: String,
    selectors: Vec<String>,
    strategy: Strategy,
    fallback: Option<String>,
    index: AtomicUsize,
    seed: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strategy {
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad,
}

impl Balancer {
    pub(crate) fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn selects(&self, tag: &str) -> bool {
        self.selectors
            .iter()
            .any(|selector| tag.starts_with(selector))
    }

    pub(crate) fn fallback(&self) -> Option<&str> {
        self.fallback.as_deref()
    }

    /// The candidate for one flow. Without the observatory the two health strategies have no
    /// reading to choose from, so they name nothing and the caller falls back as the reference does.
    pub(crate) fn pick<'a>(&self, candidates: &'a [String]) -> Option<&'a str> {
        let count = candidates.len();
        if count == 0 {
            return None;
        }
        let at = match self.strategy {
            Strategy::RoundRobin => self.index.fetch_add(1, Ordering::Relaxed) % count,
            Strategy::Random => {
                let mut state = self.seed.load(Ordering::Relaxed);
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                self.seed.store(state, Ordering::Relaxed);
                (state % count as u64) as usize
            }
            Strategy::LeastPing | Strategy::LeastLoad => return None,
        };
        Some(candidates[at].as_str())
    }

    fn parse(value: &Json, at: usize) -> Result<Self, String> {
        let pairs = object(value, "routing balancer")?;
        let mut tag = None;
        let mut selectors = None;
        let mut strategy = Strategy::Random;
        let mut fallback = None;
        for (key, field) in pairs {
            match key.as_str() {
                "tag" => {
                    tag = Some(
                        field
                            .as_str()
                            .filter(|tag| !tag.is_empty())
                            .ok_or_else(|| "balancer tag is empty".to_owned())?
                            .to_owned(),
                    );
                }
                "selector" => selectors = string_list(field, "selector")?,
                "strategy" => strategy = parse_strategy(field)?,
                "fallbackTag" => {
                    fallback = field
                        .as_str()
                        .filter(|tag| !tag.is_empty())
                        .map(str::to_owned);
                }
                other => return Err(format!("routing balancer field `{other}` is not carried")),
            }
        }
        let tag = tag.ok_or_else(|| "routing balancer has no tag".to_owned())?;
        let selectors = selectors.ok_or_else(|| format!("balancer `{tag}` has no selector"))?;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64)
            .wrapping_add(at as u64)
            | 1;
        Ok(Self {
            tag,
            selectors,
            strategy,
            fallback,
            index: AtomicUsize::new(0),
            seed: AtomicU64::new(seed),
        })
    }
}

fn parse_strategy(value: &Json) -> Result<Strategy, String> {
    let named = match value {
        Json::Null => return Ok(Strategy::Random),
        Json::Str(named) => named.as_str(),
        Json::Obj(pairs) => {
            let mut named = "";
            for (key, field) in pairs {
                match key.as_str() {
                    "type" => {
                        named = field
                            .as_str()
                            .ok_or_else(|| "balancer strategy type is not a string".to_owned())?;
                    }
                    "settings" => {
                        if !matches!(field, Json::Null | Json::Obj(_)) {
                            return Err("balancer strategy settings is not an object".into());
                        }
                    }
                    other => {
                        return Err(format!(
                            "routing balancer strategy field `{other}` is not carried"
                        ))
                    }
                }
            }
            named
        }
        _ => return Err("routing balancer strategy is not a string or object".into()),
    };
    match named.to_ascii_lowercase().as_str() {
        "" | "random" => Ok(Strategy::Random),
        "roundrobin" => Ok(Strategy::RoundRobin),
        "leastping" => Ok(Strategy::LeastPing),
        "leastload" => Ok(Strategy::LeastLoad),
        _ => Err(format!(
            "routing balancer strategy `{named}` is not random, roundRobin, leastPing or leastLoad"
        )),
    }
}

/// The name a flow carries, in the form the tables store and the form a regex must see. Lowering
/// happens on the first table that needs it, once per decision, not once per rule.
#[derive(Debug, Clone, Copy)]
struct Names<'a> {
    raw: &'a str,
    needs_lower: bool,
    lower: &'a OnceCell<String>,
}

impl Names<'_> {
    fn lower(&self) -> &str {
        if !self.needs_lower {
            return self.raw;
        }
        self.lower.get_or_init(|| self.raw.to_ascii_lowercase())
    }
}

#[derive(Debug)]
struct Rule {
    target: String,
    balancer: bool,
    tag: Option<String>,
    inbound_tags: Option<Vec<String>>,
    networks: Option<Vec<Network>>,
    local_os: Option<Vec<String>>,
    ports: Option<PortSet>,
    source_ports: Option<PortSet>,
    local_ports: Option<PortSet>,
    domains: Option<DomainMatcher>,
    ips: Option<IpMatcher>,
    source_ips: Option<IpMatcher>,
    local_ips: Option<IpMatcher>,
}

impl Routing {
    /// The routing block as configured, or `None` when the config has none; every asset it names is
    /// opened here so a missing file or code stops the process before an inbound listens.
    pub(crate) fn parse(root: &Json) -> Result<Option<Self>, String> {
        Self::parse_in(root, asset_dirs())
    }

    pub(crate) fn parse_in(root: &Json, dirs: Vec<PathBuf>) -> Result<Option<Self>, String> {
        let Some(block) = root.get("routing") else {
            return Ok(None);
        };
        if matches!(block, Json::Null) {
            return Ok(None);
        }
        let pairs = object(block, "routing")?;
        let mut strategy = DomainStrategy::AsIs;
        let mut raw_rules = None;
        let mut raw_balancers = None;
        let mut assets = Assets::new(dirs);
        for (key, value) in pairs {
            match key.as_str() {
                "domainStrategy" => {
                    if matches!(value, Json::Null) {
                        continue;
                    }
                    let named = value
                        .as_str()
                        .ok_or_else(|| "routing domainStrategy is not a string".to_owned())?;
                    strategy = match named.to_ascii_lowercase().as_str() {
                        "" | "asis" => DomainStrategy::AsIs,
                        "ipifnonmatch" => DomainStrategy::IpIfNonMatch,
                        "ipondemand" => DomainStrategy::IpOnDemand,
                        _ => {
                            return Err(format!(
                                "routing domainStrategy `{named}` is not AsIs, IpIfNonMatch or IpOnDemand"
                            ))
                        }
                    };
                }
                "rules" => {
                    raw_rules = Some(value);
                }
                "balancers" => {
                    raw_balancers = Some(value);
                }
                "script" => {
                    if value.as_str().is_some_and(|script| !script.is_empty()) {
                        return Err("routing script is not carried".into());
                    }
                }
                other => return Err(format!("routing field `{other}` is not carried")),
            }
        }
        let mut balancers = Vec::new();
        if let Some(value) = raw_balancers {
            if !matches!(value, Json::Null) {
                let items = value
                    .as_arr()
                    .ok_or_else(|| "routing balancers is not an array".to_owned())?;
                let mut tags = HashSet::new();
                for (at, item) in items.iter().enumerate() {
                    let balancer = Balancer::parse(item, at)?;
                    if !tags.insert(balancer.tag.clone()) {
                        return Err(format!("duplicate balancer tag `{}`", balancer.tag));
                    }
                    balancers.push(balancer);
                }
            }
        }
        let mut rules = Vec::new();
        if let Some(value) = raw_rules {
            if !matches!(value, Json::Null) {
                let items = value
                    .as_arr()
                    .ok_or_else(|| "routing rules is not an array".to_owned())?;
                let mut tags = HashSet::new();
                for item in items {
                    let rule = Rule::parse(item, &mut assets)?;
                    if let Some(tag) = &rule.tag {
                        if !tags.insert(tag.clone()) {
                            return Err(format!("duplicate ruleTag `{tag}`"));
                        }
                    }
                    rules.push(rule);
                }
            }
        }
        for rule in &rules {
            if rule.balancer && !balancers.iter().any(|balancer| balancer.tag == rule.target) {
                return Err(format!("balancer `{}` not found", rule.target));
            }
        }
        let has_domains = rules.iter().any(|rule| rule.domains.is_some());
        Ok(Some(Self {
            strategy,
            rules,
            balancers,
            has_domains,
        }))
    }

    /// The targets rules name and whether each names a balancer, for the registry that has to
    /// build every outbound and every balancer's candidates.
    pub(crate) fn targets(&self) -> impl Iterator<Item = RouteTarget<'_>> {
        self.rules.iter().map(|rule| {
            if rule.balancer {
                RouteTarget::Balancer(rule.target.as_str())
            } else {
                RouteTarget::Outbound(rule.target.as_str())
            }
        })
    }

    pub(crate) fn balancers(&self) -> impl Iterator<Item = &Balancer> {
        self.balancers.iter()
    }

    pub(crate) fn balancer(&self, tag: &str) -> Option<&Balancer> {
        self.balancers.iter().find(|balancer| balancer.tag == tag)
    }

    /// The first matching rule's target; `None` leaves the caller's default in place.
    #[cfg(test)]
    pub(crate) fn route(&self, flow: &Flow) -> Option<&str> {
        self.route_target(flow).map(RouteTarget::tag)
    }

    pub(crate) fn route_target(&self, flow: &Flow) -> Option<RouteTarget<'_>> {
        self.route_target_with(flow, &resolve_ips)
    }

    #[cfg(test)]
    fn route_with(&self, flow: &Flow, resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>) -> Option<&str> {
        self.route_target_with(flow, resolve).map(RouteTarget::tag)
    }

    fn route_target_with(
        &self,
        flow: &Flow,
        resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>,
    ) -> Option<RouteTarget<'_>> {
        let lower = OnceCell::new();
        let names = flow.domain.map(|raw| Names {
            raw,
            needs_lower: self.has_domains && raw.bytes().any(|byte| byte.is_ascii_uppercase()),
            lower: &lower,
        });
        match self.strategy {
            DomainStrategy::AsIs => {
                let mut ips = Ips::never();
                self.first_match(flow, names, &mut ips).map(rule_target)
            }
            DomainStrategy::IpOnDemand => {
                let mut ips = Ips::lazy(resolve);
                self.first_match(flow, names, &mut ips).map(rule_target)
            }
            DomainStrategy::IpIfNonMatch => self
                .first_match_if_non_match(flow, names, resolve)
                .map(rule_target),
        }
    }

    fn first_match<'a>(
        &'a self,
        flow: &Flow,
        names: Option<Names<'_>>,
        ips: &mut Ips<'_>,
    ) -> Option<&'a Rule> {
        self.rules
            .iter()
            .find(|rule| rule.matches(flow, names, ips))
    }

    /// `IpIfNonMatch` only resolves when a rule whose other selectors already hold still has an
    /// address set to test, and the second pass visits only those rules: a rule that failed on a
    /// port, a name or a source cannot be turned by an address it never names.
    fn first_match_if_non_match<'a>(
        &'a self,
        flow: &Flow,
        names: Option<Names<'_>>,
        resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>,
    ) -> Option<&'a Rule> {
        let mut pending = [0u64; 4];
        let mut spilled = false;
        for (at, rule) in self.rules.iter().enumerate() {
            if !rule.matches_without_ip(flow, names) {
                continue;
            }
            if let Some(ip) = flow.ip {
                if rule.ip_matches_addr(ip) {
                    return Some(rule);
                }
            } else if rule.ips.is_none() {
                return Some(rule);
            } else if at < pending.len() * 64 {
                pending[at / 64] |= 1 << (at % 64);
            } else {
                spilled = true;
            }
        }
        if !spilled && pending.iter().all(|word| *word == 0) {
            return None;
        }
        let addrs = resolve(flow.domain?, flow.port.unwrap_or(0));
        if addrs.is_empty() {
            return None;
        }
        for at in 0..self.rules.len().min(pending.len() * 64) {
            if pending[at / 64] & (1 << (at % 64)) != 0 && self.rules[at].ip_matches_any(&addrs) {
                return Some(&self.rules[at]);
            }
        }
        if spilled {
            return self.rules[pending.len() * 64..].iter().find(|rule| {
                rule.ips.is_some()
                    && rule.matches_without_ip(flow, names)
                    && rule.ip_matches_any(&addrs)
            });
        }
        None
    }

    /// The one tag a SOCKS association may use when every datagram reaches it; `None` when a
    /// per-destination rule could split the association, which the caller serves one lane per
    /// datagram's chosen tag rather than guessing.
    pub(crate) fn udp_tag<'a>(
        &'a self,
        inbound: Option<&str>,
        default: Option<&'a str>,
    ) -> Result<Option<&'a str>, ()> {
        let mut decided: Option<&str> = None;
        for rule in &self.rules {
            if !rule.reachable(inbound, Network::Udp) || !rule.local_os_matches() {
                continue;
            }
            if rule.balancer {
                return Err(());
            }
            if !agree(&mut decided, &rule.target) {
                return Err(());
            }
            if rule.association_stable() {
                return Ok(Some(rule.target.as_str()));
            }
        }
        match (decided, default) {
            (None, _) => Ok(None),
            (Some(tag), Some(default)) if tag == default => Ok(None),
            _ => Err(()),
        }
    }

    /// Proves a server inbound's fixed direct dial is what the rules would pick anyway. A rule that
    /// could match and points elsewhere refuses the start, because this tree serves that inbound direct.
    pub(crate) fn server_routes(
        &self,
        inbound: Option<&str>,
        default_direct: bool,
        direct: impl Fn(&str, bool) -> bool,
    ) -> Result<(), String> {
        for rule in &self.rules {
            if !rule.reachable(inbound, Network::Tcp) || !rule.local_os_matches() {
                continue;
            }
            if !direct(&rule.target, rule.balancer) {
                return Err(format!(
                    "a rule for inbound {} targets `{}`, which the server inbound serves direct",
                    inbound.unwrap_or("<untagged>"),
                    rule.target
                ));
            }
            if rule.server_always() {
                return Ok(());
            }
        }
        if default_direct {
            Ok(())
        } else {
            Err(format!(
                "inbound {} falls to a default outbound the server inbound cannot dial direct",
                inbound.unwrap_or("<untagged>")
            ))
        }
    }

    /// The first selector a `tun` flow cannot answer, if a rule that could reach it names one.
    pub(crate) fn source_refusal(&self, inbound: Option<&str>) -> Option<&'static str> {
        for rule in &self.rules {
            if !rule.reachable(inbound, Network::Tcp) || !rule.local_os_matches() {
                continue;
            }
            for (present, name) in [
                (rule.source_ips.is_some(), "source"),
                (rule.source_ports.is_some(), "sourcePort"),
                (rule.local_ips.is_some(), "localIP"),
                (rule.local_ports.is_some(), "localPort"),
            ] {
                if present {
                    return Some(name);
                }
            }
        }
        None
    }

    #[cfg(test)]
    fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

fn agree<'a>(decided: &mut Option<&'a str>, tag: &'a str) -> bool {
    if let Some(seen) = decided {
        *seen == tag
    } else {
        *decided = Some(tag);
        true
    }
}

type Resolver<'a> = &'a dyn Fn(&str, u16) -> Vec<IpAddr>;

struct Ips<'a> {
    allowed: bool,
    resolve: Option<Resolver<'a>>,
    addrs: Option<Vec<IpAddr>>,
}

impl<'a> Ips<'a> {
    fn never() -> Self {
        Self {
            allowed: false,
            resolve: None,
            addrs: None,
        }
    }

    fn lazy(resolve: Resolver<'a>) -> Self {
        Self {
            allowed: true,
            resolve: Some(resolve),
            addrs: None,
        }
    }

    fn get(&mut self, flow: &Flow) -> &[IpAddr] {
        if self.addrs.is_none() && self.allowed {
            let addrs = match (self.resolve, flow.domain) {
                (Some(resolve), Some(host)) => resolve(host, flow.port.unwrap_or(0)),
                _ => Vec::new(),
            };
            self.addrs = Some(addrs);
        }
        self.addrs.as_deref().unwrap_or(&[])
    }
}

fn rule_field_target(field: &Json, name: &str) -> Result<Option<String>, String> {
    field
        .as_str()
        .map(|tag| (!tag.is_empty()).then(|| tag.to_owned()))
        .ok_or_else(|| format!("routing rule {name} is not a string"))
}

impl Rule {
    fn parse(value: &Json, assets: &mut Assets) -> Result<Self, String> {
        let pairs = object(value, "routing rule")?;
        let mut target = None;
        let mut balancing_target = None;
        let mut tag = None;
        let mut inbound_tags = None;
        let mut networks = None;
        let mut local_os = None;
        let mut ports = None;
        let mut source_ports = None;
        let mut local_ports = None;
        let mut domains = None;
        let mut domain_value = None;
        let mut domains_list = None;
        let mut ips = None;
        let mut source_ips = None;
        let mut source_value = None;
        let mut source_ip_value = None;
        let mut local_ips = None;
        for (key, field) in pairs {
            match key.as_str() {
                "outboundTag" => target = rule_field_target(field, "outboundTag")?,
                "balancerTag" => balancing_target = rule_field_target(field, "balancerTag")?,
                "type" => {
                    let named = field
                        .as_str()
                        .ok_or_else(|| "routing rule type is not a string".to_owned())?;
                    if !named.eq_ignore_ascii_case("field") {
                        return Err(format!("routing rule type `{named}` is not field"));
                    }
                }
                "ruleTag" => {
                    tag = field.as_str().filter(|tag| !tag.is_empty()).map(str::to_owned);
                }
                "domain" => domain_value = Some(field),
                "domains" => domains_list = Some(field),
                "ip" => ips = Some(ip_matcher(field, assets, "ip")?),
                "port" => ports = port_set(field, "port")?,
                "network" => networks = network_list(field)?,
                "source" => source_value = Some(field),
                "sourceIP" => source_ip_value = Some(field),
                "sourcePort" => source_ports = port_set(field, "sourcePort")?,
                "localIP" => local_ips = Some(ip_matcher(field, assets, "localIP")?),
                "localPort" => local_ports = port_set(field, "localPort")?,
                "inboundTag" => inbound_tags = string_list(field, "inboundTag")?,
                "localOS" => local_os = string_list(field, "localOS")?,
                "protocol" | "attrs" | "user" | "vlessRoute" | "process" | "webhook" => {
                    return Err(format!(
                        "routing rule selector `{key}` needs the engine sniffer, users or a webhook this tree does not carry"
                    ))
                }
                other => return Err(format!("routing rule field `{other}` is not carried")),
            }
        }
        let balancing = target.is_none() && balancing_target.is_some();
        let target = target
            .or(balancing_target)
            .ok_or_else(|| "routing rule names neither outboundTag nor balancerTag".to_owned())?;
        let domain_json = domains_list.or(domain_value);
        if let Some(field) = domain_json {
            domains = Some(domain_matcher(field, assets)?);
        }
        let source_json = source_ip_value.or(source_value);
        if let Some(field) = source_json {
            source_ips = Some(ip_matcher(field, assets, "sourceIP")?);
        }
        let rule = Self {
            target,
            balancer: balancing,
            tag,
            inbound_tags,
            networks,
            local_os,
            ports,
            source_ports,
            local_ports,
            domains,
            ips,
            source_ips,
            local_ips,
        };
        if !rule.has_selector() {
            return Err("routing rule has no effective fields".into());
        }
        Ok(rule)
    }

    fn has_selector(&self) -> bool {
        self.inbound_tags.is_some()
            || self.networks.is_some()
            || self.local_os.is_some()
            || self.ports.is_some()
            || self.source_ports.is_some()
            || self.local_ports.is_some()
            || self.domains.is_some()
            || self.ips.is_some()
            || self.source_ips.is_some()
            || self.local_ips.is_some()
    }

    fn association_stable(&self) -> bool {
        !self.balancer
            && self.ports.is_none()
            && self.source_ports.is_none()
            && self.local_ports.is_none()
            && self.domains.is_none()
            && self.ips.is_none()
            && self.source_ips.is_none()
            && self.local_ips.is_none()
    }

    fn server_always(&self) -> bool {
        !self.balancer
            && self.inbound_tags.is_some()
            && self.networks.is_none()
            && self.local_os.is_none()
            && self.association_stable()
    }

    fn local_os_matches(&self) -> bool {
        let current = local_os();
        self.local_os
            .as_ref()
            .is_none_or(|list| list.iter().any(|os| os.eq_ignore_ascii_case(current)))
    }

    fn reachable(&self, inbound: Option<&str>, network: Network) -> bool {
        if let Some(tags) = &self.inbound_tags {
            let Some(tag) = inbound else {
                return false;
            };
            if !tags.iter().any(|named| named == tag) {
                return false;
            }
        }
        self.networks
            .as_ref()
            .is_none_or(|list| list.contains(&network))
    }

    fn matches(&self, flow: &Flow, names: Option<Names<'_>>, ips: &mut Ips<'_>) -> bool {
        self.matches_without_ip(flow, names) && self.ip_matches(flow, ips)
    }

    /// Every selector but the destination address, in the order a decision reads them. The address
    /// is last so a selector that already failed does not spend a resolver call under `IPOnDemand`.
    fn matches_without_ip(&self, flow: &Flow, names: Option<Names<'_>>) -> bool {
        if let Some(networks) = &self.networks {
            if !networks.contains(&flow.network) {
                return false;
            }
        }
        if let Some(tags) = &self.inbound_tags {
            let Some(tag) = flow.inbound_tag else {
                return false;
            };
            if !tags.iter().any(|named| named == tag) {
                return false;
            }
        }
        if !self.local_os_matches() {
            return false;
        }
        if let Some(ports) = &self.ports {
            if !flow.port.is_some_and(|port| ports.contains(port)) {
                return false;
            }
        }
        if let Some(ports) = &self.source_ports {
            if !flow
                .source
                .is_some_and(|source| ports.contains(source.port()))
            {
                return false;
            }
        }
        if let Some(ports) = &self.local_ports {
            if !flow.local.is_some_and(|local| ports.contains(local.port())) {
                return false;
            }
        }
        if let Some(domains) = &self.domains {
            let Some(names) = names else {
                return false;
            };
            if !domains.matches(names.raw, names.lower()) {
                return false;
            }
        }
        if let Some(matcher) = &self.source_ips {
            if !flow
                .source
                .is_some_and(|source| matcher.matches(source.ip()))
            {
                return false;
            }
        }
        if let Some(matcher) = &self.local_ips {
            if !flow.local.is_some_and(|local| matcher.matches(local.ip())) {
                return false;
            }
        }
        true
    }

    fn ip_matches(&self, flow: &Flow, ips: &mut Ips<'_>) -> bool {
        let Some(matcher) = &self.ips else {
            return true;
        };
        match flow.ip {
            Some(ip) => matcher.matches(ip),
            None => ips.get(flow).iter().any(|ip| matcher.matches(*ip)),
        }
    }

    fn ip_matches_addr(&self, ip: IpAddr) -> bool {
        self.ips.as_ref().is_none_or(|matcher| matcher.matches(ip))
    }

    fn ip_matches_any(&self, addrs: &[IpAddr]) -> bool {
        self.ips
            .as_ref()
            .is_none_or(|matcher| addrs.iter().any(|ip| matcher.matches(*ip)))
    }
}

#[derive(Debug)]
pub(crate) struct DomainMatcher {
    full: DomainSet,
    suffix: DomainSet,
    substr: Vec<Arc<str>>,
    ac: Option<aho_corasick::AhoCorasick>,
    regex: Vec<regex::Regex>,
}

/// Full and suffix names as an open-addressed table keyed by a suffix hash. Hashing one byte at a
/// time from the right means the hash of every parent domain falls out of a single pass over the
/// name, so a match never allocates a label or hashes the same bytes twice. The string is compared
/// on a hash hit, never trusting the hash alone.
#[derive(Debug, Default)]
struct DomainSet {
    entries: Vec<(u64, Arc<str>)>,
    slots: Vec<u32>,
    mask: usize,
}

/// The hash of a name, folded from its last byte to its first. Two names that share a suffix share
/// a prefix of these states, which is what makes the parent lookups fall out of one pass.
fn suffix_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0u64;
    for &byte in bytes.iter().rev() {
        hash = hash
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(u64::from(byte));
    }
    hash
}

fn hash_slot(hash: u64) -> u64 {
    let mut mixed = hash ^ (hash >> 33);
    mixed = mixed.wrapping_mul(0xff51_afd7_ed55_8ccd);
    mixed ^ (mixed >> 33)
}

impl DomainSet {
    fn insert(&mut self, value: Arc<str>) {
        self.entries.push((suffix_hash(value.as_bytes()), value));
    }

    fn finish(&mut self) {
        self.entries.sort_unstable_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.as_ref().cmp(right.1.as_ref()))
        });
        self.entries
            .dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        let mut capacity = 8;
        while capacity < self.entries.len().saturating_mul(2) {
            capacity <<= 1;
        }
        self.mask = capacity - 1;
        self.slots = vec![0; capacity];
        for (at, &(hash, _)) in self.entries.iter().enumerate() {
            let mut slot = hash_slot(hash) as usize & self.mask;
            while self.slots[slot] != 0 {
                slot = (slot + 1) & self.mask;
            }
            self.slots[slot] = at as u32 + 1;
        }
    }

    fn contains(&self, hash: u64, value: &str) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let mut slot = hash_slot(hash) as usize & self.mask;
        loop {
            let at = self.slots[slot];
            if at == 0 {
                return false;
            }
            let (entry_hash, entry) = &self.entries[at as usize - 1];
            if *entry_hash == hash && entry.as_ref() == value {
                return true;
            }
            slot = (slot + 1) & self.mask;
        }
    }

    #[cfg(test)]
    fn first(&self) -> Option<&Arc<str>> {
        self.entries.first().map(|(_, value)| value)
    }
}

#[cfg(test)]
std::thread_local! {
    static DOMAIN_TABLE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl DomainMatcher {
    pub(crate) fn new() -> Self {
        Self {
            full: DomainSet::default(),
            suffix: DomainSet::default(),
            substr: Vec::new(),
            ac: None,
            regex: Vec::new(),
        }
    }

    pub(crate) fn finish(&mut self) -> Result<(), String> {
        self.full.finish();
        self.suffix.finish();
        if !self.substr.is_empty() {
            self.ac = Some(
                aho_corasick::AhoCorasick::new(self.substr.iter().map(|value| value.as_bytes()))
                    .map_err(|error| format!("domain keyword matcher: {error}"))?,
            );
        }
        Ok(())
    }

    fn add(&mut self, kind: DomainKind, value: Arc<str>) {
        match kind {
            DomainKind::Substr => self.substr.push(value),
            DomainKind::Domain => self.suffix.insert(value),
            DomainKind::Full => self.full.insert(value),
            DomainKind::Regex => {
                if let Ok(regex) = regex::Regex::new(value.as_ref()) {
                    self.regex.push(regex);
                } else {
                    eprintln!("routing: ignoring an invalid geosite regex");
                }
            }
        }
    }

    pub(crate) fn matches(&self, host: &str, lower: &str) -> bool {
        #[cfg(test)]
        DOMAIN_TABLE_READS.with(|reads| reads.set(reads.get() + 1));
        let bytes = lower.as_bytes();
        let mut hash = 0u64;
        for at in (0..bytes.len()).rev() {
            if bytes[at] == b'.' && self.suffix.contains(hash, &lower[at + 1..]) {
                return true;
            }
            hash = hash
                .wrapping_mul(0x9e37_79b1_85eb_ca87)
                .wrapping_add(u64::from(bytes[at]));
        }
        if self.suffix.contains(hash, lower) || self.full.contains(hash, lower) {
            return true;
        }
        if self.ac.as_ref().is_some_and(|ac| ac.is_match(lower)) {
            return true;
        }
        self.regex.iter().any(|regex| regex.is_match(host))
    }
}

#[derive(Debug, Clone, Copy)]
enum DomainKind {
    Substr,
    Regex,
    Domain,
    Full,
}

#[derive(Debug)]
struct IpMatcher {
    sets: Vec<(RangeSet, bool)>,
}

impl IpMatcher {
    fn matches(&self, ip: IpAddr) -> bool {
        self.sets
            .iter()
            .any(|(set, reverse)| set.matches(ip, *reverse))
    }
}

#[derive(Debug, Default)]
struct RangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl RangeSet {
    fn add(&mut self, ip: IpAddr, prefix: u32) -> Result<(), String> {
        match ip {
            IpAddr::V4(ip) => {
                if prefix > 32 {
                    return Err(format!("CIDR prefix {prefix} exceeds 32"));
                }
                let host = u32::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let start = host & mask;
                self.v4.push((start, start | !mask));
            }
            IpAddr::V6(ip) => {
                if prefix > 128 {
                    return Err(format!("CIDR prefix {prefix} exceeds 128"));
                }
                let host = u128::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let start = host & mask;
                self.v6.push((start, start | !mask));
            }
        }
        Ok(())
    }

    fn finish(&mut self) {
        self.v4.sort_unstable();
        self.v4 = merge(&self.v4);
        self.v6.sort_unstable();
        self.v6 = merge(&self.v6);
    }

    fn matches(&self, ip: IpAddr, reverse: bool) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                if self.v4.is_empty() {
                    return false;
                }
                contains(&self.v4, u32::from(ip)) != reverse
            }
            IpAddr::V6(ip) => {
                if self.v6.is_empty() {
                    return false;
                }
                contains(&self.v6, u128::from(ip)) != reverse
            }
        }
    }
}

fn merge<T>(ranges: &[(T, T)]) -> Vec<(T, T)>
where
    T: Copy + Ord + std::ops::Add<Output = T> + From<u8>,
{
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges {
        match out.last_mut() {
            Some((_, last_end)) if start <= *last_end + T::from(1) => {
                *last_end = (*last_end).max(end);
            }
            _ => out.push((start, end)),
        }
    }
    out
}

fn contains<T: Copy + Ord>(ranges: &[(T, T)], value: T) -> bool {
    let at = ranges.partition_point(|&(_, end)| end < value);
    ranges.get(at).is_some_and(|&(start, _)| start <= value)
}

#[derive(Debug, Default)]
struct PortSet {
    ranges: Vec<(u16, u16)>,
}

impl PortSet {
    fn finish(&mut self) {
        self.ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::with_capacity(self.ranges.len());
        for &(start, end) in &self.ranges {
            match merged.last_mut() {
                Some((_, last_end)) if start <= last_end.saturating_add(1) => {
                    *last_end = (*last_end).max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        self.ranges = merged;
    }

    fn contains(&self, port: u16) -> bool {
        let at = self.ranges.partition_point(|&(_, end)| end < port);
        self.ranges.get(at).is_some_and(|&(start, _)| start <= port)
    }
}

fn object<'a>(value: &'a Json, what: &str) -> Result<&'a [(String, Json)], String> {
    match value {
        Json::Obj(pairs) => Ok(pairs),
        _ => Err(format!("{what} is not an object")),
    }
}

fn string_list(value: &Json, field: &str) -> Result<Option<Vec<String>>, String> {
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
                    .ok_or_else(|| format!("routing {field} has a value that is not a string"))?
                    .to_owned(),
            );
        }
        out
    } else {
        return Err(format!("routing {field} is not a string or array"));
    };
    Ok((!items.is_empty()).then_some(items))
}

fn network_list(value: &Json) -> Result<Option<Vec<Network>>, String> {
    let Some(items) = string_list(value, "network")? else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(
            Network::parse(&item)
                .ok_or_else(|| format!("routing network `{item}` is not tcp or udp"))?,
        );
    }
    Ok(Some(out))
}

fn port_set(value: &Json, field: &str) -> Result<Option<PortSet>, String> {
    if matches!(value, Json::Null) {
        return Ok(None);
    }
    let mut set = PortSet::default();
    if let Some(number) = value.as_u32() {
        let port =
            u16::try_from(number).map_err(|_| format!("routing {field} {number} exceeds 65535"))?;
        set.ranges.push((port, port));
    } else if let Some(text) = value.as_str() {
        for piece in text.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            if piece.starts_with("env:") {
                return Err(format!("routing {field} `env:` is not carried"));
            }
            let (from, to) = match piece.split_once('-') {
                Some((from, to)) => (from, to),
                None => (piece, piece),
            };
            let from = parse_port(from, field)?;
            let to = parse_port(to, field)?;
            if from > to {
                return Err(format!("routing {field} range `{piece}` counts down"));
            }
            set.ranges.push((from, to));
        }
    } else {
        return Err(format!("routing {field} is not a number or string"));
    }
    set.finish();
    Ok(Some(set))
}

fn parse_port(text: &str, field: &str) -> Result<u16, String> {
    let number = text
        .parse::<u32>()
        .map_err(|_| format!("routing {field} `{text}` is not a port"))?;
    u16::try_from(number).map_err(|_| format!("routing {field} {number} exceeds 65535"))
}

fn local_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn domain_matcher(value: &Json, assets: &mut Assets) -> Result<DomainMatcher, String> {
    let Some(items) = string_list(value, "domain")? else {
        return Err("routing domain is null".into());
    };
    let mut matcher = DomainMatcher::new();
    for item in items {
        add_domain(&mut matcher, &item, assets)?;
    }
    matcher.finish()?;
    Ok(matcher)
}

/// A lowercased name, allocated once when it carries uppercase and borrowed into an `Arc` otherwise.
fn lower_arc(text: &str) -> Arc<str> {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Arc::from(text.to_ascii_lowercase())
    } else {
        Arc::from(text)
    }
}

pub(crate) fn add_domain(
    matcher: &mut DomainMatcher,
    value: &str,
    assets: &mut Assets,
) -> Result<(), String> {
    if value.starts_with('!') {
        return Err(format!(
            "domain rule `{value}`: domains have no reverse form"
        ));
    }
    if let Some(rest) = value.strip_prefix("geosite:") {
        return add_geosite(matcher, "geosite.dat", rest, assets);
    }
    for prefix in ["ext:", "ext-domain:", "ext-site:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let (file, code) = rest
                .split_once(':')
                .ok_or_else(|| format!("domain rule `{value}`: expected file:code"))?;
            return add_geosite(matcher, file, code, assets);
        }
    }
    if let Some(rest) = value.strip_prefix("regexp:") {
        if rest.is_empty() {
            return Err("domain rule `regexp:` names an empty pattern".into());
        }
        let regex =
            regex::Regex::new(rest).map_err(|error| format!("domain rule `{value}`: {error}"))?;
        matcher.regex.push(regex);
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("domain:") {
        if rest.is_empty() {
            return Err(format!("domain rule `{value}` is empty"));
        }
        matcher.suffix.insert(lower_arc(rest));
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("full:") {
        if rest.is_empty() {
            return Err(format!("domain rule `{value}` is empty"));
        }
        matcher.full.insert(lower_arc(rest));
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("keyword:") {
        if rest.is_empty() {
            return Err(format!("domain rule `{value}` is empty"));
        }
        matcher.substr.push(lower_arc(rest));
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("dotless:") {
        let pattern = match rest {
            "" => "^[^.]*$".to_owned(),
            substr if !substr.contains('.') => format!("^[^.]*{substr}[^.]*$"),
            _ => {
                return Err(format!(
                    "domain rule `{value}`: the substr cannot contain a dot"
                ))
            }
        };
        let regex = regex::Regex::new(&pattern)
            .map_err(|error| format!("domain rule `{value}`: {error}"))?;
        matcher.regex.push(regex);
        return Ok(());
    }
    if value.is_empty() {
        return Err("domain rule is empty".into());
    }
    matcher.substr.push(lower_arc(value));
    Ok(())
}

fn add_geosite(
    matcher: &mut DomainMatcher,
    file: &str,
    code_with_attrs: &str,
    assets: &mut Assets,
) -> Result<(), String> {
    if file.is_empty() {
        return Err("domain rule names an empty asset file".into());
    }
    if code_with_attrs.ends_with('@') || code_with_attrs.contains("@@") {
        return Err(format!(
            "domain rule `{file}:{code_with_attrs}` has an empty attr"
        ));
    }
    let (code, attrs) = match code_with_attrs.split_once('@') {
        Some((code, attrs)) => (code, attrs),
        None => (code_with_attrs, ""),
    };
    if code.is_empty() {
        return Err(format!("domain rule `{file}:` names an empty code"));
    }
    let attrs = attrs.to_ascii_lowercase();
    for entry in assets.site(file, code, &attrs)?.iter() {
        matcher.add(entry.kind, Arc::clone(&entry.value));
    }
    Ok(())
}

fn ip_matcher(value: &Json, assets: &mut Assets, field: &str) -> Result<IpMatcher, String> {
    let Some(items) = string_list(value, field)? else {
        return Err(format!("routing {field} is null"));
    };
    let mut positive = RangeSet::default();
    let mut negative = RangeSet::default();
    for item in items {
        add_ip_rule(&mut positive, &mut negative, &item, assets)?;
    }
    positive.finish();
    negative.finish();
    let mut sets = Vec::new();
    if !positive.v4.is_empty() || !positive.v6.is_empty() {
        sets.push((positive, false));
    }
    if !negative.v4.is_empty() || !negative.v6.is_empty() {
        sets.push((negative, true));
    }
    if sets.is_empty() {
        return Err(format!("routing {field} names no address"));
    }
    Ok(IpMatcher { sets })
}

fn add_ip_rule(
    positive: &mut RangeSet,
    negative: &mut RangeSet,
    value: &str,
    assets: &mut Assets,
) -> Result<(), String> {
    let mut value = value;
    let mut reverse = false;
    while let Some(rest) = value.strip_prefix('!') {
        value = rest;
        reverse = !reverse;
    }
    if let Some(rest) = value.strip_prefix("geoip:") {
        return add_geoip(positive, negative, "geoip.dat", rest, reverse, assets);
    }
    for prefix in ["ext:", "ext-ip:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let (file, code) = rest
                .split_once(':')
                .ok_or_else(|| format!("ip rule `{value}`: expected file:code"))?;
            return add_geoip(positive, negative, file, code, reverse, assets);
        }
    }
    let (ip, prefix) = parse_cidr(value)?;
    let mut set = RangeSet::default();
    set.add(ip, prefix)?;
    let target = if reverse { negative } else { positive };
    target.v4.extend(set.v4);
    target.v6.extend(set.v6);
    Ok(())
}

fn add_geoip(
    positive: &mut RangeSet,
    negative: &mut RangeSet,
    file: &str,
    code: &str,
    reverse: bool,
    assets: &mut Assets,
) -> Result<(), String> {
    if file.is_empty() {
        return Err("ip rule names an empty asset file".into());
    }
    let mut code = code;
    let mut reverse = reverse;
    while let Some(rest) = code.strip_prefix('!') {
        code = rest;
        reverse = !reverse;
    }
    if code.is_empty() {
        return Err(format!("ip rule `{file}:` names an empty code"));
    }
    let target = if reverse { negative } else { positive };
    for (ip, prefix) in assets.ip(file, code)?.iter() {
        target.add(*ip, *prefix)?;
    }
    Ok(())
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u32), String> {
    let (ip, prefix) = match value.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (value, None),
    };
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("ip rule `{value}` is not an address"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u32>()
            .map_err(|_| format!("ip rule `{value}` has a prefix that is not a number"))?,
        None => max,
    };
    if prefix > max {
        return Err(format!("ip rule `{value}` prefix exceeds {max}"));
    }
    Ok((ip, prefix))
}

#[derive(Debug)]
struct DomainEntry {
    kind: DomainKind,
    value: Arc<str>,
}

type SiteCache = HashMap<(String, String, String), Arc<Vec<DomainEntry>>>;
type IpCache = HashMap<(String, String), Arc<Vec<(IpAddr, u32)>>>;

/// A container read into an anonymous mapping rather than the allocator's large zone. `geoip.dat`
/// is many megabytes on a real install, and a freed `Vec` that size can stay resident in the
/// process; unmapping returns the pages to the kernel as soon as startup is done.
#[cfg(unix)]
struct AssetBytes {
    ptr: *mut u8,
    len: usize,
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
const MAP_ANON: libc::c_int = libc::MAP_ANONYMOUS;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const MAP_ANON: libc::c_int = libc::MAP_ANON;

#[cfg(unix)]
impl AssetBytes {
    fn read(path: &Path) -> Result<Self, String> {
        use std::io::Read as _;

        let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        let len = usize::try_from(file.metadata().map_err(|error| error.to_string())?.len())
            .map_err(|_| "asset is larger than this address space".to_owned())?;
        if len == 0 {
            return Ok(Self {
                ptr: std::ptr::null_mut(),
                len,
            });
        }
        // SAFETY: an anonymous private mapping is writable and private to this process; its descriptor is ignored.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let buffer = Self {
            ptr: ptr.cast(),
            len,
        };
        // SAFETY: the mapping is `len` writable bytes that nothing else aliases.
        let target = unsafe { std::slice::from_raw_parts_mut(buffer.ptr, len) };
        file.read_exact(target).map_err(|error| error.to_string())?;
        Ok(buffer)
    }
}

#[cfg(unix)]
impl std::ops::Deref for AssetBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: the mapping is `len` readable bytes for the life of `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[cfg(unix)]
impl Drop for AssetBytes {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: the pointer and length are the ones `mmap` returned.
            unsafe {
                libc::munmap(self.ptr.cast(), self.len);
            }
        }
    }
}

#[cfg(not(unix))]
struct AssetBytes {
    bytes: Vec<u8>,
}

#[cfg(not(unix))]
impl AssetBytes {
    fn read(path: &Path) -> Result<Self, String> {
        Ok(Self {
            bytes: std::fs::read(path).map_err(|error| error.to_string())?,
        })
    }
}

#[cfg(not(unix))]
impl std::ops::Deref for AssetBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) struct Assets {
    dirs: Vec<PathBuf>,
    files: HashMap<PathBuf, Rc<AssetBytes>>,
    sites: SiteCache,
    ips: IpCache,
}

impl Assets {
    pub(crate) fn new(dirs: Vec<PathBuf>) -> Self {
        Self {
            dirs,
            files: HashMap::new(),
            sites: HashMap::new(),
            ips: HashMap::new(),
        }
    }

    fn file(&mut self, file: &str) -> Result<Rc<AssetBytes>, String> {
        if !is_local_asset(file) {
            return Err(format!("asset `{file}` is not a local path"));
        }
        let path = self
            .dirs
            .iter()
            .map(|dir| dir.join(file))
            .find(|path| path.is_file())
            .ok_or_else(|| format!("asset `{file}` was not found under the asset directories"))?;
        if let Some(bytes) = self.files.get(&path) {
            return Ok(Rc::clone(bytes));
        }
        let bytes = AssetBytes::read(&path).map_err(|error| format!("asset `{file}`: {error}"))?;
        let bytes = Rc::new(bytes);
        self.files.insert(path, Rc::clone(&bytes));
        Ok(bytes)
    }

    fn site(
        &mut self,
        file: &str,
        code: &str,
        attrs: &str,
    ) -> Result<Arc<Vec<DomainEntry>>, String> {
        let key = (file.to_owned(), code.to_owned(), attrs.to_owned());
        if let Some(entries) = self.sites.get(&key) {
            return Ok(Arc::clone(entries));
        }
        let bytes = self.file(file)?;
        let wanted: Vec<&str> = attrs.split('@').filter(|attr| !attr.is_empty()).collect();
        let mut entries = Vec::new();
        let mut found = false;
        let mut reader = Reader::new(&bytes, "geosite.dat");
        while let Some((field, wire)) = reader.field()? {
            match (field, wire) {
                (1, 2) => {
                    let entry = reader.bytes()?;
                    if geosite_entry(entry, code, &wanted, &mut entries)? {
                        found = true;
                    }
                }
                _ => reader.skip(wire)?,
            }
        }
        if !found {
            return Err(format!("asset `{file}` has no geosite code `{code}`"));
        }
        let entries = Arc::new(entries);
        self.sites.insert(key, Arc::clone(&entries));
        Ok(entries)
    }

    fn ip(&mut self, file: &str, code: &str) -> Result<Arc<Vec<(IpAddr, u32)>>, String> {
        let key = (file.to_owned(), code.to_owned());
        if let Some(cidrs) = self.ips.get(&key) {
            return Ok(Arc::clone(cidrs));
        }
        let bytes = self.file(file)?;
        let mut cidrs = Vec::new();
        let mut found = false;
        let mut reader = Reader::new(&bytes, "geoip.dat");
        while let Some((field, wire)) = reader.field()? {
            match (field, wire) {
                (1, 2) => {
                    let entry = reader.bytes()?;
                    if geoip_entry(entry, code, &mut cidrs)? {
                        found = true;
                    }
                }
                _ => reader.skip(wire)?,
            }
        }
        if !found {
            return Err(format!("asset `{file}` has no geoip code `{code}`"));
        }
        let cidrs = Arc::new(cidrs);
        self.ips.insert(key, Arc::clone(&cidrs));
        Ok(cidrs)
    }
}

fn is_local_asset(file: &str) -> bool {
    if file.is_empty() || file == "." {
        return false;
    }
    Path::new(file)
        .components()
        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

pub(crate) fn asset_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    match std::env::var_os("xray.location.asset")
        .or_else(|| std::env::var_os("XRAY_LOCATION_ASSET"))
    {
        Some(dir) => dirs.push(PathBuf::from(dir)),
        None => {
            if let Some(parent) = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf))
            {
                dirs.push(parent);
            }
        }
    }
    for fallback in [
        "/usr/local/share/xray/",
        "/usr/share/xray/",
        "/opt/share/xray/",
    ] {
        dirs.push(PathBuf::from(fallback));
    }
    dirs
}

fn geosite_entry(
    bytes: &[u8],
    code: &str,
    wanted: &[&str],
    entries: &mut Vec<DomainEntry>,
) -> Result<bool, String> {
    let mut reader = Reader::new(bytes, "geodata.GeoSite");
    let start = entries.len();
    let mut known = false;
    let mut matched = false;
    let mut deferred = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                matched = String::from_utf8_lossy(reader.bytes()?).eq_ignore_ascii_case(code);
                known = true;
            }
            (2, 2) => {
                let raw = reader.bytes()?;
                if !known {
                    deferred.push(raw);
                } else if matched {
                    if let Some(entry) = domain_entry(raw, wanted)? {
                        entries.push(entry);
                    }
                }
            }
            _ => reader.skip(wire)?,
        }
    }
    if matched {
        for raw in deferred {
            if let Some(entry) = domain_entry(raw, wanted)? {
                entries.push(entry);
            }
        }
    } else {
        entries.truncate(start);
    }
    Ok(matched)
}

fn domain_entry(bytes: &[u8], wanted: &[&str]) -> Result<Option<DomainEntry>, String> {
    let mut reader = Reader::new(bytes, "geodata.Domain");
    let mut kind = DomainKind::Substr;
    let mut value = None;
    let mut attrs = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                kind = match reader.varint()? {
                    0 => DomainKind::Substr,
                    1 => DomainKind::Regex,
                    2 => DomainKind::Domain,
                    3 => DomainKind::Full,
                    _ => return Ok(None),
                };
            }
            (2, 2) => {
                let Ok(text) = std::str::from_utf8(reader.bytes()?) else {
                    return Ok(None);
                };
                value = Some(text);
            }
            (3, 2) => {
                if wanted.is_empty() {
                    reader.skip(wire)?;
                } else if let Some(attr) = domain_attribute(reader.bytes()?)? {
                    attrs.push(attr);
                }
            }
            _ => reader.skip(wire)?,
        }
    }
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    if !wanted
        .iter()
        .all(|want| attrs.iter().any(|have| have.as_ref() == *want))
    {
        return Ok(None);
    }
    let value = if matches!(kind, DomainKind::Regex) {
        Arc::from(value)
    } else {
        lower_arc(value)
    };
    Ok(Some(DomainEntry { kind, value }))
}

fn domain_attribute(bytes: &[u8]) -> Result<Option<Cow<'_, str>>, String> {
    let mut reader = Reader::new(bytes, "geodata.Domain.Attribute");
    let mut key = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let bytes = reader.bytes()?;
                key = Some(String::from_utf8_lossy(bytes));
            }
            (2 | 3, 0) => {
                reader.varint()?;
            }
            _ => reader.skip(wire)?,
        }
    }
    Ok(key)
}

fn geoip_entry(bytes: &[u8], code: &str, cidrs: &mut Vec<(IpAddr, u32)>) -> Result<bool, String> {
    let mut reader = Reader::new(bytes, "geodata.GeoIP");
    let start = cidrs.len();
    let mut known = false;
    let mut matched = false;
    let mut deferred = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                matched = String::from_utf8_lossy(reader.bytes()?).eq_ignore_ascii_case(code);
                known = true;
            }
            (2, 2) => {
                let raw = reader.bytes()?;
                if !known {
                    deferred.push(raw);
                } else if matched {
                    if let Some(cidr) = geoip_cidr(raw)? {
                        cidrs.push(cidr);
                    }
                }
            }
            _ => reader.skip(wire)?,
        }
    }
    if matched {
        for raw in deferred {
            if let Some(cidr) = geoip_cidr(raw)? {
                cidrs.push(cidr);
            }
        }
    } else {
        cidrs.truncate(start);
    }
    Ok(matched)
}

fn geoip_cidr(bytes: &[u8]) -> Result<Option<(IpAddr, u32)>, String> {
    let mut reader = Reader::new(bytes, "geodata.CIDR");
    let mut ip = None;
    let mut prefix = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                ip = match reader.bytes()? {
                    octets if octets.len() == 4 => Some(IpAddr::from(
                        <[u8; 4]>::try_from(octets).map_err(|_| "geodata.CIDR: bad IPv4")?,
                    )),
                    octets if octets.len() == 16 => Some(IpAddr::from(
                        <[u8; 16]>::try_from(octets).map_err(|_| "geodata.CIDR: bad IPv6")?,
                    )),
                    _ => None,
                };
            }
            (2, 0) => prefix = u32::try_from(reader.varint()?).unwrap_or(u32::MAX),
            _ => reader.skip(wire)?,
        }
    }
    match ip {
        Some(ip) if prefix <= if ip.is_ipv4() { 32 } else { 128 } => Ok(Some((ip, prefix))),
        _ => Ok(None),
    }
}

fn resolve_ips(host: &str, port: u16) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(pairs: Vec<(&str, Json)>) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    fn text(value: &str) -> Json {
        Json::Str(value.to_owned())
    }

    fn array(items: Vec<Json>) -> Json {
        Json::Arr(items)
    }

    fn number(value: u32) -> Json {
        Json::Num(f64::from(value))
    }

    fn rule(target: &str, selectors: Vec<(&str, Json)>) -> Json {
        let mut pairs = vec![("outboundTag", text(target))];
        pairs.extend(selectors);
        object(pairs)
    }

    fn routing(rules: Vec<Json>) -> Json {
        object(vec![("rules", array(rules))])
    }

    fn dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ferrox-router-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn bytes_field(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = varint(field << 3 | 2);
        out.extend(varint(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = varint(field << 3);
        out.extend(varint(value));
        out
    }

    fn domain(kind: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut fields = vec![varint_field(1, kind), bytes_field(2, value.as_bytes())];
        for attr in attrs {
            fields.push(bytes_field(3, &bytes_field(1, attr.as_bytes())));
        }
        fields.concat()
    }

    fn geosite(code: &str, domains: Vec<Vec<u8>>) -> Vec<u8> {
        let mut entry = vec![bytes_field(1, code.as_bytes())];
        entry.extend(domains.into_iter().map(|domain| bytes_field(2, &domain)));
        bytes_field(1, &entry.concat())
    }

    fn geoip(code: &str, cidrs: &[(IpAddr, u32)]) -> Vec<u8> {
        let mut entry = vec![bytes_field(1, code.as_bytes())];
        for (ip, prefix) in cidrs {
            let raw = match ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let cidr = [bytes_field(1, &raw), varint_field(2, u64::from(*prefix))].concat();
            entry.push(bytes_field(2, &cidr));
        }
        bytes_field(1, &entry.concat())
    }

    fn geoip_code(path: &Path, code: &str, cidrs: &[(IpAddr, u32)]) {
        std::fs::write(path, geoip(code, cidrs)).expect("writes geoip");
    }

    #[test]
    fn a_rejected_entry_does_not_leave_its_domains_behind() {
        let entry = [
            bytes_field(1, b"TEST"),
            bytes_field(2, &domain(2, "leaked.test", &[])),
            bytes_field(1, b"OTHER"),
        ]
        .concat();
        let mut entries = Vec::new();
        assert!(!geosite_entry(&entry, "TEST", &[], &mut entries).expect("parses"));
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn a_rejected_entry_does_not_leave_its_ranges_behind() {
        let cidr = [bytes_field(1, &[192, 0, 2, 0]), varint_field(2, 24)].concat();
        let entry = [
            bytes_field(1, b"TEST"),
            bytes_field(2, &cidr),
            bytes_field(1, b"OTHER"),
        ]
        .concat();
        let mut cidrs = Vec::new();
        assert!(!geoip_entry(&entry, "TEST", &mut cidrs).expect("parses"));
        assert!(cidrs.is_empty(), "{cidrs:?}");
    }

    #[test]
    fn an_asset_container_reads_whole_including_its_last_byte() {
        let dir = dir();
        let path = dir.join("container.dat");
        let payload = [0u8, 1, 2, 255, 0, 42];
        std::fs::write(&path, payload).expect("writes");
        let bytes = AssetBytes::read(&path).expect("reads");
        assert_eq!(&*bytes, &payload);
        let empty = dir.join("empty.dat");
        std::fs::write(&empty, []).expect("writes");
        let bytes = AssetBytes::read(&empty).expect("reads");
        assert!(bytes.is_empty());
    }

    #[test]
    fn a_suffix_matches_the_name_itself_and_its_subdomains() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("domain:example.test")]))],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = |domain| Flow {
            network: Network::Tcp,
            domain: Some(domain),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(routing.route(&flow("example.test")), Some("direct"));
        assert_eq!(routing.route(&flow("www.example.test")), Some("direct"));
        assert_eq!(routing.route(&flow("notexample.test")), None);
    }

    #[test]
    fn a_rule_matches_every_selector_it_names() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![
                    ("network", text("tcp")),
                    ("port", text("80,443")),
                    ("domain", array(vec![text("domain:example.test")])),
                ],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let port = Some(443);
        let matching = Flow {
            network: Network::Tcp,
            domain: Some("www.example.test"),
            ip: None,
            port,
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(routing.route(&matching), Some("direct"));
        for changed in [
            Flow {
                network: Network::Udp,
                ..matching
            },
            Flow {
                port: Some(8080),
                ..matching
            },
            Flow {
                domain: Some("example.test.invalid"),
                ..matching
            },
        ] {
            assert_eq!(routing.route(&changed), None);
        }
    }

    #[test]
    fn the_first_matching_rule_decides() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("first", vec![("port", number(80))]),
                rule("second", vec![("port", text("80-90"))]),
                rule("third", vec![("network", text("tcp"))]),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: None,
            ip: None,
            port: Some(80),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(routing.route(&flow), Some("first"));
    }

    #[test]
    fn geosite_attributes_must_all_be_present() {
        let dir = dir();
        let domains = vec![
            domain(2, "both.test", &["a", "b"]),
            domain(2, "one.test", &["a"]),
            domain(3, "full.test", &[]),
        ];
        std::fs::write(dir.join("geosite.dat"), geosite("TEST", domains)).expect("writes");
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![(
                    "domain",
                    array(vec![text("geosite:test@a@b"), text("full:full.test")]),
                )],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = |domain| Flow {
            network: Network::Tcp,
            domain: Some(domain),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(routing.route(&flow("x.both.test")), Some("direct"));
        assert_eq!(routing.route(&flow("one.test")), None);
        assert_eq!(routing.route(&flow("full.test")), Some("direct"));
    }

    #[test]
    fn a_code_named_by_two_rules_shares_its_entries() {
        let dir = dir();
        std::fs::write(
            dir.join("geosite.dat"),
            geosite("TEST", vec![domain(3, "Shared.Test", &[])]),
        )
        .expect("writes");
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("first", vec![("domain", array(vec![text("geosite:test")]))]),
                rule(
                    "second",
                    vec![("domain", array(vec![text("geosite:test")]))],
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let rules = routing.rules();
        let first = rules[0]
            .domains
            .as_ref()
            .expect("first matcher")
            .full
            .first()
            .expect("first entry");
        let second = rules[1]
            .domains
            .as_ref()
            .expect("second matcher")
            .full
            .first()
            .expect("second entry");
        assert_eq!(&**first, "shared.test");
        assert!(
            Arc::ptr_eq(first, second),
            "the second rule copies the entry"
        );
    }

    #[test]
    fn an_unwanted_geosite_code_is_not_decoded() {
        let dir = dir();
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("geosite:test")]))],
            )]),
        )]);
        let wanted = || geosite("TEST", vec![domain(3, "wanted.test", &[])]);
        std::fs::write(dir.join("geosite.dat"), wanted()).expect("writes");
        let (_, small) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        let mut file = geosite(
            "HUGE",
            (0..256)
                .map(|at| domain(3, &format!("huge{at}.test"), &[]))
                .collect(),
        );
        file.extend(wanted());
        std::fs::write(dir.join("geosite.dat"), file).expect("writes");
        let (_, big) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        assert_eq!(
            big.allocs, small.allocs,
            "an unwanted code was decoded: {big:?} against {small:?}"
        );
    }

    #[test]
    fn an_unwanted_geoip_code_is_not_decoded() {
        let dir = dir();
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("ip", array(vec![text("geoip:test")]))],
            )]),
        )]);
        let wanted = || geoip("TEST", &[("192.0.2.0".parse().expect("ip"), 24)]);
        std::fs::write(dir.join("geoip.dat"), wanted()).expect("writes");
        let (_, small) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        let huge: Vec<(IpAddr, u32)> = (0..256)
            .map(|at| (IpAddr::from([10, 0, (at / 256) as u8, at as u8]), 32))
            .collect();
        let mut file = geoip("HUGE", &huge);
        file.extend(wanted());
        std::fs::write(dir.join("geoip.dat"), file).expect("writes");
        let (_, big) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        assert_eq!(
            big.allocs, small.allocs,
            "an unwanted code was decoded: {big:?} against {small:?}"
        );
    }

    #[test]
    fn attributes_are_not_decoded_unless_requested() {
        let dir = dir();
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("geosite:test")]))],
            )]),
        )]);
        std::fs::write(
            dir.join("geosite.dat"),
            geosite("TEST", vec![domain(3, "wanted.test", &[])]),
        )
        .expect("writes");
        let (_, plain) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        std::fs::write(
            dir.join("geosite.dat"),
            geosite("TEST", vec![domain(3, "wanted.test", &["ads"])]),
        )
        .expect("writes");
        let (_, attributed) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        assert_eq!(
            attributed.allocs, plain.allocs,
            "an unrequested attribute was decoded: {attributed:?} against {plain:?}"
        );
    }

    #[test]
    fn a_reversed_geoip_rule_matches_every_other_address() {
        let dir = dir();
        geoip_code(
            &dir.join("geoip.dat"),
            "TEST",
            &[("192.0.2.0".parse().expect("ip"), 24)],
        );
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![(
                    "ip",
                    array(vec![text("geoip:test"), text("!198.51.100.0/24")]),
                )],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = |ip: IpAddr| Flow {
            network: Network::Tcp,
            domain: None,
            ip: Some(ip),
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(
            routing.route(&flow("192.0.2.9".parse().expect("ip"))),
            Some("direct")
        );
        assert_eq!(
            routing.route(&flow("198.51.100.9".parse().expect("ip"))),
            None
        );
        // A family the negative set never names is not matched by its reverse, as in the reference.
        assert_eq!(
            routing.route(&flow("2001:db8::1".parse().expect("ip"))),
            None
        );
        assert_eq!(
            routing.route(&flow("10.0.0.1".parse().expect("ip"))),
            Some("direct")
        );
    }

    #[test]
    fn a_missing_asset_or_code_is_a_startup_error() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("geosite:CN")]))],
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("geosite.dat"), "{error}");
        let dir = dir();
        std::fs::write(dir.join("geosite.dat"), geosite("US", Vec::new())).expect("writes");
        let error = Routing::parse_in(&root, vec![dir]).expect_err("refused");
        assert!(error.contains("CN"), "{error}");
    }

    #[test]
    fn ip_if_non_match_resolves_only_after_no_rule_matched() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "rules",
                    array(vec![
                        rule(
                            "domain",
                            vec![("domain", array(vec![text("keyword:blocked")]))],
                        ),
                        rule("address", vec![("ip", array(vec![text("192.0.2.0/24")]))]),
                    ]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 1);
        let domain_match = Flow {
            domain: Some("blocked.test"),
            ..flow
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&domain_match, &|_, _| {
            lookups.set(lookups.get() + 1);
            Vec::new()
        });
        assert_eq!(tag, Some("domain"));
        assert_eq!(lookups.get(), 0);
    }

    #[test]
    fn a_candidate_is_not_re_evaluated_under_ip_if_non_match() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![
                            ("domain", array(vec![text("full:once.test")])),
                            ("ip", array(vec![text("192.0.2.0/24")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("once.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let before = DOMAIN_TABLE_READS.with(std::cell::Cell::get);
        let tag = routing.route_with(&flow, &|_, _| vec!["192.0.2.1".parse().expect("ip")]);
        assert_eq!(tag, Some("direct"));
        assert_eq!(
            DOMAIN_TABLE_READS.with(std::cell::Cell::get) - before,
            1,
            "the second pass re-read the domain table"
        );
    }

    #[test]
    fn ip_on_demand_resolves_only_when_an_ip_matcher_is_reached() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPOnDemand")),
                (
                    "rules",
                    array(vec![
                        rule("address", vec![("ip", array(vec![text("192.0.2.0/24")]))]),
                        rule("tcp", vec![("network", text("tcp"))]),
                    ]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 1);
        let literal = Flow {
            ip: Some("192.0.2.1".parse().expect("ip")),
            ..flow
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&literal, &|_, _| {
            lookups.set(lookups.get() + 1);
            Vec::new()
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 0);
    }

    #[test]
    fn unknown_fields_and_empty_rules_are_refused_by_name() {
        let root = object(vec![(
            "routing",
            object(vec![("script", text("x")), ("rules", array(Vec::new()))]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("script"), "{error}");
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("protocol", array(vec![text("http")]))],
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("protocol"), "{error}");
        let root = object(vec![(
            "routing",
            routing(vec![object(vec![("outboundTag", text("direct"))])]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("no effective fields"), "{error}");
    }

    #[test]
    fn port_and_network_values_are_read_like_the_reference() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![
                    ("port", text(" 80, 100-101 ")),
                    ("network", text("TCP,udp")),
                ],
            )]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let mut flow = Flow {
            network: Network::Udp,
            domain: None,
            ip: None,
            port: Some(100),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(parsed.route(&flow), Some("direct"));
        flow.port = Some(102);
        assert_eq!(parsed.route(&flow), None);
        let root = object(vec![(
            "routing",
            routing(vec![rule("direct", vec![("network", text("unix"))])]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("unix"), "{error}");
    }

    #[test]
    fn env_names_the_address_and_port_a_rule_reads() {
        std::env::set_var("FERROX_ROUTING_ENV_IP", "198.51.100.7");
        std::env::set_var("FERROX_ROUTING_ENV_PORT", "101-102");
        let root = crate::json::parse(
            r#"{"routing": {"rules": [{"outboundTag": "direct",
                "ip": ["env:FERROX_ROUTING_ENV_IP"], "port": "100, env:FERROX_ROUTING_ENV_PORT"}]}}"#,
        )
        .expect("parses");
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let mut flow = Flow {
            network: Network::Tcp,
            domain: None,
            ip: Some("198.51.100.7".parse().expect("ip")),
            port: Some(101),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(parsed.route(&flow), Some("direct"));
        flow.port = Some(100);
        assert_eq!(parsed.route(&flow), Some("direct"));
        flow.port = Some(103);
        assert_eq!(parsed.route(&flow), None);
        flow.port = Some(101);
        flow.ip = Some("198.51.100.8".parse().expect("ip"));
        assert_eq!(parsed.route(&flow), None);
        std::env::remove_var("FERROX_ROUTING_ENV_IP");
        std::env::remove_var("FERROX_ROUTING_ENV_PORT");
    }

    #[test]
    fn a_socks_association_that_could_split_is_not_pinned_to_one_tag() {
        let root = |rules| object(vec![("routing", routing(rules))]);
        let split = root(vec![
            rule("block", vec![("domain", array(vec![text("blocked.test")]))]),
            rule("direct", vec![("inboundTag", array(vec![text("in")]))]),
        ]);
        let routing = Routing::parse_in(&split, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.udp_tag(Some("in"), Some("direct")), Err(()));
        let shared = root(vec![
            rule(
                "direct",
                vec![("domain", array(vec![text("blocked.test")]))],
            ),
            rule("direct", vec![("inboundTag", array(vec![text("in")]))]),
        ]);
        let routing = Routing::parse_in(&shared, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(
            routing.udp_tag(Some("in"), Some("direct")),
            Ok(Some("direct"))
        );
        let unmatched = root(vec![rule(
            "direct",
            vec![("domain", array(vec![text("blocked.test")]))],
        )]);
        let routing = Routing::parse_in(&unmatched, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.udp_tag(Some("in"), Some("direct")), Ok(None));
        let default_elsewhere = root(vec![rule(
            "block",
            vec![("domain", array(vec![text("blocked.test")]))],
        )]);
        let routing = Routing::parse_in(&default_elsewhere, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.udp_tag(Some("in"), Some("direct")), Err(()));
    }

    #[test]
    fn a_server_inbound_is_refused_when_routing_could_change_its_direct_dial() {
        let direct = |tag: &str, _balancer: bool| tag == "direct";
        let root = |rules| object(vec![("routing", routing(rules))]);
        let pinned = root(vec![rule(
            "direct",
            vec![("inboundTag", array(vec![text("server")]))],
        )]);
        let routing = Routing::parse_in(&pinned, vec![dir()])
            .expect("parses")
            .expect("routing");
        routing
            .server_routes(Some("server"), false, direct)
            .expect("the tag's rule pins every flow to direct");
        let proxy = root(vec![rule("proxy", vec![("port", number(443))])]);
        let routing = Routing::parse_in(&proxy, vec![dir()])
            .expect("parses")
            .expect("routing");
        let error = routing
            .server_routes(Some("server"), true, direct)
            .expect_err("a per-flow rule can reach the server");
        assert!(error.contains("proxy"), "{error}");
        let default_proxy = root(Vec::new());
        let routing = Routing::parse_in(&default_proxy, vec![dir()])
            .expect("parses")
            .expect("routing");
        let error = routing
            .server_routes(Some("server"), false, direct)
            .expect_err("the default is not direct");
        assert!(error.contains("default"), "{error}");
    }

    #[test]
    fn a_tun_inbound_refuses_the_selectors_it_cannot_answer() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![
                    ("inboundTag", array(vec![text("tun")])),
                    ("source", array(vec![text("192.0.2.0/24")])),
                ],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.source_refusal(Some("tun")), Some("source"));
        assert_eq!(routing.source_refusal(Some("other")), None);
    }

    #[test]
    fn a_flow_without_a_domain_matcher_allocates_nothing() {
        let root = object(vec![(
            "routing",
            routing(vec![rule("direct", vec![("port", number(80))])]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, None);
        assert_eq!(counts.allocs, 0, "{counts:?}");
    }

    #[test]
    fn a_lowercase_host_matches_without_a_buffer() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("domain:example.test")]))],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("www.example.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("direct"));
        assert_eq!(counts.allocs, 0, "{counts:?}");
    }

    #[test]
    fn a_mixed_case_host_takes_one_lowercase_buffer() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("domain:example.test")]))],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("WWW.EXAMPLE.TEST"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("direct"));
        assert_eq!(counts.allocs, 1, "{counts:?}");
    }

    #[test]
    fn a_mixed_case_host_is_lowercased_once_for_the_table() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule(
                    "first",
                    vec![("domain", array(vec![text("keyword:blocked")]))],
                ),
                rule(
                    "second",
                    vec![("domain", array(vec![text("domain:example.test")]))],
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("WWW.EXAMPLE.TEST"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("second"));
        assert_eq!(counts.allocs, 1, "{counts:?}");
    }

    #[test]
    fn a_mixed_case_host_matched_before_a_domain_rule_is_not_lowered() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("first", vec![("port", number(443))]),
                rule(
                    "second",
                    vec![("domain", array(vec![text("keyword:blocked")]))],
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("WWW.EXAMPLE.TEST"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("first"));
        assert_eq!(counts.allocs, 0, "{counts:?}");
    }

    #[test]
    fn ip_if_non_match_does_not_resolve_without_an_ip_rule() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "rules",
                    array(vec![rule("udp", vec![("network", text("udp"))])]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            Vec::new()
        });
        assert_eq!(tag, None);
        assert_eq!(lookups.get(), 0);
    }

    #[test]
    fn ip_on_demand_does_not_resolve_when_a_later_selector_fails() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPOnDemand")),
                (
                    "rules",
                    array(vec![rule(
                        "address",
                        vec![
                            ("ip", array(vec![text("192.0.2.0/24")])),
                            ("sourceIP", array(vec![text("10.0.0.0/8")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, None);
        assert_eq!(lookups.get(), 0);
        let from_source = Flow {
            source: Some("10.1.2.3:4242".parse().expect("source")),
            ..flow
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&from_source, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 1);
    }

    #[test]
    fn a_balancer_rule_draws_from_the_outbound_tags_it_selects() {
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "balancers",
                    array(vec![object(vec![
                        ("tag", text("pool")),
                        ("selector", array(vec![text("lane-")])),
                        ("strategy", object(vec![("type", text("roundRobin"))])),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![object(vec![
                        ("balancerTag", text("pool")),
                        ("network", text("tcp")),
                    ])]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let balancer = routing.balancer("pool").expect("the balancer");
        assert!(balancer.selects("lane-a") && balancer.selects("lane-b"));
        assert!(!balancer.selects("direct"));
        let candidates = vec!["lane-a".to_owned(), "lane-b".to_owned()];
        assert_eq!(balancer.pick(&candidates), Some("lane-a"));
        assert_eq!(balancer.pick(&candidates), Some("lane-b"));
        assert_eq!(balancer.pick(&candidates), Some("lane-a"));
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(routing.route(&flow), Some("pool"));
    }

    #[test]
    fn a_balancer_parse_refuses_the_names_it_cannot_honour() {
        let balancer = |pairs: Vec<(&str, Json)>| {
            object(vec![(
                "routing",
                object(vec![("balancers", array(vec![object(pairs)]))]),
            )])
        };
        let error = Routing::parse_in(
            &balancer(vec![
                ("tag", text("pool")),
                ("selector", array(vec![text("lane")])),
                ("strategy", object(vec![("type", text("fancy"))])),
            ]),
            vec![dir()],
        )
        .expect_err("refused");
        assert!(error.contains("fancy"), "{error}");
        let error = Routing::parse_in(
            &balancer(vec![("tag", text("pool")), ("selector", array(Vec::new()))]),
            vec![dir()],
        )
        .expect_err("refused");
        assert!(error.contains("selector"), "{error}");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "balancers",
                    array(vec![object(vec![
                        ("tag", text("pool")),
                        ("selector", array(vec![text("lane")])),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![object(vec![
                        ("outboundTag", text("direct")),
                        ("balancerTag", text("pool")),
                        ("network", text("tcp")),
                    ])]),
                ),
            ]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(
            parsed.route_target(&flow),
            Some(RouteTarget::Outbound("direct")),
            "outboundTag wins over balancerTag, as the reference's switch does"
        );
        let root = object(vec![(
            "routing",
            object(vec![(
                "rules",
                array(vec![object(vec![
                    ("balancerTag", text("missing")),
                    ("network", text("tcp")),
                ])]),
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("missing"), "{error}");
    }

    #[test]
    fn the_rule_list_is_kept_in_file_order() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("a", vec![("port", number(1))]),
                rule("b", vec![("port", number(2))]),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let targets: Vec<&str> = routing
            .rules()
            .iter()
            .map(|rule| rule.target.as_str())
            .collect();
        assert_eq!(targets, ["a", "b"]);
    }
}
