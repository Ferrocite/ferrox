//! The `VeePN` lane: a launch that names a token, a region's list that names a pair, and the HTTPS upstream that answers `Basic` for it. The record, the head walk and the relay are the `Foxy` lane's, so an open here costs what an open costs there.

use crate::foxy::{Carrier, FoxyDial, Tunnel};
use crate::foxy_account::{self, Endpoint};
use crate::json::Json;
use ferrox_core::foxy::{edge_peer, Pass};
use ferrox_core::veepn::{self, BASIC_HEAD};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The plane's cached state: the token as the plane wants it, and one server list per region. The origins a walk reads are not here — they are fixed at boot, so they sit beside the lock rather than behind it.
#[derive(Debug, Default)]
struct Plane {
    /// The `Authorization` value with its scheme already on it, so an ask writes the header without formatting one.
    access: Option<(String, u64)>,
    /// A region's upstreams and the silence each has earned: the list a flow reads is the list the fetch built.
    lists: HashMap<String, (Arc<Servers>, u64)>,
    /// The optimal region the plane named, shared with every flow that reads it.
    region: Option<(Arc<str>, u64)>,
}

/// One region's upstreams, and one silence deadline per entry. The deadlines are atomics rather than a map behind the plane's lock because a flow reads all of them before it dials: an atomic load per entry costs the walk nothing it was not already paying, and a lock per flow would be new.
#[derive(Default)]
struct Servers {
    dials: Vec<FoxyDial>,
    silence: Vec<AtomicU64>,
}

impl std::fmt::Debug for Servers {
    /// The count and how many are silent, never an edge's name or its coded pair.
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let now = foxy_account::epoch();
        fmt.debug_struct("Servers")
            .field("upstreams", &self.dials.len())
            .field(
                "silent",
                &self
                    .silence
                    .iter()
                    .filter(|until| until.load(Ordering::Relaxed) > now)
                    .count(),
            )
            .finish_non_exhaustive()
    }
}

/// Why a flow did not open: what the log says, and the SOCKS reply the front owes the client for it. Everything the plane answers with a status is a general failure until it names the target, which is the client's own answer to carry.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) why: String,
    pub(crate) code: u8,
}

impl From<String> for Refusal {
    fn from(why: String) -> Self {
        Self { why, code: 0x01 }
    }
}

/// Why an ask did not carry, and which of the two very different answers that is. A plane that answered is speaking about this lane's own state — a pair even a fresh token cannot make good — and nothing cached will change it. A plane that never answered, because its domain was seized or the network went quiet, says nothing about the pair at all, and the list it handed out while it was reachable still carries flows.
#[derive(Debug)]
struct Miss {
    answered: bool,
    why: String,
}

impl Miss {
    /// The plane reached and answered about this device — a launch that refuses it or carries no token: a fact no held list changes, so the flows hear it.
    fn spoken(why: impl Into<String>) -> Self {
        Self {
            answered: true,
            why: why.into(),
        }
    }
}

impl From<String> for Miss {
    fn from(why: String) -> Self {
        Self {
            answered: false,
            why,
        }
    }
}

/// The outbound: the plane behind a lock, the rotation in front of it, the identity ahead of both.
#[derive(Debug, Clone)]
pub(crate) struct VeepnOut {
    plane: Arc<Mutex<Plane>>,
    /// The origins this lane may ask, never rewritten after boot.
    domains: Arc<[Endpoint]>,
    /// Where the next ask starts, so concurrent flows do not all knock on the first domain.
    cursor: Arc<AtomicUsize>,
    /// The region this lane serves, or empty when the plane is the one that names it. One allocation, handed to every flow as a reference count.
    region: Arc<str>,
    udid: String,
    zone: String,
    roots: ferrox_core::tls::Anchors,
    /// A region lists a dozen upstreams; every flow does not go to the first of them.
    picked: Arc<AtomicUsize>,
}

/// What one walk of the rotation came back with: an answer, or the plane's name for the token it carried.
enum Walked {
    Carried(foxy_account::Reply),
    Token,
}

impl VeepnOut {
    /// The lane from a region name and the origins it may ask. A domain that does not parse is a refusal, not a skip: a typo in the config should say so at boot.
    pub(crate) fn new(
        region: String,
        domains: &[String],
        udid: String,
        roots: ferrox_core::tls::Anchors,
    ) -> Result<Self, String> {
        let mut origins: Vec<Endpoint> = Vec::with_capacity(domains.len());
        for url in domains {
            let (host, port) = veepn::api_domain(url)
                .ok_or_else(|| format!("veepn: {url:?} is not an https origin with a real port"))?;
            origins.push(Endpoint {
                host: host.to_owned(),
                port,
                base: String::new(),
                address: None,
                roots: Arc::clone(&roots),
            });
        }
        if origins.is_empty() {
            return Err("veepn: the lane has no api domain to ask".to_owned());
        }
        Ok(Self {
            plane: Arc::new(Mutex::new(Plane::default())),
            domains: origins.into(),
            cursor: Arc::new(AtomicUsize::new(0)),
            region: Arc::from(region),
            udid,
            zone: zone_name(),
            roots,
            picked: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// One flow's tunnel: a listed upstream of the region and the `Foxy` lane's HTTP/1.1 record dialed at the target. The upstream, its pair and the region name are read where the cache holds them, so a flow builds no dial of its own. An upstream that declined a flow keeps the edge's silence for [`veepn::EDGE_SILENCE`] seconds, so one flow pays for a gone edge instead of every one after it. When a whole region has gone quiet the walk lifts the silence of the entry whose window ends first — a tie split by the flow's own rotation, so equal windows are probed in turn — and dials that one: a gone region costs a flow one handshake rather than its list, a recovered edge rejoins as soon as it answers, and an edge probed and declined again goes behind the others. One that refuses the pair takes the region's cache with it, so the next flow fetches fresh credentials. One that refuses the *target* takes nothing with it and stops the walk there: the answer is a fact about the host, every edge holds it, and the client is told so rather than about a general failure.
    pub(crate) fn open(&self, target: &str) -> Result<Tunnel, Refusal> {
        let region = self.region()?;
        let servers = self.servers(&region)?;
        let count = servers.dials.len();
        let now = foxy_account::epoch();
        let start = self.picked.fetch_add(1, Ordering::Relaxed);
        let mut declined: Option<String> = None;
        let mut tried = 0usize;
        for sweep in 0..2 {
            if sweep == 1 {
                let mut probe: Option<usize> = None;
                let mut soonest = u64::MAX;
                for step in 0..count {
                    let at = (start + step) % count;
                    let until = servers.silence[at].load(Ordering::Relaxed);
                    if until < soonest {
                        soonest = until;
                        probe = Some(at);
                    }
                }
                if let Some(at) = probe {
                    servers.silence[at].store(0, Ordering::Relaxed);
                }
            }
            for step in 0..count {
                let at = (start + step) % count;
                if servers.silence[at].load(Ordering::Relaxed) > now {
                    continue;
                }
                let dial = picked(&servers.dials[..], at);
                tried += 1;
                match crate::foxy::open_h1(
                    dial,
                    target,
                    BASIC_HEAD,
                    &dial.pass.token,
                    Some(veepn::FORBIDDEN_TARGET),
                ) {
                    Ok(lane) => return Ok(Tunnel::H1(lane)),
                    Err(ferrox_core::foxy::Failure::BlockedHost(status)) => {
                        return Err(Refusal {
                            why: format!("{target} is refused by the edge ({status})"),
                            code: 0x04,
                        })
                    }
                    Err(ferrox_core::foxy::Failure::Rejected(status))
                        if ferrox_core::foxy::pass_is_rejected(status) =>
                    {
                        self.forget(&region);
                        return Err(Refusal::from(format!(
                            "{region} refuses its pairs ({status}): asked again"
                        )));
                    }
                    Err(failure) => {
                        servers.silence[at]
                            .store(now.saturating_add(veepn::EDGE_SILENCE), Ordering::Relaxed);
                        declined = Some(format!("{}:{}: {failure}", dial.host, dial.port));
                    }
                }
            }
            if tried != 0 {
                break;
            }
        }
        Err(Refusal::from(declined.map_or_else(
            || format!("region {region:?} lists no upstream this lane can dial"),
            |last| format!("{region}: {tried} of {count} upstream(s) declined, last: {last}"),
        )))
    }

    /// The region the lane serves: the one configured, or the optimal one the plane names, kept for the same window as a list. Either way a flow takes a reference count, not a copy of the name, so an open builds no text of its own. A plane that cannot be reached is asked again after [`veepn::PLANE_RETRY`] seconds and the name it already gave is served meanwhile, because a seized API domain says nothing about which region carries this device.
    fn region(&self) -> Result<Arc<str>, String> {
        if !self.region.is_empty() {
            return Ok(Arc::clone(&self.region));
        }
        let now = foxy_account::epoch();
        let mut held: Option<Arc<str>> = None;
        if let Some((named, until)) = self
            .plane
            .lock()
            .ok()
            .and_then(|plane| plane.region.clone())
        {
            if until > now {
                return Ok(named);
            }
            held = Some(named);
        }
        let reply = match self.ask(veepn::OPTIMAL, &[]) {
            Ok(reply) => reply,
            Err(miss) => {
                if let (false, Some(named)) = (miss.answered, held) {
                    if let Ok(mut plane) = self.plane.lock() {
                        plane.region = Some((
                            Arc::clone(&named),
                            foxy_account::epoch().saturating_add(veepn::PLANE_RETRY),
                        ));
                    }
                    return Ok(named);
                }
                return Err(miss.why);
            }
        };
        let named: Arc<str> = Arc::from(
            json(&reply)?
                .get("region")
                .and_then(Json::as_str)
                .filter(|named| !named.is_empty())
                .ok_or("the plane named no optimal region")?,
        );
        if let Ok(mut plane) = self.plane.lock() {
            plane.region = Some((Arc::clone(&named), now.saturating_add(veepn::SERVERS_TTL)));
        }
        Ok(named)
    }

    /// A region's upstreams: one ask per 12 hours, each entry's pair coded and its dial built here rather than once per flow, and the list handed out by `Arc` so a flow shares the cached text instead of copying the whole region. A plane that cannot be reached keeps carrying the flows its own earlier answer can, and is asked again no sooner than [`veepn::PLANE_RETRY`] seconds later, so an outage costs the lane one ask per window instead of one per flow. A plane that *answers* is answered with its own words: a list of nothing usable is a fact about the region, not about the network, and never falls back on the old one.
    fn servers(&self, region: &str) -> Result<Arc<Servers>, String> {
        let now = foxy_account::epoch();
        let mut held: Option<Arc<Servers>> = None;
        if let Some((list, until)) = self
            .plane
            .lock()
            .ok()
            .and_then(|plane| plane.lists.get(region).cloned())
        {
            if until > now {
                return Ok(list);
            }
            held = Some(list);
        }
        let mut body = vec![0u8; veepn::server_list_len(region)];
        let text = veepn::server_list_into(region, &mut body)
            .map_err(|why| format!("region {region:?} cannot be written: {why}"))?;
        let found = match self.ask(veepn::SERVER_LIST, text) {
            Ok(found) => found,
            Err(miss) => {
                if let (false, Some(list)) = (miss.answered, held) {
                    if let Ok(mut plane) = self.plane.lock() {
                        plane.lists.insert(
                            region.to_owned(),
                            (
                                Arc::clone(&list),
                                foxy_account::epoch().saturating_add(veepn::PLANE_RETRY),
                            ),
                        );
                    }
                    return Ok(list);
                }
                return Err(miss.why);
            }
        };
        let list = servers_of(&found, &self.roots)?;
        if list.is_empty() {
            return Err(format!("region {region:?} answers no usable upstream"));
        }
        let silence = (0..list.len()).map(|_| AtomicU64::new(0)).collect();
        let list = Arc::new(Servers {
            dials: list,
            silence,
        });
        if let Ok(mut plane) = self.plane.lock() {
            plane.lists.insert(
                region.to_owned(),
                (Arc::clone(&list), now.saturating_add(veepn::SERVERS_TTL)),
            );
        }
        Ok(list)
    }

    /// A refused pair retires the region's cache, so the flow after this one pays a fetch instead of the same refusal.
    fn forget(&self, region: &str) {
        if let Ok(mut plane) = self.plane.lock() {
            plane.lists.remove(region);
            plane.access = None;
        }
    }

    /// The token the plane answers with, launched when the cache has run out: one ask per 7 days, and a plane that refuses what it issued gets exactly one relaunch. A launch that reaches the plane but answers about this device is a refusal the cache cannot fix, so it is marked as one; a launch that reaches nothing is a miss a held list survives.
    fn access(&self, force: bool) -> Result<String, Miss> {
        let now = foxy_account::epoch();
        if !force {
            if let Some((value, _)) = self
                .plane
                .lock()
                .ok()
                .and_then(|plane| plane.access.clone())
                .filter(|(_, until)| *until > now)
            {
                return Ok(value);
            }
        }
        let mut body = vec![0u8; veepn::launch_len(&self.udid, &self.zone)];
        let text = veepn::launch_into(&self.udid, &self.zone, &mut body)
            .map_err(|why| format!("launch body: {why}"))?;
        let Walked::Carried(reply) = self.walk(veepn::LAUNCH, text, None)? else {
            return Err(Miss::spoken("launch carries no token"));
        };
        if let Some(denied) = reply.denied() {
            return Err(Miss::spoken(format!("launch refused: {denied}")));
        }
        let document = json(&reply)?;
        let token = document
            .get("access")
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| Miss::spoken("launch answers no access token"))?;
        let value = format!("Bearer {token}");
        if let Ok(mut plane) = self.plane.lock() {
            plane.access = Some((value.clone(), now.saturating_add(veepn::TOKEN_TTL)));
        }
        Ok(value)
    }

    /// One plane ask with the token in front of it: a plane that refuses the token is the cache's problem, so it is relaunched and the same ask repeats once. Only a plane that answers again about the *pair* after that is a fact the cache cannot fix; every other miss leaves the held answer alone.
    fn ask(&self, path: &str, body: &[u8]) -> Result<foxy_account::Reply, Miss> {
        let value = self.access(false)?;
        if let Walked::Carried(reply) = self.walk(path, body, Some(&value))? {
            return Ok(reply);
        }
        let fresh = self.access(true)?;
        match self.walk(path, body, Some(&fresh))? {
            Walked::Carried(reply) => Ok(reply),
            Walked::Token => Err(Miss {
                answered: true,
                why: format!("{path} refuses a fresh token"),
            }),
        }
    }

    /// The rotation walked with the reference's backoff and its wall-clock budget: a domain that answers nothing rotates, the budget ends the walk, and a plane that refuses the token stops the walk to say so.
    fn walk(&self, path: &str, body: &[u8], access: Option<&str>) -> Result<Walked, String> {
        let started = Instant::now();
        let (domains, start) = self.rotation();
        let count = domains.len();
        let mut last = format!("{path} answered nothing");
        // The plane's asks are a body POSTed or a location GET: one of the two, decided by the body.
        let method = if body.is_empty() { "GET" } else { "POST" };
        for attempt in 0..count.min(veepn::MAX_ATTEMPTS) {
            if attempt != 0 && started.elapsed().as_secs() >= veepn::REQUEST_BUDGET {
                return Err(format!(
                    "{path} ran out the {}s budget: {last}",
                    veepn::REQUEST_BUDGET
                ));
            }
            let endpoint = &domains[(start + attempt) % count];
            let mut headers: Vec<(&str, &str)> = Vec::with_capacity(5);
            headers.push(("User-Agent", veepn::USER_AGENT));
            headers.push(("Accept", "application/json"));
            if !body.is_empty() {
                headers.push(("Content-Type", "application/json"));
            }
            headers.push(("Connection", "close"));
            if let Some(value) = access {
                headers.push(("Authorization", value));
            }
            // An origin of this lane names a host and a port and no prefix, so the path is the whole request target.
            match foxy_account::ask(endpoint, method, path, &headers, body) {
                Err(why) => last = why,
                Ok(reply) => match reply.status {
                    200..=299 => return Ok(Walked::Carried(reply)),
                    401 | 403 | 407 if access.is_some() => return Ok(Walked::Token),
                    429 | 500..=599 => last = format!("{} answers {}", endpoint.host, reply.status),
                    other => {
                        return Err(format!(
                            "{path} answers {other}: {}",
                            String::from_utf8_lossy(&reply.body)
                        ))
                    }
                },
            }
            std::thread::sleep(Duration::from_secs(
                veepn::BACKOFF[attempt.min(veepn::BACKOFF.len() - 1)],
            ));
        }
        Err(last)
    }

    /// The rotation to walk and where this flow starts in it. The origins do not change after boot, so the walk reads the lane's own list and only the cursor moves.
    fn rotation(&self) -> (&[Endpoint], usize) {
        let count = self.domains.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        (&self.domains[..], start)
    }
}

/// The body as one document: the plane answers JSON or an error page, and a broken one is named as itself.
fn json(reply: &foxy_account::Reply) -> Result<Json, String> {
    crate::json::parse(&String::from_utf8_lossy(&reply.body))
}

/// The entries a list answer carries, each one the `Foxy` dial its flow will use: an address this lane can dial, a real port, and the pair coded into the shell that carries it. An entry missing any of them is not an upstream, and the count of what was dropped is what a live run reads.
fn servers_of(
    reply: &foxy_account::Reply,
    roots: &ferrox_core::tls::Anchors,
) -> Result<Vec<FoxyDial>, String> {
    let Json::Arr(entries) = json(reply)? else {
        return Err("the server list is not an array".to_owned());
    };
    let mut list = Vec::with_capacity(entries.len());
    let mut unusable = 0usize;
    for entry in entries {
        let username = entry.get("username").and_then(Json::as_str);
        let secret = entry.get("password").and_then(Json::as_str);
        let port = entry
            .get("port")
            .and_then(Json::as_port)
            .filter(|port| *port != 0);
        // Every address the entry lists becomes a dial of its own: the list is read once per region per 12 hours, so a walk of the region gets one edge per address rather than one per entry, and an edge that has gone quiet silences only itself.
        let addresses = entry
            .get("addresses")
            .and_then(Json::as_arr)
            .map(|addresses| {
                addresses
                    .iter()
                    .filter_map(Json::as_str)
                    .filter(|address| !address.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|addresses| !addresses.is_empty());
        let (Some(username), Some(secret), Some(port), Some(addresses)) =
            (username, secret, port, addresses)
        else {
            unusable += 1;
            continue;
        };
        // The window is the length the pair codes to, so the whole of it is the credential and it becomes the dial's own text without a second copy.
        let mut window = vec![0u8; veepn::credential_len(username, secret)];
        if veepn::credential_into(username, secret, &mut window).is_err() {
            unusable += 1;
            continue;
        }
        let Ok(token) = String::from_utf8(window) else {
            unusable += 1;
            continue;
        };
        for host in &addresses {
            list.push(FoxyDial {
                host: (*host).to_owned(),
                port,
                // The plane lists an address, so the fetch reads it once and every flow after it dials that without parsing or asking the resolver; a listed name keeps `None` and is resolved when the flow opens.
                address: edge_peer(host, port),
                carrier: Carrier::H1,
                upstream: None,
                roots: Arc::clone(roots),
                pins: ferrox_core::foxy::pin::Pins::default(),
                pass: Pass {
                    // The pair is coded once per entry and its text is what each of the entry's addresses carries.
                    token: token.clone(),
                    expires_at: None,
                    quota_remaining: None,
                    quota_reset: None,
                },
            });
        }
    }
    if unusable != 0 {
        eprintln!("veepn: {unusable} listed entries carry no dialable address and pair");
    }
    Ok(list)
}

/// The upstream one flow dials: the `at`th of the region's list, wrapped, and borrowed from the list rather than rebuilt.
#[must_use]
fn picked(dials: &[FoxyDial], at: usize) -> &FoxyDial {
    &dials[at % dials.len()]
}

/// The zone the launch publishes: the `TZ` the operator set, else the name the machine's own localtime points at, else the one name that is always right.
fn zone_name() -> String {
    if let Ok(named) = std::env::var("TZ") {
        if !named.is_empty() {
            return named;
        }
    }
    #[cfg(unix)]
    if let Ok(link) = std::fs::read_link("/etc/localtime") {
        let text = link.to_string_lossy();
        if let Some((_, named)) = text.rsplit_once("zoneinfo/") {
            return named.to_owned();
        }
    }
    "UTC".to_owned()
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The id the launch publishes as `udid`: the one configured, or a version-4 drawn for this process so the plane's free pool sees one device rather than one per flow. Written a byte at a time — no formatter runs.
pub(crate) fn udid(named: &str) -> String {
    if !named.is_empty() {
        return named.to_owned();
    }
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    let mut text = String::with_capacity(36);
    for (at, byte) in raw.iter().enumerate() {
        if matches!(at, 4 | 6 | 8 | 11) {
            text.push('-');
        }
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use ferrox_core::tls::TlsProvider as _;

    use super::*;

    fn lane(domains: &[&str]) -> Result<VeepnOut, String> {
        let named: Vec<String> = domains.iter().map(|url| (*url).to_owned()).collect();
        VeepnOut::new(
            "DE".to_owned(),
            &named,
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ferrox_core::tls::Anchors::from(Vec::new()),
        )
    }

    /// A domain that does not parse refuses the lane at boot rather than leaving a rotation that dials nothing.
    #[test]
    fn a_domain_that_does_not_parse_refuses_the_lane() {
        assert!(lane(&["https://antpeak.com", "https://hibchr.com:8443"]).is_ok());
        for bad in [
            "http://antpeak.com",
            "https://a.com/path",
            "antpeak.com",
            "https://a..b.com",
        ] {
            assert!(lane(&[bad]).is_err(), "{bad} was accepted");
        }
        assert!(lane(&[]).is_err(), "a rotation of nothing serves nothing");
    }

    /// The rotation walks from a different origin each flow, every origin is walked before the list wraps, and the walk is handed the lane's own origins: the slice each flow reads starts where the field's bytes do.
    #[test]
    fn the_rotation_starts_where_the_last_one_left_off() {
        let out = lane(&[
            "https://a.example",
            "https://b.example",
            "https://c.example",
        ])
        .unwrap();
        let starts: Vec<String> = (0..7)
            .map(|_| {
                let (walked, start) = out.rotation();
                assert_eq!(
                    walked.as_ptr(),
                    out.domains[..].as_ptr(),
                    "the walk reads the origins where the lane holds them, not a copy of them"
                );
                walked[start].host.clone()
            })
            .collect();
        assert_eq!(
            starts,
            [
                "a.example",
                "b.example",
                "c.example",
                "a.example",
                "b.example",
                "c.example",
                "a.example"
            ]
        );
    }

    /// One listed upstream exactly as the fetch builds it: the edge name, the port, and the coded pair sitting in the dial's own pass.
    fn listed(host: &str, port: u16, token: &str) -> FoxyDial {
        FoxyDial {
            host: host.to_owned(),
            port,
            address: None,
            carrier: Carrier::H1,
            upstream: None,
            roots: ferrox_core::tls::Anchors::from(Vec::new()),
            pins: ferrox_core::foxy::pin::Pins::default(),
            pass: Pass {
                token: token.to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        }
    }

    /// The dial a flow uses is the one the list built: every pick, including the ones that wrap past the end, is the cached entry itself, the run the record gathers is the cached pair's own bytes.
    #[test]
    fn a_flow_dials_the_cached_entry_and_not_a_copy_of_it() {
        let out = lane(&["https://antpeak.com", "https://hibchr.com"]).expect("lane");
        let dials = vec![
            listed("192.0.2.12", 443, "MTAwMC1hYmM6czNjcjN0"),
            listed("192.0.2.13", 8443, "eQ=="),
        ];
        let silence: Vec<AtomicU64> = (0..dials.len()).map(|_| AtomicU64::new(0)).collect();
        let seeded = Arc::new(Servers { dials, silence });
        out.plane
            .lock()
            .expect("locks")
            .lists
            .insert("DE".to_owned(), (Arc::clone(&seeded), 4_000_000_000));
        let servers = out.servers("DE").expect("the cached region");
        for at in [0usize, 1, 2, 5, 9] {
            assert!(
                std::ptr::eq(
                    picked(&servers.dials[..], at),
                    &raw const seeded.dials[at % servers.dials.len()]
                ),
                "the {at}th pick is the cached entry, not a copy of it"
            );
        }
        let first = picked(&servers.dials[..], 0);
        let parts =
            ferrox_core::foxy::connect_request("example.com:443", BASIC_HEAD, &first.pass.token);
        assert_eq!(
            parts[5].as_ptr(),
            first.pass.token.as_ptr(),
            "the pair the record writes is the pair the list coded, in the list's own text"
        );
    }

    /// The region name is one allocation for every flow on both paths: a configured lane hands out its own text, and a lane the plane names hands out the text its cache holds. Two opens each hold the same allocation, so an open pays a reference count where it used to copy the name.
    #[test]
    fn the_named_region_is_shared_not_copied_per_flow() {
        let configured = lane(&["https://antpeak.com"]).expect("lane");
        let named = configured.region().expect("the configured region");
        assert!(
            Arc::ptr_eq(&named, &configured.region),
            "a configured lane reads its own text"
        );

        let mut out = lane(&["https://antpeak.com"]).expect("lane");
        out.region = Arc::from("");
        let cached: Arc<str> = Arc::from("IR");
        out.plane.lock().expect("locks").region = Some((Arc::clone(&cached), 4_000_000_000));
        let first = out.region().expect("the plane named one");
        let second = out.region().expect("and still names it");
        assert!(
            Arc::ptr_eq(&first, &second),
            "two flows read one region name"
        );
        assert!(
            Arc::ptr_eq(&first, &cached),
            "and the name is the one the plane holds, not a copy of it"
        );
    }

    /// The cached region is shared, not copied: two flows read the *same* list allocation, so a dozen entries cost a refcount bump per flow instead of the whole region cloned out of the cache.
    #[test]
    fn a_cached_list_is_shared_not_copied_per_flow() {
        let out = lane(&["https://antpeak.com"]).expect("lane");
        let silence = (0..1).map(|_| AtomicU64::new(0)).collect();
        let seeded = Arc::new(Servers {
            dials: vec![listed("192.0.2.12", 443, "MTAwMC1hYmM6czNjcjN0")],
            silence,
        });
        out.plane
            .lock()
            .expect("locks")
            .lists
            .insert("DE".to_owned(), (Arc::clone(&seeded), 4_000_000_000));
        let first = out.servers("DE").expect("the cached region");
        let second = out.servers("DE").expect("still the cached region");
        assert!(
            Arc::ptr_eq(&first, &second) && Arc::ptr_eq(&first, &seeded),
            "a flow reads the list it was cached under, not a copy of it"
        );
    }

    /// The list is read as the plane writes it: an entry without an address or a port is dropped with a count, a pair reaches the wire coded once rather than per flow, every address an entry lists becomes a dial of its own, and a listed address is read into the dial at the fetch so no flow parses or resolves it.
    #[test]
    fn a_list_answer_keeps_the_entries_this_lane_can_dial() {
        let body = r#"[{"username":"1000-abc","password":"s3cr3t","port":443,"addresses":["192.0.2.12","192.0.2.13"]},
                       {"username":"x","password":"y","port":0,"addresses":["192.0.2.4"]},
                       {"username":"x","password":"y","port":8080,"addresses":[]},
                       {"username":"x","password":"y","port":80,"addresses":[""]},
                       {"username":"x","password":"y","port":8443,"addresses":["","192.0.2.9"]},
                       {"username":"x","password":"y","port":443,"addresses":["edge.example"]}]"#;
        let reply = foxy_account::Reply {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        };
        let roots = ferrox_core::tls::Anchors::from(Vec::new());
        let list = servers_of(&reply, &roots).expect("a list");
        assert_eq!(
            list.iter()
                .map(|dial| (dial.host.as_str(), dial.port))
                .collect::<Vec<_>>(),
            [
                ("192.0.2.12", 443),
                ("192.0.2.13", 443),
                ("192.0.2.9", 8443),
                ("edge.example", 443),
            ],
            "every address of an entry with a port is kept, blank ones are not, and one entry with two addresses is two dials"
        );
        assert_eq!(
            list[0].pass.token, list[1].pass.token,
            "one entry codes its pair once and both of its addresses carry that text"
        );
        assert_eq!(
            list[0].address,
            Some("192.0.2.12:443".parse().expect("address")),
            "the fetch read the listed address, so the flow dials it as it stands"
        );
        assert_eq!(
            list[1].address,
            Some("192.0.2.13:443".parse().expect("address")),
            "and read the entry's second address as its own edge, not as the first's alias"
        );
        assert_eq!(
            list[3].address, None,
            "a listed name is left for the resolver rather than half-read here"
        );
        assert_eq!(
            list[0].carrier,
            Carrier::H1,
            "the one carrier a list entry dials"
        );
        let mut window = [0u8; 64];
        assert_eq!(
            list[0].pass.token,
            std::str::from_utf8(
                veepn::credential_into("1000-abc", "s3cr3t", &mut window).expect("window")
            )
            .unwrap(),
            "the pair is the one the upstream reads back"
        );
        assert!(
            servers_of(
                &foxy_account::Reply {
                    status: 200,
                    headers: Vec::new(),
                    body: b"{\"detail\": \"no json array here\"}".to_vec(),
                },
                &roots,
            )
            .is_err(),
            "an answer that is not a list is named, not served as an empty region"
        );
    }

    #[test]
    fn the_zone_the_launch_publishes_is_one_the_body_can_carry() {
        let named = zone_name();
        assert_ne!(named, "", "a launch always has a zone to publish");
        let mut window = vec![0u8; veepn::launch_len("udid", &named)];
        assert!(
            veepn::launch_into("udid", &named, &mut window).is_ok(),
            "{named}"
        );
    }

    /// The id the plane keys its free pool on: one per process unless the config names one, and shaped the way a v4 has to be.
    #[test]
    fn the_launch_id_is_the_one_configured_or_a_version_four() {
        assert_eq!(udid("given-id"), "given-id");
        let drawn = udid("");
        let bytes = drawn.as_bytes();
        assert_eq!(bytes.len(), 36, "{drawn}");
        assert_eq!(bytes[8], b'-', "and the hyphens sit where a uuid puts them");
        assert!(matches!(&drawn[14..15], "4"), "version four: {drawn}");
        assert!(
            matches!(&drawn[19..20], "8" | "9" | "a" | "b"),
            "variant ten: {drawn}"
        );
        assert_ne!(drawn, udid(""), "two lanes are two devices");
    }

    /// The lane's open, end to end: an upstream that reads the `Basic` pair the region's list coded, answers 200, and carries the tunnel's bytes back. This is the witness that the pair reaches the wire where a `Bearer` pass would.
    #[test]
    fn an_upstream_reads_the_pair_and_carries_the_tunnel() {
        use std::io::{Read, Write};
        let (roots, server) = crate::foxy::loopback::minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts tls");
            tls.handshake().expect("handshakes");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                tls.read_exact(&mut byte).expect("reads the request");
                head.push(byte[0]);
            }
            assert_eq!(
                String::from_utf8(head).expect("ascii"),
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic MTAwMC1hYmM6czNjcjN0\r\n\r\n",
                "the pair the list coded is the pair the upstream reads"
            );
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = tls.read(&mut buf).expect("reads the tunnel");
            assert_eq!(&buf[..read], crate::foxy::loopback::PAYLOAD);
            tls.write_all(&buf[..read]).expect("echoes");
        });
        let mut window = [0u8; 64];
        let coded = veepn::credential_into("1000-abc", "s3cr3t", &mut window).expect("window");
        let mut dial = crate::foxy::loopback::dial_for(
            roots,
            port,
            Carrier::H1,
            ferrox_core::foxy::pin::Pins::default(),
        );
        dial.pass.token = std::str::from_utf8(coded).expect("ascii").to_owned();
        let mut tunnel = crate::foxy::open_h1(
            &dial,
            "example.com:443",
            BASIC_HEAD,
            &dial.pass.token,
            Some(veepn::FORBIDDEN_TARGET),
        )
        .expect("opens");
        tunnel
            .write_all(crate::foxy::loopback::PAYLOAD)
            .expect("writes");
        tunnel.flush().expect("flushes");
        let mut got = [0u8; 64];
        let read = tunnel.read(&mut got).expect("reads back");
        assert_eq!(
            &got[..read],
            crate::foxy::loopback::PAYLOAD,
            "the tunnel carries the bytes unchanged"
        );
        edge.join().expect("joins");
    }

    /// Accept connections until the listener is gone, counting each one: an edge that is gone answers a handshake with a hang-up, and this says how many times a flow found it. An open costs a visit `EDGE_ATTEMPTS` connects, so the gates read these counters as deltas, never as absolutes.
    fn gone_edge(listener: crate::conn::Listener, hits: Arc<AtomicUsize>) {
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                hits.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
    }

    /// An edge that declined one flow is not dialled again while its silence lasts: the flow after it skips it and opens on the live edge, and clearing the deadline puts the gone one back in the walk.
    #[test]
    fn a_declined_edge_is_skipped_while_its_silence_lasts() {
        use std::io::{Read, Write};
        let (roots, server) = crate::foxy::loopback::minted(b"http/1.1");
        let gone = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let gone_port = gone.local_addr().expect("addr").port();
        let declined = Arc::new(AtomicUsize::new(0));
        gone_edge(gone, Arc::clone(&declined));

        let live = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let live_port = live.local_addr().expect("addr").port();
        let answered = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&answered);
        std::thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = live.accept().expect("accepts");
                hits.fetch_add(1, Ordering::SeqCst);
                let mut tls =
                    ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                        .expect("accepts tls");
                tls.handshake().expect("handshakes");
                let text = head(&mut tls);
                assert!(text.starts_with("CONNECT "), "{text}");
                tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .expect("answers");
                let mut sink = [0u8; 64];
                // The flow drops the tunnel without a close_notify, so an error ends the drain as surely as a zero read.
                while tls.read(&mut sink).unwrap_or(0) > 0 {}
            }
        });

        let out = lane(&["https://antpeak.com"]).expect("lane");
        let dials = vec![
            crate::foxy::loopback::dial_for(
                roots.clone(),
                gone_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
            crate::foxy::loopback::dial_for(
                roots,
                live_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
        ];
        let silence: Vec<AtomicU64> = (0..dials.len()).map(|_| AtomicU64::new(0)).collect();
        let seeded = Arc::new(Servers { dials, silence });
        out.plane
            .lock()
            .expect("locks")
            .lists
            .insert("DE".to_owned(), (Arc::clone(&seeded), 4_000_000_000));

        let first = out
            .open("example.com:443")
            .expect("the live edge serves the first flow");
        drop(first);
        let paid = declined.load(Ordering::SeqCst);
        assert!(
            paid > 0,
            "the first flow reached the gone edge: {paid} dial(s), then the live one"
        );
        assert_eq!(
            answered.load(Ordering::SeqCst),
            1,
            "and one open, no retry of a leg that answered"
        );
        assert!(
            seeded.silence[0].load(Ordering::Relaxed) > foxy_account::epoch(),
            "the deadline is a window, not a flag"
        );

        out.picked.store(0, Ordering::Relaxed);
        let second = out
            .open("example.com:443")
            .expect("the second flow opens without the gone edge");
        drop(second);
        assert_eq!(
            declined.load(Ordering::SeqCst),
            paid,
            "the silent edge is skipped, not dialled again"
        );
        assert_eq!(
            answered.load(Ordering::SeqCst),
            2,
            "and the live one serves it"
        );

        seeded.silence[0].store(0, Ordering::Relaxed);
        out.picked.store(0, Ordering::Relaxed);
        let third = out
            .open("example.com:443")
            .expect("the third flow opens through both");
        drop(third);
        assert!(
            declined.load(Ordering::SeqCst) > paid,
            "an expired deadline puts the edge back in the walk"
        );
    }

    /// A region whose every edge has gone quiet is probed, not swept: the first flow pays for the whole list once, and every flow after it dials the single entry whose window ends first. That is how a dead network surfaces as an error instead of a lane that hangs, and how one gone edge stops being a tax on the region.
    #[test]
    fn a_silent_region_probes_one_edge_instead_of_its_whole_list() {
        let (roots, _server) = crate::foxy::loopback::minted(b"http/1.1");
        let one = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let one_port = one.local_addr().expect("addr").port();
        let one_hits = Arc::new(AtomicUsize::new(0));
        gone_edge(one, Arc::clone(&one_hits));
        let two = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let two_port = two.local_addr().expect("addr").port();
        let two_hits = Arc::new(AtomicUsize::new(0));
        gone_edge(two, Arc::clone(&two_hits));

        let out = lane(&["https://antpeak.com"]).expect("lane");
        let dials = vec![
            crate::foxy::loopback::dial_for(
                roots.clone(),
                one_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
            crate::foxy::loopback::dial_for(
                roots,
                two_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
        ];
        let silence: Vec<AtomicU64> = (0..dials.len()).map(|_| AtomicU64::new(0)).collect();
        let seeded = Arc::new(Servers { dials, silence });
        out.plane
            .lock()
            .expect("locks")
            .lists
            .insert("DE".to_owned(), (Arc::clone(&seeded), 4_000_000_000));

        let why = out
            .open("example.com:443")
            .err()
            .expect("no edge is there")
            .why;
        assert!(
            why.contains("2 of 2 upstream(s) declined"),
            "the first flow walks the list: {why}"
        );
        assert!(
            why.contains(&two_port.to_string()),
            "the message names the edge it last dialled: {why}"
        );
        let counts = || {
            (
                one_hits.load(Ordering::SeqCst),
                two_hits.load(Ordering::SeqCst),
            )
        };
        let swept = counts();
        assert!(
            swept.0 > 0 && swept.1 > 0,
            "a first flow finds every edge the region lists: {swept:?}"
        );

        let why = out
            .open("example.com:443")
            .err()
            .expect("the edges are still gone")
            .why;
        assert!(
            why.contains("1 of 2 upstream(s) declined"),
            "a silent region is probed, not swept: {why}"
        );
        let probed = counts();
        assert_ne!(
            probed.0 > swept.0,
            probed.1 > swept.1,
            "a probe reaches one edge, never both or neither: {swept:?} then {probed:?}"
        );

        let why = out
            .open("example.com:443")
            .err()
            .expect("still nothing to dial")
            .why;
        assert!(why.contains("1 of 2 upstream(s) declined"), "{why}");
        let next = counts();
        assert_ne!(
            next.0 > probed.0,
            next.1 > probed.1,
            "and still one edge per probe: {probed:?} then {next:?}"
        );
        assert!(
            next.0 > swept.0 && next.1 > swept.1,
            "over two probes the walk reached both entries rather than hammering one: {swept:?} then {next:?}"
        );
    }

    /// An edge that refuses the *target* answers for the whole plane: the walk stops at the first such answer, the region's list and the token behind it stay where they are, and the edge is not put in the silence a gone one earns.
    fn forbidden_edge(server: &ferrox_core::tls::TlsServerConfig) -> (u16, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let answered = Arc::clone(&hits);
        let server = server.clone();
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                answered.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) =
                    ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                else {
                    continue;
                };
                if tls.handshake().is_err() {
                    continue;
                }
                // The answer follows the request: an edge that writes before it reads resets the flow's write instead of teaching it about the target.
                let request = head(&mut tls);
                assert!(
                    request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
                    "the refusal is a fact about the host the flow asked for: {request}"
                );
                let _ = tls
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nX-Hola-Error: Forbidden Host\r\n\r\n");
                let mut sink = [0u8; 64];
                // The flow ends the leg as soon as it has read the refusal, so an error closes the drain as surely as a zero read.
                while tls.read(&mut sink).unwrap_or(0) > 0 {}
            }
        });
        (port, hits)
    }

    /// A refusal that names the host is not a refusal of the pair: one answer ends the walk, the plane is asked nothing, and the client is told the host is unreachable rather than about a general failure.
    #[test]
    fn a_refused_target_stops_the_walk_and_keeps_the_region() {
        let (roots, server) = crate::foxy::loopback::minted(b"http/1.1");
        let api = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let api_port = api.local_addr().expect("addr").port();
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        std::thread::spawn(move || {
            while let Ok((stream, _)) = api.accept() {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let out = VeepnOut::new(
            "DE".to_owned(),
            &[format!("https://127.0.0.1:{api_port}")],
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ferrox_core::tls::Anchors::from(roots.clone()),
        )
        .expect("lane");
        let (one_port, one_hits) = forbidden_edge(&server);
        let (two_port, two_hits) = forbidden_edge(&server);
        let dials = vec![
            crate::foxy::loopback::dial_for(
                roots.clone(),
                one_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
            crate::foxy::loopback::dial_for(
                roots,
                two_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
        ];
        let silence: Vec<AtomicU64> = (0..dials.len()).map(|_| AtomicU64::new(0)).collect();
        let seeded = Arc::new(Servers { dials, silence });
        out.plane
            .lock()
            .expect("locks")
            .lists
            .insert("DE".to_owned(), (Arc::clone(&seeded), 4_000_000_000));

        let refusal = out
            .open("example.com:443")
            .err()
            .expect("the edge refuses this host");
        assert_eq!(
            (refusal.code, refusal.why.as_str()),
            (
                0x04,
                "example.com:443 is refused by the edge (403)"
            ),
            "the client hears a host that cannot be reached, not a proxy that failed: edges answered {}+{}, plane asked {}",
            one_hits.load(Ordering::SeqCst),
            two_hits.load(Ordering::SeqCst),
            asked.load(Ordering::SeqCst)
        );
        assert_eq!(
            one_hits.load(Ordering::SeqCst),
            1,
            "one handshake is enough to learn a fact about the target"
        );
        assert_eq!(
            two_hits.load(Ordering::SeqCst),
            0,
            "and the walk does not pay for the edges behind it"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            0,
            "the plane is asked nothing for a refusal that is not about it"
        );

        let refusal = out.open("example.com:443").err().expect("still refused");
        assert_eq!(refusal.code, 0x04);
        assert_eq!(
            two_hits.load(Ordering::SeqCst),
            1,
            "the next flow reads the same answer from the edge its own rotation picked"
        );
        assert_eq!(
            one_hits.load(Ordering::SeqCst),
            1,
            "and reads it from one edge, not from both"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            0,
            "the region's list and the token behind it survived: a refusal that retired them would ask the plane here"
        );
        assert!(
            seeded
                .silence
                .iter()
                .all(|until| until.load(Ordering::Relaxed) <= foxy_account::epoch()),
            "an edge that named the target is not remembered as a gone one"
        );
    }

    /// An edge that carries a flow out of a held list: it reads the pair the entry coded, answers `200`, then drains until the flow ends the leg. Every accept is counted, so a gate can name which edge a flow reached and how often.
    fn carrying_edge(server: &ferrox_core::tls::TlsServerConfig) -> (u16, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let answered = Arc::clone(&hits);
        let server = server.clone();
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                answered.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) =
                    ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                else {
                    continue;
                };
                if tls.handshake().is_err() {
                    continue;
                }
                assert_eq!(
                    head(&mut tls),
                    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic the-pass\r\n\r\n",
                    "the flow that came through a held list carries the pair that list coded"
                );
                let _ = tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                let mut sink = [0u8; 64];
                while tls.read(&mut sink).unwrap_or(0) > 0 {}
            }
        });
        (port, hits)
    }

    /// A plane that cannot be reached at all is no reason to stop a flow: the region's held list still carries it with the pair that list handed out, and the ask is retried once per window rather than once per flow.
    #[test]
    fn a_plane_that_answers_nothing_carries_the_list_it_gave() {
        let (roots, server) = crate::foxy::loopback::minted(b"http/1.1");
        let api = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let api_port = api.local_addr().expect("addr").port();
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        std::thread::spawn(move || {
            while let Ok((stream, _)) = api.accept() {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let out = VeepnOut::new(
            "DE".to_owned(),
            &[format!("https://127.0.0.1:{api_port}")],
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ferrox_core::tls::Anchors::from(roots.clone()),
        )
        .expect("lane");
        let (one_port, one_hits) = carrying_edge(&server);
        let (two_port, two_hits) = carrying_edge(&server);
        let dials = vec![
            crate::foxy::loopback::dial_for(
                roots.clone(),
                one_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
            crate::foxy::loopback::dial_for(
                roots,
                two_port,
                Carrier::H1,
                ferrox_core::foxy::pin::Pins::default(),
            ),
        ];
        let silence: Vec<AtomicU64> = (0..dials.len()).map(|_| AtomicU64::new(0)).collect();
        let seeded = Arc::new(Servers { dials, silence });
        // An answer the plane gave long ago, kept on past its own window.
        out.plane
            .lock()
            .expect("locks")
            .lists
            .insert("DE".to_owned(), (Arc::clone(&seeded), 1));

        let first = out
            .open("example.com:443")
            .expect("a held list carries the flow while the plane is gone");
        drop(first);
        assert_eq!(
            one_hits.load(Ordering::SeqCst),
            1,
            "the flow went out through one edge of the held list"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "and the outage was walked once, not once per edge"
        );

        let second = out.open("example.com:443").expect("and the flow after it");
        drop(second);
        assert_eq!(
            two_hits.load(Ordering::SeqCst),
            1,
            "the next flow carries on the same held list"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "the retry window holds: a plane that cannot be reached is asked once per window, not once per flow"
        );
        assert!(
            seeded
                .silence
                .iter()
                .all(|until| until.load(Ordering::Relaxed) <= foxy_account::epoch()),
            "an edge that carried a flow out of a held list leaves no silence behind"
        );
    }

    /// The region an auto lane was *told* about outlives the plane that told it: an optimal ask that reaches nothing serves the held name, and is retried once per window rather than once per flow.
    #[test]
    fn the_region_the_plane_named_survives_its_own_outage() {
        let (roots, server) = crate::foxy::loopback::minted(b"http/1.1");
        let api = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let api_port = api.local_addr().expect("addr").port();
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        std::thread::spawn(move || {
            while let Ok((stream, _)) = api.accept() {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let out = VeepnOut::new(
            String::new(),
            &[format!("https://127.0.0.1:{api_port}")],
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ferrox_core::tls::Anchors::from(roots.clone()),
        )
        .expect("lane");
        let (edge_port, hits) = carrying_edge(&server);
        let dials = vec![crate::foxy::loopback::dial_for(
            roots,
            edge_port,
            Carrier::H1,
            ferrox_core::foxy::pin::Pins::default(),
        )];
        let silence: Vec<AtomicU64> = (0..dials.len()).map(|_| AtomicU64::new(0)).collect();
        {
            let mut plane = out.plane.lock().expect("locks");
            plane.region = Some((Arc::from("US"), 1));
            plane.lists.insert(
                "US".to_owned(),
                (
                    Arc::new(Servers { dials, silence }),
                    foxy_account::epoch().saturating_add(veepn::SERVERS_TTL),
                ),
            );
        }

        let first = out
            .open("example.com:443")
            .expect("the held name still names a region");
        drop(first);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "and the flow went out");
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "the optimal ask walked the rotation once"
        );

        let second = out.open("example.com:443").expect("and the flow after it");
        drop(second);
        assert_eq!(hits.load(Ordering::SeqCst), 2, "on the same held name");
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "with the plane asked once for both flows"
        );
    }

    /// One request head read to its delimiter: both branches of the fake plane walk it, and neither needs the octets past it.
    fn head<S: std::io::Read>(io: &mut S) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            io.read_exact(&mut byte).expect("reads the head");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ascii")
    }

    /// The control plane end to end with no network in it: a launch that answers a token, a region list that answers a pair, and the upstream that reads that pair. This is the only gate that runs `access`, `ask` and `walk` to an answer, so the `Bearer` a plane ask carries, the anonymous launch that earns it and the `Basic` a tunnel carries are all witnessed by what actually went on the wire.
    #[test]
    fn the_plane_launches_lists_and_carries_a_flow() {
        use std::io::{Read, Write};
        let (roots, server) = crate::foxy::loopback::minted_at(b"http/1.1", "127.0.0.1");
        let bound = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = bound.local_addr().expect("addr").port();
        let listener = crate::conn::Listener::Tcp(bound);
        let lists = format!(
            "[{{\"username\": \"1000-abc\", \"password\": \"s3cr3t\", \"port\": {port}, \"addresses\": [\"127.0.0.1\"]}}, {{\"username\": \"\", \"password\": \"\", \"port\": 0, \"addresses\": []}}]"
        );
        let asked = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = Arc::clone(&asked);
        let plane = std::thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().expect("accepts");
                let mut tls =
                    ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                        .expect("accepts tls");
                tls.handshake().expect("handshakes");
                let text = head(&mut tls);
                if text.starts_with("CONNECT ") {
                    assert_eq!(
                        text,
                        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic MTAwMC1hYmM6czNjcjN0\r\n\r\n",
                        "the pair the list coded is the pair the upstream reads"
                    );
                    tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .expect("answers");
                    let mut buf = [0u8; 64];
                    let read = tls.read(&mut buf).expect("reads the tunnel");
                    assert_eq!(&buf[..read], crate::foxy::loopback::PAYLOAD);
                    tls.write_all(&buf[..read]).expect("echoes");
                    continue;
                }
                let mut fields = text.split("\r\n");
                let line = fields.next().expect("a request line").to_owned();
                let path = line.split(' ').nth(1).expect("a path");
                let auth = fields
                    .clone()
                    .find_map(|field| field.strip_prefix("Authorization: "))
                    .unwrap_or_default()
                    .to_owned();
                let want: usize = fields
                    .find_map(|field| field.strip_prefix("Content-Length: "))
                    .expect("a length")
                    .parse()
                    .expect("digits");
                let mut body = vec![0u8; want];
                tls.read_exact(&mut body).expect("reads the body");
                let answer = if path == veepn::LAUNCH {
                    r#"{"access": "t0ken"}"#
                } else {
                    lists.as_str()
                };
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{answer}",
                    answer.len()
                );
                tls.write_all(reply.as_bytes()).expect("answers");
                log.lock().expect("locks").push(format!(
                    "{line} auth:{auth} body:{}",
                    String::from_utf8_lossy(&body)
                ));
            }
        });
        let lane = VeepnOut::new(
            "DE".to_owned(),
            &[format!("https://127.0.0.1:{port}")],
            "udid-1".to_owned(),
            ferrox_core::tls::Anchors::from(roots),
        )
        .expect("lane");
        let mut tunnel = lane
            .open("example.com:443")
            .expect("opens through the plane");
        tunnel
            .write_all(crate::foxy::loopback::PAYLOAD)
            .expect("writes");
        tunnel.flush().expect("flushes");
        let mut got = [0u8; 64];
        let read = tunnel.read(&mut got).expect("reads back");
        assert_eq!(&got[..read], crate::foxy::loopback::PAYLOAD);
        plane.join().expect("joins");
        let asked = asked.lock().expect("locks");
        assert_eq!(asked.len(), 2, "{asked:?}");
        assert!(
            asked[0].starts_with("POST /v3/launch/") && asked[0].contains("auth: body:"),
            "a launch is anonymous: {}",
            asked[0]
        );
        assert!(asked[0].contains("\"udid\": \"udid-1\""), "{}", asked[0]);
        assert!(
            asked[1].starts_with("POST /v3/server/list/") && asked[1].contains("auth:Bearer t0ken"),
            "the list is asked with the token the launch answered: {}",
            asked[1]
        );
        assert!(asked[1].contains("\"region\": \"DE\""), "{}", asked[1]);
    }
}
