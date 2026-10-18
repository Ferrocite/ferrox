use crate::conn::{parse_target, Connection, Listener};
use std::collections::{HashMap, HashSet};
use std::io::{IoSlice, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::budgets::{
    self, ACCOUNT_ATTEMPTS, CARRIER_DEAD_SECS, RELAY_HANDOFF_SPINS, RELAY_IDLE, RELAY_LOCK_TRIES,
    RELAY_POLL, SESSION_POLL,
};
use crate::config::{
    inbound_carrier, inbound_reality_config, inbound_tls_identity, outbound_carrier, outbound_flow,
    outbound_reality, outbound_tls, stream_security, tls_ca_roots, tls_cert_paths, trojan_key,
    uuid_bytes, vless_security_supported, Carrier,
};
use crate::json::Json;
use ferrox_core::failure::{Failure, Kind, Ladder, Rung, Stage};
use ferrox_core::tls::{Edges, RecordAlignment as _, Stream, TlsProvider as _};

pub(crate) fn print_version() {
    println!("ferrox-app {}", env!("CARGO_PKG_VERSION"));
}

pub(crate) fn print_x25519() {
    let (private, public) = x25519_pair();
    println!("PrivateKey: {private}");
    println!("Password (PublicKey): {public}");
}

/// Published edges as JSON rows on stdout: the catalogue needs the network, so it is a command, not a lane call.
pub(crate) fn print_foxy_edges(path: &str) {
    // The config is read only to name itself in errors; printing the catalogue needs no config.
    let _ = std::fs::metadata(path).map_err(|error| exit(&format!("cannot read {path}: {error}")));
    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    for edge in edges {
        println!(
            "{{\"host\":\"{}\",\"port\":{},\"city\":\"{}\",\"country\":\"{}\"}}",
            edge.host, edge.port, edge.city, edge.country
        );
    }
}

pub(crate) fn serve_json(label: &str, text: &str) -> ! {
    let root = crate::json::parse(text)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    serve_root(label, &root)
}

/// Xray's own wire form; the pinned scenario suite spawns this binary with `-config=stdin: -format=pb`.
pub(crate) fn serve_protobuf(label: &str, bytes: &[u8]) -> ! {
    let root = crate::xray_pb::to_json(bytes)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    serve_root(label, &root)
}

/// The listen address an inbound names. A `unix` field is an `AF_UNIX` path standing in for
/// `listen`+`port`; otherwise it is the TCP `host:port`. `None` is an inbound naming neither,
/// which the caller skips; a datagram carrier keeps the IP address by the same rule.
fn inbound_address(inbound: &Json) -> Option<String> {
    #[cfg(unix)]
    let unix_path = inbound
        .get("unix")
        .and_then(Json::as_str)
        .filter(|path| !path.is_empty());
    #[cfg(unix)]
    if unix_path.is_none() && inbound.get("port").and_then(Json::as_port).is_none() {
        return None;
    }
    #[cfg(not(unix))]
    if inbound.get("port").and_then(Json::as_port).is_none() {
        return None;
    }
    #[cfg(unix)]
    let address = match unix_path {
        Some(path) => format!("unix:{path}"),
        None => format!(
            "{}:{}",
            inbound
                .get("listen")
                .and_then(Json::as_str)
                .unwrap_or("127.0.0.1"),
            inbound
                .get("port")
                .and_then(Json::as_port)
                .unwrap_or_default()
        ),
    };
    #[cfg(not(unix))]
    let address = format!(
        "{}:{}",
        inbound
            .get("listen")
            .and_then(Json::as_str)
            .unwrap_or("127.0.0.1"),
        inbound
            .get("port")
            .and_then(Json::as_port)
            .unwrap_or_default()
    );
    Some(address)
}

/// The address dokodemo-door rewrites every flow to; no usable target means the inbound serves nothing.
fn dokodemo_target(inbound: &Json) -> Option<Destination> {
    let settings = inbound.get("settings")?;
    let address = settings.get("address").and_then(Json::as_str)?;
    let port = settings.get("port").and_then(Json::as_port)?;
    Some(match address.parse::<std::net::IpAddr>() {
        Ok(ip) => Destination::Address(std::net::SocketAddr::new(ip, port)),
        Err(_) => Destination::Name(address.to_owned(), port),
    })
}

/// The networks dokodemo-door is told to carry; this binary relays the tcp flow.
fn dokodemo_networks(inbound: &Json) -> Vec<&str> {
    inbound
        .get("settings")
        .and_then(|s| s.get("network"))
        .and_then(Json::as_str)
        .map(|network| network.split(',').collect())
        .unwrap_or_default()
}

fn serve_root(label: &str, root: &Json) -> ! {
    // Armed before the first inbound opens, so every flow from here reads the budget the operator named.
    crate::budgets::apply(
        &crate::config::budgets(root)
            .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}"))),
    );
    let freedom = has_protocol(root, "outbounds", "freedom");
    let outbound = find_outbound(root);
    // A loopback outbound names its inbound by tag, so it resolves only when no concrete dial won.
    let loopback = find_loopback_outbound(root);
    let outbound = match outbound {
        Some(Outbound::Freedom) | None if loopback.is_some() => {
            let tag = loopback.expect("guarded by is_some");
            Some(
                resolve_loopback(root, &tag, freedom).unwrap_or_else(|reason| {
                    exit(&format!("bad config {label}: loopback {reason}"))
                }),
            )
        }
        selected => selected,
    };
    let mut inbounds = 0;
    let dial = outbound.as_ref();
    let mut hysteria_served = false;
    if let Some(list) = root.get("inbounds").and_then(Json::as_arr) {
        for inbound in list {
            let protocol = inbound.get("protocol").and_then(Json::as_str).unwrap_or("");
            let address = if crate::tun::is_device(protocol) {
                String::new()
            } else {
                let Some(a) = inbound_address(inbound) else {
                    continue;
                };
                a
            };
            if !inbound_served(protocol) {
                refuse_inbound(protocol, label, inbound);
                continue;
            }
            match protocol {
                "vless" => {
                    if serve_vless_inbound(&address, inbound, freedom, label) {
                        inbounds += 1;
                    }
                }
                "trojan" => {
                    serve_trojan_inbound(&address, inbound, freedom);
                    inbounds += 1;
                }
                "vmess" => {
                    serve_vmess_inbound(&address, inbound, freedom);
                    inbounds += 1;
                }
                "shadowsocks" => {
                    serve_shadowsocks_inbound(&address, inbound, freedom);
                    inbounds += 1;
                }
                "hysteria" => {
                    if serve_hysteria_inbound(&address, inbound, freedom, label) {
                        inbounds += 1;
                        hysteria_served = true;
                    }
                }
                "socks" | "http" | "mixed" => {
                    let Some(out) = outbound.clone() else {
                        continue;
                    };
                    // A front with no tcp carrier has no chain to arm, so the inbound is refused rather than served unmasked.
                    if crate::config::has_tcp_mask(inbound.get("streamSettings")) {
                        eprintln!("inbound `{protocol}` in {label} asks for a finalmask tcp chain it cannot arm");
                        continue;
                    }
                    let role = match protocol {
                        "socks" => Role::Socks { out },
                        "http" => Role::Http { out },
                        _ => Role::Mixed { out },
                    };
                    thread::spawn(move || accept_loop(&address, &role));
                    inbounds += 1;
                }
                "dokodemo-door" => inbounds += serve_dokodemo(&address, inbound, dial, label),
                "tun" => {
                    let Some(out) = outbound.clone() else {
                        continue;
                    };
                    if serve_tun_inbound(inbound, &out, &address) {
                        inbounds += 1;
                    }
                }
                _ => eprintln!("unsupported inbound protocol `{protocol}` in {label}"),
            }
        }
    }
    if inbounds == 0 {
        exit(&format!("no servable inbound in {label}"));
    }
    if hysteria_served {
        // The readiness token the pinned interop harness scans the server log for; not this binary's name.
        println!("ferrox-app serving; harness readiness token: core: Xray 26.7.28 started");
    }
    loop {
        thread::park();
        report_dial_failures();
    }
}

/// A device inbound is refused with the reason the device layer computes from the config; any other unserved inbound is refused by name.
fn refuse_inbound(protocol: &str, label: &str, inbound: &Json) {
    if crate::tun::is_device(protocol) {
        let settings = inbound.get("settings");
        let field = |key| {
            settings
                .as_ref()
                .and_then(|s| s.get(key))
                .or_else(|| inbound.get(key))
        };
        let spec = crate::tun::Spec::new(
            field("name").and_then(Json::as_str),
            field("mtu").and_then(Json::as_u32).map(|m| m as usize),
        );
        eprintln!(
            "device inbound `{protocol}` in {label}: {}",
            crate::tun::refusal_reason(&spec)
        );
    } else {
        eprintln!("unsupported inbound protocol `{protocol}` in {label}: refused, not served");
    }
}

/// Served inbounds; the `tun` device inbound opens a native interface and relays TCP flows.
const SERVED_INBOUNDS: [&str; 10] = [
    "vless",
    "trojan",
    "vmess",
    "shadowsocks",
    "hysteria",
    "socks",
    "http",
    "mixed",
    "tun",
    "dokodemo-door",
];

/// Whether this protocol is an inbound this binary serves.
fn inbound_served(protocol: &str) -> bool {
    SERVED_INBOUNDS.contains(&protocol)
}

fn spawn_role(address: &str, role: Role) {
    let address = address.to_owned();
    thread::spawn(move || accept_loop(&address, &role));
}

fn serve_vless_inbound(address: &str, inbound: &Json, freedom: bool, path: &str) -> bool {
    let id = inbound_id(inbound);
    let carrier = inbound_carrier(inbound);
    let sec = stream_security(inbound);
    // QUIC arrives on UDP with its own handshake, so it never reaches the TCP accept loop.
    if matches!(carrier, Carrier::Quic) {
        return serve_vless_quic_inbound(address, inbound, &id, freedom, path);
    }
    if let Carrier::Unknown { network } = &carrier {
        eprintln!("unsupported network `{network}` in {path}: refused, not served");
        return false;
    }
    match sec {
        "tls" => serve_vless_tls_inbound(address, inbound, &id, &carrier, freedom, path),
        "reality" => serve_vless_reality_inbound(address, inbound, &id, &carrier, freedom, path),
        _ if !vless_security_supported(sec) => {
            eprintln!("unsupported vless security `{sec}` in {path}: serves raw TCP only");
            false
        }
        _ => {
            let owned = address.to_owned();
            if let Carrier::Kcp(config) = carrier {
                let serve: KcpServe = Arc::new(move |conn: &Arc<ferrox_core::kcp::Connection>| {
                    serve_vless_kcp(conn, &id, freedom);
                });
                thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
                return true;
            }
            if let Carrier::Hysteria(config) = carrier {
                let config = config.clone();
                let Some(settings) = inbound.get("streamSettings") else {
                    eprintln!("unreadable hysteria identity in {path}: serves nothing");
                    return false;
                };
                let Some((cert_path, key_path)) = tls_cert_paths(settings) else {
                    eprintln!("unreadable hysteria identity in {path}: serves nothing");
                    return false;
                };
                let (cert_path, key_path) = (cert_path.to_owned(), key_path.to_owned());
                let masq = crate::config::masquerade_from_stream(Some(settings));
                let serve: crate::hysteria::Serve = Arc::new(move |flow| {
                    serve_vless_hysteria(flow, &id, freedom);
                });
                thread::spawn(move || {
                    crate::hysteria::serve_loop(
                        &owned,
                        &[config.auth],
                        config.cc,
                        &cert_path,
                        &key_path,
                        &config.obfs_password,
                        &masq,
                        &serve,
                    );
                });
                return true;
            }
            let role = Role::Vless {
                id,
                carrier,
                freedom,
            };
            thread::spawn(move || accept_loop(&owned, &role));
            true
        }
    }
}

fn dial(target: &SocketAddr) -> Result<Connection, Failure> {
    // The seam's one dial entry; an IP target is the TCP dial with its budget unchanged, so bytes and calls are identical.
    let stream = crate::conn::connect(&crate::conn::Target::Ip(*target), budgets::dial())
        .map_err(|e| Failure::new(Stage::SocketConnected, Kind::of(&e)))?;
    no_delay(&stream);
    Ok(stream)
}

pub(crate) fn dial_or_report(target: &SocketAddr) -> Option<Connection> {
    match dial(target) {
        Ok(stream) => Some(stream),
        Err(failure) => {
            note_dial_failure(target, failure);
            None
        }
    }
}

fn note_dial_failure(target: &SocketAddr, failure: Failure) {
    if failure.worth_retrying() {
        RETRYABLE_DIALS.fetch_add(1, Ordering::Relaxed);
    } else {
        FATAL_DIALS.fetch_add(1, Ordering::Relaxed);
    }
    if let Ok(mut last) = LAST_DIAL.lock() {
        *last = Some((*target, failure));
    }
    echo_trace(&format!("dial {target} failed: {failure}"));
    eprintln!("dial {target} failed: {failure}");
}

#[cfg(test)]
pub(crate) fn last_dial_failure() -> Option<(SocketAddr, Failure)> {
    LAST_DIAL.lock().ok().and_then(|last| *last)
}

// The ladder rung a configured carrier answers, if it is on the ladder.
fn rung_of(carrier: &Carrier) -> Option<Rung> {
    match carrier {
        Carrier::Raw(_) => Some(Rung::Raw),
        Carrier::Ws { .. } => Some(Rung::Ws),
        Carrier::Xhttp { .. } => Some(Rung::Xhttp),
        Carrier::Grpc { .. } => Some(Rung::Grpc),
        Carrier::HttpUpgrade { .. } => Some(Rung::HttpUpgrade),
        _ => None,
    }
}

// The (path, early-data budget) a non-raw rung reuses from the configured carrier.
fn stream_params(carrier: &Carrier) -> Option<(&str, u32)> {
    match carrier {
        Carrier::Ws { path, ed } | Carrier::HttpUpgrade { path, ed } => Some((path, *ed)),
        Carrier::Grpc { path } | Carrier::HttpHeader { path } => Some((path, 0)),
        Carrier::Xhttp { settings, .. } => Some((settings.path.as_str(), 0)),
        _ => None,
    }
}

// The rung a dial starts at: the carrier this server was configured for, or Raw when it is off the ladder.
fn ladder_start(carrier: &Carrier) -> Rung {
    rung_of(carrier).unwrap_or(Rung::Raw)
}

static FATAL_DIALS: AtomicU64 = AtomicU64::new(0);

static RETRYABLE_DIALS: AtomicU64 = AtomicU64::new(0);
// The last dial failure, so a test that outlives its dial names the stage instead of timing out in silence.
static LAST_DIAL: std::sync::Mutex<Option<(SocketAddr, Failure)>> = std::sync::Mutex::new(None);

// Echo stage tracing behind one env flag, on stdout because the harness captures stdout per test.
static ECHO_TRACE_ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub(crate) fn echo_trace_on() -> bool {
    *ECHO_TRACE_ON.get_or_init(|| std::env::var("FERROX_ECHO_TRACE").is_ok())
}

static ECHO_T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub(crate) fn echo_trace(stage: &str) {
    if echo_trace_on() {
        let at = ECHO_T0
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis();
        println!("echo-trace: t={at} {stage}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DialFailures {
    pub fatal: u64,
    pub retryable: u64,
}

pub(crate) fn dial_failures() -> DialFailures {
    DialFailures {
        fatal: FATAL_DIALS.load(Ordering::Relaxed),
        retryable: RETRYABLE_DIALS.load(Ordering::Relaxed),
    }
}

fn report_dial_failures() {
    let failures = dial_failures();
    if failures.fatal + failures.retryable == 0 {
        return;
    }
    eprintln!(
        "dials: {} fatal, {} retryable",
        failures.fatal, failures.retryable
    );
    report_ladder_rates();
}

fn report_ladder_rates() {
    let ladder = Ladder::global();
    for rung in Rung::ALL {
        eprintln!(
            "ladder: {rung}: {} attempts, {} useful",
            ladder.attempts(rung),
            ladder.useful(rung)
        );
    }
    eprintln!(
        "ladder: {} climbs, {} descents",
        ladder.climbs(),
        ladder.descents()
    );
}

fn no_delay(stream: &Connection) {
    let _ = stream.set_nodelay(true);
}

fn exit(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

#[derive(Debug, Clone)]
enum Role {
    Vless {
        id: [u8; 16],
        carrier: Carrier,
        freedom: bool,
    },
    VlessTls {
        id: [u8; 16],
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::TlsServerConfig>,
    },
    VlessReality {
        id: [u8; 16],
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::RealityServerConfig>,
    },
    Trojan {
        key: [u8; 56],
        carrier: Carrier,
        freedom: bool,
    },
    Vmess {
        id: [u8; 16],
        carrier: Carrier,
        freedom: bool,
    },
    Shadowsocks {
        password: String,
        method: String,
        carrier: Carrier,
        freedom: bool,
    },
    Socks {
        out: Outbound,
    },
    Http {
        out: Outbound,
    },
    Mixed {
        out: Outbound,
    },
    /// dokodemo-door: a raw stream to the address its config rewrites every flow to.
    Dokodemo {
        out: Outbound,
        dest: Destination,
    },
}

impl Role {
    /// The post-TLS write chain an accepted stream of this role carries, from its tcp carrier.
    fn tcp_mask(&self) -> Option<&ferrox_core::finalmask::Chain> {
        match self {
            Role::Vless { carrier, .. }
            | Role::VlessTls { carrier, .. }
            | Role::VlessReality { carrier, .. }
            | Role::Trojan { carrier, .. }
            | Role::Vmess { carrier, .. }
            | Role::Shadowsocks { carrier, .. } => carrier.tcp_mask(),
            // A front with no tcp carrier has nowhere to arm a chain, so its inbound refuses one.
            Role::Socks { .. } | Role::Http { .. } | Role::Mixed { .. } | Role::Dokodemo { .. } => {
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Outbound {
    Vless(VlessOut),
    Trojan(TrojanOut),
    Vmess(VmessOut),
    Shadowsocks(ShadowsocksOut),
    Foxy(Box<FoxyOut>),
    Freedom,
    Http(HttpOut),
}

/// The Foxy lane: an account's pass over an edge in one pinned country, plus the split-tunnel list.
#[derive(Debug, Clone)]
struct FoxyOut {
    account: Option<std::sync::Arc<crate::foxy_account::Account>>,
    country: String,
    city: String,
    carrier: crate::foxy::Carrier,
    /// The configured upstream; dialing past it leaks, so a value that does not parse refuses the outbound.
    upstream: Option<crate::foxy::UpstreamProxy>,
    candidates: Vec<ferrox_core::foxy::Candidate>,
    stored: Option<ferrox_core::foxy::Candidate>,
    /// Set when an edge refuses the pass: later flows answer locally instead of paying that round trip again.
    unauthenticated: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Strikes and the earliest next dial: one attempt answers a 429, the rest wait out the refusal curve.
    limited_strikes: std::sync::Arc<std::sync::atomic::AtomicU32>,
    limited_until: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Silent carriers and until when: otherwise an `auto` walk repays the whole handshake budget per flow.
    carrier_dead: std::sync::Arc<std::sync::Mutex<ferrox_core::foxy::Refusals>>,
    /// Edges whose TCP tunnels kept ending soon and the ones rested for a while: an edge that answers the probe yet drops the traffic is otherwise dialed by every flow.
    edge_strikes: std::sync::Arc<std::sync::Mutex<ferrox_core::foxy::EdgeStrikes>>,
    roots: Vec<Vec<u8>>,
    pins: ferrox_core::foxy::pin::Pins,
    pass: ferrox_core::foxy::Pass,
    edge_address: Option<SocketAddr>,
    direct_ports: Vec<u16>,
    direct_suffixes: Vec<String>,
    exit_probe: Option<String>,
    /// The pinned-country edge whose real exit the pre-flight confirmed, tried before the label order; empty until one agrees.
    verified: std::sync::Arc<std::sync::Mutex<Option<ferrox_core::foxy::Candidate>>>,
    /// Set when no edge could carry a probe tunnel here: the pre-flight then stops rather than costing every flow a dead dial.
    probe_unavailable: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Until when the probes are known to answer a country other than the pin: a sweep that reached an edge and agreed with none is the answer, and re-asking it per flow buys the same refusal again.
    exit_refuted_until: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl FoxyOut {
    /// Whether this edge is already known not to answer this carrier, inside the window.
    fn carrier_unanswered(
        &self,
        edge: &ferrox_core::foxy::Candidate,
        carrier: crate::foxy::Carrier,
    ) -> bool {
        let key = carrier_key(edge, carrier);
        self.carrier_dead
            .lock()
            .is_ok_and(|cache| cache.blocked(&key, now_secs()))
    }

    /// Only silence is cached: a status means the edge answered, so it never marks a carrier dead.
    fn remember_unanswered(
        &self,
        edge: &ferrox_core::foxy::Candidate,
        carrier: crate::foxy::Carrier,
        failure: ferrox_core::foxy::Failure,
    ) {
        if !matches!(
            failure,
            ferrox_core::foxy::Failure::Io
                | ferrox_core::foxy::Failure::Stream
                | ferrox_core::foxy::Failure::Frame
        ) {
            return;
        }
        let key = carrier_key(edge, carrier);
        if let Ok(mut cache) = self.carrier_dead.lock() {
            cache.remember(&key, now_secs() + CARRIER_DEAD_SECS);
        }
    }

    /// The edge answered this carrier: the remembered silence was wrong, so it is found again at once.
    fn carrier_answered(&self, edge: &ferrox_core::foxy::Candidate, carrier: crate::foxy::Carrier) {
        let key = carrier_key(edge, carrier);
        if let Ok(mut cache) = self.carrier_dead.lock() {
            cache.clear(&key);
        }
    }

    /// The edge every carrier should try first: the pre-flight's verified exit, else the configured stored edge.
    fn preferred_edge(&self) -> Option<ferrox_core::foxy::Candidate> {
        self.verified
            .lock()
            .ok()
            .and_then(|kept| kept.clone())
            .or_else(|| self.stored.clone())
    }

    /// Whether this edge's TCP tunnels kept ending soon enough to rest it right now.
    fn edge_resting(&self, edge: &ferrox_core::foxy::Candidate) -> bool {
        self.edge_strikes
            .lock()
            .is_ok_and(|cache| cache.resting(&edge.authority(), now_secs()))
    }

    /// The dial order with rested edges left out, or the whole order when every edge rests, so a full rest cannot black-hole a flow.
    fn live_dials(
        &self,
        order: &[ferrox_core::foxy::Candidate],
    ) -> Vec<ferrox_core::foxy::Candidate> {
        let live: Vec<_> = order
            .iter()
            .filter(|edge| !self.edge_resting(edge))
            .cloned()
            .collect();
        if live.is_empty() {
            order.to_vec()
        } else {
            live
        }
    }

    /// A TCP tunnel through this edge ended after lasting this long: two quick ends in a row rest the edge, a tunnel that carried traffic frees it.
    fn note_edge_end(&self, edge: &ferrox_core::foxy::Candidate, lasted: Duration) {
        if let Ok(mut cache) = self.edge_strikes.lock() {
            cache.note_end(&edge.authority(), lasted, now_secs());
        }
    }
}

/// The key a carrier's silence is remembered under: carrier, edge, and the port it was reached on.
fn carrier_key(edge: &ferrox_core::foxy::Candidate, carrier: crate::foxy::Carrier) -> String {
    format!("{carrier:?} {}:{}", edge.host, edge.port)
}

#[derive(Debug, Clone)]
struct VlessOut {
    address: String,
    port: u16,
    id: [u8; 16],
    carrier: Carrier,
    host: String,
    mux: bool,
    quic_roots: Option<Vec<Vec<u8>>>,
    hysteria_roots: Option<Vec<Vec<u8>>>,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    flow: String,
    reality: Option<Arc<ferrox_core::tls::RealityClientConfig>>,
}

#[derive(Debug, Clone)]
struct HttpOut {
    address: String,
    port: u16,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    headers: Vec<(String, String)>,
    user: Option<String>,
    pass: Option<String>,
}

macro_rules! refused_carriers {
    () => {
        Carrier::Quic
            | Carrier::Kcp(_)
            | Carrier::Hysteria(_)
            | Carrier::Masque
            | Carrier::Xdrive
            | Carrier::Http
            | Carrier::Unknown { .. }
    };
}

#[derive(Debug, Clone)]
struct VmessOut {
    address: String,
    port: u16,
    id: [u8; 16],
    cipher: crate::vmess::Cipher,
    carrier: Carrier,
    host: String,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
}

#[derive(Debug, Clone)]
struct TrojanOut {
    address: String,
    port: u16,
    key: [u8; 56],
    carrier: Carrier,
    host: String,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
}

#[derive(Debug, Clone)]
struct ShadowsocksOut {
    address: String,
    port: u16,
    method: String,
    password: String,
    carrier: Carrier,
    host: String,
}

fn accept_loop(address: &str, role: &Role) {
    let target = parse_target(address)
        .unwrap_or_else(|error| exit(&format!("cannot resolve {address}: {error}")));
    let listener = Listener::bind(&target)
        .unwrap_or_else(|error| exit(&format!("cannot listen on {address}: {error}")));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        no_delay(&stream);
        let role = role.clone();
        thread::spawn(move || {
            // Armed once per accepted stream, as the reference wraps its listener's conn.
            let stream = stream.with_mask(role.tcp_mask());
            match role {
                Role::Vless {
                    id,
                    carrier,
                    freedom,
                } => serve_vless(stream, &id, &carrier, freedom),
                Role::VlessTls {
                    id,
                    freedom,
                    carrier,
                    server,
                } => serve_vless_tls(stream, &id, freedom, &carrier, &server),
                Role::VlessReality {
                    id,
                    freedom,
                    carrier,
                    server,
                } => serve_vless_reality(stream, &id, freedom, &carrier, &server),
                Role::Trojan {
                    key,
                    carrier,
                    freedom,
                } => match carrier {
                    Carrier::Raw(_) => serve_trojan(stream, &key, freedom),
                    Carrier::Ws { path, .. } => {
                        serve_trojan_ws(stream, &key, path.as_str(), freedom);
                    }
                    Carrier::HttpUpgrade { path, .. } => {
                        serve_trojan_httpupgrade(stream, &key, path.as_str(), freedom);
                    }
                    Carrier::Grpc { path } => {
                        serve_trojan_grpc(stream, &key, path.as_str(), freedom);
                    }
                    Carrier::Xhttp { settings, .. } => {
                        serve_trojan_xhttp(stream, &key, settings.path.as_str(), freedom);
                    }
                    Carrier::HttpHeader { path } => {
                        serve_trojan_httpheader(stream, &key, path.as_str(), freedom);
                    }
                    refused_carriers!() => {}
                },
                Role::Vmess {
                    id,
                    carrier,
                    freedom,
                } => match carrier {
                    Carrier::Raw(_) => crate::vmess::serve(stream, &id, freedom),
                    Carrier::Ws { path, .. } => {
                        crate::vmess::serve_ws(stream, path.as_str(), &id, freedom);
                    }
                    Carrier::Xhttp { settings, .. } => {
                        crate::vmess::serve_xhttp(stream, settings.path.as_str(), &id, freedom);
                    }
                    Carrier::HttpHeader { path } => {
                        crate::vmess::serve_httpheader(stream, path.as_str(), &id, freedom);
                    }
                    Carrier::HttpUpgrade { path, .. } => {
                        crate::vmess::serve_httpupgrade(stream, path.as_str(), &id, freedom);
                    }
                    Carrier::Grpc { path } => {
                        crate::vmess::serve_grpc(stream, path.as_str(), &id, freedom);
                    }
                    refused_carriers!() => {}
                },
                Role::Shadowsocks {
                    password,
                    method,
                    carrier,
                    freedom,
                } => serve_shadowsocks(stream, &password, &method, &carrier, freedom),
                Role::Socks { out } => serve_socks(stream, &out),
                Role::Http { out } => serve_http(stream, &out),
                Role::Mixed { out } => serve_mixed(stream, &out),
                Role::Dokodemo { out, dest } => {
                    serve_connect(stream, &out, &dest, Front::Socks, &[]);
                }
            }
        });
    }
}

fn serve_shadowsocks(
    stream: Connection,
    password: &str,
    method: &str,
    carrier: &Carrier,
    freedom: bool,
) {
    if ferrox_core::shadowsocks2022::Method::parse(method).is_some() {
        match carrier {
            Carrier::Raw(_) => crate::shadowsocks2022::serve(stream, password, method, freedom),
            Carrier::Ws { path, .. } => {
                crate::shadowsocks2022::serve_ws(stream, password, method, path.as_str(), freedom);
            }
            Carrier::HttpUpgrade { path, .. } => {
                crate::shadowsocks2022::serve_httpupgrade(
                    stream,
                    password,
                    method,
                    path.as_str(),
                    freedom,
                );
            }
            Carrier::Grpc { path } => {
                crate::shadowsocks2022::serve_grpc(
                    stream,
                    password,
                    method,
                    path.as_str(),
                    freedom,
                );
            }
            Carrier::Xhttp { settings, .. } => {
                crate::shadowsocks2022::serve_xhttp(
                    stream,
                    password,
                    method,
                    settings.path.as_str(),
                    freedom,
                );
            }
            Carrier::HttpHeader { path } => {
                crate::shadowsocks2022::serve_httpheader(
                    stream,
                    password,
                    method,
                    path.as_str(),
                    freedom,
                );
            }
            refused_carriers!() => {}
        }
        return;
    }
    match carrier {
        Carrier::Raw(_) => crate::shadowsocks::serve(stream, password, method, freedom),
        Carrier::Ws { path, .. } => {
            crate::shadowsocks::serve_ws(stream, password, method, path.as_str(), freedom);
        }
        Carrier::HttpUpgrade { path, .. } => {
            crate::shadowsocks::serve_httpupgrade(stream, password, method, path.as_str(), freedom);
        }
        Carrier::Grpc { path } => {
            crate::shadowsocks::serve_grpc(stream, password, method, path.as_str(), freedom);
        }
        Carrier::Xhttp { settings, .. } => {
            crate::shadowsocks::serve_xhttp(
                stream,
                password,
                method,
                settings.path.as_str(),
                freedom,
            );
        }
        Carrier::HttpHeader { path } => {
            crate::shadowsocks::serve_httpheader(stream, password, method, path.as_str(), freedom);
        }
        refused_carriers!() => {}
    }
}

fn serve_vless(stream: Connection, id: &[u8; 16], carrier: &Carrier, freedom: bool) {
    match carrier {
        Carrier::Raw(_) => serve_vless_raw(stream, id, freedom),
        Carrier::Ws { path, .. } => {
            let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
                return;
            };
            // Past the upgrade the frame layer retries timeouts itself, so bound it by wall clock and poll the socket.
            let decoded = under_handshake(&mut reader, decode_request);
            let Some((got, _flow, cmd, target)) = decoded else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if !writer.send(&[0, 0]) {
                return;
            }
            crate::proxy::relay_sink(reader, &writer, &uplink, |_| {});
        }
        Carrier::HttpUpgrade { path, .. } => {
            let Some((mut reader, mut write)) = crate::httpupgrade::accept(stream, path) else {
                return;
            };
            reader.set_poll(Some(RELAY_POLL));
            let decoded = decode_request_bounded(&mut reader);
            reader.set_poll(None);
            let Some((got, _flow, cmd, target)) = decoded else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if write.write_all(&[0, 0]).is_err() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, &uplink);
        }
        Carrier::Grpc { path } => {
            let Some((mut reader, writer)) = crate::grpc::accept(stream, path) else {
                return;
            };
            // Past the preface the reader retries timeouts itself, so the opening request is polled at the relay's grain and bounded by the handshake budget, the way the websocket arm bounds its frames.
            let decoded = under_handshake(&mut reader, decode_request);
            let Some((got, _flow, cmd, target)) = decoded else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if !writer.send(&[0, 0]) {
                return;
            }
            crate::proxy::relay_sink(reader, &writer, &uplink, crate::grpc::mark_reader_dead);
        }
        Carrier::Xhttp { settings, .. } => {
            let Ok(read) = stream.try_clone() else {
                return;
            };
            serve_xhttp_stream(read, stream, settings, id, freedom);
        }
        Carrier::HttpHeader { path } => {
            let Some((mut reader, mut write)) = crate::httpheader::accept(stream, path) else {
                return;
            };
            reader.set_poll(Some(RELAY_POLL));
            let decoded = decode_request_bounded(&mut reader);
            reader.set_poll(None);
            let Some((got, _flow, cmd, target)) = decoded else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if write.write_all(&[0, 0]).is_err() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, &uplink);
        }
        refused_carriers!() => {}
    }
}

/// Turns silence past an absolute deadline into a hard read error, so `read_exact`'s timeout-retry — right for a poll quantum that a sibling thread eventually breaks — cannot spin forever on a handshake that has no sibling yet.
pub(crate) struct HandshakeDeadline<'a> {
    pub(crate) inner: &'a mut dyn Read,
    pub(crate) until: Instant,
}

impl std::io::Read for HandshakeDeadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.until {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        self.inner.read(buf)
    }
}

/// The opening request decoded under a wall-clock budget: a peer that upgrades, connects or handshakes and then stays silent costs a thread briefly, not forever.
fn decode_request_bounded(stream: &mut dyn Read) -> Option<([u8; 16], String, u8, SocketAddr)> {
    let mut bounded = HandshakeDeadline {
        inner: stream,
        until: Instant::now() + budgets::handshake(),
    };
    decode_request(&mut bounded)
}

/// The two arms a carried reader holds for the length of one decode: the `ws` and `grpc` readers both retry a timeout forever, so a head needs the socket's poll quantum and a wall-clock end.
pub(crate) trait Carried {
    fn arm(&mut self, every: std::time::Duration, until: Instant);
    fn disarm(&mut self);
}

impl Carried for crate::grpc::GrpcReader {
    fn arm(&mut self, every: std::time::Duration, until: Instant) {
        self.set_poll(Some(every));
        self.set_handshake_budget(Some(until));
    }

    fn disarm(&mut self) {
        self.set_handshake_budget(None);
        self.set_poll(None);
    }
}

impl Carried for crate::ws::WsReader {
    fn arm(&mut self, every: std::time::Duration, until: Instant) {
        self.set_poll(Some(every));
        self.set_handshake_budget(Some(until));
    }

    fn disarm(&mut self) {
        self.set_handshake_budget(None);
        self.set_poll(None);
    }
}

/// One decode run between the arms, both put away on the way out: a carrier answers its own head and then clears its clock, so the protocol that reads through it would otherwise wait unbounded.
pub(crate) fn under_handshake<T, R: Read + Carried>(
    reader: &mut R,
    decode: impl FnOnce(&mut dyn Read) -> T,
) -> T {
    reader.arm(RELAY_POLL, Instant::now() + budgets::handshake());
    let out = decode(reader);
    reader.disarm();
    out
}

fn serve_vless_raw(mut stream: Connection, id: &[u8; 16], freedom: bool) {
    // Bound only the opening request read to a wall-clock budget, then restore the blocking relay reads behind it.
    let _ = stream.set_read_timeout(Some(budgets::handshake()));
    let decoded = decode_request_bounded(&mut stream);
    let _ = stream.set_read_timeout(None);
    let Some((got, flow, cmd, target)) = decoded else {
        return;
    };
    if got != *id || !freedom {
        return;
    }
    if cmd == 2 {
        if !flow.is_empty() {
            return;
        }
        return serve_vless_udp(stream, &target);
    }
    if cmd == 3 {
        if stream.write_all(&[0, 0]).is_err() {
            return;
        }
        return serve_vless_mux(stream);
    }
    if cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if stream.write_all(&[0, 0]).is_err() {
        return;
    }
    relay(&stream, &uplink);
}

fn mux_target_addr(target: &ferrox_core::mux::Target<'_>) -> Option<SocketAddr> {
    let port = target.port;
    match target.addr {
        ferrox_core::addr::Addr::V4(octets) => {
            Some(SocketAddr::new(std::net::IpAddr::V4(octets.into()), port))
        }
        ferrox_core::addr::Addr::V6(octets) => {
            Some(SocketAddr::new(std::net::IpAddr::V6(octets.into()), port))
        }
        ferrox_core::addr::Addr::Name(bytes) => {
            let host = std::str::from_utf8(bytes).ok()?;
            resolve_endpoint(host, port)
        }
    }
}

fn resolve_endpoint(host: &str, port: u16) -> Option<SocketAddr> {
    // The tuple asks the resolver for host and port directly: no `host:port` re-serialisation, no String, no port re-scan.
    (host, port).to_socket_addrs().ok()?.next()
}

fn mux_target_of(addr: SocketAddr) -> ferrox_core::mux::Target<'static> {
    let address = match addr.ip() {
        std::net::IpAddr::V4(ip) => ferrox_core::addr::Addr::V4(ip.octets()),
        std::net::IpAddr::V6(ip) => ferrox_core::addr::Addr::V6(ip.octets()),
    };
    ferrox_core::mux::Target {
        network: ferrox_core::mux::Network::Udp,
        port: addr.port(),
        addr: address,
    }
}

fn write_mux_frame(
    shared: &Arc<Mutex<Connection>>,
    staging: &mut Vec<u8>,
    frame: ferrox_core::mux::Outgoing<'_>,
    data: Option<&[u8]>,
) -> bool {
    // A mux payload is framed, not sealed, so it goes to the socket where it was read: one writev, no copy.
    if let Some(payload) = data {
        assert!(
            payload.len() <= ferrox_core::mux::CHUNK_MAX,
            "mux chunk longer than a length field"
        );
        let at = frame.encode_header_into(staging);
        frame.patch_payload_len(staging, at, payload.len());
        write_mux_two(shared, staging, payload)
    } else {
        resize_scratch(staging, frame.frame_len(0));
        let written = frame.encode_into(None, staging);
        staging.truncate(written);
        match shared.lock() {
            Ok(mut stream) => stream.write_all(staging).is_ok(),
            Err(_) => false,
        }
    }
}

/// One vectored write of header and read buffer: both mux directions are zero-copy, gated by pointer identity.
fn write_mux_two(shared: &Arc<Mutex<Connection>>, first: &[u8], second: &[u8]) -> bool {
    match shared.lock() {
        Ok(mut stream) => write_all_parts::<2>(&mut *stream, &[first, second]).is_ok(),
        Err(_) => false,
    }
}

fn send_mux_end(shared: &Arc<Mutex<Connection>>, staging: &mut Vec<u8>, id: u16) {
    let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
    let _ = write_mux_frame(shared, staging, end, None);
}

fn write_mux_keep(
    shared: &Arc<Mutex<Connection>>,
    staging: &mut Vec<u8>,
    id: u16,
    payload: &[u8],
) -> bool {
    let keep = ferrox_core::mux::Outgoing {
        id,
        status: ferrox_core::mux::Status::Keep,
        options: ferrox_core::mux::DATA,
        target: None,
        global_id: None,
    };
    write_mux_frame(shared, staging, keep, Some(payload))
}

type MuxTable = Arc<Mutex<HashMap<u16, Arc<Mutex<Connection>>>>>;

struct UdpMux {
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
    id: Arc<AtomicU16>,
    done: Arc<AtomicBool>,
}

type UdpTable = HashMap<u16, Arc<UdpMux>>;

type UdpGlobal = HashMap<[u8; ferrox_core::mux::GLOBAL_ID], u16>;

fn remove_mux_session(
    table: &MuxTable,
    id: u16,
    shared: &Arc<Mutex<Connection>>,
    staging: &mut Vec<u8>,
) {
    if let Ok(mut table) = table.lock() {
        table.remove(&id);
    }
    send_mux_end(shared, staging, id);
}

fn serve_vless_mux(stream: Connection) {
    let Ok(mut read) = stream.try_clone() else {
        return;
    };
    let shared = Arc::new(Mutex::new(stream));
    let table: MuxTable = Arc::new(Mutex::new(HashMap::new()));
    let mut udp: UdpTable = HashMap::new();
    let mut global: UdpGlobal = HashMap::new();
    let mut handles: Vec<std::sync::mpsc::Receiver<()>> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(READ_SLICE);
    let mut at = 0;
    let mut staging = Vec::with_capacity(8192);
    loop {
        if at >= buf.len() {
            buf.clear();
            at = 0;
        } else if at > 0 {
            buf.drain(..at);
            at = 0;
        }
        let mut progressed = false;
        loop {
            match ferrox_core::mux::decode(&buf[at..], ferrox_core::mux::NewTail::Forward) {
                Err(ferrox_core::mux::Error::Short { .. }) => break,
                Err(_) => {
                    teardown_mux(&table, &udp, &handles);
                    return;
                }
                Ok((frame, used)) => {
                    at += used;
                    progressed = true;
                    handle_mux_frame(
                        frame,
                        &table,
                        &mut udp,
                        &mut global,
                        &shared,
                        &mut staging,
                        &mut handles,
                    );
                }
            }
        }
        if !progressed {
            match read_into_tail(&mut read, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
    teardown_mux(&table, &udp, &handles);
}

fn teardown_mux(table: &MuxTable, udp: &UdpTable, handles: &[std::sync::mpsc::Receiver<()>]) {
    if let Ok(table) = table.lock() {
        for half in table.values() {
            if let Ok(half) = half.lock() {
                let _ = half.shutdown(Shutdown::Both);
            }
        }
    }
    for session in udp.values() {
        session.done.store(true, Ordering::Relaxed);
    }
    for done in handles {
        join(done);
    }
}

fn handle_mux_frame(
    frame: ferrox_core::mux::Incoming<'_>,
    table: &MuxTable,
    udp: &mut UdpTable,
    global: &mut UdpGlobal,
    shared: &Arc<Mutex<Connection>>,
    staging: &mut Vec<u8>,
    handles: &mut Vec<std::sync::mpsc::Receiver<()>>,
) {
    use ferrox_core::mux::{Network, Status};
    match frame.status {
        Status::New => {
            if frame.target.is_some_and(|t| t.network == Network::Udp) {
                handle_mux_udp_new(frame, udp, global, shared, staging, handles);
            } else {
                handle_mux_tcp_new(frame, table, shared, staging, handles);
            }
        }
        Status::Keep => {
            let Some(data) = frame.data else {
                return;
            };
            if let Some(session) = udp.get(&frame.id).cloned() {
                let dest = frame
                    .target
                    .and_then(|t| mux_target_addr(&t))
                    .unwrap_or(session.dest);
                let _ = session.socket.send_to(data, dest);
                return;
            }
            if frame.target.is_some() {
                return;
            }
            let half = match table.lock() {
                Ok(table) => table.get(&frame.id).cloned(),
                Err(_) => return,
            };
            if let Some(half) = half {
                if let Ok(mut half) = half.lock() {
                    let _ = half.write_all(data);
                }
            }
        }
        Status::End => {
            if let Some(session) = udp.remove(&frame.id) {
                session.done.store(true, Ordering::Relaxed);
                global.retain(|_, id| *id != frame.id);
            }
            if let Ok(mut table) = table.lock() {
                if let Some(half) = table.remove(&frame.id) {
                    if let Ok(half) = half.lock() {
                        let _ = half.shutdown(Shutdown::Write);
                    }
                }
            }
        }
        Status::KeepAlive => {}
    }
}

fn handle_mux_tcp_new(
    frame: ferrox_core::mux::Incoming<'_>,
    table: &MuxTable,
    shared: &Arc<Mutex<Connection>>,
    staging: &mut Vec<u8>,
    handles: &mut Vec<std::sync::mpsc::Receiver<()>>,
) {
    let Some(target) = frame.target.and_then(|t| mux_target_addr(&t)) else {
        return send_mux_end(shared, staging, frame.id);
    };
    let live = match table.lock() {
        Ok(table) => table.len(),
        Err(_) => return,
    };
    if live >= ferrox_core::mux::DEFAULT_CAP {
        return send_mux_end(shared, staging, frame.id);
    }
    let Some(uplink) = dial_or_report(&target) else {
        return send_mux_end(shared, staging, frame.id);
    };
    let Ok(read_half) = uplink.try_clone() else {
        return send_mux_end(shared, staging, frame.id);
    };
    let write_half = Arc::new(Mutex::new(uplink));
    let duplicate = match table.lock() {
        Ok(mut table) => table.insert(frame.id, Arc::clone(&write_half)).is_some(),
        Err(_) => return,
    };
    if duplicate {
        return send_mux_end(shared, staging, frame.id);
    }
    if let Some(data) = frame.data {
        if write_half
            .lock()
            .is_ok_and(|mut half| half.write_all(data).is_err())
        {
            remove_mux_session(table, frame.id, shared, staging);
            return;
        }
    }
    let task_table = Arc::clone(table);
    let task_shared = Arc::clone(shared);
    let task_id = frame.id;
    let task = move || {
        let mut read_half = read_half;
        let mut chunk = [0u8; 8192];
        let mut scratch = Vec::with_capacity(8192);
        loop {
            match read_half.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if !write_mux_keep(&task_shared, &mut scratch, task_id, &chunk[..n]) {
                        break;
                    }
                }
            }
        }
        remove_mux_session(&task_table, task_id, &task_shared, &mut scratch);
    };
    handles.push(RelayPool::global().run(task));
    handles.retain(|done| done.try_recv().is_err());
}

fn handle_mux_udp_new(
    frame: ferrox_core::mux::Incoming<'_>,
    udp: &mut UdpTable,
    global: &mut UdpGlobal,
    shared: &Arc<Mutex<Connection>>,
    staging: &mut Vec<u8>,
    handles: &mut Vec<std::sync::mpsc::Receiver<()>>,
) {
    let Some(dest) = frame.target.and_then(|t| mux_target_addr(&t)) else {
        return send_mux_end(shared, staging, frame.id);
    };
    let empty = [0u8; ferrox_core::mux::GLOBAL_ID];
    let identity = frame.global_id.filter(|identity| *identity != empty);
    let reused = identity
        .and_then(|identity| global.get(&identity).copied())
        .and_then(|id| udp.remove(&id).map(|session| (id, session)));
    let session = if let Some((old, session)) = reused {
        if old != frame.id {
            send_mux_end(shared, staging, old);
        }
        session.id.store(frame.id, Ordering::Relaxed);
        session
    } else {
        if udp.len() >= ferrox_core::mux::DEFAULT_CAP {
            return send_mux_end(shared, staging, frame.id);
        }
        let bound = if dest.is_ipv6() {
            UdpSocket::bind("[::]:0")
        } else {
            UdpSocket::bind("0.0.0.0:0")
        };
        let Ok(socket) = bound else {
            return send_mux_end(shared, staging, frame.id);
        };
        let session = Arc::new(UdpMux {
            socket: Arc::new(socket),
            dest,
            id: Arc::new(AtomicU16::new(frame.id)),
            done: Arc::new(AtomicBool::new(false)),
        });
        let Some(reader) = spawn_mux_udp_reader(&session.socket, shared, &session) else {
            return send_mux_end(shared, staging, frame.id);
        };
        handles.push(reader);
        session
    };
    if let Some(identity) = identity {
        global.insert(identity, frame.id);
    }
    udp.insert(frame.id, Arc::clone(&session));
    if let Some(data) = frame.data {
        let _ = session.socket.send_to(data, dest);
    }
}

fn spawn_mux_udp_reader(
    socket: &UdpSocket,
    shared: &Arc<Mutex<Connection>>,
    session: &Arc<UdpMux>,
) -> Option<std::sync::mpsc::Receiver<()>> {
    let read = socket.try_clone().ok()?;
    read.set_read_timeout(Some(RELAY_POLL)).ok()?;
    let shared = Arc::clone(shared);
    let id = Arc::clone(&session.id);
    let done = Arc::clone(&session.done);
    Some(RelayPool::global().run(move || {
        let mut buf = udp_buffer();
        let mut staging = Vec::with_capacity(8192);
        loop {
            match read.recv_from(&mut buf) {
                Ok((n, source)) => {
                    let keep = ferrox_core::mux::Outgoing {
                        id: id.load(Ordering::Relaxed),
                        status: ferrox_core::mux::Status::Keep,
                        options: ferrox_core::mux::DATA,
                        target: Some(mux_target_of(source)),
                        global_id: None,
                    };
                    if !write_mux_frame(&shared, &mut staging, keep, Some(&buf[..n])) {
                        return;
                    }
                }
                Err(error) if is_timeout(&error) => {
                    if done.load(Ordering::Relaxed) {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }))
}

/// The QUIC identity an inbound serves: QUIC mandates TLS, so anything without a certificate serves nothing.
fn quic_inbound_identity(inbound: &Json) -> Option<Arc<ferrox_core::tls::TlsServerConfig>> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return None;
    }
    inbound_tls_identity(inbound)
}

fn serve_vless_quic_inbound(
    address: &str,
    inbound: &Json,
    id: &[u8; 16],
    freedom: bool,
    path: &str,
) -> bool {
    let Some(identity) = quic_inbound_identity(inbound) else {
        eprintln!("quic inbound in {path} needs security tls with a certificate: serves nothing");
        return false;
    };
    let Some(config) = crate::quic::serve_config(&identity) else {
        eprintln!("unreadable quic tls identity in {path}: serves nothing");
        return false;
    };
    let Ok(sock) = crate::quic::bind_datagram(address) else {
        eprintln!("cannot listen on {address}: serves nothing");
        return false;
    };
    let id = *id;
    let serve: crate::quic::Serve = Arc::new(move |stream| {
        serve_vless_quic(stream, &id, freedom);
    });
    thread::spawn(move || {
        crate::quic::serve_loop(
            crate::quic::Datagram::plain(sock),
            &Arc::new(Mutex::new(config)),
            &serve,
            &Arc::new(AtomicBool::new(false)),
        );
    });
    true
}

/// One QUIC stream, one VLESS session: the header, the accept, then the relay with a FIN at its end.
fn serve_vless_quic(mut stream: crate::quic::QuicStream, id: &[u8; 16], freedom: bool) {
    let fin = stream.clone();
    let decoded = decode_request_bounded(&mut stream);
    let Some((got, flow, cmd, target)) = decoded else {
        stream.close();
        return;
    };
    // Streams carry TCP sessions only, never Vision framing, UDP or mux: a foreign shape closes here.
    if got != *id || cmd != 1 || !flow.is_empty() || !freedom {
        stream.close();
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        stream.close();
        return;
    };
    // Both relay halves share one lock each: an untimed blocking read would pin its half forever.
    if uplink.set_read_timeout(Some(RELAY_POLL)).is_err() {
        stream.close();
        return;
    }
    if stream.write_all(&[0, 0]).is_err() {
        stream.close();
        return;
    }
    let Ok(stop) = uplink.try_clone() else {
        stream.close();
        return;
    };
    let peer = stream.clone();
    let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let _ = stop.shutdown(Shutdown::Both);
        peer.close();
    });
    relay_stream(stream, uplink, &close);
    let _ = fin.fin();
}

fn serve_vless_tls_inbound(
    address: &str,
    inbound: &Json,
    id: &[u8; 16],
    carrier: &Carrier,
    freedom: bool,
    path: &str,
) -> bool {
    let Some(server) = inbound_tls_identity(inbound) else {
        eprintln!("unreadable vless tls identity in {path}: serves raw TCP only");
        return false;
    };
    let owned = address.to_owned();
    if let Carrier::Kcp(config) = carrier {
        let config = config.clone();
        let id = *id;
        let serve: KcpServe = Arc::new(move |conn: &Arc<ferrox_core::kcp::Connection>| {
            serve_vless_kcp_tls(conn, &id, freedom, &server);
        });
        thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        return true;
    }
    let role = Role::VlessTls {
        id: *id,
        freedom,
        carrier: carrier.clone(),
        server,
    };
    thread::spawn(move || accept_loop(&owned, &role));
    true
}

fn serve_vless_reality_inbound(
    address: &str,
    inbound: &Json,
    id: &[u8; 16],
    carrier: &Carrier,
    freedom: bool,
    path: &str,
) -> bool {
    let Some(server) = inbound_reality_config(inbound) else {
        eprintln!("unreadable vless reality settings in {path}: serves nothing");
        return false;
    };
    let owned = address.to_owned();
    if let Carrier::Kcp(config) = carrier {
        let config = config.clone();
        let id = *id;
        let server = Arc::new(server);
        let serve: KcpServe = Arc::new(move |conn: &Arc<ferrox_core::kcp::Connection>| {
            serve_vless_kcp_reality(conn, &id, freedom, &server);
        });
        thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        return true;
    }
    let role = Role::VlessReality {
        id: *id,
        freedom,
        carrier: carrier.clone(),
        server: Arc::new(server),
    };
    thread::spawn(move || accept_loop(&owned, &role));
    true
}

fn serve_session_ws<R: Read, W: FrameWrite + 'static>(
    read: R,
    write: W,
    path: &str,
    id: &[u8; 16],
    freedom: bool,
) {
    let Some((mut creader, cwriter)) = crate::ws::accept_split(read, write, path) else {
        echo_trace("session ws accept refused");
        return;
    };
    creader.set_handshake_budget(Some(Instant::now() + budgets::handshake()));
    let decoded = decode_request(&mut creader);
    creader.set_handshake_budget(None);
    let Some((got, _flow, cmd, target)) = decoded else {
        echo_trace("session ws vless decode refused");
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        echo_trace("session ws vless id or cmd refused");
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        echo_trace("session ws uplink refused");
        return;
    };
    echo_trace(&format!("session ws uplink {target}"));
    if !cwriter.send(&[0, 0]) {
        echo_trace("session ws vless response refused");
        return;
    }
    echo_trace("session ws relaying");
    relay_sink(creader, &cwriter, &uplink, |_| {});
}

fn serve_session_xhttp<R: Read + Send + 'static, W: FrameWrite + 'static>(
    read: R,
    write: W,
    settings: &crate::xhttp::XhttpSettings,
    id: &[u8; 16],
    freedom: bool,
) {
    let Some((creader, cwriter)) = crate::xhttp::accept_split_with_settings(read, write, settings)
    else {
        echo_trace("session xhttp accept refused");
        return;
    };
    serve_session_xhttp_with(creader, &cwriter, id, freedom);
}

fn serve_xhttp_stream<R: Read + Send + 'static, W: FrameWrite + Send + 'static>(
    mut read: R,
    write: W,
    settings: &crate::xhttp::XhttpSettings,
    id: &[u8; 16],
    freedom: bool,
) {
    let mut magic = [0u8; 24];
    if read_exact(&mut read, &mut magic).is_ok() && magic == *crate::h2::MAGIC {
        return crate::xhttp_h2::serve_h2(read, write, settings, *id, freedom);
    }
    let chained = crate::xhttp::ChainReader::new(magic.to_vec(), read);
    serve_session_xhttp(chained, write, settings, id, freedom);
}

pub(crate) fn serve_session_xhttp_with(
    mut creader: Box<dyn Read + Send>,
    cwriter: &crate::xhttp::XhttpWriter,
    id: &[u8; 16],
    freedom: bool,
) {
    // Every refusal ends the carrier's stream: a session that answers nothing leaves its reader parked on a reply that will never come.
    let Some((got, _flow, cmd, target)) = decode_request(&mut creader) else {
        echo_trace("session xhttp vless decode refused");
        cwriter.finish();
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        echo_trace("session xhttp vless id or cmd refused");
        cwriter.finish();
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        echo_trace("session xhttp uplink refused");
        cwriter.finish();
        return;
    };
    if !cwriter.send(&[0, 0]) {
        echo_trace("session xhttp vless response refused");
        cwriter.finish();
        return;
    }
    echo_trace("session xhttp relaying");
    relay_sink_drained(creader, cwriter, &uplink);
}

fn serve_session_httpupgrade<R: Read, W: Write + Clone + Send + 'static>(
    read: R,
    write: W,
    raw: Connection,
    path: &str,
    id: &[u8; 16],
    freedom: bool,
) {
    // Every exit of a served connection drains before it closes, so the peer keeps what it had already been sent.
    let raw = Arc::new(raw);
    let Some((mut creader, cwriter)) = crate::httpupgrade::accept_split(read, write, path) else {
        echo_trace("session httpupgrade accept refused");
        crate::httpupgrade::quiet(&raw);
        return;
    };
    let decoded = decode_request_bounded(&mut creader);
    let Some((got, _flow, cmd, target)) = decoded else {
        echo_trace("session httpupgrade vless decode refused");
        crate::httpupgrade::quiet(&raw);
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        echo_trace("session httpupgrade vless id or cmd refused");
        crate::httpupgrade::quiet(&raw);
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        echo_trace("session httpupgrade uplink refused");
        crate::httpupgrade::quiet(&raw);
        return;
    };
    let mut sink = SessionSink {
        half: cwriter,
        raw: Arc::clone(&raw),
    };
    if sink.write_all(&[0, 0]).is_err() {
        echo_trace("session httpupgrade vless response refused");
        crate::httpupgrade::quiet(&raw);
        return;
    }
    echo_trace("session httpupgrade relaying");
    relay_sink(creader, &sink, &uplink, |_| {});
    crate::httpupgrade::quiet(&raw);
}

fn serve_session_httpheader<R: Read, W: Write + Clone + Send + 'static>(
    read: R,
    write: W,
    raw: Connection,
    path: &str,
    id: &[u8; 16],
    freedom: bool,
) {
    let Some((mut creader, cwriter)) = crate::httpheader::accept_split(read, write, path) else {
        echo_trace("session httpheader accept refused");
        return;
    };
    let decoded = decode_request_bounded(&mut creader);
    let Some((got, _flow, cmd, target)) = decoded else {
        echo_trace("session httpheader vless decode refused");
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        echo_trace("session httpheader vless id or cmd refused");
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        echo_trace("session httpheader uplink refused");
        return;
    };
    let mut sink = SessionSink {
        half: cwriter,
        raw: Arc::new(raw),
    };
    if sink.write_all(&[0, 0]).is_err() {
        echo_trace("session httpheader vless response refused");
        return;
    }
    echo_trace("session httpheader relaying");
    relay_sink(creader, &sink, &uplink, |_| {});
}

fn serve_session_grpc<R: Read, W: FrameWrite + 'static>(
    read: R,
    write: W,
    path: &str,
    id: &[u8; 16],
    freedom: bool,
) {
    let Some((mut creader, cwriter)) = crate::grpc::accept_split(read, write, path) else {
        echo_trace("session grpc accept refused");
        return;
    };
    // The dispatcher already polls the socket behind a session at the relay's grain, so only the request's own clock is armed here: past it a peer that answered the head and then stopped speaking is a refusal, not a thread pinned in `read_exact`'s retry.
    creader.set_handshake_budget(Some(Instant::now() + budgets::handshake()));
    let decoded = decode_request(&mut creader);
    creader.set_handshake_budget(None);
    let Some((got, _flow, cmd, target)) = decoded else {
        echo_trace("session grpc vless decode refused");
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        echo_trace("session grpc vless id or cmd refused");
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        echo_trace("session grpc uplink refused");
        return;
    };
    if !cwriter.send(&[0, 0]) {
        echo_trace("session grpc vless response refused");
        return;
    }
    echo_trace("session grpc relaying");
    relay_sink(creader, &cwriter, &uplink, crate::grpc::mark_reader_dead);
}

fn accept_tls_session(
    stream: Connection,
    server: &ferrox_core::tls::TlsServerConfig,
) -> Option<impl ferrox_core::tls::TlsProvider + ferrox_core::tls::RecordAlignment + Send> {
    let Ok(mut session) = ferrox_core::tls::accept(server, stream) else {
        echo_trace("tls-server accept refused");
        return None;
    };
    // Silence is scheduling, not death: an idle handshake retries to the deadline; anything else refuses.
    if shake_tls(&mut session) {
        Some(session)
    } else {
        echo_trace("tls-server handshake refused");
        None
    }
}

fn serve_vless_tls(
    stream: Connection,
    id: &[u8; 16],
    freedom: bool,
    carrier: &Carrier,
    server: &ferrox_core::tls::TlsServerConfig,
) {
    if stream.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    match carrier {
        Carrier::Raw(_) => {
            let Ok(raw) = stream.try_clone() else { return };
            let Ok(mut tls) = ferrox_core::tls::accept(server, stream) else {
                return;
            };
            if !shake_tls(&mut tls) {
                return;
            }
            relay_vless(tls, Some(raw), id, freedom);
        }
        Carrier::Ws { path, .. } => {
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session);
            serve_session_ws(reader, writer, path, id, freedom);
        }
        Carrier::Xhttp { settings, .. } => {
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session);
            serve_xhttp_stream(reader, writer, settings, id, freedom);
        }
        Carrier::HttpUpgrade { path, .. } => {
            let Ok(raw) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session);
            serve_session_httpupgrade(reader, writer, raw, path, id, freedom);
        }
        Carrier::HttpHeader { path } => {
            let Ok(raw) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session);
            serve_session_httpheader(reader, writer, raw, path, id, freedom);
        }
        Carrier::Grpc { path } => {
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session);
            serve_session_grpc(reader, writer, path, id, freedom);
        }
        refused_carriers!() => {}
    }
}

fn serve_carried_tls<S: Read + Write + Send + 'static>(
    stream: S,
    id: &[u8; 16],
    freedom: bool,
    server: &ferrox_core::tls::TlsServerConfig,
) {
    let Ok(mut tls) = ferrox_core::tls::accept(server, stream) else {
        return;
    };
    if tls.handshake().is_err() {
        return;
    }
    relay_vless(tls, None, id, freedom);
}

/// An idle handshake is retried until the deadline; anything but silence refuses at once.
fn shake_tls<S: ferrox_core::tls::TlsProvider>(session: &mut S) -> bool {
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    loop {
        match session.handshake() {
            Ok(()) => return true,
            Err(ferrox_core::tls::TlsError::Timeout) if Instant::now() < deadline => {}
            Err(_) => return false,
        }
    }
}

fn serve_vless_reality(
    stream: Connection,
    id: &[u8; 16],
    freedom: bool,
    carrier: &Carrier,
    server: &ferrox_core::tls::RealityServerConfig,
) {
    if stream.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    match carrier {
        Carrier::Raw(_) => {
            let Ok(raw) = stream.try_clone() else { return };
            let edges = reality_edges(server, &stream);
            let accepted =
                ferrox_core::tls::RealityServer::accept(server, unix_millis(), stream, edges);
            answer_reality(accepted, Some(raw), id, freedom, server);
        }
        Carrier::Ws { path, .. } => {
            serve_carrier_reality(stream, server, |mut session| {
                if !shake_tls(&mut session) {
                    return;
                }
                let (reader, writer) = session_halves(session);
                serve_session_ws(reader, writer, path, id, freedom);
            });
        }
        Carrier::Xhttp { settings, .. } => {
            serve_carrier_reality(stream, server, |mut session| {
                if !shake_tls(&mut session) {
                    return;
                }
                let (reader, writer) = session_halves(session);
                serve_xhttp_stream(reader, writer, settings, id, freedom);
            });
        }
        Carrier::HttpUpgrade { path, .. } => {
            let Ok(raw) = stream.try_clone() else { return };
            serve_carrier_reality(stream, server, |mut session| {
                if !shake_tls(&mut session) {
                    return;
                }
                let (reader, writer) = session_halves(session);
                serve_session_httpupgrade(reader, writer, raw, path, id, freedom);
            });
        }
        Carrier::HttpHeader { path } => {
            let Ok(raw) = stream.try_clone() else { return };
            serve_carrier_reality(stream, server, |mut session| {
                if !shake_tls(&mut session) {
                    return;
                }
                let (reader, writer) = session_halves(session);
                serve_session_httpheader(reader, writer, raw, path, id, freedom);
            });
        }
        Carrier::Grpc { path } => {
            serve_carrier_reality(stream, server, |mut session| {
                if !shake_tls(&mut session) {
                    return;
                }
                let (reader, writer) = session_halves(session);
                serve_session_grpc(reader, writer, path, id, freedom);
            });
        }
        refused_carriers!() => {}
    }
}

/// The ends the cover origin sees: looked up only for a PROXY header, so a handshake without one costs no lookup.
fn reality_edges(server: &ferrox_core::tls::RealityServerConfig, stream: &Connection) -> Edges {
    if server.xver > 0 {
        // `Edges::of` takes a `&TcpStream`; reading both ends through the seam lets a unix leg yield the same `None` ends an unbound TCP stream does.
        Edges {
            peer: stream.peer_addr().ok(),
            local: stream.local_addr().ok(),
        }
    } else {
        Edges::default()
    }
}

// REALITY runs on the raw stream because the references read the ClientHello off TCP, not an upgraded one.
fn serve_carrier_reality(
    stream: Connection,
    server: &ferrox_core::tls::RealityServerConfig,
    serve: impl FnOnce(ferrox_core::tls::RealityServer<Connection>),
) {
    let edges = reality_edges(server, &stream);
    match ferrox_core::tls::RealityServer::accept(server, unix_millis(), stream, edges) {
        Ok(ferrox_core::tls::RealityAccept::Session(session)) => serve(session),
        Ok(ferrox_core::tls::RealityAccept::Proxied(proxied)) => relay_fallback(proxied),
        Err(why) => {
            if server.show {
                eprintln!("REALITY: {why}");
            }
        }
    }
}
/// The bucket one splice direction paces with: `burst` bytes free past `after_bytes`, then `bytes_per_sec`.
#[derive(Debug)]
struct Gauge {
    limit: ferrox_core::tls::RateLimit,
    sent: u64,
    began: Option<Instant>,
}

impl Gauge {
    fn start(limit: ferrox_core::tls::RateLimit) -> Self {
        let burst = if limit.burst_bytes_per_sec < limit.bytes_per_sec {
            limit.bytes_per_sec
        } else {
            limit.burst_bytes_per_sec
        };
        Self {
            limit: ferrox_core::tls::RateLimit {
                burst_bytes_per_sec: burst,
                ..limit
            },
            sent: 0,
            began: None,
        }
    }

    /// Waits until the byte that closes this write may go out, then counts it.
    fn admit(&mut self, len: usize) {
        let end = self.sent + u64::try_from(len).unwrap_or(u64::MAX);
        self.sent = end;
        if end <= self.limit.after_bytes || self.limit.bytes_per_sec == 0 {
            return;
        }
        let began = *self.began.get_or_insert_with(Instant::now);
        let owed = end - self.limit.after_bytes;
        if owed <= self.limit.burst_bytes_per_sec {
            return;
        }
        let wait = Duration::from_nanos(
            (owed - self.limit.burst_bytes_per_sec) * 1_000_000_000 / self.limit.bytes_per_sec,
        );
        let deadline = began + wait;
        if let Some(rest) = deadline.checked_duration_since(Instant::now()) {
            std::thread::sleep(rest);
        }
    }
}

/// An authenticated session carries the record; an unauthenticated peer is spliced to the cover origin.
fn answer_reality<S: Stream + Send + 'static>(
    accepted: Result<ferrox_core::tls::RealityAccept<S>, ferrox_core::tls::TlsError>,
    raw: Option<Connection>,
    id: &[u8; 16],
    freedom: bool,
    server: &ferrox_core::tls::RealityServerConfig,
) {
    let accepted = match accepted {
        Ok(accepted) => accepted,
        Err(why) => {
            if server.show {
                eprintln!("REALITY: {why}");
            }
            return;
        }
    };
    match accepted {
        ferrox_core::tls::RealityAccept::Session(session) => {
            finish_reality(session, raw, id, freedom);
        }
        ferrox_core::tls::RealityAccept::Proxied(proxied) => relay_fallback(proxied),
    }
}

/// The cover-origin splice reuses the shared relay pump: an unauthenticated peer is a copy, not a second pump.
fn relay_fallback<S: Stream + Send + 'static>(proxied: ferrox_core::tls::Proxied<S>) {
    let ferrox_core::tls::Proxied {
        client,
        target,
        upload,
        download,
    } = proxied;
    // A silent cover origin must not hold the read across the mutex its upload writes on.
    if target.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    let one = Arc::new(Half::new(client));
    let two = Arc::new(Half::new(target));
    let mut up = upload.map(Gauge::start);
    let mut down = download.map(Gauge::start);
    // A finished leg ends the splice; the sibling notices on its next poll grain.
    let ended = Arc::new(AtomicBool::new(false));
    let (down_recv, down_send, down_ended) =
        (Arc::clone(&two), Arc::clone(&one), Arc::clone(&ended));
    let downlink =
        thread::spawn(move || copy_paced(&down_recv, &down_send, down.as_mut(), &down_ended));
    copy_paced(&one, &two, up.as_mut(), &ended);
    let _ = downlink.join();
}

fn copy_paced<R: Read, W: Write>(
    from: &Half<R>,
    to: &Half<W>,
    mut gauge: Option<&mut Gauge>,
    ended: &AtomicBool,
) {
    let mut buffer = RelayBuf::new();
    loop {
        let n = match from.read_once(buffer.as_mut()) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if is_timeout(&error) => {
                if ended.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        if let Some(gauge) = gauge.as_mut() {
            gauge.admit(n);
        }
        if to.write_once(buffer.filled(n)).is_err() {
            break;
        }
    }
    ended.store(true, Ordering::Relaxed);
}

fn finish_reality<
    S: ferrox_core::tls::TlsProvider + ferrox_core::tls::RecordAlignment + Send + 'static,
>(
    mut session: S,
    raw: Option<Connection>,
    id: &[u8; 16],
    freedom: bool,
) {
    if !shake_tls(&mut session) {
        return;
    }
    relay_vless(session, raw, id, freedom);
}

#[cfg(test)]
struct CarrierStream<R, W> {
    reader: R,
    writer: W,
}

#[cfg(test)]
impl<R: Read, W: Write> Read for CarrierStream<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

#[cfg(test)]
impl<R: Read, W: Write> Write for CarrierStream<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
impl<R: Read, W: Write> ferrox_core::tls::RecordAlignment for CarrierStream<R, W> {}

fn relay_vless<S: Read + Write + Send + ferrox_core::tls::RecordAlignment + 'static>(
    mut session: S,
    raw: Option<Connection>,
    id: &[u8; 16],
    freedom: bool,
) {
    let Some((got, flow, cmd, target)) = decode_request_bounded(&mut session) else {
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if uplink.set_read_timeout(Some(RELAY_POLL)).is_err() {
        eprintln!("tls: uplink timeout failed");
        return;
    }
    // Two pumps share the session's half-lock: read the raw arm's fd at one tick, or a silent read stalls the peer's write for a grain.
    if let Some(raw) = raw.as_ref() {
        if raw.set_read_timeout(Some(SESSION_POLL)).is_err() {
            eprintln!("tls: session timeout failed");
            return;
        }
    }
    if session.write_all(&[0, 0]).is_err() {
        return;
    }
    // Either direction ending closes the other, or the far end waits out its own deadline.
    let close_uplink = uplink.try_clone().ok();
    let close_raw = raw.as_ref().and_then(|raw| raw.try_clone().ok());
    let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        if let Some(uplink) = close_uplink.as_ref() {
            let _ = uplink.shutdown(Shutdown::Both);
        }
        if let Some(raw) = close_raw.as_ref() {
            let _ = raw.shutdown(Shutdown::Both);
        }
    });
    if flow == crate::vision::FLOW {
        relay_stream(crate::vision::Link::new(session, raw, id), uplink, &close);
    } else {
        // No direct switch coming: the limiter stops bounding and tracking reads.
        session.disarm_record_alignment();
        relay_stream(session, uplink, &close);
    }
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

#[derive(Debug)]
struct Half<T> {
    inner: Mutex<T>,
    wanted: AtomicBool,
}

impl<T> Half<T> {
    fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            wanted: AtomicBool::new(false),
        }
    }

    fn hand_off(&self) {
        let mut spins = 0;
        while self.wanted.load(Ordering::Relaxed) && spins < RELAY_HANDOFF_SPINS {
            thread::yield_now();
            spins += 1;
        }
    }
}

impl<T: Read> Half<T> {
    fn read_once(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        census!("tunnel-leg-read", crate::census::NO_FD, None);
        let result = match self.inner.lock() {
            Ok(mut guard) => guard.read(buf),
            Err(_) => Err(std::io::Error::other("relay half poisoned")),
        };
        self.hand_off();
        result
    }
}

impl<T: Write> Half<T> {
    fn write_once(&self, buf: &[u8]) -> std::io::Result<()> {
        self.wanted.store(true, Ordering::Relaxed);
        let taken = self.writer_lock();
        self.wanted.store(false, Ordering::Relaxed);
        let Ok(mut guard) = taken else {
            return Err(std::io::Error::other("relay half poisoned"));
        };
        // Buffered writers only send on flush; raw sockets treat it as a no-op.
        guard.write_all(buf)?;
        guard.flush()
    }

    fn writer_lock(&self) -> Result<MutexGuard<'_, T>, ()> {
        let mut spins = 0u32;
        loop {
            match self.inner.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(()),
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            spins += 1;
            if spins > RELAY_LOCK_TRIES {
                return self.inner.lock().map_err(|_| ());
            }
            thread::yield_now();
        }
    }
}

fn relay_stream<A: Read + Write + Send + 'static, B: Read + Write + Send + 'static>(
    a: A,
    b: B,
    close: &Arc<dyn Fn() + Send + Sync>,
) {
    let a = Arc::new(Half::new(a));
    let b = Arc::new(Half::new(b));
    // A leg polling its way through a finished relay must see that its sibling ended: shutdown delivery alone hangs when it does not arrive, as on Windows.
    let ended = Arc::new(AtomicBool::new(false));
    let (up_a, up_b, up_ended) = (Arc::clone(&a), Arc::clone(&b), Arc::clone(&ended));
    let done_close = Arc::clone(close);
    let done = thread::spawn(move || copy_stream(&up_a, &up_b, &done_close, &up_ended));
    copy_stream(&b, &a, close, &ended);
    let _ = done.join();
}

fn copy_stream<R: Read, W: Write>(
    from: &Half<R>,
    to: &Half<W>,
    close: &Arc<dyn Fn() + Send + Sync>,
    ended: &AtomicBool,
) {
    let mut buffer = RelayBuf::new();
    loop {
        let n = match from.read_once(buffer.as_mut()) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if is_timeout(&error) => {
                if ended.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        if to.write_once(buffer.filled(n)).is_err() {
            break;
        }
    }
    close();
    ended.store(true, Ordering::Relaxed);
}

pub(crate) fn resize_scratch(buf: &mut Vec<u8>, len: usize) {
    buf.clear();
    if buf.capacity() < len {
        buf.reserve(len);
    }
    unsafe { buf.set_len(len) }
}

/// One relay read's worth of stream bytes: the framing buffer's read room.
pub(crate) const READ_SLICE: usize = 8 * 1024;

/// Reads straight into the vector's spare capacity, so a relay read is not copied through a second buffer.
#[allow(
    clippy::uninit_vec,
    reason = "the tail is handed straight to `read`, and every path that does not fill it truncates"
)]
pub(crate) fn read_into_tail(read: &mut impl Read, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let base = buf.len();
    buf.reserve(READ_SLICE);
    // SAFETY: `read` initialises the bytes it reports, and `set_len` is rolled back on every path that does not.
    unsafe { buf.set_len(base + READ_SLICE) };
    match read.read(&mut buf[base..]) {
        Ok(n) => {
            buf.truncate(base + n);
            Ok(n)
        }
        Err(error) => {
            buf.truncate(base);
            Err(error)
        }
    }
}

pub(crate) fn refresh_read_timeout(
    sock: &crate::quic::Datagram,
    want: Duration,
    applied: &mut Option<Duration>,
) -> bool {
    if *applied == Some(want) {
        return true;
    }
    if sock.set_read_timeout(Some(want)).is_err() {
        return false;
    }
    *applied = Some(want);
    true
}

pub(crate) fn is_timeout(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    matches!(error.kind(), TimedOut | WouldBlock)
        || error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ferrox_core::tls::TlsError>())
            .is_some_and(|mapped| matches!(mapped, ferrox_core::tls::TlsError::Timeout))
}

pub(crate) fn vless_header(id: &[u8; 16], cmd: u8, target: &Destination) -> Vec<u8> {
    // version + uuid + addonsLen + command + port = 21, then the family byte and its body.
    let mut header = Vec::with_capacity(21 + target.addr_len());
    header.push(0);
    header.extend_from_slice(id);
    header.push(0);
    header.push(cmd);
    header.extend_from_slice(&target.port().to_be_bytes());
    target.push_addr(&mut header, 3, 2);
    header
}

/// The VLESS header with the Vision flow in its addons, the bytes the core encoder writes.
pub(crate) fn vless_vision_header(id: &[u8; 16], cmd: u8, target: &Destination) -> Vec<u8> {
    const ADDONS: &[u8] = b"\x0A\x10xtls-rprx-vision";
    // The bare header plus the fixed Flow addon, then the family byte and its body.
    let mut header = Vec::with_capacity(21 + ADDONS.len() + target.addr_len());
    header.push(0);
    header.extend_from_slice(id);
    header.push(ADDONS.len() as u8);
    header.extend_from_slice(ADDONS);
    header.push(cmd);
    header.extend_from_slice(&target.port().to_be_bytes());
    target.push_addr(&mut header, 3, 2);
    header
}

pub(crate) fn vless_mux_header(id: &[u8; 16]) -> Vec<u8> {
    let mut header = Vec::with_capacity(19);
    header.push(0);
    header.extend_from_slice(id);
    header.push(0);
    header.push(3);
    header
}

// Records a rung failure and reports whether the session stops here.
fn climb_or_hold(ladder: &Ladder, rung: Rung, stage: Stage, kind: Kind) -> bool {
    let failure = Failure::new(stage, kind);
    match ladder.record_failure(rung, &failure) {
        Some(next) => {
            eprintln!("ladder: {failure} climbs {rung} -> {next}");
            false
        }
        None => true,
    }
}

fn note_success(ladder: &Ladder, rung: Rung, stage: Stage, explicit: bool) {
    if let Some((old, successes)) = ladder.record_success(rung, stage, explicit) {
        eprintln!("ladder: {successes} useful successes descend {old} -> {rung} at {stage}");
    }
}

// A ladder rung: the step, its reused (path, budget), and whether it is the configured carrier or a probe.
#[derive(Clone, Copy)]
struct RungAttempt<'a> {
    rung: Rung,
    path: &'a str,
    ed: u32,
    explicit: bool,
}

fn dial_vless(
    client: &Connection,
    server: &SocketAddr,
    vless: &VlessOut,
    target: &Destination,
    ladder: &Ladder,
) {
    let header = vless_header(&vless.id, 1, target);
    if vless.tls.is_some() {
        dial_vless_tls(client, server, vless, target);
        return;
    }
    if vless.reality.is_some() {
        dial_vless_reality(client, server, vless, target);
        return;
    }
    let params = stream_params(&vless.carrier);
    let explicit = rung_of(&vless.carrier);
    if explicit.is_none() {
        let Some(uplink) = dial_or_report(server) else {
            return;
        };
        if dial_vless_headed(client, uplink, vless, &header) {
            return;
        }
    }
    let start = ladder_start(&vless.carrier);
    let (rungs, count) = Rung::climb_from(start);
    for rung in &rungs[..count] {
        let attempt = if *rung == Rung::Raw {
            RungAttempt {
                rung: *rung,
                path: "",
                ed: 0,
                explicit: Some(*rung) == explicit,
            }
        } else if let Some((path, ed)) = params {
            RungAttempt {
                rung: *rung,
                path,
                ed,
                explicit: Some(*rung) == explicit,
            }
        } else {
            break;
        };
        let uplink = match dial(server) {
            Ok(uplink) => uplink.with_mask(vless.carrier.tcp_mask()),
            Err(failure) => {
                let _stop = ladder.record_failure(*rung, &failure);
                note_dial_failure(server, failure);
                return;
            }
        };
        if dial_vless_rung(client, uplink, vless, &header, &attempt, ladder) {
            return;
        }
    }
}

fn dial_vless_headed(
    client: &Connection,
    uplink: Connection,
    vless: &VlessOut,
    header: &[u8],
) -> bool {
    let Carrier::HttpHeader { path } = &vless.carrier else {
        return true;
    };
    let Some((mut reader, mut write)) = crate::httpheader::connect(uplink, &vless.host, path)
    else {
        return !Failure::new(Stage::SocketConnected, Kind::Unreachable).worth_retrying();
    };
    if write.write_all(header).is_err() {
        return !Failure::new(Stage::RequestSent, Kind::Dropped).worth_retrying();
    }
    let pump = Pump::to_stream(client, &write);
    let answered = read_vless_response(&mut reader).is_some();
    pump.end();
    if !answered {
        return !Failure::new(Stage::RequestSent, Kind::Dropped).worth_retrying();
    }
    crate::proxy::relay_carried(reader, &write, client);
    true
}

fn dial_vless_rung(
    client: &Connection,
    uplink: Connection,
    vless: &VlessOut,
    header: &[u8],
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    match rung {
        Rung::Ws => {
            let Some((mut reader, writer)) =
                crate::ws::connect(uplink, &vless.host, attempt.path, attempt.ed, header)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            let pump = Pump::to_sink(client, &writer);
            let answered = read_vless_response(&mut reader).is_some();
            pump.end();
            if !answered {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
            crate::proxy::relay_sink(reader, &writer, client, |_| {});
            true
        }
        Rung::HttpUpgrade => {
            let Some((mut reader, write)) =
                crate::httpupgrade::connect(uplink, &vless.host, attempt.path, attempt.ed, header)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            let pump = Pump::to_stream(client, &write);
            let answered = read_vless_response(&mut reader).is_some();
            pump.end();
            if !answered {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
            crate::proxy::relay_carried(reader, &write, client);
            true
        }
        Rung::Grpc => {
            let Some((mut reader, writer)) =
                crate::grpc::connect(uplink, &vless.host, attempt.path)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            if !writer.send(header) {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            let pump = Pump::to_sink(client, &writer);
            let answered = read_vless_response(&mut reader).is_some();
            pump.end();
            if !answered {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
            crate::proxy::relay_sink(reader, &writer, client, crate::grpc::mark_reader_dead);
            true
        }
        Rung::Xhttp => {
            let Some((mut reader, writer)) =
                crate::xhttp::connect(uplink, &vless.host, attempt.path)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            if !writer.send(header) {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            let pump = Pump::to_sink(client, &writer);
            let answered = read_vless_response(&mut reader).is_some();
            pump.end();
            if !answered {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
            crate::proxy::relay_sink_drained(reader, &writer, client);
            true
        }
        Rung::Raw => {
            let mut uplink = uplink;
            if uplink.write_all(header).is_err() {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Dropped);
            }
            let pump = Pump::to_stream(client, &uplink);
            let answered = read_vless_response(&mut uplink).is_some();
            pump.end();
            if !answered {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
            relay(client, &uplink);
            true
        }
    }
}

// KCP carries the same protocol bytes as TCP over a reliable UDP stream.
#[derive(Clone)]
struct KcpIo {
    conn: Arc<ferrox_core::kcp::Connection>,
}

impl KcpIo {
    fn close(&self) {
        self.conn.close();
    }
}

impl Read for KcpIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // The directions share one half-lock, so a read that never returns wedges the other's write.
        self.conn.set_read_deadline(Instant::now() + RELAY_POLL);
        match self.conn.read(buf) {
            Ok(n) => Ok(n),
            Err(ferrox_core::kcp::ConnError::IoTimeout) => {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
            Err(error) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, error)),
        }
    }
}

impl Write for KcpIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.conn
            .write(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn kcp_relay(tcp: &Connection, conn: &Arc<ferrox_core::kcp::Connection>) {
    let Ok(tcp_read) = tcp.try_clone() else {
        return;
    };
    let Ok(mut tcp_write) = tcp.try_clone() else {
        return;
    };
    let up = Arc::clone(conn);
    let done = RelayPool::global().run(move || {
        let mut tcp_read = tcp_read;
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.write(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        up.close();
    });
    // The handshake's `KcpIo` leaves a 20 ms read deadline: a raw `conn.read` would answer an empty window with a terminal `IoTimeout` and half-close the client before the reply lands, so poll-retry the same quantum here.
    let mut download = KcpIo {
        conn: Arc::clone(conn),
    };
    let mut buf = vec![0u8; 16384];
    loop {
        match download.read(&mut buf) {
            Ok(n) if n > 0 => {
                if tcp_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(error) if is_timeout(&error) => {}
            _ => break,
        }
    }
    let _ = tcp_write.shutdown(Shutdown::Write);
    join(&done);
}

fn serve_vless_kcp(conn: &Arc<ferrox_core::kcp::Connection>, id: &[u8; 16], freedom: bool) {
    let mut io = KcpIo {
        conn: Arc::clone(conn),
    };
    let Some((got, _flow, cmd, target)) = decode_request_bounded(&mut io) else {
        return;
    };
    if got != *id || !freedom || cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if conn.write(&[0, 0]).is_err() {
        return;
    }
    kcp_relay(&uplink, conn);
}

/// Hysteria v2 flow: acknowledge before dialing, so a refused dial reads as EOF rather than as a refusal.
fn serve_hysteria_flow(mut flow: crate::hysteria::Flow, freedom: bool) {
    if !freedom {
        return;
    }
    let deadline = std::time::Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let Some(address) = crate::hysteria::read_request(&mut flow, deadline) else {
        return;
    };
    let mut ok = Vec::with_capacity(3);
    ferrox_core::hysteria::encode_tcp_response(true, &[], &[], &mut ok);
    if flow.write_all(&ok).is_err() {
        return;
    }
    let Some(target) = address.to_socket_addrs().ok().and_then(|mut it| it.next()) else {
        flow.close();
        return;
    };
    let Some(uplink) = dial_or_report(&target) else {
        flow.close();
        return;
    };
    crate::hysteria::relay(&uplink, &flow);
}

/// The `hysteria` inbound: v2 over the hysteria transport, users' passwords as auths; other versions refused.
fn serve_hysteria_inbound(address: &str, inbound: &Json, freedom: bool, path: &str) -> bool {
    let settings = inbound.get("settings");
    if settings
        .and_then(|node| node.get("version"))
        .and_then(Json::as_u32)
        != Some(2)
    {
        eprintln!("hysteria inbound in {path} is not version 2: serves nothing");
        return false;
    }
    let auths: Vec<String> = settings
        .and_then(|node| node.get("users"))
        .and_then(Json::as_arr)
        .map(|users| {
            users
                .iter()
                .filter_map(|user| user.get("auth").and_then(Json::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if auths.is_empty() {
        eprintln!("hysteria inbound in {path} names no user auth: serves nothing");
        return false;
    }
    let Some(stream) = inbound.get("streamSettings") else {
        eprintln!("hysteria inbound in {path} carries no transport: serves nothing");
        return false;
    };
    if stream.get("network").and_then(Json::as_str) != Some("hysteria") {
        eprintln!("hysteria inbound in {path} is not on the hysteria transport: serves nothing");
        return false;
    }
    let Some((cert_path, key_path)) = tls_cert_paths(stream) else {
        eprintln!("unreadable hysteria identity in {path}: serves nothing");
        return false;
    };
    let (cert_path, key_path) = (cert_path.to_owned(), key_path.to_owned());
    let owned = address.to_owned();
    let mut obfs_password = String::new();
    // A named obfuscation this build cannot honour is refused rather than served in the clear.
    if let Some(password) = crate::config::salamander_obfs(inbound.get("streamSettings")) {
        if ferrox_core::hysteria::Salamander::new(&password).is_none() {
            eprintln!(
                "hysteria inbound in {path} names an obfuscation it cannot honour: serves nothing"
            );
            return false;
        }
        obfs_password = password;
    }
    let serve: crate::hysteria::Serve = Arc::new(move |flow| {
        serve_hysteria_flow(flow, freedom);
    });
    let masq = crate::config::masquerade_from_stream(Some(stream));
    thread::spawn(move || {
        crate::hysteria::serve_loop(
            &owned,
            &auths,
            ferrox_core::hysteria::Congestion::Bbr,
            &cert_path,
            &key_path,
            &obfs_password,
            &masq,
            &serve,
        );
    });
    true
}

fn serve_vless_hysteria(mut flow: crate::hysteria::Flow, id: &[u8; 16], freedom: bool) {
    let Some((got, _flow, cmd, target)) = decode_request_bounded(&mut flow) else {
        return;
    };
    if got != *id || !freedom || cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if flow.write_all(&[0, 0]).is_err() {
        return;
    }
    crate::hysteria::relay(&uplink, &flow);
}

fn hysteria_dial_session(vless: &VlessOut) -> Option<crate::hysteria::Dial> {
    let Carrier::Hysteria(config) = &vless.carrier else {
        return None;
    };
    Some(crate::hysteria::Dial {
        host: vless.host.clone(),
        address: vless.address.clone(),
        port: vless.port,
        config: config.clone(),
        roots: vless.hysteria_roots.clone(),
    })
}

fn dial_vless_kcp(
    client: &Connection,
    conn: &Arc<ferrox_core::kcp::Connection>,
    vless: &VlessOut,
    target: &Destination,
) {
    let header = vless_header(&vless.id, 1, target);
    if conn.write(&header).is_err() {
        return;
    }
    let mut io = KcpIo {
        conn: Arc::clone(conn),
    };
    let pump = Pump::over(client, {
        let conn = Arc::clone(conn);
        move |bytes| conn.write(bytes).is_ok()
    });
    let answered = read_vless_response(&mut io).is_some();
    pump.end();
    if !answered {
        return;
    }
    kcp_relay(client, conn);
}

fn serve_vless_kcp_tls(
    conn: &Arc<ferrox_core::kcp::Connection>,
    id: &[u8; 16],
    freedom: bool,
    server: &ferrox_core::tls::TlsServerConfig,
) {
    serve_carried_tls(
        KcpIo {
            conn: Arc::clone(conn),
        },
        id,
        freedom,
        server,
    );
}

fn serve_vless_kcp_reality(
    conn: &Arc<ferrox_core::kcp::Connection>,
    id: &[u8; 16],
    freedom: bool,
    server: &ferrox_core::tls::RealityServerConfig,
) {
    let accepted = ferrox_core::tls::RealityServer::accept(
        server,
        unix_millis(),
        KcpIo {
            conn: Arc::clone(conn),
        },
        Edges::default(),
    );
    let Ok(accepted) = accepted else {
        if server.show {
            eprintln!("REALITY: the cover origin refused the splice");
        }
        return;
    };
    match accepted {
        ferrox_core::tls::RealityAccept::Session(session) => {
            finish_reality(session, None, id, freedom);
        }
        ferrox_core::tls::RealityAccept::Proxied(proxied) => relay_fallback(proxied),
    }
}

fn serve_trojan_kcp(conn: &Arc<ferrox_core::kcp::Connection>, key: &[u8; 56], freedom: bool) {
    let mut io = KcpIo {
        conn: Arc::clone(conn),
    };
    let Some((cmd, target)) = decode_trojan_request(&mut io, key) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    kcp_relay(&uplink, conn);
}

fn kcp_dial_session(
    carrier: &Carrier,
    address: &str,
    port: u16,
) -> Option<Arc<ferrox_core::kcp::Connection>> {
    let Carrier::Kcp(config) = carrier else {
        return None;
    };
    let endpoint = format!("{address}:{port}");
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    ferrox_core::kcp::dial(
        server,
        config.clone(),
        ferrox_core::kcp::fresh_conversation(),
    )
    .ok()
}

fn dial_trojan_kcp(
    client: &Connection,
    conn: &Arc<ferrox_core::kcp::Connection>,
    trojan: &TrojanOut,
    target: &Destination,
) {
    if conn.write(&trojan_header(&trojan.key, 1, target)).is_err() {
        return;
    }
    kcp_relay(client, conn);
}

fn dial_vmess_kcp(
    client: &Connection,
    conn: &Arc<ferrox_core::kcp::Connection>,
    vmess: &VmessOut,
    target: &Destination,
) {
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return;
    };
    if conn.write(&request).is_err() {
        return;
    }
    let mut reader = KcpIo {
        conn: Arc::clone(conn),
    };
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return;
    }
    let (_, writer, close) = kcp_parts(conn);
    crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv, None);
}

fn dial_ss_kcp(
    client: &Connection,
    conn: &Arc<ferrox_core::kcp::Connection>,
    ss: &ShadowsocksOut,
    target: &Destination,
) {
    let mut writer = KcpIo {
        conn: Arc::clone(conn),
    };
    if ferrox_core::shadowsocks2022::Method::parse(&ss.method).is_some() {
        let Some((send, recv)) = crate::shadowsocks2022::client_send_handshake(
            &mut writer,
            &ss.password,
            &ss.method,
            target,
        ) else {
            return;
        };
        let (reader, _, close) = kcp_parts(conn);
        crate::shadowsocks2022::pump_relay_carried(client, reader, writer, &close, send, recv);
        return;
    }
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return;
    };
    let (reader, _, close) = kcp_parts(conn);
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn serve_kcp_loop(address: &str, config: ferrox_core::kcp::Config, serve: &KcpServe) {
    let Some(server) = address.to_socket_addrs().ok().and_then(|mut it| it.next()) else {
        return;
    };
    let Ok(listener) = ferrox_core::kcp::Listener::bind(server, config) else {
        return;
    };
    serve_kcp_each(&listener, serve);
}

fn serve_kcp_each(listener: &ferrox_core::kcp::Listener, serve: &KcpServe) {
    loop {
        let Ok(session) = listener.accept() else {
            continue;
        };
        let serve = Arc::clone(serve);
        std::thread::spawn(move || serve(&session));
    }
}

type KcpServe = Arc<dyn Fn(&Arc<ferrox_core::kcp::Connection>) + Send + Sync>;

type KcpClose = Arc<dyn Fn() + Send + Sync>;

fn kcp_parts(conn: &Arc<ferrox_core::kcp::Connection>) -> (KcpIo, KcpIo, KcpClose) {
    let reader = KcpIo {
        conn: Arc::clone(conn),
    };
    let writer = KcpIo {
        conn: Arc::clone(conn),
    };
    let closer = KcpIo {
        conn: Arc::clone(conn),
    };
    let close: KcpClose = Arc::new(move || closer.close());
    (reader, writer, close)
}

fn serve_trojan_inbound(address: &str, inbound: &Json, freedom: bool) {
    let key = trojan_key(&inbound_password(inbound));
    match inbound_carrier(inbound) {
        Carrier::Kcp(config) => {
            let serve: KcpServe = Arc::new(move |conn| serve_trojan_kcp(conn, &key, freedom));
            let owned = address.to_owned();
            thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        }
        other => spawn_role(
            address,
            Role::Trojan {
                key,
                carrier: other,
                freedom,
            },
        ),
    }
}

fn serve_vmess_inbound(address: &str, inbound: &Json, freedom: bool) {
    let id = inbound_id(inbound);
    match inbound_carrier(inbound) {
        Carrier::Kcp(config) => {
            let serve: KcpServe = Arc::new(move |conn| {
                let (reader, writer, close) = kcp_parts(conn);
                crate::vmess::serve_kcp(reader, writer, &id, freedom, &close);
            });
            let owned = address.to_owned();
            thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        }
        other => spawn_role(
            address,
            Role::Vmess {
                id,
                carrier: other,
                freedom,
            },
        ),
    }
}

/// Bind a dokodemo-door flow and rewrite it to the target its config names, and say how many
/// inbounds it armed. Only the tcp flow is served; a udp-only inbound is refused by name so it
/// never reads as a silent no-op.
fn serve_dokodemo(address: &str, inbound: &Json, out: Option<&Outbound>, label: &str) -> usize {
    let Some(out) = out.cloned() else {
        return 0;
    };
    let Some(dest) = dokodemo_target(inbound) else {
        eprintln!("dokodemo-door rewrite target unusable in {label}: refused, not served");
        return 0;
    };
    if !dokodemo_networks(inbound).contains(&"tcp") {
        eprintln!("dokodemo-door without tcp in {label}: only the tcp flow is served");
        return 0;
    }
    // A raw front has no tcp carrier to arm a chain on, so a masked inbound is refused rather than served unmasked.
    if crate::config::has_tcp_mask(inbound.get("streamSettings")) {
        eprintln!("dokodemo-door in {label} asks for a finalmask tcp chain it cannot arm");
        return 0;
    }
    spawn_role(address, Role::Dokodemo { out, dest });
    1
}

fn inbound_ss_destinations(inbound: &Json, method: &str) -> Vec<(Vec<u8>, SocketAddr)> {
    let Some(parsed) = ferrox_core::shadowsocks2022::Method::parse(method) else {
        return Vec::new();
    };
    if parsed.is_chacha() {
        return Vec::new();
    }
    let Some(settings) = inbound.get("settings") else {
        return Vec::new();
    };
    let Some(list) = settings.get("destinations").and_then(Json::as_arr) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in list {
        let Some(key) = item.get("key").and_then(Json::as_str) else {
            continue;
        };
        let Some(addr) = item.get("address").and_then(Json::as_str) else {
            continue;
        };
        let Some(port) = item.get("port").and_then(Json::as_port) else {
            continue;
        };
        let Some(psk) = ferrox_core::shadowsocks2022::parse_psk_list(key, parsed.key_len())
            .and_then(|mut list| list.pop())
        else {
            continue;
        };
        let Ok(mut addrs) = format!("{addr}:{port}").to_socket_addrs() else {
            continue;
        };
        let Some(target) = addrs.next() else {
            continue;
        };
        out.push((psk, target));
    }
    out
}

fn serve_shadowsocks_inbound(address: &str, inbound: &Json, freedom: bool) {
    let password = inbound_ss_password(inbound);
    let method = inbound_method(inbound);
    let carrier = inbound_carrier(inbound);
    let udp_raw = matches!(carrier, Carrier::Raw(_));
    let udp_address = address.to_owned();
    let udp_password = password.clone();
    let udp_method = method.clone();
    let is_2022 = ferrox_core::shadowsocks2022::Method::parse(&method).is_some();
    let relay_dests = inbound_ss_destinations(inbound, &method);
    if !relay_dests.is_empty() && matches!(carrier, Carrier::Raw(_)) {
        let parsed = ferrox_core::shadowsocks2022::Method::parse(&method);
        let relay_psk = parsed.and_then(|m| {
            ferrox_core::shadowsocks2022::parse_psk_list(&password, m.key_len())
                .and_then(|mut list| list.pop())
        });
        if let (Some(parsed), Some(psk)) = (parsed, relay_psk) {
            let tcp_address = address.to_owned();
            let udp_address = address.to_owned();
            let method = method.clone();
            let udp_dests = relay_dests.clone();
            let udp_psk = psk.clone();
            thread::spawn(move || {
                let Ok(target) = parse_target(&tcp_address) else {
                    return;
                };
                let Ok(listener) = Listener::bind(&target) else {
                    return;
                };
                for stream in listener.incoming().flatten() {
                    crate::shadowsocks2022::serve_relay(stream, &method, &psk, &relay_dests);
                }
            });
            if !parsed.is_chacha() {
                thread::spawn(move || {
                    let Ok(clients) = UdpSocket::bind(&udp_address) else {
                        return;
                    };
                    crate::shadowsocks2022::serve_udp_relay(&clients, parsed, &udp_psk, &udp_dests);
                });
            }
            return;
        }
    }
    match carrier {
        Carrier::Kcp(config) => {
            let serve: KcpServe = Arc::new(move |conn| {
                let (reader, writer, close) = kcp_parts(conn);
                if is_2022 {
                    crate::shadowsocks2022::serve_kcp(
                        reader, writer, &password, &method, freedom, &close,
                    );
                } else {
                    crate::shadowsocks::serve_kcp(
                        reader, writer, &password, &method, freedom, &close,
                    );
                }
            });
            let owned = address.to_owned();
            thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        }
        other => spawn_role(
            address,
            Role::Shadowsocks {
                password,
                method,
                carrier: other,
                freedom,
            },
        ),
    }
    if udp_raw {
        thread::spawn(move || {
            if ferrox_core::shadowsocks2022::Method::parse(&udp_method).is_some() {
                crate::shadowsocks2022::serve_udp(
                    &udp_address,
                    &udp_password,
                    &udp_method,
                    freedom,
                );
            } else {
                crate::shadowsocks::serve_udp(&udp_address, &udp_password, &udp_method, freedom);
            }
        });
    }
}

/// Open the TUN device and spawn the packet handler. Returns true when the device opens.
fn serve_tun_inbound(inbound: &Json, out: &Outbound, _address: &str) -> bool {
    let settings = inbound.get("settings");
    let field = |key| {
        settings
            .as_ref()
            .and_then(|s| s.get(key))
            .or_else(|| inbound.get(key))
    };
    let spec = crate::tun::Spec::new(
        field("name").and_then(Json::as_str),
        field("mtu").and_then(Json::as_u32).map(|m| m as usize),
    );
    let Ok(device) = crate::tun::Device::open(&spec) else {
        eprintln!("tun inbound: {}", crate::tun::refusal_reason(&spec));
        return false;
    };
    let outbound = out.clone();
    let relay: crate::tun::Relay = std::sync::Arc::new(move |conn, dest| {
        serve_connect(conn, &outbound, &dest, Front::Socks, &[]);
    });
    let datagram = out.clone();
    let associate: crate::tun::Associate =
        std::sync::Arc::new(move |conn| serve_socks_udp(conn, &datagram));
    let mut handler = crate::tun::Handler::new(device, relay, associate);
    thread::spawn(move || {
        if let Err(e) = handler.serve() {
            eprintln!("tun handler ended: {e}");
        }
    });
    true
}

struct UdpUplink {
    write: Connection,
    target: SocketAddr,
    done: std::sync::mpsc::Receiver<()>,
}

fn dial_udp_uplink(
    vless: &VlessOut,
    dest: &SocketAddr,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<UdpUplink> {
    if !matches!(vless.carrier, Carrier::Raw(_)) {
        return None;
    }
    if vless.reality.is_some() {
        return None;
    }
    let endpoint = format!("{}:{}", vless.address, vless.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    let mut uplink = dial_or_report(&server)?.with_mask(vless.carrier.tcp_mask());
    // A datagram's destination reaches this tree already resolved by the UDP front, so the header carries that address.
    uplink
        .write_all(&vless_header(&vless.id, 2, &Destination::from(*dest)))
        .ok()?;
    read_vless_response(&mut uplink)?;
    let Ok(read) = uplink.try_clone() else {
        return None;
    };
    let Ok(udp_send) = relay.try_clone() else {
        return None;
    };
    let done = spawn_udp_uplink_reader(read, udp_send, source, *dest);
    Some(UdpUplink {
        write: uplink,
        target: *dest,
        done,
    })
}

fn spawn_udp_uplink_reader(
    read: Connection,
    udp: UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
    target: SocketAddr,
) -> std::sync::mpsc::Receiver<()> {
    RelayPool::global().run(move || {
        let mut read = read;
        let mut buf = udp_buffer();
        let mut reply = Vec::with_capacity(UDP_BUF);
        while let Some(n) = read_udp_datagram(&mut read, &mut buf) {
            let dest = match source.lock() {
                Ok(guard) => *guard,
                Err(_) => None,
            };
            let Some(dest) = dest else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            push_socks_addr(&mut reply, &target);
            reply.extend_from_slice(&buf[..n]);
            let _ = udp.send_to(&reply, dest);
        }
    })
}

struct VmessUdpUplink {
    write: Connection,
    send: crate::vmess::Flow,
    pad: crate::vmess::PadSource,
    target: SocketAddr,
    done: std::sync::mpsc::Receiver<()>,
}

fn dial_vmess_udp_uplink(
    vmess: &VmessOut,
    dest: &SocketAddr,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<VmessUdpUplink> {
    if !matches!(vmess.carrier, Carrier::Raw(_)) {
        return None;
    }
    let endpoint = format!("{}:{}", vmess.address, vmess.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    let uplink = dial_or_report(&server)?.with_mask(vmess.carrier.tcp_mask());
    let (request, send, recv, response_key, response_iv, auth) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, &Destination::from(*dest), 2)?;
    let mut uplink = uplink;
    uplink.write_all(&request).ok()?;
    let mut reader = uplink.try_clone().ok()?;
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return None;
    }
    let udp_send = relay.try_clone().ok()?;
    let done = spawn_vmess_udp_reader(reader, udp_send, source, *dest, recv);
    let pad = crate::vmess::PadSource::fresh()?;
    Some(VmessUdpUplink {
        write: uplink,
        send,
        pad,
        target: *dest,
        done,
    })
}

fn spawn_vmess_udp_reader(
    read: Connection,
    udp: UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
    target: SocketAddr,
    recv: crate::vmess::Flow,
) -> std::sync::mpsc::Receiver<()> {
    RelayPool::global().run(move || {
        let mut read = read;
        let mut recv = recv;
        let mut scratch = Vec::with_capacity(UDP_BUF);
        let mut reply = Vec::with_capacity(UDP_BUF);
        while let Some(chunk) = crate::vmess::read_frame(&mut read, &mut recv, &mut scratch) {
            if chunk.is_empty() {
                break;
            }
            let dest = match source.lock() {
                Ok(guard) => *guard,
                Err(_) => None,
            };
            let Some(dest) = dest else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            push_socks_addr(&mut reply, &target);
            reply.extend_from_slice(chunk);
            let _ = udp.send_to(&reply, dest);
        }
    })
}

struct TrojanUdpUplink {
    write: Connection,
    done: std::sync::mpsc::Receiver<()>,
}

fn dial_trojan_udp_uplink(
    trojan: &TrojanOut,
    dest: &SocketAddr,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<TrojanUdpUplink> {
    if !matches!(trojan.carrier, Carrier::Raw(_)) {
        return None;
    }
    let endpoint = format!("{}:{}", trojan.address, trojan.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    let mut uplink = dial_or_report(&server)?.with_mask(trojan.carrier.tcp_mask());
    uplink
        .write_all(&trojan_header(&trojan.key, 3, &Destination::from(*dest)))
        .ok()?;
    let Ok(read) = uplink.try_clone() else {
        return None;
    };
    let Ok(udp_send) = relay.try_clone() else {
        return None;
    };
    let done = spawn_trojan_uplink_reader(read, udp_send, source);
    Some(TrojanUdpUplink {
        write: uplink,
        done,
    })
}

fn spawn_trojan_uplink_reader(
    read: Connection,
    udp: UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> std::sync::mpsc::Receiver<()> {
    RelayPool::global().run(move || {
        let mut read = read;
        let mut buf = udp_buffer();
        let mut reply = Vec::with_capacity(UDP_BUF);
        while let Some((src_addr, n)) = read_trojan_datagram(&mut read, &mut buf) {
            let dest = match source.lock() {
                Ok(guard) => *guard,
                Err(_) => None,
            };
            let Some(dest) = dest else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            push_socks_addr(&mut reply, &src_addr);
            reply.extend_from_slice(&buf[..n]);
            let _ = udp.send_to(&reply, dest);
        }
    })
}

/// Frames one downlink hands the socket per vectored write: a read rarely holds more, and the
/// run table lives on the stack.
const MUX_RUNS: usize = 32;

fn mux_dial_downlink(mut down: Connection, mut up: Connection, id: u16) {
    if mux_downlink(&mut down, &mut up, id) {
        let _ = up.shutdown(Shutdown::Write);
    }
}

/// One mux session's downlink: every Keep payload of `id` reaches `write` in the order it arrived,
/// a batch of them in one vectored call whose segments are the read buffer's own payload subranges,
/// and `true` reports an End frame so the caller can close its half.
fn mux_downlink(read: &mut impl Read, write: &mut dyn Write, id: u16) -> bool {
    let mut buf: Vec<u8> = Vec::with_capacity(READ_SLICE);
    let mut at = 0;
    let mut runs = [(0usize, 0usize); MUX_RUNS];
    let mut batched = 0;
    'session: loop {
        if at >= buf.len() {
            buf.clear();
            at = 0;
        } else if at > 0 {
            buf.drain(..at);
            at = 0;
        }
        let mut progressed = false;
        let mut ended = false;
        loop {
            match ferrox_core::mux::decode(&buf[at..], ferrox_core::mux::NewTail::Forward) {
                Err(ferrox_core::mux::Error::Short { .. }) => break,
                Err(_) => break 'session,
                Ok((frame, used)) => {
                    at += used;
                    progressed = true;
                    if frame.id != id {
                        continue;
                    }
                    match frame.status {
                        ferrox_core::mux::Status::Keep => {
                            let Some(data) = frame.data else {
                                continue;
                            };
                            if batched == runs.len() {
                                if !write_mux_runs(write, &buf, &runs[..batched]) {
                                    return false;
                                }
                                batched = 0;
                            }
                            let start = data.as_ptr() as usize - buf.as_ptr() as usize;
                            runs[batched] = (start, data.len());
                            batched += 1;
                        }
                        ferrox_core::mux::Status::End => {
                            ended = true;
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        if batched > 0 {
            if !write_mux_runs(write, &buf, &runs[..batched]) {
                return false;
            }
            batched = 0;
        }
        if ended {
            return true;
        }
        if !progressed {
            match read_into_tail(read, &mut buf) {
                Ok(0) | Err(_) => return false,
                Ok(_) => {}
            }
        }
    }
    // A session that ends on a bad frame still delivers the frames decoded before it, as it did when each was written on its own.
    if batched > 0 {
        let _ = write_mux_runs(write, &buf, &runs[..batched]);
    }
    false
}

fn write_mux_runs(write: &mut dyn Write, buf: &[u8], runs: &[(usize, usize)]) -> bool {
    write_all_runs::<MUX_RUNS>(write, buf, runs).is_ok()
}

fn mux_dial_uplink(client: &Connection, uplink: &mut Connection, id: u16) {
    let mut chunk = [0u8; 8192];
    let Ok(mut plain) = client.try_clone() else {
        return;
    };
    let keep = ferrox_core::mux::Outgoing {
        id,
        status: ferrox_core::mux::Status::Keep,
        options: ferrox_core::mux::DATA,
        target: None,
        global_id: None,
    };
    // One header per uplink with only its payload length rewritten; a framed payload goes to the socket uncopied.
    let mut header = Vec::with_capacity(64);
    let at = keep.encode_header_into(&mut header);
    loop {
        match plain.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                keep.patch_payload_len(&mut header, at, n);
                if write_all_parts::<2>(uplink, &[&header[..], &chunk[..n]]).is_err() {
                    break;
                }
            }
        }
    }
    let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
    let _ = end.encode_header_into(&mut header);
    let _ = uplink.write_all(&header);
    let _ = uplink.shutdown(Shutdown::Both);
}

fn request_vless_mux(mut uplink: Connection, vless: &VlessOut) -> Option<Connection> {
    if !matches!(vless.carrier, Carrier::Raw(_)) {
        return None;
    }
    uplink.write_all(&vless_mux_header(&vless.id)).ok()?;
    read_vless_response(&mut uplink)?;
    Some(uplink)
}

fn open_vless_mux(vless: &VlessOut) -> Option<Connection> {
    let endpoint = format!("{}:{}", vless.address, vless.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    request_vless_mux(
        dial_or_report(&server)?.with_mask(vless.carrier.tcp_mask()),
        vless,
    )
}

fn dial_vless_mux(client: &Connection, uplink: Connection, vless: &VlessOut, target: &Destination) {
    let Some(mut uplink) = request_vless_mux(uplink, vless) else {
        return;
    };
    let mut ids = ferrox_core::mux::Ids::new(1);
    let Ok(id) = ids.take() else {
        return;
    };
    let addr = match target {
        Destination::Address(address) => match address.ip() {
            std::net::IpAddr::V4(octets) => ferrox_core::addr::Addr::V4(octets.octets()),
            std::net::IpAddr::V6(octets) => ferrox_core::addr::Addr::V6(octets.octets()),
        },
        Destination::Name(host, _) => ferrox_core::addr::Addr::Name(host.as_bytes()),
    };
    let dest = ferrox_core::mux::Target {
        network: ferrox_core::mux::Network::Tcp,
        port: target.port(),
        addr,
    };
    let new = ferrox_core::mux::Outgoing {
        id,
        status: ferrox_core::mux::Status::New,
        options: 0,
        target: Some(dest),
        global_id: None,
    };
    let mut frame = vec![0u8; new.frame_len(0)];
    let written = new.encode_into(None, &mut frame);
    if uplink.write_all(&frame[..written]).is_err() {
        return;
    }
    let Ok(down) = uplink.try_clone() else {
        return;
    };
    let Ok(up) = client.try_clone() else {
        return;
    };
    let done = RelayPool::global().run(move || mux_dial_downlink(down, up, id));
    mux_dial_uplink(client, &mut uplink, id);
    join(&done);
}

fn dial_vmess_httpupgrade(
    client: &Connection,
    uplink: Connection,
    vmess: &VmessOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    let path = attempt.path;
    let ed = attempt.ed;
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Local);
    };
    let Some((mut reader, write)) =
        crate::httpupgrade::connect(uplink, &vmess.host, path, ed, &request)
    else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
    };
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
    }
    note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
    let Ok(closer) = write.try_clone() else {
        return true;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::vmess::pump_relay_carried(client, reader, write, &close, send, recv, None);
    true
}

fn dial_vmess_grpc(
    client: &Connection,
    uplink: Connection,
    vmess: &VmessOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    let path = attempt.path;
    let Some((mut reader, writer)) = crate::grpc::connect(uplink, &vmess.host, path) else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
    };
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Local);
    };
    if !writer.send(&request) {
        return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
    }
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
    }
    note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv, None);
    true
}

fn dial_vmess_ws(
    client: &Connection,
    uplink: Connection,
    vmess: &VmessOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    let path = attempt.path;
    let ed = attempt.ed;
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Local);
    };
    let Some((reader, writer)) = crate::ws::connect(uplink, &vmess.host, path, ed, &request) else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
    };
    note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::vmess::pump_relay_carried(
        client,
        reader,
        crate::vmess::WsSink::carried(writer),
        &close,
        send,
        recv,
        Some((response_key, response_iv, auth)),
    );
    true
}

fn dial_vmess(
    client: &Connection,
    server: &SocketAddr,
    vmess: &VmessOut,
    target: &Destination,
    ladder: &Ladder,
) {
    if vmess.tls.is_some() {
        dial_vmess_tls(client, server, vmess, target);
        return;
    }
    let params = stream_params(&vmess.carrier);
    let explicit = rung_of(&vmess.carrier);
    if explicit.is_none() {
        let Some(uplink) = dial_or_report(server) else {
            return;
        };
        if dial_vmess_headed(client, uplink, vmess, target) {
            return;
        }
    }
    let start = ladder_start(&vmess.carrier);
    let (rungs, count) = Rung::climb_from(start);
    for rung in &rungs[..count] {
        let attempt = if *rung == Rung::Raw {
            RungAttempt {
                rung: *rung,
                path: "",
                ed: 0,
                explicit: Some(*rung) == explicit,
            }
        } else if let Some((path, ed)) = params {
            RungAttempt {
                rung: *rung,
                path,
                ed,
                explicit: Some(*rung) == explicit,
            }
        } else {
            break;
        };
        let uplink = match dial(server) {
            Ok(uplink) => uplink.with_mask(vmess.carrier.tcp_mask()),
            Err(failure) => {
                let _stop = ladder.record_failure(*rung, &failure);
                note_dial_failure(server, failure);
                return;
            }
        };
        if dial_vmess_rung(client, uplink, vmess, target, &attempt, ladder) {
            return;
        }
    }
}

fn dial_vmess_headed(
    client: &Connection,
    uplink: Connection,
    vmess: &VmessOut,
    target: &Destination,
) -> bool {
    let Carrier::HttpHeader { path } = &vmess.carrier else {
        return true;
    };
    let Some((mut reader, mut write)) = crate::httpheader::connect(uplink, &vmess.host, path)
    else {
        return !Failure::new(Stage::SocketConnected, Kind::Unreachable).worth_retrying();
    };
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return !Failure::new(Stage::SocketConnected, Kind::Local).worth_retrying();
    };
    if write.write_all(&request).is_err() {
        return !Failure::new(Stage::RequestSent, Kind::Dropped).worth_retrying();
    }
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return !Failure::new(Stage::RequestSent, Kind::Dropped).worth_retrying();
    }
    let Ok(closer) = write.try_clone() else {
        return true;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::vmess::pump_relay_carried(client, reader, write, &close, send, recv, None);
    true
}

fn dial_vmess_rung(
    client: &Connection,
    uplink: Connection,
    vmess: &VmessOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    match attempt.rung {
        Rung::Ws => dial_vmess_ws(client, uplink, vmess, target, attempt, ladder),
        Rung::HttpUpgrade => dial_vmess_httpupgrade(client, uplink, vmess, target, attempt, ladder),
        Rung::Grpc => dial_vmess_grpc(client, uplink, vmess, target, attempt, ladder),
        Rung::Xhttp => {
            let rung = attempt.rung;
            let Some((mut reader, writer)) =
                crate::xhttp::connect(uplink, &vmess.host, attempt.path)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            let Some((request, send, recv, response_key, response_iv, auth)) =
                crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Local);
            };
            if !writer.send(&request) {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
            let closer = writer.clone();
            let close: std::sync::Arc<dyn Fn() + Send + Sync> =
                std::sync::Arc::new(move || closer.finish());
            crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv, None);
            true
        }
        Rung::Raw => {
            let rung = attempt.rung;
            if !attempt.explicit {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            let mut uplink = uplink;
            let Some((send, recv, response_key, response_iv, auth)) =
                crate::vmess::client_handshake(&mut uplink, &vmess.id, vmess.cipher, target)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Dropped);
            };
            note_success(ladder, rung, Stage::FirstByte, attempt.explicit);
            crate::vmess::pump_relay(
                client,
                &uplink,
                send,
                recv,
                Some((response_key, response_iv, auth)),
            );
            true
        }
    }
}

fn trojan_header(key: &[u8; 56], cmd: u8, target: &Destination) -> Vec<u8> {
    // key + CRLF + command, then the address and its port, closed by a CRLF.
    let mut header = Vec::with_capacity(63 + target.addr_len());
    header.extend_from_slice(key);
    header.extend_from_slice(b"\r\n");
    header.push(cmd);
    target.push_addr(&mut header, 4, 3);
    header.extend_from_slice(&target.port().to_be_bytes());
    header.extend_from_slice(b"\r\n");
    header
}

fn dial_trojan(
    client: &Connection,
    server: &SocketAddr,
    trojan: &TrojanOut,
    target: &Destination,
    ladder: &Ladder,
) {
    let header = trojan_header(&trojan.key, 1, target);
    if trojan.tls.is_some() {
        dial_trojan_tls(client, server, trojan, &header);
        return;
    }
    let params = stream_params(&trojan.carrier);
    let explicit = rung_of(&trojan.carrier);
    if explicit.is_none() {
        let Some(uplink) = dial_or_report(server) else {
            return;
        };
        if dial_trojan_headed(client, uplink, trojan, target, &header) {
            return;
        }
    }
    let start = ladder_start(&trojan.carrier);
    let (rungs, count) = Rung::climb_from(start);
    for rung in &rungs[..count] {
        let attempt = if *rung == Rung::Raw {
            RungAttempt {
                rung: *rung,
                path: "",
                ed: 0,
                explicit: Some(*rung) == explicit,
            }
        } else if let Some((path, ed)) = params {
            RungAttempt {
                rung: *rung,
                path,
                ed,
                explicit: Some(*rung) == explicit,
            }
        } else {
            break;
        };
        let uplink = match dial(server) {
            Ok(uplink) => uplink.with_mask(trojan.carrier.tcp_mask()),
            Err(failure) => {
                let _stop = ladder.record_failure(*rung, &failure);
                note_dial_failure(server, failure);
                return;
            }
        };
        if dial_trojan_rung(client, uplink, trojan, target, &header, &attempt, ladder) {
            return;
        }
    }
}

fn dial_trojan_headed(
    client: &Connection,
    uplink: Connection,
    trojan: &TrojanOut,
    _target: &Destination,
    header: &[u8],
) -> bool {
    let Carrier::HttpHeader { path } = &trojan.carrier else {
        return true;
    };
    let Some((reader, mut write)) = crate::httpheader::connect(uplink, &trojan.host, path) else {
        return !Failure::new(Stage::SocketConnected, Kind::Unreachable).worth_retrying();
    };
    if write.write_all(header).is_err() {
        return !Failure::new(Stage::RequestSent, Kind::Dropped).worth_retrying();
    }
    crate::proxy::relay_carried(reader, &write, client);
    true
}

fn dial_trojan_rung(
    client: &Connection,
    uplink: Connection,
    trojan: &TrojanOut,
    _target: &Destination,
    header: &[u8],
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    match rung {
        Rung::Ws => {
            let Some((reader, writer)) =
                crate::ws::connect(uplink, &trojan.host, attempt.path, attempt.ed, header)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
            crate::proxy::relay_sink(reader, &writer, client, |_| {});
            true
        }
        Rung::Raw => {
            if !attempt.explicit {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            let mut uplink = uplink;
            if uplink.write_all(header).is_err() {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
            relay(client, &uplink);
            true
        }
        Rung::HttpUpgrade => {
            let Some((reader, write)) =
                crate::httpupgrade::connect(uplink, &trojan.host, attempt.path, attempt.ed, header)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
            crate::proxy::relay_carried(reader, &write, client);
            true
        }
        Rung::Grpc => {
            let Some((reader, writer)) = crate::grpc::connect(uplink, &trojan.host, attempt.path)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            if !writer.send(header) {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
            crate::proxy::relay_sink(reader, &writer, client, crate::grpc::mark_reader_dead);
            true
        }
        Rung::Xhttp => {
            let Some((reader, writer)) = crate::xhttp::connect(uplink, &trojan.host, attempt.path)
            else {
                return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
            };
            if !writer.send(header) {
                return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
            }
            note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
            crate::proxy::relay_sink_drained(reader, &writer, client);
            true
        }
    }
}

// TLS is one attempt with no ladder walk: climbing to plaintext would send what the config asked to encrypt.
fn tls_failure(error: &ferrox_core::tls::TlsError) -> Failure {
    use ferrox_core::tls::TlsError as Tls;
    match error {
        Tls::BadCertificate(_) => Failure::new(Stage::SocketConnected, Kind::Rejected),
        Tls::Timeout => Failure::new(Stage::SocketConnected, Kind::Unreachable),
        Tls::Closed | Tls::NoSharedCipher | Tls::Other(_) => {
            Failure::new(Stage::SocketConnected, Kind::Dropped)
        }
    }
}

fn dial_tls_session(
    server: &SocketAddr,
    cfg: &ferrox_core::tls::TlsConfig,
    mask: Option<&ferrox_core::finalmask::Chain>,
) -> Option<ferrox_core::tls::RustlsProvider<Connection>> {
    let uplink = match dial(server) {
        Ok(uplink) => uplink.with_mask(mask),
        Err(failure) => {
            note_dial_failure(server, failure);
            return None;
        }
    };
    let Ok(mut session) = ferrox_core::tls::RustlsProvider::connect(cfg, uplink) else {
        note_dial_failure(server, Failure::new(Stage::SocketConnected, Kind::Local));
        return None;
    };
    if let Err(error) = session.handshake() {
        note_dial_failure(server, tls_failure(&error));
        return None;
    }
    // Session-shared behind a lock: reads wait one tick, and `TlsHalf::read` spends a grain unlocked.
    if session
        .get_ref()
        .set_read_timeout(Some(SESSION_POLL))
        .is_err()
    {
        note_dial_failure(server, Failure::new(Stage::SocketConnected, Kind::Local));
        return None;
    }
    Some(session)
}

// Splits one established session into halves the carrier cores accept, plus the raw socket their teardown needs.
fn tls_halves(
    session: ferrox_core::tls::RustlsProvider<Connection>,
) -> Option<(ClientHalf, ClientHalf, Arc<Connection>)> {
    let raw = Arc::new(session.get_ref().try_clone().ok()?);
    let shared = Arc::new(Mutex::new(session));
    let reader = TlsHalf {
        session: Arc::clone(&shared),
    };
    let writer = TlsHalf { session: shared };
    Some((reader, writer, raw))
}

// One session, two owners: the carrier accept takes a reader and a writer.
fn session_halves<S>(session: S) -> (TlsHalf<S>, TlsHalf<S>) {
    let shared = Arc::new(Mutex::new(session));
    let reader = TlsHalf {
        session: Arc::clone(&shared),
    };
    (reader, TlsHalf { session: shared })
}

// A dialled TLS session a carrier can drive: split into a reader and a writer over one lock, plus the raw socket the sink shuts down on teardown.
trait Dialed:
    ferrox_core::tls::TlsProvider + ferrox_core::tls::RecordAlignment + Send + 'static
{
    fn into_halves(self) -> Option<(TlsHalf<Self>, TlsHalf<Self>, Arc<Connection>)>
    where
        Self: Sized;
}

impl Dialed for ferrox_core::tls::RustlsProvider<Connection> {
    fn into_halves(self) -> Option<(TlsHalf<Self>, TlsHalf<Self>, Arc<Connection>)> {
        tls_halves(self)
    }
}

impl Dialed
    for ferrox_core::tls::RealityClientSession<ferrox_core::tls::reality::RecordLimiter<Connection>>
{
    fn into_halves(self) -> Option<(TlsHalf<Self>, TlsHalf<Self>, Arc<Connection>)> {
        let raw = Arc::new(self.get_ref().get_ref().try_clone().ok()?);
        let (reader, writer) = session_halves(self);
        Some((reader, writer, raw))
    }
}

fn tls_ws<S: Dialed>(
    server: &SocketAddr,
    session: S,
    host: &str,
    path: &str,
    ed: u32,
    first: &[u8],
) -> Option<(crate::ws::WsReader<TlsHalf<S>>, crate::ws::WsWriter)> {
    let (reader, writer, _) = session.into_halves()?;
    crate::ws::connect_split(reader, writer, host, path, ed, first)
        .or_else(|| tls_unreachable(server))
}

fn tls_unreachable<T>(server: &SocketAddr) -> Option<T> {
    note_dial_failure(
        server,
        Failure::new(Stage::SocketConnected, Kind::Unreachable),
    );
    None
}

// The two header-only carrier lanes: a reader over the shared session and a sink that shuts the raw socket down on teardown.
type Upgraded<S> = (
    crate::httpupgrade::UpReader<TlsHalf<S>>,
    SessionSink<TlsHalf<S>>,
);
type Headed<S> = (
    crate::httpheader::HeadReader<TlsHalf<S>>,
    SessionSink<TlsHalf<S>>,
);

fn tls_httpupgrade<S: Dialed>(
    server: &SocketAddr,
    session: S,
    host: &str,
    path: &str,
    ed: u32,
    first: &[u8],
) -> Option<Upgraded<S>> {
    let (reader, writer, raw) = session.into_halves()?;
    let (reader, writer) = crate::httpupgrade::connect_split(reader, writer, host, path, ed, first)
        .or_else(|| tls_unreachable(server))?;
    Some((reader, SessionSink { half: writer, raw }))
}

fn tls_httpheader<S: Dialed>(
    server: &SocketAddr,
    session: S,
    host: &str,
    path: &str,
) -> Option<Headed<S>> {
    let (reader, writer, raw) = session.into_halves()?;
    let (reader, writer) = crate::httpheader::connect_split(reader, writer, host, path)
        .or_else(|| tls_unreachable(server))?;
    Some((reader, SessionSink { half: writer, raw }))
}

fn tls_grpc<S: Dialed>(
    server: &SocketAddr,
    session: S,
    host: &str,
    path: &str,
) -> Option<(crate::grpc::GrpcReader<TlsHalf<S>>, crate::grpc::GrpcWriter)> {
    let (reader, writer, _) = session.into_halves()?;
    crate::grpc::connect_split(reader, writer, host, path).or_else(|| tls_unreachable(server))
}

fn tls_xhttp<S: Dialed>(
    server: &SocketAddr,
    session: S,
    host: &str,
    path: &str,
) -> Option<(crate::xhttp::Reader<TlsHalf<S>>, crate::xhttp::XhttpWriter)> {
    let (reader, writer, _) = session.into_halves()?;
    crate::xhttp::connect_split(reader, writer, host, path).or_else(|| tls_unreachable(server))
}

// One session, two owners: the pump takes a reader and a writer, and a TLS session cannot split.
#[derive(Debug)]
struct TlsHalf<S> {
    session: Arc<Mutex<S>>,
}

impl<S> Clone for TlsHalf<S> {
    fn clone(&self) -> Self {
        Self {
            session: Arc::clone(&self.session),
        }
    }
}

type ClientHalf = TlsHalf<ferrox_core::tls::RustlsProvider<Connection>>;

impl<S: ferrox_core::tls::TlsProvider> Read for TlsHalf<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let out = self.locked_read(buf);
        if out.as_ref().is_err_and(is_timeout) {
            // Idle polls sleep a grain unlocked so a spinning read cannot starve the write pump.
            thread::sleep(RELAY_POLL);
        }
        out
    }
}

impl<S> TlsHalf<S> {
    fn locked_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>
    where
        S: ferrox_core::tls::TlsProvider,
    {
        let mut session = self
            .session
            .lock()
            .map_err(|_| std::io::Error::other("tls half poisoned"))?;
        session.read(buf)
    }
}

impl<S: ferrox_core::tls::TlsProvider> Write for TlsHalf<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| std::io::Error::other("tls half poisoned"))?;
        session.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| std::io::Error::other("tls half poisoned"))?;
        session.flush()
    }
}

// The server write end for header-only carriers: bytes through the shared session, teardown through the raw socket.
#[derive(Debug, Clone)]
struct SessionSink<H> {
    half: H,
    raw: Arc<Connection>,
}

impl<H: Write> Write for SessionSink<H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.half.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.half.flush()
    }
}

impl<H> CarrierSink for SessionSink<H>
where
    H: Write + Clone + Send + 'static,
{
    fn send(&self, bytes: &[u8]) -> bool {
        let mut half = self.half.clone();
        half.write_all(bytes).is_ok()
    }

    fn close(&self) {
        let _ = self.raw.shutdown(Shutdown::Both);
    }
}

/// The carrier lanes a dialled session rides, shared by the `TLS` and `REALITY` client dials: split the sealed session into a carrier's reader and writer, read the answer, then run the plain relay. `Raw` is the caller's and is left untouched here.
fn ride_carrier<S: Dialed>(
    server: &SocketAddr,
    session: S,
    vless: &VlessOut,
    header: &[u8],
    client: &Connection,
) {
    match &vless.carrier {
        Carrier::Ws { path, ed } => {
            let Some((mut reader, writer)) =
                tls_ws(server, session, &vless.host, path, *ed, header)
            else {
                return;
            };
            if read_vless_response(&mut reader).is_none() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink(reader, &writer, client, |_| {});
        }
        Carrier::HttpUpgrade { path, ed } => {
            let Some((mut reader, sink)) =
                tls_httpupgrade(server, session, &vless.host, path, *ed, header)
            else {
                return;
            };
            if read_vless_response(&mut reader).is_none() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink(reader, &sink, client, |_| {});
        }
        Carrier::Grpc { path } => {
            let Some((mut reader, writer)) = tls_grpc(server, session, &vless.host, path) else {
                return;
            };
            if !writer.send(header) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            if read_vless_response(&mut reader).is_none() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink(reader, &writer, client, crate::grpc::mark_reader_dead);
        }
        Carrier::Xhttp { settings, .. } => {
            let Some((mut reader, writer)) =
                tls_xhttp(server, session, &vless.host, &settings.path)
            else {
                return;
            };
            if !writer.send(header) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            if read_vless_response(&mut reader).is_none() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink_drained(reader, &writer, client);
        }
        Carrier::HttpHeader { path } => {
            let Some((mut reader, mut sink)) = tls_httpheader(server, session, &vless.host, path)
            else {
                return;
            };
            if sink.write_all(header).is_err() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            if read_vless_response(&mut reader).is_none() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink(reader, &sink, client, |_| {});
        }
        Carrier::Raw(_)
        | Carrier::Quic
        | Carrier::Kcp(_)
        | Carrier::Hysteria(_)
        | Carrier::Masque
        | Carrier::Xdrive
        | Carrier::Http
        | Carrier::Unknown { .. } => {}
    }
}

fn dial_vless_tls(
    client: &Connection,
    server: &SocketAddr,
    vless: &VlessOut,
    target: &Destination,
) {
    let Some(cfg) = vless.tls.as_deref() else {
        return;
    };
    let header = vless_header(&vless.id, 1, target);
    let Some(mut session) = dial_tls_session(server, cfg, vless.carrier.tcp_mask()) else {
        return;
    };
    // The session's leg reads the uplink handle it took; un-timed, a parked read outlives the relay that should end it.
    if session
        .get_ref()
        .set_read_timeout(Some(RELAY_POLL))
        .is_err()
    {
        return;
    }
    match &vless.carrier {
        Carrier::Raw(_) => {
            if session.write_all(&header).is_err() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            if read_vless_response(&mut session).is_none() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let Ok(downstream) = client.try_clone() else {
                return;
            };
            if downstream.set_read_timeout(Some(RELAY_POLL)).is_err() {
                return;
            }
            let close_downstream = downstream.try_clone().ok();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                if let Some(downstream) = close_downstream.as_ref() {
                    let _ = downstream.shutdown(Shutdown::Both);
                }
            });
            relay_stream(downstream, session, &close);
        }
        _ => ride_carrier(server, session, vless, &header, client),
    }
}

/// One REALITY dial: TCP, the sealed handshake, the VLESS header, then the relay.
fn dial_vless_reality(
    client: &Connection,
    server: &SocketAddr,
    vless: &VlessOut,
    target: &Destination,
) {
    let Some(cfg) = vless.reality.as_deref() else {
        return;
    };
    let uplink = match dial(server) {
        Ok(uplink) => uplink.with_mask(vless.carrier.tcp_mask()),
        Err(failure) => return note_dial_failure(server, failure),
    };
    let Ok(raw) = uplink.try_clone() else {
        return;
    };
    let now = u32::try_from(unix_millis() / 1000).unwrap_or(u32::MAX);
    let mut session = match ferrox_core::tls::RealityClientSession::connect(
        cfg,
        now,
        ferrox_core::tls::reality::RecordLimiter::new(uplink),
    ) {
        Ok(session) => session,
        Err(error) => {
            return note_dial_failure(
                server,
                Failure::new(
                    Stage::SocketConnected,
                    Kind::of(&std::io::Error::from(error)),
                ),
            );
        }
    };
    // Relay writes complete through reads: bound them to one tick or the first write waits out its answer.
    if session
        .get_ref()
        .get_ref()
        .set_read_timeout(Some(SESSION_POLL))
        .is_err()
    {
        return note_dial_failure(server, Failure::new(Stage::SocketConnected, Kind::Local));
    }
    // The direct switch moves reads onto the raw clone, a handle duplicated before that timeout was armed; arm it to the same tick now that the handshake is done, or an unbounded read holds the shared relay lock forever.
    if raw.set_read_timeout(Some(SESSION_POLL)).is_err() {
        return note_dial_failure(server, Failure::new(Stage::SocketConnected, Kind::Local));
    }
    let header = if vless.flow == crate::vision::FLOW {
        vless_vision_header(&vless.id, 1, target)
    } else {
        vless_header(&vless.id, 1, target)
    };
    match &vless.carrier {
        Carrier::Raw(_) => {
            if session.write_all(&header).is_err() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            // A server may hold its answer until it has payload to send, so the upload runs through the pump while this leg waits, as on every other carrier; a TLS session cannot split, so both legs share it behind one lock until the pump's owner joins and hands it back.
            let shared = Arc::new(Mutex::new(session));
            let mut reader = TlsHalf {
                session: Arc::clone(&shared),
            };
            let pump = Pump::over(client, {
                let mut writer = TlsHalf {
                    session: Arc::clone(&shared),
                };
                move |bytes| writer.write_all(bytes).is_ok()
            });
            let answered = read_vless_response(&mut reader).is_some();
            pump.end();
            if !answered {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            drop(reader);
            let Some(Ok(mut session)) = Arc::into_inner(shared).map(Mutex::into_inner) else {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Local));
            };
            let Ok(downstream) = client.try_clone() else {
                return;
            };
            if downstream.set_read_timeout(Some(RELAY_POLL)).is_err() {
                return;
            }
            let close_downstream = downstream.try_clone().ok();
            let close_raw = raw.try_clone().ok();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                if let Some(downstream) = close_downstream.as_ref() {
                    let _ = downstream.shutdown(Shutdown::Both);
                }
                if let Some(raw) = close_raw.as_ref() {
                    let _ = raw.shutdown(Shutdown::Both);
                }
            });
            if vless.flow == crate::vision::FLOW {
                relay_stream(
                    downstream,
                    crate::vision::Link::new(session, Some(raw), &vless.id),
                    &close,
                );
            } else {
                session.disarm_record_alignment();
                relay_stream(downstream, session, &close);
            }
        }
        _ => ride_carrier(server, session, vless, &header, client),
    }
}

fn dial_trojan_tls(client: &Connection, server: &SocketAddr, trojan: &TrojanOut, header: &[u8]) {
    let Some(cfg) = trojan.tls.as_deref() else {
        return;
    };
    let Some(mut session) = dial_tls_session(server, cfg, trojan.carrier.tcp_mask()) else {
        return;
    };
    // The session's leg reads the uplink handle it took; un-timed, a parked read outlives the relay that should end it.
    if session
        .get_ref()
        .set_read_timeout(Some(RELAY_POLL))
        .is_err()
    {
        return;
    }
    match &trojan.carrier {
        Carrier::Raw(_) => {
            let Ok(downstream) = client.try_clone() else {
                return;
            };
            if downstream.set_read_timeout(Some(RELAY_POLL)).is_err() {
                return;
            }
            if session.write_all(header).is_err() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let close_downstream = downstream.try_clone().ok();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                if let Some(downstream) = close_downstream.as_ref() {
                    let _ = downstream.shutdown(Shutdown::Both);
                }
            });
            relay_stream(downstream, session, &close);
        }
        Carrier::Ws { path, ed } => {
            let Some((reader, writer)) = tls_ws(server, session, &trojan.host, path, *ed, header)
            else {
                return;
            };
            relay_sink(reader, &writer, client, |_| {});
        }
        Carrier::HttpUpgrade { path, ed } => {
            let Some((reader, sink)) =
                tls_httpupgrade(server, session, &trojan.host, path, *ed, header)
            else {
                return;
            };
            relay_sink(reader, &sink, client, |_| {});
        }
        Carrier::Grpc { path } => {
            let Some((reader, writer)) = tls_grpc(server, session, &trojan.host, path) else {
                return;
            };
            if !writer.send(header) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink(reader, &writer, client, crate::grpc::mark_reader_dead);
        }
        Carrier::Xhttp { settings, .. } => {
            let Some((reader, writer)) = tls_xhttp(server, session, &trojan.host, &settings.path)
            else {
                return;
            };
            if !writer.send(header) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink_drained(reader, &writer, client);
        }
        Carrier::HttpHeader { path } => {
            let Some((reader, mut sink)) = tls_httpheader(server, session, &trojan.host, path)
            else {
                return;
            };
            if sink.write_all(header).is_err() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            relay_sink(reader, &sink, client, |_| {});
        }
        Carrier::Quic
        | Carrier::Kcp(_)
        | Carrier::Hysteria(_)
        | Carrier::Masque
        | Carrier::Xdrive
        | Carrier::Http
        | Carrier::Unknown { .. } => {}
    }
}

fn vmess_tls_raw(
    client: &Connection,
    server: &SocketAddr,
    mut session: ferrox_core::tls::RustlsProvider<Connection>,
    vmess: &VmessOut,
    target: &Destination,
) {
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return note_dial_failure(server, Failure::new(Stage::SocketConnected, Kind::Local));
    };
    if session.write_all(&request).is_err() {
        return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
    }
    if !crate::vmess::read_response(&mut session, &response_key, &response_iv, auth) {
        return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
    }
    let Ok(raw) = session.get_ref().try_clone() else {
        return;
    };
    let shared = Arc::new(Mutex::new(session));
    let reader = TlsHalf {
        session: Arc::clone(&shared),
    };
    let writer = SessionSink {
        half: TlsHalf { session: shared },
        raw: Arc::new(raw),
    };
    let closer = writer.clone();
    let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
    crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv, None);
}

fn vmess_tls_carried(
    client: &Connection,
    server: &SocketAddr,
    session: ferrox_core::tls::RustlsProvider<Connection>,
    vmess: &VmessOut,
    target: &Destination,
) {
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return note_dial_failure(server, Failure::new(Stage::SocketConnected, Kind::Local));
    };
    match &vmess.carrier {
        Carrier::Ws { path, ed } => {
            let Some((reader, writer)) = tls_ws(server, session, &vmess.host, path, *ed, &request)
            else {
                return;
            };
            let mut reader = reader;
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let closer = writer.clone();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
            crate::vmess::pump_relay_carried(
                client,
                reader,
                crate::vmess::WsSink::carried(writer),
                &close,
                send,
                recv,
                None,
            );
        }
        Carrier::HttpUpgrade { path, ed } => {
            let Some((mut reader, sink)) =
                tls_httpupgrade(server, session, &vmess.host, path, *ed, &request)
            else {
                return;
            };
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let closer = sink.clone();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
            crate::vmess::pump_relay_carried(client, reader, sink, &close, send, recv, None);
        }
        Carrier::Grpc { path } => {
            let Some((reader, writer)) = tls_grpc(server, session, &vmess.host, path) else {
                return;
            };
            let mut reader = reader;
            if !writer.send(&request) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let closer = writer.clone();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
            crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv, None);
        }
        Carrier::Xhttp { settings, .. } => {
            let Some((reader, writer)) = tls_xhttp(server, session, &vmess.host, &settings.path)
            else {
                return;
            };
            if !writer.send(&request) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let mut reader = reader;
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let closer = writer.clone();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.finish());
            crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv, None);
        }
        Carrier::HttpHeader { path } => {
            let Some((reader, sink)) = tls_httpheader(server, session, &vmess.host, path) else {
                return;
            };
            let (mut reader, mut sink) = (reader, sink);
            if sink.write_all(&request).is_err() {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return note_dial_failure(server, Failure::new(Stage::RequestSent, Kind::Dropped));
            }
            let closer = sink.clone();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
            crate::vmess::pump_relay_carried(client, reader, sink, &close, send, recv, None);
        }
        Carrier::Raw(_)
        | Carrier::Quic
        | Carrier::Kcp(_)
        | Carrier::Hysteria(_)
        | Carrier::Masque
        | Carrier::Xdrive
        | Carrier::Http
        | Carrier::Unknown { .. } => {}
    }
}

fn dial_vmess_tls(
    client: &Connection,
    server: &SocketAddr,
    vmess: &VmessOut,
    target: &Destination,
) {
    let Some(cfg) = vmess.tls.as_deref() else {
        return;
    };
    let Some(session) = dial_tls_session(server, cfg, vmess.carrier.tcp_mask()) else {
        return;
    };
    match &vmess.carrier {
        Carrier::Raw(_) => vmess_tls_raw(client, server, session, vmess, target),
        _ => vmess_tls_carried(client, server, session, vmess, target),
    }
}

fn dial_shadowsocks(
    client: &Connection,
    server: &SocketAddr,
    ss: &ShadowsocksOut,
    target: &Destination,
    ladder: &Ladder,
) {
    let params = stream_params(&ss.carrier);
    let explicit = rung_of(&ss.carrier);
    if explicit.is_none() {
        let Some(uplink) = dial_or_report(server) else {
            return;
        };
        if dial_ss_headed(client, uplink, ss, target) {
            return;
        }
    }
    let start = ladder_start(&ss.carrier);
    let (rungs, count) = Rung::climb_from(start);
    for rung in &rungs[..count] {
        let attempt = if *rung == Rung::Raw {
            RungAttempt {
                rung: *rung,
                path: "",
                ed: 0,
                explicit: Some(*rung) == explicit,
            }
        } else if let Some((path, ed)) = params {
            RungAttempt {
                rung: *rung,
                path,
                ed,
                explicit: Some(*rung) == explicit,
            }
        } else {
            break;
        };
        let uplink = match dial(server) {
            Ok(uplink) => uplink.with_mask(ss.carrier.tcp_mask()),
            Err(failure) => {
                let _stop = ladder.record_failure(*rung, &failure);
                note_dial_failure(server, failure);
                return;
            }
        };
        if dial_ss_rung(client, uplink, ss, target, &attempt, ladder) {
            return;
        }
    }
}

fn dial_ss_headed(
    client: &Connection,
    uplink: Connection,
    ss: &ShadowsocksOut,
    target: &Destination,
) -> bool {
    let Carrier::HttpHeader { path } = &ss.carrier else {
        return true;
    };
    let Some((reader, mut writer)) = crate::httpheader::connect(uplink, &ss.host, path) else {
        return !Failure::new(Stage::SocketConnected, Kind::Unreachable).worth_retrying();
    };
    if ferrox_core::shadowsocks2022::Method::parse(&ss.method).is_some() {
        let Some((send, recv)) = crate::shadowsocks2022::client_send_handshake(
            &mut writer,
            &ss.password,
            &ss.method,
            target,
        ) else {
            return !Failure::new(Stage::RequestSent, Kind::Dropped).worth_retrying();
        };
        let Ok(closer) = writer.try_clone() else {
            return true;
        };
        let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
            let _ = closer.shutdown(Shutdown::Both);
        });
        crate::shadowsocks2022::pump_relay_carried(client, reader, writer, &close, send, recv);
        return true;
    }
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return !Failure::new(Stage::RequestSent, Kind::Dropped).worth_retrying();
    };
    let Ok(closer) = writer.try_clone() else {
        return true;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
    true
}

fn dial_ss_rung(
    client: &Connection,
    uplink: Connection,
    ss: &ShadowsocksOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    match attempt.rung {
        Rung::Raw => {
            if !attempt.explicit {
                return climb_or_hold(ladder, attempt.rung, Stage::RequestSent, Kind::Dropped);
            }
            let mut uplink = uplink;
            if ferrox_core::shadowsocks2022::Method::parse(&ss.method).is_some() {
                let Some((send, recv)) = crate::shadowsocks2022::client_send_handshake(
                    &mut uplink,
                    &ss.password,
                    &ss.method,
                    target,
                ) else {
                    return climb_or_hold(ladder, attempt.rung, Stage::RequestSent, Kind::Dropped);
                };
                note_success(ladder, attempt.rung, Stage::RequestSent, attempt.explicit);
                crate::shadowsocks2022::pump_relay(client, &uplink, send, recv);
                return true;
            }
            let Some((send, recv)) = crate::shadowsocks::client_send_handshake(
                &mut uplink,
                &ss.password,
                &ss.method,
                target,
            ) else {
                return climb_or_hold(ladder, attempt.rung, Stage::RequestSent, Kind::Dropped);
            };
            note_success(ladder, attempt.rung, Stage::RequestSent, attempt.explicit);
            crate::shadowsocks::pump_relay(client, &uplink, send, recv);
            true
        }
        Rung::Ws => dial_ss_ws(client, uplink, ss, target, attempt, ladder),
        Rung::HttpUpgrade => dial_ss_httpupgrade(client, uplink, ss, target, attempt, ladder),
        Rung::Grpc => dial_ss_grpc(client, uplink, ss, target, attempt, ladder),
        Rung::Xhttp => dial_ss_xhttp(client, uplink, ss, target, attempt, ladder),
    }
}

fn dial_ss_ws(
    client: &Connection,
    uplink: Connection,
    ss: &ShadowsocksOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    let Some((reader, mut writer)) = crate::ws::connect(uplink, &ss.host, attempt.path, 0, &[])
    else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
    };
    if ferrox_core::shadowsocks2022::Method::parse(&ss.method).is_some() {
        let Some((send, recv)) = crate::shadowsocks2022::client_send_handshake(
            &mut writer,
            &ss.password,
            &ss.method,
            target,
        ) else {
            return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
        };
        note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
        let closer = writer.clone();
        let close: std::sync::Arc<dyn Fn() + Send + Sync> =
            std::sync::Arc::new(move || closer.close());
        crate::shadowsocks2022::pump_relay_carried(client, reader, writer, &close, send, recv);
        return true;
    }
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
    };
    note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
    true
}

fn dial_ss_httpupgrade(
    client: &Connection,
    uplink: Connection,
    ss: &ShadowsocksOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    // Sealed into a buffer rather than onto the socket, so the carrier writes the request packet with the `GET`: `?ed` takes the `101` off the round trip and `ed=0` still sends the whole handshake in one write.
    let mut packet = Vec::new();
    if ferrox_core::shadowsocks2022::Method::parse(&ss.method).is_some() {
        let Some((send, recv)) = crate::shadowsocks2022::client_send_handshake(
            &mut packet,
            &ss.password,
            &ss.method,
            target,
        ) else {
            return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Local);
        };
        let Some((reader, writer)) =
            crate::httpupgrade::connect(uplink, &ss.host, attempt.path, attempt.ed, &packet)
        else {
            return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
        };
        note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
        let Ok(closer) = writer.try_clone() else {
            return true;
        };
        let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
            let _ = closer.shutdown(Shutdown::Both);
        });
        crate::shadowsocks2022::pump_relay_carried(client, reader, writer, &close, send, recv);
        return true;
    }
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut packet, &ss.password, &ss.method, target)
    else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Local);
    };
    let Some((reader, writer)) =
        crate::httpupgrade::connect(uplink, &ss.host, attempt.path, attempt.ed, &packet)
    else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
    };
    note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
    let Ok(closer) = writer.try_clone() else {
        return true;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
    true
}

fn dial_ss_grpc(
    client: &Connection,
    uplink: Connection,
    ss: &ShadowsocksOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    let Some((reader, mut writer)) = crate::grpc::connect(uplink, &ss.host, attempt.path) else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
    };
    if ferrox_core::shadowsocks2022::Method::parse(&ss.method).is_some() {
        let Some((send, recv)) = crate::shadowsocks2022::client_send_handshake(
            &mut writer,
            &ss.password,
            &ss.method,
            target,
        ) else {
            return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
        };
        note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
        let closer = writer.clone();
        let close: std::sync::Arc<dyn Fn() + Send + Sync> =
            std::sync::Arc::new(move || closer.close());
        crate::shadowsocks2022::pump_relay_carried(client, reader, writer, &close, send, recv);
        return true;
    }
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
    };
    note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
    true
}

fn dial_ss_xhttp(
    client: &Connection,
    uplink: Connection,
    ss: &ShadowsocksOut,
    target: &Destination,
    attempt: &RungAttempt<'_>,
    ladder: &Ladder,
) -> bool {
    let rung = attempt.rung;
    let Some((reader, mut writer)) = crate::xhttp::connect(uplink, &ss.host, attempt.path) else {
        return climb_or_hold(ladder, rung, Stage::SocketConnected, Kind::Unreachable);
    };
    if ferrox_core::shadowsocks2022::Method::parse(&ss.method).is_some() {
        let Some((send, recv)) = crate::shadowsocks2022::client_send_handshake(
            &mut writer,
            &ss.password,
            &ss.method,
            target,
        ) else {
            return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
        };
        note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
        let closer = writer.clone();
        let close: std::sync::Arc<dyn Fn() + Send + Sync> =
            std::sync::Arc::new(move || closer.finish());
        crate::shadowsocks2022::pump_relay_carried(client, reader, writer, &close, send, recv);
        return true;
    }
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return climb_or_hold(ladder, rung, Stage::RequestSent, Kind::Dropped);
    };
    note_success(ladder, rung, Stage::RequestSent, attempt.explicit);
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
    true
}

fn serve_trojan(mut stream: Connection, key: &[u8; 56], freedom: bool) {
    // Bound only the opening request read to a wall-clock budget, then restore the blocking relay reads behind it.
    let budget = budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let decoded = {
        let mut bounded = HandshakeDeadline {
            inner: &mut stream,
            until: Instant::now() + budget,
        };
        decode_trojan_request(&mut bounded, key)
    };
    let _ = stream.set_read_timeout(None);
    let Some((cmd, target)) = decoded else {
        return;
    };
    if !freedom {
        return;
    }
    if cmd == 3 {
        return serve_trojan_udp(stream);
    }
    if cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    relay(&stream, &uplink);
}

fn serve_trojan_udp(stream: Connection) {
    let Ok(udp4) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    let udp6 = UdpSocket::bind("[::]:0").ok();
    for sock in [&udp4].into_iter().chain(udp6.as_ref()) {
        if sock.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
    }
    let mut stream = stream;
    let Ok(tcp_read) = stream.try_clone() else {
        return;
    };
    let Ok(udp4_send) = udp4.try_clone() else {
        return;
    };
    let udp6_send = match &udp6 {
        Some(sock) => {
            let Ok(clone) = sock.try_clone() else {
                return;
            };
            Some(clone)
        }
        None => None,
    };
    let done = Arc::new(AtomicBool::new(false));
    let done_in = Arc::clone(&done);
    let forward = move || {
        let mut tcp_read = tcp_read;
        let mut buf = udp_buffer();
        while let Some((dest, n)) = read_trojan_datagram(&mut tcp_read, &mut buf) {
            let sent = if dest.is_ipv6() {
                match &udp6_send {
                    Some(sock) => sock.send_to(&buf[..n], dest).is_ok(),
                    None => true,
                }
            } else {
                udp4_send.send_to(&buf[..n], dest).is_ok()
            };
            if !sent {
                break;
            }
        }
        done_in.store(true, Ordering::Relaxed);
    };
    let replied = RelayPool::global().run(forward);
    let mut buf = udp_buffer();
    let mut trojan_head = Vec::with_capacity(32);
    loop {
        if done.load(Ordering::Relaxed) {
            break;
        }
        let mut live = pump_trojan_replies(&udp4, &mut stream, &mut buf, &done, &mut trojan_head);
        if let Some(sock) = &udp6 {
            live &= pump_trojan_replies(sock, &mut stream, &mut buf, &done, &mut trojan_head);
        }
        if !live {
            break;
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(Shutdown::Both);
    join(&replied);
}

fn pump_trojan_replies(
    udp: &UdpSocket,
    stream: &mut Connection,
    buf: &mut [u8],
    done: &AtomicBool,
    head: &mut Vec<u8>,
) -> bool {
    match udp.recv_from(buf) {
        Ok((n, src)) => {
            if n == 0 {
                return true;
            }
            write_trojan_datagram(stream, &src, &buf[..n], head)
        }
        Err(error) if is_timeout(&error) => !done.load(Ordering::Relaxed),
        Err(_) => false,
    }
}

fn serve_trojan_ws(stream: Connection, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_sink(reader, &writer, &uplink, |_| {});
}

fn serve_trojan_httpupgrade(stream: Connection, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, write)) = crate::httpupgrade::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_carried(reader, &write, &uplink);
}

fn serve_trojan_grpc(stream: Connection, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, writer)) = crate::grpc::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = under_handshake(&mut reader, |read| decode_trojan_request(read, key))
    else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_sink(reader, &writer, &uplink, crate::grpc::mark_reader_dead);
}

fn serve_trojan_xhttp(stream: Connection, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_sink_drained(reader, &writer, &uplink);
}

fn serve_trojan_httpheader(stream: Connection, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, write)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_carried(reader, &write, &uplink);
}

fn serve_socks(mut client: Connection, out: &Outbound) {
    // Foxy grants only after its tunnel opens; a doubled grant reads as ten bytes of tunnel data.
    let Some((cmd, asked)) = socks_target(&mut client, !matches!(out, Outbound::Foxy(_))) else {
        return;
    };
    if cmd == 3 {
        return serve_socks_udp(client, out);
    }
    serve_connect(client, out, &asked, Front::Socks, &[]);
}

/// One tunnel request from either front: SOCKS or HTTP CONNECT; the Foxy lane grants after its tunnel opens.
fn serve_connect(
    mut client: Connection,
    out: &Outbound,
    asked: &Destination,
    front: Front,
    prefix: &[u8],
) {
    if let Outbound::Foxy(foxy) = out {
        return serve_foxy_front(client, foxy, asked, front, prefix);
    }
    let (address, port) = match out {
        Outbound::Vless(vless) => (vless.address.clone(), vless.port),
        Outbound::Vmess(vmess) => (vmess.address.clone(), vmess.port),
        Outbound::Trojan(trojan) => (trojan.address.clone(), trojan.port),
        Outbound::Shadowsocks(shadowsocks) => (shadowsocks.address.clone(), shadowsocks.port),
        Outbound::Http(http) => (http.address.clone(), http.port),
        Outbound::Foxy(_) => return,
        Outbound::Freedom => {
            // Nothing carries the destination onward, so this lane is the one that has to look it up.
            let Some(target) = asked.socket() else {
                return;
            };
            let Some(mut upstream) = dial_or_report(&target) else {
                return;
            };
            if !prefix.is_empty() && upstream.write_all(prefix).is_err() {
                return;
            }
            relay(&client, &upstream);
            return;
        }
    };
    if !prefix.is_empty() {
        // A protocol outbound handshakes over the client's own bytes, so a consumed head has nowhere to go.
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
        return;
    }
    if let Outbound::Vless(vless) = out {
        if matches!(vless.carrier, Carrier::Quic) {
            if !vless.mux {
                crate::quic::dial_pooled(
                    &client,
                    &crate::quic::QuicDial {
                        id: vless.id,
                        host: vless.host.clone(),
                        address: vless.address.clone(),
                        port: vless.port,
                        upstream: None,
                        roots: vless.quic_roots.clone(),
                    },
                    asked,
                );
            }
            return;
        }
        if matches!(vless.carrier, Carrier::Kcp(_)) && !vless.mux {
            if let Some(session) = kcp_dial_session(&vless.carrier, &vless.address, vless.port) {
                dial_vless_kcp(&client, &session, vless, asked);
            }
            return;
        }
        if matches!(vless.carrier, Carrier::Hysteria(_)) && !vless.mux {
            if let Some(dial) = hysteria_dial_session(vless) {
                crate::hysteria::dial_vless(&client, &dial, &vless.id, asked);
            }
            return;
        }
    }
    if let Outbound::Vmess(vmess) = out {
        if matches!(vmess.carrier, Carrier::Kcp(_)) {
            if let Some(session) = kcp_dial_session(&vmess.carrier, &vmess.address, vmess.port) {
                dial_vmess_kcp(&client, &session, vmess, asked);
            }
            return;
        }
    }
    if let Outbound::Trojan(trojan) = out {
        if matches!(trojan.carrier, Carrier::Kcp(_)) {
            if let Some(session) = kcp_dial_session(&trojan.carrier, &trojan.address, trojan.port) {
                dial_trojan_kcp(&client, &session, trojan, asked);
            }
            return;
        }
    }
    if let Outbound::Shadowsocks(ss) = out {
        if matches!(ss.carrier, Carrier::Kcp(_)) {
            if let Some(session) = kcp_dial_session(&ss.carrier, &ss.address, ss.port) {
                dial_ss_kcp(&client, &session, ss, asked);
            }
            return;
        }
    }
    let endpoint = format!("{address}:{port}");
    let server = endpoint.to_socket_addrs().ok().and_then(|mut it| it.next());
    let Some(server) = server else { return };
    dial_socks_outbound(&client, out, &server, asked);
}

fn dial_socks_outbound(
    client: &Connection,
    out: &Outbound,
    server: &SocketAddr,
    target: &Destination,
) {
    let ladder = Ladder::global();
    match out {
        Outbound::Vless(vless) => {
            if vless.mux {
                let Some(uplink) = dial_or_report(server) else {
                    return;
                };
                dial_vless_mux(client, uplink, vless, target);
            } else {
                dial_vless(client, server, vless, target, ladder);
            }
        }
        Outbound::Vmess(vmess) => dial_vmess(client, server, vmess, target, ladder),
        Outbound::Trojan(trojan) => dial_trojan(client, server, trojan, target, ladder),
        Outbound::Shadowsocks(shadowsocks) => {
            dial_shadowsocks(client, server, shadowsocks, target, ladder);
        }
        Outbound::Http(http) => {
            dial_http_outbound(client, server, http, target, ladder);
        }
        Outbound::Foxy(_) | Outbound::Freedom => {}
    }
}

/// The split-tunnel list: targets this lane does not carry, which leave by the plain dial.
fn foxy_splits(foxy: &FoxyOut, asked: &Destination) -> bool {
    foxy.direct_ports.contains(&asked.port())
        || foxy
            .direct_suffixes
            .iter()
            .any(|suffix| asked.host().to_ascii_lowercase().ends_with(suffix))
}

fn foxy_socks_reply(reply: u8) -> [u8; 10] {
    [5, reply, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// Edges past the first a refusal may try: the reference's count, and the most a flow is worth waiting for.
const MAX_FOXY_ALTERNATES: usize = 3;

/// The renewal thread: one per lane on the clock the pass names, stopping once the account itself is refused.
fn start_renewal(account: std::sync::Arc<crate::foxy_account::Account>) {
    thread::spawn(move || {
        let mut attempt = 0u32;
        loop {
            thread::sleep(account.renews_in());
            let Err(denied) = account.renew() else {
                attempt = 0;
                continue;
            };
            // A refused token is the only end: a rate limit, a challenge or an unreachable plane is asked again on the plane's own pause, since the pass it stands over keeps expiring meanwhile.
            if denied.is_final() {
                return;
            }
            let pause = crate::foxy_account::renewal_gap(&denied, attempt, account.pass_left());
            attempt = attempt.saturating_add(1);
            eprintln!(
                "foxy: the pass could not be replaced ({denied}), asking again in {}s",
                pause.as_secs()
            );
            thread::sleep(pause);
        }
    });
}

/// First bytes of each direction behind `FOXY_DEBUG`, so a tunnel that answers TLS with plaintext names itself.
fn debug_bytes(direction: &str, buf: &[u8]) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        let end = buf.len().min(32);
        eprintln!(
            "foxy-debug: {direction} first {end} B: {:02x?}",
            &buf[..end]
        );
    }
}

/// Lane trace behind `FOXY_DEBUG`: edge, carrier and outcome per dial, so a stall names where it stopped.
fn debug_lane(edge: &ferrox_core::foxy::Candidate, carrier: crate::foxy::Carrier, what: &str) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: {} {:?} {what}", edge.authority(), carrier);
    }
}

/// Relay totals behind `FOXY_DEBUG`: which direction ended, after how many bytes, on what error kind.
fn debug_relay(direction: &str, moved: u64, error: Option<std::io::ErrorKind>) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: relay {direction} ended after {moved} B on {error:?}");
    }
}

/// Which byte front a tunnel answers: the grant and refusal render per front, the tunnel loop does not.
#[derive(Debug, Clone, Copy)]
enum Front {
    Socks,
    Http,
}

impl Front {
    fn grant_line(self) -> Vec<u8> {
        match self {
            Self::Socks => foxy_socks_reply(0).to_vec(),
            Self::Http => b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
        }
    }
    fn direct_grant(self) -> Option<&'static [u8]> {
        match self {
            Self::Socks => None,
            Self::Http => Some(b"HTTP/1.1 200 Connection established\r\n\r\n"),
        }
    }
    fn refusal(self, code: u8) -> Vec<u8> {
        match self {
            Self::Socks => foxy_socks_reply(code).to_vec(),
            Self::Http => b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n".to_vec(),
        }
    }
}

/// An opened Foxy route: a tunnel that carries its own pooled stream, a direct dial, a refusal code, or nothing to say.
enum FoxyOpen {
    /// The lane carries the pool entry it owes, so the flow that ends it is the flow that pays the pool back.
    Tunnel(Box<crate::foxy::Tunnel>, ferrox_core::foxy::Candidate),
    Direct(SocketAddr),
    Refused(u8),
    Silent,
}

/// Whether a flow may dial yet: inside the curve it is refused locally, another attempt only extends the limit.
fn edge_limited(until: &AtomicU64, now: u64) -> bool {
    until.load(Ordering::Relaxed) > now
}

/// Records one limited attempt and returns the next allowed dial, climbing the curve instead of hammering.
fn note_limited(strikes: &AtomicU32, until: &AtomicU64, now: u64) -> u64 {
    let wait = ferrox_core::foxy::refusal_backoff(strikes.fetch_add(1, Ordering::Relaxed));
    let at = now.saturating_add(wait.as_secs());
    until.store(at, Ordering::Relaxed);
    at
}

/// A working tunnel clears the limit: the curve restarts instead of punishing later flows for an old limit.
fn clear_limited(strikes: &AtomicU32, until: &AtomicU64) {
    strikes.store(0, Ordering::Relaxed);
    until.store(0, Ordering::Relaxed);
}

/// Whether the exit probe names a real pin a disposable tunnel can answer: no probe, or `REC`, needs none.
fn exit_needs_probe(foxy: &FoxyOut) -> bool {
    foxy.exit_probe.is_some()
        && !foxy
            .country
            .eq_ignore_ascii_case(ferrox_core::foxy::catalog::RECOMMENDED)
}

/// Given each edge's probe answer in dial order — `None` carried no probe, `Some(true)` exits the pinned country, `Some(false)` exits elsewhere — the index to prefer, or `None` to keep the label order.
#[must_use]
fn pick_verified_edge(probes: &[Option<bool>]) -> Option<usize> {
    probes
        .iter()
        .position(|answer| matches!(answer, Some(true)))
}

/// Whether the answers read so far already fix the pick: once an edge honours the pin, a later probe cannot un-prefer it, so the walk is settled and every probe past here is dead work.
#[must_use]
fn probe_settled(probes: &[Option<bool>]) -> bool {
    pick_verified_edge(probes).is_some()
}

/// Whether any edge answered a probe at all: none did means this runner cannot dial the probe tunnel, so stop trying.
#[must_use]
fn probes_reachable(probes: &[Option<bool>]) -> bool {
    probes.iter().any(Option::is_some)
}

/// What a finished probe sweep concluded: the edge that honoured the pin, no probe reachable from here, or every reachable edge answering a different country than the pin.
#[derive(Debug, PartialEq, Eq)]
enum Sweep {
    Agreed(usize),
    Unreachable,
    Refuted,
}

/// The verdict of a sweep, in the order the caller acts on it: a pick wins, an unreachable probe set stops the probes, and a set that answered and agreed with none is itself the answer.
#[must_use]
fn sweep_verdict(probes: &[Option<bool>]) -> Sweep {
    if let Some(at) = pick_verified_edge(probes) {
        return Sweep::Agreed(at);
    }
    if probes_reachable(probes) {
        Sweep::Refuted
    } else {
        Sweep::Unreachable
    }
}

/// The exit country one edge really hands back: a disposable H3 tunnel to the probe authority, asked for the trace, then dropped, which is what gives its pooled stream back. It never rides a flow's own tunnel, so a per-target carrier is left intact; `None` means this runner could not carry or read the trace here. The probe is a probe, so its dial gets the probe budget rather than a named carrier's full handshake: a lane whose UDP is blackholed has to say so before the first flow's client gives up.
fn probe_edge_exit(
    foxy: &FoxyOut,
    edge: &ferrox_core::foxy::Candidate,
    authority: &str,
) -> Option<String> {
    let pass = foxy
        .account
        .as_ref()
        .map_or_else(|| foxy.pass.clone(), |account| account.current());
    let dial = crate::foxy::FoxyDial {
        host: edge.host.clone(),
        port: edge.port,
        address: foxy.edge_address,
        carrier: crate::foxy::Carrier::H3,
        upstream: foxy.upstream.clone(),
        roots: foxy.roots.clone(),
        pins: foxy.pins.clone(),
        pass,
    };
    let quic_dial = foxy_quic_dial(foxy, edge);
    let quic = crate::quic::pooled_stream_within(&quic_dial, budgets::carrier_probe())?;
    // The lease goes into the open and comes back with the lane: whoever ends the flow hands the pool entry over, and a probe that ends early ends with it.
    let opened = crate::foxy::Tunnel::open(&dial, authority, Some(quic));
    match opened {
        Ok(mut tunnel) => {
            let seen = foxy_exit_country(&mut tunnel, foxy);
            drop(tunnel);
            seen
        }
        Err(_) => None,
    }
}

/// The pinned-country edge that really exits in the pin, chosen once per lane over disposable probes and cached so every carrier rides it. The walk stops at the first edge that honours the pin, since a later probe cannot change that pick. Falls back to the label order when no edge agrees, records the truth when one cannot, and stops probing when none can be reached here.
fn verify_exit(foxy: &FoxyOut) {
    if !exit_needs_probe(foxy)
        || foxy.probe_unavailable.load(Ordering::Relaxed)
        || edge_limited(&foxy.exit_refuted_until, now_secs())
    {
        return;
    }
    if foxy.verified.lock().is_ok_and(|kept| kept.is_some()) {
        return;
    }
    let Some(probe) = foxy.exit_probe.as_deref() else {
        return;
    };
    let Some(host) = probe.split('/').next() else {
        return;
    };
    let authority = format!("{host}:80");
    let order = ferrox_core::foxy::catalog::tier(
        &foxy.candidates,
        &foxy.country,
        &foxy.city,
        MAX_FOXY_ALTERNATES,
    );
    let edges = ferrox_core::foxy::dial_order(
        &order,
        &foxy.country,
        foxy.stored.as_ref(),
        MAX_FOXY_ALTERNATES,
    );
    let pin = foxy.country.to_ascii_uppercase();
    let mut flags: Vec<Option<bool>> = Vec::with_capacity(edges.len());
    for edge in &edges {
        let agreed = probe_edge_exit(foxy, edge, &authority).map(|seen| {
            let agrees = exit_agrees(&foxy.country, &seen);
            if !agrees {
                debug_lane(
                    edge,
                    crate::foxy::Carrier::H3,
                    &format!("exit {seen} differs from pin {pin}"),
                );
            }
            agrees
        });
        flags.push(agreed);
        if probe_settled(&flags) {
            break;
        }
    }
    match sweep_verdict(&flags) {
        Sweep::Agreed(at) => {
            if let Ok(mut kept) = foxy.verified.lock() {
                *kept = Some(edges[at].clone());
            }
        }
        // The pin is not what this runner gets out; re-sweeping it per flow would only buy the same refusal again.
        Sweep::Refuted => foxy
            .exit_refuted_until
            .store(now_secs() + CARRIER_DEAD_SECS, Ordering::Relaxed),
        Sweep::Unreachable => foxy.probe_unavailable.store(true, Ordering::Relaxed),
    }
}

/// Shared loop: first answer wins, a refused pass stops every carrier and edge; the grant belongs to the front.
fn foxy_open(foxy: &FoxyOut, asked: &Destination) -> FoxyOpen {
    if foxy
        .unauthenticated
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return FoxyOpen::Refused(0x01);
    }
    if edge_limited(&foxy.limited_until, now_secs()) {
        return FoxyOpen::Refused(0x01);
    }
    if foxy_splits(foxy, asked) {
        let Some(target) = asked.socket() else {
            return FoxyOpen::Silent;
        };
        return FoxyOpen::Direct(target);
    }
    let target = asked.authority();
    verify_exit(foxy);
    let preferred = foxy.preferred_edge();
    let order = ferrox_core::foxy::catalog::tier(
        &foxy.candidates,
        &foxy.country,
        &foxy.city,
        MAX_FOXY_ALTERNATES,
    );
    let mut last = None;
    let order = ferrox_core::foxy::dial_order(
        &order,
        &foxy.country,
        preferred.as_ref(),
        MAX_FOXY_ALTERNATES,
    );
    for edge in foxy.live_dials(&order) {
        let pass = foxy
            .account
            .as_ref()
            .map_or_else(|| foxy.pass.clone(), |account| account.current());
        for carrier in foxy.carrier.order() {
            // As on UDP: a silent carrier is left alone for the window, not probed per flow.
            if foxy.carrier_unanswered(&edge, carrier) {
                continue;
            }
            let dial = crate::foxy::FoxyDial {
                host: edge.host.clone(),
                port: edge.port,
                address: foxy.edge_address,
                carrier,
                upstream: foxy.upstream.clone(),
                roots: foxy.roots.clone(),
                pins: foxy.pins.clone(),
                pass: pass.clone(),
            };
            // A named carrier gets the full budget; an `auto` walk is a probe and gets the probe's.
            let quic = match carrier {
                crate::foxy::Carrier::H3 => crate::quic::pooled_stream_within(
                    &foxy_quic_dial(foxy, &edge),
                    if foxy.carrier == crate::foxy::Carrier::H3 {
                        crate::quic::HANDSHAKE_TIMEOUT
                    } else {
                        budgets::carrier_probe()
                    },
                ),
                _ => None,
            };
            match crate::foxy::Tunnel::open(&dial, &target, quic) {
                Ok(tunnel) => {
                    debug_lane(&edge, carrier, &format!("opened for {target}"));
                    foxy.unauthenticated
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    clear_limited(&foxy.limited_strikes, &foxy.limited_until);
                    foxy.carrier_answered(&edge, carrier);
                    return FoxyOpen::Tunnel(Box::new(tunnel), edge.clone());
                }
                Err(failure) => {
                    debug_lane(&edge, carrier, &failure.to_string());
                    // A refused pass is the pass, not the edge: all carriers answer it the same.
                    if let ferrox_core::foxy::Failure::Rejected(status) = failure {
                        if ferrox_core::foxy::pass_is_rejected(status) {
                            foxy.unauthenticated
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                        // Account-wide limit: one attempt per flow, the rest wait out the curve.
                        if status == 429 {
                            note_limited(&foxy.limited_strikes, &foxy.limited_until, now_secs());
                            break;
                        }
                    }
                    // A status is the edge speaking, so only a silent carrier is remembered as dead.
                    foxy.remember_unanswered(&edge, carrier, failure);
                    last = Some(failure);
                    // A refused chain is the edge's own certificate, not the carrier's: HTTP/2 and HTTP/1.1 would answer a trust failure exactly as this one did.
                    if matches!(failure, ferrox_core::foxy::Failure::Untrusted) {
                        break;
                    }
                }
            }
        }
    }
    FoxyOpen::Refused(last.map_or(0x01, crate::foxy::refusal_reply))
}

/// The Foxy half of either front: CONNECT grants, plain HTTP forwards its head, a split target dials direct.
fn serve_foxy_front(
    mut client: Connection,
    foxy: &FoxyOut,
    asked: &Destination,
    front: Front,
    prefix: &[u8],
) {
    match foxy_open(foxy, asked) {
        FoxyOpen::Tunnel(tunnel, edge) => {
            let mut tunnel = *tunnel;
            if prefix.is_empty() && client.write_all(&front.grant_line()).is_err() {
                return;
            }
            if !prefix.is_empty() && tunnel.write_all(prefix).is_err() {
                return;
            }
            // One lock serves both directions: a blocking read would hold the writer, hence the bounded quantum.
            let _ = tunnel.set_read_quantum(budgets::relay_quantum());
            let tunnel = std::sync::Arc::new(std::sync::Mutex::new(tunnel));
            let started = Instant::now();
            relay_tunnel(&client, &tunnel);
            foxy.note_edge_end(&edge, started.elapsed());
        }
        FoxyOpen::Direct(target) => {
            let Some(mut upstream) = dial_or_report(&target) else {
                return;
            };
            if prefix.is_empty() {
                if let Some(grant) = front.direct_grant() {
                    if client.write_all(grant).is_err() {
                        return;
                    }
                }
            }
            if !prefix.is_empty() && upstream.write_all(prefix).is_err() {
                return;
            }
            relay(&client, &upstream);
        }
        FoxyOpen::Refused(code) => {
            let _ = client.write_all(&front.refusal(code));
        }
        FoxyOpen::Silent => {}
    }
}

const HTTP_HEAD_LIMIT: usize = 8192;

/// An HTTP proxy request: a tunnel to open, or a head to forward to a raw uplink.
enum ProxyRequest {
    Connect(Destination),
    Forward(Destination, Vec<u8>),
}

/// CONNECT tunnels; absolute- and origin-form forward the head with its line rewritten to origin-form.
fn http_proxy_request(head: &[u8]) -> Option<ProxyRequest> {
    let line = head.split(|byte| *byte == b'\n').next()?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|byte| *byte == b' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next().unwrap_or(b"HTTP/1.1");
    if method.eq_ignore_ascii_case(b"CONNECT") {
        return authority_target(connect_authority(target)).map(ProxyRequest::Connect);
    }
    if method.eq_ignore_ascii_case(b"OPTIONS")
        || method.eq_ignore_ascii_case(b"TRACE")
        || target.is_empty()
    {
        return None;
    }
    if let Some(rest) = target.strip_prefix(b"http://") {
        let (authority, path) = match rest.iter().position(|byte| *byte == b'/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, b"/".as_slice()),
        };
        let asked = authority_target(authority)?;
        return Some(ProxyRequest::Forward(
            asked,
            origin_head(method, path, version, head),
        ));
    }
    if target.starts_with(b"/") {
        let host = header_value(head, "host")?;
        let asked = authority_target(host.as_bytes())?;
        return Some(ProxyRequest::Forward(
            asked,
            origin_head(method, target, version, head),
        ));
    }
    None
}

/// A CONNECT target is the authority form; Go's transport also sends the
/// absolute form (`Connect http://host:port/`) when the method is CONNECT and
/// the destination is plain.
fn connect_authority(target: &[u8]) -> &[u8] {
    let rest = [b"http://".as_slice(), b"https://".as_slice()]
        .into_iter()
        .find_map(|scheme| target.strip_prefix(scheme))
        .unwrap_or(target);
    match rest.iter().position(|byte| *byte == b'/') {
        Some(at) => &rest[..at],
        None => rest,
    }
}

/// Rewrites the request line to origin-form, keeping every header byte as sent.
fn origin_head(method: &[u8], path: &[u8], version: &[u8], head: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(path);
    out.push(b' ');
    out.extend_from_slice(version);
    out.extend_from_slice(b"\r\n");
    let rest = head
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    out.extend_from_slice(&head[rest..]);
    out
}

/// An authority as a target: a literal address stays one, a name rides the tunnel untouched, no port means 80.
fn authority_target(authority: &[u8]) -> Option<Destination> {
    let authority = std::str::from_utf8(authority).ok()?;
    if let Ok(address) = authority.parse::<SocketAddr>() {
        return Some(Destination::Address(address));
    }
    if let Ok(ip) = authority.parse::<std::net::IpAddr>() {
        return Some(Destination::Address(SocketAddr::new(ip, 80)));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok()?),
        None => (authority, 80),
    };
    // A name has no longer than a length byte to be carried by, and a truncated destination is a wrong one.
    if host.is_empty() || host.len() > ferrox_core::addr::MAX_DOMAIN {
        return None;
    }
    Some(Destination::Name(host.to_owned(), port))
}

/// The `http` front: CONNECT tunnels like SOCKS, plain HTTP forwards its head, unparsable input closes quietly.
fn serve_http(mut client: Connection, out: &Outbound) {
    let Some(head) = read_http_head(&mut client, HTTP_HEAD_LIMIT, budgets::head_arrival()) else {
        return;
    };
    let Some(request) = http_proxy_request(&head) else {
        return;
    };
    match request {
        ProxyRequest::Connect(asked) => {
            if !matches!(out, Outbound::Foxy(_))
                && client.write_all(&Front::Http.grant_line()).is_err()
            {
                return;
            }
            serve_connect(client, out, &asked, Front::Http, &[]);
        }
        ProxyRequest::Forward(asked, origin) => {
            serve_connect(client, out, &asked, Front::Http, &origin);
        }
    }
}

/// The `mixed` front sniffs one byte: 0x05 is SOCKS5, a method token is HTTP, and a peek consumes nothing.
fn serve_mixed(client: Connection, out: &Outbound) {
    let mut first = [0u8; 1];
    let Ok(n) = client.peek(&mut first) else {
        return;
    };
    if n == 0 {
        return;
    }
    if first[0] == 5 {
        serve_socks(client, out);
    } else {
        serve_http(client, out);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Whether an observed exit honours the pin: the recommended location accepts any, a pinned country accepts only its own code.
#[must_use]
fn exit_agrees(pin: &str, seen: &str) -> bool {
    pin.eq_ignore_ascii_case(ferrox_core::foxy::catalog::RECOMMENDED)
        || seen == pin.to_ascii_uppercase()
}

/// Asks a tunnel where it really exits: one plaintext trace GET, then the `loc` off the reply. `None` when no probe is configured or the trace did not answer — the caller reads that as "no verdict," never as agreement.
fn foxy_exit_country<T: Read + Write>(tunnel: &mut T, foxy: &FoxyOut) -> Option<String> {
    let probe = foxy.exit_probe.as_deref()?;
    let (host, path) = probe.split_once('/')?;
    let request = format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if tunnel.write_all(request.as_bytes()).is_err() {
        return None;
    }
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    while !head.windows(2).any(|pair| pair == b"\n\n") && head.len() < 4096 {
        match tunnel.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    crate::foxy::exit_country(&head)
}

fn socks_udp_relay(client: &mut Connection) -> Option<UdpSocket> {
    let local_ip = client
        .local_addr()
        .map_or(std::net::IpAddr::V4([127, 0, 0, 1].into()), |addr| {
            addr.ip()
        });
    let relay = UdpSocket::bind(SocketAddr::new(local_ip, 0)).ok()?;
    let relay_addr = relay.local_addr().ok()?;
    let mut reply = vec![5, 0, 0];
    push_socks_addr(&mut reply, &relay_addr);
    client.write_all(&reply).ok()?;
    relay.set_read_timeout(Some(budgets::udp_idle())).ok()?;
    Some(relay)
}

fn serve_socks_udp(mut client: Connection, out: &Outbound) {
    let Some(relay) = socks_udp_relay(&mut client) else {
        return;
    };
    // The handler holds the control socket open for its life, and the Foxy arms watch it for the client's goodbye.
    match out {
        Outbound::Vless(vless)
            if matches!(vless.carrier, Carrier::Raw(_)) && vless.tls.is_none() =>
        {
            serve_socks_udp_vless(&relay, vless);
        }
        Outbound::Vless(vless) if matches!(vless.carrier, Carrier::Hysteria(_)) && !vless.mux => {
            // The datagram lane carries UDP flows the same way it carries TCP ones: one association per destination, ids never reused on the connection.
            if let Some(dial) = hysteria_dial_session(vless) {
                crate::hysteria::serve_udp(&relay, &dial);
            }
        }
        Outbound::Trojan(trojan)
            if matches!(trojan.carrier, Carrier::Raw(_)) && trojan.tls.is_none() =>
        {
            serve_socks_udp_trojan(&relay, trojan);
        }
        Outbound::Vmess(vmess)
            if matches!(vmess.carrier, Carrier::Raw(_)) && vmess.tls.is_none() =>
        {
            serve_socks_udp_vmess(&relay, vmess);
        }
        Outbound::Shadowsocks(ss) if matches!(ss.carrier, Carrier::Raw(_)) => {
            serve_socks_udp_shadowsocks(&relay, ss);
        }
        Outbound::Foxy(foxy) => match foxy.carrier {
            // One tunnel for all destinations: later ones ride the first one opened.
            crate::foxy::Carrier::H3 => serve_socks_udp_foxy_ip(&relay, foxy, &client),
            _ => serve_socks_udp_foxy(&relay, foxy, &client),
        },
        Outbound::Freedom => serve_socks_udp_freedom(&relay),
        _ => {}
    }
}

/// Freedom UDP: the machine's own socket per destination, since a datagram here has no carrier to ride.
fn serve_socks_udp_freedom(relay: &UdpSocket) {
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplinks: HashMap<SocketAddr, (UdpSocket, thread::JoinHandle<()>)> = HashMap::new();
    let mut buf = udp_buffer();
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        if uplinks.contains_key(&dest) {
            let _ = uplinks[&dest].0.send(payload);
            continue;
        }
        let Ok(up) = UdpSocket::bind(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
        )) else {
            continue;
        };
        let Ok(()) = up.connect(dest) else {
            continue;
        };
        let Ok(writer) = up.try_clone() else {
            continue;
        };
        let peer = source.clone();
        let Ok(relay_write) = relay.try_clone() else {
            continue;
        };
        let _ = up.set_read_timeout(Some(budgets::udp_idle()));
        let done = thread::spawn(move || {
            let mut back = udp_buffer();
            let writer = up;
            while let Ok(read) = writer.recv(&mut back) {
                let Some(source) = peer.lock().ok().and_then(|slot| *slot) else {
                    continue;
                };
                let mut framed = Vec::with_capacity(HEAD + read);
                framed.extend_from_slice(&[0, 0, 0]);
                push_socks_addr(&mut framed, &dest);
                framed.extend_from_slice(&back[..read]);
                if relay_write.send_to(&framed, source).is_err() {
                    break;
                }
            }
        });
        uplinks.insert(dest, (writer, done));
        // The datagram that opened the destination is its first payload; a hop must not drop it.
        let _ = uplinks[&dest].0.send(payload);
    }
    for (_, (_, handle)) in uplinks {
        // The relayed datagrams are on their own sockets, so this exit is their idle timeout.
        let _ = handle.join();
    }
}

/// The association's control socket answers a peek with zero (or an error) once the app is gone; a timeout is the answer that says it is still there.
fn peer_left(associate: &Connection) -> bool {
    let mut byte = [0u8; 1];
    match associate.peek(&mut byte) {
        Err(error) => !is_timeout(&error),
        Ok(read) => read == 0,
    }
}

/// The association's own tick: how long the relay socket waits for a datagram and how long any lane it reads waits for a packet, so one silent stream cannot cost a pass more than the tick.
const UDP_POLL: Duration = Duration::from_millis(10);

/// Datagrams one side may take per pass, so a burst is served in one pass and neither direction starves the other.
const UDP_BURST: usize = 64;

/// Foxy UDP: one CONNECT-UDP stream per destination, HTTP/2 then HTTP/3; the configured carrier does not apply.
fn serve_socks_udp_foxy(relay: &UdpSocket, foxy: &FoxyOut, associate: &Connection) {
    let _ = relay.set_read_timeout(Some(UDP_POLL));
    let _ = associate.set_read_timeout(Some(budgets::SESSION_POLL));
    let mut streams: HashMap<SocketAddr, crate::foxy::Datagram> = HashMap::new();
    let mut buf = udp_buffer();
    let mut datagram = udp_buffer();
    let mut reply = Vec::with_capacity(UDP_BUF);
    let mut client = None;
    let mut quiet = Instant::now();
    loop {
        // The client's datagrams go out as a burst: one per pass would pace the upload at the tick, and a burst is what an app sends.
        let mut ended = false;
        for _ in 0..UDP_BURST {
            match relay.recv_from(&mut buf) {
                Ok((n, src)) => {
                    quiet = Instant::now();
                    client = Some(src);
                    let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
                        continue;
                    };
                    if payload.is_empty() {
                        continue;
                    }
                    if let std::collections::hash_map::Entry::Vacant(slot) = streams.entry(dest) {
                        if let Some(lane) = foxy_udp_dial(foxy, &dest) {
                            slot.insert(lane);
                        }
                    }
                    if let Some(lane) = streams.get_mut(&dest) {
                        match lane.write(payload) {
                            // A lane whose credit the edge has not granted yet loses the datagram rather than the lane: reading is what earns the grant back, and this pass reads for every stream below.
                            Err(error) if is_timeout(&error) => {}
                            Err(_) => {
                                streams.remove(&dest);
                            }
                            Ok(_) => {}
                        }
                    }
                }
                Err(error) if is_timeout(&error) => {
                    ended = peer_left(associate) || quiet.elapsed() >= budgets::udp_idle();
                    break;
                }
                Err(_) => {
                    ended = true;
                    break;
                }
            }
        }
        if ended {
            break;
        }
        let mut dead = Vec::new();
        for (dest, lane) in &mut streams {
            for _ in 0..UDP_BURST {
                match lane.read(&mut datagram) {
                    // A stream the edge closed is gone: the next datagram for that destination dials a fresh one.
                    Ok(0) => {
                        dead.push(*dest);
                        break;
                    }
                    Ok(n) => {
                        quiet = Instant::now();
                        if let Some(src) = client {
                            reply.clear();
                            reply.extend_from_slice(&[0, 0, 0]);
                            push_socks_addr(&mut reply, dest);
                            reply.extend_from_slice(&datagram[..n]);
                            let _ = relay.send_to(&reply, src);
                        }
                    }
                    Err(error) if is_timeout(&error) => break,
                    Err(_) => {
                        dead.push(*dest);
                        break;
                    }
                }
            }
        }
        for dest in dead {
            streams.remove(&dest);
        }
    }
}

/// CONNECT-IP UDP: one tunnel shared by every destination, so later targets cost a map row, not a dial.
fn serve_socks_udp_foxy_ip(relay: &UdpSocket, foxy: &FoxyOut, associate: &Connection) {
    let _ = relay.set_read_timeout(Some(UDP_POLL));
    let _ = associate.set_read_timeout(Some(budgets::SESSION_POLL));
    // The tunnel and its owned source address are opened once and shared: that is this row's whole point.
    let mut tunnel: Option<crate::foxy::Ip> = None;
    let mut source = [0u8; 16];
    let mut width = 0usize;
    let mut buf = udp_buffer();
    let mut reply = Vec::with_capacity(UDP_BUF);
    let mut client = None;
    // One port per destination so a reply lands where it was sent from: the address is shared, the port is not.
    let mut ports: HashMap<SocketAddr, u16> = HashMap::new();
    let mut next_port = 40_000u16;
    let mut quiet = Instant::now();
    loop {
        // The client's datagrams go out as a burst, and the destination address rides a stack buffer: one packet per pass and one `Vec` per packet are both a cost the association has no reason to pay.
        let mut ended = false;
        for _ in 0..UDP_BURST {
            match relay.recv_from(&mut buf) {
                Ok((n, src)) => {
                    quiet = Instant::now();
                    client = Some(src);
                    let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
                        continue;
                    };
                    if payload.is_empty() {
                        continue;
                    }
                    if width == 0
                        && !open_foxy_ip_tunnel(foxy, &mut tunnel, &mut source, &mut width)
                    {
                        continue;
                    }
                    let Some(port) = ports.get(&dest).copied().or_else(|| {
                        let port = next_port;
                        next_port = next_port.wrapping_add(1).max(1);
                        ports.insert(dest, port);
                        Some(port)
                    }) else {
                        continue;
                    };
                    let mut address = [0u8; 16];
                    let destination: &[u8] = match dest.ip() {
                        std::net::IpAddr::V4(ip) => {
                            address[..4].copy_from_slice(&ip.octets());
                            &address[..4]
                        }
                        std::net::IpAddr::V6(ip) => {
                            address.copy_from_slice(&ip.octets());
                            &address
                        }
                    };
                    // The packet's family is the tunnel's: it cannot carry an address the proxy never assigned.
                    if destination.len() != width {
                        continue;
                    }
                    if let Some(lane) = tunnel.as_mut() {
                        if let Err(error) = lane
                            .write(&source[..width], destination, port, dest.port(), payload)
                            .and_then(|_| lane.flush())
                        {
                            // No credit is the lane waiting for a grant the next read pass carries, so the packet is lost and the tunnel is not; only a broken lane is dialled again.
                            if !is_timeout(&error) {
                                tunnel = None;
                                width = 0;
                                ports.clear();
                            }
                        }
                    }
                }
                Err(error) if is_timeout(&error) => {
                    ended = peer_left(associate) || quiet.elapsed() >= budgets::udp_idle();
                    break;
                }
                Err(_) => {
                    ended = true;
                    break;
                }
            }
        }
        if ended {
            break;
        }
        // One pass reads the tunnel until it goes quiet, so a reply burst leaves on the tick it arrived on.
        if let Some(lane) = tunnel.as_mut() {
            match drain_foxy_ip_tunnel(lane, relay, client, &mut reply) {
                Some(0) => {}
                Some(_) => quiet = Instant::now(),
                None => {
                    tunnel = None;
                    width = 0;
                    ports.clear();
                }
            }
        }
    }
}

/// The tunnel's packets, read until it goes quiet and each handed back to the client that sent for its destination: one read per pass would pace a download at one packet per tick. `None` is a tunnel to dial again.
fn drain_foxy_ip_tunnel(
    lane: &mut crate::foxy::Ip,
    relay: &UdpSocket,
    client: Option<SocketAddr>,
    reply: &mut Vec<u8>,
) -> Option<usize> {
    let mut packets = 0usize;
    for _ in 0..UDP_BURST {
        match lane.read() {
            Ok(Some(packet)) => {
                packets += 1;
                let Some(read) = ferrox_core::foxy::connectip::udp_from_packet(&packet) else {
                    continue;
                };
                if !read.verified {
                    continue;
                }
                let peer = socket_from_bytes(read.source, read.destination);
                if let Some(src) = client {
                    reply.clear();
                    reply.extend_from_slice(&[0, 0, 0]);
                    push_socks_addr(reply, &peer);
                    reply.extend_from_slice(read.payload);
                    let _ = relay.send_to(reply, src);
                }
            }
            Err(error) if is_timeout(&error) => break,
            Ok(None) | Err(_) => return None,
        }
    }
    Some(packets)
}

/// The sender read out of the packet's own source: a v6 destination never sent to is not a peer, a v4 one is.
fn socket_from_bytes(source: &[u8], destination: &[u8]) -> SocketAddr {
    let ip = if destination.len() == 4 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            source[0], source[1], source[2], source[3],
        ))
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&source[..16]);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
    };
    SocketAddr::new(ip, 0)
}

/// Opens the tunnel on the first answering edge, HTTP/3 then HTTP/2; no assigned address means refuse, not guess.
fn open_foxy_ip_tunnel(
    foxy: &FoxyOut,
    tunnel: &mut Option<crate::foxy::Ip>,
    source: &mut [u8; 16],
    width: &mut usize,
) -> bool {
    if edge_limited(&foxy.limited_until, now_secs()) {
        return false;
    }
    let order = ferrox_core::foxy::catalog::tier(
        &foxy.candidates,
        &foxy.country,
        &foxy.city,
        MAX_FOXY_ALTERNATES,
    );
    for edge in ferrox_core::foxy::dial_order(
        &order,
        &foxy.country,
        foxy.stored.as_ref(),
        MAX_FOXY_ALTERNATES,
    ) {
        let pass = foxy
            .account
            .as_ref()
            .map_or_else(|| foxy.pass.clone(), |account| account.current());
        for carrier in crate::foxy::Carrier::udp_order() {
            // As on TCP and CONNECT-UDP: a silent carrier is left alone for the window, not probed per packet.
            if foxy.carrier_unanswered(&edge, carrier) {
                continue;
            }
            let dial = crate::foxy::FoxyDial {
                host: edge.host.clone(),
                port: edge.port,
                address: foxy.edge_address,
                carrier,
                upstream: foxy.upstream.clone(),
                roots: foxy.roots.clone(),
                pins: foxy.pins.clone(),
                pass: pass.clone(),
            };
            let quic = match carrier {
                crate::foxy::Carrier::H3 => crate::quic::pooled_stream_within(
                    &foxy_quic_dial(foxy, &edge),
                    if foxy.carrier == crate::foxy::Carrier::H3 {
                        crate::quic::HANDSHAKE_TIMEOUT
                    } else {
                        budgets::carrier_probe()
                    },
                ),
                _ => None,
            };
            match crate::foxy::Ip::open(&dial, quic) {
                Ok((mut lane, assigned)) => {
                    debug_lane(&edge, carrier, "connect-ip opened");
                    clear_limited(&foxy.limited_strikes, &foxy.limited_until);
                    foxy.carrier_answered(&edge, carrier);
                    let Some(granted) = assigned else {
                        debug_lane(
                            &edge,
                            carrier,
                            "the edge granted no address, so the tunnel carries nothing",
                        );
                        continue;
                    };
                    *width = granted.width();
                    source[..*width].copy_from_slice(granted.bytes());
                    // The tunnel read waits no longer than the association's own tick: a longer quantum paces every upload at one packet per wait.
                    let _ = lane.set_read_quantum(UDP_POLL);
                    *tunnel = Some(lane);
                    return true;
                }
                Err(failure) => {
                    debug_lane(&edge, carrier, &failure.to_string());
                    let silent = matches!(
                        failure,
                        ferrox_core::foxy::Failure::Io
                            | ferrox_core::foxy::Failure::Stream
                            | ferrox_core::foxy::Failure::Frame
                    );
                    if silent {
                        foxy.remember_unanswered(&edge, carrier, failure);
                    }
                    if matches!(failure, ferrox_core::foxy::Failure::Rejected(429)) {
                        note_limited(&foxy.limited_strikes, &foxy.limited_until, now_secs());
                        break;
                    }
                }
            }
        }
    }
    false
}

/// CONNECT-UDP stream, HTTP/3 then HTTP/2; the pass is read fresh per dial so a renewal needs no reopen.
fn foxy_udp_dial(foxy: &FoxyOut, dest: &SocketAddr) -> Option<crate::foxy::Datagram> {
    if edge_limited(&foxy.limited_until, now_secs()) {
        return None;
    }
    let order = ferrox_core::foxy::catalog::tier(
        &foxy.candidates,
        &foxy.country,
        &foxy.city,
        MAX_FOXY_ALTERNATES,
    );
    for edge in ferrox_core::foxy::dial_order(
        &order,
        &foxy.country,
        foxy.stored.as_ref(),
        MAX_FOXY_ALTERNATES,
    ) {
        let pass = foxy
            .account
            .as_ref()
            .map_or_else(|| foxy.pass.clone(), |account| account.current());
        for carrier in crate::foxy::Carrier::udp_order() {
            // As on TCP: a silent carrier is left alone for the window, not probed per datagram.
            if foxy.carrier_unanswered(&edge, carrier) {
                continue;
            }
            if carrier == crate::foxy::Carrier::H3
                && foxy
                    .upstream
                    .as_ref()
                    .is_some_and(super::foxy::UpstreamProxy::http)
            {
                continue;
            }
            let dial = crate::foxy::FoxyDial {
                host: edge.host.clone(),
                port: edge.port,
                address: foxy.edge_address,
                carrier,
                upstream: foxy.upstream.clone(),
                roots: foxy.roots.clone(),
                pins: foxy.pins.clone(),
                pass: pass.clone(),
            };
            let host = dest.ip().to_string();
            let failure = match carrier {
                crate::foxy::Carrier::H3 => {
                    let Some(lease) = crate::quic::pooled_stream_within(
                        &foxy_quic_dial(foxy, &edge),
                        if foxy.carrier == crate::foxy::Carrier::H3 {
                            crate::quic::HANDSHAKE_TIMEOUT
                        } else {
                            budgets::carrier_probe()
                        },
                    ) else {
                        continue;
                    };
                    match crate::foxy::H3::open_udp(&dial, &host, dest.port(), lease) {
                        Ok(mut lane) => {
                            lane.set_read_quantum(UDP_POLL);
                            debug_lane(&edge, carrier, &format!("udp opened for {dest}"));
                            clear_limited(&foxy.limited_strikes, &foxy.limited_until);
                            foxy.carrier_answered(&edge, carrier);
                            return Some(crate::foxy::Datagram::H3(Box::new(lane)));
                        }
                        Err(failure) => failure,
                    }
                }
                _ => match crate::foxy::open_udp(&dial, &host, dest.port()) {
                    Ok(lane) => {
                        let _ = lane.set_read_quantum(UDP_POLL);
                        debug_lane(&edge, carrier, &format!("udp opened for {dest}"));
                        clear_limited(&foxy.limited_strikes, &foxy.limited_until);
                        foxy.carrier_answered(&edge, carrier);
                        return Some(crate::foxy::Datagram::H2(Box::new(lane)));
                    }
                    Err(failure) => failure,
                },
            };
            debug_lane(&edge, carrier, &failure.to_string());
            if matches!(failure, ferrox_core::foxy::Failure::Rejected(429)) {
                note_limited(&foxy.limited_strikes, &foxy.limited_until, now_secs());
                break;
            }
            foxy.remember_unanswered(&edge, carrier, failure);
        }
    }
    None
}

fn serve_socks_udp_shadowsocks(relay: &UdpSocket, ss: &ShadowsocksOut) {
    if let Some(method2022) = ferrox_core::shadowsocks2022::Method::parse(&ss.method) {
        serve_socks_udp_shadowsocks2022(relay, ss, method2022);
        return;
    }
    let Some(method) = ferrox_core::shadowsocks::Method::parse(&ss.method) else {
        return;
    };
    let master = ferrox_core::shadowsocks::MasterKey::new(&ss.password, method.key_len());
    let server: SocketAddr = match format!("{}:{}", ss.address, ss.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(server) => server,
        None => return,
    };
    let bound = if server.is_ipv6() {
        UdpSocket::bind("[::]:0")
    } else {
        UdpSocket::bind("0.0.0.0:0")
    };
    let Ok(uplink) = bound else {
        return;
    };
    if uplink.connect(server).is_err()
        || uplink.set_read_timeout(Some(budgets::udp_idle())).is_err()
    {
        return;
    }
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let done = Arc::new(AtomicBool::new(false));
    let Some(reader) = spawn_ss_udp_reader(
        &uplink,
        relay,
        &master,
        method,
        Arc::clone(&source),
        Arc::clone(&done),
    ) else {
        return;
    };
    let mut buf = Vec::new();
    resize_scratch(&mut buf, crate::shadowsocks::DATAGRAM_MAX);
    let mut hop: Option<ferrox_core::shadowsocks::Cipher> = None;
    while let Ok((n, src)) = relay
        .recv_from(&mut buf[crate::shadowsocks::SEAL_ROOM..crate::shadowsocks::SEAL_ROOM + UDP_BUF])
    {
        let Some((dest, payload)) =
            parse_socks_udp(&buf[crate::shadowsocks::SEAL_ROOM..crate::shadowsocks::SEAL_ROOM + n])
        else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        let (at, len) = (
            payload.as_ptr() as usize - buf.as_ptr() as usize,
            payload.len(),
        );
        if let Some(packet) =
            crate::shadowsocks::seal_datagram(&master, method, &dest, &mut buf, at, len, &mut hop)
        {
            let _ = uplink.send(packet);
        }
    }
    done.store(true, Ordering::Relaxed);
    join(&reader);
}

fn serve_socks_udp_shadowsocks2022(
    relay: &UdpSocket,
    ss: &ShadowsocksOut,
    method: ferrox_core::shadowsocks2022::Method,
) {
    let Some(list) = ferrox_core::shadowsocks2022::parse_psk_list(&ss.password, method.key_len())
    else {
        return;
    };
    let psk = list.last().expect("non-empty").clone();
    let server: SocketAddr = match format!("{}:{}", ss.address, ss.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(server) => server,
        None => return,
    };
    let bound = if server.is_ipv6() {
        UdpSocket::bind("[::]:0")
    } else {
        UdpSocket::bind("0.0.0.0:0")
    };
    let Ok(uplink) = bound else {
        return;
    };
    if uplink.connect(server).is_err()
        || uplink.set_read_timeout(Some(budgets::udp_idle())).is_err()
    {
        return;
    }
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let done = Arc::new(AtomicBool::new(false));
    let Some(reader) = spawn_ss_udp_reader2022(
        &uplink,
        relay,
        &psk,
        method,
        Arc::clone(&source),
        Arc::clone(&done),
    ) else {
        return;
    };
    let mut buf = udp_buffer();
    let mut datagrams = crate::shadowsocks2022::Datagrams::new();
    let multi = !method.is_chacha() && list.len() > 1;
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        if multi {
            if let Some(packet) = datagrams.seal_list(method, &list, &dest, payload) {
                let _ = uplink.send(packet);
            }
        } else if let Some(packet) = datagrams.seal(&psk, method, &dest, payload) {
            let _ = uplink.send(packet);
        }
    }
    done.store(true, Ordering::Relaxed);
    join(&reader);
}

fn spawn_ss_udp_reader2022(
    uplink: &UdpSocket,
    relay: &UdpSocket,
    psk: &[u8],
    method: ferrox_core::shadowsocks2022::Method,
    source: Arc<Mutex<Option<SocketAddr>>>,
    done: Arc<AtomicBool>,
) -> Option<std::sync::mpsc::Receiver<()>> {
    let read = uplink.try_clone().ok()?;
    read.set_read_timeout(Some(RELAY_POLL)).ok()?;
    let send = relay.try_clone().ok()?;
    let psk = psk.to_vec();
    Some(RelayPool::global().run(move || {
        let mut buf = udp_buffer();
        let mut reply = Vec::with_capacity(UDP_BUF);
        let mut datagrams = crate::shadowsocks2022::Datagrams::new();
        loop {
            match read.recv(&mut buf) {
                Ok(n) => {
                    let Some((target, payload)) = datagrams.open_server(&psk, method, &buf[..n])
                    else {
                        continue;
                    };
                    let dest = match source.lock() {
                        Ok(guard) => *guard,
                        Err(_) => None,
                    };
                    let Some(dest) = dest else {
                        continue;
                    };
                    reply.clear();
                    reply.extend_from_slice(&[0, 0, 0]);
                    push_socks_addr(&mut reply, &target);
                    reply.extend_from_slice(payload);
                    let _ = send.send_to(&reply, dest);
                }
                Err(error) if is_timeout(&error) => {
                    if done.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }))
}

fn spawn_ss_udp_reader(
    uplink: &UdpSocket,
    relay: &UdpSocket,
    master: &ferrox_core::shadowsocks::MasterKey,
    method: ferrox_core::shadowsocks::Method,
    source: Arc<Mutex<Option<SocketAddr>>>,
    done: Arc<AtomicBool>,
) -> Option<std::sync::mpsc::Receiver<()>> {
    let read = uplink.try_clone().ok()?;
    read.set_read_timeout(Some(RELAY_POLL)).ok()?;
    let send = relay.try_clone().ok()?;
    let master = master.clone();
    Some(RelayPool::global().run(move || {
        let mut buf = Vec::new();
        resize_scratch(&mut buf, crate::shadowsocks::DATAGRAM_MAX);
        let room = crate::shadowsocks::SEAL_ROOM;
        let base = buf.as_ptr() as usize;
        let mut hop: Option<ferrox_core::shadowsocks::Cipher> = None;
        loop {
            match read.recv(&mut buf[room..room + UDP_BUF]) {
                Ok(n) => {
                    let opened = crate::shadowsocks::open_datagram(
                        &master,
                        method,
                        &mut buf[room..room + n],
                        &mut hop,
                    );
                    let Some((target, payload)) = opened else {
                        continue;
                    };
                    let (at, len) = (payload.as_ptr() as usize - base, payload.len());
                    let dest = match source.lock() {
                        Ok(guard) => *guard,
                        Err(_) => None,
                    };
                    let Some(dest) = dest else {
                        continue;
                    };
                    let head = 3 + match target {
                        SocketAddr::V4(_) => 7,
                        SocketAddr::V6(_) => 19,
                    };
                    let start = at - head;
                    buf[start..start + 3].fill(0);
                    crate::shadowsocks::write_addr(&mut buf[start + 3..at], &target);
                    let _ = send.send_to(&buf[start..at + len], dest);
                }
                Err(error) if is_timeout(&error) => {
                    if done.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }))
}

fn serve_socks_udp_vmess(relay: &UdpSocket, vmess: &VmessOut) {
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplink: Option<VmessUdpUplink> = None;
    let mut staging = Vec::with_capacity(UDP_BUF);
    let mut buf = udp_buffer();
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        let redial = match &uplink {
            Some(up) => up.target != dest,
            None => true,
        };
        if redial {
            if let Some(old) = uplink.take() {
                let _ = old.write.shutdown(Shutdown::Both);
            }
            uplink = dial_vmess_udp_uplink(vmess, &dest, relay, Arc::clone(&source));
        }
        if let Some(up) = &mut uplink {
            if !crate::vmess::write_frame(
                &mut up.write,
                &mut up.send,
                payload,
                &mut staging,
                &mut up.pad,
            ) {
                if let Some(old) = uplink.take() {
                    let _ = old.write.shutdown(Shutdown::Both);
                }
            }
        }
    }
    if let Some(old) = uplink.take() {
        let _ = old.write.shutdown(Shutdown::Both);
        join(&old.done);
    }
}

fn serve_socks_udp_vless(relay: &UdpSocket, vless: &VlessOut) {
    if vless.mux {
        return serve_socks_udp_vless_xudp(relay, vless);
    }
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplink: Option<UdpUplink> = None;
    let mut buf = udp_buffer();
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        let redial = match &uplink {
            Some(up) => up.target != dest,
            None => true,
        };
        if redial {
            if let Some(old) = uplink.take() {
                let _ = old.write.shutdown(Shutdown::Both);
            }
            uplink = dial_udp_uplink(vless, &dest, relay, Arc::clone(&source));
        }
        if let Some(up) = &mut uplink {
            if !write_udp_datagram(&mut up.write, payload) {
                if let Some(old) = uplink.take() {
                    let _ = old.write.shutdown(Shutdown::Both);
                }
            }
        }
    }
    if let Some(old) = uplink.take() {
        let _ = old.write.shutdown(Shutdown::Both);
        join(&old.done);
    }
}

fn xudp_identity(source: SocketAddr) -> [u8; ferrox_core::mux::GLOBAL_ID] {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    match source.ip() {
        std::net::IpAddr::V4(ip) => mix(&ip.octets()),
        std::net::IpAddr::V6(ip) => mix(&ip.octets()),
    }
    mix(&source.port().to_be_bytes());
    hash.to_be_bytes()
}

/// One XUDP datagram as its two wire parts: the frame header just encoded, and the payload the relay
/// read, which goes to the socket where it lies instead of through a staging copy.
fn xudp_datagram<'a>(
    frame: &ferrox_core::mux::Outgoing<'_>,
    header: &'a mut Vec<u8>,
    payload: &'a [u8],
) -> (&'a [u8], &'a [u8]) {
    assert!(
        payload.len() <= ferrox_core::mux::CHUNK_MAX,
        "mux chunk longer than a length field"
    );
    let at = frame.encode_header_into(&mut *header);
    frame.patch_payload_len(&mut *header, at, payload.len());
    (header.as_slice(), payload)
}

/// One SOCKS5 UDP reply as its two parts: the request head and the payload that arrived. The reply
/// socket takes both by pointer, so a datagram is not gathered into a second buffer first.
fn udp_reply_parts<'a>(
    head: &'a mut Vec<u8>,
    target: &SocketAddr,
    payload: &'a [u8],
) -> (&'a [u8], &'a [u8]) {
    head.clear();
    head.extend_from_slice(&[0, 0, 0]);
    push_socks_addr(head, target);
    (head.as_slice(), payload)
}

fn spawn_xudp_reader(
    read: Connection,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<std::sync::mpsc::Receiver<()>> {
    let reply = relay.try_clone().ok()?;
    Some(RelayPool::global().run(move || {
        let mut read = read;
        let mut buf: Vec<u8> = Vec::with_capacity(READ_SLICE);
        let mut at = 0;
        let mut head = Vec::with_capacity(HEAD);
        loop {
            if at >= buf.len() {
                buf.clear();
                at = 0;
            } else if at > 0 {
                buf.drain(..at);
                at = 0;
            }
            let mut progressed = false;
            loop {
                match ferrox_core::mux::decode(&buf[at..], ferrox_core::mux::NewTail::Forward) {
                    Err(ferrox_core::mux::Error::Short { .. }) => break,
                    Err(_) => return,
                    Ok((frame, used)) => {
                        at += used;
                        progressed = true;
                        let Some(data) = frame.data else { continue };
                        let Some(target) = frame.target.and_then(|t| mux_target_addr(&t)) else {
                            continue;
                        };
                        let Some(dest) = source.lock().ok().and_then(|slot| *slot) else {
                            continue;
                        };
                        let (front, tail) = udp_reply_parts(&mut head, &target, data);
                        let _ = send_to_two(&reply, front, tail, dest);
                    }
                }
            }
            if !progressed {
                match read_into_tail(&mut read, &mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        }
    }))
}

fn serve_socks_udp_vless_xudp(relay: &UdpSocket, vless: &VlessOut) {
    let Some(mut write) = open_vless_mux(vless) else {
        return;
    };
    let Ok(read) = write.try_clone() else {
        return;
    };
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let Some(done) = spawn_xudp_reader(read, relay, Arc::clone(&source)) else {
        return;
    };
    let mut buf = udp_buffer();
    let mut header = Vec::with_capacity(64);
    let mut identity: Option<[u8; ferrox_core::mux::GLOBAL_ID]> = None;
    let mut published: Option<SocketAddr> = None;
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        // The reply reader only needs the slot once: an association that keeps its socket writes it once.
        if published != Some(src) {
            if let Ok(mut slot) = source.lock() {
                *slot = Some(src);
                published = Some(src);
            }
        }
        let first = identity.is_none();
        let identity = identity.get_or_insert_with(|| xudp_identity(src));
        let frame = ferrox_core::mux::Outgoing {
            id: 0,
            status: if first {
                ferrox_core::mux::Status::New
            } else {
                ferrox_core::mux::Status::Keep
            },
            options: ferrox_core::mux::DATA,
            target: Some(mux_target_of(dest)),
            global_id: if first { Some(*identity) } else { None },
        };
        let (head, body) = xudp_datagram(&frame, &mut header, payload);
        if write_all_parts::<2>(&mut write, &[head, body]).is_err() {
            break;
        }
    }
    let end = ferrox_core::mux::Outgoing::bare(0, ferrox_core::mux::Status::End, 0);
    resize_scratch(&mut header, end.frame_len(0));
    let written = end.encode_into(None, &mut header);
    let _ = write.write_all(&header[..written]);
    let _ = write.shutdown(Shutdown::Both);
    join(&done);
}

fn serve_socks_udp_trojan(relay: &UdpSocket, trojan: &TrojanOut) {
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplink: Option<TrojanUdpUplink> = None;
    let mut buf = udp_buffer();
    let mut trojan_head = Vec::with_capacity(32);
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        if uplink.is_none() {
            uplink = dial_trojan_udp_uplink(trojan, &dest, relay, Arc::clone(&source));
        }
        if let Some(up) = &mut uplink {
            if !write_trojan_datagram(&mut up.write, &dest, payload, &mut trojan_head) {
                if let Some(old) = uplink.take() {
                    let _ = old.write.shutdown(Shutdown::Both);
                }
            }
        }
    }
    if let Some(old) = uplink.take() {
        let _ = old.write.shutdown(Shutdown::Both);
        join(&old.done);
    }
}

/// The pooled dial uses the edge's name, not its resolved address, so a country's flows share one connection.
fn foxy_quic_dial(foxy: &FoxyOut, edge: &ferrox_core::foxy::Candidate) -> crate::quic::QuicDial {
    crate::quic::QuicDial {
        id: [0; 16],
        host: edge.host.clone(),
        address: edge.host.clone(),
        port: edge.port,
        upstream: foxy.upstream.clone(),
        roots: Some(foxy.roots.clone()),
    }
}

pub(crate) fn relay_tunnel(
    client: &Connection,
    tunnel: &std::sync::Arc<std::sync::Mutex<crate::foxy::Tunnel>>,
) {
    let Ok(mut client_read) = client.try_clone() else {
        return;
    };
    let Ok(mut client_write) = client.try_clone() else {
        return;
    };
    let forward_tunnel = std::sync::Arc::clone(tunnel);
    let backward_tunnel = std::sync::Arc::clone(tunnel);
    // One flag per leg, read by the other: a flow whose client said goodbye keeps its lane, its stream and both threads for the life of the process otherwise, and a quantum-bounded read is what lets a parked leg hear about it.
    let forward_ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backward_ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (report_forward, learn_backward) = (
        std::sync::Arc::clone(&forward_ended),
        std::sync::Arc::clone(&backward_ended),
    );
    let forward = move || {
        // The park's grain, armed on the read handle: a stack that leaves a blocking read asleep through a shutdown still ends it on its own timeout, and the read after that sees the closed socket.
        let _ = client_read.set_read_timeout(Some(budgets::relay_quantum()));
        copy_locked(&mut client_read, &forward_tunnel, true, &learn_backward);
        report_forward.store(true, std::sync::atomic::Ordering::Release);
    };
    let done = RelayPool::global().run(forward);
    copy_locked(&mut client_write, &backward_tunnel, false, &forward_ended);
    backward_ended.store(true, std::sync::atomic::Ordering::Release);
    // Both halves, because the other leg is parked in a blocking read on this socket: a FIN on the write half alone leaves the parked reader asleep and the flow's worker lost for the life of the process.
    let _ = client_write.shutdown(Shutdown::Both);
    join(&done);
}

fn copy_locked(
    socket: &mut Connection,
    tunnel: &std::sync::Arc<std::sync::Mutex<crate::foxy::Tunnel>>,
    forward: bool,
    peer_ended: &std::sync::atomic::AtomicBool,
) {
    const CHUNK: usize = 16 * 1024;
    let direction = if forward { "forward" } else { "backward" };
    let mut buf = [0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let moved = if forward {
            match socket.read(&mut buf) {
                Ok(0) => {
                    debug_relay(direction, total, None);
                    break;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    // The quantum expired on a client that has not spoken: idle, unless the lane's own leg has already ended.
                    if peer_ended.load(std::sync::atomic::Ordering::Acquire) {
                        debug_relay(direction, total, None);
                        break;
                    }
                    continue;
                }
                Err(error) => {
                    debug_relay(direction, total, Some(error.kind()));
                    break;
                }
                // A short write is credit, not completion: the rest retries once the window reopens.
                Ok(read) => {
                    if total == 0 {
                        debug_bytes(direction, &buf[..read]);
                    }
                    write_full(tunnel, peer_ended, &buf[..read])
                }
            }
        } else {
            // The lane is handed back before the client is written: a client that has stopped reading would otherwise cost the other direction its turn on the lane, and an upload that cannot start cannot finish the request it waits on.
            let taken = {
                let Ok(mut lane) = tunnel.lock() else {
                    break;
                };
                match lane.read(&mut buf) {
                    Ok(0) => {
                        debug_relay(direction, total, None);
                        break;
                    }
                    Ok(read) => read,
                    // No payload in the quantum: drop the lock so the writer gets a turn.
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        // The lane has not answered inside its quantum: idle, unless the client's own leg has ended and nothing is left to deliver.
                        if peer_ended.load(std::sync::atomic::Ordering::Acquire) {
                            debug_relay(direction, total, None);
                            break;
                        }
                        drop(lane);
                        std::thread::sleep(RELAY_IDLE);
                        continue;
                    }
                    Err(error) => {
                        debug_relay(direction, total, Some(error.kind()));
                        break;
                    }
                }
            };
            if total == 0 {
                debug_bytes(direction, &buf[..taken]);
            }
            match socket.write_all(&buf[..taken]) {
                Ok(()) => taken,
                Err(error) => {
                    debug_relay(direction, total, Some(error.kind()));
                    break;
                }
            }
        };
        total += moved as u64;
        if moved == 0 {
            debug_relay(direction, total, None);
            break;
        }
    }
}

/// Writes all bytes through the shared lane, taking the lock per call so the other direction interleaves.
fn write_full(
    tunnel: &std::sync::Arc<std::sync::Mutex<crate::foxy::Tunnel>>,
    peer_ended: &std::sync::atomic::AtomicBool,
    mut buf: &[u8],
) -> usize {
    let total = buf.len();
    while !buf.is_empty() {
        let Ok(mut lane) = tunnel.lock() else {
            break;
        };
        let stalled = match lane.write(buf) {
            Ok(0) => true,
            Ok(wrote) => {
                buf = &buf[wrote..];
                false
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                true
            }
            Err(_) => break,
        };
        if stalled {
            drop(lane);
            // A closed window answers before the socket is touched, so the lane cannot report its own death here: the leg that carried the other way has to say so.
            if peer_ended.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            std::thread::sleep(RELAY_IDLE);
        }
    }
    total - buf.len()
}

fn relay(client: &Connection, target: &Connection) {
    let Ok(client_read) = client.try_clone() else {
        return;
    };
    let Ok(target_read) = target.try_clone() else {
        return;
    };
    let Ok(target_write) = target.try_clone() else {
        return;
    };
    let Ok(client_write) = client.try_clone() else {
        return;
    };
    #[cfg(target_os = "linux")]
    // Splice crosses descriptors without the mask, so a leg ending on a masked stream keeps the buffered copy.
    if !target_write.masked() && !client_write.masked() && poll_relay::available() {
        poll_relay::drive(client_read, target_write, target_read, client_write);
        return;
    }
    let mut client_read = client_read;
    let mut target_write = target_write;
    let mut target_read = target_read;
    let mut client_write = client_write;
    let forward = move || {
        copy_all(&mut client_read, &mut target_write);
        let _ = target_write.shutdown(Shutdown::Write);
    };
    let done = RelayPool::global().run(forward);
    copy_all(&mut target_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    join(&done);
}

/// The CONNECT a hop answers with a 200: one authority, reused for `Host` and counted once.
#[inline]
fn http_connect_request(target: &Destination, http: &HttpOut, req: &mut Vec<u8>) {
    use base64::engine::general_purpose;
    const FIXED: usize = 29; // "CONNECT ", " HTTP/1.1\r\n", "Host: ", and both closing CRLFs
    const AUTH_LINE: usize = 30; // "Proxy-Authorization: Basic " plus its CRLF
    const HEADER_WRAPPER: usize = 4; // ": " plus CRLF
    let authority = target.authority();
    let credential_len = match (&http.user, &http.pass) {
        (Some(user), Some(pass)) => (user.len() + pass.len() + 3) / 3 * 4 + AUTH_LINE,
        _ => 0,
    };
    let header_len = http
        .headers
        .iter()
        .map(|(k, v)| k.len() + v.len() + HEADER_WRAPPER)
        .sum::<usize>();
    req.clear();
    req.reserve(FIXED + 2 * authority.len() + credential_len + header_len);
    req.extend_from_slice(b"CONNECT ");
    req.extend_from_slice(authority.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(authority.as_bytes());
    req.extend_from_slice(b"\r\n");
    if let (Some(user), Some(pass)) = (&http.user, &http.pass) {
        req.extend_from_slice(b"Proxy-Authorization: Basic ");
        {
            use base64::write::EncoderWriter;
            use std::io::Write as _;
            let mut enc = EncoderWriter::new(&mut *req, &general_purpose::STANDARD);
            let _ = enc.write_all(user.as_bytes());
            let _ = enc.write_all(b":");
            let _ = enc.write_all(pass.as_bytes());
            let _ = enc.flush();
        }
        req.extend_from_slice(b"\r\n");
    }
    for (k, v) in &http.headers {
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
}

fn dial_http_outbound(
    client: &Connection,
    server: &SocketAddr,
    http: &HttpOut,
    target: &Destination,
    _ladder: &Ladder,
) {
    fn do_connect<S: std::io::Read + std::io::Write + Send + 'static>(
        client: &Connection,
        mut stream: S,
        http: &HttpOut,
        target: &Destination,
    ) {
        use std::io::Write;
        let mut req = Vec::new();
        http_connect_request(target, http, &mut req);
        if stream.write_all(&req).is_err() {
            return;
        }
        // Whole reads, not octets: a byte reader over TLS decrypts one record per byte.
        let Some((head, at)) =
            read_exact_head(&mut stream, HTTP_HEAD_LIMIT, budgets::head_arrival())
        else {
            return;
        };
        let code = head[..at]
            .split(|b| *b == b'\n')
            .next()
            .and_then(|line| line.split(|b| *b == b' ').nth(1))
            .and_then(|code| std::str::from_utf8(code).ok())
            .and_then(|code| code.trim().parse::<u16>().ok())
            .unwrap_or(0);
        if code != 200 {
            return;
        }
        let Ok(mut downstream) = client.try_clone() else {
            return;
        };
        // Each half shares a lock, so an unbounded read would block the other direction's write.
        if downstream.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
        if at < head.len() && downstream.write_all(&head[at..]).is_err() {
            return;
        }
        let close_downstream = downstream.try_clone().ok();
        let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
            if let Some(d) = close_downstream.as_ref() {
                let _ = d.shutdown(std::net::Shutdown::Both);
            }
        });
        crate::proxy::relay_stream(stream, downstream, &close);
    }

    if let Some(cfg) = http.tls.as_deref() {
        let Some(session) = dial_tls_session(server, cfg, None) else {
            return;
        };
        // The session's leg reads the uplink handle it took; un-timed, a parked read outlives the relay that should end it.
        if session
            .get_ref()
            .set_read_timeout(Some(RELAY_POLL))
            .is_err()
        {
            return;
        }
        do_connect(client, session, http, target);
    } else {
        let Some(s) = dial_or_report(server) else {
            return;
        };
        if s.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
        do_connect(client, s, http, target);
    }
}

pub(crate) const UDP_BUF: usize = 65535;

/// The datagram slot a UDP relay loop hands every receive: every user reads back only what the receive reported, so the fill `vec![0u8; n]` pays for is work thrown away.
pub(crate) fn udp_buffer() -> Vec<u8> {
    RelayBuf::with_len(UDP_BUF).into_vec()
}

/// The largest SOCKS5 UDP request header: the three-byte opening plus the longest address this tree frames.
const HEAD: usize = 22;

fn read_udp_datagram(stream: &mut Connection, buf: &mut [u8]) -> Option<usize> {
    let mut len = [0u8; 2];
    read_exact(stream, &mut len).ok()?;
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 || len > buf.len() {
        return None;
    }
    read_exact(stream, &mut buf[..len]).ok()?;
    Some(len)
}

fn write_udp_datagram(stream: &mut Connection, payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return true;
    }
    let len = (payload.len() as u16).to_be_bytes();
    write_all_parts::<2>(stream, &[&len, payload]).is_ok()
}

fn write_trojan_datagram(
    stream: &mut Connection,
    dest: &SocketAddr,
    payload: &[u8],
    head: &mut Vec<u8>,
) -> bool {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return true;
    }
    head.clear();
    push_socks_addr(head, dest);
    head.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    head.extend_from_slice(b"\r\n");
    write_all_parts::<2>(stream, &[head.as_slice(), payload]).is_ok()
}

fn read_trojan_datagram(stream: &mut Connection, buf: &mut [u8]) -> Option<(SocketAddr, usize)> {
    let dest = read_socks_addr(stream)?;
    let mut len = [0u8; 2];
    read_exact(stream, &mut len).ok()?;
    let len = usize::from(u16::from_be_bytes(len));
    let mut crlf = [0u8; 2];
    read_exact(stream, &mut crlf).ok()?;
    if len == 0 || len > buf.len() || crlf != *b"\r\n" {
        return None;
    }
    read_exact(stream, &mut buf[..len]).ok()?;
    Some((dest, len))
}

fn serve_vless_udp(mut stream: Connection, target: &SocketAddr) {
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp) = UdpSocket::bind(bind) else {
        return;
    };
    if udp.connect(target).is_err() || udp.set_read_timeout(Some(budgets::udp_idle())).is_err() {
        return;
    }
    if stream.write_all(&[0, 0]).is_err() {
        return;
    }
    let Ok(tcp_read) = stream.try_clone() else {
        return;
    };
    let Ok(udp_send) = udp.try_clone() else {
        return;
    };
    let done = Arc::new(AtomicBool::new(false));
    let done_in = Arc::clone(&done);
    let forward = move || {
        let mut tcp_read = tcp_read;
        let mut buf = udp_buffer();
        while let Some(n) = read_udp_datagram(&mut tcp_read, &mut buf) {
            if udp_send.send(&buf[..n]).is_err() {
                break;
            }
        }
        done_in.store(true, Ordering::Relaxed);
    };
    let replied = RelayPool::global().run(forward);
    let mut buf = udp_buffer();
    loop {
        match udp.recv(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    continue;
                }
                if !write_udp_datagram(&mut stream, &buf[..n]) {
                    break;
                }
            }
            Err(error) if is_timeout(&error) => {
                if done.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(Shutdown::Both);
    join(&replied);
}

pub(crate) fn pump_vmess_udp(
    stream: &Connection,
    udp: &UdpSocket,
    send: crate::vmess::Flow,
    recv: crate::vmess::Flow,
) {
    let Ok(tcp_read) = stream.try_clone() else {
        return;
    };
    let Ok(tcp_write) = stream.try_clone() else {
        return;
    };
    let Ok(udp_send) = udp.try_clone() else {
        return;
    };
    if udp.set_read_timeout(Some(budgets::udp_idle())).is_err() {
        return;
    }
    let done = Arc::new(AtomicBool::new(false));
    let done_in = Arc::clone(&done);
    let forward = move || {
        let mut tcp_read = tcp_read;
        let mut recv = recv;
        let mut scratch = Vec::with_capacity(UDP_BUF);
        while let Some(chunk) = crate::vmess::read_frame(&mut tcp_read, &mut recv, &mut scratch) {
            if chunk.is_empty() {
                break;
            }
            if udp_send.send(chunk).is_err() {
                break;
            }
        }
        done_in.store(true, Ordering::Relaxed);
    };
    let replied = RelayPool::global().run(forward);
    let mut send = send;
    let mut staging = Vec::with_capacity(UDP_BUF);
    let Some(mut pad) = crate::vmess::PadSource::fresh() else {
        return;
    };
    let mut buf = udp_buffer();
    let mut tcp_write = tcp_write;
    loop {
        match udp.recv(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    continue;
                }
                if !crate::vmess::write_frame(
                    &mut tcp_write,
                    &mut send,
                    &buf[..n],
                    &mut staging,
                    &mut pad,
                ) {
                    break;
                }
            }
            Err(error) if is_timeout(&error) => {
                if done.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = tcp_write.shutdown(Shutdown::Both);
    join(&replied);
}

type RelayTask = Box<dyn FnOnce() + Send + 'static>;

/// A direction's thread is borrowed, not bought: a worker parks on its channel for the worker life after each task and hands the thread back when nothing has claimed it in that window, so a burst of concurrent flows costs threads for the length of the burst rather than for the life of the process.
struct RelayPool {
    idle: Mutex<Vec<(u64, std::sync::mpsc::Sender<RelayTask>)>>,
    next_id: AtomicU64,
    life: Duration,
}

static RELAY_POOL: OnceLock<Arc<RelayPool>> = OnceLock::new();

impl RelayPool {
    fn global() -> Arc<Self> {
        Arc::clone(RELAY_POOL.get_or_init(|| {
            Arc::new(RelayPool {
                idle: Mutex::new(Vec::new()),
                next_id: AtomicU64::new(1),
                life: budgets::RELAY_WORKER_LIFE,
            })
        }))
    }

    /// A pool of one's own, so a gate on what its workers do counts only the threads it borrowed.
    #[cfg(test)]
    fn with_life(life: Duration) -> Arc<Self> {
        Arc::new(RelayPool {
            idle: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            life,
        })
    }

    /// How many workers have parked themselves where the next claim can find them.
    #[cfg(test)]
    fn parked(&self) -> usize {
        self.idle.lock().map_or(0, |idle| idle.len())
    }

    fn run(
        self: &Arc<Self>,
        direction: impl FnOnce() + Send + 'static,
    ) -> std::sync::mpsc::Receiver<()> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let task: RelayTask = Box::new(move || {
            let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(direction));
            let _ = done_tx.send(());
            if ended.is_err() {
                eprintln!("ferrox-app: a relay direction panicked");
            }
        });
        let mut task = Some(task);
        if let Some((_, sender)) = self.idle.lock().ok().and_then(|mut idle| idle.pop()) {
            // A worker can hand back in the moment between the pop and the send, so a rejected send returns the direction rather than keeping it; a direction dropped here would leave its flow waiting on a hand-back that never comes.
            if let Err(rejected) = sender.send(task.take().expect("just set")) {
                task = Some(rejected.0);
            }
        }
        if let Some(orphan) = task {
            self.spawn(orphan);
        }
        done_rx
    }

    fn spawn(self: &Arc<Self>, task: RelayTask) {
        let (sender, receiver) = std::sync::mpsc::channel::<RelayTask>();
        let pool = Arc::clone(self);
        let life = pool.life;
        let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
        thread::spawn(move || {
            let mut work = task;
            loop {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
                // Parked where the next claim looks, once for every direction including the one that woke the thread.
                let Ok(mut idle) = pool.idle.lock() else {
                    return;
                };
                idle.push((id, sender.clone()));
                drop(idle);
                match receiver.recv_timeout(life) {
                    Ok(claimed) => work = claimed,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    // A claim can pop this worker's sender exactly as its park ends, so one more look at the channel decides: a task that landed here runs, a send into the receiver dropped below fails and is spawned fresh instead.
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        let Ok(mut idle) = pool.idle.lock() else {
                            return;
                        };
                        if let Ok(claimed) = receiver.try_recv() {
                            drop(idle);
                            work = claimed;
                        } else {
                            // The receiver goes first, so nothing can hand work to a thread that is leaving; the parking lot then holds no entry of this worker's.
                            drop(receiver);
                            idle.retain(|(parked, _)| *parked != id);
                            return;
                        }
                    }
                }
            }
        });
    }
}

fn join_within(direction: &std::sync::mpsc::Receiver<()>, budget: Duration) -> bool {
    census!("relay-join", crate::census::NO_FD, Some(budget));
    match direction.recv_timeout(budget) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "ferrox-app: a relay leg did not hand back inside its {budget:?} join budget"
            );
            false
        }
        // A partner whose sender is gone can never hand back, which is what the unbounded wait already read as finished.
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
    }
}

/// One leg's wait for its partner, bounded by the join budget the config named. The verdict is returned because the give-up is a fact about the flow, and a bound nobody can observe is not a bound.
fn join(direction: &std::sync::mpsc::Receiver<()>) -> bool {
    join_within(direction, budgets::relay_join())
}

pub(crate) const RELAY_BUFFER: usize = 256 * 1024;

pub(crate) const RELAY_SMALL_BUFFER: usize = 16 * 1024;

/// `read` takes the whole buffer and only the reported prefix escapes; no `Debug`, which would read uninit bytes.
pub(crate) struct RelayBuf {
    bytes: Vec<u8>,
}

impl RelayBuf {
    #[must_use]
    pub fn new() -> Self {
        Self::with_len(RELAY_SMALL_BUFFER)
    }

    /// The same shape at a caller-chosen read window, for a staging buffer whose headroom and tailroom must sit outside the window rather than shrink it.
    #[must_use]
    #[allow(
        clippy::uninit_vec,
        reason = "the length is handed straight to `read`, and only the prefix it reports is ever read back"
    )]
    pub fn with_len(len: usize) -> Self {
        let mut bytes = Vec::with_capacity(len);
        // SAFETY: only the prefix a read reports is ever read back, so the uninitialised tail is unreachable.
        unsafe { bytes.set_len(len) };
        Self { bytes }
    }

    #[must_use]
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// The buffer leaves the type; the read that owned every byte already happened, so the `Vec` is only safe to hand out when every later read is prefix-bounded like `open_chunk`'s.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    #[allow(
        clippy::uninit_vec,
        reason = "the room a promotion adds lies past the bytes the read reported, and the next read starts at index 0"
    )]
    pub fn filled(&mut self, n: usize) -> &[u8] {
        if n == self.bytes.len() && n < RELAY_BUFFER {
            self.bytes.reserve(RELAY_BUFFER - self.bytes.len());
            // SAFETY: added room sits past the prefix and the next read overwrites it from index 0.
            unsafe { self.bytes.set_len(RELAY_BUFFER) };
        }
        &self.bytes[..n]
    }

    #[cfg(test)]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    #[cfg(test)]
    #[must_use]
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

impl Default for RelayBuf {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "linux"))]
fn copy_all(from: &mut Connection, to: &mut Connection) {
    copy_all_memcpy(from, to);
}

#[inline]
fn copy_all_memcpy(from: &mut Connection, to: &mut Connection) {
    let mut buffer = RelayBuf::new();
    loop {
        let read = {
            census!("relay-leg-read", crate::census::handle(from), None);
            from.read(buffer.as_mut())
        };
        let n = match read {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let written = {
            census!("relay-leg-write", crate::census::handle(to), None);
            to.write_all(buffer.filled(n))
        };
        if written.is_err() {
            return;
        }
    }
}

#[cfg(target_os = "linux")]
fn copy_all(from: &mut Connection, to: &mut Connection) {
    // A masked destination cannot be fed by splice: the pipe would write the socket directly.
    if to.masked() {
        return copy_all_memcpy(from, to);
    }
    let Some(pipe) = SplicePipe::new() else {
        return copy_all_memcpy(from, to);
    };
    loop {
        match pipe.pull(from) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if !pipe.push(to, n) {
                    return;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct SplicePipe {
    fds: [libc::c_int; 2],
    capacity: libc::size_t,
}

#[cfg(target_os = "linux")]
impl SplicePipe {
    fn new() -> Option<Self> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        let asked = unsafe { libc::fcntl(fds[0], libc::F_SETPIPE_SZ, splice_pipe_bytes()) };
        let granted = unsafe { libc::fcntl(fds[0], libc::F_GETPIPE_SZ) };
        let capacity = libc::size_t::try_from(if asked > 0 { asked } else { granted }).ok();
        let capacity = match capacity {
            Some(bytes) if bytes > 0 => bytes,
            _ => DEFAULT_SPLICE_PIPE_BYTES,
        };
        if capacity != DEFAULT_SPLICE_PIPE_BYTES {
            eprintln!("ferrox-app: splice pipe {capacity} B");
        }
        Some(Self { fds, capacity })
    }

    fn pull(&self, from: &mut Connection) -> std::io::Result<usize> {
        census!("relay-leg-read", crate::census::handle(from), None);
        loop {
            let n = unsafe {
                libc::splice(
                    from.as_raw_fd(),
                    std::ptr::null_mut(),
                    self.fds[1],
                    std::ptr::null_mut(),
                    self.capacity,
                    0,
                )
            };
            if n < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            return Ok(n as usize);
        }
    }

    fn push(&self, to: &mut Connection, n: usize) -> bool {
        census!("relay-leg-write", crate::census::handle(to), None);
        let mut left = n;
        while left > 0 {
            let moved = unsafe {
                libc::splice(
                    self.fds[0],
                    std::ptr::null_mut(),
                    to.as_raw_fd(),
                    std::ptr::null_mut(),
                    left,
                    0,
                )
            };
            if moved < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            if moved == 0 {
                return false;
            }
            left -= moved as usize;
        }
        true
    }
}

#[cfg(target_os = "linux")]
const SPLICE_PIPE_BYTES: usize = DEFAULT_SPLICE_PIPE_BYTES;

#[cfg(target_os = "linux")]
const DEFAULT_SPLICE_PIPE_BYTES: usize = 256 * 1024;

#[cfg(target_os = "linux")]
fn splice_pipe_bytes() -> libc::c_int {
    let asked = std::env::var("FERROX_SPLICE_PIPE_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(SPLICE_PIPE_BYTES);
    libc::c_int::try_from(asked).unwrap_or(libc::c_int::MAX)
}

#[cfg(target_os = "linux")]
impl Drop for SplicePipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fds[0]);
            libc::close(self.fds[1]);
        }
    }
}

/// The first offset whose four bytes are `\r\n\r\n`, found a word at a time: a SWAR
/// pass marks the `\n` lanes of each eight-byte block, and only the byte after a
/// marked `\n` is checked against the whole terminator. Bit-identical to
/// `head.windows(4).position(|w| w == b"\r\n\r\n")` — which compares four bytes at
/// every offset — but this reads eight bytes per load and lets the wide pass skip the
/// ~255/256 of offsets that hold no `\n`, doing the four-byte verify only at a real
/// candidate. Portable integer code: no target feature, no unsafe, one owner of the
/// terminator shape. It is the one terminator scan: every handshake that ends a head at
/// `\r\n\r\n` reaches it rather than reopening the `windows(4)` byte loop.
pub(crate) fn find_double_crlf(head: &[u8]) -> Option<usize> {
    const CR: u8 = b'\r';
    const LF: u8 = b'\n';
    const SPREAD: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let n = head.len();
    // A terminator needs four bytes, so the latest start that can still hold one.
    if n < 4 {
        return None;
    }
    let last = n - 4;
    let want_lf = (LF as u64).wrapping_mul(SPREAD);
    let mut word = 0usize;
    // Whole eight-byte blocks: every `\n` in one earns a terminator check at its start.
    while word + 8 <= n {
        let block = u64::from_le_bytes(
            head[word..word + 8]
                .try_into()
                .expect("one eight-byte block"),
        );
        let x = block ^ want_lf;
        // A zero byte of `x` is a `\n` lane; isolate those lanes and walk them low to high.
        let mut lf = x.wrapping_sub(SPREAD) & !x & HIGH;
        while lf != 0 {
            let a = word + lf.trailing_zeros() as usize / 8;
            // The terminator's first `\n` sits one byte past its start (`a >= 1`), which must still hold four bytes (`a - 1 <= last`).
            if a >= 1 && a - 1 <= last {
                let s = a - 1;
                if head[s] == CR && head[s + 2] == CR && head[s + 3] == LF {
                    return Some(s);
                }
            }
            lf &= lf - 1;
        }
        word += 8;
    }
    // Starts past the last whole block, and the one whose first `\n` fell on the block boundary, are too few for SWAR to pay: check them as four-byte windows.
    let mut s = if word == 0 { 0 } else { word - 1 };
    while s <= last {
        if head[s..s + 4] == [CR, LF, CR, LF] {
            return Some(s);
        }
        s += 1;
    }
    None
}

pub(crate) fn find_across(head: &[u8], probe: &[u8], pattern: &[u8]) -> Option<usize> {
    debug_assert!(!pattern.is_empty(), "a pattern of no bytes is everywhere");
    // Optimized for \r\n\r\n pattern
    if pattern == b"\r\n\r\n" {
        let joined = head.len() + probe.len();
        if joined < 4 {
            return None;
        }
        let target = u32::from_le_bytes(*b"\r\n\r\n");
        let start = head.len().saturating_sub(3);
        // Only up to three windows can touch the head/probe seam, so assemble those byte by byte.
        let straddle_end = head.len().min(joined.saturating_sub(3));
        let mut pos = start;
        while pos < straddle_end {
            let bytes = [
                head[pos],
                if pos + 1 < head.len() {
                    head[pos + 1]
                } else {
                    probe[pos + 1 - head.len()]
                },
                if pos + 2 < head.len() {
                    head[pos + 2]
                } else {
                    probe[pos + 2 - head.len()]
                },
                if pos + 3 < head.len() {
                    head[pos + 3]
                } else {
                    probe[pos + 3 - head.len()]
                },
            ];
            if u32::from_le_bytes(bytes) == target {
                return Some(pos);
            }
            pos += 1;
        }
        // Every window past the seam lies wholly inside probe, so read it as one SWAR scan.
        if let Some(at) = find_double_crlf(probe) {
            return Some(head.len() + at);
        }
        return None;
    }
    let span = pattern.len() - 1;
    let joined = head.len() + probe.len();
    let start = head.len().saturating_sub(span);
    let limit = joined.saturating_sub(span);
    (start..limit).find(|&at| {
        let mut k = 0;
        while k < pattern.len() {
            let i = at + k;
            let b = unsafe {
                if i < head.len() {
                    *head.get_unchecked(i)
                } else {
                    *probe.get_unchecked(i - head.len())
                }
            };
            if b != pattern[k] {
                break;
            }
            k += 1;
        }
        k == pattern.len()
    })
}

/// Arm the poll quantum a head read needs: a budget cannot bound a blocking socket call, so the timeout is never longer than the caller's and the previous value goes back.
fn with_head_poll<T>(stream: &mut Connection, run: impl FnOnce(&mut Connection) -> T) -> Option<T> {
    let previous = stream.read_timeout().ok().flatten();
    let poll = previous.map_or(RELAY_POLL, |armed| armed.min(RELAY_POLL));
    if stream.set_read_timeout(Some(poll)).is_err() {
        return None;
    }
    let got = run(stream);
    let _ = stream.set_read_timeout(previous);
    Some(got)
}

pub(crate) fn read_http_head(
    stream: &mut Connection,
    limit: usize,
    budget: Duration,
) -> Option<Vec<u8>> {
    with_head_poll(stream, |stream| peek_head_rounds(stream, limit, budget)).flatten()
}

/// The head and the octets that arrived with it, in the one buffer the caller's reader keeps; the
/// returned length is where the head ends. The peek reader paid a `peek` and a re-read of the same
/// bytes to leave that tail in the socket, so a head of `H` octets crossed user space twice and a
/// round cost two calls; here `H` crosses once and a round costs one. Nothing that has nowhere to
/// put the tail — the `http` front and the Shadowsocks rung's wait for a request packet — may take it.
pub(crate) fn read_http_head_kept(
    stream: &mut Connection,
    limit: usize,
    budget: Duration,
) -> Option<(Vec<u8>, usize)> {
    with_head_poll(stream, |stream| kept_head_rounds(stream, limit, budget)).flatten()
}

/// One round's worth of octets: the peek probe's width, so a head that arrives in pieces costs the same reads it did.
const HEAD_ROUND: usize = 512;

#[allow(
    clippy::uninit_vec,
    reason = "the reader fills the grown bytes, and every path that does not truncates them back"
)]
fn kept_head_rounds(
    stream: &mut dyn Read,
    limit: usize,
    budget: Duration,
) -> Option<(Vec<u8>, usize)> {
    let mut head = Vec::with_capacity(HEAD_ROUND);
    let until = Instant::now() + budget;
    loop {
        if head.len() >= limit {
            return None;
        }
        let base = head.len();
        let want = HEAD_ROUND.min(limit - base);
        head.reserve(want);
        // SAFETY: `read` initialises the bytes it reports, and `set_len` is rolled back on every path that does not.
        unsafe { head.set_len(base + want) };
        let n = match stream.read(&mut head[base..]) {
            Ok(n) => n,
            Err(error) if is_timeout(&error) => {
                head.truncate(base);
                if Instant::now() >= until {
                    return None;
                }
                continue;
            }
            Err(_) => {
                head.truncate(base);
                return None;
            }
        };
        head.truncate(base + n);
        if n == 0 {
            return None;
        }
        // A fresh delimiter can straddle the round's bytes, so the scan starts three octets before them.
        let from = base.saturating_sub(3);
        if let Some(at) = find_double_crlf(&head[from..]).map(|hit| hit + from) {
            return Some((head, at + 4));
        }
    }
}

#[allow(
    clippy::uninit_vec,
    reason = "the tail is handed straight to `read_exact`, and the error path truncates it"
)]
fn peek_head_rounds(stream: &mut Connection, limit: usize, budget: Duration) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut probe = [0u8; 512];
    let until = Instant::now() + budget;
    loop {
        if head.len() >= limit {
            return None;
        }
        let n = match stream.peek(&mut probe) {
            Ok(n) => n,
            Err(error) if is_timeout(&error) => {
                if Instant::now() >= until {
                    return None;
                }
                continue;
            }
            Err(_) => return None,
        };
        if n == 0 {
            return None;
        }
        // `peek` cannot consume: prove the head, then re-read it, leaving pipelined bytes for the caller.
        let want = match find_across(&head, &probe[..n], b"\r\n\r\n") {
            Some(at) => at + 4 - head.len(),
            None => n.min(limit - head.len()),
        };
        let base = head.len();
        head.reserve(want);
        unsafe { head.set_len(base + want) }
        if stream.read_exact(&mut head[base..]).is_err() {
            head.truncate(base);
            return None;
        }
        if head.ends_with(b"\r\n\r\n") {
            return Some(head);
        }
    }
}

/// Head reader for a stream with no `peek`: the kept loop's own buffer and the offset where the head ends, so a head of `H` crosses user space once and its tail is not copied into an allocation of its own.
pub(crate) fn read_exact_head(
    stream: &mut dyn Read,
    limit: usize,
    budget: Duration,
) -> Option<(Vec<u8>, usize)> {
    kept_head_rounds(stream, limit, budget)
}

pub(crate) trait CarrierSink: Clone + Send + 'static {
    fn send(&self, bytes: &[u8]) -> bool;
    fn close(&self);
}

// Vectored write with and without a file descriptor: the socket packs into one `writev` or one `WSASend`, the session feeds its record batcher.
pub(crate) trait FrameWrite: Write + Send {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool;
}

impl FrameWrite for Connection {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        write_all_parts::<VECTOR_PARTS>(self, parts).is_ok()
    }
}

// The h2 server seals frames over a concrete `TcpStream`, so the generic coalescing write is impl'd for it beside the seam.
impl FrameWrite for TcpStream {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        write_all_parts::<VECTOR_PARTS>(self, parts).is_ok()
    }
}

impl<S: ferrox_core::tls::TlsProvider + ferrox_core::tls::RecordAlignment + Send> FrameWrite
    for TlsHalf<S>
{
    // One lock, one call: every part of the frame reaches the session as segments of one payload, so it seals one record where a write per part sealed one each.
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        let Ok(mut session) = self.session.lock() else {
            return false;
        };
        session.write_all_slices(parts).is_ok()
    }
}

pub(crate) fn relay_sink<R, W, F>(reader: R, writer: &W, peer: &Connection, on_reader_done: F)
where
    R: Read,
    W: CarrierSink,
    F: FnOnce(&mut R),
{
    relay_ordered::<R, W, F, CLOSE_BEFORE_JOIN>(reader, writer, peer, on_reader_done);
}

const CLOSE_BEFORE_JOIN: bool = true;

const CLOSE_AFTER_JOIN: bool = false;

fn relay_ordered<R, W, F, const CLOSE_FIRST: bool>(
    mut reader: R,
    writer: &W,
    peer: &Connection,
    on_reader_done: F,
) where
    R: Read,
    W: CarrierSink,
    F: FnOnce(&mut R),
{
    echo_trace("relay start");
    let Ok(peer_read) = peer.try_clone() else {
        echo_trace("relay no peer");
        return;
    };
    let Ok(peer_write) = peer.try_clone() else {
        return;
    };
    let mut peer_read = peer_read;
    let mut peer_write = peer_write;
    let uplink = writer.clone();
    let done = thread::spawn(move || {
        let mut buf = RelayBuf::new();
        let mut first = true;
        loop {
            match peer_read.read(buf.as_mut()) {
                Ok(n) if n > 0 => {
                    if first {
                        echo_trace("relay fwd first read");
                    }
                    if first {
                        echo_trace("relay fwd sending");
                    }
                    let sent = uplink.send(&buf.as_mut()[..n]);
                    if first {
                        echo_trace("relay fwd sent");
                    }
                    if first {
                        echo_trace(if sent {
                            "relay fwd first send ok"
                        } else {
                            "relay fwd first send failed"
                        });
                        first = false;
                    }
                    if !sent {
                        echo_trace("relay fwd send failed");
                        break;
                    }
                }
                Err(error) if is_timeout(&error) => {}
                Err(error) => {
                    echo_trace(&format!("relay fwd read err {error:?}"));
                    break;
                }
                Ok(_) => {
                    echo_trace("relay fwd eof");
                    break;
                }
            }
        }
        if CLOSE_FIRST {
            uplink.close();
            let _ = peer_read.shutdown(Shutdown::Both);
        }
    });
    let mut buf = RelayBuf::new();
    let mut first = true;
    loop {
        match reader.read(buf.as_mut()) {
            Ok(n) if n > 0 => {
                if first {
                    echo_trace("relay bwd first read");
                }
                if first {
                    echo_trace("relay bwd forwarding");
                }
                if peer_write.write_all(&buf.as_mut()[..n]).is_err() {
                    echo_trace("relay bwd peer write failed");
                    break;
                }
                if first {
                    echo_trace("relay bwd forwarded");
                    first = false;
                }
            }
            Err(error) if is_timeout(&error) => {}
            Err(error) => {
                echo_trace(&format!("relay bwd read err {error:?}"));
                break;
            }
            Ok(_) => {
                echo_trace("relay bwd eof");
                break;
            }
        }
    }
    if CLOSE_FIRST {
        writer.close();
        on_reader_done(&mut reader);
        let _ = peer_write.shutdown(Shutdown::Both);
        let _ = done.join();
    } else {
        let _ = peer_write.shutdown(Shutdown::Write);
        let _ = done.join();
        writer.close();
        let _ = peer_write.shutdown(Shutdown::Both);
    }
}

pub(crate) fn relay_sink_drained<R: Read, W: CarrierSink>(
    reader: R,
    writer: &W,
    peer: &Connection,
) {
    relay_ordered::<R, W, fn(&mut R), CLOSE_AFTER_JOIN>(reader, writer, peer, |_| {});
}

pub(crate) fn relay_carried<R: Read>(mut reader: R, write: &Connection, peer: &Connection) {
    let Ok(peer_read) = peer.try_clone() else {
        return;
    };
    let Ok(peer_write) = peer.try_clone() else {
        return;
    };
    let mut peer_read = peer_read;
    let mut peer_write = peer_write;
    let Ok(mut uplink) = write.try_clone() else {
        return;
    };
    let done = thread::spawn(move || {
        let mut buf = RelayBuf::new();
        loop {
            match peer_read.read(buf.as_mut()) {
                Ok(n) if n > 0 => {
                    if uplink.write_all(&buf.as_mut()[..n]).is_err() {
                        break;
                    }
                }
                Err(error) if is_timeout(&error) => {}
                _ => break,
            }
        }
        let _ = uplink.shutdown(Shutdown::Write);
    });
    let mut buf = RelayBuf::new();
    loop {
        match reader.read(buf.as_mut()) {
            Ok(n) if n > 0 => {
                if peer_write.write_all(&buf.as_mut()[..n]).is_err() {
                    break;
                }
            }
            Err(error) if is_timeout(&error) => {}
            _ => break,
        }
    }
    // Half-close this direction's write only: `Both` would abort the sibling clone's still-open read and drop a pending download.
    let _ = peer_write.shutdown(Shutdown::Write);
    let _ = done.join();
}

// A quiet socket is not a dead one: retry the relay's poll grain, fail only a closed stream.
pub(crate) fn read_exact(stream: &mut dyn Read, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => buf = &mut buf[n..],
            Err(error) if is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    header_value_in(std::str::from_utf8(head).ok()?, name)
}

/// The lookup over a head somebody already paid one `from_utf8` for, so a head read for three names is validated once.
pub(crate) fn header_value_in<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut lines = text.split("\r\n");
    lines.next()?;
    for line in lines {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

pub(crate) fn request_path(head: &[u8]) -> Option<&str> {
    request_path_in(std::str::from_utf8(head).ok()?)
}

pub(crate) fn request_path_in(text: &str) -> Option<&str> {
    let line = text.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    Some(target.split_once('?').map_or(target, |(base, _)| base))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddrKind {
    V4,
    V6,
    Domain,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AddrBody<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(&'a str),
}

pub(crate) fn parse_addr_body(buf: &[u8], kind: AddrKind) -> Option<(AddrBody<'_>, usize)> {
    match kind {
        AddrKind::V4 => {
            let ip: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
            Some((AddrBody::V4(ip), 5))
        }
        AddrKind::V6 => {
            let ip: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            Some((AddrBody::V6(ip), 17))
        }
        AddrKind::Domain => {
            let len = usize::from(*buf.get(1)?);
            if len == 0 {
                return None;
            }
            let host = std::str::from_utf8(buf.get(2..2 + len)?).ok()?;
            Some((AddrBody::Domain(host), 2 + len))
        }
    }
}

/// The keys of this span and the previous one: a key is refused as a replay for at least `span` seconds, and the rotation after that is what forgets it.
pub(crate) struct Replay {
    current: HashSet<[u8; 32]>,
    prev: HashSet<[u8; 32]>,
    rotated_at: u64,
    span: u64,
}

/// Keys one half of a window holds before it rotates early, so a flood bounds the window instead of growing it.
pub(crate) const REPLAY_KEYS: usize = 64 * 1024;

impl Replay {
    pub(crate) fn new(span: u64) -> Self {
        Self {
            current: HashSet::new(),
            prev: HashSet::new(),
            rotated_at: 0,
            span,
        }
    }

    /// Whether this key was already seen inside the window; the clock is the caller's, so the bounds are testable without waiting on it.
    pub(crate) fn seen(&mut self, key: &[u8; 32], now: u64) -> bool {
        if now.wrapping_sub(self.rotated_at) >= self.span || self.current.len() >= REPLAY_KEYS {
            self.prev = std::mem::take(&mut self.current);
            self.rotated_at = now;
        }
        if self.current.contains(key) || self.prev.contains(key) {
            return true;
        }
        self.current.insert(*key);
        false
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.current.len() + self.prev.len()
    }
}

/// The two `writev` parts: header plus payload handed over by pointer — why the mux uplink copies zero.
#[cfg(unix)]
pub(crate) fn two_iovecs(first: &[u8], second: &[u8]) -> [libc::iovec; 2] {
    [
        libc::iovec {
            iov_base: first.as_ptr() as *mut libc::c_void,
            iov_len: first.len(),
        },
        libc::iovec {
            iov_base: second.as_ptr() as *mut libc::c_void,
            iov_len: second.len(),
        },
    ]
}

/// One datagram as its two parts. `sendmsg` hands the head and the caller's payload to the kernel
/// by pointer, so a reply is not gathered into a second buffer first; a platform without it joins
/// the parts, which is the same datagram in the same one call. The pointer gate
/// `a_udp_reply_hands_the_payload_over_by_pointer` is what can see the difference.
fn send_to_two(
    socket: &UdpSocket,
    first: &[u8],
    second: &[u8],
    dest: SocketAddr,
) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let mut parts = two_iovecs(first, second);
        let (storage, len) = sockaddr_of(dest);
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&raw const storage).cast_mut().cast();
        msg.msg_namelen = len;
        msg.msg_iov = parts.as_mut_ptr();
        // glibc sizes `msg_iovlen` as a `usize`, every other unix in scope as a 32-bit count.
        #[cfg(target_os = "linux")]
        let count = parts.len();
        #[cfg(not(target_os = "linux"))]
        let count: libc::c_int = parts.len().try_into().expect("two iovecs fit the field");
        msg.msg_iovlen = count;
        loop {
            // SAFETY: `msg` names `parts` and `storage`, both live and sized as the call reads them.
            let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &raw const msg, 0) };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let mut one = Vec::with_capacity(first.len() + second.len());
        one.extend_from_slice(first);
        one.extend_from_slice(second);
        socket.send_to(&one, dest)
    }
}

/// The `sockaddr` a datagram goes to, and its length, in the storage the kernel reads it from.
#[cfg(unix)]
fn sockaddr_of(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let len = std::mem::size_of::<libc::sockaddr_in>();
            // SAFETY: a `sockaddr_in` is shorter and no more aligned than the storage it is built in.
            let sin = unsafe { &mut *(&raw mut storage).cast::<libc::sockaddr_in>() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            // A BSD sockaddr carries its own length as the first byte; Linux's family starts there.
            #[cfg(any(
                target_vendor = "apple",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "dragonfly"
            ))]
            {
                sin.sin_len = len as u8;
            }
            (storage, len as libc::socklen_t)
        }
        SocketAddr::V6(v6) => {
            let len = std::mem::size_of::<libc::sockaddr_in6>();
            // SAFETY: `sockaddr_in6` is shorter and no more aligned than the storage it is built in.
            let sin6 = unsafe { &mut *(&raw mut storage).cast::<libc::sockaddr_in6>() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_scope_id = v6.scope_id();
            #[cfg(any(
                target_vendor = "apple",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "dragonfly"
            ))]
            {
                sin6.sin6_len = len as u8;
            }
            (storage, len as libc::socklen_t)
        }
    }
}

/// Segments one vectored write carries: a gathered batch of h2 frames is sixty-four of them, and the
/// list stays on the stack at that width on every platform in scope.
const VECTOR_PARTS: usize = 64;

/// The segment that fills a stack list before the live parts overwrite it.
const NO_PARTS: &[u8] = &[];

/// Hand `parts` to `out` in as few vectored calls as the socket takes: one `writev` per `N` segments
/// on unix, one `WSASend` on Windows, where a write per part cost one socket call each. A short call
/// advances the list rather than restaging any byte, so the parts stay where the caller put them
/// however the kernel splits the write. `N` is the caller's own batch width, so a list is never wider
/// than the call it serves and never touches the heap.
pub(crate) fn write_all_parts<const N: usize>(
    out: &mut dyn Write,
    mut parts: &[&[u8]],
) -> std::io::Result<()> {
    while !parts.is_empty() {
        let (chunk, rest) = parts.split_at(parts.len().min(N));
        let mut made: [IoSlice; N] = std::array::from_fn(|_| IoSlice::new(NO_PARTS));
        let mut pieces = 0usize;
        for part in chunk.iter().copied().filter(|part| !part.is_empty()) {
            made[pieces] = IoSlice::new(part);
            pieces += 1;
        }
        let mut slices = &mut made[..pieces];
        while !slices.is_empty() {
            let wrote = out.write_vectored(slices)?;
            if wrote == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }
            IoSlice::advance_slices(&mut slices, wrote);
        }
        parts = rest;
    }
    Ok(())
}

/// Hand `parts` runs of `buf` to `out` in one vectored write: one syscall where the socket has
/// `writev`, one where it has `WSASend`, one per run where the sink has neither, and none at all for
/// an empty batch — so a caller that opened several records into one buffer leaves them where they
/// lie instead of gathering them. `N` is the caller's batch width, so the segment list never touches
/// the heap.
pub(crate) fn write_all_runs<const N: usize>(
    out: &mut dyn Write,
    buf: &[u8],
    parts: &[(usize, usize)],
) -> std::io::Result<()> {
    let mut made: [&[u8]; N] = [NO_PARTS; N];
    let mut pieces = 0usize;
    for (start, len) in parts.iter().copied() {
        if len > 0 {
            made[pieces] = &buf[start..start + len];
            pieces += 1;
        }
    }
    write_all_parts::<N>(out, &made[..pieces])
}

/// The app's payload pumped while the carrier still owes its answer, because a server may hold that answer until it sees payload — xray flushes its buffered response on the first downstream write and zeronet's `HeaderFirst::hold` waits for the first payload outright — so a client that stops sending to wait hangs both ways.
pub(crate) struct Pump {
    stop: std::sync::mpsc::Sender<()>,
    running: Option<std::sync::mpsc::Receiver<()>>,
}

impl Pump {
    /// Pumps the app's bytes through `to_carrier` once the answer is overdue; the leg is the only reader of the app's socket until `end` joins it.
    fn over(peer: &Connection, mut to_carrier: impl FnMut(&[u8]) -> bool + Send + 'static) -> Self {
        let (stop, stop_rx) = std::sync::mpsc::channel();
        let running = match peer.try_clone() {
            Ok(reading) => Some(RelayPool::global().run(move || {
                use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
                let mut reading = reading;
                if !matches!(
                    stop_rx.recv_timeout(budgets::payload_grace()),
                    Err(RecvTimeoutError::Timeout)
                ) {
                    return;
                }
                let _ = reading.set_read_timeout(Some(RELAY_POLL));
                // The same reused, uninitialised buffer the relay uses: no 16 KiB memset for bytes the first read overwrites.
                let mut buffer = RelayBuf::new();
                loop {
                    match reading.read(buffer.as_mut()) {
                        Ok(size) if size > 0 => {
                            if !to_carrier(buffer.filled(size)) {
                                break;
                            }
                        }
                        Err(error) if is_timeout(&error) => {
                            if !matches!(stop_rx.try_recv(), Err(TryRecvError::Empty)) {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                // A poll quantum left armed on the shared descriptor would make every later reader spin.
                let _ = reading.set_read_timeout(None);
            })),
            Err(_) => None,
        };
        Self { stop, running }
    }

    fn to_sink<W: CarrierSink>(peer: &Connection, writer: &W) -> Self {
        let sink = writer.clone();
        Self::over(peer, move |bytes| sink.send(bytes))
    }

    fn to_stream(peer: &Connection, write: &Connection) -> Self {
        let Ok(mut uplink) = write.try_clone() else {
            return Self::idle();
        };
        Self::over(peer, move |bytes| uplink.write_all(bytes).is_ok())
    }

    /// A pump with nothing to pump: a socket whose descriptor cannot be duplicated again.
    fn idle() -> Self {
        let (stop, _) = std::sync::mpsc::channel();
        Self {
            stop,
            running: None,
        }
    }

    /// Stops the leg and waits for it, so the session's own upload leg is the only reader afterwards.
    fn end(self) {
        let _ = self.stop.send(());
        if let Some(running) = self.running {
            join(&running);
        }
    }
}

pub(crate) fn read_vless_response(stream: &mut dyn Read) -> Option<()> {
    let mut prefix = [0u8; 2];
    read_exact(stream, &mut prefix).ok()?;
    let consumed = ferrox_core::vless::VlessLink::decode_response_header(&prefix).ok()?;
    if consumed > 2 {
        let mut rest = vec![0u8; consumed - 2];
        read_exact(stream, &mut rest).ok()?;
    }
    if echo_trace_on() {
        echo_trace("response ok");
    }
    Some(())
}

const MUX_TARGET: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 666);

pub(crate) fn decode_request(stream: &mut dyn Read) -> Option<([u8; 16], String, u8, SocketAddr)> {
    let mut head = [0u8; 18];
    read_exact(stream, &mut head).ok()?;
    if head[0] != 0 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&head[1..17]);
    let addons = usize::from(head[17]);
    // The add-ons and the command byte are contiguous, and every request — a mux one included — puts its next field after the command, so this one read is always header. The addons length is a single byte, so the buffer lives on the stack.
    let mut rest = [0u8; 256];
    read_exact(stream, &mut rest[..=addons]).ok()?;
    let cmd = rest[addons];
    let flow = if addons == 0 {
        String::new()
    } else {
        addons_flow(&rest[..addons])
    };
    if cmd == 3 {
        return Some((id, flow, cmd, MUX_TARGET));
    }
    // Port, family, and the body's first byte are the same four bytes for every family — an IPv4 or IPv6 octet, or a domain's length — so the whole address header is served by this read and one more.
    let mut tail = [0u8; 4];
    read_exact(stream, &mut tail).ok()?;
    let port = u16::from_be_bytes([tail[0], tail[1]]);
    let first = tail[3];
    let target = match tail[2] {
        1 => {
            let mut octets = [first; 4];
            read_exact(stream, &mut octets[1..]).ok()?;
            SocketAddr::new(std::net::IpAddr::V4(octets.into()), port)
        }
        2 => {
            let mut name = vec![0u8; usize::from(first)];
            read_exact(stream, &mut name).ok()?;
            let host = String::from_utf8(name).ok()?;
            resolve_endpoint(&host, port)?
        }
        3 => {
            let mut octets = [first; 16];
            read_exact(stream, &mut octets[1..]).ok()?;
            SocketAddr::new(std::net::IpAddr::V6(octets.into()), port)
        }
        _ => return None,
    };
    Some((id, flow, cmd, target))
}

fn addons_flow(body: &[u8]) -> String {
    let mut at = 0;
    while at < body.len() {
        let tag = body[at];
        at += 1;
        let (field, wire) = (tag >> 3, tag & 0x07);
        let Some(len) = read_varint(body, &mut at) else {
            return String::new();
        };
        let len = len as usize;
        match (field, wire) {
            (1, 2) => {
                return body
                    .get(at..at.saturating_add(len))
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .unwrap_or_default()
                    .to_owned();
            }
            (0, _) | (1, 0) | (_, 2) => at += len,
            (_, 5) => at += 4,
            (_, 1) => at += 8,
            _ => return String::new(),
        }
    }
    String::new()
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

/// The longest trojan header: key, CRLF, command, a 255-byte domain with its port, and CRLF.
const TROJAN_HEAD_MAX: usize = 56 + 2 + 1 + 1 + 1 + 255 + 2 + 2;

/// Compares every byte, so timing hides how much of the key was right and a short read never agrees.
fn key_agrees(got: &[u8], key: &[u8; 56]) -> bool {
    if got.len() != key.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(key) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Fills `head[..want]`: a `dyn Read` may answer short, so this loops; the count is what the header costs.
fn trojan_take(
    stream: &mut dyn Read,
    head: &mut [u8; TROJAN_HEAD_MAX],
    filled: &mut usize,
    want: usize,
) -> bool {
    while *filled < want {
        match stream.read(&mut head[*filled..want]) {
            Ok(0) => return false,
            Ok(n) => *filled += n,
            Err(error) if is_timeout(&error) => {}
            Err(_) => return false,
        }
    }
    true
}

/// The whole header in one read, parsed in place: 2-3 reads where the field-at-a-time parse spent 7-8.
fn decode_trojan_request(stream: &mut dyn Read, key: &[u8; 56]) -> Option<(u8, SocketAddr)> {
    let mut head = [0u8; TROJAN_HEAD_MAX];
    let mut filled = 0usize;
    if !trojan_take(stream, &mut head, &mut filled, 60)
        || !key_agrees(&head[..56], key)
        || head[56..58] != *b"\r\n"
    {
        return None;
    }
    let cmd = head[58];
    // The port ends the address in every form, so the header's closing CRLF is the two bytes after it.
    let (target, port_end) = match head[59] {
        1 => {
            if !trojan_take(stream, &mut head, &mut filled, 68) {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&head[60..64]);
            let port = u16::from_be_bytes([head[64], head[65]]);
            (SocketAddr::new(std::net::IpAddr::V4(ip.into()), port), 66)
        }
        4 => {
            if !trojan_take(stream, &mut head, &mut filled, 80) {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&head[60..76]);
            let port = u16::from_be_bytes([head[76], head[77]]);
            (SocketAddr::new(std::net::IpAddr::V6(ip.into()), port), 78)
        }
        3 => {
            if !trojan_take(stream, &mut head, &mut filled, 61) {
                return None;
            }
            let name_end = 61 + usize::from(head[60]);
            if !trojan_take(stream, &mut head, &mut filled, name_end + 4) {
                return None;
            }
            let host = std::str::from_utf8(&head[61..name_end]).ok()?;
            let port = u16::from_be_bytes([head[name_end], head[name_end + 1]]);
            (resolve_endpoint(host, port)?, name_end + 2)
        }
        _ => return None,
    };
    if head[port_end..port_end + 2] != *b"\r\n" {
        return None;
    }
    Some((cmd, target))
}

pub(crate) fn push_addr(header: &mut Vec<u8>, target: &SocketAddr, v6: u8) {
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            header.push(v6);
            header.extend_from_slice(&ip.octets());
        }
    }
}

pub(crate) fn push_socks_addr(out: &mut Vec<u8>, addr: &SocketAddr) {
    push_addr(out, addr, 4);
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Read a SOCKS address body straight off a slice: the same field order `read_socks_addr_rest` draws from a stream, read where the bytes already lie, so a relayed datagram pays no cursor, no `dyn Read` call per field and no copy into scratch.
fn parse_socks_addr_rest(buf: &[u8], atyp: u8) -> Option<(SocketAddr, usize)> {
    match atyp {
        1 => {
            let ip: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            let port: [u8; 2] = buf.get(4..6)?.try_into().ok()?;
            Some((
                SocketAddr::new(std::net::IpAddr::V4(ip.into()), u16::from_be_bytes(port)),
                6,
            ))
        }
        3 => {
            let len = usize::from(*buf.first()?);
            let name = buf.get(1..1 + len)?;
            let port: [u8; 2] = buf.get(1 + len..3 + len)?.try_into().ok()?;
            let host = std::str::from_utf8(name).ok()?;
            let addr = format!("{host}:{}", u16::from_be_bytes(port))
                .to_socket_addrs()
                .ok()?
                .next()?;
            Some((addr, 3 + len))
        }
        4 => {
            let ip: [u8; 16] = buf.get(..16)?.try_into().ok()?;
            let port: [u8; 2] = buf.get(16..18)?.try_into().ok()?;
            Some((
                SocketAddr::new(std::net::IpAddr::V6(ip.into()), u16::from_be_bytes(port)),
                18,
            ))
        }
        _ => None,
    }
}

pub(crate) fn parse_socks_udp(packet: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let (addr, used) = parse_socks_addr_rest(&packet[4..], packet[3])?;
    Some((addr, &packet[4 + used..]))
}

/// The handshake that keeps the client's name: resolving here hands the edge an address it cannot route.
fn socks_target(client: &mut Connection, grant: bool) -> Option<(u8, Destination)> {
    // Bound only the greeting to a wall-clock budget, then restore the untimed relay reads behind it.
    let budget = budgets::handshake();
    let _ = client.set_read_timeout(Some(budget));
    let asked = socks_request(client, grant, Instant::now() + budget);
    let _ = client.set_read_timeout(None);
    asked
}

/// Each greeting read under the deadline the caller armed: the relay's `read_exact` retries a quiet socket forever, so the socket's poll quantum wakes the read and the deadline ends it.
fn socks_request(
    client: &mut Connection,
    grant: bool,
    until: Instant,
) -> Option<(u8, Destination)> {
    let mut head = [0u8; 2];
    read_exact(
        &mut HandshakeDeadline {
            inner: &mut *client,
            until,
        },
        &mut head,
    )
    .ok()?;
    if head[0] != 5 {
        return None;
    }
    // The offered-method count is an unauthenticated byte and the list is never inspected, so drain it on the stack (head[1] can never overrun the 255-byte array) to keep the heap off the pre-auth path.
    let mut methods = [0u8; u8::MAX as usize];
    read_exact(
        &mut HandshakeDeadline {
            inner: &mut *client,
            until,
        },
        &mut methods[..usize::from(head[1])],
    )
    .ok()?;
    if client.write_all(&[5, 0]).is_err() {
        return None;
    }
    let mut req = [0u8; 4];
    read_exact(
        &mut HandshakeDeadline {
            inner: &mut *client,
            until,
        },
        &mut req,
    )
    .ok()?;
    if req[0] != 5 || (req[1] != 1 && req[1] != 3) {
        return None;
    }
    let target = read_socks_named(
        &mut HandshakeDeadline {
            inner: &mut *client,
            until,
        },
        req[3],
    )?;
    if grant && req[1] == 1 && client.write_all(&foxy_socks_reply(0)).is_err() {
        return None;
    }
    Some((req[1], target))
}

fn read_socks_named(stream: &mut dyn Read, atyp: u8) -> Option<Destination> {
    match atyp {
        3 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(Destination::Name(
                String::from_utf8(name).ok()?,
                u16::from_be_bytes(port),
            ))
        }
        _ => Some(Destination::Address(read_socks_addr_rest(stream, atyp)?)),
    }
}

/// What the client asked for: a name the edge resolves itself, or an address. A name stays a name down to the request bytes, because a client that looks the name up itself sends the edge an address for a destination it never kept, and the lookup itself is visible to whoever watches its resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Destination {
    Name(String, u16),
    Address(SocketAddr),
}

impl Destination {
    fn authority(&self) -> String {
        match self {
            Self::Name(host, port) => ferrox_core::foxy::authority(host, *port),
            Self::Address(address) => address.to_string(),
        }
    }

    /// The address to connect to directly: only a lane that carries no destination answers the name itself.
    fn socket(&self) -> Option<SocketAddr> {
        match self {
            Self::Address(address) => Some(*address),
            Self::Name(host, port) => format!("{host}:{port}")
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next()),
        }
    }

    fn host(&self) -> String {
        match self {
            Self::Name(host, _) => host.clone(),
            Self::Address(address) => address.ip().to_string(),
        }
    }

    pub(crate) fn port(&self) -> u16 {
        match self {
            Self::Name(_, port) => *port,
            Self::Address(address) => address.port(),
        }
    }

    /// The family byte and its body: `v6` is what this protocol numbers IPv6 and `domain` what it numbers a name, and the two conventions in the tree differ.
    pub(crate) fn push_addr(&self, out: &mut Vec<u8>, v6: u8, domain: u8) {
        match self {
            Self::Address(address) => push_addr(out, address, v6),
            Self::Name(host, _) => {
                out.push(domain);
                out.push(host.len() as u8);
                out.extend_from_slice(host.as_bytes());
            }
        }
    }

    /// The bytes `push_addr` writes, so a header reserves for the destination it holds.
    pub(crate) fn addr_len(&self) -> usize {
        match self {
            Self::Address(address) => {
                if address.is_ipv6() {
                    17
                } else {
                    5
                }
            }
            Self::Name(host, _) => host.len() + 2,
        }
    }
}

impl From<SocketAddr> for Destination {
    fn from(address: SocketAddr) -> Self {
        Self::Address(address)
    }
}

impl std::str::FromStr for Destination {
    type Err = &'static str;

    fn from_str(authority: &str) -> Result<Self, Self::Err> {
        authority_target(authority.as_bytes()).ok_or("no destination in this authority")
    }
}

fn read_socks_addr(stream: &mut dyn Read) -> Option<SocketAddr> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).ok()?;
    read_socks_addr_rest(stream, atyp[0])
}

fn read_socks_addr_rest(stream: &mut dyn Read, atyp: u8) -> Option<SocketAddr> {
    match atyp {
        1 => {
            let mut ip = [0u8; 4];
            read_exact(stream, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(SocketAddr::new(
                std::net::IpAddr::V4(ip.into()),
                u16::from_be_bytes(port),
            ))
        }
        3 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            let host = String::from_utf8(name).ok()?;
            format!("{host}:{}", u16::from_be_bytes(port))
                .to_socket_addrs()
                .ok()?
                .next()
        }
        4 => {
            let mut ip = [0u8; 16];
            read_exact(stream, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(SocketAddr::new(
                std::net::IpAddr::V6(ip.into()),
                u16::from_be_bytes(port),
            ))
        }
        _ => None,
    }
}

fn inbound_first_client(inbound: &Json) -> Option<&Json> {
    inbound
        .get("settings")
        .and_then(|s| s.get("clients"))
        .and_then(Json::as_arr)
        .and_then(|clients| clients.first())
}

fn inbound_id(inbound: &Json) -> [u8; 16] {
    inbound_first_client(inbound)
        .and_then(|client| client.get("id"))
        .and_then(Json::as_str)
        .and_then(uuid_bytes)
        .unwrap_or([0u8; 16])
}

fn has_protocol(root: &Json, array: &str, protocol: &str) -> bool {
    root.get(array).and_then(Json::as_arr).is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("protocol").and_then(Json::as_str) == Some(protocol))
    })
}

fn inbound_method(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("method"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

pub(crate) fn inbound_ss_password(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

fn inbound_password(inbound: &Json) -> String {
    inbound_first_client(inbound)
        .and_then(|client| client.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

fn find_outbound(root: &Json) -> Option<Outbound> {
    if let Some(foxy) = find_foxy_outbound(root) {
        return Some(Outbound::Foxy(Box::new(foxy)));
    }
    if let Some(vless) = find_vless_outbound(root) {
        return Some(Outbound::Vless(vless));
    }
    if let Some(vmess) = find_vmess_outbound(root) {
        return Some(Outbound::Vmess(vmess));
    }
    if let Some(trojan) = find_trojan_outbound(root) {
        return Some(Outbound::Trojan(trojan));
    }
    if let Some(http) = find_http_outbound(root) {
        return Some(Outbound::Http(http));
    }
    find_shadowsocks_outbound(root)
        .map(Outbound::Shadowsocks)
        .or_else(|| is_freedom(root).then_some(Outbound::Freedom))
}

fn is_freedom(root: &Json) -> bool {
    has_protocol(root, "outbounds", "freedom")
}

/// The tag a `loopback` outbound re-injects through, or nothing when no such
/// outbound is configured to carry. An empty tag and an enabled sniffer skip
/// the outbound the way other uncarriable settings skip theirs: the tag is
/// the whole route, and sniffing belongs to the engine sniffer this tree has
/// not built.
fn find_loopback_outbound(root: &Json) -> Option<String> {
    let outbounds = root.get("outbounds").and_then(Json::as_arr)?;
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("loopback") {
            continue;
        }
        let settings = outbound.get("settings")?;
        let tag = settings
            .get("inboundTag")
            .and_then(Json::as_str)
            .filter(|tag| !tag.is_empty())?;
        let sniffing = settings
            .get("sniffing")
            .and_then(|sniffing| sniffing.get("enabled"))
            .and_then(Json::as_bool)
            .unwrap_or(false);
        if sniffing {
            continue;
        }
        return Some(tag.to_owned());
    }
    None
}

/// Whether the redial speaks the named carrier over plain TCP. Datagram
/// handshakes need a session and roots the inbound JSON does not carry, so
/// they refuse here rather than dialling half a handshake.
fn loopback_carrier(carrier: &Carrier) -> bool {
    matches!(
        carrier,
        Carrier::Raw(_)
            | Carrier::Ws { .. }
            | Carrier::HttpUpgrade { .. }
            | Carrier::Grpc { .. }
            | Carrier::Xhttp { .. }
            | Carrier::HttpHeader { .. }
    )
}

/// The client dial a `loopback` outbound desugars to: the named inbound's own
/// credentials pointed at where it listens, so the re-injected flow carries a
/// real handshake on the loopback wire. The tag bookkeeping xray keeps for a
/// second routing pass has nothing to select here — fronts take the single
/// outbound and servers take freedom — so resolving at startup is the whole
/// re-inject, with no per-flow hop of its own.
fn resolve_loopback(root: &Json, tag: &str, freedom: bool) -> Result<Outbound, String> {
    let empty = Vec::new();
    let inbounds = root
        .get("inbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    let inbound = inbounds
        .iter()
        .find(|inbound| inbound.get("tag").and_then(Json::as_str) == Some(tag))
        .ok_or_else(|| format!("names an unknown inbound `{tag}`"))?;
    let protocol = inbound.get("protocol").and_then(Json::as_str).unwrap_or("");
    // A front would re-enter this same resolution through the single outbound.
    if matches!(protocol, "socks" | "http" | "mixed") {
        return Err(format!(
            "names front `{tag}`, which would re-enter the loopback"
        ));
    }
    if !freedom {
        return Err(format!(
            "names `{tag}`, which has no freedom outbound to leave by"
        ));
    }
    let listen = inbound
        .get("listen")
        .and_then(Json::as_str)
        .unwrap_or("127.0.0.1");
    // An every-interface bind is redialled where it also answers.
    let listen = match listen {
        "0.0.0.0" | "::" | "" => "127.0.0.1",
        named => named,
    };
    let Some(port) = inbound.get("port").and_then(Json::as_port) else {
        return Err(format!("names `{tag}`, which binds no port"));
    };
    let address = listen.to_owned();
    loopback_dial(inbound, protocol, &address, port, tag)
}

/// The named inbound's own credentials pointed at where it listens, so the
/// re-injected flow carries a real handshake on the loopback wire.
fn loopback_dial(
    inbound: &Json,
    protocol: &str,
    address: &str,
    port: u16,
    tag: &str,
) -> Result<Outbound, String> {
    match protocol {
        "vless" if vless_security_supported(stream_security(inbound)) => {
            let (carrier, host) = loopback_carrier_of(inbound, address, tag)?;
            Ok(Outbound::Vless(VlessOut {
                address: address.to_owned(),
                port,
                id: inbound_id(inbound),
                carrier,
                host,
                mux: false,
                quic_roots: None,
                hysteria_roots: None,
                tls: None,
                flow: String::new(),
                reality: None,
            }))
        }
        "trojan" if matches!(stream_security(inbound), "" | "none") => {
            let (carrier, host) = loopback_carrier_of(inbound, address, tag)?;
            Ok(Outbound::Trojan(TrojanOut {
                address: address.to_owned(),
                port,
                key: trojan_key(&inbound_password(inbound)),
                carrier,
                host,
                tls: None,
            }))
        }
        "vmess" if matches!(stream_security(inbound), "" | "none") => {
            let (carrier, host) = loopback_carrier_of(inbound, address, tag)?;
            let cipher = crate::vmess::Cipher::parse(
                inbound_first_client(inbound)
                    .and_then(|client| client.get("security"))
                    .and_then(Json::as_str)
                    .unwrap_or("auto"),
            );
            Ok(Outbound::Vmess(VmessOut {
                address: address.to_owned(),
                port,
                id: inbound_id(inbound),
                cipher,
                carrier,
                host,
                tls: None,
            }))
        }
        "shadowsocks" if matches!(stream_security(inbound), "" | "none") => {
            let method = inbound_method(inbound);
            if !inbound_ss_destinations(inbound, &method).is_empty() {
                return Err(format!(
                    "names `{tag}`, which relays to fixed destinations rather than freedom"
                ));
            }
            let (carrier, host) = loopback_carrier_of(inbound, address, tag)?;
            Ok(Outbound::Shadowsocks(ShadowsocksOut {
                address: address.to_owned(),
                port,
                method,
                password: inbound_ss_password(inbound),
                carrier,
                host,
            }))
        }
        _ => Err(format!(
            "names `{tag}` speaking `{protocol}`, which no client dial here replays"
        )),
    }
}

/// The carrier the redial speaks, or the refusal when it speaks none.
fn loopback_carrier_of(
    inbound: &Json,
    address: &str,
    tag: &str,
) -> Result<(Carrier, String), String> {
    let (carrier, host) = outbound_carrier(inbound, address);
    if loopback_carrier(&carrier) {
        Ok((carrier, host))
    } else {
        Err(format!(
            "names `{tag}`, whose carrier no plain-TCP redial speaks"
        ))
    }
}

/// Carrier defaults to `auto`: QUIC, HTTP/2, HTTP/1.1. A named edge is dialed whatever the catalogue publishes.
fn foxy_candidates(
    outbound: &Json,
    link: &ferrox_core::foxy::link::FoxyLink,
    country: &str,
    city: &str,
    roots: Vec<Vec<u8>>,
) -> Vec<ferrox_core::foxy::Candidate> {
    let named = link.host();
    let named_edge = (!named.is_empty()).then(|| ferrox_core::foxy::Candidate {
        host: named.to_owned(),
        port: link.port(),
        country: country.to_owned(),
        city: city.to_owned(),
    });
    let configured_edges = foxy_edges(outbound, country, city);
    if let Some(edge) = named_edge {
        return vec![edge];
    }
    if !configured_edges.is_empty() {
        return configured_edges;
    }
    crate::foxy_catalog::edges(roots)
}

/// A configured edge address, resolved once for every dial; otherwise catalogue names resolve per dial.
fn foxy_edge_address(settings: Option<&Json>) -> Option<SocketAddr> {
    let named = foxy_text(settings, "edgeAddress");
    if named.is_empty() {
        return None;
    }
    resolve(&named, 443)
}

/// Upstream: config first, link second. A value that does not parse is refused, since going direct would leak.
fn foxy_upstream(
    settings: Option<&Json>,
    link: &ferrox_core::foxy::link::FoxyLink,
) -> Result<Option<crate::foxy::UpstreamProxy>, String> {
    let named = foxy_text(settings, "upstreamProxy");
    let named = if named.is_empty() {
        link.upstream_proxy().to_owned()
    } else {
        named
    };
    if named.is_empty() {
        return Ok(None);
    }
    crate::foxy::upstream_proxy(&named).map(Some).ok_or(named)
}

fn foxy_carrier(
    settings: Option<&Json>,
    link: &ferrox_core::foxy::link::FoxyLink,
) -> crate::foxy::Carrier {
    let named = foxy_text(settings, "carrier");
    let named = if named.is_empty() {
        link.carrier().to_owned()
    } else {
        named
    };
    crate::foxy::carrier(&named)
}

/// One field, two spellings: a config array or a comma-separated link, since a link has no arrays.
fn foxy_list_or(
    link: &ferrox_core::foxy::link::FoxyLink,
    settings: Option<&Json>,
    key: &str,
) -> Vec<String> {
    let listed = foxy_strings(settings.and_then(|s| s.get(key)));
    if !listed.is_empty() {
        return listed;
    }
    link.param(key)
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Configured edges in the pinned country, city first, so failover matches the catalogue's own order.
fn foxy_edges(outbound: &Json, country: &str, city: &str) -> Vec<ferrox_core::foxy::Candidate> {
    let edges = outbound
        .get("settings")
        .and_then(|s| s.get("servers"))
        .and_then(Json::as_arr)
        .unwrap_or(&[]);
    edges
        .iter()
        .filter_map(|edge| {
            let host = edge.get("host").and_then(Json::as_str)?.to_owned();
            let port = edge.get("port").and_then(Json::as_port)?;
            let code = edge
                .get("country")
                .and_then(Json::as_str)
                .unwrap_or(country);
            let name = edge.get("city").and_then(Json::as_str).unwrap_or(city);
            Some(ferrox_core::foxy::Candidate {
                host,
                port,
                country: code.to_owned(),
                city: name.to_owned(),
            })
        })
        .collect()
}

fn foxy_strings(value: Option<&Json>) -> Vec<String> {
    value
        .and_then(Json::as_arr)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_owned)
        .collect()
}

fn foxy_ports(value: Option<&Json>) -> Vec<u16> {
    value
        .and_then(Json::as_arr)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_port)
        .collect()
}

/// A `foxy` outbound's account, sign-in or pasted pass, as one `Account` whose pass the renewal thread owns.
fn foxy_account(
    email: &str,
    password: &str,
    code: &str,
    pasted: &ferrox_core::foxy::Pass,
    guardian: &str,
    roots: &[Vec<u8>],
) -> Option<std::sync::Arc<crate::foxy_account::Account>> {
    let pass = pasted.clone();
    if email.is_empty() && pass.token.is_empty() {
        return None;
    }
    let account = std::sync::Arc::new(crate::foxy_account::Account {
        fxa: crate::foxy_account::Endpoint::parse(
            ferrox_core::foxy::account::FXA_SERVER,
            roots.to_vec(),
        )?,
        guardian: crate::foxy_account::Endpoint::parse(guardian, roots.to_vec())?,
        jar: std::sync::Arc::new(std::sync::Mutex::new(crate::foxy_challenge::Jar::default())),
        pending: std::sync::Arc::new(std::sync::Mutex::new(None)),
        auth: std::sync::Arc::new(std::sync::Mutex::new(crate::foxy_account::Auth {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
        })),
        pass: std::sync::Arc::new(std::sync::Mutex::new(pass.clone())),
    });
    if !email.is_empty() && pass.token.is_empty() {
        // Mints collide on one rate-limited plane: a plane refusal retries, a credential refusal does not.
        let mut attempt = 0usize;
        loop {
            match account.sign_in(email, password) {
                Ok(()) => break,
                Err(denied) if attempt + 1 < ACCOUNT_ATTEMPTS && !denied.is_final() => {
                    let pause = crate::foxy_account::renewal_gap(&denied, attempt as u32, None);
                    attempt += 1;
                    eprintln!(
                        "foxy: the account plane refused the sign-in ({denied}), again in {}s",
                        pause.as_secs()
                    );
                    std::thread::sleep(pause);
                }
                Err(denied) => {
                    eprintln!("foxy: the account did not sign in: {denied}");
                    return None;
                }
            }
        }
        if account.needs_code() {
            let Err(denied) = account.verify_code(code) else {
                return Some(account);
            };
            eprintln!("foxy: the account wants a two-factor code in settings.code: {denied}");
            return None;
        }
    }
    Some(account)
}

/// Whether this lane can keep a pass: refuse one it cannot dial or cannot replace, and put the renewal clock on the account that can.
fn foxy_pass_guard(
    account: Option<&std::sync::Arc<crate::foxy_account::Account>>,
    pass: &ferrox_core::foxy::Pass,
) -> Option<String> {
    let renews = account.filter(|account| account.can_renew());
    // A lane that opens fronts over an empty pass answers every flow with a refusal.
    if pass.token.is_empty() {
        return Some("the outbound has no pass to dial with".to_owned());
    }
    // The pass the edge accepts lives minutes, not hours: a pasted one at the end of its window has nobody to replace it.
    if renews.is_none()
        && pass
            .expires_at
            .is_some_and(|at| at <= now_secs().saturating_add(30))
    {
        return Some(format!(
            "settings.pass expires at {:?} and nothing can replace it: serve with email and password, or paste a fresh pass",
            pass.expires_at
        ));
    }
    if let Some(account) = renews {
        start_renewal(std::sync::Arc::clone(account));
    }
    None
}

fn foxy_text(settings: Option<&Json>, key: &str) -> String {
    settings
        .and_then(|s| s.get(key))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Inline field first, link parameter second: when both exist, the written-out one was edited last.
fn foxy_text_or(
    link: &ferrox_core::foxy::link::FoxyLink,
    settings: Option<&Json>,
    key: &str,
) -> String {
    let inline = foxy_text(settings, key);
    if inline.is_empty() {
        link.param(key).to_owned()
    } else {
        inline
    }
}

/// The pinned country, upper-cased so a hand-typed link matches the catalogue; defaults to every account's exit.
fn foxy_country(link: &ferrox_core::foxy::link::FoxyLink, settings: Option<&Json>) -> String {
    let named = foxy_text(settings, "country");
    let named = if named.is_empty() {
        link.country().to_owned()
    } else {
        named
    };
    let named = if named.is_empty() {
        "US".to_owned()
    } else {
        named
    };
    named.to_ascii_uppercase()
}

/// One host as an address, which pins a dial to a host while the TLS name stays the name.
fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
}

fn find_foxy_outbound(root: &Json) -> Option<FoxyOut> {
    let empty = Vec::new();
    for outbound in root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty)
    {
        if outbound.get("protocol").and_then(Json::as_str) != Some("foxy") {
            continue;
        }
        let settings = outbound.get("settings");
        let link = ferrox_core::foxy::link::FoxyLink::parse(&foxy_text(settings, "link"))
            .unwrap_or_default();
        let configured = foxy_text_or(&link, settings, "pass");
        let email = foxy_text_or(&link, settings, "email");
        let password = foxy_text_or(&link, settings, "password");
        let code = foxy_text_or(&link, settings, "code");
        if configured.is_empty() && email.is_empty() {
            continue;
        }
        let country = foxy_country(&link, settings);
        let city = foxy_text_or(&link, settings, "city").to_ascii_uppercase();
        let upstream = match foxy_upstream(settings, &link) {
            Ok(upstream) => upstream,
            Err(named) => {
                eprintln!("foxy: upstreamProxy {named:?} is not http:// or socks5(h)://host:port: serves nothing");
                continue;
            }
        };
        // No CA file trusts the machine's anchors; an empty store is trust-nothing.
        let roots = settings
            .and_then(|s| s.get("caCertFile"))
            .and_then(Json::as_str)
            .and_then(|path| std::fs::read(path).ok())
            .map(|pem| crate::quic::parse_ca_pem(&pem))
            .filter(|roots: &Vec<Vec<u8>>| !roots.is_empty())
            .unwrap_or_else(crate::quic::system_roots);
        let pins = ferrox_core::foxy::pin::Pins::parse(foxy_list_or(&link, settings, "spkiPins"));
        let edge_address = foxy_edge_address(settings);
        let candidates = foxy_candidates(outbound, &link, &country, &city, roots.clone());
        let carrier = foxy_carrier(settings, &link);
        // An HTTP hop carries streams not datagrams, so this is a refusal, not a silent carrier switch.
        if upstream
            .as_ref()
            .is_some_and(crate::foxy::UpstreamProxy::http)
            && carrier == crate::foxy::Carrier::H3
        {
            eprintln!("foxy: carrier h3 cannot ride an http upstreamProxy: use socks5(h)://, h1, h2 or auto");
            continue;
        }
        let pasted = ferrox_core::foxy::Pass {
            token: configured.clone(),
            expires_at: ferrox_core::foxy::account::jwt_expiry(&configured),
            quota_remaining: None,
            quota_reset: None,
        };
        let account = foxy_account(&email, &password, &code, &pasted, link.guardian(), &roots);
        let pass = account
            .as_ref()
            .map_or_else(|| pasted.clone(), |account| account.current());
        if let Some(reason) = foxy_pass_guard(account.as_ref(), &pass) {
            eprintln!("foxy: {reason}: serves nothing");
            continue;
        }
        return Some(FoxyOut {
            account,
            candidates,
            stored: None,
            unauthenticated: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            limited_strikes: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            limited_until: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            carrier_dead: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::Refusals::new(32),
            )),
            edge_strikes: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::EdgeStrikes::new(32),
            )),
            country,
            city,
            carrier,
            upstream,
            roots,
            pins,
            pass,
            edge_address,
            direct_ports: foxy_ports(settings.and_then(|s| s.get("directPorts"))),
            direct_suffixes: foxy_list_or(&link, settings, "directDomains"),
            exit_probe: match foxy_text_or(&link, settings, "exitProbe") {
                probe if probe.is_empty() => None,
                probe => Some(probe),
            },
            verified: std::sync::Arc::new(std::sync::Mutex::new(None)),
            probe_unavailable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            exit_refuted_until: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
    }
    None
}

/// Mints one pass and stores it so legs never sign in again: the rate limit counts logins, one job wants one.
pub(crate) fn mint_foxy_pass(config: &str, out: &str) -> ! {
    let text = std::fs::read_to_string(config)
        .unwrap_or_else(|error| exit(&format!("cannot read {config}: {error}")));
    let root = crate::json::parse(&text)
        .unwrap_or_else(|error| exit(&format!("bad config {config}: {error}")));
    let Some(foxy) = find_foxy_outbound(&root) else {
        exit("no foxy outbound with an email or a pass in {config}");
    };
    let token = foxy.account.as_ref().map(|account| account.current());
    let Some(pass) = token else {
        exit("the account did not sign in, so there is no pass to store");
    };
    if pass.token.is_empty() {
        exit("the account did not sign in, so there is no pass to store");
    }
    let mut stored = String::with_capacity(pass.token.len() + 12);
    stored.push_str("{\"pass\":\"");
    for byte in pass.token.bytes() {
        if byte == b'"' || byte == b'\\' {
            stored.push('\\');
        }
        stored.push(byte as char);
    }
    stored.push_str("\"}");
    std::fs::write(out, stored)
        .unwrap_or_else(|error| exit(&format!("cannot write {out}: {error}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600));
    }
    println!("minted=1 expires_at={:?}", pass.expires_at);
    std::process::exit(0);
}

fn find_trojan_outbound(root: &Json) -> Option<TrojanOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("trojan") {
            continue;
        }
        let server = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = server else { continue };
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let password = server.get("password").and_then(Json::as_str)?;
        let key = trojan_key(password);
        if let Some((carrier, host, tls)) = tls_parts(outbound, &address) {
            return Some(TrojanOut {
                address,
                port,
                key,
                carrier,
                host,
                tls: Some(tls),
            });
        }
        if !matches!(stream_security(outbound), "" | "none") {
            continue;
        }
        let (carrier, host) = outbound_carrier(outbound, &address);
        return Some(TrojanOut {
            address,
            port,
            key,
            carrier,
            host,
            tls: None,
        });
    }
    None
}

fn find_shadowsocks_outbound(root: &Json) -> Option<ShadowsocksOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("shadowsocks") {
            continue;
        }
        let server = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = server else { continue };
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let method = server.get("method").and_then(Json::as_str)?.to_owned();
        let password = server.get("password").and_then(Json::as_str)?.to_owned();
        let (carrier, host) = outbound_carrier(outbound, &address);
        return Some(ShadowsocksOut {
            address,
            port,
            method,
            password,
            carrier,
            host,
        });
    }
    None
}

fn find_http_outbound(root: &Json) -> Option<HttpOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("http") {
            continue;
        }
        let settings = outbound.get("settings")?;
        let servers = settings
            .get("servers")
            .and_then(Json::as_arr)
            .unwrap_or(&empty);
        for server in servers {
            let address = server.get("address").and_then(Json::as_str)?.to_owned();
            let port = server.get("port").and_then(Json::as_port)?;
            let security = stream_security(outbound);
            let tls = if security == "tls" {
                let Some((_, _, t)) = tls_parts(outbound, &address) else {
                    continue;
                };
                Some(t)
            } else {
                None
            };
            let mut headers: Vec<(String, String)> = Vec::new();
            if let Some(hdrs) = server.get("headers").and_then(Json::as_arr) {
                for h in hdrs {
                    if let Some(k) = h.get("key").and_then(Json::as_str) {
                        if let Some(v) = h.get("value").and_then(Json::as_str) {
                            headers.push((k.to_owned(), v.to_owned()));
                        }
                    }
                }
            }
            let (user, pass) = if let Some(users) = server.get("users").and_then(Json::as_arr) {
                if let Some(u) = users.first() {
                    let user = u
                        .get("user")
                        .and_then(Json::as_str)
                        .or_else(|| u.get("username").and_then(Json::as_str));
                    let pass = u
                        .get("pass")
                        .and_then(Json::as_str)
                        .or_else(|| u.get("password").and_then(Json::as_str));
                    (
                        user.map(std::borrow::ToOwned::to_owned),
                        pass.map(std::borrow::ToOwned::to_owned),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };
            return Some(HttpOut {
                address,
                port,
                tls,
                headers,
                user,
                pass,
            });
        }
    }
    None
}

fn vnext_servers<'a>(
    root: &'a Json,
    protocol: &'a str,
) -> impl Iterator<Item = (&'a Json, &'a Json)> + 'a {
    let outbounds: &[Json] = root.get("outbounds").and_then(Json::as_arr).unwrap_or(&[]);
    outbounds
        .iter()
        .filter(move |outbound| outbound.get("protocol").and_then(Json::as_str) == Some(protocol))
        .filter_map(|outbound| {
            let server = outbound
                .get("settings")
                .and_then(|s| s.get("vnext"))
                .and_then(Json::as_arr)
                .and_then(|servers| servers.first())?;
            Some((outbound, server))
        })
}

fn find_vless_outbound(root: &Json) -> Option<VlessOut> {
    for (outbound, server) in vnext_servers(root, "vless") {
        let security = stream_security(outbound);
        let quic_tls = outbound
            .get("streamSettings")
            .and_then(|s| s.get("network"))
            .and_then(Json::as_str)
            == Some("quic")
            && security == "tls";
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let id = server
            .get("users")
            .and_then(Json::as_arr)
            .and_then(|users| users.first())
            .and_then(|user| user.get("id"))
            .and_then(Json::as_str)
            .and_then(uuid_bytes)?;
        let mux = matches!(
            outbound.get("mux").and_then(|mux| mux.get("enabled")),
            Some(Json::Bool(true))
        );
        // Mux frames ride above the session, so mux over TLS needs its own dial and stays refused.
        if security == "tls" && !quic_tls && !mux {
            let Some((carrier, host, tls)) = tls_parts(outbound, &address) else {
                continue;
            };
            return Some(VlessOut {
                address,
                port,
                id,
                carrier,
                host,
                mux,
                quic_roots: None,
                hysteria_roots: None,
                tls: Some(tls),
                flow: outbound_flow(server),
                reality: None,
            });
        }
        // REALITY dials raw TCP and every carried carrier the client reaches; the rest stay refused.
        if security == "reality" && !mux {
            let (carrier, host) = outbound_carrier(outbound, &address);
            if !matches!(
                carrier,
                Carrier::Raw(_)
                    | Carrier::Ws { .. }
                    | Carrier::HttpUpgrade { .. }
                    | Carrier::Grpc { .. }
                    | Carrier::Xhttp { .. }
                    | Carrier::HttpHeader { .. }
            ) {
                continue;
            }
            let Some(reality) = outbound_reality(outbound, &address) else {
                continue;
            };
            let flow = outbound_flow(server);
            if !matches!(flow.as_str(), "" | "none" | crate::vision::FLOW) {
                continue;
            }
            return Some(VlessOut {
                address,
                port,
                id,
                carrier,
                host,
                mux,
                quic_roots: None,
                hysteria_roots: None,
                tls: None,
                flow,
                reality: Some(reality),
            });
        }
        if !vless_security_supported(security) && !quic_tls {
            continue;
        }
        let (carrier, host) = outbound_carrier(outbound, &address);
        let quic_roots = match &carrier {
            Carrier::Quic => tls_ca_roots(outbound),
            _ => None,
        };
        let hysteria_roots = match &carrier {
            Carrier::Hysteria(_) => tls_ca_roots(outbound),
            _ => None,
        };
        return Some(VlessOut {
            address,
            port,
            id,
            carrier,
            host,
            mux,
            quic_roots,
            hysteria_roots,
            tls: None,
            flow: outbound_flow(server),
            reality: None,
        });
    }
    None
}

fn find_vmess_outbound(root: &Json) -> Option<VmessOut> {
    if let Some((outbound, server)) = vnext_servers(root, "vmess").next() {
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let user = server
            .get("users")
            .and_then(Json::as_arr)
            .and_then(|users| users.first())?;
        let id = user.get("id").and_then(Json::as_str).and_then(uuid_bytes)?;
        let cipher = crate::vmess::Cipher::parse(
            user.get("security")
                .and_then(Json::as_str)
                .unwrap_or("auto"),
        );
        if let Some((carrier, host, tls)) = tls_parts(outbound, &address) {
            return Some(VmessOut {
                address,
                port,
                id,
                cipher,
                carrier,
                host,
                tls: Some(tls),
            });
        }
        // A security the tree cannot dial is refused, never silently sent plain.
        if !matches!(stream_security(outbound), "" | "none") {
            return None;
        }
        let (carrier, host) = outbound_carrier(outbound, &address);
        return Some(VmessOut {
            address,
            port,
            id,
            cipher,
            carrier,
            host,
            tls: None,
        });
    }
    None
}

// TLS runs outside the carrier, the order both references use, so every diallable carrier is accepted here.
fn tls_parts(
    outbound: &Json,
    address: &str,
) -> Option<(Carrier, String, Arc<ferrox_core::tls::TlsConfig>)> {
    if stream_security(outbound) != "tls" {
        return None;
    }
    let (carrier, host) = outbound_carrier(outbound, address);
    match carrier {
        Carrier::Raw(_)
        | Carrier::Ws { .. }
        | Carrier::HttpUpgrade { .. }
        | Carrier::Grpc { .. }
        | Carrier::Xhttp { .. }
        | Carrier::HttpHeader { .. } => {}
        Carrier::Quic
        | Carrier::Kcp(_)
        | Carrier::Hysteria(_)
        | Carrier::Masque
        | Carrier::Xdrive
        | Carrier::Http
        | Carrier::Unknown { .. } => return None,
    }
    outbound_tls(outbound, address).map(|tls| (carrier, host, tls))
}

fn x25519_pair() -> (String, String) {
    let mut private = [0u8; 32];
    getrandom::getrandom(&mut private)
        .unwrap_or_else(|error| exit(&format!("no entropy: {error}")));
    private[0] &= 0xF8;
    private[31] &= 0x7F;
    private[31] |= 0x40;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    (b64url(&private), b64url(&public))
}

fn b64url(bytes: &[u8]) -> String {
    let mut out = String::new();
    ferrox_core::transport::early_encode_into(&mut out, bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budgets::{HEAD_DEADLINE, RELAY_JOIN};
    use crate::config::{grpc_path, stream_carrier};
    use ferrox_core::finalmask::Chain;

    #[test]
    fn dokodemo_rewrites_to_the_named_address_and_port() {
        let inbound = crate::json::parse(
            r#"{"settings": {"address": "127.0.0.1", "port": 8080, "network": "tcp,udp"}}"#,
        )
        .expect("parses");
        let dest = dokodemo_target(&inbound).expect("a rewrite target");
        assert_eq!(dest.port(), 8080);
        assert_eq!(dest.host(), "127.0.0.1");
        assert_eq!(dokodemo_networks(&inbound), ["tcp", "udp"]);
    }

    #[test]
    fn dokodemo_without_a_rewrite_target_serves_nothing() {
        let inbound = crate::json::parse(r#"{"settings": {"network": "tcp"}}"#).expect("parses");
        assert!(dokodemo_target(&inbound).is_none());
        assert!(dokodemo_networks(&inbound).contains(&"tcp"));
    }

    #[test]
    fn the_seam_split_find_across_agrees_with_the_per_byte_branch_scan() {
        // The contiguous probe scan must yield the identical first position on every seam, interior and absent placement.
        fn before(head: &[u8], probe: &[u8]) -> Option<usize> {
            let joined = head.len() + probe.len();
            if joined < 4 {
                return None;
            }
            let mut pos = if head.len() >= 3 { head.len() - 3 } else { 0 };
            let target = u32::from_le_bytes(*b"\r\n\r\n");
            while pos + 3 < joined {
                let b0 = if pos < head.len() {
                    head[pos]
                } else {
                    probe[pos - head.len()]
                };
                let b1 = if pos + 1 < head.len() {
                    head[pos + 1]
                } else {
                    probe[pos + 1 - head.len()]
                };
                let b2 = if pos + 2 < head.len() {
                    head[pos + 2]
                } else {
                    probe[pos + 2 - head.len()]
                };
                let b3 = if pos + 3 < head.len() {
                    head[pos + 3]
                } else {
                    probe[pos + 3 - head.len()]
                };
                if u32::from_le_bytes([b0, b1, b2, b3]) == target {
                    return Some(pos);
                }
                pos += 1;
            }
            None
        }
        const ALPHABET: [u8; 3] = *b"\r\nZ";
        let mut buf = [0u8; 6];
        for head_len in 0..=6usize {
            for probe_len in 0..=6usize {
                let total = head_len + probe_len;
                if total > 6 {
                    continue;
                }
                for code in 0..ALPHABET.len().pow(total as u32) {
                    let mut rest = code;
                    for slot in &mut buf[..total] {
                        *slot = ALPHABET[rest % ALPHABET.len()];
                        rest /= ALPHABET.len();
                    }
                    let (head, probe) = buf.split_at(head_len);
                    assert_eq!(
                        find_across(head, probe, b"\r\n\r\n"),
                        before(head, probe),
                        "head {head:?} probe {probe:?}"
                    );
                }
            }
        }
        // At scale the scan returns the earliest of several matches, including one filling the whole tail.
        let mut tail = vec![b'x'; 255];
        tail.extend_from_slice(b"\r\n\r\n\r\n\r\n");
        assert_eq!(find_across(&[], &tail, b"\r\n\r\n"), Some(255));
        assert_eq!(find_across(b"\r\n", b"\r\nZZ", b"\r\n\r\n"), Some(0));
    }

    /// `find_double_crlf` is the SWAR pass the shared head reader now uses in place of
    /// `windows(4).position`; this sweep is its oracle. A forged `\r\n\r`, a length that
    /// is not a multiple of eight, a terminator whose first `\n` lands exactly on a
    /// block boundary, and an all-`\n` body that keeps the verify busy must all return
    /// the very same offset — or the same `None` — as the byte-by-byte form it replaced.
    #[test]
    fn the_swar_terminator_scan_is_the_windows_four_scan() {
        // Nested so the sweep takes any start iterator without collecting one first.
        fn sweep(len: usize, starts: impl Iterator<Item = usize>) {
            const CR: u8 = b'\r';
            const LF: u8 = b'\n';
            const NEEDLE: [u8; 4] = [CR, LF, CR, LF];
            let oracle = |buf: &[u8]| buf.windows(4).position(|w| w == b"\r\n\r\n");
            for start in starts {
                // A `\n`-and-`Z` body with no `\r`, so the only terminator is the one planted at `start`.
                if start + 4 <= len {
                    let mut v: Vec<u8> = (0..len)
                        .map(|i| if i % 5 == 0 { LF } else { b'Z' })
                        .collect();
                    v[start..start + 4].copy_from_slice(&NEEDLE);
                    assert_eq!(find_double_crlf(&v), oracle(&v), "len {len} at {start}");
                }
            }
            let no_lf: Vec<u8> = vec![CR; len];
            assert_eq!(find_double_crlf(&no_lf), oracle(&no_lf), "len {len} no LF");
            let all_lf: Vec<u8> = vec![LF; len];
            assert_eq!(
                find_double_crlf(&all_lf),
                oracle(&all_lf),
                "len {len} all LF"
            );
        }

        // Exhaustive over {\r, \n, Z} up to eight bytes: every alignment and near-miss.
        const ALPHABET: [u8; 3] = *b"\r\nZ";
        let mut small = [0u8; 8];
        let oracle = |buf: &[u8]| buf.windows(4).position(|w| w == b"\r\n\r\n");
        for len in 0..=8usize {
            for code in 0..ALPHABET.len().pow(len as u32) {
                let mut rest = code;
                for slot in &mut small[..len] {
                    *slot = ALPHABET[rest % ALPHABET.len()];
                    rest /= ALPHABET.len();
                }
                let view = &small[..len];
                assert_eq!(find_double_crlf(view), oracle(view), "exhaustive {view:?}");
            }
        }

        // Every start over the lengths that straddle a block boundary at both ends.
        for len in 0..=130usize {
            sweep(len, 0..len);
        }
        // At scale, the first two words, mid-buffer, and the final partial word.
        for len in [511usize, 512, 513, 4096, 16 * 1024] {
            sweep(
                len,
                (0..17)
                    .chain([len / 2, len / 2 + 1])
                    .chain(len.saturating_sub(9)..len),
            );
        }
    }

    struct Gated {
        sent: Vec<u8>,
        held: Vec<u8>,
    }
    impl Write for Gated {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.held.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.sent.extend_from_slice(&self.held);
            self.held.clear();
            Ok(())
        }
    }

    #[test]
    fn a_relay_write_is_sent_without_waiting_for_close() {
        let half = Half::new(Gated {
            sent: Vec::new(),
            held: Vec::new(),
        });
        half.write_once(b"ping").expect("writes");
        let gated = half.inner.lock().expect("reads back");
        assert_eq!(gated.sent, b"ping", "flush-gated bytes are sent, not held");
    }

    #[test]
    fn a_finished_relay_closes_the_other_side() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let fired = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&fired);
        let close: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || flag.store(true, Ordering::SeqCst));
        let from = Arc::new(Half::new(std::io::Cursor::new(b"ping".to_vec())));
        let to = Arc::new(Half::new(Gated {
            sent: Vec::new(),
            held: Vec::new(),
        }));
        copy_stream(&from, &to, &close, &AtomicBool::new(false));
        assert!(fired.load(Ordering::SeqCst), "EOF fires the close");
        let gated = to.inner.lock().expect("reads back");
        assert_eq!(gated.sent, b"ping");
    }

    /// A leg that only ever times out: a live socket whose peer fell silent, where no byte or error ends the read on its own.
    struct Poller;

    impl Read for Poller {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_millis(2));
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
        }
    }

    impl Write for Poller {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A leg whose source reaches its end at once: the sibling that must retire the other.
    struct EofReader;

    impl Read for EofReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for EofReader {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_polling_leg_ends_when_its_sibling_finishes() {
        // The stall the Windows CI caught: a busy `continue` at the timeout outlives the relay that ended, and the join on it never returns.
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        let joined = thread::spawn(move || {
            relay_stream(Poller, EofReader, &close);
        });
        joined
            .join()
            .expect("the polling leg ends on its sibling's finish");
    }

    #[test]
    fn the_cover_origin_splice_carries_the_reply_back_to_the_peer() {
        let peer_side = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let origin_side = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let origin_port = origin_side.local_addr().expect("addr").port();
        let mut peer =
            Connection::connect(peer_side.local_addr().expect("addr")).expect("connects");
        let client = peer_side.accept().expect("accepts").0;
        client
            .set_read_timeout(Some(RELAY_POLL))
            .expect("polls like the server path");
        let target = std::net::TcpStream::connect(("127.0.0.1", origin_port)).expect("dials");
        let cover = thread::spawn(move || {
            let (mut origin, _) = origin_side.accept().expect("accepts");
            let mut head = [0u8; 4];
            origin.read_exact(&mut head).expect("reads");
            origin.write_all(b"pong").expect("replies");
            origin.shutdown(Shutdown::Write).expect("half-closes");
            let mut rest = Vec::new();
            let _ = origin.read_to_end(&mut rest);
            head
        });
        let fallback = thread::spawn(move || {
            relay_fallback(ferrox_core::tls::Proxied {
                client,
                target,
                upload: None,
                download: None,
            });
        });
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("times out");
        peer.write_all(b"ping").expect("sends");
        let mut reply = [0u8; 4];
        let arrived = match peer.read_exact(&mut reply) {
            Ok(()) => Some(reply),
            Err(why) if is_timeout(&why) => None,
            Err(why) => panic!("reads: {why}"),
        };
        drop(peer);
        let head = cover.join().expect("the cover origin ends");
        fallback.join().expect("the splice ends");
        assert_eq!(
            arrived,
            Some(*b"pong"),
            "the origin's reply reaches the peer"
        );
        assert_eq!(
            &head, b"ping",
            "the peer's hello reaches the origin in order"
        );
    }

    #[test]
    fn the_cover_origin_splice_ends_when_the_peer_finishes() {
        let peer_side = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let origin_side = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let origin_port = origin_side.local_addr().expect("addr").port();
        let mut peer =
            Connection::connect(peer_side.local_addr().expect("addr")).expect("connects");
        let client = peer_side.accept().expect("accepts").0;
        client
            .set_read_timeout(Some(RELAY_POLL))
            .expect("polls like the server path");
        let target = std::net::TcpStream::connect(("127.0.0.1", origin_port)).expect("dials");
        let (gone_tx, gone_rx) = std::sync::mpsc::channel();
        let cover = thread::spawn(move || {
            let (mut origin, _) = origin_side.accept().expect("accepts");
            let mut head = [0u8; 4];
            origin.read_exact(&mut head).expect("reads");
            let _ = gone_rx.recv_timeout(Duration::from_secs(5));
            head
        });
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let fallback = thread::spawn(move || {
            relay_fallback(ferrox_core::tls::Proxied {
                client,
                target,
                upload: None,
                download: None,
            });
            let _ = finished_tx.send(());
        });
        peer.write_all(b"ping").expect("sends");
        drop(peer);
        let ended = finished_rx.recv_timeout(Duration::from_secs(1)).is_ok();
        let _ = gone_tx.send(());
        let head = cover.join().expect("the cover origin ends");
        fallback.join().expect("the splice ends");
        assert!(
            ended,
            "a finished peer ends the splice against a silent origin"
        );
        assert_eq!(&head, b"ping", "the hello reaches the origin");
    }

    /// Two pumps share one session lock: a read that holds it for a whole idle grain stalls the opposite pump's write for that grain.
    #[test]
    fn a_server_relay_bounds_the_shared_session_to_one_tick() {
        let site = crate::conn::test_bind("127.0.0.1:0").expect("binds the site");
        let site_addr: SocketAddr = site.local_addr().expect("addr");
        let dialed = thread::spawn(move || {
            let (peer, _) = site.accept().expect("accepts");
            peer
        });

        let lane = crate::conn::test_bind("127.0.0.1:0").expect("binds the lane");
        let lane_addr: SocketAddr = lane.local_addr().expect("addr");
        let mut edge = Connection::connect(lane_addr).expect("connects");
        let (session, _) = lane.accept().expect("accepts");
        session
            .set_read_timeout(Some(RELAY_POLL))
            .expect("arms the server idle grain");
        let raw = session.try_clone().expect("shares the fd");
        #[cfg(unix)]
        let probe = session.try_clone().expect("probes the fd");
        drop(lane);

        let id = [0x5Au8; 16];
        edge.write_all(&vless_header(&id, 1, &Destination::from(site_addr)))
            .expect("greets");
        let relay = thread::spawn(move || relay_vless(session, Some(raw), &id, true));

        edge.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("arms the reply read");
        let mut answer = [0u8; 2];
        edge.read_exact(&mut answer).expect("answers");
        assert_eq!(answer, [0, 0], "the relay grants the tunnel");
        // The grant is written after the SESSION_POLL arm and the relay returns early if arming fails, so it already proves the raw arm armed cross-platform; only a duplicated file description can reflect a later setsockopt, so the value witness is unix-only (WSADuplicateSocket gives Windows an independent handle).
        #[cfg(unix)]
        assert_eq!(
            probe.read_timeout().ok().flatten(),
            Some(SESSION_POLL),
            "the shared fd must poll at one tick, or a silent session read stalls the peer pump's write"
        );
        drop(edge);
        relay.join().expect("the relay ends");
        drop(dialed.join().expect("the site holds its connection"));
    }

    /// Every other TLS rung re-shakes a slow hello to its deadline; the raw arm shook once and refused at the grain.
    #[test]
    fn a_plain_tls_lane_retries_a_hello_that_arrives_past_the_grain() {
        use ferrox_core::tls::TlsProvider;

        let (server_config, client_config) = carried_tls_configs();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let server: SocketAddr = listener.local_addr().expect("addr");
        let lane = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless_tls(
                stream,
                &[0x9Du8; 16],
                true,
                &Carrier::Raw(Chain::default()),
                &server_config,
            );
        });

        // The hello arrives twelve grains later than the lane's first read; only its deadline may refuse it.
        let edge = Connection::connect(server).expect("connects");
        thread::sleep(Duration::from_millis(240));
        let mut client = ferrox_core::tls::connect(&client_config, edge).expect("opens");
        let shook = client.handshake();
        drop(client);
        lane.join().expect("the lane ends");
        shook.expect("a hello past the grain completes the handshake, not a refusal");
    }

    #[test]
    fn scratch_reuses_capacity_and_reports_its_length() {
        let mut buf = Vec::new();
        for len in [0usize, 1, 16, 4096, 65_536, 3] {
            resize_scratch(&mut buf, len);
            assert!(buf.capacity() >= len, "len {len}");
            assert_eq!(buf.len(), len, "len {len}");
            buf.fill(0x5A);
            assert!(buf.iter().all(|&byte| byte == 0x5A), "len {len}");
        }
    }

    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("no bytes today"))
        }
    }

    #[test]
    fn a_connect_lane_grants_only_after_its_tunnel_opens() {
        fn handshake(grant: bool) -> Vec<u8> {
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let accepted = std::thread::spawn(move || listener.accept().expect("accepts").0);
            let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("times out");
            client
                .write_all(&[5, 1, 0, 5, 1, 0, 3, 11])
                .expect("greets");
            client.write_all(b"example.com").expect("names");
            client.write_all(&[0, 80]).expect("ports");
            let mut server = accepted.join().expect("accepts");
            let (cmd, target) = socks_target(&mut server, grant).expect("handshakes");
            assert_eq!(cmd, 1);
            assert_eq!(target.authority(), "example.com:80");
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).expect("selects a method");
            assert_eq!(reply, [5, 0]);
            let mut rest = Vec::new();
            let _ = client.read_to_end(&mut rest);
            drop(server);
            rest
        }
        let granted = handshake(true);
        assert_eq!(granted.len(), 10, "one grant, ten bytes");
        assert_eq!(&granted[..3], &[5, 0, 0]);
        let ungranted = handshake(false);
        assert!(ungranted.is_empty(), "no grant before the tunnel opens");
    }

    #[test]
    fn a_maximal_method_offer_drains_on_the_stack_and_still_grants() {
        // head[1] = 255 is the largest count a peer can send, and with no method 0x00 offered the reply is still no-auth, so the offer is provably never inspected.
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let accepted = std::thread::spawn(move || listener.accept().expect("accepts").0);
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("times out");
        let mut greeting = vec![5u8, u8::MAX];
        greeting.extend_from_slice(&[2u8; u8::MAX as usize]);
        greeting.extend([5, 1, 0, 3, 11]);
        greeting.extend_from_slice(b"example.com");
        greeting.extend([0, 80]);
        client.write_all(&greeting).expect("greets");
        let mut server = accepted.join().expect("accepts");
        let (cmd, target) = socks_target(&mut server, true).expect("handshakes");
        assert_eq!(cmd, 1);
        assert_eq!(target.authority(), "example.com:80");
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).expect("selects a method");
        assert_eq!(reply, [5, 0]);
    }

    struct Dribble {
        inner: std::io::Cursor<Vec<u8>>,
    }

    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let take = buf.len().min(5);
            self.inner.read(&mut buf[..take])
        }
    }

    #[test]
    fn a_read_into_the_tail_appends_exactly_what_the_stream_held() {
        let stream: Vec<u8> = (0..(READ_SLICE * 2 + 137))
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
            .collect();
        let mut source = Dribble {
            inner: std::io::Cursor::new(stream.clone()),
        };
        let mut buf = Vec::with_capacity(READ_SLICE);
        let mut reads = 0usize;
        loop {
            match read_into_tail(&mut source, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    assert!(n <= READ_SLICE, "read {n} exceeds the slice");
                    reads += 1;
                }
            }
            assert_eq!(buf, stream[..buf.len()], "read {reads}");
            assert!(
                buf.capacity() >= READ_SLICE,
                "read {reads}: the framing buffer grew past the read slice"
            );
        }
        assert_eq!(buf, stream, "every byte arrived, in order");
        assert!(
            reads > 3_000,
            "a five-byte reader needs many reads: {reads}"
        );
    }

    #[test]
    fn a_read_into_the_tail_never_leaves_a_short_buffer() {
        let mut buf = Vec::from(&b"keep"[..]);
        assert!(read_into_tail(&mut Broken, &mut buf).is_err());
        assert_eq!(buf, b"keep", "a failed read leaves the bytes already there");
        let mut buf = Vec::from(&b"keep"[..]);
        assert_eq!(
            read_into_tail(&mut std::io::empty(), &mut buf).expect("eof"),
            0
        );
        assert_eq!(
            buf, b"keep",
            "an empty stream leaves the bytes already there"
        );
    }

    #[test]
    fn b64url_matches_the_shared_encoder() {
        for (bytes, want) in [
            (&b""[..], ""),
            (&b"foobar"[..], "Zm9vYmFy"),
            (&[0xff, 0xff, 0x00][..], "__8A"),
        ] {
            assert_eq!(b64url(bytes), want);
            let mut shared = String::new();
            ferrox_core::transport::early_encode_into(&mut shared, bytes);
            assert_eq!(b64url(bytes), shared);
        }
    }

    #[test]
    fn a_head_split_across_segments_is_read_whole() {
        use std::time::Duration;

        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            for piece in [
                &b"GET /tunnel HTTP/1.1\r\nHost: h\r\n"[..],
                &b"Upgrade: websocket\r\n"[..],
                &b"\r"[..],
                &b"\n"[..],
            ] {
                stream.write_all(piece).expect("writes");
                thread::sleep(Duration::from_millis(20));
            }
        });

        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let head =
            read_http_head(&mut stream, HEAD_LIMIT_TEST, HEAD_DEADLINE).expect("reads a head");
        assert_eq!(
            head,
            b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n".to_vec()
        );
        peer.join().expect("joins");
    }

    #[test]
    fn a_head_dribbled_across_reads_returns_whole_with_its_pipelined_tail() {
        // A delimiter straddling a read boundary: the head comes back whole, the overflow becomes the prefix.
        let head_bytes =
            b"HTTP/1.1 200 Connection established\r\nProxy-Connection: keep-alive\r\n\r\n";
        let tail_bytes = b"the pipelined first frame";
        let mut wire = Vec::new();
        wire.extend_from_slice(head_bytes);
        wire.extend_from_slice(tail_bytes);
        let mut source = Dribble {
            inner: std::io::Cursor::new(wire),
        };
        let (head, at) =
            read_exact_head(&mut source, HEAD_LIMIT_TEST, HEAD_DEADLINE).expect("reads the head");
        assert_eq!(
            &head[..at],
            head_bytes.to_vec(),
            "the head comes back whole"
        );
        // The tail is overflow plus reader bytes: nothing lost at the boundary, nothing handed twice.
        let mut rest = Vec::new();
        source.read_to_end(&mut rest).expect("drains the reader");
        let joined = [head[at..].to_vec(), rest].concat();
        assert_eq!(joined, tail_bytes.to_vec(), "the tail splits cleanly");
    }

    /// The kept head reader's whole claim, witnessed where a count is exact: one call proves the head *and* takes the bytes behind it. The `peek` reader spent one call proving the head and another taking it, and left the tail in the stream for a third.
    #[test]
    fn a_kept_head_costs_one_read_per_window_and_takes_its_tail() {
        let head = b"GET /tunnel HTTP/1.1\r\nHost: h\r\n\r\n";
        let tail = b"the first frame's bytes";
        let mut wire = head.to_vec();
        wire.extend_from_slice(tail);
        let whole = wire.len();
        let mut source = Counted {
            inner: std::io::Cursor::new(wire),
            reads: 0,
        };
        let (got, at) =
            kept_head_rounds(&mut source, HEAD_LIMIT_TEST, HEAD_DEADLINE).expect("reads a head");
        assert_eq!(got[..at], head.to_vec(), "the head ends at its delimiter");
        assert_eq!(
            got[at..],
            tail.to_vec(),
            "the bytes behind it came in the same buffer"
        );
        assert_eq!(
            source.reads, 1,
            "one read proved the head and took the tail"
        );
        assert_eq!(
            source.inner.position() as usize,
            whole,
            "octets were left in the stream for another read"
        );
    }

    /// The delimiter split across a round's seam: the scan starts three octets before the new bytes, so a head whose `\r\n\r\n` straddles is still proved, and it costs the two windows it arrived in and no third.
    #[test]
    fn a_kept_head_straddling_a_round_is_proved_by_two_reads() {
        let mut wire: Vec<u8> = b"GET /tunnel HTTP/1.1\r\nX-Pad: ".to_vec();
        while wire.len() < 510 {
            wire.push(b'p');
        }
        // The delimiter occupies 510..514, so the first 512-byte window ends inside it.
        wire.extend_from_slice(b"\r\n\r\npayload");
        assert_eq!(wire[510..], b"\r\n\r\npayload".to_vec());
        let mut source = Counted {
            inner: std::io::Cursor::new(wire),
            reads: 0,
        };
        let (got, at) =
            kept_head_rounds(&mut source, HEAD_LIMIT_TEST, HEAD_DEADLINE).expect("straddles");
        assert_eq!(at, 514, "the head is proved past the seam, not re-windowed");
        assert_eq!(&got[at..], b"payload");
        assert_eq!(source.reads, 2, "a round per window: {}", source.reads);
    }

    /// The worst input the round loop meets: no delimiter at all. It is refused, and so is a stream that holds nothing.
    #[test]
    fn a_kept_head_without_a_delimiter_is_refused() {
        let mut endless = Counted {
            inner: std::io::Cursor::new(vec![b'x'; 4096]),
            reads: 0,
        };
        assert!(
            kept_head_rounds(&mut endless, 8 * 1024, HEAD_DEADLINE).is_none(),
            "a head with no terminator must be refused"
        );
        assert!(
            endless.inner.position() as usize <= 8 * 1024,
            "the reader went past its limit"
        );
        let mut empty = Counted {
            inner: std::io::Cursor::new(Vec::new()),
            reads: 0,
        };
        assert!(
            kept_head_rounds(&mut empty, HEAD_LIMIT_TEST, HEAD_DEADLINE).is_none(),
            "an idle stream is not a head"
        );
    }

    #[test]
    fn bytes_pipelined_behind_a_head_stay_in_the_kernel() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut request = Vec::from(&b"GET /tunnel HTTP/1.1\r\nHost: h\r\n\r\n"[..]);
            request.extend_from_slice(b"the first frame's bytes");
            stream.write_all(&request).expect("writes");
            thread::sleep(std::time::Duration::from_millis(50));
        });

        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let head =
            read_http_head(&mut stream, HEAD_LIMIT_TEST, HEAD_DEADLINE).expect("reads a head");
        assert_eq!(head, b"GET /tunnel HTTP/1.1\r\nHost: h\r\n\r\n".to_vec());
        let tail = b"the first frame's bytes";
        let mut rest = vec![0u8; tail.len()];
        stream
            .read_exact(&mut rest)
            .expect("the tail is still there");
        assert_eq!(rest, tail);
        peer.join().expect("joins");
    }

    #[test]
    fn an_unterminated_head_is_refused_at_the_limit() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let filler = vec![b'x'; 4096];
            while stream.write_all(&filler).is_ok() {}
        });

        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        assert!(
            read_http_head(&mut stream, 8 * 1024, HEAD_DEADLINE).is_none(),
            "a head with no terminator must be refused"
        );
        drop(stream);
        peer.join().expect("joins");
    }

    /// Poll-armed socket, silent peer: the elapsed assert is the witness, since a spinning test never fails.
    #[test]
    fn a_quiet_peer_ends_both_head_readers_at_their_budget() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let budget = Duration::from_millis(60);
        let at = Instant::now();

        let mut peeked = Connection::connect(addr).expect("connects");
        peeked
            .set_read_timeout(Some(Duration::from_millis(2)))
            .expect("timeout");
        assert!(
            read_http_head(&mut peeked, HEAD_LIMIT_TEST, budget).is_none(),
            "the peeking reader must give up on a silent peer"
        );

        let mut record = Connection::connect(addr).expect("connects");
        record
            .set_read_timeout(Some(Duration::from_millis(2)))
            .expect("timeout");
        assert!(
            read_exact_head(&mut record, HEAD_LIMIT_TEST, budget).is_none(),
            "the record reader must give up on a silent peer"
        );

        // A budget cannot bound a blocking `peek`: arm one, and hand the socket back as it came.
        let unarmed = Connection::connect(addr).expect("connects");
        let mut unarmed = unarmed;
        assert!(
            read_http_head(&mut unarmed, HEAD_LIMIT_TEST, budget).is_none(),
            "an un-armed socket must not park the thread in `peek`"
        );
        assert_eq!(
            unarmed.read_timeout().ok().flatten(),
            None,
            "the reader left the socket's own timeout as it found it"
        );

        assert!(
            at.elapsed() < Duration::from_secs(5),
            "a head read outlived its budget: {}ms",
            at.elapsed().as_millis()
        );
    }

    const HEAD_LIMIT_TEST: usize = 16 * 1024;

    #[test]
    fn base64url_matches_the_oracle_shape() {
        assert_eq!(b64url(&[0u8; 32]), "A".repeat(43));
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
    }

    #[test]
    fn uuid_parses_and_rejects() {
        assert_eq!(
            uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("parses")[0..2],
            [0xaa, 0xaa]
        );
        assert!(uuid_bytes("not-a-uuid").is_none());
        assert!(uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee").is_none());
    }

    #[test]
    fn decodes_what_the_core_encodes() {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        let header = link.encode_request_header("192.0.2.53", 80);
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            decode_request(&mut stream).expect("decodes")
        });
        let mut reader = Connection::connect(("127.0.0.1", port)).expect("connects");
        reader.write_all(&header).expect("writes");
        let (id, _flow, cmd, target) = writer.join().expect("joins");
        assert_eq!(
            id,
            uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id")
        );
        assert_eq!(cmd, 1);
        assert_eq!(target.to_string(), "192.0.2.53:80");
        drop(reader);
    }

    #[test]
    fn trojan_key_is_sha224_hex() {
        assert_eq!(
            trojan_key("an-example-shared-password"),
            *b"73317e3bf920a459723610d27b71cadc07061d8f0d8587e041944896"
        );
    }

    #[test]
    fn the_splice_path_and_the_copying_path_move_the_same_bytes() {
        fn round_trip(payload: &[u8], copy: fn(&mut Connection, &mut Connection)) -> Vec<u8> {
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut other = stream.try_clone().expect("clones");
                copy(&mut stream, &mut other);
            });
            let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
            client
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            client.write_all(payload).expect("writes");
            client.shutdown(Shutdown::Write).expect("half closes");
            let mut back = Vec::new();
            client.read_to_end(&mut back).expect("reads");
            let _ = server.join();
            back
        }

        let payload: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
        let spliced = round_trip(&payload, copy_all);
        let copied = round_trip(&payload, copy_all_memcpy);
        assert_eq!(spliced, payload, "the splice path must move every byte");
        assert_eq!(copied, payload, "the copying path must move every byte");
        assert_eq!(spliced, copied, "the two paths must agree");
    }

    #[test]
    fn both_sockets_of_a_connection_have_nagle_off() {
        let listener = crate::conn::test_bind(("127.0.0.1", 0)).expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        let server = thread::spawn(move || {
            let (accepted, _) = listener.accept().expect("accepts");
            accepted
        });
        let dialled = dial(&SocketAddr::from(([127, 0, 0, 1], port))).expect("connects");
        assert!(
            dialled.nodelay().expect("reads back"),
            "the socket this binary dials must have TCP_NODELAY set"
        );
        let accepted = server.join().expect("the listener thread");
        no_delay(&accepted);
        assert!(
            accepted.nodelay().expect("reads back"),
            "and so must an accepted one"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_splice_pipe_reads_back_the_capacity_it_was_granted() {
        let pipe = SplicePipe::new().expect("a pipe is available on this host");
        assert!(
            pipe.capacity > 0,
            "a granted capacity of zero would make every splice ask for nothing"
        );
        let asked = unsafe { libc::fcntl(pipe.fds[0], libc::F_GETPIPE_SZ) };
        assert_eq!(
            asked as usize, pipe.capacity,
            "the recorded capacity must be the kernel's answer, not the request"
        );
        assert!(
            pipe.capacity <= DEFAULT_SPLICE_PIPE_BYTES.max(1) || pipe.capacity > 0,
            "a granted capacity is always positive and never invented"
        );
    }

    #[test]
    fn the_relay_pool_never_shrinks_below_the_directions_in_flight() {
        const DIRECTIONS: usize = 64;
        let pool = RelayPool::global();
        let arrived = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut waits = Vec::new();
        for _ in 0..DIRECTIONS {
            let arrived = Arc::clone(&arrived);
            waits.push(pool.run(move || {
                arrived.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while arrived.load(std::sync::atomic::Ordering::SeqCst) < DIRECTIONS {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "only {} of {DIRECTIONS} directions were ever in flight at \
                         once, so the pool serialised them",
                        arrived.load(std::sync::atomic::Ordering::SeqCst)
                    );
                    std::thread::yield_now();
                }
            }));
        }
        for wait in &waits {
            wait.recv_timeout(RELAY_JOIN).expect(
                "every direction must report that it ended, and a direction that never \
                         started means the pool serialised them instead of running them",
            );
        }
        assert_eq!(
            arrived.load(std::sync::atomic::Ordering::SeqCst),
            DIRECTIONS,
            "every direction must run exactly once"
        );
    }

    /// Threads the pool borrows answer live flows, not history: a burst of directions that all finish has to hand its workers back inside the worker life, or every burst of concurrent flows raises the process's thread count for good.
    #[test]
    fn a_finished_burst_hands_its_workers_back_to_the_process() {
        const BURST: usize = 8;
        let pool = RelayPool::with_life(Duration::from_millis(200));
        let gate = Arc::new(std::sync::Barrier::new(BURST + 1));
        let waits: Vec<_> = (0..BURST)
            .map(|_| {
                let gate = Arc::clone(&gate);
                pool.run(move || {
                    gate.wait();
                })
            })
            .collect();
        // All eight are in flight at once, so no direction was served by a worker another had already released.
        gate.wait();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            pool.parked(),
            BURST,
            "each worker a burst borrowed parks where the next claim looks"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while pool.parked() > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        for wait in waits {
            wait.recv_timeout(RELAY_JOIN)
                .expect("every direction of the burst reported that it ended");
        }
        assert_eq!(
            pool.parked(),
            0,
            "the threads a finished burst borrowed came back to the process"
        );
    }

    /// A claim can reach a worker that handed back in the moment between the pop and the send; the direction it holds has to reach the thread that replaces the gone worker, not die with the rejected send.
    #[test]
    fn a_claim_that_reaches_a_gone_worker_keeps_its_direction() {
        let pool = RelayPool::with_life(Duration::from_millis(50));
        let (gone_tx, gone_rx) = std::sync::mpsc::channel::<RelayTask>();
        drop(gone_rx);
        pool.idle.lock().expect("locks").push((7, gone_tx));
        let ran = Arc::new(AtomicBool::new(false));
        let named = Arc::clone(&ran);
        let did = pool.run(move || {
            named.store(true, Ordering::SeqCst);
        });
        did.recv_timeout(RELAY_JOIN)
            .expect("the direction of a claim that missed its worker still hands back");
        assert!(
            ran.load(Ordering::SeqCst),
            "and it ran on the thread spawned for it"
        );
    }

    #[test]
    fn a_direction_that_panics_does_not_take_the_worker_with_it() {
        let pool = RelayPool::global();
        pool.run(|| panic!("this direction is broken on purpose"))
            .recv_timeout(RELAY_JOIN)
            .expect(
                "a panicking direction still has to report that it ended, or the relay \
             waits on it forever",
            );
        let (tx, rx) = std::sync::mpsc::channel();
        pool.run(move || {
            let _ = tx.send(());
        })
        .recv_timeout(RELAY_JOIN)
        .expect("the pool still works, so a hand-back arrived");
        assert!(rx.try_recv().is_ok(), "and the work after it actually ran");
    }

    /// A leg whose partner never reports has to be given up on inside the budget, not waited out: the parked arm is the one that used to hold a thread forever.
    #[test]
    fn a_leg_that_never_hands_back_is_given_up_on_instead_of_waited_out() {
        let (_never, held) = std::sync::mpsc::channel::<()>();
        let started = std::time::Instant::now();
        assert!(
            !join_within(&held, Duration::from_millis(50)),
            "a partner that never reports is a give-up, not a park"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "and it gives up promptly"
        );

        let (ended_tx, ended_rx) = std::sync::mpsc::channel();
        ended_tx.send(()).expect("the hand-back is sent");
        assert!(
            join_within(&ended_rx, RELAY_JOIN),
            "a hand-back is a hand-back"
        );
        let (gone_tx, gone_rx) = std::sync::mpsc::channel::<()>();
        drop(gone_tx);
        assert!(
            join_within(&gone_rx, RELAY_JOIN),
            "a partner that died counts as finished, exactly as the unbounded wait read it"
        );
    }

    /// The budget a leg waits on is the one the config named: the hand-back arrives past a named millisecond and inside the two-minute constant, so the verdict says which value the site read.
    #[test]
    fn a_named_join_budget_is_the_bound_a_parked_leg_gives_up_on() {
        let _guard = budgets::lock();
        let root = crate::json::parse(r#"{"budgets": {"relayJoin": "1ms"}}"#).expect("parses");
        budgets::apply(&crate::config::budgets(&root).expect("a budget the engine acts on"));
        let handed_back_later = || {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(40));
                let _ = tx.send(());
            });
            rx
        };
        let gave_up = !join(&handed_back_later());
        // Restored before the assertion, so a leg another test is joining never reads this table.
        budgets::clear();
        assert!(
            gave_up,
            "the named 1ms gives the leg up instead of waiting the 40ms out"
        );
        assert!(
            join(&handed_back_later()),
            "with the constant armed again the same hand-back is joined"
        );
    }

    /// A head that never arrives is given up on at its own budget, so a quiet peer costs one give-up and not a task waking once per poll forever.
    #[test]
    fn a_head_that_never_arrives_is_given_up_on_at_its_named_budget() {
        struct Quiet;

        impl Read for Quiet {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
        }

        let root = crate::json::parse(r#"{"budgets": {"headArrival": "150ms"}}"#).expect("parses");
        let named = crate::config::budgets(&root)
            .expect("a budget the engine acts on")
            .head_arrival
            .expect("named");
        let started = Instant::now();
        // The site's own shape: the value the config named is the value the read is armed with.
        assert!(
            read_exact_head(&mut Quiet, HEAD_LIMIT_TEST, named).is_none(),
            "a head that never arrives is refused at its budget"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100) && elapsed < Duration::from_secs(5),
            "the read ran on the named 150ms, not the 20s constant, and took {elapsed:?}"
        );
    }

    #[derive(Clone, Default)]
    struct ClosingSink {
        state: Arc<Mutex<(bool, Vec<u8>)>>,
    }

    impl ClosingSink {
        fn closed_empty(&self) -> bool {
            let state = self.state.lock().expect("locks");
            state.0 && state.1.is_empty()
        }
        fn accepted(&self) -> Vec<u8> {
            self.state.lock().expect("locks").1.clone()
        }
    }

    impl CarrierSink for ClosingSink {
        fn send(&self, bytes: &[u8]) -> bool {
            let mut state = self.state.lock().expect("locks");
            if state.0 {
                return false;
            }
            state.1.extend_from_slice(bytes);
            true
        }
        fn close(&self) {
            self.state.lock().expect("locks").0 = true;
        }
    }

    fn relay_against_a_late_peer(drain: bool) -> (bool, Vec<u8>) {
        let peer = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let peer_port = peer.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = peer.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            let mut request = Vec::new();
            let _ = stream.read_to_end(&mut request);
            assert_eq!(&request, b"request", "the peer saw the whole request");
            stream.write_all(b"reply").expect("writes");
            std::thread::sleep(Duration::from_millis(300));
        });

        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let sink = ClosingSink::default();
        let carrier = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            let uplink = Connection::connect(("127.0.0.1", peer_port)).expect("dials");
            let sink = sink.clone();
            if drain {
                relay_sink_drained(stream, &sink, &uplink);
            } else {
                relay_sink(stream, &sink, &uplink, |_| {});
            }
            sink
        });
        let client = thread::spawn(move || {
            let stream = Connection::connect(("127.0.0.1", front_port)).expect("connects");
            let mut writer = stream.try_clone().expect("clones");
            writer.write_all(b"request").expect("writes");
            writer.shutdown(Shutdown::Write).expect("half closes");
        });
        let sink = carrier.join().expect("joins");
        client.join().expect("joins");
        server.join().expect("joins");
        (sink.closed_empty(), sink.accepted())
    }

    #[test]
    fn the_drained_order_lets_the_last_reply_reach_the_sink() {
        let (closed_empty, accepted) = relay_against_a_late_peer(true);
        assert_eq!(
            accepted, b"reply",
            "the reply the peer sent after its FIN must reach the sink before the close"
        );
        assert!(
            !closed_empty,
            "the sink must close after the reply, not before it"
        );
    }

    #[test]
    fn the_default_order_refuses_a_reply_that_follows_the_fin() {
        let (closed_empty, accepted) = relay_against_a_late_peer(false);
        assert!(
            closed_empty || accepted.is_empty(),
            "a sink that closed before the reply must not accept it"
        );
    }

    #[test]
    fn a_dial_that_cannot_connect_is_classified_not_dropped() {
        let failure =
            dial(&SocketAddr::from(([127, 0, 0, 1], 1))).expect_err("nothing listens on port 1");
        assert_eq!(failure.stage, Stage::SocketConnected);
        assert_eq!(
            failure.kind,
            Kind::Refused,
            "a refused connect is observed, not inferred"
        );
        assert!(!failure.worth_retrying());
    }

    /// A refused chain is a refusal, not a dropped connection: while the backend folded the kind into `Other` this arm was unreachable, so an untrusted server reported as a peer that hung up and counted as a dial worth retrying.
    #[test]
    fn a_refused_chain_is_a_refusal_not_a_drop() {
        let refused = ferrox_core::tls::TlsError::BadCertificate("UnknownIssuer".to_owned());
        let failure = tls_failure(&refused);
        assert_eq!(failure.stage, Stage::SocketConnected);
        assert_eq!(failure.kind, Kind::Rejected, "{failure}");
        assert!(
            !failure.worth_retrying(),
            "a chain this device does not trust is not a moment worth another dial"
        );
    }

    #[test]
    fn the_reporting_wrapper_counts_a_fatal_dial_and_returns_none() {
        let before = dial_failures();
        assert!(dial_or_report(&SocketAddr::from(([127, 0, 0, 1], 1))).is_none());
        let after = dial_failures();
        assert_eq!(after.fatal, before.fatal + 1, "a refused connect is fatal");
        assert_eq!(
            after.retryable, before.retryable,
            "and must not also be counted as retryable"
        );
    }

    #[test]
    fn a_relay_buffer_promotes_only_on_a_read_that_filled_it() {
        let mut buffer = RelayBuf::new();
        assert_eq!(buffer.size(), RELAY_SMALL_BUFFER);

        for round in 0..64u8 {
            buffer.as_mut().fill(round);
            let short = buffer.filled(RELAY_SMALL_BUFFER - 1);
            assert_eq!(short.len(), RELAY_SMALL_BUFFER - 1);
            assert_eq!(buffer.size(), RELAY_SMALL_BUFFER, "a short read promoted");
        }

        buffer.as_mut().fill(0xff);
        assert_eq!(buffer.filled(RELAY_SMALL_BUFFER).len(), RELAY_SMALL_BUFFER);
        assert_eq!(buffer.size(), RELAY_BUFFER, "a full read did not promote");

        assert_eq!(buffer.filled(1).len(), 1);
        assert_eq!(buffer.size(), RELAY_BUFFER);
    }

    #[test]
    fn a_promoted_buffer_returns_the_bytes_that_were_read() {
        let mut buffer = RelayBuf::new();
        buffer.as_mut().fill(0);
        buffer.as_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        let read = buffer.filled(RELAY_SMALL_BUFFER);
        assert_eq!(&read[..4], &[1, 2, 3, 4], "promotion lost the bytes read");
        assert_eq!(read.len(), RELAY_SMALL_BUFFER);
    }

    /// Miri, not a byte test, sees a clip past the reported prefix: that is an uninitialised read.
    #[test]
    fn the_relay_buffer_hands_back_only_what_its_read_reported() {
        let source: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut buffer = RelayBuf::new();
        let n = std::io::Cursor::new(source.clone())
            .read(buffer.as_mut())
            .expect("the cursor fills what it holds");
        assert!(
            n < RELAY_SMALL_BUFFER,
            "a full buffer would promote, not clip"
        );
        let handed = buffer.filled(n).to_vec();
        assert_eq!(handed, source[..n], "every byte handed back was read");
    }

    /// The handshake pump hands the carrier the buffer's own bytes, and a sub-buffer read holds that buffer steady — the allocation claim behind routing the pump through `RelayBuf` rather than a fresh zero-filled `Vec` per connection.
    #[test]
    fn the_pump_forwards_its_buffer_by_pointer_and_holds_capacity_steady() {
        struct Quantum;
        impl std::io::Read for Quantum {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = 1024usize.min(buf.len());
                buf[..n].fill(0xa5);
                Ok(n)
            }
        }
        let mut reader = Quantum;
        let mut buffer = RelayBuf::new();
        let base = buffer.as_mut().as_ptr();
        for round in 0..64u32 {
            let n = reader
                .read(buffer.as_mut())
                .expect("the quantum always answers");
            let (handed, len) = {
                let slice = buffer.filled(n);
                (slice.as_ptr(), slice.len())
            };
            assert_eq!(
                handed, base,
                "round {round}: the pump forwards the buffer's own bytes, not a copy"
            );
            assert_eq!(len, n, "round {round}: only the bytes read escape");
            assert_eq!(
                buffer.as_mut().as_ptr(),
                base,
                "round {round}: a short read did not move the buffer"
            );
            assert_eq!(
                buffer.size(),
                RELAY_SMALL_BUFFER,
                "round {round}: and did not grow it"
            );
        }
    }

    #[test]
    fn the_relay_moves_a_payload_larger_than_its_copy_buffer() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = vec![0u8; RELAY_BUFFER];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            let Ok(uplink) = Connection::connect(("127.0.0.1", echo_port)) else {
                return;
            };
            relay(&stream, &uplink);
        });

        let payload: Vec<u8> = (0..(3 * RELAY_BUFFER + 7))
            .map(|i| (i % 253) as u8)
            .collect();
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let sent = client.try_clone().expect("clones");
        let outbound = payload.clone();
        let reader = thread::spawn(move || {
            let mut sent = sent;
            sent.write_all(&outbound).expect("writes");
            sent.shutdown(Shutdown::Write).expect("half closes");
        });
        let mut back = vec![0u8; payload.len()];
        client.read_exact(&mut back).expect("reads");
        reader.join().expect("sender finishes");
        assert_eq!(back, payload, "the relay must move every byte, in order");
    }

    #[test]
    fn trojan_relay_round_trips_and_refuses_strangers() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = echo.accept().expect("accepts");
            relay(&stream, &stream);
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(2) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || {
                    serve_trojan(stream, &trojan_key("an-example-shared-password"), true);
                });
            }
        });
        let mut good = Connection::connect(("127.0.0.1", port)).expect("connects");
        let mut header = Vec::new();
        header.extend_from_slice(&trojan_key("an-example-shared-password"));
        header.extend_from_slice(b"\r\n\x01\x01\x7f\x00\x00\x01");
        header.extend_from_slice(&echo_port.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        good.write_all(&header).expect("writes");
        good.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        good.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        let mut bad = Connection::connect(("127.0.0.1", port)).expect("connects");
        bad.write_all(&[0u8; 64]).expect("writes");
        let mut closed = [0u8; 1];
        assert!(bad.read(&mut closed).is_err() || closed == [0]);
        drop(good);
        drop(bad);
    }

    #[test]
    fn the_trojan_header_costs_two_reads_not_seven() {
        struct Counting<'a> {
            at: usize,
            wire: &'a [u8],
            reads: usize,
        }
        impl Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                let left = self.wire.len() - self.at;
                if left == 0 {
                    return Ok(0);
                }
                let n = left.min(buf.len());
                buf[..n].copy_from_slice(&self.wire[self.at..self.at + n]);
                self.at += n;
                Ok(n)
            }
        }

        let key = trojan_key("an-example-shared-password");
        for (addr, reads) in [
            (b"\x01\x7f\x00\x00\x01\x1f\x90".to_vec(), 2usize),
            (
                [4u8]
                    .into_iter()
                    .chain([0u8; 15])
                    .chain([1u8, 0x1f, 0x90])
                    .collect::<Vec<u8>>(),
                2,
            ),
            (b"\x03\x09localhost\x1f\x90".to_vec(), 3),
        ] {
            let mut wire = key.to_vec();
            wire.extend_from_slice(b"\r\n\x01");
            wire.extend_from_slice(&addr);
            wire.extend_from_slice(b"\r\n");
            let mut reader = Counting {
                at: 0,
                wire: &wire,
                reads: 0,
            };
            let (cmd, _) = decode_trojan_request(&mut reader, &key)
                .unwrap_or_else(|| panic!("decodes {addr:?}"));
            assert_eq!(cmd, 1, "{addr:?}");
            assert_eq!(reader.reads, reads, "{addr:?}");
        }
    }

    /// The server read is four for every address family and two for mux, down from five for an IP and six for a domain: the add-ons ride in with the command byte, and the port, family and the body's first byte share one read.
    #[test]
    fn the_vless_request_header_costs_four_reads_not_six() {
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
        let id = [0x11u8; 16];
        let header = |addons: &[u8], cmd: u8, tail: &[u8]| -> Vec<u8> {
            let mut w = vec![0u8];
            w.extend_from_slice(&id);
            w.push(addons.len() as u8);
            w.extend_from_slice(addons);
            w.push(cmd);
            w.extend_from_slice(tail);
            w
        };
        let port = 80u16.to_be_bytes();
        let cases = [
            (
                "ipv4",
                header(&[], 1, &[port.as_slice(), &[1, 192, 0, 2, 53]].concat()),
                4usize,
            ),
            (
                "ipv6",
                header(
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
                header(&[], 1, &[port.as_slice(), b"\x02\x09localhost"].concat()),
                4,
            ),
            (
                "addons",
                header(
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
            let (got, _flow, cmd, _target) =
                decode_request(&mut reader).unwrap_or_else(|| panic!("decodes {label}"));
            assert_eq!((got, cmd), (id, 1), "{label}");
            assert_eq!(reader.reads, want, "{label}");
        }

        let mux = header(&[], 3, &[]);
        let mut reader = Counting {
            at: 0,
            wire: &mux,
            reads: 0,
        };
        let (_, _, cmd, _) = decode_request(&mut reader).expect("decodes mux");
        assert_eq!(cmd, 3, "a mux request stops at the command byte");
        assert_eq!(reader.reads, 2, "mux");
    }

    #[test]
    fn the_key_compare_reads_every_byte() {
        let key = trojan_key("an-example-shared-password");
        assert!(key_agrees(&key, &key), "the key agrees with itself");
        for at in [0usize, 1, 27, 55] {
            let mut other = key;
            other[at] ^= 0x01;
            assert!(!key_agrees(&other, &key), "byte {at} differs");
        }
        assert!(!key_agrees(&key[..55], &key), "a short read never agrees");
    }

    #[test]
    fn rejects_a_wrong_version_and_user() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            decode_request(&mut stream)
        });
        let mut reader = Connection::connect(("127.0.0.1", port)).expect("connects");
        reader.write_all(&[1u8; 18]).expect("writes");
        assert!(writer.join().expect("joins").is_none());
        drop(reader);
    }

    #[test]
    fn a_grpc_service_name_is_escaped_the_way_xray_escapes_it() {
        let spaced = crate::json::parse(r#"{"grpcSettings": {"serviceName": "interop grpc"}}"#)
            .expect("parses");
        assert_eq!(grpc_path(Some(&spaced)), "/interop%20grpc/Tun");
        let plain =
            crate::json::parse(r#"{"grpcSettings": {"serviceName": "svc"}}"#).expect("parses");
        assert_eq!(grpc_path(Some(&plain)), "/svc/Tun");
        assert_eq!(grpc_path(None), "/Tun");
    }

    #[test]
    fn vision_links_relay_plaintext_over_outer_tls() {
        use ferrox_core::tls::TlsProvider as _;
        use std::io::Read as _;
        use std::io::Write as _;

        let (server_config, client_config) = carried_tls_configs();
        let id = [9u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("timeout");
            let raw = stream.try_clone().expect("clones");
            let mut outer =
                ferrox_core::tls::accept(&server_config, stream).expect("outer accepts");
            outer.handshake().expect("outer handshakes");
            let mut link = crate::vision::Link::new(outer, Some(raw), &id);
            let mut buf = [0u8; 512];
            let n = link.read(&mut buf).expect("reads");
            link.write_all(&buf[..n]).expect("echoes");
            link.flush().expect("flushes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let raw = stream.try_clone().expect("clones");
        let limited = ferrox_core::tls::reality::RecordLimiter::new(stream);
        let mut outer = ferrox_core::tls::connect(&client_config, limited).expect("outer connects");
        outer.handshake().expect("outer handshakes");
        let mut link = crate::vision::Link::new(outer, Some(raw), &id);
        link.write_all(b"ping").expect("writes");
        link.flush().expect("flushes");
        let mut back = [0u8; 4];
        link.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        drop(link);
        server.join().expect("joins");
    }

    #[test]
    fn vision_direct_switch_carries_inner_tls_over_loopback() {
        use ferrox_core::tls::TlsProvider as _;
        use std::io::Read as _;
        use std::io::Write as _;

        let (server_config, client_config) = carried_tls_configs();
        let id = [9u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("timeout");
            let raw = stream.try_clone().expect("clones");
            let mut outer =
                ferrox_core::tls::accept(&server_config, stream).expect("outer accepts");
            outer.handshake().expect("outer handshakes");
            let link = crate::vision::Link::new(outer, Some(raw), &id);
            let mut inner = ferrox_core::tls::accept(&server_config, link).expect("inner accepts");
            inner.handshake().expect("inner handshakes");
            let mut buf = [0u8; 512];
            loop {
                match inner.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        inner.write_all(&buf[..n]).expect("echoes");
                        inner.flush().expect("flushes");
                    }
                }
            }
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let raw = stream.try_clone().expect("clones");
        let limited = ferrox_core::tls::reality::RecordLimiter::new(stream);
        let mut outer = ferrox_core::tls::connect(&client_config, limited).expect("outer connects");
        outer.handshake().expect("outer handshakes");
        let link = crate::vision::Link::new(outer, Some(raw), &id);
        let mut inner = ferrox_core::tls::connect(&client_config, link).expect("inner connects");
        inner.handshake().expect("inner handshakes");
        for round in 0..8 {
            let payload = format!("inner tls round {round}");
            inner.write_all(payload.as_bytes()).expect("writes");
            inner.flush().expect("flushes");
            let mut echoed = vec![0; payload.len()];
            inner.read_exact(&mut echoed).expect("reads the echo");
            assert_eq!(echoed, payload.as_bytes());
        }
        drop(inner);
        server.join().expect("joins");
    }

    #[test]
    fn reality_edges_skip_lookups_without_xver() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut site, _) = listener.accept().expect("accepts");
        let _ = &mut site;
        let plain = ferrox_core::tls::RealityServerConfig {
            xver: 0,
            ..ferrox_core::tls::RealityServerConfig::default()
        };
        assert_eq!(
            reality_edges(&plain, &stream),
            Edges::default(),
            "no PROXY header means no lookup"
        );
        let proxied = ferrox_core::tls::RealityServerConfig {
            xver: 1,
            ..ferrox_core::tls::RealityServerConfig::default()
        };
        let edges = reality_edges(&proxied, &stream);
        assert!(edges.peer.is_some() && edges.local.is_some());
        assert_ne!(edges.peer, edges.local);
    }

    #[test]
    fn vless_security_gate_keeps_plain_and_refuses_reality() {
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        let none =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "none"}}"#)
                .expect("parses");
        let reality =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "reality"}}"#)
                .expect("parses");
        let tls =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "tls"}}"#)
                .expect("parses");
        assert!(vless_security_supported(stream_security(&plain)));
        assert!(vless_security_supported(stream_security(&none)));
        assert!(!vless_security_supported(stream_security(&reality)));
        assert!(!vless_security_supported(stream_security(&tls)));
    }

    #[test]
    fn vless_outbound_with_reality_dials_raw_and_every_carrier() {
        let public =
            x25519_dalek::x25519(REALITY_TEST_PRIVATE, x25519_dalek::X25519_BASEPOINT_BYTES);
        let key = b64url(&public);
        let dials = |stream: &str| {
            let json = format!(
                r#"{{"outbounds": [{{"protocol": "vless", "settings": {{"vnext": [{{"address": "127.0.0.1",
                "port": 443, "users": [{{"id": "{REALITY_TEST_ID}"}}]}}]}},
                "streamSettings": {{{stream}, "security": "reality",
                "realitySettings": {{"serverName": "{REALITY_TEST_SNI}",
                "publicKey": "{key}", "shortId": "{REALITY_TEST_SHORT}"}}}}}}]}}"#
            );
            find_vless_outbound(&crate::json::parse(&json).expect("parses")).is_some()
        };
        assert!(dials(r#""network": "tcp""#), "raw REALITY dials");
        assert!(dials(r#""network": "ws""#), "ws REALITY dials");
        assert!(
            dials(r#""network": "httpupgrade""#),
            "httpupgrade REALITY dials"
        );
        assert!(dials(r#""network": "grpc""#), "grpc REALITY dials");
        assert!(dials(r#""network": "xhttp""#), "xhttp REALITY dials");
        assert!(
            dials(
                r#""network": "tcp", "tcpSettings": {"header": {"type": "http", "request": {"path": "/"}}}"#
            ),
            "http-header REALITY dials"
        );
        assert!(
            !dials(r#""network": "quic""#),
            "quic REALITY stays refused, no UDP leg"
        );
        assert!(
            !dials(r#""network": "kcp""#),
            "kcp REALITY stays refused, raw-carrier only"
        );
        let bare = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1",
            "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality"}}]}"#,
        )
        .expect("parses");
        assert!(
            find_vless_outbound(&bare).is_none(),
            "no identity means no dial, never a plain one"
        );
    }

    const REALITY_TEST_PRIVATE: [u8; 32] = [
        0x69, 0x20, 0xca, 0xab, 0x2b, 0x4d, 0xe3, 0x7d, 0xfc, 0xfe, 0xbf, 0x60, 0x8b, 0x2a, 0x43,
        0x1c, 0x0e, 0xbb, 0xae, 0x26, 0x93, 0x9a, 0x9c, 0x01, 0x9e, 0x06, 0x1e, 0x8a, 0x0b, 0x4e,
        0x6b, 0x91,
    ];
    const REALITY_TEST_SHORT: &str = "0123456789abcdef";
    const REALITY_TEST_SNI: &str = "www.google.com";
    const REALITY_TEST_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn reality_server_config() -> ferrox_core::tls::RealityServerConfig {
        ferrox_core::tls::RealityServerConfig {
            private_key: REALITY_TEST_PRIVATE,
            short_ids: vec![[1, 35, 69, 103, 137, 171, 205, 239]],
            server_names: vec![REALITY_TEST_SNI.to_owned()],
            ..ferrox_core::tls::RealityServerConfig::default()
        }
    }

    fn reality_client_json(server_port: u16, public_b64: &str, flow: &str) -> String {
        reality_network_json(server_port, public_b64, flow, "tcp")
    }

    fn reality_network_json(
        server_port: u16,
        public_b64: &str,
        flow: &str,
        network: &str,
    ) -> String {
        format!(
            r#"{{"outbounds": [{{"protocol": "vless", "settings": {{"vnext": [{{"address": "127.0.0.1",
            "port": {server_port}, "users": [{{"id": "{REALITY_TEST_ID}", "flow": "{flow}"}}]}}]}},
            "streamSettings": {{"network": "{network}", "security": "reality",
            "realitySettings": {{"serverName": "{REALITY_TEST_SNI}",
            "publicKey": "{public_b64}", "shortId": "{REALITY_TEST_SHORT}",
            "fingerprint": "chrome"}}}}}}]}}"#,
        )
    }

    #[test]
    fn reality_outbound_parses_its_identity() {
        let public =
            x25519_dalek::x25519(REALITY_TEST_PRIVATE, x25519_dalek::X25519_BASEPOINT_BYTES);
        let root = crate::json::parse(&reality_client_json(
            443,
            &b64url(&public),
            "xtls-rprx-vision",
        ))
        .expect("parses");
        let out = find_vless_outbound(&root).expect("dials raw REALITY");
        assert_eq!(out.flow, "xtls-rprx-vision");
        let reality = out.reality.expect("carries its identity");
        assert_eq!(reality.server_name, REALITY_TEST_SNI);
        assert_eq!(reality.public_key, public);
        assert_eq!(reality.short_id, [1, 35, 69, 103, 137, 171, 205, 239]);
        let bare_flow =
            crate::json::parse(&reality_client_json(443, &b64url(&public), "")).expect("parses");
        let bare = find_vless_outbound(&bare_flow).expect("dials without a flow too");
        assert_eq!(bare.flow, "");
        let bad_flow = crate::json::parse(&reality_client_json(
            443,
            &b64url(&public),
            "xtls-rprx-vision-udp443",
        ))
        .expect("parses");
        assert!(
            find_vless_outbound(&bad_flow).is_none(),
            "an unknown flow is refused, never sent plain"
        );
    }

    #[test]
    fn vision_header_matches_the_core_encoder() {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision#x",
        )
        .expect("parses");
        let id = uuid_bytes(REALITY_TEST_ID).expect("id");
        for target in [
            SocketAddr::from(([192, 0, 2, 53], 80)),
            SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
        ] {
            let host = match target.ip() {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => ip.to_string(),
            };
            let core = link.encode_request_header(&host, target.port());
            let proxy = vless_vision_header(&id, 1, &Destination::from(target));
            assert_eq!(proxy, core, "the dial writes the core bytes for {target}");
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let writer = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                decode_request(&mut stream).expect("decodes")
            });
            let mut reader = Connection::connect(("127.0.0.1", port)).expect("connects");
            reader.write_all(&proxy).expect("writes");
            let (got, flow, cmd, decoded) = writer.join().expect("joins");
            assert_eq!(got, id);
            assert_eq!(flow, "xtls-rprx-vision");
            assert_eq!(cmd, 1);
            assert_eq!(decoded, target);
        }
    }

    /// The dial headers are reserved to the exact bytes they hold, so an IPv6 destination —
    /// 38 and 56 bytes against the old `with_capacity(30)`/`(48)` — no longer reallocates.
    #[test]
    fn dial_headers_are_sized_to_the_bytes_they_hold() {
        let id = [0x5au8; 16];
        for target in [
            SocketAddr::from(([192, 0, 2, 53], 80)),
            SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
        ] {
            let plain = vless_header(&id, 1, &Destination::from(target));
            assert_eq!(plain.capacity(), plain.len(), "no realloc for {target}");
            let vision = vless_vision_header(&id, 1, &Destination::from(target));
            assert_eq!(vision.capacity(), vision.len(), "no realloc for {target}");
        }
    }

    /// One REALITY pair on loopback: an echo target, an inbound, the dial. The flow is the caller's.
    struct RealityPair {
        outbound: Outbound,
        server: SocketAddr,
        target: SocketAddr,
        echo: thread::JoinHandle<()>,
        front: thread::JoinHandle<()>,
    }

    fn reality_pair(flow: &str) -> RealityPair {
        reality_pair_with(flow, "tcp", Carrier::Raw(Chain::default()))
    }

    fn reality_pair_with(flow: &str, network: &str, carrier: Carrier) -> RealityPair {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_addr = echo.local_addr().expect("addr");
        let echo = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 8192];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let id = uuid_bytes(REALITY_TEST_ID).expect("id");
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let server_addr = front.local_addr().expect("addr");
        let server_config = reality_server_config();
        let front_handle = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_vless_reality(stream, &id, true, &carrier, &server_config);
        });
        let public =
            x25519_dalek::x25519(REALITY_TEST_PRIVATE, x25519_dalek::X25519_BASEPOINT_BYTES);
        let root = crate::json::parse(&reality_network_json(
            server_addr.port(),
            &b64url(&public),
            flow,
            network,
        ))
        .expect("parses");
        let outbound = find_outbound(&root).expect("a REALITY outbound");
        RealityPair {
            outbound,
            server: server_addr,
            target: echo_addr,
            echo,
            front: front_handle,
        }
    }

    fn dial_pair(pair: &RealityPair) -> (Connection, thread::JoinHandle<()>) {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let outbound = match &pair.outbound {
            Outbound::Vless(vless) => vless.clone(),
            _ => panic!("the pair dials VLESS"),
        };
        let server = pair.server;
        let target = pair.target;
        let dialled = thread::spawn(move || {
            let (client, _) = front.accept().expect("accepts");
            tx.send(()).expect("signals");
            dial_socks_outbound(
                &client,
                &Outbound::Vless(outbound),
                &server,
                &Destination::from(target),
            );
        });
        let user = Connection::connect(addr).expect("connects");
        user.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        rx.recv_timeout(Duration::from_secs(30)).expect("dials");
        (user, dialled)
    }

    // Writing before reading only completes while the whole payload fits the chain's buffering, so read while writing, and give both arms the same deadline so a blocked one reports instead of parking.
    fn echo_within(user: &mut Connection, payload: &[u8], budget: Duration) -> Vec<u8> {
        user.set_write_timeout(Some(budget)).expect("write timeout");
        let mut reader = user.try_clone().expect("clones");
        // A duplicated socket need not inherit the parent's poll timeout, so the reading arm carries its own.
        reader.set_read_timeout(Some(budget)).expect("read timeout");
        let length = payload.len();
        let back = thread::spawn(move || {
            let mut got = vec![0u8; length];
            reader.read_exact(&mut got).map(|()| got)
        });
        user.write_all(payload).expect("writes");
        back.join().expect("joins").expect("echoes")
    }

    fn echo_bulk(user: &mut Connection, payload: &[u8]) -> Vec<u8> {
        echo_within(user, payload, Duration::from_secs(30))
    }

    /// A peer that swallows the payload and answers nothing must cost the witness its budget, not the job's whole stall window; a silent read here is a red that names the arm.
    #[test]
    #[should_panic(expected = "echoes")]
    fn a_silent_echo_peer_ends_the_bulk_read_at_its_budget() {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let sink = thread::spawn(move || {
            let (mut peer, _) = front.accept().expect("accepts");
            let mut drained = [0u8; 4096];
            while let Ok(read) = peer.read(&mut drained) {
                if read == 0 {
                    break;
                }
            }
        });
        let mut user = Connection::connect(addr).expect("connects");
        let payload: Vec<u8> = (0..4096u32).map(|index| index as u8).collect();
        echo_within(&mut user, &payload, Duration::from_millis(250));
        sink.join().expect("drains");
    }

    #[test]
    fn reality_vision_dial_reaches_echo_through_the_relay() {
        let pair = reality_pair(crate::vision::FLOW);
        let (mut user, dialled) = dial_pair(&pair);
        let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(echo_bulk(&mut user, &payload), payload);
        drop(user);
        dialled.join().expect("joins");
        pair.echo.join().expect("joins");
        pair.front.join().expect("joins");
    }

    #[test]
    fn reality_raw_dial_reaches_echo_through_the_relay() {
        let pair = reality_pair("");
        let (mut user, dialled) = dial_pair(&pair);
        for seed in [11u8, 12] {
            let length = if seed == 11 { 64 } else { 96 * 1024 };
            let payload: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(29).wrapping_add(seed))
                .collect();
            let back = echo_bulk(&mut user, &payload);
            assert_eq!(back, payload, "{seed}: payload came back altered");
        }
        drop(user);
        dialled.join().expect("joins");
        pair.echo.join().expect("joins");
        pair.front.join().expect("joins");
    }

    /// A bulk round trip must not assume the socket holds the payload: 4 KiB per direction is under what a fresh loopback socket gets anywhere, and 256 KiB crosses 64 of those windows, so a hop that parked after one still stalls; 4 MiB crossed 1024 of them for no extra witness and cost the linux job 107s of delayed-ACK-throttled transfer.
    #[test]
    #[cfg(unix)]
    fn a_small_socket_buffer_does_not_park_a_bulk_round_trip() {
        use std::os::unix::io::AsRawFd;
        let pair = reality_pair("");
        let (mut user, dialled) = dial_pair(&pair);
        for (name, opt) in [
            ("SO_SNDBUF", libc::SO_SNDBUF),
            ("SO_RCVBUF", libc::SO_RCVBUF),
        ] {
            let want: libc::c_int = 4096;
            // SAFETY: `want` outlives the call, and the size is its own.
            let set = unsafe {
                libc::setsockopt(
                    user.as_raw_fd(),
                    libc::SOL_SOCKET,
                    opt,
                    std::ptr::addr_of!(want).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            assert_eq!(0, set, "{name} refused");
        }
        let payload: Vec<u8> = (0..256 * 1024usize)
            .map(|index| (index as u8).wrapping_mul(29))
            .collect();
        assert_eq!(echo_bulk(&mut user, &payload), payload);
        drop(user);
        dialled.join().expect("joins");
        pair.echo.join().expect("joins");
        pair.front.join().expect("joins");
    }

    #[test]
    fn reality_ws_dial_reaches_echo_through_the_relay() {
        let pair = reality_pair_with(
            "",
            "ws",
            Carrier::Ws {
                path: "/".to_owned(),
                ed: 0,
            },
        );
        let (mut user, dialled) = dial_pair(&pair);
        let payload: Vec<u8> = (0..200_000u32)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
            .collect();
        let back = echo_bulk(&mut user, &payload);
        assert_eq!(
            back, payload,
            "payload came back altered through the carried REALITY session"
        );
        drop(user);
        dialled.join().expect("joins");
        pair.echo.join().expect("joins");
        pair.front.join().expect("joins");
    }

    #[test]
    fn reality_vision_direct_switch_carries_inner_tls() {
        use ferrox_core::tls::TlsProvider as _;

        let pair = reality_pair(crate::vision::FLOW);
        let (server_config, client_config) = carried_tls_configs();
        let inner = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let inner_addr = inner.local_addr().expect("addr");
        let echo = thread::spawn(move || {
            let (stream, _) = inner.accept().expect("accepts");
            let mut tls = ferrox_core::tls::accept(&server_config, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut buf = [0u8; 4096];
            loop {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        tls.write_all(&buf[..n]).expect("echoes");
                        tls.flush().expect("flushes");
                    }
                }
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let outbound = match &pair.outbound {
            Outbound::Vless(vless) => vless.clone(),
            _ => panic!("the pair dials VLESS"),
        };
        let server = pair.server;
        let dialled = thread::spawn(move || {
            let (client, _) = front.accept().expect("accepts");
            tx.send(()).expect("signals");
            dial_socks_outbound(
                &client,
                &Outbound::Vless(outbound),
                &server,
                &Destination::from(inner_addr),
            );
        });
        let user = Connection::connect(addr).expect("connects");
        user.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        rx.recv_timeout(Duration::from_secs(30)).expect("dials");
        let mut inner = ferrox_core::tls::connect(&client_config, user).expect("inner configures");
        inner.handshake().expect("inner handshakes");
        for round in 0..4 {
            let payload = format!("inner tls round {round}");
            inner.write_all(payload.as_bytes()).expect("writes");
            inner.flush().expect("flushes");
            let mut echoed = vec![0; payload.len()];
            inner.read_exact(&mut echoed).expect("echoes");
            assert_eq!(echoed, payload.as_bytes());
        }
        drop(inner);
        dialled.join().expect("joins");
        echo.join().expect("joins");
        pair.front.join().expect("joins");
    }

    #[test]
    fn the_gauge_paces_only_past_the_burst_it_was_given() {
        let mut flat = Gauge::start(ferrox_core::tls::RateLimit {
            after_bytes: 4,
            bytes_per_sec: 0,
            burst_bytes_per_sec: 0,
        });
        let start = Instant::now();
        for _ in 0..8 {
            flat.admit(1);
        }
        assert!(
            start.elapsed() < Duration::from_millis(20),
            "no rate, no wait"
        );

        let mut capped = Gauge::start(ferrox_core::tls::RateLimit {
            after_bytes: 0,
            bytes_per_sec: 500,
            burst_bytes_per_sec: 4_096,
        });
        let start = Instant::now();
        capped.admit(4_096);
        assert!(
            start.elapsed() < Duration::from_millis(5),
            "the burst is free"
        );
        capped.admit(1);
        assert!(
            start.elapsed() >= Duration::from_millis(1),
            "the byte past the burst waits out its token"
        );
    }

    #[test]
    fn carriers_read_their_paths_out_of_stream_settings() {
        let xhttp = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-one"}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(xhttp.get("streamSettings")),
            Carrier::Xhttp { settings, .. } if settings.path == "/share"
        ));
        let legacy = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "splithttpSettings": {"path": "/legacy"}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(legacy.get("streamSettings")),
            Carrier::Xhttp { settings, .. } if settings.path == "/legacy"
        ));
        let packet = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"mode": "packet-up"}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(packet.get("streamSettings")),
            Carrier::Xhttp { settings, .. }
                if settings.mode == crate::xhttp::XhttpMode::PacketUp
        ));
        let reality = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "security": "reality", "xhttpSettings": {}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(reality.get("streamSettings")),
            Carrier::Xhttp { settings, .. }
                if settings.mode == crate::xhttp::XhttpMode::StreamOne
        ));
        let camouflage = crate::json::parse(
            r#"{"streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "http", "request": {"path": ["/camouflage"]}}}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(camouflage.get("streamSettings")),
            Carrier::HttpHeader { path } if path == "/camouflage"
        ));
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        assert!(matches!(
            stream_carrier(plain.get("streamSettings")),
            Carrier::Raw(_)
        ));
    }

    fn xhttp_settings(path: &str) -> Box<crate::xhttp::XhttpSettings> {
        Box::new(crate::xhttp::XhttpSettings {
            path: path.to_owned(),
            // These rows are about what a hub that was *told* a mode refuses; an unstated mode serves every shape its dialer can write.
            mode_source: crate::xhttp::ModeSource::Stated,
            ..crate::xhttp::XhttpSettings::stream_one()
        })
    }

    fn xhttp_settings_mode(
        path: &str,
        mode: crate::xhttp::XhttpMode,
    ) -> Box<crate::xhttp::XhttpSettings> {
        Box::new(crate::xhttp::XhttpSettings {
            path: path.to_owned(),
            mode,
            mode_source: crate::xhttp::ModeSource::Stated,
            ..crate::xhttp::XhttpSettings::stream_one()
        })
    }

    /// One padded request head: the padding every default-configured server accepts.
    fn xhttp_pad() -> String {
        format!(
            "Referer: http://127.0.0.1/x?x_padding={}\r\n",
            "X".repeat(128)
        )
    }

    fn vless_over_carrier_reaches_echo(carrier: &Carrier, host: &str, path: &str) {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let serving: Carrier = carrier.clone();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_vless(stream, &id, &serving, true);
        });
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        let header = link.encode_request_header("127.0.0.1", echo_port);
        let uplink = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        match &carrier {
            Carrier::Xhttp { .. } => {
                let (mut reader, writer) =
                    crate::xhttp::connect(uplink, host, path).expect("upgrades");
                writer.send(&header);
                let mut reply = [0u8; 2];
                reader.read_exact(&mut reply).expect("replies");
                assert_eq!(reply, [0, 0]);
                writer.send(b"ping");
                writer.finish();
                let mut back = Vec::new();
                reader.read_to_end(&mut back).expect("echoes");
                assert_eq!(back, b"ping");
            }
            Carrier::HttpHeader { .. } => {
                let (mut reader, mut write) =
                    crate::httpheader::connect(uplink, host, path).expect("headers");
                write.write_all(&header).expect("writes");
                let mut reply = [0u8; 2];
                reader.read_exact(&mut reply).expect("replies");
                assert_eq!(reply, [0, 0]);
                write.write_all(b"ping").expect("writes");
                let mut back = [0u8; 4];
                reader.read_exact(&mut back).expect("echoes");
                assert_eq!(&back, b"ping");
            }
            _ => unreachable!("this helper only serves the two new carriers"),
        }
    }

    #[test]
    fn vless_over_xhttp_reaches_echo() {
        vless_over_carrier_reaches_echo(
            &Carrier::Xhttp {
                settings: xhttp_settings("/share"),
            },
            "oracle.example",
            "/share",
        );
    }

    /// Raw HTTP/1.1 clients for the three xhttp modes, padded, with session and seq in the path.
    fn xhttp_get(stream: &mut Connection, target: &str) {
        stream
            .write_all(
                format!(
                    "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Connection: keep-alive\r\n\r\n",
                    xhttp_pad(),
                )
                .as_bytes(),
            )
            .expect("writes");
    }

    fn xhttp_post_head(stream: &mut Connection, target: &str, chunked: bool) {
        let framing = if chunked {
            "Transfer-Encoding: chunked"
        } else {
            "Content-Length: 0"
        };
        stream
            .write_all(
                format!(
                    "POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Content-Type: application/grpc\r\n{framing}\r\nConnection: keep-alive\r\n\r\n",
                    xhttp_pad(),
                )
                .as_bytes(),
            )
            .expect("writes");
    }

    fn xhttp_chunk(stream: &mut Connection, data: &[u8]) {
        stream
            .write_all(format!("{:X}\r\n", data.len()).as_bytes())
            .expect("writes");
        stream.write_all(data).expect("writes");
        stream.write_all(b"\r\n").expect("writes");
        stream.flush().expect("flushes");
    }

    fn xhttp_read_head(stream: &mut Connection) -> Vec<u8> {
        let mut head = Vec::new();
        let mut one = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut one) {
                Ok(0) => panic!("head ended early"),
                Ok(_) => head.extend_from_slice(&one),
                Err(error) => panic!("head failed: {error:?}"),
            }
            assert!(head.len() < 65536, "head too long");
        }
        head
    }

    fn xhttp_status(head: &[u8]) -> u16 {
        let line = head.split(|b| *b == b'\r').next().unwrap_or_default();
        let code = line.split(|b| *b == b' ').nth(1).unwrap_or_default();
        std::str::from_utf8(code)
            .unwrap_or_default()
            .parse()
            .unwrap_or(0)
    }

    /// Reads exactly `n` de-chunked bytes, the way any HTTP layer does before handing over the logical stream.
    fn xhttp_read_chunked(stream: &mut Connection, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut line = Vec::new();
        let mut one = [0u8; 1];
        while out.len() < n {
            line.clear();
            while !line.ends_with(b"\r\n") {
                match stream.read(&mut one) {
                    Ok(0) => panic!("chunk ended early"),
                    Ok(_) => line.extend_from_slice(&one),
                    Err(error) => panic!("chunk failed: {error:?}"),
                }
            }
            let size = usize::from_str_radix(
                std::str::from_utf8(&line[..line.len() - 2])
                    .unwrap_or_default()
                    .trim(),
                16,
            )
            .unwrap_or_default();
            assert!(
                size != 0,
                "downlink ended with {} of {n} bytes left",
                n - out.len()
            );
            let mut chunk = vec![0u8; size];
            stream.read_exact(&mut chunk).expect("reads the chunk");
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).expect("reads the close");
            assert_eq!(&crlf, b"\r\n");
            let take = (n - out.len()).min(size);
            out.extend_from_slice(&chunk[..take]);
        }
        out
    }

    /// Serve exactly `takes` xhttp connections the way the accept loop does.
    fn xhttp_serve_n(listener: &Listener, takes: usize, carrier: &Carrier, id: [u8; 16]) {
        for stream in listener.incoming().take(takes) {
            let Ok(stream) = stream else { continue };
            let carrier = carrier.clone();
            thread::spawn(move || serve_vless(stream, &id, &carrier, true));
        }
    }

    fn xhttp_vless_header(echo_port: u16) -> Vec<u8> {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        link.encode_request_header("127.0.0.1", echo_port)
    }

    fn xhttp_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = echo.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        (addr, handle)
    }

    fn xhttp_front(
        carrier: Carrier,
        id: [u8; 16],
        takes: usize,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let handle = thread::spawn(move || xhttp_serve_n(&front, takes, &carrier, id));
        (addr, handle)
    }

    #[test]
    fn xhttp_stream_up_carries_bulk_both_ways() {
        let (echo_addr, echo) = xhttp_echo_server();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let carrier = Carrier::Xhttp {
            settings: xhttp_settings_mode("/up", crate::xhttp::XhttpMode::StreamUp),
        };
        let (addr, server) = xhttp_front(carrier, id, 2);
        let header = xhttp_vless_header(echo_addr.port());

        let mut down = Connection::connect(addr).expect("connects");
        down.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        xhttp_get(&mut down, "/up/sess-up-01");
        let head = xhttp_read_head(&mut down);
        assert_eq!(xhttp_status(&head), 200);

        let mut up = Connection::connect(addr).expect("connects");
        up.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        xhttp_post_head(&mut up, "/up/sess-up-01", true);
        let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let writer = thread::spawn(move || {
            xhttp_chunk(&mut up, &header);
            let mut at = 0;
            while at < payload.len() {
                let end = (at + 4096).min(payload.len());
                xhttp_chunk(&mut up, &payload[at..end]);
                at = end;
            }
            up.write_all(b"0\r\n\r\n").expect("terminates");
            up
        });

        let reply = xhttp_read_chunked(&mut down, 2);
        assert_eq!(reply, [0, 0]);
        let echoed = xhttp_read_chunked(&mut down, 65536);
        assert_eq!(
            echoed,
            (0..65536u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>()
        );
        writer.join().expect("joins");
        drop(down);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    #[test]
    fn xhttp_packet_up_reassembles_out_of_order_posts() {
        let (echo_addr, _echo) = xhttp_echo_server();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let carrier = Carrier::Xhttp {
            settings: xhttp_settings_mode("/up", crate::xhttp::XhttpMode::PacketUp),
        };
        let (addr, server) = xhttp_front(carrier, id, 3);
        let header = xhttp_vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();

        let mut down = Connection::connect(addr).expect("connects");
        down.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        xhttp_get(&mut down, "/up/sess-pkt-01");
        let head = xhttp_read_head(&mut down);
        assert_eq!(xhttp_status(&head), 200);

        // Sequence 1 posts before sequence 0: the heap must still deliver in order.
        let mut one = Connection::connect(addr).expect("connects");
        one.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let body1 = &payload[4096..];
        one.write_all(
            format!(
                "POST /up/sess-pkt-01/1 HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                xhttp_pad(),
                body1.len()
            )
            .as_bytes(),
        )
        .expect("writes");
        one.write_all(body1).expect("writes");
        one.flush().expect("flushes");
        let head = xhttp_read_head(&mut one);
        assert_eq!(xhttp_status(&head), 200);

        let mut zero = Connection::connect(addr).expect("connects");
        zero.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut body0 = header.clone();
        body0.extend_from_slice(&payload[..4096]);
        zero
            .write_all(
                format!(
                    "POST /up/sess-pkt-01/0 HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    xhttp_pad(),
                    body0.len()
                )
                .as_bytes(),
            )
            .expect("writes");
        zero.write_all(&body0).expect("writes");
        zero.flush().expect("flushes");
        let head = xhttp_read_head(&mut zero);
        assert_eq!(xhttp_status(&head), 200);

        let reply = xhttp_read_chunked(&mut down, 2);
        assert_eq!(reply, [0, 0]);
        let echoed = xhttp_read_chunked(&mut down, payload.len());
        assert_eq!(echoed, payload);
        drop(down);
        drop(one);
        drop(zero);
        server.join().expect("joins");
        // No echo join: packet-up has no terminal marker, so the session outlives the last asserted byte.
    }

    #[test]
    fn xhttp_greeting_first_arrives_before_uplink_payload() {
        let greet = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let greet_addr = greet.local_addr().expect("addr");
        let greeter = thread::spawn(move || {
            let (mut stream, _) = greet.accept().expect("accepts");
            stream.write_all(b"220 greetings\r\n").expect("greets");
            stream.flush().expect("flushes");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let carrier = Carrier::Xhttp {
            settings: xhttp_settings_mode("/up", crate::xhttp::XhttpMode::StreamUp),
        };
        let (addr, server) = xhttp_front(carrier, id, 2);
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        let header = link.encode_request_header("127.0.0.1", greet_addr.port());

        let mut down = Connection::connect(addr).expect("connects");
        down.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        xhttp_get(&mut down, "/up/sess-greet-01");
        let head = xhttp_read_head(&mut down);
        assert_eq!(xhttp_status(&head), 200);

        // Only the VLESS header goes up; the greeting must arrive unprompted.
        let mut up = Connection::connect(addr).expect("connects");
        up.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        xhttp_post_head(&mut up, "/up/sess-greet-01", true);
        xhttp_chunk(&mut up, &header);
        let response = xhttp_read_chunked(&mut down, 2);
        assert_eq!(response, [0, 0]);
        let greeting = xhttp_read_chunked(&mut down, 15);
        assert_eq!(greeting, b"220 greetings\r\n");
        xhttp_chunk(&mut up, b"ping");
        up.write_all(b"0\r\n\r\n").expect("terminates");
        let echoed = xhttp_read_chunked(&mut down, 4);
        assert_eq!(echoed, b"ping");
        drop(down);
        drop(up);
        greeter.join().expect("joins");
        server.join().expect("joins");
    }

    #[test]
    fn xhttp_refusals_carry_their_statuses() {
        fn status_of(settings: &crate::xhttp::XhttpSettings, request: &[u8]) -> u16 {
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let settings = settings.clone();
            thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let Ok(read) = stream.try_clone() else {
                    return;
                };
                let _ = crate::xhttp::accept_split_with_settings(read, stream, &settings);
            });
            let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            stream.write_all(request).expect("writes");
            let head = xhttp_read_head(&mut stream);
            xhttp_status(&head)
        }
        let one = xhttp_settings("/up");
        let pad = xhttp_pad();
        let req = |method: &str, target: &str, extra: &str| {
            format!("{method} {target} HTTP/1.1\r\nHost: h\r\n{pad}{extra}\r\n")
        };
        assert_eq!(status_of(&one, req("POST", "/other", "").as_bytes()), 404);
        assert_eq!(
            status_of(
                &one,
                b"POST /up HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice()
            ),
            400
        );
        assert_eq!(status_of(&one, req("DELETE", "/up", "").as_bytes()), 405);
        let up = xhttp_settings_mode("/up", crate::xhttp::XhttpMode::StreamUp);
        assert_eq!(
            status_of(&up, req("POST", "/up", "").as_bytes()),
            400,
            "an uplink POST with no chunked framing"
        );
        assert_eq!(
            status_of(
                &up,
                req("POST", "/up", "Transfer-Encoding: chunked\r\n").as_bytes()
            ),
            200,
            "a stated stream-up hub serves a session-less POST, as the reference does"
        );
        assert_eq!(
            status_of(&up, req("GET", "/up/abc", "").as_bytes()),
            200,
            "stream-up downlink"
        );
        let packet = xhttp_settings_mode("/up", crate::xhttp::XhttpMode::PacketUp);
        assert_eq!(
            status_of(&packet, req("POST", "/up/abc", "").as_bytes()),
            400,
            "packet-up without a seq"
        );
        assert_eq!(
            status_of(&packet, req("POST", "/up/abc/notanumber", "").as_bytes()),
            500,
            "packet-up with a bad seq"
        );
        assert_eq!(
            status_of(&one, req("POST", "/up/abc", "").as_bytes()),
            400,
            "stream-one with a session id"
        );
        assert_eq!(
            status_of(
                &packet,
                format!(
                    "POST /up/abc/0 HTTP/1.1\r\nHost: h\r\n{pad}Content-Length: 2000000\r\n\r\n"
                )
                .as_bytes()
            ),
            413
        );

        let obfs = crate::json::parse(
            r#"{"xhttpSettings": {"path": "/up", "mode": "stream-one", "extra": {
                "xPaddingBytes": "1-1", "xPaddingObfsMode": true, "xPaddingKey": "ctx",
                "xPaddingHeader": "x-grpc-context", "xPaddingMethod": "tokenish"}}}"#,
        )
        .expect("parses");
        let obfs = crate::xhttp::XhttpSettings::from_json(Some(&obfs)).expect("extra parses");
        assert_eq!(
            status_of(
                &obfs,
                b"POST /up HTTP/1.1\r\nHost: h\r\nx-grpc-context: http://h/up?ctx=kq\r\nTransfer-Encoding: chunked\r\n\r\n"
            ),
            200,
            "the padding the reference puts in the configured header"
        );
        assert_eq!(
            status_of(&obfs, req("POST", "/up", "").as_bytes()),
            400,
            "the default Referer padding is refused once obfs mode is on"
        );
    }

    #[test]
    fn vless_over_http_camouflage_reaches_echo() {
        vless_over_carrier_reaches_echo(
            &Carrier::HttpHeader {
                path: "/camouflage".to_owned(),
            },
            "oracle.example",
            "/camouflage",
        );
    }

    const CARRIER_CERT: &[u8] = &[
        48, 130, 1, 106, 48, 130, 1, 16, 160, 3, 2, 1, 2, 2, 20, 9, 118, 203, 85, 160, 31, 89, 126,
        130, 240, 1, 124, 88, 139, 2, 183, 133, 180, 103, 195, 48, 10, 6, 8, 42, 134, 72, 206, 61,
        4, 3, 2, 48, 23, 49, 21, 48, 19, 6, 3, 85, 4, 3, 12, 12, 99, 97, 114, 114, 105, 101, 114,
        46, 116, 101, 115, 116, 48, 30, 23, 13, 50, 54, 49, 48, 48, 52, 49, 52, 52, 56, 50, 49, 90,
        23, 13, 51, 54, 49, 48, 48, 49, 49, 52, 52, 56, 50, 49, 90, 48, 23, 49, 21, 48, 19, 6, 3,
        85, 4, 3, 12, 12, 99, 97, 114, 114, 105, 101, 114, 46, 116, 101, 115, 116, 48, 89, 48, 19,
        6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 41,
        137, 145, 160, 42, 144, 149, 142, 54, 81, 211, 232, 207, 195, 182, 234, 177, 95, 42, 39,
        92, 183, 224, 141, 46, 233, 255, 84, 155, 88, 113, 20, 230, 111, 41, 31, 113, 3, 159, 7,
        37, 57, 17, 202, 128, 16, 91, 230, 56, 82, 214, 175, 165, 189, 32, 28, 94, 83, 15, 239,
        210, 113, 16, 253, 163, 58, 48, 56, 48, 23, 6, 3, 85, 29, 17, 4, 16, 48, 14, 130, 12, 99,
        97, 114, 114, 105, 101, 114, 46, 116, 101, 115, 116, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4,
        20, 126, 53, 130, 175, 120, 162, 169, 76, 233, 165, 63, 46, 152, 172, 200, 218, 190, 139,
        205, 23, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 72, 0, 48, 69, 2, 33, 0, 130, 231,
        244, 98, 234, 42, 158, 5, 44, 34, 56, 45, 180, 195, 201, 250, 215, 93, 204, 192, 169, 181,
        83, 133, 90, 244, 246, 224, 213, 45, 28, 10, 2, 32, 92, 67, 120, 137, 239, 251, 234, 128,
        183, 189, 254, 199, 96, 112, 70, 178, 155, 92, 36, 164, 173, 158, 104, 237, 93, 67, 213,
        174, 165, 157, 39, 208,
    ];
    const CARRIER_KEY: &[u8] = &[
        48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
        61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 203, 157, 10, 119, 189, 153, 186, 104, 43,
        21, 78, 170, 1, 87, 240, 205, 227, 168, 196, 141, 76, 209, 149, 222, 208, 177, 26, 155,
        187, 113, 5, 239, 161, 68, 3, 66, 0, 4, 41, 137, 145, 160, 42, 144, 149, 142, 54, 81, 211,
        232, 207, 195, 182, 234, 177, 95, 42, 39, 92, 183, 224, 141, 46, 233, 255, 84, 155, 88,
        113, 20, 230, 111, 41, 31, 113, 3, 159, 7, 37, 57, 17, 202, 128, 16, 91, 230, 56, 82, 214,
        175, 165, 189, 32, 28, 94, 83, 15, 239, 210, 113, 16, 253,
    ];

    fn carried_round_trip(
        name: &str,
        accept: impl FnOnce(Connection) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>
            + Send
            + 'static,
        connect: impl FnOnce(Connection) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>,
    ) {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (reader, writer) = accept(stream).expect("accepts carrier");
            let mut stream = CarrierStream { reader, writer };
            let mut buf = vec![0u8; 16 * 1024];
            stream.read_exact(&mut buf).expect("reads");
            stream.write_all(&buf).expect("echoes");
            stream.flush().expect("flushes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (reader, writer) = connect(stream).expect("connects carrier");
        let mut stream = CarrierStream { reader, writer };
        let sent: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
        stream.write_all(&sent).expect("writes");
        stream.flush().expect("flushes");
        let mut back = vec![0u8; 16 * 1024];
        stream.read_exact(&mut back).expect("reads");
        assert_eq!(back, sent, "{name} round trips");
        server.join().expect("joins");
    }

    #[test]
    fn carried_streams_round_trip_over_ws() {
        carried_round_trip(
            "ws",
            |stream| {
                let (reader, writer) = crate::ws::accept(stream, "/tunnel")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::ws::connect(stream, "127.0.0.1", "/tunnel", 0, &[])?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn carried_streams_round_trip_over_xhttp() {
        carried_round_trip(
            "xhttp",
            |stream| {
                let (reader, writer) = crate::xhttp::accept(stream, "/share")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::xhttp::connect(stream, "127.0.0.1", "/share")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn carried_streams_round_trip_behind_the_http_camouflage() {
        carried_round_trip(
            "httpheader",
            |stream| {
                let (reader, write) = crate::httpheader::accept(stream, "/camouflage")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, write) =
                    crate::httpheader::connect(stream, "127.0.0.1", "/camouflage")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn carried_streams_round_trip_past_the_upgrade() {
        carried_round_trip(
            "httpupgrade",
            |stream| {
                let (reader, write) = crate::httpupgrade::accept(stream, "/tunnel")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, write) =
                    crate::httpupgrade::connect(stream, "127.0.0.1", "/tunnel", 0, &[])?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    /// Checked, not claimed: `tun` is served while the device names with no native open behind it are still refused; every served front still starts.
    #[test]
    fn a_device_inbound_is_refused_by_name_rather_than_served() {
        assert!(
            inbound_served("tun"),
            "the native device inbound `tun` serves"
        );
        for name in ["utun", "wintun", "tun2socks"] {
            assert!(
                !inbound_served(name),
                "the device inbound `{name}` is refused by name"
            );
        }
        for name in SERVED_INBOUNDS {
            assert!(inbound_served(name), "the front `{name}` serves");
        }
    }

    fn carried_tls_configs() -> (
        std::sync::Arc<ferrox_core::tls::TlsServerConfig>,
        ferrox_core::tls::TlsConfig,
    ) {
        let server = std::sync::Arc::new(ferrox_core::tls::TlsServerConfig {
            alpn: Vec::new(),
            cert_chain: vec![CARRIER_CERT.to_vec()],
            key_der: CARRIER_KEY.to_vec(),
            key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
            send_tickets: true,
        });
        let client = ferrox_core::tls::TlsConfig {
            server_name: "carrier.test".to_owned(),
            alpn: Vec::new(),
            roots: vec![CARRIER_CERT.to_vec()],
            pins: ferrox_core::foxy::pin::Pins::default(),
            cipher_suites: Vec::new(),
            insecure: false,
        };
        (server, client)
    }

    /// Two pumps share one session: a read waiting under the lock strangles the writer for the peer's silence.
    #[test]
    fn a_shared_tls_session_yields_the_lock_between_polls() {
        use ferrox_core::tls::TlsProvider as _;
        use std::io::Read as _;
        use std::io::Write as _;
        use std::time::Instant;

        let (server_config, client_config) = carried_tls_configs();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let server: SocketAddr = listener.local_addr().expect("addr");
        let (release, hold) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::accept(&server_config, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            // Holds the session up without writing, as an edge does while waiting for the next frame.
            let _ = hold.recv_timeout(Duration::from_secs(10));
        });

        let session = dial_tls_session(&server, &client_config, None).expect("dialled");
        let (reader, writer, raw) = tls_halves(session).expect("halves");
        let reading = thread::spawn(move || {
            let mut peer = reader;
            let began = Instant::now();
            let mut buf = [0u8; 512];
            while began.elapsed() < Duration::from_secs(4) {
                let _ = peer.read(&mut buf);
            }
        });
        // Let the read pump settle into its wait before the write pump comes by.
        thread::sleep(Duration::from_millis(250));

        let mut sink = SessionSink { half: writer, raw };
        for _ in 0..3 {
            let began = Instant::now();
            sink.write_all(b"ping")
                .expect("writes while the read pump polls");
            let waited = began.elapsed();
            assert!(
                waited < Duration::from_millis(200),
                "the write pump waited {waited:?} for a session the read pump holds"
            );
        }
        let _ = reading.join();
        let _ = release.send(());
    }

    fn tls_over_carrier(
        name: &str,
        accept: impl FnOnce(Connection) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>
            + Send
            + 'static,
        connect: impl FnOnce(Connection) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>,
    ) {
        use ferrox_core::tls::TlsProvider as _;

        let (server_config, client_config) = carried_tls_configs();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            let (reader, writer) = accept(stream).expect("accepts carrier");
            let mut tls =
                ferrox_core::tls::accept(&server_config, CarrierStream { reader, writer })
                    .expect("configures");
            tls.handshake().expect("handshakes");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).expect("reads");
            tls.write_all(&buf).expect("echoes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (reader, writer) = connect(stream).expect("connects carrier");
        let mut tls = ferrox_core::tls::connect(&client_config, CarrierStream { reader, writer })
            .expect("configures");
        tls.handshake().expect("handshakes over {name}");
        tls.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        tls.read_exact(&mut back).expect("reads");
        assert_eq!(&back, b"ping", "{name} carries the session");
        server.join().expect("joins");
    }

    #[test]
    fn tls_handshakes_over_ws_messages() {
        tls_over_carrier(
            "ws",
            |stream| {
                let (reader, writer) = crate::ws::accept(stream, "/tunnel")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::ws::connect(stream, "127.0.0.1", "/tunnel", 0, &[])?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn tls_handshakes_over_xhttp_chunks() {
        tls_over_carrier(
            "xhttp",
            |stream| {
                let (reader, writer) = crate::xhttp::accept(stream, "/share")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::xhttp::connect(stream, "127.0.0.1", "/share")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    /// A peer quiet past one quantum still handshakes: idle retries to the deadline; silence is not a refusal.
    #[test]
    fn a_peer_quiet_past_one_quantum_still_handshakes() {
        use ferrox_core::tls::TlsProvider as _;

        let (server_config, client_config) = carried_tls_configs();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream.set_read_timeout(Some(RELAY_POLL)).expect("timeout");
            let Some(mut tls) = accept_tls_session(stream, &server_config) else {
                panic!("handshakes past the pause");
            };
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).expect("reads");
            tls.write_all(&buf).expect("echoes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        thread::sleep(RELAY_POLL * 5);
        let mut tls = ferrox_core::tls::connect(&client_config, stream).expect("configures");
        tls.handshake().expect("handshakes");
        tls.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        tls.read_exact(&mut back).expect("reads");
        assert_eq!(&back, b"ping");
        server.join().expect("joins");
    }

    /// Silence past the budget is death, not scheduling: a peer that opens the connection and never sends must not pin the raw VLESS handshake thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_a_raw_vless_handshake() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x11u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// Silence past the budget is death, not scheduling: a peer that opens the connection and never sends must not pin the raw Trojan handshake thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_a_raw_trojan_handshake() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let key = [b'k'; 56];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_trojan(stream, &key, true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// Silence past the budget is death, not scheduling: a peer that opens the socks front and never greets must not pin its handler thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_the_socks_greeting() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_socks(stream, &Outbound::Freedom);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded greeting read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// The budget bounds each read the greeting is made of, not only the first: a peer that selects a method and then stalls before naming its target costs the same budget.
    #[test]
    fn a_peer_stalled_mid_greeting_cannot_pin_the_socks_front() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_socks(stream, &Outbound::Freedom);
            let _ = done_tx.send(());
        });
        // The peer stays open and says nothing more, so the request read expires rather than seeing a close.
        let mut peer = Connection::connect(addr).expect("connects");
        peer.write_all(&[5, 1, 0]).expect("greets");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A peer that finishes the websocket upgrade and then goes quiet costs a handshake budget, not a thread.
    #[test]
    fn a_silent_peer_cannot_pin_a_ws_handshake() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x22u8; 16];
        let carrier = Carrier::Ws {
            path: "/p".into(),
            ed: 0,
        };
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &carrier, true);
            let _ = done_tx.send(());
        });
        let mut peer = Connection::connect(addr).expect("connects");
        peer.write_all(b"GET /p HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Key: aGVsbG8gd29ybGQxMjM0NQ==\r\n\r\n")
            .expect("upgrades");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the budgeted frame read returns instead of pinning the thread");
        drop(peer);
        serving.join().expect("joins");
    }

    /// A peer that rides the upgrade response then stops speaking releases the handshake thread.
    #[test]
    fn a_silent_peer_cannot_pin_an_httpupgrade_handshake() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x23u8; 16];
        let carrier = Carrier::HttpUpgrade {
            path: "/p".into(),
            ed: 0,
        };
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &carrier, true);
            let _ = done_tx.send(());
        });
        let mut peer = Connection::connect(addr).expect("connects");
        peer.write_all(
            b"GET /p HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .expect("upgrades");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        drop(peer);
        serving.join().expect("joins");
    }

    /// A peer whose head passes camouflage but whose body never arrives still dies on the budget.
    #[test]
    fn a_silent_peer_cannot_pin_an_httpheader_handshake() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x24u8; 16];
        let carrier = Carrier::HttpHeader { path: "/p".into() };
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &carrier, true);
            let _ = done_tx.send(());
        });
        let mut peer = Connection::connect(addr).expect("connects");
        peer.write_all(b"GET /p HTTP/1.1\r\nHost: h\r\n\r\n")
            .expect("sends head");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        drop(peer);
        serving.join().expect("joins");
    }

    /// Silence before the preface is death, not scheduling: a peer that opens a gRPC connection and never sends must not pin the accept thread past the head's budget.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_preface() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x25u8; 16];
        let carrier = Carrier::Grpc { path: "/p".into() };
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &carrier, true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded preface read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A peer that sends the 24-octet preface and then stops speaking dies on the same budget: the request headers are read under the clock the preface started on.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_request_head() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x26u8; 16];
        let carrier = Carrier::Grpc { path: "/p".into() };
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &carrier, true);
            let _ = done_tx.send(());
        });
        let mut peer = Connection::connect(addr).expect("connects");
        peer.write_all(crate::h2::MAGIC).expect("sends the preface");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded header read returns instead of pinning the thread");
        drop(peer);
        serving.join().expect("joins");
    }

    /// A client that completes the gRPC handshake and never sends its first hunk releases the serve thread: the opening request is decoded under the reader's own budget, the way the websocket frames are.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_vless_request() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x27u8; 16];
        let carrier = Carrier::Grpc { path: "/p".into() };
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &carrier, true);
            let _ = done_tx.send(());
        });
        let stream = Connection::connect(addr).expect("connects");
        let (_reader, _writer) = crate::grpc::connect(stream, "127.0.0.1", "/p").expect("dials");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A session inbound whose peer answers the head and then stops speaking releases the serve thread: the dispatcher's poll makes the session read answer, and the request's own clock makes it refuse.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_tls_vless_request() {
        use ferrox_core::tls::TlsProvider as _;
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });

        let (server_config, client_config) = carried_tls_configs();
        let id = [0x28u8; 16];
        let carrier = Carrier::Grpc { path: "/p".into() };
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless_tls(stream, &id, true, &carrier, &server_config);
            let _ = done_tx.send(());
        });
        let mut session =
            ferrox_core::tls::connect(&client_config, Connection::connect(addr).expect("connects"))
                .expect("opens");
        session.handshake().expect("handshakes");
        let (read, write) = session_halves(session);
        let (_reader, _writer) =
            crate::grpc::connect_split(read, write, "127.0.0.1", "/p").expect("dials the head");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded session request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A trojan inbound over gRPC whose peer answers the head and never writes its hash releases the serve thread: the carrier puts its clock away with the head, so the request reads under its own.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_trojan_request() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let key = trojan_key("secret");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_trojan_grpc(stream, &key, "/p", true);
            let _ = done_tx.send(());
        });
        let stream = Connection::connect(addr).expect("connects");
        let (_reader, _writer) = crate::grpc::connect(stream, "127.0.0.1", "/p").expect("dials");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A KCP session that registers with a prefix and then falls silent dies on the wall-clock budget, not on the poll quantum.
    #[test]
    fn a_silent_peer_cannot_pin_a_kcp_handshake() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x25u8; 16];
        let kcp_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let listener =
            ferrox_core::kcp::Listener::bind(kcp_addr, ferrox_core::kcp::Config::default())
                .expect("binds");
        let kcp_port = listener.local_addr().port();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let conn = listener.accept().expect("accepts");
            serve_vless_kcp(&conn, &id, true);
            let _ = done_tx.send(());
        });
        let server_addr: SocketAddr = format!("127.0.0.1:{kcp_port}").parse().expect("addr");
        let peer = ferrox_core::kcp::dial(
            server_addr,
            ferrox_core::kcp::Config::default(),
            ferrox_core::kcp::fresh_conversation(),
        )
        .expect("dials");
        // One small packet registers the session; after it the peer never speaks again.
        peer.write(b"he").expect("writes a prefix");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        drop(peer);
        serving.join().expect("joins");
    }

    /// A trojan peer that never finishes the password line releases the handshake thread.
    #[test]
    fn a_silent_peer_cannot_pin_a_trojan_handshake() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let key = [b'a'; 56];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_trojan(stream, &key, true);
            let _ = done_tx.send(());
        });
        let mut peer = Connection::connect(addr).expect("connects");
        peer.write_all(b"not-a-password-yet")
            .expect("writes a prefix");
        let returned = done_rx.recv_timeout(budgets::handshake() + Duration::from_secs(5));
        budgets::clear();
        returned.expect("the bounded password read returns instead of pinning the thread");
        drop(peer);
        serving.join().expect("joins");
    }

    /// A server that holds its `[0, 0]` until the first payload arrives — xray with padding and zeronet both do — must not deadlock the client: the client has to start the upload before it waits on the response.
    #[test]
    fn vless_client_pumps_the_upload_before_reading_the_response() {
        let id = [0x26u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            // Read the request, then wait for payload before answering: a response-withholding server.
            let Some((got, _flow, cmd, _target)) = decode_request(&mut stream) else {
                panic!("reads a vless header");
            };
            assert_eq!(got, id);
            assert_eq!(cmd, 1);
            let mut payload = [0u8; 4];
            stream
                .read_exact(&mut payload)
                .expect("reads payload before answering");
            stream.write_all(&[0, 0]).expect("answers");
            stream.write_all(&payload).expect("echoes");
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let vless = VlessOut {
            address: "127.0.0.1".to_owned(),
            port,
            id,
            carrier: Carrier::Raw(Chain::default()),
            host: String::new(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        };
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let relaying = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            dial_vless(
                &stream,
                &server_addr,
                &vless,
                &Destination::from(target),
                Ladder::global(),
            );
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client
            .read_exact(&mut back)
            .expect("echoes through a withheld response");
        assert_eq!(&back, b"ping");
        drop(client);
        server.join().expect("joins");
        relaying.join().expect("joins");
    }

    /// The edge has to see the name the client was given: a client that looks it up first sends an address for a host it never kept, and the lookup itself is visible to whoever watches its resolver.
    #[test]
    fn vless_sends_the_destination_name_to_the_edge() {
        const HOST: &str = "www.example.com";
        let id = [0x26u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 23];
            stream.read_exact(&mut head).expect("reads a vless header");
            assert_eq!(&head[1..17], &id[..], "the user");
            assert_eq!(&head[17..19], &[0, 1][..], "no addons, a connect");
            assert_eq!(&head[19..21], &8443u16.to_be_bytes()[..], "the port");
            assert_eq!(head[21], 2, "the domain family, not a resolved address");
            assert_eq!(head[22] as usize, HOST.len(), "and its whole length");
            let mut name = vec![0u8; HOST.len()];
            stream.read_exact(&mut name).expect("reads the name");
            assert_eq!(name, HOST.as_bytes());
            let mut payload = [0u8; 4];
            stream
                .read_exact(&mut payload)
                .expect("reads the payload of a named target");
            stream.write_all(&[0, 0]).expect("answers");
            stream.write_all(&payload).expect("echoes");
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let vless = VlessOut {
            address: "127.0.0.1".to_owned(),
            port,
            id,
            carrier: Carrier::Raw(Chain::default()),
            host: String::new(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        };
        let asked = Destination::Name(HOST.to_owned(), 8443);
        let relaying = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            dial_vless(&stream, &server_addr, &vless, &asked, Ladder::global());
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client
            .read_exact(&mut back)
            .expect("a named target still round-trips");
        assert_eq!(&back, b"ping");
        drop(client);
        server.join().expect("joins");
        relaying.join().expect("joins");
    }

    /// Two address conventions live in the tree: VLESS and `VMess` number a domain 2 with the port before the address, Trojan and the Shadowsocks family number it 3 with the port after. A writer that picks the other byte hands the edge a header it reads as an address.
    #[test]
    fn each_writer_numbers_a_name_by_its_own_convention() {
        const HOST: &str = "www.example.com";
        let asked = Destination::Name(HOST.to_owned(), 8443);
        assert_eq!(asked.addr_len(), HOST.len() + 2);
        assert_eq!(asked.authority(), "www.example.com:8443");
        let atyp = [2u8, HOST.len() as u8];
        let head = vless_header(&[0x26u8; 16], 1, &asked);
        let tail = head.len() - asked.addr_len();
        assert_eq!(&head[tail..tail + 2], &atyp[..], "vless: family 2");
        assert_eq!(&head[tail + 2..], HOST.as_bytes());
        let atyp = [3u8, HOST.len() as u8];
        let head = trojan_header(&[0x5au8; 56], 1, &asked);
        let tail = head.len() - 4 - asked.addr_len();
        assert_eq!(&head[tail..tail + 2], &atyp[..], "trojan: family 3");
        let mut want = HOST.as_bytes().to_vec();
        want.extend_from_slice(&8443u16.to_be_bytes());
        want.extend_from_slice(b"\r\n");
        assert_eq!(&head[tail + 2..], want, "and the port after the address");
    }

    /// The pump belongs to the carrier, not to the socket: a WebSocket server that holds its `[0, 0]` until the first frame arrives must not deadlock either.
    #[test]
    fn vless_websocket_client_pumps_the_upload_before_reading_the_response() {
        let id = [0x27u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Some((mut reader, writer)) = crate::ws::accept(stream, "/p") else {
                panic!("accepts the upgrade");
            };
            let Some((got, _flow, cmd, _target)) = decode_request(&mut reader) else {
                panic!("reads a vless header");
            };
            assert_eq!(got, id);
            assert_eq!(cmd, 1);
            let mut payload = [0u8; 4];
            read_exact(&mut reader, &mut payload).expect("reads payload before answering");
            assert!(writer.send(&[0, 0]), "answers");
            assert!(writer.send(&payload), "echoes");
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let vless = VlessOut {
            address: "127.0.0.1".to_owned(),
            port,
            id,
            carrier: Carrier::Ws {
                path: "/p".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        };
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let relaying = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            dial_vless(
                &stream,
                &server_addr,
                &vless,
                &Destination::from(target),
                Ladder::global(),
            );
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client
            .read_exact(&mut back)
            .expect("echoes through a withheld answer");
        assert_eq!(&back, b"ping");
        drop(client);
        server.join().expect("joins");
        relaying.join().expect("joins");
    }

    /// The pump belongs to the carrier, and REALITY is a carrier: a REALITY server that holds its `[0, 0]` until the first payload record arrives must not deadlock the client either.
    #[test]
    fn vless_reality_client_pumps_the_upload_before_reading_the_response() {
        let id = uuid_bytes(REALITY_TEST_ID).expect("id");
        let server_config = reality_server_config();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let server_addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let edges = reality_edges(&server_config, &stream);
            let Ok(ferrox_core::tls::RealityAccept::Session(mut session)) =
                ferrox_core::tls::RealityServer::accept(
                    &server_config,
                    unix_millis(),
                    stream,
                    edges,
                )
            else {
                panic!("the peer handshakes, it is not proxied to the cover origin");
            };
            assert!(shake_tls(&mut session), "handshakes");
            let Some((got, _flow, cmd, _target)) = decode_request(&mut session) else {
                panic!("reads a vless header");
            };
            assert_eq!(got, id);
            assert_eq!(cmd, 1);
            let mut payload = [0u8; 4];
            read_exact(&mut session, &mut payload).expect("reads payload before answering");
            session.write_all(&[0, 0]).expect("answers");
            session.write_all(&payload).expect("echoes");
        });
        let public =
            x25519_dalek::x25519(REALITY_TEST_PRIVATE, x25519_dalek::X25519_BASEPOINT_BYTES);
        let root = crate::json::parse(&reality_client_json(
            server_addr.port(),
            &b64url(&public),
            "",
        ))
        .expect("parses");
        let Outbound::Vless(vless) = find_outbound(&root).expect("a REALITY outbound") else {
            panic!("the outbound dials VLESS");
        };
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let relaying = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            dial_vless(
                &stream,
                &server_addr,
                &vless,
                &Destination::from(target),
                Ladder::global(),
            );
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client
            .read_exact(&mut back)
            .expect("echoes through a withheld answer");
        assert_eq!(&back, b"ping");
        drop(client);
        server.join().expect("joins");
        relaying.join().expect("joins");
    }

    fn vnext_tls_root(protocol: &str, stream: &str) -> crate::json::Json {
        crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "{protocol}",
                "settings": {{"vnext": [{{"address": "127.0.0.1", "port": 443,
                    "users": [{{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}]}},
                "streamSettings": {{{stream}}}}}]}}"#
        ))
        .expect("parses")
    }

    fn trojan_tls_root(stream: &str) -> crate::json::Json {
        crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "trojan",
                "settings": {{"servers": [{{"address": "127.0.0.1", "port": 443,
                    "password": "secret"}}]}},
                "streamSettings": {{{stream}}}}}]}}"#
        ))
        .expect("parses")
    }

    fn tls_stream_cases(ca_json: &str) -> Vec<(String, String)> {
        vec![
            (
                "raw".to_owned(),
                format!(
                    r#""network": "tcp", "security": "tls", "tlsSettings": {{"serverName": "tls.test", "caCertFile": "{ca_json}", "alpn": ["h2"]}}"#
                ),
            ),
            (
                "ws".to_owned(),
                format!(
                    r#""network": "ws", "security": "tls", "wsSettings": {{"path": "/w"}}, "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
                ),
            ),
            (
                "grpc".to_owned(),
                format!(
                    r#""network": "grpc", "security": "tls", "grpcSettings": {{"serviceName": "svc"}}, "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
                ),
            ),
            (
                "xhttp".to_owned(),
                format!(
                    r#""network": "xhttp", "security": "tls", "xhttpSettings": {{"path": "/share"}}, "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
                ),
            ),
            (
                "httpupgrade".to_owned(),
                format!(
                    r#""network": "httpupgrade", "security": "tls", "httpupgradeSettings": {{"path": "/u"}}, "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
                ),
            ),
            (
                "httpheader".to_owned(),
                format!(
                    r#""network": "tcp", "security": "tls", "tcpSettings": {{"header": {{"type": "http", "request": {{"path": ["/c"]}}}}}}, "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
                ),
            ),
        ]
    }

    fn carrier_tag(carrier: &Carrier) -> &'static str {
        match carrier {
            Carrier::Raw(_) => "raw",
            Carrier::Ws { .. } => "ws",
            Carrier::HttpUpgrade { .. } => "httpupgrade",
            Carrier::Grpc { .. } => "grpc",
            Carrier::Xhttp { .. } => "xhttp",
            Carrier::HttpHeader { .. } => "httpheader",
            _ => "other",
        }
    }

    #[test]
    fn vless_tls_outbound_parses_diallable_carriers() {
        let (ca, ca_json) = stage_ca_pem("vless-tls");
        for (want, stream) in tls_stream_cases(&ca_json) {
            let root = vnext_tls_root("vless", &stream);
            let out = find_vless_outbound(&root).expect("finds {want} tls");
            assert_eq!(carrier_tag(&out.carrier), want, "{want}");
            assert!(out.tls.is_some(), "{want}");
        }
        let tls = find_vless_outbound(&vnext_tls_root("vless", &tls_stream_cases(&ca_json)[0].1))
            .expect("finds raw")
            .tls
            .expect("carries tls");
        assert_eq!(tls.server_name, "tls.test");
        assert_eq!(tls.alpn, vec![b"h2".to_vec()]);
        assert_eq!(tls.roots.len(), 1);
        let insecure = format!(
            r#""network": "tcp", "security": "tls", "tlsSettings": {{"caCertFile": "{ca_json}", "allowInsecure": true}}"#
        );
        assert!(find_vless_outbound(&vnext_tls_root("vless", &insecure)).is_none());
        for network in ["quic", "kcp", "hysteria"] {
            let stream = format!(
                r#""network": "{network}", "security": "tls", "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
            );
            let root = vnext_tls_root("vless", &stream);
            if network == "quic" {
                let out = find_vless_outbound(&root).expect("quic keeps its own dial");
                assert!(matches!(out.carrier, Carrier::Quic));
                assert!(out.tls.is_none());
            } else {
                assert!(find_vless_outbound(&root).is_none(), "{network}");
            }
        }
        let muxed = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "vless", "mux": {{"enabled": true}},
                "settings": {{"vnext": [{{"address": "127.0.0.1", "port": 443,
                    "users": [{{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}]}},
                "streamSettings": {{"network": "tcp", "security": "tls",
                    "tlsSettings": {{"caCertFile": "{ca_json}"}}}}}}]}}"#
        ))
        .expect("parses");
        assert!(find_vless_outbound(&muxed).is_none());
        let _ = std::fs::remove_file(&ca);
    }

    #[test]
    fn trojan_tls_outbound_parses_diallable_carriers() {
        let (ca, ca_json) = stage_ca_pem("trojan-tls");
        for (want, stream) in tls_stream_cases(&ca_json) {
            let root = trojan_tls_root(&stream);
            let out = find_trojan_outbound(&root).expect("finds {want} tls");
            assert_eq!(carrier_tag(&out.carrier), want, "{want}");
            assert!(out.tls.is_some(), "{want}");
        }
        let out = find_trojan_outbound(&trojan_tls_root(&tls_stream_cases(&ca_json)[0].1))
            .expect("finds raw");
        assert_eq!(out.tls.expect("carries tls").server_name, "tls.test");
        for network in ["quic", "kcp", "hysteria"] {
            let stream = format!(
                r#""network": "{network}", "security": "tls", "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
            );
            assert!(
                find_trojan_outbound(&trojan_tls_root(&stream)).is_none(),
                "{network}"
            );
        }
        let plain = crate::json::parse(
            r#"{"outbounds": [{"protocol": "trojan",
                "settings": {"servers": [{"address": "127.0.0.1", "port": 443,
                    "password": "secret"}]},
                "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        let out = find_trojan_outbound(&plain).expect("finds plain");
        assert!(out.tls.is_none());
        let _ = std::fs::remove_file(&ca);
    }

    #[test]
    fn vmess_tls_outbound_parses_diallable_carriers() {
        let (ca, ca_json) = stage_ca_pem("vmess-tls");
        for (want, stream) in tls_stream_cases(&ca_json) {
            let root = vnext_tls_root("vmess", &stream);
            let out = find_vmess_outbound(&root).expect("finds {want} tls");
            assert_eq!(carrier_tag(&out.carrier), want, "{want}");
            assert!(out.tls.is_some(), "{want}");
        }
        for network in ["quic", "kcp", "hysteria"] {
            let stream = format!(
                r#""network": "{network}", "security": "tls", "tlsSettings": {{"caCertFile": "{ca_json}"}}"#
            );
            assert!(
                find_vmess_outbound(&vnext_tls_root("vmess", &stream)).is_none(),
                "{network}"
            );
        }
        let plain = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vmess",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
                    "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
                "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        let out = find_vmess_outbound(&plain).expect("finds plain");
        assert!(out.tls.is_none());
        let _ = std::fs::remove_file(&ca);
    }

    #[test]
    fn vless_over_tls_carries_an_echo() {
        use ferrox_core::tls::TlsProvider as _;

        let (server_config, client_config) = carried_tls_configs();
        let id = [0x44u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            echo_trace(&format!("srv {port} accepted"));
            let mut tls = ferrox_core::tls::accept(&server_config, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            echo_trace(&format!("srv {port} handshook"));
            let Some((got, _flow, cmd, _target)) = decode_request(&mut tls) else {
                panic!("reads a vless header");
            };
            assert_eq!(got, id);
            assert_eq!(cmd, 1);
            echo_trace(&format!("srv {port} header ok"));
            tls.write_all(&[0, 0]).expect("answers");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).expect("reads");
            echo_trace(&format!("srv {port} ping read"));
            tls.write_all(&buf).expect("echoes");
        });
        let downstream = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let dport = downstream.local_addr().expect("addr").port();
        let relay = thread::spawn(move || {
            let (client, _) = downstream.accept().expect("accepts");
            let server: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            let vless = VlessOut {
                address: "127.0.0.1".to_owned(),
                port,
                id,
                carrier: Carrier::Raw(Chain::default()),
                host: String::new(),
                mux: false,
                quic_roots: None,
                hysteria_roots: None,
                tls: Some(Arc::new(client_config)),
                flow: String::new(),
                reality: None,
            };
            echo_trace(&format!("cli {port} dialing"));
            dial_vless(
                &client,
                &server,
                &vless,
                &Destination::from(target),
                Ladder::global(),
            );
            echo_trace(&format!("cli {port} relay over"));
        });
        let mut sock = Connection::connect(("127.0.0.1", dport)).expect("connects");
        sock.set_read_timeout(Some(Duration::from_secs(120)))
            .expect("timeout");
        sock.write_all(b"ping").expect("writes");
        assert_eq!(&read_echo(&mut sock), b"ping");
        drop(sock);
        relay.join().expect("joins");
        server.join().expect("joins");
    }

    #[test]
    fn trojan_over_tls_carries_an_echo() {
        use ferrox_core::tls::TlsProvider as _;

        let (server_config, client_config) = carried_tls_configs();
        let key = trojan_key("an-example-shared-password");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            echo_trace(&format!("srv {port} accepted"));
            let mut tls = ferrox_core::tls::accept(&server_config, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            echo_trace(&format!("srv {port} handshook"));
            let Some((cmd, _target)) = decode_trojan_request(&mut tls, &key) else {
                panic!("reads a trojan header");
            };
            assert_eq!(cmd, 1);
            echo_trace(&format!("srv {port} header ok"));
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).expect("reads");
            echo_trace(&format!("srv {port} ping read"));
            tls.write_all(&buf).expect("echoes");
        });
        let downstream = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let dport = downstream.local_addr().expect("addr").port();
        let relay = thread::spawn(move || {
            let (client, _) = downstream.accept().expect("accepts");
            let server: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            let trojan = TrojanOut {
                address: "127.0.0.1".to_owned(),
                port,
                key,
                carrier: Carrier::Raw(Chain::default()),
                host: String::new(),
                tls: Some(Arc::new(client_config)),
            };
            echo_trace(&format!("cli {port} dialing"));
            dial_trojan(
                &client,
                &server,
                &trojan,
                &Destination::from(target),
                Ladder::global(),
            );
            echo_trace(&format!("cli {port} relay over"));
        });
        let mut sock = Connection::connect(("127.0.0.1", dport)).expect("connects");
        sock.set_read_timeout(Some(Duration::from_secs(120)))
            .expect("timeout");
        sock.write_all(b"ping").expect("writes");
        assert_eq!(&read_echo(&mut sock), b"ping");
        drop(sock);
        relay.join().expect("joins");
        server.join().expect("joins");
    }

    #[test]
    fn vmess_over_tls_carries_an_echo() {
        use ferrox_core::tls::TlsProvider as _;

        let (server_config, client_config) = carried_tls_configs();
        let id = [0x33u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            echo_trace(&format!("srv {port} accepted"));
            let mut tls = ferrox_core::tls::accept(&server_config, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            echo_trace(&format!("srv {port} handshook"));
            let Some((_target, mut send, mut recv, prefix, cmd)) =
                crate::vmess::accept_request(&mut tls, &id)
            else {
                panic!("reads a vmess header");
            };
            assert_eq!(cmd, 1);
            echo_trace(&format!("srv {port} header ok"));
            tls.write_all(&prefix).expect("answers");
            let mut scratch = Vec::with_capacity(16 * 1024);
            let chunk = crate::vmess::read_frame(&mut tls, &mut recv, &mut scratch)
                .expect("reads a frame")
                .to_vec();
            echo_trace(&format!("srv {port} ping read"));
            let mut staging = Vec::with_capacity(16 * 1024);
            let mut pad = crate::vmess::PadSource::fresh().expect("entropy");
            assert!(crate::vmess::write_frame(
                &mut tls,
                &mut send,
                &chunk,
                &mut staging,
                &mut pad
            ));
            echo_trace(&format!("srv {port} echoed vmess"));
        });
        let downstream = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let dport = downstream.local_addr().expect("addr").port();
        let relay = thread::spawn(move || {
            let (client, _) = downstream.accept().expect("accepts");
            let server: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            let vmess = VmessOut {
                address: "127.0.0.1".to_owned(),
                port,
                id,
                cipher: crate::vmess::Cipher::Auto,
                carrier: Carrier::Raw(Chain::default()),
                host: String::new(),
                tls: Some(Arc::new(client_config)),
            };
            echo_trace(&format!("cli {port} dialing"));
            dial_vmess(
                &client,
                &server,
                &vmess,
                &Destination::from(target),
                Ladder::global(),
            );
            echo_trace(&format!("cli {port} relay over"));
        });
        let mut sock = Connection::connect(("127.0.0.1", dport)).expect("connects");
        sock.set_read_timeout(Some(Duration::from_secs(120)))
            .expect("timeout");
        sock.write_all(b"ping").expect("writes");
        assert_eq!(&read_echo(&mut sock), b"ping");
        drop(sock);
        relay.join().expect("joins");
        server.join().expect("joins");
    }

    type ServerHalf = TlsHalf<ferrox_core::tls::RustlsServerProvider<Connection>>;

    /// The relay arms the shared timeout to its own grain, so a quiet socket retries and only a closed one fails.
    fn read_echo(sock: &mut Connection) -> [u8; 4] {
        let start = std::time::Instant::now();
        let mut back = [0u8; 4];
        let mut at = 0;
        while at < back.len() {
            match sock.read(&mut back[at..]) {
                Ok(0) => panic!(
                    "echoes: closed after {:?}; last dial: {:?}",
                    start.elapsed(),
                    last_dial_failure()
                ),
                Ok(n) => at += n,
                Err(error) => {
                    assert!(
                        is_timeout(&error) && start.elapsed() < Duration::from_secs(120),
                        "echoes: {error:?} after {:?}; last dial: {:?}",
                        start.elapsed(),
                        last_dial_failure()
                    );
                }
            }
        }
        back
    }

    enum TlsEcho {
        Vless([u8; 16]),
        Trojan([u8; 56]),
        Vmess([u8; 16]),
    }

    fn tls_carried_echo(
        kind: TlsEcho,
        out: impl FnOnce(u16) -> Outbound + Send + 'static,
        accept: impl FnOnce(ServerHalf, ServerHalf) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>
            + Send
            + 'static,
    ) {
        use ferrox_core::tls::TlsProvider as _;

        let (server_config, _) = carried_tls_configs();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            echo_trace(&format!("srv {port} accepted"));
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept((*server_config).clone(), stream)
                    .expect("accepts");
            tls.handshake().expect("handshakes");
            echo_trace(&format!("srv {port} handshook"));
            let shared = Arc::new(Mutex::new(tls));
            let (mut reader, mut writer) = accept(
                TlsHalf {
                    session: Arc::clone(&shared),
                },
                TlsHalf { session: shared },
            )
            .expect("accepts carrier");
            echo_trace(&format!("srv {port} carrier up"));
            match kind {
                TlsEcho::Vless(id) => {
                    let Some((got, _flow, cmd, _target)) = decode_request(&mut reader) else {
                        panic!("reads a vless header");
                    };
                    assert_eq!(got, id);
                    assert_eq!(cmd, 1);
                    echo_trace(&format!("srv {port} header ok"));
                    writer.write_all(&[0, 0]).expect("answers");
                    echo_trace(&format!("srv {port} response sent"));
                    let mut buf = [0u8; 4];
                    reader.read_exact(&mut buf).expect("reads");
                    echo_trace(&format!("srv {port} ping read"));
                    writer.write_all(&buf).expect("echoes");
                    echo_trace(&format!("srv {port} echoed vless"));
                }
                TlsEcho::Trojan(key) => {
                    let Some((cmd, _target)) = decode_trojan_request(&mut reader, &key) else {
                        panic!("reads a trojan header");
                    };
                    assert_eq!(cmd, 1);
                    echo_trace(&format!("srv {port} header ok"));
                    let mut buf = [0u8; 4];
                    reader.read_exact(&mut buf).expect("reads");
                    echo_trace(&format!("srv {port} ping read"));
                    writer.write_all(&buf).expect("echoes");
                    echo_trace(&format!("srv {port} echoed trojan"));
                }
                TlsEcho::Vmess(id) => {
                    let Some((_target, mut send, mut recv, prefix, cmd)) =
                        crate::vmess::accept_request(&mut reader, &id)
                    else {
                        panic!("reads a vmess header");
                    };
                    assert_eq!(cmd, 1);
                    echo_trace(&format!("srv {port} header ok"));
                    writer.write_all(&prefix).expect("answers");
                    echo_trace(&format!("srv {port} response sent"));
                    let mut scratch = Vec::with_capacity(16 * 1024);
                    let chunk = crate::vmess::read_frame(&mut reader, &mut recv, &mut scratch)
                        .expect("reads a frame")
                        .to_vec();
                    echo_trace(&format!("srv {port} ping read"));
                    let mut staging = Vec::with_capacity(16 * 1024);
                    let mut pad = crate::vmess::PadSource::fresh().expect("entropy");
                    assert!(crate::vmess::write_frame(
                        &mut writer,
                        &mut send,
                        &chunk,
                        &mut staging,
                        &mut pad
                    ));
                    echo_trace(&format!("srv {port} echoed vmess"));
                }
            }
            // Exit only after the client closed: closing with its frames unread resets the echo with it.
            let mut rest = [0u8; 1024];
            while reader.read(&mut rest).unwrap_or(0) != 0 {}
        });
        let downstream = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let dport = downstream.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (client, _) = downstream.accept().expect("accepts");
            let server: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            echo_trace(&format!("cli {port} dialing"));
            dial_socks_outbound(&client, &out(port), &server, &Destination::from(target));
            echo_trace(&format!("cli {port} relay over"));
        });
        let mut sock = Connection::connect(("127.0.0.1", dport)).expect("connects");
        sock.set_read_timeout(Some(Duration::from_secs(120)))
            .expect("timeout");
        sock.write_all(b"ping").expect("writes");
        assert_eq!(&read_echo(&mut sock), b"ping");
    }

    fn tls_vless_out(
        port: u16,
        id: [u8; 16],
        carrier: Carrier,
        tls: ferrox_core::tls::TlsConfig,
    ) -> Outbound {
        Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port,
            id,
            carrier,
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: Some(Arc::new(tls)),
            flow: String::new(),
            reality: None,
        })
    }

    fn tls_vmess_out(
        port: u16,
        id: [u8; 16],
        carrier: Carrier,
        tls: ferrox_core::tls::TlsConfig,
    ) -> Outbound {
        Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port,
            id,
            cipher: crate::vmess::Cipher::Auto,
            carrier,
            host: "127.0.0.1".to_owned(),
            tls: Some(Arc::new(tls)),
        })
    }

    fn tls_trojan_out(
        port: u16,
        key: [u8; 56],
        carrier: Carrier,
        tls: ferrox_core::tls::TlsConfig,
    ) -> Outbound {
        Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port,
            key,
            carrier,
            host: "127.0.0.1".to_owned(),
            tls: Some(Arc::new(tls)),
        })
    }

    fn tls_ws_accept(
        read: ServerHalf,
        write: ServerHalf,
    ) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let (reader, writer) = crate::ws::accept_split(read, write, "/w")?;
        Some((Box::new(reader), Box::new(writer)))
    }

    fn tls_httpupgrade_accept(
        read: ServerHalf,
        write: ServerHalf,
    ) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let (reader, writer) = crate::httpupgrade::accept_split(read, write, "/u")?;
        Some((Box::new(reader), Box::new(writer)))
    }

    fn tls_grpc_accept(
        read: ServerHalf,
        write: ServerHalf,
    ) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let (reader, writer) = crate::grpc::accept_split(read, write, "/Tun")?;
        Some((Box::new(reader), Box::new(writer)))
    }

    fn tls_xhttp_accept(
        read: ServerHalf,
        write: ServerHalf,
    ) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let (reader, writer) =
            crate::xhttp::accept_split_with_settings(read, write, &xhttp_settings("/share"))?;
        Some((Box::new(reader), Box::new(writer)))
    }

    fn tls_httpheader_accept(
        read: ServerHalf,
        write: ServerHalf,
    ) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let (reader, writer) = crate::httpheader::accept_split(read, write, "/c")?;
        Some((Box::new(reader), Box::new(writer)))
    }

    #[test]
    fn vless_over_tls_ws_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x44u8; 16];
        tls_carried_echo(
            TlsEcho::Vless(id),
            move |port| {
                tls_vless_out(
                    port,
                    id,
                    Carrier::Ws {
                        path: "/w".to_owned(),
                        ed: 0,
                    },
                    client_config,
                )
            },
            tls_ws_accept,
        );
    }

    #[test]
    fn production_tls_first_ws_matches_the_seam() {
        let (server_config, client_config) = carried_tls_configs();
        let id = [0x44u8; 16];
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds echo");
        let echo_addr: SocketAddr = echo.local_addr().expect("addr");
        thread::spawn(move || {
            let (mut s, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).expect("reads");
            s.write_all(&buf).expect("echoes");
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless_tls(
                stream,
                &id,
                true,
                &Carrier::Ws {
                    path: "/w".to_owned(),
                    ed: 0,
                },
                &server_config,
            );
        });
        let server: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let session = dial_tls_session(&server, &client_config, None).expect("dialled");
        let header = vless_header(&id, 1, &Destination::from(echo_addr));
        let (mut reader, writer) = tls_ws(&server, session, "127.0.0.1", "/w", 0, &header)
            .expect("handshakes ws inside tls");
        read_vless_response(&mut reader).expect("answers");
        assert!(writer.send(b"ping"), "relays through tls-first ws");
        let mut back = [0u8; 4];
        reader.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn vless_over_tls_httpupgrade_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x45u8; 16];
        tls_carried_echo(
            TlsEcho::Vless(id),
            move |port| {
                tls_vless_out(
                    port,
                    id,
                    Carrier::HttpUpgrade {
                        path: "/u".to_owned(),
                        ed: 0,
                    },
                    client_config,
                )
            },
            tls_httpupgrade_accept,
        );
    }

    #[test]
    fn vless_over_tls_grpc_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x46u8; 16];
        tls_carried_echo(
            TlsEcho::Vless(id),
            move |port| {
                tls_vless_out(
                    port,
                    id,
                    Carrier::Grpc {
                        path: "/Tun".to_owned(),
                    },
                    client_config,
                )
            },
            tls_grpc_accept,
        );
    }

    #[test]
    fn vless_over_tls_xhttp_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x47u8; 16];
        tls_carried_echo(
            TlsEcho::Vless(id),
            move |port| {
                tls_vless_out(
                    port,
                    id,
                    Carrier::Xhttp {
                        settings: xhttp_settings("/share"),
                    },
                    client_config,
                )
            },
            tls_xhttp_accept,
        );
    }

    #[test]
    fn vless_over_tls_httpheader_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x48u8; 16];
        tls_carried_echo(
            TlsEcho::Vless(id),
            move |port| {
                tls_vless_out(
                    port,
                    id,
                    Carrier::HttpHeader {
                        path: "/c".to_owned(),
                    },
                    client_config,
                )
            },
            tls_httpheader_accept,
        );
    }

    #[test]
    fn vmess_over_tls_ws_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x34u8; 16];
        tls_carried_echo(
            TlsEcho::Vmess(id),
            move |port| {
                tls_vmess_out(
                    port,
                    id,
                    Carrier::Ws {
                        path: "/w".to_owned(),
                        ed: 0,
                    },
                    client_config,
                )
            },
            tls_ws_accept,
        );
    }

    #[test]
    fn vmess_over_tls_grpc_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x35u8; 16];
        tls_carried_echo(
            TlsEcho::Vmess(id),
            move |port| {
                tls_vmess_out(
                    port,
                    id,
                    Carrier::Grpc {
                        path: "/Tun".to_owned(),
                    },
                    client_config,
                )
            },
            tls_grpc_accept,
        );
    }

    #[test]
    fn vmess_over_tls_httpupgrade_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x36u8; 16];
        tls_carried_echo(
            TlsEcho::Vmess(id),
            move |port| {
                tls_vmess_out(
                    port,
                    id,
                    Carrier::HttpUpgrade {
                        path: "/u".to_owned(),
                        ed: 0,
                    },
                    client_config,
                )
            },
            tls_httpupgrade_accept,
        );
    }

    #[test]
    fn vmess_over_tls_xhttp_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x37u8; 16];
        tls_carried_echo(
            TlsEcho::Vmess(id),
            move |port| {
                tls_vmess_out(
                    port,
                    id,
                    Carrier::Xhttp {
                        settings: xhttp_settings("/share"),
                    },
                    client_config,
                )
            },
            tls_xhttp_accept,
        );
    }

    #[test]
    fn vmess_over_tls_httpheader_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let id = [0x38u8; 16];
        tls_carried_echo(
            TlsEcho::Vmess(id),
            move |port| {
                tls_vmess_out(
                    port,
                    id,
                    Carrier::HttpHeader {
                        path: "/c".to_owned(),
                    },
                    client_config,
                )
            },
            tls_httpheader_accept,
        );
    }

    #[test]
    fn trojan_over_tls_ws_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let key = trojan_key("an-example-shared-password");
        tls_carried_echo(
            TlsEcho::Trojan(key),
            move |port| {
                tls_trojan_out(
                    port,
                    key,
                    Carrier::Ws {
                        path: "/w".to_owned(),
                        ed: 0,
                    },
                    client_config,
                )
            },
            tls_ws_accept,
        );
    }

    #[test]
    fn trojan_over_tls_grpc_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let key = trojan_key("another-example-password");
        tls_carried_echo(
            TlsEcho::Trojan(key),
            move |port| {
                tls_trojan_out(
                    port,
                    key,
                    Carrier::Grpc {
                        path: "/Tun".to_owned(),
                    },
                    client_config,
                )
            },
            tls_grpc_accept,
        );
    }

    #[test]
    fn trojan_over_tls_httpupgrade_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let key = trojan_key("third-example-password");
        tls_carried_echo(
            TlsEcho::Trojan(key),
            move |port| {
                tls_trojan_out(
                    port,
                    key,
                    Carrier::HttpUpgrade {
                        path: "/u".to_owned(),
                        ed: 0,
                    },
                    client_config,
                )
            },
            tls_httpupgrade_accept,
        );
    }

    #[test]
    fn trojan_over_tls_xhttp_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let key = trojan_key("fourth-example-password");
        tls_carried_echo(
            TlsEcho::Trojan(key),
            move |port| {
                tls_trojan_out(
                    port,
                    key,
                    Carrier::Xhttp {
                        settings: xhttp_settings("/share"),
                    },
                    client_config,
                )
            },
            tls_xhttp_accept,
        );
    }

    #[test]
    fn trojan_over_tls_httpheader_carries_an_echo() {
        let (_, client_config) = carried_tls_configs();
        let key = trojan_key("fifth-example-password");
        tls_carried_echo(
            TlsEcho::Trojan(key),
            move |port| {
                tls_trojan_out(
                    port,
                    key,
                    Carrier::HttpHeader {
                        path: "/c".to_owned(),
                    },
                    client_config,
                )
            },
            tls_httpheader_accept,
        );
    }

    fn stage_ca_pem(name: &str) -> (std::path::PathBuf, String) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["tls.test".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ferrox-{name}-{}-{stamp}.pem", std::process::id()));
        std::fs::write(&path, minted.cert.pem().as_bytes()).expect("stages ca");
        let text = path
            .to_str()
            .expect("ascii")
            .to_owned()
            .replace('\\', "\\\\");
        (path, text)
    }

    #[test]
    fn vmess_outbounds_carry_their_carriers() {
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vmess", "settings": {"vnext": [{"address": "192.0.2.1", "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "security": "chacha20-poly1305"}]}]}, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "host": "oracle.example"}}}]}"#,
        )
        .expect("parses");
        let out = find_vmess_outbound(&root).expect("finds");
        assert!(matches!(out.carrier, Carrier::Xhttp { .. }));
        assert_eq!(out.host, "oracle.example");
        let plain = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vmess", "settings": {"vnext": [{"address": "192.0.2.1", "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]}, "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        let out = find_vmess_outbound(&plain).expect("finds");
        assert!(matches!(out.carrier, Carrier::Raw(_)));
        assert_eq!(out.host, "192.0.2.1");
    }

    // A ladder walk dials one uplink per rung, so a test server serves the bound rather than one connection.
    const LADDER_TEST_UPLINKS: usize = 6;

    #[test]
    fn socks_dials_vmess_over_xhttp_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                crate::vmess::serve_xhttp(stream, "/share", &id, true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Xhttp {
                settings: xhttp_settings("/share"),
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn trojan_outbounds_carry_their_hosts() {
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": "192.0.2.1", "port": 443, "password": "secret"}]}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/tunnel", "host": "oracle.example"}}}]}"#,
        )
        .expect("parses");
        let out = find_trojan_outbound(&root).expect("finds");
        assert!(matches!(out.carrier, Carrier::Ws { .. }));
        assert_eq!(out.host, "oracle.example");
        let plain = crate::json::parse(
            r#"{"outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": "192.0.2.1", "port": 443, "password": "secret"}]}, "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        let out = find_trojan_outbound(&plain).expect("finds");
        assert!(matches!(out.carrier, Carrier::Raw(_)));
        assert_eq!(out.host, "192.0.2.1");
    }

    #[test]
    fn trojan_over_ws_reaches_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_trojan_ws(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let uplink = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (mut reader, writer) =
            crate::ws::connect(uplink, "oracle.example", "/tunnel", 0, &[]).expect("upgrades");
        let mut header = Vec::new();
        header.extend_from_slice(&trojan_key("secret"));
        header.extend_from_slice(b"\r\n");
        header.push(1);
        push_addr(
            &mut header,
            &SocketAddr::new(std::net::IpAddr::V4([127, 0, 0, 1].into()), echo_port),
            4,
        );
        header.extend_from_slice(&echo_port.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        assert!(writer.send(&header));
        assert!(writer.send(b"ping"));
        let mut back = [0u8; 4];
        reader.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    fn socks_dials_ss_via(
        carrier: Carrier,
        serve: fn(Connection, &str, &str, &str, bool),
        path: &str,
        key: (&str, &str),
    ) {
        let (method, password) = (key.0.to_owned(), key.1.to_owned());
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        let owned = path.to_owned();
        let (served_method, served_password) = (method.clone(), password.clone());
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                serve(stream, &served_password, &served_method, &owned, true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Shadowsocks(ShadowsocksOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            method,
            password,
            carrier,
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_ss_over_ws_to_echo() {
        socks_dials_ss_via(
            Carrier::Ws {
                path: "/ss-ws".to_owned(),
                ed: 0,
            },
            crate::shadowsocks::serve_ws,
            "/ss-ws",
            ("aes-256-gcm", "an-example-shared-password"),
        );
    }

    #[test]
    fn socks_dials_ss_over_httpupgrade_to_echo() {
        socks_dials_ss_via(
            Carrier::HttpUpgrade {
                path: "/ss-upgrade".to_owned(),
                ed: 0,
            },
            crate::shadowsocks::serve_httpupgrade,
            "/ss-upgrade",
            ("aes-256-gcm", "an-example-shared-password"),
        );
    }

    /// The dial, not the carrier: this server waits for the request packet's first byte before it answers, so a rung that held the packet back would stall in `read_head` and the SOCKS client would never be served.
    #[test]
    fn socks_dials_ss_over_httpupgrade_with_early_data_to_echo() {
        socks_dials_ss_via(
            Carrier::HttpUpgrade {
                path: "/ss-upgrade".to_owned(),
                ed: 64,
            },
            crate::shadowsocks::serve_httpupgrade_answering_after_the_request,
            "/ss-upgrade",
            ("aes-256-gcm", "an-example-shared-password"),
        );
    }

    /// The other family on the same rung: the seal-into-a-buffer path is written twice, so both keys have to reach a dial.
    #[test]
    fn socks_dials_ss2022_over_httpupgrade_with_early_data_to_echo() {
        socks_dials_ss_via(
            Carrier::HttpUpgrade {
                path: "/ss-upgrade".to_owned(),
                ed: 64,
            },
            crate::shadowsocks2022::serve_httpupgrade,
            "/ss-upgrade",
            (
                "2022-blake3-aes-256-gcm",
                &ferrox_core::b64::encode(&[0x42u8; 32]),
            ),
        );
    }

    #[test]
    fn socks_dials_ss_over_grpc_to_echo() {
        socks_dials_ss_via(
            Carrier::Grpc {
                path: "/TunnelService/Tun".to_owned(),
            },
            crate::shadowsocks::serve_grpc,
            "/TunnelService/Tun",
            ("aes-256-gcm", "an-example-shared-password"),
        );
    }

    #[test]
    fn socks_dials_ss_over_xhttp_to_echo() {
        socks_dials_ss_via(
            Carrier::Xhttp {
                settings: xhttp_settings("/ss-xhttp"),
            },
            crate::shadowsocks::serve_xhttp,
            "/ss-xhttp",
            ("aes-256-gcm", "an-example-shared-password"),
        );
    }

    #[test]
    fn socks_dials_ss_over_httpheader_to_echo() {
        socks_dials_ss_via(
            Carrier::HttpHeader {
                path: "/ss-camouflage".to_owned(),
            },
            crate::shadowsocks::serve_httpheader,
            "/ss-camouflage",
            ("aes-256-gcm", "an-example-shared-password"),
        );
    }

    #[test]
    fn udp_frames_carry_every_length() {
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = tunnel.accept().expect("accepts");
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                match read_udp_datagram(&mut stream, &mut buf) {
                    Some(n) => {
                        if !write_udp_datagram(&mut stream, &buf[..n]) {
                            return;
                        }
                    }
                    None => return,
                }
            }
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        for len in [1usize, 64, 512, 1460, 8192, 32768, 65535] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert!(write_udp_datagram(&mut stream, &payload), "len {len}");
            let mut buf = vec![0u8; UDP_BUF];
            assert_eq!(
                read_udp_datagram(&mut stream, &mut buf),
                Some(len),
                "len {len}"
            );
            assert_eq!(&buf[..len], &payload[..], "len {len}");
        }
        assert!(write_udp_datagram(&mut stream, &[]));
        let congestion: Vec<u8> = (0..64).map(|i| (i % 251) as u8).collect();
        assert!(write_udp_datagram(&mut stream, &congestion));
        let mut buf = vec![0u8; UDP_BUF];
        assert_eq!(read_udp_datagram(&mut stream, &mut buf), Some(64));
        assert_eq!(&buf[..64], &congestion[..]);
    }

    #[test]
    fn socks_udp_datagrams_split_and_reject() {
        for addr in [
            "127.0.0.1:53".parse().expect("addr"),
            "[::1]:443".parse().expect("addr"),
        ] {
            let mut packet = vec![0u8, 0, 0];
            push_socks_addr(&mut packet, &addr);
            packet.extend_from_slice(b"ping");
            let (got, payload) = parse_socks_udp(&packet).expect("splits");
            assert_eq!(got, addr);
            assert_eq!(payload, b"ping");
        }
        let mut fragged = vec![0u8, 0, 1, 1, 127, 0, 0, 1, 0, 53];
        fragged.extend_from_slice(b"ping");
        assert!(parse_socks_udp(&fragged).is_none());
        assert!(parse_socks_udp(&[0, 0, 0]).is_none());
        assert!(parse_socks_udp(&[0, 0, 0, 9, 1, 2, 3]).is_none());
        assert!(parse_socks_udp(&[0, 0, 0, 1, 127, 0, 0]).is_none());
    }

    /// The slice reader must agree with the stream reader on the address and on whether the body parses at all: that identity, over every shape a relayed datagram carries and the forged tails a peer can send, is the gate that dropping the cursor changed nothing but the copies.
    #[test]
    fn the_slice_socks_reader_matches_the_stream_one_byte_for_byte() {
        let domain = |name: &[u8], port: [u8; 2]| {
            let mut v = vec![name.len() as u8];
            v.extend_from_slice(name);
            v.extend_from_slice(&port);
            v
        };
        let cases: Vec<(u8, Vec<u8>)> = vec![
            (1, vec![127, 0, 0, 1, 0, 53]),
            (1, vec![127, 0, 0, 1]),
            (1, vec![10, 0, 0, 1, 0x1f, 0x90, 0xff]),
            (4, vec![0u8; 16]),
            (4, {
                let mut v = vec![0u8; 16];
                v[15] = 1;
                v.extend([0, 53]);
                v
            }),
            (4, vec![0u8; 10]),
            (3, domain(b"localhost", [0, 53])),
            (3, domain(b"", [0, 53])),
            (3, vec![3, b'a', b'b']),
            (9, vec![0, 0]),
            (0, vec![]),
        ];
        for (atyp, body) in cases {
            let mut cursor = std::io::Cursor::new(&body);
            let stream = read_socks_addr_rest(&mut cursor, atyp);
            let stream_used = cursor.position() as usize;
            match (parse_socks_addr_rest(&body, atyp), stream) {
                (Some((got, used)), Some(want)) => {
                    assert_eq!(got, want, "atyp {atyp} address");
                    assert_eq!(used, stream_used, "atyp {atyp} bytes consumed");
                }
                (None, None) => {}
                (got, want) => panic!("atyp {atyp} disagreed: slice {got:?} stream {want:?}"),
            }
        }
    }

    #[test]
    fn vless_udp_reaches_echo_over_raw_tcp() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = Connection::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        stream
            .write_all(&vless_header(&id, 2, &Destination::from(target)))
            .expect("requests");
        assert!(read_vless_response(&mut stream).is_some());
        assert!(write_udp_datagram(&mut stream, b"ping"));
        let mut buf = vec![0u8; UDP_BUF];
        assert_eq!(read_udp_datagram(&mut stream, &mut buf), Some(4));
        assert_eq!(&buf[..4], b"ping");
    }

    #[test]
    fn vless_udp_with_a_flow_is_refused() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = Connection::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut header = vec![0u8];
        header.extend_from_slice(&id);
        header.push(18);
        header.extend_from_slice(b"\x0A\x10xtls-rprx-vision");
        header.push(2);
        header.extend_from_slice(&target.port().to_be_bytes());
        push_addr(&mut header, &target, 3);
        stream.write_all(&header).expect("requests");
        let mut back = [0u8; 2];
        assert!(stream.read_exact(&mut back).is_err());
    }

    /// An outbound with no edges to dial: the association rides nothing, which is exactly what its lifetime budget must cover.
    fn foxy_without_edges() -> FoxyOut {
        FoxyOut {
            account: None,
            country: "US".to_owned(),
            city: String::new(),
            carrier: crate::foxy::Carrier::H2,
            upstream: None,
            candidates: Vec::new(),
            stored: None,
            unauthenticated: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            limited_strikes: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            limited_until: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            carrier_dead: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::Refusals::new(32),
            )),
            edge_strikes: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::EdgeStrikes::new(32),
            )),
            roots: Vec::new(),
            pins: ferrox_core::foxy::pin::Pins::default(),
            pass: ferrox_core::foxy::Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
            edge_address: None,
            direct_ports: Vec::new(),
            direct_suffixes: Vec::new(),
            exit_probe: None,
            verified: std::sync::Arc::new(std::sync::Mutex::new(None)),
            probe_unavailable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            exit_refuted_until: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// The handler's side of a loopback control socket, and the peer side the test can leave.
    fn association_pair() -> (Connection, Connection) {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let peer = Connection::connect(addr).expect("connects");
        let (associate, _) = front.accept().expect("accepts");
        (associate, peer)
    }

    /// Silence past the budget is death, not a leak: a stream-per-destination association with no traffic hands its thread back at the idle budget.
    #[test]
    fn a_quiet_foxy_udp_association_hands_its_thread_back() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let (associate, _peer) = association_pair();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            serve_socks_udp_foxy(&relay, &foxy_without_edges(), &associate);
            let _ = done_tx.send(());
        });
        let returned = done_rx.recv_timeout(Duration::from_millis(250) + Duration::from_secs(5));
        budgets::clear();
        returned.expect("a quiet association ends on its idle budget");
        serving.join().expect("joins");
    }

    /// The client's goodbye outranks the idle budget: an association whose control socket closed hands its thread back at the next tick.
    #[test]
    fn a_foxy_udp_association_ends_when_its_client_leaves() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let (associate, peer) = association_pair();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            serve_socks_udp_foxy(&relay, &foxy_without_edges(), &associate);
            let _ = done_tx.send(());
        });
        drop(peer);
        let returned = done_rx.recv_timeout(Duration::from_secs(5));
        budgets::clear();
        returned.expect("the closed control socket ends the association, not its idle budget");
        serving.join().expect("joins");
    }

    /// The shared tunnel obeys the same lifetime as the per-destination streams: silence past the budget hands the thread back.
    #[test]
    fn a_quiet_foxy_connect_ip_association_hands_its_thread_back() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let (associate, _peer) = association_pair();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            serve_socks_udp_foxy_ip(&relay, &foxy_without_edges(), &associate);
            let _ = done_tx.send(());
        });
        let returned = done_rx.recv_timeout(Duration::from_millis(250) + Duration::from_secs(5));
        budgets::clear();
        returned.expect("a quiet connect-ip association ends on its idle budget");
        serving.join().expect("joins");
    }

    /// And the goodbye outranks the budget here too: no tunnel is left dialled and parked when the app is gone.
    #[test]
    fn a_foxy_connect_ip_association_ends_when_its_client_leaves() {
        let _guard = budgets::lock();
        budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let (associate, peer) = association_pair();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            serve_socks_udp_foxy_ip(&relay, &foxy_without_edges(), &associate);
            let _ = done_tx.send(());
        });
        drop(peer);
        let returned = done_rx.recv_timeout(Duration::from_secs(5));
        budgets::clear();
        returned.expect("the closed control socket ends the tunnel, not its idle budget");
        serving.join().expect("joins");
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_vless() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source, target);
        assert_eq!(payload, b"ping");
    }

    /// A freedom hop carries streams not datagrams, so QUIC datagrams take the plain dial, as in `foxy-relay.yml`.
    #[test]
    fn socks_associate_over_a_freedom_hop_reaches_an_udp_echo() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &Outbound::Freedom);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source, target);
        assert_eq!(payload, b"ping");
    }

    #[test]
    fn trojan_udp_frames_carry() {
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = tunnel.accept().expect("accepts");
            let mut buf = vec![0u8; UDP_BUF];
            let mut head = Vec::with_capacity(32);
            loop {
                match read_trojan_datagram(&mut stream, &mut buf) {
                    Some((dest, n)) => {
                        if !write_trojan_datagram(&mut stream, &dest, &buf[..n], &mut head) {
                            return;
                        }
                    }
                    None => return,
                }
            }
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let v4: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut head = Vec::with_capacity(32);
        assert!(write_trojan_datagram(&mut stream, &v4, b"ping", &mut head));
        let mut buf = vec![0u8; UDP_BUF];
        let (dest, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
        assert_eq!(dest, v4);
        assert_eq!(&buf[..n], b"ping");
        assert!(write_trojan_datagram(&mut stream, &v4, &[], &mut head));
        let wide: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        assert!(write_trojan_datagram(&mut stream, &v4, &wide, &mut head));
        let mut buf = vec![0u8; UDP_BUF];
        let (dest, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
        assert_eq!(dest, v4);
        assert_eq!(&buf[..n], &wide[..]);
        let mut domain = vec![3u8, 9];
        domain.extend_from_slice(b"localhost");
        domain.extend_from_slice(&53u16.to_be_bytes());
        domain.extend_from_slice(&4u16.to_be_bytes());
        domain.extend_from_slice(b"\r\n");
        domain.extend_from_slice(b"ping");
        stream.write_all(&domain).expect("writes");
        let mut buf = vec![0u8; UDP_BUF];
        let (dest, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
        assert_eq!(dest.port(), 53);
        assert!(dest.ip().is_loopback());
        assert_eq!(&buf[..n], b"ping");
    }

    #[test]
    fn trojan_udp_frames_reject_damage() {
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = tunnel.accept().expect("accepts");
            let mut buf = vec![0u8; UDP_BUF];
            while read_trojan_datagram(&mut stream, &mut buf).is_some() {}
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        stream.write_all(b"\x07bad-separator").expect("writes");
        let mut buf = vec![0u8; UDP_BUF];
        assert!(read_trojan_datagram(&mut stream, &mut buf).is_none());
    }

    #[test]
    fn serve_trojan_udp_relays_datagrams() {
        fn echo() -> u16 {
            let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
            let port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                let mut buf = vec![0u8; UDP_BUF];
                loop {
                    let Ok((n, src)) = echo.recv_from(&mut buf) else {
                        return;
                    };
                    if echo.send_to(&buf[..n], src).is_err() {
                        return;
                    }
                }
            });
            port
        }
        let first = echo();
        let second = echo();
        let key = trojan_key("secret");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan(stream, &key, true);
        });
        let mut stream = Connection::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let target: SocketAddr = format!("127.0.0.1:{first}").parse().expect("addr");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(b"\r\n");
        header.push(3);
        push_addr(&mut header, &target, 4);
        header.extend_from_slice(&target.port().to_be_bytes());
        header.extend_from_slice(b"\r\n");
        stream.write_all(&header).expect("requests");
        let mut head = Vec::with_capacity(32);
        for (port, word) in [(first, b"ping".as_slice()), (second, b"pong".as_slice())] {
            let dest: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            assert!(write_trojan_datagram(&mut stream, &dest, word, &mut head));
            let mut buf = vec![0u8; UDP_BUF];
            let (source, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
            assert_eq!(source.port(), dest.port());
            assert_eq!(source.ip().to_canonical(), dest.ip().to_canonical());
            assert_eq!(&buf[..n], word);
        }
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_trojan() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan(stream, &trojan_key("secret"), true);
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source.port(), target.port());
        assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
        assert_eq!(payload, b"ping");
    }

    #[test]
    fn vmess_udp_reaches_echo_over_raw_tcp() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let id = [0x5au8; 16];
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            crate::vmess::serve(stream, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = Connection::connect(("127.0.0.1", tunnel_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let Some((request, mut send, mut recv, response_key, response_iv, auth)) =
            crate::vmess::client_request(
                &id,
                crate::vmess::Cipher::Chacha,
                &Destination::from(target),
                2,
            )
        else {
            panic!("handshake refused");
        };
        uplink.write_all(&request).expect("requests");
        assert!(crate::vmess::read_response(
            &mut uplink,
            &response_key,
            &response_iv,
            auth
        ));
        let Some(mut pad) = crate::vmess::PadSource::fresh() else {
            panic!("no entropy");
        };
        let mut staging = Vec::with_capacity(UDP_BUF);
        let mut scratch = Vec::with_capacity(UDP_BUF);
        assert!(crate::vmess::write_frame(
            &mut uplink,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let back = crate::vmess::read_frame(&mut uplink, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_vmess() {
        fn echo() -> u16 {
            let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
            let port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                let mut buf = vec![0u8; UDP_BUF];
                loop {
                    let Ok((n, src)) = echo.recv_from(&mut buf) else {
                        return;
                    };
                    if echo.send_to(&buf[..n], src).is_err() {
                        return;
                    }
                }
            });
            port
        }
        let first = echo();
        let second = echo();
        let id = [0x5au8; 16];
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(2) {
                let Ok(stream) = stream else {
                    continue;
                };
                thread::spawn(move || crate::vmess::serve(stream, &id, true));
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        for (port, word) in [(first, b"ping".as_slice()), (second, b"pong".as_slice())] {
            let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let mut datagram = vec![0u8, 0, 0];
            push_socks_addr(&mut datagram, &target);
            datagram.extend_from_slice(word);
            udp.send_to(&datagram, relay).expect("sends");
            let mut back = vec![0u8; UDP_BUF];
            let (n, _) = udp.recv_from(&mut back).expect("echoes");
            let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
            assert_eq!(source.port(), target.port());
            assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
            assert_eq!(payload, word);
        }
    }

    #[test]
    fn shadowsocks_udp_reaches_echo() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let front = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let password = "an-example-shared-password";
        thread::spawn(move || {
            crate::shadowsocks::serve_udp_on(&front, password, "aes-256-gcm", true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let master = ferrox_core::shadowsocks::MasterKey::new(password, 32);
        let method = ferrox_core::shadowsocks::Method::Aes256Gcm;
        let mut wire = vec![0u8; crate::shadowsocks::DATAGRAM_MAX];
        let at = crate::shadowsocks::SEAL_ROOM;
        wire[at..at + 4].copy_from_slice(b"ping");
        let mut hop = None;
        let packet =
            crate::shadowsocks::seal_datagram(&master, method, &target, &mut wire, at, 4, &mut hop)
                .expect("seals")
                .to_vec();
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            assert!(attempts <= 15, "no echo after {attempts} fresh sockets");
            let dial = UdpSocket::bind("127.0.0.1:0").expect("binds");
            dial.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let mut back = vec![0u8; UDP_BUF];
            let mut echoed = None;
            for _ in 0..3 {
                if dial
                    .send_to(&packet, format!("127.0.0.1:{front_port}"))
                    .is_err()
                {
                    break;
                }
                if let Ok((n, _)) = dial.recv_from(&mut back) {
                    echoed = Some(n);
                    break;
                }
            }
            let Some(n) = echoed else {
                continue;
            };
            let (source, payload) =
                crate::shadowsocks::open_datagram(&master, method, &mut back[..n], &mut hop)
                    .expect("opens");
            assert_eq!(source.port(), target.port());
            assert_eq!(payload, b"ping");
            return;
        }
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_shadowsocks() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        // Bound here: a datagram that reaches the port before its bind gets ICMP unreachable.
        let tunnel = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            crate::shadowsocks::serve_udp_on(
                &tunnel,
                "an-example-shared-password",
                "aes-256-gcm",
                true,
            );
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Shadowsocks(ShadowsocksOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            method: "aes-256-gcm".to_owned(),
            password: "an-example-shared-password".to_owned(),
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source.port(), target.port());
        assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
        assert_eq!(payload, b"ping");
    }

    fn mux_test_echo() -> u16 {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buf) else {
                            return;
                        };
                        if read == 0 || stream.write_all(&buf[..read]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    fn mux_test_send(
        stream: &mut Connection,
        frame: ferrox_core::mux::Outgoing<'_>,
        data: Option<&[u8]>,
    ) {
        let mut buf = vec![0u8; frame.frame_len(data.map_or(0, <[u8]>::len))];
        let n = frame.encode_into(data, &mut buf);
        stream.write_all(&buf[..n]).expect("writes");
    }

    fn mux_test_recv_frame(
        stream: &mut Connection,
    ) -> (u16, ferrox_core::mux::Status, Option<SocketAddr>, Vec<u8>) {
        let mut raw = [0u8; 2];
        stream.read_exact(&mut raw).expect("reads");
        let meta_len = usize::from(u16::from_be_bytes(raw));
        let mut meta = vec![0u8; meta_len];
        stream.read_exact(&mut meta).expect("reads");
        let mut whole = raw.to_vec();
        whole.extend_from_slice(&meta);
        if meta.get(3).is_some_and(|options| options & 1 != 0) {
            let mut chunk_len = [0u8; 2];
            stream.read_exact(&mut chunk_len).expect("reads");
            let chunk_n = usize::from(u16::from_be_bytes(chunk_len));
            let mut chunk = vec![0u8; chunk_n];
            stream.read_exact(&mut chunk).expect("reads");
            whole.extend_from_slice(&chunk_len);
            whole.extend_from_slice(&chunk);
        }
        let (frame, _) =
            ferrox_core::mux::decode(&whole, ferrox_core::mux::NewTail::Forward).expect("decodes");
        (
            frame.id,
            frame.status,
            frame.target.and_then(|t| mux_target_addr(&t)),
            frame.data.unwrap_or(&[]).to_vec(),
        )
    }

    fn mux_test_recv(stream: &mut Connection) -> (u16, ferrox_core::mux::Status, Vec<u8>) {
        let (id, status, _, data) = mux_test_recv_frame(stream);
        (id, status, data)
    }

    fn mux_test_target(port: u16) -> ferrox_core::mux::Target<'static> {
        ferrox_core::mux::Target {
            network: ferrox_core::mux::Network::Tcp,
            port,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    fn mux_test_connect(id: &[u8; 16], tunnel_port: u16) -> Connection {
        let mut stream = Connection::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        stream.write_all(&vless_mux_header(id)).expect("requests");
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).expect("replies");
        assert_eq!(response, [0, 0]);
        stream
    }

    fn mux_test_expect_close(stream: &mut Connection) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut probe = [0u8; 64];
        loop {
            match stream.read(&mut probe) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }

    fn mux_test_udp_echo() -> u16 {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        port
    }

    fn mux_test_udp_target(port: u16) -> ferrox_core::mux::Target<'static> {
        ferrox_core::mux::Target {
            network: ferrox_core::mux::Network::Udp,
            port,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    #[test]
    fn mux_udp_relays_datagrams_and_reuses_a_global_id() {
        let echo_port = mux_test_udp_echo();
        let id = [0x5au8; 16];
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut client = mux_test_connect(&id, tunnel_port);
        let identity = [9u8; ferrox_core::mux::GLOBAL_ID];
        let new = ferrox_core::mux::Outgoing {
            id: 7,
            status: ferrox_core::mux::Status::New,
            options: ferrox_core::mux::DATA,
            target: Some(mux_test_udp_target(echo_port)),
            global_id: Some(identity),
        };
        mux_test_send(&mut client, new, Some(b"ping"));
        let (got, status, source, data) = mux_test_recv_frame(&mut client);
        assert_eq!(got, 7);
        assert_eq!(status, ferrox_core::mux::Status::Keep);
        assert_eq!(source.expect("source").port(), echo_port);
        assert_eq!(data, b"ping");
        let keep = ferrox_core::mux::Outgoing {
            id: 7,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: Some(mux_test_udp_target(echo_port)),
            global_id: None,
        };
        mux_test_send(&mut client, keep, Some(b"pong"));
        let (_, _, _, data) = mux_test_recv_frame(&mut client);
        assert_eq!(data, b"pong");
        let again = ferrox_core::mux::Outgoing {
            id: 8,
            status: ferrox_core::mux::Status::New,
            options: ferrox_core::mux::DATA,
            target: Some(mux_test_udp_target(echo_port)),
            global_id: Some(identity),
        };
        mux_test_send(&mut client, again, Some(b"ping"));
        let (closed, status, _, _) = mux_test_recv_frame(&mut client);
        assert_eq!((closed, status), (7, ferrox_core::mux::Status::End));
        let (got, status, _, data) = mux_test_recv_frame(&mut client);
        assert_eq!(got, 8);
        assert_eq!(status, ferrox_core::mux::Status::Keep);
        assert_eq!(data, b"ping");
    }

    #[test]
    fn xudp_frames_match_the_upstream_layout() {
        let target = mux_target_of("203.0.113.7:5000".parse().expect("addr"));
        let new = ferrox_core::mux::Outgoing {
            id: 0,
            status: ferrox_core::mux::Status::New,
            options: ferrox_core::mux::DATA,
            target: Some(target),
            global_id: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        };
        let mut frame = vec![0u8; new.frame_len(4)];
        let written = new.encode_into(Some(b"ping"), &mut frame);
        assert_eq!(
            &frame[..written],
            &[
                0x00, 0x14, 0x00, 0x00, 0x01, 0x01, 0x02, 0x13, 0x88, 0x01, 203, 0, 113, 7, 1, 2,
                3, 4, 5, 6, 7, 8, 0x00, 0x04, b'p', b'i', b'n', b'g'
            ][..]
        );
        let keep = ferrox_core::mux::Outgoing {
            id: 0,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: Some(target),
            global_id: None,
        };
        let mut frame = vec![0u8; keep.frame_len(4)];
        let written = keep.encode_into(Some(b"pong"), &mut frame);
        assert_eq!(
            &frame[..written],
            &[
                0x00, 0x0c, 0x00, 0x00, 0x02, 0x01, 0x02, 0x13, 0x88, 0x01, 203, 0, 113, 7, 0x00,
                0x04, b'p', b'o', b'n', b'g'
            ][..]
        );
    }

    #[test]
    fn socks_associate_reaches_two_udp_targets_over_one_mux_connection() {
        let first = mux_test_udp_echo();
        let second = mux_test_udp_echo();
        let id = [0x5au8; 16];
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        let opens = Arc::new(AtomicU64::new(0));
        let opened = Arc::clone(&opens);
        thread::spawn(move || {
            for stream in tunnel.incoming() {
                let Ok(stream) = stream else {
                    continue;
                };
                opened.fetch_add(1, Ordering::Relaxed);
                thread::spawn(move || serve_vless_raw(stream, &id, true));
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
            mux: true,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        for (port, word) in [(first, b"ping".as_slice()), (second, b"pong".as_slice())] {
            let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let mut datagram = vec![0u8, 0, 0];
            push_socks_addr(&mut datagram, &target);
            datagram.extend_from_slice(word);
            udp.send_to(&datagram, relay).expect("sends");
            let mut back = vec![0u8; UDP_BUF];
            let (n, _) = udp.recv_from(&mut back).expect("echoes");
            let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
            assert_eq!(source.port(), target.port());
            assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
            assert_eq!(payload, word);
        }
        assert_eq!(
            opens.load(Ordering::Relaxed),
            1,
            "one carrier connection carries every target"
        );
    }

    #[test]
    fn mux_serve_demuxes_two_sessions() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let first = mux_test_echo();
        let second = mux_test_echo();
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = mux_test_connect(&id, tunnel_port);
        let new7 = ferrox_core::mux::Outgoing {
            id: 7,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(mux_test_target(first)),
            global_id: None,
        };
        let new9 = ferrox_core::mux::Outgoing {
            id: 9,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(mux_test_target(second)),
            global_id: None,
        };
        mux_test_send(&mut stream, new7, None);
        mux_test_send(&mut stream, new9, None);
        let keep = |id: u16| ferrox_core::mux::Outgoing {
            id,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: None,
            global_id: None,
        };
        mux_test_send(&mut stream, keep(7), Some(b"ping"));
        mux_test_send(&mut stream, keep(9), Some(b"pong"));
        let end = |id: u16| ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
        mux_test_send(&mut stream, end(7), None);
        let mut first_echo = Vec::new();
        let mut second_echo = Vec::new();
        let mut saw_end = false;
        for _ in 0..8 {
            let (got, status, payload) = mux_test_recv(&mut stream);
            match (got, status) {
                (7, ferrox_core::mux::Status::Keep) => first_echo.extend_from_slice(&payload),
                (9, ferrox_core::mux::Status::Keep) => second_echo.extend_from_slice(&payload),
                (7, ferrox_core::mux::Status::End) => {
                    saw_end = true;
                }
                other => panic!("unexpected frame {other:?}"),
            }
            if first_echo.len() >= 4 && second_echo.len() >= 4 && saw_end {
                break;
            }
        }
        assert_eq!(first_echo, b"ping");
        assert_eq!(second_echo, b"pong");
        assert!(saw_end);
    }

    #[test]
    fn mux_serve_refuses_unknown_and_malformed() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let echo_port = mux_test_echo();
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = mux_test_connect(&id, tunnel_port);
        let stray = ferrox_core::mux::Outgoing::bare(77, ferrox_core::mux::Status::Keep, 0);
        mux_test_send(&mut stream, stray, None);
        let live = ferrox_core::mux::Outgoing {
            id: 5,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(ferrox_core::mux::Target {
                network: ferrox_core::mux::Network::Tcp,
                port: echo_port,
                addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
            }),
            global_id: None,
        };
        mux_test_send(&mut stream, live, None);
        let keep = ferrox_core::mux::Outgoing {
            id: 5,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: None,
            global_id: None,
        };
        mux_test_send(&mut stream, keep, Some(b"ping"));
        let mut got = Vec::new();
        for _ in 0..4 {
            let (frame_id, frame_status, payload) = mux_test_recv(&mut stream);
            if frame_id == 5 && frame_status == ferrox_core::mux::Status::Keep {
                got.extend_from_slice(&payload);
                if got.len() >= 4 {
                    break;
                }
            }
        }
        assert_eq!(got, b"ping");
        stream.write_all(&[0, 9]).expect("writes");
        stream.write_all(b"\x09unknown-id").expect("writes");
        mux_test_expect_close(&mut stream);
    }

    /// Pointer identity is the only test that can see the copy: a staged payload delivers the same bytes.
    #[cfg(unix)]
    #[test]
    fn a_two_part_write_hands_the_payload_over_by_pointer() {
        let header = [0xAAu8; 12];
        let payload: Vec<u8> = (0..1400).map(|i| (i as u8) ^ 0x3C).collect();
        let parts = two_iovecs(&header, &payload);
        assert_eq!(parts[0].iov_base, header.as_ptr() as *mut libc::c_void);
        assert_eq!(
            parts[1].iov_base,
            payload.as_ptr() as *mut libc::c_void,
            "the payload must be the writev part itself, not a copy of it"
        );
        assert_eq!(parts[1].iov_len, 1400);
    }

    /// The XUDP uplink hands its datagram over as the frame header plus the relay's own read
    /// buffer, and those two parts are the frame the single-buffer encoder writes. A staged payload
    /// passes the byte half and fails the pointer half, and only the pointer half can see the copy.
    #[test]
    fn xudp_uplink_hands_the_payload_over_by_pointer() {
        let target = mux_target_of("198.51.100.7:5353".parse().expect("addr"));
        let frame = ferrox_core::mux::Outgoing {
            id: 4,
            status: ferrox_core::mux::Status::New,
            options: ferrox_core::mux::DATA,
            target: Some(target),
            global_id: Some([3u8; ferrox_core::mux::GLOBAL_ID]),
        };
        let payload: Vec<u8> = (0..1400).map(|i| (i as u8) ^ 0x21).collect();
        let mut header = Vec::with_capacity(64);
        let (head, body) = xudp_datagram(&frame, &mut header, &payload);
        assert_eq!(
            body.as_ptr(),
            payload.as_ptr(),
            "the payload must be the writev part itself, not a copy of it"
        );
        assert_eq!(body.len(), payload.len());
        assert_eq!(
            head.len(),
            2 + frame.meta_len() + 2,
            "the head is the metadata and the payload length"
        );

        let mut whole = vec![0u8; frame.frame_len(payload.len())];
        let n = frame.encode_into(Some(&payload), &mut whole);
        let mut joined = head.to_vec();
        joined.extend_from_slice(body);
        assert_eq!(joined, whole[..n], "two parts, one frame");
    }

    /// The framer keeps the mux uplink's rule: a payload longer than the two-byte length field is refused, not wrapped.
    #[test]
    #[should_panic(expected = "mux chunk longer than a length field")]
    fn an_xudp_datagram_longer_than_a_frame_is_refused_not_truncated() {
        let frame = ferrox_core::mux::Outgoing::bare(
            4,
            ferrox_core::mux::Status::Keep,
            ferrox_core::mux::DATA,
        );
        let mut header = Vec::with_capacity(64);
        let big = vec![0u8; ferrox_core::mux::CHUNK_MAX + 1];
        let _ = xudp_datagram(&frame, &mut header, &big);
    }

    /// What a downlink batch reached the sink with: the call shape, which a byte test cannot see.
    #[derive(Default)]
    struct RunSink {
        calls: Vec<(usize, Vec<(usize, usize)>)>,
        out: Vec<u8>,
    }

    impl Write for RunSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.calls
                .push((1, vec![(buf.as_ptr() as usize, buf.len())]));
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn write_vectored(&mut self, parts: &[IoSlice<'_>]) -> std::io::Result<usize> {
            self.calls.push((
                parts.len(),
                parts
                    .iter()
                    .map(|part| (part.as_ptr() as usize, part.len()))
                    .collect(),
            ));
            let mut wrote = 0;
            for part in parts {
                self.out.extend_from_slice(part);
                wrote += part.len();
            }
            Ok(wrote)
        }
    }

    /// Four frames read at once reach the socket as one vectored call whose segments sit where the
    /// frames put them. A write per frame is four calls; a staged batch moves the segments back to
    /// back, so the offsets are what tell the two apart.
    #[test]
    fn a_mux_downlink_hands_a_batch_of_frames_over_in_one_call() {
        let id = 7u16;
        let payloads: [&[u8]; 4] = [b"ping", b"pong-and-more", b"", b"last"];
        let mut wire = Vec::new();
        let mut offsets = Vec::new();
        let keep = ferrox_core::mux::Status::Keep;
        for (i, payload) in payloads.iter().enumerate() {
            if i == 2 {
                let stray = ferrox_core::mux::Outgoing {
                    id: id + 1,
                    status: keep,
                    options: ferrox_core::mux::DATA,
                    target: None,
                    global_id: None,
                };
                let mut frame = vec![0u8; stray.frame_len(4)];
                let n = stray.encode_into(Some(b"nope"), &mut frame);
                wire.extend_from_slice(&frame[..n]);
            }
            let frame = ferrox_core::mux::Outgoing {
                id,
                status: keep,
                options: ferrox_core::mux::DATA,
                target: None,
                global_id: None,
            };
            let mut buf = vec![0u8; frame.frame_len(payload.len())];
            let n = frame.encode_into(Some(payload), &mut buf);
            offsets.push(wire.len() + n - payload.len());
            wire.extend_from_slice(&buf[..n]);
        }

        let mut source = std::io::Cursor::new(wire);
        let mut sink = RunSink::default();
        assert!(
            !mux_downlink(&mut source, &mut sink, id),
            "no End frame, so the caller keeps its half open"
        );
        assert_eq!(
            sink.calls.len(),
            1,
            "one write for the whole read, not one per frame"
        );
        // An empty payload is nothing to write, so the batch carries a segment per non-empty one.
        let written: Vec<usize> = (0..payloads.len())
            .filter(|&i| !payloads[i].is_empty())
            .collect();
        let (segments, bases) = &sink.calls[0];
        assert_eq!(
            *segments,
            written.len(),
            "one segment per non-empty payload"
        );
        assert_eq!(sink.out, payloads.concat(), "the payloads in arrival order");
        for (segment, i) in written.iter().enumerate() {
            let (base, len) = bases[segment];
            assert_eq!(
                len,
                payloads[*i].len(),
                "segment {segment} is a whole payload"
            );
            assert_eq!(
                base.wrapping_sub(bases[0].0),
                offsets[*i] - offsets[written[0]],
                "segment {segment} is the read buffer at its frame's offset, not a staged copy"
            );
        }
    }

    /// The reply head and the payload leave as two parts. A joined buffer delivers the same
    /// datagram, so pointer identity is the half that tells the two forms apart.
    #[cfg(unix)]
    #[test]
    fn a_udp_reply_hands_the_payload_over_by_pointer() {
        let target: SocketAddr = "198.51.100.7:5353".parse().expect("addr");
        let payload: Vec<u8> = (0..512).map(|i| (i as u8) ^ 0x0f).collect();
        let mut head = Vec::with_capacity(HEAD);
        let (front, tail) = udp_reply_parts(&mut head, &target, &payload);
        assert_eq!(
            tail.as_ptr(),
            payload.as_ptr(),
            "the payload must be the sendmsg part itself, not a copy of it"
        );
        let parts = two_iovecs(front, tail);
        assert_eq!(parts[0].iov_base, front.as_ptr() as *mut libc::c_void);
        assert_eq!(parts[1].iov_base, payload.as_ptr() as *mut libc::c_void);
        assert_eq!(parts[1].iov_len, payload.len());

        let mut joined = front.to_vec();
        joined.extend_from_slice(tail);
        let (got, body) = parse_socks_udp(&joined).expect("the datagram parses back");
        assert_eq!(got, target, "reserved pair, no fragment, then the address");
        assert_eq!(body, &payload[..]);
        assert_eq!(
            front.len(),
            10,
            "three bytes, an ipv4 family, its body and a port"
        );
    }

    /// What a framed write reached the session with: the call shape, which a byte test cannot see.
    #[derive(Default)]
    struct Seam {
        writes: usize,
        calls: Vec<(usize, Vec<usize>)>,
        out: Vec<u8>,
    }

    /// A TLS session that records the seam instead of sealing records: it answers with what it was
    /// handed, so one call per frame and the caller's own buffer bases are both observable.
    #[derive(Clone, Default)]
    struct CountedSession {
        seam: Arc<Mutex<Seam>>,
    }

    impl Read for CountedSession {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no peer",
            ))
        }
    }

    impl Write for CountedSession {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut seam = self.seam.lock().expect("records");
            seam.writes += 1;
            seam.out.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ferrox_core::tls::TlsProvider for CountedSession {
        fn name() -> &'static str
        where
            Self: Sized,
        {
            "counted"
        }

        fn suites(&self) -> Vec<String> {
            Vec::new()
        }

        fn handshake(&mut self) -> Result<(), ferrox_core::tls::TlsError> {
            Ok(())
        }

        fn alpn(&self) -> Option<&[u8]> {
            None
        }
    }

    impl ferrox_core::tls::RecordAlignment for CountedSession {
        fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
            let mut seam = self.seam.lock().expect("records");
            let bases = parts.iter().map(|part| part.as_ptr() as usize).collect();
            seam.calls.push((parts.len(), bases));
            for part in parts {
                seam.out.extend_from_slice(part);
            }
            Ok(())
        }
    }

    /// One frame reaches a TLS session in one call whose segments are the caller's buffers: a write
    /// per part sealed one record each, and staging the frame would deliver the same bytes by copy.
    #[test]
    fn a_frame_reaches_the_tls_session_in_one_call() {
        let seam = Arc::new(Mutex::new(Seam::default()));
        let (_reader, mut writer) = session_halves(CountedSession {
            seam: Arc::clone(&seam),
        });
        let body: Vec<u8> = (0..1400).map(|i| (i as u8) ^ 0x5A).collect();
        let tail: Vec<u8> = (0..64).map(|i| !i).collect();

        assert!(
            crate::h2::write_frame(&mut writer, crate::h2::T_DATA, 0, 7, &body),
            "a DATA frame of head and body is written"
        );
        let head = crate::h2::frame_head(body.len() + tail.len(), crate::h2::T_DATA, 0, 8);
        assert!(writer.write_slices(&[&head, &body[..], &tail[..]]));

        let seam = seam.lock().expect("records");
        assert_eq!(
            seam.writes, 0,
            "no part left the seam as a write of its own"
        );
        assert_eq!(seam.calls.len(), 2, "one call for each frame");
        assert_eq!(seam.calls[0].0, 2, "head and body");
        assert_eq!(seam.calls[1].0, 3, "head, first and second");
        assert_eq!(
            seam.calls[0].1[1],
            body.as_ptr() as usize,
            "the payload segment is the caller's buffer, not a copy of it"
        );
        assert_eq!(seam.calls[1].1[1], body.as_ptr() as usize);
        assert_eq!(seam.calls[1].1[2], tail.as_ptr() as usize);

        let mut want = Vec::new();
        want.extend_from_slice(&[0u8, 5, 0x78, crate::h2::T_DATA, 0, 0, 0, 0, 7]);
        want.extend_from_slice(&body);
        want.extend_from_slice(&[0u8, 5, 0xb8, crate::h2::T_DATA, 0, 0, 0, 0, 8]);
        want.extend_from_slice(&body);
        want.extend_from_slice(&tail);
        assert_eq!(seam.out, want, "the same bytes, in the same order");
    }

    /// A two-byte length must never truncate, so an oversize payload is a panic, not a wrap.
    #[test]
    #[should_panic(expected = "mux chunk longer than a length field")]
    fn a_relay_payload_longer_than_a_frame_is_refused_not_truncated() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let stream = Connection::connect(("127.0.0.1", port)).expect("dials");
        let shared = Arc::new(Mutex::new(stream));
        let keep = ferrox_core::mux::Outgoing {
            id: 1,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: None,
            global_id: None,
        };
        let mut staging = Vec::new();
        let big = vec![0u8; ferrox_core::mux::CHUNK_MAX + 1];
        let _ = write_mux_frame(&shared, &mut staging, keep, Some(&big));
    }

    /// The gate is the wire: a built-once header and an uncopied payload yield the single-buffer encoder's frames.
    #[test]
    fn the_mux_uplink_frames_every_relay_read_the_same_way() {
        for total in [1usize, 15, 16, 1400, 8192, 8193, 20_000] {
            let payload: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_mul(7)).collect();

            let upstream = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let upstream_port = upstream.local_addr().expect("addr").port();
            let server = thread::spawn(move || {
                let (mut sock, _) = upstream.accept().expect("accepts");
                let mut seen = Vec::new();
                let mut buf = vec![0u8; 32 * 1024];
                while let Ok(n) = sock.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                }
                seen
            });

            let mut uplink = Connection::connect(("127.0.0.1", upstream_port)).expect("dials");
            let client = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let client_port = client.local_addr().expect("addr").port();
            let sent = payload.clone();
            let writer = thread::spawn(move || {
                let mut sock = Connection::connect(("127.0.0.1", client_port)).expect("connects");
                sock.write_all(&sent).expect("writes");
                sock.shutdown(Shutdown::Write).ok();
            });
            let (plain, _peer) = client.accept().expect("accepts");

            let id = 7u16;
            mux_dial_uplink(&plain, &mut uplink, id);

            let wire = server.join().expect("joins");
            writer.join().expect("joins");

            let mut out = Vec::new();
            let mut frames = 0usize;
            let mut at = 0usize;
            while at < wire.len() {
                let (frame, used) =
                    ferrox_core::mux::decode(&wire[at..], ferrox_core::mux::NewTail::Forward)
                        .expect("a frame decodes");
                at += used;
                assert_eq!(frame.id, id, "total {total}");
                let Some(data) = frame.data else {
                    assert_eq!(
                        frame.status,
                        ferrox_core::mux::Status::End,
                        "total {total}: only the End frame carries no payload"
                    );
                    break;
                };
                assert_eq!(
                    frame.status,
                    ferrox_core::mux::Status::Keep,
                    "total {total}"
                );
                out.extend_from_slice(data);
                frames += 1;
            }
            assert_eq!(out, payload, "total {total}: the relayed bytes differ");
            assert!(frames >= 1, "total {total}: no frames");
        }
    }

    #[test]
    fn socks_dials_vless_mux_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
            mux: true,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn trojan_over_ws_rejects_a_wrong_password() {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_trojan_ws(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let uplink = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (mut reader, writer) =
            crate::ws::connect(uplink, "oracle.example", "/tunnel", 0, &[]).expect("upgrades");
        let mut header = Vec::new();
        header.extend_from_slice(&trojan_key("wrong"));
        header.extend_from_slice(b"\r\n");
        header.push(1);
        header.extend_from_slice(&[1, 127, 0, 0, 1]);
        header.extend_from_slice(&8080u16.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        assert!(writer.send(&header));
        let mut back = [0u8; 4];
        assert!(reader.read_exact(&mut back).is_err());
    }

    #[test]
    fn socks_dials_vmess_over_ws_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                crate::vmess::serve_ws(stream, "/tunnel", &id, true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Ws {
                path: "/tunnel".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_vmess_over_httpupgrade_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                crate::vmess::serve_httpupgrade(stream, "/tunnel", &id, true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::HttpUpgrade {
                path: "/tunnel".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_vmess_over_grpc_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                crate::vmess::serve_grpc(stream, "/TunnelService/Tun", &id, true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Grpc {
                path: "/TunnelService/Tun".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_ws_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                serve_trojan_ws(stream, &trojan_key("secret"), "/tunnel", true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Ws {
                path: "/tunnel".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_httpupgrade_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                serve_trojan_httpupgrade(stream, &trojan_key("secret"), "/tunnel", true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::HttpUpgrade {
                path: "/tunnel".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_grpc_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                serve_trojan_grpc(stream, &trojan_key("secret"), "/Tun", true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Grpc {
                path: "/Tun".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_xhttp_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                serve_trojan_xhttp(stream, &trojan_key("secret"), "/tunnel", true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Xhttp {
                settings: xhttp_settings("/tunnel"),
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_httpheader_to_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(LADDER_TEST_UPLINKS) {
                let Ok(stream) = stream else { continue };
                serve_trojan_httpheader(stream, &trojan_key("secret"), "/tunnel", true);
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::HttpHeader {
                path: "/tunnel".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
            tls: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn quic_carrier_is_named_not_raw() {
        let plain = crate::json::parse(r#"{"network":"quic"}"#).expect("parses");
        assert!(matches!(stream_carrier(Some(&plain)), Carrier::Quic));
        let masked =
            crate::json::parse(r#"{"network":"quic","tcpSettings":{"header":{"type":"http"}}}"#)
                .expect("parses");
        assert!(matches!(stream_carrier(Some(&masked)), Carrier::Quic));
        assert!(matches!(stream_carrier(None), Carrier::Raw(_)));
    }

    /// The `streamSettings` the two pinned interop rows write, in both number and string spellings.
    const FRAGMENT: &str = r#"{"network":"tcp","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":[11,37],"delays":[0],"maxSplit":24}}]}}"#;
    const FRAGMENT_STRINGS: &str = r#"{"network":"tcp","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["11","37"],"delays":["0"],"maxSplit":"24"}}]}}"#;

    /// A chain read from the config all the way to the wire: the record headers a real socket write
    /// leaves behind, for either spelling of the same ranges.
    #[test]
    fn a_configured_fragment_chain_cuts_the_hello_on_the_wire() {
        for doc in [FRAGMENT, FRAGMENT_STRINGS] {
            let settings = crate::json::parse(doc).expect("parses");
            let carrier = stream_carrier(Some(&settings));
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let address = listener.local_addr().expect("address");
            let mut stream = Connection::connect(address)
                .expect("connects")
                .with_mask(carrier.tcp_mask());
            let (mut peer, _) = listener.accept().expect("accepts");
            let mut hello = vec![22, 3, 1];
            hello.extend_from_slice(&300u16.to_be_bytes());
            hello.extend((0..300).map(|i| i as u8));
            stream.write_all(&hello).expect("writes");
            // Eleven octets, then the last configured width, and one header per record but the first.
            let mut wire = vec![0u8; hello.len() + 8 * 5];
            peer.read_exact(&mut wire).expect("reads every record");
            let (widths, body) = hello_records(&wire);
            assert_eq!(
                widths,
                vec![11, 37, 37, 37, 37, 37, 37, 37, 30],
                "the widths the config names, the last clamped to the body's end"
            );
            assert_eq!(body, hello[5..], "and the hello arrives whole");
        }
    }

    /// What a peer's record walk finds: the width of each record and the message between them.
    fn hello_records(wire: &[u8]) -> (Vec<usize>, Vec<u8>) {
        let mut widths = Vec::new();
        let mut body = Vec::new();
        let mut at = 0;
        while at < wire.len() {
            assert_eq!(wire[at], 22, "every piece is a handshake record");
            let len = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
            widths.push(len);
            body.extend_from_slice(&wire[at + 5..at + 5 + len]);
            at += 5 + len;
        }
        (widths, body)
    }

    /// The splice lanes address the descriptor, so a leg that ends on a masked stream has to keep the
    /// buffered copy: on linux this is the difference between cut records and one raw write.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_masked_destination_is_not_fed_by_splice() {
        let settings = crate::json::parse(FRAGMENT).expect("parses");
        let carrier = stream_carrier(Some(&settings));
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("address");
        let source = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let mut feeder = Connection::connect(source.local_addr().expect("address")).expect("dials");
        let (mut from, _) = source.accept().expect("accepts the feeder");
        let mut to = Connection::connect(address)
            .expect("connects")
            .with_mask(carrier.tcp_mask());
        let (mut peer, _) = listener.accept().expect("accepts");
        let mut hello = vec![22, 3, 1];
        hello.extend_from_slice(&300u16.to_be_bytes());
        hello.extend((0..300).map(|i| i as u8));
        feeder.write_all(&hello).expect("feeds");
        feeder.shutdown(Shutdown::Write).expect("ends the source");
        copy_all(&mut from, &mut to);
        let mut wire = vec![0u8; hello.len() + 8 * 5];
        peer.read_exact(&mut wire).expect("reads every record");
        let (widths, body) = hello_records(&wire);
        assert!(widths.len() > 1, "the chain cut the write, not the socket");
        assert_eq!(body, hello[5..], "and the hello still arrives whole");
    }

    /// A chain this tree cannot arm is refused by name, never dialled or served in the clear.
    #[test]
    fn a_tcp_mask_this_tree_cannot_arm_is_refused() {
        let fragment = r#"{"type":"fragment","settings":{"packets":"tlshello","lengths":[11]}}"#;
        let refused = [
            r#"{"network":"tcp","finalmask":{"tcp":[{"type":"sudoku","settings":{}}]}}"#,
            r#"{"network":"tcp","finalmask":{"tcp":[{"type":"header-custom","settings":{}}]}}"#,
            r#"{"network":"tcp","finalmask":{"tcp":[{"type":"xmc","settings":{}}]}}"#,
            // A chain belongs to the tcp connection; a carrier riding another transport has nowhere to arm it.
            r#"{"network":"ws","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":[11]}}]}}"#,
            // The old header masquerade shares the connection the chain would cut.
            &format!(
                r#"{{"network":"tcp","tcpSettings":{{"header":{{"type":"http","request":{{"path":"/x"}}}}}},"finalmask":{{"tcp":[{fragment}]}}}}"#
            ),
            // A window starting at 0 is every write, which the reference refuses outright.
            r#"{"network":"tcp","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"0-5","lengths":[11]}}]}}"#,
            // A last width entry of 0 is a piece that never advances.
            r#"{"network":"tcp","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":[11,0]}}]}}"#,
            // A fragment naming no width at all is the reference's zero range.
            r#"{"network":"tcp","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}}"#,
            r#"{"network":"tcp","finalmask":{"tcp":[{}]}}"#,
            r#"{"network":"tcp","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"nonsense","lengths":[11]}}]}}"#,
        ];
        for doc in refused {
            let settings = crate::json::parse(doc).expect("parses");
            assert!(
                matches!(stream_carrier(Some(&settings)), Carrier::Unknown { .. }),
                "{doc} must be refused"
            );
        }
        // An empty tcp list is no chain at all, and a bare width list is a chain this tree does arm.
        let empty =
            crate::json::parse(r#"{"network":"tcp","finalmask":{"tcp":[]}}"#).expect("parses");
        let armed = crate::json::parse(&format!(
            r#"{{"network":"tcp","finalmask":{{"tcp":[{fragment}]}}}}"#
        ))
        .expect("parses");
        for (settings, want) in [(&empty, false), (&armed, true)] {
            let carrier = stream_carrier(Some(settings));
            assert!(matches!(carrier, Carrier::Raw(_)));
            assert_eq!(carrier.tcp_mask().is_some(), want);
        }
    }

    /// The serving role hands its carrier's chain to the accepted stream; a front with no carrier has
    /// none to give.
    #[test]
    fn a_role_arms_its_carriers_chain() {
        let settings = crate::json::parse(FRAGMENT).expect("parses");
        let role = Role::Trojan {
            key: [0u8; 56],
            carrier: stream_carrier(Some(&settings)),
            freedom: false,
        };
        assert!(role.tcp_mask().is_some(), "a raw carrier arms its chain");
        let bare = Role::Vless {
            id: [0u8; 16],
            carrier: stream_carrier(None),
            freedom: false,
        };
        assert!(
            bare.tcp_mask().is_none(),
            "a carrier with no chain arms nothing"
        );
        assert!(
            Role::Socks {
                out: Outbound::Freedom
            }
            .tcp_mask()
            .is_none(),
            "a front with no carrier arms nothing"
        );
    }

    #[test]
    fn every_upstream_network_name_is_named() {
        let cases = [
            ("ws", "Ws"),
            ("websocket", "Ws"),
            ("httpupgrade", "HttpUpgrade"),
            ("grpc", "Grpc"),
            ("xhttp", "Xhttp"),
            ("splithttp", "Xhttp"),
            ("quic", "Quic"),
            ("kcp", "Kcp"),
            ("mkcp", "Kcp"),
            ("hysteria", "Hysteria"),
            ("masque", "Masque"),
            ("xdrive", "Xdrive"),
            ("raw", "Raw"),
            ("tcp", "Raw"),
            ("h2", "Http"),
            ("h3", "Http"),
            ("http", "Http"),
            ("futureNet", "Unknown"),
        ];
        for (network, want) in cases {
            let doc = crate::json::parse(&format!(r#"{{"network":"{network}"}}"#)).expect("parses");
            let got = stream_carrier(Some(&doc));
            let tag = match &got {
                Carrier::Raw(_) => "Raw",
                Carrier::Ws { .. } => "Ws",
                Carrier::HttpUpgrade { .. } => "HttpUpgrade",
                Carrier::Grpc { .. } => "Grpc",
                Carrier::Xhttp { .. } => "Xhttp",
                Carrier::HttpHeader { .. } => "HttpHeader",
                Carrier::Quic => "Quic",
                Carrier::Kcp(_) => "Kcp",
                Carrier::Hysteria(_) => "Hysteria",
                Carrier::Masque => "Masque",
                Carrier::Xdrive => "Xdrive",
                Carrier::Http => "Http",
                Carrier::Unknown { .. } => "Unknown",
            };
            assert_eq!(tag, want, "{network} should map to {want}");
            if want == "Unknown" {
                let Carrier::Unknown { network: kept } = got else {
                    panic!("a refused network is Unknown");
                };
                assert_eq!(kept, network, "the refusal lost the rejected name");
            }
        }
    }

    /// The production QUIC inbound on loopback: real identity, real driver, real VLESS sessions.
    fn quic_serve_loopback(
        id: [u8; 16],
    ) -> (
        SocketAddr,
        Vec<Vec<u8>>,
        Arc<AtomicBool>,
        thread::JoinHandle<()>,
    ) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let identity = ferrox_core::tls::parse_pem_identity(
            minted.cert.pem().as_bytes(),
            minted.key_pair.serialize_pem().as_bytes(),
        )
        .expect("identity loads");
        let config = crate::quic::serve_config(&identity).expect("serves");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let addr = sock.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let serve: crate::quic::Serve = Arc::new(move |stream| {
            serve_vless_quic(stream, &id, true);
        });
        let driver = thread::spawn(move || {
            let config = Arc::new(Mutex::new(config));
            crate::quic::serve_loop(sock, &config, &serve, &task_stop);
        });
        (addr, roots, stop, driver)
    }

    /// One VLESS round trip over a direct QUIC stream: the same header and response bytes as TCP.
    fn quic_vless_round_trip(
        addr: SocketAddr,
        roots: &[Vec<u8>],
        header: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", addr.port())
            .expect("a socket the server can be addressed from");
        let sock = crate::quic::Datagram::plain(sock);
        let mut conn = crate::quic::handshake_within(
            &sock,
            peer,
            local,
            "localhost",
            roots,
            QUIC_TEST_TIMEOUT,
        )
        .expect("handshakes");
        assert!(crate::quic::send_h3_opening(&mut conn, &sock));
        let deadline = Instant::now() + QUIC_TEST_TIMEOUT;
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, header, false, deadline
        ));
        let response = crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, 2, deadline)
            .expect("accepts");
        assert_eq!(response, vec![0, 0]);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, payload, false, deadline
        ));
        let back =
            crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, payload.len(), deadline)
                .expect("echoes");
        let _ = conn.close(false, 0, b"done");
        crate::quic::flush_egress(&mut conn, &sock);
        back
    }

    #[test]
    fn quic_serves_vless_echo_over_loopback() {
        let _serial = quic_serial();
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 8192];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (addr, roots, stop, driver) = quic_serve_loopback(id);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let header = vless_header(&id, 1, &Destination::from(target));
        let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let back = quic_vless_round_trip(addr, &roots, &header, &payload);
        assert_eq!(back, payload, "bulk arrives whole over a QUIC stream");
        stop.store(true, Ordering::Relaxed);
        driver.join().expect("joins");
    }

    #[test]
    fn quic_serves_two_streams_on_one_connection() {
        let _serial = quic_serial();
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(2) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    loop {
                        let Ok(n) = stream.read(&mut buf) else {
                            return;
                        };
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (addr, roots, stop, driver) = quic_serve_loopback(id);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let header = vless_header(&id, 1, &Destination::from(target));
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", addr.port())
            .expect("a socket the server can be addressed from");
        let sock = crate::quic::Datagram::plain(sock);
        let mut conn = crate::quic::handshake_within(
            &sock,
            peer,
            local,
            "localhost",
            &roots,
            QUIC_TEST_TIMEOUT,
        )
        .expect("handshakes");
        assert!(crate::quic::send_h3_opening(&mut conn, &sock));
        let deadline = Instant::now() + QUIC_TEST_TIMEOUT;
        for stream in [0u64, 4] {
            assert!(crate::quic::stream_send_all(
                &mut conn, &sock, stream, &header, false, deadline
            ));
            let response =
                crate::quic::stream_recv_exact(&mut conn, &sock, local, stream, 2, deadline)
                    .expect("accepts");
            assert_eq!(response, vec![0, 0], "stream {stream} opens");
            let payload = format!("stream {stream} bulk").into_bytes();
            assert!(crate::quic::stream_send_all(
                &mut conn, &sock, stream, &payload, false, deadline
            ));
            let back = crate::quic::stream_recv_exact(
                &mut conn,
                &sock,
                local,
                stream,
                payload.len(),
                deadline,
            )
            .expect("echoes");
            assert_eq!(back, payload, "stream {stream} echoes");
        }
        let _ = conn.close(false, 0, b"done");
        crate::quic::flush_egress(&mut conn, &sock);
        stop.store(true, Ordering::Relaxed);
        driver.join().expect("joins");
    }

    #[test]
    fn quic_server_refuses_wrong_id() {
        let _serial = quic_serial();
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        echo.set_nonblocking(true).expect("nonblocking");
        let echo_port = echo.local_addr().expect("addr").port();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (addr, roots, stop, driver) = quic_serve_loopback(id);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let bad = vless_header(
            &uuid_bytes("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").expect("id"),
            1,
            &Destination::from(target),
        );
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", addr.port())
            .expect("a socket the server can be addressed from");
        let sock = crate::quic::Datagram::plain(sock);
        let mut conn = crate::quic::handshake_within(
            &sock,
            peer,
            local,
            "localhost",
            &roots,
            QUIC_TEST_TIMEOUT,
        )
        .expect("handshakes");
        assert!(crate::quic::send_h3_opening(&mut conn, &sock));
        let deadline = Instant::now() + QUIC_TEST_TIMEOUT;
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, &bad, false, deadline
        ));
        let quick = Instant::now() + Duration::from_secs(10);
        assert!(
            crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, 2, quick).is_none(),
            "a stranger gets no accept"
        );
        assert_eq!(
            echo.accept().expect_err("nothing dials the target").kind(),
            std::io::ErrorKind::WouldBlock
        );
        let _ = conn.close(false, 0, b"done");
        stop.store(true, Ordering::Relaxed);
        driver.join().expect("joins");
    }

    #[test]
    fn quic_inbound_needs_tls() {
        let bare =
            crate::json::parse(r#"{"streamSettings": {"network": "quic", "security": "none"}}"#)
                .expect("parses");
        assert!(quic_inbound_identity(&bare).is_none());
        let tls_bare = crate::json::parse(
            r#"{"streamSettings": {"security": "tls", "tlsSettings": {"certificates": []}}}"#,
        )
        .expect("parses");
        assert!(quic_inbound_identity(&tls_bare).is_none());
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-quic-in-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dirs");
        let cert_path = dir.join("c.crt");
        let key_path = dir.join("c.key");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages");
        std::fs::write(&key_path, minted.key_pair.serialize_pem().as_bytes()).expect("stages");
        let root = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"network": "quic", "security": "tls",
                "tlsSettings": {{"certificates": [{{"certificateFile": "{}", "keyFile": "{}"}}]}}}}}}"#,
            cert_path.to_string_lossy().replace('\\', "\\\\"),
            key_path.to_string_lossy().replace('\\', "\\\\"),
        ))
        .expect("parses");
        assert!(quic_inbound_identity(&root).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quic_tcp_front_closes_without_handshake() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &Carrier::Quic, true);
        });
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut probe = [0u8; 1];
        assert_eq!(client.read(&mut probe).expect("reads"), 0);
    }

    #[test]
    fn quic_dial_udp_uplink_is_none() {
        let relay = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let vless = VlessOut {
            address: "127.0.0.1".to_owned(),
            port: 9,
            id: uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id"),
            carrier: Carrier::Quic,
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        };
        let dest: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let source = Arc::new(Mutex::new(None));
        assert!(dial_udp_uplink(&vless, &dest, &relay, source).is_none());
    }

    #[test]
    fn hysteria_udp_lane_carries_a_datagram() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_udp_lane_once, 3);
    }

    fn hysteria_udp_lane_once() {
        // The client's own uplink, off the socks front: serve_udp reads a framed datagram from the relay socket, puts it on the connection's datagram lane, and the companion reader carries the echo back over the same lane.
        let echo_port = udp_echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("lane-auth", id, "");
        let relay = UdpSocket::bind("127.0.0.1:0").expect("binds");
        // The association reaps on this silence, as the production relay does on `budgets::udp_idle()`.
        relay
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let relay_addr = relay.local_addr().expect("addr");
        let dial = crate::hysteria::Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            config: ferrox_core::hysteria::Config {
                auth: "lane-auth".to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                hop: None,
                gecko: None,
            },
            roots: Some(roots),
        };
        thread::spawn(move || crate::hysteria::serve_udp(&relay, &dial));
        let client = UdpSocket::bind("127.0.0.1:0").expect("binds");
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("timeout");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut datagram = vec![0u8, 0, 0];
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"lane-ping");
        let mut back = vec![0u8; UDP_BUF];
        // The lane's handshake is not paid before the relay reads, so an early datagram is simply resent until the association is up.
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let answer = loop {
            let _ = client.send_to(&datagram, relay_addr);
            match client.recv_from(&mut back) {
                Ok((n, _)) => break n,
                Err(_) if std::time::Instant::now() < deadline => {}
                Err(error) => panic!("echo never returns: {error}"),
            }
        };
        let (source, payload) = parse_socks_udp(&back[..answer]).expect("splits");
        assert_eq!(source, target);
        assert_eq!(payload, b"lane-ping");
    }

    #[test]
    fn the_configured_carrier_owns_the_first_rung() {
        let ladder = Ladder::new();
        let unreachable = Failure::new(Stage::SocketConnected, Kind::Unreachable);
        for rung in [
            Rung::Raw,
            Rung::Ws,
            Rung::Xhttp,
            Rung::Grpc,
            Rung::HttpUpgrade,
        ] {
            assert_eq!(ladder.record_failure(rung, &unreachable), rung.next());
        }
        assert_eq!(ladder.current(), Rung::HttpUpgrade);
        for (carrier, want) in [
            (Carrier::Raw(Chain::default()), Rung::Raw),
            (
                Carrier::Ws {
                    path: "/t".to_owned(),
                    ed: 0,
                },
                Rung::Ws,
            ),
            (
                Carrier::Xhttp {
                    settings: xhttp_settings("/t"),
                },
                Rung::Xhttp,
            ),
            (
                Carrier::Grpc {
                    path: "/t".to_owned(),
                },
                Rung::Grpc,
            ),
            (
                Carrier::HttpUpgrade {
                    path: "/t".to_owned(),
                    ed: 0,
                },
                Rung::HttpUpgrade,
            ),
            (
                Carrier::HttpHeader {
                    path: "/t".to_owned(),
                },
                Rung::Raw,
            ),
        ] {
            assert_eq!(
                ladder_start(&carrier),
                want,
                "{carrier:?} lost the first rung to the ladder"
            );
        }
    }

    #[test]
    fn the_ladder_climbs_past_the_configured_rung_and_relays() {
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        thread::spawn(move || {
            for stream in server.incoming() {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    let mut head = [0u8; 5];
                    loop {
                        match stream.peek(&mut head) {
                            Ok(5) => break,
                            Ok(_) => thread::sleep(Duration::from_millis(1)),
                            Err(_) => return,
                        }
                    }
                    if head != *b"POST " {
                        return;
                    }
                    let Some((mut reader, writer)) = crate::xhttp::accept(stream, "/ladder") else {
                        return;
                    };
                    let Some((got, _flow, cmd, _target)) = decode_request(&mut reader) else {
                        return;
                    };
                    if got != id || cmd != 1 || !writer.send(&[0, 0]) {
                        return;
                    }
                    let mut buf = [0u8; 4096];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if !writer.send(&buf[..n]) {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let ladder = Arc::new(Ladder::new());
        let vless = VlessOut {
            address: "127.0.0.1".to_owned(),
            port,
            id,
            carrier: Carrier::Ws {
                path: "/ladder".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        };
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let dial_ladder = Arc::clone(&ladder);
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            dial_vless(
                &stream,
                &server_addr,
                &vless,
                &Destination::from(target),
                &dial_ladder,
            );
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("timeout");
        client.write_all(b"hello-ladder").expect("writes");
        let mut back = [0u8; 12];
        client.read_exact(&mut back).expect("reads");
        assert_eq!(&back, b"hello-ladder");
        assert_eq!(ladder.current(), Rung::Xhttp);
        assert_eq!(ladder.climbs(), 1);
        assert_eq!(ladder.attempts(Rung::Ws), 1);
        assert_eq!(ladder.attempts(Rung::Xhttp), 1);
        assert_eq!(ladder.useful(Rung::Xhttp), 1);
        assert_eq!(ladder.useful(Rung::Ws), 0);
    }

    const QUIC_TEST_TIMEOUT: Duration = Duration::from_secs(120);

    const QUIC_TEST_POLL: Duration = Duration::from_millis(100);

    fn quic_server_poll(
        sock: &crate::quic::Datagram,
        buf: &mut [u8],
    ) -> Option<(usize, SocketAddr)> {
        sock.set_read_timeout(Some(QUIC_TEST_POLL))
            .expect("timeout");
        match sock.recv_from(buf) {
            Ok(found) => Some(found),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(e) => panic!("server socket died: {e:?}"),
        }
    }

    fn quic_server_idle(
        conn: &mut quiche::Connection,
        sock: &crate::quic::Datagram,
        out: &mut [u8],
    ) {
        conn.on_timeout();
        while let Ok((written, info)) = conn.send(out) {
            sock.send_to(&out[..written], info.to).expect("answers");
        }
    }

    fn quic_server_accept(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        config: &mut quiche::Config,
    ) -> (quiche::Connection, Vec<u8>) {
        let mut buf = [0u8; 1350];
        let mut out = [0u8; 1350];
        let knock_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let (mut conn, peer_scid) = loop {
            assert!(std::time::Instant::now() < knock_deadline, "hears knocking");
            let Some((n, from)) = quic_server_poll(sock, &mut buf) else {
                continue;
            };
            let header = quiche::Header::from_slice(&mut buf[..n], 20).expect("parses");
            if header.ty != quiche::Type::Initial || header.version != quiche::PROTOCOL_VERSION {
                continue;
            }
            let peer_scid = header.scid.as_ref().to_vec();
            let mut scid = [0u8; 16];
            getrandom::getrandom(&mut scid).expect("random");
            let cid = quiche::ConnectionId::from_ref(&scid);
            let mut fresh = quiche::accept(&cid, None, local, from, config).expect("accepts");
            let info = quiche::RecvInfo { from, to: local };
            fresh.recv(&mut buf[..n], info).expect("handshakes");
            while let Ok((written, info)) = fresh.send(&mut out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            break (fresh, peer_scid);
        };
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        while !conn.is_established() {
            if let Some((n, from)) = quic_server_poll(sock, &mut buf) {
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
            } else {
                quic_server_idle(&mut conn, sock, &mut out);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client handshake stalls"
            );
        }
        (conn, peer_scid)
    }

    /// A server config with this certificate, staged in uniquely named temp files quiche reads at load time.
    fn quic_test_config(tag: &str, cert_pem: &[u8], key_pem: &[u8]) -> quiche::Config {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let name = format!("ferrox-quic-{tag}-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{name}.crt"));
        let key_path = std::env::temp_dir().join(format!("{name}.key"));
        std::fs::write(&cert_path, cert_pem).expect("stages cert");
        std::fs::write(&key_path, key_pem).expect("stages key");
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        config.set_max_idle_timeout(crate::quic::IDLE_TIMEOUT_MS);
        config.set_initial_max_data(crate::quic::MAX_DATA);
        config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
        config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
        config
            .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
            .expect("loads chain");
        config
            .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
            .expect("loads key");
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        config
    }

    fn quic_vless_echo_server(
        sock: crate::quic::Datagram,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        expected_header: Vec<u8>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut config = quic_test_config("test", &cert_pem, &key_pem);
            let local = sock.local_addr().expect("addr");
            let (mut conn, _) = quic_server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let mut seen = Vec::new();
            let stream_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
            while seen.len() < expected_header.len() {
                let Some((n, from)) = quic_server_poll(&sock, &mut buf) else {
                    quic_server_idle(&mut conn, &sock, &mut out);
                    assert!(
                        std::time::Instant::now() < stream_deadline,
                        "header never arrives"
                    );
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let mut piece = [0u8; 8192];
                while let Ok((n, _)) = conn.stream_recv(0, &mut piece) {
                    seen.extend_from_slice(&piece[..n]);
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
                assert!(
                    std::time::Instant::now() < stream_deadline,
                    "header never arrives"
                );
            }
            assert_eq!(seen, expected_header);
            assert_eq!(conn.application_proto(), crate::quic::ALPN);
            assert!(
                crate::quic::stream_send_all(&mut conn, &sock, 0, &[0, 0], false, stream_deadline),
                "the accept goes out"
            );
            while let Ok((written, info)) = conn.send(&mut out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            let echo_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
            loop {
                if conn.is_closed() {
                    return;
                }
                let Some((n, from)) = quic_server_poll(&sock, &mut buf) else {
                    quic_server_idle(&mut conn, &sock, &mut out);
                    if std::time::Instant::now() >= echo_deadline {
                        return;
                    }
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let mut piece = [0u8; 8192];
                while let Ok((n, fin)) = conn.stream_recv(0, &mut piece) {
                    if n > 0 {
                        assert!(
                            crate::quic::stream_send_all(
                                &mut conn,
                                &sock,
                                0,
                                &piece[..n],
                                false,
                                echo_deadline
                            ),
                            "the echo goes out"
                        );
                    }
                    if fin {
                        let _ = conn.close(false, 0, b"done");
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
            }
        })
    }

    /// Each field marks the `n`th packet to misbehave; 0 disables it, so the faithful case is the same code path.
    #[derive(Clone, Copy, PartialEq)]
    struct FerryFaults {
        drop: usize,
        duplicate: usize,
        hold: usize,
    }

    const FAITHFUL: FerryFaults = FerryFaults {
        drop: 0,
        duplicate: 0,
        hold: 0,
    };

    /// Loss a loopback socket cannot be requested: 1 in 4 dropped, 1 in 7 doubled, 1 in 5 held.
    const LOSSY: FerryFaults = FerryFaults {
        drop: 4,
        duplicate: 7,
        hold: 5,
    };

    /// The two ends and the addresses they call each other by: one value passed around instead of four.
    struct Pipe {
        client: quiche::Connection,
        server: quiche::Connection,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        header: Vec<u8>,
    }

    /// Carries packets in process: this proves the protocol, the socket test proves sockets.
    struct Ferry {
        faults: FerryFaults,
        carried: usize,
        dropped: usize,
        duplicated: usize,
        reordered: usize,
    }

    impl Ferry {
        fn new(faults: FerryFaults) -> Self {
            Self {
                faults,
                carried: 0,
                dropped: 0,
                duplicated: 0,
                reordered: 0,
            }
        }

        fn deliver(&mut self, pipe: &mut Pipe, bytes: &[u8], to_server: bool) {
            let Pipe {
                client,
                server,
                client_addr,
                server_addr,
                ..
            } = pipe;
            let info = quiche::RecvInfo {
                from: if to_server {
                    *client_addr
                } else {
                    *server_addr
                },
                to: if to_server {
                    *server_addr
                } else {
                    *client_addr
                },
            };
            let mut buf = bytes.to_vec();
            let outcome = if to_server {
                server.recv(&mut buf, info)
            } else {
                client.recv(&mut buf, info)
            };
            // Faithful never fails to hand a packet over; adversarial may drop or reorder, by design.
            assert!(
                !(outcome.is_err() && self.faults == FAITHFUL),
                "a faithful ferry must deliver every packet it carries"
            );
        }

        /// One packet through the faults; a held one is delivered after the round, so it arrives late.
        fn pass(
            &mut self,
            pipe: &mut Pipe,
            bytes: Vec<u8>,
            to_server: bool,
            held: &mut Vec<(Vec<u8>, bool)>,
        ) {
            self.carried += 1;
            let seen = self.carried;
            let hits = |every: usize| every > 0 && seen.is_multiple_of(every);
            if hits(self.faults.drop) {
                self.dropped += 1;
                return;
            }
            if hits(self.faults.hold) {
                held.push((bytes, to_server));
                return;
            }
            let twice = hits(self.faults.duplicate);
            self.deliver(pipe, &bytes, to_server);
            if twice {
                self.duplicated += 1;
                self.deliver(pipe, &bytes, to_server);
            }
        }

        /// Carry, release held, then offer timers: an ack-only round may still owe a retransmission.
        fn run(&mut self, pipe: &mut Pipe) {
            let mut buf = [0u8; 1350];
            let mut out: Vec<(Vec<u8>, bool)> = Vec::new();
            {
                let Pipe { client, server, .. } = pipe;
                for to_server in [true, false] {
                    loop {
                        let sent = if to_server {
                            client.send(&mut buf)
                        } else {
                            server.send(&mut buf)
                        };
                        let Ok((n, _)) = sent else { break };
                        out.push((buf[..n].to_vec(), to_server));
                    }
                }
            }
            let mut held: Vec<(Vec<u8>, bool)> = Vec::new();
            for (bytes, to_server) in out {
                self.pass(pipe, bytes, to_server, &mut held);
            }
            let late = std::mem::take(&mut held);
            self.reordered += late.len();
            for (bytes, to_server) in late {
                self.deliver(pipe, &bytes, to_server);
            }
            let Pipe { client, server, .. } = pipe;
            client.on_timeout();
            server.on_timeout();
        }

        /// One tunnel per stream: header out, `[0, 0]` back, payload echoed, all through the faults.
        fn tunnel(&mut self, pipe: &mut Pipe, stream: u64, payload: &[u8]) {
            let want = pipe.header.len();
            let header = pipe.header.clone();
            pipe.client
                .stream_send(stream, &header, false)
                .expect("opens");
            let mut piece = [0u8; 8192];
            let mut seen = Vec::new();
            for _ in 0..10_000 {
                self.run(pipe);
                {
                    let Pipe { server, .. } = pipe;
                    while let Ok((n, _)) = server.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&piece[..n]);
                    }
                }
                if seen.len() >= want {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(seen, pipe.header, "the header survives the ferry");
            let mut back = Vec::new();
            let mut offered = false;
            for _ in 0..10_000 {
                self.run(pipe);
                if !offered {
                    let Pipe { server, .. } = pipe;
                    offered = server.stream_send(stream, &[0, 0], false).is_ok();
                }
                {
                    let Pipe { client, .. } = pipe;
                    while let Ok((n, _)) = client.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        back.extend_from_slice(&piece[..n]);
                    }
                }
                if back.len() >= 2 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(back, [0, 0], "the accept survives the ferry");
            pipe.client
                .stream_send(stream, payload, false)
                .expect("writes");
            let mut echo = Vec::new();
            let mut pending: Vec<u8> = Vec::new();
            let mut held_back = 0usize;
            for _ in 0..10_000 {
                self.run(pipe);
                {
                    let Pipe { server, .. } = pipe;
                    while let Ok((n, _)) = server.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        pending.extend_from_slice(&piece[..n]);
                    }
                    while held_back < pending.len() {
                        match server.stream_send(stream, &pending[held_back..], false) {
                            Ok(written) if written > 0 => held_back += written,
                            _ => break,
                        }
                    }
                }
                {
                    let Pipe { client, .. } = pipe;
                    while let Ok((n, _)) = client.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        echo.extend_from_slice(&piece[..n]);
                    }
                }
                if echo.len() >= payload.len() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(echo, payload, "the echo survives the ferry");
        }
    }

    fn quic_pipe_endpoints() -> Pipe {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let mut client_config = crate::quic::quiche_config(&roots, None).expect("configures");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let tag = format!("ferrox-quic-pipe-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
        let key_path = std::env::temp_dir().join(format!("{tag}.key"));
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages cert");
        std::fs::write(&key_path, &key_pem).expect("stages key");
        let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        server_config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        server_config.set_initial_max_data(crate::quic::MAX_DATA);
        server_config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
        server_config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
        server_config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
        server_config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
        server_config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
        server_config
            .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
            .expect("loads chain");
        server_config
            .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
            .expect("loads key");
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        let client_addr: SocketAddr = "127.0.0.1:4433".parse().expect("addr");
        let server_addr: SocketAddr = "127.0.0.1:8443".parse().expect("addr");
        let mut ccid = [0u8; 16];
        getrandom::getrandom(&mut ccid).expect("random");
        let ccid = quiche::ConnectionId::from_ref(&ccid);
        let mut client = quiche::connect(
            Some("localhost"),
            &ccid,
            client_addr,
            server_addr,
            &mut client_config,
        )
        .expect("connects");
        let mut first = [0u8; 1350];
        let (n, _) = client.send(&mut first).expect("initial flight");
        let initial = quiche::Header::from_slice(&mut first[..n], 20).expect("parses");
        assert_eq!(initial.ty, quiche::Type::Initial);
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut server = quiche::accept(&scid, None, server_addr, client_addr, &mut server_config)
            .expect("accepts");
        let info = quiche::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        server.recv(&mut first[..n], info).expect("ingests");
        let mut pipe = Pipe {
            client,
            server,
            client_addr,
            server_addr,
            header: vless_header(&id, 1, &Destination::from(target)),
        };
        let mut ferry = Ferry::new(FAITHFUL);
        for _ in 0..1000 {
            ferry.run(&mut pipe);
            if pipe.client.is_established() && pipe.server.is_established() {
                break;
            }
        }
        assert!(pipe.client.is_established() && pipe.server.is_established());
        pipe
    }

    #[test]
    fn quic_pipe_carries_vless_header_and_close() {
        let mut pipe = quic_pipe_endpoints();
        let mut ferry = Ferry::new(FAITHFUL);
        ferry.tunnel(&mut pipe, 0, b"ping");
        ferry.tunnel(&mut pipe, 4, b"pong");
        pipe.client.stream_send(0, &[], true).expect("ends");
        let _ = pipe.client.close(false, 0, b"done");
        for _ in 0..10_000 {
            ferry.run(&mut pipe);
            if pipe.client.is_closed() && pipe.server.is_closed() {
                assert!(!pipe.client.is_timed_out() && !pipe.server.is_timed_out());
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("quic pipe never closed");
    }

    /// P30's gate: two tunnels on one handshake under live faults, with counters proving the faults fired.
    #[test]
    fn quic_pipe_shares_a_handshake_through_a_lossy_ferry() {
        let mut pipe = quic_pipe_endpoints();
        let mut ferry = Ferry::new(LOSSY);
        ferry.tunnel(&mut pipe, 0, b"ping");
        ferry.tunnel(&mut pipe, 4, b"pong");
        assert!(
            ferry.dropped > 0,
            "the ferry dropped nothing, so it proved nothing"
        );
        assert!(ferry.duplicated > 0, "the ferry doubled nothing");
        assert!(ferry.reordered > 0, "the ferry held nothing back");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per quiche event, and each arm's stage line is what names a stall in CI"
    )]
    fn quic_concurrent_echo_server(
        sock: crate::quic::Datagram,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        expected_header: Vec<u8>,
    ) -> thread::JoinHandle<(usize, usize)> {
        thread::spawn(move || {
            let mut config = quic_test_config("multi", &cert_pem, &key_pem);
            let local = sock.local_addr().expect("addr");
            let (mut conn, peer_scid) = quic_server_accept(&sock, local, &mut config);
            crate::quic::qstage(format!(
                "{} t={} accepted",
                local.port(),
                crate::quic::qms()
            ));
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let mut conns = 1usize;
            let mut seen_scids = vec![peer_scid];
            let mut streams: Vec<u64> = Vec::new();
            let mut opening: HashMap<u64, Vec<u8>> = HashMap::new();
            let echo_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
            loop {
                if conn.is_closed() {
                    crate::quic::qstage(format!(
                        "{} t={} server-closed conns={conns} streams={}",
                        local.port(),
                        crate::quic::qms(),
                        streams.len()
                    ));
                    break;
                }
                let Some((n, from)) = quic_server_poll(&sock, &mut buf) else {
                    quic_server_idle(&mut conn, &sock, &mut out);
                    if std::time::Instant::now() >= echo_deadline {
                        crate::quic::qstage(format!(
                            "{} t={} server-bound conns={conns} streams={}",
                            local.port(),
                            crate::quic::qms(),
                            streams.len()
                        ));
                        break;
                    }
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                if let Ok(header) = quiche::Header::from_slice(&mut buf[..n], 20) {
                    if header.ty == quiche::Type::Initial {
                        let scid = header.scid.as_ref().to_vec();
                        if !seen_scids.contains(&scid) {
                            seen_scids.push(scid);
                            conns += 1;
                        }
                        continue;
                    }
                }
                conn.recv(&mut buf[..n], info).expect("drives");
                let mut piece = [0u8; 8192];
                for id in conn.readable().collect::<Vec<u64>>() {
                    if !streams.contains(&id) && !opening.contains_key(&id) {
                        opening.insert(id, Vec::new());
                        crate::quic::qstage(format!(
                            "{} t={} srv-open {id}",
                            local.port(),
                            crate::quic::qms()
                        ));
                    }
                    if let Some(head) = opening.get_mut(&id) {
                        while let Ok((n, _)) = conn.stream_recv(id, &mut piece) {
                            if n == 0 {
                                break;
                            }
                            head.extend_from_slice(&piece[..n]);
                        }
                        if head.len() >= expected_header.len() {
                            assert_eq!(head, &expected_header, "stream opens with VLESS");
                            opening.remove(&id);
                            streams.push(id);
                            assert!(
                                crate::quic::stream_send_all(
                                    &mut conn,
                                    &sock,
                                    id,
                                    &[0, 0],
                                    false,
                                    echo_deadline
                                ),
                                "the accept goes out"
                            );
                            crate::quic::qstage(format!(
                                "{} t={} srv-accept {id}",
                                local.port(),
                                crate::quic::qms()
                            ));
                        }
                        continue;
                    }
                    while let Ok((n, fin)) = conn.stream_recv(id, &mut piece) {
                        if n == 0 && !fin {
                            break;
                        }
                        if n > 0 {
                            assert!(
                                crate::quic::stream_send_all(
                                    &mut conn,
                                    &sock,
                                    id,
                                    &piece[..n],
                                    false,
                                    echo_deadline
                                ),
                                "the echo goes out"
                            );
                            crate::quic::qstage(format!(
                                "{} t={} srv-echo {id} {n}",
                                local.port(),
                                crate::quic::qms()
                            ));
                        }
                        if fin {
                            break;
                        }
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
            }
            (conns, streams.len())
        })
    }

    #[test]
    fn socks_dials_vless_quic_to_echo() {
        let _serial = quic_serial();
        quic_retry_dial(socks_quic_once, 3);
    }

    fn socks_quic_once() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let quic_sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let quic_port = quic_sock.local_addr().expect("addr").port();
        let expected_header = vless_header(&id, 1, &Destination::from(target));
        let server = quic_vless_echo_server(
            quic_sock,
            minted.cert.pem().into_bytes(),
            key_pem,
            expected_header,
        );
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: quic_port,
            id,
            carrier: Carrier::Quic,
            host: "localhost".to_owned(),
            mux: false,
            quic_roots: Some(roots),
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&9u16.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        drop(client);
        server.join().expect("joins");
    }

    #[test]
    fn a_quic_carrier_with_mux_never_dials_the_server_tcp_port() {
        let _serial = quic_serial();
        let id = uuid_bytes("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").expect("id");
        let server_tcp = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        server_tcp.set_nonblocking(true).expect("nonblocking");
        let server_port = server_tcp.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: server_port,
            id,
            carrier: Carrier::Quic,
            host: "localhost".to_owned(),
            mux: true,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        });
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let (handed_back, done) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
            let _ = handed_back.send(());
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&9u16.to_be_bytes());
        client.write_all(&request).expect("connects");
        done.recv_timeout(QUIC_TEST_TIMEOUT)
            .expect("the proxy gave up on the carrier");
        assert_eq!(
            server_tcp
                .accept()
                .expect_err("nothing dials the tcp port")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn quic_outbound_reads_ca_cert_file() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ferrox-quic-ca-{}-{stamp}.pem", std::process::id()));
        std::fs::write(&path, minted.cert.pem().as_bytes()).expect("stages ca");
        let path_text = path.to_str().expect("ascii").to_owned();
        let json_path = path_text.replace('\\', "\\\\");
        let root = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "vless",
                "settings": {{"vnext": [{{"address": "127.0.0.1", "port": 443,
                    "users": [{{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}]}},
                "streamSettings": {{"network": "quic", "security": "tls",
                    "tlsSettings": {{"caCertFile": "{json_path}"}}}}}}]}}"#
        ))
        .expect("parses");
        let out = find_vless_outbound(&root).expect("finds quic+tls");
        assert!(matches!(out.carrier, Carrier::Quic));
        let roots = out.quic_roots.expect("carries anchors");
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let _ = std::fs::remove_file(&path);
        let bare = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
                    "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
                "streamSettings": {"network": "quic", "security": "tls"}}]}"#,
        )
        .expect("parses");
        let out = find_vless_outbound(&bare).expect("finds anchorless quic");
        assert!(out.quic_roots.is_none());
    }
    static QUIC_DIAL_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn quic_serial() -> std::sync::MutexGuard<'static, ()> {
        match QUIC_DIAL_SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn quic_retry_dial(once: fn(), attempts: u32) {
        for _ in 0..attempts.saturating_sub(1) {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(once)).is_ok() {
                return;
            }
        }
        once();
    }

    #[test]
    fn quic_dials_loopback_echo() {
        let _serial = quic_serial();
        quic_retry_dial(quic_loopback_once, 3);
    }

    fn quic_loopback_once() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let expected_header = vless_header(&id, 1, &Destination::from(target));
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let quic_sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let quic_port = quic_sock.local_addr().expect("addr").port();
        let server = quic_vless_echo_server(
            quic_sock,
            minted.cert.pem().into_bytes(),
            key_pem,
            expected_header,
        );
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let dial = crate::quic::QuicDial {
            id,
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: quic_port,
            upstream: None,
            roots: Some(roots),
        };
        let relay = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            crate::quic::dial_pooled(&stream, &dial, &Destination::from(target));
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        drop(client);
        relay.join().expect("joins");
        server.join().expect("joins");
    }

    #[test]
    fn quic_pool_shares_one_connection_between_two_streams() {
        let _serial = quic_serial();
        quic_retry_dial(quic_pool_once, 5);
    }

    fn pool_read(client: &mut Connection, want: [u8; 4], who: &str, port: u16) {
        let mut back = [0u8; 4];
        if let Err(e) = client.read_exact(&mut back) {
            let prefix = format!("{port} ");
            let log = crate::quic::QSTAGES
                .lock()
                .map(|stages| {
                    stages
                        .iter()
                        .filter(|line| line.starts_with(&prefix))
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            panic!("{who} echoes failed: {e:?}\nstages for {port}:\n{log}");
        }
        assert_eq!(back, want, "{who} echo mismatch");
    }

    fn quic_pool_once() {
        if let Ok(mut stages) = crate::quic::QSTAGES.lock() {
            stages.clear();
        }
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let quic_sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let quic_port = quic_sock.local_addr().expect("addr").port();
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let server = quic_concurrent_echo_server(
            quic_sock,
            minted.cert.pem().into_bytes(),
            key_pem,
            vless_header(&id, 1, &Destination::from(target)),
        );
        let dial = crate::quic::QuicDial {
            id,
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: quic_port,
            upstream: None,
            roots: Some(roots),
        };
        let front = Arc::new(crate::conn::test_bind("127.0.0.1:0").expect("binds"));
        let front_port = front.local_addr().expect("addr").port();
        let task = Arc::clone(&front);
        let dialed = dial.clone();
        let relay1 = thread::spawn(move || {
            let (stream, _) = task.accept().expect("accepts");
            crate::quic::dial_pooled(&stream, &dialed, &Destination::from(target));
        });
        let mut client1 = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client1
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client1.write_all(b"ping").expect("writes");
        pool_read(&mut client1, *b"ping", "client1", quic_port);
        let relay2 = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            crate::quic::dial_pooled(&stream, &dial, &Destination::from(target));
        });
        let mut client2 = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client2
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client2.write_all(b"pong").expect("writes");
        pool_read(&mut client2, *b"pong", "client2", quic_port);
        drop(client1);
        drop(client2);
        relay1.join().expect("joins");
        relay2.join().expect("joins");
        let (conns, streams) = server.join().expect("joins");
        assert_eq!(conns, 1, "one UDP association, not two handshakes");
        assert_eq!(streams, 2, "two VLESS sessions on it");
    }

    #[test]
    fn kcp_carries_vless_echo_over_loopback() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let kcp_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let listener =
            ferrox_core::kcp::Listener::bind(kcp_addr, ferrox_core::kcp::Config::default())
                .expect("binds");
        let kcp_port = listener.local_addr().port();
        let server = thread::spawn(move || {
            let conn = listener.accept().expect("accepts");
            serve_vless_kcp(&conn, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let header = vless_header(&id, 1, &Destination::from(target));
        let server_addr: SocketAddr = format!("127.0.0.1:{kcp_port}").parse().expect("addr");
        let conn = ferrox_core::kcp::dial(
            server_addr,
            ferrox_core::kcp::Config::default(),
            ferrox_core::kcp::fresh_conversation(),
        )
        .expect("dials");
        conn.write(&header).expect("writes");
        let mut io = KcpIo {
            conn: Arc::clone(&conn),
        };
        read_vless_response(&mut io).expect("replies");
        conn.write(b"ping").expect("writes");
        conn.set_read_deadline(std::time::Instant::now() + std::time::Duration::from_secs(10));
        let mut back = [0u8; 4];
        let mut at = 0;
        while at < 4 {
            let n = conn.read(&mut back[at..]).expect("echoes");
            if n == 0 {
                break;
            }
            at += n;
        }
        assert_eq!(&back, b"ping");
        conn.close();
        server.join().expect("joins");
    }

    /// One half-lock, two directions: an empty window answers `WouldBlock` in a quantum, not by holding the lock.
    #[test]
    fn a_kcp_read_yields_the_lock_instead_of_wedging_a_shared_relay() {
        let listener = ferrox_core::kcp::Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            ferrox_core::kcp::Config::default(),
        )
        .expect("binds");
        let conn = ferrox_core::kcp::dial(
            listener.local_addr(),
            ferrox_core::kcp::Config::default(),
            ferrox_core::kcp::fresh_conversation(),
        )
        .expect("dials");
        let mut io = KcpIo {
            conn: Arc::clone(&conn),
        };
        let started = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let error = io
            .read(&mut buf)
            .expect_err("an empty window yields rather than blocks");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::WouldBlock,
            "the retryable answer a shared relay continues on"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "it answers within the poll quantum, not the idle timeout"
        );
        conn.close();
    }

    /// A reply that lands after the 20 ms quantum a `KcpIo` handshake leaves behind still reaches the client instead of `IoTimeout` closing the relay; loopback only.
    #[test]
    fn a_stale_handshake_deadline_does_not_drop_a_kcp_reply() {
        let listener = ferrox_core::kcp::Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            ferrox_core::kcp::Config::default(),
        )
        .expect("binds");
        let conn = ferrox_core::kcp::dial(
            listener.local_addr(),
            ferrox_core::kcp::Config::default(),
            ferrox_core::kcp::fresh_conversation(),
        )
        .expect("dials");
        // One byte up front: it is the client's own packet that teaches the peer the return path a later reply rides.
        conn.write(b"Q").expect("uploads");
        let peer = thread::spawn(move || {
            let server = listener.accept().expect("accepts");
            let mut asked = [0u8; 1];
            let mut at = 0;
            while at < 1 {
                server.set_read_deadline(std::time::Instant::now() + Duration::from_secs(5));
                at += server.read(&mut asked[at..]).expect("peer reads");
            }
            thread::sleep(Duration::from_millis(80));
            server.write(b"R").expect("peer sends");
            server
        });
        let sink = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let sink_addr = sink.local_addr().expect("addr");
        let tap = Connection::connect(sink_addr).expect("client connects");
        let closer = tap.try_clone().expect("clones");
        let (tcp, _) = sink.accept().expect("relay accepts");
        // The exact stale state the handshake leaves behind: a deadline already in the past when the download loop first reads.
        conn.set_read_deadline(std::time::Instant::now());
        let reading = thread::spawn(move || {
            let mut tap = tap;
            let mut got = [0u8; 1];
            let read = tap.read(&mut got).expect("the client reads");
            assert_eq!(
                &got[..read],
                b"R",
                "a reply after the quantum must reach the client, not an early eof"
            );
        });
        let relay = Arc::clone(&conn);
        let driving = thread::spawn(move || kcp_relay(&tcp, &relay));
        reading.join().expect("the client's verdict");
        // Closing the client's write lets the relay's upload direction see its eof and finish; closing the connection lets the download leave.
        let _ = closer.shutdown(Shutdown::Write);
        conn.close();
        let server = peer.join().expect("the peer joins");
        server.close();
        let _ = driving.join();
    }

    #[test]
    fn kcp_settings_parse_in_both_casings_with_guarded_fallbacks() {
        let base = ferrox_core::kcp::Config::default();
        let plain = crate::json::parse(r#"{"network":"kcp"}"#).expect("parses");
        assert!(matches!(stream_carrier(Some(&plain)), Carrier::Kcp(cfg) if cfg == base));
        let camel = crate::json::parse(
            r#"{"network":"mkcp","kcpSettings":{"mtu":1400,"tti":20,"uplinkCapacity":10,"downlinkCapacity":50,"cwndMultiplier":2,"maxSendingWindow":1048576}}"#,
        )
        .expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&camel)) else {
            panic!("mkcp names Kcp");
        };
        assert_eq!(cfg.mtu, 1400);
        assert_eq!(cfg.tti, 20);
        assert_eq!(cfg.uplink_capacity, 10);
        assert_eq!(cfg.downlink_capacity, 50);
        assert_eq!(cfg.cwnd_multiplier, 2);
        assert_eq!(cfg.max_sending_window, 1_048_576);
        let snake = crate::json::parse(
            r#"{"network":"kcp","kcpSettings":{"uplink_capacity":7,"downlink_capacity":9,"cwnd_multiplier":3,"max_sending_window":4096}}"#,
        )
        .expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&snake)) else {
            panic!("snake case parses");
        };
        assert_eq!(cfg.uplink_capacity, 7);
        assert_eq!(cfg.downlink_capacity, 9);
        assert_eq!(cfg.cwnd_multiplier, 3);
        assert_eq!(cfg.max_sending_window, 4096);
        let bad = crate::json::parse(
            r#"{"network":"kcp","kcpSettings":{"mtu":10,"tti":0,"uplinkCapacity":7}}"#,
        )
        .expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&bad)) else {
            panic!("bad values still Kcp");
        };
        assert_eq!(cfg.mtu, base.mtu);
        assert_eq!(cfg.tti, base.tti);
        assert_eq!(cfg.uplink_capacity, 7);
        let slow =
            crate::json::parse(r#"{"network":"kcp","kcpSettings":{"tti":5000}}"#).expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&slow)) else {
            panic!("slow tti still Kcp");
        };
        assert_eq!(cfg.tti, base.tti);
    }

    #[test]
    fn hysteria_settings_parse_with_guarded_fallbacks() {
        let plain = crate::json::parse(r#"{"network":"hysteria"}"#).expect("parses");
        let Carrier::Hysteria(cfg) = stream_carrier(Some(&plain)) else {
            panic!("hysteria names Hysteria");
        };
        assert_eq!(cfg.auth, "");
        assert_eq!(cfg.cc, ferrox_core::hysteria::Congestion::Bbr);
        let full = crate::json::parse(
            r#"{"network":"hysteria","hysteriaSettings":{"auth":"s3","congestion":"reno","version":2}}"#,
        )
        .expect("parses");
        let Carrier::Hysteria(cfg) = stream_carrier(Some(&full)) else {
            panic!("full settings parse");
        };
        assert_eq!(cfg.auth, "s3");
        assert_eq!(cfg.cc, ferrox_core::hysteria::Congestion::Reno);
        let brutal = crate::json::parse(
            r#"{"network":"hysteria","hysteriaSettings":{"congestion":"force-brutal","version":"2"}}"#,
        )
        .expect("parses");
        let Carrier::Hysteria(cfg) = stream_carrier(Some(&brutal)) else {
            panic!("string version parses");
        };
        assert_eq!(cfg.cc, ferrox_core::hysteria::Congestion::Brutal);
        let old = crate::json::parse(r#"{"network":"hysteria","hysteriaSettings":{"version":1}}"#)
            .expect("parses");
        assert!(matches!(
            stream_carrier(Some(&old)),
            Carrier::Unknown { .. }
        ));
    }

    fn hysteria_loop_with(auth: &str, id: [u8; 16], obfs: &str) -> (u16, Vec<Vec<u8>>) {
        hysteria_loop_masq(auth, id, obfs, ferrox_core::hysteria::Masquerade::NotFound)
    }

    /// Brings up a hysteria inbound on a free port with the given masquerade cover, so a test can point a browser at it and read what the cover answers.
    fn hysteria_loop_masq(
        auth: &str,
        id: [u8; 16],
        obfs: &str,
        masq: ferrox_core::hysteria::Masquerade,
    ) -> (u16, Vec<Vec<u8>>) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let tag = format!("ferrox-hysteria-test-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
        let key_path = std::env::temp_dir().join(format!("{tag}.key"));
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages cert");
        std::fs::write(&key_path, &key_pem).expect("stages key");
        let probe = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let address = format!("127.0.0.1:{port}");
        let auths = vec![auth.to_owned()];
        let obfs = obfs.to_owned();
        let serve: crate::hysteria::Serve = Arc::new(move |flow| {
            serve_vless_hysteria(flow, &id, true);
        });
        let (cert_path, key_path) = (
            cert_path.to_str().expect("ascii").to_owned(),
            key_path.to_str().expect("ascii").to_owned(),
        );
        thread::spawn(move || {
            crate::hysteria::serve_loop(
                &address,
                &auths,
                ferrox_core::hysteria::Congestion::Bbr,
                &cert_path,
                &key_path,
                &obfs,
                &masq,
                &serve,
            );
        });
        (port, roots)
    }

    fn hysteria_tcp_pair(
        port: u16,
        roots: Vec<Vec<u8>>,
        auth: &str,
        id: [u8; 16],
        target: SocketAddr,
        obfs: &str,
    ) -> Connection {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let dial = crate::hysteria::Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            config: ferrox_core::hysteria::Config {
                auth: auth.to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
                obfs_password: obfs.to_owned(),
                hop: None,
                gecko: None,
            },
            roots: Some(roots),
        };
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            crate::hysteria::dial_vless(&stream, &dial, &id, &Destination::from(target));
        });
        let client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client
    }

    fn hysteria_test_server_config(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> quiche::Config {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        config.set_max_idle_timeout(crate::quic::IDLE_TIMEOUT_MS);
        config.set_initial_max_data(crate::quic::MAX_DATA);
        config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
        config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
        config
            .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
            .expect("loads chain");
        config
            .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
            .expect("loads key");
        config
    }

    fn hysteria_test_answer_auth(
        conn: &mut quiche::Connection,
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        out: &mut [u8; 1350],
    ) -> Vec<u8> {
        let mut buf = [0u8; 1350];
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let mut head = Vec::new();
        loop {
            assert!(std::time::Instant::now() < deadline, "auth never arrives");
            let Some((n, from)) = quic_server_poll(sock, &mut buf) else {
                quic_server_idle(conn, sock, out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            let mut piece = [0u8; 4096];
            while let Ok((n, _)) = conn.stream_recv(0, &mut piece) {
                head.extend_from_slice(&piece[..n]);
            }
            while let Ok((written, info)) = conn.send(out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            let mut at = 0usize;
            if let Some(frame) = ferrox_core::foxy::frames::h3_frame(&head, &mut at) {
                if frame.kind == ferrox_core::foxy::frames::H3_HEADERS {
                    if let Some(body) = head.get(at..at + frame.length as usize) {
                        return body.to_vec();
                    }
                }
            }
        }
    }

    fn hysteria_test_read_prefix(
        conn: &mut quiche::Connection,
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        out: &mut [u8; 1350],
    ) -> Vec<u8> {
        let mut buf = [0u8; 1350];
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let mut prefix = Vec::new();
        loop {
            assert!(std::time::Instant::now() < deadline, "flow never arrives");
            let Some((n, from)) = quic_server_poll(sock, &mut buf) else {
                quic_server_idle(conn, sock, out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            let mut piece = [0u8; 4096];
            while let Ok((n, _)) = conn.stream_recv(4, &mut piece) {
                prefix.extend_from_slice(&piece[..n]);
            }
            while let Ok((written, info)) = conn.send(out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            if prefix.len() >= 2 {
                return prefix.split_off(2);
            }
        }
    }

    #[test]
    fn hysteria_client_passes_a_hand_rolled_server() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_client_once, 3);
    }

    fn hysteria_client_once() {
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let tag = format!("ferrox-hysteria-bisect-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
        let key_path = std::env::temp_dir().join(format!("{tag}.key"));
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages cert");
        std::fs::write(&key_path, &key_pem).expect("stages key");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut config = hysteria_test_server_config(&cert_path, &key_path);
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let (mut conn, _) = quic_server_accept(&sock, local, &mut config);
            let mut out = [0u8; 1350];
            let body = hysteria_test_answer_auth(&mut conn, &sock, local, &mut out);
            assert!(
                ferrox_core::hysteria::verify_auth_request(&body, "bisect-auth"),
                "auth verifies"
            );
            let mut block = Vec::new();
            ferrox_core::hysteria::build_auth_response(true, &mut block);
            let mut frame = Vec::new();
            ferrox_core::foxy::frames::quic_varint(
                &mut frame,
                ferrox_core::foxy::frames::H3_HEADERS,
            );
            ferrox_core::foxy::frames::quic_varint(&mut frame, block.len() as u64);
            frame.extend_from_slice(&block);
            conn.stream_send(0, &frame, true).expect("answers");
            while let Ok((written, info)) = conn.send(&mut out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            let rest = hysteria_test_read_prefix(&mut conn, &sock, local, &mut out);
            let flow = crate::hysteria::Flow::from_parts(
                Arc::new(Mutex::new(conn)),
                Arc::new(sock),
                local,
                4,
                rest,
                true,
            );
            serve_vless_hysteria(flow, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let dial = crate::hysteria::Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            config: ferrox_core::hysteria::Config {
                auth: "bisect-auth".to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                hop: None,
                gecko: None,
            },
            roots: Some(roots),
        };
        let Some(session) = crate::hysteria::connect(&dial) else {
            panic!("client connects");
        };
        let header = vless_header(&id, 1, &Destination::from(target));
        let Some(mut flow) = crate::hysteria::open_flow(&session, 4, &header) else {
            panic!("flow opens");
        };
        flow.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        flow.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn hysteria_server_passes_a_hand_rolled_client() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_server_once, 3);
    }

    fn hysteria_server_once() {
        use ferrox_core::foxy::frames as h3;
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("bisect2-auth", id, "");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", port).expect("udp");
        let sock = crate::quic::Datagram::plain(sock);
        let mut config = crate::quic::quiche_config(&roots, Some("bbr")).expect("configures");
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn =
            quiche::connect(Some("localhost"), &cid, local, peer, &mut config).expect("connects");
        crate::quic::drive_handshake(&mut conn, &sock, local).expect("handshakes");
        let horizon = std::time::Instant::now() + Duration::from_secs(30);
        let mut settings = Vec::new();
        h3::quic_varint(&mut settings, 0x04);
        h3::quic_varint(&mut settings, 0);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 2, &settings, true, horizon
        ));
        let mut block = Vec::new();
        ferrox_core::hysteria::build_auth_request("localhost", "bisect2-auth", &mut block);
        let mut frame = Vec::new();
        h3::quic_varint(&mut frame, h3::H3_HEADERS);
        h3::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, &frame, true, horizon
        ));
        let mut head = Vec::new();
        let body = loop {
            let piece = crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, 1, horizon)
                .expect("reads");
            head.extend_from_slice(&piece);
            let mut at = 0usize;
            if let Some(got) = h3::h3_frame(&head, &mut at) {
                if got.kind == h3::H3_HEADERS {
                    if let Some(body) = head.get(at..at + got.length as usize) {
                        break body.to_vec();
                    }
                }
            }
        };
        assert!(ferrox_core::hysteria::verify_auth_response(&body));
        let header = vless_header(&id, 1, &Destination::from(target));
        let mut prefix = Vec::with_capacity(2 + header.len());
        ferrox_core::hysteria::tcp_prefix(&mut prefix);
        prefix.extend_from_slice(&header);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 4, &prefix, false, horizon
        ));
        let reply = crate::quic::stream_recv_exact(&mut conn, &sock, local, 4, 2, horizon)
            .expect("replies");
        assert_eq!(reply.as_slice(), &[0, 0]);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 4, b"ping", false, horizon
        ));
        let back =
            crate::quic::stream_recv_exact(&mut conn, &sock, local, 4, 4, horizon).expect("echoes");
        assert_eq!(back.as_slice(), b"ping");
    }

    /// Drives a browser's HTTP/3 `GET` against a masquerade port and reads the cover answer back: it hand-shakes, sends a `HEADERS` request on stream 0 with a FIN, then walks the reply's `HEADERS` and `DATA` frames into a status, its headers, and its body.
    fn masq_get(port: u16, roots: &[Vec<u8>], path: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        use ferrox_core::foxy::frames as h3;
        use ferrox_core::foxy::hpack;
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", port).expect("udp");
        let sock = crate::quic::Datagram::plain(sock);
        let mut config = crate::quic::quiche_config(roots, Some("bbr")).expect("configures");
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn =
            quiche::connect(Some("localhost"), &cid, local, peer, &mut config).expect("connects");
        crate::quic::drive_handshake(&mut conn, &sock, local).expect("handshakes");
        let horizon = std::time::Instant::now() + Duration::from_secs(15);
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", path),
            ],
            &mut block,
        );
        let mut frame = Vec::new();
        h3::quic_varint(&mut frame, h3::H3_HEADERS);
        h3::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        assert!(
            crate::quic::stream_send_all(&mut conn, &sock, 0, &frame, true, horizon),
            "the browser's request is sent"
        );
        let mut head = Vec::new();
        let mut room = [0u8; 4096];
        loop {
            match conn.stream_recv(0, &mut room) {
                Ok((0, _)) | Err(quiche::Error::Done) => {
                    if conn.is_closed() || std::time::Instant::now() >= horizon {
                        break;
                    }
                    let left = horizon.saturating_duration_since(std::time::Instant::now());
                    if !crate::quic::pump_once(&mut conn, &sock, local, left) {
                        break;
                    }
                }
                Ok((n, fin)) => {
                    head.extend_from_slice(&room[..n]);
                    if fin {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let mut at = 0usize;
        let mut status = 0u16;
        let mut headers = Vec::new();
        let mut body = Vec::new();
        while let Some(frame) = h3::h3_frame(&head, &mut at) {
            let end = at + frame.length as usize;
            let Some(payload) = head.get(at..end) else {
                break;
            };
            match frame.kind {
                h3::H3_HEADERS => {
                    for (name, value) in hpack::qpack_fields(payload).unwrap_or_default() {
                        let name = String::from_utf8_lossy(&name).into_owned();
                        let value = String::from_utf8_lossy(&value).into_owned();
                        if name == ":status" {
                            status = value.parse().unwrap_or(0);
                        } else {
                            headers.push((name, value));
                        }
                    }
                }
                h3::H3_DATA => body.extend_from_slice(payload),
                _ => {}
            }
            at = end;
        }
        (status, headers, body)
    }

    /// The `content-type` a browser's answer carried, or an empty string when it named none.
    fn content_type_of(headers: &[(String, String)]) -> &str {
        headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .map_or("", |(_, value)| value.as_str())
    }

    #[test]
    fn hysteria_answers_a_browser_get_with_the_masquerade_404() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_404_once, 3);
    }

    fn hysteria_masq_404_once() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "lane-auth",
            id,
            "",
            ferrox_core::hysteria::Masquerade::NotFound,
        );
        let (status, headers, body) = masq_get(port, &roots, "/");
        assert_eq!(status, 404);
        assert_eq!(body, b"404 page not found\n");
        assert!(content_type_of(&headers).starts_with("text/plain"));
    }

    #[test]
    fn hysteria_serves_a_canned_masquerade_response() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_response_once, 3);
    }

    fn hysteria_masq_response_once() {
        use ferrox_core::hysteria::Masquerade;
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "lane-auth",
            id,
            "",
            Masquerade::Response {
                status: 200,
                headers: vec![("content-type".to_owned(), "text/markdown".to_owned())],
                body: b"a cover page\n".to_vec(),
            },
        );
        let (status, headers, body) = masq_get(port, &roots, "/");
        assert_eq!(status, 200);
        assert_eq!(content_type_of(&headers), "text/markdown");
        assert_eq!(body, b"a cover page\n");
    }

    #[test]
    fn hysteria_serves_a_file_from_the_masquerade_directory() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_file_once, 3);
    }

    fn hysteria_masq_file_once() {
        use ferrox_core::hysteria::Masquerade;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-masq-file-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("stages dir");
        std::fs::write(dir.join("hello.txt"), b"static bytes").expect("stages file");
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "lane-auth",
            id,
            "",
            Masquerade::File {
                dir: dir.to_str().expect("ascii").to_owned(),
            },
        );
        let (status, headers, body) = masq_get(port, &roots, "/hello.txt");
        assert_eq!(status, 200);
        assert_eq!(content_type_of(&headers), "text/plain; charset=utf-8");
        assert_eq!(body, b"static bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hysteria_refuses_a_masquerade_path_that_escalates_the_directory() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_traversal_once, 3);
    }

    fn hysteria_masq_traversal_once() {
        use ferrox_core::hysteria::Masquerade;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let outer =
            std::env::temp_dir().join(format!("ferrox-masq-out-{}-{stamp}", std::process::id()));
        let root = outer.join("root");
        std::fs::create_dir_all(&root).expect("stages root");
        std::fs::write(outer.join("secret.txt"), b"never served").expect("stages secret");
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "lane-auth",
            id,
            "",
            Masquerade::File {
                dir: root.to_str().expect("ascii").to_owned(),
            },
        );
        // A percent-encoded `../secret.txt` names a file above the served root; the cover answers not-found and the secret is never read.
        let (status, _, body) = masq_get(port, &roots, "/%2e%2e%2fsecret.txt");
        assert_eq!(status, 404);
        assert_ne!(body, b"never served".to_vec());
        let _ = std::fs::remove_dir_all(&outer);
    }

    #[test]
    fn hysteria_proxies_a_masquerade_request_to_an_origin() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_proxy_once, 3);
    }

    fn hysteria_masq_proxy_once() {
        use ferrox_core::hysteria::Masquerade;
        // A one-shot HTTP/1.1 origin that answers any request with a fixed body.
        let origin = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let origin_port = origin.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = origin.accept().expect("accepts");
            let mut drain = [0u8; 1024];
            let _ = stream.read(&mut drain);
            let _ = stream.write_all(b"HTTP/1.1 201 Created\r\ncontent-type: text/plain\r\ncontent-length: 6\r\n\r\norigin");
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "lane-auth",
            id,
            "",
            Masquerade::Proxy {
                url: format!("http://127.0.0.1:{origin_port}"),
                rewrite_host: false,
                x_forwarded: false,
                insecure: false,
            },
        );
        let (status, headers, body) = masq_get(port, &roots, "/anything");
        assert_eq!(status, 201);
        assert_eq!(content_type_of(&headers), "text/plain");
        assert_eq!(body, b"origin");
    }

    /// A one-shot `https` masquerade origin: a TLS-terminating loopback listener that answers the first request it accepts with a fixed HTTP/1.1 body, then closes. Returns the port it listens on.
    fn masq_https_origin() -> u16 {
        let origin = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = origin.local_addr().expect("addr").port();
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let identity = ferrox_core::tls::parse_pem_identity(
            minted.cert.pem().as_bytes(),
            minted.key_pair.serialize_pem().as_bytes(),
        )
        .expect("identity");
        thread::spawn(move || {
            let Ok((stream, _)) = origin.accept() else {
                return;
            };
            let Ok(mut tls) = ferrox_core::tls::accept(&identity, stream) else {
                return;
            };
            if tls.handshake().is_err() {
                return;
            }
            let mut drain = [0u8; 1024];
            let _ = tls.read(&mut drain);
            let _ = tls.write_all(b"HTTP/1.1 201 Created\r\ncontent-type: text/plain\r\ncontent-length: 6\r\n\r\norigin");
            let _ = tls.flush();
        });
        port
    }

    #[test]
    fn hysteria_proxies_a_masquerade_request_to_an_https_origin() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_https_insecure_once, 3);
    }

    fn hysteria_masq_https_insecure_once() {
        use ferrox_core::hysteria::Masquerade;
        let origin_port = masq_https_origin();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "lane-auth",
            id,
            "",
            Masquerade::Proxy {
                url: format!("https://127.0.0.1:{origin_port}"),
                rewrite_host: false,
                x_forwarded: false,
                insecure: true,
            },
        );
        // The cover dials the https origin through the client TLS the relay already speaks; naming `insecure` accepts the self-signed chain and the body returns byte-identical.
        let (status, headers, body) = masq_get(port, &roots, "/anything");
        assert_eq!(status, 201);
        assert_eq!(content_type_of(&headers), "text/plain");
        assert_eq!(body, b"origin");
    }

    #[test]
    fn hysteria_refuses_a_masquerade_https_origin_whose_chain_is_untrusted() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_https_verified_once, 3);
    }

    fn hysteria_masq_https_verified_once() {
        use ferrox_core::hysteria::Masquerade;
        let origin_port = masq_https_origin();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "lane-auth",
            id,
            "",
            Masquerade::Proxy {
                url: format!("https://127.0.0.1:{origin_port}"),
                rewrite_host: false,
                x_forwarded: false,
                insecure: false,
            },
        );
        // A verified dial reaches the same self-signed origin but must not trust it: the chain fails against the platform roots, so `insecure` is honoured as opt-in and the cover answers bad-gateway, relaying no origin bytes.
        let (status, _, body) = masq_get(port, &roots, "/anything");
        assert_eq!(status, 502);
        assert_ne!(body, b"origin".to_vec());
    }

    #[test]
    fn hysteria_still_carries_proxy_flows_beside_a_masquerade_get() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_beside_flow_once, 3);
    }

    fn hysteria_masq_beside_flow_once() {
        use ferrox_core::foxy::frames as h3;
        use ferrox_core::hysteria::Masquerade;
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "bisect2-auth",
            id,
            "",
            Masquerade::Response {
                status: 200,
                headers: vec![],
                body: b"cover".to_vec(),
            },
        );
        // A browser's GET is answered as the cover, and it never disturbs the flow lane a hysteria client uses on its own connection.
        let (status, _, body) = masq_get(port, &roots, "/");
        assert_eq!((status, body.as_slice()), (200, b"cover".as_slice()));
        // A real hysteria client then authenticates and relays a TCP flow across the very same port.
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", port).expect("udp");
        let sock = crate::quic::Datagram::plain(sock);
        let mut config = crate::quic::quiche_config(&roots, Some("bbr")).expect("configures");
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn =
            quiche::connect(Some("localhost"), &cid, local, peer, &mut config).expect("connects");
        crate::quic::drive_handshake(&mut conn, &sock, local).expect("handshakes");
        let horizon = std::time::Instant::now() + Duration::from_secs(30);
        let mut settings = Vec::new();
        h3::quic_varint(&mut settings, 0x04);
        h3::quic_varint(&mut settings, 0);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 2, &settings, true, horizon
        ));
        let mut block = Vec::new();
        ferrox_core::hysteria::build_auth_request("localhost", "bisect2-auth", &mut block);
        let mut frame = Vec::new();
        h3::quic_varint(&mut frame, h3::H3_HEADERS);
        h3::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, &frame, true, horizon
        ));
        let mut head = Vec::new();
        let body = loop {
            let piece = crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, 1, horizon)
                .expect("reads");
            head.extend_from_slice(&piece);
            let mut at = 0usize;
            if let Some(got) = h3::h3_frame(&head, &mut at) {
                if got.kind == h3::H3_HEADERS {
                    if let Some(body) = head.get(at..at + got.length as usize) {
                        break body.to_vec();
                    }
                }
            }
        };
        assert!(ferrox_core::hysteria::verify_auth_response(&body));
        let header = vless_header(&id, 1, &Destination::from(target));
        let mut prefix = Vec::with_capacity(2 + header.len());
        ferrox_core::hysteria::tcp_prefix(&mut prefix);
        prefix.extend_from_slice(&header);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 4, &prefix, false, horizon
        ));
        let reply = crate::quic::stream_recv_exact(&mut conn, &sock, local, 4, 2, horizon)
            .expect("replies");
        assert_eq!(reply.as_slice(), &[0, 0]);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 4, b"ping", false, horizon
        ));
        let back =
            crate::quic::stream_recv_exact(&mut conn, &sock, local, 4, 4, horizon).expect("echoes");
        assert_eq!(back.as_slice(), b"ping");
    }

    #[test]
    fn hysteria_closes_a_wrong_hysteria_password_even_with_masquerade() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_masq_wrong_auth_once, 3);
    }

    fn hysteria_masq_wrong_auth_once() {
        use ferrox_core::foxy::frames as h3;
        use ferrox_core::hysteria::Masquerade;
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_masq(
            "right-auth",
            id,
            "",
            Masquerade::Response {
                status: 200,
                headers: vec![],
                body: b"cover".to_vec(),
            },
        );
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", port).expect("udp");
        let sock = crate::quic::Datagram::plain(sock);
        let mut config = crate::quic::quiche_config(&roots, Some("bbr")).expect("configures");
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn =
            quiche::connect(Some("localhost"), &cid, local, peer, &mut config).expect("connects");
        crate::quic::drive_handshake(&mut conn, &sock, local).expect("handshakes");
        let horizon = std::time::Instant::now() + Duration::from_secs(15);
        // The right handshake shape — a POST to the auth path — but the wrong password must still refuse and close, never quietly serve the cover page.
        let mut block = Vec::new();
        ferrox_core::hysteria::build_auth_request("localhost", "wrong-auth", &mut block);
        let mut frame = Vec::new();
        h3::quic_varint(&mut frame, h3::H3_HEADERS);
        h3::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, &frame, true, horizon
        ));
        let mut head = Vec::new();
        let body = loop {
            let Some(piece) =
                crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, 1, horizon)
            else {
                break None;
            };
            head.extend_from_slice(&piece);
            let mut at = 0usize;
            if let Some(got) = h3::h3_frame(&head, &mut at) {
                if got.kind == h3::H3_HEADERS {
                    if let Some(body) = head.get(at..at + got.length as usize) {
                        break Some(body.to_vec());
                    }
                }
            }
        };
        // The refusal is a not-found, not the cover page: the connection never masquerades a wrong credential.
        let refused = body.is_some_and(|body| {
            ferrox_core::foxy::hpack::qpack_fields(&body)
                .unwrap_or_default()
                .iter()
                .find(|(name, _)| name == b":status")
                .is_some_and(|(_, value)| String::from_utf8_lossy(value) == "404")
        });
        assert!(
            refused,
            "a wrong password is refused with a 404, not served the cover"
        );
    }

    #[test]
    fn hysteria_carries_udp_echo_over_loopback() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_udp_echo_once, 3);
    }

    fn hysteria_udp_echo_once() {
        use ferrox_core::foxy::frames as h3;
        let echo_port = udp_echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("udp-auth", id, "");
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", port).expect("udp");
        let sock = crate::quic::Datagram::plain(sock);
        let mut config = crate::quic::quiche_config(&roots, Some("bbr")).expect("configures");
        config.enable_dgram(true, 1024, 1024);
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn =
            quiche::connect(Some("localhost"), &cid, local, peer, &mut config).expect("connects");
        crate::quic::drive_handshake(&mut conn, &sock, local).expect("handshakes");
        let horizon = std::time::Instant::now() + Duration::from_secs(30);
        let mut settings = Vec::new();
        h3::quic_varint(&mut settings, 0x04);
        h3::quic_varint(&mut settings, 0);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 2, &settings, true, horizon
        ));
        let mut block = Vec::new();
        ferrox_core::hysteria::build_auth_request("localhost", "udp-auth", &mut block);
        let mut frame = Vec::new();
        h3::quic_varint(&mut frame, h3::H3_HEADERS);
        h3::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, &frame, true, horizon
        ));
        let mut head = Vec::new();
        let body = loop {
            let piece = crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, 1, horizon)
                .expect("reads");
            head.extend_from_slice(&piece);
            let mut at = 0usize;
            if let Some(got) = h3::h3_frame(&head, &mut at) {
                if got.kind == h3::H3_HEADERS {
                    if let Some(b) = head.get(at..at + got.length as usize) {
                        break b.to_vec();
                    }
                }
            }
        };
        assert!(ferrox_core::hysteria::verify_auth_response(&body));
        // The auth response advertises the datagram lane, which is what lets the client open a UDP flow.
        let fields = ferrox_core::foxy::hpack::qpack_fields(&body).expect("fields");
        assert_eq!(
            fields
                .iter()
                .find(|(k, _)| k == b"hysteria-udp")
                .map(|(_, v)| v.as_slice()),
            Some(b"true".as_slice())
        );
        // One whole UDP message to the echo target: the server opens the association on this first datagram.
        let address = format!("127.0.0.1:{echo_port}");
        let message = ferrox_core::hysteria::UdpMessage {
            session: 1,
            packet: 1,
            frag: 0,
            frags: 1,
            address: &address,
            payload: b"hello",
        };
        let mut wire = Vec::new();
        ferrox_core::hysteria::encode_udp(&message, &mut wire).expect("encodes");
        conn.dgram_send(&wire).expect("sends");
        let mut out = [0u8; 1350];
        while let Ok((written, info)) = conn.send(&mut out) {
            sock.send_to(&out[..written], info.to).expect("pumps");
        }
        // Read until the echo returns over the lane, driving the connection so the reply's packets are delivered.
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        loop {
            assert!(std::time::Instant::now() < horizon, "echo never returns");
            if let Ok((n, from)) = sock.recv_from(&mut out) {
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(&mut out[..n], info);
            }
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
            if let Ok(data) = conn.dgram_recv_buf() {
                let got = ferrox_core::hysteria::decode_udp(&data).expect("decodes");
                if got.session == 1 && got.payload == b"hello" {
                    assert_eq!(got.address, address);
                    return;
                }
            }
        }
    }

    #[test]
    fn hysteria_carries_a_udp_association_over_the_carrier() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_udp_association_once, 3);
    }

    fn hysteria_udp_association_once() {
        // The whole dispatch: a socks5 UDP associate on a hysteria outbound, framed at the front, carried by the carrier's datagram lane to the echo target, and handed back in the frame the client expects.
        let echo_port = udp_echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("association-auth", id, "");
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port,
            id,
            carrier: Carrier::Hysteria(ferrox_core::hysteria::Config {
                auth: "association-auth".to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                hop: None,
                gecko: None,
            }),
            host: "localhost".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: Some(roots),
            tls: None,
            flow: String::new(),
            reality: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_millis(250)))
            .expect("timeout");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut datagram = vec![0u8, 0, 0];
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"association-ping");
        let mut back = vec![0u8; UDP_BUF];
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let answer = loop {
            let _ = udp.send_to(&datagram, relay);
            match udp.recv_from(&mut back) {
                Ok((n, _)) => break n,
                Err(_) if std::time::Instant::now() < deadline => {}
                Err(error) => panic!("echo never returns: {error}"),
            }
        };
        let (source, payload) = parse_socks_udp(&back[..answer]).expect("splits");
        assert_eq!(source, target);
        assert_eq!(payload, b"association-ping");
    }

    #[test]
    fn hysteria_carries_vless_echo_over_loopback() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_echo_once, 3);
    }

    fn hysteria_echo_once() {
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("test-auth", id, "");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut client = hysteria_tcp_pair(port, roots, "test-auth", id, target, "");
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn hysteria_carries_a_flow_through_salamander_over_loopback() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_salamander_once, 3);
    }

    fn hysteria_salamander_once() {
        // The same dial-and-echo path as the cleartext gate, over a server and a client that both mask every datagram with the salamander key: if the hop on either side were misapplied, the QUIC handshake would never complete.
        let key = "gawrgura";
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("test-auth", id, key);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut client = hysteria_tcp_pair(port, roots, "test-auth", id, target, key);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn hysteria_shares_one_connection_between_two_flows() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_share_once, 3);
    }

    fn hysteria_share_once() {
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("test-auth", id, "");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let before = crate::hysteria::handshake_count();
        let mut back = [0u8; 4];
        let mut first = hysteria_tcp_pair(port, roots.clone(), "test-auth", id, target, "");
        first.write_all(b"ping").expect("writes");
        first.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        let mut second = hysteria_tcp_pair(port, roots, "test-auth", id, target, "");
        second.write_all(b"pong").expect("writes");
        second.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"pong");
        assert_eq!(
            crate::hysteria::handshake_count() - before,
            1,
            "one handshake carried both flows"
        );
    }

    #[test]
    fn hysteria_redials_when_a_pooled_connection_closes() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_redial_once, 3);
    }

    fn hysteria_redial_once() {
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("test-auth", id, "");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut back = [0u8; 4];
        let mut first = hysteria_tcp_pair(port, roots.clone(), "test-auth", id, target, "");
        first.write_all(b"ping").expect("writes");
        first.read_exact(&mut back).expect("echoes");
        drop(first);
        crate::hysteria::close_pooled();
        let before = crate::hysteria::handshake_count();
        let mut second = hysteria_tcp_pair(port, roots, "test-auth", id, target, "");
        second.write_all(b"pong").expect("writes");
        second.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"pong");
        assert_eq!(
            crate::hysteria::handshake_count() - before,
            1,
            "the closed pooled connection was not ridden"
        );
    }

    #[test]
    fn hysteria_refuses_a_wrong_password_without_relaying() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_refuses_once, 3);
    }

    fn hysteria_refuses_once() {
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("test-auth", id, "");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut client = hysteria_tcp_pair(port, roots, "wrong-auth", id, target, "");
        let mut probe = [0u8; 1];
        assert_eq!(client.read(&mut probe).expect("reads"), 0);
    }

    /// A UDP echo target: one bound socket that returns every datagram to whoever sent it, the far end the hysteria relay is measured against.
    fn udp_echo_loop() -> u16 {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = echo.recv_from(&mut buf) else {
                    return;
                };
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        port
    }

    fn echo_loop() -> u16 {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().flatten() {
                thread::spawn(move || {
                    let mut stream = stream;
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = stream.read(&mut buf) else {
                            return;
                        };
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    fn kcp_loop_with(serve: KcpServe) -> u16 {
        let listener = ferrox_core::kcp::Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            ferrox_core::kcp::Config::default(),
        )
        .expect("binds");
        let port = listener.local_addr().port();
        thread::spawn(move || serve_kcp_each(&listener, &serve));
        port
    }

    fn socks_tcp_client(front_port: u16, echo_port: u16) -> Connection {
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client
    }

    fn socks_front_with(out: Outbound) -> u16 {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        port
    }

    fn http_front_with(out: Outbound) -> u16 {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_http(stream, &out);
        });
        port
    }

    fn http_connect(port: u16, authority: &str) -> Connection {
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .expect("connects");
        client
    }

    fn http_status(client: &mut Connection) -> String {
        let head = read_http_head(client, HEAD_LIMIT_TEST, HEAD_DEADLINE).expect("reads a head");
        let line = head.split(|byte| *byte == b'\n').next().expect("a line");
        String::from_utf8(line.to_vec()).expect("text")
    }

    #[test]
    fn http_connect_reaches_echo_direct() {
        let echo = echo_loop();
        let front = http_front_with(Outbound::Freedom);
        let mut client = http_connect(front, &format!("127.0.0.1:{echo}"));
        assert!(http_status(&mut client).starts_with("HTTP/1.1 200"));
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn http_get_forwards_origin_form_to_direct() {
        let echo = echo_loop();
        let front = http_front_with(Outbound::Freedom);
        let mut client = Connection::connect(("127.0.0.1", front)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client
            .write_all(
                format!("GET http://127.0.0.1:{echo}/path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n")
                    .as_bytes(),
            )
            .expect("gets");
        let head =
            read_http_head(&mut client, HEAD_LIMIT_TEST, HEAD_DEADLINE).expect("echoes the head");
        assert_eq!(
            head,
            format!("GET /path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n").into_bytes()
        );
    }

    #[test]
    fn http_get_to_a_protocol_outbound_is_405() {
        let front = http_front_with(Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: 1,
            id: uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id"),
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        }));
        let mut client = Connection::connect(("127.0.0.1", front)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client
            .write_all(b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            .expect("gets");
        assert!(http_status(&mut client).starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn http_connect_tunnels_vless_raw_to_echo() {
        let echo = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let server_port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let front = http_front_with(Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: server_port,
            id,
            carrier: Carrier::Raw(Chain::default()),
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        }));
        let mut client = http_connect(front, &format!("127.0.0.1:{echo}"));
        assert!(http_status(&mut client).starts_with("HTTP/1.1 200"));
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    /// This outbound dials *upstream* of a proxy, so no front test reaches it: a fake proxy is the only witness.
    fn fake_http_proxy() -> u16 {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in front.incoming() {
                let Ok(mut client) = stream else { continue };
                thread::spawn(move || {
                    let Some(head) = read_http_head(&mut client, HEAD_LIMIT_TEST, HEAD_DEADLINE)
                    else {
                        return;
                    };
                    let Some(ProxyRequest::Connect(asked)) = http_proxy_request(&head) else {
                        return;
                    };
                    let Some(target) = asked.socket() else { return };
                    let Ok(upstream) = Connection::connect(target) else {
                        return;
                    };
                    if client.write_all(&Front::Http.grant_line()).is_err() {
                        return;
                    }
                    relay(&client, &upstream);
                });
            }
        });
        port
    }

    #[test]
    fn http_outbound_dials_the_upstream_proxy_to_echo() {
        let echo = echo_loop();
        let proxy = fake_http_proxy();
        let front = socks_front_with(Outbound::Http(HttpOut {
            address: "127.0.0.1".to_owned(),
            port: proxy,
            tls: None,
            headers: Vec::new(),
            user: None,
            pass: None,
        }));
        let mut client = socks_tcp_client(front, echo);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn mixed_serves_socks_and_http_on_one_port() {
        let echo_socks = echo_loop();
        let echo_http = echo_loop();
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in front.incoming().take(2) {
                let Ok(stream) = stream else { continue };
                thread::spawn(|| serve_mixed(stream, &Outbound::Freedom));
            }
        });
        let mut socks = socks_tcp_client(port, echo_socks);
        socks.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        socks.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        let mut http = http_connect(port, &format!("127.0.0.1:{echo_http}"));
        assert!(http_status(&mut http).starts_with("HTTP/1.1 200"));
        http.write_all(b"ping").expect("writes");
        http.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn garbage_closes_the_http_front() {
        let front = http_front_with(Outbound::Freedom);
        let mut client = Connection::connect(("127.0.0.1", front)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(b"GARBAGE\r\n\r\n").expect("writes");
        let mut probe = [0u8; 1];
        match client.read(&mut probe) {
            Ok(0) | Err(_) => {}
            Ok(_) => panic!("garbage was answered"),
        }
    }

    #[test]
    fn http_request_parses_connect_and_both_get_forms() {
        let connect = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let Some(ProxyRequest::Connect(asked)) = http_proxy_request(connect) else {
            panic!("connect parses");
        };
        assert_eq!(asked.authority(), "example.com:443");
        let golang = b"Connect http://127.0.0.1:8080/ HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n";
        let Some(ProxyRequest::Connect(asked)) = http_proxy_request(golang) else {
            panic!("Go's absolute-form connect parses");
        };
        assert_eq!(asked.authority(), "127.0.0.1:8080");
        let absolute =
            b"GET http://example.com:8080/p?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let Some(ProxyRequest::Forward(asked, origin)) = http_proxy_request(absolute) else {
            panic!("absolute-form parses");
        };
        assert_eq!(asked.authority(), "example.com:8080");
        assert_eq!(
            origin,
            b"GET /p?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        );
        let origin_form = b"GET /p HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let Some(ProxyRequest::Forward(asked, origin)) = http_proxy_request(origin_form) else {
            panic!("origin-form parses");
        };
        assert_eq!(asked.authority(), "example.com:80");
        assert_eq!(origin, origin_form);
        assert!(http_proxy_request(b"GET /p HTTP/1.1\r\n\r\n").is_none());
        assert!(http_proxy_request(b"GARBAGE\r\n\r\n").is_none());
    }

    fn http_out(user: Option<&str>, pass: Option<&str>, headers: &[(&str, &str)]) -> HttpOut {
        HttpOut {
            address: "proxy.example".to_string(),
            port: 8080,
            tls: None,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            user: user.map(str::to_string),
            pass: pass.map(str::to_string),
        }
    }

    /// The bytes a hop sees are pinned, not round-tripped through our own parser: drifting together would pass.
    #[test]
    fn the_connect_request_is_the_golden_bytes() {
        let target = "203.0.113.9:443".parse().expect("addr");
        let mut req = Vec::new();
        http_connect_request(
            &target,
            &http_out(
                Some("aladdin"),
                Some("open sesame"),
                &[("Proxy-Connection", "keep-alive")],
            ),
            &mut req,
        );
        assert_eq!(
            req,
            b"CONNECT 203.0.113.9:443 HTTP/1.1\r\nHost: 203.0.113.9:443\r\n\
               Proxy-Authorization: Basic YWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n\
               Proxy-Connection: keep-alive\r\n\r\n"
        );
        let v6 = "[2001:db8::7]:8080".parse().expect("v6 addr");
        req.clear();
        http_connect_request(&v6, &http_out(None, None, &[]), &mut req);
        assert_eq!(
            req,
            b"CONNECT [2001:db8::7]:8080 HTTP/1.1\r\nHost: [2001:db8::7]:8080\r\n\r\n"
        );
        req.clear();
        http_connect_request(
            &Destination::Name("www.example.com".to_owned(), 443),
            &http_out(None, None, &[]),
            &mut req,
        );
        assert_eq!(
            req, b"CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n",
            "a name reaches the hop as a name, so no resolver of ours sees it"
        );
    }

    /// The builder never moves the caller's buffer: the only witness that the request is one allocation.
    #[test]
    fn the_connect_request_reuses_the_callers_buffer() {
        let mut req = Vec::with_capacity(256);
        let (ptr, capacity) = (req.as_ptr(), req.capacity());
        let http = http_out(Some("u"), Some("password"), &[("X-Trace", "on")]);
        for port in 1..=8u16 {
            let target = SocketAddr::from(([198, 51, 100, 7], port));
            http_connect_request(&Destination::from(target), &http, &mut req);
            assert!(!req.is_empty(), "port {port} builds a request");
        }
        assert_eq!(req.as_ptr(), ptr, "no reallocation across the sweep");
        assert_eq!(req.capacity(), capacity, "and no growth");
    }

    struct Counted<R> {
        inner: R,
        reads: usize,
    }

    impl<R: Read> Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            self.inner.read(buf)
        }
    }

    /// `read-syscalls-per-connect-head 1`: counted on `read`, because the bytes are identical either way.
    #[test]
    fn a_whole_connect_head_costs_one_read() {
        let mut source = Counted {
            inner: std::io::Cursor::new(b"HTTP/1.1 200 OK\r\n\r\npinned".to_vec()),
            reads: 0,
        };
        let Some((head, at)) = read_exact_head(&mut source, HTTP_HEAD_LIMIT, HEAD_DEADLINE) else {
            panic!("the head is read");
        };
        assert_eq!(source.reads, 1, "one read for a head that arrives whole");
        assert_eq!(&head[..at], b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(
            &head[at..],
            b"pinned",
            "the prefix past the head is returned"
        );
        assert_eq!(
            head[at..].as_ptr() as usize - head.as_ptr() as usize,
            at,
            "head and tail are one allocation, so the tail was never copied out of it"
        );
    }

    /// Bytes past the `200\r\n\r\n` must reach the client before the relay opens, or the relay steals them.
    #[test]
    fn bytes_pipelined_past_the_connect_head_reach_the_client() {
        let hop = crate::conn::test_bind("127.0.0.1:0").expect("bind hop");
        let hop_addr = hop.local_addr().expect("hop addr");
        let hop_thread = thread::spawn(move || {
            let (mut stream, _) = hop.accept().expect("hop accepts");
            let mut byte = [0u8; 1];
            let mut asked = Vec::new();
            while !asked.ends_with(b"\r\n\r\n") {
                let read = stream.read(&mut byte).expect("hop reads");
                assert_ne!(read, 0, "hop saw an eof");
                asked.push(byte[0]);
            }
            assert_eq!(
                asked,
                b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nPONG")
                .expect("hop answers");
            let mut echoed = [0u8; 4];
            stream.read_exact(&mut echoed).expect("hop echoes");
            assert_eq!(&echoed, b"ping");
        });

        let front = crate::conn::test_bind("127.0.0.1:0").expect("bind front");
        let front_addr = front.local_addr().expect("front addr");
        let relay = thread::spawn(move || {
            let (client, _) = front.accept().expect("front accepts");
            dial_http_outbound(
                &client,
                &hop_addr,
                &http_out(None, None, &[]),
                &"127.0.0.1:1".parse().expect("target"),
                Ladder::global(),
            );
        });

        let mut sock = Connection::connect(front_addr).expect("join");
        sock.write_all(b"ping").expect("client writes");
        assert_eq!(
            &read_echo(&mut sock),
            b"PONG",
            "the prefix past the head reaches the client, not the hop"
        );
        let _ = sock.shutdown(Shutdown::Write);
        relay.join().expect("relay returns");
        hop_thread.join().expect("hop returns");
    }

    /// An HTTP hop carries no datagrams, so QUIC is refused rather than falling to a carrier nobody asked for.
    #[test]
    fn an_http_hop_refuses_the_quic_carrier_before_any_dial() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"foxy","settings":{"email":"a@b.c","password":"pw","carrier":"h3","upstreamProxy":"http://proxy.local:8080"}}]}"#,
        )
        .expect("parses");
        assert!(find_foxy_outbound(&root).is_none());
    }

    /// Over a SOCKS5 hop the lane starts: QUIC rides its UDP association, so the hop is carried.
    #[test]
    fn a_socks5_hop_carries_the_quic_carrier() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"foxy","settings":{"pass":"a.eyJleHAiOjQwMDAwMDAwMDB9.b","email":"a@b.c","password":"pw","carrier":"h3","upstreamProxy":"socks5://proxy.local:1080","link":"foxy://edge.example?username=a@b.c"}}]}"#,
        )
        .expect("parses");
        let foxy = find_foxy_outbound(&root).expect("serves");
        assert_eq!(foxy.carrier, crate::foxy::Carrier::H3);
        assert!(foxy.upstream.is_some(), "the hop is dialed, not bypassed");
    }

    #[test]
    fn a_bad_upstream_proxy_refuses_its_outbound_before_any_dial() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"foxy","settings":{"email":"a@b.c","password":"pw","country":"US","upstreamProxy":"gopher://proxy.local:70"}}]}"#,
        )
        .expect("parses");
        assert!(find_foxy_outbound(&root).is_none());
    }

    /// A pasted pass nobody can replace stops carrying at its exp: refuse the lane at start, not at the first flow.
    #[test]
    fn an_expired_pasted_pass_refuses_its_outbound() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"foxy","settings":{"pass":"a.eyJleHAiOjF9.b","link":"foxy://edge.example:443"}}]}"#,
        )
        .expect("parses");
        assert!(find_foxy_outbound(&root).is_none());
    }

    /// Inside its window the same pass serves, and the expiry comes off the JWT rather than staying unknown.
    #[test]
    fn a_live_pasted_pass_carries_the_expiry_its_jwt_names() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"foxy","settings":{"pass":"a.eyJleHAiOjQwMDAwMDAwMDB9.b","link":"foxy://edge.example:443"}}]}"#,
        )
        .expect("parses");
        let foxy = find_foxy_outbound(&root).expect("serves");
        assert_eq!(foxy.pass.expires_at, Some(4_000_000_000));
        assert!(
            !foxy
                .account
                .as_ref()
                .is_some_and(|account| account.can_renew()),
            "a pasted pass has no grant to renew with"
        );
    }

    /// The tag is the whole route: a loopback outbound without one names nowhere.
    #[test]
    fn a_loopback_outbound_names_its_inbound_tag() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"loopback","settings":{"inboundTag":"tunnel-in"}}]}"#,
        )
        .expect("parses");
        assert_eq!(find_loopback_outbound(&root).as_deref(), Some("tunnel-in"));
        for json in [
            r#"{"outbounds":[{"protocol":"loopback"}]}"#,
            r#"{"outbounds":[{"protocol":"loopback","settings":{}}]}"#,
            r#"{"outbounds":[{"protocol":"loopback","settings":{"inboundTag":""}}]}"#,
            r#"{"outbounds":[{"protocol":"freedom"}]}"#,
            r#"{"outbounds":[]}"#,
        ] {
            let root = crate::json::parse(json).expect("parses");
            assert!(
                find_loopback_outbound(&root).is_none(),
                "{json} names no re-inject"
            );
        }
    }

    /// Sniffing on re-dispatch belongs to the engine sniffer this tree has not
    /// built, so an enabled sniffer skips the outbound rather than re-injecting
    /// unsniffed in silence.
    #[test]
    fn a_loopback_outbound_with_sniffing_enabled_is_skipped() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"loopback","settings":{"inboundTag":"t","sniffing":{"enabled":true}}}]}"#,
        )
        .expect("parses");
        assert!(find_loopback_outbound(&root).is_none());
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"loopback","settings":{"inboundTag":"t","sniffing":{"enabled":false}}}]}"#,
        )
        .expect("parses");
        assert_eq!(find_loopback_outbound(&root).as_deref(), Some("t"));
    }

    fn loopback_root(inbounds: &str) -> Json {
        crate::json::parse(&format!(
            r#"{{"inbounds":[{inbounds}],"outbounds":[{{"protocol":"loopback","settings":{{"inboundTag":"tunnel-in"}}}},{{"protocol":"freedom"}}]}}"#,
        ))
        .expect("parses")
    }

    /// A tag that names no inbound is a config error, refused by name at
    /// startup rather than per flow at midnight.
    #[test]
    fn a_loopback_to_an_unknown_inbound_is_refused_by_name() {
        let root = loopback_root(
            r#"{"tag":"other","protocol":"vless","port":1,"settings":{"clients":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}}"#,
        );
        let error = resolve_loopback(&root, "tunnel-in", true).expect_err("refused");
        assert!(error.contains("tunnel-in"), "{error}");
    }

    /// A front would re-enter this same resolution through the single outbound,
    /// so naming one is a cycle of length one, refused rather than spun.
    #[test]
    fn a_loopback_into_a_front_would_re_enter() {
        for protocol in ["socks", "http", "mixed"] {
            let root = loopback_root(&format!(
                r#"{{"tag":"tunnel-in","protocol":"{protocol}","port":1}}"#,
            ));
            let error = resolve_loopback(&root, "tunnel-in", true).expect_err("refused");
            assert!(error.contains("tunnel-in"), "{error}");
        }
    }

    /// The named server leaves by freedom; without one the re-injected flow
    /// handshakes and then has nowhere to go, so the config stops at startup.
    #[test]
    fn a_loopback_without_freedom_has_nowhere_to_leave_by() {
        let root = loopback_root(
            r#"{"tag":"tunnel-in","protocol":"vless","port":1,"settings":{"clients":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}}"#,
        );
        let error = resolve_loopback(&root, "tunnel-in", false).expect_err("refused");
        assert!(error.contains("tunnel-in"), "{error}");
    }

    /// The redial speaks plain TCP plus the carried carriers. Transport
    /// security and datagram handshakes need an identity and a session the
    /// inbound JSON does not carry, so they refuse with the tag that asked.
    #[test]
    fn a_loopback_into_an_undiallable_inbound_is_refused() {
        let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        for (protocol, stream) in [
            ("vless", r#","streamSettings":{"security":"tls"}"#),
            ("vless", r#","streamSettings":{"security":"reality"}"#),
            ("vless", r#","streamSettings":{"network":"quic"}"#),
            ("vless", r#","streamSettings":{"network":"kcp"}"#),
            ("vless", r#","streamSettings":{"network":"hysteria"}"#),
            ("vless", r#","streamSettings":{"network":"masque"}"#),
            ("vless", r#","streamSettings":{"network":"bogus"}"#),
            ("dokodemo", ""),
            ("blackhole", ""),
        ] {
            let settings = if protocol == "vless" {
                format!(r#","settings":{{"clients":[{{"id":"{id}"}}]}}"#)
            } else {
                String::new()
            };
            let root = loopback_root(&format!(
                r#"{{"tag":"tunnel-in","protocol":"{protocol}","port":1{settings}{stream}}}"#,
            ));
            let error = resolve_loopback(&root, "tunnel-in", true).expect_err("refused");
            assert!(error.contains("tunnel-in"), "{protocol}{stream}: {error}");
        }
    }

    /// Each servable server protocol resolves to its own dial, pointed at
    /// where the named inbound listens with that inbound's own credentials.
    #[test]
    fn a_loopback_resolves_each_server_protocol_to_its_own_dial() {
        let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let id_bytes = uuid_bytes(id).expect("id");
        let root = loopback_root(&format!(
            r#"{{"tag":"tunnel-in","protocol":"vless","listen":"127.0.0.1","port":1234,"settings":{{"clients":[{{"id":"{id}"}}]}}}}"#,
        ));
        {
            let Outbound::Vless(dial) = resolve_loopback(&root, "tunnel-in", true).expect("vless")
            else {
                panic!("a vless inbound resolves to a vless dial");
            };
            assert_eq!(dial.id, id_bytes);
            assert_eq!((dial.address.as_str(), dial.port), ("127.0.0.1", 1234));
            assert!(dial.tls.is_none() && dial.reality.is_none());
        }
        let root = loopback_root(
            r#"{"tag":"tunnel-in","protocol":"trojan","listen":"127.0.0.1","port":1235,"settings":{"clients":[{"password":"secret"}]}}"#,
        );
        {
            let Outbound::Trojan(dial) =
                resolve_loopback(&root, "tunnel-in", true).expect("trojan")
            else {
                panic!("a trojan inbound resolves to a trojan dial");
            };
            assert_eq!(dial.key, trojan_key("secret"));
            assert_eq!((dial.address.as_str(), dial.port), ("127.0.0.1", 1235));
        }
        let root = loopback_root(&format!(
            r#"{{"tag":"tunnel-in","protocol":"vmess","listen":"127.0.0.1","port":1236,"settings":{{"clients":[{{"id":"{id}"}}]}}}}"#,
        ));
        {
            let Outbound::Vmess(dial) = resolve_loopback(&root, "tunnel-in", true).expect("vmess")
            else {
                panic!("a vmess inbound resolves to a vmess dial");
            };
            assert_eq!(dial.id, id_bytes);
            assert_eq!((dial.address.as_str(), dial.port), ("127.0.0.1", 1236));
        }
        let root = loopback_root(
            r#"{"tag":"tunnel-in","protocol":"shadowsocks","listen":"127.0.0.1","port":1237,"settings":{"method":"aes-128-gcm","password":"pw"}}"#,
        );
        {
            let Outbound::Shadowsocks(dial) =
                resolve_loopback(&root, "tunnel-in", true).expect("shadowsocks")
            else {
                panic!("a shadowsocks inbound resolves to a shadowsocks dial");
            };
            assert_eq!((dial.address.as_str(), dial.port), ("127.0.0.1", 1237));
            assert_eq!(dial.method, "aes-128-gcm");
        }
        // An every-interface bind is redialled where it also answers.
        let root = loopback_root(&format!(
            r#"{{"tag":"tunnel-in","protocol":"vless","listen":"0.0.0.0","port":1238,"settings":{{"clients":[{{"id":"{id}"}}]}}}}"#,
        ));
        {
            let Outbound::Vless(dial) = resolve_loopback(&root, "tunnel-in", true).expect("vless")
            else {
                panic!("resolves");
            };
            assert_eq!(dial.address, "127.0.0.1");
        }
        // A relay-shaped Shadowsocks inbound answers for fixed destinations, not the re-injected target.
        let root = loopback_root(
            r#"{"tag":"tunnel-in","protocol":"shadowsocks","port":1239,"settings":{"method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OUFCQ0RFRg==","destinations":[{"key":"MDEyMzQ1Njc4OUFCQ0RFRg==","address":"127.0.0.1","port":9}]}}"#,
        );
        let error = resolve_loopback(&root, "tunnel-in", true).expect_err("refused");
        assert!(error.contains("tunnel-in"), "{error}");
    }

    /// The re-injected flow carries a real handshake on the loopback wire: a
    /// SOCKS front, a loopback resolved to the named VLESS inbound, freedom to
    /// an echo. The bytes that come back are the bytes that went in.
    #[test]
    fn a_re_injected_tcp_stream_carries_an_echo() {
        let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let id_bytes = uuid_bytes(id).expect("id");
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id_bytes, true);
        });
        let root = loopback_root(&format!(
            r#"{{"tag":"tunnel-in","protocol":"vless","listen":"127.0.0.1","port":{tunnel_port},"settings":{{"clients":[{{"id":"{id}"}}]}}}}"#,
        ));
        let out = resolve_loopback(&root, "tunnel-in", true).expect("resolves");
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        let payload: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        client.write_all(&payload).expect("writes");
        let mut back = vec![0u8; 65536];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(back, payload, "a re-injected stream is byte-identical");
    }

    /// UDP takes the same re-inject: the association frames its datagram over
    /// the redialled TCP session the way a direct dial would.
    #[test]
    fn a_re_injected_udp_association_carries_a_datagram() {
        let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let id_bytes = uuid_bytes(id).expect("id");
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let tunnel = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id_bytes, true);
        });
        let root = loopback_root(&format!(
            r#"{{"tag":"tunnel-in","protocol":"vless","listen":"127.0.0.1","port":{tunnel_port},"settings":{{"clients":[{{"id":"{id}"}}]}}}}"#,
        ));
        let out = resolve_loopback(&root, "tunnel-in", true).expect("resolves");
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source, target);
        assert_eq!(payload, b"ping");
    }

    /// An edge that names no protocol the lane speaks is silent on that carrier, so the flow that learns it pays one dial and the next pays none.
    #[test]
    fn a_silent_carrier_is_dialled_once_rather_than_once_per_rung() {
        use ferrox_core::tls::TlsProvider as _;
        use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

        let (server_config, _) = carried_tls_configs();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let edge: SocketAddr = listener.local_addr().expect("addr");
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&asked);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) = ferrox_core::tls::RustlsServerProvider::accept(
                    (*server_config).clone(),
                    stream,
                ) else {
                    continue;
                };
                let _ = tls.handshake();
            }
        });

        let edge_carrier = crate::foxy::Carrier::H1;
        let foxy = FoxyOut {
            account: None,
            country: "US".to_owned(),
            city: String::new(),
            carrier: edge_carrier,
            upstream: None,
            candidates: vec![ferrox_core::foxy::Candidate {
                host: "carrier.test".to_owned(),
                port: edge.port(),
                country: "US".to_owned(),
                city: String::new(),
            }],
            stored: None,
            unauthenticated: std::sync::Arc::new(AtomicBool::new(false)),
            limited_strikes: std::sync::Arc::new(AtomicU32::new(0)),
            limited_until: std::sync::Arc::new(AtomicU64::new(0)),
            carrier_dead: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::Refusals::new(32),
            )),
            edge_strikes: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::EdgeStrikes::new(32),
            )),
            roots: vec![CARRIER_CERT.to_vec()],
            pins: ferrox_core::foxy::pin::Pins::default(),
            pass: ferrox_core::foxy::Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
            edge_address: Some(edge),
            direct_ports: Vec::new(),
            direct_suffixes: Vec::new(),
            exit_probe: None,
            verified: std::sync::Arc::new(std::sync::Mutex::new(None)),
            probe_unavailable: std::sync::Arc::new(AtomicBool::new(false)),
            exit_refuted_until: std::sync::Arc::new(AtomicU64::new(0)),
        };
        let target = Destination::Name("target.test".to_owned(), 443);

        assert!(
            matches!(foxy_open(&foxy, &target), FoxyOpen::Refused(_)),
            "an edge that names no protocol carries nothing"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "a named carrier is one rung, not the three its order repeats"
        );

        assert!(
            matches!(foxy_open(&foxy, &target), FoxyOpen::Refused(_)),
            "the silence is still the answer"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "a carrier the edge went silent on is not probed again inside the window"
        );

        // The window, not the verdict: an edge left alone for its quarantine is asked again the moment it ends.
        let edge = &foxy.candidates[0];
        if let Ok(mut cache) = foxy.carrier_dead.lock() {
            cache.remember(
                &carrier_key(edge, edge_carrier),
                now_secs().saturating_sub(1),
            );
        }
        assert!(
            matches!(foxy_open(&foxy, &target), FoxyOpen::Refused(_)),
            "the edge still names no protocol"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "a rested carrier is asked again once its window has run out"
        );
    }

    /// The connect-ip lane marks a silent carrier dead the same way the TCP flow does, so it must not knock on it again with the next packet: a lane whose carriers are all dead opens nothing, and one whose window has rested is asked again.
    #[test]
    fn the_connect_ip_lane_leaves_a_dead_carrier_dead() {
        use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let edge: SocketAddr = listener.local_addr().expect("addr");
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&asked);
        // A silent edge: it accepts, names nothing and hangs up, which is a dead carrier rather than a live one.
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let edge_carrier = crate::foxy::Carrier::H2;
        let foxy = FoxyOut {
            account: None,
            country: "US".to_owned(),
            city: String::new(),
            carrier: crate::foxy::Carrier::Auto,
            upstream: None,
            candidates: vec![ferrox_core::foxy::Candidate {
                host: "carrier.test".to_owned(),
                port: edge.port(),
                country: "US".to_owned(),
                city: String::new(),
            }],
            stored: None,
            unauthenticated: std::sync::Arc::new(AtomicBool::new(false)),
            limited_strikes: std::sync::Arc::new(AtomicU32::new(0)),
            limited_until: std::sync::Arc::new(AtomicU64::new(0)),
            carrier_dead: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::Refusals::new(32),
            )),
            edge_strikes: std::sync::Arc::new(std::sync::Mutex::new(
                ferrox_core::foxy::EdgeStrikes::new(32),
            )),
            roots: Vec::new(),
            pins: ferrox_core::foxy::pin::Pins::default(),
            pass: ferrox_core::foxy::Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
            edge_address: Some(edge),
            direct_ports: Vec::new(),
            direct_suffixes: Vec::new(),
            exit_probe: None,
            verified: std::sync::Arc::new(std::sync::Mutex::new(None)),
            probe_unavailable: std::sync::Arc::new(AtomicBool::new(false)),
            exit_refuted_until: std::sync::Arc::new(AtomicU64::new(0)),
        };
        // Both capsule carriers are known silent, and neither is to be knocked on again inside its window.
        for carrier in crate::foxy::Carrier::udp_order() {
            if let Ok(mut cache) = foxy.carrier_dead.lock() {
                cache.remember(
                    &carrier_key(&foxy.candidates[0], carrier),
                    now_secs() + CARRIER_DEAD_SECS,
                );
            }
        }
        let mut tunnel = None;
        let mut source = [0u8; 16];
        let mut width = 0usize;
        assert!(
            !open_foxy_ip_tunnel(&foxy, &mut tunnel, &mut source, &mut width),
            "an edge silent on every capsule carrier grants no address"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            0,
            "the silence the lane already knows is not probed again on this packet"
        );
        // The window, not the verdict: a carrier left alone for its quarantine is asked again when it ends.
        if let Ok(mut cache) = foxy.carrier_dead.lock() {
            cache.clear(&carrier_key(&foxy.candidates[0], edge_carrier));
        }
        assert!(
            !open_foxy_ip_tunnel(&foxy, &mut tunnel, &mut source, &mut width),
            "the rested carrier still has nothing to open"
        );
        assert_ne!(
            asked.load(Ordering::SeqCst),
            0,
            "a rested carrier is asked again once its window has run out"
        );
    }

    #[test]
    fn rate_limit_backoff_climbs_and_clears() {
        let strikes = AtomicU32::new(0);
        let until = AtomicU64::new(0);
        assert!(!edge_limited(&until, 1_000));
        assert_eq!(note_limited(&strikes, &until, 1_000), 1_030);
        assert!(edge_limited(&until, 1_000));
        assert!(!edge_limited(&until, 1_030));
        assert_eq!(note_limited(&strikes, &until, 1_030), 1_060);
        assert_eq!(note_limited(&strikes, &until, 1_060), 1_120);
        assert!(edge_limited(&until, 1_061));
        clear_limited(&strikes, &until);
        assert!(!edge_limited(&until, 1_061));
    }

    #[test]
    fn socks_dials_vless_over_kcp_to_echo() {
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let serve: KcpServe = Arc::new(move |conn| serve_vless_kcp(conn, &id, true));
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            id,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
            tls: None,
            flow: String::new(),
            reality: None,
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn trojan_over_kcp_reaches_echo() {
        let echo_port = echo_loop();
        let key = trojan_key("secret");
        let listener = ferrox_core::kcp::Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            ferrox_core::kcp::Config::default(),
        )
        .expect("binds");
        let kcp_port = listener.local_addr().port();
        let server = thread::spawn(move || {
            let conn = listener.accept().expect("accepts");
            serve_trojan_kcp(&conn, &key, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let server_addr: SocketAddr = format!("127.0.0.1:{kcp_port}").parse().expect("addr");
        let conn = ferrox_core::kcp::dial(
            server_addr,
            ferrox_core::kcp::Config::default(),
            ferrox_core::kcp::fresh_conversation(),
        )
        .expect("dials");
        conn.write(&trojan_header(&key, 1, &Destination::from(target)))
            .expect("writes");
        conn.write(b"ping").expect("writes");
        conn.set_read_deadline(std::time::Instant::now() + std::time::Duration::from_secs(10));
        let mut back = [0u8; 4];
        let mut at = 0;
        while at < 4 {
            let n = conn.read(&mut back[at..]).expect("echoes");
            if n == 0 {
                break;
            }
            at += n;
        }
        assert_eq!(&back, b"ping");
        conn.close();
        server.join().expect("joins");
    }

    #[test]
    fn socks_dials_trojan_over_kcp_to_echo() {
        let echo_port = echo_loop();
        let key = trojan_key("secret");
        let serve: KcpServe = Arc::new(move |conn| serve_trojan_kcp(conn, &key, true));
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            key,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
            tls: None,
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_vmess_over_kcp_to_echo() {
        let echo_port = echo_loop();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let serve: KcpServe = Arc::new(move |conn| {
            let (reader, writer, close) = kcp_parts(conn);
            crate::vmess::serve_kcp(reader, writer, &id, true, &close);
        });
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            id,
            cipher: crate::vmess::Cipher::Auto,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
            tls: None,
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_ss_over_kcp_to_echo() {
        let echo_port = echo_loop();
        let password = "an-example-shared-password".to_owned();
        let method = "aes-256-gcm".to_owned();
        let serve_password = password.clone();
        let serve_method = method.clone();
        let serve: KcpServe = Arc::new(move |conn| {
            let (reader, writer, close) = kcp_parts(conn);
            crate::shadowsocks::serve_kcp(
                reader,
                writer,
                &serve_password,
                &serve_method,
                true,
                &close,
            );
        });
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Shadowsocks(ShadowsocksOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            method,
            password,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }
}

#[cfg(target_os = "linux")]
mod poll_relay {
    use super::{Connection, Shutdown, SplicePipe};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};

    const SPLICE_F_NONBLOCK: libc::c_uint = 0x002;

    fn retryable() -> bool {
        matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR | libc::EAGAIN)
        )
    }

    /// Ingest splices that found no slot in a pipe that still held byte room: the wake the
    /// back-off exists to stop. Counted only under `cfg(test)`, so a production build emits nothing.
    #[cfg(test)]
    static IDLE_INGESTS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    pub(crate) fn idle_ingests() -> usize {
        IDLE_INGESTS.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn note_idle_ingest(pending: usize, capacity: usize) {
        if pending > 0 && pending < capacity {
            IDLE_INGESTS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(not(test))]
    #[inline]
    fn note_idle_ingest(_pending: usize, _capacity: usize) {}

    /// A blocking socket parks the worker inside a splice when a wake arrives for a
    /// queue that has gone — `SPLICE_F_NONBLOCK` guards the pipe half only. `held` stops
    /// the descriptor being recycled under a restore that writes back the flags it found.
    struct SpliceGuard {
        held: Connection,
        saved: libc::c_int,
    }

    impl SpliceGuard {
        fn arm(socket: &Connection) -> Option<Self> {
            let held = socket.try_clone().ok()?;
            let fd = held.as_raw_fd();
            let saved = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if saved < 0 || saved & libc::O_NONBLOCK != 0 {
                return None;
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, saved | libc::O_NONBLOCK) } < 0 {
                return None;
            }
            Some(Self { held, saved })
        }
    }

    impl Drop for SpliceGuard {
        fn drop(&mut self) {
            unsafe {
                libc::fcntl(self.held.as_raw_fd(), libc::F_SETFL, self.saved);
            }
        }
    }

    /// Every socket the flow splices, not only the half a wake reported: one wake drives
    /// both legs. Armed while both directions hold a pipe, because a direction without one
    /// hands its sockets to `copy_all_memcpy`, which ends on the first error and would read
    /// `EAGAIN` as EOF. Descriptors shared by two directions arm once.
    fn arm_flow(first: &Direction, second: &Direction) -> [Option<SpliceGuard>; 4] {
        if first.pipe.is_none() || second.pipe.is_none() {
            return [None, None, None, None];
        }
        [
            SpliceGuard::arm(&first.src),
            SpliceGuard::arm(&first.dst),
            SpliceGuard::arm(&second.src),
            SpliceGuard::arm(&second.dst),
        ]
    }

    struct Direction {
        src: Connection,
        dst: Connection,
        pipe: Option<SplicePipe>,
        pending: usize,
        /// The last ingest splice moved nothing: a pipe ring runs out of slots before it
        /// runs out of byte capacity, so an honest `POLLIN` can still have nowhere to put
        /// what it sees, and a level-triggered one would wake us forever. The drain that
        /// frees a slot clears it.
        ingest_stalled: bool,
        src_at_eof: bool,
        ended: bool,
        done: Option<mpsc::Sender<()>>,
    }

    impl Direction {
        fn new(src: Connection, dst: Connection, done: mpsc::Sender<()>) -> Self {
            Self {
                src,
                dst,
                pipe: SplicePipe::new(),
                pending: 0,
                ingest_stalled: false,
                src_at_eof: false,
                ended: false,
                done: Some(done),
            }
        }

        /// Whether a `POLLIN` on `src` could move bytes: `pending` is in bytes and the
        /// kernel's `EAGAIN` is about slots, so an empty pipe is the one state where the
        /// byte capacity is certainly available. With `pending` held the drain keeps
        /// `POLLOUT` armed, which is the wake that frees a slot and re-arms this half.
        fn can_ingest(&self) -> bool {
            let has_room = match &self.pipe {
                Some(pipe) => self.pending < pipe.capacity,
                None => true,
            };
            !self.src_at_eof && has_room && (self.pending == 0 || !self.ingest_stalled)
        }

        fn can_drain(&self) -> bool {
            self.pending > 0
        }

        fn advance(&mut self) {
            if self.ended {
                return;
            }
            let Some(pipe) = self.pipe.as_ref() else {
                super::copy_all_memcpy(&mut self.src, &mut self.dst);
                self.end();
                return;
            };
            let room = pipe.capacity - self.pending;
            if self.can_ingest() {
                let moved = unsafe {
                    libc::splice(
                        self.src.as_raw_fd(),
                        std::ptr::null_mut(),
                        pipe.fds[1],
                        std::ptr::null_mut(),
                        room,
                        SPLICE_F_NONBLOCK,
                    )
                };
                if moved > 0 {
                    self.pending += moved as usize;
                    self.ingest_stalled = false;
                } else if moved == 0 {
                    self.src_at_eof = true;
                } else if !retryable() {
                    self.end();
                    return;
                } else {
                    note_idle_ingest(self.pending, pipe.capacity);
                    self.ingest_stalled = true;
                }
            }
            while self.can_drain() {
                let moved = unsafe {
                    libc::splice(
                        pipe.fds[0],
                        std::ptr::null_mut(),
                        self.dst.as_raw_fd(),
                        std::ptr::null_mut(),
                        self.pending,
                        SPLICE_F_NONBLOCK,
                    )
                };
                if moved > 0 {
                    self.pending -= moved as usize;
                    self.ingest_stalled = false;
                    continue;
                }
                if moved < 0 && !retryable() {
                    self.end();
                    return;
                }
                break;
            }
            if self.src_at_eof && self.pending == 0 {
                self.end();
            }
        }

        fn end(&mut self) {
            if self.ended {
                return;
            }
            self.ended = true;
            let _ = self.dst.shutdown(Shutdown::Write);
            if let Some(done) = self.done.take() {
                let _ = done.send(());
            }
        }
    }

    struct Flow {
        directions: Vec<Direction>,
    }

    impl Flow {
        fn finished(&self) -> bool {
            self.directions.iter().all(|d| d.ended)
        }
    }

    struct Worker {
        queue: Mutex<Vec<Flow>>,
        wake: [libc::c_int; 2],
    }

    impl Worker {
        fn spawn() -> Option<Arc<Self>> {
            let mut wake = [-1; 2];
            if unsafe { libc::pipe(wake.as_mut_ptr()) } != 0 {
                return None;
            }
            for (fd, flags) in [
                (wake[0], libc::O_NONBLOCK),
                (wake[1], libc::O_CLOEXEC | libc::O_NONBLOCK),
            ] {
                unsafe {
                    libc::fcntl(fd, libc::F_SETFL, flags);
                }
            }
            let worker = Arc::new(Self {
                queue: Mutex::new(Vec::new()),
                wake,
            });
            let loop_worker = Arc::clone(&worker);
            let _ = std::thread::Builder::new()
                .name("ferrox-relay".into())
                .spawn(move || run(&loop_worker));
            Some(worker)
        }

        fn push(&self, flow: Flow) {
            if let Ok(mut queue) = self.queue.lock() {
                queue.push(flow);
            }
            let byte = 1u8;
            unsafe {
                libc::write(self.wake[1], std::ptr::addr_of!(byte).cast(), 1);
            }
        }

        fn take(&self) -> Vec<Flow> {
            let mut queue = match self.queue.lock() {
                Ok(queue) => queue,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *queue)
        }

        fn drain_wake(&self) {
            let mut scratch = [0u8; 64];
            loop {
                let got =
                    unsafe { libc::read(self.wake[0], scratch.as_mut_ptr().cast(), scratch.len()) };
                if got <= 0 {
                    return;
                }
            }
        }
    }

    fn run(worker: &Worker) {
        let mut flows: Vec<Flow> = Vec::new();
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(64);
        let mut owners: Vec<(usize, usize)> = Vec::with_capacity(64);
        loop {
            flows.extend(worker.take());
            if flows.iter().any(Flow::finished) {
                flows.retain(|flow| !flow.finished());
            }
            pfds.clear();
            owners.clear();
            pfds.push(libc::pollfd {
                fd: worker.wake[0],
                events: libc::POLLIN,
                revents: 0,
            });
            owners.push((usize::MAX, usize::MAX));
            for (flow_index, flow) in flows.iter().enumerate() {
                for (direction_index, direction) in flow.directions.iter().enumerate() {
                    if direction.ended {
                        continue;
                    }
                    if direction.can_ingest() {
                        pfds.push(libc::pollfd {
                            fd: direction.src.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        });
                        owners.push((flow_index, direction_index));
                    }
                    if direction.can_drain() {
                        pfds.push(libc::pollfd {
                            fd: direction.dst.as_raw_fd(),
                            events: libc::POLLOUT,
                            revents: 0,
                        });
                        owners.push((flow_index, direction_index));
                    }
                }
            }
            let answered = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
            if answered < 0 {
                continue;
            }
            for (index, entry) in pfds.iter().enumerate() {
                if entry.revents == 0 {
                    continue;
                }
                let (flow_index, direction_index) = owners[index];
                if flow_index == usize::MAX {
                    worker.drain_wake();
                    continue;
                }
                if let Some(direction) = flows
                    .get_mut(flow_index)
                    .and_then(|flow| flow.directions.get_mut(direction_index))
                {
                    direction.advance();
                }
            }
        }
    }

    fn worker_count() -> usize {
        match std::thread::available_parallelism() {
            Ok(count) => count.get().min(8),
            Err(_) => 1,
        }
    }

    fn workers() -> &'static Vec<Arc<Worker>> {
        static WORKERS: OnceLock<Vec<Arc<Worker>>> = OnceLock::new();
        WORKERS.get_or_init(|| {
            (0..worker_count())
                .filter_map(|_| Worker::spawn())
                .collect()
        })
    }

    fn next() -> &'static Worker {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let all = workers();
        let index = NEXT.fetch_add(1, Ordering::Relaxed) % all.len();
        &all[index]
    }

    pub(super) fn available() -> bool {
        !workers().is_empty()
    }

    pub(super) fn drive(
        client_read: Connection,
        target_write: Connection,
        target_read: Connection,
        client_write: Connection,
    ) {
        let worker = next();
        let (first_tx, first_rx) = mpsc::channel();
        let (second_tx, second_rx) = mpsc::channel();
        let first = Direction::new(client_read, target_write, first_tx);
        let second = Direction::new(target_read, client_write, second_tx);
        let _guards = arm_flow(&first, &second);
        worker.push(Flow {
            directions: vec![first, second],
        });
        let _ = first_rx.recv();
        let _ = second_rx.recv();
    }

    /// The arm's truth table, in the two units it mixes: `pending` counts bytes and the
    /// kernel's `EAGAIN` from `splice_to_pipe` counts slots, so a ring that holds bytes with a
    /// stall recorded has byte room and nowhere to put anything. That is the wake the pump must
    /// not take, and `can_drain` staying true over it is what keeps one fd armed, so the
    /// direction waits on the drain instead of spinning on the source.
    #[cfg(test)]
    #[test]
    fn no_pollin_is_armed_on_a_ring_that_holds_bytes_it_cannot_take() {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = front.local_addr().expect("addr").port();
        let src = Connection::connect(("127.0.0.1", port)).expect("dials");
        let (dst, _) = front.accept().expect("accepts");
        let (done, _keeper) = mpsc::channel();
        let mut direction = Direction::new(src, dst, done);
        let Some(pipe) = direction.pipe.as_ref() else {
            panic!("a splice pipe is there to size the ring");
        };
        let capacity = pipe.capacity;

        direction.pending = 0;
        direction.ingest_stalled = true;
        assert!(
            direction.can_ingest(),
            "an empty ring has room whatever the last attempt did"
        );
        assert!(!direction.can_drain(), "an empty ring has nothing to drain");

        direction.pending = capacity / 2;
        direction.ingest_stalled = false;
        assert!(
            direction.can_ingest(),
            "half a ring with no stall recorded is an ingest worth arming for"
        );
        direction.ingest_stalled = true;
        assert!(
            !direction.can_ingest(),
            "the same half ring after an ingest found no slot is a wake that moves nothing"
        );
        assert!(
            direction.can_drain(),
            "the drain that frees a slot stays armed, so the direction waits on an fd rather \
             than spinning on one it cannot serve"
        );

        direction.pending = capacity;
        assert!(
            !direction.can_ingest() && direction.can_drain(),
            "a ring full of bytes is the state the byte predicate already refused"
        );

        direction.pending = 0;
        direction.ingest_stalled = false;
        direction.src_at_eof = true;
        assert!(
            !direction.can_ingest(),
            "an exhausted source is never armed"
        );
        direction.src_at_eof = false;
        direction.pipe = None;
        assert!(
            direction.can_ingest(),
            "a leg with no pipe reads its own socket"
        );
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const PATIENCE: Duration = Duration::from_secs(30);

    const REQUEST: &[u8] = b"both ways at once";
    const REPLY: &[u8] = b"and back";

    fn read_all(stream: &mut Connection) -> Vec<u8> {
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return got,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn listener() -> Listener {
        crate::conn::test_bind("127.0.0.1:0").expect("binds")
    }

    fn port_of(listener: &Listener) -> u16 {
        listener.local_addr().expect("addr").port()
    }

    fn relayed(payload: Vec<u8>) -> Vec<u8> {
        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);
        let front_far = thread::spawn(move || {
            let (mut stream, _) = front.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            stream.write_all(&payload).expect("writes");
            let _ = stream.shutdown(Shutdown::Write);
            read_all(&mut stream);
        });
        let back_far = thread::spawn(move || {
            let (mut stream, _) = back.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            read_all(&mut stream)
        });

        let client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        let target = Connection::connect(("127.0.0.1", back_port)).expect("connects");
        let relay_side = thread::spawn(move || relay(&client, &target));

        let got = back_far.join().expect("joins");
        front_far.join().expect("joins");
        relay_side.join().expect("joins");
        got
    }

    #[test]
    fn a_body_of_every_length_survives_the_event_loop() {
        for len in [
            0usize, 1, 63, 64, 65, 4095, 4096, 4097, 65_535, 262_144, 300_000,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                relayed(payload.clone()),
                payload,
                "the event loop moved {len} bytes as something else"
            );
        }
    }

    #[test]
    fn one_flow_carries_both_directions() {
        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);
        let front_far = thread::spawn(move || {
            let (mut stream, _) = front.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            stream.write_all(REQUEST).expect("writes");
            let _ = stream.shutdown(Shutdown::Write);
            read_all(&mut stream)
        });
        let back_far = thread::spawn(move || {
            let (mut stream, _) = back.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            let got = read_all(&mut stream);
            let _ = stream.write_all(REPLY);
            got
        });

        let client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        let target = Connection::connect(("127.0.0.1", back_port)).expect("connects");
        thread::spawn(move || relay(&client, &target))
            .join()
            .expect("joins");

        assert_eq!(
            front_far.join().expect("joins"),
            REPLY,
            "the reply did not survive the client's half-close"
        );
        assert_eq!(
            back_far.join().expect("joins"),
            REQUEST,
            "the bytes were altered on the way through"
        );
    }

    const CHUNK: usize = 65_536;

    /// The client of the stalled flow: `rounds` chunks of `chunk_len` as fast as the socket
    /// takes them, then a half-close, reporting how much got out.
    fn push_until_refused(listener: &Listener, rounds: usize, chunk_len: usize) -> usize {
        let (mut stream, _) = listener.accept().expect("accepts");
        stream.set_write_timeout(Some(PATIENCE)).expect("timeout");
        let body: Vec<u8> = (0..chunk_len).map(|i| (i % 251) as u8).collect();
        let mut written = 0usize;
        for _ in 0..rounds {
            if stream.write_all(&body).is_err() {
                break;
            }
            written += body.len();
        }
        let _ = stream.shutdown(Shutdown::Write);
        written
    }

    /// The destination of the stalled flow: it reads none of the flow until the
    /// neighbours have been collected, then reports how much of it reached it.
    fn hold_then_read(listener: &Listener, release: &mpsc::Receiver<()>) -> usize {
        let (mut stream, _) = listener.accept().expect("accepts");
        stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
        let _ = release.recv();
        read_all(&mut stream).len()
    }

    /// A destination that reads one segment every 2 ms: the flow never fully parks, so neither
    /// does the pump, and a wake the ring cannot serve is one it is handed again a moment later.
    #[cfg(target_os = "linux")]
    fn trickle_then_read(listener: &Listener, release: &mpsc::Receiver<()>, want: usize) -> usize {
        let (mut stream, _) = listener.accept().expect("accepts");
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let mut got = vec![0u8; want];
        let mut total = 0usize;
        while release.try_recv().is_err() {
            match stream.read(&mut got) {
                Ok(0) => return total,
                Ok(n) => total += n,
                Err(_) => {}
            }
            thread::sleep(Duration::from_millis(2));
        }
        let _ = stream.set_read_timeout(Some(PATIENCE));
        total + read_all(&mut stream).len()
    }

    /// One neighbour peer: one chunk, a half-close, and the same bytes back.
    fn write_then_read_back(stream: &mut Connection) -> usize {
        stream.set_write_timeout(Some(PATIENCE)).expect("timeout");
        stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
        let body: Vec<u8> = (0..CHUNK).map(|i| (i % 191) as u8).collect();
        if stream.write_all(&body).is_err() {
            return 0;
        }
        let _ = stream.shutdown(Shutdown::Write);
        read_all(stream).len()
    }

    /// One neighbour origin: it reads the whole body and echoes it back.
    fn read_then_echo_back(stream: &mut Connection) {
        stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
        stream.set_write_timeout(Some(PATIENCE)).expect("timeout");
        let body = read_all(stream);
        if stream.write_all(&body).is_ok() {
            let _ = stream.shutdown(Shutdown::Write);
        }
    }

    /// One flow whose destination stops reading, driven beside sixteen flows that
    /// answer promptly. A destination that is merely slow must make that flow
    /// wait; it must not take the flows behind it down with it, and it does: one
    /// `advance` runs both legs on any wake, and `SPLICE_F_NONBLOCK` only keeps the
    /// *pipe* side from blocking, so the leg `poll` never reported ready is spliced
    /// on a descriptor nobody said was able to take it — which parks the worker
    /// inside the kernel instead of answering `EAGAIN`. Every other flow queued on
    /// that worker freezes with it, which is how one stalled connection becomes
    /// five unrelated red tests. Sixteen neighbours over at most eight workers
    /// guarantees at least two of them share the parked one, so the freeze names
    /// itself. The fallback copy path gives every direction its own thread and
    /// cannot be poisoned, so the witness is the Linux job. Loopback only, dials
    /// nothing.
    #[test]
    fn a_stalled_destination_does_not_freeze_the_flows_behind_it() {
        const ROUNDS: usize = 512;
        const NEIGHBOURS: usize = 16;

        let stalled_front = listener();
        let stalled_front_port = port_of(&stalled_front);
        let stalled_back = listener();
        let stalled_back_port = port_of(&stalled_back);
        let (release, drain_now) = mpsc::channel::<()>();
        let feeding = thread::spawn(move || push_until_refused(&stalled_front, ROUNDS, CHUNK));
        let draining = thread::spawn(move || hold_then_read(&stalled_back, &drain_now));
        let stalled_client = Connection::connect(("127.0.0.1", stalled_front_port)).expect("dials");
        let stalled_target = Connection::connect(("127.0.0.1", stalled_back_port)).expect("dials");
        let (ended, returned) = mpsc::channel::<()>();
        let stalled_side = ended.clone();
        let stalled_relay = thread::spawn(move || {
            relay(&stalled_client, &stalled_target);
            let _ = stalled_side.send(());
        });

        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);
        let (seen, counted) = mpsc::channel();
        let peers = thread::spawn(move || {
            let mut feeders = Vec::with_capacity(NEIGHBOURS);
            for _ in 0..NEIGHBOURS {
                let (mut stream, _) = front.accept().expect("accepts");
                let seen = seen.clone();
                feeders.push(thread::spawn(move || {
                    let _ = seen.send(write_then_read_back(&mut stream));
                }));
            }
            feeders
        });
        let echo = thread::spawn(move || {
            for _ in 0..NEIGHBOURS {
                let (mut stream, _) = back.accept().expect("accepts");
                thread::spawn(move || read_then_echo_back(&mut stream));
            }
        });

        for _ in 0..NEIGHBOURS {
            let client = Connection::connect(("127.0.0.1", front_port)).expect("dials");
            let target = Connection::connect(("127.0.0.1", back_port)).expect("dials");
            let closed = ended.clone();
            thread::spawn(move || {
                relay(&client, &target);
                let _ = closed.send(());
            });
        }
        drop(ended);

        let mut arrived = Vec::with_capacity(NEIGHBOURS);
        while arrived.len() < NEIGHBOURS {
            match counted.recv_timeout(PATIENCE) {
                Ok(len) => arrived.push(len),
                Err(_) => break,
            }
        }
        let _ = release.send(());
        let held = draining.join().expect("joins");
        let pushed = feeding.join().expect("joins");
        for feeder in peers.join().expect("joins") {
            feeder.join().expect("joins");
        }
        echo.join().expect("joins");

        let mut closed = 0usize;
        while closed < NEIGHBOURS + 1 {
            match returned.recv_timeout(PATIENCE) {
                Ok(()) => closed += 1,
                Err(_) => break,
            }
        }

        assert!(
            arrived.len() == NEIGHBOURS && arrived.iter().all(|len| *len == CHUNK),
            "a flow with a stalled destination was driven beside {NEIGHBOURS} that answer \
             promptly: {arrived:?} of them came back with {CHUNK} bytes, and the stalled one had \
             {pushed} written and {held} drained"
        );
        assert_eq!(
            closed,
            NEIGHBOURS + 1,
            "the flows a parked worker was holding never closed with it"
        );
        assert_eq!(
            held, pushed,
            "the stalled flow did not carry everything its client managed to write ({pushed} \
             bytes) once its destination read again ({held} drained)"
        );
        stalled_relay.join().expect("joins");
    }

    /// A pipe ring's slots go before its bytes: 512-byte segments arriving one wake at a time
    /// stuff the ring at its slot ceiling while byte room remains, so an honest `POLLIN` still
    /// has nowhere to put what it sees. The destination has to be *moving* for that to spin —
    /// measured against a pump that re-arms the wake, this shape cost 78 183 of its 79 013
    /// wakes as ingest splices that moved nothing in a 400 ms window, with the pump's cpu at
    /// the whole of it, while a destination that reads nothing at all parks the ring full and
    /// registers none. The same window on the shipped pump measures 2, and the limit is the
    /// distance between those two with room for the rest of the suite's flows. Loopback only;
    /// the Linux job owns the splice pump.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_trickling_destination_does_not_spin_the_pump() {
        const SEGMENT: usize = 512;
        const ROUNDS: usize = 8_192;
        const WINDOW: Duration = Duration::from_millis(400);
        const SPIN_LIMIT: usize = 1_000;

        let stalled_front = listener();
        let stalled_front_port = port_of(&stalled_front);
        let stalled_back = listener();
        let stalled_back_port = port_of(&stalled_back);
        let (release, drain_now) = mpsc::channel::<()>();
        let feeding = thread::spawn(move || push_until_refused(&stalled_front, ROUNDS, SEGMENT));
        let draining = thread::spawn(move || trickle_then_read(&stalled_back, &drain_now, SEGMENT));
        let stalled_client = Connection::connect(("127.0.0.1", stalled_front_port)).expect("dials");
        let stalled_target = Connection::connect(("127.0.0.1", stalled_back_port)).expect("dials");
        let stalled_relay = thread::spawn(move || relay(&stalled_client, &stalled_target));

        thread::sleep(Duration::from_millis(200));
        let before = poll_relay::idle_ingests();
        thread::sleep(WINDOW);
        let idle = poll_relay::idle_ingests().saturating_sub(before);

        let _ = release.send(());
        let held = draining.join().expect("joins");
        let pushed = feeding.join().expect("joins");
        stalled_relay.join().expect("joins");

        assert!(
            idle < SPIN_LIMIT,
            "the pump ran {idle} ingest splices that moved nothing across a {} ms window of a \
             flow whose ring was out of slots: a wake the ring cannot serve must not be re-armed",
            WINDOW.as_millis(),
        );
        assert_eq!(
            held, pushed,
            "the trickling flow carried {held} bytes of the {pushed} its client wrote"
        );
    }

    /// The two clones `relay_carried` shares one socket: a finished upload used
    /// to `shutdown(Both)` it, aborting the download direction's still-open read
    /// so the reply never arrived. The upload here is already empty, so the relay
    /// reaches its teardown before the target answers; only a `Write` half-close
    /// leaves the peer's read intact for the sibling thread to carry the reply.
    /// Loopback only, dials nothing.
    #[test]
    fn a_finished_upload_does_not_drop_the_response() {
        let carrier = listener();
        let carrier_port = port_of(&carrier);
        let target = listener();
        let target_port = port_of(&target);

        let answered = thread::spawn(move || {
            let (mut stream, _) = target.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            let _ = read_all(&mut stream);
            stream.write_all(REPLY).expect("answers");
            let _ = stream.shutdown(Shutdown::Write);
        });
        let collected = thread::spawn(move || {
            let (mut stream, _) = carrier.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            read_all(&mut stream)
        });

        let write = Connection::connect(("127.0.0.1", carrier_port)).expect("dials carrier");
        let peer = Connection::connect(("127.0.0.1", target_port)).expect("dials target");
        let reader: &[u8] = &[];
        relay_carried(reader, &write, &peer);

        answered.join().expect("target joins");
        let got = collected.join().expect("carrier joins");
        assert_eq!(got, REPLY, "a finished upload must not drop the reply");
    }

    /// One user, one reader and one relay thread per flow, all sixteen running at once, each flow
    /// moving thirty-two splice pipes' worth: the multi-connection regime the references sustain at
    /// gigabits, and the one a stalled flow poisons for its neighbours. Every count a stall needs to
    /// name itself is published, so the failure says which flow, how far in, how far out and how
    /// many relays ended. Loopback only, dials nothing.
    #[test]
    fn sixteen_flows_at_once_all_arrive_whole() {
        const FLOWS: usize = 16;
        const CHUNK: usize = 65_536;
        const ROUNDS: usize = 128;
        const LEN: usize = CHUNK * ROUNDS;
        let front = Arc::new(listener());
        let front_port = port_of(&front);
        let back = Arc::new(listener());
        let back_port = port_of(&back);

        let sent: Arc<[std::sync::atomic::AtomicUsize]> = (0..FLOWS)
            .map(|_| std::sync::atomic::AtomicUsize::new(0))
            .collect();

        let mut users = Vec::with_capacity(FLOWS);
        for user in 0..FLOWS {
            let sent = Arc::clone(&sent);
            let front = Arc::clone(&front);
            users.push(thread::spawn(move || {
                let (mut stream, _) = front.accept().expect("accepts");
                stream.set_write_timeout(Some(PATIENCE)).expect("timeout");
                let chunk: Vec<u8> = (0..CHUNK).map(|i| ((i + user) % 251) as u8).collect();
                let mut wrote = 0usize;
                for _ in 0..ROUNDS {
                    if stream.write_all(&chunk).is_err() {
                        break;
                    }
                    wrote += CHUNK;
                    sent[user].store(wrote, Ordering::Relaxed);
                }
                let _ = stream.shutdown(Shutdown::Write);
                // handed back so the kernel's unsent bytes live until the counts are read
                stream
            }));
        }
        let mut readers = Vec::with_capacity(FLOWS);
        for _ in 0..FLOWS {
            let back = Arc::clone(&back);
            readers.push(thread::spawn(move || {
                let (mut stream, _) = back.accept().expect("accepts");
                stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
                let mut arrived = 0usize;
                let mut chunk = vec![0u8; CHUNK];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => return arrived,
                        Ok(took) => arrived += took,
                    }
                }
            }));
        }

        let (ended, watched) = mpsc::channel();
        let mut relays = Vec::with_capacity(FLOWS);
        for _ in 0..FLOWS {
            let client = Connection::connect(("127.0.0.1", front_port)).expect("connects");
            let target = Connection::connect(("127.0.0.1", back_port)).expect("connects");
            let ended = ended.clone();
            relays.push(thread::spawn(move || {
                relay(&client, &target);
                let _ = ended.send(());
            }));
        }
        drop(ended);

        let arrived: Vec<usize> = readers
            .into_iter()
            .map(|reader| reader.join().expect("reads"))
            .collect();
        let mut finished = 0usize;
        for _ in 0..FLOWS {
            if watched.recv_timeout(PATIENCE).is_err() {
                break;
            }
            finished += 1;
        }
        let written: Vec<usize> = (0..FLOWS)
            .map(|user| sent[user].load(Ordering::Relaxed))
            .collect();
        assert!(
            arrived.iter().all(|count| *count == LEN) && finished == FLOWS,
            "{FLOWS} concurrent flows of {LEN} bytes each arrived {arrived:?}, were written \
             {written:?}, and {finished} of {FLOWS} relays ended"
        );

        for user in users {
            user.join().expect("feeds");
        }
        for relay_side in relays {
            relay_side.join().expect("joins");
        }
    }
}

#[cfg(test)]
mod foxy_exit_tests {
    use super::{
        exit_agrees, pick_verified_edge, probe_settled, probes_reachable, sweep_verdict, Sweep,
    };

    #[test]
    fn a_sweep_that_reached_the_edges_and_agreed_with_none_is_itself_an_answer() {
        assert_eq!(
            sweep_verdict(&[Some(false), Some(true), Some(true)]),
            Sweep::Agreed(1),
            "a pick beats every refusal before and after it"
        );
        assert_eq!(
            sweep_verdict(&[Some(false), Some(false)]),
            Sweep::Refuted,
            "the pin is not what this runner gets, and asking again buys the same refusal"
        );
        assert_eq!(
            sweep_verdict(&[None, Some(false)]),
            Sweep::Refuted,
            "one edge answering wrongly is still an answer"
        );
        assert_eq!(
            sweep_verdict(&[None, None]),
            Sweep::Unreachable,
            "nothing answering means this runner cannot carry a probe at all"
        );
        assert_eq!(
            sweep_verdict(&[]),
            Sweep::Unreachable,
            "and no edge to ask is the same verdict"
        );
    }

    #[test]
    fn a_pinned_country_accepts_its_own_exit_and_refuses_a_single_edge_anycast_that_egresses_elsewhere(
    ) {
        assert!(exit_agrees("US", "US"));
        assert!(exit_agrees("us", "US"));
        assert!(!exit_agrees("US", "CA"));
        assert!(
            exit_agrees(ferrox_core::foxy::catalog::RECOMMENDED, "CA"),
            "the recommended location accepts wherever the nearest edge exits"
        );
    }

    #[test]
    fn the_preferred_edge_is_the_first_one_whose_exit_agrees_not_the_first_one_opened() {
        // A `us` label that egresses elsewhere must not win over the next edge that truly exits US.
        assert_eq!(
            pick_verified_edge(&[Some(false), Some(true), Some(true)]),
            Some(1)
        );
        assert_eq!(
            pick_verified_edge(&[None, Some(false), Some(true)]),
            Some(2)
        );
        assert_eq!(pick_verified_edge(&[Some(true)]), Some(0));
    }

    #[test]
    fn no_agreeing_exit_leaves_the_label_order_untouched_rather_than_pinning_a_wrong_edge() {
        assert_eq!(pick_verified_edge(&[]), None);
        assert_eq!(pick_verified_edge(&[Some(false), None, Some(false)]), None);
    }

    #[test]
    fn a_runner_that_carries_no_probe_stops_trying_instead_of_failing_every_flow() {
        assert!(!probes_reachable(&[None, None, None]));
        assert!(probes_reachable(&[None, Some(false)]));
        assert!(!probes_reachable(&[]));
    }

    #[test]
    fn the_walk_ends_at_the_agreeing_edge_without_losing_the_pick() {
        for answers in [
            vec![Some(true)],
            vec![Some(false), Some(true), Some(false)],
            vec![None, Some(false), Some(true), None],
            vec![Some(false), None, Some(false)],
            vec![None, None],
            vec![],
        ] {
            let whole = pick_verified_edge(&answers);
            // The walk truncates where `probe_settled` first fires; the truncated table must pick the same edge.
            let mut walked = 0usize;
            while walked < answers.len() {
                walked += 1;
                if probe_settled(&answers[..walked]) {
                    break;
                }
            }
            assert_eq!(
                whole,
                pick_verified_edge(&answers[..walked]),
                "{walked} probe(s) of {answers:?} lost the pick"
            );
        }
    }
}

#[cfg(test)]
mod census_tests {
    use super::*;
    use crate::census;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const PATIENCE: Duration = Duration::from_secs(10);

    /// A stream that answers nothing until its lift is dropped: the in-memory peer a census dump is taken against.
    struct Silent {
        until_lifted: mpsc::Receiver<()>,
    }

    impl Read for Silent {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            let _ = self.until_lifted.recv();
            Ok(0)
        }
    }

    /// The census line a parked thread's named wait holds, once it is there: registration happens on that thread, so a dump taken too early says nothing yet.
    fn wait_for(name: &str, waiter: std::thread::ThreadId) -> String {
        let until = Instant::now() + PATIENCE;
        loop {
            if let Some(found) = census::held(name, waiter) {
                return found;
            }
            assert!(
                Instant::now() < until,
                "`{name}` never registered itself in the census:\n{}",
                census::dump()
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn a_parked_leg_read_names_the_descriptor_it_waits_on() {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let back = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let back_port = back.local_addr().expect("addr").port();
        let reader = Connection::connect(("127.0.0.1", front_port)).expect("connects");
        let sink = Connection::connect(("127.0.0.1", back_port)).expect("connects");
        // Both peers stay open and say nothing, so the only progress a leg can make is its own bound.
        let _silent_front = front.accept().map(|(stream, _)| stream).expect("accepts");
        let _silent_back = back.accept().map(|(stream, _)| stream).expect("accepts");
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bounds the leg");
        let (reports, reported) = mpsc::channel();
        let leg = thread::spawn(move || {
            let mut reader = reader;
            let mut sink = sink;
            let _ = reports.send((census::handle(&reader), census::handle(&sink)));
            copy_all_memcpy(&mut reader, &mut sink);
        });
        let leg_id = leg.thread().id();
        let (read_fd, write_fd) = reported
            .recv_timeout(PATIENCE)
            .expect("the leg reports both descriptors");
        assert_ne!(
            read_fd, write_fd,
            "one descriptor for both legs proves nothing"
        );
        let held = wait_for("relay-leg-read", leg_id);
        assert!(held.contains(&format!("fd={read_fd} ")), "{held}");
        // A raw relay leg holds no deadline at its wait: its caller restores `None`, so the census says none.
        assert!(held.contains("armed=none "), "{held}");
        leg.join().expect("joins");
        assert!(
            census::held("relay-leg-read", leg_id).is_none(),
            "a returned leg is still in the census:\n{}",
            census::dump()
        );
    }

    #[test]
    fn a_parked_tunnel_leg_reports_the_time_it_has_waited() {
        // Dropping the sender is what lifts the park, so the leg returns on its own.
        let (lift, until_lifted) = mpsc::channel::<()>();
        let leg = thread::spawn(move || {
            let half = Half::new(Silent { until_lifted });
            half.read_once(&mut [0u8; 16])
        });
        let leg_id = leg.thread().id();
        let held = wait_for("tunnel-leg-read", leg_id);
        // A leg through the shared relay half is a `dyn Read`, so no descriptor reaches its census line.
        assert!(held.contains("fd=none "), "{held}");
        thread::sleep(Duration::from_millis(30));
        let held =
            census::held("tunnel-leg-read", leg_id).expect("the leg left the census while parked");
        assert!(census::number(&held, "waited") >= 30, "{held}");
        drop(lift);
        leg.join().expect("joins").expect("reads");
        assert!(
            census::held("tunnel-leg-read", leg_id).is_none(),
            "a returned leg is still in the census:\n{}",
            census::dump()
        );
    }

    #[test]
    fn a_parked_join_reports_the_budget_it_armed() {
        let (handed, receiver) = mpsc::channel::<()>();
        let budget = Duration::from_millis(500);
        let waiter = thread::spawn(move || join_within(&receiver, budget));
        let waiter_id = waiter.thread().id();
        let held = wait_for("relay-join", waiter_id);
        assert!(held.contains("armed=500ms "), "{held}");
        assert!(held.contains("fd=none "), "{held}");
        thread::sleep(Duration::from_millis(30));
        let held =
            census::held("relay-join", waiter_id).expect("the join left the census while parked");
        assert!(census::number(&held, "waited") >= 30, "{held}");
        // A partner whose sender is gone hands back on its own, so the park ends before its budget.
        drop(handed);
        assert!(
            waiter.join().expect("joins"),
            "a gone partner is not a finished flow"
        );
        assert!(
            census::held("relay-join", waiter_id).is_none(),
            "a returned join is still in the census:\n{}",
            census::dump()
        );
    }
}
