//! The `Psiphon` lane: the psiphon-tunnel-core console client as its own program, its local SOCKS listener read from the notices it writes, and every flow dialled through that listener by the tree's SOCKS client. The client owns the tunnel, its shaping and its server list; this lane owns only the config it is started with and the wait for its first tunnel.

use crate::json::{self, Json};
use crate::socks::{Credential, Version};
use ferrox_core::psiphon::{self, Notice, Shape};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PROPAGATION_CHANNEL_ID: &str = "FFFFFFFFFFFFFFFF";
const SPONSOR_ID: &str = "FFFFFFFFFFFFFFFF";

/// The lane's process and the endpoint it announced. The child is behind a mutex because the
/// readiness reader owns the pipes while the lane owns the process, and a drop has to be able to
/// end it without waiting for a tunnel that may never open.
#[derive(Debug)]
struct Process {
    child: Mutex<Option<Child>>,
    stopping: Arc<AtomicBool>,
}

impl Drop for Process {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Ok(mut slot) = self.child.lock() {
            if let Some(mut child) = slot.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// The outbound as a flow sees it: a started client and the local SOCKS lane that answers it.
#[derive(Debug, Clone)]
pub(crate) struct PsiphonOut {
    _process: Arc<Process>,
    endpoint: SocketAddr,
    credential: Arc<Credential>,
    version: Version,
}

impl PsiphonOut {
    /// Start the client and wait for its first tunnel, so a bad binary or a blocked network is a
    /// startup refusal rather than an error on every flow.
    pub(crate) fn new(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        let credential = settings.credential();
        let (endpoint, child, stopping) = start(&settings)?;
        Ok(Self {
            _process: Arc::new(Process {
                child: Mutex::new(Some(child)),
                stopping,
            }),
            endpoint,
            credential: Arc::new(credential),
            version: Version::V5,
        })
    }

    /// Validate the config without starting the client, so `-test` proves the lane offline.
    pub(crate) fn validate(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        build_config(&settings)?;
        let credential = settings.credential();
        let endpoint = SocketAddr::new(
            dial_ip(effective_ip(settings.listen, settings.interface.as_deref())),
            settings.listen.port(),
        );
        Ok(Self {
            _process: Arc::new(Process {
                child: Mutex::new(None),
                stopping: Arc::new(AtomicBool::new(false)),
            }),
            endpoint,
            credential: Arc::new(credential),
            version: Version::V5,
        })
    }

    /// The local SOCKS server's credential, empty unless the config named a pair.
    pub(crate) fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The SOCKS version the client's listener speaks.
    pub(crate) fn version(&self) -> Version {
        self.version
    }

    /// The announced endpoint, already parsed, so a flow neither formats nor parses it again.
    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

/// Everything the client is started with, resolved once so a flow pays none of it.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct Settings {
    binary: Option<PathBuf>,
    state: PathBuf,
    listen: SocketAddr,
    http: Option<SocketAddr>,
    interface: Option<String>,
    region: Option<String>,
    shape: Shape,
    upstream: Option<String>,
    entries: Option<PathBuf>,
    base: Option<PathBuf>,
    ready: Duration,
    server_list: String,
    propagation: String,
    sponsor: String,
    client_platform: String,
    cdn_ips: Vec<String>,
    cdn_sni: Vec<String>,
    cdn_sets: Vec<String>,
    cdn_profile: Option<String>,
    geo_ip: Option<PathBuf>,
    inproxy_compartment: Option<String>,
    reject_proxy_countries: Vec<String>,
    disable_timeouts: bool,
    dns_alternate: Vec<String>,
    device_location: Option<String>,
    device_region: Option<String>,
    network_id: Option<String>,
    additional_parameters: Option<String>,
    establish_timeout: Option<u64>,
    emit_bytes_transferred: bool,
    split_own_region: bool,
    split_regions: Vec<String>,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    client_features: Vec<String>,
    latency: Option<f64>,
    tls_profiles: Vec<String>,
    quic_versions: Vec<String>,
    tunnel_pool: Option<u64>,
    workers: Option<u64>,
    aggressive: bool,
    limit_meek: bool,
    limit_relay: bool,
    limit_cpu: bool,
    initial_protocols: Vec<String>,
    initial_count: Option<u64>,
}

impl Settings {
    #[allow(clippy::too_many_lines)]
    fn from_json(settings: Option<&Json>) -> Result<Self, String> {
        let listen = listen_address(settings)?;
        let http = http_address(settings)?;
        let region = match text(settings, "region").or_else(|| env("AETHER_PSIPHON_REGION")) {
            Some(code) => Some(psiphon::region(&code).ok_or_else(|| {
                format!("psiphon: region {code:?} is not a two-letter country code")
            })?),
            None => None,
        };
        let shape = text(settings, "shape")
            .or_else(|| env("AETHER_PSIPHON_MODE"))
            .map_or(Shape::Auto, |word| Shape::parse(&word));
        let device_region =
            match text(settings, "deviceRegion").or_else(|| env("AETHER_PSIPHON_DEVICE_REGION")) {
                Some(code) => Some(psiphon::region(&code).ok_or_else(|| {
                    format!("psiphon: deviceRegion {code:?} is not a two-letter country code")
                })?),
                None => None,
            };
        let reject_censored_proxies = flag(
            settings,
            "rejectCensoredProxies",
            "AETHER_PSIPHON_REJECT_CENSORED_PROXIES",
        );
        let mut reject_proxy_countries = region_list(
            settings,
            "rejectProxyCountries",
            "AETHER_PSIPHON_REJECT_COUNTRIES",
        )?;
        if reject_censored_proxies {
            reject_proxy_countries.extend(psiphon::CENSORED_PROXY_COUNTRIES.map(str::to_owned));
            reject_proxy_countries.sort_unstable();
            reject_proxy_countries.dedup();
        }
        let explicit = text(settings, "interface").or_else(|| env("AETHER_PSIPHON_INTERFACE"));
        if let Some(name) = explicit.as_deref() {
            if name != "any" && (listen.ip().is_loopback() || listen.ip().is_unspecified()) {
                return Err(format!(
                    "psiphon: interface {name:?} makes the client listen on that interface's address; set listen to that address"
                ));
            }
        }
        let interface = explicit.or_else(|| interface_name(listen.ip()));
        let base = text(settings, "baseConfig")
            .or_else(|| env("AETHER_PSIPHON_CONFIG"))
            .map(PathBuf::from);
        let state = text(settings, "dataRootDirectory")
            .or_else(|| env("AETHER_PSIPHON_DIR"))
            .map_or_else(
                || {
                    base.as_ref().map_or_else(default_state, |path| {
                        PathBuf::from(format!("{}-psiphon", path.display()))
                    })
                },
                PathBuf::from,
            );
        let proxy_user =
            text(settings, "localProxyUsername").or_else(|| env("AETHER_PSIPHON_PROXY_USER"));
        let proxy_pass =
            text(settings, "localProxyPassword").or_else(|| env("AETHER_PSIPHON_PROXY_PASS"));
        if proxy_user.is_some() != proxy_pass.is_some() {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must be named together"
                    .to_owned(),
            );
        }
        if proxy_user.as_ref().is_some_and(|user| user.len() > 255)
            || proxy_pass.as_ref().is_some_and(|pass| pass.len() > 255)
        {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must each be at most 255 bytes"
                    .to_owned(),
            );
        }
        let ready = text(settings, "readySeconds")
            .or_else(|| {
                settings
                    .and_then(|settings| settings.get("readySeconds"))
                    .and_then(Json::as_u32)
                    .map(|value| value.to_string())
            })
            .or_else(|| env("AETHER_PSIPHON_READY_SECS"))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map_or(psiphon::READY_SECS, |value| value.min(86_400));
        Ok(Self {
            binary: text(settings, "binary")
                .or_else(|| env("AETHER_PSIPHON_BIN"))
                .map(PathBuf::from),
            state,
            listen,
            http,
            interface,
            region,
            shape,
            upstream: text(settings, "upstreamProxy").or_else(|| text(settings, "upstream")),
            entries: server_entries(settings),
            base,
            ready: Duration::from_secs(ready),
            server_list: text(settings, "serverListURL")
                .or_else(|| env("AETHER_PSIPHON_SERVER_LIST"))
                .unwrap_or_else(|| psiphon::SERVER_LIST_URL.to_owned()),
            propagation: text(settings, "propagationChannelId")
                .or_else(|| env("AETHER_PSIPHON_PROPAGATION_CHANNEL_ID"))
                .unwrap_or_else(|| PROPAGATION_CHANNEL_ID.to_owned()),
            sponsor: text(settings, "sponsorId")
                .or_else(|| env("AETHER_PSIPHON_SPONSOR_ID"))
                .unwrap_or_else(|| SPONSOR_ID.to_owned()),
            client_platform: text(settings, "clientPlatform")
                .or_else(|| env("AETHER_PSIPHON_CLIENT_PLATFORM"))
                .unwrap_or_else(client_platform),
            cdn_ips: list(settings, "cdnIps", "AETHER_PSIPHON_CDN_IPS"),
            cdn_sni: list(settings, "cdnSni", "AETHER_PSIPHON_CDN_SNI"),
            cdn_sets: list(settings, "cdnSets", "AETHER_PSIPHON_CDN_SETS"),
            cdn_profile: text(settings, "cdnProfile")
                .or_else(|| env("AETHER_PSIPHON_CDN_PROFILE"))
                .map(|word| word.to_ascii_lowercase()),
            geo_ip: text(settings, "geoIp")
                .or_else(|| env("AETHER_PSIPHON_GEOIP"))
                .map(PathBuf::from)
                .filter(|path| {
                    if path.is_file() {
                        true
                    } else {
                        eprintln!("psiphon: GeoIP database {} is not a file", path.display());
                        false
                    }
                }),
            inproxy_compartment: text(settings, "inproxyCompartment")
                .or_else(|| env("AETHER_PSIPHON_COMPARTMENT")),
            reject_proxy_countries,
            disable_timeouts: flag(
                settings,
                "disableTimeouts",
                "AETHER_PSIPHON_DISABLE_TIMEOUTS",
            ),
            dns_alternate: list(
                settings,
                "dnsResolverAlternateServers",
                "AETHER_PSIPHON_DNS_ALTERNATE",
            ),
            device_location: text(settings, "deviceLocation")
                .or_else(|| env("AETHER_PSIPHON_DEVICE_LOCATION")),
            device_region,
            network_id: text(settings, "networkId").or_else(|| env("AETHER_PSIPHON_NETWORK_ID")),
            additional_parameters: text(settings, "additionalParameters")
                .or_else(|| env("AETHER_PSIPHON_ADDITIONAL_PARAMETERS")),
            establish_timeout: integer(
                settings,
                "establishTunnelTimeoutSeconds",
                "AETHER_PSIPHON_ESTABLISH_TIMEOUT",
            )
            .filter(|value| *value > 0),
            emit_bytes_transferred: flag(
                settings,
                "emitBytesTransferred",
                "AETHER_PSIPHON_EMIT_BYTES",
            ),
            split_own_region: flag(
                settings,
                "splitTunnelOwnRegion",
                "AETHER_PSIPHON_SPLIT_OWN_REGION",
            ),
            split_regions: region_list(
                settings,
                "splitTunnelRegions",
                "AETHER_PSIPHON_SPLIT_REGIONS",
            )?,
            proxy_user,
            proxy_pass,
            client_features: list(settings, "clientFeatures", "AETHER_PSIPHON_FEATURES"),
            latency: decimal(
                settings,
                "networkLatencyMultiplier",
                "AETHER_PSIPHON_LATENCY",
            )
            .filter(|value| *value >= 1.0),
            tls_profiles: list(settings, "limitTlsProfiles", "AETHER_PSIPHON_TLS_PROFILES"),
            quic_versions: list(
                settings,
                "limitQuicVersions",
                "AETHER_PSIPHON_QUIC_VERSIONS",
            ),
            tunnel_pool: integer(settings, "tunnelPoolSize", "AETHER_PSIPHON_TUNNEL_POOL")
                .filter(|value| *value > 0),
            workers: integer(
                settings,
                "connectionWorkerPoolSize",
                "AETHER_PSIPHON_WORKERS",
            )
            .filter(|value| *value > 0),
            aggressive: flag(
                settings,
                "aggressiveEstablishment",
                "AETHER_PSIPHON_AGGRESSIVE",
            ),
            limit_meek: flag(
                settings,
                "limitMeekBufferSizes",
                "AETHER_PSIPHON_LIMIT_MEEK",
            ),
            limit_relay: flag(
                settings,
                "limitRelayBufferSizes",
                "AETHER_PSIPHON_LIMIT_RELAY",
            ),
            limit_cpu: flag(settings, "limitCpuThreads", "AETHER_PSIPHON_LIMIT_CPU"),
            initial_protocols: list(
                settings,
                "initialLimitTunnelProtocols",
                "AETHER_PSIPHON_INITIAL_PROTOCOLS",
            ),
            initial_count: integer(
                settings,
                "initialLimitTunnelProtocolsCandidateCount",
                "AETHER_PSIPHON_INITIAL_COUNT",
            )
            .filter(|value| *value > 0),
        })
    }

    fn credential(&self) -> Credential {
        Credential {
            user: self.proxy_user.clone().unwrap_or_default(),
            pass: self.proxy_pass.clone().unwrap_or_default(),
        }
    }
}

/// The first outbound is `psiphon`, built and started. A config that names another protocol answers `None`.
pub(crate) fn psiphon_outbound(root: &Json, test: bool) -> Result<Option<PsiphonOut>, String> {
    let Some(outbound) = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .and_then(|outbounds| outbounds.first())
    else {
        return Ok(None);
    };
    if outbound.get("protocol").and_then(Json::as_str) != Some("psiphon") {
        return Ok(None);
    }
    let settings = outbound.get("settings");
    if test {
        PsiphonOut::validate(settings).map(Some)
    } else {
        PsiphonOut::new(settings).map(Some)
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var_os(name)
        .and_then(|value| value.into_string().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn text(settings: Option<&Json>, key: &str) -> Option<String> {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn list(settings: Option<&Json>, key: &str, environment: &str) -> Vec<String> {
    let listed = settings.and_then(|settings| settings.get(key));
    if let Some(items) = listed.and_then(Json::as_arr) {
        return items
            .iter()
            .filter_map(Json::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(text) = listed.and_then(Json::as_str) {
        return split_list(text);
    }
    env(environment)
        .map(|text| split_list(&text))
        .unwrap_or_default()
}

fn region_list(
    settings: Option<&Json>,
    key: &str,
    environment: &str,
) -> Result<Vec<String>, String> {
    let mut codes = list(settings, key, environment)
        .into_iter()
        .map(|code| {
            psiphon::region(&code)
                .ok_or_else(|| format!("psiphon: {key} {code:?} is not a two-letter country code"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    codes.sort_unstable();
    codes.dedup();
    Ok(codes)
}

fn split_list(text: &str) -> Vec<String> {
    text.split([',', ' ', '\t', '\n', '\r', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn flag(settings: Option<&Json>, key: &str, environment: &str) -> bool {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_bool)
        .or_else(|| {
            env(environment).map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
        })
        .unwrap_or(false)
}

fn number(settings: Option<&Json>, key: &str) -> Option<f64> {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(|value| match value {
            Json::Num(number) => Some(*number),
            Json::Str(text) => text.trim().parse::<f64>().ok(),
            _ => None,
        })
}

fn integer(settings: Option<&Json>, key: &str, environment: &str) -> Option<u64> {
    number(settings, key)
        .or_else(|| env(environment).and_then(|value| value.parse::<f64>().ok()))
        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
        .map(|value| value as u64)
}

fn decimal(settings: Option<&Json>, key: &str, environment: &str) -> Option<f64> {
    number(settings, key)
        .or_else(|| env(environment).and_then(|value| value.parse::<f64>().ok()))
        .filter(|value| value.is_finite())
}

fn client_platform() -> String {
    let system = if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "android") {
        "Android"
    } else {
        "Linux"
    };
    format!("{system}_ferrox")
}

#[cfg(unix)]
fn current_uid() -> libc::uid_t {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

#[cfg(unix)]
fn state_is_owned(state: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(state)
        .map_err(|error| format!("psiphon state dir {}: {error}", state.display()))?
        .uid();
    if owner == current_uid() {
        return Ok(());
    }
    Err(format!(
        "psiphon state dir {} is not owned by the current user",
        state.display()
    ))
}

#[cfg(not(unix))]
fn state_is_owned(_state: &Path) -> Result<(), String> {
    Ok(())
}

fn default_state() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(dir).join("ferrox/psiphon");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/state/ferrox/psiphon");
    }
    #[cfg(unix)]
    return std::env::temp_dir().join(format!("ferrox-psiphon-{}", current_uid()));
    #[cfg(not(unix))]
    std::env::temp_dir().join("ferrox-psiphon")
}

fn listen_address(settings: Option<&Json>) -> Result<SocketAddr, String> {
    let text = text(settings, "listen")
        .or_else(|| env("AETHER_PSIPHON_BIND"))
        .unwrap_or_else(|| psiphon::DEFAULT_BIND.to_owned());
    let address = text
        .parse::<SocketAddr>()
        .map_err(|_| format!("psiphon: listen {text:?} is not an address and a port"))?;
    Ok(if address.port() == 0 {
        SocketAddr::new(address.ip(), free_port(address.ip())?)
    } else {
        address
    })
}

fn http_address(settings: Option<&Json>) -> Result<Option<SocketAddr>, String> {
    let Some(text) = text(settings, "httpListen").or_else(|| env("AETHER_PSIPHON_HTTP")) else {
        return Ok(None);
    };
    if text == "off" {
        return Ok(None);
    }
    let address = text
        .parse::<SocketAddr>()
        .map_err(|_| format!("psiphon: httpListen {text:?} is not an address and a port"))?;
    Ok(Some(if address.port() == 0 {
        SocketAddr::new(address.ip(), free_port(address.ip())?)
    } else {
        address
    }))
}

fn free_port(ip: IpAddr) -> Result<u16, String> {
    let socket = TcpListener::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("psiphon: no local port on {ip}: {error}"))?;
    socket
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("psiphon: the local port did not read back: {error}"))
}

fn interface_name(ip: IpAddr) -> Option<String> {
    if ip.is_loopback() {
        return None;
    }
    if ip.is_unspecified() {
        return Some("any".to_owned());
    }
    eprintln!(
        "psiphon: it names an interface rather than an address, so it listens on loopback; name settings.interface or bind 0.0.0.0 to listen elsewhere"
    );
    None
}

fn effective_ip(listen: SocketAddr, interface: Option<&str>) -> IpAddr {
    match interface {
        Some("any") => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Some(_) => listen.ip(),
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

fn dial_ip(ip: IpAddr) -> IpAddr {
    if ip.is_unspecified() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        ip
    }
}

fn binary(given: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = given {
        return path
            .is_file()
            .then(|| path.to_path_buf())
            .ok_or_else(|| format!("psiphon: binary {} is not a file", path.display()));
    }
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    for dir in search_dirs() {
        for name in psiphon::BINARY_NAMES {
            let candidate = dir.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(install_hint())
}

fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(here) = exe.parent() {
            dirs.push(here.to_path_buf());
            dirs.push(here.join("pt"));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    dirs
}

fn install_hint() -> String {
    let looked = search_dirs()
        .iter()
        .take(4)
        .map(|dir| dir.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "psiphon needs the psiphon-tunnel-core console client, and it was not in {looked} or on PATH; keep the release archive's pt folder beside the binary or point settings.binary (or AETHER_PSIPHON_BIN) at one"
    )
}

fn server_entries(settings: Option<&Json>) -> Option<PathBuf> {
    let path = text(settings, "serverList")
        .or_else(|| env("AETHER_PSIPHON_SERVER_ENTRIES"))
        .map(PathBuf::from)?;
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("psiphon: server entries {} are not a file", path.display());
        None
    }
}

fn client_arguments(
    config: &Path,
    state: &Path,
    entries: Option<&Path>,
) -> Vec<std::ffi::OsString> {
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "-config".into(),
        config.as_os_str().to_owned(),
        "-dataRootDirectory".into(),
        state.as_os_str().to_owned(),
    ];
    if let Some(path) = entries {
        arguments.push("-serverList".into());
        arguments.push(path.as_os_str().to_owned());
    }
    arguments
}

fn ca_store_env() -> Option<(&'static str, String)> {
    if std::env::var_os("SSL_CERT_FILE").is_some() || std::env::var_os("SSL_CERT_DIR").is_some() {
        return None;
    }
    let mut files = Vec::new();
    if let Some(prefix) = std::env::var_os("PREFIX") {
        files.push(PathBuf::from(prefix).join("etc/tls/cert.pem"));
    }
    for path in [
        "/data/data/com.termux/files/usr/etc/tls/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ] {
        files.push(PathBuf::from(path));
    }
    if let Some(found) = files.into_iter().find(|path| path.is_file()) {
        return Some(("SSL_CERT_FILE", found.to_string_lossy().into_owned()));
    }
    let dirs: Vec<&str> = [
        "/system/etc/security/cacerts",
        "/apex/com.android.conscrypt/cacerts",
    ]
    .into_iter()
    .filter(|dir| Path::new(*dir).is_dir())
    .collect();
    (!dirs.is_empty()).then(|| ("SSL_CERT_DIR", dirs.join(":")))
}

fn put(fields: &mut Vec<(String, Json)>, key: &str, value: Json) {
    if let Some(slot) = fields.iter_mut().find(|(name, _)| name == key) {
        slot.1 = value;
    } else {
        fields.push((key.to_owned(), value));
    }
}

fn strings(values: &[String]) -> Json {
    Json::Arr(
        values
            .iter()
            .map(|value| Json::Str(value.clone()))
            .collect(),
    )
}

fn protocols(names: &[&str]) -> Json {
    Json::Arr(
        names
            .iter()
            .map(|name| Json::Str((*name).to_owned()))
            .collect(),
    )
}

fn base_fields(path: Option<&Path>) -> Result<Vec<(String, Json)>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("psiphon config {}: {error}", path.display()))?;
    let mut clean = String::with_capacity(text.len());
    psiphon::strip_comments(&text, &mut clean);
    match json::parse(&clean)
        .map_err(|error| format!("psiphon config {}: {error}", path.display()))?
    {
        Json::Obj(pairs) => Ok(pairs),
        _ => Err(format!(
            "psiphon config {} is not a json object",
            path.display()
        )),
    }
}

fn json_strings(values: &[&str]) -> Json {
    Json::Arr(
        values
            .iter()
            .map(|value| Json::Str((*value).to_owned()))
            .collect(),
    )
}

fn unique<'a>(values: &[&'a str]) -> Vec<&'a str> {
    let mut unique = Vec::with_capacity(values.len());
    for value in values {
        if !value.is_empty() && !unique.contains(value) {
            unique.push(*value);
        }
    }
    unique
}

fn cdn_override(
    id: &str,
    providers: Option<&[&str]>,
    dials: Option<&[&str]>,
    address: &str,
    sni: &str,
    verify: &[&str],
    alpn: &[&str],
) -> Json {
    let mut fields = vec![("OverrideID".to_owned(), Json::Str(id.to_owned()))];
    if let Some(providers) = providers {
        fields.push((
            "MatchFrontingProviderIDRegexes".to_owned(),
            json_strings(providers),
        ));
    }
    if let Some(dials) = dials {
        fields.push(("MatchDialAddressRegexes".to_owned(), json_strings(dials)));
    }
    fields.push(("DialAddresses".to_owned(), json_strings(&[address])));
    fields.push(("SNIServerName".to_owned(), Json::Str(sni.to_owned())));
    fields.push((
        "VerifyServerNames".to_owned(),
        json_strings(&unique(verify)),
    ));
    fields.push(("ALPNProtocols".to_owned(), json_strings(alpn)));
    fields.push(("TLSProfile".to_owned(), Json::Str("Chrome-83".to_owned())));
    Json::Obj(fields)
}

fn shirokhorshid_dial_overrides(custom_sni: Option<&str>) -> Json {
    let custom_sni = custom_sni.unwrap_or("");
    let fastly_verify = [
        "www.python.org",
        "pypi.org",
        "fastly.com",
        "www.fastly.com",
        "developer.fastly.com",
        "githubassets.com",
        "github.com",
        "github.io",
        "githubusercontent.com",
    ];
    let fastly_alpn = ["h2", "http/1.1"];
    let mut overrides = vec![
        cdn_override(
            "fastly-provider",
            Some(&["(?i)fastly"]),
            None,
            "pypi.org",
            "pypi.org",
            &fastly_verify,
            &fastly_alpn,
        ),
        cdn_override(
            "fastly-address",
            None,
            Some(&["(?i)(fastly|pypi|python|github)"]),
            "pypi.org",
            "pypi.org",
            &fastly_verify,
            &fastly_alpn,
        ),
    ];
    for (id, octets) in [
        ("edge-a-1", [23, 215, 0, 206]),
        ("edge-a-2", [23, 215, 0, 203]),
        ("edge-b-1", [23, 212, 250, 91]),
        ("edge-b-2", [23, 212, 250, 78]),
        ("edge-c-1", [23, 12, 147, 13]),
        ("edge-c-2", [23, 12, 147, 29]),
        ("edge-d-1", [23, 73, 207, 8]),
        ("edge-d-2", [23, 73, 207, 15]),
        ("edge-original", [92, 123, 102, 43]),
    ] {
        let address = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
        let sni = if custom_sni.is_empty() {
            address.as_str()
        } else {
            custom_sni
        };
        let verify = [
            sni,
            address.as_str(),
            "a248.e.akamai.net",
            "a.akamaized.net",
            "a.akamaized-staging.net",
            "a.akamaihd.net",
            "a.akamaihd-staging.net",
            "www.akamai.com",
        ];
        overrides.push(cdn_override(
            id,
            None,
            Some(&[".*"]),
            address.as_str(),
            sni,
            &verify,
            &["http/1.1"],
        ));
    }
    Json::Arr(overrides)
}

#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
fn build_config(settings: &Settings) -> Result<String, String> {
    let mut fields: Vec<(String, Json)> = Vec::with_capacity(32);
    put(
        &mut fields,
        "PropagationChannelId",
        Json::Str(settings.propagation.clone()),
    );
    put(
        &mut fields,
        "SponsorId",
        Json::Str(settings.sponsor.clone()),
    );
    put(
        &mut fields,
        "ClientPlatform",
        Json::Str(settings.client_platform.clone()),
    );
    put(&mut fields, "ClientVersion", Json::Str("1".to_owned()));
    put(
        &mut fields,
        "RemoteServerListURLs",
        Json::Arr(vec![Json::Obj(vec![(
            "URL".to_owned(),
            Json::Str(ferrox_core::b64::encode(settings.server_list.as_bytes())),
        )])]),
    );
    put(
        &mut fields,
        "RemoteServerListSignaturePublicKey",
        Json::Str(psiphon::SERVER_LIST_SIGNATURE_KEY.to_owned()),
    );
    let conduit = settings.shape.is_conduit() || settings.inproxy_compartment.is_some();
    put(
        &mut fields,
        "InproxyTunnelProtocolPreferProbability",
        Json::Num(if conduit { 1.0 } else { 0.0 }),
    );
    put(
        &mut fields,
        "InproxyTunnelProtocolSelectionProbability",
        Json::Num(if conduit { 1.0 } else { 0.0 }),
    );
    if let Some(compartment) = &settings.inproxy_compartment {
        put(
            &mut fields,
            "InproxyClientPersonalCompartmentID",
            Json::Str(compartment.clone()),
        );
    }
    if !settings.reject_proxy_countries.is_empty() {
        if settings.geo_ip.is_some() {
            put(
                &mut fields,
                "InproxyRejectProxyCountryCodes",
                strings(&settings.reject_proxy_countries),
            );
        } else {
            eprintln!(
                "psiphon: rejectProxyCountries needs geoIp, so the client is not given the list"
            );
        }
    }
    if let Some(path) = &settings.geo_ip {
        put(
            &mut fields,
            "GeoIPDatabasePath",
            Json::Str(path.to_string_lossy().into_owned()),
        );
    }
    if !settings.cdn_ips.is_empty() {
        let mut spec = vec![("IPCandidates".to_owned(), strings(&settings.cdn_ips))];
        if !settings.cdn_sni.is_empty() {
            spec.push(("SNIServerNames".to_owned(), strings(&settings.cdn_sni)));
        }
        put(&mut fields, "FrontedMeekCDNScanSpec", Json::Obj(spec));
    }
    if settings.cdn_ips.is_empty() || !settings.cdn_sets.is_empty() {
        put(
            &mut fields,
            "FrontedMeekCDNScanUseBuiltInSpec",
            Json::Bool(true),
        );
    }
    if !settings.cdn_sets.is_empty() {
        put(
            &mut fields,
            "FrontedMeekCDNScanBuiltInSets",
            strings(&settings.cdn_sets),
        );
    }
    if let Some(profile) = settings.cdn_profile.as_deref() {
        if matches!(profile, "shirokhorshid" | "legacy" | "android") {
            put(
                &mut fields,
                "FrontedMeekDialOverrides",
                shirokhorshid_dial_overrides(settings.cdn_sni.first().map(String::as_str)),
            );
            put(
                &mut fields,
                "FrontedMeekDialOverridesProbability",
                Json::Num(1.0),
            );
            put(
                &mut fields,
                "FrontedMeekCDNScanUseBuiltInSpec",
                Json::Bool(true),
            );
        } else {
            eprintln!(
                "psiphon: cdnProfile {profile:?} is not shirokhorshid, legacy or android; ignored"
            );
        }
    }
    let chained = settings.upstream.is_some();
    put(
        &mut fields,
        "LimitTunnelProtocols",
        protocols(if conduit {
            &psiphon::INPROXY_PROTOCOLS
        } else if chained {
            settings.shape.chained()
        } else {
            settings.shape.protocols()
        }),
    );
    if settings.shape.disables_tactics() {
        put(&mut fields, "DisableTactics", Json::Bool(true));
    }
    if settings.split_own_region {
        put(&mut fields, "SplitTunnelOwnRegion", Json::Bool(true));
    }
    if !settings.split_regions.is_empty() {
        put(
            &mut fields,
            "SplitTunnelRegions",
            strings(&settings.split_regions),
        );
    }
    if let Some(location) = &settings.device_location {
        put(&mut fields, "DeviceLocation", Json::Str(location.clone()));
    }
    if let Some(region) = &settings.device_region {
        put(&mut fields, "DeviceRegion", Json::Str(region.clone()));
    }
    if let Some(network) = &settings.network_id {
        put(&mut fields, "NetworkID", Json::Str(network.clone()));
    }
    if !settings.dns_alternate.is_empty() {
        put(
            &mut fields,
            "DNSResolverAlternateServers",
            strings(&settings.dns_alternate),
        );
    }
    if let Some(parameters) = &settings.additional_parameters {
        put(
            &mut fields,
            "AdditionalParameters",
            Json::Str(parameters.clone()),
        );
    }
    if let Some(seconds) = settings.establish_timeout {
        put(
            &mut fields,
            "EstablishTunnelTimeoutSeconds",
            Json::Num(seconds as f64),
        );
    }
    if !settings.client_features.is_empty() {
        put(
            &mut fields,
            "ClientFeatures",
            strings(&settings.client_features),
        );
    }
    if settings.disable_timeouts {
        put(
            &mut fields,
            "NetworkLatencyMultiplierLambda",
            Json::Num(0.1),
        );
    } else if let Some(latency) = settings.latency {
        put(&mut fields, "NetworkLatencyMultiplier", Json::Num(latency));
    }
    if !settings.tls_profiles.is_empty() {
        put(
            &mut fields,
            "LimitTLSProfiles",
            strings(&settings.tls_profiles),
        );
    }
    if !settings.quic_versions.is_empty() {
        put(
            &mut fields,
            "LimitQUICVersions",
            strings(&settings.quic_versions),
        );
    }
    if let Some(pool) = settings.tunnel_pool {
        put(&mut fields, "TunnelPoolSize", Json::Num(pool as f64));
    }
    if let Some(workers) = settings.workers {
        put(
            &mut fields,
            "ConnectionWorkerPoolSize",
            Json::Num(workers as f64),
        );
    }
    if settings.aggressive {
        put(&mut fields, "AggressiveEstablishment", Json::Bool(true));
    }
    if settings.limit_meek {
        put(&mut fields, "LimitMeekBufferSizes", Json::Bool(true));
    }
    if settings.limit_relay {
        put(&mut fields, "LimitRelayBufferSizes", Json::Bool(true));
    }
    if settings.limit_cpu {
        put(&mut fields, "LimitCPUThreads", Json::Bool(true));
    }
    if !settings.initial_protocols.is_empty() {
        put(
            &mut fields,
            "InitialLimitTunnelProtocols",
            strings(&settings.initial_protocols),
        );
    }
    if let Some(count) = settings.initial_count {
        put(
            &mut fields,
            "InitialLimitTunnelProtocolsCandidateCount",
            Json::Num(count as f64),
        );
    }
    for (key, value) in base_fields(settings.base.as_deref())? {
        put(&mut fields, &key, value);
    }
    fields.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            "LocalProxyUsername" | "LocalProxyPassword" | "ListenInterface"
        )
    });
    if let (Some(user), Some(pass)) = (&settings.proxy_user, &settings.proxy_pass) {
        put(&mut fields, "LocalProxyUsername", Json::Str(user.clone()));
        put(&mut fields, "LocalProxyPassword", Json::Str(pass.clone()));
    }
    put(
        &mut fields,
        "DataRootDirectory",
        Json::Str(settings.state.to_string_lossy().into_owned()),
    );
    put(
        &mut fields,
        "LocalSocksProxyPort",
        Json::Num(f64::from(settings.listen.port())),
    );
    put(&mut fields, "EmitDiagnosticNotices", Json::Bool(true));
    put(
        &mut fields,
        "EmitDiagnosticNetworkParameters",
        Json::Bool(true),
    );
    put(&mut fields, "EmitServerAlerts", Json::Bool(true));
    put(
        &mut fields,
        "EmitBytesTransferred",
        Json::Bool(settings.emit_bytes_transferred),
    );
    if let Some(name) = &settings.interface {
        put(&mut fields, "ListenInterface", Json::Str(name.clone()));
    }
    match settings.http {
        Some(address) => {
            put(
                &mut fields,
                "LocalHttpProxyPort",
                Json::Num(f64::from(address.port())),
            );
            put(&mut fields, "DisableLocalHTTPProxy", Json::Bool(false));
        }
        None => put(&mut fields, "DisableLocalHTTPProxy", Json::Bool(true)),
    }
    if let Some(region) = &settings.region {
        put(&mut fields, "EgressRegion", Json::Str(region.clone()));
    }
    if let Some(upstream) = &settings.upstream {
        put(&mut fields, "UpstreamProxyURL", Json::Str(upstream.clone()));
    }
    let mut out = String::with_capacity(4096);
    json::write(&Json::Obj(fields), &mut out);
    Ok(out)
}

enum Startup {
    Ready(SocketAddr),
    Failed(String),
}

fn start(settings: &Settings) -> Result<(SocketAddr, Child, Arc<AtomicBool>), String> {
    std::fs::create_dir_all(&settings.state)
        .map_err(|error| format!("psiphon state dir {}: {error}", settings.state.display()))?;
    state_is_owned(&settings.state)?;
    let config = build_config(settings)?;
    let config_path = settings
        .state
        .join(format!("ferrox-psiphon-{}.json", settings.listen.port()));
    let save = |error: std::io::Error| {
        format!(
            "psiphon config {} could not be saved: {error}",
            config_path.display()
        )
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    {
        use std::io::Write as _;
        options
            .open(&config_path)
            .and_then(|mut file| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
                file.write_all(config.as_bytes())
            })
            .map_err(save)?;
    }

    let binary = binary(settings.binary.as_deref())?;
    let mut command = Command::new(&binary);
    command
        .args(client_arguments(
            &config_path,
            &settings.state,
            settings.entries.as_deref(),
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some((key, value)) = ca_store_env() {
        command.env(key, value);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("psiphon would not start {}: {error}", binary.display()))?;
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("psiphon gave no notice stream".to_owned());
    };
    let (sender, receiver) = mpsc::channel();
    let listen = settings.listen;
    let interface = settings.interface.clone();
    let stopping = Arc::new(AtomicBool::new(false));
    let watch_stopping = stopping.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("ferrox-psiphon".to_owned())
        .spawn(move || {
            watch(
                stderr,
                &sender,
                listen,
                interface.as_deref(),
                &watch_stopping,
            );
        })
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("psiphon notice reader: {error}"));
    }

    match receiver.recv_timeout(settings.ready) {
        Ok(Startup::Ready(socks)) => Ok((socks, child, stopping)),
        Ok(Startup::Failed(reason)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(reason)
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(format!(
                "psiphon did not come up in {}s; it may be blocked on this network",
                settings.ready.as_secs()
            ))
        }
    }
}

fn watch(
    stderr: ChildStderr,
    startup: &mpsc::Sender<Startup>,
    listen: SocketAddr,
    interface: Option<&str>,
    stopping: &AtomicBool,
) {
    let mut reader = BufReader::with_capacity(8192, stderr);
    let mut spill = Vec::new();
    let mut socks = None;
    let mut tunnelled = false;
    let mut sent = false;
    loop {
        let outcome = read_notice_line(&mut reader, &mut spill, |line| {
            let Some(notice) = psiphon::notice(line) else {
                return;
            };
            match notice.kind {
                "ListeningSocksProxyPort" => socks = notice.port,
                "ListeningHttpProxyPort" => {}
                "Tunnels" => {
                    tunnelled = notice.count.is_some_and(|count| count > 0);
                }
                other => {
                    if !sent {
                        note(other, &notice);
                    }
                }
            }
            if !sent {
                if let (true, Some(port)) = (tunnelled, socks) {
                    let bound = effective_ip(listen, interface);
                    let endpoint = SocketAddr::new(dial_ip(bound), port);
                    if startup.send(Startup::Ready(endpoint)).is_ok() {
                        sent = true;
                    }
                }
            } else if !matches!(notice.kind, "Tunnels" | "ListeningSocksProxyPort") {
                note(notice.kind, &notice);
            }
        });
        match outcome {
            Ok(true) => {}
            Ok(false) => {
                if sent && !stopping.load(Ordering::Relaxed) {
                    eprintln!("psiphon: the client's notice stream ended; the lane is down");
                } else if !sent {
                    let _ = startup.send(Startup::Failed(
                        "psiphon stopped before it was ready".to_owned(),
                    ));
                }
                return;
            }
            Err(error) => {
                if sent && !stopping.load(Ordering::Relaxed) {
                    eprintln!("psiphon: the client's notice stream failed: {error}");
                } else if !sent {
                    let _ = startup.send(Startup::Failed(format!("psiphon: {error}")));
                }
                return;
            }
        }
    }
}

fn read_notice_line<R: BufRead, F: FnMut(&[u8])>(
    reader: &mut R,
    spill: &mut Vec<u8>,
    mut visit: F,
) -> std::io::Result<bool> {
    loop {
        let buf = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if buf.is_empty() {
            if spill.is_empty() {
                return Ok(false);
            }
            visit(spill);
            spill.clear();
            return Ok(true);
        }
        if spill.is_empty() {
            if let Some(newline) = psiphon::find_byte(buf, b'\n') {
                visit(&buf[..=newline]);
                reader.consume(newline + 1);
                return Ok(true);
            }
            spill.extend_from_slice(buf);
            let taken = buf.len();
            reader.consume(taken);
            continue;
        }
        if let Some(newline) = psiphon::find_byte(buf, b'\n') {
            spill.extend_from_slice(&buf[..=newline]);
            reader.consume(newline + 1);
            visit(spill);
            spill.clear();
            return Ok(true);
        }
        spill.extend_from_slice(buf);
        let taken = buf.len();
        reader.consume(taken);
    }
}

fn note(kind: &str, notice: &Notice<'_>) {
    match kind {
        "ConnectedServer" => {
            if let Some(address) = notice.ip_address {
                eprintln!("psiphon: reached a server at {address}");
            }
        }
        "AvailableEgressRegions" => eprintln!("psiphon: the client published its egress regions"),
        "Warning" | "Alert" | "Error" | "InternalError" => {
            if notice.expected_without_inproxy() {
                return;
            }
            let text = notice.message.unwrap_or(kind);
            eprintln!("psiphon: {text}");
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn settings_json(text: &str) -> Json {
        crate::json::parse(text).expect("settings parse")
    }

    #[test]
    fn a_config_names_the_client_it_starts_and_the_lane_it_announces() {
        let port = free_port(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("a port");
        let settings = Settings::from_json(Some(&settings_json(&format!(
            r#"{{"listen":"127.0.0.1:{port}","region":"de","shape":"cdn","upstreamProxy":"socks5://127.0.0.1:1080"}}"#
        ))))
        .expect("settings");
        assert_eq!(settings.listen.port(), port);
        assert_eq!(settings.region.as_deref(), Some("DE"));
        assert_eq!(settings.shape, Shape::Cdn);
        let config = build_config(&settings).expect("a config");
        assert!(config.contains(&format!("\"LocalSocksProxyPort\":{port}")));
        assert!(config.contains("\"UpstreamProxyURL\":\"socks5://127.0.0.1:1080\""));
        assert!(config.contains("\"EgressRegion\":\"DE\""));
        for name in psiphon::CHAINED_CDN_PROTOCOLS {
            assert!(config.contains(name), "{name}");
        }
        assert!(!config.contains("QUIC-OSSH"));
        assert!(config.contains("\"DisableTactics\":true"));
    }

    #[test]
    fn split_tunnel_credentials_and_client_knobs_reach_the_config() {
        let settings = Settings::from_json(Some(&settings_json(
            r#"{"listen":"127.0.0.1:1821","localProxyUsername":"u","localProxyPassword":"p","splitTunnelOwnRegion":true,"splitTunnelRegions":["ir","de"],"clientFeatures":["VPN"],"networkLatencyMultiplier":1.5,"tunnelPoolSize":2,"connectionWorkerPoolSize":4,"aggressiveEstablishment":true,"limitCpuThreads":true,"limitMeekBufferSizes":true,"limitRelayBufferSizes":true,"limitTlsProfiles":["Chrome"],"limitQuicVersions":["v1"],"initialLimitTunnelProtocols":["SSH"],"initialLimitTunnelProtocolsCandidateCount":3}"#,
        )))
        .expect("settings");
        let credential = settings.credential();
        assert_eq!(credential.user, "u");
        assert_eq!(credential.pass, "p");
        let config = build_config(&settings).expect("a config");
        for expected in [
            "\"SplitTunnelOwnRegion\":true",
            "\"SplitTunnelRegions\":[\"DE\",\"IR\"]",
            "\"LocalProxyUsername\":\"u\"",
            "\"LocalProxyPassword\":\"p\"",
            "\"ClientFeatures\":[\"VPN\"]",
            "\"NetworkLatencyMultiplier\":1.5",
            "\"TunnelPoolSize\":2",
            "\"ConnectionWorkerPoolSize\":4",
            "\"AggressiveEstablishment\":true",
            "\"LimitCPUThreads\":true",
            "\"LimitMeekBufferSizes\":true",
            "\"LimitRelayBufferSizes\":true",
            "\"LimitTLSProfiles\":[\"Chrome\"]",
            "\"LimitQUICVersions\":[\"v1\"]",
            "\"InitialLimitTunnelProtocols\":[\"SSH\"]",
            "\"InitialLimitTunnelProtocolsCandidateCount\":3",
        ] {
            assert!(config.contains(expected), "{expected} in {config}");
        }
    }

    #[test]
    fn a_base_config_cannot_override_lane_owned_fields() {
        let dir = std::env::temp_dir().join(format!("ferrox-psiphon-base-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let base = dir.join("base.json");
        std::fs::write(
            &base,
            r#"{"LocalProxyUsername":"base","LocalProxyPassword":"base","ListenInterface":"eth0","DataRootDirectory":"/tmp/base","LocalSocksProxyPort":9999,"EmitDiagnosticNotices":false}"#,
        )
        .expect("write");
        let base_json = base.to_string_lossy().replace('\\', "\\\\");
        let settings = Settings::from_json(Some(&settings_json(&format!(
            r#"{{"listen":"127.0.0.1:1821","baseConfig":"{base_json}"}}"#
        ))))
        .expect("settings");
        let config = build_config(&settings).expect("a config");
        assert!(!config.contains("LocalProxyUsername"), "{config}");
        assert!(!config.contains("LocalProxyPassword"), "{config}");
        assert!(!config.contains("ListenInterface"), "{config}");
        assert!(config.contains("\"LocalSocksProxyPort\":1821"), "{config}");
        assert!(
            config.contains("\"EmitDiagnosticNotices\":true"),
            "{config}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_config_is_refused() {
        let dir =
            std::env::temp_dir().join(format!("ferrox-psiphon-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("target.json");
        std::fs::write(&target, b"{}").expect("write");
        let config = dir.join("ferrox-psiphon-1821.json");
        std::os::unix::fs::symlink(&target, &config).expect("symlink");
        let dir_json = dir.to_string_lossy().replace('\\', "\\\\");
        let settings = Settings::from_json(Some(&settings_json(&format!(
            r#"{{"listen":"127.0.0.1:1821","dataRootDirectory":"{dir_json}"}}"#
        ))))
        .expect("settings");
        let error = start(&settings).expect_err("refused");
        assert!(error.contains("could not be saved"), "{error}");
        assert_eq!(std::fs::read(&target).expect("target"), b"{}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shirokhorshid_knobs_reach_the_config() {
        let dir = std::env::temp_dir().join(format!("ferrox-psiphon-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let geo = dir.join("country.mmdb");
        std::fs::write(&geo, b"not a real database").expect("write");
        let geo_json = geo.to_string_lossy().replace('\\', "\\\\");
        let settings = Settings::from_json(Some(&settings_json(&format!(
            r#"{{"listen":"127.0.0.1:1821","shape":"conduit","cdnProfile":"shirokhorshid","cdnSni":["custom.example"],"geoIp":"{geo_json}","rejectCensoredProxies":true,"rejectProxyCountries":["de"],"inproxyCompartment":"room","disableTimeouts":true,"dnsResolverAlternateServers":["192.0.2.53","198.51.100.53"],"deviceLocation":"u4pruyd","deviceRegion":"ir","networkId":"wifi","additionalParameters":"eyJ4IjoxfQ==","establishTunnelTimeoutSeconds":300,"emitBytesTransferred":true}}"#
        ))))
        .expect("settings");
        let config = build_config(&settings).expect("a config");
        for expected in [
            "\"LimitTunnelProtocols\":[\"INPROXY-WEBRTC-SSH\"",
            "\"InproxyTunnelProtocolPreferProbability\":1",
            "\"InproxyTunnelProtocolSelectionProbability\":1",
            "\"InproxyClientPersonalCompartmentID\":\"room\"",
            "\"InproxyRejectProxyCountryCodes\":[\"BY\",\"CN\",\"DE\",\"IR\",\"KP\",\"RU\",\"TM\"]",
            "\"GeoIPDatabasePath\"",
            "\"NetworkLatencyMultiplierLambda\":0.1",
            "\"DNSResolverAlternateServers\":[\"192.0.2.53\",\"198.51.100.53\"]",
            "\"DeviceLocation\":\"u4pruyd\"",
            "\"DeviceRegion\":\"IR\"",
            "\"NetworkID\":\"wifi\"",
            "\"AdditionalParameters\":\"eyJ4IjoxfQ==\"",
            "\"EstablishTunnelTimeoutSeconds\":300",
            "\"EmitBytesTransferred\":true",
            "\"FrontedMeekDialOverridesProbability\":1",
            "\"FrontedMeekCDNScanUseBuiltInSpec\":true",
            "\"edge-a-1\"",
            "\"custom.example\"",
        ] {
            assert!(config.contains(expected), "{expected} in {config}");
        }
        assert!(config.contains(&format!("\"{}.{}.{}.{}\"", 23, 215, 0, 206)));
        assert!(!config.contains("\"NetworkLatencyMultiplier\":"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_flow_clone_shares_the_credential_words() {
        let lane = PsiphonOut {
            _process: Arc::new(Process {
                child: Mutex::new(None),
                stopping: Arc::new(AtomicBool::new(false)),
            }),
            endpoint: SocketAddr::from(([127, 0, 0, 1], 1821)),
            credential: Arc::new(Credential {
                user: "u".to_owned(),
                pass: "p".to_owned(),
            }),
            version: Version::V5,
        };
        let (flow, counts) = ferrox_core::alloc_count::measure(|| lane.clone());
        assert_eq!(counts.allocs, 0);
        assert!(Arc::ptr_eq(&lane.credential, &flow.credential));
        assert_eq!(
            lane.credential().user.as_ptr(),
            flow.credential().user.as_ptr()
        );
    }

    #[test]
    fn half_a_local_proxy_credential_is_refused() {
        let error = Settings::from_json(Some(&settings_json(
            r#"{"listen":"127.0.0.1:1821","localProxyUsername":"u"}"#,
        )))
        .unwrap_err();
        assert!(error.contains("named together"), "{error}");
    }

    #[test]
    fn a_local_proxy_credential_longer_than_the_rfc_field_is_refused() {
        let error = Settings::from_json(Some(&settings_json(&format!(
            r#"{{"listen":"127.0.0.1:1821","localProxyUsername":"u","localProxyPassword":"{}"}}"#,
            "p".repeat(256)
        ))))
        .unwrap_err();
        assert!(error.contains("at most 255 bytes"), "{error}");
    }

    #[test]
    fn a_region_that_is_not_a_country_code_is_refused() {
        let error = Settings::from_json(Some(&settings_json(
            r#"{"listen":"127.0.0.1:1821","region":"germany"}"#,
        )))
        .unwrap_err();
        assert!(error.contains("two-letter country code"), "{error}");
    }

    #[test]
    fn a_named_interface_on_a_loopback_listener_is_refused() {
        let error = Settings::from_json(Some(&settings_json(
            r#"{"listen":"127.0.0.1:1821","interface":"eth0"}"#,
        )))
        .unwrap_err();
        assert!(error.contains("set listen to that address"), "{error}");
    }

    #[test]
    fn a_carried_lane_offers_every_tcp_shape_and_no_quic() {
        let settings = Settings::from_json(Some(&settings_json(
            r#"{"listen":"127.0.0.1:1821","upstreamProxy":"http://127.0.0.1:8080"}"#,
        )))
        .expect("settings");
        let config = build_config(&settings).expect("a config");
        for name in psiphon::CHAINED_PROTOCOLS {
            assert!(config.contains(name), "{name}");
        }
        assert!(!config.contains("QUIC-OSSH"));
    }

    #[test]
    fn a_config_of_ones_own_is_laid_over_the_built_in_one() {
        let dir =
            std::env::temp_dir().join(format!("ferrox-psiphon-overlay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let base = dir.join("base.json");
        std::fs::write(
            &base,
            "{\n// the samples ship comments\n\"SponsorId\":\"MINE\",/* and blocks */\"EmitBytesTransferred\":true\n}",
        )
        .expect("write");
        let base_json = base.to_string_lossy().replace('\\', "\\\\");
        let settings = Settings::from_json(Some(&settings_json(&format!(
            r#"{{"listen":"127.0.0.1:1821","baseConfig":"{base_json}"}}"#
        ))))
        .expect("settings");
        let config = build_config(&settings).expect("a config");
        assert!(config.contains("\"SponsorId\":\"MINE\""));
        assert!(config.contains("\"PropagationChannelId\":\"FFFFFFFFFFFFFFFF\""));
        assert!(config.contains("\"EmitBytesTransferred\":false"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_lane_waits_for_a_tunnel_and_reads_the_port_the_client_announced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ferrox-psiphon-lane-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let port = free_port(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("a port");
        let binary = dir.join("psiphon-tunnel-core");
        std::fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '{{\"noticeType\":\"ListeningSocksProxyPort\",\"data\":{{\"port\":{port}}}}}' >&2\nprintf '%s\\n' '{{\"noticeType\":\"Tunnels\",\"data\":{{\"count\":1}}}}' >&2\nsleep 30\n"
            ),
        )
        .expect("write");
        let mut permissions = std::fs::metadata(&binary).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&binary, permissions).expect("chmod");
        let settings = format!(
            r#"{{"binary":"{}","listen":"127.0.0.1:{port}","dataRootDirectory":"{}","readySeconds":10}}"#,
            binary.display(),
            dir.display()
        );
        let lane = PsiphonOut::new(Some(&settings_json(&settings))).expect("a lane");
        assert_eq!(lane.endpoint(), SocketAddr::from(([127, 0, 0, 1], port)));
        let config = dir.join(format!("ferrox-psiphon-{port}.json"));
        assert!(config.is_file(), "the client's config was written");
        drop(lane);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_binary_that_is_not_there_is_refused_by_name() {
        let error = binary(Some(Path::new("/nowhere/psiphon-tunnel-core"))).unwrap_err();
        assert!(error.contains("/nowhere/psiphon-tunnel-core"));
    }

    #[test]
    fn a_line_that_is_not_a_notice_is_skipped_without_a_buffer() {
        let line = b"not json\n";
        assert!(psiphon::notice(line).is_none());
        let notice = br#"{"noticeType":"Tunnels","data":{"count":1}}"#;
        let mut with_newline = notice.to_vec();
        with_newline.push(b'\n');
        assert_eq!(
            psiphon::notice(&with_newline).and_then(|notice| notice.count),
            Some(1)
        );
    }

    struct OneBuffer {
        data: Vec<u8>,
        at: usize,
    }

    impl Read for OneBuffer {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let take = out.len().min(self.data.len() - self.at);
            out[..take].copy_from_slice(&self.data[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    impl BufRead for OneBuffer {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Ok(&self.data[self.at..])
        }

        fn consume(&mut self, amount: usize) {
            self.at = (self.at + amount).min(self.data.len());
        }
    }

    #[test]
    fn a_notice_line_is_visited_where_the_reader_holds_it() {
        let mut reader = OneBuffer {
            data: b"first\nsecond\nlast\n".to_vec(),
            at: 0,
        };
        let base = reader.data.as_ptr();
        let mut spill = Vec::new();
        let mut seen = Vec::new();
        for _ in 0..3 {
            assert!(read_notice_line(&mut reader, &mut spill, |line| {
                seen.push((line.as_ptr(), line.len()));
            })
            .expect("a line"));
        }
        assert_eq!(
            seen,
            [
                (base, 6),
                (base.wrapping_add(6), 7),
                (base.wrapping_add(13), 5)
            ]
        );
        assert!(!read_notice_line(&mut reader, &mut spill, |_| {}).expect("eof"));
        assert_eq!(spill.len(), 0);
    }

    #[test]
    fn a_notice_line_that_fits_the_reader_takes_no_buffer() {
        let mut reader = OneBuffer {
            data: b"{\"noticeType\":\"Tunnels\",\"data\":{\"count\":1}}\n".to_vec(),
            at: 0,
        };
        let mut spill = Vec::new();
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            read_notice_line(&mut reader, &mut spill, |line| {
                assert!(psiphon::notice(line).is_some());
            })
            .expect("a line");
        });
        assert_eq!(counts.allocs, 0);
    }

    #[test]
    fn a_notice_line_longer_than_the_reader_is_joined_once() {
        let mut data = vec![b'a'; 200];
        data.push(b'\n');
        let mut reader = OneBuffer { data, at: 0 };
        let mut spill = Vec::new();
        let mut len = 0;
        assert!(read_notice_line(&mut reader, &mut spill, |line| {
            len = line.len();
            assert!(line.iter().all(|byte| *byte == b'a' || *byte == b'\n'));
        })
        .expect("a line"));
        assert_eq!(len, 201);
        assert_eq!(spill.len(), 0);
    }
}
