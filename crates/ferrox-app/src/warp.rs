//! WARP as one outbound: a device registration, a `WireGuard` half and a
//! MASQUE CONNECT-IP half, and the race that picks the first half that carries
//! a real DNS answer. Registering a device is a POST, a MASQUE key enrollment
//! is a PATCH, and switching the device on is a second PATCH. The identity the
//! three calls produce is saved once and reused, so a restart does not create
//! a second account.

use std::io::Write as _;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;

use crate::foxy_account::{Endpoint, Reply};

/// The API host Aether dials first, and the host `ZeroNet` still uses.
const API_HOSTS: [&str; 2] = ["api.devices.cloudflare.com", "api.cloudflareclient.com"];
/// The API version both pinned clients call.
const API_VERSION: &str = "v0a4471";
/// The HTTP authority WARP's CONNECT-IP endpoint answers on.
const CONNECT_HOST: &str = "cloudflareaccess.com";
/// The SNI the MASQUE edge presents.
const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
/// WARP's `WireGuard` endpoint port; the API lists many and this one is the documented one.
const WIREGUARD_PORT: u16 = 2408;
/// The MASQUE edge's UDP port.
const QUIC_PORT: u16 = 443;
/// The name the API answers a browser-less registration with.
const REGISTER_AGENT: &str = "WARP for Android";
/// The client version the registration body names.
const CLIENT_VERSION: &str = "a-6.35-4471";
/// The name the race asks through each half before it trusts it.
const PROBE_HOST: &str = "one.one.one.one";
/// The name's port: only the answer matters, not a connection.
const PROBE_PORT: u16 = 53;
/// How long the race waits for a first successful answer.
const RACE_DEADLINE: Duration = Duration::from_secs(8);
/// The MTU WARP's own clients use.
const DEFAULT_MTU: u16 = 1280;
/// The keepalive WARP's own clients use.
const DEFAULT_KEEPALIVE: u16 = 25;
/// The tunnel's DNS servers, reachable from either half once it is up.
const TUNNEL_DNS: [&str; 2] = ["1.1.1.1", "2606:4700:4700::1111"];

/// The API reply holds the `WireGuard` half's private key only on this side; the
/// peer key, endpoint, reserved bytes and tunnel addresses come back over the
/// wire, and the MASQUE key is the one enrolled after the device exists.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    device_id: String,
    token: String,
    wireguard: WireGuardIdentity,
    masque: Option<MasqueIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WireGuardIdentity {
    private: [u8; 32],
    peer: [u8; 32],
    endpoint: SocketAddr,
    addresses: Vec<IpAddr>,
    reserved: [u8; 3],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MasqueIdentity {
    private: Vec<u8>,
    server: Vec<u8>,
    addresses: Vec<IpAddr>,
}

/// Which half the outbound may use, before the race has answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Auto,
    WireGuard,
    Masque,
}

impl Mode {
    fn parse(text: Option<&str>) -> Result<Self, String> {
        match text.unwrap_or("auto").to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "wireguard" | "wg" => Ok(Self::WireGuard),
            "masque" => Ok(Self::Masque),
            other => Err(format!(
                "warp mode `{other}` is not auto, wireguard or masque"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::WireGuard => "wireguard",
            Self::Masque => "masque",
        }
    }
}

/// One parsed `warp` outbound setting list. Everything has a WARP default so a
/// one-tap identity file is the whole config.
#[derive(Debug, Clone)]
struct WarpSpec {
    mode: Mode,
    register: bool,
    identity_file: Option<PathBuf>,
    inline: Option<Identity>,
    api: Option<String>,
    api_address: Option<String>,
    endpoint: Option<SocketAddr>,
    mtu: u16,
    keepalive: u16,
    probe_host: String,
    probe_port: u16,
    dns: Vec<IpAddr>,
    masque_address: String,
    masque_port: u16,
    masque_server_name: String,
    masque_host: String,
    masque_path: String,
}

impl WarpSpec {
    fn from(settings: &crate::json::Json) -> Result<Self, String> {
        let mode = Mode::parse(settings.get("mode").and_then(crate::json::Json::as_str))?;
        let register = settings
            .get("register")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        let identity_file = settings
            .get("identityFile")
            .and_then(crate::json::Json::as_str)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let inline = settings
            .get("identity")
            .map(Identity::from_json)
            .transpose()?;
        if inline.is_none() && identity_file.is_none() && !register {
            return Err(
                "warp outbound needs `identityFile`, an inline `identity`, or `register: true`"
                    .to_owned(),
            );
        }
        let api = settings
            .get("api")
            .and_then(crate::json::Json::as_str)
            .filter(|api| !api.is_empty())
            .map(str::to_owned);
        let api_address = settings
            .get("apiAddress")
            .and_then(crate::json::Json::as_str)
            .filter(|address| !address.is_empty())
            .map(str::to_owned);
        let endpoint = settings
            .get("endpoint")
            .and_then(crate::json::Json::as_str)
            .and_then(parse_endpoint);
        let mtu = settings
            .get("mtu")
            .and_then(crate::json::Json::as_u32)
            .and_then(|mtu| u16::try_from(mtu).ok())
            .filter(|mtu| *mtu > 0)
            .unwrap_or(DEFAULT_MTU);
        let keepalive = settings
            .get("keepAlive")
            .and_then(crate::json::Json::as_u32)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(DEFAULT_KEEPALIVE);
        let probe_host = settings
            .get("probe")
            .and_then(crate::json::Json::as_str)
            .filter(|host| !host.is_empty())
            .unwrap_or(PROBE_HOST)
            .to_owned();
        let probe_port = settings
            .get("probePort")
            .and_then(crate::json::Json::as_port)
            .unwrap_or(PROBE_PORT);
        let dns = match settings.get("dns").and_then(crate::json::Json::as_arr) {
            Some(items) => items
                .iter()
                .filter_map(crate::json::Json::as_str)
                .filter_map(|text| text.parse().ok())
                .collect(),
            None => TUNNEL_DNS
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
        };
        let (masque_address, masque_port, masque_server_name, masque_host, masque_path) =
            masque_settings(settings.get("masque"));
        Ok(Self {
            mode,
            register,
            identity_file,
            inline,
            api,
            api_address,
            endpoint,
            mtu,
            keepalive,
            probe_host,
            probe_port,
            dns,
            masque_address,
            masque_port,
            masque_server_name,
            masque_host,
            masque_path,
        })
    }

    /// The identity a config names: inline wins, then a saved file, then a new
    /// registration saved into `identityFile`. A saved file is checked against
    /// the API; a refused one is replaced unless `AETHER_REPROVISION=0`.
    fn identity(&self) -> Result<Identity, String> {
        if let Some(identity) = &self.inline {
            return Ok(identity.clone());
        }
        let Some(path) = self.identity_file.as_deref() else {
            if !self.register {
                return Err("warp outbound needs `identityFile` or an inline `identity`".to_owned());
            }
            return Err(
                "warp: `register: true` needs an `identityFile` to save the account".into(),
            );
        };
        if path.is_file() {
            let saved = match Identity::load(path) {
                Ok(saved) => saved,
                Err(error) if error.corrupt() && self.register && reprovision_enabled() => {
                    let identity = register(self, self.mode != Mode::WireGuard)?;
                    quarantine(path);
                    identity.save(path)?;
                    return Ok(identity);
                }
                Err(error) => return Err(error.into_message()),
            };
            return match refresh_saved(self, &saved) {
                Ok(fresh) if fresh != saved => {
                    if let Err(error) = fresh.save(path) {
                        eprintln!("warp: could not persist the refreshed identity: {error}");
                    }
                    Ok(fresh)
                }
                Ok(_) => Ok(saved),
                Err(error)
                    if should_reprovision(self.register, error.refused, reprovision_enabled()) =>
                {
                    let identity = register(self, saved.masque.is_some())?;
                    quarantine(path);
                    identity.save(path)?;
                    Ok(identity)
                }
                Err(error) => {
                    eprintln!("warp: keeping the saved identity: {}", error.reason);
                    Ok(saved)
                }
            };
        }
        if !self.register {
            return Err(
                "warp: the identity file does not exist and `register` is false".to_owned(),
            );
        }
        let identity = register(self, self.mode != Mode::WireGuard)?;
        identity.save(path)?;
        Ok(identity)
    }

    fn api_url(&self) -> Vec<String> {
        match self.api.as_deref() {
            Some(api) => vec![api.to_owned()],
            None => API_HOSTS
                .iter()
                .map(|host| format!("https://{host}/{API_VERSION}"))
                .collect(),
        }
    }

    fn for_command(mode: Mode, api: Option<String>, api_address: Option<String>) -> Self {
        Self {
            mode,
            register: true,
            identity_file: None,
            inline: None,
            api,
            api_address,
            endpoint: None,
            mtu: DEFAULT_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            probe_host: PROBE_HOST.to_owned(),
            probe_port: PROBE_PORT,
            dns: TUNNEL_DNS
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
            masque_address: CONNECT_HOST.to_owned(),
            masque_port: QUIC_PORT,
            masque_server_name: CONNECT_SNI.to_owned(),
            masque_host: CONNECT_HOST.to_owned(),
            masque_path: "/".to_owned(),
        }
    }
}

/// One API origin, its dialled address moved by `apiAddress` while the TLS
/// name and HTTP host stay the origin's.
fn api_endpoint(spec: &WarpSpec, base: &str) -> Result<Endpoint, String> {
    let mut endpoint = Endpoint::parse(base, crate::quic::system_roots())
        .ok_or_else(|| format!("warp: `{base}` is not an https API origin"))?
        .with_h2_fingerprint("chrome_plain")
        .without_resumption();
    if let Some(address) = &spec.api_address {
        let (host, port) = split_host_port(address, 443).ok_or_else(|| {
            format!(
                "warp: apiAddress: `{address}` is no IP address or domain name, with or without a port"
            )
        })?;
        let peer = match host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(_) => (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|error| format!("warp: apiAddress `{host}`: {error}"))?
                .next()
                .ok_or_else(|| format!("warp: apiAddress `{host}` resolves to nothing"))?,
        };
        endpoint.address = Some(peer);
    }
    Ok(endpoint)
}

/// An IP address, an IPv6 one with or without brackets, or a domain name,
/// optionally followed by `:port`.
fn split_host_port(text: &str, default_port: u16) -> Option<(String, u16)> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Some((address.ip().to_string(), address.port()));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some((ip.to_string(), default_port));
    }
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return match tail.strip_prefix(':') {
            Some(port) => port.parse().ok().map(|port| (host.to_owned(), port)),
            None if tail.is_empty() => Some((host.to_owned(), default_port)),
            None => None,
        };
    }
    if let Some((host, port)) = text.rsplit_once(':') {
        if host.is_empty() || host.contains(':') || host.parse::<IpAddr>().is_ok() {
            return None;
        }
        return port.parse().ok().map(|port| (host.to_owned(), port));
    }
    Some((text.to_owned(), default_port))
}

/// The `masque` block's five fields, each defaulting to the WARP edge the API names.
fn masque_settings(masque: Option<&crate::json::Json>) -> (String, u16, String, String, String) {
    let field = |key: &str, fallback: &str| {
        masque
            .and_then(|masque| masque.get(key))
            .and_then(crate::json::Json::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback)
            .to_owned()
    };
    let port = masque
        .and_then(|masque| masque.get("port"))
        .and_then(crate::json::Json::as_port)
        .unwrap_or(QUIC_PORT);
    (
        field("address", CONNECT_HOST),
        port,
        field("serverName", CONNECT_SNI),
        field("host", CONNECT_HOST),
        field("path", "/"),
    )
}

fn parse_endpoint(text: &str) -> Option<SocketAddr> {
    text.trim().parse().ok()
}

/// The body `POST /reg` sends: a fresh Curve25519 key and the device shape the
/// API answers with the account's own keys and addresses.
fn registration_body(public: &[u8; 32], tos: &str, serial: &str) -> Vec<u8> {
    let pairs = vec![
        ("key", string(&b64(public))),
        ("install_id", string("")),
        ("fcm_token", string("")),
        ("tos", string(tos)),
        ("model", string("PC")),
        ("serial_number", string(serial)),
        ("os_version", string("")),
        ("key_type", string("curve25519")),
        ("tunnel_type", string("wireguard")),
        ("locale", string("en_US")),
    ];
    json_bytes(&obj_pairs(pairs))
}

/// A serial of eight random bytes in hex, the shape the API's POST reads.
fn android_serial() -> String {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the OS entropy");
    let mut serial = String::with_capacity(16);
    for byte in bytes {
        std::fmt::Write::write_fmt(&mut serial, format_args!("{byte:02x}")).expect("a hex pair");
    }
    serial
}

/// The body that enrolls the P-256 key the MASQUE half presents.
fn enrollment_body(spki: &[u8]) -> Vec<u8> {
    let pairs = vec![
        ("key", string(&b64(spki))),
        ("key_type", string("secp256r1")),
        ("tunnel_type", string("masque")),
    ];
    json_bytes(&obj_pairs(pairs))
}

const ENABLE_BODY: &[u8] = br#"{"warp_enabled":true}"#;

fn registration_headers(bearer: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "Content-Type".to_owned(),
            "application/json; charset=UTF-8".to_owned(),
        ),
        ("User-Agent".to_owned(), REGISTER_AGENT.to_owned()),
        ("CF-Client-Version".to_owned(), CLIENT_VERSION.to_owned()),
        ("Accept".to_owned(), "application/json".to_owned()),
    ];
    if let Some(token) = bearer {
        headers.push(("Authorization".to_owned(), token.to_owned()));
    }
    headers
}

/// A registration can fail before the device exists (another API host may
/// answer) or after it exists (a retry would create a second device); only a
/// refusal of the identity is worth replacing rather than retrying.
#[derive(Debug)]
struct RegisterError {
    fatal: bool,
    refused: bool,
    reason: String,
}

impl RegisterError {
    fn retryable(reason: impl Into<String>) -> Self {
        Self {
            fatal: false,
            refused: false,
            reason: reason.into(),
        }
    }

    fn fatal(reason: impl Into<String>) -> Self {
        Self {
            fatal: true,
            refused: false,
            reason: reason.into(),
        }
    }

    fn refused(reason: impl Into<String>) -> Self {
        Self {
            fatal: true,
            refused: true,
            reason: reason.into(),
        }
    }
}

/// Register against the first host that answers, then enroll and enable; a
/// refusal names the host that refused so a runner's console can act on it.
fn register(spec: &WarpSpec, enroll: bool) -> Result<Identity, String> {
    let mut last = String::new();
    for base in spec.api_url() {
        let endpoint = match api_endpoint(spec, &base) {
            Ok(endpoint) => endpoint,
            Err(reason) => {
                last = reason;
                continue;
            }
        };
        match register_with(spec, enroll, &|method, path, headers, body| {
            let url = endpoint.url(path);
            // The reference dials one fresh HTTP/2 connection per call and never retries over HTTP/1.1; a failed leg says so.
            crate::foxy_account::h2_ask(&endpoint, method, &url, headers, body)
                .map_err(RegisterError::retryable)
        }) {
            Ok(identity) => return Ok(identity),
            Err(error) if error.fatal => {
                return Err(if last.is_empty() {
                    error.reason
                } else {
                    format!("{} (earlier: {last})", error.reason)
                });
            }
            Err(error) => last = error.reason,
        }
    }
    Err(last)
}

/// The calls, with the transport injected so a test records them and a real run
/// sends them over TLS. A device is saved only once WARP is enabled on it.
fn register_with<F>(spec: &WarpSpec, enroll: bool, call: &F) -> Result<Identity, RegisterError>
where
    F: Fn(&str, &str, &[(&str, &str)], &[u8]) -> Result<Reply, RegisterError>,
{
    let mut private = [0u8; 32];
    getrandom::fill(&mut private)
        .map_err(|error| RegisterError::retryable(format!("warp entropy: {error}")))?;
    clamp(&mut private);
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    let tos = tos_now();
    let serial = android_serial();
    let body = registration_body(&public, &tos, &serial);
    let headers = registration_headers(None);
    let headers = borrow_headers(&headers);
    let reply = call("POST", "/reg", &headers, &body)
        .map_err(|error| RegisterError::retryable(error.reason))?;
    // A 2xx that names the device it made is not posted again: another host would mint a second.
    let registered = parse_registration(&reply).map_err(|error| {
        let minted = (200..300).contains(&reply.status)
            && crate::json::parse(&String::from_utf8_lossy(&reply.body))
                .is_ok_and(|root| root.get("id").is_some() || root.get("token").is_some());
        if minted {
            RegisterError::fatal(error.reason)
        } else {
            error
        }
    })?;
    let bearer = format!("Bearer {}", registered.token);
    let path = format!("/reg/{}", registered.device_id);
    let mut masque = None;

    if enroll {
        let key = rcgen::KeyPair::generate()
            .map_err(|error| RegisterError::fatal(format!("warp MASQUE key: {error}")))?;
        let spki = decode_pem(&key.public_key_pem())
            .ok_or_else(|| RegisterError::fatal("warp MASQUE key: no public key"))?;
        let headers = registration_headers(Some(&bearer));
        let headers = borrow_headers(&headers);
        let reply = call("PATCH", &path, &headers, &enrollment_body(&spki)).map_err(|error| {
            RegisterError::fatal(format!("the WARP key enrollment failed: {}", error.reason))
        })?;
        let server = parse_masque_server(&reply)?;
        masque = Some(MasqueIdentity {
            private: key.serialize_der(),
            server,
            addresses: registered.addresses.clone(),
        });
    }

    let headers = registration_headers(Some(&bearer));
    let headers = borrow_headers(&headers);
    match call("PATCH", &path, &headers, ENABLE_BODY) {
        Err(error) => {
            return Err(RegisterError::fatal(format!(
                "the WARP enable failed: {}",
                error.reason
            )))
        }
        Ok(reply) if reply.status / 100 != 2 => {
            return Err(RegisterError::fatal(format!(
                "the WARP enable answered {}: {}",
                reply.status,
                reply_snippet(&reply.body)
            )))
        }
        Ok(_) => {}
    }

    Ok(Identity {
        device_id: registered.device_id,
        token: registered.token,
        wireguard: WireGuardIdentity {
            private,
            peer: registered.peer,
            endpoint: spec.endpoint.unwrap_or(registered.endpoint),
            addresses: registered.addresses,
            reserved: registered.reserved,
        },
        masque,
    })
}

/// Read a device back from the API, so an identity Cloudflare no longer knows
/// is replaced instead of handshaking into nothing.
fn refresh<F>(spec: &WarpSpec, identity: &Identity, call: &F) -> Result<Identity, RegisterError>
where
    F: Fn(&str, &str, &[(&str, &str)], &[u8]) -> Result<Reply, RegisterError>,
{
    let path = format!("/reg/{}", identity.device_id);
    let bearer = format!("Bearer {}", identity.token);
    let headers = registration_headers(Some(&bearer));
    let headers = borrow_headers(&headers);
    let reply = call("GET", &path, &headers, b"")?;
    if refuses_identity(&reply) {
        return Err(RegisterError::refused(format!(
            "the API answered the saved identity with {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    if !(200..300).contains(&reply.status) {
        return Err(RegisterError::retryable(format!(
            "the API answered the saved identity with {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    let root = reply_root(&reply)?;
    let config = parse_config(&root)?;
    let mut fresh = identity.clone();
    fresh.wireguard.peer = config.peer;
    fresh.wireguard.endpoint = spec.endpoint.unwrap_or(config.endpoint);
    fresh.wireguard.reserved = config.reserved;
    if !config.addresses.is_empty() {
        fresh.wireguard.addresses.clone_from(&config.addresses);
        if let Some(masque) = &mut fresh.masque {
            masque.addresses = config.addresses;
        }
    }
    Ok(fresh)
}

fn refuses_identity(reply: &Reply) -> bool {
    matches!(reply.status, 401 | 410) || (reply.status == 404 && is_api_envelope(&reply.body))
}

/// Cloudflare's JSON error envelope, rather than a page of another server that
/// fronts the name: a 404 page says nothing about the identity.
fn is_api_envelope(body: &[u8]) -> bool {
    crate::json::parse(&String::from_utf8_lossy(body)).is_ok_and(|root| {
        matches!(root.get("success"), Some(crate::json::Json::Bool(false)))
            && matches!(root.get("errors"), Some(crate::json::Json::Arr(errors)) if !errors.is_empty())
    })
}

/// The API's own answers only: an error page of another server is not a refusal
/// of the identity.
fn reply_root(reply: &Reply) -> Result<crate::json::Json, RegisterError> {
    crate::json::parse(&String::from_utf8_lossy(&reply.body))
        .map_err(|_| RegisterError::retryable("the WARP reply is not JSON"))
}

fn refresh_saved(spec: &WarpSpec, identity: &Identity) -> Result<Identity, RegisterError> {
    let mut last = String::new();
    for base in spec.api_url() {
        let endpoint = match api_endpoint(spec, &base) {
            Ok(endpoint) => endpoint,
            Err(reason) => {
                last = reason;
                continue;
            }
        };
        match refresh(spec, identity, &|method, path, headers, body| {
            let url = endpoint.url(path);
            crate::foxy_account::h2_ask(&endpoint, method, &url, headers, body)
                .map_err(RegisterError::retryable)
        }) {
            Ok(fresh) => return Ok(fresh),
            Err(error) if error.fatal => return Err(error),
            Err(error) => last = error.reason,
        }
    }
    Err(RegisterError::retryable(last))
}

fn reprovision_enabled() -> bool {
    reprovision_enabled_for(std::env::var("AETHER_REPROVISION").ok().as_deref())
}

fn reprovision_enabled_for(value: Option<&str>) -> bool {
    !value.is_some_and(|value| {
        ["0", "off", "false"]
            .iter()
            .any(|off| value.trim().eq_ignore_ascii_case(off))
    })
}

fn should_reprovision(register: bool, refused: bool, enabled: bool) -> bool {
    register && refused && enabled
}

fn quarantine(path: &Path) {
    let mut target = path.to_path_buf();
    let name = target.file_name().map_or_else(
        || "warp-identity.json".to_owned(),
        |name| name.to_string_lossy().to_string(),
    );
    let mut ordinal = 0;
    loop {
        target.set_file_name(if ordinal == 0 {
            format!("{name}.corrupt")
        } else {
            format!("{name}.corrupt.{ordinal}")
        });
        if !target.exists() {
            break;
        }
        ordinal += 1;
    }
    if let Err(error) = std::fs::rename(path, &target) {
        eprintln!(
            "warp: the damaged identity at {} could not be moved aside: {error}",
            path.display()
        );
    }
}

fn borrow_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

#[derive(Debug)]
struct Registered {
    device_id: String,
    token: String,
    peer: [u8; 32],
    endpoint: SocketAddr,
    addresses: Vec<IpAddr>,
    reserved: [u8; 3],
}

fn parse_registration(reply: &Reply) -> Result<Registered, RegisterError> {
    if !(200..300).contains(&reply.status) {
        return Err(RegisterError::retryable(format!(
            "the WARP service answered {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    let root = reply_root(reply)?;
    let config = parse_config(&root)?;
    let device_id = root
        .get("id")
        .and_then(crate::json::Json::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no device id"))?
        .to_owned();
    let token = root
        .get("token")
        .and_then(crate::json::Json::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no token"))?
        .to_owned();
    Ok(Registered {
        device_id,
        token,
        peer: config.peer,
        endpoint: config.endpoint,
        addresses: config.addresses,
        reserved: config.reserved,
    })
}

/// The `config` object both a registration and a read-back carry.
fn parse_config(root: &crate::json::Json) -> Result<DeviceConfig, RegisterError> {
    let config = root
        .get("config")
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no `config`"))?;
    let peer = config
        .get("peers")
        .and_then(crate::json::Json::as_arr)
        .and_then(|peers| peers.first())
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no peer"))?;
    let peer_key = peer
        .get("public_key")
        .and_then(crate::json::Json::as_str)
        .and_then(decode_key)
        .ok_or_else(|| RegisterError::retryable("the WARP reply's peer key is not 32 bytes"))?;
    let reserved = config
        .get("client_id")
        .and_then(crate::json::Json::as_str)
        .and_then(decode_bytes)
        .and_then(|bytes| <[u8; 3]>::try_from(bytes.as_slice()).ok())
        .unwrap_or([0u8; 3]);
    let endpoint = peer
        .get("endpoint")
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no endpoint"))?;
    let v4 = endpoint
        .get("v4")
        .and_then(crate::json::Json::as_str)
        .unwrap_or_default();
    let host = v4.rsplit_once(':').map_or(v4, |(host, _)| host);
    let ip = host
        .parse()
        .or_else(|_| {
            endpoint
                .get("host")
                .and_then(crate::json::Json::as_str)
                .unwrap_or_default()
                .parse()
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(162, 159, 192, 1)));
    let ports: Vec<u16> = endpoint
        .get("ports")
        .and_then(crate::json::Json::as_arr)
        .map(|ports| {
            ports
                .iter()
                .filter_map(crate::json::Json::as_u32)
                .filter_map(|port| u16::try_from(port).ok())
                .collect()
        })
        .unwrap_or_default();
    let port = if ports.is_empty() || ports.contains(&WIREGUARD_PORT) {
        WIREGUARD_PORT
    } else {
        ports[0]
    };
    Ok(DeviceConfig {
        peer: peer_key,
        endpoint: SocketAddr::new(ip, port),
        addresses: reply_addresses(config),
        reserved,
    })
}

struct DeviceConfig {
    peer: [u8; 32],
    endpoint: SocketAddr,
    addresses: Vec<IpAddr>,
    reserved: [u8; 3],
}

fn reply_addresses(config: &crate::json::Json) -> Vec<IpAddr> {
    let interface = config
        .get("interface")
        .and_then(|value| value.get("addresses"));
    ["v4", "v6"]
        .iter()
        .filter_map(|family| {
            interface?
                .get(family)
                .and_then(crate::json::Json::as_str)
                .and_then(|text| text.trim().split('/').next())
                .and_then(|text| text.parse().ok())
        })
        .collect()
}

fn parse_masque_server(reply: &Reply) -> Result<Vec<u8>, RegisterError> {
    if !(200..300).contains(&reply.status) {
        return Err(RegisterError::fatal(format!(
            "the WARP key enrollment answered {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    let root = crate::json::parse(&String::from_utf8_lossy(&reply.body))
        .map_err(|_| RegisterError::fatal("the WARP enrollment reply is not JSON"))?;
    let key = root
        .get("config")
        .and_then(|config| config.get("peers"))
        .and_then(crate::json::Json::as_arr)
        .and_then(|peers| peers.first())
        .and_then(|peer| peer.get("public_key"))
        .and_then(crate::json::Json::as_str)
        .ok_or_else(|| RegisterError::fatal("the WARP enrollment reply has no server key"))?;
    let der = if key.contains("-----BEGIN") {
        decode_pem(key)
    } else {
        decode_bytes(key)
    }
    .ok_or_else(|| RegisterError::fatal("the WARP enrollment server key is not base64 or PEM"))?;
    if !is_p256_spki(&der) {
        return Err(RegisterError::fatal(
            "the WARP enrollment reply's key is not a P-256 SPKI",
        ));
    }
    Ok(der)
}

/// The reply's head, one line, for a runner's console: a WARP refusal that only
/// names a status cannot be acted on.
fn reply_snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(&body[..body.len().min(160)]);
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.is_empty() {
        "empty".to_owned()
    } else {
        line
    }
}

/// The P-256 algorithm identifier inside a `SubjectPublicKeyInfo`.
fn is_p256_spki(der: &[u8]) -> bool {
    const P256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    der.windows(P256.len()).any(|window| window == P256)
}

/// A save the service cannot read back is not a corrupt identity: only a failed
/// parse or field check may be replaced.
#[derive(Debug)]
enum LoadError {
    Read(String),
    Corrupt(String),
}

impl LoadError {
    fn corrupt(&self) -> bool {
        matches!(self, Self::Corrupt(_))
    }

    fn into_message(self) -> String {
        match self {
            Self::Read(message) | Self::Corrupt(message) => message,
        }
    }
}

impl Identity {
    fn from_json(value: &crate::json::Json) -> Result<Self, String> {
        let device_id = value
            .get("deviceId")
            .and_then(crate::json::Json::as_str)
            .unwrap_or_default()
            .to_owned();
        let token = value
            .get("token")
            .and_then(crate::json::Json::as_str)
            .unwrap_or_default()
            .to_owned();
        let wireguard = value
            .get("wireguard")
            .ok_or("warp identity has no `wireguard`")?;
        let private = wireguard
            .get("privateKey")
            .and_then(crate::json::Json::as_str)
            .and_then(decode_key)
            .ok_or("warp identity's wireguard `privateKey` is not 32 bytes")?;
        let peer = wireguard
            .get("publicKey")
            .and_then(crate::json::Json::as_str)
            .and_then(decode_key)
            .ok_or("warp identity's wireguard `publicKey` is not 32 bytes")?;
        let endpoint = wireguard
            .get("endpoint")
            .and_then(crate::json::Json::as_str)
            .and_then(parse_endpoint)
            .ok_or("warp identity's wireguard `endpoint` is not host:port")?;
        let addresses = json_addresses(wireguard.get("address"));
        if addresses.is_empty() {
            return Err("warp identity's wireguard `address` is empty".to_owned());
        }
        let reserved = wireguard
            .get("reserved")
            .and_then(crate::json::Json::as_arr)
            .and_then(|items| {
                if items.len() != 3 {
                    return None;
                }
                let mut reserved = [0u8; 3];
                for (slot, item) in reserved.iter_mut().zip(items) {
                    *slot = u8::try_from(item.as_u32()?).ok()?;
                }
                Some(reserved)
            })
            .unwrap_or([0u8; 3]);
        let masque = value.get("masque").map(|masque| {
            let private = masque
                .get("privateKey")
                .and_then(crate::json::Json::as_str)
                .and_then(decode_bytes)
                .ok_or("warp identity's masque `privateKey` is not base64")?;
            let server = masque
                .get("publicKey")
                .and_then(crate::json::Json::as_str)
                .and_then(decode_bytes)
                .ok_or("warp identity's masque `publicKey` is not base64")?;
            let mut addresses = json_addresses(masque.get("address"));
            if addresses.is_empty() {
                addresses.clone_from(&wireguard_addresses(value));
            }
            Ok::<_, String>(MasqueIdentity {
                private,
                server,
                addresses,
            })
        });
        let masque = masque.transpose()?;
        Ok(Self {
            device_id,
            token,
            wireguard: WireGuardIdentity {
                private,
                peer,
                endpoint,
                addresses,
                reserved,
            },
            masque,
        })
    }

    fn to_json(&self) -> crate::json::Json {
        let wireguard = obj_pairs(vec![
            ("privateKey", string(&b64(&self.wireguard.private))),
            ("publicKey", string(&b64(&self.wireguard.peer))),
            ("endpoint", string(&self.wireguard.endpoint.to_string())),
            ("address", address_json(&self.wireguard.addresses)),
            (
                "reserved",
                crate::json::Json::Arr(
                    self.wireguard
                        .reserved
                        .iter()
                        .map(|byte| crate::json::Json::Num(f64::from(*byte)))
                        .collect(),
                ),
            ),
        ]);
        let mut pairs = vec![
            ("deviceId", string(&self.device_id)),
            ("token", string(&self.token)),
            ("wireguard", wireguard),
        ];
        if let Some(masque) = &self.masque {
            pairs.push((
                "masque",
                obj_pairs(vec![
                    ("privateKey", string(&b64(&masque.private))),
                    ("publicKey", string(&b64(&masque.server))),
                    ("address", address_json(&masque.addresses)),
                ]),
            ));
        }
        obj_pairs(pairs)
    }

    fn load(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            LoadError::Read(format!("warp: cannot read `{}`: {error}", path.display()))
        })?;
        let value = crate::json::parse(&text).map_err(|error| {
            LoadError::Corrupt(format!("warp: `{}` is not JSON: {error}", path.display()))
        })?;
        Self::from_json(&value)
            .map_err(|error| LoadError::Corrupt(format!("warp: `{}`: {error}", path.display())))
    }

    /// Write beside the target and rename over it, so a reader never sees half
    /// an identity and a failure leaves the old keys in place; the temporary is
    /// 0600 on Unix, and on Windows it inherits the directory ACL.
    fn save(&self, path: &Path) -> Result<(), String> {
        let mut text = String::new();
        crate::json::write(&self.to_json(), &mut text);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("warp: cannot create `{}`: {error}", parent.display()))?;
        }
        let mut temp = path.to_path_buf();
        let name = temp.file_name().map_or_else(
            || "warp-identity.json".to_owned(),
            |name| name.to_string_lossy().to_string(),
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        temp.set_file_name(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
        let mut created = false;
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|error| format!("warp: cannot write `{}`: {error}", temp.display()))?;
            created = true;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| format!("warp: cannot lock `{}`: {error}", temp.display()))?;
            }
            file.write_all(text.as_bytes())
                .map_err(|error| format!("warp: cannot write `{}`: {error}", temp.display()))?;
            file.sync_all()
                .map_err(|error| format!("warp: cannot sync `{}`: {error}", temp.display()))?;
            drop(file);
            std::fs::rename(&temp, path)
                .map_err(|error| format!("warp: cannot save `{}`: {error}", path.display()))?;
            #[cfg(unix)]
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                if let Ok(parent) = std::fs::File::open(parent) {
                    let _ = parent.sync_all();
                }
            }
            Ok(())
        })();
        if result.is_err() && created {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

fn wireguard_addresses(value: &crate::json::Json) -> Vec<IpAddr> {
    value
        .get("wireguard")
        .map(|wireguard| json_addresses(wireguard.get("address")))
        .unwrap_or_default()
}

fn json_addresses(value: Option<&crate::json::Json>) -> Vec<IpAddr> {
    value
        .and_then(crate::json::Json::as_arr)
        .map(|items| {
            items
                .iter()
                .filter_map(crate::json::Json::as_str)
                .filter_map(|text| text.trim().split('/').next())
                .filter_map(|text| text.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn address_json(addresses: &[IpAddr]) -> crate::json::Json {
    crate::json::Json::Arr(
        addresses
            .iter()
            .map(|address| string(&address.to_string()))
            .collect(),
    )
}

/// The `WireGuard` half as the existing `wireguard` outbound reads it.
fn wireguard_settings(identity: &Identity, spec: &WarpSpec) -> crate::json::Json {
    let wireguard = &identity.wireguard;
    let peer = obj_pairs(vec![
        ("publicKey", string(&b64(&wireguard.peer))),
        ("endpoint", string(&wireguard.endpoint.to_string())),
        (
            "allowedIPs",
            crate::json::Json::Arr(vec![string("0.0.0.0/0"), string("::/0")]),
        ),
        (
            "keepAlive",
            crate::json::Json::Num(f64::from(spec.keepalive)),
        ),
    ]);
    obj_pairs(vec![
        ("secretKey", string(&b64(&wireguard.private))),
        ("address", address_json(&wireguard.addresses)),
        ("peers", crate::json::Json::Arr(vec![peer])),
        ("reserved", reserved_json(wireguard.reserved)),
        ("isClient", crate::json::Json::Bool(true)),
        ("mtu", crate::json::Json::Num(f64::from(spec.mtu))),
        ("noKernelTun", crate::json::Json::Bool(true)),
        ("remoteDNS", address_json(&spec.dns)),
    ])
}

/// The MASQUE half as the existing `masque` outbound reads it: the enrolled
/// key pair, the edge's pinned key, and the WARP host and SNI.
fn masque_outbound(identity: &Identity, spec: &WarpSpec) -> Result<crate::json::Json, String> {
    let masque = identity
        .masque
        .as_ref()
        .ok_or("warp: this identity has no MASQUE key")?;
    let warp = obj_pairs(vec![
        ("privateKey", string(&b64(&masque.private))),
        ("publicKey", string(&b64(&masque.server))),
        ("address", address_json(&masque.addresses)),
    ]);
    let masque_settings = obj_pairs(vec![
        ("warp", warp),
        ("host", string(&spec.masque_host)),
        ("path", string(&spec.masque_path)),
    ]);
    let tls = obj_pairs(vec![
        ("serverName", string(&spec.masque_server_name)),
        ("allowInsecure", crate::json::Json::Bool(true)),
    ]);
    let stream = obj_pairs(vec![
        ("network", string("masque")),
        ("security", string("tls")),
        ("tlsSettings", tls),
        ("masqueSettings", masque_settings),
    ]);
    let settings = obj_pairs(vec![
        ("address", string(&spec.masque_address)),
        ("port", crate::json::Json::Num(f64::from(spec.masque_port))),
        ("remoteDNS", address_json(&spec.dns)),
    ]);
    Ok(obj_pairs(vec![
        ("protocol", string("masque")),
        ("settings", settings),
        ("streamSettings", stream),
    ]))
}

fn reserved_json(reserved: [u8; 3]) -> crate::json::Json {
    crate::json::Json::Arr(
        reserved
            .iter()
            .map(|byte| crate::json::Json::Num(f64::from(*byte)))
            .collect(),
    )
}

/// Which half carried the first answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    WireGuard,
    Masque,
}

/// The outbound: both built halves, the mode that bounds which may run, and
/// the race's answer once it has one.
#[derive(Debug)]
pub(crate) struct WarpOut {
    mode: Mode,
    wireguard: Option<Arc<crate::wg::WireGuardOut>>,
    masque: Option<Arc<crate::masque::MasqueOut>>,
    chosen: Mutex<Option<Lane>>,
    probe_host: String,
    probe_port: u16,
}

impl WarpOut {
    pub(crate) fn new(outbound: &crate::json::Json, test: bool) -> Result<Self, String> {
        let settings = outbound
            .get("settings")
            .ok_or("warp outbound has no settings")?;
        let spec = WarpSpec::from(settings)?;
        let identity = if test
            && spec.inline.is_none()
            && !spec
                .identity_file
                .as_ref()
                .is_some_and(|path| path.is_file())
        {
            // A config test names the settings; the registration stays a runtime act.
            return Ok(Self {
                mode: spec.mode,
                wireguard: None,
                masque: None,
                chosen: Mutex::new(None),
                probe_host: spec.probe_host,
                probe_port: spec.probe_port,
            });
        } else {
            spec.identity()?
        };
        let wireguard = if spec.mode == Mode::Masque {
            None
        } else {
            match build_wireguard(&identity, &spec) {
                Ok(wireguard) => Some(Arc::new(wireguard)),
                Err(reason) if spec.mode == Mode::WireGuard => {
                    return Err(format!("warp wireguard half: {reason}"));
                }
                Err(reason) => {
                    eprintln!("warp: the wireguard half did not build: {reason}");
                    None
                }
            }
        };
        let masque = if spec.mode == Mode::WireGuard {
            None
        } else if identity.masque.is_none() {
            if spec.mode == Mode::Masque {
                return Err("warp masque half: the identity has no MASQUE key".to_owned());
            }
            None
        } else {
            match build_masque(&identity, &spec) {
                Ok(masque) => Some(Arc::new(masque)),
                Err(reason) if spec.mode == Mode::Masque => {
                    return Err(format!("warp masque half: {reason}"));
                }
                Err(reason) => {
                    eprintln!("warp: the masque half did not build: {reason}");
                    None
                }
            }
        };
        if wireguard.is_none() && masque.is_none() {
            return Err("warp: neither half could be built".to_owned());
        }
        Ok(Self {
            mode: spec.mode,
            wireguard,
            masque,
            chosen: Mutex::new(None),
            probe_host: spec.probe_host,
            probe_port: spec.probe_port,
        })
    }

    /// The configured mode, or the race's winner in auto. A fixed mode never
    /// races, and an auto with one built half takes it without a probe.
    fn lane(&self) -> Lane {
        match self.mode {
            Mode::WireGuard => return Lane::WireGuard,
            Mode::Masque => return Lane::Masque,
            Mode::Auto => {}
        }
        // The lock spans the race so a second flow waits for the answer instead of probing again.
        let mut chosen = match self.chosen.lock() {
            Ok(chosen) => chosen,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(lane) = *chosen {
            return lane;
        }
        let (lane, answered) = match (&self.wireguard, &self.masque) {
            (Some(_) | None, None) => (Lane::WireGuard, true),
            (None, Some(_)) => (Lane::Masque, true),
            (Some(wireguard), Some(masque)) => {
                let wg = Arc::clone(wireguard);
                let mq = Arc::clone(masque);
                let (host, port) = (self.probe_host.clone(), self.probe_port);
                let masque_host = host.clone();
                race_probes(
                    move || wg.probe(&host, port),
                    move || mq.probe(&masque_host, port),
                    RACE_DEADLINE,
                )
            }
        };
        // Only a half that answered is a winner; a deadline fallback races again.
        if answered {
            *chosen = Some(lane);
        }
        lane
    }

    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        match self.mode {
            Mode::WireGuard => self.wireguard.as_ref().and_then(|half| half.edge()),
            Mode::Masque => self.masque.as_ref().and_then(|half| half.edge()),
            Mode::Auto => match self.chosen.lock().ok().and_then(|chosen| *chosen) {
                Some(Lane::WireGuard) => self.wireguard.as_ref().and_then(|half| half.edge()),
                Some(Lane::Masque) => self.masque.as_ref().and_then(|half| half.edge()),
                None => self
                    .wireguard
                    .as_ref()
                    .and_then(|half| half.edge())
                    .or_else(|| self.masque.as_ref().and_then(|half| half.edge())),
            },
        }
    }

    pub(crate) fn serve_tcp(
        &self,
        client: crate::conn::Connection,
        asked: &crate::proxy::Destination,
        prefix: &[u8],
    ) {
        match self.lane() {
            Lane::WireGuard => {
                if let Some(wireguard) = &self.wireguard {
                    wireguard.serve_tcp(client, asked, prefix);
                }
            }
            Lane::Masque => {
                if let Some(masque) = &self.masque {
                    masque.serve_tcp(client, asked, prefix);
                }
            }
        }
    }

    pub(crate) fn serve_udp(
        &self,
        relay: &std::net::UdpSocket,
        associate: Option<&crate::conn::Connection>,
    ) {
        match self.lane() {
            Lane::WireGuard => {
                if let Some(wireguard) = &self.wireguard {
                    wireguard.serve_udp(relay, associate);
                }
            }
            Lane::Masque => {
                if let Some(masque) = &self.masque {
                    masque.serve_udp(relay, associate);
                }
            }
        }
    }
}

/// The first half to answer the probe wins. A failed answer is not the race's
/// end: the other half may still carry. If neither answers by the deadline,
/// `WireGuard` is the fallback a fixed config would have chosen, reported as
/// unanswered so the caller keeps racing on later flows.
fn race_probes<W, M>(wireguard: W, masque: M, budget: Duration) -> (Lane, bool)
where
    W: FnOnce() -> bool + Send + 'static,
    M: FnOnce() -> bool + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let wg_sender = sender.clone();
    std::thread::spawn(move || {
        let _ = wg_sender.send((Lane::WireGuard, wireguard()));
    });
    std::thread::spawn(move || {
        let _ = sender.send((Lane::Masque, masque()));
    });
    let deadline = Instant::now() + budget;
    let mut failed = 0;
    while failed < 2 {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match receiver.recv_timeout(left) {
            Ok((lane, true)) => return (lane, true),
            Ok((_, false)) => failed += 1,
            Err(_) => break,
        }
    }
    (Lane::WireGuard, false)
}

fn build_wireguard(
    identity: &Identity,
    spec: &WarpSpec,
) -> Result<crate::wg::WireGuardOut, String> {
    let settings = wireguard_settings(identity, spec);
    let config = crate::wireguard::DeviceConfig::from_json(&settings)?;
    crate::wg::WireGuardOut::new(config)
}

fn build_masque(identity: &Identity, spec: &WarpSpec) -> Result<crate::masque::MasqueOut, String> {
    let outbound = masque_outbound(identity, spec)?;
    crate::masque::MasqueOut::new(&outbound)
}

/// The `--register` kinds: one protocol, both hops of a two-hop one, or all five.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Masque,
    WireGuard,
    Gool,
    GoolClassic,
    Mim,
    All,
}

impl KeyKind {
    fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "masque" => Ok(Self::Masque),
            "wg" | "wireguard" | "warp" => Ok(Self::WireGuard),
            "gool" | "wg-over-masque" => Ok(Self::Gool),
            "gool-classic" | "wiw" | "warp-in-warp" => Ok(Self::GoolClassic),
            "mim" | "masque-in-masque" => Ok(Self::Mim),
            "all" => Ok(Self::All),
            other => Err(format!(
                "warp-register: --register takes masque, wg, gool, gool-classic, mim or all, not `{other}`"
            )),
        }
    }

    fn slots(self) -> &'static [Slot] {
        match self {
            Self::Masque => &[Slot::Masque],
            Self::WireGuard => &[Slot::WireGuard],
            Self::Gool => &[Slot::Masque, Slot::Gool],
            Self::GoolClassic => &[Slot::WireGuard, Slot::WireGuardInner],
            Self::Mim => &[Slot::Masque, Slot::MasqueInner],
            Self::All => &[
                Slot::WireGuard,
                Slot::WireGuardInner,
                Slot::Masque,
                Slot::MasqueInner,
                Slot::Gool,
            ],
        }
    }
}

/// One identity file: a transport's first hop, its second, or the `WireGuard`
/// identity gool carries inside its MASQUE tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    WireGuard,
    WireGuardInner,
    Masque,
    MasqueInner,
    Gool,
}

impl Slot {
    fn label(self) -> &'static str {
        match self {
            Self::WireGuard => "wireguard",
            Self::WireGuardInner => "wireguard inner",
            Self::Masque => "masque",
            Self::MasqueInner => "masque inner",
            Self::Gool => "gool",
        }
    }

    /// Only a MASQUE identity carries the P-256 key the tunnel presents; the
    /// gool slot is `WireGuard` carried inside that tunnel, not a MASQUE device.
    fn enrolls_masque(self) -> bool {
        matches!(self, Self::Masque | Self::MasqueInner)
    }

    fn path(self, paths: &KeyPaths) -> PathBuf {
        match self {
            Self::WireGuard => paths.wireguard.clone(),
            Self::WireGuardInner => derive_sibling_path(&paths.wireguard, "secondary"),
            Self::Masque => paths.masque.clone(),
            Self::MasqueInner => derive_sibling_path(&paths.masque, "secondary"),
            Self::Gool => derive_sibling_path(&paths.masque, "gool"),
        }
    }
}

/// Where each transport keeps its identity: the `WireGuard` file as named, the
/// MASQUE file beside it, and every second hop derived from its own first.
struct KeyPaths {
    wireguard: PathBuf,
    masque: PathBuf,
}

impl KeyPaths {
    fn new(base: &Path, wireguard: Option<&Path>, masque: Option<&Path>) -> Self {
        Self {
            wireguard: wireguard.map_or_else(|| base.to_path_buf(), Path::to_path_buf),
            masque: masque.map_or_else(|| derive_sibling_path(base, "masque"), Path::to_path_buf),
        }
    }
}

fn derive_sibling_path(base: &Path, suffix: &str) -> PathBuf {
    let name = base
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let derived = match name.rfind('.') {
        Some(dot) if dot > 0 => format!("{}-{}{}", &name[..dot], suffix, &name[dot..]),
        _ => format!("{name}-{suffix}"),
    };
    base.with_file_name(derived)
}

fn planned_slots(kind: KeyKind, paths: &KeyPaths) -> Result<Vec<(Slot, PathBuf)>, String> {
    let mut planned: Vec<(Slot, PathBuf)> = Vec::new();
    for &slot in kind.slots() {
        let path = slot.path(paths);
        if planned.iter().any(|(_, other)| *other == path) {
            return Err(format!(
                "warp-register: the {} identity would share {}; give each slot its own file",
                slot.label(),
                path.display()
            ));
        }
        planned.push((slot, path));
    }
    Ok(planned)
}

struct PlannedSlot {
    slot: Slot,
    path: PathBuf,
    identity: Identity,
    replace: bool,
    saved: bool,
}

/// Load or make every identity the kind names. A slot with no file is saved as
/// soon as it is made so a later failure does not orphan it; a replacement is
/// held until every slot is ready, so a failed registration leaves the old keys.
fn provision_kind(
    spec: &WarpSpec,
    kind: KeyKind,
    paths: &KeyPaths,
) -> Result<Vec<PlannedSlot>, String> {
    let planned = planned_slots(kind, paths)?;
    let mut ready = Vec::new();
    for (slot, path) in planned {
        let (identity, replace, saved) = if path.is_file() {
            match Identity::load(&path) {
                Ok(saved) => match refresh_saved(spec, &saved) {
                    Ok(fresh) => (fresh, false, false),
                    Err(error) if error.refused && reprovision_enabled() => {
                        eprintln!(
                            "warp-register: the saved {} identity was refused: {}; registering a fresh one",
                            slot.label(),
                            error.reason
                        );
                        (register(spec, slot.enrolls_masque())?, true, false)
                    }
                    Err(error) => {
                        eprintln!(
                            "warp-register: keeping the saved {} identity unchecked: {}",
                            slot.label(),
                            error.reason
                        );
                        (saved, false, false)
                    }
                },
                Err(error) if error.corrupt() && reprovision_enabled() => {
                    eprintln!(
                        "warp-register: {}; registering a fresh {} identity",
                        error.into_message(),
                        slot.label()
                    );
                    (register(spec, slot.enrolls_masque())?, true, false)
                }
                Err(error) => return Err(error.into_message()),
            }
        } else {
            let identity = register(spec, slot.enrolls_masque())?;
            identity.save(&path)?;
            (identity, false, true)
        };
        ready.push(PlannedSlot {
            slot,
            path,
            identity,
            replace,
            saved,
        });
    }
    Ok(ready)
}

/// One-tap registration: create a device, enroll its MASQUE key, enable it,
/// save the identity where only the user can read it, and return the outbound
/// config that references the saved file.
pub(crate) fn one_tap(
    path: &str,
    mode: &str,
    api: Option<&str>,
    api_address: Option<&str>,
) -> Result<String, String> {
    let mode = Mode::parse(Some(mode))?;
    let path = PathBuf::from(path);
    if path.is_file() {
        return Err(format!(
            "warp: identity file {} already exists; refusing to overwrite a working device",
            path.display()
        ));
    }
    let spec = WarpSpec {
        mode,
        register: true,
        identity_file: Some(path.clone()),
        inline: None,
        api: api.map(str::to_owned),
        api_address: api_address.map(str::to_owned),
        endpoint: None,
        mtu: DEFAULT_MTU,
        keepalive: DEFAULT_KEEPALIVE,
        probe_host: PROBE_HOST.to_owned(),
        probe_port: PROBE_PORT,
        dns: TUNNEL_DNS
            .iter()
            .filter_map(|text| text.parse().ok())
            .collect(),
        masque_address: CONNECT_HOST.to_owned(),
        masque_port: QUIC_PORT,
        masque_server_name: CONNECT_SNI.to_owned(),
        masque_host: CONNECT_HOST.to_owned(),
        masque_path: "/".to_owned(),
    };
    let identity = register(&spec, true)?;
    identity.save(&path)?;
    let outbound = obj_pairs(vec![
        ("protocol", string("warp")),
        (
            "settings",
            obj_pairs(vec![
                ("mode", string(mode.label())),
                ("identityFile", string(&path.to_string_lossy())),
            ]),
        ),
    ]);
    let config = obj_pairs(vec![("outbounds", crate::json::Json::Arr(vec![outbound]))]);
    let mut text = String::new();
    crate::json::write(&config, &mut text);
    Ok(text)
}

fn string(text: &str) -> crate::json::Json {
    crate::json::Json::Str(text.to_owned())
}

fn obj_pairs(pairs: Vec<(&str, crate::json::Json)>) -> crate::json::Json {
    crate::json::Json::Obj(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn json_bytes(value: &crate::json::Json) -> Vec<u8> {
    let mut text = String::new();
    crate::json::write(value, &mut text);
    text.into_bytes()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_bytes(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    let unpadded = text.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(unpadded))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(unpadded))
        .ok()
}

fn decode_key(text: &str) -> Option<[u8; 32]> {
    decode_bytes(text).and_then(|bytes| bytes.try_into().ok())
}

/// A PEM body is standard base64 between the marker lines.
fn decode_pem(text: &str) -> Option<Vec<u8>> {
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    decode_bytes(&body)
}

fn clamp(private: &mut [u8; 32]) {
    private[0] &= 0xF8;
    private[31] &= 0x7F;
    private[31] |= 0x40;
}

/// RFC 3339 with milliseconds in UTC, the shape the API's `tos` field reads.
fn tos_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or_default();
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}+00:00",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        now.subsec_millis()
    )
}

/// The civil date of a count of days since 1970-01-01, Howard Hinnant's
/// `civil_from_days`, with the same integer arithmetic the reference uses.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

/// The `warp-register` command: with `--register` make the identities a kind
/// names and print where they are; without it, register once and print the
/// outbound that references the saved combined identity.
pub(crate) fn register_command(args: &mut std::iter::Skip<std::env::Args>, usage: fn() -> !) {
    let mut base = String::from("warp-identity.json");
    let mut mode = String::from("auto");
    let mut api = None;
    let mut api_address = None;
    let mut kind = None;
    let mut wireguard = None;
    let mut masque = None;
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "-o" | "--out" | "--identity" | "--config" => base = value(),
            "--mode" => mode = value(),
            "--api" => api = Some(value()),
            "--api-address" => api_address = Some(value()),
            "--wg-config" => wireguard = Some(value()),
            "--masque-config" => masque = Some(value()),
            "--register" => {
                let text = value();
                kind = Some(match KeyKind::parse(&text) {
                    Ok(kind) => kind,
                    Err(reason) => {
                        eprintln!("{reason}");
                        std::process::exit(2);
                    }
                });
            }
            _ => usage(),
        }
    }
    let result = match kind {
        None => {
            if wireguard.is_some() || masque.is_some() {
                usage();
            }
            one_tap(&base, &mode, api.as_deref(), api_address.as_deref())
        }
        Some(kind) => {
            let mode = match Mode::parse(Some(&mode)) {
                Ok(mode) => mode,
                Err(reason) => {
                    eprintln!("warp-register: {reason}");
                    std::process::exit(1);
                }
            };
            let spec = WarpSpec::for_command(mode, api, api_address);
            let paths = KeyPaths::new(
                Path::new(&base),
                wireguard.as_deref().map(Path::new),
                masque.as_deref().map(Path::new),
            );
            match provision_kind(&spec, kind, &paths).and_then(|planned| {
                for planned in &planned {
                    if !planned.saved {
                        if planned.replace {
                            quarantine(&planned.path);
                        }
                        planned.identity.save(&planned.path)?;
                    }
                    println!(
                        "[+] {} identity ready: device={} at {}",
                        planned.slot.label(),
                        planned.identity.device_id,
                        planned.path.display()
                    );
                }
                Ok(())
            }) {
                Ok(()) => Ok(String::new()),
                Err(reason) => Err(reason),
            }
        }
    };
    match result {
        Ok(text) if text.is_empty() => {}
        Ok(text) => println!("{text}"),
        Err(reason) => {
            eprintln!("warp-register: {reason}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_reply(peer_key: &str) -> Reply {
        let peer = obj_pairs(vec![
            ("public_key", string(peer_key)),
            (
                "endpoint",
                obj_pairs(vec![
                    ("v4", string("192.0.2.1:0")),
                    (
                        "ports",
                        crate::json::Json::Arr(vec![
                            crate::json::Json::Num(500.0),
                            crate::json::Json::Num(2408.0),
                        ]),
                    ),
                ]),
            ),
        ]);
        let interface = obj_pairs(vec![(
            "addresses",
            obj_pairs(vec![
                ("v4", string("172.16.0.2")),
                ("v6", string("2606:4700:110:8a1b::2")),
            ]),
        )]);
        let config = obj_pairs(vec![
            ("client_id", string(&b64(&[9, 8, 7]))),
            ("peers", crate::json::Json::Arr(vec![peer])),
            ("interface", interface),
        ]);
        let root = obj_pairs(vec![
            ("id", string("a-device")),
            ("token", string("a-token")),
            ("config", config),
        ]);
        Reply {
            status: 200,
            headers: Vec::new(),
            body: json_bytes(&root),
        }
    }

    #[test]
    fn a_registration_is_register_enroll_enable() {
        let key = rcgen::KeyPair::generate().expect("a MASQUE key");
        let server = key.public_key_pem();
        let calls = Mutex::new(Vec::new());
        let spec = WarpSpec {
            mode: Mode::Auto,
            register: true,
            identity_file: None,
            inline: None,
            api: None,
            api_address: None,
            endpoint: None,
            mtu: DEFAULT_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            probe_host: PROBE_HOST.to_owned(),
            probe_port: PROBE_PORT,
            dns: Vec::new(),
            masque_address: CONNECT_HOST.to_owned(),
            masque_port: QUIC_PORT,
            masque_server_name: CONNECT_SNI.to_owned(),
            masque_host: CONNECT_HOST.to_owned(),
            masque_path: "/".to_owned(),
        };
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let masque_reply = sample_reply(&server);
        let call = |method: &str, path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            calls.lock().expect("the call log").push((
                method.to_owned(),
                path.to_owned(),
                body.to_vec(),
            ));
            let reply = if method == "POST" {
                wireguard_reply.clone()
            } else {
                masque_reply.clone()
            };
            Ok::<_, RegisterError>(reply)
        };
        let identity = register_with(&spec, true, &call).expect("a registration");
        let recorded = calls.lock().expect("the call log");
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0].0, "POST");
        assert_eq!(recorded[0].1, "/reg");
        assert!(String::from_utf8_lossy(&recorded[0].2).contains(r#""key_type":"curve25519""#));
        assert_eq!(recorded[1].0, "PATCH");
        assert_eq!(recorded[1].1, "/reg/a-device");
        assert!(String::from_utf8_lossy(&recorded[1].2).contains(r#""tunnel_type":"masque""#));
        assert_eq!(recorded[2].2, ENABLE_BODY);
        assert_eq!(identity.wireguard.reserved, [9, 8, 7]);
        assert_eq!(
            identity.wireguard.endpoint,
            "192.0.2.1:2408".parse().expect("an endpoint")
        );
        assert_eq!(identity.wireguard.addresses.len(), 2);
        assert!(identity.masque.is_some());
    }

    #[test]
    fn a_registered_identity_builds_both_tunnels() {
        let key = rcgen::KeyPair::generate().expect("a MASQUE key");
        let identity = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec![
                    "172.16.0.2".parse().expect("a v4 address"),
                    "2606:4700:110:8a1b::2".parse().expect("a v6 address"),
                ],
                reserved: [1, 2, 3],
            },
            masque: Some(MasqueIdentity {
                private: key.serialize_der(),
                server: decode_pem(&key.public_key_pem()).expect("the server key"),
                addresses: vec!["172.16.0.2".parse().expect("a v4 address")],
            }),
        };
        let spec = WarpSpec {
            mode: Mode::Auto,
            register: false,
            identity_file: None,
            inline: Some(identity.clone()),
            api: None,
            api_address: None,
            endpoint: None,
            mtu: DEFAULT_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            probe_host: PROBE_HOST.to_owned(),
            probe_port: PROBE_PORT,
            dns: TUNNEL_DNS
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
            masque_address: "127.0.0.1".to_owned(),
            masque_port: QUIC_PORT,
            masque_server_name: CONNECT_SNI.to_owned(),
            masque_host: CONNECT_HOST.to_owned(),
            masque_path: "/".to_owned(),
        };
        let settings = wireguard_settings(&identity, &spec);
        let config = crate::wireguard::DeviceConfig::from_json(&settings).expect("the WG half");
        assert_eq!(config.reserved, [1, 2, 3]);
        assert_eq!(config.addresses.len(), 2);
        assert_eq!(config.mtu, usize::from(DEFAULT_MTU));
        assert_eq!(config.peers[0].endpoint, Some(identity.wireguard.endpoint));
        let outbound = masque_outbound(&identity, &spec).expect("the MASQUE half");
        crate::masque::MasqueOut::new(&outbound).expect("the MASQUE carrier");
        assert_eq!(
            wireguard_settings(&identity, &spec)
                .get("mtu")
                .and_then(crate::json::Json::as_u32),
            Some(u32::from(DEFAULT_MTU))
        );
    }

    #[test]
    fn the_auto_mode_races_both_tunnels() {
        assert_eq!(Mode::parse(None).expect("default"), Mode::Auto);
        assert_eq!(Mode::parse(Some("wg")).expect("wg"), Mode::WireGuard);
        assert_eq!(Mode::parse(Some("masque")).expect("masque"), Mode::Masque);
        assert!(Mode::parse(Some("other")).is_err());
    }

    #[test]
    fn the_first_answering_half_wins_the_race() {
        // MASQUE cannot answer until released, so WireGuard's answer is first by construction.
        let (release, wait) = mpsc::channel::<()>();
        let (lane, answered) = race_probes(
            || true,
            move || {
                let _ = wait.recv();
                true
            },
            Duration::from_secs(5),
        );
        assert_eq!(lane, Lane::WireGuard);
        assert!(answered);
        drop(release);
    }

    #[test]
    fn a_failed_probe_does_not_end_the_race() {
        // A false answer must not end the race: the other half may still carry.
        let (lane, answered) = race_probes(
            || false,
            || {
                std::thread::sleep(Duration::from_millis(50));
                true
            },
            Duration::from_secs(5),
        );
        assert_eq!(lane, Lane::Masque);
        assert!(answered);
    }

    #[test]
    fn two_failed_probes_fall_back_to_wireguard() {
        assert_eq!(
            race_probes(|| false, || false, Duration::from_secs(5)),
            (Lane::WireGuard, false)
        );
    }

    #[test]
    fn a_silent_pair_falls_back_at_the_deadline() {
        let start = Instant::now();
        let (lane, answered) = race_probes(
            || {
                std::thread::sleep(Duration::from_secs(30));
                true
            },
            || {
                std::thread::sleep(Duration::from_secs(30));
                true
            },
            Duration::from_millis(50),
        );
        assert_eq!(lane, Lane::WireGuard);
        assert!(!answered);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the deadline bound the wait"
        );
    }

    #[test]
    fn an_identity_survives_a_save_and_load() {
        let identity = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec!["172.16.0.2".parse().expect("a v4 address")],
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        let dir = std::env::temp_dir().join(format!("ferrox-warp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("identity.json");
        identity.save(&path).expect("saves");
        let loaded = Identity::load(&path).expect("loads");
        assert_eq!(loaded.device_id, identity.device_id);
        assert_eq!(loaded.wireguard.private, identity.wireguard.private);
        assert_eq!(loaded.wireguard.peer, identity.wireguard.peer);
        assert_eq!(loaded.wireguard.endpoint, identity.wireguard.endpoint);
        assert_eq!(loaded.wireguard.reserved, [1, 2, 3]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the identity is owner-only");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_api_address_moves_the_dial_not_the_name() {
        let spec = WarpSpec::for_command(Mode::Auto, None, Some("198.51.100.7:8443".to_owned()));
        let endpoint =
            api_endpoint(&spec, "https://api.cloudflareclient.com/v0a4471").expect("an endpoint");
        assert_eq!(endpoint.host, "api.cloudflareclient.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(
            endpoint.address,
            Some("198.51.100.7:8443".parse().expect("an address"))
        );
        let plain = api_endpoint(
            &WarpSpec::for_command(Mode::Auto, None, None),
            "https://api.cloudflareclient.com/v0a4471",
        )
        .expect("an endpoint");
        assert_eq!(plain.address, None);
        for (text, want) in [
            ("2606:4700::1", "[2606:4700::1]:443"),
            ("[2606:4700::1]", "[2606:4700::1]:443"),
            ("[2606:4700::1]:8443", "[2606:4700::1]:8443"),
        ] {
            let spec = WarpSpec::for_command(Mode::Auto, None, Some(text.to_owned()));
            let endpoint = api_endpoint(&spec, "https://api.cloudflareclient.com/v0a4471")
                .expect("an endpoint");
            assert_eq!(
                endpoint.address,
                Some(want.parse().expect("an address")),
                "{text}"
            );
        }
    }

    #[test]
    fn host_and_port_split_every_shape_the_flag_takes() {
        let cases = [
            ("198.51.100.7", ("198.51.100.7", 443)),
            ("198.51.100.7:80", ("198.51.100.7", 80)),
            ("2606:4700::1", ("2606:4700::1", 443)),
            ("[2606:4700::1]:8443", ("2606:4700::1", 8443)),
            ("[2606:4700::1]", ("2606:4700::1", 443)),
            ("api.example.com", ("api.example.com", 443)),
            ("api.example.com:8080", ("api.example.com", 8080)),
        ];
        for (text, (host, port)) in cases {
            assert_eq!(
                split_host_port(text, 443),
                Some((host.to_owned(), port)),
                "{text}"
            );
        }
        assert_eq!(split_host_port("", 443), None);
        assert_eq!(split_host_port("[2606:4700::1", 443), None);
        assert_eq!(split_host_port("api.example.com:port", 443), None);
    }

    #[test]
    fn every_slot_derives_beside_its_own_first_hop() {
        assert_eq!(KeyKind::All.slots().len(), 5);
        assert_eq!(KeyKind::Gool.slots().len(), 2);
        let base = Path::new("/tmp/warp-identity.json");
        let paths = KeyPaths::new(base, None, None);
        assert_eq!(Slot::WireGuard.path(&paths), base);
        assert_eq!(
            Slot::WireGuardInner.path(&paths),
            Path::new("/tmp/warp-identity-secondary.json")
        );
        assert_eq!(
            Slot::Masque.path(&paths),
            Path::new("/tmp/warp-identity-masque.json")
        );
        assert_eq!(
            Slot::MasqueInner.path(&paths),
            Path::new("/tmp/warp-identity-masque-secondary.json")
        );
        assert_eq!(
            Slot::Gool.path(&paths),
            Path::new("/tmp/warp-identity-masque-gool.json")
        );
        let overridden = KeyPaths::new(
            base,
            Some(Path::new("/etc/wg.json")),
            Some(Path::new("/etc/masque.json")),
        );
        assert_eq!(
            Slot::WireGuardInner.path(&overridden),
            Path::new("/etc/wg-secondary.json")
        );
        assert_eq!(
            Slot::Gool.path(&overridden),
            Path::new("/etc/masque-gool.json")
        );
    }

    #[test]
    fn two_slots_cannot_share_one_identity_file() {
        let base = Path::new("/tmp/warp-identity.json");
        let paths = KeyPaths::new(base, Some(base), Some(base));
        let error = planned_slots(KeyKind::All, &paths).expect_err("the slots collide");
        assert!(error.contains("share"), "{error}");
        let distinct = KeyPaths::new(
            base,
            Some(Path::new("/tmp/wg.json")),
            Some(Path::new("/tmp/masque.json")),
        );
        assert_eq!(
            planned_slots(KeyKind::All, &distinct)
                .expect("distinct slots")
                .len(),
            5
        );
    }

    #[test]
    fn a_wireguard_slot_registers_without_enrolling_masque() {
        let calls = Mutex::new(Vec::new());
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let call = |method: &str, path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            calls.lock().expect("the call log").push((
                method.to_owned(),
                path.to_owned(),
                body.to_vec(),
            ));
            Ok::<_, RegisterError>(wireguard_reply.clone())
        };
        let identity = register_with(&spec, false, &call).expect("a registration");
        let recorded = calls.lock().expect("the call log");
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].0, "POST");
        assert_eq!(recorded[1].0, "PATCH");
        assert_eq!(recorded[1].1, "/reg/a-device");
        assert_eq!(recorded[1].2, ENABLE_BODY);
        assert!(identity.masque.is_none());
    }

    #[test]
    fn a_refused_enable_is_fatal_and_saves_nothing() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let call = |method: &str, _path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            if method == "PATCH" && body == ENABLE_BODY {
                return Ok::<_, RegisterError>(Reply {
                    status: 403,
                    headers: Vec::new(),
                    body: b"{\"error\":\"refused\"}".to_vec(),
                });
            }
            Ok::<_, RegisterError>(wireguard_reply.clone())
        };
        let error = register_with(&spec, false, &call).expect_err("the enable is refused");
        assert!(error.fatal);
        assert!(error.reason.contains("403"), "{}", error.reason);
    }

    #[test]
    fn a_failed_enrollment_does_not_mint_a_second_device() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let posts = Mutex::new(0usize);
        let call = |method: &str, _path: &str, _headers: &[(&str, &str)], _body: &[u8]| {
            if method == "POST" {
                *posts.lock().expect("the post count") += 1;
                return Ok::<_, RegisterError>(wireguard_reply.clone());
            }
            Err::<Reply, _>(RegisterError::retryable("the enrollment leg is down"))
        };
        let error = register_with(&spec, true, &call).expect_err("the enrollment fails");
        assert!(error.fatal, "{}", error.reason);
        assert!(
            error.reason.contains("enrollment failed"),
            "{}",
            error.reason
        );
        assert_eq!(*posts.lock().expect("the post count"), 1);
    }

    #[test]
    fn a_read_back_updates_the_saved_identity() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let saved = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec!["172.16.0.2".parse().expect("a v4 address")],
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        let fresh_reply = sample_reply(&b64(&[0x55; 32]));
        let call = |method: &str, path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/reg/a-device");
            assert_eq!(body, []);
            Ok::<_, RegisterError>(fresh_reply.clone())
        };
        let fresh = refresh(&spec, &saved, &call).expect("a read-back");
        assert_eq!(fresh.wireguard.peer, [0x55; 32]);
        assert_eq!(fresh.wireguard.reserved, [9, 8, 7]);
        assert_eq!(fresh.wireguard.addresses.len(), 2);
    }

    #[test]
    fn a_refused_read_back_is_told_apart_from_an_outage() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let saved = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: Vec::new(),
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        for (status, body, refused) in [
            (401, &b"{\"error\":\"x\"}"[..], true),
            (404, &b"{\"error\":\"x\"}"[..], false),
            (
                404,
                &b"{\"success\":false,\"errors\":[{\"code\":1000}]}"[..],
                true,
            ),
            (404, &b"{\"success\":true,\"errors\":[]}"[..], false),
            (410, &b"{\"error\":\"x\"}"[..], true),
            (503, &b"{\"error\":\"x\"}"[..], false),
        ] {
            let call = move |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
                Ok::<_, RegisterError>(Reply {
                    status,
                    headers: Vec::new(),
                    body: body.to_vec(),
                })
            };
            let error = refresh(&spec, &saved, &call).expect_err("not a usable read-back");
            assert_eq!(error.refused, refused, "{status}");
        }
    }

    #[test]
    fn three_spellings_turn_reprovisioning_off() {
        for off in ["0", "off", "false", " OFF ", "False", "0\t"] {
            assert!(!reprovision_enabled_for(Some(off)), "{off}");
        }
        assert!(reprovision_enabled_for(None));
        assert!(reprovision_enabled_for(Some("1")));
        assert!(reprovision_enabled_for(Some("true")));
    }

    #[test]
    fn an_unreadable_identity_is_not_a_corrupt_one() {
        let dir = std::env::temp_dir().join(format!("ferrox-warp-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("identity.json");
        std::fs::create_dir(&path).expect("a directory where the file should be");
        let error = Identity::load(&path).expect_err("a read failure");
        assert!(!error.corrupt(), "{error:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_broken_identity_is_corrupt() {
        let dir = std::env::temp_dir().join(format!("ferrox-warp-broken-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("identity.json");
        std::fs::write(&path, b"not json").expect("a broken identity");
        let error = Identity::load(&path).expect_err("a parse failure");
        assert!(error.corrupt(), "{error:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_refused_identity_is_replaced_only_when_registration_is_allowed() {
        assert!(should_reprovision(true, true, true));
        assert!(!should_reprovision(false, true, true));
        assert!(!should_reprovision(true, false, true));
        assert!(!should_reprovision(true, true, false));
    }

    #[test]
    fn a_404_page_from_a_front_is_not_a_refusal() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let saved = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: Vec::new(),
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        let page = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 404,
                headers: Vec::new(),
                body: b"<html>not the API</html>".to_vec(),
            })
        };
        let error = refresh(&spec, &saved, &page).expect_err("a 404 page");
        assert!(!error.refused, "{}", error.reason);
        let envelope = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 404,
                headers: Vec::new(),
                body: b"{\"success\":false,\"errors\":[{\"code\":1000}]}".to_vec(),
            })
        };
        let error = refresh(&spec, &saved, &envelope).expect_err("a refusal");
        assert!(error.refused, "{}", error.reason);
    }

    #[test]
    fn a_shaped_registration_reply_is_not_retried_on_another_host() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let shaped = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 200,
                headers: Vec::new(),
                body: b"{\"id\":\"a-device\",\"token\":\"a-token\"}".to_vec(),
            })
        };
        let error = register_with(&spec, false, &shaped).expect_err("no config");
        assert!(error.fatal, "{}", error.reason);
        let page = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 200,
                headers: Vec::new(),
                body: b"<html>not the API</html>".to_vec(),
            })
        };
        let error = register_with(&spec, false, &page).expect_err("not the API");
        assert!(!error.fatal, "{}", error.reason);
    }

    #[test]
    fn six_register_kinds_parse() {
        let kinds = ["masque", "wg", "gool", "gool-classic", "mim", "all"];
        assert_eq!(kinds.len(), 6);
        for kind in kinds {
            assert!(KeyKind::parse(kind).is_ok(), "{kind}");
        }
        for alias in [
            "wireguard",
            "warp",
            "wg-over-masque",
            "wiw",
            "warp-in-warp",
            "masque-in-masque",
        ] {
            assert!(KeyKind::parse(alias).is_ok(), "{alias}");
        }
        assert!(KeyKind::parse("other").is_err());
    }

    #[test]
    fn a_second_quarantine_keeps_the_first_damaged_identity() {
        let dir =
            std::env::temp_dir().join(format!("ferrox-warp-quarantine-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("warp-identity.json");
        std::fs::write(&path, b"first").expect("a damaged identity");
        quarantine(&path);
        assert!(!path.exists(), "the bad file is moved aside");
        std::fs::write(&path, b"second").expect("a second damaged identity");
        quarantine(&path);
        assert_eq!(
            std::fs::read(dir.join("warp-identity.json.corrupt")).expect("the first file"),
            b"first"
        );
        assert_eq!(
            std::fs::read(dir.join("warp-identity.json.corrupt.1")).expect("the second file"),
            b"second"
        );
        std::fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    }

    #[cfg(unix)]
    #[test]
    fn saving_over_a_loose_identity_locks_it_to_the_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("ferrox-warp-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("warp-identity.json");
        std::fs::write(&path, b"loose").expect("a pre-existing identity");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("a world-readable identity");
        let identity = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [1; 32],
                peer: [2; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec!["172.16.0.2".parse().expect("an address")],
                reserved: [0, 0, 0],
            },
            masque: Some(MasqueIdentity {
                private: vec![3; 32],
                server: vec![4; 32],
                addresses: vec!["172.16.0.2".parse().expect("an address")],
            }),
        };
        identity.save(&path).expect("the identity is saved");
        let mode = std::fs::metadata(&path)
            .expect("the saved identity")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the keys are not readable by anyone else");
        assert_eq!(Identity::load(&path).expect("the saved identity"), identity);
        std::fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    }
}
