use crate::json::Json;
use ferrox_core::transport::EarlyData;
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn inbound_reality_config(
    inbound: &Json,
) -> Option<ferrox_core::tls::RealityServerConfig> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("reality") {
        return None;
    }
    let reality = settings.get("realitySettings")?;
    let short_ids: Vec<[u8; 8]> = reality
        .get("shortIds")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str().and_then(short_id))
        .collect();
    if short_ids.is_empty() {
        return None;
    }
    let server_names: Vec<String> = reality
        .get("serverNames")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str())
        .map(str::to_owned)
        .collect();
    if server_names.is_empty() {
        return None;
    }
    Some(ferrox_core::tls::RealityServerConfig {
        private_key: reality.get("privateKey")?.as_str().and_then(key32)?,
        short_ids,
        server_names,
        max_time_skew: reality
            .get("maxTimeDiff")
            .and_then(as_millis)
            .map(Duration::from_millis),
        min_client_ver: reality
            .get("minClientVer")
            .and_then(Json::as_str)
            .and_then(client_ver),
        max_client_ver: reality
            .get("maxClientVer")
            .and_then(Json::as_str)
            .and_then(client_ver),
        limit_fallback_upload: reality.get("limitFallbackUpload").and_then(rate_limit),
        limit_fallback_download: reality.get("limitFallbackDownload").and_then(rate_limit),
        dest: reality
            .get("dest")
            .and_then(Json::as_str)
            .filter(|d| !d.is_empty())
            .map(str::to_owned),
        xver: reality
            .get("xver")
            .and_then(as_uint)
            .and_then(|n| u8::try_from(n).ok())
            .unwrap_or(0),
        show: reality.get("show").and_then(Json::as_bool).unwrap_or(false),
    })
}

fn client_ver(text: &str) -> Option<[u8; 3]> {
    let mut out = [0u8; 3];
    let mut at = 0;
    for part in text.split('.') {
        let value = part.parse::<u8>().ok()?;
        *out.get_mut(at)? = value;
        at += 1;
    }
    (at > 0).then_some(out)
}

fn rate_limit(node: &Json) -> Option<ferrox_core::tls::RateLimit> {
    Some(ferrox_core::tls::RateLimit {
        after_bytes: node.get("afterBytes").and_then(as_uint)?,
        bytes_per_sec: node.get("bytesPerSec").and_then(as_uint)?,
        burst_bytes_per_sec: node.get("burstBytesPerSec").and_then(as_uint)?,
    })
}

fn as_uint(node: &Json) -> Option<u64> {
    if let Json::Num(n) = node {
        if *n >= 0.0 && n.fract() == 0.0 {
            return u64::try_from(*n as i64).ok();
        }
    }
    None
}

/// Xray fills the eight bytes from the front and zero-pads the tail, so `a8` is `a8 00 ...`, never `00 ... a8`.
fn short_id(hex: &str) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    if hex.is_empty() || hex.len() > 16 || !hex.len().is_multiple_of(2) {
        return None;
    }
    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn key32(text: &str) -> Option<[u8; 32]> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut word = 0u32;
    let mut bits = 0;
    let mut out = Vec::with_capacity(32);
    for byte in text.bytes() {
        let value = ALPHABET.iter().position(|c| *c == byte)? as u32;
        word = (word << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((word >> bits) as u8);
        }
    }
    <[u8; 32]>::try_from(out).ok()
}

fn as_millis(node: &Json) -> Option<u64> {
    match node {
        Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
        _ => None,
    }
}

pub(crate) fn inbound_tls_identity(
    inbound: &Json,
) -> Option<Arc<ferrox_core::tls::TlsServerConfig>> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return None;
    }
    let (cert_pem, key_pem) = tls_cert_pem(settings)?;
    ferrox_core::tls::parse_pem_identity(&cert_pem, &key_pem)
        .ok()
        .map(Arc::new)
}

/// PEM for the first certificate entry, in either spelling xray accepts: `certificateFile`/`keyFile` paths, or an inline `certificate`/`key` given as a string or as an array of PEM lines. A peer that hands over a bare TLS listener (a REALITY decoy, say) uses the inline form, so refusing it here leaves the inbound serving nothing.
fn tls_cert_pem(settings: &Json) -> Option<(Vec<u8>, Vec<u8>)> {
    let first = settings
        .get("tlsSettings")?
        .get("certificates")?
        .as_arr()?
        .first()?;
    if let (Some(cert_path), Some(key_path)) = (
        first.get("certificateFile").and_then(Json::as_str),
        first.get("keyFile").and_then(Json::as_str),
    ) {
        return Some((
            std::fs::read(cert_path).ok()?,
            std::fs::read(key_path).ok()?,
        ));
    }
    let inline = |field: &str| -> Option<Vec<u8>> {
        let value = first.get(field)?;
        if let Some(text) = value.as_str() {
            return Some(text.as_bytes().to_vec());
        }
        let lines = value.as_arr()?;
        Some(
            lines
                .iter()
                .filter_map(Json::as_str)
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes(),
        )
    };
    Some((inline("certificate")?, inline("key")?))
}

pub(crate) fn tls_cert_paths(settings: &Json) -> Option<(&str, &str)> {
    let first = settings
        .get("tlsSettings")?
        .get("certificates")?
        .as_arr()?
        .first()?;
    Some((
        first.get("certificateFile")?.as_str()?,
        first.get("keyFile")?.as_str()?,
    ))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The eight hex digits per group of an inbound id or an outbound server uuid, dashes optional.
pub(crate) fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut index = 0;
    let mut high: Option<u8> = None;
    for byte in text.bytes() {
        if byte == b'-' {
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        match high.take() {
            Some(h) => {
                if index >= 16 {
                    return None;
                }
                out[index] = (h << 4) | digit;
                index += 1;
            }
            None => high = Some(digit),
        }
    }
    if index == 16 && high.is_none() {
        Some(out)
    } else {
        None
    }
}

/// The 56-byte hex SHA-224 of the password that Trojan speaks on the wire.
pub(crate) fn trojan_key(password: &str) -> [u8; 56] {
    use sha2::Digest as _;
    let digest = sha2::Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    for (i, byte) in digest.iter().enumerate() {
        out[2 * i] = HEX[(byte >> 4) as usize];
        out[2 * i + 1] = HEX[(byte & 0x0F) as usize];
    }
    out
}

pub(crate) fn tls_ca_roots(outbound: &Json) -> Option<ferrox_core::tls::Anchors> {
    outbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|s| s.get("caCertFile"))
        .and_then(Json::as_str)
        .and_then(|path| std::fs::read(path).ok())
        .map(|pem| ferrox_core::tls::Anchors::from(crate::quic::parse_ca_pem(&pem)))
        .filter(|roots| !roots.is_empty())
}

fn tls_alpn(settings: Option<&Json>) -> Vec<Vec<u8>> {
    let Some(alpn) = settings.and_then(|s| s.get("alpn")) else {
        return Vec::new();
    };
    if let Some(single) = alpn.as_str() {
        if single.is_empty() {
            return Vec::new();
        }
        return vec![single.as_bytes().to_vec()];
    }
    let Some(items) = alpn.as_arr() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Json::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .collect()
}

/// The `cipher_suites` field xray's `tlsSettings.cipherSuites` produces on the wire: the names
/// parse to ids, then `crypto/tls` re-orders them by preference and appends its TLS 1.3 suites
/// across the configured version range. Empty when the config names no known suite, which
/// leaves the backend's stock ordering in place.
fn tls_cipher_suites(settings: Option<&Json>) -> Vec<u16> {
    let Some(list) = settings
        .and_then(|s| s.get("cipherSuites"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Vec::new();
    };
    let parsed = ferrox_core::tls::cipher_suites::parse(list);
    let min = tls_version(settings, "minVersion").unwrap_or(0x0301);
    let max = tls_version(settings, "maxVersion").unwrap_or(0x0304);
    ferrox_core::tls::cipher_suites::hello_ids(&parsed, min, max, true)
}

fn tls_version(settings: Option<&Json>, key: &str) -> Option<u16> {
    let text = settings.and_then(|s| s.get(key)).and_then(Json::as_str)?;
    match text.trim() {
        "1.0" => Some(0x0301),
        "1.1" => Some(0x0302),
        "1.2" => Some(0x0303),
        "1.3" => Some(0x0304),
        _ => None,
    }
}

pub(crate) fn outbound_tls(
    outbound: &Json,
    address: &str,
) -> Result<Arc<ferrox_core::tls::TlsConfig>, String> {
    let settings = outbound
        .get("streamSettings")
        .ok_or("no streamSettings in the outbound")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return Err("security is not tls".to_owned());
    }
    let tls = settings.get("tlsSettings");
    if matches!(
        tls.and_then(|s| s.get("allowInsecure")),
        Some(Json::Bool(true))
    ) {
        return Err(
            "allowInsecure is removed; use pinnedPeerCertSha256 or verifyPeerCertByName".to_owned(),
        );
    }
    let server_name = tls
        .and_then(|s| s.get("serverName"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(address)
        .to_owned();
    if server_name.is_empty() {
        return Err("no serverName".to_owned());
    }
    let alpn = tls_alpn(tls);
    let system_only = !matches!(
        tls.and_then(|s| s.get("disableSystemRoot")),
        Some(Json::Bool(true))
    );
    let roots = tls_ca_roots(outbound).or_else(|| {
        system_only
            .then(crate::quic::system_roots)
            .filter(|r| !r.is_empty())
    });
    let roots = match roots {
        Some(roots) if !roots.is_empty() => roots,
        _ => {
            return Err(
                "no certificate authorities: no caCertFile and the system roots are empty"
                    .to_owned(),
            )
        }
    };
    // xray's empty name is Chrome and a name it does not know returns nil, which dials stock.
    let fingerprint = tls
        .and_then(|s| s.get("fingerprint"))
        .and_then(Json::as_str)
        .map(|name| {
            ferrox_core::tls::Fingerprint::resolve(name)
                .unwrap_or_else(ferrox_core::tls::Fingerprint::stock)
        })
        .unwrap_or_default();
    Ok(Arc::new(ferrox_core::tls::TlsConfig {
        server_name,
        alpn: alpn.into(),
        roots,
        pins: ferrox_core::foxy::pin::Pins::default(),
        cipher_suites: tls_cipher_suites(tls),
        insecure: false,
        fingerprint: Some(fingerprint),
        websocket: matches!(
            settings.get("network").and_then(Json::as_str),
            Some("ws" | "httpupgrade")
        ),
    }))
}

/// The outbound REALITY identity: the decoy name, the server static key, the short id.
pub(crate) fn outbound_reality(
    outbound: &Json,
    address: &str,
) -> Option<Arc<ferrox_core::tls::RealityClientConfig>> {
    let settings = outbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("reality") {
        return None;
    }
    let reality = settings.get("realitySettings")?;
    let server_name = reality
        .get("serverName")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(address)
        .to_owned();
    if server_name.is_empty() {
        return None;
    }
    Some(Arc::new(ferrox_core::tls::RealityClientConfig {
        server_name,
        public_key: reality.get("publicKey")?.as_str().and_then(key32)?,
        short_id: reality
            .get("shortId")
            .and_then(Json::as_str)
            .and_then(short_id)?,
        fingerprint: reality
            .get("fingerprint")
            .and_then(Json::as_str)
            .unwrap_or("chrome")
            .to_owned(),
    }))
}

/// The user flow: empty or Vision dials, anything else is refused rather than sent plain.
pub(crate) fn outbound_flow(server: &Json) -> String {
    server
        .get("users")
        .and_then(Json::as_arr)
        .and_then(|users| users.first())
        .and_then(|user| user.get("flow"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

pub(crate) fn kcp_config(settings: Option<&Json>) -> ferrox_core::kcp::Config {
    let base = ferrox_core::kcp::Config::default();
    let Some(kcp) = settings.and_then(|s| s.get("kcpSettings")) else {
        return base;
    };
    let num = |camel: &str, snake: &str| {
        kcp.get(camel)
            .or_else(|| kcp.get(snake))
            .and_then(Json::as_u32)
    };
    let mtu = num("mtu", "mtu").unwrap_or(base.mtu);
    let tti = num("tti", "tti").unwrap_or(base.tti);
    ferrox_core::kcp::Config {
        mtu: if mtu > ferrox_core::kcp::DATA_SEGMENT_OVERHEAD {
            mtu
        } else {
            base.mtu
        },
        tti: if (1..=1000).contains(&tti) {
            tti
        } else {
            base.tti
        },
        uplink_capacity: num("uplinkCapacity", "uplink_capacity").unwrap_or(base.uplink_capacity),
        downlink_capacity: num("downlinkCapacity", "downlink_capacity")
            .unwrap_or(base.downlink_capacity),
        cwnd_multiplier: num("cwndMultiplier", "cwnd_multiplier").unwrap_or(base.cwnd_multiplier),
        max_sending_window: num("maxSendingWindow", "max_sending_window")
            .unwrap_or(base.max_sending_window),
        mask: base.mask,
    }
}

pub(crate) fn sub_path(settings: Option<&Json>, key: &str) -> String {
    settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("path"))
        .and_then(Json::as_str)
        .unwrap_or("/")
        .to_owned()
}
pub(crate) fn grpc_path(settings: Option<&Json>) -> String {
    let service = settings
        .and_then(|s| s.get("grpcSettings"))
        .and_then(|s| s.get("serviceName"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .trim();
    if service.is_empty() {
        return "/Tun".to_owned();
    }
    if service.starts_with('/') {
        return service.to_owned();
    }
    format!("/{}/Tun", grpc_escape(service.trim_matches('/')))
}

/// Go's `url.PathEscape` for one segment, the way Xray escapes a service name.
fn grpc_escape(service: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(service.len());
    for byte in service.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            );
        if keep {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

pub(crate) fn tcp_http_path(settings: Option<&Json>) -> Option<String> {
    let header = settings
        .and_then(|s| s.get("tcpSettings"))
        .and_then(|s| s.get("header"))?;
    if header.get("type").and_then(Json::as_str) != Some("http") {
        return None;
    }
    let request = header.get("request")?;
    if let Some(paths) = request.get("path").and_then(Json::as_arr) {
        let first = paths.iter().find_map(Json::as_str);
        if let Some(path) = first {
            return Some(path.to_owned());
        }
    }
    if let Some(path) = request.get("path").and_then(Json::as_str) {
        return Some(path.to_owned());
    }
    Some("/".to_owned())
}

pub(crate) fn stream_security(node: &Json) -> &str {
    node.get("streamSettings")
        .and_then(|s| s.get("security"))
        .and_then(Json::as_str)
        .unwrap_or("")
}

pub(crate) fn vless_security_supported(sec: &str) -> bool {
    sec.is_empty() || sec == "none"
}

#[derive(Debug, Clone)]
pub(crate) enum Carrier {
    Raw(ferrox_core::finalmask::Chain),
    Ws {
        path: String,
        ed: u32,
    },
    HttpUpgrade {
        path: String,
        ed: u32,
    },
    Grpc {
        path: String,
    },
    Xhttp {
        settings: Box<crate::xhttp::XhttpSettings>,
    },
    HttpHeader {
        path: String,
    },
    Quic,
    Kcp(ferrox_core::kcp::Config),
    Hysteria(ferrox_core::hysteria::Config),
    Masque,
    Xdrive {
        settings: Box<crate::xdrive::Settings>,
    },
    Http,
    Unknown {
        network: String,
    },
}

type Resolver = fn(Option<&Json>, &str) -> Carrier;

impl Carrier {
    /// The post-TLS write chain to put under a connection of this carrier, or `None` when the carrier
    /// needs none. The chain is the template: every connection clones it, so each counts its own
    /// writes from one.
    pub(crate) fn tcp_mask(&self) -> Option<&ferrox_core::finalmask::Chain> {
        match self {
            Carrier::Raw(chain) if !chain.is_empty() => Some(chain),
            _ => None,
        }
    }

    /// The xHTTP dial settings, which carry the normalised request path.
    pub(crate) fn xhttp_settings(&self) -> Option<&crate::xhttp::XhttpSettings> {
        match self {
            Carrier::Xhttp { settings } => Some(settings),
            _ => None,
        }
    }
}

// One row per network this tree recognises; a new method adds a row, not a match arm.
const CARRIERS: &[(&[&str], Resolver)] = &[
    (&["ws", "websocket"], resolve_ws),
    (&["httpupgrade"], resolve_httpupgrade),
    (&["grpc"], resolve_grpc),
    (&["xhttp", "splithttp"], resolve_xhttp),
    (&["quic"], resolve_quic),
    (&["kcp", "mkcp"], resolve_kcp),
    (&["hysteria"], resolve_hysteria),
    (&["masque"], resolve_masque),
    (&["xdrive"], resolve_xdrive),
    (&["http", "h2", "h3"], resolve_http),
    (&["", "raw", "tcp"], resolve_tcp_or_header),
];

pub(crate) fn stream_carrier(settings: Option<&Json>) -> Carrier {
    let network = settings
        .and_then(|s| s.get("network"))
        .and_then(Json::as_str)
        .unwrap_or("");
    let unknown = || Carrier::Unknown {
        network: network.to_owned(),
    };
    let carrier = CARRIERS
        .iter()
        .find(|(aliases, _)| aliases.contains(&network))
        .map_or_else(unknown, |(_, resolve)| resolve(settings, network));
    // The reference puts the chain on the TCP connection under whichever transport rides it; this tree arms it only where a carrier reaches that connection, so any other carrier refuses the config rather than dialling or serving it unmasked.
    if has_tcp_mask(settings) && !matches!(carrier, Carrier::Raw(_)) {
        return unknown();
    }
    carrier
}

/// Whether the transport asks for a post-TLS tcp mask chain at all.
pub(crate) fn has_tcp_mask(settings: Option<&Json>) -> bool {
    settings
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("tcp"))
        .and_then(Json::as_arr)
        .is_some_and(|tcp| !tcp.is_empty())
}

fn resolve_ws(settings: Option<&Json>, _: &str) -> Carrier {
    let early = EarlyData::split(&sub_path(settings, "wsSettings"));
    Carrier::Ws {
        path: early.path,
        ed: early.budget,
    }
}

fn resolve_httpupgrade(settings: Option<&Json>, _: &str) -> Carrier {
    let early = EarlyData::split(&sub_path(settings, "httpupgradeSettings"));
    Carrier::HttpUpgrade {
        path: early.path,
        ed: early.budget,
    }
}

fn resolve_grpc(settings: Option<&Json>, _: &str) -> Carrier {
    Carrier::Grpc {
        path: grpc_path(settings),
    }
}

fn resolve_xhttp(settings: Option<&Json>, network: &str) -> Carrier {
    match crate::xhttp::XhttpSettings::from_json(settings) {
        Some(settings) => Carrier::Xhttp {
            settings: Box::new(settings),
        },
        None => Carrier::Unknown {
            network: network.to_owned(),
        },
    }
}

fn resolve_quic(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Quic
}

fn resolve_kcp(settings: Option<&Json>, network: &str) -> Carrier {
    let Some(mask) = kcp_mask(settings) else {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    };
    let mut config = kcp_config(settings);
    config.mask = mask;
    Carrier::Kcp(config)
}

/// The `finalmask.udp` `mkcp-legacy` chain for a KCP carrier, already in
/// wire order (outermost first): the reference reverses the JSON list once
/// when it builds its mask manager, so the last configured entry is the
/// outermost on the wire. `Some(default)` means no finalmask at all; `None`
/// refuses the carrier — an unknown udp mask type, a bad header name or an
/// unpackable dns domain must never silently dial unmasked.
fn kcp_mask(settings: Option<&Json>) -> Option<ferrox_core::kcp::Mask> {
    use ferrox_core::kcp::{HeaderKind, Mask, Spec};
    let Some(udp) = settings
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("udp"))
        .and_then(Json::as_arr)
    else {
        return Some(Mask::default());
    };
    let mut specs = Vec::with_capacity(udp.len());
    for entry in udp {
        if entry
            .get("type")
            .and_then(Json::as_str)
            .map(str::to_lowercase)
            != Some("mkcp-legacy".to_owned())
        {
            return None;
        }
        let conf = entry.get("settings");
        let header = conf
            .and_then(|c| c.get("header"))
            .and_then(Json::as_str)
            .unwrap_or("");
        let value = conf
            .and_then(|c| c.get("value"))
            .and_then(Json::as_str)
            .unwrap_or("");
        specs.push(if header.is_empty() {
            if value.is_empty() {
                Spec::Original
            } else {
                Spec::Aes {
                    password: value.to_owned(),
                }
            }
        } else {
            match header.to_lowercase().as_str() {
                "dns" => Spec::HeaderDns {
                    domain: (if value.is_empty() {
                        "www.baidu.com"
                    } else {
                        value
                    })
                    .to_owned(),
                },
                "dtls" => Spec::Header(HeaderKind::Dtls),
                "srtp" => Spec::Header(HeaderKind::Srtp),
                "utp" => Spec::Header(HeaderKind::Utp),
                "wechat" => Spec::Header(HeaderKind::Wechat),
                "wireguard" => Spec::Header(HeaderKind::WireGuard),
                _ => return None,
            }
        });
    }
    specs.reverse();
    Mask::from_spec(&specs).ok()
}

fn resolve_hysteria(settings: Option<&Json>, network: &str) -> Carrier {
    hysteria_carrier(settings, network)
}

fn resolve_masque(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Masque
}

/// A folder the tree can reach, or no folder at all: an xdrive carrier that cannot name its store is refused rather than dialled at a default.
fn resolve_xdrive(settings: Option<&Json>, network: &str) -> Carrier {
    crate::xdrive::Settings::from_json(settings).map_or(
        Carrier::Unknown {
            network: network.to_owned(),
        },
        |settings| Carrier::Xdrive {
            settings: Box::new(settings),
        },
    )
}

fn resolve_http(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Http
}

fn resolve_tcp_or_header(settings: Option<&Json>, network: &str) -> Carrier {
    let Some(mask) = tcp_mask(settings) else {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    };
    match tcp_http_path(settings) {
        // A header masquerade plus a tcp mask is the pairing the reference answers with the refused `header-custom`.
        Some(_) if !mask.is_empty() => Carrier::Unknown {
            network: network.to_owned(),
        },
        Some(path) => Carrier::HttpHeader { path },
        None => Carrier::Raw(mask),
    }
}

/// The `finalmask.tcp` chain for a tcp carrier, in config order. `Some(empty)` means no finalmask at
/// all; `None` refuses the carrier — a tcp mask type this tree does not ship, or a fragment the
/// config cannot drive, must never dial or serve unmasked.
fn tcp_mask(settings: Option<&Json>) -> Option<ferrox_core::finalmask::Chain> {
    let Some(tcp) = settings
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("tcp"))
        .and_then(Json::as_arr)
    else {
        return Some(ferrox_core::finalmask::Chain::default());
    };
    let mut chain = ferrox_core::finalmask::Chain::default();
    for entry in tcp {
        if entry
            .get("type")
            .and_then(Json::as_str)
            .map(str::to_lowercase)
            != Some("fragment".to_owned())
        {
            return None;
        }
        chain.push(fragment(entry.get("settings"))?);
    }
    Some(chain)
}

/// One `fragment` stage. `packets` picks the writes it cuts; `lengths` and `delays` fall back to
/// their singular spelling, and an unset one is the reference's zero range — a last width entry of 0,
/// which is a stage this tree refuses rather than one that would spin.
fn fragment(conf: Option<&Json>) -> Option<ferrox_core::finalmask::Fragment> {
    use ferrox_core::finalmask::Fragment;
    let packets = conf
        .and_then(|c| c.get("packets"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_lowercase();
    let (packets_from, packets_to) = match packets.as_str() {
        "tlshello" => (0, 1),
        "" => (0, 0),
        // The reference reads a window as a range and refuses a low end of 0, which would make every write a hello.
        other => {
            let window = range_text(other)?;
            if window.low == 0 {
                return None;
            }
            (window.low as u64, window.high as u64)
        }
    };
    let widths =
        range_list(conf, "lengths").or_else(|| Some(vec![single_range(conf, "length")?]))?;
    let waits = range_list(conf, "delays").or_else(|| Some(vec![single_range(conf, "delay")?]))?;
    Fragment::new(
        packets_from,
        packets_to,
        widths,
        waits,
        single_range(conf, "maxSplit")?,
    )
}

/// A `lengths`-style list, or `None` when the key is absent or empty and the singular spelling rules.
fn range_list(conf: Option<&Json>, key: &str) -> Option<Vec<ferrox_core::finalmask::Range>> {
    let items = conf?.get(key)?.as_arr()?;
    if items.is_empty() {
        return None;
    }
    items.iter().map(int32_range).collect()
}

/// A `length`-style single range, or the reference's zero range when the key is absent.
fn single_range(conf: Option<&Json>, key: &str) -> Option<ferrox_core::finalmask::Range> {
    match conf.and_then(|c| c.get(key)) {
        Some(value) => int32_range(value),
        None => Some(ferrox_core::finalmask::Range::ordered(0, 0)),
    }
}

/// One `Int32Range` as the reference reads it: a plain number, or a string that spells one.
fn int32_range(value: &Json) -> Option<ferrox_core::finalmask::Range> {
    use ferrox_core::finalmask::Range;
    match value {
        Json::Num(n) if n.fract() == 0.0 => Some(Range::ordered(*n as i64, *n as i64)),
        Json::Str(text) => range_text(text),
        _ => None,
    }
}

/// `ParseRangeString`: a single number, an empty string as `0`, or `a-b` in either order. A leading
/// dash belongs to the first end, so `"-114-514"` and `"-1919--810"` split after its second number.
/// Anything else is a spelling that errors upstream, so it refuses the mask here rather than becoming
/// a silent `0`.
fn range_text(text: &str) -> Option<ferrox_core::finalmask::Range> {
    use ferrox_core::finalmask::Range;
    if let Ok(single) = text.parse::<i64>() {
        return Some(Range::ordered(single, single));
    }
    if text.is_empty() {
        return Some(Range::ordered(0, 0));
    }
    let leading = text.starts_with('-');
    let mut parts = text.strip_prefix('-').unwrap_or(text).splitn(2, '-');
    let low = parts.next()?.parse::<i64>().ok()?;
    let high = parts.next()?.parse::<i64>().ok()?;
    Some(Range::ordered(if leading { -low } else { low }, high))
}

fn hysteria_carrier(settings: Option<&Json>, network: &str) -> Carrier {
    use ferrox_core::hysteria::{Config, Congestion};
    let hy = settings.and_then(|s| s.get("hysteriaSettings"));
    let version = hy
        .and_then(|h| h.get("version"))
        .and_then(Json::as_u32)
        .or_else(|| {
            hy.and_then(|h| h.get("version"))
                .and_then(Json::as_str)
                .and_then(|text| text.parse::<u32>().ok())
        });
    if version.is_some_and(|v| v != 2) {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    }
    // Salamander and its gecko fragmentation variant are the datagram obfuscations carried; any other named one, or one whose password is too short to mask with, is refused rather than silently sent in the clear.
    let obfs_password = match salamander_obfs(settings) {
        None => String::new(),
        Some(password) if ferrox_core::hysteria::Salamander::new(&password).is_some() => password,
        Some(_) => {
            return Carrier::Unknown {
                network: network.to_owned(),
            };
        }
    };
    // A gecko lane whose window cannot be read is refused, never carried as a plain salamander that would silently drop the fragmentation the config asked for.
    let Ok(gecko) = hysteria_gecko(settings) else {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    };
    Carrier::Hysteria(Config {
        auth: hy
            .and_then(|h| h.get("auth"))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned(),
        cc: Congestion::parse(
            hy.and_then(|h| h.get("congestion"))
                .and_then(Json::as_str)
                .unwrap_or(""),
        ),
        obfs_password,
        hop: hysteria_hop(hy),
        gecko,
    })
}

/// The port-hopping plan a hysteria dial rotates its server port on, read from its
/// `hysteriaSettings`. `serverPorts`/`mport` names the ports or `start-end` ranges —
/// an array of numbers/strings or one comma-separated string; `hopInterval` and
/// `hopIntervalMax` bound the stay in seconds (a bare number, or an `s`/`ms` suffix).
/// A malformed token is dropped rather than guessed at, and with nothing valid left
/// the dial stays on its fixed port: a hop is anti-blocking, not correctness, so it
/// never reroutes a flow to a port the config did not name. Field names take both the
/// camel and the snake spelling the reference's two JSON dialects use.
fn hysteria_hop(hy: Option<&Json>) -> Option<ferrox_core::hysteria::Hop> {
    use ferrox_core::hysteria::{Hop, PortRange};
    let hy = hy?;
    let field = |camel: &str, snake: &str| hy.get(camel).or_else(|| hy.get(snake));
    let spec = field("serverPorts", "server_ports").or_else(|| field("mport", "mport"))?;
    let mut ranges: Vec<PortRange> = Vec::new();
    if let Some(items) = spec.as_arr() {
        for item in items {
            push_port_spec(item.as_str(), &mut ranges);
            if let Some(port) = item.as_port() {
                ranges.push(PortRange {
                    start: port,
                    end: port,
                });
            }
        }
    } else if let Some(port) = spec.as_port() {
        ranges.push(PortRange {
            start: port,
            end: port,
        });
    } else {
        push_port_spec(spec.as_str(), &mut ranges);
    }
    if ranges.is_empty() {
        return None;
    }
    let low = stay_ms(field("hopInterval", "hop_interval")).unwrap_or(5_000);
    let high = stay_ms(field("hopIntervalMax", "hop_interval_max")).unwrap_or(low);
    Some(Hop {
        ranges,
        interval_ms: (low.min(high), low.max(high)),
    })
}

/// Append every `port` or `start-end` token of a comma-separated port spec; a token
/// that is not a valid nonzero port, or a backwards range, is skipped, never guessed.
fn push_port_spec(text: Option<&str>, ranges: &mut Vec<ferrox_core::hysteria::PortRange>) {
    use ferrox_core::hysteria::PortRange;
    let Some(text) = text else { return };
    for token in text.split(',') {
        let token = token.trim();
        match token.split_once('-') {
            Some((lo, hi)) => {
                let (Ok(start), Ok(end)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>())
                else {
                    continue;
                };
                if start > 0 && start <= end {
                    ranges.push(PortRange { start, end });
                }
            }
            None => {
                if let Some(port) = token.parse::<u16>().ok().filter(|port| *port > 0) {
                    ranges.push(PortRange {
                        start: port,
                        end: port,
                    });
                }
            }
        }
    }
}

/// The next stay length in milliseconds: a bare number or string is seconds, an `s`
/// suffix is seconds, an `ms` suffix is milliseconds; `None` when absent or malformed.
fn stay_ms(value: Option<&Json>) -> Option<u64> {
    match value? {
        Json::Num(n) if n.fract() == 0.0 && *n >= 0.0 => Some(*n as u64 * 1000),
        Json::Str(text) => {
            let text = text.trim();
            if let Some(ms) = text.strip_suffix("ms") {
                ms.trim().parse::<u64>().ok()
            } else if let Some(s) = text.strip_suffix('s') {
                s.trim().parse::<u64>().ok().map(|secs| secs * 1000)
            } else {
                text.parse::<u64>().ok().map(|secs| secs * 1000)
            }
        }
        _ => None,
    }
}

/// The `obfs: salamander` (or `gecko`) password a hysteria transport names in its `tlsSettings`, or `None` for no obfuscation and `Some("")` for one this build cannot honour; the caller serves cleartext only for the first. Gecko masks each frame with salamander, so it shares this key.
pub(crate) fn salamander_obfs(stream: Option<&Json>) -> Option<String> {
    let tls = stream.and_then(|s| s.get("tlsSettings"));
    match tls.and_then(|t| t.get("obfs")).and_then(Json::as_str) {
        None | Some("") => None,
        Some("salamander" | "gecko") => Some(
            tls.and_then(|t| t.get("obfs-password"))
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
        ),
        Some(_) => Some(String::new()),
    }
}

/// The `obfs: gecko` fragment window a hysteria transport names, `Ok(None)` when the
/// obfs is absent or another kind, `Ok(Some(window))` for a valid gecko, and `Err(())`
/// when gecko is named but its window is unusable — refused rather than carried as a
/// plain salamander that would silently drop the fragmentation. Bounds accept the
/// sing-box `min_packet_size`/`max_packet_size`, their camel spellings, and the
/// reference's `packetSize` range as an object or a two-element array.
fn hysteria_gecko(stream: Option<&Json>) -> Result<Option<ferrox_core::hysteria::Gecko>, ()> {
    let Some(tls) = stream.and_then(|s| s.get("tlsSettings")) else {
        return Ok(None);
    };
    if tls.get("obfs").and_then(Json::as_str) != Some("gecko") {
        return Ok(None);
    }
    let size = |keys: [&str; 2]| {
        keys.into_iter()
            .find_map(|key| tls.get(key))
            .and_then(Json::as_u32)
            .and_then(|value| u16::try_from(value).ok())
    };
    let (min, max) = match (
        size(["minPacketSize", "min_packet_size"]),
        size(["maxPacketSize", "max_packet_size"]),
    ) {
        (Some(min), Some(max)) => (min, max),
        (min, max) => {
            // Fall back to the reference's `packetSize` range, object or array form.
            let edge = |json: &Json, from: bool| {
                json.get(if from { "from" } else { "to" })
                    .or_else(|| json.as_arr().and_then(|a| a.get(usize::from(!from))))
                    .and_then(Json::as_u32)
                    .and_then(|value| u16::try_from(value).ok())
            };
            match tls.get("packetSize") {
                Some(range) => (
                    min.or_else(|| edge(range, true)).unwrap_or(0),
                    max.or_else(|| edge(range, false)).unwrap_or(0),
                ),
                None => (min.unwrap_or(0), max.unwrap_or(0)),
            }
        }
    };
    ferrox_core::hysteria::Gecko::new(min, max)
        .map(Some)
        .ok_or(())
}

/// The masquerade cover an inbound hysteria server answers a browser with, read from its `hysteriaSettings`. Absent, empty, or an unknown type falls back to the plain not-found — today's behavior — so only a configured cover ever changes what a browser sees. Field names accept both the camel and the snake spelling the reference's two JSON dialects use.
pub(crate) fn masquerade_from_stream(stream: Option<&Json>) -> ferrox_core::hysteria::Masquerade {
    use ferrox_core::hysteria::Masquerade;
    let Some(hy) = stream.and_then(|s| s.get("hysteriaSettings")) else {
        return Masquerade::NotFound;
    };
    let field = |camel: &str, snake: &str| hy.get(camel).or_else(|| hy.get(snake));
    let text = |camel: &str, snake: &str| field(camel, snake).and_then(Json::as_str);
    let flag =
        |camel: &str, snake: &str| field(camel, snake).and_then(Json::as_bool).unwrap_or(false);
    match text("masqType", "masq_type").unwrap_or_default() {
        "file" => {
            text("masqFile", "masq_file").map_or(Masquerade::NotFound, |dir| Masquerade::File {
                dir: dir.to_owned(),
            })
        }
        "proxy" => {
            text("masqUrl", "masq_url").map_or(Masquerade::NotFound, |url| Masquerade::Proxy {
                url: url.to_owned(),
                rewrite_host: flag("masqUrlRewriteHost", "masq_url_rewrite_host"),
                x_forwarded: flag("masqUrlXForwarded", "masq_url_x_forwarded"),
                insecure: flag("masqUrlInsecure", "masq_url_insecure"),
            })
        }
        "response" => {
            let status = field("masqStringStatusCode", "masq_string_status_code")
                .and_then(Json::as_u32)
                .filter(|code| *code != 0)
                .map_or(200, |code| code as u16);
            let body = text("masqString", "masq_string")
                .unwrap_or_default()
                .as_bytes()
                .to_vec();
            let headers = field("masqStringHeaders", "masq_string_headers")
                .and_then(Json::as_arr)
                .map_or_else(Vec::new, |items| {
                    items
                        .iter()
                        .filter_map(Json::as_str)
                        .filter_map(header_line)
                        .collect()
                });
            Masquerade::Response {
                status,
                headers,
                body,
            }
        }
        _ => Masquerade::NotFound,
    }
}

/// One `Name: value` line from a masquerade response's header list, split on its first colon; a line naming nothing is dropped.
fn header_line(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once(':')?;
    Some((name.trim().to_owned(), value.trim().to_owned()))
}

pub(crate) fn outbound_carrier(outbound: &Json, address: &str) -> (Carrier, String) {
    let settings = outbound.get("streamSettings");
    let carrier = stream_carrier(settings);
    let key = match &carrier {
        Carrier::Ws { .. } => "wsSettings",
        Carrier::HttpUpgrade { .. } => "httpupgradeSettings",
        Carrier::Grpc { .. } => "grpcSettings",
        Carrier::Xhttp { .. } => "xhttpSettings",
        Carrier::HttpHeader { .. } => "tcpSettings",
        Carrier::Quic => "quicSettings",
        Carrier::Kcp(_) => "kcpSettings",
        Carrier::Hysteria(_) => "hysteriaSettings",
        Carrier::Masque => "masqueSettings",
        Carrier::Xdrive { .. } => "xdriveSettings",
        Carrier::Unknown { .. } | Carrier::Raw(_) | Carrier::Http => "",
    };
    let host = settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("host"))
        .and_then(Json::as_str)
        .unwrap_or(address)
        .to_owned();
    (carrier, host)
}

pub(crate) fn inbound_carrier(inbound: &Json) -> Carrier {
    stream_carrier(inbound.get("streamSettings"))
}

/// A wait the config restates; `None` keeps the constant beside the name in `budgets.rs`.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Budgets {
    pub(crate) dial: Option<Duration>,
    pub(crate) handshake: Option<Duration>,
    pub(crate) head_arrival: Option<Duration>,
    pub(crate) relay_join: Option<Duration>,
    pub(crate) relay_quantum: Option<Duration>,
    pub(crate) relay_stall: Option<Duration>,
    pub(crate) udp_idle: Option<Duration>,
    pub(crate) payload_grace: Option<Duration>,
    pub(crate) goaway_grace: Option<Duration>,
    pub(crate) sink_grace: Option<Duration>,
    pub(crate) carrier_probe: Option<Duration>,
}

/// The top-level `"budgets"` object, one name per wait. A name this tree does not know is refused rather than ignored, because a typo in a budget reads as the default it did not set.
pub(crate) fn budgets(root: &Json) -> Result<Budgets, String> {
    let mut out = Budgets::default();
    let Some(section) = root.get("budgets") else {
        return Ok(out);
    };
    let Json::Obj(pairs) = section else {
        return Err("`budgets` is not an object".to_owned());
    };
    for (key, value) in pairs {
        let slot = match key.as_str() {
            "dial" => &mut out.dial,
            "handshake" => &mut out.handshake,
            "headArrival" => &mut out.head_arrival,
            "relayJoin" => &mut out.relay_join,
            "relayQuantum" => &mut out.relay_quantum,
            "relayStall" => &mut out.relay_stall,
            "udpIdle" => &mut out.udp_idle,
            "payloadGrace" => &mut out.payload_grace,
            "goawayGrace" => &mut out.goaway_grace,
            "sinkGrace" => &mut out.sink_grace,
            "carrierProbe" => &mut out.carrier_probe,
            other => return Err(format!("unknown budget `{other}`")),
        };
        *slot = Some(duration(value, key)?);
    }
    Ok(out)
}

/// `"30s"` or `"2500ms"`, and nothing else: a bare number is refused because the unit a wait is measured in is not the reader's guess.
fn duration(value: &Json, key: &str) -> Result<Duration, String> {
    let reject = |reason: String| format!("budget `{key}`: {reason}");
    let text = value
        .as_str()
        .ok_or_else(|| reject("expected a string like \"500ms\" or \"30s\"".to_owned()))?;
    let (digits, scale) = match text.strip_suffix("ms") {
        Some(digits) => (digits, 1),
        None => match text.strip_suffix('s') {
            Some(digits) => (digits, 1_000),
            None => return Err(reject(format!("{text:?} names no `ms` or `s` unit"))),
        },
    };
    let count: u64 = digits
        .trim()
        .parse()
        .map_err(|_| reject(format!("{text:?} is not a count")))?;
    if count == 0 {
        return Err(reject("a wait of none is not a budget".to_owned()));
    }
    count
        .checked_mul(scale)
        .map(Duration::from_millis)
        .ok_or_else(|| reject(format!("{text:?} is past a measurable wait")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_id_hex_fills_from_the_front() {
        assert_eq!(short_id("a8"), Some([0xa8, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(short_id("01020304"), Some([1, 2, 3, 4, 0, 0, 0, 0]));
        assert_eq!(short_id(""), None);
        assert_eq!(short_id("abc"), None);
    }

    #[test]
    fn a_hysteria_carrier_carries_salamander_and_refuses_what_it_cannot_mask() {
        let carrier = |text: &str| {
            stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            )
        };
        // A named salamander with a usable password reaches the wire as that password.
        let Carrier::Hysteria(config) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "salamander", "obfs-password": "gawrgura"}}}"#,
        ) else {
            panic!("a salamander carrier");
        };
        assert_eq!(config.obfs_password, "gawrgura", "the key the config named");
        // No obfs is cleartext, so the password stays empty.
        let Carrier::Hysteria(clear) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}}}"#,
        ) else {
            panic!("a v2 hysteria carrier");
        };
        assert_eq!(clear.obfs_password, "", "cleartext names no key");
        // A different named obfuscation is refused, not silently sent in the clear.
        assert!(matches!(
            carrier(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "xray-obfs"}}}"#
            ),
            Carrier::Unknown { .. }
        ));
        // A salamander whose password is too short to mask with is refused for the same reason.
        assert!(matches!(
            carrier(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "salamander", "obfs-password": "ab"}}}"#
            ),
            Carrier::Unknown { .. }
        ));
    }

    #[test]
    fn a_hysteria_carrier_reads_a_port_hopping_plan() {
        let planned = |text: &str| {
            let Carrier::Hysteria(config) = stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            ) else {
                panic!("a v2 hysteria carrier");
            };
            config.hop
        };
        // A comma spec of a range and a lone port, bounded in seconds and one with a unit, expands to the sorted set the dial rotates over.
        let spec = r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "serverPorts": "20000-20002,443", "hopInterval": 5, "hopIntervalMax": "10s"}}}"#;
        let plan = planned(spec).expect("a plan");
        assert_eq!(plan.ports(), vec![443, 20_000, 20_001, 20_002]);
        assert_eq!(
            plan.interval_ms,
            (5_000, 10_000),
            "seconds reach the dial as ms"
        );
        // An array of numbers and range strings is the same plan; with no interval the stay defaults to a fixed five seconds.
        let arr = r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "serverPorts": [443, "9000-9001"]}}}"#;
        let plan = planned(arr).expect("a plan");
        assert_eq!(plan.ports(), vec![443, 9_000, 9_001]);
        assert_eq!(plan.interval_ms, (5_000, 5_000), "an absent stay is fixed");
        // A malformed port spec leaves no valid range, so the dial stays on its fixed port rather than routing to a port the config never named.
        assert!(
            planned(r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "serverPorts": "0,70000"}}}"#)
                .is_none(),
            "nothing valid means no hop"
        );
    }

    #[test]
    fn a_hysteria_carrier_reads_a_gecko_window() {
        use ferrox_core::hysteria::Gecko;
        let carrier = |text: &str| {
            stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            )
        };
        // A gecko obfs with the sing-box bounds keeps its shared key and reaches the dial as that window.
        let Carrier::Hysteria(config) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura", "min_packet_size": 600, "max_packet_size": 1000}}}"#,
        ) else {
            panic!("a gecko carrier");
        };
        assert_eq!(
            config.obfs_password, "gawrgura",
            "gecko masks with the shared key"
        );
        assert_eq!(
            config.gecko,
            Some(Gecko {
                min_pkt: 600,
                max_pkt: 1000
            })
        );
        // The reference's `packetSize` range, in object form, names the same window.
        let Carrier::Hysteria(range) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura", "packetSize": {"from": 700, "to": 900}}}}"#,
        ) else {
            panic!("a gecko carrier");
        };
        assert_eq!(
            range.gecko,
            Some(Gecko {
                min_pkt: 700,
                max_pkt: 900
            }),
            "the camel form is the same window"
        );
        // A gecko that names no bounds takes the reference defaults.
        let Carrier::Hysteria(defaults) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura"}}}"#,
        ) else {
            panic!("a gecko carrier");
        };
        assert_eq!(
            defaults.gecko,
            Gecko::new(0, 0),
            "an absent window is defaulted"
        );
        // A salamander obfs is not a gecko: the same key, no fragmentation window.
        let Carrier::Hysteria(salamander) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "salamander", "obfs-password": "gawrgura"}}}"#,
        ) else {
            panic!("a salamander carrier");
        };
        assert_eq!(salamander.gecko, None, "salamander never fragments");
        // A window past the largest frame is refused, not silently carried as a plain salamander.
        assert!(matches!(
            carrier(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura", "min_packet_size": 100, "max_packet_size": 5000}}}"#
            ),
            Carrier::Unknown { .. }
        ));
    }

    #[test]
    fn tls_cipher_suites_carries_the_crafted_field() {
        let with = crate::json::parse(
            r#"{"tlsSettings": {"cipherSuites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","maxVersion":"1.3","minVersion":"1.3"}}"#,
        )
        .expect("parses")
        .get("tlsSettings")
        .cloned()
        .expect("tlsSettings");
        // A TLS 1.3-only hello is the reference trio, reordered into crypto/tls order.
        assert_eq!(tls_cipher_suites(Some(&with)), vec![0x1301, 0x1302, 0x1303]);
        // No cipherSuites means stock ordering, so the backend is left untouched.
        let none = crate::json::parse(r#"{"tlsSettings": {}}"#)
            .expect("parses")
            .get("tlsSettings")
            .cloned()
            .expect("tlsSettings");
        assert_eq!(tls_cipher_suites(Some(&none)), [] as [u16; 0]);
    }

    #[test]
    fn tls_cert_paths_read_the_first_certificate() {
        let tls = crate::json::parse(
            r#"{"streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/tmp/a.crt", "keyFile": "/tmp/a.key"}]}}}"#,
        )
        .expect("parses");
        let settings = tls.get("streamSettings").expect("settings");
        assert_eq!(tls_cert_paths(settings), Some(("/tmp/a.crt", "/tmp/a.key")));
        assert!(inbound_tls_identity(&tls).is_none());
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        let settings = plain.get("streamSettings").expect("settings");
        assert_eq!(tls_cert_paths(settings), None);
    }

    #[test]
    fn inbound_tls_identity_reads_an_inline_certificate() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["tls.test".to_owned()]).expect("mints");
        let lines_json = |pem: &str| -> String {
            pem.trim_end()
                .lines()
                .map(|line| format!("\"{line}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let string_json = |pem: &str| -> String {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        // The array-of-lines spelling a REALITY decoy hands over.
        let array_form = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificate": [{}], "key": [{}]}}]}}}}}}"#,
            lines_json(&minted.cert.pem()),
            lines_json(&minted.signing_key.serialize_pem())
        ))
        .expect("parses");
        assert!(
            inbound_tls_identity(&array_form).is_some(),
            "an inline certificate/key array loads, so the inbound binds"
        );
        // The single-string spelling resolves to the same identity.
        let string_form = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificate": {}, "key": {}}}]}}}}}}"#,
            string_json(&minted.cert.pem()),
            string_json(&minted.signing_key.serialize_pem())
        ))
        .expect("parses");
        assert!(
            inbound_tls_identity(&string_form).is_some(),
            "an inline certificate/key string loads too"
        );
    }

    #[test]
    fn an_absent_budgets_section_moves_no_wait() {
        let root = crate::json::parse(r#"{"inbounds": []}"#).expect("parses");
        assert_eq!(
            budgets(&root).expect("no section is no override"),
            Budgets::default(),
            "a config that names no wait leaves every one at its constant"
        );
    }

    #[test]
    fn a_budget_the_engine_cannot_act_on_is_refused_by_name() {
        for (json, because) in [
            (
                r#"{"budgets": {"dialTimeout": "5s"}}"#,
                "a name no site reads must not read as the default it did not set",
            ),
            (
                r#"{"budgets": {"dial": "500"}}"#,
                "the unit a wait is measured in is not the reader's guess",
            ),
            (
                r#"{"budgets": {"dial": "0ms"}}"#,
                "a wait of none is not a budget",
            ),
            (
                r#"{"budgets": {"dial": 500}}"#,
                "a count with no unit spelled is not a duration",
            ),
            (
                r#"{"budgets": {"dial": "9223372036854775807s"}}"#,
                "past a measurable wait is a typo, not a deadline",
            ),
            (
                r#"{"budgets": []}"#,
                "a section that is not an object names nothing",
            ),
        ] {
            let root = crate::json::parse(json).expect("parses as JSON");
            let error = budgets(&root).expect_err(because);
            assert!(error.contains("budget"), "{json}: {error}");
        }
    }
}
