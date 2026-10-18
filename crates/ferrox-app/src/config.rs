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

pub(crate) fn tls_ca_roots(outbound: &Json) -> Option<Vec<Vec<u8>>> {
    outbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|s| s.get("caCertFile"))
        .and_then(Json::as_str)
        .and_then(|path| std::fs::read(path).ok())
        .map(|pem| crate::quic::parse_ca_pem(&pem))
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
) -> Option<Arc<ferrox_core::tls::TlsConfig>> {
    let settings = outbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return None;
    }
    let tls = settings.get("tlsSettings");
    if matches!(
        tls.and_then(|s| s.get("allowInsecure")),
        Some(Json::Bool(true))
    ) {
        return None;
    }
    let server_name = tls
        .and_then(|s| s.get("serverName"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(address)
        .to_owned();
    if server_name.is_empty() {
        return None;
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
    })?;
    if roots.is_empty() {
        return None;
    }
    Some(Arc::new(ferrox_core::tls::TlsConfig {
        server_name,
        alpn,
        roots,
        pins: ferrox_core::foxy::pin::Pins::default(),
        cipher_suites: tls_cipher_suites(tls),
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
    Raw,
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
    Xdrive,
    Http,
    Unknown {
        network: String,
    },
}

type Resolver = fn(Option<&Json>, &str) -> Carrier;

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
    for (aliases, resolve) in CARRIERS {
        if aliases.contains(&network) {
            return resolve(settings, network);
        }
    }
    Carrier::Unknown {
        network: network.to_owned(),
    }
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

fn resolve_xdrive(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Xdrive
}

fn resolve_http(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Http
}

fn resolve_tcp_or_header(settings: Option<&Json>, _: &str) -> Carrier {
    match tcp_http_path(settings) {
        Some(path) => Carrier::HttpHeader { path },
        None => Carrier::Raw,
    }
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
    // Salamander is the only datagram obfuscation carried; any other named one, or one with a password too short to mask with, is refused rather than silently sent in the clear.
    let obfs_password = match salamander_obfs(settings) {
        None => String::new(),
        Some(password) if ferrox_core::hysteria::Salamander::new(&password).is_some() => password,
        Some(_) => {
            return Carrier::Unknown {
                network: network.to_owned(),
            };
        }
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
    })
}

/// The `obfs: salamander` password a hysteria transport names in its `tlsSettings`, or `None` for no obfuscation and `Some("")` for one this build cannot honour; the caller serves cleartext only for the first.
pub(crate) fn salamander_obfs(stream: Option<&Json>) -> Option<String> {
    let tls = stream.and_then(|s| s.get("tlsSettings"));
    match tls.and_then(|t| t.get("obfs")).and_then(Json::as_str) {
        None | Some("") => None,
        Some("salamander") => Some(
            tls.and_then(|t| t.get("obfs-password"))
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
        ),
        Some(_) => Some(String::new()),
    }
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
        Carrier::Xdrive => "xdriveSettings",
        Carrier::Unknown { .. } | Carrier::Raw | Carrier::Http => "",
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
    pub(crate) udp_idle: Option<Duration>,
    pub(crate) payload_grace: Option<Duration>,
    pub(crate) goaway_grace: Option<Duration>,
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
            "udpIdle" => &mut out.udp_idle,
            "payloadGrace" => &mut out.payload_grace,
            "goawayGrace" => &mut out.goaway_grace,
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
            lines_json(&minted.key_pair.serialize_pem())
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
            string_json(&minted.key_pair.serialize_pem())
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
