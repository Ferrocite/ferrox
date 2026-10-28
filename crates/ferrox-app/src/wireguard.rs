//! `WireGuard`'s config, in the shape both xray's JSON and its protobuf carry:
//! a secret key, the tunnel addresses, and the peers a client dials or a server
//! admits. Keys arrive as hexadecimal or base64; addresses as bare or prefixed;
//! a peer's allowed IPs are the cryptokey-routing table the server answers by
//! and the client checks before it puts a flow on the tunnel.
//!
//! The defaults are the pinned `infra/conf/wireguard.go` ones: a missing address
//! list is the two bogons `10.0.0.1` and `fd59:7153:2388:b5fd::1`, a missing
//! peer allowed-IP list is `0.0.0.0/0` and `::0/0`, and a missing MTU is 1420.
//! A key that does not decode is a config error, not a zero key: a tunnel with
//! one side's public key zeroed would handshake with nobody.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};

use base64::Engine as _;

use crate::json::Json;

/// The MTU xray gives a device whose config names none.
pub(crate) const DEFAULT_MTU: usize = 1420;
/// The most answers one peer endpoint name offers to the handshake.
const ENDPOINT_CANDIDATES: usize = 8;
/// The server's own bogon addresses when the config names none.
const DEFAULT_ADDRESSES: [&str; 2] = ["10.0.0.1", "fd59:7153:2388:b5fd::1"];
/// The allowed IPs a peer with none is given: the whole of both families.
const DEFAULT_ALLOWED: [&str; 2] = ["0.0.0.0/0", "::0/0"];

#[derive(Debug, Clone)]
pub(crate) struct PeerConfig {
    pub(crate) public: [u8; 32],
    pub(crate) preshared: [u8; 32],
    pub(crate) endpoint: Option<SocketAddr>,
    pub(crate) endpoints: Vec<SocketAddr>,
    pub(crate) keepalive: u16,
    pub(crate) allowed: Vec<(IpAddr, u8)>,
}

impl PeerConfig {
    /// Whether an inner destination is this peer's to route, by longest prefix
    /// in the peer's allowed IPs. Used on the server to answer a reply and on
    /// the client before it puts a flow on the tunnel.
    #[must_use]
    pub(crate) fn routes(&self, destination: IpAddr) -> bool {
        self.longest_prefix(destination).is_some()
    }

    /// The longest allowed prefix that covers `destination`, which is the
    /// prefix length the server's reply and the client's dial choose by.
    pub(crate) fn longest_prefix(&self, destination: IpAddr) -> Option<u8> {
        self.allowed
            .iter()
            .filter(|(prefix, bits)| prefix_matches(*prefix, *bits, destination))
            .map(|(_, bits)| *bits)
            .max()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DeviceConfig {
    pub(crate) secret: [u8; 32],
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) peers: Vec<PeerConfig>,
    pub(crate) mtu: usize,
    pub(crate) reserved: [u8; 3],
    pub(crate) is_client: Option<bool>,
    pub(crate) no_kernel_tun: bool,
    pub(crate) dns: Vec<IpAddr>,
}

impl DeviceConfig {
    /// Decode the JSON a protobuf handler was lowered to, or one written in
    /// xray's own dialect. `secretKey` and at least one peer are required; the
    /// rest take the reference's defaults.
    pub(crate) fn from_json(settings: &Json) -> Result<Self, String> {
        let secret = parse_key(
            settings
                .get("secretKey")
                .and_then(Json::as_str)
                .ok_or("wireguard: no `secretKey`")?,
        )?;
        let mut addresses = strings(settings.get("address"))
            .or_else(|| strings(settings.get("endpoint")))
            .unwrap_or_else(|| DEFAULT_ADDRESSES.map(str::to_owned).to_vec());
        if addresses.is_empty() {
            addresses = DEFAULT_ADDRESSES.map(str::to_owned).to_vec();
        }
        let addresses = addresses
            .iter()
            .map(|address| parse_address(address))
            .collect::<Result<Vec<_>, _>>()?;
        let peers = match settings.get("peers").or_else(|| settings.get("users")) {
            Some(Json::Arr(items)) => items
                .iter()
                .map(peer_from_json)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err("wireguard: `peers` is not an array".to_owned()),
            None => return Err("wireguard: no `peers`".to_owned()),
        };
        if peers.is_empty() {
            return Err("wireguard: no `peers`".to_owned());
        }
        let mtu = settings
            .get("mtu")
            .and_then(Json::as_u32)
            .map_or(DEFAULT_MTU, |mtu| {
                if mtu == 0 {
                    DEFAULT_MTU
                } else {
                    mtu as usize
                }
            });
        let reserved = reserved_from_json(settings.get("reserved"))?;
        let dns = strings(settings.get("remoteDNS").or_else(|| settings.get("DNS")))
            .unwrap_or_default()
            .iter()
            .map(|address| parse_address(address))
            .collect::<Result<Vec<_>, _>>()?;
        // `kernelMode` is the client switch; `noKernelTun` is its inverse, and the newer name wins when both are present.
        let no_kernel_tun = match settings.get("kernelMode").and_then(Json::as_bool) {
            Some(kernel) => !kernel,
            None => settings
                .get("noKernelTun")
                .and_then(Json::as_bool)
                .unwrap_or(false),
        };
        Ok(Self {
            secret,
            addresses,
            peers,
            mtu,
            reserved,
            is_client: settings.get("isClient").and_then(Json::as_bool),
            no_kernel_tun,
            dns,
        })
    }
}

fn peer_from_json(peer: &Json) -> Result<PeerConfig, String> {
    let account = peer.get("account").unwrap_or(peer);
    let public = parse_key(
        account
            .get("publicKey")
            .and_then(Json::as_str)
            .ok_or("wireguard peer: no `publicKey`")?,
    )?;
    let preshared = match account.get("preSharedKey").and_then(Json::as_str) {
        Some(key) if !key.is_empty() => parse_key(key)?,
        _ => [0u8; 32],
    };
    let endpoints = account
        .get("endpoint")
        .and_then(Json::as_str)
        .filter(|endpoint| !endpoint.is_empty())
        .map(parse_endpoints)
        .transpose()?
        .unwrap_or_default();
    let endpoint = endpoints.first().copied();
    let keepalive = match account.get("keepAlive") {
        Some(Json::Num(value)) if *value >= 0.0 && *value <= f64::from(u16::MAX) => *value as u16,
        Some(Json::Str(value)) => value
            .parse()
            .map_err(|_| format!("wireguard peer: keepAlive `{value}` is not seconds"))?,
        Some(_) => return Err("wireguard peer: keepAlive is not a number".to_owned()),
        None => 0,
    };
    let mut allowed = strings(account.get("allowedIPs"))
        .unwrap_or_else(|| DEFAULT_ALLOWED.map(str::to_owned).to_vec());
    if allowed.is_empty() {
        allowed = DEFAULT_ALLOWED.map(str::to_owned).to_vec();
    }
    let allowed = allowed
        .iter()
        .map(|prefix| parse_prefix(prefix))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PeerConfig {
        public,
        preshared,
        endpoint,
        endpoints,
        keepalive,
        allowed,
    })
}

fn strings(value: Option<&Json>) -> Option<Vec<String>> {
    let value = value?;
    match value {
        Json::Arr(items) => Some(
            items
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        _ => None,
    }
}

/// A key as xray's `ParseWireGuardKey` accepts it: 64 hexadecimal characters,
/// otherwise raw standard or URL-safe base64 with the padding ignored. Exactly
/// 32 bytes is the only length a key has.
pub(crate) fn parse_key(text: &str) -> Result<[u8; 32], String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("wireguard key: empty".to_owned());
    }
    if text.len() == 64 {
        if let Some(key) = hex_key(text) {
            return Ok(key);
        }
    }
    let mut decoded = None;
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(text.trim_end_matches('=')) {
            decoded = Some(bytes);
            break;
        }
    }
    let bytes = decoded.ok_or_else(|| "wireguard key: not hex or base64".to_owned())?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "wireguard key: not 32 bytes".to_owned())?;
    Ok(key)
}

fn hex_key(text: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// A key as the hexadecimal form both this tree's config writer and its
/// diagnostics use.
#[cfg(test)]
fn hex_key_string(key: &[u8; 32]) -> String {
    ferrox_core::foxy::account::hex_encode(key)
}

pub(crate) fn parse_address(text: &str) -> Result<IpAddr, String> {
    let text = text.trim();
    let text = text.split_once('/').map_or(text, |(address, _)| address);
    text.parse()
        .map_err(|_| format!("wireguard address `{text}` is not an IP address"))
}

pub(crate) fn parse_prefix(text: &str) -> Result<(IpAddr, u8), String> {
    let text = text.trim();
    let (address, bits) = text
        .split_once('/')
        .map_or((text, None), |(address, bits)| (address, Some(bits)));
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("wireguard prefix `{text}` is not an IP network"))?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    let bits = match bits {
        Some(bits) => bits
            .parse()
            .map_err(|_| format!("wireguard prefix `{text}` has no length"))?,
        None => max,
    };
    if bits > max {
        return Err(format!("wireguard prefix `{text}` is longer than {max}"));
    }
    Ok((address, bits))
}

fn parse_endpoints(text: &str) -> Result<Vec<SocketAddr>, String> {
    if let Ok(address) = text.parse() {
        return Ok(vec![address]);
    }
    let addresses: Vec<SocketAddr> = text
        .to_socket_addrs()
        .map_err(|error| format!("wireguard endpoint `{text}` does not resolve: {error}"))?
        .collect();
    let addresses = limit_candidates(addresses);
    if addresses.is_empty() {
        return Err(format!(
            "wireguard endpoint `{text}` resolves to no address"
        ));
    }
    Ok(addresses)
}

/// The candidate list keeps one answer of each family before it fills the
/// remaining slots, so a v4-heavy name cannot crowd out its v6 answer.
fn limit_candidates(mut addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.len() <= ENDPOINT_CANDIDATES {
        return addresses;
    }
    let mut kept = Vec::with_capacity(ENDPOINT_CANDIDATES);
    for family in [true, false] {
        if let Some(address) = addresses.iter().find(|address| address.is_ipv4() == family) {
            kept.push(*address);
        }
    }
    for address in addresses {
        if kept.len() >= ENDPOINT_CANDIDATES {
            break;
        }
        if !kept.contains(&address) {
            kept.push(address);
        }
    }
    kept
}

fn reserved_from_json(value: Option<&Json>) -> Result<[u8; 3], String> {
    let Some(value) = value else {
        return Ok([0; 3]);
    };
    match value {
        Json::Null => Ok([0; 3]),
        Json::Arr(items) if items.is_empty() => Ok([0; 3]),
        Json::Arr(items) if items.len() == 3 => {
            let mut reserved = [0u8; 3];
            for (slot, item) in reserved.iter_mut().zip(items) {
                *slot = u8::try_from(item.as_u32().ok_or("wireguard reserved: not 0..=255")?)
                    .map_err(|_| "wireguard reserved: not 0..=255".to_owned())?;
            }
            Ok(reserved)
        }
        Json::Arr(_) => Err("wireguard reserved: not three bytes".to_owned()),
        Json::Str(text) if text.is_empty() => Ok([0; 3]),
        Json::Str(text) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text.trim_end_matches('='))
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(text.trim_end_matches('='))
                })
                .map_err(|_| "wireguard reserved: not base64".to_owned())?;
            bytes
                .try_into()
                .map_err(|_| "wireguard reserved: not three bytes".to_owned())
        }
        _ => Err("wireguard reserved: not bytes".to_owned()),
    }
}

fn prefix_matches(prefix: IpAddr, bits: u8, address: IpAddr) -> bool {
    match (prefix, address) {
        (IpAddr::V4(prefix), IpAddr::V4(address)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            u32::from(prefix) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(prefix), IpAddr::V6(address)) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            u128::from(prefix) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        crate::json::parse(text).expect("parses")
    }

    #[test]
    fn keys_arrive_in_hex_and_both_base64_dialects() {
        let key = [0xab; 32];
        let hex = hex_key_string(&key);
        assert_eq!(parse_key(&hex).expect("hex"), key);
        let standard = base64::engine::general_purpose::STANDARD.encode(key);
        assert_eq!(parse_key(&standard).expect("standard"), key);
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        assert_eq!(parse_key(&url).expect("url"), key);
        assert!(parse_key("not a key").is_err());
        assert!(parse_key(&"00".repeat(31)).is_err(), "31 bytes");
    }

    #[test]
    fn prefixes_match_only_their_own_family_and_length() {
        assert!(prefix_matches(
            "10.0.0.0".parse().unwrap(),
            8,
            "10.9.9.9".parse().unwrap()
        ));
        assert!(!prefix_matches(
            "10.0.0.0".parse().unwrap(),
            8,
            "192.0.2.1".parse().unwrap()
        ));
        assert!(prefix_matches(
            "::".parse().unwrap(),
            0,
            "fd00::1".parse().unwrap()
        ));
        assert!(!prefix_matches(
            "fd00::".parse().unwrap(),
            16,
            "10.0.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn the_defaults_are_the_reference_ones() {
        let config = DeviceConfig::from_json(&json(
            r#"{"secretKey":"0000000000000000000000000000000000000000000000000000000000000001",
                "peers":[{"publicKey":"0000000000000000000000000000000000000000000000000000000000000002"}]}"#,
        ))
        .expect("defaults");
        assert_eq!(config.mtu, DEFAULT_MTU);
        assert_eq!(
            config.addresses,
            vec![
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "fd59:7153:2388:b5fd::1".parse().unwrap()
            ]
        );
        assert!(config.peers[0].routes("192.0.2.1".parse().unwrap()));
        assert!(config.peers[0].routes("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn kernel_mode_is_the_newer_name_for_no_kernel_tun() {
        let base = r#""secretKey":"0000000000000000000000000000000000000000000000000000000000000001",
                "peers":[{"publicKey":"0000000000000000000000000000000000000000000000000000000000000002"}]"#;
        let absent = DeviceConfig::from_json(&json(&format!("{{{base}}}"))).expect("absent");
        assert!(!absent.no_kernel_tun);
        let old = DeviceConfig::from_json(&json(&format!("{{{base},\"noKernelTun\":true}}")))
            .expect("old");
        assert!(old.no_kernel_tun);
        let new = DeviceConfig::from_json(&json(&format!("{{{base},\"kernelMode\":false}}")))
            .expect("new");
        assert!(new.no_kernel_tun);
        let both = DeviceConfig::from_json(&json(&format!(
            "{{{base},\"noKernelTun\":true,\"kernelMode\":true}}"
        )))
        .expect("both");
        assert!(!both.no_kernel_tun);
    }

    #[test]
    fn the_longest_allowed_prefix_owns_the_reply() {
        let config = DeviceConfig::from_json(&json(
            r#"{"secretKey":"0000000000000000000000000000000000000000000000000000000000000001",
                "peers":[
                  {"publicKey":"0000000000000000000000000000000000000000000000000000000000000002",
                   "allowedIPs":["0.0.0.0/0","::/0"]},
                  {"publicKey":"0000000000000000000000000000000000000000000000000000000000000003",
                   "allowedIPs":["10.1.0.0/16"]}
                ]}"#,
        ))
        .expect("config");
        assert_eq!(
            config.peers[1].longest_prefix("10.1.2.3".parse().unwrap()),
            Some(16)
        );
        assert_eq!(
            config.peers[0].longest_prefix("10.1.2.3".parse().unwrap()),
            Some(0)
        );
        assert_eq!(
            config.peers[1].longest_prefix("10.2.2.3".parse().unwrap()),
            None
        );
    }

    #[test]
    fn a_literal_endpoint_stays_one_candidate() {
        let config = DeviceConfig::from_json(&json(
            r#"{"secretKey":"0000000000000000000000000000000000000000000000000000000000000001",
                "peers":[{"publicKey":"0000000000000000000000000000000000000000000000000000000000000002",
                          "endpoint":"127.0.0.1:51820"}]}"#,
        ))
        .expect("config");
        assert_eq!(
            config.peers[0].endpoint,
            Some("127.0.0.1:51820".parse().unwrap())
        );
        assert_eq!(
            config.peers[0].endpoints,
            vec!["127.0.0.1:51820".parse().unwrap()]
        );
    }

    #[test]
    fn the_candidate_limit_keeps_one_of_each_family() {
        let mut input: Vec<SocketAddr> = (1..=9)
            .map(|last| format!("192.0.2.{last}:9").parse().unwrap())
            .collect();
        input.push("[2001:db8::1]:9".parse().unwrap());
        input.reverse();
        let kept = limit_candidates(input);
        assert_eq!(kept.len(), ENDPOINT_CANDIDATES);
        assert!(kept.iter().any(SocketAddr::is_ipv4));
        assert!(kept.iter().any(SocketAddr::is_ipv6));
    }

    #[test]
    fn reserved_accepts_three_numbers_or_base64() {
        let base = r#""secretKey":"0000000000000000000000000000000000000000000000000000000000000001",
                    "peers":[{"publicKey":"0000000000000000000000000000000000000000000000000000000000000002"}]"#;
        let array = DeviceConfig::from_json(&json(&format!(r#"{{{base},"reserved":[1,2,3]}}"#)))
            .expect("array");
        assert_eq!(array.reserved, [1, 2, 3]);
        let encoded = base64::engine::general_purpose::STANDARD.encode([4, 5, 6]);
        let text = DeviceConfig::from_json(&json(&format!(r#"{{{base},"reserved":"{encoded}"}}"#)))
            .expect("base64");
        assert_eq!(text.reserved, [4, 5, 6]);
        assert!(
            DeviceConfig::from_json(&json(&format!(r#"{{{base},"reserved":[1,2]}}"#))).is_err()
        );
    }

    #[test]
    fn a_server_user_is_a_peer_under_its_account() {
        let config = DeviceConfig::from_json(&json(
            r#"{"secretKey":"0000000000000000000000000000000000000000000000000000000000000001",
                "users":[{"email":"love@xray.com","level":2,
                  "account":{"publicKey":"0000000000000000000000000000000000000000000000000000000000000002",
                             "allowedIPs":["10.0.0.2/32"]}}]}"#,
        ))
        .expect("users");
        assert!(config.peers[0].routes("10.0.0.2".parse().unwrap()));
        assert!(!config.peers[0].routes("10.0.0.3".parse().unwrap()));
    }
}
