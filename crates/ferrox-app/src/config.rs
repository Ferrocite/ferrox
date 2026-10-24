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
            .get("target")
            .or_else(|| reality.get("dest"))
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

/// One fallback row: the dial a front's first bytes route to when they fail the vless header.
#[derive(Debug, Clone)]
pub(crate) struct Fallback {
    pub(crate) name: String,
    pub(crate) alpn: String,
    pub(crate) path: String,
    pub(crate) network: FallbackNetwork,
    pub(crate) xver: u8,
}

/// The dial a fallback row names, spelled the way the reference hands it to its dialer: the
/// strings stay as the config wrote them and resolve when the dial fires, so an address a
/// dying resolver cannot answer now still dials when one can.
#[derive(Debug, Clone)]
pub(crate) enum FallbackNetwork {
    Tcp {
        family: u8,
        host: String,
        port: u16,
    },
    Udp {
        family: u8,
        host: String,
        port: u16,
    },
    Unix {
        path: String,
    },
    /// `serve-ws-none` leaves `type` as `serve`, which the reference's dialer refuses on
    /// every attempt; the row is carried and the flow falls after its retry budget.
    NotDialable,
}

/// The vless decryption a server names and the fallbacks it routes. The reading carries the
/// dialect's verdicts: an empty `decryption` refuses, a decryption engine this tree does not
/// carry refuses, and fallback rows refuse beside one.
pub(crate) fn server_fallbacks(inbound: &Json) -> Result<Option<Vec<Fallback>>, String> {
    let decryption = inbound
        .get("settings")
        .and_then(|settings| settings.get("decryption").and_then(Json::as_str));
    if let Some(decryption) = decryption {
        if decryption.is_empty() {
            return Err(
                r#"VLESS settings: please add/set "decryption":"none" to every settings"#.into(),
            );
        }
        if decryption != "none" {
            return Err(format!(
                r#"VLESS settings: unsupported "decryption": {decryption}"#
            ));
        }
    }
    let rows = inbound
        .get("settings")
        .and_then(|settings| settings.get("fallbacks"))
        .and_then(Json::as_arr);
    let Some(rows) = rows else {
        return Ok(None);
    };
    if rows.is_empty() {
        return Ok(None);
    }
    let mut table = Vec::with_capacity(rows.len());
    for row in rows {
        let dest_text = fallback_dest_text(row.get("dest"));
        let kind = row.get("type").and_then(Json::as_str).unwrap_or("");
        let path = row.get("path").and_then(Json::as_str).unwrap_or("");
        if !path.is_empty() && !path.starts_with('/') {
            return Err(r#"VLESS fallbacks: "path" must be empty or start with "/""#.into());
        }
        let xver = row.get("xver").and_then(Json::as_u32).unwrap_or(0);
        if xver > 2 {
            return Err(
                r#"VLESS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2"#
                    .into(),
            );
        }
        let Some(network) = fallback_network(kind, &dest_text) else {
            return Err(r#"VLESS fallbacks: please fill in a valid value for every "dest""#.into());
        };
        table.push(Fallback {
            name: row.get("name").and_then(Json::as_str).unwrap_or("").into(),
            alpn: row.get("alpn").and_then(Json::as_str).unwrap_or("").into(),
            path: path.into(),
            network,
            xver: u8::try_from(xver).expect("the version is two at most"),
        });
    }
    Ok(Some(table))
}

impl Fallback {
    /// The row that owns a flow the front named with `front` and `alpn` and whose first read
    /// `first` holds: the walk over the table's names, the fall from the front's alpn to `""`,
    /// and the scan for a request path, each in the order the reference takes them. Every miss
    /// refuses the flow, and the caller of a refused flow relays nothing.
    pub(crate) fn route<'a>(
        table: &'a [Fallback],
        front: &str,
        alpn: &str,
        first: &[u8],
    ) -> Option<&'a Fallback> {
        let mut names: Vec<&str> = Vec::new();
        for row in table {
            if !names.contains(&row.name.as_str()) {
                names.push(row.name.as_str());
            }
        }
        let front = front.to_ascii_lowercase();
        let alpn = alpn.to_ascii_lowercase();
        let mut picked = front.as_str();
        // More table names than one, or none spelled as `""`: an unmatched front walks the longest name spelled inside it, and any miss walks as `""`.
        if (names.len() > 1 || !names.contains(&""))
            && !front.is_empty()
            && !names.contains(&front.as_str())
        {
            picked = names
                .iter()
                .filter(|name| !name.is_empty() && front.contains(*name))
                .max_by_key(|name| name.len())
                .copied()
                .unwrap_or("");
        }
        if !names.contains(&picked) {
            return None;
        }
        // The alpn reads one map: the front's when the name group spells it, `""` when it doesn't; a group that spells neither leaves the flow unserved.
        let spell = |alpn: &str| {
            table
                .iter()
                .any(|row| row.name == picked && row.alpn == alpn)
        };
        let ap = if spell(&alpn) { alpn.as_str() } else { "" };
        if !spell(ap) {
            return None;
        }
        // The paths the group's two alpn maps spell together: the front's own rows keep their paths, duplicates collapse to the row spelled last, and the `""` ones fill where a path has no own cell.
        let mut cells: Vec<(&str, &Fallback)> = Vec::new();
        for row in table
            .iter()
            .filter(|row| row.name == picked && row.alpn == ap)
        {
            put_cell(&mut cells, row);
        }
        for row in table
            .iter()
            .filter(|row| row.name == picked && row.alpn.is_empty())
        {
            if !cells.iter().any(|(path, _)| *path == row.path.as_str()) {
                cells.push((row.path.as_str(), row));
            }
        }
        // The scan runs when the group spells more paths than one or no `""` row fills the default; otherwise the `""` cell answers and the probe's bytes stay unread.
        let mut wanted: &[u8] = b"";
        if cells.len() > 1 || !cells.iter().any(|(path, _)| path.is_empty()) {
            let scanned = scanned_path(first);
            if cells.iter().any(|(path, _)| path.as_bytes() == scanned) {
                wanted = scanned;
            }
        }
        cells
            .into_iter()
            .rev()
            .find(|(path, _)| path.as_bytes() == wanted)
            .map(|(_, row)| row)
    }
}

/// One path cell in a name group, spelled last wins, the way the reference's map insert
/// collapses duplicate rows.
fn put_cell<'a>(cells: &mut Vec<(&'a str, &'a Fallback)>, row: &'a Fallback) {
    match cells
        .iter_mut()
        .find(|(path, _)| *path == row.path.as_str())
    {
        Some(cell) => *cell = (row.path.as_str(), row),
        None => cells.push((row.path.as_str(), row)),
    }
}

/// The request path the probe's first bytes spell, over the window the reference looks in:
/// a `/` opened behind byte four and closed by a `?` or a space wins, the CR/LF or the
/// window's edge leaves the path unfound, and an unserved shape reads nothing at all.
fn scanned_path(first: &[u8]) -> &[u8] {
    if first.len() < 18 || first[4] == b'*' {
        return b"";
    }
    for i in 4..=8 {
        if first[i] == b'/' && first[i - 1] == b' ' {
            let mut found: &[u8] = b"";
            for j in i + 1..first.len().min(64) {
                match first[j] {
                    b'\r' | b'\n' => break,
                    b'?' | b' ' => {
                        found = &first[i..j];
                        break;
                    }
                    _ => {}
                }
            }
            return found;
        }
    }
    b""
}

/// A `dest` spells itself either as a string or as a bare port number; the number is the lonely
/// host the reference's dialer lands on `localhost`.
fn fallback_dest_text(node: Option<&Json>) -> String {
    match node {
        Some(Json::Str(text)) => text.clone(),
        Some(Json::Num(_)) => node
            .and_then(Json::as_port)
            .map(|port| port.to_string())
            .expect("a number node has a port"),
        _ => String::new(),
    }
}

/// The network kind a row resolves to, with the reference's own inference for an unnamed one.
fn fallback_network(kind: &str, dest: &str) -> Option<FallbackNetwork> {
    if !kind.is_empty() {
        return fallback_named_network(kind, dest);
    }
    if dest == "serve-ws-none" {
        return Some(FallbackNetwork::NotDialable);
    }
    if dest.starts_with('@') || dest.starts_with('/') {
        return fallback_named_network("unix", &pad_abstract(dest));
    }
    if let Ok(port) = dest.parse::<u16>() {
        return fallback_named_network("tcp", &format!("localhost:{port}"));
    }
    // A `host:port` name; anything the parser leaves behind is a dial the reference also fails.
    fallback_named_network("tcp", dest)
}

/// One spelled network kind with its address, in either the unix or the `host:port` family.
fn fallback_named_network(kind: &str, dest: &str) -> Option<FallbackNetwork> {
    if kind == "unix" {
        return Some(FallbackNetwork::Unix { path: dest.into() });
    }
    let (head, family) = match kind.as_bytes() {
        b"tcp" => (b't', 0),
        b"tcp4" => (b't', 4),
        b"tcp6" => (b't', 6),
        b"udp" => (b'u', 0),
        b"udp4" => (b'u', 4),
        b"udp6" => (b'u', 6),
        _ => return Some(FallbackNetwork::NotDialable),
    };
    let (host, port) = fallback_split_host_port(dest)?;
    Some(match head {
        b'u' => FallbackNetwork::Udp { family, host, port },
        _ => FallbackNetwork::Tcp { family, host, port },
    })
}

/// The `host` and `port` of a fallback address; a bracketed IPv6 literal keeps only its
/// interior, the way the reference's splitter hands its dialer an unbracketed host. A shape
/// the reference's dialer cannot split leaves nothing, which refuses at load time.
fn fallback_split_host_port(dest: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(close) = dest.rfind(']') {
        let open = dest[..close].find('[')?;
        let port = dest.get(close + 1..)?.strip_prefix(':')?;
        (dest[open + 1..close].to_owned(), port.to_owned())
    } else {
        let (host, port) = dest.rsplit_once(':')?;
        (host.to_owned(), port.to_owned())
    };
    Some((host, port.parse().ok()?))
}

/// The spell the reference reserves for an abstract unix name on its linuxish builds: an
/// `@@`dest is spelled as the kernel's full `sun_path`, zeros and all, one hundred and eight
/// bytes long, so the name the dialer takes behind the `@` matches the listener's own.
fn pad_abstract(dest: &str) -> String {
    if !dest.starts_with("@@") {
        return dest.into();
    }
    if !cfg!(any(target_os = "linux", target_os = "android")) {
        return dest.into();
    }
    let mut full = vec![0u8; 108];
    let body = &dest.as_bytes()[1..];
    let end = body.len().min(full.len());
    full[..end].copy_from_slice(&body[..end]);
    String::from_utf8_lossy(&full).into_owned()
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

/// Xray fills the eight bytes from the front and zero-pads the tail, so `a8` is `a8 00 ...`, never `00 ... a8`. An empty string is the all-zero short id.
fn short_id(hex: &str) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    if hex.is_empty() {
        return Some(out);
    }
    if hex.len() > 16 || !hex.len().is_multiple_of(2) {
        return None;
    }
    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const B64URL: [u8; 256] = {
    let mut table = [0xff; 256];
    let mut at = 0;
    while at < 26 {
        table[b'A' as usize + at] = at as u8;
        table[b'a' as usize + at] = at as u8 + 26;
        at += 1;
    }
    at = 0;
    while at < 10 {
        table[b'0' as usize + at] = at as u8 + 52;
        at += 1;
    }
    table[b'-' as usize] = 62;
    table[b'_' as usize] = 63;
    table
};

fn key32(text: &str) -> Option<[u8; 32]> {
    let mut word = 0u32;
    let mut bits = 0;
    let mut out = [0u8; 32];
    let mut at = 0;
    for byte in text.bytes() {
        let value = B64URL[byte as usize];
        if value == 0xff {
            return None;
        }
        word = (word << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(at)? = (word >> bits) as u8;
            at += 1;
        }
    }
    (at == 32).then_some(out)
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
    let ech = match ech_server_keys(settings) {
        Ok(keys) => keys,
        Err(why) => {
            eprintln!("ech: {why}; the inbound is refused, not served without it");
            return None;
        }
    };
    let (cert_pem, key_pem) = tls_cert_pem(settings)?;
    let mut identity = ferrox_core::tls::parse_pem_identity(&cert_pem, &key_pem).ok()?;
    identity.ech_server_keys = ech;
    Some(Arc::new(identity))
}

/// xray's certificate lookup: an absolute path is read as itself; a relative path is
/// resolved under `$XRAY_LOCATION_CERT` / `xray.location.cert`, defaulting to the
/// executable's directory, then under the working directory this tree has always served.
pub(crate) fn read_cert_file(path: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(path);
    if path.is_absolute() {
        return std::fs::read(path).ok();
    }
    let location = std::env::var_os("XRAY_LOCATION_CERT")
        .or_else(|| std::env::var_os("xray.location.cert"))
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
        });
    if let Some(bytes) = location.and_then(|dir| std::fs::read(dir.join(path)).ok()) {
        return Some(bytes);
    }
    std::fs::read(path).ok()
}

fn ech_server_keys(settings: &Json) -> Result<Option<Arc<[u8]>>, String> {
    let Some(keys) = settings
        .get("tlsSettings")
        .and_then(|tls| tls.get("echServerKeys"))
    else {
        return Ok(None);
    };
    if matches!(keys, Json::Null)
        || keys.as_arr().is_some_and(<[Json]>::is_empty)
        || keys.as_str() == Some("")
    {
        return Ok(None);
    }
    let Some(text) = keys.as_str() else {
        return Err("echServerKeys is not a string".to_owned());
    };
    ferrox_core::tls::decode_ech_keys(text)
        .map(Arc::from)
        .map(Some)
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
        return Some((read_cert_file(cert_path)?, read_cert_file(key_path)?));
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
        .and_then(read_cert_file)
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

const INVALID_ECH: &[u8] = &[1, 1, 4, 5, 1, 4];

fn tls_ech_config(
    settings: Option<&Json>,
    server_name: &str,
) -> Result<Option<std::sync::Arc<[u8]>>, String> {
    let sockopt = crate::sockopt::parse(
        settings.and_then(|s| s.get("echSockopt").or_else(|| s.get("echSocketSettings"))),
    )?;
    let Some(text) = settings
        .and_then(|s| s.get("echConfigList"))
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
    else {
        return Ok(None);
    };
    match crate::ech_dns::resolve(text, server_name, sockopt.as_ref()) {
        Ok(list) => Ok(Some(list.into())),
        Err(why) => {
            eprintln!("ech: {why}; the dial will fail");
            Ok(Some(INVALID_ECH.into()))
        }
    }
}

/// The ECH config a QUIC dial offers: xray has no QUIC transport, so this reads the TLS field it would have used and hands it to quiche's `BoringSSL` handshake.
pub(crate) fn quic_ech_config(
    outbound: &Json,
    address: &str,
) -> Result<Option<std::sync::Arc<[u8]>>, String> {
    let tls = outbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"));
    let server_name = tls
        .and_then(|s| s.get("serverName"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(address);
    tls_ech_config(tls, server_name)
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

/// The certificate digests a `pinnedPeerCertSha256` names: comma-separated hex, colons
/// stripped for the OpenSSL spelling, every entry exactly the thirty-two bytes a SHA-256 is.
fn cert_pinned_peer_cert_sha256(text: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut pins = Vec::new();
    for entry in text.split(',') {
        let entry = entry.trim().replace(':', "");
        if entry.is_empty() {
            continue;
        }
        let mut pin = [0u8; 32];
        hex_slice(&entry, &mut pin)
            .map_err(|_| format!("pinnedPeerCertSha256 `{text}` is not hex"))?;
        pins.push(pin);
    }
    Ok(pins)
}

/// The big-endian hex of an entry into the caller's slice, the whole text or nothing.
fn hex_slice(text: &str, out: &mut [u8]) -> Result<(), u8> {
    fn nibble(byte: u8) -> Result<u8, u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(byte),
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() != out.len() * 2 {
        return Err(0);
    }
    for (at, slot) in out.iter_mut().enumerate() {
        *slot = nibble(bytes[at * 2])? << 4 | nibble(bytes[at * 2 + 1])?;
    }
    Ok(())
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
    // xray honors `allowInsecure`, so we read the same field and dial the same verdict.
    let insecure = matches!(
        tls.and_then(|s| s.get("allowInsecure")),
        Some(Json::Bool(true))
    );
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
    // The reference pins comma-separated hex, colons stripped, one SHA-256 over a whole certificate; a pin is the whole contract, so no root and no name check follows a leaf pin.
    let cert_pins = tls
        .and_then(|s| s.get("pinnedPeerCertSha256"))
        .and_then(Json::as_str)
        .map(cert_pinned_peer_cert_sha256)
        .transpose()?
        .unwrap_or_default();
    let system_only = !matches!(
        tls.and_then(|s| s.get("disableSystemRoot")),
        Some(Json::Bool(true))
    );
    let roots = tls_ca_roots(outbound).or_else(|| {
        (!insecure && system_only && cert_pins.is_empty())
            .then(crate::quic::system_roots)
            .filter(|r| !r.is_empty())
    });
    let roots = match roots {
        Some(roots) if !roots.is_empty() => roots,
        // The skip verifier reads no anchor, so an insecure dial needs none and loads none; a pin verifier answers from its own pins before any chain question, so it needs none either.
        _ if insecure || !cert_pins.is_empty() => std::sync::Arc::from(Vec::new()),
        _ => {
            return Err(
                "no certificate authorities: no caCertFile and the system roots are empty"
                    .to_owned(),
            )
        }
    };
    let ech_config_list = tls_ech_config(tls, &server_name)?;
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
        cert_pins: std::sync::Arc::from(cert_pins),
        cipher_suites: tls_cipher_suites(tls),
        insecure,
        fingerprint: Some(fingerprint),
        ech_config_list,
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
        public_key: reality
            .get("password")
            .and_then(Json::as_str)
            .filter(|key| !key.is_empty())
            .or_else(|| reality.get("publicKey").and_then(Json::as_str))
            .and_then(key32)?,
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

/// The masquerade cover an inbound hysteria server answers a browser with, read from its `hysteriaSettings`. xray's JSON nests it under `masquerade`; the flat protobuf spellings stay as the second way. Absent, empty, or an unknown type falls back to the plain not-found, so only a configured cover ever changes what a browser sees.
pub(crate) fn masquerade_from_stream(stream: Option<&Json>) -> ferrox_core::hysteria::Masquerade {
    use ferrox_core::hysteria::Masquerade;
    let Some(hy) = stream.and_then(|s| s.get("hysteriaSettings")) else {
        return Masquerade::NotFound;
    };
    let nested = hy.get("masquerade");
    let field = |name: &str, camel: &str, snake: &str| {
        nested
            .and_then(|object| object.get(name))
            .or_else(|| hy.get(camel))
            .or_else(|| hy.get(snake))
    };
    let text =
        |name: &str, camel: &str, snake: &str| field(name, camel, snake).and_then(Json::as_str);
    let flag = |name: &str, camel: &str, snake: &str| {
        field(name, camel, snake)
            .and_then(Json::as_bool)
            .unwrap_or(false)
    };
    let kind = text("type", "masqType", "masq_type").unwrap_or_default();
    if kind.eq_ignore_ascii_case("file") {
        text("dir", "masqFile", "masq_file").map_or(Masquerade::NotFound, |dir| Masquerade::File {
            dir: dir.to_owned(),
        })
    } else if kind.eq_ignore_ascii_case("proxy") {
        text("url", "masqUrl", "masq_url").map_or(Masquerade::NotFound, |url| Masquerade::Proxy {
            url: url.to_owned(),
            rewrite_host: flag("rewriteHost", "masqUrlRewriteHost", "masq_url_rewrite_host"),
            x_forwarded: flag("xForwarded", "masqUrlXForwarded", "masq_url_x_forwarded"),
            insecure: flag("insecure", "masqUrlInsecure", "masq_url_insecure"),
        })
    } else if kind.eq_ignore_ascii_case("string") || kind.eq_ignore_ascii_case("response") {
        let status = field(
            "statusCode",
            "masqStringStatusCode",
            "masq_string_status_code",
        )
        .and_then(Json::as_u32)
        .filter(|code| *code != 0)
        .map_or(200, |code| code as u16);
        let body = text("content", "masqString", "masq_string")
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        let headers =
            masquerade_headers(field("headers", "masqStringHeaders", "masq_string_headers"));
        Masquerade::Response {
            status,
            headers,
            body,
        }
    } else {
        Masquerade::NotFound
    }
}

/// A response's headers in either dialect: xray's object maps names to values, while the flat form carries `Name: value` lines.
fn masquerade_headers(field: Option<&Json>) -> Vec<(String, String)> {
    match field {
        Some(Json::Obj(pairs)) => pairs
            .iter()
            .filter_map(|(name, value)| {
                value.as_str().map(|value| (name.clone(), value.to_owned()))
            })
            .collect(),
        Some(Json::Arr(items)) => items
            .iter()
            .filter_map(Json::as_str)
            .filter_map(header_line)
            .collect(),
        _ => Vec::new(),
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

    fn server_ech_key_tlv() -> Vec<u8> {
        let mut config = vec![0xfe, 0x0d, 0x00, 0x00];
        let mut contents = vec![7u8, 0x00, 0x20, 0x00, 0x20];
        contents.extend_from_slice(&[0x11; 32]);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        contents.push(0);
        contents.push(b"public.test".len() as u8);
        contents.extend_from_slice(b"public.test");
        contents.extend_from_slice(&0u16.to_be_bytes());
        config[2..4].copy_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);
        let mut keys = Vec::new();
        keys.extend_from_slice(&32u16.to_be_bytes());
        keys.extend_from_slice(&[0x22; 32]);
        keys.extend_from_slice(&(config.len() as u16).to_be_bytes());
        keys.extend_from_slice(&config);
        keys
    }

    #[test]
    fn a_short_id_hex_fills_from_the_front() {
        assert_eq!(short_id("a8"), Some([0xa8, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(short_id("01020304"), Some([1, 2, 3, 4, 0, 0, 0, 0]));
        assert_eq!(short_id(""), Some([0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(short_id("abc"), None);
    }

    #[test]
    fn reality_reads_the_references_aliases_and_empty_short_id() {
        let inbound = crate::json::parse(
            r#"{"streamSettings":{"security":"reality","realitySettings":{"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","target":"cover.test:443","shortIds":[""],"serverNames":["www.example.com"]}}}"#,
        )
        .expect("a server");
        let server = inbound_reality_config(&inbound).expect("target and the empty short id");
        assert_eq!(server.dest.as_deref(), Some("cover.test:443"));
        assert_eq!(server.short_ids, vec![[0u8; 8]]);

        let mixed = crate::json::parse(
            r#"{"streamSettings":{"security":"reality","realitySettings":{"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortIds":["","ab"],"serverNames":["www.example.com"]}}}"#,
        )
        .expect("a server with two short ids");
        assert_eq!(
            inbound_reality_config(&mixed)
                .expect("both short ids")
                .short_ids,
            vec![[0u8; 8], [0xab, 0, 0, 0, 0, 0, 0, 0]]
        );

        let outbound = crate::json::parse(
            r#"{"streamSettings":{"security":"reality","realitySettings":{"publicKey":"","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","serverName":"www.example.com","shortId":""}}}"#,
        )
        .expect("a client");
        let client =
            outbound_reality(&outbound, "127.0.0.1").expect("password and the empty short id");
        assert_eq!(client.short_id, [0u8; 8]);

        let (key, counts) = ferrox_core::alloc_count::measure(|| {
            key32("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        });
        assert_eq!(key, Some([0u8; 32]));
        assert_eq!(counts.allocs, 0, "the key is decoded into its array");
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
    fn a_hysteria_masquerade_reads_its_nested_json_object() {
        use ferrox_core::hysteria::Masquerade;
        let read = |json: &str| {
            let root = crate::json::parse(json).expect("parses");
            masquerade_from_stream(root.get("streamSettings"))
        };
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masquerade": {"type": "FILE", "dir": "/var/www/cover"}}}}"#
            ),
            Masquerade::File {
                dir: "/var/www/cover".to_owned()
            }
        );
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masquerade": {"type": "proxy", "url": "https://origin.example", "rewriteHost": true, "xForwarded": true, "insecure": true}}}}"#
            ),
            Masquerade::Proxy {
                url: "https://origin.example".to_owned(),
                rewrite_host: true,
                x_forwarded: true,
                insecure: true,
            }
        );
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masquerade": {"type": "string", "content": "<html>cover</html>", "headers": {"content-type": "text/html", "x-frame-options": "DENY"}, "statusCode": 418}}}}"#
            ),
            Masquerade::Response {
                status: 418,
                headers: vec![
                    ("content-type".to_owned(), "text/html".to_owned()),
                    ("x-frame-options".to_owned(), "DENY".to_owned()),
                ],
                body: b"<html>cover</html>".to_vec(),
            }
        );
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masqType": "file", "masqFile": "/tmp/cover"}}}"#
            ),
            Masquerade::File {
                dir: "/tmp/cover".to_owned()
            }
        );
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
    fn a_relative_certificate_resolves_under_xray_location_cert() {
        static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let minted = rcgen::generate_simple_self_signed(vec!["cert-location.test".to_owned()])
            .expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-cert-location-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        let cert = format!("cert-location-{stamp}.pem");
        let key = format!("key-location-{stamp}.pem");
        std::fs::write(dir.join(&cert), minted.cert.pem()).expect("cert");
        std::fs::write(dir.join(&key), minted.signing_key.serialize_pem()).expect("key");
        let previous = std::env::var_os("XRAY_LOCATION_CERT");
        std::env::set_var("XRAY_LOCATION_CERT", &dir);
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificateFile": "{cert}", "keyFile": "{key}"}}]}}}}}}"#
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&config);
        match previous {
            Some(value) => std::env::set_var("XRAY_LOCATION_CERT", value),
            None => std::env::remove_var("XRAY_LOCATION_CERT"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            identity.is_some(),
            "a relative certificateFile must resolve under XRAY_LOCATION_CERT"
        );
    }

    #[test]
    fn inbound_tls_identity_reads_an_inline_certificate() {
        use base64::Engine as _;
        let minted =
            rcgen::generate_simple_self_signed(vec!["tls.test".to_owned()]).expect("mints");
        let keys = server_ech_key_tlv();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&keys);
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
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"echServerKeys": "{encoded}", "certificates": [{{"certificate": {}, "key": {}}}]}}}}}}"#,
            string_json(&minted.cert.pem()),
            string_json(&minted.signing_key.serialize_pem())
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&string_form).expect("an inline string loads too");
        assert_eq!(
            identity.ech_server_keys.as_deref(),
            Some(keys.as_slice()),
            "the inbound carries the parsed ECH keys into its TLS identity"
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

    #[test]
    fn a_base64_ech_config_is_normalized_and_a_bad_one_fails_closed() {
        use base64::Engine as _;
        let list = {
            let mut contents = vec![7u8, 0x00, 0x20, 0x00, 0x20];
            contents.extend_from_slice(&[0x11; 32]);
            contents.extend_from_slice(&4u16.to_be_bytes());
            contents.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            contents.push(0);
            contents.push(b"public.test".len() as u8);
            contents.extend_from_slice(b"public.test");
            contents.extend_from_slice(&0u16.to_be_bytes());
            let mut config = vec![0xfe, 0x0d];
            config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
            config.extend_from_slice(&contents);
            let mut list = Vec::new();
            list.extend_from_slice(&(config.len() as u16).to_be_bytes());
            list.extend_from_slice(&config);
            list
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(&list);
        let settings =
            crate::json::parse(&format!(r#"{{"echConfigList":"{encoded}"}}"#)).expect("parses");
        let got = tls_ech_config(Some(&settings), "hidden.test")
            .expect("resolves")
            .expect("present");
        assert_eq!(got.as_ref(), list.as_slice());

        let malformed = crate::json::parse(r#"{"echConfigList":"not base64"}"#).expect("parses");
        let got = tls_ech_config(Some(&malformed), "hidden.test")
            .expect("fails closed")
            .expect("present");
        assert_eq!(got.as_ref(), [1, 1, 4, 5, 1, 4]);
    }

    #[test]
    fn ech_sockopt_is_read_under_xray_key_and_bad_options_refuse() {
        let settings = crate::json::parse(
            r#"{"echConfigList":"not base64","echSockopt":{"domainStrategy":"useipv4"}}"#,
        )
        .expect("parses");
        assert!(tls_ech_config(Some(&settings), "hidden.test")
            .expect("options parse")
            .is_some());

        let alias = crate::json::parse(
            r#"{"echConfigList":"not base64","echSocketSettings":{"tcpFastOpen":true}}"#,
        )
        .expect("parses");
        assert!(tls_ech_config(Some(&alias), "hidden.test")
            .expect("options parse")
            .is_some());

        let bad = crate::json::parse(
            r#"{"echConfigList":"not base64","echSockopt":{"domainStrategy":"nearest"}}"#,
        )
        .expect("parses");
        let error = tls_ech_config(Some(&bad), "hidden.test").expect_err("refuses");
        assert!(error.contains("domainStrategy"), "{error}");
    }

    #[test]
    fn a_quic_outbound_reads_the_ech_list_from_its_tls_settings() {
        let outbound = crate::json::parse(
            r#"{"streamSettings":{"network":"quic","security":"tls",
                "tlsSettings":{"echConfigList":"not base64"}}}"#,
        )
        .expect("parses");
        let got = quic_ech_config(&outbound, "hidden.test")
            .expect("parses options")
            .expect("names a list");
        assert_eq!(got.as_ref(), [1, 1, 4, 5, 1, 4]);
        let absent = crate::json::parse(
            r#"{"streamSettings":{"network":"quic","security":"tls","tlsSettings":{}}}"#,
        )
        .expect("parses");
        assert!(quic_ech_config(&absent, "hidden.test")
            .expect("parses options")
            .is_none());
    }

    #[test]
    fn server_side_ech_keys_are_parsed_and_malformed_forms_refused() {
        use base64::Engine as _;
        let keys = server_ech_key_tlv();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&keys);
        let with_keys = crate::json::parse(&format!(
            r#"{{"streamSettings":{{"tlsSettings":{{"echServerKeys":"{encoded}"}}}}}}"#
        ))
        .expect("parses");
        assert!(
            ech_server_keys(with_keys.get("streamSettings").expect("settings"))
                .expect("parses")
                .is_some()
        );
        let empty =
            crate::json::parse(r#"{"streamSettings":{"tlsSettings":{"echServerKeys":[]}}}"#)
                .expect("parses");
        assert!(
            ech_server_keys(empty.get("streamSettings").expect("settings"))
                .expect("empty is unset")
                .is_none()
        );
        let array =
            crate::json::parse(r#"{"streamSettings":{"tlsSettings":{"echServerKeys":["AAAA"]}}}"#)
                .expect("parses");
        assert!(
            ech_server_keys(array.get("streamSettings").expect("settings")).is_err(),
            "xray names a string, so an array is refused by name"
        );
        let malformed =
            crate::json::parse(r#"{"streamSettings":{"tlsSettings":{"echServerKeys":"not TLV"}}}"#)
                .expect("parses");
        assert!(
            ech_server_keys(malformed.get("streamSettings").expect("settings")).is_err(),
            "a string that is not a server-key TLV refuses the inbound"
        );
    }

    /// One inbound as the dialect names it, with the `settings` object spelled the loader reads.
    fn vless_settings(text: &str) -> Json {
        crate::json::parse(&format!(r#"{{"protocol":"vless","settings":{text}}}"#)).expect("parses")
    }

    /// The rows a settings object carries, spelled `{"decryption":"none","fallbacks":[…]}`.
    fn fallback_rows(text: &str) -> Vec<Fallback> {
        server_fallbacks(&vless_settings(&format!(
            r#"{{"decryption":"none","fallbacks":[{text}]}}"#
        )))
        .expect("serves")
        .expect("the rows the dialect carries")
    }

    #[test]
    fn the_fallback_verdicts_are_the_reference_s_own() {
        assert_eq!(
            fallback_rows(r#"{"dest":"127.0.0.1:8080"}"#).len(),
            1,
            "an unnamed decryption carries the rows it spells"
        );

        assert_eq!(
            server_fallbacks(&vless_settings(r#"{"decryption":""}"#)).expect_err("empty"),
            r#"VLESS settings: please add/set "decryption":"none" to every settings"#
        );
        assert_eq!(
            server_fallbacks(&vless_settings(r#"{"decryption":"always"}"#)).expect_err("engine"),
            r#"VLESS settings: unsupported "decryption": always"#
        );

        // Rows beside `none` serve; beside an engine they refuse on the first line.
        assert_eq!(
            fallback_rows(r#"{"dest":"127.0.0.1:8080"}"#).len(),
            1,
            "none carries the rows it names"
        );
        assert_eq!(
            server_fallbacks(&vless_settings(
                r#"{"decryption":"always","fallbacks":[{"dest":"192.0.2.1:80"}]}"#
            ))
            .expect_err("engine"),
            r#"VLESS settings: unsupported "decryption": always"#
        );

        let path = r#"{"dest":"127.0.0.1:8080","path":"no"}"#;
        assert_eq!(
            server_fallbacks(&vless_settings(&format!(r#"{{"fallbacks":[{path}]}}"#)))
                .expect_err("path"),
            r#"VLESS fallbacks: "path" must be empty or start with "/""#
        );

        let tiny = r#"{"dest":"8080","xver":3}"#;
        assert_eq!(
            server_fallbacks(&vless_settings(&format!(r#"{{"fallbacks":[{tiny}]}}"#)))
                .expect_err("xver"),
            r#"VLESS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2"#
        );

        let unspelled = r#"{"dest":"not a dest"}"#;
        assert_eq!(
            server_fallbacks(&vless_settings(&format!(
                r#"{{"fallbacks":[{unspelled}]}}"#
            )))
            .expect_err("dest"),
            r#"VLESS fallbacks: please fill in a valid value for every "dest""#
        );
    }

    #[test]
    fn the_fallback_dials_are_inferred_the_reference_s_way() {
        let unnamed = fallback_rows(r#"{"dest":"8080"}"#);
        assert!(
            matches!(
                &unnamed[0].network,
                FallbackNetwork::Tcp { family: 0, host, port } if host == "localhost" && *port == 8080
            ),
            "a bare port dials localhost"
        );
        assert!(
            matches!(
                fallback_rows(r#"{"dest":"[::1]:80","xver":1}"#)[0].network,
                FallbackNetwork::Tcp { family: 0, .. }
            ),
            "a bracketed literal keeps the same unbracketed dialer"
        );
        assert!(matches!(
            fallback_rows(r#"{"dest":"/tmp/app.sock"}"#)[0].network,
            FallbackNetwork::Unix { .. }
        ));
        assert!(matches!(
            fallback_rows(r#"{"dest":"@abs"}"#)[0].network,
            FallbackNetwork::Unix { .. }
        ));
        assert_eq!(
            server_fallbacks(&vless_settings(
                r#"{"fallbacks":[{"dest":"@abs","type":"tcp"}]}"#
            ))
            .expect_err("named tcp with an abstract name"),
            r#"VLESS fallbacks: please fill in a valid value for every "dest""#
        );
        assert!(matches!(
            fallback_rows(r#"{"dest":"serve-ws-none"}"#)[0].network,
            FallbackNetwork::NotDialable
        ));

        // The named kinds keep the family the spelling selects, `serve` included.
        for (kind, family, head) in [
            ("tcp6", 6u8, "2001:db8::1"),
            ("udp", 0u8, "127.0.0.1"),
            ("udp4", 4u8, "127.0.0.1"),
        ] {
            let rows = fallback_rows(&format!(r#"{{"dest":"{head}:8080","type":"{kind}"}}"#));
            let network = rows[0].network.clone();
            match &network {
                FallbackNetwork::Udp {
                    family: got, host, ..
                }
                | FallbackNetwork::Tcp {
                    family: got, host, ..
                } => {
                    assert_eq!(*got, family);
                    assert_eq!(host, head);
                }
                other => panic!("{other:?} is not the dial `{kind}` spells"),
            }
        }
        assert!(
            matches!(
                fallback_rows(r#"{"type":"serve","dest":"x"}"#)[0].network,
                FallbackNetwork::NotDialable
            ),
            "an unknown kind keeps the row, the dialer refusing every round"
        );
    }

    #[test]
    fn the_fallback_route_walks_the_reference_s_table() {
        let rows = fallback_rows(
            r#"
            {"dest":"127.0.0.1:1"},
            {"name":"apple","dest":"127.0.0.1:2"},
            {"name":"www.apple.com","dest":"127.0.0.1:3"},
            {"name":"web","alpn":"h2","dest":"127.0.0.1:4"},
            {"name":"web","alpn":"","path":"/api","dest":"127.0.0.1:5"},
            {"name":"web","alpn":"","dest":"127.0.0.1:6"}"#,
        );
        let dial = |picked: Option<&Fallback>| {
            picked.and_then(|row| match &row.network {
                FallbackNetwork::Tcp { port, .. } => Some(*port),
                _ => None,
            })
        };
        // The front without a name dials the unnamed row.
        assert_eq!(
            dial(Fallback::route(&rows, "", "", b"GET / HTTP/1.1")),
            Some(1)
        );

        // A name the table contains routes to the tightest spelling of it.
        assert_eq!(
            dial(Fallback::route(
                &rows,
                "www.apple.com",
                "",
                b"GET / HTTP/1.1"
            )),
            Some(3)
        );
        assert_eq!(
            dial(Fallback::route(&rows, "apple", "", b"GET / HTTP/1.1")),
            Some(2)
        );
        assert_eq!(
            dial(Fallback::route(&rows, "front.dev", "", b"GET / HTTP/1.1")),
            Some(1),
            "a name nothing in the table contains shares the unnamed cell"
        );

        // An alpn the exact cell spells beats the empty one.
        assert_eq!(
            dial(Fallback::route(&rows, "web", "h2", b"GET / HTTP/1.1")),
            Some(4)
        );

        // The first request line's path picks inside the empty-alpn cell, and the front's alpn falls to the group's `""` map the way the reference reads one.
        assert_eq!(
            dial(Fallback::route(
                &rows,
                "web",
                "http/1.1",
                b"GET /api?q=1 HTTP/1.1"
            )),
            Some(5)
        );
        assert_eq!(
            dial(Fallback::route(&rows, "web", "http/1.1", b"GET / HTTP/1.1")),
            Some(6)
        );

        // A group that spells neither the front's alpn nor `""` leaves the flow unserved.
        let only_h2 = fallback_rows(r#"{"name":"web","alpn":"h2","dest":"127.0.0.1:7"}"#);
        assert_eq!(
            dial(Fallback::route(
                &only_h2,
                "web",
                "http/1.1",
                b"GET / HTTP/1.1"
            )),
            None
        );
    }
}
