//! The lane config the binary is handed. One writer for every outbound, so a
//! share link, an account and a verbatim file all reach the engine the same way.

use std::net::TcpListener;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::args::{Options, Outbound};
use crate::paths::{read_trim, write_private, Paths};

#[derive(Clone, Copy, Debug)]
pub struct Ports {
    pub socks: u16,
    pub http: u16,
    pub mixed: u16,
}

#[derive(Clone, Debug)]
pub struct FoxyAccount {
    pub email: String,
    pub password: String,
}

pub fn fronts(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|front| !front.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn port_of(front: &str, ports: Ports) -> u16 {
    match front {
        "socks" => ports.socks,
        "mixed" => ports.mixed,
        _ => ports.http,
    }
}

fn split_host_port(value: &str, flag: &str) -> Result<(String, u64), String> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(format!("--{flag} wants HOST:PORT, got '{value}'"));
    };
    if host.is_empty() || port.is_empty() {
        return Err(format!("--{flag} wants HOST:PORT, got '{value}'"));
    }
    let port: u64 = port
        .parse()
        .map_err(|_| format!("--{flag} wants HOST:PORT, got '{value}'"))?;
    if port == 0 || port > 65535 {
        return Err(format!(
            "--{flag} wants a port between 1 and 65535, got '{value}'"
        ));
    }
    Ok((host.to_owned(), port))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn split_domains(raw: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for item in raw.split(',') {
        let mut name = item.trim().to_lowercase().trim_end_matches('.').to_owned();
        if let Some(stripped) = name.strip_prefix("*.") {
            name = stripped.to_owned();
        }
        if let Some(stripped) = name.strip_prefix('.') {
            name = stripped.to_owned();
        }
        if name.is_empty() {
            continue;
        }
        if name.contains('/')
            || name.contains(':')
            || name.contains('*')
            || name.contains("..")
            || name.starts_with('.')
            || name.chars().any(char::is_whitespace)
        {
            return Err(format!(
                "--exclude-domains wants domain suffixes like example.com, got '{}'; nothing was started.",
                item.trim()
            ));
        }
        names.push(name);
    }
    if names.is_empty() {
        return Err(
            "--exclude-domains wants at least one domain suffix; nothing was started.".to_owned(),
        );
    }
    Ok(names)
}

fn split_ports(raw: &str) -> Result<Vec<u16>, String> {
    let mut numbers = Vec::new();
    for item in raw.split(',') {
        let value = item.trim();
        if value.is_empty() {
            continue;
        }
        let Ok(port) = value.parse::<u32>() else {
            return Err(format!(
                "--exclude-ports wants ports 1-65535, got '{value}'; nothing was started."
            ));
        };
        if port == 0 || port > 65535 {
            return Err(format!(
                "--exclude-ports wants ports 1-65535, got '{value}'; nothing was started."
            ));
        }
        numbers.push(port as u16);
    }
    if numbers.is_empty() {
        return Err("--exclude-ports wants at least one port; nothing was started.".to_owned());
    }
    Ok(numbers)
}

pub fn effective_region(options: &Options) -> String {
    let region = if options.region.is_empty() && options.country_set {
        options.country.clone()
    } else {
        options.region.clone()
    };
    region.to_lowercase()
}

pub fn stable_udid(options: &Options, paths: &Paths) -> Result<String, String> {
    if !options.veepn_udid.is_empty() {
        return Ok(options.veepn_udid.clone());
    }
    let file = paths.conf_dir.join("veepn.udid");
    if let Some(value) = read_trim(&file).filter(|value| !value.is_empty()) {
        return Ok(value);
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| format!("cannot mint a device id: {error}"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    );
    write_private(&file, &format!("{value}\n"))
        .map_err(|error| format!("cannot save the device id: {error}"))?;
    Ok(value)
}

pub fn load_foxy_location(options: &mut Options, paths: &Paths) {
    if options.country_set {
        return;
    }
    let Some(line) = read_trim(&paths.location_file) else {
        return;
    };
    let mut parts = line.split_whitespace();
    let Some(country) = parts.next() else {
        return;
    };
    options.country = country.to_uppercase();
    if !options.city_set {
        if let Some(city) = parts.next() {
            options.city = city.to_uppercase();
        }
    }
}

pub fn save_foxy_location(options: &Options, paths: &Paths) -> Result<(), String> {
    if options.country.is_empty() {
        return Ok(());
    }
    write_private(
        &paths.location_file,
        &format!(
            "{} {}\n",
            options.country.to_uppercase(),
            options.city.to_uppercase()
        ),
    )
    .map_err(|error| format!("cannot remember the exit: {error}"))
}

pub fn remembered_country(paths: &Paths) -> String {
    read_trim(&paths.location_file)
        .and_then(|line| line.split_whitespace().next().map(str::to_owned))
        .unwrap_or_default()
}

pub fn remembered_city(paths: &Paths) -> String {
    read_trim(&paths.location_file)
        .and_then(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .unwrap_or_default()
}

pub fn build_outbound(
    options: &Options,
    paths: &Paths,
    account: Option<&FoxyAccount>,
) -> Result<Value, String> {
    match options.outbound {
        Some(Outbound::Foxy) => foxy_outbound(options, paths, account),
        Some(Outbound::Veepn) => veepn_outbound(options, paths),
        Some(Outbound::Vless) => vless_outbound(&options.vless),
        Some(Outbound::Vmess) => vmess_outbound(options),
        Some(Outbound::Trojan) => trojan_outbound(options),
        Some(Outbound::Ss) => ss_outbound(options),
        Some(Outbound::Config) | None => Err("no outbound chosen".to_owned()),
    }
}

fn foxy_outbound(
    options: &Options,
    paths: &Paths,
    account: Option<&FoxyAccount>,
) -> Result<Value, String> {
    let Some(account) = account else {
        return Err("no foxy account: run 'ferrox-cli login' first".to_owned());
    };
    let mut settings = Map::new();
    settings.insert("email".to_owned(), json!(account.email));
    settings.insert("password".to_owned(), json!(account.password));
    settings.insert("country".to_owned(), json!(options.country.to_uppercase()));
    settings.insert("carrier".to_owned(), json!(options.carrier));
    if !paths.token_file.as_os_str().is_empty() {
        settings.insert(
            "tokenFile".to_owned(),
            json!(paths.token_file.to_string_lossy()),
        );
    }
    if !options.city.is_empty() {
        settings.insert("city".to_owned(), json!(options.city.to_uppercase()));
    }
    if !options.upstream.is_empty() {
        settings.insert("upstreamProxy".to_owned(), json!(options.upstream));
    }
    if !options.code.is_empty() {
        settings.insert("code".to_owned(), json!(options.code));
    }
    if !options.exclude_domains.is_empty() {
        settings.insert(
            "directDomains".to_owned(),
            json!(split_domains(&options.exclude_domains)?),
        );
    }
    if !options.exclude_ports.is_empty() {
        settings.insert(
            "directPorts".to_owned(),
            json!(split_ports(&options.exclude_ports)?),
        );
    }
    Ok(json!({"protocol": "foxy", "settings": settings}))
}

fn veepn_outbound(options: &Options, paths: &Paths) -> Result<Value, String> {
    let mut settings = Map::new();
    let region = effective_region(options);
    if !region.is_empty() {
        settings.insert("region".to_owned(), json!(region));
    }
    let listed: Vec<String> = options
        .veepn_domains
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect();
    if !listed.is_empty() {
        settings.insert("domains".to_owned(), json!(listed));
    }
    let udid = stable_udid(options, paths)?;
    if !udid.is_empty() {
        settings.insert("udid".to_owned(), json!(udid));
    }
    Ok(json!({"protocol": "veepn", "settings": settings}))
}

fn vless_outbound(link: &str) -> Result<Value, String> {
    if !link.starts_with("vless://") {
        return Err(format!(
            "--vless wants a vless:// share link, got '{link}'; nothing was started.\n  example: ferrox-cli up --vless 'vless://uuid@host:443?type=ws&security=tls&sni=host&path=/ws'"
        ));
    }
    let body = &link["vless://".len()..];
    let body = body.split('#').next().unwrap_or(body);
    let (body, query) = body.split_once('?').unwrap_or((body, ""));
    let (uuid, hostport) = body
        .rsplit_once('@')
        .ok_or_else(|| "a vless link is vless://{uuid}@{host}:{port}?{query}".to_owned())?;
    if uuid.is_empty() || hostport.is_empty() {
        return Err("a vless link is vless://{uuid}@{host}:{port}?{query}".to_owned());
    }
    let (host, port) = split_host_port(hostport, "vless")?;

    let mut params: Map<String, Value> = Map::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        params.insert(percent_decode(key), json!(percent_decode(value)));
    }
    let get = |name: &str| {
        params
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };

    let kind = {
        let value = get("type").to_lowercase();
        if value.is_empty() {
            "tcp".to_owned()
        } else {
            value
        }
    };
    let security = {
        let value = get("security").to_lowercase();
        if value.is_empty() {
            "none".to_owned()
        } else {
            value
        }
    };
    let sni = if get("sni").is_empty() {
        get("peer")
    } else {
        get("sni")
    };
    let host_header = get("host");
    let path = get("path");
    let service = get("serviceName");
    let mode = get("mode");
    let flow = get("flow");

    let mut stream = Map::new();
    stream.insert(
        "network".to_owned(),
        json!(if kind == "raw" { "tcp" } else { kind.as_str() }),
    );
    match kind.as_str() {
        "ws" | "websocket" => {
            let mut ws = Map::new();
            ws.insert(
                "path".to_owned(),
                json!(if path.is_empty() { "/" } else { path.as_str() }),
            );
            if !host_header.is_empty() {
                ws.insert("headers".to_owned(), json!({"Host": host_header}));
            }
            stream.insert("wsSettings".to_owned(), Value::Object(ws));
        }
        "grpc" => {
            stream.insert("grpcSettings".to_owned(), json!({"serviceName": service}));
        }
        "httpupgrade" => {
            let mut settings = Map::new();
            settings.insert(
                "path".to_owned(),
                json!(if path.is_empty() { "/" } else { path.as_str() }),
            );
            if !host_header.is_empty() {
                settings.insert("host".to_owned(), json!(host_header));
            }
            stream.insert("httpupgradeSettings".to_owned(), Value::Object(settings));
        }
        "xhttp" => {
            let mut settings = Map::new();
            settings.insert(
                "path".to_owned(),
                json!(if path.is_empty() { "/" } else { path.as_str() }),
            );
            if !host_header.is_empty() {
                settings.insert("host".to_owned(), json!(host_header));
            }
            if !mode.is_empty() {
                settings.insert("mode".to_owned(), json!(mode));
            }
            stream.insert("xhttpSettings".to_owned(), Value::Object(settings));
        }
        "tcp" | "raw" => {}
        other => {
            return Err(format!(
                "`{other}` needs --config: this converter writes tcp, ws, grpc, httpupgrade and xhttp"
            ));
        }
    }

    match security.as_str() {
        "tls" => {
            let mut tls = Map::new();
            tls.insert(
                "serverName".to_owned(),
                json!(if sni.is_empty() {
                    host.as_str()
                } else {
                    sni.as_str()
                }),
            );
            tls.insert("allowInsecure".to_owned(), json!(false));
            if !get("fp").is_empty() {
                tls.insert("fingerprint".to_owned(), json!(get("fp")));
            }
            if !get("alpn").is_empty() {
                tls.insert(
                    "alpn".to_owned(),
                    json!(get("alpn").split(',').collect::<Vec<_>>()),
                );
            }
            stream.insert("security".to_owned(), json!("tls"));
            stream.insert("tlsSettings".to_owned(), Value::Object(tls));
        }
        "reality" => {
            if get("pbk").is_empty() {
                return Err("a reality link without `pbk` names no server key".to_owned());
            }
            let mut reality = Map::new();
            reality.insert(
                "serverName".to_owned(),
                json!(if sni.is_empty() {
                    host.as_str()
                } else {
                    sni.as_str()
                }),
            );
            reality.insert("publicKey".to_owned(), json!(get("pbk")));
            if !get("sid").is_empty() {
                reality.insert("shortId".to_owned(), json!(get("sid")));
            }
            if !get("fp").is_empty() {
                reality.insert("fingerprint".to_owned(), json!(get("fp")));
            }
            if !get("spx").is_empty() {
                reality.insert("spiderX".to_owned(), json!(get("spx")));
            }
            stream.insert("security".to_owned(), json!("reality"));
            stream.insert("realitySettings".to_owned(), Value::Object(reality));
        }
        "none" | "" => {
            stream.insert("security".to_owned(), json!("none"));
        }
        other => {
            return Err(format!("security `{other}` needs --config"));
        }
    }

    let mut user = Map::new();
    user.insert("id".to_owned(), json!(uuid));
    user.insert("encryption".to_owned(), json!("none"));
    if !flow.is_empty() && flow != "none" {
        user.insert("flow".to_owned(), json!(flow));
    }
    Ok(json!({
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [Value::Object(user)]}]},
        "streamSettings": Value::Object(stream),
    }))
}

fn vmess_outbound(options: &Options) -> Result<Value, String> {
    let (host, port) = split_host_port(&options.vmess, "vmess")?;
    if options.vmess_id.is_empty() {
        return Err(
            "--vmess needs --uuid ID as well, e.g. ferrox-cli up --vmess host:443 --uuid UUID"
                .to_owned(),
        );
    }
    Ok(json!({
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port,
            "users": [{"id": options.vmess_id, "security": "auto"}]}]},
        "streamSettings": {"network": if options.vmess_network.is_empty() { "tcp" } else { options.vmess_network.as_str() }},
    }))
}

fn trojan_outbound(options: &Options) -> Result<Value, String> {
    let (host, port) = split_host_port(&options.trojan, "trojan")?;
    if options.password.is_empty() {
        return Err(
            "--trojan needs --password PW as well, e.g. ferrox-cli up --trojan host:443 --password PW"
                .to_owned(),
        );
    }
    Ok(json!({
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": options.password}]},
    }))
}

fn ss_outbound(options: &Options) -> Result<Value, String> {
    let (host, port) = split_host_port(&options.ss, "ss")?;
    if options.password.is_empty() {
        return Err(
            "--ss needs --password PW as well, e.g. ferrox-cli up --ss host:8388 --password PW"
                .to_owned(),
        );
    }
    Ok(json!({
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port,
            "method": options.ss_method, "password": options.password}]},
    }))
}

pub fn write_config(
    path: &Path,
    outbound: &Value,
    fronts: &str,
    ports: Ports,
) -> Result<(), String> {
    let mut inbounds = Vec::new();
    for front in self::fronts(fronts) {
        let port = match front.as_str() {
            "socks" => ports.socks,
            "http" => ports.http,
            "mixed" => ports.mixed,
            other => return Err(format!("unknown front `{other}`: socks, http, mixed")),
        };
        inbounds.push(json!({"protocol": front, "listen": "127.0.0.1", "port": port}));
    }
    let document = json!({"inbounds": inbounds, "outbounds": [outbound.clone()]});
    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("cannot encode the config: {error}"))?;
    write_private(path, &format!("{text}\n"))
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn adopted_ports(path: &Path, fronts: &[String], fixed: &mut [bool], ports: &mut Ports) {
    let Some(text) = read_trim(path) else {
        return;
    };
    let Ok(document) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    let Some(inbounds) = document.get("inbounds").and_then(Value::as_array) else {
        return;
    };
    let names = ["socks", "http", "mixed"];
    let mut adopted: Vec<&str> = Vec::new();
    for inbound in inbounds {
        let Some(name) = inbound.get("protocol").and_then(Value::as_str) else {
            continue;
        };
        let Some(index) = names.iter().position(|candidate| *candidate == name) else {
            continue;
        };
        if !fronts.iter().any(|front| front == name)
            || fixed[index]
            || adopted.contains(&names[index])
        {
            continue;
        }
        let Some(port) = inbound.get("port").and_then(Value::as_u64) else {
            continue;
        };
        let Ok(port) = u16::try_from(port) else {
            continue;
        };
        match index {
            0 => ports.socks = port,
            1 => ports.http = port,
            _ => ports.mixed = port,
        }
        fixed[index] = true;
        adopted.push(names[index]);
    }
}

fn free_port(start: u16, taken: &[u16]) -> u16 {
    for port in start..=u16::MAX {
        if !taken.contains(&port) && TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    start
}

pub fn plan_ports(options: &Options, paths: &Paths, scan: bool) -> Ports {
    let mut ports = Ports {
        socks: options.socks,
        http: options.http,
        mixed: options.mixed,
    };
    let fronts = fronts(&options.fronts);
    let mut fixed = [options.socks_set, options.http_set, options.mixed_set];
    if paths.cfg.exists() {
        adopted_ports(&paths.cfg, &fronts, &mut fixed, &mut ports);
    }
    let mut taken: Vec<u16> = Vec::new();
    let names = ["socks", "http", "mixed"];
    let values = [ports.socks, ports.http, ports.mixed];
    for (index, name) in names.iter().enumerate() {
        if fronts.iter().any(|front| front == name) && fixed[index] {
            taken.push(values[index]);
        }
    }
    if scan {
        for (index, name) in names.iter().enumerate() {
            if !fronts.iter().any(|front| front == name) || fixed[index] {
                continue;
            }
            let value = match index {
                0 => ports.socks,
                1 => ports.http,
                _ => ports.mixed,
            };
            let port = free_port(value, &taken);
            match index {
                0 => ports.socks = port,
                1 => ports.http = port,
                _ => ports.mixed = port,
            }
            taken.push(port);
        }
    }
    ports
}

pub fn config_fronts(
    path: &str,
    vpn: bool,
    fronts_set: bool,
    asked: &str,
) -> Result<String, String> {
    let text = read_trim(Path::new(path)).ok_or_else(|| format!("cannot read config {path}"))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(|error| format!("cannot read config {path}: {error}"))?;
    let mut order: Vec<String> = Vec::new();
    if let Some(inbounds) = document.get("inbounds").and_then(Value::as_array) {
        for inbound in inbounds {
            let Some(name) = inbound.get("protocol").and_then(Value::as_str) else {
                continue;
            };
            if !matches!(name, "socks" | "http" | "mixed") {
                continue;
            }
            let Some(port) = inbound.get("port").and_then(Value::as_u64) else {
                return Err(format!("inbound `{name}` has no port in 1-65535"));
            };
            if port == 0 || port > 65535 {
                return Err(format!("inbound `{name}` has no port in 1-65535"));
            }
            if !order.iter().any(|front| front == name) {
                order.push(name.to_owned());
            }
        }
    }
    if fronts_set {
        let wanted = fronts(asked);
        for front in &wanted {
            if !order.contains(front) {
                return Err(format!(
                    "the config serves no {front} inbound; --fronts names it"
                ));
            }
        }
        order.retain(|front| wanted.contains(front));
    }
    if vpn {
        if order.is_empty() {
            return Err(
                "the config serves no socks, http or mixed inbound; --vpn needs one".to_owned(),
            );
        }
        let mut checked: Vec<String> = Vec::new();
        if let Some(inbounds) = document.get("inbounds").and_then(Value::as_array) {
            for inbound in inbounds {
                let Some(name) = inbound.get("protocol").and_then(Value::as_str) else {
                    continue;
                };
                if !order.iter().any(|front| front == name) || checked.iter().any(|c| c == name) {
                    continue;
                }
                checked.push(name.to_owned());
                let listen = inbound.get("listen").and_then(Value::as_str);
                let loopback = listen.is_some_and(|listen| {
                    listen == "::1" || listen == "localhost" || listen.starts_with("127.")
                });
                if !loopback {
                    return Err(format!(
                        "inbound `{name}` listens on {}, not loopback; --vpn needs 127.0.0.1 or ::1",
                        listen.unwrap_or("all interfaces")
                    ));
                }
            }
        }
    }
    Ok(order.join(","))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrox-cli-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |span| span.subsec_nanos())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn options() -> Options {
        Options {
            fronts: "socks,http,mixed".to_owned(),
            fronts_set: false,
            socks: 10808,
            http: 8080,
            mixed: 10809,
            socks_set: false,
            http_set: false,
            mixed_set: false,
            ..Options::default()
        }
    }

    #[test]
    fn fronts_trims_and_drops_empty_entries() {
        assert_eq!(fronts(" socks, ,http , mixed"), ["socks", "http", "mixed"]);
        assert_eq!(fronts(" , "), Vec::<String>::new());
    }

    #[test]
    fn ports_follow_the_front_name() {
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        assert_eq!(port_of("socks", ports), 1);
        assert_eq!(port_of("http", ports), 2);
        assert_eq!(port_of("mixed", ports), 3);
    }

    #[test]
    fn exclude_domains_normalize_star_and_dot() {
        assert_eq!(
            split_domains("*.Example.COM., .lan, printer").unwrap(),
            ["example.com", "lan", "printer"]
        );
    }

    #[test]
    fn exclude_domains_refuse_the_shapes_a_suffix_cannot_be() {
        assert!(split_domains("a/b").is_err());
        assert!(split_domains("a:1").is_err());
        assert!(split_domains("*.example..com").is_err());
        assert!(split_domains(" , ").is_err());
    }

    #[test]
    fn exclude_ports_refuse_zero_and_overflow() {
        assert_eq!(split_ports("22, 443").unwrap(), [22, 443]);
        assert!(split_ports("0").is_err());
        assert!(split_ports("65536").is_err());
        assert!(split_ports("http").is_err());
        assert!(split_ports(" ").is_err());
    }

    #[test]
    fn vless_ws_tls_matches_the_reference_shape() {
        let outbound = vless_outbound(
            "vless://uuid@host.test:443?type=ws&security=tls&sni=edge.example&host=cdn.example&path=%2Fws#name",
        )
        .unwrap();
        assert_eq!(outbound["protocol"], "vless");
        assert_eq!(outbound["settings"]["vnext"][0]["address"], "host.test");
        assert_eq!(outbound["settings"]["vnext"][0]["port"], 443);
        assert_eq!(outbound["settings"]["vnext"][0]["users"][0]["id"], "uuid");
        assert_eq!(outbound["streamSettings"]["network"], "ws");
        assert_eq!(outbound["streamSettings"]["security"], "tls");
        assert_eq!(
            outbound["streamSettings"]["tlsSettings"]["serverName"],
            "edge.example"
        );
        assert_eq!(outbound["streamSettings"]["wsSettings"]["path"], "/ws");
        assert_eq!(
            outbound["streamSettings"]["wsSettings"]["headers"]["Host"],
            "cdn.example"
        );
    }

    #[test]
    fn vless_reality_without_a_key_is_refused() {
        let error = vless_outbound("vless://uuid@host:443?security=reality").unwrap_err();
        assert!(error.contains("pbk"));
    }

    #[test]
    fn vless_unknown_carrier_needs_a_config() {
        let error = vless_outbound("vless://uuid@host:443?type=kcp").unwrap_err();
        assert!(error.contains("--config"));
    }

    #[test]
    fn plan_ports_adopts_the_config_ports_but_a_named_flag_wins() {
        let dir = scratch("ports");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        std::fs::write(
            &paths.cfg,
            r#"{"inbounds":[{"protocol":"socks","port":19080},{"protocol":"http","port":19081}]}"#,
        )
        .unwrap();
        let mut options = options();
        options.fronts = "socks,http".to_owned();
        assert_eq!(plan_ports(&options, &paths, false).socks, 19080);
        assert_eq!(plan_ports(&options, &paths, false).http, 19081);
        options.http_set = true;
        options.http = 28080;
        assert_eq!(plan_ports(&options, &paths, false).http, 28080);
    }

    #[test]
    fn plan_ports_scans_only_when_an_instance_asked() {
        let dir = scratch("scan");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), Some("work"));
        let mut options = options();
        options.fronts = "socks".to_owned();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = listener.local_addr().unwrap().port();
        options.socks = taken;
        let ports = plan_ports(&options, &paths, true);
        assert_ne!(ports.socks, taken);
        drop(listener);
    }

    #[test]
    fn write_config_writes_every_named_front_and_no_other() {
        let dir = scratch("write");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let outbound = serde_json::json!({"protocol": "freedom"});
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        write_config(&paths.cfg, &outbound, "socks,mixed", ports).unwrap();
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.cfg).unwrap()).unwrap();
        assert_eq!(document["inbounds"][0]["protocol"], "socks");
        assert_eq!(document["inbounds"][0]["port"], 1);
        assert_eq!(document["inbounds"][1]["protocol"], "mixed");
        assert_eq!(document["inbounds"][1]["port"], 3);
        assert_eq!(document["outbounds"][0]["protocol"], "freedom");
    }

    #[test]
    fn config_fronts_refuses_a_vpn_route_that_is_not_loopback() {
        let dir = scratch("fronts");
        let file = dir.join("mine.json");
        std::fs::write(
            &file,
            r#"{"inbounds":[{"protocol":"socks","listen":"0.0.0.0","port":1080}]}"#,
        )
        .unwrap();
        let error = config_fronts(file.to_str().unwrap(), true, false, "").unwrap_err();
        assert!(error.contains("not loopback"));
    }

    #[test]
    fn effective_region_lowers_the_country_alias() {
        let mut options = options();
        options.country = "US".to_owned();
        options.country_set = true;
        assert_eq!(effective_region(&options), "us");
        options.region = "US-VA".to_owned();
        assert_eq!(effective_region(&options), "us-va");
    }

    #[test]
    fn stable_udid_is_kept_across_calls() {
        let dir = scratch("udid");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let options = options();
        let first = stable_udid(&options, &paths).unwrap();
        let second = stable_udid(&options, &paths).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 36);
    }
}
