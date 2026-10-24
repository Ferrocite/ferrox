use crate::sockopt::SocketOptions;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DNS_HTTPS: u16 = 65;
const DNS_CLASS_IN: u16 = 1;
const EDNS_OPT: u16 = 41;
const ECH_PARAM: u16 = 5;
const TIMEOUT: Duration = Duration::from_secs(5);

type Cache = HashMap<String, (Instant, Vec<u8>)>;

static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

pub(crate) fn resolve(
    text: &str,
    server_name: &str,
    options: Option<&SocketOptions>,
) -> Result<Vec<u8>, String> {
    if !text.contains("://") {
        let bytes = ferrox_core::tls::decode_ech_config(text)?;
        return ferrox_core::tls::normalize_ech_config_list(bytes);
    }
    let (name, server) = split(text, server_name)?;
    let key = match options {
        Some(options) => format!("{server}|{name}|{}", options.cache_key()),
        None => format!("{server}|{name}"),
    };
    let cache = CACHE.get_or_init(Default::default);
    let stale = {
        let kept = cache.lock().map_err(|_| "ech: cache poisoned")?;
        kept.get(&key).cloned()
    };
    if let Some((expires, bytes)) = &stale {
        if *expires > Instant::now() {
            return Ok(bytes.clone());
        }
    }
    let queried = query(&name, server, options).and_then(|(bytes, ttl)| {
        ferrox_core::tls::normalize_ech_config_list(bytes).map(|list| (list, ttl))
    });
    match queried {
        Ok((bytes, ttl)) => {
            let expires = Instant::now() + Duration::from_secs(u64::from(ttl.max(1)));
            let mut kept = cache.lock().map_err(|_| "ech: cache poisoned")?;
            kept.insert(key, (expires, bytes.clone()));
            Ok(bytes)
        }
        Err(why) => stale
            .map(|(_, bytes)| bytes)
            .ok_or_else(|| format!("ech: {why}")),
    }
}

fn split<'a>(text: &'a str, server_name: &str) -> Result<(String, &'a str), String> {
    let (name, server) = match text.split_once('+') {
        Some((name, server)) => (name, server),
        None => (server_name, text),
    };
    if name.is_empty() || name.parse::<std::net::IpAddr>().is_ok() {
        return Err(
            "Using DNS for ECH Config needs serverName or use Server format example.com+https://192.0.2.53/dns-query"
                .to_owned(),
        );
    }
    Ok((name.to_owned(), server))
}

fn query(
    name: &str,
    server: &str,
    options: Option<&SocketOptions>,
) -> Result<(Vec<u8>, u32), String> {
    if let Some(rest) = server.strip_prefix("https://") {
        let (authority_text, path) = rest
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or((rest, "/dns-query".to_owned()));
        let (host, port) = authority(authority_host(authority_text), 443);
        return doh(&host, port, &path, name, false, options);
    }
    if let Some(rest) = server.strip_prefix("h2c://") {
        let (authority_text, path) = rest
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or((rest, "/dns-query".to_owned()));
        let (host, port) = authority(authority_host(authority_text), 80);
        return doh(&host, port, &path, name, true, options);
    }
    if let Some(rest) = server.strip_prefix("udp://") {
        let (host, port) = authority(authority_host(rest), 53);
        return udp(&host, port, name, options);
    }
    if let Some(rest) = server.strip_prefix("tcp://") {
        let (host, port) = authority(authority_host(rest), 53);
        return tcp(&host, port, name, options);
    }
    Err(format!("unsupported ECH DNS server {server}"))
}

fn authority_host(text: &str) -> &str {
    text.split('/').next().unwrap_or(text)
}

fn authority(text: &str, default_port: u16) -> (String, u16) {
    match text.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') || host.ends_with(']') => match port.parse() {
            Ok(port) => (host.trim_matches(['[', ']']).to_owned(), port),
            Err(_) => (text.trim_matches(['[', ']']).to_owned(), default_port),
        },
        _ => (text.trim_matches(['[', ']']).to_owned(), default_port),
    }
}

fn question(name: &str, id: u16, edns: bool) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(edns).to_be_bytes());
    let name = name.strip_suffix('.').unwrap_or(name);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("ech: invalid DNS name {name}"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&DNS_HTTPS.to_be_bytes());
    out.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    if edns {
        out.push(0);
        out.extend_from_slice(&EDNS_OPT.to_be_bytes());
        out.extend_from_slice(&4096u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    Ok(out)
}

fn random_id() -> Result<u16, String> {
    let mut raw = [0u8; 2];
    getrandom::fill(&mut raw).map_err(|_| "ech: no randomness")?;
    Ok(u16::from_be_bytes(raw))
}

fn udp(
    host: &str,
    port: u16,
    name: &str,
    options: Option<&SocketOptions>,
) -> Result<(Vec<u8>, u32), String> {
    let id = random_id()?;
    let packet = question(name, id, false)?;
    let response = crate::dnsnet::udp(host, port, &packet, None, options, TIMEOUT, true)?;
    parse_response(&response, Some(id), name)
}

fn tcp(
    host: &str,
    port: u16,
    name: &str,
    options: Option<&SocketOptions>,
) -> Result<(Vec<u8>, u32), String> {
    let id = random_id()?;
    let packet = question(name, id, false)?;
    let response = crate::dnsnet::tcp(host, port, &packet, None, options, TIMEOUT, true)?;
    parse_response(&response, Some(id), name)
}

fn doh(
    host: &str,
    port: u16,
    path: &str,
    name: &str,
    cleartext: bool,
    options: Option<&SocketOptions>,
) -> Result<(Vec<u8>, u32), String> {
    let packet = question(name, 0, true)?;
    let body = crate::dnsnet::doh(
        host, port, path, cleartext, &packet, None, options, TIMEOUT, true,
    )?;
    parse_response(&body, None, name)
}

fn parse_response(packet: &[u8], id: Option<u16>, name: &str) -> Result<(Vec<u8>, u32), String> {
    if packet.len() < 12 {
        return Err("ech: short DNS response".to_owned());
    }
    let got_id = u16::from_be_bytes([packet[0], packet[1]]);
    if let Some(id) = id {
        if got_id != id {
            return Err("ech: DNS response id mismatch".to_owned());
        }
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Err("ech: DNS response is not an answer".to_owned());
    }
    if flags & 0x000f != 0 {
        return Err(format!("ech: DNS rcode {}", flags & 0x000f));
    }
    let questions = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let answers = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    let mut at = 12;
    for _ in 0..questions {
        skip_name(packet, &mut at)?;
        at = at
            .checked_add(4)
            .filter(|at| *at <= packet.len())
            .ok_or("ech: short question")?;
    }
    for _ in 0..answers {
        let owner = read_name(packet, &mut at)?;
        let kind = take_u16(packet, &mut at)?;
        let _class = take_u16(packet, &mut at)?;
        let ttl = take_u32(packet, &mut at)?;
        let length = usize::from(take_u16(packet, &mut at)?);
        let end = at
            .checked_add(length)
            .filter(|end| *end <= packet.len())
            .ok_or("ech: answer past the end")?;
        if kind == DNS_HTTPS && owner.eq_ignore_ascii_case(name) {
            if let Some(ech) = svcb_ech(packet, at, end)? {
                return Ok((ech, ttl));
            }
        }
        at = end;
    }
    Err(format!("ech: no ECH config in the HTTPS record for {name}"))
}

fn svcb_ech(packet: &[u8], start: usize, end: usize) -> Result<Option<Vec<u8>>, String> {
    let mut at = start;
    let _priority = take_u16(packet, &mut at)?;
    skip_name(packet, &mut at)?;
    while at + 4 <= end {
        let key = take_u16(packet, &mut at)?;
        let length = usize::from(take_u16(packet, &mut at)?);
        let value_end = at
            .checked_add(length)
            .filter(|value_end| *value_end <= end)
            .ok_or("ech: SVCB parameter past the end")?;
        if key == ECH_PARAM {
            return Ok(Some(packet[at..value_end].to_vec()));
        }
        at = value_end;
    }
    Ok(None)
}

fn skip_name(packet: &[u8], at: &mut usize) -> Result<(), String> {
    read_name(packet, at).map(|_| ())
}

fn read_name(packet: &[u8], at: &mut usize) -> Result<String, String> {
    let mut pos = *at;
    let mut resume = None;
    let mut hops = 0;
    let mut out = String::new();
    loop {
        let length = *packet.get(pos).ok_or("ech: name past the end")?;
        if length == 0 {
            *at = resume.unwrap_or(pos + 1);
            return Ok(out);
        }
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(pos + 1).ok_or("ech: short pointer")?;
            if resume.is_none() {
                resume = Some(pos + 2);
            }
            pos = (usize::from(length & 0x3f) << 8) | usize::from(low);
            hops += 1;
            if hops > 32 {
                return Err("ech: name pointer loop".to_owned());
            }
            continue;
        }
        let length = usize::from(length);
        let end = pos
            .checked_add(1 + length)
            .filter(|end| *end <= packet.len())
            .ok_or("ech: label past the end")?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(&packet[pos + 1..end]).unwrap_or(""));
        pos = end;
    }
}

fn take_u16(packet: &[u8], at: &mut usize) -> Result<u16, String> {
    let end = at
        .checked_add(2)
        .filter(|end| *end <= packet.len())
        .ok_or("ech: short u16")?;
    let value = u16::from_be_bytes([packet[*at], packet[*at + 1]]);
    *at = end;
    Ok(value)
}

fn take_u32(packet: &[u8], at: &mut usize) -> Result<u32, String> {
    let end = at
        .checked_add(4)
        .filter(|end| *end <= packet.len())
        .ok_or("ech: short u32")?;
    let value = u32::from_be_bytes([
        packet[*at],
        packet[*at + 1],
        packet[*at + 2],
        packet[*at + 3],
    ]);
    *at = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(packet: &mut Vec<u8>, name: &str, ech: &[u8], id: u16) {
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x8180u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&DNS_HTTPS.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&DNS_HTTPS.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0);
        rdata.extend_from_slice(&ECH_PARAM.to_be_bytes());
        rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(ech);
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
    }

    #[test]
    fn an_https_answer_carries_the_ech_parameter() {
        let mut packet = Vec::new();
        response(&mut packet, "example.com", &[1, 2, 3, 4], 0);
        let (ech, ttl) = parse_response(&packet, Some(0), "example.com").unwrap();
        assert_eq!(ech, [1, 2, 3, 4]);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn a_dns_query_names_https_and_edns() {
        let query = question("example.com", 0, true).unwrap();
        assert_eq!(&query[..2], &[0, 0]);
        assert!(query.windows(2).any(|pair| pair == DNS_HTTPS.to_be_bytes()));
        assert_eq!(
            &query[query.len() - 11..],
            &[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn the_server_form_separates_the_query_name() {
        let (name, server) =
            split("example.com+https://192.0.2.53/dns-query", "edge.test").unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(server, "https://192.0.2.53/dns-query");
        let (name, server) = split("https://192.0.2.53/dns-query", "edge.test").unwrap();
        assert_eq!(name, "edge.test");
        assert_eq!(server, "https://192.0.2.53/dns-query");
        assert!(split("https://192.0.2.53/dns-query", "192.0.2.53").is_err());
    }

    #[test]
    fn a_compressed_owner_is_followed() {
        let mut packet = vec![0u8; 12];
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        let mut at = 12;
        assert_eq!(read_name(&packet, &mut at).unwrap(), "example.com");
        assert_eq!(at, packet.len());
    }

    #[test]
    fn an_ech_query_carries_the_socket_options() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 512];
            let (read, from) = server.recv_from(&mut packet).unwrap();
            let id = u16::from_be_bytes([packet[0], packet[1]]);
            let mut answer = Vec::new();
            response(&mut answer, "example.test", &[9, 8, 7], id);
            server.send_to(&answer, from).unwrap();
            read
        });
        let settings =
            crate::json::parse(r#"{"domainStrategy":"useipv4","tcpFastOpen":false}"#).unwrap();
        let options = crate::sockopt::parse(Some(&settings)).unwrap();
        let (ech, ttl) = udp("127.0.0.1", addr.port(), "example.test", options.as_ref()).unwrap();
        assert_eq!(ech, [9, 8, 7]);
        assert_eq!(ttl, 300);
        assert!(worker.join().unwrap() > 2);
    }
}
