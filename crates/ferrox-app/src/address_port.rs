use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use crate::sockopt::AddressPortStrategy;

const SRV: u16 = 33;
const TXT: u16 = 16;
const TIMEOUT: Duration = Duration::from_secs(2);
const ANSWER_MAX: usize = 4096;

/// The destination a strategy takes a named edge to, or `None` when the lookup
/// answers nothing usable and the original name is dialled as configured.
pub(crate) fn replace(
    strategy: AddressPortStrategy,
    host: &str,
    port: u16,
) -> Option<(String, u16)> {
    let (by_srv, port_of, address_of) = strategy.overrides()?;
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let servers = nameservers();
    if servers.is_empty() {
        return None;
    }
    let (answer_host, answer_port) = if by_srv {
        srv(&servers, host)?
    } else {
        txt(&servers, host)?
    };
    Some((
        if address_of {
            answer_host
        } else {
            host.to_owned()
        },
        if port_of { answer_port } else { port },
    ))
}

/// The first usable SRV record of xray's `_service._proto.name` form: the
/// lowest priority, then one record weighted by its share of that group.
fn srv(servers: &[SocketAddr], host: &str) -> Option<(String, u16)> {
    let mut parts = host.splitn(3, '.');
    let service = parts.next()?.get(1..)?;
    let proto = parts.next()?.get(1..)?;
    let name = parts.next()?;
    let query = format!("_{service}._{proto}.{name}.");
    let records = query_records(servers, &query, SRV)?;
    let mut rows = Vec::new();
    for record in &records {
        if record.len() < 7 {
            continue;
        }
        let priority = u16::from_be_bytes([record[0], record[1]]);
        let weight = u16::from_be_bytes([record[2], record[3]]);
        let port = u16::from_be_bytes([record[4], record[5]]);
        let Some(target) = wire_name(&record[6..]) else {
            continue;
        };
        if target.is_empty() || target == "." {
            continue;
        }
        rows.push((
            priority,
            weight,
            port,
            target.trim_end_matches('.').to_owned(),
        ));
    }
    if rows.is_empty() {
        return None;
    }
    rows.sort_by_key(|row| row.0);
    let priority = rows[0].0;
    let group: Vec<&(u16, u16, u16, String)> =
        rows.iter().filter(|row| row.0 == priority).collect();
    let at = weighted(&group)?;
    let row = group[at];
    Some((row.3.clone(), row.2))
}

/// The first TXT record that carries a `host:port` pair whose port parses.
fn txt(servers: &[SocketAddr], host: &str) -> Option<(String, u16)> {
    let query = if host.ends_with('.') {
        host.to_owned()
    } else {
        format!("{host}.")
    };
    let records = query_records(servers, &query, TXT)?;
    for record in &records {
        let Some(text) = txt_text(record) else {
            continue;
        };
        let Some((named, port)) = split_host_port(&text) else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if named.is_empty() || !valid_name(named) {
            continue;
        }
        return Some((named.to_owned(), port));
    }
    None
}

/// RFC 2782's weighted pick inside one priority: with every weight zero the
/// first record is the answer, as Go's shuffle leaves it.
fn weighted(group: &[&(u16, u16, u16, String)]) -> Option<usize> {
    let total: u64 = group.iter().map(|row| u64::from(row.1)).sum();
    if total == 0 {
        return Some(0);
    }
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).ok()?;
    let mut at = u64::from_le_bytes(raw) % total;
    for (index, row) in group.iter().enumerate() {
        let weight = u64::from(row.1);
        if at < weight {
            return Some(index);
        }
        at -= weight;
    }
    Some(group.len() - 1)
}

/// One uncompressed wire name from record data; a compression pointer or a
/// label that runs past the record refuses it.
fn wire_name(data: &[u8]) -> Option<String> {
    let mut at = 0;
    let mut out = String::new();
    loop {
        let span = usize::from(*data.get(at)?);
        at += 1;
        if span == 0 {
            break;
        }
        if span & 0xC0 != 0 {
            return None;
        }
        let label = data.get(at..at.checked_add(span)?)?;
        if label.contains(&b'.') {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(label).ok()?);
        at += span;
    }
    Some(out)
}

/// A TXT record's character-strings joined the way Go joins them.
fn txt_text(record: &[u8]) -> Option<String> {
    if record.is_empty() {
        return None;
    }
    let mut at = 0;
    let mut out = String::new();
    while at < record.len() {
        let span = usize::from(record[at]);
        at += 1;
        let text = record.get(at..at.checked_add(span)?)?;
        out.push_str(std::str::from_utf8(text).ok()?);
        at += span;
    }
    Some(out)
}

/// Go's `SplitHostPort`: brackets name an IPv6 host, and a bare host may not
/// carry a colon of its own.
fn split_host_port(text: &str) -> Option<(&str, &str)> {
    if let Some(rest) = text.strip_prefix('[') {
        let (named, rest) = rest.split_once(']')?;
        return Some((named, rest.strip_prefix(':')?));
    }
    let (named, port) = text.rsplit_once(':')?;
    if named.contains(':') {
        return None;
    }
    Some((named, port))
}

/// `net.ParseAddress`'s domain half: an address literal or a name a dial can
/// take. Anything else is not a usable record.
fn valid_name(named: &str) -> bool {
    named.parse::<IpAddr>().is_ok()
        || named.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_'
        })
}

fn query_records(servers: &[SocketAddr], name: &str, qtype: u16) -> Option<Vec<Vec<u8>>> {
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).ok()?;
    let id = u16::from_be_bytes(id);
    let query = ferrox_core::dns::build_query(id, name.as_bytes(), qtype, None)?;
    for server in servers {
        let Some(answer) = ask_udp(*server, &query, id).or_else(|| ask_tcp(*server, &query, id))
        else {
            continue;
        };
        if answer.id != id || answer.rcode != 0 {
            continue;
        }
        let records = answer
            .records
            .into_iter()
            .filter(|record| record.kind == qtype)
            .map(|record| record.rdata)
            .collect();
        return Some(records);
    }
    None
}

fn ask_udp(server: SocketAddr, query: &[u8], id: u16) -> Option<ferrox_core::dns::Answer> {
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.set_read_timeout(Some(TIMEOUT)).ok()?;
    socket.set_write_timeout(Some(TIMEOUT)).ok()?;
    socket.send_to(query, server).ok()?;
    let mut answer = vec![0u8; ANSWER_MAX];
    let read = socket.recv(&mut answer).ok()?;
    let parsed = ferrox_core::dns::parse_answer(&answer[..read])?;
    if parsed.id != id {
        return None;
    }
    if parsed.truncated {
        return None;
    }
    Some(parsed)
}

fn ask_tcp(server: SocketAddr, query: &[u8], id: u16) -> Option<ferrox_core::dns::Answer> {
    let mut stream = TcpStream::connect_timeout(&server, TIMEOUT).ok()?;
    stream.set_read_timeout(Some(TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;
    let length = u16::try_from(query.len()).ok()?;
    stream.write_all(&length.to_be_bytes()).ok()?;
    stream.write_all(query).ok()?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(head))];
    stream.read_exact(&mut answer).ok()?;
    let parsed = ferrox_core::dns::parse_answer(&answer)?;
    (parsed.id == id).then_some(parsed)
}

#[cfg(test)]
thread_local! {
    static TEST_SERVERS: std::cell::RefCell<Option<Vec<SocketAddr>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct TestServers(Option<Vec<SocketAddr>>);

#[cfg(test)]
impl Drop for TestServers {
    fn drop(&mut self) {
        let previous = self.0.take();
        TEST_SERVERS.with(|cell| *cell.borrow_mut() = previous);
    }
}

/// Point the strategy's lookups at a loopback nameserver for one test.
#[cfg(test)]
pub(crate) fn test_servers(servers: Vec<SocketAddr>) -> TestServers {
    let previous = TEST_SERVERS.with(|cell| cell.borrow_mut().replace(servers));
    TestServers(previous)
}

fn nameservers() -> Vec<SocketAddr> {
    #[cfg(test)]
    if let Some(servers) = TEST_SERVERS.with(|cell| cell.borrow().clone()) {
        return servers;
    }
    #[cfg(unix)]
    {
        unix_nameservers()
    }
    #[cfg(windows)]
    {
        windows_nameservers()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

#[cfg(unix)]
fn unix_nameservers() -> Vec<SocketAddr> {
    let Ok(conf) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    conf.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next()? != "nameserver" {
                return None;
            }
            let named = words.next()?.split('#').next()?;
            named
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

#[cfg(windows)]
fn windows_nameservers() -> Vec<SocketAddr> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetNetworkParams, FIXED_INFO_W2KSP1};

    let mut size = 0u32;
    let mut info = std::mem::MaybeUninit::<FIXED_INFO_W2KSP1>::zeroed();
    let status = unsafe { GetNetworkParams(info.as_mut_ptr(), &mut size) };
    if status != ERROR_BUFFER_OVERFLOW {
        return Vec::new();
    }
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    let status = unsafe { GetNetworkParams(buffer.as_mut_ptr().cast(), &mut size) };
    if status != ERROR_SUCCESS {
        return Vec::new();
    }
    let info = unsafe { &*buffer.as_ptr().cast::<FIXED_INFO_W2KSP1>() };
    let mut servers = Vec::new();
    let mut node: *const _ = &raw const info.DnsServerList;
    while !node.is_null() {
        let entry = unsafe { &*node };
        let raw = &entry.IpAddress.String;
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        let named: String = raw[..end].iter().map(|byte| *byte as u8 as char).collect();
        if let Ok(ip) = named.parse::<IpAddr>() {
            servers.push(SocketAddr::new(ip, 53));
        }
        node = entry.Next;
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn srv_rdata(priority: u16, weight: u16, port: u16, target: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&priority.to_be_bytes());
        out.extend_from_slice(&weight.to_be_bytes());
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(&wire(target));
        out
    }

    fn txt_rdata(text: &str) -> Vec<u8> {
        let mut out = vec![text.len() as u8];
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn response(query: &[u8], qtype: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = query.to_vec();
        out[2] = 0x81;
        out[3] = 0x80;
        out[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&qtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&(record.len() as u16).to_be_bytes());
            out.extend_from_slice(record);
        }
        out
    }

    /// One loopback nameserver answering a single query with `records`.
    fn nameserver(qtype: u16, records: Vec<Vec<u8>>) -> std::net::SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let address = socket.local_addr().expect("has an address");
        let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
        std::thread::spawn(move || loop {
            let mut query = vec![0u8; ANSWER_MAX];
            let Ok((read, from)) = socket.recv_from(&mut query) else {
                return;
            };
            let answer = response(&query[..read], qtype, &records);
            let _ = socket.send_to(&answer, from);
        });
        address
    }

    #[test]
    fn an_srv_answer_replaces_the_half_the_strategy_names() {
        let target = ["edge", "example", "test"];
        let server = nameserver(SRV, vec![srv_rdata(0, 0, 9000, &target)]);
        let _servers = test_servers(vec![server]);
        let host = "_svc._tcp.example.test";

        assert_eq!(
            replace(AddressPortStrategy::SrvPortOnly, host, 1),
            Some((host.to_owned(), 9000))
        );
        assert_eq!(
            replace(AddressPortStrategy::SrvAddressOnly, host, 1),
            Some(("edge.example.test".to_owned(), 1))
        );
    }

    #[test]
    fn an_srv_answer_can_replace_both_halves() {
        let target = ["edge", "example", "test"];
        let server = nameserver(SRV, vec![srv_rdata(0, 0, 9000, &target)]);
        let _servers = test_servers(vec![server]);
        assert_eq!(
            replace(
                AddressPortStrategy::SrvPortAndAddress,
                "_svc._tcp.example.test",
                1
            ),
            Some(("edge.example.test".to_owned(), 9000))
        );
    }

    #[test]
    fn the_lowest_priority_srv_record_wins() {
        let first = ["one", "example", "test"];
        let second = ["two", "example", "test"];
        let server = nameserver(
            SRV,
            vec![
                srv_rdata(10, 0, 7000, &first),
                srv_rdata(0, 0, 8000, &second),
            ],
        );
        let _servers = test_servers(vec![server]);
        assert_eq!(
            replace(
                AddressPortStrategy::SrvPortAndAddress,
                "_svc._tcp.example.test",
                1
            ),
            Some(("two.example.test".to_owned(), 8000))
        );
    }

    #[test]
    fn a_txt_answer_replaces_the_half_the_strategy_names() {
        let server = nameserver(TXT, vec![txt_rdata("127.0.0.1:8443")]);
        let _servers = test_servers(vec![server]);
        let host = "edge.example.test";

        assert_eq!(
            replace(AddressPortStrategy::TxtPortOnly, host, 1),
            Some((host.to_owned(), 8443))
        );
        assert_eq!(
            replace(AddressPortStrategy::TxtAddressOnly, host, 1),
            Some(("127.0.0.1".to_owned(), 1))
        );
        assert_eq!(
            replace(AddressPortStrategy::TxtPortAndAddress, host, 1),
            Some(("127.0.0.1".to_owned(), 8443))
        );
    }

    #[test]
    fn an_unusable_answer_leaves_the_configured_name() {
        let server = nameserver(TXT, vec![txt_rdata("not-a-host-port")]);
        let _servers = test_servers(vec![server]);
        assert_eq!(
            replace(
                AddressPortStrategy::TxtPortAndAddress,
                "edge.example.test",
                1
            ),
            None
        );
    }

    #[test]
    fn a_numeric_edge_and_a_none_strategy_are_never_queried() {
        assert_eq!(
            replace(AddressPortStrategy::SrvPortOnly, "127.0.0.1", 1),
            None
        );
        assert_eq!(
            replace(AddressPortStrategy::None, "_svc._tcp.example.test", 1),
            None
        );
    }
}
