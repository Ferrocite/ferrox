//! A tiny synchronous DNS fallback for the alternate resolvers the Android client names.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REPLY: usize = 4096;

/// Resolve `host`, preferring the system resolver and falling back to `servers`.
pub(crate) fn resolve(
    host: &str,
    port: u16,
    servers: &[SocketAddr],
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    if let Ok(addresses) = (host, port).to_socket_addrs() {
        let addresses: Vec<SocketAddr> = addresses.collect();
        if !addresses.is_empty() {
            return Ok(addresses);
        }
    }
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no alternate DNS server");
    for server in servers {
        match query(host, *server) {
            Ok(addresses) if !addresses.is_empty() => {
                return Ok(addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, port))
                    .collect());
            }
            Ok(_) => {
                last = io::Error::new(io::ErrorKind::NotFound, "alternate DNS answered no address");
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn query(host: &str, server: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for record in [1u16, 28] {
        match query_one(host, server, record) {
            Ok(mut found) => addresses.append(&mut found),
            Err(error) if addresses.is_empty() => return Err(error),
            Err(_) => {}
        }
    }
    Ok(addresses)
}

fn query_one(host: &str, server: SocketAddr, record: u16) -> io::Result<Vec<IpAddr>> {
    let bind = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT))?;
    let id = crate::psiphon_ssh::random::<2>();
    let request = query_packet(id, host, record)?;
    socket.send(&request)?;
    let mut reply = [0u8; MAX_REPLY];
    let count = socket.recv(&mut reply)?;
    parse_reply(id, &reply[..count], record)
}

fn query_packet(id: [u8; 2], host: &str, record: u16) -> io::Result<Vec<u8>> {
    let name = host.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad DNS name"));
    }
    let mut packet = Vec::with_capacity(12 + name.len() + 6);
    packet.extend_from_slice(&id);
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS label too long"))?;
        if label.is_empty() || length > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad DNS label"));
        }
        packet.push(length);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&record.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

fn parse_reply(id: [u8; 2], reply: &[u8], record: u16) -> io::Result<Vec<IpAddr>> {
    if reply.len() < 12 || reply[..2] != id[..] || reply[2] & 0x80 == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS reply"));
    }
    if reply[3] & 0x0f != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS error"));
    }
    let questions = usize::from(u16::from_be_bytes([reply[4], reply[5]]));
    let answers = usize::from(u16::from_be_bytes([reply[6], reply[7]]));
    let mut at = 12;
    for _ in 0..questions {
        skip_name(reply, &mut at)?;
        at = at
            .checked_add(4)
            .filter(|at| *at <= reply.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS question"))?;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        skip_name(reply, &mut at)?;
        let head = reply
            .get(at..at + 10)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS answer"))?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let class = u16::from_be_bytes([head[2], head[3]]);
        let length = usize::from(u16::from_be_bytes([head[8], head[9]]));
        at += 10;
        let data = reply
            .get(at..at + length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS record"))?;
        at += length;
        if kind != record || class != 1 {
            continue;
        }
        match (kind, data) {
            (1, [a, b, c, d]) => addresses.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
            (28, bytes) if bytes.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }
    Ok(addresses)
}

fn skip_name(reply: &[u8], at: &mut usize) -> io::Result<()> {
    loop {
        let length = usize::from(
            *reply
                .get(*at)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS name"))?,
        );
        *at += 1;
        match length & 0xc0 {
            0xc0 => {
                *at += 1;
                return Ok(());
            }
            0 => {
                if length == 0 {
                    return Ok(());
                }
                *at = (*at)
                    .checked_add(length)
                    .filter(|at| *at <= reply.len())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS label"))?;
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS name")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::thread;

    #[test]
    fn a_literal_address_needs_no_query() {
        let addresses = resolve("192.0.2.7", 443, &[]).expect("literal");
        assert_eq!(addresses, [SocketAddr::from(([192, 0, 2, 7], 443))]);
    }

    #[test]
    fn an_alternate_server_answers_a_record() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let server = socket.local_addr().expect("address");
        let responder = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (count, peer) = socket.recv_from(&mut request).expect("query");
            let request = &request[..count];
            let question_end = 12
                + request[12..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .expect("question")
                + 5;
            let mut reply = Vec::new();
            reply.extend_from_slice(&request[..2]);
            reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            reply.extend_from_slice(&request[12..question_end]);
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7]);
            socket.send_to(&reply, peer).expect("reply");
        });
        let addresses = super::query_one("psiphon.test", server, 1).expect("alternate");
        responder.join().expect("responder");
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]);
    }
}
