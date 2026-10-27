//! `WireGuard`'s runtime: the UDP socket, the per-peer tunnels, and the threads
//! that move an inner packet between the tunnel and the userspace stack.
//!
//! One reader owns the tunnel state. It decrypts every datagram, routes it to
//! the peer that authenticated it, and hands a TCP packet to `smoltcp` or a UDP
//! packet to the lane that asked. Writers only enqueue inner packets, so no
//! flow ever locks a session or races a counter.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ferrox_core::dns::{build_query, parse_answer, Answer};
use ferrox_core::foxy::connectip::{
    udp_datagram, udp_from_packet, UdpDatagram, IPV4_HEADER, IPV6_HEADER, UDP_HEADER,
};
use ferrox_core::wireguard::device::{tai64n, Event, Tunnel};
use ferrox_core::wireguard::handshake::{
    check_mac1, INITIATION_SIZE, TYPE_INITIATION, TYPE_RESPONSE,
};
use ferrox_core::wireguard::transport::clear_reserved;

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{Destination, Outbound};
use crate::wg_stack::{self, ip_bytes, ClientFlow, Packet, UdpRoutes};
use crate::wireguard::{DeviceConfig, PeerConfig};

/// The reader's wait for a datagram: it also bounds how long a queued inner
/// packet waits before the tunnel encrypts it.
const IO_TICK: Duration = Duration::from_millis(10);
/// The reference's DNS servers when the config names none.
const DEFAULT_DNS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];
/// The wire DNS port; the config names addresses, not ports.
const DNS_PORT: u16 = 53;
/// How long one remote-DNS exchange waits for its answer.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// The source-port range reserved for remote-DNS queries, below the ephemeral
/// range the datagram lanes bind.
const DNS_PORT_FIRST: u16 = 1024;
const DNS_PORT_LAST: u16 = 49_152;
/// The most names one outbound caches.
const DNS_CACHE: usize = 256;

/// A cached remote-DNS answer and the instant it stops being usable.
#[derive(Debug)]
struct Resolved {
    addrs: Vec<IpAddr>,
    until: Instant,
}

/// The addresses of `qtype` an answer carries, with the smallest record TTL.
fn addresses(answer: &Answer, qtype: u16) -> Option<(Vec<IpAddr>, u32)> {
    let mut addrs = Vec::new();
    let mut ttl = 300u32;
    for record in &answer.records {
        if record.kind != qtype {
            continue;
        }
        let address = match record.rdata.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(record.rdata.as_slice()).ok()?),
            16 => IpAddr::from(<[u8; 16]>::try_from(record.rdata.as_slice()).ok()?),
            _ => continue,
        };
        addrs.push(address);
        ttl = ttl.min(record.ttl.max(1));
    }
    (!addrs.is_empty()).then_some((addrs, ttl))
}

/// A client outbound: the flow channel, the inner-packet queue the stack and
/// the datagram lanes write, and the lane table the reader routes replies by.
#[derive(Debug)]
pub(crate) struct WireGuardOut {
    config: Arc<DeviceConfig>,
    flows: Sender<ClientFlow>,
    to_tunnel: Sender<Vec<u8>>,
    routes: UdpRoutes,
    stop: Arc<AtomicBool>,
    dns_servers: Vec<IpAddr>,
    dns_port: u16,
    dns_port_next: AtomicU16,
    dns_id: AtomicU16,
    resolved: Mutex<HashMap<String, Resolved>>,
}

impl WireGuardOut {
    pub(crate) fn new(config: DeviceConfig) -> Result<Self, String> {
        Self::with_dns_port(config, DNS_PORT)
    }

    fn with_dns_port(config: DeviceConfig, dns_port: u16) -> Result<Self, String> {
        if config.is_client == Some(false) {
            return Err("a wireguard outbound must set `isClient: true`".to_owned());
        }
        if !config.no_kernel_tun {
            eprintln!(
                "wireguard: `noKernelTun` is false, so the reference opens a kernel TUN; this tree opens none and serves the userspace stack"
            );
        }
        let dns_servers = if config.dns.is_empty() {
            DEFAULT_DNS.to_vec()
        } else {
            config.dns.clone()
        };
        let socket = bind_socket(&config)?;
        let (packets_tx, packets_rx) = mpsc::channel();
        let (to_tunnel, from_tunnel) = mpsc::channel();
        let (flows, flow_rx) = mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let io_config = config.clone();
        let io_packets = packets_tx.clone();
        let io_routes = Arc::clone(&routes);
        let io_stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            io(
                io_config,
                socket,
                from_tunnel,
                io_packets,
                Some(io_routes),
                Some(io_stop),
            );
        });
        let stack_config = config.clone();
        let stack_tunnel = to_tunnel.clone();
        std::thread::spawn(move || {
            wg_stack::client(stack_config, stack_tunnel, packets_rx, flow_rx);
        });
        Ok(Self {
            config: Arc::new(config),
            flows,
            to_tunnel,
            routes,
            stop,
            dns_servers,
            dns_port,
            dns_port_next: AtomicU16::new(0),
            dns_id: AtomicU16::new(0),
            resolved: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        self.config.peers.first().and_then(|peer| peer.endpoint)
    }

    pub(crate) fn serve_tcp(&self, client: Connection, asked: &Destination, prefix: &[u8]) {
        let Some(destination) = self.destination(asked) else {
            eprintln!("wireguard: destination `{asked:?}` does not resolve");
            return;
        };
        if !self
            .config
            .peers
            .iter()
            .any(|peer| peer.routes(destination.ip()))
        {
            eprintln!("wireguard: no peer allows `{destination}`");
            return;
        }
        if self
            .flows
            .send(ClientFlow {
                client,
                destination,
                prefix: prefix.to_vec(),
            })
            .is_err()
        {
            eprintln!("wireguard: the userspace stack is gone");
        }
    }

    pub(crate) fn serve_udp(&self, relay: &UdpSocket, associate: Option<&Connection>) {
        wg_stack::client_udp(
            relay,
            &self.config,
            &self.to_tunnel,
            &self.routes,
            associate,
            &|host, port| {
                self.resolve(host, port).into_iter().find(|address| {
                    self.config
                        .peers
                        .iter()
                        .any(|peer| peer.routes(address.ip()))
                })
            },
        );
    }

    /// The address to dial: a literal stands, a name is asked through the tunnel
    /// against the configured servers and the first answer a peer routes wins.
    fn destination(&self, asked: &Destination) -> Option<SocketAddr> {
        match asked {
            Destination::Address(address) => Some(*address),
            Destination::Name(host, port) => {
                self.resolve(host, *port).into_iter().find(|address| {
                    self.config
                        .peers
                        .iter()
                        .any(|peer| peer.routes(address.ip()))
                })
            }
        }
    }

    fn resolve(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return vec![SocketAddr::new(address, port)];
        }
        self.lookup(host)
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect()
    }

    fn lookup(&self, host: &str) -> Vec<IpAddr> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Ok(cache) = self.resolved.lock() {
            if let Some(entry) = cache.get(&key) {
                if entry.until > Instant::now() {
                    return entry.addrs.clone();
                }
            }
        }
        let Some((addrs, ttl)) = self.query(host) else {
            return Vec::new();
        };
        if let Ok(mut cache) = self.resolved.lock() {
            if cache.len() >= DNS_CACHE {
                cache.clear();
            }
            cache.insert(
                key,
                Resolved {
                    addrs: addrs.clone(),
                    until: Instant::now() + Duration::from_secs(u64::from(ttl)),
                },
            );
        }
        addrs
    }

    fn query(&self, host: &str) -> Option<(Vec<IpAddr>, u32)> {
        let name = if host.ends_with('.') {
            host.to_owned()
        } else {
            format!("{host}.")
        };
        let has_v4 = self.config.addresses.iter().any(IpAddr::is_ipv4);
        let has_v6 = self.config.addresses.iter().any(IpAddr::is_ipv6);
        let mut answers = Vec::new();
        let mut ttl = 300u32;
        for server in &self.dns_servers {
            if !self.config.peers.iter().any(|peer| peer.routes(*server)) {
                continue;
            }
            let Some(source) = self
                .config
                .addresses
                .iter()
                .find(|address| address.is_ipv4() == server.is_ipv4())
                .copied()
            else {
                continue;
            };
            let (v4, v6) = std::thread::scope(|scope| {
                let v4 = has_v4.then(|| scope.spawn(|| self.exchange(source, *server, &name, 1)));
                let v6 = has_v6.then(|| scope.spawn(|| self.exchange(source, *server, &name, 28)));
                (
                    v4.and_then(|handle| handle.join().ok().flatten()),
                    v6.and_then(|handle| handle.join().ok().flatten()),
                )
            });
            for (mut records, answer_ttl) in [v4, v6].into_iter().flatten() {
                answers.append(&mut records);
                ttl = ttl.min(answer_ttl.max(1));
            }
            if !answers.is_empty() {
                break;
            }
        }
        (!answers.is_empty()).then_some((answers, ttl))
    }

    fn exchange(
        &self,
        source: IpAddr,
        server: IpAddr,
        name: &str,
        qtype: u16,
    ) -> Option<(Vec<IpAddr>, u32)> {
        let id = self.dns_id.fetch_add(1, Ordering::Relaxed);
        let query = build_query(id, name.as_bytes(), qtype, None)?;
        let (port, replies) = self.reserve_dns_route()?;
        let source_bytes = ip_bytes(source);
        let destination_bytes = ip_bytes(server);
        let header = if source.is_ipv4() {
            IPV4_HEADER
        } else {
            IPV6_HEADER
        };
        let mut packet = Vec::with_capacity(header + UDP_HEADER + query.len());
        if !udp_datagram(
            &UdpDatagram {
                source: &source_bytes,
                destination: &destination_bytes,
                source_port: port,
                destination_port: self.dns_port,
                payload: &query,
            },
            &mut packet,
        ) {
            self.remove_dns_route(port);
            return None;
        }
        if self.to_tunnel.send(packet).is_err() {
            self.remove_dns_route(port);
            return None;
        }
        let deadline = Instant::now() + DNS_TIMEOUT;
        let result = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break None;
            }
            let Ok(inner) = replies.recv_timeout(remaining) else {
                break None;
            };
            let Some(datagram) = udp_from_packet(&inner) else {
                continue;
            };
            if datagram.source != destination_bytes.as_slice()
                || datagram.source_port != self.dns_port
                || datagram.destination_port != port
            {
                continue;
            }
            let Some(answer) = parse_answer(datagram.payload) else {
                continue;
            };
            if answer.id != id || answer.rcode != 0 {
                continue;
            }
            if answer.truncated {
                break self.exchange_tcp(server, &query, id, qtype);
            }
            break addresses(&answer, qtype);
        };
        self.remove_dns_route(port);
        result
    }

    /// Ask again over a TCP flow through the same tunnel when a UDP answer is
    /// truncated, as the reference does: a local loopback pair hands the stream
    /// to the client stack, and the query travels length-prefixed.
    fn exchange_tcp(
        &self,
        server: IpAddr,
        query: &[u8],
        id: u16,
        qtype: u16,
    ) -> Option<(Vec<IpAddr>, u32)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        let mut app = TcpStream::connect(listener.local_addr().ok()?).ok()?;
        let (tunnel, _) = listener.accept().ok()?;
        app.set_read_timeout(Some(DNS_TIMEOUT)).ok()?;
        app.set_write_timeout(Some(DNS_TIMEOUT)).ok()?;
        if self
            .flows
            .send(ClientFlow {
                client: Connection::from(tunnel),
                destination: SocketAddr::new(server, self.dns_port),
                prefix: Vec::new(),
            })
            .is_err()
        {
            return None;
        }
        let len = u16::try_from(query.len()).ok()?;
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        app.write_all(&framed).ok()?;
        let mut prefix = [0u8; 2];
        app.read_exact(&mut prefix).ok()?;
        let len = usize::from(u16::from_be_bytes(prefix));
        if len == 0 {
            return None;
        }
        let mut response = vec![0u8; len];
        app.read_exact(&mut response).ok()?;
        let answer = parse_answer(&response)?;
        if answer.id != id || answer.rcode != 0 || answer.truncated {
            return None;
        }
        addresses(&answer, qtype)
    }

    fn reserve_dns_route(&self) -> Option<(u16, Receiver<Vec<u8>>)> {
        let mut routes = self.routes.lock().ok()?;
        let span = u32::from(DNS_PORT_LAST - DNS_PORT_FIRST);
        for _ in 0..span {
            let offset = u32::from(self.dns_port_next.fetch_add(1, Ordering::Relaxed)) % span;
            let port = DNS_PORT_FIRST + offset as u16;
            if let std::collections::hash_map::Entry::Vacant(entry) = routes.entry(port) {
                let (sender, receiver) = mpsc::channel();
                entry.insert(sender);
                return Some((port, receiver));
            }
        }
        None
    }

    fn remove_dns_route(&self, port: u16) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.remove(&port);
        }
    }
}

impl Drop for WireGuardOut {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Open the server's UDP socket and spawn its reader and stack. Returns the
/// port the OS bound, or a refusal the startup names.
pub(crate) fn serve_inbound(inbound: &Json, out: &Outbound, address: &str) -> Result<u16, String> {
    let settings = inbound
        .get("settings")
        .ok_or("wireguard inbound has no settings")?;
    let config = DeviceConfig::from_json(settings)?;
    if config.is_client == Some(true) {
        return Err("a wireguard inbound must not set `isClient: true`".to_owned());
    }
    if !config.no_kernel_tun {
        eprintln!(
            "wireguard: the reference's server always serves a userspace stack; `noKernelTun` is not read here"
        );
    }
    let socket = UdpSocket::bind(address)
        .map_err(|error| format!("cannot bind wireguard `{address}`: {error}"))?;
    let port = socket
        .local_addr()
        .map_err(|error| format!("wireguard `{address}` has no local address: {error}"))?
        .port();
    let _ = socket.set_read_timeout(Some(IO_TICK));
    let (packets_tx, packets_rx) = mpsc::channel();
    let (to_tunnel, from_tunnel) = mpsc::channel();
    let io_config = config.clone();
    let io_packets = packets_tx.clone();
    std::thread::spawn(move || io(io_config, socket, from_tunnel, io_packets, None, None));
    let stack_config = config;
    let stack_tunnel = to_tunnel;
    let stack_out = out.clone();
    std::thread::spawn(move || {
        wg_stack::server(stack_config, stack_tunnel, packets_rx, stack_out);
    });
    Ok(port)
}

/// One peer's configured identity beside the tunnel state the reader owns.
struct Peer {
    config: PeerConfig,
    tunnel: Tunnel,
}

/// The tunnel reader and writer: inner packets leave, datagrams arrive, and the
/// timers run on the same clock.
#[allow(clippy::needless_pass_by_value)]
fn io(
    config: DeviceConfig,
    socket: UdpSocket,
    from_tunnel: Receiver<Vec<u8>>,
    to_stack: Sender<Packet>,
    routes: Option<UdpRoutes>,
    stop: Option<Arc<AtomicBool>>,
) {
    let _ = socket.set_read_timeout(Some(IO_TICK));
    let epoch = tai64n_now();
    let mut peers = peers(&config, epoch);
    let started = Instant::now();
    let mut buf = vec![0u8; 65_535];
    let mut events = Vec::new();
    let mut incoming = Vec::new();
    loop {
        if stop
            .as_ref()
            .is_some_and(|stop| stop.load(Ordering::Relaxed))
        {
            return;
        }
        let now = started.elapsed().as_millis() as u64;
        loop {
            let packet = match from_tunnel.try_recv() {
                Ok(packet) => packet,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            };
            let Some((_, destination)) = wg_stack::inner_addresses(&packet) else {
                continue;
            };
            let Some(index) = peer_for(&peers, destination) else {
                continue;
            };
            peers[index].tunnel.send(now, &packet, &mut events);
            flush(
                &mut events,
                &socket,
                &to_stack,
                routes.as_ref(),
                &peers,
                Some(index),
            );
        }
        for peer in &mut peers {
            peer.tunnel.poll(now, &mut events);
        }
        flush(
            &mut events,
            &socket,
            &to_stack,
            routes.as_ref(),
            &peers,
            None,
        );

        match socket.recv_from(&mut buf) {
            Ok((n, source)) if n >= 4 => {
                let kind = u32::from(buf[0]);
                if kind == TYPE_INITIATION && n == INITIATION_SIZE {
                    let mut packet = buf[..n].to_vec();
                    clear_reserved(&mut packet);
                    handle_initiation(&mut peers, now, source, &packet, &socket, &to_stack);
                } else {
                    let at = if kind == TYPE_RESPONSE { 8 } else { 4 };
                    let receiver = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap_or([0; 4]));
                    let Some(index) = peers.iter().position(|peer| peer.tunnel.owns(receiver))
                    else {
                        continue;
                    };
                    peers[index]
                        .tunnel
                        .receive(now, source, &mut buf[..n], &mut incoming);
                    flush(
                        &mut incoming,
                        &socket,
                        &to_stack,
                        routes.as_ref(),
                        &peers,
                        Some(index),
                    );
                }
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionRefused
                ) => {}
            Err(_) => return,
        }
    }
}

fn handle_initiation(
    peers: &mut [Peer],
    now: u64,
    source: SocketAddr,
    packet: &[u8],
    socket: &UdpSocket,
    to_stack: &Sender<Packet>,
) {
    let Some(state) = peers.first().and_then(|peer| {
        let message: &[u8; INITIATION_SIZE] = packet.try_into().ok()?;
        if !check_mac1(packet, &peer.tunnel.public()) {
            return None;
        }
        peer.tunnel.consume(message)
    }) else {
        return;
    };
    let remote = state.remote_static();
    let Some(index) = peers.iter().position(|peer| peer.config.public == remote) else {
        return;
    };
    let mut events = Vec::new();
    peers[index].tunnel.answer(now, source, state, &mut events);
    flush(&mut events, socket, to_stack, None, peers, Some(index));
}

/// Send every event, and for each decrypted payload require the authenticating
/// peer to own the source by longest allowed prefix before the upper layer sees
/// it.
fn flush(
    events: &mut Vec<Event>,
    socket: &UdpSocket,
    to_stack: &Sender<Packet>,
    routes: Option<&UdpRoutes>,
    peers: &[Peer],
    peer: Option<usize>,
) {
    for event in events.drain(..) {
        match event {
            Event::Send { endpoint, packet } => {
                let _ = socket.send_to(&packet, endpoint);
            }
            Event::Data(inner) => {
                let Some(index) = peer else {
                    continue;
                };
                let Some((source, _)) = wg_stack::inner_addresses(&inner) else {
                    continue;
                };
                if peer_for(peers, source) != Some(index) {
                    continue;
                }
                if let Some(routes) = routes {
                    if let Some(datagram) = ferrox_core::foxy::connectip::udp_from_packet(&inner) {
                        if let Ok(table) = routes.lock() {
                            if let Some(lane) = table.get(&datagram.destination_port) {
                                let _ = lane.send(inner);
                            }
                        }
                        continue;
                    }
                }
                let _ = to_stack.send(Packet {
                    peer: peers[index].config.public,
                    bytes: inner,
                });
            }
        }
    }
}

fn tai64n_now() -> [u8; 12] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    tai64n(now.as_secs(), now.subsec_nanos())
}

fn peers(config: &DeviceConfig, epoch: [u8; 12]) -> Vec<Peer> {
    config
        .peers
        .iter()
        .map(|peer| Peer {
            config: peer.clone(),
            tunnel: Tunnel::new(
                config.secret,
                peer.public,
                peer.preshared,
                peer.endpoint.unwrap_or_else(|| {
                    let address = config
                        .addresses
                        .iter()
                        .find(|address| address.is_ipv4())
                        .or_else(|| config.addresses.first())
                        .copied()
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    SocketAddr::new(address, 0)
                }),
                peer.keepalive,
                config.reserved,
                epoch,
            ),
        })
        .collect()
}

fn peer_for(peers: &[Peer], destination: IpAddr) -> Option<usize> {
    peers
        .iter()
        .enumerate()
        .filter_map(|(index, peer)| {
            peer.config
                .longest_prefix(destination)
                .map(|bits| (index, bits))
        })
        .max_by_key(|(_, bits)| *bits)
        .map(|(index, _)| index)
}

fn bind_socket(config: &DeviceConfig) -> Result<UdpSocket, String> {
    let endpoint = config
        .peers
        .iter()
        .find_map(|peer| peer.endpoint)
        .ok_or("wireguard client: no peer has an `endpoint`")?;
    let unspecified = if endpoint.is_ipv4() {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    };
    if config
        .peers
        .iter()
        .filter_map(|peer| peer.endpoint)
        .any(|candidate| candidate.is_ipv4() != endpoint.is_ipv4())
    {
        return Err(
            "wireguard client: peers on both address families need two sockets, not carried"
                .to_owned(),
        );
    }
    UdpSocket::bind(unspecified)
        .map_err(|error| format!("cannot bind wireguard's UDP socket: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_peer_may_not_originate_another_peers_source() {
        let config = DeviceConfig {
            secret: [0x11; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: vec![
                PeerConfig {
                    public: [0x22; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    keepalive: 0,
                    allowed: vec![("10.0.0.2".parse().unwrap(), 32)],
                },
                PeerConfig {
                    public: [0x33; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    keepalive: 0,
                    allowed: vec![("10.0.0.0".parse().unwrap(), 8)],
                },
            ],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            dns: Vec::new(),
        };
        let peers = peers(&config, [0; 12]);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let (to_stack, packets) = mpsc::channel();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        let mut events = vec![Event::Data(packet)];
        flush(&mut events, &socket, &to_stack, None, &peers, Some(1));
        assert!(packets.try_recv().is_err(), "the owner is peer zero");
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 1, 2, 3]);
        let mut events = vec![Event::Data(packet)];
        flush(&mut events, &socket, &to_stack, None, &peers, Some(1));
        assert!(packets.try_recv().is_ok(), "the peer owns its own source");
    }

    #[test]
    fn a_tcp_flow_crosses_the_tunnel_to_a_freedom_dial() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = echo.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let mut seen = 0;
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
                seen += n;
                if seen >= 9 {
                    return;
                }
            }
        });

        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let hex = ferrox_core::foxy::account::hex_encode;
        let server_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"reserved":[4,5,6],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex(&server_private),
            hex(&client_public)
        );
        let inbound =
            crate::json::parse(&format!(r#"{{"settings":{server_settings}}}"#)).expect("inbound");
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let port = serve_inbound(&inbound, &out, "127.0.0.1:0").expect("serve");
        assert_ne!(port, 0);

        let client = DeviceConfig::from_json(
            &crate::json::parse(&format!(
                r#"{{"secretKey":"{}","address":["10.0.0.2"],"reserved":[1,2,3],"peers":[{{"publicKey":"{}","endpoint":"127.0.0.1:{port}"}}]}}"#,
                hex(&client_private),
                hex(&server_public)
            ))
            .expect("client config"),
        )
        .expect("device");
        let wireguard = WireGuardOut::new(client).expect("outbound");
        let listener = TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        wireguard.serve_tcp(
            Connection::from(tun),
            &Destination::Address(echo_address),
            b"head",
        );
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 9];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"headhello");
        let mut eof = [0u8; 1];
        assert_eq!(app.read(&mut eof).expect("eof"), 0);
    }

    #[test]
    fn a_name_resolves_through_the_tunnel_before_the_flow() {
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns");
        let dns_address = dns.local_addr().expect("dns address");
        let (answered, answer) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let Ok((n, from)) = dns.recv_from(&mut buf) else {
                return;
            };
            let Some(question) = ferrox_core::dns::parse_query(&buf[..n]) else {
                return;
            };
            let Some(reply) = ferrox_core::dns::ip_answer(&question, 0, 60, &[vec![127, 0, 0, 1]])
            else {
                return;
            };
            if dns.send_to(&reply, from).is_ok() {
                let _ = answered.send(());
            }
        });

        let echo = TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("echo address");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = echo.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let mut seen = 0;
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
                seen += n;
                if seen >= 9 {
                    return;
                }
            }
        });

        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let hex = ferrox_core::foxy::account::hex_encode;
        let server_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex(&server_private),
            hex(&client_public)
        );
        let inbound =
            crate::json::parse(&format!(r#"{{"settings":{server_settings}}}"#)).expect("inbound");
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let port = serve_inbound(&inbound, &out, "127.0.0.1:0").expect("serve");

        let client = DeviceConfig::from_json(
            &crate::json::parse(&format!(
                r#"{{"secretKey":"{}","address":["10.0.0.2"],"remoteDNS":["127.0.0.1"],"peers":[{{"publicKey":"{}","endpoint":"127.0.0.1:{port}"}}]}}"#,
                hex(&client_private),
                hex(&server_public)
            ))
            .expect("client config"),
        )
        .expect("device");
        let wireguard = WireGuardOut::with_dns_port(client, dns_address.port()).expect("outbound");
        assert_eq!(
            wireguard.resolve("example.test", 7),
            vec!["127.0.0.1:7".parse().expect("address")]
        );
        answer
            .recv_timeout(Duration::from_secs(5))
            .expect("the resolver asked the tunnel's DNS server");

        let listener = TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        wireguard.serve_tcp(
            Connection::from(tun),
            &Destination::Name("example.test".to_owned(), echo_address.port()),
            b"head",
        );
        app.write_all(b"hello").expect("write");
        let mut received = [0u8; 9];
        app.read_exact(&mut received).expect("read");
        assert_eq!(&received, b"headhello");
    }

    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp() {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("dns tcp");
        let dns_address = tcp.local_addr().expect("dns address");
        let udp = UdpSocket::bind(dns_address).expect("dns udp");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let Ok((n, from)) = udp.recv_from(&mut buf) else {
                return;
            };
            let Some(question) = ferrox_core::dns::parse_query(&buf[..n]) else {
                return;
            };
            let Some(mut reply) =
                ferrox_core::dns::ip_answer(&question, 0, 60, &[vec![192, 0, 2, 9]])
            else {
                return;
            };
            reply[2] |= 0x02;
            let _ = udp.send_to(&reply, from);
        });
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = tcp.accept() else {
                return;
            };
            let mut prefix = [0u8; 2];
            if stream.read_exact(&mut prefix).is_err() {
                return;
            }
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            if stream.read_exact(&mut query).is_err() {
                return;
            }
            let Some(question) = ferrox_core::dns::parse_query(&query) else {
                return;
            };
            let Some(reply) = ferrox_core::dns::ip_answer(&question, 0, 60, &[vec![127, 0, 0, 1]])
            else {
                return;
            };
            let len = u16::try_from(reply.len()).expect("fits");
            let mut framed = Vec::with_capacity(2 + reply.len());
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(&reply);
            let _ = stream.write_all(&framed);
        });

        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let hex = ferrox_core::foxy::account::hex_encode;
        let server_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex(&server_private),
            hex(&client_public)
        );
        let inbound =
            crate::json::parse(&format!(r#"{{"settings":{server_settings}}}"#)).expect("inbound");
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let port = serve_inbound(&inbound, &out, "127.0.0.1:0").expect("serve");

        let client = DeviceConfig::from_json(
            &crate::json::parse(&format!(
                r#"{{"secretKey":"{}","address":["10.0.0.2"],"remoteDNS":["127.0.0.1"],"peers":[{{"publicKey":"{}","endpoint":"127.0.0.1:{port}"}}]}}"#,
                hex(&client_private),
                hex(&server_public)
            ))
            .expect("client config"),
        )
        .expect("device");
        let wireguard = WireGuardOut::with_dns_port(client, dns_address.port()).expect("outbound");
        assert_eq!(
            wireguard.resolve("example.test", 7),
            vec!["127.0.0.1:7".parse().expect("address")]
        );
    }
}
