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
use ferrox_core::wireguard::transport::{
    check_mac2, clear_reserved, cookie_encryption_key, create_reply, COOKIE_NONCE_SIZE,
};

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{Destination, Outbound};
use crate::wg_stack::{self, ip_bytes, ClientFlow, Packet, UdpRoutes};
use crate::wireguard::{DeviceConfig, PeerConfig};

/// The reader's wait for a datagram: it also bounds how long a queued inner
/// packet waits before the tunnel encrypts it, because a packet queued while
/// the read waits has no datagram to interrupt it.
const IO_TICK: Duration = Duration::from_millis(1);
/// The kernel queue one socket keeps for a fast link, as the reference's bind
/// asks for: a default queue holds a few milliseconds of a gigabit stream and
/// a single scheduling gap drops the datagrams a TCP flow then retransmits.
const SOCKET_BUFFER: usize = 7 << 20;
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
/// How long one remote-DNS query waits before it is sent again: the tunnel may
/// still be handshaking when the first datagram is offered, and a lost query
/// is cheaper to repeat than to fail.
const DNS_RETRY: Duration = Duration::from_secs(1);
/// The source-port range reserved for remote-DNS queries, below the ephemeral
/// range the datagram lanes bind.
const DNS_PORT_FIRST: u16 = 1024;
const DNS_PORT_LAST: u16 = 49_152;
/// The most names one outbound caches.
const DNS_CACHE: usize = 256;
/// The reference's cookie lifetime and its one-second under-load tail.
const COOKIE_REFRESH: u64 = 120_000;
const UNDER_LOAD: u64 = 1_000;
/// The reference queues 1024 handshakes and treats an eighth of that as load.
const COOKIE_AFTER: u32 = 128;
/// The responder's rotating cookie secret and handshake-load window. `now` is
/// the reader's monotonic milliseconds, not wall time.
#[derive(Default)]
struct CookieGuard {
    secret: [u8; 32],
    secret_set: Option<u64>,
    window: u64,
    initiations: u32,
    under_load_until: u64,
}

impl CookieGuard {
    fn observe(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.window) >= UNDER_LOAD {
            self.window = now;
            self.initiations = 0;
        }
        self.initiations = self.initiations.saturating_add(1);
        if self.initiations >= COOKIE_AFTER && now >= self.under_load_until {
            self.under_load_until = now.saturating_add(UNDER_LOAD);
        }
        now < self.under_load_until
    }

    fn check(&self, now: u64, packet: &[u8], source: &[u8]) -> bool {
        self.secret_set
            .is_some_and(|set| now.saturating_sub(set) <= COOKIE_REFRESH)
            && check_mac2(packet, &self.secret, source)
    }

    fn reply(
        &mut self,
        now: u64,
        packet: &[u8],
        source: &[u8],
        encryption_key: &[u8; 32],
    ) -> Option<[u8; 64]> {
        if self
            .secret_set
            .is_none_or(|set| now.saturating_sub(set) > COOKIE_REFRESH)
        {
            getrandom::fill(&mut self.secret).ok()?;
            self.secret_set = Some(now);
        }
        let mut nonce = [0u8; COOKIE_NONCE_SIZE];
        getrandom::fill(&mut nonce).ok()?;
        let receiver = u32::from_le_bytes(packet.get(4..8)?.try_into().ok()?);
        create_reply(
            packet,
            receiver,
            &self.secret,
            source,
            encryption_key,
            &nonce,
        )
    }
}

/// The source address bytes the reference hashes: family bytes then the port in
/// big-endian, as `netip.AddrPort.MarshalBinary` writes them.
fn endpoint_bytes(source: SocketAddr) -> ([u8; 18], usize) {
    let mut bytes = [0u8; 18];
    let width = match source.ip() {
        IpAddr::V4(address) => {
            bytes[..4].copy_from_slice(&address.octets());
            4
        }
        IpAddr::V6(address) => {
            bytes[..16].copy_from_slice(&address.octets());
            16
        }
    };
    bytes[width..width + 2].copy_from_slice(&source.port().to_be_bytes());
    (bytes, width + 2)
}

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
        let destinations = self.destinations(asked);
        if destinations.is_empty() {
            eprintln!("wireguard: no peer allows `{asked:?}`");
            return;
        }
        if self
            .flows
            .send(ClientFlow {
                client,
                destinations,
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
            &|host, port| self.destinations(&Destination::Name(host.to_owned(), port)),
        );
    }

    /// The addresses to race: a literal stands, and a name becomes every answer
    /// a peer routes. The stack caps how many it dials at once.
    fn destinations(&self, asked: &Destination) -> Vec<SocketAddr> {
        let addresses = match asked {
            Destination::Address(address) => vec![*address],
            Destination::Name(host, port) => self.resolve(host, *port),
        };
        addresses
            .into_iter()
            .filter(|address| {
                self.config
                    .peers
                    .iter()
                    .any(|peer| peer.routes(address.ip()))
            })
            .collect()
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
        if self.to_tunnel.send(packet.clone()).is_err() {
            self.remove_dns_route(port);
            return None;
        }
        let deadline = Instant::now() + DNS_TIMEOUT;
        let mut resend_at = Instant::now() + DNS_RETRY;
        let result = loop {
            let now = Instant::now();
            if now >= deadline {
                break None;
            }
            if now >= resend_at {
                if self.to_tunnel.send(packet.clone()).is_err() {
                    break None;
                }
                resend_at = now + DNS_RETRY;
            }
            let until = resend_at.min(deadline);
            if until <= now {
                break None;
            }
            let inner = match replies.recv_timeout(until - now) {
                Ok(inner) => inner,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break None,
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
            let payload = datagram.payload;
            if let Some(header) = payload.get(..12) {
                let response_id = u16::from_be_bytes([header[0], header[1]]);
                let flags = u16::from_be_bytes([header[2], header[3]]);
                if response_id == id && flags.trailing_zeros() >= 4 && flags & 0x0200 != 0 {
                    break self.exchange_tcp(server, &query, id, qtype);
                }
            }
            let Some(answer) = parse_answer(payload) else {
                continue;
            };
            if answer.id != id || answer.rcode != 0 {
                continue;
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
                destinations: vec![SocketAddr::new(server, self.dns_port)],
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
#[allow(clippy::too_many_lines)]
fn io(
    config: DeviceConfig,
    socket: UdpSocket,
    from_tunnel: Receiver<Vec<u8>>,
    to_stack: Sender<Packet>,
    routes: Option<UdpRoutes>,
    stop: Option<Arc<AtomicBool>>,
) {
    let _ = socket.set_read_timeout(Some(IO_TICK));
    widen(&socket);
    let ipv6_socket = socket.local_addr().is_ok_and(|address| address.is_ipv6());
    let epoch = tai64n_now();
    let mut peers = peers(&config, epoch);
    let mut cookies = CookieGuard::default();
    let started = Instant::now();
    let mut buf = vec![0u8; 65_535];
    let mut incoming = Vec::new();
    loop {
        if stop
            .as_ref()
            .is_some_and(|stop| stop.load(Ordering::Relaxed))
        {
            return;
        }
        let now = started.elapsed().as_millis() as u64;
        let mut events = Vec::new();
        for _ in 0..TX_DRAIN {
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
                ipv6_socket,
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
            ipv6_socket,
        );

        match socket.recv_from(&mut buf) {
            Ok((n, source)) if n >= 4 => {
                let source = recv_endpoint(source, ipv6_socket);
                let kind = u32::from(buf[0]);
                if kind == TYPE_INITIATION && n == INITIATION_SIZE {
                    let under_load = cookies.observe(now);
                    let mut packet = buf[..n].to_vec();
                    clear_reserved(&mut packet);
                    handle_initiation(
                        &mut peers,
                        now,
                        source,
                        &packet,
                        &socket,
                        &to_stack,
                        &mut cookies,
                        under_load,
                    );
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
                        ipv6_socket,
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

/// The most tunnel packets one socket turn forwards before it reads again, so
/// a backlog on the stack's channel cannot leave a burst wider than a peer's
/// receive queue.
const TX_DRAIN: usize = 64;

#[allow(clippy::too_many_arguments)]
fn handle_initiation(
    peers: &mut [Peer],
    now: u64,
    source: SocketAddr,
    packet: &[u8],
    socket: &UdpSocket,
    to_stack: &Sender<Packet>,
    cookies: &mut CookieGuard,
    under_load: bool,
) {
    let Some(peer) = peers.first() else {
        return;
    };
    if !check_mac1(packet, &peer.tunnel.public()) {
        return;
    }
    if under_load {
        let (source_bytes, source_width) = endpoint_bytes(source);
        let source_bytes = &source_bytes[..source_width];
        if !cookies.check(now, packet, source_bytes) {
            if let Some(reply) = cookies.reply(
                now,
                packet,
                source_bytes,
                &cookie_encryption_key(&peer.tunnel.public()),
            ) {
                let ipv6 = socket.local_addr().is_ok_and(|address| address.is_ipv6());
                let _ = socket.send_to(&reply, send_endpoint(source, ipv6));
            }
            return;
        }
    }
    let Some(state) = peers.first().and_then(|peer| {
        let message: &[u8; INITIATION_SIZE] = packet.try_into().ok()?;
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
    let ipv6 = socket.local_addr().is_ok_and(|address| address.is_ipv6());
    flush(
        &mut events,
        socket,
        to_stack,
        None,
        peers,
        Some(index),
        ipv6,
    );
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
    ipv6_socket: bool,
) {
    for event in events.drain(..) {
        match event {
            Event::Send { endpoint, packet } => {
                let _ = socket.send_to(&packet, send_endpoint(endpoint, ipv6_socket));
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
    let mut v4 = false;
    let mut v6 = false;
    let mut any = false;
    for endpoint in config.peers.iter().filter_map(|peer| peer.endpoint) {
        any = true;
        if endpoint.is_ipv4() {
            v4 = true;
        } else {
            v6 = true;
        }
    }
    if !any {
        return Err("wireguard client: no peer has an `endpoint`".to_owned());
    }
    if v4 && v6 {
        return bind_dual_stack();
    }
    let unspecified = if v4 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    UdpSocket::bind(unspecified)
        .map_err(|error| format!("cannot bind wireguard's UDP socket: {error}"))
}

fn bind_dual_stack() -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| format!("cannot create wireguard's dual-stack socket: {error}"))?;
    socket
        .set_only_v6(false)
        .map_err(|error| format!("cannot enable wireguard's dual-stack socket: {error}"))?;
    let address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    socket
        .bind(&address.into())
        .map_err(|error| format!("cannot bind wireguard's dual-stack socket: {error}"))?;
    Ok(socket.into())
}

/// Ask the kernel for the queue the reference gives its `WireGuard` socket. It
/// may cap the request at `net.core.*mem_max`; the default is the smaller
/// number, and a larger ask never costs the flow anything.
fn widen(socket: &UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(SOCKET_BUFFER);
    let _ = sock.set_send_buffer_size(SOCKET_BUFFER);
}

fn send_endpoint(endpoint: SocketAddr, ipv6: bool) -> SocketAddr {
    match endpoint {
        SocketAddr::V4(address) if ipv6 => SocketAddr::new(
            IpAddr::V6(Ipv4Addr::to_ipv6_mapped(address.ip())),
            address.port(),
        ),
        _ => endpoint,
    }
}

fn recv_endpoint(socket: SocketAddr, ipv6: bool) -> SocketAddr {
    match socket {
        SocketAddr::V6(address) if ipv6 => match address.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), address.port()),
            None => SocketAddr::V6(address),
        },
        _ => socket,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn sent(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .find_map(|event| match event {
                Event::Send { packet, .. } => Some(packet.clone()),
                Event::Data(_) => None,
            })
            .expect("an outbound packet")
    }

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
        flush(
            &mut events,
            &socket,
            &to_stack,
            None,
            &peers,
            Some(1),
            false,
        );
        assert!(packets.try_recv().is_err(), "the owner is peer zero");
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 1, 2, 3]);
        let mut events = vec![Event::Data(packet)];
        flush(
            &mut events,
            &socket,
            &to_stack,
            None,
            &peers,
            Some(1),
            false,
        );
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
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
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
    #[allow(clippy::too_many_lines)]
    fn a_name_races_every_routed_answer_before_the_flow() {
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns");
        let dns_address = dns.local_addr().expect("dns address");
        let (answered, answer) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let mut seen = 0;
            loop {
                let Ok((n, from)) = dns.recv_from(&mut buf) else {
                    return;
                };
                seen += 1;
                // A tunnel still handshaking drops the first query; the resolver's retry carries it.
                if seen == 1 {
                    continue;
                }
                let Some(question) = ferrox_core::dns::parse_query(&buf[..n]) else {
                    continue;
                };
                let Some(reply) = ferrox_core::dns::ip_answer(
                    &question,
                    0,
                    60,
                    &[vec![192, 0, 2, 1], vec![127, 0, 0, 1]],
                ) else {
                    continue;
                };
                if dns.send_to(&reply, from).is_ok() {
                    let _ = answered.send(());
                }
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

        let dead = UdpSocket::bind("127.0.0.1:0").expect("dead endpoint");
        let client = DeviceConfig {
            secret: client_private,
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![
                PeerConfig {
                    public: server_public,
                    preshared: [0; 32],
                    endpoint: Some(dead.local_addr().expect("dead address")),
                    keepalive: 0,
                    allowed: vec![("192.0.2.1".parse().unwrap(), 32)],
                },
                PeerConfig {
                    public: server_public,
                    preshared: [0; 32],
                    endpoint: Some(format!("127.0.0.1:{port}").parse().unwrap()),
                    keepalive: 0,
                    allowed: vec![("127.0.0.1".parse().unwrap(), 32)],
                },
            ],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            dns: vec!["127.0.0.1".parse().unwrap()],
        };
        let wireguard = WireGuardOut::with_dns_port(client, dns_address.port()).expect("outbound");
        assert_eq!(
            wireguard.resolve("example.test", 7),
            vec![
                "192.0.2.1:7".parse().expect("address"),
                "127.0.0.1:7".parse().expect("address"),
            ]
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

    /// A truncated UDP response retries the same DNS question over TCP on the reserved server port.
    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp() {
        let (tcp, udp, dns_address) = (0..64)
            .find_map(|_| {
                let udp = UdpSocket::bind("127.0.0.1:0").expect("dns udp");
                let address = udp.local_addr().expect("dns address");
                match TcpListener::bind(address) {
                    Ok(tcp) => Some((tcp, udp, address)),
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => None,
                    Err(error) => panic!("dns tcp: {error}"),
                }
            })
            .expect("a port free for both DNS transports");
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
            reply.truncate(reply.len() - 4);
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

    #[test]
    fn a_client_with_peers_in_both_families_binds_a_dual_stack_socket() {
        let config = DeviceConfig {
            secret: [0x11; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![
                PeerConfig {
                    public: [0x22; 32],
                    preshared: [0; 32],
                    endpoint: Some("127.0.0.1:9".parse().unwrap()),
                    keepalive: 0,
                    allowed: vec![("0.0.0.0".parse().unwrap(), 0)],
                },
                PeerConfig {
                    public: [0x33; 32],
                    preshared: [0; 32],
                    endpoint: Some("[::1]:9".parse().unwrap()),
                    keepalive: 0,
                    allowed: vec![("::".parse().unwrap(), 0)],
                },
            ],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            dns: Vec::new(),
        };
        let socket = bind_socket(&config).expect("dual-stack socket");
        assert!(socket.local_addr().expect("address").is_ipv6());
        let v4: SocketAddr = "127.0.0.1:7".parse().unwrap();
        let mapped = send_endpoint(v4, true);
        assert_eq!(mapped, "[::ffff:127.0.0.1]:7".parse().unwrap());
        assert_eq!(recv_endpoint(mapped, true), v4);
    }

    #[test]
    fn the_handshake_window_requires_cookies_after_an_eighth_of_the_queue() {
        let mut guard = CookieGuard::default();
        for _ in 0..(COOKIE_AFTER - 1) {
            assert!(!guard.observe(0));
        }
        assert!(guard.observe(0), "the 128th initiation is under load");
        assert!(guard.observe(500), "the load tail outlives the burst");
        assert!(!guard.observe(1_001), "a quiet second clears the window");
    }

    #[test]
    fn cookie_source_bytes_are_the_reference_address_port_form() {
        let (v4, width) = endpoint_bytes("127.0.0.1:51820".parse().unwrap());
        assert_eq!(&v4[..width], &[127, 0, 0, 1, 0xca, 0x6c]);
        let (v6, width) = endpoint_bytes("[::1]:53".parse().unwrap());
        let mut expected = [0u8; 18];
        expected[15] = 1;
        expected[16..].copy_from_slice(&53u16.to_be_bytes());
        assert_eq!(&v6[..width], &expected);
    }

    #[test]
    fn a_loaded_responder_issues_a_cookie_and_accepts_the_retry() {
        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let config = DeviceConfig {
            secret: server_private,
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: vec![PeerConfig {
                public: client_public,
                preshared: [0; 32],
                endpoint: None,
                keepalive: 0,
                allowed: vec![("10.0.0.2".parse().unwrap(), 32)],
            }],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            dns: Vec::new(),
        };
        let server = UdpSocket::bind("127.0.0.1:0").expect("server");
        let server_address = server.local_addr().expect("server address");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        let client_address = client.local_addr().expect("client address");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");

        let mut peer = peers(&config, [0; 12]);
        let (to_stack, _) = mpsc::channel();
        let mut guard = CookieGuard::default();
        let mut initiator = Tunnel::new(
            client_private,
            server_public,
            [0; 32],
            server_address,
            0,
            [0; 3],
            [0; 12],
        );
        let mut events = Vec::new();
        assert!(initiator.initiate(0, &mut events));
        let first = sent(&events);
        handle_initiation(
            &mut peer,
            0,
            client_address,
            &first,
            &server,
            &to_stack,
            &mut guard,
            true,
        );

        let mut cookie = [0u8; 64];
        let (n, _) = client.recv_from(&mut cookie).expect("cookie reply");
        assert_eq!(n, cookie.len());
        assert_eq!(
            u32::from(cookie[0]),
            ferrox_core::wireguard::transport::TYPE_COOKIE_REPLY
        );

        let mut incoming = Vec::new();
        initiator.receive(0, server_address, &mut cookie, &mut incoming);
        let retry = sent(&incoming);
        assert!(
            retry[INITIATION_SIZE - 16..].iter().any(|byte| *byte != 0),
            "mac2 is set"
        );
        handle_initiation(
            &mut peer,
            1,
            client_address,
            &retry,
            &server,
            &to_stack,
            &mut guard,
            true,
        );

        let mut answer = [0u8; 128];
        let (n, _) = client.recv_from(&mut answer).expect("handshake response");
        assert_eq!(u32::from(answer[0]), TYPE_RESPONSE);
        assert_eq!(n, 92);
    }
}
