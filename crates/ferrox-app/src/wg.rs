//! `WireGuard`'s runtime: the UDP socket, the per-peer tunnels, and the threads
//! that move an inner packet between the tunnel and the userspace stack.
//!
//! One reader owns the tunnel state. It decrypts every datagram, routes it to
//! the peer that authenticated it, and hands a TCP packet to `smoltcp` or a UDP
//! packet to the lane that asked. Writers only enqueue inner packets, so no
//! flow ever locks a session or races a counter.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ferrox_core::wireguard::device::{tai64n, Event, Tunnel};
use ferrox_core::wireguard::handshake::{
    check_mac1, INITIATION_SIZE, TYPE_INITIATION, TYPE_RESPONSE,
};
use ferrox_core::wireguard::transport::clear_reserved;

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{Destination, Outbound};
use crate::wg_stack::{self, ClientFlow, Packet, UdpRoutes};
use crate::wireguard::{DeviceConfig, PeerConfig};

/// The reader's wait for a datagram: it also bounds how long a queued inner
/// packet waits before the tunnel encrypts it.
const IO_TICK: Duration = Duration::from_millis(10);

/// A client outbound: the flow channel, the inner-packet queue the stack and
/// the datagram lanes write, and the lane table the reader routes replies by.
#[derive(Debug)]
pub(crate) struct WireGuardOut {
    config: Arc<DeviceConfig>,
    flows: Sender<ClientFlow>,
    to_tunnel: Sender<Vec<u8>>,
    routes: UdpRoutes,
    stop: Arc<AtomicBool>,
}

impl WireGuardOut {
    pub(crate) fn new(config: DeviceConfig) -> Result<Self, String> {
        if config.is_client == Some(false) {
            return Err("a wireguard outbound must set `isClient: true`".to_owned());
        }
        if !config.no_kernel_tun {
            eprintln!(
                "wireguard: `noKernelTun` is false, so the reference opens a kernel TUN; this tree opens none and serves the userspace stack"
            );
        }
        if !config.dns.is_empty() {
            eprintln!("wireguard: `remoteDNS` is not carried; names resolve on the host");
        }
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
        })
    }

    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        self.config.peers.first().and_then(|peer| peer.endpoint)
    }

    pub(crate) fn serve_tcp(&self, client: Connection, asked: &Destination, prefix: &[u8]) {
        let Some(destination) = asked.socket() else {
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
        );
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
    loop {
        if stop
            .as_ref()
            .is_some_and(|stop| stop.load(Ordering::Relaxed))
        {
            return;
        }
        let now = started.elapsed().as_millis() as u64;
        let mut events = Vec::new();
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
                    let mut incoming = Vec::new();
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
    use std::io::{Read as _, Write as _};
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
}
