//! The userspace IP stack a `WireGuard` tunnel carries: `smoltcp` owns the TCP
//! state machine, its windows and retransmits, while this file owns only the
//! bridge between a tunnel's inner packets and the local streams.
//!
//! A client connects a local flow to the destination it asked for; a server
//! listens on every destination address and port at once (`any_ip`, and a
//! wildcard listener raised per SYN), so a packet addressed to 192.0.2.1:7 is
//! accepted even though no interface owns that address. Datagrams do not need
//! the state machine: the tunnel carries them as UDP, and the tree's own
//! datagram lane dials them, so this file builds and parses their packets
//! directly and leaves their routing to the caller.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use ferrox_core::foxy::connectip::{
    icmp_echo_reply, udp_datagram, udp_from_packet, UdpDatagram, IPV4_HEADER, IPV6_HEADER,
    PROTOCOL_UDP,
};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    CongestionControl, RecvError, SendError, Socket as TcpSocket, SocketBuffer, State,
};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};

use crate::conn::Connection;
use crate::proxy::{serve_device_flow, serve_udp_lane, Destination, Outbound};
use crate::wireguard::DeviceConfig;

/// The bytes one direction of a TCP flow may buffer inside `smoltcp`: a 1 MiB
/// transfer needs no window larger than this, and five concurrent flows stay
/// under a few megabytes.
const TCP_BUFFER: usize = 256 * 1024;
/// The most listeners one inbound may hold across every destination port. Each
/// listener owns both TCP buffers, so a spoofed SYN stream must not grow the
/// set past a fixed share of memory.
const LISTENERS: usize = 64;
/// The most listeners one destination port may hold, so concurrent SYNs to one
/// service do not wait for a retransmit while the total stays bounded.
const LISTENERS_PER_PORT: usize = 8;
/// How long a listener may wait for a handshake before it is reclaimed, so a
/// spoofed SYN cannot hold a slot for the life of the inbound.
const LISTENER_TTL: Duration = Duration::from_secs(60);
/// The stack's poll interval when no packet arrived: retransmit timers are
/// seconds, so ten milliseconds is latency without a spin.
const TICK: Duration = Duration::from_millis(10);
/// The most inner packets the tunnel reader may queue before the stack drains
/// them; past it the oldest is dropped, as a full device would drop.
const RX_PACKETS: usize = 4096;
/// The most segments one poll may hand to the tunnel: half the queue the
/// stream writer drains, so a burst of every flow's window cannot overrun it
/// and the stack keeps the rest, closing its window, instead of losing it.
const TX_PACKETS: usize = crate::masque::QUEUE / 2;
/// The most server datagram lanes one inbound may hold.
const UDP_FLOWS: usize = 4096;

/// One decrypted inner packet and the peer that authenticated it.
pub(crate) struct Packet {
    pub(crate) peer: [u8; 32],
    pub(crate) bytes: Vec<u8>,
}

/// One local stream the client asks the stack to connect.
pub(crate) struct ClientFlow {
    pub(crate) client: Connection,
    pub(crate) destination: SocketAddr,
    pub(crate) prefix: Vec<u8>,
}

/// The route table of live client datagram lanes, keyed by the loopback relay
/// port each lane bound: an inner reply names that port, so the reader hands it
/// to the lane that asked.
pub(crate) type UdpRoutes = Arc<Mutex<HashMap<u16, Sender<Vec<u8>>>>>;

/// An in-memory IP device: the reader pushes inner packets into `rx`, and every
/// packet `smoltcp` emits is left in `tx` for the tunnel writer.
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    fn push(&mut self, packet: Vec<u8>) {
        if self.rx.len() >= RX_PACKETS {
            self.rx.pop_front();
        }
        self.rx.push_back(packet);
    }

    /// A path MTU an ICMP Packet Too Big names narrows every later segment; a packet that names no usable MTU leaves it alone.
    fn absorb(&mut self, packet: &[u8]) -> bool {
        let Some(mtu) = icmp_mtu(packet) else {
            return false;
        };
        if mtu >= self.mtu {
            return false;
        }
        self.mtu = mtu;
        true
    }
}

struct QueueRx {
    buffer: Vec<u8>,
}

impl RxToken for QueueRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct QueueTx<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let answer = f(&mut buffer);
        self.tx.push_back(buffer);
        answer
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = QueueRx
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        Some((QueueRx { buffer }, QueueTx { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= TX_PACKETS {
            return None;
        }
        Some(QueueTx { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// One TCP flow and the local stream on the other side of it. `pending_down`
/// holds bytes the local socket refused because its send buffer was full;
/// `pending_up` holds bytes read locally that the TCP window has not accepted.
#[allow(clippy::struct_excessive_bools)]
struct Flow {
    handle: SocketHandle,
    local: Connection,
    local_port: u16,
    pending_down: VecDeque<Vec<u8>>,
    pending_up: Vec<u8>,
    up_eof: bool,
    sent_fin: bool,
    down_eof: bool,
    down_shutdown: bool,
    established: bool,
    done: bool,
}

impl Flow {
    fn new(handle: SocketHandle, local: Connection, local_port: u16) -> Self {
        Self {
            handle,
            local,
            local_port,
            pending_down: VecDeque::new(),
            pending_up: Vec::new(),
            up_eof: false,
            sent_fin: false,
            down_eof: false,
            down_shutdown: false,
            established: false,
            done: false,
        }
    }
}

/// What a stack loop sends the tunnel writer.
type ToTunnel = Sender<Vec<u8>>;
/// What the tunnel reader sends the stack.
type Packets = Receiver<Packet>;

/// Run the client stack until the outbound is dropped.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn client(
    config: DeviceConfig,
    to_tunnel: ToTunnel,
    packets: Packets,
    flows: Receiver<ClientFlow>,
) {
    let mut stack = ClientStack::new(&config, to_tunnel);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut progress = false;
        while let Ok(flow) = flows.try_recv() {
            if let Err(error) = stack.connect(flow) {
                eprintln!("wireguard client: {error}");
            }
            progress = true;
        }
        match packets.recv_timeout(TICK) {
            Ok(packet) => {
                if inner_protocol(&packet.bytes) == Some(PROTOCOL_TCP) {
                    stack.device.push(packet.bytes);
                    progress = true;
                } else if stack.answer_echo(&packet.bytes) || stack.device.absorb(&packet.bytes) {
                    progress = true;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
        stack.poll(&mut buf);
        if progress {
            stack.poll(&mut buf);
        }
    }
}

/// Run the server stack until its inbound is dropped.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn server(config: DeviceConfig, to_tunnel: ToTunnel, packets: Packets, out: Outbound) {
    let mut stack = ServerStack::new(&config, to_tunnel, out);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match packets.recv_timeout(TICK) {
            Ok(packet) => stack.receive(packet),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
        stack.poll(&mut buf);
    }
}

struct ClientStack {
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: Vec<Flow>,
    ports: HashSet<u16>,
    next_port: u16,
    to_tunnel: ToTunnel,
    addresses: Vec<IpAddr>,
    started: StdInstant,
}

impl ClientStack {
    fn new(config: &DeviceConfig, to_tunnel: ToTunnel) -> Self {
        let mut device = QueueDevice::new(config.mtu);
        let mut iface = Interface::new(
            iface_config(0x5eed_1234),
            &mut device,
            Instant::from_millis(0),
        );
        add_addresses(&mut iface, &config.addresses);
        add_default_routes(&mut iface, &config.addresses);
        Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows: Vec::new(),
            ports: HashSet::new(),
            next_port: 49_152,
            to_tunnel,
            addresses: config.addresses.clone(),
            started: StdInstant::now(),
        }
    }

    fn answer_echo(&self, packet: &[u8]) -> bool {
        answer_echo(packet, &self.addresses, &self.to_tunnel)
    }

    fn connect(&mut self, flow: ClientFlow) -> std::io::Result<()> {
        if flow.destination.port() == 0 || flow.destination.ip().is_unspecified() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("destination {} is not a TCP endpoint", flow.destination),
            ));
        }
        let Some(local_port) = self.free_port() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "wireguard has no free local ephemeral port",
            ));
        };
        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(CongestionControl::Reno);
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::from(flow.destination),
                IpListenEndpoint::from(local_port),
            )
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("cannot connect {}: {error:?}", flow.destination),
                )
            })?;
        flow.client.set_nonblocking(true)?;
        let handle = self.sockets.add(socket);
        self.ports.insert(local_port);
        let mut routed = Flow::new(handle, flow.client, local_port);
        routed.pending_up = flow.prefix;
        self.flows.push(routed);
        Ok(())
    }

    fn free_port(&mut self) -> Option<u16> {
        let span = usize::from(u16::MAX) - 49_152 + 1;
        for _ in 0..span {
            let port = self.next_port.max(49_152);
            self.next_port = if port == u16::MAX { 49_152 } else { port + 1 };
            if !self.ports.contains(&port) {
                return Some(port);
            }
        }
        None
    }

    fn poll(&mut self, buf: &mut [u8]) {
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        for flow in &mut self.flows {
            pump(flow, &mut self.sockets, buf);
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(packet) = self.device.tx.pop_front() {
            if self.to_tunnel.send(packet).is_err() {
                return;
            }
        }
        self.flows.retain(|flow| {
            if flow.done {
                let _ = flow.local.shutdown(Shutdown::Both);
                self.sockets.remove(flow.handle);
                self.ports.remove(&flow.local_port);
                false
            } else {
                true
            }
        });
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.started.elapsed().as_millis() as i64)
    }
}

struct Listener {
    handle: SocketHandle,
    since: StdInstant,
}

struct UdpLane {
    uplink: UdpSocket,
    stop: Arc<AtomicBool>,
    last_used: Arc<AtomicU64>,
}

fn elapsed_ms(started: StdInstant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct ServerStack {
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: Vec<Flow>,
    listeners: HashMap<u16, Vec<Listener>>,
    udp: HashMap<([u8; 32], SocketAddr, SocketAddr), UdpLane>,
    to_tunnel: ToTunnel,
    out: Outbound,
    addresses: Vec<IpAddr>,
    started: StdInstant,
}

impl ServerStack {
    fn new(config: &DeviceConfig, to_tunnel: ToTunnel, out: Outbound) -> Self {
        let mut device = QueueDevice::new(config.mtu);
        let mut iface = Interface::new(
            iface_config(0x5eed_5678),
            &mut device,
            Instant::from_millis(0),
        );
        add_addresses(&mut iface, &config.addresses);
        add_default_routes(&mut iface, &config.addresses);
        iface.set_any_ip(true);
        Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows: Vec::new(),
            listeners: HashMap::new(),
            udp: HashMap::new(),
            to_tunnel,
            out,
            addresses: config.addresses.clone(),
            started: StdInstant::now(),
        }
    }

    fn receive(&mut self, packet: Packet) {
        match inner_protocol(&packet.bytes) {
            Some(PROTOCOL_TCP) => self.device.push(packet.bytes),
            Some(PROTOCOL_UDP) => self.datagram(packet.peer, &packet.bytes),
            _ => {
                if !self.answer_echo(&packet.bytes) {
                    self.device.absorb(&packet.bytes);
                }
            }
        }
    }

    fn answer_echo(&self, packet: &[u8]) -> bool {
        answer_echo(packet, &self.addresses, &self.to_tunnel)
    }

    fn datagram(&mut self, peer: [u8; 32], bytes: &[u8]) {
        let Some(datagram) = udp_from_packet(bytes) else {
            return;
        };
        let Some(source) = socket_addr(datagram.source, datagram.source_port) else {
            return;
        };
        let Some(target) = socket_addr(datagram.destination, datagram.destination_port) else {
            return;
        };
        let key = (peer, source, target);
        if !self.udp.contains_key(&key) {
            if self.udp.len() >= UDP_FLOWS {
                return;
            }
            let last_used = Arc::new(AtomicU64::new(elapsed_ms(self.started)));
            let Some((uplink, stop)) =
                server_udp(key, self.started, &last_used, &self.out, &self.to_tunnel)
            else {
                return;
            };
            self.udp.insert(
                key,
                UdpLane {
                    uplink,
                    stop,
                    last_used,
                },
            );
        }
        let Some(lane) = self.udp.get_mut(&key) else {
            return;
        };
        lane.last_used
            .store(elapsed_ms(self.started), Ordering::Relaxed);
        let mut frame = Vec::with_capacity(32 + datagram.payload.len());
        let out = crate::proxy::socks_udp_frame(&mut frame, None, &target, datagram.payload);
        let _ = lane.uplink.send(out);
    }

    fn poll(&mut self, buf: &mut [u8]) {
        let mut arriving = std::mem::take(&mut self.device.rx);
        while let Some(packet) = arriving.pop_front() {
            if let Some(port) = tcp_syn_port(&packet) {
                self.listen(port);
            }
            self.device.rx.push_back(packet);
        }
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.handoff();
        for flow in &mut self.flows {
            pump(flow, &mut self.sockets, buf);
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(packet) = self.device.tx.pop_front() {
            if self.to_tunnel.send(packet).is_err() {
                return;
            }
        }
        self.flows.retain(|flow| {
            if flow.done {
                let _ = flow.local.shutdown(Shutdown::Both);
                self.sockets.remove(flow.handle);
                false
            } else {
                true
            }
        });
        let dead: Vec<(u16, SocketHandle)> = self
            .listeners
            .iter()
            .flat_map(|(port, listeners)| {
                listeners.iter().filter_map(|listener| {
                    let state = self.sockets.get::<TcpSocket>(listener.handle).state();
                    let live = matches!(state, State::Listen | State::SynReceived)
                        && listener.since.elapsed() < LISTENER_TTL;
                    (!live).then_some((*port, listener.handle))
                })
            })
            .collect();
        for (port, handle) in dead {
            self.sockets.remove(handle);
            if let Some(listeners) = self.listeners.get_mut(&port) {
                listeners.retain(|listener| listener.handle != handle);
                if listeners.is_empty() {
                    self.listeners.remove(&port);
                }
            }
        }
        let idle = u64::try_from(crate::budgets::udp_idle().as_millis()).unwrap_or(u64::MAX);
        let now = elapsed_ms(self.started);
        let stale: Vec<_> = self
            .udp
            .iter()
            .filter(|(_, lane)| now.saturating_sub(lane.last_used.load(Ordering::Relaxed)) >= idle)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            if let Some(lane) = self.udp.remove(&key) {
                lane.stop.store(true, Ordering::Relaxed);
            }
        }
    }

    fn listen(&mut self, port: u16) {
        let total = self.listeners.values().map(Vec::len).sum::<usize>();
        if total >= LISTENERS {
            return;
        }
        let listeners = self.listeners.entry(port).or_default();
        if listeners.len() >= LISTENERS_PER_PORT {
            return;
        }
        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(CongestionControl::Reno);
        if socket.listen(IpListenEndpoint { addr: None, port }).is_ok() {
            let handle = self.sockets.add(socket);
            listeners.push(Listener {
                handle,
                since: StdInstant::now(),
            });
        }
    }

    fn handoff(&mut self) {
        let mut ready = Vec::new();
        for (port, listeners) in &self.listeners {
            for listener in listeners {
                let socket = self.sockets.get::<TcpSocket>(listener.handle);
                if socket.state() == State::Established {
                    if let Some(local) = socket.local_endpoint() {
                        ready.push((*port, listener.handle, local));
                    }
                }
            }
        }
        for (port, handle, local) in ready {
            if let Some(listeners) = self.listeners.get_mut(&port) {
                listeners.retain(|listener| listener.handle != handle);
                if listeners.is_empty() {
                    self.listeners.remove(&port);
                }
            }
            let destination = match local.addr {
                IpAddress::Ipv4(address) => SocketAddr::new(IpAddr::V4(address), local.port),
                IpAddress::Ipv6(address) => SocketAddr::new(IpAddr::V6(address), local.port),
            };
            let Ok((tun, proxy)) = loopback() else {
                self.sockets.remove(handle);
                self.listen(port);
                continue;
            };
            let out = self.out.clone();
            std::thread::spawn(move || {
                let _ = serve_device_flow(
                    Connection::from(proxy),
                    &out,
                    &Destination::Address(destination),
                );
            });
            if tun.set_nonblocking(true).is_err() {
                self.sockets.remove(handle);
                self.listen(port);
                continue;
            }
            self.flows.push(Flow::new(handle, Connection::from(tun), 0));
            self.listen(port);
        }
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.started.elapsed().as_millis() as i64)
    }
}

/// Move bytes between one flow's local stream and its TCP socket. Every read and
/// write is nonblocking, so a slow local peer parks only its own buffers.
#[allow(clippy::too_many_lines)]
fn pump(flow: &mut Flow, sockets: &mut SocketSet<'_>, buf: &mut [u8]) {
    let socket = sockets.get_mut::<TcpSocket>(flow.handle);
    if matches!(socket.state(), State::Established | State::CloseWait) {
        flow.established = true;
    }
    if socket.state() == State::Closed && !flow.established {
        flow.done = true;
    }

    let mut pending = std::mem::take(&mut flow.pending_down);
    while let Some(front) = pending.front_mut() {
        match flow.local.write(front) {
            Ok(0) => {
                flow.down_eof = true;
                break;
            }
            Ok(n) => {
                front.drain(..n);
                if front.is_empty() {
                    pending.pop_front();
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                flow.done = true;
                socket.abort();
                break;
            }
        }
    }
    flow.pending_down = pending;

    while flow.pending_down.is_empty() {
        match socket.recv_slice(buf) {
            Ok(0) | Err(RecvError::InvalidState) => break,
            Ok(n) => {
                let mut at = 0;
                while at < n {
                    match flow.local.write(&buf[at..n]) {
                        Ok(0) => {
                            flow.down_eof = true;
                            at = n;
                        }
                        Ok(written) => at += written,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            flow.pending_down.push_back(buf[at..n].to_vec());
                            at = n;
                        }
                        Err(_) => {
                            flow.done = true;
                            socket.abort();
                            at = n;
                        }
                    }
                }
            }
            Err(RecvError::Finished) => {
                flow.down_eof = true;
                break;
            }
        }
    }

    if flow.pending_up.is_empty() && !flow.up_eof && socket.can_send() {
        match flow.local.read(buf) {
            Ok(0) => flow.up_eof = true,
            Ok(n) => match socket.send_slice(&buf[..n]) {
                Ok(sent) if sent < n => flow.pending_up.extend_from_slice(&buf[sent..n]),
                Ok(_) => {}
                Err(SendError::InvalidState) => {
                    flow.done = true;
                    socket.abort();
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                flow.done = true;
                socket.abort();
            }
        }
    }
    if !flow.pending_up.is_empty() && socket.can_send() {
        match socket.send_slice(&flow.pending_up) {
            Ok(0) => {}
            Ok(n) => {
                flow.pending_up.drain(..n);
            }
            Err(SendError::InvalidState) => {
                flow.done = true;
                socket.abort();
            }
        }
    }
    if flow.up_eof && flow.pending_up.is_empty() && socket.is_open() && !flow.sent_fin {
        socket.close();
        flow.sent_fin = true;
    }
    if flow.down_eof && !flow.down_shutdown && flow.pending_down.is_empty() {
        let _ = flow.local.shutdown(Shutdown::Write);
        flow.down_shutdown = true;
    }
    if socket.state() == State::Closed && flow.established && flow.pending_down.is_empty() {
        flow.down_eof = true;
        flow.done = true;
    }
    if flow.sent_fin && flow.down_eof && socket.state() == State::Closed {
        flow.done = true;
    }
}

fn loopback() -> std::io::Result<(std::net::TcpStream, std::net::TcpStream)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let tun = std::net::TcpStream::connect(address)?;
    let (proxy, _) = listener.accept()?;
    Ok((tun, proxy))
}

fn iface_config(seed: u64) -> IfaceConfig {
    let mut config = IfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = seed;
    config
}

fn add_addresses(iface: &mut Interface, addresses: &[IpAddr]) {
    iface.update_ip_addrs(|slots| {
        for address in addresses {
            let prefix = if address.is_ipv4() { 24 } else { 64 };
            let cidr = IpCidr::new(IpAddress::from(*address), prefix);
            let _ = slots.push(cidr);
        }
    });
}

/// A default route via the first configured address of each family. The bridge
/// is `Medium::Ip`, so the gateway is only a route-table choice; the packet
/// keeps the destination the flow asked for.
fn add_default_routes(iface: &mut Interface, addresses: &[IpAddr]) {
    if let Some(IpAddr::V4(address)) = addresses.iter().find(|address| address.is_ipv4()) {
        let _ = iface.routes_mut().add_default_ipv4_route(*address);
    }
    if let Some(IpAddr::V6(address)) = addresses.iter().find(|address| address.is_ipv6()) {
        let _ = iface.routes_mut().add_default_ipv6_route(*address);
    }
}

/// The destination port of an unfragmented TCP SYN, the packet that raises a
/// listener on a server that owns none of the addresses it receives.
fn tcp_syn_port(packet: &[u8]) -> Option<u16> {
    let tcp = match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet.first()? & 0x0f) * 4;
            if *packet.get(9)? != PROTOCOL_TCP || header < IPV4_HEADER {
                return None;
            }
            packet.get(header..)?
        }
        6 => {
            if *packet.get(6)? != PROTOCOL_TCP {
                return None;
            }
            packet.get(IPV6_HEADER..)?
        }
        _ => return None,
    };
    let flags = *tcp.get(13)?;
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None;
    }
    Some(u16::from_be_bytes([*tcp.get(2)?, *tcp.get(3)?]))
}

/// Whether an inner packet carries TCP, which the stack takes, or UDP, which
/// the datagram lane takes.
pub(crate) fn inner_protocol(packet: &[u8]) -> Option<u8> {
    match packet.first()? >> 4 {
        4 => packet.get(9).copied(),
        6 => packet.get(6).copied(),
        _ => None,
    }
}

/// The inner source and destination addresses of an IPv4 or IPv6 packet.
pub(crate) fn inner_addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 => {
            let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let destination: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some((IpAddr::from(source), IpAddr::from(destination)))
        }
        6 => {
            let source: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let destination: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some((IpAddr::from(source), IpAddr::from(destination)))
        }
        _ => None,
    }
}

/// A client datagram lane: every frame the local SOCKS5 front writes becomes an
/// inner UDP packet, and the reply the tunnel returns is framed back to the last
/// app that spoke. The lane's relay port is also its inner source port, so the
/// reader routes a reply to exactly one lane.
pub(crate) fn client_udp(
    relay: &UdpSocket,
    config: &DeviceConfig,
    to_tunnel: &ToTunnel,
    routes: &UdpRoutes,
    associate: Option<&Connection>,
    resolve: &dyn Fn(&str, u16) -> Option<SocketAddr>,
) {
    let Ok(local) = relay.local_addr() else {
        return;
    };
    let port = local.port();
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    if let Ok(mut table) = routes.lock() {
        table.insert(port, reply_tx);
    }
    let _ = relay.set_read_timeout(Some(TICK));
    if let Some(associate) = associate {
        let _ = associate.set_read_timeout(Some(crate::budgets::SESSION_POLL));
    }
    let mut buf = crate::proxy::udp_buffer();
    let mut frame = Vec::new();
    let mut app: Option<SocketAddr> = None;
    let mut quiet = StdInstant::now();
    loop {
        while let Ok(inner) = reply_rx.try_recv() {
            let Some(datagram) = udp_from_packet(&inner) else {
                continue;
            };
            if datagram.destination_port != port {
                continue;
            }
            let Some(app) = app else {
                continue;
            };
            let Some(remote) = socket_addr(datagram.source, datagram.source_port) else {
                continue;
            };
            let out = crate::proxy::socks_udp_frame(&mut frame, None, &remote, datagram.payload);
            let _ = relay.send_to(out, app);
            quiet = StdInstant::now();
        }
        match relay.recv_from(&mut buf) {
            Ok((n, sender)) => {
                quiet = StdInstant::now();
                let Some((destination, payload)) = crate::proxy::parse_socks_udp_dest(&buf[..n])
                else {
                    continue;
                };
                if app.is_some_and(|bound| bound != sender) {
                    continue;
                }
                app = Some(sender);
                let target = match destination {
                    Destination::Address(address) => address,
                    Destination::Name(host, port) => {
                        let Some(address) = resolve(&host, port) else {
                            continue;
                        };
                        address
                    }
                };
                let Some(inner_source) = config
                    .addresses
                    .iter()
                    .find(|address| address.is_ipv4() == target.is_ipv4())
                else {
                    continue;
                };
                let mut source_bytes = [0u8; 16];
                let mut destination_bytes = [0u8; 16];
                let source_bytes = ip_bytes_into(*inner_source, &mut source_bytes);
                let destination_bytes = ip_bytes_into(target.ip(), &mut destination_bytes);
                let mut packet = Vec::with_capacity(IPV4_HEADER + 8 + payload.len());
                let datagram = UdpDatagram {
                    source: source_bytes,
                    destination: destination_bytes,
                    source_port: port,
                    destination_port: target.port(),
                    payload,
                };
                if !udp_datagram(&datagram, &mut packet) {
                    continue;
                }
                if to_tunnel.send(packet).is_err() {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if associate.is_some_and(crate::proxy::peer_left)
                    || quiet.elapsed() >= crate::budgets::udp_idle()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if let Ok(mut table) = routes.lock() {
        table.remove(&port);
    }
}

/// A server datagram lane: the inner flow is one client source and one target,
/// so its loopback relay carries only that pair. The tree's own UDP dispatcher
/// dials the outbound, and a reader wraps every answer as the packet the client
/// expects back.
pub(crate) fn server_udp(
    flow: ([u8; 32], SocketAddr, SocketAddr),
    started: StdInstant,
    last_used: &Arc<AtomicU64>,
    out: &Outbound,
    to_tunnel: &ToTunnel,
) -> Option<(UdpSocket, Arc<AtomicBool>)> {
    let relay = UdpSocket::bind("127.0.0.1:0").ok()?;
    let relay_address = relay.local_addr().ok()?;
    let uplink = UdpSocket::bind("127.0.0.1:0").ok()?;
    uplink.connect(relay_address).ok()?;
    let reader = uplink.try_clone().ok()?;
    let (_, source, target) = flow;
    let outbound = match out {
        Outbound::Route(plan) => plan
            .pick(
                &Destination::Address(target),
                crate::router::Network::Udp,
                None,
            )
            .into_owned(),
        other => other.clone(),
    };
    let _ = relay.set_read_timeout(Some(crate::budgets::udp_idle()));
    std::thread::spawn(move || serve_udp_lane(&relay, &outbound, None));

    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop);
    let reader_activity = Arc::clone(last_used);
    let tunnel = to_tunnel.clone();
    std::thread::spawn(move || {
        let mut buf = crate::proxy::udp_buffer();
        let _ = reader.set_read_timeout(Some(TICK));
        loop {
            if reader_stop.load(Ordering::Relaxed) {
                break;
            }
            match reader.recv(&mut buf) {
                Ok(n) => {
                    let Some((_, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
                        continue;
                    };
                    let mut source_bytes = [0u8; 16];
                    let mut destination_bytes = [0u8; 16];
                    let source_bytes = ip_bytes_into(target.ip(), &mut source_bytes);
                    let destination_bytes = ip_bytes_into(source.ip(), &mut destination_bytes);
                    let mut packet = Vec::with_capacity(IPV4_HEADER + 8 + payload.len());
                    let datagram = UdpDatagram {
                        source: source_bytes,
                        destination: destination_bytes,
                        source_port: target.port(),
                        destination_port: source.port(),
                        payload,
                    };
                    if !udp_datagram(&datagram, &mut packet) {
                        continue;
                    }
                    reader_activity.store(elapsed_ms(started), Ordering::Relaxed);
                    if tunnel.send(packet).is_err() {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    });
    Some((uplink, stop))
}

fn socket_addr(bytes: &[u8], port: u16) -> Option<SocketAddr> {
    match bytes.len() {
        4 => Some(SocketAddr::new(
            IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
            port,
        )),
        16 => Some(SocketAddr::new(
            IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
            port,
        )),
        _ => None,
    }
}

pub(crate) fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

/// The same octets in the caller's stack room, so a datagram lane builds a packet without a heap buffer per address.
fn ip_bytes_into(address: IpAddr, out: &mut [u8; 16]) -> &[u8] {
    match address {
        IpAddr::V4(address) => {
            out[..4].copy_from_slice(&address.octets());
            &out[..4]
        }
        IpAddr::V6(address) => {
            out.copy_from_slice(&address.octets());
            &out[..]
        }
    }
}

/// The IP protocol number a TCP segment carries.
pub(crate) const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_ICMPV6: u8 = 58;

/// Answer an echo request the tunnel sent to one of this device's own addresses; the reply
/// rides the same tunnel back, so a ping to the tunnel address returns instead of vanishing.
fn answer_echo(packet: &[u8], addresses: &[IpAddr], to_tunnel: &ToTunnel) -> bool {
    let Some((source, destination)) = inner_addresses(packet) else {
        return false;
    };
    if !addresses.contains(&destination) {
        return false;
    }
    let Some(message) = icmp_message(packet) else {
        return false;
    };
    let mut reply = Vec::with_capacity(packet.len());
    if !icmp_echo_reply(source, destination, message, &mut reply) {
        return false;
    }
    to_tunnel.send(reply).is_ok()
}

/// The ICMP message an inner packet carries, cut at its IP header's length so trailing
/// padding is not read as part of the message.
fn icmp_message(packet: &[u8]) -> Option<&[u8]> {
    match packet.first()? >> 4 {
        4 => {
            let header = usize::from(*packet.first()? & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            (packet.get(9) == Some(&PROTOCOL_ICMP)
                && header >= IPV4_HEADER
                && header + 8 <= total
                && total <= packet.len())
            .then(|| &packet[header..total])
        }
        6 => {
            let payload = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
            let total = IPV6_HEADER + payload;
            (packet.get(6) == Some(&PROTOCOL_ICMPV6) && total <= packet.len())
                .then(|| &packet[IPV6_HEADER..total])
        }
        _ => None,
    }
}

/// The MTU an ICMP Packet Too Big names, when the packet is one at all: a v4 destination-unreachable with code 4, or a v6 packet-too-big, both at or above their family's floor.
fn icmp_mtu(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 28
            && packet[9] == PROTOCOL_ICMP
            && packet[20] == 3
            && packet[21] == 4 =>
        {
            let mtu = usize::from(u16::from_be_bytes([packet[26], packet[27]]));
            (mtu >= 68).then_some(mtu)
        }
        6 if packet.len() >= 48
            && packet[6] == PROTOCOL_ICMPV6
            && packet[40] == 2
            && packet[41] == 0 =>
        {
            let mtu = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]);
            if mtu >= 1280 {
                usize::try_from(mtu).ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listeners_share_one_total_budget_and_expire() {
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            dns: Vec::new(),
        };
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&config, to_tunnel, out);
        for port in 0..(LISTENERS as u16 + 10) {
            stack.listen(10_000 + port);
        }
        assert_eq!(stack.listeners.len(), LISTENERS);
        let expired = 10_000;
        stack.listeners.get_mut(&expired).expect("listener")[0].since = StdInstant::now()
            .checked_sub(LISTENER_TTL)
            .expect("instant");
        let mut buf = [0u8; 1024];
        stack.poll(&mut buf);
        assert!(!stack.listeners.contains_key(&expired));
        stack.listen(10_000 + LISTENERS as u16 + 20);
        assert_eq!(stack.listeners.len(), LISTENERS);
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += if pair.len() == 2 {
                u32::from(u16::from_be_bytes([pair[0], pair[1]]))
            } else {
                u32::from(pair[0]) << 8
            };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// The SYN-ACK a peer would answer a client's SYN with, so the upload path runs on an established socket without a second stack.
    fn syn_ack(syn: &[u8]) -> Vec<u8> {
        let ihl = usize::from(syn[0] & 0x0f) * 4;
        let source: [u8; 4] = syn[12..16].try_into().expect("source");
        let destination: [u8; 4] = syn[16..20].try_into().expect("destination");
        let source_port = u16::from_be_bytes([syn[ihl], syn[ihl + 1]]);
        let destination_port = u16::from_be_bytes([syn[ihl + 2], syn[ihl + 3]]);
        let sequence = u32::from_be_bytes(
            syn[ihl + 4..ihl + 8]
                .try_into()
                .expect("the client's sequence"),
        );
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&destination);
        packet[16..20].copy_from_slice(&source);
        let header_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&destination_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&source_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x1234u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&(sequence + 1).to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x12;
        tcp[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        let tcp_sum = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
        packet
    }

    #[test]
    fn a_direct_upload_never_builds_the_staging_buffer() {
        let (mut app, proxy) = loopback().expect("pair");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&device(&["10.0.0.2"], true), to_tunnel);
        stack
            .connect(ClientFlow {
                client: Connection::from(proxy),
                destination: "192.0.2.1:80".parse().expect("destination"),
                prefix: Vec::new(),
            })
            .expect("connect");
        let mut buf = [0u8; 2048];
        stack.poll(&mut buf);
        let syn = packets
            .recv_timeout(Duration::from_secs(5))
            .expect("the client's SYN");
        assert_eq!(syn[9], 6, "the inner packet is TCP");
        stack.device.push(syn_ack(&syn));
        stack.poll(&mut buf);
        assert_eq!(
            stack
                .sockets
                .get::<TcpSocket>(stack.flows[0].handle)
                .state(),
            State::Established,
            "the SYN-ACK establishes the flow"
        );
        while packets.try_recv().is_ok() {}

        app.write_all(b"hello").expect("write");
        let mut seen = false;
        for _ in 0..50 {
            stack.poll(&mut buf);
            while let Ok(packet) = packets.try_recv() {
                if packet
                    .windows(b"hello".len())
                    .any(|window| window == b"hello")
                {
                    seen = true;
                }
            }
            if seen {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            stack.flows[0].pending_up.capacity(),
            0,
            "an accepted upload is never copied into pending_up"
        );
        assert!(seen, "the accepted bytes leave on the tunnel");
    }

    #[test]
    fn a_datagram_address_is_written_in_stack_room_and_the_bytes_are_the_allocated_ones() {
        let source: IpAddr = "2001:db8::2".parse().unwrap();
        let destination: IpAddr = "2001:db8::7".parse().unwrap();
        let payload = b"addresses";
        let mut packet = Vec::with_capacity(IPV6_HEADER + 8 + payload.len());

        let ((), new) = ferrox_core::alloc_count::measure(|| {
            let mut source_room = [0u8; 16];
            let mut destination_room = [0u8; 16];
            let source_bytes = ip_bytes_into(source, &mut source_room);
            let destination_bytes = ip_bytes_into(destination, &mut destination_room);
            let datagram = UdpDatagram {
                source: source_bytes,
                destination: destination_bytes,
                source_port: 1234,
                destination_port: 53,
                payload,
            };
            assert!(udp_datagram(&datagram, &mut packet));
        });
        assert_eq!(new.allocs, 0, "the address build takes no heap: {new:?}");

        let mut reference = Vec::with_capacity(IPV6_HEADER + 8 + payload.len());
        let ((), old) = ferrox_core::alloc_count::measure(|| {
            let source_bytes = ip_bytes(source);
            let destination_bytes = ip_bytes(destination);
            let datagram = UdpDatagram {
                source: &source_bytes,
                destination: &destination_bytes,
                source_port: 1234,
                destination_port: 53,
                payload,
            };
            assert!(udp_datagram(&datagram, &mut reference));
        });
        assert_eq!(
            old.allocs, 2,
            "the old build allocated each address: {old:?}"
        );
        assert_eq!(packet, reference, "the stack room writes the same packet");
    }

    #[test]
    fn a_server_datagram_lane_echoes_through_freedom() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let target = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (to_tunnel, replies) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let source: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let started = StdInstant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("instant");
        let last_used = Arc::new(AtomicU64::new(0));
        let (uplink, _) = server_udp(
            ([0x11; 32], source, target),
            started,
            &last_used,
            &out,
            &to_tunnel,
        )
        .expect("lane");
        let mut buf = Vec::new();
        let frame = crate::proxy::socks_udp_frame(&mut buf, None, &target, b"hi");
        uplink.send(frame).expect("send");
        let packet = replies.recv_timeout(Duration::from_secs(5)).expect("reply");
        assert!(
            last_used.load(Ordering::Relaxed) > 0,
            "a reply refreshes the lane's activity"
        );
        let datagram = udp_from_packet(&packet).expect("inner datagram");
        assert_eq!(datagram.payload, b"hi");
        assert_eq!(datagram.source, ip_bytes(target.ip()));
        assert_eq!(datagram.source_port, target.port());
        assert_eq!(datagram.destination, ip_bytes(source.ip()));
        assert_eq!(datagram.destination_port, source.port());
    }

    #[test]
    fn a_server_datagram_lane_is_reclaimed_when_idle() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_millis(100)),
            ..Default::default()
        });
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            dns: Vec::new(),
        };
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&config, to_tunnel.clone(), out.clone());
        let source: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let target: SocketAddr = "192.0.2.1:7".parse().unwrap();
        let key = ([0x11; 32], source, target);
        let started = StdInstant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("instant");
        stack.started = started;
        let last_used = Arc::new(AtomicU64::new(0));
        let (uplink, stop) = server_udp(key, started, &last_used, &out, &to_tunnel).expect("lane");
        stack.udp.insert(
            key,
            UdpLane {
                uplink,
                stop: Arc::clone(&stop),
                last_used,
            },
        );
        let mut buf = [0u8; 1024];
        stack.poll(&mut buf);
        assert!(stack.udp.is_empty(), "an idle lane leaves the table");
        assert!(stop.load(Ordering::Relaxed), "its reader is told to stop");
        crate::budgets::clear();
    }

    fn echo_v4(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let length = IPV4_HEADER + 8 + payload.len();
        let mut packet = vec![0u8; length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTOCOL_ICMP;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[IPV4_HEADER] = 8;
        packet[IPV4_HEADER + 8..].copy_from_slice(payload);
        packet
    }

    fn echo_v6(source: [u8; 16], destination: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let length = 8 + payload.len();
        let mut packet = vec![0u8; IPV6_HEADER + length];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        packet[6] = PROTOCOL_ICMPV6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet[IPV6_HEADER] = 128;
        packet[IPV6_HEADER + 8..].copy_from_slice(payload);
        packet
    }

    fn device(addresses: &[&str], is_client: bool) -> DeviceConfig {
        DeviceConfig {
            secret: [0u8; 32],
            addresses: addresses
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(is_client),
            no_kernel_tun: true,
            dns: Vec::new(),
        }
    }

    #[test]
    fn an_echo_to_the_devices_own_address_is_answered_on_the_tunnel() {
        let (to_tunnel, replies) = std::sync::mpsc::channel();
        let stack = ClientStack::new(&device(&["10.0.0.2", "fd00::2"], true), to_tunnel);

        assert!(stack.answer_echo(&echo_v4([10, 0, 0, 1], [10, 0, 0, 2], b"ping")));
        let reply = replies.try_recv().expect("a v4 reply");
        assert_eq!(reply[0], 0x45);
        assert_eq!(&reply[12..16], &[10, 0, 0, 2], "source is this device");
        assert_eq!(&reply[16..20], &[10, 0, 0, 1], "target is the pinger");
        assert_eq!(reply[IPV4_HEADER], 0, "an echo reply");
        assert_eq!(&reply[IPV4_HEADER + 8..], b"ping");

        assert!(stack.answer_echo(&echo_v6(
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            b"ping",
        )));
        let reply = replies.try_recv().expect("a v6 reply");
        assert_eq!(reply[0], 0x60);
        assert_eq!(reply[IPV6_HEADER], 129, "an echo reply");
        assert_eq!(&reply[IPV6_HEADER + 8..], b"ping", "the message comes back");

        assert!(
            !stack.answer_echo(&echo_v4([10, 0, 0, 1], [10, 0, 0, 9], b"ping")),
            "not this device's address"
        );
        assert!(replies.try_recv().is_err(), "and no reply was sent");
    }

    #[test]
    fn a_server_answers_an_echo_to_its_own_address() {
        let (to_tunnel, replies) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&device(&["10.13.0.1"], false), to_tunnel, out);

        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: echo_v4([10, 13, 0, 2], [10, 13, 0, 1], b"ping"),
        });
        let reply = replies.try_recv().expect("a reply");
        assert_eq!(&reply[12..16], &[10, 13, 0, 1], "source is this server");
        assert_eq!(&reply[16..20], &[10, 13, 0, 2], "target is the pinger");
        assert_eq!(reply[IPV4_HEADER], 0);

        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: echo_v4([10, 13, 0, 2], [10, 13, 0, 9], b"ping"),
        });
        assert!(replies.try_recv().is_err(), "an address it does not own");
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use std::time::Duration;

    fn config() -> DeviceConfig {
        DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            dns: Vec::new(),
        }
    }

    #[test]
    fn a_client_datagram_lane_returns_when_its_client_leaves() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let port = relay.local_addr().expect("address").port();
        let (associate, remote) = loopback().expect("pair");
        drop(remote);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let routes: UdpRoutes = Arc::default();
        let thread_routes = Arc::clone(&routes);
        std::thread::spawn(move || {
            let (to_tunnel, _) = std::sync::mpsc::channel();
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                Some(&Connection::from(associate)),
                &crate::proxy::resolve_endpoint,
            );
            let _ = done_tx.send(());
        });
        let returned = done_rx.recv_timeout(Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("a closed control socket ends the lane");
        assert!(!routes.lock().expect("routes").contains_key(&port));
    }

    #[test]
    fn a_quiet_client_datagram_lane_returns_on_the_idle_budget() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let port = relay.local_addr().expect("address").port();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let routes: UdpRoutes = Arc::default();
        let thread_routes = Arc::clone(&routes);
        std::thread::spawn(move || {
            let (to_tunnel, _) = std::sync::mpsc::channel();
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                None,
                &crate::proxy::resolve_endpoint,
            );
            let _ = done_tx.send(());
        });
        let returned = done_rx.recv_timeout(Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("a quiet lane ends on its idle budget");
        assert!(!routes.lock().expect("routes").contains_key(&port));
    }

    #[test]
    fn a_client_datagram_lane_frames_and_unframes() {
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("address");
        let app = UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let thread_routes = Arc::clone(&routes);
        std::thread::spawn(move || {
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                None,
                &crate::proxy::resolve_endpoint,
            );
        });
        let port = relay_address.port();
        for _ in 0..100 {
            if routes.lock().expect("routes").contains_key(&port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(routes.lock().expect("routes").contains_key(&port));

        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let mut buf = Vec::new();
        let frame = crate::proxy::socks_udp_frame(&mut buf, None, &target, b"query");
        app.send_to(frame, relay_address).expect("send");
        let inner = packets.recv_timeout(Duration::from_secs(5)).expect("inner");
        let datagram = udp_from_packet(&inner).expect("packet");
        assert_eq!(datagram.source_port, port);
        assert_eq!(datagram.destination_port, 53);
        assert_eq!(datagram.payload, b"query");

        let source = ip_bytes(target.ip());
        let destination = ip_bytes("10.0.0.2".parse().unwrap());
        let mut reply = Vec::new();
        let answer = UdpDatagram {
            source: &source,
            destination: &destination,
            source_port: 53,
            destination_port: port,
            payload: b"answer",
        };
        assert!(udp_datagram(&answer, &mut reply));
        routes
            .lock()
            .expect("routes")
            .get(&port)
            .expect("lane")
            .send(reply)
            .expect("reply");
        let mut received = [0u8; 2048];
        let (n, _) = app.recv_from(&mut received).expect("framed reply");
        let (remote, payload) = crate::proxy::parse_socks_udp(&received[..n]).expect("frame");
        assert_eq!(remote, target);
        assert_eq!(payload, b"answer");
    }

    #[test]
    fn a_client_datagram_name_uses_the_supplied_resolver() {
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("address");
        let app = UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let thread_routes = Arc::clone(&routes);
        let target: SocketAddr = "192.0.2.7:53".parse().unwrap();
        std::thread::spawn(move || {
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                None,
                &|host, port| {
                    assert_eq!(host, "example.test");
                    assert_eq!(port, 53);
                    Some(target)
                },
            );
        });
        let port = relay_address.port();
        for _ in 0..100 {
            if routes.lock().expect("routes").contains_key(&port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(routes.lock().expect("routes").contains_key(&port));

        let name = b"example.test";
        let mut frame = vec![0, 0, 0, 3, name.len() as u8];
        frame.extend_from_slice(name);
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(b"query");
        app.send_to(&frame, relay_address).expect("send");
        let inner = packets.recv_timeout(Duration::from_secs(5)).expect("inner");
        let datagram = udp_from_packet(&inner).expect("packet");
        assert_eq!(datagram.destination, ip_bytes(target.ip()).as_slice());
        assert_eq!(datagram.destination_port, 53);
        assert_eq!(datagram.payload, b"query");
    }

    #[test]
    fn a_poll_hands_at_most_tx_packets_to_the_tunnel() {
        use smoltcp::phy::{Device, TxToken};

        let mut device = QueueDevice::new(1420);
        for _ in 0..TX_PACKETS {
            let token = device.transmit(Instant::from_millis(0)).expect("room left");
            token.consume(1280, |buffer| buffer.fill(0));
        }
        assert_eq!(device.tx.len(), TX_PACKETS);
        assert!(
            device.transmit(Instant::from_millis(0)).is_none(),
            "past the bound the stack keeps the segment and closes its window"
        );
        device.tx.clear();
        assert!(device.transmit(Instant::from_millis(0)).is_some());
    }

    #[test]
    fn a_packet_too_big_narrows_the_device_mtu() {
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[8] = 64;
        inner[9] = PROTOCOL_UDP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 2]);
        inner[16..20].copy_from_slice(&[198, 51, 100, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 1170).expect("a v4 answer");
        let mut device = QueueDevice::new(1420);
        assert!(device.absorb(&too_big));
        assert_eq!(device.capabilities().max_transmission_unit, 1170);
        assert!(!device.absorb(&too_big), "never wider again");

        let mut inner = vec![0u8; 48];
        inner[0] = 0x60;
        inner[4..6].copy_from_slice(&8u16.to_be_bytes());
        inner[6] = PROTOCOL_UDP;
        inner[7] = 64;
        inner[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 1280).expect("a v6 answer");
        let mut device = QueueDevice::new(1420);
        assert!(device.absorb(&too_big));
        assert_eq!(device.capabilities().max_transmission_unit, 1280);

        let mut forged = too_big;
        forged[40] = 3;
        assert!(!device.absorb(&forged), "not a packet too big");
    }
}
