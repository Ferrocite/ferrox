//! MASQUE CONNECT-IP over HTTP/3 (RFC 9484): the request names `connect-ip`, the
//! control capsules ride the request stream as HTTP/3 DATA frames, and every IP
//! packet rides a QUIC DATAGRAM with a quarter-stream-id prefix and context zero.
//!
//! A client assigns both families and hands its inner packets to the userspace
//! stack; a server authenticates once, assigns one address per family from each
//! pool, and forwards a packet to the tunnel that owns its destination — or to
//! the stack when no tunnel does.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::connectip::{self, Assigned, Route};
use ferrox_core::foxy::frames;
use ferrox_core::foxy::hpack;
use ferrox_core::tls::TlsConfig;

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{Destination, Outbound};
use crate::quic::{self, Datagram};
use crate::wg_stack::{self, ClientFlow, Packet, UdpRoutes};
use crate::wireguard::DeviceConfig;

const TICK: Duration = Duration::from_millis(10);
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";
const DEFAULT_MTU: usize = 1280;
const QUEUE: usize = 512;
/// The server's own connection ID: a short header carries no length, so the demultiplexer reads exactly this many bytes.
const CID_LEN: usize = 16;
const AUTH_REALM: &str = "Basic realm=\"masque\", charset=\"UTF-8\"";
const H3_SETTINGS: u64 = 0x04;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;

/// One client outbound: the conversation it opened, the stack that answers its
/// inner TCP flows, and the per-lane route table its datagrams return through.
#[derive(Debug)]
pub(crate) struct MasqueOut {
    spec: ClientSpec,
    inner: Mutex<Option<Arc<Inner>>>,
    edge: Option<SocketAddr>,
}

#[derive(Debug)]
struct Inner {
    config: Arc<DeviceConfig>,
    flows: Sender<ClientFlow>,
    to_tunnel: Sender<Vec<u8>>,
    routes: UdpRoutes,
}

impl MasqueOut {
    pub(crate) fn new(outbound: &Json) -> Result<Self, String> {
        if outbound
            .get("settings")
            .and_then(|settings| settings.get("remoteDNS"))
            .and_then(Json::as_arr)
            .is_some_and(|dns| !dns.is_empty())
        {
            eprintln!("masque: `remoteDNS` is not carried; names resolve on the host");
        }
        if outbound
            .get("streamSettings")
            .and_then(|settings| settings.get("masqueSettings"))
            .and_then(|settings| settings.get("warp"))
            .is_some()
        {
            eprintln!("masque: WARP's mutual TLS and static addresses are not carried");
        }
        let spec = ClientSpec::from(outbound)?;
        let edge = format!("{}:{}", spec.address, spec.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut resolved| resolved.next());
        Ok(Self {
            spec,
            inner: Mutex::new(None),
            edge,
        })
    }

    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        self.edge
    }

    fn ensure(&self) -> Result<Arc<Inner>, String> {
        let mut slot = self
            .inner
            .lock()
            .map_err(|_| "masque: the lane lock is poisoned".to_owned())?;
        if let Some(inner) = slot.as_ref() {
            return Ok(Arc::clone(inner));
        }
        let inner = Arc::new(open(&self.spec)?);
        *slot = Some(Arc::clone(&inner));
        Ok(inner)
    }

    pub(crate) fn serve_tcp(&self, client: Connection, asked: &Destination, prefix: &[u8]) {
        let Some(destination) = asked.socket() else {
            eprintln!("masque: destination `{asked:?}` does not resolve");
            return;
        };
        let inner = match self.ensure() {
            Ok(inner) => inner,
            Err(reason) => {
                eprintln!("masque: {reason}");
                return;
            }
        };
        if inner
            .flows
            .send(ClientFlow {
                client,
                destination,
                prefix: prefix.to_vec(),
            })
            .is_err()
        {
            eprintln!("masque: the userspace stack is gone");
        }
    }

    pub(crate) fn serve_udp(&self, relay: &UdpSocket, associate: Option<&Connection>) {
        match self.ensure() {
            Ok(inner) => {
                wg_stack::client_udp(
                    relay,
                    &inner.config,
                    &inner.to_tunnel,
                    &inner.routes,
                    associate,
                );
            }
            Err(reason) => eprintln!("masque: {reason}"),
        }
    }
}

fn open(spec: &ClientSpec) -> Result<Inner, String> {
    let (sock, peer, local) = quic::udp_to_server(&spec.address, spec.port)
        .ok_or_else(|| format!("cannot resolve masque `{}:{}`", spec.address, spec.port))?;
    let sock = Datagram::plain(sock);
    let mut lane = establish(spec, &sock, peer, local)?;
    let config = Arc::new(DeviceConfig {
        secret: [0u8; 32],
        addresses: lane.addresses.clone(),
        peers: Vec::new(),
        mtu: lane.mtu,
        reserved: [0u8; 3],
        is_client: Some(true),
        no_kernel_tun: true,
        dns: Vec::new(),
    });
    let (packets_tx, packets_rx) = mpsc::channel();
    let (to_tunnel, from_tunnel) = mpsc::channel();
    let (flows, flow_rx) = mpsc::channel();
    let routes: UdpRoutes = Arc::default();
    let stack_config = Arc::clone(&config);
    let stack_tunnel = to_tunnel.clone();
    std::thread::spawn(move || {
        wg_stack::client((*stack_config).clone(), stack_tunnel, packets_rx, flow_rx);
    });
    let io_routes = Arc::clone(&routes);
    let stream = lane.stream;
    let mut conn = lane.conn.take().ok_or("the masque lane closed")?;
    let mut initial = std::mem::take(&mut lane.packets);
    std::thread::spawn(move || {
        for packet in initial.drain(..) {
            deliver(&packets_tx, &io_routes, &packet);
        }
        io(
            &mut conn,
            &sock,
            local,
            stream,
            from_tunnel,
            packets_tx,
            io_routes,
        );
    });
    Ok(Inner {
        config,
        flows,
        to_tunnel,
        routes,
    })
}

/// One lane that finished its handshake and its first address assignment: the
/// connection and request stream the caller now owns, and what it may source.
struct Lane {
    conn: Option<quiche::Connection>,
    stream: u64,
    addresses: Vec<IpAddr>,
    mtu: usize,
    packets: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct ClientSpec {
    address: String,
    port: u16,
    tls: Arc<TlsConfig>,
    path: String,
    host: Option<String>,
    headers: Vec<(String, String)>,
}

impl ClientSpec {
    fn from(outbound: &Json) -> Result<Self, String> {
        let settings = outbound
            .get("settings")
            .ok_or("masque outbound has no settings")?;
        let server = settings
            .get("server")
            .ok_or("masque outbound has no `server`")?;
        let (address, port) = if let Json::Str(text) = server {
            split_host_port(text).ok_or_else(|| format!("masque server `{text}` has no port"))?
        } else {
            let address = server
                .get("address")
                .and_then(Json::as_str)
                .ok_or("masque server has no `address`")?;
            let port = server
                .get("port")
                .and_then(Json::as_port)
                .ok_or("masque server has no `port`")?;
            (address.to_owned(), port)
        };
        let tls = crate::config::outbound_tls(outbound, &address)?;
        let transport = outbound
            .get("streamSettings")
            .and_then(|settings| settings.get("masqueSettings"));
        let path = transport
            .and_then(|settings| settings.get("path"))
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
            .unwrap_or(DEFAULT_PATH)
            .to_owned();
        let host = transport
            .and_then(|settings| settings.get("host"))
            .and_then(Json::as_str)
            .filter(|host| !host.is_empty())
            .map(str::to_owned);
        let mut headers: Vec<(String, String)> =
            match transport.and_then(|settings| settings.get("headers")) {
                Some(Json::Arr(items)) => items
                    .iter()
                    .filter_map(|entry| {
                        Some((
                            entry.get("name")?.as_str()?.to_ascii_lowercase(),
                            entry.get("value")?.as_str()?.to_owned(),
                        ))
                    })
                    .collect(),
                Some(Json::Obj(pairs)) => pairs
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.to_ascii_lowercase(),
                            value.as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect(),
                _ => Vec::new(),
            };
        headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("capsule-protocol")
                && !name.eq_ignore_ascii_case("host")
                && !name.starts_with(':')
        });
        browser_user_agent(&mut headers);
        Ok(Self {
            address,
            port,
            tls,
            path,
            host,
            headers,
        })
    }
}

/// xray reads a browser name as a request for its own masked set rather than a literal value, and a
/// bare `golang` as a request to send none.
fn browser_user_agent(headers: &mut Vec<(String, String)>) {
    let Some(at) = headers
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
    else {
        headers.push((
            "user-agent".to_owned(),
            crate::headers::CHROME_UA.to_owned(),
        ));
        return;
    };
    let value = headers[at].1.as_str();
    if value.is_empty() || value.eq_ignore_ascii_case("golang") {
        headers.remove(at);
    } else if ["chrome", "firefox", "safari", "edge", "curl"]
        .iter()
        .any(|browser| value.eq_ignore_ascii_case(browser))
    {
        crate::headers::CHROME_UA.clone_into(&mut headers[at].1);
    }
}

fn split_host_port(text: &str) -> Option<(String, u16)> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_owned(), port.parse().ok()?));
    }
    let (host, port) = text.rsplit_once(':')?;
    Some((host.to_owned(), port.parse().ok()?))
}

fn client_config(spec: &ClientSpec) -> Result<quiche::Config, String> {
    let mut config = if spec.tls.insecure || !spec.tls.cert_pins.is_empty() {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|error| format!("masque TLS: {error}"))?;
        config.verify_peer(false);
        if !quic::tune(&mut config, quic::ALPN) {
            return Err("masque cannot name the h3 protocol".to_owned());
        }
        config
    } else {
        quic::quiche_config(&spec.tls.roots, None)
            .ok_or("masque: no certificate authorities for the edge")?
    };
    config.enable_dgram(true, quic::MAX_DATAGRAM, quic::MAX_DATAGRAM);
    Ok(config)
}

fn establish(
    spec: &ClientSpec,
    sock: &Datagram,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Lane, String> {
    attempt(spec, sock, peer, local).map_err(|reason| format!("masque: {reason}"))
}

fn attempt(
    spec: &ClientSpec,
    sock: &Datagram,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Lane, String> {
    let mut config = client_config(spec)?;
    let mut scid = [0u8; 16];
    getrandom::fill(&mut scid).map_err(|error| format!("masque: no connection id: {error}"))?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = quiche::connect(Some(&spec.tls.server_name), &cid, local, peer, &mut config)
        .map_err(|error| format!("masque: cannot open a connection: {error}"))?;
    quic::drive_handshake_by(&mut conn, sock, local, ESTABLISH_TIMEOUT)
        .ok_or("the QUIC handshake did not finish")?;
    verify_edge(spec, &conn)?;
    open_h3(&mut conn, spec)?;
    let mut stream = Stream::default();
    let status = stream.wait_head(&mut conn, sock, local, HEAD_TIMEOUT)?;
    if !(200..300).contains(&status) {
        return Err(format!("masque: the edge answered {status}"));
    }
    send_address_requests(&mut conn, stream.id)?;
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut addresses = Vec::new();
    while addresses.is_empty() && Instant::now() < deadline {
        stream.poll(&mut conn, sock, local, TICK)?;
        for capsule in stream.take_capsules() {
            if let Owned::AddressAssign(body) = capsule {
                let mut assigned = Vec::new();
                if connectip::address_assign(&body, &mut assigned).is_some() {
                    addresses.extend(assigned.iter().filter_map(|grant| {
                        (!grant.refused()).then(|| address_of(grant)).flatten()
                    }));
                }
            }
        }
    }
    if addresses.is_empty() {
        return Err("masque: no address assigned".to_owned());
    }
    Ok(Lane {
        conn: Some(conn),
        stream: stream.id,
        addresses,
        mtu: DEFAULT_MTU,
        packets: stream.packets,
    })
}

fn verify_edge(spec: &ClientSpec, conn: &quiche::Connection) -> Result<(), String> {
    if spec.tls.insecure || spec.tls.cert_pins.is_empty() {
        return Ok(());
    }
    let chain: Vec<Vec<u8>> = match conn.peer_cert_chain() {
        Some(chain) => chain.iter().map(|cert| cert.to_vec()).collect(),
        None => conn
            .peer_cert()
            .map(|cert| vec![cert.to_vec()])
            .unwrap_or_default(),
    };
    if ferrox_core::tls::verify_cert_pinned(&chain, &spec.tls.cert_pins, &spec.tls.server_name) {
        Ok(())
    } else {
        Err("masque: the edge certificate does not match the pins".to_owned())
    }
}

fn open_h3(conn: &mut quiche::Connection, spec: &ClientSpec) -> Result<(), String> {
    send_server_settings(conn, 2, 6, 10)?;
    let authority = authority(spec);
    let mut block = Vec::with_capacity(256 + spec.path.len());
    connectip::connect_ip_qpack_named(&authority, &spec.path, &spec.headers, &mut block);
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    send_stream(conn, 0, &head, false)
}

fn send_server_settings(
    conn: &mut quiche::Connection,
    control: u64,
    encoder: u64,
    decoder: u64,
) -> Result<(), String> {
    let settings = h3_settings();
    let mut frame = Vec::with_capacity(17 + settings.len());
    frames::quic_varint(&mut frame, 0x00);
    frames::quic_varint(&mut frame, H3_SETTINGS);
    frames::quic_varint(&mut frame, settings.len() as u64);
    frame.extend_from_slice(&settings);
    send_stream(conn, control, &frame, false)?;
    send_stream(conn, encoder, &[0x02], false)?;
    send_stream(conn, decoder, &[0x03], false)
}

fn h3_settings() -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    for (id, value) in [
        (0x01u64, 0u64),
        (0x07, 0),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
    ] {
        frames::quic_varint(&mut out, id);
        frames::quic_varint(&mut out, value);
    }
    out
}

fn send_stream(
    conn: &mut quiche::Connection,
    stream: u64,
    bytes: &[u8],
    fin: bool,
) -> Result<(), String> {
    let mut rest = bytes;
    loop {
        match conn.stream_send(stream, rest, fin) {
            Ok(0) => return Err("masque: the stream accepted no bytes".to_owned()),
            Ok(wrote) => {
                rest = &rest[wrote..];
                if rest.is_empty() {
                    return Ok(());
                }
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(format!("masque: cannot write the stream: {error}")),
        }
    }
}

fn send_address_requests(conn: &mut quiche::Connection, stream: u64) -> Result<(), String> {
    let v4 = [0u8; 4];
    let v6 = [0u8; 16];
    let mut requests = Vec::with_capacity(40);
    connectip::address_requests(&[(1, 4, &v4), (2, 6, &v6)], &mut requests);
    send_data(conn, stream, &requests)
}

fn send_data(conn: &mut quiche::Connection, stream: u64, bytes: &[u8]) -> Result<(), String> {
    let mut head = [0u8; 9];
    let length = frames::h3_data_header(&mut head, bytes.len() as u64);
    let mut frame = Vec::with_capacity(length + bytes.len());
    frame.extend_from_slice(&head[..length]);
    frame.extend_from_slice(bytes);
    send_stream(conn, stream, &frame, false)
}

fn authority(spec: &ClientSpec) -> String {
    if let Some(host) = &spec.host {
        return host.clone();
    }
    let host = &spec.tls.server_name;
    if spec.port == 443 {
        return host.clone();
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        return format!("[{host}]:{}", spec.port);
    }
    format!("{host}:{}", spec.port)
}

/// xray takes a subnet grant's first usable address rather than the raw bytes, so a proxy that assigns a range still names one host.
fn address_of(grant: &Assigned) -> Option<IpAddr> {
    match grant.version {
        4 => {
            let address = u32::from_be_bytes([
                grant.address[0],
                grant.address[1],
                grant.address[2],
                grant.address[3],
            ]);
            let host = 32u32.saturating_sub(u32::from(grant.prefix));
            let mask = if host == 32 {
                u32::MAX
            } else {
                (1u32 << host) - 1
            };
            let network = address & !mask;
            Some(IpAddr::V4(Ipv4Addr::from(if host == 0 {
                network
            } else {
                network.saturating_add(1)
            })))
        }
        6 => {
            let address = u128::from_be_bytes(grant.address);
            let prefix = grant.prefix.min(128);
            let mask = if prefix == 0 {
                u128::MAX
            } else {
                (1u128 << (128 - prefix)) - 1
            };
            let network = address & !mask;
            Some(IpAddr::V6(Ipv6Addr::from(if prefix == 128 {
                network
            } else {
                network.saturating_add(1)
            })))
        }
        _ => None,
    }
}

/// A capsule this lane owns: the parser borrows the stream buffer, and a
/// capsule can arrive while the caller is elsewhere.
enum Owned {
    AddressAssign(Vec<u8>),
    Other,
}

/// The request stream's frame state: the head block and the capsule bytes a
/// CONNECT-IP tunnel answers with, kept apart because a frame can split either.
#[derive(Default)]
struct Stream {
    id: u64,
    buf: Vec<u8>,
    at: usize,
    capsules: Vec<u8>,
    capsule_at: usize,
    status: Option<u16>,
    pending: Vec<Owned>,
    done: bool,
    packets: Vec<Vec<u8>>,
}

impl Stream {
    fn wait_head(
        &mut self,
        conn: &mut quiche::Connection,
        sock: &Datagram,
        local: SocketAddr,
        budget: Duration,
    ) -> Result<u16, String> {
        let deadline = Instant::now() + budget;
        while self.status.is_none() {
            if Instant::now() >= deadline {
                return Err("masque: the edge sent no response head".to_owned());
            }
            self.poll(conn, sock, local, TICK)?;
        }
        Ok(self.status.unwrap_or(0))
    }

    fn take_capsules(&mut self) -> Vec<Owned> {
        std::mem::take(&mut self.pending)
    }

    fn poll(
        &mut self,
        conn: &mut quiche::Connection,
        sock: &Datagram,
        local: SocketAddr,
        wait: Duration,
    ) -> Result<(), String> {
        if !quic::pump_once(conn, sock, local, wait) {
            return Err("masque: the connection ended".to_owned());
        }
        if conn.is_closed() {
            return Err("masque: the edge closed the connection".to_owned());
        }
        let mut room = [0u8; 4096];
        loop {
            match conn.stream_recv(self.id, &mut room) {
                Ok((0, fin)) => {
                    self.done = fin;
                    break;
                }
                Ok((n, fin)) => {
                    self.buf.extend_from_slice(&room[..n]);
                    if fin {
                        self.done = true;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(format!("masque: stream read: {error}")),
            }
        }
        self.parse();
        let mut room = vec![0u8; 65535];
        while let Ok(n) = conn.dgram_recv(&mut room) {
            if let Some((stream, packet)) = connectip::datagram_split(&room[..n]) {
                if stream == self.id {
                    self.packets.push(packet.to_vec());
                }
            }
        }
        Ok(())
    }

    fn parse(&mut self) {
        let mut at = self.at;
        loop {
            let before = at;
            let Some(frame) = frames::h3_frame(&self.buf, &mut at) else {
                at = before;
                break;
            };
            let length = frame.length as usize;
            let Some(room) = self.buf.get(at..at + length) else {
                at = before;
                break;
            };
            at += length;
            match frame.kind {
                frames::H3_HEADERS if self.status.is_none() => {
                    self.status = hpack::qpack_status(room);
                }
                frames::H3_DATA => self.capsules.extend_from_slice(room),
                _ => {}
            }
        }
        self.buf.drain(..at);
        self.at = 0;
        while let Some((used, capsule)) =
            connectip::capsule_split(&self.capsules[self.capsule_at..])
        {
            self.capsule_at += used;
            let owned = match capsule {
                connectip::Capsule::AddressAssign(body) => Owned::AddressAssign(body.to_vec()),
                _ => Owned::Other,
            };
            self.pending.push(owned);
        }
        if self.capsule_at > 0 {
            self.capsules.drain(..self.capsule_at);
            self.capsule_at = 0;
        }
    }
}

/// Writes inner packets to the tunnel and hands the ones it answers back: a TCP
/// packet to the stack, a UDP packet to the loopback lane waiting on its port.
#[allow(clippy::needless_pass_by_value)]
fn io(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    stream: u64,
    from_tunnel: Receiver<Vec<u8>>,
    to_stack: Sender<Packet>,
    routes: UdpRoutes,
) {
    let mut room = vec![0u8; 65535];
    loop {
        while let Ok(packet) = from_tunnel.try_recv() {
            send_datagram(conn, stream, &packet);
        }
        if !quic::pump_once(conn, sock, local, TICK) || conn.is_closed() {
            return;
        }
        while let Ok(n) = conn.dgram_recv(&mut room) {
            let Some((id, packet)) = connectip::datagram_split(&room[..n]) else {
                continue;
            };
            if id != stream {
                continue;
            }
            deliver(&to_stack, &routes, packet);
        }
        quic::flush_egress(conn, sock);
    }
}

fn deliver(to_stack: &Sender<Packet>, routes: &UdpRoutes, packet: &[u8]) {
    if let Some(datagram) = connectip::udp_from_packet(packet) {
        if !datagram.verified {
            return;
        }
        if let Ok(table) = routes.lock() {
            if let Some(lane) = table.get(&datagram.destination_port) {
                let _ = lane.send(packet.to_vec());
            }
        }
        return;
    }
    if wg_stack::inner_protocol(packet) == Some(6) {
        let _ = to_stack.send(Packet {
            peer: [0u8; 32],
            bytes: packet.to_vec(),
        });
    }
}

fn send_datagram(conn: &mut quiche::Connection, stream: u64, packet: &[u8]) {
    let mut datagram = Vec::with_capacity(3 + packet.len());
    connectip::datagram_prefix(stream, &mut datagram);
    datagram.extend_from_slice(packet);
    if conn
        .dgram_max_writable_len()
        .is_some_and(|max| max >= datagram.len())
    {
        let _ = conn.dgram_send(&datagram);
    }
}

/// Open a server inbound's socket and spawn its demultiplexer, stack and forwarder.
pub(crate) fn serve_inbound(inbound: &Json, out: &Outbound, address: &str) -> Result<u16, String> {
    let spec = Arc::new(ServerSpec::from(inbound)?);
    let identity = crate::proxy::quic_inbound_identity(inbound)
        .ok_or("masque inbound requires security tls with a certificate")?;
    let Some(mut config) = quic::serve_config(&identity) else {
        return Err("unreadable masque tls identity".to_owned());
    };
    config.enable_dgram(true, quic::MAX_DATAGRAM, quic::MAX_DATAGRAM);
    let sock = UdpSocket::bind(address)
        .map_err(|error| format!("cannot bind masque `{address}`: {error}"))?;
    let local = sock
        .local_addr()
        .map_err(|error| format!("masque `{address}` has no local address: {error}"))?;
    let sock = Arc::new(Datagram::plain(sock));
    let (packets, packets_rx) = mpsc::channel();
    let shared = Arc::new(Shared {
        pool: Mutex::new(spec.pool.clone()),
        tunnels: Mutex::new(HashMap::new()),
        packets,
        local: spec.pool.server.clone(),
    });
    let (to_tunnel, from_stack) = mpsc::channel();
    let dispatcher = Arc::clone(&shared);
    std::thread::spawn(move || dispatch(&dispatcher, from_stack));
    let device = DeviceConfig {
        secret: [0u8; 32],
        addresses: spec.pool.server.clone(),
        peers: Vec::new(),
        mtu: spec.mtu,
        reserved: [0u8; 3],
        is_client: Some(false),
        no_kernel_tun: true,
        dns: Vec::new(),
    };
    let stack_out = out.clone();
    std::thread::spawn(move || wg_stack::server(device, to_tunnel, packets_rx, stack_out));
    let demux_config = Arc::new(Mutex::new(config));
    let demux_sock = Arc::clone(&sock);
    let demux_shared = Arc::clone(&shared);
    let demux_spec = Arc::clone(&spec);
    std::thread::spawn(move || {
        demux(demux_sock, local, demux_config, demux_shared, demux_spec);
    });
    Ok(local.port())
}

#[derive(Debug, Clone)]
struct ServerSpec {
    users: Vec<(String, String)>,
    path: String,
    pool: AddressPool,
    mtu: usize,
}

impl ServerSpec {
    fn from(inbound: &Json) -> Result<Self, String> {
        let settings = inbound
            .get("settings")
            .ok_or("masque inbound has no settings")?;
        let users: Vec<(String, String)> = settings
            .get("users")
            .and_then(Json::as_arr)
            .ok_or("masque inbound has no `users`")?
            .iter()
            .filter_map(|user| {
                let email = user.get("email").and_then(Json::as_str)?.to_owned();
                let password = user
                    .get("password")
                    .and_then(Json::as_str)
                    .or_else(|| user.get("account")?.get("password")?.as_str())?
                    .to_owned();
                Some((email, password))
            })
            .collect();
        if users.is_empty() {
            return Err("masque inbound has no user with a password".to_owned());
        }
        let addresses: Vec<String> = settings
            .get("address")
            .and_then(Json::as_arr)
            .ok_or("masque inbound has no `address`")?
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_owned)
            .collect();
        if addresses.is_empty() {
            return Err("masque inbound has no address to assign".to_owned());
        }
        let pool = AddressPool::from_prefixes(&addresses)?;
        let path = inbound
            .get("streamSettings")
            .and_then(|settings| settings.get("masqueSettings"))
            .and_then(|settings| settings.get("path"))
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
            .unwrap_or(DEFAULT_PATH)
            .to_owned();
        let mtu = settings
            .get("mtu")
            .and_then(Json::as_u32)
            .filter(|mtu| *mtu > 0)
            .map_or(DEFAULT_MTU, |mtu| mtu as usize);
        Ok(Self {
            users,
            path,
            pool,
            mtu,
        })
    }

    fn authenticates(&self, header: Option<&[u8]>) -> bool {
        let Some(text) = header.and_then(|value| std::str::from_utf8(value).ok()) else {
            return false;
        };
        let Some((scheme, token)) = text.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Some(decoded) = ferrox_core::b64::decode(token.trim().as_bytes()) else {
            return false;
        };
        let Ok(credentials) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((name, password)) = credentials.split_once(':') else {
            return false;
        };
        self.users
            .iter()
            .any(|(email, secret)| email.eq_ignore_ascii_case(name) && secret == password)
    }
}

struct Shared {
    pool: Mutex<AddressPool>,
    tunnels: Mutex<HashMap<IpAddr, SyncSender<Vec<u8>>>>,
    packets: Sender<Packet>,
    local: Vec<IpAddr>,
}

/// One address a pool may hand out, per family: the server's own address, the
/// network, the usable range and the next candidate, so an assignment walks the
/// range rather than searching it.
#[derive(Debug, Clone)]
struct Family {
    server: u128,
    network: u128,
    span: u128,
    first: u128,
    last: u128,
    next: u128,
    used: HashSet<u128>,
}

#[derive(Debug, Clone, Default)]
struct AddressPool {
    v4: Option<Family>,
    v6: Option<Family>,
    server: Vec<IpAddr>,
}

impl AddressPool {
    fn from_prefixes(addresses: &[String]) -> Result<Self, String> {
        let mut pool = Self::default();
        for text in addresses {
            let (address, prefix) = text
                .split_once('/')
                .ok_or_else(|| format!("masque address `{text}` has no prefix"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("masque address `{text}` has a bad prefix"))?;
            let ip: IpAddr = address
                .parse()
                .map_err(|_| format!("masque address `{text}` is not an IP"))?;
            match ip {
                IpAddr::V4(ip) => {
                    if pool.v4.is_some() {
                        return Err("masque: one address per family".to_owned());
                    }
                    if prefix > 32 {
                        return Err(format!("masque address `{text}` has a bad prefix"));
                    }
                    pool.v4 = Some(Family::new(u128::from(u32::from(ip)), prefix, 32)?);
                }
                IpAddr::V6(ip) => {
                    if pool.v6.is_some() {
                        return Err("masque: one address per family".to_owned());
                    }
                    if prefix > 128 {
                        return Err(format!("masque address `{text}` has a bad prefix"));
                    }
                    pool.v6 = Some(Family::new(u128::from(ip), prefix, 128)?);
                }
            }
            pool.server.push(ip);
        }
        Ok(pool)
    }

    fn assign(&mut self) -> Vec<IpAddr> {
        let mut addrs = Vec::with_capacity(2);
        if let Some(ip) = self.v4.as_mut().and_then(Family::allocate) {
            addrs.push(IpAddr::V4(Ipv4Addr::from(ip as u32)));
        }
        if let Some(ip) = self.v6.as_mut().and_then(Family::allocate) {
            addrs.push(IpAddr::V6(Ipv6Addr::from(ip)));
        }
        addrs
    }

    fn release(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(ip) => {
                if let Some(family) = self.v4.as_mut() {
                    family.used.remove(&u128::from(u32::from(ip)));
                }
            }
            IpAddr::V6(ip) => {
                if let Some(family) = self.v6.as_mut() {
                    family.used.remove(&u128::from(ip));
                }
            }
        }
    }

    fn holds(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self
                .v4
                .as_ref()
                .is_some_and(|family| family.holds(u128::from(u32::from(ip)))),
            IpAddr::V6(ip) => self
                .v6
                .as_ref()
                .is_some_and(|family| family.holds(u128::from(ip))),
        }
    }
}

impl Family {
    fn new(server: u128, prefix: u8, bits: u8) -> Result<Self, String> {
        let mask = if prefix == 0 {
            u128::MAX
        } else {
            (1u128 << (bits - prefix)) - 1
        };
        let network = server & !mask;
        let span = mask;
        let first = network.saturating_add(1);
        // A v4 pool gives up its broadcast address; a v6 one has no broadcast, so the last host stays assignable exactly as the reference leaves it.
        let last = if prefix == bits {
            network
        } else if bits == 32 && prefix <= 30 {
            network.saturating_add(span - 1)
        } else {
            network.saturating_add(span)
        };
        if first > last {
            return Err("masque pool has no assignable address".to_owned());
        }
        Ok(Self {
            server,
            network,
            span,
            first,
            last,
            next: first,
            used: HashSet::new(),
        })
    }

    fn allocate(&mut self) -> Option<u128> {
        let start = if self.next < self.first || self.next > self.last {
            self.first
        } else {
            self.next
        };
        let mut candidate = start;
        loop {
            if candidate != self.server && !self.used.contains(&candidate) {
                self.used.insert(candidate);
                self.next = if candidate >= self.last {
                    self.first
                } else {
                    candidate + 1
                };
                return Some(candidate);
            }
            candidate = if candidate >= self.last {
                self.first
            } else {
                candidate + 1
            };
            if candidate == start {
                return None;
            }
        }
    }

    fn holds(&self, address: u128) -> bool {
        address >= self.network && address <= self.network.saturating_add(self.span)
    }
}

/// A tunnel's addresses go back to the pool when its worker ends, whatever ended it.
struct Granted {
    shared: Arc<Shared>,
    addrs: Vec<IpAddr>,
}

impl Drop for Granted {
    fn drop(&mut self) {
        if let Ok(mut tunnels) = self.shared.tunnels.lock() {
            for address in &self.addrs {
                tunnels.remove(address);
            }
        }
        if let Ok(mut pool) = self.shared.pool.lock() {
            for address in &self.addrs {
                pool.release(*address);
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn dispatch(shared: &Shared, from_stack: Receiver<Vec<u8>>) {
    while let Ok(packet) = from_stack.recv() {
        let Some(destination) = packet_destination(&packet) else {
            continue;
        };
        if let Ok(tunnels) = shared.tunnels.lock() {
            if let Some(tunnel) = tunnels.get(&destination) {
                let _ = tunnel.try_send(packet);
            }
        }
    }
}

type Routes = Arc<Mutex<HashMap<Vec<u8>, (u64, Sender<(Vec<u8>, SocketAddr)>)>>>;

static WORKERS: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::needless_pass_by_value)]
fn demux(
    sock: Arc<Datagram>,
    local: SocketAddr,
    config: Arc<Mutex<quiche::Config>>,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
) {
    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65535];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let (kind, dcid) = {
            let Ok(head) = quiche::Header::from_slice(&mut buf[..n], CID_LEN) else {
                continue;
            };
            (head.ty, head.dcid.to_vec())
        };
        let queued = routes
            .lock()
            .ok()
            .and_then(|table| table.get(&dcid).map(|(_, tx)| tx.clone()));
        if let Some(tx) = queued {
            let _ = tx.send((buf[..n].to_vec(), from));
            continue;
        }
        if kind != quiche::Type::Initial {
            continue;
        }
        let mut scid = [0u8; CID_LEN];
        if getrandom::fill(&mut scid).is_err() {
            continue;
        }
        let scid = quiche::ConnectionId::from_ref(&scid);
        let Ok(mut guard) = config.lock() else {
            continue;
        };
        let Ok(conn) = quiche::accept(&scid, None, local, from, &mut guard) else {
            continue;
        };
        drop(guard);
        let server_scid = conn.source_id().to_vec();
        let (tx, rx) = mpsc::channel();
        let worker_id = WORKERS.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut table) = routes.lock() {
            table.insert(dcid.clone(), (worker_id, tx.clone()));
            table.insert(server_scid.clone(), (worker_id, tx.clone()));
        }
        let _ = tx.send((buf[..n].to_vec(), from));
        let sock = Arc::clone(&sock);
        let shared = Arc::clone(&shared);
        let spec = Arc::clone(&spec);
        let keys = Arc::clone(&routes);
        let worker_tx = tx.clone();
        std::thread::spawn(move || {
            worker(
                conn,
                sock,
                local,
                rx,
                worker_tx,
                shared,
                spec,
                Arc::clone(&keys),
                worker_id,
            );
            if let Ok(mut table) = keys.lock() {
                table.retain(|_, (owner, _)| *owner != worker_id);
            }
        });
    }
}

#[allow(clippy::struct_excessive_bools)]
struct Tunnel {
    stream: Option<u64>,
    buf: Vec<u8>,
    at: usize,
    headers: bool,
    capsules: Vec<u8>,
    capsule_at: usize,
    opened: bool,
    rejected: bool,
    settings_sent: bool,
    pending: Option<Vec<u8>>,
    outgoing: Receiver<Vec<u8>>,
    sender: SyncSender<Vec<u8>>,
    addrs: Vec<IpAddr>,
    granted: Option<Granted>,
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn worker(
    mut conn: quiche::Connection,
    sock: Arc<Datagram>,
    local: SocketAddr,
    rx: Receiver<(Vec<u8>, SocketAddr)>,
    tx: Sender<(Vec<u8>, SocketAddr)>,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
    routes: Routes,
    worker_id: u64,
) {
    let (sender, outgoing) = mpsc::sync_channel(QUEUE);
    let mut tunnel = Tunnel {
        stream: None,
        buf: Vec::new(),
        at: 0,
        headers: false,
        capsules: Vec::new(),
        capsule_at: 0,
        opened: false,
        rejected: false,
        settings_sent: false,
        pending: None,
        outgoing,
        sender,
        addrs: Vec::new(),
        granted: None,
    };
    loop {
        if conn.is_closed() {
            return;
        }
        let wait = conn.timeout().unwrap_or(TICK).min(TICK);
        match rx.recv_timeout(wait) {
            Ok((mut bytes, from)) => {
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(&mut bytes, info);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => conn.on_timeout(),
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if conn.is_established() {
            if !tunnel.settings_sent {
                send_server_settings(&mut conn, 3, 7, 11).ok();
                tunnel.settings_sent = true;
            }
            service(&mut conn, &shared, &spec, &mut tunnel);
        }
        while let Ok(packet) = tunnel.outgoing.try_recv() {
            if let Some(stream) = tunnel.stream {
                send_datagram(&mut conn, stream, &packet);
            }
        }
        if let Ok(mut table) = routes.lock() {
            for id in conn.source_ids() {
                table.insert(id.to_vec(), (worker_id, tx.clone()));
            }
        }
        quic::flush_egress(&mut conn, &sock);
    }
}

fn service(
    conn: &mut quiche::Connection,
    shared: &Arc<Shared>,
    spec: &ServerSpec,
    tunnel: &mut Tunnel,
) {
    let mut room = [0u8; 4096];
    while let Some(id) = conn.stream_readable_next() {
        if id % 4 != 0 {
            // Control and QPACK streams are read and forgotten, so their bytes do not sit on the connection waiting for a handler.
            while let Ok((n, _)) = conn.stream_recv(id, &mut room) {
                if n == 0 {
                    break;
                }
            }
            continue;
        }
        if tunnel.stream.is_some_and(|stream| stream != id) {
            while let Ok((n, _)) = conn.stream_recv(id, &mut room) {
                if n == 0 {
                    break;
                }
            }
            continue;
        }
        tunnel.stream = Some(id);
        loop {
            match conn.stream_recv(id, &mut room) {
                Ok((0, _)) | Err(quiche::Error::Done) => break,
                Ok((n, fin)) => {
                    tunnel.buf.extend_from_slice(&room[..n]);
                    if fin && !tunnel.headers {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        if !tunnel.headers {
            if !parse_head(tunnel, spec) {
                continue;
            }
            if let Some(head) = tunnel.pending.take() {
                send_stream(conn, id, &head, true).ok();
                tunnel.rejected = true;
            } else {
                accept(conn, shared, spec, tunnel);
            }
        } else if !tunnel.rejected {
            parse_capsules(conn, tunnel);
        }
    }
    if tunnel.opened && !tunnel.rejected {
        read_datagrams(conn, shared, spec, tunnel);
    }
}

/// Parses the request head once its HEADERS frame is whole; `false` leaves the
/// bytes for the next read.
fn parse_head(tunnel: &mut Tunnel, spec: &ServerSpec) -> bool {
    let mut at = tunnel.at;
    let Some(frame) = frames::h3_frame(&tunnel.buf, &mut at) else {
        return false;
    };
    if frame.kind != frames::H3_HEADERS {
        return false;
    }
    let length = frame.length as usize;
    let Some(block) = tunnel.buf.get(at..at + length) else {
        return false;
    };
    at += length;
    tunnel.at = at;
    let Some(fields) = hpack::qpack_fields(block) else {
        return false;
    };
    let field = |name: &[u8]| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_slice())
    };
    let path_ok = field(b":path").is_some_and(|path| path_matches(path, &spec.path));
    let method_ok = field(b":method") == Some(b"CONNECT");
    let protocol_ok = field(b":protocol") == Some(b"connect-ip");
    let capsules_ok = field(b"capsule-protocol")
        .and_then(|value| value.strip_prefix(b"?"))
        .is_some_and(|value| value.split(|byte| *byte == b';').next() == Some(b"1"));
    tunnel.headers = true;
    if !path_ok {
        reject(tunnel, 404);
        tunnel.rejected = true;
    } else if !method_ok || !protocol_ok || !capsules_ok {
        reject(tunnel, 400);
        tunnel.rejected = true;
    } else if !spec.authenticates(field(b"authorization")) {
        reject_auth(tunnel);
        tunnel.rejected = true;
    }
    true
}

fn path_query(bytes: &[u8]) -> (&[u8], &[u8]) {
    match bytes.iter().position(|byte| *byte == b'?') {
        Some(at) => (&bytes[..at], &bytes[at + 1..]),
        None => (bytes, &[]),
    }
}

/// xray parses the request URI before comparing, so an escaped star names the same path the literal does.
fn path_matches(got: &[u8], want: &str) -> bool {
    fn decode(bytes: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(bytes.len());
        let mut at = 0;
        while let Some(byte) = bytes.get(at) {
            if *byte != b'%' {
                out.push(*byte);
                at += 1;
                continue;
            }
            let high = (*bytes.get(at + 1)? as char).to_digit(16)?;
            let low = (*bytes.get(at + 2)? as char).to_digit(16)?;
            out.push((high * 16 + low) as u8);
            at += 3;
        }
        Some(out)
    }
    let (got_path, got_query) = path_query(got);
    let (want_path, want_query) = path_query(want.as_bytes());
    decode(got_path).as_deref() == decode(want_path).as_deref() && got_query == want_query
}

fn accept(
    conn: &mut quiche::Connection,
    shared: &Arc<Shared>,
    _spec: &ServerSpec,
    tunnel: &mut Tunnel,
) {
    let Some(stream) = tunnel.stream else {
        return;
    };
    let addrs = {
        let Ok(mut pool) = shared.pool.lock() else {
            reject(tunnel, 503);
            return;
        };
        pool.assign()
    };
    if addrs.is_empty() {
        reject(tunnel, 503);
        return;
    }
    let Some(granted) = register(shared, tunnel, &addrs) else {
        if let Ok(mut pool) = shared.pool.lock() {
            for address in &addrs {
                pool.release(*address);
            }
        }
        reject(tunnel, 503);
        return;
    };
    let assignments: Vec<Assigned> = addrs
        .iter()
        .map(|address| match address {
            IpAddr::V4(ip) => Assigned {
                request_id: 0,
                version: 4,
                address: {
                    let mut bytes = [0u8; 16];
                    bytes[..4].copy_from_slice(&ip.octets());
                    bytes
                },
                prefix: 32,
            },
            IpAddr::V6(ip) => Assigned {
                request_id: 0,
                version: 6,
                address: ip.octets(),
                prefix: 128,
            },
        })
        .collect();
    tunnel.addrs = addrs;
    tunnel.granted = Some(granted);
    tunnel.opened = true;
    let mut block = Vec::new();
    hpack::qpack_literal_many(
        &[(":status", "200"), ("capsule-protocol", "?1")],
        &mut block,
    );
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    send_stream(conn, stream, &head, false).ok();
    let mut control = Vec::new();
    connectip::address_assign_encode(&assignments, &mut control);
    send_data(conn, stream, &control).ok();
    control.clear();
    let mut routes = Vec::new();
    if tunnel.addrs.iter().any(IpAddr::is_ipv4) {
        routes.push(Route {
            first: [0u8; 16],
            last: {
                let mut last = [0u8; 16];
                last[..4].copy_from_slice(&[255, 255, 255, 255]);
                last
            },
            version: 4,
            protocol: 0,
        });
    }
    if tunnel.addrs.iter().any(IpAddr::is_ipv6) {
        routes.push(Route {
            first: [0u8; 16],
            last: [0xff; 16],
            version: 6,
            protocol: 0,
        });
    }
    connectip::route_advert_encode(&routes, &mut control);
    send_data(conn, stream, &control).ok();
}

fn register(shared: &Arc<Shared>, tunnel: &Tunnel, addrs: &[IpAddr]) -> Option<Granted> {
    let mut tunnels = shared.tunnels.lock().ok()?;
    let mut inserted = Vec::with_capacity(addrs.len());
    for address in addrs {
        if tunnels.contains_key(address) {
            for address in &inserted {
                tunnels.remove(address);
            }
            return None;
        }
        tunnels.insert(*address, tunnel.sender.clone());
        inserted.push(*address);
    }
    Some(Granted {
        shared: Arc::clone(shared),
        addrs: addrs.to_vec(),
    })
}

fn parse_capsules(conn: &mut quiche::Connection, tunnel: &mut Tunnel) {
    let mut at = tunnel.at;
    while let Some(frame) = frames::h3_frame(&tunnel.buf, &mut at) {
        let length = frame.length as usize;
        let Some(room) = tunnel.buf.get(at..at + length) else {
            break;
        };
        at += length;
        if frame.kind == frames::H3_DATA {
            tunnel.capsules.extend_from_slice(room);
        }
    }
    tunnel.buf.drain(..at);
    tunnel.at = 0;
    while let Some((used, capsule)) =
        connectip::capsule_split(&tunnel.capsules[tunnel.capsule_at..])
    {
        tunnel.capsule_at += used;
        let connectip::Capsule::AddressRequest(body) = capsule else {
            continue;
        };
        let mut requested = Vec::new();
        if connectip::address_assign(body, &mut requested).is_none() {
            continue;
        }
        let mut assignments = Vec::new();
        for request in &requested {
            let wanted = tunnel.addrs.iter().find(|address| {
                (request.version == 4 && address.is_ipv4())
                    || (request.version == 6 && address.is_ipv6())
            });
            let Some(address) = wanted else {
                continue;
            };
            let grant = match address {
                IpAddr::V4(ip) => Assigned {
                    request_id: request.request_id,
                    version: 4,
                    address: {
                        let mut bytes = [0u8; 16];
                        bytes[..4].copy_from_slice(&ip.octets());
                        bytes
                    },
                    prefix: 32,
                },
                IpAddr::V6(ip) => Assigned {
                    request_id: request.request_id,
                    version: 6,
                    address: ip.octets(),
                    prefix: 128,
                },
            };
            assignments.push(grant);
        }
        if !assignments.is_empty() {
            let mut body = Vec::new();
            connectip::address_assign_encode(&assignments, &mut body);
            if let Some(stream) = tunnel.stream {
                send_data(conn, stream, &body).ok();
            }
        }
    }
    if tunnel.capsule_at > 0 {
        tunnel.capsules.drain(..tunnel.capsule_at);
        tunnel.capsule_at = 0;
    }
}

fn read_datagrams(
    conn: &mut quiche::Connection,
    shared: &Arc<Shared>,
    spec: &ServerSpec,
    tunnel: &mut Tunnel,
) {
    let mut room = vec![0u8; 65535];
    while let Ok(n) = conn.dgram_recv(&mut room) {
        let Some((stream, packet)) = connectip::datagram_split(&room[..n]) else {
            continue;
        };
        if tunnel.stream != Some(stream) {
            continue;
        }
        forward(shared, spec, tunnel, packet);
    }
}

fn forward(shared: &Arc<Shared>, spec: &ServerSpec, tunnel: &Tunnel, packet: &[u8]) {
    let Some(destination) = packet_destination(packet) else {
        return;
    };
    if dropped_destination(destination) {
        return;
    }
    if let Ok(tunnels) = shared.tunnels.lock() {
        if let Some(other) = tunnels.get(&destination) {
            if !tunnel.addrs.contains(&destination) {
                let _ = other.try_send(packet.to_vec());
            }
            return;
        }
    }
    if spec.pool.holds(destination) && !shared.local.contains(&destination) {
        return;
    }
    let _ = shared.packets.send(Packet {
        peer: peer_key(&tunnel.addrs),
        bytes: packet.to_vec(),
    });
}

fn reject(tunnel: &mut Tunnel, status: u16) {
    let status = status.to_string();
    let mut block = Vec::new();
    hpack::qpack_literal_many(&[(":status", &status)], &mut block);
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    tunnel.buf.clear();
    tunnel.at = 0;
    // The response rides the next `send`; no stream is accepted, so there is nothing else to write.
    tunnel.pending = Some(head);
}

fn reject_auth(tunnel: &mut Tunnel) {
    let mut block = Vec::new();
    hpack::qpack_literal_many(
        &[(":status", "401"), ("www-authenticate", AUTH_REALM)],
        &mut block,
    );
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    tunnel.buf.clear();
    tunnel.at = 0;
    tunnel.pending = Some(head);
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn dropped_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local() || ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_unicast_link_local() || ip.is_multicast(),
    }
}

fn peer_key(addrs: &[IpAddr]) -> [u8; 32] {
    let mut key = [0u8; 32];
    for address in addrs {
        match address {
            IpAddr::V4(ip) => key[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => key[16..32].copy_from_slice(&ip.octets()),
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pool_skips_its_server_and_wraps() {
        let mut pool = AddressPool::from_prefixes(&["10.14.0.1/30".to_owned()]).expect("a pool");
        assert_eq!(
            pool.assign(),
            vec!["10.14.0.2".parse::<IpAddr>().expect("an address")]
        );
        assert_eq!(pool.assign().len(), 0);
        pool.release("10.14.0.2".parse().expect("an address"));
        assert_eq!(
            pool.assign(),
            vec!["10.14.0.2".parse::<IpAddr>().expect("an address")]
        );
    }

    #[test]
    fn a_v6_pool_keeps_its_last_host() {
        let mut pool = AddressPool::from_prefixes(&["fd14::1/126".to_owned()]).expect("a pool");
        assert_eq!(
            pool.assign(),
            vec!["fd14::2".parse::<IpAddr>().expect("an address")]
        );
        assert_eq!(
            pool.assign(),
            vec!["fd14::3".parse::<IpAddr>().expect("an address")]
        );
        assert_eq!(pool.assign().len(), 0);
    }

    #[test]
    fn a_pool_holds_every_address_its_prefix_covers() {
        let pool = AddressPool::from_prefixes(&["10.14.0.1/24".to_owned()]).expect("a pool");
        assert!(pool.holds("10.14.0.0".parse().expect("an address")));
        assert!(pool.holds("10.14.0.255".parse().expect("an address")));
        assert!(!pool.holds("10.15.0.1".parse().expect("an address")));
    }

    #[test]
    fn a_subnet_grant_names_its_first_host() {
        let grant = Assigned {
            request_id: 0,
            version: 4,
            address: [192, 0, 2, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix: 24,
        };
        assert_eq!(
            address_of(&grant),
            Some("192.0.2.1".parse().expect("an address"))
        );
        let grant = Assigned {
            request_id: 0,
            version: 6,
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5).octets(),
            prefix: 64,
        };
        assert_eq!(
            address_of(&grant),
            Some("2001:db8::1".parse().expect("an address"))
        );
    }

    fn pem_lines(pem: &str) -> String {
        pem.trim_end()
            .lines()
            .map(|line| format!("\"{line}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn inbound(settings: &str) -> Json {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{}],"key":[{}]}}]}}}}}}"#,
            pem_lines(&minted.cert.pem()),
            pem_lines(&minted.signing_key.serialize_pem())
        ))
        .expect("a masque inbound")
    }

    fn outbound(port: u16) -> Json {
        outbound_with(port, "Basic dUBleGFtcGxlLmNvbTpw")
    }

    fn outbound_with(port: u16, authorization: &str) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{{"server":{{"address":"127.0.0.1","port":{port}}}}},"streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true}},"masqueSettings":{{"headers":[{{"name":"Authorization","value":"{authorization}"}}]}}}}}}"#
        ))
        .expect("a masque outbound")
    }

    fn freedom(redirect: &str) -> Outbound {
        let root = crate::json::parse(&format!(
            r#"{{"outbounds":[{{"protocol":"freedom","settings":{{"redirect":"{redirect}"}}}}]}}"#
        ))
        .expect("a freedom outbound");
        Outbound::Freedom(Arc::new(
            crate::proxy::find_freedom_outbound(&root)
                .expect("the outbound reads")
                .expect("a freedom outbound"),
        ))
    }

    fn serve(redirect: &str) -> (Json, u16) {
        let inbound = inbound(
            r#"{"users":[{"email":"u@example.com","password":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#,
        );
        let port = serve_inbound(&inbound, &freedom(redirect), "127.0.0.1:0").expect("serve");
        (inbound, port)
    }

    #[test]
    fn a_tcp_flow_crosses_the_tunnel_to_a_freedom_dial() {
        use std::io::{Read as _, Write as _};
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = echo.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
        let (_inbound, port) = serve(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound(port)).expect("outbound");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        masque.serve_tcp(Connection::from(tun), &Destination::Address(target), &[]);
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 5];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"hello");
    }

    #[test]
    fn a_tcp_flow_crosses_the_tunnel_over_ipv6() {
        use std::io::{Read as _, Write as _};
        let Ok(echo) = std::net::TcpListener::bind("[::1]:0") else {
            return;
        };
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("[2001:db8::1]:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = echo.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
        let (_inbound, port) = serve(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound(port)).expect("outbound");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        masque.serve_tcp(Connection::from(tun), &Destination::Address(target), &[]);
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 5];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"hello");
    }

    #[test]
    fn a_datagram_flow_crosses_the_tunnel_to_a_freedom_dial() {
        let echo = std::net::UdpSocket::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (_inbound, port) = serve(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound(port)).expect("outbound");
        let relay = std::net::UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("relay address");
        let thread_relay = relay.try_clone().expect("clone");
        std::thread::spawn(move || masque.serve_udp(&thread_relay, None));
        std::thread::sleep(Duration::from_secs(1));
        let app = std::net::UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let mut frame = Vec::new();
        crate::proxy::socks_udp_frame(&mut frame, None, &target, b"hello");
        app.send_to(&frame, relay_address).expect("send");
        let mut received = [0u8; 2048];
        let (n, _) = app.recv_from(&mut received).expect("framed reply");
        let (remote, payload) = crate::proxy::parse_socks_udp(&received[..n]).expect("frame");
        assert_eq!(remote, target);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn a_wrong_password_is_refused_with_401() {
        let (_inbound, port) = serve("127.0.0.1:1");
        let outbound = outbound_with(port, "Basic dTpw");
        let spec = ClientSpec::from(&outbound).expect("spec");
        let reason = open(&spec).expect_err("the edge refuses");
        assert!(reason.ends_with("the edge answered 401"), "{reason}");
    }

    #[test]
    fn the_authority_prefers_a_configured_host() {
        let outbound = crate::json::parse(
            r#"{"settings":{"server":{"address":"127.0.0.1","port":8443}},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"host":"edge.example:443"}}}"#,
        )
        .expect("an outbound");
        let spec = ClientSpec::from(&outbound).expect("spec");
        assert_eq!(authority(&spec), "edge.example:443");
    }

    #[test]
    fn a_request_path_reads_the_way_xray_parses_it() {
        assert!(path_matches(b"/.well-known/masque/ip/*/*/", DEFAULT_PATH));
        assert!(path_matches(
            b"/.well-known/masque/ip/%2A/%2A/",
            DEFAULT_PATH
        ));
        assert!(!path_matches(b"/.well-known/masque/ip/*/*", DEFAULT_PATH));
        assert!(!path_matches(
            b"/.well-known/masque/ip/*/*/?x=1",
            DEFAULT_PATH
        ));
        assert!(!path_matches(
            b"/.well-known/masque/ip/192.0.2.1/6/",
            DEFAULT_PATH
        ));
    }

    #[test]
    fn the_datagram_prefix_round_trips() {
        let mut out = Vec::new();
        connectip::datagram_prefix(8, &mut out);
        out.extend_from_slice(&[0x45, 0, 0, 20]);
        let (stream, packet) = connectip::datagram_split(&out).expect("a datagram");
        assert_eq!(stream, 8);
        assert_eq!(packet, &[0x45, 0, 0, 20]);
    }
}
