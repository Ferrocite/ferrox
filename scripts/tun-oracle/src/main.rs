//! Records the (target, payload) dial set a pinned userspace stack produces from
//! `script.txt`. This is the oracle of matrix row 29: the bytes in `expected.txt`
//! come from running smoltcp 0.12 — the stack the pinned zero-tun `zero-tun`
//! crate builds its TUN inbound on — over the rendered packet stream, not from
//! this tree. `tun::tests::the_dial_set_matches_the_pinned_stream` diffs the
//! Ferrox inbound's TCP half against the same pair, and
//! `tun::tests::the_datagram_dial_set_matches_the_pinned_stream` its UDP half.
//!
//! Run: `cargo run --manifest-path scripts/tun-oracle/Cargo.toml` in the workspace.

use std::collections::VecDeque;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Packet, TcpPacket,
};

struct Frame {
    at: Instant,
    bytes: Vec<u8>,
}

/// A medium-IP device with queued frames in both directions, so no root,
/// no `CAP_NET_ADMIN`, and no real interface: the same injected-descriptor
/// shape the Ferrox inbound runs on in CI.
struct QueueDevice {
    rx: VecDeque<Frame>,
    tx: VecDeque<Frame>,
}

struct Rx<'a>(&'a mut VecDeque<Frame>);
struct Tx<'a>(&'a mut VecDeque<Frame>, Instant);

impl<'a> phy::RxToken for Rx<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let frame = self.0.pop_front().expect("a queued frame");
        f(&frame.bytes)
    }
}

impl<'a> phy::TxToken for Tx<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0u8; len];
        let result = f(&mut bytes);
        self.0.push_back(Frame { at: self.1, bytes });
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = Rx<'a>;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let timestamp = self.rx.front()?.at;
        Some((Rx(&mut self.rx), Tx(&mut self.tx, timestamp)))
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(Tx(&mut self.tx, timestamp))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

/// The one's-complement sum over a slice of big-endian words, folded to a
/// checksum; the trailing odd byte (which both IP and the pseudo-header can
/// carry) enters as the high byte of one word, as the spec draws it.
fn checksum(mut sum: u32, bytes: &[u8]) -> u16 {
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        sum += u32::from(bytes[i]) << 8;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    !(sum as u16)
}

/// The rendering rules for a TCP flow, shared with `script.txt` and the Rust
/// test: SYN, then the ACK whose acknowledgement number is this stack's own
/// SYN-ACK sequence plus one, then each payload chunk as one PSH, then FIN.
fn build_tcp_packet(
    src: Ipv4Address,
    dst: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    syn: bool,
    ack_flag: bool,
    fin: bool,
    psh: bool,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut pkt = vec![0u8; ip_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(0, &pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let t = &mut pkt[20..40];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;
    t[13] = (if fin { 1 } else { 0 }
        | if syn { 2 } else { 0 }
        | if psh { 8 } else { 0 }
        | if ack_flag { 16 } else { 0 });
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);
    let mut pseudo: Vec<u8> = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[20..]);
    pkt[36..38].copy_from_slice(&checksum(0, &pseudo).to_be_bytes());
    pkt
}

/// One IPv4 UDP datagram: the header carries the two ports, the length over the
/// header plus body, and a checksum over the same pseudo-header a TCP segment
/// uses but with protocol 17. Every body byte is delivered verbatim, so two
/// datagrams to one port stay two, never one coalesced stream.
fn build_udp_packet(
    src: Ipv4Address,
    dst: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut pkt = vec![0u8; ip_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(0, &pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let u = &mut pkt[20..28];
    u[0..2].copy_from_slice(&src_port.to_be_bytes());
    u[2..4].copy_from_slice(&dst_port.to_be_bytes());
    u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    let mut pseudo: Vec<u8> = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[20..]);
    let sum = checksum(0, &pseudo);
    // A zero UDP checksum means "not computed"; the fold rarely lands there, and where it does the datagram still carries its own length, so pin the field to the one value that is never the sentinel.
    pkt[26..28].copy_from_slice(&if sum == 0 {
        [0xff, 0xff]
    } else {
        sum.to_be_bytes()
    });
    pkt
}

struct Flow {
    destination: IpEndpoint,
    source_port: u16,
    syn_seq: u32,
    chunks: Vec<Vec<u8>>,
}

/// One `UFLOW` line: a client source port, a destination endpoint, and every
/// datagram body that flows, each rendered as its own IPv4 UDP packet.
struct DatagramFlow {
    destination: IpEndpoint,
    source_port: u16,
    datagrams: Vec<Vec<u8>>,
}

fn parse_endpoint(field: &str) -> IpEndpoint {
    let destination = field.parse::<std::net::SocketAddr>().unwrap();
    let std::net::IpAddr::V4(ip) = destination.ip() else {
        panic!("the script names IPv4 endpoints only");
    };
    let o = ip.octets();
    IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])),
        destination.port(),
    )
}

fn parse_script(path: &std::path::Path) -> (Vec<Flow>, Vec<DatagramFlow>) {
    let text = std::fs::read_to_string(path).expect("script.txt beside this file");
    let mut flows = Vec::new();
    let mut datagrams = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("FLOW") => {
                let destination = parse_endpoint(fields.next().unwrap());
                let source_port = fields.next().unwrap().parse().unwrap();
                let syn_seq = fields.next().unwrap().parse().unwrap();
                let chunks = fields.map(hex_decode).collect();
                flows.push(Flow {
                    destination,
                    source_port,
                    syn_seq,
                    chunks,
                });
            }
            Some("UFLOW") => {
                let destination = parse_endpoint(fields.next().unwrap());
                let source_port = fields.next().unwrap().parse().unwrap();
                let bodies = fields.map(hex_decode).collect();
                datagrams.push(DatagramFlow {
                    destination,
                    source_port,
                    datagrams: bodies,
                });
            }
            other => panic!("the script holds only FLOW and UFLOW lines, found {other:?}"),
        }
    }
    (flows, datagrams)
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The SYN-ACK the stack emits in reply to the fed SYN: its sequence number is
/// the acknowledgement number the script's next packet must carry.
fn observed_syn_ack_seq(frames: &VecDeque<Frame>) -> u32 {
    for frame in frames {
        if let Ok(ip) = Ipv4Packet::new_checked(&frame.bytes[..]) {
            if let Ok(tcp) = TcpPacket::new_checked(ip.payload()) {
                if tcp.syn() && tcp.ack() {
                    return tcp.seq_number().0 as u32;
                }
            }
        }
    }
    panic!("the stack answered the SYN with a SYN-ACK");
}

fn main() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("script.txt");
    let (flows, dgram_flows) = parse_script(&script);

    let mut device = QueueDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        let mut seen: Vec<IpAddress> = Vec::new();
        for destination in flows
            .iter()
            .map(|flow| flow.destination)
            .chain(dgram_flows.iter().map(|flow| flow.destination))
        {
            if !seen.contains(&destination.addr) {
                seen.push(destination.addr);
                addrs.push(IpCidr::new(destination.addr, 32)).unwrap();
            }
        }
    });
    let mut sockets = SocketSet::new(vec![]);

    let mut handles = Vec::new();
    for flow in &flows {
        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0u8; 8192]),
            SocketBuffer::new(vec![0u8; 8192]),
        );
        socket
            .listen(flow.destination)
            .expect("listen on the script endpoint");
        handles.push(sockets.add(socket));
    }
    let mut udp_handles = Vec::new();
    for flow in &dgram_flows {
        let mut socket = UdpSocket::new(
            UdpPacketBuffer::new(vec![UdpPacketMetadata::EMPTY; 8], vec![0u8; 8192]),
            UdpPacketBuffer::new(vec![UdpPacketMetadata::EMPTY; 8], vec![0u8; 512]),
        );
        socket
            .bind(flow.destination)
            .expect("bind on the script endpoint");
        udp_handles.push(sockets.add(socket));
    }

    let client = Ipv4Address::new(10, 0, 0, 2);
    let mut tcp_dials: Vec<(String, Vec<u8>)> = Vec::new();
    let mut udp_dials: Vec<(String, Vec<u8>)> = Vec::new();
    let mut now = Instant::ZERO;

    for (flow, handle) in flows.iter().zip(handles.iter()) {
        let IpAddress::Ipv4(dst) = flow.destination.addr;
        let syn = build_tcp_packet(
            client,
            dst,
            flow.source_port,
            flow.destination.port,
            flow.syn_seq,
            0,
            true,
            false,
            false,
            false,
            &[],
        );
        now += smoltcp::time::Duration::from_millis(1);
        device.rx.push_back(Frame {
            at: now,
            bytes: syn,
        });
        poll(&mut iface, &mut device, &mut sockets, now, 8);
        let peer_ack = observed_syn_ack_seq(&device.tx) + 1;
        device.tx.clear();

        let ack = build_tcp_packet(
            client,
            dst,
            flow.source_port,
            flow.destination.port,
            flow.syn_seq + 1,
            peer_ack,
            false,
            true,
            false,
            false,
            &[],
        );
        now += smoltcp::time::Duration::from_millis(1);
        device.rx.push_back(Frame {
            at: now,
            bytes: ack,
        });
        poll(&mut iface, &mut device, &mut sockets, now, 4);
        assert_eq!(
            state(&sockets, *handle),
            smoltcp::socket::tcp::State::Established,
            "the handshake established"
        );

        let mut seq = flow.syn_seq + 1;
        for chunk in &flow.chunks {
            let psh = build_tcp_packet(
                client,
                dst,
                flow.source_port,
                flow.destination.port,
                seq,
                peer_ack,
                false,
                true,
                false,
                true,
                chunk,
            );
            now += smoltcp::time::Duration::from_millis(1);
            device.rx.push_back(Frame {
                at: now,
                bytes: psh,
            });
            poll(&mut iface, &mut device, &mut sockets, now, 4);
            seq += chunk.len() as u32;
        }
        let fin = build_tcp_packet(
            client,
            dst,
            flow.source_port,
            flow.destination.port,
            seq,
            peer_ack,
            false,
            true,
            true,
            false,
            &[],
        );
        now += smoltcp::time::Duration::from_millis(1);
        device.rx.push_back(Frame {
            at: now,
            bytes: fin,
        });
        poll(&mut iface, &mut device, &mut sockets, now, 8);

        let mut payload = Vec::new();
        let mut buf = [0u8; 4096];
        let socket = sockets.get_mut::<TcpSocket>(*handle);
        loop {
            match socket.recv_slice(&mut buf) {
                Ok(0) => break,
                Ok(n) => payload.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        let target = format!("{}", flow.destination);
        tcp_dials.push((target, payload));
    }

    for (flow, handle) in dgram_flows.iter().zip(udp_handles.iter()) {
        let IpAddress::Ipv4(dst) = flow.destination.addr;
        for body in &flow.datagrams {
            let pkt = build_udp_packet(client, dst, flow.source_port, flow.destination.port, body);
            now += smoltcp::time::Duration::from_millis(1);
            device.rx.push_back(Frame {
                at: now,
                bytes: pkt,
            });
            poll(&mut iface, &mut device, &mut sockets, now, 4);
        }
        // Drain in arrival order: the stack hands each datagram up on its own, so a flow of two bodies is two dials, never the concatenation a TCP stream would form.
        let socket = sockets.get_mut::<UdpSocket>(*handle);
        let target = format!("{}", flow.destination);
        while let Ok((payload, _meta)) = socket.recv() {
            udp_dials.push((target.clone(), payload.to_vec()));
        }
    }

    for (target, payload) in &tcp_dials {
        println!("DIAL {target} {}", hex_encode(payload));
    }
    for (target, payload) in &udp_dials {
        println!("UDIAL {target} {}", hex_encode(payload));
    }
}

fn poll(
    iface: &mut Interface,
    device: &mut QueueDevice,
    sockets: &mut SocketSet,
    now: Instant,
    rounds: usize,
) {
    for _ in 0..rounds {
        iface.poll(now, device, sockets);
    }
}

fn state(sockets: &SocketSet, handle: SocketHandle) -> smoltcp::socket::tcp::State {
    sockets.get::<TcpSocket>(handle).state()
}
