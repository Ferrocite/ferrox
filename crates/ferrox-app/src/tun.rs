//! The native TUN device inbound: opens a virtual interface, reads IP packets, turns each
//! TCP flow into a proxy dial through the existing outbound relay machinery.
//!
//! Byte-identity: a TUN carries no wire byte-stream to diff, so this row's identity claim is
//! the (target, payload) dial-set differential — the set of (destination, payload) pairs the
//! inbound produces from a given packet stream must match the pinned reference. Proven by
//! the loopback test set; the oracle lives in `scripts/tun-oracle`.
//!
//! Platform opens: Linux `/dev/net/tun` + `TUNSETIFF`, macOS utun, and an inherited
//! descriptor (`FERROX_TUN_FD`). The privileged opens are compile-checked only — no CI
//! runner holds `CAP_NET_ADMIN` — while the inherited-fd path runs fully in tests.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::sync::{mpsc, Arc};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::budgets;
use crate::conn::Connection;
use ferrox_core::foxy::connectip::{checksum, ipv4_checksum, ipv4_head, Ipv4Head, IPV4_HEADER};

const DEFAULT_MTU: usize = 1500;
const TCP_PROTO: u8 = 6;
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

pub(crate) fn is_device(protocol: &str) -> bool {
    matches!(protocol, "tun" | "utun" | "wintun" | "tun2socks")
}

pub(crate) struct Spec {
    name: String,
    mtu: usize,
}

impl Spec {
    pub(crate) fn new(name: Option<&str>, mtu: Option<usize>) -> Self {
        Self {
            name: name
                .filter(|n| !n.is_empty())
                .unwrap_or("ferrox0")
                .to_owned(),
            mtu: mtu.filter(|m| *m > 0).unwrap_or(DEFAULT_MTU),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TcpHead {
    source_port: u16,
    destination_port: u16,
    seq: u32,
    flags: u8,
}

fn tcp_head(body: &[u8]) -> Option<(TcpHead, &[u8])> {
    if body.len() < 20 {
        return None;
    }
    let source_port = u16::from_be_bytes([body[0], body[1]]);
    let destination_port = u16::from_be_bytes([body[2], body[3]]);
    let seq = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let data_offset = usize::from(body[12] >> 4) * 4;
    if data_offset < 20 || data_offset > body.len() {
        return None;
    }
    let flags = body[13];
    Some((
        TcpHead {
            source_port,
            destination_port,
            seq,
            flags,
        },
        &body[data_offset..],
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
}

/// A TUN device: a file descriptor carrying raw IP packets (`IFF_TUN` | `IFF_NO_PI` on Linux).
pub(crate) struct Device {
    handle: std::fs::File,
    mtu: usize,
}

impl Device {
    pub(crate) fn open(spec: &Spec) -> io::Result<Self> {
        if let Some(handle) = inherited_handle() {
            return Ok(Self {
                handle,
                mtu: spec.mtu,
            });
        }
        #[cfg(target_os = "linux")]
        return Self::open_linux(spec);
        #[cfg(target_os = "macos")]
        return Self::open_macos(spec);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no TUN platform open; set FERROX_TUN_FD for an inherited descriptor",
        ))
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = buf.len().min(self.mtu + 4);
        self.handle.read(&mut buf[..limit])
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.handle.write_all(packet)
    }

    fn clone_writer(&self) -> io::Result<std::fs::File> {
        self.handle.try_clone()
    }

    #[cfg(all(test, unix))]
    fn from_handle(handle: std::fs::File, mtu: usize) -> Self {
        Self { handle, mtu }
    }
}

#[cfg(unix)]
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_raw_fd()
    }
}

fn inherited_handle() -> Option<std::fs::File> {
    let fd_str = std::env::var_os("FERROX_TUN_FD")?;
    let fd: i64 = fd_str.to_str()?.parse().ok()?;
    if fd < 0 {
        return None;
    }
    #[cfg(unix)]
    return Some(unsafe { std::fs::File::from_raw_fd(fd as RawFd) });
    #[cfg(not(unix))]
    {
        let _ = fd;
        None
    }
}

#[cfg(target_os = "linux")]
impl Device {
    fn open_linux(spec: &Spec) -> io::Result<Self> {
        use std::ffi::CString;
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; 16],
            ifr_flags: libc::c_short,
            _pad: [u8; 22],
        }
        let path = CString::new("/dev/net/tun").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut req = IfReq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let n = spec.name.as_bytes();
        let l = n.len().min(15);
        req.ifr_name[..l].copy_from_slice(&n[..l]);
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &req) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Self {
            handle: unsafe { std::fs::File::from_raw_fd(fd) },
            mtu: spec.mtu,
        })
    }
}

#[cfg(target_os = "macos")]
impl Device {
    fn open_macos(spec: &Spec) -> io::Result<Self> {
        const SYSPROTO_CONTROL: libc::c_int = 2;
        const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
        const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
        #[repr(C)]
        struct CtlInfo {
            ci_id: u32,
            ci_name: [u8; 128],
            ci_rcvbuf: libc::c_int,
            ci_sndbuf: libc::c_int,
            ci_flags: u16,
            _p: [u8; 6],
            ci_maxunits: libc::c_int,
            _r: [u8; 2],
        }
        #[repr(C)]
        struct SockaddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            _r: [u8; 8],
        }
        let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut info = CtlInfo {
            ci_id: 0,
            ci_name: [0; 128],
            ci_rcvbuf: 0,
            ci_sndbuf: 0,
            ci_flags: 0,
            _p: [0; 6],
            ci_maxunits: 0,
            _r: [0; 2],
        };
        let nl = UTUN_CONTROL_NAME.len();
        info.ci_name[..nl].copy_from_slice(UTUN_CONTROL_NAME);
        if unsafe { libc::ioctl(fd, CTLIOCGINFO as _, &mut info) } < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: 2,
            sc_id: info.ci_id,
            sc_unit: 0,
            _r: [0; 8],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Self {
            handle: unsafe { std::fs::File::from_raw_fd(fd) },
            mtu: spec.mtu,
        })
    }
}

/// Build an IPv4 + TCP packet with valid IP and TCP checksums.
fn build_tcp_packet(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (src, src_port) = src;
    let (dst, dst_port) = dst;
    let tcp_len = 20 + payload.len();
    let ip_len = IPV4_HEADER + tcp_len;
    let mut pkt = vec![0u8; ip_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = TCP_PROTO;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    let c = ipv4_checksum(&pkt[..IPV4_HEADER]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    let t = &mut pkt[IPV4_HEADER..IPV4_HEADER + 20];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack_num.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&window.to_be_bytes());
    if !payload.is_empty() {
        pkt[IPV4_HEADER + 20..].copy_from_slice(payload);
    }
    let mut pseudo: Vec<u8> = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0);
    pseudo.push(TCP_PROTO);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[IPV4_HEADER..]);
    let tc = checksum(&pseudo);
    pkt[IPV4_HEADER + 16..IPV4_HEADER + 18].copy_from_slice(&tc.to_be_bytes());
    pkt
}

/// One active TCP flow's state. The two cursors are shared with the response
/// thread: `rcv_nxt` advances as the handler delivers payload to the proxy, and
/// `snd_nxt` advances as the response thread sends payload out, so a pure ACK
/// carries both numbers truthfully.
struct Flow {
    write_half: TcpStream,
    rcv_nxt: Arc<AtomicU32>,
    snd_nxt: Arc<AtomicU32>,
    /// Payload reached the proxy since the response thread's last idle expiry: a flow is alive when either direction spoke inside the budget.
    busy: Arc<AtomicBool>,
    last_acked: u32,
}

/// The relay function the TUN handler calls per TCP flow: takes the proxied Connection and
/// the destination extracted from the packet headers.
pub(crate) type Relay = Arc<dyn Fn(Connection, crate::proxy::Destination) + Send + Sync>;

/// The TUN handler: reads packets, relays TCP flows through the proxy outbound.
pub(crate) struct Handler {
    device: Device,
    relay: Relay,
    flows: HashMap<FlowKey, Flow>,
    ended_tx: mpsc::Sender<FlowKey>,
    ended_rx: mpsc::Receiver<FlowKey>,
}

impl Handler {
    pub(crate) fn new(device: Device, relay: Relay) -> Self {
        let (ended_tx, ended_rx) = mpsc::channel();
        Self {
            device,
            relay,
            flows: HashMap::new(),
            ended_tx,
            ended_rx,
        }
    }

    pub(crate) fn serve(&mut self) -> io::Result<()> {
        let mut buf = vec![0u8; self.device.mtu + 64];
        loop {
            let n = self.device.read_packet(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            if let Err(e) = self.dispatch(&buf[..n]) {
                eprintln!("tun dispatch: {e}");
            }
        }
    }

    fn dispatch(&mut self, packet: &[u8]) -> io::Result<()> {
        let Some((ip, body)) = ipv4_head(packet) else {
            return Ok(());
        };
        match ip.protocol {
            TCP_PROTO => self.handle_tcp(&ip, body),
            _ => Ok(()),
        }
    }

    fn handle_tcp(&mut self, ip: &Ipv4Head, body: &[u8]) -> io::Result<()> {
        let Some((tcp, payload)) = tcp_head(body) else {
            return Ok(());
        };
        let key = FlowKey {
            source_port: tcp.source_port,
            destination: ip.destination,
            destination_port: tcp.destination_port,
        };
        if tcp.flags & FLAG_SYN != 0 && tcp.flags & FLAG_ACK == 0 {
            return self.accept_flow(ip, &tcp, key);
        }
        if tcp.flags & FLAG_RST != 0 {
            self.close_flow(key);
            return Ok(());
        }
        let mut dead = false;
        if let Some(flow) = self.flows.get_mut(&key) {
            let end = tcp.seq.wrapping_add(payload.len() as u32);
            let fin = tcp.flags & FLAG_FIN != 0;
            if !payload.is_empty() {
                flow.busy.store(true, Relaxed);
                dead = flow.write_half.write_all(payload).is_err();
                flow.rcv_nxt.store(end, Relaxed);
            }
            if fin {
                flow.rcv_nxt.store(end.wrapping_add(1), Relaxed);
                let _ = flow.write_half.shutdown(Shutdown::Write);
            }
            // Delayed like the references: answer at a push, at a finish, or at a full MTU unacked.
            let unacked = flow.rcv_nxt.load(Relaxed).wrapping_sub(flow.last_acked);
            if fin
                || (tcp.flags & FLAG_PSH != 0 && !payload.is_empty())
                || unacked >= self.device.mtu as u32
            {
                let ack = build_tcp_packet(
                    (ip.destination, tcp.destination_port),
                    (ip.source, tcp.source_port),
                    flow.snd_nxt.load(Relaxed),
                    flow.rcv_nxt.load(Relaxed),
                    FLAG_ACK,
                    65535,
                    &[],
                );
                let _ = self.device.write_packet(&ack);
                flow.last_acked = flow.rcv_nxt.load(Relaxed);
            }
        }
        // The proxy half is gone: an upload into a closed lane has no flow to finish, and keeping the entry would keep its socket and its cursors.
        if dead {
            self.close_flow(key);
        }
        Ok(())
    }

    fn accept_flow(&mut self, ip: &Ipv4Head, tcp: &TcpHead, key: FlowKey) -> io::Result<()> {
        // Flows whose response thread has already left are removed here, so the packet path pays nothing for the reap.
        while let Ok(ended) = self.ended_rx.try_recv() {
            self.flows.remove(&ended);
        }
        let local_ip = ip.destination;
        let remote_ip = ip.source;
        let local_port = tcp.destination_port;
        let remote_port = tcp.source_port;
        let syn_seq = tcp.seq;

        let syn_ack = build_tcp_packet(
            (local_ip, local_port),
            (remote_ip, remote_port),
            syn_seq.wrapping_add(1),
            syn_seq.wrapping_add(1),
            FLAG_SYN | FLAG_ACK,
            65535,
            &[],
        );
        self.device.write_packet(&syn_ack)?;

        let target = SocketAddr::from((ip.destination, tcp.destination_port));
        let destination = crate::proxy::Destination::from(target);
        let relay = Arc::clone(&self.relay);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let pair_addr = listener.local_addr()?;
        let tun_half = TcpStream::connect(pair_addr)?;
        let (proxy_half, _) = listener.accept()?;
        drop(listener);

        let write_half = tun_half.try_clone()?;
        let rcv_nxt = Arc::new(AtomicU32::new(syn_seq.wrapping_add(1)));
        let snd_nxt = Arc::new(AtomicU32::new(syn_seq.wrapping_add(2)));
        let busy = Arc::new(AtomicBool::new(false));
        self.flows.insert(
            key,
            Flow {
                write_half,
                rcv_nxt: Arc::clone(&rcv_nxt),
                snd_nxt: Arc::clone(&snd_nxt),
                busy: Arc::clone(&busy),
                last_acked: syn_seq.wrapping_add(1),
            },
        );

        let mut read_half = tun_half;
        // Silence past the idle budget is death: an untimed read parks a thread, and with it the flow's relay leg and its lane, for the life of the process.
        read_half.set_read_timeout(Some(budgets::udp_idle()))?;
        let mut dev_writer = self.device.clone_writer()?;
        let ended_tx = self.ended_tx.clone();

        std::thread::spawn(move || {
            let conn = Connection::from(proxy_half);
            relay(conn, destination);
        });

        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            loop {
                match read_half.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let seq = snd_nxt.fetch_add(n as u32, Relaxed);
                        let pkt = build_tcp_packet(
                            (local_ip, local_port),
                            (remote_ip, remote_port),
                            seq,
                            rcv_nxt.load(Relaxed),
                            FLAG_PSH | FLAG_ACK,
                            65535,
                            &buf[..n],
                        );
                        let mut dev = Device {
                            handle: dev_writer,
                            mtu: 65535,
                        };
                        if dev.write_packet(&pkt).is_err() {
                            break;
                        }
                        dev_writer = dev.handle;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    // The budget expired with nothing to carry: the upload leg gets one more budget to speak, and a silent one ends the flow.
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if !busy.swap(false, Relaxed) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Both halves, because the handler's write half is a clone of this descriptor and only a shutdown tells it the flow is over.
            let _ = read_half.shutdown(Shutdown::Both);
            let _ = ended_tx.send(key);
        });

        Ok(())
    }

    fn close_flow(&mut self, key: FlowKey) {
        if let Some(flow) = self.flows.remove(&key) {
            let _ = flow.write_half.shutdown(Shutdown::Both);
        }
    }
}

pub(crate) fn refusal_reason(spec: &Spec) -> String {
    format!(
        "`{}` (mtu {} B) cannot open a TUN: no ioctl and no FERROX_TUN_FD",
        spec.name, spec.mtu
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_protocols_recognized() {
        for p in ["tun", "utun", "wintun", "tun2socks"] {
            assert!(is_device(p));
        }
        assert!(!is_device("vless"));
    }

    #[test]
    fn tcp_head_parses_syn() {
        let pkt = build_tcp_packet(
            ([10, 0, 0, 2], 12345),
            ([10, 0, 0, 1], 80),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.protocol, TCP_PROTO);
        let (tcp, pl) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(tcp.destination_port, 80);
        assert_eq!(tcp.seq, 1000);
        assert_eq!(tcp.flags, FLAG_SYN);
        assert_eq!(pl, []);
    }

    #[test]
    fn tcp_head_parses_payload() {
        let pkt = build_tcp_packet(
            ([1, 2, 3, 4], 999),
            ([5, 6, 7, 8], 1000),
            50,
            10,
            FLAG_ACK,
            4096,
            b"hello tun",
        );
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(payload, b"hello tun");
    }

    #[test]
    fn tcp_head_refuses_short_segment() {
        assert!(tcp_head(&[0u8; 10]).is_none());
    }

    #[test]
    fn the_payload_is_borrowed_from_the_read_buffer() {
        // Pointer identity, not bytes: a parsing copy returns the same bytes from a moved base.
        let pkt = build_tcp_packet(
            ([10, 0, 0, 2], 5),
            ([10, 0, 0, 1], 6),
            100,
            0,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"borrow me",
        );
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_tcp, payload) = tcp_head(body).unwrap();
        let base = pkt.as_ptr() as usize;
        assert_eq!(payload.as_ptr() as usize, base + IPV4_HEADER + 20);
        assert!(payload.as_ptr() as usize + payload.len() <= base + pkt.len());
    }

    #[test]
    fn build_tcp_packet_roundtrips() {
        let pkt = build_tcp_packet(
            ([10, 0, 0, 1], 443),
            ([10, 0, 0, 2], 55555),
            100,
            200,
            FLAG_SYN | FLAG_ACK,
            65535,
            b"x",
        );
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.source, [10, 0, 0, 1]);
        assert_eq!(ip.destination, [10, 0, 0, 2]);
        let (_tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(payload, b"x");
    }

    #[cfg(unix)]
    #[test]
    fn a_syn_flow_replies_syn_ack_over_a_socketpair() {
        let (a, b) = unix_socketpair().unwrap();
        let device = Device::from_handle(a, DEFAULT_MTU);
        let mut peer = b;

        let relay: Relay = Arc::new(|_conn, _dest| {});
        let mut handler = Handler::new(device, relay);

        let syn = build_tcp_packet(
            ([10, 0, 0, 2], 44444),
            ([10, 0, 0, 1], 8080),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], &syn[..]);
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = vec![0u8; 64];
        let rn = peer.read(&mut reply).unwrap();
        assert!(rn > 0);
        let (_rip, rbody) = ipv4_head(&reply[..rn]).unwrap();
        let (rtcp, _) = tcp_head(rbody).unwrap();
        assert_eq!(rtcp.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(rtcp.source_port, 8080);
        assert_eq!(rtcp.destination_port, 44444);
        assert_eq!(rtcp.seq, 1001);
    }

    #[cfg(unix)]
    fn unix_socketpair() -> io::Result<(std::fs::File, std::fs::File)> {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((unsafe { std::fs::File::from_raw_fd(fds[0]) }, unsafe {
            std::fs::File::from_raw_fd(fds[1])
        }))
    }

    #[cfg(unix)]
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// One `FLOW` line of `scripts/tun-oracle/script.txt`: the destination the packet
    /// names, the client port, the SYN sequence, and the payload chunks as separate
    /// segments — the same rendering rules the Go oracle reads from that file.
    #[cfg(unix)]
    struct FlowSpec {
        destination: SocketAddr,
        source_port: u16,
        syn_seq: u32,
        chunks: Vec<Vec<u8>>,
    }

    #[cfg(unix)]
    const SCRIPT_CLIENT: [u8; 4] = [10, 0, 0, 2];

    #[cfg(unix)]
    fn parse_script(text: &str) -> Vec<FlowSpec> {
        let mut flows = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            assert_eq!(
                fields.next(),
                Some("FLOW"),
                "the script holds only FLOW lines"
            );
            let destination = fields.next().unwrap().parse().unwrap();
            let source_port = fields.next().unwrap().parse().unwrap();
            let syn_seq = fields.next().unwrap().parse().unwrap();
            let chunks = fields.map(hex_decode).collect();
            flows.push(FlowSpec {
                destination,
                source_port,
                syn_seq,
                chunks,
            });
        }
        flows
    }

    /// One `DIAL` line of the golden: the target address the stack dialed and every
    /// payload byte the stack handed up on that flow, to EOF.
    #[cfg(unix)]
    fn parse_expected(text: &str) -> Vec<(String, Vec<u8>)> {
        let mut dials = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            assert_eq!(
                fields.next(),
                Some("DIAL"),
                "the golden holds only DIAL lines"
            );
            dials.push((
                fields.next().unwrap().to_owned(),
                hex_decode(fields.next().unwrap()),
            ));
        }
        dials.sort();
        dials
    }

    /// The recorded dial set: every (target, payload) pair a relay saw, shared
    /// between the recorder and the tests that wait on it.
    #[cfg(unix)]
    type Dials = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    /// A dial recorder behind the same `Relay` seam the app installs: it reads each
    /// flow to EOF, exactly as `serve_connect` does, and keeps (target, payload).
    #[cfg(unix)]
    fn recording_relay(results: Dials) -> Relay {
        Arc::new(
            move |mut conn: Connection, dest: crate::proxy::Destination| {
                let mut payload = Vec::new();
                let _ = conn.read_to_end(&mut payload);
                let target = match dest {
                    crate::proxy::Destination::Address(a) => a.to_string(),
                    crate::proxy::Destination::Name(host, port) => format!("{host}:{port}"),
                };
                results.lock().unwrap().push((target, payload));
            },
        )
    }

    #[cfg(unix)]
    fn wait_for(results: &Dials, count: usize) {
        for _ in 0..2_500 {
            if results.lock().unwrap().len() == count {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!(
            "{count} dials did not arrive; got {:?}",
            results.lock().unwrap().len()
        );
    }

    /// One client-side flow rendered by the script's rules: SYN, then the ACK whose
    /// acknowledgement number is read off this stack's own SYN-ACK (a reference picks
    /// its initial sequence itself — `tcp_lightweight.go` `rand.Uint32()` — so the
    /// golden cannot pin it), then each payload chunk as one PSH, then FIN.
    #[cfg(unix)]
    fn run_flow(handler: &mut Handler, peer: &mut std::fs::File, flow: &FlowSpec, buf: &mut [u8]) {
        let SocketAddr::V4(destination) = flow.destination else {
            panic!("the script names IPv4 destinations only");
        };
        let dst = destination.ip().octets();
        let dst_port = destination.port();
        let endpoint = (dst, dst_port);
        let client = (SCRIPT_CLIENT, flow.source_port);
        let syn = build_tcp_packet(client, endpoint, flow.syn_seq, 0, FLAG_SYN, 65535, &[]);
        peer.write_all(&syn).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let syn_ack = next_syn_ack(peer);
        assert_eq!(
            syn_ack.flags,
            FLAG_SYN | FLAG_ACK,
            "the handshake opens with a SYN-ACK"
        );
        let peer_ack = syn_ack.seq.wrapping_add(1);

        let ack = build_tcp_packet(
            client,
            endpoint,
            flow.syn_seq.wrapping_add(1),
            peer_ack,
            FLAG_ACK,
            65535,
            &[],
        );
        peer.write_all(&ack).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut seq = flow.syn_seq.wrapping_add(1);
        for chunk in &flow.chunks {
            let psh = build_tcp_packet(
                client,
                endpoint,
                seq,
                peer_ack,
                FLAG_PSH | FLAG_ACK,
                65535,
                chunk,
            );
            peer.write_all(&psh).unwrap();
            let n = handler.device.read_packet(buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
            seq = seq.wrapping_add(chunk.len() as u32);
        }
        let fin = build_tcp_packet(
            client,
            endpoint,
            seq,
            peer_ack,
            FLAG_FIN | FLAG_ACK,
            65535,
            &[],
        );
        peer.write_all(&fin).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
    }

    /// The row's identity claim, checked: the set of (target, payload) dials the
    /// inbound produces from the pinned packet stream equals the golden recorded
    /// from the reference stack by `scripts/tun-oracle`.
    #[cfg(unix)]
    #[test]
    fn the_dial_set_matches_the_pinned_stream() {
        let flows = parse_script(include_str!("../../../scripts/tun-oracle/script.txt"));
        let expected = parse_expected(include_str!("../../../scripts/tun-oracle/expected.txt"));
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, mut peer) = peer_with_deadline().unwrap();
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            recording_relay(results.clone()),
        );

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for flow in &flows {
            run_flow(&mut handler, &mut peer, flow, &mut buf);
        }
        wait_for(&results, flows.len());

        let mut got: Vec<(String, Vec<u8>)> = results.lock().unwrap().clone();
        got.sort();
        assert_eq!(got, expected, "the dial set is the reference's own");
    }

    /// A nonblocking peer: a frame that never arrives fails the assertions instead
    /// of parking the suite until the job timeout names nothing.
    #[cfg(unix)]
    fn peer_with_deadline() -> io::Result<(std::fs::File, std::fs::File)> {
        let (a, peer) = unix_socketpair()?;
        let rc = unsafe { libc::fcntl(peer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((a, peer))
    }

    /// Read frames off the peer until the SYN-ACK: a flow that ran earlier leaves
    /// its delayed ACKs queued ahead of it on the shared descriptor.
    #[cfg(unix)]
    fn next_syn_ack(peer: &mut std::fs::File) -> TcpHead {
        let mut reply = [0u8; 64];
        for _ in 0..1_000 {
            match peer.read(&mut reply) {
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((tcp, _)) = tcp_head(body) {
                            if tcp.flags == FLAG_SYN | FLAG_ACK {
                                return tcp;
                            }
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        panic!("no SYN-ACK arrived on the device");
    }

    /// The reverse role, checked: bytes the outbound writes back leave the handler as
    /// IP packets carrying exactly those bytes on the same descriptor.
    #[cfg(unix)]
    #[test]
    fn the_response_bytes_come_back_as_ip_packets() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|mut conn: Connection, _dest| {
            use std::io::Write;
            let _ = conn.write_all(b"pong\n");
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay);
        let flow = FlowSpec {
            destination: "203.0.113.53:53".parse().unwrap(),
            source_port: 51001,
            syn_seq: 7000,
            chunks: vec![vec![0xde, 0xad, 0xbe, 0xef]],
        };
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        run_flow(&mut handler, &mut peer, &flow, &mut buf);

        let mut reply = vec![0u8; DEFAULT_MTU + 64];
        let mut payload = Vec::new();
        for _ in 0..250 {
            match peer.read(&mut reply) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((_, pl)) = tcp_head(body) {
                            payload.extend_from_slice(pl);
                        }
                    }
                    if payload.windows(5).any(|w| w == b"pong\n") {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        assert!(
            payload.windows(5).any(|w| w == b"pong\n"),
            "the response bytes ride back as a payload"
        );
    }

    /// One flow opened and then silent: SYN, the ACK read off this stack's own SYN-ACK, and nothing after.
    #[cfg(unix)]
    fn open_flow(
        handler: &mut Handler,
        peer: &mut std::fs::File,
        destination: SocketAddr,
        source_port: u16,
        syn_seq: u32,
        buf: &mut [u8],
    ) -> FlowKey {
        let SocketAddr::V4(destination) = destination else {
            panic!("the flow names an IPv4 destination");
        };
        let endpoint = (destination.ip().octets(), destination.port());
        let client = (SCRIPT_CLIENT, source_port);
        peer.write_all(&build_tcp_packet(
            client,
            endpoint,
            syn_seq,
            0,
            FLAG_SYN,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let syn_ack = next_syn_ack(peer);
        peer.write_all(&build_tcp_packet(
            client,
            endpoint,
            syn_seq.wrapping_add(1),
            syn_ack.seq.wrapping_add(1),
            FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        FlowKey {
            source_port,
            destination: endpoint.0,
            destination_port: endpoint.1,
        }
    }

    /// Silence past the idle budget is death, not a leak: a flow that stops speaking on both sides hands its relay leg back at the budget, and its entry goes at the next dial.
    #[cfg(unix)]
    #[test]
    fn a_quiet_tun_flow_hands_its_threads_back() {
        let _guard = budgets::lock();
        let idle = std::time::Duration::from_millis(250);
        budgets::apply(&crate::config::Budgets {
            udp_idle: Some(idle),
            ..Default::default()
        });
        let (a, mut peer) = peer_with_deadline().unwrap();
        let (gone_tx, gone_rx) = std::sync::mpsc::channel::<()>();
        let relay: Relay = Arc::new(move |mut conn: Connection, _dest| {
            let mut sink = Vec::new();
            let _ = conn.read_to_end(&mut sink);
            let _ = gone_tx.send(());
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay);
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let destination: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let key = open_flow(&mut handler, &mut peer, destination, 51500, 9000, &mut buf);
        assert!(
            handler.flows.contains_key(&key),
            "the dial opens before its budget runs"
        );
        let back = gone_rx.recv_timeout(idle + std::time::Duration::from_secs(5));
        budgets::clear();
        assert!(
            back.is_ok(),
            "a flow silent past its idle budget still holds its relay leg"
        );

        // The entry goes at the next dial, so the packet path pays nothing for the reap.
        let second = open_flow(&mut handler, &mut peer, destination, 51501, 9500, &mut buf);
        assert!(
            handler.flows.contains_key(&second) && !handler.flows.contains_key(&key),
            "the quiet flow's entry is gone at the next dial"
        );
        assert_eq!(handler.flows.len(), 1, "only the live flow is left");

        // The client's goodbye outranks the budget: a reset flow hands its leg back at once.
        peer.write_all(&build_tcp_packet(
            (SCRIPT_CLIENT, second.source_port),
            (second.destination, second.destination_port),
            9501,
            0,
            FLAG_RST | FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let second_back = gone_rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(
            second_back.is_ok(),
            "a reset flow is still holding its relay leg"
        );
        assert!(handler.flows.is_empty(), "the reset flow's entry is gone");
    }

    #[test]
    fn a_forged_packet_is_refused_not_repaired() {
        // A forged IP length and a short TCP body must leave the parse silent, not reading past.
        let mut pkt = build_tcp_packet(
            ([10, 0, 0, 2], 1),
            ([10, 0, 0, 1], 2),
            1000,
            0,
            FLAG_SYN,
            65535,
            b"x",
        );
        let forged_len = (pkt.len() + 8) as u16;
        pkt[2..4].copy_from_slice(&forged_len.to_be_bytes());
        assert!(ipv4_head(&pkt).is_none());
        let short = build_tcp_packet(
            ([10, 0, 0, 2], 1),
            ([10, 0, 0, 1], 2),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        assert!(tcp_head(&short[IPV4_HEADER..IPV4_HEADER + 19]).is_none());
    }

    #[test]
    fn a_syn_with_options_leaves_the_payload_where_the_header_ends() {
        let mut pkt = build_tcp_packet(
            ([10, 0, 0, 2], 12345),
            ([10, 0, 0, 1], 80),
            1000,
            0,
            FLAG_SYN,
            65535,
            b"ab",
        );
        // Insert a 4-byte MSS option and bump the data offset to six words.
        let head = pkt[..IPV4_HEADER + 20].to_vec();
        let tail = pkt[IPV4_HEADER + 20..].to_vec();
        pkt = head;
        pkt[IPV4_HEADER + 12] = 0x60;
        pkt.extend_from_slice(&[2, 4, 0, 140]);
        pkt.extend_from_slice(&tail);
        let l = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&l.to_be_bytes());
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(payload, b"ab", "the payload starts after the options");
    }

    #[cfg(unix)]
    #[test]
    fn the_syn_ack_numbers_wrap_at_the_sequence_space_boundary() {
        let (a, mut peer) = unix_socketpair().unwrap();
        let relay: Relay = Arc::new(|_conn, _dest| {});
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay);
        let syn = build_tcp_packet(
            ([10, 0, 0, 2], 44444),
            ([10, 0, 0, 1], 80),
            u32::MAX - 1,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = [0u8; 64];
        let rn = peer.read(&mut reply).unwrap();
        let (_ip, body) = ipv4_head(&reply[..rn]).unwrap();
        let (syn_ack, _) = tcp_head(body).unwrap();
        assert_eq!(
            syn_ack.seq,
            u32::MAX,
            "the reply sequence wraps instead of saturating"
        );
    }
}
