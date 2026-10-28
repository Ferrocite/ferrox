//! The Linux kernel `WireGuard` device, driven from generic and route netlink.
//!
//! A client opens one `wireguard` link, sets its key and peers, and sends only
//! marked sockets through a private table. The mark and the table are per
//! process, so no firewall rule, global sysctl or interface-wide setting is
//! touched; the link, its routes and its rules are removed when the outbound
//! is dropped. The userspace stack remains the fallback when the device cannot
//! be opened.

use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::wireguard::DeviceConfig;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

const RTM_NEWLINK: u16 = libc::RTM_NEWLINK;
const RTM_DELLINK: u16 = libc::RTM_DELLINK;
const RTM_NEWADDR: u16 = libc::RTM_NEWADDR;
const RTM_NEWROUTE: u16 = libc::RTM_NEWROUTE;
const RTM_DELROUTE: u16 = libc::RTM_DELROUTE;
const RTM_NEWRULE: u16 = libc::RTM_NEWRULE;
const RTM_DELRULE: u16 = libc::RTM_DELRULE;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_F_NODAD: u32 = 0x02;
const RTA_OIF: u16 = 4;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
const FRA_IIFNAME: u16 = 3;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;

const FR_ACT_TO_TBL: u8 = 1;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 6;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

const RULE_PRIORITY: u32 = 32_765;
const IIF_PRIORITY: u32 = 32_764;
const NETLINK_TIMEOUT: Duration = Duration::from_secs(2);
const NETLINK_BUF: usize = 8192;
const SOCKET_BUFFER: usize = 7 << 20;

/// The kernel device one outbound owns.
#[derive(Debug)]
pub(crate) struct KernelWireGuard {
    name: String,
    index: u32,
    table: u32,
    mark: u32,
    families: Vec<u8>,
}

impl KernelWireGuard {
    /// Create and configure one device. A failure leaves no link, route or rule
    /// behind; the caller may then use the userspace stack.
    pub(crate) fn new(config: &DeviceConfig) -> Result<Self, String> {
        if config.addresses.is_empty() {
            return Err("kernel wireguard: no address".to_owned());
        }
        if config.reserved != [0; 3] {
            return Err("kernel wireguard: reserved bytes need the userspace stack".to_owned());
        }
        if !config.peers.iter().any(|peer| peer.endpoint.is_some()) {
            return Err("kernel wireguard: no peer has an `endpoint`".to_owned());
        }
        let (name, table, mark) = identity();
        let mut route = Netlink::open(libc::NETLINK_ROUTE).map_err(|error| kernel_error(&error))?;
        let mut index = None;
        let mut families = Vec::new();
        if let Err(error) = setup(
            &mut route,
            &name,
            table,
            mark,
            config,
            &mut index,
            &mut families,
        ) {
            teardown(&name, index, table, mark, &families);
            return Err(kernel_error(&error));
        }
        Ok(Self {
            name,
            index: index.unwrap_or_default(),
            table,
            mark,
            families,
        })
    }

    /// The interface name, for diagnostics and the privileged test.
    #[cfg(test)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// A TCP stream that leaves through the marked table.
    pub(crate) fn connect_tcp(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        let socket = Socket::new(domain(target), Type::STREAM, Some(Protocol::TCP))?;
        set_mark(&socket, self.mark)?;
        socket.set_tcp_nodelay(true)?;
        let _ = socket.set_recv_buffer_size(SOCKET_BUFFER);
        let _ = socket.set_send_buffer_size(SOCKET_BUFFER);
        socket.connect_timeout(&target.into(), timeout)?;
        Ok(socket.into())
    }

    /// A connected UDP socket that leaves through the marked table.
    pub(crate) fn udp_socket(&self, target: SocketAddr) -> io::Result<UdpSocket> {
        let socket = Socket::new(domain(target), Type::DGRAM, Some(Protocol::UDP))?;
        set_mark(&socket, self.mark)?;
        socket.connect(&target.into())?;
        Ok(socket.into())
    }
}

/// Mark a socket for the private table; `socket2` has no portable mark setter.
fn set_mark(socket: &Socket, mark: u32) -> io::Result<()> {
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_ref(&mark).cast(),
            size_of::<u32>() as libc::socklen_t,
        )
    };
    if set == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl Drop for KernelWireGuard {
    fn drop(&mut self) {
        teardown(
            &self.name,
            Some(self.index),
            self.table,
            self.mark,
            &self.families,
        );
    }
}

fn setup(
    route: &mut Netlink,
    name: &str,
    table: u32,
    mark: u32,
    config: &DeviceConfig,
    index: &mut Option<u32>,
    families: &mut Vec<u8>,
) -> io::Result<()> {
    route.request(link_create_message(name, config.mtu))?;
    let ifindex = interface_index(name)?;
    *index = Some(ifindex);
    let mut genl = Netlink::open(libc::NETLINK_GENERIC)?;
    let family = generic_family(&mut genl, b"wireguard\0")?;
    genl.request(device_message(family, name, config))?;
    for address in &config.addresses {
        route.request(address_message(ifindex, *address))?;
        let family = if address.is_ipv4() { AF_INET } else { AF_INET6 };
        if !families.contains(&family) {
            families.push(family);
        }
    }
    route.request(link_up_message(ifindex))?;
    for family in families.iter().copied() {
        let source = config
            .addresses
            .iter()
            .find(|address| address.is_ipv4() == (family == AF_INET))
            .copied()
            .ok_or_else(|| io::Error::other("kernel wireguard: no source address"))?;
        route.request(route_message(family, table, ifindex, source))?;
        route.request(rule_message(family, table, mark, RULE_PRIORITY, None))?;
        route.request(rule_message(family, table, mark, IIF_PRIORITY, Some(name)))?;
    }
    Ok(())
}

fn domain(target: SocketAddr) -> Domain {
    if target.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    }
}

fn kernel_error(error: &io::Error) -> String {
    format!("kernel wireguard: {error}")
}

fn identity() -> (String, u32, u32) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let token = NEXT.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = format!("fwg{:04x}{:04x}", pid & 0xffff, token & 0xffff);
    let table = 0x4645_0000 | ((pid & 0xff) << 8) | (token & 0xff);
    (name, table, table)
}

fn teardown(name: &str, index: Option<u32>, table: u32, mark: u32, families: &[u8]) {
    let Ok(mut route) = Netlink::open(libc::NETLINK_ROUTE) else {
        return;
    };
    for family in families {
        let _ = route.request(delete_rule_message(
            *family,
            table,
            mark,
            IIF_PRIORITY,
            Some(name),
        ));
        let _ = route.request(delete_rule_message(
            *family,
            table,
            mark,
            RULE_PRIORITY,
            None,
        ));
        if let Some(index) = index {
            let _ = route.request(delete_route_message(*family, table, index));
        }
    }
    if let Some(index) = index {
        let _ = route.request(delete_link_message(index));
    } else {
        let _ = route.request(delete_link_name_message(name));
    }
}

fn interface_index(name: &str) -> io::Result<u32> {
    let name = CString::new(name).map_err(|_| io::Error::other("interface name has a NUL"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

fn cstr(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn endpoint_bytes(endpoint: SocketAddr) -> Vec<u8> {
    match endpoint {
        SocketAddr::V4(address) => {
            let mut bytes = vec![0u8; 16];
            bytes[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&address.ip().octets());
            bytes
        }
        SocketAddr::V6(address) => {
            let mut bytes = vec![0u8; 28];
            bytes[..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
            bytes[8..24].copy_from_slice(&address.ip().octets());
            bytes[24..28].copy_from_slice(&address.scope_id().to_ne_bytes());
            bytes
        }
    }
}

fn ifinfo(index: u32, flags: u32, change: u32) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0] = AF_UNSPEC;
    bytes[4..8].copy_from_slice(&i32::try_from(index).unwrap_or(i32::MAX).to_ne_bytes());
    bytes[8..12].copy_from_slice(&flags.to_ne_bytes());
    bytes[12..16].copy_from_slice(&change.to_ne_bytes());
    bytes
}

fn ifaddr(family: u8, prefix: u8, index: u32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0] = family;
    bytes[1] = prefix;
    bytes[4..8].copy_from_slice(&index.to_ne_bytes());
    bytes
}

fn rtmsg(family: u8) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[0] = family;
    bytes[5] = RTPROT_STATIC;
    bytes[6] = RT_SCOPE_UNIVERSE;
    bytes[7] = RTN_UNICAST;
    bytes
}

fn fib_rule(family: u8) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[0] = family;
    bytes[7] = FR_ACT_TO_TBL;
    bytes
}

fn link_create_message(name: &str, mtu: usize) -> Vec<u8> {
    let mut msg = Msg::new(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.payload(&ifinfo(0, 0, 0));
    msg.attr(IFLA_IFNAME, &cstr(name));
    msg.attr(
        IFLA_MTU,
        &u32::try_from(mtu).unwrap_or(u32::MAX).to_ne_bytes(),
    );
    msg.nested(IFLA_LINKINFO, |msg| {
        msg.attr(IFLA_INFO_KIND, b"wireguard\0");
    });
    msg.finish()
}

fn link_up_message(index: u32) -> Vec<u8> {
    let mut msg = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.payload(&ifinfo(index, libc::IFF_UP as u32, libc::IFF_UP as u32));
    msg.finish()
}

fn delete_link_message(index: u32) -> Vec<u8> {
    let mut msg = Msg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.payload(&ifinfo(index, 0, 0));
    msg.finish()
}

fn delete_link_name_message(name: &str) -> Vec<u8> {
    let mut msg = Msg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.payload(&ifinfo(0, 0, 0));
    msg.attr(IFLA_IFNAME, &cstr(name));
    msg.finish()
}

fn address_message(index: u32, address: IpAddr) -> Vec<u8> {
    let (family, prefix) = if address.is_ipv4() {
        (AF_INET, 32)
    } else {
        (AF_INET6, 128)
    };
    let mut msg = Msg::new(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.payload(&ifaddr(family, prefix, index));
    let address = ip_bytes(address);
    msg.attr(IFA_LOCAL, &address);
    if family == AF_INET {
        msg.attr(IFA_ADDRESS, &address);
    } else {
        msg.attr(IFA_FLAGS, &IFA_F_NODAD.to_ne_bytes());
    }
    msg.finish()
}

fn route_message(family: u8, table: u32, index: u32, source: IpAddr) -> Vec<u8> {
    let mut msg = Msg::new(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.payload(&rtmsg(family));
    msg.attr(RTA_TABLE, &table.to_ne_bytes());
    msg.attr(RTA_OIF, &index.to_ne_bytes());
    msg.attr(RTA_PREFSRC, &ip_bytes(source));
    msg.finish()
}

fn delete_route_message(family: u8, table: u32, index: u32) -> Vec<u8> {
    let mut msg = Msg::new(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);
    msg.payload(&rtmsg(family));
    msg.attr(RTA_TABLE, &table.to_ne_bytes());
    msg.attr(RTA_OIF, &index.to_ne_bytes());
    msg.finish()
}

fn rule_message(family: u8, table: u32, mark: u32, priority: u32, iif: Option<&str>) -> Vec<u8> {
    rule(RTM_NEWRULE, family, table, mark, priority, iif, true)
}

fn delete_rule_message(
    family: u8,
    table: u32,
    mark: u32,
    priority: u32,
    iif: Option<&str>,
) -> Vec<u8> {
    rule(RTM_DELRULE, family, table, mark, priority, iif, false)
}

fn rule(
    kind: u16,
    family: u8,
    table: u32,
    mark: u32,
    priority: u32,
    iif: Option<&str>,
    create: bool,
) -> Vec<u8> {
    let flags = if create {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    } else {
        NLM_F_REQUEST | NLM_F_ACK
    };
    let mut msg = Msg::new(kind, flags);
    msg.payload(&fib_rule(family));
    msg.attr(FRA_TABLE, &table.to_ne_bytes());
    msg.attr(FRA_PRIORITY, &priority.to_ne_bytes());
    if let Some(name) = iif {
        msg.attr(FRA_IIFNAME, &cstr(name));
    } else {
        msg.attr(FRA_FWMARK, &mark.to_ne_bytes());
        msg.attr(FRA_FWMASK, &u32::MAX.to_ne_bytes());
    }
    msg.finish()
}

fn device_message(family: u16, name: &str, config: &DeviceConfig) -> Vec<u8> {
    let mut msg = Msg::new(family, NLM_F_REQUEST | NLM_F_ACK);
    msg.payload(&[WG_CMD_SET_DEVICE, 1, 0, 0]);
    msg.attr(WGDEVICE_A_IFNAME, &cstr(name));
    msg.attr(WGDEVICE_A_PRIVATE_KEY, &config.secret);
    msg.attr(WGDEVICE_A_FLAGS, &WGDEVICE_F_REPLACE_PEERS.to_ne_bytes());
    msg.nested(WGDEVICE_A_PEERS, |msg| {
        for peer in &config.peers {
            msg.nested(0, |msg| {
                msg.attr(WGPEER_A_PUBLIC_KEY, &peer.public);
                if peer.preshared != [0; 32] {
                    msg.attr(WGPEER_A_PRESHARED_KEY, &peer.preshared);
                }
                if let Some(endpoint) = peer.endpoint {
                    msg.attr(WGPEER_A_ENDPOINT, &endpoint_bytes(endpoint));
                }
                if peer.keepalive != 0 {
                    msg.attr(
                        WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                        &peer.keepalive.to_ne_bytes(),
                    );
                }
                msg.nested(WGPEER_A_ALLOWEDIPS, |msg| {
                    for (address, bits) in &peer.allowed {
                        msg.nested(0, |msg| {
                            let family = if address.is_ipv4() { AF_INET } else { AF_INET6 };
                            msg.attr(WGALLOWEDIP_A_FAMILY, &(family as u16).to_ne_bytes());
                            msg.attr(WGALLOWEDIP_A_IPADDR, &ip_bytes(*address));
                            msg.attr(WGALLOWEDIP_A_CIDR_MASK, &[*bits]);
                        });
                    }
                });
            });
        }
    });
    msg.finish()
}

fn generic_family(genl: &mut Netlink, name: &[u8]) -> io::Result<u16> {
    let mut msg = Msg::new(GENL_ID_CTRL, NLM_F_REQUEST);
    msg.payload(&[CTRL_CMD_GETFAMILY, 1, 0, 0]);
    msg.attr(CTRL_ATTR_FAMILY_NAME, name);
    let reply = genl.request(msg.finish())?;
    let payload = reply
        .get(20..)
        .ok_or_else(|| io::Error::other("short generic-netlink family reply"))?;
    let value = Attrs::new(payload)
        .find_map(|(kind, value)| (kind == CTRL_ATTR_FAMILY_ID).then_some(value))
        .ok_or_else(|| io::Error::other("the wireguard generic-netlink family is absent"))?;
    let bytes = value
        .get(..2)
        .ok_or_else(|| io::Error::other("short wireguard family id"))?;
    Ok(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

struct Msg {
    bytes: Vec<u8>,
}

impl Msg {
    fn new(kind: u16, flags: u16) -> Self {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        Self { bytes }
    }

    fn payload(&mut self, payload: &[u8]) {
        self.bytes.extend_from_slice(payload);
    }

    fn attr(&mut self, kind: u16, value: &[u8]) {
        push_attr(&mut self.bytes, kind, value);
    }

    fn nested(&mut self, kind: u16, fill: impl FnOnce(&mut Self)) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(&0u16.to_ne_bytes());
        self.bytes
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        fill(self);
        let len = self.bytes.len() - start;
        self.bytes[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        let len = self.bytes.len() as u32;
        self.bytes[..4].copy_from_slice(&len.to_ne_bytes());
        self.bytes
    }
}

fn push_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    let pad = (4 - len % 4) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
}

struct Attrs<'a> {
    rest: &'a [u8],
}

impl<'a> Attrs<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let len = usize::from(u16::from_ne_bytes(self.rest.get(..2)?.try_into().ok()?));
        if len < 4 || len > self.rest.len() {
            self.rest = &[];
            return None;
        }
        let kind = u16::from_ne_bytes(self.rest[2..4].try_into().ok()?);
        let value = &self.rest[4..len];
        let step = (len + 3) & !3;
        self.rest = self.rest.get(step..).unwrap_or(&[]);
        Some((kind & NLA_TYPE_MASK, value))
    }
}

struct Netlink {
    fd: OwnedFd,
    seq: u32,
}

impl Netlink {
    fn open(protocol: i32) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let address = sockaddr_nl();
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        set_timeout(fd.as_raw_fd(), libc::SO_RCVTIMEO)?;
        set_timeout(fd.as_raw_fd(), libc::SO_SNDTIMEO)?;
        Ok(Self { fd, seq: 0 })
    }

    fn request(&mut self, mut message: Vec<u8>) -> io::Result<Vec<u8>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        message[8..12].copy_from_slice(&seq.to_ne_bytes());
        let address = sockaddr_nl();
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
                std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != message.len() {
            return Err(io::Error::other("short netlink send"));
        }
        let mut buffer = [0u8; NETLINK_BUF];
        loop {
            let read = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let read = read as usize;
            let mut offset = 0;
            while offset + 16 <= read {
                let len =
                    u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap_or([0; 4]))
                        as usize;
                if len < 16 || offset + len > read {
                    return Err(io::Error::other("short netlink reply"));
                }
                let kind =
                    u16::from_ne_bytes(buffer[offset + 4..offset + 6].try_into().unwrap_or([0; 2]));
                let reply_seq = u32::from_ne_bytes(
                    buffer[offset + 8..offset + 12].try_into().unwrap_or([0; 4]),
                );
                if reply_seq != seq {
                    offset += (len + 3) & !3;
                    continue;
                }
                match kind {
                    NLMSG_ERROR => {
                        if len < 20 {
                            return Err(io::Error::other("short netlink error"));
                        }
                        let code = i32::from_ne_bytes(
                            buffer[offset + 16..offset + 20]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        if code < 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                        return Ok(Vec::new());
                    }
                    NLMSG_DONE => return Ok(Vec::new()),
                    _ => return Ok(buffer[offset..offset + len].to_vec()),
                }
            }
            if offset == 0 {
                return Err(io::Error::other("empty netlink reply"));
            }
        }
    }
}

fn sockaddr_nl() -> libc::sockaddr_nl {
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address
}

fn set_timeout(fd: libc::c_int, option: libc::c_int) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: libc::time_t::try_from(NETLINK_TIMEOUT.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_usec: libc::suseconds_t::from(NETLINK_TIMEOUT.subsec_micros()),
    };
    let set = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&timeout).cast::<libc::c_void>(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::PeerConfig;

    fn config() -> DeviceConfig {
        DeviceConfig {
            secret: [1; 32],
            addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            peers: vec![PeerConfig {
                public: [2; 32],
                preshared: [0; 32],
                endpoint: Some("127.0.0.1:51820".parse().unwrap()),
                endpoints: Vec::new(),
                keepalive: 25,
                allowed: vec![("0.0.0.0".parse().unwrap(), 0), ("::".parse().unwrap(), 0)],
            }],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(true),
            no_kernel_tun: false,
            dns: Vec::new(),
        }
    }

    fn attr(payload: &[u8], kind: u16) -> Option<&[u8]> {
        Attrs::new(payload).find_map(|(found, value)| (found == kind).then_some(value))
    }

    fn header(message: &[u8]) -> (u16, usize) {
        (
            u16::from_ne_bytes(message[4..6].try_into().unwrap()),
            16 + 16,
        )
    }

    #[test]
    fn the_link_message_names_wireguard() {
        let message = link_create_message("fwgtest", 1420);
        let (kind, payload) = header(&message);
        assert_eq!(kind, RTM_NEWLINK);
        assert_eq!(
            attr(&message[payload..], IFLA_IFNAME),
            Some(b"fwgtest\0".as_slice())
        );
        assert_eq!(
            attr(&message[payload..], IFLA_MTU),
            Some(&1420u32.to_ne_bytes()[..])
        );
        let linkinfo = attr(&message[payload..], IFLA_LINKINFO).expect("linkinfo");
        assert_eq!(
            attr(linkinfo, IFLA_INFO_KIND),
            Some(b"wireguard\0".as_slice())
        );
    }

    #[test]
    fn the_device_message_carries_one_peer_and_its_allowed_ips() {
        let message = device_message(0x1234, "fwgtest", &config());
        let payload = &message[20..];
        assert_eq!(
            attr(payload, WGDEVICE_A_IFNAME),
            Some(b"fwgtest\0".as_slice())
        );
        assert_eq!(attr(payload, WGDEVICE_A_PRIVATE_KEY), Some(&[1u8; 32][..]));
        let peers = attr(payload, WGDEVICE_A_PEERS).expect("peers");
        let (kind, peer) = Attrs::new(peers).next().expect("one peer");
        assert_eq!(kind, 0);
        assert_eq!(attr(peer, WGPEER_A_PUBLIC_KEY), Some(&[2u8; 32][..]));
        assert_eq!(
            attr(peer, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL),
            Some(&25u16.to_ne_bytes()[..])
        );
        let allowed = attr(peer, WGPEER_A_ALLOWEDIPS).expect("allowed");
        let (kind, v4) = Attrs::new(allowed).next().expect("v4");
        assert_eq!(kind, 0);
        assert_eq!(
            attr(v4, WGALLOWEDIP_A_FAMILY),
            Some(&(AF_INET as u16).to_ne_bytes()[..])
        );
        assert_eq!(attr(v4, WGALLOWEDIP_A_IPADDR), Some(&[0u8; 4][..]));
        assert_eq!(attr(v4, WGALLOWEDIP_A_CIDR_MASK), Some(&[0u8][..]));
    }

    #[test]
    fn the_rule_marks_the_table() {
        let message = rule_message(AF_INET, 0x4645_0001, 0x4645_0001, RULE_PRIORITY, None);
        let (kind, _) = header(&message);
        assert_eq!(kind, RTM_NEWRULE);
        let payload = &message[28..];
        assert_eq!(
            attr(payload, FRA_TABLE),
            Some(&0x4645_0001u32.to_ne_bytes()[..])
        );
        assert_eq!(
            attr(payload, FRA_FWMARK),
            Some(&0x4645_0001u32.to_ne_bytes()[..])
        );
        assert_eq!(attr(payload, FRA_FWMASK), Some(&u32::MAX.to_ne_bytes()[..]));
        assert_eq!(
            attr(payload, FRA_PRIORITY),
            Some(&RULE_PRIORITY.to_ne_bytes()[..])
        );
    }

    #[test]
    fn the_iif_rule_keeps_the_reverse_path_inside_the_tunnel() {
        let message = rule_message(
            AF_INET6,
            0x4645_0001,
            0x4645_0001,
            IIF_PRIORITY,
            Some("fwgtest"),
        );
        let payload = &message[28..];
        assert_eq!(attr(payload, FRA_IIFNAME), Some(b"fwgtest\0".as_slice()));
        assert!(attr(payload, FRA_FWMARK).is_none());
    }

    #[test]
    fn the_ipv6_address_skips_dad() {
        let message = address_message(7, "2001:db8::1".parse().unwrap());
        let payload = &message[24..];
        assert_eq!(
            attr(payload, IFA_FLAGS),
            Some(&IFA_F_NODAD.to_ne_bytes()[..])
        );
    }

    #[test]
    fn the_route_sends_the_table_to_the_link() {
        let message = route_message(AF_INET, 0x4645_0001, 7, "192.0.2.1".parse().unwrap());
        let (kind, _) = header(&message);
        assert_eq!(kind, RTM_NEWROUTE);
        let payload = &message[28..];
        assert_eq!(
            attr(payload, RTA_TABLE),
            Some(&0x4645_0001u32.to_ne_bytes()[..])
        );
        assert_eq!(attr(payload, RTA_OIF), Some(&7u32.to_ne_bytes()[..]));
        assert_eq!(attr(payload, RTA_PREFSRC), Some(&[192, 0, 2, 1][..]));
    }

    #[test]
    fn the_endpoint_is_a_sockaddr() {
        assert_eq!(
            endpoint_bytes("127.0.0.1:51820".parse().unwrap()),
            vec![2, 0, 0xca, 0x6c, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let v6 = endpoint_bytes("[2001:db8::1]:51820".parse().unwrap());
        assert_eq!(v6.len(), 28);
        assert_eq!(&v6[..2], &(AF_INET6 as u16).to_ne_bytes());
        assert_eq!(&v6[2..4], &51820u16.to_be_bytes());
        let expected = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        assert_eq!(&v6[8..24], expected.octets().as_slice());
    }

    #[test]
    fn reserved_bytes_stay_on_the_userspace_stack() {
        let mut config = config();
        config.reserved = [1, 2, 3];
        assert!(KernelWireGuard::new(&config).is_err());
    }

    #[test]
    #[ignore = "needs CAP_NET_ADMIN and the wireguard module"]
    fn the_kernel_device_is_created_and_removed() {
        let config = config();
        let kernel = KernelWireGuard::new(&config).expect("kernel wireguard");
        let name = kernel.name().to_owned();
        assert!(interface_index(&name).is_ok());
        drop(kernel);
        assert!(interface_index(&name).is_err());
    }
}
