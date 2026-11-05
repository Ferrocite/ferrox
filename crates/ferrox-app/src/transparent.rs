//! The kernel side of a transparent inbound: where a redirected flow was really going,
//! and the socket options that let a listener receive another host's traffic.

#[cfg(not(target_os = "linux"))]
use std::io;
use std::net::SocketAddr;

/// Whether a redirect lookup exists on this host.
pub(crate) const REDIRECT: bool = cfg!(any(target_os = "linux", target_os = "macos"));

/// Whether a transparent listener can receive traffic addressed to another host.
pub(crate) const TPROXY: bool = cfg!(target_os = "linux");

#[cfg(target_os = "linux")]
pub(crate) use linux::{
    bind_udp, original_destination, receive_original, reply_socket, set_transparent,
};

#[cfg(target_os = "macos")]
pub(crate) use darwin::{original_destination, set_transparent};

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) use other::original_destination;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use other::set_transparent;

#[cfg(not(target_os = "linux"))]
pub(crate) fn bind_udp(_address: SocketAddr) -> io::Result<std::net::UdpSocket> {
    unsupported("a transparent UDP listener")
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn receive_original(
    _socket: &std::net::UdpSocket,
    _buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsupported("a transparent UDP datagram")
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn reply_socket(_from: SocketAddr) -> io::Result<std::net::UdpSocket> {
    unsupported("a transparent UDP reply")
}

#[cfg(not(target_os = "linux"))]
fn unsupported<T>(what: &str) -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} needs Linux"),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn storage_address(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says these bytes are a `sockaddr_in`.
            let address = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::new(
                std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says these bytes are a `sockaddr_in6`.
            let address = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::new(
                std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).into(),
                u16::from_be(address.sin6_port),
            ))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{storage_address, SocketAddr};
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP_TRANSPARENT: libc::c_int = 19;
    const IPV6_TRANSPARENT: libc::c_int = 75;
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

    fn enable(fd: libc::c_int, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
        let value: libc::c_int = 1;
        // SAFETY: `value` outlives the call and `fd` is the caller's live socket.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                std::ptr::from_ref(&value).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(crate) fn set_transparent(socket: &socket2::Socket, v6: bool) -> io::Result<()> {
        if v6 {
            enable(socket.as_raw_fd(), libc::SOL_IPV6, IPV6_TRANSPARENT)
        } else {
            enable(socket.as_raw_fd(), libc::SOL_IP, IP_TRANSPARENT)
        }
    }

    pub(crate) fn original_destination(
        fd: libc::c_int,
        peer: SocketAddr,
        _local: Option<SocketAddr>,
    ) -> io::Result<SocketAddr> {
        let v4 = match peer.ip() {
            std::net::IpAddr::V4(_) => true,
            std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some(),
        };
        // SAFETY: an all-zero storage is valid and the kernel writes at most `len` bytes into it.
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let level = if v4 { libc::SOL_IP } else { libc::SOL_IPV6 };
        // SAFETY: the storage and length are valid for the call, and `fd` is live.
        let result = unsafe {
            libc::getsockopt(
                fd,
                level,
                SO_ORIGINAL_DST,
                std::ptr::from_mut(&mut storage).cast(),
                std::ptr::from_mut(&mut len),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        storage_address(&storage).ok_or_else(|| io::Error::other("unknown address family"))
    }

    pub(crate) fn bind_udp(address: SocketAddr) -> io::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};
        let v6 = address.is_ipv6();
        let socket = Socket::new(
            if v6 { Domain::IPV6 } else { Domain::IPV4 },
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        set_transparent(&socket, v6)?;
        socket.set_reuse_address(true)?;
        let _ = enable(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEPORT);
        if v6 {
            enable(socket.as_raw_fd(), libc::SOL_IPV6, IPV6_RECVORIGDSTADDR)?;
            let _ = enable(socket.as_raw_fd(), libc::SOL_IP, IP_RECVORIGDSTADDR);
        } else {
            enable(socket.as_raw_fd(), libc::SOL_IP, IP_RECVORIGDSTADDR)?;
        }
        socket.bind(&address.into())?;
        Ok(UdpSocket::from(socket))
    }

    pub(crate) fn receive_original(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        // SAFETY: zeroed values are valid and every pointer names a local outliving the call.
        unsafe {
            let mut source: libc::sockaddr_storage = zeroed();
            let mut control = [0u64; 32];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut message: libc::msghdr = zeroed();
            message.msg_name = std::ptr::from_mut(&mut source).cast();
            message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            message.msg_iov = std::ptr::from_mut(&mut iov);
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of_val(&control) as _;
            let read = libc::recvmsg(socket.as_raw_fd(), std::ptr::from_mut(&mut message), 0);
            if read < 0 {
                return Err(io::Error::last_os_error());
            }
            let client = storage_address(&source).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "datagram from an unknown family",
                )
            })?;
            let mut header = libc::CMSG_FIRSTHDR(std::ptr::from_ref(&message));
            while !header.is_null() {
                let level = (*header).cmsg_level;
                let kind = (*header).cmsg_type;
                if (level == libc::SOL_IP && kind == IP_RECVORIGDSTADDR)
                    || (level == libc::SOL_IPV6 && kind == IPV6_RECVORIGDSTADDR)
                {
                    let data = libc::CMSG_DATA(header);
                    let offset = data.offset_from(header.cast::<u8>()) as usize;
                    let size = ((*header).cmsg_len as usize)
                        .saturating_sub(offset)
                        .min(size_of::<libc::sockaddr_storage>());
                    let mut destination: libc::sockaddr_storage = zeroed();
                    std::ptr::copy_nonoverlapping(
                        data,
                        std::ptr::from_mut(&mut destination).cast(),
                        size,
                    );
                    if let Some(destination) = storage_address(&destination) {
                        let client = match (client, destination) {
                            (SocketAddr::V6(c), SocketAddr::V4(_)) => c
                                .ip()
                                .to_ipv4_mapped()
                                .map_or(client, |ip| SocketAddr::new(ip.into(), c.port())),
                            _ => client,
                        };
                        return Ok((read as usize, client, destination));
                    }
                }
                header = libc::CMSG_NXTHDR(std::ptr::from_ref(&message), header);
            }
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram without its destination",
            ))
        }
    }

    pub(crate) fn reply_socket(from: SocketAddr) -> io::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};
        let v6 = from.is_ipv6();
        let socket = Socket::new(
            if v6 { Domain::IPV6 } else { Domain::IPV4 },
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        set_transparent(&socket, v6)?;
        socket.set_reuse_address(true)?;
        let _ = enable(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEPORT);
        socket.bind(&from.into())?;
        Ok(UdpSocket::from(socket))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_direct_connection_has_no_other_destination() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
            let address = listener.local_addr().expect("addr");
            let client = std::thread::spawn(move || std::net::TcpStream::connect(address));
            let (stream, peer) = listener.accept().expect("accepts");
            let local = stream.local_addr().ok();
            match original_destination(stream.as_raw_fd(), peer, local) {
                Err(_) => {}
                Ok(found) => assert_eq!(found, address),
            }
            drop(client.join().expect("client"));
        }
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::{storage_address, SocketAddr};
    use std::io;
    use std::mem::zeroed;
    use std::os::fd::AsRawFd;

    const PF_OUT: u8 = 2;
    // macOS widened each port to `union pf_state_xport`, so the ioctl size is 84, not 76.
    const DIOCNATLOOK: libc::c_ulong = 0xc054_4417;

    #[repr(C, align(4))]
    struct NatLook {
        source: [u8; 16],
        destination: [u8; 16],
        reply_source: [u8; 16],
        reply_destination: [u8; 16],
        source_port: [u8; 4],
        destination_port: [u8; 4],
        reply_source_port: [u8; 4],
        reply_destination_port: [u8; 4],
        family: u8,
        protocol: u8,
        proto_variant: u8,
        direction: u8,
    }

    const _: () = assert!(std::mem::size_of::<NatLook>() == 84);
    const _: () = assert!(std::mem::offset_of!(NatLook, proto_variant) == 82);
    const _: () = assert!(std::mem::offset_of!(NatLook, direction) == 83);
    const _: () = assert!(DIOCNATLOOK == 0xc054_4417);

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn set_transparent(_socket: &socket2::Socket, _v6: bool) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn original_destination(
        _fd: libc::c_int,
        peer: SocketAddr,
        local: Option<SocketAddr>,
    ) -> io::Result<SocketAddr> {
        let file = std::fs::File::open("/dev/pf")?;
        // SAFETY: an all-zero struct is valid.
        let mut look: NatLook = unsafe { zeroed() };
        look.protocol = libc::IPPROTO_TCP as u8;
        look.direction = PF_OUT;
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let local = local.map(|local| SocketAddr::new(local.ip().to_canonical(), local.port()));
        let local = match local {
            Some(local) => local,
            None if peer.is_ipv4() => "127.0.0.1:0".parse().expect("literal"),
            None => "[::1]:0".parse().expect("literal"),
        };
        match peer.ip() {
            std::net::IpAddr::V4(ip) => {
                look.family = libc::AF_INET as u8;
                look.source[..4].copy_from_slice(&ip.octets());
                let destination = match local.ip() {
                    std::net::IpAddr::V4(ip) if !ip.is_unspecified() => ip,
                    _ => std::net::Ipv4Addr::LOCALHOST,
                };
                look.destination[..4].copy_from_slice(&destination.octets());
            }
            std::net::IpAddr::V6(ip) => {
                look.family = libc::AF_INET6 as u8;
                look.source.copy_from_slice(&ip.octets());
                let destination = match local.ip() {
                    std::net::IpAddr::V6(ip) if !ip.is_unspecified() => ip,
                    _ => std::net::Ipv6Addr::LOCALHOST,
                };
                look.destination.copy_from_slice(&destination.octets());
            }
        }
        look.source_port[..2].copy_from_slice(&peer.port().to_be_bytes());
        look.destination_port[..2].copy_from_slice(&local.port().to_be_bytes());
        // SAFETY: the argument is a live `pfioc_natlook` the kernel writes back into.
        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                DIOCNATLOOK as libc::c_ulong,
                std::ptr::from_mut(&mut look),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        reply_destination(&look)
    }

    fn reply_destination(look: &NatLook) -> io::Result<SocketAddr> {
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        match look.family as libc::c_int {
            libc::AF_INET => {
                // SAFETY: the kernel's family says the reply destination is IPv4.
                let address =
                    unsafe { &mut *std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in>() };
                address.sin_family = libc::AF_INET as _;
                address.sin_port = u16::from_ne_bytes([
                    look.reply_destination_port[0],
                    look.reply_destination_port[1],
                ]);
                address.sin_addr.s_addr = u32::from_ne_bytes(
                    look.reply_destination[..4].try_into().expect("four octets"),
                );
            }
            libc::AF_INET6 => {
                // SAFETY: the kernel's family says the reply destination is IPv6.
                let address =
                    unsafe { &mut *std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in6>() };
                address.sin6_family = libc::AF_INET6 as _;
                address.sin6_port = u16::from_ne_bytes([
                    look.reply_destination_port[0],
                    look.reply_destination_port[1],
                ]);
                address.sin6_addr.s6_addr = look.reply_destination;
            }
            _ => return Err(io::Error::other("unknown address family")),
        }
        storage_address(&storage).ok_or_else(|| io::Error::other("unknown address family"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_nat_look_reply_port_keeps_its_network_order() {
            let mut look: NatLook = unsafe { zeroed() };
            look.family = libc::AF_INET as u8;
            look.reply_destination[..4].copy_from_slice(&[127, 0, 0, 1]);
            look.reply_destination_port[..2].copy_from_slice(&8080u16.to_be_bytes());
            assert_eq!(
                reply_destination(&look).expect("decodes"),
                "127.0.0.1:8080".parse().expect("literal")
            );
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod other {
    use std::io;

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent proxying needs Linux or macOS",
        ))
    }

    pub(crate) fn set_transparent(_socket: &socket2::Socket, _v6: bool) -> io::Result<()> {
        unsupported()
    }

    #[cfg(unix)]
    pub(crate) fn original_destination(
        _fd: std::os::fd::RawFd,
        _peer: std::net::SocketAddr,
        _local: Option<std::net::SocketAddr>,
    ) -> io::Result<std::net::SocketAddr> {
        unsupported()
    }
}
