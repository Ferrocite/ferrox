use crate::json::Json;
use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
use std::time::Duration;

/// The outbound half of xray's `SocketConfig`: the options an ECH DNS query puts on the
/// socket it dials. Inbound-only fields are read and left alone, as the reference leaves them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocketOptions {
    mark: Option<i32>,
    tfo: Option<i32>,
    tproxy: bool,
    domain: DomainStrategy,
    keep_alive: Option<KeepAlive>,
    congestion: Option<String>,
    window_clamp: Option<i32>,
    user_timeout: Option<i32>,
    max_seg: Option<i32>,
    interface: Option<String>,
    custom: Vec<CustomSockopt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepAlive {
    /// xray starts from Chrome's 45-second defaults whenever a socket config exists.
    Enabled {
        idle: u64,
        interval: u64,
    },
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainStrategy {
    AsIs,
    UseIp,
    UseIp4,
    UseIp6,
    UseIp46,
    UseIp64,
    ForceIp4,
    ForceIp6,
    ForceIp46,
    ForceIp64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CustomSockopt {
    system: String,
    network: String,
    level: i32,
    opt: i32,
    value: CustomValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CustomValue {
    Int(i32),
    Str(String),
}

pub(crate) fn parse(node: Option<&Json>) -> Result<Option<SocketOptions>, String> {
    let Some(node) = node else {
        return Ok(None);
    };
    if matches!(node, Json::Null) {
        return Ok(None);
    }
    if !matches!(node, Json::Obj(_)) {
        return Err("echSockopt is not an object".to_owned());
    }
    let mark = int(node, "mark")?.filter(|value| *value != 0);
    let tfo = match node.get("tcpFastOpen") {
        None => None,
        Some(Json::Bool(true)) => Some(1),
        Some(Json::Bool(false)) => Some(0),
        Some(Json::Num(_)) => match int(node, "tcpFastOpen")?.unwrap_or(0) {
            0 => None,
            value if value < 0 => Some(0),
            _ => Some(1),
        },
        Some(_) => {
            return Err("echSockopt.tcpFastOpen is neither a boolean nor an integer".to_owned())
        }
    };
    let tproxy = matches!(
        node.get("tproxy").and_then(Json::as_str),
        Some(text) if text.eq_ignore_ascii_case("tproxy") || text.eq_ignore_ascii_case("redirect")
    );
    let domain = match node
        .get("domainStrategy")
        .and_then(Json::as_str)
        .map(str::trim)
    {
        None | Some("") => DomainStrategy::AsIs,
        Some(text) => match text.to_ascii_lowercase().as_str() {
            "asis" => DomainStrategy::AsIs,
            "useip" | "forceip" => DomainStrategy::UseIp,
            "useipv4" => DomainStrategy::UseIp4,
            "useipv6" => DomainStrategy::UseIp6,
            "useipv4v6" => DomainStrategy::UseIp46,
            "useipv6v4" => DomainStrategy::UseIp64,
            "forceipv4" => DomainStrategy::ForceIp4,
            "forceipv6" => DomainStrategy::ForceIp6,
            "forceipv4v6" => DomainStrategy::ForceIp46,
            "forceipv6v4" => DomainStrategy::ForceIp64,
            other => return Err(format!("unsupported echSockopt domainStrategy {other}")),
        },
    };
    let keep_alive = Some(keep_alive(node)?);
    let congestion = text(node, "tcpCongestion")?;
    let window_clamp = int(node, "tcpWindowClamp")?.filter(|value| *value > 0);
    let user_timeout = int(node, "tcpUserTimeout")?.filter(|value| *value > 0);
    let max_seg = int(node, "tcpMaxSeg")?.filter(|value| *value > 0);
    let interface = text(node, "interface")?;
    let custom = custom(node.get("customSockopt"))?;
    warn_unsupported(node);
    Ok(Some(SocketOptions {
        mark,
        tfo,
        tproxy,
        domain,
        keep_alive,
        congestion,
        window_clamp,
        user_timeout,
        max_seg,
        interface,
        custom,
    }))
}

fn warn_unsupported(node: &Json) {
    if node
        .get("dialerProxy")
        .and_then(Json::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        eprintln!("ech: echSockopt.dialerProxy is not wired; the ECH query dials directly");
    }
    if node
        .get("addressPortStrategy")
        .and_then(Json::as_str)
        .is_some_and(|text| !text.is_empty() && !text.eq_ignore_ascii_case("none"))
    {
        eprintln!(
            "ech: echSockopt.addressPortStrategy is not wired; the ECH query dials its own target"
        );
    }
    if node
        .get("happyEyeballs")
        .is_some_and(|value| !matches!(value, Json::Null))
    {
        eprintln!("ech: echSockopt.happyEyeballs is not wired; the ECH query dials one address");
    }
    if matches!(node.get("penetrate"), Some(Json::Bool(true))) {
        eprintln!("ech: echSockopt.penetrate is not wired; the ECH query dials directly");
    }
    if matches!(node.get("tcpMptcp"), Some(Json::Bool(true))) {
        eprintln!("ech: echSockopt.tcpMptcp is not wired; the ECH query dials a plain TCP socket");
    }
}

fn int(node: &Json, key: &str) -> Result<Option<i32>, String> {
    let Some(value) = node.get(key) else {
        return Ok(None);
    };
    let Json::Num(number) = value else {
        return Err(format!("echSockopt.{key} is not a number"));
    };
    if number.fract() != 0.0 || *number < f64::from(i32::MIN) || *number > f64::from(i32::MAX) {
        return Err(format!("echSockopt.{key} is not an int32"));
    }
    Ok(Some(*number as i32))
}

fn text(node: &Json, key: &str) -> Result<Option<String>, String> {
    let Some(value) = node.get(key) else {
        return Ok(None);
    };
    match value {
        Json::Null => Ok(None),
        Json::Str(text) if text.is_empty() => Ok(None),
        Json::Str(text) => Ok(Some(text.clone())),
        _ => Err(format!("echSockopt.{key} is not a string")),
    }
}

fn keep_alive(node: &Json) -> Result<KeepAlive, String> {
    let idle = int(node, "tcpKeepAliveIdle")?.unwrap_or(0);
    let interval = int(node, "tcpKeepAliveInterval")?.unwrap_or(0);
    if idle.signum() * interval.signum() < 0 {
        return Err("echSockopt tcpKeepAliveIdle and tcpKeepAliveInterval disagree".to_owned());
    }
    if idle < 0 || interval < 0 {
        return Ok(KeepAlive::Disabled);
    }
    Ok(KeepAlive::Enabled {
        idle: u64::try_from(if idle == 0 { 45 } else { idle }).unwrap_or(45),
        interval: u64::try_from(if interval == 0 { 45 } else { interval }).unwrap_or(45),
    })
}

fn custom(node: Option<&Json>) -> Result<Vec<CustomSockopt>, String> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let Some(items) = node.as_arr() else {
        return Err("echSockopt.customSockopt is not an array".to_owned());
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let system = item
            .get("system")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let network = item
            .get("network")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let level = item
            .get("level")
            .and_then(Json::as_str)
            .unwrap_or("")
            .parse::<i32>()
            .unwrap_or(6);
        let opt = item
            .get("opt")
            .and_then(Json::as_str)
            .ok_or_else(|| "echSockopt.customSockopt has no opt".to_owned())?
            .parse::<i32>()
            .unwrap_or(0);
        let value = item
            .get("value")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let kind = item.get("type").and_then(Json::as_str);
        let value = match kind {
            Some("int") => CustomValue::Int(value.parse::<i32>().unwrap_or(0)),
            Some("str") => CustomValue::Str(value),
            Some(other) => {
                return Err(format!("echSockopt.customSockopt type {other} is unknown"));
            }
            None => return Err("echSockopt.customSockopt has no type".to_owned()),
        };
        out.push(CustomSockopt {
            system,
            network,
            level,
            opt,
            value,
        });
    }
    Ok(out)
}

impl SocketOptions {
    /// The DNS cache key differs whenever an option that changes the query socket differs.
    pub(crate) fn cache_key(&self) -> String {
        format!("{self:?}")
    }

    fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, String> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for addr in (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("ech: resolve {host}: {e}"))?
        {
            if addr.is_ipv4() {
                v4.push(addr);
            } else {
                v6.push(addr);
            }
        }
        let pick = match self.domain {
            DomainStrategy::AsIs | DomainStrategy::UseIp => v4.first().or_else(|| v6.first()),
            DomainStrategy::UseIp4 | DomainStrategy::ForceIp4 => v4.first(),
            DomainStrategy::UseIp6 | DomainStrategy::ForceIp6 => v6.first(),
            DomainStrategy::UseIp46 | DomainStrategy::ForceIp46 => {
                v4.first().or_else(|| v6.first())
            }
            DomainStrategy::UseIp64 | DomainStrategy::ForceIp64 => {
                v6.first().or_else(|| v4.first())
            }
        };
        pick.copied()
            .ok_or_else(|| format!("ech: {host} resolved to nothing this strategy allows"))
    }

    fn apply(&self, socket: &Socket, addr: SocketAddr, tcp: bool) -> io::Result<()> {
        if tcp {
            match self.keep_alive {
                Some(KeepAlive::Enabled { idle, interval }) => {
                    let params = TcpKeepalive::new()
                        .with_time(Duration::from_secs(idle))
                        .with_interval(Duration::from_secs(interval));
                    socket.set_keepalive(true)?;
                    socket.set_tcp_keepalive(&params)?;
                }
                Some(KeepAlive::Disabled) => socket.set_keepalive(false)?,
                None => {}
            }
        }
        platform::apply(self, socket, addr, tcp)?;
        self.apply_custom(
            socket,
            if tcp {
                if addr.is_ipv4() {
                    "tcp4"
                } else {
                    "tcp6"
                }
            } else if addr.is_ipv4() {
                "udp4"
            } else {
                "udp6"
            },
        )
    }

    fn apply_custom(&self, socket: &Socket, network: &str) -> io::Result<()> {
        for custom in &self.custom {
            if !custom.system.is_empty() && custom.system != platform::GOOS {
                continue;
            }
            if !network.starts_with(&custom.network) {
                continue;
            }
            match &custom.value {
                CustomValue::Int(value) => {
                    platform::set_int(socket, custom.level, custom.opt, *value)?;
                }
                CustomValue::Str(value) => {
                    platform::set_str(socket, custom.level, custom.opt, value)?;
                }
            }
        }
        Ok(())
    }
}

/// Connect a DNS transport with the ECH socket settings applied before the first packet.
pub(crate) fn connect(
    options: Option<&SocketOptions>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let addr = match options {
        Some(options) => options.resolve(host, port)?,
        None => (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("ech: resolve {host}: {e}"))?
            .next()
            .ok_or_else(|| format!("ech: {host} resolved to nothing"))?,
    };
    let socket = Socket::new(domain_of(addr), Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("ech: tcp socket: {e}"))?;
    if let Some(options) = options {
        options
            .apply(&socket, addr, true)
            .map_err(|e| format!("ech: tcp options: {e}"))?;
    }
    socket
        .connect_timeout(&SockAddr::from(addr), timeout)
        .map_err(|e| format!("ech: connect {addr}: {e}"))?;
    Ok(TcpStream::from(socket))
}

/// Bind a UDP DNS socket with the ECH socket settings applied before the query is sent.
pub(crate) fn datagram(
    options: Option<&SocketOptions>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<UdpSocket, String> {
    let addr = match options {
        Some(options) => options.resolve(host, port)?,
        None => (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("ech: resolve {host}: {e}"))?
            .next()
            .ok_or_else(|| format!("ech: {host} resolved to nothing"))?,
    };
    let socket = Socket::new(domain_of(addr), Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("ech: udp socket: {e}"))?;
    if let Some(options) = options {
        options
            .apply(&socket, addr, false)
            .map_err(|e| format!("ech: udp options: {e}"))?;
    }
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let bind: SocketAddr = bind
        .parse()
        .map_err(|_| "ech: udp bind address".to_owned())?;
    socket
        .bind(&SockAddr::from(bind))
        .map_err(|e| format!("ech: udp bind: {e}"))?;
    socket
        .connect(&SockAddr::from(addr))
        .map_err(|e| format!("ech: udp connect: {e}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("ech: udp timeout: {e}"))?;
    Ok(UdpSocket::from(socket))
}

fn domain_of(addr: SocketAddr) -> Domain {
    if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    }
}

#[cfg(unix)]
mod platform {
    use super::SocketOptions;
    use socket2::Socket;
    use std::ffi::CString;
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd as _;

    pub(super) const GOOS: &str = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        std::env::consts::OS
    };

    pub(super) fn apply(
        options: &SocketOptions,
        socket: &Socket,
        addr: SocketAddr,
        tcp: bool,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            if let Some(mark) = options.mark {
                set_int(socket, libc::SOL_SOCKET, libc::SO_MARK, mark)?;
            }
            if let Some(interface) = &options.interface {
                set_str(socket, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, interface)?;
            }
            if tcp {
                if let Some(tfo) = options.tfo {
                    set_int(socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT, tfo)?;
                }
                if let Some(congestion) = &options.congestion {
                    set_str(socket, libc::IPPROTO_TCP, libc::TCP_CONGESTION, congestion)?;
                }
                if let Some(clamp) = options.window_clamp {
                    set_int(socket, libc::IPPROTO_TCP, libc::TCP_WINDOW_CLAMP, clamp)?;
                }
                if let Some(timeout) = options.user_timeout {
                    set_int(socket, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, timeout)?;
                }
                if let Some(max_seg) = options.max_seg {
                    set_int(socket, libc::IPPROTO_TCP, libc::TCP_MAXSEG, max_seg)?;
                }
            }
            if options.tproxy {
                let level = if addr.is_ipv4() {
                    libc::SOL_IP
                } else {
                    libc::SOL_IPV6
                };
                let name = if addr.is_ipv4() {
                    libc::IP_TRANSPARENT
                } else {
                    libc::IPV6_TRANSPARENT
                };
                set_int(socket, level, name, 1)?;
            }
        }
        #[cfg(target_os = "macos")]
        {
            let _ = options.mark;
            if let Some(interface) = &options.interface {
                let name = CString::new(interface.as_str())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name"))?;
                // SAFETY: the name is a live NUL-terminated string.
                let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
                if index == 0 {
                    return Err(io::Error::last_os_error());
                }
                let index = i32::try_from(index)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface index"))?;
                if addr.is_ipv6() {
                    set_int(socket, libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF, index)?;
                } else {
                    set_int(socket, libc::IPPROTO_IP, libc::IP_BOUND_IF, index)?;
                }
            }
            if tcp {
                if let Some(tfo) = options.tfo {
                    set_int(socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, tfo * 2)?;
                }
                if let Some(max_seg) = options.max_seg {
                    set_int(socket, libc::IPPROTO_TCP, libc::TCP_MAXSEG, max_seg)?;
                }
                let _ = (
                    &options.congestion,
                    options.window_clamp,
                    options.user_timeout,
                );
            }
            let _ = options.tproxy;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (options, addr, tcp);
        }
        Ok(())
    }

    pub(super) fn set_int(
        socket: &Socket,
        level: libc::c_int,
        name: libc::c_int,
        value: i32,
    ) -> io::Result<()> {
        // SAFETY: `value` outlives the call and the descriptor is the socket's own.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                std::ptr::addr_of!(value).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn set_str(
        socket: &Socket,
        level: libc::c_int,
        name: libc::c_int,
        value: &str,
    ) -> io::Result<()> {
        let value = CString::new(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket option string"))?;
        // SAFETY: the string is NUL-terminated and outlives the call.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                value.as_ptr().cast(),
                value.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::SocketOptions;
    use socket2::Socket;
    use std::io;
    use std::net::SocketAddr;
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET};

    pub(super) const GOOS: &str = "windows";

    pub(super) fn apply(
        _options: &SocketOptions,
        _socket: &Socket,
        _addr: SocketAddr,
        _tcp: bool,
    ) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_int(socket: &Socket, level: i32, name: i32, value: i32) -> io::Result<()> {
        // SAFETY: the value outlives the call and the handle is the socket's own.
        let rc = unsafe {
            setsockopt(
                socket.as_raw_socket() as SOCKET,
                level,
                name,
                std::ptr::addr_of!(value).cast(),
                i32::try_from(std::mem::size_of_val(&value)).unwrap_or(i32::MAX),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn set_str(
        _socket: &Socket,
        _level: i32,
        _name: i32,
        _value: &str,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "string socket options are not supported on windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> SocketOptions {
        let json = crate::json::parse(text).expect("parses");
        parse(Some(&json)).expect("parses").expect("present")
    }

    fn refused(text: &str) -> String {
        let json = crate::json::parse(text).expect("parses");
        parse(Some(&json)).expect_err("refuses")
    }

    #[test]
    fn tfo_follows_xray_zero_and_sign() {
        assert_eq!(parsed(r#"{"tcpFastOpen":true}"#).tfo, Some(1));
        assert_eq!(parsed(r#"{"tcpFastOpen":false}"#).tfo, Some(0));
        assert_eq!(parsed(r#"{"tcpFastOpen":0}"#).tfo, None);
        assert_eq!(parsed(r#"{"tcpFastOpen":-1}"#).tfo, Some(0));
        assert_eq!(parsed(r#"{"tcpFastOpen":5}"#).tfo, Some(1));
    }

    #[test]
    fn a_socket_config_defaults_keepalive_to_chrome() {
        assert_eq!(
            parsed("{}").keep_alive,
            Some(KeepAlive::Enabled {
                idle: 45,
                interval: 45
            })
        );
        assert_eq!(
            parsed(r#"{"tcpKeepAliveIdle":11,"tcpKeepAliveInterval":7}"#).keep_alive,
            Some(KeepAlive::Enabled {
                idle: 11,
                interval: 7
            })
        );
        assert_eq!(
            parsed(r#"{"tcpKeepAliveIdle":-1}"#).keep_alive,
            Some(KeepAlive::Disabled)
        );
        assert!(
            refused(r#"{"tcpKeepAliveIdle":10,"tcpKeepAliveInterval":-1}"#).contains("disagree")
        );
    }

    #[test]
    fn domain_strategy_names_and_refusals_match_the_reference() {
        assert_eq!(parsed("{}").domain, DomainStrategy::AsIs);
        assert_eq!(
            parsed(r#"{"domainStrategy":"UseIPv4v6"}"#).domain,
            DomainStrategy::UseIp46
        );
        assert_eq!(
            parsed(r#"{"domainStrategy":"forceIPv6v4"}"#).domain,
            DomainStrategy::ForceIp64
        );
        assert!(refused(r#"{"domainStrategy":"preferIp"}"#).contains("domainStrategy"));
    }

    #[test]
    fn custom_options_are_typed() {
        let options = parsed(
            r#"{"customSockopt":[{"system":"darwin","network":"tcp","level":"1","opt":"2","type":"int","value":"65536"},{"system":"linux","network":"udp","level":"17","opt":"1","type":"str","value":"x"}]}"#,
        );
        assert_eq!(options.custom.len(), 2);
        assert_eq!(options.custom[0].value, CustomValue::Int(65536));
        assert_eq!(options.custom[1].value, CustomValue::Str("x".to_owned()));
        assert!(
            refused(r#"{"customSockopt":[{"opt":"2","type":"bool","value":"1"}]}"#)
                .contains("unknown")
        );
        assert!(refused(r#"{"customSockopt":[{"type":"int","value":"x"}]}"#).contains("opt"));
    }

    #[test]
    fn an_invalid_socket_value_is_refused() {
        assert!(refused(r#"{"mark":"1"}"#).contains("mark"));
        assert!(refused(r#"{"tcpWindowClamp":1.5}"#).contains("int32"));
        assert!(refused(r#"{"interface":4}"#).contains("interface"));
    }

    #[test]
    fn use_ipv4_picks_a_v4_address() {
        let options = parsed(r#"{"domainStrategy":"useipv4"}"#);
        let addr = options.resolve("localhost", 443).expect("resolves");
        assert!(addr.is_ipv4());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_bad_interface_fails_before_connect() {
        let options = parsed(r#"{"interface":"ferrox-no-such-interface"}"#);
        let err = connect(Some(&options), "127.0.0.1", 9, Duration::from_millis(10))
            .expect_err("interface is absent");
        assert!(err.contains("options"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn keepalive_and_custom_options_reach_the_connected_socket() {
        use std::net::TcpListener;
        use std::os::fd::AsRawFd as _;

        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let worker = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let text = format!(
            r#"{{"tcpKeepAliveIdle":11,"tcpKeepAliveInterval":7,"customSockopt":[{{"system":"{}","network":"tcp","level":"{}","opt":"{}","type":"int","value":"1"}}]}}"#,
            platform::GOOS,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY
        );
        let options = parsed(&text);
        let stream =
            connect(Some(&options), "127.0.0.1", port, Duration::from_secs(5)).expect("connects");
        let fd = stream.as_raw_fd();
        assert_ne!(get_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 0);
        #[cfg(target_os = "macos")]
        assert_eq!(get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPALIVE), 11);
        #[cfg(target_os = "linux")]
        assert_eq!(get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE), 11);
        assert_eq!(get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL), 7);
        assert_ne!(get_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY), 0);
        worker.join().expect("accepts");
    }

    #[cfg(unix)]
    fn get_int(fd: std::os::fd::RawFd, level: libc::c_int, name: libc::c_int) -> i32 {
        let mut value = 0i32;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: the descriptor is live and the value buffer is writable.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                std::ptr::addr_of_mut!(value).cast(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
        value
    }
}
