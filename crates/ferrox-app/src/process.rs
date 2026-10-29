//! The process behind a client socket, which a `process` routing rule names.
//!
//! The lookup walks the kernel's own tables the way the reference's does: the socket's local address
//! in `/proc/net/{tcp,tcp6,udp,udp6}` names an inode, the inode names a pid, and the pid's executable
//! names the process. A host without that table — and a socket whose owner has exited — answers
//! nothing, which fails every `process` rule exactly as the reference's matcher does on a lookup error.

use crate::router::Network;
use std::net::SocketAddr;

/// The process behind a client socket: the pid `self/` names, the executable path an absolute path or
/// a folder prefix names, and the path's basename that a bare name names.
#[derive(Debug)]
pub(crate) struct Owner {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) path: String,
}

#[cfg(target_os = "linux")]
pub(crate) fn owner(network: Network, source: SocketAddr) -> Option<Owner> {
    let inode = socket_inode(network, source)?;
    let pid = owner_pid(&inode)?;
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let path = path.to_str()?.to_owned();
    let name = path.rsplit('/').next()?.to_owned();
    Some(Owner { pid, name, path })
}

/// The reference's own lookup answers nothing off Linux, so a `process` rule matches no flow here
/// rather than being dropped: the rest of the rule still narrows, it just cannot hold.
#[cfg(not(target_os = "linux"))]
pub(crate) fn owner(_network: Network, _source: SocketAddr) -> Option<Owner> {
    None
}

/// The inode of the local socket bound to `source`. The `/proc/net` tables list each socket's *local*
/// address, so a remote peer's address never matches and needs no local-address test of its own.
#[cfg(target_os = "linux")]
fn socket_inode(network: Network, source: SocketAddr) -> Option<String> {
    let (files, address): (&[&str], String) = match (network, source.ip().to_canonical()) {
        (Network::Tcp, std::net::IpAddr::V4(ip)) => {
            (&["/proc/net/tcp"], local_hex(&ip.octets(), source.port()))
        }
        (Network::Tcp, std::net::IpAddr::V6(ip)) => {
            (&["/proc/net/tcp6"], local_hex(&ip.octets(), source.port()))
        }
        (Network::Udp, std::net::IpAddr::V4(ip)) => (
            &["/proc/net/udp", "/proc/net/udp6"],
            local_hex(&ip.octets(), source.port()),
        ),
        (Network::Udp, std::net::IpAddr::V6(ip)) => (
            &["/proc/net/udp6", "/proc/net/udp"],
            local_hex(&ip.octets(), source.port()),
        ),
        (Network::Other(_), _) => return None,
    };
    // A wildcard-bound UDP socket lists under the zero address, so its port alone names it; the reference keeps the last.
    let port = matches!(network, Network::Udp).then(|| format!(":{:04X}", source.port()));
    let mut wildcard = None;
    for file in files {
        let Ok(table) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in table.lines().skip(1) {
            let mut fields = line.split_ascii_whitespace();
            let Some(_slot) = fields.next() else {
                break;
            };
            let Some(local) = fields.next() else {
                break;
            };
            // sl, local_address, rem_address, st, tx:rx, tr:tm->when, retrnsmt, uid, timeout, inode.
            let Some(inode) = fields.nth(7) else {
                break;
            };
            if local == address {
                return Some(inode.to_owned());
            }
            if let Some(suffix) = &port {
                if let Some(bound) = local.strip_suffix(suffix.as_str()) {
                    if matches!(bound.len(), 8 | 32) && bound.bytes().all(|byte| byte == b'0') {
                        wildcard = Some(inode.to_owned());
                    }
                }
            }
        }
    }
    wildcard
}

/// The local address as the `/proc/net` tables spell it: the address bytes in host order, uppercase
/// hex, then the port.
#[cfg(target_os = "linux")]
fn local_hex(octets: &[u8], port: u16) -> String {
    use std::fmt::Write as _;
    let mut address = String::with_capacity(octets.len() * 2 + 5);
    for byte in octets.iter().rev() {
        let _ = write!(address, "{byte:02X}");
    }
    let _ = write!(address, ":{port:04X}");
    address
}

/// The pid holding `inode`, by the one file descriptor that links it to `socket:[inode]`.
#[cfg(target_os = "linux")]
fn owner_pid(inode: &str) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path())
                .is_ok_and(|link| link.to_str() == Some(target.as_str()))
            {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// The socket this process opened is the socket this process owns: the pid is ours and the path
    /// is our executable, which is what `self/` and a bare name decide on.
    #[test]
    fn a_client_socket_resolves_to_this_process() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let client = TcpStream::connect(listener.local_addr().expect("local")).expect("connects");
        let (_server, _) = listener.accept().expect("accepts");
        let source = client.local_addr().expect("source");
        let found = owner(Network::Tcp, source).expect("the client socket belongs to this process");
        assert_eq!(found.pid, std::process::id());
        let exe = std::fs::canonicalize(std::env::current_exe().expect("exe")).expect("canonical");
        assert_eq!(found.path, exe.to_str().expect("utf-8"));
        assert_eq!(
            found.name,
            exe.file_name().expect("basename").to_str().expect("utf-8")
        );
    }
}
