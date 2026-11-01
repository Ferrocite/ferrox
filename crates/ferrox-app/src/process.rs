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
pub(crate) fn socket_inode(network: Network, source: SocketAddr) -> Option<String> {
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
        let (exact, file_wildcard) = inodes_in(&table, &address, port.as_deref());
        if let Some(inode) = exact {
            return Some(inode);
        }
        wildcard = file_wildcard.or(wildcard);
    }
    wildcard
}

/// The two inodes one `/proc/net` table names for a source — the row that spells the address exactly and the last wildcard row on the same port — with the rows the kernel prints with an inode of `0` skipped, because a socket with no descriptor names no process and must not end the scan.
#[cfg(target_os = "linux")]
fn inodes_in(table: &str, address: &str, port: Option<&str>) -> (Option<String>, Option<String>) {
    let mut wildcard = None;
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
        if inode == "0" {
            continue;
        }
        if local == address {
            return (Some(inode.to_owned()), wildcard);
        }
        if let Some(suffix) = port {
            if let Some(bound) = local.strip_suffix(suffix) {
                if matches!(bound.len(), 8 | 32) && bound.bytes().all(|byte| byte == b'0') {
                    wildcard = Some(inode.to_owned());
                }
            }
        }
    }
    (None, wildcard)
}

/// The local address as the `/proc/net` tables spell it: each 32-bit word in host byte order, then
/// the port. IPv4 is one word; IPv6 is four.
#[cfg(target_os = "linux")]
fn local_hex(octets: &[u8], port: u16) -> String {
    use std::fmt::Write as _;
    let mut address = String::with_capacity(octets.len() * 2 + 5);
    for word in octets.as_chunks::<4>().0 {
        let _ = write!(address, "{:08X}", u32::from_ne_bytes(*word));
    }
    let _ = write!(address, ":{port:04X}");
    address
}

/// The pid holding `inode`, by the one file descriptor that links it to `socket:[inode]`.
#[cfg(target_os = "linux")]
pub(crate) fn owner_pid(inode: &str) -> Option<u32> {
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

    /// The kernel prints IPv4 as one 32-bit word and IPv6 as four, each in host byte order; a
    /// single byte reversal only matches the one-word spelling.
    #[test]
    fn local_hex_spells_each_32_bit_word_as_the_kernel_does() {
        let (v4, v6) = if cfg!(target_endian = "little") {
            ("0100007F:0050", "00000000000000000000000001000000:01BB")
        } else {
            ("7F000001:0050", "00000000000000000000000000000001:01BB")
        };
        assert_eq!(local_hex(&[127, 0, 0, 1], 80), v4);
        let loopback = std::net::Ipv6Addr::LOCALHOST.octets();
        assert_eq!(local_hex(&loopback, 443), v6);
    }

    /// A row the kernel leaves ownerless is no answer: the live row anywhere else in the table names
    /// the process, and a table of ownerless rows names nothing.
    #[test]
    fn an_ownerless_row_does_not_end_the_scan() {
        const HEADER: &str =
            "sl local_address rem_address st tx:rx tr:tm->when retrnsmt uid timeout inode";
        let row = |slot: &str, local: &str, state: &str, inode: &str| {
            format!("{slot} {local} 0100007F:0050 {state} 0:0 0:0 0 0 0 {inode}")
        };
        let table = |rows: [String; 4]| format!("{HEADER}\n{}\n", rows.join("\n"));
        let mixed = table([
            row("0:", "0100007F:1F90", "06", "0"),
            row("1:", "00000000:1F90", "07", "5678"),
            row("2:", "00000000:1F90", "06", "0"),
            row("3:", "0100007F:1F90", "01", "1234"),
        ]);
        let (exact, wildcard) = inodes_in(&mixed, "0100007F:1F90", Some(":1F90"));
        assert_eq!(
            exact.as_deref(),
            Some("1234"),
            "the source's own row, not the ownerless one ahead of it"
        );
        assert_eq!(
            wildcard.as_deref(),
            Some("5678"),
            "an ownerless wildcard row behind the live one is no answer either"
        );
        let dead = table([
            row("0:", "0100007F:1F90", "06", "0"),
            row("1:", "00000000:1F90", "06", "0"),
            row("2:", "00000000:1F90", "06", "0"),
            row("3:", "0100007F:1F90", "06", "0"),
        ]);
        assert_eq!(
            inodes_in(&dead, "0100007F:1F90", Some(":1F90")),
            (None, None),
            "a table of ownerless rows names no process"
        );
    }

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
