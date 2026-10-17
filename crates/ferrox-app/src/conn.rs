//! The transport-agnostic stream a proxy connection rides, and the two roles that produce
//! one: a listener that accepts it and a dialer that connects it.
//!
//! Until now the app spoke `std::net::TcpStream` end to end, so a config naming a Unix
//! domain socket had nowhere to bind or dial. `Connection` is the seam that lets an `AF_UNIX`
//! stream stand in for a TCP one wherever a connection is carried: it forwards the reads,
//! writes and half-closes the relay needs, keeps the same read and write timeouts the engine
//! arms a leg with, and — because `TCP_NODELAY` has no socket analogue — makes the no-delay
//! request a documented no-op on a Unix stream rather than a silent failure.
//!
//! The Unix arm is `#[cfg(unix)]` only: `std` has no `UnixStream` on Windows and `libc` has no
//! `timeval` there, so on a non-Unix host a `Connection` is a TCP stream and the row's Unix
//! half is not built. The Unix socket is a local-interconnect transport; the hosts that name
//! one in a config are Unix hosts.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::PathBuf;

/// A live proxy connection: a TCP stream, or on a Unix host an `AF_UNIX` stream, carried the
/// same way. Every method forwards to whichever it holds, so the relay, the carriers and the
/// handshake never learn which family they were handed.
#[derive(Debug)]
pub(crate) enum Connection {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl From<TcpStream> for Connection {
    fn from(stream: TcpStream) -> Self {
        Connection::Tcp(stream)
    }
}

#[cfg(unix)]
impl From<UnixStream> for Connection {
    fn from(stream: UnixStream) -> Self {
        Connection::Unix(stream)
    }
}

/// The raw descriptor the vectored-write and splice fast paths address. Both families are
/// sockets, so `writev`/`splice` reach the queue identically; `AsRawFd` is a Unix trait, and on
/// a non-Unix host a `Connection` is TCP-only and those `#[cfg(unix)]` paths are not built.
#[cfg(unix)]
impl std::os::fd::AsRawFd for Connection {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        match self {
            Connection::Tcp(stream) => stream.as_raw_fd(),
            Connection::Unix(stream) => stream.as_raw_fd(),
        }
    }
}

/// The record-boundary marker the TLS layer needs of a stream it seals records onto. `TcpStream`
/// impls it in `ferrox-core`; a `Connection` forwards to whichever family it holds, so a TLS
/// session over either arm keeps the same record alignment the TCP path had.
impl ferrox_core::tls::RecordAlignment for Connection {}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Connection::Unix(stream) => stream.read(buf),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.read_vectored(bufs),
            #[cfg(unix)]
            Connection::Unix(stream) => stream.read_vectored(bufs),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Connection::Unix(stream) => stream.write(buf),
        }
    }

    // One `writev` for a frame's parts on either family; `write_vectored` is `writev` on a socket, so the TCP coalescing is the same call, not a relocation.
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.write_vectored(bufs),
            #[cfg(unix)]
            Connection::Unix(stream) => stream.write_vectored(bufs),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Connection::Unix(stream) => stream.flush(),
        }
    }
}

// A socket answers on a shared descriptor, so `std` impls `Read`/`Write` for `&TcpStream` and the relay drains each leg by shared reference; `&Connection` does the same for whichever arm it holds.
impl Read for &Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.read(buf)
            }
            #[cfg(unix)]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.read(buf)
            }
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.read_vectored(bufs)
            }
            #[cfg(unix)]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.read_vectored(bufs)
            }
        }
    }
}

impl Write for &Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.write(buf)
            }
            #[cfg(unix)]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.write(buf)
            }
        }
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.write_vectored(bufs)
            }
            #[cfg(unix)]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.write_vectored(bufs)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.flush()
            }
            #[cfg(unix)]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.flush()
            }
        }
    }
}

impl Connection {
    /// A second handle to the same socket, so a relay reads on one leg and writes on the other.
    pub(crate) fn try_clone(&self) -> io::Result<Connection> {
        match self {
            Connection::Tcp(stream) => stream.try_clone().map(Connection::Tcp),
            #[cfg(unix)]
            Connection::Unix(stream) => stream.try_clone().map(Connection::Unix),
        }
    }

    /// Which direction of the full-duplex connection to tear down: the relay's half-close edge.
    pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.shutdown(how),
            #[cfg(unix)]
            Connection::Unix(stream) => stream.shutdown(how),
        }
    }

    /// Look ahead without consuming, the way the HTTP-head readers prove a head before taking
    /// it. TCP has `peek`; `std`'s `UnixStream::peek` is unstable, so the Unix arm issues the
    /// same `recv(MSG_PEEK)` the kernel serves under the hood.
    pub(crate) fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.peek(buf),
            #[cfg(unix)]
            Connection::Unix(stream) => unix_peek(stream, buf),
        }
    }

    /// The peer's address. `std` answers `io::Result` for a TCP stream and an `AF_UNIX` one
    /// has no IP tuple, so the Unix arm yields the same error a caller asking a never-bound TCP
    /// stream gets — matching the std signature keeps every `peer_addr()?`/`.ok()` call-site
    /// unchanged across the transport swap.
    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Connection::Tcp(stream) => stream.peer_addr(),
            #[cfg(unix)]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream reports no peer address",
            )),
        }
    }

    /// The local address, `std`'s `io::Result` shape; `Unsupported` for a Unix stream, which
    /// reports no port.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Connection::Tcp(stream) => stream.local_addr(),
            #[cfg(unix)]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream reports no local address",
            )),
        }
    }

    /// Arm the read side's wait bound. TCP uses `SO_RCVTIMEO`; on a Unix stream `std` omits the
    /// setter, so the same `timeval` goes through `setsockopt` at `SOL_SOCKET`, the level that
    /// carries it for `AF_UNIX` too. `None` clears the bound and lets the read block.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_read_timeout(timeout),
            #[cfg(unix)]
            Connection::Unix(stream) => set_socket_timeout(stream, libc::SO_RCVTIMEO, timeout),
        }
    }

    /// Arm the write side's wait bound, mirroring `set_read_timeout` on `SO_SNDTIMEO`.
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_write_timeout(timeout),
            #[cfg(unix)]
            Connection::Unix(stream) => set_socket_timeout(stream, libc::SO_SNDTIMEO, timeout),
        }
    }

    /// Read back the armed wait bound, so a caller can save and restore it around a stage that
    /// tightens it. TCP asks `std`; a Unix stream reads the same `SO_RCVTIMEO`/`SO_SNDTIMEO`
    /// `timeval` back through `getsockopt`, so the save/restore is as exact as the set was.
    pub(crate) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            Connection::Tcp(stream) => stream.read_timeout(),
            #[cfg(unix)]
            Connection::Unix(stream) => get_socket_timeout(stream, libc::SO_RCVTIMEO),
        }
    }

    /// Turn Nagle off, matching `TcpStream::set_nodelay(bool)` so the `no_delay` wrapper's call
    /// is unchanged. Meaningful only on TCP; a Unix stream needs no analogue — there is no
    /// internetwork to delay on — so the request is accepted and does nothing rather than
    /// failing, which is why a caller keeps calling it uniformly on either family.
    pub(crate) fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_nodelay(nodelay),
            #[cfg(unix)]
            Connection::Unix(_) => Ok(()),
        }
    }
}

/// Set `SO_RCVTIMEO`/`SO_SNDTIMEO` the way `std` does for TCP but not Unix: one `timeval`
/// through `setsockopt` at `SOL_SOCKET`, the level carrying the timeout for `AF_UNIX`. A zero
/// `timeval` clears the bound and the call blocks, matching `None`.
#[cfg(unix)]
fn set_socket_timeout(
    stream: &UnixStream,
    option: libc::c_int,
    timeout: Option<Duration>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    if let Some(timeout) = timeout {
        // Whole microseconds; the sub-microsecond remainder would only round the bound down.
        value.tv_sec = timeout.as_secs().try_into().unwrap_or(i64::MAX);
        value.tv_usec = timeout.subsec_micros().try_into().unwrap_or(0);
    }
    // SAFETY: `value` is a live `timeval`, sized as the kernel reads the option, on the stream's own descriptor.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw const value).cast::<libc::c_void>(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read `SO_RCVTIMEO`/`SO_SNDTIMEO` back as the `Duration` `std` would report for TCP: a zero
/// `timeval` is no bound (`None`), otherwise seconds plus microseconds. This keeps a save/restore
/// of the budget exact on a Unix stream, where `std` gives no getter.
#[cfg(unix)]
fn get_socket_timeout(stream: &UnixStream, option: libc::c_int) -> io::Result<Option<Duration>> {
    use std::os::fd::AsRawFd;
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: `value` and `len` are writable and sized as the kernel writes the option, on the stream's own descriptor.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let secs = u64::try_from(value.tv_sec).unwrap_or(0);
    let micros = u32::try_from(value.tv_usec).unwrap_or(0);
    if secs == 0 && micros == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::new(secs, micros * 1_000)))
}

/// A Unix `peek`: `recv` with `MSG_PEEK` reads the head of the queue without consuming it,
/// which is exactly the `TcpStream::peek` the head readers rely on. A zero-length buffer is
/// refused by the kernel as `EINVAL`, so an empty peek answers `Ok(0)` before the call.
#[cfg(unix)]
fn unix_peek(stream: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        // SAFETY: `buf` is a live slice of `buf.len()` readable bytes on the stream's own descriptor; `MSG_PEEK` leaves the queue unchanged.
        let read = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if read >= 0 {
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Where a proxy connection goes: an IP address and port, or, on a Unix host, the path of an
/// `AF_UNIX` socket. The dial role needs both because a config naming `unix:/path/sock` is not
/// a `SocketAddr`, and the address is what picks the family before anything is dialed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Ip(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

/// Parse a listen or dial address into a `Target`. A leading `unix:` (the spelling the
/// references use for a socket path) names an `AF_UNIX` stream on a Unix host; anything else
/// resolves as an address, so every `ip:port` caller keeps its behavior untouched. An empty
/// path after the prefix is refused rather than dialed at the filesystem root.
pub(crate) fn parse_target(address: &str) -> io::Result<Target> {
    #[cfg(unix)]
    if let Some(rest) = address.strip_prefix("unix:") {
        if rest.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a unix address names no path",
            ));
        }
        return Ok(Target::Unix(PathBuf::from(rest)));
    }
    let mut addrs = address.to_socket_addrs()?;
    addrs
        .next()
        .map(Target::Ip)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address resolved to nothing"))
}

/// One bound socket yielding `Connection`s, whichever family it was opened in, so the accept
/// loop keeps the same shape whichever the config named.
pub(crate) enum Listener {
    Tcp(std::net::TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl Listener {
    /// Bind a listener for the target's family. A Unix path left from a previous run is unlinked
    /// first: binding over an existing socket file fails `EADDRINUSE`, and a stale socket nobody
    /// owns is exactly that — the same unlink-then-bind recovery the references do.
    pub(crate) fn bind(target: &Target) -> io::Result<Listener> {
        match target {
            Target::Ip(addr) => std::net::TcpListener::bind(addr).map(Listener::Tcp),
            #[cfg(unix)]
            Target::Unix(path) => {
                if std::fs::symlink_metadata(path).is_ok() {
                    std::fs::remove_file(path)?;
                }
                UnixListener::bind(path).map(Listener::Unix)
            }
        }
    }

    #[cfg(test)]
    /// The socket address a TCP listener holds. A Unix listener has no port to report, so it
    /// answers the error a caller expecting an ephemeral TCP port would get from no bind.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Listener::Tcp(listener) => listener.local_addr(),
            #[cfg(unix)]
            Listener::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix listener reports no socket address",
            )),
        }
    }

    pub(crate) fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }
}

/// The accepted connections of a `Listener`, one family or the other.
pub(crate) struct Incoming<'a> {
    listener: &'a Listener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<Connection>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.listener {
            Listener::Tcp(listener) => listener
                .incoming()
                .map(|stream| stream.map(Connection::Tcp))
                .next(),
            #[cfg(unix)]
            Listener::Unix(listener) => listener
                .incoming()
                .map(|stream| stream.map(Connection::Unix))
                .next(),
        }
    }
}

/// Dial a resolved TCP address with a budget, yielding a `Connection`. This is the one dial
/// primitive the edge/uplink producers use; it forwards to `TcpStream::connect_timeout` with the
/// same arguments, so the dial it issues (and its budget) is byte-for-byte what the TCP path
/// did before the transport seam — the transport type changed, the syscall did not.
pub(crate) fn dial_tcp(addr: &SocketAddr, timeout: Duration) -> io::Result<Connection> {
    TcpStream::connect_timeout(addr, timeout).map(Connection::Tcp)
}

#[cfg(test)]
impl Connection {
    /// A TCP connection to an address, for the suites that dial their own echo servers before
    /// handing the stream to a carrier. They once wrote `TcpStream::connect`; the transport type
    /// on both sides of such a test is now `Connection`, and this keeps that one call the same.
    pub(crate) fn connect(addr: impl std::net::ToSocketAddrs) -> io::Result<Connection> {
        TcpStream::connect(addr).map(Connection::Tcp)
    }

    /// Read the `TCP_NODELAY` flag back, for the one test that proves a dial and an accept both
    /// turn Nagle off. A Unix stream has no such flag, so it answers as a never-set query would.
    pub(crate) fn nodelay(&self) -> io::Result<bool> {
        match self {
            Connection::Tcp(stream) => stream.nodelay(),
            #[cfg(unix)]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream has no TCP_NODELAY flag",
            )),
        }
    }
}

/// Bind a TCP listener for the suites that stand up their own echo servers. They once wrote
/// `TcpListener::bind`; a listener now yields `Connection`s on both roles, so a fixture binds
/// through the same seam and gets the matching type back.
#[cfg(test)]
pub(crate) fn test_bind(addr: impl std::net::ToSocketAddrs) -> io::Result<Listener> {
    std::net::TcpListener::bind(addr).map(Listener::Tcp)
}

#[cfg(test)]
impl Listener {
    /// The single accept a fixture that dials one client needs; the std `accept` shape, mapped
    /// onto the seam so a bound listener hands back a `Connection` and the peer address.
    pub(crate) fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
        match self {
            Listener::Tcp(listener) => listener
                .accept()
                .map(|(stream, addr)| (Connection::Tcp(stream), addr)),
            #[cfg(unix)]
            Listener::Unix(listener) => listener.accept().map(|(stream, _addr)| {
                (
                    Connection::Unix(stream),
                    SocketAddr::from(([0, 0, 0, 0], 0)),
                )
            }),
        }
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Listener::Tcp(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Listener::Unix(listener) => listener.set_nonblocking(nonblocking),
        }
    }
}

/// Connect to a target, whichever family it names. The IP arm is the TCP dial with its budget
/// unchanged; the Unix arm connects a socket path. A local `AF_UNIX` connect returns at once
/// (`ENOENT`/`ECONNREFUSED`) rather than waiting out a retransmission, so it needs no timeout.
pub(crate) fn connect(target: &Target, timeout: Duration) -> io::Result<Connection> {
    match target {
        Target::Ip(addr) => dial_tcp(addr, timeout),
        #[cfg(unix)]
        Target::Unix(path) => UnixStream::connect(path).map(Connection::Unix),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The row's identity claim is transparency: a Unix stream carries the exact bytes the same
    /// round trip over TCP carries, in both directions, with no re-framing. A differential over
    /// a real `AF_UNIX` socket witnesses it and runs with no root and no `CAP_NET_ADMIN`.
    #[test]
    fn a_unix_connection_carries_the_same_bytes_the_tcp_round_trip_does() {
        let sent: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 253) as u8).collect();
        let over_unix = round_trip_unix(&sent);
        let over_tcp = round_trip_tcp(&sent);
        assert_eq!(
            over_unix, over_tcp,
            "a unix round trip must be byte-identical to the tcp one"
        );
        assert_eq!(
            over_unix, sent,
            "the payload is delivered whole and unchanged"
        );
    }

    /// A head that is not a multiple of any vector width, and a big bulk write the kernel buffer
    /// cannot take at once — the inputs a round number hides — must still arrive whole.
    #[test]
    fn a_unix_round_trip_survives_lengths_a_vector_would_split() {
        for len in [1usize, 3, 1501, 65535] {
            let sent: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                round_trip_unix(&sent),
                sent,
                "{len} bytes round-trip whole over a unix stream"
            );
        }
    }

    /// The timeout setter must arm a Unix read the way it arms a TCP one, or a leg the engine
    /// bounds would park forever on unix while failing on tcp — the budget-parity claim.
    #[test]
    fn a_unix_read_timeout_arms_the_way_the_tcp_one_does() {
        let (_client, listener) = unix_pair();
        let server = listener.incoming().next().unwrap().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("arms a read timeout on a unix stream");
        let mut reader = match server {
            Connection::Unix(stream) => stream,
            Connection::Tcp(_) => unreachable!("a unix pair yields a unix stream"),
        };
        let mut buf = [0u8; 4];
        let error = reader
            .read(&mut buf)
            .expect_err("an empty armed unix read times out");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "the bound fired, not a block: {:?}",
            error.kind()
        );
    }

    /// The `unix:` spelling is what selects the family before anything is dialed; an empty path
    /// is refused rather than bound at the root.
    #[test]
    fn a_unix_address_parses_to_a_path_and_an_empty_one_is_refused() {
        let target = parse_target("unix:/run/ferrox/sock").expect("parses");
        assert_eq!(target, Target::Unix(PathBuf::from("/run/ferrox/sock")));
        assert!(parse_target("unix:").is_err(), "an empty path is refused");
        assert!(
            matches!(
                parse_target("127.0.0.1:1").expect("ip parses"),
                Target::Ip(_)
            ),
            "an ip:port stays an ip target"
        );
    }

    fn round_trip_unix(sent: &[u8]) -> Vec<u8> {
        let (mut client, listener) = unix_pair();
        let handle = std::thread::spawn(move || {
            let mut server = listener.incoming().next().unwrap().unwrap();
            let mut got = Vec::new();
            server.read_to_end(&mut got).expect("reads the request");
            server.write_all(&got).expect("echoes it");
            server.flush().expect("flushes");
            server.shutdown(Shutdown::Write).expect("half-closes");
        });
        echo_round_trip(&mut client, sent, handle)
    }

    fn round_trip_tcp(sent: &[u8]) -> Vec<u8> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().expect("accepts");
            let mut got = Vec::new();
            server.read_to_end(&mut got).expect("reads the request");
            server.write_all(&got).expect("echoes it");
            server.flush().expect("flushes");
            let _ = server.shutdown(Shutdown::Write);
        });
        let mut client: Connection = TcpStream::connect(addr).expect("connects").into();
        echo_round_trip(&mut client, sent, handle)
    }

    fn echo_round_trip(
        client: &mut Connection,
        sent: &[u8],
        handle: std::thread::JoinHandle<()>,
    ) -> Vec<u8> {
        client.write_all(sent).expect("writes the request");
        client.flush().expect("flushes");
        client
            .shutdown(Shutdown::Write)
            .expect("half-closes the write side");
        let mut back = Vec::new();
        client.read_to_end(&mut back).expect("reads the echo");
        handle.join().expect("the echo thread finishes");
        back
    }

    /// A connected unix client and its still-bound listener, in a per-test directory that is
    /// removed so no two runs collide on one socket path.
    fn unix_pair() -> (Connection, Listener) {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-unix-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("sock");
        let listener = Listener::bind(&Target::Unix(path.clone())).expect("binds a unix socket");
        let client = connect(&Target::Unix(path.clone()), Duration::from_secs(5))
            .expect("connects a unix socket");
        // The socket file lives on by the listener's descriptor; drop the directory entry now so an interrupted run leaves nothing to unlink.
        std::fs::remove_dir_all(&dir).ok();
        (client, listener)
    }
}
