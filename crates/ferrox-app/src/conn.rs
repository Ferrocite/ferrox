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
//! The Unix arm is built on both host families that name a socket path in a config. On a Unix
//! host it is `std`'s `UnixStream`; on Windows `std` has the type but keeps it behind the
//! unstable `windows_unix_domain_sockets` feature, which a stable build cannot name, so there the
//! same arm is a `SOCK_STREAM` socket in the `AF_UNIX` family, opened and driven through
//! `WinSock` (`winunix` below) the way `std` drives its own sockets. What neither host gives for
//! free is carried by the seam: `std` has no timeout setter for a Unix stream at all, and
//! `WinSock` spells the wait bound in milliseconds rather than a `timeval`. The `SOCK_STREAM`
//! shape and the Windows 10 build 17063 floor are the ones `std`'s own Windows unix module names.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::time::Duration;

#[cfg(unix)]
use libc::{SO_RCVTIMEO, SO_SNDTIMEO};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(any(unix, windows))]
use std::path::PathBuf;
#[cfg(windows)]
use winunix::{
    get_socket_timeout, set_socket_timeout, unix_peek, UnixListener, UnixStream, SO_RCVTIMEO,
    SO_SNDTIMEO,
};

/// A live proxy connection: a TCP stream, that stream under a post-TLS write mask, or an
/// `AF_UNIX` stream on either host family, carried the same way. Every method forwards to
/// whichever it holds, so the relay, the carriers and the handshake never learn which family they
/// were handed.
#[derive(Debug)]
pub(crate) enum Connection {
    Tcp(TcpStream),
    Masked(Masked),
    /// The same stream with a flow's counters and policy above it; every read and write reaches
    /// the socket through the meter, and a clone shares the counters rather than starting new ones.
    Metered(Metered),
    /// A stream whose peer is the one a PROXY protocol header reported rather than the socket's
    /// own peer: reads and writes still reach the socket, but routing sees the reported source.
    Proxied {
        inner: Box<Connection>,
        peer: SocketAddr,
    },
    /// The level policy a flow's account names, above a stream that counts no bytes itself.
    Policied {
        inner: Box<Connection>,
        flow: crate::policy::Flow,
    },
    #[cfg(any(unix, windows))]
    Unix(UnixStream),
}

/// A connection under the stats manager: the inner stream keeps its family and mask, while the
/// meter counts each direction and carries the policy the flow's level names.
#[derive(Debug)]
pub(crate) struct Metered {
    inner: Box<Connection>,
    meter: crate::stats::Meter,
}

/// A TCP stream with the `finalmask` chain under it, which is what the reference's wrapped conn
/// is: reads, timeouts, addresses and teardown reach the socket itself and only writes pass through
/// the chain. The chain is shared behind a lock because a cloned handle must keep counting the same
/// writes, and because a relay leg holds its stream by shared reference.
#[derive(Debug)]
pub(crate) struct Masked {
    stream: TcpStream,
    chain: std::sync::Arc<std::sync::Mutex<ferrox_core::finalmask::Chain>>,
}

impl Masked {
    /// The chain's write over a shared handle: the socket side is `&TcpStream`, which `std` also
    /// makes a writer, so a leg drained by reference masks exactly as one moved by value.
    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // A stage never panics while held, so a poisoned lock is a broken process, not a wire state.
        let Ok(mut chain) = self.chain.lock() else {
            return Err(io::Error::other("the mask chain is gone"));
        };
        chain.write(&mut &self.stream, buf)
    }

    // A chain is a byte writer, so a gathered write answers its first run and the caller's loop hands the rest over as the write it would have been.
    fn send_vectored(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        bufs.first().map_or(Ok(0), |first| self.send(first))
    }
}

impl Connection {
    /// The same socket with this chain's clone beneath it; `None`, or a chain with no stage, leaves
    /// the stream exactly as it came, which is the ordinary case.
    pub(crate) fn with_mask(self, mask: Option<&ferrox_core::finalmask::Chain>) -> Self {
        match (self, mask.filter(|chain| !chain.is_empty())) {
            (Connection::Tcp(stream), Some(chain)) => Connection::Masked(Masked {
                stream,
                chain: std::sync::Arc::new(std::sync::Mutex::new(chain.clone())),
            }),
            (Connection::Metered(metered), mask) => Connection::Metered(Metered {
                inner: Box::new(metered.inner.with_mask(mask)),
                meter: metered.meter,
            }),
            (Connection::Proxied { inner, peer }, mask) => Connection::Proxied {
                inner: Box::new(inner.with_mask(mask)),
                peer,
            },
            (Connection::Policied { inner, flow }, mask) => Connection::Policied {
                inner: Box::new(inner.with_mask(mask)),
                flow,
            },
            (this, _) => this,
        }
    }

    /// The same stream with the peer a PROXY protocol header reported, which routing reads in
    /// place of the socket's own peer.
    pub(crate) fn with_peer(self, peer: SocketAddr) -> Self {
        Connection::Proxied {
            inner: Box::new(self),
            peer,
        }
    }

    /// Whether a write to this stream must pass the chain, which a descriptor-level fast path
    /// addressing the socket would skip. Reads, teardown and the census are unaffected by it.
    pub(crate) fn masked(&self) -> bool {
        match self {
            Connection::Masked(_) => true,
            Connection::Metered(metered) => metered.inner.masked(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.masked()
            }
            Connection::Tcp(_) => false,
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => false,
        }
    }

    /// Whether a descriptor-level fast path would skip the meter above this stream.
    pub(crate) fn metered(&self) -> bool {
        match self {
            Connection::Metered(metered) => metered.meter.counts(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.metered()
            }
            Connection::Masked(_) => false,
            Connection::Tcp(_) => false,
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => false,
        }
    }

    /// Put this flow's counters above the stream. A stream that already carries a meter keeps
    /// every counter and adds the newer one's, so the inbound and the account both count.
    pub(crate) fn with_meter(self, meter: crate::stats::Meter) -> Self {
        if meter.is_empty() {
            return self;
        }
        match self {
            Connection::Metered(metered) => Connection::Metered(Metered {
                inner: metered.inner,
                meter: metered.meter.merged(meter),
            }),
            inner => Connection::Metered(Metered {
                inner: Box::new(inner),
                meter,
            }),
        }
    }

    /// Put this flow's level policy above the stream without counting its bytes.
    pub(crate) fn with_policy(self, flow: Option<crate::policy::Flow>) -> Self {
        let Some(flow) = flow else {
            return self;
        };
        match self {
            Connection::Policied { inner, .. } => Connection::Policied { inner, flow },
            Connection::Proxied { inner, peer } => Connection::Proxied {
                inner: Box::new(inner.with_policy(Some(flow))),
                peer,
            },
            inner => Connection::Policied {
                inner: Box::new(inner),
                flow,
            },
        }
    }

    /// The policy a flow's level names, if one is above this stream.
    pub(crate) fn policy(&self) -> Option<crate::policy::Flow> {
        match self {
            Connection::Metered(metered) => metered.inner.policy(),
            Connection::Proxied { inner, .. } => inner.policy(),
            Connection::Policied { flow, .. } => Some(*flow),
            Connection::Masked(_) | Connection::Tcp(_) => None,
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => None,
        }
    }
}

impl From<TcpStream> for Connection {
    fn from(stream: TcpStream) -> Self {
        Connection::Tcp(stream)
    }
}

#[cfg(any(unix, windows))]
impl From<UnixStream> for Connection {
    fn from(stream: UnixStream) -> Self {
        Connection::Unix(stream)
    }
}

/// The raw descriptor the vectored-write and splice fast paths address. Every arm is a socket, so
/// `writev`/`splice` reach the queue identically and a masked stream answers with the socket its
/// chain writes through; those paths are `#[cfg(target_os = "linux")]`, `AsRawFd` is their Unix
/// spelling, and the `AF_UNIX` arm answers with the same descriptor its reads and writes go to.
#[cfg(unix)]
impl std::os::fd::AsRawFd for Connection {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        match self {
            Connection::Tcp(stream) => stream.as_raw_fd(),
            Connection::Masked(masked) => masked.stream.as_raw_fd(),
            Connection::Metered(metered) => metered.inner.as_raw_fd(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.as_raw_fd()
            }
            Connection::Unix(stream) => stream.as_raw_fd(),
        }
    }
}

/// The same descriptor under the Windows spelling, so `census::handle` reads a `Connection` the
/// way it reads a `TcpStream` there. Every Windows arm is a `WinSock` socket — a `SOCK_STREAM` in
/// the `AF_UNIX` family is still a `SOCKET` — so this forwards whichever handle the leg holds. The
/// census only names it, so no TCP-only query is ever issued against the unix arm.
#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for Connection {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        match self {
            Connection::Tcp(stream) => stream.as_raw_socket(),
            Connection::Masked(masked) => masked.stream.as_raw_socket(),
            Connection::Metered(metered) => metered.inner.as_raw_socket(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.as_raw_socket()
            }
            Connection::Unix(stream) => stream.as_raw_socket(),
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
            Connection::Masked(masked) => masked.stream.read(buf),
            Connection::Metered(metered) => {
                let n = metered.inner.read(buf)?;
                metered.meter.read(n);
                Ok(n)
            }
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.read(buf)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.read(buf),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.read_vectored(bufs),
            Connection::Masked(masked) => masked.stream.read_vectored(bufs),
            Connection::Metered(metered) => {
                let n = metered.inner.read_vectored(bufs)?;
                metered.meter.read(n);
                Ok(n)
            }
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.read_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.read_vectored(bufs),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.write(buf),
            Connection::Masked(masked) => masked.send(buf),
            Connection::Metered(metered) => {
                let n = metered.inner.write(buf)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.write(buf)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.write(buf),
        }
    }

    // One `writev` for a frame's parts on either family; `write_vectored` is `writev` on a socket, so the TCP coalescing is the same call, not a relocation.
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.write_vectored(bufs),
            Connection::Masked(masked) => masked.send_vectored(bufs),
            Connection::Metered(metered) => {
                let n = metered.inner.write_vectored(bufs)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.write_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.write_vectored(bufs),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.flush(),
            Connection::Masked(masked) => masked.stream.flush(),
            Connection::Metered(metered) => metered.inner.flush(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => inner.flush(),
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.flush(),
        }
    }
}

// A socket answers on a shared descriptor, so `std` impls `Read`/`Write` for `&TcpStream` and the relay drains each leg by shared reference; `&Connection` does the same for whichever arm it holds, and a masked leg's writes reach its chain the same way.
impl Read for &Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.read(buf)
            }
            Connection::Masked(masked) => {
                let mut inner = &masked.stream;
                inner.read(buf)
            }
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                let n = inner.read(buf)?;
                metered.meter.read(n);
                Ok(n)
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.read(buf)
            }
            #[cfg(any(unix, windows))]
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
            Connection::Masked(masked) => {
                let mut inner = &masked.stream;
                inner.read_vectored(bufs)
            }
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                let n = inner.read_vectored(bufs)?;
                metered.meter.read(n);
                Ok(n)
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.read_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
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
            Connection::Masked(masked) => masked.send(buf),
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                let n = inner.write(buf)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.write(buf)
            }
            #[cfg(any(unix, windows))]
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
            Connection::Masked(masked) => masked.send_vectored(bufs),
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                let n = inner.write_vectored(bufs)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.write_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
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
            Connection::Masked(masked) => {
                let mut inner = &masked.stream;
                inner.flush()
            }
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                inner.flush()
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.flush()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.flush()
            }
        }
    }
}

impl Connection {
    /// A second handle to the same socket, so a relay reads on one leg and writes on the other. A
    /// masked handle shares its chain rather than starting a fresh one, because the reference's
    /// wrapped conn counts writes once per connection, not once per handle.
    pub(crate) fn try_clone(&self) -> io::Result<Connection> {
        match self {
            Connection::Tcp(stream) => stream.try_clone().map(Connection::Tcp),
            Connection::Masked(masked) => masked.stream.try_clone().map(|stream| {
                Connection::Masked(Masked {
                    stream,
                    chain: std::sync::Arc::clone(&masked.chain),
                })
            }),
            Connection::Metered(metered) => metered.inner.try_clone().map(|inner| {
                Connection::Metered(Metered {
                    inner: Box::new(inner),
                    meter: metered.meter.clone(),
                })
            }),
            Connection::Proxied { inner, peer } => {
                inner.try_clone().map(|inner| Connection::Proxied {
                    inner: Box::new(inner),
                    peer: *peer,
                })
            }
            Connection::Policied { inner, flow } => {
                inner.try_clone().map(|inner| Connection::Policied {
                    inner: Box::new(inner),
                    flow: *flow,
                })
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.try_clone().map(Connection::Unix),
        }
    }

    /// Which direction of the full-duplex connection to tear down: the relay's half-close edge.
    pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.shutdown(how),
            Connection::Masked(masked) => masked.stream.shutdown(how),
            Connection::Metered(metered) => metered.inner.shutdown(how),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.shutdown(how)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.shutdown(how),
        }
    }

    /// Look ahead without consuming, the way the HTTP-head readers prove a head before taking
    /// it. TCP has `peek`; `std`'s `UnixStream::peek` is unstable, so the Unix arm issues the
    /// same `recv(MSG_PEEK)` the kernel serves under the hood.
    pub(crate) fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.peek(buf),
            Connection::Masked(masked) => masked.stream.peek(buf),
            Connection::Metered(metered) => metered.inner.peek(buf),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.peek(buf)
            }
            #[cfg(any(unix, windows))]
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
            Connection::Masked(masked) => masked.stream.peer_addr(),
            Connection::Metered(metered) => metered.inner.peer_addr(),
            Connection::Proxied { peer, .. } => Ok(*peer),
            Connection::Policied { inner, .. } => inner.peer_addr(),
            #[cfg(any(unix, windows))]
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
            Connection::Masked(masked) => masked.stream.local_addr(),
            Connection::Metered(metered) => metered.inner.local_addr(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.local_addr()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream reports no local address",
            )),
        }
    }

    /// Switch the socket's blocking mode, the readiness seam's one socket-shape change: a
    /// duplicate shares the descriptor's status flags, so the relay restores it when the flow ends.
    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_nonblocking(nonblocking),
            Connection::Masked(masked) => masked.stream.set_nonblocking(nonblocking),
            Connection::Metered(metered) => metered.inner.set_nonblocking(nonblocking),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_nonblocking(nonblocking)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.set_nonblocking(nonblocking),
        }
    }

    /// Arm the read side's wait bound. TCP uses `SO_RCVTIMEO`; on a Unix stream `std` omits the
    /// setter, so the same `timeval` goes through `setsockopt` at `SOL_SOCKET`, the level that
    /// carries it for `AF_UNIX` too. `None` clears the bound and lets the read block.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_read_timeout(timeout),
            Connection::Masked(masked) => masked.stream.set_read_timeout(timeout),
            Connection::Metered(metered) => metered.inner.set_read_timeout(timeout),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_read_timeout(timeout)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => set_socket_timeout(stream, SO_RCVTIMEO, timeout),
        }
    }

    /// Arm the write side's wait bound, mirroring `set_read_timeout` on `SO_SNDTIMEO`.
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_write_timeout(timeout),
            Connection::Masked(masked) => masked.stream.set_write_timeout(timeout),
            Connection::Metered(metered) => metered.inner.set_write_timeout(timeout),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_write_timeout(timeout)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => set_socket_timeout(stream, SO_SNDTIMEO, timeout),
        }
    }

    /// Read back the armed wait bound, so a caller can save and restore it around a stage that
    /// tightens it. TCP asks `std`; a Unix stream reads the same `SO_RCVTIMEO`/`SO_SNDTIMEO`
    /// `timeval` back through `getsockopt`, so the save/restore is as exact as the set was.
    pub(crate) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            Connection::Tcp(stream) => stream.read_timeout(),
            Connection::Masked(masked) => masked.stream.read_timeout(),
            Connection::Metered(metered) => metered.inner.read_timeout(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.read_timeout()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => get_socket_timeout(stream, SO_RCVTIMEO),
        }
    }

    /// Turn Nagle off, matching `TcpStream::set_nodelay(bool)` so the `no_delay` wrapper's call
    /// is unchanged. Meaningful only on TCP; a Unix stream needs no analogue — there is no
    /// internetwork to delay on — so the request is accepted and does nothing rather than
    /// failing, which is why a caller keeps calling it uniformly on either family.
    pub(crate) fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_nodelay(nodelay),
            Connection::Masked(masked) => masked.stream.set_nodelay(nodelay),
            Connection::Metered(metered) => metered.inner.set_nodelay(nodelay),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_nodelay(nodelay)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Ok(()),
        }
    }

    /// Wait for this socket to have something to read, without taking a byte or blocking the
    /// caller's own reads: a relay leg parks here so it can hold nothing while it waits. `Ok(true)`
    /// is readiness, the peer's end included, which the next read then reports; `Ok(false)` is the
    /// wait expiring. `#[cfg(unix)]` spelling: one `poll` row.
    #[cfg(unix)]
    pub(crate) fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut row = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one descriptor this leg holds, one element in the array, and the call writes only `revents`.
            let ready = unsafe { libc::poll(&raw mut row, 1, millis) };
            if ready > 0 {
                return Ok(row.revents != 0);
            }
            if ready == 0 {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// The Windows spelling of the same wait: one `WSAPoll` row, whose error code comes from
    /// `WSAGetLastError` rather than the process error slot.
    #[cfg(windows)]
    pub(crate) fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            WSAGetLastError, WSAPoll, POLLERR, POLLHUP, POLLIN, POLLRDNORM, SOCKET, WSAPOLLFD,
        };
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut row = WSAPOLLFD {
            fd: self.as_raw_socket() as SOCKET,
            events: POLLIN | POLLRDNORM,
            revents: 0,
        };
        // SAFETY: one handle this leg holds and one element the call writes `revents` into.
        let ready = unsafe { WSAPoll(&raw mut row, 1, millis) };
        if ready < 0 {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        let readable = POLLIN | POLLRDNORM | POLLHUP | POLLERR;
        Ok(ready > 0 && row.revents & readable != 0)
    }
}

/// Read the PROXY protocol header a listener's `acceptProxyProtocol` promised. A v1 text line or
/// a v2 binary header is consumed in full and the source address it reports is returned; `None`
/// means the header is valid but names no IP source (`UNKNOWN`, `LOCAL`, or a Unix/unspecified
/// family), so the socket's own peer stays the source. A malformed or truncated header is an
/// error, and the caller closes the connection rather than letting carrier bytes stand in for it.
pub(crate) fn read_proxy_header(stream: &mut Connection) -> io::Result<Option<SocketAddr>> {
    const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
    let mut first = [0u8; 12];
    stream.read_exact(&mut first)?;
    if &first[..6] == b"PROXY " {
        let mut line = [0u8; 108];
        line[..12].copy_from_slice(&first);
        let mut len = 12;
        while len < line.len() {
            if len >= 2 && &line[len - 2..len] == b"\r\n" {
                break;
            }
            stream.read_exact(&mut line[len..=len])?;
            len += 1;
        }
        if len < 2 || &line[len - 2..len] != b"\r\n" {
            return Err(bad_proxy(
                "the PROXY v1 line is longer than the protocol allows",
            ));
        }
        return parse_proxy_v1(&line[..len]);
    }
    if first != V2_SIGNATURE {
        return Err(bad_proxy(
            "the connection does not start with a PROXY header",
        ));
    }
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] >> 4 != 2 {
        return Err(bad_proxy("the PROXY v2 header names another version"));
    }
    let command = head[0] & 0x0f;
    let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    if command == 0 {
        return Ok(None);
    }
    if command != 1 {
        return Err(bad_proxy("the PROXY v2 header names an unknown command"));
    }
    let family = head[1] >> 4;
    match family {
        0 | 3 => Ok(None),
        1 if body.len() >= 12 => {
            let source = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(Some(SocketAddr::from((source, port))))
        }
        2 if body.len() >= 36 => {
            let mut source = [0u8; 16];
            source.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(Some(SocketAddr::from((
                std::net::Ipv6Addr::from(source),
                port,
            ))))
        }
        _ => Err(bad_proxy(
            "the PROXY v2 header is shorter than its family needs",
        )),
    }
}

fn parse_proxy_v1(line: &[u8]) -> io::Result<Option<SocketAddr>> {
    let text = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|_| bad_proxy("the PROXY v1 line is not UTF-8"))?;
    let mut fields = text.split(' ');
    if fields.next() != Some("PROXY") {
        return Err(bad_proxy("the PROXY v1 line has no PROXY prefix"));
    }
    let family = fields
        .next()
        .ok_or_else(|| bad_proxy("the PROXY v1 line names no family"))?;
    if family == "UNKNOWN" {
        return Ok(None);
    }
    if family != "TCP4" && family != "TCP6" {
        return Err(bad_proxy("the PROXY v1 line names an unknown family"));
    }
    let source = fields
        .next()
        .and_then(|field| field.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| bad_proxy("the PROXY v1 line has no source address"))?;
    let destination = fields
        .next()
        .and_then(|field| field.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| bad_proxy("the PROXY v1 line has no destination address"))?;
    let source_port = fields
        .next()
        .and_then(|field| field.parse::<u16>().ok())
        .ok_or_else(|| bad_proxy("the PROXY v1 line has no source port"))?;
    if fields
        .next()
        .and_then(|field| field.parse::<u16>().ok())
        .is_none()
    {
        return Err(bad_proxy("the PROXY v1 line has no destination port"));
    }
    if fields.next().is_some() {
        return Err(bad_proxy("the PROXY v1 line carries extra fields"));
    }
    if (family == "TCP4") != source.is_ipv4() || (family == "TCP4") != destination.is_ipv4() {
        return Err(bad_proxy(
            "the PROXY v1 line's family does not match its addresses",
        ));
    }
    Ok(Some(SocketAddr::new(source, source_port)))
}

fn bad_proxy(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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
        // `suseconds_t` is `i32` on macOS, where this conversion can fail, and `i64` on Linux, where it cannot.
        #[allow(clippy::unnecessary_fallible_conversions)]
        let usec: libc::suseconds_t = timeout.subsec_micros().try_into().unwrap_or(0);
        value.tv_usec = usec;
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

/// Where a proxy connection goes: an IP address and port, or the path of an `AF_UNIX` socket,
/// which either host family serves. The dial role needs both because a config naming
/// `unix:/path/sock` is not a `SocketAddr`, and the address is what picks the family before
/// anything is dialed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Ip(SocketAddr),
    #[cfg(any(unix, windows))]
    Unix(PathBuf),
}

/// Parse a listen or dial address into a `Target`. A leading `unix:` (the spelling the
/// references use for a socket path) names an `AF_UNIX` stream, on either host; anything else
/// resolves as an address, so every `ip:port` caller keeps its behavior untouched. An empty
/// path after the prefix is refused rather than dialed at the filesystem root.
pub(crate) fn parse_target(address: &str) -> io::Result<Target> {
    #[cfg(any(unix, windows))]
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
    #[cfg(any(unix, windows))]
    Unix(UnixListener),
}

impl Listener {
    /// Bind a listener for the target's family. A Unix path left from a previous run is unlinked
    /// first: binding over an existing socket file fails `EADDRINUSE`, and a stale socket nobody
    /// owns is exactly that — the same unlink-then-bind recovery the references do.
    pub(crate) fn bind(target: &Target) -> io::Result<Listener> {
        match target {
            Target::Ip(addr) => std::net::TcpListener::bind(addr).map(Listener::Tcp),
            #[cfg(any(unix, windows))]
            Target::Unix(path) => {
                if std::fs::symlink_metadata(path).is_ok() {
                    std::fs::remove_file(path)?;
                }
                UnixListener::bind(path).map(Listener::Unix)
            }
        }
    }

    /// The socket address a TCP listener holds. A Unix listener has no port to report, so it
    /// answers the error a caller expecting an ephemeral TCP port would get from no bind.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Listener::Tcp(listener) => listener.local_addr(),
            #[cfg(any(unix, windows))]
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
            #[cfg(any(unix, windows))]
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
            Connection::Masked(masked) => masked.stream.nodelay(),
            Connection::Metered(metered) => metered.inner.nodelay(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.nodelay()
            }
            #[cfg(any(unix, windows))]
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
            #[cfg(any(unix, windows))]
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
            #[cfg(any(unix, windows))]
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
        #[cfg(any(unix, windows))]
        Target::Unix(path) => UnixStream::connect(path).map(Connection::Unix),
    }
}

/// The seam's `AF_UNIX` arm on the host whose `std` keeps `UnixStream` behind the unstable
/// `windows_unix_domain_sockets` feature, so a stable build cannot name the type. Windows serves
/// the family from build 17063 as a `SOCK_STREAM` socket through `WinSock` — the shape and the
/// floor `std`'s own Windows unix module names — and this module is the part `std` would be
/// writing for itself: open, dial, bind, accept, the four `Read`/`Write` shapes, and the wait
/// bounds `std` has setters for on TCP and none for a unix stream.
///
/// What the seam refuses it refuses rather than papers over: an address query answers
/// `Unsupported` because a socket path has no port to name, on either host, and `try_clone` shares
/// the one handle behind an `Arc` instead of calling `WSADuplicateSocket`, so no leg depends on
/// what the provider serves for this family. That is the same lifetime a `dup`ed descriptor pair
/// has on Unix — the relay's two legs reach one socket, and the last drop closes it.
#[cfg(windows)]
mod winunix {
    use std::io::{self, IoSlice, IoSliceMut, Read, Write};
    use std::net::Shutdown;
    #[cfg(test)]
    use std::net::SocketAddr;
    use std::os::windows::io::{AsRawSocket, RawSocket};
    use std::path::Path;
    use std::ptr::null_mut;
    use std::sync::{Arc, Once};
    use std::time::Duration;
    use windows_sys::Win32::Networking::WinSock::{
        accept, bind, closesocket, connect, getsockopt, listen, recv, send, setsockopt, shutdown,
        socket, WSAGetLastError, WSARecv, WSASend, WSAStartup, AF_UNIX, INVALID_SOCKET, MSG_PEEK,
        SD_BOTH, SD_RECEIVE, SD_SEND, SOCKADDR, SOCKADDR_UN, SOCKET, SOCKET_ERROR, SOCK_STREAM,
        SOL_SOCKET, WSABUF, WSADATA, WSAESHUTDOWN,
    };
    use windows_sys::Win32::Networking::WinSock::{ioctlsocket, FIONBIO};

    pub(crate) use windows_sys::Win32::Networking::WinSock::{SO_RCVTIMEO, SO_SNDTIMEO};

    /// The run of buffers one `WSASend`/`WSARecv` is offered. The frame writer's part cap is wider,
    /// and parts past this go out on the next turn of its loop, so nothing is dropped by the clamp.
    const VECTORS: usize = 16;

    /// One `WinSock` socket, closed when the last leg holding it drops.
    #[derive(Debug)]
    struct Handle(SOCKET);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: this is the handle's own socket and `closesocket` is its free.
            unsafe { closesocket(self.0) };
        }
    }

    // A socket handle names a kernel object every thread can reach, and WinSock serializes the calls made on it — which is what a relay's two legs do with one connection.
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}

    /// `WinSock` has to be opened before a call reaches it, and `std` does that only for its own
    /// sockets, so this arm asks for itself once. The version is the one `std` requests, and no
    /// `WSACleanup` follows: the process that owns a leg outlives it.
    fn startup() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // SAFETY: `data` is a live `WSADATA`, sized as the library writes it.
            let mut data: WSADATA = unsafe { std::mem::zeroed() };
            let code = unsafe { WSAStartup(0x0202, &raw mut data) };
            assert_eq!(code, 0, "winsock will not start");
        });
    }

    /// A refused call as the `io::Error` `std` gives for the same code: `WSAGetLastError` is the
    /// provider's answer, and `from_raw_os_error` maps the WSA codes onto the kinds the relay reads.
    fn last_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    /// The socket address a path names: `AF_UNIX` then the path's bytes, NUL-terminated inside the
    /// field, with the length the provider reads being the family plus those bytes. An address here
    /// is always a named path — the arm has no autobind or abstract-namespace spelling — so an empty
    /// one is refused rather than bound at nothing.
    fn address(path: &Path) -> io::Result<(SOCKADDR_UN, i32)> {
        let text = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a unix path is not utf-8 on windows",
            )
        })?;
        let bytes = text.as_bytes();
        let field = std::mem::offset_of!(SOCKADDR_UN, sun_path);
        if bytes.is_empty() || bytes.len() + 1 > std::mem::size_of::<SOCKADDR_UN>() - field {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a unix path does not fit a socket address",
            ));
        }
        // SAFETY: an all-zero `SOCKADDR_UN` is a valid address with an empty path and a zero length.
        let mut addr: SOCKADDR_UN = unsafe { std::mem::zeroed() };
        addr.sun_family = AF_UNIX;
        for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as i8;
        }
        Ok((
            addr,
            i32::try_from(field + bytes.len() + 1).unwrap_or(i32::MAX),
        ))
    }

    /// A `SOCK_STREAM` socket in the `AF_UNIX` family — the shape `std`'s own Windows unix
    /// module opens, and the only one this seam needs.
    fn open() -> io::Result<Handle> {
        startup();
        // SAFETY: the family and type are WinSock's own constants and no buffer is touched.
        let handle = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        if handle == INVALID_SOCKET {
            return Err(last_error());
        }
        Ok(Handle(handle))
    }

    /// One `recv`, peeking or not: a zero return is the peer's EOF, an interrupted call is retried,
    /// and `WSAESHUTDOWN` — the code for a socket this side already shut down for reading — answers
    /// that same clean end, so a leg reading past its own shutdown stops instead of erroring.
    fn receive(socket: SOCKET, buf: &mut [u8], flags: i32) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // A run wider than the count the call names is clamped to it, never wrapped around.
            let asked = i32::try_from(buf.len()).unwrap_or(i32::MAX);
            // SAFETY: `buf` is a live slice of `asked` writable bytes on this socket.
            let read = unsafe { recv(socket, buf.as_mut_ptr(), asked, flags) };
            if read >= 0 {
                return Ok(read as usize);
            }
            let error = last_error();
            if error.raw_os_error() == Some(WSAESHUTDOWN) {
                return Ok(0);
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// One `send`, returning how much of the buffer the queue took; the caller's loop writes the rest.
    fn transmit(socket: SOCKET, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // A run wider than the count the call names is clamped to it, never wrapped around.
            let asked = i32::try_from(buf.len()).unwrap_or(i32::MAX);
            // SAFETY: `buf` is a live slice of readable bytes; `send` only reads `asked` of them.
            let sent = unsafe { send(socket, buf.as_ptr(), asked, 0) };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = last_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// The gathered half of a vectored call: the runs the caller handed, as the `WSABUF` array
    /// `WinSock` reads, clamped to `VECTORS` so the provider is never offered more buffers than the
    /// loop is prepared to retry.
    fn gather(bufs: &[IoSlice<'_>]) -> ([WSABUF; VECTORS], u32) {
        let mut array = [WSABUF {
            len: 0,
            buf: null_mut(),
        }; VECTORS];
        for (slot, part) in array.iter_mut().zip(bufs) {
            slot.len = part.len().min(u32::MAX as usize) as u32;
            // WinSock declares a `WSABUF`'s buffer mutable for a send too; the call only reads it.
            slot.buf = part.as_ptr().cast_mut();
        }
        (array, bufs.len().min(VECTORS) as u32)
    }

    /// The same array for a receive, whose runs the caller owns mutably.
    fn gather_mut(bufs: &mut [IoSliceMut<'_>]) -> ([WSABUF; VECTORS], u32) {
        let mut array = [WSABUF {
            len: 0,
            buf: null_mut(),
        }; VECTORS];
        let count = bufs.len().min(VECTORS) as u32;
        for (slot, part) in array.iter_mut().zip(bufs) {
            slot.len = part.len().min(u32::MAX as usize) as u32;
            slot.buf = part.as_mut_ptr();
        }
        (array, count)
    }

    /// A connected `AF_UNIX` stream.
    #[derive(Debug)]
    pub(crate) struct UnixStream {
        socket: Arc<Handle>,
    }

    impl UnixStream {
        /// Dial a socket path. A local connect answers at once — `ENOENT` for no listener, a refused
        /// code for one that will not take it — so there is no retransmission to bound with a timeout.
        pub(crate) fn connect(path: &Path) -> io::Result<UnixStream> {
            let (addr, len) = address(path)?;
            let handle = open()?;
            // SAFETY: `addr` is a live socket address of `len` bytes; `connect` neither keeps nor writes it.
            if unsafe { connect(handle.0, (&raw const addr).cast::<SOCKADDR>(), len) }
                == SOCKET_ERROR
            {
                return Err(last_error());
            }
            Ok(UnixStream {
                socket: Arc::new(handle),
            })
        }

        /// The other leg of the same socket: the handle is shared behind the `Arc`, not
        /// duplicated, so the last leg to drop closes it — the lifetime a `dup`ed unix
        /// descriptor has.
        #[allow(
            clippy::unnecessary_wraps,
            reason = "the seam matches one fallible clone signature"
        )]
        pub(crate) fn try_clone(&self) -> io::Result<UnixStream> {
            Ok(UnixStream {
                socket: Arc::clone(&self.socket),
            })
        }

        /// Which direction of the full-duplex stream to tear down.
        pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            let how = match how {
                Shutdown::Write => SD_SEND,
                Shutdown::Read => SD_RECEIVE,
                Shutdown::Both => SD_BOTH,
            };
            // SAFETY: this is the stream's own socket and `how` is one of WinSock's three directions.
            if unsafe { shutdown(self.socket.0, how) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(())
        }

        /// Switch the socket's blocking mode; every leg shares the one handle, so the flags
        /// change for the relay's duplicates together and are restored together.
        pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            // SAFETY: `mode` is the one `u32` flag `FIONBIO` reads, on this socket.
            let mut mode = u32::from(nonblocking);
            if unsafe { ioctlsocket(self.socket.0, FIONBIO, &raw mut mode) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(())
        }
    }

    impl AsRawSocket for UnixStream {
        fn as_raw_socket(&self) -> RawSocket {
            self.socket.0 as RawSocket
        }
    }

    impl Read for &UnixStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            receive(self.socket.0, buf, 0)
        }

        // One `WSARecv` for the whole run, the call that stands in for `readv` here.
        fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
            if bufs.is_empty() {
                return Ok(0);
            }
            let (array, count) = gather_mut(bufs);
            loop {
                let mut received = 0u32;
                let mut flags = 0u32;
                // SAFETY: `array` describes the caller's runs, live for the call; a blocking socket takes no overlapped or completion routine, and `flags` is the reserved zero WinSock requires.
                let code = unsafe {
                    WSARecv(
                        self.socket.0,
                        array.as_ptr(),
                        count,
                        &raw mut received,
                        &raw mut flags,
                        null_mut(),
                        None,
                    )
                };
                if code == SOCKET_ERROR {
                    let error = last_error();
                    if error.raw_os_error() == Some(WSAESHUTDOWN) {
                        return Ok(0);
                    }
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                    continue;
                }
                return Ok(received as usize);
            }
        }
    }

    impl Write for &UnixStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            transmit(self.socket.0, buf)
        }

        // One `WSASend` for a frame's parts, so the coalescing the TCP path does with `writev` is the same single call here, not a relocation into one buffer per part.
        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            if bufs.is_empty() {
                return Ok(0);
            }
            let (array, count) = gather(bufs);
            loop {
                let mut sent = 0u32;
                // SAFETY: `array` describes the caller's buffers, live and read-only for the call; a blocking socket takes no overlapped or completion routine.
                let code = unsafe {
                    WSASend(
                        self.socket.0,
                        array.as_ptr(),
                        count,
                        &raw mut sent,
                        0,
                        null_mut(),
                        None,
                    )
                };
                if code == SOCKET_ERROR {
                    let error = last_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                    continue;
                }
                return Ok(sent as usize);
            }
        }

        // A socket queue has no user-space buffer to push.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for UnixStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.read(buf)
        }

        fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.read_vectored(bufs)
        }
    }

    impl Write for UnixStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.write(buf)
        }

        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.write_vectored(bufs)
        }

        fn flush(&mut self) -> io::Result<()> {
            let mut inner = &*self;
            inner.flush()
        }
    }

    /// A bound `AF_UNIX` socket file. The file outlives the descriptor that made it, which is why
    /// `Listener::bind` unlinks before binding instead of trusting the path to be free.
    #[derive(Debug)]
    pub(crate) struct UnixListener {
        socket: Arc<Handle>,
    }

    impl UnixListener {
        /// Bind a path and queue for it. `windows-sys` names `SOMAXCONN` as `5`, not the
        /// `0x7fffffff` that `WinSock` means by it, so the deepest queue the provider will read is
        /// asked for by number.
        pub(crate) fn bind(path: &Path) -> io::Result<UnixListener> {
            let (addr, len) = address(path)?;
            let handle = open()?;
            // SAFETY: `addr` is a live socket address of `len` bytes; `bind` neither keeps nor writes it.
            if unsafe { bind(handle.0, (&raw const addr).cast::<SOCKADDR>(), len) } == SOCKET_ERROR
            {
                return Err(last_error());
            }
            // SAFETY: this is the socket the bind above just took.
            if unsafe { listen(handle.0, 0x7fff_ffff) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(UnixListener {
                socket: Arc::new(handle),
            })
        }

        /// The next peer. The seam reports no address for a unix leg on either host, so the tuple's
        /// second half is the zero address `std`'s unix accept hands back for a path that names no
        /// port.
        #[cfg(test)]
        pub(crate) fn accept(&self) -> io::Result<(UnixStream, SocketAddr)> {
            self.accept_one()
                .map(|stream| (stream, SocketAddr::from(([0, 0, 0, 0], 0))))
        }

        /// One accepted socket, with an interrupted accept retried the way `std` retries it.
        fn accept_one(&self) -> io::Result<UnixStream> {
            loop {
                // SAFETY: no peer address is asked for — the seam has no use for one — so both out-params are null.
                let handle = unsafe { accept(self.socket.0, null_mut(), null_mut()) };
                if handle == INVALID_SOCKET {
                    let error = last_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                    continue;
                }
                return Ok(UnixStream {
                    socket: Arc::new(Handle(handle)),
                });
            }
        }

        pub(crate) fn incoming(&self) -> Incoming<'_> {
            Incoming { listener: self }
        }

        #[cfg(test)]
        pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            // SAFETY: `mode` is the one `u32` flag `FIONBIO` reads, on this socket.
            let mut mode = u32::from(nonblocking);
            if unsafe { ioctlsocket(self.socket.0, FIONBIO, &raw mut mode) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(())
        }
    }

    /// The accepted connections of a `UnixListener`.
    pub(crate) struct Incoming<'a> {
        listener: &'a UnixListener,
    }

    impl Iterator for Incoming<'_> {
        type Item = io::Result<UnixStream>;

        fn next(&mut self) -> Option<Self::Item> {
            Some(self.listener.accept_one())
        }
    }

    /// Arm the wait bound the way `WinSock` spells it: one `DWORD` of milliseconds, where `None` is no
    /// bound and a zero `Duration` is the invalid value `std` refuses on TCP too.
    pub(crate) fn set_socket_timeout(
        stream: &UnixStream,
        option: i32,
        timeout: Option<Duration>,
    ) -> io::Result<()> {
        let millis = match timeout {
            None => 0,
            Some(timeout) => {
                let millis = u32::try_from(timeout.as_millis())
                    .map_err(|_| invalid("a unix timeout is past its bounds"))?;
                if millis == 0 {
                    return Err(invalid("a unix timeout is zero"));
                }
                millis
            }
        };
        let bytes = i32::try_from(std::mem::size_of::<u32>()).unwrap_or(i32::MAX);
        // SAFETY: `millis` is a live `DWORD`, sized as WinSock reads the option, on the stream's own socket.
        let code = unsafe {
            setsockopt(
                stream.socket.0,
                SOL_SOCKET,
                option,
                (&raw const millis).cast::<u8>(),
                bytes,
            )
        };
        if code == SOCKET_ERROR {
            return Err(last_error());
        }
        Ok(())
    }

    /// The bound read back: zero is no bound, exactly as `std` reports for a TCP socket on Windows,
    /// so a save/restore of the budget is as exact here as the set was.
    pub(crate) fn get_socket_timeout(
        stream: &UnixStream,
        option: i32,
    ) -> io::Result<Option<Duration>> {
        let mut millis: u32 = 0;
        let mut len = i32::try_from(std::mem::size_of::<u32>()).unwrap_or(i32::MAX);
        // SAFETY: `millis` and `len` are writable and sized as WinSock writes the option, on the stream's own socket.
        let code = unsafe {
            getsockopt(
                stream.socket.0,
                SOL_SOCKET,
                option,
                (&raw mut millis).cast::<u8>(),
                &raw mut len,
            )
        };
        if code == SOCKET_ERROR {
            return Err(last_error());
        }
        if millis == 0 {
            return Ok(None);
        }
        Ok(Some(Duration::from_millis(u64::from(millis))))
    }

    /// A unix `peek`: the same `recv` a `TcpStream::peek` is built on, with `MSG_PEEK` leaving the
    /// queue whole.
    pub(crate) fn unix_peek(stream: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
        receive(stream.socket.0, buf, MSG_PEEK)
    }

    fn invalid(reason: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, reason)
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    #[test]
    fn a_policy_without_counters_does_not_forbid_the_splice_path() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connects");
        let (server, _) = listener.accept().expect("accepts");
        let stream = Connection::Tcp(server).with_policy(Some(crate::policy::flow(0)));
        assert!(stream.policy().is_some());
        assert!(!stream.metered());
        drop(client);
    }

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
    /// bounds would park forever on unix while failing on tcp — the budget-parity claim. The bound
    /// read back is what either family can witness; that it then stops the block is proven where a
    /// refusal fails fast instead of parking the suite: a provider that ignored the option would
    /// hang this test, not fail it.
    #[test]
    fn a_unix_read_timeout_arms_the_way_the_tcp_one_does() {
        let (_client, listener) = unix_pair();
        let server = listener.incoming().next().unwrap().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("arms a read timeout on a unix stream");
        assert_eq!(
            server.read_timeout().expect("reads the bound back"),
            Some(Duration::from_millis(50)),
            "a unix stream reports the bound it was given"
        );
        #[cfg(unix)]
        match server {
            Connection::Unix(mut reader) => {
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
            Connection::Tcp(_)
            | Connection::Masked(_)
            | Connection::Metered(_)
            | Connection::Proxied { .. }
            | Connection::Policied { .. } => {
                unreachable!("a unix pair yields a unix stream")
            }
        }
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

    /// The path field of a socket address is a fixed array on every host — 108 bytes on Linux and
    /// Windows, 104 on macOS — so a name past it is refused, never truncated into a prefix of
    /// itself. The same directory holds the short path that does bind, so the refusal is about the
    /// length and not about where it lives.
    #[test]
    fn a_unix_path_past_the_socket_field_is_refused() {
        let dir = std::env::temp_dir();
        let short = dir.join(format!("ferrox-unix-len-{}", std::process::id()));
        let listener = Listener::bind(&Target::Unix(short.clone()))
            .expect("a path inside the field binds in the same directory");
        drop(listener);
        std::fs::remove_file(&short).ok();
        let long = dir.join("a".repeat(200));
        assert!(
            Listener::bind(&Target::Unix(long)).is_err(),
            "a path past the socket address field is refused, not truncated and bound"
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
