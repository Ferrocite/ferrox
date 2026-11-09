//! HTTP/3 over QUIC for the CDN-fronted meek entries that carry QUIC.

use crate::psiphon_webrtc::WebRtcStream;
use quiche::h3::NameValue as _;
use std::io;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAX_DATAGRAM: usize = 1350;
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
/// How long a handshake still waits for a real datagram after an ICMP error.
/// A refused front is skipped quickly, but a stale ICMP must not kill a
/// connection whose `ServerHello` is already in flight.
const DEAD_FRONT_GRACE: Duration = Duration::from_millis(500);
/// The pause between receives while an ICMP error is being confirmed, so a
/// socket that keeps reporting the same error cannot spin the loop.
const DEAD_FRONT_POLL: Duration = Duration::from_millis(10);

/// One HTTP/3 response.
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

/// What one datagram receive reported when it returned no datagram.
enum ReceiveError {
    /// The read timeout elapsed; QUIC's own timer must be driven.
    Timeout,
    /// A connected UDP socket reported an ICMP error for its peer. The front
    /// is a dead candidate, but a real datagram can still be in flight.
    DeadFront(io::Error),
    /// A genuine socket failure still aborts this dial.
    Fatal(io::Error),
}

/// Classify a receive error the way both the handshake and response loops
/// must treat it. A connected UDP socket reports an ICMP port-unreachable as
/// `ConnectionRefused`; ending the relay there leaves the front rotation with
/// nothing to rotate to.
fn classify_receive(error: io::Error) -> ReceiveError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ReceiveError::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => ReceiveError::DeadFront(error),
        _ => ReceiveError::Fatal(error),
    }
}

/// The short window in which one ICMP report is allowed to be stale.
#[derive(Default)]
struct DeadFront(Option<(Instant, String)>);

impl DeadFront {
    /// Fold a receive error into the window. Every outcome but a real socket
    /// failure is a QUIC timeout: the caller keeps driving `on_timeout` and
    /// the loop reaches its deadline instead of dying on the first ICMP.
    fn receive(&mut self, error: io::Error, label: &str) -> Result<(), String> {
        match classify_receive(error) {
            ReceiveError::Timeout => Ok(()),
            ReceiveError::DeadFront(error) => {
                self.0.get_or_insert_with(|| {
                    (
                        Instant::now() + DEAD_FRONT_GRACE,
                        format!("psiphon h3 dead front: {error}"),
                    )
                });
                std::thread::sleep(DEAD_FRONT_POLL);
                Ok(())
            }
            ReceiveError::Fatal(error) => Err(format!("psiphon h3 {label}: {error}")),
        }
    }

    /// A real datagram proves the ICMP was stale; start fresh afterwards.
    fn datagram(&mut self) {
        self.0 = None;
    }

    /// The clean reason to return when the window expires without a datagram.
    fn expired(&self, now: Instant) -> Option<String> {
        self.0
            .as_ref()
            .filter(|(until, _)| now >= *until)
            .map(|(_, why)| why.clone())
    }

    /// Cap the socket's read timeout at the grace window.
    fn cap(&self, wait: Duration, now: Instant) -> Duration {
        self.0.as_ref().map_or(wait, |(until, _)| {
            wait.min(until.saturating_duration_since(now))
                .max(Duration::from_millis(1))
        })
    }
}

/// A datagram path for QUIC: a UDP socket or an in-proxy WebRTC channel.
enum Link {
    Udp(UdpSocket),
    WebRtc(WebRtcStream),
}

impl Link {
    fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.send(buffer),
            Self::WebRtc(stream) => stream.write(buffer),
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.recv(buffer),
            Self::WebRtc(stream) => stream.read(buffer),
        }
    }

    fn set_read_timeout(&mut self, wait: Duration) -> io::Result<()> {
        match self {
            Self::Udp(socket) => socket.set_read_timeout(Some(wait)),
            Self::WebRtc(stream) => {
                stream.set_read_timeout(Some(wait));
                Ok(())
            }
        }
    }

    fn addresses(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        match self {
            Self::Udp(socket) => Ok((socket.local_addr()?, socket.peer_addr()?)),
            Self::WebRtc(_) => Ok((
                SocketAddr::from(([0, 0, 0, 0], 0)),
                SocketAddr::from(([0, 0, 0, 0], 0)),
            )),
        }
    }
}

/// A persistent HTTP/3 connection to one front.
pub(crate) struct H3 {
    link: Link,
    peer: SocketAddr,
    local: SocketAddr,
    conn: quiche::Connection,
    http3: quiche::h3::Connection,
    stream: Option<u64>,
    response: Response,
    finished: bool,
    read_chunk: usize,
}

impl H3 {
    /// Open a QUIC connection carrying HTTP/3 to one already-resolved front
    /// address. The caller owns the candidate list so a refused address can be
    /// followed by the next resolved IP instead of ending the relay.
    pub(crate) fn connect_address(
        peer: SocketAddr,
        dial: &str,
        sni: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).map_err(|error| format!("psiphon h3 bind: {error}"))?;
        socket
            .connect(peer)
            .map_err(|error| format!("psiphon h3 connect {dial}: {error}"))?;
        socket
            .set_read_timeout(Some(timeout))
            .and_then(|()| socket.set_write_timeout(Some(timeout)))
            .map_err(|error| format!("psiphon h3 socket: {error}"))?;
        Self::connect_link(Link::Udp(socket), dial, sni, timeout)
    }

    /// Open HTTP/3 over an in-proxy WebRTC datagram channel.
    pub(crate) fn connect_over(
        stream: WebRtcStream,
        dial: &str,
        sni: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        Self::connect_link(Link::WebRtc(stream), dial, sni, timeout)
    }

    /// Open HTTP/3 over one datagram path.
    #[allow(clippy::too_many_lines)]
    fn connect_link(
        mut link: Link,
        dial: &str,
        sni: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        let (local, peer) = link
            .addresses()
            .map_err(|error| format!("psiphon h3 local address: {error}"))?;
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|error| format!("psiphon h3 config: {error}"))?;
        // The front certificate is cover; the inner SSH host key authenticates the server.
        config.verify_peer(false);
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|error| format!("psiphon h3 protocol: {error}"))?;
        config.set_max_idle_timeout(millis(timeout));
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM);
        config.set_initial_max_data(16 * 1024 * 1024);
        config.set_initial_max_stream_data_bidi_local(4 * 1024 * 1024);
        config.set_initial_max_stream_data_bidi_remote(4 * 1024 * 1024);
        config.set_initial_max_stream_data_uni(4 * 1024 * 1024);
        config.set_initial_max_streams_bidi(16);
        config.set_initial_max_streams_uni(16);
        config.set_disable_active_migration(true);
        let scid = crate::psiphon_ssh::random::<{ quiche::MAX_CONN_ID_LEN }>();
        let scid = quiche::ConnectionId::from_ref(&scid);
        let sni = (!sni.is_empty()).then_some(sni);
        let mut conn = quiche::connect(sni, &scid, local, peer, &mut config)
            .map_err(|error| format!("psiphon h3 start {dial}: {error}"))?;
        let deadline = Instant::now() + timeout;
        let mut buffer = vec![0u8; 65535];
        let mut out = [0u8; MAX_DATAGRAM];
        let mut dead = DeadFront::default();
        while !conn.is_established() {
            loop {
                match conn.send(&mut out) {
                    Ok((write, _)) => {
                        if let Err(error) = link.send(&out[..write]) {
                            dead.receive(error, "send")?;
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => return Err(format!("psiphon h3 send: {error}")),
                }
            }
            let now = Instant::now();
            if let Some(why) = dead.expired(now) {
                return Err(why);
            }
            if now >= deadline || conn.is_closed() {
                return Err(format!("psiphon h3 handshake {dial} timed out"));
            }
            let wait = deadline
                .saturating_duration_since(now)
                .min(conn.timeout().unwrap_or(Duration::ZERO))
                .max(Duration::from_millis(1));
            link.set_read_timeout(dead.cap(wait, now))
                .map_err(|error| format!("psiphon h3 socket: {error}"))?;
            match link.receive(&mut buffer) {
                Ok(read) => {
                    dead.datagram();
                    let info = quiche::RecvInfo {
                        from: peer,
                        to: local,
                    };
                    conn.recv(&mut buffer[..read], info)
                        .map_err(|error| format!("psiphon h3 receive: {error}"))?;
                }
                Err(error) => {
                    dead.receive(error, "receive")?;
                    conn.on_timeout();
                }
            }
        }
        let http3_config =
            quiche::h3::Config::new().map_err(|error| format!("psiphon h3 settings: {error}"))?;
        let http3 = quiche::h3::Connection::with_transport(&mut conn, &http3_config)
            .map_err(|error| format!("psiphon h3 transport: {error}"))?;
        Ok(Self {
            link,
            peer,
            local,
            conn,
            http3,
            stream: None,
            response: Response {
                status: 0,
                headers: Vec::new(),
                body: Vec::new(),
            },
            finished: false,
            read_chunk: 16 * 1024,
        })
    }

    /// Whether the peer closed the QUIC connection.
    pub(crate) fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Send one request and collect its response.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn round_trip(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
        read_chunk: usize,
    ) -> Result<Response, String> {
        self.read_chunk = read_chunk.max(1);
        let mut list = vec![
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", host.as_bytes()),
            quiche::h3::Header::new(b":path", path.as_bytes()),
        ];
        for (name, value) in headers {
            list.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
        }
        self.response = Response {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
        };
        self.finished = false;
        let stream = self
            .http3
            .send_request(&mut self.conn, &list, body.is_empty())
            .map_err(|error| format!("psiphon h3 request: {error}"))?;
        self.stream = Some(stream);
        let deadline = Instant::now() + timeout;
        let mut buffer = vec![0u8; 65535];
        let mut out = [0u8; MAX_DATAGRAM];
        let mut dead = DeadFront::default();
        if !body.is_empty() {
            let mut sent = 0;
            while sent < body.len() {
                match self
                    .http3
                    .send_body(&mut self.conn, stream, &body[sent..], true)
                {
                    Ok(0) => return Err("psiphon h3 body was not sent".to_owned()),
                    Ok(wrote) => sent += wrote,
                    Err(quiche::h3::Error::Done) => {
                        self.flush(&mut out, &mut dead)?;
                        self.receive(&mut buffer, deadline, &mut dead)?;
                    }
                    Err(error) => return Err(format!("psiphon h3 body: {error}")),
                }
            }
        }
        self.flush(&mut out, &mut dead)?;
        while !self.finished {
            self.receive(&mut buffer, deadline, &mut dead)?;
            self.flush(&mut out, &mut dead)?;
        }
        if self.response.status == 0 {
            return Err("psiphon h3 response had no status".to_owned());
        }
        Ok(std::mem::replace(
            &mut self.response,
            Response {
                status: 0,
                headers: Vec::new(),
                body: Vec::new(),
            },
        ))
    }

    /// Whether the server has begun answering the current request.
    pub(crate) fn response_started(&self) -> bool {
        self.response.status != 0 || !self.response.body.is_empty()
    }

    fn receive(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
        dead: &mut DeadFront,
    ) -> Result<(), String> {
        let now = Instant::now();
        if let Some(why) = dead.expired(now) {
            return Err(why);
        }
        if now >= deadline || self.conn.is_closed() {
            return Err("psiphon h3 response timed out".to_owned());
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(self.conn.timeout().unwrap_or(Duration::ZERO))
            .max(Duration::from_millis(1));
        self.link
            .set_read_timeout(dead.cap(wait, now))
            .map_err(|error| format!("psiphon h3 socket: {error}"))?;
        match self.link.receive(buffer) {
            Ok(read) => {
                dead.datagram();
                let info = quiche::RecvInfo {
                    from: self.peer,
                    to: self.local,
                };
                self.conn
                    .recv(&mut buffer[..read], info)
                    .map_err(|error| format!("psiphon h3 receive: {error}"))?;
            }
            Err(error) => {
                dead.receive(error, "receive")?;
                self.conn.on_timeout();
            }
        }
        self.poll()
    }

    /// Write every queued QUIC packet to the peer.
    fn flush(&mut self, out: &mut [u8], dead: &mut DeadFront) -> Result<(), String> {
        loop {
            match self.conn.send(out) {
                Ok((write, _)) => {
                    if let Err(error) = self.link.send(&out[..write]) {
                        dead.receive(error, "send")?;
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(format!("psiphon h3 send: {error}")),
            }
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        let Some(stream) = self.stream else {
            return Ok(());
        };
        loop {
            match self.http3.poll(&mut self.conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) if id == stream => {
                    for header in list {
                        let name = String::from_utf8_lossy(header.name()).to_string();
                        let value = String::from_utf8_lossy(header.value()).to_string();
                        if name == ":status" {
                            self.response.status = value.parse().unwrap_or(0);
                        } else if !name.starts_with(':') {
                            self.response.headers.push((name, value));
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Data)) if id == stream => {
                    let mut chunk = [0u8; 16 * 1024];
                    let limit = self.read_chunk.min(chunk.len()).max(1);
                    let chunk = &mut chunk[..limit];
                    loop {
                        match self.http3.recv_body(&mut self.conn, stream, chunk) {
                            Ok(0) | Err(quiche::h3::Error::Done) => break,
                            Ok(read) => {
                                if self.response.body.len() + read > MAX_RESPONSE {
                                    return Err("psiphon h3 response is too large".to_owned());
                                }
                                self.response.body.extend_from_slice(&chunk[..read]);
                            }
                            Err(error) => {
                                return Err(format!("psiphon h3 response body: {error}"));
                            }
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) if id == stream => {
                    self.finished = true;
                    self.stream = None;
                    break;
                }
                Ok((id, quiche::h3::Event::Reset(code))) if id == stream => {
                    return Err(format!("psiphon h3 response reset {code}"));
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => return Err(format!("psiphon h3 response: {error}")),
            }
        }
        Ok(())
    }
}

/// Clamp a duration to the millisecond field a QUIC setting takes.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_error(kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, "probe")
    }

    fn armed(until: Instant) -> DeadFront {
        DeadFront(Some((until, "psiphon h3 dead front: probe".to_owned())))
    }

    #[test]
    fn a_refused_front_is_a_dead_candidate_not_a_fatal_receive() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
        ] {
            assert!(matches!(
                classify_receive(io_error(kind)),
                ReceiveError::DeadFront(_)
            ));
        }
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            assert!(matches!(
                classify_receive(io_error(kind)),
                ReceiveError::Timeout
            ));
        }
        assert!(matches!(
            classify_receive(io_error(io::ErrorKind::PermissionDenied)),
            ReceiveError::Fatal(_)
        ));
    }

    #[test]
    fn a_refused_front_drives_the_quic_timeout_path() {
        let mut dead = DeadFront::default();
        assert!(dead
            .receive(io_error(io::ErrorKind::ConnectionRefused), "receive")
            .is_ok());
        assert!(dead.0.is_some(), "the dead-front window is armed");
        let why = dead
            .0
            .as_ref()
            .map(|(_, why)| why.as_str())
            .unwrap_or_default();
        assert!(why.starts_with("psiphon h3 dead front: "));
        assert!(!why.contains("psiphon h3 receive:"));
    }

    #[test]
    fn a_real_datagram_clears_a_late_icmp() {
        let mut dead = armed(Instant::now() + DEAD_FRONT_GRACE);
        dead.datagram();
        assert!(dead.expired(Instant::now()).is_none());
        assert_eq!(
            dead.cap(Duration::from_secs(5), Instant::now()),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn an_expired_grace_returns_a_clean_reason_and_caps_the_wait() {
        let until = Instant::now();
        let dead = armed(until);
        let now = until + Duration::from_millis(1);
        assert_eq!(
            dead.expired(now).as_deref(),
            Some("psiphon h3 dead front: probe")
        );
        assert!(dead.cap(Duration::from_secs(5), now) <= Duration::from_millis(1));
    }

    #[test]
    fn a_real_socket_failure_still_aborts_the_dial() {
        let mut dead = DeadFront::default();
        assert_eq!(
            dead.receive(io_error(io::ErrorKind::PermissionDenied), "receive")
                .expect_err("fatal"),
            "psiphon h3 receive: probe"
        );
        assert_eq!(
            DeadFront::default()
                .receive(io_error(io::ErrorKind::PermissionDenied), "send")
                .expect_err("fatal"),
            "psiphon h3 send: probe"
        );
        assert!(dead.0.is_none());
    }

    /// The socket that produced `Connection refused (os error 61)`: a connected
    /// UDP socket whose peer has no listener. Whatever the platform calls the
    /// ICMP report, it must not surface as a fatal receive error again.
    #[test]
    fn a_refused_udp_front_never_reports_a_fatal_receive() {
        use std::net::Ipv4Addr;

        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a probe");
        let dead = probe.local_addr().expect("probe address");
        drop(probe);
        let Err(why) = H3::connect_address(dead, "127.0.0.1", "", Duration::from_secs(1)) else {
            panic!("a closed UDP port cannot handshake");
        };
        assert!(!why.contains("psiphon h3 receive: "), "{why}");
        assert!(
            why.starts_with("psiphon h3 dead front: ") || why.ends_with("timed out"),
            "{why}"
        );
    }
}
