//! CONNECT-IP over HTTP/1.1 (RFC 9484 §4): the request upgrades a `GET` with
//! the `connect-ip` token, and the 101 answer turns the same bytes into the
//! capsule stream the other carriers write.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrox_core::foxy::{connectip, frames, head_end};
use ferrox_core::tls::{TlsConfig, TlsProvider as _};

use crate::httpupgrade::HEAD_LIMIT;
use crate::masque::{self, deliver, withdrawn, ServerSpec, Shared, AUTH_REALM};
use crate::wg_stack::{Packet, UdpRoutes};

const HANDSHAKE: Duration = Duration::from_secs(10);
const READ_WAIT: Duration = Duration::from_millis(10);
const READ_ROOM: usize = 16 * 1024;
const QUEUED_CAP: usize = 64;
const CAP: usize = 1 << 20;

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

struct Wire {
    stream: Box<dyn ReadWrite + Send>,
    pending: Vec<u8>,
    closed: bool,
}

impl Wire {
    /// Read once into the pending buffer, treating EOF and errors as closure.
    fn fill(&mut self) -> bool {
        let mut room = [0u8; READ_ROOM];
        match self.stream.read(&mut room) {
            Ok(0) => {
                self.closed = true;
                false
            }
            Ok(n) => {
                self.pending.extend_from_slice(&room[..n]);
                true
            }
            Err(error) if ferrox_core::tls::TlsError::is_timeout(&error) => true,
            Err(_) => {
                self.closed = true;
                false
            }
        }
    }

    /// Write the whole buffer, marking the wire closed on failure.
    fn send(&mut self, bytes: &[u8]) -> bool {
        if self.closed || self.stream.write_all(bytes).is_err() {
            self.closed = true;
            return false;
        }
        true
    }

    /// Read until the response head ends or the budget runs out.
    fn head(&mut self, budget: Duration) -> Option<usize> {
        let until = Instant::now() + budget;
        loop {
            if self.pending.len() >= HEAD_LIMIT {
                return None;
            }
            if let Some(at) = head_end(&self.pending) {
                return Some(at + 4);
            }
            if Instant::now() >= until || !self.fill() {
                return None;
            }
        }
    }
}

/// True when the target already carries an http or https scheme.
fn absolute(path: &str) -> bool {
    path.find("://").is_some_and(|at| {
        let scheme = &path[..at];
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    })
}

/// The RFC 9484 §4.2 upgrade: an absolute URI, the authority, and the tokens.
pub(crate) fn request(authority: &str, path: &str, headers: &[(String, String)]) -> Vec<u8> {
    let target = if absolute(path) {
        path.to_owned()
    } else {
        format!("https://{authority}{path}")
    };
    let mut out = Vec::with_capacity(192 + target.len() + authority.len());
    out.extend_from_slice(b"GET ");
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(authority.as_bytes());
    out.extend_from_slice(
        b"\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\nCapsule-Protocol: ?1\r\n",
    );
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
            || name.eq_ignore_ascii_case("capsule-protocol")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

pub(crate) const SWITCH: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\nCapsule-Protocol: ?1\r\n\r\n";

/// A minimal error answer; a 401 also carries the Basic challenge.
fn refusal(status: u16) -> Vec<u8> {
    let reason = match status {
        401 => "Unauthorized",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Bad Request",
    };
    let mut out =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n");
    if status == 401 {
        out.push_str("WWW-Authenticate: ");
        out.push_str(AUTH_REALM);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// True when a comma-separated header names the token in any case.
fn header_has(text: &str, name: &str, token: &str) -> bool {
    crate::proxy::header_value_in(text, name).is_some_and(|value| {
        value
            .split(',')
            .any(|entry| entry.trim().eq_ignore_ascii_case(token))
    })
}

/// True when Capsule-Protocol offers the version `?1`.
fn capsules_ok(text: &str) -> bool {
    crate::proxy::header_value_in(text, "capsule-protocol")
        .and_then(|value| value.strip_prefix('?'))
        .is_some_and(|value| value.split(';').next() == Some("1"))
}

/// The path of an absolute-form target, or the target itself.
fn target_path(target: &str) -> &str {
    let Some(at) = target.find("://") else {
        return target;
    };
    let scheme = &target[..at];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return target;
    }
    let rest = &target[at + 3..];
    rest.find('/').map_or("/", |slash| &rest[slash..])
}

pub(crate) struct Client {
    wire: Wire,
    capsules: Vec<u8>,
    capsule_at: usize,
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) mtu: usize,
    pub(crate) packets: Vec<Vec<u8>>,
    early_bytes: usize,
    to_stack: Option<Sender<Packet>>,
    routes: Option<UdpRoutes>,
    end: bool,
}

impl Client {
    /// Dial the edge, upgrade to connect-ip, and ask for addresses.
    pub(crate) fn dial(
        tls_config: &TlsConfig,
        edge: SocketAddr,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Self, String> {
        let tcp = connect_edge(edge)?;
        let _ = tcp.set_read_timeout(Some(HANDSHAKE));
        let _ = tcp.set_write_timeout(Some(HANDSHAKE));
        let (tcp, deadline) = crate::masque_h2::handshake_stream(tcp);
        let mut tls =
            ferrox_core::tls::connect(tls_config, tcp).map_err(|error| format!("tls: {error}"))?;
        tls.handshake()
            .map_err(|error| format!("tls handshake: {error}"))?;
        if tls.alpn() != Some(b"http/1.1") {
            return Err("the edge did not negotiate http/1.1".to_owned());
        }
        deadline.clear();
        tls.get_ref().set_read_timeout(Some(READ_WAIT));
        tls.write_all(&request(authority, path, headers))
            .map_err(|error| format!("upgrade request: {error}"))?;
        let mut client = Self {
            wire: Wire {
                stream: Box::new(tls),
                pending: Vec::new(),
                closed: false,
            },
            capsules: Vec::new(),
            capsule_at: 0,
            addresses: Vec::new(),
            mtu: masque::DEFAULT_MTU,
            packets: Vec::new(),
            early_bytes: 0,
            to_stack: None,
            routes: None,
            end: false,
        };
        let Some(at) = client.wire.head(HANDSHAKE) else {
            return Err("the edge sent no response head".to_owned());
        };
        let text = std::str::from_utf8(&client.wire.pending[..at])
            .map_err(|_| "the edge answer is not HTTP".to_owned())?;
        let mut line = text
            .split("\r\n")
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let version = line.next().unwrap_or_default();
        let status = line
            .next()
            .and_then(|status| status.parse::<u16>().ok())
            .unwrap_or(0);
        if version != "HTTP/1.1" || status != 101 {
            return Err(format!("the edge answered {status}"));
        }
        if !header_has(text, "connection", "upgrade")
            || !header_has(text, "upgrade", "connect-ip")
            || !capsules_ok(text)
        {
            return Err("the edge did not accept connect-ip".to_owned());
        }
        client.wire.pending.drain(..at);
        client.request_addresses()?;
        Ok(client)
    }

    /// Ask for one address per family and wait for the assignment.
    fn request_addresses(&mut self) -> Result<(), String> {
        let v4 = [0u8; 4];
        let v6 = [0u8; 16];
        let mut requests = Vec::with_capacity(40);
        connectip::address_requests(&[(1, 4, &v4), (2, 6, &v6)], &mut requests);
        self.capsule(&requests);
        let deadline = Instant::now() + HANDSHAKE;
        while self.addresses.is_empty() {
            if Instant::now() > deadline {
                return Err("no address assigned".to_owned());
            }
            self.pump();
            if self.wire.closed || self.end {
                return Err("the edge closed before assigning an address".to_owned());
            }
            if self.addresses.is_empty() && !self.wire.fill() {
                break;
            }
        }
        if self.addresses.is_empty() {
            return Err("no address assigned".to_owned());
        }
        Ok(())
    }

    /// Pump capsules both ways until the wire or the session ends.
    pub(crate) fn run(
        &mut self,
        from_tunnel: &Receiver<Vec<u8>>,
        to_stack: &Sender<Packet>,
        routes: &UdpRoutes,
    ) {
        self.to_stack = Some(to_stack.clone());
        self.routes = Some(routes.clone());
        for packet in self.packets.drain(..) {
            deliver(to_stack, routes, &packet);
        }
        self.early_bytes = 0;
        let mut capsule = Vec::new();
        while !self.wire.closed && !self.end {
            self.pump();
            if self.wire.closed || self.end {
                break;
            }
            for _ in 0..QUEUED_CAP {
                if self.end || self.wire.closed {
                    break;
                }
                let Ok(packet) = from_tunnel.try_recv() else {
                    break;
                };
                capsule.clear();
                datagram(&packet, &mut capsule);
                self.capsule(&capsule);
            }
            if !self.wire.fill() {
                break;
            }
        }
    }

    /// Write one capsule unless the session already ended.
    fn capsule(&mut self, capsule: &[u8]) {
        if !self.end && !self.wire.closed {
            self.wire.send(capsule);
        }
    }

    /// Split pending capsules, handle each, and answer the survivors.
    fn pump(&mut self) {
        let bytes = std::mem::take(&mut self.wire.pending);
        let mut capsules = std::mem::take(&mut self.capsules);
        capsules.extend_from_slice(&bytes);
        let mut at = self.capsule_at;
        let mut answers = Vec::new();
        while let Some((used, capsule)) = connectip::capsule_split(&capsules[at..]) {
            at += used;
            if let Some(answer) = self.handle(capsule) {
                answers.push(answer);
            }
        }
        if at > 0 {
            capsules.drain(..at);
            at = 0;
        }
        self.capsule_at = at;
        if capsules.len() > CAP {
            self.end = true;
        }
        self.capsules = capsules;
        for answer in answers {
            self.capsule(&answer);
        }
    }

    /// Handle one capsule, returning an answer when one is owed.
    fn handle(&mut self, capsule: connectip::Capsule<'_>) -> Option<Vec<u8>> {
        match capsule {
            connectip::Capsule::AddressAssign(body) => {
                if self.addresses.is_empty() {
                    let mut assigned = Vec::new();
                    if connectip::address_assign(body, &mut assigned).is_some() {
                        self.addresses.extend(assigned.iter().filter_map(|grant| {
                            (!grant.refused())
                                .then(|| masque::address_of(grant))
                                .flatten()
                        }));
                    }
                } else if let Some(address) = withdrawn(body, &self.addresses) {
                    eprintln!("masque: the proxy withdrew {address}");
                    self.end = true;
                }
                None
            }
            connectip::Capsule::Datagram(packet) => {
                if let (Some(to_stack), Some(routes)) = (&self.to_stack, &self.routes) {
                    deliver(to_stack, routes, packet);
                } else if self.packets.len() >= masque::EARLY_PACKETS
                    || self.early_bytes.saturating_add(packet.len()) > masque::EARLY_BYTES
                {
                    self.end = true;
                } else {
                    self.early_bytes += packet.len();
                    self.packets.push(packet.to_vec());
                }
                None
            }
            connectip::Capsule::AddressRequest(body) => {
                let granted = masque::respond(body, &self.addresses);
                if granted.is_empty() {
                    return None;
                }
                let mut out = Vec::new();
                connectip::address_assign_encode(&granted, &mut out);
                Some(out)
            }
            _ => None,
        }
    }
}

/// Connect with three quick attempts so a just-bound listener is reached.
fn connect_edge(edge: SocketAddr) -> Result<TcpStream, String> {
    let mut last = None;
    for _ in 0..3 {
        match TcpStream::connect(edge) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(format!(
        "cannot reach {edge}: {}",
        last.map(|error| error.to_string()).unwrap_or_default()
    ))
}

/// Encode one packet as a context-zero connect-ip datagram capsule.
fn datagram(packet: &[u8], out: &mut Vec<u8>) {
    frames::quic_varint(out, 0);
    frames::quic_varint(out, (packet.len() + 1) as u64);
    out.push(0);
    out.extend_from_slice(packet);
}

/// A server connection that already finished its TLS handshake and negotiated
/// `http/1.1`.
pub(crate) fn serve(
    stream: impl Read + Write + Send + 'static,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
) {
    let mut wire = Wire {
        stream: Box::new(stream),
        pending: Vec::new(),
        closed: false,
    };
    let Some(at) = wire.head(HANDSHAKE) else {
        return;
    };
    let head = wire.pending[..at].to_vec();
    wire.pending.drain(..at);
    let Some(text) = std::str::from_utf8(&head).ok() else {
        wire.send(&refusal(400));
        return;
    };
    let Some(request_line) = text.split("\r\n").next() else {
        wire.send(&refusal(400));
        return;
    };
    let mut fields = request_line.split(' ');
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or_default();
    let path = target_path(target);
    if version != "HTTP/1.1" || method != "GET" {
        wire.send(&refusal(400));
        return;
    }
    if !masque::path_matches(path.as_bytes(), &spec.path) {
        wire.send(&refusal(404));
        return;
    }
    if !header_has(text, "connection", "upgrade")
        || !header_has(text, "upgrade", "connect-ip")
        || !capsules_ok(text)
        || crate::proxy::header_value_in(text, "host").is_none()
    {
        wire.send(&refusal(400));
        return;
    }
    if !spec.authenticates(crate::proxy::header_value_in(text, "authorization").map(str::as_bytes))
    {
        wire.send(&refusal(401));
        return;
    }
    let Some(addrs) = masque::assign(&shared) else {
        wire.send(&refusal(503));
        return;
    };
    let (sender, outgoing) = mpsc::sync_channel::<Vec<u8>>(masque::QUEUE);
    let queue = masque::TunnelQueue::new(sender, None);
    let Some(_granted) = masque::register(&shared, &addrs, &queue) else {
        masque::release(&shared, &addrs);
        wire.send(&refusal(503));
        return;
    };
    if !wire.send(SWITCH) {
        return;
    }
    let mut control = Vec::new();
    connectip::address_assign_encode(&masque::grants(&addrs, 0), &mut control);
    if !wire.send(&control) {
        return;
    }
    control.clear();
    connectip::route_advert_encode(&masque::routes(&addrs), &mut control);
    if !wire.send(&control) {
        return;
    }
    let mut session = Session {
        shared,
        spec,
        addrs,
        outgoing: Some(outgoing),
        capsules: Vec::new(),
        capsule_at: 0,
        end: false,
    };
    session.run(&mut wire);
}

struct Session {
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
    addrs: Vec<IpAddr>,
    outgoing: Option<Receiver<Vec<u8>>>,
    capsules: Vec<u8>,
    capsule_at: usize,
    end: bool,
}

impl Session {
    /// Pump capsules both ways until the wire or the session ends.
    fn run(&mut self, wire: &mut Wire) {
        let mut capsule = Vec::new();
        while !wire.closed && !self.end {
            self.pump(wire);
            if wire.closed || self.end {
                break;
            }
            for _ in 0..QUEUED_CAP {
                if self.end || wire.closed {
                    break;
                }
                let Some(packet) = self
                    .outgoing
                    .as_ref()
                    .and_then(|outgoing| outgoing.try_recv().ok())
                else {
                    break;
                };
                capsule.clear();
                datagram(&packet, &mut capsule);
                wire.send(&capsule);
            }
            if !wire.fill() {
                break;
            }
        }
    }

    /// Split pending capsules, forward packets, and answer requests.
    fn pump(&mut self, wire: &mut Wire) {
        let bytes = std::mem::take(&mut wire.pending);
        self.capsules.extend_from_slice(&bytes);
        let mut answers = Vec::new();
        while let Some((used, capsule)) =
            connectip::capsule_split(&self.capsules[self.capsule_at..])
        {
            self.capsule_at += used;
            match capsule {
                connectip::Capsule::Datagram(packet) => {
                    masque::forward(&self.shared, &self.spec, &self.addrs, packet);
                }
                connectip::Capsule::AddressRequest(body) => {
                    let granted = masque::respond(body, &self.addrs);
                    if !granted.is_empty() {
                        let mut out = Vec::new();
                        connectip::address_assign_encode(&granted, &mut out);
                        answers.push(out);
                    }
                }
                _ => {}
            }
        }
        if self.capsule_at > 0 {
            self.capsules.drain(..self.capsule_at);
            self.capsule_at = 0;
        }
        if self.capsules.len() > CAP {
            self.end = true;
        }
        for answer in answers {
            wire.send(&answer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_h1_request_is_the_rfc_upgrade() {
        let bytes = request("example.org", "/.well-known/masque/ip/*/*/", &[]);
        assert_eq!(
            bytes,
            b"GET https://example.org/.well-known/masque/ip/*/*/ HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\nCapsule-Protocol: ?1\r\n\r\n"
        );
        let absolute = request("example.org", "HTTPS://example.org/ip", &[]);
        assert!(absolute.starts_with(b"GET HTTPS://example.org/ip HTTP/1.1\r\n"));
    }

    #[test]
    fn an_h1_answer_is_the_rfc_switch() {
        assert_eq!(
            SWITCH,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\nCapsule-Protocol: ?1\r\n\r\n"
        );
    }

    #[test]
    fn an_h1_request_keeps_its_extra_headers_and_drops_the_ones_it_owns() {
        let headers = vec![
            ("host".to_owned(), "wrong".to_owned()),
            ("connection".to_owned(), "close".to_owned()),
            ("upgrade".to_owned(), "websocket".to_owned()),
            ("capsule-protocol".to_owned(), "?0".to_owned()),
            ("authorization".to_owned(), "Basic dTpw".to_owned()),
        ];
        let request = request("edge.example", "/", &headers);
        let text = std::str::from_utf8(&request).expect("text");
        assert_eq!(text.matches("Host:").count(), 1);
        assert_eq!(text.matches("Connection:").count(), 1);
        assert_eq!(text.matches("Upgrade:").count(), 1);
        assert_eq!(text.matches("Capsule-Protocol:").count(), 1);
        assert!(text.contains("authorization: Basic dTpw\r\n"));
    }

    fn bare_client() -> Client {
        Client {
            wire: Wire {
                stream: Box::new(std::io::Cursor::new(Vec::new())),
                pending: Vec::new(),
                closed: false,
            },
            capsules: Vec::new(),
            capsule_at: 0,
            addresses: Vec::new(),
            mtu: masque::DEFAULT_MTU,
            packets: Vec::new(),
            early_bytes: 0,
            to_stack: None,
            routes: None,
            end: false,
        }
    }

    #[test]
    fn a_pre_stack_datagram_flood_is_bounded() {
        let mut client = bare_client();
        let packet = [0u8; 32];
        for _ in 0..masque::EARLY_PACKETS {
            client.handle(connectip::Capsule::Datagram(&packet));
        }
        assert!(!client.end, "the count cap itself is accepted");
        client.handle(connectip::Capsule::Datagram(&packet));
        assert!(client.end, "the next datagram ends the session");

        let mut client = bare_client();
        let packet = vec![0u8; masque::EARLY_BYTES / masque::EARLY_PACKETS + 1];
        for _ in 0..masque::EARLY_PACKETS {
            client.handle(connectip::Capsule::Datagram(&packet));
            if client.end {
                break;
            }
        }
        assert!(client.end, "the byte cap ends the session");
        assert!(client.packets.len() < masque::EARLY_PACKETS);
        assert!(client.early_bytes <= masque::EARLY_BYTES);
    }

    #[test]
    fn an_absolute_target_still_matches_the_configured_path() {
        assert_eq!(
            target_path("https://edge.example/.well-known/masque/ip/192.0.2.1/32/"),
            "/.well-known/masque/ip/192.0.2.1/32/"
        );
        assert_eq!(
            target_path("/.well-known/masque/ip/*/*/"),
            "/.well-known/masque/ip/*/*/"
        );
        assert_eq!(
            target_path("HTTPS://edge.example/.well-known/masque/ip/192.0.2.1/32/"),
            "/.well-known/masque/ip/192.0.2.1/32/"
        );
        assert_eq!(target_path("Http://edge.example"), "/");
    }
}
