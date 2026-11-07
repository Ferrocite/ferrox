//! The realm rendezvous and punch: STUN discovery of the reflexive address, the HTTP
//! exchange of addresses with the rendezvous, and the UDP hole punch that carries the QUIC peer.
//!
//! The reference carries this as `stun.Message` objects, `encoding/json` bodies and a `sha256.Hash`
//! per punch, with a readiness map that raids every pending metadata on every packet. This tree
//! carries the same bytes on the stack: the binding request is twenty bytes in the caller's buffer,
//! the punch packet is built behind its salt in the caller's buffer and decodes by re-xoring the
//! header in place, and a candidate is punched only in a family its locals allow. The lean choices
//! the reference leaves behind — the bodies the events stream re-creates, the copies it joins behind
//! the salt — are the counts the buffers state.

use std::io::{BufRead, BufReader, Read, Write};

/// The socket a rendezvous exchange rides, plain or behind TLS. One trait object the plain
/// `TcpStream` and the client TLS session both answer, so `open` hands back one shape either way.
trait Io: Read + Write {}
impl<T: Read + Write> Io for T {}
type DynStream = Box<dyn Io>;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use ferrox_core::realm::{self, Config, Family, Metadata, PacketType};

/// The realm rendezvous over hand-written HTTP/1.1. One request is one closed exchange, so the
/// caller never holds a pooled HTTP connection beside the QUIC peer it punches for.
#[derive(Clone)]
pub(crate) struct Client {
    scheme: String,
    host: String,
    port: u16,
    token: String,
}

impl Client {
    /// The rendezvous `config` names. `scheme` is `http` or `https`; `host` and `port` are reached as
    /// the origin the request line carries.
    #[must_use]
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            scheme: config.scheme.clone(),
            host: config.host.clone(),
            port: config.port,
            token: config.token.clone(),
        }
    }

    /// One HTTP exchange, answered with its body text. The request line and headers ride the same
    /// buffer, so the body it carries is one write. `None` answers only a transport failure, a
    /// non-`expected_status` reply, or a body that will not fit the ceiling — a rendezvous that
    /// refuses is `None` with nothing dialled direct.
    fn exchange(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<&str>,
    ) -> Option<String> {
        let mut stream = self.open()?;
        let host_header = self.host_header();
        let mut request = Vec::with_capacity(256 + body.map_or(0, str::len));
        let _ = write!(request, "{method} {path} HTTP/1.1\r\n");
        let _ = write!(request, "Host: {host_header}\r\n");
        if !token.is_empty() {
            let _ = write!(request, "Authorization: Bearer {token}\r\n");
        }
        if let Some(body) = body {
            let _ = write!(request, "Content-Type: application/json\r\n");
            let _ = write!(request, "Content-Length: {}\r\n", body.len());
            let _ = write!(request, "Connection: close\r\n\r\n");
            request.extend_from_slice(body.as_bytes());
        } else {
            let _ = write!(request, "Connection: close\r\n\r\n");
        }
        stream.write_all(&request).ok()?;
        stream.flush().ok()?;
        read_http_body(&mut stream, self.is_https())
    }

    /// The transport to the rendezvous, plain TCP or the client TLS the relay already speaks. The
    /// server name is the authority host and the roots are the platform anchors, verified unless the
    /// rendezvous itself names `http` — the scheme already chose which one travels.
    fn open(&self) -> Option<DynStream> {
        self.open_with_timeout(Some(Duration::from_secs(5)))
    }

    fn open_with_timeout(&self, read_timeout: Option<Duration>) -> Option<DynStream> {
        let address: SocketAddr = format!("{}:{}", self.host, self.port)
            .to_socket_addrs()
            .ok()?
            .next()?;
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).ok()?;
        let _ = stream.set_read_timeout(read_timeout);
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        if !self.is_https() {
            return Some(Box::new(stream));
        }
        let config = ferrox_core::tls::TlsConfig {
            server_name: self.host.clone(),
            roots: crate::quic::system_roots(),
            insecure: false,
            resumption: true,
            ..Default::default()
        };
        let tls = ferrox_core::tls::connect(&config, stream).ok()?;
        Some(Box::new(tls))
    }

    fn host_header(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn is_https(&self) -> bool {
        self.scheme == "https"
    }

    /// `POST /v1/{id}/` with the locals this side announces, answered with `{session_id, ttl}`.
    #[must_use]
    pub(crate) fn register(&self, id: &str, locals: &[SocketAddr]) -> Option<(String, u64)> {
        let body = encode_addresses(locals);
        let reply = self.exchange("POST", &join_path(id, ""), &self.token, Some(&body))?;
        Some((
            json_string(&reply, "session_id")?,
            json_u64(&reply, "ttl").unwrap_or(60),
        ))
    }

    /// `DELETE /v1/{id}/` under the session token. The body is the deregistration the run loop
    /// issues when it closes; a failure to deregister is logged by the caller, never fatal.
    pub(crate) fn deregister(&self, id: &str, session: &str) -> bool {
        self.exchange("DELETE", &join_path(id, ""), session, None)
            .is_some()
    }

    /// `POST /v1/{id}/heartbeat` with new locals when they moved. Answered with the new TTL.
    #[must_use]
    pub(crate) fn heartbeat(
        &self,
        id: &str,
        session: &str,
        locals: Option<&[SocketAddr]>,
    ) -> Option<u64> {
        let body = match locals {
            Some(addrs) => encode_addresses(addrs),
            None => String::new(),
        };
        let reply = self.exchange(
            "POST",
            &join_path(id, "heartbeat"),
            session,
            if body.is_empty() { None } else { Some(&body) },
        )?;
        Some(json_u64(&reply, "ttl").unwrap_or(60))
    }

    /// `POST /v1/{id}/connect` with the locals announced and fresh punch metadata attached,
    /// answered with the peer's addresses and its own metadata.
    #[must_use]
    pub(crate) fn connect(
        &self,
        id: &str,
        locals: &[SocketAddr],
        meta: &Metadata,
    ) -> Option<(Vec<SocketAddr>, Metadata)> {
        let nonce_hex = realm::hex_encode(&meta.nonce);
        let obfs_hex = realm::hex_encode(&meta.obfs);
        let body = format!(
            "{{\"addresses\":{},\"nonce\":\"{nonce_hex}\",\"obfs\":\"{obfs_hex}\"}}",
            encode_addresses(locals)
        );
        let reply = self.exchange("POST", &join_path(id, "connect"), &self.token, Some(&body))?;
        let addresses = json_addr_list(&reply, "addresses");
        let nonce = json_string(&reply, "nonce")?;
        let obfs = json_string(&reply, "obfs")?;
        let peer_meta = realm::decode_metadata_hex(&nonce, &obfs)?;
        Some((addresses, peer_meta))
    }

    /// `POST /v1/{id}/connects/{nonce}` with the locals this side answers. The body is
    /// `{"addresses":[...]}`; the rendezvous answers it with no body.
    pub(crate) fn connect_response(
        &self,
        id: &str,
        session: &str,
        nonce: &str,
        locals: &[SocketAddr],
    ) -> bool {
        let body = encode_addresses(locals);
        self.exchange(
            "POST",
            &format!("/v1/{}/connects/{nonce}", sanitize_id(id)),
            session,
            Some(&body),
        )
        .is_some()
    }

    /// `GET /v1/{id}/events`, held open for the punches the rendezvous delivers. The returned
    /// stream is read line by line for `event: punch` and the `data:` JSON that follows. The read
    /// times out at sixty seconds — longer than the rendezvous keep-alive comments — so a silent dead
    /// connection ends the stream and the caller re-registers, rather than blocking the serve loop
    /// forever. A non-2xx reply ends the open instead of
    /// the punches the loop would otherwise read off the error body.
    #[must_use]
    pub(crate) fn open_events(&self, id: &str, session: &str) -> Option<EventStream> {
        let mut stream = self.open_with_timeout(Some(Duration::from_secs(60)))?;
        let host_header = self.host_header();
        let path = join_path(id, "events");
        let mut request = Vec::with_capacity(128);
        let _ = write!(request, "GET {path} HTTP/1.1\r\n");
        let _ = write!(request, "Host: {host_header}\r\n");
        let _ = write!(request, "Authorization: Bearer {session}\r\n");
        let _ = write!(request, "Accept: text/event-stream\r\n");
        let _ = write!(request, "Connection: close\r\n\r\n");
        stream.write_all(&request).ok()?;
        stream.flush().ok()?;
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        reader.read_line(&mut head).ok()?;
        let status = head.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        if !(200..300).contains(&status) {
            return None;
        }
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        Some(EventStream {
            reader,
            event: String::new(),
            data: String::new(),
        })
    }
}

/// One server-sent event off a rendezvous `events` stream.
pub(crate) struct EventStream {
    reader: BufReader<DynStream>,
    event: String,
    data: String,
}

impl EventStream {
    /// The next punch event, or `None` when the stream ends. A `: comment` heartbeat is skipped, a
    /// non-`punch` event resets the pending data, and a malformed arm ends the stream — the caller's
    /// backoff opens a fresh one rather than the reader guessing at a split event.
    #[must_use]
    pub(crate) fn next_punch(&mut self) -> Option<(Vec<SocketAddr>, Metadata)> {
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line).ok()? == 0 {
                return None;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.starts_with(':') {
                continue;
            }
            if line.is_empty() {
                let event = std::mem::take(&mut self.event);
                let data = std::mem::take(&mut self.data);
                if event != "punch" {
                    continue;
                }
                let addresses = json_addr_list(&data, "addresses");
                let nonce = json_string(&data, "nonce")?;
                let obfs = json_string(&data, "obfs")?;
                let meta = realm::decode_metadata_hex(&nonce, &obfs)?;
                return Some((addresses, meta));
            }
            if let Some((field, value)) = line.split_once(':') {
                let value = value.trim_start();
                match field.trim() {
                    "event" => self.event = value.to_owned(),
                    "data" => {
                        if !self.data.is_empty() {
                            self.data.push('\n');
                        }
                        self.data.push_str(value);
                    }
                    _ => {}
                }
            }
        }
    }
}

/// `/v1/{id}` or `/v1/{id}/{sub}`, with the slot escaped as a single name — the caller's id has
/// already answered `valid_realm_id`, so the escape is the one needed for anything the pattern
/// admits.
fn join_path(id: &str, sub: &str) -> String {
    let id = sanitize_id(id);
    if sub.is_empty() {
        format!("/v1/{id}/")
    } else {
        format!("/v1/{id}/{sub}")
    }
}

fn sanitize_id(id: &str) -> String {
    // `valid_realm_id` admits only chars the path needs no escape for.
    id.replace('%', "%25").replace('?', "%3F")
}

/// The JSON addresses object the rendezvous reads: `{"addresses":["ip:port"]}`.
fn encode_addresses(addrs: &[SocketAddr]) -> String {
    let mut body = String::with_capacity(16 + addrs.len() * 20);
    body.push_str("{\"addresses\":[");
    for (at, addr) in addrs.iter().enumerate() {
        if at > 0 {
            body.push(',');
        }
        crate::json::write(&crate::json::Json::Str(addr.to_string()), &mut body);
    }
    body.push_str("]}");
    body
}

/// Read one HTTP response body off `stream` as text, refusing the body a chunked or content-length
/// head cannot name within the ceiling.
fn read_http_body(stream: &mut dyn Io, with_tls: bool) -> Option<String> {
    const MAX_BODY: usize = 64 * 1024;
    let _ = with_tls;
    let mut reader = BufReader::new(StreamReader(stream));
    let mut head = String::new();
    reader.read_line(&mut head).ok()?;
    let status = head.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let mut content_length = 0usize;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse().ok()?;
            } else if name == "transfer-encoding"
                && value
                    .to_ascii_lowercase()
                    .split(',')
                    .any(|part| part.trim() == "chunked")
            {
                chunked = true;
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let body = if chunked {
        let mut out = String::new();
        loop {
            if Instant::now() >= deadline {
                return None;
            }
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            let size_text = line.trim().split(';').next()?.trim();
            let size = usize::from_str_radix(size_text, 16).ok()?;
            if size == 0 {
                reader.read_line(&mut line).ok()?;
                break;
            }
            if size > MAX_BODY - out.len() {
                return None;
            }
            let mut buf = vec![0u8; size];
            reader.read_exact(&mut buf).ok()?;
            out.push_str(std::str::from_utf8(&buf).ok()?);
            let mut tail = [0u8; 2];
            reader.read_exact(&mut tail).ok()?;
        }
        out
    } else {
        if content_length > MAX_BODY {
            return None;
        }
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf).ok()?;
        String::from_utf8(buf).ok()?
    };
    if !(200..300).contains(&status) && status != 204 {
        return None;
    }
    Some(body)
}

/// Borrow open-ended [`Read`] for [`BufReader`]: the ownership this helper hands `BufReader` a
/// `&mut dyn` and then gives back, without a wrapper type that lives beside the stream.
struct StreamReader<'a>(&'a mut dyn Io);

impl Read for StreamReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// Pull a string field `key` out of a tiny JSON object, or `None` when the rendezvous does not
/// carry it. The rendezvous bodies name only the fields the caller reads; a body that names more is
/// answered the same way, so no decoder beside the fields is kept.
fn json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let at = body.find(&needle)?;
    let rest = &body[at + needle.len()..];
    let rest = rest.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = rest[1..].chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Some(out),
            '\\' => out.push(chars.next()?),
            _ => out.push(ch),
        }
    }
    None
}

/// Pull a u64 field `key` out of a tiny JSON object.
fn json_u64(body: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let at = body.find(&needle)?;
    let rest = &body[at + needle.len()..];
    let rest = rest.trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Pull the address list `key` names out of a tiny JSON object as socket addresses. A malformed
/// address is dropped rather than failing the whole list — the rendezvous may name an IPv6
/// endpoint this side cannot parse, and the others still punch.
fn json_addr_list(body: &str, key: &str) -> Vec<SocketAddr> {
    let needle = format!("\"{key}\":");
    let Some(at) = body.find(&needle) else {
        return Vec::new();
    };
    let Some(mut rest) = body[at + needle.len()..].trim_start().strip_prefix('[') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\n', '\r', ',']);
        if rest.starts_with(']') || rest.is_empty() {
            break;
        }
        let Some(quoted) = rest.strip_prefix('"') else {
            break;
        };
        let Some(end) = quoted.find('"') else {
            break;
        };
        let raw = &quoted[..end];
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            out.push(addr);
        }
        rest = &quoted[end + 1..];
    }
    out
}

/// Discover the reflexive addresses `socket` names to the STUN servers, sorted distinct. `servers`
/// are `host` (3478) or `host:port` strings; a host that will not resolve is skipped, as the
/// reference skips it. `None` answers only a fresh transaction the RNG fails to draw.
#[must_use]
pub(crate) fn stun_discover(
    socket: &UdpSocket,
    servers: &[String],
    family: Family,
) -> Vec<SocketAddr> {
    let mut transactions: Vec<[u8; ferrox_core::stun::TRANSACTION_SIZE]> =
        Vec::with_capacity(servers.len());
    let mut targets: Vec<SocketAddr> = Vec::with_capacity(servers.len());
    for server in servers {
        let (host, port) = split_server(server);
        let resolved: Vec<SocketAddr> = match format!("{host}:{port}").to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(_) => continue,
        };
        let Some(target) = resolved
            .into_iter()
            .find(|addr| addr.is_ipv4() == addr_is_v4_of_local(socket))
        else {
            continue;
        };
        let mut transaction = [0u8; ferrox_core::stun::TRANSACTION_SIZE];
        if getrandom::fill(&mut transaction).is_err() {
            continue;
        }
        let mut request = [0u8; ferrox_core::stun::HEADER_LEN];
        let _ = ferrox_core::stun::binding_request_into(&mut request, &transaction);
        let _ = socket.send_to(&request, target);
        transactions.push(transaction);
        targets.push(target);
    }
    if transactions.is_empty() {
        return Vec::new();
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let _ = socket.set_read_timeout(Some(Duration::from_millis(50)));
    let mut results: Vec<SocketAddr> = Vec::new();
    let mut buffer = [0u8; 1500];
    while !transactions.is_empty() && Instant::now() < deadline {
        let Ok((length, source)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        if !targets.contains(&source) {
            continue;
        }
        let packet = &buffer[..length.min(buffer.len())];
        for (at, transaction) in transactions.iter().enumerate() {
            if let Some(mapped) = ferrox_core::stun::decode_binding_response(packet, transaction) {
                results.push(mapped);
                transactions.remove(at);
                targets.remove(at);
                break;
            }
        }
    }
    let _ = socket.set_read_timeout(None);
    results.sort_unstable();
    results.dedup();
    match family {
        Family::V4 => results.retain(SocketAddr::is_ipv4),
        Family::V6 => results.retain(SocketAddr::is_ipv6),
        Family::Dual => {}
    }
    results
}

fn addr_is_v4_of_local(socket: &UdpSocket) -> bool {
    socket.local_addr().is_ok_and(|addr| addr.is_ipv4())
}

fn split_server(server: &str) -> (String, u16) {
    let server = server.trim();
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.port());
    }
    if let Some((host, port)) = server.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.trim_matches(['[', ']']).to_owned(), port);
        }
    }
    (server.to_owned(), 3478)
}

/// Discover, connect and punch one peer to dial: the reflexive locals STUN names, the rendezvous
/// names the peer's publics, and the punch opens the hole the QUIC dial then walks. `None` fails the
/// dial — the peer is only reachable through the punch, so no direct address is dialled instead.
#[must_use]
pub(crate) fn dial_peer(socket: &UdpSocket, config: &Config) -> Option<SocketAddr> {
    let locals = stun_discover(socket, &config.stun_servers, config.family);
    if locals.is_empty() {
        return None;
    }
    let meta = realm::Metadata::new_random()?;
    let client = Client::new(config);
    let (raw_peers, peer_meta) = client.connect(&config.id, &locals, &meta)?;
    let filtered = realm::candidate_addrs(&locals, &raw_peers, config.family);
    let peers = realm::expand_symmetric(&filtered);
    punch(socket, &peer_meta, &peers)
}

/// The pending state the serve loop's packet router demultiplexes into: one sender a STUN
/// discovery waits on, and one sender a punch attempt waits on. The router is the only reader of the
/// inbound socket, so no second reader steals the answers; the registration threads only hold these
/// senders.
#[allow(clippy::type_complexity)]
pub(crate) struct RealmState {
    stun: std::sync::Mutex<
        std::collections::HashMap<
            [u8; ferrox_core::stun::TRANSACTION_SIZE],
            std::sync::mpsc::Sender<SocketAddr>,
        >,
    >,
    punch: std::sync::Mutex<
        std::collections::HashMap<
            [u8; realm::NONCE_SIZE],
            (realm::Metadata, std::sync::mpsc::Sender<SocketAddr>),
        >,
    >,
}

impl RealmState {
    /// Empty pending state: no discovery or punch is waiting for an answer yet.
    #[must_use]
    pub(crate) fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            stun: std::sync::Mutex::new(std::collections::HashMap::new()),
            punch: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }
}

/// Discover the reflexive addresses the rendezvous names to for this `config`, through the serve
/// router's pending state rather than a second reader of the socket. The binding requests go out on
/// the serve socket; each answer the demux names it is forwarded here. `None` answers a fresh
/// transaction the RNG fails to draw, or a discovery that named no address at all — callers must
/// not announce an empty list.
#[must_use]
pub(crate) fn stun_discover_via_state(
    state: &RealmState,
    sock: &crate::quic::Datagram,
    servers: &[String],
    family: Family,
) -> Option<Vec<SocketAddr>> {
    let local = sock.local_addr().ok()?;
    let mut results: Vec<SocketAddr> = Vec::new();
    for server in servers {
        let (host, port) = split_server(server);
        let resolved: Vec<SocketAddr> = match format!("{host}:{port}").to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(_) => continue,
        };
        let Some(target) = resolved
            .into_iter()
            .find(|addr| addr.is_ipv4() == local.is_ipv4())
        else {
            continue;
        };
        let mut transaction = [0u8; ferrox_core::stun::TRANSACTION_SIZE];
        if getrandom::fill(&mut transaction).is_err() {
            continue;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        state
            .stun
            .lock()
            .ok()
            .map(|mut map| map.insert(transaction, tx));
        let mut request = [0u8; ferrox_core::stun::HEADER_LEN];
        let _ = ferrox_core::stun::binding_request_into(&mut request, &transaction);
        let _ = sock.send_to(&request, target);
        if let Ok(mapped) = rx.recv_timeout(Duration::from_secs(2)) {
            results.push(mapped);
        }
        state
            .stun
            .lock()
            .ok()
            .map(|mut map| map.remove(&transaction));
    }
    results.sort_unstable();
    results.dedup();
    match family {
        Family::V4 => results.retain(SocketAddr::is_ipv4),
        Family::V6 => results.retain(SocketAddr::is_ipv6),
        Family::Dual => {}
    }
    if results.is_empty() {
        return None;
    }
    Some(results)
}

/// Punch one peer through the serve router's pending state: hello every interval until the demux
/// hands an ack's source back. `None` answers only an empty peer list.
#[must_use]
pub(crate) fn punch_via_state(
    state: &RealmState,
    sock: &crate::quic::Datagram,
    meta: &realm::Metadata,
    peers: &[SocketAddr],
) -> Option<SocketAddr> {
    if peers.is_empty() {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    state
        .punch
        .lock()
        .ok()
        .map(|mut map| map.insert(meta.nonce, (meta.clone(), tx)));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut next_send = Instant::now();
    let found = loop {
        let now = Instant::now();
        if now >= deadline {
            break None;
        }
        if now >= next_send {
            for peer in peers {
                let mut packet = [0u8; realm::MAX_WIRE_LEN];
                if let Some(written) = realm::encode_punch(PacketType::Hello, meta, &mut packet) {
                    let _ = sock.send_to(&packet[..written], *peer);
                }
            }
            next_send = now + Duration::from_millis(100);
        }
        let wait = next_send.min(deadline).saturating_duration_since(now);
        match rx.recv_timeout(wait.max(Duration::from_millis(1))) {
            Ok(from) => break Some(from),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break None,
        }
    };
    state
        .punch
        .lock()
        .ok()
        .map(|mut map| map.remove(&meta.nonce));
    found
}

/// Try the demux once for a packet the router arrived: a STUN binding success for a pending
/// discovery, or a punch packet for a pending punch. `true` says the packet was the realm's and the
/// router must not feed it to quiche. A hello is answered ack immediately, so the NAT filter opens on
/// the peer's next visit even before the punch loop's hello lands.
#[must_use]
pub(crate) fn demux(
    state: &RealmState,
    sock: &crate::quic::Datagram,
    packet: &[u8],
    from: SocketAddr,
) -> bool {
    if ferrox_core::stun::is_message(packet) {
        // The transaction is the header bytes 8..20.
        let Ok(transaction) = <[u8; ferrox_core::stun::TRANSACTION_SIZE]>::try_from(&packet[8..20])
        else {
            return false;
        };
        if let Some(mapped) = ferrox_core::stun::decode_binding_response(packet, &transaction) {
            if let Ok(mut map) = state.stun.lock() {
                if let Some(tx) = map.remove(&transaction) {
                    let _ = tx.send(mapped);
                    return true;
                }
            }
        }
        // Even if no transaction is waiting, a STUN message the peer spoke is not a QUIC packet.
        return false;
    }
    for (meta, sender) in state
        .punch
        .lock()
        .ok()
        .map(|map| map.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default()
    {
        if let Some(decoded) = realm::decode_punch(packet, &meta) {
            if decoded.packet_type == PacketType::Hello {
                let mut ack = [0u8; realm::MAX_WIRE_LEN];
                if let Some(written) = realm::encode_punch(PacketType::Ack, &meta, &mut ack) {
                    let _ = sock.send_to(&ack[..written], from);
                }
            }
            let _ = sender.send(from);
            return true;
        }
    }
    false
}

/// Register this serve at the rendezvous and answer its punches until `stop` names the end: the
/// heartbeat and the events stream run beside each other, each recovering from a refused or closed
/// rendezvous with the reference's backoff (one second doubling to thirty), and each punch event
/// answers its `connect_response` before its hello walk begins. A rendezvous that refuses is
/// logged and retried — the direct lane still serves — while a punch that times out simply ends its
/// visit: the peer punches again and the demux hands the next answer to the next attempt.
#[allow(
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::never_loop
)]
pub(crate) fn serve_registration(
    sock: std::sync::Arc<crate::quic::Datagram>,
    config: &Config,
    state: std::sync::Arc<RealmState>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let client = Client::new(config);
    let mut backoff = Duration::from_secs(1);
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let Some(base) =
            stun_discover_via_state(&state, &sock, &config.stun_servers, config.family)
        else {
            std::thread::sleep(backoff.min(Duration::from_secs(30)));
            backoff = (backoff * 2).min(Duration::from_secs(30));
            continue;
        };
        let mut locals = base;
        if let Some(mapping) = &config.port_mapping.filter(|mapping| mapping.enabled) {
            if let Some(external) = crate::hysteria_realm::port_mapping_external(
                sock.local_addr().ok(),
                mapping.timeout,
                mapping.lifetime,
            ) {
                if !locals.contains(&external) {
                    locals.push(external);
                    locals.sort_unstable();
                    locals.dedup();
                }
            } else {
                eprintln!("hysteria realm port mapping: gateway unreachable; serving without a gateway address");
            }
        }
        let shared_locals = std::sync::Arc::new(std::sync::Mutex::new(locals.clone()));
        let Some((session, ttl)) = client.register(&config.id, &locals) else {
            std::thread::sleep(backoff.min(Duration::from_secs(30)));
            backoff = (backoff * 2).min(Duration::from_secs(30));
            continue;
        };
        let heartbeat_client = client.clone();
        let heartbeat_id = config.id.clone();
        let heartbeat_session = session.clone();
        let heartbeat_sock = std::sync::Arc::clone(&sock);
        let heartbeat_state = std::sync::Arc::clone(&state);
        let heartbeat_locals = std::sync::Arc::clone(&shared_locals);
        let heartbeat_stop = std::sync::Arc::clone(&stop);
        let heartbeat_servers = config.stun_servers.clone();
        let heartbeat_family = config.family;
        let ttl_for_heartbeat = ttl;
        let session_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let heartbeat_session_stop = std::sync::Arc::clone(&session_stop);
        std::thread::spawn(move || {
            heartbeat_loop(
                heartbeat_client,
                &heartbeat_id,
                &heartbeat_session,
                heartbeat_sock,
                heartbeat_state,
                heartbeat_locals,
                heartbeat_servers,
                heartbeat_family,
                ttl_for_heartbeat,
                heartbeat_stop,
                heartbeat_session_stop,
            );
        });
        let events_client = client.clone();
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            session_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = events_client.deregister(&config.id, &session);
            return;
        }
        let Some(mut stream) = events_client.open_events(&config.id, &session) else {
            session_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            std::thread::sleep(backoff.min(Duration::from_secs(30)));
            backoff = (backoff * 2).min(Duration::from_secs(30));
            continue;
        };
        backoff = Duration::from_secs(1);
        while let Some((peer_addresses, meta)) = stream.next_punch() {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                session_stop.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            let current_locals = shared_locals
                .lock()
                .ok()
                .map_or_else(|| locals.clone(), |guard| guard.clone());
            let filtered = realm::candidate_addrs(&current_locals, &peer_addresses, config.family);
            let expanded = realm::expand_symmetric(&filtered);
            if expanded.is_empty() {
                continue;
            }
            let nonce_hex = realm::hex_encode(&meta.nonce);
            let _ =
                events_client.connect_response(&config.id, &session, &nonce_hex, &current_locals);
            let punch_state = std::sync::Arc::clone(&state);
            let punch_sock = std::sync::Arc::clone(&sock);
            std::thread::spawn(move || {
                let _ = punch_via_state(&punch_state, &punch_sock, &meta, &expanded);
            });
        }
        // The stream ended: re-register with the same backoff a refused register pays.
        session_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(backoff.min(Duration::from_secs(30)));
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// One heartbeat wait: every `ttl / 2` (fifteen seconds when the rendezvous names no ttl) the
/// reflexive locals are re-discovered, and only a change travels as the heartbeat body.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn heartbeat_loop(
    client: Client,
    id: &str,
    session: &str,
    sock: std::sync::Arc<crate::quic::Datagram>,
    state: std::sync::Arc<RealmState>,
    locals: std::sync::Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    servers: Vec<String>,
    family: Family,
    ttl: u64,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    session_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let interval = if ttl > 0 {
        Duration::from_secs(ttl / 2).max(Duration::from_secs(1))
    } else {
        Duration::from_secs(15)
    };
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed)
            || session_stop.load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        std::thread::sleep(interval);
        let Some(base) = stun_discover_via_state(&state, &sock, &servers, family) else {
            continue;
        };
        let held = locals.lock().is_ok_and(|mut guard| {
            if *guard == base {
                false
            } else {
                guard.clone_from(&base);
                true
            }
        });
        if held {
            let _ = client.heartbeat(id, session, Some(&base));
        } else {
            let _ = client.heartbeat(id, session, None);
        }
    }
}

/// Ask the local gateway for a UDP mapping of `local` and read its external address back. Until this
/// build discovers a gateway without hard-coding one and exchanges the correct RFC 6886 requests and
/// replies, it asks for no mapping and answers `None` — a wrong external address registered with the
/// rendezvous would mislead the punch, and the caller continues with its STUN address instead. The
/// reference's mapper is `UPnP` and NAT-PMP through `go-nat`; SSDP discovery of `UPnP` gateways is the
/// named gap, so no mapping is claimed from either family of gateway yet.
#[must_use]
pub(crate) fn port_mapping_external(
    local: Option<SocketAddr>,
    timeout_secs: u64,
    lifetime_secs: u64,
) -> Option<SocketAddr> {
    let _ = (local, timeout_secs, lifetime_secs);
    eprintln!("hysteria realm port mapping: gateway discovery not yet implemented; serving without a gateway address");
    None
}

/// Punch the hole the QUIC dial walks: at every interval a hello goes to every candidate, and the
/// first packet that answers as the meta the punch is under returns its source. A hello from the
/// peer is answered with an ack before the return, so both NAT filters open before QUIC arrives.
/// The walk ends at the punch timeout with `None`.
#[must_use]
pub(crate) fn punch(
    socket: &UdpSocket,
    meta: &Metadata,
    peers: &[SocketAddr],
) -> Option<SocketAddr> {
    if peers.is_empty() {
        return None;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut next_send = Instant::now();
    let mut buffer = [0u8; realm::MAX_WIRE_LEN];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        if now >= next_send {
            for peer in peers {
                let mut packet = [0u8; realm::MAX_WIRE_LEN];
                if let Some(written) = realm::encode_punch(PacketType::Hello, meta, &mut packet) {
                    let _ = socket.send_to(&packet[..written], peer);
                }
            }
            next_send = now + Duration::from_millis(100);
        }
        let wait = next_send.min(deadline).saturating_duration_since(now);
        let _ = socket.set_read_timeout(Some(wait.max(Duration::from_millis(1))));
        let Ok((length, from)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        if let Some(packet) = realm::decode_punch(&buffer[..length], meta) {
            if packet.packet_type == PacketType::Hello {
                let mut ack = [0u8; realm::MAX_WIRE_LEN];
                if let Some(written) = realm::encode_punch(PacketType::Ack, meta, &mut ack) {
                    let _ = socket.send_to(&ack[..written], from);
                }
            }
            return Some(from);
        }
    }
}
