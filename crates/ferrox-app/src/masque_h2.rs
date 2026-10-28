//! CONNECT-IP over HTTP/2, the TCP carrier RFC 9484 §3 names: the same
//! `connect-ip` request and capsule stream as the QUIC listener, sharing its
//! port, users, address pools and forwarding table.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrox_core::foxy::{connectip, frames};
use ferrox_core::tls::{TlsConfig, TlsProvider as _, TlsServerConfig};

use crate::h2::{self, Decoder};
use crate::masque::{self, deliver, withdrawn, Granted, ServerSpec, Shared, AUTH_REALM};
use crate::wg_stack::{Packet, UdpRoutes};

const HANDSHAKE: Duration = Duration::from_secs(10);
const EDGE_RETRY: Duration = Duration::from_secs(1);
const READ_WAIT: Duration = Duration::from_millis(10);
const READ_ROOM: usize = 16 * 1024;
const PREFACE: usize = 24;
const SETTINGS_INITIAL_WINDOW: u16 = 0x4;
const SETTINGS_ENABLE_CONNECT: u16 = 0x8;
const FRAME_CAP: usize = 1 << 20;
const DEFAULT_WINDOW: i64 = 65_535;

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// The TCP half of a MASQUE inbound: a listener on the port the QUIC socket
/// already owns, one thread per HTTP/2 connection. A port the platform will
/// not give twice leaves h3 serving and names the h2 listener it could not raise.
pub(crate) fn serve(
    identity: Arc<TlsServerConfig>,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
    local: SocketAddr,
) {
    let address = SocketAddr::new(local.ip(), local.port());
    let Ok(listener) = TcpListener::bind(address) else {
        eprintln!("masque: no HTTP/2 listener on {address}; h3 still serves");
        return;
    };
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let _ = stream.set_read_timeout(Some(HANDSHAKE));
            let shared = Arc::clone(&shared);
            let spec = Arc::clone(&spec);
            let identity = Arc::clone(&identity);
            std::thread::spawn(move || connection(stream, &identity, shared, spec));
        }
    });
}

fn connection(
    stream: TcpStream,
    identity: &TlsServerConfig,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
) {
    let Ok(mut tls) = ferrox_core::tls::accept(identity, stream) else {
        return;
    };
    if tls.handshake().is_err() || tls.alpn() != Some(b"h2") {
        return;
    }
    let _ = tls.get_ref().get_ref().set_read_timeout(Some(READ_WAIT));
    let mut wire = Wire {
        stream: Box::new(tls),
        pending: Vec::new(),
        closed: false,
    };
    if wire.preface() {
        Session::new(shared, spec).run(&mut wire);
    }
}

struct Wire {
    stream: Box<dyn ReadWrite + Send>,
    pending: Vec<u8>,
    closed: bool,
}

impl Wire {
    fn preface(&mut self) -> bool {
        let deadline = Instant::now() + HANDSHAKE;
        while self.pending.len() < PREFACE {
            if Instant::now() > deadline || !self.fill() || self.closed {
                return false;
            }
        }
        if !self.pending.starts_with(h2::MAGIC) {
            return false;
        }
        self.pending.drain(..PREFACE);
        true
    }

    /// One read: the caller's wait is the socket's timeout, so a quiet peer
    /// parks here rather than spinning.
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

    fn send(&mut self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let head = h2::frame_head(body.len(), kind, flags, id);
        let sent = self
            .stream
            .write_all(&head)
            .and_then(|()| self.stream.write_all(body));
        if sent.is_err() {
            self.closed = true;
            return false;
        }
        true
    }
}

struct Frame {
    kind: u8,
    flags: u8,
    id: u32,
    start: usize,
    end: usize,
}

/// One whole frame in a pending buffer, as its body's range: the caller reads the body where it landed instead of copying it out. `Err` is a frame past the cap, which closes the wire.
fn frame_at(pending: &[u8], at: usize) -> Result<Option<Frame>, ()> {
    let Some(head) = pending.get(at..at.saturating_add(9)) else {
        return Ok(None);
    };
    let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    if len > FRAME_CAP {
        return Err(());
    }
    let end = at.saturating_add(9).saturating_add(len);
    if pending.len() < end {
        return Ok(None);
    }
    let id = u32::from_be_bytes(head[5..9].try_into().expect("four bytes")) & 0x7fff_ffff;
    Ok(Some(Frame {
        kind: head[3],
        flags: head[4],
        id,
        start: at.saturating_add(9),
        end,
    }))
}

/// The dialer's half of the same wire: the request rides stream one, capsules
/// go out as DATA, and the peer's assignment names the addresses the stack may
/// source. Windows are tracked per stream and per connection, as the reference
/// transport does, so a peer that grants only one cannot be overrun.
pub(crate) struct Client {
    wire: Wire,
    decoder: Decoder,
    stream: u32,
    status: Option<u16>,
    continuation: Option<(u32, Vec<u8>)>,
    send_window: i64,
    connection_window: i64,
    queued: VecDeque<Vec<u8>>,
    capsules: Vec<u8>,
    capsule_at: usize,
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) mtu: usize,
    pub(crate) packets: Vec<Vec<u8>>,
    to_stack: Option<Sender<Packet>>,
    routes: Option<UdpRoutes>,
    end: bool,
}

/// An edge still binding refuses the first dial the way a QUIC handshake loses it, so a refused dial is retried for a second.
fn dial_until_bound(
    edge: SocketAddr,
    mut dial: impl FnMut(SocketAddr) -> std::io::Result<TcpStream>,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + EDGE_RETRY;
    loop {
        match dial(edge) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionRefused
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("cannot reach {edge}: {error}")),
        }
    }
}

fn connect_edge(edge: SocketAddr) -> Result<TcpStream, String> {
    dial_until_bound(edge, |edge| TcpStream::connect_timeout(&edge, HANDSHAKE))
}

impl Client {
    pub(crate) fn dial(
        tls_config: &TlsConfig,
        edge: SocketAddr,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Self, String> {
        let tcp = connect_edge(edge)?;
        let _ = tcp.set_nodelay(true);
        let _ = tcp.set_read_timeout(Some(HANDSHAKE));
        let _ = tcp.set_write_timeout(Some(HANDSHAKE));
        let mut tls =
            ferrox_core::tls::connect(tls_config, tcp).map_err(|error| format!("tls: {error}"))?;
        tls.handshake()
            .map_err(|error| format!("tls handshake: {error}"))?;
        if tls.alpn() != Some(b"h2".as_slice()) {
            return Err("the edge did not negotiate h2".to_owned());
        }
        let _ = tls.get_ref().set_read_timeout(Some(READ_WAIT));
        tls.write_all(h2::MAGIC)
            .map_err(|error| format!("preface: {error}"))?;
        let mut client = Self {
            wire: Wire {
                stream: Box::new(tls),
                pending: Vec::new(),
                closed: false,
            },
            decoder: Decoder::default(),
            stream: 1,
            status: None,
            continuation: None,
            send_window: DEFAULT_WINDOW,
            connection_window: DEFAULT_WINDOW,
            queued: VecDeque::new(),
            capsules: Vec::new(),
            capsule_at: 0,
            addresses: Vec::new(),
            mtu: masque::DEFAULT_MTU,
            packets: Vec::new(),
            to_stack: None,
            routes: None,
            end: false,
        };
        let mut settings = Vec::with_capacity(12);
        settings.extend_from_slice(&SETTINGS_ENABLE_CONNECT.to_be_bytes());
        settings.extend_from_slice(&1u32.to_be_bytes());
        settings.extend_from_slice(&SETTINGS_INITIAL_WINDOW.to_be_bytes());
        settings.extend_from_slice(&h2::WINDOW.to_be_bytes());
        let raised = h2::WINDOW - u32::try_from(DEFAULT_WINDOW).expect("a positive window");
        if !client.wire.send(h2::T_SETTINGS, 0, 0, &settings)
            || !client.wire.send(h2::T_WINDOW, 0, 0, &raised.to_be_bytes())
        {
            return Err("the edge closed while settings were written".to_owned());
        }
        let mut fields: Vec<(&str, &str)> = Vec::with_capacity(6 + headers.len());
        fields.push((":method", "CONNECT"));
        fields.push((":protocol", "connect-ip"));
        fields.push((":scheme", "https"));
        fields.push((":path", path));
        fields.push((":authority", authority));
        fields.push(("capsule-protocol", "?1"));
        for (name, value) in headers {
            fields.push((name, value));
        }
        let block = h2::block_encode(&fields);
        if !client
            .wire
            .send(h2::T_HEADERS, h2::F_END_HEADERS, client.stream, &block)
        {
            return Err("the edge closed while the request was written".to_owned());
        }
        let deadline = Instant::now() + HANDSHAKE;
        while client.status.is_none() {
            if Instant::now() > deadline {
                return Err("the edge sent no response head".to_owned());
            }
            client.pump();
            if client.wire.closed || client.end {
                return Err("the edge closed before the response head".to_owned());
            }
            client.wire.fill();
        }
        let status = client.status.unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(format!("the edge answered {status}"));
        }
        let v4 = [0u8; 4];
        let v6 = [0u8; 16];
        let mut requests = Vec::with_capacity(40);
        connectip::address_requests(&[(1, 4, &v4), (2, 6, &v6)], &mut requests);
        client.capsule(&requests);
        let deadline = Instant::now() + HANDSHAKE;
        while client.addresses.is_empty() {
            if Instant::now() > deadline {
                return Err("no address assigned".to_owned());
            }
            client.flush();
            client.pump();
            if client.wire.closed || client.end {
                return Err("the edge closed before assigning an address".to_owned());
            }
            client.wire.fill();
        }
        Ok(client)
    }

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
        let mut capsule = Vec::new();
        while !self.wire.closed && !self.end {
            self.pump();
            if self.wire.closed || self.end {
                break;
            }
            while let Ok(packet) = from_tunnel.try_recv() {
                capsule.clear();
                datagram(&packet, &mut capsule);
                self.capsule(&capsule);
            }
            self.flush();
            if self.wire.closed || self.end {
                break;
            }
            if !self.wire.fill() {
                break;
            }
        }
    }

    fn pump(&mut self) {
        let mut pending = std::mem::take(&mut self.wire.pending);
        let mut at = 0;
        loop {
            match frame_at(&pending, at) {
                Ok(Some(frame)) => {
                    self.on(
                        frame.kind,
                        frame.flags,
                        frame.id,
                        &pending[frame.start..frame.end],
                    );
                    at = frame.end;
                    if self.end || self.wire.closed {
                        break;
                    }
                }
                Ok(None) => break,
                Err(()) => {
                    self.wire.closed = true;
                    break;
                }
            }
        }
        if at > 0 {
            pending.drain(..at);
        }
        self.wire.pending = pending;
    }

    fn on(&mut self, kind: u8, flags: u8, id: u32, body: &[u8]) {
        match kind {
            h2::T_SETTINGS if flags & h2::F_ACK == 0 => {
                let mut at = 0;
                while at + 6 <= body.len() {
                    let setting = u16::from_be_bytes([body[at], body[at + 1]]);
                    let value = u32::from_be_bytes([
                        body[at + 2],
                        body[at + 3],
                        body[at + 4],
                        body[at + 5],
                    ]);
                    if setting == SETTINGS_INITIAL_WINDOW {
                        self.send_window = i64::from(value);
                    }
                    at += 6;
                }
                self.wire.send(h2::T_SETTINGS, h2::F_ACK, 0, &[]);
            }
            h2::T_WINDOW if body.len() == 4 => {
                let increment =
                    u32::from_be_bytes(body.try_into().expect("four bytes")) & 0x7fff_ffff;
                if id == 0 {
                    self.connection_window += i64::from(increment);
                } else if id == self.stream {
                    self.send_window += i64::from(increment);
                }
            }
            h2::T_PING if flags & h2::F_ACK == 0 => {
                self.wire.send(h2::T_PING, h2::F_ACK, 0, body);
            }
            h2::T_HEADERS if id == self.stream => {
                let block = strip_padding(flags, body);
                if flags & h2::F_END_HEADERS != 0 {
                    self.head(block);
                } else {
                    self.continuation = Some((id, block.to_vec()));
                }
                if flags & h2::F_END != 0 {
                    self.end = true;
                }
            }
            h2::T_CONT => {
                if let Some((stream, mut block)) = self.continuation.take() {
                    if stream != id {
                        self.end = true;
                        return;
                    }
                    block.extend_from_slice(strip_padding(flags, body));
                    if flags & h2::F_END_HEADERS != 0 {
                        self.head(&block);
                    } else {
                        self.continuation = Some((id, block));
                    }
                }
            }
            h2::T_DATA if id == self.stream => {
                let length = body.len();
                let data = strip_padding(flags, body);
                self.window(length);
                self.capsules(data);
                if flags & h2::F_END != 0 {
                    self.end = true;
                }
            }
            h2::T_RST if id == self.stream => self.end = true,
            h2::T_GOAWAY => self.end = true,
            _ => {}
        }
    }

    fn head(&mut self, block: &[u8]) {
        if self.status.is_some() {
            return;
        }
        let mut status = None;
        let decoded = self
            .decoder
            .decode(block, &mut |name, value| {
                if name == b":status" {
                    status = std::str::from_utf8(value)
                        .ok()
                        .and_then(|value| value.parse().ok());
                }
            })
            .is_some();
        if decoded {
            self.status = status;
        } else {
            self.end = true;
        }
    }

    fn window(&mut self, length: usize) {
        let length = u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes();
        self.wire.send(h2::T_WINDOW, 0, 0, &length);
        self.wire.send(h2::T_WINDOW, 0, self.stream, &length);
    }

    fn capsules(&mut self, bytes: &[u8]) {
        let mut capsules = std::mem::take(&mut self.capsules);
        let mut at = 0;
        let mut answers = Vec::new();
        if capsules.is_empty() {
            let mut used = 0;
            while let Some((n, capsule)) = connectip::capsule_split(&bytes[used..]) {
                used += n;
                if let Some(answer) = self.handle(capsule) {
                    answers.push(answer);
                }
            }
            if used < bytes.len() {
                capsules.extend_from_slice(&bytes[used..]);
            }
        } else {
            at = self.capsule_at;
            capsules.extend_from_slice(bytes);
            while let Some((n, capsule)) = connectip::capsule_split(&capsules[at..]) {
                at += n;
                if let Some(answer) = self.handle(capsule) {
                    answers.push(answer);
                }
            }
            if at > 0 {
                capsules.drain(..at);
                at = 0;
            }
        }
        self.capsules = capsules;
        self.capsule_at = at;
        if self.capsules.len() > FRAME_CAP {
            self.end = true;
        }
        for answer in answers {
            self.capsule(&answer);
        }
    }

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
                } else {
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

    fn capsule(&mut self, capsule: &[u8]) {
        let length = i64::try_from(capsule.len()).unwrap_or(i64::MAX);
        if length <= self.send_window.min(self.connection_window) {
            if self.wire.send(h2::T_DATA, 0, self.stream, capsule) {
                self.send_window -= length;
                self.connection_window -= length;
            }
        } else {
            self.queued.push_back(capsule.to_vec());
        }
    }

    fn flush(&mut self) {
        while let Some(answer) = self.queued.front() {
            let length = i64::try_from(answer.len()).unwrap_or(i64::MAX);
            if length > self.send_window.min(self.connection_window) {
                return;
            }
            let Some(answer) = self.queued.pop_front() else {
                return;
            };
            if self.wire.send(h2::T_DATA, 0, self.stream, &answer) {
                self.send_window -= length;
                self.connection_window -= length;
            } else {
                return;
            }
        }
    }
}

struct Session {
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
    decoder: Decoder,
    capsules: Vec<u8>,
    capsule_at: usize,
    request: Option<u32>,
    continuation: Option<(u32, Vec<u8>, u8)>,
    outgoing: Option<Receiver<Vec<u8>>>,
    queued: VecDeque<Vec<u8>>,
    send_window: i64,
    granted: Option<Granted>,
    addrs: Vec<IpAddr>,
    end: bool,
}

impl Session {
    fn new(shared: Arc<Shared>, spec: Arc<ServerSpec>) -> Self {
        Self {
            shared,
            spec,
            decoder: Decoder::default(),
            capsules: Vec::new(),
            capsule_at: 0,
            request: None,
            continuation: None,
            outgoing: None,
            queued: VecDeque::new(),
            send_window: DEFAULT_WINDOW,
            granted: None,
            addrs: Vec::new(),
            end: false,
        }
    }

    fn run(&mut self, wire: &mut Wire) {
        let mut settings = Vec::new();
        settings.extend_from_slice(&SETTINGS_ENABLE_CONNECT.to_be_bytes());
        settings.extend_from_slice(&1u32.to_be_bytes());
        wire.send(h2::T_SETTINGS, 0, 0, &settings);
        while !wire.closed && !self.end {
            let mut pending = std::mem::take(&mut wire.pending);
            let mut at = 0;
            loop {
                match frame_at(&pending, at) {
                    Ok(Some(frame)) => {
                        self.on(
                            wire,
                            frame.kind,
                            frame.flags,
                            frame.id,
                            &pending[frame.start..frame.end],
                        );
                        at = frame.end;
                        if self.end || wire.closed {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(()) => {
                        wire.closed = true;
                        break;
                    }
                }
            }
            if at > 0 {
                pending.drain(..at);
            }
            wire.pending = pending;
            self.flush(wire);
            if !wire.fill() {
                break;
            }
        }
    }

    fn on(&mut self, wire: &mut Wire, kind: u8, flags: u8, id: u32, body: &[u8]) {
        match kind {
            h2::T_SETTINGS if flags & h2::F_ACK == 0 => {
                let mut at = 0;
                while at + 6 <= body.len() {
                    let setting = u16::from_be_bytes([body[at], body[at + 1]]);
                    let value = u32::from_be_bytes([
                        body[at + 2],
                        body[at + 3],
                        body[at + 4],
                        body[at + 5],
                    ]);
                    if setting == SETTINGS_INITIAL_WINDOW {
                        self.send_window = i64::from(value);
                    }
                    at += 6;
                }
                wire.send(h2::T_SETTINGS, h2::F_ACK, 0, &[]);
            }
            h2::T_WINDOW if body.len() == 4 => {
                let increment =
                    u32::from_be_bytes(body.try_into().expect("four bytes")) & 0x7fff_ffff;
                if id == 0 || Some(id) == self.request {
                    self.send_window += i64::from(increment);
                }
            }
            h2::T_PING if flags & h2::F_ACK == 0 => {
                wire.send(h2::T_PING, h2::F_ACK, 0, body);
            }
            h2::T_HEADERS => {
                if self.request.is_some() {
                    return;
                }
                let block = strip_padding(flags, body);
                if flags & h2::F_END_HEADERS != 0 {
                    self.request(wire, id, block);
                } else {
                    self.continuation = Some((id, block.to_vec(), flags));
                }
            }
            h2::T_CONT => {
                if let Some((stream, mut block, head_flags)) = self.continuation.take() {
                    if stream != id {
                        self.end = true;
                        return;
                    }
                    block.extend_from_slice(strip_padding(flags, body));
                    if flags & h2::F_END_HEADERS != 0 {
                        self.request(wire, id, &block);
                    } else {
                        self.continuation = Some((id, block, head_flags));
                    }
                }
            }
            h2::T_DATA => {
                if Some(id) != self.request {
                    return;
                }
                let length = body.len();
                let data = strip_padding(flags, body);
                self.window(wire, length);
                self.capsules(wire, data);
                if flags & h2::F_END != 0 {
                    self.end = true;
                }
            }
            h2::T_RST if Some(id) == self.request => self.end = true,
            h2::T_GOAWAY => self.end = true,
            _ => {}
        }
    }

    fn request(&mut self, wire: &mut Wire, id: u32, block: &[u8]) {
        let mut fields = Vec::new();
        let decoded = self
            .decoder
            .decode(block, &mut |name, value| {
                fields.push((name.to_vec(), value.to_vec()));
            })
            .is_some();
        let field = |name: &[u8]| {
            fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_slice())
        };
        let path_ok =
            field(b":path").is_some_and(|path| masque::path_matches(path, &self.spec.path));
        let method_ok = field(b":method") == Some(b"CONNECT");
        let protocol_ok = field(b":protocol") == Some(b"connect-ip");
        let capsules_ok = field(b"capsule-protocol")
            .and_then(|value| value.strip_prefix(b"?"))
            .is_some_and(|value| value.split(|byte| *byte == b';').next() == Some(b"1"));
        if !decoded {
            self.reply(wire, id, 400);
            return;
        }
        if !path_ok {
            self.reply(wire, id, 404);
            return;
        }
        if !method_ok || !protocol_ok || !capsules_ok {
            self.reply(wire, id, 400);
            return;
        }
        if !self.spec.authenticates(field(b"authorization")) {
            self.reply(wire, id, 401);
            return;
        }
        let Some(addrs) = masque::assign(&self.shared) else {
            self.reply(wire, id, 503);
            return;
        };
        let (sender, outgoing) = mpsc::sync_channel::<Vec<u8>>(masque::QUEUE);
        let queue = masque::TunnelQueue::new(sender, None);
        let Some(granted) = masque::register(&self.shared, &addrs, &queue) else {
            masque::release(&self.shared, &addrs);
            self.reply(wire, id, 503);
            return;
        };
        self.addrs = addrs;
        self.granted = Some(granted);
        self.outgoing = Some(outgoing);
        self.request = Some(id);
        self.send_window = DEFAULT_WINDOW;
        let block = h2::block_encode(&[(":status", "200"), ("capsule-protocol", "?1")]);
        wire.send(h2::T_HEADERS, h2::F_END_HEADERS, id, &block);
        let mut control = Vec::new();
        connectip::address_assign_encode(&masque::grants(&self.addrs, 0), &mut control);
        self.capsule(wire, &control);
        control.clear();
        connectip::route_advert_encode(&masque::routes(&self.addrs), &mut control);
        self.capsule(wire, &control);
    }

    fn reply(&mut self, wire: &mut Wire, id: u32, status: u16) {
        let status = status.to_string();
        let mut fields = vec![(":status", status.as_str())];
        if status == "401" {
            fields.push(("www-authenticate", AUTH_REALM));
        }
        let block = h2::block_encode(&fields);
        wire.send(h2::T_HEADERS, h2::F_END_HEADERS | h2::F_END, id, &block);
        self.end = true;
    }

    fn window(&mut self, wire: &mut Wire, length: usize) {
        let Some(request) = self.request else {
            return;
        };
        let length = u32::try_from(length).expect("a frame fits four bytes");
        wire.send(h2::T_WINDOW, 0, 0, &length.to_be_bytes());
        wire.send(h2::T_WINDOW, 0, request, &length.to_be_bytes());
    }

    fn capsules(&mut self, wire: &mut Wire, bytes: &[u8]) {
        self.capsules.extend_from_slice(bytes);
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
        if self.capsules.len() > FRAME_CAP {
            self.end = true;
        }
        for answer in answers {
            self.capsule(wire, &answer);
        }
    }

    fn capsule(&mut self, wire: &mut Wire, capsule: &[u8]) {
        let Some(id) = self.request else {
            return;
        };
        if i64::try_from(capsule.len()).unwrap_or(i64::MAX) <= self.send_window {
            if wire.send(h2::T_DATA, 0, id, capsule) {
                self.send_window -= i64::try_from(capsule.len()).unwrap_or(i64::MAX);
            }
        } else {
            self.queued.push_back(capsule.to_vec());
        }
    }

    fn flush(&mut self, wire: &mut Wire) {
        while let Some(answer) = self.queued.front() {
            let Some(id) = self.request else {
                return;
            };
            if i64::try_from(answer.len()).unwrap_or(i64::MAX) > self.send_window {
                return;
            }
            let Some(answer) = self.queued.pop_front() else {
                return;
            };
            if wire.send(h2::T_DATA, 0, id, &answer) {
                self.send_window -= i64::try_from(answer.len()).unwrap_or(i64::MAX);
            } else {
                return;
            }
        }
        let packets: Vec<Vec<u8>> = self
            .outgoing
            .as_ref()
            .map(|outgoing| outgoing.try_iter().collect())
            .unwrap_or_default();
        for packet in packets {
            let mut capsule = Vec::with_capacity(packet.len() + 8);
            datagram(&packet, &mut capsule);
            self.capsule(wire, &capsule);
        }
    }
}

fn strip_padding(flags: u8, body: &[u8]) -> &[u8] {
    if flags & h2::F_PADDED == 0 {
        return body;
    }
    let Some((&padding, rest)) = body.split_first() else {
        return body;
    };
    let rest = if flags & h2::F_PRIORITY != 0 {
        rest.get(5..).unwrap_or_default()
    } else {
        rest
    };
    rest.get(..rest.len().saturating_sub(usize::from(padding)))
        .unwrap_or_default()
}

fn datagram(packet: &[u8], out: &mut Vec<u8>) {
    frames::quic_varint(out, 0);
    frames::quic_varint(out, (packet.len() + 1) as u64);
    out.push(0);
    out.extend_from_slice(packet);
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use ferrox_core::foxy::connectip::{self, UdpDatagram};
    use ferrox_core::tls::TlsConfig;

    use super::*;
    use crate::json::Json;

    fn bare_client() -> Client {
        Client {
            wire: Wire {
                stream: Box::new(std::io::Cursor::new(Vec::new())),
                pending: Vec::new(),
                closed: false,
            },
            decoder: Decoder::default(),
            stream: 1,
            status: None,
            continuation: None,
            send_window: DEFAULT_WINDOW,
            connection_window: DEFAULT_WINDOW,
            queued: std::collections::VecDeque::new(),
            capsules: Vec::new(),
            capsule_at: 0,
            addresses: Vec::new(),
            mtu: masque::DEFAULT_MTU,
            packets: Vec::new(),
            to_stack: None,
            routes: None,
            end: false,
        }
    }

    fn udp_packet(destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 14, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    #[test]
    fn a_frame_body_is_read_where_it_landed() {
        let body = [0x00, 0x02, 0x00, 0xde, 0xad];
        let mut pending = Vec::new();
        pending.extend_from_slice(&h2::frame_head(body.len(), h2::T_DATA, 0, 1));
        pending.extend_from_slice(&body);
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            let frame = frame_at(&pending, 0)
                .expect("a frame")
                .expect("a whole frame");
            assert_eq!((frame.kind, frame.flags, frame.id), (h2::T_DATA, 0, 1));
            assert_eq!(&pending[frame.start..frame.end], &body);
        });
        assert_eq!(
            counts.allocs, 0,
            "the frame body is read where it landed: {counts:?}"
        );
    }

    #[test]
    fn a_whole_capsule_is_read_where_it_landed() {
        let mut capsule = Vec::new();
        frames::quic_varint(&mut capsule, 0x1234);
        frames::quic_varint(&mut capsule, 0);
        let mut client = bare_client();
        let ((), counts) = ferrox_core::alloc_count::measure(|| client.capsules(&capsule));
        assert_eq!(
            counts.allocs, 0,
            "a whole capsule is parsed without staging: {counts:?}"
        );
        assert_eq!(
            client.capsules.capacity(),
            0,
            "a whole capsule is never staged"
        );
        assert_eq!(client.packets.len(), 0);
    }

    #[test]
    fn a_datagram_capsule_goes_straight_to_its_lane() {
        let packet = udp_packet(53);
        let mut capsule = Vec::new();
        datagram(&packet, &mut capsule);
        let (lane, received) = std::sync::mpsc::channel();
        let mut table = std::collections::HashMap::new();
        table.insert(53, lane);
        let routes = Arc::new(std::sync::Mutex::new(table));
        let (to_stack, _stack_rx) = std::sync::mpsc::channel();
        let mut client = bare_client();
        client.routes = Some(routes);
        client.to_stack = Some(to_stack);
        client.capsules(&capsule);
        assert_eq!(
            client.capsules.capacity(),
            0,
            "a whole capsule is never staged"
        );
        assert_eq!(
            client.packets.len(),
            0,
            "the packet went straight to its lane"
        );
        assert_eq!(received.recv().expect("delivered"), packet);
    }

    #[test]
    fn an_incomplete_capsule_cannot_grow_past_the_frame_cap() {
        let mut client = bare_client();
        let mut partial = Vec::new();
        frames::quic_varint(&mut partial, 0);
        frames::quic_varint(&mut partial, (FRAME_CAP + 2) as u64);
        partial.resize(FRAME_CAP + 1, 0);
        client.capsules(&partial);
        assert!(client.end, "an incomplete capsule grew past the frame cap");
    }

    #[test]
    fn a_dial_refused_until_the_edge_binds_is_retried() {
        let edge = TcpListener::bind("127.0.0.1:0").expect("edge");
        let address = edge.local_addr().expect("addr");
        let mut dials = 0;
        let stream = dial_until_bound(address, |address| {
            dials += 1;
            if dials < 3 {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
            }
            TcpStream::connect_timeout(&address, Duration::from_secs(1))
        })
        .expect("reached the edge");
        drop(stream);
        assert_eq!(dials, 3);
        drop(edge);
    }

    fn pem_lines(pem: &str) -> String {
        pem.trim_end()
            .lines()
            .map(|line| format!("\"{line}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn inbound(settings: &str) -> Json {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"security":"tls","tlsSettings":{{"alpn":["h3","h2"],"certificates":[{{"certificate":[{}],"key":[{}]}}]}}}}}}"#,
            pem_lines(&minted.cert.pem()),
            pem_lines(&minted.signing_key.serialize_pem())
        ))
        .expect("a masque inbound")
    }

    fn freedom(redirect: &str) -> crate::proxy::Outbound {
        let root = crate::json::parse(&format!(
            r#"{{"outbounds":[{{"protocol":"freedom","settings":{{"redirect":"{redirect}"}}}}]}}"#
        ))
        .expect("a freedom outbound");
        crate::proxy::Outbound::Freedom(Arc::new(
            crate::proxy::find_freedom_outbound(&root)
                .expect("the outbound reads")
                .expect("a freedom outbound"),
        ))
    }

    fn field(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        block.push(0);
        block.push(name.len() as u8);
        block.extend_from_slice(name.as_bytes());
        block.push(value.len() as u8);
        block.extend_from_slice(value);
    }

    fn read_frame(stream: &mut dyn Read) -> (u8, u8, u32, Vec<u8>) {
        let mut head = [0u8; 9];
        stream.read_exact(&mut head).expect("a frame head");
        let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("a frame body");
        (
            head[3],
            head[4],
            u32::from_be_bytes(head[5..9].try_into().expect("four bytes")),
            body,
        )
    }

    fn write_frame(stream: &mut dyn Write, kind: u8, flags: u8, id: u32, body: &[u8]) {
        let head = h2::frame_head(body.len(), kind, flags, id);
        stream.write_all(&head).expect("a frame head");
        stream.write_all(body).expect("a frame body");
    }

    fn established(echo: SocketAddr) -> (ferrox_core::tls::ClientSession<TcpStream>, IpAddr) {
        let config = inbound(
            r#"{"users":[{"email":"u@example.com","password":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#,
        );
        let port =
            crate::masque::serve_inbound(&config, &freedom(&echo.to_string()), "127.0.0.1:0")
                .expect("serve");

        let tcp = TcpStream::connect(("127.0.0.1", port)).expect("tcp");
        tcp.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let config = TlsConfig {
            server_name: "localhost".to_owned(),
            alpn: Arc::from([b"h2".to_vec()]),
            insecure: true,
            ..TlsConfig::default()
        };
        let mut tls = ferrox_core::tls::connect(&config, tcp).expect("tls");
        tls.handshake().expect("handshake");
        assert_eq!(tls.alpn(), Some(b"h2".as_slice()));

        tls.write_all(h2::MAGIC).expect("preface");
        write_frame(&mut tls, h2::T_SETTINGS, 0, 0, &[]);
        let mut block = Vec::new();
        field(&mut block, ":method", b"CONNECT");
        field(&mut block, ":protocol", b"connect-ip");
        field(&mut block, ":scheme", b"https");
        field(&mut block, ":path", b"/.well-known/masque/ip/*/*/");
        field(
            &mut block,
            ":authority",
            format!("localhost:{port}").as_bytes(),
        );
        field(&mut block, "capsule-protocol", b"?1");
        field(&mut block, "authorization", b"Basic dUBleGFtcGxlLmNvbTpw");
        write_frame(&mut tls, h2::T_HEADERS, h2::F_END_HEADERS, 1, &block);

        let mut status = None;
        let mut assigned = Vec::new();
        while status.is_none() || assigned.is_empty() {
            let (kind, flags, id, body) = read_frame(&mut tls);
            if kind == h2::T_SETTINGS {
                if flags & h2::F_ACK == 0 {
                    write_frame(&mut tls, h2::T_SETTINGS, h2::F_ACK, 0, &[]);
                }
            } else if kind == h2::T_HEADERS && id == 1 {
                let mut fields = Vec::new();
                Decoder::default()
                    .decode(&body, &mut |name, value| {
                        fields.push((name.to_vec(), value.to_vec()));
                    })
                    .expect("a header block");
                status = fields
                    .iter()
                    .find(|(name, _)| name == b":status")
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned());
            } else if kind == h2::T_DATA && id == 1 {
                let mut at = 0;
                while let Some((used, capsule)) = connectip::capsule_split(&body[at..]) {
                    at += used;
                    if let connectip::Capsule::AddressAssign(body) = capsule {
                        connectip::address_assign(body, &mut assigned).expect("an assignment");
                    }
                }
            }
        }
        assert_eq!(status.as_deref(), Some("200"));
        let client = assigned
            .iter()
            .find(|grant| grant.version == 4)
            .map(|grant| {
                let octets: [u8; 4] = grant.address[..4].try_into().expect("four bytes");
                IpAddr::from(octets)
            })
            .expect("a v4 address");
        (tls, client)
    }

    #[test]
    fn an_h2_tunnel_assigns_and_carries_a_datagram() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });

        let (mut tls, client) = established(echo_address);

        let mut packet = Vec::new();
        assert!(connectip::udp_datagram(
            &UdpDatagram {
                source: &client
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .expect("v4")
                    .octets(),
                destination: &[192, 0, 2, 1],
                source_port: 1234,
                destination_port: echo_address.port(),
                payload: b"hello",
            },
            &mut packet
        ));
        let mut capsule = Vec::new();
        datagram(&packet, &mut capsule);
        write_frame(&mut tls, h2::T_DATA, 0, 1, &capsule);

        let deadline = Instant::now() + Duration::from_secs(20);
        let mut answered = None;
        while Instant::now() < deadline && answered.is_none() {
            let (kind, _, id, body) = read_frame(&mut tls);
            if kind != h2::T_DATA || id != 1 {
                continue;
            }
            let mut at = 0;
            while let Some((used, capsule)) = connectip::capsule_split(&body[at..]) {
                at += used;
                if let connectip::Capsule::Datagram(packet) = capsule {
                    if let Some(datagram) = connectip::udp_from_packet(packet) {
                        answered = Some(datagram.payload.to_vec());
                    }
                }
            }
        }
        assert_eq!(
            answered.as_deref(),
            Some(b"hello".as_slice()),
            "{client} → 192.0.2.1:{}",
            echo_address.port()
        );
    }
}
