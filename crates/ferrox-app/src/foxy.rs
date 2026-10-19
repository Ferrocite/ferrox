//! Foxy lane: a CONNECT tunnel to an account's CDN edge over H1/H2/H3; a lane hands the caller a carrier-agnostic `Read + Write`.

use crate::conn::Connection;
use ferrox_core::foxy::connectip;
use ferrox_core::foxy::{self, authority, frames, hpack, masque, Failure, Pass};
use ferrox_core::tls::RecordAlignment;
use ferrox_core::tls::TlsProvider;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Attempts at one address before the lane moves on, and the pause between them: an edge that closes a handshake it started answers again in ~0.1s, so retry fast without waiting minutes on a dead address.
const EDGE_ATTEMPTS: usize = 8;
const EDGE_BACKOFF_MS: u64 = 250;
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_FRAME: usize = frames::MAX_FRAME as usize;
const MAX_HEAD: usize = 8_192;
/// Unparsed capsule-stream cap: fail the association rather than buffer a peer that never completes a capsule.
const DATAGRAM_BUF_MAX: usize = 256 * 1024;
const SEND_WAIT: Duration = Duration::from_secs(10);
/// The client's first unidirectional stream, carrying the SETTINGS that make the connection HTTP/3.
const CONTROL_STREAM: u64 = 2;
/// The request-stream window's cap: the downlink never stages a frame here — only the head walk and the capsule stream land bytes in the window, and the max DATA frame the lane writes fits inside one read of this size.
const H3_WINDOW: usize = 64 * 1024;
/// A QUIC frame header is two varints of at most eight bytes each; the downlink reads no more than this into its window, because the payload it names lands in the caller.
const H3_PEEK: usize = 16;
const H3_FRAME: usize = 16 * 1024;

/// The carriers the lane can carry, in `auto`'s preference order: QUIC (one handshake carries every flow), HTTP/2 (the edge speaks it), HTTP/1.1 (every edge does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carrier {
    H1,
    H2,
    H3,
    /// Try each carrier in turn: an edge that will not answer QUIC is a slower tunnel, not a refused one.
    Auto,
}

impl Carrier {
    #[must_use]
    pub(crate) const fn alpn(self) -> &'static [u8] {
        match self {
            Self::H1 => b"http/1.1",
            Self::H2 => b"h2",
            Self::H3 => b"h3",
            // An unexpanded `auto` offers nothing: a dial reaching here fails the handshake instead of quietly dialling HTTP/2.
            Self::Auto => b"",
        }
    }

    /// The carriers to try, most preferred first, one entry when not `auto`.
    #[must_use]
    pub(crate) const fn order(self) -> [Self; 3] {
        match self {
            Self::Auto => [Self::H3, Self::H2, Self::H1],
            Self::H3 => [Self::H3, Self::H3, Self::H3],
            Self::H2 => [Self::H2, Self::H2, Self::H2],
            Self::H1 => [Self::H1, Self::H1, Self::H1],
        }
    }

    /// The carriers a UDP flow rides: HTTP/1.1 has no extended CONNECT for datagrams, and the configured carrier does not apply.
    #[must_use]
    pub(crate) const fn udp_order() -> [Self; 2] {
        [Self::H3, Self::H2]
    }
}

/// Reads a carrier from a config or a link: `auto` is a carrier, and an unknown name is `auto`, never a silent HTTP/2.
pub(crate) fn carrier(name: &str) -> Carrier {
    match name {
        "h1" | "http/1.1" => Carrier::H1,
        "h2" | "http/2" => Carrier::H2,
        "h3" | "quic" => Carrier::H3,
        _ => Carrier::Auto,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FoxyDial {
    /// The edge name: the TLS server name, the ALPN subject, and the country the hostname pins.
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The address to connect to, when it is not the name's own resolution.
    pub(crate) address: Option<SocketAddr>,
    pub(crate) carrier: Carrier,
    /// The upstream hop the dial chains through (TCP over CONNECT or SOCKS5; QUIC over a SOCKS5 UDP association).
    pub(crate) upstream: Option<UpstreamProxy>,
    pub(crate) roots: ferrox_core::tls::Anchors,
    pub(crate) pins: foxy::pin::Pins,
    pub(crate) pass: Pass,
}

/// One hop before the edge: plain HTTP CONNECT or a no-auth SOCKS5 handshake; anything else, including credentials, refuses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamProxy {
    http: bool,
    host: String,
    port: u16,
}

impl UpstreamProxy {
    /// Whether the hop speaks HTTP CONNECT, a TCP-only hop: a QUIC carrier must be refused instead.
    pub(crate) fn http(&self) -> bool {
        self.http
    }
}

pub(crate) fn upstream_proxy(text: &str) -> Option<UpstreamProxy> {
    let text = text.trim();
    let (http, rest) = text
        .strip_prefix("http://")
        .map(|rest| (true, rest))
        .or_else(|| text.strip_prefix("socks5://").map(|rest| (false, rest)))
        .or_else(|| text.strip_prefix("socks5h://").map(|rest| (false, rest)))?;
    let (host, port) = rest.rsplit_once(':')?;
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    Some(UpstreamProxy {
        http,
        host: host.to_owned(),
        port,
    })
}

/// The TLS session to the edge, dialed address by address — the handshake and ALPN are part of "does this address work"; a configured hop is the dial instead.
fn tls_to_edge(dial: &FoxyDial) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    if let Some(proxy) = dial.upstream.as_ref() {
        return edge_over_hop(proxy, dial);
    }
    let peers = match dial.address {
        Some(address) => vec![address],
        None => format!("{}:{}", dial.host, dial.port)
            .to_socket_addrs()
            .map_err(|_| Failure::Io)?
            .collect(),
    };
    let mut tried = 0usize;
    let mut last = Failure::Io;
    for peer in peers {
        tried += 1;
        // The edge sometimes closes a handshake it started with no reason, seconds away from carrying the tunnel; 8 quick asks make that a leg, not a flow.
        for attempt in 0..EDGE_ATTEMPTS {
            let stream = match crate::conn::dial_tcp(&peer, CONNECT_TIMEOUT) {
                Ok(stream) => stream,
                Err(error) => {
                    debug_address(peer, &format!("tcp {error}"));
                    break;
                }
            };
            let _ = stream.set_nodelay(true);
            // Half-second handshake budget: a quiet edge would otherwise hold the flow for the OS TCP timeout, which answers EAGAIN on macOS.
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            match finish_tls(dial, stream) {
                Ok(tls) => {
                    // The handshake's budget hands over to the head's: an edge that finishes TLS and never answers the CONNECT costs this open the named head wait, not the life of the flow.
                    let _ = tls
                        .get_ref()
                        .set_read_timeout(Some(crate::budgets::head_arrival()));
                    return Ok(tls);
                }
                Err(failure) => {
                    last = failure;
                    // An ALPN mismatch is the edge naming a protocol, which no retry changes; only losing the connection is worth a second try.
                    let worth = matches!(failure, Failure::Io);
                    if attempt + 1 < EDGE_ATTEMPTS && worth {
                        std::thread::sleep(after_attempt(attempt));
                        continue;
                    }
                    debug_address(peer, &failure.to_string());
                    break;
                }
            }
        }
    }
    if tried > 1 {
        eprintln!("foxy: the edge carried the lane on none of its {tried} addresses");
    }
    Err(last)
}

/// The edge through the configured hop, retried like a direct dial: a hop head read answers `WouldBlock`, not `TimedOut`, on macOS (`Os { code: 35 }`).
fn edge_over_hop(
    proxy: &UpstreamProxy,
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    let mut tried = 0usize;
    let mut failure = Failure::Io;
    for attempt in 0..EDGE_ATTEMPTS {
        tried += 1;
        match tcp_via(proxy, dial).and_then(|stream| finish_tls(dial, stream)) {
            Ok(tls) => return Ok(tls),
            Err(lost) => {
                failure = lost;
                let worth = matches!(failure, Failure::Io | Failure::Stream);
                if attempt + 1 < EDGE_ATTEMPTS && worth {
                    std::thread::sleep(after_attempt(attempt));
                }
            }
        }
    }
    debug_loss(
        "the hop refused the edge",
        &format!("after {tried} attempts"),
    );
    Err(failure)
}

/// The pause before the next attempt at one address: flat, because the edge answers a refusal in ~0.1s, so 8 attempts cost seconds, not a whole budget.
fn after_attempt(_attempt: usize) -> std::time::Duration {
    Duration::from_millis(EDGE_BACKOFF_MS)
}

/// Diagnostics behind `FOXY_DEBUG`: a red leg is only actionable when it names the address, the stage and the platform error — a refusal and a hang share a message otherwise.
fn debug_loss(stage: &str, error: &dyn std::fmt::Display) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: {stage}: {error}");
    }
}

fn debug_address(peer: SocketAddr, why: &str) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: address {peer} lost: {why}");
    }
}

/// One address, all the way to a usable session, naming the failed stage — a bare "io" cannot be told apart from any other leg's.
fn finish_tls(
    dial: &FoxyDial,
    stream: Connection,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    let mut tls = match ferrox_core::tls::RustlsProvider::connect(&tls_config(dial), stream) {
        Ok(tls) => tls,
        Err(error) => {
            debug_loss("the TLS client failed to start", &error.to_string());
            return Err(error.into());
        }
    };
    if let Err(error) = tls.handshake() {
        debug_loss("the TLS handshake with the edge failed", &error.to_string());
        return Err(error.into());
    }
    negotiated(&tls, dial)
        .inspect_err(|_| debug_stage("the edge named no protocol this lane speaks"))
        .map(|()| tls)
}

fn tls_config(dial: &FoxyDial) -> ferrox_core::tls::TlsConfig {
    ferrox_core::tls::TlsConfig {
        server_name: dial.host.clone(),
        alpn: vec![dial.carrier.alpn().to_vec()],
        roots: Arc::clone(&dial.roots),
        pins: dial.pins.clone(),
        cipher_suites: Vec::new(),
        insecure: false,
    }
}

/// TCP to the edge through one upstream hop: the TLS name stays the edge's, so the hop carries bytes it can neither read nor address.
fn tcp_via(proxy: &UpstreamProxy, dial: &FoxyDial) -> Result<Connection, Failure> {
    let mut stream = tcp_to_proxy(proxy).ok_or(Failure::Io)?;
    let edge = authority(&dial.host, dial.port);
    if proxy.http {
        // Build CONNECT request without allocating String in most cases
        let mut request = Vec::with_capacity(edge.len() + 32);
        request.extend_from_slice(b"CONNECT ");
        request.extend_from_slice(edge.as_bytes());
        request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        request.extend_from_slice(edge.as_bytes());
        request.extend_from_slice(b"\r\n\r\n");
        stream.write_all(&request).map_err(|_| Failure::Io)?;
        // The whole head, not just the status line
        let mut head = Vec::with_capacity(64);
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            read_exact(&mut stream, &mut byte).map_err(|_| Failure::Io)?;
            head.push(byte[0]);
            if head.len() > 4096 {
                return Err(Failure::Io);
            }
        }
        let code = head
            .split(|b| *b == b'\n')
            .next()
            .and_then(|line| line.split(|b| *b == b' ').nth(1))
            .and_then(|code| std::str::from_utf8(code).ok())
            .and_then(|code| code.trim().parse::<u16>().ok())
            .ok_or(Failure::Io)?;
        opened(code)?;
    } else {
        socks_greeting(&mut stream)?;
        let host_len = u8::try_from(dial.host.len()).map_err(|_| Failure::Io)?;
        let mut request = vec![5, 1, 0, 3, host_len];
        request.extend_from_slice(dial.host.as_bytes());
        request.extend_from_slice(&dial.port.to_be_bytes());
        stream.write_all(&request).map_err(|_| Failure::Io)?;
        // The hop's bound address is not the edge's: read past it and drop it, the connection itself is the answer.
        if socks_reply(&mut stream)?.is_none() {
            return Err(Failure::Io);
        }
    }
    Ok(stream)
}

/// One UDP association with a SOCKS5 hop: greeting, a request naming no destination, the relay address; the caller holds the control connection — dropping it ends the association.
pub(crate) fn associate_udp(proxy: &UpstreamProxy) -> Option<(Arc<Connection>, SocketAddr)> {
    let mut control = tcp_to_proxy(proxy)?;
    if socks_greeting(&mut control).is_err() {
        return None;
    }
    if control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return None;
    }
    let Ok(Some(relay)) = socks_reply(&mut control) else {
        return None;
    };
    Some((Arc::new(control), relay))
}

/// The one hop this tree speaks to, dialed: a proxy that does not answer at all is a failed dial, not a lane running direct.
fn tcp_to_proxy(proxy: &UpstreamProxy) -> Option<Connection> {
    // Same reason the edge dial tries each one: a hop answering on the second listed family is still the hop this lane uses.
    for addr in format!("{}:{}", proxy.host, proxy.port)
        .to_socket_addrs()
        .ok()?
    {
        if let Ok(stream) = crate::conn::dial_tcp(&addr, CONNECT_TIMEOUT) {
            let _ = stream.set_nodelay(true);
            // The head is read a byte at a time and is small, so a few seconds is the honest bound; without it a missing byte holds the flow for the OS's minutes-long timeout.
            let _ = stream.set_read_timeout(Some(HEADER_TIMEOUT));
            return Some(stream);
        }
    }
    None
}

/// No authentication offered, none accepted: a hop that selects anything else is one this lane cannot use.
fn socks_greeting(stream: &mut Connection) -> Result<(), Failure> {
    stream.write_all(&[5, 1, 0]).map_err(|_| Failure::Io)?;
    let mut method = [0u8; 2];
    read_exact(stream, &mut method).map_err(|_| Failure::Io)?;
    if method != [5, 0] {
        return Err(Failure::Io);
    }
    Ok(())
}

/// Whether the hop granted the request, and the address it bound: a refusal answers the same reply with a non-zero status, and a name in the reply is something this tree cannot address back.
fn socks_reply(stream: &mut Connection) -> Result<Option<SocketAddr>, Failure> {
    let mut head = [0u8; 4];
    read_exact(stream, &mut head).map_err(|_| Failure::Io)?;
    if head[1] != 0 {
        return Ok(None);
    }
    let mut read = |into: &mut [u8]| read_exact(stream, into).map_err(|_| Failure::Io);
    let ip = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            read(&mut octets)?;
            std::net::Ipv4Addr::from(octets).into()
        }
        4 => {
            let mut octets = [0u8; 16];
            read(&mut octets)?;
            std::net::Ipv6Addr::from(octets).into()
        }
        _ => return Err(Failure::Io),
    };
    let mut port = [0u8; 2];
    read(&mut port)?;
    Ok(Some(SocketAddr::new(ip, u16::from_be_bytes(port))))
}

/// A handshake that answered a different ALPN is a refusal, not a downgrade: the lane asked for exactly one protocol.
fn negotiated<S: TlsProvider>(tls: &S, dial: &FoxyDial) -> Result<(), Failure> {
    match tls.alpn() {
        Some(got) if got == dial.carrier.alpn() => Ok(()),
        _ => Err(Failure::Frame),
    }
}

fn opened(status: u16) -> Result<(), Failure> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(Failure::Rejected(status))
    }
}

fn read_exact<S: Read>(io: &mut S, buf: &mut [u8]) -> std::io::Result<()> {
    let mut at = 0usize;
    while at < buf.len() {
        match io.read(&mut buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            // A socket timeout on macOS answers EAGAIN, so a would-block read is the same answer: retried by the caller, which is what a quantum is for.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && at == 0 =>
            {
                return Err(error);
            }
            Err(error) => return Err(error),
            Ok(read) => at += read,
        }
    }
    Ok(())
}

/// HTTP/1.1 CONNECT: the request, the status line, then the target's own bytes.
pub(crate) fn open_h1(dial: &FoxyDial, target: &str) -> Result<Tls1, Failure> {
    let mut tls = tls_to_edge(dial)?;
    tls.write_all_slices(&foxy::connect_request(target, &dial.pass.token))
        .map_err(|_| Failure::Io)?;
    opened(foxy::connect_status(&head(&mut tls)?)?)?;
    Ok(Tls1(tls))
}

fn head<S: Read>(io: &mut S) -> Result<Vec<u8>, Failure> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    // The budget bounds the whole head, not one byte of it: a drip that keeps every read inside the socket's arm still ends at the wall.
    let until = Instant::now() + crate::budgets::head_arrival();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(Failure::Frame);
        }
        if Instant::now() >= until {
            return Err(Failure::Stream);
        }
        read_exact(io, &mut byte).map_err(|_| Failure::Stream)?;
        head.push(byte[0]);
    }
    Ok(head)
}

/// HTTP/2 CONNECT: preface, settings, stream 1 and the status in its first header block. Stream 1 is the lane's only stream, so the codec needs no stream-id bookkeeping.
pub(crate) fn open_h2(dial: &FoxyDial, target: &str) -> Result<Tls2, Failure> {
    let mut block = Vec::with_capacity(96 + dial.pass.token.len());
    hpack::hpack_connect(target, &dial.pass.token, &mut block);
    open_h2_with(dial, &block)
}

/// One UDP target as its own H2 connection carrying CONNECT-UDP: a lane stays one stream on one connection, so a second target is a second connection.
pub(crate) fn open_udp(
    dial: &FoxyDial,
    target_host: &str,
    target_port: u16,
) -> Result<Tls2, Failure> {
    let edge = if dial.port == 443 {
        dial.host.clone()
    } else {
        format!("{}:{}", dial.host, dial.port)
    };
    let mut block = Vec::with_capacity(160 + dial.pass.token.len() + target_host.len());
    masque::connect_udp(
        &edge,
        target_host,
        target_port,
        &dial.pass.token,
        &mut block,
    );
    open_h2_with(dial, &block)
}

fn open_h2_with(dial: &FoxyDial, block: &[u8]) -> Result<Tls2, Failure> {
    let mut tls = tls_to_edge(dial)?;

    // The stream window arrives in the settings; the connection window only moves by a frame, so without this the tunnel is paced by a round trip for its first 64 KiB.
    let mut opening = Vec::with_capacity(48 + block.len());
    opening.extend_from_slice(frames::PREFACE);
    h2_frame(
        frames::SETTINGS,
        0,
        0,
        &frames::CLIENT_SETTINGS,
        &mut opening,
    );
    h2_frame(
        frames::WINDOW_UPDATE,
        0,
        0,
        &(frames::WINDOW - frames::DEFAULT_WINDOW).to_be_bytes(),
        &mut opening,
    );
    h2_frame(frames::HEADERS, 0x4, 1, block, &mut opening);
    tls.write_all(&opening).map_err(|_| Failure::Io)?;

    let mut lane = Tls2 {
        tls,
        // What this lane may put on the wire is only what the edge grants: the stream window arrives in its settings and the connection window only moves by a `WINDOW_UPDATE` on stream 0, so both start at the protocol default rather than at the window this lane asks the edge to keep open for it.
        window: foxy::flow::Window::new(
            i64::from(frames::DEFAULT_WINDOW),
            i64::from(frames::DEFAULT_WINDOW),
        ),
        max_frame: MAX_FRAME,
        carry: Vec::new(),
        at: 0,
        out: Vec::new(),
        capsule_buf: Vec::new(),
        pending_credit: 0,
        frame: FrameState::default(),
        fin: false,
    };
    let status = lane.await_status()?;
    opened(status)?;
    Ok(lane)
}

/// The stage the lane's edge dial lost, behind `FOXY_DEBUG`: a red leg is only actionable when it says where.
fn debug_stage(stage: &str) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: {stage}");
    }
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8], out: &mut Vec<u8>) {
    let frame = frames::H2Frame {
        kind,
        flags,
        stream,
        length: payload.len() as u32,
    };
    out.extend_from_slice(&frame.header());
    out.extend_from_slice(payload);
}

/// The two `WINDOW_UPDATE` frames a credit grants differ only by stream id, so their eighteen header bytes are constant and each call writes the increment into the two slots left zero here.
const CREDIT_TEMPLATE: [u8; 26] = {
    let mut out = [0u8; 26];
    // length 4, WINDOW_UPDATE, no flags, stream 1 at [0..9], stream 0 at [13..22].
    out[2] = 4;
    out[3] = frames::WINDOW_UPDATE;
    out[8] = 1;
    out[15] = 4;
    out[16] = frames::WINDOW_UPDATE;
    out
};

/// The credit a lane holds before it grants it back: the edge is granted a 16 MiB window to fill, so a held update cannot stall it, while a write per frame spends a record and a segment on 26 bytes the edge already owes us.
const CREDIT_FLOOR: u32 = 1 << 16;

/// A relay over a TLS stream that speaks HTTP/2: a caller writing bytes sees a DATA frame, a caller reading bytes sees one's payload.
pub(crate) struct Tls2 {
    tls: ferrox_core::tls::RustlsProvider<Connection>,
    window: foxy::flow::Window,
    max_frame: usize,
    /// Bytes read from a DATA frame the caller has not taken, with a cursor: draining would move what is left on every call.
    carry: Vec<u8>,
    at: usize,
    /// The frame this lane writes, reused so a relay allocates nothing per frame.
    out: Vec<u8>,
    /// Capsule-stream bytes not parsed yet: one capsule may span DATA frames, so frames accumulate here.
    capsule_buf: Vec<u8>,
    /// Bytes the edge has sent into its granted window that this lane has taken but not yet granted back: the update goes out when the held credit reaches `CREDIT_FLOOR`, never per frame.
    pending_credit: u32,
    frame: FrameState,
    fin: bool,
}

/// How much of the frame in flight has arrived: a read quantum expires between two socket reads, not between two frames.
#[derive(Default)]
struct FrameState {
    head: [u8; frames::H2_HEADER],
    head_at: usize,
    payload_at: usize,
    /// The DATA frame in flight that has not yet reached its caller: a caller's buffer smaller than the frame, or a quantum that expired mid-frame, leaves the rest here so the next read resumes into its buffer instead of re-fetching what was already paid for.
    data_at: u32,
    data_len: u32,
    /// The `END_STREAM` of the frame in flight: only the delivery that takes its last byte may tell the caller the stream ended.
    data_end: bool,
    /// Bytes handed into the caller's buffer by the current call: the frame's total cursor cannot tell one call's delivery from the next's, and the credit is owed per byte the caller actually got.
    delivered: u32,
}

/// Fills `buf` from `at` on, leaving `at` where the wire stopped: a timeout mid-buffer is a pause the next call resumes, and only a closed stream ends it.
fn fill_from<S: Read>(io: &mut S, buf: &mut [u8], at: &mut usize) -> std::io::Result<()> {
    while *at < buf.len() {
        match io.read(&mut buf[*at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(read) => *at += read,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Consumes the payload of the DATA frame in flight, straight into the destination: the destination gets exactly the room left in the frame, so no caller can be fed a byte of the next frame's header, and a quantum that expires mid-frame hands over what arrived and leaves the rest in `state`.
fn fill_data<S: Read>(
    io: &mut S,
    state: &mut FrameState,
    dst: &mut [u8],
) -> std::io::Result<usize> {
    let want = (state.data_len - state.data_at).min(dst.len() as u32) as usize;
    let mut at = 0usize;
    while at < want {
        match io.read(&mut dst[at..want]) {
            Ok(0) => {
                state.data_at += at as u32;
                state.delivered += at as u32;
                if at == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                return Ok(at);
            }
            Ok(read) => at += read,
            // The pause mid-frame is a handover, not a loss: what arrived sits in the caller's buffer, and the cursor says where the wire stopped.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                state.data_at += at as u32;
                state.delivered += at as u32;
                if at == 0 {
                    return Err(error);
                }
                return Ok(at);
            }
            Err(error) => {
                state.data_at += at as u32;
                state.delivered += at as u32;
                return Err(error);
            }
        }
    }
    state.data_at += at as u32;
    state.delivered += at as u32;
    Ok(at)
}

/// One frame off the wire; a socket timeout keeps its kind so a relay can tell an idle quantum from a dead peer.
/// A DATA frame whose caller has room goes straight into `dst` with no staging buffer between the lane and its caller: the answer carries the frame's end flag only on the delivery of its last byte, and a caller whose buffer filled mid-frame sees a zero-length marker, the bytes where it put them, and the remainder waiting in `state`.
fn read_frame<S: Read>(
    io: &mut S,
    state: &mut FrameState,
    out: &mut Vec<u8>,
    max_frame: usize,
    dst: &mut [u8],
) -> std::io::Result<frames::H2Frame> {
    if state.data_len > 0 {
        // A caller that cannot receive the rest of the frame into its buffer cannot receive it at all: the bytes already handed over are not replayable, and staging them again would be the loss this path exists to avoid.
        if dst.is_empty() {
            return Err(std::io::Error::other(
                "foxy: a resumed frame met a caller with no room",
            ));
        }
        fill_data(io, state, dst)?;
        let done = state.data_at == state.data_len;
        let frame = frames::H2Frame {
            kind: frames::DATA,
            flags: if done && state.data_end {
                frames::END_STREAM
            } else {
                0
            },
            stream: 0,
            length: if done { state.data_len } else { 0 },
        };
        if done {
            state.data_len = 0;
            state.data_at = 0;
            state.data_end = false;
        }
        return Ok(frame);
    }
    fill_from(io, &mut state.head, &mut state.head_at)?;
    let frame = frames::H2Frame::parse(&state.head)
        .ok_or_else(|| std::io::Error::other("foxy: a header that is not a frame"))?;
    if frame.kind == frames::DATA && frame.stream == 1 && frame.length > 0 && !dst.is_empty() {
        out.clear();
        state.data_len = frame.length;
        state.data_at = 0;
        state.data_end = frame.flags & frames::END_STREAM != 0;
        state.head_at = 0;
        state.head = [0u8; frames::H2_HEADER];
        fill_data(io, state, dst)?;
        if state.data_at < state.data_len {
            return Ok(frames::H2Frame {
                kind: frames::DATA,
                flags: 0,
                stream: 0,
                length: 0,
            });
        }
        let end = std::mem::take(&mut state.data_end);
        state.data_len = 0;
        state.data_at = 0;
        return Ok(frames::H2Frame {
            kind: frames::DATA,
            flags: if end { frames::END_STREAM } else { 0 },
            stream: frame.stream,
            length: frame.length,
        });
    }
    if state.payload_at == 0 {
        crate::proxy::resize_scratch(out, (frame.length as usize).min(max_frame));
    }
    fill_from(io, out, &mut state.payload_at)?;
    state.head_at = 0;
    state.payload_at = 0;
    state.head = [0u8; frames::H2_HEADER];
    Ok(frame)
}

impl Tls2 {
    pub(crate) fn set_read_quantum(&self, quantum: Duration) -> std::io::Result<()> {
        self.tls.get_ref().set_read_timeout(Some(quantum))
    }

    /// Reads one frame, hands it to `body` with the payload borrowed, and puts the buffer back.
    /// A `dst` with room takes a DATA frame's payload directly, and `body` then sees that payload already in the caller's buffer through `frame`'s length and end flag, with `payload` empty; the bytes this call delivered are counted in `frame_state.delivered`.
    fn with_frame<R>(
        &mut self,
        dst: &mut [u8],
        body: impl FnOnce(&mut Self, frames::H2Frame, &[u8]) -> R,
    ) -> std::io::Result<R> {
        let mut payload = std::mem::take(&mut self.out);
        self.frame.delivered = 0;
        let frame = read_frame(
            &mut self.tls,
            &mut self.frame,
            &mut payload,
            self.max_frame,
            dst,
        );
        let out = match frame {
            Ok(frame) => body(self, frame, &payload),
            Err(error) => {
                self.out = payload;
                return Err(error);
            }
        };
        self.out = payload;
        Ok(out)
    }

    /// Holds the credit a DATA payload grants back until it is worth a write: the edge has a 16 MiB window to ride on, so a held update is never the reason it stalls, while one 26-byte frame per inbound frame spends a TLS record and a segment to move a number the edge has already granted.
    fn credit(&mut self, len: usize) -> Result<(), Failure> {
        // Saturating because the held total is only ever a flush threshold: a lane that has taken the whole 16 MiB window and not yet granted any of it is served by the flush, not by an exact count.
        self.pending_credit = self
            .pending_credit
            .saturating_add(u32::try_from(len).unwrap_or(u32::MAX));
        if self.pending_credit >= CREDIT_FLOOR {
            return self.flush_credit();
        }
        Ok(())
    }

    /// Grants back everything the lane has taken: the held total is cleared whether or not the write lands, because a lane that cannot write has lost the flow the credit would have paced.
    fn flush_credit(&mut self) -> Result<(), Failure> {
        let increment = std::mem::take(&mut self.pending_credit).to_be_bytes();
        let mut out = CREDIT_TEMPLATE;
        out[9..13].copy_from_slice(&increment);
        out[22..26].copy_from_slice(&increment);
        self.tls.write_all(&out).map_err(|_| Failure::Io)
    }

    /// The credit this lane may spend on one frame: the edge grants the stream and the connection windows independently, so the tighter of the two is the limit.
    fn spend(&self) -> u32 {
        self.window.stream().min(self.window.connection())
    }

    /// Applies one `WINDOW_UPDATE` from the edge: stream 0 moves the connection credit and our own stream moves the stream credit; nothing else gets spent by receiving DATA.
    fn grant(&mut self, stream: u32, increment: u32) {
        if stream == 0 {
            self.window.add_connection(increment);
        } else if stream == 1 {
            self.window.add_stream(increment);
        }
    }

    fn ack(&mut self, kind: u8, payload: &[u8]) -> Result<(), Failure> {
        self.out.clear();
        h2_frame(kind, 0x1, 0, payload, &mut self.out);
        self.tls.write_all(&self.out).map_err(|_| Failure::Io)
    }

    /// A push promise is refused by name — the only stream the lane answers that is not the one it opened.
    fn refuse_push(&mut self) -> Result<(), Failure> {
        self.out.clear();
        h2_frame(frames::RST_STREAM, 0, 1, &8u32.to_be_bytes(), &mut self.out);
        self.tls.write_all(&self.out).map_err(|_| Failure::Io)
    }

    fn await_status(&mut self) -> Result<u16, Failure> {
        // The status is the h2 form of the head, so it waits the named head budget; unset, that is the same twenty seconds.
        let deadline = Instant::now() + crate::budgets::head_arrival();
        let mut block = Vec::with_capacity(64);
        while Instant::now() < deadline {
            let status = self
                .with_frame(&mut [], |lane, frame, payload| {
                    match frames::h2_event(frame, payload, 1) {
                        frames::H2Event::Headers { block: more, .. } => {
                            header_status(&mut block, more, frame.flags & frames::END_HEADERS != 0)
                        }
                        frames::H2Event::Settings { ack: false, .. } => {
                            let mut at = 0usize;
                            while let Some((id, value)) = frames::setting(payload, at) {
                                match id {
                                    4 => lane.window.reset_stream(value),
                                    5 => lane.max_frame = (value as usize).clamp(16_384, MAX_FRAME),
                                    _ => {}
                                }
                                at += 6;
                            }
                            lane.ack(frames::SETTINGS, &[]).map(|()| None)
                        }
                        // A DATA frame that arrives while the status is still out is payload the edge sent early: hold its credit like any other, and let the walk ignore the bytes until `END_STREAM` says the status itself is gone.
                        frames::H2Event::Data { payload, end } => {
                            lane.fin = end;
                            if !payload.is_empty() {
                                lane.credit(payload.len())?;
                            }
                            Ok(None)
                        }
                        frames::H2Event::Ping { ack: false, .. } => {
                            lane.ack(frames::PING, payload).map(|()| None)
                        }
                        frames::H2Event::Push => lane.refuse_push().map(|()| None),
                        frames::H2Event::Window { stream, increment } => {
                            lane.grant(stream, increment);
                            Ok(None)
                        }
                        frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                            Err(Failure::Stream)
                        }
                        // A status larger than one frame arrives in pieces: each fragment is appended and the block read once `END_HEADERS` says it is whole.
                        frames::H2Event::Other { kind } if kind == frames::CONTINUATION => {
                            header_status(
                                &mut block,
                                payload,
                                frame.flags & frames::END_HEADERS != 0,
                            )
                        }
                        _ => Ok(None),
                    }
                })
                .map_err(|_| Failure::Stream)??;
            if let Some(status) = status {
                return Ok(status);
            }
        }
        Err(Failure::Stream)
    }

    /// Hands the caller what it asked for out of `carry` and moves the cursor: a copy of bytes, never a move of what is left.
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let take = buf.len().min(self.carry.len() - self.at);
        buf[..take].copy_from_slice(&self.carry[self.at..self.at + take]);
        self.at += take;
        if self.at == self.carry.len() {
            self.carry.clear();
            self.at = 0;
        }
        take
    }

    /// Stages the tail of a payload the caller had no room for, after handing over the part it took: only that tail is copied twice.
    fn stage(&mut self, payload: &[u8], taken: usize) {
        if taken < payload.len() {
            self.carry.clear();
            self.carry.extend_from_slice(&payload[taken..]);
            self.at = 0;
        }
    }

    /// One UDP payload as one DATAGRAM capsule, split over DATA frames when needed: the capsule stream is byte-oriented and the reader reassembles. The frame header and the capsule header ride a fixed buffer and the payload keeps the caller's bytes, so the whole datagram is never staged before the record takes it.
    pub(crate) fn write_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let mut prefix = [0u8; 10];
        let plen = masque::datagram_prefix_into(&mut prefix, payload.len());
        let total = plen + payload.len();
        // The whole capsule rides or waits: a credit the lane has not been granted would be spent by the capsule's head, and a caller holding this lane cannot read the `WINDOW_UPDATE` that would grant it.
        if u32::try_from(total).unwrap_or(u32::MAX) > self.spend() {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let mut at = 0usize;
        while at < total {
            let frame = foxy::flow::frame_size(total - at, self.max_frame).min(self.spend());
            self.window.take(frame);
            let frame = frame as usize;
            let header = frames::H2Frame {
                kind: frames::DATA,
                flags: 0,
                stream: 1,
                length: frame as u32,
            }
            .header();
            let end = at + frame;
            // A frame boundary may fall inside the capsule header, so the header is a slice of `prefix` and the payload a slice of the caller's buffer, joined only where one frame spans both.
            if end <= plen {
                self.tls
                    .write_all_slices(&[&header[..], &prefix[at..end]])?;
            } else if at < plen {
                self.tls.write_all_slices(&[
                    &header[..],
                    &prefix[at..plen],
                    &payload[..end - plen],
                ])?;
            } else {
                self.tls
                    .write_all_slices(&[&header[..], &payload[at - plen..end - plen]])?;
            }
            at = end;
        }
        Ok(())
    }

    /// One UDP payload out of the capsule stream: frames accumulate until a whole DATAGRAM capsule parses; empty datagrams are skipped so `Ok(0)` stays the end of stream.
    pub(crate) fn read_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some((used, payload)) = masque::datagram_split(&self.capsule_buf) {
                let len = payload.len();
                let take = buf.len().min(len);
                buf[..take].copy_from_slice(&payload[..take]);
                self.capsule_buf.drain(..used);
                if len == 0 {
                    continue;
                }
                return Ok(len);
            }
            if self.fin {
                return Ok(0);
            }
            if self.capsule_buf.len() > DATAGRAM_BUF_MAX {
                self.capsule_buf.clear();
                return Err(std::io::Error::other(
                    "foxy: a capsule stream that never parses",
                ));
            }
            let read = self.with_frame(&mut [], |lane, frame, payload| -> std::io::Result<usize> {
                match frames::h2_event(frame, payload, 1) {
                    frames::H2Event::Data { payload, end } => {
                        let len = payload.len();
                        lane.fin = end;
                        if len > 0 {
                            lane.credit(len).map_err(io)?;
                        }
                        // A capsule is usually whole inside one DATA frame, so it is handed over where it lies and only the ones behind it staged; nothing is handed over while a split capsule waits, because stream order is datagram order.
                        if lane.capsule_buf.is_empty() {
                            if let Some((used, datagram)) = masque::datagram_split(payload) {
                                let take = buf.len().min(datagram.len());
                                buf[..take].copy_from_slice(&datagram[..take]);
                                lane.capsule_buf.extend_from_slice(&payload[used..]);
                                return Ok(datagram.len());
                            }
                        }
                        lane.capsule_buf.extend_from_slice(payload);
                        Ok(0)
                    }
                    frames::H2Event::Window { stream, increment } => {
                        lane.grant(stream, increment);
                        Ok(0)
                    }
                    frames::H2Event::Ping { ack: false, .. } => {
                        lane.ack(frames::PING, payload).map_err(io)?;
                        Ok(0)
                    }
                    frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                        lane.fin = true;
                        Ok(0)
                    }
                    _ => Ok(0),
                }
            });
            let read = read??;
            if read > 0 {
                return Ok(read);
            }
        }
    }
}

/// One HTTP/2 session to the edge, opening written and no stream yet, for the live check of what the edge does with a second CONNECT — no loopback edge can stand in for the real one.
#[cfg(test)]
pub(crate) fn raw_h2_session(
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    open_h2_with_raw(dial)
}

/// The dial half of `open_h2_with`, before any stream.
#[cfg(test)]
fn open_h2_with_raw(
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    let mut tls = tls_to_edge(dial)?;
    let mut opening = Vec::with_capacity(48);
    opening.extend_from_slice(frames::PREFACE);
    h2_frame(
        frames::SETTINGS,
        0,
        0,
        &frames::CLIENT_SETTINGS,
        &mut opening,
    );
    h2_frame(
        frames::WINDOW_UPDATE,
        0,
        0,
        &(frames::WINDOW - frames::DEFAULT_WINDOW).to_be_bytes(),
        &mut opening,
    );
    tls.write_all(&opening).map_err(|_| Failure::Io)?;
    tls.flush().map_err(|_| Failure::Io)?;
    Ok(tls)
}

impl Write for Tls2 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = foxy::flow::frame_size(buf.len(), self.max_frame).min(self.spend());
        if frame == 0 {
            return Ok(0);
        }
        self.window.take(frame);
        let frame = frame as usize;
        // Header and payload in one write: two writes would be two TLS records, and the record boundary is on the wire.
        let header = frames::H2Frame {
            kind: frames::DATA,
            flags: 0,
            stream: 1,
            length: frame as u32,
        }
        .header();
        self.tls.write_parts(&header, &buf[..frame])?;
        Ok(frame as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tls.flush()
    }
}

impl Read for Tls2 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.at < self.carry.len() {
                return Ok(self.take(buf));
            }
            if self.fin {
                return Ok(0);
            }
            // The payload is copied once, by the frame reader, straight into the caller's buffer: nothing is staged between the lane and its caller, and a frame the caller has no room left for resumes in the caller's own space on the next read.
            let read = self.with_frame(buf, |lane, frame, payload| -> std::io::Result<usize> {
                // A DATA frame the reader delivered arrives with the wire's payload already in the caller's buffer and none left in the lane's hands: what this call handed over is counted in `delivered`, and the credit is owed for exactly that.
                if frame.kind == frames::DATA && payload.is_empty() {
                    lane.fin = frame.flags & frames::END_STREAM != 0;
                    let got = lane.frame.delivered as usize;
                    if got > 0 {
                        lane.credit(got).map_err(io)?;
                    }
                    return Ok(got);
                }
                match frames::h2_event(frame, payload, 1) {
                    frames::H2Event::Data { payload, end } => {
                        // Only reachable for a caller that asked for nothing: the frame stages whole, and a later read with room is fed from the stage.
                        let len = payload.len();
                        lane.stage(payload, 0);
                        lane.fin = end;
                        if len > 0 {
                            lane.credit(len).map_err(io)?;
                        }
                        Ok(0)
                    }
                    frames::H2Event::Window { stream, increment } => {
                        lane.grant(stream, increment);
                        Ok(0)
                    }
                    frames::H2Event::Ping { ack: false, .. } => {
                        lane.ack(frames::PING, payload).map_err(io)?;
                        Ok(0)
                    }
                    frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                        lane.fin = true;
                        Ok(0)
                    }
                    _ => Ok(0),
                }
            });
            let read = read??;
            if read > 0 {
                return Ok(read);
            }
        }
    }
}

/// The HTTP/1.1 relay: bytes in, bytes out, once the status has been read.
pub(crate) struct Tls1(pub(crate) ferrox_core::tls::RustlsProvider<Connection>);

/// Undecodable-block dump behind `FOXY_DEBUG`: the hex of a header block no codec here reads, so a red live run names the encoding.
fn debug_block(block: &[u8]) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: undecodable header block {block:02x?}");
    }
}

/// Appends one header-block fragment and reads the status only once the peer's `END_HEADERS` says the block is whole; a partial block is never parsed.
fn header_status(
    block: &mut Vec<u8>,
    piece: &[u8],
    end_headers: bool,
) -> Result<Option<u16>, Failure> {
    block.extend_from_slice(piece);
    if !end_headers {
        return Ok(None);
    }
    hpack::hpack_status(block).map(Some).ok_or_else(|| {
        debug_block(block);
        Failure::Frame
    })
}

/// Bounds one blocking read so a relay holding one lock for both directions can interleave: the backward read returns `WouldBlock` within the quantum instead of holding the lock.
impl Tls1 {
    pub(crate) fn set_read_quantum(&self, quantum: Duration) -> std::io::Result<()> {
        self.0.get_ref().set_read_timeout(Some(quantum))
    }
}

impl Write for Tls1 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Read for Tls1 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// HTTP/3 CONNECT over one pooled QUIC connection (control stream, request stream, one HEADERS each way, DATA both ways — the pooling is what makes QUIC worth having); ending the lane is what hands the stream back to the pool, and a lane that never got built hands it back the same way.
pub(crate) type Quic = crate::quic::PooledStream;

pub(crate) struct H3 {
    /// The stream this lane rides, and the pool entry it owes back when the lane ends.
    quic: Quic,
    /// The request stream's read window, filled a header's worth at a time — the DATA payload it frames lands in the caller, not here: `head[..filled]` has arrived, `head[carried..filled]` is unparsed.
    head: Vec<u8>,
    filled: usize,
    carried: usize,
    /// Bytes of the DATA frame being delivered that the caller has not asked for yet: a frame spans reads from here, straight from the stream into each call's own buffer.
    body: usize,
    /// The frame this lane writes, reused so a relay allocates nothing per frame.
    out: Vec<u8>,
    /// Capsule-stream bytes no whole DATAGRAM capsule has consumed yet: one capsule may span DATA frames, so frames accumulate only here.
    capsule_buf: Vec<u8>,
    fin: bool,
    deadline: Instant,
    /// How long this lane waits for a CONNECT answer: a carrier's own open gets the head timeout, a disposable probe gets the budget its caller names.
    head_wait: Duration,
    /// Bounds one blocking `Read::read` the way the socket timeout bounds TCP carriers: set, it returns `WouldBlock` after the quantum so a one-lock relay can interleave.
    quantum: Option<Duration>,
}

impl H3 {
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) {
        self.quantum = Some(quantum);
    }

    pub(crate) fn open(dial: &FoxyDial, target: &str, quic: Quic) -> Result<Self, Failure> {
        Self::open_within(dial, target, quic, HEADER_TIMEOUT)
    }

    pub(crate) fn open_within(
        dial: &FoxyDial,
        target: &str,
        quic: Quic,
        head_wait: Duration,
    ) -> Result<Self, Failure> {
        let mut lane = Self {
            quic,
            head: Self::open_window(),
            filled: 0,
            carried: 0,
            body: 0,
            out: Vec::new(),
            capsule_buf: Vec::new(),
            fin: false,
            deadline: Instant::now(),
            head_wait,
            quantum: None,
        };
        let status = lane.request(target, &dial.pass.token)?;
        opened(status)?;
        Ok(lane)
    }

    fn with_conn<T>(&mut self, body: impl FnOnce(&mut quiche::Connection) -> T) -> Option<T> {
        let mut guard = self.quic.conn.lock().ok()?;
        let out = body(&mut guard);
        crate::quic::flush_egress(&mut guard, &self.quic.sock);
        Some(out)
    }

    /// Read window opened into its uninitialised tail rather than zero-filled: the stream fills what it reads and the walk never reads past what arrived.
    fn open_window() -> Vec<u8> {
        let mut window = Vec::with_capacity(H3_WINDOW);
        crate::proxy::resize_scratch(&mut window, H3_WINDOW);
        window
    }

    /// The HTTP/3 opening a fresh connection carries exactly once: a complete SETTINGS plus QPACK encoder/decoder hellos, literal-only with no dynamic table; a truncated SETTINGS waits forever and a second control stream is a connection error, and nothing is ever finished.
    pub(crate) fn h3_opening() -> [(u64, Vec<u8>); 3] {
        let mut control = Vec::with_capacity(16);
        frames::quic_varint(&mut control, 0x00);
        let settings = [0x01u8, 0x00, 0x07, 0x00, 0x08, 0x00];
        frames::quic_varint(&mut control, 0x04);
        frames::quic_varint(&mut control, settings.len() as u64);
        control.extend_from_slice(&settings);
        let mut encoder = Vec::with_capacity(2);
        frames::quic_varint(&mut encoder, 0x02);
        let mut decoder = Vec::with_capacity(2);
        frames::quic_varint(&mut decoder, 0x03);
        [(CONTROL_STREAM, control), (6, encoder), (10, decoder)]
    }

    /// One UDP target as its own stream on a shared HTTP/3 connection: the extended CONNECT names `capsule-protocol: ?1` and datagrams ride DATAGRAM capsules — RFC 9298, the same capsule stream the HTTP/2 edge carries.
    pub(crate) fn open_udp(
        dial: &FoxyDial,
        target_host: &str,
        target_port: u16,
        quic: Quic,
    ) -> Result<Self, Failure> {
        let mut lane = Self {
            quic,
            head: Self::open_window(),
            filled: 0,
            carried: 0,
            body: 0,
            out: Vec::new(),
            capsule_buf: Vec::new(),
            fin: false,
            deadline: Instant::now(),
            head_wait: HEADER_TIMEOUT,
            quantum: None,
        };
        let status = lane.udp_request(dial, target_host, target_port)?;
        opened(status)?;
        Ok(lane)
    }

    /// One CONNECT-IP tunnel as its own stream on a shared HTTP/3 connection: the request names `connect-ip` and `capsule-protocol: ?1`, and the address request that follows opens a tunnel carrying every destination.
    pub(crate) fn open_ip(dial: &FoxyDial, quic: Quic) -> Result<Self, Failure> {
        let mut lane = Self {
            quic,
            head: Self::open_window(),
            filled: 0,
            carried: 0,
            body: 0,
            out: Vec::new(),
            capsule_buf: Vec::new(),
            fin: false,
            deadline: Instant::now(),
            head_wait: HEADER_TIMEOUT,
            quantum: None,
        };
        let edge = if dial.port == 443 {
            dial.host.clone()
        } else {
            format!("{}:{}", dial.host, dial.port)
        };
        let mut block = Vec::with_capacity(160 + dial.pass.token.len());
        connectip::connect_ip_qpack(&edge, "*", 0, &dial.pass.token, &mut block);
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        lane.send(lane.quic.id, &frame, false)?;
        let status = lane.read_head()?;
        opened(status)?;
        let mut request = Vec::new();
        connectip::address_request(1, 4, &[0, 0, 0, 0], &mut request);
        connectip::address_request(2, 6, &[0; 16], &mut request);
        // The request rides one DATA frame the way a packet does: capsules here are framed, and raw bytes would read as a frame header.
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, request.len() as u64);
        lane.send_pair(lane.quic.id, &head[..hl], &request)?;
        Ok(lane)
    }

    fn udp_request(
        &mut self,
        dial: &FoxyDial,
        target_host: &str,
        target_port: u16,
    ) -> Result<u16, Failure> {
        let edge = if dial.port == 443 {
            dial.host.clone()
        } else {
            format!("{}:{}", dial.host, dial.port)
        };
        let mut block = Vec::with_capacity(160 + dial.pass.token.len() + target_host.len());
        masque::connect_udp_qpack(
            &edge,
            target_host,
            target_port,
            &dial.pass.token,
            &mut block,
        );
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        self.send(self.quic.id, &frame, false)?;
        self.read_head()
    }

    /// One pump of the request stream into the capsule buffer: whole DATA frames are staged where they lie, and the cursor is shared with the frame walk because a byte spent here cannot be spent again.
    fn fill_capsules(&mut self) -> Result<(), Failure> {
        if H3_WINDOW - self.filled < 16 {
            self.head.copy_within(self.carried..self.filled, 0);
            self.filled -= self.carried;
            self.carried = 0;
        }
        self.deadline = Instant::now() + HEADER_TIMEOUT;
        self.fill()?;
        let mut at = self.carried;
        while at < self.filled {
            let mut head = 0usize;
            let Some(frame) = frames::h3_frame(&self.head[at..self.filled], &mut head) else {
                break;
            };
            let end = match at
                .checked_add(head)
                .and_then(|body| body.checked_add(frame.length as usize))
            {
                Some(end) if end <= self.filled => end,
                _ => break,
            };
            let body = at + head;
            if matches!(
                frames::h3_event(frame, &self.head[body..end]),
                frames::H3Event::Data { .. }
            ) {
                self.capsule_buf.extend_from_slice(&self.head[body..end]);
            }
            at = end;
        }
        self.carried = at;
        Ok(())
    }

    /// Sends the address request and reads the assignment: without one the lane has no source address to write into a packet, and a proxy that refuses is refused rather than guessed at.
    pub(crate) fn address_assign(
        &mut self,
    ) -> Result<Option<ferrox_core::foxy::connectip::Assigned>, Failure> {
        let deadline = Instant::now() + HEADER_TIMEOUT;
        let mut assigned = None;
        while Instant::now() < deadline {
            if let Some((used, capsule)) = connectip::capsule_split(&self.capsule_buf) {
                let (granted, quit) = match capsule {
                    connectip::Capsule::AddressAssign(body) => {
                        let mut into = Vec::new();
                        if connectip::address_assign(body, &mut into).is_none() {
                            (None, true)
                        } else {
                            (into.into_iter().find(|grant| !grant.refused()), false)
                        }
                    }
                    connectip::Capsule::RouteAdvert(body) => {
                        let mut routes = Vec::new();
                        let _ = connectip::route_advert(body, &mut routes);
                        (None, false)
                    }
                    _ => (None, false),
                };
                self.capsule_buf.drain(..used);
                if let Some(granted) = granted {
                    assigned = Some(granted);
                }
                if quit {
                    return Err(Failure::Frame);
                }
                if assigned.is_some() {
                    return Ok(assigned);
                }
                continue;
            }
            if self.fin {
                return Err(Failure::Stream);
            }
            self.fill_capsules().map_err(io)?;
        }
        Ok(assigned)
    }

    /// One IP packet, as a frame's payload the caller takes whole.
    pub(crate) fn read_ip(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let started = Instant::now();
        loop {
            if let Some((used, capsule)) = connectip::capsule_split(&self.capsule_buf) {
                let packet = if let connectip::Capsule::Datagram(packet) = capsule {
                    packet.to_vec()
                } else {
                    Vec::new()
                };
                self.capsule_buf.drain(..used);
                if !packet.is_empty() {
                    return Ok(Some(packet));
                }
                continue;
            }
            if self.fin {
                return Ok(None);
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.fill_capsules().map_err(io)?;
        }
    }

    /// One UDP payload as one DATAGRAM capsule inside one DATA frame: the capsule's length is its own, so the frame's length is issued first and the capsule follows — one buffer, one stream write.
    pub(crate) fn write_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        masque::datagram_encode(payload, &mut out);
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, out.len() as u64);
        let sent = self.send_pair(self.quic.id, &head[..hl], &out);
        self.out = out;
        sent.map_err(io)?;
        Ok(())
    }

    /// One UDP payload out of the capsule stream: DATA frames are parsed until a whole DATAGRAM capsule appears, capsules that span frames accumulate, and empty datagrams are skipped so `Ok(0)` stays the end of stream.
    pub(crate) fn read_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let started = Instant::now();
        // One wait per call, armed from its start: re-armed inside the loop the check below could never see an expiry, so a peer that stopped answering cost this lane nothing but its own parking.
        self.deadline = started + HEADER_TIMEOUT;
        loop {
            if let Some((used, payload)) = masque::datagram_split(&self.capsule_buf) {
                let take = buf.len().min(payload.len());
                buf[..take].copy_from_slice(&payload[..take]);
                let len = payload.len();
                self.capsule_buf.drain(..used);
                if len == 0 {
                    continue;
                }
                return Ok(len);
            }
            if self.fin {
                return Ok(0);
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if self.capsule_buf.len() > DATAGRAM_BUF_MAX {
                self.capsule_buf.clear();
                return Err(std::io::Error::other(
                    "foxy: a capsule stream that never parses",
                ));
            }
            self.fill().map_err(io)?;
            // A capsule is usually whole inside one DATA frame, so a frame's payload is parsed where it lies and only a split capsule staged: the same one copy the tunnel read makes.
            let mut at = self.carried;
            while at < self.filled {
                let mut head = 0usize;
                let Some(frame) = frames::h3_frame(&self.head[at..self.filled], &mut head) else {
                    break;
                };
                let end = match at
                    .checked_add(head)
                    .and_then(|body| body.checked_add(frame.length as usize))
                {
                    Some(end) if end <= self.filled => end,
                    _ => break,
                };
                let body = at + head;
                match frames::h3_event(frame, &self.head[body..end]) {
                    frames::H3Event::Data {
                        payload,
                        end: stream_end,
                    } => {
                        self.fin = stream_end;
                        // A capsule is usually whole inside one DATA frame, so it is handed over where it lies and only the ones behind it staged; nothing is handed over while a split capsule waits, because stream order is datagram order.
                        if self.capsule_buf.is_empty() {
                            if let Some((used, datagram)) = masque::datagram_split(payload) {
                                let take = buf.len().min(datagram.len());
                                buf[..take].copy_from_slice(&datagram[..take]);
                                let len = datagram.len();
                                self.capsule_buf.extend_from_slice(&payload[used..]);
                                self.carried = end;
                                if len == 0 {
                                    at = end;
                                    break;
                                }
                                return Ok(len);
                            }
                        }
                        self.capsule_buf.extend_from_slice(payload);
                    }
                    frames::H3Event::Reset { .. } | frames::H3Event::GoAway { .. } => {
                        self.fin = true;
                        self.carried = self.filled;
                        return Ok(0);
                    }
                    _ => {}
                }
                at = end;
            }
            self.carried = at;
        }
    }

    fn request(&mut self, target: &str, bearer: &str) -> Result<u16, Failure> {
        let mut block = Vec::with_capacity(96 + bearer.len());
        hpack::qpack_connect(target, bearer, &mut block);
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        self.send(self.quic.id, &frame, false)?;
        self.read_head()
    }

    fn send(&mut self, stream: u64, buf: &[u8], fin: bool) -> Result<(), Failure> {
        let deadline = Instant::now() + SEND_WAIT;
        let mut rest = buf;
        while !rest.is_empty() {
            let written = self
                .with_conn(|conn| conn.stream_send(stream, rest, false))
                .ok_or(Failure::Io)?
                .map_err(|_| Failure::Io)?;
            rest = &rest[written..];
            if written == 0 {
                if Instant::now() >= deadline {
                    return Err(Failure::Io);
                }
                self.pump(Duration::from_millis(5));
            }
        }
        if fin {
            self.fin(stream)?;
        }
        Ok(())
    }

    /// The frame's header and its payload accepted under one lock and flushed once: two `send` calls pay the connection mutex twice, and the egress sweep after the header alone puts those nine bytes in a datagram of their own.
    fn send_pair(&mut self, stream: u64, head: &[u8], payload: &[u8]) -> Result<(), Failure> {
        let deadline = Instant::now() + SEND_WAIT;
        let (mut head, mut payload) = (head, payload);
        loop {
            let (took_head, took_body) = self
                .with_conn(|conn| {
                    let n = conn.stream_send(stream, head, false).ok()?;
                    if n < head.len() || payload.is_empty() {
                        return Some((n, 0));
                    }
                    let m = conn.stream_send(stream, payload, false).ok()?;
                    Some((n, m))
                })
                .ok_or(Failure::Io)?
                .ok_or(Failure::Io)?;
            head = &head[took_head..];
            payload = &payload[took_body..];
            if head.is_empty() && payload.is_empty() {
                return Ok(());
            }
            if took_head + took_body == 0 {
                if Instant::now() >= deadline {
                    return Err(Failure::Io);
                }
                self.pump(Duration::from_millis(5));
            }
        }
    }

    fn fin(&mut self, stream: u64) -> Result<(), Failure> {
        let sent = self
            .with_conn(|conn| conn.stream_send(stream, &[], true))
            .ok_or(Failure::Io)?;
        sent.map(|_| ()).map_err(|_| Failure::Io)
    }

    fn pump(&mut self, wait: Duration) {
        let local = self.quic.local;
        if let Ok(mut guard) = self.quic.conn.lock() {
            crate::quic::pump_once(&mut guard, &self.quic.sock, local, wait);
        }
    }

    /// Pulls the request stream until a whole HEADERS frame has arrived, then reads the status; bytes read past that frame stay buffered because the edge's first DATA frame is the tunnel, not a header.
    fn read_head(&mut self) -> Result<u16, Failure> {
        self.deadline = Instant::now() + self.head_wait;
        while Instant::now() < self.deadline {
            if let Some(status) = Self::header_in(&self.head[self.carried..self.filled])? {
                return Ok(status);
            }
            self.fill()?;
        }
        Err(Failure::Stream)
    }

    /// The status of the first complete HEADERS frame in `bytes`, and how much of it that frame was.
    fn header_in(bytes: &[u8]) -> Result<Option<u16>, Failure> {
        let mut at = 0usize;
        let Some(frame) = frames::h3_frame(bytes, &mut at) else {
            return Ok(None);
        };
        let Some(end) = at.checked_add(frame.length as usize) else {
            return Err(Failure::Frame);
        };
        let Some(body) = bytes.get(at..end) else {
            return Ok(None);
        };
        match frames::h3_event(frame, body) {
            frames::H3Event::Headers { block, .. } => {
                hpack::qpack_status(block).map(Some).ok_or(Failure::Frame)
            }
            frames::H3Event::Reset { .. } | frames::H3Event::GoAway { .. } => Err(Failure::Stream),
            _ => Ok(None),
        }
    }

    /// One read from the request stream straight into the window's spare room, or a pump when nothing arrived — the same two answers a QUIC stream gives, minus the second copy.
    fn fill(&mut self) -> Result<(), Failure> {
        let id = self.quic.id;
        let mut window = std::mem::take(&mut self.head);
        let filled = self.filled;
        let room = window.len() - filled;
        let room = if room == 0 {
            window.resize(filled + H3_WINDOW, 0);
            H3_WINDOW
        } else {
            room
        };
        let read = self.with_conn(|conn| conn.stream_recv(id, &mut window[filled..filled + room]));
        self.head = window;
        match read {
            Some(Ok((0, true))) => Err(Failure::Stream),
            Some(Ok((read, _))) => {
                self.filled += read;
                Ok(())
            }
            Some(Err(quiche::Error::Done)) => {
                if Instant::now() >= self.deadline {
                    return Err(Failure::Stream);
                }
                self.pump(Duration::from_millis(5));
                Ok(())
            }
            _ => Err(Failure::Io),
        }
    }

    /// The next frame's header, a peek's worth at most: the DATA payload the header names never passes through the window, so what sits unparsed here is always smaller than a header and its spill.
    fn fill_peek(&mut self) -> Result<(), Failure> {
        if self.head.len() - self.filled < H3_PEEK {
            self.head.copy_within(self.carried..self.filled, 0);
            self.filled -= self.carried;
            self.carried = 0;
        }
        // A window filled by the head walk's whole-frame read can still run out of tail; nothing is unparsed at a header boundary, so the window restarts empty rather than handing the stream a zero-length buffer.
        if self.filled == self.head.len() {
            self.filled = 0;
        }
        let id = self.quic.id;
        let mut window = std::mem::take(&mut self.head);
        let filled = self.filled;
        let room = H3_PEEK.min(window.len() - filled);
        let read = self.with_conn(|conn| conn.stream_recv(id, &mut window[filled..filled + room]));
        self.head = window;
        match read {
            Some(Ok((0, true))) => Err(Failure::Stream),
            Some(Ok((read, _))) => {
                self.filled += read;
                Ok(())
            }
            Some(Err(quiche::Error::Done)) => {
                if Instant::now() >= self.deadline {
                    return Err(Failure::Stream);
                }
                self.pump(Duration::from_millis(5));
                Ok(())
            }
            _ => Err(Failure::Io),
        }
    }

    /// Delivers the frame in flight: what already sits in the window moves first — those bytes crossed once before this lane knew their length — and the rest arrives from the stream straight into the caller's buffer. A quantum that expires mid-frame hands back what was delivered; the next read resumes at the cursor.
    fn body_into(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let started = Instant::now();
        self.deadline = started + self.head_wait;
        let mut delivered = 0usize;
        while self.body > 0 && delivered < buf.len() {
            if self.carried < self.filled {
                let n = (self.filled - self.carried)
                    .min(self.body)
                    .min(buf.len() - delivered);
                buf[delivered..delivered + n]
                    .copy_from_slice(&self.head[self.carried..self.carried + n]);
                self.carried += n;
                self.body -= n;
                delivered += n;
                continue;
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                break;
            }
            let want = self.body.min(buf.len() - delivered);
            let id = self.quic.id;
            let read =
                self.with_conn(|conn| conn.stream_recv(id, &mut buf[delivered..delivered + want]));
            match read {
                Some(Ok((0, true))) => return Err(io(Failure::Stream)),
                Some(Ok((read, _))) => {
                    delivered += read;
                    self.body -= read;
                }
                Some(Err(quiche::Error::Done)) => {
                    if Instant::now() >= self.deadline {
                        return Err(io(Failure::Stream));
                    }
                    self.pump(Duration::from_millis(5));
                }
                _ => return Err(io(Failure::Io)),
            }
        }
        Ok(delivered)
    }
}

impl Write for H3 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = foxy::flow::frame_size(buf.len(), H3_FRAME);
        if frame == 0 {
            return Ok(0);
        }
        // The frame's varints are their own send and the payload keeps the caller's buffer: quiche copies every slice it is handed, so staging the two together would be a second copy of every byte.
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, u64::from(frame));
        self.send_pair(self.quic.id, &head[..hl], &buf[..frame as usize])
            .map_err(io)?;
        Ok(frame as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.with_conn(|_| ()).ok_or_else(|| io(Failure::Io))
    }
}

impl Read for H3 {
    /// The tunnel, not the stream: the caller gets the payload of DATA frames, because a frame header read as payload carries the tunnel's own framing into every byte after it.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.body > 0 {
            return self.body_into(buf);
        }
        let started = Instant::now();
        // One wait per read call, armed from its own start: re-arming inside the loop would let a peer that answers nothing park this lane forever, where the socket carriers' read timeout costs the caller `head_wait` and returns.
        self.deadline = started + self.head_wait;
        loop {
            if self.fin {
                return Ok(0);
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let mut head = 0usize;
            let Some(frame) = frames::h3_frame(&self.head[self.carried..self.filled], &mut head)
            else {
                self.fill_peek().map_err(io)?;
                continue;
            };
            let Some(body_at) = self.carried.checked_add(head) else {
                return Err(io(Failure::Frame));
            };
            let Ok(length) = usize::try_from(frame.length) else {
                return Err(io(Failure::Stream));
            };
            if frame.kind == frames::H3_DATA {
                self.carried = body_at;
                self.body = length;
                return self.body_into(buf);
            }
            let Some(end) = body_at.checked_add(length) else {
                return Err(io(Failure::Frame));
            };
            if end > self.filled {
                // A frame bigger than the window would leave fill() indexing a full tail out of range; at a boundary with nothing unparsed the window restarts empty instead of growing.
                if self.carried == self.filled {
                    self.filled = 0;
                    self.carried = 0;
                }
                self.fill().map_err(io)?;
                continue;
            }
            match frames::h3_event(frame, &self.head[body_at..end]) {
                frames::H3Event::Reset { .. } | frames::H3Event::GoAway { .. } => {
                    self.fin = true;
                    self.carried = self.filled;
                }
                _ => self.carried = end,
            }
        }
    }
}

/// Reads the two-letter country out of whatever the probe answered: a `loc=XX` line, a `"countryCode":"XX"` field, or nothing — a probe that cannot be read is not evidence.
#[must_use]
pub(crate) fn exit_country(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    if let Some(after) = text.split_once("loc=") {
        let code: String = after
            .1
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
            return Some(code);
        }
    }
    let key = "\"countryCode\":\"";
    let at = text.find(key)? + key.len();
    text.get(at..at + 2)
        .filter(|code| code.chars().all(|c| c.is_ascii_uppercase()))
        .map(str::to_owned)
}

fn io(failure: Failure) -> std::io::Error {
    std::io::Error::other(failure.to_string())
}

/// One CONNECT-UDP lane on whichever carrier the edge answers: a UDP flow is a capsule stream either way, and which carrier carries it is the dial's question.
pub(crate) enum Datagram {
    H2(Box<Tls2>),
    H3(Box<H3>),
}

/// One CONNECT-IP lane, on whichever carrier the edge answers: there is one tunnel for *every* destination at once, so the lane carries an IP address the proxy assigned it and demultiplexes by the destination in the packet; the tunnel opens by an address request and the assignment, both arriving as capsules on the stream the packets ride.
pub(crate) enum Ip {
    /// HTTP/2, whose frames carry the capsule stream as their payload.
    H2(Box<Tls2>),
    /// HTTP/3, whose frames carry it the same way.
    H3(Box<H3>),
}

impl Ip {
    /// Opens the tunnel on the carrier the dial names, with the address the proxy assigned.
    pub(crate) fn open(
        dial: &FoxyDial,
        quic: Option<Quic>,
    ) -> Result<(Self, Option<ferrox_core::foxy::connectip::Assigned>), Failure> {
        match (quic, dial.carrier) {
            (Some(quic), _) => {
                let mut lane = H3::open_ip(dial, quic)?;
                let assigned = lane.address_assign()?;
                Ok((Self::H3(Box::new(lane)), assigned))
            }
            (None, Carrier::H1) => Err(Failure::Frame),
            (None, _) => {
                let lane = open_ip_h2(dial)?;
                Ok((Self::H2(Box::new(lane.0)), lane.1))
            }
        }
    }

    /// Flushes what a write staged so the edge reads it: a lane over a TLS session writes into the session, and the record leaves on the flush.
    pub(crate) fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::H2(lane) => lane.tls.flush(),
            Self::H3(lane) => lane.flush(),
        }
    }

    /// One UDP payload out, as one IP packet: the build is the codec's, the frame that carries it is the carrier's.
    pub(crate) fn write(
        &mut self,
        source: &[u8],
        destination: &[u8],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> std::io::Result<bool> {
        let mut packet = Vec::new();
        let built = ferrox_core::foxy::connectip::udp_datagram(
            &ferrox_core::foxy::connectip::UdpDatagram {
                source,
                destination,
                source_port,
                destination_port,
                payload,
            },
            &mut packet,
        );
        if !built {
            return Ok(false);
        }
        // The packet leaves on the flush rather than waiting for the next write: these are datagrams, and one that waits is one the peer never sees.
        match self {
            Self::H2(lane) => lane.write_datagram(&packet).map(|()| true),
            Self::H3(lane) => lane.write_datagram(&packet).map(|()| true),
        }
    }

    /// One UDP payload in, as one IP packet: the destination is what a reply is addressed to, and `None` is a frame that is not a datagram yet.
    pub(crate) fn read(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        match self {
            Self::H2(lane) => lane.read_ip(),
            Self::H3(lane) => lane.read_ip(),
        }
    }

    /// Bounds one blocking read on either carrier, so a tunnel nobody has answered parks its relay on the quantum's tick rather than forever.
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        match self {
            Self::H2(lane) => lane.set_read_quantum(quantum),
            Self::H3(lane) => {
                lane.set_read_quantum(quantum);
                Ok(())
            }
        }
    }
}

/// One CONNECT-IP lane as its own H2 connection: the tunnel carries UDP datagrams for every destination, so a lane is one connection rather than a stream per target.
pub(crate) fn open_ip_h2(
    dial: &FoxyDial,
) -> Result<(Tls2, Option<ferrox_core::foxy::connectip::Assigned>), Failure> {
    let edge = if dial.port == 443 {
        dial.host.clone()
    } else {
        format!("{}:{}", dial.host, dial.port)
    };
    let mut block = Vec::with_capacity(160 + dial.pass.token.len());
    connectip::connect_ip(&edge, "*", 0, &dial.pass.token, &mut block);
    let mut lane = open_h2_with(dial, &block)?;
    let assigned = lane.address_assign()?;
    Ok((lane, assigned))
}

impl Tls2 {
    /// Sends the address request and reads the assignment: without one the lane has no source address to write into a packet, and a proxy that refuses is refused rather than guessed at.
    fn address_assign(
        &mut self,
    ) -> Result<Option<ferrox_core::foxy::connectip::Assigned>, Failure> {
        let mut request = Vec::new();
        connectip::address_request(1, 4, &[0, 0, 0, 0], &mut request);
        connectip::address_request(2, 6, &[0; 16], &mut request);
        self.out.clear();
        self.out.extend_from_slice(&request);
        // The request rides the capsule stream inside DATA frames, the way a packet does: raw TLS bytes would desynchronise the edge's frame walk.
        let mut at = 0usize;
        let send_by = Instant::now() + HEADER_TIMEOUT;
        while at < self.out.len() {
            let frame =
                foxy::flow::frame_size(self.out.len() - at, self.max_frame).min(self.spend());
            if frame == 0 {
                if Instant::now() >= send_by {
                    return Err(Failure::Stream);
                }
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            self.window.take(frame);
            let frame = frame as usize;
            let header = frames::H2Frame {
                kind: frames::DATA,
                flags: 0,
                stream: 1,
                length: frame as u32,
            }
            .header();
            self.tls
                .write_parts(&header, &self.out[at..at + frame])
                .map_err(|_| Failure::Io)?;
            at += frame;
        }

        let deadline = Instant::now() + HEADER_TIMEOUT;
        let mut assigned = None;
        while Instant::now() < deadline {
            if let Some((used, capsule)) = connectip::capsule_split(&self.capsule_buf) {
                // The capsule is read before the buffer is drained, so a refused or granted answer costs no copy of it.
                let (granted, quit) = match capsule {
                    connectip::Capsule::AddressAssign(body) => {
                        let mut into = Vec::new();
                        if connectip::address_assign(body, &mut into).is_none() {
                            (None, true)
                        } else {
                            (into.into_iter().find(|grant| !grant.refused()), false)
                        }
                    }
                    connectip::Capsule::RouteAdvert(body) => {
                        let mut routes = Vec::new();
                        let _ = connectip::route_advert(body, &mut routes);
                        (None, false)
                    }
                    _ => (None, false),
                };
                self.capsule_buf.drain(..used);
                if let Some(granted) = granted {
                    assigned = Some(granted);
                }
                if quit {
                    return Err(Failure::Frame);
                }
                if assigned.is_some() {
                    return Ok(assigned);
                }
                continue;
            }
            if self.fin {
                return Err(Failure::Stream);
            }
            let read = self.with_frame(&mut [], |lane, frame, payload| -> std::io::Result<()> {
                match frames::h2_event(frame, payload, 1) {
                    frames::H2Event::Data { payload, end } => {
                        lane.capsule_buf.extend_from_slice(payload);
                        lane.fin = end;
                        if !payload.is_empty() {
                            lane.credit(payload.len()).map_err(io)?;
                        }
                        Ok(())
                    }
                    frames::H2Event::Window { stream, increment } => {
                        lane.grant(stream, increment);
                        Ok(())
                    }
                    frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                        lane.fin = true;
                        Ok(())
                    }
                    _ => Ok(()),
                }
            });
            read??;
        }
        Ok(assigned)
    }

    /// One IP packet, as a datagram this lane can read both ends of. A capsule whole inside one DATA frame is handed out where it lies, so the packet crosses userspace once instead of through the capsule buffer.
    pub(crate) fn read_ip(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some((used, capsule)) = connectip::capsule_split(&self.capsule_buf) {
                // A datagram is handed whole — the caller takes the buffer and the lane keeps it — so this reads a packet out rather than a slice of one.
                let packet = if let connectip::Capsule::Datagram(packet) = capsule {
                    packet.to_vec()
                } else {
                    Vec::new()
                };
                self.capsule_buf.drain(..used);
                if !packet.is_empty() {
                    return Ok(Some(packet));
                }
                continue;
            }
            if self.fin {
                return Ok(None);
            }
            let read = self.with_frame(
                &mut [],
                |lane, frame, payload| -> std::io::Result<Option<Vec<u8>>> {
                    match frames::h2_event(frame, payload, 1) {
                        frames::H2Event::Data { payload, end } => {
                            lane.fin = end;
                            if !payload.is_empty() {
                                lane.credit(payload.len()).map_err(io)?;
                            }
                            // The capsule is usually whole inside one DATA frame, so it is handed out where it lies and only the bytes behind it staged; nothing is handed out while a split capsule waits, because stream order is packet order.
                            if lane.capsule_buf.is_empty() {
                                if let Some((used, connectip::Capsule::Datagram(packet))) =
                                    connectip::capsule_split(payload)
                                {
                                    let packet = packet.to_vec();
                                    lane.capsule_buf.extend_from_slice(&payload[used..]);
                                    return Ok(Some(packet));
                                }
                            }
                            lane.capsule_buf.extend_from_slice(payload);
                            Ok(None)
                        }
                        frames::H2Event::Window { stream, increment } => {
                            lane.grant(stream, increment);
                            Ok(None)
                        }
                        frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                            lane.fin = true;
                            Ok(None)
                        }
                        _ => Ok(None),
                    }
                },
            );
            if let Some(packet) = read?? {
                if !packet.is_empty() {
                    return Ok(Some(packet));
                }
                // An empty datagram is skipped, exactly as the staged path skips one, so `Ok(None)` stays the end of stream.
            }
        }
    }
}

/// Opens the tunnel on whichever carrier the dial names and hands the caller something it can read and write; the `H3` arm needs the connection the pool already established.
pub(crate) enum Tunnel {
    H1(Tls1),
    H2(Tls2),
    H3(Box<H3>),
}

impl Tunnel {
    pub(crate) fn open(dial: &FoxyDial, target: &str, quic: Option<Quic>) -> Result<Self, Failure> {
        match (dial.carrier, quic) {
            (Carrier::H1, _) => open_h1(dial, target).map(Self::H1),
            (Carrier::H2, _) => open_h2(dial, target).map(Self::H2),
            (Carrier::H3, Some(quic)) => {
                H3::open(dial, target, quic).map(|lane| Self::H3(Box::new(lane)))
            }
            (Carrier::H3, None) => Err(Failure::Stream),
            // `auto` is expanded by the caller into the carriers it prefers; an unexpanded one here is a bug, and the answer is not a downgrade.
            (Carrier::Auto, _) => Err(Failure::Frame),
        }
    }

    /// The disposable probe's open: the same lane, but its CONNECT waits the budget the caller names rather than a carrier's full head timeout.
    pub(crate) fn open_within(
        dial: &FoxyDial,
        target: &str,
        quic: Quic,
        head_wait: Duration,
    ) -> Result<Self, Failure> {
        H3::open_within(dial, target, quic, head_wait).map(|lane| Self::H3(Box::new(lane)))
    }

    /// Bounds one blocking read on every carrier so a relay sharing one lane between its two directions stops holding its lock while idle: reads past the quantum answer `WouldBlock` and the relay retries instead of wedging.
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        match self {
            Self::H1(lane) => lane.set_read_quantum(quantum),
            Self::H2(lane) => lane.set_read_quantum(quantum),
            Self::H3(lane) => {
                lane.set_read_quantum(quantum);
                Ok(())
            }
        }
    }
}

impl std::io::Write for Datagram {
    fn write(&mut self, payload: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::H2(lane) => lane.write_datagram(payload),
            Self::H3(lane) => lane.write_datagram(payload),
        }
        .map(|()| payload.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Read for Datagram {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::H2(lane) => lane.read_datagram(buf),
            Self::H3(lane) => lane.read_datagram(buf),
        }
    }
}

impl Write for Tunnel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.write(buf),
            Self::H2(lane) => lane.write(buf),
            Self::H3(lane) => lane.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::H1(lane) => lane.flush(),
            Self::H2(lane) => lane.flush(),
            Self::H3(lane) => lane.flush(),
        }
    }
}

impl Read for Tunnel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.read(buf),
            Self::H2(lane) => lane.read(buf),
            Self::H3(lane) => lane.read(buf),
        }
    }
}

/// The SOCKS reply a refusal becomes: an edge that declined the target says so locally instead of paying a round trip to hear the same status again.
pub(crate) fn refusal_reply(failure: Failure) -> u8 {
    match failure {
        Failure::Rejected(status) if foxy::target_is_unreachable(status) => 0x04,
        Failure::Stream => 0x06,
        Failure::Rejected(_) | Failure::Frame | Failure::Io | Failure::Untrusted => 0x01,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constant credit buffer is the two frames the per-call loop built: a window update for stream 1 and one for the connection, each with the increment slot left for the caller to fill.
    #[test]
    fn the_credit_template_is_the_two_window_update_frames() {
        for (slot, stream) in [(0usize, 1u32), (13, 0)] {
            let frame = frames::H2Frame {
                kind: frames::WINDOW_UPDATE,
                flags: 0,
                stream,
                length: 4,
            };
            assert_eq!(
                &CREDIT_TEMPLATE[slot..slot + 9],
                &frame.header()[..],
                "header at {slot}"
            );
        }
        assert_eq!(
            &CREDIT_TEMPLATE[9..13],
            &[0u8; 4],
            "increment is patched per call"
        );
        assert_eq!(
            &CREDIT_TEMPLATE[22..26],
            &[0u8; 4],
            "increment is patched per call"
        );
    }

    fn dial(host: &str, carrier: Carrier) -> FoxyDial {
        FoxyDial {
            host: host.to_owned(),
            port: 443,
            address: Some(SocketAddr::from(([127, 0, 0, 1], 1))),
            carrier,
            upstream: None,
            roots: Vec::new().into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        }
    }

    #[test]
    fn every_carrier_asks_for_exactly_its_own_alpn() {
        for (carrier, want) in [
            (Carrier::H1, &b"http/1.1"[..]),
            (Carrier::H2, &b"h2"[..]),
            (Carrier::H3, &b"h3"[..]),
        ] {
            assert_eq!(
                tls_config(&dial("edge.example", carrier)).alpn,
                vec![want.to_vec()]
            );
        }
    }

    #[test]
    fn the_tls_config_names_the_edge_and_carries_its_pins() {
        let mut d = dial("edge.example", Carrier::H2);
        d.roots = vec![vec![1, 2, 3]].into();
        d.pins = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let config = tls_config(&d);
        assert_eq!(config.server_name, "edge.example");
        assert_eq!(
            config.roots,
            ferrox_core::tls::Anchors::from(vec![vec![1, 2, 3]])
        );
        assert_eq!(config.pins.len(), 1);
    }

    /// The order the lane trusts to find a tunnel, and the order a datagram trusts: `auto` walks all three, UDP walks the two that can carry a capsule at all.
    #[test]
    fn the_carriers_are_ordered_by_what_the_edge_can_answer() {
        assert_eq!(
            Carrier::Auto.order(),
            [Carrier::H3, Carrier::H2, Carrier::H1]
        );
        assert_eq!(Carrier::H2.order(), [Carrier::H2, Carrier::H2, Carrier::H2]);
        assert_eq!(Carrier::udp_order(), [Carrier::H3, Carrier::H2]);
        assert!(
            !Carrier::udp_order().contains(&Carrier::H1),
            "HTTP/1.1 has no extended CONNECT to carry a capsule"
        );
    }

    /// The pause between attempts bounds the budget the whole dial spends: a peer that would have answered is not waited on for long.
    #[test]
    fn an_edge_attempt_is_retried_under_a_growing_pause() {
        // The pause is flat because a refusal comes back fast: eight asks at one address is a couple of seconds of pause, not a leg's budget.
        assert_eq!(super::after_attempt(0), Duration::from_millis(250));
        assert_eq!(super::after_attempt(7), Duration::from_millis(250));
        let budget: u64 = (0..EDGE_ATTEMPTS - 1)
            .map(|attempt| super::after_attempt(attempt).as_millis() as u64)
            .sum();
        assert!(
            budget <= 5_000,
            "eight asks at one address cost a couple of seconds, not {budget}ms"
        );
    }

    #[test]
    fn only_a_two_hundred_opens_the_tunnel() {
        for status in [200u16, 204, 299] {
            assert!(opened(status).is_ok(), "{status}");
        }
        for status in [199u16, 300, 401, 403, 502] {
            assert_eq!(opened(status), Err(Failure::Rejected(status)));
        }
    }

    #[test]
    fn a_refusal_becomes_the_socks_reply_that_says_so() {
        assert_eq!(refusal_reply(Failure::Rejected(502)), 0x04);
        assert_eq!(refusal_reply(Failure::Rejected(403)), 0x01);
        assert_eq!(refusal_reply(Failure::Stream), 0x06);
        assert_eq!(refusal_reply(Failure::Io), 0x01);
        assert_eq!(refusal_reply(Failure::Frame), 0x01);
        assert_eq!(refusal_reply(Failure::Untrusted), 0x01);
    }

    #[test]
    fn the_dial_order_is_the_pinned_country_only() {
        let edges = vec![
            foxy::Candidate {
                host: "de1".into(),
                port: 443,
                country: "DE".into(),
                city: "berlin".into(),
            },
            foxy::Candidate {
                host: "us1".into(),
                port: 443,
                country: "US".into(),
                city: "nyc".into(),
            },
            foxy::Candidate {
                host: "de2".into(),
                port: 443,
                country: "DE".into(),
                city: "frankfurt".into(),
            },
        ];
        let order = foxy::dial_order(&edges, "DE", None, 3);
        assert_eq!(order.len(), 2);
        assert!(order.iter().all(|edge| edge.country == "DE"));
    }

    #[test]
    fn a_quic_lane_without_a_connection_is_a_refusal_not_a_panic() {
        assert_eq!(
            Tunnel::open(&dial("edge.example", Carrier::H3), "e:443", None).err(),
            Some(Failure::Stream)
        );
    }

    #[test]
    fn an_upstream_proxy_names_its_scheme_host_and_port() {
        let http = upstream_proxy("http://proxy.local:8080").expect("parses");
        assert!(http.http);
        assert_eq!((http.host, http.port), ("proxy.local".to_owned(), 8080));
        let socks = upstream_proxy("socks5://proxy.local:1080").expect("parses");
        assert!(!socks.http);
        assert_eq!((socks.host, socks.port), ("proxy.local".to_owned(), 1080));
        let h = upstream_proxy("socks5h://proxy.local:1080").expect("parses");
        assert!(!h.http);
        for bad in [
            "",
            "proxy.local:8080",
            "gopher://proxy.local:70",
            "http://proxy.local",
            "http://proxy.local:99999",
            "http://proxy.local:80/extra",
            "http://user:pass@proxy.local:8080",
        ] {
            assert!(upstream_proxy(bad).is_none(), "{bad:?} refuses");
        }
    }

    #[test]
    fn an_exit_probe_is_read_in_either_shape_it_can_answer_in() {
        assert_eq!(exit_country(b"fl=1\nloc=DE\n"), Some("DE".to_owned()));
        assert_eq!(
            exit_country(b"{\"status\":\"success\",\"countryCode\":\"US\"}"),
            Some("US".to_owned())
        );
        assert_eq!(
            exit_country(b"loc=de"),
            None,
            "a lowercase answer is not a country code"
        );
        assert_eq!(exit_country(b"nothing here"), None);
        assert_eq!(exit_country(b"loc=DEU"), None);
    }
}

#[cfg(test)]
mod loopback {
    use super::*;
    use crate::conn::Listener;

    const PAYLOAD: &[u8] = b"the tunnel carries the bytes unchanged";

    fn minted(alpn: &[u8]) -> (Vec<Vec<u8>>, ferrox_core::tls::TlsServerConfig) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let server = ferrox_core::tls::TlsServerConfig {
            cert_chain: vec![minted.cert.der().to_vec()],
            key_der: minted.key_pair.serialize_der(),
            key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
            alpn: vec![alpn.to_vec()],
            send_tickets: true,
        };
        (roots, server)
    }

    fn dial_for(
        roots: Vec<Vec<u8>>,
        port: u16,
        carrier: Carrier,
        pins: foxy::pin::Pins,
    ) -> FoxyDial {
        FoxyDial {
            host: "localhost".to_owned(),
            port,
            address: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            carrier,
            upstream: None,
            roots: roots.into(),
            pins,
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        }
    }

    /// A dial names the trust store, it does not own a copy of it: two dials of one edge, and the configs built from them, answer with the same allocation.
    #[test]
    fn every_dial_of_one_trust_names_the_same_anchors() {
        let anchors = crate::quic::system_roots();
        let no_pins = foxy::pin::Pins::default();
        let first = FoxyDial {
            roots: Arc::clone(&anchors),
            ..dial_for(Vec::new(), 443, Carrier::H2, no_pins.clone())
        };
        let second = FoxyDial {
            roots: anchors,
            ..dial_for(Vec::new(), 443, Carrier::H3, no_pins)
        };
        assert!(
            Arc::ptr_eq(&tls_config(&first).roots, &tls_config(&second).roots),
            "the platform store is read once for the process, not once per dial"
        );
    }

    /// An address that accepts TCP is not an address that carries the lane: `localhost` answers v6 first on both runners that matter, so a silent v6 listener must not cost the lane the v4 edge behind it.
    #[test]
    fn an_address_whose_tls_does_not_answer_costs_the_lane_the_next_one() {
        use ferrox_core::tls::TlsProvider as _;

        let (roots, server) = minted(b"h2");
        let mute = crate::conn::test_bind("[::1]:0").expect("binds v6");
        let mute_port = mute.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            // Accepts the connection and then says nothing, which is the whole of an address that cannot carry TLS.
            let (stream, _) = mute.accept().expect("accepts");
            drop(stream);
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds v4");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            while tls.read(&mut [0u8; 1]).map_or(true, |n| n > 0) {}
        });

        let dial = FoxyDial {
            // The port the name resolves to for both families, so the two listeners are the two addresses of one name.
            host: "localhost".to_owned(),
            port: mute_port.min(port) + mute_port.max(port).saturating_sub(mute_port),
            address: None,
            carrier: Carrier::H2,
            upstream: None,
            roots: roots.into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        };
        // The v4 edge's port, which is the one that speaks.
        let dial = FoxyDial { port, ..dial };
        let tls = tls_to_edge(&dial).expect("dials the address whose TLS answers");
        assert_eq!(tls.alpn(), Some(&b"h2"[..]), "the session is the live one");
    }

    /// An address the config names is the dial it named: a name that answers does not get it, because the named address is the poison-proof dial and the TLS name is verified against it.
    #[test]
    fn an_address_the_config_names_is_the_dial_it_named() {
        let (roots, _server) = minted(b"h2");
        let dial = FoxyDial {
            host: "localhost".to_owned(),
            port: 443,
            address: Some(SocketAddr::from(([127, 0, 0, 1], 1))),
            carrier: Carrier::H2,
            upstream: None,
            roots: roots.into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        };
        assert!(
            tls_to_edge(&dial).is_err(),
            "the named address is the only one"
        );
    }

    /// An edge whose chain this device does not trust is a fact about the certificate, not about the moment: the lane asks it once and names the refusal, where an io failure reads as a peer that is merely slow.
    #[test]
    fn an_untrusted_edge_is_named_and_asked_once() {
        use ferrox_core::tls::TlsProvider as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_foreign_roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) =
                    ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                else {
                    continue;
                };
                let _ = tls.handshake();
            }
        });

        // The roots of some other hand: the same shape of certificate, on a chain that does not verify.
        let (roots, _) = minted(b"h2");
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let at = Instant::now();
        let failure = tls_to_edge(&dial).expect_err("the chain is refused");
        assert_eq!(failure, Failure::Untrusted, "{failure}");
        assert!(
            at.elapsed() < Duration::from_millis(EDGE_BACKOFF_MS),
            "one ask costs no backoff, it took {:?}",
            at.elapsed()
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "an edge that never had the certificate is not asked eight times"
        );
    }

    /// A silent edge is a peer that is slow, not a peer that is dead: the CONNECT it never answers costs the open the named head wait and a `Stream` failure the walk can move past, where an unbounded head read held the flow for as long as the edge kept the session.
    #[test]
    fn a_silent_edge_costs_the_open_its_head_budget_not_the_flow() {
        use ferrox_core::tls::TlsProvider as _;

        let _guard = crate::budgets::lock();
        for (alpn, carrier, label) in [
            (&b"http/1.1"[..], Carrier::H1, "h1"),
            (&b"h2"[..], Carrier::H2, "h2"),
        ] {
            // The budget is re-applied per iteration because each leg clears it before its asserts, so a panic never leaks a tight arm to the next test.
            let root =
                crate::json::parse(r#"{"budgets": {"headArrival": "300ms"}}"#).expect("parses");
            crate::budgets::apply(
                &crate::config::budgets(&root).expect("a name the engine acts on"),
            );
            let (roots, server) = minted(alpn);
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let edge = std::thread::spawn(move || {
                // Handshakes, reads the request, answers nothing: the session stays open until the client's failure ends it.
                let (stream, _) = listener.accept().expect("accepts");
                let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server, stream)
                    .expect("accepts");
                tls.handshake().expect("handshakes");
                let mut sink = [0u8; 64];
                while tls.read(&mut sink).is_ok_and(|read| read > 0) {}
            });
            let dial = dial_for(roots, port, carrier, foxy::pin::Pins::default());
            let at = Instant::now();
            let opened = Tunnel::open(&dial, "example.com:443", None).err();
            crate::budgets::clear();
            let failure = opened.expect("the head never arrives");
            assert_eq!(failure, Failure::Stream, "{label} against a silent edge");
            assert!(
                at.elapsed() < Duration::from_secs(5),
                "the head budget expired the dial, it took {:?}",
                at.elapsed()
            );
            edge.join().expect("joins");
        }
    }

    /// A head that arrives a byte at a time is the arithmetic the silent-edge test does not reach: every drip stays inside the armed per-byte wait, so only a wall on the whole head keeps a trickling edge from holding the open for its length times the budget.
    #[test]
    fn a_dripping_head_costs_the_open_its_head_budget_not_its_length() {
        use ferrox_core::tls::TlsProvider as _;

        let _guard = crate::budgets::lock();
        let root = crate::json::parse(r#"{"budgets": {"headArrival": "300ms"}}"#).expect("parses");
        crate::budgets::apply(&crate::config::budgets(&root).expect("a name the engine acts on"));
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                read_exact(&mut tls, &mut byte).expect("reads the request");
                request.push(byte[0]);
            }
            for byte in b"HTTP/1.1 200 Connection established\r\n\r\n" {
                if tls.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(60));
            }
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let at = Instant::now();
        let opened = Tunnel::open(&dial, "example.com:443", None).err();
        crate::budgets::clear();
        let failure = opened.expect("the head never lands whole");
        assert_eq!(failure, Failure::Stream, "a drip ends at the wall");
        assert!(
            at.elapsed() < Duration::from_secs(2),
            "43 drips of 60 ms are not 2580 ms of open, it took {:?}",
            at.elapsed()
        );
        edge.join().expect("joins");
    }

    fn round_trip(tunnel: &mut Tunnel) {
        tunnel.write_all(PAYLOAD).expect("writes");
        tunnel.flush().expect("flushes");
        let mut back = vec![0u8; PAYLOAD.len()];
        tunnel.read_exact(&mut back).expect("reads");
        assert_eq!(back, PAYLOAD);
    }

    /// A dial whose hop is the only way to the edge: the name the CONNECT carries is not the name anything resolves, so a dial that reaches the edge has gone through the hop.
    fn hop_stream(proxy: &UpstreamProxy) -> Connection {
        tcp_via(proxy, &upstream_dial(proxy.clone(), None)).expect("chains through the hop")
    }

    fn upstream_dial(proxy: UpstreamProxy, edge: Option<SocketAddr>) -> FoxyDial {
        FoxyDial {
            host: "edge.test".to_owned(),
            port: 2499,
            address: edge,
            carrier: Carrier::H1,
            upstream: Some(proxy),
            roots: Vec::new().into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        }
    }

    fn read_head(stream: &mut dyn std::io::Read) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("reads a head");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ascii")
    }

    #[test]
    fn tcp_through_an_http_upstream_sends_connect_and_carries_bytes() {
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let seen = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let head = read_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).expect("reads");
            stream.write_all(&buf[..read]).expect("echoes");
            head
        });
        let proxy = upstream_proxy(&format!("http://127.0.0.1:{port}")).expect("parses");
        let mut stream = hop_stream(&proxy);
        stream.write_all(PAYLOAD).expect("writes");
        let mut back = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut back).expect("echoes");
        assert_eq!(back, PAYLOAD);
        assert_eq!(
            seen.join().expect("joins"),
            "CONNECT edge.test:2499 HTTP/1.1\r\nHost: edge.test:2499\r\n\r\n"
        );
    }

    #[test]
    fn tcp_through_a_socks5_upstream_shakes_hands_and_carries_bytes() {
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let seen = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            stream.write_all(&[5, 0]).expect("selects");
            let mut request = vec![0u8; 16];
            read_exact(&mut stream, &mut request).expect("connects");
            let mut want = vec![5, 1, 0, 3, 9];
            want.extend_from_slice(b"edge.test");
            want.extend_from_slice(&2499u16.to_be_bytes());
            assert_eq!(request, want);
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("grants");
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).expect("reads");
            stream.write_all(&buf[..read]).expect("echoes");
            greet.to_vec()
        });
        let proxy = upstream_proxy(&format!("socks5://127.0.0.1:{port}")).expect("parses");
        let mut stream = hop_stream(&proxy);
        stream.write_all(PAYLOAD).expect("writes");
        let mut back = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut back).expect("echoes");
        assert_eq!(back, PAYLOAD);
        assert_eq!(seen.join().expect("joins"), vec![5, 1, 0]);
    }

    /// A hop that refuses is a failed dial and not a fallback: the edge is never dialed around a proxy the config named, because a lane that bypasses its configured hop is a leak.
    #[test]
    fn a_refused_upstream_is_a_failed_dial_and_not_a_direct_one() {
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let edge_port = listener.local_addr().expect("addr").port();
        let (dialed_tx, dialed_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
                let _ = dialed_tx.send(());
            }
        });
        std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            stream.write_all(&[5, 0]).expect("selects");
            let mut request = vec![0u8; 15];
            read_exact(&mut stream, &mut request).expect("connects");
            // A general failure, which is how a hop says it will not connect.
            stream
                .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("refuses");
        });
        let proxy = upstream_proxy(&format!("socks5://127.0.0.1:{port}")).expect("parses");
        let edge = Some(SocketAddr::from(([127, 0, 0, 1], edge_port)));
        assert!(
            tls_to_edge(&upstream_dial(proxy.clone(), edge)).is_err(),
            "a refused hop is a failed dial"
        );
        assert!(
            dialed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "the edge on port {edge_port} was dialed around the hop"
        );
    }

    #[test]
    fn h1_through_an_http_upstream_reaches_its_edge() {
        let (roots, server) = minted(b"http/1.1");
        let edge = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let edge_port = edge.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (stream, _) = edge.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let request = read_head(&mut tls);
            assert_eq!(
                request,
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer the-pass\r\n\r\n"
            );
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = tls.read(&mut buf).expect("reads");
            assert_eq!(&buf[..read], PAYLOAD);
            tls.write_all(&buf[..read]).expect("echoes");
        });
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let proxy_port = proxy.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (mut downstream, _) = proxy.accept().expect("accepts");
            downstream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let head = read_head(&mut downstream);
            assert_eq!(
                head,
                format!(
                    "CONNECT localhost:{edge_port} HTTP/1.1\r\nHost: localhost:{edge_port}\r\n\r\n"
                )
            );
            downstream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let edge = Connection::connect(("127.0.0.1", edge_port)).expect("dials");
            let (mut up_read, mut up_write) = (edge.try_clone().expect("clones"), edge);
            let mut down = downstream.try_clone().expect("clones");
            let pipe = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(read) = down.read(&mut buf) {
                    if read == 0 || up_write.write_all(&buf[..read]).is_err() {
                        break;
                    }
                }
            });
            let mut buf = [0u8; 8192];
            while let Ok(read) = up_read.read(&mut buf) {
                if read == 0 || downstream.write_all(&buf[..read]).is_err() {
                    break;
                }
            }
            pipe.join().expect("joins");
        });
        let mut dial = dial_for(roots, edge_port, Carrier::H1, foxy::pin::Pins::default());
        dial.upstream = upstream_proxy(&format!("http://127.0.0.1:{proxy_port}"));
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        round_trip(&mut tunnel);
    }

    /// A SOCKS5 hop for the QUIC carrier: a TCP side answering `UDP ASSOCIATE` with the address of its relay socket, and a relay carrying datagrams with the association's own header — both halves write that header themselves, so the framing is witnessed by something other than the code it checks.
    fn socks_relay(edge_port: u16) -> UpstreamProxy {
        let control = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let proxy_port = control.local_addr().expect("addr").port();
        let relay = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let relay_addr = relay.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut stream, _) = control.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            assert_eq!(greet, [5, 1, 0], "no authentication offered");
            stream.write_all(&[5, 0]).expect("selects");
            let mut ask = [0u8; 10];
            read_exact(&mut stream, &mut ask).expect("associates");
            assert_eq!(&ask[..4], [5, 3, 0, 1], "a UDP association, naming nothing");
            let octets = match relay_addr.ip() {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut grant = vec![5, 0, 0, 1];
            grant.extend_from_slice(&octets);
            grant.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&grant).expect("grants");
            // The association lives as long as the control connection does, so this thread holds it until the lane is done with the hop.
            let mut sink = [0u8; 64];
            let _ = stream.read(&mut sink);
        });
        std::thread::spawn(move || {
            relay
                .set_read_timeout(Some(Duration::from_secs(60)))
                .expect("times out");
            let mut lane: Option<SocketAddr> = None;
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                match lane {
                    // The lane's first datagram is the one that says so: the association names no destination, so nothing arrives from the edge until the lane has spoken.
                    None => lane = Some(from),
                    Some(lane) if lane == from => {
                        if n < 10 || buf[2] != 0 || buf[3] != 1 {
                            continue;
                        }
                        let ip = [buf[4], buf[5], buf[6], buf[7]];
                        let port = u16::from_be_bytes([buf[8], buf[9]]);
                        let _ = relay.send_to(&buf[10..n], SocketAddr::from((ip, port)));
                    }
                    Some(lane) => {
                        // The edge's answer, framed for the lane the way the lane's own header framed the request.
                        let mut framed = vec![0, 0, 0, 1, 127, 0, 0, 1];
                        framed.extend_from_slice(&edge_port.to_be_bytes());
                        framed.extend_from_slice(&buf[..n]);
                        let _ = relay.send_to(&framed, lane);
                    }
                }
            }
        });
        upstream_proxy(&format!("socks5://127.0.0.1:{proxy_port}")).expect("parses")
    }

    #[test]
    fn the_quic_carrier_rides_a_socks5_upstream_and_carries_the_bytes() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let edge_port = sock.local_addr().expect("addr").port();
        let cert = crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE");
        let key = crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, uni_rx) = std::sync::mpsc::channel();
        let edge = h3_edge(sock, cert, key, seen_tx, uni_tx, PAYLOAD.to_vec());
        let proxy = socks_relay(edge_port);
        let (client, peer, local) = crate::quic::udp_to_server("127.0.0.1", edge_port)
            .expect("a socket the edge can be addressed from");
        let (relay_control, relay) = associate_udp(&proxy).expect("associates");
        let quic = crate::quic::direct_stream_on(
            crate::quic::Datagram::relayed(client, relay, relay_control),
            peer,
            local,
            "localhost",
            &roots,
        )
        .expect("a connection through the hop");
        let mut dial = dial_for(roots, edge_port, Carrier::H3, foxy::pin::Pins::default());
        dial.upstream = Some(proxy);
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        let block = seen_rx
            // The edge's own budget is a minute, so a lane that needs longer than that is a hang and not a slow machine.
            .recv_timeout(Duration::from_secs(60))
            .expect("block");
        let mut want = Vec::new();
        hpack::qpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge read the block the lane wrote");
        // The opening arrived as well as the request: a relay that dropped the control stream would still carry the request stream, because both travel the same datagrams.
        let uni = uni_rx.recv_timeout(Duration::from_secs(60)).expect("uni");
        let stream = |id| {
            uni.iter()
                .find(|(known, _, _)| *known == id)
                .unwrap_or_else(|| panic!("stream {id} opened"))
        };
        let (_, control, control_fin) = stream(2);
        let mut at = 0usize;
        assert_eq!(control.first(), Some(&0x00), "a control stream type");
        at += 1;
        assert_eq!(control.get(at), Some(&0x04), "one SETTINGS frame");
        at += 1;
        let len = frames::quic_read(control, &mut at).expect("a length") as usize;
        assert_eq!(
            control.len(),
            at + len,
            "a complete SETTINGS, no truncation"
        );
        assert!(!control_fin, "control stays open");
        for (id, first) in [(6u64, 0x02u8), (10, 0x03)] {
            let (_, bytes, fin) = stream(id);
            assert_eq!(bytes.as_slice(), &[first], "qpack stream {id}");
            assert!(!fin, "qpack stream {id} stays open");
        }
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    #[test]
    fn the_http11_carrier_sends_three_fields_and_carries_the_bytes() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                read_exact(&mut tls, &mut byte).expect("reads the request");
                head.push(byte[0]);
            }
            let request = String::from_utf8(head).expect("ascii");
            assert_eq!(
                request,
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer the-pass\r\n\r\n"
            );
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = tls.read(&mut buf).expect("reads");
            assert_eq!(&buf[..read], PAYLOAD);
            tls.write_all(&buf[..read]).expect("echoes");
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    #[test]
    fn a_rejected_http11_request_is_a_status_not_a_tunnel() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf);
            tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .expect("answers");
            std::thread::sleep(Duration::from_millis(50));
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        assert_eq!(
            Tunnel::open(&dial, "example.com:443", None).err(),
            Some(Failure::Rejected(407))
        );
        assert_eq!(refusal_reply(Failure::Rejected(407)), 0x01);
        edge.join().expect("joins");
    }

    /// Reads exactly `buf` the way a real edge server must: a socket timeout answers `WouldBlock` on macOS under scheduler load and means "nothing yet", not a closed lane, so it is retried until the budget or a genuine close — aborting on the timeout would tear the lane down mid-echo while nothing is wrong.
    fn read_exact_poll<S: Read>(io: &mut S, buf: &mut [u8]) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut at = 0usize;
        while at < buf.len() {
            match io.read(&mut buf[at..]) {
                Ok(0) => return false,
                Ok(read) => at += read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }

    /// The edge side of the HTTP/2 carrier: preface, settings, one stream, one status, then DATA both ways.
    fn h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            assert_eq!(head, frames::PREFACE);
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).ok();
                    }
                    frames::H2Event::Headers { block, .. } => {
                        let _ = seen.send(block.to_vec());
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).ok();
                    }
                    frames::H2Event::Data { payload, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::DATA, 0, 1, payload, &mut out);
                        tls.write_all(&out).ok();
                    }
                    _ => {}
                }
            }
        })
    }

    #[test]
    fn the_http2_carrier_writes_one_literal_header_block_and_relays() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let mut want = Vec::new();
        hpack::hpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the same block the lane wrote");
        round_trip(&mut tunnel);
    }

    #[test]
    fn the_shared_lane_carries_both_directions_at_once() {
        const BIG: usize = 16 * 1024;
        const STEP: usize = 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = std::sync::Arc::new(std::sync::Mutex::new(tunnel));
        let sent: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let forward = std::sync::Arc::clone(&lane);
        let chunk = sent.clone();
        std::thread::spawn(move || {
            let mut at = 0usize;
            while at < chunk.len() {
                let end = (at + STEP).min(chunk.len());
                match forward.lock().expect("locks").write(&chunk[at..end]) {
                    Ok(0) => std::thread::sleep(Duration::from_millis(5)),
                    Ok(wrote) => at += wrote,
                    Err(error) => panic!("the write failed: {error}"),
                }
            }
            done_tx.send(()).expect("reports");
        });
        let mut back = vec![0u8; BIG];
        let mut at = 0usize;
        while at < BIG {
            match lane.lock().expect("locks").read(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    // The lane is shared with the writer, so an idle poll sleeps instead of re-locking: a tight poll loop starves the writer behind the same mutex under load.
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("both directions flow at once");
        assert_eq!(back, sent);
    }

    /// The read quantum is what lets the writer behind the same mutex have a turn, so it must not cost the frame: a pause inside one DATA frame has to resume where it stopped, not abandon the bytes already promised to the header.
    #[test]
    fn a_frame_that_straddles_a_read_quantum_arrives_whole() {
        const BODY: usize = 32 * 1024;
        const HALF: usize = BODY / 2;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let body: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
            std::thread::sleep(Duration::from_millis(200));
            let head = frames::H2Frame {
                kind: frames::DATA,
                flags: 0,
                stream: 1,
                length: BODY as u32,
            }
            .header();
            // One frame, two writes: the second lands only after the lane's quantum has expired inside the first.
            tls.write_all(&head).expect("writes the header");
            tls.write_all(&body[..HALF]).expect("writes the first half");
            tls.flush().expect("flushes the first half");
            std::thread::sleep(Duration::from_millis(300));
            tls.write_all(&body[HALF..]).expect("writes the tail");
            tls.flush().expect("flushes the tail");
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(20))
            .expect("bounds one read");
        let mut back = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while back.len() < BODY && std::time::Instant::now() < deadline {
            match tunnel.read(&mut buf) {
                Ok(0) => panic!("the lane called an end of stream inside a frame"),
                Ok(read) => back.extend_from_slice(&buf[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("the lane lost the frame: {error}"),
            }
        }
        let want: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            back, want,
            "a quantum inside a frame must not drop its tail"
        );
        edge.join().expect("the edge finishes");
    }

    /// A flow's forward leg is parked in a blocking read on the client, so the end of a flow has to wake that read: a leg that never wakes keeps its pool worker, its lane and the lane's buffers for the life of the process.
    #[test]
    fn a_lane_that_ends_releases_the_leg_parked_on_its_client() {
        const PARK: Duration = Duration::from_secs(10);
        // The wake is the armed quantum, not the join budget: two of the 100 ms grains plus scheduling is the honest bound.
        const WAKE: Duration = Duration::from_secs(2);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (close_tx, close_rx) = std::sync::mpsc::channel::<()>();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let _ = close_rx.recv();
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let _browser = Connection::connect(front.local_addr().expect("addr")).expect("connects");
        let (client, _) = front.accept().expect("accepts");
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let flow_lane = Arc::clone(&lane);
        std::thread::spawn(move || {
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        // The leg has to be parked before the lane ends, or the test measures a flow that never started.
        std::thread::sleep(Duration::from_millis(200));
        close_tx.send(()).expect("ends the edge");
        edge.join().expect("the edge finishes");
        let _ = ended_rx.recv_timeout(PARK);
        assert!(
            started.elapsed() < WAKE,
            "the flow that lost its lane is still holding the leg parked on its client"
        );
    }

    /// The other half of the same promise: a client that says goodbye while its lane stays open has ended the flow, so the leg parked reading that lane has to come back rather than hold the lane, its stream and the flow's own thread for the life of the process.
    #[test]
    fn a_client_that_ends_releases_the_leg_parked_on_its_lane() {
        const PARK: Duration = Duration::from_secs(10);
        const WAKE: Duration = Duration::from_secs(2);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        // The edge answers, then holds the stream open the way a keep-alive target does: nothing on the lane ends this flow.
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let _ = hold_rx.recv();
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let browser = Connection::connect(front.local_addr().expect("addr")).expect("connects");
        let (client, _) = front.accept().expect("accepts");
        let started = Instant::now();
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let flow_lane = Arc::clone(&lane);
        std::thread::spawn(move || {
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        // The leg has to be parked on the lane before the client goes, or the test measures a flow that never started.
        std::thread::sleep(Duration::from_millis(200));
        browser
            .shutdown(std::net::Shutdown::Write)
            .expect("the client says goodbye");
        let _ = ended_rx.recv_timeout(PARK);
        assert!(
            started.elapsed() < WAKE,
            "the flow that lost its client is still holding the leg parked on its lane"
        );
        hold_tx.send(()).expect("the edge is released");
        edge.join().expect("the edge finishes");
    }

    /// The lane is the flow's shared resource: the leg that hands bytes to the client has to give the lane back before it waits on the socket, or a client that has stopped reading costs its own upload the road it came in on.
    #[test]
    fn a_client_that_has_stopped_reading_does_not_cost_the_flow_its_lane() {
        const CHUNK: usize = 16 * 1024;
        const PARK: Duration = Duration::from_secs(10);
        const WAKE: Duration = Duration::from_millis(300);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        // The edge answers, then pushes a download past what a client that never reads can queue: 4 MiB, several times the loopback queue a parked leg leaves behind.
        let (close_tx, close_rx) = std::sync::mpsc::channel::<()>();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            // Past the 300 ms the test polls at, so the edge is still parked on its push while the lane is asked for its lock.
            stream
                .set_write_timeout(Some(Duration::from_millis(800)))
                .expect("write times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let body = vec![0xA5u8; CHUNK];
            for _ in 0..256 {
                if close_rx.try_recv().is_ok() {
                    return;
                }
                let mut out = Vec::new();
                h2_frame(frames::DATA, 0, 1, &body, &mut out);
                if tls.write_all(&out).is_err() {
                    return;
                }
            }
            let _ = close_rx.recv();
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        // The browser asks for the flow and then never reads a byte, which is the whole of a stalled download from the relay's side.
        let browser = Connection::connect(front.local_addr().expect("addr")).expect("connects");
        let (client, _) = front.accept().expect("accepts");
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let flow_lane = Arc::clone(&lane);
        std::thread::spawn(move || {
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        // The leg has to be parked on the client's socket before the lane is asked for, or the test measures a flow that never waited.
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        let handed_back = loop {
            if lane.try_lock().is_ok() {
                break true;
            }
            if started.elapsed() >= WAKE {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            handed_back,
            "the leg parked writing a client that never reads is still holding the lane"
        );
        drop(browser);
        close_tx.send(()).ok();
        ended_rx
            .recv_timeout(PARK)
            .expect("the flow ends with its client");
        edge.join().expect("the edge finishes");
    }

    /// A lane whose peer is gone never says so to a writer that has no credit left: the window check answers before the socket is touched, so a leg parked on a stalled upload ends only when the other direction reports it is done.
    #[test]
    fn a_lane_that_dies_while_the_upload_is_parked_ends_the_flow() {
        const CHUNK: usize = 16 * 1024;
        const PARK: Duration = Duration::from_secs(10);
        const WAKE: Duration = Duration::from_millis(500);
        // One chunk past the credit the edge grants, so the last write is the one that cannot go through.
        const UPLOAD: usize = frames::DEFAULT_WINDOW as usize + CHUNK;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<usize>();
        // The edge reads the whole credit, grants none of it back, and hangs up once it has had every byte the lane is allowed to send.
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            // The edge reads the credit it granted and gives none of it back, then hangs up on the lane that still has a chunk to send.
            let mut credit = 0usize;
            while credit < frames::DEFAULT_WINDOW as usize {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind == frames::DATA {
                    credit += payload.len();
                    let _ = seen_tx.send(payload.len());
                }
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        // The upload leaves the client's socket before the lane stops taking it, so the leg's only wait is the lane.
        let browser = std::thread::spawn(move || {
            let mut socket = Connection::connect(addr).expect("connects");
            let body = vec![0x5Au8; CHUNK];
            for _ in 0..UPLOAD / CHUNK {
                if socket.write_all(&body).is_err() {
                    return;
                }
            }
        });
        let (client, _) = front.accept().expect("accepts");
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let flow_lane = Arc::clone(&lane);
        std::thread::spawn(move || {
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        let mut credit = 0usize;
        while credit < frames::DEFAULT_WINDOW as usize {
            credit += seen_rx
                .recv_timeout(PARK)
                .expect("the edge keeps reading what the lane sends");
        }
        ended_rx
            .recv_timeout(WAKE)
            .expect("the upload parked on a dead lane is still holding its workers");
        browser.join().expect("the browser finishes");
        edge.join().expect("the edge finishes");
    }

    /// An upload is paced by what the edge grants, not by what the lane reads back: this edge answers no payload at all and grants exactly the credit it consumes, so a lane that spends credit on inbound DATA rather than on the edge's `WINDOW_UPDATE` frames stops partway and a lane that reads them finishes the body.
    #[test]
    fn an_upload_is_paced_by_the_grants_the_edge_sends_rather_than_by_the_bytes_it_reads() {
        const GRANT: u32 = 32 * 1024;
        const CHUNK: usize = 16 * 1024;
        // Wider than either window the lane starts with, so the body only leaves if both the stream and the connection credit are refilled.
        const UPLOAD: usize = 8 * GRANT as usize;
        const PARK: Duration = Duration::from_secs(30);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<usize>();
        // A consuming edge: it reads every frame, answers with a grant per payload, and never sends a payload of its own.
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            let mut settings = Vec::new();
            settings.extend_from_slice(&4u16.to_be_bytes());
            settings.extend_from_slice(&GRANT.to_be_bytes());
            h2_frame(frames::SETTINGS, 0, 0, &settings, &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            tls.write_all(&opening).expect("advertises and answers");
            let mut taken = 0usize;
            while taken < UPLOAD {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind != frames::DATA {
                    continue;
                }
                taken += payload.len();
                let _ = seen_tx.send(payload.len());
                let increment = (payload.len() as u32).to_be_bytes();
                let mut grant = Vec::new();
                h2_frame(frames::WINDOW_UPDATE, 0, 1, &increment, &mut grant);
                h2_frame(frames::WINDOW_UPDATE, 0, 0, &increment, &mut grant);
                tls.write_all(&grant).expect("grants what it took");
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let body = vec![0x5Au8; CHUNK];
        let mut wrote = 0usize;
        let mut probe = [0u8; 8];
        let by = Instant::now() + PARK;
        while wrote < UPLOAD {
            assert!(
                Instant::now() < by,
                "the upload stopped at {wrote} of {UPLOAD} bytes"
            );
            match tunnel.write(&body) {
                Ok(0) => {
                    // The credit only arrives as a frame, so the way to earn it back is to read the lane.
                    let _ = tunnel.read(&mut probe);
                }
                Ok(written) => wrote += written,
                Err(error) => panic!("the lane ended the upload: {error}"),
            }
        }
        let mut arrived = 0usize;
        while arrived < UPLOAD {
            arrived += seen_rx
                .recv_timeout(PARK)
                .expect("the edge keeps taking what the lane sends");
        }
        assert_eq!(arrived, UPLOAD);
        edge.join().expect("the edge finishes");
    }

    /// A byte-level test cannot see a copy, so capacity is the witness: `out` is the write buffer and `carry` the read one, and a lane that stages a payload before handing it over has grown the buffer it staged in.
    #[test]
    fn a_relayed_byte_is_copied_once_on_its_way_through_the_lane() {
        const BIG: usize = 40 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let sent: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
        let staged = lane.out.capacity();
        let mut wrote = 0usize;
        while wrote < sent.len() {
            match lane.write(&sent[wrote..]) {
                Ok(0) => panic!("a lane that stops writing"),
                Ok(advanced) => wrote += advanced,
                Err(error) => panic!("the write failed: {error}"),
            }
        }
        lane.flush().expect("flushes");
        assert_eq!(
            lane.out.capacity(),
            staged,
            "the payload went into the record, not into a staging buffer"
        );
        // A read hands the frame payload straight to the caller's buffer: what is staged is only what the caller's buffer had no room for.
        let mut back = vec![0u8; BIG];
        let mut read = 0usize;
        while read < BIG {
            read += lane.read(&mut back[read..]).expect("reads");
        }
        assert_eq!(back, sent, "the bytes are the bytes either way");
        assert_eq!(lane.carry.capacity(), 0, "nothing was staged");
        assert_eq!(lane.at, 0, "the read cursor is where it started");
    }

    /// A frame read a hundred bytes at a time leaves nothing staged in the lane: every byte the caller took went from the wire into its own buffer, and between those visits the lane holds only the cursor.
    #[test]
    fn a_frame_read_a_hundred_bytes_at_a_time_stages_nothing() {
        const FRAME: usize = 16 * 1024;
        const STEP: usize = 100;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let sent: Vec<u8> = (0..FRAME).map(|i| (i % 251) as u8).collect();
        lane.write_all(&sent).expect("writes");
        lane.flush().expect("flushes");
        let mut back = vec![0u8; FRAME];
        let mut at = 0usize;
        while at < FRAME {
            let room = (FRAME - at).min(STEP);
            let read = lane.read(&mut back[at..at + room]).expect("reads");
            assert!(read > 0, "a frame that stops mid-way");
            at += read;
        }
        assert_eq!(back, sent, "the bytes are the bytes either way");
        assert!(lane.carry.is_empty(), "the remainder was drained");
        assert_eq!(lane.at, 0, "the read cursor is where it started");
    }

    /// The downlink edge: it answers the status, writes each named piece (pausing after it if one is named), and reports every `WINDOW_UPDATE` it reads from the lane until the socket ends.
    fn downlink_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        pieces: Vec<(Vec<u8>, Option<Duration>)>,
        updates: std::sync::mpsc::Sender<(u32, u32)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            tls.write_all(&opening).expect("answers the status");
            for (piece, pause) in pieces {
                tls.write_all(&piece).expect("pushes");
                tls.flush().expect("flushes");
                if let Some(pause) = pause {
                    std::thread::sleep(pause);
                }
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind == frames::WINDOW_UPDATE && payload.len() == 4 {
                    let increment = u32::from_be_bytes(payload[..4].try_into().expect("four"));
                    let _ = updates.send((frame.stream, increment));
                }
            }
        })
    }

    /// One DATA frame, whole: the header names the payload it carries.
    fn data_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = frames::H2Frame {
            kind: frames::DATA,
            flags: 0,
            stream: 1,
            length: payload.len() as u32,
        }
        .header()
        .to_vec();
        out.extend_from_slice(payload);
        out
    }

    /// The rest of a frame the caller only half-takes stays on the wire, not in a buffer the relay copies through: the lane holds a cursor and the next read resumes into the caller's own space.
    #[test]
    fn half_a_frame_reaches_the_caller_with_the_rest_left_on_the_wire() {
        const FRAME: usize = 8 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..FRAME).map(|i| (i % 251) as u8).collect();
        let (tx, _rx) = std::sync::mpsc::channel();
        let _edge = downlink_edge(listener, server, vec![(data_frame(&payload), None)], tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut half = [0u8; FRAME / 2];
        let got = lane.read(&mut half).expect("the first half");
        assert_eq!(
            got,
            half.len(),
            "the caller's buffer was filled and stopped"
        );
        assert_eq!(lane.frame.data_len, FRAME as u32);
        assert_eq!(
            lane.frame.data_at,
            FRAME as u32 / 2,
            "the cursor says what the wire still owes"
        );
        assert!(lane.carry.is_empty(), "the rest was not staged anywhere");
        let mut rest = [0u8; FRAME / 2];
        let got = lane.read(&mut rest).expect("the second half");
        assert_eq!(got, rest.len());
        assert_eq!(lane.frame.data_len, 0, "the frame is spent");
        assert_eq!(
            &half[..],
            &payload[..FRAME / 2],
            "the first half is the first half"
        );
        assert_eq!(
            &rest[..],
            &payload[FRAME / 2..],
            "the second half resumed where the wire stopped"
        );
    }

    /// A read quantum that expires mid-frame is a handover, not a loss: what arrived sits in the caller's buffer, the lane keeps the cursor, and the resume re-reads nothing that was already paid for.
    #[test]
    fn a_quantum_that_expires_mid_frame_resumes_without_re_reading_a_byte() {
        const FRAME: usize = 8 * 1024;
        const PART: usize = 3 * 1024;
        const STEP: usize = 1000;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..FRAME).map(|i| (i % 251) as u8).collect();
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut head = data_frame(&payload);
        head.truncate(frames::H2_HEADER + PART);
        let tail = payload[PART..FRAME].to_vec();
        let _edge = downlink_edge(
            listener,
            server,
            vec![
                (head, Some(Duration::from_millis(200))),
                (tail, Some(Duration::from_millis(50))),
            ],
            tx,
        );
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(30))
            .expect("bounds one read");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; FRAME];
        let mut at = 0usize;
        let mut parks = 0usize;
        let mut mid_frame_parks = 0usize;
        let stop_by = Instant::now() + Duration::from_secs(20);
        while at < FRAME {
            assert!(Instant::now() < stop_by, "the frame never finished");
            let room = (FRAME - at).min(STEP);
            match lane.read(&mut back[at..at + room]) {
                Ok(read) => {
                    assert!(read > 0, "a read that returns nothing without saying so");
                    at += read;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    parks += 1;
                    if lane.frame.data_len > 0 {
                        mid_frame_parks += 1;
                        assert!(
                            lane.frame.data_len == FRAME as u32
                                && lane.frame.data_at > 0
                                && lane.frame.data_at < FRAME as u32,
                            "the pause lost which frame was in flight"
                        );
                        assert!(lane.carry.is_empty(), "the pause staged nothing");
                    }
                }
                Err(error) => panic!("the lane died: {error}"),
            }
        }
        assert!(
            mid_frame_parks > 0,
            "the witness needs a pause inside the frame, not before it: {parks} parks"
        );
        assert_eq!(back, payload, "the pause cost no byte and added none");
        assert_eq!(lane.frame.data_len, 0);
    }

    /// A frame whose bytes do not all arrive is a dead lane, not an endless short read: the caller learns the stream broke rather than waiting on payload that will not come.
    #[test]
    fn a_frame_truncated_on_the_wire_ends_the_flow_it_was_meant_for() {
        const CLAIM: usize = 4096;
        const ARRIVED: usize = 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..CLAIM).map(|i| (i % 251) as u8).collect();
        let mut push = data_frame(&payload);
        push.truncate(frames::H2_HEADER + ARRIVED);
        // The edge pushes the truncated frame and leaves: its goodbye is what the lane must read as a break.
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            tls.write_all(&opening).expect("answers the status");
            tls.write_all(&push).expect("pushes the fragment");
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = [0u8; CLAIM];
        let mut at = 0usize;
        let mut broken = false;
        let stop_by = Instant::now() + Duration::from_secs(20);
        while !broken {
            assert!(
                Instant::now() < stop_by,
                "no verdict on the truncated frame"
            );
            match lane.read(&mut back[at..]) {
                Ok(read) => {
                    assert!(
                        read > 0,
                        "a clean end is not the answer to a truncated frame"
                    );
                    at += read;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => broken = true,
            }
        }
        assert!(at < CLAIM, "the truncation was swallowed as a full frame");
        assert_eq!(&back[..at], &payload[..at], "what arrived is what was sent");
        edge.join().expect("the edge finishes");
    }

    /// The credit a lane owes is held to the floor and granted back in one pair, not written per frame: crossing `CREDIT_FLOOR` costs two `WINDOW_UPDATE` frames no matter how many frames filled it.
    #[test]
    fn credit_crossing_the_floor_costs_one_pair_not_one_per_frame() {
        const FRAME: usize = 16 * 1024;
        const FRAMES: usize = 5;
        const TOTAL: usize = FRAME * FRAMES;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
        let pieces = (0..FRAMES)
            .map(|i| (data_frame(&payload[i * FRAME..(i + 1) * FRAME]), None))
            .collect();
        let (tx, rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(listener, server, pieces, tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; TOTAL];
        let mut at = 0usize;
        while at < TOTAL {
            at += lane.read(&mut back[at..]).expect("reads");
        }
        assert_eq!(back, payload);
        assert_eq!(
            lane.pending_credit,
            (TOTAL - CREDIT_FLOOR as usize) as u32,
            "the crossing was granted and the remainder held"
        );
        drop(tunnel);
        let mut tally = Vec::new();
        while let Ok(update) = rx.recv_timeout(Duration::from_secs(20)) {
            tally.push(update);
        }
        edge.join().expect("the edge finishes");
        // One pair at the crossing (the template grants stream 1 then stream 0), beside the lane's own opening grant on stream 0.
        let grants: Vec<_> = tally
            .iter()
            .filter(|(_, increment)| *increment == CREDIT_FLOOR)
            .copied()
            .collect();
        assert_eq!(
            grants,
            vec![(1, CREDIT_FLOOR), (0, CREDIT_FLOOR)],
            "five frames cost one pair, not five"
        );
        assert_eq!(
            tally.len(),
            3,
            "no other window update left the lane: {tally:?}"
        );
    }

    /// Credit held below the floor never reaches the wire: a lane that has taken less than `CREDIT_FLOOR` owes the edge a number, not a write.
    #[test]
    fn credit_held_under_the_floor_never_reaches_the_wire() {
        const FRAME: usize = 16 * 1024;
        const LAST: usize = 16 * 1024 - 153;
        const TOTAL: usize = 3 * FRAME + LAST;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
        let mut pieces = (0..3)
            .map(|i| (data_frame(&payload[i * FRAME..(i + 1) * FRAME]), None))
            .collect::<Vec<_>>();
        pieces.push((data_frame(&payload[3 * FRAME..]), None));
        let (tx, rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(listener, server, pieces, tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; TOTAL];
        let mut at = 0usize;
        while at < TOTAL {
            at += lane.read(&mut back[at..]).expect("reads");
        }
        assert_eq!(back, payload);
        assert_eq!(
            lane.pending_credit, TOTAL as u32,
            "everything taken is still owed, unstated"
        );
        drop(tunnel);
        let tally: Vec<_> = (0..10)
            .map_while(|_| rx.recv_timeout(Duration::from_millis(500)).ok())
            .collect();
        edge.join().expect("the edge finishes");
        assert!(
            tally
                .iter()
                .all(|(_, increment)| *increment != CREDIT_FLOOR),
            "a held credit below the floor wrote nothing: {tally:?}"
        );
    }

    #[test]
    fn the_http2_carrier_assembles_a_status_split_over_continuation() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).expect("acks the settings");
                    }
                    frames::H2Event::Headers { .. } => {
                        // The status in two fragments: an indexed field the lane skips, then the indexed 200 on a CONTINUATION.
                        let mut first = Vec::new();
                        h2_frame(frames::HEADERS, 0x0, 1, &[0x80 | 0x21], &mut first);
                        tls.write_all(&first).expect("sends the fragment");
                        let mut rest = Vec::new();
                        h2_frame(frames::CONTINUATION, 0x4, 1, &[0x88], &mut rest);
                        tls.write_all(&rest).expect("sends the tail");
                        return;
                    }
                    _ => {}
                }
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    /// The CONNECT-IP tunnel over HTTP/2: the request is `connect-ip`, the assignment that follows carries the tunnel's own address, and a datagram to one destination rides the tunnel the address bought rather than a stream of its own.
    #[test]
    fn the_connect_ip_carrier_opens_one_tunnel_and_carries_a_datagram() {
        let (roots, server) = minted(b"\x68\x32");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = ip_h2_edge(listener, server, seen_tx, udp_tx, 1);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let (mut lane, assigned) = Ip::open(&dial, None).expect("opens");
        let assigned = assigned.expect("an address");
        assert!(!assigned.refused(), "the tunnel owns an address");
        assert_eq!(assigned.bytes(), &[198, 51, 100, 9]);
        assert_eq!(assigned.width(), 4, "an IPv4 tunnel");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let text = String::from_utf8_lossy(&block);
        for field in [
            "CONNECT",
            "connect-ip",
            "/.well-known/masque/ip/*/0/",
            "Bearer the-pass",
            "capsule-protocol",
            "?1",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        let written = lane
            .write(
                &[198, 51, 100, 9],
                &[203, 0, 113, 9],
                40_000,
                443,
                b"hello ip",
            )
            .expect("writes");
        assert!(written, "the packet was built");
        lane.flush().expect("flushes");
        let (destination, port, payload) = udp_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the edge read it");
        assert_eq!(destination, vec![203, 0, 113, 9]);
        assert_eq!(port, 443);
        assert_eq!(payload, b"hello ip");
        // The reply is read as a packet whose source is where the datagram went, and a byte-equal packet cannot see a staging copy, so capacity is the witness: reset the capsule buffer with nothing pending, read one reply, and the buffer a whole-in-one-frame capsule would have been staged through must still be empty.
        {
            let Ip::H2(inner) = &mut lane else {
                unreachable!("an h2 dial opens an h2 lane");
            };
            assert!(
                inner.capsule_buf.is_empty(),
                "the assignment left no capsule bytes pending"
            );
            inner.capsule_buf = Vec::new();
        }
        let packet = lane.read().expect("reads").expect("a reply");
        let Ip::H2(inner) = &mut lane else {
            unreachable!("an h2 dial opens an h2 lane");
        };
        assert_eq!(
            inner.capsule_buf.capacity(),
            0,
            "a datagram whole inside one DATA frame was handed out, not staged through the capsule buffer"
        );
        let read = connectip::udp_from_packet(&packet).expect("parses");
        assert!(read.verified);
        assert_eq!(
            read.source,
            &[203, 0, 113, 9],
            "the reply is from the target"
        );
        assert_eq!(read.destination, &[198, 51, 100, 9]);
        assert_eq!(read.payload, b"hello ip");
        edge.join().expect("joins");
    }

    /// The tunnel carries more than one destination, which is what the shared address buys: a second destination rides the tunnel the first one opened.
    #[test]
    fn one_tunnel_carries_every_destination_at_once() {
        let (roots, server) = minted(b"\x68\x32");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = ip_h2_edge(listener, server, seen_tx, udp_tx, 2);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let (mut lane, _) = Ip::open(&dial, None).expect("opens");
        let _ = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        for (host, payload) in [
            ([203, 0, 113, 1], &b"first"[..]),
            ([203, 0, 113, 2], &b"second"[..]),
        ] {
            assert!(lane
                .write(&[198, 51, 100, 9], &host, 40_000, 443, payload)
                .expect("writes"));
            lane.flush().expect("flushes");
        }
        for (host, payload) in [
            ([203, 0, 113, 1], &b"first"[..]),
            ([203, 0, 113, 2], &b"second"[..]),
        ] {
            let (destination, _, seen) = udp_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("the edge read it");
            assert_eq!(destination, host.to_vec());
            assert_eq!(seen, payload);
        }
        edge.join().expect("joins");
    }

    /// A loopback HTTP/2 edge that speaks CONNECT-IP: it answers the request, sends an `ADDRESS_ASSIGN` for the tunnel's own address, then relays whichever destination the packet names — one stream carrying more than one destination, where a CONNECT-UDP edge answers only a single target.
    fn ip_h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        udp: std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            // A TLS flush performs one read when nothing is pending to write, so the socket's read timeout is a flush's latency: the product's relays arm a quantum, and an edge that arms twenty seconds spends twenty in one idle read.
            stream
                .set_read_timeout(Some(crate::budgets::RELAY_QUANTUM))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).expect("acks the settings");
                    }
                    frames::H2Event::Headers { block, .. } => {
                        seen.send(block.to_vec()).expect("reports the block");
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).expect("answers");
                        break;
                    }
                    _ => {}
                }
            }
            // The address the proxy assigns: an RFC 1918 one, since the tunnel is a private network and not the internet.
            ip_h2_assign(&mut tls);
            // The client's address request arrives as DATA before the first packet, so the capsule loop below drains it where it lies.
            ip_h2_relay(&mut tls, &udp, want);
        })
    }

    /// The assignment a CONNECT-IP edge answers with: one address the tunnel owns, flushed so the lane's first read finds it.
    fn ip_h2_assign(tls: &mut ferrox_core::tls::RustlsServerProvider<Connection>) {
        let mut capsule = Vec::new();
        connectip::address_assign_encode(&[ip_tunnel_grant()], &mut capsule);
        let mut frame = Vec::new();
        h2_frame(frames::DATA, 0, 1, &capsule, &mut frame);
        tls.write_all(&frame).expect("assigns an address");
        tls.flush().expect("flushes the assignment");
    }

    /// The one grant both CONNECT-IP edges answer with: the tunnel's own RFC 1918-ish address, request id one, `198.51.100.9/32`.
    fn ip_tunnel_grant() -> connectip::Assigned {
        let mut address = [0u8; 16];
        address[..4].copy_from_slice(&[198, 51, 100, 9]);
        connectip::Assigned {
            request_id: 1,
            version: 4,
            address,
            prefix: 32,
        }
    }

    /// The packets one CONNECT-IP edge carries: each names its destination, so one stream serves `want` of them and then the edge rests.
    fn ip_h2_relay(
        tls: &mut ferrox_core::tls::RustlsServerProvider<Connection>,
        udp: &std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) {
        let mut stream = Vec::new();
        let mut carried = 0usize;
        loop {
            let mut header = [0u8; frames::H2_HEADER];
            if read_exact(tls, &mut header).is_err() {
                continue;
            }
            let Some(frame) = frames::H2Frame::parse(&header) else {
                continue;
            };
            let mut payload = vec![0u8; frame.length as usize];
            if read_exact(tls, &mut payload).is_err() {
                continue;
            }
            if frame.kind != frames::DATA {
                continue;
            }
            stream.extend_from_slice(&payload);
            while let Some((used, capsule)) = connectip::capsule_split(&stream) {
                let packet = if let connectip::Capsule::Datagram(packet) = capsule {
                    packet.to_vec()
                } else {
                    stream.drain(..used);
                    continue;
                };
                stream.drain(..used);
                let Some(read) = connectip::udp_from_packet(&packet) else {
                    continue;
                };
                if read.source != [198, 51, 100, 9] {
                    continue;
                }
                udp.send((
                    read.destination.to_vec(),
                    read.destination_port,
                    read.payload.to_vec(),
                ))
                .expect("reports the datagram");
                // A reply from the destination, which is what a caller reads.
                let mut reply = Vec::new();
                assert!(connectip::udp_datagram(
                    &connectip::UdpDatagram {
                        source: read.destination,
                        destination: &[198, 51, 100, 9],
                        source_port: read.destination_port,
                        destination_port: read.source_port,
                        payload: read.payload,
                    },
                    &mut reply
                ));
                let mut coded = Vec::new();
                connectip::packet_encode(&reply, &mut coded);
                let mut frame = Vec::new();
                h2_frame(frames::DATA, 0, 1, &coded, &mut frame);
                tls.write_all(&frame).expect("replies");
                tls.flush().expect("flushes the reply");
                carried += 1;
                if carried >= want {
                    // The reply is not the end of the edge: a lane that has to read a second frame to find the rest of its capsule must find the edge still there.
                    std::thread::sleep(Duration::from_millis(250));
                    return;
                }
            }
        }
    }
    #[test]
    fn the_masque_carrier_opens_connect_udp_and_echoes_a_datagram() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = masque_h2_edge(listener, server, seen_tx, 1);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let text = String::from_utf8_lossy(&block);
        for field in [
            "connect-udp",
            "/.well-known/masque/udp/example.com/443/",
            "Bearer the-pass",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        // A byte-level echo cannot see a staging copy, so capacity is the witness on the write side: reset the pooled write buffer, write one datagram, and the buffer a stage would have grown must still be empty.
        lane.out = Vec::new();
        lane.write_datagram(b"hello udp").expect("writes");
        lane.flush().expect("flushes");
        assert_eq!(
            lane.out.capacity(),
            0,
            "the datagram's payload went into the record, not into a staging buffer"
        );
        read_datagram(&mut lane, b"hello udp");
        assert!(
            lane.capsule_buf.is_empty(),
            "a capsule whole inside one frame is not staged"
        );
        edge.join().expect("joins");
    }

    /// A capsule the edge split over several DATA frames arrives as one datagram, and the only bytes staged are the ones the split made it stage: the reassembly is the copy that cannot be avoided.
    #[test]
    fn a_capsule_split_over_frames_reassembles_as_one_datagram() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = masque_h2_edge(listener, server, seen_tx, 2);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        let _block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        lane.write_datagram(b"hello udp").expect("writes");
        lane.flush().expect("flushes");
        read_datagram(&mut lane, b"hello udp");
        assert!(lane.capsule_buf.is_empty(), "the remainder was drained");
        edge.join().expect("joins");
    }

    /// A frame boundary is not a capsule boundary: two DATAGRAM capsules inside one DATA frame are two datagrams, in order — the edge echoes a received frame as one frame, so the pair comes back together or not at all.
    #[test]
    fn a_frame_of_two_datagrams_arrives_as_two_datagrams() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        let mut both = Vec::new();
        masque::datagram_encode(b"first", &mut both);
        masque::datagram_encode(b"second", &mut both);
        lane.write_all(&both).expect("writes");
        lane.flush().expect("flushes");
        lane.set_read_quantum(Duration::from_secs(5))
            .expect("bounds a read");
        read_datagram(&mut lane, b"first");
        read_datagram(&mut lane, b"second");
    }

    /// One datagram through the lane, asserted whole; a buffer that has grown is the only thing a staged capsule leaves behind.
    fn read_datagram(lane: &mut Tls2, want: &[u8]) {
        let mut back = [0u8; 64];
        let mut at = 0usize;
        while at < want.len() {
            match lane.read_datagram(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        assert_eq!(&back[..at], want);
    }

    /// A loopback HTTP/2 edge that answers a CONNECT-UDP request and echoes the datagram back, `parts` bytes of capsule to a DATA frame.
    fn masque_h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        parts: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).expect("acks the settings");
                    }
                    frames::H2Event::Headers { block, .. } => {
                        seen.send(block.to_vec()).expect("reports the block");
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).expect("answers");
                        break;
                    }
                    _ => {}
                }
            }
            let mut stream = Vec::new();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind != frames::DATA {
                    continue;
                }
                stream.extend_from_slice(&payload);
                if let Some((_, datagram)) = masque::datagram_split(&stream) {
                    let mut echo = Vec::new();
                    masque::datagram_encode(datagram, &mut echo);
                    // The capsule in one piece, or split over `parts` frames: a frame boundary inside a capsule is legal, and the lane has to answer the datagram either way.
                    let halves: Vec<usize> =
                        (1..parts).map(|part| echo.len() * part / parts).collect();
                    let mut at = 0usize;
                    for cut in halves.into_iter().chain([echo.len()]) {
                        let mut out = Vec::new();
                        h2_frame(frames::DATA, 0, 1, &echo[at..cut], &mut out);
                        tls.write_all(&out).expect("echoes");
                        at = cut;
                    }
                    // The echo is not the end of the edge: a lane that has to read a second frame to find the rest of its capsule must find the edge still there, and a TLS peer that drops on a reader's next syscall is one the runner decides.
                    std::thread::sleep(Duration::from_millis(250));
                    return;
                }
            }
        })
    }

    /// A loopback QUIC edge that speaks the HTTP/3 opening and nothing else that matters: one request stream answered with a 200, and one capsule echoed back.
    fn quic_udp_edge(
        sock: crate::quic::Datagram,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let tag = format!("ferrox-foxy-udp-{}-{stamp}", std::process::id());
            let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
            let key_path = std::env::temp_dir().join(format!("{tag}.key"));
            let cert_pem = crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE");
            let key_pem = crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY");
            std::fs::write(&cert_path, &cert_pem).expect("stages cert");
            std::fs::write(&key_path, &key_pem).expect("stages key");
            let mut config = crate::quic::server_config(crate::quic::ALPN);
            config
                .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
                .expect("loads chain");
            config
                .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
                .expect("loads key");
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut stream = None;
            let mut raw = Vec::new();
            while stream.is_none() {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        raw.extend_from_slice(&piece);
                        stream = Some(id);
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let stream = stream.expect("a request stream");
            let mut at = 0usize;
            let frame = frames::h3_frame(&raw, &mut at).expect("a frame");
            seen.send(raw[at..at + frame.length as usize].to_vec())
                .expect("reports");
            answer_udp(
                &sock, local, &mut conn, stream, &mut buf, &mut out, deadline,
            );
        })
    }

    /// The 200 the request is answered with, then the capsule echoed: the frame the edge sends back is the frame it read, header and capsule together, because the frame's payload *is* the capsule stream.
    fn answer_udp(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        conn: &mut quiche::Connection,
        stream: u64,
        buf: &mut [u8; 1350],
        out: &mut [u8; 1350],
        deadline: Instant,
    ) {
        let mut reply = Vec::new();
        frames::quic_varint(&mut reply, frames::H3_HEADERS);
        frames::quic_varint(&mut reply, 3);
        // `0xd9` is QPACK static index 25, which is `:status 200`: the indexed field line, after the block's two required zero bytes.
        reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
        conn.stream_send(stream, &reply, false).expect("answers");
        // A frame's header and its payload can arrive in different packets, so a capsule is walked whole or not at all: only what whole frames cover is spent out of the window.
        let mut pending: Vec<u8> = Vec::new();
        while std::time::Instant::now() < deadline {
            let Some((n, from)) = crate::quic::server_poll(sock, buf) else {
                crate::quic::server_idle(conn, sock, out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            pending.extend_from_slice(&drain(conn, stream));
            let mut echo = Vec::new();
            let mut at = 0usize;
            let mut whole = 0usize;
            while at < pending.len() {
                let start = at;
                let Some(frame) = frames::h3_frame(&pending, &mut at) else {
                    break;
                };
                let end = at + frame.length as usize;
                if end > pending.len() {
                    break;
                }
                if matches!(
                    frames::h3_event(frame, &pending[at..end]),
                    frames::H3Event::Data { .. }
                ) {
                    echo.extend_from_slice(&pending[start..end]);
                }
                at = end;
                whole = end;
            }
            pending.drain(..whole);
            if !echo.is_empty() {
                // One datagram is one DATA frame, so a flow that split its own capsule over several of them would be a change the peer sees.
                assert_eq!(
                    frames::h3_frame(&echo, &mut 0).map(|frame| frame.kind),
                    Some(frames::H3_DATA),
                    "the echo carries a DATA frame"
                );
                conn.stream_send(stream, &echo, false).expect("echoes");
                while let Ok((written, info)) = conn.send(out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
                return;
            }
            while let Ok((written, info)) = conn.send(out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        }
    }

    /// A loopback QUIC edge that speaks CONNECT-IP: one request stream answered with a 200, an address assignment for the tunnel's own address, and a relay that answers whichever destination the packet names.
    fn quic_ip_edge(
        sock: crate::quic::Datagram,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        udp: std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let tag = format!("ferrox-foxy-ip-{}-{stamp}", std::process::id());
            let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
            let key_path = std::env::temp_dir().join(format!("{tag}.key"));
            let cert_pem = crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE");
            let key_pem = crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY");
            std::fs::write(&cert_path, &cert_pem).expect("stages cert");
            std::fs::write(&key_path, &key_pem).expect("stages key");
            let mut config = crate::quic::server_config(crate::quic::ALPN);
            config
                .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
                .expect("loads chain");
            config
                .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
                .expect("loads key");
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut stream = None;
            let mut raw = Vec::new();
            while stream.is_none() {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        raw.extend_from_slice(&piece);
                        stream = Some(id);
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let stream = stream.expect("a request stream");
            let mut at = 0usize;
            let frame = frames::h3_frame(&raw, &mut at).expect("a frame");
            seen.send(raw[at..at + frame.length as usize].to_vec())
                .expect("reports");
            answer_ip(&sock, local, &mut conn, stream, &udp, want);
        })
    }

    /// The 200 the CONNECT-IP request is answered with, the assignment the tunnel owns, and one relayed packet per destination: the reply is a new packet with the ends swapped, because the tunnel carries addresses and not an echo.
    fn answer_ip(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        conn: &mut quiche::Connection,
        stream: u64,
        udp: &std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) {
        let mut buf = [0u8; 1350];
        let mut out = [0u8; 1350];
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut reply = Vec::new();
        frames::quic_varint(&mut reply, frames::H3_HEADERS);
        frames::quic_varint(&mut reply, 3);
        reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
        conn.stream_send(stream, &reply, false).expect("answers");
        // The tunnel's own grant, encoded by the same codec the client reads it back with.
        let mut capsule = Vec::new();
        connectip::address_assign_encode(&[ip_tunnel_grant()], &mut capsule);
        send_h3_data(conn, stream, &capsule);
        while let Ok((written, info)) = conn.send(&mut out) {
            let _ = sock.send_to(&out[..written], info.to);
        }
        // The client's address request arrives as DATA before the first packet, so the capsule loop below drains it where it lies.
        let mut pending: Vec<u8> = Vec::new();
        let mut stream_buf: Vec<u8> = Vec::new();
        let mut carried = 0usize;
        while std::time::Instant::now() < deadline {
            let Some((n, from)) = crate::quic::server_poll(sock, &mut buf) else {
                crate::quic::server_idle(conn, sock, &mut out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            pending.extend_from_slice(&drain(conn, stream));
            let mut at = 0usize;
            let mut whole = 0usize;
            while at < pending.len() {
                let Some(frame) = frames::h3_frame(&pending, &mut at) else {
                    break;
                };
                let end = at + frame.length as usize;
                if end > pending.len() {
                    break;
                }
                if matches!(
                    frames::h3_event(frame, &pending[at..end]),
                    frames::H3Event::Data { .. }
                ) {
                    stream_buf.extend_from_slice(&pending[at..end]);
                }
                at = end;
                whole = end;
            }
            pending.drain(..whole);
            while let Some((used, capsule)) = connectip::capsule_split(&stream_buf) {
                let packet = if let connectip::Capsule::Datagram(packet) = capsule {
                    packet.to_vec()
                } else {
                    stream_buf.drain(..used);
                    continue;
                };
                stream_buf.drain(..used);
                let Some(read) = connectip::udp_from_packet(&packet) else {
                    continue;
                };
                if read.source != [198, 51, 100, 9] {
                    continue;
                }
                udp.send((
                    read.destination.to_vec(),
                    read.destination_port,
                    read.payload.to_vec(),
                ))
                .expect("reports the datagram");
                // A reply from the destination, which is what a caller reads.
                let mut reply = Vec::new();
                assert!(connectip::udp_datagram(
                    &connectip::UdpDatagram {
                        source: read.destination,
                        destination: &[198, 51, 100, 9],
                        source_port: read.destination_port,
                        destination_port: read.source_port,
                        payload: read.payload,
                    },
                    &mut reply
                ));
                let mut coded = Vec::new();
                connectip::packet_encode(&reply, &mut coded);
                send_h3_data(conn, stream, &coded);
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
                carried += 1;
                if carried >= want {
                    // The reply is not the end of the edge: a lane that has to read a second frame to find the rest of its capsule must find the edge still there.
                    std::thread::sleep(Duration::from_millis(250));
                    return;
                }
            }
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        }
    }

    /// One H3 DATA frame carrying `payload` on `stream`: capsules on this stream are framed, and the header is its own send because quiche copies every slice it is handed.
    fn send_h3_data(conn: &mut quiche::Connection, stream: u64, payload: &[u8]) {
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, payload.len() as u64);
        conn.stream_send(stream, &head[..hl], false)
            .expect("frames");
        conn.stream_send(stream, payload, false).expect("carries");
    }

    /// CONNECT-IP over QUIC: the request names `connect-ip`, the assignment carries the tunnel's own address, and a datagram rides the tunnel it bought — the block the edge reads is asserted against the block the codec writes, so this is the carrier's proof, not the codec's.
    #[test]
    fn the_connect_ip_carrier_opens_one_tunnel_over_quic_and_carries_a_datagram() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = quic_ip_edge(sock, server, seen_tx, udp_tx, 1);
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let (mut lane, assigned) = Ip::open(&dial, Some(quic)).expect("opens");
        let assigned = assigned.expect("an address");
        assert!(!assigned.refused(), "the tunnel owns an address");
        assert_eq!(assigned.bytes(), &[198, 51, 100, 9]);
        assert_eq!(assigned.width(), 4, "an IPv4 tunnel");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("block");
        let mut want = Vec::new();
        connectip::connect_ip_qpack(&format!("localhost:{port}"), "*", 0, "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the block the lane wrote");
        let written = lane
            .write(
                &[198, 51, 100, 9],
                &[203, 0, 113, 9],
                40_000,
                443,
                b"hello ip",
            )
            .expect("writes");
        assert!(written, "the packet was built");
        lane.flush().expect("flushes");
        let (destination, port, payload) = udp_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the edge read it");
        assert_eq!(destination, vec![203, 0, 113, 9]);
        assert_eq!(port, 443);
        assert_eq!(payload, b"hello ip");
        // The reply comes back from the destination, and the lane reads it as a packet whose source is where the datagram went.
        let packet = lane.read().expect("reads").expect("a reply");
        let read = connectip::udp_from_packet(&packet).expect("parses");
        assert!(read.verified);
        assert_eq!(
            read.source,
            &[203, 0, 113, 9],
            "the reply is from the target"
        );
        assert_eq!(read.destination, &[198, 51, 100, 9]);
        assert_eq!(read.payload, b"hello ip");
        edge.join().expect("joins");
    }

    /// A QUIC lane belongs to the pool, not to the lease that opened it: one lease ending leaves the connection the other still rides, the last ending parks the lane with its thread gone, and the next flow rides the same handshake instead of paying for a new one.
    #[test]
    fn a_lane_outlives_its_leases_and_the_next_flow_rides_it() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = quic_ip_edge(sock, server, seen_tx, udp_tx, 1);
        let dial = crate::quic::QuicDial {
            id: [0u8; 16],
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            upstream: None,
            roots: Some(roots.clone().into()),
        };
        let first = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
            .expect("a pooled stream");
        let lane = std::sync::Arc::clone(&first.conn);
        assert!(crate::quic::pool_holds(&dial), "a live lease holds it");
        let second = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
            .expect("a second stream on the same connection");
        drop(first);
        assert!(
            crate::quic::pool_holds(&dial),
            "one lease ending does not evict a connection the other still rides"
        );
        {
            let foxy = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
            let (mut lane, _) = Ip::open(&foxy, Some(second)).expect("the tunnel opens");
            assert!(
                lane.write(
                    &[198, 51, 100, 9],
                    &[203, 0, 113, 9],
                    40_000,
                    443,
                    b"hello ip"
                )
                .expect("writes"),
                "the packet was built"
            );
            lane.flush().expect("flushes");
            udp_rx
                .recv_timeout(Duration::from_secs(60))
                .expect("the edge read it");
            lane.read().expect("reads").expect("a reply");
        }
        // The park is the pump's own report and it lands inside one poll of a quiet socket, so waiting for the flag is the witness that an idle edge keeps its connection and drops its thread.
        for _ in 0..60 {
            if crate::quic::lane_parked(&dial) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            crate::quic::pool_holds(&dial),
            "the lane outlived the last lease that rode it"
        );
        assert!(crate::quic::lane_parked(&dial), "the pump said it left");
        let third = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
            .expect("the next flow rides the parked lane");
        assert!(
            std::sync::Arc::ptr_eq(&lane, &third.conn),
            "one handshake serves three flows, not three handshakes"
        );
        assert!(
            !crate::quic::lane_parked(&dial),
            "the lease put a pump back behind the lane"
        );
        drop(third);
        edge.join().expect("joins");
    }

    /// A lane lends a bounded number of flows: the lookup after its grant is spent hands it back for a fresh dial, and a flow already riding it is left alone rather than closed with it.
    #[test]
    fn a_lane_that_lent_its_whole_grant_of_flows_is_handed_back() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = quic_ip_edge(sock, server, seen_tx, udp_tx, 1);
        let dial = crate::quic::QuicDial {
            id: [0u8; 16],
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            upstream: None,
            roots: Some(roots.clone().into()),
        };
        let mut last = None;
        for flow in 1..=crate::quic::MAX_FLOWS_ON_LANE {
            let lease = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
                .expect("a lease on the lane");
            if flow == crate::quic::MAX_FLOWS_ON_LANE {
                last = Some(lease);
            } else {
                drop(lease);
            }
        }
        assert!(
            crate::quic::pool_holds(&dial),
            "a spent lane is held until a lease looks at it"
        );
        assert!(
            crate::quic::lane_spent(&dial),
            "the lane has no flow left to lend"
        );
        assert!(
            crate::quic::lane_handed_back(&dial),
            "a spent lane is not the one a flow rides"
        );
        assert!(
            !crate::quic::pool_holds(&dial),
            "the hand-back took the entry out of the pool"
        );
        let foxy = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let (mut tunnel, _) = Ip::open(&foxy, last).expect("the rode-over lane still carries it");
        assert!(
            tunnel
                .write(
                    &[198, 51, 100, 9],
                    &[203, 0, 113, 9],
                    40_000,
                    443,
                    b"at the cap"
                )
                .expect("writes"),
            "the last flow the lane lends still carries bytes"
        );
        tunnel.flush().expect("flushes");
        udp_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the edge read it");
        tunnel.read().expect("reads").expect("a reply");
        edge.join().expect("joins");
    }

    /// MASQUE over the pooled QUIC connection: a QPACK block naming `connect-udp` and the capsule protocol, and a datagram riding one DATAGRAM capsule inside one DATA frame — the block the edge reads is asserted against the block the codec writes, so this is the carrier's proof, not the codec's.
    #[test]
    fn the_masque_carrier_opens_connect_udp_over_quic_and_echoes_a_datagram() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = quic_udp_edge(sock, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("block");
        let mut want = Vec::new();
        masque::connect_udp_qpack(
            &format!("localhost:{port}"),
            "example.com",
            443,
            "the-pass",
            &mut want,
        );
        assert_eq!(block, want, "the edge reads the block the lane wrote");
        lane.write_datagram(b"hello udp").expect("writes");
        let mut back = [0u8; 64];
        let mut at = 0usize;
        while at < b"hello udp".len() {
            match lane.read_datagram(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        assert_eq!(&back[..at], b"hello udp");
        edge.join().expect("joins");
    }

    /// The QUIC twin of a frame that carries two datagrams: the edge answers a DATA frame with the frame it read, header and capsules together, so one frame leaving the lane must come back as two datagrams in order.
    #[test]
    fn a_quic_frame_of_two_datagrams_arrives_as_two_datagrams() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let edge = quic_udp_edge(sock, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        lane.set_read_quantum(Duration::from_secs(5));
        let mut both = Vec::new();
        masque::datagram_encode(b"first", &mut both);
        masque::datagram_encode(b"second", &mut both);
        lane.write_all(&both).expect("writes one frame");
        for want in [b"first".as_slice(), b"second".as_slice()] {
            let mut back = [0u8; 64];
            let mut at = 0usize;
            while at < want.len() {
                match lane.read_datagram(&mut back[at..]) {
                    Ok(0) => panic!("the echo ended early"),
                    Ok(read) => at += read,
                    Err(error) => panic!("the echo failed: {error}"),
                }
            }
            assert_eq!(&back[..at], want);
        }
        edge.join().expect("joins");
    }

    #[test]
    fn the_http2_carrier_reads_a_huffman_coded_status() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 4096];
            let _ = tls.read(&mut sink);
            // an indexed `:status` of 200, which is one byte
            let mut out = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
            tls.write_all(&out).expect("answers");
            std::thread::sleep(Duration::from_millis(100));
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    #[test]
    fn a_pinned_edge_that_is_not_the_pin_is_refused() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            let _ = tls.handshake();
            std::thread::sleep(Duration::from_millis(200));
        });
        let wrong = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let dial = dial_for(roots, port, Carrier::H1, wrong);
        assert!(Tunnel::open(&dial, "example.com:443", None).is_err());
        edge.join().expect("joins");
    }

    #[test]
    fn a_pinned_edge_that_is_the_pin_opens_the_tunnel() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let right =
            foxy::pin::Pins::parse([foxy::pin::spki_pin(&server.cert_chain[0]).expect("pins")]);
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 1024];
            let _ = tls.read(&mut sink);
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            std::thread::sleep(Duration::from_millis(100));
        });
        let dial = dial_for(roots, port, Carrier::H1, right);
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    /// A device whose trust store cannot build the edge's chain is not a device that distrusts the edge: the pinned leaf is its own anchor, so the tunnel opens and carries bytes where the same edge with no pin is refused.
    #[test]
    fn a_pinned_leaf_carries_the_tunnel_when_the_store_cannot_build_the_chain() {
        let (_foreign, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let right =
            foxy::pin::Pins::parse([foxy::pin::spki_pin(&server.cert_chain[0]).expect("pins")]);
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 1024];
            let _ = tls.read(&mut sink);
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let read = tls.read(&mut sink).expect("reads the payload");
            tls.write_all(&sink[..read]).expect("echoes");
        });
        // The roots of some other hand: the same shape of certificate, on a chain that does not verify.
        let (roots, _) = minted(b"http/1.1");
        let dial = dial_for(roots, port, Carrier::H1, right);
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None)
            .expect("the pinned leaf is its own anchor");
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    /// The anchor is the key the operator named, not any key: a pin that is not this edge's leaf leaves the stale store exactly as refusing as it was.
    #[test]
    fn a_pin_that_is_not_the_edges_key_is_still_refused_without_a_trust_store() {
        let (_foreign, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            let _ = tls.handshake();
        });
        let wrong = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let (roots, _) = minted(b"http/1.1");
        let dial = dial_for(roots, port, Carrier::H1, wrong);
        let failure = Tunnel::open(&dial, "example.com:443", None)
            .err()
            .expect("a stranger's pin");
        assert_eq!(failure, Failure::Untrusted, "{failure}");
        edge.join().expect("joins");
    }

    /// Pinning replaces who signed the leaf, not what the leaf says: a pinned key answering for a name the certificate does not cover is still refused, which is the check a pinned leaf alone would have skipped.
    #[test]
    fn a_pinned_leaf_still_has_to_answer_the_name_it_was_dialled_for() {
        let (_foreign, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let right =
            foxy::pin::Pins::parse([foxy::pin::spki_pin(&server.cert_chain[0]).expect("pins")]);
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            let _ = tls.handshake();
        });
        let (roots, _) = minted(b"http/1.1");
        // The minted leaf covers `localhost`; this dial names another host to the same address.
        let dial = FoxyDial {
            host: "edge.test".to_owned(),
            ..dial_for(roots, port, Carrier::H1, right)
        };
        let failure = Tunnel::open(&dial, "example.com:443", None)
            .err()
            .expect("the wrong name");
        assert_eq!(failure, Failure::Untrusted, "{failure}");
        edge.join().expect("joins");
    }

    /// The edge half of the QUIC carrier: a control stream, one HEADERS frame with a QPACK status, and DATA frames echoing the uplink back then streaming `downlink` — the proof the QUIC lane lacked: the wire request compared byte for byte with the lane's block, the status read through the QPACK decoder, and the bytes after the head travelling through the tunnel; a codec test answers none of those three.
    fn h3_edge(
        sock: crate::quic::Datagram,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        uni: std::sync::mpsc::Sender<Vec<(u64, Vec<u8>, bool)>>,
        downlink: Vec<u8>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let tag = format!("ferrox-foxy-h3-{}-{stamp}", std::process::id());
            let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
            let key_path = std::env::temp_dir().join(format!("{tag}.key"));
            std::fs::write(&cert_path, &cert_pem).expect("stages cert");
            std::fs::write(&key_path, &key_pem).expect("stages key");
            let mut config = crate::quic::server_config(crate::quic::ALPN);
            config
                .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
                .expect("loads chain");
            config
                .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
                .expect("loads key");
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            // A server's own control stream is its first unidirectional stream, id 3, and the client's SETTINGS are answered on it.
            let mut control = Vec::new();
            frames::quic_varint(&mut control, frames::H3_DATA);
            frames::quic_varint(&mut control, 0);
            conn.stream_send(3, &control, true).expect("opens control");
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut request = None;
            // The client's unidirectional streams, id plus bytes plus whether the lane closed one: control must arrive whole and stay open.
            let mut uni_streams: Vec<(u64, Vec<u8>, bool)> = Vec::new();
            let uni_ready = |streams: &[(u64, Vec<u8>, bool)]| {
                [2u64, 6, 10].iter().all(|want| {
                    streams
                        .iter()
                        .any(|(id, bytes, _)| id == want && !bytes.is_empty())
                })
            };
            while request.is_none() || !uni_ready(&uni_streams) {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 == 2 {
                        drain_uni(&mut conn, id, &mut uni_streams);
                        continue;
                    }
                    // The control stream is unidirectional and the request is not, so the stream id itself tells them apart.
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        request = Some((id, piece));
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let _ = uni.send(uni_streams);
            let (stream, raw) = request.expect("read");
            let mut at = 0usize;
            let frame = frames::h3_frame(&raw, &mut at).expect("a frame");
            let block = raw[at..at + frame.length as usize].to_vec();
            let _ = seen.send(block);

            let mut reply = Vec::new();
            frames::quic_varint(&mut reply, frames::H3_HEADERS);
            frames::quic_varint(&mut reply, 3);
            // `0xd9` is QPACK static index 25, which is `:status 200`: the indexed field line with a six-bit prefix, then the block's two required zero bytes.
            reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
            conn.stream_send(stream, &reply, false).expect("answers");
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
            echo_stream(
                &sock, local, &mut conn, &mut buf, &mut out, stream, &downlink,
            );
        })
    }

    /// Streams `downlink` onto one request stream as DATA frames, held to the length of the lane's own payload until the uplink has come in: a lane that never wrote gets nothing back, and a downlink longer than the uplink still arrives. The tunnel half of the loopback proof, and the downlink half the byte-count witnesses stand on.
    fn echo_stream(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        conn: &mut quiche::Connection,
        buf: &mut [u8; 1350],
        out: &mut [u8; 1350],
        stream: u64,
        downlink: &[u8],
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut received: Vec<u8> = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        let mut frame: Vec<u8> = Vec::new();
        let mut sent = 0usize;
        // The head of what the edge sends is the echo's debt: no byte leaves before the uplink paid for it, so a lane that never wrote never reads. Past `PAYLOAD` the stream is the edge's own to give and it flows at the credit's pace, which is what lets a downlink longer than the uplink arrive at all.
        let echo = PAYLOAD.len().min(downlink.len());
        let mut quiet = std::time::Instant::now();
        loop {
            assert!(std::time::Instant::now() < deadline, "the tunnel echoes");
            match crate::quic::server_poll(sock, &mut buf[..]) {
                Some((n, from)) => {
                    let info = quiche::RecvInfo { from, to: local };
                    conn.recv(&mut buf[..n], info).expect("drives");
                    pending.extend_from_slice(&drain(&mut *conn, stream));
                }
                // A quiet turn still drives the connection: its timer is what turns a datagram the loopback dropped back into a retransmission.
                None => conn.on_timeout(),
            }
            let mut at = 0usize;
            let mut whole = 0usize;
            while let Some(head) = frames::h3_frame(&pending, &mut at) {
                let end = at + head.length as usize;
                if end > pending.len() {
                    break;
                }
                if let frames::H3Event::Data { payload, .. } =
                    frames::h3_event(head, &pending[at..end])
                {
                    received.extend_from_slice(payload);
                }
                at = end;
                whole = end;
            }
            // Only what whole frames cover is spent: a header that arrived without its payload has to wait for the rest of it.
            pending.drain(..whole);
            if sent < downlink.len() {
                let owed = if sent < echo {
                    received.len().min(downlink.len())
                } else {
                    downlink.len()
                };
                let n = owed.saturating_sub(sent).min(16_384);
                if n > 0 {
                    frame.clear();
                    frames::quic_varint(&mut frame, frames::H3_DATA);
                    frames::quic_varint(&mut frame, n as u64);
                    frame.extend_from_slice(&downlink[sent..sent + n]);
                    // The credit-aware write: a send buffer the reader has not emptied takes only part of a frame, and the rest lives on solely because the writer waited for it.
                    assert!(
                        crate::quic::stream_send_all(conn, sock, stream, &frame, false, deadline),
                        "the echo reaches the lane"
                    );
                    sent += n;
                }
            }
            let mut wrote = false;
            while let Ok((written, info)) = conn.send(out) {
                wrote = true;
                let _ = sock.send_to(&out[..written], info.to);
            }
            // Handing quiche the bytes is not delivering them: the tail of a burst survives a dropped datagram only while someone is left to retransmit it, so the edge stays until a whole quiet period has nothing to send.
            if wrote || sent < downlink.len() {
                quiet = std::time::Instant::now();
            } else if sent == downlink.len() && quiet.elapsed() >= Duration::from_millis(200) {
                return;
            }
        }
    }

    /// One unidirectional stream's bytes plus whether it has closed, merged into the snapshot the test asserts the lane's opening against.
    fn drain_uni(conn: &mut quiche::Connection, id: u64, streams: &mut Vec<(u64, Vec<u8>, bool)>) {
        let mut chunk = [0u8; 8192];
        loop {
            match conn.stream_recv(id, &mut chunk) {
                Ok((0, _)) | Err(_) => break,
                Ok((n, fin)) => match streams.iter_mut().find(|(known, _, _)| *known == id) {
                    Some((_, bytes, closed)) => {
                        bytes.extend_from_slice(&chunk[..n]);
                        *closed = *closed || fin;
                    }
                    None => streams.push((id, chunk[..n].to_vec(), fin)),
                },
            }
        }
    }

    /// Every byte a stream holds, read into a buffer that exists: a `Vec` handed to `stream_recv` is a zero-length slice and never receives anything.
    fn drain(conn: &mut quiche::Connection, id: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok((n, _)) = conn.stream_recv(id, &mut chunk) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        out
    }

    #[test]
    fn the_quic_carrier_sends_the_block_reads_the_status_and_carries_the_bytes() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let key_pem = crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, uni_rx) = std::sync::mpsc::channel();
        let edge = h3_edge(
            sock,
            crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE"),
            key_pem,
            seen_tx,
            uni_tx,
            PAYLOAD.to_vec(),
        );

        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("block");
        let mut want = Vec::new();
        hpack::qpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the same block the lane wrote");
        let uni = uni_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("uni streams");
        let stream = |id| {
            uni.iter()
                .find(|(known, _, _)| *known == id)
                .unwrap_or_else(|| panic!("stream {id} opened"))
        };
        let (_, control, control_fin) = stream(2);
        let mut at = 0usize;
        assert_eq!(control.first(), Some(&0x00), "a control stream type");
        at += 1;
        assert_eq!(control.get(at), Some(&0x04), "one SETTINGS frame");
        at += 1;
        let len = frames::quic_read(control, &mut at).expect("a length") as usize;
        assert_eq!(
            control.len(),
            at + len,
            "a complete SETTINGS, no truncation"
        );
        assert!(!control_fin, "control stays open");
        for (id, first) in [(6u64, 0x02u8), (10, 0x03)] {
            let (_, bytes, fin) = stream(id);
            assert_eq!(bytes.as_slice(), &[first], "qpack stream {id}");
            assert!(!fin, "qpack stream {id} stays open");
        }
        round_trip(&mut tunnel);
        // The frame's varints are sent beside the payload rather than staged with it, so the lane's write buffer never grows: capacity is the witness, because the bytes are the same either way.
        let Tunnel::H3(lane) = &tunnel else {
            panic!("an h3 lane");
        };
        assert_eq!(lane.out.capacity(), 0, "no buffer was staged to write one");
        edge.join().expect("joins");
    }

    /// A downlink several times the old frame cap: bytes no window could have held whole, so a lane that stages a frame before handing it over would have to grow one.
    const DOWNLINK: usize = 204_800;

    #[test]
    fn the_h3_downlink_hands_the_caller_the_frame_without_staging_it() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, _uni_rx) = std::sync::mpsc::channel();
        let downlink: Vec<u8> = (0..DOWNLINK as u64).map(|i| (i % 251) as u8).collect();
        let edge = h3_edge(
            sock,
            crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE"),
            crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY"),
            seen_tx,
            uni_tx,
            downlink.clone(),
        );

        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        seen_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the edge read the block");
        tunnel.write_all(PAYLOAD).expect("writes");
        tunnel.flush().expect("flushes");

        // Small caller buffers: every frame spans many reads, so a resumed-read bug cannot hide behind one big pull.
        let mut chunk = vec![0u8; 4096];
        let mut got: Vec<u8> = Vec::new();
        while got.len() < downlink.len() {
            let read = tunnel.read(&mut chunk).expect("reads");
            assert!(
                read > 0,
                "a read that returns nothing is an EOF, and the stream has not ended"
            );
            assert!(
                read <= chunk.len(),
                "the lane never hands back more than the caller asked for"
            );
            got.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(
            got, downlink,
            "every downlink byte arrives, in order, with no framing in it"
        );
        let Tunnel::H3(lane) = &tunnel else {
            panic!("an h3 lane");
        };
        // The window holds at most a header and the spill of the frame it names: under the old lane this is where the whole 16 KiB frame sat before any of it reached the caller.
        assert!(
            lane.filled - lane.carried <= H3_PEEK,
            "the window staged {} bytes of a frame the caller was reading",
            lane.filled - lane.carried
        );
        assert_eq!(lane.body, 0, "the frame in flight was delivered, not kept");
        edge.join().expect("joins");
    }
}
