//! The live lane: `#[ignore]`d for needing a network; it prints metadata only, never a pass, token or header.
//!
//! ```text
//! FOXY_EMAIL  the account to sign in with
//! FOXY_PASS   its password
//! FOXY_CODE   the emailed two-factor code, when the account asks for one
//! FOXY_COUNTRY the country to pin, United States when nothing says otherwise
//! ```

use crate::foxy::{Carrier, FoxyDial, Tunnel};
use crate::foxy_account::{Account, Auth, Endpoint};
use crate::foxy_challenge::Jar;
use ferrox_core::foxy::Pass;
use std::io::{Read, Write};
use std::net::ToSocketAddrs as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PROBE_HOST: &str = "api.ipify.org";
const PROBE_PATH: &str = "/";
const TRACE_HOST: &str = "www.cloudflare.com";
const TRACE_PATH: &str = "/cdn-cgi/trace";
const READ: Duration = Duration::from_secs(20);
/// One host, one small and one large payload: a charge fixed per flow and a charge per byte separate across the pair.
const PAYLOAD_HOST: &str = "speedtest.tele2.net";
const PAYLOAD_SMALL: (&str, usize) = ("/1MB.zip", 2 << 20);
const PAYLOAD_LARGE: (&str, usize) = ("/10MB.zip", 12 << 20);
/// The smallest answer worth measuring: a redirect page is not a payload.
const PAYLOAD_FLOOR: usize = 512 << 10;
/// What a canceled flow reads before it closes: a browser that drops a download after its first bytes.
const ABORT_READ: usize = 512 << 10;
const PAYLOAD_WAIT: Duration = Duration::from_secs(45);
/// The whole crawl, so one dead host cannot spend the live job's clock.
const PAYLOAD_TOTAL: Duration = Duration::from_secs(600);
/// The plane's counter is another writer's arithmetic: a charge showed up thirteen seconds after its transfer, so the first look comes later than that and a figure is taken only when two looks agree.
const SETTLE: Duration = Duration::from_secs(15);
/// Mints spent waiting on one charge, so a counter that never settles still ends the test.
const SETTLE_MINTS: usize = 12;
/// How long the lane sits connected with no flow, to read what an idle account is charged.
const IDLE: Duration = Duration::from_secs(60);
/// What an idle window may cost before the account is read as shared: anything under this is a counter's own digest, not a transfer.
const IDLE_GRACE: u64 = 64 << 10;

fn account() -> Option<Account> {
    let roots = crate::quic::system_roots();
    Some(Account {
        fxa: Endpoint::parse(ferrox_core::foxy::account::FXA_SERVER, roots.clone())?,
        guardian: Endpoint::parse(ferrox_core::foxy::account::GUARDIAN_SERVER, roots)?,
        jar: std::sync::Arc::new(Mutex::new(Jar::default())),
        pending: std::sync::Arc::new(Mutex::new(None)),
        auth: std::sync::Arc::new(Mutex::new(Auth {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
        })),
        pass: std::sync::Arc::new(Mutex::new(Pass {
            token: std::sync::Arc::from(""),
            expires_at: None,
            quota_remaining: None,
            quota_reset: None,
            quota_limit: None,
        })),
        tokens: None,
    })
}

/// One request through the tunnel, read back as its head: the tunnel is opaque bytes to whoever dials it.
fn through_tunnel<T: Read + Write>(tunnel: &mut T, host: &str, path: &str) -> Option<String> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tunnel.write_all(request.as_bytes()).ok()?;
    tunnel.flush().ok()?;
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let deadline = Instant::now() + READ;
    while !head.windows(4).any(|pair| pair == b"\r\n\r\n") && Instant::now() < deadline {
        match tunnel.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    String::from_utf8(head).ok()
}

fn opened<T: Read + Write>(tunnel: &mut T, country: &str) -> Option<String> {
    let trace = through_tunnel(tunnel, TRACE_HOST, TRACE_PATH)?;
    let seen = crate::foxy::exit_country(trace.as_bytes())?;
    (seen.eq_ignore_ascii_case(country) || seen == "T1" || country == "REC").then_some(seen)
}

/// One carrier on one edge, as the lane would dial it.
fn dial(
    edge: &ferrox_core::foxy::Candidate,
    carrier: Carrier,
    pass: &Pass,
) -> (FoxyDial, crate::quic::QuicDial) {
    let dial = FoxyDial {
        host: edge.host.clone(),
        port: edge.port,
        address: None,
        carrier,
        upstream: None,
        roots: crate::quic::system_roots(),
        pins: ferrox_core::foxy::pin::Pins::default(),
        pass: pass.clone(),
    };
    let quic_dial = crate::quic::QuicDial {
        id: [0u8; 16],
        host: std::sync::Arc::clone(&edge.host),
        address: std::sync::Arc::clone(&edge.host),
        port: edge.port,
        upstream: None,
        roots: None,
    };
    (dial, quic_dial)
}

/// One carrier, one edge: CONNECT, a request through it, the exit country — refused edge vs unreachable network.
fn try_carrier(
    carrier: Carrier,
    edge: &ferrox_core::foxy::Candidate,
    pass: &Pass,
    country: &str,
) -> Result<String, String> {
    let (dial, quic_dial) = dial(edge, carrier, pass);
    let started = Instant::now();
    let quic = match carrier {
        Carrier::H3 => {
            crate::quic::pooled_stream_within(&quic_dial, crate::quic::HANDSHAKE_TIMEOUT)
        }
        _ => None,
    };
    // The lease goes into the open and rides the lane, so the probe gives the pool entry back when it ends.
    let mut tunnel = Tunnel::open(&dial, &format!("{PROBE_HOST}:80"), quic)
        .map_err(|failure| failure.to_string())?;
    let ip = through_tunnel(&mut tunnel, PROBE_HOST, PROBE_PATH)
        .ok_or_else(|| "no answer through the tunnel".to_owned())?;
    let seen = opened(&mut tunnel, country);
    Ok(format!(
        "{} {} in {:?}, exit {}",
        ip.split_whitespace().last().unwrap_or("?"),
        edge.authority(),
        started.elapsed(),
        seen.unwrap_or_else(|| "unread".to_owned())
    ))
}

/// One request the probe carries: its method and path, and the most payload it may take.
#[derive(Clone, Copy)]
struct Ask<'a> {
    method: &'a str,
    path: &'a str,
    cap: usize,
}

/// One request for a known payload, read back through the tunnel until its cap or its end: what the exit carried, counted where it lands.
fn carried(
    carrier: Carrier,
    edge: &ferrox_core::foxy::Candidate,
    pass: &Pass,
    ask: Ask<'_>,
    until: Instant,
) -> Result<usize, String> {
    let Ask { method, path, cap } = ask;
    let (dial, quic_dial) = dial(edge, carrier, pass);
    let quic = match carrier {
        Carrier::H3 => {
            crate::quic::pooled_stream_within(&quic_dial, crate::quic::HANDSHAKE_TIMEOUT)
        }
        _ => None,
    };
    let mut tunnel = Tunnel::open(&dial, &format!("{PAYLOAD_HOST}:80"), quic)
        .map_err(|failure| failure.to_string())?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {PAYLOAD_HOST}\r\nUser-Agent: ferrox-live\r\nConnection: close\r\n\r\n"
    );
    tunnel
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    tunnel.flush().map_err(|error| error.to_string())?;
    let mut chunk = vec![0u8; 32 * 1024];
    let mut got = 0usize;
    while got < cap && Instant::now() < until {
        match tunnel.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => got += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    // The lane's own end of a flow, on every path: the client half ends, and a stream the edge was still filling is stopped rather than left open.
    let _ = tunnel.finish();
    tunnel.settle();
    Ok(got)
}

/// The plane's counter after a charge has landed: mint until two mints agree, so a figure read before the plane wrote it is not read as the charge.
fn settled(account: &Account, mut was: u64) -> u64 {
    for _ in 0..SETTLE_MINTS {
        std::thread::sleep(SETTLE);
        account
            .renew()
            .expect("mints a pass while the counter settles");
        let now = account
            .current()
            .quota_remaining
            .expect("the plane names an allowance on every mint");
        if now == was {
            return now;
        }
        was = now;
    }
    was
}

/// The charge per carried byte, in thousandths: whole and three digits.
fn per_byte(charged: u64, bytes: u64) -> (u64, u64) {
    let milli = charged.saturating_mul(1000).checked_div(bytes).unwrap_or(0);
    (milli / 1000, milli % 1000)
}

/// What a flow that ended before its response did costs: the payload it read and the window the edge was allowed to fill ahead of it.
fn canceled(
    account: &Account,
    carrier: Carrier,
    edge: &ferrox_core::foxy::Candidate,
    pass: &Pass,
    was: u64,
    deadline: Instant,
) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Ok(());
    }
    let until = (Instant::now() + PAYLOAD_WAIT).min(deadline);
    let read = carried(
        carrier,
        edge,
        pass,
        Ask {
            method: "GET",
            path: PAYLOAD_LARGE.0,
            cap: ABORT_READ,
        },
        until,
    )?;
    std::thread::sleep(SETTLE);
    let charged = was.saturating_sub(settled(account, was));
    let (whole, fraction) = per_byte(charged, read as u64);
    println!(
        "closed {PAYLOAD_HOST}{} after {read} bytes: {charged} charged ({whole}.{fraction:03}x) for a canceled flow",
        PAYLOAD_LARGE.0
    );
    Ok(())
}

/// One carrier's charge with every other cost held still: an idle window, a head, a small payload and a large one, each read only after the counter has stopped moving.
fn brackets(
    account: &Account,
    carrier: Carrier,
    edge: &ferrox_core::foxy::Candidate,
    pass: &Pass,
    deadline: Instant,
) -> Result<(), String> {
    let mut was = pass
        .quota_remaining
        .ok_or("the plane names no allowance; without one there is nothing to charge")?;
    was = settled(account, was);
    std::thread::sleep(IDLE);
    let idle = settled(account, was);
    let drained = was.saturating_sub(idle);
    println!(
        "idle {:.0}s through {carrier:?}: {drained} bytes charged with no flow",
        IDLE.as_secs_f64()
    );
    // A counter that moves with no flow is another client's traffic on the same account; bracketing a transfer over it would charge that client's bytes to the transfer.
    assert!(
        drained <= IDLE_GRACE,
        "the allowance fell {drained} bytes over {} s with no flow: another client shares the account, so no transfer can be bracketed",
        IDLE.as_secs_f64()
    );
    was = idle;
    let until = (Instant::now() + PAYLOAD_WAIT).min(deadline);
    let head = carried(
        carrier,
        edge,
        pass,
        Ask {
            method: "HEAD",
            path: PAYLOAD_LARGE.0,
            cap: 4096,
        },
        until,
    )?;
    let now = settled(account, was);
    let fixed = was.saturating_sub(now);
    println!(
        "HEAD {PAYLOAD_HOST}{}: {head} bytes carried, {fixed} charged",
        PAYLOAD_LARGE.0
    );
    was = now;
    let mut marks = Vec::new();
    for (path, cap) in [PAYLOAD_SMALL, PAYLOAD_LARGE] {
        if Instant::now() >= deadline {
            return Err(format!("{path}: the crawl spent its clock"));
        }
        let until = (Instant::now() + PAYLOAD_WAIT).min(deadline);
        let bytes = carried(
            carrier,
            edge,
            pass,
            Ask {
                method: "GET",
                path,
                cap,
            },
            until,
        )?;
        if bytes < PAYLOAD_FLOOR {
            return Err(format!("{path}: {bytes} bytes is not a payload"));
        }
        let bytes = bytes as u64;
        let now = settled(account, was);
        let charged = was.saturating_sub(now);
        let (whole, fraction) = per_byte(charged, bytes);
        println!(
            "GET {PAYLOAD_HOST}{path}: {bytes} bytes carried, {charged} charged ({whole}.{fraction:03}x)"
        );
        marks.push((bytes, charged));
        was = now;
    }
    let (small_bytes, small_charge) = marks[0];
    let (large_bytes, large_charge) = marks[1];
    let delta_bytes = large_bytes.saturating_sub(small_bytes);
    let delta_charge = large_charge.saturating_sub(small_charge);
    let (whole, fraction) = per_byte(delta_charge, delta_bytes);
    println!(
        "{carrier:?}: {whole}.{fraction:03} bytes charged per byte carried between {small_bytes} and {large_bytes} bytes; {fixed} bytes fixed per flow"
    );
    // Last, so a closing flow's fetch cannot be read as the large payload's: what a cancel costs is the window the edge was allowed to fill ahead of the caller.
    canceled(account, carrier, edge, pass, was, deadline)?;
    // A tunnel that costs its payload spends one allowance byte per carried byte; a per-flow cost is the head's, and is not the slope.
    assert!(
        delta_charge.saturating_mul(4) <= delta_bytes.saturating_mul(5),
        "{carrier:?} charged {whole}.{fraction:03} bytes per carried byte between {small_bytes} and {large_bytes}: {large_charge} for {large_bytes} after {small_charge} for {small_bytes}, {fixed} fixed per flow"
    );
    Ok(())
}

/// The plane charges what the exit carried: a mint before and after a known payload names the ratio.
#[test]
#[ignore = "needs a Firefox account and the network; run by foxy-live.yml"]
fn the_allowance_charges_the_payload_the_tunnel_carried() {
    let email = std::env::var("FOXY_EMAIL").unwrap_or_default();
    let password = std::env::var("FOXY_PASS").unwrap_or_default();
    let country = std::env::var("FOXY_COUNTRY").unwrap_or_else(|_| "US".to_owned());
    assert!(
        !email.is_empty(),
        "FOXY_EMAIL is the account to sign in with"
    );
    assert!(!password.is_empty(), "FOXY_PASS is its password");

    let Some(account) = account() else {
        panic!("the account plane URLs are not the ones this tree knows");
    };
    account.sign_in(&email, &password).expect("signs in");
    if account.needs_code() {
        let code = std::env::var("FOXY_CODE").expect("FOXY_CODE is the emailed code");
        account.verify_code(&code).expect("verifies");
    }
    account.renew().expect("mints a pass");
    let mut pass = account.current();
    println!("the plane names its allowance: {:?}", pass.allowance_line());

    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let picked = ferrox_core::foxy::catalog::tier(&edges, &country, "", 3);
    let edge = picked
        .first()
        .unwrap_or_else(|| panic!("the catalogue publishes no edge for {country}"));

    let total = Instant::now() + PAYLOAD_TOTAL;
    let mut measured = 0usize;
    for carrier in crate::foxy::carrier("auto").order() {
        if Instant::now() >= total {
            break;
        }
        account
            .renew()
            .expect("mints a pass before the carrier's first payload");
        pass = account.current();
        match brackets(&account, carrier, edge, &pass, total) {
            Ok(()) => {
                measured += 1;
                break;
            }
            Err(why) => println!("{carrier:?}: {why}"),
        }
    }
    assert!(measured > 0, "no carrier carried a payload to measure");
}

/// Every carrier in `auto`'s order on one pinned-country edge; all refused is a failure, not a green exit.
#[test]
#[ignore = "needs a Firefox account and the network; run by foxy-live.yml"]
fn the_lane_carries_a_tunnel_on_the_carrier_the_edge_answers() {
    let email = std::env::var("FOXY_EMAIL").unwrap_or_default();
    let password = std::env::var("FOXY_PASS").unwrap_or_default();
    let country = std::env::var("FOXY_COUNTRY").unwrap_or_else(|_| "US".to_owned());
    assert!(
        !email.is_empty(),
        "FOXY_EMAIL is the account to sign in with"
    );
    assert!(!password.is_empty(), "FOXY_PASS is its password");

    println!("trust anchors read: {}", crate::quic::system_roots().len());
    let Some(account) = account() else {
        panic!("the account plane URLs are not the ones this tree knows");
    };
    account.sign_in(&email, &password).expect("signs in");
    if account.needs_code() {
        let code = std::env::var("FOXY_CODE").expect("FOXY_CODE is the emailed code");
        account.verify_code(&code).expect("verifies");
    }
    account.renew().expect("mints a pass");
    let pass = account.current();
    assert!(
        pass.token.len() > 32,
        "the pass is a token and not a refusal"
    );
    println!("pass minted, quota left {:?}", pass.quota_remaining);

    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let picked = ferrox_core::foxy::catalog::tier(&edges, &country, "", 3);
    assert!(
        !picked.is_empty(),
        "the catalogue publishes no edge for {country}"
    );
    let edge = &picked[0];
    println!(
        "country {country} edge {} city {} of {} published",
        edge.authority(),
        edge.city,
        edges.len()
    );

    let mut answered = Vec::new();
    for carrier in crate::foxy::carrier("auto").order() {
        match try_carrier(carrier, edge, &pass, &country) {
            Ok(report) => {
                println!("{carrier:?} {report}");
                answered.push(format!("{carrier:?}"));
                break;
            }
            Err(why) => println!("{carrier:?} refused: {why}"),
        }
    }
    assert!(
        !answered.is_empty(),
        "no carrier opened a tunnel to {country} (edge {})",
        edge.authority()
    );
}

/// Does an edge name a UDP port at all? The `connect` entry is TCP, so a QUIC dial must reuse it over UDP.
#[test]
#[ignore = "needs the network; run by foxy-live.yml"]
fn the_quic_lane_reaches_the_edge_over_udp_or_says_why_not() {
    let country = std::env::var("FOXY_COUNTRY").unwrap_or_else(|_| "US".to_owned());
    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let picked = ferrox_core::foxy::catalog::tier(&edges, &country, "", 1);
    let Some(edge) = picked.first() else {
        panic!("the catalogue publishes no edge for {country}");
    };
    let dial = crate::quic::QuicDial {
        id: [0u8; 16],
        host: std::sync::Arc::clone(&edge.host),
        address: std::sync::Arc::clone(&edge.host),
        port: edge.port,
        upstream: None,
        roots: None,
    };
    // The same authority over TCP, so a failure names the protocol, not the address.
    let peer = format!("{}:{}", edge.host, edge.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next());
    let tcp = peer
        .and_then(|peer| std::net::TcpStream::connect_timeout(&peer, Duration::from_secs(10)).ok());
    println!(
        "tcp to {}: {}",
        edge.authority(),
        if tcp.is_some() { "answered" } else { "refused" }
    );
    match crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT) {
        Some(_) => println!("h3 handshake completed with {}", edge.authority()),
        None => println!("no h3 handshake with {} over udp/{}", edge.host, edge.port),
    }
}

/// Two CONNECTs (streams 1 and 3) on one session: only a live edge says whether it takes a shared handshake.
#[test]
#[ignore = "needs a Firefox account and the network; run by foxy-live.yml"]
fn a_second_connect_stream_on_one_session_names_what_the_edge_does() {
    let email = std::env::var("FOXY_EMAIL").unwrap_or_default();
    let password = std::env::var("FOXY_PASS").unwrap_or_default();
    let country = std::env::var("FOXY_COUNTRY").unwrap_or_else(|_| "US".to_owned());
    assert!(
        !email.is_empty(),
        "FOXY_EMAIL is the account to sign in with"
    );
    assert!(!password.is_empty(), "FOXY_PASS is its password");

    let Some(account) = account() else {
        panic!("the account plane URLs are not the ones this tree knows");
    };
    account.sign_in(&email, &password).expect("signs in");
    if account.needs_code() {
        let code = std::env::var("FOXY_CODE").expect("FOXY_CODE is the emailed code");
        account.verify_code(&code).expect("verifies");
    }
    account.renew().expect("mints a pass");
    let pass = account.current();

    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let picked = ferrox_core::foxy::catalog::tier(&edges, &country, "", 3);
    let edge = picked
        .first()
        .unwrap_or_else(|| panic!("the catalogue publishes no edge for {country}"));
    let dial = FoxyDial {
        host: edge.host.clone(),
        port: edge.port,
        address: None,
        carrier: Carrier::H2,
        upstream: None,
        roots: crate::quic::system_roots(),
        pins: ferrox_core::foxy::pin::Pins::default(),
        pass: pass.clone(),
    };

    // Both CONNECTs ask the same target, so only the stream the edge answers on differs.
    let target = format!("{PROBE_HOST}:80");
    let mut session = crate::foxy::raw_h2_session(&dial).expect("one H2 session to the edge");
    let first = ask_stream(&mut session, 1, &target, &dial.pass.token);
    let second = ask_stream(&mut session, 3, &target, &dial.pass.token);
    println!("stream 1 answered {first:?}, stream 3 answered {second:?}");
    assert!(
        first.is_some(),
        "the first stream on a session the edge accepted carries a status"
    );
    assert!(
        second.is_some(),
        "the edge answers a second CONNECT on the same session, so one session can carry \
         many flows: a pool that opens one session per edge is what the fixed cost per \
         flow is paid for"
    );
    println!("the edge answers a second CONNECT on the same session, so the session can be pooled");
}

/// One CONNECT on one stream: `None` when the edge resets it or never answers — the two ways this probe says no.
fn ask_stream(
    session: &mut (impl Read + Write),
    stream: u32,
    target: &str,
    token: &str,
) -> Option<u16> {
    let mut block = Vec::with_capacity(96 + token.len());
    ferrox_core::foxy::hpack::hpack_connect(target, token, &mut block);
    let mut head = Vec::with_capacity(frames::H2_HEADER + block.len());
    let frame = ferrox_core::foxy::frames::H2Frame {
        kind: ferrox_core::foxy::frames::HEADERS,
        flags: 0x4,
        stream,
        length: block.len() as u32,
    };
    head.extend_from_slice(&frame.header());
    head.extend_from_slice(&block);
    session.write_all(&head).ok()?;
    session.flush().ok()?;
    let deadline = Instant::now() + READ;
    while Instant::now() < deadline {
        let mut header = [0u8; frames::H2_HEADER];
        read_frames_exact(session, &mut header).ok()?;
        let frame = ferrox_core::foxy::frames::H2Frame::parse(&header)?;
        let mut payload = vec![0u8; frame.length as usize];
        read_frames_exact(session, &mut payload).ok()?;
        match ferrox_core::foxy::frames::h2_event(frame, &payload, stream) {
            ferrox_core::foxy::frames::H2Event::Headers { block, .. } => {
                return ferrox_core::foxy::hpack::hpack_status(block);
            }
            ferrox_core::foxy::frames::H2Event::Reset { .. } => {
                println!("stream {stream}: the edge reset it");
                return None;
            }
            ferrox_core::foxy::frames::H2Event::Settings { ack: false, .. } => {
                let mut ack = Vec::new();
                let frame = ferrox_core::foxy::frames::H2Frame {
                    kind: ferrox_core::foxy::frames::SETTINGS,
                    flags: 0x1,
                    stream: 0,
                    length: 0,
                };
                ack.extend_from_slice(&frame.header());
                session.write_all(&ack).ok()?;
            }
            _ => {}
        }
    }
    println!("stream {stream}: no answer within {READ:?}");
    None
}

use ferrox_core::foxy::frames;

fn read_frames_exact(
    stream: &mut (impl Read + ?Sized),
    mut into: &mut [u8],
) -> std::io::Result<()> {
    while !into.is_empty() {
        match stream.read(into) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => into = &mut into[n..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
