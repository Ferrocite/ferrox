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

/// One carrier, one edge: CONNECT, a request through it, the exit country — refused edge vs unreachable network.
fn try_carrier(
    carrier: Carrier,
    edge: &ferrox_core::foxy::Candidate,
    pass: &Pass,
    country: &str,
) -> Result<String, String> {
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
