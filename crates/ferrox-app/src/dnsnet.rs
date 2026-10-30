//! The transports a DNS query rides: one datagram, one length-framed stream,
//! that stream under TLS, the same bytes as an HTTP/2 POST, or one QUIC
//! bidirectional stream. The wire message is the caller's; this module only
//! moves it and returns the answer bytes whole.

use crate::conn::Connection;
use crate::h2::{
    block_encode, frame_head, read_head, Decoder, F_ACK, F_END, F_END_HEADERS, T_CONT, T_DATA,
    T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS,
};
use crate::sockopt::SocketOptions;
use ferrox_core::tls::TlsProvider as _;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[allow(clippy::too_many_arguments)]
pub(crate) fn udp(
    host: &str,
    port: u16,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    if !local {
        if let Some(response) = crate::proxy::dns_udp(host, port, tag, query, timeout) {
            return Ok(response);
        }
    }
    let socket = crate::sockopt::datagram(options, host, port, timeout)?;
    socket
        .send(query)
        .map_err(|error| format!("dns udp send: {error}"))?;
    let mut response = vec![0u8; ferrox_core::dns::MESSAGE_MAX];
    let read = socket
        .recv(&mut response)
        .map_err(|error| format!("dns udp receive: {error}"))?;
    response.truncate(read);
    Ok(response)
}

pub(crate) fn tcp(
    host: &str,
    port: u16,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    let mut stream = connect(host, port, tag, options, timeout, local)?;
    write_frame(&mut stream, query)?;
    read_frame(&mut stream)
}

pub(crate) fn tls(
    host: &str,
    port: u16,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    let stream = connect(host, port, tag, options, timeout, local)?;
    let config = std::sync::Arc::new(ferrox_core::tls::TlsConfig {
        server_name: host.to_owned(),
        alpn: Vec::new().into(),
        roots: crate::quic::system_roots(),
        cert_pins: std::sync::Arc::default(),
        verify_names: std::sync::Arc::default(),
        pins: ferrox_core::foxy::pin::Pins::default(),
        cipher_suites: std::sync::Arc::default(),
        insecure: false,
        fingerprint: None,
        ech_config_list: None,
        websocket: false,
        master_key_log: None,
    });
    let mut stream = ferrox_core::tls::RustlsProvider::connect(&config, stream)
        .map_err(|error| format!("dns tls: {error}"))?;
    stream
        .handshake()
        .map_err(|error| format!("dns tls handshake: {error}"))?;
    write_frame(&mut stream, query)?;
    read_frame(&mut stream)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn doh(
    host: &str,
    port: u16,
    path: &str,
    cleartext: bool,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    let default_port = if cleartext { 80 } else { 443 };
    let authority = if port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let scheme = if cleartext { "http" } else { "https" };
    let stream = connect(host, port, tag, options, timeout, local)?;
    if cleartext {
        return exchange(stream, &authority, scheme, path, query);
    }
    let config = std::sync::Arc::new(ferrox_core::tls::TlsConfig {
        server_name: host.to_owned(),
        alpn: vec![b"h2".to_vec()].into(),
        roots: crate::quic::system_roots(),
        cert_pins: std::sync::Arc::default(),
        verify_names: std::sync::Arc::default(),
        pins: ferrox_core::foxy::pin::Pins::default(),
        cipher_suites: std::sync::Arc::default(),
        insecure: false,
        fingerprint: None,
        ech_config_list: None,
        websocket: false,
        master_key_log: None,
    });
    let mut tls = ferrox_core::tls::RustlsProvider::connect(&config, stream)
        .map_err(|error| format!("dns doh tls: {error}"))?;
    tls.handshake()
        .map_err(|error| format!("dns doh handshake: {error}"))?;
    exchange(tls, &authority, scheme, path, query)
}

pub(crate) fn doq(
    host: &str,
    port: u16,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let (socket, peer, local) =
        crate::quic::udp_to_server(host, port).ok_or_else(|| "dns doq: no route".to_owned())?;
    let socket = crate::quic::Datagram::plain(socket);
    let roots = crate::quic::system_roots();
    let mut scid = [0u8; 16];
    getrandom::fill(&mut scid).map_err(|_| "dns doq: no randomness".to_owned())?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config = crate::quic::quiche_config_alpn(&roots, None, &[b"doq"])
        .ok_or_else(|| "dns doq: no trust roots".to_owned())?;
    let mut conn = quiche::connect(Some(host), &cid, local, peer, &mut config)
        .map_err(|error| format!("dns doq connect: {error}"))?;
    crate::quic::drive_handshake_by(&mut conn, &socket, local, timeout)
        .ok_or_else(|| "dns doq handshake".to_owned())?;
    let deadline = Instant::now() + timeout;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    if !crate::quic::stream_send_all(&mut conn, &socket, 0, &framed, true, deadline) {
        return Err("dns doq send".to_owned());
    }
    let head = crate::quic::stream_recv_exact(&mut conn, &socket, local, 0, 2, deadline)
        .ok_or_else(|| "dns doq length".to_owned())?;
    let length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if length > ferrox_core::dns::MESSAGE_MAX {
        return Err("dns doq answer over the message bound".to_owned());
    }
    crate::quic::stream_recv_exact(&mut conn, &socket, local, 0, length, deadline)
        .ok_or_else(|| "dns doq answer".to_owned())
}

fn connect(
    host: &str,
    port: u16,
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Connection, String> {
    if !local {
        if let Some(stream) = crate::proxy::dns_stream(host, port, tag, timeout) {
            return Ok(stream);
        }
    }
    Ok(Connection::Tcp(crate::sockopt::connect(
        options, host, port, timeout,
    )?))
}

fn write_frame(stream: &mut impl Write, query: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .and_then(|()| stream.write_all(query))
        .map_err(|error| format!("dns stream send: {error}"))
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut head = [0u8; 2];
    stream
        .read_exact(&mut head)
        .map_err(|error| format!("dns stream length: {error}"))?;
    let length = usize::from(u16::from_be_bytes(head));
    if length > ferrox_core::dns::MESSAGE_MAX {
        return Err("dns answer over the message bound".to_owned());
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| format!("dns stream answer: {error}"))?;
    Ok(body)
}

fn exchange(
    mut stream: impl Read + Write,
    authority: &str,
    scheme: &str,
    path: &str,
    query: &[u8],
) -> Result<Vec<u8>, String> {
    let path = if path.is_empty() { "/" } else { path };
    stream
        .write_all(crate::h2::MAGIC)
        .map_err(|error| format!("dns doh preface: {error}"))?;
    frame(&mut stream, T_SETTINGS, 0, 0, &[])?;
    let length = query.len().to_string();
    let headers = [
        (":method", "POST"),
        (":scheme", scheme),
        (":path", path),
        (":authority", authority),
        ("content-type", "application/dns-message"),
        ("accept", "application/dns-message"),
        ("content-length", length.as_str()),
    ];
    frame(
        &mut stream,
        T_HEADERS,
        F_END_HEADERS,
        1,
        &block_encode(&headers),
    )?;
    frame(&mut stream, T_DATA, F_END, 1, query)?;
    stream
        .flush()
        .map_err(|error| format!("dns doh flush: {error}"))?;
    let mut decoder = Decoder::default();
    let mut block = Vec::new();
    let mut body = Vec::new();
    let mut status = None;
    loop {
        let (len, kind, flags, id) = read_head(&mut stream).ok_or("dns doh closed")?;
        let mut payload = vec![0u8; len];
        stream
            .read_exact(&mut payload)
            .map_err(|error| format!("dns doh read: {error}"))?;
        match kind {
            T_SETTINGS => {
                if flags & F_ACK == 0 {
                    frame(&mut stream, T_SETTINGS, F_ACK, 0, &[])?;
                }
            }
            T_PING => {
                if flags & F_ACK == 0 {
                    frame(&mut stream, T_PING, F_ACK, 0, &payload)?;
                }
            }
            T_HEADERS | T_CONT => {
                block.extend_from_slice(&payload);
                if flags & F_END_HEADERS != 0 {
                    decoder
                        .decode(&block, &mut |name, value| {
                            if name == b":status" {
                                status = Some(String::from_utf8_lossy(value).into_owned());
                            }
                        })
                        .ok_or("dns doh headers")?;
                    block.clear();
                }
                if flags & F_END != 0 {
                    break;
                }
            }
            T_DATA => {
                if id == 1 {
                    body.extend_from_slice(&payload);
                }
                if flags & F_END != 0 {
                    break;
                }
            }
            T_RST => return Err("dns doh stream reset".to_owned()),
            T_GOAWAY => break,
            _ => {}
        }
    }
    match status.as_deref() {
        Some("200") => {}
        Some(other) => return Err(format!("dns doh answered {other}")),
        None => return Err("dns doh answered no status".to_owned()),
    }
    Ok(body)
}

fn frame(stream: &mut impl Write, kind: u8, flags: u8, id: u32, body: &[u8]) -> Result<(), String> {
    stream
        .write_all(&frame_head(body.len(), kind, flags, id))
        .and_then(|()| stream.write_all(body))
        .map_err(|error| format!("dns doh write: {error}"))
}
