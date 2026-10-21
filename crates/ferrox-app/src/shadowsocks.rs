use std::collections::HashMap;
use std::io::{IoSliceMut, Read, Write};
use std::net::{Shutdown, SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::Duration;

use ferrox_core::shadowsocks::{
    rc4_md5_key, Cipher, MasterKey, Method, Rc4, LENGTH_LEN, MAX_CHUNK, TAG_LEN,
};

use crate::budgets::RELAY_POLL;
use crate::conn::Connection;
use crate::proxy::{read_exact, under_handshake, write_all_runs, Destination, UDP_BUF};

const SALT_LEN: usize = 32;
// Chunks one relay read takes and one write carries. A batch never waits for the chunk that has not arrived, so this is a syscall count rather than a latency budget: four costs the same one read and the same one write as one.
const CHUNKS_PER_BATCH: usize = 4;
// One relay read of a stream is exactly one chunk: a 16384 B read would seal as 16383 + 1, a second length seal and tag for a single tail byte, and a batch read of CHUNKS_PER_BATCH of them tiles into whole chunks for the same reason. A stream has no chunks to batch, so its granularity — and every carrier frame size that follows from it — is unchanged.
const READ_CHUNK: usize = MAX_CHUNK;
const IV_LEN: usize = 16;

/// What the uplink thread seals with: the AEAD chunk cipher, or the stream state whose crypt writes into the read buffer itself.
#[allow(
    clippy::large_enum_variant,
    reason = "the 258-byte schedule is built once per handshake; boxing it would add a heap allocation and a pointer chase to a state that lives in the thread that uses it"
)]
pub(crate) enum Uplink {
    Aead(Cipher),
    Stream(Rc4),
}

pub(crate) fn serve(mut stream: Connection, password: &str, method: &str, freedom: bool) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    if method.is_stream() {
        return serve_stream(stream, password);
    }
    let master = MasterKey::new(password, method.key_len());
    let salt_len = method.key_len();
    let mut head = wire_buffer();
    // Bound the salt and first-chunk reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: &mut stream,
            until: std::time::Instant::now() + budget,
        };
        let mut salt = [0u8; SALT_LEN];
        read_exact(&mut bounded, &mut salt[..salt_len])
            .ok()
            .and_then(|()| Cipher::from_master_key(method, &master, &salt[..salt_len]))
            .and_then(|mut recv| {
                open_chunk(&mut bounded, &mut recv, &mut head).map(|chunk| (recv, chunk))
            })
    };
    let _ = stream.set_read_timeout(None);
    let Some((recv, chunk)) = opened else {
        return;
    };
    let Some((target, used)) = parse_addr_header(chunk) else {
        return;
    };
    let Ok(mut uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if uplink.write_all(&chunk[used..]).is_err() {
        return;
    }
    // The relay allocates its own chunk buffer, so this one stops costing 16 KiB.
    drop(head);
    let mut salt = [0u8; SALT_LEN];
    if getrandom::getrandom(&mut salt[..salt_len]).is_err() {
        return;
    }
    let Some(send) = Cipher::from_master_key(method, &master, &salt[..salt_len]) else {
        return;
    };
    if stream.write_all(&salt[..salt_len]).is_err() {
        return;
    }
    pump_relay(&uplink, &stream, Uplink::Aead(send), Recv::Ready(recv));
}

/// The stream handshake: a 16-byte IV in the clear, then the address header rides the RC4 stream itself, so the first read already carries payload and whatever arrived with the header is forwarded, not re-read.
fn serve_stream(mut stream: Connection, password: &str) {
    let master = MasterKey::new(password, Method::Rc4Md5.key_len());
    let mut head = [0u8; 512];
    // Bound the IV and address-header reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: &mut stream,
            until: std::time::Instant::now() + budget,
        };
        let mut iv = [0u8; IV_LEN];
        read_exact(&mut bounded, &mut iv)
            .ok()
            .and_then(|()| rc4_md5_key(master.as_bytes(), &iv))
            .and_then(|key| Rc4::new(&key))
            .and_then(|mut recv| {
                let mut len = 0usize;
                while len < head.len() {
                    match bounded.read(&mut head[len..]) {
                        Ok(0) => return None,
                        Ok(n) => {
                            recv.crypt(&mut head[len..len + n]);
                            len += n;
                            if let Some(found) = parse_addr_header(&head[..len]) {
                                return Some((recv, found, len));
                            }
                        }
                        Err(error) if crate::proxy::is_timeout(&error) => {}
                        Err(_) => return None,
                    }
                }
                None
            })
    };
    let _ = stream.set_read_timeout(None);
    let Some((recv, (target, used), len)) = opened else {
        return;
    };
    let Ok(mut uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if used < len && uplink.write_all(&head[used..len]).is_err() {
        return;
    }
    let mut iv = [0u8; IV_LEN];
    if getrandom::getrandom(&mut iv).is_err() {
        return;
    }
    let Some(key) = rc4_md5_key(master.as_bytes(), &iv) else {
        return;
    };
    let Some(send) = Rc4::new(&key) else {
        return;
    };
    if stream.write_all(&iv).is_err() {
        return;
    }
    pump_relay(
        &uplink,
        &stream,
        Uplink::Stream(send),
        Recv::StreamReady(recv),
    );
}

pub(crate) fn serve_ws(
    stream: Connection,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

pub(crate) fn serve_httpupgrade(
    stream: Connection,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::httpupgrade::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// The carrier's answer held back until a blocking peek finds the first byte of the request packet, so a dial that waits for the `101` before it writes is never answered: only a dial that puts the packet on the wire with the `GET` finishes.
#[cfg(test)]
pub(crate) fn serve_httpupgrade_answering_after_the_request(
    stream: Connection,
    password: &str,
    method: &str,
    _path: &str,
    freedom: bool,
) {
    let mut read = stream;
    let Ok(write) = read.try_clone() else {
        return;
    };
    let mut write = write;
    if crate::proxy::read_http_head(
        &mut read,
        crate::httpupgrade::HEAD_LIMIT,
        crate::budgets::head_arrival(),
    )
    .is_none()
    {
        return;
    }
    // A blocking peek waits for the first byte of the request packet without taking it, so nothing is answered until the packet has arrived.
    let mut probe = [0u8; 1];
    if read.peek(&mut probe).is_err() {
        return;
    }
    if write.write_all(crate::httpupgrade::SWITCH).is_err() {
        return;
    }
    let Some((uplink, send, recv)) = accept_on(&mut read, &mut write, password, method, freedom)
    else {
        return;
    };
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, read, write, &close, send, recv);
}

pub(crate) fn serve_grpc(
    stream: Connection,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::grpc::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = under_handshake(&mut reader, |read| {
        accept_on(read, &mut writer, password, method, freedom)
    }) else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

pub(crate) fn serve_xhttp(
    stream: Connection,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

pub(crate) fn serve_httpheader(
    stream: Connection,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

pub(crate) fn serve_kcp<R, W>(
    mut reader: R,
    mut writer: W,
    password: &str,
    method: &str,
    freedom: bool,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let Some((uplink, send, recv)) = accept_on(
        &mut reader as &mut dyn Read,
        &mut writer as &mut dyn Write,
        password,
        method,
        freedom,
    ) else {
        return;
    };
    pump_relay_carried(&uplink, reader, writer, close, send, recv);
}

fn accept_stream(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    master: &MasterKey,
) -> Option<(Connection, Uplink, Recv)> {
    let mut iv = [0u8; IV_LEN];
    read_exact(reader, &mut iv).ok()?;
    let key = rc4_md5_key(master.as_bytes(), &iv)?;
    let mut recv = Rc4::new(&key)?;
    let mut head = [0u8; 512];
    let mut len = 0usize;
    let (target, used) = loop {
        if len >= 512 {
            return None;
        }
        let n = match reader.read(&mut head[len..]) {
            Ok(0) => return None,
            Ok(n) => n,
            Err(error) if crate::proxy::is_timeout(&error) => continue,
            Err(_) => return None,
        };
        recv.crypt(&mut head[len..len + n]);
        len += n;
        if let Some(found) = parse_addr_header(&head[..len]) {
            break found;
        }
    };
    let mut uplink = crate::conn::dial_tcp(&target, Duration::from_secs(8)).ok()?;
    uplink.write_all(&head[used..len]).ok()?;
    let mut iv = [0u8; IV_LEN];
    getrandom::getrandom(&mut iv).ok()?;
    let key = rc4_md5_key(master.as_bytes(), &iv)?;
    let send = Rc4::new(&key)?;
    writer.write_all(&iv).ok()?;
    Some((uplink, Uplink::Stream(send), Recv::StreamReady(recv)))
}

fn accept_on(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    password: &str,
    method: &str,
    freedom: bool,
) -> Option<(Connection, Uplink, Recv)> {
    let method = Method::parse(method)?;
    if !freedom {
        return None;
    }
    let master = MasterKey::new(password, method.key_len());
    if method.is_stream() {
        return accept_stream(reader, writer, &master);
    }
    let salt_len = method.key_len();
    let mut salt = [0u8; SALT_LEN];
    read_exact(reader, &mut salt[..salt_len]).ok()?;
    let mut recv = Cipher::from_master_key(method, &master, &salt[..salt_len])?;
    let mut head = wire_buffer();
    let chunk = open_chunk(reader, &mut recv, &mut head)?;
    let (target, used) = parse_addr_header(chunk)?;
    let mut uplink = crate::conn::dial_tcp(&target, Duration::from_secs(8)).ok()?;
    uplink.write_all(&chunk[used..]).ok()?;
    drop(head);
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt[..salt_len]).ok()?;
    let send = Cipher::from_master_key(method, &master, &salt[..salt_len])?;
    writer.write_all(&salt[..salt_len]).ok()?;
    Some((uplink, Uplink::Aead(send), Recv::Ready(recv)))
}

pub(crate) fn client_send_handshake(
    uplink: &mut dyn Write,
    password: &str,
    method: &str,
    target: &Destination,
) -> Option<(Uplink, Recv)> {
    let method = Method::parse(method)?;
    let master = MasterKey::new(password, method.key_len());
    if method.is_stream() {
        let mut iv = [0u8; IV_LEN];
        getrandom::getrandom(&mut iv).ok()?;
        uplink.write_all(&iv).ok()?;
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut send = Rc4::new(&key)?;
        let mut addr = Vec::with_capacity(2 + target.addr_len());
        target.push_addr(&mut addr, 4, 3);
        addr.extend_from_slice(&target.port().to_be_bytes());
        send.crypt(&mut addr);
        uplink.write_all(&addr).ok()?;
        return Some((Uplink::Stream(send), Recv::StreamWaiting(master)));
    }
    let salt_len = method.key_len();
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt[..salt_len]).ok()?;
    uplink.write_all(&salt[..salt_len]).ok()?;
    let mut send = Uplink::Aead(Cipher::from_master_key(method, &master, &salt[..salt_len])?);
    let mut addr = Vec::with_capacity(2 + target.addr_len());
    target.push_addr(&mut addr, 4, 3);
    addr.extend_from_slice(&target.port().to_be_bytes());
    let n = addr.len();
    let mut buf = crate::proxy::unfilled(SEAL_HEAD + n + TAG_LEN);
    buf[SEAL_HEAD..SEAL_HEAD + n].copy_from_slice(&addr);
    seal_all(&mut send, &mut buf, n, uplink).ok()?;
    Some((send, Recv::Waiting(method, master)))
}

#[allow(
    clippy::large_enum_variant,
    reason = "the 258-byte schedule is built once per handshake; boxing it would add a heap allocation and a pointer chase to a state that lives in the thread that uses it"
)]
pub(crate) enum Recv {
    Ready(Cipher),
    Waiting(Method, MasterKey),
    StreamReady(Rc4),
    StreamWaiting(MasterKey),
}

pub(crate) fn pump_relay(plain: &Connection, sealed: &Connection, send: Uplink, recv: Recv) {
    let Ok(sealed_read) = sealed.try_clone() else {
        return;
    };
    let Ok(sealed_write) = sealed.try_clone() else {
        return;
    };
    let Ok(closer) = sealed.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(plain, sealed_read, sealed_write, &close, send, recv);
}

pub(crate) fn pump_relay_carried<R, W>(
    plain: &Connection,
    reader: R,
    mut writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    send: Uplink,
    recv: Recv,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut plain_write = plain_write;
    let mut send = send;
    let thread_close = std::sync::Arc::clone(close);
    let done = thread::spawn(move || {
        let mut buf = crate::proxy::unfilled(uplink_buffer_len(&send));
        loop {
            let read = match &send {
                Uplink::Aead(_) => read_slots(&mut plain_read, &mut buf),
                Uplink::Stream(_) => plain_read.read(&mut buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]),
            };
            let Ok(read) = read else { break };
            if read == 0 {
                break;
            }
            if seal_all(&mut send, &mut buf, read, &mut writer).is_err() {
                break;
            }
        }
        thread_close();
        let _ = plain_read.shutdown(Shutdown::Both);
    });
    if !relay_downlink(reader, recv, &mut plain_write) {
        return;
    }
    close();
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

/// The downlink the dials build: the carrier's octets opened into the codec's own window, so the
/// widest ask the carrier ever hears is a window and a payload byte crosses user space once.
/// `false` is the handshake never opening, which is the pump's own early exit: the carrier is not
/// finished and the uplink is not joined, because the dial dropping the sockets is what ends it.
fn relay_downlink<R: Read>(mut reader: R, recv: Recv, out: &mut dyn Write) -> bool {
    let mut aead: Option<Cipher> = None;
    let mut stream: Option<Rc4> = None;
    match recv {
        Recv::Ready(cipher) => aead = Some(cipher),
        Recv::Waiting(method, master) => {
            let salt_len = method.key_len();
            let mut peer = [0u8; SALT_LEN];
            if read_exact(&mut reader, &mut peer[..salt_len]).is_err() {
                return false;
            }
            let Some(cipher) = Cipher::from_master_key(method, &master, &peer[..salt_len]) else {
                return false;
            };
            aead = Some(cipher);
        }
        Recv::StreamReady(rc4) => stream = Some(rc4),
        Recv::StreamWaiting(master) => {
            let mut peer = [0u8; IV_LEN];
            if read_exact(&mut reader, &mut peer).is_err() {
                return false;
            }
            let Some(key) = rc4_md5_key(master.as_bytes(), &peer) else {
                return false;
            };
            let Some(rc4) = Rc4::new(&key) else {
                return false;
            };
            stream = Some(rc4);
        }
    }
    if let Some(mut cipher) = aead {
        let mut window = ChunkReader::new(reader);
        let _ = drain_window(&mut window, &mut cipher, out);
    } else if let Some(mut rc4) = stream {
        let mut buf = crate::proxy::unfilled(READ_CHUNK);
        while let Some(payload) = open_stream(&mut reader, &mut rc4, &mut buf) {
            if out.write_all(payload).is_err() {
                break;
            }
        }
    }
    true
}

pub(crate) fn serve_udp(address: &str, password: &str, method: &str, freedom: bool) {
    let Ok(clients) = UdpSocket::bind(address) else {
        return;
    };
    serve_udp_on(&clients, password, method, freedom);
}

pub(crate) fn serve_udp_on(clients: &UdpSocket, password: &str, method: &str, freedom: bool) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    let master = MasterKey::new(password, method.key_len());
    let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    let upstream6 = UdpSocket::bind("[::]:0").ok();
    for sock in [clients, &upstream].into_iter().chain(upstream6.as_ref()) {
        if sock.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
    }
    let mut table: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let mut buf = crate::proxy::unfilled(DATAGRAM_MAX);
    let mut reply = crate::proxy::unfilled(DATAGRAM_MAX);
    let mut hop: Option<Cipher> = None;
    loop {
        match clients.recv_from(&mut buf[SEAL_ROOM..SEAL_ROOM + UDP_BUF]) {
            Ok((n, src)) => {
                if let Some((dest, payload)) = open_datagram(
                    &master,
                    method,
                    &mut buf[SEAL_ROOM..SEAL_ROOM + n],
                    &mut hop,
                ) {
                    if table.len() >= 4096 {
                        table.clear();
                    }
                    table.insert(dest, src);
                    if dest.is_ipv6() {
                        if let Some(sock) = &upstream6 {
                            let _ = sock.send_to(payload, dest);
                        }
                    } else {
                        let _ = upstream.send_to(payload, dest);
                    }
                }
            }
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => break,
        }
        for sock in [&upstream].into_iter().chain(upstream6.as_ref()) {
            while let Ok((n, src)) = sock.recv_from(&mut reply[SEAL_ROOM..SEAL_ROOM + UDP_BUF]) {
                if let Some(client) = table.get(&src) {
                    if let Some(packet) =
                        seal_datagram(&master, method, &src, &mut reply, SEAL_ROOM, n, &mut hop)
                    {
                        let _ = clients.send_to(packet, client);
                    }
                }
            }
        }
    }
}

/// Bytes one wire chunk can never exceed: `MAX_CHUNK` of payload plus its tag.
pub(crate) const WIRE_MAX: usize = MAX_CHUNK + TAG_LEN;

/// Room around one chunk's payload inside the caller's buffer: a sealed length before it and its tag after it, so both seals land beside the payload instead of the payload moving to them.
pub(crate) const SEAL_HEAD: usize = LENGTH_LEN + TAG_LEN;

/// One batch slot: its own headroom, a full chunk of payload, its own tailroom. A stride this wide is what lets a chunk's tag land beside its own payload rather than on the next chunk's plaintext, which is the one reason a batch cannot simply be a wider read.
const SLOT: usize = SEAL_HEAD + MAX_CHUNK + TAG_LEN;

/// The relay's read buffer: one slot per chunk of a batch.
const BATCH: usize = CHUNKS_PER_BATCH * SLOT;

/// The uplink's read buffer, sized by what the rung can fill: an AEAD leg reads four chunks at a
/// time, a stream crypt reads one — four slots would be buffers for a batch that leg never makes.
fn uplink_buffer_len(send: &Uplink) -> usize {
    match send {
        Uplink::Aead(_) => BATCH,
        Uplink::Stream(_) => SLOT,
    }
}

/// A chunk buffer sized once: `open_chunk` writes into a prefix of it, so no read ever grows or re-zeroes it.
pub(crate) fn wire_buffer() -> Vec<u8> {
    crate::proxy::unfilled(WIRE_MAX)
}

/// Seal what one relay read filled: every chunk of it seals inside its own slot — length into that slot's headroom, tag into its tailroom — and the batch leaves as one vectored write whose slices are exactly the wire bytes a chunk at a time used to be, so a carrier with no `writev` still sees one write per chunk. A payload byte is never copied in user space, and more chunks than the buffer has slots is refused loudly rather than corrupted quietly.
fn seal_all(
    send: &mut Uplink,
    buf: &mut [u8],
    n: usize,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    match send {
        Uplink::Aead(cipher) => {
            let mut sealed = [(0usize, 0usize); CHUNKS_PER_BATCH];
            let mut chunks = 0usize;
            let mut got = 0usize;
            while got < n {
                let take = (n - got).min(MAX_CHUNK);
                let head = chunks * SLOT;
                let end = head + SEAL_HEAD + take;
                let slot = sealed.get_mut(chunks).ok_or_else(invalid)?;
                if end + TAG_LEN > buf.len() {
                    return Err(invalid());
                }
                let mut length = (take as u16).to_be_bytes();
                let length_tag = cipher
                    .seal_piece_in_place(&mut length)
                    .ok_or_else(invalid)?;
                let tag = {
                    let chunk = &mut buf[head + SEAL_HEAD..end];
                    cipher.seal_piece_in_place(chunk).ok_or_else(invalid)?
                };
                buf[head..head + LENGTH_LEN].copy_from_slice(&length);
                buf[head + LENGTH_LEN..head + SEAL_HEAD].copy_from_slice(&length_tag);
                buf[end..end + TAG_LEN].copy_from_slice(&tag);
                *slot = (head, end + TAG_LEN - head);
                chunks += 1;
                got += take;
            }
            write_all_runs::<CHUNKS_PER_BATCH>(out, buf, &sealed[..chunks])
        }
        Uplink::Stream(rc4) => {
            let payload = &mut buf[SEAL_HEAD..SEAL_HEAD + n];
            rc4.crypt(payload);
            out.write_all(payload)
        }
    }
}

/// Fill a batch's payload slots with one vectored read. The kernel takes iovecs in order, so a short slot is always the last one and every sealed chunk still sits in its own slot.
fn read_slots(read: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut slots: [IoSliceMut; CHUNKS_PER_BATCH] =
        std::array::from_fn(|_| IoSliceMut::new(&mut []));
    let mut room = buf[..BATCH].chunks_mut(SLOT);
    for slot in &mut slots {
        let filled = room
            .next()
            .expect("the batch buffer holds one slot per chunk of a batch");
        *slot = IoSliceMut::new(&mut filled[SEAL_HEAD..SEAL_HEAD + MAX_CHUNK]);
    }
    read.read_vectored(&mut slots)
}

/// Read one wire chunk out of `chunk`'s prefix: `chunk` is the caller's, sized [`WIRE_MAX`] once and opened in place — no allocation, no zero-fill — and the handshake opens exactly one chunk because whatever the peer pipelined after it belongs to the relay.
fn open_chunk<'a>(
    stream: &mut dyn Read,
    recv: &mut Cipher,
    chunk: &'a mut [u8],
) -> Option<&'a [u8]> {
    use crate::proxy::read_exact;
    let mut length = [0u8; LENGTH_LEN + TAG_LEN];
    read_exact(stream, &mut length).ok()?;
    let size = open_length(recv, &mut length)?;
    if size + TAG_LEN > chunk.len() {
        return None;
    }
    let wire = &mut chunk[..size + TAG_LEN];
    read_exact(stream, wire).ok()?;
    let plain = open_into(recv, wire)?;
    Some(&wire[..plain])
}

/// Open an 18 B sealed length in place: the payload size it names, or `None` on a forged tag or an impossible size; both chunk readers share this so the framing lives in one place.
fn open_length(recv: &mut Cipher, length: &mut [u8]) -> Option<usize> {
    if open_into(recv, length)? != LENGTH_LEN {
        return None;
    }
    let size = usize::from(u16::from_be_bytes([length[0], length[1]]));
    (size <= MAX_CHUNK).then_some(size)
}

/// One relay connection's downlink window: wire bytes land here once and chunks open where they lie — a length never costs its own read and the payload decrypts in the caller's buffer with no copy; sized for a whole batch of full chunks so one bulk read serves the length, the payloads and usually the next length too.
struct ChunkReader<R> {
    read: R,
    buf: Vec<u8>,
    at: usize,
    end: usize,
    /// A chunk whose length is drawn but whose bytes have not all arrived.
    held: Option<usize>,
}

impl<R: Read> ChunkReader<R> {
    fn new(read: R) -> Self {
        Self {
            read,
            buf: crate::proxy::unfilled(BATCH),
            at: 0,
            end: 0,
            held: None,
        }
    }

    /// Fill until `need` bytes wait at `at`, compacting only when the buffer is full so leftovers move once: one `read` per fill on a live socket, and short reads and quiet sockets loop exactly like `read_exact`.
    fn fill(&mut self, need: usize) -> Option<()> {
        loop {
            if self.end - self.at >= need {
                return Some(());
            }
            if self.end == self.buf.len() {
                self.buf.copy_within(self.at..self.end, 0);
                self.end -= self.at;
                self.at = 0;
            }
            match self.read.read(&mut self.buf[self.end..]) {
                Ok(0) => return None,
                Ok(n) => self.end += n,
                Err(error) if crate::proxy::is_timeout(&error) => {}
                Err(_) => return None,
            }
        }
    }

    /// Open one chunk where it lies and say where its plaintext ended up. `None` with `wait` is the
    /// stream ending or a tag that will not open, and nothing after either is trustworthy; without
    /// `wait` it also means this chunk has not finished arriving, which is why its length is drawn
    /// once and held rather than drawn again against the next chunk's nonce.
    fn open_chunk(&mut self, recv: &mut Cipher, wait: bool) -> Option<(usize, usize)> {
        let head = LENGTH_LEN + TAG_LEN;
        let size = if let Some(size) = self.held {
            size
        } else {
            if self.end - self.at < head {
                if !wait {
                    return None;
                }
                self.fill(head)?;
            }
            let length = &mut self.buf[self.at..self.at + head];
            let size = open_length(recv, length)?;
            self.held = Some(size);
            size
        };
        let body = size + TAG_LEN;
        if self.end - self.at < head + body {
            if !wait {
                return None;
            }
            self.fill(head + body)?;
        }
        self.held = None;
        let start = self.at + head;
        let plain = open_into(recv, &mut self.buf[start..start + body])?;
        self.at = start + body;
        Some((start, plain))
    }

    /// Open the chunks this window already holds, waiting only for the first: a peer that stops to
    /// hear back from its own target must never find the chunk it is waiting on held for a batch
    /// that has not arrived. The plaintexts are disjoint runs of one buffer, so they leave together
    /// in one vectored write. Returns how many opened, or `0` once the stream is over or damaged.
    fn open_batch(&mut self, recv: &mut Cipher, out: &mut [(usize, usize)]) -> usize {
        let mut opened = 0usize;
        let mut wait = true;
        while opened < out.len() {
            let Some(chunk) = self.open_chunk(recv, wait) else {
                break;
            };
            out[opened] = chunk;
            opened += 1;
            // Only the first chunk of a batch may be waited for.
            wait = false;
        }
        opened
    }
}

/// Hand the whole batch the window already holds to the target, and keep doing so until the stream
/// ends or the target refuses: one `write_vectored` per batch where the socket has `writev`, one
/// write per chunk where the carrier has not, and no wait for a chunk that has not arrived.
fn drain_window<R: Read>(
    window: &mut ChunkReader<R>,
    recv: &mut Cipher,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let mut batch = [(0usize, 0usize); CHUNKS_PER_BATCH];
    loop {
        let opened = window.open_batch(recv, &mut batch);
        if opened == 0 {
            return Ok(());
        }
        write_all_runs::<CHUNKS_PER_BATCH>(out, &window.buf, &batch[..opened])?;
    }
}

fn open_into(recv: &mut Cipher, chunk: &mut [u8]) -> Option<usize> {
    recv.open_in_place(chunk)
}

/// A stream has no chunks: one read is one payload, decrypted where it lies and handed on without a second buffer.
fn open_stream<'a>(stream: &mut dyn Read, rc4: &mut Rc4, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    loop {
        match stream.read(buf) {
            Ok(0) => return None,
            Ok(n) => {
                rc4.crypt(&mut buf[..n]);
                return Some(&buf[..n]);
            }
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => return None,
        }
    }
}

/// Room a sealed datagram's salt and address header take before its payload: the widest header is an IPv6 one at 19 bytes.
pub(crate) const SEAL_ROOM: usize = SALT_LEN + 19;

/// One UDP datagram's whole wire room: the headroom a seal needs, the payload, and one AEAD tag.
pub(crate) const DATAGRAM_MAX: usize = SEAL_ROOM + UDP_BUF + TAG_LEN;

/// One SOCKS-style address header — kind, octets, port — written where a datagram's buffer has room for it, so a per-datagram `Vec` is not needed to build the head.
pub(crate) fn write_addr(out: &mut [u8], dest: &SocketAddr) -> usize {
    match dest {
        SocketAddr::V4(v4) => {
            out[0] = 1;
            out[1..5].copy_from_slice(&v4.ip().octets());
            out[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        SocketAddr::V6(v6) => {
            out[0] = 4;
            out[1..17].copy_from_slice(&v6.ip().octets());
            out[17..19].copy_from_slice(&v6.port().to_be_bytes());
            19
        }
    }
}

/// Seal `n` payload bytes already at `buf[at..at + n]`, writing the salt or stream IV and the address header into the headroom before it and the tag after it: a datagram is sealed where the socket put it, with no per-datagram buffer and no second pass over the payload.
pub(crate) fn seal_datagram<'a>(
    master: &MasterKey,
    method: Method,
    dest: &SocketAddr,
    buf: &'a mut [u8],
    at: usize,
    n: usize,
    hop: &mut Option<Cipher>,
) -> Option<&'a [u8]> {
    let addr_bytes = if dest.is_ipv6() { 19 } else { 7 };
    if method.is_stream() {
        let head = IV_LEN + addr_bytes;
        if at < head || at + n > buf.len() {
            return None;
        }
        let mut iv = [0u8; IV_LEN];
        getrandom::getrandom(&mut iv).ok()?;
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut rc4 = Rc4::new(&key)?;
        let clear_at = at - head;
        buf[clear_at..clear_at + IV_LEN].copy_from_slice(&iv);
        write_addr(&mut buf[clear_at + IV_LEN..at], dest);
        rc4.crypt(&mut buf[at - addr_bytes..at + n]);
        return Some(&buf[clear_at..at + n]);
    }
    let salt_len = method.key_len();
    let head = salt_len + addr_bytes;
    if at < head || at + n + TAG_LEN > buf.len() {
        return None;
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt[..salt_len]).ok()?;
    // The first datagram on the chain builds the engine; every one after rekeys it: the salt is the key, so the HKDF and the schedule run again and the heap holds still.
    let cipher: &mut Cipher = match hop {
        Some(cipher) => {
            cipher.rekey(master, &salt[..salt_len])?;
            cipher
        }
        None => hop.insert(Cipher::from_master_key(method, master, &salt[..salt_len])?),
    };
    let clear_at = at - head;
    buf[clear_at..clear_at + salt_len].copy_from_slice(&salt[..salt_len]);
    write_addr(&mut buf[clear_at + salt_len..at], dest);
    let tag = cipher.seal_piece_in_place(&mut buf[at - addr_bytes..at + n])?;
    buf[at + n..at + n + TAG_LEN].copy_from_slice(&tag);
    Some(&buf[clear_at..at + n + TAG_LEN])
}

/// Open one wire datagram in place in the caller's buffer: the salt and the address header precede the payload and the payload comes back where the datagram put it, so a datagram costs no allocation, no second buffer and no `memmove`.
pub(crate) fn open_datagram<'a>(
    master: &MasterKey,
    method: Method,
    packet: &'a mut [u8],
    hop: &mut Option<Cipher>,
) -> Option<(SocketAddr, &'a [u8])> {
    if method.is_stream() {
        if packet.len() < IV_LEN + 1 {
            return None;
        }
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&packet[..IV_LEN]);
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut rc4 = Rc4::new(&key)?;
        rc4.crypt(&mut packet[IV_LEN..]);
        let (target, used) = parse_addr_header(&packet[IV_LEN..])?;
        return Some((target, &packet[IV_LEN + used..]));
    }
    let salt_len = method.key_len();
    if packet.len() < salt_len + TAG_LEN + 1 {
        return None;
    }
    // The first datagram on the chain builds the engine; every one after rekeys it: the salt is the key, so the HKDF and the schedule run again and the heap holds still.
    let cipher: &mut Cipher = match hop {
        Some(cipher) => {
            cipher.rekey(master, &packet[..salt_len])?;
            cipher
        }
        None => hop.insert(Cipher::from_master_key(
            method,
            master,
            &packet[..salt_len],
        )?),
    };
    let body = &mut packet[salt_len..];
    let len = cipher.open_in_place(body)?;
    let (target, used) = parse_addr_header(&body[..len])?;
    Some((target, &body[used..len]))
}

fn parse_addr_header(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let kind = match buf.first()? {
        1 => crate::proxy::AddrKind::V4,
        4 => crate::proxy::AddrKind::V6,
        3 => crate::proxy::AddrKind::Domain,
        _ => return None,
    };
    let (body, mut used) = crate::proxy::parse_addr_body(buf, kind)?;
    let port = u16::from_be_bytes(buf.get(used..used + 2)?.try_into().ok()?);
    used += 2;
    let target = match body {
        crate::proxy::AddrBody::V4(ip) => SocketAddr::new(std::net::IpAddr::V4(ip.into()), port),
        crate::proxy::AddrBody::V6(ip) => SocketAddr::new(std::net::IpAddr::V6(ip.into()), port),
        crate::proxy::AddrBody::Domain(host) => {
            format!("{host}:{port}").to_socket_addrs().ok()?.next()?
        }
    };
    Some((target, used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IoSlice;

    /// Silence past the budget is death, not scheduling: a peer that opens the connection and never sends must not pin the raw Shadowsocks handshake thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_a_raw_shadowsocks_handshake() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, "an-example-shared-password", "aes-256-gcm", true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// Silence past the budget is death, not scheduling: the stream handshake reads a clear IV then scans the encrypted header, and a peer that opens the connection and never sends must not pin that thread forever either.
    #[test]
    fn a_silent_peer_cannot_pin_a_stream_shadowsocks_handshake() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, "an-example-shared-password", "rc4-md5", true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    fn methods() -> [(&'static str, Method); 10] {
        [
            ("aes-128-gcm", Method::Aes128Gcm),
            ("aead_aes_128_gcm", Method::Aes128Gcm),
            ("aes-256-gcm", Method::Aes256Gcm),
            ("aead_aes_256_gcm", Method::Aes256Gcm),
            ("chacha20-ietf-poly1305", Method::Chacha20Poly1305),
            ("aead_chacha20_poly1305", Method::Chacha20Poly1305),
            ("chacha20-poly1305", Method::Chacha20Poly1305),
            ("xchacha20-ietf-poly1305", Method::XChacha20Poly1305),
            ("aead_xchacha20_poly1305", Method::XChacha20Poly1305),
            ("AES-256-GCM", Method::Aes256Gcm),
        ]
    }

    #[test]
    fn every_named_method_and_spelling_relays_an_echo() {
        for (name, method) in methods() {
            let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let echo_port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                let (mut stream, _) = echo.accept().expect("accepts");
                let mut buf = [0u8; 1024];
                while let Ok(read) = stream.read(&mut buf) {
                    if read == 0 || stream.write_all(&buf[..read]).is_err() {
                        return;
                    }
                }
            });
            let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            let announced = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let announced = announced.clone();
                    thread::spawn(move || {
                        serve(stream, "an-example-shared-password", &announced, true);
                    });
                }
            });
            let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
            let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("timeout");
            let Some((mut send, recv)) = client_send_handshake(
                &mut uplink,
                "an-example-shared-password",
                name,
                &Destination::from(target),
            ) else {
                panic!("{name}: handshake refused");
            };
            assert!(
                matches!(send, Uplink::Aead(_)),
                "{name}: and it is the named one"
            );
            let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
            seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(_, master) => {
                    let salt_len = method.key_len();
                    let mut peer = [0u8; SALT_LEN];
                    read_exact(&mut uplink, &mut peer[..salt_len]).expect("salt");
                    Cipher::from_master_key(method, &master, &peer[..salt_len]).expect("derives")
                }
                Recv::StreamReady(_) | Recv::StreamWaiting(_) => {
                    panic!("{name}: an AEAD method never answers with stream state");
                }
            };
            let mut buf = wire_buffer();
            let back = open_chunk(&mut uplink, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"ping"[..], "{name}");
        }
    }

    #[test]
    fn a_method_outside_the_rung_is_refused() {
        for name in [
            "aes-192-gcm",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
            "none",
            "",
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "chacha20-ietf",
            "xchacha20",
        ] {
            let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            let refused = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let refused = refused.clone();
                    thread::spawn(move || {
                        serve(stream, "an-example-shared-password", &refused, true);
                    });
                }
            });
            let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("timeout");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            assert!(
                client_send_handshake(
                    &mut uplink,
                    "an-example-shared-password",
                    name,
                    &Destination::from(target)
                )
                .is_none(),
                "{name}: refused"
            );
        }
    }

    #[test]
    fn stream_relays_an_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(1) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || {
                    serve(stream, "an-example-shared-password", "rc4-md5", true);
                });
            }
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        uplink
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .expect("timeout");
        let Some((mut send, recv)) = client_send_handshake(
            &mut uplink,
            "an-example-shared-password",
            "rc4-md5",
            &Destination::from(target),
        ) else {
            panic!("handshake refused");
        };
        assert!(matches!(send, Uplink::Stream(_)), "and it is the named one");
        let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
        ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
        seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
        let mut recv = match recv {
            Recv::StreamWaiting(master) => {
                let mut peer = [0u8; IV_LEN];
                read_exact(&mut uplink, &mut peer).expect("iv");
                let key = rc4_md5_key(master.as_bytes(), &peer).expect("derives");
                Rc4::new(&key).expect("schedules")
            }
            Recv::Ready(_) | Recv::Waiting(..) | Recv::StreamReady(_) => {
                panic!("a stream handshake never answers with AEAD state");
            }
        };
        let mut back = [0u8; 4];
        read_exact(&mut uplink, &mut back).expect("echo");
        recv.crypt(&mut back);
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn stream_rides_the_ws_carrier() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_ws(
                stream,
                "an-example-shared-password",
                "rc4-md5",
                "/ss-ws",
                true,
            );
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::ws::connect(stream, "127.0.0.1", "/ss-ws", 0, &[]).expect("carries");
        let Some((mut send, recv)) = client_send_handshake(
            &mut writer,
            "an-example-shared-password",
            "rc4-md5",
            &Destination::from(target),
        ) else {
            panic!("handshake refused");
        };
        let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
        ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
        seal_all(&mut send, &mut ping, 4, &mut writer).expect("seals");
        let mut recv = match recv {
            Recv::StreamWaiting(master) => {
                let mut peer = [0u8; IV_LEN];
                read_exact(&mut reader, &mut peer).expect("iv");
                let key = rc4_md5_key(master.as_bytes(), &peer).expect("derives");
                Rc4::new(&key).expect("schedules")
            }
            Recv::Ready(_) | Recv::Waiting(..) | Recv::StreamReady(_) => {
                panic!("a stream handshake never answers with AEAD state");
            }
        };
        let mut buf = vec![0u8; READ_CHUNK];
        let back = open_stream(&mut reader, &mut recv, &mut buf).expect("opens");
        assert_eq!(back, &b"ping"[..]);
    }

    #[test]
    fn stream_relay_read_becomes_one_write() {
        struct Counting<'a> {
            seen: &'a mut Vec<u8>,
            writes: usize,
        }
        impl Write for Counting<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                self.seen.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let master = MasterKey::new("an-example-shared-password", 16);
        let key = rc4_md5_key(master.as_bytes(), &[9u8; IV_LEN]).expect("derives");
        let mut send = Uplink::Stream(Rc4::new(&key).expect("schedules"));
        let mut buf = vec![0u8; SEAL_HEAD + READ_CHUNK + TAG_LEN];
        for (i, b) in buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 251) as u8;
        }
        let want = buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK].to_vec();
        let mut seen = Vec::new();
        let writes = {
            let mut out = Counting {
                seen: &mut seen,
                writes: 0,
            };
            seal_all(&mut send, &mut buf, READ_CHUNK, &mut out).expect("seals");
            out.writes
        };
        assert_eq!(writes, 1, "a relay read is crypted and written once");
        let mut back = seen.clone();
        Rc4::new(&key).expect("schedules").crypt(&mut back);
        assert_eq!(back, want, "every byte came back");
    }

    /// What each rung is given for its read buffer, asserted rather than left to the loop above it.
    #[test]
    fn a_stream_uplink_buffers_one_slot_and_an_aead_uplink_a_batch() {
        let salt = [7u8; SALT_LEN];
        let master = MasterKey::new("an-example-shared-password", 16);
        let key = rc4_md5_key(master.as_bytes(), &[9u8; IV_LEN]).expect("derives");
        assert_eq!(
            uplink_buffer_len(&Uplink::Stream(Rc4::new(&key).expect("schedules"))),
            SLOT,
            "a stream read fills one chunk, so three more slots are memory that leg never touches"
        );
        assert_eq!(
            uplink_buffer_len(&Uplink::Aead(
                Cipher::new(Method::Aes256Gcm, "an-example-shared-password", &salt)
                    .expect("derives")
            )),
            BATCH,
            "an AEAD read fills the batch"
        );
    }

    /// Seal one datagram into a buffer of its own, the way a socket thread hands its payload to the sealer.
    fn seal_to_wire(
        master: &MasterKey,
        method: Method,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; DATAGRAM_MAX];
        buf[SEAL_ROOM..SEAL_ROOM + payload.len()].copy_from_slice(payload);
        let mut hop = None;
        seal_datagram(
            master,
            method,
            dest,
            &mut buf,
            SEAL_ROOM,
            payload.len(),
            &mut hop,
        )
        .expect("seals")
        .to_vec()
    }

    /// Open one wire datagram and copy out what it carried, for the tests that compare bytes rather than pointers.
    fn open_from_wire(
        master: &MasterKey,
        method: Method,
        packet: &[u8],
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let mut wire = packet.to_vec();
        let mut hop = None;
        let (target, payload) = open_datagram(master, method, &mut wire, &mut hop)?;
        Some((target, payload.to_vec()))
    }

    #[test]
    fn stream_udp_round_trips_and_rejects_damage() {
        let method = Method::Rc4Md5;
        let master = MasterKey::new("an-example-shared-password", 16);
        for target in [
            "127.0.0.1:53".parse().expect("v4"),
            "[2001:db8::1]:443".parse().expect("v6"),
        ] {
            let packet = seal_to_wire(&master, method, &target, b"ping");
            let header = if target.is_ipv6() { 19 } else { 7 };
            assert_eq!(
                packet.len(),
                IV_LEN + header + b"ping".len(),
                "a datagram is the IV, the header and the payload, with no tag"
            );
            let (got, payload) = open_from_wire(&master, method, &packet).expect("opens");
            assert_eq!(got, target);
            assert_eq!(payload, b"ping");
        }
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let packet = seal_to_wire(&master, method, &target, b"ping");
        let mut cut = packet.clone();
        cut.pop();
        let (_, short) = open_from_wire(&master, method, &cut).expect("opens");
        assert_eq!(
            short, b"pin",
            "a stream has no tag: truncation truncates, it does not refuse"
        );
        assert!(open_from_wire(&master, method, &packet[..10]).is_none());
        assert!(open_from_wire(&master, method, &[]).is_none());
        let wrong = MasterKey::new("a-different-password", 16);
        if let Some((_, payload)) = open_from_wire(&wrong, method, &packet) {
            assert_ne!(payload, b"ping", "a wrong password opens only noise");
        }
    }

    /// A shadowsocks inbound over gRPC whose peer answers the head and never sends its IV releases the serve thread: the carrier puts its clock away with the head, so the handshake reads under its own.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_shadowsocks_request() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(
                stream,
                "an-example-shared-password",
                "aes-256-gcm",
                "/p",
                true,
            );
            let _ = done_tx.send(());
        });
        let stream = Connection::connect(addr).expect("connects");
        let (_reader, _writer) = crate::grpc::connect(stream, "127.0.0.1", "/p").expect("dials");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A listener that answers every connection with whatever it reads.
    fn echo() -> u16 {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else { continue };
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    while let Ok(read) = stream.read(&mut buf) {
                        if read == 0 || stream.write_all(&buf[..read]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    #[test]
    fn carried_transports_relay_an_echo() {
        const PASSWORD: &str = "an-example-shared-password";
        const METHOD: &str = "aes-256-gcm";
        fn answers(reader: &mut dyn Read, writer: &mut dyn Write, mut send: Uplink, recv: Recv) {
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(_, master) => {
                    let mut peer = [0u8; SALT_LEN];
                    read_exact(reader, &mut peer).expect("salt");
                    Cipher::from_master_key(Method::Aes256Gcm, &master, &peer).expect("derives")
                }
                Recv::StreamReady(_) | Recv::StreamWaiting(_) => {
                    panic!("an AEAD method never answers with stream state");
                }
            };
            let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
            seal_all(&mut send, &mut ping, 4, writer).expect("seals");
            let mut buf = wire_buffer();
            let back = open_chunk(reader, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"ping"[..]);
        }
        fn round_trip(reader: &mut dyn Read, writer: &mut dyn Write, target: &Destination) {
            let Some((send, recv)) = client_send_handshake(writer, PASSWORD, METHOD, target) else {
                panic!("handshake refused");
            };
            answers(reader, writer, send, recv);
        }
        fn tunnel(serve: fn(Connection, &str, &str, &str, bool), path: &'static str) -> Connection {
            let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            thread::spawn(move || {
                let (stream, _) = server.accept().expect("accepts");
                serve(stream, PASSWORD, METHOD, path, true);
            });
            Connection::connect(("127.0.0.1", port)).expect("connects")
        }
        fn sealed(target: &Destination) -> (Vec<u8>, Uplink, Recv) {
            let mut packet = Vec::new();
            let Some((send, recv)) = client_send_handshake(&mut packet, PASSWORD, METHOD, target)
            else {
                panic!("handshake refused");
            };
            (packet, send, recv)
        }
        let echo_port = echo();
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let target = Destination::from(target);
        let (mut reader, mut writer) =
            crate::ws::connect(tunnel(serve_ws, "/ss-ws"), "127.0.0.1", "/ss-ws", 0, &[])
                .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        // What the dial does on this carrier: the request packet is sealed before the connect, so `ed=0` leaves it whole after the answer and a budget puts it on the wire with the `GET`.
        let (packet, send, recv) = sealed(&target);
        let (mut reader, mut writer) = crate::httpupgrade::connect(
            tunnel(serve_httpupgrade, "/ss-upgrade"),
            "127.0.0.1",
            "/ss-upgrade",
            0,
            &packet,
        )
        .expect("carries");
        answers(&mut reader, &mut writer, send, recv);
        let (packet, send, recv) = sealed(&target);
        let (mut reader, mut writer) = crate::httpupgrade::connect(
            tunnel(serve_httpupgrade, "/ss-upgrade"),
            "127.0.0.1",
            "/ss-upgrade",
            64,
            &packet,
        )
        .expect("rides ahead of the answer");
        answers(&mut reader, &mut writer, send, recv);
        let (mut reader, mut writer) = crate::grpc::connect(
            tunnel(serve_grpc, "/TunnelService/Tun"),
            "127.0.0.1",
            "/TunnelService/Tun",
        )
        .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let (mut reader, mut writer) =
            crate::xhttp::connect(tunnel(serve_xhttp, "/ss-xhttp"), "127.0.0.1", "/ss-xhttp")
                .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let (mut reader, mut writer) = crate::httpheader::connect(
            tunnel(serve_httpheader, "/ss-camouflage"),
            "127.0.0.1",
            "/ss-camouflage",
        )
        .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
    }

    /// A writer that has `writev`, which is what the relay's own socket is: it counts vectored
    /// calls, so a batch that leaves in one of them is one syscall by the same account the kernel
    /// keeps, and a carrier without `writev` is the other writer below.
    struct Vectored<'a> {
        seen: &'a mut Vec<u8>,
        writes: usize,
        bases: Vec<usize>,
    }
    impl Write for Vectored<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bases.push(buf.as_ptr() as usize);
            self.seen.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
            self.writes += 1;
            let mut taken = 0usize;
            for piece in bufs {
                self.bases.push(piece.as_ptr() as usize);
                self.seen.extend_from_slice(piece);
                taken += piece.len();
            }
            Ok(taken)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Bytes of a batch, each in the slot the kernel would have filled it with.
    fn slot_fill(total: usize) -> Vec<u8> {
        let mut buf = vec![0u8; CHUNKS_PER_BATCH * SLOT];
        for (i, byte) in (0..total).map(|i| (i % 251) as u8).enumerate() {
            buf[SEAL_HEAD + (i / MAX_CHUNK) * SLOT + (i % MAX_CHUNK)] = byte;
        }
        buf
    }

    #[test]
    fn one_relay_read_becomes_one_write_and_reads_back_whole() {
        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let total = MAX_CHUNK * CHUNKS_PER_BATCH;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let mut buf = slot_fill(total);
        let plain: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let base = buf.as_ptr() as usize;
        let capacity = buf.capacity();
        let room = base + buf.len();
        let mut seen = Vec::new();
        let (writes, bases) = {
            let mut out = Vectored {
                seen: &mut seen,
                writes: 0,
                bases: Vec::new(),
            };
            seal_all(&mut send, &mut buf, total, &mut out).expect("seals");
            (out.writes, out.bases)
        };
        assert_eq!(writes, 1, "four sealed chunks leave in one vectored write");
        assert_eq!(bases.len(), CHUNKS_PER_BATCH);
        for at in &bases {
            assert!(
                (base..room).contains(at),
                "a chunk leaves from the caller's buffer"
            );
        }
        assert_eq!(buf.as_ptr() as usize, base, "the read buffer never moves");
        assert_eq!(buf.capacity(), capacity, "the read buffer never grows");

        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&seen);
        let mut wire = wire_buffer();
        let mut got = 0usize;
        let mut chunks = 0usize;
        while got < plain.len() {
            let back = open_chunk(&mut cursor, &mut recv, &mut wire).expect("opens");
            assert_eq!(back, &plain[got..got + back.len()]);
            got += back.len();
            chunks += 1;
        }
        assert_eq!(got, plain.len(), "every byte came back");
        assert_eq!(
            chunks, CHUNKS_PER_BATCH,
            "one relay read of {total} B seals as four chunks"
        );

        // The batch is the same stream the same chunks sealed one at a time are: same lengths, same order, same tags, because every nonce and every byte position is unchanged by batching.
        let mut one_by_one = Vec::new();
        let mut again = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        for part in plain.chunks(MAX_CHUNK) {
            let mut slot = vec![0u8; SLOT];
            slot[SEAL_HEAD..SEAL_HEAD + part.len()].copy_from_slice(part);
            seal_all(&mut again, &mut slot, part.len(), &mut one_by_one).expect("seals");
        }
        assert_eq!(
            seen, one_by_one,
            "a batch is the chunks written one at a time"
        );
    }

    /// The read half of the batch, counted where the count is exact: one vectored read asks for
    /// [`CHUNKS_PER_BATCH`] slots of [`MAX_CHUNK`], and a fill that stops short lands only in the
    /// last slot, which is the one layout [`seal_all`] can tile without moving a byte.
    #[test]
    fn one_relay_read_asks_for_every_slot_of_a_batch() {
        struct Slots {
            rest: Vec<u8>,
            given: Vec<usize>,
            reads: usize,
        }
        impl Read for Slots {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let take = self.rest.len().min(buf.len());
                buf[..take].copy_from_slice(&self.rest[..take]);
                self.rest.drain(..take);
                Ok(take)
            }
            fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
                self.reads += 1;
                self.given = bufs.iter().map(|slot| slot.len()).collect();
                let mut filled = 0usize;
                for slot in bufs {
                    let take = self.rest.len().min(slot.len());
                    slot[..take].copy_from_slice(&self.rest[..take]);
                    self.rest.drain(..take);
                    filled += take;
                }
                Ok(filled)
            }
        }

        let plain: Vec<u8> = (0..MAX_CHUNK * CHUNKS_PER_BATCH - 7)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut read = Slots {
            rest: plain.clone(),
            given: Vec::new(),
            reads: 0,
        };
        let mut buf = vec![0u8; BATCH];
        let got = read_slots(&mut read, &mut buf).expect("reads");
        assert_eq!(got, plain.len(), "one read takes the whole fill");
        assert_eq!(read.reads, 1, "a batch is one read syscall");
        assert_eq!(
            read.given,
            vec![MAX_CHUNK; CHUNKS_PER_BATCH],
            "every slot of the batch is offered at once"
        );
        for (i, byte) in plain.iter().enumerate() {
            assert_eq!(
                buf[SEAL_HEAD + (i / MAX_CHUNK) * SLOT + (i % MAX_CHUNK)],
                *byte,
                "byte {i} of the fill sits in the slot seal_all reads it from"
            );
        }
    }

    /// The downlink's batch path end to end, counted where the count is exact: a source that
    /// answers the whole window in one read, a target that counts vectored writes, and two chunks
    /// that open and leave without one byte copied out of the window.
    #[test]
    fn a_bulk_read_serves_every_buffered_chunk() {
        struct CountingReads<R> {
            read: R,
            reads: usize,
        }
        impl<R: Read> Read for CountingReads<R> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                self.read.read(buf)
            }
        }

        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let n1 = MAX_CHUNK;
        let n2 = 100usize;
        let plain: Vec<u8> = (0..n1 + n2).map(|i| (i % 251) as u8).collect();
        let mut wire = Vec::new();
        for (off, n) in [(0, n1), (n1, n2)] {
            let mut buf = vec![0u8; SEAL_HEAD + n + TAG_LEN];
            buf[SEAL_HEAD..SEAL_HEAD + n].copy_from_slice(&plain[off..off + n]);
            seal_all(&mut send, &mut buf, n, &mut wire).expect("seals");
        }
        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut window = ChunkReader::new(CountingReads {
            read: std::io::Cursor::new(wire),
            reads: 0,
        });
        let mut got = Vec::new();
        let (writes, bases) = {
            let mut out = Vectored {
                seen: &mut got,
                writes: 0,
                bases: Vec::new(),
            };
            drain_window(&mut window, &mut recv, &mut out).expect("drains");
            (out.writes, out.bases)
        };
        assert_eq!(
            window.read.reads, 2,
            "one bulk read serves both chunks, the next one finds the end"
        );
        assert_eq!(writes, 1, "the opened batch leaves in one write");
        assert_eq!(bases.len(), 2, "one piece per opened chunk");
        assert!(
            bases[0] < bases[1],
            "the chunks open where they lie, in wire order"
        );
        let base = window.buf.as_ptr() as usize;
        let room = base + window.buf.len();
        for at in &bases {
            assert!(
                (base..room).contains(at),
                "a plaintext leaves from the window's own buffer"
            );
        }
        assert_eq!(got, plain, "the batch is the stream the seals made");
        let mut oversize = vec![0u8; SEAL_HEAD + MAX_CHUNK + 1 + TAG_LEN];
        assert!(
            seal_all(&mut send, &mut oversize, MAX_CHUNK + 1, &mut Vec::new()).is_err(),
            "a second chunk has no slot of its own in a one-slot buffer"
        );
    }

    /// A batch is the chunks the window already holds, and nothing more: a peer that stops to hear
    /// back from its own target must find the chunk it sent already at the target, so only the
    /// first chunk of a batch is ever waited for. One read, two opened, no third byte asked for.
    #[test]
    fn a_batch_never_waits_for_a_chunk_that_has_not_arrived() {
        struct Staged {
            parts: Vec<Vec<u8>>,
            at: usize,
            reads: usize,
        }
        impl Read for Staged {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                let Some(part) = self.parts.get(self.at) else {
                    return Ok(0);
                };
                self.at += 1;
                let take = part.len().min(buf.len());
                buf[..take].copy_from_slice(&part[..take]);
                Ok(take)
            }
        }

        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let first: Vec<u8> = (0..MAX_CHUNK).map(|i| (i % 251) as u8).collect();
        let second: Vec<u8> = (0..MAX_CHUNK).map(|i| (i % 197) as u8).collect();
        let seal = |send: &mut Uplink, plain: &[u8]| {
            let mut buf = vec![0u8; SLOT];
            buf[SEAL_HEAD..SEAL_HEAD + plain.len()].copy_from_slice(plain);
            let mut wire = Vec::new();
            seal_all(send, &mut buf, plain.len(), &mut wire).expect("seals");
            wire
        };
        let whole = seal(&mut send, &first);
        let rest = seal(&mut send, &second);
        // Chunk one whole, then the second chunk's sealed length and part of its payload; the rest of that payload is what the pump must not wait for.
        let split = LENGTH_LEN + TAG_LEN + 8;
        let mut staged = Staged {
            parts: vec![
                [whole.as_slice(), &rest[..split]].concat(),
                rest[split..].to_vec(),
            ],
            at: 0,
            reads: 0,
        };
        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut window = ChunkReader::new(&mut staged);
        let mut batch = [(0usize, 0usize); CHUNKS_PER_BATCH];
        assert_eq!(
            window.open_batch(&mut recv, &mut batch),
            1,
            "the second chunk is still arriving"
        );
        assert_eq!(window.read.reads, 1, "no read is spent waiting for it");
        assert_eq!(&window.buf[batch[0].0..batch[0].0 + batch[0].1], &first[..]);
        assert_eq!(
            window.open_batch(&mut recv, &mut batch),
            1,
            "the held length opens against its own nonce once the payload lands"
        );
        assert_eq!(
            &window.buf[batch[0].0..batch[0].0 + batch[0].1],
            &second[..]
        );
    }

    #[test]
    fn chunks_open_that_seal_sealed_and_reject_damage() {
        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let mut wire = Vec::new();
        let mut msg = [0u8; SEAL_HEAD + 17 + TAG_LEN];
        msg[SEAL_HEAD..SEAL_HEAD + 17].copy_from_slice(b"length-is-framing");
        seal_all(&mut send, &mut msg, 17, &mut wire).expect("seals");
        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&wire);
        let mut buf = wire_buffer();
        let base = buf.as_ptr() as usize;
        let room = buf.capacity();
        let back_at = {
            let back = open_chunk(&mut cursor, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"length-is-framing"[..]);
            back.as_ptr() as usize
        };
        assert!(
            (base..base + room).contains(&back_at),
            "the opened payload is a separate buffer, so a chunk read copies it out"
        );
        assert_eq!(buf.as_ptr() as usize, base, "the read buffer never moves");
        assert_eq!(buf.capacity(), room, "the read buffer never grows");

        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut damaged = std::io::Cursor::new(&tampered);
        let mut fresh = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        assert!(open_chunk(&mut damaged, &mut fresh, &mut wire_buffer()).is_none());
    }

    #[test]
    fn udp_salts_follow_the_method() {
        for (name, salt_len) in [
            ("aes-128-gcm", 16),
            ("aes-256-gcm", 32),
            ("chacha20-ietf-poly1305", 32),
        ] {
            let method = Method::parse(name).expect("names");
            assert_eq!(method.key_len(), salt_len, "{name}");
            let master = MasterKey::new("an-example-shared-password", salt_len);
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let packet = seal_to_wire(&master, method, &target, b"ping");
            assert_eq!(packet.len(), salt_len + 7 + 4 + TAG_LEN, "{name}");
            let (got, payload) = open_from_wire(&master, method, &packet).expect("opens");
            assert_eq!(got, target, "{name}");
            assert_eq!(payload, b"ping", "{name}");
        }
    }

    #[test]
    fn every_payload_length_and_address_survives_the_round_trip() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let mut checked = 0usize;
        for addr in [
            "127.0.0.1:53".parse().expect("v4"),
            "[2001:db8::1]:443".parse().expect("v6"),
            "0.0.0.0:65535".parse().expect("v4 edge"),
        ] {
            for len in (0..=300usize).chain([511, 512, 513, 1024, 1500, 4096]) {
                let payload: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(9))
                    .collect();
                let packet = seal_to_wire(&master, method, &addr, &payload);
                let (got, back) = open_from_wire(&master, method, &packet).expect("opens");
                assert_eq!(got, addr, "{addr} len {len}");
                assert_eq!(back, payload, "{addr} len {len}");
                checked += 1;
            }
        }
        assert!(checked > 900, "the sweep should be dense, not a sample");
    }

    /// The sealed packet and the opened payload must both be slices of the caller's own datagram buffer: one buffer per datagram, no second pass, and the buffer must not move or grow while datagrams flow through it.
    #[test]
    fn an_opened_payload_is_the_callers_own_bytes() {
        for (method, key_len) in [(Method::Aes256Gcm, 32), (Method::Rc4Md5, 16)] {
            let master = MasterKey::new("an-example-shared-password", key_len);
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let payload = b"a payload worth keeping";
            let mut wire = vec![0u8; DATAGRAM_MAX];
            let base = wire.as_ptr() as usize;
            let room = wire.capacity();
            let mut hop = None;
            for round in 0..8 {
                wire[SEAL_ROOM..SEAL_ROOM + payload.len()].copy_from_slice(payload);
                let (sealed_at, sealed) = {
                    let packet = seal_datagram(
                        &master,
                        method,
                        &target,
                        &mut wire,
                        SEAL_ROOM,
                        payload.len(),
                        &mut hop,
                    )
                    .expect("seals");
                    let at = packet.as_ptr() as usize;
                    assert!(
                        (base..base + room).contains(&at),
                        "round {round}: the sealed datagram is outside the caller's buffer"
                    );
                    (at - base, packet.len())
                };
                assert_eq!(
                    wire.as_ptr() as usize,
                    base,
                    "round {round}: the seal buffer moved, so a datagram reallocates"
                );
                assert_eq!(
                    wire.capacity(),
                    room,
                    "round {round}: the seal buffer grew, so a datagram reallocates"
                );
                let opened_at = {
                    let (got, opened) = open_datagram(
                        &master,
                        method,
                        &mut wire[sealed_at..sealed_at + sealed],
                        &mut hop,
                    )
                    .expect("opens");
                    assert_eq!(got, target, "round {round}");
                    assert_eq!(opened, payload, "round {round}");
                    opened.as_ptr() as usize
                };
                assert!(
                    (base..base + room).contains(&opened_at),
                    "round {round}: the payload is a separate buffer, so the datagram paid a \
                     second pass to reach it"
                );
                assert_eq!(
                    wire.as_ptr() as usize,
                    base,
                    "round {round}: the open buffer moved, so a datagram reallocates"
                );
                assert_eq!(
                    wire.capacity(),
                    room,
                    "round {round}: the open buffer grew, so a datagram reallocates"
                );
            }
        }
    }

    #[test]
    fn udp_datagrams_reject_damage() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let packet = seal_to_wire(&master, method, &target, b"ping");
        let wrong = MasterKey::new("a-different-password", 32);
        assert!(open_from_wire(&wrong, method, &packet).is_none());
        let mut cut = packet.clone();
        cut.pop();
        assert!(open_from_wire(&master, method, &cut).is_none());
        let mut flipped = packet.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        let as_sent = flipped.clone();
        let mut hop = None;
        assert!(open_datagram(&master, method, &mut flipped, &mut hop).is_none());
        assert_eq!(
            flipped, as_sent,
            "a refused datagram is left exactly as it arrived"
        );
        assert!(open_from_wire(&master, method, &packet[..10]).is_none());
        assert!(open_from_wire(&master, method, &[]).is_none());
    }

    /// What a stage between the carrier and the codec asks for: its own capacity.
    const STAGE: usize = 32 * 1024;

    /// The record size this tree's own xhttp writer frames a body in.
    const FRAME: usize = 16 * 1024;

    /// The carrier side of a carried downlink: every width the codec reaches the carrier with, which
    /// is where a stage's capacity would stand in for the codec's own ask.
    struct Asks<R> {
        read: R,
        widths: std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
    }

    impl<R: Read> Read for Asks<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.widths.borrow_mut().push(buf.len());
            self.read.read(buf)
        }
    }

    impl crate::proxy::FrameWrite for std::io::Cursor<Vec<u8>> {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            parts.iter().all(|part| self.write_all(part).is_ok())
        }
    }

    /// A carrier's answer: the head, the body framed in records the way this tree's writer frames
    /// them, and the terminator, so the codec below the carrier hears the wire as a dial hands it.
    fn carrier_answer(body: &[u8]) -> Vec<u8> {
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut wire = Vec::from(HEAD);
        for frame in body.chunks(FRAME) {
            let len = frame.len();
            wire.extend_from_slice(format!("{len:x}\r\n").as_bytes());
            wire.extend_from_slice(frame);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        wire
    }

    /// The chain the xhttp arm composes, driven from memory: an AEAD batch arrives through the real
    /// carrier framing into the window that opens it, and the carrier hears the window's own room —
    /// a `BufReader` between them would have swallowed the ask below its capacity and answered the
    /// window from its stage, so the capacity itself is what the carrier would hear.
    #[test]
    fn the_carrier_and_the_window_ask_the_socket_as_one() {
        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let plain: Vec<u8> = (0..MAX_CHUNK * 8).map(|i| (i % 251) as u8).collect();
        let mut body = Vec::new();
        for piece in plain.chunks(MAX_CHUNK) {
            let len = piece.len();
            let mut buf = vec![0u8; SEAL_HEAD + len + TAG_LEN];
            buf[SEAL_HEAD..SEAL_HEAD + len].copy_from_slice(piece);
            seal_all(&mut send, &mut buf, len, &mut body).expect("seals");
        }
        let (carrier, _writer) = crate::xhttp::connect_split(
            std::io::Cursor::new(carrier_answer(&body)),
            std::io::Cursor::new(Vec::new()),
            "h",
            "/share",
        )
        .expect("dials the head");
        let widths = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut out = Vec::new();
        assert!(
            relay_downlink(
                Asks {
                    read: carrier,
                    widths: std::rc::Rc::clone(&widths),
                },
                Recv::Ready(recv),
                &mut out,
            ),
            "the batch opens"
        );
        assert_eq!(out, plain, "a downlink byte crosses user space once");
        let seen = widths.borrow();
        assert!(
            seen.contains(&BATCH),
            "the whole window is asked of the carrier: {seen:?}"
        );
        assert!(
            seen.contains(&(BATCH - 4 * FRAME)),
            "the window's sub-capacity remainder reaches the carrier as the window asked it: {seen:?}"
        );
    }

    /// The stream rung's downlink: it asks one chunk at a time and the carrier hears that chunk, not
    /// a stage's capacity — the shape the `rc4-md5` page claims, witnessed below the carrier.
    #[test]
    fn the_stream_downlink_asks_its_own_chunk_of_the_socket() {
        let master = MasterKey::new("an-example-shared-password", 16);
        let iv = [9u8; IV_LEN];
        let key = rc4_md5_key(master.as_bytes(), &iv).expect("derives");
        let mut send = Rc4::new(&key).expect("cipher");
        let mut body = vec![0u8; READ_CHUNK * 2 + 10];
        for (i, byte) in body.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        send.crypt(&mut body);
        let widths = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let recv = Rc4::new(&key).expect("cipher");
        let (carrier, _writer) = crate::xhttp::connect_split(
            std::io::Cursor::new(carrier_answer(&body)),
            std::io::Cursor::new(Vec::new()),
            "h",
            "/share",
        )
        .expect("dials the head");
        let plain: Vec<u8> = (0..READ_CHUNK * 2 + 10).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        assert!(
            relay_downlink(
                Asks {
                    read: carrier,
                    widths: std::rc::Rc::clone(&widths),
                },
                Recv::StreamReady(recv),
                &mut out,
            ),
            "the stream opens"
        );
        assert_eq!(out, plain, "the keystream writes where the carrier read");
        let seen = widths.borrow();
        assert!(
            seen.contains(&READ_CHUNK),
            "the relay read is asked of the carrier whole: {seen:?}"
        );
        assert!(
            !seen.contains(&STAGE),
            "a stage would ask its capacity here: {seen:?}"
        );
    }
}
