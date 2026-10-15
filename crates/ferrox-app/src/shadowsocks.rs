use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::Duration;

use ferrox_core::shadowsocks::{
    rc4_md5_key, Cipher, MasterKey, Method, Rc4, LENGTH_LEN, MAX_CHUNK, TAG_LEN,
};

use crate::budgets::RELAY_POLL;
use crate::proxy::{push_addr, read_exact, UDP_BUF};

const SALT_LEN: usize = 32;
// One relay read is exactly one AEAD chunk: a 16384 B read would seal as 16383 + 1, a second length seal and tag for a single tail byte.
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

pub(crate) fn serve(mut stream: TcpStream, password: &str, method: &str, freedom: bool) {
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
    let Ok(mut uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
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
fn serve_stream(mut stream: TcpStream, password: &str) {
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
    let Ok(mut uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
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

pub(crate) fn serve_ws(stream: TcpStream, password: &str, method: &str, path: &str, freedom: bool) {
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
    stream: TcpStream,
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

pub(crate) fn serve_grpc(
    stream: TcpStream,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::grpc::accept(stream, path) else {
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

pub(crate) fn serve_xhttp(
    stream: TcpStream,
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
    stream: TcpStream,
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
) -> Option<(TcpStream, Uplink, Recv)> {
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
    let mut uplink = TcpStream::connect_timeout(&target, Duration::from_secs(8)).ok()?;
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
) -> Option<(TcpStream, Uplink, Recv)> {
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
    let mut uplink = TcpStream::connect_timeout(&target, Duration::from_secs(8)).ok()?;
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
    target: &SocketAddr,
) -> Option<(Uplink, Recv)> {
    let method = Method::parse(method)?;
    let master = MasterKey::new(password, method.key_len());
    if method.is_stream() {
        let mut iv = [0u8; IV_LEN];
        getrandom::getrandom(&mut iv).ok()?;
        uplink.write_all(&iv).ok()?;
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut send = Rc4::new(&key)?;
        let mut addr = Vec::with_capacity(20);
        push_addr(&mut addr, target, 4);
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
    let mut addr = Vec::with_capacity(20);
    push_addr(&mut addr, target, 4);
    addr.extend_from_slice(&target.port().to_be_bytes());
    let n = addr.len();
    let mut buf = vec![0u8; SEAL_HEAD + n + TAG_LEN];
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

pub(crate) fn pump_relay(plain: &TcpStream, sealed: &TcpStream, send: Uplink, recv: Recv) {
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
    plain: &TcpStream,
    mut reader: R,
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
        let mut buf = vec![0u8; SEAL_HEAD + READ_CHUNK + TAG_LEN];
        while let Ok(read) = plain_read.read(&mut buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]) {
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
    let mut aead: Option<Cipher> = None;
    let mut stream: Option<Rc4> = None;
    match recv {
        Recv::Ready(cipher) => aead = Some(cipher),
        Recv::Waiting(method, master) => {
            let salt_len = method.key_len();
            let mut peer = [0u8; SALT_LEN];
            if read_exact(&mut reader, &mut peer[..salt_len]).is_err() {
                return;
            }
            let Some(cipher) = Cipher::from_master_key(method, &master, &peer[..salt_len]) else {
                return;
            };
            aead = Some(cipher);
        }
        Recv::StreamReady(rc4) => stream = Some(rc4),
        Recv::StreamWaiting(master) => {
            let mut peer = [0u8; IV_LEN];
            if read_exact(&mut reader, &mut peer).is_err() {
                return;
            }
            let Some(key) = rc4_md5_key(master.as_bytes(), &peer) else {
                return;
            };
            let Some(rc4) = Rc4::new(&key) else {
                return;
            };
            stream = Some(rc4);
        }
    }
    if let Some(mut cipher) = aead {
        let mut window = ChunkReader::new(reader);
        while let Some(payload) = window.open_chunk(&mut cipher) {
            if plain_write.write_all(payload).is_err() {
                break;
            }
        }
    } else if let Some(mut rc4) = stream {
        let mut buf = vec![0u8; READ_CHUNK];
        while let Some(payload) = open_stream(&mut reader, &mut rc4, &mut buf) {
            if plain_write.write_all(payload).is_err() {
                break;
            }
        }
    }
    close();
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
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
    let mut buf = vec![0u8; UDP_BUF];
    let mut reply = vec![0u8; UDP_BUF];
    let mut datagrams = Datagrams::new();
    loop {
        match clients.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some((dest, payload)) = datagrams.open(&master, method, &buf[..n]) {
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
            while let Ok((n, src)) = sock.recv_from(&mut reply) {
                if let Some(client) = table.get(&src) {
                    if let Some(packet) = datagrams.seal(&master, method, &src, &reply[..n]) {
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

/// A chunk buffer sized once: `open_chunk` writes into a prefix of it, so no read ever grows or re-zeroes it.
pub(crate) fn wire_buffer() -> Vec<u8> {
    vec![0u8; WIRE_MAX]
}

/// Seal `n` payload bytes at `buf[SEAL_HEAD..]` and hand seals and payload to `out` in one write: a payload byte is never copied in user space, and one call seals one chunk because the first chunk's tag would clobber a second's plaintext — oversize input is refused loudly rather than corrupted quietly.
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
            if n > MAX_CHUNK {
                return Err(invalid());
            }
            debug_assert!(buf.len() >= SEAL_HEAD + n + TAG_LEN);
            let end = SEAL_HEAD + n;
            let mut length = (n as u16).to_be_bytes();
            let length_tag = cipher
                .seal_piece_in_place(&mut length)
                .ok_or_else(invalid)?;
            let tag = {
                let chunk = &mut buf[SEAL_HEAD..end];
                cipher.seal_piece_in_place(chunk).ok_or_else(invalid)?
            };
            buf[..LENGTH_LEN].copy_from_slice(&length);
            buf[LENGTH_LEN..SEAL_HEAD].copy_from_slice(&length_tag);
            buf[end..end + TAG_LEN].copy_from_slice(&tag);
            out.write_all(&buf[..end + TAG_LEN])
        }
        Uplink::Stream(rc4) => {
            let payload = &mut buf[SEAL_HEAD..SEAL_HEAD + n];
            rc4.crypt(payload);
            out.write_all(payload)
        }
    }
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

/// One relay connection's downlink window: wire bytes land here once and chunks open where they lie — a length never costs its own read and the payload decrypts in the caller's buffer with no copy; sized for two full chunks so a bulk read usually serves the next length too.
struct ChunkReader<R> {
    read: R,
    buf: Vec<u8>,
    at: usize,
    end: usize,
}

impl<R: Read> ChunkReader<R> {
    fn new(read: R) -> Self {
        Self {
            read,
            buf: vec![0u8; 2 * WIRE_MAX],
            at: 0,
            end: 0,
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

    fn open_chunk(&mut self, recv: &mut Cipher) -> Option<&[u8]> {
        self.fill(LENGTH_LEN + TAG_LEN)?;
        let size = {
            let length = &mut self.buf[self.at..self.at + LENGTH_LEN + TAG_LEN];
            open_length(recv, length)?
        };
        self.fill(LENGTH_LEN + TAG_LEN + size + TAG_LEN)?;
        let start = self.at + LENGTH_LEN + TAG_LEN;
        let wire = &mut self.buf[start..start + size + TAG_LEN];
        let plain = open_into(recv, wire)?;
        self.at = start + size + TAG_LEN;
        Some(&self.buf[start..start + plain])
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

/// The two buffers one UDP socket thread reuses for every datagram it sends and opens: one scratch per direction, owned by the thread that owns the socket, so a datagram costs no allocation and no pass over the payload beyond the copy the address header forces.
pub(crate) struct Datagrams {
    sealed: Vec<u8>,
    opened: Vec<u8>,
}

impl Datagrams {
    pub(crate) fn new() -> Self {
        Self {
            sealed: Vec::new(),
            opened: Vec::new(),
        }
    }

    pub(crate) fn seal(
        &mut self,
        master: &MasterKey,
        method: Method,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        if method.is_stream() {
            return self.seal_stream(master, dest, payload);
        }
        let salt_len = method.key_len();
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt[..salt_len]).ok()?;
        let mut cipher = Cipher::from_master_key(method, master, &salt[..salt_len])?;
        let out = &mut self.sealed;
        out.clear();
        out.reserve(salt_len + 20 + payload.len() + TAG_LEN);
        out.extend_from_slice(&salt[..salt_len]);
        push_addr(out, dest, 4);
        out.extend_from_slice(&dest.port().to_be_bytes());
        out.extend_from_slice(payload);
        cipher.seal_tail_in_place(out, salt_len)?;
        Some(out)
    }

    /// The IV and the address header precede the payload and the stream opens in place, so the payload stays where the datagram put it: one copy in, no tag, and no `memmove` at all.
    fn seal_stream(
        &mut self,
        master: &MasterKey,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        let mut iv = [0u8; IV_LEN];
        getrandom::getrandom(&mut iv).ok()?;
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut rc4 = Rc4::new(&key)?;
        let out = &mut self.sealed;
        out.clear();
        out.reserve(IV_LEN + 20 + payload.len());
        out.extend_from_slice(&iv);
        let at = out.len();
        push_addr(out, dest, 4);
        out.extend_from_slice(&dest.port().to_be_bytes());
        out.extend_from_slice(payload);
        rc4.crypt(&mut out[at..]);
        Some(out)
    }

    /// The salt and the address header precede the payload and the AEAD opens in place, so the payload stays where the datagram put it: one copy in, and the returned slice points into it rather than at a second buffer.
    pub(crate) fn open(
        &mut self,
        master: &MasterKey,
        method: Method,
        packet: &[u8],
    ) -> Option<(SocketAddr, &[u8])> {
        if method.is_stream() {
            return self.open_stream(master, packet);
        }
        let salt_len = method.key_len();
        if packet.len() < salt_len + TAG_LEN + 1 {
            return None;
        }
        let mut cipher = Cipher::from_master_key(method, master, &packet[..salt_len])?;
        let sealed = &mut self.opened;
        sealed.clear();
        sealed.extend_from_slice(&packet[salt_len..]);
        let len = cipher.open_in_place(sealed)?;
        let (target, used) = parse_addr_header(&sealed[..len])?;
        Some((target, &sealed[used..len]))
    }

    fn open_stream(&mut self, master: &MasterKey, packet: &[u8]) -> Option<(SocketAddr, &[u8])> {
        if packet.len() < IV_LEN + 1 {
            return None;
        }
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&packet[..IV_LEN]);
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut rc4 = Rc4::new(&key)?;
        let sealed = &mut self.opened;
        sealed.clear();
        sealed.extend_from_slice(&packet[IV_LEN..]);
        rc4.crypt(sealed);
        let (target, used) = parse_addr_header(sealed)?;
        Some((target, &sealed[used..]))
    }
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

    /// Silence past the budget is death, not scheduling: a peer that opens the connection and never sends must not pin the raw Shadowsocks handshake thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_a_raw_shadowsocks_handshake() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, "an-example-shared-password", "aes-256-gcm", true);
            let _ = done_tx.send(());
        });
        let _peer = TcpStream::connect(addr).expect("connects");
        done_rx
            .recv_timeout(crate::budgets::HANDSHAKE_REQUEST_TIMEOUT + Duration::from_secs(5))
            .expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// Silence past the budget is death, not scheduling: the stream handshake reads a clear IV then scans the encrypted header, and a peer that opens the connection and never sends must not pin that thread forever either.
    #[test]
    fn a_silent_peer_cannot_pin_a_stream_shadowsocks_handshake() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, "an-example-shared-password", "rc4-md5", true);
            let _ = done_tx.send(());
        });
        let _peer = TcpStream::connect(addr).expect("connects");
        done_rx
            .recv_timeout(crate::budgets::HANDSHAKE_REQUEST_TIMEOUT + Duration::from_secs(5))
            .expect("the bounded request read returns instead of pinning the thread");
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
            let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
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
            let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
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
            let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("timeout");
            let Some((mut send, recv)) =
                client_send_handshake(&mut uplink, "an-example-shared-password", name, &target)
            else {
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
            let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
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
            let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("timeout");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            assert!(
                client_send_handshake(&mut uplink, "an-example-shared-password", name, &target)
                    .is_none(),
                "{name}: refused"
            );
        }
    }

    #[test]
    fn stream_relays_an_echo() {
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        uplink
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .expect("timeout");
        let Some((mut send, recv)) = client_send_handshake(
            &mut uplink,
            "an-example-shared-password",
            "rc4-md5",
            &target,
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
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::ws::connect(stream, "127.0.0.1", "/ss-ws", 0, &[]).expect("carries");
        let Some((mut send, recv)) = client_send_handshake(
            &mut writer,
            "an-example-shared-password",
            "rc4-md5",
            &target,
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

    #[test]
    fn stream_udp_round_trips_and_rejects_damage() {
        let method = Method::Rc4Md5;
        let master = MasterKey::new("an-example-shared-password", 16);
        for target in [
            "127.0.0.1:53".parse().expect("v4"),
            "[2001:db8::1]:443".parse().expect("v6"),
        ] {
            let mut datagrams = Datagrams::new();
            let packet = datagrams
                .seal(&master, method, &target, b"ping")
                .expect("seals")
                .to_vec();
            let header = if target.is_ipv6() { 19 } else { 7 };
            assert_eq!(
                packet.len(),
                IV_LEN + header + b"ping".len(),
                "a datagram is the IV, the header and the payload, with no tag"
            );
            let (got, payload) = datagrams.open(&master, method, &packet).expect("opens");
            assert_eq!(got, target);
            assert_eq!(payload, b"ping");
        }
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut datagrams = Datagrams::new();
        let packet = datagrams
            .seal(&master, method, &target, b"ping")
            .expect("seals")
            .to_vec();
        let mut cut = packet.clone();
        cut.pop();
        let (_, short) = datagrams.open(&master, method, &cut).expect("opens");
        assert_eq!(
            short, b"pin",
            "a stream has no tag: truncation truncates, it does not refuse"
        );
        assert!(datagrams.open(&master, method, &packet[..10]).is_none());
        assert!(datagrams.open(&master, method, &[]).is_none());
        let wrong = MasterKey::new("a-different-password", 16);
        if let Some((_, payload)) = datagrams.open(&wrong, method, &packet) {
            assert_ne!(payload, b"ping", "a wrong password opens only noise");
        }
    }

    /// The opened payload must be a subslice of the buffer the datagram was opened in: that is what makes the copy count zero instead of two, and the buffer must not move or grow or a datagram reallocates.
    #[test]
    fn stream_opened_payload_is_the_datagrams_own_bytes() {
        let method = Method::Rc4Md5;
        let master = MasterKey::new("an-example-shared-password", 16);
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut datagrams = Datagrams::new();
        let packet = datagrams
            .seal(&master, method, &target, b"a payload worth keeping")
            .expect("seals")
            .to_vec();
        datagrams
            .open(&master, method, &packet)
            .expect("warms the buffer");
        let opened_at = datagrams.opened.as_ptr() as usize;
        let opened_room = datagrams.opened.capacity();
        for round in 0..8 {
            let packet = datagrams
                .seal(&master, method, &target, b"a payload worth keeping")
                .expect("seals")
                .to_vec();
            let (got, payload) = datagrams.open(&master, method, &packet).expect("opens");
            assert_eq!(got, target, "round {round}");
            assert_eq!(payload, b"a payload worth keeping", "round {round}");
            let at = payload.as_ptr();
            assert!(
                datagrams.opened.as_ptr_range().contains(&at),
                "round {round}: the payload is a separate buffer, so the datagram paid a \
                 second pass to reach it"
            );
            assert_eq!(
                datagrams.opened.as_ptr() as usize,
                opened_at,
                "round {round}: the open buffer moved, so a datagram reallocates"
            );
            assert_eq!(
                datagrams.opened.capacity(),
                opened_room,
                "round {round}: the open buffer grew, so a datagram reallocates"
            );
        }
    }

    #[test]
    fn carried_transports_relay_an_echo() {
        fn echo() -> u16 {
            let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                for stream in echo.incoming() {
                    let Ok(mut stream) = stream else {
                        continue;
                    };
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
        fn round_trip(reader: &mut dyn Read, writer: &mut dyn Write, target: &SocketAddr) {
            let Some((mut send, recv)) =
                client_send_handshake(writer, "an-example-shared-password", "aes-256-gcm", target)
            else {
                panic!("handshake refused");
            };
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
        let password = "an-example-shared-password";
        let method = "aes-256-gcm";
        let echo_port = echo();
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_ws(stream, password, method, "/ss-ws", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::ws::connect(stream, "127.0.0.1", "/ss-ws", 0, &[]).expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_httpupgrade(stream, password, method, "/ss-upgrade", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::httpupgrade::connect(stream, "127.0.0.1", "/ss-upgrade", 0, &[])
                .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_grpc(stream, password, method, "/TunnelService/Tun", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::grpc::connect(stream, "127.0.0.1", "/TunnelService/Tun").expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_xhttp(stream, password, method, "/ss-xhttp", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::xhttp::connect(stream, "127.0.0.1", "/ss-xhttp").expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_httpheader(stream, password, method, "/ss-camouflage", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::httpheader::connect(stream, "127.0.0.1", "/ss-camouflage").expect("carries");
        round_trip(&mut reader, &mut writer, &target);
    }

    #[test]
    fn one_relay_read_becomes_one_write_and_reads_back_whole() {
        struct Counting<'a> {
            seen: &'a mut Vec<u8>,
            writes: usize,
            base: usize,
        }
        impl Write for Counting<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                self.base = buf.as_ptr() as usize;
                self.seen.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let mut buf = vec![0u8; SEAL_HEAD + READ_CHUNK + TAG_LEN];
        for (i, b) in buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 251) as u8;
        }
        let plain = buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK].to_vec();
        let base = buf.as_ptr() as usize;
        let capacity = buf.capacity();
        let mut seen = Vec::new();
        let (writes, wrote_base) = {
            let mut out = Counting {
                seen: &mut seen,
                writes: 0,
                base: 0,
            };
            seal_all(&mut send, &mut buf, READ_CHUNK, &mut out).expect("seals");
            (out.writes, out.base)
        };
        assert_eq!(writes, 1, "a relay read is sealed and written once");
        assert_eq!(
            wrote_base, base,
            "the write leaves from the caller's buffer"
        );
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
        assert_eq!(chunks, 1, "a relay read seals into one chunk");
    }

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
        let first = window.open_chunk(&mut recv).expect("opens").to_vec();
        assert_eq!(first, &plain[..MAX_CHUNK]);
        let second = window.open_chunk(&mut recv).expect("opens").to_vec();
        assert_eq!(second, &plain[MAX_CHUNK..]);
        assert_eq!(window.read.reads, 1, "one bulk read serves both chunks");
        assert!(window.open_chunk(&mut recv).is_none());
        let mut oversize = vec![0u8; SEAL_HEAD + MAX_CHUNK + 1 + TAG_LEN];
        assert!(
            seal_all(&mut send, &mut oversize, MAX_CHUNK + 1, &mut Vec::new()).is_err(),
            "a second chunk's plaintext is already the first chunk's tag room"
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
        let back = open_chunk(&mut cursor, &mut recv, &mut buf).expect("opens");
        assert_eq!(back, &b"length-is-framing"[..]);

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
            let mut datagrams = Datagrams::new();
            let packet = datagrams
                .seal(&master, method, &target, b"ping")
                .expect("seals")
                .to_vec();
            assert_eq!(packet.len(), salt_len + 7 + 4 + TAG_LEN, "{name}");
            let (got, payload) = datagrams.open(&master, method, &packet).expect("opens");
            assert_eq!(got, target, "{name}");
            assert_eq!(payload, b"ping", "{name}");
        }
    }

    #[test]
    fn every_payload_length_and_address_survives_the_round_trip() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let mut datagrams = Datagrams::new();
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
                let packet = datagrams
                    .seal(&master, method, &addr, &payload)
                    .expect("seals")
                    .to_vec();
                let (got, back) = datagrams.open(&master, method, &packet).expect("opens");
                assert_eq!(got, addr, "{addr} len {len}");
                assert_eq!(back, payload, "{addr} len {len}");
                checked += 1;
            }
        }
        assert!(checked > 900, "the sweep should be dense, not a sample");
    }

    /// The opened payload must be a subslice of the buffer the datagram was opened in: that is what makes the copy count one instead of three, and the buffer must not move or grow or a datagram reallocates.
    #[test]
    fn an_opened_payload_is_the_datagrams_own_bytes() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut datagrams = Datagrams::new();
        let packet = datagrams
            .seal(&master, method, &target, b"a payload worth keeping")
            .expect("seals")
            .to_vec();
        datagrams
            .open(&master, method, &packet)
            .expect("warms the buffer");
        let opened_at = datagrams.opened.as_ptr() as usize;
        let opened_room = datagrams.opened.capacity();
        for round in 0..8 {
            let (got, payload) = datagrams.open(&master, method, &packet).expect("opens");
            assert_eq!(got, target, "round {round}");
            assert_eq!(payload, b"a payload worth keeping", "round {round}");
            let at = payload.as_ptr();
            assert!(
                datagrams.opened.as_ptr_range().contains(&at),
                "round {round}: the payload is a separate buffer, so the datagram paid a \
                 second pass to reach it"
            );
            assert_eq!(
                datagrams.opened.as_ptr() as usize,
                opened_at,
                "round {round}: the open buffer moved, so a datagram reallocates"
            );
            assert_eq!(
                datagrams.opened.capacity(),
                opened_room,
                "round {round}: the open buffer grew, so a datagram reallocates"
            );
        }
    }

    #[test]
    fn udp_datagrams_reject_damage() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut datagrams = Datagrams::new();
        let packet = datagrams
            .seal(&master, method, &target, b"ping")
            .expect("seals")
            .to_vec();
        let wrong = MasterKey::new("a-different-password", 32);
        assert!(datagrams.open(&wrong, method, &packet).is_none());
        let mut cut = packet.clone();
        cut.pop();
        assert!(datagrams.open(&master, method, &cut).is_none());
        let mut flipped = packet.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(datagrams.open(&master, method, &flipped).is_none());
        assert!(datagrams.open(&master, method, &packet[..10]).is_none());
        assert!(datagrams.open(&master, method, &[]).is_none());
    }
}
