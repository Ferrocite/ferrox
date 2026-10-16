use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrox_core::shadowsocks2022::{self, Cipher, Method, BLOCK_LEN, MAX_CHUNK, TAG_LEN};

use crate::budgets::RELAY_POLL;
use crate::proxy::{push_addr, read_exact};

const READ_CHUNK: usize = 0x4000;
const SKEW: u64 = 30;
const LENGTH_LEN: usize = 2;
/// Room around one chunk's payload inside the caller's buffer: a sealed length before it and its tag after it, so both seals land beside the payload instead of the payload moving to them.
const SEAL_HEAD: usize = LENGTH_LEN + TAG_LEN;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn salt_seen(salt: &[u8]) -> bool {
    static WINDOW: OnceLock<Mutex<crate::proxy::Replay>> = OnceLock::new();
    let mut key = [0u8; 32];
    key[..salt.len()].copy_from_slice(salt);
    let mut guard = WINDOW
        .get_or_init(|| Mutex::new(crate::proxy::Replay::new(SKEW)))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.seen(&key, now_secs())
}

fn psks(password: &str, method: Method) -> Option<Vec<Vec<u8>>> {
    shadowsocks2022::parse_psk_list(password, method.key_len())
}

fn fresh_salt(key_len: usize) -> Option<Vec<u8>> {
    let mut salt = vec![0u8; key_len];
    getrandom::getrandom(&mut salt).ok()?;
    Some(salt)
}

fn padding_for(payload_len: usize) -> usize {
    if payload_len > 0 {
        0
    } else {
        16
    }
}

pub(crate) fn serve(mut stream: TcpStream, password: &str, method: &str, freedom: bool) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    let Some(list) = psks(password, method) else {
        return;
    };
    if list.len() == 1 {
        serve_single(&mut stream, method, &list[0], freedom);
    } else if !method.is_chacha() {
        serve_multi(&mut stream, method, &list, freedom);
    }
}

/// Read and open the fixed+variable header of an already-salted request, returning the target and any early data; the single- and multi-psk handshakes share this so the framing lives in one place.
fn read_request_header(stream: &mut dyn Read, recv: &mut Cipher) -> Option<(SocketAddr, Vec<u8>)> {
    let mut fixed = vec![0u8; 11 + TAG_LEN];
    if read_exact(stream, &mut fixed).is_err() {
        return None;
    }
    let len = recv.open_in_place(&mut fixed)?;
    if len != 11 || fixed[0] != 0 {
        return None;
    }
    let stamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap_or([0u8; 8]));
    if now_secs().abs_diff(stamp) > SKEW {
        return None;
    }
    let var_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
    if var_len == 0 || var_len > 2048 {
        return None;
    }
    let mut variable = vec![0u8; var_len + TAG_LEN];
    if read_exact(stream, &mut variable).is_err() {
        return None;
    }
    recv.open_in_place(&mut variable)?;
    variable.truncate(var_len);
    let (target, used) = parse_addr_header(&variable)?;
    if variable.len() < used + 2 {
        return None;
    }
    let pad = usize::from(u16::from_be_bytes([variable[used], variable[used + 1]]));
    let at = used + 2 + pad;
    if at > variable.len() || (pad == 0 && at == variable.len()) {
        return None;
    }
    Some((target, variable[at..].to_vec()))
}

fn serve_single(stream: &mut TcpStream, method: Method, psk: &[u8], freedom: bool) {
    if !freedom {
        return;
    }
    let key_len = method.key_len();
    // Bound the salt/fixed/variable request reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: stream,
            until: std::time::Instant::now() + budget,
        };
        'req: {
            let mut salt = vec![0u8; key_len];
            if read_exact(&mut bounded, &mut salt).is_err() {
                break 'req None;
            }
            if salt_seen(&salt) {
                break 'req None;
            }
            let Some(mut recv) = Cipher::from_psk(method, psk, &salt) else {
                break 'req None;
            };
            let Some((target, early)) = read_request_header(&mut bounded, &mut recv) else {
                break 'req None;
            };
            Some((recv, salt, target, early))
        }
    };
    let _ = stream.set_read_timeout(None);
    let Some((recv, salt, target, early)) = opened else {
        return;
    };
    let Ok(mut uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if !early.is_empty() && uplink.write_all(&early).is_err() {
        return;
    }
    let Some(server_salt) = fresh_salt(key_len) else {
        return;
    };
    let Some(mut send) = Cipher::from_psk(method, psk, &server_salt) else {
        return;
    };
    let mut fixed_resp = Vec::with_capacity(1 + 8 + key_len + 2);
    fixed_resp.push(1);
    fixed_resp.extend_from_slice(&now_secs().to_be_bytes());
    fixed_resp.extend_from_slice(&salt);
    fixed_resp.extend_from_slice(&0u16.to_be_bytes());
    let mut out = Vec::with_capacity(server_salt.len() + fixed_resp.len() + TAG_LEN);
    out.extend_from_slice(&server_salt);
    if send.seal_into(&fixed_resp, &mut out).is_none() {
        return;
    }
    if stream.write_all(&out).is_err() {
        return;
    }
    pump_relay(&uplink, stream, send, Recv::Ready(recv));
}

fn serve_multi(stream: &mut TcpStream, method: Method, list: &[Vec<u8>], freedom: bool) {
    if !freedom || list.len() < 2 {
        return;
    }
    let key_len = method.key_len();
    let master = &list[0];
    // Bound the salt/eih/fixed/variable request reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: stream,
            until: std::time::Instant::now() + budget,
        };
        'req: {
            let mut salt = vec![0u8; key_len];
            if read_exact(&mut bounded, &mut salt).is_err() {
                break 'req None;
            }
            if salt_seen(&salt) {
                break 'req None;
            }
            let mut eih = [0u8; BLOCK_LEN];
            if read_exact(&mut bounded, &mut eih).is_err() {
                break 'req None;
            }
            let Some(hash) = shadowsocks2022::decrypt_eih(method, master, &salt, &eih) else {
                break 'req None;
            };
            let Some(psk) = list[1..]
                .iter()
                .find(|p| shadowsocks2022::user_hash(p) == hash)
            else {
                break 'req None;
            };
            let psk = psk.clone();
            let Some(mut recv) = Cipher::from_psk(method, &psk, &salt) else {
                break 'req None;
            };
            let Some((target, early)) = read_request_header(&mut bounded, &mut recv) else {
                break 'req None;
            };
            Some((recv, psk, salt, target, early))
        }
    };
    let _ = stream.set_read_timeout(None);
    let Some((recv, psk, salt, target, early)) = opened else {
        return;
    };
    let Ok(mut uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if !early.is_empty() && uplink.write_all(&early).is_err() {
        return;
    }
    let Some(server_salt) = fresh_salt(key_len) else {
        return;
    };
    let Some(mut send) = Cipher::from_psk(method, &psk, &server_salt) else {
        return;
    };
    let mut fixed_resp = Vec::with_capacity(1 + 8 + key_len + 2);
    fixed_resp.push(1);
    fixed_resp.extend_from_slice(&now_secs().to_be_bytes());
    fixed_resp.extend_from_slice(&salt);
    fixed_resp.extend_from_slice(&0u16.to_be_bytes());
    let mut out = Vec::with_capacity(server_salt.len() + fixed_resp.len() + TAG_LEN);
    out.extend_from_slice(&server_salt);
    if send.seal_into(&fixed_resp, &mut out).is_none() {
        return;
    }
    if stream.write_all(&out).is_err() {
        return;
    }
    pump_relay(&uplink, stream, send, Recv::Ready(recv));
}

pub(crate) fn serve_relay(
    stream: TcpStream,
    method: &str,
    relay_psk: &[u8],
    dests: &[(Vec<u8>, SocketAddr)],
) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if method.is_chacha() {
        return;
    }
    serve_relay_on(stream, method, relay_psk, dests);
}

fn serve_relay_on(
    mut stream: TcpStream,
    method: Method,
    relay_psk: &[u8],
    dests: &[(Vec<u8>, SocketAddr)],
) {
    let key_len = method.key_len();
    if relay_psk.len() != key_len {
        return;
    }
    let mut salt = vec![0u8; key_len];
    if read_exact(&mut stream, &mut salt).is_err() {
        return;
    }
    let mut eih = [0u8; BLOCK_LEN];
    if read_exact(&mut stream, &mut eih).is_err() {
        return;
    }
    let Some(hash) = shadowsocks2022::decrypt_eih(method, relay_psk, &salt, &eih) else {
        return;
    };
    let Some((_, target)) = dests
        .iter()
        .find(|(k, _)| shadowsocks2022::user_hash(k) == hash)
    else {
        return;
    };
    let target = *target;
    let Ok(mut next) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let mut rest = crate::proxy::RelayBuf::new();
    let mut head = Vec::with_capacity(salt.len() + READ_CHUNK);
    head.extend_from_slice(&salt);
    match stream.read(rest.as_mut()) {
        Ok(0) | Err(_) => {}
        Ok(n) => head.extend_from_slice(&rest.as_mut()[..n]),
    }
    let _ = stream.set_read_timeout(None);
    if next.write_all(&head).is_err() {
        return;
    }
    relay_raw(&mut stream, &mut next);
}

fn relay_raw(a: &mut TcpStream, b: &mut TcpStream) {
    let Ok(a_read) = a.try_clone() else { return };
    let Ok(mut b_write) = b.try_clone() else {
        return;
    };
    let t = thread::spawn(move || {
        let mut buf = crate::proxy::RelayBuf::new();
        let mut src = a_read;
        loop {
            match src.read(buf.as_mut()) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if b_write.write_all(&buf.as_mut()[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut buf = crate::proxy::RelayBuf::new();
    loop {
        match b.read(buf.as_mut()) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if a.write_all(&buf.as_mut()[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = t.join();
}

fn accept_on(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    password: &str,
    method: &str,
    freedom: bool,
) -> Option<(TcpStream, Cipher, Recv)> {
    let method = Method::parse(method)?;
    if !freedom {
        return None;
    }
    let list = psks(password, method)?;
    let (psk, eih_len) = if list.len() == 1 {
        (list[0].clone(), 0)
    } else {
        if method.is_chacha() {
            return None;
        }
        let mut salt_probe = vec![0u8; method.key_len()];
        read_exact(reader, &mut salt_probe).ok()?;
        if salt_seen(&salt_probe) {
            return None;
        }
        let mut eih = [0u8; BLOCK_LEN];
        read_exact(reader, &mut eih).ok()?;
        let hash = shadowsocks2022::decrypt_eih(method, &list[0], &salt_probe, &eih)?;
        let user = list[1..]
            .iter()
            .find(|p| shadowsocks2022::user_hash(p) == hash)?
            .clone();
        let mut recv = Cipher::from_psk(method, &user, &salt_probe)?;
        let target = open_handshake(reader, &mut recv)?;
        let mut uplink = TcpStream::connect_timeout(&target.0, Duration::from_secs(8)).ok()?;
        uplink.write_all(&target.1).ok()?;
        let server_salt = fresh_salt(method.key_len())?;
        let mut send = Cipher::from_psk(method, &user, &server_salt)?;
        let mut fixed_resp = Vec::with_capacity(1 + 8 + method.key_len() + 2);
        fixed_resp.push(1);
        fixed_resp.extend_from_slice(&now_secs().to_be_bytes());
        fixed_resp.extend_from_slice(&salt_probe);
        fixed_resp.extend_from_slice(&0u16.to_be_bytes());
        let mut out = Vec::with_capacity(server_salt.len() + fixed_resp.len() + TAG_LEN);
        out.extend_from_slice(&server_salt);
        send.seal_into(&fixed_resp, &mut out)?;
        writer.write_all(&out).ok()?;
        return Some((uplink, send, Recv::Ready(recv)));
    };
    let _ = eih_len;
    let key_len = method.key_len();
    let mut salt = vec![0u8; key_len];
    read_exact(reader, &mut salt).ok()?;
    if salt_seen(&salt) {
        return None;
    }
    let mut recv = Cipher::from_psk(method, &psk, &salt)?;
    let (target, early) = open_handshake(reader, &mut recv)?;
    let mut uplink = TcpStream::connect_timeout(&target, Duration::from_secs(8)).ok()?;
    uplink.write_all(&early).ok()?;
    let server_salt = fresh_salt(key_len)?;
    let mut send = Cipher::from_psk(method, &psk, &server_salt)?;
    let mut fixed_resp = Vec::with_capacity(1 + 8 + key_len + 2);
    fixed_resp.push(1);
    fixed_resp.extend_from_slice(&now_secs().to_be_bytes());
    fixed_resp.extend_from_slice(&salt);
    fixed_resp.extend_from_slice(&0u16.to_be_bytes());
    let mut out = Vec::with_capacity(server_salt.len() + fixed_resp.len() + TAG_LEN);
    out.extend_from_slice(&server_salt);
    send.seal_into(&fixed_resp, &mut out)?;
    writer.write_all(&out).ok()?;
    Some((uplink, send, Recv::Ready(recv)))
}

fn open_handshake(reader: &mut dyn Read, recv: &mut Cipher) -> Option<(SocketAddr, Vec<u8>)> {
    let mut fixed = vec![0u8; 11 + TAG_LEN];
    read_exact(reader, &mut fixed).ok()?;
    let len = recv.open_in_place(&mut fixed)?;
    if len != 11 || fixed[0] != 0 {
        return None;
    }
    let stamp = u64::from_be_bytes(fixed[1..9].try_into().ok()?);
    if now_secs().abs_diff(stamp) > SKEW {
        return None;
    }
    let var_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
    if var_len == 0 || var_len > 2048 {
        return None;
    }
    let mut variable = vec![0u8; var_len + TAG_LEN];
    read_exact(reader, &mut variable).ok()?;
    recv.open_in_place(&mut variable)?;
    variable.truncate(var_len);
    let (target, used) = parse_addr_header(&variable)?;
    if variable.len() < used + 2 {
        return None;
    }
    let pad = usize::from(u16::from_be_bytes([variable[used], variable[used + 1]]));
    let at = used + 2 + pad;
    if at > variable.len() || (pad == 0 && at == variable.len()) {
        return None;
    }
    Some((target, variable[at..].to_vec()))
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
        let _ = closer.shutdown(std::net::Shutdown::Both);
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
        let _ = closer.shutdown(std::net::Shutdown::Both);
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

pub(crate) fn client_send_handshake(
    uplink: &mut dyn Write,
    password: &str,
    method: &str,
    target: &SocketAddr,
) -> Option<(Cipher, Recv)> {
    let method = Method::parse(method)?;
    let list = psks(password, method)?;
    let final_psk = list.last()?.clone();
    let key_len = method.key_len();
    let salt = fresh_salt(key_len)?;
    uplink.write_all(&salt).ok()?;
    if list.len() > 1 {
        if method.is_chacha() {
            return None;
        }
        for i in 0..list.len() - 1 {
            let eih = shadowsocks2022::encrypt_eih(method, &list[i], &salt, &list[i + 1])?;
            uplink.write_all(&eih).ok()?;
        }
    }
    let mut send = Cipher::from_psk(method, &final_psk, &salt)?;
    let mut addr = Vec::with_capacity(20);
    push_addr(&mut addr, target, 4);
    addr.extend_from_slice(&target.port().to_be_bytes());
    let pad_len = padding_for(0);
    let mut variable = Vec::with_capacity(addr.len() + 2 + pad_len);
    variable.extend_from_slice(&addr);
    variable.extend_from_slice(&(pad_len as u16).to_be_bytes());
    variable.resize(variable.len() + pad_len, 0);
    let mut fixed = Vec::with_capacity(11);
    fixed.push(0);
    fixed.extend_from_slice(&now_secs().to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
    let mut staging = Vec::with_capacity(salt.len() + fixed.len() + variable.len() + 2 * TAG_LEN);
    send.seal_into(&fixed, &mut staging)?;
    send.seal_into(&variable, &mut staging)?;
    uplink.write_all(&staging).ok()?;
    Some((send, Recv::Waiting(method, final_psk, salt)))
}

pub(crate) enum Recv {
    Ready(Cipher),
    Waiting(Method, Vec<u8>, Vec<u8>),
}

pub(crate) fn pump_relay(plain: &TcpStream, sealed: &TcpStream, send: Cipher, recv: Recv) {
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
        let _ = closer.shutdown(std::net::Shutdown::Both);
    });
    pump_relay_carried(plain, sealed_read, sealed_write, &close, send, recv);
}

pub(crate) fn pump_relay_carried<R, W>(
    plain: &TcpStream,
    mut reader: R,
    mut writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    send: Cipher,
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
        let mut buf = crate::proxy::RelayBuf::with_len(SEAL_HEAD + READ_CHUNK + TAG_LEN);
        while let Ok(read) = plain_read.read(&mut buf.as_mut()[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]) {
            if read == 0 {
                break;
            }
            if seal_all(&mut send, buf.as_mut(), read, &mut writer).is_err() {
                break;
            }
        }
        thread_close();
        let _ = plain_read.shutdown(std::net::Shutdown::Both);
    });
    let mut recv = match recv {
        Recv::Ready(cipher) => cipher,
        Recv::Waiting(method, psk, client_salt) => {
            let key_len = method.key_len();
            let mut server_salt = vec![0u8; key_len];
            if read_exact(&mut reader, &mut server_salt).is_err() {
                return;
            }
            let Some(mut cipher) = Cipher::from_psk(method, &psk, &server_salt) else {
                return;
            };
            let fixed_len = 1 + 8 + key_len + 2 + TAG_LEN;
            let mut fixed = vec![0u8; fixed_len];
            if read_exact(&mut reader, &mut fixed).is_err() {
                return;
            }
            let Some(len) = cipher.open_in_place(&mut fixed) else {
                return;
            };
            if len != 1 + 8 + key_len + 2 || fixed[0] != 1 {
                return;
            }
            let stamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap_or([0u8; 8]));
            if now_secs().abs_diff(stamp) > SKEW {
                return;
            }
            if fixed[9..9 + key_len] != client_salt[..] {
                return;
            }
            let first = usize::from(u16::from_be_bytes([
                fixed[9 + key_len],
                fixed[10 + key_len],
            ]));
            if first > 0 {
                let mut chunk = vec![0u8; first + TAG_LEN];
                if read_exact(&mut reader, &mut chunk).is_err() {
                    return;
                }
                let Some(got) = cipher.open_in_place(&mut chunk) else {
                    return;
                };
                if plain_write.write_all(&chunk[..got]).is_err() {
                    return;
                }
            }
            cipher
        }
    };
    let mut chunk = wire_buffer();
    while let Some(payload) = open_chunk(&mut reader, &mut recv, &mut chunk) {
        if plain_write.write_all(payload).is_err() {
            break;
        }
    }
    close();
    let _ = plain_write.shutdown(std::net::Shutdown::Both);
    let _ = done.join();
}

pub(crate) const WIRE_MAX: usize = MAX_CHUNK + TAG_LEN;

pub(crate) fn wire_buffer() -> Vec<u8> {
    crate::proxy::RelayBuf::with_len(WIRE_MAX).into_vec()
}

/// Seal `n` payload bytes at `buf[SEAL_HEAD..]` and hand seals and payload to `out` in one write: a payload byte is never copied in user space, and one call seals one chunk because `READ_CHUNK` is a quarter of `MAX_CHUNK` — a relay read is already one chunk, and oversize input is refused loudly rather than corrupted.
fn seal_all(
    send: &mut Cipher,
    buf: &mut [u8],
    n: usize,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    if n > MAX_CHUNK {
        return Err(invalid());
    }
    debug_assert!(buf.len() >= SEAL_HEAD + n + TAG_LEN);
    let end = SEAL_HEAD + n;
    let mut length = (n as u16).to_be_bytes();
    let length_tag = send.seal_piece_in_place(&mut length).ok_or_else(invalid)?;
    let tag = send
        .seal_piece_in_place(&mut buf[SEAL_HEAD..end])
        .ok_or_else(invalid)?;
    buf[..LENGTH_LEN].copy_from_slice(&length);
    buf[LENGTH_LEN..SEAL_HEAD].copy_from_slice(&length_tag);
    buf[end..end + TAG_LEN].copy_from_slice(&tag);
    out.write_all(&buf[..end + TAG_LEN])
}

fn open_chunk<'a>(
    stream: &mut dyn Read,
    recv: &mut Cipher,
    chunk: &'a mut [u8],
) -> Option<&'a [u8]> {
    let mut length = [0u8; 2 + TAG_LEN];
    read_exact(stream, &mut length).ok()?;
    if recv.open_in_place(&mut length)? != 2 {
        return None;
    }
    let size = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if size == 0 || size > MAX_CHUNK || size + TAG_LEN > chunk.len() {
        return None;
    }
    let wire = &mut chunk[..size + TAG_LEN];
    read_exact(stream, wire).ok()?;
    let plain = recv.open_in_place(wire)?;
    Some(&wire[..plain])
}

struct ServerUdp {
    window: shadowsocks2022::SlidingWindow,
    cipher: Option<Cipher>,
    user: Option<usize>,
    server_session: u64,
    server_packet: u64,
    server_cipher: Option<Cipher>,
}

struct PeerServer {
    window: shadowsocks2022::SlidingWindow,
    cipher: Option<Cipher>,
    last_seen: u64,
}

pub(crate) struct Datagrams {
    sealed: Vec<u8>,
    opened: Vec<u8>,
    session: u64,
    packet: u64,
    sessions: HashMap<u64, ServerUdp>,
    peers: HashMap<u64, PeerServer>,
    client_body: Option<Cipher>,
    client_psk: Vec<u8>,
    client_session: [u8; 8],
}

impl Datagrams {
    pub(crate) fn new() -> Self {
        let mut session = [0u8; 8];
        let _ = getrandom::getrandom(&mut session);
        Self {
            sealed: Vec::new(),
            opened: Vec::new(),
            session: u64::from_be_bytes(session),
            packet: 0,
            sessions: HashMap::new(),
            peers: HashMap::new(),
            client_body: None,
            client_psk: Vec::new(),
            client_session: [0u8; 8],
        }
    }
    pub(crate) fn seal(
        &mut self,
        psk: &[u8],
        method: Method,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        let key_len = method.key_len();
        if psk.len() != key_len {
            return None;
        }
        if method.is_chacha() {
            let mut nonce = [0u8; 24];
            getrandom::getrandom(&mut nonce).ok()?;
            let out = &mut self.sealed;
            out.clear();
            out.reserve(24 + 16 + 11 + payload.len() + TAG_LEN);
            out.extend_from_slice(&nonce);
            let at = out.len();
            out.extend_from_slice(&self.session.to_be_bytes());
            out.extend_from_slice(&self.packet.to_be_bytes());
            self.packet = self.packet.wrapping_add(1);
            out.push(0);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            shadowsocks2022::x_seal_tail(psk, &nonce, out, at)?;
            Some(out)
        } else {
            let mut raw = [0u8; BLOCK_LEN];
            raw[..8].copy_from_slice(&self.session.to_be_bytes());
            raw[8..].copy_from_slice(&self.packet.to_be_bytes());
            self.packet = self.packet.wrapping_add(1);
            let enc = shadowsocks2022::block_encrypt(psk, &raw)?;
            let session = self.session.to_be_bytes();
            let fresh = self.client_body.is_none()
                || self.client_psk != psk
                || self.client_session != session;
            if fresh {
                let sub = shadowsocks2022::session_subkey(psk, &session, key_len);
                let cipher = Cipher::from_subkey(method, &sub)?;
                self.client_body = Some(cipher);
                self.client_psk = psk.to_vec();
                self.client_session = session;
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            let (out, body_key) = (&mut self.sealed, self.client_body.as_ref()?);
            out.clear();
            out.reserve(16 + 11 + payload.len() + TAG_LEN);
            out.extend_from_slice(&enc);
            let at = out.len();
            out.push(0);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            body_key.seal_tail_with_nonce(&nonce, out, at)?;
            Some(out)
        }
    }
    pub(crate) fn seal_list(
        &mut self,
        method: Method,
        psks: &[Vec<u8>],
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        let final_psk = psks.last()?;
        if method.is_chacha() || psks.len() < 2 {
            return None;
        }
        let key_len = method.key_len();
        if psks.iter().any(|p| p.len() != key_len) {
            return None;
        }
        let mut raw = [0u8; BLOCK_LEN];
        raw[..8].copy_from_slice(&self.session.to_be_bytes());
        raw[8..].copy_from_slice(&self.packet.to_be_bytes());
        self.packet = self.packet.wrapping_add(1);
        let session = self.session.to_be_bytes();
        let fresh = self.client_body.is_none()
            || self.client_psk != final_psk.as_slice()
            || self.client_session != session;
        if fresh {
            let sub = shadowsocks2022::session_subkey(final_psk, &session, key_len);
            let cipher = Cipher::from_subkey(method, &sub)?;
            self.client_body = Some(cipher);
            self.client_psk.clone_from(final_psk);
            self.client_session = session;
        }
        let enc = shadowsocks2022::block_encrypt(&psks[0], &raw)?;
        let (out, body_key) = (&mut self.sealed, self.client_body.as_ref()?);
        out.clear();
        out.reserve((1 + psks.len()) * BLOCK_LEN + 11 + payload.len() + TAG_LEN);
        out.extend_from_slice(&enc);
        for pair in psks.windows(2) {
            let hash = shadowsocks2022::user_hash(&pair[1]);
            let eih = shadowsocks2022::encrypt_udp_eih(&pair[0], &raw, &hash)?;
            out.extend_from_slice(&eih);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&raw[4..16]);
        let at = out.len();
        out.push(0);
        out.extend_from_slice(&now_secs().to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        push_addr(out, dest, 4);
        out.extend_from_slice(&dest.port().to_be_bytes());
        out.extend_from_slice(payload);
        body_key.seal_tail_with_nonce(&nonce, out, at)?;
        Some(out)
    }
    pub(crate) fn open(
        &mut self,
        psk: &[u8],
        method: Method,
        packet: &[u8],
    ) -> Option<(SocketAddr, &[u8], u64)> {
        if method.is_chacha() {
            if psk.len() != 32 || packet.len() < 24 + TAG_LEN {
                return None;
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&packet[..24]);
            let sealed = &mut self.opened;
            sealed.clear();
            sealed.extend_from_slice(&packet[24..]);
            let len = shadowsocks2022::x_open(psk, &nonce, sealed)?;
            sealed.truncate(len);
            if sealed.len() < 16 + 11 {
                return None;
            }
            let session = u64::from_be_bytes(sealed[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(sealed[8..16].try_into().ok()?);
            let entry = self.sessions.entry(session).or_insert_with(|| ServerUdp {
                window: shadowsocks2022::SlidingWindow::new(),
                cipher: None,
                user: None,
                server_session: 0,
                server_packet: 0,
                server_cipher: None,
            });
            if !entry.window.check_and_add(packet_id) {
                return None;
            }
            let body = &sealed[16..];
            if body[0] != 0 {
                return None;
            }
            let stamp = u64::from_be_bytes(body[1..9].try_into().ok()?);
            if now_secs().abs_diff(stamp) > SKEW {
                return None;
            }
            let pad = usize::from(u16::from_be_bytes([body[9], body[10]]));
            if body.len() < 11 + pad {
                return None;
            }
            let (target, used) = parse_addr_header(&body[11 + pad..])?;
            Some((target, &sealed[16 + 11 + pad + used..], session))
        } else {
            let key_len = method.key_len();
            if psk.len() != key_len || packet.len() < 16 + TAG_LEN {
                return None;
            }
            let mut enc = [0u8; BLOCK_LEN];
            enc.copy_from_slice(&packet[..16]);
            let raw = shadowsocks2022::block_decrypt(psk, &enc)?;
            let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(raw[8..].try_into().ok()?);
            let entry = self.sessions.entry(session).or_insert_with(|| ServerUdp {
                window: shadowsocks2022::SlidingWindow::new(),
                cipher: None,
                user: None,
                server_session: 0,
                server_packet: 0,
                server_cipher: None,
            });
            if !entry.window.check_and_add(packet_id) {
                return None;
            }
            if entry.cipher.is_none() {
                let sub = shadowsocks2022::session_subkey(psk, &raw[..8], key_len);
                entry.cipher = Cipher::from_subkey(method, &sub);
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            let (opened, entry) = (&mut self.opened, self.sessions.get(&session)?);
            let cipher = entry.cipher.as_ref()?;
            let (target, payload_len) = open_body_into(cipher, &nonce, &packet[16..], opened)?;
            Some((target, &opened[..payload_len], session))
        }
    }
    pub(crate) fn open_multi(
        &mut self,
        method: Method,
        psks: &[Vec<u8>],
        packet: &[u8],
    ) -> Option<(SocketAddr, &[u8], usize, u64)> {
        if method.is_chacha() || psks.len() < 2 {
            return None;
        }
        let key_len = method.key_len();
        if psks.iter().any(|p| p.len() != key_len) || packet.len() < 32 + TAG_LEN {
            return None;
        }
        let mut enc = [0u8; BLOCK_LEN];
        enc.copy_from_slice(&packet[..16]);
        let raw = shadowsocks2022::block_decrypt(&psks[0], &enc)?;
        let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
        let packet_id = u64::from_be_bytes(raw[8..].try_into().ok()?);
        let entry = self.sessions.entry(session).or_insert_with(|| ServerUdp {
            window: shadowsocks2022::SlidingWindow::new(),
            cipher: None,
            user: None,
            server_session: 0,
            server_packet: 0,
            server_cipher: None,
        });
        if !entry.window.check_and_add(packet_id) {
            return None;
        }
        if entry.user.is_none() {
            let mut eih = [0u8; BLOCK_LEN];
            eih.copy_from_slice(&packet[16..32]);
            let hash = shadowsocks2022::decrypt_udp_eih(&psks[0], &raw, &eih)?;
            let idx = psks[1..]
                .iter()
                .position(|p| shadowsocks2022::user_hash(p) == hash)?
                + 1;
            let sub = shadowsocks2022::session_subkey(&psks[idx], &raw[..8], key_len);
            entry.cipher = Cipher::from_subkey(method, &sub);
            entry.user = Some(idx);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&raw[4..16]);
        let idx = entry.user?;
        let (opened, entry) = (&mut self.opened, self.sessions.get(&session)?);
        let cipher = entry.cipher.as_ref()?;
        let (target, payload_len) = open_body_into(cipher, &nonce, &packet[32..], opened)?;
        Some((target, &opened[..payload_len], idx, session))
    }
    pub(crate) fn seal_server(
        &mut self,
        method: Method,
        user_psk: &[u8],
        client_session: u64,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        if user_psk.len() != method.key_len() {
            return None;
        }
        let fresh = self.sessions.get(&client_session).is_none_or(|e| {
            e.server_session == 0 || (!method.is_chacha() && e.server_cipher.is_none())
        });
        if fresh {
            let mut sid = [0u8; 8];
            getrandom::getrandom(&mut sid).ok()?;
            let sid = u64::from_be_bytes(sid);
            if sid == 0 {
                return None;
            }
            let entry = self
                .sessions
                .entry(client_session)
                .or_insert_with(|| ServerUdp {
                    window: shadowsocks2022::SlidingWindow::new(),
                    cipher: None,
                    user: None,
                    server_session: 0,
                    server_packet: 0,
                    server_cipher: None,
                });
            entry.server_session = sid;
            if !method.is_chacha() {
                let sub =
                    shadowsocks2022::session_subkey(user_psk, &sid.to_be_bytes(), method.key_len());
                entry.server_cipher = Cipher::from_subkey(method, &sub);
            }
        }
        if method.is_chacha() {
            let (server_session, server_packet) = {
                let entry = self.sessions.get_mut(&client_session)?;
                let id = entry.server_packet;
                entry.server_packet = entry.server_packet.wrapping_add(1);
                (entry.server_session, id)
            };
            let mut nonce = [0u8; 24];
            getrandom::getrandom(&mut nonce).ok()?;
            let out = &mut self.sealed;
            out.clear();
            out.reserve(24 + 16 + 19 + payload.len() + TAG_LEN);
            out.extend_from_slice(&nonce);
            let at = out.len();
            out.extend_from_slice(&server_session.to_be_bytes());
            out.extend_from_slice(&server_packet.to_be_bytes());
            out.push(1);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&client_session.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            shadowsocks2022::x_seal_tail(user_psk, &nonce, out, at)?;
            Some(out)
        } else {
            let (server_session, server_packet) = {
                let entry = self.sessions.get_mut(&client_session)?;
                let id = entry.server_packet;
                entry.server_packet = entry.server_packet.wrapping_add(1);
                (entry.server_session, id)
            };
            let mut raw = [0u8; BLOCK_LEN];
            raw[..8].copy_from_slice(&server_session.to_be_bytes());
            raw[8..].copy_from_slice(&server_packet.to_be_bytes());
            let enc = shadowsocks2022::block_encrypt(user_psk, &raw)?;
            let (out, sessions) = (&mut self.sealed, &self.sessions);
            let cipher = sessions.get(&client_session)?.server_cipher.as_ref()?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            out.clear();
            out.reserve(16 + 19 + payload.len() + TAG_LEN);
            out.extend_from_slice(&enc);
            let at = out.len();
            out.push(1);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&client_session.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            cipher.seal_tail_with_nonce(&nonce, out, at)?;
            Some(out)
        }
    }
    pub(crate) fn open_server(
        &mut self,
        psk: &[u8],
        method: Method,
        packet: &[u8],
    ) -> Option<(SocketAddr, &[u8])> {
        let now = now_secs();
        if method.is_chacha() {
            if psk.len() != 32 || packet.len() < 24 + TAG_LEN {
                return None;
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&packet[..24]);
            let sealed = &mut self.opened;
            sealed.clear();
            sealed.extend_from_slice(&packet[24..]);
            let len = shadowsocks2022::x_open(psk, &nonce, sealed)?;
            sealed.truncate(len);
            if sealed.len() < 16 + 19 {
                return None;
            }
            let session = u64::from_be_bytes(sealed[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(sealed[8..16].try_into().ok()?);
            if !peer_check(&mut self.peers, session, packet_id, now) {
                return None;
            }
            let body = &sealed[16..];
            if body[0] != 1 {
                return None;
            }
            if now.abs_diff(u64::from_be_bytes(body[1..9].try_into().ok()?)) > SKEW {
                return None;
            }
            if u64::from_be_bytes(body[9..17].try_into().ok()?) != self.session {
                return None;
            }
            let pad = usize::from(u16::from_be_bytes([body[17], body[18]]));
            if body.len() < 19 + pad {
                return None;
            }
            let (target, used) = parse_addr_header(&body[19 + pad..])?;
            Some((target, &sealed[16 + 19 + pad + used..]))
        } else {
            let key_len = method.key_len();
            if psk.len() != key_len || packet.len() < 16 + TAG_LEN {
                return None;
            }
            let mut enc = [0u8; BLOCK_LEN];
            enc.copy_from_slice(&packet[..16]);
            let raw = shadowsocks2022::block_decrypt(psk, &enc)?;
            let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(raw[8..].try_into().ok()?);
            if !peer_check(&mut self.peers, session, packet_id, now) {
                return None;
            }
            if self
                .peers
                .get(&session)
                .is_none_or(|peer| peer.cipher.is_none())
            {
                let sub = shadowsocks2022::session_subkey(psk, &raw[..8], key_len);
                let cipher = Cipher::from_subkey(method, &sub)?;
                self.peers.get_mut(&session)?.cipher = Some(cipher);
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            let (opened, peers) = (&mut self.opened, &self.peers);
            let cipher = peers.get(&session)?.cipher.as_ref()?;
            opened.clear();
            opened.extend_from_slice(&packet[16..]);
            let mut tmp = std::mem::take(opened);
            let len = cipher.open_with_nonce(&nonce, &mut tmp)?;
            tmp.truncate(len);
            *opened = tmp;
            if opened.len() < 19 || opened[0] != 1 {
                return None;
            }
            if now.abs_diff(u64::from_be_bytes(opened[1..9].try_into().ok()?)) > SKEW {
                return None;
            }
            if u64::from_be_bytes(opened[9..17].try_into().ok()?) != self.session {
                return None;
            }
            let pad = usize::from(u16::from_be_bytes([opened[17], opened[18]]));
            if opened.len() < 19 + pad {
                return None;
            }
            let (target, used) = parse_addr_header(&opened[19 + pad..])?;
            let total = 19 + pad + used;
            if opened.len() < total {
                return None;
            }
            let payload_len = opened.len() - total;
            opened.copy_within(total.., 0);
            opened.truncate(payload_len);
            let len = opened.len();
            Some((target, &opened[..len]))
        }
    }
}

fn peer_check(
    peers: &mut HashMap<u64, PeerServer>,
    session: u64,
    packet_id: u64,
    now: u64,
) -> bool {
    if let Some(peer) = peers.get_mut(&session) {
        peer.last_seen = now;
        return peer.window.check_and_add(packet_id);
    }
    peers.retain(|_, peer: &mut PeerServer| now.wrapping_sub(peer.last_seen) < 60);
    if peers
        .values()
        .any(|peer| now.wrapping_sub(peer.last_seen) < 60)
    {
        return false;
    }
    if peers.len() >= 8 {
        return false;
    }
    let mut peer = PeerServer {
        window: shadowsocks2022::SlidingWindow::new(),
        cipher: None,
        last_seen: now,
    };
    if !peer.window.check_and_add(packet_id) {
        return false;
    }
    peers.insert(session, peer);
    true
}

fn open_body_into(
    cipher: &Cipher,
    nonce: &[u8; 12],
    packet_body: &[u8],
    opened: &mut Vec<u8>,
) -> Option<(SocketAddr, usize)> {
    opened.clear();
    opened.extend_from_slice(packet_body);
    let mut tmp = std::mem::take(opened);
    let len = cipher.open_with_nonce(nonce, &mut tmp)?;
    tmp.truncate(len);
    *opened = tmp;
    if opened.len() < 11 || opened[0] != 0 {
        return None;
    }
    let stamp = u64::from_be_bytes(opened[1..9].try_into().ok()?);
    if now_secs().abs_diff(stamp) > SKEW {
        return None;
    }
    let pad = usize::from(u16::from_be_bytes([opened[9], opened[10]]));
    if opened.len() < 11 + pad {
        return None;
    }
    let (target, used) = parse_addr_header(&opened[11 + pad..])?;
    let total = 11 + pad + used;
    if opened.len() < total {
        return None;
    }
    let payload_len = opened.len() - total;
    opened.copy_within(total.., 0);
    opened.truncate(payload_len);
    Some((target, payload_len))
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

pub(crate) fn serve_udp(address: &str, password: &str, method: &str, freedom: bool) {
    let Ok(clients) = UdpSocket::bind(address) else {
        return;
    };
    serve_udp_on(&clients, password, method, freedom);
}

pub(crate) fn relay_udp_forward(
    relay_psk: &[u8],
    dests: &[(Vec<u8>, SocketAddr)],
    packet: &[u8],
) -> Option<(Vec<u8>, SocketAddr, u64)> {
    if packet.len() < 32 + TAG_LEN {
        return None;
    }
    let mut enc = [0u8; BLOCK_LEN];
    enc.copy_from_slice(&packet[..16]);
    let raw = shadowsocks2022::block_decrypt(relay_psk, &enc)?;
    let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
    let mut eih = [0u8; BLOCK_LEN];
    eih.copy_from_slice(&packet[16..32]);
    let hash = shadowsocks2022::decrypt_udp_eih(relay_psk, &raw, &eih)?;
    let (dest_psk, dest) = dests
        .iter()
        .find(|(k, _)| shadowsocks2022::user_hash(k) == hash)?;
    let re_enc = shadowsocks2022::block_encrypt(dest_psk, &raw)?;
    let mut out = Vec::with_capacity(16 + packet.len() - 32);
    out.extend_from_slice(&re_enc);
    out.extend_from_slice(&packet[32..]);
    Some((out, *dest, session))
}

pub(crate) fn relay_udp_client_of(dest_psk: &[u8], packet: &[u8]) -> Option<u64> {
    if packet.len() < 16 + 19 + TAG_LEN {
        return None;
    }
    let mut enc = [0u8; BLOCK_LEN];
    enc.copy_from_slice(&packet[..16]);
    let raw = shadowsocks2022::block_decrypt(dest_psk, &enc)?;
    let sub = shadowsocks2022::session_subkey(dest_psk, &raw[..8], dest_psk.len());
    let cipher = Cipher::from_subkey(
        if dest_psk.len() == 16 {
            Method::Aes128Gcm
        } else {
            Method::Aes256Gcm
        },
        &sub,
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw[4..16]);
    let mut body = packet[16..].to_vec();
    let len = cipher.open_with_nonce(&nonce, &mut body)?;
    body.truncate(len);
    if body.len() < 19 || body[0] != 1 {
        return None;
    }
    if now_secs().abs_diff(u64::from_be_bytes(body[1..9].try_into().ok()?)) > SKEW {
        return None;
    }
    Some(u64::from_be_bytes(body[9..17].try_into().ok()?))
}

pub(crate) fn serve_udp_relay(
    clients: &UdpSocket,
    method: Method,
    relay_psk: &[u8],
    dests: &[(Vec<u8>, SocketAddr)],
) {
    if method.is_chacha() || relay_psk.len() != method.key_len() {
        return;
    }
    let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    if upstream.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    if clients.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    let mut by_addr: HashMap<SocketAddr, usize> = HashMap::new();
    for (idx, (_, addr)) in dests.iter().enumerate() {
        by_addr.insert(*addr, idx);
    }
    let mut client_of: HashMap<u64, SocketAddr> = HashMap::new();
    let mut buf = crate::proxy::udp_buffer();
    loop {
        match clients.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some((forwarded, dest, session)) =
                    relay_udp_forward(relay_psk, dests, &buf[..n])
                {
                    if client_of.len() >= 4096 {
                        client_of.clear();
                    }
                    client_of.insert(session, src);
                    let _ = upstream.send_to(&forwarded, dest);
                }
            }
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => break,
        }
        while let Ok((n, from)) = upstream.recv_from(&mut buf) {
            let Some(idx) = by_addr.get(&from).copied() else {
                continue;
            };
            let Some((dest_psk, _)) = dests.get(idx) else {
                continue;
            };
            if let Some(session) = relay_udp_client_of(dest_psk, &buf[..n]) {
                if let Some(client) = client_of.get(&session) {
                    let _ = clients.send_to(&buf[..n], client);
                }
            }
        }
    }
}

pub(crate) fn serve_udp_on(clients: &UdpSocket, password: &str, method: &str, freedom: bool) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    let Some(list) = psks(password, method) else {
        return;
    };
    if list.is_empty() {
        return;
    }
    if method.is_chacha() && list.len() > 1 {
        return;
    }
    let multi = !method.is_chacha() && list.len() > 1;
    let psk = list.last().expect("non-empty").clone();
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
    let mut users: HashMap<SocketAddr, usize> = HashMap::new();
    let mut sessions: HashMap<SocketAddr, u64> = HashMap::new();
    let mut buf = crate::proxy::udp_buffer();
    let mut reply = crate::proxy::udp_buffer();
    let mut datagrams = Datagrams::new();
    loop {
        match clients.recv_from(&mut buf) {
            Ok((n, src)) => {
                if multi {
                    if let Some((dest, payload, idx, session)) =
                        datagrams.open_multi(method, &list, &buf[..n])
                    {
                        if table.len() >= 4096 {
                            table.clear();
                            users.clear();
                            sessions.clear();
                        }
                        table.insert(dest, src);
                        users.insert(src, idx);
                        sessions.insert(src, session);
                        if dest.is_ipv6() {
                            if let Some(sock) = &upstream6 {
                                let _ = sock.send_to(payload, dest);
                            }
                        } else {
                            let _ = upstream.send_to(payload, dest);
                        }
                    }
                } else if let Some((dest, payload, session)) =
                    datagrams.open(&psk, method, &buf[..n])
                {
                    if table.len() >= 4096 {
                        table.clear();
                        sessions.clear();
                    }
                    table.insert(dest, src);
                    sessions.insert(src, session);
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
                let state = UdpAnswer {
                    method,
                    list: &list,
                    psk: &psk,
                    multi,
                    table: &table,
                    users: &users,
                    sessions: &sessions,
                };
                answer_udp(clients, &mut datagrams, &state, &reply[..n], src);
            }
        }
    }
}

struct UdpAnswer<'a> {
    method: Method,
    list: &'a [Vec<u8>],
    psk: &'a [u8],
    multi: bool,
    table: &'a HashMap<SocketAddr, SocketAddr>,
    users: &'a HashMap<SocketAddr, usize>,
    sessions: &'a HashMap<SocketAddr, u64>,
}

fn answer_udp(
    clients: &UdpSocket,
    datagrams: &mut Datagrams,
    state: &UdpAnswer<'_>,
    reply: &[u8],
    src: SocketAddr,
) {
    let Some(client) = state.table.get(&src).copied() else {
        return;
    };
    let Some(session) = state.sessions.get(&client).copied() else {
        return;
    };
    let user = if state.multi {
        let idx = state
            .users
            .get(&client)
            .copied()
            .unwrap_or(state.list.len() - 1);
        state.list.get(idx).map(Vec::as_slice)
    } else {
        Some(state.psk)
    };
    let Some(user) = user else {
        return;
    };
    if user.len() != state.method.key_len() {
        return;
    }
    if let Some(packet) = datagrams.seal_server(state.method, user, session, &src, reply) {
        let _ = clients.send_to(packet, client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk_b64(key_len: usize) -> String {
        ferrox_core::b64::encode(&vec![0x42u8; key_len])
    }

    #[test]
    fn a_silent_peer_cannot_pin_a_single_psk_shadowsocks2022_handshake() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let psk = psk_b64(32);
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, &psk, "2022-blake3-aes-256-gcm", true);
            let _ = done_tx.send(());
        });
        let _peer = TcpStream::connect(addr).expect("connects");
        done_rx
            .recv_timeout(crate::budgets::HANDSHAKE_REQUEST_TIMEOUT + Duration::from_secs(5))
            .expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn a_silent_peer_cannot_pin_a_multi_psk_shadowsocks2022_handshake() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let password = format!("{}:{}", psk_b64(32), psk_b64(32));
        let serving = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, &password, "2022-blake3-aes-256-gcm", true);
            let _ = done_tx.send(());
        });
        let _peer = TcpStream::connect(addr).expect("connects");
        done_rx
            .recv_timeout(crate::budgets::HANDSHAKE_REQUEST_TIMEOUT + Duration::from_secs(5))
            .expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn every_named_method_relays_an_echo() {
        for (name, method) in [
            ("2022-blake3-aes-128-gcm", Method::Aes128Gcm),
            ("2022-blake3-aes-256-gcm", Method::Aes256Gcm),
            ("2022-blake3-chacha20-poly1305", Method::Chacha20Poly1305),
        ] {
            let psk = psk_b64(method.key_len());
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
            let announced = psk.clone();
            let named = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let announced = announced.clone();
                    let named = named.clone();
                    thread::spawn(move || {
                        serve(stream, &announced, &named, true);
                    });
                }
            });
            let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
            let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            let Some((mut send, recv)) = client_send_handshake(&mut uplink, &psk, name, &target)
            else {
                panic!("{name}: handshake refused");
            };
            assert_eq!(send.method(), method, "{name}");
            let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
            seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(m, p, s) => {
                    let mut peer = vec![0u8; m.key_len()];
                    read_exact(&mut uplink, &mut peer).expect("salt");
                    let mut cipher = Cipher::from_psk(m, &p, &peer).expect("derives");
                    let fixed_len = 1 + 8 + m.key_len() + 2 + TAG_LEN;
                    let mut fixed = vec![0u8; fixed_len];
                    read_exact(&mut uplink, &mut fixed).expect("fixed");
                    cipher.open_in_place(&mut fixed).expect("opens");
                    let _ = s;
                    cipher
                }
            };
            let mut buf = wire_buffer();
            let back = open_chunk(&mut uplink, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"ping"[..], "{name}");
        }
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
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
        let mut send = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut buf = crate::proxy::RelayBuf::with_len(SEAL_HEAD + READ_CHUNK + TAG_LEN);
        for (i, b) in buf.as_mut()[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 251) as u8;
        }
        let plain = buf.as_mut()[SEAL_HEAD..SEAL_HEAD + READ_CHUNK].to_vec();
        let base = buf.as_mut().as_ptr() as usize;
        let capacity = buf.capacity();
        let mut seen = Vec::new();
        let (writes, wrote_base) = {
            let mut out = Counting {
                seen: &mut seen,
                writes: 0,
                base: 0,
            };
            seal_all(&mut send, buf.as_mut(), READ_CHUNK, &mut out).expect("seals");
            (out.writes, out.base)
        };
        assert_eq!(writes, 1, "a relay read is sealed and written once");
        assert_eq!(
            wrote_base, base,
            "the write leaves from the caller's buffer, so no payload byte is copied"
        );
        assert_eq!(
            buf.as_mut().as_ptr() as usize,
            base,
            "the read buffer never moves"
        );
        assert_eq!(buf.capacity(), capacity, "the read buffer never grows");
        let mut cursor = std::io::Cursor::new(&seen);
        let mut wire = wire_buffer();
        let mut got = 0usize;
        let mut chunks = 0usize;
        let mut recv2 = Cipher::from_psk(method, &psk, &salt).expect("derives");
        while got < plain.len() {
            let back = open_chunk(&mut cursor, &mut recv2, &mut wire).expect("opens");
            assert_eq!(back, &plain[got..got + back.len()]);
            got += back.len();
            chunks += 1;
        }
        assert_eq!(got, plain.len());
        assert_eq!(chunks, 1, "a 16 KiB read is one 2022 chunk, not two");
    }

    #[test]
    fn chunks_open_that_seal_sealed_and_reject_damage() {
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
        let mut send = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut wire = Vec::new();
        let msg = b"length-is-framing";
        let mut plain_buf = vec![0u8; SEAL_HEAD + msg.len() + TAG_LEN];
        plain_buf[SEAL_HEAD..SEAL_HEAD + msg.len()].copy_from_slice(msg);
        seal_all(&mut send, &mut plain_buf, msg.len(), &mut wire).expect("seals");
        let mut recv = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&wire);
        let mut buf = wire_buffer();
        let back = open_chunk(&mut cursor, &mut recv, &mut buf).expect("opens");
        assert_eq!(back, &b"length-is-framing"[..]);
        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut damaged = std::io::Cursor::new(&tampered);
        let mut fresh = Cipher::from_psk(method, &psk, &salt).expect("derives");
        assert!(open_chunk(&mut damaged, &mut fresh, &mut wire_buffer()).is_none());
    }

    #[test]
    fn an_opened_payload_is_the_datagrams_own_bytes() {
        let method = Method::Aes256Gcm;
        let psk = vec![0x11u8; 32];
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut datagrams = Datagrams::new();
        datagrams.session = 0x0102_0304_0506_0708;
        datagrams.packet = 0;
        let warm = datagrams
            .seal(&psk, method, &target, b"a payload worth keeping")
            .expect("seals")
            .to_vec();
        datagrams
            .open(&psk, method, &warm)
            .expect("warms the buffer");
        let opened_at = datagrams.opened.as_ptr() as usize;
        let opened_room = datagrams.opened.capacity();
        for round in 0..8 {
            let packet = datagrams
                .seal(&psk, method, &target, b"a payload worth keeping")
                .expect("seals")
                .to_vec();
            let (got, payload, _) = datagrams.open(&psk, method, &packet).expect("opens");
            let _ = got;
            assert_eq!(payload, b"a payload worth keeping", "round {round}");
            let at = payload.as_ptr();
            assert!(
                datagrams.opened.as_ptr_range().contains(&at),
                "round {round}: payload is a separate buffer"
            );
            assert_eq!(
                datagrams.opened.as_ptr() as usize,
                opened_at,
                "round {round}: buffer moved"
            );
            assert_eq!(
                datagrams.opened.capacity(),
                opened_room,
                "round {round}: buffer grew"
            );
        }
    }

    #[test]
    fn eih_multi_user_hands_the_right_psk_to_the_session() {
        let method = Method::Aes128Gcm;
        let master = ferrox_core::b64::encode(&[0x11u8; 16]);
        let user = ferrox_core::b64::encode(&[0x22u8; 16]);
        let password = format!("{master}:{user}");
        let list = psks(&password, method).expect("lists");
        assert_eq!(list.len(), 2);
        let salt = vec![0x33u8; 16];
        let eih = shadowsocks2022::encrypt_eih(method, &list[0], &salt, &list[1]).expect("seals");
        let hash = shadowsocks2022::decrypt_eih(method, &list[0], &salt, &eih).expect("opens");
        assert_eq!(hash, shadowsocks2022::user_hash(&list[1]));
    }

    #[test]
    fn udp_multi_user_packs_one_eih_and_opens_with_the_pinned_psk() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let key_len = method.key_len();
            let master = vec![0x11u8; key_len];
            let user = vec![0x22u8; key_len];
            let list = vec![master, user];
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let mut client = Datagrams::new();
            client.session = 0x0a0b_0c0d_0e0f_1011;
            client.packet = 0;
            let packet = client
                .seal_list(method, &list, &target, b"multi-payload")
                .expect("seals")
                .to_vec();
            let single = client
                .seal(&list[1], method, &target, b"multi-payload")
                .expect("seals")
                .to_vec();
            assert_eq!(
                packet.len(),
                single.len() + BLOCK_LEN,
                "{method}: one EIH block rides beside the header"
            );
            let mut server = Datagrams::new();
            let (got, payload, idx, _) = server.open_multi(method, &list, &packet).expect("opens");
            assert_eq!(got, target);
            assert_eq!(idx, 1);
            assert_eq!(payload, b"multi-payload");
            assert!(server.open_multi(method, &list, &packet).is_none());
            assert!(client
                .seal_list(method, &list[..1], &target, b"x")
                .is_none());
            assert!(Datagrams::new()
                .open_multi(Method::Chacha20Poly1305, &list, &packet)
                .is_none());
        }
        assert!(
            Datagrams::new()
                .seal_list(
                    Method::Chacha20Poly1305,
                    &[vec![0u8; 32], vec![1u8; 32]],
                    &"127.0.0.1:53".parse().expect("addr"),
                    b"x",
                )
                .is_none(),
            "chacha multi-user stays refused"
        );
    }

    #[test]
    fn udp_server_replies_are_server_typed_and_stay_with_their_session() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let key_len = method.key_len();
            let psk = vec![0x33u8; key_len];
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let mut server = Datagrams::new();
            let client_session = 0x7172_7374_7576_7778;
            let packet = server
                .seal_server(method, &psk, client_session, &target, b"reply-payload")
                .expect("seals")
                .to_vec();
            let mut client = Datagrams::new();
            client.session = client_session;
            let (got, payload) = client.open_server(&psk, method, &packet).expect("opens");
            assert_eq!(got, target, "{method}");
            assert_eq!(payload, b"reply-payload", "{method}");
            let mut stranger = Datagrams::new();
            stranger.session = client_session ^ 1;
            assert!(
                stranger.open_server(&psk, method, &packet).is_none(),
                "{method}: a forged client session is refused"
            );
            let mut tampered = packet.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert!(
                Datagrams::new()
                    .open_server(&psk, method, &tampered)
                    .is_none(),
                "{method}: damage is refused"
            );
        }
    }

    #[test]
    fn udp_relay_strips_one_header_and_still_opens() {
        let method = Method::Aes256Gcm;
        let relay_psk = vec![0x44u8; 32];
        let dest_psk = vec![0x55u8; 32];
        let dest: SocketAddr = "127.0.0.1:8388".parse().expect("addr");
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let list = vec![relay_psk.clone(), dest_psk.clone()];
        let mut client = Datagrams::new();
        client.session = 0x1a1b_1c1d_1e1f_2021;
        client.packet = 0;
        let packet = client
            .seal_list(method, &list, &target, b"relay-payload")
            .expect("seals")
            .to_vec();
        let (forwarded, got, session) =
            relay_udp_forward(&relay_psk, &[(dest_psk.clone(), dest)], &packet).expect("relays");
        assert_eq!(got, dest);
        assert_eq!(forwarded.len(), packet.len() - BLOCK_LEN);
        let mut server = Datagrams::new();
        let (target_back, payload, _) = server.open(&dest_psk, method, &forwarded).expect("opens");
        assert_eq!(target_back, target);
        assert_eq!(payload, b"relay-payload");
        assert_eq!(session, 0x1a1b_1c1d_1e1f_2021);
        assert!(relay_udp_forward(&relay_psk, &[(dest_psk.clone(), dest)], &forwarded).is_none());
        let reply = server
            .seal_server(method, &dest_psk, session, &target, b"relay-reply")
            .expect("seals")
            .to_vec();
        assert_eq!(
            relay_udp_client_of(&dest_psk, &reply),
            Some(session),
            "the relay reads the client session out of the response"
        );
    }

    #[test]
    fn udp_relay_carries_an_echo_end_to_end() {
        let method = Method::Aes256Gcm;
        let relay_psk = vec![0x71u8; 32];
        let dest_psk = vec![0x72u8; 32];
        let dest_b64 = ferrox_core::b64::encode(&dest_psk);
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_addr = echo.local_addr().expect("addr");
        echo.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let dest_addr = dest_sock.local_addr().expect("addr");
        let relay_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let relay_addr = relay_sock.local_addr().expect("addr");
        let client_relay = relay_psk.clone();
        let client_dest = dest_psk.clone();
        thread::spawn(move || {
            let mut buf = vec![0u8; crate::proxy::UDP_BUF];
            while let Ok((n, src)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], src);
            }
        });
        thread::spawn(move || {
            serve_udp_on(&dest_sock, &dest_b64, "2022-blake3-aes-256-gcm", true);
        });
        thread::spawn(move || {
            serve_udp_relay(&relay_sock, method, &relay_psk, &[(dest_psk, dest_addr)]);
        });
        let client = UdpSocket::bind("127.0.0.1:0").expect("binds");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut datagrams = Datagrams::new();
        let list = vec![client_relay, client_dest.clone()];
        let packet = datagrams
            .seal_list(method, &list, &echo_addr, b"udp-relay-ping")
            .expect("seals")
            .to_vec();
        client.send_to(&packet, relay_addr).expect("sends");
        let mut buf = vec![0u8; crate::proxy::UDP_BUF];
        let (n, _) = client.recv_from(&mut buf).expect("receives");
        let (_, payload) = datagrams
            .open_server(&client_dest, method, &buf[..n])
            .expect("opens");
        assert_eq!(payload, b"udp-relay-ping");
    }

    #[test]
    fn tcp_relay_carries_an_echo_behind_one_eih() {
        let relay_psk = psk_b64(32);
        let dest_psk = ferrox_core::b64::encode(&[0x66u8; 32]);
        let password = format!("{relay_psk}:{dest_psk}");
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
        let dest = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let dest_port = dest.local_addr().expect("addr").port();
        let dest_psk_thread = dest_psk.clone();
        thread::spawn(move || {
            let (stream, _) = dest.accept().expect("accepts");
            serve(stream, &dest_psk_thread, "2022-blake3-aes-256-gcm", true);
        });
        let relay = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let relay_port = relay.local_addr().expect("addr").port();
        let relay_psk_thread = relay_psk.clone();
        let dest_addr: SocketAddr = format!("127.0.0.1:{dest_port}").parse().expect("addr");
        let dest_psk_raw = ferrox_core::b64::decode(dest_psk.as_bytes()).expect("decodes");
        thread::spawn(move || {
            let (stream, _) = relay.accept().expect("accepts");
            serve_relay(
                stream,
                "2022-blake3-aes-256-gcm",
                &ferrox_core::b64::decode(relay_psk_thread.as_bytes()).expect("decodes"),
                &[(dest_psk_raw, dest_addr)],
            );
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = TcpStream::connect(("127.0.0.1", relay_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let Some((mut send, recv)) =
            client_send_handshake(&mut uplink, &password, "2022-blake3-aes-256-gcm", &target)
        else {
            panic!("relay handshake refused");
        };
        let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
        ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
        seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
        let mut recv = match recv {
            Recv::Ready(cipher) => cipher,
            Recv::Waiting(m, p, s) => {
                let mut peer = vec![0u8; m.key_len()];
                read_exact(&mut uplink, &mut peer).expect("salt");
                let mut cipher = Cipher::from_psk(m, &p, &peer).expect("derives");
                let fixed_len = 1 + 8 + m.key_len() + 2 + TAG_LEN;
                let mut fixed = vec![0u8; fixed_len];
                read_exact(&mut uplink, &mut fixed).expect("fixed");
                cipher.open_in_place(&mut fixed).expect("opens");
                let _ = s;
                cipher
            }
        };
        let mut buf = wire_buffer();
        let back = open_chunk(&mut uplink, &mut recv, &mut buf).expect("opens");
        assert_eq!(back, &b"ping"[..]);
    }
}
