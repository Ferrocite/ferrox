//! The fronted-meek relay the native `Psiphon` lane rides when a server entry
//! carries a CDN front: a loopback TCP stream whose bytes are carried in
//! `POST /` requests to the fronting host.

use crate::psiphon_ssh::{derive_key, random, Proxy, Rc4, MAGIC, SEED_LENGTH};
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use ferrox_core::tls::{ClientSession, TlsConfig, TlsProvider as _};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

const MAX_PAYLOAD: usize = 64 * 1024;
const MIN_COOKIE_PADDING: usize = 16;
const MAX_COOKIE_PADDING: usize = 256;
const POLL: Duration = Duration::from_millis(100);
const MAX_POLL: Duration = Duration::from_secs(5);
const POLL_GROWTH: f64 = 1.5;
const COOKIE_PROTOCOL: &str = "FRONTED-MEEK-OSSH";
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";

/// One server entry's CDN front.
#[derive(Debug, Clone)]
pub(crate) struct Meek {
    pub(crate) dial: String,
    pub(crate) port: u16,
    pub(crate) host: String,
    pub(crate) sni: String,
    pub(crate) public_key: String,
    pub(crate) obfuscated_key: String,
}

/// Start the loopback relay and return the socket the SSH handshake rides.
pub(crate) fn connect(
    meek: &Meek,
    timeout: Duration,
    proxy: Option<&Proxy>,
) -> Result<TcpStream, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("psiphon meek listener: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("psiphon meek listener: {error}"))?;
    let local = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("psiphon meek loopback: {error}"))?;
    local
        .set_nodelay(true)
        .and_then(|()| local.set_read_timeout(Some(timeout)))
        .and_then(|()| local.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("psiphon meek loopback: {error}"))?;
    let config = meek.clone();
    let proxy = proxy.cloned();
    std::thread::Builder::new()
        .name("psiphon-meek".to_owned())
        .spawn(move || match listener.accept() {
            Ok((socket, _)) => {
                if let Err(why) = relay(socket, &config, proxy.as_ref(), timeout) {
                    eprintln!("psiphon: fronted-meek relay: {why}");
                }
            }
            Err(why) => eprintln!("psiphon: fronted-meek accept: {why}"),
        })
        .map_err(|error| format!("psiphon meek thread: {error}"))?;
    Ok(local)
}

fn relay(
    mut local: TcpStream,
    meek: &Meek,
    proxy: Option<&Proxy>,
    timeout: Duration,
) -> Result<(), String> {
    local
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("psiphon meek socket: {error}"))?;
    let mut http = MeekHttp::new(meek.clone(), proxy.cloned(), timeout)?;
    let mut buffer = vec![0u8; MAX_PAYLOAD];
    let mut interval = POLL;
    loop {
        local
            .set_read_timeout(Some(interval))
            .map_err(|error| format!("psiphon meek socket: {error}"))?;
        let body = match local.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => &buffer[..read],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                &[]
            }
            Err(error) => return Err(format!("psiphon meek read: {error}")),
        };
        let reply = http.round_trip(body)?;
        if body.is_empty() && reply.is_empty() {
            interval = interval.mul_f64(POLL_GROWTH).min(MAX_POLL);
        } else {
            interval = POLL;
        }
        if !reply.is_empty() {
            local
                .write_all(&reply)
                .map_err(|error| format!("psiphon meek write: {error}"))?;
        }
    }
    Ok(())
}

struct MeekHttp {
    meek: Meek,
    proxy: Option<Proxy>,
    timeout: Duration,
    tls: Option<ClientSession<TcpStream>>,
    cookie_name: String,
    cookie_value: String,
}

impl MeekHttp {
    fn new(meek: Meek, proxy: Option<Proxy>, timeout: Duration) -> Result<Self, String> {
        let (cookie_name, cookie_value) = make_cookie(&meek)?;
        Ok(Self {
            meek,
            proxy,
            timeout,
            tls: None,
            cookie_name,
            cookie_value,
        })
    }

    fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.tls.is_none() {
            self.open()?;
        }
        match self.exchange(body) {
            Ok(reply) => Ok(reply),
            Err(why) if body.is_empty() => {
                self.tls = None;
                self.open()?;
                self.exchange(body).map_err(|_| why)
            }
            Err(why) => {
                self.tls = None;
                Err(why)
            }
        }
    }

    fn open(&mut self) -> Result<(), String> {
        let address = (self.meek.dial.as_str(), self.meek.port)
            .to_socket_addrs()
            .map_err(|error| format!("psiphon meek resolve {}: {error}", self.meek.dial))?
            .next()
            .ok_or_else(|| format!("psiphon meek resolve {}: no address", self.meek.dial))?;
        let stream = match &self.proxy {
            Some(proxy) => proxy.connect(address, self.timeout)?,
            None => TcpStream::connect_timeout(&address, self.timeout)
                .map_err(|error| format!("psiphon meek connect {}: {error}", self.meek.dial))?,
        };
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|error| format!("psiphon meek socket: {error}"))?;
        // The SSH host key authenticates the payload; the fronting certificate is only cover.
        let config = TlsConfig {
            server_name: self.meek.sni.clone(),
            alpn: vec![b"http/1.1".to_vec()].into(),
            roots: crate::quic::system_roots(),
            insecure: true,
            resumption: true,
            ..TlsConfig::default()
        };
        let mut tls = ferrox_core::tls::connect(&config, stream)
            .map_err(|error| format!("psiphon meek tls {}: {error}", self.meek.sni))?;
        tls.handshake()
            .map_err(|error| format!("psiphon meek handshake {}: {error}", self.meek.sni))?;
        self.tls = Some(tls);
        Ok(())
    }

    fn peer_closed(&self) -> bool {
        let Some(tls) = self.tls.as_ref() else {
            return true;
        };
        if tls.closed() {
            return true;
        }
        let stream = tls.get_ref();
        if stream.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let closed = matches!(stream.peek(&mut byte), Ok(0));
        let _ = stream.set_nonblocking(false);
        closed
    }

    fn exchange(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.tls.is_none() {
            self.open()?;
        }
        if !body.is_empty() && self.peer_closed() {
            self.tls = None;
            self.open()?;
        }
        let cookie = format!("{}={}", self.cookie_name, self.cookie_value);
        let headers = [
            ("Content-Type", "application/octet-stream"),
            ("Cookie", cookie.as_str()),
            ("User-Agent", USER_AGENT),
            ("Accept", "*/*"),
            ("Connection", "keep-alive"),
        ];
        let request = crate::foxy_account::request("POST", &self.meek.host, "/", &headers, body);
        let tls = self
            .tls
            .as_mut()
            .ok_or_else(|| "psiphon meek has no connection".to_owned())?;
        tls.write_all(&request)
            .and_then(|()| tls.flush())
            .map_err(|error| format!("psiphon meek request: {error}"))?;
        let reply =
            crate::foxy_account::read_reply(tls).map_err(|_| "psiphon meek response".to_owned())?;
        if reply.status != 200 {
            return Err(format!("psiphon meek status {}", reply.status));
        }
        for (name, value) in &reply.headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let pair = value.split(';').next().unwrap_or(value);
            if let Some((name, value)) = pair.split_once('=') {
                if name.trim() == self.cookie_name {
                    value.trim().clone_into(&mut self.cookie_value);
                }
            }
        }
        if reply
            .header("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close"))
        {
            self.tls = None;
        }
        Ok(reply.body)
    }
}

fn make_cookie(meek: &Meek) -> Result<(String, String), String> {
    let key = ferrox_core::b64::decode(meek.public_key.as_bytes())
        .ok_or_else(|| "psiphon meek cookie key is not base64".to_owned())?;
    let key = PublicKey::from_slice(&key)
        .map_err(|_| "psiphon meek cookie key is not 32 bytes".to_owned())?;
    let mut rng = OsRng;
    let secret = SecretKey::generate(&mut rng);
    let ephemeral = secret.public_key();
    let boxed = SalsaBox::new(&key, &secret);
    let nonce = crypto_box::aead::Nonce::<SalsaBox>::from_slice(&[0u8; 24]);
    let plaintext = format!(r#"{{"v":4,"t":"{COOKIE_PROTOCOL}"}}"#);
    let sealed = boxed
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "psiphon meek cookie encryption".to_owned())?;
    let seed = random::<SEED_LENGTH>();
    let mut client = Rc4::new(&derive_key(
        &seed,
        meek.obfuscated_key.as_bytes(),
        b"client_to_server",
    ));
    let padding_len = MIN_COOKIE_PADDING
        + usize::from(u16::from_be_bytes(random::<2>()))
            % (MAX_COOKIE_PADDING - MIN_COOKIE_PADDING + 1);
    let mut value = Vec::with_capacity(SEED_LENGTH + 8 + padding_len + 32 + sealed.len());
    value.extend_from_slice(&seed);
    value.extend_from_slice(&MAGIC.to_be_bytes());
    value.extend_from_slice(&u32::try_from(padding_len).unwrap_or(0).to_be_bytes());
    let mut padding = vec![0u8; padding_len];
    getrandom::fill(&mut padding).map_err(|error| format!("psiphon meek entropy: {error}"))?;
    value.extend_from_slice(&padding);
    client.apply(&mut value[SEED_LENGTH..]);
    let seed_len = value.len();
    value.extend_from_slice(ephemeral.as_bytes());
    value.extend_from_slice(&sealed);
    client.apply(&mut value[seed_len..]);
    let name = char::from(b'A' + random::<1>()[0] % 26).to_string();
    Ok((name, ferrox_core::b64::encode(&value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Meek {
        Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "key".to_owned(),
        }
    }

    #[test]
    fn a_cookie_carries_a_seed_then_an_encrypted_payload() {
        let (name, value) = make_cookie(&entry()).expect("cookie");
        assert!(name.as_bytes()[0].is_ascii_uppercase());
        let bytes = ferrox_core::b64::decode(value.as_bytes()).expect("base64");
        assert!(bytes.len() > SEED_LENGTH + 8 + MIN_COOKIE_PADDING + 32);
    }

    #[test]
    fn the_cookie_name_is_one_letter() {
        let (name, _) = make_cookie(&entry()).expect("cookie");
        assert_eq!(name.len(), 1);
    }
}
