//! The meek relay the native `Psiphon` lane rides for unfronted and CDN-fronted
//! entries: a loopback TCP stream whose bytes are carried in `POST /` requests.

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
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";

/// One server entry's meek front.
#[derive(Debug, Clone)]
pub(crate) struct Meek {
    pub(crate) dial: String,
    pub(crate) port: u16,
    pub(crate) host: String,
    pub(crate) sni: String,
    pub(crate) public_key: String,
    pub(crate) obfuscated_key: String,
    pub(crate) disable_sni: bool,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) fronts: Vec<(String, u16)>,
    pub(crate) hosts: Vec<String>,
    pub(crate) https: bool,
    pub(crate) fronted: bool,
    pub(crate) protocol: &'static str,
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

/// A plain TCP or TLS stream carrying meek HTTP.
enum MeekStream {
    Plain(TcpStream),
    Tls(ClientSession<TcpStream>),
}

impl Read for MeekStream {
    /// Read from the plain or TLS stream.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for MeekStream {
    /// Write to the plain or TLS stream.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    /// Flush the plain or TLS stream.
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

impl MeekStream {
    /// Whether the peer closed the stream.
    fn peer_closed(&self) -> bool {
        let stream = match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) if stream.closed() => return true,
            Self::Tls(stream) => stream.get_ref(),
        };
        if stream.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let closed = matches!(stream.peek(&mut byte), Ok(0));
        let _ = stream.set_nonblocking(false);
        closed
    }
}

struct MeekHttp {
    meek: Meek,
    proxy: Option<Proxy>,
    timeout: Duration,
    stream: Option<MeekStream>,
    cookie_name: String,
    cookie_value: String,
    front_index: usize,
    alpn_warned: bool,
}

impl MeekHttp {
    /// Build a meek HTTP client from an entry and optional proxy.
    fn new(meek: Meek, proxy: Option<Proxy>, timeout: Duration) -> Result<Self, String> {
        let (cookie_name, cookie_value) = make_cookie(&meek)?;
        Ok(Self {
            meek,
            proxy,
            timeout,
            stream: None,
            cookie_name,
            cookie_value,
            front_index: 0,
            alpn_warned: false,
        })
    }

    /// Send one request body and return the response body.
    fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.stream.is_none() {
            self.open()?;
        }
        match self.exchange(body) {
            Ok(reply) => Ok(reply),
            Err(why) if body.is_empty() => {
                self.stream = None;
                self.open()?;
                self.exchange(body).map_err(|_| why)
            }
            Err(why) => {
                self.stream = None;
                Err(why)
            }
        }
    }

    /// Dial the next front and start a TLS session when required.
    fn open(&mut self) -> Result<(), String> {
        self.rotate_front();
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
        if !self.meek.https {
            self.stream = Some(MeekStream::Plain(stream));
            return Ok(());
        }
        // The SSH host key authenticates the payload; the fronting certificate is only cover.
        let server_name = if self.meek.disable_sni {
            address.ip().to_string()
        } else {
            self.meek.sni.clone()
        };
        let alpn =
            if self.meek.alpn.is_empty() || self.meek.alpn.iter().any(|name| name == b"http/1.1") {
                vec![b"http/1.1".to_vec()]
            } else {
                if !self.alpn_warned {
                    eprintln!("psiphon: fronting ALPN names no http/1.1; using http/1.1");
                    self.alpn_warned = true;
                }
                vec![b"http/1.1".to_vec()]
            };
        let config = TlsConfig {
            server_name,
            alpn: alpn.into(),
            roots: crate::quic::system_roots(),
            insecure: true,
            resumption: true,
            ..TlsConfig::default()
        };
        let mut tls = ferrox_core::tls::connect(&config, stream)
            .map_err(|error| format!("psiphon meek tls {}: {error}", self.meek.sni))?;
        tls.handshake()
            .map_err(|error| format!("psiphon meek handshake {}: {error}", self.meek.sni))?;
        self.stream = Some(MeekStream::Tls(tls));
        Ok(())
    }

    /// Advance to the next fronting address.
    fn rotate_front(&mut self) {
        let index = self.front_index;
        self.front_index = self.front_index.wrapping_add(1);
        if let Some((dial, port)) = self.meek.fronts.get(index % self.meek.fronts.len().max(1)) {
            self.meek.dial.clone_from(dial);
            self.meek.port = *port;
        }
        if let Some(host) = self.meek.hosts.get(index % self.meek.hosts.len().max(1)) {
            self.meek.host.clone_from(host);
        }
    }

    /// Whether the current front closed the stream.
    fn peer_closed(&self) -> bool {
        self.stream.as_ref().is_none_or(MeekStream::peer_closed)
    }

    /// Exchange one request, rotating to a fresh front after a failure.
    fn exchange(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.stream.is_none() {
            self.open()?;
        }
        if !body.is_empty() && self.peer_closed() {
            self.stream = None;
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
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "psiphon meek has no connection".to_owned())?;
        stream
            .write_all(&request)
            .and_then(|()| stream.flush())
            .map_err(|error| format!("psiphon meek request: {error}"))?;
        let reply = crate::foxy_account::read_reply(stream)
            .map_err(|_| "psiphon meek response".to_owned())?;
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
            self.stream = None;
        }
        Ok(reply.body)
    }
}

/// The protocol name the meek cookie reports, with the CDN marker removed.
fn cookie_protocol(protocol: &str) -> String {
    protocol.replacen("-CDN", "", 1)
}

/// Build the cookie header for a meek request.
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
    let plaintext = format!(r#"{{"v":4,"t":"{}"}}"#, cookie_protocol(meek.protocol));
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
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
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

    #[test]
    fn the_cookie_names_the_base_tunnel_protocol() {
        assert_eq!(
            cookie_protocol("FRONTED-MEEK-CDN-OSSH"),
            "FRONTED-MEEK-OSSH"
        );
        assert_eq!(
            cookie_protocol("FRONTED-MEEK-CDN-HTTP-OSSH"),
            "FRONTED-MEEK-HTTP-OSSH"
        );
        assert_eq!(
            cookie_protocol("UNFRONTED-MEEK-HTTPS-OSSH"),
            "UNFRONTED-MEEK-HTTPS-OSSH"
        );
    }
}
