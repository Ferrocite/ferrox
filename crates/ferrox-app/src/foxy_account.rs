//! One TLS connection per call: the plane is too sparse to pool, and the codec is provable over a pipe.

use crate::foxy_challenge::{self, Jar};
use ferrox_core::foxy::account::{self, Signed};
use ferrox_core::foxy::{Failure, Pass};
use ferrox_core::tls::{RustlsProvider, TlsConfig, TlsProvider as _};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";
pub(crate) const JSON_ACCEPT: &str = "application/json";
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Denied {
    /// The access token or the account is not accepted: sign in again.
    Token,
    /// The account has no quota left, and the answer says when it resets.
    Quota,
    /// The edge is asking for a client it considers a bot. Named, not guessed.
    Challenged(u16),
    /// The plane could not be reached at all, with the phase that gave up.
    Unreachable(String),
    /// Anything else, with the status it came back as.
    Other(u16),
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token => f.write_str("the account token was refused"),
            Self::Quota => f.write_str("the account has no quota left"),
            Self::Challenged(status) => {
                write!(f, "the edge answered {status} and asked for a challenge")
            }
            Self::Unreachable(why) => write!(f, "the account plane is unreachable: {why}"),
            Self::Other(status) => write!(f, "the account plane answered {status}"),
        }
    }
}

impl Denied {
    /// The statuses that mean the same thing whatever the body said.
    #[must_use]
    pub(crate) fn of(status: u16) -> Option<Self> {
        match status {
            401 | 403 => Some(Self::Token),
            406 => Some(Self::Challenged(status)),
            429 => Some(Self::Quota),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Auth {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) expires_at: u64,
}

impl Auth {
    #[must_use]
    pub(crate) fn valid_at(&self, now: u64) -> bool {
        self.expires_at.saturating_sub(now) > 60
    }
}

/// A response with head and body already split: a chunked body cannot be read until the head is off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    #[must_use]
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[must_use]
    pub(crate) fn field(&self, name: &str) -> Option<String> {
        let text = String::from_utf8_lossy(&self.body);
        let needle = format!("\"{name}\":");
        let at = text.find(&needle)? + needle.len();
        let rest = &text[at..];
        let value = match rest.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next().unwrap_or_default(),
            None => rest
                .trim_start_matches([' ', '\n', '\r', '\t'])
                .split(|c: char| c == ',' || c == '}' || c.is_whitespace())
                .next()
                .unwrap_or_default(),
        };
        (!value.is_empty() && value != "null").then(|| value.to_owned())
    }

    #[must_use]
    pub(crate) fn header_number(&self, name: &str) -> Option<u64> {
        self.header(name)
            .and_then(|value| value.trim().parse().ok())
    }
}

/// Exact request bytes, no defaults: challenge and API send different agents and accepts, so callers write them.
#[must_use]
pub(crate) fn request(
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Content-Length: ");
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    let mut left = body.len();
    loop {
        at -= 1;
        digits[at] = b'0' + u8::try_from(left % 10).unwrap_or(0);
        left /= 10;
        if left == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// Head to the blank line, then the declared body shape; a TLS record costs a syscall, so the head is buffered.
pub(crate) fn read_reply<S: Read>(io: &mut S) -> Result<Reply, Failure> {
    let mut io = BufReader::with_capacity(1024, io);
    let mut lines: Vec<String> = Vec::with_capacity(12);
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let read = io.read_line(&mut line).map_err(|_| Failure::Stream)?;
        if read == 0 {
            return Err(Failure::Frame);
        }
        total += read;
        if total > MAX_HEAD {
            return Err(Failure::Frame);
        }
        let blank = line == "\r\n" || line == "\n";
        if blank {
            break;
        }
        lines.push(line);
    }
    let status = lines
        .first()
        .and_then(|line| {
            let mut parts = line.split(' ');
            let version = parts.next()?;
            let code = parts.next()?;
            (version.starts_with("HTTP/1.") && code.len() == 3)
                .then(|| code.parse::<u16>().ok())
                .flatten()
        })
        .ok_or(Failure::Frame)?;
    let mut headers = Vec::with_capacity(lines.len());
    for line in &lines[1..] {
        let Some(colon) = line.find(':') else {
            continue;
        };
        headers.push((
            line[..colon].trim().to_owned(),
            line[colon + 1..].trim().to_owned(),
        ));
    }
    let body = read_body(&mut io, &headers)?;
    Ok(Reply {
        status,
        headers,
        body,
    })
}

fn read_body<S: BufRead>(io: &mut S, headers: &[(String, String)]) -> Result<Vec<u8>, Failure> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        let mut body = Vec::new();
        loop {
            let mut line = String::new();
            if io.read_line(&mut line).map_err(|_| Failure::Stream)? > 64 {
                return Err(Failure::Frame);
            }
            let size = usize::from_str_radix(line.trim_end_matches(['\r', '\n']), 16)
                .map_err(|_| Failure::Frame)?;
            if size == 0 {
                let mut trailer = String::new();
                let _ = io.read_line(&mut trailer);
                return Ok(body);
            }
            if body.len() + size > MAX_BODY {
                return Err(Failure::Frame);
            }
            let at = body.len();
            body.resize(at + size, 0);
            io.read_exact(&mut body[at..])
                .map_err(|_| Failure::Stream)?;
            let mut tail = [0u8; 2];
            io.read_exact(&mut tail).map_err(|_| Failure::Stream)?;
        }
    }
    let len = header("content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY);
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).map_err(|_| Failure::Stream)?;
    Ok(body)
}

/// Split into the TLS name and the dialled address: a pinned address never becomes the TLS name.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The path prefix the origin publishes (`Guardian` serves none); a path, never part of the TLS name.
    pub(crate) base: String,
    pub(crate) address: Option<SocketAddr>,
    pub(crate) roots: Vec<Vec<u8>>,
}

impl Endpoint {
    #[must_use]
    pub(crate) fn parse(url: &str, roots: Vec<Vec<u8>>) -> Option<Self> {
        let rest = url.strip_prefix("https://")?;
        let (hostport, path) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (hostport, 443),
        };
        if host.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            port,
            base: path.to_owned(),
            address: None,
            roots,
        })
    }

    #[must_use]
    pub(crate) fn origin(&self) -> String {
        self.host.clone()
    }

    /// Where a request goes: the origin's own prefix, then the path.
    #[must_use]
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn tls(&self) -> TlsConfig {
        TlsConfig {
            server_name: self.host.clone(),
            alpn: Vec::new(),
            roots: self.roots.clone(),
            pins: ferrox_core::foxy::pin::Pins::default(),
        }
    }

    /// Where an account-plane failure keeps its name instead of flattening to an uninformative "io failed".
    fn connect(&self) -> Result<RustlsProvider<TcpStream>, String> {
        let peer = match self.address {
            Some(address) => address,
            None => format!("{}:{}", self.host, self.port)
                .to_socket_addrs()
                .map_err(|why| format!("resolve {}: {why}", self.host))?
                .next()
                .ok_or_else(|| format!("{} resolves to nothing", self.host))?,
        };
        let stream = TcpStream::connect_timeout(&peer, IO_TIMEOUT)
            .map_err(|why| format!("connect {peer}: {why}"))?;
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let mut tls = RustlsProvider::connect(&self.tls(), stream)
            .map_err(|why| format!("tls {}: {why}", self.host))?;
        tls.handshake()
            .map_err(|why| format!("handshake {}: {why}", self.host))?;
        Ok(tls)
    }
}

use std::net::ToSocketAddrs as _;

/// One request and answer through the jar; the agent and accept are the caller's because API and challenge differ.
pub(crate) fn send(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    agent: crate::foxy_challenge::Agent,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, Denied> {
    // The API is served under the origin's prefix; the challenge at its root, so only the API takes it.
    let url = match agent {
        crate::foxy_challenge::Agent::Api => endpoint.url(path),
        _ => path.to_owned(),
    };
    let cookie = jar.lock().ok().and_then(|jar| jar.header(&endpoint.host));
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(extra.len() + 4);
    headers.push(("User-Agent", agent.user_agent()));
    headers.push(("Accept", agent.accept()));
    headers.push(("Connection", "close"));
    headers.extend_from_slice(extra);
    if let Some(cookie) = cookie.as_deref() {
        headers.push(("Cookie", cookie));
    }
    let mut tls = endpoint.connect().map_err(Denied::Unreachable)?;
    tls.write_all(&request(method, &endpoint.origin(), &url, &headers, body))
        .and_then(|()| tls.flush())
        .map_err(|why| Denied::Unreachable(format!("writing {} {url}: {why}", endpoint.host)))?;
    let reply = read_reply(&mut tls)
        .map_err(|why| Denied::Unreachable(format!("reading {} {url}: {why}", endpoint.host)))?;
    if let Ok(mut jar) = jar.lock() {
        jar.absorb(&endpoint.host, &reply);
    }
    Ok(reply)
}

/// The `FxA` login, tried without the two-factor method first: the first attempt's error is the reason to drop it.
pub(crate) fn login(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    email: &str,
    password: &str,
) -> Result<(String, bool), Denied> {
    // An autofilled or pasted identity carries padding that FxA rejects; the address has no significant edge whitespace, so trim before the stretch and the body.
    let email = email.trim();
    let stretched = account::auth_pw(email, password);
    for method in [Some("email-2fa"), None] {
        let body = account::login_body(email, &stretched, method);
        let reply = foxy_challenge::send_with_challenge(
            endpoint,
            jar,
            "POST",
            "/account/login",
            &[("Content-Type", JSON_ACCEPT)],
            &body,
        )?;
        if let Some(errno) = errno(&reply) {
            if errno == 107 && method.is_some() {
                continue;
            }
            return Err(Denied::Other(reply.status));
        }
        if let Some(denied) = Denied::of(reply.status) {
            return Err(denied);
        }
        let token = reply.field("sessionToken").ok_or(Denied::Token)?;
        return Ok((token, reply.field("verified").is_some_and(|v| v == "true")));
    }
    Err(Denied::Token)
}

fn errno(reply: &Reply) -> Option<u64> {
    reply
        .field("errno")
        .and_then(|value| value.trim().parse().ok())
}

/// The token exchange: only the credentials grant is Hawk-signed; the refresh grant is not.
pub(crate) fn token(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    session_token: Option<&str>,
    refresh_token: Option<&str>,
    nonce: &str,
    timestamp: u64,
) -> Result<Auth, Denied> {
    let body = match (session_token, refresh_token) {
        (Some(_), _) => account::token_body("fxa-credentials", None),
        (None, Some(refresh)) => account::token_body("refresh_token", Some(refresh)),
        (None, None) => return Err(Denied::Token),
    };
    let authorization = session_token.and_then(|session| {
        let (id, mac) = account::hawk_credentials(session)?;
        Some(
            Signed {
                method: "POST",
                path: &endpoint.url("/oauth/token"),
                host: &endpoint.origin(),
                port: endpoint.port,
                body: &body,
                timestamp,
                nonce,
            }
            .header(&id, &mac),
        )
    });
    let mut headers: Vec<(&str, &str)> = vec![("Content-Type", JSON_ACCEPT)];
    if let Some(authorization) = authorization.as_deref() {
        headers.push(("Authorization", authorization));
    }
    let reply = foxy_challenge::send_with_challenge(
        endpoint,
        jar,
        "POST",
        "/oauth/token",
        &headers,
        &body,
    )?;
    if let Some(denied) = Denied::of(reply.status) {
        return Err(denied);
    }
    if reply.status != 200 {
        return Err(Denied::Other(reply.status));
    }
    let access_token = reply.field("access_token").ok_or(Denied::Token)?;
    let refresh_token = reply
        .field("refresh_token")
        .or_else(|| refresh_token.map(str::to_owned))
        .ok_or(Denied::Token)?;
    let ttl = reply
        .field("expires_in")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(86_400);
    Ok(Auth {
        access_token,
        refresh_token,
        expires_at: timestamp + ttl,
    })
}

/// The pass the tunnel carries, read from the token response and the quota headers with it.
pub(crate) fn pass(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    access_token: &str,
) -> Result<Pass, Denied> {
    let bearer = format!("Bearer {access_token}");
    let reply = foxy_challenge::send_with_challenge(
        endpoint,
        jar,
        "GET",
        "/api/v1/fpn/token",
        &[("Authorization", &bearer), ("Content-Type", JSON_ACCEPT)],
        b"",
    )?;
    if let Some(denied) = Denied::of(reply.status) {
        return Err(denied);
    }
    if reply.status != 200 {
        return Err(Denied::Other(reply.status));
    }
    let token = reply
        .field("token")
        .filter(|t| !t.is_empty())
        .ok_or(Denied::Token)?;
    let expires_at = reply
        .field("expires_at")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|at| *at > 0)
        .or_else(|| account::jwt_expiry(&token));
    Ok(Pass {
        token,
        expires_at,
        quota_remaining: reply.header_number("X-Quota-Remaining"),
        quota_reset: reply.header_number("X-Quota-Reset"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piped(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn a_request_carries_the_line_the_host_the_agent_and_the_length() {
        let raw = request(
            "POST",
            "api.accounts.firefox.com",
            "/v1/account/login",
            &[
                ("User-Agent", USER_AGENT),
                ("Accept", JSON_ACCEPT),
                ("X-A", "1"),
            ],
            b"{}",
        );
        let text = String::from_utf8(raw).expect("ascii");
        assert!(text
            .starts_with("POST /v1/account/login HTTP/1.1\r\nHost: api.accounts.firefox.com\r\n"));
        assert!(text.contains("\r\nUser-Agent: MozillaVPN/2.35.0 (sys:linux; iap:true)\r\n"));
        assert!(text.contains("\r\nAccept: application/json\r\n"));
        assert!(text.contains("\r\nX-A: 1\r\n"));
        assert!(text.ends_with("\r\nContent-Length: 2\r\n\r\n{}"));
    }

    #[test]
    fn a_reply_splits_its_head_from_a_content_length_body() {
        let raw = piped(b"HTTP/1.1 200 OK\r\nX-Quota-Limit: 10\r\nContent-Length: 5\r\n\r\nhello");
        let reply = read_reply(&mut raw.as_slice()).expect("reads");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("x-quota-limit"), Some("10"));
        assert_eq!(reply.header_number("X-Quota-Limit"), Some(10));
        assert_eq!(reply.body, b"hello");
    }

    #[test]
    fn a_chunked_body_is_reassembled_before_it_is_read() {
        let raw = piped(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let reply = read_reply(&mut raw.as_slice()).expect("reads");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"hello world");
    }

    #[test]
    fn a_reply_without_a_length_is_a_head_and_nothing_else() {
        let raw = piped(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        let reply = read_reply(&mut raw.as_slice()).expect("reads");
        assert_eq!(reply.status, 407);
        assert_eq!(reply.body, Vec::new());
        assert_eq!(reply.header_number("X-Quota-Reset"), None);
    }

    #[test]
    fn a_head_that_is_not_a_reply_is_refused_rather_than_guessed() {
        for raw in [
            &b"garbage\r\n\r\n"[..],
            &b"HTTP/2 200\r\n\r\n"[..],
            &b"HTTP/1.1 20 OK\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK"[..],
        ] {
            assert!(read_reply(&mut &raw[..]).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn a_json_field_is_read_as_a_string_or_a_number_and_nothing_else() {
        let reply = Reply {
            status: 200,
            headers: Vec::new(),
            body: br#"{"token":"a.b.c","expires_at":1735689600,"maxBytes":null,"flag":true}"#
                .to_vec(),
        };
        assert_eq!(reply.field("token").as_deref(), Some("a.b.c"));
        assert_eq!(reply.field("expires_at").as_deref(), Some("1735689600"));
        assert_eq!(reply.field("maxBytes"), None, "a null is not a value");
        assert_eq!(reply.field("flag").as_deref(), Some("true"));
        assert_eq!(reply.field("absent"), None);
    }

    #[test]
    fn the_status_taxonomy_is_the_one_the_references_name() {
        assert_eq!(Denied::of(401), Some(Denied::Token));
        assert_eq!(Denied::of(403), Some(Denied::Token));
        assert_eq!(Denied::of(406), Some(Denied::Challenged(406)));
        assert_eq!(Denied::of(429), Some(Denied::Quota));
        assert_eq!(Denied::of(500), None);
        assert!(Denied::of(406)
            .expect("challenged")
            .to_string()
            .contains("challenge"));
    }

    #[test]
    fn an_access_token_is_stale_before_it_expires_rather_than_at_it() {
        let auth = Auth {
            access_token: "t".to_owned(),
            refresh_token: "r".to_owned(),
            expires_at: 1_000,
        };
        assert!(auth.valid_at(900));
        assert!(!auth.valid_at(940), "the clock skew margin");
        assert!(!auth.valid_at(1_000));
    }

    #[test]
    fn an_endpoint_names_itself_and_keeps_the_address_out_of_the_tls_name() {
        let endpoint = Endpoint::parse("https://vpn.mozilla.org", Vec::new()).expect("parses");
        assert_eq!(endpoint.host, "vpn.mozilla.org");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.address, None);
        assert_eq!(endpoint.origin(), "vpn.mozilla.org");
        let pinned = Endpoint {
            address: Some("127.0.0.1:443".parse().expect("addr")),
            ..endpoint.clone()
        };
        assert_eq!(
            pinned.host, "vpn.mozilla.org",
            "the pin dial keeps the name"
        );
        assert!(Endpoint::parse("http://vpn.mozilla.org", Vec::new()).is_none());
        assert!(Endpoint::parse("vpn.mozilla.org", Vec::new()).is_none());
        assert_eq!(
            Endpoint::parse("https://host:8443", Vec::new())
                .expect("parses")
                .port,
            8443
        );
    }
}

#[cfg(test)]
mod activation {
    use super::loopback::{ACTIVE, EDGE};

    /// An account that never activated its entitlement is refused a pass: activate, mint again, one retry.
    #[test]
    fn a_refused_pass_is_activated_once_and_minted_again() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
        let (address, roots) = super::loopback::edge();
        let account = super::loopback::account(address, roots);
        account
            .sign_in("person@example.com", "hunter2")
            .expect("signs in");
        assert!(
            account.current().token.starts_with("eyJ"),
            "the pass arrives after one activation"
        );
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The whole account, from sign-in to a pass, with the renewal on a clock the dial already reads.
#[derive(Debug, Clone)]
pub(crate) struct Account {
    pub(crate) fxa: Endpoint,
    pub(crate) guardian: Endpoint,
    /// A sign-in stopped at two-factor, holding the session token the code must be submitted against.
    pub(crate) pending: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    /// One jar for both hosts, so a challenge solved on one is not solved twice.
    pub(crate) jar: std::sync::Arc<Mutex<Jar>>,
    pub(crate) auth: std::sync::Arc<std::sync::Mutex<Auth>>,
    pub(crate) pass: std::sync::Arc<std::sync::Mutex<Pass>>,
}

fn epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn nonce() -> String {
    let mut raw = [0u8; 6];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    ferrox_core::b64::encode(&raw)
}

impl Account {
    /// Signs in, exchanges the session token, and mints the first pass.
    pub(crate) fn sign_in(&self, email: &str, password: &str) -> Result<(), Denied> {
        let now = epoch();
        let (session, verified) = login(&self.fxa, &self.jar, email, password)?;
        if !verified {
            *self.pending.lock().map_err(|_| Denied::Token)? = Some(session);
            return Ok(());
        }
        self.exchange(&session, now)
    }

    /// Turns a session token into an access token and mints the first pass.
    fn exchange(&self, session: &str, now: u64) -> Result<(), Denied> {
        let auth = token(&self.fxa, &self.jar, Some(session), None, &nonce(), now)?;
        *self.auth.lock().map_err(|_| Denied::Token)? = auth.clone();
        self.mint(&auth.access_token)
    }

    /// Whether the sign-in stopped at two-factor: the one branch a username and password cannot cover.
    pub(crate) fn needs_code(&self) -> bool {
        self.pending.lock().is_ok_and(|pending| pending.is_some())
    }

    /// Confirms the two-factor code the sign-in asked for.
    pub(crate) fn verify_code(&self, code: &str) -> Result<(), Denied> {
        let session = self
            .pending
            .lock()
            .map_err(|_| Denied::Token)?
            .clone()
            .ok_or(Denied::Token)?;
        let body = account::code_body(code);
        foxy_challenge::send_with_challenge(
            &self.fxa,
            &self.jar,
            "POST",
            "/session/verify_code",
            &[("Content-Type", JSON_ACCEPT)],
            &body,
        )?;
        let now = epoch();
        *self.pending.lock().map_err(|_| Denied::Token)? = None;
        self.exchange(&session, now)
    }

    pub(crate) fn mint(&self, access_token: &str) -> Result<(), Denied> {
        let minted = match pass(&self.guardian, &self.jar, access_token) {
            // A never-activated entitlement is refused a pass, so the plane activates it and mints once more.
            Err(Denied::Token) => {
                self.activate(access_token)?;
                pass(&self.guardian, &self.jar, access_token)?
            }
            minted => minted?,
        };
        *self.pass.lock().map_err(|_| Denied::Token)? = minted;
        Ok(())
    }

    fn activate(&self, access_token: &str) -> Result<(), Denied> {
        let bearer = format!("Bearer {access_token}");
        foxy_challenge::send_with_challenge(
            &self.guardian,
            &self.jar,
            "POST",
            "/api/v1/fpn/activate",
            &[("Authorization", &bearer), ("Content-Type", JSON_ACCEPT)],
            b"",
        )
        .map(|_| ())
    }

    /// Refreshes a stale token and mints a new pass, rotated in place so no tunnel is rebuilt to carry it.
    pub(crate) fn renew(&self) -> Result<(), Denied> {
        let stale = self
            .auth
            .lock()
            .map_or(true, |auth| !auth.valid_at(epoch()));
        let access_token = if stale {
            let current = self.auth.lock().map_err(|_| Denied::Token)?.clone();
            let now = epoch();
            let fresh = token(
                &self.fxa,
                &self.jar,
                None,
                Some(&current.refresh_token),
                &nonce(),
                now,
            )?;
            let access = fresh.access_token.clone();
            *self.auth.lock().map_err(|_| Denied::Token)? = fresh;
            access
        } else {
            self.auth
                .lock()
                .map_err(|_| Denied::Token)?
                .access_token
                .clone()
        };
        self.mint(&access_token)
    }

    /// How long until the current pass wants replacing.
    pub(crate) fn renews_in(&self) -> std::time::Duration {
        self.pass
            .lock()
            .map_or(std::time::Duration::from_secs(240), |pass| {
                pass.renews_in(epoch())
            })
    }

    pub(crate) fn current(&self) -> Pass {
        self.pass.lock().map_or_else(
            |_| Pass {
                token: String::new(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
            |pass| pass.clone(),
        )
    }
}

#[cfg(test)]
mod renewal {
    use super::*;

    fn account_with(pass: Pass) -> Account {
        Account {
            fxa: Endpoint::parse("https://api.accounts.firefox.com/v1", Vec::new())
                .expect("parses"),
            guardian: Endpoint::parse("https://vpn.mozilla.org", Vec::new()).expect("parses"),
            jar: std::sync::Arc::new(Mutex::new(Jar::default())),
            pending: std::sync::Arc::new(std::sync::Mutex::new(None)),
            auth: std::sync::Arc::new(std::sync::Mutex::new(Auth {
                access_token: "a".to_owned(),
                refresh_token: "r".to_owned(),
                expires_at: 0,
            })),
            pass: std::sync::Arc::new(std::sync::Mutex::new(pass)),
        }
    }

    #[test]
    fn the_clock_a_pass_asks_for_is_the_one_the_core_wrote() {
        let account = account_with(Pass {
            token: "t".to_owned(),
            expires_at: Some(epoch() + 600),
            quota_remaining: None,
            quota_reset: None,
        });
        let want = account.current().renews_in(epoch());
        assert_eq!(account.renews_in(), want);
    }

    #[test]
    fn an_unknown_expiry_asks_for_the_four_minute_fallback() {
        let account = account_with(Pass {
            token: "t".to_owned(),
            expires_at: None,
            quota_remaining: None,
            quota_reset: None,
        });
        assert_eq!(account.renews_in(), std::time::Duration::from_secs(240));
        assert_eq!(account.current().token, "t");
    }
}

#[cfg(test)]
mod loopback {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    pub(crate) const HOSTS: [&str; 2] = ["api.accounts.firefox.com", "vpn.mozilla.org"];
    use sha2::Digest as _;
    const PREFIX: &str = "/_fs-ch-loopback";
    pub(crate) const SESSION: &str =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// Whether the sign-in stops at two-factor. Process-wide because the answering server runs on its own thread.
    pub(crate) static TWO_FACTOR: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// One edge at a time: the flag is process-wide, so the two tests that read it take turns rather than race.
    pub(crate) static EDGE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    /// Whether the plane treats the entitlement as activated, which the activate-and-mint-again path turns on.
    pub(crate) static ACTIVE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(true);

    #[derive(Debug, Clone)]
    pub(crate) struct Seen {
        method: String,
        path: String,
        agent: String,
        accept: String,
        cookie: Option<String>,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    /// One request's worth, read the way a server reads it: line, headers, then the body the length declares.
    fn take<S: std::io::BufRead>(io: &mut S) -> Option<Seen> {
        let mut line = String::new();
        if io.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let mut parts = line.trim_end().split(' ');
        let method = parts.next()?.to_owned();
        let path = parts.next()?.to_owned();
        let mut seen = Seen {
            method,
            path,
            agent: String::new(),
            accept: String::new(),
            cookie: None,
            authorization: None,
            body: Vec::new(),
        };
        let mut length = 0usize;
        loop {
            let mut head = String::new();
            if io.read_line(&mut head).ok()? == 0 {
                return None;
            }
            let head = head.trim_end();
            if head.is_empty() {
                break;
            }
            let Some((name, value)) = head.split_once(':') else {
                continue;
            };
            match name.to_ascii_lowercase().as_str() {
                "user-agent" => seen.agent = value.trim().to_owned(),
                "accept" => seen.accept = value.trim().to_owned(),
                "cookie" => seen.cookie = Some(value.trim().to_owned()),
                "authorization" => seen.authorization = Some(value.trim().to_owned()),
                "content-length" => length = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        if length > 0 {
            seen.body.resize(length, 0);
            io.read_exact(&mut seen.body).ok()?;
        }
        Some(seen)
    }

    fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status} X\r\n").into_bytes();
        for (name, value) in headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
        out
    }

    const PASS_HEADERS: [(&str, &str); 2] = [
        ("X-Quota-Limit", "5368709120"),
        ("X-Quota-Remaining", "4294967296"),
    ];
    const PASS_BODY: &str = r#"{"token":"eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3MzU2ODk2MDB9.sig"}"#;

    /// The served challenge script, with a proof of work whose target hash is the digest of the answer to find.
    fn challenge_script() -> String {
        let target = ferrox_core::foxy::account::hex_encode(&sha2::Sha256::digest(b"loopbacka1"));
        format!(
            "init([],\"old\",\"x\");init([{{\"ty\":\"pow\",\"data\":{{\"base\":\"loopback\",\"hash\":\"{target}\",\"hmac\":\"hm\",\"expires\":\"soon\"}}}},{{\"ty\":\"pat\"}},{{\"ty\":\"clientmetrics\"}}],\"tok\",\"y\");"
        )
    }

    fn session_answer() -> String {
        let verified = !TWO_FACTOR.load(std::sync::atomic::Ordering::Relaxed);
        format!(r#"{{"sessionToken":"{SESSION}","verified":{verified}}}"#)
    }

    /// The whole account plane on one loopback port: challenge, sign-in, Hawk-signed exchange, pass.
    pub(crate) fn serve(
        listener: &TcpListener,
        root: &ferrox_core::tls::TlsServerConfig,
        tx: &mpsc::Sender<Seen>,
    ) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            stream.set_read_timeout(Some(IO_TIMEOUT)).expect("timeout");
            let mut tls = ferrox_core::tls::accept(root, stream).expect("accepts");
            let mut io = BufReader::new(&mut tls);
            let Some(seen) = take(&mut io) else {
                drop(io);
                continue;
            };
            drop(io);
            let out = answer(&seen, tx);
            let _ = tls.write_all(&out);
            let _ = tls.flush();
        }
    }

    fn answer(seen: &Seen, tx: &mpsc::Sender<Seen>) -> Vec<u8> {
        let _ = tx.send(seen.clone());
        let cleared = seen
            .cookie
            .as_deref()
            .is_some_and(|c| c.contains("_fs_chl="));
        match (seen.method.as_str(), seen.path.as_str()) {
            ("GET", "/") if cleared => reply(200, &[], "<html>no challenge now</html>"),
            ("GET", "/") => reply(
                200,
                &[("Set-Cookie", "seen=1; Path=/")],
                "<html>Client Challenge at /_fs-ch-loopback/x.js</html>",
            ),
            ("GET", path)
                if path.starts_with(PREFIX) && path.ends_with("script.js?reload=true") =>
            {
                reply(200, &[], &challenge_script())
            }
            ("POST", path) if path.starts_with(&format!("{PREFIX}/pat")) => {
                assert!(path.contains("token=tok"), "{path}");
                reply(200, &[], r#"{"auth":"pat-answer"}"#)
            }
            ("POST", path) if path == format!("{PREFIX}/fst-post-back") => {
                let body = String::from_utf8_lossy(&seen.body);
                assert!(body.contains("\"token\":\"tok\""), "{body}");
                assert!(body.contains("\"answer\":\"a1\""), "{body}");
                assert!(body.contains("\"auth\":\"pat-answer\""), "{body}");
                assert!(body.contains("\"bot_detected\":false"), "{body}");
                reply(
                    200,
                    &[("Set-Cookie", "_fs_chl=cleared; Path=/; Domain=firefox.com")],
                    r#"{"status":"success"}"#,
                )
            }
            ("POST", "/v1/account/login") => {
                if !seen
                    .cookie
                    .as_deref()
                    .is_some_and(|c| c.contains("_fs_chl=cleared"))
                {
                    return reply(406, &[], "");
                }
                let body = String::from_utf8_lossy(&seen.body);
                assert!(
                    body.contains(r#""email":"person@example.com""#),
                    "the login must carry the trimmed identity: {body}"
                );
                reply(200, &[], &session_answer())
            }
            ("POST", "/v1/oauth/token") => {
                let auth = seen.authorization.as_deref().unwrap_or_default();
                assert!(auth.starts_with("Hawk id=\""), "{auth}");
                assert!(auth.contains("mac=\""), "{auth}");
                assert!(auth.contains(", hash=\""), "a body is hashed in: {auth}");
                reply(
                    200,
                    &[],
                    r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}"#,
                )
            }
            ("POST", "/v1/session/verify_code") => {
                assert_eq!(
                    seen.body,
                    br#"{"code":"424242"}"#.to_vec(),
                    "{:?}",
                    seen.body
                );
                reply(200, &[], "{}")
            }
            ("POST", "/api/v1/fpn/activate") => {
                ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
                reply(200, &[], r#"{"subscribed":true,"maxBytes":5368709120}"#)
            }
            ("GET", "/api/v1/fpn/token") if !ACTIVE.load(std::sync::atomic::Ordering::Relaxed) => {
                reply(401, &[], "")
            }
            ("GET", "/api/v1/fpn/token") => {
                assert_eq!(
                    seen.authorization.as_deref(),
                    Some("Bearer access-1"),
                    "{:?}",
                    seen.authorization
                );
                reply(200, &PASS_HEADERS, PASS_BODY)
            }
            _ => reply(404, &[], "{}"),
        }
    }

    pub(crate) fn account(address: std::net::SocketAddr, roots: Vec<Vec<u8>>) -> Account {
        Account {
            fxa: Endpoint {
                address: Some(address),
                ..Endpoint::parse(ferrox_core::foxy::account::FXA_SERVER, roots.clone())
                    .expect("parses")
            },
            guardian: Endpoint {
                address: Some(address),
                ..Endpoint::parse(ferrox_core::foxy::account::GUARDIAN_SERVER, roots)
                    .expect("parses")
            },
            jar: std::sync::Arc::new(Mutex::new(Jar::default())),
            pending: std::sync::Arc::new(std::sync::Mutex::new(None)),
            auth: std::sync::Arc::new(std::sync::Mutex::new(Auth {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: 0,
            })),
            pass: std::sync::Arc::new(std::sync::Mutex::new(Pass {
                token: String::new(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            })),
        }
    }

    /// The edge loopback two tests share: a certificate, a port and a listener with the whole plane behind it.
    pub(crate) fn edge() -> (std::net::SocketAddr, Vec<Vec<u8>>) {
        let minted = rcgen::generate_simple_self_signed(
            HOSTS
                .iter()
                .map(|host| (*host).to_owned())
                .collect::<Vec<String>>(),
        )
        .expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let root = ferrox_core::tls::parse_pem_identity(minted.cert.pem().as_bytes(), &key_pem)
            .expect("identity");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, _rx) = mpsc::channel();
        std::thread::spawn(move || serve(&listener, &root, &tx));
        (format!("127.0.0.1:{port}").parse().expect("addr"), roots)
    }

    #[test]
    fn an_account_signs_in_through_a_challenge_and_mints_a_pass() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let minted = rcgen::generate_simple_self_signed(
            HOSTS
                .iter()
                .map(|h| (*h).to_owned())
                .collect::<Vec<String>>(),
        )
        .expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let root = ferrox_core::tls::parse_pem_identity(minted.cert.pem().as_bytes(), &key_pem)
            .expect("identity");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || serve(&listener, &root, &tx));

        let address = format!("127.0.0.1:{port}").parse().expect("addr");
        let account = account(address, roots);
        account
            .sign_in("person@example.com", "hunter2")
            .expect("signs in");
        let pass = account.current();
        assert!(pass.token.starts_with("eyJ"), "{}", pass.token);
        assert_eq!(pass.expires_at, Some(1_735_689_600));
        assert_eq!(pass.quota_remaining, Some(4_294_967_296));
        assert!(!account.needs_code());

        let seen: Vec<String> = rx
            .try_iter()
            .map(|s| format!("{} {}", s.method, s.path))
            .collect();
        assert_eq!(
            seen.first().map(String::as_str),
            Some("POST /v1/account/login")
        );
        assert_eq!(
            seen.iter().filter(|line| *line == "GET /").count(),
            2,
            "{seen:?}"
        );
        assert!(
            seen.iter()
                .any(|line| line.ends_with("script.js?reload=true")),
            "{seen:?}"
        );
        assert!(seen.iter().any(|line| line.contains("/pat?")), "{seen:?}");
        assert_eq!(
            seen.last().map(String::as_str),
            Some("GET /api/v1/fpn/token")
        );
    }
}

#[cfg(test)]
mod two_factor {
    use super::loopback::{HOSTS, SESSION, TWO_FACTOR};
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[test]
    fn an_account_that_stops_at_two_factor_waits_for_a_code_and_then_mints() {
        let _turn = super::loopback::EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(true, std::sync::atomic::Ordering::Relaxed);
        let minted = rcgen::generate_simple_self_signed(
            HOSTS
                .iter()
                .map(|h| (*h).to_owned())
                .collect::<Vec<String>>(),
        )
        .expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let root = ferrox_core::tls::parse_pem_identity(minted.cert.pem().as_bytes(), &key_pem)
            .expect("identity");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, _rx) = mpsc::channel();
        std::thread::spawn(move || super::loopback::serve(&listener, &root, &tx));

        let address = format!("127.0.0.1:{port}").parse().expect("addr");
        let account = super::loopback::account(address, roots);
        account
            .sign_in("person@example.com", "hunter2")
            .expect("signs in");
        assert!(account.needs_code(), "an unverified sign-in waits");
        assert!(
            account.current().token.is_empty(),
            "no pass before the code"
        );
        account.verify_code("424242").expect("verifies");
        assert!(!account.needs_code(), "the code clears the wait");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
        assert_eq!(SESSION.len(), 64, "a session token is 32 bytes of hex");
    }
}

#[cfg(test)]
mod padded_identity {
    /// `FoxyVPN` v1.0.5 fixed a sign-in rejected by autofill padding; the lane must trim the identity before the stretch and the body, never send it raw.
    #[test]
    fn an_autofilled_identity_signs_in_trimmed() {
        let _turn = super::loopback::EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        super::loopback::ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        super::loopback::TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        let (address, roots) = super::loopback::edge();
        let account = super::loopback::account(address, roots);
        account
            .sign_in("  person@example.com\t", "hunter2")
            .expect("a padded identity signs in with the trimmed email");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
    }
}
