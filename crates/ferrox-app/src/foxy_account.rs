//! One TLS connection per call: the plane is too sparse to pool, and the codec is provable over a pipe.

use crate::conn::Connection;
use crate::foxy_challenge::{self, Jar};
use ferrox_core::foxy::account::{self, Signed};
use ferrox_core::foxy::{edge_peer, Failure, Pass};
use ferrox_core::tls::{TlsConfig, TlsProvider as _};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
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
    /// The account is not allowed to ask right now, with the seconds it named before it will answer (0 when it said nothing).
    Quota(u64),
    /// The edge is asking for a client it considers a bot. Named, not guessed.
    Challenged(u16),
    /// The plane could not be reached at all, with the phase that gave up.
    Unreachable(String),
    /// The grant was accepted but the pass minted from it was refused: an entitlement or device refusal, not a dead session.
    Pass,
    /// Anything else, with the status it came back as.
    Other(u16),
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token => f.write_str("the account token was refused"),
            Self::Quota(0) => f.write_str("the account has no quota left"),
            Self::Quota(wait) => write!(f, "the account plane asked to wait {wait}s"),
            Self::Challenged(status) => {
                write!(f, "the edge answered {status} and asked for a challenge")
            }
            Self::Unreachable(why) => write!(f, "the account plane is unreachable: {why}"),
            Self::Pass => {
                f.write_str("the pass was refused for an accepted grant: check the VPN entitlement or device list")
            }
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
            429 => Some(Self::Quota(0)),
            _ => None,
        }
    }

    /// The one refusal that makes the stored grant dead: the credential itself, not the plane's mood.
    #[must_use]
    pub(crate) fn is_final(&self) -> bool {
        matches!(self, Self::Token)
    }

    /// Whether asking again can change the answer: a dead credential and a pass refused for an accepted grant cannot.
    #[must_use]
    pub(crate) fn is_retryable(&self) -> bool {
        !matches!(self, Self::Token | Self::Pass)
    }

    /// The seconds the plane asked to wait before answering again, when it named any.
    #[must_use]
    pub(crate) fn retry_after(&self) -> u64 {
        match self {
            Self::Quota(wait) => *wait,
            _ => 0,
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

/// The grant one process leaves the next, and a sign-in stopped at two-factor, so a password is asked for once rather than per launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Session {
    pub(crate) email: String,
    pub(crate) auth: Option<Auth>,
    pub(crate) pending: Option<String>,
    pub(crate) pending_method: Option<String>,
}

/// The one file that spares a launch `FxA`'s sign-in: the email it belongs to is stored with the grant, so a different account never resumes the last one's session.
#[derive(Debug, Clone)]
pub(crate) struct TokenFile {
    path: std::path::PathBuf,
    email: String,
}

impl TokenFile {
    #[must_use]
    pub(crate) fn new(path: &str, email: &str) -> Option<Self> {
        let email = normalize_identity(email);
        // A grant is bound to the account it was written for: a file with no account to bind it to is a sign-in, not a resume.
        if path.is_empty() || email.is_empty() {
            return None;
        }
        Some(Self {
            path: std::path::PathBuf::from(path),
            email,
        })
    }

    /// A file for another account, an unreadable file and a file with neither a grant nor a pending sign-in all read as no session.
    pub(crate) fn load(&self) -> Option<Session> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        let doc = crate::json::parse(&text).ok()?;
        let field = |key: &str| {
            doc.get(key)
                .and_then(crate::json::Json::as_str)
                .map(str::to_owned)
        };
        let email = field("email").unwrap_or_default();
        if !email.eq_ignore_ascii_case(&self.email) {
            return None;
        }
        let access = field("access_token").filter(|token| !token.is_empty());
        let refresh = field("refresh_token").filter(|token| !token.is_empty());
        let auth = (access.is_some() || refresh.is_some()).then(|| Auth {
            access_token: access.unwrap_or_default(),
            refresh_token: refresh.unwrap_or_default(),
            expires_at: doc
                .get("expires_at")
                .and_then(crate::json::Json::as_u32)
                .map_or(0, u64::from),
        });
        let pending = field("pending_session").filter(|session| !session.is_empty());
        let pending_method = field("pending_method").filter(|method| !method.is_empty());
        (auth.is_some() || pending.is_some()).then_some(Session {
            email,
            auth,
            pending,
            pending_method,
        })
    }

    /// Best-effort and owner-only: a session that cannot be written costs the next launch a sign-in, which is a line, not a failed lane.
    pub(crate) fn save(&self, auth: Option<&Auth>, pending: Option<&str>) {
        self.save_pending(auth, pending, None);
    }

    fn save_pending(
        &self,
        auth: Option<&Auth>,
        pending: Option<&str>,
        pending_method: Option<&str>,
    ) {
        use crate::json::{self, Json};
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let mut pairs = vec![("email".to_owned(), Json::Str(self.email.clone()))];
        if let Some(auth) = auth {
            pairs.push((
                "access_token".to_owned(),
                Json::Str(auth.access_token.clone()),
            ));
            pairs.push((
                "refresh_token".to_owned(),
                Json::Str(auth.refresh_token.clone()),
            ));
            let expires_at = u32::try_from(auth.expires_at).unwrap_or(u32::MAX);
            pairs.push(("expires_at".to_owned(), Json::Num(f64::from(expires_at))));
        }
        if let Some(pending) = pending {
            pairs.push(("pending_session".to_owned(), Json::Str(pending.to_owned())));
            if let Some(method) = pending_method {
                pairs.push(("pending_method".to_owned(), Json::Str(method.to_owned())));
            }
        }
        let mut text = String::new();
        json::write(&Json::Obj(pairs), &mut text);
        // A lane beside this one may read the file at any moment: a rename shows it the old grant or the new one, never half of either.
        let mut temp = self.path.clone().into_os_string();
        temp.push(format!(".{}.tmp", std::process::id()));
        let temp = std::path::PathBuf::from(temp);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let Ok(mut file) = options.open(&temp) else {
            eprintln!("foxy: cannot write the session to {}", self.path.display());
            return;
        };
        if file.write_all(text.as_bytes()).is_err() {
            eprintln!("foxy: cannot write the session to {}", self.path.display());
            let _ = std::fs::remove_file(&temp);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        drop(file);
        if std::fs::rename(&temp, &self.path).is_err() {
            eprintln!("foxy: cannot write the session to {}", self.path.display());
            let _ = std::fs::remove_file(&temp);
        }
    }

    /// Another process refreshes a rotating grant in this file, so a token this launch loaded may already be spent; the pair the file names instead is the one to spend.
    pub(crate) fn rotated_from(&self, access: &str) -> Option<Auth> {
        self.load()
            .and_then(|session| session.auth)
            .filter(|fresh| fresh.access_token != access)
    }

    /// The refused grant only stops a future launch when the file still holds it; a grant another process rotated in since is left alone.
    pub(crate) fn clear_if(&self, refused: &str) {
        let same = self
            .load()
            .is_none_or(|session| session.auth.is_none_or(|auth| auth.access_token == refused));
        if same {
            self.clear();
        }
    }

    pub(crate) fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
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

    /// The status's meaning with the wait the head names: `Denied::of` reads the number, this reads the clock beside it.
    #[must_use]
    pub(crate) fn denied(&self) -> Option<Denied> {
        Denied::of(self.status).map(|denied| match denied {
            Denied::Quota(_) => {
                Denied::Quota(self.header_number("Retry-After").unwrap_or_default())
            }
            other => other,
        })
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
    pub(crate) roots: ferrox_core::tls::Anchors,
}

impl Endpoint {
    #[must_use]
    pub(crate) fn parse(url: &str, roots: ferrox_core::tls::Anchors) -> Option<Self> {
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
            // An origin that already is an address is read here, once, so an ask does not build the name and ask the resolver what it means.
            address: edge_peer(host, port),
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

    /// The same origin under another Firefox Accounts host: a pinned loopback keeps its address, a real host resolves the new name.
    #[must_use]
    fn with_host(&self, host: &str) -> Self {
        let mut endpoint = self.clone();
        host.clone_into(&mut endpoint.host);
        if self.address.is_none() {
            endpoint.address = edge_peer(host, self.port);
        }
        endpoint
    }

    fn tls(&self) -> TlsConfig {
        TlsConfig {
            server_name: self.host.clone(),
            alpn: vec![b"http/1.1".to_vec()].into(),
            roots: std::sync::Arc::clone(&self.roots),
            pins: ferrox_core::foxy::pin::Pins::default(),
            cert_pins: std::sync::Arc::from(Vec::new()),
            verify_names: std::sync::Arc::default(),
            cipher_suites: std::sync::Arc::default(),
            curves: std::sync::Arc::default(),
            insecure: false,
            resumption: true,
            fingerprint: None,
            ech_config_list: None,
            websocket: false,
            master_key_log: None,
        }
    }

    /// Mozilla's challenge endpoint only serves its script over HTTP/2, so the edge speaks it.
    fn tls_h2(&self) -> TlsConfig {
        let mut cfg = self.tls();
        cfg.alpn = vec![b"h2".to_vec()].into();
        cfg.fingerprint = ferrox_core::tls::shaped::Fingerprint::resolve("firefox_148");
        cfg
    }

    /// Where an account-plane failure keeps its name instead of flattening to an uninformative "io failed".
    fn connect(&self) -> Result<ferrox_core::tls::ClientSession<Connection>, String> {
        self.connect_with(&self.tls())
    }

    fn connect_h2(&self) -> Result<ferrox_core::tls::ClientSession<Connection>, String> {
        self.connect_with(&self.tls_h2())
    }

    fn connect_with(
        &self,
        cfg: &TlsConfig,
    ) -> Result<ferrox_core::tls::ClientSession<Connection>, String> {
        let peer = match self.address {
            Some(address) => address,
            None => format!("{}:{}", self.host, self.port)
                .to_socket_addrs()
                .map_err(|why| format!("resolve {}: {why}", self.host))?
                .next()
                .ok_or_else(|| format!("{} resolves to nothing", self.host))?,
        };
        let stream = crate::conn::dial_tcp(&peer, IO_TIMEOUT)
            .map_err(|why| format!("connect {peer}: {why}"))?;
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let mut tls = ferrox_core::tls::connect(cfg, stream)
            .map_err(|why| format!("tls {}: {why}", self.host))?;
        tls.handshake()
            .map_err(|why| format!("handshake {}: {why}", self.host))?;
        Ok(tls)
    }
}

use std::net::ToSocketAddrs as _;

/// The challenge host serves its script only over HTTP/2 and binds the page's state to the connection, so one connection carries every stream of a solve.
struct H2Connection {
    tls: ferrox_core::tls::ClientSession<Connection>,
    next: u32,
    decoder: crate::h2::Decoder,
}

thread_local! {
    static H2: std::cell::RefCell<Option<(String, H2Connection)>> = const { std::cell::RefCell::new(None) };
}

impl H2Connection {
    fn connect(endpoint: &Endpoint) -> Result<Self, String> {
        use crate::h2::{frame_head, MAGIC, S_WINDOW, T_SETTINGS, WINDOW};
        let mut tls = endpoint.connect_h2()?;
        let mut out = Vec::with_capacity(24 + 9 + 12);
        out.extend_from_slice(MAGIC);
        let mut settings = Vec::with_capacity(8);
        settings.extend_from_slice(&S_WINDOW.to_be_bytes());
        settings.extend_from_slice(&WINDOW.to_be_bytes());
        out.extend_from_slice(&frame_head(settings.len(), T_SETTINGS, 0, 0));
        out.extend_from_slice(&settings);
        tls.write_all(&out)
            .and_then(|()| tls.flush())
            .map_err(|why| format!("writing {} preface: {why}", endpoint.host))?;
        Ok(Self {
            tls,
            next: 1,
            decoder: crate::h2::Decoder::default(),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn request(
        &mut self,
        endpoint: &Endpoint,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Reply, String> {
        use crate::h2::{
            block_encode, frame_head, read_head_bounded, F_ACK, F_END, F_END_HEADERS, F_PADDED,
            F_PRIORITY, T_CONT, T_DATA, T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS,
        };
        let mut fields: Vec<(String, String)> = Vec::with_capacity(headers.len() + 4);
        fields.push((":method".to_owned(), method.to_owned()));
        fields.push((":path".to_owned(), path.to_owned()));
        fields.push((":scheme".to_owned(), "https".to_owned()));
        fields.push((":authority".to_owned(), endpoint.host.clone()));
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if matches!(lower.as_str(), "connection" | "host") {
                continue;
            }
            fields.push((lower, (*value).to_owned()));
        }
        let borrowed: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let block = block_encode(&borrowed);
        let stream = self.next;
        self.next += 2;
        let mut out = Vec::with_capacity(9 + block.len() + 9 + body.len());
        let flags = if body.is_empty() {
            F_END_HEADERS | F_END
        } else {
            F_END_HEADERS
        };
        out.extend_from_slice(&frame_head(block.len(), T_HEADERS, flags, stream));
        out.extend_from_slice(&block);
        if !body.is_empty() {
            out.extend_from_slice(&frame_head(body.len(), T_DATA, F_END, stream));
            out.extend_from_slice(body);
        }
        self.tls
            .write_all(&out)
            .and_then(|()| self.tls.flush())
            .map_err(|why| format!("writing {} {path}: {why}", endpoint.host))?;
        let mut block = Vec::new();
        let mut reply = Reply {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut ended = false;
        while !ended {
            let (len, kind, flags, id) = read_head_bounded(&mut self.tls)
                .ok_or_else(|| format!("reading {} {path}: frame head", endpoint.host))?;
            let mut frame = vec![0u8; len];
            std::io::Read::read_exact(&mut self.tls, &mut frame)
                .map_err(|why| format!("reading {} {path}: frame body: {why}", endpoint.host))?;
            match kind {
                T_SETTINGS if flags & F_ACK == 0 => {
                    let head = frame_head(0, T_SETTINGS, F_ACK, 0);
                    self.tls
                        .write_all(&head)
                        .and_then(|()| self.tls.flush())
                        .map_err(|why| format!("acknowledging settings: {why}"))?;
                }
                T_PING if flags & F_ACK == 0 => {
                    let head = frame_head(frame.len(), T_PING, F_ACK, 0);
                    self.tls
                        .write_all(&head)
                        .and_then(|()| self.tls.write_all(&frame))
                        .and_then(|()| self.tls.flush())
                        .map_err(|why| format!("answering ping: {why}"))?;
                }
                T_HEADERS | T_CONT if id == stream => {
                    let mut at = 0;
                    if kind == T_HEADERS {
                        if flags & F_PADDED != 0 {
                            at += 1;
                        }
                        if flags & F_PRIORITY != 0 {
                            at += 5;
                        }
                    }
                    let padding = if flags & F_PADDED != 0 {
                        usize::from(frame.first().copied().unwrap_or(0))
                    } else {
                        0
                    };
                    let end = frame.len().saturating_sub(padding);
                    block.extend_from_slice(frame.get(at..end).unwrap_or_default());
                    if flags & F_END_HEADERS != 0 {
                        let mut decode_failed = false;
                        self.decoder
                            .decode(&block, &mut |name, value| match name {
                                b":status" => {
                                    reply.status = std::str::from_utf8(value)
                                        .ok()
                                        .and_then(|text| text.parse().ok())
                                        .unwrap_or(0);
                                }
                                _ if !name.starts_with(b":") => reply.headers.push((
                                    String::from_utf8_lossy(name).into_owned(),
                                    String::from_utf8_lossy(value).into_owned(),
                                )),
                                _ => {}
                            })
                            .or_else(|| {
                                decode_failed = true;
                                None
                            });
                        if decode_failed {
                            return Err(format!("reading {} {path}: header block", endpoint.host));
                        }
                        block.clear();
                    }
                    ended = flags & F_END != 0;
                }
                T_DATA if id == stream => {
                    let mut at = 0;
                    let padding = if flags & F_PADDED != 0 {
                        at = 1;
                        usize::from(frame.first().copied().unwrap_or(0))
                    } else {
                        0
                    };
                    let end = frame.len().saturating_sub(padding);
                    reply
                        .body
                        .extend_from_slice(frame.get(at..end).unwrap_or_default());
                    ended = flags & F_END != 0;
                }
                T_RST => return Err(format!("reading {} {path}: stream reset", endpoint.host)),
                T_GOAWAY => {
                    return Err(format!(
                        "reading {} {path}: connection closed",
                        endpoint.host
                    ))
                }
                _ => {}
            }
        }
        if reply.status == 0 {
            return Err(format!("reading {} {path}: no status", endpoint.host));
        }
        Ok(reply)
    }
}

fn h2_ask(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, String> {
    let mut retried = false;
    loop {
        let result = H2.with(|cached| {
            let mut cached = cached.borrow_mut();
            let fresh = !matches!(cached.as_ref(), Some((host, _)) if host == &endpoint.host);
            if fresh {
                *cached = Some((endpoint.host.clone(), H2Connection::connect(endpoint)?));
            }
            let (_, connection) = cached.as_mut().expect("a connection was just built");
            connection.request(endpoint, method, path, headers, body)
        });
        match result {
            Ok(reply) => return Ok(reply),
            Err(why) if retried => return Err(why),
            Err(_) => {
                H2.with(|cached| *cached.borrow_mut() = None);
                retried = true;
            }
        }
    }
}

/// One request and its answer over HTTP/1.1, headers exactly as the caller wrote them: the exchange every plane of this app makes, cookie jar or none.
pub(crate) fn ask(
    endpoint: &Endpoint,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, String> {
    let mut tls = endpoint.connect()?;
    tls.write_all(&request(method, &endpoint.origin(), url, headers, body))
        .and_then(|()| tls.flush())
        .map_err(|why| format!("writing {} {url}: {why}", endpoint.host))?;
    read_reply(&mut tls).map_err(|why| format!("reading {} {url}: {why}", endpoint.host))
}

/// The browser plane's challenge only exists over HTTP/2 on the real Firefox host; every other host, and every pinned loopback edge, stays HTTP/1.1.
fn wants_h2(endpoint: &Endpoint, agent: crate::foxy_challenge::Agent) -> bool {
    !matches!(
        agent,
        crate::foxy_challenge::Agent::Api | crate::foxy_challenge::Agent::Fxa
    ) && endpoint.address.is_none()
        && endpoint.host.ends_with("firefox.com")
}

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
        crate::foxy_challenge::Agent::Api | crate::foxy_challenge::Agent::Fxa => endpoint.url(path),
        _ => path.to_owned(),
    };
    let cookie = jar.lock().ok().and_then(|jar| jar.header(&endpoint.host));
    let user_agent = agent.user_agent();
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(extra.len() + 4);
    headers.push(("User-Agent", user_agent.as_ref()));
    headers.push(("Accept", agent.accept()));
    headers.push(("Connection", "close"));
    headers.extend_from_slice(extra);
    if let Some(cookie) = cookie.as_deref() {
        headers.push(("Cookie", cookie));
    }
    // The account API answers the same bytes over HTTP/1.1; only the browser challenge needs h2.
    let reply = if wants_h2(endpoint, agent) {
        h2_ask(endpoint, method, &url, &headers, body)
    } else {
        ask(endpoint, method, &url, &headers, body)
    }
    .map_err(Denied::Unreachable)?;
    if let Ok(mut jar) = jar.lock() {
        jar.absorb(&endpoint.host, &reply);
    }
    Ok(reply)
}

/// A padding character an autofilled or pasted credential can carry: every Unicode whitespace/separator (space, NBSP, ideographic, line/paragraph breaks) plus the zero-width marks (ZWSP/ZWNJ/ZWJ) and the BOM, none of which a real address or a real code contains.
#[must_use]
fn is_padding(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}')
}

/// The identity as `FxA` accepts it: padding removed wherever it sits, then lower-cased to the form the stretch salt and the login body must agree on.
#[must_use]
fn normalize_identity(email: &str) -> String {
    email
        .chars()
        .filter(|c| !is_padding(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

/// The two-factor code with its padding removed but its case untouched: only the digits reach the edge.
#[must_use]
fn sanitize_code(code: &str) -> String {
    code.chars().filter(|c| !is_padding(*c)).collect()
}

/// The Firefox Accounts hosts a password may be sent to: the OAuth origin today, the API origin the older client used, and each as the other's fallback.
const FXA_HOSTS: [&str; 2] = ["oauth.accounts.firefox.com", "api.accounts.firefox.com"];

/// Every origin worth asking, the caller's own first: a host that answers a challenge or a 404 is not a dead account.
fn fxa_attempts(endpoint: &Endpoint) -> Vec<Endpoint> {
    let mut hosts = vec![endpoint.host.clone()];
    for host in FXA_HOSTS {
        if host != endpoint.host && !hosts.iter().any(|seen| seen == host) {
            hosts.push(host.to_owned());
        }
    }
    hosts.iter().map(|host| endpoint.with_host(host)).collect()
}

/// The session a password sign-in produced and what `FxA` says it still wants before the session is fully verified.
pub(crate) struct Login {
    session: String,
    verified: bool,
    method: Option<String>,
}

/// The `FxA` login, tried without the two-factor method first: the first attempt's error is the reason to drop it.
pub(crate) fn login(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    email: &str,
    password: &str,
) -> Result<Login, Denied> {
    // An autofilled or pasted identity carries padding FxA rejects and a casing the stretch must not depend on; drop every separator, zero-width mark and BOM wherever it sits and lower-case to the one form the salt and the body must agree on.
    let email = normalize_identity(email);
    let stretched = account::auth_pw(&email, password);
    let mut last = Denied::Unreachable("no Firefox Accounts host".to_owned());
    for endpoint in fxa_attempts(endpoint) {
        match login_on(&endpoint, jar, &email, &stretched) {
            Ok(signed) => return Ok(signed),
            Err(denied) if host_may_fallback(&denied) => last = denied,
            Err(denied) => return Err(denied),
        }
    }
    Err(last)
}

/// A refusal about the credential itself is the account's answer, not a reason to ask another origin; a challenge, a missing route and an unreachable plane are.
fn host_may_fallback(denied: &Denied) -> bool {
    matches!(
        denied,
        Denied::Unreachable(_) | Denied::Challenged(_) | Denied::Other(0 | 404 | 405 | 406)
    ) || matches!(denied, Denied::Other(status) if *status >= 500)
}

fn login_on(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    email: &str,
    stretched: &str,
) -> Result<Login, Denied> {
    for method in [None, Some("email-2fa")] {
        let body = account::login_body(email, stretched, method);
        let reply = foxy_challenge::send_fxa(
            endpoint,
            jar,
            "POST",
            "/account/login",
            &[("Content-Type", JSON_ACCEPT)],
            &body,
        )?;
        if let Some(errno) = errno(&reply) {
            if errno == 107 && method.is_none() {
                continue;
            }
            return Err(Denied::Other(reply.status));
        }
        if let Some(denied) = reply.denied() {
            return Err(denied);
        }
        let session = reply.field("sessionToken").ok_or(Denied::Token)?;
        return Ok(Login {
            session,
            verified: reply.field("verified").is_some_and(|v| v == "true"),
            method: reply.field("verificationMethod"),
        });
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
    timestamp: u64,
) -> Result<Auth, Denied> {
    let body = match (session_token, refresh_token) {
        (Some(_), _) => account::token_body("fxa-credentials", None),
        (None, Some(refresh)) => account::token_body("refresh_token", Some(refresh)),
        (None, None) => return Err(Denied::Token),
    };
    let mut last = Denied::Token;
    for endpoint in fxa_attempts(endpoint) {
        for (at, path) in token_paths(&endpoint, session_token.is_some())
            .into_iter()
            .enumerate()
        {
            let authorization = session_token.and_then(|session| {
                let (id, mac) = account::hawk_credentials(session)?;
                let nonce = nonce();
                Some(
                    Signed {
                        method: "POST",
                        path: &endpoint.url(path),
                        host: &endpoint.origin(),
                        port: endpoint.port,
                        body: &body,
                        timestamp,
                        nonce: &nonce,
                    }
                    .header(&id, &mac),
                )
            });
            let mut headers: Vec<(&str, &str)> = vec![("Content-Type", JSON_ACCEPT)];
            if let Some(authorization) = authorization.as_deref() {
                headers.push(("Authorization", authorization));
            }
            let reply =
                match foxy_challenge::send_fxa(&endpoint, jar, "POST", path, &headers, &body) {
                    Ok(reply) => reply,
                    Err(denied) if host_may_fallback(&denied) => {
                        last = denied;
                        continue;
                    }
                    Err(denied) => return Err(denied),
                };
            match token_reply(&reply, refresh_token, timestamp, session_token.is_some()) {
                Ok(auth) => return Ok(auth),
                // A credential refusal on the origin's own route is the account's answer; the other spelling was only a probe, so ask the other host.
                Err(denied @ (Denied::Token | Denied::Quota(_))) if at == 0 => return Err(denied),
                Err(denied) => last = denied,
            }
        }
    }
    Err(last)
}

/// The token route each origin publishes: the OAuth origin renews at `/token`, the auth origin at `/oauth/token`, and the other spelling is tried before the other host.
fn token_paths(endpoint: &Endpoint, session_token: bool) -> [&'static str; 2] {
    if !session_token && endpoint.host.starts_with("oauth.") {
        ["/token", "/oauth/token"]
    } else {
        ["/oauth/token", "/token"]
    }
}

fn token_reply(
    reply: &Reply,
    refresh_token: Option<&str>,
    timestamp: u64,
    session_token: bool,
) -> Result<Auth, Denied> {
    if let Some(denied) = reply.denied() {
        return Err(denied);
    }
    // A refresh grant FxA refuses outright is dead, not a plane to ask again: 400 joins the 401/403s that mean sign-in.
    if !session_token && reply.status == 400 {
        return Err(Denied::Token);
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
    if let Some(denied) = reply.denied() {
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
        token: std::sync::Arc::from(token),
        expires_at,
        quota_remaining: reply.header_number("X-Quota-Remaining"),
        quota_reset: reply.header_number("X-Quota-Reset"),
        quota_limit: reply.header_number("X-Quota-Limit"),
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
    fn the_account_hosts_fall_back_both_ways() {
        let roots: ferrox_core::tls::Anchors = Vec::new().into();
        let oauth = Endpoint::parse("https://oauth.accounts.firefox.com/v1", roots.clone())
            .expect("parses");
        let hosts: Vec<String> = fxa_attempts(&oauth)
            .into_iter()
            .map(|endpoint| endpoint.host)
            .collect();
        assert_eq!(
            hosts,
            ["oauth.accounts.firefox.com", "api.accounts.firefox.com"]
        );
        let api = Endpoint::parse("https://api.accounts.firefox.com/v1", roots).expect("parses");
        let hosts: Vec<String> = fxa_attempts(&api)
            .into_iter()
            .map(|endpoint| endpoint.host)
            .collect();
        assert_eq!(
            hosts,
            ["api.accounts.firefox.com", "oauth.accounts.firefox.com"]
        );
    }

    #[test]
    fn a_token_route_is_the_one_each_origin_publishes() {
        let roots: ferrox_core::tls::Anchors = Vec::new().into();
        let oauth = Endpoint::parse("https://oauth.accounts.firefox.com/v1", roots.clone())
            .expect("parses");
        assert_eq!(token_paths(&oauth, false), ["/token", "/oauth/token"]);
        assert_eq!(token_paths(&oauth, true), ["/oauth/token", "/token"]);
        let api = Endpoint::parse("https://api.accounts.firefox.com/v1", roots).expect("parses");
        assert_eq!(token_paths(&api, false), ["/oauth/token", "/token"]);
    }

    #[test]
    fn only_the_browser_plane_on_the_real_firefox_host_speaks_h2() {
        let roots = Vec::new().into();
        let fxa = Endpoint::parse("https://oauth.accounts.firefox.com/v1", roots).expect("parses");
        assert!(!wants_h2(&fxa, crate::foxy_challenge::Agent::Api));
        assert!(!wants_h2(&fxa, crate::foxy_challenge::Agent::Fxa));
        assert!(wants_h2(&fxa, crate::foxy_challenge::Agent::Page));
        assert!(wants_h2(&fxa, crate::foxy_challenge::Agent::Text));
        assert!(wants_h2(&fxa, crate::foxy_challenge::Agent::TextApi));
        let pinned = Endpoint {
            address: Some("127.0.0.1:1".parse().expect("addr")),
            ..fxa
        };
        assert!(!wants_h2(&pinned, crate::foxy_challenge::Agent::Page));
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
        assert_eq!(Denied::of(429), Some(Denied::Quota(0)));
        assert_eq!(Denied::of(500), None);
        assert!(Denied::of(406)
            .expect("challenged")
            .to_string()
            .contains("challenge"));
    }

    /// The wait only a head can name, read where the status is decided.
    #[test]
    fn a_rate_limit_carries_the_wait_its_head_names() {
        let with = Reply {
            status: 429,
            headers: vec![("Retry-After".to_owned(), " 37 ".to_owned())],
            body: Vec::new(),
        };
        assert_eq!(with.denied(), Some(Denied::Quota(37)));
        assert_eq!(with.denied().expect("quota").retry_after(), 37);
        let without = Reply {
            status: 429,
            headers: vec![("Content-Length".to_owned(), "0".to_owned())],
            body: Vec::new(),
        };
        assert_eq!(
            without.denied(),
            Denied::of(429),
            "a silent 429 names no wait"
        );
        let date = Reply {
            status: 429,
            headers: vec![(
                "Retry-After".to_owned(),
                "Wed, 21 Oct 2026 07:28:00 GMT".to_owned(),
            )],
            body: Vec::new(),
        };
        assert_eq!(
            date.denied(),
            Some(Denied::Quota(0)),
            "the date form is not a number, so no wait"
        );
        let refused = Reply {
            status: 401,
            headers: vec![("Retry-After".to_owned(), "37".to_owned())],
            body: Vec::new(),
        };
        assert_eq!(
            refused.denied(),
            Some(Denied::Token),
            "only a rate limit names a wait"
        );
    }

    /// The refusal that ends a renewal, and the ones that only slow it down.
    #[test]
    fn a_refused_credential_is_the_only_answer_a_second_ask_cannot_change() {
        assert!(Denied::Token.is_final());
        assert!(
            !Denied::Token.is_retryable(),
            "the credential itself is the end"
        );
        let refused_pass = Denied::Pass;
        assert!(!refused_pass.is_final(), "a refused pass keeps the grant");
        assert!(
            !refused_pass.is_retryable(),
            "and a second ask with the same account cannot change it"
        );
        for slow in [
            Denied::Quota(0),
            Denied::Quota(37),
            Denied::Challenged(406),
            Denied::Unreachable("dial".to_owned()),
            Denied::Other(500),
        ] {
            assert!(!slow.is_final(), "{slow}");
            assert!(slow.is_retryable(), "{slow}");
        }
        assert_eq!(Denied::Quota(37).retry_after(), 37);
        assert_eq!(
            Denied::Other(429).retry_after(),
            0,
            "only a quota names a wait"
        );
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
        let endpoint =
            Endpoint::parse("https://vpn.mozilla.org", Vec::new().into()).expect("parses");
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
        assert!(Endpoint::parse("http://vpn.mozilla.org", Vec::new().into()).is_none());
        assert!(Endpoint::parse("vpn.mozilla.org", Vec::new().into()).is_none());
        assert_eq!(
            Endpoint::parse("https://127.0.0.1:8443", Vec::new().into())
                .expect("parses")
                .address,
            Some("127.0.0.1:8443".parse().expect("addr")),
            "a numeric origin is read at the parse, so an ask dials it without asking the resolver"
        );
        assert_eq!(
            Endpoint::parse("https://host:8443", Vec::new().into())
                .expect("parses")
                .port,
            8443
        );
    }

    /// The pause before the next ask: the plane's own when it names one, else a curve that grows and stops growing.
    #[test]
    fn the_next_ask_waits_the_gap_the_plane_names_or_a_curve_that_caps() {
        let named = Denied::Quota(37);
        assert_eq!(renewal_gap(&named, 0, Some(600)), Duration::from_secs(37));
        assert_eq!(
            renewal_gap(&named, 4, Some(10)),
            Duration::from_secs(37),
            "a named wait outlives the pass rather than hammering the plane"
        );
        assert_eq!(
            renewal_gap(&Denied::Quota(u64::MAX), 0, None),
            Duration::from_secs(crate::budgets::ACCOUNT_NAMED_WAIT_MAX),
            "a wait past the named ceiling is not slept on"
        );
        let guessed = Denied::Unreachable("dial".to_owned());
        for (attempt, want) in [
            (0, 5),
            (1, 10),
            (2, 20),
            (3, 40),
            (4, 80),
            (5, 160),
            (6, 320),
            (7, 640),
            (8, 900),
            (64, 900),
        ] {
            assert_eq!(
                renewal_gap(&guessed, attempt, None),
                Duration::from_secs(want)
            );
        }
        assert_eq!(
            renewal_gap(&guessed, 2, Some(7)),
            Duration::from_secs(7),
            "a pass about to lapse is asked about sooner"
        );
        assert_eq!(
            renewal_gap(&guessed, 2, Some(0)),
            Duration::from_secs(1),
            "a lapsed pass still leaves a second between asks"
        );
        assert_eq!(
            renewal_gap(&Denied::Token, 0, Some(7)),
            Duration::from_secs(5),
            "a token refusal is asked by nothing: is_final ends the clock before the gap"
        );
    }
}

#[cfg(test)]
mod activation {
    use super::loopback::{ACTIVE, EDGE, TWO_FACTOR};

    /// An account that never activated its entitlement is refused a pass: activate, mint again, one retry.
    #[test]
    fn a_refused_pass_is_activated_once_and_minted_again() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
        // The edge mints only for a verified session; a turn that left the two-factor flag set would park this sign-in at the code instead.
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
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
    /// The method that stopped the sign-in, so an authenticator code goes to its own route.
    pub(crate) pending_method: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    /// One jar for both hosts, so a challenge solved on one is not solved twice.
    pub(crate) jar: std::sync::Arc<Mutex<Jar>>,
    pub(crate) auth: std::sync::Arc<std::sync::Mutex<Auth>>,
    pub(crate) pass: std::sync::Arc<std::sync::Mutex<Pass>>,
    /// Where the grant is kept between launches; none is a lane that signs in every time.
    pub(crate) tokens: Option<TokenFile>,
}

pub(crate) fn epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn nonce() -> String {
    let mut raw = [0u8; 6];
    getrandom::fill(&mut raw).unwrap_or_default();
    ferrox_core::b64::encode(&raw)
}

impl Account {
    /// Signs in, exchanges the session token, and mints the first pass.
    pub(crate) fn sign_in(&self, email: &str, password: &str) -> Result<(), Denied> {
        let now = epoch();
        let Login {
            session,
            verified,
            method,
        } = login(&self.fxa, &self.jar, email, password)?;
        // A two-factor session needs its code; an email-verification session still exchanges, so the password path does not fall back to a browser.
        if !verified
            && method
                .as_deref()
                .is_some_and(|method| method.ends_with("-2fa"))
        {
            *self.pending.lock().map_err(|_| Denied::Token)? = Some(session);
            *self.pending_method.lock().map_err(|_| Denied::Token)? = method;
            self.persist();
            return Ok(());
        }
        self.exchange(&session, now)
    }

    /// Exchanges a session token already minted by the sign-in page, skipping the password and its challenge.
    pub(crate) fn sign_in_session(&self, session: &str) -> Result<(), Denied> {
        let session = session.trim().trim_matches('"').to_ascii_lowercase();
        if session.len() != 64 || !session.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Denied::Token);
        }
        self.exchange(&session, epoch())
    }

    /// Continues from the grant a previous launch stored: a live access token is used, a lapsed one is refreshed, and only a rejected grant reaches the password again.
    pub(crate) fn resume(&self, session: Session) -> Result<(), Denied> {
        if let Some(pending) = session.pending {
            *self.pending.lock().map_err(|_| Denied::Token)? = Some(pending);
            *self.pending_method.lock().map_err(|_| Denied::Token)? = session.pending_method;
            return Ok(());
        }
        let auth = session.auth.ok_or(Denied::Token)?;
        let current = self.auth.lock().map_err(|_| Denied::Token)?.clone();
        // A retry keeps the grant a refresh already rotated in, rather than spending the old token a second time.
        let auth = if !current.access_token.is_empty() && current.valid_at(epoch()) {
            current
        } else {
            *self.auth.lock().map_err(|_| Denied::Token)? = auth.clone();
            auth
        };
        if auth.valid_at(epoch()) {
            match self.mint(&auth.access_token) {
                // A clock-valid token the plane refuses is not a dead session until a refresh says so: spend the grant, not the password.
                Err(Denied::Token) if !auth.refresh_token.is_empty() => {
                    let fresh = self.refresh(&auth, true)?;
                    self.mint(&fresh.access_token).map_err(refused_pass)
                }
                other => other,
            }
        } else if !auth.refresh_token.is_empty() {
            let fresh = self.refresh(&auth, false)?;
            self.mint(&fresh.access_token).map_err(refused_pass)
        } else {
            Err(Denied::Token)
        }
    }

    /// Forgets a grant the plane refused, so the next launch asks for the password instead of replaying a dead token.
    pub(crate) fn forget(&self) {
        let refused = self
            .auth
            .lock()
            .map(|auth| auth.access_token.clone())
            .unwrap_or_default();
        if let Ok(mut auth) = self.auth.lock() {
            *auth = Auth {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: 0,
            };
        }
        if let Some(tokens) = &self.tokens {
            tokens.clear_if(&refused);
        }
    }

    /// Sets the new grant before minting so a refresh that is written but not yet used still renews the next launch; `forced` stops trusting a clock the plane has already refused.
    fn refresh(&self, stale: &Auth, forced: bool) -> Result<Auth, Denied> {
        // Another lane may have rotated the file's grant since this launch loaded it: that refresh token is the live one, even when its access token has lapsed.
        let base = self
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.rotated_from(&stale.access_token))
            .unwrap_or_else(|| stale.clone());
        // The forced grant was refused, but a rotation another lane wrote since is untried: adopting it spends nothing.
        if base.valid_at(epoch()) && (!forced || base.access_token != stale.access_token) {
            return Ok(self.adopt(base));
        }
        let now = epoch();
        let fresh = match token(&self.fxa, &self.jar, None, Some(&base.refresh_token), now) {
            Ok(fresh) => fresh,
            Err(Denied::Token) => {
                // A refusal can mean another lane spent this rotating grant first: give its write a second before asking for a password.
                let mut adopted = None;
                for _ in 0..5 {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    adopted = self
                        .tokens
                        .as_ref()
                        .and_then(|tokens| tokens.rotated_from(&base.access_token))
                        .filter(|fresh| fresh.valid_at(epoch()))
                        .map(|fresh| self.adopt(fresh));
                    if adopted.is_some() {
                        break;
                    }
                }
                adopted.ok_or(Denied::Token)?
            }
            Err(other) => return Err(other),
        };
        *self.auth.lock().map_err(|_| Denied::Token)? = fresh.clone();
        self.persist();
        Ok(fresh)
    }

    /// The grant another lane rotated in, kept in memory so the pass and the next refresh use it.
    fn adopt(&self, fresh: Auth) -> Auth {
        if let Ok(mut auth) = self.auth.lock() {
            *auth = fresh.clone();
        }
        fresh
    }

    fn persist(&self) {
        let Some(tokens) = &self.tokens else {
            return;
        };
        let auth = self.auth.lock().ok().map(|auth| auth.clone());
        let pending = self.pending.lock().ok().and_then(|pending| pending.clone());
        let method = self
            .pending_method
            .lock()
            .ok()
            .and_then(|method| method.clone());
        tokens.save_pending(auth.as_ref(), pending.as_deref(), method.as_deref());
    }

    /// Turns a session token into an access token and mints the first pass.
    fn exchange(&self, session: &str, now: u64) -> Result<(), Denied> {
        let auth = token(&self.fxa, &self.jar, Some(session), None, now)?;
        *self.auth.lock().map_err(|_| Denied::Token)? = auth.clone();
        *self.pending.lock().map_err(|_| Denied::Token)? = None;
        *self.pending_method.lock().map_err(|_| Denied::Token)? = None;
        self.persist();
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
        // The code arrives from the same autofill that pads the identity; strip its padding, keep its case, before it is sent.
        let code = sanitize_code(code);
        let body = account::code_body(&code);
        let method = self
            .pending_method
            .lock()
            .map_err(|_| Denied::Token)?
            .clone();
        let totp = method.as_deref() == Some("totp-2fa");
        let path = if totp {
            "/session/verify/totp"
        } else {
            "/session/verify_code"
        };
        let (id, mac) = account::hawk_credentials(&session).ok_or(Denied::Token)?;
        let mut last = Denied::Unreachable("no Firefox Accounts host".to_owned());
        for endpoint in fxa_attempts(&self.fxa) {
            let now = epoch();
            let nonce = nonce();
            let authorization = Signed {
                method: "POST",
                path: &endpoint.url(path),
                host: &endpoint.origin(),
                port: endpoint.port,
                body: &body,
                timestamp: now,
                nonce: &nonce,
            }
            .header(&id, &mac);
            let reply = match foxy_challenge::send_fxa(
                &endpoint,
                &self.jar,
                "POST",
                path,
                &[
                    ("Content-Type", JSON_ACCEPT),
                    ("Authorization", &authorization),
                ],
                &body,
            ) {
                Ok(reply) => reply,
                Err(denied) if host_may_fallback(&denied) => {
                    last = denied;
                    continue;
                }
                Err(denied) => return Err(denied),
            };
            // A refused code is the account's answer; a host that does not publish the route is not.
            if let Some(denied) = reply.denied() {
                return Err(denied);
            }
            if !(200..300).contains(&reply.status) {
                let denied = Denied::Other(reply.status);
                if host_may_fallback(&denied) {
                    last = denied;
                    continue;
                }
                return Err(denied);
            }
            if totp && reply.field("success").as_deref() != Some("true") {
                return Err(Denied::Token);
            }
            let now = epoch();
            *self.pending.lock().map_err(|_| Denied::Token)? = None;
            return self.exchange(&session, now);
        }
        Err(last)
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
        let auth = self.auth.lock().map_err(|_| Denied::Token)?.clone();
        let auth = if auth.valid_at(epoch()) {
            auth
        } else {
            self.refresh(&auth, false)?
        };
        match self.mint(&auth.access_token) {
            // The plane refused a token FxA still calls live: one forced refresh tells a revoked token from a refused account.
            Err(Denied::Token) if !auth.refresh_token.is_empty() => {
                let fresh = self.refresh(&auth, true)?;
                self.mint(&fresh.access_token).map_err(refused_pass)
            }
            other => other,
        }
    }

    /// Whether a renewal has anything to renew with: a pasted pass alone does not.
    pub(crate) fn can_renew(&self) -> bool {
        self.auth
            .lock()
            .is_ok_and(|auth| !auth.refresh_token.is_empty())
    }

    /// How long until the current pass wants replacing.
    pub(crate) fn renews_in(&self) -> std::time::Duration {
        self.pass
            .lock()
            .map_or(std::time::Duration::from_secs(240), |pass| {
                pass.renews_in(epoch())
            })
    }

    /// What the carried pass has left before it lapses, for a pause that must not outlive it.
    #[must_use]
    pub(crate) fn pass_left(&self) -> Option<u64> {
        self.pass
            .lock()
            .ok()
            .and_then(|pass| pass.expires_at)
            .map(|at| at.saturating_sub(epoch()))
    }

    pub(crate) fn current(&self) -> Pass {
        self.pass.lock().map_or_else(
            |_| Pass {
                token: std::sync::Arc::from(""),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
                quota_limit: None,
            },
            |pass| pass.clone(),
        )
    }
}

/// A pass refused after `FxA` accepted the grant is an entitlement refusal, not a dead session: keeping the grant avoids a password and its mail.
fn refused_pass(denied: Denied) -> Denied {
    match denied {
        Denied::Token => Denied::Pass,
        other => other,
    }
}

/// When to ask the plane again: its own wait when it names one, else a pause that grows, and never one that would land after the pass still being carried has lapsed.
#[must_use]
pub(crate) fn renewal_gap(
    denied: &Denied,
    attempt: u32,
    pass_left: Option<u64>,
) -> std::time::Duration {
    if let Some(wait) = (denied.retry_after() > 0).then_some(denied.retry_after()) {
        return std::time::Duration::from_secs(
            wait.clamp(1, crate::budgets::ACCOUNT_NAMED_WAIT_MAX),
        );
    }
    let guessed = (crate::budgets::ACCOUNT_BACKOFF_SECS << attempt.min(8))
        .min(crate::budgets::ACCOUNT_RETRY_CAP);
    std::time::Duration::from_secs(pass_left.map_or(guessed, |left| guessed.min(left).max(1)))
}

#[cfg(test)]
mod renewal {
    use super::*;

    fn account_with(pass: Pass) -> Account {
        Account {
            fxa: Endpoint::parse(ferrox_core::foxy::account::FXA_SERVER, Vec::new().into())
                .expect("parses"),
            guardian: Endpoint::parse("https://vpn.mozilla.org", Vec::new().into())
                .expect("parses"),
            jar: std::sync::Arc::new(Mutex::new(Jar::default())),
            pending: std::sync::Arc::new(std::sync::Mutex::new(None)),
            pending_method: std::sync::Arc::new(std::sync::Mutex::new(None)),
            auth: std::sync::Arc::new(std::sync::Mutex::new(Auth {
                access_token: "a".to_owned(),
                refresh_token: "r".to_owned(),
                expires_at: 0,
            })),
            pass: std::sync::Arc::new(std::sync::Mutex::new(pass)),
            tokens: None,
        }
    }

    #[test]
    fn the_clock_a_pass_asks_for_is_the_one_the_core_wrote() {
        let account = account_with(Pass {
            token: std::sync::Arc::from("t"),
            expires_at: Some(epoch() + 600),
            quota_remaining: None,
            quota_reset: None,
            quota_limit: None,
        });
        let want = account.current().renews_in(epoch());
        assert_eq!(account.renews_in(), want);
    }

    /// A pasted pass has no grant to renew with, so the renewal thread would only spend plane calls.
    #[test]
    fn only_a_signed_in_account_can_renew() {
        let account = account_with(Pass {
            token: std::sync::Arc::from("t"),
            expires_at: None,
            quota_remaining: None,
            quota_reset: None,
            quota_limit: None,
        });
        assert!(
            account.can_renew(),
            "the signed-in account holds a refresh grant"
        );
        *account.auth.lock().expect("locks") = Auth {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
        };
        assert!(!account.can_renew(), "a pasted pass renews with nothing");
    }

    #[test]
    fn an_unknown_expiry_asks_for_the_four_minute_fallback() {
        let account = account_with(Pass {
            token: std::sync::Arc::from("t"),
            expires_at: None,
            quota_remaining: None,
            quota_reset: None,
            quota_limit: None,
        });
        assert_eq!(account.renews_in(), std::time::Duration::from_secs(240));
        assert_eq!(account.current().token.as_ref(), "t");
    }
}

#[cfg(test)]
mod loopback {
    use super::*;
    use crate::conn::Listener;
    use std::sync::mpsc;

    pub(crate) const HOSTS: [&str; 3] = [
        "api.accounts.firefox.com",
        "oauth.accounts.firefox.com",
        "vpn.mozilla.org",
    ];
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
    /// Whether the edge refuses the `MozillaVPN` agent on `FxA` calls, the UA-class denial the pinned Firefox identity clears.
    pub(crate) static REFUSE_VPN_AGENT: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// Whether the edge refuses the Firefox identity everywhere, the revert the old `MozillaVPN` path still has to clear.
    pub(crate) static REFUSE_FIREFOX_AGENT: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// Arms the UA-class refusal and clears it even when a test panics.
    struct DenyVpnAgent;

    impl DenyVpnAgent {
        fn arm() -> Self {
            REFUSE_VPN_AGENT.store(true, std::sync::atomic::Ordering::Relaxed);
            Self
        }
    }

    impl Drop for DenyVpnAgent {
        fn drop(&mut self) {
            REFUSE_VPN_AGENT.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    struct DenyFirefoxAgent;

    impl DenyFirefoxAgent {
        fn arm() -> Self {
            REFUSE_FIREFOX_AGENT.store(true, std::sync::atomic::Ordering::Relaxed);
            Self
        }
    }

    impl Drop for DenyFirefoxAgent {
        fn drop(&mut self) {
            REFUSE_FIREFOX_AGENT.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn firefox_agent() -> String {
        crate::foxy_challenge::Agent::Fxa.user_agent().into_owned()
    }

    #[derive(Debug, Clone)]
    pub(crate) struct Seen {
        method: String,
        path: String,
        host: String,
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
            host: String::new(),
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
                "host" => seen.host = value.trim().to_owned(),
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

    fn session_answer(method: Option<&str>) -> String {
        let verified = method.is_none();
        let method = method
            .map(|method| format!(r#","verificationMethod":"{method}""#))
            .unwrap_or_default();
        format!(r#"{{"sessionToken":"{SESSION}","verified":{verified}{method}}}"#)
    }

    /// The whole account plane on one loopback port: challenge, sign-in, Hawk-signed exchange, pass.
    pub(crate) fn serve(
        listener: &Listener,
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

    /// A Hawk-signed session exchange mints the first pair; an unsigned refresh rotates the stored one.
    fn token_answer(seen: &Seen) -> Vec<u8> {
        let body = String::from_utf8_lossy(&seen.body);
        if body.contains(r#""grant_type":"refresh_token""#) {
            assert!(
                seen.authorization.is_none(),
                "a refresh grant is not Hawk-signed"
            );
            let minted = if body.contains(r#""refresh_token":"refresh-1""#) {
                r#"{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}"#
            } else if body.contains(r#""refresh_token":"refresh-7""#) {
                r#"{"access_token":"access-9","refresh_token":"refresh-9","expires_in":3600}"#
            } else if body.contains(r#""refresh_token":"refresh-8""#) {
                r#"{"access_token":"access-10","refresh_token":"refresh-10","expires_in":3600}"#
            } else {
                return reply(400, &[], r#"{"errno":110}"#);
            };
            return reply(200, &[], minted);
        }
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

    fn code_answer(seen: &Seen, totp: bool) -> Vec<u8> {
        assert!(
            seen.authorization
                .as_deref()
                .is_some_and(|header| header.starts_with("Hawk ")),
            "the code is signed with the pending session: {:?}",
            seen.authorization
        );
        if totp && seen.body == br#"{"code":"000000"}"# {
            return reply(200, &[], r#"{"success":false}"#);
        }
        assert_eq!(
            seen.body,
            br#"{"code":"424242"}"#.to_vec(),
            "{:?}",
            seen.body
        );
        if totp {
            reply(200, &[], r#"{"success":true}"#)
        } else {
            reply(200, &[], "{}")
        }
    }

    fn answer(seen: &Seen, tx: &mpsc::Sender<Seen>) -> Vec<u8> {
        let _ = tx.send(seen.clone());
        if REFUSE_FIREFOX_AGENT.load(std::sync::atomic::Ordering::Relaxed)
            && seen.agent == firefox_agent()
        {
            return reply(406, &[], "");
        }
        if REFUSE_VPN_AGENT.load(std::sync::atomic::Ordering::Relaxed)
            && seen.agent == USER_AGENT
            && seen.path.starts_with("/v1/")
        {
            return reply(406, &[], "");
        }
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
                assert!(!body.contains("detector_results"), "{body}");
                assert!(!body.contains("\"v\":"), "{body}");
                reply(
                    200,
                    &[("Set-Cookie", "_fs_chl=cleared; Path=/; Domain=firefox.com")],
                    r#"{"status":"success"}"#,
                )
            }
            ("POST", "/v1/account/login") => {
                let cleared = seen
                    .cookie
                    .as_deref()
                    .is_some_and(|c| c.contains("_fs_chl=cleared"));
                // The pinned Firefox identity is accepted as a UA class, so it logs in without solving the page.
                if !cleared && seen.agent != firefox_agent() {
                    return reply(406, &[], "");
                }
                let body = String::from_utf8_lossy(&seen.body);
                assert!(
                    body.contains(r#""email":"person@example.com""#)
                        || body.contains(r#""email":"verify@example.com""#)
                        || body.contains(r#""email":"totp@example.com""#),
                    "the login must carry the trimmed identity: {body}"
                );
                let two_factor = body.contains(r#""verificationMethod":"email-2fa""#);
                if TWO_FACTOR.load(std::sync::atomic::Ordering::Relaxed) && !two_factor {
                    return reply(400, &[], r#"{"errno":107}"#);
                }
                let method = if two_factor {
                    Some("email-2fa")
                } else if body.contains(r#""email":"totp@example.com""#) {
                    Some("totp-2fa")
                } else if body.contains(r#""email":"verify@example.com""#) {
                    Some("email")
                } else {
                    None
                };
                reply(200, &[], &session_answer(method))
            }
            ("POST", "/v1/oauth/token" | "/v1/token") => token_answer(seen),
            ("POST", "/v1/session/verify_code") => code_answer(seen, false),
            ("POST", "/v1/session/verify/totp") => code_answer(seen, true),
            ("POST", "/api/v1/fpn/activate") => {
                ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
                reply(200, &[], r#"{"subscribed":true,"maxBytes":5368709120}"#)
            }
            ("GET", "/api/v1/fpn/token") if !ACTIVE.load(std::sync::atomic::Ordering::Relaxed) => {
                reply(401, &[], "")
            }
            ("GET", "/api/v1/fpn/token") => {
                let bearer = seen.authorization.as_deref().unwrap_or_default();
                match bearer {
                    "Bearer access-1" | "Bearer access-2" | "Bearer access-9" => {
                        reply(200, &PASS_HEADERS, PASS_BODY)
                    }
                    // A clock-valid grant the plane has revoked: refreshable, but not mintable until it is.
                    "Bearer access-6" | "Bearer access-7" | "Bearer access-8"
                    | "Bearer access-10" => reply(401, &[], ""),
                    other => panic!("a resumed grant mints with the token it carries: {other:?}"),
                }
            }
            _ => reply(404, &[], "{}"),
        }
    }

    pub(crate) fn account(
        address: std::net::SocketAddr,
        roots: ferrox_core::tls::Anchors,
    ) -> Account {
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
            pending_method: std::sync::Arc::new(std::sync::Mutex::new(None)),
            auth: std::sync::Arc::new(std::sync::Mutex::new(Auth {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: 0,
            })),
            pass: std::sync::Arc::new(std::sync::Mutex::new(Pass {
                token: std::sync::Arc::from(""),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
                quota_limit: None,
            })),
            tokens: None,
        }
    }

    /// The edge loopback two tests share: a certificate, a port and a listener with the whole plane behind it.
    pub(crate) fn edge() -> (std::net::SocketAddr, ferrox_core::tls::Anchors) {
        let (address, roots, _rx) = edge_with_log();
        (address, roots)
    }

    /// The same edge with its request log, for the turns that prove what was not asked.
    fn edge_with_log() -> (
        std::net::SocketAddr,
        ferrox_core::tls::Anchors,
        mpsc::Receiver<Seen>,
    ) {
        let minted = rcgen::generate_simple_self_signed(
            HOSTS
                .iter()
                .map(|host| (*host).to_owned())
                .collect::<Vec<String>>(),
        )
        .expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let key_pem = crate::quic::der_to_pem(&minted.signing_key.serialize_der(), "PRIVATE KEY");
        let root = ferrox_core::tls::parse_pem_identity(minted.cert.pem().as_bytes(), &key_pem)
            .expect("identity");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || serve(&listener, &root, &tx));
        (
            format!("127.0.0.1:{port}").parse().expect("addr"),
            roots.into(),
            rx,
        )
    }

    #[test]
    fn an_account_signs_in_and_mints_a_pass() {
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
        let key_pem = crate::quic::der_to_pem(&minted.signing_key.serialize_der(), "PRIVATE KEY");
        let root = ferrox_core::tls::parse_pem_identity(minted.cert.pem().as_bytes(), &key_pem)
            .expect("identity");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || serve(&listener, &root, &tx));

        let address = format!("127.0.0.1:{port}").parse().expect("addr");
        let account = account(address, roots.into());
        account
            .sign_in("person@example.com", "hunter2")
            .expect("signs in");
        let pass = account.current();
        assert!(pass.token.starts_with("eyJ"), "{}", pass.token);
        assert_eq!(pass.expires_at, Some(1_735_689_600));
        assert_eq!(pass.quota_remaining, Some(4_294_967_296));
        assert_eq!(
            pass.quota_limit,
            Some(5_368_709_120),
            "the ceiling the plane named rides with the remainder"
        );
        assert!(!account.needs_code());

        let seen: Vec<String> = rx
            .try_iter()
            .map(|s| format!("{} {}", s.method, s.path))
            .collect();
        assert_eq!(
            seen.first().map(String::as_str),
            Some("POST /v1/account/login")
        );
        assert!(
            !seen.iter().any(|line| line == "GET /"),
            "the Firefox identity needs no challenge page: {seen:?}"
        );
        assert_eq!(
            seen.last().map(String::as_str),
            Some("GET /api/v1/fpn/token")
        );
    }

    /// A UA-class `406` on `FxA` is cleared by the pinned Firefox identity, with no challenge page in the log.
    #[test]
    fn the_firefox_identity_clears_an_agent_class_refusal() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let _denied = DenyVpnAgent::arm();
        let (address, roots, rx) = edge_with_log();
        let account = account(address, roots);
        account
            .sign_in("person@example.com", "hunter2")
            .expect("the Firefox identity clears the refusal");
        let firefox = crate::foxy_challenge::Agent::Fxa.user_agent();
        let log: Vec<Seen> = rx.try_iter().collect();
        assert!(
            log.iter().all(|seen| seen.path != "/"),
            "no challenge page was fetched: {log:?}"
        );
        assert!(
            log.iter()
                .filter(|seen| seen.host.ends_with("accounts.firefox.com"))
                .all(|seen| seen.agent == firefox.as_ref()),
            "every FxA call presents the Firefox identity: {log:?}"
        );
        assert!(
            log.iter()
                .filter(|seen| seen.host == "vpn.mozilla.org")
                .all(|seen| seen.agent == USER_AGENT),
            "the Guardian pass keeps the MozillaVPN identity: {log:?}"
        );
        assert!(
            log.iter().any(|seen| seen.path == "/api/v1/fpn/token"),
            "the pass was minted: {log:?}"
        );
    }

    /// A revert that refuses the Firefox identity still signs in: the `MozillaVPN` path earns and presents its own cookie.
    #[test]
    fn the_old_identity_clears_a_firefox_refusal() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let _denied = DenyFirefoxAgent::arm();
        let (address, roots, rx) = edge_with_log();
        let account = account(address, roots);
        account
            .sign_in("person@example.com", "hunter2")
            .expect("the old identity still signs in");
        let log: Vec<Seen> = rx.try_iter().collect();
        assert!(
            log.iter()
                .any(|seen| seen.agent == USER_AGENT && seen.path == "/v1/account/login"),
            "the account call falls back to the MozillaVPN identity: {log:?}"
        );
        assert!(
            log.iter().any(|seen| seen.agent == USER_AGENT
                && seen.path == "/"
                && seen.host.ends_with("accounts.firefox.com")),
            "the solver earns the page under the identity it presents: {log:?}"
        );
        assert!(
            log.iter().any(
                |seen| seen.agent == USER_AGENT && seen.path.ends_with("script.js?reload=true")
            ),
            "the solver keeps that identity for its script: {log:?}"
        );
        assert!(
            log.iter().any(|seen| seen.agent == USER_AGENT
                && seen.path.contains("/pat?")
                && seen.accept == "text/plain"),
            "the PAT call keeps the solver identity and its text answer: {log:?}"
        );
        assert!(account.current().token.starts_with("eyJ"), "and mints");
    }

    /// A login that only asks for email verification still exchanges: the password path does not need a browser.
    #[test]
    fn an_email_verification_session_mints_without_a_code() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let account = account(address, roots);
        account
            .sign_in("verify@example.com", "hunter2")
            .expect("an email-verification session signs in");
        assert!(
            !account.needs_code(),
            "email verification is not a two-factor wait"
        );
        assert!(account.current().token.starts_with("eyJ"), "and mints");
        let log = seen(&rx);
        assert!(
            log.iter().any(|line| line == "POST /v1/oauth/token"),
            "the unverified session is exchanged: {log:?}"
        );
    }

    /// An authenticator code is submitted to its own route, signed with the same pending session.
    #[test]
    fn a_totp_session_verifies_at_the_authenticator_route() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("totp");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "totp@example.com").expect("bound");
        let mut account = account(address, roots);
        account.tokens = Some(tokens);
        account
            .sign_in("totp@example.com", "hunter2")
            .expect("a TOTP session signs in");
        assert!(account.needs_code(), "the authenticator code is required");
        assert!(
            account.current().token.is_empty(),
            "no pass before the code"
        );
        let stored = account
            .tokens
            .as_ref()
            .expect("the file rides the account")
            .load()
            .expect("the pending sign-in is written");
        assert_eq!(
            stored.pending_method.as_deref(),
            Some("totp-2fa"),
            "the method survives a restart"
        );
        assert_eq!(
            account.verify_code("000000"),
            Err(Denied::Token),
            "a refused authenticator code does not exchange"
        );
        assert!(account.needs_code(), "the refused code keeps the wait");
        account.verify_code("424242").expect("verifies");
        assert!(!account.needs_code(), "the code clears the wait");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
        let log = seen(&rx);
        assert!(
            log.iter()
                .any(|line| line == "POST /v1/session/verify/totp"),
            "the authenticator route is used: {log:?}"
        );
        assert!(
            !log.iter()
                .any(|line| line == "POST /v1/session/verify_code"),
            "the email route is not used for an authenticator: {log:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A browser's session token is already a credential: exchange it without asking `FxA` for a password.
    #[test]
    fn a_session_token_mints_a_pass_without_a_sign_in() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let account = account(address, roots);
        account
            .sign_in_session(SESSION)
            .expect("a browser session token signs in");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
        let log = seen(&rx);
        assert!(
            !log.iter().any(|line| line == "POST /v1/account/login"),
            "a session token skips the password sign-in: {log:?}"
        );
        assert!(
            log.iter().any(|line| line == "POST /v1/oauth/token"),
            "the session token is exchanged: {log:?}"
        );
    }

    #[test]
    fn a_session_token_that_is_not_thirty_two_bytes_of_hex_is_refused() {
        let (address, roots) = edge();
        let account = account(address, roots);
        assert_eq!(
            account.sign_in_session("not-a-session-token"),
            Err(Denied::Token)
        );
    }

    fn token_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ferrox-foxy-token-{}-{label}.json",
            std::process::id()
        ))
    }

    fn seen(rx: &mpsc::Receiver<Seen>) -> Vec<String> {
        rx.try_iter()
            .map(|s| format!("{} {}", s.method, s.path))
            .collect()
    }

    /// The point of the file: a second launch mints from the stored grant and never asks `FxA` to sign in.
    #[test]
    fn a_stored_grant_mints_a_pass_without_a_sign_in() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("resume");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "Person@Example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let session = tokens.load().expect("the file reads back");
        assert_eq!(
            session.email, "person@example.com",
            "the identity is stored normalized, so the binding does not depend on casing"
        );
        let mut account = account(address, roots);
        account.tokens = Some(tokens);
        account.resume(session).expect("resumes");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
        let log = seen(&rx);
        assert!(
            !log.iter().any(|line| line == "POST /v1/account/login"),
            "a resumed launch sends no sign-in, which is the mail it must not send: {log:?}"
        );
        assert_eq!(
            log.last().map(String::as_str),
            Some("GET /api/v1/fpn/token")
        );
        let _ = std::fs::remove_file(&path);
    }

    /// An access token past its window refreshes with the stored grant, and the rotated pair is written for the next launch.
    #[test]
    fn a_lapsed_grant_refreshes_and_the_rotated_pair_is_written_down() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("refresh");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                expires_at: 1,
            }),
            None,
        );
        let session = tokens.load().expect("reads");
        let mut account = account(address, roots);
        account.tokens = Some(tokens);
        account.resume(session).expect("refreshes and mints");
        assert!(account.current().token.starts_with("eyJ"));
        let log = seen(&rx);
        assert!(
            !log.iter().any(|line| line == "POST /v1/account/login"),
            "a refresh is not a sign-in: {log:?}"
        );
        assert!(
            log.iter().any(|line| line == "POST /v1/token"),
            "the lapsed access token is renewed: {log:?}"
        );
        let stored = account
            .tokens
            .as_ref()
            .expect("the file rides the account")
            .load()
            .expect("the rotation is written")
            .auth
            .expect("and it is a grant");
        assert_eq!(
            (stored.access_token.as_str(), stored.refresh_token.as_str()),
            ("access-2", "refresh-2"),
            "the refresh token FxA rotated in is the one the next launch spends"
        );
        assert!(stored.expires_at > epoch() + 3_000);
        let _ = std::fs::remove_file(&path);
    }

    /// A lane launched beside another reads the grant the other rotated in instead of spending a refresh token that was already used.
    #[test]
    fn a_grant_another_process_rotated_in_is_adopted_not_refreshed() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("handoff");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        let stale = Auth {
            access_token: "access-1".to_owned(),
            refresh_token: "refresh-1".to_owned(),
            expires_at: 1,
        };
        tokens.save(Some(&stale), None);
        let mut account = account(address, roots);
        account.tokens = Some(tokens.clone());
        tokens.save(
            Some(&Auth {
                access_token: "access-9".to_owned(),
                refresh_token: "refresh-9".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let fresh = account.refresh(&stale, false).expect("adopts");
        assert_eq!(
            (fresh.access_token.as_str(), fresh.refresh_token.as_str()),
            ("access-9", "refresh-9"),
            "the other process's rotated pair is the one this lane keeps"
        );
        let log = seen(&rx);
        assert!(
            !log.iter().any(|line| line == "POST /v1/token"),
            "an adopted grant is not spent again: {log:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A rotated-in grant whose access token has also lapsed still carries the live refresh token: that is the one spent, not the dead one this launch loaded.
    #[test]
    fn an_expired_grant_another_process_wrote_is_refreshed_with_its_own_token() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, _rx) = edge_with_log();
        let path = token_path("handoff-expired");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        let stale = Auth {
            access_token: "access-1".to_owned(),
            refresh_token: "refresh-dead".to_owned(),
            expires_at: 1,
        };
        tokens.save(Some(&stale), None);
        let mut account = account(address, roots);
        account.tokens = Some(tokens.clone());
        tokens.save(
            Some(&Auth {
                access_token: "access-9".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                expires_at: 1,
            }),
            None,
        );
        let fresh = account
            .refresh(&stale, false)
            .expect("refreshes the adopted grant");
        assert_eq!(
            (fresh.access_token.as_str(), fresh.refresh_token.as_str()),
            ("access-2", "refresh-2"),
            "the adopted grant's live refresh token is the one spent"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A refresh refused because a lane beside this one spent the token first adopts what that lane wrote, rather than asking for a password.
    #[test]
    fn a_refused_refresh_adopts_the_grant_written_while_it_was_in_flight() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("handoff-refused");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        let stale = Auth {
            access_token: "access-1".to_owned(),
            refresh_token: "refresh-dead".to_owned(),
            expires_at: 1,
        };
        tokens.save(Some(&stale), None);
        let mut account = account(address, roots);
        account.tokens = Some(tokens.clone());
        let writer = tokens;
        let wrote = std::thread::spawn(move || {
            let request = rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the refresh arrives");
            assert_eq!(request.path, "/v1/token");
            writer.save(
                Some(&Auth {
                    access_token: "access-9".to_owned(),
                    refresh_token: "refresh-9".to_owned(),
                    expires_at: epoch() + 3_600,
                }),
                None,
            );
        });
        let fresh = account
            .refresh(&stale, false)
            .expect("adopts after the refusal");
        wrote.join().expect("the writer finishes");
        assert_eq!(
            (fresh.access_token.as_str(), fresh.refresh_token.as_str()),
            ("access-9", "refresh-9"),
            "the refusal is another lane's rotation, not a dead account"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A clock-valid grant the plane refuses is refreshed before the password: the sign-in mail is what a resume must never spend.
    #[test]
    fn a_refused_live_grant_is_refreshed_before_the_password() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("refused-live");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-7".to_owned(),
                refresh_token: "refresh-7".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let session = tokens.load().expect("reads");
        let mut account = account(address, roots);
        account.tokens = Some(tokens);
        account
            .resume(session)
            .expect("refreshes the refused grant");
        assert!(
            account.current().token.starts_with("eyJ"),
            "the pass comes from the refreshed grant"
        );
        let log = seen(&rx);
        assert!(
            log.iter().any(|line| line == "POST /v1/token"),
            "a refused clock-valid token is refreshed, not replayed: {log:?}"
        );
        assert!(
            !log.iter().any(|line| line == "POST /v1/account/login"),
            "the refresh is what spares the sign-in mail: {log:?}"
        );
        let stored = account
            .tokens
            .as_ref()
            .expect("the file rides the account")
            .load()
            .expect("the rotation is written")
            .auth
            .expect("and it is a grant");
        assert_eq!(
            (stored.access_token.as_str(), stored.refresh_token.as_str()),
            ("access-9", "refresh-9"),
            "the rotated pair is the one the next launch spends"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A pass still refused after the rotation is an entitlement refusal: the grant is kept, and no retry turns it into a password.
    #[test]
    fn a_refused_pass_after_a_refresh_keeps_the_stored_grant() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("refused-pass");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-8".to_owned(),
                refresh_token: "refresh-8".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let session = tokens.load().expect("reads");
        let mut account = account(address, roots);
        account.tokens = Some(tokens);
        let denied = account.resume(session).expect_err("the pass is refused");
        assert_eq!(denied, Denied::Pass);
        assert!(!denied.is_final(), "the grant is not dead");
        assert!(
            !denied.is_retryable(),
            "asking again with the same account cannot change it"
        );
        assert!(account.can_renew(), "the stored grant stays");
        let log = seen(&rx);
        assert!(
            log.iter().any(|line| line == "POST /v1/token"),
            "the refusal was reached after a refresh: {log:?}"
        );
        assert!(
            !log.iter().any(|line| line == "POST /v1/account/login"),
            "a refused pass never reaches the password: {log:?}"
        );
        let stored = account
            .tokens
            .as_ref()
            .expect("the file rides the account")
            .load()
            .expect("the rotation was written")
            .auth
            .expect("and it is a grant");
        assert_eq!(
            (stored.access_token.as_str(), stored.refresh_token.as_str()),
            ("access-10", "refresh-10"),
            "the rotated grant is kept for the next launch"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Only a refresh the plane refuses makes the grant dead: then, and only then, is the password the next step.
    #[test]
    fn a_refused_grant_with_a_dead_refresh_is_still_a_sign_in() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("dead-refresh");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-6".to_owned(),
                refresh_token: "refresh-dead".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let session = tokens.load().expect("reads");
        let mut account = account(address, roots);
        account.tokens = Some(tokens);
        let denied = account.resume(session).expect_err("the grant is dead");
        assert!(
            denied.is_final(),
            "only a refused refresh spends the password: {denied}"
        );
        let log = seen(&rx);
        assert!(
            log.iter().any(|line| line == "POST /v1/token"),
            "the dead grant is spent before it is called dead: {log:?}"
        );
        assert!(
            !log.iter().any(|line| line == "POST /v1/account/login"),
            "resume itself never signs in: {log:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A launch that stopped at two-factor resumes the pending session: the code is the only thing it asks for.
    #[test]
    fn a_pending_two_factor_session_resumes_without_the_password() {
        let _turn = EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots, rx) = edge_with_log();
        let path = token_path("pending");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(None, Some(SESSION));
        let session = tokens.load().expect("reads");
        let mut account = account(address, roots);
        account.tokens = Some(tokens);
        account.resume(session).expect("resumes");
        assert!(
            account.needs_code(),
            "the pending session waits for its code"
        );
        account.verify_code("424242").expect("verifies");
        assert!(!account.needs_code(), "the code clears the wait");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
        let log = seen(&rx);
        assert!(
            !log.iter().any(|line| line == "POST /v1/account/login"),
            "the password is not asked for again: {log:?}"
        );
        let stored = account
            .tokens
            .as_ref()
            .expect("the file rides the account")
            .load()
            .expect("the exchange is written");
        assert!(stored.pending.is_none(), "the verified session is done");
        assert!(stored.auth.is_some(), "and its grant is kept");
        let _ = std::fs::remove_file(&path);
    }

    /// A file belongs to the account it names: another identity and an unbound file both read as no session, not someone else's.
    #[test]
    fn a_token_file_belongs_to_the_account_it_names() {
        let path = token_path("binding");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let other =
            TokenFile::new(path.to_str().expect("utf-8"), "someone@example.com").expect("bound");
        assert!(
            other.load().is_none(),
            "another account's grant is never resumed for this one"
        );
        assert!(
            TokenFile::new("", "person@example.com").is_none(),
            "no path is no file"
        );
        assert!(
            TokenFile::new(path.to_str().expect("utf-8"), " ").is_none(),
            "no account is no binding"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A refused grant is cleared, but one another process rotated in over it is not: forgetting is not allowed to erase a live session.
    #[test]
    fn forgetting_a_refused_grant_keeps_the_one_another_process_wrote() {
        let path = token_path("clear-if");
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-9".to_owned(),
                refresh_token: "refresh-9".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        tokens.clear_if("access-1");
        assert!(
            tokens.load().is_some(),
            "a grant rotated in since the refusal is left standing"
        );
        tokens.clear_if("access-9");
        assert!(tokens.load().is_none(), "the refused grant is cleared");
        let _ = std::fs::remove_file(&path);
    }

    /// A write is a rename: a handle already opened on the file keeps the grant it opened, and the path holds the new one whole.
    #[test]
    fn a_session_write_never_rewrites_the_file_a_reader_holds() {
        use std::io::Read as _;
        let path = token_path("atomic");
        let _ = std::fs::remove_file(&path);
        let tokens =
            TokenFile::new(path.to_str().expect("utf-8"), "person@example.com").expect("bound");
        tokens.save(
            Some(&Auth {
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let mut opened = std::fs::File::open(&path).expect("opens the first grant");
        tokens.save(
            Some(&Auth {
                access_token: "access-2".to_owned(),
                refresh_token: "refresh-2".to_owned(),
                expires_at: epoch() + 3_600,
            }),
            None,
        );
        let mut before = String::new();
        opened.read_to_string(&mut before).expect("reads");
        assert!(
            before.contains("access-1"),
            "the handle a reader holds was rewritten in place: {before}"
        );
        let after = tokens
            .load()
            .expect("the path is readable")
            .auth
            .expect("a grant");
        assert_eq!(
            after.access_token, "access-2",
            "the path names the grant the writer saved"
        );
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod two_factor {
    use super::loopback::{HOSTS, SESSION, TWO_FACTOR};
    use std::sync::mpsc;

    #[test]
    fn an_account_that_stops_at_two_factor_waits_for_a_code_and_then_mints() {
        let _turn = super::loopback::EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Both flags the edge reads are armed, so no earlier turn can leave this sign-in parked at a pass the mint refuses.
        super::loopback::ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        TWO_FACTOR.store(true, std::sync::atomic::Ordering::Relaxed);
        let minted = rcgen::generate_simple_self_signed(
            HOSTS
                .iter()
                .map(|h| (*h).to_owned())
                .collect::<Vec<String>>(),
        )
        .expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let key_pem = crate::quic::der_to_pem(&minted.signing_key.serialize_der(), "PRIVATE KEY");
        let root = ferrox_core::tls::parse_pem_identity(minted.cert.pem().as_bytes(), &key_pem)
            .expect("identity");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, _rx) = mpsc::channel();
        std::thread::spawn(move || super::loopback::serve(&listener, &root, &tx));

        let address = format!("127.0.0.1:{port}").parse().expect("addr");
        let account = super::loopback::account(address, roots.into());
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
    /// `FoxyVPN` v1.0.5 rejects a sign-in whose identity or code carries autofill padding; the lane must strip every separator, zero-width mark and BOM wherever it sits, lower-case the identity, and never send a padded credential raw.
    #[test]
    fn an_autofilled_identity_signs_in_normalized() {
        let _turn = super::loopback::EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        super::loopback::ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        super::loopback::TWO_FACTOR.store(false, std::sync::atomic::Ordering::Relaxed);
        let (address, roots) = super::loopback::edge();
        let account = super::loopback::account(address, roots);
        // An interior space, a non-breaking space, a zero-width space, upper case and a trailing BOM: the login handler asserts the body carries exactly "person@example.com", so an edge-trim-only fix fails it.
        account
            .sign_in(" Pe\u{00A0}rson@Ex\u{200B}ample.com \u{FEFF}", "hunter2")
            .expect("a padded, cased identity signs in normalized");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
    }

    /// The two-factor code is stripped the same way, but its case is left alone because it carries digits, not an address.
    #[test]
    fn an_autofilled_code_is_verified_sanitized() {
        let _turn = super::loopback::EDGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        super::loopback::ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        super::loopback::TWO_FACTOR.store(true, std::sync::atomic::Ordering::Relaxed);
        let (address, roots) = super::loopback::edge();
        let account = super::loopback::account(address, roots);
        account
            .sign_in("person@example.com", "hunter2")
            .expect("signs in and stops at two-factor");
        assert!(account.needs_code(), "the sign-in waits for a code");
        // The verify handler asserts the body is exactly {"code":"424242"}; a raw padded code leaves the spaces and the zero-width mark in and fails it.
        account
            .verify_code(" 4\u{200B} 2 4 2 4\u{00A0}2 ")
            .expect("a padded code is sanitized to 424242 and verifies");
        assert!(!account.needs_code(), "the code clears the wait");
        assert!(account.current().token.starts_with("eyJ"), "and mints");
    }
}
