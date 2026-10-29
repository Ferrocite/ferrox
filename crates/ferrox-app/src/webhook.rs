//! One rule's webhook action: the event xray POSTs when that rule matches a flow.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ferrox_core::tls::TlsProvider as _;

use crate::conn::{Connection, HttpUrl, Target};
use crate::json::Json;
use crate::router::Network;

/// The whole request's budget, which is the reference's `http.Client{Timeout: 5s}`.
const BUDGET: Duration = Duration::from_secs(5);

/// What a stage still has to spend, floored at a millisecond because `std` refuses a zero wait.
fn left(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1))
}

/// One rule's callback: the URL, the headers it adds, and the window in which one email fires once.
#[derive(Debug)]
pub(crate) struct Webhook {
    url: String,
    socket: Option<String>,
    headers: Vec<(String, String)>,
    deduplication: u32,
    seen: Mutex<Seen>,
}

#[derive(Debug)]
struct Seen {
    emails: HashMap<String, Instant>,
    swept: Instant,
}

/// The facts a matched flow hands the event, as the reference's `buildEvent` reads them.
pub(crate) struct Event<'a> {
    pub(crate) email: Option<&'a str>,
    pub(crate) level: Option<u32>,
    pub(crate) protocol: Option<&'a str>,
    pub(crate) network: Network,
    pub(crate) source: Option<SocketAddr>,
    pub(crate) destination: &'a crate::proxy::Destination,
    pub(crate) original: Option<&'a crate::proxy::Destination>,
    pub(crate) route: Option<&'a crate::proxy::Destination>,
    pub(crate) inbound_tag: Option<&'a str>,
    pub(crate) inbound_name: Option<&'a str>,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) outbound_tag: &'a str,
}

/// The rule's notifier, or `None` for an entry that names no URL: the reference builds none either.
pub(crate) fn parse(field: &Json) -> Result<Option<Arc<Webhook>>, String> {
    let url = field.get("url").and_then(Json::as_str).unwrap_or("");
    if url.is_empty() {
        return Ok(None);
    }
    let (url, socket) = split_socket(url);
    let mut headers = Vec::new();
    if let Some(list) = field.get("headers") {
        if !matches!(list, Json::Null) {
            for (name, value) in crate::router::object(list, "webhook headers")? {
                let value = value
                    .as_str()
                    .ok_or_else(|| format!("webhook header `{name}` is not a string"))?;
                headers.push((name.clone(), value.to_owned()));
            }
        }
    }
    let deduplication = field
        .get("deduplication")
        .and_then(Json::as_u32)
        .unwrap_or(0);
    Ok(Some(Arc::new(Webhook {
        url,
        socket,
        headers,
        deduplication,
        seen: Mutex::new(Seen {
            emails: HashMap::new(),
            swept: Instant::now(),
        }),
    })))
}

/// The reference's `SplitHTTPUnixURL`: a socket path and the HTTP path after `:/` become a
/// `http://localhost` URL, and a URL keeps its socket empty.
fn split_socket(raw: &str) -> (String, Option<String>) {
    if !(raw.starts_with('@') || std::path::Path::new(raw).is_absolute()) {
        return (raw.to_owned(), None);
    }
    match raw.find(":/") {
        Some(at) => (
            format!("http://localhost{}", &raw[at + 1..]),
            Some(raw[..at].to_owned()),
        ),
        None => ("http://localhost/".to_owned(), Some(raw.to_owned())),
    }
}

impl Webhook {
    /// Send the event one matched flow carries, on its own thread as the reference's goroutine does;
    /// an email inside the window sends nothing.
    pub(crate) fn fire(self: &Arc<Self>, event: &Event<'_>) {
        if self.is_duplicate(event.email.unwrap_or("")) {
            return;
        }
        let body = event_body(event);
        let webhook = Arc::clone(self);
        if let Err(error) = std::thread::Builder::new()
            .name("webhook".to_owned())
            .spawn(move || webhook.post(&body))
        {
            eprintln!("webhook: cannot start the POST: {error}");
        }
    }

    /// Whether this email already fired inside the window, which also records the send.
    fn is_duplicate(&self, email: &str) -> bool {
        if self.deduplication == 0 || email.is_empty() {
            return false;
        }
        let ttl = Duration::from_secs(u64::from(self.deduplication));
        let now = Instant::now();
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.duration_since(seen.swept) >= ttl {
            seen.emails.retain(|_, at| now.duration_since(*at) < ttl);
            seen.swept = now;
        }
        if seen
            .emails
            .get(email)
            .is_some_and(|at| now.duration_since(*at) < ttl)
        {
            return true;
        }
        seen.emails.insert(email.to_owned(), now);
        false
    }

    /// The sending thread's body: one failure reports itself and ends the thread.
    fn post(&self, body: &str) {
        if let Err(reason) = self.send(body) {
            eprintln!("webhook: POST {} failed: {reason}", self.url);
        }
    }

    /// The POST, from the URL it parses to the status line it reads, inside the one budget.
    fn send(&self, body: &str) -> Result<(), String> {
        let url = HttpUrl::parse(&self.url)?;
        let deadline = Instant::now() + BUDGET;
        let connection = self.dial(&url, left(deadline))?;
        connection
            .set_read_timeout(Some(left(deadline)))
            .map_err(|error| error.to_string())?;
        connection
            .set_write_timeout(Some(left(deadline)))
            .map_err(|error| error.to_string())?;
        let request = request_bytes(&url, &self.headers, body);
        if url.tls {
            let config = ferrox_core::tls::TlsConfig {
                server_name: url.host.clone(),
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
            };
            let mut session = ferrox_core::tls::RustlsProvider::connect(&config, connection)
                .map_err(|error| error.to_string())?;
            session.handshake().map_err(|error| error.to_string())?;
            exchange(&mut session, &request)
        } else {
            let mut connection = connection;
            exchange(&mut connection, &request)
        }
    }

    /// The address the URL names: the socket path it carries, or the first address its host resolves to.
    fn dial(&self, url: &HttpUrl, budget: Duration) -> Result<Connection, String> {
        if let Some(path) = &self.socket {
            return dial_socket(path, budget);
        }
        let mut last = format!("{} resolved to no address", url.host);
        for address in (url.host.as_str(), url.port)
            .to_socket_addrs()
            .map_err(|error| format!("{}: {error}", url.host))?
        {
            match crate::conn::connect(&Target::Ip(address), budget) {
                Ok(connection) => return Ok(connection),
                Err(error) => last = format!("{address}: {error}"),
            }
        }
        Err(last)
    }
}

/// A socket URL dials the path it named: one `@` is the kernel's abstract namespace, two the padded
/// name `HAProxy` spells and the reference fails to dial, and anything else a filesystem path.
fn dial_socket(path: &str, budget: Duration) -> Result<Connection, String> {
    #[cfg(any(unix, windows))]
    {
        #[cfg(target_os = "linux")]
        if let Some(name) = path.strip_prefix('@') {
            return crate::conn::connect_abstract(&abstract_name(name)?)
                .map_err(|error| format!("{path}: {error}"));
        }
        crate::conn::connect(
            &crate::conn::Target::Unix(std::path::PathBuf::from(path)),
            budget,
        )
        .map_err(|error| format!("{path}: {error}"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = budget;
        Err(format!("{path}: this host has no unix sockets"))
    }
}

/// The abstract name a `@@` spelling pads to: the bytes `HAProxy`'s `sun_path` holds, so a name with
/// a second `@` fills the kernel's field.
#[cfg(target_os = "linux")]
fn abstract_name(name: &str) -> Result<Vec<u8>, String> {
    let Some(padded) = name.strip_prefix('@') else {
        return Ok(name.as_bytes().to_vec());
    };
    let bytes = padded.as_bytes();
    if bytes.len() > 107 {
        return Err(format!(
            "abstract socket `{name}` is longer than the kernel's field"
        ));
    }
    let mut name = vec![0u8; 107];
    name[..bytes.len()].copy_from_slice(bytes);
    Ok(name)
}

/// The exact request bytes: the JSON content type first, then each configured header, a repeated name
/// replacing the one already written as `http.Header.Set` does.
fn request_bytes(url: &HttpUrl, headers: &[(String, String)], body: &str) -> Vec<u8> {
    let mut wire: Vec<(&str, &str)> = Vec::with_capacity(headers.len() + 1);
    wire.push(("Content-Type", "application/json"));
    for (name, value) in headers {
        match wire
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            Some(slot) => *slot = (name, value),
            None => wire.push((name, value)),
        }
    }
    crate::foxy_account::request("POST", &url.authority, &url.path, &wire, body.as_bytes())
}

/// Write the request and read only the status line back: the body is discarded, and dropping the
/// connection is what ends it, so nothing pays to drain what the peer sends.
fn exchange(io: &mut (impl Read + Write), request: &[u8]) -> Result<(), String> {
    io.write_all(request).map_err(|error| error.to_string())?;
    io.flush().map_err(|error| error.to_string())?;
    let mut head = [0u8; 128];
    let mut len = 0;
    while len < head.len() {
        let read = io
            .read(&mut head[len..])
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        len += read;
        if head[..len].windows(2).any(|window| window == b"\r\n") {
            break;
        }
    }
    let status = head[..len]
        .split(|byte| *byte == b' ')
        .nth(1)
        .and_then(|code| std::str::from_utf8(code).ok())
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("the reply carries no status")?;
    if status >= 400 {
        return Err(format!("POST returned status {status}"));
    }
    Ok(())
}

/// The reference's `event` as `encoding/json` renders it: every field present in declaration order,
/// a nil pointer as `null`, and the runes Go's encoder escapes written as escapes.
fn event_body(event: &Event<'_>) -> String {
    let network = match event.network {
        Network::Tcp => "tcp",
        Network::Udp => "udp",
    };
    let mut out = String::with_capacity(320);
    out.push_str("{\"email\":");
    push_optional(&mut out, event.email);
    out.push_str(",\"level\":");
    push_level(&mut out, event.level);
    out.push_str(",\"protocol\":");
    push_string(&mut out, event.protocol.unwrap_or(""));
    out.push_str(",\"network\":");
    push_string(&mut out, network);
    out.push_str(",\"source\":");
    push_address(&mut out, event.source);
    out.push_str(",\"destination\":");
    push_string(&mut out, &event.destination.authority());
    out.push_str(",\"originalTarget\":");
    push_string(
        &mut out,
        &event.original.unwrap_or(event.destination).authority(),
    );
    out.push_str(",\"routeTarget\":");
    match event.route {
        Some(route) => push_string(&mut out, &route.authority()),
        None => out.push_str("null"),
    }
    out.push_str(",\"inboundTag\":");
    push_string(&mut out, event.inbound_tag.unwrap_or(""));
    out.push_str(",\"inboundName\":");
    push_optional(&mut out, event.inbound_name);
    out.push_str(",\"inboundLocal\":");
    push_address(&mut out, event.local);
    out.push_str(",\"outboundTag\":");
    push_string(&mut out, event.outbound_tag);
    out.push_str(",\"ts\":");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let _ = write!(out, "{now}");
    out.push('}');
    out
}

/// A JSON string, or the bare word the reference's encoder writes for a nil pointer.
fn push_optional(out: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_string(out, value),
        None => out.push_str("null"),
    }
}

/// A JSON number for the account level, or `null` for a flow that authenticated as nobody.
fn push_level(out: &mut String, level: Option<u32>) {
    match level {
        Some(level) => {
            let _ = write!(out, "{level}");
        }
        None => out.push_str("null"),
    }
}

/// A JSON string for a `host:port` fact, or `null` when the transport could not answer it.
fn push_address(out: &mut String, address: Option<SocketAddr>) {
    match address {
        Some(address) => push_string(out, &address.to_string()),
        None => out.push_str("null"),
    }
}

/// One JSON string with the escapes Go's encoder writes, so the bytes match the reference's body.
fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            ch if u32::from(ch) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Destination;

    fn event(destination: &Destination) -> Event<'_> {
        Event {
            email: None,
            level: None,
            protocol: None,
            network: Network::Tcp,
            source: None,
            destination,
            original: None,
            route: None,
            inbound_tag: None,
            inbound_name: None,
            local: None,
            outbound_tag: "direct",
        }
    }

    fn notifier(url: &str) -> Arc<Webhook> {
        let field = crate::json::parse(&format!(r#"{{"url":"{url}"}}"#)).expect("json");
        parse(&field).expect("parses").expect("a notifier")
    }

    #[test]
    fn the_event_body_is_the_reference_json() {
        let destination = Destination::Name("example.test".to_owned(), 80);
        let original = Destination::Name("original.test".to_owned(), 80);
        let route = Destination::Name("sniffed.test".to_owned(), 80);
        let full = Event {
            email: Some("a@x"),
            level: Some(0),
            protocol: Some("http/1.1"),
            network: Network::Tcp,
            source: Some("127.0.0.1:1234".parse().expect("address")),
            destination: &destination,
            original: Some(&original),
            route: Some(&route),
            inbound_tag: Some("in"),
            inbound_name: Some("http"),
            local: Some("127.0.0.1:8080".parse().expect("address")),
            outbound_tag: "direct",
        };
        let body = event_body(&full);
        let (head, timestamp) = body.rsplit_once(",\"ts\":").expect("a timestamp");
        assert_eq!(
            head,
            "{\"email\":\"a@x\",\"level\":0,\"protocol\":\"http/1.1\",\"network\":\"tcp\",\
             \"source\":\"127.0.0.1:1234\",\"destination\":\"example.test:80\",\
             \"originalTarget\":\"original.test:80\",\"routeTarget\":\"sniffed.test:80\",\
             \"inboundTag\":\"in\",\"inboundName\":\"http\",\"inboundLocal\":\"127.0.0.1:8080\",\
             \"outboundTag\":\"direct\""
        );
        assert!(timestamp.ends_with('}'), "{timestamp}");
        assert!(
            timestamp[..timestamp.len() - 1]
                .chars()
                .all(|ch| ch.is_ascii_digit()),
            "{timestamp}"
        );
    }

    #[test]
    fn an_absent_fact_is_null_and_a_hostile_name_is_escaped() {
        let destination = Destination::Name("a\"<b>&\\c".to_owned(), 1);
        let body = event_body(&event(&destination));
        let head = body
            .rsplit_once(",\"ts\":")
            .map(|(head, _)| head)
            .expect("a timestamp");
        assert_eq!(
            head,
            "{\"email\":null,\"level\":null,\"protocol\":\"\",\"network\":\"tcp\",\
             \"source\":null,\"destination\":\"a\\\"\\u003cb\\u003e\\u0026\\\\c:1\",\
             \"originalTarget\":\"a\\\"\\u003cb\\u003e\\u0026\\\\c:1\",\"routeTarget\":null,\
             \"inboundTag\":\"\",\"inboundName\":null,\"inboundLocal\":null,\"outboundTag\":\"direct\""
        );
    }

    #[test]
    fn a_socket_url_splits_into_a_localhost_url() {
        assert_eq!(
            split_socket("http://example.test/hook"),
            ("http://example.test/hook".to_owned(), None)
        );
        assert_eq!(
            split_socket("@name:/post"),
            ("http://localhost/post".to_owned(), Some("@name".to_owned()))
        );
        // `filepath.IsAbs` names a leading slash absolute only on a host that has that root.
        #[cfg(unix)]
        {
            assert_eq!(
                split_socket("/tmp/hook.sock"),
                (
                    "http://localhost/".to_owned(),
                    Some("/tmp/hook.sock".to_owned())
                )
            );
            assert_eq!(
                split_socket("/tmp/hook.sock:/post"),
                (
                    "http://localhost/post".to_owned(),
                    Some("/tmp/hook.sock".to_owned())
                )
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(
                split_socket("/tmp/hook.sock"),
                ("/tmp/hook.sock".to_owned(), None)
            );
            assert_eq!(
                split_socket(r"C:\tmp\hook.sock:/post"),
                (
                    "http://localhost/post".to_owned(),
                    Some(r"C:\tmp\hook.sock".to_owned())
                )
            );
        }
    }

    #[test]
    fn a_duplicate_email_inside_the_window_is_dropped() {
        let webhook = notifier_with(r#"{"url":"http://127.0.0.1:1/x","deduplication":60}"#);
        assert!(!webhook.is_duplicate("a@x"));
        assert!(webhook.is_duplicate("a@x"));
        assert!(!webhook.is_duplicate("b@x"));
        assert!(!webhook.is_duplicate(""));
    }

    fn notifier_with(config: &str) -> Arc<Webhook> {
        let field = crate::json::parse(config).expect("json");
        parse(&field).expect("parses").expect("a notifier")
    }

    #[test]
    fn a_receiver_that_never_answers_ends_the_post_at_the_budget() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("receiver");
        let port = listener.local_addr().expect("address").port();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("arms");
            let mut total = 0;
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(read) => total += read,
                    Err(error) => {
                        send.send(Err(error.to_string())).ok();
                        return;
                    }
                }
            }
            send.send(Ok(total)).ok();
        });
        let started = Instant::now();
        let webhook = notifier(&format!("http://127.0.0.1:{port}/hook"));
        let destination = Destination::Name("example.test".to_owned(), 80);
        webhook.fire(&event(&destination));
        let total = receive
            .recv_timeout(Duration::from_secs(20))
            .expect("the client gives up")
            .expect("a clean close");
        let waited = started.elapsed();
        assert!(total > 0, "the request reached the receiver");
        assert!(
            waited >= Duration::from_secs(4),
            "the budget is the reference's five seconds: {waited:?}"
        );
        assert!(
            waited < Duration::from_secs(15),
            "the budget ends the wait: {waited:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_url_reaches_the_unix_listener() {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ferrox-webhook-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("hook.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("binds");
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = Vec::new();
            let mut buf = [0u8; 256];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).expect("reads");
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .expect("replies");
            send.send(String::from_utf8_lossy(&head).into_owned()).ok();
        });
        let webhook = notifier(&format!("{}:/post", path.display()));
        let destination = Destination::Name("example.test".to_owned(), 80);
        webhook.fire(&event(&destination));
        let head = receive
            .recv_timeout(Duration::from_secs(10))
            .expect("the request arrives");
        assert!(head.starts_with("POST /post HTTP/1.1\r\n"), "{head}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_padded_spelling_fills_the_kernel_field() {
        assert_eq!(abstract_name("plain").expect("fits"), b"plain".to_vec());
        let padded = abstract_name("@padded").expect("fits");
        assert_eq!(padded.len(), 107);
        assert_eq!(&padded[..6], b"padded");
        assert!(padded[6..].iter().all(|byte| *byte == 0));
        assert!(abstract_name(&format!("@{}", "x".repeat(108))).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_abstract_socket_url_reaches_the_kernel_name() {
        use std::os::linux::net::SocketAddrExt;
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("ferrox-webhook-{}-{id}", std::process::id());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
            .expect("the name fits");
        let listener = std::os::unix::net::UnixListener::bind_addr(&address).expect("binds");
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut head = Vec::new();
            let mut buf = [0u8; 256];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).expect("reads");
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .expect("replies");
            send.send(String::from_utf8_lossy(&head).into_owned()).ok();
        });
        let webhook = notifier(&format!("@{name}:/post"));
        let destination = Destination::Name("example.test".to_owned(), 80);
        webhook.fire(&event(&destination));
        let head = receive
            .recv_timeout(Duration::from_secs(10))
            .expect("the request arrives");
        assert!(head.starts_with("POST /post HTTP/1.1\r\n"), "{head}");
    }
}
