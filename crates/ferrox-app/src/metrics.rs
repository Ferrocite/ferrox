use crate::json::Json;
use crate::stats;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) listen: Option<String>,
    pub(crate) tag: Option<String>,
}

static CONFIG: Mutex<Option<Config>> = Mutex::new(None);
static TAGGED: Mutex<Option<SocketAddr>> = Mutex::new(None);

fn lock() -> std::sync::MutexGuard<'static, Option<Config>> {
    CONFIG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read the top-level `metrics` object: one listener address and the outbound tag the reference
/// gives its internal metrics inbound.
pub(crate) fn parse(root: &Json) -> Result<Config, String> {
    let Some(section) = root.get("metrics") else {
        return Ok(Config::default());
    };
    let Json::Obj(pairs) = section else {
        return Err("`metrics` is not an object".to_owned());
    };
    let mut config = Config::default();
    for (key, value) in pairs {
        match key.as_str() {
            "listen" => {
                config.listen = value
                    .as_str()
                    .filter(|listen| !listen.is_empty())
                    .map(str::to_owned);
            }
            "tag" => {
                config.tag = value
                    .as_str()
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_owned);
            }
            _ => {}
        }
    }
    Ok(config)
}

/// Install the metrics app and open its listener before the inbounds do, so a bind failure stops
/// startup rather than surfacing on the first scrape.
pub(crate) fn install(root: &Json) -> Result<Config, String> {
    let config = parse(root)?;
    let listener = config.listen.as_deref().map(bind).transpose()?;
    let tagged = if config.tag.is_some() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("cannot listen for metrics tag: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("cannot read metrics tag address: {error}"))?;
        Some((listener, address))
    } else {
        None
    };
    if let Some(listener) = listener {
        thread::Builder::new()
            .name("ferrox-metrics".to_owned())
            .spawn(move || serve(&listener))
            .map_err(|error| format!("cannot start metrics listener: {error}"))?;
    }
    if let Some((listener, address)) = tagged {
        thread::Builder::new()
            .name("ferrox-metrics-tag".to_owned())
            .spawn(move || serve(&listener))
            .map_err(|error| format!("cannot start metrics tag listener: {error}"))?;
        *TAGGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(address);
    } else {
        *TAGGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
    *lock() = Some(config.clone());
    Ok(config)
}

/// The tag the reference registers as an outbound handler, when the config names one.
pub(crate) fn tag() -> Option<String> {
    lock().as_ref().and_then(|config| config.tag.clone())
}

/// The loopback lane a route to [`tag`] dials.
pub(crate) fn tagged_address() -> Option<SocketAddr> {
    *TAGGED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bind(listen: &str) -> Result<TcpListener, String> {
    let address = if listen.starts_with(':') {
        format!("0.0.0.0{listen}")
    } else {
        listen.to_owned()
    };
    TcpListener::bind(&address)
        .map_err(|error| format!("cannot listen for metrics on `{listen}`: {error}"))
}

fn serve(listener: &TcpListener) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        thread::spawn(move || answer(stream));
    }
}

fn answer(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut request = [0u8; 4096];
    let read = match stream.read(&mut request) {
        Ok(0) | Err(_) => return,
        Ok(read) => read,
    };
    let head = String::from_utf8_lossy(&request[..read]);
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, content_type, body) = match path {
        "/debug/vars" => ("200 OK", "application/json", expvar()),
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", prometheus()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_owned()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn expvar() -> String {
    let snapshot = stats::snapshot();
    let mut rows = Vec::new();
    for (tag, traffic) in &snapshot.inbound {
        rows.push((
            format!("inbound>>>{tag}>>>traffic>>>uplink"),
            traffic.uplink,
        ));
        rows.push((
            format!("inbound>>>{tag}>>>traffic>>>downlink"),
            traffic.downlink,
        ));
    }
    for (tag, traffic) in &snapshot.outbound {
        rows.push((
            format!("outbound>>>{tag}>>>traffic>>>uplink"),
            traffic.uplink,
        ));
        rows.push((
            format!("outbound>>>{tag}>>>traffic>>>downlink"),
            traffic.downlink,
        ));
    }
    for (email, traffic) in &snapshot.user {
        rows.push((format!("user>>>{email}>>>traffic>>>uplink"), traffic.uplink));
        rows.push((
            format!("user>>>{email}>>>traffic>>>downlink"),
            traffic.downlink,
        ));
    }
    for (email, count) in &snapshot.online {
        rows.push((format!("user>>>{email}>>>online"), count.cast_signed()));
    }
    let mut out = String::from("{");
    for (index, (name, value)) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let mut key = String::new();
        crate::json::write(&Json::Str(name.clone()), &mut key);
        out.push_str(&key);
        out.push(':');
        out.push_str(&value.to_string());
    }
    out.push('}');
    out
}

fn prometheus() -> String {
    let snapshot = stats::snapshot();
    let mut out = String::new();
    for (tag, traffic) in &snapshot.inbound {
        let _ = writeln!(
            out,
            "ferrox_inbound_traffic_uplink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.uplink
        );
        let _ = writeln!(
            out,
            "ferrox_inbound_traffic_downlink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.downlink
        );
    }
    for (tag, traffic) in &snapshot.outbound {
        let _ = writeln!(
            out,
            "ferrox_outbound_traffic_uplink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.uplink
        );
        let _ = writeln!(
            out,
            "ferrox_outbound_traffic_downlink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.downlink
        );
    }
    for (email, traffic) in &snapshot.user {
        let _ = writeln!(
            out,
            "ferrox_user_traffic_uplink{{email=\"{}\"}} {}",
            escape(email),
            traffic.uplink
        );
        let _ = writeln!(
            out,
            "ferrox_user_traffic_downlink{{email=\"{}\"}} {}",
            escape(email),
            traffic.downlink
        );
    }
    for (email, count) in &snapshot.online {
        let _ = writeln!(
            out,
            "ferrox_user_online{{email=\"{}\"}} {}",
            escape(email),
            count
        );
    }
    out
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_listen_and_tag_are_read() {
        let root = crate::json::parse(r#"{"metrics":{"listen":"127.0.0.1:8080","tag":"metrics"}}"#)
            .expect("parses");
        assert_eq!(
            parse(&root).expect("metrics parses"),
            Config {
                listen: Some("127.0.0.1:8080".to_owned()),
                tag: Some("metrics".to_owned()),
            }
        );
    }

    #[test]
    fn a_metrics_section_that_is_not_an_object_is_refused() {
        let root = crate::json::parse(r#"{"metrics":[]}"#).expect("parses");
        assert!(parse(&root)
            .expect_err("metrics is an object")
            .contains("metrics"));
    }

    #[test]
    fn a_tag_opens_a_loopback_lane_that_answers_its_own_handler() {
        let _guard = crate::stats::test_lock();
        let root = crate::json::parse(r#"{"metrics":{"tag":"metrics"}}"#).expect("parses");
        install(&root).expect("metrics installs");
        assert_eq!(tag().as_deref(), Some("metrics"));
        let address = tagged_address().expect("a tagged lane");
        let mut stream = TcpStream::connect(address).expect("connects");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        stream
            .write_all(b"GET /debug/vars HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("writes");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("reads");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("application/json"));
        install(&crate::json::parse("{}").expect("parses")).expect("clears the tag");
        assert!(tagged_address().is_none());
    }

    #[test]
    fn the_prometheus_body_carries_a_registered_inbound_counter() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"system":{"statsInboundUplink":true}},
                "inbounds":[{"tag":"in"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        crate::stats::install(&root).expect("stats installs");
        crate::stats::inbound(Some("in")).read(12);
        let body = prometheus();
        assert!(body.contains(r#"ferrox_inbound_traffic_uplink{tag="in"} 12"#));
        crate::stats::clear();
    }

    #[test]
    fn prometheus_names_escape_a_quote() {
        assert_eq!(escape("a\"b"), "a\\\"b");
    }
}
