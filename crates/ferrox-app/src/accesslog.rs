use crate::json::Json;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};

#[derive(Clone, Default)]
struct Flow {
    source: Option<SocketAddr>,
    email: String,
}

thread_local! {
    static FLOW: RefCell<Flow> = RefCell::new(Flow::default());
}

/// The source and account a front's flows are logged with until the session ends.
pub(crate) struct FlowGuard;

pub(crate) fn flow(source: Option<SocketAddr>, email: &str) -> FlowGuard {
    FLOW.with(|flow| {
        *flow.borrow_mut() = Flow {
            source,
            email: email.to_owned(),
        };
    });
    FlowGuard
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        FLOW.with(|flow| *flow.borrow_mut() = Flow::default());
    }
}

/// One accepted line for the flow the current front is serving, at the destination its request named.
pub(crate) fn record_current(destination: &dyn std::fmt::Display) {
    let (source, email) = FLOW.with(|flow| {
        let flow = flow.borrow();
        (flow.source, flow.email.clone())
    });
    record(source, true, destination, None, "", &email);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) access: Option<String>,
    pub(crate) mask_address: bool,
}

static CONFIG: Mutex<Option<Config>> = Mutex::new(None);
static SINK: Mutex<Option<Box<dyn Write + Send>>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<Config>> {
    CONFIG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn sink() -> MutexGuard<'static, Option<Box<dyn Write + Send>>> {
    SINK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read the top-level `log` object, keeping the reference's names and the access path's meaning.
pub(crate) fn parse(root: &Json) -> Result<Config, String> {
    let Some(section) = root.get("log") else {
        return Ok(Config::default());
    };
    let Json::Obj(pairs) = section else {
        return Err("`log` is not an object".to_owned());
    };
    let mut config = Config::default();
    for (key, value) in pairs {
        match key.as_str() {
            "access" => {
                config.access = value
                    .as_str()
                    .filter(|path| !path.is_empty())
                    .map(str::to_owned);
            }
            "maskAddress" => {
                config.mask_address = value
                    .as_str()
                    .is_some_and(|mask| !mask.is_empty() && !mask.eq_ignore_ascii_case("none"));
            }
            _ => {}
        }
    }
    Ok(config)
}

/// Install the access sink before any inbound opens; a path that cannot be opened stops startup.
pub(crate) fn install(root: &Json) -> Result<Config, String> {
    let config = parse(root)?;
    let writer: Option<Box<dyn Write + Send>> = match config.access.as_deref() {
        Some("-") => Some(Box::new(std::io::stdout())),
        Some(path) => Some(Box::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| format!("cannot open access log `{path}`: {error}"))?,
        )),
        None => None,
    };
    *sink() = writer;
    *lock() = Some(config.clone());
    Ok(config)
}

/// One reference access line: `from <source> <accepted|rejected> <destination> [detour] reason email: <email>`.
pub(crate) fn record(
    source: Option<SocketAddr>,
    accepted: bool,
    destination: &dyn std::fmt::Display,
    detour: Option<&str>,
    reason: &str,
    email: &str,
) {
    let Some(config) = lock().clone() else {
        return;
    };
    let mut sink = sink();
    let Some(writer) = sink.as_mut() else {
        return;
    };
    let source = source.map_or_else(
        || "unknown".to_owned(),
        |source| address(source, config.mask_address),
    );
    let mut line = format!(
        "from {source} {} {destination}",
        if accepted { "accepted" } else { "rejected" }
    );
    if let Some(detour) = detour.filter(|detour| !detour.is_empty()) {
        line.push_str(" [");
        line.push_str(detour);
        line.push(']');
    }
    if !reason.is_empty() {
        line.push(' ');
        line.push_str(reason);
    }
    if !email.is_empty() {
        line.push_str(" email: ");
        line.push_str(email);
    }
    line.push('\n');
    let _ = writer.write_all(line.as_bytes());
    let _ = writer.flush();
}

fn address(address: SocketAddr, masked: bool) -> String {
    if !masked {
        return address.to_string();
    }
    match address {
        SocketAddr::V4(address) => format!("{}:{}", address.ip().octets()[0], address.port()),
        SocketAddr::V6(address) => format!("{}:{}", address.ip().segments()[0], address.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_access_and_mask_are_read() {
        let root = crate::json::parse(r#"{"log":{"access":"/tmp/access.log","maskAddress":"/8"}}"#)
            .expect("parses");
        assert_eq!(
            parse(&root).expect("log parses"),
            Config {
                access: Some("/tmp/access.log".to_owned()),
                mask_address: true,
            }
        );
    }

    #[test]
    fn a_log_section_that_is_not_an_object_is_refused() {
        let root = crate::json::parse(r#"{"log":1}"#).expect("parses");
        assert!(parse(&root).expect_err("log is an object").contains("log"));
    }

    #[test]
    fn a_recorded_line_names_the_source_verdict_destination_detour_reason_and_email() {
        let _guard = crate::stats::test_lock();
        let path = std::env::temp_dir().join(format!(
            "ferrox-access-{}-{}.log",
            std::process::id(),
            line!()
        ));
        let mut quoted = String::new();
        crate::json::write(&Json::Str(path.to_string_lossy().into_owned()), &mut quoted);
        let root =
            crate::json::parse(&format!(r#"{{"log":{{"access":{quoted}}}}}"#)).expect("parses");
        install(&root).expect("access log installs");
        let source: SocketAddr = "192.0.2.10:1234".parse().expect("address");
        record(
            Some(source),
            true,
            &"example.com:443",
            Some("proxy"),
            "accept",
            "a@b.c",
        );
        let text = std::fs::read_to_string(&path).expect("reads the line");
        assert_eq!(
            text,
            "from 192.0.2.10:1234 accepted example.com:443 [proxy] accept email: a@b.c\n"
        );
        let _ = std::fs::remove_file(&path);
        install(&crate::json::parse("{}").expect("parses")).expect("clears the sink");
    }

    #[test]
    fn a_flow_records_the_fronts_source_and_email() {
        let _guard = crate::stats::test_lock();
        let path = std::env::temp_dir().join(format!(
            "ferrox-access-flow-{}-{}.log",
            std::process::id(),
            line!()
        ));
        let mut quoted = String::new();
        crate::json::write(&Json::Str(path.to_string_lossy().into_owned()), &mut quoted);
        let root =
            crate::json::parse(&format!(r#"{{"log":{{"access":{quoted}}}}}"#)).expect("parses");
        install(&root).expect("access log installs");
        let source: SocketAddr = "192.0.2.10:1234".parse().expect("address");
        let flow = flow(Some(source), "a@b.c");
        record_current(&"example.com:443");
        drop(flow);
        let text = std::fs::read_to_string(&path).expect("reads the line");
        assert_eq!(
            text,
            "from 192.0.2.10:1234 accepted example.com:443 email: a@b.c
"
        );
        let _ = std::fs::remove_file(&path);
        install(&crate::json::parse("{}").expect("parses")).expect("clears the sink");
    }

    #[test]
    fn a_masked_address_keeps_the_first_octet_and_the_port() {
        let peer: SocketAddr = "192.0.2.10:443".parse().expect("address");
        assert_eq!(address(peer, true), "192:443");
        assert_eq!(address(peer, false), "192.0.2.10:443");
    }
}
