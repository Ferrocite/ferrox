use crate::json::Json;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Default)]
struct Flow {
    source: Option<SocketAddr>,
    email: String,
    level: u32,
    online: Option<Arc<crate::stats::OnlineLease>>,
}

thread_local! {
    static FLOW: RefCell<Flow> = RefCell::new(Flow::default());
}

/// The source and account a front's flows are logged with until the session ends.
pub(crate) struct FlowGuard;

pub(crate) fn flow(source: Option<SocketAddr>, email: &str, level: u32) -> FlowGuard {
    FLOW.with(|flow| {
        *flow.borrow_mut() = Flow {
            source,
            email: email.to_owned(),
            level,
            online: None,
        };
    });
    FlowGuard
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        FLOW.with(|flow| *flow.borrow_mut() = Flow::default());
    }
}

/// The account a front authenticates after its flow opened: the source and the lease stay, the identity is the one the client proved.
pub(crate) fn reidentify(email: &str, level: u32) {
    FLOW.with(|flow| {
        let mut flow = flow.borrow_mut();
        email.clone_into(&mut flow.email);
        flow.level = level;
    });
}

/// One accepted line for the flow the current front is serving, at the destination its request named.
pub(crate) fn record_current(destination: &dyn std::fmt::Display) {
    let (source, email) = FLOW.with(|flow| {
        let flow = flow.borrow();
        (flow.source, flow.email.clone())
    });
    record(source, true, destination, None, "", &email);
    if email.is_empty() {
        return;
    }
    FLOW.with(|flow| {
        let mut flow = flow.borrow_mut();
        if flow.online.is_none() {
            flow.online = crate::stats::online(&flow.email, flow.level);
        }
    });
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
    let writer = open_access(config.access.as_deref())?;
    *sink() = writer;
    *lock() = Some(config.clone());
    Ok(config)
}

/// Reopen the access path on `RestartLogger`, so a rotated file is picked up without a restart.
/// The new writer is opened before the old one is dropped; a path that cannot be opened leaves
/// the running sink in place and answers the call with the failure.
pub(crate) fn restart() -> Result<(), String> {
    let Some(config) = lock().clone() else {
        return Ok(());
    };
    let writer = open_access(config.access.as_deref())?;
    *sink() = writer;
    Ok(())
}

fn open_access(access: Option<&str>) -> Result<Option<Box<dyn Write + Send>>, String> {
    match access {
        Some("-") => Ok(Some(Box::new(std::io::stdout()))),
        Some(path) => OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(|file| Some(Box::new(file) as Box<dyn Write + Send>))
            .map_err(|error| format!("cannot open access log `{path}`: {error}")),
        None => Ok(None),
    }
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
    let mut line = String::with_capacity(64 + source.len());
    line.push_str("from ");
    line.push_str(&source);
    line.push(' ');
    line.push_str(if accepted { "accepted " } else { "rejected " });
    let _ = std::fmt::write(
        &mut Escaper { out: &mut line },
        format_args!("{destination}"),
    );
    if let Some(detour) = detour.filter(|detour| !detour.is_empty()) {
        line.push_str(" [");
        push_escaped(&mut line, detour);
        line.push(']');
    }
    if !reason.is_empty() {
        line.push(' ');
        push_escaped(&mut line, reason);
    }
    if !email.is_empty() {
        line.push_str(" email: ");
        push_escaped(&mut line, email);
    }
    line.push('\n');
    let _ = writer.write_all(line.as_bytes());
    let _ = writer.flush();
}

/// A line holds one entry: a path, tag or account that carries a control byte is escaped, not
/// written through, so nothing a peer names can start a second record.
fn push_escaped(out: &mut String, value: &str) {
    let mut start = 0;
    for (at, ch) in value.char_indices() {
        if ch == '\\' {
            out.push_str(&value[start..at]);
            out.push_str("\\\\");
            start = at + 1;
        } else if ch.is_control() {
            out.push_str(&value[start..at]);
            out.extend(ch.escape_default());
            start = at + ch.len_utf8();
        }
    }
    out.push_str(&value[start..]);
}

/// The destination is a `Display`, so its bytes are escaped as they are written rather than materialised into a second string first.
struct Escaper<'a> {
    out: &'a mut String,
}

impl std::fmt::Write for Escaper<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        push_escaped(self.out, text);
        Ok(())
    }
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
    fn a_clean_field_is_escaped_without_a_second_buffer() {
        let mut out = String::with_capacity(64);
        let ((), counts) =
            ferrox_core::alloc_count::measure(|| push_escaped(&mut out, "example.com:443"));
        assert_eq!(counts.allocs, 0, "a clean field allocated: {counts:?}");
        assert_eq!(out, "example.com:443");
    }

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
    fn a_destination_from_the_wire_cannot_forge_a_second_line() {
        let _guard = crate::stats::test_lock();
        let path = std::env::temp_dir().join(format!(
            "ferrox-access-wire-{}-{}.log",
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
            false,
            &"bad\nline:443",
            Some("tag\nx"),
            "why\ny",
            "a@b.c\nz",
        );
        let text = std::fs::read_to_string(&path).expect("reads the line");
        assert_eq!(text.lines().count(), 1, "one request writes one line");
        for field in ["bad\\nline:443", "[tag\\nx]", "why\\ny", "email: a@b.c\\nz"] {
            assert!(text.contains(field), "{field:?} is escaped: {text:?}");
        }
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
        let flow = flow(Some(source), "a@b.c", 0);
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
    fn a_recorded_flow_holds_the_online_lease() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        crate::policy::clear();
        install(&crate::json::parse("{}").expect("parses")).expect("clears the sink");
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserOnline":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        crate::stats::install(&root).expect("stats installs");
        let source: SocketAddr = "192.0.2.10:1234".parse().expect("address");
        let flow = flow(Some(source), "a@b.c", 1);
        record_current(&"example.com:443");
        assert_eq!(crate::stats::snapshot().online.get("a@b.c"), Some(&1));
        drop(flow);
        assert_eq!(crate::stats::snapshot().online.get("a@b.c"), None);
        crate::stats::clear();
        crate::policy::clear();
    }

    #[test]
    fn a_masked_address_keeps_the_first_octet_and_the_port() {
        let peer: SocketAddr = "192.0.2.10:443".parse().expect("address");
        assert_eq!(address(peer, true), "192:443");
        assert_eq!(address(peer, false), "192.0.2.10:443");
    }

    #[cfg(unix)]
    #[test]
    fn a_restart_reopens_the_rotated_access_path() {
        let _guard = crate::stats::test_lock();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-access-restart-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("creates the log directory");
        let path = dir.join("access.log");
        let rotated = dir.join("access.log.1");
        let mut quoted = String::new();
        crate::json::write(&Json::Str(path.to_string_lossy().into_owned()), &mut quoted);
        let root =
            crate::json::parse(&format!(r#"{{"log":{{"access":{quoted}}}}}"#)).expect("parses");
        install(&root).expect("access log installs");
        let source: SocketAddr = "192.0.2.10:1234".parse().expect("address");
        record(Some(source), true, &"first.example:443", None, "", "");
        std::fs::rename(&path, &rotated).expect("rotates the access log");
        restart().expect("reopens the path");
        record(Some(source), true, &"second.example:443", None, "", "");
        let opened = std::fs::read_to_string(&path).expect("reads the new file");
        let previous = std::fs::read_to_string(&rotated).expect("reads the rotated file");
        assert_eq!(opened, "from 192.0.2.10:1234 accepted second.example:443\n");
        assert_eq!(
            previous,
            "from 192.0.2.10:1234 accepted first.example:443\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
        install(&crate::json::parse("{}").expect("parses")).expect("clears the sink");
    }
}
