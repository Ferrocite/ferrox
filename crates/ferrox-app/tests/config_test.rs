//! `-test` builds every handler a config names and stops before the first listener, so an
//! installer's `ExecStartPre` gets xray's verdict — `Configuration OK.` and status 0, or
//! `Failed to start:` and status 23 — without touching a port a running instance holds.

use std::net::TcpListener;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferrox-app"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn ferrox-app")
}

fn config_path(name: &str, text: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ferrox-test-{name}-{}.json", std::process::id()));
    std::fs::write(&path, text).expect("write config");
    path
}

#[test]
fn test_proves_a_config_whose_port_is_held() {
    // The parent keeps the configured port, so only a run that never binds it can report OK.
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("local address").port();
    let text = format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":{port},"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}}}}],
        "outbounds":[{{"protocol":"freedom"}}]}}"#
    );
    let path = config_path("held", &text);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-test` refused a servable config: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    // A serve with the same config is the control: the port really is taken.
    let served = run(&["-c", &named]);
    assert!(
        !served.status.success(),
        "the held port was never actually held"
    );
    let _ = std::fs::remove_file(&path);
}

/// A cert path the config names and the disk does not have is a config error: the handler was
/// really built, not just the JSON parsed.
#[test]
fn test_refuses_a_config_whose_cert_is_missing() {
    let text = r#"{"inbounds":[{"listen":"127.0.0.1","port":443,"protocol":"vless",
        "settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"decryption":"none"},
        "streamSettings":{"security":"tls","tlsSettings":{"certificates":[
        {"certificateFile":"/nonexistent/ferrox-test-cert.pem","keyFile":"/nonexistent/ferrox-test-key.pem"}]}}}],
        "outbounds":[{"protocol":"freedom"}]}"#;
    let path = config_path("cert", text);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(23),
        "a missing cert is xray's config-error status: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Failed to start:"),
        "the refusal carries xray's spelling: {stdout}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_refuses_json_it_cannot_parse() {
    let path = config_path("broken", r#"{"inbounds": ]"#);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(23), "{stdout}");
    assert!(stdout.contains("Failed to start:"), "{stdout}");
    let _ = std::fs::remove_file(&path);
}

fn geodata_config(url: &str) -> String {
    format!(
        r#"{{"geodata": {{"cron": "0 3 * * *", "outbound": "direct",
        "assets": [{{"url": "{url}", "file": "Cargo.toml"}}]}},
        "inbounds": [{{"tag": "in", "listen": "127.0.0.1", "port": 18095, "protocol": "socks",
        "settings": {{"auth": "noauth"}}}}],
        "outbounds": [{{"protocol": "freedom", "tag": "direct"}}]}}"#
    )
}

/// The reference refuses an asset URL that is not HTTPS while building the config, so `-test` does too.
#[test]
fn test_refuses_a_geodata_asset_over_plain_http() {
    let path = config_path(
        "geodata-http",
        &geodata_config("http://example.test/geosite.dat"),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(23),
        "a plain-http asset is xray's config error: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("invalid geodata asset url") && stdout.contains("scheme must be https"),
        "the refusal carries the reference's spelling: {stdout}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A schedule this tree does not run is still a config the reference runs, so it starts with one line saying so.
#[test]
fn test_accepts_a_geodata_schedule_it_does_not_carry() {
    let path = config_path(
        "geodata-cron",
        &geodata_config("https://example.test/geosite.dat"),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a valid geodata block is servable: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("asset downloads are not carried"),
        "the unscheduled refresh is named instead of silent"
    );
    let _ = std::fs::remove_file(&path);
}

fn reality_config(seed: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":18096,"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}},
        "streamSettings":{{"network":"tcp","security":"reality","realitySettings":{{
        "target":"cover.test:443","serverNames":["www.example.com"],
        "privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortIds":[""],
        "mldsa65Seed":"{seed}"}}}}}}],"outbounds":[{{"protocol":"freedom"}}]}}"#
    )
}

/// The reference refuses a seed that is its own private key while building the config, so `-test` does too.
#[test]
fn test_refuses_a_reality_seed_that_names_the_private_key() {
    let path = config_path(
        "reality-seed-alias",
        &reality_config("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(23),
        "an aliased seed is xray's config error: {}{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(r#""mldsa65Seed" and "privateKey" can not be the same value"#),
        "the refusal carries the reference's spelling: {stderr}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A seed the reference signs with is still a config this tree runs, so it starts with one line saying the binding is absent.
#[test]
fn test_accepts_a_reality_seed_it_does_not_carry_the_binding_for() {
    let path = config_path(
        "reality-seed",
        &reality_config("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a valid seed is servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            r#""mldsa65Seed" is checked, and the ML-DSA-65 binding it names is not carried"#
        ),
        "the absent binding is named instead of silent"
    );
    let _ = std::fs::remove_file(&path);
}

fn xmux_inbound(xmux: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":18097,"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}},
        "streamSettings":{{"network":"xhttp","xhttpSettings":{{
        "path":"/share","mode":"stream-up","xmux":{xmux}}}}}}}],"outbounds":[{{"protocol":"freedom"}}]}}"#
    )
}

/// The reference refuses both pool bounds at once while building the config, so `-test` does too.
#[test]
fn test_refuses_xhttp_xmux_with_both_bounds() {
    let path = config_path(
        "xmux-both",
        &xmux_inbound(r#"{"maxConnections":3,"maxConcurrency":2}"#),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(23),
        "two exclusive bounds are xray's config error: {}{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("maxConnections cannot be specified together with maxConcurrency"),
        "the refusal carries the reference's spelling: {stderr}"
    );
    let _ = std::fs::remove_file(&path);
}

fn xmux_outbound(xmux: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":18098,"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}}}}],
        "outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"192.0.2.1","port":443,
        "users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]}}]}},
        "streamSettings":{{"network":"xhttp","xhttpSettings":{{
        "path":"/share","mode":"stream-up","xmux":{xmux}}}}}}}]}}"#
    )
}

/// A pool bound the reference dials out of is still a config this tree runs, so it starts with one line saying the bound is not applied.
#[test]
fn test_accepts_xhttp_xmux_bounds_it_does_not_apply() {
    let path = config_path("xmux-one", &xmux_outbound(r#"{"maxConnections":3}"#));
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a valid xmux block is servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(r#"xhttp: "xmux" bounds are checked"#),
        "the unapplied pool is named instead of silent"
    );
    let _ = std::fs::remove_file(&path);
}

fn config_dir(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ferrox-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create config dir");
    for (file, text) in files {
        std::fs::write(dir.join(file), text).expect("write config");
    }
    dir
}

fn held_port_inbound(port: u16) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":{port},"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}}}}]}}"#
    )
}

/// xray's `-confdir` loads every `*.json` in the directory and merges them; here the flag was refused.
#[test]
fn test_reads_a_confdir_the_reference_discovers() {
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("local address").port();
    let dir = config_dir(
        "confdir",
        &[
            ("01-inbound.json", &held_port_inbound(port)),
            (
                "02-outbound.json",
                r#"{"outbounds":[{"protocol":"freedom"}]}"#,
            ),
        ],
    );
    let named = dir.to_string_lossy().into_owned();
    let output = run(&["-test", "-confdir", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a config dir the reference reads is servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two `-c` files merge into one config, as the reference's `MergeConfig` does.
#[test]
fn test_merges_a_second_config_file() {
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("local address").port();
    let inbound = config_path("merge-inbound", &held_port_inbound(port));
    let outbound = config_path(
        "merge-outbound",
        r#"{"outbounds":[{"protocol":"freedom"}]}"#,
    );
    let output = run(&[
        "-test",
        "-c",
        &inbound.to_string_lossy(),
        "-c",
        &outbound.to_string_lossy(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "two files the reference merges are servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    let _ = std::fs::remove_file(&inbound);
    let _ = std::fs::remove_file(&outbound);
}

/// The reference's `Override` replaces a block whole, replaces an inbound or outbound of the same
/// tag in place, and prepends one no config named yet; `-dump` prints what the merge built.
#[test]
fn dump_prints_the_config_the_reference_would_merge() {
    let base = r#"{"log":{"loglevel":"warning"},
        "inbounds":[{"tag":"in","listen":"127.0.0.1","port":18099,"protocol":"socks",
        "settings":{"auth":"noauth"}}],
        "outbounds":[{"tag":"direct","protocol":"freedom"}]}"#;
    let over = r#"{"log":{"loglevel":"debug"},
        "inbounds":[{"tag":"in","listen":"127.0.0.1","port":18100,"protocol":"http"},
        {"tag":"extra","listen":"127.0.0.1","port":18101,"protocol":"socks","settings":{"auth":"noauth"}}],
        "outbounds":[{"tag":"direct","protocol":"blackhole"},{"tag":"new","protocol":"blackhole"}]}"#;
    let dir = config_dir("dump", &[("01-base.json", base), ("02-over.json", over)]);
    let named = dir.to_string_lossy().into_owned();
    let output = run(&["-dump", "-confdir", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-dump` prints and exits: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(r#""port":18100"#) && !stdout.contains(r#""port":18099"#),
        "an inbound of the same tag is replaced in place: {stdout}"
    );
    assert!(
        stdout.contains(r#""port":18101"#),
        "an inbound of a tag no file named yet is appended: {stdout}"
    );
    assert!(
        stdout.contains(r#""loglevel":"debug""#) && !stdout.contains("warning"),
        "a block the later file names is replaced whole: {stdout}"
    );
    assert!(
        stdout.contains("blackhole") && !stdout.contains("freedom"),
        "an outbound of the same tag is replaced in place: {stdout}"
    );
    let new = stdout.find(r#""tag":"new""#).expect("the new outbound");
    let direct = stdout
        .find(r#""tag":"direct""#)
        .expect("the replaced outbound");
    assert!(
        new < direct,
        "an outbound no file named yet prepends, so it stays first: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file whose name contains `tail` appends its new outbounds instead of prepending them.
#[test]
fn a_config_file_named_tail_appends_its_outbounds() {
    let base = r#"{"outbounds":[{"tag":"direct","protocol":"freedom"}]}"#;
    let over = r#"{"outbounds":[{"tag":"last","protocol":"blackhole"}]}"#;
    let plain = config_dir(
        "append-plain",
        &[("01-base.json", base), ("02-extra.json", over)],
    );
    let tail = config_dir(
        "append-tail",
        &[("01-base.json", base), ("99-tail.json", over)],
    );
    let first = run(&["-dump", "-confdir", &plain.to_string_lossy()]);
    let second = run(&["-dump", "-confdir", &tail.to_string_lossy()]);
    let first = String::from_utf8_lossy(&first.stdout);
    let second = String::from_utf8_lossy(&second.stdout);
    assert!(
        first.find(r#""tag":"last""#).expect("the new outbound")
            < first.find(r#""tag":"direct""#).expect("the base outbound"),
        "an ordinary file prepends its outbounds: {first}"
    );
    assert!(
        second.find(r#""tag":"direct""#).expect("the base outbound")
            < second.find(r#""tag":"last""#).expect("the new outbound"),
        "a file named tail appends them: {second}"
    );
    let _ = std::fs::remove_dir_all(&plain);
    let _ = std::fs::remove_dir_all(&tail);
}

/// The merged config is what the handlers are built from: a later file's inbound of the same tag
/// is the one built, so its missing certificate is the refusal `-test` reports.
#[test]
fn a_later_config_file_replaces_an_inbound_the_handler_builds() {
    let base = r#"{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":18102,"protocol":"socks",
        "settings":{"auth":"noauth"}}]}"#;
    let over = r#"{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":443,"protocol":"vless",
        "settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"decryption":"none"},
        "streamSettings":{"security":"tls","tlsSettings":{"certificates":[
        {"certificateFile":"/nonexistent/ferrox-test-cert.pem","keyFile":"/nonexistent/ferrox-test-key.pem"}]}}}]}"#;
    let dir = config_dir(
        "merged-inbound",
        &[("01-base.json", base), ("02-over.json", over)],
    );
    let named = dir.to_string_lossy().into_owned();
    let output = run(&["-test", "-confdir", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(23),
        "the later file's inbound is the one built: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("no servable inbound")
            && String::from_utf8_lossy(&output.stderr).contains("unreadable vless tls identity"),
        "the refusal names the certificate the later file's inbound is missing: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
