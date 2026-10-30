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
