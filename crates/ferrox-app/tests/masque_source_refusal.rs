use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_masque_inbound_refuses_a_udp_source_rule() {
    let dir = std::env::temp_dir().join(format!(
        "ferrox-masque-source-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        r#"{
            "inbounds": [{
                "tag": "masque-in",
                "listen": "127.0.0.1",
                "port": 0,
                "protocol": "masque"
            }],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }],
            "routing": {
                "rules": [{
                    "inboundTag": ["masque-in"],
                    "network": "udp",
                    "source": ["192.0.2.0/24"],
                    "outboundTag": "direct"
                }]
            }
        }"#,
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferrox-app"))
        .arg("-config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ferrox-app");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("reap");
            panic!(
                "ferrox-app did not refuse the MASQUE source rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("output");
    assert!(!output.status.success(), "the config was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("masque inbound masque-in names `source`"),
        "unexpected refusal: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
