//! xray finds its config when no `-config` is given: the working directory first, then
//! `xray.location.config`'s directory, then stdin. Each refused spelling used to print usage.

use std::path::Path;
use std::process::{Command, Stdio};

/// The refusal a bare invocation earns, so the file it chose is provable: a `config.json` holding
/// broken JSON is refused with the path it was read from.
fn refusal(cwd: &Path, installed: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ferrox-app"))
        .args(args)
        .current_dir(cwd)
        .env("XRAY_LOCATION_CONFIG", installed)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn ferrox-app");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "a broken config was served: {stderr}"
    );
    assert!(
        !stderr.contains("usage:"),
        "the config was never looked for: {stderr}"
    );
    stderr
}

#[test]
fn a_bare_invocation_serves_the_config_it_discovers() {
    let dir = std::env::temp_dir().join(format!("ferrox-discovery-{}", std::process::id()));
    let here = dir.join("here");
    let empty = dir.join("empty");
    let installed = dir.join("installed");
    for dir in [&here, &empty, &installed] {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).expect("temp dir");
    }
    let broken = r#"{"inbounds": ]"#;
    std::fs::write(here.join("config.json"), broken).expect("the working directory's config");
    std::fs::write(installed.join("config.json"), broken).expect("the installed config");
    let named = |path: &Path| path.to_string_lossy().into_owned();
    let from_here = refusal(&here, &installed, &[]);
    assert!(
        from_here.contains(&named(&here.join("config.json"))),
        "the working directory's config is the one served: {from_here}"
    );
    let from_installed = refusal(&empty, &installed, &[]);
    assert!(
        from_installed.contains(&named(&installed.join("config.json"))),
        "with none in the working directory, `xray.location.config`'s is served: {from_installed}"
    );
    let from_run = refusal(&here, &installed, &["run"]);
    assert!(
        from_run.contains(&named(&here.join("config.json"))),
        "`run` with no flag is xray's bare invocation: {from_run}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
