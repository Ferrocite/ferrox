fn version_of(mod_text: &str, module: &str) -> Option<(u32, u32, u32)> {
    for line in mod_text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(module) {
            let version = fields.next()?.strip_prefix("v")?;
            let mut numbers = version.split('.').map(|part| part.parse::<u32>());
            let major = numbers.next().ok()??;
            let minor = numbers.next().ok()??;
            let patch = numbers.next().ok()??;
            return Some((major, minor, patch));
        }
    }
    None
}

#[test]
fn utls_oracle_does_not_pin_a_vulnerable_crypto() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let go_mod = std::fs::read_to_string(root.join("scripts/utls-oracle/go.mod")).expect("utls go.mod");
    let crypto = version_of(&go_mod, "golang.org/x/crypto").expect("crypto pin");
    assert!(crypto >= (0, 48, 0), "golang.org/x/crypto {crypto:?} is below the post-CVE floor");
    let sys = version_of(&go_mod, "golang.org/x/sys").expect("sys pin");
    assert!(sys >= (0, 42, 0), "golang.org/x/sys {sys:?} is below the peer floor");
    let go_sum = std::fs::read_to_string(root.join("scripts/utls-oracle/go.sum")).expect("utls go.sum");
    assert!(!go_sum.contains("golang.org/x/crypto v0.36.0"), "go.sum still pins the vulnerable crypto");
    assert!(!go_sum.contains("golang.org/x/sys v0.31.0"), "go.sum still pins the old sys");
}
