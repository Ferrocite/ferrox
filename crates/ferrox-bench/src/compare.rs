use ferrox_core::vless::VlessLink;
use std::fmt::Write as _;

pub fn describe_redacted(link: &VlessLink) -> String {
    format!(
        "type={} security={} flow={} fp={} sni-present={} support={}",
        link.param("type"),
        link.param("security"),
        link.flow(),
        if link.fingerprint().is_empty() {
            "-"
        } else if link.wants_unsafe_fingerprint() {
            "unsafe-*"
        } else {
            "set"
        },
        !link.sni().is_empty(),
        link.support(),
    )
}

pub fn compare_offline(link: &VlessLink) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "\n## Config comparison (offline, no network)\n");
    let _ = writeln!(s, "link: `{}`", describe_redacted(link));
    let _ = writeln!(
        s,
        "support: `{}` (unsafe opt-in: none — see `policy::UnsafeOptIn`)",
        link.support()
    );

    let target = "example.com";
    let need = link.request_header_len(target);
    let mut hdr_buf = vec![0u8; need];
    let iters = 50_000u64;
    let t0 = std::time::Instant::now();
    for _ in 0..iters {
        let n = link.encode_into(target, 443, &mut hdr_buf);
        std::hint::black_box(n);
    }
    let ns = t0.elapsed().as_secs_f64() * 1e9 / iters as f64;
    let _ = writeln!(s, "\n| what | result |");
    let _ = writeln!(s, "|---|---|");
    let _ = writeln!(s, "| header len | {need} B |");
    let _ = writeln!(
        s,
        "| encode_into | {ns:.1} ns/op, 0 allocs (caller buffer) |"
    );

    let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let nonce: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));
    for len in [1440usize, 16384] {
        let mut buf = vec![0u8; len];
        let iters = (4 * 1024 * 1024u64 / len.max(1) as u64).clamp(64, 20_000);
        let mut bases = Vec::with_capacity(5);
        let mut ours_v = Vec::with_capacity(5);
        for _ in 0..5 {
            let t = std::time::Instant::now();
            for _ in 0..iters {
                ferrox_core::reference::reference_xor(
                    &key,
                    &nonce,
                    0,
                    std::hint::black_box(&mut buf[..]),
                );
            }
            bases.push(t.elapsed().as_secs_f64() / iters as f64);
            let t = std::time::Instant::now();
            for _ in 0..iters {
                ferrox_core::record::fill_exact(
                    &key,
                    &nonce,
                    0,
                    std::hint::black_box(&mut buf[..]),
                );
            }
            ours_v.push(t.elapsed().as_secs_f64() / iters as f64);
        }
        bases.sort_by(f64::total_cmp);
        ours_v.sort_by(f64::total_cmp);
        let (base, ours) = (bases[2], ours_v[2]);
        let _ = writeln!(
            s,
            "| record {len} B | ref {:.1} ns, ours {:.1} ns, {:.2}x (median of 5) |",
            base * 1e9,
            ours * 1e9,
            base / ours
        );
    }

    s.push_str("\n| upstream | pinned rev | suite |\n");
    s.push_str("|---|---|---|\n");
    for (name, rev, suite) in pinned_sources() {
        let short = rev.chars().take(7).collect::<String>();
        let suite_cell = if suite.is_empty() {
            "—"
        } else {
            suite.as_str()
        };
        let _ = writeln!(s, "| {name} | `{short}` | {suite_cell} |");
    }

    s.push_str("\n| core | vless-tcp-reality-vision | live throughput |\n");
    s.push_str("|---|---|---|\n");
    let cell = match link.support() {
        ferrox_core::transport::Support::Implemented { method } => format!("ours ({method})"),
        ferrox_core::transport::Support::Planned { reason } => format!("empty: {reason}"),
        ferrox_core::transport::Support::UnsafeRequiresOptIn { reason } => {
            format!("empty: {reason}")
        }
    };
    let _ = writeln!(
        s,
        "| ferrox | {cell} | empty: live runs only with FERROX_LIVE=1 |"
    );
    s.push_str("| xray-core | empty: built from pin in compare.yml; no live without secret | empty: needs FERROX_LIVE=1 + secret |\n");
    s.push_str("| sing-box | empty: built from pin in compare.yml; no live without secret | empty: needs FERROX_LIVE=1 + secret |\n");
    s.push_str("| xray-rust | empty: built from pin in compare.yml; no live without secret | empty: needs FERROX_LIVE=1 + secret |\n");
    s.push_str("| pattng | empty: unsafe rows need UnsafeOptIn harness; built from pin in compare.yml | empty: needs FERROX_LIVE=1 + secret |\n");
    s.push_str("| zeronet/zray | empty: ferrox-app tracks its app surface on ferrox-core; built from pin in compare.yml | empty: needs FERROX_LIVE=1 + secret |\n");
    s.push_str("\n> Credentials (uuid, pbk, sid, host) are never printed. A live column\n> appears only when CI is given a working config as a secret and\n> `FERROX_LIVE=1`; otherwise every live cell stays empty with its reason.\n");
    s
}

fn pinned_sources() -> Vec<(String, String, String)> {
    const PINS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../upstream/pins.toml"
    ));
    let mut out = Vec::new();
    let mut name = String::new();
    let mut rev = String::new();
    let mut suite = String::new();
    let mut flush = |name: &mut String, rev: &mut String, suite: &mut String| {
        if !name.is_empty() {
            out.push((
                std::mem::take(name),
                std::mem::take(rev),
                std::mem::take(suite),
            ));
        }
    };
    for line in PINS.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("[sources.")
            .and_then(|r| r.strip_suffix(']'))
        {
            flush(&mut name, &mut rev, &mut suite);
            name = rest.to_string();
        } else if let Some(v) = value_of(line, "rev") {
            rev = v;
        } else if let Some(v) = value_of(line, "suite") {
            suite = v;
        }
    }
    flush(&mut name, &mut rev, &mut suite);
    out
}

fn value_of(line: &str, key: &str) -> Option<String> {
    let (k, v) = line.split_once('=')?;
    if k.trim() != key {
        return None;
    }
    Some(
        v.trim()
            .trim_start_matches('"')
            .trim_end_matches('"')
            .to_string(),
    )
}
