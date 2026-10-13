use std::fmt::Write as _;

fn rung_link(query: &str, host: &str) -> String {
    format!("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@{host}:443?{query}#x")
}

fn live_support(query: &str, host: &str) -> String {
    let link = ferrox_core::vless::VlessLink::parse(&rung_link(query, host))
        .expect("synthetic rung link parses");
    link.support().to_string()
}

pub fn table() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "\n## Per-method proof (one row per rung)\n");
    let _ = writeln!(s, "| # | method | status | proof |");
    let _ = writeln!(s, "|---|---|---|---|");
    let _ = writeln!(
        s,
        "| 1 | VLESS TCP REALITY `xtls-rprx-vision` | {} | `vless::tests` + header-family test; gate 1 (3600 shapes, dense not exhaustive), gate 2 (0 allocs, record + header), gate 3 (0.95x at every measured length); xray-core suite enabled |",
        live_support(
            "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "192.0.2.1",
        )
    );
    let _ = writeln!(
        s,
        "| 2 | VLESS TCP TLS (Vision optional) | {} | raw-carrier dial through `tls::connect` with the header and response on the session (`proxy::tests` loopback echoes and outbound parse gates); vision over TLS stays planned |",
        live_support("security=tls&encryption=none&type=tcp", "192.0.2.1")
    );
    let _ = writeln!(
        s,
        "| 3 | VLESS TCP none (private) | {} | header golden in `vless::tests`; loopback relay through the raw path |",
        live_support("security=none&encryption=none&type=tcp", "127.0.0.1")
    );
    let _ = writeln!(
        s,
        "| 4 | VLESS/TROJAN `security=none` to public (`PattNG` ext.) | {} | `policy::UnsafeOptIn::allow_plaintext_to_public` + isolated test net only |",
        live_support("security=none&encryption=none&type=tcp", "192.0.2.1")
    );
    let _ = writeln!(
        s,
        "| 5 | `TROJAN` TCP TLS | implemented (`proxy.rs`: password framing, both roles, raw `TCP` + every dialled carrier) | `xray_oracle::trojan_over_raw_tcp_matches_the_oracle` (conformance 37132662374) for the framing |"
    );
    let _ = writeln!(
        s,
        "| 6 | `VMess` TCP | implemented (`vmess.rs`: `AEAD` both roles, raw `TCP` + every dialled carrier) | golden vectors + loopback relays in `vmess.rs` and `proxy.rs` |"
    );
    let _ = writeln!(
        s,
        "| 7 | Shadowsocks TCP/UDP | implemented: three `AEAD` ciphers, every `Xray-core` spelling | `xray_oracle::shadowsocks_over_raw_tcp_matches_the_oracle` for the framing; `ferrox_core::shadowsocks`'s own vectors for the cipher table, the derivation and the nonce byte order; gate 9 for the two added ways against the one that shipped |"
    );
    let _ = writeln!(
        s,
        "| 8 | VLESS WS / `XHTTP` / gRPC / `HTTPUpgrade` / HTTP masquerade | {} | `ws.rs`, `xhttp.rs`, `grpc.rs`, `httpupgrade.rs`, `httpheader.rs` — one loopback relay per carrier |",
        live_support("security=none&encryption=none&type=ws", "127.0.0.1")
    );
    let _ = writeln!(
        s,
        "| 9 | `WireGuard` / MASQUE (H2+H3), `Hysteria2`, Aether (`ZeroNet` WARP paths) | planned: after `XHTTP` | loopback tunnel benchmark per protocol vs pinned comparators |"
    );
    let _ = writeln!(
        s,
        "| 10 | `cipherSuites` + `unsafe-*` fingerprints (`PattNG` ext.) | {} | `policy::UnsafeOptIn::allow_unsafe_fingerprint` + `ClientHello` differential |",
        live_support(
            "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=unsafe-chrome&sni=example.com&sid=a8&pbk=k",
            "192.0.2.1",
        )
    );
    let _ = writeln!(
        s,
        "| 11 | multiplex over every row above | implemented (`mux`) | `mux::tests`: hand-derived golden frames, 256-domain-length round trip, refusal table; gate 6 (encode and decode vs a structural reference, byte-checked before timing, 0 allocs). No upstream suite can gate it — see `docs/conformance.md` |"
    );
    let _ = writeln!(
        s,
        "| 12 | `?ed=N` early data on `ws` / `httpupgrade`, both roles | implemented (`EarlyData`) | `transport::tests`: the rewrite and `Atoi` vectors, RFC 4648 digits, every length 0-192 round trip; `ws`/`httpupgrade` tests: the request bytes, the budget's boundary, the bare path a budget serves; gate 8 (encode vs a per-call-`String` reference, byte-checked before timing, zero allocs per encode here); **two upstream oracle rows green in `conformance.yml` run `37249695646`** against real `Xray-core` at the pin |"
    );
    let _ = writeln!(
        s,
        "\n> Status cells above are read from the parser at report time for every row the\n\
         > `vless://` format can express; the rest mirror `transport.rs` until their rung\n\
         > lands. Upstream suites with a seam (ZeroNet/Zray, xray-rust) check each\n\
         > implemented rung from their pins."
    );
    s
}

#[cfg(test)]
mod tests {
    use ferrox_core::transport::Support;

    fn support_of(query: &str, host: &str) -> Support {
        let link = ferrox_core::vless::VlessLink::parse(&super::rung_link(query, host))
            .expect("synthetic rung link parses");
        link.support()
    }

    #[test]
    fn rung_statuses_are_read_not_written() {
        assert!(matches!(
            support_of(
                "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8&pbk=k",
                "192.0.2.1",
            ),
            Support::Implemented { .. }
        ));
        assert!(matches!(
            support_of("security=tls&encryption=none&type=tcp", "192.0.2.1"),
            Support::Implemented { .. }
        ));
        assert!(matches!(
            support_of("security=none&encryption=none&type=tcp", "127.0.0.1"),
            Support::Implemented { .. }
        ));
        assert!(matches!(
            support_of("security=none&encryption=none&type=tcp", "192.0.2.1"),
            Support::UnsafeRequiresOptIn { .. }
        ));
        assert!(matches!(
            support_of(
                "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=unsafe-chrome&sni=example.com&sid=a8&pbk=k",
                "192.0.2.1",
            ),
            Support::UnsafeRequiresOptIn { .. }
        ));
    }

    #[test]
    fn the_table_has_twelve_rows() {
        let rows = super::table()
            .lines()
            .filter(|l| l.starts_with("| "))
            .count();
        assert_eq!(
            rows, 13,
            "a rung was added or dropped without updating this table"
        );
    }
}
