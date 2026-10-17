# Ferrox

FERROX — Fast Efficient Relay Router Overlay X. *ferro*, iron, for Rust; *X*, for Xray.

A from-scratch proxy core, built to be **bit-identical to the implementations it replaces** and **verifiably not slower than any of them**.

## Goals

1. **Prove everything shipped is faster and leaner.** Bit-identical output, fewer operations, zero surviving copies, no allocation; counts prove, durations suggest.
2. **Be a drop-in replacement for Xray-core.** Not "implement its protocols" — run its pinned test suites unmodified against a Ferrox binary in CI, plus every suite with a seam to inject it through.
3. **Be a drop-in replacement for zeptun**, the `tun2socks` engine: TUN to TCP/UDP/ICMP through a SOCKS5 or direct handler, `userspace` / `hybrid` / `system` stacks.
4. **Be feature-complete in what quiche, slipstream and aether are ahead on.** QUIC and MASQUE, DNS-tunnel carriers, nested tunnels, multi-path schedulers, domain fronting. Libraries and product surfaces, read for the technique and implemented on Ferrox's terms.
5. **Spoof SNI without root.** DPI circumvention by injecting a fake TLS ClientHello with an allowlisted SNI ahead of the real handshake. `VpnService` TUN plus a userspace TCP stack does it in user space. Nothing in CI checks this yet.

## How it is built

- **One algorithm, four widths.** The record layer is one generic function over a `Lanes` trait — portable arrays, NEON, SSE2, AVX2 — so backends execute the *same source* and cannot disagree. The portable path is safe Rust, so Miri interprets the ladder and the SIMD modules stay five instructions each whose only failure mode is a wrong answer.
- **Rewrite, not port.** The minimal subset covering the matrix, proven faster down to the parsing. One line of comment per item at most, no changelogs — checked by `scripts/check-comments.sh`. The shared protocol is `crates/ferrox-prompt/prompts.md`.
- **Counts prove, durations suggest.** Instruction counts are gated exact; allocation counts, copy counts and syscall counts are gated exactly too, and each method page names the checker for every number it states. A count nobody has measured is written `UNBLESSED`, which is a claim that is open, not a number.
- **One TLS stack, one interface.** `TlsProvider` is implemented by rustls, and the provider *is* `Read + Write`, so nothing above can depend on the stack underneath. No feature to select, no build without TLS.
- **quiche is the default QUIC, not a preference.** Whenever a rung needs QUIC and quiche is feasible, quiche; anything else must name the rung, the library, and the measurement that won.
- **The reference is not as fast as it looks.** Comparators often ship SIMD behind a cfg nothing sets, so part of any speedup is the baseline not using its path. Every report prints both backends in the header; a ratio quoted without both names is not a measurement.
- **Lints and operation counts are local; nothing connection-dependent is.** `./scripts/check.sh` runs before every push. Benchmarks, parity, upstream suites and Miri are CI-only, because every developer machine is behind a VPN and a proxy — a local dial measures a tunnel, not the reference.
- **Nothing runs on a merge.** A merge cannot break what a pull request did not already prove, so every gate fires on the PR and `main` is covered by schedules: benches daily, staggered so they never read each other's load as a regression; Miri weekly in seven shards; pins and the dependency graph only when their inputs change.

## What is checked

| claim | checked by |
| --- | --- |
| compiles | `ci.yml`: `cargo test --workspace` on linux x86_64, macos aarch64, windows x86_64; clippy clean |
| no test stalls the suite unnoticed | `scripts/watch-test.sh` wraps that same run: past the quiet limit with nothing written it stops the suite, names the test that does not return on its own, prints what each thread waits in, and leaves the log as an artefact — a stall that only burns the job timeout names nothing |
| bit-identical output | differential test against the pinned reference, run *before* any timing |
| no use-after-free, no leak | Miri weekly for safe-Rust paths; differential tests for SIMD |
| no allocation, no zero-fill | counting global allocator, gated at exactly 0 |
| no work generated and discarded | the ladder returns its blocks; gate 2 compares against `ceil(len / 64)` at every length and offset |
| no operation added or removed | exact instruction counts, `scripts/count-ops.sh` against `scripts/expected-ops.txt` — same number on every machine, so this one runs before the push |
| not slower at any measured length ≥ 65 B | benchmark gate; 1–64 B are a tie by construction, identity-checked only. One regressing length fails the job, after a re-measure |
| upstream conformance | pinned upstream suites run unmodified against `ferrox-app` |
| parsers never panic on untrusted bytes | seeded cases over every untrusted entry point, printed on failure so a red run replays anywhere |
| dependency licence and provenance | `deny.toml` + `scripts/check-dependency-policy.sh`; GPL/AGPL comparators are refused as dependencies |
| roadmap coherence | `ferrox-prompt check`: no duplicate id, no gate-less slice, no cycle, no renamed `**Touches:**` path |
| every method page's counts match one manifest | `scripts/check-method-docs.sh` against `scripts/method-counts.txt` — a number edited in a page without editing the manifest fails, and a manifest row with no page fails |
| a change measured against what it actually touches | [`scripts/check-ci-scope.sh`](scripts/check-ci-scope.sh) against the scope block in each [`docs/function/`](docs/function) page — see [`docs/ci-scope.md`](docs/ci-scope.md); a name that matches no file, matrix id, oracle test or reference package fails, and a file no page owns plans a wide run |

Not claimed: that this is the fastest implementation. A benchmark measures a configuration at a point in time and decays. What is built instead is the machinery that notices.

```bash
./scripts/check.sh    # fmt, clippy, docs, policy checks, operation counts, prompt library, tests
```

That is what `ci.yml` runs. Running it first is how a lint stops costing a queue.

## Method pages

Every connection method this tree implements has a page under [`docs/function/`](docs/function). Each one carries the same four numbers — **ops** (retired instructions), **syscalls**, **memory copies**, and **time** — each with the name of the checker that produces it, a `graph TD` of the data path, and what was removed against Xray-core, sing-box and ZeroNet. A method lands with its page, or the page and the code drift and the checker says so.

Every number in those tables is a row in [`scripts/method-counts.txt`](scripts/method-counts.txt), and `scripts/check-method-docs.sh` fails if a page and that file disagree in either direction: a count that is not in the manifest is not a claim, and a claim with no checker is not made.

```bash
printf '%s %s %s %s\n' '<doc>' '<key>' '<value>' '<checker>' >> scripts/method-counts.txt
./scripts/check-method-docs.sh
```

| method | page | syscalls | copies per byte | ops | time |
| --- | --- | --- | --- | --- | --- |
| record layer (ChaCha20) | [record-layer](docs/function/record-layer.md) | 0 | 0 (in place) | `UNBLESSED` | not measured |
| Shadowsocks AEAD | [shadowsocks](docs/function/shadowsocks.md) | **1 read + 1 write per 64 KiB read** (4 chunks), 1 target write per opened batch | **0** written, **0** read | `UNBLESSED` | **1.394×** `xray-core` throughput, 1.345× less CPU/GiB (CI cell) |
| Shadowsocks 2022 | [shadowsocks-2022](docs/function/shadowsocks-2022.md) | **1 write per 16 KiB read**, 2 reads per chunk | 1 written, **0** read | `UNBLESSED` | not measured |
| VMess AEAD | [vmess](docs/function/vmess.md) | **1 write per 128 KiB read** (16 frames) | 1 written, **0** read | `UNBLESSED` | not measured |
| VLESS TCP | [vless](docs/function/vless.md) | 1 write per header, 0 framing after | 1 (the relay's own) | `UNBLESSED` | not measured |
| Trojan TCP | [trojan](docs/function/trojan.md) | 1 write per header, 0 framing after | 1 (the relay's own) | `UNBLESSED` | not measured |
| XTLS Vision | [xtls-vision](docs/function/xtls-vision.md) | 0 framing after the switch | **2** framed, **0** after the switch | `UNBLESSED` | not measured |
| Mux.Cool + XUDP | [mux-cool](docs/function/mux-cool.md) | 1 write per uplink frame, **1 per downlink read batch**, 1 `sendmsg` per XUDP datagram | **0** written, 1 read | `UNBLESSED` | not measured |
| WebSocket | [carrier-websocket](docs/function/carrier-websocket.md) | **1 read per 32 KiB window** (64 frames), 1 write per frame | 0 unmasked write, 1 masked | `UNBLESSED` | not measured |
| HTTPUpgrade | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | 1 read, 1 write | 1 (the relay's own) | `UNBLESSED` | not measured |
| HTTP masquerade | [carrier-httpheader](docs/function/carrier-httpheader.md) | 1 read, 1 write | 1 (the relay's own) | `UNBLESSED` | not measured |
| gRPC | [carrier-grpc](docs/function/carrier-grpc.md) | 1 write per message | 1 written, 1 read | `UNBLESSED` | not measured |
| xHTTP | [carrier-xhttp](docs/function/carrier-xhttp.md) | 1 write per chunk, **2 reads per 16 KiB chunk** | 1 written | `UNBLESSED` | not measured |
| QUIC | [carrier-quic](docs/function/carrier-quic.md) | 1 handshake per server | quiche's | `UNBLESSED` | not measured |
| Foxy lane (h1/h2/h3 + CONNECT-UDP) | [carrier-foxy](docs/function/carrier-foxy.md) | 1 write per DATA frame, **1 DATA frame per datagram** | **0** staged either way, 1 in the record | `UNBLESSED` | not measured |
| Hysteria v2 | [carrier-hysteria](docs/function/carrier-hysteria.md) | **1 handshake per pooled outbound** (2 flows witnessed) | 1 backlog plus the relay's own | `UNBLESSED` | not measured |
| REALITY / TLS | [reality-tls](docs/function/reality-tls.md) | per handshake, rustls | per handshake, rustls | `UNBLESSED` | not measured |
| KCP | [kcp](docs/function/kcp.md) | 1 sendto per segment | in place, **1 send buffer for the whole window, pooled receive buffers** | `UNBLESSED` | not measured |

The `ops` and `time` columns are open on every row — `UNBLESSED` and not measured — and that is the honest state rather than a gap in the table:

- **ops.** `scripts/expected-ops.txt` blesses exactly one symbol in the whole tree, `der_to_pem 2653`, and it is a PEM formatting helper rather than a carrier. `scripts/method-ops.txt` is the open list: `ops.yml` measures every symbol on it on every run and publishes the numbers as the `method-ops` artefact, which is what turns a row from `UNBLESSED` into a number somebody can read and decide to bless. Blessing one means reading the diff that moved it, never copying a measurement to silence the gate.
- **time.** Every duration in this repository comes from a named runner: `bench.yml`, `parity.yml`, `compare.yml`, `speedtest.yml` and `benchmark-matrix.yml`. A number produced off a laptop behind a VPN is a measurement of the tunnel, so no page quotes one that no CI artefact has produced. The gates that *are* deterministic — allocation counts, copy counts, syscall counts — are gated, and those are the numbers the pages lead with.

## Connection methods

The goal is a drop-in replacement for xray-core — the same JSON, the same share links, every protocol, transport and security it dials or serves — and then a superset of it: everything sing-box, ZeroNet and LxBox carry that Xray does not. Tables A–I are the verdict so far; tables J–N are the rest of that superset, each row naming the paths that prove the reference carries it.

The whole superset is one table in
[`docs/method-superset.md`](docs/method-superset.md), with a state per row, the
pinned paths that prove the reference carries it, and the needless copies this
tree still pays. `scripts/check-method-superset.sh` is its gate and it runs in
`./scripts/check.sh`: every method this tree carries has a row, and so does
every method any of the four pinned trees carries, so a rewrite cannot quietly
drop one in either direction.

**Every method in table A parses.** A row is only as good as what a binary does with it, and there are two separate answers, so the table carries both:

| column | meaning |
| --- | --- |
| `link` | what `VlessLink::support()` reports — `Implemented`, `Planned { reason }` or `UnsafeRequiresOptIn { reason }` (`crates/ferrox-core/src/transport.rs:310`). This is a verdict about the *shape of the link*, computed offline. |
| `binary` | what `ferrox-app` actually dials or serves from a config — the only axis a connection ever exercises. |

They are not the same, and where they differ the table says so. `Support::Planned` exists because a cell that says why is evidence and a blank cell is not: a refusal always carries its reason string.

`ferrox-app run <vless://…>` is deliberately *not* a dialler: it refuses unless the link is `Implemented`, then opens one TCP connection, reports the time and sends nothing. Real traffic goes through `run -c config.json`, which binds inbounds (`vless`, `trojan`, `vmess`, `shadowsocks`, `socks`, `http`, `mixed`) and needs a `freedom` outbound; xray's own invocation `-config=<file|stdin:> [-format=json|pb]` is accepted too, with the protobuf form carrying only what the pinned scenario suite writes (`xray_pb.rs`) and refusing every other field by number or name. `check <vless://…>` is fully offline.

The one parameter group the JSON carries outside a method is `budgets`: `{"budgets": {"dial": "450ms", "handshake": "30s", "relayJoin": "60s"}}` restates nine wait bounds the engine arms per flow (row 124), and a name this tree does not know, a value with no `ms`/`s` unit or a zero wait stops the start rather than reading as the default it did not set. The cadences that pace a byte loop (`RELAY_POLL`, `SESSION_POLL`, `RELAY_IDLE`, the spin and try counts) are compile-time constants and no knob reaches one: a runtime cadence is a load per iteration in the relay's hottest loop.

### A — proxy protocols (the share-link world)

Every implemented row links to its page: the counts, the data-path graph, and
what was removed against the pinned implementations live there, not here.
This table is the verdict; the page is the evidence. Rows 1–22 are the share-link world; rows 23–39 are the xray-core config surface the tree must also read — same columns, same honesty.

| # | method | link | binary | page | notes |
| --- | --- | --- | --- | --- | --- |
| 1 | VLESS TCP REALITY `xtls-rprx-vision` | `vless-tcp-reality-vision` | **both roles, raw + all carried carriers** | [vless](docs/function/vless.md) · [xtls-vision](docs/function/xtls-vision.md) · [reality-tls](docs/function/reality-tls.md) | Server role is complete: `shortId`/`X25519` auth (`crates/ferrox-core/src/tls/reality.rs`), Vision framing (`crates/ferrox-app/src/vision.rs`), over raw + gRPC + ws + xhttp + httpUpgrade + http header. An unauthenticated hello is spliced to `dest` with an optional PROXY header and rate limit, dialled lazily so an authenticated hello costs the cover origin nothing. The client dials with and without Vision over raw TCP and every carried carrier: the session id is sealed into a stock hello in two passes, the bound leaf is HMAC-verified, and a wrong key fails before any proxy byte (`proxy.rs:4125`, `reality.rs:966`); UDP carriers stay refused and no fingerprint shapes the hello. No uTLS shaping under any fingerprint. `run` opens TCP and drops it. |
| 2 | VLESS TCP TLS (Vision optional) | `vless-tcp-tls` | **both roles, raw + ws + httpUpgrade + gRPC + xhttp + http header** | [reality-tls](docs/function/reality-tls.md) | Serves `streamSettings.tlsSettings.certificates[0].{certificateFile,keyFile}` through rustls (`proxy.rs:991`, `proxy.rs:1443`), PEM in PKCS8/SEC1/PKCS1 (`tls/mod.rs:94`), Vision optional on `flow`. The client dials `security: tls` outside the carrier through rustls (`proxy.rs:3051`, `proxy.rs:3262`); `allowInsecure`, mux and quic/kcp/hysteria rows are refused, and vision over TLS stays planned. |
| 3 | VLESS TCP none, private/loopback only | `vless-tcp-none` | implemented | [vless](docs/function/vless.md) | Both roles, TCP + UDP both directions, plus Mux: client `proxy.rs:1555`, server `proxy.rs:538`. Reachable only for hosts that fail `is_public_host` (`transport.rs:286`) — that check is the gate, not a heuristic. |
| 4 | VLESS/TROJAN `security=none` to public (PattNG ext.) | unsafe opt-in — *"security=none to a public address (`PattNG` extension): explicit opt-in required"* | refused | — | `Support::UnsafeRequiresOptIn`, `check` exits 3. The flag type exists (`policy.rs:17`, `UnsafeOptIn::allow_plaintext_to_public`) and nothing constructs it yet: the gate is parse-level only, so it has never been exercised with consent. |
| 5 | TROJAN TCP | *no `trojan://` link parser* | implemented, raw + TLS over every dialled carrier | [trojan](docs/function/trojan.md) | Both roles over raw + ws + httpUpgrade + gRPC + xhttp + http header, TCP and UDP (`proxy.rs:2283`, `proxy.rs:2074`). `security: tls` dials outside the carrier (`proxy.rs:3359`); quic/kcp/hysteria rows that ask for TLS are refused rather than sent plain. UDP is raw-carrier only. |
| 6 | VMess TCP (AEAD) | — (config-driven) | implemented, raw + TLS over every dialled carrier | [vmess](docs/function/vmess.md) | Both roles; ciphers `aes-128-gcm` → AES-GCM, `chacha20-ietf-poly1305`/`chacha20-poly1305` → ChaCha, `none`/unknown → Auto = ChaCha (`vmess.rs:19`). `security: tls` dials outside the carrier (`proxy.rs:3442`); any other security is refused rather than sent plain. UDP both roles, **raw carrier only** (`proxy.rs:1643` refuses anything else). Carriers implemented for VMess too: raw, ws, xhttp, http header, httpUpgrade, gRPC (`vmess.rs:1091`–`1185`). |
| 7 | Shadowsocks TCP/UDP | — (config-driven) | implemented | [shadowsocks](docs/function/shadowsocks.md) | `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305` plus the Xray spellings (`shadowsocks.rs:17`); key length 16/32. **MD5 chain only** (`MasterKey::new`, `shadowsocks.rs:183`) — plus `rc4-md5` as a stream with a 16-byte IV and `MD5(key ++ IV)` session keys, zero-copy both directions; the 2022 family lives in row 28. UDP both roles, every carried carrier, per-datagram salt or IV. |
| 8 | VLESS over ws | `vless-ws`, `vless-ws-tls` | implemented | [carrier-websocket](docs/function/carrier-websocket.md) | Both roles; TLS and REALITY sit outside the carrier on both roles, the way the references order it. |
| 9 | VLESS over xhttp | `vless-xhttp`, `vless-xhttp-tls` | implemented, one mode | [carrier-xhttp](docs/function/carrier-xhttp.md) | Both roles. One mode only: POST plus `Transfer-Encoding: chunked` (`xhttp.rs:264`) — padding and placement rules per mode are not implemented. |
| 10 | VLESS over gRPC | `vless-grpc`, `vless-grpc-tls` | implemented | [carrier-grpc](docs/function/carrier-grpc.md) | Both roles, full HTTP/2 + HPACK, `T_DATA`/`T_HEADERS`/`T_SETTINGS` (`grpc.rs`). Path built as `/<service>/Tun`, default `/Tun` (`proxy.rs:4175`). |
| 11 | VLESS over httpUpgrade | `vless-httpupgrade`, `vless-httpupgrade-tls` | implemented | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | Both roles (`proxy.rs:1502`, `proxy.rs:462`). |
| 12 | VLESS http masquerade / header | `vless-tcp` | implemented | [carrier-httpheader](docs/function/carrier-httpheader.md) | Both roles (`proxy.rs:1541`, `proxy.rs:516`); selected by `tcpSettings.header.type == "http"` (`proxy.rs:4206`). |
| 13 | VLESS over QUIC | `vless-quic` | **both roles**, raw TCP only | [carrier-quic](docs/function/carrier-quic.md) | Dial + pool, one handshake per server (`quic.rs:591`, `quic.rs:671`), quiche with ALPN `h3`, roots required from `caCertFile` — without them the dial returns `None` (`quic.rs:206`). The server role serves (`serve_vless_quic`, `proxy.rs:1352`, `proxy.rs:163`) on a `tls` identity only, each bidirectional stream a VLESS TCP session, TCP/UDP target dialled upstream; streams without the right UUID or with a non-empty flow are closed before relay. Reached from a SOCKS inbound without Mux (client) and a `vless` inbound on `security: tls` (server). |
| 14 | KCP / mKCP | `vless-kcp` | implemented, TCP only | [kcp](docs/function/kcp.md) | Both roles for VLESS, VMess, Trojan and Shadowsocks over plaintext KCP, plus VLESS over KCP under TLS and REALITY (`proxy.rs` `serve_*_kcp`/`dial_*_kcp`); `kcpSettings` (`mtu`, `tti`, capacities, multiplier, window, both casings) parsed into `kcp::Config` (`proxy.rs` `kcp_config`). The core rung stays oracle-proven against pinned Go `xray-core/transport/internet/kcp` (`kcp/oracle.rs`). UDP and Mux stay raw-carrier-only tree-wide, so they refuse KCP like every other carrier. |
| 15 | `?ed=N` early data, ws | — | implemented, both roles | [carrier-websocket](docs/function/carrier-websocket.md) | One parse for both roles (`transport::EarlyData`), one allocation per encode; client adds the `Sec-WebSocket-Protocol` line into a request opened to its own length (`ws.rs:583`), server reads the head once (`from_utf8` + `header_value_in`) and replays it (`ws.rs:476`). The pipelined bytes behind the head are handed to the reader as its own buffer rather than copied into the early data. |
| 16 | `?ed=N` early data, httpUpgrade | — | implemented, both roles | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | Budget held in `Carrier::HttpUpgrade { ed }` and read as a flag, the way xray reads it: any non-empty first payload leaves in the same vectored write as the `GET` (one `writev` on a socket, one record over a session), ahead of reading the `101`, whatever its size, and the server leaves the pipelined bytes as the reader's first bytes (`httpupgrade.rs`). Only `ed=0` holds the payload to after the `101`. Every dialled protocol reaches that write with its own first payload: vless, trojan and vmess pass a header they build before dialling, and the Shadowsocks dial now seals its request packet through the handshake's own `dyn Write` seam and hands it over as the same one part, so no protocol's `?ed` is ignored. The request is sized to its bytes (`66 + host + path`), so no dial grows it. |
| 17 | `cipherSuites` (PattNG ext.) | — | parsed; dialer TLS 1.3 field byte-identical to `crypto/tls` | [tls-cipher-suites](docs/function/tls-cipher-suites.md) | `tlsSettings.cipherSuites` is `:`-split, name→id, dropped unknowns, re-ordered by Go's `cipherSuitesPreferenceOrder`, TLS 1.3 trio appended (`tls/cipher_suites.rs`); byte-identical to real `crypto/tls` on 10/10 oracle cases replayed from `scripts/hello-oracle` (Xray `:` list, empty list, max<1.2, NoAES, TLS 1.3-only, unknown-name fallback). When the config names a suite the `ring` provider's `cipher_suites` is sorted to the crafted order and `rustls::client::hs` writes the hello field in provider order — so the ClientHello on the wire equals the reference field, gated by `a_crafted_list_reorders_the_dialer_hello_to_the_reference` which captures a real hello via `write_tls`. Ceiling, named on the page: `rustls` is built `features=["std","ring"]` with no `tls12` (`cargo tree -e features -i -p rustls` shows only `ring`+`std`), so `ALL_CIPHER_SUITES` is the three TLS 1.3 ids and no TLS 1.2 CBC/static-RSA id is reachable on this backend's wire; advertising and negotiating that half needs a `tls12` provider — an add-on in `prompts.md`, not this row. |
| 18 | `unsafe-*` fingerprints (PattNG ext.) | unsafe opt-in — *"unsafe fingerprint requested: re-run with explicit opt-in"* | implemented under opt-in | [reality-tls](docs/function/reality-tls.md) | `fp` starting `unsafe-`, or `allowUnsafeFp=1` (`vless.rs:96`). PattNG's `unsafe` means build the hello with the stdlib `crypto/tls` rather than uTLS — exactly the stock rustls hello this tree already dials — so the fingerprint dimension collapses to the consent gate: `VlessLink::support_opted` honours `UnsafeOptIn::allow_unsafe_fingerprint` (`--allow-unsafe-fp`), which clears the parse veto so a consented link reports `Implemented` and dials both roles (`vless-tcp-reality-vision`, `vless-tcp-none`), while a bare `support()` still refuses. `an_unsafe_fingerprint_adds_no_header_byte` proves the fingerprint adds no VLESS byte; the hello itself is byte-identical to the no-`fp` dial because there is nothing to spoof. `cipherSuites` (row 17) is parsed and the TLS 1.3 half re-orders the dialer's hello; `allow_plaintext_to_public` (row 4) remains unconstructed. |
| 19 | Hysteria v2 | `vless-hysteria` | implemented, TCP only | [carrier-hysteria](docs/function/carrier-hysteria.md) | Both roles over quiche, ALPN `h3` (`hysteria.rs`, `proxy.rs` serve/dial arms); `hysteriaSettings` (`auth`, `congestion`, `version`) parsed with guarded fallbacks, non-v2 refused as `Unknown`. Wrong password refused with `404` then close, nothing relayed. The `protocol: hysteria` inbound serves the proxy shape itself — the request names its destination, the server acknowledges before it dials — proven against the pinned xray-rust Hysteria v2 client by the `xray-rust-hysteria` row in `conformance.yml`. UDP flows, salamander obfuscation and the masquerade site are not carried. The dialer pools one authenticated connection per outbound and opens a stream per flow, reused within half the idle timeout and dropped when closed, stale or out of streams (`MAX_STREAMS`): `hysteria_shares_one_connection_between_two_flows` witnesses one handshake carrying two echoes and `hysteria_redials_when_a_pooled_connection_closes` the fresh handshake after a close. |
| 20 | MASQUE CONNECT-IP (RFC 9484) | — (Foxy `h3` outbound); `vless-masque` *"CONNECT-IP dials on the Foxy HTTP/3 lane; VLESS over a MASQUE outbound not wired"* | client role, both carriers; server role refused | [carrier-foxy](docs/function/carrier-foxy.md) | The CONNECT-IP **client** is implemented and loopback-proven over both HTTP/2 and quiche HTTP/3 (`serve_socks_udp_foxy_ip`, `proxy.rs:5564`; `the_connect_ip_carrier_opens_one_tunnel_and_carries_a_datagram`, `..._over_quic_and_carries_a_datagram`) — one tunnel carrying every destination as IP packets over the type-0 DATAGRAM capsule. The codec reads **and** writes every capsule (`foxy/connectip.rs`): `ADDRESS_REQUEST` write, `ADDRESS_ASSIGN` and `ROUTE_ADVERTISEMENT` each with a writer proven the exact inverse of its reader by a byte-exact capsule (`address-assign-capsule-bytes-per-grant 9`, `route-advert-capsule-bytes-per-route 12`). **Not wired**: a proxy that *terminates* a tunnel (address pool + IP/ICMP forwarding to a device) and a standalone `Carrier::Masque` VLESS outbound — both routed to a `prompts.md` add-on. |
| 21 | TUIC / AnyTLS / ShadowTLS / Snell / Naive / SSH / OpenConnect / OpenVPN | parse to `TransportKind::Other` — *"unknown type: parses, transport not scheduled"* | refused | — | Zero occurrences in `crates/`. They are refused by falling into `Other`, not by a hand-written list, so there is no per-protocol reason string to quote for them. |
| 22 | Mux / XUDP / `multi` | — | implemented, **raw carrier only** | [mux-cool](docs/function/mux-cool.md) | The codec is complete — `Status`/`Network`/`Target`/`Outgoing`/`Incoming`, `global_id`, `CHUNK_MAX` (`mux.rs`) — and it is wired in both roles when `mux.enabled` is true. XUDP rides the mux: a `Network::Udp` target opens a UDP socket keyed by the frame's `global_id`, datagrams arrive as `Keep` frames carrying their own destination, and replies return as `Keep` frames carrying their source. The client sends one XUDP session per SOCKS association instead of dialling a carrier per destination. Both roles encode the mux request the way upstream does — command 3, no address (`vless_mux_header`) — so a real Xray peer agrees on the wire; `KeepAlive` is a no-op and the cap is `DEFAULT_CAP` 8 sessions. |
| 23 | HTTP proxy, both roles | — (config-driven) | implemented | — | sing-box `protocol/http/` in+out. The `http`/`mixed` inbound serves CONNECT to every outbound and origin-form to raw uplinks (`serve_http`, `proxy.rs`), proven by loopback and by the `foxy-relay.yml` http-front legs. An `http` outbound tunnels CONNECT through the upstream proxy with optional TLS, custom headers and basic auth (`dial_http_outbound`, `find_http_outbound`), proven by `http_outbound_dials_the_upstream_proxy_to_echo`, with the request line and auth bytes pinned by `the_connect_request_is_the_golden_bytes`. Chaining (section G) still has no engine, so an `https-proxy → …` stack composes one hop deep. |
| 24 | dokodemo-door transparent inbound | — (config-driven) | refused | — | Planned. Xray `proxy/dokodemo/`, TCP+UDP. Zero occurrences in `crates/`. ZeroNet's shape of it is the target: `settings.followRedirect` + `settings.portMap` (`xray_json.rs`) over `SO_ORIGINAL_DST`/TPROXY (`zero-net/src/transparent.rs`), proven by `tests/transparent_netns.rs`; row 86 is the sing-box spelling. |
| 25 | blackhole sink outbound | — (config-driven) | refused | — | Planned. Xray `proxy/blackhole/`; sing-box `protocol/block/`. The only sink-shaped outbound in tree is `Freedom` (`proxy.rs:247`). |
| 26 | DNS outbound | — (config-driven) | refused | — | Planned. Xray `proxy/dns/` + `app/dns/` (UDP/TCP/DoH/QUIC/FakeDNS); sing-box `protocol/dns/`; ZeroNet `zero-dns` (UDP/TCP/DoT/DoH/DoH2/DoH3/DoQ). No `dns` protocol in `proxy.rs`. |
| 27 | loopback re-inject inbound | — (config-driven) | implemented | [loopback](docs/function/loopback.md) | A `loopback` outbound (`settings.inboundTag`, Xray `proxy/loopback/`) resolves at startup into the client dial the named inbound's own credentials imply — vless/trojan/vmess/shadowsocks over raw TCP and every carried carrier — so a front re-injects through a real handshake on the loopback wire, TCP and UDP both directions (`a_re_injected_tcp_stream_carries_an_echo` 64 KiB byte-identical, `a_re_injected_udp_association_carries_a_datagram`). Unknown tags, fronts, missing freedom, transport security, datagram carriers and enabled sniffing refuse at startup or skip the outbound; the protobuf form stays refused, since no pinned scenario names it. |
| 28 | Shadowsocks-2022 ciphers | — (config-driven) | implemented | [shadowsocks-2022](docs/function/shadowsocks-2022.md) | `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`; BLAKE3 subkeys, EIH multi-user (AES), TCP+UDP relay, server-typed UDP replies. Xray `proxy/shadowsocks_2022/`; ZeroNet `shadowsocks2022.rs`. |
| 29 | TUN inbound (native) | — (config-driven) | refused by name | [a_device_inbound_is_refused_by_name_rather_than_served](crates/ferrox-app/src/proxy.rs) | Planned. Xray `proxy/tun/`; sing-box `protocol/tun/` + `transport/device/`; ZeroNet `zero-tun`. Row 58 is the tun2socks translator; this row is the native inbound. A device needs a platform device (`utun`/`tun`/Wintun), a userspace IP stack and root or an entitlement, none of which this binary has, so a config naming one is refused and serves nothing — the served surface stays the fronts, and `foxy-macos.sh --vpn` is the documented system-proxy mode. |
| 30 | Unix domain sockets | — (config-driven) | refused | — | Planned. Xray `transport/internet/system_listener.go:46-75` Unix wrappers. Tree binds TCP only (`unix` hits are `UNIX_EPOCH` clocks). |
| 31 | finalmask post-TLS mask chain | — (config-driven) | refused | — | Planned. Xray `transport/internet/finalmask/` (`fragment`/`noise`/`salamander`/`realm`/…). Zero occurrences in `crates/`. |
| 32 | xdrive cloud-drive carrier | — (config-driven) | refused | — | Name only: `TransportKind::Xdrive`, `Carrier::Xdrive` (`refused_carriers!`, `proxy.rs:284`). Xray `transport/internet/xdrive/` polls Drive remotes. |
| 33 | native HTTP/H2/H3 transport | — (config-driven) | refused | — | `TransportKind::Http` parses (`transport.rs:47`), never dialled (`is_dialled`, `transport.rs:56`). Xray itself refuses these: `transport_internet.go` maps `h2`/`h3`/`http` to a removed-feature error pointing at XHTTP. |
| 34 | VLESS `encryption=mlkem768x25519plus` | — | refused | — | Planned. ZeroNet `vless_encryption.rs` (`native`/`xorpub`/`random` x `1rtt`/`0rtt`, 0-RTT tickets, TLS-1.3-shaped AES-256-GCM records) with its own oracle row `vless_encryption_matches_the_oracle`; xray-core-rust `xray-proxy-vless/src/encryption` (`params.rs` parses `mlkem768x25519plus.*`); LxBox passes it through (task 335); sing-box-lx SPEC 032. The tree's only ML-KEM is the REALITY hybrid key-share group (`reality.rs:10`). |
| 35 | `flow=xtls-rprx-vision-udp443` | — | refused | — | Planned. Xray accepts it outbound (`infra/conf/vless.go:329-334`); the tree knows only `xtls-rprx-vision`. |
| 36 | REALITY client | `vless-tcp-reality-vision` | **client dials raw + ws + httpUpgrade + gRPC + xhttp + http header; UDP refused** | [reality-tls](docs/function/reality-tls.md) | Outbounds with `realitySettings` (`serverName`, `publicKey`, `shortId`, `fingerprint`) dial with or without Vision over raw TCP and every carried carrier (`proxy.rs:4125`); the one seal the raw dial pays rides the `ws`/`httpUpgrade`/`gRPC`/`xhttp`/`http header` framings, a loopback dial round-trips a 200 KB payload byte-for-byte over `ws` (`reality_ws_dial_reaches_echo_through_the_relay`), UDP stays refused, and no fingerprint shapes the hello. ZeroNet `reality.rs` (`reality_connect`) is the second implementation read. |
| 37 | TLS client from config | `vless-tcp-tls` + carriers | implemented for vless/vmess/trojan over raw, ws, httpUpgrade, gRPC, xhttp and http header | — | One session dials TCP, handshakes, then runs the carrier and the protocol header inside it (`proxy.rs:3051`); roots come from `caCertFile` or the system store, `allowInsecure` refuses. Xray `tls.go` and sing-box `common/tls/` are the shapes it was read against. |
| 38 | uTLS fingerprints | — | refused | — | Nothing shapes a ClientHello (row 18; bench emits the `utls` object, `linkconfig.rs:235`, shaping none). Xray `tls.go:204-277` preset/modern/other prints; sing-box `common/tls/utls_client.go`. |
| 39 | ECH | — | refused | — | Planned. Xray `ech.go` + `config.proto:80-86`; sing-box `common/tls/ech.go`; LxBox passes `tls.ech{}` through from JSON. Zero word-hits in `crates/`. |

### B — PattNG in full (what the fork wires)

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 40 | `PROXYCHAIN` ordered member list | planned (see chaining) | PattNG only — at most one `AETHER` member per chain |
| 41 | `POLICYGROUP` / routing groups | planned | PattNG only |
| 42 | Psiphon as its own program (`AETHER_PSIPHON_BIN`) | planned | PattNG, mlmvpn |
| 43 | Pluggable transports via lyrebird (`obfs4`/`snowflake`/`webtunnel`/`meek`) | planned | PattNG, Aether |
| 44 | hev-socks5-tunnel TUN (`libhev-socks5-tunnel.so`) | planned | PattNG |

### C — VPN / tunnel carriers

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 45 | WireGuard (UDP) | planned | Xray-core, sing-box, Aether, PattNG, mlmvpn; ZeroNet ships both ends — the `wireguard` inbound (`zero-protocol/src/wg_server.rs`: boringtun tunnels, cryptokey routing, allowedIPs longest-prefix, roaming, 250 ms tick, userspace netstack shared with TUN, proven by `tests/wireguard_inbound.rs`) and the `wireguard|amnezia-wg` outbound (`xray_json.rs`). This tree carries the handshake/record primitives (`ferrox-core/src/wireguard/`) — timers, config binding and the inbound are the method slice. |
| 46 | AmneziaWG | planned | amneziawg-go, amnezia-client, mlmvpn |
| 47 | MASQUE CONNECT-IP over QUIC | planned, quiche by default | mqvpn, Aether, sing-box, Xray-core, PattNG, configer |
| 48 | MASQUE over HTTP/3 vs HTTP/2 carriers | planned | Aether, mqvpn, configer |
| 49 | Multipath QUIC (`draft-ietf-quic-multipath`) | planned | mqvpn, slipstream, quiche |
| 50 | quiche itself: QUIC + HTTP/3, 0-RTT, migration, key updates, batched datagram I/O | provider, not a lane — in use for row 13 | quiche pin |
| 51 | Multipath schedulers `minrtt` / `wlb` / `wlb_udp_pin` / `backup-fec` | planned | mqvpn |
| 52 | Hybrid TCP lane (local termination over an H3 stream) | planned | mqvpn |
| 53 | Reorder buffer + reinjection (`deadline` / `idle` / `dgram`) | planned | mqvpn |
| 54 | Nested WireGuard (`gool`, two hops) | planned | Aether |
| 55 | Nested MASQUE (`mim`, tunnel in a tunnel) | planned | Aether |
| 56 | TCP-over-DNS covert channel (base32 domain + TXT) | planned | slipstream |
| 57 | Multi-resolver parallel + port-53 impersonation, DCUBIC/BBR | planned | slipstream |
| 58 | tun2socks engine (TUN → TCP/UDP/ICMP; `userspace`/`hybrid`/`system`) | planned — zeptun; a TUN device is the whole gap, and the name alone refuses a config, same as row 29 | zeptun |

### D — DNS-tunnel ways (learned from CottenDNS / MasterDnsVPN, not pinned)

Custom ARQ, ~5–7 B header overhead, session multiplexing, compatibility kept across the MasterDNS/StormDNS/CottenDNS lineage (MIT).

| # | method | state | learned from |
| --- | --- | --- | --- |
| 59 | DNS carriers UDP/53 + TCP/53 + DoT/853 + DoH/443, per-resolver `auto`/`udp`/`tcp`/`dot`/`doh` + per-path override | planned | CottenDNS |
| 60 | Record-type rotation + QNAME reshaping + ID/cookie randomization | planned | CottenDNS |
| 61 | Reliability: ARQ + ACK/NACK, adaptive duplication, Reed-Solomon FEC, MTU discovery, ZSTD/LZ4/ZLIB, request packing | planned | CottenDNS, MasterDnsVPN |
| 62 | Balancing across resolvers: round-robin / least-loss / lowest-latency / hybrid + health checks, failover | planned | CottenDNS, MasterDnsVPN |
| 63 | Local DNS service + cache + DNS-over-SOCKS5 + hijack guards; SOCKS4/5 with auth; CIDR resolver lists | planned | CottenDNS, MasterDnsVPN |
| 64 | Server egress direct / upstream-SOCKS5 chaining + flood protection | planned | CottenDNS, MasterDnsVPN |
| 65 | Encryption methods 0–5 (none / XOR / ChaCha20 / AES-128/192/256-GCM) + auto-detect | planned | CottenDNS |

### E — circumvention engines (learned from mlmvpn_android, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 66 | SoftEther / L2TP + WireGuard via `kittoku`; VPN Gate public relays | planned | mlmvpn |
| 67 | GST / EDG relay engines; GitHub Tunnel + Quick Connect pool; OpenVPN with TunnelBear | planned | mlmvpn |
| 68 | MLM Adaptive Engine: per-app route learning on one Xray tunnel + 5-step repair ladder | planned | mlmvpn |
| 69 | Config Studio + Config Arena: one Cloudflare Worker panel raced across panels on a clean IP | planned | mlmvpn |
| 70 | Game Booster: DNS/latency racing + pass-through DNS-only VPN | planned | mlmvpn |
| 71 | Sanction-domain smart routing | planned | mlmvpn |
| 72 | Server-less domain fronting (on-device CA, local TLS termination, re-establish under unblocked SNI) | planned | mlmvpn |
| 73 | Serverless / mihomo / superdns / pdoq / openvpn / http-injector / tunnel-wg / oblivion / auto lanes | planned | configer |
| 74 | Three-tier Emergency fallback | planned | mlmvpn |

### F — configer `https-proxy` + `foxy` lanes (learned, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 75 | Free HTTPS-proxy lane: anonymous `POST /v3/launch/` mints a token, server list yields HTTPS proxies exported as `http://` URIs + Clash/sing-box profiles | planned | configer |
| 76 | Foxy lane: CONNECT to an account's edge over HTTP/1.1, HTTP/2 or HTTP/3, country-pinned at dial, per-flow Bearer, failover inside the country, SPKI pins, split-tunnel | in tree, every carrier socket-proven over a real QUIC, TCP and TLS connection (`cargo test -p ferrox-app foxy`): the FxA login with its two-factor branch, the Hawk-signed exchange, the Fastly `/_fs-ch-` bot challenge, the Guardian mint with its activate-and-retry, and the published Remote Settings catalogue that turns a `country` in a `foxy://` link into an edge. `auto` tries QUIC, then HTTP/2, then HTTP/1.1, and a refused pass latches. Against the live account the catalogue answers with `*.fastly-masque.net:2499`, and all three carriers reach it: `foxy-relay.yml` downloads 1 MB per carrier (h1, h2, h3, auto) with the exit country pinned, on ubuntu and windows; UDP datagrams ride CONNECT-UDP over HTTP/3 and then HTTP/2, whatever the TCP carrier is (`foxy::loopback::the_masque_carrier_opens_connect_udp_and_echoes_a_datagram`, and the HTTP/3 form `foxy::loopback::the_masque_carrier_opens_connect_udp_over_quic_and_echoes_a_datagram` over a loopback quiche edge). `foxy-live.yml` reports the sign-in, the minted pass and the edge's carriers on a weekly schedule | configer, FoxyVPN |

### G — chaining: lanes stack, not just single dials

Today exactly one method dials per hop. The engine to build stacks them as an ordered list of hops, each hop dialling through the previous hop's local SOCKS / HTTP CONNECT / TUN front. (The 8-session cap and `global_id` reuse in `mux.rs` are the pieces this reuses.)

- `foxy` first, then a `vless://`: the VLESS dial goes through the Foxy H2 CONNECT tunnel, so the VLESS server sees the Foxy exit — the shape of Aether `--mim`/`--gool`, PattNG `PROXYCHAIN` ordering and Aether `--upstream`, generalized to every lane above.
- Rules taken from the references: the control plane stays DIRECT unless a hop explicitly chains; each hop names its own upstream; at most one core-needing member per chain; every hop verifies its own exit; teardown runs before redial; headless runs take the first attempt and log the reasoning.
- Anything chains with anything: `https-proxy` → `vless`, `foxy` → `trojan`, `tor` → `masque-h2` (Tor carries TCP only, so the upper hop must be a TCP carrier), `dns-tunnel` → `shadowsocks`. A chain needing a capability its carrier lacks is refused with the reason, never silently downgraded.

### H — arti (Tor) + onionmasq

- `arti`: Aether carries it (`tor` feature) for `--tor`, `--tor-reverse` (MASQUE-H2 only, since Tor carries TCP only) and `--tor-only`, with bridges from bridgedb and `lyrebird` transports. Ferrox would support the same three shapes plus configer's Tor-lane synthesis (`torrc` rendering, bridge lines, `ClientTransportPlugin`, entry/exit pinning, control port, SNI verdicts). Planned; nothing in this tree.
- `onionmasq` (MIT/Apache-2.0): the experimental TUN interface for Arti — userspace TCP/UDP over Tor on an `onion0` device with its own DNS resolver, the piece `oniux` uses for per-app namespace isolation. Planned as the Tor-family TUN lane with binary-level exit-country pinning.

### I — SNI spoofing without root (learned, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 77 | Fake-ClientHello SNI spoofing (DPI allowlist bypass, no root) | planned — nothing in CI checks it | `UAC-SNI-Spoofer-Android`; `sni-spoofing-rust` |

`VpnService` TUN intercepts device traffic and a userspace TCP stack owns the connection, so no `SOCK_RAW` is ever opened. The stack sends a fake ClientHello with a spoofed SNI and a deliberately wrong sequence number first: DPI sees the allowlist entry and permits the flow, the real server discards the bad-seq packet, and the legitimate handshake proceeds.

One day every box above is checked: a row keeps `planned` until its differential proof and its benchmark gate are green, with the gaps in table A named in place rather than rounded off.

### J — engine: routing, balancing, DNS, management (xray-core `app/`)

The config surface no link exercises: what sits around the protocols in a drop-in.

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 78 | Routing rules + geosite/geoip | planned | Xray `app/router/` + `app/geodata/`; sing-box `route/`; ZeroNet `zero-router`. No routing engine in `proxy.rs`: inbounds bind fixed ports, outbounds pick by protocol only. |
| 79 | Balancers: leastPing/leastLoad/roundRobin/random + urltest/selector | planned | Xray `router/balancing.go` + `app/observatory/`; sing-box `protocol/group/`; ZeroNet `zero-observatory` ladder; LxBox round-robin urltest (task 208). |
| 80 | Built-in DNS app (UDP/TCP/DoT/DoH/DoQ/FakeDNS/cache) | planned | Xray `app/dns/`; sing-box `dns/`; ZeroNet `zero-dns` + `dns_oracle` tests. Row 26 is the outbound; this row is the resolver. |
| 81 | Reverse tunnel bridge/portal | planned | Xray `app/reverse/`; ZeroNet `zero-protocol/src/reverse.rs` + `zero-runtime/src/reverse.rs` (portal/bridge over Mux.cool carriers, `Control{ACTIVE|DRAIN}` heartbeat, DRAIN after 256 sessions, ≤16 carriers per bridge, proven by `tests/reverse_proxy.rs`); xray-core-rust `xray-app-reverse/` (bridge/relay/worker/picker/timer). Row 22 is the mux it rides; this row is the direction-reversed dial. |
| 82 | Commander gRPC management API | planned | Xray `app/commander/`. |
| 83 | Connection-planner ladder (ordered rungs, climb on failure, earned descent) | planned | ZeroNet `zero-observatory` (10-rung `ALL`: DirectReality through AmneziaWireguard, 3 access classes). |
| 84 | Subnet scanner + server discovery | planned | ZeroNet `zero-scanner`, `zero-discovery` (feeds, link sort/probe, `warp.rs` account creation). |

### K — sing-box-only protocols and transports

What Xray has no equivalent of. Section H already covers Tor as a lane; the Hysteria2 carrier is row 19 — row 100 is only its missing options.

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 85 | mixed (HTTP + SOCKS) inbound | implemented | sing-box `protocol/mixed/`. `http` serves CONNECT to every outbound and origin-form to raw uplinks (`serve_http`, `proxy.rs`); `mixed` sniffs one byte (`serve_mixed`). Plain HTTP through a protocol outbound is 405; the prefix buffer that would carry it is not built. Proven by loopback (`http_connect_*`, `http_get_*`, `mixed_serves_*`) and by the `foxy-relay.yml` http-front legs downloading 1 MB live. |
| 86 | redirect + tproxy inbounds | planned | sing-box `protocol/redirect/`. Zero `tproxy`/`redirect` in `crates/`. |
| 87 | NaïveProxy | planned | sing-box `protocol/naive/`; LxBox imports `naive+https://` (task 037F). Zero `naive` in `crates/`. |
| 88 | AnyTLS | planned | sing-box `protocol/anytls/`; ZeroNet `anytls.rs`; LxBox imports `anytls://` (task 269). Row 21 is the link-type parse; this row is the auth + handshake. |
| 89 | ShadowTLS | planned | sing-box `protocol/shadowtls/`. Zero `shadowtls` in `crates/`. |
| 90 | Snell | planned | sing-box `protocol/snell/`. Zero `snell` in `crates/`. |
| 91 | SSH outbound | planned | sing-box `protocol/ssh/`; LxBox imports `ssh://` (§6). Zero `ssh` in `crates/`. |
| 92 | TUIC v5 over QUIC | planned | sing-box `protocol/tuic/`; ZeroNet `tuic.rs` + `quic_pool.rs`; LxBox imports `tuic://` (§9.5). Zero `tuic` in `crates/`. |
| 93 | Tailscale endpoint (tsnet, MagicDNS, exit nodes) | planned | sing-box `protocol/tailscale/`; LxBox feature 030 (preset 945, NETWORKS tab). Zero `tailscale` in `crates/`. |
| 94 | OpenConnect / OpenVPN endpoints | planned | sing-box `protocol/openconnect/`, `protocol/openvpn/` (each with `dns_transport.go`); LxBox passes `openvpn-client` through, no `.ovpn` (task 584F). |
| 95 | cloudflared (Argo) inbound | planned | sing-box `protocol/cloudflare/`. |
| 96 | Plain H2 + gRPC-lite transports | planned | sing-box `transport/v2rayhttp/`, `transport/v2raygrpclite/`. Tree has full gRPC only (row 10). |
| 97 | simple-obfs (http/tls) | planned | sing-box `transport/simple-obfs/`. |
| 98 | SIP003 plugin manager (obfs/v2ray-plugin) | planned | sing-box `transport/sip003/`. LxBox imports `plugin`/`plugin_opts` (§4) — carried nowhere yet. |
| 99 | Mux variants smux/yamux/h2mux | planned | sing-box `common/mux/` + `option/multiplex.go`. Tree has mux-cool only (row 22). |
| 100 | Hysteria2 salamander obfuscation + multiport | planned (salamander refused, row 19) | sing-box `protocol/hysteria2/`; LxBox §5 (`salamander`, `mport`/`server_ports`, gecko obfs). |

### L — ZeroNet + LxBox superset

Reading copies for the lanes: WARP, Tailscale UX, detour shapes, DPI parameters, import formats, config building. Section G stays the chaining engine; row 104 names the reference shapes it must match.

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 101 | WARP: auto-race WireGuard vs MASQUE-H2/H3 + one-tap registration | planned | ZeroNet `warp.rs` + `warp/report.rs` (`WarpRoute::Auto`); LxBox feature 015 (on-device keys, `warp_endpoints.json`, SCAN generator). Row 45 is the carrier; this row is the account + race. |
| 102 | AmneziaWG 1.0–3.1 parameter set (junk/masquerade/header-protection/timings) | planned | LxBox §8.5 + tasks 097F/112/421; ZeroNet `amnezia.rs`; amneziawg-go + amnezia-client pins. Row 46 stays the one-line pointer. |
| 103 | Evasion on TCP/TLS (fragment, keepalive shaping, noise, fake-SNI) | planned | ZeroNet `zero-evasion/` — `fragment.rs` takes `packets: tlshello|tlssni|from-to` (the tlssni cut lands inside the SNI's second-level label, counters DPI that reassembles and re-reads records; oracle row `vless_over_tls_with_a_hello_split_inside_the_name_matches_the_oracle`) and `domestic.rs` the curated decoy-SNI pool with `method: auto|decoy|urgent|record|empty|fastopen` + `fooling: md5|ttl|auto`; LxBox 016 (first-hop-only fragment, mixed-case SNI, REALITY pbk/sid validation). |
| 104 | Detour graph + hop chains with cycle detection | planned (G is the engine sketch) | LxBox feature 006 (`type:chain`, detour-as-direction, fail-closed, culprits named); Xray `dialerProxy`, sing-box `detour`. |
| 105 | Import superset: Xray JSON, sing-box JSON, WG INI, Amnezia `vpn://`, OpenVPN passthrough — with `.ovpn`, Clash YAML and hysteria-v1 as named gaps | planned | LxBox feature 002 + `PROTOCOLS.md` §§9–11 (gaps named in its Boundaries, not silently dropped). |
| 106 | VLESS `flow`/`encryption` grammar + XHTTP full params (modes, padding, placements, `xmux`) | planned | LxBox 016 (`xhttp-params.md`, task 127F); ZeroNet `xhttp.rs` + `xhttp_request.rs` (stream-one/stream-up/packet-up). Tree: one xhttp mode (row 9), one flow (row 35 is the gap). |
| 107 | Config template + contract registry (typed vars, schemas, build gate) | planned | LxBox features 024/025 (`build_config.dart`, `contract/registry/protocols/*.json`). |

### M — SlipNet tunnel types (learned from anonvector/SlipNet, not pinned)

Android VPN client (Kotlin + Go CLI) whose tunnel table is DNS-first: three KCP + Noise DNS transports, QUIC Slipstream, SSH everywhere as a chaining layer, NaiveProxy, a DNS-only DoH mode, and Tor — with a built-in DNS scanner. Searched this machine and this tree first: no local copy exists, nothing was pinned or cloned; the rows below are read off its README Tunnel Types + Features and its submodule list (`dnstt`, `dnstt-mobile`, `noizdns`, `vaydns`, `vaydns-mobile`, `lyrebird`, `meek-mobile`, `snowflake-mobile`).

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 108 | DNSTT (KCP + Noise DNS tunneling, the default) | planned | SlipNet (`dnstt`, `dnstt-mobile` submodules). Zero `dnstt` in `crates/`. |
| 109 | NoizDNS (DPI-resistant DNS tunneling, stealth mode) | planned | SlipNet (`noizdns` submodule). Zero `noizdns` in `crates/`. |
| 110 | VayDNS (configurable wire format: QNAME lengths, record types, rate limiting) | planned | SlipNet (`vaydns`, `vaydns-mobile` submodules). Zero `vaydns` in `crates/`. |
| 111 | `+ SSH` chaining over any tunnel (zero DNS leaks) | planned | SlipNet tunnel table (DNSTT/NoizDNS/VayDNS/Slipstream/NaiveProxy each ship a `+ SSH` variant). Standalone SSH is row 91; the Slipstream carrier is row 58 — chaining one through the other exists nowhere in tree. |
| 112 | SSH over TLS (custom SNI, domain fronting) / over ws-wss (CDN proxying) / over HTTP CONNECT (custom Host) | planned | SlipNet features. Zero `ssh` in `crates/`, so no SSH dialects either. |
| 113 | SSH payload injection (raw bytes before the handshake) + cipher selection (AES-128-GCM/ChaCha20/AES-128-CTR) | planned | SlipNet features. |
| 114 | DoH lane (DNS-only encryption per RFC 8484, no tunnel) | planned | SlipNet (`DOH` tunnel type). Row 80 is the resolver; this row is the DNS-only lane. |
| 115 | DNS server scanner (EDNS probing, NXDOMAIN-hijack detection, country-range scan) | planned | SlipNet (built-in DNS scanner). Row 84 scans subnets/proxies; this row scans resolvers. |

### N — ZeroNet server engine + xray-core-rust config deltas

The server-engine and config surface ZeroNet and xray-core-rust carry beyond the rows above: PROXY-protocol parsing on an inbound and on the freedom outbound, post-quantum REALITY binding, a raw `setsockopt` escape hatch, tunable dial parameters, tide shaping, a fountain-coded DoH rendezvous, multi-file config layering and the named wait budgets.

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 116 | PROXY protocol v1+v2 parsed on an inbound (`acceptProxyProtocol`) | planned | ZeroNet `zero-protocol/src/proxy_protocol.rs` reads both forms behind a balancer; `xray_json.rs` wires it under `sockopt`/`tcpSettings`. This tree only *writes* the header into a REALITY `dest` (`reality.rs` `proxy_protocol`, gated by `xver`); inbound parsing exists nowhere in `crates/`. |
| 117 | freedom `proxyProtocol: 1\|2` send + fallback `xver` parity | planned | ZeroNet freedom `settings.proxyProtocol: 1\|2` (`xray_json.rs`) and per-fallback `xver`; xray `proxy/freedom`. Tree: `xver` acts on the REALITY splice only, so a plain front cannot announce its client. |
| 118 | REALITY `mldsa65Seed` / `mldsa65Verify` (post-quantum key binding) | planned | ZeroNet `xray_json.rs` parses the 32-byte seed into the keypair and the client verifies it; the oracle row `reality_with_the_mldsa65_binding_matches_the_oracle` proves the pair. Xray `transport/internet/reality`. Zero `mldsa` hits in `crates/`. |
| 119 | `customSockopt` raw setsockopt escape hatch (`system`/`network`/`level` filters) | planned | ZeroNet `zero-core/src/custom_sockopt.rs`, applied on listen (`zero-net/src/socket.rs`) and dial (`dial.rs`); xray `sockopt.customSockopt`. The tree sets its options by name only; no arbitrary-option surface exists, so a kernel knob we never modelled is unreachable. |
| 120 | Tunable dial parameters: `tcpCongestion`, `tcpUserTimeout`, `tcpWindowClamp`, `tcpMaxSeg`, `tcpMptcp`, `V6Only`, keepalive idle/interval, `sendThrough`, `dialerProxy`, `interface`, `mark`, Happy-Eyeballs block | planned | ZeroNet `parse_sockopt` (`xray_json.rs`) + `zero-net/src/dial.rs`; xray-core-rust `xray-transport/src/sockopt/mod.rs` (adds `reusePort` and `receiveBufferSize`/`sendBufferSize`, which Go xray lacks); xray `transport/internet`. The tree dials with defaults for every one of these — row 124 is the *wait* surface that is runtime-configurable, not these socket options. |
| 121 | Tide down/up traffic-ratio shaping (`shape: off|light|full`) | planned | ZeroNet `zero-protocol/src/tide/shape.rs` pads the downlink so a watched flow keeps `down ≥ ratio × up` (Light 0.5, Full 2.0, 20 s half-life). This tree's echo-shaped lanes carry no ratio objective; read as a superset obfuscation rung beside row 103. |
| 122 | Fountain-coded carrier rendezvous over DoH TXT | planned | ZeroNet `zero-discovery/src/rendezvous.rs`: a signed descriptor split into XOR-fountain TXT packets (`f<i>.<zone>`), decoded from random queries at any resolver; epoch anti-replay, ed25519. Row 84 is the scanner; this is the carrier-recovery rung of it. |
| 123 | Multi-file config layering (`-c` repeats, `-confdir`, tag-merge of inbounds/outbounds, `_priority`) | planned | ZeroNet `zero-config/src/merge.rs` merges by tag with whole-element replace and appended arrays; xray's own confloader does the same. The tree reads one file; the superset parameter surface (rows 119–122) lands per-file layers only once merging exists. |
| 124 | Nine wait budgets restated by the config: top-level `budgets` = `dial`, `handshake`, `headArrival`, `relayJoin`, `relayQuantum`, `udpIdle`, `payloadGrace`, `goawayGrace`, `carrierProbe` (`"450ms"` / `"30s"`) | implemented | xray `app/policy` budgets a wait per *level*, ZeroNet per `sockopt`/timeout name; this tree names each wait once (`crates/ferrox-app/src/budgets.rs`) and arms it before the first inbound opens. An unknown name, a missing unit or a zero wait is refused by name, so a typo cannot read as the default it did not set. Cadences that pace a byte loop stay constants: a runtime cadence is a load per iteration in the relay's hottest loop. |

### Conformance, per row

The oracle names live in `upstream/pins.toml`, and `scripts/run-upstream-suite.sh` is the checker: it builds the named binary, refuses a pin whose rev does not read the seam it claims, injects the binary through that seam and rejects a green run that executed no test. Four pins are enabled — `zeronet` (9 named `xray_oracle` tests, seam `ZRAY_XRAY_BINARY`), `xray-rust` (23 named `local_xray_interop_tests`, seam `XRAY_VLESS_FULL_BINARY`), `xray-rust-hysteria` (one pinned Hysteria v2 client test, seam `XRAY_HYSTERIA_BINARY`) and `xray-core` (four `http_test.go` tests, which build a binary of their own at run time, so `scripts/xray-scenarios.sh` builds that package with `go -overlay`, `main.go` replaced by a launcher that execs `ferrox-app`, and refuses a green run whose launcher never spawned); the other eleven print `SKIPPED` with the rung that would enable them. Those suites are run in CI only. The zeronet oracle file carries rows no enabled suite names — `vless_mux_matches_the_oracle`, `vless_xudp_matches_the_oracle`, `vless_encryption_matches_the_oracle`, `vless_over_reality_raw_tcp_matches_the_oracle`, `vless_vision_over_reality_matches_the_oracle`, `vless_over_tls_with_a_hello_split_inside_the_name_matches_the_oracle`, `hysteria_matches_the_oracle_with_and_without_salamander`, `vision_with_a_custom_testseed_matches_the_oracle`, `reality_with_the_mldsa65_binding_matches_the_oracle` — and each becomes a conformance rung exactly when the feature it names ships: an enabled oracle on a refused feature is a red CI run, not a check.

Fifteen upstream pins, all resolving, all re-derivable by `scripts/fetch-upstream.sh`, all licence-clean for execution rather than copying:
`xray-core` (`c77a4d0e`), `sing-box` (`e4b7e692`), `amneziawg-go` (`b5928efb`),
`amnezia-client` (`f1af8efb`), `xray-rust` (`07dd396a`, `crates/`) and its second suite entry `xray-rust-hysteria` (same rev), `xray-core-rust` (`80477c8a`, `crates/`, `master`), `pattng` (`10f18e1c`, `V2rayNG/`),
`zeronet` (`29e7a95e`, `crates/`, the zeghostwriter upstream itself, not the fork), `mqvpn` (`0a53f5ac`), `aether` (`6175b67d`),
`zeptun` (`3fd354d4`), `slipstream` (`397850b1`), `quiche` (`b60aff93`, `quiche/`, `master`),
`lxbox` (`22a03912`, `app/`).
Read but not pinned: `WhiteDNS/CottenDNS`, `masterking32/MasterDnsVPN`, `mlmvpn/mlmvpn_android`, `anonvector/SlipNet`, local `configer`.

## Layout

```
crates/ferrox-core       record layer, ChaCha20 core, AES-GCM, TLS interface + rustls backend,
                         vless/vmess/shadowsocks parsers, transport superset, failure taxonomy
crates/ferrox-bench      counting allocator, gates, benchmark report, comparator
crates/ferrox-app        ZeroNet-compatible app on ferrox-core (MIT)
crates/ferrox-prompt     roadmap advisor; reads prompts.md, the only place a slice is written down
docs/function            one page per connection method: ops, syscalls, copies, time, data-path
                         graph, and the scope block that says what a change there owes CI
upstream/                pins plus derived reading copies, re-fetched by scripts/fetch-upstream.sh
scripts/                 pin checking, upstream fetching, gate and policy checks, count manifests
```

## Driving this with an agent

The roadmap is `crates/ferrox-prompt/prompts.md`: reusable templates, each filled from the live matrix here and the pins in `upstream/pins.toml`, so the roadmap moves toward completeness without anybody transcribing a new section. Three commands:

```bash
cargo run -p ferrox-prompt -- next        # the slice, the reason, prompt → clipboard
cargo run -p ferrox-prompt -- list        # roadmap progress and what is ready now
cargo run -p ferrox-prompt -- check       # is the library still coherent?
```

`next` is repeatable — it records each (template, matrix row) pair in `.ferrox/slices.log` and points the same template at the next outstanding row, so calling it again walks the matrix rather than re-offering one slice. A template's `{references}` lists only the pins relevant to the matrix row it fills. Each handout also names the worktree the slice runs in: `../ferrox-<slice>` is where `scripts/new-worktree.sh` puts it, and the prompt either says to create it with that script or to work in the one that already exists after bringing it onto `main` — `--json` carries the same as `worktree`. Pinned checkouts under `upstream/` are for reading only; a duration is evidence only from a named runner.

## Contributing

```bash
./scripts/new-worktree.sh <name>      # isolated worktree: shared build cache, linked upstreams
./scripts/fetch-upstream.sh           # only what the links missed
cargo run -p ferrox-prompt -- next    # the slice
./scripts/check.sh                    # everything ci.yml runs, in seconds, before the push
```

Worktree first, so branches never share a working tree. Re-run the fetch whenever `upstream/pins.toml` changes under you.

```bash
cargo run -p ferrox-bench -- --config 'vless://...'   # the comparison table for a link
cargo run -p ferrox-app -- check 'vless://...'       # parse offline; `run` dials TCP, sends nothing
```

## Licence

`MIT OR Apache-2.0` — see `LICENSE-MIT` and `LICENSE-APACHE`. Every dependency permits both, and Apache-2.0 contributes the express patent grant a cryptographic core should carry.