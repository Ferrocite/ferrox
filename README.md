# Ferrox

FERROX — Fast Efficient Relay Router Overlay X. *ferro*, iron, for Rust; *X*, for Xray.

A from-scratch proxy core, **bit-identical to the implementations it replaces** and **verifiably not slower than any of them**.

## Goals

1. **Everything shipped is faster and leaner.** Bit-identical output, fewer operations, zero surviving copies, no allocation; counts prove, durations suggest.
2. **Drop-in replacement for Xray-core.** Run its pinned test suites unmodified against a Ferrox binary in CI, plus every suite with a seam to inject it through.
3. **Drop-in replacement for zeptun** (`tun2socks`): TUN to TCP/UDP/ICMP through a SOCKS5 or direct handler, `userspace`/`hybrid`/`system` stacks.
4. **Feature-complete where quiche, slipstream and aether are ahead** — QUIC/MASQUE, DNS-tunnel carriers, nested tunnels, multi-path schedulers, domain fronting.
5. **Spoof SNI without root.** DPI circumvention by injecting a fake TLS ClientHello with an allowlisted SNI ahead of the real handshake, via `VpnService` TUN plus a userspace TCP stack.

**The drop-in rule:** xray-core is the floor, not the ceiling. Anything a xray config can do must work here — and where xray has one way, we may have two (a cert path resolves against the working directory *and* against the executable's, as `xray-core` does). Ship more, refuse less, and never answer a config xray runs with a failure or a silently different verdict; when behaviour diverges, the fix is to accept both ways, faster and leaner, not to narrow.

**The ratio rule:** a cell is read against the engines in that same cell, never against a local run. Ferrox is never slower than a comparator at the same work, and at least 1.2x faster wherever the cell measures the same thing; a ratio under 1.0 is a defect to root-cause — name the leg that lost, the operation behind it, and the row that gates its removal — not variance to note. Counts prove, durations suggest, and the durations that decide are CI's.

## How it is built

- **One algorithm, four widths.** The record layer is one generic function over a `Lanes` trait — portable, NEON, SSE2, AVX2 — so backends execute the *same source*. The portable path is safe Rust (Miri-interpretable); the SIMD modules stay tiny.
- **Rewrite, not port.** The minimal subset covering the matrix, proven faster down to the parsing. No upstream line enters this tree.
- **Counts prove, durations suggest.** Instruction, allocation, copy and syscall counts are gated exact; each method page names the checker for every number. An unmeasured count is `UNBLESSED`, not a figure.
- **One TLS stack, one interface.** `TlsProvider` is implemented by rustls and *is* `Read + Write`, so nothing above depends on the stack underneath.
- **quiche is the default QUIC.** Any other QUIC backend must name the rung, the library and the measurement that won.
- **The reference is not as fast as it looks.** Comparators often ship SIMD behind a cfg nothing sets; every report prints both backends, and a ratio without both names is not a measurement.
- **Lints and operation counts are local; nothing connection-dependent is.** `./scripts/check.sh` runs before every push; benchmarks, parity, upstream suites and Miri are CI-only.
- **Nothing runs on a merge.** Every gate fires on the PR; `main` is covered by schedules (benches daily, Miri weekly, pins on input change).
- **Fixed-worker readiness seam on raw TCP; pooled blocking relay on carrier legs.** Raw flows hand their descriptors to `min(cores, 8)` workers and the accept thread returns. Carrier legs hold a thread per parked leg; see [concurrency](docs/concurrency.md).

## What is checked

| claim | checked by |
| --- | --- |
| compiles | `ci.yml`: `cargo test --workspace` on linux x86_64, macos aarch64, windows x86_64; clippy clean |
| no test stalls unnoticed | `scripts/watch-test.sh` names the test that does not return and prints each thread's wait |
| bit-identical output | differential test against the pinned reference, run before any timing |
| no use-after-free, no leak | Miri weekly (safe paths); differential tests (SIMD) |
| no allocation, no zero-fill | counting global allocator, gated at exactly 0 |
| no work generated and discarded | ladder returns its blocks; gate 2 vs `ceil(len / 64)` |
| no operation added or removed | `scripts/count-ops.sh` against `scripts/expected-ops.txt` |
| not slower at any length ≥ 65 B | benchmark gate; one regressing length fails after a re-measure |
| upstream conformance | pinned suites run unmodified against `ferrox-app` |
| xray-core scenario coverage | `conformance.yml`: every `testing/scenarios` test against the binary |
| parsers never panic on untrusted bytes | seeded cases over every untrusted entry point |
| dependency licence and provenance | `deny.toml` + `scripts/check-dependency-policy.sh`; GPL/AGPL refused as dependencies |
| roadmap coherence | `ferrox-prompt check`: no duplicate id, no gate-less slice, no cycle |
| method pages match one manifest | `scripts/check-method-docs.sh` against `scripts/method-counts.txt` |
| no conflict left half-resolved | `scripts/check-merge-markers.sh` over every tracked file |
| change measured against what it touches | `scripts/check-ci-scope.sh` against each page's scope block — see [`docs/ci-scope.md`](docs/ci-scope.md) |

Not claimed: that this is the fastest implementation. What is built is the machinery that notices when it is not.

```bash
./scripts/check.sh    # fmt, clippy, docs, policy checks, counts, prompt library, tests
```

## Method pages

Every implemented method has a page under [`docs/function/`](docs/function) carrying four counts — **ops**, **syscalls**, **memory copies**, **time** — each naming its checker, a `graph TD` of the data path, and what was removed against Xray-core, sing-box and ZeroNet. Every number is a row in [`scripts/method-counts.txt`](scripts/method-counts.txt); `scripts/check-method-docs.sh` fails if a page and that file disagree in either direction.

```bash
printf '%s %s %s %s\n' '<doc>' '<key>' '<value>' '<checker>' >> scripts/method-counts.txt
./scripts/check-method-docs.sh
```

| method | page | syscalls | copies/byte | ops | time |
| --- | --- | --- | --- | --- | --- |
| record layer (ChaCha20) | [record-layer](docs/function/record-layer.md) | 0 | 0 (in place) | `UNBLESSED` | not measured |
| Shadowsocks AEAD | [shadowsocks](docs/function/shadowsocks.md) | 1 read + 1 write per 64 KiB | **0** | `UNBLESSED` | 1.394× xray-core throughput (CI) |
| Shadowsocks 2022 | [shadowsocks-2022](docs/function/shadowsocks-2022.md) | 1 write per 16 KiB read | 1 written, 0 read | `UNBLESSED` | not measured |
| VMess AEAD | [vmess](docs/function/vmess.md) | 1 write per 128 KiB read | 1 written, 0 read | `UNBLESSED` | not measured |
| VLESS TCP | [vless](docs/function/vless.md) | 1 write per header | 1 (relay's own) | `UNBLESSED` | not measured |
| Trojan TCP | [trojan](docs/function/trojan.md) | 1 write per header | 1 (relay's own) | `UNBLESSED` | not measured |
| XTLS Vision | [xtls-vision](docs/function/xtls-vision.md) | 0 framing after switch | 2 framed, 0 after | `UNBLESSED` | not measured |
| Mux.Cool + XUDP | [mux-cool](docs/function/mux-cool.md) | 1 write per uplink frame | 0 written, 1 read | `UNBLESSED` | not measured |
| WebSocket | [carrier-websocket](docs/function/carrier-websocket.md) | 1 read per 32 KiB window | 0 unmasked, 1 masked | `UNBLESSED` | not measured |
| HTTPUpgrade | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | 1 read, 1 write | 1 (relay's own) | `UNBLESSED` | not measured |
| HTTP masquerade | [carrier-httpheader](docs/function/carrier-httpheader.md) | 1 read, 1 write | 1 (relay's own) | `UNBLESSED` | not measured |
| gRPC | [carrier-grpc](docs/function/carrier-grpc.md) | 1 write per 64 KiB read | 0 written, 1 read | `UNBLESSED` | not measured |
| xHTTP | [carrier-xhttp](docs/function/carrier-xhttp.md) | 1 write per chunk | 1 written | `UNBLESSED` | not measured |
| QUIC | [carrier-quic](docs/function/carrier-quic.md) | 1 handshake per server | quiche's | `UNBLESSED` | not measured |
| Foxy lane (h1/h2/h3 + CONNECT-UDP) | [carrier-foxy](docs/function/carrier-foxy.md) | 1 write per DATA frame | 0 staged | `UNBLESSED` | not measured |
| VeePN lane (`Basic` CONNECT) | [carrier-veepn](docs/function/carrier-veepn.md) | 1 write per open | 0 staged: pair, request, region list | `UNBLESSED` | not measured (two local coder runs, no cell to reproduce them) |
| Hysteria v2 | [carrier-hysteria](docs/function/carrier-hysteria.md) | 1 handshake per pooled outbound | 0 extra on datagram lane | `UNBLESSED` | not measured |
| REALITY / TLS | [reality-tls](docs/function/reality-tls.md) | per handshake | per handshake | `UNBLESSED` | `vless-tls-raw-*` arm (CI) |
| KCP | [kcp](docs/function/kcp.md) | 1 sendto per segment | in place, pooled | `UNBLESSED` | not measured |
| dokodemo-door inbound | [front-dokodemo](docs/function/front-dokodemo.md) | 1 send + 1 recv per datagram | 1 (the relay's own) | `UNBLESSED` | not measured |
| SOCKS5 + SOCKS4, both roles | [socks](docs/function/socks.md) | 3 writes + 4 reads per dial | 1 (the relay's own) | `UNBLESSED` | not measured |
| Reverse tunnel (bridge + portal) | [reverse](docs/function/reverse.md) | 1 write per mux frame | 1 downlink, 0 uplink | `UNBLESSED` | not measured |

`ops` and `time` are `UNBLESSED`/not measured on every row — the honest state. `scripts/expected-ops.txt` blesses exactly one symbol (`der_to_pem 2653`, a PEM helper); `scripts/method-ops.txt` is the open list that `ops.yml` measures into the `method-ops` artefact. Every duration comes from a named CI runner (`bench.yml`, `parity.yml`, `compare.yml`, `speedtest.yml`, `benchmark-matrix.yml`); no page quotes one off a laptop behind a VPN. The per-server grid, its tables and its charts are in [`docs/benchmarks/matrix.md`](docs/benchmarks/matrix.md).

## Connection methods

The target is a drop-in replacement for xray-core (same JSON, same share links, every protocol/transport/security it dials or serves), then a superset of sing-box, ZeroNet and LxBox. The rows below are the live matrix; [`docs/method-superset.md`](docs/method-superset.md) is the method-level ledger, gated by `scripts/check-method-superset.sh`.

`planned — high priority` marks a surface xray-core or a pinned reference runs and this tree does not carry yet, so the drop-in rule puts it ahead of a row that only widens the superset. `partial — high priority` marks the same gap inside a row that already carries part of the method. `not-scheduled` is the ledger's state for a reference surface parked behind another row, listed so the absence is not mistaken for coverage. Rows 147–167 are the gaps an audit against the pins found missing from this matrix; rows 1–146 keep their numbers.

Each table A row carries two independent verdicts: `link` (what `VlessLink::support()` reports — `Implemented`, `Planned { reason }` or `UnsafeRequiresOptIn { reason }`) and `binary` (what `ferrox-app` actually dials or serves). `Support::Planned` means the roadmap owns the row. A `link` marked `Planned` is a route, not a dead end.

`ferrox-app run <vless://…>` is not a dialler: it refuses unless `Implemented`, opens one TCP connection, times it, sends nothing. Real traffic goes through `run -c config.json` (inbounds `vless`/`trojan`/`vmess`/`shadowsocks`/`socks`/`http`/`mixed` with a `freedom` outbound, or xray's `direct` spelling of it; an outbound this tree has not built (`wireguard`, `masque`) dials direct with one warning; xray's `-config=… -format=json|pb` is also accepted). `check <vless://…>` is offline. The `budgets` group restates ten wait bounds the engine arms per flow; unknown names, missing units or zero waits stop startup. Byte-loop cadences stay compile-time constants.

### A — proxy protocols

Rows 1–22 are the share-link world; rows 23–39 are the xray-core config surface, and row 40 is the outline-sdk stack-in-a-string delta. Pages carry the evidence.

| # | method | link | binary | page | notes |
| --- | --- | --- | --- | --- | --- |
| 1 | VLESS TCP REALITY `xtls-rprx-vision` | `vless-tcp-reality-vision` | both roles, raw + all carried carriers | [vless](docs/function/vless.md) · [xtls-vision](docs/function/xtls-vision.md) · [reality-tls](docs/function/reality-tls.md) | Server complete (`shortId`/X25519, Vision framing over raw + gRPC + ws + xhttp + httpUpgrade + http header). Client dials with/without Vision over raw TCP and every carried carrier; wrong key fails before any proxy byte. UDP carriers are planned; the client hello is fingerprint-shaped (row 38). |
| 2 | VLESS TCP TLS (Vision optional) | `vless-tcp-tls`, `vless-tcp-tls-vision` | partial — both roles, raw + ws + httpUpgrade + gRPC + xhttp + http header + kcp | [reality-tls](docs/function/reality-tls.md) | Serves `tlsSettings.certificates[0]` through rustls, PEM in PKCS8/SEC1/PKCS1. Client dials `security: tls`, and a KCP row carries the session above the connection both roles. `allowInsecure` honors xray's verdict, anchored skip-verify; Vision-over-TLS dials the flow framing over the session. quic/hysteria-with-TLS are planned; neither is sent plain. Not finished by the drop-in rule for the quic/hysteria leg. |
| 3 | VLESS TCP none | `vless-tcp-none` | implemented | [vless](docs/function/vless.md) | Both roles, TCP+UDP, plus Mux. Reachable only for hosts failing `is_public_host` — that check is the gate. The inbound serves the reference's fallback table on raw, tls and reality fronts: the name/alpn/path maps with both inheritance passes, the first read's path scan, and the `xver` PROXY head before the probe's own bytes. The pb bridge decodes `xray.proxy.vless.inbound.Config` (users, `fallbacks`, `decryption`; a decryption past `none` refuses), `xray.proxy.vless.outbound.Config` (one `vnext`) and the handler's sibling `streamSettings`; ML-KEM `decryption` with its `xorMode`/seconds/padding rides row 34, account `reverse` row 83, every `clients` entry is served, keyed the way the reference's validator keys it (bytes 6–7 are the mux route), and the wire flow must be the account's own, with Vision only on a front that frames it. Scenario map at this pin: `vless` 5/5 (all five, the tls and reality siblings through the bridge). |
| 4 | VLESS/TROJAN `security=none` to public (PattNG) | unsafe opt-in | implemented under opt-in | [reality-tls](docs/function/reality-tls.md) | `--allow-plaintext-public` reads a consented cleartext session as the private `security=none` it is byte-for-byte; the veto stands without consent. Consent adds no VLESS byte. |
| 5 | TROJAN TCP | `trojan://` | partial — high priority; both roles, raw + ws + httpUpgrade + gRPC + xhttp + http header + kcp, TCP and UDP | [trojan](docs/function/trojan.md) | Both roles over raw + ws + httpUpgrade + gRPC + xhttp + http header + kcp, every carrier carrying a TCP stream and a UDP association, plain or under a terminated session; a KCP row carries the session above the connection both roles. Missing: a `security: reality` inbound is not carried yet rather than served, and mux is VLESS-only. TLS rows asking for quic/hysteria are planned; neither is sent plain. |
| 6 | VMess TCP (AEAD) | — (config) | partial — high priority; raw + TLS over every dialled carrier, UDP both roles | [vmess](docs/function/vmess.md) | Ciphers aes-128-gcm, chacha20-ietf-poly1305, none/unknown→Auto. UDP both roles over raw, ws, xhttp, http header, httpUpgrade, gRPC, KCP and xdrive, with the carrier's TLS where it has one. Missing: only AEAD framing with `OptionChunkStream \| OptionChunkMasking \| OptionGlobalPadding`; the reference's `AuthenticatedLengthExperiment` framing is not carried. |
| 7 | Shadowsocks TCP/UDP | — (config) | partial | [shadowsocks](docs/function/shadowsocks.md) | aes-gcm/chacha variants + Xray spellings, MD5 chain only; `rc4-md5` stream zero-copy both ways. UDP both roles, every dialled carrier. The pb bridge decodes `xray.proxy.shadowsocks.ServerConfig` (one user → `method`/`password`) and `ClientConfig` (one endpoint → `servers[0]`); `level` dropped, and `iv_check`, an unknown cipher, a second user, an email or a unix network refuse by name. Scenario map at this pin: `shadowsocks` 2/4. |
| 8 | VLESS over ws | `vless-ws`, `vless-ws-tls` | implemented | [carrier-websocket](docs/function/carrier-websocket.md) | Both roles; TLS/REALITY sit outside the carrier on both. |
| 9 | VLESS over xhttp | `vless-xhttp`, `vless-xhttp-tls` | partial — all three modes, both roles; xmux open | [carrier-xhttp](docs/function/carrier-xhttp.md) | The dial resolves an unstated `mode` (`auto`) and dials it: `packet-up` posts one POST per slice under one session with a `GET` downlink beside it, `stream-up` streams one chunked POST under the session, `stream-one` keeps the single staged head. A relay half-close ends the request body. `xmux` planned (row 110). |
| 10 | VLESS over gRPC | `vless-grpc`, `vless-grpc-tls` | partial — both roles, full HTTP/2 + HPACK, path `/<service>/Tun` | [carrier-grpc](docs/function/carrier-grpc.md) | The reference's multi-mode dial and method-path derivation are not carried. |
| 11 | VLESS over httpUpgrade | `vless-httpupgrade`, `vless-httpupgrade-tls` | implemented | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | Both roles. |
| 12 | VLESS http masquerade | `vless-tcp` | implemented | [carrier-httpheader](docs/function/carrier-httpheader.md) | Both roles; selected by `tcpSettings.header.type == "http"`. |
| 13 | VLESS over QUIC | `vless-quic` | partial — both roles, VLESS/TCP only | [carrier-quic](docs/function/carrier-quic.md) | Dial + pool, one handshake per server, quiche ALPN `h3`, roots from `caCertFile`. Server serves a `tls` identity; each stream a VLESS TCP session, and a UDP/mux offer closes it. Missing: server-side UDP/mux, and 0-RTT/migration/key updates are not exposed (row 51). |
| 14 | KCP / mKCP | `vless-kcp` | implemented, VMess UDP both roles; other protocols TCP only; mkcp-legacy masks | [kcp](docs/function/kcp.md) | Both roles for VLESS/VMess/Trojan/Shadowsocks over plaintext, all four under TLS both roles, and REALITY served only. Each protocol's `tls` row opens the session above the connection; the dial and listener tests are the witnesses (#444). VMess command 2 rides KCP both roles, plaintext and TLS. A shadowsocks `tls` row on any other carrier is not carried yet rather than answered plaintext. `kcpSettings` parsed; core oracle-proven against pinned Go. |
| 15 | `?ed=N` early data, ws | — | implemented, both roles | [carrier-websocket](docs/function/carrier-websocket.md) | One parse, one allocation per encode; pipelined bytes handed to the reader as its own buffer. |
| 16 | `?ed=N` early data, httpUpgrade | — | implemented, both roles | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | Non-empty first payload leaves in the same vectored write as the `GET`, ahead of the `101`. Only `ed=0` holds it. |
| 17 | `cipherSuites` (PattNG) | — | partial — high priority; dialer TLS 1.3 field byte-identical | [tls-cipher-suites](docs/function/tls-cipher-suites.md) | Re-ordered to `crypto/tls` on 10/10 oracle cases; the dialer's hello field matches. Missing: TLS 1.2 ids are parsed but unreachable — `rustls` ships `ring+std` with no `tls12`, so a config naming a TLS 1.2 suite is parsed and never dialled. |
| 18 | `unsafe-*` fingerprints (PattNG) | unsafe opt-in | implemented under opt-in | [reality-tls](docs/function/reality-tls.md) | PattNG `unsafe` = stock `crypto/tls` hello, so the dimension collapses to the consent gate; `--allow-unsafe-fp` clears the veto. Hello is byte-identical to no-`fp`. |
| 19 | Hysteria v2 | `vless-hysteria` | partial, both roles both shapes | [carrier-hysteria](docs/function/carrier-hysteria.md) | quiche ALPN `h3`; TCP streams + UDP datagram lane, salamander + gecko obfs, masquerade site (404/response/file/proxy), client port-hop, dial pooling. Only the sing-box-only realm/server_url/STUN discovery is not carried yet (no peer to pin bytes against). |
| 20 | MASQUE CONNECT-IP (RFC 9484) | `vless-masque` (planned) | partial — high priority; client both carriers, server planned | [carrier-foxy](docs/function/carrier-foxy.md) | CONNECT-IP client loopback-proven over h2 and quiche h3; codec reads and writes every capsule. Missing: the terminating server (address pool + IP/ICMP forwarding) and standalone `Carrier::Masque` outbound are planned (`prompts.md` add-on). |
| 21 | TUIC/AnyTLS/ShadowTLS/Snell/Naive/SSH/OpenConnect/OpenVPN | parse to `TransportKind::Other` | planned | — | Not dispatched yet: they fall into `Other`, not a hand-written list. Rows 90–98 own each. |
| 22 | Mux / XUDP / `multi` | — | partial — raw carrier only | [mux-cool](docs/function/mux-cool.md) | Full codec wired both roles when `mux.enabled`; XUDP rides the mux; one XUDP session per SOCKS association. Missing: mux is not carried over ws/httpUpgrade/gRPC/xhttp/TLS. xray-core removed its own mux, so this is a superset row, not a parity row. |
| 23 | HTTP proxy, both roles | — (config) | implemented | [http-proxy](docs/function/http-proxy.md) | `http`/`mixed` inbound serves CONNECT and origin-form; `http` outbound tunnels CONNECT with optional TLS/headers/basic auth. Chaining (section G) planned. |
| 24 | dokodemo-door transparent inbound | — (config) | partial — tcp and udp rewrite served | [front-dokodemo](docs/function/front-dokodemo.md) | Flows rewrite to the config's one target; the udp half rides the outbound's datagram lane over the tree's own SOCKS5 UDP association, one leg per client. The pb bridge decodes `dokodemo.Config` (`AllowedNetworks` packed or per field, empty refused as the pinned handler refuses it) and `PortList` ranges fan out one inbound per port up to 64; accepted TCP streams go to `serve_connect` with the fixed target. `portMap`/`followRedirect` over `SO_ORIGINAL_DST`/TPROXY and a finalmask tcp chain are not carried yet — the `tun` front is the transparent path; `tunnel` alias accepted; row 89 is sing-box's spelling. Scenario map at this pin: `dokodemo` 2/2, `vmess` 3/10, `policy` 2/2, `feature` 2/8. |
| 25 | blackhole sink outbound | — (config) | partial — outbound | [blackhole](docs/function/blackhole.md) | Xray `proxy/blackhole/`, sing-box `protocol/block/`, ZeroNet `block`, xray-core-rust `xray-proxy-blackhole`, Leaf `proxy/drop/`. The three answers (`none`/`http`/`custom`), the 403's bytes oracle-compared octet for octet against the pinned handler; the flow ends when the peer is done and its bytes are read, so the close is a finish and not the reset an unread request earns. The datagram lane refuses the association with `0x07`. The pb form decodes `xray.proxy.blackhole.Config`; `block` alias accepted as the only lane and as a rule's tag. Scenario map: `feature` 2/8 with `TestBlackhole` green. |
| 26 | DNS outbound | — (config) | implemented — outbound; resolver rows are row 82 | [dns-outbound](docs/function/dns-outbound.md) | Xray `proxy/dns` + `app/dns`; sing-box `protocol/dns`; ZeroNet `zero-dns`. The query and answer bytes are the pinned handler's own, replayed case for case from the oracle; rules (`qType` port lists, domains), the rewrite fields with the legacy `network`/`address`/`port` aliases, and the legacy `nonIPQuery`/`blockTypes` form decode with the reference's refusals. The stream lane and the datagram lane ride `serve_connect`/the SOCKS association, name lookups resolve inline and A/AAAA hijack per the rules. Row 82 is the resolver. |
| 27 | loopback re-inject inbound | — (config) | partial — TCP+UDP | [loopback](docs/function/loopback.md) | A `loopback` outbound resolves to the client dial the named inbound's credentials imply. Protobuf form not carried yet (no pinned scenario names it). |
| 28 | Shadowsocks-2022 ciphers | — (config) | partial — TCP+UDP relay | [shadowsocks-2022](docs/function/shadowsocks-2022.md) | `2022-blake3-*`, BLAKE3 subkeys, EIH multi-user. The client's handshake leaves in three writes, not the one SIP022 §3.1.4 asks for. |
| 29 | TUN inbound (native) | — (config) | partial — high priority; both roles, IPv4 TCP/UDP + echo | [front-tun](docs/function/front-tun.md) | Raw IPv4 packets off a virtual device; each TCP flow becomes a proxy dial through `serve_connect`, responses re-wrapped as IP. Differential against smoltcp; UDP rides the SOCKS5 UDP association; ICMP echo answered. Missing: ICMPv6, ICMP errors, GSO/GRO/multi-queue and the privileged opens (compile-checked only). Row 59 is the tun2socks translator; row 133 the stacks. |
| 30 | Unix domain sockets | — (config) | implemented, both roles, both hosts | [unix](docs/function/unix.md) | A `unix` field names an `AF_UNIX` path; one `Connection` seam carries both families, byte-identical to TCP. The arm builds on either host: `std` keeps a Windows `UnixStream` behind the unstable `windows_unix_domain_sockets` feature, so `conn.rs`'s `winunix` drives the same `SOCK_STREAM` family through `WinSock`, and the two round-trip rows check it there too. Datagram carriers keep the IP address given. |
| 31 | finalmask post-TLS mask chain | — (config) | partial, both roles (`fragment`) | [finalmask](docs/function/finalmask.md) | A `finalmask.tcp[]` `fragment` list wraps a TCP stream below TLS both roles. `header-custom`, `sudoku`, `xmc` are not carried yet (planned in `obfs-finalmask`). UDP `finalmask.udp` rides KCP mkcp-legacy and hysteria salamander. |
| 32 | xdrive cloud-drive carrier | — (config) | partial — high priority; both roles, three services | [carrier-xdrive](docs/function/carrier-xdrive.md) | Xray `transport/internet/xdrive/` polls a cloud drive as a transport. `local`, `template` and `Google Drive` in both roles, the WAL hold, the `.err`/hole/TTL names, a kept-alive `HTTP/1.1` lane pool per store, one store per identical config; a `security: tls` row is the store's lanes' handshake and dials in all three protocols. Missing: no `Yandex` service, no `security: reality` store lane, and no conformance cell — every reference test for this transport is in-package Go with no seam to inject `ferrox-app`. |
| 33 | native HTTP/H2/H3 transport | — (config) | planned | — | `TransportKind::Http` parses, never dialled. Xray itself refuses these (removed-feature, points at XHTTP); rows 99/110 are the superset path. |
| 34 | VLESS `encryption=mlkem768x25519plus` | — | planned — high priority | — | ZeroNet `vless_encryption.rs` and xray-core-rust `encryption/` are the references; only ML-KEM today is the REALITY hybrid key-share group. |
| 35 | `flow=xtls-rprx-vision-udp443` | — | planned — high priority | — | Xray accepts it outbound; the tree knows only `xtls-rprx-vision`. |
| 36 | REALITY client | `vless-tcp-reality-vision` | partial — client dials raw + ws + httpUpgrade + gRPC + xhttp + http header; UDP planned | [reality-tls](docs/function/reality-tls.md) | Outbounds with `realitySettings` dial with/without Vision over raw TCP and every carried carrier; a loopback dial round-trips 200 KB byte-for-byte over `ws`. Missing: the UDP-carrier set (`quic`, `kcp`, `hysteria`) is not carried for want of a client leg. |
| 37 | TLS client from config | `vless-tcp-tls` + carriers | partial (vless/vmess/trojan over raw + carried carriers) | — | One session dials TCP, handshakes, then runs carrier + protocol header inside it; roots from `caCertFile` or system store, or none when `allowInsecure`. |
| 38 | uTLS fingerprints | — | implemented, client | [security-utls](docs/function/security-utls.md) | xray's three name tables in `transport/internet/tls/tls.go`: an empty name is Chrome, an unknown one the stock hello, and 50 names replayed byte-for-byte onto 31 pinned uTLS presets (Chrome's nine shuffled presets as extension multiset, invariant slots and the body ahead of the extensions). Both client lanes (`tls` and `reality`) dial the shaped hello over its own TLS 1.3/1.2 record layer, on every carrier including KCP; rustls stays only the certificate verifier. `conformance.yml` runs xray-rust's `selected_fingerprints` interop rows through `XRAY_VLESS_FULL_BINARY` — eight named fingerprints. Limits: the four `*_psk` names dial their preset with uTLS's empty psk extension omitted, which xray's own dial errors on, and the `random*` family stays weight-identical but not byte-gated. TLS 1.2 keys every TLS 1.2 suite Go's own table implements — its nine AEAD ids, the nine AES-CBC ids, both 3DES-EDE-CBC ids and all three RC4-SHA ones — `scripts/tls12-oracle` replays 16 Go-to-Go sessions of them byte-for-byte, and a shaped dial finishes each record shape (an AEAD, a CBC block, an RC4 stream) against the tree's own TLS 1.2 listener, and each lane answers a `CertificateRequest` with the empty chain Go sends when it holds no client certificate; the ids in no Go table stay unreachable, as they are in the reference. |
| 39 | ECH | — | partial — TLS and QUIC both roles | [security-ech](docs/function/security-ech.md) | Xray `ech.go`: `tlsSettings.echConfigList` is raw base64/PEM or `name+udp://…` / `name+https://…/dns-query`, queried through HTTPS/SVCB and replayed as a real ECH offer by both the stock and shaped client; a bad list fails the dial closed, and a server that rejects the offer is redialled once with the retry list it returns. `tlsSettings.echServerKeys` is the base64 TLV a TLS listener answers through BoringSSL, with the context cached per identity; a bad key set refuses the inbound. A QUIC listener hands the same keys to quiche's BoringSSL context: `an_ech_serving_lane_accepts_an_offer` carries the offer over loopback and both ends report `ech_accepted`, and `an_ech_serving_lane_answers_a_client_without_an_offer` proves the fallback. Missing: BoringSSL requires at least one retry config, so an offer that does not match gets a retry list where Go's `SendAsRetry=false` sends none; an accepted offer is unchanged, so only the retry bytes diverge. A QUIC dial reads the same `tlsSettings.echConfigList` and offers it before its first packet: `a_client_dial_offers_the_configured_ech_list` proves the production dial, and a list the connection refuses fails the dial. `tlsSettings.echSockopt` (also read as `echSocketSettings`) rides the ECH DNS query socket: mark, interface, TFO, keepalive, congestion, window clamp, user timeout, max segment, tproxy and custom options are applied before connect, and a dialer-level field is warned and skipped. `security-ech` owns it. |
| 40 | transport stack as one shareable string | — | planned | — | Outline SDK `x/configurl/` (not pinned) — a pipe-separated sequence whose each URL-shaped element wraps the one on its left (`ss://…\|tlsfrag://`), so one paste carries a proxy *and* its shaping stack; rows 1–22's share links name a server, not a stack, and row 104 is the same composability spelled in config objects |

### B — PattNG in full

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 41 | `PROXYCHAIN` ordered member list | planned (chaining, section G) | PattNG — at most one `AETHER` member per chain |
| 42 | `POLICYGROUP` / routing groups | planned | PattNG |
| 43 | Psiphon as its own program (`AETHER_PSIPHON_BIN`) | planned | PattNG, mlmvpn |
| 44 | Pluggable transports via lyrebird (`obfs4`/`snowflake`/`webtunnel`/`meek`) | planned | PattNG, Aether |
| 45 | hev-socks5-tunnel TUN (`libhev-socks5-tunnel.so`) | implemented | PattNG — the SOCKS5 **client** role (CONNECT + UDP ASSOCIATE, RFC 1929 credential) as a lane of the tree's own front layer, driven by the native `tun` device front: [socks](docs/function/socks.md). A datagram with a literal address is sent as it arrived — no copy of its payload, no buffer of its own. |

### C — VPN / tunnel carriers

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 46 | WireGuard (UDP) | planned | Xray-core, sing-box, Aether, PattNG, mlmvpn; ZeroNet ships both ends. Primitives in `ferrox-core/src/wireguard/`; handshake/record done — timers, config binding, inbound are the method slice. |
| 47 | AmneziaWG | planned | amneziawg-go, amnezia-client, mlmvpn |
| 48 | MASQUE CONNECT-IP over QUIC | planned, quiche default | mqvpn, Aether, sing-box, Xray-core, PattNG |
| 49 | MASQUE over HTTP/3 vs HTTP/2 | planned | Aether, mqvpn |
| 50 | Multipath QUIC | planned | mqvpn, slipstream, quiche |
| 51 | quiche: QUIC + HTTP/3, 0-RTT, migration, key updates, batched datagrams | partial — provider, in use for rows 13/19/20; 0-RTT, migration and key updates not exposed, while datagram sweeps batch `sendmmsg`/`recvmmsg` on Linux | quiche pin |
| 52 | Multipath schedulers `minrtt`/`wlb`/`backup-fec` | planned | mqvpn |
| 53 | Hybrid TCP lane (local termination over an H3 stream) | planned | mqvpn |
| 54 | Reorder buffer + reinjection | planned | mqvpn |
| 55 | Nested WireGuard (`gool`, two hops) | planned | Aether |
| 56 | Nested MASQUE (`mim`, tunnel in a tunnel) | planned | Aether |
| 57 | TCP-over-DNS covert channel | planned | slipstream |
| 58 | Multi-resolver parallel + port-53 impersonation, DCUBIC/BBR | planned | slipstream |
| 59 | tun2socks engine (zeptun) | planned | zeptun; Leaf `proxy/tun/` (device front + smoltcp translator in one tree); a TUN device is the whole gap |
| 60 | filter-driver transparent front (no TUN device) | planned | Leaf `proxy/nf/` — a Windows-only inbound that dlopens a filter-driver API (`nf_addRule`, `nf_free`) and feeds the captured flows straight into the tun2socks lane, with fake-DNS include/exclude lists deciding what is captured; rows 24 and 89 are the Linux spellings, and this is the third one — no device node, no route table |

### D — DNS-tunnel ways (learned from CottenDNS / MasterDnsVPN, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 61 | DNS carriers UDP/TCP/DoT/DoH, per-resolver `auto` | planned | CottenDNS |
| 62 | Record-type rotation + QNAME reshaping + ID randomization | planned | CottenDNS |
| 63 | ARQ + ACK/NACK, adaptive duplication, Reed-Solomon FEC, MTU discovery, compression | planned | CottenDNS, MasterDnsVPN |
| 64 | Resolver balancing + health checks + failover | planned | CottenDNS, MasterDnsVPN |
| 65 | Local DNS service + cache + DNS-over-SOCKS5 + hijack guards | planned | CottenDNS, MasterDnsVPN |
| 66 | Server egress direct / upstream-SOCKS5 chaining + flood protection | planned | CottenDNS, MasterDnsVPN |
| 67 | Encryption methods 0–5 (none/XOR/ChaCha20/AES-GCM) + auto-detect | planned | CottenDNS |

### E — circumvention engines (learned from mlmvpn_android, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 68 | SoftEther / L2TP + WireGuard via `kittoku`; VPN Gate relays | planned | mlmvpn |
| 69 | GST / EDG relay engines; GitHub Tunnel; OpenVPN with TunnelBear | planned | mlmvpn |
| 70 | MLM Adaptive Engine: per-app route learning + repair ladder | planned | mlmvpn |
| 71 | Config Studio + Config Arena | planned | mlmvpn |
| 72 | Game Booster: DNS/latency racing + DNS-only VPN | planned | mlmvpn |
| 73 | Sanction-domain smart routing | planned | mlmvpn |
| 74 | Server-less domain fronting | planned | mlmvpn; Outline SDK `transport/tls/` OuterName — SNI and `Host` name different sites (not pinned) |
| 75 | Serverless / mihomo / superdns / pdoq / http-injector / oblivion lanes | planned | configer |
| 76 | Three-tier Emergency fallback | planned | mlmvpn |

### F — configer `https-proxy` + `foxy` lanes

| # | method | state | learned from |
| --- | --- | --- | --- |
| 77 | Free HTTPS-proxy lane (token mint, proxy export) | planned | configer |
| 78 | Foxy lane: CONNECT over HTTP/1.1, HTTP/2 or HTTP/3, country-pinned, per-flow Bearer, failover, SPKI pins, split-tunnel | in tree — every carrier socket-proven over real QUIC/TCP/TLS; `foxy-relay.yml` downloads 1 MB per carrier, `foxy-live.yml` reports sign-in weekly | configer, FoxyVPN |

### G — chaining

Today exactly one method dials per hop. The chaining engine builds stacks as an ordered list, each hop dialling through the previous hop's local SOCKS / HTTP CONNECT / TUN front (reusing the `mux.rs` 8-session cap and `global_id`). Reference rules: control plane stays DIRECT unless a hop chains; each hop names its own upstream; at most one core-needing member per chain; every hop verifies its exit; teardown before redial. A chain needing a capability its carrier lacks is not carried, with the reason, never silently downgraded.

### H — arti (Tor) + onionmasq

- `arti`: Aether carries `--tor`, `--tor-reverse` (MASQUE-H2 only, Tor is TCP-only) and `--tor-only` with bridges and `lyrebird` transports. Planned; nothing in this tree.
- `onionmasq`: the experimental TUN for Arti (userspace TCP/UDP over Tor on `onion0`). Planned as the Tor-family TUN lane.

### I — SNI spoofing without root

| # | method | state | learned from |
| --- | --- | --- | --- |
| 79 | Fake-ClientHello SNI spoofing (DPI bypass, no root) | planned — nothing in CI checks it | `UAC-SNI-Spoofer-Android`, `sni-spoofing-rust` |

`VpnService` TUN plus a userspace TCP stack sends a fake ClientHello (spoofed SNI, wrong sequence number) first; DPI permits the flow, the real server discards the bad-seq packet, the legitimate handshake proceeds. A row keeps `planned` until its differential proof and benchmark gate are green.

### J — engine: routing, balancing, DNS, management (xray-core `app/`)

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 80 | Routing rules + geosite/geoip | partial — high priority; rules with AND selectors and first match, domain/geoip/geosite assets, `blackhole`, per-inbound tags, `AsIs`/`IpOnDemand`/`IpIfNonMatch`, `balancerTag` with prefix selectors and `random`/`roundRobin`/`fallbackTag`, per-destination UDP association lanes; `leastPing`/`leastLoad` fall back without an observatory, and scripts, rule sets and sniffing selectors are not carried yet; [page](docs/function/engine-router.md) | Xray `app/router` + `app/geodata`; sing-box `route/`; ZeroNet `zero-router`; Leaf `app/router.rs` + `config/geosite.rs` + `common/dns_sniff.rs` |
| 81 | Balancers leastPing/leastLoad/roundRobin/random + urltest/selector | planned — high priority | Xray `router/balancing.go`; sing-box `protocol/group/`; ZeroNet `zero-observatory`; Leaf `proxy/tryall`, `proxy/failover`, `proxy/select`, `proxy/static` |
| 82 | Built-in DNS app (UDP/TCP/DoT/DoH/DoQ/FakeDNS/cache) | implemented — UDP/TCP/DoT/DoH/DoQ transports, per-server A/AAAA cache with stale/expired policy, hosts with xray's forms and `#rcode`, expected/unexpected IP filters with `*` prioritization, FakeDNS pools with LRU/reverse seams, and `queryStrategy`/fallback fields; server addresses ride the configured outbounds (a hostname in a UDP server address resolves before the frame names it), `+local` spellings and DoQ keep the direct dial, each routed query carries its server's tag, and `enableParallelQuery` starts every `policyID` group together (a JSON block derives the IDs from the reference's fields); xray's Lua `script` is outside this row, warns, and leaves the server list in order; [page](docs/function/engine-dns.md) | Xray `app/dns`; sing-box `dns/`; ZeroNet `zero-dns`; Leaf `app/dns` + `app/fake_dns.rs`; Outline SDK `dns/resolver.go` — DoH/DoT with alternate host:port (not pinned). Row 26 is the outbound |
| 83 | Reverse tunnel bridge/portal | partial | Xray `app/reverse`; ZeroNet `reverse.rs` over Mux.cool; xray-core-rust `xray-app-reverse`. Both roles are modern VLESS reverse (inbound `reverse.tag`, outbound `settings.reverse.tag`, cmd 4, `Control` over mux UDP to `reverse`); the bridge carries freedom and blackhole lanes only, and xhttp/QUIC/KCP/hysteria/xdrive are not carried yet. [Page](docs/function/reverse.md) |
| 84 | Commander gRPC management API | planned — high priority | Xray `app/commander` |
| 85 | Connection-planner ladder (climb on failure, earned descent) | planned — high priority | ZeroNet `zero-observatory`; Leaf `app/healthcheck.rs` (the per-outbound latency the balancers read) |
| 86 | Subnet scanner + server discovery | planned | ZeroNet `zero-scanner`, `zero-discovery` |
| 87 | Load-balancer healthcheck probe inbound | planned | Leaf `proxy/hc/` — answers one HTTP path with a fixed body and an optional request signature; the far end urltest/leastPing (row 81) actually check against |

### K — sing-box-only protocols and transports

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 88 | mixed (HTTP + SOCKS) inbound | implemented | sing-box `protocol/mixed/`; one-byte sniff between SOCKS and HTTP |
| 89 | redirect + tproxy inbounds | planned | sing-box `protocol/redirect/`; Leaf `proxy/redirect/` (the origin-destination spelling, inbound and outbound) |
| 90 | NaïveProxy | planned | sing-box `protocol/naive/`; LxBox `naive+https://` |
| 91 | AnyTLS | planned | sing-box `protocol/anytls/`; ZeroNet `anytls.rs`. Row 21 is the link parse |
| 92 | ShadowTLS | planned | sing-box `protocol/shadowtls/` |
| 93 | Snell | planned | sing-box `protocol/snell/` |
| 94 | SSH outbound | planned | sing-box `protocol/ssh/`; LxBox `ssh://` |
| 95 | TUIC v5 over QUIC | planned | sing-box `protocol/tuic/`; ZeroNet `tuic.rs`. LxBox `tuic://` |
| 96 | Tailscale endpoint (tsnet, MagicDNS, exit nodes) | planned | sing-box `protocol/tailscale/`; LxBox feature 030 |
| 97 | OpenConnect / OpenVPN endpoints | planned | sing-box `protocol/openconnect/`, `openvpn/` |
| 98 | cloudflared (Argo) inbound | planned | sing-box `protocol/cloudflare/` |
| 99 | Plain H2 + gRPC-lite transports | planned | sing-box `transport/v2rayhttp/`, `v2raygrpclite/`. Tree has full gRPC (row 10) |
| 100 | simple-obfs (http/tls) | planned | sing-box `transport/simple-obfs/`; Leaf `proxy/obfs/` (http + tls shapes) |
| 101 | SIP003 plugin manager | planned | sing-box `transport/sip003/`; LxBox `plugin`/`plugin_opts`; Leaf `OutboundSettings::Plugin` (an external transformer named by `path`+`args`) |
| 102 | Mux variants smux/yamux/h2mux | planned | sing-box `common/mux/`; Leaf `proxy/amux`, `proxy/mptp` (multipath TCP beside the muxes). Tree has mux-cool (row 22) |
| 103 | Hysteria2 multiport (`mport`/`server_ports`) | partial (with salamander/gecko, row 19) | sing-box `protocol/hysteria2/`; LxBox §5. Port-hop rotates among the expanded set; `gecko` obfs splits/masks long-header packets; a dial naming both port-hop and gecko is not carried at `connect` |
| 104 | carrier fronts as standalone stackable in/out objects | planned | Leaf `proxy/{tls,websocket,amux,quic,mptp}/` — each carrier is its own inbound and outbound protocol that chains to another by tag, not a `streamSettings` stanza inside one protocol's config; the same seat row 108's chain engine fills, and row 80's per-inbound tags read it |

### L — ZeroNet + LxBox superset

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 105 | WARP: auto-race WireGuard vs MASQUE + one-tap registration | planned | ZeroNet `warp.rs`; LxBox feature 015. Row 46 is the carrier |
| 106 | AmneziaWG 1.0–3.1 parameter set | planned | LxBox §8.5; ZeroNet `amnezia.rs`; amneziawg-go. Row 47 pointer |
| 107 | Evasion on TCP/TLS (fragment, keepalive shaping, noise, fake-SNI) | planned | ZeroNet `zero-evasion/`; LxBox 016 |
| 108 | Detour graph + hop chains with cycle detection | planned (section G engine) | LxBox 006; Xray `dialerProxy`; sing-box `detour`; Leaf `proxy/chain/` |
| 109 | Import superset (Xray/sing-box JSON, WG INI, Amnezia `vpn://`, OpenVPN) | planned | LxBox 002 + `PROTOCOLS.md` §§9–11 |
| 110 | VLESS `flow`/`encryption` grammar + XHTTP full params | planned | LxBox 016; ZeroNet `xhttp.rs`. Rows 9 and 35 are the gaps. The three xhttp dial shapes, both packet placements and the app half-close have a working implementation on the local `option1` branch (`b37bbc9`, `5fda672`) — a port candidate, not a landed diff; [carrier-xhttp](docs/function/carrier-xhttp.md) names what a port owes |
| 111 | Config template + contract registry | planned | LxBox features 024/025 |

### M — SlipNet tunnel types (learned from anonvector/SlipNet, not pinned)

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 112 | DNSTT (KCP + Noise DNS tunneling) | planned | SlipNet `dnstt` |
| 113 | NoizDNS (DPI-resistant DNS tunneling) | planned | SlipNet `noizdns` |
| 114 | VayDNS (configurable wire format) | planned | SlipNet `vaydns` |
| 115 | `+ SSH` chaining over any tunnel | planned | SlipNet tunnel table. Row 94 standalone SSH |
| 116 | SSH over TLS / ws-wss / HTTP CONNECT | planned | SlipNet features |
| 117 | SSH payload injection + cipher selection | planned | SlipNet features |
| 118 | DoH lane (DNS-only, RFC 8484) | planned | SlipNet `DOH`. Row 82 is the resolver |
| 119 | DNS server scanner (EDNS, NXDOMAIN-hijack, country scan) | planned | SlipNet built-in scanner |

### N — ZeroNet server engine + xray-core-rust config deltas

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 120 | PROXY protocol v1+v2 parsed on an inbound (`acceptProxyProtocol`) | planned — high priority | ZeroNet `proxy_protocol.rs`. Tree only writes the header into a REALITY `dest` |
| 121 | freedom `proxyProtocol: 1\|2` send + fallback `xver` parity | planned — high priority | ZeroNet freedom; xray `proxy/freedom` |
| 122 | REALITY `mldsa65Seed`/`mldsa65Verify` (post-quantum binding) | planned — high priority | ZeroNet `xray_json.rs`; the oracle row waits on it |
| 123 | `customSockopt` raw setsockopt escape hatch | planned — high priority | ZeroNet `custom_sockopt.rs`; xray `sockopt` |
| 124 | Tunable dial params (`tcpCongestion`, `tcpUserTimeout`, `tcpFastOpen`, `dialerProxy`, `mark`, Happy-Eyeballs…) | planned — high priority | ZeroNet `parse_sockopt`; xray-core-rust `sockopt`; Outline SDK `transport/happyeyeballs.go` — the dual-stack race dial (not pinned). `tcpFastOpen` is xray's own sockopt: a stored kernel cookie lets the next SYN carry the ClientHello, one RTT back on every reconnect. Row 128 is the runtime-configurable *wait* surface |
| 125 | Tide down/up traffic-ratio shaping | planned | ZeroNet `tide/shape.rs`. Read as a superset rung beside row 107 |
| 126 | Fountain-coded carrier rendezvous over DoH TXT | planned | ZeroNet `rendezvous.rs` |
| 127 | Multi-file config layering (`-c` repeats, `-confdir`, tag-merge) | planned | ZeroNet `merge.rs`. Rows 123–126 land per-file layers once merging exists |
| 128 | Ten wait budgets (`dial`, `handshake`, `headArrival`, `relayJoin`, `relayQuantum`, `relayStall`, `udpIdle`, `payloadGrace`, `goawayGrace`, `carrierProbe`) | partial — every wait named and armed before the first inbound; splice/carrier-sink waits unarmed | Each wait named once (`budgets.rs`); unknown/missing-unit/zero refused by name. Missing: splice `pull`/`push` still read `armed=none`, an ordered carrier's upload sink has nothing to arm, and eight names have no census entry. Loop cadences stay constants |

### O — client shaping, mobile service and the TUN edge

Rows 129–134 are the client-side gaps the FoxyVPN v1.0.7 release surfaces, read against the pinned trees; rows 135–139 are the DPI-evasion moves the Outline SDK `x/` module makes, learned from it without pinning it. Row 31 keeps the generic ClientHello mask and row 29 the native TUN; these rows are the parts neither reaches.

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 129 | ClientHello fragmentation on the Foxy lane (first-byte and SNI-aware cut) | planned | FoxyVPN v1.0.7 `TlsClientHelloSplitter.kt`; ZeroNet `zero-evasion/src/fragment.rs` (`tlssni`). Generic `tlshello` re-framing ships row 31, but the Foxy lane's TCP carriers (rustls) arm neither cut and the h3 handshake is quiche's own |
| 130 | Custom tunnel MTU (576–9000) | planned | FoxyVPN v1.0.7 `SettingsStore.kt`/`HevSocks5TunnelConfig.kt`; sing-box `option/tun.go`; mqvpn `src/config.h` (`tun_mtu`). The native TUN honours `settings.mtu` (row 29); Foxy, tun2socks (row 59) and MASQUE (row 20) carry no MTU knob |
| 131 | Cellular keepalive and handover rebind | planned | FoxyVPN v1.0.7 h2 PING (3 s check, 15 s idle, 25 s timeout) and `NetworkCallback`; ZeroNet `zero-evasion/src/keepalive.rs`. The Foxy h2 lane acks a peer PING and sends none; no lane rebinds after a network change |
| 132 | QUIC congestion controller and pacing (CUBIC/BBR/BBR2) | planned | quiche `quiche/src/recovery/mod.rs`; ZeroNet `zero-transport/src/quic_shape.rs`; SlipStream `docs/protocol.md` (DCUBIC). Hysteria picks BBR; the Foxy h3 lane leaves quiche's CUBIC default and paces nothing |
| 133 | TUN stack and offloads (`userspace`/`system`/`hybrid`, GSO/GRO, multi-queue) | planned | zeptun `docs/wiki/Stacks.md`; sing-box `option/tun.go`; mqvpn `src/mqvpn_internal.h`; aether `aether/src/netstack.rs`; ZeroNet `zero-tun`. The tree opens one userspace device on one handler loop, without GSO/GRO |
| 134 | Split tunneling (per-app/per-UID and per-domain) | planned | sing-box `option/tun.go` (`include_package`/`exclude_package`); LxBox 011-SPLIT_TUNNELING; xray-rust `platform/android/README.md`; Leaf `ProcessNameMatcher` (a regex over the session's process name). Router field rules (row 80) carry no app identity |
| 135 | QUIC prelude: an unparseable Initial before every parseable one | planned | Outline SDK `x/quicprelude/` (not pinned) — decoy Initial-shaped datagrams precede each packet that may carry a QUIC ClientHello, judged from the header alone and remembered nowhere, so a middlebox that reads the SNI off the first Initial it can parse reaches no decision and matches nothing after it; rows 31 and 129 cut TCP streams, this is the h3 seat (rows 78, 132) |
| 136 | In-flight TTL drop ("disorder") | planned | Outline SDK `x/disorder/` (not pinned) — the Nth write goes out with TTL 1, dies at the first hop, and the stack retransmits it with TTL restored; every byte lands but the observer's reassembly holds a hole that never fills. Rows 31 and 129 re-time writes, none drops one |
| 137 | Boot strategy race over resolvers and shaping | planned | Outline SDK `x/smart/` (not pinned) — a list of (DNS resolver × stream split × TLS-record frag) strategies raced against test domains at boot, the first that resolves *and* handshakes is kept, with an access-key fallback beneath; rows 72, 76 and 85 each own one tier of this, none races across the DNS and TCP/TLS layers at once |
| 138 | Interference probe that names what the network blocks | planned | Outline SDK `x/connectivity/` + `x/tools/test-connectivity/` (not pinned) — layered probes classify the failure (poisoned resolution, blackholed address, SNI reset, blocked TLS) so the user learns what is censored instead of "connection failed"; row 85's ladder is the engine that wants this verdict |
| 139 | Truncated-answer DNS front (force the retry onto TCP) | planned | Outline SDK `network/dnstruncate/` (not pinned) — a listener answers the client's UDP query with the TC bit set so the retry rides TCP, the one path the tunnel owns; row 82's app picks TCP for itself, this is the trick for apps whose resolver the engine does not own |

### P — seats of our own: speed, fairness and a verdict

Nothing on the pinned trees spells these; they are read off this engine's own seams. The aim is the three things a filtered connection is short of — a faster first byte, a fairer shared server, and an honest last word when a flow dies.

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 140 | TLS resumption that survives a restart and the LRU | planned | `tls/rustls_backend.rs` caches one `rustls::ClientConfig` per (material, alpn, insecure) exactly so its in-memory store resumes within a process — but a restart throws every ticket away, and the LRU cap evicts edge tickets along with their configs. Writing the store to disk and re-seeding it at boot makes a restart's first flow 1-RTT like its second. Row 37 is the dial; row 51's 0-RTT is quiche's, on the QUIC side only. Early data refuses by name — replay risk on a censor-facing wire is not worth one RTT |
| 141 | Carrier lane pre-warm pool | planned | the client holds K idle carrier sessions — dialled, handshaked, carrier-opened — hands one to the next flow and refills asynchronously, so a burst's first packet pays no TCP+TLS+carrier open. The xdrive per-store lane pool (row 32) and xhttp's kept-alive lane are the single-carrier precedents; this is the seat under every carrier at once |
| 142 | MPTCP carrier (`IPPROTO_MPTCP`, RFC 8684) | planned | a TCP-carrier flow that walks from wifi to cellular without a redial, in the kernel, with transparent fallback to plain TCP where MPTCP is absent (every Windows build takes the fallback). Row 131 rebinds at the app layer and row 50's MPQUIC needs a QUIC stack; Leaf's `mptp` (row 104) is userspace framing over several lanes, kernel MPTCP needs neither |
| 143 | Fail-closed TUN kill switch | planned | the native TUN (row 29) opens a device and touches no route table; the switch owns the routes it adds, pulls them when the lane they feed dies inside one budget tick (row 128), and reclaims them on exit — an app is never handed a dead tunnel that quietly falls back to bare egress. A keep-routes-on-failure escape hatch is not carried yet |
| 144 | Weighted fair-share scheduler per user or inbound tag | planned | token buckets per authenticated user with an interactive priority band, so one user's bulk download cannot starve another's VoIP on a shared server. xray-core has no bandwidth fairness at all; row 125 shapes a down/up ratio, not people. The identity already exists — per-inbound tags ship in row 80 |
| 145 | Hot config reload with a drained old generation | planned | SIGHUP or the commander RPC (row 84 is that seat) swaps in a new generation: new dials read the new config, live sessions finish on the snapshot they dialled with, and the swap prints a per-tag diff. Today a config edit means a restart, and every flow dies with it |
| 146 | Close-verdict journal: why every flow ended, in one line | planned | each flow closes with tag, bytes each way, duration, and *which* of the ten named budgets (row 128) or which socket error ended it — the budgets are already named and the errors already observed, nothing joins them into a per-flow verdict. Row 138's probe, from the operator's seat: a censoring shift becomes a verdict distribution, not a user report |

### Q — gaps the audit found missing (147–167)

These are the pinned-tree surfaces the tables above did not name. Every one is unimplemented today, so every one is planned work; a config that reaches one is the next slice, not a scope limit. Row 147 is the sniffing gap behind row 80's uncarried selectors.

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 147 | Engine sniffing (HTTP/TLS/QUIC/FakeDNS) | planned — high priority | xray `app/dispatcher`; `engine-sniffing`. Inbound `sniffing` is not implemented, so a route needing a sniffed domain falls to its IP rule. |
| 148 | Stats, metrics, access log, policy levels | planned — high priority | xray `app/stats`, `app/metrics`, `app/log`, `app/policy`; `engine-stats`, `engine-policy`. Counters/channel, Prometheus, access log and per-level buffers/timeouts are absent. |
| 149 | Observatory burst probes + healthcheck inbound | planned — high priority | xray `app/observatory`; Leaf `proxy/hc`; `engine-observatory`, `front-healthcheck`. Row 81 falls back because no probe history exists. |
| 150 | Tagged outbound | planned — high priority | xray `transport/internet/tagged`; `engine-tagged`. Row 80 tags inbounds, not outbound sockets. |
| 151 | Hysteria v1 | planned — high priority | xray `proxy/hysteria`; only v2 is carried (row 19), so a v1 config is not carried. |
| 152 | Freedom outbound options | planned — high priority | xray `proxy/freedom`; `domainStrategy`, `fragment`/`noises`/`finalRules`. Row 121 is the PROXY-protocol head. |
| 153 | SOCKS front HTTP fallback | planned — high priority | xray `proxy/socks` `ProcessWithFirstbyte`. `mixed` sniffs, but a `socks` inbound does not hand an HTTP request to its HTTP handler. |
| 154 | HTTP proxy chaining (`dialerProxy` over CONNECT) | planned — high priority | xray `dialerProxy`, sing-box `detour`, Leaf `proxy/chain`. Row 108 is the graph; this is the HTTP/CONNECT hop. |
| 155 | TLS min/max version, curves, `pinnedPeerCertSha256`, `rejectUnknownSNI`, `masterKeyLog` | planned — high priority | xray `transport/internet/tls`, sing-box `option/tls.go`; `security-tls-options`. Rows 17/38/39 cover ciphers/fingerprints/ECH. |
| 156 | OCSP stapling + anti-replay/time-window caches | planned — high priority | xray `common/ocsp`, `common/antireplay`, `transport/internet/tls`. VMess has its own replay window; TLS/REALITY have neither stapling nor a shared cache. |
| 157 | Browser dialer | planned | xray `transport/internet/browser_dialer`; `carrier-browser-dialer`. |
| 158 | kTLS | planned | sing-box `common/tls/ktls.go`; `security-ktls`. Linux only, gated on ALPN and cipher. |
| 159 | L2 bridge protocol | planned | sing-box `protocol/bridge`; pf/netlink/nft/WinDivert NAT. |
| 160 | sing-box v2ray QUIC + dispatch transports | not-scheduled | sing-box `transport/v2rayquic`, `transport/v2ray`; `carrier-v2ray-quic`, `carrier-v2ray-dispatch`. The reference's own dispatcher and second QUIC spelling; row 99 owns v2ray HTTP/gRPC-lite; row 13 is QUIC. |
| 161 | Shared HTTP CONNECT/capsule transport | planned | sing-box `transport/http`; `carrier-singbox-http`. Behind HTTP-proxy, naive and masque. |
| 162 | Device abstraction | planned | sing-box `transport/device`; `carrier-device`. Row 29 opens one TUN directly. |
| 163 | MasterDns protocol | planned | ZeroNet `zero-masterdns`; rows 61–67 are DNS tunnel carriers. |
| 164 | FFI/JNI surface | planned | xray-rust `xray-ffi`, ZeroNet `zray-mobile`; `surface-ffi`. C ABI and JNI with panic containment. |
| 165 | Fuzz targets | planned | xray-rust `fuzz`, ZeroNet `fuzz`; `surface-fuzz`. `check.sh` has no pinned fuzz harness. |
| 166 | Config formats + lint | planned | xray-rust `xray-conf` `vformat`/`lint`; `engine-config`. JSON5/YAML/TOML by extension; row 127 is merging. |
| 167 | Routing rule sets + scripts | planned — high priority | xray `app/router` scripts, sing-box `route/rule_set`; `engine-router`. Row 80 does not carry either yet. |

### Conformance, per row

The oracle names live in `upstream/pins.toml`; `scripts/run-upstream-suite.sh` is the checker. Four pins are enabled — `zeronet` (9 `xray_oracle` tests), `xray-rust` (24 interop tests), `xray-rust-hysteria` (1 client test), `xray-core` (31 scenario tests, launched via `go -overlay`); the other twelve print `SKIPPED` with the enabling rung. `conformance.yml` maps all 73 xray-core scenario tests family by family without gating; the map at this pin answers 31, with 33 failing and 9 carrying no verdict, and the gate names every one of the 31 green tests, so an unserved family is a map row not a red job. Suites run in CI only; each remaining oracle row becomes a rung exactly when the feature it names ships.

Sixteen upstream pins, all resolving and re-derivable by `scripts/fetch-upstream.sh`, licence-clean for reading: `xray-core`, `sing-box`, `amneziawg-go`, `amnezia-client`, `xray-rust`, `xray-rust-hysteria`, `xray-core-rust`, `pattng`, `zeronet`, `mqvpn`, `aether`, `zeptun`, `slipstream`, `quiche`, `leaf`, `lxbox`. Read but not pinned: `CottenDNS`, `MasterDnsVPN`, `mlmvpn_android`, `SlipNet`, local `configer`. Pins naming the same commit of the same repo are read from one checkout: `xray-rust` clones it and `xray-rust-hysteria` links to it, which is what `upstream/manifest.toml` records as `shares`.

## Layout

```
crates/ferrox-core       record layer, ChaCha20, AES-GCM, TLS interface + rustls, protocol parsers, transport superset, failure taxonomy
crates/ferrox-bench      counting allocator, gates, benchmark report, comparator
crates/ferrox-app        ZeroNet-compatible app on ferrox-core (MIT)
crates/ferrox-prompt     roadmap advisor; reads prompts.md, the only place a slice is written down
docs/function            one page per connection method: counts, data-path graph, CI scope
upstream/                pins plus derived reading copies, re-fetched by scripts/fetch-upstream.sh
scripts/                 pin checking, upstream fetching, gate and policy checks, count manifests
```

## Driving this with an agent

The roadmap is `crates/ferrox-prompt/prompts.md`: reusable templates, each filled from the live matrix here and the pins in `upstream/pins.toml`.

```bash
cargo run -p ferrox-prompt -- next        # the slice, the reason, prompt → clipboard
cargo run -p ferrox-prompt -- list        # roadmap progress and what is ready now
cargo run -p ferrox-prompt -- check       # is the library still coherent?
cargo run -p ferrox-prompt -- rows        # the matrix rows a slice can be about
```

`next` records each (template, matrix row) pair in `.ferrox/slices.log` and points the same template at the next outstanding row, walking the matrix toward completeness. A row can also be picked by hand: `render 1 --row A13` renders one template for one row, and `next --row A13` lets the advisor choose the template that draws it. Each handout names the worktree the slice runs in; create it with `scripts/new-worktree.sh`. Pinned checkouts under `upstream/` are for reading only; a duration is evidence only from a named runner.

## Contributing

```bash
./scripts/new-worktree.sh <name>      # worktree with its own copy-on-write warm target
./scripts/claim-target.sh             # claim/re-clone this worktree's target from the seed
./scripts/link-shared-target.sh       # repair config/upstream links (--all claims every worktree)
./scripts/gc-target.sh --apply        # reclaim dead incremental sessions and stranded target dirs
./scripts/fetch-upstream.sh           # only what the links missed
cargo run -p ferrox-prompt -- next    # the slice
./scripts/check.sh                    # everything ci.yml runs, before the push

cargo run -p ferrox-bench -- --config 'vless://...'   # the comparison table for a link
cargo run -p ferrox-app -- check 'vless://...'        # parse offline; `run` dials TCP, sends nothing
```

Worktree first, so branches never share a working tree. Re-run the fetch whenever `upstream/pins.toml` changes under you.

## Licence

`MIT OR Apache-2.0` — see `LICENSE-MIT` and `LICENSE-APACHE`. Every dependency permits both; Apache-2.0 adds the express patent grant a cryptographic core should carry.
