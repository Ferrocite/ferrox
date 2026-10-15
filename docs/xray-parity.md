# Ferrox vs Xray-core feature map

Pinned reference: `upstream/xray-core` @ `c77a4d0e` (`upstream/pins.toml`).
This tree: `crates/ferrox-core`, `crates/ferrox-app`, `docs/function/`.

What runs against what: `xray-rust`'s interop tests drive the pinned Xray client into `ferrox-app` (23 tests, seam `XRAY_VLESS_FULL_BINARY`); `zeronet`'s `xray_oracle` replays its differential checks against a binary injected as Xray (9 tests, seam `ZRAY_XRAY_BINARY`); `xray-core`'s `testing/scenarios` builds `github.com/xtls/xray-core/main` at run time and spawns it with `-config=stdin: -format=pb` (`testing/scenarios/common_regular.go`), and that build is the seam `scripts/xray-scenarios.sh` answers with `go -overlay`: four http tests run unmodified against `ferrox-app`, which reads that wire form in `crates/ferrox-app/src/xray_pb.rs`. Its unit tests are in-process with no seam and stay in `xray-baseline.yml`.

## What ferrox has that xray-core does not

| area | ferrox | xray-core |
| --- | --- | --- |
| Foxy / FoxyVPN lane | `ferrox-core/src/foxy/` — FxA login + 2FA, Hawk-signed exchange, bot challenge, Guardian token, Remote Settings catalog, country pin, SPKI pins, split tunnel, upstream proxy chain, auto = QUIC → H2 → H1 | none (it is a separate product) |
| TUN as zeptun-style tun2socks | roadmap goal 3; zeptun pinned as comparator | `proxy/tun` exists, but oriented to gVisor stack only, no zeptun-style policy split documented here |
| Record layer, four widths, one source | `record.rs` + `Lanes` trait: portable/NEON/SSE2/AVX2 execute the same source | per-arch crypto with divergent implementations |
| Count-gated claims | exact ops/syscall/copy counts per method, `scripts/method-counts.txt` ⇔ pages | no equivalent gate |
| Single TLS stack | rustls behind `TlsProvider`, no feature flags | utls + stdlib TLS, selectable per config |
| KCP bit-exact oracle | `kcp::oracle` vs pinned Go KCP | KCP implementation, no cross-implementation oracle in-tree |

## What xray-core has that ferrox does not

### Proxy protocols

| xray-core | ferrox state |
| --- | --- |
| VMess (AEAD) — full matrix: UDP over ws/grpc/xhttp/tls, all encodings | partial: no UDP except raw carrier; no auth-length framing bits (matches client default only) |
| Trojan share-link `trojan://` parser | absent |
| Dokodemo transparent inbound | refused (row 24) |
| Freedom — `domainStrategy`, fragment, dialer fields | direct dial only (`Outbound::Freedom` in `proxy.rs`); no `fragment`, `domainStrategy`, `proxyProtocol` or dialer options (rows 117, 120) |
| DNS proxy + fakeDNS + hosts + DoH/DoQ/local nameservers (`app/dns`) | refused (row 26) |
| Blackhole outbound | refused (row 25) |
| Loopback | refused (row 27) |
| WireGuard proxy (`proxy/wireguard`, gVisor netstack) | absent |
| Hysteria v1 proxy (`proxy/hysteria`) | absent (only v2 as carrier) |
| MASQUE proxy (`proxy/masque`) | server not carried; the CONNECT-IP client dials on the Foxy `h3` lane (row 20) |
| TUN inbound (`proxy/tun`) | refused (row 29) |
| uTLS fingerprints per connection | refused (row 38) |
| ECH | refused (row 39) |
| VLESS stream encryption (`encryption` field, XOR/MLKEM) | refused (row 34) |
| XTLS Vision UDP-over-443 flow | refused (row 35) |
| REALITY ML-DSA-65 binding (`mldsa65Seed` / `mldsa65Verify`) | planned (row 118; the ZeroNet oracle row `reality_with_the_mldsa65_binding_matches_the_oracle` is waiting on it) |

### Transports

| xray-core | ferrox state |
| --- | --- |
| TCP | done |
| WebSocket (`?ed=` both roles) | done |
| gRPC | done, own HTTP/2 |
| HTTPUpgrade | done, both roles, `?ed=N` carried (row 16) |
| xHTTP / SplitHTTP modes (packet-up, stream-up, stream-one, padding/placement) | one mode only (POST + chunked) |
| KCP/mKCP + FinalMask (aes128gcm, header, original) | core done; finalmask refused (row 31) |
| Hysteria v2 transport (network `hysteria`, masquerade surface) | done as `vless-hysteria` / `protocol: hysteria` over quiche, both roles (row 19); datagrams, salamander and the masquerade site are not carried |
| MASQUE transport | CONNECT-IP client dialled (h2/h3) on the Foxy lane; server transport refused (row 20) |
| XDrive | refused (row 32) |
| Browser dialer | absent |
| Tagged connections / observatory webhooks | absent |
| UDP `transport/internet/udp` fullcone/NAT behavior | mux-cool carries XUDP; no standalone UDP transport service parity |
| Unix sockets | refused (row 30) |

### Features / apps

| xray-core | ferrox state |
| --- | --- |
| DNS client: DoH, DoQ, local, cached, fakeDNS | refused (row 26) |
| Router with rules, balancers (leastload/leastping/random), webhook | absent — inbounds bind fixed ports, outbounds pick by protocol |
| Observatory / burst probe | partially: QUIC ladder climb/descend, no burst |
| Reverse portal / bridge | absent |
| Stats, metrics (Prometheus), policy manager | policy.rs is parse-level gate only; no stats/metrics service |
| `app/commander` gRPC API (config/inbound/outbound/log/router/stats) | absent |
| Geodata (.dat) loader/downloader | absent |
| Sniffer (HTTP/TLS/QUIC/bittorrent) + dispatcher sniffer | absent |
| Config schema for every protocol (`infra/conf`) | ferrox-app's own JSON dialect; the protobuf `xray.core.Config` only for the shape the http scenarios write (`xray_pb.rs`: http inbound, freedom outbound, receiver port/listen, apps skipped) — every other field is refused by number or by name |
| OCSP, antireplay, time-window caches | absent |
| Freedom fragment, VLESS encryption fragment | refused |
| finalmask: fragment, header/custom, noise, realm (STUN hole-punch, portmap), salamander, sudoku, udphop, xdns, xicmp, xmc | refused (row 31) |

## What to build next

Every refused or absent row above is a `README.md` matrix row the `crates/ferrox-prompt/prompts.md` templates draw their target from. `cargo run -p ferrox-prompt -- next` hands over the next outstanding row, ordered by leverage and nearness-to-done, rather than a hand-numbered priority list that goes stale.
