# Ferrox vs Xray-core feature map

Pinned reference: `upstream/xray-core` @ `92ccc939` (`upstream/pins.toml`). This tree: `crates/ferrox-core`, `crates/ferrox-app`, `docs/function/`.

What runs against what: `xray-rust` interop (23 tests, seam `XRAY_VLESS_FULL_BINARY`), `zeronet` `xray_oracle` (9 tests, seam `ZRAY_XRAY_BINARY`), and `xray-core`'s `testing/scenarios` built at run time and spawned with `-config=stdin: -format=pb` via `go -overlay` (`scripts/xray-scenarios.sh`), which `ferrox-app` reads in `crates/ferrox-app/src/xray_pb.rs`. The gate is four http tests; the other 68 run unmapped into the `conformance.yml` scenario map. `xray-core`'s own unit tests are in-process with no seam and stay in `xray-baseline.yml`.

## What ferrox has that xray-core does not

| area | ferrox | xray-core |
| --- | --- | --- |
| Foxy / FoxyVPN lane | `ferrox-core/src/foxy/` — FxA login + 2FA, Hawk-signed exchange, bot challenge, Guardian token, Remote Settings catalog, country pin, SPKI pins, split tunnel, upstream proxy chain, auto = QUIC → H2 → H1 | none (it is a separate product) |
| TUN as zeptun-style tun2socks | roadmap goal 3; zeptun pinned as comparator | `proxy/tun` exists, on xray's own lightweight `netstack.go` (gVisor left the source at #7156), no zeptun-style policy split documented here |
| Record layer, four widths, one source | `record.rs` + `Lanes` trait: portable/NEON/SSE2/AVX2 execute the same source | per-arch crypto with divergent implementations |
| Count-gated claims | exact ops/syscall/copy counts per method, `scripts/method-counts.txt` ⇔ pages | no equivalent gate |
| Single TLS stack | rustls behind `TlsProvider`, no feature flags | utls + stdlib TLS, selectable per config |
| KCP bit-exact oracle | `kcp::oracle` vs pinned Go KCP | KCP implementation, no cross-implementation oracle in-tree |

## What xray-core has that ferrox does not

### Proxy protocols

| xray-core | ferrox state |
| --- | --- |
| VMess (AEAD) — full matrix: UDP over ws/grpc/xhttp/tls, all encodings | partial: no UDP except raw carrier; no auth-length framing bits (matches client default only) |
| Trojan share-link `trojan://` parser | planned |
| Dokodemo transparent inbound | tcp rewrite served (row 24); udp relay and the `SO_ORIGINAL_DST`/TPROXY transparent spelling planned |
| Freedom — `domainStrategy`, fragment, dialer fields | direct dial (`Outbound::Freedom`); fragment/`domainStrategy`/`proxyProtocol`/dialer options planned (rows 121, 124) |
| DNS proxy + fakeDNS + hosts + DoH/DoQ/local nameservers (`app/dns`) | planned (rows 26, 82) |
| Blackhole outbound | partial (row 25): the three answers, the 403's bytes the reference's own (an oracle drives the pinned handler and the comparison is octet for octet), the flow ending when the peer is done; the datagram lane refuses the association with `0x07` ([blackhole](function/blackhole.md)) |
| Loopback | done (row 27) |
| WireGuard proxy (`proxy/wireguard`, lightweight `netstack.go`) | planned (row 46) |
| Hysteria v1 proxy (`proxy/hysteria`) | planned (only v2 as carrier today) |
| MASQUE proxy (`proxy/masque`) | planned; CONNECT-IP client dials on the Foxy `h3` lane (row 20) |
| TUN inbound (`proxy/tun`) | done (row 29) |
| uTLS fingerprints per connection | planned (row 38) |
| ECH | client done; TLS server done; QUIC server keys wired, acceptance over QUIC unproven (row 39) |
| VLESS stream encryption (`encryption` field, XOR/MLKEM) | planned (row 34) |
| XTLS Vision UDP-over-443 flow | planned (row 35) |
| REALITY ML-DSA-65 binding (`mldsa65Seed` / `mldsa65Verify`) | planned (row 122; the ZeroNet oracle row `reality_with_the_mldsa65_binding_matches_the_oracle` is waiting on it) |

### Transports

| xray-core | ferrox state |
| --- | --- |
| TCP | done |
| WebSocket (`?ed=` both roles) | done |
| gRPC | done, own HTTP/2; the multi-mode dial (`multiMode`) and the reference's method-path derivation not carried ([carrier-grpc](function/carrier-grpc.md)) |
| HTTPUpgrade | done, both roles, `?ed=N` carried (row 16) |
| xHTTP / SplitHTTP modes (packet-up, stream-up, stream-one, padding/placement) | all three modes both roles: the dial resolves an unstated `mode` and mints the session the hub validates, packets split at `uplinkChunkSize` into body or `X-Data-{i}`/cookie parts, posts paced by `scMinPostsIntervalMs`, and a relay half-close ends the request body ([carrier-xhttp](function/carrier-xhttp.md)) |
| KCP/mKCP + FinalMask (aes128gcm, header, original) | core done; finalmask `fragment` done (row 31), other mask types planned |
| Hysteria v2 transport (network `hysteria`, masquerade surface) | done as `vless-hysteria` / `protocol: hysteria` over quiche, both roles (row 19); datagrams, salamander obfs, masquerade site |
| MASQUE transport | CONNECT-IP client dialled (h2/h3); server transport planned (row 20) |
| XDrive (remote-storage carrier) | planned (row 32) |
| Browser dialer | not scheduled |
| Tagged connections / observatory webhooks | planned (rows 81, 144) |
| UDP `transport/internet/udp` fullcone/NAT behavior | mux-cool carries XUDP; standalone UDP transport planned |
| Unix sockets | done (row 30) |

### Features / apps

| xray-core | ferrox state |
| --- | --- |
| DNS client: DoH, DoQ, local, cached, fakeDNS | planned (rows 26, 82) |
| Router with rules, balancers (leastload/leastping/random), webhook | planned (rows 80, 81) |
| Observatory / burst probe | partially planned: QUIC ladder climb/descend, no burst |
| Reverse portal / bridge | planned (row 83) |
| Stats, metrics (Prometheus), policy manager | planned: policy.rs is parse-level gate only |
| `app/commander` gRPC API (config/inbound/outbound/log/router/stats) | planned (row 84) |
| Geodata (.dat) loader/downloader | planned (row 80) |
| Sniffer (HTTP/TLS/QUIC/bittorrent) + dispatcher sniffer | planned (engine-sniffing) |
| Config schema for every protocol (`infra/conf`) | ferrox-app's own JSON dialect; the protobuf `xray.core.Config` covers the shapes the http, dokodemo, vmess, vless and shadowsocks scenarios write (`xray_pb.rs`), every other field refused by number or name |
| OCSP, antireplay, time-window caches | planned |
| Freedom fragment, VLESS encryption fragment | planned (rows 121, 34) |
| finalmask: fragment, header/custom, noise, realm, salamander, sudoku, udphop, xdns, xicmp, xmc | `fragment` done (row 31), salamander on hysteria, mkcp-legacy on KCP; the rest planned (`obfs-finalmask`) |

## What to build next

Every planned or absent row above is a `README.md` matrix row the `crates/ferrox-prompt/prompts.md` templates draw their target from. `cargo run -p ferrox-prompt -- next` hands over the next outstanding row, ordered by leverage and nearness-to-done.
