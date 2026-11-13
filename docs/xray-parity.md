# Ferrox vs Xray-core feature map

Pinned reference: `upstream/xray-core` @ `1b1647c` (`upstream/pins.toml`). This tree: `crates/ferrox-core`, `crates/ferrox-app`, `docs/function/`.

What runs against what: `xray-rust` interop (24 tests, seam `XRAY_VLESS_FULL_BINARY`), `zeronet` `xray_oracle` (9 tests, seam `ZRAY_XRAY_BINARY`), and `xray-core`'s `testing/scenarios` built at run time and spawned with `-config=stdin: -format=pb` via `go -overlay` (`scripts/xray-scenarios.sh`), which `ferrox-app` reads in `crates/ferrox-app/src/xray_pb.rs`. The gate is every scenario test the map answers green — 43 of 73 at this pin, across http, socks, dokodemo, dns, feature, policy, shadowsocks (legacy AEAD and 2022), tls, vless, vmess and masque; all 73 run into the `conformance.yml` scenario map. `xray-core`'s own unit tests are in-process with no seam and stay in `xray-baseline.yml`.

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
| Trojan share-link `trojan://` parser | implemented (`ferrox_core::trojan::TrojanLink`; `check`/`run` accept it beside `vless://`) |
| Dokodemo transparent inbound | done (row 27): tcp/udp rewrite, `portMap`, `followRedirect` over `SO_ORIGINAL_DST`/`DIOCNATLOOK` and Linux `TPROXY`, UDP ancillary original-destination replies on Linux, `finalmask.tcp` fragment chain, JSON and protobuf config including the protobuf `tproxy` mode and receiver marker; Windows, macOS UDP, the non-follow missing-rewrite fallback, and partial `portMap` spellings are named open |
| Freedom — `domainStrategy`, fragment, dialer fields | direct dial (`Outbound::Freedom`); fragment/`domainStrategy`/`proxyProtocol`/dialer options planned (rows 163, 166) |
| DNS proxy + fakeDNS + hosts + DoH/DoQ/local nameservers (`app/dns`) | `proxy/dns` outbound done (row 29); the resolver app planned (row 119) |
| Blackhole outbound | done (row 28): the outbound shares the three answers and the 403's bytes the reference's own (an oracle drives the pinned handler and the comparison is octet for octet); the flow ends when the peer is done. The Ferrox inbound is an extension — `xray-core` registers `blackhole` only as an outbound — and gives each accepted flow the same answer, draining only when it answered. The datagram lane refuses the association with `0x07` ([blackhole](function/blackhole.md)) |
| Loopback | done (row 30) |
| WireGuard proxy (`proxy/wireguard`, lightweight `netstack.go`) | partial (row 75): client outbound and server inbound over `smoltcp`, IPv4/IPv6 TCP and UDP, JSON and protobuf config, no kernel TUN; `TestWireguard` is the CI gate ([wireguard](function/wireguard.md)) |
| Hysteria v1 proxy (`proxy/hysteria`) | planned (only v2 as carrier today) |
| MASQUE proxy (`proxy/masque`) | done over h3, both roles (row 77): `protocol: masque` inbound with an address pool, and the `masque` transport dial (row 21); the h2 listener and the h2 dialer serve the same inbound and outbound (row 78), chosen by the configured ALPN; the reference's flat `address`/`port` outbound and `users`/`clients` with `pass` read the same edge and table |
| TUN inbound (`proxy/tun`) | done (row 32) |
| uTLS fingerprints per connection | planned (row 41) |
| ECH | client done, `echSockopt` applied to the DNS query socket; TLS server done; QUIC both roles, a dial offers the same list and a serving lane accepts it, while one that omits it still falls back; a rejected offer is redialled once with the BoringSSL retry list it returns where Go's `SendAsRetry=false` sends none, while an accepted offer is unchanged (row 42) |
| VLESS stream encryption (`encryption` field, XOR/MLKEM) | partial (row 37): both roles raw/TLS/REALITY and carried ws/gRPC/httpUpgrade/xhttp (H1)/http header, Vision on raw, server UDP/mux/reverse and client UDP/mux served; Vision over carried and xhttp H2 open |
| XTLS Vision UDP-over-443 flow | planned (row 38) |
| REALITY ML-DSA-65 binding (`mldsa65Seed` / `mldsa65Verify`) | partial (row 164; both fields are validated with the reference's lengths and messages, and the handshake names the binding it does not carry; the ZeroNet oracle row `reality_with_the_mldsa65_binding_matches_the_oracle` waits on the signature itself) |

### Transports

| xray-core | ferrox state |
| --- | --- |
| TCP | done |
| WebSocket (`?ed=` both roles) | done |
| gRPC | done, own HTTP/2; the multi-mode dial (`multiMode`), the reference's method-path derivation and the TLS authority fallback are carried, and a custom service without a split serves both message shapes on its one path ([carrier-grpc](function/carrier-grpc.md)) |
| HTTPUpgrade | done, both roles, `?ed=N` carried (row 17) |
| xHTTP / SplitHTTP modes (packet-up, stream-up, stream-one, padding/placement) | all three modes both roles: the dial resolves an unstated `mode` and mints the session the hub validates, packets split at `uplinkChunkSize` into body or `X-Data-{i}`/cookie parts, posts paced by `scMinPostsIntervalMs`, and a relay half-close ends the request body ([carrier-xhttp](function/carrier-xhttp.md)) |
| KCP/mKCP + FinalMask (aes128gcm, header, original) | core done; finalmask `fragment` done (row 34), other mask types planned |
| Hysteria v2 transport (network `hysteria`, masquerade surface) | done as `vless-hysteria` / `protocol: hysteria` over quiche, both roles (row 20); datagrams, salamander obfs, masquerade site |
| MASQUE transport | CONNECT-IP client and terminating server over h3 (row 77) and, on the same port, h2 (row 78), chosen by the configured ALPN |
| XDrive (remote-storage carrier) | planned (row 35) |
| Browser dialer | not scheduled |
| Tagged connections | done (row 125, [engine-tagged](function/engine-tagged.md)); observatory webhooks planned |
| UDP `transport/internet/udp` fullcone/NAT behavior | mux-cool carries XUDP; standalone UDP transport planned |
| Unix sockets | done (row 33) |

### Features / apps

| xray-core | ferrox state |
| --- | --- |
| DNS client: DoH, DoQ, local, cached, fakeDNS | `proxy/dns` outbound done (row 29); the resolver app planned (row 119) |
| Router with rules, balancers (leastload/leastping/random), webhook | rules, the selector set and the `webhook` action done (row 116); the four balancer strategies done, urltest and selector planned (row 118) |
| Observatory / burst probe | partially planned: QUIC ladder climb/descend, no burst |
| Reverse portal / bridge | planned (row 120) |
| Stats, metrics (Prometheus), policy manager | planned: policy.rs is parse-level gate only |
| `app/commander` gRPC API (config/inbound/outbound/log/router/stats) | planned (row 121) |
| Geodata (.dat) loader/downloader | planned (row 116) |
| Sniffer (HTTP/TLS/QUIC/bittorrent) + dispatcher sniffer | implemented (engine-sniffing: HTTP/TLS/QUIC/FakeDNS, bittorrent, UDP, plain-HTTP protocol, loopback outbound sniffing and the named inbound's second routing pass are carried) |
| Config schema for every protocol (`infra/conf`) | ferrox-app's own JSON dialect; the protobuf `xray.core.Config` covers the shapes the http, dokodemo, vmess, vless, shadowsocks, shadowsocks_2022 and loopback scenarios write (`xray_pb.rs`), every other field refused by number or name |
| OCSP, antireplay, time-window caches | planned |
| Freedom fragment, VLESS encryption fragment | planned (rows 163, 37) |
| finalmask: fragment, header/custom, noise, realm, salamander, sudoku, udphop, xdns, xicmp, xmc | `fragment`, `sudoku`, `header-custom` and `xmc` done (row 34), salamander on hysteria, mkcp-legacy on KCP; the rest planned (`obfs-finalmask`) |

## What to build next

Every planned or absent row above is a `README.md` matrix row the `crates/ferrox-prompt/prompts.md` templates draw their target from. `cargo run -p ferrox-prompt -- next` hands over the next outstanding row, ordered by leverage and nearness-to-done.
