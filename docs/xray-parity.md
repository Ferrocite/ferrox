# Ferrox vs Xray-core feature map

Pinned reference: `upstream/xray-core` @ `7da5dae6` (`upstream/pins.toml`).
This tree: `crates/ferrox-core`, `crates/ferrox-app`, `docs/function/`.

## What ferrox has that xray-core does not

| area | ferrox | xray-core |
| --- | --- | --- |
| Foxy / FoxyVPN lane | `ferrox-core/src/foxy/` — FxA login + 2FA, Hawk-signed exchange, bot challenge, Guardian token, Remote Settings catalog, country pin, SPKI pins, split tunnel, upstream proxy chain, auto = QUIC → H2 → H1 | none (it is a separate product) |
| TUN as zeptun-style tun2socks | roadmap goal 3; zeptun pinned as comparator | `proxy/tun` exists, but oriented to gVisor stack only, no zeptun-style policy split documented here |
| Record layer, four widths, one source | `record.rs` + `Lanes` trait: portable/NEON/SSE2/AVX2 execute the same source | per-arch crypto with divergent implementations |
| Count-gated claims | exact ops/syscall/copy counts per method, `scripts/method-counts.txt` ⇔ pages | no equivalent gate |
| Single TLS stack | rustls behind `TlsProvider`, no feature flags | utls + stdlib TLS, selectable per config |
| Hysteria carried as VLESS transport | `protocol: hysteria` row wired in `ferrox-app` | transport `hysteria` exists, but proxy-level Hysteria is its own proxy, not a VLESS carrier row |
| KCP bit-exact oracle | `kcp::oracle` vs pinned Go KCP | KCP implementation, no cross-implementation oracle in-tree |

## What xray-core has that ferrox does not

### Proxy protocols

| xray-core | ferrox state |
| --- | --- |
| VMess (AEAD) — full matrix: UDP over ws/grpc/xhttp/tls, all encodings | partial: no UDP except raw carrier; no auth-length framing bits (matches client default only) |
| Trojan share-link `trojan://` parser | absent |
| Shadowsocks-2022 (`proxy/shadowsocks_2022/`) | refused by name (row 28) |
| HTTP proxy inbound/outbound (`proxy/http`) | absent — only SOCKS inbound |
| Dokodemo transparent inbound | refused (row 24) |
| Freedom — fragment/dialer freedom fields | present, but fragment option surface thin |
| DNS proxy + fakeDNS + hosts + DoH/DoQ/local nameservers (`app/dns`) | refused (row 26) |
| Blackhole outbound | refused (row 25) |
| Loopback | refused (row 27) |
| WireGuard proxy (`proxy/wireguard`, gVisor netstack) | absent |
| Hysteria v1 proxy (`proxy/hysteria`) | absent (only v2 as carrier) |
| MASQUE proxy (`proxy/masque`) | not carried; a matrix row `next` draws |
| TUN inbound (`proxy/tun`) | refused (row 29) |
| uTLS fingerprints per connection | refused (row 38) |
| ECH | refused (row 39) |
| VLESS stream encryption (`encryption` field, XOR/MLKEM) | refused (row 34) |
| XTLS Vision UDP-over-443 flow | refused (row 35) |
| REALITY client dial | refused (row 36) |

### Transports

| xray-core | ferrox state |
| --- | --- |
| TCP | done |
| WebSocket (`?ed=` both roles) | done |
| gRPC | done, own HTTP/2 |
| HTTPUpgrade | done; `?ed=` parsed, not carried |
| xHTTP / SplitHTTP modes (packet-up, stream-up, stream-one, padding/placement) | one mode only (POST + chunked) |
| KCP/mKCP + FinalMask (aes128gcm, header, original) | core done; finalmask refused (row 31) |
| Hysteria QUIC transport | done |
| MASQUE transport | refused; a matrix row `next` draws |
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
| Config schema for every protocol (`infra/conf`) | ferrox-app has its own smaller JSON config |
| OCSP, antireplay, time-window caches | absent |
| Freedom fragment, VLESS encryption fragment | refused |
| finalmask: fragment, header/custom, noise, realm (STUN hole-punch, portmap), salamander, sudoku, udphop, xdns, xicmp, xmc | refused (row 31) |

## What to build next

Every refused or absent row above is a `README.md` matrix row the `crates/ferrox-prompt/prompts.md` templates draw their target from. `cargo run -p ferrox-prompt -- next` hands over the next outstanding row, ordered by leverage and nearness-to-done, rather than a hand-numbered priority list that goes stale.
