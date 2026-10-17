# The method matrix this core must carry

This is **not** a method page. A method page under `docs/function/` carries the
four counts, the `graph TD` of the data path and the `## Time` section for
something this tree *implements*, and `scripts/check-method-docs.sh` is its
gate. This file is the other half: **which** methods this tree carries, which
it refuses by name, and for each row where at least one of the four pinned
reading copies proves the method exists in the world this core has to drop
into.

`scripts/check-method-superset.sh` is the checker, and it runs in
`./scripts/check.sh`. It enforces three things and nothing else:

1. every row names a state from a closed vocabulary, a layer, at least one
   reference path that exists, and a note;
2. **every method this tree already carries has a row** — every
   `Support::Implemented` method string in `crates/ferrox-core/src/vless.rs`
   (above `#[cfg(test)]`) and every page under `docs/function/`;
3. **every method any of the four pinned trees carries has a row** — every
   directory in `xray-core/proxy`, `xray-core/transport/internet`,
   `sing-box/protocol`, `sing-box/transport`, `xray-rust/crates`,
   `zeronet/crates`, plus `zeronet/bench/hotpath`, `xray-rust/fuzz` and
   `zeronet/fuzz`, is cited by at least one row's references.

Rules 2 and 3 together are the superset claim, and they are what makes a
rewrite safe: the matrix cannot shrink in either direction without a gate
going red. A row that moves from `planned` to `implemented` is either a
`docs/function` page with counts, or it is not implemented.

## Why a superset and not a union

The shared protocol in `crates/ferrox-prompt/prompts.md` states it as "a
superset of connection ways, a subset of code". Concretely:

- **The ways**: xray-core is the drop-in target, so every protocol tag, every
  transport tag, every security key and every `app/` app it accepts is a row.
  sing-box, xray-rust and ZeroNet are then read for what *they* carry that
  xray-core does not — AnyTLS, ShadowTLS, Snell, SSH, Naive, TUIC, Tailscale,
  Tor, OpenVPN/OpenConnect, selectors/urltest, MASQUE as an endpoint, the
  `finalmask` and `zero-evasion` obfuscation families — and each of those
  becomes a row too. That is the direction where a core ends up *narrower*
  than the thing it replaces, which is the failure a drop-in exists to avoid.
- **The code**: no upstream line enters this tree. A row is a *target*, not a
  port. Learn where the reference puts each byte, then write the smaller,
  cheaper, bit-identical thing, and prove it the way everything else here is
  proved. `upstream/` is a reading copy: it proves what exists, never what to
  write.
- **A superset is not an obligation to implement.** `not-scheduled` is an
  honest state: it says the four trees carry it, this tree does not, and
  nothing in this tree pretends otherwise. `refused` is a deliberate no with a
  reason, the way `Carrier::Masque` and `TransportKind::Xdrive` refuse today.
  What is forbidden is a method that parses to nothing — `TransportKind::Other`
  with `"unknown type: parses, transport not scheduled"` is exactly that, and
  it is why rows exist for `tuic`, `anytls`, `shadowtls`, `snell`, `ssh` and
  `naive` (README table A row 21).

## The matrix

<!-- matrix:begin -->
| row | layer | state | references | note |
| --- | --- | --- | --- | --- |
| vless | protocol | implemented | upstream/xray-core/proxy/vless, upstream/sing-box/protocol/vless, upstream/xray-rust/crates/xray-proxy, docs/function/vless.md | both roles; method strings `vless-tcp`, `vless-tcp-tls`, `vless-tcp-none` |
| vless-reality-vision | protocol | implemented | upstream/xray-core/proxy/vless, upstream/xray-core/transport/internet/reality, docs/function/reality-tls.md, docs/function/xtls-vision.md | `xtls-rprx-vision`, server role complete; method string `vless-tcp-reality-vision` |
| vless-encryption | protocol | planned | upstream/xray-core/proxy/vless/encryption, upstream/xray-rust/crates/xray-vless-encryption, upstream/zeronet/crates/zero-protocol/src/vless_encryption.rs | `mlkem768x25519plus.<native\|xorpub\|random>.<1rtt\|0rtt>`; README table A row 34 |
| vless-flow-udp443 | protocol | planned | upstream/xray-core/infra/conf/vless.go | `xtls-rprx-vision-udp443`; README row 35 |
| vmess | protocol | implemented | upstream/xray-core/proxy/vmess, upstream/sing-box/protocol/vmess, upstream/zeronet/crates/zero-protocol, docs/function/vmess.md | AEAD only, four ciphers, both roles, every carried carrier |
| trojan | protocol | implemented | upstream/xray-core/proxy/trojan, upstream/sing-box/protocol/trojan, upstream/sing-box/transport/trojan, upstream/zeronet/crates/zero-protocol, docs/function/trojan.md | 56-byte SHA-224 key, commands 1/3, TCP+UDP |
| shadowsocks | protocol | implemented | upstream/xray-core/proxy/shadowsocks, upstream/sing-box/protocol/shadowsocks, upstream/zeronet/crates/zero-protocol, docs/function/shadowsocks.md | AEAD set + `rc4-md5` + Xray spellings; MD5 chain only |
| shadowsocks-2022 | protocol | implemented | upstream/xray-core/proxy/shadowsocks_2022, upstream/zeronet/crates/zero-protocol/src/shadowsocks2022.rs, docs/function/shadowsocks-2022.md | `2022-blake3-*`, EIH identity, TCP+UDP relay; README row 28 |
| anytls | protocol | planned | upstream/sing-box/protocol/anytls, upstream/zeronet/crates/zero-protocol/src/anytls.rs | padding scheme, session pooling, client metadata |
| shadowtls | protocol | planned | upstream/sing-box/protocol/shadowtls | versions 1–3, `wildcard_sni`, `strict_mode`, handshake detour |
| snell | protocol | planned | upstream/sing-box/protocol/snell | v4–v6, `obfs_mode`, `mode`, userkey |
| ssh | protocol | planned | upstream/sing-box/protocol/ssh | outbound only; also the `+SSH` chaining layer |
| naive | protocol | planned | upstream/sing-box/protocol/naive | HTTP/2 + QUIC, padding headers, `insecure_concurrency` |
| tuic | protocol | planned | upstream/sing-box/protocol/tuic, upstream/zeronet/crates/zero-transport/src/tuic.rs | v5 over QUIC, `udp_relay_mode`, 0-RTT |
| hysteria | protocol | implemented | upstream/xray-core/proxy/hysteria, upstream/sing-box/protocol/hysteria, upstream/sing-box/protocol/hysteria2, upstream/zeronet/crates/zero-transport/src/hysteria2.rs, upstream/xray-rust/crates/xray-proxy | v2 TCP carried in both roles; UDP flows, salamander obfs and masquerade refused by name |
| masque-protocol | protocol | planned | upstream/xray-core/proxy/masque, upstream/sing-box/protocol/masque | CONNECT-IP as a protocol with its own user table, not only as a carrier |
| wireguard | protocol | planned | upstream/xray-core/proxy/wireguard, upstream/sing-box/protocol/wireguard, upstream/sing-box/transport/wireguard, upstream/xray-rust/crates/xray-wireguard, upstream/zeronet/crates/zero-protocol/src/wg_stack.rs, upstream/zeronet/crates/zero-protocol/src/wg_server.rs | userspace netstack, no kernel TUN, reserved bytes; the reference now ships the responder side too — cryptokey routing, allowedIPs longest-prefix, roaming — plus `secretKey`/`mtu`/`peers[]` config |
| amneziawg | protocol | planned | upstream/zeronet/crates/zero-protocol/src/amnezia.rs | junk + S1–S4 + H1–H4 parameter set |
| tailscale | protocol | planned | upstream/sing-box/protocol/tailscale | tsnet endpoint, DERP, MagicDNS, exit node |
| tor | protocol | planned | upstream/sing-box/protocol/tor, upstream/zeronet/crates/zero-tor | spawned `tor` binary or an arti lane; TCP only, so no UDP carrier above it |
| openvpn | protocol | planned | upstream/sing-box/protocol/openvpn, upstream/sing-box/transport/openvpn | client + server, `tls_auth`/`tls_crypt`/`tls_crypt_v2` |
| openconnect | protocol | planned | upstream/sing-box/protocol/openconnect, upstream/sing-box/transport/openconnect | anyconnect/gp/fortinet/f5/pulse/nc flavours |
| cloudflared | protocol | planned | upstream/sing-box/protocol/cloudflare | Argo tunnel inbound |
| bridge | protocol | not-scheduled | upstream/sing-box/protocol/bridge | L2 bridge: pf, netlink/nft, WinDivert NAT |
| freedom | protocol | implemented | upstream/xray-core/proxy/freedom, upstream/sing-box/protocol/direct | the sink outbound; `fragment`/`noises`/`finalRules` and the `proxyProtocol: 1\|2` send (`zeronet/crates/zero-config/src/xray_json.rs`) not carried |
| blackhole | protocol | planned | upstream/xray-core/proxy/blackhole, upstream/sing-box/protocol/block | `none`/`http`/`custom` response |
| dns-outbound | protocol | planned | upstream/xray-core/proxy/dns, upstream/sing-box/protocol/dns | rules `direct`/`drop`/`return`/`hijack`, `rewrite_server` |
| masterdns | protocol | planned | upstream/zeronet/crates/zero-masterdns, upstream/zeronet/crates/zero-protocol/src/masterdns | a VPN over DNS queries: the base/codec wire half and the live half that carries it — UDP resolver, optional compression, ARQ reliability, session handshake, SOCKS stream management |
| loopback | protocol | implemented | upstream/xray-core/proxy/loopback, docs/function/loopback.md | re-inject into a named inbound tag, with sniffing refused |
| http-protocol | protocol | implemented | upstream/xray-core/proxy/http, upstream/sing-box/protocol/http | front implemented in both directions of the front; the upstream HTTP-proxy outbound is planned |
| socks | protocol | implemented | upstream/xray-core/proxy/socks, upstream/sing-box/protocol/socks, upstream/zeronet/crates/zero-protocol/src/socks.rs | front implemented; the SOCKS *outbound* is planned (P49's chaining surface) |
| dokodemo | front | planned | upstream/xray-core/proxy/dokodemo | `tunnel`/`dokodemo-door`, TCP+UDP, `portMap`, `followRedirect`, SNI+ALPN original dst |
| front-mixed | front | implemented | upstream/sing-box/protocol/mixed | one-byte sniff between SOCKS and HTTP |
| front-tun | front | planned | upstream/xray-core/proxy/tun, upstream/sing-box/protocol/tun, upstream/sing-box/transport/device, upstream/xray-rust/crates/xray-tun, upstream/zeronet/crates/zero-tun | needs a platform device, a userspace IP stack and privilege; refused by name today |
| front-redirect | front | planned | upstream/sing-box/protocol/redirect | `redirect` and `tproxy` inbounds, original destination |
| front-tun2socks | front | planned | README.md | zeptun's translator: TUN to TCP/UDP/ICMP through the SOCKS front that exists |
| carrier-tcp-raw | carrier | implemented | upstream/xray-core/transport/internet/tcp | `header.type: none` only; `acceptProxyProtocol` not carried — the reference parses v1+v2 inbound (`zeronet/crates/zero-protocol/src/proxy_protocol.rs`) and this tree only writes the header into a REALITY `dest` via `xver` |
| carrier-httpheader | carrier | implemented | upstream/xray-core/transport/internet/headers, upstream/xray-core/infra/conf/transport_method.go, upstream/zeronet/crates/zero-transport/src/tcp_header.rs, docs/function/carrier-httpheader.md | one-shot request/response camouflage, both roles |
| carrier-websocket | carrier | implemented | upstream/xray-core/transport/internet/websocket, upstream/sing-box/transport/v2raywebsocket, upstream/zeronet/crates/zero-transport/src/ws, docs/function/carrier-websocket.md | early data both roles; method strings `vless-ws`, `vless-ws-tls` |
| carrier-httpupgrade | carrier | implemented | upstream/xray-core/transport/internet/httpupgrade, upstream/sing-box/transport/v2rayhttpupgrade, docs/function/carrier-httpupgrade.md | method strings `vless-httpupgrade`, `vless-httpupgrade-tls`; `?ed=` parsed, not carried |
| carrier-grpc | carrier | implemented | upstream/xray-core/transport/internet/grpc, upstream/sing-box/transport/v2raygrpc, upstream/zeronet/crates/zero-transport/src/grpc.rs, docs/function/carrier-grpc.md | full HTTP/2 + HPACK; method strings `vless-grpc`, `vless-grpc-tls` |
| carrier-grpc-lite | carrier | planned | upstream/sing-box/transport/v2raygrpclite | dependency-free gun: the reference's fallback when `with_grpc` is absent or forced |
| carrier-xhttp | carrier | partial | upstream/xray-core/transport/internet/splithttp, upstream/xray-rust/crates/xray-transport/src/stream/xhttp, upstream/zeronet/crates/zero-transport/src/xhttp.rs, upstream/zeronet/crates/zero-transport/src/xhttp_request.rs, docs/function/carrier-xhttp.md | one mode (POST + chunked); stream-one/stream-up/packet-up, padding, per-key placements and `xmux` not carried; method strings `vless-xhttp`, `vless-xhttp-tls` |
| carrier-singbox-http | carrier | planned | upstream/sing-box/transport/http | the shared CONNECT / Extended-CONNECT / capsule transport behind HTTP-proxy, naive and masque |
| carrier-v2ray-http | carrier | planned | upstream/sing-box/transport/v2rayhttp | HTTP/1.1 POST or HTTP/2 CONNECT-style stream with an idle-conn pool |
| carrier-v2ray-dispatch | carrier | not-scheduled | upstream/sing-box/transport/v2ray, upstream/sing-box/constant/v2ray.go | the reference's own dispatcher, listed so its absence is a state rather than a gap |
| carrier-quic | carrier | partial | upstream/xray-core/infra/conf/transport_internet.go, upstream/sing-box/transport/v2rayquic, docs/function/carrier-quic.md | client only, quiche, ALPN `h3`; the reference refuses the transport by name, so this row carries its own P35 decision; method string `vless-quic` |
| carrier-v2ray-quic | carrier | not-scheduled | upstream/sing-box/transport/v2rayquic | the same transport in the second reference, named so the row above is not read as universal |
| carrier-hysteria | carrier | implemented | upstream/xray-core/transport/internet/hysteria, upstream/zeronet/crates/zero-transport/src/hysteria2.rs, docs/function/carrier-hysteria.md | quiche, ALPN `h3`, one handshake per flow; no UDP, no pooling; method string `vless-hysteria` |
| carrier-masque | carrier | planned | upstream/xray-core/transport/internet/masque, upstream/sing-box/transport/masque, upstream/zeronet/crates/zero-transport/src/masque.rs | CONNECT-IP client dialled over h2/h3 with both-direction capsules (Foxy lane, row 20); address pool and terminating server refused by name |
| carrier-xdrive | carrier | planned | upstream/xray-core/transport/internet/xdrive | polls a cloud-drive remote as a transport |
| carrier-device | carrier | planned | upstream/sing-box/transport/device | the generic TUN/IP device abstraction the reference's VPN endpoints share |
| carrier-simple-obfs | carrier | planned | upstream/sing-box/transport/simple-obfs | http and tls obfs backends |
| carrier-sip003 | carrier | planned | upstream/sing-box/transport/sip003 | plugin harness: `obfs-local`, `v2ray-plugin` |
| carrier-browser-dialer | carrier | not-scheduled | upstream/xray-core/transport/internet/browser_dialer | browser-driven dial |
| carrier-foxy | carrier | implemented | upstream/zeronet/crates/zero-transport/src/xhttp.rs, README.md, docs/function/carrier-foxy.md | this tree's own lane: h1/h2/h3 plus CONNECT-UDP; socket-proven over real QUIC, TCP and TLS |
| kcp | carrier | implemented | upstream/xray-core/transport/internet/kcp, docs/function/kcp.md | core oracle-proven against the pinned Go; the app seam is P29 and P36; method string `vless-kcp` |
| reality-tls | security | implemented | upstream/xray-core/transport/internet/reality, upstream/xray-core/transport/internet/tls, upstream/sing-box/option/tls.go, upstream/zeronet/crates/zero-security, docs/function/reality-tls.md | TLS in both roles, REALITY server complete, client unwired |
| tls-cipher-suites | security | implemented | upstream/xray-core/transport/internet/tls, upstream/sing-box/option/tls.go, docs/function/tls-cipher-suites.md | PattNG ext. matrix row 17: `tlsSettings.cipherSuites` is parsed and re-ordered to `crypto/tls` byte-for-byte (10/10 oracle cases in `scripts/hello-oracle`), and the dialer's TLS 1.3 field on the wire matches the reference; TLS 1.2 ids are parsed but unreachable — `rustls` ships `ring+std` with no `tls12` (see `prompts.md` `pattng-tls12-advertise`) |
| security-tls-options | security | planned | upstream/xray-core/infra/conf/transport_security.go, upstream/sing-box/option/tls.go | min/max version, cipher suites, curve preferences, `masterKeyLog`, `pinnedPeerCertSha256`, `rejectUnknownSNI`; the REALITY-side knobs the tree already acts on are `maxTimeDiff`, `minClientVer`/`maxClientVer` and the `limitFallback{Upload,Download}` gauge (`reality.rs` `Gauge`); `mldsa65Seed`/`mldsa65Verify` are not |
| security-utls | security | planned | upstream/xray-rust/crates/xray-utls, upstream/xray-rust/crates/xray-transport/src/utls_profiles.rs, upstream/zeronet/crates/zero-security/src/fingerprint.rs, upstream/zeronet/crates/zero-security/src/reality_compat.rs | 61 fingerprint names across two references; nothing here shapes a ClientHello |
| security-ech | security | planned | upstream/xray-core/transport/internet/tls/ech.go, upstream/sing-box/common/tls/ech.go, upstream/sing-box/common/tls/ech_shared.go, upstream/sing-box/option/tls.go, upstream/zeronet/crates/zero-security | client config list (raw, SVCB or DoH) and server `ECH KEYS` |
| security-ktls | security | planned | upstream/sing-box/common/tls/ktls.go | kernel TX/RX, Linux only, gated on ALPN and cipher |
| xtls-vision | security | implemented | upstream/xray-core/proxy/vless, upstream/zeronet/crates/zero-protocol/src/vless.rs, docs/function/xtls-vision.md | padding commands 0/1/2, 16-byte first frame, `NumberOfPacketToFilter` 8 |
| mux-cool | multiplex | implemented | upstream/zeronet/crates/zero-protocol/src/mux.rs, upstream/sing-box/common/mux, docs/function/mux-cool.md | Xray-core removed its own mux, so this row is a superset row, not a parity row |
| mux-variants | multiplex | planned | upstream/sing-box/common/mux | smux, yamux, h2mux |
| obfs-finalmask | obfuscation | planned | upstream/xray-core/transport/internet/finalmask, upstream/xray-core/infra/conf/transport_finalmask.go | fragment, noise, salamander, sudoku, xdns, xicmp, realm, udphop, xmc, header-custom |
| obfs-evasion | obfuscation | planned | upstream/zeronet/crates/zero-evasion | ClientHello fragment, UDP noise, fake-SNI inject, keepalive shaping |
| obfs-dns-tunnel | obfuscation | planned | README.md | DNSTT / NoizDNS / VayDNS / CottenDNS, read off unpinned sources |
| obfs-sni-spoof | obfuscation | planned | README.md | fake ClientHello without root; nothing in CI checks it yet |
| record-layer | record | implemented | crates/ferrox-core/src/record.rs, docs/function/record-layer.md | the rung every AEAD method sits on |
| engine-router | engine | planned | upstream/xray-core/app/router, upstream/sing-box/option/route.go, upstream/zeronet/crates/zero-router, upstream/xray-rust/crates/xray-routing | rules, rule sets, rule actions |
| engine-geodata | engine | planned | upstream/xray-core/app/geodata, upstream/zeronet/crates/zero-router/src/assets.rs | geoip/geosite assets, refresh policy |
| engine-dns | engine | planned | upstream/xray-core/app/dns, upstream/sing-box/option/dns.go, upstream/zeronet/crates/zero-dns | UDP/TCP/DoT/DoH/DoQ, cache, FakeDNS, hosts |
| engine-observatory | engine | planned | upstream/xray-core/app/observatory, upstream/sing-box/protocol/group, upstream/zeronet/crates/zero-observatory | balancers plus the 10-rung ladder with access-class failover |
| engine-selector | engine | planned | upstream/sing-box/protocol/group | `selector` and `urltest` with history |
| engine-api | engine | planned | upstream/xray-core/app/commander, upstream/sing-box/option/api.go, upstream/sing-box/option/experimental.go | gRPC services, HTTP management, v2ray api |
| engine-stats | engine | planned | upstream/xray-core/app/stats, upstream/xray-core/transport/internet/stat | counters and channel |
| engine-reverse | engine | planned | upstream/xray-core/app/reverse, upstream/zeronet/crates/zero-runtime/src/reverse.rs, upstream/xray-core-rust/crates/xray-app-reverse | bridge and portal; the ZeroNet shape rides Mux.cool carriers with a `Control{ACTIVE|DRAIN}` heartbeat, DRAIN after 256 sessions, ≤16 carriers per bridge |
| engine-sniffing | engine | planned | upstream/xray-core/app/dispatcher | http, tls, quic, fakedns sniffers |
| engine-tagged | engine | planned | upstream/xray-core/transport/internet/tagged | the tagged outbound |
| engine-policy | engine | planned | upstream/xray-core/app/policy | per-level timeouts and buffer sizes |
| engine-udp-dialer | engine | implemented | upstream/xray-core/transport/internet/udp | the shared UDP dialer every UDP destination in the reference goes through |
| engine-dialer | engine | planned | upstream/zeronet/crates/zero-net, upstream/xray-core-rust/crates/xray-transport, upstream/xray-core/transport/internet/dialer.go | racing, socket options, happy eyeballs; the reference surface now includes raw `customSockopt` entries with system/network/level filters (`zeronet/crates/zero-core/src/custom_sockopt.rs`), transparent dials (`zero-net/src/transparent.rs`: `SO_ORIGINAL_DST`, `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`), and the two knobs xray-core-rust adds over Go: `reusePort` and `receiveBufferSize`/`sendBufferSize` (`xray-transport/src/sockopt/mod.rs`) |
| engine-budgets | engine | implemented | upstream/xray-core/app/policy, crates/ferrox-app/src/budgets.rs, crates/ferrox-app/src/census.rs, crates/ferrox-app/src/config.rs | a top-level `budgets` object restates nine wait bounds — `dial`, `handshake`, `headArrival`, `relayJoin`, `relayQuantum`, `udpIdle`, `payloadGrace`, `goawayGrace`, `carrierProbe` — in `"450ms"`/`"30s"` spelling, armed before the first inbound opens; the reference budgets waits per policy *level*, this names each wait itself. An unknown name, a missing unit or a zero wait is refused with the name that caused it rather than read as the default. Cadences that pace a loop (`RELAY_POLL`, `SESSION_POLL`, `RELAY_IDLE`, the spin and try counts) stay constants on purpose: a runtime cadence is a load per iteration in the relay's hottest loop. Witnessed by `budgets::tests::a_budget_the_config_names_is_the_value_a_site_reads`, `proxy::tests::a_named_join_budget_is_the_bound_a_parked_leg_gives_up_on` and `proxy::tests::a_head_that_never_arrives_is_given_up_on_at_its_named_budget`; the other seven names reach the same table at their arm site (`connect_timeout`, a `set_read_timeout`, a `set_read_quantum`, a `recv_timeout`, a sleep, a QUIC probe budget), and a bound that only bites on a real lane is a CI witness, not a local one. Part of the table now reports itself at runtime: a census beside it registers a wait with its name, the descriptor it blocks on and the deadline it armed, deregisters on return, and dumps one `key=value` line per live wait in the shape `watch-test.sh`'s procfs lines take — which is what a stall on macOS or Windows has no procfs to show. It is a test-shape instrument: the call site is a macro whose arm outside `cfg(test)` expands to nothing, so the shipped relay carries neither the map nor the lock nor the name, and the release binary read with `strings` finds no `relay-leg-read` string where the test binary does. Four of the table's waits register today — `relay-leg-read` and `relay-leg-write` in both raw copy shapes (`copy_all_memcpy`, and the Linux splice `pull`/`push`, whose fd is the socket's own), `tunnel-leg-read` through the shared relay half, and `relay-join`, the only one of the four that holds its budget at the wait — gated by `proxy::census_tests::a_parked_leg_read_names_the_descriptor_it_waits_on`, `proxy::census_tests::a_parked_tunnel_leg_reports_the_time_it_has_waited` and `proxy::census_tests::a_parked_join_reports_the_budget_it_armed`, with `census::tests::a_returned_wait_leaves_the_others_it_crossed_in_place` holding the deregistration. Two gaps are the finding rather than an omission: a leg through the shared half is a `dyn Read`, so no descriptor reaches its line, and a raw leg's deadline is armed by its caller upstream (`serve_vless_raw` restores `set_read_timeout(None)`) instead of held at the wait, so its line reads `armed=none`; `dial`, `handshake`, `headArrival`, `relayQuantum`, `udpIdle`, `payloadGrace`, `goawayGrace` and `carrierProbe` still have no census entry, and each is the next slice's row |
| engine-config | engine | planned | upstream/xray-rust/crates/xray-config, upstream/zeronet/crates/zero-config | a strict parser with a compile step, never a loose one; the reference also layers configs — repeated `-c` and `-confdir` merged by inbound/outbound tag with appended arrays and a `_priority` marker (`zero-config/src/merge.rs`) — and the Rust xray reads JSON5/YAML/TOML by extension (`xray-conf/src/vformat.rs`) with a lint-stage registry (`xray-conf/src/lint.rs`) |
| engine-runtime | engine | planned | upstream/xray-rust/crates/xray-core-rs, upstream/xray-rust/crates/xray-runtime, upstream/zeronet/crates/zero-runtime, upstream/zeronet/crates/zero-core | composition root, failure taxonomy, session vocabulary |
| engine-codecs | engine | not-scheduled | upstream/zeronet/crates/zero-protocol, upstream/xray-rust/crates/xray-proxy | their shared codec crates, read for technique; this tree keeps its codecs beside their carriers |
| engine-scanner | engine | planned | upstream/zeronet/crates/zero-scanner | CDN clean-IP and edge scanning |
| engine-discovery | engine | planned | upstream/zeronet/crates/zero-discovery | feeds, link sorting, WARP registration |
| engine-chaining | engine | planned | upstream/zeronet/crates/zero-runtime, README.md | detour graph and ordered hop chains |
| surface-cli | surface | implemented | upstream/xray-rust/crates/xray-cli, upstream/zeronet/crates/zray-cli | `run -c`, `check`, parser tooling |
| surface-ffi | surface | planned | upstream/xray-rust/crates/xray-ffi, upstream/zeronet/crates/zray-mobile | C ABI and JNI with panic containment |
| surface-bench | surface | implemented | upstream/xray-rust/crates/xray-bench, upstream/zeronet/bench/hotpath, crates/ferrox-bench | counting gates and comparators |
| surface-tui | surface | not-scheduled | upstream/zeronet/crates/zeronet-tui | a desktop UI is not a core |
| surface-provision | surface | not-scheduled | upstream/zeronet/crates/zero-provision | facts, guide, keys, layout, links, probe, record, release, scripts and SSH install: a server installer is an operating tool, not a core |
| surface-fuzz | surface | planned | upstream/xray-rust/fuzz, upstream/zeronet/fuzz | seeded untrusted-input targets |
| obfs-tide-shaping | obfuscation | planned | upstream/zeronet/crates/zero-protocol/src/tide/shape.rs | server pads downstream bursts so a watched flow keeps `down ≥ ratio × up` (off/light 0.5 / full 2.0, 20 s half-life decay, 4 KiB min burst, free for download-only sessions) — a superset rung no other reference carries |
| obfs-fragment-tlssni | obfuscation | planned | upstream/zeronet/crates/zero-evasion/src/fragment.rs | a `packets: tlssni` cut landing inside the SNI's second-level label, against DPI that reassembles segments and re-reads TLS records; `from-to` raw ranges and `0`-empty lead pieces ride it |
| engine-rendezvous | engine | planned | upstream/zeronet/crates/zero-discovery/src/rendezvous.rs | fountain-coded carrier descriptors published as DoH TXT (`f<i>.<zone>`, XOR packets, GF(2) decode), ed25519-signed with epoch anti-replay — carrier recovery through a DNS-only view of the net |
<!-- matrix:end -->

Rows without a `docs/function` page are targets or refusals; they make no
count claim. When one of them lands, it lands with its page, and
`scripts/check-method-docs.sh` plus a new row in
`scripts/method-counts.txt` are what say so.

## The in-flight methods a rewrite must not lose

These are the rows the checker's rule 2 protects. Every one of them has a page
with gated counts today, so a rewrite that drops or silently widens any of them
loses a gate, not just a feature:

- the VLESS method strings `vless-tcp`, `vless-tcp-tls`, `vless-tcp-none`,
  `vless-tcp-reality-vision`, `vless-ws`, `vless-ws-tls`, `vless-xhttp`,
  `vless-xhttp-tls`, `vless-grpc`, `vless-grpc-tls`, `vless-httpupgrade`,
  `vless-httpupgrade-tls`, `vless-quic`, `vless-kcp`, `vless-hysteria`;
- the pages `record-layer`, `shadowsocks`, `vmess`, `vless`, `trojan`,
  `xtls-vision`, `mux-cool`, `reality-tls`, `kcp`,
  `carrier-websocket`, `carrier-httpupgrade`, `carrier-httpheader`,
  `carrier-grpc`, `carrier-xhttp`, `carrier-quic`, `carrier-hysteria`,
  `carrier-foxy`.

Two of those rows are the ones a rewrite is most likely to break by accident,
because they are *not* parity rows: `carrier-foxy` and `mux-cool` exist in no
xray-core config at the pinned revision, and `kcp`'s arithmetic is proved
against a Go oracle that a rewrite must not re-derive by hand.

## Needless copies, branches and refills

Read out of this tree, verified line by line. Each item states whether a fix
is bit-identical on the wire and what witnesses it, because a copy claim is
proved by pointer identity and not by reading. Rows are ordered by work
removed.

### Copies

| # | what | where | bit-identical | witness | covered today by | slice |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | closed: a `BufReader` in front of a two-read-per-frame codec staged every payload byte a second time, at five sites | the vmess four (`vmess.rs:1396` `pump_relay`, `vmess.rs:1201` `serve_xhttp`, `proxy.rs:3376` `dial_vmess_rung`, `proxy.rs:4097` `vmess_tls_carried`) went with 9ef3719; the fifth, `proxy.rs:4354` `dial_ss_xhttp`, goes with P56, which hands both Shadowsocks rungs' carriers straight to `relay_downlink`; P57 then gave the 2022 `relay_downlink` the classic rung's window, so neither rung asks its header and its payload separately | yes — a read boundary is not a frame boundary | a read-width counter between the carrier and the codec, driven from an in-memory stream that frames real carrier records | `shadowsocks::tests::the_carrier_and_the_window_ask_the_socket_as_one`, `shadowsocks::tests::the_stream_downlink_asks_its_own_chunk_of_the_socket`, `shadowsocks2022::tests::the_carrier_and_the_window_ask_the_socket_as_one`, and the window's own gates `shadowsocks2022::tests::a_bulk_read_serves_every_buffered_chunk` and `a_batch_never_waits_for_a_chunk_that_has_not_arrived`, each with its manifest row. The vmess four went with no ask-width witness of their own — `vmess::tests::frames_reuse_the_callers_buffers` drives `read_frame` directly and never entered the wrap | P54, closed |
| 2 | closed: the gRPC read path staged every payload byte twice — socket → `frame` → `msg` → `backlog` → caller | `grpc.rs` `GrpcReader::data` reads a DATA body onto the end of `msg`; `read` delivers the payload from `msg_at`..`pay_end` | yes | the reader's own `staged` counter over an in-memory server that answers whole frames, at three shapes: one message per frame, two messages in one frame, one message split over frames | `carrier-grpc payload-staging-copies-per-byte-read 0` by `grpc::tests::a_body_never_lands_in_a_second_buffer`, with the padded frame's one move counted beside it | P55 |
| 3 | the xudp path is the one mux write that still stages into a scratch buffer instead of handing the payload by pointer | `proxy.rs:5703-5705` (`resize_scratch(&mut staging, frame.frame_len(payload.len()))` then `write.write_all(&staging[..written])`) in `serve_socks_udp_vless_xudp` | yes — `mux::tests::a_header_plus_a_patched_length_is_the_whole_frame` (`mux.rs:667`) already holds the two encoders byte-equal | the app-side cousin of `proxy::tests::a_two_part_write_hands_the_payload_over_by_pointer` (`proxy.rs:11901`): `parts[1].iov_base == payload.as_ptr()`, plus `staging.capacity()` steady | `proxy::tests::xudp_frames_match_the_upstream_layout` (`proxy.rs:11673`) is bytes only | P55 |
| 4 | `read_http_head` reads every head twice — `peek` into a stack probe, then `read_exact` of the same bytes — **closed for HTTPUpgrade**, whose fd path now reads into the buffer it keeps (`proxy::read_http_head_kept`); the `peek` reader stays for the callers with nowhere to put the tail | `proxy.rs` `peek_head_rounds` (`stream.peek(&mut probe)`, then `read_exact` of the same octets) | yes | `Counted` over an in-memory stream asserting one read per window and the tail taken with the head — `proxy::tests::a_kept_head_costs_one_read_per_window_and_takes_its_tail` | that test, `a_kept_head_straddling_a_round_is_proved_by_two_reads`, `a_head_that_straddles_a_read_round_keeps_its_riding_payload`, and `bytes_pipelined_behind_a_head_stay_in_the_kernel` for the reader that still leaves them | P54, closed for `ws`/`xhttp`/`httpheader` on their pages |
| 5 | closed: `read_exact_head` copied socket → 512-byte `chunk` → `head` on every step and `split_off`'d the tail into a third trip; it is `kept_head_rounds` now, so the record carriers read straight into the buffer they return and get back the offset where the head ends | `proxy.rs` (`read_exact_head`) | yes | head and tail in one allocation, seen as `tail.as_ptr() - head.as_ptr() == at` over an in-memory stream | `proxy::tests::a_whole_connect_head_costs_one_read` and `a_kept_head_costs_one_read_per_window_and_takes_its_tail`, plus one per record carrier: `ws`, `httpupgrade`, `httpheader` and `xhttp` each have `the_record_head_hands_over_the_buffer_it_filled` | P55 |

### Branches

| # | what | where | bit-identical | witness | slice |
| --- | --- | --- | --- | --- | --- |
| 9 | the dial branch tree is written three times over the same five arms, and the serve branch tree twice more over six — about 450 lines differing in which `connect` is called, not in what is decided | `dial_vless_rung` (`proxy.rs:2269`), `dial_trojan_rung` (`proxy.rs:3491`), `dial_vmess_rung` (`proxy.rs:3342`), `serve_session_*` (`proxy.rs:1301-1465`), `serve_vless` (`proxy.rs:704-801`), `vmess.rs:1132-1261`, `shadowsocks.rs:58-154` | yes | the matrix tests that already exercise every arm (`proxy::tests::vless_over_tls_*_carries_an_echo`, `proxy.rs:10133-10274`) | P57 |
| 10 | `relay_ordered` re-tests the same `first` flag four times per relay read | `proxy.rs:6521`, `proxy.rs:6524`, `proxy.rs:6528`, `proxy.rs:6532` | yes | no counter needed; the relay gates stay green | P57 |
| 11 | the relay's teardown path `format!`s a string before `echo_trace` (`proxy.rs:306`) tests its flag | `proxy.rs:6546`, `proxy.rs:6582` | yes | no counter needed | P57 |
| 12 | `Lanes::xor_chunk` branches on `c == 0` per 16-byte chunk; the neon and portable impls discard `c` entirely | `chacha/mod.rs:38` (the trait), `avx2.rs:137-147`, `neon.rs:95`, `portable.rs:84` | yes | `ferrox-core-chacha::backend` blocks-per-iteration, unchanged | P57 |
| 13 | `xor_groups` tests `skips_first` per chunk inside the store loop over a value fixed at function entry | `chacha/mod.rs:221`, fixed at `chacha/mod.rs:197` | yes | the same per-length sweeps (`chacha::avx2::tests::the_eight_block_pass_is_the_ladder_at_every_length`) | P57 |

### Refills

| # | what | where | bit-identical | witness | slice |
| --- | --- | --- | --- | --- | --- |
| 14 | UDP-over-TCP pays two read syscalls per datagram for VLESS and four to six for Trojan, where one window read into a per-connection remainder would amortise to one | `proxy.rs:5965-5974` (`read_udp_datagram`), `proxy.rs:6000-6012` (`read_trojan_datagram`), via `read_socks_addr` (`proxy.rs:7156-7199`) | yes | the `Counting` reader idiom already blessed for this file by `proxy::tests::the_trojan_header_costs_two_reads_not_seven` (`proxy.rs:8883`) | P54 |

### Wakes

| # | what | where | bit-identical | witness | slice |
| --- | --- | --- | --- | --- | --- |
| 15 | closed: the splice pump armed `POLLIN` on a predicate in *bytes* (`pending < capacity`) while the kernel's `EAGAIN` from `splice_to_pipe` is about *slots*, so a ring of partially filled buffers woke it on data it had nowhere to put, and re-arming that wake is a spin on a flow nobody can move | `proxy.rs` `poll_relay::run` (the arm) and `poll_relay::Direction::advance` (the attempt) | yes — the same two splices at the same lengths into the same buffers; only when the attempt is made changed | `poll_relay::no_pollin_is_armed_on_a_ring_that_holds_bytes_it_cannot_take` is the arm's truth table and holds the invariant that the drain stays armed; `relay_tests::a_trickling_destination_does_not_spin_the_pump` counts `poll_relay::idle_ingests()` (a `cfg(test)` counter, so production emits nothing) over a 400 ms window, where the same counter against unpumped code measured 78 183 of 79 013 wakes moving nothing and 390 ms of pump cpu, and measures 2 on this one; priced by the `vless-raw-up-1` cell as 0.431× xray-core's cost before (2 501 ms of system time per GiB against its 1 076 on that runner, gate red) and 3.818× better after (185 against 721), each ratio against its own runner since the cells landed on different machines, with `vless-raw-down-1` moving from 2.271× to 2.459× xray-core's cost rather than regressing | landed (#129) |

### Zero-fills that are not witnessed by anything

Three of these carry a manifest row whose named checker cannot see the fill,
because `count::measure` (`alloc_count.rs:70-97`) hooks `alloc`/`alloc_zeroed`
and a `resize` into spare capacity is a plain `memset`:

- `mux::Outgoing::encode_header_into` (`mux.rs:253`) zeroes `2 + meta` bytes
  that `write_meta` (`mux.rs:216-238`) then overwrites byte for byte, per
  relayed frame. Row `mux-cool mux-frame-allocations 0` passes anyway.
- **Closed: the relay buffer's two fills.** `RelayBuf::new` was
  `vec![0u8; RELAY_SMALL_BUFFER]` and `RelayBuf::filled` promoted with
  `resize(RELAY_BUFFER, 0)`; both are `with_capacity`/`reserve` plus `set_len`
  now, the shape `read_into_tail` already uses. The difference is witnessed in
  `ferrox-core` by `alloc_count::tests::an_uninitialised_tail_is_allocated_but_not_filled`,
  which measures the two shapes against each other: same allocation, same bytes,
  and `alloc_zeroed` is the only count that moves. There is no row for it. Gating
  it from the app needed the counting allocator installed in `ferrox-app`'s test
  binary, and CI showed the price — `der_to_pem Ir=2743` against a blessed
  `2653`, because a thread-local test joined every allocation that count measures.
  The promotion's 240 KiB is still the `memset` this section is about:
  `write_bytes` is not `alloc_zeroed`, so no counter sees it and the page says so
  instead of blessing a number. The other half of the shape is checked now:
  `safety.yml`'s `tails` shard interprets `ferrox-app`'s test binary, so a `filled`
  that stops clipping at `n` aborts on `memory is uninitialized` in
  `the_relay_buffer_hands_back_only_what_its_read_reported` — Miri watches the read
  discipline, while the removed fill stays uncounted (P66).
- the relay's other buffers: `vec![0u8; CHUNK]` at `proxy.rs:6516`,
  `proxy.rs:6560`, `proxy.rs:6622`, `proxy.rs:6637`, `vmess.rs:1058`,
  `vmess.rs:1362`, `shadowsocks.rs:272`, `hysteria.rs:417`, `hysteria.rs:431`,
  `proxy.rs:2403`, `proxy.rs:2416`.
  Every one is handed straight to `Read::read`, which initialises exactly the
  bytes it reports.
- `vec![0u8; 65536]` per KCP connection in both socket threads
  (`kcp/listener.rs:43`, `kcp/listener.rs:132`), where only `&buf[..n]` is ever
  read.

## What is not removed

Named because a page that lists only wins is not evidence:

- **KCP still sends one datagram per 1 332-byte segment.** Batching would
  change the datagram boundaries a peer sees, so it is named and left alone.
- **The mux uplink still copies every payload byte once**, because removing
  that copy means splitting `mux::Outgoing::encode_into` in two. Item 3 above
  removes one *further* copy on one path; the one that remains is stated.
- **The AEAD open path is two keystream passes and no staging buffer.** That
  is the named tradeoff the page records (`keystream-passes-per-decrypt 2`
  against `staging-bytes-per-decrypt 0`); changing it changes the method
  rather than tuning it.
- **The websocket masked-write path still copies once**, into the thread-local
  mask buffer. A mask must be applied to a copy of the caller's bytes and a
  three-part `writev` of header, mask and data is not available.
- **The 2022 handshake reader's two reads** (`relay_downlink`'s `Recv::Waiting`
  arm reads the sealed header, then the payload) — it opens exactly one chunk, so
  there is no second chunk for a window to serve, and the relay loop that follows
  it has had the classic rung's window since P57 (`ChunkReader`, `open_batch`,
  `drain_window`, held lengths and no-wait batches included). P56 removed the
  wraps that were in front of both rungs; a `BufReader` is still not the fix for
  either, because the wrap is what would cost the `shadowsocks
  user-space-copies-per-byte-read 0` row its test already proves
  (`shadowsocks::tests::chunks_open_that_seal_sealed_and_reject_damage`).
- **`read_client_hello`** (`tls/reality.rs:380-432`) reads the 5-byte record
  header and then the body, and that is necessary: the record length is *in*
  the header and reading further would steal bytes from the next record.
- **The KCP arena copy** (`kcp/window.rs`, `push`) is load-bearing: a segment is
  retransmitted after the caller's buffer is gone.
