# Benchmark matrix

Every cell measures one client engine against a fixed server engine on loopback.
The grid runs `ferrox` and `xray-core` as servers for every scenario they admit,
and `sing-box` as a third server in the standalone Hysteria v1 cell, where
`xray-core` reads v2 only, in the VLESS-over-QUIC cell, where `xray-core`
removed the transport at its pin, and in the WireGuard cells, whose pinned
endpoint carries both roles. Every client the scenario's protocol and carrier
admit is measured: `ferrox`, `xray-core`, `xray-core-rust`, `zeronet`,
`sing-box`, and in the standard and full tiers `xray-rust` and `leaf`.
`xray-core` is the reference wherever it participates; the standalone Hysteria
v1 cell has no `xray-core` control and is left to its ratio row. The pinned
`sing-box` serves every scenario except the `xhttp` and `kcp` carriers, VLESS
over `hysteria`, and the `vless-encryption-*` arms, which are omitted from its
cells rather than failed: it has no such transport and its VLESS has no
`encryption` field. Each remaining sing-box cell reads the same client outbound
translated by `scripts/xray-to-singbox.py`; the Hysteria v1 cell translates both
the standalone client and the server, which sing-box carries at its pin. At its
pin sing-box strips the X25519MLKEM768 key share from a REALITY handshake, which
xray-core's REALITY server requires, so `scripts/patch-sing-box.py` restores it
before the build and the cell measures the transport rather than a TLS refusal.
The nightly standard run also builds and runs sing-box, so the translated
client is exercised without a full dispatch.

`leaf` joins where its pin has the protocol and carrier: VMess, Trojan, legacy
Shadowsocks, and VLESS only with the Vision flow on raw TCP. It has no plain
VLESS, `xhttp`, KCP, gRPC, HTTPUpgrade, Hysteria, VLESS encryption, or
Shadowsocks 2022, and those cells name that in the bundle's skipped list.
`scripts/xray-to-leaf.py` writes its TLS, REALITY and WebSocket layers as chain
actors. `xray-rust` joins every standard and full cell its pin admits, except
VLESS over Hysteria: its Hysteria outbound speaks Hysteria's own proxy protocol,
not a transport that carries VLESS. `matrix_rust_client_config` removes the CA
file and verify certificate it rejects while keeping the certificate pin.

Each scenario that has both servers also runs the reference client against both,
so `scripts/check-matrix-legs.py` can say which leg lost: a ferrox client below
the xray-core client on the xray-core server is a client hole, and a ferrox
server below the xray-core server under the xray-core client is a server hole.
The standalone Hysteria v1 and VLESS-over-QUIC cells have no xray-core server
control — xray-core reads only v2 Hysteria and removed QUIC — so that check
leaves them to their ratio rows. The workload moves 128 MiB per flow, scaled down
from the bytes a profile needs so a
standard run finishes in minutes rather than hours; throughput, CPU and syscall
ratios are unchanged by the size.

The tables are generated from `matrix-results.json` and the charts from the same
cell bundles by `scripts/render-benchmark-charts.py`; CI commits the dated
results and the latest charts here and opens a review PR. Do not edit between
the markers by hand: a refresh replaces one runner block at a time.

Each bundle carries one image per test, never one image that merges every test:
the panel shows throughput, CPU per GiB, peak RSS, peak threads, cold start and
kernel asks per MiB from the same cell, so a reader never matches one test's
bar against another test's. The coverage grid is a markdown table, so a missing
cell and its reason survive both text review and the artifact browser. The
README block and the bundle's `README.md` are generated from the same
`matrix-results.json`. A scheduled refresh compares the new medians with the
last published run and leaves the committed markdown and charts alone when no
cell moved by more than 10%, the top of the shared runner's noise band.

## Known holes (2026-10-25, rechecked 2026-10-27, standard / ubuntu-latest)

These are the gaps this tree still measures. `scripts/check-matrix-legs.py`
reads the same list from `scripts/leg-gaps.txt`: a filed gap warns with its issue,
while a new leg or one worse than its filed ratio by more than 0.10 fails the
matrix. Remove a line only when a run proves the leg fixed, so the fix is a
visible gate rather than a quiet baseline; a closed issue can still cover an
open regression. The 2026-10-27 recheck of the vmess, hysteria and gRPC rows
is runs [40523513428](https://github.com/FerroxCo/ferrox/actions/runs/40523513428)
and [40527294332](https://github.com/FerroxCo/ferrox/actions/runs/40527294332).

| leg | cell | measurement | issue |
| --- | ---- | ----------- | ----- |
| both | `vless-hysteria-down-8`, `vless-hysteria-up-1`, `vless-hysteria-duplex-8` | down server 32.8 vs 109.6 MiB/s and 1.82x CPU; upload/duplex below the gate | [#670](https://github.com/FerroxCo/ferrox/issues/670) |
| server | `vless-tls-grpc-down-8` | one run moved 450.8 vs 167.0 MiB/s, another stopped at 64 MiB; [#702](https://github.com/FerroxCo/ferrox/issues/702) covers the dropped clients | [#669](https://github.com/FerroxCo/ferrox/issues/669) |
| server | `vless-reality-grpc-down-8` | 0.78x (121 vs 156 MiB/s) | [#468](https://github.com/FerroxCo/ferrox/issues/468) |
| both | `vless-reality-xhttp-down-8` | all engines 0 B on the ferrox server; ferrox client 0 B on xray-core | [#668](https://github.com/FerroxCo/ferrox/issues/668) |

The coverage holes with no number — a client that cannot use a ferrox server at all — are tracked in [#480](https://github.com/FerroxCo/ferrox/issues/480):
`shadowsocks2022-raw-down-8--srv-ferrox` drops xray-core-rust and zeronet, and
xray-core-rust reads 0 in hysteria and reality-grpc on both servers. The
remaining untested lanes, including UDP, more than 16 flows and carriers
without a cell, stay in #384, #387 and #388 rather than being inferred from
these rows. `sing-box` is absent from `vless-xhttp-down-8`,
`vless-reality-xhttp-down-8`, `vless-kcp-down-8`, `vless-hysteria-down-8` and
the three `vless-encryption-*` scenarios because its pinned dialect has no such
transport and no VLESS `encryption` field.

## Every standard configuration

The standard tier measures these 74 configurations: one row per scenario and server. The standalone Hysteria v1 and VLESS-over-QUIC rows run the ferrox and sing-box servers; the WireGuard rows run all three. The full tier adds the 16-flow cells (`vless-raw-down-16`, `vless-raw-duplex-16`, `vless-tls-raw-duplex-16`, `vless-ws-down-16`), the missing up/duplex lanes for every method that had only a down lane, plus `vmess-tls-raw`, the v1 up and duplex lanes, and the userspace and kernel WireGuard up and duplex lanes: 83 scenarios and 172 configurations. The full tier is dispatched manually on `ubuntu-latest`, `ubuntu-24.04-arm` and `macos-15`; `windows-latest` is available by `workflow_dispatch`, because 83 scenarios across four runners is more than one matrix job may hold. The nightly standard tier runs on `ubuntu-latest` only, because a ratio is read inside one cell and four runners were measuring the same ratio four times. The matrix never runs on a pull request.

| scenario | server | measured |
| --- | --- | --- |
| `vless-raw-down-1` | ferrox | yes |
| `vless-raw-down-1` | xray-core | yes |
| `vless-raw-down-8` | ferrox | yes |
| `vless-raw-down-8` | xray-core | yes |
| `vless-raw-up-1` | ferrox | yes |
| `vless-raw-up-1` | xray-core | yes |
| `vless-raw-duplex-8` | ferrox | yes |
| `vless-raw-duplex-8` | xray-core | yes |
| `vless-ws-down-8` | ferrox | yes |
| `vless-ws-down-8` | xray-core | yes |
| `vless-grpc-down-8` | ferrox | yes |
| `vless-grpc-down-8` | xray-core | yes |
| `vless-xhttp-down-8` | ferrox | yes |
| `vless-xhttp-down-8` | xray-core | yes |
| `vmess-raw-down-8` | ferrox | yes |
| `vmess-raw-down-8` | xray-core | yes |
| `trojan-raw-down-8` | ferrox | yes |
| `trojan-raw-down-8` | xray-core | yes |
| `shadowsocks-raw-down-8` | ferrox | yes |
| `shadowsocks-raw-down-8` | xray-core | yes |
| `vless-raw-setup-1k` | ferrox | yes |
| `vless-raw-setup-1k` | xray-core | yes |
| `vless-encryption-raw-down-8` | ferrox | yes |
| `vless-encryption-raw-down-8` | xray-core | yes |
| `vless-tls-raw-down-8` | ferrox | yes |
| `vless-tls-raw-down-8` | xray-core | yes |
| `vless-encryption-tls-raw-down-8` | ferrox | yes |
| `vless-encryption-tls-raw-down-8` | xray-core | yes |
| `vless-tls-raw-up-1` | ferrox | yes |
| `vless-tls-raw-up-1` | xray-core | yes |
| `vless-tls-raw-duplex-8` | ferrox | yes |
| `vless-tls-raw-duplex-8` | xray-core | yes |
| `vless-tls-ws-down-8` | ferrox | yes |
| `vless-tls-ws-down-8` | xray-core | yes |
| `trojan-tls-raw-down-8` | ferrox | yes |
| `trojan-tls-raw-down-8` | xray-core | yes |
| `vless-httpupgrade-down-8` | ferrox | yes |
| `vless-httpupgrade-down-8` | xray-core | yes |
| `vless-tls-grpc-down-8` | ferrox | yes |
| `vless-tls-grpc-down-8` | xray-core | yes |
| `vless-reality-raw-down-8` | ferrox | yes |
| `vless-reality-raw-down-8` | xray-core | yes |
| `vless-encryption-reality-raw-down-8` | ferrox | yes |
| `vless-encryption-reality-raw-down-8` | xray-core | yes |
| `vless-reality-grpc-down-8` | ferrox | yes |
| `vless-reality-grpc-down-8` | xray-core | yes |
| `vless-reality-xhttp-down-8` | ferrox | yes |
| `vless-reality-xhttp-down-8` | xray-core | yes |
| `vless-vision-tls-raw-down-8` | ferrox | yes |
| `vless-vision-tls-raw-down-8` | xray-core | yes |
| `vless-vision-reality-raw-down-8` | ferrox | yes |
| `vless-vision-reality-raw-down-8` | xray-core | yes |
| `vless-kcp-down-8` | ferrox | yes |
| `vless-kcp-down-8` | xray-core | yes |
| `vless-quic-down-8` | ferrox | yes |
| `vless-quic-down-8` | sing-box | yes |
| `vless-hysteria-down-8` | ferrox | yes |
| `vless-hysteria-down-8` | xray-core | yes |
| `hysteria-v1-down-8` | ferrox | yes |
| `hysteria-v1-down-8` | sing-box | yes |
| `wireguard-raw-down-8` | ferrox | yes |
| `wireguard-raw-down-8` | xray-core | yes |
| `wireguard-raw-down-8` | sing-box | yes |
| `wireguard-kernel-raw-down-8` | ferrox | yes |
| `wireguard-kernel-raw-down-8` | xray-core | yes |
| `wireguard-kernel-raw-down-8` | sing-box | yes |
| `masque-down-8` | ferrox | yes |
| `masque-down-8` | xray-core | yes |
| `shadowsocks2022-raw-down-8` | ferrox | yes |
| `shadowsocks2022-raw-down-8` | xray-core | yes |
| `vmess-tls-ws-down-8` | ferrox | yes |
| `vmess-tls-ws-down-8` | xray-core | yes |
| `trojan-tls-ws-down-8` | ferrox | yes |
| `trojan-tls-ws-down-8` | xray-core | yes |

## Not measured yet

These are the ways a config can name a method that no cell measures in the
standard tier. A row here is a known gap in the harness or a full-tier-only
lane, not a claim that the method works.

| method | carrier or security | direction | status |
| --- | --- | --- | --- |
| vless | raw with mux | down, up | no scenario; mux is read, not measured |
| vless | tls raw with mux | down, up | no scenario |
| vless | ws 16 flows | down | full tier only |
| vless | raw 16 flows | down, duplex | full tier only |
| vless | tls raw 16 flows | duplex | full tier only |
| vmess | plain ws | down, up, duplex | no scenario; only `vmess-tls-ws` exists |
| vmess | grpc, xhttp, httpupgrade, kcp, hysteria, reality | down | no scenario |
| trojan | grpc, xhttp, httpupgrade, kcp, hysteria, reality | down | no scenario |
| shadowsocks | tls, ws, grpc, xhttp, httpupgrade, kcp, hysteria | down | no scenario; raw up/duplex are full tier |
| shadowsocks2022 | tls, ws, grpc, xhttp, httpupgrade, kcp, hysteria | down | no scenario; raw up/duplex are full tier |
| httpupgrade | tls | down, up | no scenario; only `vless-httpupgrade` |
| hysteria | v1 | up, duplex | full tier only; the standard tier measures down, and the v1 byte and loopback gates are `carrier-hysteria.md` |
| any | udp dns through the socks front | request/response | no scenario |
| any | ipv6 target | down | no scenario |
| any | more than 16 flows | down | no scenario |

<!-- benchmark-matrix:start -->
<!-- benchmark-matrix:end -->
