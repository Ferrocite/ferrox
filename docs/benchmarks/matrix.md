# Benchmark matrix

Every cell measures one client engine against a fixed server engine on loopback.
The grid runs both servers (`ferrox`, `xray-core`) for every scenario and every
client the scenario's protocol and carrier admit (`ferrox`, `xray-core`,
`xray-core-rust`, `zeronet`, `sing-box`). `xray-core` is always the reference; a
cell without it is not a comparison. `xray-rust` is left out while its pinned
release refuses the harness's non-loopback SOCKS listener. The pinned `sing-box`
serves every scenario except the `xhttp`, `kcp` and `hysteria` carriers, which
are omitted from its cells rather than failed. Each sing-box cell reads the same
client outbound translated by `scripts/xray-to-singbox.py`.

Each scenario also runs the reference client against both servers, so
`scripts/check-matrix-legs.py` can say which leg lost: a ferrox client below the
xray-core client on the xray-core server is a client hole, and a ferrox server
below the xray-core server under the xray-core client is a server hole. The same
control prices the server process itself: its CPU per GiB and peak threads,
sampled beside the client over the same bytes, are lower-is-better holes when
the ferrox server spends more than xray-core's. The workload moves 128 MiB per
flow, scaled down from the bytes a profile needs so a standard run finishes in
minutes rather than hours; throughput, CPU and syscall ratios are unchanged by
the size.

The tables are generated from `matrix-results.json` and the charts from the same
cell bundles by `scripts/render-benchmark-charts.py`; CI commits the dated
results and the latest charts here and opens a review PR. Do not edit between
the markers by hand: a refresh replaces one runner block at a time.

Each bundle carries one image per test, never one image that merges every test:
the panel shows the client's throughput, CPU per GiB, peak RSS, peak threads,
cold start and kernel asks per MiB from the same cell, so a reader never matches
one test's bar against another test's; the server's CPU and threads live in each
run's `server` object and the leg gate, never as a client bar. The coverage grid is a markdown table, so a missing
cell and its reason survive both text review and the artifact browser. The
README block and the bundle's `README.md` are generated from the same
`matrix-results.json`. A scheduled refresh compares the new medians with the
last published run and leaves the committed markdown and charts alone when no
cell moved by more than 10%, the top of the shared runner's noise band.

## Known holes (2026-10-25, standard / ubuntu-latest)

These are the gaps this tree still measures. `scripts/check-matrix-legs.py`
reads the same list from `scripts/leg-gaps.txt`: a filed gap warns with its issue,
while a new leg or one worse than its filed ratio by more than 0.10 fails the
matrix. Remove a line when its issue closes, so the fix is a visible gate rather
than a quiet baseline. The numbers come from the
`benchmark-matrix-standard-ubuntu-latest` bundle of run
[40032539826](https://github.com/FerroxCo/ferrox/actions/runs/40032539826).

| leg | cell | measurement | issue |
| --- | ---- | ----------- | ----- |
| both | `vless-hysteria-down-8` | ferrox server 4.9 vs 110.9 MiB/s (0.04x); ferrox client reads 0 against xray-core | [#466](https://github.com/FerroxCo/ferrox/issues/466) |
| server | `vless-tls-grpc-down-8` | 0.79x (118 vs 149 MiB/s) | [#467](https://github.com/FerroxCo/ferrox/issues/467) |
| server | `vless-reality-grpc-down-8` | 0.78x (121 vs 156 MiB/s) | [#468](https://github.com/FerroxCo/ferrox/issues/468) |
| server | `vmess-raw-down-8` | xray-core reads 0 after a 64 KiB write (broken pipe); ferrox, xray-core-rust and zeronet pass | [#470](https://github.com/FerroxCo/ferrox/issues/470) |
| both | `vless-reality-xhttp-down-8` | all engines 0 B on the ferrox server; ferrox client 0 B on xray-core | [#472](https://github.com/FerroxCo/ferrox/issues/472) |

The coverage holes with no number — a client that cannot use a ferrox server at all — are tracked in [#480](https://github.com/FerroxCo/ferrox/issues/480):
`shadowsocks2022-raw-down-8--srv-ferrox` drops xray-core-rust and zeronet, and
xray-core-rust reads 0 in hysteria and reality-grpc on both servers. The
remaining untested lanes, including UDP, more than 16 flows and carriers
without a cell, stay in #384, #387 and #388 rather than being inferred from
these rows. `sing-box` is absent from `vless-xhttp-down-8`,
`vless-reality-xhttp-down-8`, `vless-kcp-down-8` and `vless-hysteria-down-8`
because its pinned dialect has no such transport.

## Every standard configuration

The standard tier measures these 56 configurations: one row per scenario and server. The full tier adds the 16-flow cells (`vless-raw-down-16`, `vless-raw-duplex-16`, `vless-tls-raw-duplex-16`, `vless-ws-down-16`) and the missing up/duplex lanes for every method that had only a down lane, plus `vmess-tls-raw`, for 78 more: 134 in all. The full tier runs weekly on `ubuntu-latest`, `ubuntu-24.04-arm` and `macos-15`; `windows-latest` is available by `workflow_dispatch`, because 67 scenarios across four runners is more than one matrix job may hold. The nightly standard tier runs on `ubuntu-latest` only, because a ratio is read inside one cell and four runners were measuring the same ratio four times.

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
| `vless-tls-raw-down-8` | ferrox | yes |
| `vless-tls-raw-down-8` | xray-core | yes |
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
| `vless-hysteria-down-8` | ferrox | yes |
| `vless-hysteria-down-8` | xray-core | yes |
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
| vless | quic | down, up, duplex | no scenario; the config path exists, the harness does not |
| vless | tls over quic | down | no scenario |
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
| hysteria | v1 | down, up, duplex | no scenario; only v2 is measured |
| any | udp dns through the socks front | request/response | no scenario |
| any | ipv6 target | down | no scenario |
| any | more than 16 flows | down | no scenario |
| any | leaf and xray-rust as clients | down | engines pinned but not in the matrix |

<!-- benchmark-matrix:start -->
<!-- benchmark-matrix:end -->
