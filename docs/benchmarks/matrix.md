# Benchmark matrix

Every cell measures one client engine against a fixed server engine on loopback.
The grid runs both servers (`ferrox`, `xray-core`) for every scenario and every
client the scenario's protocol and carrier admit (`ferrox`, `xray-core`,
`xray-core-rust`, `zeronet`). `xray-core` is always the reference; a cell
without it is not a comparison. `xray-rust` is left out while its pinned release
refuses the harness's non-loopback SOCKS listener.

Each scenario also runs the reference client against both servers, so
`scripts/check-matrix-legs.py` can say which leg lost: a ferrox client below the
xray-core client on the xray-core server is a client hole, and a ferrox server
below the xray-core server under the xray-core client is a server hole. The
workload moves 128 MiB per flow, scaled down from the bytes a profile needs so a
standard run finishes in minutes rather than hours; throughput, CPU and syscall
ratios are unchanged by the size.

The tables are generated from `matrix-results.json` and the charts from the same
cell bundles by `scripts/render-benchmark-charts.py`; CI commits the dated
results and the latest charts here and opens a review PR. Do not edit between
the markers by hand: a refresh replaces one runner block at a time.

Each bundle carries one throughput plot per test, never one plot that merges
every test: the comparison is only readable when each scenario has its own
axes. The coverage grid is a markdown table, so a missing cell and its reason
survive both text review and the artifact browser. The README block and the
bundle's `README.md` are generated from the same `matrix-results.json`.

## Known holes (2026-10-23, standard / ubuntu-latest)

These are the gaps this tree still measures. `scripts/check-matrix-legs.py`
reads the same list from `scripts/leg-gaps.txt`: a filed gap warns with its issue,
while a new leg or one worse than its filed ratio by more than 0.10 fails the
matrix. Remove a line when its issue closes, so the fix is a visible gate rather
than a quiet baseline. The numbers come from the
`benchmark-matrix-standard-ubuntu-latest` bundle of run
[40027235841](https://github.com/FerroxCo/ferrox/actions/runs/40027235841).

| leg | cell | measurement | issue |
| --- | ---- | ----------- | ----- |
| both | `vless-hysteria-down-8` | 0 MiB/s in both directions; xray-core server 111 MiB/s, ferrox server 5 MiB/s | [#466](https://github.com/FerroxCo/ferrox/issues/466) |
| server | `vless-tls-grpc-down-8` | 0.61x (114 vs 187 MiB/s) | [#467](https://github.com/FerroxCo/ferrox/issues/467) |
| server | `vless-reality-grpc-down-8` | 0.71-0.85x (130 vs 184 MiB/s in the second run) | [#468](https://github.com/FerroxCo/ferrox/issues/468) |
| server | `vmess-raw-down-8` | xray-core client reads 0 B; ferrox and xray-core-rust pass | [#470](https://github.com/FerroxCo/ferrox/issues/470) |
| server | `vmess-tls-ws-down-8`, `vless-tls-ws-down-8` | every vmess client reads 0 B; vless truncates at 117/134 MiB | [#471](https://github.com/FerroxCo/ferrox/issues/471) |
| both | `vless-reality-xhttp-down-8` | all engines 0 B on the ferrox server; ferrox client 0 B on xray-core | [#472](https://github.com/FerroxCo/ferrox/issues/472) |
| client | `vless-vision-reality-raw-down-8`, `vless-vision-tls-raw-down-8` | 67-117 of 134 MiB before EOF on both servers | [#473](https://github.com/FerroxCo/ferrox/issues/473) |
| both | `vless-kcp-down-8` | cell exits 134; xray-core KCP server never listens | [#474](https://github.com/FerroxCo/ferrox/issues/474) |

The remaining untested lanes, including UDP, more than 16 flows and carriers
without a cell, stay in #384, #387 and #388 rather than being inferred from
these rows.

<!-- benchmark-matrix:start -->
<!-- benchmark-matrix:end -->
