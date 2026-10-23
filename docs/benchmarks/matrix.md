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

<!-- benchmark-matrix:start -->
<!-- benchmark-matrix:end -->
