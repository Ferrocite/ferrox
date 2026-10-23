# Benchmark matrix

Every cell measures one client engine against a fixed server engine on loopback.
The grid runs both servers (`ferrox`, `xray-core`) for every scenario and every
client the scenario's protocol and carrier admit (`ferrox`, `xray-core`,
`zeronet`, `xray-rust`). `xray-core` is always the reference; a cell without it
is not a comparison.

The tables are generated from `matrix-results.json` and the charts from the same
cell bundles by `scripts/render-benchmark-charts.py`; CI commits the dated
results and the latest charts here and opens a review PR. Do not edit between
the markers by hand: a refresh replaces one runner block at a time.

<!-- benchmark-matrix:start -->
<!-- benchmark-matrix:end -->
