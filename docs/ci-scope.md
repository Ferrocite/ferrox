# CI scope

Every expensive job in this repository measures against the pins in
[`upstream/pins.toml`](../upstream/pins.toml), and running all of them for a
change to one method spends the time on the methods that did not move. This is
the mechanism that decides what a change actually owes.

## The rule

**A page declares what its method owes; a changed file decides when it is owed.**

[`docs/function/`](function) is the registry: one page per connection method, and
each page carries a scope block between `<!-- scope:begin -->` and
`<!-- scope:end -->`:

| key | what it is | who reads it |
| --- | --- | --- |
| `paths` | the source files that trigger this method | `scripts/ci-scope.py` classifies a diff with them |
| `scenarios` | substring patterns over the matrix ids in `scripts/lib-matrix.sh` | `benchmark-matrix.yml` |
| `oracle` | test-name patterns over each enabled pin's suite | `conformance.yml` narrows the suite to those names; `interop-baseline.yml` only decides whether the suite is reached, and runs a suite that stays whole |
| `go` | packages of the pinned reference that test this method | `xray-baseline.yml` |

`oracle` patterns may be bound to one suite with `pin=pattern`, which is how
`carrier-hysteria` names a test that only the `xray-rust-hysteria` pin has. A
pattern has to land on whole `_`-separated segments of a test name, the way
`vmess` lands on `vmess_over_websocket_matches_the_oracle`: libtest's own filter
is a bare substring, and a bare substring here would silently widen the scope —
`ws` is inside `shadowsocks_over_raw_tcp` and inside `…_echo_flows_…`.
`paths: -` says the method has no file of its own — Trojan's header decode lives
in the shared relay — so its source changes plan a wide run while its page still
declares what it owes.

A changed path no page owns is **shared code**, and shared code owes everything:
the plan goes wide and every job runs as it always did. `scripts/**`,
`.github/**`, `upstream/**`, `Cargo.toml` and `Cargo.lock` are shared for the
same reason. `crates/ferrox-prompt/**` and `crates/ferrox-bench/**` are the two
exceptions: they plan and measure, they ship no method code, so they owe the
workspace build and its tests and nothing else.

## The plan

```bash
python3 scripts/ci-scope.py scope --base "$BASE"   # writes .ferrox/ci-scope.json
python3 scripts/ci-scope.py scope --wide           # a scheduled or manual run
python3 scripts/ci-scope.py rows                   # method-ops rows in scope
python3 scripts/ci-scope.py suite zeronet          # the pin's suite, narrowed
python3 scripts/ci-scope.py scenarios              # matrix cell ids
python3 scripts/ci-scope.py go-packages            # reference packages in scope
python3 scripts/ci-scope.py check                  # refuse a drifted declaration
python3 scripts/ci-scope.py selftest               # the planner's own fixtures
```

A workflow's first job is a five-line `plan` job that runs `scope` with the pull
request's base commit and publishes the flags as job outputs; the measuring job
re-runs `scope` so the plan file exists in its own checkout, then reads its slice
of it. With no plan file — locally, or on any run that skipped the step — every
query answers **wide**, so nothing can narrow by accident. Every `scope` call
also writes the plan into the run's step summary, so a reader sees what was
skipped and why without opening a log.

| job | gate | what the gate means |
| --- | --- | --- |
| `ci.yml`'s `test` (three runners) | `rust` | no `.rs`, `Cargo.*` or tool change ⇒ the prose did not move the compiler |
| `ops.yml`'s `counts` | `ops`, then `rust` for the exact-count step | the row list is the touched methods'; the blessed-count check only rebuilds when Rust moved |
| `benchmark-matrix.yml`'s `fetch…collect` | `matrix` | a method the matrix does not measure has no cell to run |
| `conformance.yml`'s `suites`, `interop-baseline.yml`'s `baseline` | `suites` | a pin whose suite holds no test in scope is skipped, and says so; conformance then narrows the suite it keeps to those names, while the baseline runs a suite that stays whole |
| `xray-baseline.yml`'s `baseline` | `go` | only the reference packages that test the touched methods |
| `foxy-relay.yml`'s live lane | `wide`, or `methods` naming foxy or quic | the lane dials those carriers; a method it never dials does not owe three runners and real quota |

`scripts/check-ci-scope.sh` runs the fixtures and the declaration check, and is
one of the gates in `ci.yml`'s no-toolchain step and in `./scripts/check.sh`. It
fails when a scope path matches no file, when a file is claimed by two pages,
when a method in `scripts/method-ops.txt` has no page, when a `scenarios`
pattern matches no id in `scripts/lib-matrix.sh`, when an `oracle` pattern
matches no test in any enabled suite, and when a `go` package is not a directory
of the checked-out reference. Those are the five ways a scope declaration rots.

## What it saves

Read from the planner on 2026-10-14 with the commands above, against the tree at
the time of writing. `ops rows` is the `scripts/method-ops.txt` count and the
number of valgrind runs those rows group into — two rows measured by one test are
one run. `oracle` is the test names kept in each enabled pin's suite.

| changed file | wide | builds and tests | cells | ops rows | oracle names kept | go packages |
| --- | --- | --- | --- | --- | --- | --- |
| `crates/ferrox-app/src/vmess.rs` | no | yes | 1 | 2 of 31, 1 run | zeronet 2 | 2 |
| `crates/ferrox-app/src/ws.rs` | no | yes | 2 | 4 of 31, 3 runs | zeronet 3, xray-rust 3 | 1 |
| `crates/ferrox-core/src/record.rs` | no | yes | 10 | 4 of 31, 3 runs | zeronet 4 | 1 |
| `crates/ferrox-core/src/kcp/segment.rs` | no | yes | 0 | 3 of 31, 3 runs | none | 1 |
| `crates/ferrox-core/src/tls/reality.rs` | no | yes | 0 | 0 of 31 | xray-rust 6 | 1 |
| `crates/ferrox-prompt/prompts.md` | no | yes | 0 | 0 of 31 | none | 0 |
| `docs/function/vmess.md` (any method page) | no | **no** | 1 | 2 of 31, 1 run | zeronet 2 | 2 |
| `README.md` | no | **no** | 0 | 0 of 31 | none | 0 |
| `crates/ferrox-app/src/proxy.rs` | **yes** | yes | tier default | 31 of 31, 24 runs | zeronet 9, xray-rust 23, hysteria 1 | `./...` |

`cells` counts the matrix ids, and a narrow plan runs each of them at the full
tier — five engines, five repeats — instead of the smoke pair. `crates/ferrox-app`
and `crates/ferrox-core` are where every method's code lives, and the 18 source
files no page owns are the shared ones (`proxy.rs`, `config.rs`, `transport.rs`,
the wireguard tree, …), so they plan wide by design: `check-ci-scope.sh` prints
that list and fails when it changes shape.

Two gates stack in front of any measurement. A workflow's own
`on.pull_request.paths` decides whether it starts at all, and the plan then
decides which of its jobs run. Of the jobs above only `ci.yml` and `ops.yml`
start on `docs/**`, so a method page re-measures its method's ops rows and not
the compiler: the matrix, the oracle suites and the reference stay with the
source changes their filters name, and with the weekly wide run. The `cells`,
`oracle` and `go` columns are therefore what the planner answers *for the
method*, which is what a change to that method's source file pays — editing
`docs/function/vmess.md` and editing `crates/ferrox-app/src/vmess.rs` plan the
same scope, and only the second one starts the workflows that measure it.

The `rows` column is the one that costs wall-clock: a valgrind run per row, so a
VMess change pays 1 measurement instead of 24. A narrow plan also *deepens* what
it keeps — the touched method's own cells run at the full tier's engine list and
repeats rather than the smoke pair, which is the point: the method that moved gets
measured against every reference, and the ones that did not are not measured at
all.

The same day's CI, measured from the step timings of the runs of five recent
pull requests, is the left column below. The right column is the same change —
`crates/ferrox-app/src/vmess.rs`, one method's own file — measured on this
wiring's own runs, with the run id named so a reader can open it:

| job, on a change that touches one method | what it paid | what it pays now |
| --- | --- | --- |
| `ops.yml` | 4 m 17 s build + 22 s of valgrind over 31 rows in 24 runs | 4 m 8 s total: the same one build, 2 of 31 rows in **1** run, report step 1 s — run 38658878715 |
| `conformance.yml` | 4 m 6 s, every test of every enabled suite against `ferrox-app` | 2 m 41 s: zeronet at `running 2 tests … 17 filtered out`, both xray-rust pins out of scope — run 38658878645 |
| `interop-baseline.yml` | 5 m 0 s, every suite whole | 2 m 19 s: one suite whole (19 tests), the two pins it does not reach skipped — run 38658878627 |
| `xray-baseline.yml` | 6 m 21 s, `go test ./...` over the pinned xray-core | 47 s: `go test ./common/crypto/... ./proxy/vmess/...`, 4 packages, all green — run 38658878637 |
| `benchmark-matrix.yml` | 1 m 31 s per cell, and the smoke pair's cells are **VLESS** cells on a VMess change | one `vmess-raw-down-8` cell at the full tier: five engines, five repeats — run 38658878689, and it is **red**, which is the discovery this row exists to make |
| `foxy-relay.yml` | 2 m 48 s … 14 m on three runners, plus real quota | 6 s: the plan answers, the live lane job is skipped — run 38658878623 |
| `ci.yml`'s `test` | three runners, one workspace build each | still three runners: `.rs` moved. On a page or `README.md` edit the job is skipped outright — run 38658518128 |

The two layers of that table are worth keeping straight. A `docs/**` edit does
not even start the comparing jobs, because their `paths:` filters name source; a
source edit starts them all and the plan then decides what each one measures. So
a VMess change used to pay for a whole reference tree's test suite, three
whole oracle suites, 24 valgrind runs, a live three-runner dial of a lane it does
not touch, and a VLESS benchmark. It now pays for one run, two reference
packages, the tests of the one suite that has a VMess oracle, its own cell at
every engine, and no live lane at all.

What that VMess cell came back with is the reason to run it: 2 663 ms of CPU per
GiB against xray-core's 2 422 ms over the same 8 GiB on 8 flows, a ~10% gap the
harness resolves as its own regression gate (interval `[0.907x, 0.917x]` over
five pairs), at 7.5x lower peak RSS and equal throughput — run 38658878689,
artefact `matrix-cell-ubuntu-latest-vmess-raw-down-8`. Two of the five engines
return nothing there at all: `sing-box` because the matrix's per-cell config is
an Xray-dialect document and sing-box reads SingBox, and `xray-rust` because it
does not serve vmess at its pin. None of this was reachable from a pull request
before, because a VMess change ran a VLESS smoke cell.

Not claimed: that this is a fixed factor. It is a function of how much of the
tree a change touches, and the honest summary is that a single-method change now
pays a fraction of the measurements while any change to shared code still pays
all of them — which is what run 38657406765 and its siblings, the wide plan of
this wiring's own pull request, are the evidence for: every job ran, and every
one passed.

One row of that table is not a saving, and naming it is the point: `ops.yml`'s
build is the floor on any change that moves code, and its two VMess rows read
`Ir=inlined-not-a-frame` in the artefact of run 38658878715 — the test ran, the
profile held no frame for either symbol, so those two blessed counts are not
being observed at all. That is a gap in the gate, not in the scope planner, and
it is the next thing to fix.

## Adding a method

A new method page ships with its scope block, or its first source edit runs the
whole comparison set. The steps:

1. write `docs/function/<method>.md` with its counts block (that is already the
   rule) and a scope block naming its `paths`;
2. add its scenario ids to `scripts/lib-matrix.sh` and name them in `scenarios`;
3. add its rows to `scripts/method-ops.txt` under the same key as the page name;
4. name the reference packages that test it in `go`, and the oracle test names in
   `oracle`, once a pin has a suite that runs them;
5. run `./scripts/check-ci-scope.sh` — it refuses any name in that list that does
   not exist.

A page that declares no `oracle` and no `scenarios` is not a gap in CI so much as
a statement that no pin measures it yet: those jobs skip it and say why, and the
scheduled wide run still measures everything.
