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
| `oracle` | test-name patterns over each enabled pin's suite | `conformance.yml`, `interop-baseline.yml` |
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
| `conformance.yml`'s `suites`, `interop-baseline.yml`'s `baseline` | `suites` | a pin whose suite holds no test in scope is skipped, and says so |
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

A method page moves its method's measurements and not the compiler: the page is
where the counts live, so `ops`, the matrix cell, the oracle names and the
reference packages for that method all run, while the three-runner workspace
build in `ci.yml` does not. `README.md` is not a page, so it moves nothing.

The `rows` column is the one that costs wall-clock: a valgrind run per row, so a
VMess change pays 1 measurement instead of 24. A narrow plan also *deepens* what
it keeps — the touched method's own cells run at the full tier's engine list and
repeats rather than the smoke pair, which is the point: the method that moved gets
measured against every reference, and the ones that did not are not measured at
all.

The same day's CI, measured from the step timings of the runs of five recent
pull requests, is what the gate is actually buying:

| job, on a change that touches one method | time it takes now | what it is doing |
| --- | --- | --- |
| `ops.yml` | 4 m 17 s build + count, 22 s for all 31 rows | one `cargo` build under `-C debuginfo=line-tables-only`, then one valgrind run per test |
| `conformance.yml` | 4 m 6 s | every test of every enabled suite, against `ferrox-app` |
| `interop-baseline.yml` | 5 m 0 s | the same suites, whole |
| `xray-baseline.yml` | 6 m 21 s | `go test ./...` over the pinned xray-core |
| `benchmark-matrix.yml` | 1 m 31 s per cell | the smoke cell, which is a **VLESS** cell on a VMess change |
| `foxy-relay.yml` | 2 m 48 s … 14 m, three runners | signs into a live account and moves 1 MB per carrier |
| `ci.yml`'s `test` | three runners, one workspace build each | the suite, on Linux, macOS and Windows |

So a VMess change used to pay for a whole reference tree's test suite, three
whole oracle suites, 24 valgrind runs, a live three-runner dial of a lane it does
not touch, and a VLESS benchmark. It now pays for one run, two reference
packages, two oracle tests, and the VMess cell against all five engines. A method
page pays that same measurement with no compiler at all — `ci.yml`'s three
runners are what it drops, since the counts on the page are what moved, not the
code they describe. Prose no page is about, `README.md` included, drops the
measurements too and leaves only the gates that read the declarations.

Not claimed: that this is a fixed factor. It is a function of how much of the
tree a change touches, and the honest summary is that a single-method change now
plans a fraction of the measurements while any change to shared code still plans
all of them.

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
