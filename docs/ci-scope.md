# CI scope

Every expensive job in this repository measures against the pins in [`upstream/pins.toml`](../upstream/pins.toml), and running all of them for a change to one method spends the time on the methods that did not move. This is the mechanism that decides what a change actually owes.

## The rule

**A page declares what its method owes; a changed file decides when it is owed.**

[`docs/function/`](function) is the registry: one page per connection method, and each page carries a scope block between `
<!-- scope:begin -->` and `
<!-- scope:end -->`:

| key | what it is | who reads it |
| --- | --- | --- |
| `paths` | the source files that trigger this method | `scripts/ci-scope.py` classifies a diff with them |
| `symbols` | the names, in files no page owns, whose hunks are this method's | `scripts/ci-scope.py` attributes a shared file's hunks with them |
| `engines` | the comparators this method's matrix row is gated against | `scripts/ci-scope.py engines`; the matrix itself runs its tier whole |
| `scenarios` | substring patterns over the matrix ids in `scripts/lib-matrix.sh` | `scripts/ci-scope.py scenarios`; the matrix itself runs its tier whole |
| `oracle` | test-name patterns over each enabled pin's suite | `conformance.yml` narrows the suite to those names; `interop-baseline.yml` only decides whether the suite is reached, and runs a suite that stays whole |
| `go` | packages of the pinned reference that test this method | `xray-baseline.yml` |

`oracle` patterns may be bound to one suite with `pin=pattern`, which is how `carrier-hysteria` names a test that only the `xray-rust-hysteria` pin has. A pattern has to land on whole `_`-separated segments of a test name, the way `vmess` lands on `vmess_over_websocket_matches_the_oracle`: libtest's own filter is a bare substring, and a bare substring here would silently widen the scope — `ws` is inside `shadowsocks_over_raw_tcp` and inside `…_echo_flows_…`. The same matching reads an item name, so `vmess` claims `dial_vmess_rung` and `tls_vmess_out`. `paths: -` says the method has no file of its own — Trojan's header decode lives in the shared relay — so its page has to name the items it owns (`symbols`) or its source changes plan a wide run.

A changed path no page owns is **shared code**, and shared code owes everything — unless every hunk in it is provably one method's. `proxy.rs` carries every method's dial and serve rungs beside the relay helpers, so the planner reads the item each hunk sits in and asks which page claims that name:

```
crates/ferrox-app/src/proxy.rs::dial_vmess_rung  -> vmess.md claims `vmess`
crates/ferrox-app/src/proxy.rs::read_exact       -> no page claims it
crates/ferrox-app/src/proxy.rs::decode_request   -> no page claims it
```

A hunk whose item no page claims, a hunk that sits between two items, or a hunk at or above its item's own indentation keeps the plan wide; attribution may narrow on evidence, never skip a measurement. `decode_request` is the proof the refusal works: every inbound calls it, so a change there plans wide, and it should. `scripts/method-counts.txt` and `scripts/method-ops.txt` need no declaration — each row's first column already *is* the page name — and a blessed count in `scripts/expected-ops.txt` is claimed by the same `symbols` list that claims the function it measures.

`.github/**`, `upstream/**`, `scripts/**` outside those three data files, `Cargo.toml` and `Cargo.lock` are shared for the same reason as ever. `crates/ferrox-prompt/**` and `crates/ferrox-bench/**` are the two exceptions: they plan and measure, they ship no method code, so they owe the workspace build and its tests and nothing else.

## The plan

```bash
python3 scripts/ci-scope.py scope --base "$BASE"   # writes .ferrox/ci-scope.json
python3 scripts/ci-scope.py scope --wide           # a scheduled or manual run
python3 scripts/ci-scope.py rows                   # method-ops rows in scope
python3 scripts/ci-scope.py suite zeronet          # the pin's suite, narrowed
python3 scripts/ci-scope.py scenarios              # matrix cell ids
python3 scripts/ci-scope.py engines                # comparators the plan's cells need
python3 scripts/ci-scope.py go-packages            # reference packages in scope
python3 scripts/ci-scope.py check                  # refuse a drifted declaration
python3 scripts/ci-scope.py selftest               # the planner's own fixtures
```

A workflow's first job is a five-line `plan` job that runs `scope` with the pull request's base commit and publishes the flags as job outputs; the measuring job re-runs `scope` so the plan file exists in its own checkout, then reads its slice of it. With no plan file — locally, or on any run that skipped the step — every query answers **wide**, so nothing can narrow by accident. Every `scope` call also writes the plan into the run's step summary, so a reader sees what was skipped and why without opening a log.

| job | gate | what the gate means |
| --- | --- | --- |
| `ci.yml`'s `test` (three runners) | `rust` | a `.rs`, `Cargo.*` or tool-crate change: the compiler's own inputs moved. A wide plan that names none of them — a workflow file, a script — still skips it, because nothing a test reads changed; a schedule with no diff to read keeps the tests |
| `ops.yml`'s `counts` | `ops`, then `rust` for the exact-count step | the row list is the touched methods'; the blessed-count check only rebuilds when Rust moved |
| `conformance.yml`'s `suites`, `interop-baseline.yml`'s `baseline` | `suites` | a pin whose suite holds no test in scope is skipped, and says so; conformance then narrows the suite it keeps to those names, while the baseline runs a suite that stays whole |
| `xray-baseline.yml`'s `baseline` | `go` | only the reference packages that test the touched methods |
| `foxy-relay.yml`'s live lane | `wide`, or `methods` naming foxy or quic | the lane dials those carriers; a method it never dials does not owe three runners and real quota |

The benchmark matrix is not in this table: it runs on the nightly standard schedule and on manual dispatch, never on a pull request, so the plan does not choose its cells.

`engines` is only ever a reduction, and only the page may make it: VMess's page records that `sing-box` and `xray-rust` return nothing in its cell — an Xray-dialect config they do not read, and a pin that does not serve vmess — so a VMess plan names neither. `xray-core` cannot be dropped, because the harness refuses a comparison without the reference, and a page that declares no list owes every comparator. A wide plan always carries an empty list, so the nightly keeps the tier's whole set.

`scripts/check-ci-scope.sh` runs the fixtures and the declaration check, and is one of the gates in `ci.yml`'s no-toolchain step and in `./scripts/check.sh`. It fails when a scope path matches no file, when a file is claimed by two pages, when a method in `scripts/method-ops.txt` has no page, when a `scenarios` pattern matches no id in `scripts/lib-matrix.sh`, when an `oracle` pattern matches no test in any enabled suite, when a `go` package is not a directory of the checked-out reference, when a `symbols` pattern names no item in the shared files or is claimed by two pages, and when an `engines` name is not a comparator the matrix builds from a pinned rev. Those are the ways a scope declaration rots: each is a name CI gates on that no longer resolves to anything.

## What it saves

Read from the planner with the commands above. `ops rows` is the `scripts/method-ops.txt` count and the number of valgrind runs those rows group into — two rows measured by one test are one run. `oracle` is the test names kept in each enabled pin's suite. The last two rows are a narrow and a wide diff replayed through the planner: a method-local batch (`dial_vmess_rung`, `vmess_tls_carried`) narrows; a hunk in the shared `decode_request` plans wide.

| change | wide | builds and tests | cells | ops rows | oracle names kept | go packages | comparators |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `crates/ferrox-app/src/vmess.rs` | no | yes | 1 | 2 of 31, 1 run | zeronet 2 | 2 | xray-core, zeronet |
| `crates/ferrox-app/src/ws.rs` | no | yes | 2 | 4 of 31, 3 runs | zeronet 3, xray-rust 3 | 1 | tier default |
| `crates/ferrox-core/src/record.rs` | no | yes | 10 | 4 of 31, 3 runs | zeronet 4 | 1 | tier default |
| `crates/ferrox-core/src/kcp/segment.rs` | no | yes | 0 | 3 of 31, 3 runs | none | 1 | tier default |
| `crates/ferrox-core/src/tls/reality.rs` | no | yes | 0 | 0 of 31 | xray-rust 6 | 1 | tier default |
| `crates/ferrox-prompt/prompts.md` | no | yes | 0 | 0 of 31 | none | 0 | tier default |
| `docs/function/vmess.md` (any method page) | no | **no** | 1 | 2 of 31, 1 run | zeronet 2 | 2 | xray-core, zeronet |
| `README.md` | no | **no** | 0 | 0 of 31 | none | 0 | tier default |
| VMess's batch: `vmess.rs` + `proxy.rs` rungs + `method-counts.txt` + page | no | yes | 1 | 2 of 31, 1 run | zeronet 2 | 2 | xray-core, zeronet |
| VLESS header fold: `proxy.rs` in `decode_request` | **yes** | yes | tier default | 31 of 31, 24 runs | zeronet 9, xray-rust 23, hysteria 1 | `./...` | tier default |

`cells` and `comparators` are the planner's answers for a manual matrix dispatch; the nightly runs the whole tier, and a pull request's diff never chooses a cell. `crates/ferrox-app` and `crates/ferrox-core` are where every method's code lives, and the 19 files no page owns hold 1 272 items, 388 of which some page claims by name: those are the rungs and per-method helpers, and a hunk that lands in one of them is that method's change. The other 884 — `read_exact`, `decode_request`, the budgets, the JSON and failure layers, the wireguard tree — are shared, and a hunk in one of them plans wide by design. `check-ci-scope.sh` prints that split, and a `symbols` pattern that names none of it is a gate failure.

Two gates stack in front of any measurement. A workflow's own `on.pull_request.paths` decides whether it starts at all, and the plan then decides which of its jobs run. Of the jobs above only `ci.yml` and `ops.yml` start on `docs/**`, so a method page re-measures its method's ops rows and not the compiler: the oracle suites and the reference stay with the source changes their filters name, and with the scheduled wide run. The benchmark matrix never starts on a pull request; the nightly standard schedule runs its whole tier. The `oracle` and `go` columns are therefore what a change to that method's source file pays; `cells` and `comparators` are for a manual matrix dispatch. Editing `docs/function/vmess.md` and editing `crates/ferrox-app/src/vmess.rs` plan the same scope, and only the second one starts the workflows that measure it.

The `rows` column is the one that costs wall-clock: a valgrind run per row, so a VMess change pays one measurement instead of 24. The method that moved gets its own rows; the methods that did not move are not measured at all.

The two layers are worth keeping straight: a `docs/**` edit does not even start the comparing jobs, because their `paths:` filters name source; a source edit starts them all and the plan then decides what each measures. A VMess change used to pay for a whole reference tree's test suite, three whole oracle suites, 24 valgrind runs, a live three-runner dial of a lane it does not touch, and a VLESS benchmark; it now pays for one run, two reference packages, the tests of the one suite with a VMess oracle, and no live lane at all. The benchmark matrix is left to the nightly and manual dispatches.

Not claimed: that this is a fixed factor. It is a function of how much of the tree a change touches — a single-method change pays a fraction of the measurements, while any change to shared code still pays all of them.

One real effect of the deepening is worth keeping: `xray-baseline.yml`'s wide case is the pinned reference testing itself, so its answer is a property of the rev, the Go toolchain and never our diff — Go's own result cache holds it exactly. `scripts/run-xray-baseline.sh` therefore drops `-count=1` and clones the pin to one fixed path, because Go keys a cached verdict on the source paths that produced it and a `mktemp` tree rebuilds every package every run: cold the job re-executes all packages; warm it reads most from the cache. Go never caches a failing package, so a red at the pin still runs and still shows, and the report names per run how many verdicts it read from the cache.

## Adding a method

A new method page ships with its scope block, or its first source edit runs the whole comparison set. The steps:

1. write `docs/function/<method>.md` with its counts block (that is already the rule) and a scope block naming its `paths`;
2. name in `symbols` every item of a shared file that is the method's own — its rungs in `proxy.rs`, its resolver in `config.rs` — because a method whose code lives in the relay has only those names to be recognised by;
3. add its scenario ids to `scripts/lib-matrix.sh` and name them in `scenarios`;
4. add its rows to `scripts/method-ops.txt` under the same key as the page name;
5. name the reference packages that test it in `go`, and the oracle test names in `oracle`, once a pin has a suite that runs them;
6. run `./scripts/check-ci-scope.sh` — it refuses any name in that list that does not exist, including a `symbols` name no shared file holds and an item two pages both claim.

A page that declares no `oracle` and no `scenarios` is not a gap in CI so much as a statement that no pin measures it yet: those jobs skip it and say why, and the scheduled wide run still measures everything.
