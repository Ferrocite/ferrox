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
`carrier-hysteria` names a test that only the `xray-rust-hysteria` pin has.
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
python3 scripts/ci-scope.py list scenarios         # matrix cell ids
python3 scripts/ci-scope.py check                  # refuse a drifted declaration
python3 scripts/ci-scope.py selftest               # the planner's own fixtures
```

A workflow's first step runs `scope` with the pull request's base commit and
publishes `wide`, `methods`, `cells`, `matrix`, `suites`, `go` and `ops` as job
outputs, which is what the later jobs gate their `if:` on. With no plan file —
locally, or on any run that skipped the step — every query answers **wide**, so
nothing can narrow by accident.

`scripts/check-ci-scope.sh` runs the fixtures and the declaration check, and is
one of the gates in `ci.yml`'s no-toolchain step and in `./scripts/check.sh`. It
fails when a scope path matches no file, when a file is claimed by two pages,
when a method in `scripts/method-ops.txt` has no page, when a `scenarios`
pattern matches no id in `scripts/lib-matrix.sh`, when an `oracle` pattern
matches no test in any enabled suite, and when a `go` package is not a directory
of the checked-out reference. Those are the five ways a scope declaration rots.

## What it saves

Read from the planner on 2026-10-14 with the commands above, against the tree at
the time of writing. `rows` is the `scripts/method-ops.txt` count, `oracle` the
test names kept out of each enabled pin's suite.

| changed file | wide | cells | ops rows | oracle names kept | go packages |
| --- | --- | --- | --- | --- | --- |
| `crates/ferrox-app/src/vmess.rs` | no | 1 | 2 of 31 | zeronet 2 | 2 |
| `crates/ferrox-app/src/ws.rs` | no | 2 | 4 of 31 | xray-rust 6, zeronet 4 | 1 |
| `crates/ferrox-core/src/record.rs` | no | 10 | 4 of 31 | zeronet 4 | 1 |
| `crates/ferrox-core/src/kcp/segment.rs` | no | 0 | 3 of 31 | none | 1 |
| `crates/ferrox-core/src/tls/reality.rs` | no | 0 | 0 of 31 | xray-rust 7 | 1 |
| `crates/ferrox-prompt/prompts.md` | no | 0 | 0 of 31 | none | 0 |
| `crates/ferrox-app/src/proxy.rs` | **yes** | tier default | 31 of 31 | xray-rust 24, hysteria 1, zeronet 9 | `./...` |

The `rows` column is the one that costs wall-clock: a valgrind run per row, so a
VMess change pays 2 measurements instead of 31. A narrow plan also *deepens*
what it keeps — the touched method's own cells run at the full tier's engine list
and repeats rather than the smoke pair, which is the point: the method that
moved gets measured against every reference, and the ones that did not are not
measured at all.

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
