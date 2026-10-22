# AGENTS.md

Rules for working in this repository. The shared protocol in [`crates/ferrox-prompt/prompts.md`](crates/ferrox-prompt/prompts.md) is the source of truth and says the same things at more length; if this file and that one disagree, that one is right.

## What is checked locally, and what is never checked locally

The split is not negotiable.

| check | where |
| --- | --- |
| fmt, clippy, rustdoc | local, every push — `./scripts/check.sh` |
| policy checks: leak surface, dependency policy, comment trace, merge markers, fixture safety, windows paths, method docs, ci scope | local, every push |
| **exact operation counts** — `scripts/count-ops.sh` against `scripts/expected-ops.txt` | local, every push |
| prompt library — `cargo run -p ferrox-prompt -- check` | local, every push |
| `cargo test --workspace` | local, every push |
| benchmarks, ratios, comparisons (`bench.yml`, `parity.yml`, `compare.yml`, `speedtest.yml`, `benchmark-matrix.yml`) | **CI only** |
| per-method instruction counts (`ops.yml`, artefact `method-ops`) | **CI only** — informational, never red |
| upstream suites against `ferrox-app` (`conformance.yml`) | **CI only** |
| Miri (`safety.yml`) | **CI only** |

**Nothing connection-dependent runs on a contributor machine.** Every developer sits behind a VPN and a proxy, so a local benchmark measures a tunnel, a local conformance run measures somebody's exit node, and a local dial measures neither this code nor the reference. Push and read CI instead.

```bash
./scripts/check.sh    # everything above that is local, in one command
```

`scripts/count-ops.sh` needs `valgrind` (`apt-get install valgrind strace`, or `brew install valgrind`). Without it the gate fails — it does not skip. It does not exist on macOS/aarch64, so there the count gate is CI-only: name that and say why rather than skipping it silently. Counts go into `scripts/expected-ops.txt` only after reading the diff that moved them; never paste a measured number there to silence the gate.

## Reporting

Terse verdicts, never a history of the diff, always in this shape: what changed, what was measured with numbers, what is still open. A slice that fails is worth more than one reported done that quietly skipped half its gates. If a gate cannot be run, name it and say why, and do not call the slice complete.

## Rules that shape a change

- **The drop-in rule: xray-core is the floor, not the ceiling.** Anything a config xray runs must work here — same path resolution, same default, same verdict — and where xray has one way we may have two (a cert path resolves against the working directory *and* the executable's). Ship more, refuse less. A refusal or a silent no-op where xray acts is the bug, even when the missing feature is legitimately row-scoped: read the config, warn in one line, go somewhere. Never narrow a working way to match the reference, and prove the divergence by running the config — a message can blame the inbound while the cause is an unrecognised outbound name.
- A claim is either checked by something that runs or it is not made; never write one without naming its checker.
- **A method page ships with the method, or with the change to it.** Every page under `docs/function/` carries four counts — ops, syscalls, memory copies, time — a `graph TD` of the data path, and what was removed against the references. The numbers live in `scripts/method-counts.txt` only, and `scripts/check-method-docs.sh` fails when a page and that file disagree in either direction.
- **Prove a copy or allocation removal by pointer identity, not by reading the code.** Assert the returned slice's base lies inside the caller's buffer, that the buffer's own pointer does not move, and that its capacity does not grow. A byte-level test passes with the copy and without it, so it cannot witness the removal.
- **The named checker has to observe the thing the row claims.** Pointer identity sees copies and reallocations; a differential sweep sees bytes, not the operation count behind them. A row with no checker that can see it belongs in the page's prose, not as a number.
- **Gate an allocator claim on `capacity()` held steady over a push/drain cycle.** A per-call buffer cannot hold capacity steady, and a reclaim that stopped firing shows up as a number that only rises. Write the capacity assertion before the buffer.
- **Prefer a counter already lying around as state over a test that reconstructs it.** If a quantity is already snapshotted somewhere, its delta is the gate.
- **Audit the gate before the code.** A blessed count is a claim about what a test executes; before adding an optimisation, read the test the manifest row names and confirm it reaches the code the row describes. A never-observed row is worse than `UNBLESSED`, because it reads as a number.
- **A pool filled by one thread and drained by another has one owner**, and the parse order respects it — when parsing needs the pool and the pool needs the session, look up before parsing.
- **A loopback test cannot gate a syscall count, and a scheduler-dependent count is not a gate.** Drive the count from an in-memory stream that answers the whole buffer, where the number is exact; over a real socket assert only the bytes.
- **Changing a read's granularity is a count change** — it moves the syscall count and how often the caller's `Read::read` returns; both belong on the page.
- **Do the arithmetic on the input the tests do not reach.** Before landing a rewrite, ask what the worst case does — the length that is not a multiple of the vector width, the full window, the cursor or counter the change moves.
- **A rewrite that trades one pass for another says so, with both numbers.** Naming the pass that got worse is what keeps a removal from being a relocation.
- **Bit-identical means the block, byte, counter and panic-threshold counts are unchanged too**, not just the output; a rewrite that reaches the same bytes by a different route changed the method. The differential sweep is the gate, and a forged input must leave the buffer untouched.
- `UNBLESSED` is the value for a count nobody has measured — an open claim, not a figure, and never quoted as one. Read the `ops.yml` artefact before turning it into a number.
- **Name what was not removed.** A page that lists only wins is not evidence. A change that alters the bytes on the wire is not an optimisation, however many syscalls it saves.
- **Rebase onto `main` before trusting a long session**; `main` moves under a worktree, and a `git checkout <file>` to bisect can silently revert commits that landed meanwhile. Re-apply work as a patch so an overlap is a conflict, not a lost hunk.
- `scripts/new-worktree.sh` points every worktree at one shared `target-dir`, so a `cargo test` can pick up another worktree's rebuild. When a bisect points at something absurd, rerun it with a `CARGO_TARGET_DIR` of its own before believing it, and snapshot files before re-checking out.
- Rewrite, do not copy — no upstream line or test enters this tree; learn how the pinned implementations do it and write the smaller, cheaper thing.
- Faster, safer, leaner, or it does not land; counts prove, durations suggest.
- Simpler with less code wins every tie at equal performance; no abstraction with one implementor, no second way of doing something, no debt.
- Unsafe only for a measured win; if the safe form ties, the safe form ships.
- Fixes leave no trace: one line of comment per item at most, no TODOs, no changelogs (`scripts/check-comments.sh` fails them).
- Do not widen a slice. If it exposes a larger problem, tighten an existing prompt in `prompts.md` with a surgical edit of ten words at most; add no new template, add-on, or prompt.
- Checkouts under `upstream/` are for reading and never committed. Re-run `scripts/fetch-upstream.sh` whenever `upstream/pins.toml` changes under you.

## Roadmap

The roadmap is `crates/ferrox-prompt/prompts.md`: reusable templates, not one hand-written entry per idea. Each carries a status, a leverage, an effort, the gates that prove it finished, and a `**Targets:**` class. `next` fills a template's blanks from the live matrix in `README.md` and the pins in `upstream/pins.toml`, records the (template, row) pair in `.ferrox/slices.log`, and points the same template at the next outstanding row on the next call, so the loop walks the matrix toward completeness.

```bash
cargo run -p ferrox-prompt -- next        # the slice, the reason, prompt → clipboard
cargo run -p ferrox-prompt -- list        # roadmap progress and what is ready now
cargo run -p ferrox-prompt -- check       # is the library still coherent?
cargo run -p ferrox-prompt -- rows        # the matrix rows a slice can be about
```

A row can also be picked by hand: `render <id> --row A13` renders one template for one row, `next --row A13` lets the advisor choose the template that draws it, and a template refuses a row outside its own `**Targets:**` class rather than doing the wrong work.

Status is the only field to edit, and a slice is `done` when its gates are green, not when its diff looks finished.

A handout names the worktree its slice runs in and what to do about it: create it with `scripts/new-worktree.sh <slice>` when there is none, and when that script has already made one for this task, work there after bringing it onto `main`.
