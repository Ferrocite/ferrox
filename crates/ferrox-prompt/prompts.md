# Ferrox prompt library

Eighteen reusable templates. `ferrox-prompt` fills each one from the live matrix in `README.md` and the pins in `upstream/pins.toml`, so `next` names the concrete row to work on rather than a hand-transcribed idea. If the tool and these files disagree, the files are right — that is why `ferrox-prompt check` is a CI step and `tests/contract.rs` locks the properties below.

## Grammar

One `## P<n> · <title>` section per template, ids `1..=n` with no gaps. Required lines, `check` fails if one is missing:

| line | meaning |
| --- | --- |
| `**When to use:**` | the situation that calls for this slice |
| `**Status:**` | `todo`, `doing`, `done`, `blocked`; a template stays `todo` because it is a standing kind of work |
| `**Leverage:**` | 1-5, the advisor's ranking key |
| `**Effort:**` | `small`, `medium`, `large`; ties break to the smaller one |
| `**Gates:**` | semicolon-separated checks that must pass; wrap a command in backticks so it reads as one |
| `**Targets:**` | `open`, `implemented`, `all`, or `none` — which matrix rows the template draws from |

Optional: `**Depends on:**` (prompt ids), `**Touches:**` (paths; `+` prefix for one created), `**Random weight:**` (0-9, 0 excludes it from `--rotate`), `**Prompt protocol:**` (a rule that layers on top of the shared one). Only `**Status:**` is meant to be edited; the advisor records progress via `set-status`.

A body is the single fenced `text` block in the section — a second fenced block is an error, not a fallback. Seven blanks fill automatically; any other `{name}` the tool refuses to invent and prints the command to supply instead:

| blank | source |
| --- | --- |
| `{method}` | the chosen row's method name |
| `{index}` | its `#` in the matrix |
| `{section}` | the table letter (`A`..`M`) |
| `{state}` | its verdict cell, verbatim |
| `{page}` | its method page, or the page its slug suggests |
| `{target}` | its key — `{section}{index}` |
| `{references}` | the pins relevant to that row: the `always` set plus any whose `name` or `topics` keywords appear in the row's line |

`next` picks the first row of the template's target class the ledger (`.ferrox/slices.log`) has not served to *this* template, records it, and renders the body. Calling `next` again moves on. For `open` templates the candidates are ordered nearness-to-done: a row that already links a method page goes before a `planned` greenfield one, because finishing the missing half of something already on the wire is the cheapest parity win. `implemented` and `all` templates are offered in plain matrix order.

A row's verdict is read from its state cell alone: `implemented`, `in tree`, or `both roles` with no `planned`/`not carried`/`not parsed`/`refused` negation beside it. Everything else is open, including a half-role. Neighbouring columns never flip a verdict.

Add-ons are one line each: `**Add-on — <slug>:** <extra instruction>`. Paths under `upstream/<name>/` are pinned reading copies fetched by `scripts/fetch-upstream.sh`; they never appear in `**Touches:**` and are never committed. `{references}` is drawn per row from that pin file — every `always` pin, plus every pin the row's own line names or hits one of its `topics` keywords, so a QUIC row asks for quiche and an unrelated row does not, with the whole list as the fallback when nothing matches — which keeps "compare against the best implementation" reading the pins rather than a hand-kept sentence.

## Shared protocol

```text
You are working on Ferrox, a from-scratch proxy core. Two claims define it and both are checked: output is byte-identical to the implementation it replaces, and it is not slower at any measured length.

The bar is the best implementation, not a working one. References are the pins in `upstream/pins.toml`. Learn how each does the thing, find where it copies, branches, refills, or allocates needlessly, and write the smaller, faster, leaner thing that is bit-identical. Rewrite, do not copy — no upstream line or test enters this tree.

A claim is either checked by something that runs or it is not made. Never write one without naming its checker; if there is no such thing, say so in the same sentence. A count nobody has measured stays `UNBLESSED`, never quoted as a figure.

Local before every push: `./scripts/check.sh` runs fmt, clippy, doc, the policy checks, exact operation counts, and the workspace tests. Never local: anything connection-dependent — benchmarks, parity, upstream suites, Miri. Every contributor sits behind a VPN and a proxy, so a local dial measures a tunnel, not the reference. On a platform without valgrind the count gate is CI-only there; name that rather than skipping it silently.

Faster, safer, leaner, or it does not land. Counts prove; durations suggest. A copy or allocation claim is proved by pointer identity, not by reading the code: assert the returned slice's base lies inside the caller's buffer, that the buffer's own pointer does not move, and its capacity does not grow. A byte-level test cannot see a copy — the bytes are identical either way.

Do not trust an existing implementation, this tree's or a reference's — assume it leaves wins on the table, and hunt them. Try many ideas, including ones no template names, and keep only the ones a count proves faster; revert a measured regression and put its arithmetic on the page. One fewer proven operation is a win worth landing, and believing a breakthrough is findable is what makes you look.

Simpler with less code wins every tie at equal performance. No abstraction with one implementor, no second way of doing something, no debt left for a later slice. Unsafe only for a measured win; if the safe form ties, the safe form ships.

A change that alters the bytes on the wire to save a syscall is not an optimisation, and it does not land.

Before landing a rewrite, ask what the worst input does: the length that is not a multiple of the vector width, the window already full, the cursor this change moves. A rewrite that passed every test can still be a regression, and the arithmetic finds it without a benchmark.

Report tersely: what changed, what was measured with numbers, what is still open. A slice that fails is worth more than one reported done that quietly skipped half its gates. Fixes leave no trace — one line of comment per item at most, no TODO, no changelog.

Do not widen the slice. If the slice exposes a larger problem, add a template or an add-on to this file rather than fixing it here.
```

## P1 · Land an open method row

**When to use:** The matrix has a row the tree does not implement, and moving it from planned, refused, or one-role-only to shipped is the largest single step towards parity with the references.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Targets:** open
**Gates:** `cargo test --workspace --all-features`; CI: `conformance.yml`; CI: `bench.yml`; CI: `parity.yml`
**Random weight:** 8

```text
Implement {method} — matrix row {index} of table {section}, currently "{state}". Finish the whole row, both roles where the method has two. Read {references} first and take the best idea from each; do not transcribe. Prove byte-identity before speed, and where a reference has a suite with a seam to inject `ferrox-app`, run it unmodified in `conformance.yml`.
```

**Add-on — both-roles:** If the state cell concedes one role only, the missing role is the whole slice.
**Add-on — refused-by-name:** A config naming an unimplemented surface must still refuse with a reason until this slice makes it dial.

## P2 · Make a shipped method faster and leaner

**When to use:** A row is implemented — the standing hunt for maximum throughput and minimum CPU now applies to it.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: `ops.yml`; CI: `compare.yml`
**Random weight:** 9

```text
Move {method} — matrix row {index} of table {section}, state "{state}" — towards the best known implementation among {references}. Throughput and leanness at bit-identical output: fewer retired instructions, fewer copies, fewer branches. Think in eliminated work, not added code: factor the math, fuse passes that touch the buffer twice, hoist per-record dispatch, narrow a parse that re-checks what a caller already checked. Re-measure the exact instruction count with `scripts/count-ops.sh` and read the diff before blessing a number in `scripts/expected-ops.txt`.
```

**Add-on — worst-case:** Ask what the input that is not a multiple of the vector width, or the window already full, does before landing — the tests may pass and the arithmetic may not.
**Add-on — revert-what-lost:** A measured regression is reverted, and the arithmetic goes on the page.

## P3 · Take a shipped method's memory footprint down

**When to use:** A row is implemented and its steady-state allocations, buffers, or per-record copies still scale with traffic rather than with the connection.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: `ops.yml`
**Random weight:** 6

```text
For {method} — matrix row {index} of table {section} — remove work that is generated and thrown away: a per-record buffer that could be reused, a second copy of a payload already in the caller's buffer, a zero-fill before a read that overwrites every byte, a `Vec` that reallocates under steady traffic. Prove each removal by pointer identity, gate the allocation claim on `capacity()` held steady over a push/drain cycle, and name the pass that got worse if there is one.
```

**Add-on — pool-owner:** When one buffer is filled by one thread and drained by another, the pool lives in the object both touch; the parse order respects that single owner.

## P4 · Prove a shipped row bit-identical to the references

**When to use:** A row is implemented but its byte-identity is argued from the source rather than swept against the pinned copy — the check that must run before any speed claim on that row.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `parity.yml`; CI: `bench.yml`; `cargo test --workspace --all-features`
**Random weight:** 4

```text
For {method} — matrix row {index} of table {section} — replace the argument with a differential sweep against the pinned reference: every length and every offset the method can see, both sides of every group boundary where a vector rung could overrun. Keep the key or nonce material such that a permuted implementation cannot pass. Name both backends in every row of the report; if one build dispatches to scalar against the reference's vector path, say so.
```

**Add-on — forged-input:** A malformed or wrong-tag input must leave the buffer exactly as it found it; a sweep that only feeds valid input proves the happy path.

## P5 · Rewrite one parser or framer to the best form

**When to use:** The bytes of a method are right but the code that produces or reads them is not the smallest, cheapest thing the references imply.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** all
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `compare.yml`
**Random weight:** 5

```text
Read the parsing and framing for {method} — matrix row {index} of table {section} — against {references}, find where they copy, branch per field, or re-scan, and rewrite this tree's version to be bit-identical and cheaper. The output bytes do not move; the operation count goes down. Benchmark the parse and the check the same way — validating code has to be proven faster too.
```

**Add-on — seed-fuzz:** Feed untrusted bytes through every entry point on a seeded corpus and assert no panic.

## P6 · Bring a method page up to the four-number standard

**When to use:** A row's data path is real but its page under `docs/function` is missing, or states counts with no checker named.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** all
**Gates:** `./scripts/check.sh`; `bash scripts/check-method-docs.sh`; CI: `ci.yml`
**Random weight:** 3

```text
Write or bring up to standard {page} for {method} — matrix row {index} of table {section}, state "{state}". Every connection-method page carries the same four numbers — ops, syscalls, memory copies, time — each with the name of the thing that produces it, a `graph TD` of the data path, and what was removed against {references}. The numbers live in exactly one place, `scripts/method-counts.txt`; the page cites the manifest row and does not keep a second copy. Name what was not removed as openly as the wins.
```

## P7 · Wire a conformance seam for a shipped row

**When to use:** A method is implemented here and a pinned reference ships a suite for it, but nothing runs that suite against `ferrox-app`.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `conformance.yml`; `cargo test --workspace --all-features`
**Random weight:** 3

```text
Give matrix row {index} of table {section} — the implemented method {method} — a conformance leg: find the suite in {references} that exercises it, add or enable the `[sources.*]` seam in `upstream/pins.toml` that injects `ferrox-app`, and run that suite unmodified in `conformance.yml`. Prove the leg reached this binary — name the seam and the test count. Green here plus red there is not done; if no seam exists anywhere to inject through, say so plainly.
```

**Add-on — pin-honesty:** Any pins edit carries the real rev from a resolved ref; never fabricate one to satisfy a gate.

## P8 · Find the work the tree does and discards

**When to use:** The standing RAM/CPU hunt on a shipped row — where something is computed, filled, or locked and then thrown away or re-done before the value is ever used.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: `ops.yml`
**Random weight:** 5

```text
Audit the hot path of {method} — matrix row {index} of table {section} — for work done and discarded: a value generated then overwritten, a memset before a read that fills every byte, a lock taken twice for one wait, a buffer sized for the worst case on the common small one. For each finding, remove it or prove why it is load-bearing against the leanest shape in {references}. Before writing a test that reconstructs a quantity, look for the counter already lying around as state.
```

## P9 · Prove a vector rung on the ISA it compiles for

**When to use:** A SIMD or width-generic rung is in the tree and a CI runner whose architecture is named has not yet run the differential on it.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `bench.yml`; CI: `safety.yml`; `cargo test --workspace --all-features`
**Random weight:** 3

```text
For {method} — matrix row {index} of table {section} — confirm each width backend of its vector rung means what it claims on a runner whose architecture the job names: lane count, chunk-to-block layout, the store that writes consecutive output bytes with no transpose. The layout is the part worth reading twice — a backend that produces the right bytes through the wrong layout is right by accident, and the next change makes it wrong. Make the layout a named constant or an assertion, not a comment.
```

**Add-on — miri-boundary:** Miri interprets the safe-Rust ladder but not `core::arch` intrinsics; say which rungs Miri covered and which the differential covers instead.

## P10 · Prove the engine does less at a length nobody measured

**When to use:** A rung's counts are argued rather than blessed, or a length boundary has never been swept — turning an `UNBLESSED` claim into a number a runner reproduces.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `ops.yml`; CI: `bench.yml`; `./scripts/check.sh`
**Random weight:** 3

```text
For {method} — matrix row {index} of table {section} — measure the operation count of its hot symbol with `scripts/count-ops.sh` across every length and boundary the method reaches; read `scripts/method-ops.txt` for the CI number before deciding anything. Blessing a count means reading the diff that moved it and recording why, never pasting a figure to quiet the gate. Where the count is connection-dependent, it belongs to `ops.yml`, not to a laptop run.
```

## P11 · Make a test that loses to the runner fail on a defect

**When to use:** A test for a shipped row goes red one run in several and green otherwise — it is asserting a quantity the scheduler or the runner moves, not a property of the code.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`
**Random weight:** 4

```text
Take the flaky test on {method} — matrix row {index} of table {section} — and make it fail only on a defect. Drive the counted quantity from an in-memory stream that always answers the whole buffer, where the number is exact; over a real socket assert only the bytes. A loopback test cannot gate a syscall count and a scheduler-dependent count is not a gate at all — move the assertion to where it is deterministic and leave the socket test proving the wire.
```

**Add-on — replay:** Seed any corpus-dependent test so a red run prints the case that broke it and replays on any machine.

## P12 · Collapse a duplicated walk, ladder, or dispatch to one copy

**When to use:** The same config walk, header parse, ladder fork, or relay dispatch is written out in more than one file, and a change to one silently diverges from the others.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** all
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `compare.yml`
**Random weight:** 4

```text
Find where the bytes or dispatch of {method} — matrix row {index} of table {section} — are written more than once across the carrier and proxy files, and fold them into one copy with no new abstraction: the shared helper, not a trait for one implementer. The wire format and the operation count do not move; the line count and the divergence risk go down. Where a fork exists only because two paths disagree on one boundary, make them agree and delete the fork.
```

**Add-on — retire-dead:** A knob or code path with no consumer gets a caller in a test or is deleted — do not leave it named-but-unreachable.

## P13 · Bound a loop or handshake the socket currently ignores

**When to use:** A handshake, relay, or server drive can spin or block on a peer that goes silent — the hang is reachable in principle and no deadline stops it.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; CI: `safety.yml`
**Random weight:** 5

```text
Give {method} — matrix row {index} of table {section} — every wait a deadline the socket cannot ignore: bound the handshake, the relay read, and the server drive that spins on an idle peer. Test it by parking the peer and asserting the loop stops within the budget, not by sleeping and hoping. A budget a peer can exhaust must refuse cleanly, not truncate or silently drop what is in flight.
```

**Add-on — no-widening:** The deadline is the smallest fix; do not fold an unrelated timeout policy into the same slice.
**Add-on — deep-retry:** A carrier whose own reader loops on timeouts (gRPC, xHTTP, VMess, Shadowsocks handshakes) needs the budget inside that loop, not around it; record it as a row rather than bolting a wrapper on top.

## P14 · Put a layer where the references put it

**When to use:** A method's bytes are right but the security layer, framing, or session lives at a different depth than every pinned reference puts it, so the next row that reuses it cannot.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `parity.yml`
**Random weight:** 3

```text
Compare where {references} place the layer for {method} — matrix row {index} of table {section} — against where this tree places it, and move it to match if the references agree and this tree does not: the security layer outside the carrier, the session above the transport, the framer below the record. Same wire bytes, same operation count — a layering change that alters either is a method change and does not land. Prove the move by the byte-differential still passing and the seam a later row needs now existing.
```

## P15 · Give a non-matrix surface a working seam

**When to use:** Engine-adjacent capability the matrix does not carry a row for — the account plane, an upstream-proxy chain, TUN/VPN modes — that parses or is described but is not reachable from a config or a test.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Targets:** none
**Gates:** `cargo test --workspace --all-features`; CI: `conformance.yml`
**Random weight:** 2

```text
Take one engine-adjacent surface {references} carry that this tree names but cannot drive — the account plane, the upstream-proxy chain, or a TUN/VPN mode — and give it a working seam: wire it to a config path or a test entry point, name the reference it matches, and prove one round-trip in CI. If it genuinely cannot be reached from this tree's shape, say why plainly in the place a reader would expect the capability rather than leaving it silently half-described.
```

**Add-on — no-diary:** Land the capability and its page; do not record the change in the page as a changelog.

## P16 · Deep-optimization hunt: beat every reference, or prove the floor

**When to use:** The open-ended, high-effort pass on a shipped method — not the one clean win, but the hunt for an order-of-magnitude one, assuming the current implementation and every reference still leave the breakthrough undiscovered.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: `ops.yml`; CI: `compare.yml`; CI: `parity.yml`
**Random weight:** 9

```text
Make {method} — matrix row {index} of table {section} — faster, leaner and more functional than {references} put together, at bit-identical output. Assume the current form and every reference leave wins on the table; do not trust any of them. Generate many ideas — including ones this prompt does not name — try each, keep only what a count proves, and revert every measured regression with its arithmetic on the page. One fewer proven operation is a win worth landing, so push each winner to the end instead of stopping at the first.

Think like a math paper, not a patch: change the basis or the order, factor, recast the computation, and prove the new form equivalent before shipping it. Mine every lens — algebraic structure and hot inner loops; bit tricks and SIMD across every width the ladder runs; microarchitecture (cache locality, branch prediction, IPC); I/O (batching, zero-copy, vectored and kernel offloads, ring buffers, lock-free handoffs, segment offloads); outright elimination of ops, copies, allocations, syscalls, locks, atomics, branches, zeroing, checks and dead code nothing reads; and the method-specific tricks — codec tables and DFA walks, one's-complement folding where the modulus allows, varint and padding shapes, multiplexing, and the crypto primitives' hardware paths.

Prove the win or discard it: an exact instruction count from `scripts/count-ops.sh`, allocation and copy counts held by pointer identity, and the benchmark gate in CI. Re-measure the byte-differential before and after — bit-identical means the block, byte, counter and panic-threshold counts are unchanged, not only the output. Where the wire shape is fixed, say so and do not buy a syscall with a datagram boundary. Believe the breakthrough is findable and check every idea, even new ones specific to this task.
```

**Add-on — novel-idea:** An idea no template or lens named here is welcome; prove it the same way — a surprising win is still a win, and a named, measured loss is still evidence.
**Add-on — floor-proof:** If the hunt finds nothing above noise, prove the floor: record the ideas tried, each one's count, and what a reader should try next — an argued floor beats a quiet stop.
**Add-on — many-rounds:** Land one proven win per commit and keep hunting; a single diff that "optimized the method" is the end of one round, not the end of the slice.

## P17 · Hunt and fix the concurrency, timing and flakiness bugs

**When to use:** The engine has races, stalls and flaky tests — half-closed races, duplex deadlocks, timeouts that never fire, buffer-ownership races, tests that lose to the scheduler — and each one is a defect to find, prove, and fix one at a time.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; CI: `safety.yml`; CI: `conformance.yml`; CI: `bench.yml`
**Random weight:** 8

```text
Find a concurrency, timing or duplex defect in {method} — matrix row {index} of table {section} — and fix it: a half-closed race, a full-duplex stall, a timeout or deadline the socket can miss, a buffer-ownership or pool race, a wakeup lost behind a cursor, or a test that goes red one run in several. Fix them one at a time, and prove each one rather than guessing at it — a bug found by reading a symptom is a guess until a test reproduces it.

Reproduce first: land a test that is red on the defect before the fix, then green after, and keep the red case in the suite. Make the reproduction deterministic where the defect is deterministic; where a timing window is genuinely involved, drive it from an in-memory stream or a controllable clock rather than a real socket, because a loopback or scheduler-dependent assertion proves nothing. A flaky test is itself the defect's witness — pin what it actually observes.

Prove the fix under the tools that see these bugs: Miri in CI for the memory and aliasing races, the differential and byte tests for the wire staying identical, CI conformance and benches for the connections — never a local dial, since every contributor sits behind a VPN and a proxy and a local connection measures neither this code nor the reference. Do not change the bytes on the wire or a datagram boundary to paper over a race; fix the ordering or the ownership, and say which.
```

**Add-on — race-hunt:** Audit where one buffer is touched by two actors, where a cursor or counter can lag what a read consumed, and where a window can fill; name the invariant each guard holds.
**Add-on — half-close:** The close edge is the usual bug site — check who shuts which direction, what the peer sees, and whether a pending read can outlive its writer.
**Add-on — shared-close:** Where both directions of one relay tear down through a single shared `close` closure, no per-direction half-close is expressible and whichever thread finishes first aborts the sibling's still-open read; carry two directional closes per site, and where a carrier has no half-close primitive at all, name that limit rather than sweeping `Both` to `Write` blind.
**Add-on — withheld-answer:** A server may hold its handshake answer until it sees client payload — xray flushes its buffered response on the first downstream write, zeronet's `HeaderFirst::hold` waits for it outright — so a client that stops sending to wait deadlocks both ways; pump the upload leg during the answer wait and hand it back before the session relay. Where the answer read shares one session lock with its writer (TLS halves, mux, the UDP uplink) the leg has to yield that lock first, so record those arms as rows instead of bolting a pump onto a locked half.
**Add-on — de-flake:** A test failing under load but green alone is scheduler-dependent; move the assertion where it is exact and leave the socket test asserting only bytes.

## P18 · Give a decision the engine already implies its owner

**When to use:** The engine classifies failures, negotiates capabilities or probes alternatives somewhere, but no component acts on that knowledge — the recovery ladder, the climb or the probe is implied by the design and unwritten in the code.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `conformance.yml`
**Random weight:** 4

```text
{method} — matrix row {index} of table {section} — already implies a decision the engine does not own: which failure is worth retrying versus terminal, what it climbs or descends when one path stops answering, what it asks the peer before committing to a pooled or multiplexed shape, when a credential or pass latches rather than retries. Read how {references} make the same call, then give this one a named owner and a bounded policy: the taxonomy row that decides, the component that acts on it, the counter or deadline that bounds it.

Prove the decision, not the intent: a test that drives each failure kind and asserts the ladder takes the branch it names, and — where the policy depends on what the peer says — a test that answers differently and asserts the engine follows the answer. A probe that costs a round-trip on every flow is a count change; state what it costs and what it saves.
```

**Add-on — bounded-cost:** Name the worst case of the probe or retry — rounds, bytes, latency — and cap it, so recovery cannot become a stall.
**Add-on — one-owner:** One component decides and one acts; a policy consulted in two places diverges, so fold the second into the first.
