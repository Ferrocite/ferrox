# The record layer: one ChaCha20 ladder, one Poly1305, one AES-GCM

Every AEAD method in this tree ends here. Shadowsocks, VMess and XTLS Vision
never touch a cipher primitive of their own; they call
`record::fill_exact` and `record::fill_exact_with_head`, and the only thing
above this rung that knows a block is 64 bytes long is `ferrox-bench`.

The shape that makes it cheap is that there is exactly one ladder round
function, written once, generic over a `Lanes` trait. `portable::U4` (four
`u32`), `sse2::S4`, `neon::N4` and `avx2::A8` implement it, so a ladder backend
cannot disagree with another about the algorithm — it can only be slower. The
portable backend is safe Rust, which is what lets Miri interpret the ladder at
all; the SIMD backends are five instructions each whose only failure mode is a
wrong answer, and a wrong answer is caught by a differential test before any
timing runs. Above the ladder sit the passes — `chacha::soa` on `aarch64` and
`chacha::wide` over `chacha::avx512` on `x86_64` — and those are one body over a
wider trait rather than one body over a wider register, for the reason the
section below counts out.

Above 512 bytes on aarch64 a fifth implementation takes over, `chacha::soa`: it
gives a register one *word* of eight blocks instead of one row of one block, so
a diagonal round is a rename of the row registers where `neon::N4` needs six
`vext` per double round per block — and the permute pipe is the floor this core
has. The four registers of a row transpose once at the store instead, which is
the layout `x/crypto`'s arm64 assembly keeps. Two sets of four blocks, not one:
a half round ends in a barrier, because all four diagonal quarter rounds read
what all four column quarter rounds wrote, so a four-block pass has four chains
across that barrier and nothing to issue while they are in flight. The
four-block form measured exactly that — in gate 3 of `bench.yml` runs
`37720316104` and `37723102887` its ratio against the pinned `chacha20` crate
went 1.50x to 1.98x on the linux aarch64 runner and 2.96x to 2.08x on the macos
aarch64 one, a kernel bound by its own dependency chains rather than by its op
count. Sharing the sixteen broadcasts and the base between two sets puts
sixteen quarter rounds and eight chains in a double round, which is the ladder's
shape, at the register cost the ladder already pays for its eight blocks. Its
only *checked* claim is equality: `chacha::soa` is timed nowhere until it has
produced the same keystream as the ladder, which
`chacha::soa::tests::the_eight_block_pass_is_the_ladder_at_every_length` asserts
byte for byte at every length to 1032 bytes and at four start counters, head and
headless, and gate 1 asserts the same bytes against the pinned `chacha20` crate
before gate 3 times anything.

From 1024 bytes on `x86_64` — 960 when the buffer carries a head, since the head
is one of the pass's own blocks — and when the machine has both `avx512f` and
`avx2`, one more pass takes over before that one: `chacha::wide`, the
sixteen-block pass, instantiated over `__m512i` in `chacha::avx512`. It exists
for two reasons that are counts and not tastes. The first is the register file.

```bash
CARGO_TARGET_DIR=/tmp/xtarget cargo rustc --release --target x86_64-apple-darwin \
  -p ferrox-core --lib -- --emit=asm -C debuginfo=0
# then read the round loop of `ferrox_core6chacha6avx210xor_blocks`
# and of `ferrox_core6chacha6avx51210xor_blocks`: `decl`/`jne` close each.
```

The AVX2 pass's round loop body is **143 instructions a double round for eight
blocks**: 128 operations, thirteen `vmovdqa` to and from the frame, and the
loop's own two. Sixteen live state words fill a sixteen-register file, so the
temporaries a rotate by twelve and a rotate by seven need come out of memory;
`avx512f` has thirty-two registers and `vprold`, which makes all four rotations
one instruction. Its loop body is **98 instructions for sixteen blocks**: 96
operations and the loop's two, with no stack operand anywhere inside it. Per byte
of keystream the rounds cost 2.79 instructions against 0.96, and that is the
number the pass below 1024 bytes is measured against. The transpose is the other
half of the trade and it also comes out ahead: sixty-four gathers for sixteen
blocks, four a block, against the forty-eight the AVX2 pass's four 12-instruction
transposes spend on eight — six a block for the same permutation, because a
gather can move a 32-bit element across the whole register where an unpack
network moves 128-bit lanes twice.

Those instructions are the assembler's and not the clock's, which is why they
can be counted for a target this machine cannot run. The equality cannot: the
pass is instantiated a second time over sixteen `u32` in the same module, and
`chacha::wide::tests::the_portable_pass_is_the_ladder_at_every_length` holds that
instantiation to `portable::U4` at every length to 2072 bytes, four start
counters, head and headless — the counter lanes, the diagonal, the index network
and the head, all of it on the machine reading this. What is left to a machine
with AVX-512 is the one instruction that applies the index network, and
`chacha::avx512::tests::the_sixteen_block_pass_is_the_ladder_at_every_length` is
that check on the two `x86_64` runners of `bench.yml` — both of which report
`avx512f` in the machine line of every run quoted under `## Time` — and in the
`x86_64` job of `ci.yml`, which runs the same test. A machine without `avx512f`
neither reaches the code nor runs the test, and the report says which one it is:
`ferrox_core::chacha_backend()` names the pass the dispatch found.

`fill_exact_with_head` is the interesting entry point. ChaCha20-Poly1305 needs
block 0 as the Poly1305 one-time key and blocks 1.. as the payload keystream,
and a naive seal generates block 0, throws away 32 of its bytes, generates
blocks 1.. separately, and pays for the 32 unused bytes. The head form takes
the first 32 bytes of block 0 out of the same group of states that computes
blocks 1.., so the fused seal generates `ceil(len / 64) + 1` blocks and
discards nothing.

## Data path

```mermaid
graph TD
    A["fill_exact_with_head, len bytes"] --> B["base_state: constants,<br/>key, nonce, counter 0"]
    B --> Z0{"x86_64 with avx512f, and 1024 bytes or more?"}
    Z0 -- yes --> Z["16 broadcasts, one word per register,<br/>the sixteen blocks in the lanes"]
    Z --> ZT["10 double rounds over all sixteen,<br/>the diagonal is a register rename"]
    ZT --> ZU["add the base back, then four index stages:<br/>each swaps one bit of the register name<br/>with one bit of the lane"]
    ZU --> ZV["xor a whole block at a time<br/>into the caller's buffer,<br/>sixteen blocks a pass"]
    ZV --> ZW{"another whole pass?"}
    ZW -- yes --> Z
    ZW -- no --> C{"a wide target, and 512 bytes or more?"}
    Z0 -- no --> C
    C -- yes --> S["16 broadcasts, one word per register:<br/>aarch64 keeps two sets of four,<br/>x86_64 one set of eight, the blocks in the lanes"]
    S --> T["10 double rounds over every set,<br/>the diagonal is a register rename"]
    T --> U["add the base back,<br/>transpose one row of eight blocks"]
    U --> V["xor into the caller's buffer,<br/>eight blocks a pass"]
    V --> W{"a whole pass left?"}
    W -- yes --> S
    C -- no --> D["counters: NST states, each holding<br/>CHUNKS consecutive block counters"]
    D --> E["10 double rounds,<br/>quarter round then diagonalise"]
    E --> F["state + base, 16 bytes per chunk"]
    F --> G{"more than a group left?"}
    G -- yes --> D
    W -- no --> H
    G -- no --> H["one group sized to the blocks left,<br/>the last stored partial,<br/>the single-block path for what the clamp cannot cover"]
    H --> I(("buffer, in place, nothing discarded"))
    J["decrypt_in_place, len bytes"] --> K["poly_key: block 0 only,<br/>32 bytes, no body"]
    K --> L["Poly1305 over the ciphertext<br/>pad_to_block per section"]
    L --> M{"tag matches?"}
    M -- no --> N(("caller's buffer,<br/>still ciphertext, no keystream written"))
    M -- yes --> O["fill_exact from block 1,<br/>into the caller's buffer"]
    O --> P(("plaintext, in place,<br/>no staging buffer"))
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| discarded-keystream-blocks | 0 | ferrox-bench-gate-2 |
| allocations-per-fill | 0 | ferrox-bench-gate-2 |
| zero-filled-bytes-per-fill | 0 | ferrox-bench-gate-2 |
| blocks-per-byte | 1/64 | ferrox-bench-gate-2 |
| blocks-per-iteration | 8 | ferrox-core-chacha::backend |
| blocks-per-iteration-on-avx512 | 16 | ferrox-core-chacha::backend |
| fused-head-blocks | 1 | ferrox-core-record::tests::the_head_is_the_references_own_first_block_and_the_rest_is_unshifted |
| backends-a-differential-test-cannot-lie-to | 6 | ferrox-bench-gate-1 |
<!-- counts:end -->

## Ops

```bash
./scripts/count-ops.sh report \
  record::tests::the_head_is_the_references_own_first_block_and_the_rest_is_unshifted \
  'ferrox_core::record::fill_exact'
```

`UNBLESSED`, as above: no measured instruction count is quoted for this rung.

### What is counted here, and what is only argued

The table above is the gated half of this page. Four of the removals just
described — the staging buffer, the two keystream passes, the second
`update` per padded section, and the empty absorbs — are **counts with no
counter behind them**. Nothing in this tree counts ChaCha blocks per open,
stack bytes staged, `update` calls, or `absorb` invocations, and
`ferrox-bench`'s counting allocator would not see a stack `[u8; 64]` even if
it were extended to measure the open: `count::measure` hooks `alloc` and
`alloc_zeroed`, and the staging buffer is on the stack. So those four are
argued from the source at the line named beside each one, and what *is* gated
is that they are bit-identical — `every_decrypt_matches_the_crate_it_replaces`
opens 6 000+ cases against the pinned `chacha20poly1305` crate and requires the
same plaintext, and requires a forged tag to leave the buffer encrypted.

A number nobody can produce is not a number, so those four are not in the table.
If they are ever to be gated rather than argued, the honest instrument is a
block counter on the ladder that `count-ops` reads, not an allocation counter:
that is the same gap P41 and P25 are named for.

Two more removals belong beside them, argued and not counted, because the
instrument that would count them is `count-ops.sh` — which needs `valgrind`,
which does not exist on this `aarch64` machine at all — and a callgrind reading
is the only number that would mean anything here.

- **The 32 bytes of keystream the Poly1305 one-time key never used.**
  `poly_key` used to fill sixty-four bytes, take thirty-two and drop the rest:
  the same block is generated either way, so what went was the second half's
  store and a thirty-two-byte copy, plus the buffer itself. It now asks
  `fill_exact` for thirty-two bytes and the store loop writes two rows instead
  of four. The five backends agree that the first thirty-two bytes of block
  zero do not depend on the buffer length, and the two 5 000/6 000-case sweeps
  in `aead::tests` would fail on the first case if they did not.
- **A `base_state` rebuilt on the way to the tail, on `x86_64` only.** The AVX2
  pass loop breaks on less than a pass, and a pass is the group loop's own
  budget of 512 bytes, so what it hands to `xor_ladder` can never reach that
  loop's body: the ladder was being called for the state it rebuilt, twelve
  loads and a sixty-four-byte store per fill. It now builds the rows once and
  calls `xor_tail` directly, the shape `chacha/soa.rs` has always had.
  `chacha::avx2::tests::the_eight_block_pass_is_the_ladder_at_every_length`
  reads the pass against that same ladder at every length to 1032 bytes across
  four start counters, so a one-block or one-counter divergence fails it.
  `aarch64` never had the second `base_state`, and this change does not touch
  it — so the row it would move is an `x86_64` row, and on `aarch64` the
  diff is empty.

## Time

Measured in `bench.yml` run `37728743550`, which carries the pass (`66c704e`
over `89f9714`), against the same rows in run `37720316104`, which carried the
ladder alone (`4bb63c5`). Gate 3 times this rung against the pinned `chacha20`
0.9 crate at 235 lengths from 65 to 65 537, interleaved best of five per side,
and re-measures any length under 0.95x before the job can fail on it; gate 1
runs the differential identity check first, so a backend that is fast because
it is wrong cannot pass.

| bytes | linux aarch64, ladder | linux aarch64, pass | macos aarch64, ladder | macos aarch64, pass |
| ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 1.49x | 1.66x | 3.19x | 3.12x |
| 4 KiB | 1.50x | 1.69x | 2.96x | 3.13x |
| 16 KiB | 1.50x | 1.70x | 2.95x | 3.19x |
| 64 KiB | 1.50x | 1.70x | 2.98x | 3.25x |

Both runs measured their own reference in the same process, so the ratios
compare, but they are different runner instances. Lengths below 512 bytes
compile to the same ladder in both runs, and those 203 rows are this
comparison's noise floor: 0.94x to 1.01x on linux aarch64, 0.61x to 1.30x on
macos aarch64. Against that floor, the 32 measured lengths at or above 512
bytes — the ones the pass handles — run 1.04x to 1.14x, median 1.11x, on linux
aarch64, every one of them above it, and 0.92x to 1.42x, median 1.05x, on macos
aarch64, where the three rows under 1.0x (769, 1024 and 2047 bytes) move less
than the noise beside them does.

Gate 7b's halves are printed and not gated, and at these sizes they are the
weaker instrument: on macos aarch64 its 16 KiB keystream row read 9356 ns for
the pass against 9041 ns for the ladder, while gate 3 read the pass 1.08x faster
at the same length. The self-timed row has no reference to cancel a drifting
runner, so the claim here rests on gate 3.

`c8e19b4` then sized the ladder's last group to every block a buffer has left
rather than leaving one over for the single-block path, and `701298f` made the
calibration time the chain that one block pays for. The pair is measured in
`bench.yml` run `37737912879` against run `37730127644`, which carried the pass
at `d31ddae`, and the lengths it moves are the ones whose remainder is exactly a
group: on `aarch64` that is any length of the form `k × 512 + 449..511`, where
eight states in one group replace seven states and a whole dependent round
chain. Four of the 235 timed lengths sit in that window — 449, 511, 1023 and
1535 — and all four are most of what separates the two runs on linux aarch64,
0.08x of ratio being this pair's noise floor there. The macos rows move further
because its small lengths are the noisier ones, so its four are quoted beside
them rather than claimed:

| bytes | linux aarch64, before | linux aarch64, after | macos aarch64, before | macos aarch64, after |
| ---: | ---: | ---: | ---: | ---: |
| 449 | 1.29x (640 ns) | 1.54x (539 ns) | 1.71x (445 ns) | 2.91x (280 ns) |
| 511 | 1.30x (646 ns) | 1.53x (545 ns) | 1.84x (415 ns) | 2.91x (282 ns) |
| 1023 | 1.44x (1 146 ns) | 1.60x (1 042 ns) | 2.33x (655 ns) | 2.97x (549 ns) |
| 1535 | 1.52x (1 632 ns) | 1.62x (1 528 ns) | 2.55x (893 ns) | 3.01x (810 ns) |

Run `37740838172` repeats those two rows on the same two runners — 449 bytes
reads 1.53x (543 ns) on linux aarch64 and 2.93x (274 ns) on macos aarch64 — so
the change is the tail and not the run.

`d207fe2` then answered the same question on `x86_64`, where a group of four
`A8` states spills and the split groups are what fit, and it lowered
`TAIL_STATES` on every arch — which took `aarch64` back to the shape `c8e19b4`
had just measured away: seven states and a dependent round chain for the one to
three blocks a remainder of 449 to 511 leaves over. The `aarch64` runner was
never re-read for that.

`TAIL_STATES` is per-arch now — the group itself on `aarch64`, one fewer
elsewhere. The two runs that name the difference are `bench.yml` run
`37981057929` (main at `c54fae6`, the clamp at seven) against run `37976368393`
(this branch), each `ferrox` column read against its own reference column so the
runner cancels. The control is 448 bytes, the last length seven states cover,
and it does not move:

| bytes | linux aarch64, before | linux aarch64, after | macos aarch64, before | macos aarch64, after |
| ---: | ---: | ---: | ---: | ---: |
| 448 | 1.58x (459 ns) | 1.56x (463 ns) | 2.75x (260 ns) | 2.84x (240 ns) |
| 449 | 1.29x (639 ns) | 1.55x (536 ns) | 1.85x (452 ns) | 2.93x (259 ns) |
| 511 | 1.29x (645 ns) | 1.54x (541 ns) | 1.88x (516 ns) | 2.93x (261 ns) |
| 1023 | 1.44x (1 147 ns) | 1.58x (1 043 ns) | 2.36x (726 ns) | 3.00x (508 ns) |
| 1535 | 1.52x (1 632 ns) | 1.63x (1 525 ns) | 2.52x (1 086 ns) | 3.03x (777 ns) |

`x86_64` is the arch this does not touch — one state fewer than its group, before
and after — and its 449-byte row reads 2.05x against 2.08x on the same two runs,
which is the runner and not the change. The claim is gated on the aarch64 side by
`chacha::tail_sizing_tests::the_first_group_carries_the_whole_remainder_a_pass_leaves`
— a pass always leaves less than a pass behind, so the tail's first group carries
the whole remainder of every record — and on the `x86_64` side by a `const`
assertion over its own sixteen-register file. The pass hands that group the state
it already holds instead of rebuilding it from the key to feed `xor_ladder`, whose
group loop a pass's remainder can never reach: on `aarch64` the ladder is what the
tests read the pass against, and it ships with them rather than in the release
binary.

The `x86_64` rows of those two runs are not usable for that comparison, and the
reason is the one the `x86_64` pass below exists for. GitHub moved those runners
between the runs: the rows before and after were read on an `avx2` + `vaes`
machine, and run `37737912879` landed on one carrying `avx512f`, where the same
`x86_64` binary read 0.76x to 0.96x of the reference at 512 bytes and above
against 1.20x on the machine before it, while the reference's own clock moved
18%. The ladder's pass-length loop is untouched by both commits and the same
binary ran on both machines, so that was a property of the runner: the ladder
spends forty shuffle ops a double round for the eight blocks it holds, where the
pass spends sixteen, and a machine that issues one shuffle a cycle charges for
the difference.

Run `37740838172` carries the pass, against run `37737912879`, which is the same
ladder on the same runner class — the reference's own clock at 16 KiB reads
9 316 ns against 9 175 ns on linux `x86_64` and 7 781 ns against 6 974 ns on
windows `x86_64`, so the windows runner is the slower of the two by about a
tenth and its absolute column is read with that in mind:

| bytes | linux x86_64, ladder | linux x86_64, pass | windows x86_64, ladder | windows x86_64, pass |
| ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 0.98x (601 ns) | 1.38x (428 ns) | 0.80x (569 ns) | 1.29x (392 ns) |
| 4 KiB | 3.58x (1 773 ns) | 3.58x (1 743 ns) | 0.79x (2 243 ns, remeasured) | 1.32x (1 483 ns) |
| 16 KiB | 0.96x (9 521 ns) | 1.36x (6 846 ns) | 0.76x (9 159 ns) | 1.33x (5 863 ns) |
| 64 KiB | 0.96x (38 329 ns) | 1.36x (27 188 ns) | 0.76x (36 648 ns) | 1.32x (23 561 ns) |

The 4 KiB linux row is the one that does not move, and the reason is in the
reference rather than in either side of the change: at 4 KiB the reference
itself takes 6 351 ns against 6 604 ns for 16 KiB, so that ratio is set by the
reference's own buffer and both sides read 3.58x. Every other row is the pass,
with the absolute times down 28% on linux `x86_64` and 36% on windows `x86_64`.
Below 512 bytes on `x86_64` the ladder is what runs in every one of those runs,
so those rows read the machine and not the pass: 64 to 128 bytes move between
2.0x and 2.3x across the ladder pair on linux `x86_64` while running the same
binary, and the only small lengths either commit touches there are the tail's
own groups — 320 bytes reads 1.47x (185 ns) in the pass's run against 1.48x
(179 ns) in the run before it, and 448 bytes 1.51x (312 ns) against 1.52x
(304 ns).

Run `37749274086` carries the sixteen-block pass — `f2c624e`, the commit this
page ships with — against run `37740838172`, the eight-block pass at
`d31ddae`, on the same two runner classes. Both `x86_64` reports name the pass in
their own machine line: `ferrox core` reads `4-lane core: AVX-512, one word per
register, 16 blocks a pass, the eight-block pass below a pass, at
runtime-detected width`, and that line is `ferrox_core::chacha_backend()`, which
returns it only when the runner's own `is_x86_feature_detected!("avx512f")` and
`is_x86_feature_detected!("avx2")` both read true — the same condition that lets
`chacha::avx512`'s differential test execute its body, so a run whose machine
line names the pass is a run in which gate 1's 7 200 shapes went through it.
Every length below 1024 bytes compiles to the same call in both runs, and the
reference's own clock moved between them — 8 057 ns at 16 KiB against 9 316 ns
on linux `x86_64`, 9 203 ns against 7 781 ns on windows `x86_64` — so each pair
of columns is read as two runs and not one:

| bytes | linux x86_64, eight-block pass | linux x86_64, sixteen-block pass | windows x86_64, eight-block pass | windows x86_64, sixteen-block pass |
| ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 1.38x (428 ns) | 2.39x (213 ns) | 1.29x (392 ns) | 2.71x (220 ns) |
| 4 KiB | 1.36x (1 743 ns) | 2.44x (831 ns) | 1.32x (1 483 ns) | 2.76x (841 ns) |
| 16 KiB | 1.36x (6 846 ns) | 2.40x (3 359 ns) | 1.33x (5 863 ns) | 2.71x (3 400 ns) |
| 64 KiB | 1.36x (27 188 ns) | 2.36x (13 688 ns) | 1.32x (23 561 ns) | 2.63x (13 977 ns) |

The 16 KiB row is the record-sized one, and it halves on both runners: 6 846 ns
to 3 359 ns on linux `x86_64` and 5 863 ns to 3 400 ns on windows `x86_64`,
against a reference that read 13% *faster* on linux `x86_64` this time and 18%
*slower* on windows `x86_64`, so the windows ratio is the flattered one of the
two. That is the same shape the counts above predict from both halves of the
trade: 0.96 round-loop instructions a byte against 2.79, and four transpose
gathers a block against six, with the whole of the pass's extra setup inside a
rate the eight-block pass already pays. The lengths that straddle a pass are
where it pays for what it cannot cover — 1 023 bytes reads 1.63x (469 ns) on
linux `x86_64` while 1 025 reads 2.00x (310 ns), the first being the eight-block
pass plus a tail and the second a whole pass plus a one-block remainder. Gate
3's own line for the run is 235 lengths with none below 0.95x, worst 1.00x at
256 bytes, best 2.86x at 224 bytes; no length under 1024 bytes reaches the pass
in either run, so those rows — the 1.15x worst the run before this one carried
at the same 256 bytes included — are the runner and not either change.

Gate 7 measures the seal against the two-call shape it replaced, and for one
run it carried a length at which the fused shape's head looked like it stopped
paying for itself: a head takes a lane of every pass it rides in, so a body that
fills whole passes pays one more of them, and run `37749274086` read 0.96x at
16 KiB on macos `aarch64` — the one sub-1.00x row of the seal. Rows at 2 KiB and
8 KiB were added to bracket it, and in run `37763295337` the crossover is not
there on any runner: from 1 KiB up the two shapes read 0.98x-1.06x of each other
at every length, on all four, and the fused shape's win is where a pass is most
of the call — 1.44x-1.75x at 64 bytes, 1.25x-1.54x at 256 — so the 0.96x was
one runner's noise and no length threshold belongs in the seal. That is a
negative result the rows were added to be able to state, and the reason no
dispatch sits in `aead.rs`.

## What we removed

- **Thirteen stack moves a double round, and four operations a quarter round.**
  `vprold` makes all four of a quarter round's rotations one instruction where
  `avx2` spends a shift, a shift and an or on each of the two that are not byte
  moves, and the thirty-two-register file holds sixteen live state words with
  room for the temporaries that a sixteen-register file has to send to the frame:
  the AVX2 pass's round loop body is 143 instructions for eight blocks, thirteen
  of them `vmovdqa` against the frame, and the AVX-512 pass's is 98 for sixteen
  blocks — 96 operations and no stack operand at all. Per byte of keystream,
  2.79 instructions against 0.96.
- **Six lane permutations a double round a block on `aarch64`, and ten
  single-cycle shuffles a double round a state on `x86_64`.** Both lane layouts
  diagonalise by rotating the lane order of the row registers: `neon::N4`
  spends six `vext` a double round for its one block, so a block's twenty rounds
  pay sixty permutations, and `avx2::A8` spends six `vpshufd` and four `vpshufb`
  a double round for its two blocks, forty shuffles a double round for the eight
  blocks it holds. The pass diagonalises by *naming*: one state word per
  register and the blocks in the lanes means the four registers of a diagonal
  quarter round are the four registers of the column one, so the rotation is
  free and the only shuffles left are the two byte-level rotations of each
  quarter round — two a block a double round, against five on `x86_64` and six
  on `aarch64`. What the pass pays instead is one transpose of four registers
  per row of blocks at the store. Nothing else moves: the quarter round, the ten
  double rounds and the keystream bytes are the same, and the pass's equality
  with the ladder is asserted at every length before gate 3 times either side —
  `soa::tests::the_eight_block_pass_is_the_ladder_at_every_length` on `aarch64`
  and `avx2::tests::the_eight_block_pass_is_the_ladder_at_every_length` on
  `x86_64`, both at every length to two passes and six start counters, with the
  one-time key compared beside the ciphertext.
- **What the pass did not remove, on purpose.** Below 512 bytes both targets
  are still their lane ladder: a pass pays its setup for eight blocks whether
  eight are wanted or one, and a group sized to the blocks that are left asks
  for exactly the blocks the caller asked for. The single-block path that closes
  a call — one dependent round chain, which is the whole cost of a short record
  — is still there for a block or less, and it is the one place the calibration
  decides: it timed sixty-four *independent* blocks per core, which measures the
  throughput of a wide register file and not the latency of one block with
  nothing beside it to issue, and read the lanes as the faster tail on machines
  where one block does not fill the four-lane core. It now counts each call from
  the word the one before it wrote, so the loop is the dependent chain the tail
  actually pays for, and the same verdict test still checks that the two cores
  agree byte for byte before the verdict is trusted. The MAC beside the keystream is untouched by
  this slice, and the limb extraction it got in the slice before is not a clean
  win: five `TBL4` lookups a group read 4152 ns against the scalar windows' 4421
  ns at 16 KiB on macos aarch64, and 6436 ns against 6222 ns on linux aarch64.
  It is faster on one runner, slower on the other, and named here rather than
  left as a win.
- **Keystream that was generated and thrown away.** Gate 2 compares the block
  count the ladder reports against `ceil(len / 64)` at every length in a
  0..=65 537 sweep and at six start counters, and fails on any excess. The
  `chacha20` crate the reference uses fills a keystream buffer *four blocks at
  a time* on every backend it ships, which is what makes a short call expensive;
  the ladder here sizes its last group to the blocks that are left and only
  rounds up to a state's width — two blocks on `x86_64`, one on `aarch64` — so
  the blocks a length asks for are the blocks a length pays for, and the count
  it reports is `ceil(len / 64)` at every length. `record::blocks_with_head_match`
  is the same accounting for the fused head: an empty body plus a 32-byte head
  is one block, not two. Two things that are *not* zero, named rather than
  claimed: a two-block state computes its second block whether or not the
  buffer carries it on `x86_64`, and a pass of eight blocks carries its lanes
  whether or not a headed buffer stores all of them. Neither is a *discarded*
  block in the table's sense — the table's row is the count the ladder reports,
  which gate 2 sweeps against `ceil(len / 64)` — they are lanes of an
  instruction that was already being issued.
- **A per-call allocation and a memset.** Gate 2 runs the fill under a
  `#[global_allocator]` that separates `alloc` from `alloc_zeroed`, and requires
  exactly zero of each at every length. A `Vec<u8>` staging buffer per call, or
  a `vec![0; len]` that the caller then overwrites, both fail that gate — which
  is the same finding Zray recorded in its own hot-path allocator gate, where
  `vec![0u8; n]` "zeroes up to 64 KiB that the read then overwrites".
- **The 64-byte staging buffer every open used to carry.** A ChaCha20-Poly1305
  open has to authenticate the *ciphertext*, so it cannot decrypt before the tag
  is checked and it cannot check the tag after the buffer holds plaintext. The
  way out is that Poly1305 needs no keystream at all: `aead.rs` now derives the
  one-time key, authenticates the ciphertext in place, compares the tag, and
  only then calls `fill_exact(key, nonce, 1, buf)`. The old shape generated the
  first 64 bytes of body keystream into a `[u8; 64]` on the stack, XORed them
  back into the caller's buffer with a 64-iteration scalar loop, and then called
  `fill_exact(key, nonce, 2, rest)` for the tail. Three things went with it: the
  staging buffer and its zero-fill, the scalar loop, and the split. The block
  count is identical at every length (`1 + ceil(len/64)` before and after) and
  the panic threshold is identical, because `fill_exact_with_head` on a 64-byte
  head plus `fill_exact` from block 2 on the tail already cost two passes. This
  is the order `aesgcm::open_impl` in this same tree has always used — GHASH
  over the ciphertext, verify, then CTR — so the AEADs no longer disagree about
  when plaintext appears. The 6 000-case sweep
  `aead::tests::every_decrypt_matches_the_crate_it_replaces` is what proves the
  reorder is byte-identical: it opens with the `chacha20poly1305` crate and
  compares, and it also checks that a forged tag leaves the buffer encrypted.
- **A second `update` and a wasted `absorb(&[])` per padded section.**
  `Poly1305::pad_to_block` zeroes `buffer` up to a block and absorbs it in one
  call, replacing `update(&[0u8; 16][..slack])`, which cost a call, a `min`, two
  bounds checks and a *dynamically sized* `memcpy` for 1..15 bytes. Padding
- **The empty `absorb` at both ends of every record.** `Poly1305::update` called
  `absorb(&data[..whole])` and copied `rest` even when `whole` was zero and
  `rest` was empty, which is exactly the shape of every padding call: a dispatch,
  three length compares, eight loads of `r`/`s`/`h`, three stores and a call,
  for no bytes. `update` now guards both, and both 4-lane ladders call
  `absorb_one_block_chain` directly instead of recursing through `absorb` when
  the head is zero blocks — which is every 64-byte-aligned record, so every
  8 KiB VMess frame on the AVX2 and NEON-4 rungs.


What is **not** removed, and is named rather than claimed:

- **There is no 512-byte NEON rung, and two tests read as if there were.**
  `NEON_THRESHOLD_BYTES` and `absorb_neon` are both `#[cfg(all(test,
  target_arch = "aarch64"))]`, so the 512-byte rung exists only under the test
  harness — but `every_threshold_reaches_the_same_tag_from_both_sides` sweeps it
  as a shipping threshold and `the_neon_halves_are_the_three_limbs_at_every_length_around_the_threshold`
  gates on it. A reader of those two tests believes a shorter aarch64 rung ships.
  It does not. The shipping ladders are `{128 stride-2, 1024 NEON-4}` on
  aarch64 and `{128 stride-2, 1024 AVX2}` on x86_64, so any page that quotes a
  threshold has to say which architecture it means — the two do not agree, and
  each four-lane rung moved to 1 KiB where the other's gate sits: the AVX2 one
  in `815eeb2` because its fixed setup cost is repaid by then, and the NEON-4
  one in `89f9714` on the same measurement, taken again after the four blocks'
  limbs came out of one `TBL4` a group.

  **The two-lane rung below the four-lane one was unreachable, and it is gone.**
  `89f9714` moved `NEON4_THRESHOLD_BYTES` down to 1 024 where the two-lane
  threshold sat, and `absorb` tested the four-lane rung first, so every slice
  of 1 024 bytes or more reached `absorb_neon4` and `absorb_two_lane` ran only
  where a test called it by name. P45 deleted the rung, its threshold, its
  dispatch arm, its two helpers and that test: a second Horner step, its own
  pair of `q`/`qs` powers and its own tail walk, none of them reachable from
  any input. The shipping ladders were already `{128 stride-2, 1024 NEON-4}`
  on aarch64 and `{128 stride-2, 1024 AVX2}` on x86_64; now the code says so
  with no leftover arm to misread as a third.

  This also bounds what the ladder-head guards on the four-lane rungs can
  assume: the head is `e = blocks % 4` blocks, so at most 48 bytes, and the
  smallest dispatch threshold on either architecture is 128. That is why both
  guards may call `absorb_one_block_chain` directly instead of going back
  through `absorb` — a 48-byte slice can never reach another rung, so there is
  no dispatch to skip.
- **The sixteen-block pass is checked by the runners, not here.** Nothing this
  repository builds on can execute `avx512f` without a machine that has it, so
  `chacha::avx512::Z16` is not run on the machine reading this — and an emulator
  does not stand in: a `x86_64` build of this crate run under Rosetta on Apple
  silicon reports `avx512f` false, which is the very `is_x86_feature_detected!`
  the test reads on its first line and the dispatch itself calls, so the body
  returns before it runs a block. The pass's *shape* is checked everywhere:
  `chacha::wide` carries the same body over sixteen `u32`, and the differential
  test beside it holds that instantiation to `portable::U4` at every length to
  2072 bytes and four start counters, head and headless. What is left to a
  machine with AVX-512 is one instruction — the gather whose `idx & 0x10` bit
  picks the source register — so the honest split is: the index table is proved a
  transpose here, the pass over it is proved the ladder here, and the one
  instruction that applies it is proved on the two `x86_64` runners of
  `bench.yml` and in the `x86_64` job of `ci.yml`. If no runner carried
  `avx512f`, the test would still return without testing anything, which is why
  the machine line of each run quoted under `## Time` is quoted beside the
  number: the claim is a claim about those machines.
- **`ops-retired-instructions` is still `UNBLESSED` on every page.** One symbol
  in this repository carries a blessed exact count, `der_to_pem`. The removed
  operations named above are counted in the table — copies, allocations, passes,
  blocks, absorbs — but the retired-instruction figure for each is not measured,
  so no page states one.

## Pins

| what | where |
| --- | --- |
| the one-shot AEAD that forces a refill per call | `upstream/sing-box` → `golang.org/x/crypto/chacha20poly1305`, `chacha20poly1305.go:35` |
| the explicit block range and the 8→4→2→1 ladder | `upstream/zeronet/crates/zero-protocol/src/chacha20/mod.rs` |
| the stream cipher this rung replaces | `upstream/xray-core/common/crypto/internal/chacha.go` |

## CI scope

What a change here owes, read by `scripts/ci-scope.py`; see [`docs/ci-scope.md`](../ci-scope.md).

<!-- scope:begin -->
- paths: crates/ferrox-core/src/record.rs, crates/ferrox-core/src/aead.rs, crates/ferrox-core/src/poly1305.rs, crates/ferrox-core/src/chacha/*, crates/ferrox-core/src/aesgcm/*
- scenarios: vless-raw, vmess-raw, trojan-raw, shadowsocks-raw
- oracle: over_raw_tcp
- go: ./common/crypto/...
<!-- scope:end -->
