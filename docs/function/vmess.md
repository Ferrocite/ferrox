# VMess AEAD

VMess is the one method here that pays for a keyed handshake and then gets out of the way. The header is read once per connection and every later frame is an 8 KiB payload, a SHAKE-masked 2-byte length, and a 16-byte tag.

A dial that was handed a name writes it inside the sealed request header as ATYP 2 with its own length, so the edge resolves it and the client's resolver is never asked.

The framing this tree speaks is `OptionChunkStream | OptionChunkMasking | OptionGlobalPadding` with **no** authenticated-length option, which is the shape that costs one AEAD call per frame instead of two. That is not a simplification: a peer negotiates framing options in the clear, so a different set is visible on the wire. Xray's client default is the same three bits, so this matches.

Read and write are symmetric about one thing: both batch. Writing stages sixteen 8 KiB frames into one buffer and writes them once. Reading keeps the sealed bytes and the plaintext gathered from them in one buffer, so the pump can tell without asking the carrier that a whole batch is already here, and it leaves the plain leg in one write instead of sixteen. A `BufReader` cannot offer that — it hides how much it holds — which is why the relay reads through `vmess::Wire` and the handshake still reads through `read_frame`.

The payload cipher follows the reference's `auto` negotiation rather than a fixed choice: AES-128-GCM where the machine has hardware for it, ChaCha20-Poly1305 where it does not. Xray's `GetSecurityType` (`common/protocol/headers.go:82`) selects on `HasAESGCMHardwareSupport` the same way, so on a runner with AES-NI or armv8 crypto this tree pays hardware AES like the reference instead of a software stream cipher, and the request's cipher byte and the flows that seal the body are resolved through one function so they cannot diverge — `the_header_cipher_byte_matches_the_flow_cipher` is that gate.

## Data path

```mermaid
graph TD
    W["plaintext read, 128 KiB"] --> W1["16 frames of 8192 B"]
    W1 --> W2["each: mask a 2-byte length with SHAKE,<br/>seal the payload in place, append the tag"]
    W2 --> W3["one staging buffer<br/>1 copy per byte, 0 allocations"]
    W3 --> W4["write_all, 1 syscall"]
    W4 --> W(("wire"))
    R(("wire")) --> R1["fill the pump's own buffer<br/>1 read per refill"]
    R1 --> R2["unmask the 2-byte length,<br/>open each frame in place"]
    R2 --> R3["gather the plaintext to the front<br/>of that same buffer, 0 allocations"]
    R3 --> R4["counter +1 per frame"]
    R4 --> R5["write the whole batch to the target,<br/>1 syscall"]
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| maximum-payload-per-frame | 8192 | ferrox-app-vmess::tests::frames_seal_to_stable_bytes |
| frames-per-write-syscall | 16 | ferrox-app-vmess::tests::a_batch_on_the_wire_is_the_frames_written_one_at_a_time |
| write-syscalls-per-128KiB-relay-read | 1 | ferrox-app-vmess::tests::a_batch_on_the_wire_is_the_frames_written_one_at_a_time |
| user-space-copies-per-byte-written | 1 | ferrox-app-vmess::tests::frames_reuse_the_callers_buffers |
| frame-buffer-allocations-per-relay-write | 0 | ferrox-app-vmess::tests::frames_reuse_the_callers_buffers |
| frames-per-plain-write | 16 | ferrox-app-vmess::tests::a_batch_of_frames_leaves_the_pump_in_one_write |
| plain-write-syscalls-per-16-frame-batch | 1 | ferrox-app-vmess::tests::a_batch_of_frames_leaves_the_pump_in_one_write |
| pump-buffer-allocations-per-batch | 0 | ferrox-app-vmess::tests::the_pump_gathers_into_its_own_buffer_and_never_moves_it |
| counters-per-frame | 1 | ferrox-app-vmess::tests::counters_advance_one_per_frame_at_any_offset |
| replay-keys-held-at-most | 131072 | ferrox-app-vmess::tests::the_window_holds_two_rotations_at_most |
| zero-filled-bytes-per-flow | 0 | ferrox-app-vmess::tests::the_flows_windows_are_not_zero_filled |
<!-- counts:end -->

`zero-filled-bytes-per-flow 0` is the flow's own windows: the wire's receive window, the relay leg's read window and the response header's buffer were each `vec![0u8; n]`, so a flow zeroed 393 KiB that its first read overwrites in full. `the_flows_windows_are_not_zero_filled` drives the counting allocator over the two windows a flow allocates and reads its `zeroed` counter, which is zero only when no allocation asked for zeroed memory; the same counter would read three on the old shape. The bytes on the wire are not in question: no buffer changed size, and the reads that filled them are the same reads.

## Ops

```bash
./scripts/count-ops.sh report \
  vmess::tests::frames_reuse_the_callers_buffers 'vmess::stage_frames'
```

`UNBLESSED`, as above.

## Time

`ferrox-bench` gate 4 (`framing.rs`) compares VMess-style framing rows byte for byte against the pinned reference, and gate 7b compares the AEAD seals; neither is a clock. The clock is gate 3's ratio at every measured length plus `.github/workflows/parity.yml`'s `vmess-raw` scenario, and the batch's own number is `benchmark-matrix.yml`'s `vmess-raw-down-8` cell: **full tier, ubuntu-latest (4 logical CPUs), 5 medians per engine.**

| ratio vs xray-core (higher throughput / lower CPU is better) | interval | verdict |
| --- | --- | --- |
| throughput | 1.235 [1.216, 1.269] | better, gating |
| cpu per GiB | 1.178 [1.169, 1.187] | better, gating |
| peak rss | 7.122 [7.079, 7.165] | better, gating |

The split those two totals are made of, in ms/GiB medians:

| engine | user | sys | total | MiB/s | peak RSS MiB | threads |
| --- | --- | --- | --- | --- | --- | --- |
| ferrox | 790 | 1 291 | 2 065 | 1 557.5 | 8.6 | 35 |
| xray-core | 1 264 | 1 170 | 2 435 | 1 274.8 | 61.2 | 14 |
| zeronet | 7 578 | 1 614 | 9 201 | 399.2 | 12.5 | 5 |

Against the standard-tier baseline (788 user / 1 850 sys, cpu per GiB 0.921 of xray-core) **the batch moved the kernel half and only the kernel half**: −30 % sys per GiB, user CPU inside the noise, and the reference on this run reads 1 170 sys against its baseline's 1 153, so the runner did not move under the number. zeronet's `vmess` rows are informational and non-gating; sing-box and xray-rust are **unproven** here for the reasons the cell records — Xray-dialect configs and a pin that does not serve vmess.

The tag and the payload are both authenticated over the ciphertext, so this method's open path is the [`record-layer`](record-layer.md) open path: the tag is checked before any keystream exists and block one onward is xored into the frame buffer once. That is what `vmess user-space-copies-per-byte-written 1` and `vmess frame-buffer-allocations-per-relay-write 0` above are counting, and the Poly1305 rungs it shares — one absorb per padded section, no empty absorb at either end of a record, no head recursion into the dispatch on a 64-byte-aligned frame — apply to every 8 KiB VMess frame on the AVX2 and NEON-4 paths.

- **Two rows this page claims were not being checked at all.** The gate for `frames-per-write-syscall` and `write-syscalls-per-128KiB-relay-read` swept payload lengths that topped out at `3 * MAX_PLAIN` when the batch was four frames — **three** frames, so the fourth iteration of `stage_frames`' loop was never entered by any test and the number 4 was unobserved; and the sink was a `Vec`, which cannot tell one `write` from four, so the syscall row had no counter behind it either. The sweep now runs to the batch bound *written in the constant* — `(FRAMES_PER_WRITE - 1) * MAX_PLAIN`, `FRAMES_PER_WRITE * MAX_PLAIN - 1`, `FRAMES_PER_WRITE * MAX_PLAIN`, one over it, and `READ_PLAIN` — and writes into a `CountingWriter`, so both rows are observed at whatever width the batch is, not at the width they were written for. Nothing about the frames changed; only what the test can see.
- **A silent truncation that the same gap was hiding.** `stage_frames` staged at most `FRAMES_PER_WRITE` frames and, if the read was wider, exited its loop with bytes left and returned `true` — a truncated frame sequence on the wire, with no assertion anywhere. `pump_relay` clamps to `READ_PLAIN`, which equals the batch bound, so nothing reaches it today; but the two expressions that have to agree were checked by nobody, and raising `FRAMES_PER_WRITE` without raising `READ_PLAIN` would have dropped the tail of every relay read over one batch. `stage_frames` now refuses instead, and `a_read_wider_than_one_batch_is_refused_not_truncated` gates that: it drives `READ_PLAIN + 1` and `READ_PLAIN + MAX_PLAIN`, requires `false`, and requires that **nothing** reached the sink.

## What we removed

- **A `host:port` string per datagram.** The datagram lane's target was re-serialised into a `host:port` string for the resolver, so every datagram that named a host paid a string the resolver then had to take apart again. The resolver is asked for a host and a port now, the way this tree already asks on the flow's own dial, and the `host:port` spelling is gone from the tree.
- **Three hundred and ninety-three kilobytes of zero fill per flow.** The wire's receive window, the relay leg's read window and the response header's buffer were each allocated with `vec![0u8; n]`, so a flow paid a zero pass over 393 KiB of memory that the first read overwrites in full. They are the same buffers without the pass now: the counting allocator's `zeroed` counter is the witness, and `the_flows_windows_are_not_zero_filled` fails if any of them is zeroed again. What did not move: the bytes on the wire, and the buffers' sizes — the same memory is still allocated, and the pages the fill used to fault in are now faulted in by the read that overwrites them.
- **A frame buffer per relay write.** `frames_reuse_the_callers_buffers` is the gate: one buffer, sized once per connection by `with_capacity`, refilled by `clear`. For comparison, Xray's `common/crypto/auth.go:287` does `mb2Write := make(buf.MultiBuffer, 0, len(mb)+10)` and takes a pooled `temp := buf.New()` scratch on every `WriteMultiBuffer` call, so the batch is the pipe's read granularity rather than a number chosen for syscalls.
- **Sixteen write syscalls per relay read.** sing-box's VMess writes one `ChunkWriter` frame per write with `WriteChunkSize = 15000` (`sing-vmess/protocol.go:24-32`) and only coalesces when the upper layer is vectorised. Xray's stream path coalesces with `writev` but starts from a fresh scratch each call. This tree stages sixteen frames and writes once; `a_batch_on_the_wire_is_the_frames_written_one_at_a_time` is the gate that the batch is byte-identical to writing the frames one at a time.
- **Four write syscalls — and four segments — per relayed batch.** The plain leg of a relay wrote one decoded frame per `write_all`: a syscall and a loopback segment for every 8 KiB. On `vmess-raw-down-8` (ubuntu-latest, 3 repeats each) ferrox reads **1 850 ms/GiB of system CPU against xray-core's 1 153**, while the same runs read **788 ms/GiB of user CPU against their 1 275**: the user-space half of this method already costs 1.6x less than the reference, and the row that is red is entirely the kernel. The reference batches for the same reason — `AuthenticationReader.ReadMultiBuffer` (`common/crypto/auth.go:207`) pulls one frame and then up to fifteen more **only from what its `BufferedReader` already holds**, so a batch never waits and an interactive byte is never held up to fill one. `Wire::batch` is that shape over one buffer instead of two, which also drops the `BufReader` hop into a scratch `Vec` and the `resize` that zeroed a frame right before `read_exact` overwrote it. `a_batch_of_frames_leaves_the_pump_in_one_write` gates the batch, and `a_dribbled_carrier_still_offers_one_frame_and_loses_nothing` that a carrier arriving three bytes at a time still loses nothing. The moved row: **1 850 → 1 291 ms/GiB of system CPU**, user CPU left where it was (788 → 790), which is what makes this a kernel-side removal rather than a relocation into user space.
- **Three more writes, and three more reads, per relayed batch.** The same lever, taken to the width the reference already caps itself at: `FRAMES_PER_WRITE` 4 → 16, xray's `one frame, then up to fifteen more from what the buffer holds`. The batch still never waits — only the first frame blocks — so the width buys syscalls and costs buffer, nothing else. Measured on `vmess-raw-down-8` (ubuntu-latest, 5 medians) against the 4-frame shape's own cell (same runner and reader): **system CPU 1 301 → 1 098 ms/GiB**, which is under xray-core's 1 171 for the first time on this cell, and **user CPU 781 → 635**, so total CPU **2 083 → 1 737** and the gating rows move with it — `cpu per GiB` 1.172x → **1.403x**, throughput 1.208x → **1.459x**. What that buys in RAM is named rather than hidden: `WIRE_LEN` 41 365 → 140 641 B per pump and `READ_PLAIN` 32 → 128 KiB per relay read, so peak RSS goes **8.67 → 11.4 MiB (+32 %)** and the RSS row's lead over the reference narrows from 7.31x to 5.43x; thread count is unmoved at 35. What is *not* removed is the gather: the batch still leaves as one buffer's front bytes, one copy per byte, because the four-`iovec` shape that avoided it lost more on the kernel than it gained in user space.
- **A second copy on read.** Xray's large-chunk read path (`common/crypto/auth.go:188-203`) allocates a pooled buffer, reads into it, opens in place, and then calls `buf.MergeBytes`, which is a second copy plus a whole new `MultiBuffer` of 8 KiB buffers per chunk. The `≤ 8 KiB` path (`:137-151`) is in place and is the cheaper of the two; this tree always takes the in-place shape because its frame size is fixed at 8 KiB.
- **An `auto` that was never automatic.** `Cipher::Auto` used to resolve to ChaCha20-Poly1305 unconditionally, so on a machine with hardware AES this tree sealed every VMess payload with a software stream cipher while the reference pays hardware AES for the same `auto` config. The measured cost was the whole payload path: on the `vmess-raw-down-8` matrix cell ferrox ran ~0.44x of xray-core's throughput and ~2.3x its CPU per GiB, and the gap was the cipher, not the concurrency — `vless-raw-down-8`, which shares the relay model but negotiates no cipher, beats xray on the same runner. `Auto` now resolves the way `GetSecurityType` does, onto the already-gated hardware AES path.
- **Nested HMAC construction.** The VMess KDF is an explicit HMAC-chain state machine (`vmess::Kdf`) that reuses a precomputed inner/outer pair, where Xray's `proxy/vmess/aead/kdf.go` builds a fresh `hmac.New` per path element and the handshake pays four of them. Zray made the same call for the same reason.
- **The 512 MiB flow ceiling.** The seal counter used to stop at `u16::MAX`, which ends every flow past 65536 seals while the reference wraps its `uint16` counter and continues. The counter now wraps exactly like `GenerateChunkNonce` (`proxy/vmess/encoding/client.go:302`), so long flows keep the reference's nonces; past the wrap the nonces repeat, which is the reference's wire and is named here rather than hidden. `counter_wrap_matches_the_reference` is the gate.
- **The replay set that grew for the life of the process.** `replay_seen` kept every 16-byte auth id it had ever accepted, so each new connection added to it and nothing ever left; a subscriber reconnecting on its own could grow it without bound. It is now the two-rotation window Shadowsocks 2022's salt filter already used, shared as one `Replay` type rather than written twice. The span is 240 s because `valid_auth_id` accepts an id 120 s either side of the clock, so an id is still refused for the whole time it can be replayed; `the_window_refuses_a_replay_for_its_span_and_forgets_after_two` moves the clock over both edges of that. What is **not** removed is the bound's cost: past 64 Ki ids in one span the window rotates early and the oldest ids are forgotten, which is the same trade the salt filter makes, and `the_window_holds_two_rotations_at_most` is the gate that it stays at two rotations.

What was **not** removed, and is named rather than rounded off: the auth-id lookup. `replay_seen` is a probe over the window's two `HashSet`s of 16-byte ids with no per-connection cache keyed by auth id, which is the same shape as Xray's `AuthIDDecoderHolder.Match`. The read side of the header costs three `read_exact` calls (16 + 18 + 8 bytes) rather than one, because the auth id has to be read before the length can be decrypted. Both are handshake-only, once per connection, and neither is where a connection spends its time.

The batch also **trades one user-space copy for three kernel calls**: gathering a frame's plaintext to the front of the pump's buffer is one `copy_within` per frame, which the one-frame-per-`write` pump did not pay. It is a relocation, not a removal, and it is on the side of the ledger the split above says is already cheap — `vmess user-space-copies-per-byte-written 1` counts the write leg only, so this read-leg copy is prose rather than a row. `the_pump_gathers_into_its_own_buffer_and_never_moves_it` holds the buffer's pointer and capacity steady across a batch so the gather cannot quietly become a reallocating batch. The copy was removed once and put back: leaving each frame where its open left it and sending the batch as four iovecs of one `write_vectored` moves no byte at all, and on `vmess-raw-down-8` that shape read **user 757.5 against system 1 351.7 ms/GiB** (3 repeats) where the gather reads **user 790.3 against system 1 284.2** pooled over 8 repeats, total CPU spread 2 027 to 2 110 ms/GiB. The vectored batch took ~33 ms/GiB off user space and put ~68 ms/GiB on the kernel, ending ~35 ms/GiB worse on total CPU and tied on throughput (−0.6%): a relocation onto the half of the ledger this method is already behind on, so it does not land. The same runs clear the other suspect. `vless-raw-down-8` — this relay model with no framing — holds **31 threads at peak** and spends **498.75 ms/GiB of system CPU against xray-core's 1 225.8**: 2.6x less kernel than this method's 1 284 at four more threads. **35 threads against xray-core's 14** is therefore not what makes the sys row red here; the framing is, and which part of it the kernel charges for stays open on this page.

## Pins

| what | where |
| --- | --- |
| chunk stream + chunk masking options, frame sizes | `upstream/xray-core/proxy/vmess/encoding/`, `common/crypto/auth.go` |
| chunk stream + chunk masking options, `WriteChunkSize` | `upstream/sing-box` → `sagernet/sing-vmess/protocol.go` |
| the same framing, in place, batched | `upstream/zeronet/crates/zero-protocol/src/vmess.rs` |

## CI scope

What a change here owes, read by `scripts/ci-scope.py`; see [`docs/ci-scope.md`](../ci-scope.md).

<!-- scope:begin -->
- paths: crates/ferrox-app/src/vmess.rs
- symbols: vmess, Replay
- engines: xray-core, zeronet
- scenarios: vmess-raw, vmess-tls-ws
- oracle: vmess
- go: ./proxy/vmess/..., ./common/crypto/...
<!-- scope:end -->
