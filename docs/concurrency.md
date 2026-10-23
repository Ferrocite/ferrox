# Concurrency model

One decision, stated with its checker. This is the design answer to the thread/kernel-CPU tax the method pages name and batching does not remove. The raw TCP data path has it and is measured; the carriered legs still run the old pooled blocking copy.

## The tax, honestly

Ferrox is a **pooled blocking relay** on its carriered legs. Each accepted flow hands its directions to a `RelayTask` worker pool (`crates/ferrox-app/src/proxy.rs`): a worker runs a leg, and on completion parks itself in an idle lot a later flow can claim. Idle workers cost nothing. But a leg that is *waiting* — blocked in `read` on a socket the peer has not fed — holds its OS thread for the whole wait. So the thread a flow costs is not one-per-connection, it is **one-per-*active*-leg**, and "active" includes "blocked, waiting for bytes". At ten thousand quiet-but-open tunnels that is tens of thousands of threads parked in the kernel, each with a stack the scheduler must switch.

The raw TCP legs have left that shape. Their descriptors are handed to a fixed worker set and the connection's own thread returns to accept the next flow, so the peak is a property of the machine rather than of the flow count. The copy above is what the carrier paths (TLS, mux, Shadowsocks, xHTTP) still run.

`xray-core` does not pay this. A Go goroutine blocked on a read is descheduled by the runtime netpoller and its OS thread released for other work; a per-connection goroutine is ~2 KiB of heap and a link in a run queue, not a kernel thread. The pages that admit the gap are honest about which half they closed: [`shadowsocks`](function/shadowsocks.md) says of its batch "the thread count did not move at all (36 before, 36 after)", [`carrier-xhttp`](function/carrier-xhttp.md) buys "a thread per idle connection", [`carrier-quic`](function/carrier-quic.md) "a thread per idle lane", and [`carrier-grpc`](function/carrier-grpc.md) prices "95% of this carrier's Windows cpu is kernel time".

## Why buffered batching is the wrong tool for *this* tax

Batching is real and it landed: `CHUNKS_PER_BATCH` folds four chunks into one `readv`/`writev` on Shadowsocks, and gRPC/xHTTP coalesce a frame's parts into one socket call per 256 KiB read. Every one of those cuts **syscalls per byte on the wire** — the throughput axis. None of them touches **threads per concurrency** — the connection-count axis. A batched read that returns quickly still blocks its thread when there is nothing to read; coalescing writes never un-parks an idle leg waiting on the far half. The two taxes are orthogonal, and the shadowsocks page already proved it by moving one and not the other. More micro-batching is not the answer here; the user is right that this needs a design, not another syscall shave.

## The chosen design: a readiness seam, not an async rewrite

The seam sits *under* the `Read`/`Write` contract, so nothing above it changes. On Linux the raw legs reuse the `splice` pump that already existed: a direction splices source to a pipe and pipe to destination, and one `poll` wake on either descriptor drives both legs. On the hosts without `splice`, `poll_copy` keeps the same shape with a 64 KiB buffered copy and `poll`/`WSAPoll`; a wake pipe (Unix) or loopback TCP pair (Windows) releases a worker when a flow is queued. Both pools are fixed at `min(available_parallelism, 8)` workers and both hand a flow back only when both directions have ended.

Ownership is what makes the hand-off real: `relay_handoff` clones the four descriptors, arms them non-blocking, queues the flow, and returns. The accept loop's thread is therefore finished with the flow before the first byte moves. The guards and the completion channels live in the `Flow`, so the sockets' blocking mode is restored and the joiner woken when the workers finish — not by the caller's thread parked on a channel. `Pump` uses a one-shot `RelayPool::run_once` for the same reason: a finished pump thread leaves instead of parking for `RELAY_WORKER_LIFE`.

A masked leg, or a host where the arm fails, still falls back to one spawned blocking relay thread; that is the safe path, not the measured one.

This is the same M:N trick the goroutine netpoller runs: **N legs ride ~`cores` worker threads**, and a thread is held while a leg has work, not while it waits. It does not release a thread for a leg that is actively copying — that leg was never the tax — it releases the ones parked in `read`.

## Rejected, and why

- **Adopt tokio / rewrite to `async`.** A runtime is a second scheduler whose own task wakes are kernel CPU — the thing being removed — and rewriting every carrier's `Read`/`Write` to `Future` sweeps the whole tree and puts the byte-identity differential at risk for a change that is orthogonal to it. It also violates "no second way of doing something": there would be an async relay and the existing sync relay side by side. The poller gets the same M:N win behind a `Read`/`Write` interface with no signature churn above it.
- **Stay thread-per-leg and just cap/shrink stacks.** A thread-count ceiling turns the tax into dropped connections; smaller stacks do not remove the context switch. Neither answers the concurrency scaling, only hides where it fails.
- **More buffered batching.** Shown above to be the wrong axis.
- **The TLS-raw fixed-worker poll relay, measured and rejected.** A branch moved the TLS-raw carrier legs from the per-direction blocking copy to one 64 KiB non-blocking `poll` direction under the same `Read`/`Write` seam. On `vless-tls-raw-down-8` (ubuntu-24.04-arm, five repeats) the best shape — a 64 KiB window with sixteen windows per wake — moved ferrox from the then-current main (`92abb52`, matrix `39875376209`) at 2060–2104 MiB/s, 1598–1648 CPU ms/GiB, 11.78–11.83 MiB RSS and 35 threads to 1963–2000 MiB/s, 1611–1639 CPU ms/GiB, 12.87–12.94 MiB RSS and 11 threads (matrix `39883157871`). It beats xray-core and zeronet on all three axes but loses to main on all three, so it was deleted rather than landed. A 16 KiB window cut RSS to 10.6 MiB but fell to 1625–1679 MiB/s and 1808–1882 CPU ms/GiB; 128 KiB bought no throughput and raised RSS to 13.7 MiB. The thread count alone is not worth a throughput, CPU or RSS regression: the next attempt needs a cell with more than sixteen flows (issue #387) to show the saving where it matters, or a blocking-copy shape that keeps main's byte path. The final matrix (`39887381638`) passed with no stall; the work is documented here rather than kept as a branch.

## The checker (has to observe the thing the row claims)

A duration suggests; a thread count proves. The matrix already records `threads_peak` per engine per cell, and the same cell records the paired throughput and CPU intervals, so the claim is read from one run rather than two. The measured cell is `vless-raw-down-8` at five repeats, CI run `39826752985`; the one-flow control is `vless-raw-down-1`, CI run `39833614246`:

| cell | ferrox before | ferrox now | xray-core | zeronet |
| --- | ---: | ---: | ---: | ---: |
| ubuntu x86_64, 8 connections | 31 | 7 | 17 | 5 |
| ubuntu aarch64, 8 connections | — | 7 | 17 | 5 |
| windows x86_64, 8 connections | 39 | 11 | 11 | 9 |
| macOS aarch64, 8 connections | `None` | 6 | 19 | 4 |

The "before" Linux and Windows numbers are the source run in issue #381 (`39707834882`); macOS reported no count there because the sampler had no thread column on that host. At one connection the peak is **7** on both Ubuntu runners and **11** on Windows, the same as at eight; on the three platforms measured at both counts the number does not move with the flow count. macOS was measured at eight only, where it is 6.

The throughput gate passed in every cell, so no leg got slower: the paired ferrox/xray-core midpoints are 2.13× on ubuntu x86_64, 2.63× on ubuntu aarch64, 1.20× on Windows, and within noise on macOS (median 1.08×, paired midpoint 1.28×). CPU per GiB and peak RSS are lower than xray-core in the same cells.

The **idle-leg** form of the claim is still open for the carriered paths: this cell carries active traffic, so it proves the fixed peak for raw TCP, not that a silent TLS or mux peer pins nothing. The per-peer `pinned-threads` rows on the carrier pages remain the checker for that half, and `idle-legs-pinned-threads-per-connection` stays `UNBLESSED` until a carrier cell reads it.

## Status

`landed and measured` for the raw TCP data path: vless/vmess/trojan raw, the SOCKS client and freedom direct paths now hand off to the fixed worker set, and the thread peak is 7 (Linux), 11 (Windows) and 6 (macOS) at eight flows, unchanged at one flow where both were measured. The `census` wait table, the batch rungs and the splice pump are unchanged above the seam.

`open` for every carriered leg (`relay_stream`, `Half`, xHTTP idle connections, Shadowsocks, gRPC): those still hold a thread per parked leg, and no number here claims otherwise. Closing that half is the next slice; this one does not fold into it.
