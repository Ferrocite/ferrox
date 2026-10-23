# Concurrency model

One decision, stated with its checker. This is the design answer to the thread/kernel-CPU tax the method pages name and batching does not remove. The raw TCP data path has it and is measured; the carriered legs still run the old pooled blocking copy.

## The tax, honestly

On its carriered legs Ferrox is a **pooled blocking relay**: a `RelayTask` worker pool (`crates/ferrox-app/src/proxy.rs`) runs each leg, parking finished workers in an idle lot. Idle workers cost nothing, but a leg blocked in `read` holds its OS thread for the whole wait — so the thread a flow costs is one per *active* leg, "active" including "blocked, waiting for bytes". At ten thousand quiet-but-open tunnels that is tens of thousands of threads parked in the kernel.

`xray-core` does not pay this: a goroutine blocked on a read is descheduled by the runtime netpoller, and a per-connection goroutine is ~2 KiB of heap, not a kernel thread.

## Why buffered batching is the wrong tool for *this* tax

Batching is real and it landed: `CHUNKS_PER_BATCH` folds four chunks into one `readv`/`writev` on Shadowsocks, and gRPC/xHTTP coalesce a frame's parts into one socket call per 256 KiB read. Every one of those cuts **syscalls per byte** — the throughput axis. None touches **threads per concurrency**: a batched read that returns quickly still blocks its thread when there is nothing to read, and coalescing writes never un-parks an idle leg. The two taxes are orthogonal; more micro-batching cannot close this one.

## The chosen design: a readiness seam, not an async rewrite

The seam sits *under* the `Read`/`Write` contract, so nothing above it changes. On Linux the raw legs reuse the `splice` pump: a direction splices source to pipe and pipe to destination, one `poll` wake on either descriptor driving both legs. Where there is no `splice`, `poll_copy` keeps the same shape with a 64 KiB buffered copy and `poll`/`WSAPoll`; a wake pipe (Unix) or loopback TCP pair (Windows) releases a worker when a flow is queued. Both pools are fixed at `min(available_parallelism, 8)` workers and both hand a flow back only when both directions have ended.

`relay_handoff` clones the four descriptors, arms them non-blocking, queues the flow and returns; the accept loop's thread is finished with the flow before the first byte moves. The guards and completion channels live in the `Flow`, so the sockets' blocking mode is restored and the joiner woken by the workers, not by a caller parked on a channel. `Pump` uses a one-shot `RelayPool::run_once` for the same reason. This is the M:N trick the goroutine netpoller runs — **N legs ride ~`cores` worker threads** — releasing the threads parked in `read`, never the ones actively copying.

A masked leg, or a host where the arm fails, still falls back to one spawned blocking relay thread; that is the safe path, not the measured one.

## Rejected, and why

- **Adopt tokio / rewrite to `async`.** A second scheduler whose task wakes are the kernel CPU being removed, a whole-tree rewrite risking the byte-identity differential, and a violation of "no second way of doing something". The poller takes the same M:N win behind `Read`/`Write` with no signature churn.
- **Thread-per-leg with caps or smaller stacks.** A ceiling turns the tax into dropped connections; smaller stacks do not remove the context switch.
- **More buffered batching.** The wrong axis, shown above.
- **The TLS-raw fixed-worker poll relay, measured and rejected.** One 64 KiB non-blocking `poll` direction under the same seam cut threads 35 → 11 on `vless-tls-raw-down-8` (ubuntu-24.04-arm, five repeats) but lost to main on all three axes: 1963–2000 vs 2060–2104 MiB/s, 1611–1639 vs 1598–1648 CPU ms/GiB, 12.9 vs 11.8 MiB RSS. A 16 KiB window cut RSS further and fell harder; 128 KiB bought nothing. Thread count alone is not worth a throughput/CPU/RSS regression; the next attempt needs >16 flows (issue #387) or a shape that keeps main's byte path.

## The checker

A duration suggests; a thread count proves. `threads_peak` per engine per cell is recorded beside the paired throughput and CPU intervals in the same run. Measured cell `vless-raw-down-8` at five repeats; one-flow control `vless-raw-down-1`:

| cell | ferrox before | ferrox now | xray-core | zeronet |
| --- | ---: | ---: | ---: | ---: |
| ubuntu x86_64, 8 connections | 31 | 7 | 17 | 5 |
| ubuntu aarch64, 8 connections | — | 7 | 17 | 5 |
| windows x86_64, 8 connections | 39 | 11 | 11 | 9 |
| macOS aarch64, 8 connections | — | 6 | 19 | 4 |

At one connection the peak is **7** (both Ubuntu runners) and **11** (Windows) — the same as at eight; the number does not move with the flow count. Throughput gate passed in every cell (paired ferrox/xray-core midpoints 2.13×, 2.63×, 1.20×, and 1.28× at eight ties and 1.08× five-way median on macOS); CPU per GiB and peak RSS are lower than xray-core in the same cells.

The **idle-leg** half is still open for the carriered paths: the cell above carries active traffic, proving the fixed peak for raw TCP only. The pages' per-peer `pinned-threads` rows are the checker there, and `idle-legs-pinned-threads-per-connection` stays `UNBLESSED` until a carrier cell reads it.

## Status

`landed and measured` for the raw TCP data path: vless/vmess/trojan raw, the SOCKS client and freedom direct paths hand off to the fixed worker set, and the peak is 7 (Linux), 11 (Windows), 6 (macOS) at eight flows, unchanged at one flow. `open` for every carriered leg (`relay_stream`, `Half`, xHTTP idle connections, Shadowsocks, gRPC): those still hold a thread per parked leg, and no number here claims otherwise.
