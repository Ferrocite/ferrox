# Concurrency model

One decision, stated with its checker. This is the design answer to the thread/kernel-CPU tax the method pages name and batching does not remove; it is `planned`, not measured, and the one number it would move is `UNBLESSED` until a run reads it.

## The tax, honestly

Ferrox is a **pooled blocking relay**. Each accepted flow hands its directions to a `RelayTask` worker pool (`crates/ferrox-app/src/proxy.rs`): a worker runs a leg, and on completion parks itself in an idle lot a later flow can claim. Idle workers cost nothing. But a leg that is *waiting* — blocked in `read` on a socket the peer has not fed — holds its OS thread for the whole wait. So the thread a flow costs is not one-per-connection, it is **one-per-*active*-leg**, and "active" includes "blocked, waiting for bytes". At ten thousand quiet-but-open tunnels that is tens of thousands of threads parked in the kernel, each with a stack the scheduler must switch.

`xray-core` does not pay this. A Go goroutine blocked on a read is descheduled by the runtime netpoller and its OS thread released for other work; a per-connection goroutine is ~2 KiB of heap and a link in a run queue, not a kernel thread. The pages that admit the gap are honest about which half they closed: [`shadowsocks`](function/shadowsocks.md) says of its batch "the thread count did not move at all (36 before, 36 after)", [`carrier-xhttp`](function/carrier-xhttp.md) buys "a thread per idle connection", [`carrier-quic`](function/carrier-quic.md) "a thread per idle lane", and [`carrier-grpc`](function/carrier-grpc.md) prices "95% of this carrier's Windows cpu is kernel time".

## Why buffered batching is the wrong tool for *this* tax

Batching is real and it landed: `CHUNKS_PER_BATCH` folds four chunks into one `readv`/`writev` on Shadowsocks, and gRPC/xHTTP coalesce a frame's parts into one socket call per 256 KiB read. Every one of those cuts **syscalls per byte on the wire** — the throughput axis. None of them touches **threads per concurrency** — the connection-count axis. A batched read that returns quickly still blocks its thread when there is nothing to read; coalescing writes never un-parks an idle leg waiting on the far half. The two taxes are orthogonal, and the shadowsocks page already proved it by moving one and not the other. More micro-batching is not the answer here; the user is right that this needs a design, not another syscall shave.

## The chosen design: a readiness seam, not an async rewrite

Add a `Poller` behind the existing pool — `epoll` on Linux, `kqueue` on macOS, IOCP on Windows — so a blocking leg-read becomes three steps: register the fd for readability as a `RelayTask` *interest*, release the worker back to the idle lot, and re-claim a worker only when the fd is ready with bytes in hand. This is the same M:N trick the goroutine netpoller runs: **N legs ride ~`cores` worker threads**, and a thread is held while a leg has work, not while it waits. It does not release a thread for a leg that is actively copying — that leg was never the tax — it releases the ones parked in `read`.

The seam sits *under* the `Read`/`Write` contract, so nothing above it changes. Byte-identity is a claim about bytes, not about how a wait is slept through, and every codec/carrier keeps its synchronous `read_exact`/`write_all` shapes. It reuses machinery that already exists: the `RelayTask` lot is the worker set, and the `census` wait table (`crates/ferrox-app/src/census.rs`, `engine-budgets` in the superset) already registers each parked leg with the descriptor it blocks on — that table is both the design's bookkeeping and its checker. Linux already runs a `splice` `pull`/`push` copy shape for raw legs; the poller generalises "don't hold a thread for a wait" from one copy shape to every leg.

## Rejected, and why

- **Adopt tokio / rewrite to `async`.** A runtime is a second scheduler whose own task wakes are kernel CPU — the thing being removed — and rewriting every carrier's `Read`/`Write` to `Future` sweeps the whole tree and puts the byte-identity differential at risk for a change that is orthogonal to it. It also violates "no second way of doing something": there would be an async relay and the existing sync relay side by side. The poller gets the same M:N win behind a `Read`/`Write` interface with no signature churn above it.
- **Stay thread-per-leg and just cap/shrink stacks.** A thread-count ceiling turns the tax into dropped connections; smaller stacks do not remove the context switch. Neither answers the concurrency scaling, only hides where it fails.
- **More buffered batching.** Shown above to be the wrong axis.

## The checker (has to observe the thing the row claims)

A duration suggests; a thread count proves. The claim to gate is **idle legs pin no thread**, and the tree already carries its shape: `carrier-grpc.md` asserts `pinned-threads-per-silent-{preface,request-head,vless-request,tls-request,trojan-request,vmess-request,shadowsocks-request} = 0` against a silent peer. The seam generalises that per-peer assertion to a scale count — **live OS threads at N concurrent mostly-idle connections**, read from `/proc/<pid>/task` (Linux) or `task_threads` (macOS), gated in the `parity.yml`/`bench.yml` matrix beside the existing kernel-ms/GiB ratio against `xray-core`. Until a CI run reads it, `idle-legs-pinned-threads-per-connection` stays `UNBLESSED` on each page and this doc quotes no figure for it.

## Status

`planned`, its own slice — a cross-carrier change to the copy seam, not a method row and not a fold into any batching slice. The pool, the batch, the splice rung and the census table are the rungs already climbed; closing the concurrency axis is the one rung left between "bit-identical and not slower per byte" and "not slower per connection at scale".
