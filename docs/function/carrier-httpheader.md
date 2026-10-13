# The HTTP masquerade carrier

VLESS and VMess and Shadowsocks and Trojan all ride this carrier, which is the
cheapest one in the matrix: a request head with `Connection: upgrade` and a
matching response, and then no framing at all. It exists so a connection looks
like HTTP to something in the middle, and it costs one `memcmp`-shaped scan.

`read_http_head` is the interesting part and it is shared with every carrier
that has a handshake head. It uses `peek` to find `\r\n\r\n` and then reads
exactly that many bytes, so it never over-reads into the payload. The price is
one syscall for the `peek` and one for the `read`, per handshake. That is the
cost of *not* over-reading, which is the right trade at the head and the wrong
one per frame — see [the WebSocket page](carrier-websocket.md) for where the
per-frame cost was removed instead.

## Data path

```mermaid
graph TD
    C["client: POST or GET with the<br/>camouflage head"] --> S["server: peek, scan for CRLFCRLF"]
    S --> S2["read exactly the head"]
    S2 --> V["validate path and host"]
    V --> B["inner socket: bytes in, bytes out"]
    B --> Z["0 framing bytes added<br/>1 copy per byte, the relay's own"]
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| framing-bytes-added | 0 | ferrox-app-httpheader::tests::header_carries_an_echo_over_loopback |
| user-space-copies-per-byte-relayed | 1 | ferrox-app-proxy::tests::carried_streams_round_trip_behind_the_http_camouflage |
<!-- counts:end -->

## Ops

```bash
./scripts/count-ops.sh report \
  httpheader::tests::header_carries_an_echo_over_loopback 'proxy::read_http_head'
```

`UNBLESSED`, as above.

## Time

**Not measured on this branch.** The HTTP camouflage scenarios run in
`benchmark-matrix.yml` and `parity.yml`; no artefact from this branch has been
read.

## What we removed

Nothing on the data path. Two things are named because they are easy to get
wrong rather than because they were fixed:

- The 8 KiB head limit (`HEAD_LIMIT = 8192`) is a *limit*, not a buffer. A
  carrier that reads its head into a 64 KiB window to be safe pays 64 KiB of
  allocation per handshake to reject the same request one round later.
  `header_rejects_a_wrong_path` and the shared `read_http_head` limit check are
  the gate.
- `read_http_head`'s `peek`-then-`read` is two syscalls per round and no
  allocation: the tail is `read_exact`'d straight into the head's own spare
  capacity, so the bytes are never staged in a second buffer and zero-filled
  before they are overwritten. `bytes_pipelined_behind_a_head_stay_in_the_kernel`
  is the gate that the second pass leaves the pipelined tail untouched.
- A timed-out read is retried until the head's own budget runs out
  (`proxy::HEAD_DEADLINE`, twenty seconds, the header budget the rest of this
  binary already gives a handshake), and the socket is armed with `RELAY_POLL`
  for the rounds if the caller armed nothing — so a peer that connects and stays
  quiet is a refused handshake, not a thread parked in `peek` or a loop that
  wakes once per poll forever. The price is two `setsockopt` per handshake (arm,
  restore); the socket is handed back with the timeout it came with, which the
  gate asserts. `a_quiet_peer_ends_both_head_readers_at_their_budget` is the gate.

## Pins

| what | where |
| --- | --- |
| head read, `BufferedReader`, `http.ReadRequest` | `upstream/xray-core/transport/internet/headers/` |
| head read, pooled buffer | `upstream/sing-box` → `transport/v2rayhttp/` |
| `scanned` head scan, no over-read | `upstream/zeronet/crates/zero-transport/src/httpupgrade.rs` |