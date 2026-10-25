# The loopback re-inject outbound

A `loopback` outbound names an inbound by tag, and a flow that reaches it is handled as if it had arrived on that inbound: the tag is resolved once at startup into the client dial the named inbound's own credentials imply, so the re-injected flow carries a real handshake on the loopback wire. The outbound's own `sniffing` block runs before that dial, so an HTTP `Host` or TLS SNI can replace the destination the front was asked for. There is no second routing pass here — fronts take the single outbound and servers take freedom — so resolving at startup *is* the whole re-inject, with no per-flow hop of its own.

Sniffing is the reference's TCP behavior: a loopback datagram keeps the named dial's datagram lane and is not read by the outbound's sniffer. A concrete dial always wins over the single front outbound: `find_loopback_outbound` resolves only when no `vless`/`vmess`/`trojan`/`http`/`shadowsocks`/`foxy` outbound matched, ahead of `freedom`. A loopback outbound is also a routing target and a default outbound, resolved by `route_shared` through the same tag. A config whose fronts should re-inject therefore carries `outbounds: [loopback, freedom]` and nothing more specific.

What refuses, and where: an empty or missing `inboundTag` skips the outbound the way other uncarriable settings skip theirs; a malformed `sniffing` block refuses at startup rather than silently not sniffing. Everything else fails at startup, naming the tag: an unknown tag, a front (which would re-enter the same resolution), no `freedom` outbound to leave by, transport security or a datagram carrier the redial cannot speak, and a relay-shaped Shadowsocks inbound that answers for fixed destinations rather than the re-injected target. The protobuf form stays refused: it carries only what the pinned scenarios name, and none names this.

## Data path

```mermaid
graph TD
    C["front: SOCKS / HTTP / mixed<br/>parses the destination"] --> R["startup: tag to client dial<br/>find_loopback_outbound + resolve_loopback"]
    R --> N["loopback sniffing, when enabled<br/>HTTP Host / TLS SNI → a name"]
    N --> L["local dial to 127.0.0.1:named-port<br/>real handshake, existing dial code"]
    L --> S["named inbound serves<br/>checks its own id, key or password"]
    S --> F["freedom dials the target"]
    F --> Z["0 bytes added by the re-inject<br/>1 relay copy per byte, the relay's own"]
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| tcp-echo-bytes-preserved | 65536 | ferrox-app-proxy::tests::a_re_injected_tcp_stream_carries_an_echo |
| udp-datagram-bytes-preserved | 4 | ferrox-app-proxy::tests::a_re_injected_udp_association_carries_a_datagram |
| sniffed-http-host-dials-the-sniffed-name | 1 | ferrox-app-proxy::tests::a_loopback_sniffing_overrides_the_re_inject_destination |
| route-targets-resolved-at-startup | 1 | ferrox-app-proxy::tests::a_loopback_outbound_is_a_route_target |
<!-- counts:end -->

Syscalls: one extra local TCP connect per flow plus the named inbound's own handshake reads and writes — no checker counts this yet. The sniffer adds `peek` calls on the client until it reads a whole HTTP head or a whole TLS ClientHello, or 200 ms pass; the re-inject itself adds none. Copies: the resolve stages nothing per flow, and the redialled session copies exactly what a direct dial copies, so the only copy is the relay's own — with no loopback-side pointer-identity test to separate it from a direct dial's, it stays prose, not a manifest row. The worst case the tests do not reach is a payload past both relay promotions: the 64 KiB echo already promotes each of the two relay legs past `RELAY_SMALL_BUFFER` once each, exactly as a direct dial promotes its one, and a larger payload only pipelines further — no second promotion, no deadlock, since both legs stay duplex.

## Ops

```bash
./scripts/count-ops.sh report \
  proxy::tests::a_re_injected_tcp_stream_carries_an_echo 'proxy::resolve_loopback'
```

`UNBLESSED`, as above.

## Time

**Not measured yet.** Durations in this repository come from CI runners (`bench.yml`, `parity.yml`); no CI artefact has been read, and a laptop behind a VPN measures a tunnel either way.

## What we removed

The dispatcher's per-flow re-entry. Xray's `Loopback::Process` hands the live link back to the dispatcher, which routes again under the new tag; ZeroNet caps that second look at `MAX_LOOPBACK_DEPTH` and xray-core-rust injects it through a `LoopbackSink` that errors aloud when unassembled. None of those pieces has anything to route here, so a re-inject is resolved once at startup into the named inbound's client dial: a front would re-enter the same resolution, and every server shape leaves by freedom, so no chain this tree can express goes around twice.

The sniffer no longer refuses. An enabled `sniffing` block is parsed with the reference's fields and applied before the TCP re-inject; when it is absent or disabled the outbound keeps the plain dial, so the unsniffed path allocates and reads exactly what it did before. The datagram half delegates to the named dial unchanged, because the reference's loopback `Process` has no UDP arm.

## What was not removed

The local hop itself. An in-process dispatch moves no handshake; this one dials `127.0.0.1` and handshakes as any client would, which costs one connect and the inbound's handshake bytes per flow. That is the re-inject the row names, not overhead around it, so it stays on the page rather than in a follow-up. The second routing pass stays for row 27: the named inbound's own routing rules are not consulted here, and xray would run them. The protobuf form stays refused alongside it: no pinned scenario names a loopback, so there is no seam to prove it through — the xray-core scenario suite has no loopback test, ZeroNet's loopback tests are in-process, and the xray-core-rust suite ships disabled.

## Pins

| what | where |
| --- | --- |
| re-inject into a named inbound tag, with sniffing | `upstream/xray-core/proxy/loopback/` |
| sink injection, explicit no-sink error, target validation | `upstream/xray-core-rust/crates/xray-proxy-loopback/` |
| depth cap, unknown-inbound error, balancer-member refusal | `upstream/zeronet/crates/zero-runtime/src/server.rs`, `upstream/zeronet/crates/zero-config/src/xray_json.rs` |
| no loopback protocol to take anything from | `upstream/sing-box/`, `upstream/xray-rust/` |

## CI scope

What a change here owes, read by `scripts/ci-scope.py`; see [`docs/ci-scope.md`](../ci-scope.md).

<!-- scope:begin -->
- paths: -
- symbols: find_loopback_outbound, resolve_loopback, loopback_dial, loopback_carrier, loopback_carrier_of, loopback_sniffing, loopback_asked
- go: ./proxy/loopback/...
<!-- scope:end -->
