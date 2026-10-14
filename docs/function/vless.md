# VLESS over TCP

VLESS has no framing. One request header, then the stream is the stream, and
the whole method's cost is in reading that header without copying it and
encoding it without allocating.

The header is `version(1) | uuid(16) | addonsLen(1) | addons | command(1) |
address | port`. `addons` is a protobuf whose only field this tree honours is
`Flow`, the XTLS Vision selector; a header that carries a flow gets 2 add-on
bytes and nothing else. For `xtls-rprx-vision` the command byte and the address
are still written — Vision is a framing *around* VLESS, not a replacement for
its target field.

`request_header_len` is a pure function of the destination, so the caller knows
the exact length before reading anything. `encode_into` writes into a buffer the
caller owns. That combination is why `ferrox-bench` gate 2 can assert zero
allocations, zero allocated bytes and zero zero-fills for the encode at an
IPv4, an IPv6 and a domain destination.

## Data path

```mermaid
graph TD
    A["outbound needs a target"] --> B["request_header_len: the exact length,<br/>computed, not discovered"]
    B --> C["encode_into: version, uuid,<br/>addons, command, address, port"]
    C --> D["one write_all with header +<br/>the first payload in the same call"]
    D --> E(("wire"))
    F(("wire")) --> G["server: read the header<br/>address parsed in place"]
    G --> H["connect to the target"]
    H --> I["relay: copy in, copy out,<br/>no framing bytes added"]
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| request-header-allocations | 0 | ferrox-bench-gate-2 |
| request-header-bytes-zero-filled | 0 | ferrox-bench-gate-2 |
| address-families-encoded | 4 | ferrox-core-vless::tests::header_address_families_encode_stably |
| vision-addons-bytes | 2 | ferrox-core-vless::tests::non_vision_header_carries_empty_addons |
| reality-outbound-rows-dialled | 1 | ferrox-app-proxy::tests::vless_outbound_with_reality_security_dials_raw_only |
| vision-header-targets-matching-core | 2 | ferrox-app-proxy::tests::vision_header_matches_the_core_encoder |
| dial-header-reallocations | 0 | ferrox-app-proxy::tests::dial_headers_are_sized_to_the_bytes_they_hold |
<!-- counts:end -->

The relay buffer's zero-fills are prose, not a row. A row needs a checker that
sees the thing it names, and the only counter that sees a fill is `alloc_zeroed`:
the counting `GlobalAlloc` that could watch one `RelayBuf`'s whole life (`new()`
and one promotion) has to be installed by the test binary that runs the gate, and
this crate's test binary is where the tree's one blessed instruction count lives.
CI measured the collision — `der_to_pem` went `2653 → 2743` because every
allocation it makes grew a thread-local test — and a harness cost is not a change
to the product, so the allocator stays in `ferrox-core`'s own test binary, where
nothing is blessed, and the shape it proves is
`alloc_count::tests::an_uninitialised_tail_is_allocated_but_not_filled`: capacity
plus `set_len` and `vec![0u8; n]` are the same allocation and the same bytes, and
the fill is the only difference. The promotion's 240 KiB was never visible to any
counter here anyway — growing with `resize(.., 0)` writes the tail with
`write_bytes`, which is not `alloc_zeroed` — and the only counter that would see
it is an instruction count, which is the `UNBLESSED` row above.

## Ops

```bash
./scripts/count-ops.sh report \
  vless::tests::header_address_families_encode_stably 'ferrox_core::vless::VlessLink::encode_into'
```

`UNBLESSED`, as above.

## Time

**Not measured on this branch.** `.github/workflows/parity.yml` runs the
`vless-raw` scenario across the pinned engines for upload, download and
full-duplex; `.github/workflows/benchmark-matrix.yml` runs the same. Both are
CI-only. No artefact from this branch has been read.

## What we removed

- **A field-at-a-time header read.** This is the largest difference between the
  three implementations and it is not close. Xray's
  `proxy/vless/encoding/encoding.go:120` calls
  `addrParser.ReadAddressPort`, which issues a separate `io.ReadFull` for the
  port, another for the address type byte, then another per family, then one for
  a domain's length and one for its body — up to seven reads served out of one
  `BufferedReader`, so one syscall but seven slice splits and seven `Read`
  calls. sing-box's `sagernet/sing-vmess/vless/protocol.go:29-79` does the same
  thing against the **bare `net.Conn`**, so it is 6–8 real syscalls for a 19–34
  byte header, plus a `make([]byte, strLen)` and a `string(strBytes)` second
  allocation for a domain. Zray parses a slice in place with zero allocations.
  This tree parses in place too, and `parses_the_brief_link` and
  `header_address_families_encode_stably` are the gates.
- **A header written through a temporary.** sing-box's `WriteBuffer` path is
  already good — it extends the header into the pooled buffer's headroom and
  writes header and payload in one call — and this tree matches that shape
  rather than the `buf.NewSize` + copy shape beside it.
- **An 8 KiB buffer per connection that is thrown away.** Xray's
  `proxy/vless/inbound/inbound.go:286` does
  `buf.FromBytes(make([]byte, buf.Size))`, and because `FromBytes` marks the
  buffer `ownership: unmanaged` its `Release` is a no-op, so that 8 KiB never
  reaches `bytespool`. The relay buffer here starts at 16 KiB and is promoted to
  256 KiB only once a read fills it completely, and on Linux the plain `copy`
  path is `splice(2)` with no user-space copy at all.
- **The relay buffer's own `memset`.** Both of its fills were setup cost paid
  before the first byte arrived: `vec![0u8; 16 KiB]` reaches for `alloc_zeroed`,
  and `resize(256 KiB, 0)` on promotion writes another 240 KiB — 32 KiB per
  connection up front, since each direction has its own buffer, and 240 KiB per
  direction that ever sees a full read. None of it is read: the buffer's whole
  length goes to `read`, and `filled` hands back only the prefix that read
  reported, so the socket writes every byte before a caller can reach it. Both
  paths are `with_capacity` plus `set_len` now, the shape `read_into_tail` and
  the head reader already use. What that trades is stated plainly: the invariant
  is no longer enforced by the type, it is the fact that `as_mut` is only ever
  given to a `read`. A caller that compared or printed the whole buffer would be
  reading bytes nobody wrote, which is why `RelayBuf` lost its `Debug`, and why
  the two size gates (`a_relay_buffer_promotes_only_on_a_read_that_filled_it`,
  `a_promoted_buffer_returns_the_bytes_that_were_read`) fill the buffer before
  reading through it.

- **A reallocating dial header.** The app-side `vless_header` and
  `vless_vision_header` reserved a fixed 30 and 30+18 bytes, but an IPv6
  destination writes 38 and 56 — the family byte plus 16 octets instead of 4 —
  so every v6 dial, including this row's TLS path, overran the reservation and
  paid a heap reallocation, a copy, and a free on a 38-byte header. They now
  reserve the exact length (the fixed prefix plus `1 + 4` or `1 + 16` chosen
  from the destination family), so `capacity == len` and the buffer never
  grows. `dial_headers_are_sized_to_the_bytes_they_hold` holds the capacity at
  the length for both families and both header shapes; nothing got worse — the
  IPv4 shape also loses its 4 bytes of slack, and the bytes on the wire are the
  same the core encoder writes.

## Rows that are dialled

`security=reality` outbounds dial raw TCP
(`vless_outbound_with_reality_security_dials_raw_only`): the dial seals the
session id into a stock hello, verifies the bound leaf, and relays with or
without Vision. A REALITY row over any carrier is still skipped rather than
dialled, so those shapes stay server rows. The dial writes the same header
bytes the core encoder writes (`vision_header_matches_the_core_encoder`).

## Pins

| what | where |
| --- | --- |
| header layout, addons, address parsing | `upstream/xray-core/proxy/vless/encoding/` |
| header layout, field-at-a-time socket reads | `upstream/sing-box` → `sagernet/sing-vmess/vless/protocol.go` |
| slice parser, zero allocations | `upstream/zeronet/crates/zero-protocol/src/vless.rs` |