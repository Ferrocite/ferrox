# The DNS outbound

<!-- scope:begin -->
- paths: -
- symbols: find_dns_outbound, build_dns_outbound, decode_dns_rules, decode_dns_rule, decode_dns_legacy, decode_dns_network, serve_dns_tcp, serve_dns_udp, dns_lookup, dial_dns, read_dns_source, answer_handle, write_dns_frame, send_dns_query, dns_lane_tests
- go: ./proxy/dns/..., ./features/dns/...
<!-- scope:end -->
Row 26: a `dns` outbound answers DNS questions the way the reference's `proxy/dns` does. One flow opens a SOCKS CONNECT or a SOCKS association with the `dns` tag, and the lane behind it reads framed questions, decides each one against the rules, and answers from the resolver or relays the question out.

The decision is `ferrox-core`'s `dns` module, and its bytes are the reference's own. The oracle (`scripts/dns-oracle`) drives the pinned `xray-core`'s handler over every case the script carries — hijack, reject, drop, direct, oversize, a malformed name — over both networks, TCP framed and UDP raw; `ferrox-core`'s decisions are replayed octet for octet against that record (`ferrox-core-dns::tests::the_answer_is_the_bytes_the_pinned_go_writes`). The header the replies carry is the reference's own first block, AA bit included, and the A/AAAA answers point at the name with `C00C` the way its server punts.

The refusals are the reference's refusals. A query longer than `MESSAGE_MAX` (8192) is refused by the lane's own framing read before any decision; a compressed name that hops more than 10 pointers is refused; a name longer than 254 bytes is refused; a `0x40`/`0x80` question type is refused. The script's `broken` lines are the reference's own malformed inputs, and a replay of them writes nothing.

The config is the reference's shape — `{"settings": {"rewriteNetwork": "tcp"|"udp", "rewriteAddress": "...", "rewritePort": n, "rules": [{"action": "return"|"direct"|"hijack"|"block", "rCode": n, "qType": "1,28"|"...", "domain": "..."}]}}` — with the legacy `network`/`address`/`port` aliases filling the fields the rewrite spelling skips, as an unknown network name keeps the asked lane. A rule without an action, a `qType` that is neither string nor array-of-strings, and an `rCode` outside the 16-bit range build errors, and legacy `nonIPQuery`/`blockTypes` standalone build the reference's three-rule form. Mixed, they are a build error.

## Data path

```mermaid
graph TD
    C["client: SOCKS CONNECT / association"] --> G["the tag picks the DNS lane"]
    G --> D["decide: rules first,<br/>then the inline resolve"]
    D --> H["hijack / reject:<br/>the answer, written framed"]
    D --> F["forward:<br/>the question out, the answer back"]
    H --> C
    F --> C
```

## The lanes

The stream lane rides `serve_connect` after the refuse gate: one connection, framed questions each carrying their own two-byte length, answers framed by `write_all_parts` from the question's own buffers — the header and body leave in one loop and no third buffer exists. A lane end is the upstream's idle read, the reference's 300-second `ConnectionIdle` read, and a reply the lane cannot read whole (the length prefix over the maximum, the read ending early) ends the lane with the connection.

The datagram lane is `serve_socks_udp`'s shape: one association, one lane per client address keyed by the rewritten destination, the first datagram the payload that opens the lane, and the answers written back from the client-named destination. An upstream that has not dialled when the first datagram arrives dials it there, and the handoff parks the answer thread on the dial instead of polling.

The direct rule resolves inline: the name minus its root, the literal-IP fast path, then the engine's cached lookup, and an empty answer writes the reference's empty-answer reply. Name what is left: the stream lane reads each message into its own heap buffer, and the syscalls a loopback lane spends are only gated over real sockets as bytes — the counts a dial spends belong to CI's profile, not to a loopback test.

## What we removed

- **A copy of the resolver's address vector on every cache hit.** `cached_lookup` cloned the cached `Vec<SocketAddr>` and the answer was built from the clone; the entry now holds an `Arc<[SocketAddr]>`, so a hit is one refcount and the answer's own buffers are the only allocations, gated by `a_cached_lookup_answers_without_a_copy_of_the_cache` (`allocations-per-cached-lookup 2` — the record list and its one address). The entry and the first answer share the same address bytes, which the decision copies out of as before.
- **A second parse and a `Vec<SocketAddr>` for every literal name.** `dns_lookup` parsed the literal, discarded the address, and asked `to_socket_addrs` to parse it again into a vector it copied out of; the parsed address is now the answer, one allocation less (`allocations-per-literal-lookup 2`).
- **A heap buffer for every question, and one for every domain rule it matched.** `parse_query` built the name in a `Vec::with_capacity(NAME_MAX)` — a 254-byte allocation per message — and `Rule::applies` lowercased that name into a `String` per domain rule the question reached, a second allocation on the common forwarded path. The name now rides the `Question` (the `NAME_MAX` bytes the widest parse accepts, inline) and the fold lands in a stack buffer, so `decide` opens nothing for a question it forwards: `allocations-per-forwarded-question 0` is gated by `a_forwarded_question_is_decided_without_an_allocation`, which drives a mixed-case name through a full-match domain rule under the counting allocator, and `allocations-per-hijacked-question 1` by `a_hijacked_question_opens_only_its_answer`, which holds the returned answer as the only buffer a type-A hijack opens. The resolver's record list is handed to `ip_answer` as it stands instead of being collected into a `Vec<&[u8]>`, one allocation the answered path no longer pays. The bytes are unchanged: the replay against the pinned handler (`answer-cases-replayed`) still matches octet for octet, because the parse stores the same name bytes and `pack_name` writes them the same way. What is **not** removed: the stream lane's message buffer, one allocation per query it reads, and the resolver's own `rdata` vectors, one per address, which the decision receives rather than opens.

## Time

Nothing here is timed by a local run — every dial through this outbound is a connection a contributor's tunnel would measure, so the duration numbers are CI's `bench.yml` and `parity.yml` cells alone. The lane's own waits are the reference's: the upstream read that ends a lane is its idle timeout, and nothing in the decision path spins between a question and its answer.

## Gated counts

The decision's retired instructions are the decide probe's frame — `ferrox-core-dns::tests::the_decide_probe_costs_the_parse_rules_and_answer_and_nothing_else`, walked 4096 times so the frame is the method and not the caller that inlined it — read by `scripts/count-ops.sh` under the probe's own filter, the row the count gate now accepts per test. The inline question and rule buffers of #507 moved the frame from 55,544,745 to 60,123,580; two ops runs after that change returned 60,123,580.

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | 60123580 | scripts/count-ops.sh |
| answer-cases-replayed | 21 | ferrox-core-dns::tests::the_answer_is_the_bytes_the_pinned_go_writes |
| parse-refusals-replayed | 8 | ferrox-core-dns::tests::the_parse_refuses_what_the_reference_refuses |
| pointer-hop-cap | 10 | ferrox-core-dns::tests::the_pointer_loop_refuses_at_the_cap |
| maximum-name-bytes | 254 | ferrox-core-dns::tests::the_name_bound_matches_the_reference |
| allocations-per-forwarded-question | 0 | ferrox-core-dns::tests::a_forwarded_question_is_decided_without_an_allocation |
| allocations-per-hijacked-question | 1 | ferrox-core-dns::tests::a_hijacked_question_opens_only_its_answer |
| allocations-per-literal-lookup | 2 | ferrox-app-proxy::dns_lane_tests::a_literal_lookup_answers_without_a_socket_addr_buffer |
| allocations-per-cached-lookup | 2 | ferrox-app-proxy::dns_lane_tests::a_cached_lookup_answers_without_a_copy_of_the_cache |
| stream-answer-bytes-per-query | 38 | ferrox-app-proxy::dns_lane_tests::the_dns_stream_lane_relays_a_direct_query_byte_for_byte |
| datagram-query-bytes-per-datagram | 43 | ferrox-app-proxy::dns_lane_tests::the_dns_datagram_lane_relays_a_direct_datagram_byte_for_byte |
| datagram-answer-bytes-per-datagram | 58 | ferrox-app-proxy::dns_lane_tests::the_dns_datagram_lane_relays_a_direct_datagram_byte_for_byte |
<!-- counts:end -->
