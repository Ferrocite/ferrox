# The built-in DNS app

<!-- scope:begin -->
- paths: crates/ferrox-app/src/dnsapp.rs, crates/ferrox-app/src/dnsnet.rs
- symbols: build_query, parse_answer, resolve_endpoint
- go: ./app/dns/..., ./app/dns/fakedns/..., ./infra/conf/...
<!-- scope:end -->
Row 82: a `dns` block builds the resolver the relay's own name lookups use. A question rides one server's transport — UDP, a length-framed TCP stream, that stream under TLS, an HTTP/2 POST, or one QUIC bidirectional stream — and the answer is the small resolver's own bytes: the same core `build_query`/`parse_answer` the DNS outbound (row 26) already replays against the pinned Go. The app keeps A and AAAA apart per server, honours the reference's cache policy, serves the static `hosts` map with its ten-second TTL, and allocates fake addresses from the configured pools. Per-server `expectedIPs`/`unexpectedIPs` filter an answer before it can win, with `*` raising the filter to a priority that narrows rather than rejects; hosts `#rcode` answers as that rcode instead of falling through to a server. A protobuf `xray.app.dns.Config` decodes into the same block, including both filters and their `actPrior`/`actUnprior` flags. A server address is dispatched through the configured route and outbound, the way the reference's dispatcher carries it; the `+local` spellings and DoQ (always local in the reference) keep the direct dial, and a hostname in a UDP server address resolves locally before the SOCKS datagram frame is addressed. `enableParallelQuery` starts every group together, returns the first non-empty answer of the earliest `policyID` group and consults the next group only when all before it failed; a JSON block derives each policy ID from the reference's key (client IP, `skipFallback`, query strategy, tag, domains, expected and unexpected lists). The Lua `script` is named on stderr and the server list is queried in order. A routed query carries its server's `tag`, or the config's, as the inbound tag the route's rules see.

Routing's `IpIfNonMatch` and `IpOnDemand` resolve through this resolver, so a static host can steer a route before the dial.

The server forms are Xray's: a bare address (UDP), `udp://`, `tcp://`, `tls://`, `https://`, `h2c://`, `quic://`, `localhost`, and `fakedns`, each with the `+local` spelling where the pin carries one. DoH keeps the configured path exactly; an empty path becomes `/`, never an implicit `/dns-query`. DoH and DoQ pin the message id to zero and carry the reference's EDNS0 record — 1350-byte UDP size, class `0xfe00`, the client-subnet option from `clientIp`, and a random 100–300 byte DoH padding option. UDP and TCP take an increasing per-server id. Per-server `domains`, `queryStrategy`, `clientIp`, `timeoutMs`, `disableCache`, `serveStale`, `serveExpiredTTL`, `skipFallback`, `finalQuery`, `port`, and the root `queryStrategy`, `hosts`, `useSystemHosts`, `disableFallback`, `disableFallbackIfMatch` decode with the reference's spellings and aliases.

The fake pools follow the pinned allocator: the network base, an offset from the current millisecond modulo the pool's room count, the first unused address, wrap, and an LRU of the configured size. The LRU is a slot arena with its recency list threaded through the slots, so the oldest name is the list's head and a hit is a constant number of index writes rather than a walk of every held name. The defaults are `198.18.0.0/15` and `2001:2::/48`, 32768 names each when both families are on, 65535 for the single-family form, and TTL 1. The family-aware lookup seam is what a routing script's `xray.dns.Query` calls, and `domain_of` is the reverse seam; a normal `lookup` skips a `fakedns` server unless fake mode is asked for, matching the reference's `DisableFakeDNS` default.

## Data path

```mermaid
graph TD
    C["config: dns block and fakeDns"] --> P["Resolver::from_root: strategy, servers, hosts, pools"]
    L["one hostname lookup"] --> H{"hosts map matches?"}
    H -- yes --> A["the mapped IPs, TTL 10,<br/>or the rule's rcode"]
    H -- no --> S{"queryStrategy"}
    S -- UseSys --> Y["system resolver"]
    S -- UseIP / UseIP4 / UseIP6 --> M["match servers by domains,<br/>then fall back"]
    M --> G["policyID groups:<br/>race, then the next"]
    G --> F["expected / unexpected<br/>IP filter"]
    F --> R["route: the configured outbound"]
    R --> U["UDP datagram"]
    R --> T["TCP / TLS framed message"]
    R --> D["DoH POST over HTTP/2"]
    M --> X["+local and DoQ:<br/>direct dial"]
    X --> U
    X --> T
    X --> D
    X --> Q["DoQ over QUIC"]
    U --> K["cache: A and AAAA per server"]
    T --> K
    D --> K
    Q --> K
    K --> A
```

## What was removed

- **A walk of every held name on every fake-answer hit.** The pool held each name three times — a `String` in the name map, another in the reverse map, and a third in a `VecDeque` — and a hit walked the deque until it found the name and then pushed a fresh copy of it, so an answer that was already known cost `O(held)` string comparisons and one allocation. The recency order is now a doubly linked list threaded through one slot arena: a hit is the name map's index and four index writes and allocates nothing, an eviction is the list's head, and a freed slot is taken back by the next name. Each name is one `Arc<str>` shared by the map's key and its slot, where the queue form kept three copies. `a_fake_hit_allocates_nothing` holds the allocator to zero over a pool of 4096 names and the order unmoved, `a_fake_name_is_held_once` the one buffer per name (from three, `fake-name-allocations` 1), and `the_slot_pool_is_the_queue_pool_at_every_request` keeps the queue form as the oracle: three thousand draws over two hundred names on a sixty-four-name pool, comparing every address, every eviction and the whole recency order element by element.
- **A cache key allocation on every lookup.** The cache was one map keyed by `(server, name.to_owned())`, so a hit built a `String` before it could find the entry. Each server now owns a map keyed by the name alone, and a hit borrows the caller's name. The answer vector is still copied out of the record, and the routing vectors are still opened: `allocations-per-cached-lookup 4` is the measured count, not a claim that the cache hands out the record's own bytes.
- **A lowercase copy for resolvers with no rules to match.** `lookup_inner` and `host_lookup` folded the name unconditionally. They now fold only when a host rule or a server matcher exists, so the common configured-server lookup reaches the cache without a fold.
- **A second DoH client alongside the first.** `ech_dns` carried its own UDP, TCP and HTTP/2 exchange. It now calls the same `dnsnet` functions, so one place owns the framing, the HTTP/2 preface, and the response read.
- **A DNS query for the proxy's own server name routed through that proxy.** Outbound addresses now resolve through the resolver's local dial, so opening the tunnel never asks the tunnel to resolve its own far end.

What is **not** removed: the cache record owns its `Vec<IpAddr>` and the answer is a clone of it; the routing order and focus vectors are per-lookup allocations; the DoQ path ignores configured socket options; the Lua `script` warns and falls back to ordered server queries; a parallel query leaves every slower thread running after the first answer returns; a hostname in a UDP server address resolves through the system before the frame names it; the routed datagram pays a loopback relay and a thread per uncached query; and a fake answer is still a one-element `Vec<IpAddr>` of its own, with one name allocation on the miss that first holds it.

## Time

Nothing here is timed by a local run — a contributor's tunnel would measure the dial, not this code. Neither `bench.yml` nor `parity.yml` has a built-in DNS cell, so this page carries no duration and quotes none. The operations and syscall counts are `UNBLESSED` until an `ops.yml` artefact measures this method; `scripts/count-ops.sh` does not exist on macOS/aarch64, so the gate is CI-only here.

## Gated counts

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| syscalls-per-udp-exchange | UNBLESSED | scripts/count-ops.sh |
| allocations-per-cached-lookup | 4 | ferrox-app-dnsapp::resolver_tests::a_cache_hit_copies_only_the_answer_vector |
| fake-hit-allocations | 0 | ferrox-app-dnsapp::resolver_tests::a_fake_hit_allocates_nothing |
| fake-name-allocations | 1 | ferrox-app-dnsapp::resolver_tests::a_fake_name_is_held_once |
| seconds-per-lookup | UNBLESSED | CI bench.yml (no cell yet) |
<!-- counts:end -->
