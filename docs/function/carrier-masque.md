# The MASQUE carrier

MASQUE is the RFC 9484 CONNECT-IP row, carried as the `masque` transport name and as a `protocol: masque` inbound: both roles over quiche/HTTP-3, and the same terminating server over TLS/HTTP-2 on the same port. An HTTP/3 `CONNECT` request names the path `/.well-known/masque/ip/*/*/`, `:protocol` `connect-ip` and a Basic credential; the server answers `200` with a Capsule-Protocol header, assigns one address per configured family over the request stream, advertises the default routes, and from then on every IP packet rides a QUIC DATAGRAM frame prefixed with the quarter stream id and a zero context byte. TCP and UDP inside the tunnel feed the same `wg_stack` seams the WireGuard row uses — the client resolves the flow's source from the local CIDR, the server routes each packet through the outbound table — so a packet too wide for the lane's next datagram is answered with the reference's ICMP Packet Too Big and the writing stack narrows to the MTU it names, while an ICMP echo request is not answered.

The server is the part xray-core owns that row 20 did not: an address pool built from the configured prefixes, one address per family per connection, the 401 challenge with `WWW-Authenticate: Basic realm="masque", charset="UTF-8"`, the 503 when a family is exhausted, and the per-capsule DATA frames the reference writes. Address containment is the reference's `inPool` — the network and broadcast addresses are inside a prefix and are therefore never handed to a stack — and a subnet grant is narrowed to its first host the way `prefix.Masked().Addr().Next()` does. The configured `host` wins over the SNI for the request authority, the path is compared after percent-decoding so `%2A` reads as `*`, and the user's email compares case-insensitively because the reference lowercases it in its validator. A configured WARP block is parsed and warned about rather than refused: its static address and mutual TLS are not carried.

The dialer collapses xray's user-agent selector to the pinned Chrome UA for `chrome`, `firefox`, `safari`, `edge` and `curl`; `golang` and an empty value send no user agent, and an absent value sends the same Chrome UA. A configured `remoteDNS` is warned about and names resolve on the host, because resolving them inside the tunnel would need the DNS forwarder this row does not carry. `enable_dgram` is set to quiche's `MAX_DATAGRAM` on both roles: the numbers are datagram payload bytes, and the reference's `QUEUE` constant is a queue depth, not a size.

## Data path

```mermaid
graph TD
    A["SOCKS / app flow"] --> B["wg_stack client:<br/>source from local CIDR, MTU 1280"]
    B -- "IP packet" --> C["datagram_prefix(stream,<br/>context 0)"]
    C --> D["QUIC DATAGRAM"]
    D --> E["quiche server conn"]
    E --> F["datagram_split:<br/>stream + packet"]
    H2["TCP + TLS (ALPN h2)"] --> H2F["HTTP/2 frames:<br/>SETTINGS + HEADERS"]
    H2F --> H2S["capsule stream<br/>(DATA frames)"]
    H2S --> F
    F --> G{"TCP or UDP?"}
    G -- TCP --> H["freedom dial, relay"]
    G -- UDP --> I["freedom datagram, relay"]
    H & I --> J["reply packet"]
    J --> C
    S["quiche server socket"] --> T["Header::from_slice<br/>local CID length 16"]
    T --> U{"known SCID?"}
    U -- no --> V["accept + worker thread"]
    U -- yes --> W["route to its stream"]
    V --> X["parse request:<br/>path → :protocol → auth"]
    X -- "401" --> Y["WWW-Authenticate, close"]
    X -- "200" --> Z["AssignAddresses,<br/>AdvertiseRoute"]
    Z --> E
    Z --> AA["register address → conn"]
    AA --> AB{"packet's destination<br/>in this conn's pool?"}
    AB -- yes --> F
    AB -- no --> AC["drop"]
```

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| tcp-echo-round-trips | 1 | ferrox-app-masque::tests::a_tcp_flow_crosses_the_tunnel_to_a_freedom_dial |
| ipv6-tcp-echo-round-trips | 1 | ferrox-app-masque::tests::a_tcp_flow_crosses_the_tunnel_over_ipv6 |
| udp-echo-round-trips | 1 | ferrox-app-masque::tests::a_datagram_flow_crosses_the_tunnel_to_a_freedom_dial |
| wrong-password-status | 401 | ferrox-app-masque::tests::a_wrong_password_is_refused_with_401 |
| path-forms-witnessed | 5 | ferrox-app-masque::tests::a_request_path_reads_the_way_xray_parses_it |
| pool-contained-addresses-witnessed | 2 | ferrox-app-masque::tests::a_pool_holds_every_address_its_prefix_covers |
| pool-outside-addresses-witnessed | 1 | ferrox-app-masque::tests::a_pool_holds_every_address_its_prefix_covers |
| subnet-grants-witnessed | 2 | ferrox-app-masque::tests::a_subnet_grant_names_its_first_host |
| datagram-prefix-round-trips | 1 | ferrox-app-masque::tests::the_datagram_prefix_round_trips |
| assignment-outcomes-witnessed | 5 | ferrox-app-masque::tests::an_address_capsule_withdraws_what_it_no_longer_grants |
| icmp-too-big-shapes | 2 | ferrox-core-connectip::tests::a_packet_too_big_swaps_the_addresses_and_verifies_at_both_versions |
| icmp-too-big-edges | 5 | ferrox-core-connectip::tests::a_packet_too_big_copies_options_and_refuses_a_narrow_mtu |
| icmp-mtu-narrows | 2 | ferrox-app-wg-stack::tests::a_packet_too_big_narrows_the_device_mtu |
| icmp-too-big-responses | 1 | ferrox-app-masque::tests::a_packet_wider_than_one_datagram_is_answered_with_icmp |
| h2-datagram-round-trips | 1 | ferrox-app-masque-h2::tests::an_h2_tunnel_assigns_and_carries_a_datagram |
<!-- counts:end -->

## Time

No duration is quoted here. The matrix's `vless-masque` cell and the `TestMasque` / `TestMasqueServer` / `TestMasqueServerClientToClient` conformance run are CI-only (`parity.yml`, `conformance.yml`); a local number would measure this machine's tunnel, not the code, so the page carries `UNBLESSED` for the retired-instruction count until the `ops.yml` artefact is read and the gate moves only with that measurement. What the counts above witness is shape, not speed: one TCP echo per family through the full tunnel, one UDP datagram, the 401 on a wrong password, and the pool's containment rule, five post-establish assignment outcomes, the Packet Too Big the two families compose, and one HTTP/2 tunnel's assigned address and echoed datagram.

## What we removed

- **The terminating server's separate packet forwarder.** The reference carries a dedicated CONNECT-IP server with its own netstack; this tree feeds the same `wg_stack` the WireGuard row already owns, so the server has no packet loop of its own — the capsule parser, the pool and the demux are the only new code.
- **A copy of the flow source.** The client's stack resolves the source from the local CIDR once per flow and the datagram prefix borrows the packet it was handed; no byte of the IP packet is copied to add the prefix.
- **The reference's per-request address manager.** The pool is one masked prefix per family, assigned and released under the same lock, with no goroutines or retry timers; a request whose family is exhausted is answered 503 rather than queued.
- **The reference's HTTP/2 server stack.** `golang.org/x/net/http2` is replaced by this tree's own frame head and HPACK decoder: the preface, SETTINGS with `ENABLE_CONNECT_PROTOCOL`, the extended CONNECT head, DATA and WINDOW_UPDATE frames are handwritten, and the capsule bodies reuse the same `connectip` encoders the h3 path writes. The h2 client leg is still open; the dialer stays h3.
- **What was not removed, named.** The IP packet still crosses one `Vec` from the tunnel receiver into quiche's datagram queue, the reply takes one more into the stack, and each capsule body is staged in a control buffer before its DATA frame; A packet too wide for one datagram is answered with the reference's ICMP Packet Too Big instead of dropped: the composer swaps the addresses, copies the header and eight bytes (or 1,232 for v6), and the v6 checksum covers the pseudo-header. The stack that wrote the packet narrows to the named MTU, so later segments fit; an ICMP echo request is still not answered, which the TUN inbound's responder covers on its own row. A post-establish `ADDRESS_ASSIGN` that omits or refuses an address closes the lane, as the reference closes its tunnel; the next flow opens a new lane, and a newly granted family is only used then. The h2 listener keeps one thread per connection and a 10 ms read wait: a packet queued for a peer this tunnel does not own leaves on the next turn, so a cross-connection forward is bounded by that wait rather than pushed by a writer thread.

<!-- scope:begin -->
- paths: crates/ferrox-app/src/masque.rs, crates/ferrox-app/src/masque_h2.rs
- symbols: masque
- go: ./proxy/masque/...
<!-- scope:end -->
