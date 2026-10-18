# HTTP proxy, both roles

Row 23: the `http`/`mixed` inbound answers a client (front), and the `http` outbound tunnels through an upstream proxy (hop). Both roles speak the same one-line grammar — a `CONNECT authority HTTP/1.1` to open a tunnel, an absolute-URI or origin-form head to forward a plain request — and both now pay for it in the caller's own buffer: the front's grant is one static byte string, the hop's CONNECT request is built with zero staging allocations, and a head that is already origin-form reaches the uplink where it landed.

## Data path

```mermaid
graph TD
    C["client: CONNECT, absolute-URI GET,<br/>or origin-form GET"] --> S["serve_http: read the head, split the request line once"]
    S --> G["grant: one static byte string per front"]
    S --> O["forward: origin-form head moves untouched,<br/>absolute-form rewrites the line only"]
    S --> X["dial_http_outbound: CONNECT built in the caller's buffer,<br/>authority pushed once, Host duplicated in place"]
    X --> Z["0 staging buffers per hop<br/>1 copy per byte, the relay's own"]
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| connect-grant-allocations | 0 | ferrox-app-proxy::tests::a_connect_grant_costs_no_heap_buffer |
| connect-request-allocations | 0 | ferrox-app-proxy::tests::the_connect_request_builds_in_one_buffer |
| forwarded-head-allocations | 0 | ferrox-app-proxy::tests::an_origin_form_head_reaches_the_uplink_where_it_landed |
<!-- counts:end -->

`connect-request-allocations` is gated on base and capacity held steady over a four-target sweep of the caller's `Vec` (name, bracketed name, v4 literal, v6 literal): the request reserve counts the authority without materialising it, so no CONNECT grows or replaces the buffer it was handed. `forwarded-head-allocations` is the moved head's own pointer and capacity asserted at the uplink writer — a rebuilt head would not be the same allocation. Copies the rows do not see stay out of the table: the in-buffer `Host` duplication is one copy per authority byte with no allocation to witness, and the front's head read is still `peek` then re-read, so two syscalls per request stand — named below, not blessed as a number.

## Ops

```bash
./scripts/count-ops.sh report \
  proxy::tests::the_connect_request_builds_in_one_buffer 'proxy::http_connect_request'
```

`UNBLESSED`, as above. `scripts/count-ops.sh` needs valgrind, which does not exist on macOS/aarch64, so this count is CI-only (`ops.yml`); nothing quotes it until the artefact has been read.

## Time

**Not measured.** `scripts/lib-matrix.sh` carries no benchmark cell for this row — no `http-*` scenario id exists — so `bench.yml` and `compare.yml` gate nothing here; the live shape is the `foxy-relay.yml` http-front legs, which download 1 MB through the front and do not gate on duration either.

## What we removed

The `String` the CONNECT was dialled through. The hop formatted its authority into a `String` and copied it twice into the request — into the request line and again into `Host:` — so one heap buffer and three walks of the authority bytes per tunnel. Now `authority_len` counts the octets without producing them (exact for a name and a v4 literal, the uncompressed bound `42 + digits(port)` for v6), `push_authority` writes them straight into the caller's buffer, and `extend_from_within` repeats them for `Host:` from where they already are. `the_connect_request_is_the_golden_bytes` pins the bytes unchanged — v4, v6 bracketed, basic-auth and custom-header shapes — and `the_connect_request_builds_in_one_buffer` holds the caller's pointer and capacity steady across the sweep, which is the allocation proof; the duplication it removes is visible only through the capacity gate, so that is what the row claims and no more.

The grant that was re-rendered per request. `Front::grant_line` returned a fresh `Vec` per call — `foxy_socks_reply(0).to_vec()` for SOCKS, a `to_vec()` of a literal for HTTP — and `direct_grant` built its own copy again beside it. Both answers are fixed octets, so they are now one `&'static [u8]` per front, shared by `grant_line` and `direct_grant`: `a_connect_grant_costs_no_heap_buffer` asserts the two calls hand back the same base pointer, that `direct_grant` hands back exactly that pointer, and that the bytes are the ones the old builders wrote.

The rewrite every forwarded request paid. An origin-form head — already `GET /path HTTP/1.1` as it landed — was run through `origin_head` like an absolute one, allocating a second head and copying every byte into it. The predicate now recognises the shape (CRLF line end, three line tokens, no trailing junk) and moves the caller's `Vec` to the uplink untouched; `an_origin_form_head_reaches_the_uplink_where_it_landed` asserts the forwarded head's base and capacity *are* the parsed buffer's, and that a four-token line and a bare-LF absolute line still get the rebuilt bytes the old path wrote. The request-line scan itself was fused too: the `\n` position found to split the line is handed to `origin_head` as `line_end` instead of being walked a second time — arithmetic on the same pass, which no row counts, so it stays here.

Against the references: xray-core's hop builds an `http.Request` with a `url.URL` and a `http.Header` map and hands it to `req.Write` (`upstream/xray-core/proxy/http/client.go:211-235`), and its front writes the `200` as a fresh `[]byte` per request (`server.go:173`); sing-box routes its CONNECT through its `transport/http` client stack the same way. Neither re-walks what this tree now copies zero times — the map, the URL and the per-request byte slice exist there, and none exist here.

## What was not removed

The absolute-form rewrite still allocates: a `http://`-form head leaves as a fresh `Vec` with every byte copied once, because its request line changes and `Vec` cannot shrink an allocation in place. The front's head read still costs `peek` plus re-read: `read_http_head` is what `serve_http` calls, because a CONNECT head that keeps the bytes behind `\r\n\r\n` has nowhere to put them — only the `Freedom` and Foxy-direct legs can accept a pipelined prefix today, so the kept-head reader swap is its own slice and this page only prices the calls it carries. `Destination::authority()` still returns a `String` for the Foxy cache key beside it (`proxy.rs:5856`); the CONNECT builder no longer calls it, and no other hot rung does, so it stays. The base64 credential still walks `user:pass` through `EncoderWriter` into the same request buffer — one pass, the encoder's own tail cache unchanged. And the relay copy per byte is the relay's own, counted nowhere in this page.

## Pins

| what | where |
| --- | --- |
| CONNECT hop via `http.Request`, per-request `200` write | `upstream/xray-core/proxy/http/` |
| h1/h2/h3 client stack, extended CONNECT errors | `upstream/sing-box/transport/http/`, `upstream/sing-box/protocol/http/` |
| socks-side CONNECT grant shapes to keep byte-identical | `upstream/zeronet/crates/zero-protocol/src/socks.rs` |

## CI scope

What a change here owes, read by `scripts/ci-scope.py`; see [`docs/ci-scope.md`](../ci-scope.md). The run's oracle is the `xray-core` pin's four http scenario tests (`TestHttpConformance`, `TestHttpError`, `TestHTTPConnectMethod`, `TestHttpPost`), which the pin's suite already names as its whole list — no `oracle:` pattern can narrow it further, because the suite has no `--` name list to filter.

<!-- scope:begin -->
- paths: -
- symbols: serve_http, http_proxy, http_proxy_request, http_request_parses, http_connect, connect_request, connect_grant, connect_authority, origin_head, origin_form, grant_line, direct_grant, SOCKS_GRANTED, authority_len, push_authority, authority_target, http_outbound
- go: ./proxy/http/...
<!-- scope:end -->
