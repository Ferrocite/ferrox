# Psiphon lane (its own client, its notices, and a local SOCKS hop)

The Psiphon console client (`psiphon-tunnel-core`) owns the tunnel, the server list, the shaping and the retry. This lane starts it once with a generated config, reads the one-line JSON notices it writes, waits for the port it announces and for a first tunnel, and then dials every flow through that local SOCKS server with the tree's own client lane. The process is a child of the lane and is ended with it; the flow path never formats a config, parses a notice or formats the announced endpoint again.

## Data path

```mermaid
graph TD
    A["outbound JSON: binary, listen, region, shape, upstream,<br/>split tunnel, local credentials, client knobs"] --> B["Settings: one read of every field<br/>env fallbacks only when the field is absent"]
    B --> C["build_config: app Json DOM, comments stripped from a base file<br/>mandatory listen, state and notice fields win"]
    C --> D["spawn psiphon-tunnel-core -config ... -dataRootDirectory ...<br/>stdin null, stderr notices, stdout null"]
    D --> E["notice(): one pass over the line, fields borrowed<br/>no DOM, no map, no allocation"]
    E --> F{"ListeningSocksProxyPort<br/>and Tunnels.count > 0"}
    F -->|no| E
    F -->|yes| G["SocketAddr and Arc<Credential> stored once in PsiphonOut"]
    G --> H["serve_connect: Outbound::Psiphon edge, clone shares the credential"]
    H --> I["dial_socks_client: greeting, CONNECT, relay_handoff"]
    I --> J["the child's local SOCKS listener"]
    G --> K["serve_socks_udp_client: UDP ASSOCIATE control leg<br/>held open until the client closes it"]
    K --> L["socks_udp_frame: address + payload to the relay"]
    L --> J
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| syscalls-per-notice-line | UNBLESSED | scripts/count-ops.sh |
| notice-scan-allocations-per-line | 0 | ferrox-core-psiphon::tests::a_notice_scan_takes_no_buffer_of_its_own |
| notice-line-copies-when-it-fits | 0 | ferrox-app-psiphon::tests::a_notice_line_is_visited_where_the_reader_holds_it |
| notice-line-allocations-when-it-fits | 0 | ferrox-app-psiphon::tests::a_notice_line_that_fits_the_reader_takes_no_buffer |
| flow-clone-allocations | 0 | ferrox-app-psiphon::tests::a_flow_clone_shares_the_credential_words |
| seconds-per-live-transfer | UNBLESSED | .github/workflows/psiphon-live.yml |
<!-- counts:end -->

`notice-scan-allocations-per-line` runs the scanner over a real `ListeningSocksProxyPort` line inside the counting allocator and holds the count at zero: the notice's kind, message and address point into the caller's line, so the readiness path allocates no DOM, no map and no owned string per line. The scanner's tests also pin the borrowed message and address, a malformed line, an escaped message, the tunnel count, and a line that is not one JSON object. `read_notice_line` visits the line inside the `BufReader`'s own buffer; `a_notice_line_is_visited_where_the_reader_holds_it` asserts the slice is the reader's buffer at the line's offset, and `a_notice_line_that_fits_the_reader_takes_no_buffer` holds the allocation count at zero. The `BufReader` buffer itself is allocated once when the reader starts, not once per notice; only a line longer than that buffer is copied into the spill, and `a_notice_line_longer_than_the_reader_is_joined_once` covers it.

`flow-clone-allocations` clones a started `PsiphonOut` inside the counting allocator and holds the count at zero. The credential is one `Arc<Credential>` shared by every clone, and the test checks both the allocation count and the two strings' pointer identity, so a future field that goes back to owning the words fails the row.

## Time

No bench cell and no conformance suite. Psiphon is an external program and a live network service, so a local duration measures the path to its servers, not this code. The readiness wait is bounded by `readySeconds` (default 180, capped at one day), and no duration is quoted. The only local gate is the fake client in `ferrox-app-psiphon`, which writes the two notices and holds the lane to the port it announced; it proves the startup contract, not throughput. `.github/workflows/psiphon-live.yml` is the live check: it builds the pinned console client, starts the lane, asserts an exact 1 MB transfer through the socks and mixed fronts, and sends a DNS query through the client's SOCKS5 UDP association. The runner's own egress and the console client with no lane are the controls. It runs on dispatch and weekly, never per push; its durations are reported against those controls and gate nothing. `.github/workflows/psiphon-windows.yml` runs the same lane on `windows-latest` twice, once with the pinned client and once with the console engine `Psiphon-Inc/psiphon-windows` bundles, then prints the pinned-over-Windows time and speed ratios for the same three legs. It is dispatch-only, fetches the GPLv3 pin at run time, commits neither its source nor its binary, and its ratios suggest rather than gate.

## What we removed against the reference

Xray-core, `sing-box` and ZeroNet carry no Psiphon lane and no `psiphon-tunnel-core` child, so there is no equivalent method to remove against; the only overlap is the SOCKS5 client, compared on [socks.md](socks.md), and the reference for this page is the pinned console client, with the live workflow's direct client control as its own baseline.

**The JSON DOM on the readiness path.** The reference writes each notice through a JSON decoder and an owned value tree. This lane scans the line once and borrows the fields where they landed, which is the zero-allocation row above. A message with an escape is left out rather than half-decoded, because the scanner refuses what it cannot return as a borrowed slice.

**A credential copied into every flow.** The outbound used to own its two credential strings, so every `Outbound::Psiphon` clone copied both. It now owns one `Arc<Credential>`; a flow clone bumps one refcount and shares the same bytes, and `a_flow_clone_shares_the_credential_words` holds the clone to zero allocations and the same string pointers.

**A stdout drain thread that read nothing.** The console client writes its notices to stderr; stdout was piped only to keep a full pipe from blocking the child, and a thread drained it. `Stdio::null()` gives the child a null sink instead, so the lane starts one thread fewer and never wakes for bytes it does not use.

**A config assembled through a serializer.** The client config is a small, fixed set of fields. It is written with the app's existing `Json` writer into one `String`; the lane does not add a serializer dependency, and a base config's comments are stripped in place with the core scanner before the overlay. The mandatory `DataRootDirectory`, `LocalSocksProxyPort` and notice fields are applied after the base file, so a sample config cannot silently move the lane's own state or port. The state directory must be owned by the current uid, and the config is opened with `O_NOFOLLOW` and 0600 on the open handle, so a planted symlink cannot redirect the write.

**The endpoint formatted and parsed per flow.** The scanner hands the announced port to the readiness thread, which stores one parsed `SocketAddr` in `PsiphonOut` beside the credential and version a flow needs. A flow borrows those fields; it does not join or parse `127.0.0.1:port` again, and it does not build a `SocksOut` of its own to reach the local listener.

**A 32-byte scan where the CPU can walk 64.** The AVX2 paths now load two 256-bit blocks per turn, check the low block before the high one, and hand a sub-64-byte tail to one 32-byte block and then the eight-byte SWAR scan. The order is the same as the byte scan: the first matching byte in the low block wins, then the high block, then the tail. `the_wide_scan_is_the_byte_scan` and `the_single_byte_scan_is_the_byte_scan` sweep every alignment and length through the widened paths.

**A second walk over every quoted field, and a trim before the parser.** The scanner stepped a quoted field byte by byte and `text` walked it twice, once to find the end and once to ask whether a backslash was inside. `next_quote_or_backslash` finds either byte one eight-byte block at a time and returns the field and its escaped flag from the same walk, so a readiness line costs one pass per quoted field. `strip_comments` uses the same word scan: outside a string it jumps to the next quote or slash, inside one to the next quote or backslash, and a block comment to its `*`. The notice reader's newline, the comment's `*` and its newline use `find_byte`, one lane instead of two, so they spend half the marks `next_of` would on the same block. `the_word_scan_is_the_byte_scan` holds the field scan to the byte scan at every alignment, `the_single_byte_scan_is_the_byte_scan` holds the one-lane scan to it over every pad and length, and `the_word_strip_is_the_byte_strip` holds the comment strip to the byte strip over twenty thousand random documents. The watch loop also handed `notice` a trimmed line built by `line_body`; the scanner already steps over leading and trailing space, so the raw line with its newline goes in and the copy is gone. `a_notice_is_read_from_the_line_with_its_newline` proves the raw line parses to the same notice.

**A byte-at-a-time config writer and reader.** The writer pushed one byte at a time and the parser pushed one `char` at a time, which also double-encoded non-ASCII text. `next_json_special` finds the next quote, backslash or control byte a word at a time; the writer copies the run before it with one `push_str`, and the parser copies the run as a UTF-8 `&str`. `the_word_scan_is_the_byte_scan_for_a_json_string` holds the scanner to the byte scan, and `a_written_string_is_the_bytes_the_parser_reads` round-trips control bytes and non-ASCII text.

**A copy of every notice line.** The watch loop read each line into a reusable `Vec` before parsing it. `read_notice_line` now visits the line where the reader holds it; only a line longer than the reader's buffer is copied, once, into a spill. `a_notice_line_is_visited_where_the_reader_holds_it`, `a_notice_line_that_fits_the_reader_takes_no_buffer` and `a_notice_line_longer_than_the_reader_is_joined_once` are the three checks.

What is **not** removed: the client's own TLS, server-list fetch, tunnel and pacing; one config write and one `create_dir_all` at startup; one `BufReader` per client; one process and one notice thread; and the SOCKS greeting and request every flow pays to the local listener; a no-auth flow writes the greeting, waits for the method reply, then writes the request, because the Psiphon client's Go SOCKS server rejects a request already sitting in its buffer. A credentialed flow writes the greeting, the credential and the request in the same order. The lane carries TCP and UDP. A stream flow pays the SOCKS5 `CONNECT` greeting and request; a datagram flow opens one SOCKS5 `UDP ASSOCIATE` control leg and frames every payload through the relay address the client names, so the client's local listener owns the datagram path; the upstream handshake is bounded by the handshake budget, and the client closing its control leg ends the lane rather than waiting out the idle budget. The client may still use its own QUIC transport to a server; that is the client's tunnel, not a datagram the lane claims to carry. The reference's modes, region validation, CDN fronting fields, split-tunnel regions, local proxy credentials, client features, latency multiplier, TLS/QUIC profile limits, tunnel and worker pool sizes, aggressive establishment, buffer/CPU limits, initial protocol limits, comments in a base config, server-entry file and `AETHER_PSIPHON_*` environment spellings are kept. The Shirokhorshid Android knobs are carried too: a `conduit` shape over the in-proxy WebRTC protocols, a personal compartment, the censored-proxy country list with its GeoIP database, `disableTimeouts` as a 0.1 latency lambda, alternate DNS resolvers, the device location/region/network id, base64 `AdditionalParameters`, the establishment timeout, byte-transfer notices and the built-in CDN edge profile with its custom SNI. A country list without a GeoIP database is not sent, because the client would ignore it; the lane says so in one line.

## References

| what | where |
| --- | --- |
| the client, its modes, config fields and notice parsing | `upstream/aether/aether/src/psiphon.rs` |
| the Shirokhorshid Android knobs and CDN edge list | `upstream/psiphon-tunnel-core/psiphon/frontedMeekCDNScanBuiltIn.go`, the Shirokhorshid `TunnelManager` |
| the Windows console engine the comparison runs | `upstream/psiphon-windows/src/3rdParty/psiphon-tunnel-core.exe` |
| the SOCKS5 client handshake and relay used by a flow | `upstream/xray-core/proxy/socks` |

## CI scope

What a change here owes, read by `scripts/ci-scope.py`. The fake-client test drives the lane through process spawn, config write, notice scan, endpoint storage and drop; it is the only local gate for the app seam. The live client is built from the pin by `psiphon-live.yml`; local gates never download it.

<!-- scope:begin -->
- paths: crates/ferrox-core/src/psiphon.rs, crates/ferrox-app/src/psiphon.rs, dist/ferrox-cli.sh
- symbols: find_outbound
<!-- scope:end -->
