# Psiphon lane (native SSH/OSSH, signed server list, local SOCKS and HTTP edges)

The lane no longer starts `psiphon-tunnel-core`. It fetches the signed server list, verifies the publisher's RSA signature, decodes the SSH entries, and speaks the OSSH/SSH transport itself: RC4 obfuscation with the seed message, curve25519 key exchange, AES-128-CTR with HMAC-SHA-256, password authentication, and multiplexed `direct-tcpip` channels. The proxy still sees one local SOCKS endpoint (loopback by default; `listen` and `shareProxyOnNetwork` can widen it), so its TCP and UDP paths are unchanged, and `LocalHttpProxyPort` adds the CONNECT front the reference client also exposes.

## Data path

```mermaid
graph TD
    A["outbound JSON: listen, region, readySeconds,<br/>serverList, serverListURLs, credentials,<br/>LocalHttpProxyPort, UpstreamProxyURL,<br/>LimitTunnelProtocols, TargetServerEntry, CustomHeaders"] --> B["Settings: one read of every field<br/>env fallbacks only when the field holds no usable value"]
    B --> C["fetch_list: zlib, JSON package,<br/>SHA-256 key digest, RSA PKCS#1 v1.5 signature,<br/>custom request headers"]
    C --> D["decode_entry: hex, five fields, JSON entry"]
    D --> E["Server: host, port, user, password,<br/>host key, OSSH key, region"]
    E --> F["Session::connect: four servers raced,<br/>optional upstream CONNECT or SOCKS5 hop,<br/>OSSH preamble, curve25519 KEX, host-key check,<br/>password auth"]
    F --> G["Psiphon local SOCKS listener"]
    G --> H["SOCKS4/4a CONNECT or SOCKS5 CONNECT"]
    H --> I["Channel: direct-tcpip, 2 MiB window,<br/>32 KiB packets, one reader dispatch"]
    G --> J["SOCKS5 UDP ASSOCIATE"]
    J --> K["udpgw: one channel to 127.0.0.1:7300,<br/>16-bit flow ids, framed datagrams"]
    K --> I
    L["LocalHttpProxyPort listener"] --> M["CONNECT only; 407 when a credential<br/>is configured and the request is not authorized"]
    M --> I
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-per-ssh-handshake | UNBLESSED | scripts/count-ops.sh |
| syscalls-per-relayed-megabyte | UNBLESSED | scripts/count-ops.sh |
| relay-staging-copies-per-byte | UNBLESSED | not measured |
| flow-clone-allocations | 0 | ferrox-app-psiphon::tests::a_flow_clone_shares_the_credential_words |
| seconds-per-live-transfer | UNBLESSED | .github/workflows/psiphon-live.yml |
<!-- counts:end -->

`flow-clone-allocations` clones a validated `PsiphonOut` inside the counting allocator and holds the count at zero. The credential is one `Arc<Credential>` shared by every clone, and the test checks the allocation count and the `Arc` pointer identity, so a future field that goes back to owning the words fails the row.

A relayed byte crosses one userspace copy in each direction: the socket into the pooled packet on the read side, and the client socket into the relay buffer on the write side. The outbound packet is encrypted where it was read, so no second copy carries it into a frame. No counter in this tree sees those copies, so `relay-staging-copies-per-byte` stays `UNBLESSED`; the counted rows above are the ones a checker observes.

The operation and syscall rows are unmeasured: the transport is new and `scripts/count-ops.sh` has no blessed count for it yet. `UNBLESSED` is an open claim, not a figure. The live workflows are the only checkers that see the path to a real Psiphon server.

## Time

No bench cell and no conformance suite. Psiphon is a live network service, and a local duration measures the path to its servers, not this code. The local edge is bound before a tunnel exists, so a refused startup is a retried dial rather than a lane that refuses to run; each dial gets at most 12 seconds, `readySeconds` (default 180, capped at one day) bounds the whole race, and four servers are dialed at once (eight when `beastMode` is set), so a server that accepts and then stalls costs one slot instead of the whole window, held by `a_stalled_server_does_not_hold_the_one_that_answers`. A batch that answers nothing is cut at the same 12 seconds, held by `a_stalled_batch_is_cut_at_its_budget`, so one slow batch cannot spend the whole readiness window; a session that finishes after its batch was decided is dropped and closes its own socket. `.github/workflows/psiphon-live.yml` starts the lane, asserts an exact 1 MB transfer through the SOCKS, mixed and HTTP fronts and a DNS query through the SOCKS5 UDP association, then runs the pinned Go console client on the same runner and pins it to the server and SSH/OSSH protocol the native lane selected, its SOCKS front on the same 10808 and its HTTP front on 10809 (the native lane's own HTTP edge is 10819, since its mixed inbound holds 10809), and prints native/reference speed, RSS and CPU. `.github/workflows/psiphon-windows.yml` runs the same SOCKS, HTTP and mixed transfer legs beside the engine `Psiphon-Inc/psiphon-windows` ships, checked against the blob hash the pin names; it does not run the UDP DNS check. The native legs gate; the reference legs are measurements, and the runner's own egress is the control. The Linux workflow runs on dispatch and weekly; the Windows one runs on dispatch only; neither runs per push, and their durations gate nothing.

## What we removed against the reference

The protocol reference is the pinned `psiphon-tunnel-core` console client; both live workflows now run it (or the engine the Windows client bundles) on the same runner and server as the native lane, with the SOCKS fronts on the same port, each HTTP front on its own port, and `TargetServerEntry` plus `LimitTunnelProtocols` pinning the server and SSH/OSSH shape, so a ratio compares the implementations rather than two carriers. Xray-core, `sing-box` and ZeroNet carry no Psiphon lane.

**The child process and its config.** The lane used to generate a client config, spawn `psiphon-tunnel-core`, read its stderr notices, and wait for `ListeningSocksProxyPort` plus a non-zero tunnel count. That is gone, with the config writer, notice scanner, `BufReader`, stdout drain, and the kill-on-drop path. The lane now owns the socket from the first byte.

**A second SOCKS server.** The reference's local SOCKS listener was a second server between the flow and the tunnel. The local edge here is the lane's own SOCKS4/4a and SOCKS5 server; it speaks the same wire shape the proxy already dials, so `proxy.rs` keeps one code path for both TCP and UDP.

**The reference's server-list client.** The lane fetches the list over its existing HTTPS account client, verifies the publisher digest and signature with `ring`, and decodes entries in place. It keeps the reference's local `serverList`/`serverEntries` file, the remote URL spellings (`RemoteServerListURLs` objects with base64 `URL` values included), custom request headers, the region filter, and the cached `server_entries.txt`.

**The reference's UDP gateway multiplexer.** One SSH channel to `127.0.0.1:7300` carries every flow. A 16-bit id selects the flow, the first write carries `rebind`, and a keepalive is ignored. Each SOCKS UDP association gets a local relay socket and a reader per destination, so replies return to the client that sent the datagram.

**The reference's second front and its upstream hop.** `LocalHttpProxyPort` binds the edge's IP on its own port and serves CONNECT there, answers `407` with a Basic challenge when `localProxyUsername`/`localProxyPassword` name a credential and the request is not authorized, and compares it in constant time; a credentialed edge refuses SOCKS4, which carries no credential exchange, rather than serving it open. `UpstreamProxyURL` dials the SSH server through an HTTP CONNECT or SOCKS5 hop, so a network that only permits its own proxy still reaches a Psiphon server.

**The fork's configuration surface.** `LimitTunnelProtocols` (and the legacy `TunnelProtocol`), `TargetServerEntry`, `CustomHeaders` (a string or an array of strings per name, as the reference accepts), `DisableRemoteServerListFetcher`, `SponsorId`, `EgressRegion`, `DataRootDirectory`, `DisableLocalHTTPProxy`, and the `shareProxyOnNetwork*` spellings are read, with the same meaning the console client gives them. Shiro's `protocolSelection` accepts `auto` and `direct`; `cdn_fronting` and `conduit` fall back to the SSH list with one line, because those carriers are not in this transport. Its `beastMode` widens the initial race from four servers to eight. A protocol limit keeps only the shapes this transport speaks (`SSH`, `UNFRONTED-SSH`, `OSSH`, `UNFRONTED-OSSH`); it names the values it ignores in one line, and a limit that leaves nothing falls back to the whole list rather than an empty lane. A credential is read the way the console client reads it: `localProxyUsername` and `localProxyPassword` must both be non-empty, and an empty word means no credential rather than an empty one.

**The read copy and the write copy.** The SSH reader used to pull every packet through a 256 KiB `BufReader` and then copy it into the pooled packet; it now reads the pool buffer directly. The client-to-tunnel relay used to copy every 32 KiB chunk into the writer scratch before encrypting it; it now encrypts the read buffer in place and sends header, ciphertext, padding and MAC with one vectored write. Both remove a memcpy per byte without changing the SSH payload, padding rules or MAC input.

**The reference's 128 KiB channel window.** The console client opens a channel with `ChannelWindowSize` packets of 32 KiB, four by default, and its own comment names the trade: a large window backlogs a bulk transfer ahead of new channels. The lane advertises a 2 MiB window and adjusts at 1 MiB, sixteen times the in-flight allowance on one flow, so a copy on a high-RTT path is capped by the path rather than by the window; the live workflows' 1 MB leg is the measurement.

**What is still refused.** QUIC noise profiles (`QUICNoiseProfile` presets, junk and signature datagrams before a QUIC handshake) and the built-in fronted-meek CDN scan candidate sets target carriers this lane does not speak (QUIC and fronted meek); in-proxy WebRTC, split-tunnel regions, Conjure and Tapdance, and the relay-side knobs have no native transport here. The lane names every setting it does not read in one line rather than pretending to honour it.

## References

| what | where |
| --- | --- |
| the signed package and server-list format | `upstream/psiphon-tunnel-core/psiphon/common/authPackage.go`, `psiphon/remoteServerList.go` |
| the server entry fields | `upstream/psiphon-tunnel-core/psiphon/common/protocol/serverEntry.go` |
| the OSSH seed message and RC4 key derivation | `upstream/psiphon-tunnel-core/psiphon/common/obfuscator/obfuscator.go` |
| the SSH client and `direct-tcpip` | `upstream/psiphon-tunnel-core/psiphon/common/crypto/ssh` |
| the udpgw framing and flags | `upstream/psiphon-tunnel-core/psiphon/udpgw.go` |
| the local SOCKS client and UDP relay | `upstream/xray-core/proxy/socks` |
| the local HTTP front and its credential | `upstream/psiphon-tunnel-core/psiphon/httpProxy.go`, `psiphon/localProxyAuth_test.go` |
| the QUIC noise presets the fork adds | `upstream/psiphon-tunnel-core/psiphon/common/noise/noise.go` |
| the fronted-meek CDN scan sets the fork adds | `upstream/psiphon-tunnel-core/psiphon/frontedMeekCDNScanBuiltIn.go` |

## CI scope

What a change here owes, read by `scripts/ci-scope.py`. The unit tests cover the RC4 vector, key derivation, the RSA DER wrapper, the signed-package shape, entry decoding, the SOCKS UDP frame, the udpgw frame, the HTTP proxy credential and the allocation-free clone. The live lane is built and run beside the pinned console client by `psiphon-live.yml`, and beside the engine `psiphon-windows` ships by `psiphon-windows.yml`; local gates never download or start a Psiphon client.

<!-- scope:begin -->
- paths: crates/ferrox-core/src/psiphon.rs, crates/ferrox-app/src/psiphon.rs, crates/ferrox-app/src/psiphon_ssh.rs, dist/ferrox-cli.sh
- symbols: psiphon_ssh
<!-- scope:end -->
