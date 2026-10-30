# Ferrox on macOS and Windows

Windows packages ship `ferrox-cli.exe`, a native launcher with the same commands and flags as the shell CLI below. Replace `./dist/ferrox-cli.sh` with `.\ferrox-cli.exe` (or just `ferrox-cli` on `PATH`); the release package keeps the binary beside it, so no Bash, WSL or Python is needed. `--vpn` is supported on Windows through the WinINET system proxy; macOS `--vpn` remains in `ferrox-cli.sh`.

Two things were built here, from the same release binary — a release package from the `release` workflow ships the second and third of these beside the binary, and finds it without cargo:

| what | where |
| --- | --- |
| the binary | `target/release/ferrox-app` (arm64, `ferrox-app 0.0.1`) |
| the CLI | `dist/ferrox-cli.sh` — every lane, every front, ports, system proxy |
| the Windows CLI | `ferrox-cli.exe` — the same commands natively; `--vpn` uses the Windows system proxy |
| the app | `dist/Ferrox.app` — the same CLI behind a double-click |

`ferrox-cli.sh`, this page and `README.md` are tracked so the release job can ship them; everything else under `dist/` — the bundle, its build script, any lane config — stays git-ignored, and so does every file that carries an account.

## 1. The account

The Foxy lane needs a Firefox account, and it is the only credential this tool holds — an email and a password, with no server to name: the edge comes from Mozilla's catalogue. The simplest way in is the connect command itself: the first `up --foxy` notices there is no account stored, asks for the email and the password (hidden), saves them once, and connects:

```bash
./dist/ferrox-cli.sh up --foxy --vpn         # asks once on a fresh machine, then carries
```

Saving up front is the same one prompt, ahead of time, and `login --email E --password P` is its non-interactive form. Either way the account lands in `~/.config/ferrox/credentials`, outside the repository, mode 0600:

```
~/.config/ferrox/credentials
FOXY_EMAIL='you@example.com'
FOXY_PASS='the-password'
```

`ferrox-cli` reads it, or `--email` / `--password`, or `FOXY_EMAIL` / `FOXY_PASS` in the environment. A copy inside the repository is refused when git tracks it. Nothing in this tool writes a password into a tracked file, and `/lane.json` and `/pass.json` are ignored.

The lane is handed the account, not a saved pass: the pass the edge accepts lives 600 seconds, so a lane given only a pasted token stops carrying when it expires and cannot replace it. Signed in, it renews on its own clock and a lane left running overnight keeps working. The account plane rate-limits sign-ins with `429`, so `up` signs in once and the lane reuses that session's refresh grant.

That sign-in is also the only one. The first launch writes the session FxA returned — its access token, its refresh token, the account it belongs to, and a two-factor sign-in that has not been verified yet — to `~/.config/ferrox/foxy-token.json`, mode 0600, outside the repository. Every launch after it resumes that grant: a live access token mints the pass with no sign-in at all, a lapsed one is refreshed in place, and the password only reaches FxA when the plane refuses the grant (or `logout` or `login` removed it). That is why Mozilla sends a new-sign-in mail on the first launch and not on the rest: no `/account/login` request is made. The browser challenge, when the plane asks for one, is solved locally by the binary, so it never waits for a person. `ferrox-cli logout` stops the lane and removes the session, the saved account and the lane config; `ferrox-cli login` replaces the account and clears the old session.

## 1b. Choosing an exit

The catalogue is public and unauthenticated, so the location list needs no account:

```bash
./dist/ferrox-cli.sh locations              # every country, and the cities each one publishes
./dist/ferrox-cli.sh locations US           # one country in detail
./dist/ferrox-cli.sh locations --ping       # the same list, nearest exit first
./dist/ferrox-cli.sh locations --ping US    # one country, its cities by latency
./dist/ferrox-cli.sh location DE            # remember Germany for every up
./dist/ferrox-cli.sh location US SFO        # remember a country and a city
./dist/ferrox-cli.sh up --foxy --vpn        # connects to the remembered exit
```

The list prints one line per country and one per city with the number of published edges, marks the remembered choice with `*`, and keeps the raw JSON rows in `~/.config/ferrox/foxy-locations.jsonl`; when the catalogue cannot be reached, the last copy is what `locations` prints. `--country` and `--city` still win over the remembered exit for one launch and become the new remembered one. `REC` is the catalogue's recommended country: it picks the exit Mozilla considers best and verification accepts whichever country that edge reports.

`--ping` adds one TCP handshake per edge and prints its time in milliseconds. Countries and cities sort fastest first, and `REC` stays at the top because it is a recommendation rather than a measurement. An edge that does not answer inside 1.5 s prints `no answer`, the same silence that would cost a flow its dial. The reading is this machine's own path to the edge's TCP port: it measures the hop, not the MASQUE session, and an `--upstream` hop is not in it. The readings are not kept: `foxy-locations.jsonl` stores the rows without them, and an offline `locations --ping` says the latency was not measured instead of printing stale numbers.

## 2. Connect (CLI)

```bash
./dist/ferrox-cli.sh up --foxy                 # lane up, three local fronts (asks for the account first time)
./dist/ferrox-cli.sh up --foxy --vpn           # plus the macOS system proxy
./dist/ferrox-cli.sh up --foxy --country DE --carrier h2
./dist/ferrox-cli.sh up --foxy --exclude-domains printer.lan --exclude-ports 22,53
./dist/ferrox-cli.sh up --foxy --socks 1080 --http 8081 --mixed 1082
./dist/ferrox-cli.sh up --foxy --instance work --country DE   # a second lane, own ports
./dist/ferrox-cli.sh status                    # uptime, carrier, quota, exit IP and country
./dist/ferrox-cli.sh status --instance work    # the same, for the named lane
./dist/ferrox-cli.sh down                      # stop, clear the system proxy
./dist/ferrox-cli.sh down --all                # stop every lane
```

`up` prints the port map, then proves one flow through the first front. With `--vpn` it arms the macOS system proxy only after that flow answers, so a lane that carries nothing never takes the machine's traffic with it. If the fronts are open but no flow gets through, it says so, shows the lane log, and stops the lane itself: the pid file and config are removed and the proxy cleared, so nothing needs a `down` and nothing is left behind except the log.

On a terminal `up --foxy` also asks which carrier to use — `auto` (h2, then h1, then h3), `h2`, `h1` or `h3` — and an empty answer or a pipe takes `auto`, so nothing needs typing. `--carrier` skips the question. `h2` is the rung `auto` opens on because it outran `h3` on every CI runner, and `h3` is the only carrier that also carries UDP. A named `h3` is a preference rather than a pin: it leads, and `h2` and `h1` follow when the path drops QUIC, which is silence rather than a refusal. `status` reads back how long the lane has been up, the carrier it was given, the allowance the plane last named (bytes left of the plan, and when they reset), and the exit IP and country. An allowance that is not there is named, not skipped: either the plane sent no quota header for the pass this lane carries, which is silence rather than zero, or the running lane was started by a binary that names neither the carrier nor the allowance, and `down` then `up` restarts it on the binary this script runs.

`--exclude-domains` and `--exclude-ports` split the tunnel: a target whose host is one of the named suffixes or a subdomain of one, or whose port is listed, leaves the lane and is dialled directly. Excluded traffic is neither carried nor encrypted by the lane, so keep the list to targets that are already private, such as a LAN printer or a port that must stay on the local network. `*.example.com` and `.example.com` are accepted and mean the same as `example.com`, which covers that name and its subdomains but not `notexample.com`. The list belongs to one launch: it is not remembered, and another lane refuses it by name.

An `up` that cannot start the lane it names fails before anything starts: `--vless` with no link prints the example, `--vmess` without `--uuid` names the id, every flag missing its value says which flag — and none of them stops a lane that is already carrying traffic. `ferrox-cli version` prints the binary's release.

## 3. Ports, and what each one serves

| front | default | what it is |
| --- | --- | --- |
| SOCKS5 | `127.0.0.1:10808` | SOCKS5, no local auth, hostnames resolved at the exit, UDP ASSOCIATE rides the lane |
| HTTP + HTTPS | `127.0.0.1:8080` | one port for both: `CONNECT` tunnels (that is HTTPS) and plain `http://` forwards |
| mixed | `127.0.0.1:10809` | sniffs the first byte, serves SOCKS5 or HTTP on one port |

All three bind loopback only. Change them with `--socks`, `--http`, `--mixed`, or serve a subset with `--fronts socks,http`.

### Several lanes at once

`--instance NAME` starts a second lane beside the unnamed one: its config, pid, log, ports and remembered exit are its own, while the account and the edge catalogue stay shared. Ports left unnamed are the first free ones near the defaults, so a second lane never fights the first; `--socks`, `--http` and `--mixed` still pin them, and a port outside 1-65535 or two fronts on one port is refused before anything starts.

```bash
./dist/ferrox-cli.sh up --foxy --instance work --country DE
./dist/ferrox-cli.sh up --foxy --instance home --country NL --socks 10818 --http 8088
./dist/ferrox-cli.sh status --instance work
./dist/ferrox-cli.sh down --instance work
./dist/ferrox-cli.sh down --all
```

`--vpn` belongs to the unnamed lane: the macOS system proxy is one machine-wide setting, so point the app you want at the instance's fronts (`ferrox-cli ports --instance work`). `status` with no instance names the other running lanes when the unnamed one is down, and `logout` stops every lane.

### macOS system proxy

System Settings > Network > the active service > Details... > Proxies:

- **Web proxy (HTTP)** `127.0.0.1:8080`
- **Secure web proxy (HTTPS)** `127.0.0.1:8080`
- **SOCKS proxy** `127.0.0.1:10808`

Leave "Proxy server requires password" off: the fronts are unauthenticated and only reachable from this machine. HTTPS needs no certificate: the proxy opens a `CONNECT` tunnel and TLS stays end to end between the app and the site.

`ferrox-cli up --vpn` writes exactly those three settings on every network service and `down` clears them. `scutil --proxy` shows what macOS believes.

### One app instead of the whole system

```bash
curl --socks5-hostname 127.0.0.1:10808 https://www.cloudflare.com/cdn-cgi/trace
curl -x http://127.0.0.1:8080 https://www.cloudflare.com/cdn-cgi/trace
HTTPS_PROXY=http://127.0.0.1:8080 ALL_PROXY=socks5h://127.0.0.1:10808 git clone ...
```

Use `socks5h://` (not `socks5://`) so the name is resolved at the exit instead of on this machine.

## 4. Modes

**Ports mode** (`up --foxy`): the three fronts, nothing else touched. One app at a time, or a browser profile pointed at a port.

**VPN mode** (`up --vpn`): the same fronts plus the macOS system proxy. This covers TCP apps that honour the system proxy — browsers, most Electron apps. It is not a tunnel: apps that ignore the system proxy, and UDP, are not captured.

**TUN mode** (`--tun`): refused by name. This binary has no `tun`/`utun` inbound and no tun2socks engine (README rows 29 and 58), so there is no device-wide capture. `ferrox-cli tun` prints the same explanation. A config that names a device inbound is refused with its reason rather than served as silence.

## 5. Every other lane

The binary serves and dials far more than Foxy; `ferrox-cli` writes the config for each:

```bash
ferrox-cli up --vless 'vless://uuid@host:443?type=ws&security=tls&sni=host&path=/ws'
ferrox-cli up --veepn --region us-va      # anonymous: no account, no server
ferrox-cli up --vmess host:443 --uuid ID --network tcp
ferrox-cli up --trojan host:443 --password PW
ferrox-cli up --ss host:8388 --method aes-256-gcm --password PW
ferrox-cli up --config mine.json          # served verbatim, any inbound/outbound
```

The vless converter writes `tcp`, `ws`, `grpc`, `httpupgrade` and `xhttp`, with `security=none|tls|reality`. Anything else (kcp, quic, hysteria, httpheader, masque, xdrive) goes through `--config`: those are config shapes this binary already serves, and the converter does not guess at them. A share-link lane with no link, a missing `--uuid`, or a missing password is refused before the lane starts, with the example to run.

`--veepn` is the one lane that needs nothing typed in. The plane launches this device anonymously, names the fastest region (or the one `--region` pins, with `--country` as its alias), and lists the upstreams that answer `Basic` for the pair it printed. The region ids are the plane's own, lowercase and from its free pool (`nl`, `us-va`, `us-or`, `gb-lnd`, `fr-prs`, `sg`, `ru-spb` at the time of writing); a typed id is lowered for the ask, and a name the plane does not list is answered `422` and diagnosed as such. The device id the plane sees is kept in `~/.config/ferrox/veepn.udid` (mode 0600), so a restart is the same device; `--domains` replaces the seven API origins this build ships with, and `--udid` names the identity outright.

A config file can carry any inbound the binary serves — `vless`, `vmess`, `trojan`, `shadowsocks`, `hysteria`, `socks`, `http`, `mixed` — and any outbound — those plus `foxy`, `veepn`, `http` and `freedom`.

## 6. The app

```bash
open dist/Ferrox.app
```

Double-clicking it opens a Terminal window with a menu: connect the Foxy or VeePN lane with the system proxy or ports-only, change the ports, another lane, status, the port map, the TUN explanation, stop. Closing the window stops the lane.

Drag `dist/Ferrox.app` to `/Applications` to keep it. It is ad-hoc signed, so the first launch may need right-click > Open.

## 7. Rebuild

```bash
./dist/build-macos-app.sh        # binary + CLI + connect script into the bundle
```

## 8. When it does not work

| symptom | cause |
| --- | --- |
| `lane up`, then "no flow got through" with `429` in the log | the account plane is rate-limiting sign-ins; wait it out, a second login does not buy bytes back |
| same, with `did not sign in` | the account or password is refused, or the account wants a two-factor code: `up --foxy --code 123456` |
| same, with `the stored session was refused` | the saved grant was revoked or expired and the password fallback is not there: `ferrox-cli login --email you@example.com`, or delete `~/.config/ferrox/foxy-token.json` |
| same, with `401`/`403` after a sign-in that worked | the edge refuses this account's pass at this exit: the subscription or its devices say otherwise; try `--country`, and check the account on vpn.mozilla.org |
| same, with "the TLS handshake with the edge failed" | this network blocks TLS to `*.fastly-masque.net:2499`; see below |
| `the lane did not open its fronts` | the port is taken (`lsof -nP -iTCP:8080`), the config names an inbound this binary refuses, or its `settings.pass` is past its `exp` and nothing can replace it |
| a browser works, `curl` does not | `curl` ignores the system proxy: pass `-x` or `--socks5-hostname` |
| VeePN says "every upstream … declined" | the plane's edges are unreachable from this network: try `--region`, or `--domains` with an origin that answers |
| VeePN says "does not list the region" (`422`) | the id is not in the plane's free pool, or was spelled differently: its ids are lowercase (`nl`, `us-va`), and leaving `--region` off lets the plane pick |
| VeePN says "refuses its pairs" | the plane retired the pair it listed; `up` again fetches a fresh list, and `--region` moves the exit |
| VeePN says "granted the CONNECT and then closed" | the edge accepted the pair but this network's path dropped the tunnel: the lane is healthy, the egress is not; use a hop that carries the edge's high port, or a network that reaches it |
| `git`/`ssh` still go direct | they do not read the system proxy: set `HTTPS_PROXY`, or `ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:10808 %h %p'` |
| DNS looks local | the SOCKS front resolves at the exit; the HTTP front receives a hostname in `CONNECT`. A browser's own DNS-over-HTTPS setting bypasses both |

### When the edge itself is unreachable

A lane that signs in, listens, and then fails every flow with "the TLS handshake with the edge failed" is a network problem, not an account problem. Check it by hand:

```bash
ferrox-app edges -c ~/.config/ferrox/lane.json | head    # the edges the catalogue offers
python3 - <<'PY'
import socket, ssl, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE; ctx.set_alpn_protocols(["h2"])
t0 = time.time()
raw = socket.create_connection(("us.m1.fastly-masque.net", 2499), timeout=8)
ctx.wrap_socket(raw, server_hostname="us.m1.fastly-masque.net")
print("edge TLS ok in", round(time.time() - t0, 2), "s")
PY
```

If that handshake times out while ordinary HTTPS works, the network drops the edge port. Two ways through, both on the CLI:

```bash
# chain the edge dial through a proxy this network does allow
ferrox-cli up --foxy --upstream socks5://127.0.0.1:1080
ferrox-cli up --foxy --upstream http://127.0.0.1:8080     # h3 cannot ride http; use h1/h2/auto

# or use a lane this network does carry
ferrox-cli up --vless 'vless://...' --vpn
```
