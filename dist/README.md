# Ferrox — release build

No installer: the binary, the one-command CLI, and the full manual (`USAGE.md`). macOS and Linux ship `ferrox-cli.sh`; Windows ships the native `ferrox-cli.exe` and the same `ferrox-cli.sh` as an optional Git Bash fallback. Nothing here needs cargo, a repository, or a config by hand.

```
ferrox-app            the lane engine: serves SOCKS5/HTTP/mixed fronts, dials every implemented lane
ferrox-cli.sh         login, up, down, status, ports, locations, version — the only command you need
ferrox-cli.exe        the same CLI built for Windows; no Bash, WSL or Python
                      (the Windows zip also carries ferrox-cli.sh for Git Bash users)
USAGE.md              the manual: every lane, every port, what to do when it does not work
```

## 30-second start — the Foxy lane

The Foxy lane needs a Firefox account: an email and a password, nothing else. There is no server to configure — the edge is chosen for you from Mozilla's catalogue, and `--country` moves the exit. One command connects, and the first run asks you for the two facts right there:

```bash
tar xzf ferrox-*-aarch64-apple-darwin.tar.gz   # or your platform's package
cd ferrox-*-aarch64-apple-darwin
./ferrox-cli.sh up --foxy --vpn    # asks email + password and the carrier, then connects
./ferrox-cli.sh status             # uptime, carrier, quota left, exit IP and country
./ferrox-cli.sh down               # stop and clear the system proxy
```

On Windows, unpack the zip and use `ferrox-cli.exe`; the flags and prompts are identical:

```powershell
Expand-Archive ferrox-*-x86_64-pc-windows-msvc.zip -DestinationPath .
cd ferrox-*-x86_64-pc-windows-msvc
.\ferrox-cli.exe up --foxy --vpn
.\ferrox-cli.exe status
.\ferrox-cli.exe down
```

The same zip includes `ferrox-cli.sh`. From Git Bash, with Python 3 and curl on `PATH`, it runs the same commands as the macOS/Linux CLI: `bash ./ferrox-cli.sh up --foxy --vpn`. The native `ferrox-cli.exe` is the recommended path and needs none of those.

On Windows the native launcher keeps config and account files under `%APPDATA%\ferrox` and pid/log/system-proxy state under `%LOCALAPPDATA%\ferrox`, owner-only through NTFS ACLs. The `~/.config/ferrox` paths below describe macOS and Linux.

The answer is stored once, in `~/.config/ferrox/credentials`, mode 0600, outside every repository; a copy inside a git repository is refused on purpose. Later runs read it silently and never ask again. The first launch also saves the FxA session it signed in with — access token, refresh token, account — to `~/.config/ferrox/foxy-token.json` (0600), so every launch after it resumes that grant instead of calling `/account/login`: Mozilla sends one new-sign-in mail, not one per connect, and the password is only asked for again when the plane refuses the grant. The browser challenge is solved locally. Prefer to save the account up front, or pass it non-interactively:

```bash
./ferrox-cli.sh login --email you@example.com   # prompts for the password, hidden
./ferrox-cli.sh login --email you@example.com --password 'the-password'
./ferrox-cli.sh up --foxy --country DE          # any exit country, no --vpn for ports-only
./ferrox-cli.sh logout                          # forget the account and the saved session
```

Pick an exit before connecting — the catalogue is public, so this needs no account:

```bash
./ferrox-cli.sh locations           # every country and its cities, remembered one marked *
./ferrox-cli.sh locations --ping    # nearest exit first: one handshake per edge, in ms
./ferrox-cli.sh locations US        # one country in detail
./ferrox-cli.sh location DE         # remember Germany for every up
./ferrox-cli.sh location US SFO     # remember a country and a city
./ferrox-cli.sh up --foxy --exclude-ports 22 --exclude-domains printer.lan   # these leave the tunnel
```

Run more than one lane at once — each named instance owns its config, pid, log, ports and remembered exit, while the account and catalogue stay shared; ports left unnamed are the first free ones near the defaults:

```bash
./ferrox-cli.sh up --foxy --instance work --country DE
./ferrox-cli.sh status --instance work
./ferrox-cli.sh down --all
```

`up` prints the port map, then proves one real flow through a front before it routes anything: a lane that carries nothing never takes the machine's traffic with it. If it says NOT CONNECTED it also prints why, from the lane's own log, with the fix to run, and stops the lane it started so nothing is left running and no `down` is needed; an interrupted start is cleaned up the same way. `--exclude-domains`/`--exclude-ports` take targets out of the lane for that launch: they dial directly and unencrypted.

## 30-second start — the VeePN lane

VeePN needs nothing typed in: no account, no server. The plane launches this device anonymously, names a region, and lists the upstreams that answer for the pair it printed, so one command starts the lane:

```bash
./ferrox-cli.sh up --veepn --vpn    # anonymous: no account, no server
./ferrox-cli.sh status
./ferrox-cli.sh down
```

`--region us-va` pins the exit; the plane's free pool spells its regions in lowercase (`nl`, `us-va`, `us-or`, `gb-lnd`, `fr-prs`, `sg`, `ru-spb`), and anything typed is lowered for it. Without `--region` the plane picks the fastest region it has, which is the no-friction path. The device id it sees is kept in `~/.config/ferrox/veepn.udid` (0600), so a restart is the same device, and `--domains` replaces the seven API origins this build ships with.

## The other lanes

Every share link this build dials goes through the same one command; anything beyond the link shapes rides `--config` (any config the binary serves is used verbatim — see USAGE.md §5 for the full inbound/outbound list):

```bash
./ferrox-cli.sh up --vless 'vless://uuid@host:443?type=ws&security=tls&sni=host&path=/ws' --vpn
./ferrox-cli.sh up --vmess host:443 --uuid ID --vpn
./ferrox-cli.sh up --trojan host:443 --password PW --vpn
./ferrox-cli.sh up --ss host:8388 --method aes-256-gcm --password PW --vpn
./ferrox-cli.sh up --config mine.json
```

Here the server is in the link or the `HOST:PORT` — unlike Foxy, these lanes dial the server you name. An invocation that cannot start the lane it names is refused before anything runs: `up --vless` with no link prints the example, `up --vmess` without `--uuid` names the missing id, and a rejected `up` leaves a lane that is already carrying traffic untouched.

## Ports, on every platform

The fronts are loopback-only: SOCKS5 `127.0.0.1:10808`, HTTP+HTTPS `127.0.0.1:8080`, mixed `127.0.0.1:10809` (`--socks`/`--http`/`--mixed` move them, `./ferrox-cli.sh ports` prints the map).

- **macOS** — `--vpn` arms and clears the system proxy for you.
- **Linux** — point apps at the fronts by hand: `ALL_PROXY=socks5h://127.0.0.1:10808 <app>`, or set GNOME/KDE network proxy to `127.0.0.1:8080`.
- **Windows** — `ferrox-cli.exe up --foxy --vpn` arms the system proxy through the WinINET Internet Settings that Chrome, Edge and most desktop apps read, and `ferrox-cli.exe down` restores the previous settings. From Git Bash, `bash ./ferrox-cli.sh up --foxy --vpn` is the fallback. Without `--vpn`, set Settings > Network & Internet > Proxy to `127.0.0.1:8080`, or use the fronts per app.

Use `socks5h://` (the `h`) so names resolve at the exit, not on your machine.

## What VPN mode is, and is not

`--vpn` routes every app that honours the system proxy (browsers, most Electron apps) over the lane. It is not a device-wide tunnel: this build carries no TUN device, so apps that ignore proxies and raw UDP are not captured — `./ferrox-cli.sh tun` prints the full reason and what to use instead (SOCKS5 UDP rides the lane for apps that speak it).

## Verify the download

Every release includes `SHA256SUMS` beside the packages. On macOS or Linux:

```bash
sha256sum --check SHA256SUMS
```

On Windows, compare the zip's hash with the matching line:

```powershell
Get-FileHash .\ferrox-*-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

## When it does not work

USAGE.md §8 is the table: rate-limited sign-ins (429), a refused account or a 2FA code (`--code 123456`), an edge blocked by your network (`--upstream socks5://127.0.0.1:PORT`), a port already taken. `up` diagnoses all of these itself and prints the one-line fix.
