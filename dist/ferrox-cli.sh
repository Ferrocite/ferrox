#!/bin/bash
# ferrox-cli: one front-facing command for every lane this binary dials.
#
#   ferrox-cli login                           save the foxy account once (0600)
#   ferrox-cli up --foxy --vpn                 the Foxy lane, whole-device proxy
#   ferrox-cli up --veepn --vpn                the VeePN lane, no account needed
#   ferrox-cli up --vless 'vless://...'        any vless share link
#   ferrox-cli up --config mine.json           any config the binary serves
#   ferrox-cli down | status | ports | tun | version
#
# In a release package this script sits beside the binary and runs it; in the
# repository it runs what `cargo build --release` last produced.
#
# The fronts are local proxies (SOCKS5, HTTP CONNECT, mixed). "VPN mode" here
# means the macOS system proxy, because this binary has no utun device: TUN
# mode is refused by name, and `ferrox-cli tun` says what that costs.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Three homes for the binary, first hit wins: $FERROX_BIN names one outright; a
# release package puts it next to this script; in the repository cargo writes
# where build.target-dir says, not under $ROOT/target, so resolving the name is
# the only way `up` runs the binary `cargo build --release` just built. It is
# deferred: --help, down or a missing flag answers without waiting for cargo.
BIN="${FERROX_BIN:-}"
resolve_bin() {
  [ -n "$BIN" ] && return 0
  local cand cargo_target
  for cand in "$SCRIPT_DIR/ferrox-app" "$SCRIPT_DIR/ferrox-app.exe"; do
    [ -x "$cand" ] && { BIN="$cand"; return 0; }
  done
  cargo_target="$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps 2>/dev/null | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -1)"
  BIN="${cargo_target:-$ROOT/target}/release/ferrox-app"
}
CONF_DIR="${FERROX_CONF_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/ferrox}"
CREDS="${FOXY_CREDENTIALS:-$CONF_DIR/credentials}"
CFG="$CONF_DIR/lane.json"
# The signed-in session FxA handed back, so a launch after the first signs in
# once and never sees a new-sign-in mail: the grant lives here, not in the config.
TOKEN_FILE="$CONF_DIR/foxy-token.json"
# The exit the user remembered, and the last published edge list kept so the
# selection still answers when the catalogue is down.
LOCATION_FILE="$CONF_DIR/foxy-location"
LOCATIONS_FILE="$CONF_DIR/foxy-locations.jsonl"
PID_FILE="$CONF_DIR/lane.pid"
LOG="$CONF_DIR/lane.log"
PROXY_PORTS="$CONF_DIR/system-proxy.ports"
PROXY_STATE="$CONF_DIR/system-proxy.state"

ACTION="up"
OUTBOUND=""
INSTANCE=""
ALL=0
VLESS=""
VMESS=""
VMESS_ID=""
VMESS_NETWORK="tcp"
TROJAN=""
SS=""
SS_METHOD="aes-256-gcm"
CONFIG_FILE=""
EMAIL=""
PASSWORD=""
CODE=""
COUNTRY="US"
COUNTRY_SET=0
CITY=""
CITY_SET=0
CARRIER="auto"
CARRIER_SET=0
LOC_COUNTRY=""
LOC_CITY=""
LOC_FILTER=""
LOC_PING=0
# Targets that leave the tunnel instead of riding it: a domain suffix or a port is enough.
EXCLUDE_DOMAINS=""
EXCLUDE_PORTS=""
UPSTREAM=""
# VeePN has no account and no server: an empty region lets the plane pick, and
# the device id is kept under $CONF_DIR so a restart is the same device.
REGION=""
VEEPN_DOMAINS=""
VEEPN_UDID=""
PROBE_TIMEOUT=20
FRONTS="socks,http,mixed"
FRONTS_SET=0
SOCKS_PORT="${FOXY_SOCKS_PORT:-10808}"
HTTP_PORT="${FOXY_HTTP_PORT:-8080}"
MIXED_PORT="${FOXY_MIXED_PORT:-10809}"
SOCKS_SET=0; [ -n "${FOXY_SOCKS_PORT:-}" ] && SOCKS_SET=1
HTTP_SET=0; [ -n "${FOXY_HTTP_PORT:-}" ] && HTTP_SET=1
MIXED_SET=0; [ -n "${FOXY_MIXED_PORT:-}" ] && MIXED_SET=1
WANT_VPN=0
DEBUG=0

die() { echo "ferrox-cli: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
rule() { printf '%s\n' "----------------------------------------------------------------"; }

# A flag that takes a value must have one. `shift 2` on a lone flag fails
# without consuming it, and the parse loop would ask the same question forever.
# Say what is missing and stop before a running lane is touched.
need_value() {
  local flag="$1" hint="$2" have="$3" value="${4:-}"
  [ "$have" -ge 2 ] && [ -n "$value" ] && return 0
  if [ "$flag" = --vless ]; then
    die "--vless needs a vless:// share link; nothing was started.
  example: ferrox-cli up --vless 'vless://uuid@host:443?type=ws&security=tls&sni=host&path=/ws'
  a config instead: ferrox-cli up --config mine.json
  no server to name: ferrox-cli up --foxy   or   ferrox-cli up --veepn"
  fi
  die "$flag needs $hint; nothing was started (see --help)."
}

need_port() {
  local flag="$1" have="$2" value="${3:-}"
  need_value "$flag" "a port number" "$have" "$value"
  case "$value" in
    ''|*[!0-9]*) die "$flag wants a port number, got '$value'; nothing was started." ;;
  esac
  [ "$value" -ge 1 ] && [ "$value" -le 65535 ] ||
    die "$flag wants a port between 1 and 65535, got '$value'; nothing was started."
}

usage() {
  cat <<EOF
usage: ferrox-cli <command> [options]

commands
  login      save the foxy account once (prompts for the password; file is 0600)
  logout     stop the lane, then forget the account and its stored session
  locations  list the countries and cities the catalogue publishes
             (--ping measures the handshake to each edge, fastest first)
  location   remember an exit: location CC [CITY] (survives every up)
  up         start the lane in the background, print the port map (default)
  serve      start the lane in this terminal, until Ctrl-C
  down       stop the lane and clear the system proxy it set (--all: every lane)
  status     show the lane (--instance NAME for one of several), then its exit
  ports      print the port map and the macOS settings to type
  tun        what TUN mode would need, and why this binary refuses it
  version    print the release binary's version

first run, then every run: the foxy lane signs in once and keeps the session in
\$CONF_DIR/foxy-token.json (0600). The launches after it mint a pass from that grant,
so no password is asked again and FxA sends no new-sign-in mail.

  ferrox-cli up --foxy --vpn                    # asks once, then connects
  ferrox-cli up --foxy --vpn                    # second run: resumes, no sign-in
  ferrox-cli locations                          # countries and cities to pin
  ferrox-cli locations --ping                   # the same list, nearest exit first
  ferrox-cli location DE                        # remember Germany for every up
  ferrox-cli status                             # exit IP and country
  ferrox-cli down                               # stop, clear the system proxy
  ferrox-cli logout                             # forget the account and session

and from the same fresh package, with nothing to type in at all:
  ferrox-cli up --veepn --vpn                   # anonymous, no account, no server

several lanes at once
  ferrox-cli up --foxy --instance work --country DE
  ferrox-cli up --foxy --instance home --country NL --socks 10818 --http 8088
  ferrox-cli status --instance work
  ferrox-cli down --all
  A named instance keeps its own config, pid, log, ports and remembered exit;
  the account and the edge catalogue are shared. Ports left unnamed are the
  first free ones near the defaults, so a second lane never fights the first.
  --vpn belongs to the unnamed lane: the system proxy is one machine-wide
  setting, and an instance is reached by pointing the app at its fronts.

outbound (choose one)
  --foxy                 Foxy lane; account from \$FOXY_CREDENTIALS
  --veepn                VeePN lane; anonymous, no account and no server
  --vless LINK           a vless:// share link (tcp, ws, grpc, httpupgrade, xhttp)
  --vmess HOST:PORT --uuid ID
  --trojan HOST:PORT --password PW
  --ss HOST:PORT --method METHOD --password PW
  --config FILE          any JSON config this binary serves, used verbatim

foxy options (email + password is the whole setup; there is no server to name)
  --email ADDR           Firefox account, else \$FOXY_EMAIL, else the credentials file
  --password PW          password, else \$FOXY_PASS (a file with 0600 is better)
  --code CODE            two-factor code (kept with the pending sign-in until it verifies)
  --country CC           exit country; default is the remembered one, else US
  --city CODE            city tier inside the country (SFO, NYC; see locations)
  --carrier NAME         auto|h1|h2|h3, default auto (h2, then h1, then h3);
                         asked once on a terminal when the flag is left off, and
                         auto on a pipe; h2 outran h3 on CI in every run and on
                         every runner, so auto opens on h2; h3 is still the
                         carrier UDP asks first, and a named h3 falls back to
                         h2 and h1 when the path drops QUIC
  --upstream URL         http:// or socks5(h):// hop to reach the edge through
  --exclude-domains LIST domain suffixes that leave the tunnel and dial directly
                         (comma-separated; example.com also covers its subdomains)
  --exclude-ports LIST   destination ports that leave the tunnel and dial directly
                         (comma-separated; 22,53 are the usual ones)

locations
  ferrox-cli locations [--ping] [CC]   every country, and the cities each one has
  ferrox-cli location CC [CITY]        remember it; up --foxy moves there
  The list is public: it needs no account and is cached by the binary, and the
  last one fetched is kept in \$CONF_DIR/foxy-locations.jsonl for when the
  catalogue cannot be reached.  --ping adds a TCP-handshake latency per edge,
  sorts the exits fastest first, and marks an edge that did not answer.

veepn options (nothing is required: the plane names the region and its edges)
  --region CC            exit region id (lowercase, e.g. nl, us-va), else the plane picks
  --country CC           an alias for --region on this lane
  --domains URLS         comma-separated https origins to ask, else the shipped seven
  --udid ID              the device identity the plane sees, else one kept per machine

fronts
  --fronts LIST          socks,http,mixed (default all three)
  --socks PORT           default $SOCKS_PORT (a named instance takes the next free one)
  --http PORT            default $HTTP_PORT
  --mixed PORT           default $MIXED_PORT
  --instance NAME        another lane beside the unnamed one: its config, pid,
                         log, ports and remembered exit are its own; ports left
                         unnamed are the first free ones near the defaults
  --vpn                  also point the macOS system proxy at the fronts; the
                         unnamed lane only (it is one machine-wide setting)
  --all                  with down: stop every lane
  --debug                keep the lane's dial trace in the log (FOXY_DEBUG=1)
  --tun                  refused: this binary has no utun device
  -h, --help             this text
  -V, --version          print the release binary's version

ports (defaults)
  SOCKS5         127.0.0.1:$SOCKS_PORT    curl --socks5-hostname, UDP-aware
  HTTP + HTTPS   127.0.0.1:$HTTP_PORT     CONNECT tunnels and plain forwards
  mixed          127.0.0.1:$MIXED_PORT    SOCKS5 and HTTP on one port
EOF
}

# ---------------------------------------------------------------- credentials

shell_quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

action_login() {
  local email="$EMAIL" pass="$PASSWORD"
  if [ -z "$email" ]; then
    printf 'firefox account email: ' && read -r email
  fi
  if [ -z "$pass" ]; then
    printf 'password (hidden, not echoed): ' && read -rs pass && printf '\n'
  fi
  [ -n "$email" ] && [ -n "$pass" ] || die "an account is an email and a password"
  mkdir -p "$CONF_DIR"
  chmod 700 "$CONF_DIR" 2>/dev/null || true
  (
    umask 077
    {
      printf "FOXY_EMAIL=%s\n" "$(shell_quote "$email")"
      printf "FOXY_PASS=%s\n" "$(shell_quote "$pass")"
    } >"$CREDS"
  )
  chmod 600 "$CREDS"
  # A login is the user asking for this account now: the grant the last one left is not the one to resume.
  rm -f "$TOKEN_FILE"
  if [ "${LOGIN_QUIET:-0}" != 1 ]; then
    say "account saved to $CREDS: owner-only, outside the repository, read by every future up."
    say "the next up --foxy signs in once and keeps the session in $TOKEN_FILE."
  fi
}

read_credentials() {
  [ -f "$CREDS" ] || return 0
  case "$CREDS" in "$ROOT"/*)
    if git -C "$ROOT" ls-files --error-unmatch "$CREDS" >/dev/null 2>&1; then
      die "$CREDS is tracked by git; move it outside the repository"
    fi ;;
  esac
  # shellcheck disable=SC1090
  . "$CREDS"
  # A named flag beats a stored file: what you typed this minute is what you mean.
  EMAIL="${EMAIL:-${FOXY_EMAIL:-$EMAIL}}"
  PASSWORD="${PASSWORD:-${FOXY_PASS:-$PASSWORD}}"
}

# The account a stored session belongs to, so a launch can resume it even when
# the credentials file is gone; a missing or corrupt session answers nothing.
stored_email() {
  [ -f "$TOKEN_FILE" ] || return 0
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("email", ""))' "$TOKEN_FILE" 2>/dev/null || true
}

same_stored_account() {
  local stored
  stored="$(stored_email)"
  [ -n "$stored" ] || return 1
  [ "$(printf '%s' "$stored" | tr '[:upper:]' '[:lower:]')" = \
    "$(printf '%s' "$EMAIL" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" ]
}

action_logout() {
  stop_all_lanes
  rm -f "$TOKEN_FILE" "$CREDS" "$CONF_DIR"/lane*.json
  say "signed out: every lane is stopped, and the stored session, the saved account and the lane configs are gone."
  say "the remembered exit stays in $LOCATION_FILE; 'ferrox-cli login' signs in again."
}

# ---------------------------------------------------------------- locations

# The list is public and needs no account, so it is the binary's catalogue call
# and not an authenticated one; the last answer is kept for an offline listing.
action_locations() {
  local filter rows plain formatter
  filter="$(printf '%s' "$LOC_FILTER" | tr '[:lower:]' '[:upper:]')"
  require_bin
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null || true
  if [ "$LOC_PING" = 1 ]; then
    rows="$("$BIN" edges --ping 2>/dev/null)"
  else
    rows="$("$BIN" edges 2>/dev/null)"
  fi
  if [ -z "$rows" ]; then
    if [ -s "$LOCATIONS_FILE" ]; then
      say "the catalogue did not answer; showing the last list it gave ($LOCATIONS_FILE)."
      rows="$(cat "$LOCATIONS_FILE")"
    else
      die "the catalogue did not answer and no list is saved yet: check the network, then run 'ferrox-cli locations' again."
    fi
  else
    # The offline copy keeps the same rows without this launch's readings.
    plain="$(printf '%s\n' "$rows" | sed -e 's/,"ms":null//' -e 's/,"ms":[0-9][0-9]*//')"
    ( umask 077; printf '%s\n' "$plain" >"$LOCATIONS_FILE" )
  fi
  # A here-document on this command would take stdin's place and hide the rows.
  formatter="$(cat <<'PY'
import json, sys

wanted, current_country, current_city, saved, ping = sys.argv[1:6]
ping = ping == "1"
places = {}
best = {}
total = 0
measured = False
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        edge = json.loads(line)
    except ValueError:
        continue
    country = str(edge.get("country") or "").upper()
    city = str(edge.get("city") or "").upper()
    if not country:
        continue
    if wanted and country != wanted:
        continue
    cities = places.setdefault(country, {})
    cities[city] = cities.get(city, 0) + 1
    total += 1
    if "ms" in edge:
        measured = True
        reading = edge.get("ms")
        key = (country, city)
        if not isinstance(reading, int):
            best.setdefault(key, None)
        elif key not in best or best[key] is None or reading < best[key]:
            best[key] = reading
if not places:
    if wanted:
        print(f"{wanted} is not in the published catalogue; run 'ferrox-cli locations' for every country it lists.")
    else:
        print("the catalogue listed no dialable edge just now; the lane would refuse every country.")
    sys.exit(1)
country_best = {}
for (country, _city), reading in best.items():
    if not isinstance(reading, int):
        country_best.setdefault(country, None)
    elif country not in country_best or country_best[country] is None or reading < country_best[country]:
        country_best[country] = reading

def reading_of(key, table):
    if not ping or key not in table:
        return ""
    value = table[key]
    if not isinstance(value, int):
        return "no answer".rjust(12)
    return f"{value} ms".rjust(12)

def country_order(code):
    if code == "REC":
        return (0, 0, code)
    if code not in country_best:
        return (3, 0, code)
    reading = country_best[code]
    return (1, reading, code) if isinstance(reading, int) else (2, 0, code)

def city_order(country, code):
    key = (country, code)
    if key not in best:
        return (3, 0, code)
    reading = best[key]
    return (1, reading, code) if isinstance(reading, int) else (2, 0, code)

print(f"exit locations from Mozilla's catalogue: {len(places)} countries, {total} edges")
print("country and city are the codes --country and --city take; * is what this machine remembers.")
if ping:
    print("ms is one TCP handshake from this machine to the edge (1.5 s budget); 'no answer' is an edge that did not take it.")
    if not measured:
        print("latency not measured: this listing came from the offline copy; run 'locations --ping' again when the catalogue answers.")
if ping:
    countries = sorted(places, key=country_order)
else:
    countries = sorted(places, key=lambda code: (code != "REC", code))
for country in countries:
    cities = places[country]
    mark = "*" if country == current_country else " "
    print(f" {mark} {country:<4} {sum(cities.values()):>3} edges{reading_of(country, country_best)}")
    if ping:
        ordered = sorted(cities, key=lambda code: city_order(country, code))
    else:
        ordered = sorted(cities, key=lambda code: (code == "", code))
    for city in ordered:
        star = "*" if country == current_country and city == current_city else " "
        print(f"   {star}   {(city or 'any'):<6} {cities[city]:>3}{reading_of((country, city), best)}")
print()
print("remember one:  ferrox-cli location <CC> [CITY]")
print(f"the list is saved in {saved}")
PY
)"
  printf '%s\n' "$rows" | python3 -c "$formatter" "$filter" "$(remembered_country)" "$(remembered_city)" "$LOCATIONS_FILE" "$LOC_PING"
}

action_location() {
  local country city
  country="$(printf '%s' "$LOC_COUNTRY" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
  city="$(printf '%s' "$LOC_CITY" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
  [ -n "$country" ] || die "usage: ferrox-cli location <CC> [CITY]   (see 'ferrox-cli locations')"
  if [ -s "$LOCATIONS_FILE" ] && ! grep -qiF "\"country\":\"$country\"" "$LOCATIONS_FILE"; then
    die "'$country' is not in the saved catalogue list; run 'ferrox-cli locations' to refresh it, or pick a code it prints."
  fi
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null || true
  ( umask 077; printf '%s %s\n' "$country" "$city" >"$LOCATION_FILE" )
  if [ -n "$city" ]; then
    say "exit remembered: $country / $city. The next 'up --foxy' moves there."
  else
    say "exit remembered: $country (its catalogue order picks the city). The next 'up --foxy' moves there."
  fi
}

# ---------------------------------------------------------------- config files

# One JSON writer for every outbound: python3 already carries this tree's scripts.
write_config() {
  local outbound="$1"
  python3 - "$CFG" "$outbound" "$FRONTS" "$SOCKS_PORT" "$HTTP_PORT" "$MIXED_PORT" <<'PY'
import json, sys

cfg, outbound, fronts, socks, http, mixed = sys.argv[1:7]
ports = {"socks": int(socks), "http": int(http), "mixed": int(mixed)}
wanted = [f.strip() for f in fronts.split(",") if f.strip()]
for front in wanted:
    if front not in ports:
        sys.exit(f"unknown front `{front}`: socks, http, mixed")
doc = {
    "inbounds": [{"protocol": f, "listen": "127.0.0.1", "port": ports[f]} for f in wanted],
    "outbounds": [json.loads(outbound)],
}
with open(cfg, "w") as handle:
    json.dump(doc, handle, indent=2)
PY
  chmod 600 "$CFG"
}

# The ports this lane runs: the flags win, a lane's own config is adopted so a
# restart keeps its fronts, and a named instance takes the next free ones so a
# second lane never fights the first. Prints "socks http mixed".
plan_ports() {
  local scan="$1"
  python3 - "$SOCKS_PORT" "$HTTP_PORT" "$MIXED_PORT" "$SOCKS_SET" "$HTTP_SET" \
    "$MIXED_SET" "$FRONTS" "$scan" "$CFG" <<'PY'
import json, socket, sys

values = [int(a) for a in sys.argv[1:4]]
explicit = [a == "1" for a in sys.argv[4:7]]
fronts = {f.strip() for f in sys.argv[7].split(",") if f.strip()}
scan = sys.argv[8] == "1"
config = sys.argv[9]
names = ["socks", "http", "mixed"]
fixed = list(explicit)
if config:
    try:
        with open(config, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        document = {}
    adopted = set()
    for inbound in document.get("inbounds", []):
        name = inbound.get("protocol")
        port = inbound.get("port")
        if name in names and name in fronts and not explicit[names.index(name)] and name not in adopted and isinstance(port, int):
            values[names.index(name)] = port
            fixed[names.index(name)] = True
            adopted.add(name)
taken = {values[i] for i, name in enumerate(names) if name in fronts and fixed[i]}
if scan:
    for i, name in enumerate(names):
        if name not in fronts or fixed[i]:
            continue
        port = values[i]
        while port <= 65535:
            if port not in taken:
                probe = socket.socket()
                try:
                    probe.bind(("127.0.0.1", port))
                    break
                except OSError:
                    pass
                finally:
                    probe.close()
            port += 1
        values[i] = port
        taken.add(port)
print(" ".join(str(v) for v in values))
PY
}

# A config lane serves the proxy inbounds its file names, so the fronts and the
# ports a system proxy may point at come from that file, not from the defaults.
# A selected front must be loopback before it is armed, and a file with none is
# refused by name.
config_fronts() {
  python3 - "$CONFIG_FILE" "$WANT_VPN" "$FRONTS_SET" "$FRONTS" <<'PY'
import json, sys

path, vpn, explicit, asked = sys.argv[1:5]
try:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
except (OSError, ValueError) as error:
    sys.exit(f"cannot read config {path}: {error}")
order = []
for inbound in document.get("inbounds", []):
    if not isinstance(inbound, dict):
        continue
    name = inbound.get("protocol")
    if name not in ("socks", "http", "mixed"):
        continue
    port = inbound.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        sys.exit(f"inbound `{name}` has no port in 1-65535")
    if name not in order:
        order.append(name)
if explicit == "1":
    wanted = [front.strip() for front in asked.split(",") if front.strip()]
    missing = [front for front in wanted if front not in order]
    if missing:
        sys.exit(f"the config serves no {missing[0]} inbound; --fronts names it")
    order = [front for front in order if front in wanted]
if vpn == "1":
    if not order:
        sys.exit("the config serves no socks, http or mixed inbound; --vpn needs one")
    checked = set()
    for inbound in document.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        name = inbound.get("protocol")
        if name not in order or name in checked:
            continue
        checked.add(name)
        listen = inbound.get("listen")
        loopback = isinstance(listen, str) and (
            listen == "::1" or listen == "localhost" or listen.startswith("127.")
        )
        if not loopback:
            sys.exit(
                f"inbound `{name}` listens on {listen or 'all interfaces'}, not loopback;"
                " --vpn needs 127.0.0.1 or ::1"
            )
print(",".join(order))
PY
}

# The config a running lane is served is the truth about its fronts; status and
# ports read it back instead of guessing the defaults.
adopt_lane_ports() {
  [ -f "$CFG" ] || return 1
  local planned
  planned="$(plan_ports 0 2>/dev/null)" || return 1
  read -r SOCKS_PORT HTTP_PORT MIXED_PORT <<<"$planned"
}

foxy_outbound() {
  python3 - "$EMAIL" "$PASSWORD" "$CODE" "$COUNTRY" "$CITY" "$CARRIER" "$UPSTREAM" "$TOKEN_FILE" "$EXCLUDE_DOMAINS" "$EXCLUDE_PORTS" <<'PY'
import json, sys

email, password, code, country, city, carrier, upstream, token_file, domains, ports = sys.argv[1:11]

def split_domains(raw):
    names = []
    for item in raw.split(","):
        name = item.strip().lower().rstrip(".")
        # The starred and dotted spellings mean what they mean in a browser: this name and below it.
        if name.startswith("*."):
            name = name[2:]
        if name.startswith("."):
            name = name[1:]
        if not name:
            continue
        if ("/" in name or ":" in name or "*" in name or ".." in name
                or name.startswith(".") or any(ch.isspace() for ch in name)):
            sys.exit(f"--exclude-domains wants domain suffixes like example.com, got '{item.strip()}'; nothing was started.")
        names.append(name)
    if not names:
        sys.exit("--exclude-domains wants at least one domain suffix; nothing was started.")
    return names

def split_ports(raw):
    numbers = []
    for item in raw.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            port = int(value, 10)
        except ValueError:
            sys.exit(f"--exclude-ports wants ports 1-65535, got '{value}'; nothing was started.")
        if not 0 < port < 65536:
            sys.exit(f"--exclude-ports wants ports 1-65535, got '{value}'; nothing was started.")
        numbers.append(port)
    if not numbers:
        sys.exit("--exclude-ports wants at least one port; nothing was started.")
    return numbers

# The account, not a minted pass: the pass the edge accepts lives 600 seconds,
# so a lane handed a bare token cannot renew it and dies when it expires.
settings = {"email": email, "password": password, "country": country.upper(), "carrier": carrier}
# The session the first sign-in leaves: later launches mint from it instead of
# signing in again, which is what keeps FxA from mailing a new-sign-in notice.
if token_file:
    settings["tokenFile"] = token_file
if city:
    settings["city"] = city.upper()
if upstream:
    settings["upstreamProxy"] = upstream
if code:
    settings["code"] = code
if domains:
    settings["directDomains"] = split_domains(domains)
if ports:
    settings["directPorts"] = split_ports(ports)
print(json.dumps({"protocol": "foxy", "settings": settings}))
PY
}

# ---------------------------------------------------------------- locations

# The remembered exit fills only the flags nobody typed: a country typed now
# starts from that country's own edges, so a city remembered for another one is dropped.
load_foxy_location() {
  [ -f "$LOCATION_FILE" ] || return 0
  [ "$COUNTRY_SET" = 1 ] && return 0
  local country city
  IFS=' ' read -r country city < "$LOCATION_FILE" || true
  [ -n "$country" ] || return 0
  COUNTRY="$country"
  if [ "$CITY_SET" = 0 ] && [ -n "$city" ]; then CITY="$city"; fi
  return 0
}

save_foxy_location() {
  [ -n "$COUNTRY" ] || return 0
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null || true
  (
    umask 077
    printf '%s %s\n' \
      "$(printf '%s' "$COUNTRY" | tr '[:lower:]' '[:upper:]')" \
      "$(printf '%s' "$CITY" | tr '[:lower:]' '[:upper:]')" >"$LOCATION_FILE"
  )
}

remembered_country() {
  [ -f "$LOCATION_FILE" ] || return 0
  local country _city
  IFS=' ' read -r country _city < "$LOCATION_FILE" || true
  printf '%s' "$country"
}

remembered_city() {
  [ -f "$LOCATION_FILE" ] || return 0
  local _country city
  IFS=' ' read -r _country city < "$LOCATION_FILE" || true
  printf '%s' "$city"
}

# --region wins, --country is the alias, and an empty answer means the plane picks.
# The plane's own codes are lowercase region ids (`nl`, `us-va`) and its list ask
# is case-sensitive, so what was typed is lowered rather than passed as typed.
effective_region() {
  local region="$REGION"
  if [ -z "$region" ] && [ "$COUNTRY_SET" = 1 ]; then region="$COUNTRY"; fi
  printf '%s' "$region" | tr '[:upper:]' '[:lower:]'
}

# The plane counts devices by the id the launch carries, so it is kept: a fresh
# one per launch reads as a new device every time.
stable_udid() {
  [ -n "$VEEPN_UDID" ] && { printf '%s' "$VEEPN_UDID"; return 0; }
  local file="$CONF_DIR/veepn.udid" value=""
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null || true
  if [ -f "$file" ]; then value="$(tr -d '[:space:]' < "$file" 2>/dev/null)"; fi
  if [ -z "$value" ]; then
    value="$(python3 -c 'import uuid; print(uuid.uuid4())')" || die "cannot mint a device id"
    ( umask 077; printf '%s\n' "$value" > "$file" )
  fi
  printf '%s' "$value"
}

# The VeePN outbound: no account, no server, and only the fields that were asked for.
veepn_outbound() {
  local region udid
  region="$(effective_region)"
  udid="$(stable_udid)" || return 1
  python3 - "$region" "$VEEPN_DOMAINS" "$udid" <<'PY'
import json, sys

region, domains, udid = sys.argv[1:4]
settings = {}
if region:
    settings["region"] = region
listed = [url.strip() for url in domains.split(",") if url.strip()]
if listed:
    settings["domains"] = listed
if udid:
    settings["udid"] = udid
print(json.dumps({"protocol": "veepn", "settings": settings}))
PY
}

# vless link -> xray json, for the five carriers this tree proves in CI.
vless_outbound() {
  python3 - "$VLESS" <<'PY'
import json, sys
from urllib.parse import unquote, urlsplit

link = sys.argv[1]
if not link.startswith("vless://"):
    sys.exit("--vless wants a vless:// link")
body, _, name = link[len("vless://"):].partition("#")
body, _, query = body.partition("?")
uuid, _, hostport = body.rpartition("@")
if not uuid or not hostport:
    sys.exit("a vless link is vless://{uuid}@{host}:{port}?{query}")
host, _, port = hostport.rpartition(":")
params = {}
for pair in query.split("&"):
    if pair:
        key, _, value = pair.partition("=")
        params[unquote(key)] = unquote(value)

kind = (params.get("type") or "tcp").lower()
security = (params.get("security") or "none").lower()
sni = params.get("sni") or params.get("peer") or ""
hosthdr = params.get("host") or ""
path = params.get("path") or ""
service = params.get("serviceName") or ""
mode = params.get("mode") or ""
flow = params.get("flow") or ""

stream = {"network": "tcp" if kind == "raw" else kind}
if kind in ("ws", "websocket"):
    ws = {"path": path or "/"}
    if hosthdr:
        ws["headers"] = {"Host": hosthdr}
    stream["wsSettings"] = ws
elif kind == "grpc":
    stream["grpcSettings"] = {"serviceName": service}
elif kind == "httpupgrade":
    settings = {"path": path or "/"}
    if hosthdr:
        settings["host"] = hosthdr
    stream["httpupgradeSettings"] = settings
elif kind == "xhttp":
    settings = {"path": path or "/"}
    if hosthdr:
        settings["host"] = hosthdr
    if mode:
        settings["mode"] = mode
    stream["xhttpSettings"] = settings
elif kind in ("tcp", "raw", ""):
    pass
else:
    sys.exit(f"`{kind}` needs --config: this converter writes tcp, ws, grpc, httpupgrade and xhttp")

if security == "tls":
    tls = {"serverName": sni or host, "allowInsecure": False}
    if params.get("fp"):
        tls["fingerprint"] = params["fp"]
    if params.get("alpn"):
        tls["alpn"] = params["alpn"].split(",")
    stream["security"] = "tls"
    stream["tlsSettings"] = tls
elif security == "reality":
    if not params.get("pbk"):
        sys.exit("a reality link without `pbk` names no server key")
    reality = {"serverName": sni or host, "publicKey": params["pbk"]}
    if params.get("sid"):
        reality["shortId"] = params["sid"]
    if params.get("fp"):
        reality["fingerprint"] = params["fp"]
    if params.get("spx"):
        reality["spiderX"] = params["spx"]
    stream["security"] = "reality"
    stream["realitySettings"] = reality
elif security in ("none", ""):
    stream["security"] = "none"
else:
    sys.exit(f"security `{security}` needs --config")

user = {"id": uuid, "encryption": "none"}
if flow and flow != "none":
    user["flow"] = flow
print(json.dumps({
    "protocol": "vless",
    "settings": {"vnext": [{"address": host, "port": int(port), "users": [user]}]},
    "streamSettings": stream,
}))
PY
}

vmess_outbound() {
  python3 - "$VMESS" "$VMESS_ID" "$VMESS_NETWORK" <<'PY'
import json, sys
hostport, uuid, network = sys.argv[1:4]
host, _, port = hostport.rpartition(":")
if not host or not port.isdigit():
    sys.exit("--vmess wants HOST:PORT and --uuid ID")
if not uuid:
    sys.exit("--vmess needs --uuid ID as well, e.g. ferrox-cli up --vmess host:443 --uuid UUID")
stream = {"network": network or "tcp"}
print(json.dumps({
    "protocol": "vmess",
    "settings": {"vnext": [{"address": host, "port": int(port),
                            "users": [{"id": uuid, "security": "auto"}]}]},
    "streamSettings": stream,
}))
PY
}

trojan_outbound() {
  python3 - "$TROJAN" "$PASSWORD" <<'PY'
import json, sys
hostport, password = sys.argv[1:3]
host, _, port = hostport.rpartition(":")
if not host or not port.isdigit():
    sys.exit("--trojan wants HOST:PORT and --password PW")
if not password:
    sys.exit("--trojan needs --password PW as well, e.g. ferrox-cli up --trojan host:443 --password PW")
print(json.dumps({
    "protocol": "trojan",
    "settings": {"servers": [{"address": host, "port": int(port), "password": password}]},
}))
PY
}

ss_outbound() {
  python3 - "$SS" "$SS_METHOD" "$PASSWORD" <<'PY'
import json, sys
hostport, method, password = sys.argv[1:4]
host, _, port = hostport.rpartition(":")
if not host or not port.isdigit():
    sys.exit("--ss wants HOST:PORT, --method and --password")
if not password:
    sys.exit("--ss needs --password PW as well, e.g. ferrox-cli up --ss host:8388 --password PW")
print(json.dumps({
    "protocol": "shadowsocks",
    "settings": {"servers": [{"address": host, "port": int(port),
                              "method": method, "password": password}]},
}))
PY
}

# ------------------------------------------------------------------- system proxy

proxy_pac_line() { networksetup -getautoproxyurl "$1" 2>/dev/null; }
proxy_auto_line() { networksetup -getproxyautodiscovery "$1" 2>/dev/null; }

proxy_readback_has() {
  printf '%s\n' "$1" | grep -Eq "^[[:space:]]*$2[[:space:]]*:[[:space:]]*$3[[:space:]]*$"
}

system_proxy_on() {
  command -v networksetup >/dev/null 2>&1 || { say "no networksetup: point your apps at the ports by hand."; return 0; }
  command -v scutil >/dev/null 2>&1 || { say "system proxy: no scutil to read the proxy back; nothing was armed." >&2; return 1; }
  local any=0 svc want_socks="" want_http="" front pac auto pac_url pac_on auto_on readback bad
  for front in ${FRONTS//,/ }; do
    case "$front" in
      socks) want_socks="$SOCKS_PORT" ;;
      http) want_http="$HTTP_PORT" ;;
      mixed)
        [ -n "$want_socks" ] || want_socks="$MIXED_PORT"
        [ -n "$want_http" ] || want_http="$MIXED_PORT"
        ;;
    esac
  done
  [ -n "$want_socks$want_http" ] || { say "system proxy: --fronts names no socks, http or mixed front; nothing was armed." >&2; return 1; }
  # Keep the first snapshot: a re-arm must still restore what the user had before any lane touched it.
  if [ ! -f "$PROXY_STATE" ]; then
    [ -f "$PROXY_PORTS" ] && system_proxy_off
    : > "$PROXY_STATE"
    while IFS= read -r svc; do
      [ -z "$svc" ] && continue
      case "$svc" in *\**) continue ;; esac
      pac="$(proxy_pac_line "$svc")" || {
        say "system proxy: cannot read the PAC setting for '$svc'; nothing was armed." >&2
        system_proxy_off
        return 1
      }
      auto="$(proxy_auto_line "$svc")" || {
        say "system proxy: cannot read auto discovery for '$svc'; nothing was armed." >&2
        system_proxy_off
        return 1
      }
      pac_url="$(printf '%s\n' "$pac" | sed -n 's/^URL: //p' | head -n 1)"
      case "$pac_url" in "(null)"|"(empty)") pac_url="" ;; esac
      pac_on=off
      case "$(printf '%s\n' "$pac" | sed -n 's/^Enabled: //p' | head -n 1 | tr '[:upper:]' '[:lower:]')" in yes|on) pac_on=on ;; esac
      auto_on=off
      case "$(printf '%s\n' "$auto" | sed -n 's/^Auto Proxy Discovery: //p' | head -n 1 | tr '[:upper:]' '[:lower:]')" in on|yes) auto_on=on ;; esac
      printf '%s\t%s\t%s\t%s\n' "$svc" "$pac_on" "${pac_url:--}" "$auto_on" >> "$PROXY_STATE"
    done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  fi
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    case "$svc" in *\**) continue ;; esac
    networksetup -setproxyautodiscovery "$svc" off 2>/dev/null || true
    networksetup -setautoproxyurl "$svc" "" 2>/dev/null || true
    networksetup -setautoproxystate "$svc" off 2>/dev/null || true
    if [ -n "$want_socks" ]; then
      networksetup -setsocksfirewallproxy "$svc" 127.0.0.1 "$want_socks" 2>/dev/null || continue
      networksetup -setsocksfirewallproxystate "$svc" on 2>/dev/null || true
    fi
    if [ -n "$want_http" ]; then
      networksetup -setwebproxy "$svc" 127.0.0.1 "$want_http" 2>/dev/null || true
      networksetup -setwebproxystate "$svc" on 2>/dev/null || true
      networksetup -setsecurewebproxy "$svc" 127.0.0.1 "$want_http" 2>/dev/null || true
      networksetup -setsecurewebproxystate "$svc" on 2>/dev/null || true
    fi
    any=1
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  [ "$any" = 1 ] || { system_proxy_off; say "no network service took the proxy" >&2; return 1; }
  printf '%s %s\n' "${want_socks:--}" "${want_http:--}" > "$PROXY_PORTS"
  readback="$(scutil --proxy 2>/dev/null)" || readback=""
  bad=""
  proxy_readback_has "$readback" ProxyAutoConfigEnable 0 || bad="PAC"
  proxy_readback_has "$readback" ProxyAutoDiscoveryEnable 0 || bad="$bad auto discovery"
  if [ -n "$want_socks" ]; then
    proxy_readback_has "$readback" SOCKSEnable 1 || bad="$bad SOCKS"
  fi
  if [ -n "$want_http" ]; then
    proxy_readback_has "$readback" HTTPEnable 1 || bad="$bad HTTP"
    proxy_readback_has "$readback" HTTPSEnable 1 || bad="$bad HTTPS"
  fi
  if [ -n "$bad" ]; then
    say "system proxy: the read-back did not show the armed state ($bad); clearing it." >&2
    system_proxy_off
    return 1
  fi
  [ -n "$want_socks" ] && say "system proxy on: SOCKS 127.0.0.1:$want_socks"
  [ -n "$want_http" ] && say "system proxy on: HTTP and HTTPS 127.0.0.1:$want_http"
  say "scope: apps that honour the system proxy. There is no utun device, so"
  say "apps that ignore it (and UDP) are not captured: ferrox-cli tun says why."
}

system_proxy_off() {
  [ -f "$PROXY_PORTS" ] || [ -f "$PROXY_STATE" ] || return 0
  local svc pac_on pac_url auto_on
  if command -v networksetup >/dev/null 2>&1; then
    if [ -f "$PROXY_STATE" ]; then
      while IFS=$'\t' read -r svc pac_on pac_url auto_on; do
        [ -z "$svc" ] && continue
        case "$svc" in *\**) continue ;; esac
        [ "$pac_url" = - ] && pac_url=""
        if [ -n "$pac_url" ]; then
          networksetup -setautoproxyurl "$svc" "$pac_url" 2>/dev/null || true
        else
          networksetup -setautoproxyurl "$svc" "" 2>/dev/null || true
        fi
        if [ "$pac_on" = on ]; then
          networksetup -setautoproxystate "$svc" on 2>/dev/null || true
        else
          networksetup -setautoproxystate "$svc" off 2>/dev/null || true
        fi
        if [ "$auto_on" = on ]; then
          networksetup -setproxyautodiscovery "$svc" on 2>/dev/null || true
        else
          networksetup -setproxyautodiscovery "$svc" off 2>/dev/null || true
        fi
        networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
        networksetup -setwebproxystate "$svc" off 2>/dev/null || true
        networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
      done < "$PROXY_STATE"
    else
      while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        case "$svc" in *\**) continue ;; esac
        networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
        networksetup -setwebproxystate "$svc" off 2>/dev/null || true
        networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
      done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
    fi
    say "system proxy cleared."
  fi
  rm -f "$PROXY_PORTS" "$PROXY_STATE"
}

# ---------------------------------------------------------------------- lane

# Every lane owns its config, pid, log and remembered exit; the account and the
# edge catalogue stay shared. The unnamed lane keeps the names it always had.
apply_instance() {
  local suffix=""
  [ -n "$INSTANCE" ] && suffix="-$INSTANCE"
  CFG="$CONF_DIR/lane$suffix.json"
  PID_FILE="$CONF_DIR/lane$suffix.pid"
  LOG="$CONF_DIR/lane$suffix.log"
  PROXY_PORTS="$CONF_DIR/system-proxy$suffix.ports"
  PROXY_STATE="$CONF_DIR/system-proxy$suffix.state"
  LOCATION_FILE="$CONF_DIR/foxy-location$suffix"
}

lane_running() {
  [ -f "$PID_FILE" ] || return 1
  local pid; pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

lane_pid() { cat "$PID_FILE" 2>/dev/null || true; }

# Only a foxy lane has an allowance to report, and its own config says so without asking the plane.
foxy_lane_configured() {
  [ -f "$CFG" ] && grep -q '"protocol"[[:space:]]*:[[:space:]]*"foxy"' "$CFG" 2>/dev/null
}

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3>&- ; }

wait_fronts() {
  local front port i
  for front in ${FRONTS//,/ }; do
    case "$front" in
      socks) port="$SOCKS_PORT" ;;
      http) port="$HTTP_PORT" ;;
      mixed) port="$MIXED_PORT" ;;
      *) continue ;;
    esac
    for i in $(seq 1 90); do
      port_open "$port" && break
      lane_running || return 1
      sleep 1
    done
    port_open "$port" || return 1
  done
  return 0
}

port_map() {
  local front
  for front in ${FRONTS//,/ }; do
    case "$front" in
      socks) printf '  SOCKS5        socks5://127.0.0.1:%s   (curl --socks5-hostname, UDP-aware)\n' "$SOCKS_PORT" ;;
      http)  printf '  HTTP + HTTPS  http://127.0.0.1:%s     (CONNECT tunnels, plain forwards)\n' "$HTTP_PORT" ;;
      mixed) printf '  mixed         http://127.0.0.1:%s     (SOCKS5 and HTTP on one port)\n' "$MIXED_PORT" ;;
    esac
  done
}

# One converter, one sentence: a refusal says what is missing and prints no
# second line restating it.
build_outbound() {
  local lane="$1" json
  json="$("${lane}_outbound" 2>&1)" || die "$json"
  printf '%s' "$json"
}

build_config() {
  local outbound
  case "$OUTBOUND" in
    foxy)
      read_credentials
      load_foxy_location
      # A session already signed in is the account: the credentials file only
      # has to exist for the first sign-in, and a resume needs no password.
      if [ -z "$EMAIL" ]; then EMAIL="$(stored_email)"; fi
      if [ -z "$EMAIL" ] || { [ -z "$PASSWORD" ] && ! same_stored_account; }; then
        [ -t 0 ] || die "no account: run 'ferrox-cli login' first, or pass --email and --password"
        say "Foxy needs a Firefox account — an email and a password, no server to name."
        LOGIN_QUIET=1 action_login
        say "account saved to $CREDS (owner-only); connecting."
        read_credentials
      fi
      outbound="$(build_outbound foxy)" || exit 1
      save_foxy_location
      ;;
    vless)
      case "$VLESS" in
        vless://*) ;;
        *) die "--vless wants a vless:// share link, got '$VLESS'; nothing was started.
  example: ferrox-cli up --vless 'vless://uuid@host:443?type=ws&security=tls&sni=host&path=/ws'" ;;
      esac
      outbound="$(build_outbound vless)" || exit 1
      ;;
    veepn) outbound="$(build_outbound veepn)" || exit 1 ;;
    vmess) outbound="$(build_outbound vmess)" || exit 1 ;;
    trojan) outbound="$(build_outbound trojan)" || exit 1 ;;
    ss) outbound="$(build_outbound ss)" || exit 1 ;;
    config)
      [ -f "$CONFIG_FILE" ] || die "no such config: $CONFIG_FILE"
      CFG="$CONFIG_FILE"
      return 0
      ;;
    *)
      cat >&2 <<EOF
ferrox-cli: no outbound chosen; nothing was started.
  --foxy                 account only, no server to name (asks once)
  --veepn                anonymous: no account and no server
  --vless 'vless://...'  a share link
  --vmess HOST:PORT --uuid ID
  --trojan HOST:PORT --password PW
  --ss HOST:PORT --method METHOD --password PW
  --config FILE          any JSON config this binary serves
Run 'ferrox-cli up --foxy --vpn' for the shortest path, or --help for the menu.
EOF
      exit 2
      ;;
  esac
  write_config "$outbound" || die "cannot write $CFG"
}

# The carrier is a choice, not a default: h2 is the rung auto opens on and h3 is
# the only one that carries UDP. Asked once on a terminal, never of a pipe, and
# an empty answer or an unreadable one takes auto rather than stopping the lane.
choose_carrier() {
  if [ "$OUTBOUND" != foxy ] || [ "$CARRIER_SET" = 1 ] || [ ! -t 0 ]; then
    return 0
  fi
  say "carrier: where the lane sends its flows (name --carrier to skip this):"
  say "  1) auto  h2, then h1, then h3 — the fastest that answers (default)"
  say "  2) h2    HTTPS/2 on a session reused across flows"
  say "  3) h1    one TLS connection per flow"
  say "  4) h3    QUIC; also carries UDP. Falls back to h2, then h1"
  printf 'carrier [auto]: '
  local answer=""
  IFS= read -r answer || true
  case "$(printf '%s' "$answer" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
    ""|1|auto) CARRIER=auto ;;
    2|h2) CARRIER=h2 ;;
    3|h1) CARRIER=h1 ;;
    4|h3) CARRIER=h3 ;;
    *) say "carrier: '$answer' is not one of the four; using auto."; CARRIER=auto ;;
  esac
}

start_lane() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null || true
  # Validate first: an invocation that cannot start must not stop a healthy lane,
  # and a bad link must not send the user to a build before saying what is wrong.
  build_config
  require_bin
  if lane_running; then
    say "a lane${INSTANCE:+ '$INSTANCE'} is already running (pid $(lane_pid)); stopping it first."
    stop_lane 0
  fi
  if [ "$DEBUG" = 1 ]; then
    FOXY_DEBUG=1 "$BIN" run -c "$CFG" >"$LOG" 2>&1 &
  else
    "$BIN" run -c "$CFG" >"$LOG" 2>&1 &
  fi
  echo "$!" > "$PID_FILE"
}

stop_lane() {
  local clear="${1:-1}"
  if lane_running; then
    kill "$(lane_pid)" 2>/dev/null || true
    sleep 1
    lane_running && kill -9 "$(lane_pid)" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  [ "$clear" = 1 ] && system_proxy_off
  return 0
}

# The config is ours only when we generated it: a --config file belongs to its owner.
stop_and_forget() {
  stop_lane 1
  [ "$OUTBOUND" = config ] || rm -f "$CFG"
}

# The account is shared, so signing out ends every lane; each owns its pid and config.
stop_all_lanes() {
  local pidfile base
  for pidfile in "$CONF_DIR"/lane*.pid; do
    [ -f "$pidfile" ] || continue
    base="${pidfile##*/}"; base="${base#lane}"; base="${base%.pid}"
    INSTANCE="${base#-}"
    apply_instance
    stop_lane 0
    rm -f "$CFG"
  done
  INSTANCE=""
  apply_instance
  system_proxy_off
}

other_lanes() {
  local pidfile base pid
  for pidfile in "$CONF_DIR"/lane-*.pid; do
    [ -f "$pidfile" ] || continue
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || continue
    base="${pidfile##*/}"; base="${base#lane-}"; base="${base%.pid}"
    printf '  %s (pid %s)\n' "$base" "$pid"
  done
}

# -------------------------------------------------------------------- actions

# One trace through the first front: a lane that listens but cannot dial is not
# connected, and saying so here is cheaper than a browser that times out.
probe_front() {
  local front="$1" port="$2"
  if [ "$front" = socks ]; then
    curl -s --noproxy '' --max-time "$PROBE_TIMEOUT" --socks5-hostname "127.0.0.1:$port" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null
  else
    curl -s --noproxy '' --max-time "$PROBE_TIMEOUT" -x "http://127.0.0.1:$port" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null
  fi
}

# A VeePN edge is a free pool with its own blocklist, so a refused trace host is
# not proof about the lane: a plain 200 is what says the flow got through.
probe_plain() {
  local front="$1" port="$2"
  if [ "$front" = socks ]; then
    curl -s --noproxy '' --max-time "$PROBE_TIMEOUT" --socks5-hostname "127.0.0.1:$port" http://example.com/ 2>/dev/null
  else
    curl -s --noproxy '' --max-time "$PROBE_TIMEOUT" -x "http://127.0.0.1:$port" http://example.com/ 2>/dev/null
  fi
}

# Why a lane that listens still carries nothing: read the lane's own words, and
# if it said nothing, ask it again with the dial trace on.
diagnose() {
  local quiet=0
  if ! grep -q . "$LOG" 2>/dev/null; then quiet=1; fi
  if [ "$quiet" = 1 ] && [ "$DEBUG" = 0 ]; then
    say "the lane log is empty: it refuses a flow without saying why. Re-running"
    say "it once with the dial trace on to get the reason."
    DEBUG=1
    start_lane >/dev/null 2>&1
    wait_fronts >/dev/null 2>&1
    probe_front "${FRONTS%%,*}" "$(front_port_of "${FRONTS%%,*}")" >/dev/null 2>&1
  fi
  if grep -q . "$LOG" 2>/dev/null; then
    say "the lane's own words, last lines of $LOG:"
    tail -n 8 "$LOG"
  else
    say "the lane log stayed empty even with the trace on: nothing was dialled,"
    say "so the front refused the request before any carrier was tried."
    return 0
  fi
  # The VeePN lane has no account and no edge it configures: every refusal it
  # writes is about the plane or the region, so its three shapes are its own.
  if [ "$OUTBOUND" = veepn ]; then
    if grep -q "answers 422" "$LOG"; then
      say "diagnosis: the plane does not list the region that was named. Its free pool"
      say "uses lowercase ids (nl, us-va, gb-lnd); leaving --region off lets the plane"
      say "name the fastest one it serves."
    elif grep -q "refuses its pairs" "$LOG"; then
      say "diagnosis: an edge refused the pair the plane listed, so the lane dropped"
      say "the region's list; run up again, or move the exit with --region CC."
    elif grep -q "refused by the edge" "$LOG"; then
      say "diagnosis: the edge answered that it will not carry this target. The pair"
      say "and the region are healthy; the host is what was refused."
    elif grep -q "relay forward ended after" "$LOG" && ! grep -qE "relay backward ended after [1-9]" "$LOG"; then
      say "diagnosis: an edge granted the CONNECT and then closed the tunnel without"
      say "returning a byte, so the plane, the region and the pair are healthy: this"
      say "network's path to the edge's relay is what drops the flow."
    elif grep -q "declined" "$LOG"; then
      say "diagnosis: every upstream the region listed declined. That is this network"
      say "failing to reach the plane's edges, not an account: try another region, or"
      say "--domains with an origin this network reaches."
    else
      say "diagnosis: the plane answered no list this lane can dial; the lines above"
      say "name the region and the reason."
    fi
    return 0
  fi
  if grep -q "handshake with the edge failed" "$LOG"; then
    say "diagnosis: TLS to the edge never completed. That is the network, not"
    say "the account: chain the dial through a proxy this network does allow:"
    say "  ferrox-cli up --foxy --upstream socks5://127.0.0.1:PORT"
    if grep -q "the edge closed the stream" "$LOG"; then
      say "the QUIC carrier got a handshake and the edge closed the stream, so"
      say "UDP reaches the edge while TCP is dropped: force --carrier h3 to see"
      say "whether the pass itself is refused, or keep --upstream for TCP."
    fi
  elif grep -q "the carrier io failed" "$LOG"; then
    say "diagnosis: a carrier's path answered no datagram. Many networks drop UDP"
    say "and QUIC while TCP works, so a named h3 has already walked h2 and h1; if"
    say "every rung is in the lines above, the edge or the hop drops both."
  elif grep -q "the edge closed the stream" "$LOG"; then
    say "diagnosis: the QUIC carrier reached the edge and HTTP/2 answered the same"
    say "pass with 401, so the edge refuses the pass this lane signed in for. The"
    say "account is not entitled here: check the subscription and its devices at"
    say "https://vpn.mozilla.org, or move the exit with --country."
  elif grep -qE "did not sign in|token was refused" "$LOG"; then
    say "diagnosis: the lane never signed in, so it has no pass to dial with. The"
    say "account or password in $CREDS is refused, or the account wants a"
    say "two-factor code: ferrox-cli up --foxy --code 123456."
  elif grep -qE "no quota left|answered 429" "$LOG"; then
    say "diagnosis: the plane is refusing this account for quota, and it names when"
    say "that resets. Wait for it; signing in again does not buy bytes back."
  else
    say "diagnosis: none of the known shapes; the lines above are all there is."
  fi
}

front_port_of() {
  case "$1" in
    socks) printf '%s' "$SOCKS_PORT" ;;
    mixed) printf '%s' "$MIXED_PORT" ;;
    *) printf '%s' "$HTTP_PORT" ;;
  esac
}

verify_flow() {
  local front port answer got want
  front="${FRONTS%%,*}"
  port="$(front_port_of "$front")"
  answer="$(probe_front "$front" "$port")"
  if ! printf '%s\n' "$answer" | grep -qE '^(ip|loc)='; then
    if [ "$OUTBOUND" = veepn ] && probe_plain "$front" "$port" | grep -q 'Example Domain'; then
      say "exit through $front: a plain HTTP flow answered."
      return 0
    fi
    say "NOT CONNECTED: the fronts are up, but no flow got through them."
    diagnose
    return 1
  fi
  say "exit through $front: $(printf '%s\n' "$answer" | grep -E '^(ip|loc)=' | tr '\n' ' ')"
  # Any answer at all is not proof: this machine's own exit answers the same trace.
  want="$(printf '%s' "$COUNTRY" | tr '[:lower:]' '[:upper:]')"
  got="$(printf '%s\n' "$answer" | sed -n 's/^loc=//p' | tr '[:lower:]' '[:upper:]')"
  # The plane's free pool may route outside the region it lists, so a pinned
  # region that reads otherwise is named and the flow still counts as carried.
  if [ "$OUTBOUND" = veepn ]; then
    want="$(effective_region)"
    got="$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]')"
    if [ -n "$want" ] && [ "$got" != "$want" ]; then
      say "note: the exit reads ${got:-unreadable}, not the pinned $want; the plane's"
      say "pool can route elsewhere, so the front is carrying the flow either way."
    fi
  fi
  if [ "$OUTBOUND" = foxy ] && [ "$want" != REC ] && [ "$got" != "$want" ]; then
    say "the exit reads ${got:-unreadable}, not the pinned $want: that is either another"
    say "country's edge or this machine's own address, so the lane is not carrying it."
    diagnose
    return 1
  fi
  return 0
}

action_up() {
  choose_carrier
  start_lane
  # An attempt cut short is not a lane: Ctrl-C before it proves a flow removes what it started.
  trap 'stop_and_forget; say "interrupted: the lane was stopped and its config removed; the log stays at $LOG."; exit 130' INT TERM
  if [ -n "$FRONTS" ] && ! wait_fronts; then
    say "the lane did not open its fronts; last lines of $LOG:"
    tail -n 20 "$LOG" 2>/dev/null || true
    stop_and_forget
    say "the lane was stopped and its config removed; the log stays at $LOG."
    exit 1
  fi
  say "lane${INSTANCE:+ '$INSTANCE'} up (pid $(lane_pid)), fronts:"
  if [ "$OUTBOUND" = config ]; then
    say "  the ones $CONFIG_FILE names (served verbatim)"
  fi
  port_map
  [ "$OUTBOUND" = foxy ] && say "carrier: $CARRIER"
  local ok=0
  if [ -n "$FRONTS" ]; then verify_flow || ok=1; fi
  if [ "$ok" = 1 ]; then
    # A lane that carries no flow is a leftover, not a result: end it here.
    stop_and_forget
    say "the lane was stopped and its config removed; nothing is routed, and the"
    say "log stays at $LOG."
    exit 3
  fi
  # Route the machine only at a lane that proved it carries a flow: an armed
  # system proxy over a dead lane takes the network down with it.
  if [ "$WANT_VPN" = 1 ] && ! system_proxy_on; then
    stop_and_forget
    say "the system proxy was not armed; the lane was stopped and its config removed."
    exit 1
  fi
  say "log:  $LOG"
  say "stop: ferrox-cli down"
}

action_serve() {
  choose_carrier
  start_lane
  # A serve that never proved a flow is an attempt too: the same interruption cleanup applies.
  trap 'stop_and_forget; say "interrupted: the lane was stopped and its config removed; the log stays at $LOG."; exit 130' INT TERM
  if [ -n "$FRONTS" ] && ! wait_fronts; then
    say "the lane did not open its fronts; last lines of $LOG:"
    tail -n 20 "$LOG" 2>/dev/null || true
    stop_and_forget
    say "the lane was stopped and its config removed; the log stays at $LOG."
    exit 1
  fi
  say "lane${INSTANCE:+ '$INSTANCE'} up, fronts:"
  if [ "$OUTBOUND" = config ]; then
    say "  the ones $CONFIG_FILE names (served verbatim)"
  fi
  port_map
  [ "$OUTBOUND" = foxy ] && say "carrier: $CARRIER"
  local ok=0
  if [ -n "$FRONTS" ]; then verify_flow || ok=1; fi
  if [ "$ok" = 1 ]; then
    stop_and_forget
    say "the lane was stopped and its config removed; nothing is routed, and the"
    say "log stays at $LOG."
    exit 3
  fi
  if [ "$WANT_VPN" = 1 ] && ! system_proxy_on; then
    stop_and_forget
    say "the system proxy was not armed; the lane was stopped and its config removed."
    exit 1
  fi
  say "Ctrl-C stops it."
  trap 'stop_and_forget; exit 0' INT TERM
  local pid; pid="$(lane_pid)"
  while [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; do sleep 2; done
  say "the lane exited; last lines of $LOG:"
  tail -n 15 "$LOG" 2>/dev/null || true
  stop_and_forget
}

action_status() {
  if ! lane_running; then
    say "lane${INSTANCE:+ '$INSTANCE'} not running."
    local others; others="$(other_lanes)"
    if [ -n "$others" ]; then
      say "instances running:"
      printf '%s\n' "$others"
      say "read one with: ferrox-cli status --instance NAME"
    fi
    [ -f "$TOKEN_FILE" ] && say "foxy session stored in $TOKEN_FILE: the next up --foxy resumes it without a sign-in mail."
    return 1
  fi
  say "lane${INSTANCE:+ '$INSTANCE'} pid $(lane_pid), fronts:"
  port_map
  local pid uptime chosen quota
  pid="$(lane_pid)"
  uptime="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$uptime" ] && say "up for $uptime"
  chosen="$(sed -n 's/^foxy: carrier //p' "$LOG" 2>/dev/null | tail -n 1)"
  [ -n "$chosen" ] && say "carrier: $chosen"
  quota="$(sed -n 's/^foxy: allowance //p' "$LOG" 2>/dev/null | tail -n 1)"
  if [ -n "$quota" ]; then
    say "quota left: $quota"
  elif [ -n "$chosen" ]; then
    say "quota: the plane named no allowance for the pass this lane carries: that is silence, not zero."
  elif foxy_lane_configured; then
    say "quota: this lane's binary names neither the carrier nor the allowance; 'down' then 'up' restarts it on the binary this script runs."
  fi
  local front port mode answer
  front="${FRONTS%%,*}"
  case "$front" in
    socks) port="$SOCKS_PORT"; mode=socks ;;
    mixed) port="$MIXED_PORT"; mode=http ;;
    *) port="$HTTP_PORT"; mode=http ;;
  esac
  say "exit through $front ($port):"
  if [ "$mode" = socks ]; then
    answer="$(curl -s --noproxy '' --max-time 30 --socks5-hostname "127.0.0.1:$port" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)"
  else
    answer="$(curl -s --noproxy '' --max-time 30 -x "http://127.0.0.1:$port" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)"
  fi
  printf '%s\n' "$answer" | grep -E '^(ip|loc)=' || say "no answer through the front; see $LOG"
}

action_ports() {
  rule
  say "local fronts (127.0.0.1 only):"
  port_map
  if [ -n "$INSTANCE" ]; then
    rule
    [ -f "$CFG" ] || say "instance '$INSTANCE' has not started: these are the defaults it moves off if they are taken."
    say "point the app you want at these fronts: the macOS system proxy is one"
    say "machine-wide setting, so an instance never arms it (--vpn belongs to the"
    say "unnamed lane)."
    return 0
  fi
  rule
  cat <<EOF
macOS, System Settings > Network > <service> > Details... > Proxies:
  Web proxy (HTTP)     127.0.0.1:$HTTP_PORT
  Secure web proxy     127.0.0.1:$HTTP_PORT
  SOCKS proxy          127.0.0.1:$SOCKS_PORT
Turn on all three, leave "Proxy server requires password" off (the fronts are
unauthenticated and loopback-only), and put local names in "Bypass proxy
settings for these hosts and domains":  *.local, 169.254/16

One app instead of the whole system:
  curl --socks5-hostname 127.0.0.1:$SOCKS_PORT https://example.com
  curl -x http://127.0.0.1:$HTTP_PORT https://example.com
  HTTPS_PROXY=http://127.0.0.1:$HTTP_PORT ALL_PROXY=socks5h://127.0.0.1:$SOCKS_PORT git clone ...
EOF
}

action_version() {
  require_bin
  say "ferrox-cli at $SCRIPT_DIR"
  "$BIN" version
}

action_tun() {
  cat <<EOF
TUN mode is refused by this binary, by name, not by silence.

What TUN would be: a virtual network device (utun on macOS) that takes every IP
packet, so apps that ignore proxies are captured too, UDP included. That needs
a device driver, a userspace IP stack, and root or a signed entitlement.

What this binary has: no tun/utun inbound and no tun2socks engine (README rows
29 and 58). A config naming one is refused with that reason, and \`--tun\` here
refuses before anything starts.

What you get instead:
  * ferrox-cli up --vpn      the macOS system proxy: TCP apps that honour it
  * ferrox-cli up --fronts socks   UDP for apps that speak SOCKS5 (browsers do
                             not send UDP to a SOCKS proxy, so their QUIC goes
                             around the lane)
EOF
}

# ---------------------------------------------------------------------- parse

while [ $# -gt 0 ]; do
  case "$1" in
    up|serve|down|status|ports|tun|login|logout|version) ACTION="$1"; shift ;;
    locations)
      ACTION=locations; shift
      # Both spellings: `locations --ping US` and `locations US --ping`.
      if [ $# -gt 0 ] && [ "$1" = --ping ]; then LOC_PING=1; shift; fi
      if [ $# -gt 0 ]; then
        case "$1" in
          -*) ;;
          *) LOC_FILTER="$1"; shift ;;
        esac
      fi ;;
    location)
      ACTION=location; shift
      if [ $# -gt 0 ]; then
        case "$1" in
          -*) ;;
          *) LOC_COUNTRY="$1"; shift ;;
        esac
      fi
      if [ $# -gt 0 ]; then
        case "$1" in
          -*) ;;
          *) LOC_CITY="$1"; shift ;;
        esac
      fi ;;
    --foxy) OUTBOUND=foxy; shift ;;
    --veepn) OUTBOUND=veepn; shift ;;
    --vless) need_value --vless "a vless:// share link" "$#" "${2:-}"; OUTBOUND=vless; VLESS="$2"; shift 2 ;;
    --vmess) need_value --vmess "HOST:PORT" "$#" "${2:-}"; OUTBOUND=vmess; VMESS="$2"; shift 2 ;;
    --uuid) need_value --uuid "the VMess user id" "$#" "${2:-}"; VMESS_ID="$2"; shift 2 ;;
    --network) need_value --network "tcp or ws" "$#" "${2:-}"; VMESS_NETWORK="$2"; shift 2 ;;
    --trojan) need_value --trojan "HOST:PORT" "$#" "${2:-}"; OUTBOUND=trojan; TROJAN="$2"; shift 2 ;;
    --ss) need_value --ss "HOST:PORT" "$#" "${2:-}"; OUTBOUND=ss; SS="$2"; shift 2 ;;
    --method) need_value --method "a shadowsocks method" "$#" "${2:-}"; SS_METHOD="$2"; shift 2 ;;
    --config) need_value --config "a JSON config path" "$#" "${2:-}"; OUTBOUND=config; CONFIG_FILE="$2"; shift 2 ;;
    --email) need_value --email "an email address" "$#" "${2:-}"; EMAIL="$2"; shift 2 ;;
    --password) need_value --password "a password" "$#" "${2:-}"; PASSWORD="$2"; shift 2 ;;
    --code) need_value --code "a two-factor code" "$#" "${2:-}"; CODE="$2"; shift 2 ;;
    --country) need_value --country "a country code" "$#" "${2:-}"; COUNTRY="$2"; COUNTRY_SET=1; shift 2 ;;
    --region) need_value --region "a region id" "$#" "${2:-}"; REGION="$2"; shift 2 ;;
    --domains) need_value --domains "comma-separated origins" "$#" "${2:-}"; VEEPN_DOMAINS="$2"; shift 2 ;;
    --udid) need_value --udid "a device id" "$#" "${2:-}"; VEEPN_UDID="$2"; shift 2 ;;
    --city) need_value --city "a city code" "$#" "${2:-}"; CITY="$2"; CITY_SET=1; shift 2 ;;
    --carrier)
      need_value --carrier "auto, h1, h2 or h3" "$#" "${2:-}"
      case "$2" in
        auto|h1|h2|h3) CARRIER="$2" ;;
        *) die "--carrier wants auto, h1, h2 or h3, got '$2'; nothing was started." ;;
      esac
      CARRIER_SET=1; shift 2 ;;
    --upstream) need_value --upstream "an http:// or socks5:// URL" "$#" "${2:-}"; UPSTREAM="$2"; shift 2 ;;
    --exclude-domains) need_value --exclude-domains "comma-separated domain suffixes" "$#" "${2:-}"; EXCLUDE_DOMAINS="$2"; shift 2 ;;
    --exclude-ports) need_value --exclude-ports "comma-separated ports" "$#" "${2:-}"; EXCLUDE_PORTS="$2"; shift 2 ;;
    --fronts) need_value --fronts "a comma-separated front list" "$#" "${2:-}"; FRONTS="$2"; FRONTS_SET=1; shift 2 ;;
    --socks) need_port --socks "$#" "${2:-}"; SOCKS_PORT="$2"; SOCKS_SET=1; shift 2 ;;
    --http) need_port --http "$#" "${2:-}"; HTTP_PORT="$2"; HTTP_SET=1; shift 2 ;;
    --mixed) need_port --mixed "$#" "${2:-}"; MIXED_PORT="$2"; MIXED_SET=1; shift 2 ;;
    --instance)
      need_value --instance "a name of letters, digits, - or _" "$#" "${2:-}"
      case "$2" in
        *[!A-Za-z0-9_-]*) die "--instance wants letters, digits, - or _, got '$2'; nothing was started." ;;
      esac
      [ "${#2}" -le 32 ] || die "an --instance name is at most 32 characters; nothing was started."
      INSTANCE="$2"; shift 2 ;;
    --all) ALL=1; shift ;;
    --vpn) WANT_VPN=1; shift ;;
    --debug) DEBUG=1; shift ;;
    --ping) LOC_PING=1; shift ;;
    --tun) ACTION=tun; shift ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) ACTION=version; shift ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

# A measurement flag belongs to the listing: a lane started by a typo is not one.
if [ "$LOC_PING" = 1 ] && [ "$ACTION" != locations ]; then
  die "--ping belongs to 'locations' (ferrox-cli locations --ping); nothing was started."
fi

# Excluded targets leave the tunnel unencrypted, so the lists are foxy-only and refused before a lane is touched.
if [ -n "$EXCLUDE_DOMAINS$EXCLUDE_PORTS" ] && [ "$OUTBOUND" != foxy ]; then
  die "--exclude-domains and --exclude-ports belong to the foxy lane; nothing was started."
fi

if [ "$ALL" = 1 ]; then
  [ "$ACTION" = down ] || die "--all belongs to 'down' (ferrox-cli down --all); nothing was started."
  [ -z "$INSTANCE" ] || die "--all stops every lane, so it takes no --instance; nothing was started."
fi

# The macOS system proxy is one machine-wide setting: two lanes cannot share it.
if [ -n "$INSTANCE" ] && [ "$WANT_VPN" = 1 ]; then
  die "the system proxy points at one lane: run '$INSTANCE' without --vpn and point the app at its fronts (ferrox-cli ports --instance $INSTANCE), or arm --vpn on the unnamed lane; nothing was started."
fi

apply_instance
case "$ACTION" in
  up|serve)
    scan=0
    if [ "$OUTBOUND" = config ]; then
      CFG="$CONFIG_FILE"
      FRONTS="$(config_fronts 2>&1)" || die "$FRONTS"
      # The file is served verbatim, so its ports win over the flags.
      SOCKS_SET=0; HTTP_SET=0; MIXED_SET=0
    else
      [ -n "$INSTANCE" ] && scan=1
    fi
    planned="$(plan_ports "$scan")" || die "the lane's ports could not be chosen; nothing was started."
    read -r SOCKS_PORT HTTP_PORT MIXED_PORT <<<"$planned"
    seen=""
    for front in ${FRONTS//,/ }; do
      case "$front" in
        socks) port="$SOCKS_PORT" ;;
        http) port="$HTTP_PORT" ;;
        mixed) port="$MIXED_PORT" ;;
        *) continue ;;
      esac
      case " $seen " in *" $port "*) die "two fronts cannot share port $port; nothing was started." ;; esac
      seen="$seen $port"
    done ;;
  status|ports) adopt_lane_ports || true ;;
esac

# A VeePN flow pays a launch and a list before bytes move, so its first probe
# waits longer than a lane that configures the server it dials.
[ "$OUTBOUND" = veepn ] && PROBE_TIMEOUT=45

# Only up, serve and version need the binary: down, status and login must
# still work when it was never fetched.
require_bin() {
  resolve_bin
  [ -x "$BIN" ] && return 0
  # In a checkout the binary is a build, not a download: build it once rather
  # than send the reader to a release page for a lane this tree already has.
  if [ -f "$ROOT/Cargo.toml" ] && command -v cargo >/dev/null 2>&1; then
    say "building ferrox-app (release, one time)..."
    ( cd "$ROOT" && cargo build --locked --release -p ferrox-app ) >&2 || die "the build failed"
    [ -x "$BIN" ] || die "the build finished but $BIN is still missing"
    return 0
  fi
  die "no binary at $BIN: unpack a release package beside this script (https://github.com/FerroxCo/ferrox/releases), or build one: cargo build --release -p ferrox-app"
}

case "$ACTION" in
  up) action_up ;;
  serve) action_serve ;;
  login) action_login ;;
  logout) action_logout ;;
  locations) action_locations ;;
  location) action_location ;;
  down)
    if [ "$ALL" = 1 ]; then
      stop_all_lanes
      say "every lane is stopped and its config removed. The stored foxy session is kept; 'ferrox-cli logout' forgets it."
    else
      stop_lane 1; rm -f "$CFG"
      say "lane${INSTANCE:+ '$INSTANCE'} stopped; the lane config is removed. The stored foxy session is kept; 'ferrox-cli logout' forgets it."
    fi ;;
  status) action_status ;;
  ports) action_ports ;;
  tun) action_tun ;;
  version) action_version ;;
esac
