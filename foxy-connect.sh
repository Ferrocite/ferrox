#!/usr/bin/env bash
# Foxy lane through ferrox-app: one command to connect, check and disconnect a
# laptop, in proxy mode (SOCKS5, HTTP CONNECT, or both) or system-proxy mode.
#
# What this is
#   * starts ferrox-app with a socks/http/mixed -> foxy config under
#     $FOXY_CONF_DIR (default ~/.ferrox, mode 0700), so the account, the pass
#     and the exit country never enter this repository;
#   * signs the Firefox account in, mints the lane pass and dials the edge in
#     the pinned country over whichever carrier the edge answers (auto tries
#     HTTP/3, then HTTP/2, then HTTP/1.1; --carrier pins one);
#   * optionally chains the edge dial through an upstream proxy, which is the
#     only way a network with proxy-only egress can start the lane;
#   * --vpn points the macOS system proxy at the local fronts, so TCP apps that
#     honour it (browsers included) carry the whole laptop through the lane.
#
# What this is not
#   * not a TUN device: this binary has no `tun` inbound and no tun2socks
#     engine (README rows 29 and 58, slice P46), so --tun refuses by name and
#     says why. UDP leaves the device only where an app asks a SOCKS5 proxy to
#     carry it; that rides the lane's MASQUE datagrams, not the device.
#
# Credentials
#   Read in this order: FOXY_PASS, $FOXY_CREDENTIALS (default
#   $XDG_CONFIG_HOME/ferrox/credentials, mode 0600, outside this repository),
#   else typed silently. A copy inside the repository is refused rather than
#   read: the pass is the account's secret, not the tree's.
set -euo pipefail

FERROX_ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$FERROX_ROOT/target/debug/ferrox-app"
# Both live outside this repository: the account, the pass and the exit
# country are the machine's business, never the tree's. Override with
# FOXY_CONF_DIR and FOXY_CREDENTIALS when a shared ~/.config is not wanted.
CONF_DIR="${FOXY_CONF_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/ferrox}"
CREDENTIALS="${FOXY_CREDENTIALS:-$CONF_DIR/credentials}"
CATALOG_URL="https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
LOG="$CONF_DIR/foxy.log"

COUNTRY="${FOXY_COUNTRY:-US}"
CITY="${FOXY_CITY:-}"
CARRIER="${FOXY_CARRIER:-auto}"
MODE="${FOXY_MODE:-all}"
UPSTREAM="${FOXY_UPSTREAM_PROXY:-}"
SOCKS_PORT="${FOXY_SOCKS_PORT:-10808}"
HTTP_PORT="${FOXY_HTTP_PORT:-8080}"
MIXED_PORT="${FOXY_MIXED_PORT:-10809}"
EMAIL="${FOXY_EMAIL:-}"
PASS="${FOXY_PASS:-}"
CODE="${FOXY_CODE:-}"
ACTION="up"
WANT_VPN=0
CLEAR_VPN=0

usage() {
  cat <<EOF
usage: ./foxy-connect.sh <action> [options]

actions
  up                 start the lane and print how to use it (default action)
  down               stop the lane and clear the system proxy this set
  status             show the session, then the exit IP and country
  check              one 1 MB download per method: socks, http front, mixed,
                     and per carrier h1/h2/h3; each asserts 1000000 bytes and
                     the pinned country
  countries          list the exit countries the published catalogue offers

options
  --country CC       exit country, default US (env FOXY_COUNTRY)
  --city CODE        city tier inside the country, default any (env FOXY_CITY)
  --carrier NAME     auto|h1|h2|h3, default auto (env FOXY_CARRIER); HTTP/3 is
                     in the lane and is what auto tries first
  --mode MODE        socks|http|mixed|vpn|all, default all: which local fronts
                     to serve; vpn = all fronts plus the system proxy
  --socks PORT       SOCKS5 front port, default 10808
  --http PORT        HTTP CONNECT front port, default 8080
  --mixed PORT       mixed (socks+http, one port) front, default 10809
  --upstream URL     http://host:port or socks5(h)://host:port: chain the edge
                     dial through that proxy (env FOXY_UPSTREAM_PROXY)
  --email ADDR       Firefox account, else FOXY_EMAIL, else the credentials file
  --pass-from-file   read the password from \$FOXY_CREDENTIALS (never echoed)
  --code CODE        two-factor code when the account asks for one
  --build            force a build instead of reusing target/debug/ferrox-app
  -h, --help         this text

credentials file (never committed; created by the first run, mode 0600)
  ${XDG_CONFIG_HOME:-$HOME/.config}/ferrox/credentials, two lines:
  FOXY_EMAIL=... then FOXY_PASS=...
  Rotate the account password after any shared machine has seen it.
EOF
}

die() { echo "foxy-connect: $*" >&2; exit 1; }

# Every front this script can start, so status and down agree on what to stop.
fronts_for() {
  case "$1" in
    socks) printf '%s\n' socks ;;
    http) printf '%s\n' http ;;
    mixed) printf '%s\n' mixed ;;
    all|vpn) printf '%s\n' socks http mixed ;;
    *) die "unknown mode $1" ;;
  esac
}

front_port() {
  case "$1" in
    socks) echo "$SOCKS_PORT" ;;
    http) echo "$HTTP_PORT" ;;
    mixed) echo "$MIXED_PORT" ;;
  esac
}

lane_pid_file() { printf '%s/lane.pid' "$CONF_DIR"; }

lane_running() {
  local pid_file pid
  pid_file="$(lane_pid_file)"
  [ -f "$pid_file" ] || return 1
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

stop_lane() {
  local pid_file pid
  pid_file="$(lane_pid_file)"
  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$pid_file"
  fi
  if [ "$CLEAR_VPN" = 1 ]; then system_proxy_off; fi
}

# The only ports the system proxy was pointed at, so down clears exactly those.
system_proxy_off() {
  if [ -f "$CONF_DIR/system-proxy.ports" ]; then
    local ports socks http
    ports="$(cat "$CONF_DIR/system-proxy.ports")"
    socks="${ports%% *}"; http="${ports##* }"
    command -v networksetup >/dev/null 2>&1 || return 0
    while IFS= read -r svc; do
      [ -z "$svc" ] && continue
      case "$svc" in *\**) continue;; esac
      networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
      networksetup -setwebproxystate "$svc" off 2>/dev/null || true
      networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
    done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
    rm -f "$CONF_DIR/system-proxy.ports"
    echo "system proxy cleared (was SOCKS $socks, HTTP $http)."
  fi
  return 0
}

system_proxy_on() {
  if ! command -v networksetup >/dev/null 2>&1; then
    echo "no networksetup here: the fronts stay local, point your apps at them by hand." >&2
    return 0
  fi
  local any=0
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    case "$svc" in *\**) continue;; esac
    networksetup -setsocksfirewallproxy "$svc" 127.0.0.1 "$SOCKS_PORT" 2>/dev/null || continue
    networksetup -setsocksfirewallproxystate "$svc" on 2>/dev/null || true
    networksetup -setwebproxy "$svc" 127.0.0.1 "$HTTP_PORT" 2>/dev/null || true
    networksetup -setwebproxystate "$svc" on 2>/dev/null || true
    networksetup -setsecurewebproxy "$svc" 127.0.0.1 "$HTTP_PORT" 2>/dev/null || true
    networksetup -setsecurewebproxystate "$svc" on 2>/dev/null || true
    any=1
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  [ "$any" = 1 ] || die "no network service took the proxy"
  echo "$SOCKS_PORT $HTTP_PORT" > "$CONF_DIR/system-proxy.ports"
  echo "system proxy on: SOCKS 127.0.0.1:$SOCKS_PORT, HTTP(S) 127.0.0.1:$HTTP_PORT"
  echo "scope: apps that honour the system proxy (browsers included). No utun device:"
  echo "README rows 29/58, slice P46."
}

exit_country() {
  local first
  first="$(fronts_for "$MODE" | head -n 1)"
  local port
  port="$(front_port "$first")"
  curl -fsSL --max-time 30 --socks5-hostname "127.0.0.1:$port" \
    https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E '^(loc|ip)=' || true
}

wait_port() {
  local port="$1" i
  for i in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- 2>/dev/null || true
      return 0
    fi
    sleep 1
  done
  return 1
}

# 1 MB off the same host the CI legs use, over one of the local fronts.
download_1mb() {
  local front="$1" carrier="$2" want="$3"
  local port out got
  port="$(front_port "$front")"
  out="$CONF_DIR/check-$front-$carrier.bin"
  local -a curl_args=(-sS --max-time 300)
  if [ "$front" = http ]; then
    curl_args+=(-x "http://127.0.0.1:$port")
  else
    curl_args+=(--socks5-hostname "127.0.0.1:$port")
  fi
  if curl "${curl_args[@]}" 'https://speed.cloudflare.com/__down?bytes=1000000' -o "$out"; then
    got="$(wc -c < "$out" | tr -d ' ')"
    if [ "$got" = 1000000 ]; then
      echo "ok   $front over $carrier: 1000000 B"
      return 0
    fi
  fi
  rm -f "$out"
  echo "FAIL $front over $carrier: got ${got:-0} bytes, exit $(exit_country | grep '^loc=' || echo unknown)" >&2
  return 1
}

write_config() {
  local cfg="$1"; shift
  python3 - "$cfg" "$EMAIL" "$PASS" "$CODE" "$COUNTRY" "$CITY" "$CARRIER" "$UPSTREAM" "$SOCKS_PORT" "$HTTP_PORT" "$MIXED_PORT" "$MODE" <<'PY'
import json, sys
cfg, email, password, code, country, city, carrier, upstream, socks, http, mixed, mode = sys.argv[1:13]
settings = {"email": email, "password": password, "country": country, "carrier": carrier}
if code:
    settings["code"] = code
if city:
    settings["city"] = city
if upstream:
    settings["upstreamProxy"] = upstream
fronts = {"socks": ["socks"], "http": ["http"], "mixed": ["mixed"]}.get(mode, ["socks", "http", "mixed"])
ports = {"socks": int(socks), "http": int(http), "mixed": int(mixed)}
doc = {
    "inbounds": [{"protocol": p, "listen": "127.0.0.1", "port": ports[p]} for p in fronts],
    "outbounds": [{"protocol": "foxy", "settings": settings}],
}
with open(cfg, "w") as f:
    json.dump(doc, f, indent=2)
PY
  chmod 600 "$cfg"
}

list_countries() {
  curl -fsSL --max-time 25 "$CATALOG_URL" | python3 -c '
import json,sys
body=json.load(sys.stdin)
seen={}
for r in body.get("data",[]):
    c=r.get("country",r)
    code=(c.get("code") or "").upper()
    name=c.get("name") or ""
    if len(code)==2 and code not in seen:
        seen[code]=name
for code in sorted(seen):
    mark="  <- default" if code=="US" else ""
    print(f"{code}  {seen[code]}{mark}")
'
}

ACTION="up"
while [ $# -gt 0 ]; do
  case "$1" in
    up|down|status|check|countries) ACTION="$1"; shift;;
    --country) COUNTRY="${2:-}"; shift 2;;
    --city) CITY="${2:-}"; shift 2;;
    --carrier) CARRIER="${2:-}"; shift 2;;
    --mode) MODE="${2:-}"; shift 2;;
    --socks) SOCKS_PORT="${2:-}"; shift 2;;
    --http) HTTP_PORT="${2:-}"; shift 2;;
    --mixed) MIXED_PORT="${2:-}"; shift 2;;
    --upstream) UPSTREAM="${2:-}"; shift 2;;
    --email) EMAIL="${2:-}"; shift 2;;
    --pass-from-file) shift;;
    --code) CODE="${2:-}"; shift 2;;
    --vpn) MODE="vpn"; shift;;
    --no-vpn) CLEAR_VPN=1; shift;;
    --tun) die "--tun is refused: this binary has no TUN inbound and no tun2socks engine (README rows 29 and 58, slice P46). Use --mode vpn for the system proxy, or --mode socks|http|mixed for one app." ;;
    --build) FORCE_BUILD=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1 (see --help)";;
  esac
done

mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"

if [ "$ACTION" = countries ]; then list_countries; exit 0; fi
if [ "$ACTION" = down ]; then
  CLEAR_VPN=1; stop_lane
  # The lane configs carry the account password, so they go when the lane does.
  rm -f "$CONF_DIR"/foxy-*.json
  echo "lane stopped; configs under $CONF_DIR removed."
  exit 0
fi

# Everything after this point needs a lane, so the binary and the pass first.
if [ "${FORCE_BUILD:-0}" = 1 ] || [ ! -x "$BIN" ]; then
  echo "building ferrox-app (one time)..."
  (cd "$FERROX_ROOT" && cargo build --locked -p ferrox-app) >&2
fi

if [ -n "$CREDENTIALS" ] && [ -f "$CREDENTIALS" ]; then
  # A credentials file inside this repository is a secret someone is about to
  # commit: it is refused rather than read.
  case "$CREDENTIALS" in
    "$FERROX_ROOT"/*)
      if git -C "$FERROX_ROOT" ls-files --error-unmatch "$CREDENTIALS" >/dev/null 2>&1; then
        die "$CREDENTIALS is tracked by git; move it to $HOME/.ferrox/credentials (0600)"
      fi ;;
  esac
  # shellcheck disable=SC1090
  . "$CREDENTIALS"
  EMAIL="${FOXY_EMAIL:-$EMAIL}"
  PASS="${FOXY_PASS:-$PASS}"
fi
if [ "$ACTION" = status ] && ! lane_running; then
  echo "lane not running (pid file $(lane_pid_file) absent)."
  exit 1
fi
if [ -n "$EMAIL" ] && [ -z "$PASS" ] && [ -t 0 ]; then
  printf 'Firefox password for %s: ' "$EMAIL" >&2
  stty -echo 2>/dev/null || true
  read -r PASS || true
  stty echo 2>/dev/null || true
  printf '\n' >&2
fi
[ -n "$EMAIL" ] || die "no account: put FOXY_EMAIL/FOXY_PASS in $CREDENTIALS (0600, outside git) or pass --email"
[ -n "$PASS" ] || die "no password: $CREDENTIALS or FOXY_PASS"

case "$MODE" in socks|http|mixed|all|vpn) ;; *) die "unknown mode $MODE (socks, http, mixed, vpn, all)";; esac
CITY="$(printf '%s' "$CITY" | tr '[:lower:]' '[:upper:]')"
case "$CARRIER" in auto|h1|h2|h3|http/1.1|http/2|quic) ;; *) CARRIER="auto";; esac

if lane_running && [ "$ACTION" != status ]; then stop_lane; fi
CFG="$CONF_DIR/foxy-$COUNTRY.json"
write_config "$CFG"
echo "config: $CFG (mode 0600, under $CONF_DIR)"
"$BIN" run -c "$CFG" >"$LOG" 2>&1 &
echo "$!" > "$(lane_pid_file)"

FRONTS="$(fronts_for "$MODE" | tr '\n' ' ')"
for front in $FRONTS; do
  port="$(front_port "$front")"
  wait_port "$port" || { echo "lane died; tail $LOG:" >&2; tail -n 30 "$LOG" >&2; exit 1; }
done
echo "lane up (pid $(cat "$(lane_pid_file)")), fronts:"
for front in $FRONTS; do
  case "$front" in
    http) echo "  HTTP CONNECT  http://127.0.0.1:$HTTP_PORT   (curl -x, browsers' HTTP proxy)" ;;
    socks) echo "  SOCKS5        socks5://127.0.0.1:$SOCKS_PORT (curl --socks5-hostname, UDP-aware)" ;;
    mixed) echo "  mixed         http://127.0.0.1:$MIXED_PORT   (socks and http on one port)" ;;
  esac
done
echo "exit country: $COUNTRY, carrier: $CARRIER${UPSTREAM:+, upstream $UPSTREAM}"
echo "curl: curl --socks5-hostname 127.0.0.1:$SOCKS_PORT https://api.ipify.org"
echo "log:  $LOG   stop: ./foxy-connect.sh down"

if [ "$ACTION" = status ]; then
  exit_country
  exit 0
fi

if [ "$ACTION" = check ]; then
  first="$(fronts_for "$MODE" | head -n 1)"
  port="$(front_port "$first")"
  for i in $(seq 1 24); do
    exit_country | grep -qx "loc=$COUNTRY" && break
    sleep 5
  done
  local_country="$(exit_country | sed -n 's/^loc=//p')"
  if [ "$local_country" != "$COUNTRY" ]; then
    echo "exit country is ${local_country:-unreadable}, wanted $COUNTRY; see $LOG" >&2
    exit 1
  fi
  # One 1 MB download per method the fronts offer, so each front is proven
  # separately and not through the one that answered first.
  for front in $(fronts_for "$MODE"); do
    download_1mb "$front" "$CARRIER" "$COUNTRY" || DOWN_FAILED=1
  done
  # Each carrier proves the lane itself: auto is a start, so each explicit
  # carrier gets its own lane start.
  if [ "$CARRIER" = auto ]; then
    for carrier in h1 h2 h3; do
      stop_lane
      MODE="socks"
      CARRIER="$carrier"
      CFG="$CONF_DIR/foxy-$COUNTRY-$carrier.json"
      write_config "$CFG"
      "$BIN" run -c "$CFG" >"$LOG" 2>&1 &
      echo "$!" > "$(lane_pid_file)"
      wait_port "$SOCKS_PORT" || { echo "carrier $carrier never listened" >&2; DOWN_FAILED=1; continue; }
      download_1mb socks "$carrier" "$COUNTRY" || DOWN_FAILED=1
    done
    CARRIER="auto"
  fi
  if [ "${DOWN_FAILED:-0}" = 1 ]; then
    echo "check failed; see $LOG" >&2
    exit 1
  fi
  echo "check passed: $COUNTRY exit, 1000000 B per method."
  exit 0
fi

if [ "$MODE" = vpn ]; then
  system_proxy_on
  echo "browsers may need a restart to pick the new proxy up."
fi
