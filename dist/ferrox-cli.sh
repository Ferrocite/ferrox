#!/bin/bash
# ferrox-cli: one front-facing command for every lane this binary dials.
#
#   ferrox-cli login                           save the foxy account once (0600)
#   ferrox-cli up --foxy --vpn                 the Foxy lane, whole-device proxy
#   ferrox-cli up --vless 'vless://...'        any vless share link
#   ferrox-cli up --config mine.json           any config the binary serves
#   ferrox-cli down | status | ports | tun
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
# the only way `up` runs the binary `cargo build --release` just built.
BIN="${FERROX_BIN:-}"
if [ -z "$BIN" ]; then
  for _cand in "$SCRIPT_DIR/ferrox-app" "$SCRIPT_DIR/ferrox-app.exe"; do
    [ -x "$_cand" ] && { BIN="$_cand"; break; }
  done
fi
if [ -z "$BIN" ]; then
  CARGO_TARGET="$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps 2>/dev/null | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -1)"
  BIN="${CARGO_TARGET:-$ROOT/target}/release/ferrox-app"
fi
CONF_DIR="${FERROX_CONF_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/ferrox}"
CREDS="${FOXY_CREDENTIALS:-$CONF_DIR/credentials}"
CFG="$CONF_DIR/lane.json"
PID_FILE="$CONF_DIR/lane.pid"
LOG="$CONF_DIR/lane.log"
PROXY_PORTS="$CONF_DIR/system-proxy.ports"

ACTION="up"
OUTBOUND=""
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
CITY=""
CARRIER="auto"
UPSTREAM=""
FRONTS="socks,http,mixed"
SOCKS_PORT="${FOXY_SOCKS_PORT:-10808}"
HTTP_PORT="${FOXY_HTTP_PORT:-8080}"
MIXED_PORT="${FOXY_MIXED_PORT:-10809}"
WANT_VPN=0
DEBUG=0

die() { echo "ferrox-cli: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
rule() { printf '%s\n' "----------------------------------------------------------------"; }

usage() {
  cat <<EOF
usage: ferrox-cli <command> [options]

commands
  login      save the foxy account once (prompts for the password; file is 0600)
  up         start the lane in the background, print the port map (default)
  serve      start the lane in this terminal, until Ctrl-C
  down       stop the lane and clear the system proxy it set
  status     show the lane, then the exit IP through the SOCKS front
  ports      print the port map and the macOS settings to type
  tun        what TUN mode would need, and why this binary refuses it

three commands from a fresh package (the foxy lane needs no server: the edge
comes from Mozilla's catalogue, and --country moves the exit; with no account
stored yet, the first up --foxy simply asks for the email and password):
  ferrox-cli up --foxy --vpn                    # asks once, then connects
  ferrox-cli status                             # exit IP and country
  ferrox-cli down                               # stop, clear the system proxy

outbound (choose one)
  --foxy                 Foxy lane; account from \$FOXY_CREDENTIALS
  --vless LINK           a vless:// share link (tcp, ws, grpc, httpupgrade, xhttp)
  --vmess HOST:PORT --uuid ID
  --trojan HOST:PORT --password PW
  --ss HOST:PORT --method METHOD --password PW
  --config FILE          any JSON config this binary serves, used verbatim

foxy options (email + password is the whole setup; there is no server to name)
  --email ADDR           Firefox account, else \$FOXY_EMAIL, else the credentials file
  --password PW          password, else \$FOXY_PASS (a file with 0600 is better)
  --code CODE            two-factor code
  --country CC           exit country, default US
  --city CODE            city tier inside the country
  --carrier NAME         auto|h1|h2|h3, default auto (h3 first)
  --upstream URL         http:// or socks5(h):// hop to reach the edge through

fronts
  --fronts LIST          socks,http,mixed (default all three)
  --socks PORT           default $SOCKS_PORT
  --http PORT            default $HTTP_PORT
  --mixed PORT           default $MIXED_PORT
  --vpn                  also point the macOS system proxy at the fronts
  --debug                keep the lane's dial trace in the log (FOXY_DEBUG=1)
  --tun                  refused: this binary has no utun device
  -h, --help             this text

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
  if [ "${LOGIN_QUIET:-0}" != 1 ]; then
    say "account saved to $CREDS: owner-only, outside the repository, read by every future up."
    say "next:  ferrox-cli up --foxy --vpn"
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

foxy_outbound() {
  python3 - "$EMAIL" "$PASSWORD" "$CODE" "$COUNTRY" "$CITY" "$CARRIER" "$UPSTREAM" <<'PY'
import json, sys

email, password, code, country, city, carrier, upstream = sys.argv[1:8]
# The account, not a minted pass: the pass the edge accepts lives 600 seconds,
# so a lane handed a bare token cannot renew it and dies when it expires.
settings = {"email": email, "password": password, "country": country.upper(), "carrier": carrier}
if city:
    settings["city"] = city.upper()
if upstream:
    settings["upstreamProxy"] = upstream
if code:
    settings["code"] = code
print(json.dumps({"protocol": "foxy", "settings": settings}))
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
print(json.dumps({
    "protocol": "shadowsocks",
    "settings": {"servers": [{"address": host, "port": int(port),
                              "method": method, "password": password}]},
}))
PY
}

# ------------------------------------------------------------------- system proxy

system_proxy_on() {
  command -v networksetup >/dev/null 2>&1 || { say "no networksetup: point your apps at the ports by hand."; return 0; }
  local any=0 svc want_socks=0 want_http=0 front
  for front in ${FRONTS//,/ }; do
    case "$front" in socks) want_socks=1 ;; http|mixed) want_http=1 ;; esac
  done
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    case "$svc" in *\**) continue ;; esac
    if [ "$want_socks" = 1 ]; then
      networksetup -setsocksfirewallproxy "$svc" 127.0.0.1 "$SOCKS_PORT" 2>/dev/null || continue
      networksetup -setsocksfirewallproxystate "$svc" on 2>/dev/null || true
    fi
    if [ "$want_http" = 1 ]; then
      networksetup -setwebproxy "$svc" 127.0.0.1 "$HTTP_PORT" 2>/dev/null || true
      networksetup -setwebproxystate "$svc" on 2>/dev/null || true
      networksetup -setsecurewebproxy "$svc" 127.0.0.1 "$HTTP_PORT" 2>/dev/null || true
      networksetup -setsecurewebproxystate "$svc" on 2>/dev/null || true
    fi
    any=1
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  [ "$any" = 1 ] || die "no network service took the proxy"
  printf '%s %s\n' "$SOCKS_PORT" "$HTTP_PORT" > "$PROXY_PORTS"
  [ "$want_socks" = 1 ] && say "system proxy on: SOCKS 127.0.0.1:$SOCKS_PORT"
  [ "$want_http" = 1 ] && say "system proxy on: HTTP and HTTPS 127.0.0.1:$HTTP_PORT"
  say "scope: apps that honour the system proxy. There is no utun device, so"
  say "apps that ignore it (and UDP) are not captured: ferrox-cli tun says why."
}

system_proxy_off() {
  [ -f "$PROXY_PORTS" ] || return 0
  command -v networksetup >/dev/null 2>&1 || return 0
  local svc
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    case "$svc" in *\**) continue ;; esac
    networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
    networksetup -setwebproxystate "$svc" off 2>/dev/null || true
    networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  rm -f "$PROXY_PORTS"
  say "system proxy cleared."
}

# ---------------------------------------------------------------------- lane

lane_running() {
  [ -f "$PID_FILE" ] || return 1
  local pid; pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

lane_pid() { cat "$PID_FILE" 2>/dev/null || true; }

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

build_config() {
  local outbound
  case "$OUTBOUND" in
    foxy)
      read_credentials
      # No stored account and a terminal to type in: ask right here, so the one
      # command the user typed is the one command that gets connected.
      if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
        [ -t 0 ] || die "no account: run 'ferrox-cli login' first, or pass --email and --password"
        say "Foxy needs a Firefox account — an email and a password, no server to name."
        LOGIN_QUIET=1 action_login
        say "account saved to $CREDS (owner-only); connecting."
        read_credentials
      fi
      outbound="$(foxy_outbound)" || die "cannot build the foxy outbound"
      ;;
    vless) outbound="$(vless_outbound)" || die "cannot read the vless link" ;;
    vmess) outbound="$(vmess_outbound)" || die "cannot build the vmess outbound" ;;
    trojan) outbound="$(trojan_outbound)" || die "cannot build the trojan outbound" ;;
    ss) outbound="$(ss_outbound)" || die "cannot build the shadowsocks outbound" ;;
    config)
      [ -f "$CONFIG_FILE" ] || die "no such config: $CONFIG_FILE"
      CFG="$CONFIG_FILE"
      return 0
      ;;
    *) die "choose an outbound: --foxy, --vless, --vmess, --trojan, --ss or --config" ;;
  esac
  write_config "$outbound" || die "cannot write $CFG"
}

start_lane() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null || true
  if lane_running; then
    say "a lane is already running (pid $(lane_pid)); stopping it first."
    stop_lane 0
  fi
  build_config
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

# -------------------------------------------------------------------- actions

# One trace through the first front: a lane that listens but cannot dial is not
# connected, and saying so here is cheaper than a browser that times out.
probe_front() {
  local front="$1" port="$2"
  if [ "$front" = socks ]; then
    curl -s --noproxy '' --max-time 20 --socks5-hostname "127.0.0.1:$port" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null
  else
    curl -s --noproxy '' --max-time 20 -x "http://127.0.0.1:$port" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null
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
  if grep -q "handshake with the edge failed" "$LOG"; then
    say "diagnosis: TLS to the edge never completed. That is the network, not"
    say "the account: chain the dial through a proxy this network does allow:"
    say "  ferrox-cli up --foxy --upstream socks5://127.0.0.1:PORT"
    if grep -q "the edge closed the stream" "$LOG"; then
      say "the QUIC carrier got a handshake and the edge closed the stream, so"
      say "UDP reaches the edge while TCP is dropped: force --carrier h3 to see"
      say "whether the pass itself is refused, or keep --upstream for TCP."
    fi
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
    say "NOT CONNECTED: the fronts are up, but no flow got through them."
    diagnose
    return 1
  fi
  say "exit through $front: $(printf '%s\n' "$answer" | grep -E '^(ip|loc)=' | tr '\n' ' ')"
  # Any answer at all is not proof: this machine's own exit answers the same trace.
  want="$(printf '%s' "$COUNTRY" | tr '[:lower:]' '[:upper:]')"
  got="$(printf '%s\n' "$answer" | sed -n 's/^loc=//p' | tr '[:lower:]' '[:upper:]')"
  if [ "$OUTBOUND" = foxy ] && [ "$got" != "$want" ]; then
    say "the exit reads ${got:-unreadable}, not the pinned $want: that is either another"
    say "country's edge or this machine's own address, so the lane is not carrying it."
    diagnose
    return 1
  fi
  return 0
}

action_up() {
  start_lane
  if [ "$OUTBOUND" != config ] && ! wait_fronts; then
    say "the lane did not open its fronts; last lines of $LOG:"
    tail -n 20 "$LOG" 2>/dev/null || true
    stop_lane 0
    exit 1
  fi
  say "lane up (pid $(lane_pid)), fronts:"
  if [ "$OUTBOUND" = config ]; then
    say "  the ones $CONFIG_FILE names (served verbatim)"
  else
    port_map
  fi
  local ok=0
  if [ "$OUTBOUND" != config ]; then verify_flow || ok=1; fi
  # Route the machine only at a lane that proved it carries a flow: an armed
  # system proxy over a dead lane takes the network down with it.
  if [ "$ok" = 0 ] && [ "$WANT_VPN" = 1 ]; then system_proxy_on; fi
  say "log:  $LOG"
  say "stop: ferrox-cli down"
  if [ "$ok" = 1 ]; then
    if [ "$WANT_VPN" = 1 ]; then
      say "the system proxy was left as it was: nothing is routed through a lane"
      say "that carries no flow."
    fi
    say "the lane stays up so it can be inspected; nothing is routed until it"
    say "carries a flow."
    exit 3
  fi
}

action_serve() {
  start_lane
  if [ "$OUTBOUND" != config ] && ! wait_fronts; then
    say "the lane did not open its fronts; last lines of $LOG:"
    tail -n 20 "$LOG" 2>/dev/null || true
    exit 1
  fi
  say "lane up, fronts:"
  if [ "$OUTBOUND" = config ]; then
    say "  the ones $CONFIG_FILE names (served verbatim)"
  else
    port_map
  fi
  local ok=0
  if [ "$OUTBOUND" != config ]; then verify_flow || ok=1; fi
  if [ "$ok" = 0 ] && [ "$WANT_VPN" = 1 ]; then system_proxy_on; fi
  say "Ctrl-C stops it."
  trap 'stop_lane 1; exit 0' INT TERM
  local pid; pid="$(lane_pid)"
  while [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; do sleep 2; done
  say "the lane exited; last lines of $LOG:"
  tail -n 15 "$LOG" 2>/dev/null || true
  stop_lane 0
}

action_status() {
  if ! lane_running; then
    say "lane not running."
    return 1
  fi
  say "lane pid $(lane_pid), fronts:"
  port_map
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
    up|serve|down|status|ports|tun|login) ACTION="$1"; shift ;;
    --foxy) OUTBOUND=foxy; shift ;;
    --vless) OUTBOUND=vless; VLESS="${2:-}"; shift 2 ;;
    --vmess) OUTBOUND=vmess; VMESS="${2:-}"; shift 2 ;;
    --uuid) VMESS_ID="${2:-}"; shift 2 ;;
    --network) VMESS_NETWORK="${2:-}"; shift 2 ;;
    --trojan) OUTBOUND=trojan; TROJAN="${2:-}"; shift 2 ;;
    --ss) OUTBOUND=ss; SS="${2:-}"; shift 2 ;;
    --method) SS_METHOD="${2:-}"; shift 2 ;;
    --config) OUTBOUND=config; CONFIG_FILE="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --password) PASSWORD="${2:-}"; shift 2 ;;
    --code) CODE="${2:-}"; shift 2 ;;
    --country) COUNTRY="${2:-}"; shift 2 ;;
    --city) CITY="${2:-}"; shift 2 ;;
    --carrier) CARRIER="${2:-}"; shift 2 ;;
    --upstream) UPSTREAM="${2:-}"; shift 2 ;;
    --fronts) FRONTS="${2:-}"; shift 2 ;;
    --socks) SOCKS_PORT="${2:-}"; shift 2 ;;
    --http) HTTP_PORT="${2:-}"; shift 2 ;;
    --mixed) MIXED_PORT="${2:-}"; shift 2 ;;
    --vpn) WANT_VPN=1; shift ;;
    --debug) DEBUG=1; shift ;;
    --tun) ACTION=tun; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

# up and serve are the only actions that need the binary: down, status and
# login must still work when it was never fetched.
require_bin() {
  [ -x "$BIN" ] || die "no binary at $BIN: unpack a release package beside this script (https://github.com/FerroxCo/ferrox/releases), or build one: cargo build --release -p ferrox-app"
}

case "$ACTION" in
  up) require_bin; action_up ;;
  serve) require_bin; action_serve ;;
  login) action_login ;;
  down) stop_lane 1; rm -f "$CFG"; say "lane stopped; the lane config (which carries the account) is removed." ;;
  status) action_status ;;
  ports) action_ports ;;
  tun) action_tun ;;
esac
