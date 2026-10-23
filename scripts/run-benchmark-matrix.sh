#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tier="standard"
out="target/benchmark-matrix"
engines_list=""
repeats=""
bench_bin="target/release/ferrox-bench"
only=()
exclude=()
probe_only=0
no_build=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tier="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --engines) engines_list="$2"; shift 2 ;;
    --repeats) repeats="$2"; shift 2 ;;
    --bench-bin) bench_bin="$2"; shift 2 ;;
    --only) only+=("$2"); shift 2 ;;
    --exclude) exclude+=("$2"); shift 2 ;;
    --probe-only) probe_only=1; shift ;;
    --no-build) no_build=1; shift ;;
    *) echo "::error::unknown argument $1" >&2; exit 2 ;;
  esac
done
case "$tier" in
  smoke | standard | full) ;;
  *) echo "::error::--tier needs smoke, standard or full, got $tier" >&2; exit 2 ;;
esac

pins_file="upstream/pins.toml"
engine_dir="target/parity-engines"
source "$(dirname "$0")/lib-engines.sh"
source "$(dirname "$0")/lib-matrix.sh"

main() {
mkdir -p "$out" "$engine_dir" "$out/cells"
[[ -f "$pins_file" ]] || fail "$pins_file is missing; refusing to guess a comparator"


if [[ -z "$engines_list" ]]; then
  if [[ "$tier" == "smoke" ]]; then
    engines_list="ferrox,xray-core"
  else
    engines_list="ferrox,xray-core,zeronet,sing-box,xray-rust,leaf"
  fi
fi
if [[ -z "$repeats" ]]; then
  if [[ "$tier" == "full" ]]; then repeats=5; else repeats=3; fi
fi

note "building the harness driver"
if ((no_build)); then
  note "skipping the build: binaries are handed over, not rebuilt"
else
  build_log="$(mktemp)"
  if ! cargo build --locked --release -p ferrox-bench -p ferrox-app >"$build_log" 2>&1; then
    tail -80 "$build_log" >&2
    rm -f "$build_log"
    fail "the harness driver did not build"
  fi
  rm -f "$build_log"
fi
bench_bin="$(built "$bench_bin")" || fail \
  "no executable at $bench_bin(.exe) after the build above"
ferrox_bin="$(built target/release/ferrox-app)" || fail \
  "no executable at target/release/ferrox-app(.exe) after the build above"

engine_list="${engines_list//,/ }"
built=()
skipped=()
for entry in $engine_list; do
  label="${entry%%=*}"
  source="${entry#*=}"
  [[ "$label" != "$entry" ]] || label="$source"
  if [[ "$label" == "ferrox" ]]; then
    path="$ferrox_bin"
  elif [[ "$source" == /* ]]; then
    path="$source"
  else
    build_log="$(mktemp)"
    if path="$(build "$source" 2>"$build_log")"; then
      rm -f "$build_log"
    else
      echo "::warning::could not build $label from its pin on this host; log:" >&2
      cat "$build_log" >&2 || true
      rm -f "$build_log"
      skipped+=("$label (could not be built from its pin on this host)")
      continue
    fi
  fi
  [[ -x "$path" ]] || {
    echo "::warning::$label built at $path but it is not executable; ls:" >&2
    ls -la "$path" "$(dirname "$path")" >&2 || true
    skipped+=("$label ($path is not executable)")
    continue
  }
  built+=("$label=$path")
done
{
  echo "engines built: ${built[*]:-<none>}" >&2
  echo "engines skipped: ${skipped[*]:-<none>}" >&2
} || true
ordered=()
for want in xray-core ferrox zeronet sing-box xray-rust leaf; do
  for have in ${built[@]+"${built[@]}"}; do
    [[ "${have%%=*}" == "$want" ]] && ordered+=("$have")
  done
done
for have in ${built[@]+"${built[@]}"}; do
  seen=0
  for want in ${ordered[@]+"${ordered[@]}"}; do [[ "$want" == "$have" ]] && seen=1; done
  [[ "$seen" == "0" ]] && ordered+=("$have")
done
engines=(${ordered[@]+"${ordered[@]}"})
engine_args=()
for have in "${engines[@]}"; do
  label="${have%%=*}"
  engine_args+=(--engine "$have")
  shape="$(config_arg_for "$label")"
  [[ "$shape" == "long" ]] || engine_args+=(--config-arg "$label=$shape")
  dialect="$(dialect_for "$label")"
  [[ "$dialect" == "xray" ]] || engine_args+=(--dialect "$label=$dialect")
done
[[ "${engines[0]%%=*}" == "xray-core" ]] || fail "no xray-core reference: a comparison without one is not a comparison"
ferrox_present=0
for have in "${engines[@]}"; do [[ "${have%%=*}" == "ferrox" ]] && ferrox_present=1; done
[[ "$ferrox_present" == "1" ]] || fail "no ferrox engine: the matrix gates nothing without it"


manifest() {
  {
    echo "tier: $tier"
    echo "date: $(date -u +%F)"
    echo "runner: $(runner_slug)"
    echo "host: $(uname -a)"
    echo "cpu: $(cpu_model)"
    echo "memory: $(memory_total)"
    echo "load: $(load_average)"
    echo "rustc: $(rustc -vV | tr '\n' ' ')"
    echo "go: $(go version 2>/dev/null || echo 'no go toolchain')"
    echo "repeats: $repeats"
    ((${#only[@]})) && echo "only: ${only[*]}"
    ((${#exclude[@]})) && echo "exclude: ${exclude[*]}"
    ((probe_only)) && echo "probe-only: true"
    for have in "${engines[@]}"; do
      label="${have%%=*}"
      echo "engine $label: ${have#*=} sha256=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "${have#*=}") mib=$(python3 -c 'import os,sys;print(f"{os.path.getsize(sys.argv[1]) / 1048576:.1f}")' "${have#*=}")"
    done
    for pin in xray-core sing-box zeronet xray-rust leaf; do
      echo "pin $pin: $(pin_of "$pin")"
    done
  } >"$out/manifest.txt"
}

runner_slug() {
  local sys machine
  sys="$(uname -s)"
  machine="$(uname -m)"
  case "$sys" in
    Linux) sys="linux" ;;
    Darwin) sys="macos" ;;
    *) sys="unknown" ;;
  esac
  case "$machine" in
    x86_64 | amd64) machine="x86_64" ;;
    arm64 | aarch64) machine="aarch64" ;;
  esac
  echo "$sys-$machine"
}

cpu_model() {
  if [[ -f /proc/cpuinfo ]]; then
    grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | xargs || echo "unknown"
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

memory_total() {
  if [[ -f /proc/meminfo ]]; then
    grep -m1 MemTotal /proc/meminfo | awk '{print $2 " " $3}'
  elif command -v sysctl >/dev/null 2>&1; then
    echo "$((($(sysctl -n hw.memsize 2>/dev/null || echo 0) + 512) / 1048576)) MiB"
  else
    echo "unknown"
  fi
}

load_average() {
  if [[ -f /proc/loadavg ]]; then
    cut -d' ' -f1-3 /proc/loadavg
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n vm.loadavg 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

status=0
cells_run=0
cells_failed=()

manifest
{
  echo "# Replay: tier $tier on $(date -u +%FT%TZ)"
  echo "# engines: ${engines[*]}"
  ((${#only[@]})) && echo "# only: ${only[*]}"
  ((${#exclude[@]})) && echo "# exclude: ${exclude[*]}"
  ((probe_only)) && echo "# probe-only: configs written, no traffic moved"
} >"$out/commands.sh"

scenario_kept() {
  local id="$1" pattern
  for pattern in ${only[@]+"${only[@]}"}; do
    [[ "$id" == *"$pattern"* ]] || return 1
  done
  for pattern in ${exclude[@]+"${exclude[@]}"}; do
    [[ "$id" == *"$pattern"* ]] && return 1
  done
  return 0
}

engine_path() {
  local have
  for have in "${engines[@]}"; do
    [[ "${have%%=*}" == "$1" ]] && { printf '%s\n' "${have#*=}"; return 0; }
  done
  return 1
}

# The server side of a cell needs only its inbound and a direct outbound: the proxy outbound is
# the client's, and leaving it first would send the server's own traffic back into itself.
matrix_split_config() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
outbounds = doc.get("outbounds", [])
direct = [o for o in outbounds if o.get("tag") == "direct" or o.get("protocol") in ("freedom", "direct")]
proxy = [o for o in outbounds if o not in direct]
ready = {"tag": "matrix-ready", "protocol": "socks", "listen": "127.0.0.1",
         "port": int(sys.argv[4]), "settings": {"auth": "noauth", "udp": False}}
server = {"inbounds": doc.get("inbounds", []) + [ready],
          "outbounds": direct or [{"tag": "direct", "protocol": "freedom", "settings": {}}]}
json.dump(server, open(sys.argv[2], "w"), indent=2)
json.dump({"outbounds": proxy}, open(sys.argv[3], "w"), indent=2)
PY
}

# xray-rust rejects the CA file and verify certificate the other Xray dialects take; the pin it
# does read is the same one the certificate minted in the ignored target tree produces.
matrix_rust_client_config() {
  python3 - "$1" "$2" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
for outbound in doc.get("outbounds", []):
    stream = outbound.get("streamSettings") or {}
    for key in ("tlsSettings", "realitySettings"):
        section = stream.get(key)
        if isinstance(section, dict):
            section.pop("caCertFile", None)
            section.pop("certificates", None)
            if stream.get("network") == "hysteria":
                section.pop("alpn", None)
json.dump(doc, open(sys.argv[2], "w"), indent=2)
PY
}

matrix_start_server() {
  local label="$1" bin="$2" config="$3" logdir="$4"
  local -a args=()
  case "$(config_arg_for "$label")" in
    long) args=(run -config "$config") ;;
    short) args=(run -c "$config") ;;
    positional) args=(run "$config") ;;
    dash-c) args=(-c "$config") ;;
  esac
  "$bin" "${args[@]}" >>"$logdir/server.log" 2>&1 &
  echo "$!"
}

matrix_wait_tcp() {
  python3 - "$1" "$2" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
deadline = time.time() + 20
while time.time() < deadline:
    try:
        socket.create_connection((host, port), timeout=0.2).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.05)
sys.exit(1)
PY
}

matrix_wait_udp() {
  python3 - "$1" "$2" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
deadline = time.time() + 10
while time.time() < deadline:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((host, port))
    except OSError:
        probe.close()
        sys.exit(0)
    probe.close()
    time.sleep(0.05)
sys.exit(1)
PY
}

server_pid=""
matrix_stop_server() {
  [[ -n "$server_pid" ]] || return 0
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
}
trap 'matrix_stop_server' EXIT INT TERM

servers=()
for want in ferrox xray-core; do
  if engine_path "$want" >/dev/null; then servers+=("$want"); fi
done
((${#servers[@]})) || fail "no server engine: the grid needs ferrox or xray-core"
echo "servers: ${servers[*]}" >>"$out/commands.sh"

while read -r id traffic connections iterations payload; do
  [[ -n "$id" ]] || continue
  if ! scenario_kept "$id"; then
    echo "# $id: skipped by --only/--exclude" >>"$out/commands.sh"
    continue
  fi
  note "cell $id ($traffic $connections flows)"
  if matrix_udp_carrier "$id"; then
    srvport="$(matrix_udp_srvport)"
  else
    srvport="$(matrix_srvport)"
  fi || {
    cells_failed+=("$id (could not allocate a server port)")
    status=1
    continue
  }
  readyport="$(matrix_srvport)" || {
    cells_failed+=("$id (could not allocate a readiness port)")
    status=1
    continue
  }
  config="$(scenario_config "$id" "$srvport")" || {
    cells_failed+=("$id (unknown scenario)")
    status=1
    continue
  }
  for server in "${servers[@]}"; do
    cell="$id--srv-$server"
    celldir="$out/cells/$cell"
    rm -rf "$celldir"
    mkdir -p "$celldir"
    echo "$config" >"$celldir/engine-config.json"
    matrix_split_config "$celldir/engine-config.json" "$celldir/server.json" "$celldir/client.json" "$readyport" || {
      cells_failed+=("$cell (could not split the config)")
      status=1
      continue
    }
    client_args=(--outbound-config "$(cat "$celldir/client.json")")
    if engine_path xray-rust >/dev/null; then
      matrix_rust_client_config "$celldir/client.json" "$celldir/client-xray-rust.json" || {
        cells_failed+=("$cell (could not strip the TLS fixture for xray-rust)")
        status=1
        continue
      }
      client_args+=(--outbound-config-for "xray-rust=$(cat "$celldir/client-xray-rust.json")")
    fi
    if ((probe_only)); then
      cells_run=$((cells_run + 1))
      {
        echo "# $cell: $traffic $connections flows, $iterations x $payload B, $repeats repeats (probe only)"
        echo "# server: cells/$cell/server.json ; client: cells/$cell/client.json"
      } >>"$out/commands.sh"
      continue
    fi
    server_bin="$(engine_path "$server")"
    server_pid="$(matrix_start_server "$server" "$server_bin" "$celldir/server.json" "$celldir")"
    if ! matrix_wait_tcp 127.0.0.1 "$readyport" || ! kill -0 "$server_pid" 2>/dev/null; then
      cells_failed+=("$cell (server $server never listened on $readyport)")
      status=1
      {
        echo "=== $cell: $server did not become ready; server.log (last 40 lines) ==="
        tail -n 40 "$celldir/server.log" 2>/dev/null || true
      } >&2
      matrix_stop_server
      continue
    fi
    if matrix_udp_carrier "$id" && ! matrix_wait_udp 127.0.0.1 "$srvport"; then
      echo "::warning::$cell: $server has not bound udp/$srvport yet; the harness will say if it cannot carry" >&2
    fi
    # `panic = "abort"` turns a panic into a bare `exit 134`; the backtrace names the frame the fault left behind.
    if RUST_BACKTRACE=full "$bench_bin" "${engine_args[@]}" \
      --traffic "$traffic" --connections "$connections" \
      --iterations "$iterations" --payload-size "$payload" \
      --repeats "$repeats" \
      "${client_args[@]}" \
      --output-dir "$celldir/runs" \
      --scenario "$cell" \
      --json-report "$celldir/cell.json" >>"$celldir/stdout.log" 2>&1; then
      cells_run=$((cells_run + 1))
    else
      code=$?
      cells_failed+=("$cell (exit $code)")
      status=1
      # A failed cell's bench output and engine stderr are files the job never reads; echo the panic back into the log.
      {
        echo "=== $cell failed (exit $code): $celldir/stdout.log (last 40 lines) ==="
        tail -n 40 "$celldir/stdout.log" 2>/dev/null || true
        echo "=== $cell: panic frames in engine stderr ==="
        grep -rhE "panicked at|panic:|memory allocation|index out of bounds|attempt to .* zero|stack overflow" \
          "$celldir/runs" 2>/dev/null | sort -u | head -20 || true
      } >&2
    fi
    matrix_stop_server
    {
      echo "# $cell: $traffic $connections flows, $iterations x $payload B, $repeats repeats"
      echo "# server: $server at $celldir/server.json ; client: $celldir/client.json"
      echo "# server port: $srvport, ready port: $readyport (allocated per cell; see lib-matrix.sh)"
      echo "# report: cells/$cell/cell.json"
    } >>"$out/commands.sh"
  done
done < <(scenarios "$tier")

{
  echo "cells run: $cells_run"
  echo "cells failed: ${#cells_failed[@]}"
  for f in "${cells_failed[@]+"${cells_failed[@]}"}"; do echo "failed: $f"; done
  for s in "${skipped[@]+"${skipped[@]}"}"; do echo "skipped engine: $s"; done
} | tee "$out/summary.txt" >&2
return "$status"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit "$?"
fi
