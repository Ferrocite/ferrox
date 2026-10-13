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
    engines_list="ferrox,xray-core,zeronet,sing-box,xray-rust"
  fi
fi
if [[ -z "$repeats" ]]; then
  if [[ "$tier" == "full" ]]; then repeats=5; else repeats=3; fi
fi

note "building the harness driver"
if ((no_build)); then
  note "skipping the build: binaries are handed over, not rebuilt"
else
  cargo build --locked --release -p ferrox-bench -p ferrox-app 2>&1 | tail -2 >&2
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
for want in xray-core ferrox zeronet sing-box xray-rust; do
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
  if [[ "$label" == "sing-box" ]]; then
    engine_args+=(--dialect "$label=sing-box")
  fi
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
    for pin in xray-core sing-box zeronet xray-rust; do
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

while read -r id traffic connections iterations payload; do
  [[ -n "$id" ]] || continue
  if ! scenario_kept "$id"; then
    echo "# $id: skipped by --only/--exclude" >>"$out/commands.sh"
    continue
  fi
  note "cell $id ($traffic $connections flows)"
  srvport="$(matrix_srvport)" || {
    cells_failed+=("$id (could not allocate a server port)")
    status=1
    continue
  }
  config="$(scenario_config "$id" "$srvport")" || {
    cells_failed+=("$id (unknown scenario)")
    status=1
    continue
  }
  celldir="$out/cells/$id"
  rm -rf "$celldir"
  mkdir -p "$celldir"
  echo "$config" >"$celldir/engine-config.json"
  if ((probe_only)); then
    cells_run=$((cells_run + 1))
    {
      echo "# $id: $traffic $connections flows, $iterations x $payload B, $repeats repeats (probe only)"
      echo "# config: cells/$id/engine-config.json"
    } >>"$out/commands.sh"
    continue
  fi
  if "$bench_bin" "${engine_args[@]}" \
    --traffic "$traffic" --connections "$connections" \
    --iterations "$iterations" --payload-size "$payload" \
    --repeats "$repeats" \
    --outbound-config "$config" \
    --output-dir "$celldir/runs" \
    --scenario "$id" \
    --json-report "$celldir/cell.json" >>"$celldir/stdout.log" 2>&1; then
    cells_run=$((cells_run + 1))
  else
    cells_failed+=("$id (exit $?)")
    status=1
  fi
  {
    echo "# $id: $traffic $connections flows, $iterations x $payload B, $repeats repeats"
    echo "# server port: $srvport (allocated per cell; see lib-matrix.sh)"
    echo "# config: cells/$id/engine-config.json ; report: cells/$id/cell.json"
  } >>"$out/commands.sh"
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
