#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "::error::live speedtest samples /proc, so it runs on Linux runners only" >&2
  exit 2
fi
for tool in curl python3 sha256sum md5sum; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "::error::live speedtest needs $tool on PATH" >&2
    exit 2
  }
done

configs_file=""
target_url=""
target_sha256=""
target_md5=""
repeats=2
cores_list=""
out="target/live-speedtest"
bench_bin="target/release/ferrox-bench"
curl_max_time=1500
stall_time=60
stall_bytes=10240
socks_base=11801
while [[ $# -gt 0 ]]; do
  case "$1" in
    --configs-file) configs_file="$2"; shift 2 ;;
    --target-url) target_url="$2"; shift 2 ;;
    --target-sha256) target_sha256="$2"; shift 2 ;;
    --target-md5) target_md5="$2"; shift 2 ;;
    --repeats) repeats="$2"; shift 2 ;;
    --cores) cores_list="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --bench-bin) bench_bin="$2"; shift 2 ;;
    --curl-max-time) curl_max_time="$2"; shift 2 ;;
    --stall-time) stall_time="$2"; shift 2 ;;
    --stall-bytes) stall_bytes="$2"; shift 2 ;;
    --socks-base) socks_base="$2"; shift 2 ;;
    *) echo "::error::unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$configs_file" && -f "$configs_file" ]] || {
  echo "::error::--configs-file needs a file with one vless:// per line" >&2
  exit 2
}
[[ -n "$target_url" ]] || {
  echo "::error::--target-url names the static file every core downloads" >&2
  exit 2
}
if [[ -n "$target_sha256" && -n "$target_md5" ]]; then
  echo "::error::pass --target-sha256 or --target-md5, not both" >&2
  exit 2
fi

pins_file="upstream/pins.toml"
engine_dir="target/live-engines"
source "$(dirname "$0")/lib-engines.sh"

ALL_CORES="ferrox xray-core zeronet sing-box xray-rust"

main() {
  mkdir -p "$out" "$engine_dir" "$out/configs" "$out/dl" "$out/attempts"
  [[ -f "$pins_file" ]] || fail "$pins_file is missing; refusing to guess a comparator"

  mapfile -t links < <(grep -v '^[[:space:]]*\(#\|$\)' "$configs_file" || true)
  ((${#links[@]} > 0)) || fail "no configs in $configs_file"
  echo "note: ${#links[@]} config(s) to try" >&2

  if [[ -z "$cores_list" ]]; then
    cores_list="$ALL_CORES"
  fi
  wanted=(${cores_list//,/ })

  note "building the harness driver"
  cargo build --locked --release -p ferrox-bench -p ferrox-app 2>&1 | tail -2 >&2
  bench_bin="$(built "$bench_bin")" || fail \
    "no executable at $bench_bin(.exe) after the build above"
  ferrox_bin="$(built target/release/ferrox-app)" || fail \
    "no executable at target/release/ferrox-app(.exe) after the build above"

  declare -A bin_of=()
  declare -A skip_reason=()
  for core in ${wanted[@]+"${wanted[@]}"}; do
    if [[ "$core" == "ferrox" ]]; then
      bin_of[$core]="$ferrox_bin"
      continue
    fi
    if path="$(build "$core" 2>/dev/null)"; then
      bin_of[$core]="$path"
    else
      skip_reason[$core]="could not be built from its pin on this host"
    fi
  done

  {
    echo "date: $(date -u +%FT%TZ)"
    echo "host: $(uname -a)"
    echo "target: $target_url"
    echo "target_sha256: ${target_sha256:-unverified}"
    echo "target_md5: ${target_md5:-unverified}"
    echo "repeats: $repeats"
    echo "cores: ${wanted[*]}"
    for core in ${wanted[@]+"${wanted[@]}"}; do
      if [[ -n "${bin_of[$core]:-}" ]]; then
        echo "engine $core: ${bin_of[$core]} sha256=$(sha256_of "${bin_of[$core]}")"
      else
        echo "engine $core: SKIPPED (${skip_reason[$core]:-unknown})"
      fi
    done
    for pin in xray-core sing-box zeronet xray-rust; do
      echo "pin $pin: $(pin_of "$pin")"
    done
  } >"$out/manifest.txt"

  : >"$out/records.jsonl"
  : >"$out/tokens.txt"
  chmod 600 "$out/tokens.txt"
  port="$socks_base"
  index=0
  for link in ${links[@]+"${links[@]}"}; do
    index=$((index + 1))
    "$bench_bin" linkconfig --tokens --link "$link" >>"$out/tokens.txt" 2>/dev/null \
      || fail "config #$index: unreadable link (not logged; check the paste)"
    label="$("$bench_bin" linkconfig --describe --index "$index" --link "$link" 2>/dev/null)" \
      || fail "config #$index: unreadable link (not logged; check the paste)"
    for core in ${wanted[@]+"${wanted[@]}"}; do
      if [[ -z "${bin_of[$core]:-}" ]]; then
        record "$index" "$label" "$core" 0 "skipped" \
          "${skip_reason[$core]:-unknown}" "" "" "" "" "" "" ""
        continue
      fi
      cfg="$out/configs/cfg${index}-${core}.json"
      if ! "$bench_bin" linkconfig --link "$link" --engine "$core" \
        --socks-port "$port" >"$cfg" 2>"$out/attempts/cfg${index}-${core}.gen.log"; then
        reason="$(head -c 300 "$out/attempts/cfg${index}-${core}.gen.log")"
        record "$index" "$label" "$core" 0 "skipped" "no $core config: $reason" \
          "" "" "" "" "" "" ""
        continue
      fi
      for ((r = 1; r <= repeats; r++)); do
        attempt "$index" "$label" "$core" "$r" "$cfg" "$port" "$link" || true
        port=$((port + 1))
      done
    done
  done
  local measured
  measured="$(wc -l <"$out/records.jsonl" | tr -d ' ')"
  {
    echo "configs: $index"
    echo "attempts: $measured"
  } | tee "$out/summary.txt" >&2
  [[ "$measured" != "0" ]]
}

sha256_of() {
  sha256sum "$1" | cut -d' ' -f1
}

digest_of() {
  case "$2" in
    MD5) md5sum "$1" | cut -d' ' -f1 ;;
    *) sha256sum "$1" | cut -d' ' -f1 ;;
  esac
}

record() {
  python3 scripts/record-live-attempt.py "$@" >>"$out/records.jsonl"
}

jiffies() {
  awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

peak_rss_kib() {
  awk '/VmHWM/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0
}

attempt() {
  local index="$1" label="$2" core="$3" repeat="$4" cfg="$5" port="$6"
  local adir="$out/attempts/cfg${index}-${core}-r${repeat}"
  mkdir -p "$adir"
  local bin="${bin_of[$core]}"
  local shape
  shape="$(config_arg_for "$core")"

  local -a cargs=("run")
  case "$shape" in
    long) cargs+=(-config "$cfg") ;;
    short) cargs+=(-c "$cfg") ;;
    positional) cargs+=("$cfg") ;;
  esac
  "$bin" "${cargs[@]}" >"$adir/stdout.log" 2>"$adir/stderr.log" &
  local pid=$!
  local waited=0
  while ! (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; do
    sleep 0.2
    waited=$((waited + 1))
    if ! kill -0 "$pid" 2>/dev/null; then
      record "$index" "$label" "$core" "$repeat" "error" "engine exited during startup" \
        "" "" "" "" "" "" ""
      wait "$pid" 2>/dev/null || true
      return 1
    fi
    if ((waited > 100)); then
      record "$index" "$label" "$core" "$repeat" "error" "SOCKS never listened" \
        "" "" "" "" "" "" ""
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 1
    fi
  done

  local cpu_start cpu_end rss_kib
  cpu_start="$(jiffies "$pid")"
  local file="$out/dl/cfg${index}-${core}-r${repeat}.bin"
  local curl_json="$adir/curl.json"
  local curl_code=0
  curl -sS --socks5-hostname "127.0.0.1:$port" \
    --max-time "$curl_max_time" --speed-time "$stall_time" --speed-limit "$stall_bytes" \
    --retry 0 --fail \
    -o "$file" \
    -w '{"http_code":%{http_code},"size":%{size_download},"total":%{time_total},"starttransfer":%{time_starttransfer}}\n' \
    "$target_url" >"$curl_json" 2>"$adir/curl.err" || curl_code=$?
  cpu_end="$(jiffies "$pid")"
  rss_kib="$(peak_rss_kib "$pid")"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  if ((curl_code != 0)); then
    local why
    why="$(head -c 300 "$adir/curl.err")"
    record "$index" "$label" "$core" "$repeat" "error" "curl exit $curl_code: $why" \
      "" "" "" "" "" "" ""
    return 1
  fi
  local size total starttransfer
  size="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["size"]))' "$curl_json")"
  total="$(python3 -c 'import json,sys; print(float(json.load(open(sys.argv[1]))["total"]))' "$curl_json")"
  starttransfer="$(python3 -c 'import json,sys; print(float(json.load(open(sys.argv[1]))["starttransfer"]))' "$curl_json")"
  local window
  window="$(python3 -c 'print(max(float(sys.argv[1]) - float(sys.argv[2]), 0.001))' "$total" "$starttransfer")"
  local mib_per_s
  mib_per_s="$(python3 -c 'print(float(sys.argv[1]) / 1048576.0 / float(sys.argv[2]))' "$size" "$window")"
  local cpu_ms gib
  cpu_ms="$(((cpu_end - cpu_start) * 10))"
  gib="$(python3 -c 'print(float(sys.argv[1]) / 1073741824.0)' "$size")"
  local cpu_per_gib
  cpu_per_gib="$(python3 -c 'print(float(sys.argv[1]) / float(sys.argv[2])) if float(sys.argv[2]) > 0 else print(0.0)' "$cpu_ms" "$gib")"
  local rss_mib
  rss_mib="$(python3 -c 'print(float(sys.argv[1]) / 1024.0)' "$rss_kib")"
  local hash="unverified"
  local want_hash="" want_algo=""
  if [[ -n "$target_sha256" ]]; then
    want_hash="$target_sha256"
    want_algo="SHA-256"
  elif [[ -n "$target_md5" ]]; then
    want_hash="$target_md5"
    want_algo="MD5"
  fi
  if [[ -n "$want_hash" ]]; then
    local have
    have="$(digest_of "$file" "$want_algo")"
    if [[ "${have,,}" == "${want_hash,,}" ]]; then
      hash="ok"
    else
      record "$index" "$label" "$core" "$repeat" "error" "$want_algo mismatch" \
        "$mib_per_s" "$cpu_per_gib" "$rss_mib" "$starttransfer" "$size" \
        "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_code"])' "$curl_json")" "mismatch"
      return 1
    fi
  fi
  record "$index" "$label" "$core" "$repeat" "ok" "" \
    "$mib_per_s" "$cpu_per_gib" "$rss_mib" "$starttransfer" "$size" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_code"])' "$curl_json")" "$hash"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit "$?"
fi
