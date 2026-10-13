#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

pins_file="upstream/pins.toml"
engine_dir="target/parity-engines"
out_dir="target/parity"
mkdir -p "$engine_dir" "$out_dir"

rm -rf "${out_dir:?}"/*

note() { echo "note: $*" >&2; }
fail() { echo "::error::$*" >&2; exit 1; }

[[ -f "$pins_file" ]] || fail "$pins_file is missing; refusing to guess a comparator"

pin_of() {
  awk -v want="$1" '
    /^\[sources\./ { in_source = ($0 == "[sources." want "]") }
    in_source && /^rev[[:space:]]*=/ {
      gsub(/^rev[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "")
      print; exit
    }
  ' "$pins_file"
}

verify_checkout() {
  local name="$1" rev
  rev="$(pin_of "$name")"
  [[ -n "$rev" ]] || fail "no rev for $name in $pins_file"
  if [[ ! -d "upstream/$name/.git" ]]; then
    fail "upstream/$name is missing; run scripts/fetch-upstream.sh"
  fi
  local have
  have="$(GIT_CEILING_DIRECTORIES="$PWD" git -C "upstream/$name" rev-parse HEAD 2>/dev/null)" || \
    fail "upstream/$name has no readable HEAD; re-run scripts/fetch-upstream.sh"
  [[ "$have" == "$rev" ]] || fail "upstream/$name is at $have, not the pinned $rev"
}

exe_suffix() {
  case "${OS:-}" in
    Windows_NT) printf '.exe' ;;
    *) printf '' ;;
  esac
}

built() {
  if [[ -x "$1$(exe_suffix)" ]]; then
    printf '%s\n' "$1$(exe_suffix)"
  elif [[ -x "$1" ]]; then
    printf '%s\n' "$1"
  else
    return 1
  fi
}

build() {
  local name="$1" rev binary cached
  rev="$(pin_of "$name")"
  binary="$engine_dir/$name$(exe_suffix)"
  if cached="$(built "$binary")"; then
    echo "$cached"
    return 0
  fi
  if ! (verify_checkout "$name" 2>/dev/null); then
    note "re-fetching $name at its pin; the handoff did not carry it"
    ./scripts/fetch-upstream.sh --only "$name" >&2 || return 1
    verify_checkout "$name" || return 1
  fi
  case "$name" in
    xray-core)
      note "building the pinned Xray-core at $rev"
      (cd "upstream/$name" && GOENV=off GOWORK=off CGO_ENABLED=0 \
        go build -o "$OLDPWD/$binary" ./main) || return 1
      ;;
    sing-box)
      note "building the pinned sing-box at $rev"
      (cd "upstream/$name" && GOENV=off GOWORK=off CGO_ENABLED=0 \
        go build -tags "with_utls" -o "$OLDPWD/$binary" ./cmd/sing-box) || return 1
      ;;
    zeronet)
      note "building the pinned ZeroNet (zray) at $rev"
      (cd "upstream/$name" && cargo build --release -p zray-cli --bin zray) || return 1
      local zray
      zray="$(built "upstream/$name/target/release/zray")" || return 1
      cp "$zray" "$binary" || return 1
      ;;
    xray-rust)
      note "building the pinned xray-rust at $rev (long: aws-lc-rs, quinn, prost)"
      (cd "upstream/$name" && CARGO_TARGET_DIR="$OLDPWD/$engine_dir/xray-rust-target" \
        cargo build --release -p xray-cli --bin xray-rust) || return 1
      local rust_cli
      rust_cli="$(built "$engine_dir/xray-rust-target/release/xray-rust")" || return 1
      cp "$rust_cli" "$binary" || return 1
      ;;
    *)
      fail "unknown engine source `$name`"
      ;;
  esac
  built "$binary"
}

config_arg_for() {
  case "$1" in
    sing-box) echo short ;;
    zeronet) echo positional ;;
    *) echo long ;;
  esac
}

dialect_for() {
  case "$1" in
    sing-box) echo sing-box ;;
    *) echo xray ;;
  esac
}

engines=()
engine_args=()
config_shapes=()
skipped=()

engine_list="${ENGINES:-xray-core,zeronet,sing-box}"
engine_list="${engine_list//,/ }"

for entry in $engine_list; do
  label="${entry%%=*}"
  source="${entry#*=}"
  [[ "$label" != "$entry" ]] || label="$source"

  if [[ "$source" == /* ]]; then
    path="$source"
  else
    build_log="$(mktemp)"
    if path="$(build "$source" 2>"$build_log")"; then
      rm -f "$build_log"
    else
      echo "::warning::could not build $label from its pin on this host; log:" >&2
      cat "$build_log" >&2 || true
      rm -f "$build_log"
      skipped+=("$label (could not be built from its pin on this host; see the log above)")
      continue
    fi
  fi
  [[ -x "$path" ]] || {
    echo "::warning::$label built at $path but it is not executable; ls:" >&2
    ls -la "$path" "$(dirname "$path")" >&2 || true
    skipped+=("$label ($path is not executable)")
    continue
  }

  engines+=("$label=$path")
  engine_args+=(--engine "$label=$path")
  shape="$(config_arg_for "$source")"
  [[ "$shape" == "long" ]] || { engine_args+=(--config-arg "$label=$shape"); config_shapes+=("$shape"); }
  engine_args+=(--dialect "$label=$(dialect_for "$source")")
done

ferrox_path="$(built target/release/ferrox-app)" || fail \
  "no executable at target/release/ferrox-app(.exe); cargo build --locked --release -p ferrox-app"
engines+=("ferrox=$ferrox_path")
engine_args+=(--engine "ferrox=$ferrox_path")
engine_args+=(--dialect "ferrox=xray")

for entry in "${engines[@]}"; do
  path="${entry#*=}"
  built "$path" >/dev/null || fail "$path is not an executable; cargo build --release -p ferrox-app"
done

if [[ -n "${SPLICE_PIPE:-}" ]]; then
  export FERROX_SPLICE_PIPE_BYTES="$SPLICE_PIPE"
  echo "note: relay splice pipe capacity overridden to ${SPLICE_PIPE} B" >&2
fi

RUN_TIMEOUT_CAP=120
FLOOR_MIB_S=500

for var in REPEATS CONNECTIONS TRAFFIC ITERATIONS; do
  if [[ -z "${!var:-}" ]]; then
    unset "$var"
  fi
done
repeats="${REPEATS:-5}"
iterations="${ITERATIONS:-131072}"
payload_size="${PAYLOAD_SIZE:-65536}"
connections="${CONNECTIONS:-1}"
traffic="${TRAFFIC:-download}"

if (( iterations * payload_size > 16 * 1024 * 1024 * 1024 )); then
  fail "gate 5: one flow of $iterations x $payload_size B is \
$(( iterations * payload_size / 1024 / 1024 / 1024 )) GiB, above the 16 GiB ceiling \
one flow is allowed; a transfer that cannot finish inside the harness's \
${RUN_TIMEOUT_CAP}s cap would be reported as a truncated transfer"
fi

per_repeat_bytes=$(( connections * iterations * payload_size ))
if (( per_repeat_bytes / 1024 / 1024 > RUN_TIMEOUT_CAP * FLOOR_MIB_S )); then
  fail "gate 5: $connections flows x $iterations x $payload_size B is \
$(( per_repeat_bytes / 1024 / 1024 / 1024 )) GiB for one repeat of one engine, which \
cannot finish inside the harness's ${RUN_TIMEOUT_CAP}s cap even at ${FLOOR_MIB_S} \
MiB/s. Lower --iterations, or --connections, or both."
fi

engines_n=${#engines[@]}
echo "note: $(( per_repeat_bytes / 1024 / 1024 / 1024 )) GiB per repeat per engine, \
x $engines_n engines x $repeats repeats, plus $repeats ceiling runs" >&2

echo "gate 5: ${#engines[@]} engines x $repeats paired repeats, $traffic, \
$connections x $iterations x $payload_size B \
($(( connections * iterations * payload_size / (1024 * 1024) )) MiB per flow)" >&2
for note_line in "${skipped[@]+"${skipped[@]}"}"; do
  echo "skipped: $note_line" >&2
done

bench_bin="$(built target/release/ferrox-bench)" || fail \
  "no executable at target/release/ferrox-bench(.exe); cargo build --locked --release -p ferrox-bench"

set +e
"$bench_bin" \
  "${engine_args[@]}" \
  --repeats "$repeats" \
  --iterations "$iterations" \
  --payload-size "$payload_size" \
  --connections "$connections" \
  --traffic "$traffic"
exit "$?"
