#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

name_filter="${1:-}"
pins_file="upstream/pins.toml"
status=0
ran=0

libtest_ran_named() {
  local command="$1" log="$2" filters="" word count named=0 sum=0 saw=0
  if [[ "$command" == *" -- "* ]]; then
    filters="${command##* -- }"
  fi
  for word in $filters; do
    [[ "$word" == -* ]] || named=$((named + 1))
  done
  while IFS= read -r count; do
    saw=1
    sum=$((sum + count))
  done < <(sed -n 's/^running \([0-9][0-9]*\) tests\{0,1\}$/\1/p' "$log")
  if ((saw == 0)); then
    echo "note: no libtest test count in the output; its exit code is the only evidence"
    return 0
  fi
  if ((sum == 0)); then
    echo "::error::the suite ran no tests, so a zero exit says nothing about it"
    return 1
  fi
  if ((named > 0 && sum != named)); then
    echo "::error::the suite ran $sum tests and its command names $named; libtest filters by \
substring, so a name that prefixes a sibling runs tests the pin never named"
    return 1
  fi
}

selftest="$(mktemp -d)"
selftest_names="cargo test --test t -- --ignored --exact one two"
printf 'running 2 tests\n' >"$selftest/exact.log"
printf 'running 5 tests\n' >"$selftest/prefix.log"
printf 'running 0 tests\n' >"$selftest/empty.log"
printf 'ok  pkg  0.01s\n' >"$selftest/other.log"
for shape in exact:accept prefix:refuse empty:refuse other:accept; do
  verdict=0
  libtest_ran_named "$selftest_names" "$selftest/${shape%%:*}.log" >/dev/null || verdict=$?
  if [[ "$verdict" -eq 0 && "${shape##*:}" == refuse ]] || [[ "$verdict" -ne 0 && "${shape##*:}" == accept ]]; then
    echo "::error::self-test: ${shape%%:*}.log is answered $verdict; it must be ${shape##*:}"
    status=1
  fi
done
rm -rf "$selftest"

tally_floor() {
  local ran="$1" filtered="$2"
  if [[ -z "$filtered" && "$ran" -eq 0 ]]; then
    echo "::error::upstream suites: none ran green against a Ferrox binary, so a green job would prove nothing"
    return 1
  fi
}

for shape in zero-full:refuse some-full:accept zero-filtered:accept; do
  verdict=0
  case "${shape%%:*}" in
    zero-full) tally_floor 0 "" >/dev/null || verdict=$? ;;
    some-full) tally_floor 2 "" >/dev/null || verdict=$? ;;
    zero-filtered) tally_floor 0 "one-pin" >/dev/null || verdict=$? ;;
  esac
  if [[ "$verdict" -eq 0 && "${shape##*:}" == refuse ]] || [[ "$verdict" -ne 0 && "${shape##*:}" == accept ]]; then
    echo "::error::self-test: tally ${shape%%:*} is answered $verdict; it must be ${shape##*:}"
    status=1
  fi
done

parse_pins() {
  awk '
    function f(v) { return v == "" ? "-" : v }
    /^\[sources\./ {
      if (name != "") print name "\t" repo "\t" rev "\t" enabled "\t" f(suite) "\t" f(binary) "\t" f(seam) "\t" f(path)
      name = $0; sub(/^\[sources\./, "", name); sub(/\]$/, "", name)
      repo = ""; rev = ""; enabled = ""; suite = ""; binary = ""; seam = ""; path = ""
      next
    }
    /^repo[[:space:]]*=/ { repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next }
    /^rev[[:space:]]*=/ { rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next }
    /^test_enabled[[:space:]]*=/ { enabled = $0; sub(/^[^=]*=[[:space:]]*/, "", enabled); next }
    /^suite[[:space:]]*=/ { suite = $0; sub(/^[^=]*=[[:space:]]*"/, "", suite); sub(/"[[:space:]]*$/, "", suite); next }
    /^ferrox_binary[[:space:]]*=/ { binary = $0; sub(/^[^=]*=[[:space:]]*"/, "", binary); sub(/"[[:space:]]*$/, "", binary); next }
    /^seam[[:space:]]*=/ { seam = $0; sub(/^[^=]*=[[:space:]]*"/, "", seam); sub(/"[[:space:]]*$/, "", seam); next }
    /^path[[:space:]]*=/ { path = $0; sub(/^[^=]*=[[:space:]]*"/, "", path); sub(/"[[:space:]]*$/, "", path); next }
    END { if (name != "") print name "\t" repo "\t" rev "\t" enabled "\t" f(suite) "\t" f(binary) "\t" f(seam) "\t" f(path) }
  ' "$pins_file"
}

workspace="$PWD"
while IFS=$'\t' read -r name repo rev enabled suite binary seam path; do
  [[ "$suite" == "-" ]] && suite=""
  [[ "$binary" == "-" ]] && binary=""
  [[ "$seam" == "-" ]] && seam=""
  [[ "$path" == "-" ]] && path=""
  [[ -n "$name" ]] || continue
  if [[ -n "$name_filter" && "$name" != "$name_filter" ]]; then
    continue
  fi
  if [[ -n "${path:-}" ]]; then
    scratch="$(mktemp -d)"
    if git init --quiet --bare "$scratch" >/dev/null 2>&1 \
      && git -C "$scratch" remote add origin "$repo" >/dev/null 2>&1 \
      && git -C "$scratch" fetch --quiet --depth 1 origin "$rev" >/dev/null 2>&1 \
      && git -C "$scratch" cat-file -e "$rev:$path" 2>/dev/null; then
      echo "path ok: $name $path at ${rev:0:7}"
    else
      echo "::error::$name declares path $path but it is absent at $rev"
      status=1
      rm -rf "$scratch"
      continue
    fi
    rm -rf "$scratch"
  fi
  if [[ "$enabled" != "true" ]]; then
    echo "SKIPPED: $name @ ${rev:0:7} — no Ferrox binary wired yet (would need ${binary:-nothing exists for this rung yet}); rung not implemented (see docs/conformance.md)"
    continue
  fi
  if [[ -z "${binary:-}" ]]; then
    echo "::error::$name is enabled with no ferrox_binary: refusing a PASS that ran no Ferrox binary"
    status=1
    continue
  fi
  if [[ -z "$suite" ]]; then
    echo "COVERED-BY-BUILD: $name @ ${rev:0:7} — no upstream suite; build matrix is the check"
    continue
  fi
  if [[ -z "$seam" ]]; then
    echo "::error::$name has no seam: its suite at $rev cannot execute $binary, so a PASS would name a binary that never ran"
    status=1
    continue
  fi
  echo "RUNNING: $name @ $rev against Ferrox binary $binary via $seam"
  echo "  suite: $suite"
  if ! cargo build --locked -q -p "$binary" 2>/dev/null; then
    echo "::error::$name: Ferrox binary $binary does not build in this workspace"
    status=1
    continue
  fi
  dir="$(mktemp -d)"
  if ! git clone --quiet --no-checkout "$repo" "$dir" 2>/dev/null; then
    echo "::error::$name: could not clone $repo"
    rm -rf "$dir"
    status=1
    continue
  fi
  if ! git -C "$dir" checkout --quiet "$rev" 2>/dev/null; then
    echo "::error::$name: rev $rev does not resolve"
    rm -rf "$dir"
    status=1
    continue
  fi
  if ! git -C "$dir" grep -qI -e "$seam" -- . 2>/dev/null; then
    echo "::error::$name declares seam $seam but $rev never reads it: nothing would execute $binary"
    rm -rf "$dir"
    status=1
    continue
  fi
  log="$(mktemp)"
  passed=0
  if (cd "$dir" && env "$seam=$workspace/target/debug/$binary" bash -c "$suite") 2>&1 | tee "$log"; then
    passed=1
  fi
  if ((passed == 0)); then
    echo "::error::$name suite failed at $rev"
    status=1
  elif libtest_ran_named "$suite" "$log"; then
    echo "PASS: $name suite green against $binary at $rev (injected via $seam)"
    ran=$((ran + 1))
  else
    echo "::error::$name suite exited 0 without running what its command names"
    status=1
  fi
  rm -rf "$dir" "$log"
done < <(parse_pins)

echo "upstream suites: $ran ran green against Ferrox binaries (the rest skipped with reasons above)"
if ! tally_floor "$ran" "$name_filter"; then
  status=1
fi
exit "$status"
