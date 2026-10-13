#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

pattern="${1:-${BASELINE_PATTERN:-./...}}"
go_timeout="${GO_TEST_TIMEOUT:-20m}"
pins_file="upstream/pins.toml"
out_dir="target/xray-baseline"
log="$out_dir/xray-baseline.log"
summary="$out_dir/xray-baseline-summary.md"

repo="$(awk '/^\[sources\.xray-core\]/{hit=1; next} /^\[/{hit=0} hit && /^repo[[:space:]]*=/ {s=$0; sub(/^[^=]*=[[:space:]]*"/, "", s); sub(/"[[:space:]]*$/, "", s); print s}' "$pins_file")"
rev="$(awk '/^\[sources\.xray-core\]/{hit=1; next} /^\[/{hit=0} hit && /^rev[[:space:]]*=/ {s=$0; sub(/^[^=]*=[[:space:]]*"/, "", s); sub(/"[[:space:]]*$/, "", s); print s}' "$pins_file")"

if [[ -z "${repo:-}" || -z "${rev:-}" ]]; then
  echo "::error::could not parse [sources.xray-core] repo/rev from $pins_file"
  exit 1
fi
if [[ ! "$rev" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "::error::xray-core rev '$rev' is not a commit id"
  exit 1
fi

mkdir -p "$out_dir"
log="$PWD/$log"
summary="$PWD/$summary"

dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
if ! git clone --quiet --no-checkout "$repo" "$dir" 2>/dev/null; then
  echo "::error::could not clone $repo"
  exit 1
fi
if ! git -C "$dir" checkout --quiet "$rev" 2>/dev/null; then
  echo "::error::xray-core rev $rev does not resolve on $repo"
  exit 1
fi
head="$(git -C "$dir" rev-parse HEAD)"
if [[ "$head" != "$rev" ]]; then
  echo "::error::checkout holds $head, not its pin $rev"
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "::error::go toolchain not found"
  exit 1
fi
go_version="$(go version)"

echo "baseline: xray-core @ $rev (upstream against itself, no Ferrox binary)"
echo "  pattern: go test -count=1 -timeout $go_timeout $pattern"
echo "  $go_version"

set +e
(cd "$dir" && go test -count=1 -timeout "$go_timeout" "$pattern" >"$log" 2>&1)
test_rc=$?
set -e

pkg_ok="$(grep -c '^ok[[:space:]]' "$log" || true)"; pkg_ok="${pkg_ok:-0}"
pkg_fail="$(grep -c '^FAIL[[:space:]]' "$log" || true)"; pkg_fail="${pkg_fail:-0}"
pkg_notest="$(grep -c 'no test files' "$log" || true)"; pkg_notest="${pkg_notest:-0}"
case_fail="$(grep -c '^--- FAIL:' "$log" || true)"; case_fail="${case_fail:-0}"
sub_fail="$(grep -c '^[[:space:]][[:space:]]*--- FAIL:' "$log" || true)"; sub_fail="${sub_fail:-0}"

{
  echo "# xray-core baseline @ \`${rev:0:7}\`"
  echo
  echo "Upstream against itself at its pin, not against a Ferrox binary. Informational: test failures never fail this job; infra failures (unresolvable pin, no Go) do."
  echo
  echo "- rev: \`$rev\`"
  echo "- pattern: \`$pattern\`"
  echo "- timeout: \`$go_timeout\`"
  echo "- toolchain: \`$go_version\`"
  echo "- go exit code: \`$test_rc\`"
  echo
  echo "## totals"
  echo
  echo "| packages ok | packages FAIL | no test files | \`--- FAIL\` cases | subtest fails |"
  echo "| --- | --- | --- | --- | --- |"
  echo "| $pkg_ok | $pkg_fail | $pkg_notest | $case_fail | $sub_fail |"
  echo
  if ((pkg_fail > 0)); then
    echo "## failing packages"
    echo
    echo '```'
    grep '^FAIL[[:space:]]' "$log" | sort -u || true
    echo '```'
    echo
  fi
  if ((case_fail > 0 || sub_fail > 0)); then
    echo "## failing cases (first 100)"
    echo
    echo '```'
    grep -E '^[[:space:]]*--- FAIL:' "$log" | head -100 || true
    echo '```'
    echo
  fi
  if ((pkg_fail == 0 && case_fail == 0 && test_rc == 0)); then
    echo "All ran green at this pin and pattern."
    echo
  else
    echo "Red at this pin and pattern; the rows above are the work list."
    echo
  fi
  echo "Full log: \`$log\` (uploaded as the \`xray-baseline\` artifact in CI)."
} >"$summary"

cat "$summary"

if ((pkg_fail > 0 || case_fail > 0)) || ((test_rc != 0)); then
  echo "::warning::xray-core baseline: $pkg_ok package(s) ok, $pkg_fail FAIL, $case_fail failing case(s); recorded, job stays green"
else
  echo "xray-core baseline: all green ($pkg_ok packages ok)"
fi

exit 0
