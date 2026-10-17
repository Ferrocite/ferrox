#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

default_pattern="${1:-${BASELINE_PATTERN:-./...}}"
# A plan file narrows the run to the packages of the reference that measure the
# change; with none, every package is the answer, which is what a scheduled,
# manual or local run wants.
patterns=()
if [[ -f .ferrox/ci-scope.json ]]; then
  while IFS= read -r line; do [[ -n "$line" ]] && patterns+=("$line"); done \
    < <(python3 scripts/ci-scope.py go-packages)
  if [[ "${#patterns[@]}" -eq 0 ]]; then
    echo "no package of the pinned reference measures this change: nothing to run"
    exit 0
  fi
else
  read -r -a patterns <<<"$default_pattern"
fi
pattern="${patterns[*]}"
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

# Go keys a package's build and its cached verdict on the paths of its sources, so an
# mktemp'd tree rebuilds the pin from nothing on every run. One fixed path, emptied
# first: the verdict this rev already gave becomes the answer the next run reads.
dir="${TMPDIR:-/tmp}/ferrox-xray-baseline-src"
rm -rf "$dir"
mkdir -p "$dir"
trap 'rm -rf "$dir"' EXIT
# One commit, the pinned one: go test reads the tree, never its history, and a
# full clone of xray-core costs a minute the pin cannot pay back.
if ! git init --quiet "$dir" >/dev/null 2>&1 \
  || ! git -C "$dir" remote add origin "$repo" >/dev/null 2>&1 \
  || ! git -C "$dir" fetch --quiet --no-tags --depth 1 origin "$rev" >/dev/null 2>&1 \
  || ! git -C "$dir" checkout --quiet FETCH_HEAD 2>/dev/null; then
  echo "::error::could not fetch $rev from $repo"
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
echo "  pattern: go test -timeout $go_timeout $pattern"
echo "  $go_version"

# No `-count=1`: this suite runs the pin against itself, so its verdict is a property of $rev
# and the Go toolchain and never of our diff; the line below names what was reused per PR.
set +e
(cd "$dir" && go test -timeout "$go_timeout" "${patterns[@]}" >"$log" 2>&1)
test_rc=$?
set -e

pkg_ok="$(grep -c '^ok[[:space:]]' "$log" || true)"; pkg_ok="${pkg_ok:-0}"
pkg_fail="$(grep -c '^FAIL[[:space:]]' "$log" || true)"; pkg_fail="${pkg_fail:-0}"
pkg_notest="$(grep -c 'no test files' "$log" || true)"; pkg_notest="${pkg_notest:-0}"
pkg_cached="$(grep -c '[[:space:]](cached)$' "$log" || true)"; pkg_cached="${pkg_cached:-0}"
case_fail="$(grep -c '^--- FAIL:' "$log" || true)"; case_fail="${case_fail:-0}"
sub_fail="$(grep -c '^[[:space:]][[:space:]]*--- FAIL:' "$log" || true)"; sub_fail="${sub_fail:-0}"

{
  echo "# xray-core baseline @ \`${rev:0:7}\`"
  echo
  echo "Upstream against itself at its pin, not against a Ferrox binary. Informational: test failures never fail this job; infra failures (unresolvable pin, no Go) do."
  echo
  echo "- rev: \`$rev\`"
  echo "- tree: \`$dir\`"
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
  echo "Re-executed this run: $((pkg_ok - pkg_cached)) of $pkg_ok passing package result(s); the other $pkg_cached came from this pin's own Go cache, which holds the verdict \`$rev\` already gave."
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
