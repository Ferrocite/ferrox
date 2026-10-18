#!/usr/bin/env bash
# xray-core writes its own config form and spawns its own binary: `testing/scenarios`
# builds `main` at run time (BuildXray) and execs it with `-config=stdin: -format=pb`.
# scripts/xray-scenarios.sh replaces that build with a launcher that execs ferrox-app, so
# the suite's own tests run against Ferrox. The gate in upstream/pins.toml names four of
# those tests. This script runs EVERY test in the package, family by family, and records
# which ones Ferrox answers: a family is one source file, because a hang inside one
# family must cost that family's remaining verdicts and nothing else.
#
# Informational: a failing test never fails this job. What does fail it is a run that
# proved nothing — a pin that will not resolve, a binary that will not build, a family
# whose Ferrox launcher never spawned, or a gated test that this map does not name.
set -euo pipefail

cd "$(dirname "$0")/.."

self="$(basename "$0")"

# One `go test -v` transcript into per-test verdicts: name|verdict, verdict in
# pass|fail|skip. Only an unindented `--- ` line is a test's own verdict; the indented
# ones are its subtests, which belong to their parent's row and must not become rows.
tally_log() {
  local log="$1"
  awk '
    /^--- (PASS|FAIL|SKIP): ([A-Za-z0-9_]+)( |$)/ {
      verdict = $2; sub(/:$/, "", verdict); name = $3
      print name "|" tolower(verdict)
    }
  ' "$log"
}

# A `-run` that matched no name exits 0 having proven nothing, so every name the command
# asked for must carry a verdict; one without a row is `absent`, never a silent pass.
verdict_for() {
  local name="$1" tallies="$2"
  awk -F'|' -v want="$name" '$1 == want { print $2; found = 1 } END { if (!found) print "absent" }' <<<"$tallies"
}

# A family is one source file of the pinned package; its tests are the `Test…` functions
# in it. TestMain is the package's harness, not a test: naming it in `-run` would ask for
# a verdict it never writes. Printed as `family|name,name,...`, one line per family.
# Every skipped file is an `if` rather than a `|| continue`: a loop's status is its body's
# last command, and a failed test at the end of the last file would otherwise read to
# `set -e` as the enumeration itself failing.
enumerate_families() {
  local dir="$1" file name names
  for file in "$dir"/*_test.go; do
    if [[ ! -f "$file" ]]; then continue; fi
    name="$(basename "$file" _test.go)"
    # `|| true` twice over: a file whose only test is TestMain makes the filter match
    # nothing, and a grep that matches nothing exits 1, which under `set -e` would end the
    # whole map on the package's harness file rather than skip it.
    names="$(grep -hoE '^func (Test[A-Za-z0-9_]+)\(' "$file" | sed -E 's/^func //; s/\($//' | { grep -v '^TestMain$' || true; } | paste -sd, -)"
    if [[ -z "$names" ]]; then continue; fi
    printf '%s|%s\n' "$name" "$names"
  done
}

# A count that can be zero, which `grep -c` reports by exiting 1: the count is the answer,
# not a failure.
count_rows() {
  grep -c . || true
}

# The `-run` pattern a family's names turn into: one alternation, anchored at both ends so
# a test that prefixes a sibling cannot be run under a name the family never declared.
run_pattern() {
  printf '^(%s)$' "$(tr ',' '|' <<<"$1")"
}

run_selftest() {
  local tmp failures=0 tallies verdict spec family names got want
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/scenarios"

  # The tally: a pass, a failure whose only other line is an indented subtest, a skip, and
  # a name nobody reported.
  printf '%s\n' \
    '=== RUN   TestAlpha' '--- PASS: TestAlpha (0.31s)' \
    '=== RUN   TestBravo' '    --- FAIL: TestBravo/inner (0.01s)' '--- FAIL: TestBravo (1.02s)' \
    '=== RUN   TestCharlie' '--- SKIP: TestCharlie (0.00s)' >"$tmp/go.log"
  tallies="$(tally_log "$tmp/go.log")"
  for shape in TestAlpha:pass TestBravo:fail TestCharlie:skip TestDelta:absent; do
    verdict="$(verdict_for "${shape%%:*}" "$tallies")"
    if [[ "$verdict" != "${shape##*:}" ]]; then
      echo "::error::$self self-test: ${shape%%:*} is tallied '$verdict'; it must be '${shape##*:}'"
      failures=1
    fi
  done
  if [[ "$(count_rows <<<"$tallies")" -ne 3 ]]; then
    echo "::error::$self self-test: the subtest line became a row; the map would count two witnesses where one ran"
    failures=1
  fi

  # The enumeration: TestMain is not a test, a file with no tests is not a family, and a
  # file the suite never built must not be invented.
  printf 'package s\nfunc TestMain(m *testing.M) {}\nfunc TestOne(t *testing.T) {}\nfunc TestTwo(t *testing.T) {}\n' >"$tmp/scenarios/alpha_test.go"
  printf 'package s\nfunc TestThree(t *testing.T) {}\n' >"$tmp/scenarios/beta_test.go"
  printf 'package s\n// no tests here\n' >"$tmp/scenarios/gamma_test.go"
  got="$(enumerate_families "$tmp/scenarios" | paste -sd' ' -)"
  want="alpha|TestOne,TestTwo beta|TestThree"
  if [[ "$got" != "$want" ]]; then
    echo "::error::$self self-test: families enumerated as '$got'; they must be '$want'"
    failures=1
  fi

  # The pattern: anchored, and a comma is the only separator a name cannot contain.
  spec="$(enumerate_families "$tmp/scenarios" | sed -n 1p)"
  family="${spec%%|*}"; names="${spec#*|}"
  got="$(run_pattern "$names")"
  want='^(TestOne|TestTwo)$'
  if [[ "$got" != "$want" ]]; then
    echo "::error::$self self-test: $family built pattern '$got'; it must be '$want'"
    failures=1
  fi
  return "$failures"
}

if [[ "${1:-}" == "--selftest" ]]; then
  run_selftest
  exit $?
fi

if [[ $# -gt 1 ]]; then
  echo "::error::$self takes no arguments; the families come from the pinned checkout"
  exit 2
fi

pins_file="upstream/pins.toml"
out_dir="target/xray-scenario-map"
log_dir="$out_dir/logs"
summary="$out_dir/xray-scenario-map.md"
binary_name="ferrox-app"
# A family that cannot answer inside this is recorded TIMEOUT and the run moves on; the
# budget is the whole map's ceiling, and what it cannot reach is NOT RUN rather than passed.
family_timeout="${SCENARIO_FAMILY_TIMEOUT:-120s}"
total_budget="${SCENARIO_MAP_BUDGET:-2100}"

repo="$(awk '/^\[sources\.xray-core\]/{hit=1; next} /^\[/{hit=0} hit && /^repo[[:space:]]*=/ {s=$0; sub(/^[^=]*=[[:space:]]*"/, "", s); sub(/"[[:space:]]*$/, "", s); print s}' "$pins_file")"
rev="$(awk '/^\[sources\.xray-core\]/{hit=1; next} /^\[/{hit=0} hit && /^rev[[:space:]]*=/ {s=$0; sub(/^[^=]*=[[:space:]]*"/, "", s); sub(/"[[:space:]]*$/, "", s); print s}' "$pins_file")"
gate="$(awk '/^\[sources\.xray-core\]/{hit=1; next} /^\[/{hit=0} hit && /^suite[[:space:]]*=/ {s=$0; sub(/^[^=]*=[[:space:]]*"/, "", s); print s}' "$pins_file")"

if [[ -z "$repo" || -z "$rev" ]]; then
  echo "::error::$self: could not parse [sources.xray-core] repo/rev from $pins_file"
  exit 1
fi
if [[ ! "$rev" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "::error::$self: xray-core rev '$rev' is not a commit id"
  exit 1
fi

# The gated names are read out of the pin's own command so the map and the gate cannot
# drift apart: a test the gate runs that the map does not name would let the map report a
# family as unaccounted while the gate still called it green.
gated=()
while IFS= read -r name; do
  if [[ -n "$name" ]]; then gated+=("$name"); fi
done < <(grep -oE 'Test[A-Za-z0-9_]+' <<<"$gate" | sort -u)
if [[ "${#gated[@]}" -eq 0 ]]; then
  echo "::error::$self: parsed no gated test names out of the xray-core suite line"
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "::error::$self: go toolchain not found"
  exit 1
fi
go_version="$(go version)"

if ! cargo build --locked -q -p "$binary_name"; then
  echo "::error::$self: $binary_name does not build in this workspace"
  exit 1
fi
binary="$PWD/target/debug/$binary_name"
if [[ ! -x "$binary" ]]; then
  echo "::error::$self: built $binary_name but $binary is not executable"
  exit 1
fi

rm -rf "$out_dir"
mkdir -p "$log_dir"
workspace="$PWD"

# Go keys a package's build on its sources' paths, so a mktemp tree rebuilds the pin from
# nothing on every run. One fixed path, emptied first.
dir="${TMPDIR:-/tmp}/ferrox-xray-scenario-map-src"
rm -rf "$dir"
mkdir -p "$dir"
if ! git init --quiet "$dir" >/dev/null 2>&1 \
  || ! git -C "$dir" remote add origin "$repo" >/dev/null 2>&1 \
  || ! git -C "$dir" fetch --quiet --no-tags --depth 1 origin "$rev" >/dev/null 2>&1 \
  || ! git -C "$dir" checkout --quiet FETCH_HEAD 2>/dev/null; then
  echo "::error::$self: could not fetch $rev from $repo"
  exit 1
fi
if [[ "$(git -C "$dir" rev-parse HEAD)" != "$rev" ]]; then
  echo "::error::$self: checkout holds $(git -C "$dir" rev-parse HEAD), not its pin $rev"
  exit 1
fi

scenarios="testing/scenarios"
if [[ ! -d "$dir/$scenarios" ]]; then
  echo "::error::$self: the pinned checkout has no $scenarios package"
  exit 1
fi

families="$(enumerate_families "$dir/$scenarios")"
if [[ -z "$families" ]]; then
  echo "::error::$self: no test functions found in $scenarios at $rev; the map would prove nothing"
  exit 1
fi

total_tests=0
while IFS= read -r spec; do
  if [[ -z "$spec" ]]; then continue; fi
  names="${spec#*|}"
  total_tests=$((total_tests + $(tr ',' '\n' <<<"$names" | count_rows)))
done <<<"$families"

rows=()
pass=0 fail=0 skip=0 absent=0 timeouts=0
started="$SECONDS"
echo "$self: xray-core @ $rev, $total_tests test(s) across $(count_rows <<<"$families") families, against $binary_name"
echo "  per-family timeout $family_timeout, whole-map budget ${total_budget}s"

while IFS= read -r spec; do
  [[ -n "$spec" ]] || continue
  family="${spec%%|*}"
  names_csv="${spec#*|}"
  names="$(tr ',' '\n' <<<"$names_csv")"
  suite="go test -count=1 -timeout $family_timeout -v -run '$(run_pattern "$names_csv")' ./$scenarios"
  log="$log_dir/$family.log"
  if ((SECONDS - started >= total_budget)); then
    rows+=("| $family | NOT RUN | $(count_rows <<<"$names") | the map budget of ${total_budget}s was spent before this family |")
    while IFS= read -r n; do
      if [[ -n "$n" ]]; then absent=$((absent + 1)); fi
    done <<<"$names"
    continue
  fi
  status=0
  (cd "$dir" && FERROX_BINARY="$binary" bash "$workspace/scripts/xray-scenarios.sh" "$suite") >"$log" 2>&1 || status=$?
  tallies="$(tally_log "$log")"
  f_pass=0 f_fail=0 f_skip=0 f_absent=0
  while IFS= read -r n; do
    if [[ -z "$n" ]]; then continue; fi
    case "$(verdict_for "$n" "$tallies")" in
      pass) f_pass=$((f_pass + 1)); pass=$((pass + 1)) ;;
      fail) f_fail=$((f_fail + 1)); fail=$((fail + 1)) ;;
      skip) f_skip=$((f_skip + 1)); skip=$((skip + 1)) ;;
      *) f_absent=$((f_absent + 1)); absent=$((absent + 1)) ;;
    esac
  done <<<"$names"
  f_total=$((f_pass + f_fail + f_skip + f_absent))
  # The launcher touches its marker on the way to Ferrox; no marker means the family never
  # spawned our binary. A family that answers no test while the command still exits 0 is
  # the same nothing: `-run` matched no name, so its row would read as a verdict.
  if ((f_absent == f_total)) && { ((status == 0)) || grep -q 'never ran what its own build produced' "$log"; }; then
    echo "::error::$self: family $family answered no test at all, so it proves nothing"
    exit 1
  fi
  verdict="mixed"
  if ((f_absent > 0)); then
    verdict="TIMEOUT($f_pass/$f_total)"
    timeouts=$((timeouts + 1))
  elif ((f_fail == 0 && f_pass > 0)); then
    verdict="green"
  elif ((f_pass == 0)); then
    verdict="red"
  fi
  rows+=("| $family | $verdict | $f_total | $f_pass pass, $f_fail fail, $f_skip skip, $f_absent no verdict |")
  echo "  $family: $verdict — $f_pass/$f_total"
done <<<"$families"

# A gated test that no family declares is a gate naming something the map cannot see; that
# is the drift this check exists to catch, so it is an infra failure rather than a row.
all_names="$(while IFS= read -r spec; do
  if [[ -n "$spec" ]]; then tr ',' '\n' <<<"${spec#*|}"; fi
done <<<"$families")"
for g in "${gated[@]}"; do
  if ! grep -qx "$g" <<<"$all_names"; then
    echo "::error::$self: the gate names $g, which no family in $scenarios at $rev declares"
    exit 1
  fi
done

{
  echo "# xray-core scenario map @ \`${rev:0:7}\`"
  echo
  echo "Every test in \`$scenarios\` at the pin, run against \`$binary_name\` through \`scripts/xray-scenarios.sh\`. Informational: a failing test never fails this job; a run that proved nothing does. The gate stays the $(printf '%s\n' "${gated[@]}" | count_rows) named in \`upstream/pins.toml\`."
  echo
  echo "- rev: \`$rev\`"
  echo "- binary: \`$binary_name\` (\`$binary\`)"
  echo "- toolchain: \`$go_version\`"
  echo "- per-family timeout: \`$family_timeout\`; spent: \`$((SECONDS - started))s\` of a ${total_budget}s budget"
  echo
  echo "## totals"
  echo
  echo "| tests | pass | fail | skip | no verdict | families cut off by a timeout |"
  echo "| --- | --- | --- | --- | --- | --- |"
  echo "| $total_tests | $pass | $fail | $skip | $absent | $timeouts |"
  echo
  echo "## families"
  echo
  echo "| family | verdict | tests | tally |"
  echo "| --- | --- | --- | --- |"
  for row in "${rows[@]}"; do
    printf '%s\n' "$row"
  done
  echo
  echo "A family tallied \`TIMEOUT\` stopped answering inside \`$family_timeout\`: the tests it never reported are counted as no verdict, not as failures."
  echo
  echo "Ferrox answers none of a \`red\` family today; the rows are the work list, and \`docs/xray-parity.md\` states what each family needs from the config surface first."
} >"$summary"

cat "$summary"
echo "$self: $pass of $total_tests test(s) green against $binary_name at $rev; the gate's own verdict is unchanged by this map"
exit 0
