#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fast=0
case "${1:-}" in
  "") ;;
  --fast) fast=1 ;;
  -h|--help)
    echo "usage: scripts/check.sh [--fast]"
    echo "  --fast  fmt, clippy and the test suite only (no docs, policy gates or counts)"
    exit 0
    ;;
  *) echo "usage: scripts/check.sh [--fast]" >&2; exit 2 ;;
esac

export RUSTFLAGS="${RUSTFLAGS:--D warnings --cfg aes_armv8 --cfg polyval_armv8}"
start=$SECONDS

step() { printf '\n=== %s ===\n' "$1"; }

# Independent gates are a wall-clock cost only; run them together and print
# their logs in a stable order, the way ci.yml does.
run_gates() {
  local tmp gate pid status=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/ferrox-gates.XXXXXX")"
  local -a pids=()
  for gate in "$@"; do
    ( "./scripts/$gate.sh" >"$tmp/$gate.log" 2>&1; echo $? >"$tmp/$gate.rc" ) &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || true
  done
  for gate in "$@"; do
    cat "$tmp/$gate.log"
    if [[ "$(cat "$tmp/$gate.rc")" != 0 ]]; then
      echo "::error::$gate.sh failed" >&2
      status=1
    fi
  done
  rm -rf "$tmp"
  return "$status"
}

step "worktree target"
./scripts/claim-target.sh

step "fmt"
cargo fmt --all -- --check

step "clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::perf -W clippy::suspicious

if [[ $fast == 0 ]]; then
  step "doc"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps

  step "policy gates"
  run_gates \
    check-worktree-artifacts \
    check-leak-surface \
    check-identity-leak \
    check-dependency-policy \
    check-comments \
    check-merge-markers \
    check-fixture-safety \
    check-windows-binary-paths \
    check-method-docs \
    check-ci-scope \
    check-method-superset

  step "benchmark and matrix selftests"
  python3 scripts/benchmark-delta.py --selftest
  python3 scripts/check-matrix-legs.py --selftest
  python3 scripts/rewrite-depinfo.py --selftest

  step "cli arguments"
  python3 scripts/check-cli-args.py
  python3 scripts/check-cli-lane.py

  step "prompt library"
  cargo run --locked --quiet -p ferrox-prompt -- check
fi

if [[ $fast == 0 ]]; then
  step "stall detector"
  mkdir -p target/ci
  ./scripts/watch-test.sh --selftest > target/ci/selftest.log 2>&1 &
  selftest=$!
fi

step "tests"
tests=0
./scripts/watch-test.sh -- cargo test --workspace --locked || tests=$?

if [[ $fast == 0 ]]; then
  selftest_rc=0
  wait "$selftest" || selftest_rc=$?
  cat target/ci/selftest.log
  if [ "$tests" -ne 0 ] || [ "$selftest_rc" -ne 0 ]; then
      exit 1
  fi
elif [ "$tests" -ne 0 ]; then
  exit 1
fi

if [[ $fast == 0 ]]; then
  # Same flags ops.yml blesses under: line tables only, nothing else, because a
  # different RUSTFLAGS is a different program and the counts in expected-ops.txt
  # are counts of that one.
  step "operation counts"
  if [[ "$(uname -s)" == Darwin ]]; then
    echo "count-ops: CI-only on macOS (valgrind does not run here); ops.yml gates the counts"
  elif ! command -v valgrind >/dev/null 2>&1 || ! command -v strace >/dev/null 2>&1; then
    echo "::error::count-ops needs valgrind and strace; install them first" >&2
    exit 1
  else
    RUSTFLAGS="-C debuginfo=line-tables-only" \
      ./scripts/count-ops.sh check quic::tests::pem_wraps_at_sixty_four_columns scripts/expected-ops.txt
  fi
fi

printf '\nall local checks green in %ss\n' "$((SECONDS - start))"
