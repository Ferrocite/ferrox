#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export RUSTFLAGS="${RUSTFLAGS:--D warnings --cfg aes_armv8 --cfg polyval_armv8}"

step() { printf '\n=== %s ===\n' "$1"; }

step "worktree target"
./scripts/claim-target.sh

step "fmt"
cargo fmt --all -- --check

step "clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::perf -W clippy::suspicious

step "doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps

step "worktree artifacts"
./scripts/check-worktree-artifacts.sh

step "leak surface"
./scripts/check-leak-surface.sh

step "dependency policy"
./scripts/check-dependency-policy.sh

step "comment trace"
./scripts/check-comments.sh

step "merge markers"
./scripts/check-merge-markers.sh

step "cli arguments"
python3 scripts/check-cli-args.py

step "cli lane report"
python3 scripts/check-cli-lane.py

step "fixture safety"
./scripts/check-fixture-safety.sh

step "windows binary paths"
./scripts/check-windows-binary-paths.sh

step "method docs"
./scripts/check-method-docs.sh

step "ci scope"
./scripts/check-ci-scope.sh

step "benchmark delta"
python3 scripts/benchmark-delta.py --selftest
python3 scripts/check-matrix-legs.py --selftest

step "method matrix"
./scripts/check-method-superset.sh

step "prompt library"
cargo run --locked --quiet -p ferrox-prompt -- check

step "stall detector"
mkdir -p target/ci
./scripts/watch-test.sh --selftest > target/ci/selftest.log 2>&1 &
selftest=$!

step "tests"
tests=0
./scripts/watch-test.sh -- cargo test --workspace --locked || tests=$?

selftest_rc=0
wait "$selftest" || selftest_rc=$?
cat target/ci/selftest.log
if [ "$tests" -ne 0 ] || [ "$selftest_rc" -ne 0 ]; then
    exit 1
fi

# Same flags ops.yml blesses under: line tables only, nothing else, because a
# different RUSTFLAGS is a different program and the counts in expected-ops.txt
# are counts of that one.
step "operation counts"
RUSTFLAGS="-C debuginfo=line-tables-only" \
    ./scripts/count-ops.sh check quic::tests::pem_wraps_at_sixty_four_columns scripts/expected-ops.txt

printf '\nall local checks green\n'