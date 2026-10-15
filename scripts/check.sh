#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export RUSTFLAGS="${RUSTFLAGS:--D warnings --cfg aes_armv8 --cfg polyval_armv8}"

step() { printf '\n=== %s ===\n' "$1"; }

step "fmt"
cargo fmt --all -- --check

step "clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::perf -W clippy::suspicious

step "doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps

step "leak surface"
./scripts/check-leak-surface.sh

step "dependency policy"
./scripts/check-dependency-policy.sh

step "comment trace"
./scripts/check-comments.sh

step "fixture safety"
./scripts/check-fixture-safety.sh

step "windows binary paths"
./scripts/check-windows-binary-paths.sh

step "method docs"
./scripts/check-method-docs.sh

step "ci scope"
./scripts/check-ci-scope.sh

step "method matrix"
./scripts/check-method-superset.sh

step "prompt library"
cargo run --locked --quiet -p ferrox-prompt -- check

step "tests"
./scripts/watch-test.sh -- cargo test --workspace --locked

# Same flags ops.yml blesses under: line tables only, nothing else, because a
# different RUSTFLAGS is a different program and the counts in expected-ops.txt
# are counts of that one.
step "operation counts"
RUSTFLAGS="-C debuginfo=line-tables-only" \
    ./scripts/count-ops.sh check quic::tests::pem_wraps_at_sixty_four_columns scripts/expected-ops.txt

printf '\nall local checks green\n'