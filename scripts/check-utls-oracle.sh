#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
(cd scripts/utls-oracle && go run . < script.txt > "$out")
diff -u scripts/utls-oracle/expected.txt "$out"
