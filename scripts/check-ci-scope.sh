#!/usr/bin/env bash
# The scope plan is a claim about what each change has to be measured against, so
# it is checked two ways: the planner's own fixtures, and every declaration in
# docs/function against the tree, the matrix and the pins it names.
set -euo pipefail

cd "$(dirname "$0")/.."

python3 scripts/ci-scope.py selftest
python3 scripts/ci-scope.py check
