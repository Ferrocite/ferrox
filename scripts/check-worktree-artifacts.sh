#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# CI checks out into a disposable runner; only a contributor machine can grow a
# worktree with build trees, and only there is the shared target the rule.
if [[ -n "${CI:-}" ]]; then
  exit 0
fi

status=0
if [[ -e .build ]]; then
  echo "::error::.build/ is inside the worktree; move it under the shared target or delete it" >&2
  status=1
fi
if [[ -e target && ! -L target ]]; then
  echo "::error::target/ is a real directory; point it at the shared target with scripts/new-worktree.sh" >&2
  status=1
fi
if [[ -L target ]]; then
  resolved="$(cd "$(dirname "$(readlink target)")" 2>/dev/null && pwd -P)/$(basename "$(readlink target)")"
  case "$resolved" in
    "$PWD"/*)
      echo "::error::target resolves inside the worktree ($resolved); point it outside" >&2
      status=1
      ;;
  esac
  printf 'target -> %s\n' "$resolved"
fi
exit "$status"
