#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# CI checks out into a disposable runner; only a contributor machine can grow a
# worktree with build trees, and only there is the copy-on-write target the rule.
if [[ -n "${CI:-}" ]]; then
  exit 0
fi

# shellcheck source=scripts/lib-shared-target.sh
source scripts/lib-shared-target.sh
shared="$(ferrox_shared_target)"

status=0
if [[ -e .build ]]; then
  echo "::error::.build/ is inside the worktree; move it under the shared target or delete it" >&2
  status=1
fi
if ferrox_target_is_shared "$PWD" "$shared"; then
  if [[ "$(git rev-parse --git-dir)" == "$(git rev-parse --git-common-dir)" ]]; then
    printf 'target -> %s (seed)\n' "$shared"
  else
    echo "::error::target/ is the shared seed; run ./scripts/claim-target.sh for a copy-on-write clone" >&2
    status=1
  fi
elif [[ -L target ]]; then
  echo "::error::target/ points elsewhere; run ./scripts/claim-target.sh" >&2
  status=1
elif [[ ! -d target ]]; then
  echo "::error::target/ is missing; run ./scripts/claim-target.sh" >&2
  status=1
else
  printf 'target -> %s (own clone)\n' "$PWD/target"
fi
if ! ferrox_config_is_shared "$PWD" "$shared"; then
  echo "::error::.cargo/config.toml is not the shared config; run ./scripts/link-shared-target.sh" >&2
  status=1
fi
exit "$status"
