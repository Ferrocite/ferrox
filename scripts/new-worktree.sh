#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: scripts/new-worktree.sh <name> [base-ref]" >&2
  exit 2
fi
name="$1"
base="${2:-HEAD}"

top="$(git rev-parse --show-toplevel)"
parent="$(dirname "$top")"
case "$name" in
  *-ferrox) dest="$parent/$name" ;;
  *) dest="$parent/ferrox-$name" ;;
esac

# shellcheck source=scripts/lib-shared-target.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-shared-target.sh"
# The seed is only read: each worktree gets a copy-on-write clone, so its build
# holds a lock nobody else wants and shares the seed's blocks on disk.
shared="$(ferrox_shared_target)"
ferrox_require_shared_writable "$shared"

if [[ -e "$dest" ]]; then
  # A retry, or a worktree another agent's session left behind: repair it rather
  # than refuse, because a stranded worktree is what grows a private target.
  if git -C "$top" worktree list --porcelain | sed -n 's/^worktree //p' | grep -Fxq "$dest"; then
    ferrox_link_worktree "$dest" "$top" "$shared" >/dev/null
    echo "worktree: $dest (already exists, pointers and target repaired)"
    echo "seed: $shared"
    exit 0
  fi
  echo "::error::$dest already exists" >&2
  exit 1
fi

git -C "$top" worktree add "$dest" -b "$name" "$base"

ferrox_write_cargo_config "$dest" "$shared"
ferrox_claim_target "$dest" "$shared"
linked="$(ferrox_link_upstream "$dest" "$top")"

echo "worktree: $dest (branch $name)"
echo "target: own copy-on-write clone of $shared"
echo "upstream checkouts linked: $linked"
echo "next: ./scripts/fetch-upstream.sh (only what the links missed), then ./scripts/check.sh"
