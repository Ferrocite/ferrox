#!/usr/bin/env bash
# Give this worktree its own copy-on-write target, cloned from the warm seed.
# Cargo locks a target dir for the whole build; a clone turns a queue of agents
# into parallel builds that share the seed's blocks until one of them writes.
#
#   ./scripts/claim-target.sh          clone if this worktree is still on the seed
#
# The main checkout keeps the seed: it is the one build that refreshes the tree
# every clone starts from.
set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck source=scripts/lib-shared-target.sh
source scripts/lib-shared-target.sh
shared="$(ferrox_shared_target)"

if [[ "$(git rev-parse --git-dir)" == "$(git rev-parse --git-common-dir)" ]]; then
  # `cargo clean` removes the symlink, not the tree it names, and the next build
  # then writes a real target. Adopt that tree as the seed instead of leaving
  # the main checkout with a private one every clone has to bypass.
  if [[ -d "$PWD/target" && ! -L "$PWD/target" ]]; then
    echo "claim: adopting the main checkout's target as the seed" >&2
    chmod -R u+w "$shared" 2>/dev/null || true
    rm -rf "$shared"
    mv "$PWD/target" "$shared"
    ln -s "$shared" "$PWD/target"
  fi
  # The main checkout keeps the seed; repair its config here so a changed
  # generator does not make `check-worktree-artifacts` red before the first
  # worktree is created. CI has no seed and needs no link.
  if [[ -d "$shared" ]]; then
    ferrox_write_cargo_config "$PWD" "$shared"
  fi
  exit 0
fi
if ferrox_target_is_own "$PWD"; then
  exit 0
fi

# Keep a free-space floor before a clone: a full disk fails every agent at once,
# and the idlest clones are cheap to recreate from the seed. A worktree that
# already owns its target allocates nothing, so the scan is not on its path.
if [[ -z "${CI:-}" ]]; then
  ./scripts/gc-target.sh --ensure-free "${FERROX_MIN_FREE_GIB:-25}" --keep "$PWD" >/dev/null || true
fi

ferrox_require_shared_writable "$shared"
ferrox_write_cargo_config "$PWD" "$shared"
ferrox_claim_target "$PWD" "$shared"
echo "claim: cloned the warm target into $PWD/target (copy-on-write, own lock)"
