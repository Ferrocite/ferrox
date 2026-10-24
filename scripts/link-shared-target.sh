#!/usr/bin/env bash
# Repair every worktree's shared config and upstream symlinks, and give the
# current worktree its own copy-on-write target if it is still building on the
# seed. Idempotent: a worktree already correct is one line of output.
#
#   ./scripts/link-shared-target.sh            repair links, claim this worktree
#   ./scripts/link-shared-target.sh --all      also claim every other worktree
#   ./scripts/link-shared-target.sh --check    report drift, touch nothing
set -euo pipefail

# shellcheck source=scripts/lib-shared-target.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-shared-target.sh"
shared="$(ferrox_shared_target)"
check_only=0
claim_all=0
case "${1:-}" in
  "") ;;
  --all) claim_all=1 ;;
  --check) check_only=1 ;;
  *) echo "usage: scripts/link-shared-target.sh [--all|--check]" >&2; exit 2 ;;
esac
ferrox_require_shared_writable "$shared"

top="$(git rev-parse --show-toplevel)"
here="$(cd "$top" && pwd -P)"

# `git worktree list` is the only list of the branches that exist; a pointer
# written by hand before this script landed is invisible otherwise.
drift=0
unclaimed=0
while IFS= read -r path; do
  [[ -d $path ]] || continue
  path="$(cd "$path" && pwd -P)"
  is_main=0
  if [[ "$(git -C "$path" rev-parse --git-dir)" == "$(git -C "$path" rev-parse --git-common-dir)" ]]; then
    is_main=1
  fi

  config_ok=0
  if ferrox_config_is_shared "$path" "$shared"; then
    config_ok=1
  fi
  target_state="own"
  if ferrox_target_is_shared "$path" "$shared"; then
    target_state="seed"
  elif [[ ! -e "$path/target" ]]; then
    target_state="missing"
  fi
  upstream_missing=()
  for checkout in "$top"/upstream/*/; do
    checkout="${checkout%/}"
    [[ -d "$checkout/.git" ]] || continue
    base_name="$(basename "$checkout")"
    [[ "$path/upstream/$base_name" -ef "$checkout" ]] || upstream_missing+=("$base_name")
  done

  worktree_drift=0
  [[ $config_ok == 1 ]] || worktree_drift=1
  [[ ${#upstream_missing[@]} -eq 0 ]] || worktree_drift=1
  [[ $worktree_drift == 0 ]] || drift=$((drift + 1))
  if [[ $is_main == 0 && $target_state != "own" ]]; then
    unclaimed=$((unclaimed + 1))
  fi

  if [[ $check_only == 1 ]]; then
    if [[ $worktree_drift == 0 && $target_state == "own" ]] || [[ $is_main == 1 && $worktree_drift == 0 ]]; then
      echo "ok: $path (target=$target_state)"
    else
      echo "drift: $path (config=$([[ $config_ok == 1 ]] && echo shared || echo elsewhere), target=$target_state, upstream missing=${upstream_missing[*]:-none})"
    fi
    continue
  fi

  if [[ $worktree_drift == 1 ]]; then
    echo "link: $path (config=$([[ $config_ok == 1 ]] && echo shared || echo elsewhere), target=$target_state, upstream missing=${upstream_missing[*]:-none})"
    ferrox_write_cargo_config "$path" "$shared"
    ferrox_link_upstream "$path" "$top" >/dev/null
  fi

  # The main checkout keeps the seed; it is the one build that refreshes the
  # tree every clone starts from.
  if [[ "$path" == "$here" || $claim_all == 1 ]] &&
      ! ferrox_target_is_own "$path" &&
      [[ "$(git -C "$path" rev-parse --git-dir)" != "$(git -C "$path" rev-parse --git-common-dir)" ]]; then
    ferrox_claim_target "$path" "$shared"
    target_state="own"
  fi

  [[ $worktree_drift == 1 || $target_state == "missing" ]] || echo "ok: $path (target=$target_state)"
done < <(git worktree list --porcelain | sed -n 's/^worktree //p')

if [[ $check_only == 1 ]]; then
  if [[ $drift != 0 || $unclaimed != 0 ]]; then
    [[ $drift == 0 ]] || echo "::error::$drift worktree(s) drifted; run ./scripts/link-shared-target.sh" >&2
    [[ $unclaimed == 0 ]] || echo "::error::$unclaimed worktree(s) still build on the seed; run ./scripts/link-shared-target.sh --all" >&2
    exit 1
  fi
  echo "every worktree shares the config and upstream links and owns its target; seed is $shared"
  exit 0
fi
echo "seed: $shared"
