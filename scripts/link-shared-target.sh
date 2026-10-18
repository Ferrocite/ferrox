#!/usr/bin/env bash
# Point every worktree that exists right now at the one shared target dir, and
# report what moved. Idempotent: a worktree already correct is one line of output.
#
#   ./scripts/link-shared-target.sh          repair
#   ./scripts/link-shared-target.sh --check  exit 1 on drift, touch nothing
set -euo pipefail

# shellcheck source=scripts/lib-shared-target.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-shared-target.sh"
shared="$(ferrox_shared_target)"
check_only=0
case "${1:-}" in
  "") ;;
  --check) check_only=1 ;;
  *) echo "usage: scripts/link-shared-target.sh [--check]" >&2; exit 2 ;;
esac
ferrox_require_shared_writable "$shared"

# `git worktree list` is the only list of the branches that exist; a pointer
# written by hand before this script landed is invisible otherwise.
drift=0
while IFS= read -r path; do
  [[ -d $path ]] || continue

  current_dir=""
  [[ -f $path/.cargo/config.toml ]] &&
    current_dir="$(sed -n 's/^target-dir *= *"\(.*\)"$/\1/p' "$path/.cargo/config.toml" | head -1)"

  if [[ $current_dir == "$shared" && "$path/target" -ef "$shared" ]]; then
    echo "ok: $path"
    continue
  fi
  drift=$((drift + 1))
  if [[ $check_only == 1 ]]; then
    echo "drift: $path (target-dir=${current_dir:-none}, target=$(readlink "$path/target" 2>/dev/null || echo "$path/target"))"
    continue
  fi

  echo "link: $path (was target-dir=${current_dir:-none}, target=$(readlink "$path/target" 2>/dev/null || echo "a real directory"))"
  ferrox_write_cargo_config "$path" "$shared"
  ferrox_link_target "$path" "$shared"
done < <(git worktree list --porcelain | sed -n 's/^worktree //p')

if [[ $drift == 0 ]]; then
  echo "every worktree builds into $shared"
  exit 0
fi
if [[ $check_only == 1 ]]; then
  echo "::error::$drift worktree(s) point elsewhere; run ./scripts/link-shared-target.sh" >&2
  exit 1
fi
echo "$drift worktree(s) now build into $shared"
