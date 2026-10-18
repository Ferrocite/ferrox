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
# No override: a per-slice target dir defeats the point, which is that the
# dependencies are compiled once for every branch.
shared="$(ferrox_shared_target)"
ferrox_require_shared_writable "$shared"

if [[ -e "$dest" ]]; then
  echo "::error::$dest already exists" >&2
  exit 1
fi

git -C "$top" worktree add "$dest" -b "$name" "$base"

ferrox_write_cargo_config "$dest" "$shared"
ferrox_link_target "$dest" "$shared"

linked=0
for checkout in "$top"/upstream/*/; do
  checkout="${checkout%/}"
  base_name="$(basename "$checkout")"
  if [[ -d "$checkout/.git" && ! -e "$dest/upstream/$base_name" ]]; then
    ln -s "$checkout" "$dest/upstream/$base_name"
    linked=$((linked + 1))
  fi
done

echo "worktree: $dest (branch $name)"
echo "target-dir: $shared"
echo "upstream checkouts linked: $linked"
echo "next: ./scripts/fetch-upstream.sh (only what the links missed), then ./scripts/check.sh"
