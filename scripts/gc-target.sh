#!/usr/bin/env bash
# Reclaim what warm build trees accumulate but Cargo never revisits: incremental
# sessions of worktrees nobody has touched, per-worktree dirs moved aside by a
# repair, and target forges left under $TMPDIR with no worktree around them.
# Dry run unless --apply is passed, so the size is known before anything goes.
#
#   ./scripts/gc-target.sh                          show what would go
#   ./scripts/gc-target.sh --apply                  reclaim it
#   ./scripts/gc-target.sh --older-than 12 --apply
#   ./scripts/gc-target.sh --reset-idle 14 --apply  drop clones idle 14 days
set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck source=scripts/lib-shared-target.sh
source scripts/lib-shared-target.sh
shared="$(ferrox_shared_target)"
apply=0
hours=48
reset_days=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    --older-than) hours="${2:?--older-than wants hours}"; shift 2 ;;
    --reset-idle) reset_days="${2:?--reset-idle wants days}"; shift 2 ;;
    *) echo "usage: scripts/gc-target.sh [--dry-run|--apply] [--older-than HOURS] [--reset-idle DAYS]" >&2; exit 2 ;;
  esac
done
[[ "$hours" =~ ^[0-9]+$ ]] || { echo "--older-than wants whole hours" >&2; exit 2; }
[[ "$reset_days" =~ ^[0-9]+$ ]] || { echo "--reset-idle wants whole days" >&2; exit 2; }
minutes=$((hours * 60))
idle_minutes=$((reset_days * 1440))

top="$(git rev-parse --show-toplevel)"
tmp="${TMPDIR:-/tmp}"
tmp="${tmp%/}"

size_of() { du -sh "$1" 2>/dev/null | cut -f1; }
reclaim() {
  local path="$1" size
  size="$(size_of "$path")"
  printf '%s %s\n' "$([[ $apply == 1 ]] && echo remove || echo would-remove)" "$path ($size)"
  if [[ $apply == 1 ]]; then
    chmod -R u+w "$path" 2>/dev/null || true
    rm -rf "$path"
  fi
}

total() { du -sk "$1" 2>/dev/null | cut -f1; }
before=0
if [[ -d "$shared" ]]; then
  before="$(total "$shared")"
fi

# A session names the source paths it was built from, so a clone never hits the
# seed's sessions and an idle worktree's sessions only grow. Age is the witness:
# a build that is running has just touched its session.
prune_sessions() {
  local root="$1" session
  if [[ ! -d "$root" ]]; then
    return 0
  fi
  while IFS= read -r session; do
    if [[ -n "$session" ]]; then
      reclaim "$session"
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -mmin "+$minutes" 2>/dev/null)
}

for dir in "$shared"/*/incremental; do
  if [[ -d "$dir" ]]; then
    prune_sessions "$dir"
  fi
done

worktrees="$(git worktree list --porcelain | sed -n 's/^worktree //p')"
while IFS= read -r path; do
  if [[ ! -d "$path" ]]; then
    continue
  fi
  # A claim that died mid-copy leaves this staging dir, never a half `target`.
  if [[ -d "$path/target.claim" ]]; then
    reclaim "$path/target.claim"
  fi
  for dir in "$path"/target/*/incremental; do
    if [[ -d "$dir" ]]; then
      prune_sessions "$dir"
    fi
  done
  # A clone is cheap to recreate (a copy-on-write pass) and its workspace
  # artefacts are the one part that is not shared with the seed. An idle tree is
  # dropped; the next `check.sh` claims a fresh one.
  if [[ $reset_days -gt 0 ]] && ferrox_target_is_own "$path"; then
    recent="$(find "$path/target" -type f -mmin "-$idle_minutes" -print -quit 2>/dev/null)"
    if [[ -z "$recent" ]]; then
      reclaim "$path/target"
    fi
  fi
done <<< "$worktrees"

# A repair moves a real worktree target here rather than deleting it. Nothing
# reads it after the move, so it is only kept as a grace period.
if [[ -d "$shared/aside" ]]; then
  # The directory is sealed so an old checkout cannot park a target here; a
  # reclaim has to open it first, then close it again.
  if [[ $apply == 1 ]]; then
    chmod u+w "$shared/aside" 2>/dev/null || true
  fi
  while IFS= read -r dir; do
    if [[ -n "$dir" ]]; then
      reclaim "$dir"
    fi
  done < <(find "$shared/aside" -mindepth 1 -maxdepth 1 -type d -mmin "+$minutes" 2>/dev/null)
  if [[ $apply == 1 ]]; then
    chmod 555 "$shared/aside" 2>/dev/null || true
  fi
fi

# A stale forge is a target dir under the temp tree with no worktree around it.
# The named owner is gone; the bytes are a cold rebuild waiting to be paid again.
if [[ -d "$tmp" ]]; then
  while IFS= read -r dir; do
    if [[ -z "$dir" ]]; then
      continue
    fi
    case "$dir" in
      "$top"/*) continue ;;
    esac
    reclaim "$dir"
  done < <(find "$tmp" -maxdepth 3 -type d -name 'ferrox-*target*' -mmin "+$minutes" 2>/dev/null)
fi

if [[ $apply == 1 && -d "$shared" ]]; then
  after="$(total "$shared")"
  echo "seed: $((before / 1024)) MiB -> $((after / 1024)) MiB"
else
  echo "dry run: pass --apply to reclaim; seed is $((before / 1024)) MiB"
fi
