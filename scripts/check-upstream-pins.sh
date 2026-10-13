#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${CHECK_PINS:-1}" == "0" ]]; then
  echo "note: CHECK_PINS=0, upstream pins not verified"
  exit 0
fi

pins_file="upstream/pins.toml"
if [[ ! -f "$pins_file" ]]; then
  echo "::error::$pins_file is missing; nothing to verify"
  exit 1
fi

parsed="$(awk '
  /^\[sources\./ {
    name = $0
    sub(/^\[sources\./, "", name)
    sub(/\]$/, "", name)
    repo = ""; rev = ""; branch = ""
    next
  }
  /^repo[[:space:]]*=/ {
    repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next
  }
  /^rev[[:space:]]*=/ {
    rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next
  }
  /^default_branch[[:space:]]*=/ {
    branch = $0; sub(/^[^=]*=[[:space:]]*"/, "", branch); sub(/"[[:space:]]*$/, "", branch); next
  }
  /^$/ {
    if (name != "") print name "\t" repo "\t" rev "\t" branch
    name = ""
  }
  END { if (name != "") print name "\t" repo "\t" rev "\t" branch }
' "$pins_file")"

if [[ -z "$parsed" ]]; then
  echo "::error::no [sources.*] entries parsed from $pins_file; the checker is broken, not clean"
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

status=0
checked=0

cores="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
[[ "$cores" =~ ^[0-9]+$ && "$cores" -ge 1 ]] || cores=4
reclaim="wait"
if help wait 2>/dev/null | grep -q -- '-n'; then
  reclaim="wait -n"
fi

check_one() {
  local name="$1" repo="$2" rev="$3" branch="$4"
  local out="$tmp/$name.out" verdict="$tmp/$name.verdict"
  bad() { echo BAD >"$verdict"; return; }
  {
    if [[ -z "$repo" ]]; then
      echo "::error::$name has no repo"
      bad
      return
    fi

    if [[ -z "$rev" ]]; then
      echo "::error::$name ($repo) is not pinned: no rev. A comparison against 'latest' is not a comparison."
      bad
      return
    fi

    if [[ ! "$rev" =~ ^[0-9a-f]{7,40}$ ]]; then
      echo "::error::$name rev '$rev' is not a commit id"
      bad
      return
    fi

    local dir="$tmp/repo-$name"
    if ! git init --quiet --bare "$dir" 2>/dev/null; then
      echo "::error::could not create a scratch repo for $name"
      bad
      return
    fi

    if git -C "$dir" remote add origin "$repo" >/dev/null 2>&1 &&
       git -C "$dir" fetch --quiet --no-tags --depth 1 origin "$rev" >/dev/null 2>&1; then
      echo GOOD >"$verdict"
      echo "ok: $name $rev resolves on $repo"
    else
      echo "::error::$name rev $rev does not resolve on $repo (deleted, force-pushed, or the repo moved)"
      bad
      return
    fi

    if [[ -n "$branch" ]]; then
      local head
      head="$(git ls-remote "$repo" "refs/heads/$branch" 2>/dev/null | cut -f1 || true)"
      if [[ -n "$head" && "$head" != "$rev" ]]; then
        echo "note: $name is pinned behind $branch ($head is the tip); refresh with scripts/update-pins.sh"
      fi
    fi
  } >"$out" 2>&1
}

running=0
while IFS=$'\t' read -r name repo rev branch; do
  [[ -n "$name" ]] || continue
  check_one "$name" "$repo" "$rev" "$branch" &
  running=$((running + 1))
  if [[ "$running" -ge "$cores" ]]; then
    $reclaim 2>/dev/null || wait
    running=$((running - 1))
  fi
done <<<"$parsed"
wait

while IFS=$'\t' read -r name _ _ _; do
  [[ -n "$name" ]] || continue
  out="$tmp/$name.out"
  verdict_file="$tmp/$name.verdict"
  if [[ ! -f "$verdict_file" ]]; then
    echo "::error::$name was not checked; the check for it did not finish"
    [[ -f "$out" ]] && cat "$out"
    status=1
    continue
  fi
  [[ -f "$out" ]] && cat "$out"
  if [[ "$(cat "$verdict_file")" == "GOOD" ]]; then
    checked=$((checked + 1))
  else
    status=1
  fi
done <<<"$parsed"

if [[ "$checked" -eq 0 && "$status" -eq 0 ]]; then
  echo "::error::parsed zero sources from $pins_file; refusing to report success"
  exit 1
fi

echo "verified $checked pinned upstream source(s)"
exit "$status"