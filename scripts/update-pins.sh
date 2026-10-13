#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

pins_file="upstream/pins.toml"
open_pr=0
[[ "${1:-}" == "--pr" ]] && open_pr=1

if [[ ! -f "$pins_file" ]]; then
  echo "::error::$pins_file not found"
  exit 1
fi

entries=()
while IFS= read -r line; do
  [[ -n "$line" ]] && entries+=("$line")
done < <(awk '
  /^\[sources\./ { name = $0; sub(/^\[sources\./, "", name); sub(/\]$/, "", name); repo=""; branch=""; next }
  /^repo[[:space:]]*=/ { repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next }
  /^default_branch[[:space:]]*=/ { branch = $0; sub(/^[^=]*=[[:space:]]*"/, "", branch); sub(/"[[:space:]]*$/, "", branch); next }
  /^$/ { if (name != "") print name "\t" repo "\t" branch; name = "" }
  END { if (name != "") print name "\t" repo "\t" branch }
' "$pins_file")

if [[ "${#entries[@]}" -eq 0 ]]; then
  echo "::error::parsed no [sources.*] entries from $pins_file"
  exit 1
fi

changed=0
for entry in "${entries[@]}"; do
  IFS=$'\t' read -r name repo branch <<< "$entry"

  if [[ -z "$branch" ]]; then
    echo "::warning::$name has no default_branch; leaving it alone"
    continue
  fi

  tip="$(git ls-remote "$repo" "refs/heads/$branch" 2>/dev/null | cut -f1 || true)"
  if [[ -z "$tip" ]]; then
    echo "::warning::$name: could not read refs/heads/$branch from $repo; leaving it alone"
    continue
  fi

  old="$(awk -v want="$name" '
    /^\[sources\./ { cur = $0; sub(/^\[sources\./, "", cur); sub(/\]$/, "", cur) }
    cur == want && /^rev[[:space:]]*=/ { v = $0; sub(/^[^=]*=[[:space:]]*"/, "", v); sub(/"[[:space:]]*$/, "", v); print v; exit }
  ' "$pins_file")"

  if [[ "$old" == "$tip" ]]; then
    echo "unchanged: $name $tip"
    continue
  fi

  echo "bump: $name ${old:-<none>} -> $tip"

  awk -v want="$name" -v tip="$tip" '
    /^\[sources\./ { cur = $0; sub(/^\[sources\./, "", cur); sub(/\]$/, "", cur) }
    cur == want && /^rev[[:space:]]*=/ && !done { print "rev           = \"" tip "\""; done = 1; next }
    { print }
  ' "$pins_file" > "$pins_file.tmp"
  mv "$pins_file.tmp" "$pins_file"
  changed=$((changed + 1))
done

if [[ "$changed" -eq 0 ]]; then
  echo "all pins already current"
  exit 0
fi

echo
git --no-pager diff -- "$pins_file"

if ! git diff --quiet -- "$pins_file"; then
  echo
  echo "Pins changed. The benchmark table must be regenerated on this commit before"
  echo "any number produced against the new pins is quoted."
fi

if [[ "$open_pr" -eq 1 ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "::error::--pr given but gh is not installed; the change is left unstaged"
    exit 1
  fi
  git checkout -b "chore/pins-$(date -u +%Y%m%d)"
  git add "$pins_file"
  git commit -q -m "chore(upstream): refresh pinned commits

Changes what every comparison in this project is measured against, so it is
kept reviewable on its own. Regenerate the benchmark table on this commit
before quoting any number that depends on it."
  git push -q --set-upstream origin HEAD
  gh pr create --fill --title "chore(upstream): refresh pinned commits" \
    --body "Automated by scripts/update-pins.sh. Regenerates the benchmark table; see upstream/pins.toml."
fi