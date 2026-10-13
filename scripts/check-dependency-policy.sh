#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

note() { printf '::error::%s\n' "$1"; status=1; }

allow_list="$(sed -n '/^\[licenses\]/,/^\[/p' deny.toml | sed -n 's/^  "\(.*\)",\{0,1\}$/\1/p')"

if [[ -z "$allow_list" ]]; then
  note "deny.toml's [licenses].allow is empty or unreadable, so this check would pass on nothing"
fi

metadata=""
if metadata="$(cargo metadata --offline --format-version 1 --all-features 2>/dev/null)"; then
  :
elif metadata="$(cargo metadata --format-version 1 --all-features 2>/dev/null)"; then
  :
else
  note "cargo metadata could not read the graph, so no licence was checked; run \`cargo fetch\` and try again"
  metadata=""
fi

if [[ -n "$metadata" ]]; then
  expressions="$(printf '%s' "$metadata" | python3 -c '
import json, sys
graph = json.load(sys.stdin)
print("\n".join(sorted({p.get("license", "") for p in graph["packages"] if p.get("license")})))
')"
  while read -r expression; do
    [[ -z "$expression" ]] && continue
    normalised="$(printf '%s' "$expression" | tr -d '()' | tr 'A-Z' 'a-z' | tr '/' ' ')"
    IFS=', ' read -r -a parts <<<"$normalised"
    for part in "${parts[@]}"; do
      [[ -z "$part" || "$part" == "or" || "$part" == "and" ]] && continue
      if [[ "$part" == "with" || "$part" == *-exception || "$part" == exception-* ]]; then
        continue
      fi
      if ! grep -qixF "$part" <<<"$allow_list"; then
        note "the graph carries \`$expression\`, which needs \`$part\`; deny.toml's allow list does not name it"
      fi
    done
  done <<<"$expressions"
fi

if grep -E '^source = "git\+' Cargo.lock >/dev/null; then
  grep -E '^source = "git\+' Cargo.lock | sort -u | while read -r _ line; do
    note "$line is not crates.io; deny.toml's [sources] allows no git source"
  done || true
  status=1
fi

for banned in sing-box v2ray-rust; do
  hits="$(grep -rnE "^[[:space:]]*${banned}[[:space:]]*=" --include='Cargo.toml' crates Cargo.toml 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    note "\`${banned}\` is a comparator, read at its pin under upstream/ and never a dependency"
    printf '%s\n' "$hits"
  fi
done

exit "$status"
