#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

markers='TODO|FIXME|HACK|(^|[^A-Za-z0-9_])XXX([^A-Za-z0-9_]|$)'

selftest="$(mktemp -d)"
printf '%s\n' 'tmp="$(mktemp -d prefix.XXXXXX)"' > "$selftest/template.sh"
printf '%s\n' '// TODO: trace left behind' '// XXX: trace left behind' > "$selftest/marker.rs"
if grep -E -q "$markers" "$selftest/template.sh"; then
  echo "::error::self-test: the marker grep flags an mktemp template"
  status=1
fi
if ! grep -E -q "$markers" "$selftest/marker.rs"; then
  echo "::error::self-test: the marker grep misses a real marker"
  status=1
fi
rm -rf "$selftest"

if git grep -I -n -E "$markers" -- '*.rs' 'scripts/*' '.github/**/*' ':!scripts/check-comments.sh'; then
  echo "::error::trace markers do not land in this tree; the roadmap lives in prompts.md"
  status=1
fi

if git grep -I -n -E '^[[:space:]]*/\*' -- '*.rs'; then
  echo "::error::no /* */ blocks; docs are /// and //!, one line per item at most"
  status=1
fi

runs="$(git ls-files '*.rs' | while IFS= read -r file; do
  longest="$(awk '/^[[:space:]]*\/\/[^!\/]/ {n++; if (n>m) m=n} !/^[[:space:]]*\/\/[^!\/]/ {n=0} END {print m+0}' "$file")"
  if [[ "$longest" -gt 1 ]]; then
    printf '%s: %s line run\n' "$file" "$longest"
  fi
done)"
if [[ -n "$runs" ]]; then
  printf '%s\n' "$runs"
  echo "::error::one line of // comment per item, at most; fold the run or delete it"
  status=1
fi

exit "$status"
