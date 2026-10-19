#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: fetch-upstream.sh [--only name[,name...]] [--selftest]" >&2
  exit 2
}

only_list=""
selftest=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) [[ $# -ge 2 ]] || usage; only_list="$2"; shift 2 ;;
    --selftest) selftest=1; shift ;;
    -h | --help) usage ;;
    *) echo "::error::unknown argument $1" >&2; usage ;;
  esac
done

pins_file="upstream/pins.toml"
manifest="upstream/manifest.toml"

# One line per [sources.*] entry: name, repo, rev, the first name pinning the same
# repo at the same rev, and the fallback. Two pins on one commit are two identities
# to read and one checkout to hold, so the first owns the clone and the rest link.
parse_pins() {
  awk '
    function emit() {
      if (name == "") return
      key = repo SUBSEP rev
      if (!(key in first)) first[key] = name
      print name "\t" repo "\t" rev "\t" first[key] "\t" fallback
      name = ""
    }
    /^\[sources\./ {
      emit()
      name = $0
      sub(/^\[sources\./, "", name)
      sub(/\]$/, "", name)
      repo = ""; rev = ""; fallback = ""
      next
    }
    /^repo[[:space:]]*=/ {
      repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next
    }
    /^fallback_repo[[:space:]]*=/ {
      fallback = $0; sub(/^[^=]*=[[:space:]]*"/, "", fallback); sub(/"[[:space:]]*$/, "", fallback); next
    }
    /^rev[[:space:]]*=/ {
      rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next
    }
    /^$/ { emit() }
    END { emit() }
  ' "$1"
}

tmp="$(mktemp -d)"
root=""
manifest_tmp=""
trap 'rm -rf "$tmp"; rm -f "$manifest_tmp"; [[ -z "$root" ]] || rm -rf "$root"' EXIT

fetch_one() {
  local name="$1" repo="$2" rev="$3" fallback="$4"
  local log="$tmp/$name.log" verdict="$tmp/$name.verdict"
  {
    if [[ -z "$repo" || -z "$rev" ]]; then
      echo "::error::$name is missing repo or rev; pin it before fetching"
      echo BAD >"$verdict"
      return 1
    fi

    local dir="upstream/$name" fetched_from
    fetched_from="cached (already at pin)"
    if [[ -d "$dir/.git" && ! -L "$dir" ]] && [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$rev" ]]; then
      echo "ok: $name already at $rev"
    else
      rm -rf "$dir"
      git init --quiet "$dir"
      fetched_from=""
      local candidate
      for candidate in "$repo" "$fallback"; do
        [[ -n "$candidate" ]] || continue
        git -C "$dir" remote add origin "$candidate" 2>/dev/null || git -C "$dir" remote set-url origin "$candidate"
        if git -C "$dir" fetch --quiet --no-tags --depth 1 origin "$rev"; then
          fetched_from="$candidate"
          break
        fi
      done
      if [[ -z "$fetched_from" ]]; then
        echo "::error::$name rev $rev resolves nowhere (tried primary and fallback)"
        echo BAD >"$verdict"
        return 1
      fi
      git -C "$dir" checkout --quiet FETCH_HEAD
      echo "fetched: $name at $rev from $fetched_from"
    fi

    local head
    head="$(git -C "$dir" rev-parse HEAD)"
    if [[ "$head" != "$rev" ]]; then
      echo "::error::$name holds $head, not its pin $rev"
      echo BAD >"$verdict"
      return 1
    fi

    {
      echo ""
      echo "[checkout.$name]"
      echo "repo = \"$repo\""
      echo "rev  = \"$rev\""
      echo "fetched_from = \"$fetched_from\""
    } >"$tmp/$name.stanza"
    echo GOOD >"$verdict"
  } >"$log" 2>&1
}

# The alias reads the primary's checkout instead of cloning the same commit twice.
link_one() {
  local name="$1" repo="$2" rev="$3" primary="$4"
  local log="$tmp/$name.log" verdict="$tmp/$name.verdict"
  {
    local dir="upstream/$name" pdir="upstream/$primary"
    if [[ ! -d "$pdir/.git" ]]; then
      echo "::error::$name shares $primary, whose checkout is not in place at $rev"
      echo BAD >"$verdict"
      return 1
    fi

    if [[ -L "$dir" && "$(readlink "$dir")" == "$primary" ]]; then
      echo "ok: $name shares $pdir"
    else
      if [[ -e "$dir" && ! -L "$dir" ]]; then
        if [[ ! -d "$dir/.git" ]]; then
          echo "::error::$name is a directory that is not a pinned checkout; leaving it alone"
          echo BAD >"$verdict"
          return 1
        fi
        if [[ -n "$(git -C "$dir" status --porcelain 2>/dev/null)" ]]; then
          echo "::error::$name holds uncommitted reading notes; sharing it would discard them"
          echo BAD >"$verdict"
          return 1
        fi
        echo "collapsed: $name was a second clone of $repo at ${rev:0:12}"
      fi
      rm -rf "$dir"
      ln -s "$primary" "$dir"
      echo "linked: $name -> $pdir"
    fi

    local head
    head="$(git -C "$dir" rev-parse HEAD 2>/dev/null)"
    if [[ "$head" != "$rev" ]]; then
      echo "::error::$name reaches ${head:-nothing} through $primary, not its pin $rev"
      echo BAD >"$verdict"
      return 1
    fi

    {
      echo ""
      echo "[checkout.$name]"
      echo "repo = \"$repo\""
      echo "rev  = \"$rev\""
      echo "shares = \"$primary\""
    } >"$tmp/$name.stanza"
    echo GOOD >"$verdict"
  } >"$log" 2>&1
}

primary_fallback() {
  awk -F'\t' -v n="$1" '$1 == n { print $5; exit }' <<<"$plan"
}

run_all() {
  plan="$(parse_pins "$pins_file")"
  if [[ -z "$plan" ]]; then
    echo "::error::no [sources.*] entries parsed from $pins_file"
    return 1
  fi

  manifest_tmp="$manifest.part"
  {
    echo "# Derived artifact. Do not edit: rerun scripts/fetch-upstream.sh."
    echo "# Each entry is the exact commit the named checkout holds."
    echo "# A shares field names the checkout this pin reads instead of its own clone."
  } >"$manifest_tmp"

  local cores reclaim
  cores="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
  [[ "$cores" =~ ^[0-9]+$ && "$cores" -ge 1 ]] || cores=4
  reclaim="wait"
  if help wait 2>/dev/null | grep -q -- '-n'; then
    reclaim="wait -n"
  fi

  local name repo rev fallback primary
  local selected="" running=0
  while IFS=$'\t' read -r name repo rev primary fallback; do
    [[ -n "$name" ]] || continue
    if [[ -n "$only_list" ]] && [[ ",$only_list," != *",$name,"* ]]; then
      continue
    fi
    selected="$selected $name"
    if [[ "$name" != "$primary" ]]; then
      continue
    fi
    fetch_one "$name" "$repo" "$rev" "$fallback" &
    running=$((running + 1))
    if [[ "$running" -ge "$cores" ]]; then
      $reclaim 2>/dev/null || wait
      running=$((running - 1))
    fi
  done <<<"$plan"
  wait

  # An alias whose primary this run never named still owes the one checkout:
  # fetch the primary on its behalf, then link. Never a second clone of one commit.
  while IFS=$'\t' read -r name repo rev primary fallback; do
    [[ -n "$name" ]] || continue
    if [[ -n "$only_list" ]] && [[ ",$only_list," != *",$name,"* ]]; then
      continue
    fi
    [[ "$name" != "$primary" ]] || continue
    if [[ ! -d "upstream/$primary/.git" ]] || [[ -L "upstream/$primary" ]] ||
      [[ "$(git -C "upstream/$primary" rev-parse HEAD 2>/dev/null)" != "$rev" ]]; then
      case " $selected " in
        *" $primary "*) ;;
        *)
          selected="$selected $primary"
          fetch_one "$primary" "$repo" "$rev" "$(primary_fallback "$primary")"
          ;;
      esac
    fi
    link_one "$name" "$repo" "$rev" "$primary"
  done <<<"$plan"

  local fetched=0 status=0
  for name in $selected; do
    [[ -f "$tmp/$name.log" ]] && cat "$tmp/$name.log"
    if [[ ! -f "$tmp/$name.verdict" || "$(cat "$tmp/$name.verdict")" != "GOOD" ]]; then
      echo "::error::$name was not fetched; see above"
      status=1
      continue
    fi
    cat "$tmp/$name.stanza" >>"$manifest_tmp"
    fetched=$((fetched + 1))
  done

  if [[ "$fetched" -eq 0 ]]; then
    echo "::error::fetched nothing; refusing to write a manifest that reads as a complete account"
    return 1
  fi

  mv "$manifest_tmp" "$manifest"
  echo "fetched $fetched pinned upstream source(s); manifest in $manifest"
  return "$status"
}

# Three pins, two source commits, one local repo: no network and no runner needed,
# so the sharing rule is checked wherever this script is.
selftest() {
  local src rev rev2 notes=""
  root="$(mktemp -d)"
  src="$root/reference"
  git init --quiet "$src"
  git -C "$src" config user.email selftest@ferrox.invalid
  git -C "$src" config user.name selftest
  git -C "$src" config uploadpack.allowAnySHA1InWant true
  echo one >"$src/file.txt"
  git -C "$src" add file.txt
  git -C "$src" commit --quiet -m one
  rev="$(git -C "$src" rev-parse HEAD)"
  echo two >"$src/file.txt"
  git -C "$src" commit --quiet -am two
  rev2="$(git -C "$src" rev-parse HEAD)"

  mkdir -p "$root/upstream"
  cat >"$root/upstream/pins.toml" <<EOF
[sources.alpha]
repo = "$src"
rev  = "$rev"

[sources.beta]
repo = "$src"
rev  = "$rev"

[sources.gamma]
repo = "$src"
rev  = "$rev2"
EOF

  cd "$root"
  pins_file="upstream/pins.toml"
  manifest="upstream/manifest.toml"

  run_all || notes="$notes the shared run exited red;"
  [[ -d upstream/alpha/.git && ! -L upstream/alpha ]] ||
    notes="$notes alpha does not hold the real checkout;"
  [[ -L upstream/beta && "$(readlink upstream/beta)" == alpha ]] ||
    notes="$notes beta is its own clone of a commit alpha already holds;"
  [[ "$(git -C upstream/beta rev-parse HEAD)" == "$rev" ]] ||
    notes="$notes beta does not read alpha's checkout at its pin;"
  [[ "$(git -C upstream/gamma rev-parse HEAD)" == "$rev2" ]] ||
    notes="$notes gamma shares a checkout of a commit it is not pinned to;"
  local shares
  shares="$(grep -c '^shares' upstream/manifest.toml || true)"
  [[ "$shares" == "1" ]] || notes="$notes the manifest accounts for $shares shared checkout(s), not 1;"

  # Rerunning over the tree it just made must not re-clone or re-link.
  run_all || notes="$notes the rerun exited red;"
  [[ -L upstream/beta && -d upstream/alpha/.git && ! -L upstream/alpha ]] ||
    notes="$notes the rerun undid the sharing;"

  # A run naming only the alias owes both stanzas: the link has to have something to read.
  rm -rf upstream/alpha upstream/beta upstream/gamma upstream/manifest.toml
  only_list=beta
  run_all || notes="$notes an alias-only run exited red;"
  only_list=""
  [[ -L upstream/beta && -d upstream/alpha/.git ]] ||
    notes="$notes an alias-only run left the link with no checkout to read;"
  local stanzas
  stanzas="$(grep -c '^\[checkout\.' upstream/manifest.toml || true)"
  [[ "$stanzas" == "2" ]] || notes="$notes an alias-only run recorded $stanzas checkouts, not 2;"

  rm -rf "$root"
  if [[ -n "$notes" ]]; then
    echo "::error::self-test: $notes"
    return 1
  fi
  echo "ok: self-test — one checkout per repo and rev, aliases link, a pin at another rev clones"
}

if [[ "$selftest" -eq 1 ]]; then
  selftest
  exit $?
fi

if [[ ! -f "$pins_file" ]]; then
  echo "::error::$pins_file is missing; nothing to fetch"
  exit 1
fi

run_all
exit $?
