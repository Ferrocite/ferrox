#!/usr/bin/env bash

note() { echo "note: $*" >&2; }
fail() { echo "::error::$*" >&2; exit 1; }

pin_of() {
  awk -v want="$1" '
    /^\[sources\./ { in_source = ($0 == "[sources." want "]") }
    in_source && /^rev[[:space:]]*=/ {
      gsub(/^rev[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "")
      print; exit
    }
  ' "$pins_file"
}

verify_checkout() {
  local name="$1" rev
  rev="$(pin_of "$name")"
  [[ -n "$rev" ]] || fail "no rev for $name in $pins_file"
  # Never let git walk up to the ferrox tree itself: a missing .git must read
  # as missing, not as the parent checkout's HEAD.
  if [[ ! -d "upstream/$name/.git" ]]; then
    fail "upstream/$name is missing; run scripts/fetch-upstream.sh"
  fi
  local have
  have="$(GIT_CEILING_DIRECTORIES="$PWD" git -C "upstream/$name" rev-parse HEAD 2>/dev/null)" || \
    fail "upstream/$name has no readable HEAD; re-run scripts/fetch-upstream.sh"
  [[ "$have" == "$rev" ]] || fail "upstream/$name is at $have, not the pinned $rev"
}

exe_suffix() {
  case "${OS:-}" in
    Windows_NT) printf '.exe' ;;
    *) printf '' ;;
  esac
}

built() {
  # `download-artifact` records the mode in its zip and restores 0644, so a
  # binary handed over from the build job arrives non-executable and would be
  # refused for the one thing `--no-build` needs it for. Put the bit back
  # before judging, or the cells job fails on a binary it was given.
  local path
  for path in "$1$(exe_suffix)" "$1"; do
    if [[ -f "$path" ]]; then
      chmod +x "$path" 2>/dev/null || true
    fi
    if [[ -x "$path" ]]; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}

build() {
  local name="$1" rev binary cached
  rev="$(pin_of "$name")"
  binary="$engine_dir/$name$(exe_suffix)"
  if cached="$(built "$binary")"; then
    echo "$cached"
    return 0
  fi
  # The artifact lane hands checkouts between jobs, and a checkout that did
  # not survive the handoff is re-fetched at its pin here, never guessed: the
  # subshell keeps verify_checkout's exit from ending the whole matrix run.
  if ! (verify_checkout "$name" 2>/dev/null); then
    note "re-fetching $name at its pin; the handoff did not carry it"
    ./scripts/fetch-upstream.sh --only "$name" >&2 || return 1
    verify_checkout "$name" || return 1
  fi
  case "$name" in
    xray-core)
      note "building the pinned Xray-core at $rev"
      (cd "upstream/$name" && GOENV=off GOWORK=off CGO_ENABLED=0 \
        go build -o "$OLDPWD/$binary" ./main) || return 1
      ;;
    sing-box)
      note "building the pinned sing-box at $rev"
      (cd "upstream/$name" && GOENV=off GOWORK=off CGO_ENABLED=0 \
        go build -tags "with_utls" -o "$OLDPWD/$binary" ./cmd/sing-box) || return 1
      ;;
    zeronet)
      note "building the pinned ZeroNet (zray) at $rev"
      (cd "upstream/$name" && cargo build --release -p zray-cli --bin zray) || return 1
      local zray
      zray="$(built "upstream/$name/target/release/zray")" || return 1
      cp "$zray" "$binary" || return 1
      ;;
    xray-rust)
      note "building the pinned xray-rust at $rev (long: aws-lc-rs, quinn, prost)"
      (cd "upstream/$name" && CARGO_TARGET_DIR="$OLDPWD/$engine_dir/xray-rust-target" \
        cargo build --release -p xray-cli --bin xray-rust) || return 1
      local rust_cli
      rust_cli="$(built "$engine_dir/xray-rust-target/release/xray-rust")" || return 1
      cp "$rust_cli" "$binary" || return 1
      ;;
    *)
      fail "unknown engine source `$name`"
      ;;
  esac
  built "$binary"
}

config_arg_for() {
  case "$1" in
    sing-box) echo short ;;
    zeronet) echo positional ;;
    *) echo long ;;
  esac
}

dialect_for() {
  case "$1" in
    sing-box) echo sing-box ;;
    *) echo xray ;;
  esac
}
