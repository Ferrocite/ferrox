#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
target="${1:?usage: cross-gate.sh <target-triple>}"
name="$(basename "$0")"

die() { printf '%s: %s\n' "$name" "$1" >&2; exit "${2:-2}"; }

command -v rustup >/dev/null || die "rustup is not on PATH"
rustup target list --installed | grep -qx "$target" ||
  die "the $target standard library is missing: run \`rustup target add $target\`"

env_key="$(printf '%s' "$target" | tr -- '-' '_')"
normalised="$env_key"

zig="${ZIG:-}"
if [ -z "$zig" ]; then
  zig="$(command -v zig || true)"
  for candidate in "$HOME"/.local/opt/zig-*/zig "$HOME"/.local/bin/zig /opt/homebrew/bin/zig; do
    [ -x "$candidate" ] && { zig="$candidate"; break; }
  done
fi
[ -n "$zig" ] || die "no \`zig\` found, and \`ring\` will not build for $target without one; set ZIG=/path/to/zig"

case "$target" in
  x86_64-unknown-linux-gnu) zig_target=x86_64-linux-gnu ;;
  x86_64-pc-windows-msvc) zig_target=x86_64-windows-gnu ;;
  *) die "$target has no zig target spelling in this script" ;;
esac

shim="$(mktemp -d)"
trap 'rm -rf "$shim"' EXIT

cat >"$shim/cc" <<SHIM
#!/bin/sh
set -f
count=\$#
i=0
while [ "\$i" -lt "\$count" ]; do
  arg="\$1"; shift
  case "\$arg" in
    --target=$target) i=\$((i + 1)); continue ;;
    -std=c1x) set -- "\$@" -std=c11; i=\$((i + 1)); continue ;;
  esac
  set -- "\$@" "\$arg"
  i=\$((i + 1))
done
exec "$zig" cc -target $zig_target "\$@"
SHIM

cat >"$shim/ar" <<SHIM
#!/bin/sh
out=""
rest=""
seen_archive=0
for arg in "\$@"; do
  case "\$arg" in
    -nologo) ;;
    -out:*) out="\${arg#-out:}" ;;
    c*) ;;   # `cq` and `cr`: the letters, which llvm-ar wants without the `q`.
    *)
      if [ "\$seen_archive" = 0 ] && [ -z "\$out" ]; then
        out="\$arg"
        seen_archive=1
      else
        rest="\$rest \$arg"
      fi
      ;;
  esac
done
[ -n "\$out" ] || { echo "ar: no archive named in: \$*" >&2; exit 2; }
exec "$zig" ar rcs "\$out" \$rest
SHIM
chmod +x "$shim/cc" "$shim/ar"

export "CC_${env_key}=$shim/cc"
export "AR_${env_key}=$shim/ar"
export "CC_$normalised=$shim/cc"
export "AR_$normalised=$shim/ar"

if cargo clippy --workspace --all-targets --locked --target "$target" \
  --target-dir "$root/target/cross-gate" \
  -- -D warnings -W clippy::perf -W clippy::suspicious; then
  echo "$name: $target clean"
else
  status=$?
  echo "$name: $target has findings above" >&2
  exit "$status"
fi
