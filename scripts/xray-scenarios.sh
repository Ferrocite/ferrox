#!/usr/bin/env bash
# xray-core's scenario suite builds a binary of its own at run time
# (testing/scenarios BuildXray) and spawns it with `-config=stdin: -format=pb`.
# The go the suite's build runs under belongs to the toolchain and puts its own
# bin dir first on PATH for children, so a PATH shim cannot answer that build;
# go's -overlay can: the pin's main package is built with main.go replaced by a
# launcher that execs FERROX_BINARY, which is what the suite then spawns. The
# launcher touches the marker on the way, and a suite that never ran it is
# refused, so a green result always means the suite ran against Ferrox.
set -euo pipefail

self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

selftest() {
  local fake stub suite verdict failures=0
  fake="$(mktemp -d)"
  mkdir -p "$fake/main"
  printf 'module xray-scenarios-selftest\n\ngo 1.21\n' >"$fake/go.mod"
  printf 'package main\n\nfunc main() { panic("the harness must have replaced this file") }\n' >"$fake/main/main.go"
  stub="$(mktemp)"
  printf '#!/usr/bin/env bash\necho ferrox-stub\n' >"$stub"
  chmod +x "$stub"
  for shape in spawns:0 silent:1; do
    case "${shape%%:*}" in
      spawns) suite="tmp=\$(mktemp -d); go build -o=\$tmp/x ./main && test \"\$(\$tmp/x)\" = ferrox-stub" ;;
      silent) suite="true" ;;
    esac
    verdict=0
    (cd "$fake" && FERROX_BINARY="$stub" bash "$self" "$suite") >/dev/null 2>&1 || verdict=$?
    if [[ "$verdict" -ne "${shape##*:}" ]]; then
      echo "::error::xray-scenarios self-test: ${shape%%:*} is answered $verdict; it must be ${shape##*:}"
      failures=1
    fi
  done
  rm -rf "$fake" "$stub"
  return "$failures"
}

if [[ "${1:-}" == "--selftest" ]]; then
  if selftest; then
    exit 0
  fi
  exit 1
fi

if [[ $# -ne 1 ]]; then
  echo "::error::xray-scenarios: one argument, the suite command"
  exit 1
fi
suite="$1"
binary="${FERROX_BINARY:-}"
if [[ -z "$binary" || ! -x "$binary" ]]; then
  echo "::error::xray-scenarios: FERROX_BINARY must name an executable (got '${binary:-unset}')"
  exit 1
fi

main_file=""
for candidate in main/*.go; do
  if [[ -f "$candidate" ]] && grep -q '^func main(' "$candidate"; then
    main_file="$candidate"
    break
  fi
done
if [[ -z "$main_file" ]]; then
  echo "::error::xray-scenarios: no func main in $(pwd)/main; run from the pinned xray-core checkout"
  exit 1
fi

work="$(mktemp -d)"
marker="$work/built"
trap 'rm -rf "$work"' EXIT

cat >"$work/launcher.go" <<GO
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	binary := os.Getenv("FERROX_BINARY")
	if binary == "" {
		fmt.Fprintln(os.Stderr, "xray-scenarios: FERROX_BINARY is not set")
		os.Exit(1)
	}
	if err := os.WriteFile("$marker", nil, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "xray-scenarios:", err)
		os.Exit(1)
	}
	if err := syscall.Exec(binary, append([]string{binary}, os.Args[1:]...), os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "xray-scenarios: cannot exec", binary, err)
		os.Exit(1)
	}
}
GO

cat >"$work/overlay.json" <<JSON
{"Replace": {"$PWD/$main_file": "$work/launcher.go"}}
JSON

export GOFLAGS="-overlay=$work/overlay.json${GOFLAGS:+ $GOFLAGS}"
status=0
bash -c "$suite" || status=$?
if [[ ! -e "$marker" ]]; then
  echo "::error::xray-scenarios: the suite never ran what its own build produced, so nothing ran against Ferrox"
  exit 1
fi
exit "$status"
