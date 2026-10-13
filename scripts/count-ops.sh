#!/usr/bin/env bash
set -euo pipefail

mode="${1:?usage: count-ops.sh report|check ...}"
command -v valgrind >/dev/null || { echo "count-ops: valgrind not installed (apt-get install valgrind strace / brew install valgrind)" >&2; exit 2; }

outdir="$(mktemp -d)"
trap 'rm -rf "$outdir"' EXIT

bin="$(cargo test --release --bin ferrox-app --no-run --locked --message-format=json \
    | python3 -c 'import json,sys
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("reason") == "compiler-artifact" and m.get("executable"):
        print(m["executable"]); break')"
[ -n "$bin" ] || { echo "count-ops: no test binary built" >&2; exit 2; }

ir_of() {
    local filter="$1" symbol="$2" data="$outdir/callgrind.out"
    rm -f "$data" "$data".*
    local status=0
    valgrind --tool=callgrind --callgrind-out-file="$data" \
        --compress-strings=no --compress-pos=no \
        "$bin" --exact "$filter" --nocapture >"$outdir/valgrind.out" 2>"$outdir/valgrind.err" || status=$?
    if [ "$status" -ne 0 ]; then
        echo "count-ops: valgrind exited $status for $filter" >&2
        tail -n 15 "$outdir/valgrind.err" >&2
        return 2
    fi
    local produced
    produced="$(ls "$data" "$data".* 2>/dev/null | head -n 1)"
    if [ -z "${produced:-}" ]; then
        echo "count-ops: no callgrind output for $filter (valgrind exit $status)" >&2
        tail -n 15 "$outdir/valgrind.err" >&2
        return 2
    fi
    local total
    total="$(python3 - "$produced" "$symbol" <<'EOF'
import sys
total, active = 0, False
with open(sys.argv[1], errors="ignore") as f:
    for line in f:
        line = line.strip()
        if line.startswith("fn="):
            active = sys.argv[2] in line
        elif active:
            fields = line.split()
            if len(fields) >= 2 and fields[0].isdigit() and fields[1].lstrip("-").isdigit():
                total += int(fields[1])
print(total)
EOF
)"
    [ "${total:-0}" != "0" ] || {
        echo "count-ops: symbol not found: $symbol" >&2
        echo "count-ops: positions/events header and quic fn records:" >&2
        grep -E "^(positions|events):" "$produced" >&2 || true
        grep "^fn=.*quic" "$produced" | head -n 10 >&2 || true
        return 2
    }
    echo "$total"
}

syscalls_of() {
    local filter="$1"
    if ! command -v strace >/dev/null; then
        echo "count-ops: strace not installed, skipping syscall table" >&2
        return 0
    fi
    strace -c -f -o "$outdir/strace.out" "$bin" --exact "$filter" --nocapture >/dev/null 2>&1 || true
    sed -n '/^%/,$p' "$outdir/strace.out" | head -n 25
}

if [ "$mode" = "report" ]; then
    filter="$2"
    shift 2
    for symbol in "$@"; do
        echo "$symbol Ir=$(ir_of "$filter" "$symbol")"
    done
    syscalls_of "$filter"
    exit 0
fi

if [ "$mode" = "check" ]; then
    filter="$2"
    expect="$3"
    failed=0
    while read -r symbol want _; do
        case "$symbol" in ''|'#'*) continue ;; esac
        got="$(ir_of "$filter" "$symbol")"
        if [ "$got" != "$want" ]; then
            echo "count-ops: $symbol Ir=$got, expected $want" >&2
            failed=1
        else
            echo "count-ops: $symbol Ir=$got ok"
        fi
    done < "$expect"
    syscalls_of "$filter"
    exit "$failed"
fi

echo "count-ops: unknown mode $mode" >&2
exit 2
