#!/usr/bin/env bash
set -euo pipefail

mode="${1:?usage: count-ops.sh report|report-file|check ...}"
command -v valgrind >/dev/null || { echo "count-ops: valgrind not installed (apt-get install valgrind strace / brew install valgrind)" >&2; exit 2; }

outdir="$(mktemp -d)"
trap 'rm -rf "$outdir"' EXIT

test_bin() {
    cargo test --release "$@" --no-run --locked --message-format=json \
        | python3 -c 'import json,sys
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("reason") == "compiler-artifact" and m.get("executable"):
        print(m["executable"]); break'
}

app_bin="$(test_bin --bin ferrox-app)"
core_bin="$(test_bin -p ferrox-core --lib)"
[ -n "$app_bin" ] || { echo "count-ops: no ferrox-app test binary" >&2; exit 2; }
[ -n "$core_bin" ] || { echo "count-ops: no ferrox-core test binary" >&2; exit 2; }

# The filter decides which binary can be profiled, and a `ferrox_core::` method is driven from either crate's tests, so the symbol's own crate is tried first and the other binary is the fallback.
find_bin() {
    local filter="$1" symbol="$2" candidate
    local -a order=("$app_bin" "$core_bin")
    case "$symbol" in
        ferrox_core*) order=("$core_bin" "$app_bin") ;;
    esac
    for candidate in "${order[@]}"; do
        if "$candidate" --exact "$filter" --list 2>/dev/null | grep -q "^$filter: test$"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# Returns the count, or 2 when the measurement broke, 3 when the test ran and the profile holds no frame, 4 when neither test binary has a test by the filter's name.
ir_of() {
    local filter="$1" symbol="$2" data="$outdir/callgrind.out"
    local bin
    # Profiling a binary where the filter matches no test runs zero tests, and then every symbol reads frame-less; the test is confirmed before valgrind is pointed at it.
    bin="$(find_bin "$filter" "$symbol")" || {
        echo "count-ops: no test named $filter in either test binary" >&2
        return 4
    }
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
    # A zero total means no frame was ever active for the symbol, not that the call happened and cost nothing.
    [ "${total:-0}" != "0" ] || {
        echo "count-ops: no frame for symbol: $symbol" >&2
        # A row that holds no frame has to name which of the two opposite faults it is: a frame
        # under another path means the row points at the wrong symbol, a dearer caller means the
        # pass was inlined into it and no gate can price it on its own.
        python3 - "$produced" "$symbol" <<'EOF'
import sys
leaf = sys.argv[2].rsplit("::", 1)[-1]
cost, active = {}, None
with open(sys.argv[1], errors="ignore") as f:
    for line in f:
        line = line.strip()
        if line.startswith("fn="):
            active = line[3:].split(")", 1)[-1]
            cost.setdefault(active, 0)
        elif line.startswith("calls="):
            active = None
        elif active is not None:
            fields = line.split()
            if len(fields) >= 2 and fields[0].isdigit() and fields[1].lstrip("-").isdigit():
                cost[active] += int(fields[1])
named = [n for n in cost if leaf in n]
print("count-ops: frames held: %d, frames naming %s: %s"
      % (len(cost), leaf, ", ".join(named[:5]) or "none"), file=sys.stderr)
for name, own in sorted(cost.items(), key=lambda kv: -kv[1])[:5]:
    print("count-ops: dearest frame %d %s" % (own, name), file=sys.stderr)
EOF
        return 3
    }
    echo "$total"
}

syscalls_of() {
    local filter="$1" bin="$2"
    if ! command -v strace >/dev/null; then
        echo "count-ops: strace not installed, skipping syscall table" >&2
        return 0
    fi
    strace -c -f -o "$outdir/strace.out" "$bin" --exact "$filter" --nocapture >/dev/null 2>&1 || true
    sed -n '/^%/,$p' "$outdir/strace.out" | head -n 25
}

if [ "$mode" = "report-file" ]; then
    rows="${2:?usage: count-ops.sh report-file <rows-file>}"
    # One build, one binary resolution per test. The loop that lived in ops.yml
    # called `report` once per row, and every call resolved both test binaries
    # again: 31 rows paid cargo 31 times for the same two executables.
    # A line is `method filter symbol...`: `ci-scope.py rows` groups the symbols
    # a test measures, and one valgrind run of it holds every one of them.
    while read -r -a fields; do
        doc="${fields[0]:-}"
        filter="${fields[1]:-}"
        case "$doc" in ''|'#'*) continue ;; esac
        [ "${#fields[@]}" -ge 3 ] || {
            echo "count-ops: $rows wants \`method filter symbol...\`, got: ${fields[*]}" >&2
            exit 2
        }
        printf '\n## %s -- %s\n' "$doc" "$filter"
        bin=""
        bin="$(find_bin "$filter" "${fields[2]}")" || bin=""
        for symbol in "${fields[@]:2}"; do
            got=""
            status=0
            got="$(ir_of "$filter" "$symbol")" || status=$?
            case "$status" in
                0) echo "$symbol Ir=$got" ;;
                # 3 = the test ran and the profile holds no frame for the symbol; 4 = neither test binary has a test by that name. A blank here would read as a count that was never taken.
                3) echo "$symbol Ir=inlined-not-a-frame" ;;
                4) echo "$symbol Ir=no-such-test" ;;
                # 2 = valgrind or its output broke. The row loop in ops.yml used to
                # swallow this as "not found" and carry on, so a break names itself
                # on the row and the rows after it still get measured.
                *) echo "$symbol Ir=measurement-broke" ;;
            esac
        done
        if [ -n "$bin" ]; then syscalls_of "$filter" "$bin"; fi
    done < "$rows"
    exit 0
fi

if [ "$mode" = "report" ]; then
    filter="$2"
    shift 2
    first="$1"
    bin=""
    bin="$(find_bin "$filter" "$first")" || bin=""
    for symbol in "$@"; do
        got=""
        status=0
        got="$(ir_of "$filter" "$symbol")" || status=$?
        case "$status" in
            0) echo "$symbol Ir=$got" ;;
            # 3 = the test ran and the profile holds no frame for the symbol; 4 = neither test binary has a test by that name. A blank here would read as a count that was never taken.
            3) echo "$symbol Ir=inlined-not-a-frame" ;;
            4) echo "$symbol Ir=no-such-test" ;;
            *) exit "$status" ;;
        esac
    done
    # The syscall table needs one resolved binary; an unresolvable filter has no run to count syscalls in.
    [ -n "$bin" ] && syscalls_of "$filter" "$bin"
    exit 0
fi

if [ "$mode" = "check" ]; then
    filter="$2"
    expect="$3"
    first_symbol="$(awk '$1 !~ /^#/ && NF { print $1; exit }' "$expect")"
    bin=""
    bin="$(find_bin "$filter" "$first_symbol")" || bin=""
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
    [ -n "$bin" ] && syscalls_of "$filter" "$bin"
    exit "$failed"
fi

echo "count-ops: unknown mode $mode" >&2
exit 2
