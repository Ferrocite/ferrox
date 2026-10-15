#!/usr/bin/env bash
# Make a stall name itself: fail on silence instead of at the job timeout, keep the
# log as it was written, say what every thread was blocked in, then run the stalled
# binary's tests one at a time until the one that never returns is the only answer left.
set -uo pipefail

quiet="${WATCH_QUIET:-600}"
out="${WATCH_OUT:-target/ci/watch-test.log}"
selftest=0

usage() {
  cat >&2 <<'EOF'
usage: watch-test.sh [--quiet SECONDS] [--out FILE] [--selftest] -- COMMAND...

  --quiet SECONDS   silence allowed before the command is stopped (600)
  --out FILE        where the log is written as it happens (target/ci/watch-test.log)

WATCH_QUIET and WATCH_OUT set the same two from the environment. The command's own
exit code is returned, except for a stall, which returns 124. libtest writes a test's
name when it finishes, so a parallel run only shows which names are missing; the
second pass runs the stalled binary's tests one per process and stops on the first
that does not return, which is the only test that could have done it.
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quiet) quiet="${2:?--quiet wants a number}"; shift 2 ;;
    --out) out="${2:?--out wants a path}"; shift 2 ;;
    --selftest) selftest=1; shift ;;
    --) shift; break ;;
    *) echo "unknown argument '$1'" >&2; usage ;;
  esac
done
[[ "$quiet" =~ ^[0-9]+$ ]] || { echo "--quiet wants seconds, got '$quiet'" >&2; exit 2; }

# blocked_under PID: every thread below PID and what procfs says it is waiting in.
# A deadlock reads as a futex wait and a socket stall as a read on one fd; macOS and
# Windows have no procfs, so this says nothing there and the named test is the witness.
blocked_under() {
  local pid="$1" child dir
  [[ -d "/proc/$pid/task" ]] || return 0
  for dir in "/proc/$pid"/task/*; do
    printf '  thread %s %s wchan=%s syscall=%s\n' \
      "$(basename "$dir")" "$(cat "$dir/comm" 2>/dev/null || echo '?')" \
      "$(cat "$dir/wchan" 2>/dev/null || echo '?')" \
      "$(cut -d' ' -f1,7- "$dir/syscall" 2>/dev/null | tr -s ' ' || echo '?')"
  done
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do blocked_under "$child"; done
  return 0
}

# STALLED and WRC are what a watched command left behind.
STALLED=0
WRC=0
watch() {
  local command="$1" sent=0 size last_change=$SECONDS pid
  STALLED=0
  WRC=0
  mkdir -p "$(dirname "$out")"
  printf '%s\n' "$command" >"$out"
  # -C, not -la: `cat -u` would buffer the very output this reads, and a pipe would
  # hand the kill signal to the reader instead of to the command under watch.
  stdbuf -oL -eL bash -c "$command" >"$out.part" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    size=$(wc -c <"$out.part" 2>/dev/null || echo 0)
    if ((size > sent)); then
      tail -c +"$((sent + 1))" "$out.part"
      sent=$size
      last_change=$SECONDS
    fi
    if ((SECONDS - last_change >= quiet)); then
      STALLED=1
      echo "nothing written for $((SECONDS - last_change))s (the limit is $quiet): stopping it" >&2
      echo "blocked threads:" >&2
      blocked_under "$pid" >&2
      # The shell reports a background job it had to kill; that line is noise under a
      # witness whose own messages already say what happened, so this group is mute.
      {
        kill -TERM "$pid" 2>/dev/null || true
        sleep 2
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid"
      } 2>/dev/null
      WRC=$?
      break
    fi
    sleep 1
  done
  if ((STALLED == 0)); then
    wait "$pid" 2>/dev/null
    WRC=$?
  fi
  cat "$out.part" >>"$out" 2>/dev/null || true
  rm -f "$out.part"
}

# culprit BINARY: run each of BINARY's tests in its own process and print the first
# that does not return within the same quiet limit. A test that fails alone is not a
# stall, so its code is ignored; only silence is evidence here.
culprit() {
  local binary="$1" keep="$out" names name
  [[ -x "$binary" ]] || return 1
  names=$("$binary" --list --format terse 2>/dev/null | sed -n 's/: test$//p')
  [[ -n "$names" ]] || return 1
  out="$keep.stall"
  for name in $names; do
    watch "$binary --exact '$name' --test-threads=1" >/dev/null
    if ((STALLED == 1)); then
      cp "$out" "$keep.last" 2>/dev/null || true
      printf '%s\n' "$name"
      out="$keep"
      return 0
    fi
  done
  out="$keep"
  return 1
}

# last_binary LOG: the test executable cargo had started when the log stopped.
last_binary() {
  sed -n 's/^.*(target\/[^)]*\/\([^/()]*\)).*$/\1/p' "$1" | tail -1
}

selftest_run() {
  local fake="$PWD/target/ci/selftest-fake" want
  mkdir -p target/ci
  cat >"$fake" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--list" ]]; then
  printf 'hangs::forever: test\nquick::done: test\n'
  exit 0
fi
if [[ "${1:-}" == "--exact" ]]; then
  if [[ "${2:-}" == "hangs::forever" ]]; then sleep 600; fi
  echo "test ${2:-} ... ok"
  exit 0
fi
echo "test quick::done ... ok"
sleep 600
EOF
  chmod +x "$fake"
  quiet=2
  out="target/ci/selftest.log"
  watch "$fake" >/dev/null
  ((STALLED == 1)) || { echo "selftest: a sleeping command did not read as stalled" >&2; return 1; }
  want="$(culprit "$fake")" || { echo "selftest: the stalled test was not named" >&2; return 1; }
  [[ "$want" == "hangs::forever" ]] || { echo "selftest: named '$want', want hangs::forever" >&2; return 1; }
  echo "selftest: ok   a stall stops at the quiet limit and the test that stalls is named"
  watch "sleep 0.2; echo alive" >/dev/null
  ((STALLED == 0 && WRC == 0)) || { echo "selftest: a working command read as stalled" >&2; return 1; }
  watch "exit 3" >/dev/null
  ((WRC == 3)) || { echo "selftest: a failing command's code did not survive the watch" >&2; return 1; }
  echo "selftest: ok   a command that writes is left alone, and its exit code is returned"
  if [[ -d /proc/self/task ]]; then
    [[ -n "$(blocked_under $$ | grep '^  thread ' || true)" ]] || {
      echo "selftest: procfs is here yet no blocked thread was read" >&2; return 1; }
    echo "selftest: ok   procfs is read, so a stall reports what each thread waits in"
  else
    echo "note: no procfs on $(uname -s), so the thread witness is only proven on a Linux runner"
  fi
  rm -f "$fake" "$out" "${out}.stall"
  return 0
}

if ((selftest)); then
  selftest_run
  exit $?
fi
[[ $# -gt 0 ]] || usage

mkdir -p "$(dirname "$out")"
watch "$*"
if ((STALLED == 1)); then
  echo "::error::$* stalled: nothing was written for $quiet s, so the log ends where it stopped"
  binary="$(last_binary "$out")"
  if [[ -n "$binary" ]]; then
    name="$(culprit "$binary")"
    if [[ -n "$name" ]]; then
      echo "STALLED IN $name (the only test of $binary that does not return on its own)"
    else
      echo "no single test of $binary stalls on its own: the stall is in what they share"
    fi
  else
    echo "the log holds no test binary to run alone: the stall is before any test started"
  fi
  exit 124
fi
exit "$WRC"
