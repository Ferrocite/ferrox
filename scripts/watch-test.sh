#!/usr/bin/env bash
# Make a stall name itself: fail on silence instead of at the job timeout, keep the
# log as it was written, say what every thread was blocked in, then run the stalled
# binary's tests one at a time until the one that never returns is the only answer left.
set -uo pipefail

quiet="${WATCH_QUIET:-240}"
bootstrap="${WATCH_BOOTSTRAP:-900}"
out="${WATCH_OUT:-target/ci/watch-test.log}"
selftest=0

usage() {
  cat >&2 <<'EOF'
usage: watch-test.sh [--quiet SECONDS] [--bootstrap SECONDS] [--out FILE] [--selftest] -- COMMAND...

  --quiet SECONDS     silence allowed once a test is running (240)
  --bootstrap SECONDS silence allowed while the command is still building (900)
  --out FILE          where the log is written as it happens (target/ci/watch-test.log)

WATCH_QUIET, WATCH_BOOTSTRAP and WATCH_OUT set the same three from the environment.
Two limits because a suite has two shapes: a cold Windows build can leave one crate
linking for a quarter of an hour with nothing to print, while a test that has started
and means to finish prints its name the moment it does. The limit drops to the second
number as soon as the log says a test binary is running. The command's own exit code
is returned, except for a stall, which returns 124. libtest writes a test's name when
it finishes, so a parallel run shows which names are missing; the second pass runs only
those missing tests, one per process, and stops on the first that does not
return, which is the only test that could have done it.
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quiet) quiet="${2:?--quiet wants a number}"; shift 2 ;;
    --bootstrap) bootstrap="${2:?--bootstrap wants a number}"; shift 2 ;;
    --out) out="${2:?--out wants a path}"; shift 2 ;;
    --selftest) selftest=1; shift ;;
    --) shift; break ;;
    *) echo "unknown argument '$1'" >&2; usage ;;
  esac
done
[[ "$quiet" =~ ^[0-9]+$ && "$bootstrap" =~ ^[0-9]+$ ]] \
  || { echo "--quiet and --bootstrap want seconds" >&2; exit 2; }

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
  local command="$1" sent=0 size last_change=$SECONDS pid limit running
  STALLED=0
  WRC=0
  running=0
  mkdir -p "$(dirname "$out")"
  printf '%s\n' "$command" >"$out"
  # -C, not -la: `cat -u` would buffer the very output this reads, and a pipe would
  # hand the kill signal to the reader instead of to the command under watch. The child
  # opens the file asynchronously, so create it here or the first poll's read can race it.
  : >"$out.part"
  stdbuf -oL -eL bash -c "$command" >"$out.part" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    size=$(wc -c <"$out.part" 2>/dev/null || echo 0)
    if ((size > sent)); then
      tail -c +"$((sent + 1))" "$out.part"
      sent=$size
      last_change=$SECONDS
    fi
    # Once a test binary has started, silence means a test is not finishing.
    ((running == 1)) || grep -q '^ *[Rr]unning ' "$out.part" 2>/dev/null && running=1
    limit=$((running == 1 ? quiet : bootstrap))
    if ((SECONDS - last_change >= limit)); then
      STALLED=1
      echo "nothing written for $((SECONDS - last_change))s (the $(
        ((running == 1)) && echo measuring || echo building) limit is $limit): stopping it" >&2
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
  # The last poll is up to a second behind the close, and what lands in that gap is how a
  # suite names itself: libtest writes the failing name, the `failures:` block and the
  # `test result:` line at the end. Echo the tail before archiving it, or the step log ends
  # where the polling did and a red run reads as a hang.
  size=$(wc -c <"$out.part" 2>/dev/null || echo 0)
  if ((size > sent)); then
    tail -c +"$((sent + 1))" "$out.part"
    sent=$size
  fi
  cat "$out.part" >>"$out" 2>/dev/null || true
  rm -f "$out.part"
}

# culprit BINARY: print the test in BINARY that does not return, running each candidate
# in its own process. libtest writes a finished test's name the moment it finishes, so
# the stalled log already names every test that DID return; the one still hanging is the
# only name missing from it. Probe just those, a handful bounded by the runner's thread
# count, not the whole list of several hundred, so naming a hang costs one pass rather
# than a walk over every name. Fall back to the full list only when the log yields
# nothing to subtract. A test that fails alone is not a stall, so its code is ignored;
# only silence is evidence here.
culprit() {
  local binary="$1" keep="$out" names done missing name
  [[ -x "$binary" ]] || return 1
  names=$("$binary" --list --format terse 2>/dev/null | sed -n 's/: test$//p')
  [[ -n "$names" ]] || return 1
  done=$(grep -E '^test .* \.\.\. (ok|FAILED|ignored)' "$keep" 2>/dev/null |
    sed -E 's/^test (.*) \.\.\. (ok|FAILED|ignored).*/\1/')
  missing=$(comm -23 <(printf '%s\n' "$names" | sort) <(printf '%s\n' "$done" | sort))
  [[ -n "$missing" ]] || missing="$names"
  out="$keep.stall"
  for name in $missing; do
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

# last_binary LOG: the runnable path of the test executable cargo had started when the log stopped.
last_binary() {
  sed -n 's/.*(\([^()]*target[\\/][^()]*\)).*/\1/p' "$1" | tail -1 | tr '\\' '/'
}

selftest_run() {
  local fake="$PWD/target/ci/selftest-fake-abcd" want got probes
  mkdir -p target/ci
  probes="target/ci/selftest-probes.txt"
  cat >"$fake" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--list" ]]; then
  printf 'early::done: test\nhangs::forever: test\n'
  exit 0
fi
if [[ "${1:-}" == "--exact" ]]; then
  printf '%s\n' "${2:-}" >>"${FAKE_PROBE:-/dev/null}"
  if [[ "${2:-}" == "hangs::forever" ]]; then sleep 600; fi
  echo "test ${2:-} ... ok"
  exit 0
fi
echo "     Running unittests src/lib.rs (target/debug/deps/selftest-fake-abcd)"
echo "     Running unittests src/lib.rs (target/debug/deps/selftest-fake-abcd)"
echo "test early::done ... ok"
sleep 600
EOF
  chmod +x "$fake"
  # A 2s limit races the child's own startup: on a loaded runner bash can be slower than
  # that to reach its echoes, so the suite stalls before it has printed the finished test
  # and culprit is right to walk the whole list. Give it room to print, then stall.
  quiet=5
  bootstrap=5
  out="target/ci/selftest.log"
  watch "$fake" >/dev/null
  ((STALLED == 1)) || { echo "selftest: a sleeping command did not read as stalled" >&2; return 1; }
  # The stalled log printed `test early::done ... ok`, so culprit must NOT re-run it: the
  # hang is the one name still missing, and only that name is worth a process of its own.
  : >"$probes"; export FAKE_PROBE="$PWD/$probes"
  want="$(culprit "$fake")" || { echo "selftest: the stalled test was not named" >&2; return 1; }
  unset FAKE_PROBE
  [[ "$want" == "hangs::forever" ]] || { echo "selftest: named '$want', want hangs::forever" >&2; return 1; }
  grep -qx 'hangs::forever' "$probes" || { echo "selftest: the hung test was never probed alone" >&2; return 1; }
  grep -qx 'early::done' "$probes" && { echo "selftest: culprit re-ran a test the log already saw finish" >&2; return 1; }
  echo "selftest: ok   a stall stops at the quiet limit, and only the test still missing from the log is run alone"
  # With nothing completed in the log to subtract, culprit falls back to the full list and
  # must reach every name -- here the finished one, which sorts before the hang, so it is
  # probed and returns before the hang names itself.
  out="target/ci/selftest-empty.log"
  printf '%s\n' '     Running unittests src/lib.rs (target/debug/deps/selftest-fake-abcd)' >"$out"
  : >"$probes"; export FAKE_PROBE="$PWD/$probes"
  want="$(culprit "$fake")" || { echo "selftest: the fallback walk did not name the hang" >&2; return 1; }
  unset FAKE_PROBE
  [[ "$want" == "hangs::forever" ]] || { echo "selftest: fallback named '$want', want hangs::forever" >&2; return 1; }
  grep -qx 'early::done' "$probes" || { echo "selftest: an unparseable log did not fall back to the full walk" >&2; return 1; }
  echo "selftest: ok   when the log names nothing finished, culprit walks every test"
  # culprit() runs only on what last_binary() hands back, and that has to be a runnable path:
  # cargo writes the deps separator as `/` on unix and `\` on Windows.
  out="target/ci/selftest-last.log"
  printf '%s\n' 'test x ... ok' '     Running unittests src\main.rs (target\ci\selftest-fake-abcd)' >"$out"
  got="$(last_binary "$out")"
  [[ "$got" == "target/ci/selftest-fake-abcd" ]] || {
    echo "selftest: a windows-shaped Running line yielded '$got'" >&2; return 1; }
  [[ -x "$got" ]] || {
    echo "selftest: last_binary yielded '$got', which is not runnable: no test would be run alone" >&2; return 1; }
  [[ "$(last_binary <(printf '%s\n' '     Running unittests src/main.rs (target/ci/selftest-fake-abcd)'))" \
    == "target/ci/selftest-fake-abcd" ]] || {
    echo "selftest: a unix-shaped Running line did not yield the same path" >&2; return 1; }
  echo "selftest: ok   the stalled run's log yields the runnable binary, on both separators"
  watch "sleep 0.2; echo alive" >/dev/null
  ((STALLED == 0 && WRC == 0)) || { echo "selftest: a working command read as stalled" >&2; return 1; }
  watch "exit 3" >/dev/null
  ((WRC == 3)) || { echo "selftest: a failing command's code did not survive the watch" >&2; return 1; }
  echo "selftest: ok   a command that writes is left alone, and its exit code is returned"
  # A suite names itself after the last poll: the failing test's name, the `failures:` block
  # and the `test result:` line all arrive as the process exits, between two polls.
  out="target/ci/selftest-tail.log"
  watch "sleep 1.2; echo 'a_name_that_failed'; echo 'test result: FAILED.'" \
    >"target/ci/selftest-tail-output.log" 2>/dev/null
  grep -q 'test result: FAILED' "target/ci/selftest-tail-output.log" || {
    echo "selftest: the bytes after the last poll never reached the watcher's own output" >&2; return 1; }
  echo "selftest: ok   the run's last lines reach the step log, so a red suite names itself"
  if [[ -d /proc/self/task ]]; then
    [[ -n "$(blocked_under $$ | grep '^  thread ' || true)" ]] || {
      echo "selftest: procfs is here yet no blocked thread was read" >&2; return 1; }
    echo "selftest: ok   procfs is read, so a stall reports what each thread waits in"
  else
    echo "note: no procfs on $(uname -s), so the thread witness is only proven on a Linux runner"
  fi
  quiet=1 bootstrap=8
  out="target/ci/selftest-measuring.log"
  started=$SECONDS
  watch "echo '     Running unittests src/lib.rs (target/debug/deps/x-abcd)'; sleep 60" >/dev/null
  ((STALLED == 1 && SECONDS - started < 6)) || {
    echo "selftest: a stall after a test started was not cut by the quiet limit" >&2; return 1; }
  out="target/ci/selftest-building.log"
  started=$SECONDS
  watch "echo '   Compiling slow-crate v1.0.0'; sleep 60" >/dev/null
  ((STALLED == 1 && SECONDS - started >= 8)) || {
    echo "selftest: a silent build was cut before its bootstrap limit" >&2; return 1; }
  echo "selftest: ok   patient while it builds, strict once a test is running"
  rm -f "$fake" "$out" "${out}.stall" "$probes" target/ci/selftest-*.log
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
