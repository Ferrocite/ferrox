#!/usr/bin/env python3
"""The CLI's carrier choice and lane report, checked without a lane.

A terminal gets the four-way prompt and the answer is the carrier the lane is
started with; a pipe is never prompted and takes auto. `status` reads the
carrier, the allowance and the uptime back from the lane it was given: a fake
pid and a synthetic log stand in for a live account, and the front refuses the
trace immediately because nothing listens on its port. A missing allowance is
reported rather than skipped, and which of the two reasons it is comes from what
the log does hold. `locations --ping` is given a fake catalogue: the rows must
order by latency, keep a silent edge as `no answer`, pin REC, and leave the
readings out of the offline copy. The split
lists must reach the lane normalized, and a port outside 1-65535 must be refused
before the lane config is written. A lane that binds its front but carries no
flow must be stopped by `up` itself, with its pid file, config and proxy marker
removed and its port free again. An attempt cut short by an interrupt must leave
nothing either: the lane child, its pid file, its config and the proxy marker
are all gone. The proxy is never armed or cleared on the machine running the
gate: a fake `networksetup` and `scutil` record and answer the calls instead, so
`--vpn` must turn PAC and auto discovery off, restore them on `down`, and fail
when the read-back still shows PAC enabled. An armed proxy is read back per
service and through `scutil` for the exact loopback host and port, and one trace
must pass through that endpoint before the arm is reported.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import pty
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI = ROOT / "dist" / "ferrox-cli.sh"
WATCH = 15


_PORT_LOCK = threading.Lock()
_PORTS: set[int] = set()


def free_port() -> int:
    while True:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with _PORT_LOCK:
            if port not in _PORTS:
                _PORTS.add(port)
                return port


def fake_networksetup(state: pathlib.Path) -> pathlib.Path:
    bin_dir = state / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / "networksetup"
    tool.write_text(
        """#!/bin/sh
state="${FERROX_CONF_DIR:?}"
machine="${FERROX_STATE_DIR:-$state}"
printf '%s\n' "$*" >> "$state/networksetup.calls"

command="${1:-}"
[ "$#" -gt 0 ] && shift
root="$machine/fake-net"
mkdir -p "$root"
deny="${FERROX_FAKE_DENY_SET:-}"
ignore="${FERROX_FAKE_SET_IGNORE:-}"
lie="${FERROX_FAKE_PROXY_LIE:-}"

case "$command" in
  -set*)
    [ "$deny" = 1 ] && exit 1
    [ "$ignore" = 1 ] && exit 0
    ;;
esac

directory() {
  printf '%s/%s' "$root" "$(printf '%s' "$1" | tr ' /' '__')"
}
field() {
  if [ -f "$1/$2" ]; then cat "$1/$2"; else printf '%s' "${3:-}"; fi
}
write() {
  mkdir -p "$1"
  printf '%s' "$2" > "$1/$3"
}

case "$command" in
  -listallnetworkservices)
    echo "An asterisk (*) denotes that a network service is disabled."
    if [ -f "$machine/fake-services" ]; then
      cat "$machine/fake-services"
    else
      echo "Wi-Fi"
    fi
    ;;
  -getsocksfirewallproxy|-getwebproxy|-getsecurewebproxy)
    case "$command" in
      -getsocksfirewallproxy) kind=socks ;;
      -getwebproxy) kind=http ;;
      *) kind=https ;;
    esac
    dir="$(directory "$1")"
    endpoint="$(field "$dir" "$kind-proxy")"
    case "$endpoint" in
      *:*) server="${endpoint%:*}"; port="${endpoint##*:}" ;;
      *) server=""; port="$endpoint" ;;
    esac
    if [ "$lie" = 1 ] && [ "$kind" = socks ]; then
      server=192.0.2.1
      port=$(( ${port:-0} + 1 ))
    fi
    enabled=No
    case "$(field "$dir" "$kind-enabled")" in on|yes) enabled=Yes ;; esac
    auth=0
    [ "$(field "$dir" "$kind-auth" 0)" = 1 ] && auth=1
    echo "Enabled: $enabled"
    echo "Server: $server"
    echo "Port: $port"
    echo "Authenticated Proxy Enabled: $auth"
    ;;
  -setsocksfirewallproxystate|-setwebproxystate|-setsecurewebproxystate)
    case "$command" in
      -setsocksfirewallproxystate) kind=socks ;;
      -setwebproxystate) kind=http ;;
      *) kind=https ;;
    esac
    last=""
    for one in "$@"; do last="$one"; done
    [ -f "$machine/fail-off" ] && [ "$last" = off ] && exit 1
    write "$(directory "$1")" "$2" "$kind-enabled"
    ;;
  -getautoproxyurl)
    dir="$(directory "$1")"
    echo "URL: $(field "$dir" pac-url)"
    enabled=No
    [ "$(field "$dir" pac-enabled)" = yes ] && enabled=Yes
    echo "Enabled: $enabled"
    ;;
  -setautoproxyurl)
    [ -n "${2:-}" ] || {
      echo "** Error: The parameters were not valid." >&2
      exit 4
    }
    dir="$(directory "$1")"
    write "$dir" "${2:-}" pac-url
    write "$dir" yes pac-enabled
    ;;
  -setautoproxystate)
    dir="$(directory "$1")"
    enabled=no
    [ "$2" = on ] && enabled=yes
    write "$dir" "$enabled" pac-enabled
    ;;
  -getproxyautodiscovery)
    dir="$(directory "$1")"
    state=Off
    [ "$(field "$dir" autodiscovery off)" = on ] && state=On
    echo "Auto Proxy Discovery: $state"
    ;;
  -setproxyautodiscovery)
    write "$(directory "$1")" "$2" autodiscovery
    ;;
  -getproxybypassdomains)
    dir="$(directory "$1")"
    if [ -s "$dir/bypass" ]; then
      cat "$dir/bypass"
    else
      echo "There aren't any bypass domains set on $1."
    fi
    ;;
  -setproxybypassdomains)
    dir="$(directory "$1")"
    shift
    mkdir -p "$dir"
    : > "$dir/bypass"
    if [ "$#" = 1 ] && [ "$1" = Empty ]; then
      :
    else
      for one in "$@"; do printf '%s\n' "$one"; done > "$dir/bypass"
    fi
    ;;
  -setsocksfirewallproxy|-setwebproxy|-setsecurewebproxy)
    case "$command" in
      -setsocksfirewallproxy) kind=socks ;;
      -setwebproxy) kind=http ;;
      *) kind=https ;;
    esac
    dir="$(directory "$1")"
    write "$dir" "$2:$3" "$kind-proxy"
    if [ "$#" -gt 3 ]; then
      auth=0
      case "$4" in on|yes) auth=1 ;; esac
      write "$dir" "$auth" "$kind-auth"
    fi
    if [ "${FERROX_FAKE_INTERRUPT:-}" = 1 ] && [ "$kind" = socks ]; then
      kill -s INT "$PPID"
    fi
    ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    tool.chmod(0o755)

    scutil = bin_dir / "scutil"
    scutil.write_text(
        """#!/bin/sh
state="${FERROX_CONF_DIR:?}"
machine="${FERROX_STATE_DIR:-$state}"
override="$machine/scutil.override"
if [ -f "$override" ]; then cat "$override"; exit 0; fi
lie="${FERROX_FAKE_SCUTIL_LIE:-}"
dir="$machine/fake-net/Wi-Fi"

read_field() {
  if [ -f "$dir/$1" ]; then cat "$dir/$1"; else printf '%s' "${2:-}"; fi
}
is_enabled() {
  case "$(read_field "$1" off)" in on|yes) return 0 ;; *) return 1 ;; esac
}

echo "<dictionary> {"
if is_enabled pac-enabled; then
  echo "  ProxyAutoConfigEnable : 1"
else
  echo "  ProxyAutoConfigEnable : 0"
fi
if is_enabled autodiscovery; then
  echo "  ProxyAutoDiscoveryEnable : 1"
else
  echo "  ProxyAutoDiscoveryEnable : 0"
fi
for kind in http https socks; do
  case "$kind" in
    http) label=HTTP ;;
    https) label=HTTPS ;;
    *) label=SOCKS ;;
  esac
  if is_enabled "$kind-enabled"; then
    echo "  ${label}Enable : 1"
  else
    echo "  ${label}Enable : 0"
  fi
done
for kind in http https socks; do
  case "$kind" in
    http) proxy=HTTPProxy; port=HTTPPort ;;
    https) proxy=HTTPSProxy; port=HTTPSPort ;;
    *) proxy=SOCKSProxy; port=SOCKSPort ;;
  esac
  if is_enabled "$kind-enabled"; then
    endpoint="$(read_field "$kind-proxy" "")"
    case "$endpoint" in
      *:*) server="${endpoint%:*}"; number="${endpoint##*:}" ;;
      *) server=""; number="$endpoint" ;;
    esac
    if [ "$lie" = 1 ]; then
      server=192.0.2.1
      number=$(( ${number:-0} + 1 ))
    fi
    echo "  $proxy : $server"
    echo "  $port : $number"
  fi
done
echo "}"
""",
        encoding="utf-8",
    )
    scutil.chmod(0o755)
    return bin_dir


def fake_curl(state: pathlib.Path) -> pathlib.Path:
    bin_dir = state / "fake-curl-bin"
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / "curl"
    tool.write_text(
        """#!/bin/sh
if [ -n "${FERROX_FAKE_CURL_LOG:-}" ]; then
  {
    printf 'args:'
    printf ' %s' "$@"
    printf '\\n'
    env | grep -E '^(ALL_PROXY|all_proxy|HTTP_PROXY|http_proxy|HTTPS_PROXY|https_proxy|NO_PROXY|no_proxy)=' |
      sed -E 's#(=[^/:]+://)[^/@]*@#\\1#' || true
    printf 'end\\n'
  } >> "$FERROX_FAKE_CURL_LOG"
fi
if [ "${FERROX_FAKE_SYSTEM_FAIL:-}" = 1 ]; then
  case " $* " in *" --noproxy "*) ;; *) exit 7 ;; esac
fi
if [ "${FERROX_FAKE_CLOUDFLARE_BLOCK:-}" = 1 ]; then
  case " $* " in *cloudflare.com*) exit 7 ;; esac
fi
if [ "${FERROX_FAKE_TRACE:-}" = 1 ]; then
  case " $* " in *example.com*) printf 'Example Domain\\n' ;; *) printf 'ip=203.0.113.9\\nloc=US\\n' ;; esac
  exit 0
fi
exit 7
""",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    return bin_dir


def seed_proxy_state(
    state: pathlib.Path,
    *,
    pac_url: str = "",
    pac_enabled: bool = False,
    autodiscovery: bool = False,
    bypass: list[str] | None = None,
) -> pathlib.Path:
    directory = state / "fake-net" / "Wi-Fi"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pac-url").write_text(pac_url, encoding="utf-8")
    (directory / "pac-enabled").write_text(
        "yes" if pac_enabled else "no", encoding="utf-8"
    )
    (directory / "autodiscovery").write_text(
        "on" if autodiscovery else "off", encoding="utf-8"
    )
    entries = bypass or []
    (directory / "bypass").write_text(
        "\n".join(entries) + ("\n" if entries else ""), encoding="utf-8"
    )
    return directory


def proxy_field(
    state: pathlib.Path, field: str, default: str = "", service: str = "Wi-Fi"
) -> str:
    path = state / "fake-net" / service / field
    return path.read_text(encoding="utf-8") if path.exists() else default


def proxy_bypass(state: pathlib.Path) -> list[str]:
    return proxy_field(state, "bypass").splitlines()


def seed_service_proxy(
    state: pathlib.Path,
    kind: str,
    server: str,
    port: int,
    *,
    enabled: bool = True,
    service: str = "Wi-Fi",
    auth: bool = False,
) -> None:
    directory = state / "fake-net" / service
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{kind}-proxy").write_text(f"{server}:{port}", encoding="utf-8")
    (directory / f"{kind}-enabled").write_text(
        "on" if enabled else "off", encoding="utf-8"
    )
    (directory / f"{kind}-auth").write_text("1" if auth else "0", encoding="utf-8")


def reset_fake_net(state: pathlib.Path) -> None:
    shutil.rmtree(state / "fake-net", ignore_errors=True)
    for stale in (
        "networksetup.calls",
        "system-proxy.ports",
        "system-proxy.state",
        "scutil.override",
        "fail-off",
        "fake-services",
        "lanes",
        "system-proxy.owner",
        "system-proxy.supervisor",
        "system-proxy.supervisor.pid",
        "fake-vpn-lane.pids",
        "fake-exiting-lane.pids",
        "lane.pid",
        "lane.json",
    ):
        (state / stale).unlink(missing_ok=True)


def env_for(
    state: pathlib.Path, curl: bool = False, darwin: bool = False
) -> dict[str, str]:
    env = dict(os.environ)
    env["FERROX_CONF_DIR"] = str(state)
    env["FERROX_STATE_DIR"] = str(state)
    env["FERROX_BIN"] = shutil.which("true") or "/bin/true"
    path = f"{fake_networksetup(state)}:{env.get('PATH', '')}"
    if darwin:
        bin_dir = state / "fake-darwin-bin"
        bin_dir.mkdir(exist_ok=True)
        uname = bin_dir / "uname"
        uname.write_text("#!/bin/sh\nprintf 'Darwin\\n'\n", encoding="utf-8")
        uname.chmod(0o755)
        path = f"{bin_dir}:{path}"
    if curl:
        path = f"{fake_curl(state)}:{path}"
    env["PATH"] = path
    return env


def up_argv(port: int) -> list[str]:
    return [
        str(CLI),
        "up",
        "--foxy",
        "--email",
        "lane@example.com",
        "--password",
        "not-a-secret",
        "--fronts",
        "socks",
        "--socks",
        str(port),
    ]


def under_a_terminal(answer: bytes, env: dict[str, str]) -> str:
    master, slave = pty.openpty()
    run = subprocess.Popen(
        up_argv(free_port()),
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
    )
    os.close(slave)
    os.write(master, answer)
    spoken = bytearray()
    while True:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        spoken.extend(chunk)
    run.wait(timeout=WATCH)
    os.close(master)
    return spoken.decode(errors="replace")


def chosen_carrier(state: pathlib.Path) -> str:
    document = json.loads((state / "lane-snapshot.json").read_text(encoding="utf-8"))
    return document["outbounds"][0]["settings"]["carrier"]


def snapshot_binary(state: pathlib.Path) -> pathlib.Path:
    binary = state / "fake-carrier-lane"
    binary.write_text(
        """#!/bin/sh
cp "$3" "$FERROX_CONF_DIR/lane-snapshot.json"
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary


def check_picker(state: pathlib.Path) -> int:
    env = env_for(state)
    env["FERROX_BIN"] = str(snapshot_binary(state))
    cases = [
        ("a typed h3 starts the lane on h3", b"4\n", "h3"),
        ("an empty answer takes auto", b"\n", "auto"),
    ]
    for label, answer, want in cases:
        (state / "lane-snapshot.json").unlink(missing_ok=True)
        output = under_a_terminal(answer, env)
        if chosen_carrier(state) != want:
            print(
                f"check-cli-lane: {label}: the lane was handed "
                f"{chosen_carrier(state)!r}:\n{output}",
                file=sys.stderr,
            )
            return 1
        print(f"check-cli-lane: {label}")
    (state / "lane-snapshot.json").unlink(missing_ok=True)
    piped = subprocess.run(
        up_argv(free_port()),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    output = piped.stdout + piped.stderr
    if chosen_carrier(state) != "auto":
        print(
            "check-cli-lane: a pipe did not take auto:\n" + output, file=sys.stderr
        )
        return 1
    if "carrier [auto]:" in output:
        print("check-cli-lane: a pipe was prompted for a carrier", file=sys.stderr)
        return 1
    print("check-cli-lane: a pipe is never prompted and takes auto")
    return 0


def check_status(state: pathlib.Path) -> int:
    lane = subprocess.Popen(["sleep", "30"])
    foxy = {"protocol": "foxy", "settings": {"email": "lane@example.com"}}
    vless = {"protocol": "vless", "settings": {"vnext": []}}
    cases = [
        (
            "status prints uptime, carrier and the last allowance",
            foxy,
            "foxy: allowance 8.0 GiB of 10.0 GiB, resets in 3h 5m\n"
            "foxy: carrier h2\n"
            "foxy: allowance 4.0 GiB of 10.0 GiB, resets in 2h 5m\n",
            ("up for 00:", "carrier: h2", "quota left: 4.0 GiB of 10.0 GiB"),
            (),
        ),
        (
            "a plane that named no allowance is reported as silence",
            foxy,
            "foxy: carrier h2\n",
            ("quota: the plane named no allowance",),
            ("quota left:",),
        ),
        (
            "a lane that named nothing at all says to restart it",
            foxy,
            "",
            ("quota: this lane's binary names neither the carrier nor the allowance",),
            ("quota left:",),
        ),
        (
            "a lane with no allowance to report stays quiet",
            vless,
            "",
            (),
            ("quota",),
        ),
    ]
    try:
        (state / "lane.pid").write_text(f"{lane.pid}\n", encoding="utf-8")
        for label, outbound, log, wants, absent in cases:
            (state / "lane.log").write_text(log, encoding="utf-8")
            (state / "lane.json").write_text(
                json.dumps({"outbounds": [outbound]}), encoding="utf-8"
            )
            run = subprocess.run(
                [
                    str(CLI),
                    "status",
                    "--fronts",
                    "socks",
                    "--socks",
                    str(free_port()),
                ],
                capture_output=True,
                text=True,
                timeout=WATCH,
                env=env_for(state),
            )
            output = run.stdout + run.stderr
            for want in wants:
                if want not in output:
                    print(
                        f"check-cli-lane: status does not print {want!r}:\n{output}",
                        file=sys.stderr,
                    )
                    return 1
            for word in absent:
                if word in output:
                    print(
                        f"check-cli-lane: status printed {word!r} where it should "
                        f"have said nothing:\n{output}",
                        file=sys.stderr,
                    )
                    return 1
            print(f"check-cli-lane: {label}")
    finally:
        lane.terminate()
        lane.wait(timeout=WATCH)
    return 0


def check_locations(state: pathlib.Path) -> int:
    binary = state / "fake-edges"
    binary.write_text(
        """#!/bin/sh
if [ "${2:-}" = "--ping" ]; then
  printf '%s\\n' \\
    '{"host":"c","port":1,"city":"BER","country":"DE","ms":70}' \\
    '{"host":"a","port":1,"city":"SFO","country":"US","ms":40}' \\
    '{"host":"b","port":1,"city":"NYC","country":"US","ms":null}' \\
    '{"host":"d","port":1,"city":"ANY","country":"REC","ms":90}'
else
  printf '%s\\n' \\
    '{"host":"c","port":1,"city":"BER","country":"DE"}' \\
    '{"host":"a","port":1,"city":"SFO","country":"US"}' \\
    '{"host":"b","port":1,"city":"NYC","country":"US"}' \\
    '{"host":"d","port":1,"city":"ANY","country":"REC"}'
fi
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    env = env_for(state)
    env["FERROX_BIN"] = str(binary)
    run = subprocess.run(
        [str(CLI), "locations", "--ping"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: locations --ping exited {run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    marked = re.search(r"REC\s+1 edges\s+90 ms", output)
    fast = re.search(r"US\s+2 edges\s+40 ms", output)
    slow = re.search(r"DE\s+1 edges\s+70 ms", output)
    if not (marked and fast and slow):
        print(
            f"check-cli-lane: locations --ping lost a reading:\n{output}",
            file=sys.stderr,
        )
        return 1
    if not (marked.start() < fast.start() < slow.start()):
        print(
            f"check-cli-lane: locations --ping did not order REC, then fastest first:\n{output}",
            file=sys.stderr,
        )
        return 1
    quick = re.search(r"SFO\s+1\s+40 ms", output)
    silent = re.search(r"NYC\s+1\s+no answer", output)
    if not (quick and silent and quick.start() < silent.start()):
        print(
            f"check-cli-lane: locations --ping did not put the silent city last:\n{output}",
            file=sys.stderr,
        )
        return 1
    cache = (state / "foxy-locations.jsonl").read_text(encoding="utf-8")
    if '"ms"' in cache or "SFO" not in cache:
        print(
            "check-cli-lane: the offline list kept a reading or lost the rows",
            file=sys.stderr,
        )
        return 1
    plain = subprocess.run(
        [str(CLI), "locations"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    spoken = plain.stdout + plain.stderr
    if "40 ms" in spoken or "SFO" not in spoken:
        print(
            f"check-cli-lane: locations without --ping shows a reading or an empty list:\n{spoken}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: locations --ping orders by latency, marks silence, and caches no reading"
    )
    return 0


def check_splits(state: pathlib.Path) -> int:
    env = env_for(state)
    env["FERROX_BIN"] = str(snapshot_binary(state))
    snapshot = state / "lane-snapshot.json"
    snapshot.unlink(missing_ok=True)
    subprocess.run(
        [
            *up_argv(free_port()),
            "--exclude-domains",
            "*.Example.com, printer.lan",
            "--exclude-ports",
            "22,53",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    settings = json.loads(snapshot.read_text(encoding="utf-8"))["outbounds"][0][
        "settings"
    ]
    if settings.get("directDomains") != ["example.com", "printer.lan"]:
        print(
            f"check-cli-lane: the split domains reach the lane as "
            f"{settings.get('directDomains')!r}",
            file=sys.stderr,
        )
        return 1
    if settings.get("directPorts") != [22, 53]:
        print(
            f"check-cli-lane: the split ports reach the lane as "
            f"{settings.get('directPorts')!r}",
            file=sys.stderr,
        )
        return 1
    snapshot.unlink(missing_ok=True)
    subprocess.run(
        up_argv(free_port()),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    settings = json.loads(snapshot.read_text(encoding="utf-8"))["outbounds"][0][
        "settings"
    ]
    if "directDomains" in settings or "directPorts" in settings:
        print(
            "check-cli-lane: a lane with no split lists still carried one",
            file=sys.stderr,
        )
        return 1
    snapshot.unlink(missing_ok=True)
    refused = subprocess.run(
        [*up_argv(free_port()), "--exclude-ports", "70000"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    spoken = refused.stdout + refused.stderr
    if (
        refused.returncode == 0
        or "1-65535" not in spoken
        or (state / "lane.json").exists()
        or snapshot.exists()
    ):
        print(
            f"check-cli-lane: a port outside 1-65535 was not refused before the "
            f"config was written:\n{spoken}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: split lists reach the lane normalized, and a bad port is refused"
    )
    return 0


def dead_lane_binary(state: pathlib.Path) -> pathlib.Path:
    binary = state / "fake-dead-lane"
    binary.write_text(
        """#!/usr/bin/env python3
import json, os, socket, sys
config = sys.argv[sys.argv.index("-c") + 1]
with open(config, encoding="utf-8") as handle:
    document = json.load(handle)
port = document["inbounds"][0]["port"]
state = os.environ["FERROX_CONF_DIR"]
with open(os.path.join(state, "fake-lane.pids"), "a", encoding="utf-8") as handle:
    handle.write(f"{os.getpid()}\\n")
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(16)
while True:
    conn, _ = server.accept()
    conn.close()
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary


def check_failed_lane_is_closed(state: pathlib.Path) -> int:
    for stale in (
        "lane.json",
        "lane.pid",
        "fake-lane.pids",
        "system-proxy.ports",
        "networksetup.calls",
    ):
        (state / stale).unlink(missing_ok=True)
    (state / "system-proxy.ports").write_text("10808 8080\n", encoding="utf-8")
    seed_service_proxy(state, "socks", "127.0.0.1", 10808)
    seed_service_proxy(state, "http", "127.0.0.1", 8080)
    seed_service_proxy(state, "https", "127.0.0.1", 8080)
    port = free_port()
    env = env_for(state)
    env["FERROX_BIN"] = str(dead_lane_binary(state))
    run = subprocess.run(
        up_argv(port),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH * 2,
        env=env,
    )
    output = run.stdout + run.stderr
    if run.returncode != 3:
        print(
            f"check-cli-lane: a lane that carries no flow exited {run.returncode},"
            f" not 3:\n{output}",
            file=sys.stderr,
        )
        return 1
    if "NOT CONNECTED" not in output:
        print(
            f"check-cli-lane: a lane that carries no flow did not say so:\n{output}",
            file=sys.stderr,
        )
        return 1
    for gone in ("lane.pid", "lane.json", "system-proxy.ports"):
        if (state / gone).exists():
            print(
                f"check-cli-lane: a failed lane left {gone} behind:\n{output}",
                file=sys.stderr,
            )
            return 1
    pids = (state / "fake-lane.pids")
    started = pids.read_text(encoding="utf-8").split() if pids.exists() else []
    if not started:
        print("check-cli-lane: the fake lane never ran", file=sys.stderr)
        return 1
    for pid in started:
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            continue
        print(
            f"check-cli-lane: a failed lane left process {pid} running:\n{output}",
            file=sys.stderr,
        )
        return 1
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            print(
                "check-cli-lane: a failed lane left its port bound", file=sys.stderr
            )
            return 1
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if "-setsocksfirewallproxystate Wi-Fi off" not in recorded:
        print(
            "check-cli-lane: a failed lane left the system proxy armed",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: a lane that carries no flow is stopped, with its pid, config"
        " and proxy marker removed, the system proxy cleared and its port free"
    )
    return 0


def stuck_lane_binary(state: pathlib.Path) -> pathlib.Path:
    binary = state / "fake-stuck-lane"
    binary.write_text(
        """#!/usr/bin/env python3
import os, time
state = os.environ["FERROX_CONF_DIR"]
with open(os.path.join(state, "fake-stuck-lane.pids"), "a", encoding="utf-8") as handle:
    handle.write(f"{os.getpid()}\\n")
while True:
    time.sleep(3600)
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary


def check_interrupted_attempt_leaves_nothing(state: pathlib.Path) -> int:
    for stale in (
        "lane.json",
        "lane.pid",
        "fake-stuck-lane.pids",
        "system-proxy.ports",
        "networksetup.calls",
    ):
        (state / stale).unlink(missing_ok=True)
    (state / "system-proxy.ports").write_text("10808 8080\n", encoding="utf-8")
    seed_service_proxy(state, "socks", "127.0.0.1", 10808)
    seed_service_proxy(state, "http", "127.0.0.1", 8080)
    seed_service_proxy(state, "https", "127.0.0.1", 8080)
    port = free_port()
    env = env_for(state)
    env["FERROX_BIN"] = str(stuck_lane_binary(state))
    run = subprocess.Popen(
        up_argv(port),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
    )
    recorded = state / "fake-stuck-lane.pids"
    deadline = time.monotonic() + WATCH
    while time.monotonic() < deadline:
        if (state / "lane.pid").exists() and recorded.exists():
            break
        time.sleep(0.1)
    else:
        run.kill()
        output, _ = run.communicate()
        print(
            "check-cli-lane: an interrupted attempt never started its lane:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    time.sleep(0.3)
    run.send_signal(signal.SIGINT)
    try:
        output, _ = run.communicate(timeout=WATCH)
    except subprocess.TimeoutExpired:
        run.kill()
        output, _ = run.communicate()
        print(
            f"check-cli-lane: an interrupted attempt kept running:\n{output}",
            file=sys.stderr,
        )
        return 1
    if run.returncode != 130:
        print(
            "check-cli-lane: an interrupted attempt exited"
            f" {run.returncode}, not 130:\n{output}",
            file=sys.stderr,
        )
        return 1
    if "interrupted:" not in output:
        print(
            f"check-cli-lane: an interrupted attempt did not say so:\n{output}",
            file=sys.stderr,
        )
        return 1
    for gone in ("lane.pid", "lane.json", "system-proxy.ports"):
        if (state / gone).exists():
            print(
                f"check-cli-lane: an interrupted attempt left {gone} behind:\n{output}",
                file=sys.stderr,
            )
            return 1
    started = recorded.read_text(encoding="utf-8").split() if recorded.exists() else []
    if not started:
        print("check-cli-lane: the fake lane never ran", file=sys.stderr)
        return 1
    for pid in started:
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            continue
        os.kill(int(pid), signal.SIGKILL)
        print(
            f"check-cli-lane: an interrupted attempt left process {pid} running:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            print(
                "check-cli-lane: an interrupted attempt left its port bound",
                file=sys.stderr,
            )
            return 1
    calls = state / "networksetup.calls"
    recorded_calls = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if "-setsocksfirewallproxystate Wi-Fi off" not in recorded_calls:
        print(
            "check-cli-lane: an interrupted attempt left the system proxy armed",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: an interrupted attempt is stopped, with its pid, config and"
        " proxy marker removed, the system proxy cleared and its port free"
    )
    return 0


def check_config_survives(state: pathlib.Path) -> int:
    user = state / "user-config.json"
    user.write_text('{"inbounds": [], "outbounds": []}\n', encoding="utf-8")
    run = subprocess.run(
        [str(CLI), "serve", "--config", str(user)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env_for(state),
    )
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: serve --config exited {run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    if not user.exists():
        print(
            f"check-cli-lane: a lane exit removed the user's --config file:\n{output}",
            file=sys.stderr,
        )
        return 1
    if (state / "lane.pid").exists():
        print(
            f"check-cli-lane: serve --config left its pid file behind:\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: a lane exit clears its pid but never the user's --config file")
    return 0


def vpn_lane_binary(state: pathlib.Path) -> pathlib.Path:
    binary = state / "fake-vpn-lane"
    binary.write_text(
        """#!/usr/bin/env python3
import json, os, socket, sys, time
config = sys.argv[sys.argv.index("-c") + 1]
with open(config, encoding="utf-8") as handle:
    document = json.load(handle)
state = os.environ["FERROX_CONF_DIR"]
with open(os.path.join(state, "fake-vpn-lane.pids"), "a", encoding="utf-8") as handle:
    handle.write(f"{os.getpid()}\\n")
bound = []
for inbound in document.get("inbounds", []):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", inbound["port"]))
    server.listen(16)
    bound.append(server)
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary


def check_vpn_fronts(state: pathlib.Path) -> int:
    ports = []
    while len(ports) < 3:
        port = free_port()
        if port not in ports:
            ports.append(port)
    socks_port, http_port, mixed_port = ports
    config = state / "vpn-fronts.json"
    config.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": socks_port},
                    {"protocol": "http", "listen": "127.0.0.1", "port": http_port},
                    {"protocol": "mixed", "listen": "127.0.0.1", "port": mixed_port},
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    env = env_for(state, curl=True, darwin=True)
    env["FERROX_BIN"] = str(vpn_lane_binary(state))
    env["FERROX_FAKE_TRACE"] = "1"
    cases = [
        ("socks", socks_port, None),
        ("http", None, http_port),
        ("mixed", mixed_port, mixed_port),
        ("socks,http", socks_port, http_port),
        ("socks,mixed", socks_port, mixed_port),
        ("http,mixed", mixed_port, http_port),
        ("socks,http,mixed", socks_port, http_port),
    ]
    calls = state / "networksetup.calls"
    for fronts, want_socks, want_http in cases:
        calls.unlink(missing_ok=True)
        (state / "system-proxy.ports").unlink(missing_ok=True)
        run = subprocess.run(
            [
                str(CLI),
                "up",
                "--config",
                str(config),
                "--fronts",
                fronts,
                "--socks",
                str(socks_port),
                "--http",
                str(http_port),
                "--mixed",
                str(mixed_port),
                "--vpn",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )
        output = run.stdout + run.stderr
        if run.returncode != 0:
            print(
                f"check-cli-lane: --fronts {fronts} exited {run.returncode}:\n{output}",
                file=sys.stderr,
            )
            return 1
        recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
        wanted = []
        if want_socks is not None:
            wanted.append(f"-setsocksfirewallproxy Wi-Fi 127.0.0.1 {want_socks}")
        if want_http is not None:
            wanted.extend(
                [
                    f"-setwebproxy Wi-Fi 127.0.0.1 {want_http}",
                    f"-setsecurewebproxy Wi-Fi 127.0.0.1 {want_http}",
                ]
            )
        missing = [call for call in wanted if call not in recorded]
        wrong_socks = want_socks is None and "-setsocksfirewallproxy" in recorded
        wrong_http = want_http is None and (
            "-setwebproxy" in recorded or "-setsecurewebproxy" in recorded
        )
        if missing or wrong_socks or wrong_http:
            print(
                f"check-cli-lane: --fronts {fronts} armed the wrong system proxy:"
                f"\n{recorded}\n{output}",
                file=sys.stderr,
            )
            return 1
        down = subprocess.run(
            [str(CLI), "down"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )
        if down.returncode != 0:
            print(
                f"check-cli-lane: down after --fronts {fronts} exited {down.returncode}:"
                f"\n{down.stdout + down.stderr}",
                file=sys.stderr,
            )
            return 1
    print("check-cli-lane: every front list arms the system proxy at the port it serves")
    return 0


def config_lane(
    state: pathlib.Path, config: pathlib.Path, trace: bool = True
) -> tuple[subprocess.CompletedProcess[str], str]:
    calls = state / "networksetup.calls"
    calls.unlink(missing_ok=True)
    (state / "system-proxy.ports").unlink(missing_ok=True)
    env = env_for(state, curl=True, darwin=True)
    env["FERROX_BIN"] = str(vpn_lane_binary(state))
    env["FERROX_FAKE_TRACE"] = "1" if trace else ""
    run = subprocess.run(
        [str(CLI), "up", "--config", str(config), "--vpn"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    return run, recorded


def check_config_fronts(state: pathlib.Path) -> int:
    def down() -> int:
        run = subprocess.run(
            [str(CLI), "down"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env_for(state),
        )
        if run.returncode != 0:
            print(
                f"check-cli-lane: a config lane's down exited {run.returncode}:"
                f"\n{run.stdout + run.stderr}",
                file=sys.stderr,
            )
            return 1
        if (state / "system-proxy.supervisor").exists():
            print(
                "check-cli-lane: a config lane's down left its supervisor behind",
                file=sys.stderr,
            )
            return 1
        return 0

    http_port = free_port()
    http = state / "config-http.json"
    http.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "http", "listen": "127.0.0.1", "port": http_port}
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    run, recorded = config_lane(state, http)
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: an HTTP config lane exited {run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    wanted = [
        f"-setwebproxy Wi-Fi 127.0.0.1 {http_port}",
        f"-setsecurewebproxy Wi-Fi 127.0.0.1 {http_port}",
    ]
    marker = state / "system-proxy.ports"
    if (
        any(call not in recorded for call in wanted)
        or "-setsocksfirewallproxy" in recorded
        or not marker.exists()
        or marker.read_text(encoding="utf-8").strip() != f"- {http_port}"
    ):
        print(
            f"check-cli-lane: an HTTP config lane armed the wrong system proxy:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    if down():
        return 1

    mixed_port = free_port()
    mixed = state / "config-mixed.json"
    mixed.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "mixed", "listen": "127.0.0.1", "port": mixed_port}
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    run, recorded = config_lane(state, mixed)
    output = run.stdout + run.stderr
    wanted = [
        f"-setsocksfirewallproxy Wi-Fi 127.0.0.1 {mixed_port}",
        f"-setwebproxy Wi-Fi 127.0.0.1 {mixed_port}",
        f"-setsecurewebproxy Wi-Fi 127.0.0.1 {mixed_port}",
    ]
    if (
        run.returncode != 0
        or any(call not in recorded for call in wanted)
        or not marker.exists()
        or marker.read_text(encoding="utf-8").strip()
        != f"{mixed_port} {mixed_port}"
    ):
        print(
            f"check-cli-lane: a mixed config lane armed the wrong system proxy:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    if down():
        return 1

    exposed = state / "config-exposed.json"
    exposed.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "protocol": "http",
                        "listen": "0.0.0.0",
                        "port": free_port(),
                    }
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    run, recorded = config_lane(state, exposed, trace=False)
    output = run.stdout + run.stderr
    if (
        run.returncode == 0
        or recorded
        or (state / "lane.pid").exists()
        or "loopback" not in output
    ):
        print(
            f"check-cli-lane: a config on 0.0.0.0 was armed instead of refused:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1

    no_front = state / "config-no-front.json"
    no_front.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "protocol": "dokodemo-door",
                        "listen": "127.0.0.1",
                        "port": free_port(),
                    }
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    run, recorded = config_lane(state, no_front, trace=False)
    output = run.stdout + run.stderr
    if (
        run.returncode == 0
        or recorded
        or (state / "lane.pid").exists()
        or "no socks, http or mixed inbound" not in output
    ):
        print(
            f"check-cli-lane: a config with no proxy front was armed:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1

    silent = state / "config-silent.json"
    silent.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "protocol": "http",
                        "listen": "127.0.0.1",
                        "port": free_port(),
                    }
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    run, recorded = config_lane(state, silent, trace=False)
    output = run.stdout + run.stderr
    writes = [
        line
        for line in recorded.splitlines()
        if line.startswith("-set")
        and not line.startswith("-setproxyautodiscovery ")
    ]
    if (
        run.returncode == 0
        or writes
        or (state / "lane.pid").exists()
        or marker.exists()
    ):
        print(
            f"check-cli-lane: a config lane that answered no flow was armed:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1

    print(
        "check-cli-lane: a config lane arms the fronts and ports it serves, and"
        " refuses an exposed, frontless or silent one"
    )
    return 0


def check_vpn_pac(state: pathlib.Path) -> int:
    port = free_port()
    config = state / "vpn-pac.json"
    config.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": port}
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    env = env_for(state, curl=True, darwin=True)
    env["FERROX_BIN"] = str(vpn_lane_binary(state))
    env["FERROX_FAKE_TRACE"] = "1"
    calls = state / "networksetup.calls"
    override = state / "scutil.override"
    pac_url = "http://pac.corp.example/proxy.pac"

    def clear() -> None:
        for stale in (
            "lane.pid",
            "lane.json",
            "system-proxy.ports",
            "system-proxy.state",
            "networksetup.calls",
            "scutil.override",
            "fake-vpn-lane.pids",
        ):
            (state / stale).unlink(missing_ok=True)

    def arm(readback: str | None = None) -> subprocess.CompletedProcess[str]:
        clear()
        if readback is not None:
            override.write_text(readback, encoding="utf-8")
        return subprocess.run(
            [
                str(CLI),
                "up",
                "--config",
                str(config),
                "--fronts",
                "socks",
                "--socks",
                str(port),
                "--vpn",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )

    def down() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CLI), "down"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )

    seed_proxy_state(state, pac_url=pac_url, pac_enabled=True, autodiscovery=True)
    run = arm()
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: --vpn over a PAC exited {run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if "-setproxyautodiscovery Wi-Fi off" not in recorded:
        print(
            f"check-cli-lane: --vpn left auto discovery on:\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    if "-setautoproxystate Wi-Fi off" not in recorded:
        print(
            f"check-cli-lane: --vpn left the PAC enabled:\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    if proxy_field(state, "pac-enabled") != "no":
        print("check-cli-lane: --vpn left the PAC enabled", file=sys.stderr)
        return 1
    if proxy_field(state, "autodiscovery") != "off":
        print("check-cli-lane: --vpn left auto discovery on", file=sys.stderr)
        return 1
    if proxy_field(state, "socks-enabled") != "on":
        print("check-cli-lane: --vpn did not enable the SOCKS proxy", file=sys.stderr)
        return 1
    down_run = down()
    output = down_run.stdout + down_run.stderr
    if down_run.returncode != 0:
        print(
            f"check-cli-lane: down after a PAC arm exited {down_run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    if proxy_field(state, "pac-url") != pac_url:
        print(
            f"check-cli-lane: down restored the PAC URL as "
            f"{proxy_field(state, 'pac-url')!r}",
            file=sys.stderr,
        )
        return 1
    if proxy_field(state, "pac-enabled") != "yes":
        print("check-cli-lane: down left the PAC disabled", file=sys.stderr)
        return 1
    if proxy_field(state, "autodiscovery") != "on":
        print("check-cli-lane: down left auto discovery off", file=sys.stderr)
        return 1
    print(
        "check-cli-lane: --vpn disables PAC and auto discovery, and down restores both"
    )

    seed_proxy_state(state)
    run = arm()
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: --vpn with no PAC exited {run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    down_run = down()
    output = down_run.stdout + down_run.stderr
    if down_run.returncode != 0:
        print(
            f"check-cli-lane: down after a PAC-free arm exited {down_run.returncode}:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    if (
        proxy_field(state, "pac-url") != ""
        or proxy_field(state, "pac-enabled") != "no"
        or proxy_field(state, "autodiscovery") != "off"
    ):
        print(
            "check-cli-lane: down changed a service that had no PAC",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: a service with PAC off is unchanged by down")

    seed_proxy_state(state, pac_url=pac_url, pac_enabled=True)
    run = arm("ProxyAutoConfigEnable : 1\nSOCKSEnable : 1\n")
    output = run.stdout + run.stderr
    if run.returncode == 0:
        print(
            f"check-cli-lane: a read-back that still shows PAC enabled passed:\n{output}",
            file=sys.stderr,
        )
        return 1
    if (state / "system-proxy.ports").exists() or (state / "system-proxy.state").exists():
        print(
            f"check-cli-lane: a failed PAC read-back left the marker behind:\n{output}",
            file=sys.stderr,
        )
        return 1
    if (state / "lane.pid").exists():
        print(
            f"check-cli-lane: a failed PAC read-back left the lane behind:\n{output}",
            file=sys.stderr,
        )
        return 1
    if proxy_field(state, "socks-enabled") == "on":
        print(
            f"check-cli-lane: a failed PAC read-back left the proxy armed:\n{output}",
            file=sys.stderr,
        )
        return 1
    pids = state / "fake-vpn-lane.pids"
    for pid in pids.read_text(encoding="utf-8").split() if pids.exists() else []:
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            continue
        print(
            f"check-cli-lane: a failed PAC read-back left process {pid} running:\n"
            f"{output}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: a read-back that still shows PAC enabled fails the arm and clears it"
    )
    return 0


def check_vpn_proxy_readback(state: pathlib.Path) -> int:
    port = free_port()
    config = vpn_config(state, "vpn-readback.json", port)
    curl_log = state / "curl.calls"

    def fresh() -> None:
        reset_fake_net(state)
        curl_log.unlink(missing_ok=True)

    def run(args: list[str], extra: dict[str, str] | None = None):
        env = env_for(state, curl=True, darwin=True)
        env["FERROX_BIN"] = str(vpn_lane_binary(state))
        env["FERROX_FAKE_TRACE"] = "1"
        env["FERROX_FAKE_CURL_LOG"] = str(curl_log)
        if extra:
            env.update(extra)
        return subprocess.run(
            [str(CLI), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )

    def up(extra: dict[str, str] | None = None):
        return run(["up", "--config", str(config), "--vpn"], extra)

    def live_lanes() -> list[int]:
        pids = state / "fake-vpn-lane.pids"
        live = []
        for raw in pids.read_text(encoding="utf-8").split() if pids.exists() else []:
            try:
                os.kill(int(raw), 0)
            except ProcessLookupError:
                continue
            live.append(int(raw))
        return live

    def cleared(output: str, label: str) -> bool:
        if (state / "system-proxy.ports").exists() or (
            state / "system-proxy.state"
        ).exists():
            print(
                f"check-cli-lane: {label} left a proxy marker:\n{output}",
                file=sys.stderr,
            )
            return False
        if (state / "lane.pid").exists() or live_lanes():
            print(
                f"check-cli-lane: {label} left a lane behind:\n{output}",
                file=sys.stderr,
            )
            return False
        return True

    try:
        fresh()
        arm = up()
        output = arm.stdout + arm.stderr
        if (
            arm.returncode != 0
            or proxy_field(state, "socks-proxy") != f"127.0.0.1:{port}"
            or proxy_field(state, "socks-enabled") != "on"
            or not (state / "system-proxy.ports").exists()
        ):
            print(
                f"check-cli-lane: a successful arm did not read back its endpoint:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
        recorded = curl_log.read_text(encoding="utf-8") if curl_log.exists() else ""
        probe = [
            block
            for block in recorded.split("end\n")
            if "args:" in block
            and "--noproxy" not in block
            and f"ALL_PROXY=socks5h://127.0.0.1:{port}" in block
        ]
        if not probe:
            print(
                "check-cli-lane: a successful arm never proved a trace through the"
                f" system proxy:\n{recorded}\n{output}",
                file=sys.stderr,
            )
            return 1
        down = run(["down"])
        output = down.stdout + down.stderr
        if down.returncode != 0 or not cleared(output, "down after a successful arm"):
            return 1
        print(
            "check-cli-lane: an arm reads its exact endpoint back and proves a trace through it"
        )

        fresh()
        denied = up({"FERROX_FAKE_DENY_SET": "1"})
        output = denied.stdout + denied.stderr
        if (
            denied.returncode == 0
            or "administrator" not in output
            or "nothing was started" not in output
            or (state / "fake-vpn-lane.pids").exists()
            or not cleared(output, "a denied preflight")
        ):
            print(
                f"check-cli-lane: a denied proxy write did not refuse before the lane:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
        print(
            "check-cli-lane: a denied proxy write refuses before the lane starts"
        )

        fresh()
        ignored = up({"FERROX_FAKE_SET_IGNORE": "1"})
        output = ignored.stdout + ignored.stderr
        if ignored.returncode == 0 or "read-back" not in output or not cleared(
            output, "a write that persisted nothing"
        ):
            print(
                f"check-cli-lane: a write that persisted nothing passed the arm:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
        print("check-cli-lane: a write that persisted nothing fails the read-back")

        fresh()
        lied = up({"FERROX_FAKE_PROXY_LIE": "1"})
        output = lied.stdout + lied.stderr
        if lied.returncode == 0 or "read-back" not in output or not cleared(
            output, "a service read-back at the wrong endpoint"
        ):
            print(
                f"check-cli-lane: a service read-back at the wrong endpoint passed:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
        print("check-cli-lane: a service read-back must show the exact host and port")

        fresh()
        scutil_lie = up({"FERROX_FAKE_SCUTIL_LIE": "1"})
        output = scutil_lie.stdout + scutil_lie.stderr
        if scutil_lie.returncode == 0 or "read-back" not in output or not cleared(
            output, "a scutil read-back at the wrong endpoint"
        ):
            print(
                f"check-cli-lane: a scutil read-back at the wrong endpoint passed:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
        print("check-cli-lane: scutil's read-back must show the exact host and port")

        fresh()
        silent = up({"FERROX_FAKE_SYSTEM_FAIL": "1"})
        output = silent.stdout + silent.stderr
        if (
            silent.returncode == 0
            or "did not carry a trace" not in output
            or not cleared(output, "a system proxy that carried no trace")
        ):
            print(
                f"check-cli-lane: a system proxy that carried no trace passed:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
        print("check-cli-lane: a trace through the system proxy must pass before the arm")

        fresh()
        veepn_port = free_port()
        veepn = run(
            [
                "up",
                "--veepn",
                "--vpn",
                "--fronts",
                "socks",
                "--socks",
                str(veepn_port),
            ],
            {"FERROX_FAKE_CLOUDFLARE_BLOCK": "1"},
        )
        output = veepn.stdout + veepn.stderr
        if (
            veepn.returncode != 0
            or "system proxy on" not in output
            or not (state / "system-proxy.ports").exists()
        ):
            print(
                f"check-cli-lane: a VeePN lane's system proxy fallback failed:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
        print(
            "check-cli-lane: a VeePN lane proves its system proxy through Example Domain"
        )
    finally:
        run(["down"])
    return 0


def check_vpn_bypass(state: pathlib.Path) -> int:
    defaults = [
        "localhost",
        "127.0.0.1",
        "::1",
        "*.local",
        "169.254.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]
    port = free_port()
    config = state / "vpn-bypass.json"
    config.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": port}
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    env = env_for(state, curl=True, darwin=True)
    env["FERROX_BIN"] = str(vpn_lane_binary(state))
    env["FERROX_FAKE_TRACE"] = "1"
    calls = state / "networksetup.calls"

    def clear() -> None:
        for stale in (
            "lane.pid",
            "lane.json",
            "system-proxy.ports",
            "system-proxy.state",
            "networksetup.calls",
            "scutil.override",
            "fake-vpn-lane.pids",
        ):
            (state / stale).unlink(missing_ok=True)

    def arm() -> subprocess.CompletedProcess[str]:
        clear()
        return subprocess.run(
            [
                str(CLI),
                "up",
                "--config",
                str(config),
                "--fronts",
                "socks",
                "--socks",
                str(port),
                "--vpn",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )

    def down() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CLI), "down"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )

    seed_proxy_state(state)
    run = arm()
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: --vpn over an empty bypass list exited {run.returncode}:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if "-setproxybypassdomains Wi-Fi" not in recorded:
        print(
            f"check-cli-lane: --vpn left the bypass list unset:\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    armed = proxy_bypass(state)
    if armed != defaults:
        print(
            f"check-cli-lane: --vpn armed the bypass list as {armed!r}, not {defaults!r}",
            file=sys.stderr,
        )
        return 1
    down_run = down()
    output = down_run.stdout + down_run.stderr
    if down_run.returncode != 0:
        print(
            f"check-cli-lane: down after a bypass arm exited {down_run.returncode}:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    if proxy_bypass(state) != []:
        print(
            f"check-cli-lane: down restored an empty bypass list as "
            f"{proxy_bypass(state)!r}",
            file=sys.stderr,
        )
        return 1

    seed_proxy_state(state, bypass=["*.corp.example"])
    run = arm()
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: --vpn over a prior bypass list exited {run.returncode}:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    armed = proxy_bypass(state)
    if armed != defaults + ["*.corp.example"]:
        print(
            f"check-cli-lane: --vpn lost the prior bypass entry: {armed!r}",
            file=sys.stderr,
        )
        return 1
    down_run = down()
    output = down_run.stdout + down_run.stderr
    if down_run.returncode != 0:
        print(
            f"check-cli-lane: down after a merged bypass arm exited "
            f"{down_run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    if proxy_bypass(state) != ["*.corp.example"]:
        print(
            f"check-cli-lane: down restored the bypass list as "
            f"{proxy_bypass(state)!r}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: --vpn sets the default bypass union and down restores the exact prior list"
    )
    return 0


def check_vpn_platform_refusal(state: pathlib.Path) -> int:
    fake_bin = fake_networksetup(state)
    curl_bin = fake_curl(state)
    lane = vpn_lane_binary(state)

    def run_case(platform: str, with_networksetup: bool, expected: str) -> int:
        label = platform.lower().replace(" ", "-")
        bin_dir = state / f"platform-bin-{label}"
        bin_dir.mkdir(exist_ok=True)
        uname = bin_dir / "uname"
        uname.write_text(
            f"#!/bin/sh\nprintf '%s\\n' '{platform}'\n", encoding="utf-8"
        )
        uname.chmod(0o755)
        python = bin_dir / "python3"
        if python.exists() or python.is_symlink():
            python.unlink()
        python.symlink_to(shutil.which("python3") or "/usr/bin/python3")
        path = f"{curl_bin}:{bin_dir}:/usr/bin:/bin"
        if with_networksetup:
            path = f"{fake_bin}:{path}"
        port = free_port()
        config = state / f"vpn-platform-{label}.json"
        config.write_text(
            json.dumps(
                {
                    "inbounds": [
                        {"protocol": "socks", "listen": "127.0.0.1", "port": port}
                    ],
                    "outbounds": [],
                }
            ),
            encoding="utf-8",
        )
        for stale in (
            "lane.pid",
            "system-proxy.ports",
            "system-proxy.state",
            "networksetup.calls",
            "fake-vpn-lane.pids",
            "scutil.override",
        ):
            (state / stale).unlink(missing_ok=True)
        env = dict(os.environ)
        env["FERROX_CONF_DIR"] = str(state)
        env["FERROX_BIN"] = str(lane)
        env["FERROX_FAKE_TRACE"] = "1"
        env["PATH"] = path
        run = subprocess.run(
            [
                str(CLI),
                "up",
                "--config",
                str(config),
                "--fronts",
                "socks",
                "--socks",
                str(port),
                "--vpn",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )
        output = run.stdout + run.stderr
        problem = ""
        try:
            if run.returncode == 0:
                problem = (
                    f"check-cli-lane: --vpn on {platform} exited 0 instead of "
                    f"refusing:\n{output}"
                )
            elif expected not in output:
                problem = (
                    f"check-cli-lane: --vpn on {platform} did not name "
                    f"{expected!r}:\n{output}"
                )
            elif "nothing was started" not in output:
                problem = (
                    f"check-cli-lane: --vpn on {platform} did not say nothing "
                    f"started:\n{output}"
                )
            elif (state / "lane.pid").exists():
                problem = (
                    f"check-cli-lane: --vpn on {platform} left a lane pid behind:"
                    f"\n{output}"
                )
            elif (state / "system-proxy.state").exists():
                problem = (
                    f"check-cli-lane: --vpn on {platform} left a proxy marker "
                    f"behind:\n{output}"
                )
            elif (state / "fake-vpn-lane.pids").exists():
                problem = (
                    f"check-cli-lane: --vpn on {platform} started the lane:\n{output}"
                )
        finally:
            subprocess.run(
                [str(CLI), "down"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=WATCH,
                env=env,
            )
        if problem:
            print(problem, file=sys.stderr)
            return 1
        return 0

    if run_case("Linux", with_networksetup=True, expected="Linux") != 0:
        return 1
    if run_case("Darwin", with_networksetup=False, expected="networksetup") != 0:
        return 1
    env = dict(os.environ)
    env["FERROX_CONF_DIR"] = str(state)
    env["FERROX_BIN"] = str(lane)
    env["FERROX_FAKE_TRACE"] = "1"
    env["PATH"] = (
        f"{curl_bin}:{fake_bin}:{state / 'platform-bin-linux'}:/usr/bin:/bin"
    )
    for stale in (
        "lane.pid",
        "system-proxy.ports",
        "system-proxy.state",
        "networksetup.calls",
        "fake-vpn-lane.pids",
        "scutil.override",
    ):
        (state / stale).unlink(missing_ok=True)
    run = subprocess.run(
        [
            str(CLI),
            "up",
            "--config",
            str(state / "vpn-platform-linux.json"),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    output = run.stdout + run.stderr
    problem = ""
    try:
        if run.returncode != 0:
            problem = (
                f"check-cli-lane: up without --vpn on Linux exited "
                f"{run.returncode}:\n{output}"
            )
        elif "lane up" not in output:
            problem = (
                f"check-cli-lane: up without --vpn on Linux did not start a "
                f"lane:\n{output}"
            )
        elif (state / "system-proxy.state").exists():
            problem = (
                f"check-cli-lane: up without --vpn on Linux armed a proxy:"
                f"\n{output}"
            )
    finally:
        subprocess.run(
            [str(CLI), "down"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )
    if problem:
        print(problem, file=sys.stderr)
        return 1
    print(
        "check-cli-lane: --vpn refuses a non-macOS platform and a missing "
        "networksetup before the lane starts, and up without --vpn still starts"
    )
    return 0


def check_proxy_transaction(state: pathlib.Path) -> int:
    def run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CLI), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )

    def lane_env() -> dict[str, str]:
        env = env_for(state, curl=True, darwin=True)
        env["FERROX_BIN"] = str(vpn_lane_binary(state))
        env["FERROX_FAKE_TRACE"] = "1"
        return env

    def config(name: str, protocol: str, port: int) -> pathlib.Path:
        path = state / name
        path.write_text(
            json.dumps(
                {
                    "inbounds": [
                        {"protocol": protocol, "listen": "127.0.0.1", "port": port}
                    ],
                    "outbounds": [],
                }
            ),
            encoding="utf-8",
        )
        return path

    def clear() -> None:
        reset_fake_net(state)
        for stale in ("system-proxy.state", "system-proxy.ports"):
            (state / stale).unlink(missing_ok=True)

    clear()
    seed_service_proxy(state, "http", "proxy.corp", 3128)
    port = free_port()
    up = run(["up", "--config", str(config("txn-corp.json", "http", port)), "--vpn"], lane_env())
    output = up.stdout + up.stderr
    if up.returncode != 0:
        print(f"check-cli-lane: a corporate-proxy arm failed:\n{output}", file=sys.stderr)
        return 1
    down = run(["down"], env_for(state))
    output = down.stdout + down.stderr
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if (
        down.returncode != 0
        or "-setwebproxy Wi-Fi proxy.corp 3128" not in recorded
        or "-setwebproxystate Wi-Fi on" not in recorded
        or proxy_field(state, "http-proxy") != "proxy.corp:3128"
        or proxy_field(state, "http-enabled") != "on"
        or proxy_field(state, "socks-enabled") != "off"
        or proxy_field(state, "https-enabled") != "off"
        or (state / "system-proxy.ports").exists()
        or (state / "system-proxy.state").exists()
    ):
        print(
            "check-cli-lane: down did not restore the corporate proxy it replaced:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: down restores the proxy that was there before the arm")

    clear()
    port = free_port()
    up = run(["up", "--config", str(config("txn-none.json", "http", port)), "--vpn"], lane_env())
    output = up.stdout + up.stderr
    if up.returncode != 0:
        print(f"check-cli-lane: an empty-proxy arm failed:\n{output}", file=sys.stderr)
        return 1
    down = run(["down"], env_for(state))
    output = down.stdout + down.stderr
    if (
        down.returncode != 0
        or proxy_field(state, "socks-enabled") != "off"
        or proxy_field(state, "http-enabled") != "off"
        or proxy_field(state, "https-enabled") != "off"
        or (state / "system-proxy.ports").exists()
        or (state / "system-proxy.state").exists()
    ):
        print(
            f"check-cli-lane: a service with no prior proxy was not left off:\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: a service with no prior proxy ends with every proxy off")

    clear()
    seed_service_proxy(state, "http", "proxy.corp", 3128)
    port = free_port()
    env = lane_env()
    env["FERROX_FAKE_INTERRUPT"] = "1"
    run_interrupted = subprocess.Popen(
        [str(CLI), "up", "--config", str(config("txn-int.json", "socks", port)), "--vpn"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    try:
        output, _ = run_interrupted.communicate(timeout=WATCH)
    except subprocess.TimeoutExpired:
        run_interrupted.kill()
        output, _ = run_interrupted.communicate()
        print(f"check-cli-lane: an interrupted arm kept running:\n{output}", file=sys.stderr)
        return 1
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if (
        run_interrupted.returncode != 130
        or "interrupted:" not in output
        or "-setwebproxy Wi-Fi proxy.corp 3128" not in recorded
        or proxy_field(state, "http-enabled") != "on"
        or proxy_field(state, "socks-enabled") != "off"
        or (state / "system-proxy.ports").exists()
        or (state / "system-proxy.state").exists()
        or (state / "lane.pid").exists()
    ):
        print(
            "check-cli-lane: an interrupted arm did not restore the snapshot:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: an interrupted arm restores the snapshot and leaves no marker")

    clear()
    (state / "fake-services").write_text("Wi-Fi\n*Ethernet\n", encoding="utf-8")
    port = free_port()
    up = run(["up", "--config", str(config("txn-other.json", "http", port)), "--vpn"], lane_env())
    output = up.stdout + up.stderr
    if up.returncode != 0:
        print(f"check-cli-lane: an untouched-service arm failed:\n{output}", file=sys.stderr)
        return 1
    seed_service_proxy(state, "http", "user.corp", 8081, service="Ethernet")
    down = run(["down"], env_for(state))
    output = down.stdout + down.stderr
    if (
        down.returncode != 0
        or proxy_field(state, "http-proxy", service="Ethernet") != "user.corp:8081"
        or proxy_field(state, "http-enabled", service="Ethernet") != "on"
    ):
        print(
            f"check-cli-lane: down touched a service the arm never did:\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: down leaves a service the arm never touched alone")
    return 0


def check_proxy_cleanup(state: pathlib.Path) -> int:
    def run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CLI), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )

    reset_fake_net(state)
    seed_service_proxy(state, "socks", "127.0.0.1", 10808)
    seed_service_proxy(state, "http", "127.0.0.1", 3128)
    down = run(["down"], env_for(state))
    output = down.stdout + down.stderr
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if (
        down.returncode != 0
        or "-setsocksfirewallproxystate Wi-Fi off" not in recorded
        or "-setwebproxystate Wi-Fi off" in recorded
        or proxy_field(state, "socks-enabled") != "off"
        or proxy_field(state, "http-enabled") != "on"
    ):
        print(
            "check-cli-lane: down without a marker did not clear the ferrox"
            f" endpoint and leave the user's proxy alone:\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: down without a marker clears the ferrox loopback proxy"
        " and leaves a non-ferrox proxy untouched"
    )

    reset_fake_net(state)
    seed_service_proxy(state, "socks", "127.0.0.1", 10808)
    (state / "system-proxy.ports").write_text("10808 -\n", encoding="utf-8")
    (state / "fail-off").write_text("", encoding="utf-8")
    down = run(["down"], env_for(state))
    output = down.stdout + down.stderr
    if (
        down.returncode == 0
        or "system proxy cleared." in output
        or "failed" not in output
        or not (state / "system-proxy.ports").exists()
    ):
        print(
            "check-cli-lane: a failed proxy clear was reported as success:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: a failed proxy clear is named and down exits nonzero")

    reset_fake_net(state)
    seed_service_proxy(state, "socks", "127.0.0.1", 10808)
    status = run(["status"], env_for(state))
    output = status.stdout + status.stderr
    if (
        status.returncode == 0
        or "system proxy" not in output
        or "no lane" not in output
    ):
        print(
            f"check-cli-lane: status hid a stale system proxy:\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: status names a stale system proxy and exits nonzero")

    reset_fake_net(state)
    seed_service_proxy(state, "socks", "127.0.0.1", 10808)
    login = run(
        ["login", "--email", "lane@example.com", "--password", "not-a-secret"],
        env_for(state),
    )
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    output = login.stdout + login.stderr
    if (
        login.returncode != 0
        or "-setsocksfirewallproxystate Wi-Fi off" not in recorded
        or proxy_field(state, "socks-enabled") != "off"
    ):
        print(
            "check-cli-lane: login did not reconcile a stale ferrox proxy:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    print("check-cli-lane: login reconciles a stale ferrox proxy")

    reset_fake_net(state)
    state_a = state / "moved-a"
    state_b = state / "moved-b"
    state_a.mkdir(exist_ok=True)
    state_b.mkdir(exist_ok=True)
    port = free_port()
    config = state / "moved.json"
    config.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "http", "listen": "127.0.0.1", "port": port}
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    env_a = env_for(state_a, curl=True, darwin=True)
    env_a["FERROX_STATE_DIR"] = str(state)
    env_a["FERROX_BIN"] = str(vpn_lane_binary(state))
    env_a["FERROX_FAKE_TRACE"] = "1"
    up = run(["up", "--config", str(config), "--vpn"], env_a)
    output = up.stdout + up.stderr
    if up.returncode != 0 or not (state / "system-proxy.ports").exists():
        print(
            f"check-cli-lane: the moved-dir lane did not arm:\n{output}",
            file=sys.stderr,
        )
        return 1
    env_b = env_for(state_b)
    env_b["FERROX_STATE_DIR"] = str(state)
    down = run(["down", "--all"], env_b)
    output = down.stdout + down.stderr
    calls = state_b / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if (
        down.returncode != 0
        or f"-setwebproxystate Wi-Fi off" not in recorded
        or proxy_field(state, "http-enabled") == "on"
        or (state / "system-proxy.ports").exists()
        or (state_a / "lane.pid").exists()
        or not config.exists()
    ):
        print(
            "check-cli-lane: down --all from another config dir did not clear the"
            f" moved lane's proxy:\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: down --all finds a lane armed under another config dir"
        " and clears its proxy"
    )
    return 0


def check_instance_ports(state: pathlib.Path) -> int:
    held = socket.socket()
    held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        held.bind(("127.0.0.1", 10808))
        held.listen(1)
    except OSError:
        held.close()
        held = None
    snapshot = state / "lane-snapshot.json"
    snapshot.unlink(missing_ok=True)
    try:
        env = env_for(state)
        env["FERROX_BIN"] = str(snapshot_binary(state))
        run = subprocess.run(
            [
                str(CLI),
                "up",
                "--foxy",
                "--email",
                "lane@example.com",
                "--password",
                "not-a-secret",
                "--fronts",
                "socks",
                "--instance",
                "two",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env,
        )
    finally:
        if held is not None:
            held.close()
    output = run.stdout + run.stderr
    if not snapshot.exists():
        print(
            f"check-cli-lane: a named instance never started (exit {run.returncode}):\n{output}",
            file=sys.stderr,
        )
        return 1
    port = json.loads(snapshot.read_text(encoding="utf-8"))["inbounds"][0]["port"]
    if port == 10808:
        print(
            f"check-cli-lane: a named instance took the busy default port {port}:\n{output}",
            file=sys.stderr,
        )
        return 1
    for gone in ("lane-two.pid", "lane-two.json"):
        if (state / gone).exists():
            print(
                f"check-cli-lane: a failed named instance left {gone} behind:\n{output}",
                file=sys.stderr,
            )
            return 1
    print(f"check-cli-lane: a named instance moved off the busy default to {port}")
    return 0


def check_instance_lifecycle(state: pathlib.Path) -> int:
    unnamed = subprocess.Popen(["sleep", "60"])
    named = subprocess.Popen(["sleep", "60"])
    port = free_port()
    (state / "lane.pid").write_text(f"{unnamed.pid}\n", encoding="utf-8")
    (state / "lane.json").write_text(
        '{"inbounds": [], "outbounds": []}\n', encoding="utf-8"
    )
    (state / "lane-two.pid").write_text(f"{named.pid}\n", encoding="utf-8")
    (state / "lane-two.json").write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": port}
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    try:
        status = subprocess.run(
            [str(CLI), "status", "--instance", "two"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env_for(state),
        )
        output = status.stdout + status.stderr
        if f"lane 'two' pid {named.pid}" not in output or str(port) not in output:
            print(
                f"check-cli-lane: status --instance lost the lane or its ports:\n{output}",
                file=sys.stderr,
            )
            return 1
        down = subprocess.run(
            [str(CLI), "down", "--instance", "two"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=WATCH,
            env=env_for(state),
        )
        output += down.stdout + down.stderr
        named.wait(timeout=WATCH)
        if (state / "lane-two.json").exists() or (state / "lane-two.pid").exists():
            print(
                f"check-cli-lane: down --instance left its lane behind:\n{output}",
                file=sys.stderr,
            )
            return 1
        if not (state / "lane.pid").exists() or not (state / "lane.json").exists():
            print(
                f"check-cli-lane: down --instance touched the unnamed lane:\n{output}",
                file=sys.stderr,
            )
            return 1
    finally:
        for lane in (unnamed, named):
            if lane.poll() is None:
                lane.terminate()
            lane.wait(timeout=WATCH)
        (state / "lane.pid").unlink(missing_ok=True)
        (state / "lane.json").unlink(missing_ok=True)
    print(
        "check-cli-lane: a named lane reports its own ports and down takes only that lane"
    )
    return 0


def exiting_lane_binary(state: pathlib.Path) -> pathlib.Path:
    binary = state / "fake-exiting-lane"
    binary.write_text(
        """#!/usr/bin/env python3
import json, os, socket, sys, time
config = sys.argv[sys.argv.index("-c") + 1]
with open(config, encoding="utf-8") as handle:
    document = json.load(handle)
state = os.environ["FERROX_CONF_DIR"]
with open(os.path.join(state, "fake-exiting-lane.pids"), "a", encoding="utf-8") as handle:
    handle.write(f"{os.getpid()}\\n")
bound = []
for inbound in document.get("inbounds", []):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", inbound["port"]))
    server.listen(16)
    bound.append(server)
time.sleep(1.5)
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary


def wait_for_proxy_clear(state: pathlib.Path) -> bool:
    deadline = time.monotonic() + WATCH
    while time.monotonic() < deadline:
        if (
            not (state / "system-proxy.ports").exists()
            and not (state / "system-proxy.state").exists()
            and not (state / "lane.pid").exists()
        ):
            return True
        time.sleep(0.1)
    return False


def vpn_config(state: pathlib.Path, name: str, port: int) -> pathlib.Path:
    path = state / name
    path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": port}
                ],
                "outbounds": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def check_vpn_lane_exit_clears_proxy(state: pathlib.Path) -> int:
    reset_fake_net(state)
    seed_service_proxy(state, "http", "proxy.corp", 3128)
    (state / "fake-services").write_text("Wi-Fi\nEthernet\n", encoding="utf-8")
    port = free_port()
    env = env_for(state, curl=True, darwin=True)
    env["FERROX_BIN"] = str(exiting_lane_binary(state))
    env["FERROX_FAKE_TRACE"] = "1"
    config = vpn_config(state, "vpn-exit.json", port)
    run = subprocess.run(
        [str(CLI), "up", "--config", str(config), "--vpn"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    output = run.stdout + run.stderr
    if run.returncode != 0:
        print(
            f"check-cli-lane: a --vpn lane exited {run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    if not (state / "system-proxy.ports").exists():
        print(f"check-cli-lane: --vpn did not arm the proxy:\n{output}", file=sys.stderr)
        return 1
    if not wait_for_proxy_clear(state):
        print(
            "check-cli-lane: the system proxy outlived its lane; the marker is still"
            f" armed:\n{output}",
            file=sys.stderr,
        )
        return 1
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    for service in ("Wi-Fi", "Ethernet"):
        if f"-setsocksfirewallproxystate {service} off" not in recorded:
            print(
                f"check-cli-lane: the lane exit did not clear {service}:\n{recorded}\n"
                f"{output}",
                file=sys.stderr,
            )
            return 1
    if (
        "-setwebproxy Wi-Fi proxy.corp 3128" not in recorded
        or proxy_field(state, "http-proxy") != "proxy.corp:3128"
        or proxy_field(state, "http-enabled") != "on"
        or proxy_field(state, "socks-enabled") != "off"
    ):
        print(
            "check-cli-lane: the lane exit did not restore the prior proxy:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    if (state / "system-proxy.owner").exists():
        print(
            f"check-cli-lane: the lane exit left the proxy owner behind:\n{output}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: a lane that exits after up clears the system proxy it armed"
        " and restores the prior settings"
    )
    return 0


def check_vpn_hangup_clears_proxy(state: pathlib.Path) -> int:
    reset_fake_net(state)
    seed_service_proxy(state, "http", "proxy.corp", 3128)
    port = free_port()
    env = env_for(state, curl=True, darwin=True)
    env["FERROX_BIN"] = str(vpn_lane_binary(state))
    env["FERROX_FAKE_TRACE"] = "1"
    run = subprocess.Popen(
        [str(CLI), "up", "--config", str(vpn_config(state, "vpn-hup.json", port)), "--vpn"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        output, _ = run.communicate(timeout=WATCH)
    except subprocess.TimeoutExpired:
        run.kill()
        output, _ = run.communicate()
        print(f"check-cli-lane: a --vpn lane kept running:\n{output}", file=sys.stderr)
        return 1
    if run.returncode != 0:
        print(
            f"check-cli-lane: a --vpn lane exited {run.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    supervisor = state / "system-proxy.supervisor"
    deadline = time.monotonic() + WATCH
    while not supervisor.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    if not supervisor.exists():
        print(
            f"check-cli-lane: --vpn left no supervisor to clear a dead lane:\n{output}",
            file=sys.stderr,
        )
        return 1
    try:
        os.killpg(run.pid, signal.SIGHUP)
    except ProcessLookupError:
        print(
            f"check-cli-lane: the --vpn process group was gone before the hangup:\n{output}",
            file=sys.stderr,
        )
        return 1
    if not wait_for_proxy_clear(state):
        print(
            "check-cli-lane: a terminal hangup left the system proxy armed:"
            f"\n{output}",
            file=sys.stderr,
        )
        return 1
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if (
        "-setsocksfirewallproxystate Wi-Fi off" not in recorded
        or "-setwebproxy Wi-Fi proxy.corp 3128" not in recorded
        or proxy_field(state, "http-proxy") != "proxy.corp:3128"
        or proxy_field(state, "socks-enabled") != "off"
    ):
        print(
            "check-cli-lane: a terminal hangup did not restore the prior proxy:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    pids = state / "fake-vpn-lane.pids"
    started = pids.read_text(encoding="utf-8").split() if pids.exists() else []
    deadline = time.monotonic() + WATCH
    while time.monotonic() < deadline:
        if all(not _alive(int(pid)) for pid in started):
            break
        time.sleep(0.1)
    for pid in started:
        if _alive(int(pid)):
            print(
                f"check-cli-lane: a terminal hangup left lane process {pid} running:"
                f"\n{output}",
                file=sys.stderr,
            )
            return 1
    print(
        "check-cli-lane: a terminal hangup stops the lane and clears the system proxy"
        " it armed"
    )
    return 0


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def check_stale_proxy_reconciled(state: pathlib.Path) -> int:
    def fabricate() -> None:
        reset_fake_net(state)
        seed_service_proxy(state, "socks", "127.0.0.1", 10808)
        (state / "system-proxy.ports").write_text("10808 -\n", encoding="utf-8")
        (state / "lane.pid").write_text("999999\n", encoding="utf-8")

    fabricate()
    status = subprocess.run(
        [str(CLI), "status"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env_for(state, darwin=True),
    )
    output = status.stdout + status.stderr
    calls = state / "networksetup.calls"
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    if (
        status.returncode == 0
        or "-setsocksfirewallproxystate Wi-Fi off" not in recorded
        or proxy_field(state, "socks-enabled") != "off"
        or (state / "system-proxy.ports").exists()
    ):
        print(
            f"check-cli-lane: status did not clear a stale armed proxy:\n{recorded}\n"
            f"{output}",
            file=sys.stderr,
        )
        return 1

    fabricate()
    port = free_port()
    env = env_for(state, curl=True, darwin=True)
    env["FERROX_BIN"] = str(vpn_lane_binary(state))
    env["FERROX_FAKE_TRACE"] = "1"
    up = subprocess.run(
        [str(CLI), "up", "--config", str(vpn_config(state, "vpn-stale.json", port)), "--vpn"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env,
    )
    output = up.stdout + up.stderr
    recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
    cleared = recorded.find("-setsocksfirewallproxystate Wi-Fi off")
    armed = recorded.find(f"-setsocksfirewallproxy Wi-Fi 127.0.0.1 {port}")
    subprocess.run(
        [str(CLI), "down"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=WATCH,
        env=env_for(state, darwin=True),
    )
    if up.returncode != 0:
        print(
            f"check-cli-lane: up over a stale proxy exited {up.returncode}:\n{output}",
            file=sys.stderr,
        )
        return 1
    if cleared == -1 or armed == -1 or cleared > armed:
        print(
            "check-cli-lane: up armed the new proxy before clearing the stale one:"
            f"\n{recorded}\n{output}",
            file=sys.stderr,
        )
        return 1
    print(
        "check-cli-lane: status and up clear a stale armed proxy before anything else"
    )
    return 0


CHECKS = (
    ("picker", check_picker),
    ("status", check_status),
    ("locations", check_locations),
    ("splits", check_splits),
    ("failed lane", check_failed_lane_is_closed),
    ("interrupted attempt", check_interrupted_attempt_leaves_nothing),
    ("config survives", check_config_survives),
    ("instance ports", check_instance_ports),
    ("vpn fronts", check_vpn_fronts),
    ("config fronts", check_config_fronts),
    ("vpn pac", check_vpn_pac),
    ("proxy readback", check_vpn_proxy_readback),
    ("vpn bypass", check_vpn_bypass),
    ("vpn platform", check_vpn_platform_refusal),
    ("proxy transaction", check_proxy_transaction),
    ("proxy cleanup", check_proxy_cleanup),
    ("lane exit", check_vpn_lane_exit_clears_proxy),
    ("hangup", check_vpn_hangup_clears_proxy),
    ("stale proxy", check_stale_proxy_reconciled),
    ("instance lifecycle", check_instance_lifecycle),
)


def main() -> int:
    # Every check owns its own config and state directory, so the only thing
    # they share is the port allocator: a warm run is twenty checks waiting on
    # fake tools rather than twenty checks one after another.
    workers = min(8, max(4, os.cpu_count() or 4))
    failed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        running = {}
        for name, check in CHECKS:
            state = pathlib.Path(tempfile.mkdtemp(prefix=f"ferrox-cli-{check.__name__}-"))
            running[pool.submit(check, state)] = name
        for job in concurrent.futures.as_completed(running):
            name = running[job]
            try:
                if job.result() != 0:
                    failed.append(name)
            except Exception:
                traceback.print_exc()
                failed.append(name)
    if failed:
        print(f"check-cli-lane: failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
