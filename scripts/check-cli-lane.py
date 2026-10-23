#!/usr/bin/env python3
"""The CLI's carrier choice and lane report, checked without a lane.

A terminal gets the four-way prompt and the answer is the carrier the lane is
started with; a pipe is never prompted and takes auto. `status` reads the
carrier, the allowance and the uptime back from the lane it was given: a fake
pid and a synthetic log stand in for a live account, and the front refuses the
trace immediately because nothing listens on its port. `locations --ping` is
given a fake catalogue: the rows must order by latency, keep a silent edge as
`no answer`, pin REC, and leave the readings out of the offline copy. The split
lists must reach the lane normalized, and a port outside 1-65535 must be refused
before the lane config is written. A lane that binds its front but carries no
flow must be stopped by `up` itself, with its pid file, config and proxy marker
removed and its port free again.
"""

from __future__ import annotations

import json
import os
import pathlib
import pty
import re
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI = ROOT / "dist" / "ferrox-cli.sh"
WATCH = 15


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def env_for(state: pathlib.Path) -> dict[str, str]:
    env = dict(os.environ)
    env["FERROX_CONF_DIR"] = str(state)
    env["FERROX_BIN"] = shutil.which("true") or "/bin/true"
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
    try:
        (state / "lane.pid").write_text(f"{lane.pid}\n", encoding="utf-8")
        (state / "lane.log").write_text(
            "foxy: allowance 8.0 GiB of 10.0 GiB, resets in 3h 5m\n"
            "foxy: carrier h2\n"
            "foxy: allowance 4.0 GiB of 10.0 GiB, resets in 2h 5m\n",
            encoding="utf-8",
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
    finally:
        lane.terminate()
        lane.wait(timeout=WATCH)
    output = run.stdout + run.stderr
    for want in (
        "up for 00:",
        "carrier: h2",
        "quota left: 4.0 GiB of 10.0 GiB, resets in 2h 5m",
    ):
        if want not in output:
            print(
                f"check-cli-lane: status does not print {want!r}:\n{output}",
                file=sys.stderr,
            )
            return 1
    print("check-cli-lane: status prints uptime, carrier and the last allowance")
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
    for stale in ("lane.json", "lane.pid", "fake-lane.pids", "system-proxy.ports"):
        (state / stale).unlink(missing_ok=True)
    (state / "system-proxy.ports").write_text("10808 8080\n", encoding="utf-8")
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
    print(
        "check-cli-lane: a lane that carries no flow is stopped, with its pid, config"
        " and proxy marker removed and its port free"
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


def main() -> int:
    state = pathlib.Path(tempfile.mkdtemp(prefix="ferrox-cli-lane-"))
    if check_picker(state) != 0:
        return 1
    if check_status(state) != 0:
        return 1
    if check_locations(state) != 0:
        return 1
    if check_splits(state) != 0:
        return 1
    if check_failed_lane_is_closed(state) != 0:
        return 1
    return check_config_survives(state)


if __name__ == "__main__":
    raise SystemExit(main())
