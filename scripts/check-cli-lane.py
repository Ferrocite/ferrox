#!/usr/bin/env python3
"""The CLI's carrier choice and lane report, checked without a lane.

A terminal gets the four-way prompt and the answer is the carrier the lane is
started with; a pipe is never prompted and takes auto. `status` reads the
carrier, the allowance and the uptime back from the lane it was given: a fake
pid and a synthetic log stand in for a live account, and the front refuses the
trace immediately because nothing listens on its port.
"""

from __future__ import annotations

import json
import os
import pathlib
import pty
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
    document = json.loads((state / "lane.json").read_text(encoding="utf-8"))
    return document["outbounds"][0]["settings"]["carrier"]


def check_picker(state: pathlib.Path) -> int:
    env = env_for(state)
    cases = [
        ("a typed h3 starts the lane on h3", b"4\n", "h3"),
        ("an empty answer takes auto", b"\n", "auto"),
    ]
    for label, answer, want in cases:
        (state / "lane.json").unlink(missing_ok=True)
        output = under_a_terminal(answer, env)
        if chosen_carrier(state) != want:
            print(
                f"check-cli-lane: {label}: the lane was handed "
                f"{chosen_carrier(state)!r}:\n{output}",
                file=sys.stderr,
            )
            return 1
        print(f"check-cli-lane: {label}")
    (state / "lane.json").unlink(missing_ok=True)
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


def main() -> int:
    state = pathlib.Path(tempfile.mkdtemp(prefix="ferrox-cli-lane-"))
    if check_picker(state) != 0:
        return 1
    return check_status(state)


if __name__ == "__main__":
    raise SystemExit(main())
