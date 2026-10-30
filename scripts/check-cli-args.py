#!/usr/bin/env python3
"""Refuse what the CLI cannot start, and refuse it without waiting.

A value flag parsed with `shift 2` used to leave the flag in place when its
value was missing, so the parse loop spun forever. Each case below must exit
non-zero inside the watchdog and name the thing it is missing.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI = ROOT / "dist" / "ferrox-cli.sh"
# The CLI reconciles every service's proxy before it parses, which can outlast 15 s.
WATCH = 60

CASES = [
    ("up --psiphon-ready with a non-number", ["up", "--psiphon", "--psiphon-ready", "soon"], "--psiphon-ready wants seconds"),
    ("up --psiphon-mode with a bad mode", ["up", "--psiphon", "--psiphon-mode", "turbo"], "--psiphon-mode wants auto, cdn, conduit or direct"),
    ("up --psiphon-pool with a non-number", ["up", "--psiphon", "--psiphon-pool", "many"], "--psiphon-pool wants a number"),
    ("up --psiphon-workers with a non-number", ["up", "--psiphon", "--psiphon-workers", "many"], "--psiphon-workers wants a number"),
    ("up --psiphon-establish-timeout with a non-number", ["up", "--psiphon", "--psiphon-establish-timeout", "soon"], "--psiphon-establish-timeout wants seconds"),
    ("up --psiphon-establish-timeout with zero", ["up", "--psiphon", "--psiphon-establish-timeout", "0"], "--psiphon-establish-timeout wants seconds"),
    ("up --psiphon-cdn-profile with a bad profile", ["up", "--psiphon", "--psiphon-cdn-profile", "turbo"], "--psiphon-cdn-profile wants shirokhorshid"),
    ("up --vless with no link", ["up", "--vless"], "vless://"),
    ("up --vless with a non-link", ["up", "--vless", "notalink"], "vless://"),
    ("up --vmess without --uuid", ["up", "--vmess", "host:443"], "--uuid"),
    ("up --trojan without --password", ["up", "--trojan", "host:443"], "--password"),
    ("up --ss without --password", ["up", "--ss", "host:8388"], "--password"),
    ("up --config without a path", ["up", "--config"], "JSON config path"),
    ("up with an unknown carrier", ["up", "--carrier", "banana"], "h1, h2 or h3"),
    ("up with no lane", ["up"], "no outbound chosen"),
    ("ping outside locations", ["up", "--ping"], "--ping"),
    ("exclusions outside foxy", ["up", "--exclude-ports", "22"], "--exclude-ports"),
    ("a port outside 1-65535", ["up", "--foxy", "--socks", "70000"], "1 and 65535"),
    ("a port that is not a number", ["up", "--foxy", "--http", "http"], "port number"),
    ("two fronts on one port", ["up", "--foxy", "--socks", "1080", "--http", "1080"], "two fronts"),
    ("an instance named like a path", ["up", "--foxy", "--instance", "a/b"], "--instance"),
    ("--vpn on a named instance", ["up", "--foxy", "--instance", "work", "--vpn"], "system proxy"),
    ("--all outside down", ["status", "--all"], "--all"),
]


def main() -> int:
    state = pathlib.Path(tempfile.mkdtemp(prefix="ferrox-cli-args-"))
    env = dict(os.environ)
    env["FERROX_CONF_DIR"] = str(state)
    env["FERROX_BIN"] = shutil.which("true") or "/bin/true"
    for label, args, want in CASES:
        try:
            run = subprocess.run(
                [CLI, *args],
                capture_output=True,
                text=True,
                timeout=WATCH,
                stdin=subprocess.DEVNULL,
                env=env,
            )
        except subprocess.TimeoutExpired:
            print(
                f"check-cli-args: {label}: still running after {WATCH} s",
                file=sys.stderr,
            )
            return 1
        output = run.stdout + run.stderr
        if run.returncode == 0:
            print(
                f"check-cli-args: {label}: expected a refusal, got exit 0",
                file=sys.stderr,
            )
            print(output, file=sys.stderr)
            return 1
        if want not in output:
            print(
                f"check-cli-args: {label}: refusal does not name {want!r}",
                file=sys.stderr,
            )
            print(output, file=sys.stderr)
            return 1
        if list(state.iterdir()):
            print(
                f"check-cli-args: {label}: a refusal left state behind:"
                f" {sorted(p.name for p in state.iterdir())}",
                file=sys.stderr,
            )
            return 1
        print(f"check-cli-args: {label} refused")
    print(f"check-cli-args: {len(CASES)} refusal(s), no hang")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
