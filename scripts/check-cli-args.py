#!/usr/bin/env python3
"""Refuse what the CLI cannot start, and refuse it without waiting.

A value flag parsed with `shift 2` used to leave the flag in place when its
value was missing, so the parse loop spun forever. Each case below must exit
non-zero inside the watchdog and name the thing it is missing.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI = ROOT / "dist" / "ferrox-cli.sh"
WATCH = 15

CASES = [
    ("up --vless with no link", ["up", "--vless"], "vless://"),
    ("up --vless with a non-link", ["up", "--vless", "notalink"], "vless://"),
    ("up --vmess without --uuid", ["up", "--vmess", "host:443"], "--uuid"),
    ("up --trojan without --password", ["up", "--trojan", "host:443"], "--password"),
    ("up --ss without --password", ["up", "--ss", "host:8388"], "--password"),
    ("up --config without a path", ["up", "--config"], "JSON config path"),
    ("up with an unknown carrier", ["up", "--carrier", "banana"], "h1, h2 or h3"),
    ("up with no lane", ["up"], "no outbound chosen"),
]


def main() -> int:
    for label, args, want in CASES:
        try:
            run = subprocess.run(
                [CLI, *args], capture_output=True, text=True, timeout=WATCH
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
        print(f"check-cli-args: {label} refused")
    print(f"check-cli-args: {len(CASES)} refusal(s), no hang")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
