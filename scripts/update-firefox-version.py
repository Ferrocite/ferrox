#!/usr/bin/env python3
"""Keep the Foxy lane's pinned desktop Firefox identity on the current stable.

Runtime never fetches this: the binary carries one version, and CI moves it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHALLENGE = ROOT / "crates/ferrox-app/src/foxy_challenge.rs"
WORKFLOW = ROOT / ".github/workflows/update-firefox-version.yml"
VERSIONS = "https://product-details.mozilla.org/1.0/firefox_versions.json"

VERSION = re.compile(r'^pub\(crate\) const FIREFOX_VERSION: &str = "([^"]+)";$', re.M)
AGENT = re.compile(r'^const BROWSER_AGENT: &str =\n    "([^"]+)";$', re.M)
AGENT_SHAPE = re.compile(
    r"^Mozilla/5\.0 \(X11; Linux x86_64; rv:(\d+)\.0\) "
    r"Gecko/20100101 Firefox/(\d+)\.0$"
)


class PinError(Exception):
    pass


def stable_major(payload: str | bytes) -> str:
    try:
        document = json.loads(payload)
    except (TypeError, ValueError) as error:
        raise PinError(f"firefox_versions.json is not JSON: {error}") from error
    if not isinstance(document, dict):
        raise PinError("firefox_versions.json is not an object")
    version = document.get("LATEST_FIREFOX_VERSION")
    if not isinstance(version, str):
        raise PinError("firefox_versions.json has no LATEST_FIREFOX_VERSION")
    major = version.split(".", 1)[0]
    if not major.isdigit():
        raise PinError(f"LATEST_FIREFOX_VERSION is not a version: {version!r}")
    return major


def rewrite(source: str, major: str) -> str:
    if not major.isdigit():
        raise PinError(f"a Firefox major is numeric: {major!r}")
    version = f"{major}.0"
    agent = (
        f"Mozilla/5.0 (X11; Linux x86_64; rv:{version}) "
        f"Gecko/20100101 Firefox/{version}"
    )
    if not VERSION.search(source):
        raise PinError("foxy_challenge.rs has no FIREFOX_VERSION to move")
    if not AGENT.search(source):
        raise PinError("foxy_challenge.rs has no BROWSER_AGENT to move")
    source = VERSION.sub(f'pub(crate) const FIREFOX_VERSION: &str = "{version}";', source)
    return AGENT.sub(f'const BROWSER_AGENT: &str =\n    "{agent}";', source)


def check(source: str) -> str:
    version = VERSION.search(source)
    agent = AGENT.search(source)
    if not version or not agent:
        raise PinError("foxy_challenge.rs must carry FIREFOX_VERSION and BROWSER_AGENT")
    major = version.group(1).split(".", 1)[0]
    shape = AGENT_SHAPE.match(agent.group(1))
    if not shape:
        raise PinError(f"the pinned identity is not a desktop Firefox: {agent.group(1)!r}")
    if shape.groups() != (major, major):
        raise PinError(
            f"FIREFOX_VERSION {version.group(1)!r} and BROWSER_AGENT "
            f"{agent.group(1)!r} name different majors"
        )
    return version.group(1)


def check_tree() -> str:
    if not WORKFLOW.is_file():
        raise PinError(f"missing {WORKFLOW.relative_to(ROOT)}")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    if "scripts/update-firefox-version.py" not in workflow or "cron:" not in workflow:
        raise PinError("the updater workflow must run this script on a schedule")
    return check(CHALLENGE.read_text(encoding="utf-8"))


def fetch() -> str:
    with urllib.request.urlopen(VERSIONS, timeout=30) as response:
        return stable_major(response.read())


def update_tree(major: str) -> bool:
    source = CHALLENGE.read_text(encoding="utf-8")
    moved = rewrite(source, major)
    if moved == source:
        return False
    CHALLENGE.write_text(moved, encoding="utf-8", newline="\n")
    return True


def selftest() -> None:
    source = (
        'pub(crate) const FIREFOX_VERSION: &str = "159.0";\n'
        "const BROWSER_AGENT: &str =\n"
        '    "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0";\n'
        "const UNTOUCHED: &str = \"159.0\";\n"
    )
    assert check(source) == "159.0"
    moved = rewrite(source, "160")
    assert 'FIREFOX_VERSION: &str = "160.0"' in moved
    assert "rv:160.0" in moved and "Firefox/160.0" in moved
    assert "UNTOUCHED" in moved and '"159.0"' in moved
    assert stable_major(b'{"LATEST_FIREFOX_VERSION":"160.0.1"}') == "160"
    for payload in (b"{}", b'{"LATEST_FIREFOX_VERSION":"beta"}', b"not json"):
        try:
            stable_major(payload)
        except PinError:
            pass
        else:
            raise AssertionError(f"accepted {payload!r}")
    try:
        check(source.replace('FIREFOX_VERSION: &str = "159.0"', 'FIREFOX_VERSION: &str = "161.0"'))
    except PinError:
        pass
    else:
        raise AssertionError("accepted a mismatched pin")
    print("update-firefox-version: selftest green")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the committed pin")
    parser.add_argument("--selftest", action="store_true", help="check the updater itself")
    parser.add_argument("--print-version", action="store_true", help="print the pinned version")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0
    try:
        if args.check:
            version = check_tree()
            if args.print_version:
                print(version)
            else:
                print(f"firefox pin: {version} (desktop Firefox, consistent)")
            return 0
        major = fetch()
        changed = update_tree(major)
        version = check_tree()
        print(f"firefox pin: {version} ({'moved' if changed else 'already current'})")
        return 0
    except (PinError, OSError) as error:
        print(f"update-firefox-version: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
