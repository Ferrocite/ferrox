#!/usr/bin/env python3
"""Report what one matrix run moved against the previous published run.

`matrix-results.json` carries medians, not a baseline. This reads two of them
and lists only the scenario/engine/metric cells that moved beyond the shared
runner's noise band. The refresh workflow uses `--require-change` so a nightly
run that measured nothing new leaves the committed markdown and charts alone.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchstats


def load(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        sys.exit(f"benchmark-delta: unreadable {path}: {exc}")


def selftest():
    """The noise boundary and both metric directions, without a matrix bundle."""
    checks = [
        ("throughput at threshold is noise", "throughput_mib_s", 100, 110, None),
        ("throughput above threshold is better", "throughput_mib_s", 100, 120,
         "improvement"),
        ("throughput below threshold is worse", "throughput_mib_s", 100, 80,
         "regression"),
        ("cpu above threshold is worse", "cpu_millis_per_gib", 100, 120,
         "regression"),
        ("cpu below threshold is better", "cpu_millis_per_gib", 100, 80,
         "improvement"),
        ("a missing side is coverage", "rss_mib", 100, None, "missing"),
        ("a new side is coverage", "rss_mib", None, 100, "new"),
    ]
    failed = 0
    for label, metric, before, after, want in checks:
        found = benchstats.change_for(metric, before, after)
        got = None if found is None else found["verdict"]
        ok = got == want
        failed += not ok
        print(f"selftest: {'ok  ' if ok else 'FAIL'} {label}: {got}")
    after = {
        "scenarios": [
            {
                "id": "vless-raw-down-1--srv-xray-core",
                "base": "vless-raw-down-1",
                "server": "xray-core",
                "medians": {"ferrox": {"throughput_mib_s": 120.0}},
            }
        ]
    }
    before = {
        "scenarios": [
            {
                "id": "vless-raw-down-1--srv-xray-core",
                "base": "vless-raw-down-1",
                "server": "xray-core",
                "medians": {"ferrox": {"throughput_mib_s": 100.0}},
            }
        ]
    }
    changes = benchstats.compare_results(after, before)
    ok = len(changes) == 1 and changes[0]["verdict"] == "improvement"
    failed += not ok
    print(f"selftest: {'ok  ' if ok else 'FAIL'} compare_results finds one move")
    text = benchstats.changes_markdown(changes)
    ok = "vless-raw-down-1" in text and "+20.0%" in text
    failed += not ok
    print(f"selftest: {'ok  ' if ok else 'FAIL'} markdown names the cell and change")
    after["scenarios"].append({"id": "new-cell", "base": "new-cell", "server": "xray-core", "medians": {}})
    changes = benchstats.compare_results(after, before)
    ok = any(change["verdict"] == "new scenario" for change in changes)
    failed += not ok
    print(f"selftest: {'ok  ' if ok else 'FAIL'} a new scenario counts as coverage")
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new", type=Path, help="this run's matrix-results.json")
    parser.add_argument("--baseline", type=Path, help="the previous matrix-results.json")
    parser.add_argument(
        "--threshold",
        type=float,
        default=benchstats.CHANGE_THRESHOLD,
        help="fraction a median must move to count (default 0.10)",
    )
    parser.add_argument(
        "--require-change",
        action="store_true",
        help="exit 0 only when at least one cell moved beyond the threshold",
    )
    parser.add_argument("--quiet", action="store_true", help="print nothing")
    parser.add_argument("--selftest", action="store_true", help="check the rules")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.new is None or args.baseline is None:
        parser.error("--new and --baseline are required unless --selftest is used")

    after = load(args.new)
    before = load(args.baseline)
    changes = benchstats.compare_results(after, before, args.threshold)
    if not args.quiet:
        print(
            benchstats.changes_markdown(
                changes, before.get("date", "the previous run"), args.threshold
            )
        )
    if args.require_change:
        return 0 if changes else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
