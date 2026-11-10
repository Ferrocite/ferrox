"""Fail a cell whose engine under test is below another comparator's median.

The harness already decides this once, on the `never_below` rows it publishes: a
`throughput (engine vs comparator)` row fails the cell when the engine's own
median is under that comparator's median, unless the runner's own generator
bound was the limit. This check does not restate the rule; it reads the verdict
the harness wrote and turns the gaps filed in `scripts/comparator-gaps.txt` into
warnings, so a new loss fails the matrix and a known one is fixed rather than
re-noticed on every run.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TOLERANCE = 0.10


def load(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"::error::{path}: {exc}", file=sys.stderr)
        return None


def load_baseline(path):
    """(scenario, comparator) -> (filed ratio, issue)."""
    filed = {}
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        raise SystemExit(f"::error::{path}: {exc}") from exc
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 4:
            raise SystemExit(
                f"::error::{path}:{number}: want scenario|comparator|ratio|issue, got {line!r}"
            )
        scenario, comparator, ratio, issue = parts
        try:
            filed[(scenario, comparator)] = (float(ratio), issue)
        except ValueError as exc:
            raise SystemExit(f"::error::{path}:{number}: {line!r}: {exc}") from exc
    return filed


def comparator_of(label):
    """The peer named in `throughput (engine vs comparator)`."""
    if " vs " not in label:
        return ""
    return label.split(" vs ", 1)[1].rstrip(")").strip()


def deficits(cells_dir):
    """Every peer row the harness called a deficit, plus the cells that were measured."""
    found = []
    measured = set()
    for path in sorted(Path(cells_dir).glob("*/cell.json")):
        cell = load(path)
        if cell is None:
            continue
        scenario = cell.get("scenario") or path.parent.name
        measured.add(scenario)
        for row in cell.get("rows", []):
            if not row.get("never_below") or not row.get("deficit"):
                continue
            label = str(row.get("label", ""))
            own = row.get("own_mib_s")
            other = row.get("comparator_mib_s")
            ratio = row.get("ratio")
            comparator = comparator_of(label)
            if not comparator or not isinstance(ratio, (int, float)):
                raise SystemExit(
                    f"::error::{scenario}: a deficit row names no comparator or ratio: {label!r}"
                )
            if isinstance(own, (int, float)) and isinstance(other, (int, float)) and own >= other:
                raise SystemExit(
                    f"::error::{scenario} {label}: flagged a deficit its own medians do not "
                    f"show ({own} MiB/s against {other} MiB/s)"
                )
            found.append(
                {
                    "scenario": scenario,
                    "comparator": comparator,
                    "ratio": float(ratio),
                    "text": f"{scenario} {label}: {ratio:.2f}x of {comparator}",
                }
            )
    return found, measured


def worse_than_filed(ratio, filed):
    """A measured deficit worse than its filed one by more than the tolerance."""
    return ratio < filed - TOLERANCE


def report(found, measured, baseline, stream=sys.stderr):
    """Errors for new or worse deficits; warnings for filed and fixed ones."""
    new, known, fixed = [], [], []
    for hole in found:
        filed = baseline.get((hole["scenario"], hole["comparator"]))
        if filed is None or worse_than_filed(hole["ratio"], filed[0]):
            new.append(hole)
        else:
            known.append((hole, filed[1]))
    seen = {(hole["scenario"], hole["comparator"]) for hole in found}
    for key, (ratio, issue) in sorted(baseline.items()):
        if key[0] in measured and key not in seen:
            fixed.append((key, ratio, issue))
    for hole in new:
        print(f"::error::per-comparator deficit: {hole['text']}", file=stream)
    for hole, issue in known:
        print(f"::warning::known per-comparator deficit ({issue}): {hole['text']}", file=stream)
    for (scenario, comparator), ratio, issue in fixed:
        print(
            f"::warning::{scenario} {comparator} no longer gaps (baseline {ratio:.2f}x, "
            f"{issue}); remove its line from scripts/comparator-gaps.txt",
            file=stream,
        )
    print(
        f"per-comparator rows checked: {len(found)} "
        f"(new {len(new)}, known {len(known)}, fixed {len(fixed)}; "
        f"tolerance {TOLERANCE:.2f})",
        file=stream,
    )
    return 1 if new else 0


def write_fixture(cells, scenario, comparator, ratio, deficit=True, runner_bound=False):
    own = ratio * 1000.0
    doc = {
        "scenario": scenario,
        "rows": [
            {
                "label": f"throughput (ferrox vs {comparator})",
                "gates": True,
                "never_below": True,
                "own_mib_s": own,
                "comparator_mib_s": 1000.0,
                "ratio": ratio,
                "deficit": deficit,
                "runner_bound": runner_bound,
            }
        ],
    }
    path = Path(cells) / scenario / "cell.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))


def run_self(cells, baseline):
    command = [sys.executable, __file__, "--cells", str(cells)]
    command += ["--baseline", str(baseline)] if baseline else ["--no-baseline"]
    return subprocess.run(command, text=True, capture_output=True)


def selftest():
    with tempfile.TemporaryDirectory() as temp:
        cells = Path(temp) / "cells"
        baseline = Path(temp) / "comparator-gaps.txt"
        write_fixture(cells, "vless-raw-down-8--srv-ferrox", "zeronet", 0.24)
        write_fixture(
            cells, "vless-ws-down-8--srv-ferrox", "aether", 0.90, deficit=False, runner_bound=True
        )

        baseline.write_text("# none\n")
        proc = run_self(cells, baseline)
        if proc.returncode == 0:
            return "a deficit with no filed line passed the check"
        if "vless-raw-down-8--srv-ferrox" not in proc.stderr:
            return f"the error does not name the cell: {proc.stderr}"

        baseline.write_text("vless-raw-down-8--srv-ferrox|zeronet|0.20|359\n")
        proc = run_self(cells, baseline)
        if proc.returncode != 0:
            return f"a filed deficit failed: {proc.stderr}"

        baseline.write_text("vless-raw-down-8--srv-ferrox|zeronet|0.40|359\n")
        proc = run_self(cells, baseline)
        if proc.returncode == 0:
            return "a deficit worse than its filed ratio passed"

        baseline.write_text("vless-raw-down-8--srv-ferrox|zeronet|0.40|359\n")
        proc = run_self(cells, None)
        if proc.returncode == 0:
            return "--no-baseline did not fail a deficit"

        baseline.write_text(
            "vless-raw-down-8--srv-ferrox|zeronet|0.24|359\n"
            "vless-ws-down-8--srv-ferrox|aether|0.50|359\n"
        )
        proc = run_self(cells, baseline)
        if proc.returncode != 0:
            return f"a cell whose peer row is not a deficit passed: {proc.stderr}"
        if "no longer gaps" not in proc.stderr:
            return f"a filed line whose cell no longer gaps was not reported: {proc.stderr}"
    print("check-comparator-rows selftest: passed")
    return None


def main():
    if "--selftest" in sys.argv:
        failure = selftest()
        if failure:
            print(f"::error::check-comparator-rows selftest: {failure}", file=sys.stderr)
            return 1
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", required=True, help="cells/ directory")
    parser.add_argument(
        "--baseline",
        default=str(Path(__file__).with_name("comparator-gaps.txt")),
        help="deficits filed already; new or worse ones still fail",
    )
    parser.add_argument("--no-baseline", action="store_true", help="fail on every deficit")
    args = parser.parse_args()
    if not Path(args.cells).is_dir():
        parser.error(f"{args.cells} is not a directory")
    baseline = {} if args.no_baseline else load_baseline(args.baseline)
    found, measured = deficits(args.cells)
    return report(found, measured, baseline)


if __name__ == "__main__":
    sys.exit(main())
