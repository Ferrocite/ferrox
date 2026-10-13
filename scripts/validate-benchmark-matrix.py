"""Validate a benchmark matrix bundle: schema, verdicts, digests, freshness.

Re-derives every verdict from its interval with the whole-interval rule and
every median from its repeats, so a matrix-results.json that disagrees with
its own cells fails. Checks the manifest digests against the committed cell
files, the PNGs it claims exist, and the README table against the medians it
prints. Mirrors `upstream/zeronet/.../validate_results.py:11` and the
`revalidate` this workspace runs on every result.json: a report nobody can
re-derive is a report nobody can check.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchstats

REQUIRED_CELL_KEYS = {
    "scenario",
    "workload",
    "machine",
    "reference",
    "engines",
    "rows",
    "gate_passed",
    "failures",
    "harness_ceilings_mib_s",
}
REQUIRED_RESULTS_KEYS = {
    "version",
    "tier",
    "date",
    "host",
    "repeats",
    "reference",
    "scenarios",
    "manifest",
}
ALWAYS_CHARTS = [
    "throughput.png",
    "cpu-per-gib.png",
    "memory-rss.png",
    "threads.png",
    "startup.png",
    "ceiling.png",
    "coverage.png",
    "binary-size.png",
]
SETUP_CHART = "setup-latency.png"
THROUGHPUT_ENGINES = ["ferrox", "xray-core", "zeronet", "sing-box", "xray-rust"]

failures = []


def fail(message):
    """Collect rather than raise: one run reports every disagreement."""
    failures.append(message)


def check(condition, message):
    """Record a failed expectation without stopping the rest of the checks."""
    if not condition:
        fail(message)


def load_json(path):
    """Parsed JSON or a recorded failure."""
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        fail(f"unreadable JSON {path}: {exc}")
        return None


def check_cell(path):
    """Schema plus re-derived verdicts for one cell document."""
    doc = load_json(path)
    if doc is None:
        return None
    missing = REQUIRED_CELL_KEYS - set(doc)
    check(not missing, f"{path}: missing keys {sorted(missing)}")
    for row in doc.get("rows", []):
        interval = row.get("interval")
        pair = None
        if interval is not None:
            pair = (interval.get("low"), interval.get("high"))
            check(
                all(isinstance(v, (int, float)) for v in pair),
                f"{path}: interval is not numeric in {row.get('label')}",
            )
        expected = benchstats.verdict_for(pair, row.get("direction"))
        check(
            row.get("verdict") == expected,
            f"{path}: verdict {row.get('verdict')} re-derives to "
            f"{expected} in {row.get('label')}",
        )
    check_repeat_digests(path, doc)
    return doc


def check_repeat_digests(path, doc):
    """Every repeat of an engine names the same binary as the cell header.

    A cell whose repeats ran different binaries is a comparison against two
    things, which reads as one row. The per-repeat result.json files carry
    their own digest; they must all agree with each other and the header.
    """
    runs_dir = Path(path).parent / "runs"
    if not runs_dir.is_dir():
        return
    by_engine = {}
    for result in sorted(runs_dir.glob("*/result.json")):
        entry = load_json(result)
        if entry is None:
            continue
        digest = entry.get("engine_sha256")
        name = None
        for part in result.parent.name.split("-run"):
            name = part
            break
        by_engine.setdefault(name, set()).add(digest)
    header = {
        engine["name"]: engine.get("binary_sha256")
        for engine in doc.get("engines", [])
    }
    for name, digests in by_engine.items():
        check(
            len(digests) == 1,
            f"{path}: engine {name} ran {len(digests)} different binaries",
        )
        if name in header:
            check(
                header[name] in digests,
                f"{path}: engine {name} header digest disagrees with its repeats",
            )


def check_medians(results):
    """Every plotted median re-derived from its repeats."""
    for scenario in results.get("scenarios", []):
        for engine, values in scenario.get("medians", {}).items():
            for metric, median in values.items():
                samples = []
                cell_path = None
                for cell_file in Path(args.cells).glob(f"{scenario['id']}/cell.json"):
                    cell_path = cell_file
                if cell_path is None:
                    continue
                cell = load_json(cell_path)
                if cell is None:
                    continue
                for entry in cell.get("engines", []):
                    if entry.get("name") == engine:
                        samples = [
                            run[metric]
                            for run in entry.get("runs", [])
                            if isinstance(run.get(metric), (int, float))
                        ]
                if samples:
                    check(
                        benchstats.median(samples) == median,
                        f"{scenario['id']}/{engine}/{metric}: median {median} "
                        f"re-derives to {benchstats.median(samples)}",
                    )


def check_manifest(results_dir, results):
    """Manifest digests match the committed files they name."""
    manifest = results.get("manifest", [])
    for line in manifest:
        if not line.startswith("engine "):
            continue
        parts = line.split()
        digest = None
        for part in parts[2:]:
            if part.startswith("sha256="):
                digest = part.split("=", 1)[1]
        check(digest is not None, f"manifest line without digest: {line}")


def check_charts(charts_dir, results):
    """Every chart the bundle should hold exists and is non-empty.

    The setup chart exists only when a setup scenario ran: requiring it
    unconditionally would fail every tier that does not measure setup.
    """
    wanted = list(ALWAYS_CHARTS)
    if any("setup" in scenario.get("id", "") for scenario in results.get("scenarios", [])):
        wanted.append(SETUP_CHART)
    for name in wanted:
        path = Path(charts_dir) / name
        check(path.is_file(), f"missing chart {path}")
        if path.is_file():
            check(path.stat().st_size > 0, f"empty chart {path}")


def check_readme(readme_path, charts_dir, results):
    """README tables match matrix-results.json medians, all five engines."""
    try:
        text = Path(readme_path).read_text()
    except OSError as exc:
        fail(f"unreadable README {readme_path}: {exc}")
        return
    start = "<!-- benchmark-matrix:start -->"
    end = "<!-- benchmark-matrix:end -->"
    if start not in text or end not in text:
        fail("README has no benchmark-matrix markers")
        return
    section = text.split(start)[1].split(end)[0]
    runner = results.get("runner", "?")
    check(
        f"<!-- runner:{runner} -->" in section,
        f"README has no block for runner {runner}",
    )
    for scenario in results.get("scenarios", []):
        medians = scenario.get("medians", {})
        cells = []
        for engine in THROUGHPUT_ENGINES:
            value = medians.get(engine, {}).get("throughput_mib_s")
            cells.append("\u2014" if value is None else f"{value:.0f}")
        expected = f"| `{scenario['id']}` | " + " | ".join(cells) + " |"
        check(
            expected in section,
            f"README row for {scenario['id']} does not match "
            f"matrix-results.json ({'/'.join(cells)})",
        )
    _ = charts_dir


def main(argv=None):
    """Validate a rendered matrix bundle."""
    global args
    parser = argparse.ArgumentParser(description="validate benchmark matrix bundle")
    parser.add_argument("--cells", required=True, help="cells/ directory")
    parser.add_argument("--results", required=True, help="matrix-results.json path")
    parser.add_argument("--charts", required=True, help="charts directory")
    parser.add_argument("--readme", default=None, help="README path to cross-check")
    args = parser.parse_args(argv)

    results_doc = load_json(args.results)
    if results_doc is None:
        print("\n".join(failures))
        return 1
    missing = REQUIRED_RESULTS_KEYS - set(results_doc)
    check(not missing, f"matrix-results.json missing keys {sorted(missing)}")
    for scenario in results_doc.get("scenarios", []):
        cell = check_cell(Path(args.cells) / scenario["id"] / "cell.json")
        if cell is not None:
            check(
                cell.get("scenario") == scenario["id"],
                f"cell scenario {cell.get('scenario')} filed under {scenario['id']}",
            )
            ran = any(
                engine.get("runs")
                for engine in cell.get("engines", [])
            )
            check(
                not ran or cell.get("harness_ceilings_mib_s"),
                f"{scenario['id']}: engines ran but no harness ceiling was recorded",
            )
    check_medians(results_doc)
    check_manifest(Path(args.cells).parent, results_doc)
    check_charts(args.charts, results_doc)
    if args.readme:
        check_readme(args.readme, args.charts, results_doc)
    if failures:
        print("\n".join(failures))
        return 1
    print(
        f"matrix valid: {len(results_doc.get('scenarios', []))} scenarios"
        + (", README consistent" if args.readme else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
