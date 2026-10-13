"""Render the benchmark matrix charts from measured cells.

Reads per-scenario `cell.json` documents (written by `ferrox-bench
--json-report`, one per matrix cell) plus `manifest.txt`, assembles
`matrix-results.json`, and draws PNGs: throughput, CPU per GiB, peak RSS,
peak threads, cold start, harness ceiling, setup latency, binary size, and
the coverage grid. With `--readme`, rewrites the README section between the
benchmark-matrix markers from the same numbers, so the table cannot disagree
with the plots.

The chart set covers every image the two pinned harnesses publish, plus the
two only a shipped binary has: ZeroNet's throughput / CPU / idle+peak memory
/ connect-time / coverage / resolution / capability charts and xray-rust's
throughput / CPU / latency / memory / tunnel charts map to throughput,
cpu-per-gib, memory-rss, setup-latency, coverage and ceiling here; binary
size and cold start are ours, because nobody else charts what ships. Idle
RSS, per-packet latency and setup rate have no chart yet: the harness
refuses held-open flows, measures throughput rather than latency, and times
setup stages without rating them, so those cells are empty with the reason
in matrix.md rather than plotted from nothing.

Bars are medians of each cell's repeats. Whiskers are 95% bootstrap intervals
of that engine's own repeats (seeded); the Rust intervals in `cell.json` are
ratios for verdicts, not absolute error bars, and are never drawn as if they
were. `validate-benchmark-matrix.py` re-derives every verdict.
"""

import argparse
import json
import random
import statistics
import sys
from pathlib import Path

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import ListedColormap
    from matplotlib.patches import Patch
except ImportError:
    sys.exit(
        "matplotlib is required for charts only: "
        "pip install -r scripts/requirements-benchmark.txt"
    )

import benchstats

ENGINE_ORDER = ["xray-core", "ferrox", "zeronet", "sing-box", "xray-rust"]
PALETTE = {
    "xray-core": "#4C78A8",
    "ferrox": "#F58518",
    "zeronet": "#54A24B",
    "sing-box": "#E45756",
    "xray-rust": "#B279A2",
}
MISSING = "#BBBBBB"
STATUS_TEXT = {"pass": "\u2713", "fail": "\u2717", "empty": "\u2014"}
METRICS = ("throughput_mib_s", "cpu_millis_per_gib", "rss_mib",
           "threads_peak", "startup_seconds", "transfer_seconds")
HARNESS_BOUND = 0.85


def load_cells(input_dir):
    """scenario id -> cell document; fails closed on unreadable JSON."""
    cells = {}
    for path in sorted(Path(input_dir).glob("*/cell.json")):
        try:
            with open(path) as handle:
                doc = json.load(handle)
        except (OSError, ValueError) as exc:
            sys.exit(f"unreadable cell {path}: {exc}")
        scenario = doc.get("scenario") or path.parent.name
        cells[scenario] = doc
    if not cells:
        sys.exit(f"no cells under {input_dir}")
    return cells


def parse_manifest(path):
    """manifest.txt lines into a dict; unknown lines are kept, not dropped."""
    meta = {"raw": []}
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        sys.exit(f"unreadable manifest {path}: {exc}")
    meta["raw"] = lines
    for line in lines:
        for key in ("tier:", "date:", "host:", "rustc:", "repeats:"):
            if line.startswith(key):
                meta[key[:-1]] = line[len(key):].strip()
    meta["engines"] = {}
    for line in lines:
        if line.startswith("engine "):
            parts = line.split()
            name = parts[1].rstrip(":")
            info = {}
            for part in parts[2:]:
                if "=" in part:
                    key, _, value = part.partition("=")
                    info[key] = value
            meta["engines"][name] = info
    for key in ("runner:", "cpu:", "memory:", "load:", "go:", "only:",
                "exclude:", "probe-only:"):
        for line in lines:
            if line.startswith(key):
                meta[key[:-1]] = line[len(key):].strip()
    return meta


def run_values(cell, engine, metric):
    """Raw per-repeat values for one engine and metric, in repeat order.

    Nulls are not values: a run without a thread peak (the sampler found no
    source) contributes no sample rather than a zero that would read as
    "free".
    """
    for entry in cell.get("engines", []):
        if entry.get("name") == engine:
            out = []
            for run in entry.get("runs", []):
                value = run.get(metric)
                if isinstance(value, (int, float)):
                    out.append(value)
            return out
    return []


def ceiling_values(cell):
    """Harness ceiling samples for one cell, MiB/s, in repeat order."""
    values = []
    for value in cell.get("harness_ceilings_mib_s", []):
        if isinstance(value, (int, float)) and value > 0:
            values.append(value)
    return values


def cell_status(cell, engine):
    """pass (runs present), fail (named fault), or empty (named roadmap).

    Skipped engines never attempted the cell: gray, with the reason in the
    cell document, never red. Failed engines were attempted: red.
    """
    if run_values(cell, engine, "throughput_mib_s"):
        return "pass"
    for skipped in cell.get("skipped", []):
        if skipped.get("engine") == engine:
            return "empty"
    for failure in cell.get("failures", []):
        if failure.get("engine") == engine:
            return "fail"
    return "empty"


def cell_reason(cell, engine):
    """Named reason for a non-passing cell, skipped first."""
    for skipped in cell.get("skipped", []):
        if skipped.get("engine") == engine:
            return skipped.get("reason", "no reason recorded")
    return fail_reason(cell, engine)


def fail_reason(cell, engine):
    """Reason for a failed cell, for footnotes."""
    for failure in cell.get("failures", []):
        if failure.get("engine") == engine:
            return failure.get("reason", "no reason recorded")
    return "never attempted"


def bootstrap_interval(values, seed=0):
    """95% bootstrap interval of the mean, mirroring stats::bootstrap_ci."""
    if len(values) < 2:
        return None
    rng = random.Random(seed)
    count = len(values)
    means = []
    for _ in range(1000):
        total = sum(values[rng.randrange(count)] for _ in range(count))
        means.append(total / count)
    means.sort()
    return (means[25], means[974])


def footer(meta):
    """Provenance line on every chart: date, runner, host, tier, repeats."""
    engines = ", ".join(
        f"{name}@{info.get('sha256', '?')[:8]}"
        for name, info in sorted(meta.get("engines", {}).items())
    )
    return (
        f"ferrox benchmark matrix \u00b7 {meta.get('tier', '?')} \u00b7 "
        f"{meta.get('date', '?')} \u00b7 {meta.get('runner', '?')} \u00b7 "
        f"{meta.get('host', '?')} \u00b7 "
        f"N={meta.get('repeats', '?')} repeats \u00b7 whiskers 95% of own "
        f"repeats where drawn \u00b7 {engines}"
    )


def engines_present(cells):
    """Fixed order, so a chart cannot reorder itself between runs."""
    seen = set()
    for cell in cells.values():
        for engine in cell.get("engines", []):
            if engine.get("runs"):
                seen.add(engine["name"])
    return [name for name in ENGINE_ORDER if name in seen]


def gated_verdict(cell, engine, metric_word):
    """Verdict of the gated row for one engine and metric, if any."""
    for row in cell.get("rows", []):
        if not row.get("gates"):
            continue
        label = row.get("label", "")
        if f"({engine} vs" not in label:
            continue
        if metric_word == "throughput" and not label.startswith("throughput"):
            continue
        if metric_word == "cpu" and "cpu" not in label:
            continue
        if metric_word == "rss" and "rss" not in label:
            continue
        return row.get("verdict")
    return None


def metric_chart(scenarios, cells, metric, metric_word, unit, title, path, foot):
    """Grouped bars of medians with own-repeat whiskers; gaps stay labeled."""
    present = engines_present(cells)
    names = [s for s in scenarios if s in cells]
    if not names or not present:
        return None
    fig, ax = plt.subplots(figsize=(max(8.0, 1.6 * len(names)), 4.6))
    bar_width = 0.8 / max(1, len(present))
    missing = []
    for index, engine in enumerate(present):
        values, lower, upper, edges = [], [], [], []
        for scenario in names:
            samples = run_values(cells[scenario], engine, metric)
            if not samples:
                values.append(float("nan"))
                lower.append(0.0)
                upper.append(0.0)
                edges.append("black")
                missing.append(f"{scenario}/{engine}: {cell_reason(cells[scenario], engine)}")
                continue
            median = benchstats.median(samples)
            values.append(median)
            interval = bootstrap_interval(samples)
            if interval:
                lower.append(median - interval[0])
                upper.append(interval[1] - median)
            else:
                lower.append(0.0)
                upper.append(0.0)
            verdict = gated_verdict(cells[scenario], engine, metric_word)
            edges.append(
                {"better": "#2CA02C", "worse": "#D62728"}.get(verdict, "black")
            )
        xs = [p + (index - (len(present) - 1) / 2) * bar_width for p in range(len(names))]
        ax.bar(
            xs,
            values,
            width=bar_width,
            yerr=[lower, upper],
            capsize=3,
            label=engine,
            color=PALETTE.get(engine, MISSING),
            edgecolor=edges,
            linewidth=1.2,
            error_kw={"elinewidth": 1},
        )
        for x, value in zip(xs, values):
            if value == value:  # not NaN: label the median on the bar
                ax.text(x, value, f"{value:.0f}", ha="center", va="bottom", fontsize=7)
    ax.set_xticks(list(range(len(names))))
    ax.set_xticklabels(names, rotation=18, ha="right", fontsize=8)
    ax.set_ylabel(unit, fontsize=9)
    ax.set_title(title, fontsize=11)
    ax.legend(fontsize=8, ncol=len(present))
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    if missing:
        ax.text(
            0.0,
            -0.02,
            "no data: " + "; ".join(sorted(set(missing))),
            transform=ax.transAxes,
            fontsize=7,
            color="#666666",
            va="top",
            ha="left",
        )
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def setup_chart(cells, runs_dir, path, foot):
    """Setup-stage medians for setup scenarios, milliseconds.

    Each repeat's result.json already holds per-stage medians over its flows;
    the cell value is the median of those medians, stated as such.
    """
    names = sorted(s for s in cells if "setup" in s)
    if not names:
        return None
    stages = [
        ("tcp_connect_us", "tcp connect"),
        ("socks_method_us", "socks method"),
        ("socks_connect_us", "socks connect"),
        ("socks_setup_us", "socks setup"),
        ("total_us", "total"),
    ]
    present = engines_present(cells)
    fig, ax = plt.subplots(figsize=(max(8.0, 1.6 * len(names)), 4.6))
    bar_width = 0.8 / max(1, len(stages))
    labels = []
    for stage_index, (key, label) in enumerate(stages):
        column = []
        for engine in present:
            samples = []
            for scenario in names:
                samples.extend(setup_medians(cells[scenario], engine, runs_dir, key))
            column.append(benchstats.median(samples) / 1000.0 if samples else float("nan"))
        xs = [
            stage_index + (e - (len(present) - 1) / 2) * bar_width
            for e in range(len(present))
        ]
        ax.bar(
            xs,
            column,
            width=bar_width,
            color=[PALETTE.get(e, MISSING) for e in present],
            edgecolor="black",
            linewidth=0.5,
        )
        for x, value, engine in zip(xs, column, present):
            if value == value:
                ax.text(x, value, engine, ha="center", va="bottom", fontsize=6, rotation=90)
        labels.append(label)
    ax.set_xticks(list(range(len(stages))))
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("ms (median of per-repeat medians)", fontsize=9)
    ax.set_title("connection setup cost by stage", fontsize=11)
    ax.legend(
        handles=[Patch(color=PALETTE.get(e, MISSING), label=e) for e in present],
        fontsize=8,
        ncol=len(present),
    )
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def setup_medians(cell, engine, runs_dir, stage):
    """Per-repeat setup medians (µs) for one engine, from result.json files."""
    scenario = cell.get("scenario", "")
    values = []
    pattern = sorted((runs_dir / scenario / "runs").glob("*-run*"))
    for rundir in pattern:
        if not rundir.is_dir():
            continue
        if not (rundir.name.startswith(f"{engine}-run") or f"-{engine}-run" in rundir.name):
            continue
        path = rundir / "result.json"
        try:
            with open(path) as handle:
                doc = json.load(handle)
        except (OSError, ValueError):
            continue
        stage_doc = doc.get("setup", {}).get(stage)
        if isinstance(stage_doc, dict) and "median" in stage_doc:
            values.append(stage_doc["median"])
    return values


def coverage_chart(scenarios, cells, path, foot):
    """Protocol-by-scenario grid: measured pass, measured fail, or named gap."""
    present = engines_present(cells)
    names = [s for s in scenarios if s in cells]
    if not names or not present:
        return None
    grid = []
    for scenario in names:
        row = []
        for engine in present:
            status = cell_status(cells[scenario], engine)
            row.append({"pass": 2, "fail": 1, "empty": 0}[status])
        grid.append(row)
    fig, ax = plt.subplots(
        figsize=(max(7.0, 1.1 * len(present)), 0.7 * len(names) + 1.6)
    )
    cmap = ListedColormap([MISSING, "#E45756", "#54A24B"])
    ax.imshow(grid, cmap=cmap, vmin=0, vmax=2, aspect="auto")
    ax.set_xticks(range(len(present)))
    ax.set_xticklabels(present, fontsize=9)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=8)
    for row, scenario in enumerate(names):
        for col, engine in enumerate(present):
            status = cell_status(cells[scenario], engine)
            ax.text(
                col,
                row,
                STATUS_TEXT[status],
                ha="center",
                va="center",
                fontsize=10,
                color="white" if status == "pass" else "#333333",
            )
    ax.set_title("coverage: measured cells by scenario and engine", fontsize=11)
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def binary_size_chart(meta, path, foot):
    """Release binary size per engine, MiB."""
    sizes = {
        name: float(info["mib"])
        for name, info in meta.get("engines", {}).items()
        if "mib" in info
    }
    names = [name for name in ENGINE_ORDER if name in sizes]
    if not names:
        return None
    fig, ax = plt.subplots(figsize=(max(6.0, 1.2 * len(names)), 4.2))
    ax.bar(
        names,
        [sizes[name] for name in names],
        color=[PALETTE.get(name, MISSING) for name in names],
        edgecolor="black",
        linewidth=0.5,
    )
    for tick, name in enumerate(names):
        ax.text(tick, sizes[name], f"{sizes[name]:.1f}", ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("MiB", fontsize=9)
    ax.set_title("release binary size", fontsize=11)
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def ceiling_chart(scenarios, cells, path, foot):
    """Harness ceiling per scenario with each engine's share of it.

    The ceiling is the same validated loop with no engine in the path,
    measured per repeat beside the engines. A bar at the ceiling is the
    generator saturating, not the engine beating physics; rows at or above
    85% of it carry the HARNESS_BOUND mark. The spread line under each group
    is the runner's own variance measured, not assumed.
    """
    names = [s for s in scenarios if s in cells]
    present = engines_present(cells)
    if not names or not present:
        return None
    fig, ax = plt.subplots(figsize=(max(8.0, 1.6 * len(names)), 4.6))
    bar_width = 0.8 / max(1, len(present) + 1)
    for index, engine in enumerate(present):
        values = []
        for scenario in names:
            samples = run_values(cells[scenario], engine, "throughput_mib_s")
            ceiling = ceiling_values(cells[scenario])
            if not samples or not ceiling:
                values.append(float("nan"))
                continue
            values.append(benchstats.median(samples) / benchstats.median(ceiling))
        xs = [p + (index - len(present) / 2) * bar_width for p in range(len(names))]
        bars = ax.bar(
            xs, values, width=bar_width, label=engine,
            color=PALETTE.get(engine, MISSING), edgecolor="black", linewidth=0.5,
        )
        for x, value in zip(xs, values):
            if value == value:
                mark = " \u25c6" if value >= HARNESS_BOUND else ""
                ax.text(x, value, f"{value:.0%}{mark}", ha="center",
                        va="bottom", fontsize=7)
    ax.axhline(HARNESS_BOUND, color="#999999", linestyle="--", linewidth=1)
    ax.text(len(names) - 1, HARNESS_BOUND, " generator-bound (85%)",
            fontsize=7, color="#666666", va="bottom", ha="right")
    ax.set_xticks(list(range(len(names))))
    ax.set_xticklabels(names, rotation=18, ha="right", fontsize=8)
    ax.set_ylabel("share of the one-hop ceiling", fontsize=9)
    ax.set_title("throughput as a share of the harness ceiling (\u25c6 = generator-bound)", fontsize=11)
    ax.legend(fontsize=8, ncol=len(present))
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    spreads = []
    for scenario in names:
        ceiling = ceiling_values(cells[scenario])
        if len(ceiling) >= 2:
            spreads.append(f"{scenario}: ceiling spread "
                           f"{max(ceiling) / min(ceiling):.2f}x over {len(ceiling)}")
    if spreads:
        ax.text(0.0, -0.02, "runner spread: " + "; ".join(sorted(spreads)),
                transform=ax.transAxes, fontsize=7, color="#666666",
                va="top", ha="left")
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def threads_chart(scenarios, cells, path, foot):
    """Peak thread count per scenario, one bar per engine."""
    names = [s for s in scenarios if s in cells]
    present = engines_present(cells)
    if not names or not present:
        return None
    fig, ax = plt.subplots(figsize=(max(8.0, 1.6 * len(names)), 4.2))
    bar_width = 0.8 / max(1, len(present))
    for index, engine in enumerate(present):
        values = []
        for scenario in names:
            samples = run_values(cells[scenario], engine, "threads_peak")
            values.append(benchstats.median(samples) if samples else float("nan"))
        xs = [p + (index - (len(present) - 1) / 2) * bar_width for p in range(len(names))]
        ax.bar(xs, values, width=bar_width, label=engine,
               color=PALETTE.get(engine, MISSING), edgecolor="black", linewidth=0.5)
        for x, value in zip(xs, values):
            if value == value:
                ax.text(x, value, f"{value:.0f}", ha="center", va="bottom", fontsize=7)
    ax.set_xticks(list(range(len(names))))
    ax.set_xticklabels(names, rotation=18, ha="right", fontsize=8)
    ax.set_ylabel("peak threads", fontsize=9)
    ax.set_title("peak thread count by scenario (lower is better)", fontsize=11)
    ax.legend(fontsize=8, ncol=len(present))
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def startup_chart(scenarios, cells, path, foot):
    """Cold start to first listen per scenario, seconds."""
    names = [s for s in scenarios if s in cells]
    present = engines_present(cells)
    if not names or not present:
        return None
    fig, ax = plt.subplots(figsize=(max(8.0, 1.6 * len(names)), 4.2))
    bar_width = 0.8 / max(1, len(present))
    for index, engine in enumerate(present):
        values = []
        for scenario in names:
            samples = run_values(cells[scenario], engine, "startup_seconds")
            values.append(benchstats.median(samples) if samples else float("nan"))
        xs = [p + (index - (len(present) - 1) / 2) * bar_width for p in range(len(names))]
        ax.bar(xs, values, width=bar_width, label=engine,
               color=PALETTE.get(engine, MISSING), edgecolor="black", linewidth=0.5)
        for x, value in zip(xs, values):
            if value == value:
                ax.text(x, value, f"{value:.2f}s", ha="center", va="bottom", fontsize=7)
    ax.set_xticks(list(range(len(names))))
    ax.set_xticklabels(names, rotation=18, ha="right", fontsize=8)
    ax.set_ylabel("seconds", fontsize=9)
    ax.set_title("cold start to first listen (lower is better)", fontsize=11)
    ax.legend(fontsize=8, ncol=len(present))
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def assemble(cells_dir, meta):
    """matrix-results.json: cells plus medians, verdicts, manifest."""
    cells = load_cells(cells_dir)
    scenarios = []
    for scenario in sorted(cells):
        cell = cells[scenario]
        medians = {}
        for engine in cell.get("engines", []):
            name = engine["name"]
            values = {}
            for metric in METRICS:
                samples = run_values(cell, name, metric)
                if samples:
                    values[metric] = benchstats.median(samples)
            if values:
                medians[name] = values
        ceiling = ceiling_values(cell)
        scenarios.append(
            {
                "id": scenario,
                "workload": cell.get("workload", {}),
                "reference": cell.get("reference"),
                "gate_passed": cell.get("gate_passed"),
                "failures": cell.get("failures", []),
                "skipped": cell.get("skipped", []),
                "medians": medians,
                "ceilings_mib_s": ceiling,
                "ceiling_median_mib_s": benchstats.median(ceiling) if ceiling else None,
                "rows": cell.get("rows", []),
            }
        )
    return {
        "version": 2,
        "tier": meta.get("tier", "?"),
        "date": meta.get("date", "?"),
        "runner": meta.get("runner", "?"),
        "host": meta.get("host", "?"),
        "cpu": meta.get("cpu", "?"),
        "memory": meta.get("memory", "?"),
        "load": meta.get("load", "?"),
        "repeats": meta.get("repeats", "?"),
        "reference": "xray-core",
        "scenarios": scenarios,
        "manifest": meta.get("raw", []),
    }


def format_median(value):
    """README cell: whole MiB/s, or an em dash for no data."""
    if value is None:
        return "\u2014"
    return f"{value:.0f}"


def format_cost(value):
    """README cost cell: one decimal, or an em dash for no data."""
    if value is None:
        return "\u2014"
    return f"{value:.1f}"


def update_readme(readme_path, results, charts_dir, runner):
    """Rewrite the README section between the benchmark-matrix markers.

    One subsection per runner: a five-engine throughput table with the gated
    verdict, a cost table (CPU, RSS, threads, cold start), and every chart.
    The image paths carry the runner slug, so three runners' sections combine
    without colliding.
    """
    img = f"docs/benchmarks/charts/latest/{runner}"
    try:
        text = Path(readme_path).read_text()
    except OSError as exc:
        sys.exit(f"unreadable README {readme_path}: {exc}")
    start = "<!-- benchmark-matrix:start -->"
    end = "<!-- benchmark-matrix:end -->"
    if start not in text or end not in text:
        sys.exit("README has no benchmark-matrix markers")
    engines = ["ferrox", "xray-core", "zeronet", "sing-box", "xray-rust"]
    lines = [
        "",
        f"_Latest full matrix: {results['date']} on {results['runner']} "
        f"({results.get('cpu', '?')}), "
        f"tier {results['tier']}, reference `{results['reference']}`. "
        "Bars are medians with 95% intervals; empty cells name their reason in "
        "`docs/benchmarks/matrix.md`. Full bundles with replay commands live "
        "under `docs/benchmarks/results/`._",
        "",
        "| scenario | " + " | ".join(engines) + " | verdict |",
        "| -------- | " + " | ".join(["--------"] * len(engines)) + " | ------- |",
    ]
    for scenario in results["scenarios"]:
        medians = scenario["medians"]
        cells = [format_median(medians.get(e, {}).get("throughput_mib_s"))
                 for e in engines]
        verdicts = [
            row["verdict"]
            for row in scenario["rows"]
            if row.get("gates") and row["label"].startswith("throughput")
        ]
        verdict = verdicts[0] if verdicts else "unproven"
        lines.append(f"| `{scenario['id']}` | " + " | ".join(cells) + f" | {verdict} |")
    lines += [
        "",
        "Cost medians (CPU ms/GiB, peak RSS MiB, peak threads, cold start s):",
        "",
        "| scenario | engine | cpu | rss | threads | start |",
        "| -------- | ------ | --- | --- | ------- | ----- |",
    ]
    for scenario in results["scenarios"]:
        for engine in engines:
            values = scenario["medians"].get(engine, {})
            if not values:
                continue
            lines.append(
                f"| `{scenario['id']}` | {engine} | "
                f"{format_cost(values.get('cpu_millis_per_gib'))} | "
                f"{format_cost(values.get('rss_mib'))} | "
                f"{format_cost(values.get('threads_peak'))} | "
                f"{format_cost(values.get('startup_seconds'))} |"
            )
    lines += [
        "",
        f"![bulk throughput]({img}/throughput.png)",
        f"![CPU per GiB]({img}/cpu-per-gib.png)",
        f"![peak RSS]({img}/memory-rss.png)",
        f"![peak threads]({img}/threads.png)",
        f"![cold start]({img}/startup.png)",
        f"![share of ceiling]({img}/ceiling.png)",
        f"![setup latency]({img}/setup-latency.png)",
        f"![coverage]({img}/coverage.png)",
        f"![binary size]({img}/binary-size.png)",
        "",
    ]
    section = "\n".join(lines)
    before, _, rest = text.partition(start)
    area, _, after = rest.partition(end)
    area = replace_runner_block(area, runner, section)
    Path(readme_path).write_text(before + start + "\n" + area + end + after)
    print(f"README section rewritten in {readme_path}")


def replace_runner_block(area, runner, section):
    """Swap one runner's block inside the README matrix area.

    Blocks are delimited by `<!-- runner:<slug> -->` markers; a refresh for
    one runner leaves the others untouched. Pure string surgery, tested
    without matplotlib.
    """
    marker = "<!-- runner:"
    prelude, blocks = area, []
    idx = area.find(marker)
    if idx != -1:
        prelude, rest = area[:idx], area[idx:]
        while True:
            end = rest.find("-->\n")
            if end == -1:
                prelude += rest
                break
            name = rest[len(marker):end].strip()
            body_start = end + len("-->\n")
            nxt = rest.find(marker, body_start)
            if nxt == -1:
                body, rest = rest[body_start:], ""
            else:
                body, rest = rest[body_start:nxt], rest[nxt:]
            blocks.append([name, body])
            if not rest:
                break
    if not any(name == runner for name, _ in blocks):
        blocks.append([runner, ""])
    if "First full matrix run pending" in prelude:
        prelude = "\n"
    out = [prelude] if prelude else []
    for name, body in blocks:
        if name == runner:
            body = section + "\n"
        out.append(f"<!-- runner:{name} -->\n" + body)
    return "".join(out)


def main(argv=None):
    """Render charts for a measured matrix directory."""
    parser = argparse.ArgumentParser(description="render benchmark matrix charts")
    parser.add_argument("--input", required=True, help="matrix out dir with cells/")
    parser.add_argument("--charts", required=True, help="directory for PNGs")
    parser.add_argument("--results", required=True, help="matrix-results.json path")
    parser.add_argument("--readme", default=None, help="README path to update")
    parser.add_argument("--runner", default=None,
                        help="runner slug for README image paths "
                             "(defaults to the manifest's runner:)")
    args = parser.parse_args(argv)

    input_dir = Path(args.input)
    charts_dir = Path(args.charts)
    charts_dir.mkdir(parents=True, exist_ok=True)
    meta = parse_manifest(input_dir / "manifest.txt")
    runner = args.runner or meta.get("runner", "unknown")
    cells = load_cells(input_dir / "cells")
    foot = footer(meta)
    runs_dir = input_dir / "cells"

    results = assemble(input_dir / "cells", meta)
    with open(args.results, "w") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
        handle.write("\n")

    bulk = sorted(s for s in cells if "setup" not in s)
    made = [
        metric_chart(
            bulk, cells, "throughput_mib_s", "throughput", "MiB/s",
            "bulk throughput by scenario (higher is better)",
            str(charts_dir / "throughput.png"), foot,
        ),
        metric_chart(
            bulk, cells, "cpu_millis_per_gib", "cpu", "ms/GiB",
            "CPU per GiB by scenario (lower is better)",
            str(charts_dir / "cpu-per-gib.png"), foot,
        ),
        metric_chart(
            bulk, cells, "rss_mib", "rss", "MiB",
            "peak RSS by scenario (lower is better)",
            str(charts_dir / "memory-rss.png"), foot,
        ),
        threads_chart(bulk, cells, str(charts_dir / "threads.png"), foot),
        startup_chart(
            sorted(cells), cells, str(charts_dir / "startup.png"), foot
        ),
        ceiling_chart(bulk, cells, str(charts_dir / "ceiling.png"), foot),
        setup_chart(cells, runs_dir, str(charts_dir / "setup-latency.png"), foot),
        coverage_chart(
            sorted(cells), cells, str(charts_dir / "coverage.png"), foot
        ),
        binary_size_chart(meta, str(charts_dir / "binary-size.png"), foot),
    ]
    made = [path for path in made if path]
    print(f"charts: {len(made)} PNGs in {charts_dir}")
    for path in made:
        print(f"  {path}")
    if args.readme:
        update_readme(args.readme, results, str(charts_dir), runner)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
