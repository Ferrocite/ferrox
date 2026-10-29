"""Render the benchmark matrix charts from measured cells.

Reads per-scenario `cell.json` documents (written by `ferrox-bench
--json-report`, one per matrix cell) plus `manifest.txt`, assembles
`matrix-results.json`, and draws one multi-metric PNG per test family (all
servers of that test together) plus the summary charts: CPU per GiB, peak RSS,
peak threads, cold start, harness ceiling, setup latency and binary size. With `--readme`, rewrites the README
section between the benchmark-matrix markers from the same numbers, so the
table cannot disagree with the plots.

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
import csv
import io
import json
import random
import sys
from pathlib import Path

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch
except ImportError:
    sys.exit(
        "matplotlib is required for charts only: "
        "pip install -r scripts/requirements-benchmark.txt"
    )

import benchstats

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "axes.titlesize": 10,
        "axes.labelsize": 8,
        "xtick.labelsize": 8,
        "ytick.labelsize": 9,
        "axes.edgecolor": "#CCCCCC",
        "axes.linewidth": 0.8,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
    }
)

PANELS = (
    ("throughput_mib_s", "throughput", "MiB/s", 1.0, "higher"),
    ("cpu_millis_per_gib", "CPU per GiB", "ms/GiB", 1.0, "lower"),
    ("rss_mib", "peak RSS", "MiB", 1.0, "lower"),
    ("threads_peak", "peak threads", "threads", 1.0, "lower"),
    ("startup_seconds", "cold start", "s", 1.0, "lower"),
    ("kernel_calls_per_gib", "kernel asks", "calls/MiB", 1.0 / 1024.0, "lower"),
)
SETUP_PANELS = (
    ("total_us", "setup total", "ms", 1.0 / 1000.0, "lower"),
    ("tcp_connect_us", "tcp connect", "ms", 1.0 / 1000.0, "lower"),
    ("socks_setup_us", "SOCKS setup", "ms", 1.0 / 1000.0, "lower"),
    ("rss_mib", "peak RSS", "MiB", 1.0, "lower"),
    ("threads_peak", "peak threads", "threads", 1.0, "lower"),
    ("startup_seconds", "cold start", "s", 1.0, "lower"),
)

ENGINE_ORDER = [
    "xray-core",
    "ferrox",
    "xray-core-rust",
    "zeronet",
    "sing-box",
    "xray-rust",
    "leaf",
]
PALETTE = {
    "xray-core": "#4C78A8",
    "ferrox": "#F58518",
    "xray-core-rust": "#72B7B2",
    "zeronet": "#54A24B",
    "sing-box": "#B279A2",
    "xray-rust": "#E45756",
    "leaf": "#B6992D",
}
MISSING = "#BBBBBB"
STATUS_TEXT = {"pass": "\u2713", "fail": "\u2717", "empty": "\u2014"}
METRICS = ("throughput_mib_s", "cpu_millis_per_gib", "rss_mib",
           "threads_peak", "startup_seconds", "kernel_calls_per_gib",
           "transfer_seconds")
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
                "exclude:", "probe-only:", "build-only:", "kernel:", "cpus:",
                "commit:", "run:", "attempt:", "event:", "ref:", "image:"):
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
    """One short provenance line, identical on every chart.

    The host, full manifest and engine digests live in README.md and
    matrix-results.json; repeating them under every plot makes the plot
    unreadable on a narrow bundle page.
    """
    commit = str(meta.get("commit", "?"))[:12]
    return (
        f"ferrox benchmark matrix \u00b7 {meta.get('tier', '?')} \u00b7 "
        f"{meta.get('date', '?')} \u00b7 {meta.get('runner', '?')} \u00b7 "
        f"commit {commit} \u00b7 N={meta.get('repeats', '?')} repeats \u00b7 "
        "whiskers 95% of own repeats"
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


def summary_bars(series, unit, title, path, foot, suffix="", reference=None, percent=False):
    """One horizontal bar per engine: the median of that engine's cell medians.

    The per-test plots carry the scenario detail; a 56-group bar chart is wider
    than a page and reads as noise, so the cost plots answer the one question a
    reader has here: which engine is cheapest overall, and over how many cells.
    """
    present = [name for name in ENGINE_ORDER if series.get(name)]
    if not present:
        return None
    values = [benchstats.median(series[name]) for name in present]
    fig, ax = plt.subplots(figsize=(7.6, max(2.4, 0.5 * len(present) + 1.3)))
    ax.barh(
        present,
        values,
        height=0.62,
        color=[PALETTE.get(name, MISSING) for name in present],
        edgecolor="#555555",
        linewidth=0.8,
    )
    span = max(values) if values else 1.0
    span = span if span > 0 else 1.0
    for tick, (name, value) in enumerate(zip(present, values)):
        ax.text(
            value + span * 0.02,
            tick,
            (f"{value:.0%}" if percent else f"{value:.1f}{suffix}")
            + f"  ({len(series[name])} cell" + ("" if len(series[name]) == 1 else "s") + ")",
            va="center",
            fontsize=8,
        )
    ax.set_xlim(0, span * 1.45)
    ax.invert_yaxis()
    ax.set_xlabel(unit, fontsize=9)
    ax.set_title(title, fontsize=11, loc="left")
    ax.grid(axis="x", linestyle=":", alpha=0.6)
    ax.set_axisbelow(True)
    if reference is not None:
        ax.axvline(reference, color="#999999", linestyle="--", linewidth=1)
        ax.text(reference, -0.45, f" {reference:.0%} generator bound", fontsize=7,
                color="#666666", va="top", ha="left")
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0)
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.10, 1, 1))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def metric_chart(scenarios, cells, metric, metric_word, unit, title, path, foot):
    """Median cost per engine across the measured cells, never a merged bar per scenario."""
    series = {}
    for engine in ENGINE_ORDER:
        values = []
        for scenario in scenarios:
            if scenario not in cells:
                continue
            samples = run_values(cells[scenario], engine, metric)
            if samples:
                values.append(benchstats.median(samples))
        if values:
            series[engine] = values
    return summary_bars(series, unit, title, path, foot)

def load_setup_index(cells_dir):
    """One pass over the result.json files, so a chart never re-globs them.

    The old per-panel read walked the whole runs tree for every setup stage and
    every engine, which is quadratic in the cells a bundle holds. The index is
    scenario -> engine -> stage -> values, built once before any chart is drawn.
    """
    index = {}
    for path in sorted(Path(cells_dir).glob("*/runs/*/result.json")):
        try:
            with open(path) as handle:
                doc = json.load(handle)
        except (OSError, ValueError):
            continue
        scenario = path.parent.parent.parent.name
        engine = path.parent.name.rsplit("-run", 1)[0]
        for stage, value in doc.get("setup", {}).items():
            if not isinstance(value, dict) or "median" not in value:
                continue
            index.setdefault(scenario, {}).setdefault(engine, {}).setdefault(
                stage, []
            ).append(value["median"])
    return index


def setup_chart(cells, setup_index, path, foot):
    """Setup-stage medians for setup scenarios, milliseconds.

    Stages and total sit on separate axes: a total several times the largest
    stage would flatten every stage bar if they shared one scale. Stages are
    rows and engines are bars, so long engine names never rotate into the bars.
    """
    names = sorted(s for s in cells if "setup" in s)
    if not names:
        return None
    stages = [
        ("tcp_connect_us", "tcp connect"),
        ("socks_method_us", "socks method"),
        ("socks_connect_us", "socks connect"),
        ("socks_setup_us", "socks setup"),
    ]
    total = ("total_us", "total")
    present = engines_present(cells)
    fig, (left, right) = plt.subplots(
        1, 2, figsize=(9.6, 4.6), gridspec_kw={"width_ratios": [3.0, 1.0]}
    )

    def draw(ax, specs):
        bar_height = 0.68 / max(1, len(present))
        row_height = 0.82 / max(1, len(present))
        for index, engine in enumerate(present):
            values = []
            for key, _ in specs:
                samples = []
                for scenario in names:
                    samples.extend(setup_medians(cells[scenario], engine, setup_index, key))
                values.append(
                    benchstats.median(samples) / 1000.0 if samples else float("nan")
                )
            ys = [
                stage + (index - (len(present) - 1) / 2) * row_height
                for stage in range(len(specs))
            ]
            ax.barh(
                ys,
                values,
                height=bar_height,
                color=PALETTE.get(engine, MISSING),
                edgecolor="#444444",
                linewidth=0.4,
                label=engine if specs is stages else None,
            )
        ax.set_yticks(range(len(specs)))
        if len(specs) == 1:
            ax.set_yticklabels([])
        else:
            ax.set_yticklabels([label for _, label in specs])
        ax.invert_yaxis()
        ax.set_xlabel("ms (median of per-repeat medians)", fontsize=8)
        ax.grid(axis="x", color="#E6E6E6", linewidth=0.6)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color("#CCCCCC")
        ax.tick_params(axis="y", length=0)

    draw(left, stages)
    draw(right, [total])
    left.set_title("per stage", fontsize=10, loc="left")
    right.set_title("total", fontsize=10, loc="left")
    fig.legend(
        ncol=len(present),
        loc="upper center",
        bbox_to_anchor=(0.5, 0.98),
        frameon=False,
        fontsize=8,
    )
    fig.text(0.5, 0.01, foot, ha="center", fontsize=7, color="#777777")
    fig.tight_layout(rect=(0, 0.06, 1, 0.93))
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def setup_medians(cell, engine, setup_index, stage):
    """Per-repeat setup medians (µs) for one engine, from the one-pass index."""
    scenario = cell.get("scenario", "")
    return setup_index.get(scenario, {}).get(engine, {}).get(stage, [])


def panel_samples(cell, engine, key, scale, setup_index):
    """One panel's per-repeat values, scaled into the unit the panel prints."""
    if key.endswith("_us"):
        values = setup_medians(cell, engine, setup_index, key)
    else:
        values = run_values(cell, engine, key)
    return [value * scale for value in values if isinstance(value, (int, float))]


def metric_label(value, unit):
    """The value printed beside one bar, in the panel's own unit."""
    if unit == "threads":
        return f"{value:.0f}"
    if unit == "s":
        return f"{value:.2f} s"
    if unit == "calls/MiB":
        return f"{value:.1f} calls/MiB" if value < 10 else f"{value:.0f} calls/MiB"
    if unit == "MiB/s":
        return f"{value:,.0f} MiB/s"
    return f"{value:.1f} {unit}"


def scenario_server(scenario):
    """The server leg of a scenario id, or empty for a standalone scenario."""
    return scenario.partition("--srv-")[2]


def ordered_servers(servers):
    """xray-core first, ferrox second, then any third server by name."""
    return sorted(
        servers, key=lambda name: ({"xray-core": 0, "ferrox": 1}.get(name, 2), name)
    )


def scenario_family_chart(base, group, path, foot, setup_index):
    """One image for every server of one test.

    Rows are engine *and* server, so the same engine's two server legs sit
    next to each other and a missing leg is a labelled gap. Server shade is
    the only difference between the two bars: the engine keeps its colour.
    The last two panels show the repeat distribution and its coefficient of
    variation, which is where a split xray-core cell becomes visible.
    """
    setup = "setup" in base
    panels = SETUP_PANELS if setup else PANELS
    by_server = {scenario_server(scenario): scenario for scenario in group}
    cells_by_server = {
        scenario_server(scenario): group[scenario] for scenario in group
    }
    servers = ordered_servers(by_server)
    present = [
        engine
        for engine in ENGINE_ORDER
        if any(
            panel_samples(cell, engine, key, scale, setup_index)
            for cell in group.values()
            for key, _, _, scale, _ in panels
        )
    ]
    rows = [
        (engine, server, cells_by_server.get(server))
        for engine in present
        for server in servers
    ]
    columns = 3 if setup else 4
    fig, axes = plt.subplots(
        2,
        columns,
        figsize=(16.0 if setup else 19.0, 9.2 if setup else 10.4),
        sharey=True,
    )
    fig.subplots_adjust(
        left=0.135 if not setup else 0.115,
        right=0.985,
        top=0.86,
        bottom=0.085,
        hspace=0.52,
        wspace=0.12,
    )
    if not present:
        for ax in axes.flat:
            ax.set_axis_off()
        axes.flat[0].text(
            0.5,
            0.5,
            "no engine landed a number in this test\nsee the coverage table",
            transform=axes.flat[0].transAxes,
            ha="center",
            va="center",
            fontsize=10,
            color="#333333",
        )
    reference_cell = group.get(by_server.get("xray-core", "")) or next(
        iter(group.values())
    )
    references = {}
    for key, _, _, scale, _ in panels:
        samples = panel_samples(reference_cell, "xray-core", key, scale, setup_index)
        references[key] = benchstats.median(samples) if samples else None

    def server_shade(index):
        return max(0.40, 0.95 - 0.22 * index)

    def row_label(engine, server):
        return engine if not server else f"{engine} · {server}"

    def finish(ax, index):
        if index % columns == 0:
            ax.set_yticks(range(len(rows)))
            ax.set_yticklabels([row_label(*row[:2]) for row in rows])
        else:
            ax.set_yticks(range(len(rows)))
            ax.tick_params(axis="y", labelleft=False)
        ax.set_ylim(len(rows) - 0.5, -0.5)
        ax.grid(axis="x", color="#E6E6E6", linewidth=0.6)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color("#CCCCCC")
        ax.tick_params(axis="y", length=0, pad=4)
        ax.tick_params(axis="x", length=2, colors="#555555")

    for index, (ax, (key, title, unit, scale, direction)) in enumerate(
        zip(axes.flat, panels)
    ):
        del direction
        reference = references.get(key)
        values = []
        lower = []
        upper = []
        measured = []
        for engine, server, cell in rows:
            samples = (
                panel_samples(cell, engine, key, scale, setup_index) if cell else []
            )
            if samples:
                median = benchstats.median(samples)
                interval = bootstrap_interval(samples)
                values.append(median)
                lower.append(max(0.0, median - interval[0]) if interval else 0.0)
                upper.append(max(0.0, interval[1] - median) if interval else 0.0)
                measured.append(True)
            else:
                values.append(0.0)
                lower.append(0.0)
                upper.append(0.0)
                measured.append(False)
        for server_index, server in enumerate(servers):
            positions = [i for i, row in enumerate(rows) if row[1] == server]
            edges = []
            for i in positions:
                engine, _, cell = rows[i]
                verdict = (
                    gated_verdict(cell, engine, "throughput")
                    if key == "throughput_mib_s" and cell
                    else None
                )
                edges.append(
                    {"better": "#2CA02C", "worse": "#D62728"}.get(verdict, "#444444")
                )
            ax.barh(
                positions,
                [values[i] for i in positions],
                xerr=[[lower[i] for i in positions], [upper[i] for i in positions]],
                height=0.58,
                color=[
                    PALETTE.get(rows[i][0], MISSING) for i in positions
                ],
                alpha=server_shade(server_index),
                edgecolor=edges,
                linewidth=0.9,
                error_kw={"elinewidth": 0.9, "capsize": 2, "capthick": 0.9},
            )
        span = max(
            max((value + up for value, up in zip(values, upper)), default=0.0),
            reference or 0.0,
        )
        span = span if span > 0 else 1.0
        for tick, (value, up) in enumerate(zip(values, upper)):
            if measured[tick]:
                ax.text(
                    value + up + span * 0.02,
                    tick,
                    metric_label(value, unit),
                    va="center",
                    fontsize=7.0 if len(rows) > 6 else 7.5,
                    color="#333333",
                )
            else:
                ax.text(
                    0,
                    tick,
                    "not measured",
                    va="center",
                    fontsize=6.8,
                    color="#999999",
                )
        if reference:
            ax.axvline(reference, color="#8A8A8A", linestyle=(0, (3, 2)), linewidth=0.9)
        ax.set_xlim(0, span * 1.28)
        ax.set_xlabel(unit, fontsize=8, labelpad=2)
        ax.set_title(title, fontsize=10, loc="left", pad=6)
        finish(ax, index)

    if not setup:
        distribution = axes.flat[len(panels)]
        spread_panel = axes.flat[len(panels) + 1]
        span = 0.0
        cv_max = 0.0
        for tick, (engine, server, cell) in enumerate(rows):
            samples = run_values(cell, engine, "throughput_mib_s") if cell else []
            if not samples:
                distribution.text(0, tick, "not measured", va="center",
                                  fontsize=6.8, color="#999999")
                spread_panel.text(0, tick, "not measured", va="center",
                                  fontsize=6.8, color="#999999")
                continue
            state = benchstats.spread(samples)
            span = max(span, max(samples))
            server_index = servers.index(server)
            distribution.plot(
                [min(samples), max(samples)], [tick, tick],
                color="#B0B0B0", linewidth=1.0, zorder=1,
            )
            jitter = (-0.08, 0.08, 0.0)
            distribution.scatter(
                samples,
                [tick + jitter[i % len(jitter)] for i in range(len(samples))],
                s=20,
                color=PALETTE.get(engine, MISSING),
                alpha=server_shade(server_index),
                edgecolor="white",
                linewidth=0.5,
                zorder=3,
            )
            distribution.plot(
                [benchstats.median(samples)], [tick], marker="|", markersize=10,
                markeredgewidth=1.6, color="#222222", zorder=4,
            )
            if state and state["state"] == "split":
                distribution.annotate(
                    "split",
                    xy=(max(samples), tick),
                    xytext=(4, 0),
                    textcoords="offset points",
                    color="#D62728",
                    fontsize=7,
                    va="center",
                )
            cv_values = [state["cv"] * 100.0] if state else [0.0]
            cv_max = max(cv_max, cv_values[0])
            spread_panel.barh(
                [tick],
                cv_values,
                height=0.58,
                color={"split": "#D62728", "wide": "#F2A93B"}.get(
                    state["state"] if state else "stable", "#7F7F7F"
                ),
                alpha=server_shade(server_index),
                edgecolor="#444444",
                linewidth=0.5,
            )
            spread_panel.text(
                cv_values[0] + 0.5,
                tick,
                f"{state['cv']:.0%}" if state else "—",
                va="center",
                fontsize=7,
                color="#333333",
            )
        distribution.set_xlim(0, (span if span > 0 else 1.0) * 1.28)
        distribution.axvline(
            references.get("throughput_mib_s") or 0,
            color="#8A8A8A",
            linestyle=(0, (3, 2)),
            linewidth=0.9,
        )
        distribution.set_xlabel("MiB/s", fontsize=8, labelpad=2)
        distribution.set_title("throughput repeats", fontsize=10, loc="left", pad=6)
        finish(distribution, len(panels))
        spread_panel.set_xlim(0, max(15.0, cv_max * 1.25))
        spread_panel.set_xlabel("coefficient of variation", fontsize=8, labelpad=2)
        spread_panel.set_title("throughput spread", fontsize=10, loc="left", pad=6)
        finish(spread_panel, len(panels) + 1)

    fig.suptitle(
        f"{base} · " + ("all servers" if len(servers) > 1 else (servers[0] or "no server")),
        x=0.011,
        y=0.972,
        ha="left",
        fontsize=15,
        fontweight="bold",
        color="#222222",
    )
    fig.text(
        0.011,
        0.93,
        "Medians of each cell's repeats; whiskers are 95% bootstrap intervals. "
        "Later servers are lighter. "
        + ("Lower is better." if setup else "Lower is better except throughput."),
        fontsize=8,
        color="#666666",
        ha="left",
    )
    handles = [
        Patch(
            facecolor="#777777",
            alpha=server_shade(i),
            label=f"server {server}" if server else "no server",
        )
        for i, server in enumerate(servers)
    ]
    if any(references.values()):
        handles.append(
            Line2D(
                [0], [0], color="#8A8A8A", linestyle=(0, (3, 2)), linewidth=1,
                label="xray-core baseline",
            )
        )
    fig.legend(
        handles=handles,
        loc="upper right",
        bbox_to_anchor=(0.985, 0.955),
        frameon=False,
        fontsize=8,
    )
    fig.text(0.011, 0.018, foot, ha="left", fontsize=7, color="#777777")
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return path

def coverage_table(results):
    """Markdown coverage grid: pass, fail, or the reason for a gap."""
    engines = [
        name
        for name in ENGINE_ORDER
        if any(name in scenario.get("medians", {}) or any(
            failure.get("engine") == name for failure in scenario.get("failures", [])
        ) for scenario in results.get("scenarios", []))
    ]
    lines = [
        "| scenario | server | " + " | ".join(engines) + " |",
        "| -------- | ------ | " + " | ".join(["---"] * len(engines)) + " |",
    ]
    reasons = []
    for scenario in results.get("scenarios", []):
        marks = []
        for engine in engines:
            if engine in scenario.get("medians", {}):
                marks.append("pass")
            elif any(f.get("engine") == engine for f in scenario.get("failures", [])):
                marks.append("fail")
            else:
                marks.append("\u2014")
                skipped = next(
                    (s for s in scenario.get("skipped", []) if s.get("engine") == engine),
                    None,
                )
                reasons.append(
                    f"`{scenario['id']}` / {engine}: "
                    + (skipped.get("reason", "not attempted") if skipped else "not attempted")
                )
        lines.append(
            f"| `{scenario.get('base', scenario['id'])}` | "
            f"{scenario.get('server') or '\u2014'} | " + " | ".join(marks) + " |"
        )
    if reasons:
        lines += ["", "Gaps:", ""] + [f"- {reason}" for reason in reasons]
    return "\n".join(lines)


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
    """Share of cells where each engine reached the harness ceiling."""
    series = {}
    for engine in ENGINE_ORDER:
        values = []
        for scenario in scenarios:
            if scenario not in cells:
                continue
            samples = run_values(cells[scenario], engine, "throughput_mib_s")
            ceiling = ceiling_values(cells[scenario])
            if samples and ceiling:
                share = benchstats.median(samples) / benchstats.median(ceiling)
                values.append(1.0 if share >= HARNESS_BOUND else 0.0)
        if values:
            series[engine] = values
    return summary_bars(
        series,
        "share of measured cells",
        "cells at or above 85% of the harness ceiling (higher means generator-bound)",
        path,
        foot,
        percent=True,
    )

def threads_chart(scenarios, cells, path, foot):
    """Median peak thread count per engine across cells."""
    series = {}
    for engine in ENGINE_ORDER:
        values = []
        for scenario in scenarios:
            if scenario not in cells:
                continue
            samples = run_values(cells[scenario], engine, "threads_peak")
            if samples:
                values.append(benchstats.median(samples))
        if values:
            series[engine] = values
    return summary_bars(
        series, "peak threads", "peak thread count (median over cells, lower is better)",
        path, foot,
    )

def startup_chart(scenarios, cells, path, foot):
    """Median cold start per engine across cells."""
    series = {}
    for engine in ENGINE_ORDER:
        values = []
        for scenario in scenarios:
            if scenario not in cells:
                continue
            samples = run_values(cells[scenario], engine, "startup_seconds")
            if samples:
                values.append(benchstats.median(samples))
        if values:
            series[engine] = values
    return summary_bars(
        series, "seconds", "cold start to first listen (median over cells, lower is better)",
        path, foot, suffix=" s",
    )

def assemble(cells_dir, meta):
    """matrix-results.json: cells plus medians, verdicts, manifest."""
    cells = load_cells(cells_dir)
    scenarios = []
    for scenario in sorted(cells):
        cell = cells[scenario]
        medians = {}
        spread = {}
        for engine in cell.get("engines", []):
            name = engine["name"]
            values = {}
            for metric in METRICS:
                samples = run_values(cell, name, metric)
                if samples:
                    values[metric] = benchstats.median(samples)
            if values:
                medians[name] = values
                samples = run_values(cell, name, "throughput_mib_s")
                if samples:
                    stats = benchstats.spread(samples)
                    if stats:
                        spread[name] = stats
        ceiling = ceiling_values(cell)
        base, _, server = scenario.partition("--srv-")
        scenarios.append(
            {
                "id": scenario,
                "base": base,
                "server": server,
                "workload": cell.get("workload", {}),
                "reference": cell.get("reference"),
                "gate_passed": cell.get("gate_passed"),
                "failures": cell.get("failures", []),
                "skipped": cell.get("skipped", []),
                "medians": medians,
                "spread": spread,
                "ceilings_mib_s": ceiling,
                "ceiling_median_mib_s": benchstats.median(ceiling) if ceiling else None,
                "rows": cell.get("rows", []),
            }
        )
    references = sorted(
        {scenario["reference"] for scenario in scenarios if scenario.get("reference")},
        key=lambda name: (name != "xray-core", name),
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
        "kernel": meta.get("kernel", "?"),
        "cpus": meta.get("cpus", "?"),
        "commit": meta.get("commit", "?"),
        "run_id": meta.get("run", "?"),
        "run_attempt": meta.get("attempt", "?"),
        "event": meta.get("event", "?"),
        "ref": meta.get("ref", "?"),
        "image": meta.get("image", "?").strip(),
        "repeats": meta.get("repeats", "?"),
        "reference": ", ".join(references) or "xray-core",
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


def scenario_name(scenario):
    """Base test name and server leg, for a heading or an axis."""
    return scenario.get("base", scenario["id"]), scenario.get("server") or "\u2014"


def leg_tables(results):
    """Client and server leg ratios, computed from the same-cell reference."""
    by_key = {
        (scenario.get("base"), scenario.get("server")): scenario
        for scenario in results.get("scenarios", [])
    }
    gap_lines = []
    rows = [
        "| test | client leg | server leg | client vs xray-core-rust |",
        "| ---- | ---------- | ---------- | ------------------------ |",
    ]
    for base in sorted({key[0] for key in by_key if key[0]}):
        if "setup" in base:
            continue
        xray_server = by_key.get((base, "xray-core"))
        ferrox_server = by_key.get((base, "ferrox"))
        if not xray_server or not ferrox_server:
            continue
        xray_ref = xray_server.get("medians", {}).get("xray-core", {}).get("throughput_mib_s")
        ferrox_on_xray = xray_server.get("medians", {}).get("ferrox", {}).get("throughput_mib_s")
        xray_on_ferrox = ferrox_server.get("medians", {}).get("xray-core", {}).get("throughput_mib_s")
        rust_on_xray = xray_server.get("medians", {}).get("xray-core-rust", {}).get("throughput_mib_s")
        client = ferrox_on_xray / xray_ref if ferrox_on_xray and xray_ref else None
        server = xray_on_ferrox / xray_ref if xray_on_ferrox and xray_ref else None
        rust = ferrox_on_xray / rust_on_xray if ferrox_on_xray and rust_on_xray else None
        def cell(value, measured):
            if value is None:
                return "missing **gap**" if measured else "\u2014"
            mark = " **gap**" if value < HARNESS_BOUND else ""
            return f"{value:.2f}x{mark}"
        rows.append(
            f"| `{base}` | {cell(client, bool(xray_ref))} | "
            f"{cell(server, bool(xray_ref))} | {cell(rust, bool(rust_on_xray))} |"
        )
        if client is None and xray_ref and not ferrox_on_xray:
            gap_lines.append(f"`{base}` client leg: ferrox landed no number on the xray-core server")
        elif client is not None and client < HARNESS_BOUND:
            gap_lines.append(
                f"`{base}` client leg {client:.2f}x: ferrox on xray-core "
                f"{ferrox_on_xray:.0f} MiB/s vs xray-core {xray_ref:.0f} MiB/s"
            )
        if server is None and xray_ref and not xray_on_ferrox:
            gap_lines.append(f"`{base}` server leg: xray-core landed no number on the ferrox server")
        elif server is not None and server < HARNESS_BOUND:
            gap_lines.append(
                f"`{base}` server leg {server:.2f}x: xray-core on ferrox "
                f"{xray_on_ferrox:.0f} MiB/s vs xray-core server {xray_ref:.0f} MiB/s"
            )
    return "\n".join(rows) + ("\n\nLeg gaps (below the 0.85 harness bound):\n\n" + "\n".join(f"- {line}" for line in gap_lines) if gap_lines else "")


def throughput_table(results):
    """Scenario-by-engine medians, the same table the README and bundle carry."""
    engines = [name for name in ENGINE_ORDER if any(
        name in scenario.get("medians", {}) for scenario in results.get("scenarios", [])
    )]
    lines = [
        "| scenario | server | " + " | ".join(engines) + " | verdict |",
        "| -------- | ------ | " + " | ".join(["--------"] * len(engines)) + " | ------- |",
    ]
    for scenario in results.get("scenarios", []):
        if "setup" in scenario.get("id", ""):
            continue
        medians = scenario.get("medians", {})
        cells = [format_median(medians.get(engine, {}).get("throughput_mib_s")) for engine in engines]
        verdicts = [
            row["verdict"]
            for row in scenario.get("rows", [])
            if row.get("gates") and row["label"].startswith("throughput")
        ]
        verdict = verdicts[0] if verdicts else "unproven"
        base, server = scenario_name(scenario)
        lines.append(f"| `{base}` | {server} | " + " | ".join(cells) + f" | {verdict} |")
    return "\n".join(lines)


def cost_table(results):
    """CPU, RSS, thread and startup medians per scenario and engine."""
    engines = [name for name in ENGINE_ORDER if any(
        name in scenario.get("medians", {}) for scenario in results.get("scenarios", [])
    )]
    lines = [
        "| scenario | server | engine | cpu | rss | threads | start | kernel |",
        "| -------- | ------ | ------ | --- | --- | ------- | ----- | ------ |",
    ]
    for scenario in results.get("scenarios", []):
        if "setup" in scenario.get("id", ""):
            continue
        base, server = scenario_name(scenario)
        for engine in engines:
            values = scenario.get("medians", {}).get(engine, {})
            if not values:
                continue
            lines.append(
                f"| `{base}` | {server} | {engine} | "
                f"{format_cost(values.get('cpu_millis_per_gib'))} | "
                f"{format_cost(values.get('rss_mib'))} | "
                f"{format_cost(values.get('threads_peak'))} | "
                f"{format_cost(values.get('startup_seconds'))} | "
                f"{format_cost(values.get('kernel_calls_per_gib'))} |"
            )
    return "\n".join(lines)


TABLE_METRICS = (
    ("throughput_mib_s", "throughput", "MiB/s"),
    ("cpu_millis_per_gib", "cpu", "ms/GiB"),
    ("rss_mib", "rss", "MiB"),
    ("threads_peak", "threads", "threads"),
    ("startup_seconds", "startup", "s"),
    ("kernel_calls_per_gib", "kernel", "calls/MiB"),
    ("transfer_seconds", "transfer", "s"),
)


def result_cell_status(scenario, engine):
    """pass, fail or empty for one engine in a matrix-results scenario."""
    if scenario.get("medians", {}).get(engine):
        return "pass", ""
    for skipped in scenario.get("skipped", []):
        if skipped.get("engine") == engine:
            return "empty", skipped.get("reason", "no reason recorded")
    for failure in scenario.get("failures", []):
        if failure.get("engine") == engine:
            return "fail", failure.get("reason", "no reason recorded")
    return "empty", "not attempted"


def result_verdict(scenario):
    """The gated throughput verdict and the engine it judges."""
    for row in scenario.get("rows", []):
        if row.get("gates") and str(row.get("label", "")).startswith("throughput"):
            label = str(row.get("label", ""))
            engine = ""
            if "(" in label:
                engine = label.split("(", 1)[1].split(" vs ", 1)[0].strip()
            return engine, row.get("verdict", "unproven")
    return "", "unproven"


def table_rows(results):
    """One row per scenario, engine and metric, including the missing sides."""
    rows = []
    for scenario in results.get("scenarios", []):
        medians = scenario.get("medians", {})
        verdict_engine, verdict = result_verdict(scenario)
        engines = {name for name in medians if name}
        engines.update(
            item["engine"] for item in scenario.get("skipped", []) if item.get("engine")
        )
        engines.update(
            item["engine"] for item in scenario.get("failures", []) if item.get("engine")
        )
        ordered = [name for name in ENGINE_ORDER if name in engines]
        ordered += sorted(engines - set(ordered))
        for engine in ordered:
            status, reason = result_cell_status(scenario, engine)
            values = medians.get(engine, {})
            for metric, label, unit in TABLE_METRICS:
                value = values.get(metric)
                rows.append(
                    {
                        "run_date": results.get("date", "?"),
                        "runner": results.get("runner", "?"),
                        "tier": results.get("tier", "?"),
                        "repeats": results.get("repeats", "?"),
                        "scenario": scenario.get("id", "?"),
                        "base": scenario.get("base", ""),
                        "server": scenario.get("server", ""),
                        "engine": engine,
                        "metric": label,
                        "value": "" if value is None else value,
                        "unit": unit,
                        "status": status,
                        "reason": reason,
                        "verdict": verdict
                        if engine == verdict_engine and label == "throughput"
                        else "",
                        "reference": scenario.get("reference") or "",
                    }
                )
    return rows


def table_csv(results):
    """The tidy table, one measured or missing value per row."""
    fields = [
        "run_date", "runner", "tier", "repeats", "scenario", "base", "server",
        "engine", "metric", "value", "unit", "status", "reason", "verdict",
        "reference",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(table_rows(results))
    return buffer.getvalue()


def table_markdown(results):
    """The complete text table: no image links, so it stays small and greppable."""
    lines = [
        f"# ferrox benchmark matrix table \u2014 {results.get('date', '?')} on {results.get('runner', '?')}",
        "",
        (
            f"Tier `{results.get('tier', '?')}`, reference "
            f"`{results.get('reference', 'xray-core')}`, "
            f"{results.get('repeats', '?')} repeats, host `{results.get('host', '?')}`, "
            f"CPU `{results.get('cpu', '?')}`, memory `{results.get('memory', '?')}`, "
            f"load `{results.get('load', '?')}`, kernel `{results.get('kernel', '?')}`, "
            f"commit `{results.get('commit', '?')}` (run `{results.get('run_id', '?')}`). "
            "Text-only companion to `README.md`: the same medians, verdicts and "
            "coverage, with no images."
        ),
        "",
        (
            "`table.csv` is the tidy long form; only the judged engine's `throughput` "
            "row carries the gated `verdict`, so it is not repeated across unrelated "
            "metrics. `distribution.csv` carries each engine's repeat spread for the "
            "same cells."
        ),
        "",
    ]
    if results.get("changes") is not None:
        lines += [
            "## Changes since the previous run",
            "",
            benchstats.changes_markdown(
                results["changes"],
                results.get("previous_date", "the previous run"),
                results.get("change_threshold", benchstats.CHANGE_THRESHOLD),
            ),
            "",
        ]
    lines += [
        "## Throughput by test",
        "",
        throughput_table(results),
        "",
        "## Ferrox against the reference, leg by leg",
        "",
        leg_tables(results),
        "",
        "The client leg compares ferrox and xray-core as clients of the xray-core server; "
        "the server leg compares xray-core as a client of the ferrox and xray-core servers. "
        "A value below 0.85 is marked `gap` and is a hole in this tree, not variance.",
        "",
        "## Cost",
        "",
        cost_table(results),
        "",
        "## Repeat spread",
        "",
        spread_markdown(results),
        "",
        "## Coverage",
        "",
        coverage_table(results),
        "",
    ]
    return "\n".join(lines)


def write_table_files(input_dir, results):
    """Write the small table pair beside the bundle's charts."""
    markdown_path = Path(input_dir) / "table.md"
    csv_path = Path(input_dir) / "table.csv"
    distribution_path = Path(input_dir) / "distribution.csv"
    markdown_path.write_text(table_markdown(results) + "\n")
    csv_path.write_text(table_csv(results))
    distribution_path.write_text(distribution_csv(results))
    print(
        f"table written to {markdown_path}, {csv_path} and {distribution_path}"
    )


def distribution_rows(results):
    """One row per scenario and engine: the throughput repeat spread."""
    rows = []
    for scenario in results.get("scenarios", []):
        for engine, stats in sorted(scenario.get("spread", {}).items()):
            rows.append(
                {
                    "run_date": results.get("date", "?"),
                    "runner": results.get("runner", "?"),
                    "tier": results.get("tier", "?"),
                    "scenario": scenario.get("id", "?"),
                    "base": scenario.get("base", ""),
                    "server": scenario.get("server", ""),
                    "engine": engine,
                    "n": stats.get("n", 0),
                    "min": stats.get("min"),
                    "median": stats.get("median"),
                    "max": stats.get("max"),
                    "mean": stats.get("mean"),
                    "stdev": stats.get("stdev"),
                    "cv": stats.get("cv"),
                    "ratio": stats.get("ratio"),
                    "gap_ratio": stats.get("gap_ratio"),
                    "state": stats.get("state", ""),
                }
            )
    return rows


def distribution_csv(results):
    """The tidy repeat-spread table, separate from the metric table."""
    fields = [
        "run_date", "runner", "tier", "scenario", "base", "server", "engine",
        "n", "min", "median", "max", "mean", "stdev", "cv", "ratio",
        "gap_ratio", "state",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(distribution_rows(results))
    return buffer.getvalue()


def spread_markdown(results):
    """Only the cells whose repeats moved enough to explain a median."""
    flagged = [
        row for row in distribution_rows(results) if row["state"] in ("split", "wide")
    ]
    if not flagged:
        return "No cell's throughput repeats separated by more than the spread rule."
    lines = [
        "`split` means the repeats separate by at least 1.25x with a gap over "
        "half the range; `wide` is a coefficient of variation above 10%. "
        "Medians alone hide both.",
        "",
        "| scenario | server | engine | repeats | median | min | max | CV | state |",
        "| -------- | ------ | ------ | ------: | -----: | --: | --: | -: | ----- |",
    ]
    for row in flagged:
        lines.append(
            f"| `{row['base']}` | {row['server'] or '—'} | {row['engine']} | "
            f"{row['n']} | {row['median']:.0f} | {row['min']:.0f} | "
            f"{row['max']:.0f} | {row['cv']:.0%} | {row['state']} |"
        )
    return "\n".join(lines)


def matrix_markdown(results, image_prefix):
    """The complete bundle document: tables, one multi-metric image per test, coverage."""
    scenarios = results.get("scenarios", [])
    bulk = any("setup" not in scenario.get("id", "") for scenario in scenarios)
    setup = any("setup" in scenario.get("id", "") for scenario in scenarios)
    lines = [
        f"# ferrox benchmark matrix \u2014 {results.get('date', '?')} on {results.get('runner', '?')}",
        "",
        f"Tier `{results.get('tier', '?')}`, reference `{results.get('reference', 'xray-core')}`, "
        f"{results.get('repeats', '?')} repeats, host `{results.get('host', '?')}`, "
        f"CPU `{results.get('cpu', '?')}`, memory `{results.get('memory', '?')}`, "
        f"load `{results.get('load', '?')}`, kernel `{results.get('kernel', '?')}`, "
        f"commit `{results.get('commit', '?')}` (run `{results.get('run_id', '?')}`). "
        "Bars are medians; whiskers are 95% bootstrap intervals over the engine's own "
        "repeats.",
        "",
    ]
    if results.get("changes") is not None:
        lines += [
            "## Changes since the previous run",
            "",
            benchstats.changes_markdown(
                results["changes"],
                results.get("previous_date", "the previous run"),
                results.get("change_threshold", benchstats.CHANGE_THRESHOLD),
            ),
            "",
        ]
    lines += [
        "## Throughput by test",
        "",
        throughput_table(results),
        "",
        "## Ferrox against the reference, leg by leg",
        "",
        leg_tables(results),
        "",
        "The client leg compares ferrox and xray-core as clients of the xray-core server; "
        "the server leg compares xray-core as a client of the ferrox and xray-core servers. "
        "A value below 0.85 is marked `gap` and is a hole in this tree, not variance.",
        "",
        "## One image per test",
        "",
        "Each image is one test with every server side by side: throughput, CPU per "
        "GiB, peak RSS, peak threads, cold start, kernel asks per MiB, the throughput "
        "repeats and their spread, from the same repeats. A panel the runner cannot "
        "see says so; it is never drawn as zero.",
        "",
    ]
    families = {}
    for scenario in results.get("scenarios", []):
        base, server = scenario_name(scenario)
        families.setdefault(base, []).append(server)
    for base, servers in sorted(families.items()):
        servers = ordered_servers(set(servers))
        lines += [
            f"### `{base}`",
            "",
            f"Servers: {', '.join(servers)}.",
            "",
            f"![{base}]({image_prefix}/scenarios/{base}.png)",
            "",
        ]
    lines += [
        "## Cost",
        "",
        cost_table(results),
        "",
        "## Repeat spread",
        "",
        spread_markdown(results),
        "",
        "## Coverage",
        "",
        coverage_table(results),
        "",
        "## Other charts",
        "",
    ]
    if bulk:
        lines += [
            f"![CPU per GiB]({image_prefix}/cpu-per-gib.png)",
            "",
            f"![peak RSS]({image_prefix}/memory-rss.png)",
            "",
            f"![peak threads]({image_prefix}/threads.png)",
            "",
        ]
    lines += [
        f"![cold start]({image_prefix}/startup.png)",
        "",
    ]
    if bulk:
        lines += [
            f"![cells at harness ceiling]({image_prefix}/ceiling.png)",
            "",
        ]
    if setup:
        lines += [
            f"![setup latency]({image_prefix}/setup-latency.png)",
            "",
        ]
    lines += [
        f"![binary size]({image_prefix}/binary-size.png)",
        "",
    ]
    return "\n".join(lines)


def write_bundle_markdown(input_dir, results):
    """Put the complete document in the bundle, beside the plots it embeds."""
    path = Path(input_dir) / "README.md"
    path.write_text(matrix_markdown(results, "charts"))
    print(f"bundle document written to {path}")


def update_readme(readme_path, results, charts_dir, runner):
    """Rewrite one runner's README block from the same numbers as the charts."""
    del charts_dir
    img = f"docs/benchmarks/charts/latest/{runner}"
    try:
        text = Path(readme_path).read_text()
    except OSError as exc:
        sys.exit(f"unreadable README {readme_path}: {exc}")
    start = "<!-- benchmark-matrix:start -->"
    end = "<!-- benchmark-matrix:end -->"
    if start not in text or end not in text:
        sys.exit("README has no benchmark-matrix markers")
    section = matrix_markdown(results, img)
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
    parser.add_argument("--previous", default=None,
                        help="previous matrix-results.json for the change table")
    parser.add_argument("--change-threshold", type=float,
                        default=benchstats.CHANGE_THRESHOLD,
                        help="fraction a median must move to count (default 0.10)")
    args = parser.parse_args(argv)

    input_dir = Path(args.input)
    charts_dir = Path(args.charts)
    charts_dir.mkdir(parents=True, exist_ok=True)
    (charts_dir / "scenarios").mkdir(parents=True, exist_ok=True)
    meta = parse_manifest(input_dir / "manifest.txt")
    runner = args.runner or meta.get("runner", "unknown")
    cells = load_cells(input_dir / "cells")
    foot = footer(meta)
    setup_index = load_setup_index(input_dir / "cells")

    results = assemble(input_dir / "cells", meta)
    if args.previous:
        previous = json.loads(Path(args.previous).read_text())
        results["changes"] = benchstats.compare_results(
            results, previous, args.change_threshold
        )
        results["previous_date"] = previous.get("date", "the previous run")
        results["change_threshold"] = args.change_threshold
    with open(args.results, "w") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
        handle.write("\n")
    write_table_files(input_dir, results)

    bulk = sorted(s for s in cells if "setup" not in s)
    families = {}
    for scenario, cell in cells.items():
        families.setdefault(scenario.partition("--srv-")[0], {})[scenario] = cell
    made = []
    for base, group in sorted(families.items()):
        chart = scenario_family_chart(
            base,
            group,
            str(charts_dir / "scenarios" / f"{base}.png"),
            foot,
            setup_index,
        )
        if chart:
            made.append(chart)
    made += [
        metric_chart(
            bulk, cells, "cpu_millis_per_gib", "cpu", "ms/GiB",
            "CPU per GiB (median over cells, lower is better)",
            str(charts_dir / "cpu-per-gib.png"), foot,
        ),
        metric_chart(
            bulk, cells, "rss_mib", "rss", "MiB",
            "peak RSS (median over cells, lower is better)",
            str(charts_dir / "memory-rss.png"), foot,
        ),
        threads_chart(bulk, cells, str(charts_dir / "threads.png"), foot),
        startup_chart(
            sorted(cells), cells, str(charts_dir / "startup.png"), foot
        ),
        ceiling_chart(bulk, cells, str(charts_dir / "ceiling.png"), foot),
        setup_chart(cells, setup_index, str(charts_dir / "setup-latency.png"), foot),
        binary_size_chart(meta, str(charts_dir / "binary-size.png"), foot),
    ]
    made = [path for path in made if path]
    print(f"charts: {len(made)} PNGs in {charts_dir}")
    for path in made:
        print(f"  {path}")
    write_bundle_markdown(input_dir, results)
    if args.readme:
        update_readme(args.readme, results, str(charts_dir), runner)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
