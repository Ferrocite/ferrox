"""Shared numbers for the benchmark matrix: medians, verdicts, and run deltas.

The Rust harness measures and gates; this module restates its two pure
functions so the renderer and the validator share them: the median of a cell's
repeats, and the whole-interval rule that turns an interval into a verdict.
Tolerance and rule match `crates/ferrox-bench/src/stats.rs` (`TOLERANCE`,
`verdict`); if they ever disagree the validator fails, which is the point.

The comparison helpers are the other direction: they ask whether this run moved
against the previous published run, not whether it beat the reference in its own
cell. A shared runner can move 5-10% without a code change, so a delta needs a
threshold; the default is the top of that noise band, 10%.
"""

import statistics

TOLERANCE = 0.05
CHANGE_THRESHOLD = 0.10

COMPARE_METRICS = {
    "throughput_mib_s": ("throughput", "MiB/s", "higher"),
    "cpu_millis_per_gib": ("CPU per GiB", "ms/GiB", "lower"),
    "rss_mib": ("peak RSS", "MiB", "lower"),
    "threads_peak": ("peak threads", "threads", "lower"),
    "startup_seconds": ("cold start", "s", "lower"),
    "kernel_calls_per_gib": ("kernel asks", "calls/GiB", "lower"),
}


def median(values):
    """Median of a non-empty cell sample, statistics.median."""
    if not values:
        raise ValueError("median of no values")
    return statistics.median(values)


def verdict_for(interval, direction):
    """Whole-interval verdict: better, worse, within-noise, or unproven.

    `interval` is a (low, high) pair or None; `direction` is "higher" or
    "lower". Mirrors `stats::verdict`: a verdict needs the whole interval
    beyond tolerance on one side, and anything unmeasured is unproven.
    """
    if interval is None:
        return "unproven"
    low, high = interval
    if high < 1.0 - TOLERANCE:
        return "worse"
    if low > 1.0 + TOLERANCE:
        return "better"
    return "within-noise"


def change_for(metric, before, after, threshold=CHANGE_THRESHOLD):
    """Classify one metric's move against the previous run.

    A change smaller than the threshold is not reported, whatever its sign:
    the shared runner's own noise is larger than that, and a table full of
    five-percent flickers is not a regression report. A metric with a missing
    side is reported as `new` or `missing`, because coverage moving is worth
    seeing even when no ratio exists.
    """
    if metric not in COMPARE_METRICS:
        raise ValueError(f"unknown metric {metric}")
    _, _, direction = COMPARE_METRICS[metric]
    if before is None and after is None:
        return None
    if before is None:
        return {"kind": "new", "change": None, "verdict": "new"}
    if after is None:
        return {"kind": "missing", "change": None, "verdict": "missing"}
    if before == 0:
        return {"kind": "new", "change": None, "verdict": "new"}
    change = (after - before) / before
    if abs(change) <= threshold:
        return None
    better = change > 0 if direction == "higher" else change < 0
    return {
        "kind": "change",
        "change": change,
        "verdict": "improvement" if better else "regression",
    }


def compare_results(after, before, threshold=CHANGE_THRESHOLD):
    """Every scenario/engine/metric that moved beyond the noise threshold.

    Both documents are `matrix-results.json`; the comparison is only between
    cells both runs measured, so a tier that added a scenario reports the new
    scenario's absence rather than inventing a ratio.
    """
    previous = {
        scenario.get("id"): scenario for scenario in before.get("scenarios", [])
    }
    changes = []
    for scenario in after.get("scenarios", []):
        old = previous.get(scenario.get("id"))
        if old is None:
            changes.append(
                {
                    "scenario": scenario.get("id"),
                    "base": scenario.get("base"),
                    "server": scenario.get("server"),
                    "engine": "all",
                    "metric": "scenario",
                    "before": None,
                    "after": None,
                    "kind": "new-scenario",
                    "change": None,
                    "verdict": "new scenario",
                }
            )
            continue
        for engine, medians in sorted(scenario.get("medians", {}).items()):
            old_medians = old.get("medians", {}).get(engine, {})
            for metric in COMPARE_METRICS:
                found = change_for(
                    metric, old_medians.get(metric), medians.get(metric), threshold
                )
                if found is None:
                    continue
                changes.append(
                    {
                        "scenario": scenario.get("id"),
                        "base": scenario.get("base"),
                        "server": scenario.get("server"),
                        "engine": engine,
                        "metric": metric,
                        "before": old_medians.get(metric),
                        "after": medians.get(metric),
                        **found,
                    }
                )
    return changes


def changes_markdown(changes, before_date="previous run", threshold=CHANGE_THRESHOLD):
    """A table of meaningful moves, or one line saying there were none."""
    if not changes:
        return (
            f"No cell moved by more than {threshold:.0%} against "
            f"{before_date}; the previous bundle stands."
        )
    lines = [
        f"Only cells whose median moved by more than {threshold:.0%} against "
        f"{before_date} are listed. A positive change is not always good: "
        "`lower is better` metrics read the other way.",
        "",
        "| scenario | server | engine | metric | before | after | change | verdict |",
        "| -------- | ------ | ------ | ------ | -----: | ----: | -----: | ------- |",
    ]
    for change in changes:
        if change["metric"] == "scenario":
            metric = ("new scenario", "")
            before = after = delta = "\u2014"
        else:
            metric = COMPARE_METRICS[change["metric"]]
            before = format_metric(change["before"], metric[1])
            after = format_metric(change["after"], metric[1])
            delta = (
                "\u2014"
                if change["change"] is None
                else f"{change['change']:+.1%}"
            )
        lines.append(
            f"| `{change['base'] or change['scenario']}` | "
            f"{change['server'] or '\u2014'} | {change['engine']} | "
            f"{metric[0]} | {before} | {after} | {delta} | "
            f"{change['verdict']} |"
        )
    return "\n".join(lines)


def format_metric(value, unit):
    """A compact metric value for a table cell."""
    if value is None:
        return "\u2014"
    if unit in ("threads", "calls/GiB", "MiB/s"):
        return f"{value:.0f}"
    if unit == "s":
        return f"{value:.2f}"
    return f"{value:.1f}"
