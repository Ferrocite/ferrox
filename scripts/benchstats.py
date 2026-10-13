"""Shared numbers for the benchmark matrix: medians and the verdict rule.

The Rust harness measures and gates; this module only restates its two pure
functions so the renderer and the validator share them: the median of a cell's
repeats, and the whole-interval rule that turns an interval into a verdict.
Tolerance and rule match `crates/ferrox-bench/src/stats.rs` (`TOLERANCE`,
`verdict`); if they ever disagree the validator fails, which is the point.
"""

import statistics

TOLERANCE = 0.05


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
