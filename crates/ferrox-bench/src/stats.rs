use std::collections::BTreeMap;

pub const TOLERANCE: f64 = 0.05;

pub const MIN_PAIRS: usize = 2;

pub const MIN_RUNS: usize = 3;

pub const HARNESS_BOUND: f64 = 0.85;

pub const BOOTSTRAP_RESAMPLES: usize = 4000;
pub const BOOTSTRAP_SEED: u64 = 20_260_902;

pub const RSS_TOLERANCE: f64 = 0.05;

/// Whether a run's cpu span is long enough for a per-GiB ratio to resolve: one tick of the sampler
/// has to be a smaller change than the tolerance this harness decides at, or the row measures the
/// tick rather than the engine.
pub fn cpu_span_is_pricable(cpu_millis: u64) -> bool {
    cpu_millis as f64 * TOLERANCE >= crate::parity::cpu_resolution_floor_millis() as f64
}

/// The shortest span [`cpu_span_is_pricable`] accepts, so a report can name it. Walked from the
/// predicate rather than divided, so the printed number cannot disagree with the gate it describes.
pub fn min_pricable_cpu_millis() -> u64 {
    let mut millis = 0;
    while !cpu_span_is_pricable(millis) {
        millis += 1;
    }
    millis
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Higher,
    Lower,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cell {
    pub run_index: usize,
    pub value: f64,
}

pub fn rotate(engines: &[&'static str], repeat: usize) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = engines.to_vec();
    if order.len() < 2 {
        return order;
    }
    let shift = repeat.saturating_sub(1) % order.len();
    order.rotate_left(shift);
    if repeat.is_multiple_of(2) {
        order.reverse();
    }
    order
}

pub fn paired_ratios(candidate: &[Cell], reference: &[Cell], direction: Direction) -> Vec<f64> {
    let mut by_repeat: BTreeMap<usize, f64> = BTreeMap::new();
    for cell in reference {
        by_repeat.entry(cell.run_index).or_insert(cell.value);
    }
    let mut ratios: Vec<f64> = candidate
        .iter()
        .filter_map(|cell| {
            let base = by_repeat.get(&cell.run_index)?;
            if *base <= 0.0 {
                return None;
            }
            Some(match direction {
                Direction::Higher => cell.value / *base,
                Direction::Lower if cell.value > 0.0 => *base / cell.value,
                Direction::Lower => return None,
            })
        })
        .collect();
    ratios.sort_by(f64::total_cmp);
    ratios
}

pub fn bootstrap_ci(ratios: &[f64]) -> Option<Interval> {
    if ratios.len() < MIN_PAIRS {
        return None;
    }
    let mut rng = Rng::new(BOOTSTRAP_SEED);
    let mut means = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let n = ratios.len();
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut total = 0.0;
        for _ in 0..n {
            total += ratios[rng.below(n)];
        }
        means.push(total / n as f64);
    }
    means.sort_by(f64::total_cmp);
    Some(Interval {
        low: percentile(&means, 2.5),
        mid: percentile(&means, 50.0),
        high: percentile(&means, 97.5),
        pairs: n,
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Interval {
    pub low: f64,
    pub mid: f64,
    pub high: f64,
    pub pairs: usize,
}

impl Interval {
    pub fn worse_than_reference(&self, tolerance: f64) -> bool {
        self.high < 1.0 - tolerance
    }

    pub fn better_than_reference(&self, tolerance: f64) -> bool {
        self.low > 1.0 + tolerance
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Better(Interval),
    Worse(Interval),
    WithinNoise(Interval),
    Unproven,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Higher => "higher",
            Self::Lower => "lower",
        }
    }
}

impl Verdict {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Better(_) => "better",
            Self::Worse(_) => "worse",
            Self::WithinNoise(_) => "within-noise",
            Self::Unproven => "unproven",
        }
    }
}

pub fn verdict(interval: Option<Interval>, direction: Direction) -> Verdict {
    let Some(i) = interval else {
        return Verdict::Unproven;
    };
    let _ = direction;
    if i.worse_than_reference(TOLERANCE) {
        Verdict::Worse(i)
    } else if i.better_than_reference(TOLERANCE) {
        Verdict::Better(i)
    } else {
        Verdict::WithinNoise(i)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Gate {
    pub passed: bool,
    pub lines: Vec<String>,
}

impl Gate {
    pub fn no_comparison() -> Self {
        Self {
            passed: false,
            lines: vec![
                "no comparison: no scenario produced a candidate/reference pair, so \
                 nothing could be gated"
                    .to_owned(),
            ],
        }
    }

    pub fn no_gated_row(rows: usize) -> Self {
        Self {
            passed: false,
            lines: vec![format!(
                "no gated row: {rows} row(s) were measured and every one of them is \
                 a pinned comparator, so the job's verdict had nothing to rest on. \
                 The engine under test has to be in the engine list."
            )],
        }
    }

    /// The reference landed no run, so the cell has no baseline: reported `no-reference` and failed, because zero reference runs is missing data and missing data must never read as parity. `detail` names the reference and what its runs reported.
    pub fn no_reference(detail: impl Into<String>) -> Self {
        Self {
            passed: false,
            lines: vec![format!(
                "no reference: {}; the cell is reported `no-reference` rather than passed, \
                 because no pair was compared — a fact about the reference engine or the \
                 runner, not a regression in the engine under test",
                detail.into()
            )],
        }
    }

    /// The reference ran and the runner starved only the engine under test: the pair was never measured because of the machine, so it cannot read as a regression the engine caused. `detail` names what the machine starved.
    pub fn unmeasured_by_runner(detail: impl Into<String>) -> Self {
        Self {
            passed: true,
            lines: vec![format!(
                "unmeasured by the runner: {}; reported inconclusive because of the machine, \
                 not a regression in the engine under test",
                detail.into()
            )],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub label: String,
    pub direction: Direction,
    pub interval: Option<Interval>,
    pub gates: bool,
    pub runner_blamed: bool,
    /// A per-GiB row the workload prices no rate for; it reports, and says why it is not gated.
    pub unpriced: bool,
}

impl Row {
    pub fn gating(
        label: impl Into<String>,
        direction: Direction,
        interval: Option<Interval>,
    ) -> Self {
        Self {
            label: label.into(),
            direction,
            interval,
            gates: true,
            runner_blamed: false,
            unpriced: false,
        }
    }

    pub fn reported(
        label: impl Into<String>,
        direction: Direction,
        interval: Option<Interval>,
    ) -> Self {
        Self {
            label: label.into(),
            direction,
            interval,
            gates: false,
            runner_blamed: false,
            unpriced: false,
        }
    }

    pub fn reported_unpriced(
        label: impl Into<String>,
        direction: Direction,
        interval: Option<Interval>,
    ) -> Self {
        Self {
            unpriced: true,
            ..Self::reported(label, direction, interval)
        }
    }

    pub fn runner_blamed(mut self) -> Self {
        self.runner_blamed = true;
        self
    }
}

pub fn gate_rows(rows: &[Row]) -> Gate {
    if rows.is_empty() {
        return Gate::no_comparison();
    }
    let mut lines = Vec::new();
    let mut passed = true;
    let mut unproven_gating = 0usize;
    let gated = rows.iter().filter(|r| r.gates).count();
    if gated == 0 {
        return Gate::no_gated_row(rows.len());
    }
    for row in rows {
        let v = verdict(row.interval, row.direction);
        let mut note = if row.gates {
            String::new()
        } else if row.unpriced {
            format!(
                " — reported, not gated: pricing a per-GiB rate takes {} ms of cpu, so that \
                 one {} ms tick of the sampler moves the ratio by less than the {:.0}% this row \
                 decides at, and these runs span less; the ratio is the sampler's, not the \
                 engine's",
                min_pricable_cpu_millis(),
                crate::parity::cpu_resolution_floor_millis(),
                TOLERANCE * 100.0
            )
        } else {
            " — reported, not gated: this row is a pinned comparator, so its \
             verdict is published and does not decide the job"
                .to_owned()
        };
        let inconclusive = matches!(v, Verdict::WithinNoise(_) | Verdict::Unproven);
        if row.runner_blamed && inconclusive {
            note.push_str(
                " — the runner's own throughput moved further than the tolerance above \
                 between repeats of one unchanged build, so this row cannot tell \
                 because of the machine rather than because the engines are close",
            );
        }
        let counts = row.gates;
        match v {
            Verdict::Better(i) => {
                lines.push(format!(
                    "{}: better, 95% interval [{:.3}x, {:.3}x] over {} pairs \
                     (median {:.3}x), outside the {:.0}% tolerance{note}",
                    row.label,
                    i.low,
                    i.high,
                    i.pairs,
                    i.mid,
                    TOLERANCE * 100.0
                ));
            }
            Verdict::Worse(i) => {
                if counts {
                    passed = false;
                }
                lines.push(format!(
                    "{}: WORSE, 95% interval [{:.3}x, {:.3}x] over {} pairs \
                     (median {:.3}x). The whole interval is beyond the {:.0}% \
                     tolerance, so this is a resolved regression and not noise{note}",
                    row.label,
                    i.low,
                    i.high,
                    i.pairs,
                    i.mid,
                    TOLERANCE * 100.0
                ));
            }
            Verdict::WithinNoise(i) => lines.push(format!(
                "{}: within noise, 95% interval [{:.3}x, {:.3}x] over {} pairs \
                 (median {:.3}x) includes 1.0x, so this run cannot resolve a \
                 difference of {:.0}% or more{note}",
                row.label,
                i.low,
                i.high,
                i.pairs,
                i.mid,
                TOLERANCE * 100.0
            )),
            Verdict::Unproven => {
                if counts {
                    unproven_gating += 1;
                }
                lines.push(format!(
                    "{}: UNPROVEN, fewer than {MIN_PAIRS} usable pairs, so no \
                     interval exists. An unproven row is not a passing row{note}",
                    row.label
                ));
            }
        }
    }
    // Measured parity is not a regression: gating rows within noise pass; missing data still fails, because an unproven row means the comparison never happened.
    if unproven_gating > 0 {
        return Gate {
            passed: false,
            lines,
        };
    }
    Gate { passed, lines }
}

pub fn rederive(raw: &[f64], reported_median: f64, reported_mean: f64) -> Result<(), String> {
    if raw.is_empty() {
        return Err("cannot re-derive an aggregate from no samples".to_owned());
    }
    let mut sorted = raw.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median = if sorted.len().is_multiple_of(2) {
        f64::midpoint(sorted[sorted.len() / 2 - 1], sorted[sorted.len() / 2])
    } else {
        sorted[sorted.len() / 2]
    };
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    if (median - reported_median).abs() > 1e-6 {
        return Err(format!(
            "the reported median {reported_median} does not match the samples' \
             median {median}"
        ));
    }
    if (mean - reported_mean).abs() > 1e-3 {
        return Err(format!(
            "the reported mean {reported_mean} does not match the samples' mean {mean}"
        ));
    }
    Ok(())
}

struct Rng {
    state: u64,
}

impl Rng {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn below(&mut self, n: usize) -> usize {
        assert!(n > 0, "below(0) has no answer");
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state % n as u64) as usize
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (pct / 100.0) * (sorted.len() - 1) as f64;
    let low = rank.floor() as usize;
    let high = rank.ceil() as usize;
    if low == high {
        return sorted[low];
    }
    sorted[low] + (rank - low as f64) * (sorted[high] - sorted[low])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_gating(rows: &[(String, Direction, Option<Interval>)]) -> Vec<Row> {
        rows.iter()
            .map(|(label, direction, interval)| Row::gating(label.clone(), *direction, *interval))
            .collect()
    }

    fn cell(run_index: usize, value: f64) -> Cell {
        Cell { run_index, value }
    }

    #[test]
    fn wire_words_name_direction_and_verdict() {
        assert_eq!(Direction::Higher.as_str(), "higher");
        assert_eq!(Direction::Lower.as_str(), "lower");
        let interval = Interval {
            low: 0.9,
            mid: 1.0,
            high: 1.1,
            pairs: 3,
        };
        assert_eq!(Verdict::Better(interval).as_str(), "better");
        assert_eq!(Verdict::Worse(interval).as_str(), "worse");
        assert_eq!(Verdict::WithinNoise(interval).as_str(), "within-noise");
        assert_eq!(Verdict::Unproven.as_str(), "unproven");
    }

    #[test]
    fn order_rotates_and_then_reverses() {
        let engines = ["a", "b", "c"];
        assert_eq!(rotate(&engines, 1), vec!["a", "b", "c"]);
        assert_eq!(rotate(&engines, 2), vec!["a", "c", "b"]);
        assert_eq!(rotate(&engines, 3), vec!["c", "a", "b"]);
        assert_eq!(rotate(&engines, 4), vec!["c", "b", "a"]);
        for repeat in 1..=6 {
            let order = rotate(&engines, repeat);
            assert_eq!(order.len(), 3);
            let mut sorted = order.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, engines.to_vec(), "every engine runs every repeat");
        }
    }

    #[test]
    fn order_of_one_engine_is_itself() {
        assert_eq!(rotate(&["only"], 1), vec!["only"]);
    }

    #[test]
    fn pairs_are_matched_by_repeat_index_not_by_order() {
        let candidate = vec![cell(1, 10.0), cell(2, 20.0), cell(3, 30.0)];
        let reference = vec![cell(1, 5.0), cell(3, 10.0)];
        let ratios = paired_ratios(&candidate, &reference, Direction::Higher);
        assert_eq!(ratios.len(), 2, "repeat 2 has no reference cell");
        assert!((ratios[0] - 2.0).abs() < 1e-9);
        assert!((ratios[1] - 3.0).abs() < 1e-9);
    }

    #[test]
    fn a_zero_reference_is_not_a_ratio() {
        let candidate = vec![cell(1, 10.0), cell(2, 20.0)];
        let reference = vec![cell(1, 0.0), cell(2, 0.0)];
        assert!(
            paired_ratios(&candidate, &reference, Direction::Higher).is_empty(),
            "a zero reference must produce no ratios at all"
        );
        assert!(
            paired_ratios(&candidate, &reference, Direction::Lower).is_empty(),
            "a zero candidate must produce no ratios for a lower-is-better metric"
        );
    }

    #[test]
    fn a_single_pair_is_unproven_not_a_pass() {
        let ratios = vec![1.5];
        assert!(bootstrap_ci(&ratios).is_none());
        assert_eq!(verdict(None, Direction::Higher), Verdict::Unproven);
    }

    #[test]
    fn the_gate_separates_a_real_regression_from_the_tolerance_band() {
        let better = Interval {
            low: 1.20,
            mid: 1.30,
            high: 1.40,
            pairs: 5,
        };
        let at = |offset: f64| Interval {
            low: 1.0 + offset,
            mid: 1.0 + offset,
            high: 1.0 + offset,
            pairs: 5,
        };
        let with = |i: Interval| {
            vec![
                ("throughput".into(), Direction::Higher, Some(i)),
                ("cpu".into(), Direction::Lower, Some(better)),
            ]
        };
        assert!(
            !gate_rows(&all_gating(&with(at(-0.40)))).passed,
            "a 40% regression must fail"
        );
        assert!(
            gate_rows(&all_gating(&with(at(-0.04)))).passed,
            "a 4% regression must pass a 5% gate"
        );
        assert!(gate_rows(&all_gating(&with(at(0.04)))).passed);
    }

    #[test]
    fn a_noisy_interval_with_a_bad_point_estimate_does_not_fail() {
        let noisy = Interval {
            low: 0.85,
            mid: 0.90,
            high: 1.10,
            pairs: 5,
        };
        let better = Interval {
            low: 1.20,
            mid: 1.30,
            high: 1.40,
            pairs: 5,
        };
        let g = gate_rows(&all_gating(&[
            ("throughput".into(), Direction::Higher, Some(noisy)),
            ("cpu".into(), Direction::Lower, Some(better)),
        ]));
        assert!(g.passed, "{:?}", g.lines);
        assert!(g.lines[0].contains("within noise"));
    }

    #[test]
    fn an_empty_comparison_fails() {
        let g = gate_rows(&[]);
        assert!(!g.passed);
        assert!(g.lines[0].contains("no comparison"));
    }

    #[test]
    fn measured_parity_passes_the_gate() {
        let tight = Interval {
            low: 0.99,
            mid: 1.0,
            high: 1.01,
            pairs: 5,
        };
        let g = gate_rows(&all_gating(&[(
            "throughput".into(),
            Direction::Higher,
            Some(tight),
        )]));
        assert!(g.passed, "{:?}", g.lines);
        assert!(g.lines[0].contains("within noise"));
    }

    #[test]
    fn an_unproven_row_alone_does_not_pass() {
        let g = gate_rows(&all_gating(&[(
            "throughput".into(),
            Direction::Higher,
            None,
        )]));
        assert!(!g.passed);
    }

    #[test]
    fn one_bad_row_fails_the_whole_gate() {
        let good = Interval {
            low: 1.10,
            mid: 1.20,
            high: 1.30,
            pairs: 5,
        };
        let bad = Interval {
            low: 0.50,
            mid: 0.55,
            high: 0.60,
            pairs: 5,
        };
        let g = gate_rows(&all_gating(&[
            ("throughput".into(), Direction::Higher, Some(good)),
            ("cpu".into(), Direction::Lower, Some(bad)),
        ]));
        assert!(!g.passed);
        assert!(g.lines.iter().any(|l| l.contains("WORSE")));
    }

    #[test]
    fn a_reported_row_is_printed_but_does_not_decide_the_job() {
        let worse = Interval {
            low: 0.50,
            mid: 0.55,
            high: 0.60,
            pairs: 5,
        };
        let better = Interval {
            low: 1.10,
            mid: 1.20,
            high: 1.30,
            pairs: 5,
        };
        let ours = "throughput (ferrox vs xray-core)";
        let theirs = "throughput (zeronet vs xray-core)";
        let g = gate_rows(&[
            Row::gating(ours, Direction::Higher, Some(better)),
            Row::reported(theirs, Direction::Higher, Some(worse)),
        ]);
        assert!(g.passed, "{:?}", g.lines);
        let line = g
            .lines
            .iter()
            .find(|l| l.starts_with(theirs))
            .expect("the comparator row is published");
        assert!(line.contains("WORSE"), "{line}");
        assert!(line.contains("not gated"), "{line}");
    }

    #[test]
    fn the_same_row_gated_still_fails() {
        let worse = Interval {
            low: 0.50,
            mid: 0.55,
            high: 0.60,
            pairs: 5,
        };
        let better = Interval {
            low: 1.10,
            mid: 1.20,
            high: 1.30,
            pairs: 5,
        };
        let ours = "throughput (ferrox vs xray-core)";
        let theirs = "throughput (other vs xray-core)";
        let g = gate_rows(&[
            Row::gating(ours, Direction::Higher, Some(better)),
            Row::gating(theirs, Direction::Higher, Some(worse)),
        ]);
        assert!(!g.passed, "{:?}", g.lines);
    }

    #[test]
    fn rows_that_all_report_fail_the_gate() {
        let better = Interval {
            low: 1.20,
            mid: 1.30,
            high: 1.40,
            pairs: 5,
        };
        let theirs = "throughput (zeronet vs xray-core)";
        let g = gate_rows(&[Row::reported(theirs, Direction::Higher, Some(better))]);
        assert!(!g.passed);
        assert!(g.lines[0].contains("no gated row"), "{:?}", g.lines);
    }

    #[test]
    fn the_runner_marker_attaches_only_to_a_row_that_could_not_tell() {
        let resolved_better = Interval {
            low: 1.221,
            mid: 1.388,
            high: 1.632,
            pairs: 7,
        };
        let resolved_worse = Interval {
            low: 0.573,
            mid: 0.696,
            high: 0.897,
            pairs: 7,
        };
        let inconclusive = Interval {
            low: 0.623,
            mid: 0.857,
            high: 1.081,
            pairs: 7,
        };

        let rss = Row::gating(
            "peak rss",
            Direction::Lower,
            Some(Interval {
                low: 10.9,
                mid: 11.0,
                high: 11.2,
                pairs: 7,
            }),
        );

        for interval in [resolved_better, resolved_worse] {
            let g = gate_rows(&[
                Row::runner_blamed(Row::gating("throughput", Direction::Higher, Some(interval))),
                rss.clone(),
            ]);
            let throughput = g
                .lines
                .iter()
                .find(|l| l.starts_with("throughput"))
                .expect("the throughput row is published");
            assert!(
                !throughput.contains("runner's own throughput moved"),
                "a resolved row must not be re-read as the runner's fault: {throughput}"
            );
            assert!(
                throughput.contains("better") || throughput.contains("WORSE"),
                "and must keep its own verdict: {throughput}"
            );
        }

        let g = gate_rows(&[
            Row::runner_blamed(Row::gating(
                "throughput",
                Direction::Higher,
                Some(inconclusive),
            )),
            rss,
        ]);
        let throughput = g
            .lines
            .iter()
            .find(|l| l.starts_with("throughput"))
            .expect("the throughput row is published");
        assert!(throughput.contains("within noise"), "{throughput}");
        assert!(
            throughput.contains("runner's own throughput moved"),
            "an inconclusive row on a noisy runner must say whose fault that is: {throughput}"
        );
    }

    #[test]
    fn the_bootstrap_is_reproducible_and_brackets_the_mean() {
        let ratios = vec![1.02, 1.05, 0.99, 1.01, 1.03, 1.00, 1.04];
        let a = bootstrap_ci(&ratios).expect("interval");
        let b = bootstrap_ci(&ratios).expect("interval");
        assert_eq!(a, b, "the same data must give the same interval");
        assert!(a.low <= a.mid && a.mid <= a.high);
        assert!(a.low < 1.05 && a.high > 1.0, "{a:?}");
        assert_eq!(a.pairs, 7);
    }

    #[test]
    fn a_lower_is_better_metric_is_oriented_so_more_is_better() {
        let candidate = vec![cell(1, 2.0), cell(2, 2.0), cell(3, 2.0)];
        let reference = vec![cell(1, 32.0), cell(2, 32.0), cell(3, 32.0)];
        let lower = paired_ratios(&candidate, &reference, Direction::Lower);
        assert!(
            lower.iter().all(|r| (*r - 16.0).abs() < 1e-9),
            "reference/candidate must be 16, not 1/16: {lower:?}"
        );
        assert!(matches!(
            verdict(bootstrap_ci(&lower), Direction::Lower),
            Verdict::Better(_)
        ));
        let higher = paired_ratios(&candidate, &reference, Direction::Higher);
        assert!(matches!(
            verdict(bootstrap_ci(&higher), Direction::Higher),
            Verdict::Worse(_)
        ));
    }

    #[test]
    fn a_consistent_regression_resolves_where_a_scatter_does_not() {
        let consistent = vec![0.60, 0.62, 0.59, 0.61, 0.60];
        let scattered = vec![0.60, 0.95, 0.75, 1.05, 0.65];
        assert_eq!(
            verdict(bootstrap_ci(&consistent), Direction::Higher),
            Verdict::Worse(bootstrap_ci(&consistent).expect("interval")),
        );
        assert!(matches!(
            verdict(bootstrap_ci(&scattered), Direction::Higher),
            Verdict::WithinNoise(_)
        ));
    }

    #[test]
    fn rederivation_catches_a_wrong_aggregate() {
        let raw = [1.0, 2.0, 3.0, 4.0];
        assert!(rederive(&raw, 2.5, 2.5).is_ok());
        assert!(
            rederive(&raw, 3.0, 2.5).is_err(),
            "a wrong median must fail"
        );
        assert!(rederive(&raw, 2.5, 9.0).is_err(), "a wrong mean must fail");
        assert!(rederive(&[], 0.0, 0.0).is_err(), "no samples must fail");
    }

    #[test]
    fn rederivation_uses_its_own_median() {
        assert!(rederive(&[1.0, 2.0, 3.0, 4.0], 2.5, 2.5).is_ok());
        assert!(rederive(&[1.0, 2.0, 3.0, 4.0, 5.0], 3.0, 3.0).is_ok());
    }

    #[test]
    fn the_generator_stays_in_range() {
        let mut rng = Rng::new(BOOTSTRAP_SEED);
        for _ in 0..1000 {
            assert!(rng.below(7) < 7, "the generator left 0..7");
        }
    }

    #[test]
    fn percentiles_interpolate() {
        assert_eq!(percentile(&[1.0], 50.0), 1.0);
        assert_eq!(percentile(&[], 50.0), 0.0);
        let v = percentile(&[0.0, 10.0], 50.0);
        assert!((v - 5.0).abs() < 1e-9);
    }

    #[test]
    fn the_thresholds_are_the_published_ones() {
        assert_eq!(MIN_RUNS, 3);
        assert_eq!(MIN_PAIRS, 2);
        assert_eq!(BOOTSTRAP_RESAMPLES, 4000);
        assert_eq!(BOOTSTRAP_SEED, 20_260_902);
        assert!((TOLERANCE - 0.05).abs() < f64::EPSILON);
        assert!((HARNESS_BOUND - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn the_cpu_price_floor_is_the_sampler_tick_over_the_tolerance() {
        let resolution = crate::parity::cpu_resolution_floor_millis();
        let floor = min_pricable_cpu_millis();
        assert!(
            cpu_span_is_pricable(floor),
            "the floor prices by definition"
        );
        assert!(
            !cpu_span_is_pricable(floor - 1),
            "one millisecond below the floor is one tick of the sampler's own error"
        );
        assert!(
            floor > resolution,
            "a {resolution} ms run reads 0 or {resolution}, so one tick is never a priced span"
        );
        assert!(
            !cpu_span_is_pricable(resolution),
            "and the nightly setup row, at one tick, is exactly that run"
        );
    }

    #[test]
    fn an_unpriced_row_names_the_workload_and_not_a_comparator() {
        let better = Interval {
            low: 1.20,
            mid: 1.30,
            high: 1.40,
            pairs: 5,
        };
        let g = gate_rows(&[
            Row::gating(
                "throughput (ferrox vs xray-core)",
                Direction::Higher,
                Some(better),
            ),
            Row::reported_unpriced("cpu per GiB (ferrox vs xray-core)", Direction::Lower, None),
        ]);
        assert!(g.passed, "{:?}", g.lines);
        let line = g
            .lines
            .iter()
            .find(|line| line.starts_with("cpu per GiB"))
            .expect("an unpriced row is still published");
        assert!(line.contains("UNPROVEN"), "{line}");
        assert!(line.contains("reported, not gated"), "{line}");
        assert!(
            !line.contains("pinned comparator"),
            "this row reports because of the workload, not because of the engine's role: {line}"
        );
    }

    #[test]
    fn the_cpu_resolution_is_the_mechanisms_not_a_typed_in_number() {
        let published = crate::parity::cpu_resolution_floor_millis();
        assert_eq!(
            published,
            crate::ps::CpuSource::current().resolution_millis()
        );
        assert!(published > 0, "a floor of zero resolves nothing");
        match crate::ps::Host::current() {
            crate::ps::Host::Linux => {
                assert_eq!(
                    crate::ps::CpuSource::current(),
                    crate::ps::CpuSource::ProcStat
                );
                assert_eq!(published, 10, "USER_HZ is 100 on every Linux");
            }
            crate::ps::Host::Macos => {
                assert_eq!(
                    crate::ps::CpuSource::current(),
                    crate::ps::CpuSource::PsTime
                );
                assert_eq!(published, 10, "BSD ps prints hundredths");
            }
            crate::ps::Host::Windows => assert_eq!(published, 1),
            crate::ps::Host::Other => assert_eq!(published, 1_000),
        }
    }
}
