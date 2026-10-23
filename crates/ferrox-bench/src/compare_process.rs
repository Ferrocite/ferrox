use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::json::{self, Json};
use crate::parity::{self, ConfigArg, Error, Request, Run};
use crate::stats::{self, Cell, Direction};

fn caveat() -> String {
    format!(
        "\n> **What this row is not.** `ps` samples RSS and CPU from outside the \
         > process, which is the only way a Go engine and a Rust engine are \
         > comparable at all, but it sees no allocation counts: those stay \
         > in-process and exact, in gates 2 and 4. A CPU delta under {n} ms reads \
         > as `0`, so a `0` in that column means \"below the kernel's resolution\", \
         > not \"free\". Only the `SOCKS` path is measured: `TUN`, DNS, geodata \
         > routing, and the `REALITY`/Vision TLS paths are the pinned harness's \
         > workloads and are **not** covered here — `docs/methodology.md` lists \
         > each one as `not_covered` with its reason, rather than leaving it out.\n",
        n = parity::cpu_resolution_floor_millis()
    )
}

pub const MIN_TRAFFIC_SAMPLES: usize = 3;

#[derive(Debug, Clone)]
pub struct Engine {
    pub name: &'static str,
    pub path: PathBuf,
    pub config_arg: ConfigArg,
    pub gated: bool,
    pub dialect: parity::Dialect,
    pub protocols: &'static [&'static str],
}

#[derive(Debug, Clone)]
pub struct Workload {
    pub traffic: String,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    pub warmup: bool,
    pub outbound_config: String,
    pub outbound_configs: Vec<(String, String)>,
    pub scenario: String,
}

impl Workload {
    fn flow_bytes(&self) -> u64 {
        (self.iterations * self.payload_size) as u64
    }

    fn total_bytes(&self) -> u64 {
        let directions = match self.traffic.as_str() {
            "full-duplex" => 2u64,
            _ => 1,
        };
        (self.flow_bytes() * self.connections as u64).saturating_mul(directions)
    }

    fn config_for(&self, engine: &Engine) -> String {
        if let Some((_, config)) = self
            .outbound_configs
            .iter()
            .find(|(label, _)| label == engine.name)
        {
            return config.clone();
        }
        if self.outbound_config.trim().is_empty() {
            engine
                .dialect
                .base_config()
                .to_string()
                .expect("a document built from strings and counts always serialises")
        } else {
            self.outbound_config.clone()
        }
    }

    fn request(&self, engine: &Engine, output: &Path) -> String {
        let mut root = Json::object();
        root.insert("binary", Json::Str(engine.path.display().to_string()));
        root.insert("config", Json::Str(self.config_for(engine)));
        root.insert("path", Json::Str("socks".into()));
        root.insert("traffic", Json::Str(self.traffic.clone()));
        root.insert("connections", Json::Num(self.connections as f64));
        root.insert("iterations", Json::Num(self.iterations as f64));
        root.insert("payload_size", Json::Num(self.payload_size as f64));
        root.insert("output", Json::Str(output.display().to_string()));
        root.insert("warmup", Json::Bool(self.warmup));
        root.to_string()
            .expect("a document built from strings and counts always serialises")
    }

    fn describe(&self) -> String {
        format!(
            "{} x {} flows of {} iterations at {} B ({} MiB total)",
            self.traffic,
            self.connections,
            self.iterations,
            self.payload_size,
            self.total_bytes() as f64 / (1024.0 * 1024.0)
        )
    }
}

#[derive(Debug)]
pub struct EngineRuns {
    pub engine: &'static str,
    pub dialect: parity::Dialect,
    pub runs: Vec<Run>,
}

#[derive(Debug)]
pub struct Comparison {
    pub workload: Workload,
    pub repeats: usize,
    pub by_engine: Vec<EngineRuns>,
    pub ceilings_mib_s: Vec<f64>,
    pub gated: Option<&'static str>,
    pub failures: Vec<(String, String)>,
    pub skipped: Vec<(String, String)>,
    pub machine: String,
}

/// Whether every run moves bytes and spans enough cpu for a per-GiB ratio to resolve the
/// tolerance. An engine with no runs vacates the check, so missing data keeps its gate.
fn prices_per_gib(runs: &[Run]) -> bool {
    runs.iter()
        .all(|run| run.bytes_moved() > 0 && stats::cpu_span_is_pricable(run.outcome.cpu_millis))
}

fn run_cell_json(run: &Run) -> Json {
    let mut cell = Json::object();
    cell.insert("throughput_mib_s", Json::Num(run.throughput_mib_s()));
    cell.insert("cpu_millis_per_gib", Json::Num(run.cpu_millis_per_gib()));
    let io = run.io_per_gib();
    cell.insert(
        "kernel_calls_per_gib",
        io.map_or(Json::Null, |(calls, _)| Json::Num(calls)),
    );
    cell.insert(
        "kernel_bytes_per_gib",
        io.map_or(Json::Null, |(_, bytes)| Json::Num(bytes)),
    );
    cell.insert("rss_mib", Json::Num(run.rss_mib()));
    cell.insert(
        "threads_peak",
        match run.outcome.threads_peak {
            Some(t) => Json::Num(t as f64),
            None => Json::Null,
        },
    );
    cell.insert("startup_seconds", Json::Num(run.outcome.startup_seconds));
    cell.insert(
        "transfer_seconds",
        Json::Num(run.outcome.transfer.as_secs_f64()),
    );
    cell
}

impl Comparison {
    fn throughput_cells(&self, engine: &str) -> Vec<Cell> {
        self.runs(engine)
            .iter()
            .enumerate()
            .map(|(i, run)| Cell {
                run_index: i + 1,
                value: run.throughput_mib_s(),
            })
            .collect()
    }

    fn cpu_cells(&self, engine: &str) -> Vec<Cell> {
        self.runs(engine)
            .iter()
            .enumerate()
            .map(|(i, run)| Cell {
                run_index: i + 1,
                value: run.cpu_millis_per_gib(),
            })
            .collect()
    }

    fn rss_cells(&self, engine: &str) -> Vec<Cell> {
        self.runs(engine)
            .iter()
            .enumerate()
            .map(|(i, run)| Cell {
                run_index: i + 1,
                value: run.rss_mib(),
            })
            .collect()
    }

    /// The kernel's counts, per GiB, or nothing at all when any run of the engine lacks them — a
    /// tally that is missing, or one blind to the run's crossing: a paired ratio over runs that did
    /// not all report compares different runs, and a row that cannot be trusted reports nothing.
    fn io_cells(&self, engine: &str, pick: fn((f64, f64)) -> f64) -> Vec<Cell> {
        let runs = self.runs(engine);
        let cells = runs
            .iter()
            .enumerate()
            .filter_map(|(i, run)| {
                run.io_per_gib().map(|pair| Cell {
                    run_index: i + 1,
                    value: pick(pair),
                })
            })
            .collect::<Vec<_>>();
        if cells.len() != runs.len() {
            return Vec::new();
        }
        cells
    }

    fn runs(&self, engine: &str) -> &[Run] {
        self.by_engine
            .iter()
            .find(|e| e.engine == engine)
            .map_or(&[], |e| e.runs.as_slice())
    }

    fn reference(&self) -> Option<&'static str> {
        self.by_engine.first().map(|e| e.engine)
    }

    fn candidates(&self) -> Vec<&'static str> {
        let Some(reference) = self.reference() else {
            return Vec::new();
        };
        self.by_engine
            .iter()
            .map(|e| e.engine)
            .filter(|name| *name != reference)
            .collect()
    }

    fn throughput_uncertain_because_of_the_runner(
        &self,
        interval: Option<stats::Interval>,
    ) -> bool {
        self.runner_spread()
            .is_some_and(|spread| spread > stats::TOLERANCE)
            && interval.is_some_and(|i| {
                !i.worse_than_reference(stats::TOLERANCE)
                    && !i.better_than_reference(stats::TOLERANCE)
            })
    }

    pub fn gate(&self) -> stats::Gate {
        let Some(reference) = self.reference() else {
            return stats::Gate::no_comparison();
        };
        if self.candidates().is_empty() {
            return stats::Gate::no_comparison();
        }
        // A cell whose reference landed no run has no baseline: no-reference and failed, because zero reference runs is missing data, not parity. The machine-wide escape below needs the reference to have run.
        if self.runs(reference).is_empty() {
            let failures: Vec<&str> = self
                .failures
                .iter()
                .filter(|(engine, _)| engine == reference)
                .map(|(_, reason)| reason.as_str())
                .collect();
            let detail = match failures.as_slice() {
                [] => format!(
                    "`{reference}` (the reference) landed none of {} run(s) and recorded no failure",
                    self.repeats
                ),
                [only] => format!(
                    "`{reference}` (the reference) landed none of {} run(s); its failure was: {only}",
                    self.repeats
                ),
                [first, ..] => format!(
                    "`{reference}` (the reference) landed none of {} run(s); the runner recorded \
                     {} failure(s) for it, the first: {first}",
                    self.repeats,
                    failures.len()
                ),
            };
            return stats::Gate::no_reference(detail);
        }
        if self
            .gated
            .filter(|candidate| self.runs(candidate).is_empty())
            .is_some_and(|candidate| self.runner_disturbed_beyond_the_candidate(candidate))
        {
            return stats::Gate::unmeasured_by_runner(format!(
                "`{}` (the engine under test) landed no run while the same runner disturbed \
                 the other engines, so no gated pair exists because of the machine",
                self.gated.unwrap_or("")
            ));
        }
        stats::gate_rows(&self.rows())
    }

    /// Whether the machine, not one engine, is responsible for a shortfall: the runner ran out of its cell window, or took a workload disturbance on an engine other than `candidate`. A disturbance is per-machine, so one seen across engines cannot be read as the candidate's fault.
    fn runner_disturbed_beyond_the_candidate(&self, candidate: &str) -> bool {
        self.failures.iter().any(|(engine, reason)| {
            engine != candidate && (engine == "cell" || reason.starts_with("workload"))
        })
    }

    fn rows(&self) -> Vec<stats::Row> {
        let Some(reference) = self.reference() else {
            return Vec::new();
        };
        let candidates = self.candidates();
        if candidates.is_empty() {
            return Vec::new();
        }
        candidates
            .into_iter()
            .flat_map(|candidate| {
                let gates = Some(candidate) == self.gated;
                let priced =
                    prices_per_gib(self.runs(candidate)) && prices_per_gib(self.runs(reference));
                [
                    (
                        format!("throughput ({candidate} vs {reference})"),
                        Direction::Higher,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.throughput_cells(candidate),
                            &self.throughput_cells(reference),
                            Direction::Higher,
                        )),
                        true,
                        true,
                    ),
                    (
                        format!("cpu per GiB ({candidate} vs {reference})"),
                        Direction::Lower,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.cpu_cells(candidate),
                            &self.cpu_cells(reference),
                            Direction::Lower,
                        )),
                        true,
                        priced,
                    ),
                    (
                        format!(
                            "peak rss ({candidate} vs {reference}, {:.0}% tolerance)",
                            stats::RSS_TOLERANCE * 100.0
                        ),
                        Direction::Lower,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.rss_cells(candidate),
                            &self.rss_cells(reference),
                            Direction::Lower,
                        )),
                        true,
                        true,
                    ),
                    // The kernel's asks and bytes per GiB attribute the cpu row; they never gate it.
                    (
                        format!("kernel calls per GiB ({candidate} vs {reference})"),
                        Direction::Lower,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.io_cells(candidate, |(calls, _)| calls),
                            &self.io_cells(reference, |(calls, _)| calls),
                            Direction::Lower,
                        )),
                        false,
                        true,
                    ),
                    (
                        format!("kernel bytes per GiB ({candidate} vs {reference})"),
                        Direction::Lower,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.io_cells(candidate, |(_, bytes)| bytes),
                            &self.io_cells(reference, |(_, bytes)| bytes),
                            Direction::Lower,
                        )),
                        false,
                        true,
                    ),
                ]
                .into_iter()
                .map(move |(label, direction, interval, gates_row, priced_row)| {
                    let row = if gates && gates_row {
                        if priced_row {
                            stats::Row::gating(label.clone(), direction, interval)
                        } else {
                            stats::Row::reported_unpriced(label.clone(), direction, interval)
                        }
                    } else {
                        stats::Row::reported(label.clone(), direction, interval)
                    };
                    if label.starts_with("throughput")
                        && self.throughput_uncertain_because_of_the_runner(interval)
                    {
                        stats::Row::runner_blamed(row)
                    } else {
                        row
                    }
                })
            })
            .collect()
    }

    pub fn comparison_json(&self, scenario: &str) -> Result<String, String> {
        fn interval_json(interval: Option<stats::Interval>) -> Json {
            match interval {
                Some(i) => {
                    let mut o = Json::object();
                    o.insert("low", Json::Num(i.low));
                    o.insert("mid", Json::Num(i.mid));
                    o.insert("high", Json::Num(i.high));
                    o.insert("pairs", Json::Num(i.pairs as f64));
                    o
                }
                None => Json::Null,
            }
        }
        let mut root = Json::object();
        root.insert("scenario", Json::Str(scenario.to_owned()));
        let mut workload = Json::object();
        workload.insert("traffic", Json::Str(self.workload.traffic.clone()));
        workload.insert("connections", Json::Num(self.workload.connections as f64));
        workload.insert("iterations", Json::Num(self.workload.iterations as f64));
        workload.insert("payload_size", Json::Num(self.workload.payload_size as f64));
        workload.insert("repeats", Json::Num(self.repeats as f64));
        root.insert("workload", workload);
        root.insert("machine", Json::Str(self.machine.clone()));
        root.insert(
            "reference",
            self.reference()
                .map_or(Json::Null, |name| Json::Str(name.to_owned())),
        );
        let mut engines = Vec::new();
        for entry in &self.by_engine {
            let mut engine = Json::object();
            engine.insert("name", Json::Str(entry.engine.to_owned()));
            engine.insert(
                "binary_sha256",
                entry
                    .runs
                    .first()
                    .map_or(Json::Null, |run| Json::Str(run.engine_sha256.clone())),
            );
            let mut runs = Vec::new();
            for run in &entry.runs {
                runs.push(run_cell_json(run));
            }
            engine.insert("runs", Json::Arr(runs));
            engines.push(engine);
        }
        root.insert("engines", Json::Arr(engines));
        let gate = self.gate();
        let mut rows = Vec::new();
        for row in self.rows() {
            let mut item = Json::object();
            item.insert("label", Json::Str(row.label.clone()));
            item.insert("direction", Json::Str(row.direction.as_str().into()));
            item.insert("interval", interval_json(row.interval));
            item.insert(
                "verdict",
                Json::Str(stats::verdict(row.interval, row.direction).as_str().into()),
            );
            item.insert("gates", Json::Bool(row.gates));
            item.insert("unpriced", Json::Bool(row.unpriced));
            rows.push(item);
        }
        root.insert("rows", Json::Arr(rows));
        root.insert("gate_passed", Json::Bool(gate.passed));
        let mut failures = Vec::new();
        for (engine, reason) in &self.failures {
            let mut item = Json::object();
            item.insert("engine", Json::Str(engine.clone()));
            item.insert("reason", Json::Str(reason.clone()));
            failures.push(item);
        }
        root.insert("failures", Json::Arr(failures));
        let mut skipped = Vec::new();
        for (engine, reason) in &self.skipped {
            let mut item = Json::object();
            item.insert("engine", Json::Str(engine.clone()));
            item.insert("reason", Json::Str(reason.clone()));
            skipped.push(item);
        }
        root.insert("skipped", Json::Arr(skipped));
        root.insert(
            "harness_ceilings_mib_s",
            Json::Arr(
                self.ceilings_mib_s
                    .iter()
                    .map(|ceiling| Json::Num(*ceiling))
                    .collect(),
            ),
        );
        root.to_string()
    }

    pub fn report(&self) -> String {
        let mut s = self.preamble();
        s.push_str(&self.failure_note());
        s.push_str(&self.headline_table());
        s.push_str(&self.per_repeat_table());
        s.push_str(&self.medians_table());
        s.push_str(&self.gate_section());
        s.push_str(&caveat());
        s
    }

    fn preamble(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "\n## Gate 5 — process-level comparison\n");
        let _ = writeln!(
            s,
            "Each engine runs as a child process over one validated workload, driven \
             through a `SOCKS5` inbound the harness injects — the contract the \
             pinned `xray-rust` harness defines \
             (`upstream/xray-rust/crates/xray-bench/src/protocol_bench.rs:122`) \
             and `ferrox-app` satisfies, so one request file measures either \
             binary. Their harness is `MPL-2.0` and is run from its pin rather than \
             copied; the request and result schemas are reproduced so the files mean \
             the same thing on both sides.\n"
        );
        let _ = writeln!(s, "| | |");
        let _ = writeln!(s, "| --- | --- |");
        let _ = writeln!(s, "| workload | {} |", self.workload.describe());
        let _ = writeln!(s, "| repeats | {} |", self.repeats);
        let _ = writeln!(
            s,
            "| engines and config dialects | {} |",
            self.by_engine
                .iter()
                .map(|e| format!("`{}` {}", e.engine, dialect_cell(e.dialect)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(s, "| machine | {} |", self.machine);
        let _ = writeln!(
            s,
            "| cpu resolution floor | {} ms (a delta below this reads 0) |",
            parity::cpu_resolution_floor_millis()
        );
        let _ = writeln!(
            s,
            "| one-hop ceiling | {} |",
            match self.ceiling_summary() {
                Some((median, low, high)) => format!(
                    "{median:.1} MiB/s with no engine in the path and **one** socket \
                     hop, {} per repeat, min {low:.1} max {high:.1}, spread {}. Every \
                     row below is a relay, which is **two** hops, so 100% here is \
                     the generator saturating rather than a ceiling being exceeded. \
                     ZeroNet's {:.0}% generator bound ([`stats::HARNESS_BOUND`]) \
                     applies to a row over the *same* hops as the ceiling and so \
                     does not apply to any row here",
                    self.ceilings_mib_s.len(),
                    spread_text((high - low) / median),
                    stats::HARNESS_BOUND * 100.0
                ),
                None => "not measured, so no row below can be called generator-saturated".into(),
            }
        );
        let _ = writeln!(
            s,
            "| runner spread | {} |",
            self.runner_spread().map_or_else(
                || "unmeasured, so no throughput row below can be certified".to_owned(),
                |spread| format!(
                    "the harness ceiling moved {} between repeats of one unchanged \
                     build, which {} the {:.0}% tolerance this gate decides \
                     at, so a throughput row on this runner is {}",
                    spread_text(spread),
                    if spread > stats::TOLERANCE {
                        "exceeds"
                    } else {
                        "is inside"
                    },
                    stats::TOLERANCE * 100.0,
                    if spread > stats::TOLERANCE {
                        "reported but not certified"
                    } else {
                        "decidable"
                    }
                )
            )
        );
        let _ = writeln!(s);
        s
    }

    fn failure_note(&self) -> String {
        if self.failures.is_empty() {
            return String::new();
        }
        let mut s = String::new();
        let _ = writeln!(
            s,
            "> **A cell is never blank.** Each engine below either produced runs or \
             carries the reason it did not:\n"
        );
        for (engine, reason) in &self.failures {
            let _ = writeln!(s, "> - `{engine}`: {reason}");
        }
        let _ = writeln!(s);
        s
    }

    fn per_repeat_table(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "### Per-repeat measurements\n");
        let _ = writeln!(
            s,
            "| engine | run | throughput MiB/s | cpu ms/GiB | cpu user/sys ms/GiB | kernel asks / MiB crossed per GiB | peak RSS MiB | threads | transfer s | traffic samples |"
        );
        let _ = writeln!(
            s,
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        );
        for entry in &self.by_engine {
            for (i, run) in entry.runs.iter().enumerate() {
                let cpu = if run.outcome.traffic_samples < MIN_TRAFFIC_SAMPLES {
                    format!("**{:.2}**", run.cpu_millis_per_gib())
                } else {
                    format!("{:.2}", run.cpu_millis_per_gib())
                };
                let split = run.cpu_split_per_gib().map_or_else(
                    || "n/a".to_owned(),
                    |(user, sys)| format!("{user:.1} / {sys:.1}"),
                );
                let kernel = run.io_per_gib().map_or_else(
                    || "n/a".to_owned(),
                    |(calls, bytes)| format!("{calls:.0} / {:.0} MiB", bytes / 1_048_576.0),
                );
                let _ = writeln!(
                    s,
                    "| {} | {} | {:.1} | {cpu} | {split} | {kernel} | {:.1} | {} | {:.3} | {} |",
                    entry.engine,
                    i + 1,
                    run.throughput_mib_s(),
                    run.rss_mib(),
                    run.outcome
                        .threads_peak
                        .map_or_else(|| "n/a".to_owned(), |t| t.to_string()),
                    run.outcome.transfer.as_secs_f64(),
                    run.outcome.traffic_samples,
                );
            }
        }
        s
    }

    fn medians_table(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "\n### Medians over {} repeats\n", self.repeats);
        let _ = writeln!(
            s,
            "| engine | throughput MiB/s | vs one-hop ceiling | cpu ms/GiB | peak RSS MiB | setup median us |"
        );
        let _ = writeln!(s, "| --- | ---: | ---: | ---: | ---: | ---: |");
        for entry in &self.by_engine {
            let m = self.medians(entry.engine);
            let cell = |values: &[f64], median: f64, places: usize| -> String {
                match mean_of(values).and_then(|mean| stats::rederive(values, median, mean)) {
                    Ok(()) => format!("{median:.places$}"),
                    Err(e) => format!("**not re-derivable: {e}**"),
                }
            };
            let throughput = cell(&m.throughput_cells, m.throughput, 1);
            let bound = self.ceiling_fraction(m.throughput);
            let cpu = cell(&m.cpu_cells, m.cpu, 2);
            let rss = cell(&m.rss_cells, m.rss, 1);
            let _ = writeln!(
                s,
                "| {} | {throughput} | {bound} | {cpu} | {rss} | {} |",
                entry.engine, m.setup
            );
        }
        s
    }

    fn ceiling_fraction(&self, throughput: f64) -> String {
        self.ceiling_summary().map_or_else(
            || "unknown".to_owned(),
            |(ceiling, _, _)| {
                let fraction = if ceiling > 0.0 {
                    throughput / ceiling
                } else {
                    0.0
                };
                if fraction >= 1.0 {
                    format!("**{:.0}% — at the one-hop ceiling**", fraction * 100.0)
                } else {
                    format!("{:.0}%", fraction * 100.0)
                }
            },
        )
    }

    fn ceiling_summary(&self) -> Option<(f64, f64, f64)> {
        if self.ceilings_mib_s.is_empty() {
            return None;
        }
        let mut sorted = self.ceilings_mib_s.clone();
        sorted.sort_by(f64::total_cmp);
        let low = sorted[0];
        let high = sorted[sorted.len() - 1];
        Some((median_of(&sorted), low, high))
    }

    pub fn runner_spread(&self) -> Option<f64> {
        let (median, low, high) = self.ceiling_summary()?;
        if median <= 0.0 {
            return None;
        }
        Some((high - low) / median)
    }

    fn headline_table(&self) -> String {
        let Some(reference) = self.reference() else {
            return String::new();
        };
        let candidates = self.candidates();
        if candidates.is_empty() {
            return String::new();
        }
        let mut s = String::new();
        let _ = writeln!(s, "### Versus `{reference}`, paired on the repeat index\n");
        let _ = writeln!(
            s,
            "**Every ratio is oriented so that above `1.00x` is better**, and each cell \
             carries the absolute medians it came from. The absolute is not decoration: \
             a bare `2.00x` on a CPU row reads as *twice the CPU*, and it means the \
             opposite — half of it. A ratio that can be misread by a reasonable reader \
             is a reporting defect, not a compact one.\n"
        );
        let _ = writeln!(
            s,
            "`ns` marks a row whose interval includes 1.0: this run declining to tell, \
             not a tie.\n"
        );
        let _ = writeln!(
            s,
            "| engine | throughput (MiB/s) | cpu (ms/GiB, lower is better) | peak RSS (MiB, lower is better) | rows resolved |"
        );
        let _ = writeln!(s, "| --- | ---: | ---: | ---: | ---: |");
        for candidate in std::iter::once(reference).chain(candidates) {
            let absolute = self.medians(candidate);
            let (throughput_abs, cpu_abs, rss_abs) =
                (absolute.throughput, absolute.cpu, absolute.rss);
            if candidate == reference {
                let _ = writeln!(
                    s,
                    "| **{reference}** (the reference) | {throughput_abs:.0} | \
                     {cpu_abs:.0} | {rss_abs:.1} | — |"
                );
                continue;
            }
            let cell = |value: Option<stats::Interval>, absolute: String| -> String {
                match value {
                    None => format!("{absolute} (**unproven**)"),
                    Some(i) if !resolved_verdict(Some(i)) => {
                        format!(
                            "{absolute} ({:.2}x [{:.2}, {:.2}] ns)",
                            i.mid, i.low, i.high
                        )
                    }
                    Some(i) => {
                        format!(
                            "{absolute} (**{:.2}x** [{:.2}, {:.2}])",
                            i.mid, i.low, i.high
                        )
                    }
                }
            };
            let throughput = stats::bootstrap_ci(&stats::paired_ratios(
                &self.throughput_cells(candidate),
                &self.throughput_cells(reference),
                Direction::Higher,
            ));
            let cpu = stats::bootstrap_ci(&stats::paired_ratios(
                &self.cpu_cells(candidate),
                &self.cpu_cells(reference),
                Direction::Lower,
            ));
            let rss = stats::bootstrap_ci(&stats::paired_ratios(
                &self.rss_cells(candidate),
                &self.rss_cells(reference),
                Direction::Lower,
            ));
            let resolved = [throughput, cpu, rss]
                .into_iter()
                .filter(|i| resolved_verdict(*i))
                .count();
            let _ = writeln!(
                s,
                "| {candidate} | {} | {} | {} | {resolved}/3 |",
                cell(throughput, format!("{throughput_abs:.0}")),
                cell(cpu, format!("{cpu_abs:.0}")),
                cell(rss, format!("{rss_abs:.1}")),
            );
        }
        s.push('\n');
        s
    }

    fn gate_section(&self) -> String {
        let gate = self.gate();
        let mut s = String::new();
        let _ = writeln!(s, "\n### Gate\n");
        let _ = writeln!(
            s,
            "Paired on the repeat index, engine order rotated and reversed, 95% \
             bootstrap interval over {} resamples at seed {}. A row fails only when \
             its **whole** interval is beyond the {:.0}% tolerance: with three repeats \
             a 4% regression and a 40% one look identical until the interval is read \
             (`upstream/zeronet/docs/benchmarks/harness/zbench/report.py:885`). Fewer \
             than {} usable pairs is `UNPROVEN`, which is not a pass: missing \
             data must never silently pass. A run whose gating rows all land \
             within noise passes — measured parity is not a regression — while \
             a run with an unproven gating row fails, because the comparison \
             never happened. A cell whose reference landed no run is reported \
             `no-reference` and fails: zero reference runs is missing data, and \
             missing data must never read as parity. The one pair-less cell that \
             passes is the engine under test landing none while the same runner \
             disturbed the other engines — that pair was starved by the machine, \
             not the engine, and is reported `unmeasured by the runner` \
             (`.../zbench/report.py:968`).\n\
             Only the rows for `{}` decide this gate. Every other engine here is a \
             pinned comparator: it is measured and published so a reader can see \
             where it sits, but a comparator measuring worse than the reference is \
             a fact about that comparator, and gating on it would make this job's \
             verdict a property of a binary this repository does not build. Those \
             rows carry a `reported, not gated` marker.\n\
             A per-GiB row gates only over runs that price one: one tick of the sampler is {} ms, \
             so a rate the {:.0}% tolerance can resolve takes {} ms of cpu, and a shorter span \
             measures the tick instead of the engine. Such a row reports with that reason while \
             the throughput and peak rss rows — same repeats, no per-GiB unit — still decide the \
             job, so an unpriced row never hides a missing engine.\n",
            stats::BOOTSTRAP_RESAMPLES,
            stats::BOOTSTRAP_SEED,
            stats::TOLERANCE * 100.0,
            stats::MIN_PAIRS,
            self.gated.unwrap_or("(none)"),
            parity::cpu_resolution_floor_millis(),
            stats::TOLERANCE * 100.0,
            stats::min_pricable_cpu_millis(),
        );
        for line in &gate.lines {
            let _ = writeln!(s, "- {line}");
        }
        let _ = writeln!(
            s,
            "\n**Gate: {}.**",
            if gate.passed {
                "pass"
            } else {
                "FAIL — see the rows above"
            }
        );
        s
    }

    fn medians(&self, engine: &str) -> Medians {
        let runs = self.runs(engine);
        let throughput: Vec<f64> = runs.iter().map(Run::throughput_mib_s).collect();
        let cpu: Vec<f64> = runs.iter().map(Run::cpu_millis_per_gib).collect();
        let rss: Vec<f64> = runs.iter().map(Run::rss_mib).collect();
        let mut setup_samples: Vec<u128> = runs
            .iter()
            .flat_map(|r| r.outcome.setup.iter().map(|s| s.total_us))
            .collect();
        setup_samples.sort_unstable();
        Medians {
            throughput: median_of(&throughput),
            cpu: median_of(&cpu),
            rss: median_of(&rss),
            setup: parity::median(&setup_samples),
            throughput_cells: throughput,
            cpu_cells: cpu,
            rss_cells: rss,
        }
    }
}

fn dialect_cell(dialect: parity::Dialect) -> &'static str {
    match dialect {
        parity::Dialect::Xray => "(`protocol`, `port`)",
        parity::Dialect::SingBox => "(`type`, `listen_port`)",
        parity::Dialect::Leaf => "(`protocol`, `address`, `port`)",
    }
}

fn spread_text(spread: f64) -> String {
    format!("{:.2}x", 1.0 + spread.max(0.0))
}

fn resolved_verdict(interval: Option<stats::Interval>) -> bool {
    !matches!(
        stats::verdict(interval, Direction::Higher),
        stats::Verdict::WithinNoise(_) | stats::Verdict::Unproven
    )
}

struct Medians {
    throughput: f64,
    cpu: f64,
    rss: f64,
    setup: u128,
    throughput_cells: Vec<f64>,
    cpu_cells: Vec<f64>,
    rss_cells: Vec<f64>,
}

fn median_of(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        f64::midpoint(sorted[mid - 1], sorted[mid])
    } else {
        sorted[mid]
    }
}

fn mean_of(values: &[f64]) -> Result<f64, String> {
    if values.is_empty() {
        return Err("there are no cells to average".to_owned());
    }
    Ok(values.iter().sum::<f64>() / values.len() as f64)
}

const SCENARIO_PROTOCOLS: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "shadowsocks2022",
    "socks",
    "http",
    "tun",
];

fn protocol_of(scenario: &str) -> Option<&str> {
    let rung = scenario.split('-').next().unwrap_or_default();
    SCENARIO_PROTOCOLS.contains(&rung).then_some(rung)
}

fn carrier_of(scenario: &str) -> Option<&'static str> {
    ["kcp", "hysteria"]
        .into_iter()
        .find(|carrier| scenario.split('-').any(|rung| rung == *carrier))
}

fn carries(engine: &str, carrier: &str) -> bool {
    !matches!(
        (engine, carrier),
        ("xray-rust" | "zeronet", "kcp") | ("zeronet", "hysteria")
    )
}

fn participant_names(
    engines: &[Engine],
    workload: &Workload,
) -> (Vec<&'static str>, Vec<(String, String)>) {
    let mut skipped = Vec::new();
    let custom = !workload.outbound_config.trim().is_empty();
    let protocol = protocol_of(&workload.scenario);
    let carrier = carrier_of(&workload.scenario);
    let names = engines
        .iter()
        .filter(|e| {
            if custom && e.dialect != parity::Dialect::Xray {
                skipped.push((
                    e.name.to_owned(),
                    format!(
                        "custom scenario configs are Xray-dialect documents; {} reads {:?}",
                        e.name, e.dialect
                    ),
                ));
                return false;
            }
            if let Some(protocol) = protocol.filter(|_| !e.protocols.is_empty()) {
                if !e.protocols.contains(&protocol) {
                    skipped.push((
                        e.name.to_owned(),
                        format!(
                            "{protocol} is not served by {} at its pin; it accepts {}",
                            e.name,
                            e.protocols.join(", ")
                        ),
                    ));
                    return false;
                }
            }
            if let Some(carrier) = carrier.filter(|carrier| !carries(e.name, carrier)) {
                skipped.push((
                    e.name.to_owned(),
                    format!("{carrier} is not a carrier {} has at its pin", e.name),
                ));
                return false;
            }
            true
        })
        .map(|e| e.name)
        .collect();
    (names, skipped)
}

pub fn run(
    engines: &[Engine],
    workload: &Workload,
    repeats: usize,
    out_dir: &Path,
    measure_ceiling: bool,
) -> Result<Comparison, Error> {
    if engines.len() < 2 {
        return Err(Error::Invalid(format!(
            "a comparison needs at least two engines, got {}: with one there is \
             nothing to compare against",
            engines.len()
        )));
    }
    if repeats < stats::MIN_RUNS {
        return Err(Error::Invalid(format!(
            "{repeats} repeats cannot be read: {} is the minimum worth reading \
             (`upstream/zeronet/docs/benchmarks/README.md:251`), and below two \
             usable pairs a ratio has no interval at all, which is `unproven` \
             rather than a pass",
            stats::MIN_RUNS
        )));
    }

    let mut ceilings: Vec<f64> = Vec::new();
    // The measures of one cell share one wall clock, so the re-measuring of a storm is bounded by the cell and not by each measure: a job cut off at its CI timeout prints no verdict and uploads no bundle.
    let cell = parity::Cell::new(parity::CELL_WINDOW);

    let mut by_engine: Vec<EngineRuns> = engines
        .iter()
        .map(|e| EngineRuns {
            engine: e.name,
            dialect: e.dialect,
            runs: Vec::with_capacity(repeats),
        })
        .collect();
    let mut failures = Vec::new();
    let (names, skipped) = participant_names(engines, workload);

    'measures: for repeat in 1..=repeats {
        if measure_ceiling {
            if let Ok(ceiling) = parity::harness_ceiling(
                workload.connections,
                workload.payload_size,
                workload.flow_bytes(),
            ) {
                ceilings.push(ceiling);
            }
        }
        for name in stats::rotate(&names, repeat) {
            let Some(engine) = engines.iter().find(|e| e.name == name) else {
                continue;
            };
            let (output, request) = write_request(workload, engine, out_dir, name, repeat)?;
            if !cell.fits() {
                failures.push(window_ended(&by_engine, &names, repeats));
                break 'measures;
            }
            match parity::measure(&request, engine.config_arg, engine.dialect, &cell) {
                Ok(run) => {
                    let result_path = output.join("result.json");
                    let result_text = run
                        .to_result_json(&request)
                        .to_string()
                        .map_err(|e| Error::Invalid(format!("result.json: {e}")))?;
                    std::fs::write(&result_path, result_text).map_err(|source| Error::Io {
                        action: "writing result.json".into(),
                        source,
                    })?;
                    match revalidate(&result_path) {
                        Ok(checked) => {
                            debug_assert_eq!(
                                checked.engine_sha256, run.engine_sha256,
                                "the re-read result names a different binary"
                            );
                            let Some(slot) = by_engine.iter_mut().find(|e| e.engine == name) else {
                                continue;
                            };
                            slot.runs.push(run);
                        }
                        Err(e) => failures.push((
                            name.to_owned(),
                            format!("result.json did not re-derive: {e}"),
                        )),
                    }
                }
                Err(e) => failures.push((name.to_owned(), e.to_string())),
            }
        }
    }

    Ok(Comparison {
        workload: workload.clone(),
        repeats,
        by_engine,
        ceilings_mib_s: ceilings,
        gated: engines.iter().find(|e| e.gated).map(|e| e.name),
        failures,
        skipped,
        machine: machine_description(),
    })
}

/// The harness's request for one repeat, written to disk and read back so the file and the measure describe the workload identically.
fn write_request(
    workload: &Workload,
    engine: &Engine,
    out_dir: &Path,
    name: &str,
    repeat: usize,
) -> Result<(PathBuf, Request), Error> {
    let output = out_dir.join(format!("{name}-run{repeat}"));
    std::fs::create_dir_all(out_dir).map_err(|source| Error::Io {
        action: format!("creating {}", out_dir.display()),
        source,
    })?;
    let request_path = out_dir.join(format!("{name}-run{repeat}.json"));
    std::fs::write(&request_path, workload.request(engine, &output)).map_err(|source| {
        Error::Io {
            action: format!("writing {}", request_path.display()),
            source,
        }
    })?;
    Ok((output, Request::read(&request_path)?))
}

/// The cell ran out of its CI window before every measure landed. It names `cell`, not an engine, because it says nothing about any one engine: it counts what landed against what the cell asked for, so the report is honest about the repeats a cut-off cell never measured.
fn window_ended(
    by_engine: &[EngineRuns],
    names: &[&'static str],
    repeats: usize,
) -> (String, String) {
    let landed = by_engine.iter().map(|e| e.runs.len()).sum::<usize>();
    (
        "cell".to_owned(),
        format!(
            "the cell's {}s window ended before every measure ran: {landed} run(s) landed, and the cell asked for {} engine(s) x {repeats} repeats",
            parity::CELL_WINDOW.as_secs(),
            names.len()
        ),
    )
}

fn machine_description() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let cpus = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    let bind = parity::local_non_loopback_ipv4().map_or_else(
        |e| format!("no usable non-loopback IPv4 ({e})"),
        |ip| format!("bound on {ip}"),
    );
    format!(
        "{os} {arch}, {cpus} logical CPUs, {bind}, cpu from `{}`",
        crate::ps::CpuSource::current().as_str()
    )
}

pub fn revalidate(result_path: &Path) -> Result<Run, Error> {
    let text = std::fs::read_to_string(result_path).map_err(|source| Error::Io {
        action: format!("reading {}", result_path.display()),
        source,
    })?;
    let root = json::parse(&text)
        .map_err(|e| Error::Invalid(format!("{} is not valid json: {e}", result_path.display())))?;
    let num = |key: &str| -> Result<f64, Error> {
        root.get(key)
            .and_then(Json::as_num)
            .ok_or_else(|| Error::Invalid(format!("result.json has no number `{key}`")))
    };
    let status = root.get("status").and_then(Json::as_str).unwrap_or("");
    if status != "pass" {
        return Err(Error::Invalid(format!(
            "result.json status is `{status}`, not `pass`"
        )));
    }

    let bytes_sent = num("bytes_sent")?;
    let bytes_received = num("bytes_received")?;
    let seconds = num("transfer_seconds")?;
    let cpu_millis = num("cpu_millis")?;
    check_derived(&root, bytes_sent + bytes_received, seconds, cpu_millis)?;
    check_samples(&root, cpu_millis)?;
    check_split(&root, cpu_millis)?;
    check_io(&root, bytes_sent + bytes_received)?;

    let optional = |key: &str| root.get(key).and_then(Json::as_num).map(|n| n as u64);

    let read_setup = |key: &str| -> u128 {
        root.get("setup")
            .and_then(|s| s.get(key))
            .and_then(|q| q.get("median"))
            .and_then(Json::as_num)
            .map_or(0, |n| n as u128)
    };
    let setup = vec![parity::Setup {
        tcp_connect_us: read_setup("tcp_connect_us"),
        socks_method_us: read_setup("socks_method_us"),
        socks_connect_us: read_setup("socks_connect_us"),
        socks_setup_us: read_setup("socks_setup_us"),
        total_us: read_setup("total_us"),
    }];

    let samples = read_samples(&root);
    Ok(Run {
        engine: root
            .get("engine_binary")
            .and_then(Json::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        engine_sha256: root
            .get("engine_sha256")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned(),
        outcome: parity::Outcome {
            bytes_sent: bytes_sent as u64,
            bytes_received: bytes_received as u64,
            transfer: std::time::Duration::from_secs_f64(seconds.max(0.0)),
            wall: std::time::Duration::from_secs_f64(
                root.get("wall_seconds")
                    .and_then(Json::as_num)
                    .unwrap_or(seconds)
                    .max(0.0),
            ),
            setup,
            peak_rss_kib: num("peak_rss_kib")? as u64,
            cpu_millis: cpu_millis as u64,
            user_millis: optional("cpu_user_millis"),
            sys_millis: optional("cpu_sys_millis"),
            traffic_samples: samples
                .iter()
                .filter(|(phase, _)| *phase == parity::Phase::Traffic)
                .count(),
            threads_peak: root
                .get("threads_peak")
                .and_then(Json::as_num)
                .map(|n| n as u64),
            io: read_io(root.get("io")),
            startup_cpu_millis: num("client_startup_cpu_millis")? as u64,
            startup_seconds: num("client_startup_seconds")?,
            samples,
        },
    })
}

fn check_derived(root: &Json, moved: f64, seconds: f64, cpu_millis: f64) -> Result<(), Error> {
    let num = |key: &str| {
        root.get(key)
            .and_then(Json::as_num)
            .ok_or_else(|| Error::Invalid(format!("result.json has no number `{key}`")))
    };
    let rederived_throughput = if seconds > 0.0 {
        moved / (1024.0 * 1024.0) / seconds
    } else {
        0.0
    };
    let reported_throughput = num("throughput_mib_s")?;
    if (rederived_throughput - reported_throughput).abs()
        > 1e-6 * reported_throughput.abs().max(1.0)
    {
        return Err(Error::Invalid(format!(
            "throughput_mib_s {reported_throughput} does not match its own fields: \
             {moved} bytes over {seconds}s re-derives to {rederived_throughput}"
        )));
    }
    let rederived_cpu = if moved > 0.0 {
        cpu_millis / (moved / 1_073_741_824.0)
    } else {
        0.0
    };
    let reported_cpu = num("cpu_millis_per_gib")?;
    if (rederived_cpu - reported_cpu).abs() > 1e-6 * reported_cpu.abs().max(1.0) {
        return Err(Error::Invalid(format!(
            "cpu_millis_per_gib {reported_cpu} does not match its own fields: \
             {cpu_millis} ms over {moved} bytes re-derives to {rederived_cpu}"
        )));
    }
    Ok(())
}

fn check_samples(root: &Json, cpu_millis: f64) -> Result<(), Error> {
    let Some(items) = root.get("samples").and_then(Json::as_arr) else {
        return Err(Error::Invalid(
            "result.json carries no samples, so nothing in it can be re-derived".into(),
        ));
    };
    let rss: Vec<f64> = items
        .iter()
        .filter_map(|i| i.get("rss_kib").and_then(Json::as_num))
        .collect();
    let cpu: Vec<f64> = items
        .iter()
        .filter_map(|i| i.get("cpu_millis").and_then(Json::as_num))
        .collect();
    let peak = rss.iter().copied().fold(0.0f64, f64::max);
    let reported_peak = root
        .get("peak_rss_kib")
        .and_then(Json::as_num)
        .ok_or_else(|| Error::Invalid("result.json has no `peak_rss_kib`".into()))?;
    if (peak - reported_peak).abs() > 1e-6 * peak.max(1.0) {
        return Err(Error::Invalid(format!(
            "peak_rss_kib {reported_peak} does not match the samples' maximum {peak}"
        )));
    }
    let (Some(&first), Some(&last)) = (cpu.first(), cpu.last()) else {
        return Err(Error::Invalid(
            "result.json carries no cpu samples, so cpu_millis cannot be re-derived".into(),
        ));
    };
    let total = last - first;
    if (total - cpu_millis).abs() > f64::EPSILON * total.abs().max(1.0) {
        return Err(Error::Invalid(format!(
            "cpu_millis {cpu_millis} does not match its own samples' delta {total}"
        )));
    }
    Ok(())
}

/// The split is the same cpu counted twice, and every source that reports it rounds once per half,
/// so the pair has to add up to the whole exactly; a `ps` line reports neither and is no split.
fn check_split(root: &Json, cpu_millis: f64) -> Result<(), Error> {
    let user = root.get("cpu_user_millis").and_then(Json::as_num);
    let sys = root.get("cpu_sys_millis").and_then(Json::as_num);
    match (user, sys) {
        (None, None) => Ok(()),
        (Some(user), Some(sys)) => {
            let whole = user + sys;
            // Half-tick margin: the halves are whole ms, so this is an exact add-up that survives float representation.
            if (whole - cpu_millis).abs() > 0.5 {
                return Err(Error::Invalid(format!(
                    "cpu_user_millis {user} + cpu_sys_millis {sys} = {whole}, which is not \
                     the {cpu_millis} ms of cpu the run reports"
                )));
            }
            Ok(())
        }
        _ => Err(Error::Invalid(
            "result.json reports half a cpu split: one of `cpu_user_millis` or \
             `cpu_sys_millis` is missing"
                .into(),
        )),
    }
}

fn check_io(root: &Json, moved: f64) -> Result<(), Error> {
    let count = |key: &str| {
        root.get("io")
            .and_then(|io| io.get(key))
            .and_then(Json::as_num)
    };
    let (Some(read_calls), Some(write_calls), Some(read_bytes), Some(write_bytes)) = (
        count("syscr"),
        count("syscw"),
        count("rchar"),
        count("wchar"),
    ) else {
        // A sampler with no `/proc/<pid>/io` leaves the tally out: a gap in the source, not the run.
        return Ok(());
    };
    if moved <= 0.0 {
        return Ok(());
    }
    let gib = moved / 1_073_741_824.0;
    let calls = read_calls + write_calls;
    let bytes = read_bytes + write_bytes;
    let whole = |count: f64| count.max(0.0) as u64;
    let priced = parity::io_crossing_per_gib(
        crate::ps::Io {
            read_calls: whole(read_calls),
            write_calls: whole(write_calls),
            read_bytes: whole(read_bytes),
            write_bytes: whole(write_bytes),
        },
        whole(moved),
    )
    .is_some();
    let matches = |key: &str, rederived: f64| -> Result<(), Error> {
        let Some(reported) = root.get(key).and_then(Json::as_num) else {
            return if priced {
                Err(Error::Invalid(format!("result.json has no number `{key}`")))
            } else {
                Ok(())
            };
        };
        if !priced {
            return Err(Error::Invalid(format!(
                "{key} {reported} prices a tally of {bytes} bytes over a run that moved {moved}, \
                 which the tally never saw"
            )));
        }
        if (rederived - reported).abs() > 1e-6 * reported.abs().max(1.0) {
            return Err(Error::Invalid(format!(
                "{key} {reported} does not match its own fields: {rederived}"
            )));
        }
        Ok(())
    };
    matches("io_calls_per_gib", calls / gib)?;
    matches("io_bytes_per_gib", bytes / gib)?;
    let samples = read_samples(root);
    let Some(delta) = crate::ps::Io::window(samples.into_iter().filter_map(|(_, s)| s.io)) else {
        // The artefact's samples carry no tally, so the reported one has nothing to be checked against.
        return Ok(());
    };
    let (calls_seen, bytes_seen) = (delta.calls() as f64, delta.bytes() as f64);
    // Whole counters on both sides, so half a call is the tightest band that still means equal.
    if (calls_seen - calls).abs() > 0.5 || (bytes_seen - bytes).abs() > 0.5 {
        return Err(Error::Invalid(format!(
            "io reports {calls} calls over {bytes} bytes, which is not the samples' window of \
             {} over {}",
            delta.calls(),
            delta.bytes(),
        )));
    }
    Ok(())
}

fn read_samples(root: &Json) -> Vec<(parity::Phase, crate::ps::Sample)> {
    root.get("samples")
        .and_then(Json::as_arr)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let read = |key: &str| item.get(key).and_then(Json::as_num).unwrap_or(0.0);
                    let phase = match item.get("phase").and_then(Json::as_str) {
                        Some("startup") => parity::Phase::Startup,
                        Some("traffic") => parity::Phase::Traffic,
                        _ => parity::Phase::Settle,
                    };
                    (
                        phase,
                        crate::ps::Sample {
                            elapsed_ms: read("elapsed_ms") as u128,
                            rss_kib: read("rss_kib") as u64,
                            cpu_millis: read("cpu_millis") as u64,
                            user_millis: item
                                .get("user_millis")
                                .and_then(Json::as_num)
                                .map(|n| n as u64),
                            sys_millis: item
                                .get("sys_millis")
                                .and_then(Json::as_num)
                                .map(|n| n as u64),
                            threads: item.get("threads").and_then(Json::as_num).map(|n| n as u64),
                            io: read_io(item.get("io")),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The kernel tally under the names `/proc/<pid>/io` prints it. Half a tally is no tally: a sample
/// that reports three of the four counters would let a run's delta depend on which line was read.
fn read_io(item: Option<&Json>) -> Option<crate::ps::Io> {
    let item = item?;
    let count = |key: &str| item.get(key).and_then(Json::as_num).map(|n| n as u64);
    Some(crate::ps::Io {
        read_calls: count("syscr")?,
        write_calls: count("syscw")?,
        read_bytes: count("rchar")?,
        write_bytes: count("wchar")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn engine(name: &'static str, path: &str) -> Engine {
        Engine {
            name,
            path: PathBuf::from(path),
            config_arg: ConfigArg::Long,
            gated: name == "ferrox",
            dialect: parity::Dialect::Xray,
            protocols: &[],
        }
    }

    #[test]
    fn a_cpu_split_has_to_add_up_to_the_cpu_it_splits() {
        let mut root = Json::object();
        root.insert("cpu_user_millis", Json::Num(600.0));
        root.insert("cpu_sys_millis", Json::Num(400.0));
        assert!(check_split(&root, 1000.0).is_ok());
        assert!(
            check_split(&root, 1001.0).is_err(),
            "one millisecond apart is two endpoints' roundings disagreeing, which no source may offer"
        );
        assert!(
            check_split(&root, 1200.0).is_err(),
            "a pair that is not the whole cpu is not a split of it"
        );
        let mut half = Json::object();
        half.insert("cpu_user_millis", Json::Num(600.0));
        assert!(
            check_split(&half, 1000.0).is_err(),
            "half a split is a fault in the writer, not a gap in the source"
        );
        assert!(
            check_split(&Json::object(), 1000.0).is_ok(),
            "a ps-only run reports no split and is not a fault"
        );
    }

    #[test]
    fn the_kernel_tally_in_an_artefact_has_to_be_its_own_samples_window() {
        let one_gib = 1024.0 * 1024.0 * 1024.0;
        let end = [100.0, 50.0, one_gib, one_gib];
        let mut root = Json::object();
        root.insert("io", tally(end));
        root.insert("io_calls_per_gib", Json::Num(150.0));
        root.insert("io_bytes_per_gib", Json::Num(2.0 * one_gib));
        root.insert("samples", Json::Arr(vec![sample([0.0; 4]), sample(end)]));
        assert!(check_io(&root, one_gib).is_ok());
        root.insert("io_calls_per_gib", Json::Num(151.0));
        assert!(
            check_io(&root, one_gib).is_err(),
            "a per-GiB number has to be the tally over the run's own bytes"
        );
        root.insert("io_calls_per_gib", Json::Num(150.0));
        root.insert("io", tally([101.0, 50.0, one_gib, one_gib]));
        root.insert("io_calls_per_gib", Json::Num(151.0));
        assert!(
            check_io(&root, one_gib).is_err(),
            "a tally self-consistent but not its samples' window is still a fault"
        );
        root.insert("io", tally(end));
        root.insert("io_calls_per_gib", Json::Num(150.0));
        root.insert(
            "samples",
            Json::Arr(vec![
                sample([200.0, 100.0, 2.0 * one_gib, 2.0 * one_gib]),
                sample(end),
            ]),
        );
        assert!(
            check_io(&root, one_gib).is_err(),
            "a run whose every sample sits under its first prices no window, so the calls it \
             claims did not come from its samples"
        );
        assert!(
            check_io(&Json::object(), one_gib).is_ok(),
            "a run sampled where `/proc/<pid>/io` cannot be read reports no tally, which is a gap \
             in the source and not a fault"
        );
    }

    /// The window is why a thread-per-flow engine gets a number: its worker threads exit with the
    /// traffic, so the settle samples are the idle leader's and only a peak-reaching read prices them.
    #[test]
    fn a_tally_that_falls_back_after_its_worker_threads_exit_is_still_the_run_s_window() {
        let one_gib = 1024.0 * 1024.0 * 1024.0;
        let base = [18.0, 0.0, 1_150.0, 0.0];
        let peak = [100.0, 988_719.0, one_gib + 1_150.0, 8.0 * one_gib];
        let idle = [19.0, 0.0, 1_160.0, 0.0];
        let mut root = Json::object();
        root.insert("io", tally([82.0, 988_719.0, one_gib, 8.0 * one_gib]));
        root.insert("io_calls_per_gib", Json::Num(988_801.0 / 8.0));
        root.insert("io_bytes_per_gib", Json::Num(1.125 * one_gib));
        root.insert(
            "samples",
            Json::Arr(vec![sample(base), sample(peak), sample(idle), sample(idle)]),
        );
        assert!(
            check_io(&root, 8.0 * one_gib).is_ok(),
            "the reported tally is the peak's window, not the last sample's"
        );
        root.insert("io", tally([1.0, 0.0, 10.0, 0.0]));
        root.insert("io_calls_per_gib", Json::Null);
        root.insert("io_bytes_per_gib", Json::Null);
        assert!(
            check_io(&root, 8.0 * one_gib).is_err(),
            "the run's bytes crossed while the tallies that counted them were alive, so a report \
             that reads the last sample as the run is a fault the window catches"
        );
    }

    #[test]
    fn a_tally_blind_to_the_run_s_crossing_reports_no_per_gib_number() {
        let one_gib = 1024.0 * 1024.0 * 1024.0;
        let moved = 8.0 * one_gib;
        // Rust relays cross sockets on send/recv, which the counter does not name: only startup reads show.
        let blind = [9.0, 8.0, 11410.0, 3200.0];
        let mut root = Json::object();
        root.insert("io", tally(blind));
        root.insert("io_calls_per_gib", Json::Null);
        root.insert("io_bytes_per_gib", Json::Null);
        root.insert("samples", Json::Arr(vec![sample([0.0; 4]), sample(blind)]));
        assert!(
            check_io(&root, moved).is_ok(),
            "a run the tally never saw gets null, which is its own answer rather than a missing number"
        );
        root.insert("io_calls_per_gib", Json::Num(2.125));
        assert!(
            check_io(&root, moved).is_err(),
            "a per-GiB number off a blind tally reads as a win over an engine whose counter does \
             see its syscalls"
        );
    }

    fn tally(counts: [f64; 4]) -> Json {
        let mut io = Json::object();
        for (name, value) in ["syscr", "syscw", "rchar", "wchar"].into_iter().zip(counts) {
            io.insert(name, Json::Num(value));
        }
        io
    }

    fn sample(counts: [f64; 4]) -> Json {
        let mut item = Json::object();
        item.insert("rss_kib", Json::Num(1.0));
        item.insert("cpu_millis", Json::Num(1.0));
        item.insert("io", tally(counts));
        item
    }

    fn workload() -> Workload {
        Workload {
            traffic: "upload".into(),
            connections: 1,
            iterations: 16,
            payload_size: 1024,
            warmup: false,
            outbound_config: String::new(),
            outbound_configs: Vec::new(),
            scenario: String::new(),
        }
    }

    #[test]
    fn a_comparison_needs_two_engines() {
        let err = run(
            &[engine("a", "/bin/true")],
            &workload(),
            1,
            Path::new("/tmp/x"),
            false,
        )
        .expect_err("one engine is not a comparison");
        assert!(err.to_string().contains("at least two engines"));
    }

    fn synth_run(mibs: u64, cpu_millis: u64, rss_kib: u64) -> parity::Run {
        parity::Run {
            engine: String::new(),
            engine_sha256: "abc".into(),
            outcome: parity::Outcome {
                bytes_sent: mibs * 1024 * 1024,
                bytes_received: 0,
                transfer: std::time::Duration::from_secs(1),
                wall: std::time::Duration::from_secs(1),
                setup: Vec::new(),
                peak_rss_kib: rss_kib,
                cpu_millis,
                user_millis: Some(cpu_millis * 2 / 3),
                sys_millis: Some(cpu_millis - cpu_millis * 2 / 3),
                traffic_samples: 10,
                threads_peak: None,
                io: Some(crate::ps::Io {
                    read_calls: mibs * 128,
                    write_calls: mibs * 128,
                    read_bytes: mibs * 1_048_576,
                    write_bytes: mibs * 1_048_576,
                }),
                startup_cpu_millis: 0,
                startup_seconds: 0.0,
                samples: Vec::new(),
            },
        }
    }

    /// Three repeats of one engine, so a cell's fixture stays shorter than what it asserts.
    fn synth_engine(engine: &'static str, runs: [(u64, u64, u64); 3]) -> EngineRuns {
        EngineRuns {
            engine,
            dialect: parity::Dialect::Xray,
            runs: runs
                .map(|(mibs, cpu_millis, rss_kib)| synth_run(mibs, cpu_millis, rss_kib))
                .into_iter()
                .collect(),
        }
    }

    /// Three repeats whose runs cross a fraction of a mebibyte, the shape of a setup scenario:
    /// `bytes` crossed in `transfer_ms`, on `cpu_millis` of cpu and `rss_kib` of memory.
    fn synth_micro_engine(engine: &'static str, runs: [(u64, u64, u64, u64); 3]) -> EngineRuns {
        EngineRuns {
            engine,
            dialect: parity::Dialect::Xray,
            runs: runs
                .map(|(bytes, transfer_ms, cpu_millis, rss_kib)| {
                    let mut run = synth_run(0, cpu_millis, rss_kib);
                    run.outcome.bytes_sent = bytes;
                    run.outcome.transfer = std::time::Duration::from_millis(transfer_ms);
                    run
                })
                .into_iter()
                .collect(),
        }
    }

    fn dialect_engine(name: &'static str, dialect: parity::Dialect) -> Engine {
        Engine {
            name,
            path: PathBuf::from("/bin/false"),
            config_arg: ConfigArg::Long,
            gated: false,
            dialect,
            protocols: &[],
        }
    }

    #[test]
    fn custom_configs_sit_out_non_xray_engines_with_a_reason() {
        let engines = vec![
            dialect_engine("xray-core", parity::Dialect::Xray),
            dialect_engine("sing-box", parity::Dialect::SingBox),
        ];
        let custom = Workload {
            outbound_config: r#"{"outbounds":[]}"#.into(),
            ..workload()
        };
        let (names, skipped) = participant_names(&engines, &custom);
        assert_eq!(names, vec!["xray-core"]);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "sing-box");
        assert!(
            skipped[0].1.contains("Xray-dialect"),
            "the reason names the mismatch: {}",
            skipped[0].1
        );
        let (names, skipped) = participant_names(&engines, &workload());
        assert_eq!(names, vec!["xray-core", "sing-box"]);
        assert_eq!(skipped, Vec::new());
    }

    fn protocol_limited_engine() -> Engine {
        Engine {
            protocols: &["socks", "http", "tun"],
            ..dialect_engine("xray-rust", parity::Dialect::Xray)
        }
    }

    fn scenario_workload(scenario: &str) -> Workload {
        Workload {
            scenario: scenario.into(),
            ..workload()
        }
    }

    #[test]
    fn an_engine_that_cannot_serve_the_scenarios_protocol_sits_out_with_a_reason() {
        let engines = vec![
            protocol_limited_engine(),
            dialect_engine("xray-core", parity::Dialect::Xray),
        ];
        let (names, skipped) = participant_names(&engines, &scenario_workload("vless-raw-down-8"));
        assert_eq!(
            names,
            vec!["xray-core"],
            "an engine that cannot parse the inbound must not be measured"
        );
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "xray-rust");
        let reason = &skipped[0].1;
        assert!(
            reason.contains("vless") && reason.contains("socks, http, tun"),
            "the reason names the protocol and what the pin does accept: {reason}"
        );

        for id in [
            "vless-ws-down-8",
            "vless-grpc-down-8",
            "vless-xhttp-down-8",
            "vmess-raw-down-8",
            "trojan-raw-down-8",
            "shadowsocks-raw-down-8",
        ] {
            let (names, skipped) = participant_names(&engines, &scenario_workload(id));
            assert_eq!(
                names,
                vec!["xray-core"],
                "{id}: the protocol is the leading rung, whatever follows it"
            );
            assert!(
                skipped[0].1.starts_with(id.split('-').next().unwrap()),
                "{id}: the reason names the protocol it sat out on: {}",
                skipped[0].1
            );
        }

        let (names, skipped) = participant_names(&engines, &scenario_workload("socks-down-1"));
        assert_eq!(names, vec!["xray-rust", "xray-core"]);
        assert_eq!(skipped, Vec::new());
    }

    #[test]
    fn a_per_engine_config_keeps_the_protocol_its_pin_lacks_out() {
        let mut rust = dialect_engine("xray-rust", parity::Dialect::Xray);
        rust.protocols = &["vless", "vmess", "trojan", "shadowsocks2022", "hysteria"];
        let engines = vec![rust, dialect_engine("xray-core", parity::Dialect::Xray)];
        let mut workload = scenario_workload("shadowsocks-raw-down-8");
        workload.outbound_configs = vec![("xray-rust".into(), "{}".into())];
        let (names, skipped) = participant_names(&engines, &workload);
        assert_eq!(names, vec!["xray-core"]);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].1.starts_with("shadowsocks"));
        let mut workload = scenario_workload("shadowsocks2022-raw-down-8");
        workload.outbound_configs = vec![("xray-rust".into(), "{}".into())];
        let (names, _) = participant_names(&engines, &workload);
        assert_eq!(names, vec!["xray-rust", "xray-core"]);
    }

    #[test]
    fn an_engine_without_the_scenarios_carrier_sits_out_with_a_reason() {
        let engines = vec![
            dialect_engine("xray-rust", parity::Dialect::Xray),
            dialect_engine("zeronet", parity::Dialect::Xray),
            dialect_engine("xray-core", parity::Dialect::Xray),
        ];
        let (names, skipped) = participant_names(&engines, &scenario_workload("vless-kcp-down-8"));
        assert_eq!(names, vec!["xray-core"]);
        assert_eq!(skipped.len(), 2);
        assert!(skipped.iter().all(|(_, reason)| reason.contains("kcp")));
        let (names, skipped) =
            participant_names(&engines, &scenario_workload("vless-hysteria-down-8"));
        assert_eq!(names, vec!["xray-rust", "xray-core"]);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "zeronet");
    }

    #[test]
    fn a_scenario_that_names_no_protocol_never_sits_an_engine_out() {
        let engines = vec![protocol_limited_engine()];
        for id in ["gate5", ""] {
            let (names, skipped) = participant_names(&engines, &scenario_workload(id));
            assert_eq!(
                names,
                vec!["xray-rust"],
                "{id:?}: no protocol is named, so there is nothing to sit out"
            );
            assert_eq!(skipped, Vec::new(), "{id:?}: and no reason may be invented");
        }
    }

    #[test]
    fn every_matrix_scenario_id_names_a_protocol() {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/lib-matrix.sh");
        let text = std::fs::read_to_string(&script)
            .unwrap_or_else(|e| panic!("reading {}: {e}", script.display()));
        let mut ids = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("echo \"") else {
                continue;
            };
            let Some(id) = rest.split(' ').next() else {
                continue;
            };
            if id.split('-').count() >= 2 && !id.contains(['/', '"']) {
                ids.push(id.to_owned());
            }
        }
        assert!(
            ids.len() >= 11,
            "found only {} cell ids in {}: the reader has stopped matching the \
             script rather than the matrix having shrunk",
            ids.len(),
            script.display()
        );
        for id in &ids {
            assert!(
                protocol_of(id).is_some(),
                "{id}: the matrix runs this cell but `protocol_of` does not name \
                 a protocol for it, so an engine that cannot serve it would be \
                 started and reported as a fault instead of sitting out"
            );
        }
    }

    /// The window a cell may spend measuring is bounded by the CI job that runs it: a job cut off at its timeout prints no verdict and uploads no bundle, which is exactly what a per-measure budget of 240s did to macos-15 `vless-raw-duplex-8` - the cell ran 04:47:09 to 05:16:55 of a 30-minute job and was cancelled mid-run. The grid now runs both server passes in that job, so the bound doubles.
    #[test]
    fn the_cell_window_leaves_room_for_the_job_timeout_the_matrix_declares() {
        // What the job spends outside the harness. Measured on the macos-15 duplex-8 cell of run 39194705301: 27s from `Set up job` to the cell step, 4s from the step's end to `Complete job`, rounded up.
        const CELL_JOB_STEPS: Duration = Duration::from_secs(60);
        const SERVER_PASSES: u32 = 2;
        let workflow = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.github/workflows/benchmark-matrix.yml");
        let text = std::fs::read_to_string(&workflow)
            .unwrap_or_else(|e| panic!("reading {}: {e}", workflow.display()));
        let cells = text
            .split_once("\n  cells:")
            .unwrap_or_else(|| panic!("{} has no `cells:` job", workflow.display()))
            .1;
        let declared = cells
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("timeout-minutes:")
                    .and_then(|value| value.trim().parse::<u64>().ok())
            })
            .unwrap_or_else(|| panic!("the cells job declares no timeout-minutes"));
        // The last measure a cell starts can take its run cap and then the whole re-measure bound, and `fits` only admits it while the margin plus the cap are still left - so past the window the cell can cost the bound it kept back, once per server pass.
        let worst = (parity::CELL_WINDOW + parity::REMEASURE_BUDGET)
            .checked_sub(parity::CELL_MARGIN)
            .expect("the window plus the re-measure bound outlasts the margin")
            * SERVER_PASSES;
        assert!(
            worst + CELL_JOB_STEPS <= Duration::from_secs(declared * 60),
            "a cell can cost {worst:?} at its worst and the job spends {CELL_JOB_STEPS:?} outside \
             the harness, but the matrix declares only {declared} minutes: the cell would be cut \
             off mid-run and report nothing"
        );
    }

    /// A reference that landed no run is no baseline, so the cell is `no-reference` and fails: zero reference runs is missing data, and missing data must never read as parity (#358). The old line called it `unmeasured by the runner` and passed.
    #[test]
    fn a_reference_that_landed_no_run_is_no_reference_not_a_pass() {
        let empty = |engine: &'static str| EngineRuns {
            engine,
            dialect: parity::Dialect::Xray,
            runs: Vec::new(),
        };
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![empty("xray-core"), empty("ferrox")],
            ceilings_mib_s: Vec::new(),
            gated: Some("ferrox"),
            failures: vec![
                ("xray-core".to_owned(), "workload: forged byte".to_owned()),
                ("ferrox".to_owned(), "workload: transient".to_owned()),
            ],
            skipped: Vec::new(),
            machine: "test".into(),
        };
        let gate = comparison.gate();
        assert!(
            !gate.passed,
            "an empty reference has nothing to compare against, so the cell is not a pass: {:?}",
            gate.lines
        );
        assert!(
            gate.lines
                .iter()
                .any(|line| line.contains("no reference") && line.contains("xray-core")),
            "the line names the missing reference: {:?}",
            gate.lines
        );
    }

    /// #358's shape: `xray-core` exits during startup in every repeat while `ferrox` measures, and the cell used to report `gate_passed: true` over three empty reference runs and three `unproven` rows.
    #[test]
    fn a_reference_that_died_at_startup_is_no_reference_not_a_pass() {
        let startup_failure =
            "engine: exited during startup with exit status: 23; stderr tail: <empty>";
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                EngineRuns {
                    engine: "xray-core",
                    dialect: parity::Dialect::Xray,
                    runs: Vec::new(),
                },
                synth_engine(
                    "ferrox",
                    [(200, 3000, 10240), (220, 3100, 10250), (240, 3200, 10260)],
                ),
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: vec![
                ("xray-core".to_owned(), startup_failure.to_owned()),
                ("xray-core".to_owned(), startup_failure.to_owned()),
                ("xray-core".to_owned(), startup_failure.to_owned()),
            ],
            skipped: Vec::new(),
            machine: "test".into(),
        };
        let gate = comparison.gate();
        assert!(
            !gate.passed,
            "a reference that never started cannot make the cell pass: {:?}",
            gate.lines
        );
        let line = gate.lines.join("\n");
        assert!(
            line.contains("no reference") && line.contains("xray-core"),
            "the line names the missing reference: {line}"
        );
        assert!(
            line.contains("exit status: 23") && line.contains("3 failure(s)"),
            "the line carries why the reference never ran: {line}"
        );
    }

    /// The escape hatch is only for an unmeasurable reference: a candidate that lands nothing while the reference does is still an unproven regression.
    #[test]
    fn a_candidate_that_lands_nothing_while_the_reference_is_measured_still_fails() {
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                synth_engine(
                    "xray-core",
                    [(100, 6000, 20480), (110, 6200, 20500), (120, 6400, 20600)],
                ),
                EngineRuns {
                    engine: "ferrox",
                    dialect: parity::Dialect::Xray,
                    runs: Vec::new(),
                },
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: vec![("ferrox".to_owned(), "workload: transient".to_owned())],
            skipped: Vec::new(),
            machine: "test".into(),
        };
        assert!(
            !comparison.gate().passed,
            "a ferrox that lands nothing against a measured reference is still an unproven regression"
        );
    }

    /// The storm of a saturated runner is per-machine, so a workload fault seen on an engine other than the one under test means the candidate was starved by the machine, not bested: a gated candidate that lands nothing while a comparator took the same fault is unmeasured, not a regression.
    #[test]
    fn a_candidate_starved_by_a_machine_wide_workload_storm_is_unmeasured() {
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                synth_engine(
                    "xray-core",
                    [(100, 6000, 20480), (110, 6200, 20500), (120, 6400, 20600)],
                ),
                EngineRuns {
                    engine: "ferrox",
                    dialect: parity::Dialect::Xray,
                    runs: Vec::new(),
                },
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: vec![
                ("xray-core".to_owned(), "workload: desync".to_owned()),
                ("ferrox".to_owned(), "workload: transient".to_owned()),
            ],
            skipped: Vec::new(),
            machine: "test".into(),
        };
        let gate = comparison.gate();
        assert!(
            gate.passed,
            "a ferrox starved by a storm the reference also hit is not its regression: {:?}",
            gate.lines
        );
        assert!(
            gate.lines
                .iter()
                .any(|line| line.contains("unmeasured by the runner")
                    && line.contains("engine under test")),
            "the line names the engine under test starved by the machine, not the reference: {:?}",
            gate.lines
        );
    }

    /// A cell that ran out of its CI window is the clearest machine-wide shortfall: no engine was fairly measured, so the gated candidate landing nothing while the window-end failure names `cell` is unmeasured, not a regression.
    #[test]
    fn a_candidate_starved_when_the_cell_window_ended_is_unmeasured() {
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                synth_engine(
                    "xray-core",
                    [(100, 6000, 20480), (110, 6200, 20500), (120, 6400, 20600)],
                ),
                EngineRuns {
                    engine: "ferrox",
                    dialect: parity::Dialect::Xray,
                    runs: Vec::new(),
                },
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: vec![(
                "cell".to_owned(),
                "the cell's window ended before every measure ran".to_owned(),
            )],
            skipped: Vec::new(),
            machine: "test".into(),
        };
        let gate = comparison.gate();
        assert!(
            gate.passed,
            "a ferrox starved by a cut-off cell window is not its regression: {:?}",
            gate.lines
        );
        assert!(
            gate.lines
                .iter()
                .any(|line| line.contains("unmeasured by the runner")
                    && line.contains("engine under test")),
            "the window-end case names the engine under test starved by the machine: {:?}",
            gate.lines
        );
    }

    #[test]
    fn comparison_json_reports_rows_verdicts_and_cells() {
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                synth_engine(
                    "xray-core",
                    [(100, 6000, 20480), (110, 6200, 20500), (120, 6400, 20600)],
                ),
                synth_engine(
                    "ferrox",
                    [(200, 3000, 10240), (220, 3100, 10250), (240, 3200, 10260)],
                ),
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: Vec::new(),
            skipped: Vec::new(),
            machine: "test".into(),
        };
        let text = comparison
            .comparison_json("vless-raw-down-1")
            .expect("synthetic cells always serialise");
        let root = json::parse(&text).expect("the document parses as json");
        let str_of = |doc: &Json, key: &str| {
            doc.get(key)
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(str_of(&root, "scenario"), "vless-raw-down-1");
        assert_eq!(str_of(&root, "reference"), "xray-core");
        let rows = root.get("rows").expect("rows");
        let pairs: Vec<(String, String, String, bool)> = match rows {
            Json::Arr(items) => items
                .iter()
                .map(|row| {
                    (
                        str_of(row, "label"),
                        str_of(row, "direction"),
                        str_of(row, "verdict"),
                        row.get("gates").and_then(Json::as_bool) == Some(true),
                    )
                })
                .collect(),
            _ => panic!("rows is an array"),
        };
        assert_eq!(
            pairs
                .iter()
                .map(|(_, _, verdict, _)| verdict.clone())
                .collect::<Vec<_>>(),
            vec!["better", "better", "better", "within-noise", "within-noise"]
        );
        assert_eq!(pairs[0].1, "higher");
        assert_eq!(pairs[1].1, "lower");
        assert_eq!(pairs[2].1, "lower");
        // A call count diagnoses how the cpu was spent, so the kernel rows attribute and never gate.
        let kernel: Vec<&str> = pairs
            .iter()
            .filter(|(_, _, _, gated)| *gated)
            .map(|(label, ..)| label.as_str())
            .collect();
        assert_eq!(
            kernel,
            vec![
                "throughput (ferrox vs xray-core)",
                "cpu per GiB (ferrox vs xray-core)",
                "peak rss (ferrox vs xray-core, 5% tolerance)",
            ],
            "the two kernel rows report and never gate"
        );
        assert!(
            pairs[3].0.starts_with("kernel calls per GiB")
                && pairs[4].0.starts_with("kernel bytes per GiB"),
            "a cell names what it counted: {:?}",
            pairs[3].0,
        );
        assert!(root
            .get("gate_passed")
            .and_then(Json::as_bool)
            .unwrap_or(false));
        let engines = root.get("engines").expect("engines");
        let first_run = match engines {
            Json::Arr(items) => match items.first().expect("an engine").get("runs") {
                Some(Json::Arr(runs)) => runs.first().expect("a run").clone(),
                other => panic!("runs is an array, got {other:?}"),
            },
            _ => panic!("engines is an array"),
        };
        assert!(
            first_run.get("threads_peak").is_some(),
            "threads_peak travels with the cell"
        );
        assert_eq!(
            first_run.get("startup_seconds").and_then(Json::as_num),
            Some(0.0)
        );
        assert_eq!(
            first_run.get("transfer_seconds").and_then(Json::as_num),
            Some(1.0)
        );
    }

    /// One connection crossing 8 KiB in the whole run, the shape of `vless-raw-setup-1k`: the
    /// reference burns `cpu_millis` per repeat, the candidate finishes inside a single tick.
    fn micro_comparison(cpu_millis: [u64; 3]) -> Comparison {
        const EIGHT_KIB: u64 = 8 * 1024;
        Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                synth_micro_engine(
                    "xray-core",
                    [
                        (EIGHT_KIB, 512, cpu_millis[0], 35_900),
                        (EIGHT_KIB, 512, cpu_millis[1], 36_100),
                        (EIGHT_KIB, 512, cpu_millis[2], 36_300),
                    ],
                ),
                synth_micro_engine(
                    "ferrox",
                    [
                        (EIGHT_KIB, 10, 0, 6_500),
                        (EIGHT_KIB, 10, 0, 6_600),
                        (EIGHT_KIB, 11, 0, 6_700),
                    ],
                ),
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: Vec::new(),
            skipped: Vec::new(),
            machine: "test".into(),
        }
    }

    fn gated_row(comparison: &Comparison, prefix: &str) -> stats::Row {
        comparison
            .rows()
            .into_iter()
            .find(|row| row.label.starts_with(prefix) && row.label.contains("(ferrox vs xray-core"))
            .unwrap_or_else(|| panic!("no {prefix} row for the gated engine"))
    }

    #[test]
    fn a_workload_that_prices_no_per_gib_rate_reports_the_cpu_row_with_its_reason() {
        let comparison = micro_comparison([0, 0, stats::min_pricable_cpu_millis() - 1]);
        let cpu = gated_row(&comparison, "cpu per GiB");
        assert_eq!(
            stats::verdict(cpu.interval, cpu.direction),
            stats::Verdict::Unproven,
            "the nightly setup row: every pair divides by a zero tick count"
        );
        assert!(
            !cpu.gates && cpu.unpriced,
            "one tick of the sampler is the whole cpu span, so this row measures the tick: {cpu:?}"
        );
        for prefix in ["throughput", "peak rss"] {
            let row = gated_row(&comparison, prefix);
            assert!(
                row.gates && !row.unpriced,
                "the {prefix} row reads the same repeats and still decides the job"
            );
        }
        let gate = comparison.gate();
        assert!(gate.passed, "{:?}", gate.lines);
        let line = gate
            .lines
            .iter()
            .find(|line| line.starts_with("cpu per GiB"))
            .expect("the cpu row is published");
        assert!(line.contains("reported, not gated"), "{line}");
        assert!(line.contains("sampler"), "{line}");
        assert!(
            !line.contains("pinned comparator"),
            "the reason is the size of the workload, not the role of the engine: {line}"
        );
        let root = json::parse(&comparison.comparison_json("t").expect("serialises"))
            .expect("the document parses");
        let flags: Vec<(String, bool)> = match root.get("rows").expect("rows") {
            Json::Arr(items) => items
                .iter()
                .map(|row| {
                    (
                        row.get("label")
                            .and_then(Json::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        row.get("unpriced").and_then(Json::as_bool) == Some(true),
                    )
                })
                .collect(),
            _ => panic!("rows is an array"),
        };
        assert_eq!(
            flags.iter().filter(|(_, unpriced)| *unpriced).count(),
            1,
            "exactly the per-GiB row this workload cannot price: {flags:?}"
        );
        assert!(flags[1].0.starts_with("cpu per GiB"), "{:?}", flags[1].0);
    }

    #[test]
    fn an_unpriced_cpu_row_never_hides_a_missing_repeat() {
        let mut thin = synth_engine(
            "ferrox",
            [(200, 3000, 10240), (220, 3100, 10250), (240, 3200, 10260)],
        );
        thin.runs.truncate(1);
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                synth_engine(
                    "xray-core",
                    [(100, 6000, 20480), (110, 6200, 20500), (120, 6400, 20600)],
                ),
                thin,
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: Vec::new(),
            skipped: Vec::new(),
            machine: "test".into(),
        };
        let cpu = gated_row(&comparison, "cpu per GiB");
        assert!(
            cpu.gates && !cpu.unpriced,
            "these repeats price a per-GiB rate, so one repeat short is missing data: {cpu:?}"
        );
        assert!(
            !comparison.gate().passed,
            "and missing data must not pass on the strength of an unpriced row"
        );
    }

    #[test]
    fn too_few_repeats_is_refused() {
        let err = run(
            &[engine("a", "/bin/true"), engine("b", "/bin/true")],
            &workload(),
            0,
            Path::new("/tmp/x"),
            false,
        )
        .expect_err("too few repeats cannot be read");
        assert!(err.to_string().contains("minimum worth reading"), "{err}");
    }

    #[test]
    fn a_request_names_the_engine_and_the_workload() {
        let w = workload();
        let text = w.request(&engine("ferrox", "/bin/dv"), Path::new("/tmp/out"));
        let root = json::parse(&text).expect("valid json");
        assert_eq!(root.get("binary").and_then(Json::as_str), Some("/bin/dv"));
        assert_eq!(root.get("traffic").and_then(Json::as_str), Some("upload"));
        assert_eq!(root.get("connections").and_then(Json::as_num), Some(1.0));
        assert_eq!(root.get("iterations").and_then(Json::as_num), Some(16.0));
        assert_eq!(
            root.get("payload_size").and_then(Json::as_num),
            Some(1024.0)
        );
        assert_eq!(root.get("output").and_then(Json::as_str), Some("/tmp/out"));
        assert_eq!(root.get("warmup").and_then(Json::as_bool), Some(false));
    }

    #[test]
    fn the_request_it_writes_is_one_it_accepts() {
        let w = workload();
        let exe = std::env::current_exe().expect("a test binary has a path");
        let text = w.request(
            &engine("ferrox", &exe.to_string_lossy()),
            Path::new("/tmp/ferrox-parity-test"),
        );
        let parsed = Request::parse(text.as_bytes()).expect("the harness accepts its own request");
        assert_eq!(parsed.connections, w.connections);
        assert_eq!(parsed.iterations, w.iterations);
        assert_eq!(parsed.payload_size, w.payload_size);
        assert_eq!(parsed.total_bytes(), w.total_bytes());
    }

    #[test]
    fn the_workload_description_names_the_bytes() {
        let w = workload();
        let described = w.describe();
        assert!(described.contains("16 MiB") || described.contains("MiB total"));
        assert!(described.contains("upload"));
    }

    #[test]
    fn byte_accounting_matches_the_request() {
        let mut w = workload();
        w.connections = 4;
        w.iterations = 100;
        w.payload_size = 16384;
        assert_eq!(w.flow_bytes(), 100 * 16_384);
        assert_eq!(w.total_bytes(), 4 * 100 * 16_384);

        let mut duplex = workload();
        duplex.traffic = "full-duplex".into();
        duplex.connections = 8;
        duplex.iterations = 16384;
        duplex.payload_size = 65536;
        assert_eq!(duplex.flow_bytes(), 16384 * 65536);
        assert_eq!(duplex.total_bytes(), 2 * 8 * 16384 * 65536);
        assert!(
            duplex.describe().contains("(16384 MiB total)"),
            "the header names the same figure the accounting does: {}",
            duplex.describe()
        );

        let mut down = workload();
        down.traffic = "download".into();
        down.connections = 1;
        assert_eq!(down.total_bytes(), down.flow_bytes());
        down.connections = 8;
        assert_eq!(down.total_bytes(), 8 * down.flow_bytes());
    }
}
