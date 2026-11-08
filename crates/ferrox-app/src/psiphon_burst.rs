//! The reference's client burst metrics: a transfer of `target` bytes inside a
//! deadline is one burst, and the first, last, fastest and slowest are kept.

use std::time::{Duration, Instant};

/// One direction's target and deadline; both must be non-zero to enable it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    pub(crate) upstream_target: u64,
    pub(crate) upstream_deadline: Duration,
    pub(crate) downstream_target: u64,
    pub(crate) downstream_deadline: Duration,
}

impl Config {
    /// Build a config from the four reference settings, disabled when either half is zero.
    pub(crate) fn new(
        upstream_target: u64,
        upstream_deadline: Duration,
        downstream_target: u64,
        downstream_deadline: Duration,
    ) -> Option<Self> {
        let config = Self {
            upstream_target,
            upstream_deadline,
            downstream_target,
            downstream_deadline,
        };
        (config.up_enabled() || config.down_enabled()).then_some(config)
    }

    /// Whether the upstream half has both a target and a deadline.
    fn up_enabled(&self) -> bool {
        self.upstream_target > 0 && !self.upstream_deadline.is_zero()
    }

    /// Whether the downstream half has both a target and a deadline.
    fn down_enabled(&self) -> bool {
        self.downstream_target > 0 && !self.downstream_deadline.is_zero()
    }
}

/// One completed or in-progress transfer.
#[derive(Clone, Copy, Debug, Default)]
struct Record {
    start: Option<Instant>,
    end: Option<Instant>,
    bytes: u64,
}

impl Record {
    /// Whether no burst is currently open.
    fn is_zero(&self) -> bool {
        self.start.is_none()
    }

    /// The completed burst's elapsed time.
    fn duration(&self) -> Duration {
        match (self.start, self.end) {
            (Some(start), Some(end)) => end.saturating_duration_since(start),
            _ => Duration::ZERO,
        }
    }

    /// The burst start offset from the session open.
    fn offset(&self, base: Instant) -> Duration {
        self.start.map_or(Duration::ZERO, |start| {
            start.saturating_duration_since(base)
        })
    }

    /// The burst rate in bytes per second.
    fn rate(&self) -> u64 {
        let nanos = self.duration().as_nanos();
        if nanos == 0 {
            return 0;
        }
        u64::try_from(u128::from(self.bytes) * 1_000_000_000 / nanos).unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct History {
    first: Record,
    last: Record,
    min: Record,
    max: Record,
}

impl History {
    /// Keep the first, last, slowest and fastest completed burst.
    fn record(&mut self, burst: Record) {
        if self.first.is_zero() {
            self.first = burst;
        }
        self.last = burst;
        if self.min.is_zero() || self.min.rate() > burst.rate() {
            self.min = burst;
        }
        if self.max.is_zero() || self.max.rate() < burst.rate() {
            self.max = burst;
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Direction {
    current: Record,
    history: History,
}

impl Direction {
    /// Fold one write into the open burst, or start a new one.
    fn update(
        &mut self,
        start: Instant,
        end: Instant,
        bytes: u64,
        target: u64,
        deadline: Duration,
    ) {
        if !self.current.is_zero()
            && end.saturating_duration_since(self.current.start.unwrap_or(end)) > deadline
        {
            self.current = Record::default();
        }
        if end.saturating_duration_since(start) > deadline {
            return;
        }
        if self.current.is_zero() {
            self.current.start = Some(start);
        }
        self.current.bytes = self.current.bytes.saturating_add(bytes);
        if self.current.bytes >= target {
            self.current.end = Some(end);
            self.history.record(self.current);
            self.current = Record::default();
        }
    }
}

/// The per-session burst monitor. Disabled means every update is one branch.
#[derive(Debug)]
pub(crate) struct Burst {
    config: Option<Config>,
    upstream: Direction,
    downstream: Direction,
    base: Instant,
}

impl Default for Burst {
    fn default() -> Self {
        Self {
            config: None,
            upstream: Direction::default(),
            downstream: Direction::default(),
            base: Instant::now(),
        }
    }
}

impl Burst {
    /// Build a monitor; `config` is `None` when both directions are disabled.
    pub(crate) fn new(config: Option<Config>, base: Instant) -> Self {
        Self {
            config,
            upstream: Direction::default(),
            downstream: Direction::default(),
            base,
        }
    }

    /// Record an upstream write when the upstream half is enabled.
    pub(crate) fn upstream(&mut self, start: Instant, end: Instant, bytes: u64) {
        if let Some(config) = self.config {
            if config.up_enabled() {
                self.upstream.update(
                    start,
                    end,
                    bytes,
                    config.upstream_target,
                    config.upstream_deadline,
                );
            }
        }
    }

    /// Record a downstream read when the downstream half is enabled.
    pub(crate) fn downstream(&mut self, start: Instant, end: Instant, bytes: u64) {
        if let Some(config) = self.config {
            if config.down_enabled() {
                self.downstream.update(
                    start,
                    end,
                    bytes,
                    config.downstream_target,
                    config.downstream_deadline,
                );
            }
        }
    }

    /// The reference's four bursts per direction, or `None` when nothing completed.
    pub(crate) fn metrics(&self) -> Option<String> {
        if self.upstream.history.first.is_zero() && self.downstream.history.first.is_zero() {
            return None;
        }
        let mut line = String::with_capacity(256);
        push_history(&mut line, "upstream", &self.upstream.history, self.base);
        push_history(&mut line, "downstream", &self.downstream.history, self.base);
        Some(line)
    }
}

/// Append one direction's completed bursts to the close-time line.
fn push_history(line: &mut String, name: &str, history: &History, base: Instant) {
    use std::fmt::Write as _;
    for (label, burst) in [
        ("first", history.first),
        ("last", history.last),
        ("min", history.min),
        ("max", history.max),
    ] {
        if burst.is_zero() {
            continue;
        }
        let _ = write!(
            line,
            " {name}_{label}=offset:{}ms,duration:{}ms,bytes:{},rate:{}",
            burst.offset(base).as_millis(),
            burst.duration().as_millis(),
            burst.bytes,
            burst.rate()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_completes_and_keeps_the_first_and_last() {
        let start = Instant::now();
        let config = Config::new(100, Duration::from_secs(1), 0, Duration::ZERO).expect("config");
        let mut burst = Burst::new(Some(config), start);
        burst.upstream(start, start + Duration::from_millis(10), 60);
        burst.upstream(
            start + Duration::from_millis(10),
            start + Duration::from_millis(20),
            50,
        );
        let metrics = burst.metrics().expect("metrics");
        assert!(metrics.contains("upstream_first=offset:0ms,duration:20ms,bytes:110"));
        assert!(metrics.contains("upstream_last=offset:0ms,duration:20ms,bytes:110"));
        assert!(!metrics.contains("downstream_"));
    }

    #[test]
    fn a_burst_that_misses_its_deadline_is_discarded() {
        let start = Instant::now();
        let config =
            Config::new(100, Duration::from_millis(10), 0, Duration::ZERO).expect("config");
        let mut burst = Burst::new(Some(config), start);
        burst.upstream(start, start, 50);
        burst.upstream(
            start + Duration::from_millis(20),
            start + Duration::from_millis(20),
            50,
        );
        assert!(burst.metrics().is_none());
    }

    #[test]
    fn disabled_bursts_record_nothing() {
        let start = Instant::now();
        let mut burst = Burst::new(None, start);
        burst.upstream(start, start, 1_000_000);
        burst.downstream(start, start, 1_000_000);
        assert!(burst.metrics().is_none());
    }

    #[test]
    fn zero_target_or_deadline_disables_its_direction() {
        assert!(Config::new(0, Duration::from_secs(1), 0, Duration::from_secs(1)).is_none());
        assert!(Config::new(1, Duration::ZERO, 1, Duration::ZERO).is_none());
        assert!(Config::new(1, Duration::from_secs(1), 0, Duration::ZERO).is_some());
    }
}
