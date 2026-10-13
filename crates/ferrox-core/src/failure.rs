use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Rung {
    Raw = 0,
    Ws = 1,
    Xhttp = 2,
    Grpc = 3,
    HttpUpgrade = 4,
}

impl Rung {
    pub const ALL: [Self; 5] = [
        Self::Raw,
        Self::Ws,
        Self::Xhttp,
        Self::Grpc,
        Self::HttpUpgrade,
    ];

    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Raw => Some(Self::Ws),
            Self::Ws => Some(Self::Xhttp),
            Self::Xhttp => Some(Self::Grpc),
            Self::Grpc => Some(Self::HttpUpgrade),
            Self::HttpUpgrade => None,
        }
    }

    #[must_use]
    pub const fn previous(self) -> Option<Self> {
        match self {
            Self::Raw => None,
            Self::Ws => Some(Self::Raw),
            Self::Xhttp => Some(Self::Ws),
            Self::Grpc => Some(Self::Xhttp),
            Self::HttpUpgrade => Some(Self::Grpc),
        }
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Ws,
            2 => Self::Xhttp,
            3 => Self::Grpc,
            4 => Self::HttpUpgrade,
            _ => Self::Raw,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Ws => "ws",
            Self::Xhttp => "xhttp",
            Self::Grpc => "grpc",
            Self::HttpUpgrade => "httpupgrade",
        }
    }

    #[must_use]
    pub const fn climb_from(start: Self) -> ([Self; 5], usize) {
        let mut rungs = [Self::Raw; 5];
        let mut count = 0;
        let mut rung = start;
        loop {
            rungs[count] = rung;
            count += 1;
            match rung.next() {
                Some(above) => rung = above,
                None => break,
            }
        }
        (rungs, count)
    }
}

impl fmt::Display for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// Useful successes at the current rung before a cheaper one is re-probed.
const DESCEND_AFTER_SUCCESSES: u32 = 16;

#[derive(Debug, Default)]
struct LadderCounts {
    attempts: [u64; 5],
    useful: [u64; 5],
    climbs: u64,
    descents: u64,
}

#[derive(Debug)]
pub struct Ladder {
    packed: AtomicU64,
    locked: Mutex<LadderCounts>,
}

impl Ladder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            packed: AtomicU64::new(0),
            locked: Mutex::new(LadderCounts::default()),
        }
    }

    #[must_use]
    pub fn global() -> &'static Self {
        static LADDER: OnceLock<Ladder> = OnceLock::new();
        LADDER.get_or_init(Self::new)
    }

    fn unpack(packed: u64) -> (Rung, u32) {
        (Rung::from_u8(packed as u8), (packed >> 8) as u32)
    }

    fn pack(current: Rung, successes: u32) -> u64 {
        (u64::from(successes) << 8) | u64::from(current.as_u8())
    }

    #[must_use]
    pub fn current(&self) -> Rung {
        Self::unpack(self.packed.load(Ordering::Relaxed)).0
    }

    #[must_use]
    pub fn start_rung(&self) -> Rung {
        let (current, successes) = Self::unpack(self.packed.load(Ordering::Relaxed));
        if successes >= DESCEND_AFTER_SUCCESSES {
            current.previous().unwrap_or(current)
        } else {
            current
        }
    }

    #[must_use]
    pub fn record_success(&self, rung: Rung, stage: Stage, explicit: bool) -> Option<(Rung, u32)> {
        let Ok(mut counts) = self.locked.lock() else {
            return None;
        };
        counts.attempts[rung.as_u8() as usize] =
            counts.attempts[rung.as_u8() as usize].saturating_add(1);
        if !stage.is_useful_progress() {
            return None;
        }
        counts.useful[rung.as_u8() as usize] =
            counts.useful[rung.as_u8() as usize].saturating_add(1);
        let (current, successes) = Self::unpack(self.packed.load(Ordering::Relaxed));
        if rung == current {
            let successes = successes.saturating_add(1);
            self.packed
                .store(Self::pack(current, successes), Ordering::Relaxed);
            None
        } else if rung < current
            && (explicit
                || Some(rung) == current.previous() && successes >= DESCEND_AFTER_SUCCESSES)
        {
            self.packed.store(Self::pack(rung, 0), Ordering::Relaxed);
            counts.descents = counts.descents.saturating_add(1);
            Some((current, successes))
        } else {
            None
        }
    }

    // The rung the walk moves to is the rung the ladder keeps, so report and next dial agree.
    #[must_use]
    pub fn record_failure(&self, rung: Rung, failure: &Failure) -> Option<Rung> {
        let Ok(mut counts) = self.locked.lock() else {
            return None;
        };
        counts.attempts[rung.as_u8() as usize] =
            counts.attempts[rung.as_u8() as usize].saturating_add(1);
        if !failure.worth_retrying() {
            return None;
        }
        let (current, _) = Self::unpack(self.packed.load(Ordering::Relaxed));
        let Some(above) = rung.next() else {
            self.packed.store(Self::pack(current, 0), Ordering::Relaxed);
            return None;
        };
        self.packed.store(Self::pack(above, 0), Ordering::Relaxed);
        if above != current {
            counts.climbs = counts.climbs.saturating_add(1);
        }
        Some(above)
    }

    #[must_use]
    pub fn attempts(&self, rung: Rung) -> u64 {
        self.locked
            .lock()
            .map_or(0, |counts| counts.attempts[rung.as_u8() as usize])
    }

    #[must_use]
    pub fn useful(&self, rung: Rung) -> u64 {
        self.locked
            .lock()
            .map_or(0, |counts| counts.useful[rung.as_u8() as usize])
    }

    #[must_use]
    pub fn climbs(&self) -> u64 {
        self.locked.lock().map_or(0, |counts| counts.climbs)
    }

    #[must_use]
    pub fn descents(&self) -> u64 {
        self.locked.lock().map_or(0, |counts| counts.descents)
    }
}

impl Default for Ladder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Stage {
    Resolving = 0,
    SocketConnected = 1,
    RequestSent = 2,
    FirstByte = 3,
    PayloadTransferred = 4,
    Completed = 5,
}

impl Stage {
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn is_useful_progress(self) -> bool {
        self.rank() >= Self::FirstByte.rank()
    }

    pub const ALL: [Self; 6] = [
        Self::Resolving,
        Self::SocketConnected,
        Self::RequestSent,
        Self::FirstByte,
        Self::PayloadTransferred,
        Self::Completed,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Resolving => "resolving",
            Self::SocketConnected => "socket-connected",
            Self::RequestSent => "request-sent",
            Self::FirstByte => "first-byte",
            Self::PayloadTransferred => "payload-transferred",
            Self::Completed => "completed",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Unreachable,
    Refused,
    Dropped,
    Dns,
    Rejected,
    Local,
}

impl Kind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Refused => "refused",
            Self::Dropped => "dropped",
            Self::Dns => "dns",
            Self::Rejected => "rejected",
            Self::Local => "local",
        }
    }

    #[must_use]
    pub fn of(error: &std::io::Error) -> Self {
        use std::io::ErrorKind as E;
        match error.kind() {
            E::ConnectionRefused => Self::Refused,
            E::ConnectionReset | E::ConnectionAborted | E::BrokenPipe => Self::Dropped,
            E::NotFound => Self::Dns,
            E::PermissionDenied | E::AddrNotAvailable | E::InvalidInput => Self::Local,
            _ => Self::Unreachable,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Dropped | Self::Unreachable)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Inferred,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Failure {
    pub stage: Stage,
    pub kind: Kind,
    pub confidence: Confidence,
}

impl Failure {
    #[must_use]
    pub const fn new(stage: Stage, kind: Kind) -> Self {
        Self {
            stage,
            kind,
            confidence: match kind {
                Kind::Unreachable => Confidence::Inferred,
                _ => Confidence::Observed,
            },
        }
    }

    #[must_use]
    pub const fn worth_retrying(&self) -> bool {
        self.kind.retryable() && self.stage.rank() < Stage::FirstByte.rank()
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.kind, self.stage)?;
        if self.confidence == Confidence::Inferred {
            f.write_str(" (inferred)")
        } else {
            Ok(())
        }
    }
}

impl std::error::Error for Failure {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Support, TransportKind};
    use crate::vless::VlessLink;
    use std::io::{Error, ErrorKind};

    #[test]
    fn stage_order_is_evidence_order() {
        for pair in Stage::ALL.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} must sort below {:?}",
                pair[0],
                pair[1]
            );
            assert!(
                pair[0].is_useful_progress() <= pair[1].is_useful_progress(),
                "the threshold must be monotone or it is not a threshold"
            );
        }
    }

    #[test]
    fn first_byte_is_the_threshold_and_nothing_earlier_is() {
        for stage in Stage::ALL {
            assert_eq!(
                stage.is_useful_progress(),
                stage >= Stage::FirstByte,
                "{stage} disagrees with the ladder"
            );
        }
        assert!(!Stage::SocketConnected.is_useful_progress());
        assert!(Stage::FirstByte.is_useful_progress());
    }

    #[test]
    fn every_stage_has_a_distinct_name() {
        let mut names: Vec<&str> = Stage::ALL.iter().map(|s| s.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            count,
            "two stages share a name, so a report cannot tell them apart"
        );
        for stage in Stage::ALL {
            assert_eq!(stage.to_string(), stage.name());
        }
    }

    #[test]
    fn every_error_kind_lands_somewhere_and_the_unmapped_one_is_conservative() {
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::AddrNotAvailable,
            ErrorKind::BrokenPipe,
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
            ErrorKind::InvalidInput,
            ErrorKind::WouldBlock,
            ErrorKind::UnexpectedEof,
        ] {
            let name = Kind::of(&Error::new(kind, "x")).to_string();
            assert!(!name.is_empty(), "{kind:?} landed on an unnamed kind");
        }
        for error in [Error::other("x"), Error::new(ErrorKind::Interrupted, "x")] {
            assert_eq!(Kind::of(&error), Kind::Unreachable);
        }
    }

    #[test]
    fn each_error_kind_maps_to_the_kind_named_for_it() {
        let of = |k| Kind::of(&Error::new(k, "x"));
        assert_eq!(of(ErrorKind::ConnectionRefused), Kind::Refused);
        assert_eq!(of(ErrorKind::ConnectionReset), Kind::Dropped);
        assert_eq!(of(ErrorKind::ConnectionAborted), Kind::Dropped);
        assert_eq!(of(ErrorKind::BrokenPipe), Kind::Dropped);
        assert_eq!(of(ErrorKind::TimedOut), Kind::Unreachable);
        assert_eq!(of(ErrorKind::NotFound), Kind::Dns);
        assert_eq!(of(ErrorKind::AddrNotAvailable), Kind::Local);
        assert_eq!(of(ErrorKind::PermissionDenied), Kind::Local);
        assert_eq!(of(ErrorKind::InvalidInput), Kind::Local);
    }

    #[test]
    fn only_the_silent_kind_is_inferred() {
        for kind in [
            Kind::Unreachable,
            Kind::Refused,
            Kind::Dropped,
            Kind::Dns,
            Kind::Rejected,
            Kind::Local,
        ] {
            let failure = Failure::new(Stage::SocketConnected, kind);
            assert_eq!(
                failure.confidence,
                if kind == Kind::Unreachable {
                    Confidence::Inferred
                } else {
                    Confidence::Observed
                },
                "{kind} carries the wrong confidence"
            );
        }
    }

    #[test]
    fn worth_retrying_needs_both_halves_of_the_argument() {
        assert!(Failure::new(Stage::SocketConnected, Kind::Unreachable).worth_retrying());
        assert!(Failure::new(Stage::Resolving, Kind::Dropped).worth_retrying());
        assert!(!Failure::new(Stage::FirstByte, Kind::Dropped).worth_retrying());
        assert!(!Failure::new(Stage::SocketConnected, Kind::Refused).worth_retrying());
        assert!(!Failure::new(Stage::SocketConnected, Kind::Dns).worth_retrying());
        assert!(!Failure::new(Stage::FirstByte, Kind::Rejected).worth_retrying());
        assert!(!Failure::new(Stage::Resolving, Kind::Local).worth_retrying());
    }

    #[test]
    fn a_completed_stage_is_never_a_failure_but_names_anyway() {
        assert!(!Failure::new(Stage::Completed, Kind::Dropped).worth_retrying());
        assert!(Stage::Completed.is_useful_progress());
        assert_eq!(Stage::Completed.name(), "completed");
    }

    #[test]
    fn display_names_the_stage_the_kind_and_the_hedge_only_when_it_applies() {
        assert_eq!(
            Failure::new(Stage::SocketConnected, Kind::Refused).to_string(),
            "refused at socket-connected"
        );
        assert_eq!(
            Failure::new(Stage::Resolving, Kind::Unreachable).to_string(),
            "unreachable at resolving (inferred)"
        );
        assert_eq!(Kind::Rejected.to_string(), "rejected");
    }

    #[test]
    fn every_stage_is_reachable_and_ordered_by_its_discriminant() {
        let mut sorted = Stage::ALL;
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            Stage::ALL,
            "the discriminants and the order disagree"
        );
        assert_eq!(Stage::ALL[0], Stage::Resolving);
        assert_eq!(Stage::ALL[Stage::ALL.len() - 1], Stage::Completed);
    }

    #[test]
    fn every_dialled_carrier_reports_implemented_not_planned() {
        for (kind, query) in [
            (TransportKind::Tcp, "type=tcp"),
            (TransportKind::Ws, "type=ws"),
            (TransportKind::Xhttp, "type=xhttp"),
            (TransportKind::Grpc, "type=grpc"),
            (TransportKind::Quic, "type=quic"),
            (TransportKind::HttpUpgrade, "type=httpupgrade"),
            (TransportKind::Kcp, "type=kcp"),
            (TransportKind::Hysteria, "type=hysteria"),
        ] {
            assert!(kind.is_dialled(), "{kind:?} is claimed dialled");
            let link = VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&{query}#rung"
            ))
            .expect("a synthetic rung link parses");
            assert!(
                matches!(link.support(), Support::Implemented { .. }),
                "{query} is dialled by proxy.rs, so support() must say so: {:?}",
                link.support()
            );
        }
    }

    #[test]
    fn an_undialled_carrier_stays_planned_with_its_reason() {
        for query in ["type=masque", "type=xdrive", "type=made-up"] {
            let link = VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&{query}#rung"
            ))
            .expect("a synthetic rung link parses");
            assert!(
                matches!(link.support(), Support::Planned { reason } if !reason.is_empty()),
                "{query} has no dial arm and must stay planned with a reason"
            );
        }
    }

    #[test]
    fn every_transport_kind_is_either_dialled_or_planned_with_a_reason() {
        for kind in TransportKind::ALL {
            assert_eq!(
                TransportKind::from_link(link_name(kind)),
                kind,
                "link_name and from_link disagree, so this walks the wrong cell"
            );
            let link = VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type={}#rung",
                link_name(kind)
            ))
            .expect("a synthetic rung link parses");
            match link.support() {
                Support::Implemented { .. } => assert!(kind.is_dialled(), "{kind:?} dials nothing"),
                Support::Planned { reason } => {
                    assert!(!kind.is_dialled(), "{kind:?} has a dial arm");
                    assert!(!reason.is_empty(), "{kind:?} is blank");
                }
                Support::UnsafeRequiresOptIn { reason } => assert_ne!(reason, ""),
            }
        }
    }

    fn link_name(kind: TransportKind) -> &'static str {
        match kind {
            TransportKind::Tcp => "tcp",
            TransportKind::Ws => "ws",
            TransportKind::Xhttp => "xhttp",
            TransportKind::Grpc => "grpc",
            TransportKind::Quic => "quic",
            TransportKind::HttpUpgrade => "httpupgrade",
            TransportKind::Kcp => "kcp",
            TransportKind::Http => "http",
            TransportKind::Hysteria => "hysteria",
            TransportKind::Masque => "masque",
            TransportKind::Xdrive => "xdrive",
            TransportKind::Other => "made-up",
        }
    }

    #[test]
    fn rungs_climb_in_ladder_order_and_fit_one_byte() {
        assert_eq!(Rung::ALL.len(), 5);
        let mut rung = Rung::Raw;
        for (index, want) in Rung::ALL.iter().enumerate() {
            assert_eq!(rung, *want);
            assert_eq!(rung.as_u8() as usize, index);
            assert_eq!(Rung::from_u8(index as u8), *want);
            rung = rung.next().unwrap_or(Rung::HttpUpgrade);
        }
        assert_eq!(Rung::HttpUpgrade.next(), None);
        assert_eq!(Rung::Raw.previous(), None);
        assert_eq!(Rung::from_u8(99), Rung::Raw);
    }

    #[test]
    fn a_session_climbs_each_rung_once_and_no_further() {
        let (rungs, count) = Rung::climb_from(Rung::Raw);
        assert_eq!(count, 5);
        assert_eq!(rungs, Rung::ALL);
        let (rungs, count) = Rung::climb_from(Rung::Grpc);
        assert_eq!(count, 2);
        assert_eq!(rungs[..count], [Rung::Grpc, Rung::HttpUpgrade]);
        let (_, count) = Rung::climb_from(Rung::HttpUpgrade);
        assert_eq!(count, 1);
    }

    #[test]
    fn a_retryable_failure_climbs_and_a_final_one_holds() {
        let ladder = Ladder::new();
        let failure = Failure::new(Stage::SocketConnected, Kind::Dropped);
        assert_eq!(ladder.record_failure(Rung::Raw, &failure), Some(Rung::Ws));
        assert_eq!(ladder.current(), Rung::Ws);
        assert_eq!(ladder.climbs(), 1);
        assert_eq!(ladder.record_failure(Rung::HttpUpgrade, &failure), None);
    }

    #[test]
    fn a_refusal_and_a_local_build_error_hold_the_rung() {
        let ladder = Ladder::new();
        assert_eq!(
            ladder.record_failure(
                Rung::Raw,
                &Failure::new(Stage::SocketConnected, Kind::Refused)
            ),
            None
        );
        assert_eq!(
            ladder.record_failure(
                Rung::Raw,
                &Failure::new(Stage::SocketConnected, Kind::Local)
            ),
            None
        );
        assert_eq!(ladder.current(), Rung::Raw);
        assert_eq!(ladder.climbs(), 0);
    }

    #[test]
    fn progress_after_first_byte_never_climbs() {
        let ladder = Ladder::new();
        assert_eq!(
            ladder.record_failure(Rung::Raw, &Failure::new(Stage::FirstByte, Kind::Dropped)),
            None
        );
        assert_eq!(ladder.current(), Rung::Raw);
    }

    #[test]
    fn sixteen_useful_successes_earn_a_cheaper_probe() {
        let ladder = Ladder::new();
        assert_eq!(
            ladder.record_failure(
                Rung::Raw,
                &Failure::new(Stage::SocketConnected, Kind::Unreachable),
            ),
            Some(Rung::Ws)
        );
        assert_eq!(ladder.current(), Rung::Ws);
        for _ in 0..15 {
            assert_eq!(
                ladder.record_success(Rung::Ws, Stage::FirstByte, false),
                None
            );
            assert_eq!(ladder.start_rung(), Rung::Ws);
        }
        assert_eq!(
            ladder.record_success(Rung::Ws, Stage::FirstByte, false),
            None
        );
        assert_eq!(ladder.start_rung(), Rung::Raw);
        assert_eq!(
            ladder.record_success(Rung::Raw, Stage::FirstByte, false),
            Some((Rung::Ws, 16))
        );
        assert_eq!(ladder.current(), Rung::Raw);
        assert_eq!(ladder.descents(), 1);
    }

    #[test]
    fn a_failed_probe_restarts_the_success_count() {
        let ladder = Ladder::new();
        assert_eq!(
            ladder.record_failure(
                Rung::Raw,
                &Failure::new(Stage::SocketConnected, Kind::Unreachable),
            ),
            Some(Rung::Ws)
        );
        for _ in 0..16 {
            assert_eq!(
                ladder.record_success(Rung::Ws, Stage::FirstByte, false),
                None
            );
        }
        assert_eq!(ladder.start_rung(), Rung::Raw);
        assert_eq!(
            ladder.record_failure(
                Rung::Raw,
                &Failure::new(Stage::SocketConnected, Kind::Unreachable),
            ),
            Some(Rung::Ws)
        );
        assert_eq!(ladder.current(), Rung::Ws);
        assert_eq!(ladder.start_rung(), Rung::Ws);
        assert_eq!(ladder.descents(), 0);
    }

    #[test]
    fn shallow_successes_never_earn_a_probe() {
        let ladder = Ladder::new();
        assert_eq!(
            ladder.record_failure(
                Rung::Raw,
                &Failure::new(Stage::SocketConnected, Kind::Unreachable),
            ),
            Some(Rung::Ws)
        );
        for _ in 0..100 {
            assert_eq!(
                ladder.record_success(Rung::Ws, Stage::RequestSent, false),
                None
            );
        }
        assert_eq!(ladder.start_rung(), Rung::Ws);
        assert_eq!(ladder.descents(), 0);
        assert_eq!(ladder.useful(Rung::Ws), 0);
        assert_eq!(ladder.attempts(Rung::Ws), 100);
    }

    #[test]
    fn an_explicit_success_adopts_down_past_unprobed_rungs() {
        let ladder = Ladder::new();
        let unreachable = Failure::new(Stage::SocketConnected, Kind::Unreachable);
        assert_eq!(
            ladder.record_failure(Rung::Raw, &unreachable),
            Some(Rung::Ws)
        );
        assert_eq!(
            ladder.record_failure(Rung::Ws, &unreachable),
            Some(Rung::Xhttp)
        );
        assert_eq!(
            ladder.record_failure(Rung::Xhttp, &unreachable),
            Some(Rung::Grpc)
        );
        assert_eq!(
            ladder.record_failure(Rung::Grpc, &unreachable),
            Some(Rung::HttpUpgrade)
        );
        assert_eq!(ladder.current(), Rung::HttpUpgrade);
        assert_eq!(
            ladder.record_success(Rung::Raw, Stage::FirstByte, true),
            Some((Rung::HttpUpgrade, 0))
        );
        assert_eq!(ladder.current(), Rung::Raw);
        assert_eq!(ladder.descents(), 1);
    }

    #[test]
    fn fallback_rates_count_every_attempt_and_useful_one() {
        let ladder = Ladder::new();
        assert_eq!(
            ladder.record_success(Rung::Raw, Stage::FirstByte, false),
            None
        );
        assert_eq!(
            ladder.record_failure(
                Rung::Raw,
                &Failure::new(Stage::SocketConnected, Kind::Dropped),
            ),
            Some(Rung::Ws)
        );
        assert_eq!(ladder.attempts(Rung::Raw), 2);
        assert_eq!(ladder.useful(Rung::Raw), 1);
        assert_eq!(ladder.useful(Rung::Ws), 0);
    }
}
