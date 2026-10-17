use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// Every wait cadence in the app: the dial, the handshake read, the relay polls, the head arrival, the carrier probe, the payload grace, the idle timeouts. A hang hunt starts here; anything that can wait and how long is named on this page, and which of them holds a thread right now is the census' dump.

pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

// Bound the raw opening request read: a peer that connects and stays silent must not pin its per-connection thread forever.
pub(crate) const HANDSHAKE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const RELAY_POLL: Duration = Duration::from_millis(20);

/// How long a connection we refused stays open after its GOAWAY: closing with the peer's bytes still unread makes the stack abort with RST, and that can swallow the refusal itself.
pub(crate) const GOAWAY_GRACE: Duration = Duration::from_millis(100);

/// How long a shared read holds the lock: under one grain on purpose, so a writer never waits out the wait.
pub(crate) const SESSION_POLL: Duration = Duration::from_millis(1);

pub(crate) const RELAY_HANDOFF_SPINS: u32 = 64;

/// One leg's wait for its partner after the flow has ended: a partner still missing past the relay's own idle bound is starved rather than draining, and a thread that waits forever turns one stalled peer into a pile-up of held sessions.
pub(crate) const RELAY_JOIN: Duration = Duration::from_secs(120);

pub(crate) const RELAY_LOCK_TRIES: u32 = 64;

/// How long a relay worker may sit unclaimed before it hands its thread back: long enough for the next flow to reuse it, short enough that a burst of finished flows leaves no residue.
pub(crate) const RELAY_WORKER_LIFE: Duration = Duration::from_secs(30);

/// A head's arrival budget: without one a quiet peer keeps a task waking once per poll, burning a core.
pub(crate) const HEAD_DEADLINE: Duration = Duration::from_secs(20);

/// The bound on one backward read's lock hold: without it the first idle read wedges every upload.
pub(crate) const RELAY_QUANTUM: Duration = Duration::from_millis(100);

/// How long an `auto` carrier the user did not ask for is proven for; a configured one gets the full budget.
pub(crate) const CARRIER_PROBE: Duration = Duration::from_millis(2_500);

/// A silent edge's quarantine: long enough to skip a per-flow probe, short enough to find it answering again.
pub(crate) const CARRIER_DEAD_SECS: u64 = 60;

/// Sign-in attempts and the first pause: only wrong credentials and quota are not worth asking again.
pub(crate) const ACCOUNT_ATTEMPTS: usize = 4;
pub(crate) const ACCOUNT_BACKOFF_SECS: u64 = 5;

/// A quiet poll's sleep: long enough not to spin, short enough that traffic never feels it.
pub(crate) const RELAY_IDLE: Duration = Duration::from_millis(10);

pub(crate) const UDP_IDLE: Duration = Duration::from_secs(120);

/// How long a carrier may stay open and silent before the app's payload goes out ahead of the answer: a carrier that refuses inside the window leaves the bytes for the ladder's next rung.
pub(crate) const PAYLOAD_GRACE: Duration = Duration::from_millis(100);

// The same waits restated by a config, in milliseconds, where zero means the name was never written. Each getter is read once per flow — at a dial, a handshake arm, a relay teardown, an idle arming — and never inside a byte loop, so naming a budget adds no operation to a measured path. Cadences that pace a loop (`RELAY_POLL`, `SESSION_POLL`, `RELAY_IDLE`, the spin and try counts) stay constants on purpose: a runtime cadence is a load per iteration in the hottest loop this file describes.
static DIAL_MS: AtomicU64 = AtomicU64::new(0);
static HANDSHAKE_MS: AtomicU64 = AtomicU64::new(0);
static HEAD_ARRIVAL_MS: AtomicU64 = AtomicU64::new(0);
static RELAY_JOIN_MS: AtomicU64 = AtomicU64::new(0);
static RELAY_QUANTUM_MS: AtomicU64 = AtomicU64::new(0);
static UDP_IDLE_MS: AtomicU64 = AtomicU64::new(0);
static PAYLOAD_GRACE_MS: AtomicU64 = AtomicU64::new(0);
static GOAWAY_GRACE_MS: AtomicU64 = AtomicU64::new(0);
static CARRIER_PROBE_MS: AtomicU64 = AtomicU64::new(0);

fn named(set: &AtomicU64, default: Duration) -> Duration {
    match set.load(Ordering::Relaxed) {
        0 => default,
        millis => Duration::from_millis(millis),
    }
}

pub(crate) fn dial() -> Duration {
    named(&DIAL_MS, DIAL_TIMEOUT)
}

pub(crate) fn handshake() -> Duration {
    named(&HANDSHAKE_MS, HANDSHAKE_REQUEST_TIMEOUT)
}

pub(crate) fn head_arrival() -> Duration {
    named(&HEAD_ARRIVAL_MS, HEAD_DEADLINE)
}

pub(crate) fn relay_join() -> Duration {
    named(&RELAY_JOIN_MS, RELAY_JOIN)
}

pub(crate) fn relay_quantum() -> Duration {
    named(&RELAY_QUANTUM_MS, RELAY_QUANTUM)
}

pub(crate) fn udp_idle() -> Duration {
    named(&UDP_IDLE_MS, UDP_IDLE)
}

pub(crate) fn payload_grace() -> Duration {
    named(&PAYLOAD_GRACE_MS, PAYLOAD_GRACE)
}

pub(crate) fn goaway_grace() -> Duration {
    named(&GOAWAY_GRACE_MS, GOAWAY_GRACE)
}

pub(crate) fn carrier_probe() -> Duration {
    named(&CARRIER_PROBE_MS, CARRIER_PROBE)
}

/// Write every budget the config named; a name it did not write stays the constant above.
pub(crate) fn apply(overrides: &crate::config::Budgets) {
    fn one(set: &AtomicU64, value: Option<Duration>) {
        if let Some(value) = value {
            set.store(
                u64::try_from(value.as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }
    one(&DIAL_MS, overrides.dial);
    one(&HANDSHAKE_MS, overrides.handshake);
    one(&HEAD_ARRIVAL_MS, overrides.head_arrival);
    one(&RELAY_JOIN_MS, overrides.relay_join);
    one(&RELAY_QUANTUM_MS, overrides.relay_quantum);
    one(&UDP_IDLE_MS, overrides.udp_idle);
    one(&PAYLOAD_GRACE_MS, overrides.payload_grace);
    one(&GOAWAY_GRACE_MS, overrides.goaway_grace);
    one(&CARRIER_PROBE_MS, overrides.carrier_probe);
}

/// A named budget is the value a test can restore; nothing else writes the table outside `apply`.
#[cfg(test)]
pub(crate) fn clear() {
    for set in [
        &DIAL_MS,
        &HANDSHAKE_MS,
        &HEAD_ARRIVAL_MS,
        &RELAY_JOIN_MS,
        &RELAY_QUANTUM_MS,
        &UDP_IDLE_MS,
        &PAYLOAD_GRACE_MS,
        &GOAWAY_GRACE_MS,
        &CARRIER_PROBE_MS,
    ] {
        set.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
static ARMED: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The table is process-global and read by every thread, so a test that arms one takes this lock: two arming tests never overlap, and the values they arm are held for no assertion of their own.
#[cfg(test)]
pub(crate) fn lock() -> std::sync::MutexGuard<'static, ()> {
    ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every override here is at least as generous as the constant it replaces, so a table left armed by a failed assertion cannot tighten a wait another test is racing.
    #[test]
    fn a_budget_the_config_names_is_the_value_a_site_reads() {
        let _guard = lock();
        // Nothing has armed the table, so each site reads the constant beside its name.
        assert_eq!(dial(), DIAL_TIMEOUT);
        assert_eq!(handshake(), HANDSHAKE_REQUEST_TIMEOUT);
        assert_eq!(head_arrival(), HEAD_DEADLINE);
        assert_eq!(relay_join(), RELAY_JOIN);
        assert_eq!(relay_quantum(), RELAY_QUANTUM);
        assert_eq!(udp_idle(), UDP_IDLE);
        assert_eq!(payload_grace(), PAYLOAD_GRACE);
        assert_eq!(goaway_grace(), GOAWAY_GRACE);
        assert_eq!(carrier_probe(), CARRIER_PROBE);

        let root = crate::json::parse(
            r#"{"budgets": {"dial": "20s", "handshake": "30s", "headArrival": "40s",
                            "relayJoin": "5mn", "relayQuantum": "250ms", "udpIdle": "300s",
                            "payloadGrace": "400ms", "goawayGrace": "200ms", "carrierProbe": "3s"}}"#,
        )
        .expect("parses");
        // A name spelled past the units the engine reads is refused with its own name, not silently the default.
        let error = crate::config::budgets(&root).expect_err("`5mn` names no wait");
        assert!(error.contains("relayJoin"), "{error}");

        let root = crate::json::parse(
            r#"{"budgets": {"dial": "20s", "handshake": "30s", "headArrival": "40s",
                            "relayJoin": "300s", "relayQuantum": "250ms", "udpIdle": "300s",
                            "payloadGrace": "400ms", "goawayGrace": "200ms", "carrierProbe": "3s"}}"#,
        )
        .expect("parses");
        apply(&crate::config::budgets(&root).expect("every name is one the engine acts on"));
        assert_eq!(dial(), Duration::from_secs(20));
        assert_eq!(handshake(), Duration::from_secs(30));
        assert_eq!(head_arrival(), Duration::from_secs(40));
        assert_eq!(relay_join(), Duration::from_secs(300));
        assert_eq!(relay_quantum(), Duration::from_millis(250));
        assert_eq!(udp_idle(), Duration::from_secs(300));
        assert_eq!(payload_grace(), Duration::from_millis(400));
        assert_eq!(goaway_grace(), Duration::from_millis(200));
        assert_eq!(carrier_probe(), Duration::from_secs(3));
        clear();
        assert_eq!(
            carrier_probe(),
            CARRIER_PROBE,
            "an unnamed wait is its constant"
        );
    }
}
