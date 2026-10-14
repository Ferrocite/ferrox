use std::time::Duration;

// Every wait cadence in the app: the dial, the handshake read, the relay polls, the head arrival, the carrier probe, the payload grace, the idle timeouts. A hang hunt starts here; anything that can wait and how long is named on this page.

pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

// Bound the raw opening request read: a peer that connects and stays silent must not pin its per-connection thread forever.
pub(crate) const HANDSHAKE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const RELAY_POLL: Duration = Duration::from_millis(20);

/// How long a shared read holds the lock: under one grain on purpose, so a writer never waits out the wait.
pub(crate) const SESSION_POLL: Duration = Duration::from_millis(1);

pub(crate) const RELAY_HANDOFF_SPINS: u32 = 64;

pub(crate) const RELAY_LOCK_TRIES: u32 = 64;

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
