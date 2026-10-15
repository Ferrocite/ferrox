//! A runtime census of the waits `budgets.rs` names statically.
//!
//! `budgets.rs` says every cadence the engine can park on and how long it can
//! hold for; nothing at runtime says which named wait holds which thread on
//! which fd for how long. This module is that missing view: `Wait::arm` parks
//! a slot in a fixed table with the wait's name, the fd it blocks on, the
//! thread that armed it and the deadline it armed; `Drop` clears the slot on
//! return; `dump` prints one line per parked thread, oldest first, naming the
//! armed budget and how long the wait has already been held.
//!
//! The gate is a Cargo feature, `census`, off by default. A build without the
//! feature does not compile the module at all, so a production relay path pays
//! neither the arm's mutex nor the slot. The proof is `cargo build --locked -p
//! ferrox-app` (the default-shape build in `ci.yml` and `scripts/check.sh`),
//! which does not include `census.rs` in the crate graph; enabling the feature
//! is the shape a stall hunt and the CI harness use. This is the same pattern
//! `scripts/count-ops.sh` uses for its binary: a build shape with no production
//! traffic exercises the code the shipped build never sees.
//!
//! An integration at a real wait site reads:
//!
//! ```ignore
//! let stream = /* the TcpStream the relay will block on */;
//! stream.set_read_timeout(Some(budgets::relay_quantum())).ok();
//! let _hold = census::Wait::arm("relay-quantum", stream.as_raw_fd(), budgets::relay_quantum());
//! let n = stream.read(&mut buf);
//! // `_hold` drops on the way out, the census deregisters the row.
//! ```
#![allow(dead_code)]
// Nothing in the shipped relay calls the census yet — it is the API a stall hunt adds *into* a wait site, landing per site as slices are written from a dump line — so a `--features census` build with no test run reads a set of never-used warnings; the allow names that missing wiring rather than pretending the census is already consumed.

use std::cell::Cell;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;
use std::time::Duration;

/// Generous for the thread count the app runs per connection and the stall
/// hunts that read this file; the table is fixed-size so no allocation joins
/// a parked wait. Every field is `Copy` and const-init-able: `Instant` is not
/// const-constructible, so the row stores microseconds from a process anchor
/// installed on the first arm (a `OnceLock<Instant>` in `now_us`).
const SLOTS: usize = 256;

#[derive(Copy, Clone, PartialEq, Eq)]
enum Kind {
    Empty,
    Armed,
}

#[derive(Copy, Clone)]
struct Row {
    kind: Kind,
    /// Microseconds from the process anchor when this wait armed.
    armed_at: u64,
    /// The budget this wait armed with, in microseconds; `armed_at + budget_us`
    /// is the deadline the row parks under.
    budget_us: u64,
    tid: Option<ThreadId>,
    fd: i32,
    name: Option<&'static str>,
}

const EMPTY: Row = Row {
    kind: Kind::Empty,
    armed_at: 0,
    budget_us: 0,
    tid: None,
    fd: -1,
    name: None,
};

static TABLE: Mutex<[Row; SLOTS]> = Mutex::new([EMPTY; SLOTS]);

thread_local! {
    /// The re-entrance flag: `arm` refuses a second parked wait on the same
    /// thread. It is *not* the slot index, so a forgotten guard on one thread
    /// cannot strand a slot the next test on this thread would read.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

/// Microseconds since the process anchor. The anchor is installed on the
/// first call; every row shares it, so an `armed_at + budget_us` sum fits in
/// u64 for the longest wait `budgets.rs` names (120 s, well under 2^64 µs).
fn now_us() -> u64 {
    static ANCHOR: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let anchor = ANCHOR.get_or_init(std::time::Instant::now);
    u64::try_from(anchor.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// A thread's parked wait. `arm` writes the row; dropping the guard clears
/// it. `arm` blocks on the table's mutex — a stall hunt accepts that, the
/// shipped relay build does not compile this module.
pub(crate) struct Wait {
    slot: usize,
}

impl Wait {
    /// Park a named wait on an fd with the deadline it armed. `budget` is
    /// what a `budgets::*` getter returns; `fd` is `-1` for a wait that has
    /// no file descriptor (a condvar, a join, a lock).
    pub(crate) fn arm(name: &'static str, fd: i32, budget: Duration) -> Wait {
        assert!(
            !ARMED.with(Cell::get),
            "a thread holds at most one parked wait at a time"
        );
        ARMED.with(|a| a.set(true));
        let mut table: MutexGuard<'static, [Row; SLOTS]> =
            TABLE.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(at) = table.iter().position(|r| matches!(r.kind, Kind::Empty)) else {
            // Release the re-entrance flag before refusing: the census is at capacity, not the wait.
            ARMED.with(|a| a.set(false));
            panic!("the census is full: 256 waits do not fit this shape");
        };
        table[at] = Row {
            kind: Kind::Armed,
            armed_at: now_us(),
            budget_us: u64::try_from(budget.as_micros()).unwrap_or(u64::MAX),
            tid: Some(std::thread::current().id()),
            fd,
            name: Some(name),
        };
        Wait { slot: at }
    }

    /// The slot this wait wrote. Test-only: an assertion on the raw table is
    /// a witness the dump can also give, and this one is cheaper to read in
    /// a failure message.
    #[cfg(test)]
    fn slot(&self) -> usize {
        self.slot
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        let mut table: MutexGuard<'static, [Row; SLOTS]> =
            TABLE.lock().unwrap_or_else(PoisonError::into_inner);
        // Deregister on return: the slot goes Empty for the next arm and drops out of the dump. A guard whose frame never returns (`mem::forget`, an abort past the unwind) is never dropped, so it stays Armed — a leaked row indistinguishable from a live wait, which is exactly what a stall hunt wants to see.
        table[self.slot] = EMPTY;
        ARMED.with(|a| a.set(false));
    }
}

/// One line per parked wait, oldest first. A row the running process cannot
/// explain is the finding a stall hunt opens.
pub(crate) fn dump() -> String {
    let table: MutexGuard<'static, [Row; SLOTS]> =
        TABLE.lock().unwrap_or_else(PoisonError::into_inner);
    let now = now_us();
    let mut rows: Vec<(u64, ThreadId, i32, u64, &'static str)> = table
        .iter()
        .filter(|r| r.kind == Kind::Armed)
        .map(|r| {
            (
                r.armed_at,
                r.tid.unwrap_or_else(|| std::thread::current().id()),
                r.fd,
                r.budget_us,
                r.name.unwrap_or("<unnamed>"),
            )
        })
        .collect();
    rows.sort_by_key(|(armed_at, ..)| *armed_at);
    let mut out = String::new();
    for (armed_at, tid, fd, budget_us, name) in rows {
        let waited = now.saturating_sub(armed_at);
        let _ = writeln!(
            out,
            "thread {tid:?} waits on fd {fd} for {}s, armed {}s — {name}",
            secs_str(waited),
            secs_str(budget_us),
        );
    }
    out
}

/// Microseconds as a fixed three-decimal second figure ("0.500", "120.000"),
/// by integer division so a long-held wait costs no `u64 as f64` precision.
fn secs_str(us: u64) -> String {
    let whole = us / 1_000_000;
    let millis = (us % 1_000_000) / 1000;
    format!("{whole}.{millis:03}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind, Read};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// The census table is process-global; serialize the tests that read it
    /// so no other test's parked row appears in a `dump` assertion.
    static GATE: Mutex<()> = Mutex::new(());

    fn hold() -> MutexGuard<'static, ()> {
        GATE.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A reader that answers nothing. Not a socket: the census test asserts
    /// the row directly, and no scheduler decides what the dump sees.
    struct Dead;

    impl Read for Dead {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::new(ErrorKind::WouldBlock, "dead"))
        }
    }

    #[test]
    fn census_arms_and_drops_a_named_wait() {
        let _gate = hold();
        let armed = Duration::from_millis(500);
        let me = std::thread::current().id();
        let w = Wait::arm("census-hold", 7, armed);
        let text = dump();
        assert!(text.contains("census-hold"), "{text}");
        assert!(text.contains("fd 7"), "{text}");
        assert!(text.contains("armed 0.500s"), "{text}");
        assert!(text.contains(&format!("thread {me:?}")), "{text}");
        assert_ne!(w.slot(), usize::MAX, "the arm wrote a slot");
        drop(w);
        assert_eq!(dump(), "", "the census deregisters its row on return");
    }

    /// The stall hunt's witness: a parked thread's row names the wait, the fd
    /// and the armed deadline while it is parked, and the row clears when the
    /// thread returns from the wait.
    #[test]
    fn census_dump_names_a_parked_thread_across_a_blocking_read() {
        let _gate = hold();
        let parked = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let p = parked.clone();
        let s = stop.clone();
        let driver = std::thread::spawn(move || {
            let mut dead = Dead;
            let mut buf = [0u8; 4];
            let _hold = Wait::arm("census-park", 42, Duration::from_millis(60));
            p.store(true, Ordering::SeqCst);
            while !s.load(Ordering::SeqCst) {
                let _ = dead.read(&mut buf);
                std::thread::yield_now();
            }
        });
        while !parked.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        let text = dump();
        stop.store(true, Ordering::SeqCst);
        let _ = driver.join();
        assert!(text.contains("census-park"), "{text}");
        assert!(text.contains("fd 42"), "{text}");
        assert!(
            text.contains("armed 0.060s"),
            "{text} did not name the armed duration"
        );
        assert!(
            text.contains("waits on fd 42 for "),
            "{text} did not name a waited-for duration"
        );
        assert!(
            dump().is_empty(),
            "the census emptied when the parked thread joined"
        );
    }

    /// A second arm on the same thread refuses; the refusal runs on a
    /// dedicated thread so this test thread's `ARMED` flag is not stuck.
    #[test]
    fn a_thread_cannot_arm_two_parked_waits() {
        let _gate = hold();
        let refused = Arc::new(AtomicBool::new(false));
        let r = refused.clone();
        let driver = std::thread::spawn(move || {
            let _outer = Wait::arm("census-a", 1, Duration::from_millis(1));
            let panicked = std::panic::catch_unwind(|| {
                let _inner = Wait::arm("census-b", 2, Duration::from_millis(1));
            })
            .is_err();
            r.store(panicked, Ordering::SeqCst);
        });
        let _ = driver.join();
        assert!(
            refused.load(Ordering::SeqCst),
            "the second arm did not refuse on the same thread"
        );
        assert_eq!(dump(), "", "the driver's park cleared on unwind");
    }
}
