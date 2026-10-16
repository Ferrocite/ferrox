use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

// The engine's own wchan, in the test shape alone: a wait that registers here names itself, the descriptor it blocks on and the deadline it armed, and deregisters on return. `watch-test.sh` reads procfs, which sees the kernel on Linux and nothing elsewhere; only this sees the engine, and a shipped relay pays neither the map nor the call.

/// Hold a wait in the census for the enclosing scope.
macro_rules! census {
    ($name:literal, $fd:expr, $armed:expr) => {
        let _waited = $crate::census::enter($name, $fd, $armed);
    };
}

/// A wait that blocks on no descriptor: a join, a channel receive, a condvar park.
pub(crate) const NO_FD: i64 = -1;

struct Entry {
    id: u64,
    name: &'static str,
    fd: i64,
    armed: Option<Duration>,
    started: Instant,
    thread: ThreadId,
}

static LIVE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(0);

fn live() -> MutexGuard<'static, Vec<Entry>> {
    LIVE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One wait in progress; the census forgets it when this drops, which is the return, the timeout or the panic alike.
pub(crate) struct Waited(u64);

impl Drop for Waited {
    fn drop(&mut self) {
        let mut live = live();
        // The id, not an index: another wait leaving first moves whatever sat after it.
        if let Some(at) = live.iter().position(|entry| entry.id == self.0) {
            live.swap_remove(at);
        }
    }
}

/// Register a wait as this thread holding it, and return the guard that unregisters it.
#[must_use = "a wait that registers nothing cannot be dumped"]
pub(crate) fn enter(name: &'static str, fd: i64, armed: Option<Duration>) -> Waited {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    live().push(Entry {
        id,
        name,
        fd,
        armed,
        started: Instant::now(),
        thread: std::thread::current().id(),
    });
    Waited(id)
}

/// The descriptor a stream's blocking calls wait on, in the number the census prints.
#[cfg(unix)]
#[must_use]
pub(crate) fn handle<T: std::os::fd::AsRawFd>(stream: &T) -> i64 {
    i64::from(stream.as_raw_fd())
}

#[cfg(windows)]
#[must_use]
pub(crate) fn handle<T: std::os::windows::io::AsRawSocket>(socket: &T) -> i64 {
    socket.as_raw_socket() as i64
}

/// One line per live wait, in the `key=value` shape `watch-test.sh`'s procfs lines take.
#[must_use]
pub(crate) fn dump() -> String {
    let live = live();
    let mut out = String::new();
    for entry in live.iter() {
        let fd = match entry.fd {
            NO_FD => "none".to_owned(),
            descriptor => descriptor.to_string(),
        };
        let armed = match entry.armed {
            Some(budget) => format!("{budget:?}"),
            None => "none".to_owned(),
        };
        let _ = writeln!(
            out,
            "census thread {:?} name={} fd={fd} armed={armed} waited={}ms",
            entry.thread,
            entry.name,
            entry.started.elapsed().as_millis()
        );
    }
    out
}

/// The census line one thread's named wait holds, or none when the census carries no such line. The thread is what tells this wait from another test's running beside it.
#[must_use]
pub(crate) fn held(name: &str, thread: ThreadId) -> Option<String> {
    let named = format!("name={name} ");
    let ours = dump();
    ours.lines()
        .find(|line| line.contains(&named) && line.contains(&format!("thread {thread:?} ")))
        .map(str::to_owned)
}

/// The number a census line's field carries: `waited=34ms` reads as 34.
#[must_use]
pub(crate) fn number(line: &str, field: &str) -> u64 {
    let wanted = format!("{field}=");
    let at = line
        .find(&wanted)
        .unwrap_or_else(|| panic!("no `{field}` field in: {line}"));
    let digits: String = line[at + wanted.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("`{wanted}` holds no number in: {line}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registered_wait_dumps_and_a_returned_one_does_not() {
        let this = std::thread::current().id();
        let waited = enter("census-mechanism", 7, Some(Duration::from_millis(900)));
        let line = held("census-mechanism", this).expect("the wait is in the census");
        assert!(line.contains("fd=7 "), "{line}");
        assert!(line.contains("armed=900ms "), "{line}");
        assert!(number(&line, "waited") < 900, "{line}");
        drop(waited);
        assert!(
            held("census-mechanism", this).is_none(),
            "a returned wait is still in the census:\n{}",
            dump()
        );
    }

    #[test]
    fn a_wait_without_a_descriptor_or_a_budget_says_so() {
        let this = std::thread::current().id();
        let _waited = enter("census-shape", NO_FD, None);
        let line = held("census-shape", this).expect("the wait is in the census");
        assert!(line.contains("fd=none "), "{line}");
        assert!(line.contains("armed=none "), "{line}");
    }

    #[test]
    fn a_returned_wait_leaves_the_others_it_crossed_in_place() {
        let this = std::thread::current().id();
        let first = enter("census-order-first", NO_FD, None);
        let second = enter("census-order-second", NO_FD, None);
        let third = enter("census-order-third", NO_FD, None);
        // The middle wait returns first, so the last one it left behind must still be named.
        drop(second);
        assert!(
            held("census-order-third", this).is_some(),
            "a swap-down erased a live wait:\n{}",
            dump()
        );
        drop(third);
        drop(first);
        assert!(held("census-order-first", this).is_none(), "{}", dump());
    }
}
