//! The `xmux` session pool (`mux.go`): a stream-one H2 session is dialled out of a shared
//! connection while its running, request and lifetime counters allow, and only H2 multiplexes a
//! connection, so only that carrier reuses one.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::xhttp::Xmux;
use crate::xhttp_h2::H2Client;

/// The reference's conf-layer defaults when a config wrote no block (`transport_method.go:458`).
pub(crate) fn defaults() -> Xmux {
    Xmux {
        max_connections: (3, 3),
        h_max_request_times: (600, 900),
        h_max_reusable_secs: (1800, 3000),
        ..Xmux::default()
    }
}

/// What identifies one manager: the destination and transport settings the reference keys its
/// `globalDialerMap` on (`dialer.go:63`), plus the TLS identity a pooled connection authenticated.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) server: SocketAddr,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) h2: bool,
    pub(crate) identity: (String, [u8; 32], [u8; 8], String),
}

pub(crate) struct Manager {
    bounds: Xmux,
    entries: Mutex<Vec<Arc<Entry>>>,
}

struct Entry {
    conn: Arc<H2Client>,
    running: AtomicUsize,
    /// `-1` is the reference's unlimited sentinel for `cMaxReuseTimes`.
    left_usage: AtomicI64,
    left_requests: AtomicI64,
    unreusable_at: Option<Instant>,
    retired: AtomicBool,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.conn.close();
    }
}

impl Entry {
    fn new(conn: Arc<H2Client>, bounds: &Xmux) -> Self {
        let usage = roll(bounds.c_max_reuse_times);
        let requests = roll(bounds.h_max_request_times);
        let secs = roll(bounds.h_max_reusable_secs);
        Self {
            conn,
            running: AtomicUsize::new(0),
            left_usage: AtomicI64::new(if usage > 0 { usage - 1 } else { -1 }),
            left_requests: AtomicI64::new(if requests > 0 {
                requests
            } else {
                i64::from(i32::MAX)
            }),
            unreusable_at: (secs > 0).then(|| Instant::now() + Duration::from_secs(secs as u64)),
            retired: AtomicBool::new(false),
        }
    }

    fn expired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
            || !self.conn.reusable()
            || self.left_usage.load(Ordering::SeqCst) == 0
            || self.left_requests.load(Ordering::SeqCst) <= 0
            || self.unreusable_at.is_some_and(|at| Instant::now() > at)
    }

    fn running(&self) -> usize {
        self.running.load(Ordering::SeqCst)
    }
}

/// One session's hold on an entry: dropping it frees the concurrency slot the session used.
pub(crate) struct Lease {
    entry: Arc<Entry>,
}

impl Lease {
    pub(crate) fn conn(&self) -> &Arc<H2Client> {
        &self.entry.conn
    }

    /// The connection died under the session: retire the entry rather than hand it to the next one.
    pub(crate) fn retire(&self) {
        self.entry.retired.store(true, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("XmuxLease")
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.entry.running.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Manager {
    pub(crate) fn new(bounds: Xmux) -> Arc<Self> {
        Arc::new(Self {
            bounds,
            entries: Mutex::new(Vec::new()),
        })
    }

    /// The reference's `getXmuxClient(create=true)` (`mux.go:66`): reuse a live entry the bounds
    /// allow, otherwise dial one, and never block — a saturated pool over its target dials fresh,
    /// as `getXmuxClient` does when every client is filtered out.
    pub(crate) fn lease(&self, create: impl FnOnce() -> Option<Arc<H2Client>>) -> Option<Lease> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|entry| !entry.expired());
        let chosen = self.choose(&entries);
        let entry = if let Some(entry) = chosen {
            entry
        } else {
            let entry = Arc::new(Entry::new(create()?, &self.bounds));
            entries.push(Arc::clone(&entry));
            entry
        };
        Some(hold(entry))
    }

    /// `GetExistingXmuxClient` (`mux.go:73`): a session that would rather dial its own transport
    /// takes a live entry or nothing, so a pooled stream is opened without a handshake.
    pub(crate) fn existing(&self) -> Option<Lease> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|entry| !entry.expired());
        let chosen = self.choose(&entries);
        chosen.map(hold)
    }

    fn choose(&self, entries: &[Arc<Entry>]) -> Option<Arc<Entry>> {
        if entries.is_empty()
            || (self.bounds.max_connections.1 > 0
                && entries.len() < self.bounds.max_connections.1 as usize)
        {
            return None;
        }
        let limit = self.bounds.max_concurrency.1;
        let open: Vec<Arc<Entry>> = entries
            .iter()
            .filter(|entry| limit <= 0 || entry.running() < limit as usize)
            .cloned()
            .collect();
        if open.is_empty() {
            return None;
        }
        Some(Arc::clone(&open[pick(open.len())]))
    }
}

fn hold(entry: Arc<Entry>) -> Lease {
    let left = entry.left_usage.load(Ordering::SeqCst);
    if left > 0 {
        entry.left_usage.fetch_sub(1, Ordering::SeqCst);
    }
    entry.left_requests.fetch_sub(1, Ordering::SeqCst);
    entry.running.fetch_add(1, Ordering::SeqCst);
    Lease { entry }
}

type Managers = HashMap<(Key, Xmux), Arc<Manager>>;

static MANAGERS: Mutex<Option<Managers>> = Mutex::new(None);

pub(crate) fn manager(key: Key, bounds: Option<Xmux>) -> Arc<Manager> {
    let mut managers = MANAGERS.lock().unwrap_or_else(PoisonError::into_inner);
    // `transport_method.go:458` fills the defaults only for a wholly empty block, so `{}` takes them too.
    let bounds = bounds
        .filter(|bounds| *bounds != Xmux::default())
        .unwrap_or_else(defaults);
    let map = managers.get_or_insert_with(HashMap::new);
    Arc::clone(
        map.entry((key, bounds))
            .or_insert_with(|| Manager::new(bounds)),
    )
}

/// `crypto.RandBetween(from, to)`, inclusive, on the reference's closed range.
fn roll(range: (i32, i32)) -> i64 {
    let from = i64::from(range.0.max(0));
    let to = i64::from(range.1.max(0));
    if to <= from {
        return from;
    }
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).ok();
    let span = u64::try_from(to - from + 1).unwrap_or(u64::MAX);
    from + i64::try_from(u64::from_le_bytes(bytes) % span).unwrap_or(0)
}

fn pick(len: usize) -> usize {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).ok();
    (u64::from_le_bytes(bytes) % len as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct Sink;

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Sink {
        fn write_slices(&mut self, _slices: &[&[u8]]) -> bool {
            true
        }

        fn settle(&mut self) -> crate::proxy::Settle {
            crate::proxy::Settle::Clear
        }
    }

    fn client() -> Option<Arc<H2Client>> {
        H2Client::new(std::io::empty(), Sink, None)
    }

    fn counter() -> (Arc<AtomicUsize>, impl Fn() -> Option<Arc<H2Client>>) {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        (count, move || {
            seen.fetch_add(1, Ordering::SeqCst);
            client()
        })
    }

    #[test]
    fn managers_partition_by_their_effective_bounds() {
        let key = Key {
            server: "127.0.0.1:443".parse().expect("an address"),
            host: "bounds.example".to_owned(),
            path: "/bounds".to_owned(),
            query: String::new(),
            h2: true,
            identity: (
                "bounds.example".to_owned(),
                [1; 32],
                [2; 8],
                "chrome".to_owned(),
            ),
        };
        let one = Xmux {
            max_connections: (1, 1),
            ..Xmux::default()
        };
        let two = Xmux {
            max_connections: (2, 2),
            ..Xmux::default()
        };
        let first = manager(key.clone(), Some(one));
        let second = manager(key.clone(), Some(two));
        let again = manager(key, Some(one));
        assert!(
            !Arc::ptr_eq(&first, &second),
            "two outbounds with different connection caps shared one pool"
        );
        assert!(Arc::ptr_eq(&first, &again));
    }

    #[test]
    fn the_default_target_dials_three_connections_then_reuses_them() {
        let manager = Manager::new(defaults());
        let (dialed, create) = counter();
        let leased: Vec<Lease> = (0..4)
            .map(|_| manager.lease(&create).expect("a lease"))
            .collect();
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            3,
            "the third connection is the target"
        );
        let mut ids: Vec<usize> = leased
            .iter()
            .map(|lease| Arc::as_ptr(lease.conn()) as usize)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3, "the fourth session came out of the pool");
    }

    #[test]
    fn a_saturated_concurrency_dials_raw_rather_than_waiting() {
        let mut bounds = defaults();
        bounds.max_connections = (1, 1);
        bounds.max_concurrency = (1, 1);
        let manager = Manager::new(bounds);
        let (dialed, create) = counter();
        let first = manager.lease(&create).expect("a lease");
        let first_conn = Arc::clone(first.conn());
        let second = manager.lease(&create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            2,
            "the bound does not park a session"
        );
        assert!(!Arc::ptr_eq(&first_conn, second.conn()));
        drop(first);
        let third = manager.lease(&create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            2,
            "a freed slot is reused rather than grown past the target"
        );
        assert!(Arc::ptr_eq(&first_conn, third.conn()));
    }

    #[test]
    fn the_reuse_count_retires_an_entry() {
        let mut bounds = defaults();
        bounds.max_connections = (1, 1);
        bounds.c_max_reuse_times = (3, 3);
        let manager = Manager::new(bounds);
        let (dialed, create) = counter();
        let one = manager.lease(&create).expect("a lease");
        let one_conn = Arc::clone(one.conn());
        drop(one);
        let two = manager.lease(&create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            1,
            "the second session reuses the client"
        );
        assert!(Arc::ptr_eq(&one_conn, two.conn()));
        drop(two);
        let three = manager.lease(&create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            2,
            "the use count retires the client on the next selection"
        );
        assert!(!Arc::ptr_eq(&one_conn, three.conn()));
    }

    #[test]
    fn the_request_count_retires_an_entry() {
        let mut bounds = defaults();
        bounds.h_max_request_times = (1, 1);
        let manager = Manager::new(bounds);
        let (dialed, create) = counter();
        drop(manager.lease(&create).expect("a lease"));
        drop(manager.lease(&create).expect("a lease"));
        assert_eq!(dialed.load(Ordering::SeqCst), 2, "one request per client");
    }

    #[test]
    fn the_reusable_seconds_retire_an_entry() {
        let mut bounds = defaults();
        bounds.h_max_reusable_secs = (1, 1);
        let manager = Manager::new(bounds);
        let (dialed, create) = counter();
        drop(manager.lease(&create).expect("a lease"));
        std::thread::sleep(Duration::from_millis(1100));
        let _second = manager.lease(&create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            2,
            "an expired client is replaced"
        );
    }
}
