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
/// `globalDialerMap` on (`dialer.go:63`), plus the TLS identity a pooled connection authenticated
/// and the key-log sink a new connection would write to.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) server: SocketAddr,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) h2: bool,
    pub(crate) identity: Identity,
    pub(crate) log_sink: Option<String>,
}

/// The client a pooled connection authenticated as. REALITY names its material, and TLS pins the
/// config by address; the manager holds that config so a retired address is never handed out again.
#[derive(Clone)]
pub(crate) enum Identity {
    Reality {
        server_name: String,
        public_key: [u8; 32],
        short_id: [u8; 8],
        fingerprint: String,
    },
    Tls(usize),
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Reality {
                    server_name,
                    public_key,
                    short_id,
                    fingerprint,
                },
                Self::Reality {
                    server_name: other_name,
                    public_key: other_key,
                    short_id: other_id,
                    fingerprint: other_fingerprint,
                },
            ) => {
                server_name == other_name
                    && public_key == other_key
                    && short_id == other_id
                    && fingerprint == other_fingerprint
            }
            (Self::Tls(config), Self::Tls(other)) => config == other,
            _ => false,
        }
    }
}

impl Eq for Identity {}

impl std::hash::Hash for Identity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Reality {
                server_name,
                public_key,
                short_id,
                fingerprint,
            } => {
                0u8.hash(state);
                server_name.hash(state);
                public_key.hash(state);
                short_id.hash(state);
                fingerprint.hash(state);
            }
            Self::Tls(config) => {
                1u8.hash(state);
                config.hash(state);
            }
        }
    }
}

pub(crate) struct Manager {
    bounds: Xmux,
    /// Keeps a TLS identity's address valid for the life of the pool, so a new config cannot be
    /// allocated where a retired one's pointer sat.
    _config: Option<Arc<ferrox_core::tls::TlsConfig>>,
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
    pub(crate) fn new(bounds: Xmux, config: Option<Arc<ferrox_core::tls::TlsConfig>>) -> Arc<Self> {
        Arc::new(Self {
            bounds,
            _config: config,
            entries: Mutex::new(Vec::new()),
        })
    }

    /// The reference's `newXmuxClient` (`mux.go:62`): a session that found no live entry dials its
    /// own transport and adds it, so a stale entry can never discard the session it just handshook.
    pub(crate) fn adopt(&self, conn: Arc<H2Client>) -> Lease {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|entry| !entry.expired());
        let entry = Arc::new(Entry::new(conn, &self.bounds));
        entries.push(Arc::clone(&entry));
        hold(entry)
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
        let open = |entry: &Arc<Entry>| limit <= 0 || entry.running() < limit as usize;
        let count = entries.iter().filter(|entry| open(entry)).count();
        if count == 0 {
            return None;
        }
        let at = pick(count);
        entries.iter().filter(|entry| open(entry)).nth(at).cloned()
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

pub(crate) fn manager(
    key: Key,
    bounds: Option<Xmux>,
    config: Option<Arc<ferrox_core::tls::TlsConfig>>,
) -> Arc<Manager> {
    let mut managers = MANAGERS.lock().unwrap_or_else(PoisonError::into_inner);
    // `transport_method.go:458` fills the defaults only for a wholly empty block, so `{}` takes them too.
    let bounds = bounds
        .filter(|bounds| *bounds != Xmux::default())
        .unwrap_or_else(defaults);
    let map = managers.get_or_insert_with(HashMap::new);
    Arc::clone(
        map.entry((key, bounds))
            .or_insert_with(|| Manager::new(bounds, config)),
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

    fn take(manager: &Arc<Manager>, create: &impl Fn() -> Option<Arc<H2Client>>) -> Option<Lease> {
        manager
            .existing()
            .or_else(|| create().map(|conn| manager.adopt(conn)))
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
            identity: Identity::Reality {
                server_name: "bounds.example".to_owned(),
                public_key: [1; 32],
                short_id: [2; 8],
                fingerprint: "chrome".to_owned(),
            },
            log_sink: None,
        };
        let one = Xmux {
            max_connections: (1, 1),
            ..Xmux::default()
        };
        let two = Xmux {
            max_connections: (2, 2),
            ..Xmux::default()
        };
        let first = manager(key.clone(), Some(one), None);
        let second = manager(key.clone(), Some(two), None);
        let again = manager(key, Some(one), None);
        assert!(
            !Arc::ptr_eq(&first, &second),
            "two outbounds with different connection caps shared one pool"
        );
        assert!(Arc::ptr_eq(&first, &again));
    }

    /// A pool is only as trustworthy as the config that filled it: the same TLS config shares, a
    /// second one with equal fields does not, and no REALITY pool answers a TLS dial.
    #[test]
    fn tls_pools_partition_by_their_exact_config() {
        let config = Arc::new(ferrox_core::tls::TlsConfig::default());
        let twin = Arc::new(ferrox_core::tls::TlsConfig::default());
        let key = |identity| Key {
            server: "127.0.0.1:4443".parse().expect("an address"),
            host: "tls.example".to_owned(),
            path: "/tls".to_owned(),
            query: String::new(),
            h2: true,
            identity,
            log_sink: None,
        };
        let one = manager(
            key(Identity::Tls(Arc::as_ptr(&config) as usize)),
            None,
            Some(Arc::clone(&config)),
        );
        let again = manager(
            key(Identity::Tls(Arc::as_ptr(&config) as usize)),
            None,
            Some(Arc::clone(&config)),
        );
        let other = manager(
            key(Identity::Tls(Arc::as_ptr(&twin) as usize)),
            None,
            Some(twin),
        );
        let reality = manager(
            key(Identity::Reality {
                server_name: "tls.example".to_owned(),
                public_key: [0; 32],
                short_id: [0; 8],
                fingerprint: String::new(),
            }),
            None,
            None,
        );
        assert!(Arc::ptr_eq(&one, &again), "one config split its own pool");
        assert!(
            !Arc::ptr_eq(&one, &other),
            "two TLS configs shared a pooled connection"
        );
        assert!(
            !Arc::ptr_eq(&one, &reality),
            "a REALITY and a TLS pool shared a connection"
        );
    }

    #[test]
    fn the_default_target_dials_three_connections_then_reuses_them() {
        let manager = Manager::new(defaults(), None);
        let (dialed, create) = counter();
        let leased: Vec<Lease> = (0..4)
            .map(|_| take(&manager, &create).expect("a lease"))
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
        let manager = Manager::new(bounds, None);
        let (dialed, create) = counter();
        let first = take(&manager, &create).expect("a lease");
        let first_conn = Arc::clone(first.conn());
        let second = take(&manager, &create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            2,
            "the bound does not park a session"
        );
        assert!(!Arc::ptr_eq(&first_conn, second.conn()));
        drop(first);
        let third = take(&manager, &create).expect("a lease");
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
        let manager = Manager::new(bounds, None);
        let (dialed, create) = counter();
        let one = take(&manager, &create).expect("a lease");
        let one_conn = Arc::clone(one.conn());
        drop(one);
        let two = take(&manager, &create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            1,
            "the second session reuses the client"
        );
        assert!(Arc::ptr_eq(&one_conn, two.conn()));
        drop(two);
        let three = take(&manager, &create).expect("a lease");
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
        let manager = Manager::new(bounds, None);
        let (dialed, create) = counter();
        drop(take(&manager, &create).expect("a lease"));
        drop(take(&manager, &create).expect("a lease"));
        assert_eq!(dialed.load(Ordering::SeqCst), 2, "one request per client");
    }

    /// The choice counts the open entries and walks them again rather than collecting them, so the pick lands on the same entry without a vector.
    #[test]
    fn a_lease_chooses_without_allocating() {
        let bounds = defaults();
        let manager = Manager::new(bounds, None);
        let entries: Vec<Arc<Entry>> = (0..3)
            .map(|_| Arc::new(Entry::new(client().expect("a client"), &bounds)))
            .collect();
        let (chosen, counts) = ferrox_core::alloc_count::measure(|| manager.choose(&entries));
        assert!(chosen.is_some(), "three open entries are a choice");
        assert_eq!(counts.allocs, 0, "{counts:?}");
    }

    #[test]
    fn the_reusable_seconds_retire_an_entry() {
        let mut bounds = defaults();
        bounds.h_max_reusable_secs = (1, 1);
        let manager = Manager::new(bounds, None);
        let (dialed, create) = counter();
        drop(take(&manager, &create).expect("a lease"));
        std::thread::sleep(Duration::from_millis(1100));
        let _second = take(&manager, &create).expect("a lease");
        assert_eq!(
            dialed.load(Ordering::SeqCst),
            2,
            "an expired client is replaced"
        );
    }
}
