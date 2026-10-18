//! The xdrive carrier: one proxy stream carried by an object store both ends poll, so a lane survives addresses, restarts and rebindings by naming its segments in send order.

use crate::budgets::RELAY_POLL;
use crate::conn::Connection;
use crate::json::Json;
use ferrox_core::tls::{RustlsProvider, TlsConfig, TlsProvider as _};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::io::{self, ErrorKind, Read, Write};
use std::net::ToSocketAddrs as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SESSIONS_DIR: &str = "sessions";
const STREAMS_DIR: &str = "streams";
const UPLINK_DIR: &str = "c2s";
const DOWNLINK_DIR: &str = "s2c";
const SEG_SUFFIX: &str = ".seg";
const END_SUFFIX: &str = ".end";
const ERR_SUFFIX: &str = ".err";
const TEMP_PREFIX: &str = ".xdrive-tmp-";

const DEFAULT_SEGMENT_BYTES: usize = 512 * 1024;
const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_FLUSH: Duration = Duration::from_millis(20);
const DEFAULT_MIN_POLL: Duration = Duration::from_millis(50);
const DEFAULT_MAX_POLL: Duration = Duration::from_millis(500);
const DEFAULT_EAGER: Duration = Duration::from_millis(2000);
const DEFAULT_HOLE: Duration = Duration::from_secs(30);
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CONCURRENCY: usize = 8;
const MAX_CONCURRENCY: usize = 64;
const MAX_COALESCED_TICKS: usize = 8;
const WORKER_STACK: usize = 256 * 1024;
const DRAIN_WAIT: Duration = Duration::from_millis(500);
const DRAIN_TRIES: u32 = 120;

/// One object a listing names, with the payload the listing carried alongside it where the service can hand both at once; an inline entry costs the reader no second request.
pub(crate) struct Entry {
    name: String,
    inline: Option<Vec<u8>>,
}

/// The object store a session runs over. `get` answers `NotFound` for an absent name, the one error a polling reader reads as "not yet" rather than as a lane failure.
pub(crate) trait Storage: Send + Sync {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()>;
    fn get(&self, name: &str) -> io::Result<Vec<u8>>;
    fn delete(&self, name: &str) -> io::Result<()>;
    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>>;

    /// Whether a batch of gets is worth a thread each: a store read from the local filesystem answers one in less time than a thread takes to start, so the pump reads it in order.
    fn threaded(&self) -> bool {
        true
    }
}

/// The tuned budgets of one carrier instance, with the reference's defaults and caps applied to whatever the config left out.
#[derive(Debug, Clone)]
pub(crate) struct Params {
    segment_bytes: usize,
    flush: Duration,
    min_poll: Duration,
    max_poll: Duration,
    eager: Duration,
    hole: Duration,
    ttl: Duration,
    concurrency: usize,
}

/// `xdriveSettings` as the reference spells its fields: where the objects live, which service holds them, and the budgets, with the snake_case fallback every resolver in this tree accepts.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub remote_folder: String,
    pub service: String,
    pub secrets: Vec<String>,
    pub template: Option<Json>,
    pub params: Params,
    /// The transport's `security`, which the reference counts in the identity of a shared store.
    pub security: String,
    /// The transport's own TLS, applied to the lanes the store dials; `None` speaks the url's scheme with system roots.
    pub tls: Option<Arc<TlsConfig>>,
}

impl Settings {
    /// An empty folder or an unknown service is a refusal by the caller, not a silent default: a carrier pointed at nowhere must not start polling.
    pub(crate) fn from_json(stream: Option<&Json>) -> Option<Self> {
        let stream = stream?;
        let drive = stream.get("xdriveSettings")?;
        let text = |name: &str| {
            drive
                .get(name)
                .or_else(|| drive.get(&snake_case(name)))
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let number = |name: &str| {
            drive
                .get(name)
                .or_else(|| drive.get(&snake_case(name)))
                .and_then(Json::as_u32)
                .unwrap_or(0)
        };
        let remote_folder = text("remoteFolder");
        let service = text("service");
        if remote_folder.is_empty()
            || (service != "local" && service != "template" && service != "Google Drive")
        {
            return None;
        }
        let security = stream
            .get("security")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let secrets = drive
            .get("secrets")
            .and_then(Json::as_arr)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Json::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let params = Params {
            segment_bytes: bytes_of(
                number("segmentBytes"),
                DEFAULT_SEGMENT_BYTES,
                MAX_SEGMENT_BYTES,
            ),
            flush: millis(number("flushIntervalMs"), DEFAULT_FLUSH),
            min_poll: millis(number("pollIntervalMs"), DEFAULT_MIN_POLL),
            max_poll: millis(number("maxPollIntervalMs"), DEFAULT_MAX_POLL),
            eager: millis(number("eagerWindowMs"), DEFAULT_EAGER),
            hole: millis(number("holeTimeoutMs"), DEFAULT_HOLE),
            ttl: seconds(number("sessionTtlSeconds"), DEFAULT_TTL),
            concurrency: count(number("concurrency"), DEFAULT_CONCURRENCY, MAX_CONCURRENCY),
        }
        .clamped();
        Some(Self {
            params,
            template: template_of(drive),
            remote_folder,
            service,
            secrets,
            tls: transport_tls(stream, &security),
            security,
        })
    }

    /// The store this config names: one per folder for the services that carry a lane pool and an id cache, a fresh one for a folder on disk.
    ///
    /// # Errors
    /// A folder that cannot be created, a template that does not describe four operations, or a Drive set without three secrets.
    pub(crate) fn store(&self, front: Option<(&str, u16)>) -> io::Result<Arc<dyn Storage>> {
        if self.security == "reality" {
            return Err(carrier_error(
                "a store lane does not speak reality: the service is the destination",
            ));
        }
        match self.service.as_str() {
            "local" => Ok(Arc::new(Local::new(&self.remote_folder)?)),
            "template" => {
                let cap = self
                    .template
                    .as_ref()
                    .and_then(|root| root.get("concurrency"))
                    .and_then(Json::as_u32)
                    .unwrap_or(0);
                shared(
                    self,
                    front,
                    count(cap, DEFAULT_INFLIGHT, MAX_INFLIGHT),
                    |settings, http| Ok(Arc::new(Template::build(settings, http)?)),
                )
            }
            "Google Drive" => shared(self, front, DEFAULT_INFLIGHT, |settings, http| {
                Ok(Arc::new(Drive::build(settings, http)?))
            }),
            other => Err(carrier_error(format!(
                "the {other} service is not built here"
            ))),
        }
    }

    /// The store this config names, opened as a client: the session announcement first, then both logs on it.
    pub(crate) fn dial(&self, front: Option<(&str, u16)>) -> io::Result<Conn> {
        dial(self.store(front)?, &Arc::new(self.params.clone()))
    }

    /// The store this config names, watched as a listener: every accepted session goes to `accept` on a thread of its own.
    pub(crate) fn listen(
        &self,
        front: Option<(&str, u16)>,
        accept: Accept,
    ) -> io::Result<Arc<Server>> {
        Server::serve(self.store(front)?, Arc::new(self.params.clone()), accept)
    }

    /// The template as one text, which is what makes two configs the same store.
    fn template_text(&self) -> String {
        let mut text = String::new();
        if let Some(root) = &self.template {
            crate::json::write(root, &mut text);
        }
        text
    }
}

/// The `template` field either as the object it describes or as the JSON text the reference ships it in.
fn template_of(drive: &Json) -> Option<Json> {
    match drive
        .get("template")
        .or_else(|| drive.get("template_json"))?
    {
        Json::Str(text) => crate::json::parse(text).ok(),
        Json::Obj(items) => Some(Json::Obj(items.clone())),
        _ => None,
    }
}

/// The transport's TLS as the store dials it: the config's server name or the url's host, its roots or the system's, and no `ALPN` because the store speaks `HTTP/1.1`.
fn transport_tls(stream: &Json, security: &str) -> Option<Arc<TlsConfig>> {
    (security == "tls").then(|| {
        let tls = stream.get("tlsSettings").unwrap_or(&Json::Null);
        Arc::new(TlsConfig {
            server_name: tls
                .get("serverName")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
            alpn: Vec::new(),
            roots: tls
                .get("caCertFile")
                .and_then(Json::as_str)
                .and_then(|path| std::fs::read(path).ok())
                .map(|pem| crate::quic::parse_ca_pem(&pem))
                .unwrap_or_default(),
            pins: ferrox_core::foxy::pin::Pins::default(),
            cipher_suites: Vec::new(),
            insecure: tls.get("allowInsecure").and_then(Json::as_bool) == Some(true),
        })
    })
}

/// The snake_case spelling of a camelCase config name, so either form reaches one field.
fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for ch in name.chars() {
        if ch.is_uppercase() {
            out.push('_');
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// A budget left at zero is unset; any other value is taken as configured.
fn millis(value: u32, fallback: Duration) -> Duration {
    if value == 0 {
        fallback
    } else {
        Duration::from_millis(u64::from(value))
    }
}

fn seconds(value: u32, fallback: Duration) -> Duration {
    if value == 0 {
        fallback
    } else {
        Duration::from_secs(u64::from(value))
    }
}

/// A byte budget capped at the ceiling the reference enforces, never rounded down to zero.
fn bytes_of(value: u32, fallback: usize, limit: usize) -> usize {
    if value == 0 {
        return fallback;
    }
    usize::try_from(value).unwrap_or(limit).clamp(1, limit)
}

fn count(value: u32, fallback: usize, limit: usize) -> usize {
    if value == 0 {
        return fallback;
    }
    usize::try_from(value).unwrap_or(limit).clamp(1, limit)
}

impl Params {
    /// A `maxPollIntervalMs` configured below its own `pollIntervalMs` is raised to it, so the backoff never inverts.
    fn clamped(mut self) -> Self {
        if self.max_poll < self.min_poll {
            self.max_poll = self.min_poll;
        }
        self
    }
}

/// `sessions/<unixnano>-<session>`: the stamp is part of the name because the listener ages announcements out of the name alone, with no metadata to read.
fn announce_name(session: &str, nanos: i64) -> String {
    format!("{SESSIONS_DIR}/{nanos}-{session}")
}

/// The name split back apart: a digit-only nanosecond stamp and the session after the first dash.
fn parse_announce(entry: &str) -> Option<(&str, i64)> {
    let (stamp, session) = entry.split_once('-')?;
    if session.is_empty() {
        return None;
    }
    Some((session, digits(stamp)?.parse().ok()?))
}

/// Only ASCII digits, so a forged listing that carries a sign, a space or a non-decimal digit names nothing.
fn digits(text: &str) -> Option<&str> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then_some(text)
}

fn uplink_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}/{UPLINK_DIR}")
}

fn downlink_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}/{DOWNLINK_DIR}")
}

/// The nine-digit sequence and the suffix: a listing sorts into send order by this width, so the padding is wire format.
fn object_name(prefix: &str, seq: u64, suffix: &str) -> String {
    format!("{prefix}/{seq:09}{suffix}")
}

/// The sequence and suffix a listed name carries, or nothing for a name this carrier did not write.
fn parse_entry(name: &str) -> Option<(u64, &str)> {
    let dot = name.rfind('.')?;
    let suffix = &name[dot..];
    if suffix != SEG_SUFFIX && suffix != END_SUFFIX && suffix != ERR_SUFFIX {
        return None;
    }
    digits(&name[..dot])?.parse().ok().map(|seq| (seq, suffix))
}

fn unix_nanos(now: SystemTime) -> i64 {
    i64::try_from(
        now.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    )
    .unwrap_or(i64::MAX)
}

/// The 32 lowercase hex characters that name one session.
fn session_id() -> io::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|error| io::Error::other(error.to_string()))?;
    let mut hex = String::with_capacity(32);
    for byte in raw {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// A failure the lane reports as its own end: an object the store refused to hold, a segment that never arrived while later ones did, or a peer that marked one lost.
fn carrier_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Why a loop's wait ended, since a loop woken by the peer polls at once while one woken by a halt returns.
enum Woke {
    Stopped,
    Rung,
    Waited,
}

/// The wait every xdrive loop parks on: a poll interval, a ring from the peer's write, or the lane's halt, all on one condvar so closing a stream ends every loop without a join.
struct Wake {
    stopped: AtomicBool,
    rung: AtomicBool,
    lock: Mutex<()>,
    cv: Condvar,
}

impl Wake {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            rung: AtomicBool::new(false),
            lock: Mutex::new(()),
            cv: Condvar::new(),
        }
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Shorten the next wait: the peer's write means an object the reader would otherwise learn of only when its backoff expires.
    fn ring(&self) {
        self.rung.store(true, Ordering::Release);
        self.cv.notify_one();
    }

    fn halt(&self) {
        self.stopped.store(true, Ordering::Release);
        self.cv.notify_all();
    }

    /// Wait out `longest`, or until rung, or until halted; a flag set while nobody waited is read here, so a wake is never lost between two polls.
    fn wait(&self, longest: Duration) -> Woke {
        if self.stopped() {
            return Woke::Stopped;
        }
        if self.rung.swap(false, Ordering::AcqRel) {
            return Woke::Rung;
        }
        census!("xdrive-wait", crate::census::NO_FD, Some(longest));
        let guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (guard, timed_out) = self
            .cv
            .wait_timeout(guard, longest)
            .unwrap_or_else(PoisonError::into_inner);
        drop(guard);
        if self.stopped() {
            return Woke::Stopped;
        }
        if self.rung.swap(false, Ordering::AcqRel) || !timed_out.timed_out() {
            return Woke::Rung;
        }
        Woke::Waited
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

/// The jobs a `Pool` drains, with those handed to a worker counted beside those still waiting so a closer can wait for its last upload to land.
struct Queue {
    jobs: VecDeque<Job>,
    left: usize,
    shut: bool,
}

/// Bounded concurrent work against the store — uploads, deletes — whose threads exist only while jobs wait: a lane idle for an hour costs no thread, and a burst of segments gets as many as the config allows and no more.
struct Pool {
    queue: Mutex<Queue>,
    run: Condvar,
    settled: Condvar,
    live: AtomicUsize,
    cap: usize,
}

impl Pool {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(Queue {
                jobs: VecDeque::new(),
                left: 0,
                shut: false,
            }),
            run: Condvar::new(),
            settled: Condvar::new(),
            live: AtomicUsize::new(0),
            cap,
        })
    }

    /// Hand a job over, starting a worker when every one it has may already be busy. The count and the queue move under one lock, so a job never sits waiting with no worker awake for it.
    fn push(self: &Arc<Self>, job: Job) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.shut {
            return false;
        }
        queue.jobs.push_back(job);
        queue.left += 1;
        let live = self.live.load(Ordering::Acquire);
        let spawn = queue.jobs.len() >= live && live < self.cap;
        self.run.notify_one();
        if !spawn {
            return true;
        }
        self.live.fetch_add(1, Ordering::AcqRel);
        let pool = Arc::clone(self);
        if std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || Self::drain(&pool))
            .is_ok()
        {
            return true;
        }
        self.live.fetch_sub(1, Ordering::AcqRel);
        if let Some(job) = queue.jobs.pop_front() {
            drop(queue);
            job();
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.left -= 1;
            if queue.left == 0 {
                self.settled.notify_all();
            }
        }
        true
    }

    /// A worker's life: wait for a job, run it outside the lock, and retire only when the queue holds nothing and no more can arrive.
    fn drain(self: &Arc<Self>) {
        loop {
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            while queue.jobs.is_empty() {
                if queue.shut {
                    drop(queue);
                    self.live.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                census!("xdrive-worker", crate::census::NO_FD, None);
                queue = self.run.wait(queue).unwrap_or_else(PoisonError::into_inner);
            }
            let Some(job) = queue.jobs.pop_front() else {
                continue;
            };
            drop(queue);
            job();
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.left -= 1;
            if queue.left == 0 {
                self.settled.notify_all();
            }
        }
    }

    /// No further jobs, but every one already promised still runs: the `.end` marker a writer puts after this must not overtake the segments queued before it.
    fn shut(&self) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .shut = true;
        self.run.notify_all();
    }

    /// Wait for every promised job, giving up if the lane ends underneath: a relay tearing down has no reader left to wait for.
    fn wait_settled(&self, wake: &Wake) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        for _ in 0..DRAIN_TRIES {
            if queue.left == 0 {
                return true;
            }
            if wake.stopped() {
                return false;
            }
            census!("xdrive-drain", crate::census::NO_FD, Some(DRAIN_WAIT));
            let (guard, _timeout) = self
                .settled
                .wait_timeout(queue, DRAIN_WAIT)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
        }
        queue.left == 0
    }

    /// End the queue and throw away what never started: the lane is already dying and nothing left can read it.
    fn abort(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        queue.shut = true;
        queue.left -= queue.jobs.len();
        queue.jobs.clear();
        if queue.left == 0 {
            self.settled.notify_all();
        }
        drop(queue);
        self.run.notify_all();
    }
}

/// One writer's place in the shared ticker.
struct Ticker {
    sink: Arc<Sink>,
    pending: Arc<Mutex<Pending>>,
    uploads: Arc<Pool>,
    every: Duration,
    due: AtomicU64,
    done: AtomicBool,
}

/// The clock every writer registers with: the interval is the same for every session, so one thread pacing all of them replaces one timer per stream.
struct Clock {
    list: Mutex<Vec<Arc<Ticker>>>,
    cv: Condvar,
}

/// Milliseconds since the first mark, so one monotonic clock numbers every writer's deadline.
fn mark() -> u64 {
    static ZERO: OnceLock<Instant> = OnceLock::new();
    Instant::now()
        .duration_since(*ZERO.get_or_init(Instant::now))
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

impl Clock {
    fn global() -> Arc<Self> {
        static CLOCK: OnceLock<Arc<Clock>> = OnceLock::new();
        Arc::clone(CLOCK.get_or_init(|| {
            let clock = Arc::new(Self {
                list: Mutex::new(Vec::new()),
                cv: Condvar::new(),
            });
            let runner = Arc::clone(&clock);
            std::thread::Builder::new()
                .stack_size(WORKER_STACK)
                .spawn(move || runner.run())
                .expect("the xdrive ticker always starts");
            clock
        }))
    }

    /// Wake the runner so it recomputes its deadline the moment a writer joins or leaves.
    fn wakeup(&self) {
        let _guard = self.list.lock().unwrap_or_else(PoisonError::into_inner);
        self.cv.notify_one();
    }

    fn add(&self, ticker: Arc<Ticker>) {
        self.list
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(ticker);
        self.wakeup();
    }

    /// Drop writers that ended, arm the ones now due, fire them off the lock, then sleep until the next deadline.
    fn run(&self) {
        loop {
            let mut due: Vec<Arc<Ticker>> = Vec::new();
            let mut next = u64::MAX;
            {
                let mut list = self.list.lock().unwrap_or_else(PoisonError::into_inner);
                let now = mark();
                list.retain(|ticker| {
                    if ticker.done.load(Ordering::Acquire) {
                        return false;
                    }
                    let at = ticker.due.load(Ordering::Acquire);
                    if at > now {
                        next = next.min(at);
                        return true;
                    }
                    let again = now.saturating_add(ticker.every.as_millis().max(1) as u64);
                    ticker.due.store(again, Ordering::Release);
                    next = next.min(again);
                    due.push(Arc::clone(ticker));
                    true
                });
            }
            for ticker in &due {
                tick(ticker);
            }
            let sleep = if next == u64::MAX {
                DEFAULT_FLUSH
            } else {
                Duration::from_millis(next.saturating_sub(mark()).max(1))
            };
            census!("xdrive-ticker", crate::census::NO_FD, Some(sleep));
            let guard = self.list.lock().unwrap_or_else(PoisonError::into_inner);
            let (guard, _timeout) = self
                .cv
                .wait_timeout(guard, sleep)
                .unwrap_or_else(PoisonError::into_inner);
            drop(guard);
        }
    }
}

/// The parts of a writer an upload worker needs, held apart from the buffer state so a worker's closure never points back at the stream that owns it.
struct Sink {
    storage: Arc<dyn Storage>,
    prefix: String,
    wake: Arc<Wake>,
    segment: usize,
    err: Mutex<Option<String>>,
    spare: Mutex<Vec<Vec<u8>>>,
}

impl Sink {
    /// A failed put is the lane's last word: the writer reports it and stops writing, as the reference latches its first error, and names the object so the peer ends instead of waiting out the hole timeout.
    fn note(&self, message: String) {
        let mut err = self.err.lock().unwrap_or_else(PoisonError::into_inner);
        if err.is_none() {
            *err = Some(message);
        }
        drop(err);
        self.wake.ring();
    }

    fn failure(&self) -> Option<String> {
        self.err
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// An empty buffer with the capacity a finished upload left behind, so steady traffic writes into the same allocation instead of paying for a fresh one per segment.
    fn adopt(&self) -> Vec<u8> {
        self.spare
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_default()
    }

    /// A buffer that reached the store is worth keeping only for its capacity, and only a couple of them.
    fn reclaim(&self, data: Vec<u8>) {
        let mut spare = self.spare.lock().unwrap_or_else(PoisonError::into_inner);
        if spare.len() < 2 && !data.is_empty() {
            spare.push(data);
        }
    }

    /// One segment's upload: the store's refusal latches the failure and marks the sequence, and the buffer comes back either way.
    fn send(&self, name: String, marker: String, buf: Vec<u8>, len: usize) {
        if let Err(error) = self.storage.put(&name, &buf[..len]) {
            self.note(format!("the store refused {name}: {error}"));
            let _ = self.storage.put(&marker, &[]);
        }
        self.reclaim(buf);
    }
}

/// The bytes not yet sent, with the coalescing state beside them: `held` counts the ticks a still-growing buffer was left alone and `last` is the size the tick before saw.
struct Pending {
    buf: Vec<u8>,
    seq: u64,
    last: usize,
    held: usize,
    closed: bool,
    err: Option<String>,
}

impl Pending {
    /// The reference's rule: while the buffer keeps growing hold the cut for a bounded number of ticks so a burst coalesces, and flush the moment growth stops.
    fn ready(&mut self) -> bool {
        let grew = self.buf.len() > self.last;
        self.last = self.buf.len();
        if grew && self.held < MAX_COALESCED_TICKS {
            self.held += 1;
            return false;
        }
        self.held = 0;
        true
    }
}

/// The write half of a session: coalesce into segments, hand each to the store, and close with the `.end` marker at the sequence the peer reads to know the stream is over.
struct Writer {
    sink: Arc<Sink>,
    uploads: Arc<Pool>,
    pending: Arc<Mutex<Pending>>,
    ticker: Arc<Ticker>,
    ended: AtomicBool,
}

impl Writer {
    fn new(storage: Arc<dyn Storage>, prefix: String, params: &Params, wake: Arc<Wake>) -> Self {
        let sink = Arc::new(Sink {
            segment: params.segment_bytes,
            storage,
            prefix,
            wake,
            err: Mutex::new(None),
            spare: Mutex::new(Vec::new()),
        });
        let uploads = Pool::new(params.concurrency);
        let pending = Arc::new(Mutex::new(Pending {
            buf: Vec::new(),
            seq: 0,
            last: 0,
            held: 0,
            closed: false,
            err: None,
        }));
        let ticker = Arc::new(Ticker {
            sink: Arc::clone(&sink),
            pending: Arc::clone(&pending),
            uploads: Arc::clone(&uploads),
            every: params.flush,
            due: AtomicU64::new(mark().saturating_add(params.flush.as_millis() as u64)),
            done: AtomicBool::new(false),
        });
        Clock::global().add(Arc::clone(&ticker));
        Self {
            sink,
            uploads,
            pending,
            ticker,
            ended: AtomicBool::new(false),
        }
    }

    /// Append and cut whole segments as the buffer fills, so a bulk write never parks bytes in memory waiting for the clock.
    fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.err.is_none() {
            pending.err = self.sink.failure();
        }
        if let Some(message) = &pending.err {
            return Err(carrier_error(message.clone()));
        }
        if pending.closed {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        }
        pending.buf.extend_from_slice(data);
        while pending.buf.len() >= self.sink.segment {
            if !Self::cut(&self.sink, &self.uploads, &mut pending) {
                let message = pending
                    .err
                    .clone()
                    .unwrap_or_else(|| "the store stopped answering".to_owned());
                return Err(carrier_error(message));
            }
        }
        Ok(data.len())
    }

    /// Move one segment out of the buffer and onto the store. The buffer goes whole and only the bytes past this sequence are copied into a recycled continuation, so a flush that empties the tail costs no copy and one that does not costs the remainder once, against the reference's segment-plus-remainder pair.
    fn cut(sink: &Arc<Sink>, uploads: &Arc<Pool>, pending: &mut Pending) -> bool {
        if pending.buf.is_empty() {
            return true;
        }
        if let Some(message) = sink.failure() {
            pending.err.get_or_insert(message);
            return false;
        }
        let len = pending.buf.len().min(sink.segment);
        let rest = pending.buf.len() - len;
        let mut next = sink.adopt();
        if next.capacity() < rest {
            next = Vec::with_capacity(rest.max(sink.segment));
        }
        next.extend_from_slice(&pending.buf[len..]);
        let buf = std::mem::replace(&mut pending.buf, next);
        let seq = pending.seq;
        pending.seq += 1;
        pending.last = pending.buf.len();
        pending.held = 0;
        let name = object_name(&sink.prefix, seq, SEG_SUFFIX);
        let marker = object_name(&sink.prefix, seq, ERR_SUFFIX);
        let job_sink = Arc::clone(sink);
        if !uploads.push(Box::new(move || job_sink.send(name, marker, buf, len))) {
            pending
                .err
                .get_or_insert("the writer closed with a segment unsent".to_owned());
            return false;
        }
        true
    }

    /// Drain what the stream still holds, wait for every segment to land, then name the end: a peer reads the `.end` at the next sequence and closes its own side.
    fn close(&self) -> io::Result<()> {
        if self.ended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let seq = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            pending.closed = true;
            while !pending.buf.is_empty() && Self::cut(&self.sink, &self.uploads, &mut pending) {}
            pending.seq
        };
        self.ticker.done.store(true, Ordering::Release);
        Clock::global().wakeup();
        self.uploads.shut();
        if let Some(message) = self.sink.failure() {
            self.uploads.abort();
            return Err(carrier_error(message));
        }
        if !self.uploads.wait_settled(&self.sink.wake) {
            self.uploads.abort();
            return Err(carrier_error(
                "the store stopped answering the last segments".to_owned(),
            ));
        }
        self.sink
            .storage
            .put(&object_name(&self.sink.prefix, seq, END_SUFFIX), &[])
    }
}

impl Drop for Writer {
    /// A write log left open by a relay that dropped its handle gets its `.end` here; `close` is idempotent, so the leg that closed in prose costs one atomic swap.
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// A writer's tick: decide whether the buffer is ripe and, if it is, hand over a segment.
fn tick(ticker: &Ticker) {
    let mut pending = ticker
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if pending.closed || pending.err.is_some() || pending.buf.is_empty() || !pending.ready() {
        return;
    }
    Writer::cut(&ticker.sink, &ticker.uploads, &mut pending);
}

/// What the relay's read asks the inbox for next.
enum Piece {
    Chunk(Vec<u8>),
    Ended(Option<String>),
    Waited,
}

/// The read half's mailbox: the chunks the poll delivered, bounded by the same concurrency the store is read with so a fast store cannot outrun a slow relay leg.
struct Inbox {
    chunks: Mutex<VecDeque<Vec<u8>>>,
    got: Condvar,
    room: Condvar,
    ended: AtomicBool,
    err: Mutex<Option<String>>,
}

impl Inbox {
    fn new() -> Self {
        Self {
            chunks: Mutex::new(VecDeque::new()),
            got: Condvar::new(),
            room: Condvar::new(),
            ended: AtomicBool::new(false),
            err: Mutex::new(None),
        }
    }

    /// The poll's hand-off: wait for room, and give up if the lane ends underneath.
    fn push(&self, chunk: Vec<u8>, cap: usize, wake: &Wake) -> bool {
        let mut queue = self.chunks.lock().unwrap_or_else(PoisonError::into_inner);
        while queue.len() >= cap {
            if wake.stopped() {
                return false;
            }
            census!("xdrive-inbox-room", crate::census::NO_FD, Some(DRAIN_WAIT));
            let (guard, _timeout) = self
                .room
                .wait_timeout(queue, DRAIN_WAIT)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
        }
        queue.push_back(chunk);
        drop(queue);
        self.got.notify_one();
        true
    }

    /// End the stream for the reader, once: no reason is a clean `.end`, a reason is a refusal, which is how the reference splits `io.EOF` from a latched error.
    fn end(&self, reason: Option<String>) {
        if self.ended.swap(true, Ordering::AcqRel) {
            return;
        }
        *self.err.lock().unwrap_or_else(PoisonError::into_inner) = reason;
        self.got.notify_all();
        self.room.notify_all();
    }

    /// The next chunk, the stream's end, or nothing within `longest`.
    fn take(&self, longest: Duration) -> Piece {
        let mut queue = self.chunks.lock().unwrap_or_else(PoisonError::into_inner);
        let until = Instant::now() + longest;
        loop {
            if let Some(chunk) = queue.pop_front() {
                drop(queue);
                self.room.notify_one();
                return Piece::Chunk(chunk);
            }
            if self.ended.load(Ordering::Acquire) {
                let reason = self
                    .err
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                return Piece::Ended(reason);
            }
            let now = Instant::now();
            if now >= until {
                return Piece::Waited;
            }
            census!("xdrive-read", crate::census::NO_FD, Some(until - now));
            let (guard, timeout) = self
                .got
                .wait_timeout(queue, until - now)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
            if timeout.timed_out() {
                return Piece::Waited;
            }
        }
    }
}

/// What the polling half of a stream needs of the store, held apart from the mailbox so the pump thread can reach both.
struct Rd {
    storage: Arc<dyn Storage>,
    prefix: String,
    params: Arc<Params>,
    wake: Arc<Wake>,
    discards: Arc<Pool>,
}

impl Rd {
    /// Forget one object once it has been read: a store holds a live stream only as long as its objects do.
    fn discard(&self, full: String) {
        let storage = Arc::clone(&self.storage);
        let _ = self.discards.push(Box::new(move || {
            let _ = storage.delete(&full);
        }));
    }

    /// One pass at the store: list, work out what comes next, fetch it, hand the bytes over. The answer says whether the sequence moved and whether the peer ended the stream.
    fn poll(
        &self,
        seq: &mut u64,
        hole: &mut Option<Instant>,
        inbox: &Inbox,
    ) -> io::Result<(bool, bool)> {
        let mut listed = self.storage.list(&self.prefix)?;
        if listed.is_empty() {
            return Ok((false, false));
        }
        let mut pending: HashMap<u64, usize> = HashMap::new();
        let mut ahead = false;
        for (index, entry) in listed.iter().enumerate() {
            if let Some((number, _)) = parse_entry(&entry.name) {
                pending.insert(number, index);
                if number > *seq {
                    ahead = true;
                }
            }
        }
        if !pending.contains_key(seq) && ahead {
            match hole {
                empty @ None => *empty = Some(Instant::now()),
                Some(since) if since.elapsed() >= self.params.hole => {
                    return Err(carrier_error(format!(
                        "segment {seq} never arrived while later ones did, the peer lost it"
                    )));
                }
                Some(_) => {}
            }
        } else {
            *hole = None;
        }

        let mut advanced = false;
        loop {
            if let Some(&index) = pending.get(seq) {
                if listed[index].name.ends_with(ERR_SUFFIX) {
                    let full = format!("{}/{}", self.prefix, listed[index].name);
                    self.discard(full);
                    return Err(carrier_error(format!(
                        "the peer could not store segment {seq}"
                    )));
                }
            }
            let mut batch: Vec<usize> = Vec::with_capacity(self.params.concurrency);
            let mut done = false;
            for offset in 0..self.params.concurrency as u64 {
                let Some(&index) = pending.get(&(*seq + offset)) else {
                    break;
                };
                let name = &listed[index].name;
                if !name.ends_with(SEG_SUFFIX) {
                    if offset == 0 && name.ends_with(END_SUFFIX) {
                        let full = format!("{}/{}", self.prefix, name);
                        self.discard(full);
                        done = true;
                    }
                    break;
                }
                batch.push(index);
            }
            if done {
                return Ok((advanced, true));
            }
            let chunks = match self.fetch(&mut listed, &batch) {
                Ok(chunks) => chunks,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok((advanced, false)),
                Err(error) => return Err(error),
            };
            if chunks.is_empty() {
                return Ok((advanced, false));
            }
            for (offset, chunk) in chunks.into_iter().enumerate() {
                if !inbox.push(chunk, self.params.concurrency, &self.wake) {
                    return Ok((advanced, true));
                }
                let full = format!("{}/{}", self.prefix, listed[batch[offset]].name);
                self.discard(full);
                *seq += 1;
                advanced = true;
            }
        }
    }

    /// Pull a batch down: an inline entry costs nothing, one object costs no thread, and a remote store is read with a whole batch of requests in flight.
    fn fetch(&self, listed: &mut [Entry], batch: &[usize]) -> io::Result<Vec<Vec<u8>>> {
        let mut got: Vec<Option<Vec<u8>>> = batch.iter().map(|_| None).collect();
        let mut need: Vec<(usize, String)> = Vec::with_capacity(batch.len());
        for (slot, &index) in batch.iter().enumerate() {
            if let Some(data) = listed[index].inline.take() {
                got[slot] = Some(data);
                continue;
            }
            need.push((slot, format!("{}/{}", self.prefix, listed[index].name)));
        }
        if need.is_empty() {
            return Ok(got.into_iter().flatten().collect());
        }
        if need.len() == 1 || !self.storage.threaded() {
            for (slot, name) in need {
                got[slot] = Some(self.storage.get(&name)?);
            }
            return Ok(got.into_iter().flatten().collect());
        }
        let answers: Mutex<HashMap<usize, io::Result<Vec<u8>>>> = Mutex::new(HashMap::new());
        std::thread::scope(|scope| {
            for (slot, name) in need {
                let storage = &self.storage;
                let filled = &answers;
                let _ = std::thread::Builder::new()
                    .stack_size(WORKER_STACK)
                    .spawn_scoped(scope, move || {
                        let answer = storage.get(&name);
                        filled
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(slot, answer);
                    });
            }
        });
        let mut answers = answers
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (slot, place) in got.iter_mut().enumerate() {
            if place.is_some() {
                continue;
            }
            match answers.remove(&slot) {
                Some(Ok(data)) => *place = Some(data),
                Some(Err(error)) => return Err(error),
                None => {
                    return Err(carrier_error(format!(
                        "the store answered nothing for segment {}",
                        listed[batch[slot]].name
                    )));
                }
            }
        }
        Ok(got.into_iter().flatten().collect())
    }

    /// The pump's own loop: poll, then wait out a backoff the peer's write can cut short; the mailbox ends with the reason the loop stopped.
    fn run(&self, inbox: &Inbox) {
        let mut seq = 0u64;
        let mut hole: Option<Instant> = None;
        let mut delay = self.params.min_poll;
        let mut active = Instant::now();
        loop {
            let polled = Instant::now();
            match self.poll(&mut seq, &mut hole, inbox) {
                Ok((advanced, eof)) => {
                    if eof {
                        return;
                    }
                    if advanced {
                        active = Instant::now();
                    }
                    delay = backoff(advanced, active, delay, &self.params);
                }
                Err(error) => {
                    inbox.end(Some(error.to_string()));
                    return;
                }
            }
            match self.wake.wait(delay) {
                Woke::Stopped => return,
                Woke::Waited => {}
                Woke::Rung => {
                    active = Instant::now();
                    delay = self.params.min_poll;
                    if let Some(rest) = self.params.min_poll.checked_sub(polled.elapsed()) {
                        if matches!(self.wake.wait(rest), Woke::Stopped) {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// The wait the next poll of a lane gets: the interval while it advances or is still fresh, then doubling to the cap.
fn backoff(advanced: bool, active: Instant, delay: Duration, params: &Params) -> Duration {
    if advanced || active.elapsed() < params.eager {
        return params.min_poll;
    }
    delay
        .checked_mul(2)
        .unwrap_or(params.max_poll)
        .min(params.max_poll)
}

/// The read half: a pump thread polling the store, and the mailbox the relay reads.
struct Reader {
    rd: Arc<Rd>,
    inbox: Arc<Inbox>,
    rest: Mutex<(Vec<u8>, usize)>,
}

impl Reader {
    fn new(
        storage: Arc<dyn Storage>,
        prefix: String,
        params: Arc<Params>,
        wake: Arc<Wake>,
    ) -> Self {
        let rd = Arc::new(Rd {
            discards: Pool::new(params.concurrency),
            storage,
            prefix,
            params,
            wake,
        });
        let inbox = Arc::new(Inbox::new());
        let pump = Arc::clone(&rd);
        let mailbox = Arc::clone(&inbox);
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || {
                pump.run(&mailbox);
                mailbox.end(None);
            })
            .expect("a reader always gets its pump");
        Self {
            rd,
            inbox,
            rest: Mutex::new((Vec::new(), 0)),
        }
    }

    /// Fill from the mailbox and keep the unread tail of a chunk the caller could not take, so a chunk is delivered once and never copied back.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut rest = self.rest.lock().unwrap_or_else(PoisonError::into_inner);
        if rest.1 < rest.0.len() {
            let n = (rest.0.len() - rest.1).min(buf.len());
            buf[..n].copy_from_slice(&rest.0[rest.1..rest.1 + n]);
            rest.1 += n;
            if rest.1 == rest.0.len() {
                rest.0.clear();
                rest.1 = 0;
            }
            return Ok(n);
        }
        drop(rest);
        match self.inbox.take(RELAY_POLL) {
            Piece::Waited => Err(io::Error::from(ErrorKind::WouldBlock)),
            Piece::Ended(None) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Piece::Ended(Some(reason)) => Err(carrier_error(reason)),
            Piece::Chunk(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                let mut rest = self.rest.lock().unwrap_or_else(PoisonError::into_inner);
                rest.0 = data;
                rest.1 = n;
                Ok(n)
            }
        }
    }
}

impl Drop for Reader {
    /// The last handle dropping ends the pump and the discards, so a session never outlives the relay that read it.
    fn drop(&mut self) {
        self.rd.wake.halt();
        self.rd.discards.abort();
    }
}

/// One xdrive stream: the two write-ahead logs one session names, with the object store the peer reads and writes beside them.
#[derive(Clone)]
pub(crate) struct Conn {
    writer: Arc<Writer>,
    reader: Arc<Reader>,
    wake: Arc<Wake>,
}

impl Conn {
    fn pair(storage: Arc<dyn Storage>, params: &Arc<Params>, write: String, read: String) -> Self {
        let wake = Arc::new(Wake::new());
        Self {
            writer: Arc::new(Writer::new(
                Arc::clone(&storage),
                write,
                params,
                Arc::clone(&wake),
            )),
            reader: Arc::new(Reader::new(
                storage,
                read,
                Arc::clone(params),
                Arc::clone(&wake),
            )),
            wake,
        }
    }

    /// End only the write log, so a relay whose source went quiet lets the peer read its `.end` while our own reader keeps serving the reply.
    pub(crate) fn end_write(&self) -> io::Result<()> {
        self.writer.close()
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.wake.ring();
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The client's half of a session: name the session where the listener looks, then open both logs on it.
pub(crate) fn dial(storage: Arc<dyn Storage>, params: &Arc<Params>) -> io::Result<Conn> {
    let session = session_id()?;
    storage.put(&announce_name(&session, unix_nanos(SystemTime::now())), &[])?;
    Ok(Conn::pair(
        storage,
        params,
        uplink_prefix(&session),
        downlink_prefix(&session),
    ))
}

/// What a listener hands each accepted session to: the caller's relay, on a thread of its own.
pub(crate) type Accept = Arc<dyn Fn(Conn) + Send + Sync>;

/// The sessions one listener has already seen, so a second listing of the same announcement cannot open it twice.
#[derive(Default)]
struct Claims {
    active: HashSet<String>,
    handled: HashMap<String, Instant>,
    idle: HashMap<String, Instant>,
}

/// The server's half: a poll for announcements, a sweep for abandoned sessions, and the claims that keep each session opening once.
pub(crate) struct Server {
    wake: Arc<Wake>,
    claims: Mutex<Claims>,
}

impl Server {
    /// Watch the store for sessions and hand each one over, then keep the folder clean of what nobody closed.
    pub(crate) fn serve(
        storage: Arc<dyn Storage>,
        params: Arc<Params>,
        accept: Accept,
    ) -> io::Result<Arc<Self>> {
        let server = Arc::new(Self {
            wake: Arc::new(Wake::new()),
            claims: Mutex::new(Claims::default()),
        });
        let rd = Arc::new(Rd {
            discards: Pool::new(params.concurrency),
            storage,
            prefix: String::new(),
            params,
            wake: Arc::clone(&server.wake),
        });
        let accept_loop = Arc::clone(&server);
        let accept_rd = Arc::clone(&rd);
        let accept_handler = Arc::clone(&accept);
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || accept_loop.accept(&accept_rd, &accept_handler))
            .map_err(|error| io::Error::other(error.to_string()))?;
        let collect_loop = Arc::clone(&server);
        let collect_rd = Arc::clone(&rd);
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || collect_loop.collect_loop(&collect_rd))
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(server)
    }

    /// Claim a session once: a name already active or already handed over is not opened again.
    fn claim(&self, session: &str) -> bool {
        let mut claims = self.claims.lock().unwrap_or_else(PoisonError::into_inner);
        if claims.active.contains(session) || claims.handled.contains_key(session) {
            return false;
        }
        claims.active.insert(session.to_owned());
        claims.handled.insert(session.to_owned(), Instant::now());
        true
    }

    fn release(&self, session: &str) {
        self.claims
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active
            .remove(session);
    }

    /// Poll the announcement folder on the same backoff as a stream: a busy listener stays at the fast interval, a quiet one sleeps out to the cap.
    fn accept(self: &Arc<Self>, rd: &Rd, accept: &Accept) {
        let mut delay = rd.params.min_poll;
        let mut active = Instant::now();
        loop {
            let accepted = self.accept_pending(rd, accept);
            if accepted {
                active = Instant::now();
            }
            delay = backoff(accepted, active, delay, &rd.params);
            match rd.wake.wait(delay) {
                Woke::Stopped => return,
                Woke::Rung => {
                    active = Instant::now();
                    delay = rd.params.min_poll;
                }
                Woke::Waited => {}
            }
        }
    }

    /// One listing of `sessions`: drop what is not an announcement or older than the ttl, and open what is fresh and unclaimed.
    fn accept_pending(self: &Arc<Self>, rd: &Rd, accept: &Accept) -> bool {
        let Ok(listed) = rd.storage.list(SESSIONS_DIR) else {
            return false;
        };
        let mut accepted = false;
        for entry in listed {
            let full = format!("{SESSIONS_DIR}/{}", entry.name);
            let Some((session, at)) = parse_announce(&entry.name) else {
                rd.discard(full);
                continue;
            };
            if unix_nanos(SystemTime::now()) - at
                > i64::try_from(rd.params.ttl.as_nanos()).unwrap_or(i64::MAX)
            {
                rd.discard(full);
                rd.discard(format!("{STREAMS_DIR}/{session}"));
                continue;
            }
            if !self.claim(session) {
                continue;
            }
            rd.discard(full);
            accepted = true;
            let conn = Conn::pair(
                Arc::clone(&rd.storage),
                &rd.params,
                downlink_prefix(session),
                uplink_prefix(session),
            );
            let server = Arc::clone(self);
            let handler = Arc::clone(accept);
            let session = session.to_owned();
            let handed = session.clone();
            if std::thread::Builder::new()
                .stack_size(WORKER_STACK)
                .spawn(move || {
                    handler(conn);
                    server.release(&handed);
                })
                .is_err()
            {
                self.release(&session);
            }
        }
        accepted
    }

    /// Sweep the streams folder twice a ttl: a session nobody has touched for a ttl is bytes no peer will read again.
    fn collect_loop(&self, rd: &Rd) {
        let interval = rd.params.ttl / 2;
        loop {
            if matches!(rd.wake.wait(interval), Woke::Stopped) {
                return;
            }
            let _ = self.collect(rd);
        }
    }

    fn collect(&self, rd: &Rd) -> io::Result<()> {
        let listed = rd.storage.list(STREAMS_DIR)?;
        let now = Instant::now();
        let mut expired: Vec<String> = Vec::new();
        {
            let mut claims = self.claims.lock().unwrap_or_else(PoisonError::into_inner);
            let mut present: HashSet<String> = HashSet::new();
            for entry in &listed {
                let session = &entry.name;
                present.insert(session.clone());
                if claims.active.contains(session.as_str()) {
                    claims.idle.remove(session.as_str());
                    continue;
                }
                match claims.idle.get(session.as_str()).copied() {
                    None => {
                        claims.idle.insert(session.clone(), now);
                    }
                    Some(since) if now.duration_since(since) >= rd.params.ttl => {
                        expired.push(session.clone());
                        claims.idle.remove(session.as_str());
                    }
                    Some(_) => {}
                }
            }
            claims.idle.retain(|session, _| present.contains(session));
            let ttl = rd.params.ttl;
            let active = claims.active.clone();
            claims.handled.retain(|session, at| {
                !active.contains(session.as_str()) && now.duration_since(*at) < ttl
            });
        }
        for session in expired {
            rd.storage.delete(&format!("{STREAMS_DIR}/{session}"))?;
        }
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.wake.halt();
    }
}

/// The store both ends can reach on one filesystem: the same folder an `xray` process would poll, with every object committed by a temp-name move so a reader never sees half a segment.
pub(crate) struct Local {
    root: PathBuf,
}

static TEMP_MARK: AtomicU64 = AtomicU64::new(0);

impl Local {
    pub(crate) fn new(root: &str) -> io::Result<Self> {
        let path = PathBuf::from(root);
        create_dir(&path)?;
        Ok(Self { root: path })
    }

    /// An absolute clean of an object name: empty and `.` segments drop, a `..` pops what it can, and the result can never name its way out of the folder.
    fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        let mut parts: Vec<&str> = Vec::new();
        for part in name.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        let Some(last) = parts.last() else {
            return Err(carrier_error(format!("invalid object name: {name}")));
        };
        if last.starts_with(TEMP_PREFIX) {
            return Err(carrier_error(format!("reserved object name: {name}")));
        }
        let mut path = self.root.clone();
        for part in parts {
            path.push(part);
        }
        Ok(path)
    }
}

/// A folder with the reference's permissions: readable by nobody but the process that polls it.
fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

impl Storage for Local {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let full = self.resolve(name)?;
        let dir = full
            .parent()
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        create_dir(&dir)?;
        let temp = dir.join(format!(
            "{TEMP_PREFIX}{}-{}",
            std::process::id(),
            TEMP_MARK.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        file.write_all(data)?;
        let committed = std::fs::rename(&temp, &full);
        if committed.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        committed
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.resolve(name)?)
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let path = self.resolve(name)?;
        let result = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match result {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let Ok(readable) = std::fs::read_dir(self.resolve(prefix)?) else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for name in readable
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
        {
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            found.push(Entry { name, inline: None });
        }
        Ok(found)
    }

    fn threaded(&self) -> bool {
        false
    }
}

/// The separator a flattened name uses where the folder step would be a slash.
const FLAT_SEP: &str = "~";
const DRIVE_INLINE_LIMIT: usize = 12_000;
const DRIVE_BOUNDARY: &str = "xdrive-boundary";
const DRIVE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DRIVE_FILES_URL: &str = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD_URL: &str =
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name";
const MAX_ATTEMPTS: usize = 8;
const DEFAULT_INFLIGHT: usize = 32;
const MAX_INFLIGHT: usize = 256;
const SERVICE_TIMEOUT: Duration = Duration::from_secs(60);
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(8);
const LINE_CAP: usize = 8 * 1024;
const HEAD_CAP: usize = 16 * 1024;
const TOKEN_CAP: usize = 1 << 20;
const TOKEN_SKEW: Duration = Duration::from_secs(60);
const TOKEN_LIFE: Duration = Duration::from_secs(3600);
const DRIVE_PAGE_SIZE: usize = 1000;

/// The folder steps an object name carries, replaced by `~` for a service that keeps names in one flat listing.
fn flatten(name: &str) -> String {
    name.replace('/', FLAT_SEP)
}

/// Whether one name sits under the folder prefix a listing was asked for.
fn under<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    name.strip_prefix(prefix)
        .and_then(|rest| (!rest.is_empty()).then_some(rest))
}

/// The first step of a flattened name, which is what a listing of one folder level reports.
fn first_step(rest: &str) -> &str {
    rest.split(FLAT_SEP).next().unwrap_or(rest)
}

/// A bound on how many requests one service answers at once, which is also its connection cap: a lane is held for exactly as long as its holder lives.
struct Gate {
    left: Mutex<usize>,
    room: Condvar,
}

/// The borrowed slot; dropping it is the release.
struct Hold<'a> {
    gate: &'a Gate,
}

impl Gate {
    fn new(cap: usize) -> Self {
        Self {
            left: Mutex::new(cap),
            room: Condvar::new(),
        }
    }

    /// Wait for a slot, re-checking on a timer so a stuck holder still names itself in the census.
    fn hold(&self) -> Hold<'_> {
        let mut left = self.left.lock().unwrap_or_else(PoisonError::into_inner);
        while *left == 0 {
            census!("xdrive-gate", crate::census::NO_FD, Some(DRAIN_WAIT));
            let (guard, _timeout) = self
                .room
                .wait_timeout(left, DRAIN_WAIT)
                .unwrap_or_else(PoisonError::into_inner);
            left = guard;
        }
        *left -= 1;
        Hold { gate: self }
    }
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        let mut left = self
            .gate
            .left
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *left += 1;
        self.gate.room.notify_one();
    }
}

/// The stream one service lane rides: plain to a loopback fake, TLS to a real origin.
enum Kind {
    Plain(Connection),
    Secure(RustlsProvider<Connection>),
}

impl Read for Kind {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Secure(tls) => tls.read(buf),
        }
    }
}

impl Write for Kind {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Secure(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Secure(tls) => tls.flush(),
        }
    }
}

/// One kept-alive exchange, with the read buffer the lane keeps warm so the next reply costs no allocation and bytes that arrive past an answer are still there for it.
struct Lane {
    kind: Kind,
    buf: Vec<u8>,
    at: usize,
}

/// A reply and whether its lane can be kept: a peer that said `close`, or that ended the body at EOF, has nothing left to answer.
struct Answer {
    status: u16,
    body: Vec<u8>,
    kept: bool,
}

impl Lane {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            buf: Vec::with_capacity(crate::proxy::READ_SLICE),
            at: 0,
        }
    }

    /// At least one unread byte in the buffer, or zero once the peer has said it is done.
    fn ready(&mut self) -> io::Result<usize> {
        while self.at >= self.buf.len() {
            self.settle();
            if crate::proxy::read_into_tail(&mut self.kind, &mut self.buf)? == 0 {
                return Ok(0);
            }
        }
        Ok(self.buf.len() - self.at)
    }

    /// Move the consumed prefix out of the way without moving the unread tail.
    fn settle(&mut self) {
        if self.at >= self.buf.len() {
            self.buf.clear();
            self.at = 0;
        }
    }

    /// One `CRLF`-terminated line as a slice of the lane's own buffer: a head is read out of the buffer it arrived in, and the bytes past the line stay there for the next one.
    fn line(&mut self) -> io::Result<&[u8]> {
        loop {
            if let Some(step) = self.buf[self.at..].iter().position(|byte| *byte == b'\n') {
                let start = self.at;
                let stop = start + step;
                let end = (stop > start && self.buf[stop - 1] == b'\r').then_some(stop - 1);
                self.at = stop + 1;
                return Ok(&self.buf[start..end.unwrap_or(stop)]);
            }
            if self.ready()? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "the service ended the head",
                ));
            }
            if self.buf.len() - self.at > LINE_CAP {
                return Err(carrier_error("a service head line is too long"));
            }
        }
    }

    /// Exactly `want` body bytes appended to `out`, the chunked framing of a service that has none left being the only thing that ends the read early.
    fn append_body(&mut self, want: usize, out: &mut Vec<u8>) -> io::Result<()> {
        let stop = out.len() + want;
        while out.len() < stop {
            if self.ready()? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "the service ended the body early",
                ));
            }
            let take = (stop - out.len()).min(self.buf.len() - self.at);
            out.extend_from_slice(&self.buf[self.at..self.at + take]);
            self.at += take;
            self.settle();
        }
        Ok(())
    }

    /// Everything the peer has left to say, which is a reply only a `close`ing service can give.
    fn read_to_eof(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        while self.ready()? > 0 {
            out.extend_from_slice(&self.buf[self.at..]);
            self.at = self.buf.len();
        }
        Ok(())
    }

    /// The request, then the answer; `header_only` is a `HEAD`, whose declared length never arrives as bytes.
    fn exchange(
        &mut self,
        head: &[u8],
        body: Option<&[u8]>,
        header_only: bool,
        limit: Option<usize>,
    ) -> io::Result<Answer> {
        self.buf.clear();
        self.at = 0;
        self.kind.write_all(head)?;
        if let Some(payload) = body {
            self.kind.write_all(payload)?;
        }
        self.kind.flush()?;
        self.reply(header_only, limit)
    }

    fn reply(&mut self, header_only: bool, limit: Option<usize>) -> io::Result<Answer> {
        let first = self.line()?;
        let mut counted = first.len();
        let status =
            status_of(first).ok_or_else(|| carrier_error("a service head has no status"))?;
        let mut transfer = false;
        let mut length = None;
        let mut closing = false;
        loop {
            let line = self.line()?;
            counted += line.len();
            if counted > HEAD_CAP {
                return Err(carrier_error("the service head is too long"));
            }
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            let name = String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase();
            let value = String::from_utf8_lossy(&line[colon + 1..])
                .trim()
                .to_owned();
            match name.as_str() {
                "content-length" if !transfer => {
                    length = value.parse::<usize>().ok().or(length);
                }
                "transfer-encoding" => {
                    transfer |= value.to_ascii_lowercase().contains("chunked");
                }
                "connection" => {
                    closing |= value.to_ascii_lowercase().contains("close");
                }
                _ => {}
            }
        }
        if header_only || matches!(status, 204 | 304) {
            return Ok(Answer {
                status,
                body: Vec::new(),
                kept: !closing,
            });
        }
        let mut body = Vec::new();
        let kept = if transfer {
            self.chunks(&mut body, limit)?;
            !closing
        } else if let Some(want) = length {
            guard(want, limit)?;
            self.append_body(want, &mut body)?;
            !closing
        } else {
            self.read_to_eof(&mut body)?;
            false
        };
        Ok(Answer { status, body, kept })
    }

    /// A chunked body: the framing read one chunk at a time, so a chunk boundary is never a copy boundary.
    fn chunks(&mut self, out: &mut Vec<u8>, limit: Option<usize>) -> io::Result<()> {
        loop {
            let line = self.line()?;
            let Some(want) = chunk_size(line) else {
                return Err(carrier_error("the service framed a chunk badly"));
            };
            if want == 0 {
                while !self.line()?.is_empty() {}
                return Ok(());
            }
            guard(out.len() + want, limit)?;
            self.append_body(want, out)?;
            self.line()?;
        }
    }
}

/// A declared length the caller will not let the store spend.
fn guard(want: usize, limit: Option<usize>) -> io::Result<()> {
    if limit.is_some_and(|cap| want > cap) {
        return Err(carrier_error(format!(
            "the service declared {want} bytes past its limit"
        )));
    }
    Ok(())
}

/// The status out of `HTTP/1.1 200 OK`.
fn status_of(line: &[u8]) -> Option<u16> {
    let mut parts = line.split(|byte| *byte == b' ');
    let version = parts.next()?;
    if !version.starts_with(b"HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    let text = String::from_utf8_lossy(code);
    (text.len() == 3)
        .then(|| text.parse::<u16>().ok())
        .flatten()
}

/// A chunk's hex length, with its extension dropped.
fn chunk_size(line: &[u8]) -> Option<usize> {
    let hex = line
        .split(|byte| *byte == b';')
        .next()
        .map_or("", |part| std::str::from_utf8(part).unwrap_or(""));
    usize::from_str_radix(hex.trim(), 16).ok()
}

/// Where one service url says to go: the authority for the `Host` header, the path and query for the request line.
#[derive(Debug)]
struct Target {
    secure: bool,
    host: String,
    port: u16,
    path: String,
}

impl Target {
    fn parse(url: &str) -> Option<Self> {
        let (secure, rest) = url
            .strip_prefix("https://")
            .map(|rest| (true, rest))
            .or_else(|| url.strip_prefix("http://").map(|rest| (false, rest)))?;
        let cut = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = (&rest[..cut], &rest[cut..]);
        let host = match authority.strip_prefix('[') {
            Some(bracketed) => bracketed.split(']').next()?,
            None => authority
                .rsplit_once(':')
                .map_or(authority, |(host, _)| host),
        };
        let port = match authority.strip_prefix('[') {
            Some(bracketed) => bracketed
                .split(']')
                .nth(1)
                .and_then(|rest| rest.strip_prefix(':'))
                .and_then(|digits| digits.parse().ok()),
            None if authority.contains(':') => authority
                .rsplit_once(':')
                .and_then(|(_, digits)| digits.parse().ok()),
            None => None,
        }
        .unwrap_or(if secure { 443 } else { 80 });
        if host.is_empty() {
            return None;
        }
        Some(Self {
            secure,
            host: host.to_owned(),
            port,
            path: if tail.is_empty() {
                "/".to_owned()
            } else {
                tail.to_owned()
            },
        })
    }

    /// The bucket this lane belongs to: a scheme, a host and a port, with the fronting the transport arms kept out of it because a lane to a front speaks for the origin.
    fn origin(&self) -> String {
        format!(
            "{}:{}:{}",
            if self.secure { "https" } else { "http" },
            self.host,
            self.port
        )
    }

    /// The `Host` header, whose port only shows when it is not the scheme's own.
    fn authority(&self) -> String {
        let default = self.port == if self.secure { 443 } else { 80 };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// The request head, with the payload deliberately left out of it: a segment is written behind the head instead of copied into it, which is the one thing a Go `bytes.Reader` gets for free and a merged buffer would not.
fn request_head(
    method: &str,
    authority: &str,
    path: &str,
    headers: &[(&str, &str)],
    length: Option<usize>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + path.len());
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(authority.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some(want) = declared_length(method, length) {
        let _ = write!(out, "Content-Length: {want}\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The length line the service's own http library would write: a body always declares, and a bodyless `POST`, `PUT` or `PATCH` declares zero while a `GET`, `HEAD` or `DELETE` says nothing at all.
fn declared_length(method: &str, length: Option<usize>) -> Option<usize> {
    length.or_else(|| match method {
        "POST" | "PUT" | "PATCH" => Some(0),
        _ => None,
    })
}

/// The pooled `HTTP/1.1` lanes one object service shares: a lane per in-flight request, kept for the next rather than handshaken again.
pub(crate) struct Http {
    tls: Option<Arc<TlsConfig>>,
    front: Option<(String, u16)>,
    gate: Gate,
    lanes: Mutex<HashMap<String, VecDeque<Lane>>>,
}

impl Http {
    fn new(tls: Option<Arc<TlsConfig>>, front: Option<(String, u16)>, cap: usize) -> Arc<Self> {
        Arc::new(Self {
            tls,
            front,
            gate: Gate::new(cap),
            lanes: Mutex::new(HashMap::new()),
        })
    }

    /// One request and its answer, retried by the caller's ladder: a lane taken from the pool gets one second try on a fresh one, because a server that timed out an idle connection is the ordinary reason a first try fails.
    pub(crate) fn ask(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        limit: Option<usize>,
    ) -> io::Result<(u16, Vec<u8>)> {
        let target = Target::parse(url)
            .ok_or_else(|| carrier_error(format!("the service url {url} names no origin")))?;
        let head = request_head(
            method,
            &target.authority(),
            &target.path,
            headers,
            body.map(<[u8]>::len),
        );
        let key = target.origin();
        let _hold = self.gate.hold();
        let header_only = method.eq_ignore_ascii_case("HEAD");
        let pooled = self.borrow(&key);
        if let Some(mut lane) = pooled {
            return match lane.exchange(&head, body, header_only, limit) {
                Ok(answer) => {
                    self.finish(&key, lane, &answer);
                    Ok((answer.status, answer.body))
                }
                Err(first) => {
                    let mut again = self.dial(&target)?;
                    let answer =
                        again
                            .exchange(&head, body, header_only, limit)
                            .map_err(|why| {
                                carrier_error(format!(
                                    "the service lane failed twice: {why}; first {first}"
                                ))
                            })?;
                    self.finish(&key, again, &answer);
                    Ok((answer.status, answer.body))
                }
            };
        }
        let mut lane = self.dial(&target)?;
        let answer = lane.exchange(&head, body, header_only, limit)?;
        self.finish(&key, lane, &answer);
        Ok((answer.status, answer.body))
    }

    fn borrow(&self, key: &str) -> Option<Lane> {
        let mut lanes = self.lanes.lock().unwrap_or_else(PoisonError::into_inner);
        let queue = lanes.get_mut(key)?;
        let lane = queue.pop_front();
        if queue.is_empty() {
            lanes.remove(key);
        }
        lane
    }

    fn finish(&self, key: &str, lane: Lane, answer: &Answer) {
        if !answer.kept {
            return;
        }
        self.lanes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.to_owned())
            .or_default()
            .push_back(lane);
    }

    /// Dial the fronting the outbound names, or the url's own origin, and put TLS on it when the url asks for that scheme.
    fn dial(&self, target: &Target) -> io::Result<Lane> {
        let (host, port) = match &self.front {
            Some((front, 0)) => (front.clone(), target.port),
            Some((front, at)) => (front.clone(), *at),
            None => (target.host.clone(), target.port),
        };
        let peer = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|why| carrier_error(format!("resolve {host}: {why}")))?
            .next()
            .ok_or_else(|| carrier_error(format!("{host} resolves to nothing")))?;
        let stream = crate::conn::dial_tcp(&peer, SERVICE_TIMEOUT)
            .map_err(|why| carrier_error(format!("connect {peer}: {why}")))?;
        let _ = stream.set_read_timeout(Some(SERVICE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SERVICE_TIMEOUT));
        if !target.secure {
            return Ok(Lane::new(Kind::Plain(stream)));
        }
        let mut cfg = self.tls.as_deref().cloned().unwrap_or_default();
        if cfg.server_name.is_empty() {
            cfg.server_name = target.host.clone();
        }
        if cfg.roots.is_empty() {
            cfg.roots = crate::quic::system_roots();
        }
        let mut tls = RustlsProvider::connect(&cfg, stream)
            .map_err(|why| carrier_error(format!("tls {}: {why}", target.host)))?;
        tls.handshake()
            .map_err(|why| carrier_error(format!("handshake {}: {why}", target.host)))?;
        Ok(Lane::new(Kind::Secure(tls)))
    }
}

/// The bearer both `HTTP` services carry, with the moment it stops being worth sending.
struct Token {
    value: String,
    until: Instant,
}

impl Default for Token {
    fn default() -> Self {
        Self {
            value: String::new(),
            until: Instant::now(),
        }
    }
}

impl Token {
    fn fresh(&self, now: Instant) -> Option<&str> {
        (!self.value.is_empty() && now < self.until).then(|| self.value.as_str())
    }

    /// The lifetime the service stated, less the minute it may be wrong by, and never less than zero.
    fn set(&mut self, value: String, life: Duration) {
        let kept = (life > TOKEN_SKEW)
            .then(|| life - TOKEN_SKEW)
            .unwrap_or_default();
        self.value = value;
        self.until = Instant::now() + kept;
    }
}

/// A byte below `top`, the way the reference jitters a backoff: no entropy is a roll of zero, which is the smallest wait rather than a failure.
fn roll(top: u64) -> u64 {
    if top == 0 {
        return 0;
    }
    let mut raw = [0u8; 8];
    getrandom::getrandom(&mut raw).map_or(0, |_| u64::from_le_bytes(raw) % top)
}

/// Half the wait kept, half of it rolled, so a whole fleet of sessions does not poll one store in lockstep.
fn jitter(backoff: Duration) -> Duration {
    let half = backoff / 2;
    let room = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
    if room == 0 {
        return backoff;
    }
    half + Duration::from_nanos(roll(room))
}

/// One ask, either answered or worth another attempt with the reason it was not.
enum Control {
    Done(io::Result<(u16, Vec<u8>)>),
    Again(String),
}

/// The reference's attempt ladder: eight tries, the wait doubling from 200 ms to 8 s with half of each rung jittered.
fn retried(mut ask: impl FnMut() -> Control) -> io::Result<(u16, Vec<u8>)> {
    let mut backoff = INITIAL_BACKOFF;
    let mut last = String::from("the service never answered");
    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(jitter(backoff));
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        match ask() {
            Control::Done(answer) => return answer,
            Control::Again(why) => last = why,
        }
    }
    Err(carrier_error(last))
}

/// A value byte that needs quoting in a query: the unreserved set and nothing else.
fn reserved(byte: u8) -> bool {
    !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// One byte as the percent-escape the services' url library writes: uppercase, two digits.
fn pct(out: &mut String, byte: u8) {
    out.push('%');
    out.push(UPPER_HEX[(byte >> 4) as usize] as char);
    out.push(UPPER_HEX[(byte & 0x0f) as usize] as char);
}

/// `url.Values.Encode` of a list of pairs: keys sorted, every value percent-quoted with a space as `+`.
fn query(pairs: &[(&str, &str)]) -> String {
    let mut sorted = pairs.to_vec();
    sorted.sort_unstable();
    let mut out = String::new();
    for (index, (key, value)) in sorted.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        for byte in value.as_bytes() {
            match byte {
                b' ' => out.push('+'),
                other if reserved(*other) => pct(&mut out, *other),
                other => out.push(*other as char),
            }
        }
    }
    out
}

/// A `'`-quoted value inside a Drive query, with its own quotes and backslashes escaped.
fn quoted(value: &str) -> String {
    value.replace('\\', r"\\").replace('\'', r"\'")
}

/// One step of a dotted answer path.
fn walk<'a>(node: &'a Json, path: &str) -> Option<&'a Json> {
    let mut at = node;
    for key in path.split('.') {
        at = at.get(key)?;
    }
    Some(at)
}

fn text_of(node: &Json, name: &str) -> String {
    node.get(name)
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

fn flag_of(node: &Json, name: &str) -> bool {
    node.get(name).and_then(Json::as_bool).unwrap_or(false)
}

/// A `map[string]string` config field, in the order the config wrote it.
fn pairs_of(node: &Json, name: &str) -> Vec<(String, String)> {
    let Some(Json::Obj(items)) = node.get(name) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_owned()))
        .collect()
}

fn numbers_of(node: &Json, name: &str) -> Vec<u32> {
    let Some(items) = node.get(name).and_then(Json::as_arr) else {
        return Vec::new();
    };
    items.iter().filter_map(Json::as_u32).collect()
}

/// The variables a template name, in one pass over it instead of one pass per variable.
#[derive(Clone)]
struct Vars(Vec<(String, String)>);

impl Vars {
    fn new(folder: &str, secrets: &[String]) -> Self {
        let mut out = vec![("folder".to_owned(), folder.to_owned())];
        for (index, secret) in secrets.iter().enumerate() {
            out.push((format!("secret{index}"), secret.clone()));
        }
        Self(out)
    }

    fn set(&mut self, key: &str, value: String) {
        if let Some(found) = self.0.iter_mut().find(|(name, _)| name == key) {
            found.1 = value;
            return;
        }
        self.0.push((key.to_owned(), value));
    }

    /// Every `{name}` this holds, and nothing else: an unknown brace is left as the config wrote it, which is what the reference's per-key replace leaves.
    fn sub(&self, text: &str) -> String {
        if !text.contains('{') {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find('{') {
            out.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            let Some(cut) = after.find('}') else {
                out.push('{');
                rest = after;
                continue;
            };
            let name = &after[..cut];
            match self.0.iter().find(|(key, _)| key == name) {
                Some((_, value)) => out.push_str(value),
                None => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = &after[cut + 1..];
        }
        out.push_str(rest);
        out
    }
}

/// One templated operation: `GET` when it names no method, and no body until it writes one.
struct Op {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
    names: String,
}

fn op_of(node: &Json, name: &str) -> Op {
    let empty = Json::Null;
    let at = node.get(name).unwrap_or(&empty);
    Op {
        method: text_of(at, "method"),
        url: text_of(at, "url"),
        headers: pairs_of(at, "headers"),
        body: text_of(at, "body"),
        names: text_of(at, "namesRegex"),
    }
}

/// Which answers the templated service wants asked again.
struct Retry {
    status: Vec<u32>,
    reason: String,
}

/// How a templated service is proved: nothing, a header the config writes, a `Basic` pair, or an `OAuth2` token it fetches first.
struct Auth {
    kind: String,
    headers: Vec<(String, String)>,
    username: String,
    password: String,
    token_url: String,
    form: Vec<(String, String)>,
    token_path: String,
    expiry_path: String,
}

/// A JSON-described object service: four operations spelled as templates over `{folder}`, `{secret0}`, `{name}`, `{prefix}` and `{data}`, so any store that speaks `HTTP` can carry a session.
pub(crate) struct Template {
    http: Arc<Http>,
    folder: String,
    secrets: Vec<String>,
    flatten: bool,
    names: regex::Regex,
    auth: Auth,
    put: Op,
    get: Op,
    drop: Op,
    list: Op,
    retry: Retry,
    token: Mutex<Token>,
}

impl Template {
    fn build(settings: &Settings, http: Arc<Http>) -> io::Result<Self> {
        let root = settings
            .template
            .as_ref()
            .ok_or_else(|| carrier_error("the template service has no template"))?;
        let put = op_of(root, "put");
        let get = op_of(root, "get");
        let drop = op_of(root, "delete");
        let list = op_of(root, "list");
        if put.url.is_empty() || get.url.is_empty() || drop.url.is_empty() || list.url.is_empty() {
            return Err(carrier_error(
                "the template needs put, get, list and delete operations",
            ));
        }
        if list.names.is_empty() {
            return Err(carrier_error("the template list needs a namesRegex"));
        }
        let names = regex::Regex::new(&list.names)
            .map_err(|why| carrier_error(format!("bad namesRegex: {why}")))?;
        if names.captures_len() < 2 {
            return Err(carrier_error("namesRegex needs one capture group"));
        }
        let retry = root.get("retry").unwrap_or(&Json::Null);
        let auth = root.get("auth").unwrap_or(&Json::Null);
        Ok(Self {
            http,
            folder: settings.remote_folder.clone(),
            secrets: settings.secrets.clone(),
            flatten: flag_of(root, "flatten"),
            names,
            auth: Auth {
                kind: text_of(auth, "type"),
                headers: pairs_of(auth, "header"),
                username: text_of(auth, "username"),
                password: text_of(auth, "password"),
                token_url: text_of(auth, "tokenUrl"),
                form: pairs_of(auth, "form"),
                token_path: text_of(auth, "tokenPath"),
                expiry_path: text_of(auth, "expiryPath"),
            },
            put,
            get,
            drop,
            list,
            retry: Retry {
                status: numbers_of(retry, "status"),
                reason: text_of(retry, "rateReason"),
            },
            token: Mutex::new(Token::default()),
        })
    }

    fn stored(&self, name: &str) -> String {
        if self.flatten {
            flatten(name)
        } else {
            name.to_owned()
        }
    }

    fn base(&self) -> Vars {
        Vars::new(&self.folder, &self.secrets)
    }

    /// The answer's status against the config's list, and the `403` whose body says the reason the config named.
    fn retryable(&self, status: u16, payload: &[u8]) -> bool {
        if self.retry.status.contains(&u32::from(status)) {
            return true;
        }
        if status != 403 || self.retry.reason.is_empty() {
            return false;
        }
        let Ok(answer) = crate::json::parse(&String::from_utf8_lossy(payload)) else {
            return false;
        };
        answer
            .get(&self.retry.reason)
            .and_then(Json::as_str)
            .is_some_and(|reason| !reason.is_empty())
    }

    fn access(&self, vars: &mut Vars) -> io::Result<String> {
        let now = Instant::now();
        if let Some(found) = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fresh(now)
            .map(str::to_owned)
        {
            return Ok(found);
        }
        let mut form = String::new();
        for (index, (key, value)) in self.auth.form.iter().enumerate() {
            if index > 0 {
                form.push('&');
            }
            let _ = write!(form, "{key}={}", vars.sub(value));
        }
        let (status, payload) = self.http.ask(
            "POST",
            &self.auth.token_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(form.as_bytes()),
            Some(TOKEN_CAP),
        )?;
        if status != 200 {
            return Err(carrier_error(format!(
                "the token endpoint answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the token answer is not json: {why}")))?;
        let path = if self.auth.token_path.is_empty() {
            "access_token"
        } else {
            &self.auth.token_path
        };
        let value = walk(&answer, path)
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| carrier_error(format!("the token answer has no token at {path}")))?
            .to_owned();
        let life = (!self.auth.expiry_path.is_empty())
            .then(|| walk(&answer, &self.auth.expiry_path).and_then(Json::as_u32))
            .flatten()
            .filter(|seconds| *seconds > 0)
            .map_or(TOKEN_LIFE, |seconds| {
                Duration::from_secs(u64::from(seconds))
            });
        let mut token = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        token.set(value.clone(), life);
        Ok(value)
    }

    /// The headers the credential needs, with the `oauth2` token put where its template can reach it.
    fn headers(&self, vars: &mut Vars) -> io::Result<Vec<(String, String)>> {
        match self.auth.kind.as_str() {
            "" | "none" => Ok(Vec::new()),
            "static" => Ok(self
                .auth
                .headers
                .iter()
                .map(|(key, value)| (key.clone(), vars.sub(value)))
                .collect()),
            "oauth2" => {
                let token = self.access(vars)?;
                vars.set("token", token);
                Ok(self
                    .auth
                    .headers
                    .iter()
                    .map(|(key, value)| (key.clone(), vars.sub(value)))
                    .collect())
            }
            "basic" => {
                let pair = format!(
                    "{}:{}",
                    vars.sub(&self.auth.username),
                    vars.sub(&self.auth.password)
                );
                Ok(vec![(
                    "Authorization".to_owned(),
                    format!("Basic {}", ferrox_core::b64::encode(pair.as_bytes())),
                )])
            }
            other => Err(carrier_error(format!("unsupported auth type: {other}"))),
        }
    }

    fn do_op(&self, op: &Op, vars: &mut Vars, body: Option<&[u8]>) -> io::Result<(u16, Vec<u8>)> {
        let method = if op.method.is_empty() {
            "GET"
        } else {
            &op.method
        };
        retried(|| {
            let mut slots = vars.clone();
            let mut owned: Vec<(String, String)> = match self.headers(&mut slots) {
                Ok(headers) => headers,
                Err(why) => return Control::Again(why.to_string()),
            };
            owned.extend(
                op.headers
                    .iter()
                    .map(|(key, value)| (key.clone(), slots.sub(value))),
            );
            let url = slots.sub(&op.url);
            let sent: Vec<(&str, &str)> = owned
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            let answer = self.http.ask(method, &url, &sent, body, None);
            let (status, payload) = match answer {
                Ok(answer) => answer,
                Err(why) => return Control::Again(format!("request failed: {why}")),
            };
            if status == 401 && self.auth.kind == "oauth2" {
                self.token
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .value
                    .clear();
                return Control::Again("the service rejected the token".to_owned());
            }
            if self.retryable(status, &payload) {
                return Control::Again(format!("the service answered {status}"));
            }
            Control::Done(Ok((status, payload)))
        })
    }
}

impl Storage for Template {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let mut vars = self.base();
        vars.set("name", self.stored(name));
        let encoded: Vec<u8>;
        let payload: Option<&[u8]> = if self.put.body.is_empty() {
            (!data.is_empty()).then_some(data)
        } else {
            vars.set("data", ferrox_core::b64::encode(data));
            encoded = vars.sub(&self.put.body).into_bytes();
            Some(&encoded)
        };
        let (status, payload) = self.do_op(&self.put, &mut vars, payload)?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        Err(carrier_error(format!(
            "put of {name} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut vars = self.base();
        vars.set("name", self.stored(name));
        let (status, payload) = self.do_op(&self.get, &mut vars, None)?;
        if (200..300).contains(&status) {
            return Ok(payload);
        }
        if status == 404 {
            return Err(io::Error::from(ErrorKind::NotFound));
        }
        Err(carrier_error(format!(
            "get of {name} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let mut vars = self.base();
        vars.set("name", self.stored(name));
        let (status, payload) = self.do_op(&self.drop, &mut vars, None)?;
        if status == 404 || (200..300).contains(&status) {
            return Ok(());
        }
        Err(carrier_error(format!(
            "delete of {name} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let mut vars = self.base();
        let flat = self.stored(prefix);
        vars.set("prefix", flat.clone());
        let (status, payload) = self.do_op(&self.list, &mut vars, None)?;
        if status == 404 {
            return Ok(Vec::new());
        }
        if !(200..300).contains(&status) {
            return Err(carrier_error(format!(
                "list of {prefix} answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let text = String::from_utf8_lossy(&payload);
        if !self.flatten {
            return Ok(self
                .names
                .captures_iter(text.as_ref())
                .filter_map(|found| {
                    found.get(1).map(|at| Entry {
                        name: at.as_str().to_owned(),
                        inline: None,
                    })
                })
                .collect());
        }
        let mut out = Vec::new();
        let want = format!("{flat}{FLAT_SEP}");
        let mut seen: HashSet<String> = HashSet::new();
        for found in self.names.captures_iter(text.as_ref()) {
            let Some(at) = found.get(1).map(|at| at.as_str()) else {
                continue;
            };
            let Some(name) = under(at, &want) else {
                continue;
            };
            let step = first_step(name).to_owned();
            if seen.insert(step.clone()) {
                out.push(Entry {
                    name: step,
                    inline: None,
                });
            }
        }
        Ok(out)
    }
}

/// A file a Drive listing named, with the payload it carried alongside when the object was small enough to ride in the description.
struct Found {
    id: String,
    description: Option<Vec<u8>>,
}

/// Google Drive as an object store: a name becomes a file id, a small object rides base64 in the file's description, and a larger one its media.
pub(crate) struct Drive {
    http: Arc<Http>,
    folder: String,
    client_id: String,
    client_secret: String,
    refresh: String,
    token_url: String,
    files_url: String,
    upload_url: String,
    token: Mutex<Token>,
    ids: Mutex<HashMap<String, String>>,
}

impl Drive {
    fn build(settings: &Settings, http: Arc<Http>) -> io::Result<Self> {
        let [client_id, client_secret, refresh] = settings.secrets.as_slice() else {
            return Err(carrier_error(
                "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken",
            ));
        };
        if client_id.is_empty() || client_secret.is_empty() || refresh.is_empty() {
            return Err(carrier_error("a Google Drive secret is empty"));
        }
        Ok(Self {
            http,
            folder: settings.remote_folder.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            refresh: refresh.clone(),
            token_url: DRIVE_TOKEN_URL.to_owned(),
            files_url: DRIVE_FILES_URL.to_owned(),
            upload_url: DRIVE_UPLOAD_URL.to_owned(),
            token: Mutex::new(Token::default()),
            ids: Mutex::new(HashMap::new()),
        })
    }

    fn access(&self) -> io::Result<String> {
        let now = Instant::now();
        if let Some(found) = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fresh(now)
            .map(str::to_owned)
        {
            return Ok(found);
        }
        let form = query(&[
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("grant_type", "refresh_token"),
            ("refresh_token", &self.refresh),
        ]);
        let (status, payload) = self.http.ask(
            "POST",
            &self.token_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(form.as_bytes()),
            Some(TOKEN_CAP),
        )?;
        if status != 200 {
            return Err(carrier_error(format!(
                "the token endpoint answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the token answer is not json: {why}")))?;
        let value = answer
            .get("access_token")
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| carrier_error("the token endpoint returned no access token"))?
            .to_owned();
        let life = answer
            .get("expires_in")
            .and_then(Json::as_u32)
            .map_or(Duration::ZERO, |seconds| {
                Duration::from_secs(u64::from(seconds))
            });
        let mut token = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        token.set(value.clone(), life);
        Ok(value)
    }

    fn forget(&self, name: &str) {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
    }

    fn remember(&self, name: &str, id: &str) {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), id.to_owned());
    }

    fn cached(&self, name: &str) -> Option<String> {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    /// The `403` that is a rate limit rather than a refusal, which is the one a retry can outlast.
    fn rate_limited(payload: &[u8]) -> bool {
        let Ok(answer) = crate::json::parse(&String::from_utf8_lossy(payload)) else {
            return false;
        };
        let Some(error) = answer.get("error") else {
            return false;
        };
        if error
            .get("errors")
            .and_then(Json::as_arr)
            .unwrap_or(&[])
            .iter()
            .filter_map(|item| item.get("reason").and_then(Json::as_str))
            .any(|reason| {
                matches!(
                    reason,
                    "rateLimitExceeded" | "userRateLimitExceeded" | "sharingRateLimitExceeded"
                )
            })
        {
            return true;
        }
        error
            .get("status")
            .and_then(Json::as_str)
            .is_some_and(|status| status == "RESOURCE_EXHAUSTED")
    }

    fn ask(
        &self,
        method: &str,
        target: String,
        content: &str,
        body: Option<&[u8]>,
    ) -> io::Result<(u16, Vec<u8>)> {
        retried(|| {
            let token = match self.access() {
                Ok(token) => token,
                Err(why) => return Control::Again(why.to_string()),
            };
            let headers = vec![("Authorization", format!("Bearer {token}"))];
            let mut sent: Vec<(&str, &str)> = headers
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect();
            if !content.is_empty() {
                sent.push(("Content-Type", content));
            }
            let answer = self.http.ask(method, &target, &sent, body, None);
            let (status, payload) = match answer {
                Ok(answer) => answer,
                Err(why) => return Control::Again(format!("Drive request failed: {why}")),
            };
            if status == 401 {
                self.token
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .value
                    .clear();
                return Control::Again("Drive rejected the access token".to_owned());
            }
            if status == 403 && Self::rate_limited(&payload) {
                return Control::Again(format!(
                    "Drive is rate limiting: {}",
                    String::from_utf8_lossy(&payload)
                ));
            }
            if matches!(status, 429 | 500 | 502 | 503 | 504) {
                return Control::Again(format!(
                    "Drive answered {status}: {}",
                    String::from_utf8_lossy(&payload)
                ));
            }
            Control::Done(Ok((status, payload)))
        })
    }

    /// One page of a Drive listing, and every page after it, keeping the last answer for a name as the reference does.
    fn query(&self, condition: &str) -> io::Result<HashMap<String, Found>> {
        let mut found: HashMap<String, Found> = HashMap::new();
        let mut page = String::new();
        loop {
            let mut pairs = vec![
                (
                    "fields",
                    "nextPageToken,files(id,name,description)".to_owned(),
                ),
                ("includeItemsFromAllDrives", "true".to_owned()),
                ("pageSize", DRIVE_PAGE_SIZE.to_string()),
                (
                    "q",
                    format!(
                        "'{}' in parents and trashed = false and {condition}",
                        quoted(&self.folder)
                    ),
                ),
                ("supportsAllDrives", "true".to_owned()),
            ];
            if !page.is_empty() {
                pairs.push(("pageToken", page.clone()));
            }
            let owned: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect();
            let target = format!("{}?{}", self.files_url, query(&owned));
            let (status, payload) = self.ask("GET", target, "", None)?;
            if status != 200 {
                return Err(carrier_error(format!(
                    "Drive listing answered {status}: {}",
                    String::from_utf8_lossy(&payload)
                )));
            }
            let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
                .map_err(|why| carrier_error(format!("the Drive listing is not json: {why}")))?;
            for file in answer.get("files").and_then(Json::as_arr).unwrap_or(&[]) {
                let name = file.get("name").and_then(Json::as_str).unwrap_or("");
                let id = file.get("id").and_then(Json::as_str).unwrap_or("");
                if name.is_empty() || id.is_empty() {
                    continue;
                }
                let description = file
                    .get("description")
                    .and_then(Json::as_str)
                    .filter(|text| !text.is_empty())
                    .and_then(|text| ferrox_core::b64::decode(text.as_bytes()));
                self.remember(name, id);
                found.insert(
                    name.to_owned(),
                    Found {
                        id: id.to_owned(),
                        description,
                    },
                );
            }
            page = answer
                .get("nextPageToken")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned();
            if page.is_empty() {
                return Ok(found);
            }
        }
    }

    fn resolve(&self, flat: &str) -> io::Result<String> {
        if let Some(id) = self.cached(flat) {
            return Ok(id);
        }
        let found = self.query(&format!("name = '{}'", quoted(flat)))?;
        found
            .get(flat)
            .map(|file| file.id.clone())
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))
    }

    /// The object as Drive stores it: small enough it rides base64 in the metadata, otherwise the metadata and the payload go out as one multipart body.
    fn write(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let flat = flatten(name);
        let inline = data.len() <= DRIVE_INLINE_LIMIT;
        // The keys in the order the reference's map marshaller writes them, so the metadata body is byte for byte the same.
        let mut pairs = Vec::with_capacity(3);
        if inline {
            pairs.push((
                "description".to_owned(),
                Json::Str(ferrox_core::b64::encode(data)),
            ));
        }
        pairs.push(("name".to_owned(), Json::Str(flat.clone())));
        pairs.push((
            "parents".to_owned(),
            Json::Arr(vec![Json::Str(self.folder.clone())]),
        ));
        let mut text = String::new();
        crate::json::write(&Json::Obj(pairs), &mut text);
        let (target, content, body) = if inline {
            (
                format!("{}?fields=id", self.files_url),
                "application/json; charset=UTF-8".to_owned(),
                text.into_bytes(),
            )
        } else {
            let mut body = Vec::with_capacity(text.len() + data.len() + 128);
            let _ = write!(
                body,
                "--{DRIVE_BOUNDARY}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            );
            body.extend_from_slice(text.as_bytes());
            let _ = write!(
                body,
                "\r\n--{DRIVE_BOUNDARY}\r\nContent-Type: application/octet-stream\r\n\r\n"
            );
            body.extend_from_slice(data);
            let _ = write!(body, "\r\n--{DRIVE_BOUNDARY}--\r\n");
            (
                self.upload_url.clone(),
                format!("multipart/related; boundary={DRIVE_BOUNDARY}"),
                body,
            )
        };
        let (status, payload) = self.ask("POST", target, &content, Some(&body))?;
        if status != 200 {
            return Err(carrier_error(format!(
                "Drive upload of {name} answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the Drive upload answer is not json: {why}")))?;
        if let Some(id) = answer
            .get("id")
            .and_then(Json::as_str)
            .filter(|id| !id.is_empty())
        {
            self.remember(&flat, id);
        }
        Ok(())
    }

    fn remove(&self, flat: &str, id: &str) -> io::Result<()> {
        let target = format!(
            "{}/{id}?supportsAllDrives=true",
            self.files_url,
            id = path_escape(id)
        );
        let (status, payload) = self.ask("DELETE", target, "", None)?;
        self.forget(flat);
        if matches!(status, 200 | 204 | 404) {
            return Ok(());
        }
        Err(carrier_error(format!(
            "Drive deletion of {flat} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    /// The base64 a small object rode in, which is what a `0`-length media read means.
    fn inline(&self, id: &str) -> io::Result<Vec<u8>> {
        let target = format!(
            "{}/{id}?fields=description&supportsAllDrives=true",
            self.files_url,
            id = path_escape(id)
        );
        let (status, payload) = self.ask("GET", target, "", None)?;
        if status != 200 {
            return Err(carrier_error(format!(
                "Drive answered {status} for inline data: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the inline data is not json: {why}")))?;
        let description = answer
            .get("description")
            .and_then(Json::as_str)
            .unwrap_or("");
        if description.is_empty() {
            return Ok(Vec::new());
        }
        ferrox_core::b64::decode(description.as_bytes())
            .ok_or_else(|| carrier_error("the inline data is not valid base64"))
    }
}

/// The way a path segment quotes an id: every byte outside the unreserved set, uppercase.
fn path_escape(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for byte in id.as_bytes() {
        if reserved(*byte) {
            pct(&mut out, *byte);
        } else {
            out.push(*byte as char);
        }
    }
    out
}

impl Storage for Drive {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        self.write(name, data)
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let flat = flatten(name);
        let id = self.resolve(&flat)?;
        let target = format!(
            "{}/{id}?alt=media&supportsAllDrives=true",
            self.files_url,
            id = path_escape(&id)
        );
        let (status, payload) = self.ask("GET", target, "", None)?;
        match status {
            200 if !payload.is_empty() => Ok(payload),
            200 => self.inline(&id),
            404 => {
                self.forget(&flat);
                Err(io::Error::from(ErrorKind::NotFound))
            }
            other => Err(carrier_error(format!(
                "Drive download of {name} answered {other}: {}",
                String::from_utf8_lossy(&payload)
            ))),
        }
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let flat = flatten(name);
        match self.resolve(&flat) {
            Ok(id) => self.remove(&flat, &id)?,
            Err(why) if why.kind() == ErrorKind::NotFound => {}
            Err(why) => return Err(why),
        }
        let children = self.query(&format!(
            "name contains '{}'",
            quoted(&format!("{flat}{FLAT_SEP}"))
        ))?;
        for (child, file) in children {
            self.remove(&child, &file.id)?;
        }
        Ok(())
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let flat = format!("{}{FLAT_SEP}", flatten(prefix));
        let found = self.query(&format!("name contains '{}'", quoted(&flat)))?;
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for (name, file) in found {
            let Some(rest) = under(&name, &flat) else {
                continue;
            };
            let direct = !rest.contains(FLAT_SEP);
            let step = first_step(rest).to_owned();
            if !seen.insert(step.clone()) {
                continue;
            }
            out.push(Entry {
                inline: direct.then_some(file.description).flatten(),
                name: step,
            });
        }
        Ok(out)
    }
}

/// One store per folder, shared by every session that names it: a token cache and a file-id map are worth one per service, not one per stream.
static SHARED: LazyLock<Mutex<HashMap<String, Arc<dyn Storage>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The identity of one service's store, the way the reference keys it: the service, the folder, every secret, the transport's security, and the address it fronts through.
fn share_key(settings: &Settings, front: Option<(&str, u16)>) -> String {
    use sha2::Digest as _;
    let mut joined = vec![settings.service.clone(), settings.remote_folder.clone()];
    joined.extend_from_slice(&settings.secrets);
    joined.push(settings.security.clone());
    if let Some((host, port)) = front {
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        joined.push(if port == 0 {
            format!("tcp:{host}")
        } else {
            format!("tcp:{host}:{port}")
        });
    }
    joined.push(settings.template_text());
    let digest = sha2::Sha256::digest(joined.join("\0").as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The store the settings name, or the one an earlier session with the same settings already opened.
fn shared(
    settings: &Settings,
    front: Option<(&str, u16)>,
    cap: usize,
    build: impl FnOnce(&Settings, Arc<Http>) -> io::Result<Arc<dyn Storage>>,
) -> io::Result<Arc<dyn Storage>> {
    let key = share_key(settings, front);
    let mut pool = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(found) = pool.get(&key) {
        return Ok(Arc::clone(found));
    }
    let http = Http::new(
        settings.tls.clone(),
        front.map(|(host, port)| (host.to_owned(), port)),
        cap,
    );
    let made = build(settings, http)?;
    pool.insert(key, Arc::clone(&made));
    Ok(made)
}
