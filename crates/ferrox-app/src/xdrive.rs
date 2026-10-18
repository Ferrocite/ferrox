//! The xdrive carrier: one proxy stream carried by an object store both ends poll, so a lane survives addresses, restarts and rebindings by naming its segments in send order.

use crate::budgets::RELAY_POLL;
use crate::json::Json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
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
    pub template: String,
    pub params: Params,
}

impl Settings {
    /// An empty folder or an unknown service is a refusal by the caller, not a silent default: a carrier pointed at nowhere must not start polling.
    pub(crate) fn from_json(settings: Option<&Json>) -> Option<Self> {
        let drive = settings?.get("xdriveSettings")?;
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
            template: text("template"),
            remote_folder,
            service,
            secrets,
        })
    }

    /// The store this config names: one per folder for the services that carry a connection pool and an id cache, a fresh one for a folder on disk.
    pub(crate) fn store(&self) -> io::Result<Arc<dyn Storage>> {
        match self.service.as_str() {
            "local" => Ok(Arc::new(Local::new(&self.remote_folder)?)),
            _ => Err(io::Error::other(format!(
                "the {} service is not built here",
                self.service
            ))),
        }
    }
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
    digits(&name[..dot])?
        .parse()
        .ok()
        .map(|seq| (seq, suffix))
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
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// A failure the lane reports as its own end: an object the store refused to hold, a segment that never arrived while later ones did, or a peer that marked one lost.
fn carrier_error(message: String) -> io::Error {
    io::Error::other(message)
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
        self.queue.lock().unwrap_or_else(PoisonError::into_inner).shut = true;
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

/// A writer's tick: decide whether the buffer is ripe and, if it is, hand over a segment.
fn tick(ticker: &Ticker) {
    let mut pending = ticker.pending.lock().unwrap_or_else(PoisonError::into_inner);
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
            need.push((
                slot,
                format!("{}/{}", self.prefix, listed[index].name),
            ));
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
                let _ = std::thread::Builder::new().stack_size(WORKER_STACK).spawn_scoped(
                    scope,
                    move || {
                        let answer = storage.get(&name);
                        filled
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(slot, answer);
                    },
                );
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
    delay.checked_mul(2).unwrap_or(params.max_poll).min(params.max_poll)
}

/// The read half: a pump thread polling the store, and the mailbox the relay reads.
struct Reader {
    rd: Arc<Rd>,
    inbox: Arc<Inbox>,
    rest: Mutex<(Vec<u8>, usize)>,
}

impl Reader {
    fn new(storage: Arc<dyn Storage>, prefix: String, params: Arc<Params>, wake: Arc<Wake>) -> Self {
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
            reader: Arc::new(Reader::new(storage, read, Arc::clone(params), Arc::clone(&wake))),
            wake,
        }
    }

    /// End the stream: flush and mark the write log, then release every loop that waits on it.
    pub(crate) fn close(&self) -> io::Result<()> {
        let result = self.writer.close();
        self.wake.halt();
        self.reader.rd.discards.abort();
        result
    }

    /// Whether the lane is already ending, so a relay can stop polling a stream whose store refused a segment.
    pub(crate) fn stopped(&self) -> bool {
        self.wake.stopped()
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

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = self.writer.close();
        self.wake.halt();
        self.reader.rd.discards.abort();
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
type Accept = Arc<dyn Fn(Conn) + Send + Sync>;

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
            if unix_nanos(SystemTime::now()) - at > i64::try_from(rd.params.ttl.as_nanos()).unwrap_or(i64::MAX) {
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
        let dir = full.parent().map_or_else(|| self.root.clone(), Path::to_path_buf);
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
        for name in readable.flatten().filter_map(|entry| entry.file_name().into_string().ok()) {
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            found.push(Entry {
                name,
                inline: None,
            });
        }
        Ok(found)
    }

    fn threaded(&self) -> bool {
        false
    }
}
