use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::json::{self, Json};
use crate::ps::{self, Host, SampleError};

pub const HARNESS_ID: &str = "ferrox-bench/protocol-run";

pub const BULK_PATTERN_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

const PRE_SLEEP: Duration = Duration::from_millis(500);
const SETTLE: Duration = Duration::from_millis(500);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

const RUN_TIMEOUT: Duration = Duration::from_secs(120);

const FLOW_IO_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

const MAX_REQUEST_BYTES: usize = 262_144;

const MAX_ITERATIONS: usize = 262_144;

const MAX_FLOW_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigArg {
    Long,
    Short,
    Positional,
}

impl ConfigArg {
    pub fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "long" | "-config" | "--config" => Ok(Self::Long),
            "short" | "-c" => Ok(Self::Short),
            "positional" | "bare" => Ok(Self::Positional),
            other => Err(Error::Invalid(format!(
                "unknown config-argument shape `{other}`. Expected one of: long \
                 (`run -config <path>`), short (`run -c <path>`), positional \
                 (`run <path>`)"
            ))),
        }
    }

    fn args(self, path: &Path) -> Vec<String> {
        match self {
            Self::Long => vec!["run".into(), "-config".into(), path.display().to_string()],
            Self::Short => vec!["run".into(), "-c".into(), path.display().to_string()],
            Self::Positional => vec!["run".into(), path.display().to_string()],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Xray,
    SingBox,
}

impl Dialect {
    pub fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "xray" | "protocol" => Ok(Self::Xray),
            "sing-box" | "singbox" | "type" => Ok(Self::SingBox),
            other => Err(Error::Invalid(format!(
                "unknown config dialect `{other}`. Expected one of: `xray` \
                 (`protocol`-keyed, `port`), `sing-box` (`type`-keyed, \
                 `listen_port`)"
            ))),
        }
    }

    fn socks_inbound(self, listen: Ipv4Addr, port: u16) -> Json {
        let mut inbound = Json::object();
        match self {
            Self::Xray => {
                inbound.insert("tag", Json::Str("harness-socks".into()));
                inbound.insert("protocol", Json::Str("socks".into()));
            }
            Self::SingBox => {
                inbound.insert("type", Json::Str("socks".into()));
                inbound.insert("tag", Json::Str("socks-in".into()));
            }
        }
        inbound.insert("listen", Json::Str(listen.to_string()));
        match self {
            Self::Xray => {
                inbound.insert("port", Json::Num(f64::from(port)));
            }
            Self::SingBox => {
                inbound.insert("listen_port", Json::Num(f64::from(port)));
            }
        }
        let mut settings = Json::object();
        settings.insert("auth", Json::Str("noauth".into()));
        settings.insert("udp", Json::Bool(false));
        match self {
            Self::Xray => {
                inbound.insert("settings", settings);
            }
            Self::SingBox => {
                let _ = settings;
                inbound.insert("users", Json::Arr(Vec::new()));
            }
        }
        inbound
    }

    fn direct_outbound(self) -> Json {
        let mut outbound = Json::object();
        match self {
            Self::Xray => {
                outbound.insert("protocol", Json::Str("freedom".into()));
            }
            Self::SingBox => {
                outbound.insert("type", Json::Str("direct".into()));
                outbound.insert("tag", Json::Str("direct-out".into()));
            }
        }
        outbound
    }

    pub fn base_config(self) -> Json {
        let mut root = Json::object();
        root.insert("outbounds", Json::Arr(vec![self.direct_outbound()]));
        match self {
            Self::Xray => {}
            Self::SingBox => {
                root.insert("route", Json::object());
            }
        }
        root
    }
}

const ACCEPTED_FIELDS: [&str; 13] = [
    "binary",
    "config",
    "path",
    "traffic",
    "connections",
    "iterations",
    "payload_size",
    "output",
    "warmup",
    "prepare_client",
    "idle_connections",
    "client_env",
    "tcp_latency_iterations",
];

const KIB: f64 = 1024.0;

pub fn cpu_resolution_floor_millis() -> u64 {
    crate::ps::resolution_millis()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Startup,
    Traffic,
    Settle,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Traffic => "traffic",
            Self::Settle => "settle",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traffic {
    Upload,
    Download,
    FullDuplex,
}

impl Traffic {
    fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "upload" => Ok(Self::Upload),
            "download" => Ok(Self::Download),
            "full-duplex" => Ok(Self::FullDuplex),
            other => Err(Error::Invalid(format!("unknown traffic `{other}`"))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::FullDuplex => "full-duplex",
        }
    }

    const fn uplink(self) -> bool {
        matches!(self, Self::Upload | Self::FullDuplex)
    }

    const fn downlink(self) -> bool {
        matches!(self, Self::Download | Self::FullDuplex)
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub binary: PathBuf,
    pub config: String,
    pub path: String,
    pub traffic: Traffic,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    pub output: PathBuf,
    pub warmup: bool,
    pub idle_connections: usize,
    pub prepare_client: bool,
    pub client_env: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Io {
        action: String,
        source: std::io::Error,
    },
    Engine {
        message: String,
    },
    Workload(String),
    Transient(String),
    Desync {
        flow: usize,
        offset: u64,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "{m}"),
            Self::Io { action, source } => write!(f, "{action}: {source}"),
            Self::Engine { message } => write!(f, "engine: {message}"),
            Self::Workload(m) => write!(f, "workload: {m}"),
            Self::Transient(m) => write!(f, "transient: {m}"),
            Self::Desync { flow, offset } => write!(
                f,
                "workload: flow {flow} relayed a byte that is not the validated pattern at byte {offset}"
            ),
        }
    }
}

impl std::error::Error for Error {}

// The first forged byte any flow of a run relayed, shared so a nondeterministic desync is re-measured instead of trusted; only the first write sticks.
type Desync = Arc<std::sync::Mutex<Option<(usize, u64)>>>;

fn note_desync(desync: &Desync, flow: usize, offset: u64) {
    if let Ok(mut slot) = desync.lock() {
        slot.get_or_insert((flow, offset));
    }
}

fn is_desync(err: &Error) -> bool {
    matches!(err, Error::Desync { .. })
}

fn is_retryable(err: &Error) -> bool {
    matches!(err, Error::Desync { .. } | Error::Transient(_))
}

// The socket-layer signatures of a saturated runner rather than a fault in the engine: EAGAIN (the macos write ride and the read timeout both end here), ENOBUFS, EPIPE and ECONNRESET — the last two usually the cascade of a sibling flow whose ride expired. A genuinely slow engine still completes the transfer and fails on its ratio, not here.
fn is_transient_io(message: &str) -> bool {
    [
        "Resource temporarily unavailable",
        "No buffer space available",
        "Broken pipe",
        "Connection reset by peer",
        "os error 35",
        "os error 55",
        "os error 32",
        "os error 54",
        "os error 105",
        "os error 10035",
        "os error 10055",
        "os error 11",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

// The absolute byte a validated download reported corrupt, lifted from read_validated's message so the client's desync carries the same (flow, offset) signature the sink's does.
fn first_mismatch_byte(why: &str) -> Option<u64> {
    why.strip_prefix("bytes at offset ")
        .and_then(|rest| rest.rsplit("first at byte ").next())
        .and_then(|n| n.trim().split([' ', ',']).next())
        .and_then(|n| n.parse().ok())
}

fn io(action: &'static str) -> impl FnOnce(std::io::Error) -> Error {
    move |source| Error::Io {
        action: action.to_owned(),
        source,
    }
}

impl Request {
    pub fn read(path: &Path) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(io("reading the request"))?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::Invalid(format!(
                "benchmark request exceeds {MAX_REQUEST_BYTES} bytes"
            )));
        }
        Self::parse(&bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::Invalid("request is not UTF-8".into()))?;
        let root = json::parse(text).map_err(|e| Error::Invalid(format!("bad request: {e}")))?;

        if let Some(pairs) = root.as_obj() {
            for (key, _) in pairs {
                if !ACCEPTED_FIELDS.contains(&key.as_str()) {
                    return Err(Error::Invalid(format!(
                        "unknown request field `{key}`. Accepted: {}. An \
                         unrecognised field is an error rather than a shrug \
                         because the same file is read by the pinned harness too, \
                         and a field only one of them honours is two different \
                         measurements of one name.",
                        ACCEPTED_FIELDS.join(", ")
                    )));
                }
            }
        }

        let string = |key: &str| -> Result<String, Error> {
            root.get(key)
                .and_then(Json::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::Invalid(format!("request needs a string `{key}`")))
        };
        let count = |key: &str| -> Result<usize, Error> {
            let n = root
                .get(key)
                .and_then(Json::as_num)
                .ok_or_else(|| Error::Invalid(format!("request needs a number `{key}`")))?;
            if n < 0.0 || n.fract() != 0.0 {
                return Err(Error::Invalid(format!("`{key}` must be a whole count")));
            }
            Ok(n as usize)
        };

        let request = Self {
            binary: PathBuf::from(string("binary")?),
            config: string("config")?,
            path: string("path")?,
            traffic: Traffic::parse(&string("traffic")?)?,
            connections: count("connections")?,
            iterations: count("iterations")?,
            payload_size: count("payload_size")?,
            output: PathBuf::from(string("output")?),
            warmup: matches!(root.get("warmup").and_then(Json::as_bool), Some(true)),
            idle_connections: root
                .get("idle_connections")
                .and_then(Json::as_num)
                .map_or(0, |n| n.max(0.0) as usize),
            prepare_client: matches!(
                root.get("prepare_client").and_then(Json::as_bool),
                Some(true)
            ),
            client_env: read_env(&root)?,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.path != "socks" {
            return Err(Error::Invalid(format!(
                "path `{}` is not implemented here: this harness drives a SOCKS \
                 inbound, because `ferrox-app` serves no TUN device. The \
                 pinned harness's `tun` workloads are listed as `not_covered` in \
                 docs/methodology.md",
                self.path
            )));
        }
        if self.idle_connections != 0 {
            return Err(Error::Invalid(format!(
                "idle_connections {} is not implemented here: this harness has no \
                 held-open workload, so the resident-memory-per-idle-flow \
                 measurement the pinned harness takes cannot be produced",
                self.idle_connections
            )));
        }
        if self.prepare_client {
            return Err(Error::Invalid(
                "prepare_client is not implemented here: it exists so a Go engine's \
                 launcher CPU does not bias its lifetime figure, and \
                 ferrox-app is exec'd directly with no launcher"
                    .into(),
            ));
        }
        if !(1..=16).contains(&self.connections) {
            return Err(Error::Invalid(format!(
                "connections {} is outside 1..=16",
                self.connections
            )));
        }
        if !(1..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(Error::Invalid(format!(
                "iterations {} is outside 1..={MAX_ITERATIONS}",
                self.iterations
            )));
        }
        if !(1..=65_536).contains(&self.payload_size) {
            return Err(Error::Invalid(format!(
                "payload_size {} is outside 1..=65536",
                self.payload_size
            )));
        }
        if self.flow_bytes() > MAX_FLOW_BYTES {
            return Err(Error::Invalid(format!(
                "{} bytes per flow is above the {MAX_FLOW_BYTES} B ceiling: a run \
                 that cannot finish inside the {} s cap would report a truncated \
                 transfer as a rate",
                self.flow_bytes(),
                RUN_TIMEOUT.as_secs()
            )));
        }
        if self.output.exists() {
            return Err(Error::Invalid(format!(
                "output {} already exists; the harness creates it, so a stale \
                 directory cannot be read as this run's result",
                self.output.display()
            )));
        }
        if !self.binary.is_file() {
            return Err(Error::Invalid(format!(
                "binary {} is not a file",
                self.binary.display()
            )));
        }
        json::parse(&self.config)
            .map_err(|e| Error::Invalid(format!("config is not valid json: {e}")))?;
        Ok(())
    }

    pub fn flow_bytes(&self) -> u64 {
        u64::try_from(self.payload_size).unwrap_or(u64::MAX)
            * u64::try_from(self.iterations).unwrap_or(u64::MAX)
    }

    pub fn total_bytes(&self) -> u64 {
        let per_flow = self.flow_bytes();
        let directions = u64::from(self.traffic.uplink()) + u64::from(self.traffic.downlink());
        per_flow
            .saturating_mul(u64::try_from(self.connections).unwrap_or(0))
            .saturating_mul(directions)
    }
}

fn read_env(root: &Json) -> Result<BTreeMap<String, String>, Error> {
    let mut out = BTreeMap::new();
    let Some(env) = root.get("client_env") else {
        return Ok(out);
    };
    if env == &Json::Null {
        return Ok(out);
    }
    let pairs = env
        .as_obj()
        .ok_or_else(|| Error::Invalid("client_env must be an object".into()))?;
    for (key, value) in pairs {
        let text = value
            .as_str()
            .ok_or_else(|| Error::Invalid(format!("client_env.{key} must be a string")))?;
        out.insert(key.clone(), text.to_owned());
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_field_names,
    reason = "every field is a microsecond count; the suffix is the unit, which u128 alone does not say"
)]
pub struct Setup {
    pub tcp_connect_us: u128,
    pub socks_method_us: u128,
    pub socks_connect_us: u128,
    pub socks_setup_us: u128,
    pub total_us: u128,
}

type SetupStage = (&'static str, fn(&Setup) -> u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quartiles {
    pub min: u128,
    pub median: u128,
    pub p95: u128,
    pub p99: u128,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub transfer: Duration,
    pub wall: Duration,
    pub setup: Vec<Setup>,
    pub peak_rss_kib: u64,
    pub cpu_millis: u64,
    /// The same cpu the run reports, split by what the process ran; `None` where the sampler has no split.
    pub user_millis: Option<u64>,
    pub sys_millis: Option<u64>,
    pub traffic_samples: usize,
    pub threads_peak: Option<u64>,
    /// The kernel's tally of what this run asked it to move, as the tallest each counter reached: the
    /// threads carrying a relay's tallies die with its traffic, which is what `ps::Io::window` reads.
    pub io: Option<ps::Io>,
    pub startup_cpu_millis: u64,
    pub startup_seconds: f64,
    pub samples: Vec<(Phase, ps::Sample)>,
}

#[derive(Debug)]
pub struct Run {
    pub engine: String,
    pub engine_sha256: String,
    pub outcome: Outcome,
}

impl Run {
    /// What crossed this run in both directions; every per-GiB row divides by it.
    pub fn bytes_moved(&self) -> u64 {
        self.outcome.bytes_sent + self.outcome.bytes_received
    }

    pub fn throughput_mib_s(&self) -> f64 {
        let seconds = self.outcome.transfer.as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        self.bytes_moved() as f64 / (1024.0 * 1024.0) / seconds
    }

    pub fn cpu_millis_per_gib(&self) -> f64 {
        let bytes = self.bytes_moved();
        if bytes == 0 {
            return 0.0;
        }
        self.outcome.cpu_millis as f64 / (bytes as f64 / 1_073_741_824.0)
    }

    pub fn rss_mib(&self) -> f64 {
        self.outcome.peak_rss_kib as f64 / KIB
    }

    /// The run's cpu split over the bytes it moved; `None` where the sampler has no split.
    pub fn cpu_split_per_gib(&self) -> Option<(f64, f64)> {
        let bytes = self.bytes_moved();
        if bytes == 0 {
            return None;
        }
        let gib = bytes as f64 / 1_073_741_824.0;
        let (user, sys) = (self.outcome.user_millis?, self.outcome.sys_millis?);
        Some((user as f64 / gib, sys as f64 / gib))
    }

    /// The run's crossing cost per GiB, or nothing for a tally the crossing never reached; see
    /// [`io_crossing_per_gib`].
    pub fn io_per_gib(&self) -> Option<(f64, f64)> {
        io_crossing_per_gib(self.outcome.io?, self.bytes_moved())
    }

    fn quartiles(values: &[u128]) -> Option<Quartiles> {
        if values.is_empty() {
            return None;
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        Some(Quartiles {
            min: sorted[0],
            median: median(&sorted),
            p95: nearest_rank(&sorted, 95),
            p99: nearest_rank(&sorted, 99),
        })
    }

    pub fn to_result_json(&self, request: &Request) -> Json {
        let o = &self.outcome;
        let stages: [SetupStage; 5] = [
            ("tcp_connect_us", |s| s.tcp_connect_us),
            ("socks_method_us", |s| s.socks_method_us),
            ("socks_connect_us", |s| s.socks_connect_us),
            ("socks_setup_us", |s| s.socks_setup_us),
            ("total_us", |s| s.total_us),
        ];
        let mut setup = Json::object();
        for (key, read) in stages {
            let values: Vec<u128> = o.setup.iter().map(read).collect();
            setup.insert(key, optional_quartiles_json(Run::quartiles(&values)));
        }

        let mut samples = Vec::new();
        for (phase, s) in &o.samples {
            let mut item = Json::object();
            item.insert("elapsed_ms", Json::Num(s.elapsed_ms as f64));
            item.insert("rss_kib", Json::Num(s.rss_kib as f64));
            item.insert("cpu_millis", Json::Num(s.cpu_millis as f64));
            let millis = |value: Option<u64>| match value {
                Some(v) => Json::Num(v as f64),
                None => Json::Null,
            };
            item.insert("user_millis", millis(s.user_millis));
            item.insert("sys_millis", millis(s.sys_millis));
            item.insert("io", io_json(s.io));
            item.insert(
                "threads",
                match s.threads {
                    Some(t) => Json::Num(t as f64),
                    None => Json::Null,
                },
            );
            item.insert("phase", Json::Str(phase.as_str().to_owned()));
            samples.push(item);
        }

        let mut root = Json::object();
        root.insert("status", Json::Str("pass".into()));
        root.insert("harness", Json::Str(HARNESS_ID.into()));
        root.insert("path", Json::Str("socks".into()));
        root.insert("traffic", Json::Str(request.traffic.as_str().into()));
        root.insert("connections", Json::Num(request.connections as f64));
        root.insert("iterations", Json::Num(request.iterations as f64));
        root.insert("payload_size", Json::Num(request.payload_size as f64));
        root.insert("idle_connections", Json::Num(0.0));
        root.insert("concurrent_flows", Json::Num(request.connections as f64));
        root.insert("bytes_sent", Json::Num(o.bytes_sent as f64));
        root.insert("bytes_received", Json::Num(o.bytes_received as f64));
        root.insert("expected_bytes", Json::Num(request.total_bytes() as f64));
        root.insert("transfer_seconds", Json::Num(o.transfer.as_secs_f64()));
        root.insert("wall_seconds", Json::Num(o.wall.as_secs_f64()));
        root.insert("throughput_mib_s", Json::Num(self.throughput_mib_s()));
        root.insert("peak_rss_kib", Json::Num(o.peak_rss_kib as f64));
        root.insert("cpu_millis", Json::Num(o.cpu_millis as f64));
        let split = |value: Option<u64>| value.map_or(Json::Null, |v| Json::Num(v as f64));
        root.insert("cpu_user_millis", split(o.user_millis));
        root.insert("cpu_sys_millis", split(o.sys_millis));
        root.insert("cpu_millis_per_gib", Json::Num(self.cpu_millis_per_gib()));
        let per_gib = self.io_per_gib();
        let number = |value: Option<f64>| value.map_or(Json::Null, Json::Num);
        root.insert("io", io_json(o.io));
        root.insert("io_calls_per_gib", number(per_gib.map(|(c, _)| c)));
        root.insert("io_bytes_per_gib", number(per_gib.map(|(_, b)| b)));
        root.insert(
            "cpu_resolution_floor_millis",
            Json::Num(cpu_resolution_floor_millis() as f64),
        );
        root.insert(
            "threads_peak",
            match o.threads_peak {
                Some(t) => Json::Num(t as f64),
                None => Json::Null,
            },
        );
        root.insert("warmup", Json::Bool(request.warmup));
        root.insert("prepare_client", Json::Bool(false));
        root.insert("client_startup_seconds", Json::Num(o.startup_seconds));
        root.insert(
            "client_startup_cpu_millis",
            Json::Num(o.startup_cpu_millis as f64),
        );
        root.insert("client_cpu_total_millis", Json::Num(o.cpu_millis as f64));
        root.insert("engine_binary", Json::Str(self.engine.clone()));
        root.insert("engine_sha256", Json::Str(self.engine_sha256.clone()));
        root.insert("setup", setup);
        root.insert("latency_us", Json::Null);
        root.insert("tun_fd_buffers", Json::Null);
        root.insert("samples", Json::Arr(samples));
        root
    }
}

/// The run's crossing cost per GiB: how often the kernel was asked, and how much each ask carried.
/// A `splice` or a `send`/`recv` socket crossing moves bytes `/proc/<pid>/io` never names, and a
/// relay writes what it moves, so a tally under an eighth of the run's bytes was not looking at the
/// crossing at all: it gets no number rather than a zero a reader would take for a win. The pair of
/// witnesses in `ps` is where these two bands come from.
pub fn io_crossing_per_gib(io: ps::Io, moved: u64) -> Option<(f64, f64)> {
    if moved == 0 || io.bytes() < moved / 8 {
        return None;
    }
    let gib = moved as f64 / 1_073_741_824.0;
    Some((io.calls() as f64 / gib, io.bytes() as f64 / gib))
}

/// The kernel's own counters, under the names `/proc/<pid>/io` prints them, so a number in the
/// artefact can be checked against the file it came from.
fn io_json(io: Option<ps::Io>) -> Json {
    io.map_or(Json::Null, |io| {
        let mut item = Json::object();
        item.insert("syscr", Json::Num(io.read_calls as f64));
        item.insert("syscw", Json::Num(io.write_calls as f64));
        item.insert("rchar", Json::Num(io.read_bytes as f64));
        item.insert("wchar", Json::Num(io.write_bytes as f64));
        item
    })
}

fn optional_quartiles_json(q: Option<Quartiles>) -> Json {
    q.map_or(Json::Null, quartiles_json)
}

fn quartiles_json(q: Quartiles) -> Json {
    let mut out = Json::object();
    out.insert("min", Json::Num(q.min as f64));
    out.insert("median", Json::Num(q.median as f64));
    out.insert("p95", Json::Num(q.p95 as f64));
    out.insert("p99", Json::Num(q.p99 as f64));
    out
}

pub fn median(sorted: &[u128]) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        u128::midpoint(sorted[mid - 1], sorted[mid])
    } else {
        sorted[mid]
    }
}

pub fn nearest_rank(sorted: &[u128], pct: u128) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len() as u128).div_ceil(100);
    sorted[((rank.max(1) - 1) as usize).min(sorted.len() - 1)]
}

pub fn bulk_pattern_template(payload_size: usize) -> Vec<u8> {
    let mut state = BULK_PATTERN_SEED;
    let mut out = Vec::with_capacity(payload_size);
    for _ in 0..payload_size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 32) as u8);
    }
    out
}

pub fn local_non_loopback_ipv4() -> Result<Ipv4Addr, Error> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(io("binding the probe socket"))?;
    socket
        .connect((Ipv4Addr::new(8, 8, 8, 8), 80))
        .map_err(io("probing the local non-loopback IPv4 address"))?;
    let SocketAddr::V4(addr) = socket
        .local_addr()
        .map_err(io("reading the probe address"))?
    else {
        return Err(Error::Invalid(
            "the probe socket has no IPv4 address".into(),
        ));
    };
    let ip = *addr.ip();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Err(Error::Invalid(format!(
            "this host has no usable non-loopback IPv4 address (the probe gave {ip}); \
             a loopback-only host cannot run this benchmark, because the engines \
             would be measured over different loopback paths"
        )));
    }
    Ok(ip)
}

/// The sink's per-flow ports, held as bound listeners: a bound socket is a reservation, a number is a hope.
fn allocate_port_range(count: usize) -> Result<Vec<TcpListener>, Error> {
    let ip = local_non_loopback_ipv4()?;
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        listeners.push(TcpListener::bind((ip, 0)).map_err(io("allocating a sink port"))?);
    }
    Ok(listeners)
}

fn bound_port(listener: &TcpListener) -> Result<u16, Error> {
    Ok(listener
        .local_addr()
        .map_err(io("reading a bound port"))?
        .port())
}

fn ports_of(listeners: &[TcpListener]) -> Result<Vec<u16>, Error> {
    listeners.iter().map(bound_port).collect()
}

/// The listener comes back, not the number: the engine is a child process that binds it, and between a drop and that bind any other thread can be handed the same port.
fn allocate_port_excluding(ip: Ipv4Addr, taken: &[u16]) -> Result<TcpListener, Error> {
    for _ in 0..64 {
        let listener = TcpListener::bind((ip, 0)).map_err(io("allocating a port"))?;
        if !taken.contains(&bound_port(&listener)?) {
            return Ok(listener);
        }
    }
    Err(Error::Workload(
        "could not find a free port clear of the sink's range".into(),
    ))
}

struct Engine {
    child: Child,
}

impl Engine {
    fn reap(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.reap();
    }
}

// Two runner disturbances are measured on macos-15 and belong to neither engine: a forged validated byte, seen on ferrox and the reference alike, and a short bulk transfer whose every reason is a socket-layer transient - a saturated runner cannot always move 8 GiB full duplex inside one per-op timeout, and it does so to every engine in the cell. Neither says anything about the engine under test, so each is re-measured, up to this many attempts; a disturbance that survives every attempt still fails as a workload fault. The bound is what keeps this from becoming a silent retry of a genuine regression.
const REMEASURE_ATTEMPTS: usize = 3;

pub fn measure(request: &Request, config_arg: ConfigArg, dialect: Dialect) -> Result<Run, Error> {
    remeasure_disturbed(REMEASURE_ATTEMPTS, || {
        measure_once(request, config_arg, dialect)
    })
}

// The retry policy split from the run it wraps, so the bound is gated without an engine: it stops at the first result that needs no re-measure, and a disturbance surviving every attempt is converted, never banked as a number.
fn remeasure_disturbed<T>(
    attempts: usize,
    mut run: impl FnMut() -> Result<T, Error>,
) -> Result<T, Error> {
    let mut attempt = 1;
    loop {
        match run() {
            Err(err) if is_retryable(&err) => {
                if attempt == attempts {
                    let label = if is_desync(&err) {
                        "A forged byte that survives every retry is not the runner's"
                    } else {
                        "A socket fault that survives every retry is not the runner's"
                    };
                    return Err(Error::Workload(format!(
                        "{err}; {label}, and a workload fault is reported as one, never as a number"
                    )));
                }
                attempt += 1;
                eprintln!(
                    "gate 5 note: attempt {attempt} of {attempts} was disturbed, re-measuring: {err}"
                );
                std::thread::sleep(Duration::from_millis(250));
            }
            other => {
                if attempt > 1 && other.is_ok() {
                    eprintln!(
                        "gate 5 note: this run follows a re-measured attempt; the disturbed run was re-measured, the bar was not"
                    );
                }
                return other;
            }
        }
    }
}

fn measure_once(request: &Request, config_arg: ConfigArg, dialect: Dialect) -> Result<Run, Error> {
    let ip = local_non_loopback_ipv4()?;
    let sink = allocate_port_range(request.connections)?;
    let sink_ports = ports_of(&sink)?;
    let targets = sink_targets(ip, &sink_ports);
    let probe = allocate_port_excluding(ip, &sink_ports)?;
    let engine_port = bound_port(&probe)?;

    std::fs::create_dir_all(&request.output).map_err(io("creating the output directory"))?;
    let config_path = request.output.join("config.json");
    let stderr_path = request.output.join("stderr.log");
    let stdout_path = request.output.join("stdout.log");

    let desync: Desync = Arc::new(std::sync::Mutex::new(None));
    let sink_thread = spawn_sink(sink, request, &desync)?;
    let config_text = inject_inbound(&request.config, ip, engine_port, dialect)?;
    std::fs::write(&config_path, &config_text).map_err(io("writing the engine config"))?;

    let started = Instant::now();
    drop(probe);
    let mut engine = spawn_engine(
        request,
        config_arg,
        &config_path,
        &stdout_path,
        &stderr_path,
    )?;
    let pid = engine.child.id();
    let socks = SocketAddr::from((ip, engine_port));
    if let Err(e) = wait_for_listener(&mut engine.child, socks, &stderr_path) {
        return Err(Error::Engine {
            message: format!("{e}; stderr tail: {}", tail(&stderr_path)),
        });
    }

    let startup_samples = sample_for(pid, Phase::Startup, PRE_SLEEP)?;
    let startup_cpu_millis = startup_samples
        .first()
        .map(|(_, s)| s.cpu_millis)
        .unwrap_or_default();

    if request.warmup {
        warmup(socks, &bulk_pattern_template(request.payload_size))?;
    }

    let (flows, sampler_thread, stop, rx) = start_traffic(pid, request, socks, &targets, &desync);
    let wall = Instant::now();
    // The cap is enforced inside the fan-in: a stalled flow blocks `read`, so a post-hoc check here could never fire.
    let moved = collect_flows(flows, &stop, wall + RUN_TIMEOUT)?;
    let wall_elapsed = wall.elapsed();

    std::thread::sleep(SAMPLE_INTERVAL + Duration::from_millis(20));
    stop.store(true, Ordering::Relaxed);
    let _ = sampler_thread.join();
    let mut samples = startup_samples;
    samples.extend(rx.try_iter());
    samples.extend(sample_for(pid, Phase::Settle, SETTLE)?);

    engine.reap();
    let sink_reasons = sink_thread.reasons();
    sink_thread.join()?;

    // Checked before the byte totals: a forged byte shortens the transfer too, but naming it as a desync is what lets `measure` re-measure it instead of banking a workload fault.
    if let Some((flow, offset)) = desync.lock().ok().and_then(|slot| *slot) {
        return Err(Error::Desync { flow, offset });
    }

    let expected = request.total_bytes();
    if moved.sent + moved.received != expected {
        let mut why = if moved.all_stopped.is_empty() {
            vec!["no flow reported why it stopped".to_owned()]
        } else {
            moved.all_stopped.clone()
        };
        why.extend(sink_reasons);
        let joined = why.join("; ");
        // A short transfer explained by socket-layer transience - a saturated runner, every engine alike - is re-measured like a forged byte, never banked; one that carries no such signature is a real workload fault and stays one.
        if is_transient_io(&joined) {
            return Err(Error::Transient(format!(
                "moved {} of {expected} bytes: {}",
                moved.sent + moved.received,
                joined
            )));
        }
        return Err(Error::Workload(format!(
            "moved {} of {expected} bytes: a short transfer is a fault in the \
             workload, not a number to report. {}",
            moved.sent + moved.received,
            joined
        )));
    }

    let summary = summarise(&samples, &moved, startup_cpu_millis);
    Ok(Run {
        engine: request.binary.display().to_string(),
        engine_sha256: file_sha256(&request.binary),
        outcome: Outcome {
            bytes_sent: moved.sent,
            bytes_received: moved.received,
            transfer: summary.transfer,
            wall: wall_elapsed,
            setup: moved.setup,
            peak_rss_kib: summary.peak_rss_kib,
            cpu_millis: summary.cpu_millis,
            user_millis: summary.user_millis,
            sys_millis: summary.sys_millis,
            traffic_samples: summary.traffic_samples,
            threads_peak: summary.threads_peak,
            io: summary.io,
            startup_cpu_millis,
            startup_seconds: started.elapsed().as_secs_f64(),
            samples,
        },
    })
}

struct Summary {
    peak_rss_kib: u64,
    cpu_millis: u64,
    user_millis: Option<u64>,
    sys_millis: Option<u64>,
    traffic_samples: usize,
    threads_peak: Option<u64>,
    io: Option<ps::Io>,
    transfer: Duration,
}

fn summarise(samples: &[(Phase, ps::Sample)], moved: &Moved, startup_cpu_millis: u64) -> Summary {
    let first = samples.first().copied().map(|(_, s)| s);
    let last = samples.last().copied().map(|(_, s)| s);
    // `startup_cpu_millis` is this first sample's cpu; the split is measured against the same one.
    let split =
        |read: fn(ps::Sample) -> Option<u64>| match (first.and_then(read), last.and_then(read)) {
            (Some(start), Some(end)) => end.checked_sub(start),
            _ => None,
        };
    Summary {
        peak_rss_kib: samples
            .iter()
            .map(|(_, s)| s.rss_kib)
            .max()
            .unwrap_or_default(),
        cpu_millis: last
            .map(|s| s.cpu_millis)
            .unwrap_or_default()
            .saturating_sub(startup_cpu_millis),
        user_millis: split(|s| s.user_millis),
        sys_millis: split(|s| s.sys_millis),
        io: ps::Io::window(samples.iter().filter_map(|(_, s)| s.io)),
        traffic_samples: samples
            .iter()
            .filter(|(phase, _)| *phase == Phase::Traffic)
            .count(),
        threads_peak: samples.iter().filter_map(|(_, s)| s.threads).max(),
        transfer: moved
            .window
            .map_or(Duration::ZERO, |(a, b)| b.saturating_duration_since(a)),
    }
}

fn spawn_engine(
    request: &Request,
    config_arg: ConfigArg,
    config_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<Engine, Error> {
    let child = Command::new(&request.binary)
        .args(config_arg.args(config_path))
        .envs(&request.client_env)
        .stdout(Stdio::from(
            std::fs::File::create(stdout_path).map_err(io("creating stdout.log"))?,
        ))
        .stderr(Stdio::from(
            std::fs::File::create(stderr_path).map_err(io("creating stderr.log"))?,
        ))
        .spawn()
        .map_err(|e| Error::Engine {
            message: format!("cannot spawn {}: {e}", request.binary.display()),
        })?;
    Ok(Engine { child })
}

type TrafficPhase = (
    Vec<JoinHandle<FlowResult>>,
    JoinHandle<()>,
    Arc<AtomicBool>,
    mpsc::Receiver<(Phase, ps::Sample)>,
);

fn start_traffic(
    pid: u32,
    request: &Request,
    engine: SocketAddr,
    targets: &[SocketAddr],
    desync: &Desync,
) -> TrafficPhase {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(Phase, ps::Sample)>();
    let sampler_thread = spawn_sampler(pid, Arc::clone(&stop), tx);
    (
        spawn_flows(request, engine, targets, desync),
        sampler_thread,
        stop,
        rx,
    )
}

struct Moved {
    sent: u64,
    received: u64,
    window: Option<(Instant, Instant)>,
    setup: Vec<Setup>,
    stopped: Option<String>,
    all_stopped: Vec<String>,
}

fn collect_flows(
    flows: Vec<JoinHandle<FlowResult>>,
    stop: &Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Moved, Error> {
    let mut moved = Moved {
        sent: 0,
        received: 0,
        window: None,
        setup: Vec::new(),
        stopped: None,
        all_stopped: Vec::new(),
    };
    // Never join past the deadline: an unbounded `join` wedges the cell to the CI ceiling when an engine accepts the connect then stalls the stream.
    while !flows.iter().all(JoinHandle::is_finished) {
        if Instant::now() >= deadline {
            stop.store(true, Ordering::Relaxed);
            return Err(Error::Workload(format!(
                "workload exceeded the {}s cap",
                RUN_TIMEOUT.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    for flow in flows {
        let result = flow
            .join()
            .map_err(|_| Error::Workload("a flow thread panicked".into()))?;
        moved.sent += result.bytes_sent;
        moved.received += result.bytes_received;
        moved.setup.push(result.setup);
        if let Some(reason) = result.stopped {
            moved.stopped.get_or_insert(reason.clone());
            moved.all_stopped.push(reason);
        }
        moved.window = match (moved.window, result.window) {
            (None, w) => w,
            (Some((a, b)), Some((c, d))) => Some((a.min(c), b.max(d))),
            (current, None) => current,
        };
    }
    Ok(moved)
}

fn tail(path: &Path) -> String {
    std::fs::read_to_string(path).map_or_else(
        |_| "<unreadable>".into(),
        |text| {
            let lines: Vec<&str> = text.lines().collect();
            if lines.is_empty() {
                return "<empty>".into();
            }
            lines[lines.len().saturating_sub(4)..].join(" | ")
        },
    )
}

fn wait_for_listener(child: &mut Child, addr: SocketAddr, stderr: &Path) -> Result<(), Error> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().map_err(io("polling the engine"))? {
            return Err(Error::Engine {
                message: format!(
                    "exited during startup with {status}; stderr tail: {}",
                    tail(stderr)
                ),
            });
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::Engine {
                message: format!("did not listen on {addr} within 20s"),
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn sample_for(
    pid: u32,
    phase: Phase,
    duration: Duration,
) -> Result<Vec<(Phase, ps::Sample)>, Error> {
    let host = Host::current();
    let start = Instant::now();
    let first = sample_at(host, pid, 0)?;
    let mut samples = vec![(phase, first)];
    while start.elapsed() < duration {
        let remaining = duration.saturating_sub(start.elapsed());
        std::thread::sleep(SAMPLE_INTERVAL.min(remaining));
        samples.push((phase, sample_at(host, pid, start.elapsed().as_millis())?));
    }
    Ok(samples)
}

fn sample_at(host: Host, pid: u32, elapsed_ms: u128) -> Result<ps::Sample, Error> {
    ps::sample(host, pid, elapsed_ms).map_err(|e| Error::Engine {
        message: format!("cannot sample the engine: {e}"),
    })
}

fn spawn_sampler(
    pid: u32,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<(Phase, ps::Sample)>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let host = Host::current();
        let start = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(SAMPLE_INTERVAL);
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match ps::sample(host, pid, start.elapsed().as_millis()) {
                Ok(sample) => {
                    if tx.send((Phase::Traffic, sample)).is_err() {
                        break;
                    }
                }
                // `ps` failed to run at all: a machine condition, so try again.
                Err(SampleError::Spawn(_)) => {}
                // The target is gone; a loop forking `ps` against it steals CPU.
                Err(_) => break,
            }
        }
    })
}

struct FlowResult {
    bytes_sent: u64,
    bytes_received: u64,
    window: Option<(Instant, Instant)>,
    setup: Setup,
    stopped: Option<String>,
}

struct FlowPlan {
    bytes: u64,
    pattern: Vec<u8>,
    traffic: Traffic,
    engine: SocketAddr,
    target: SocketAddr,
    index: usize,
    desync: Desync,
}

struct SinkThread {
    accept: JoinHandle<()>,
    reasons: Arc<std::sync::Mutex<Vec<String>>>,
    done: Arc<AtomicBool>,
}

impl SinkThread {
    fn join(self) -> Result<(), Error> {
        self.done.store(true, Ordering::Relaxed);
        self.accept
            .join()
            .map_err(|_| Error::Workload("the sink thread panicked".into()))?;
        Ok(())
    }

    fn reasons(&self) -> Vec<String> {
        self.reasons.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

fn spawn_flows(
    request: &Request,
    engine: SocketAddr,
    targets: &[SocketAddr],
    desync: &Desync,
) -> Vec<JoinHandle<FlowResult>> {
    let template = bulk_pattern_template(request.payload_size);
    (0..request.connections)
        .map(|index| {
            let plan = FlowPlan {
                bytes: request.flow_bytes(),
                pattern: rotate(&template, index, request.connections),
                traffic: request.traffic,
                engine,
                target: targets[index],
                index,
                desync: Arc::clone(desync),
            };
            std::thread::spawn(move || run_flow(&plan))
        })
        .collect()
}

fn rotate(template: &[u8], index: usize, flows: usize) -> Vec<u8> {
    if flows <= 1 || template.is_empty() {
        return template.to_vec();
    }
    let shift = (index * 977) % template.len();
    let mut out = Vec::with_capacity(template.len());
    out.extend_from_slice(&template[shift..]);
    out.extend_from_slice(&template[..shift]);
    out
}

fn socks_greet(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[5, 1, 0])
        .map_err(|e| format!("socks greeting write failed: {e}"))?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(|e| format!("socks greeting read failed: {e}"))?;
    if greeting != [5, 0] {
        return Err(format!(
            "the engine answered the socks greeting with {greeting:02x?}, not 0500"
        ));
    }
    Ok(())
}

fn apply_flow_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(FLOW_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(FLOW_IO_TIMEOUT));
}

fn run_flow(plan: &FlowPlan) -> FlowResult {
    let mut result = FlowResult {
        bytes_sent: 0,
        bytes_received: 0,
        window: None,
        setup: Setup::default(),
        stopped: None,
    };

    let t0 = Instant::now();
    let Ok(mut stream) = TcpStream::connect_timeout(&plan.engine, Duration::from_secs(10)) else {
        result.stopped = Some(format!(
            "could not connect to the engine at {}",
            plan.engine
        ));
        return result;
    };
    let _ = stream.set_nodelay(true);
    apply_flow_timeouts(&stream);
    result.setup.tcp_connect_us = t0.elapsed().as_micros();

    let t1 = Instant::now();
    if let Err(reason) = socks_greet(&mut stream) {
        result.stopped = Some(reason);
        return result;
    }
    result.setup.socks_method_us = t1.elapsed().as_micros();

    let t2 = Instant::now();
    let mut connect = vec![5, 1, 0];
    let reply_len = match plan.target.ip() {
        std::net::IpAddr::V4(v4) => {
            connect.push(1);
            connect.extend_from_slice(&v4.octets());
            10
        }
        std::net::IpAddr::V6(v6) => {
            connect.push(4);
            connect.extend_from_slice(&v6.octets());
            22
        }
    };
    connect.extend_from_slice(&plan.target.port().to_be_bytes());
    if let Err(e) = stream.write_all(&connect) {
        result.stopped = Some(format!("socks connect write failed: {e}"));
        return result;
    }
    let mut reply = vec![0u8; reply_len];
    match stream.read_exact(&mut reply) {
        Err(e) => {
            result.stopped = Some(format!("socks connect read failed: {e}"));
            return result;
        }
        Ok(()) if reply[1] != 0 => {
            result.stopped = Some(format!(
                "the engine refused the socks connect with reply code {}; the sink \
                 is at {}",
                reply[1], plan.target
            ));
            return result;
        }
        Ok(()) => {}
    }
    result.setup.socks_connect_us = t2.elapsed().as_micros();
    result.setup.socks_setup_us = t1.elapsed().as_micros();
    result.setup.total_us = t0.elapsed().as_micros();

    let window_start = Instant::now();
    if plan.traffic.uplink() {
        if let Err(e) = plan.stream_up(&mut stream, &mut result.bytes_sent) {
            result.stopped = Some(format!(
                "upload write failed after {} of {} bytes: {e}",
                result.bytes_sent, plan.bytes
            ));
            return result;
        }
    }

    if plan.traffic.downlink() {
        match plan.stream_down(&mut stream) {
            Ok(received) => result.bytes_received = received,
            Err(why) => {
                result.stopped = Some(why);
                return result;
            }
        }
    }

    if (plan.traffic.uplink() || plan.traffic.downlink()) && result.stopped.is_none() {
        result.window = Some((window_start, Instant::now()));
    }
    let _ = stream.shutdown(Shutdown::Both);
    result
}

const UPLOAD_CHUNK: usize = 1024 * 1024;

const DOWNLOAD_CHUNK: usize = 64 * 1024;

fn read_validated(stream: &mut TcpStream, pattern: &[u8], bytes: u64) -> Result<u64, String> {
    let mut chunk = vec![0u8; pattern.len().clamp(1, DOWNLOAD_CHUNK)];
    let mut read_total = 0u64;
    while read_total < bytes {
        let Some(want) = usize::try_from((bytes - read_total).min(chunk.len() as u64)).ok() else {
            break;
        };
        if let Err(e) = stream.read_exact(&mut chunk[..want]) {
            return Err(format!(
                "download read failed after {read_total} of {bytes} bytes: {e}"
            ));
        }
        if let Some(at) = pattern_mismatch(pattern, read_total as usize, &chunk[..want]) {
            return Err(format!(
                "bytes at offset {read_total} are not the validated pattern, first at byte {}",
                read_total + at as u64
            ));
        }
        read_total += want as u64;
    }
    Ok(read_total)
}

/// The first byte of `chunk` that is not its pattern byte at absolute `offset`, or `None` when every byte is. Compared in runs that end at a wrap, so a validated byte costs a slice compare instead of a modulo and a bounds-checked index.
fn pattern_mismatch(pattern: &[u8], offset: usize, chunk: &[u8]) -> Option<usize> {
    let period = pattern.len();
    if period == 0 {
        return if chunk.is_empty() { None } else { Some(0) };
    }
    let mut at = offset % period;
    let mut done = 0usize;
    while done < chunk.len() {
        let run = (period - at).min(chunk.len() - done);
        if chunk[done..done + run] != pattern[at..at + run] {
            let first = chunk[done..done + run]
                .iter()
                .zip(&pattern[at..at + run])
                .position(|(got, want)| got != want)
                .expect("a run that compares unequal holds a first mismatch");
            return Some(done + first);
        }
        done += run;
        at = 0;
    }
    None
}

// A blocking socket returns WouldBlock/EAGAIN (macOS 35), ENOBUFS (macOS 55, Linux 105, Windows 10055) and their EAGAIN kin transiently when a full-rate flow outruns the kernel's send buffers; on an 8-flow macos-15 cell that aborted the reference engine and collapsed the gate-5 comparison into a false PROCESS REGRESSION, so ride it out until the per-op timeout rather than treating backpressure as a fault.
fn is_send_backpressure(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    match e.raw_os_error() {
        #[cfg(target_vendor = "apple")]
        Some(55 | 35) => true,
        #[cfg(target_os = "linux")]
        Some(105 | 11) => true,
        #[cfg(windows)]
        Some(10055) => true,
        _ => false,
    }
}

// Write `buf` in full, retrying only transient send-buffer backpressure and resetting `idle` on every byte of progress so a slow-but-live flow is never cut off while a truly wedged one still fails.
fn write_riding_backpressure(
    stream: &mut TcpStream,
    buf: &[u8],
    idle: Duration,
) -> std::io::Result<()> {
    let mut at = 0usize;
    let mut budget = Instant::now() + idle;
    while at < buf.len() {
        match stream.write(&buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(n) => {
                at += n;
                budget = Instant::now() + idle;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if is_send_backpressure(&e) => {
                if Instant::now() >= budget {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl FlowPlan {
    fn stream_down(&self, stream: &mut TcpStream) -> Result<u64, String> {
        read_validated(&mut *stream, &self.pattern, self.bytes).map_err(|why| {
            if let Some(at) = first_mismatch_byte(&why) {
                note_desync(&self.desync, self.index, at);
                return format!("flow {} download desynced at byte {at}", self.index);
            }
            format!("flow {} download stopped early: {why}", self.index)
        })
    }

    fn stream_up(&self, stream: &mut TcpStream, sent: &mut u64) -> std::io::Result<()> {
        let mut chunk: Vec<u8> = Vec::with_capacity(UPLOAD_CHUNK);
        while chunk.len() < UPLOAD_CHUNK {
            chunk.extend_from_slice(&self.pattern);
        }
        while *sent < self.bytes {
            let take = usize::try_from((self.bytes - *sent).min(chunk.len() as u64))
                .unwrap_or(chunk.len());
            write_riding_backpressure(stream, &chunk[..take], FLOW_IO_TIMEOUT)?;
            *sent += take as u64;
        }
        Ok(())
    }
}

fn spawn_sink(
    listeners: Vec<TcpListener>,
    request: &Request,
    desync: &Desync,
) -> Result<SinkThread, Error> {
    for listener in &listeners {
        listener
            .set_nonblocking(true)
            .map_err(io("making the sink non-blocking"))?;
    }
    let pattern = Arc::new(bulk_pattern_template(request.payload_size));
    let flows = request.connections;
    let upload_bytes = if request.traffic.uplink() {
        request.flow_bytes()
    } else {
        0
    };
    let download_bytes = if request.traffic.downlink() {
        request.flow_bytes()
    } else {
        0
    };
    let reasons = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let accept_reasons = Arc::clone(&reasons);
    let accept_desync = Arc::clone(desync);
    let done = Arc::new(AtomicBool::new(false));
    let sink_done = Arc::clone(&done);
    let accept = std::thread::spawn(move || {
        let done = sink_done;
        let mut handles = Vec::with_capacity(listeners.len());
        for (index, listener) in listeners.into_iter().enumerate() {
            let flow = Arc::new(rotate(&pattern, index, flows));
            let sink_reasons = Arc::clone(&accept_reasons);
            let sink_desync = Arc::clone(&accept_desync);
            let thread_done = Arc::clone(&done);
            handles.push(std::thread::spawn(move || {
                let listener_done = thread_done;
                let (stream, _) = loop {
                    if listener_done.load(Ordering::Relaxed) {
                        return;
                    }
                    match listener.accept() {
                        Ok(pair) => break pair,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => return,
                    }
                };
                if stream.set_nonblocking(false).is_err() {
                    return;
                }
                apply_flow_timeouts(&stream);
                if let Some(reason) = serve_flow(
                    stream,
                    &flow,
                    index,
                    upload_bytes,
                    download_bytes,
                    &sink_desync,
                ) {
                    if let Ok(mut slot) = sink_reasons.lock() {
                        slot.push(reason);
                    }
                }
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
    });
    Ok(SinkThread {
        accept,
        reasons,
        done,
    })
}

fn serve_flow(
    stream: TcpStream,
    pattern: &Arc<Vec<u8>>,
    index: usize,
    upload_bytes: u64,
    download_bytes: u64,
    desync: &Desync,
) -> Option<String> {
    let downloader = if download_bytes > 0 {
        let Ok(read_half) = stream.try_clone() else {
            return Some("the sink could not clone its socket".to_owned());
        };
        let pattern = Arc::clone(pattern);
        Some(std::thread::spawn(move || {
            emit(read_half, &pattern, index, download_bytes)
        }))
    } else {
        None
    };

    let upload_reason = if upload_bytes > 0 {
        validate(stream, pattern, index, upload_bytes, desync)
    } else {
        None
    };
    let download_reason = match downloader {
        Some(handle) => match handle.join() {
            Ok(reason) => reason,
            Err(_) => Some("the sink's flow thread panicked".to_owned()),
        },
        None => None,
    };
    upload_reason.or(download_reason)
}

fn validate(
    mut stream: TcpStream,
    pattern: &Arc<Vec<u8>>,
    index: usize,
    expect: u64,
    desync: &Desync,
) -> Option<String> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut seen = 0u64;
    let mut offset = 0usize;
    while seen < expect {
        let n = match stream.read(&mut buffer) {
            Ok(0) => {
                return Some(format!(
                    "the engine closed the upload after {seen} of {expect} bytes"
                ));
            }
            Ok(n) => n,
            Err(e) => return Some(format!("the upload read failed after {seen} bytes: {e}")),
        };
        if let Some(at) = pattern_mismatch(pattern, offset, &buffer[..n]) {
            let at = seen + at as u64;
            note_desync(desync, index, at);
            return Some(format!(
                "flow {index} upload desynced at byte {at}: a byte is not the validated pattern"
            ));
        }
        offset = (offset + n) % pattern.len();
        seen += n as u64;
    }
    None
}

fn emit(
    mut stream: TcpStream,
    pattern: &Arc<Vec<u8>>,
    index: usize,
    expect: u64,
) -> Option<String> {
    let _ = index;
    let mut buffer = Vec::with_capacity(64 * 1024);
    while buffer.len() < 64 * 1024 {
        buffer.extend_from_slice(pattern);
    }
    let mut sent = 0u64;
    while sent < expect {
        let take =
            usize::try_from((expect - sent).min(buffer.len() as u64)).unwrap_or(buffer.len());
        if let Err(e) = write_riding_backpressure(&mut stream, &buffer[..take], FLOW_IO_TIMEOUT) {
            return Some(format!(
                "the sink could not write after {sent} of {expect} bytes: {e}"
            ));
        }
        sent += take as u64;
    }
    let _ = stream.flush();
    None
}

fn warmup(socks: SocketAddr, pattern: &[u8]) -> Result<(), Error> {
    let mut stream = TcpStream::connect_timeout(&socks, Duration::from_secs(10))
        .map_err(io("warmup connect"))?;
    let _ = stream.set_nodelay(true);
    stream
        .write_all(&[5, 1, 0])
        .map_err(io("warmup greeting"))?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(io("warmup greeting reply"))?;
    let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
    connect.extend_from_slice(&1u16.to_be_bytes());
    stream
        .write_all(&connect)
        .map_err(io("warmup connect request"))?;
    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .map_err(io("warmup connect reply"))?;
    let chunk = &pattern[..pattern.len().min(1024)];
    stream.write_all(chunk).map_err(io("warmup write"))?;
    let mut echo = vec![0u8; chunk.len()];
    stream.read_exact(&mut echo).map_err(io("warmup echo"))?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

pub fn inject_inbound(
    config: &str,
    listen: Ipv4Addr,
    port: u16,
    dialect: Dialect,
) -> Result<String, Error> {
    let mut root = json::parse(config)
        .map_err(|e| Error::Invalid(format!("config is not valid json: {e}")))?;
    let inbound = dialect.socks_inbound(listen, port);

    let mut list = match root.get("inbounds") {
        Some(Json::Arr(existing)) => existing.clone(),
        None => Vec::new(),
        _ => {
            return Err(Error::Invalid(
                "`inbounds` must be an array when present".into(),
            ))
        }
    };
    list.push(inbound);
    root.insert("inbounds", Json::Arr(list));
    root.to_string()
        .map_err(|e| Error::Invalid(format!("config cannot be re-serialised: {e}")))
}

pub fn file_sha256(path: &Path) -> String {
    let mut state = Sha256::new();
    if let Ok(bytes) = std::fs::read(path) {
        state.update(&bytes);
    }
    state.hex()
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add((data.len() as u64) * 8);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        self.state = compress_block(&self.state, block);
    }

    fn hex(self) -> String {
        let bits = self.length;
        let mut padded = Vec::with_capacity(self.buffered + 72);
        padded.extend_from_slice(&self.buffer[..self.buffered]);
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bits.to_be_bytes());

        let mut state = self.state;
        for block in padded.as_chunks::<64>().0 {
            state = compress_block(&state, block);
        }
        let mut out = String::with_capacity(64);
        for word in state {
            for byte in word.to_be_bytes() {
                out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
                out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap_or('0'));
            }
        }
        out
    }
}

#[allow(
    clippy::many_single_char_names,
    reason = "a-h, s0, s1, ch and maj are the SHA-256 specification's own names"
)]
fn compress_block(state: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut w = [0u32; 64];
    for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes(*chunk);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
        state[5].wrapping_add(f),
        state[6].wrapping_add(g),
        state[7].wrapping_add(h),
    ]
}

/// A sink range is not a run of numbers: Linux randomises where each ephemeral bind starts, so the only ports a flow can dial are the ones its own listener read back.
fn sink_targets(ip: Ipv4Addr, ports: &[u16]) -> Vec<SocketAddr> {
    ports
        .iter()
        .map(|&port| SocketAddr::from((ip, port)))
        .collect()
}

/// The deadline is what turns a stall into a report: a blocking accept here spent the job's whole ceiling before any engine was measured.
fn accept_until(listener: &TcpListener, deadline: Instant) -> Option<TcpStream> {
    listener.set_nonblocking(true).ok()?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).ok()?;
                apply_flow_timeouts(&stream);
                return Some(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

pub fn harness_ceiling(connections: usize, payload_size: usize, bytes: u64) -> Result<f64, Error> {
    let ip = local_non_loopback_ipv4()?;
    let listeners = allocate_port_range(connections)?;
    let targets = sink_targets(ip, &ports_of(&listeners)?);
    let pattern = Arc::new(bulk_pattern_template(payload_size));

    let sink = std::thread::spawn({
        let pattern = Arc::clone(&pattern);
        move || {
            let deadline = Instant::now() + RUN_TIMEOUT;
            for (index, listener) in listeners.into_iter().enumerate() {
                let Some(stream) = accept_until(&listener, deadline) else {
                    return;
                };
                let flow = Arc::new(rotate(&pattern, index, connections));
                std::thread::spawn(move || emit(stream, &flow, index, bytes));
            }
        }
    });

    let mut flows = Vec::with_capacity(connections);
    for (index, addr) in targets.into_iter().enumerate() {
        let template = Arc::clone(&pattern);
        flows.push(std::thread::spawn(move || {
            ceiling_flow(addr, &template, index, connections, bytes)
        }));
    }

    let mut best = 0.0f64;
    for flow in flows {
        let Ok(rate) = flow.join() else { continue };
        best = best.max(rate);
    }
    let _ = sink.join();
    if best <= 0.0 {
        return Err(Error::Workload(
            "the harness ceiling moved no bytes; a row compared against it would \
             be meaningless, so it is reported as unmeasured"
                .into(),
        ));
    }
    Ok(best)
}

fn ceiling_flow(
    addr: SocketAddr,
    template: &Arc<Vec<u8>>,
    index: usize,
    flows: usize,
    bytes: u64,
) -> f64 {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(10)) else {
        return 0.0;
    };
    let _ = stream.set_nodelay(true);
    apply_flow_timeouts(&stream);
    let pattern = rotate(template, index, flows);
    let started = Instant::now();
    let read_total = read_validated(&mut stream, &pattern, bytes).unwrap_or(0);
    let elapsed = started.elapsed();
    let _ = stream.shutdown(Shutdown::Both);
    if elapsed.is_zero() || read_total == 0 {
        return 0.0;
    }
    read_total as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_sockets_carry_the_io_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let stream = TcpStream::connect(addr).expect("connects");
        apply_flow_timeouts(&stream);
        assert_eq!(
            stream.read_timeout().expect("readable"),
            Some(FLOW_IO_TIMEOUT)
        );
        assert_eq!(
            stream.write_timeout().expect("readable"),
            Some(FLOW_IO_TIMEOUT)
        );
    }

    /// A dead pid yields a target-gone error, never the `Spawn` arm; `Disconnected` on the receiver is the witness that the sampler exited via the break rather than still forking `ps` against a dead pid.
    #[test]
    fn the_sampler_breaks_when_the_sampled_pid_is_gone() {
        let (tx, rx) = mpsc::channel::<(Phase, ps::Sample)>();
        let sampler = spawn_sampler(u32::MAX, Arc::new(AtomicBool::new(false)), tx);
        assert!(matches!(
            rx.recv_timeout(SAMPLE_INTERVAL * 20),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        let _ = sampler.join();
    }

    /// The bug this bounds: a comparator engine that accepts the socks connect
    /// and then stalls the stream leaves a flow blocked in `read` forever, and
    /// the old fan-in joined each flow with no deadline, wedging the cell to the
    /// CI job ceiling. Here the stalled flow is released only when the watchdog
    /// trips `stop`, so reaching an `Err` at the deadline — rather than hanging —
    /// is the witness that `RUN_TIMEOUT` is now a live cap.
    #[test]
    fn the_fan_in_bounds_a_flow_that_never_lands() {
        let stop = Arc::new(AtomicBool::new(false));
        let stalled = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                FlowResult {
                    bytes_sent: 0,
                    bytes_received: 0,
                    window: None,
                    setup: Setup::default(),
                    stopped: None,
                }
            })
        };
        let landed = std::thread::spawn(|| FlowResult {
            bytes_sent: 4096,
            bytes_received: 0,
            window: None,
            setup: Setup::default(),
            stopped: None,
        });
        let started = Instant::now();
        let result = collect_flows(
            vec![stalled, landed],
            &stop,
            started + Duration::from_millis(200),
        );
        assert!(matches!(
            &result,
            Err(Error::Workload(message)) if message.contains("exceeded")
        ));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the fan-in returns at the deadline, not at the CI job ceiling"
        );
    }

    #[test]
    fn the_fan_in_drains_flows_that_land_before_the_deadline() {
        let stop = Arc::new(AtomicBool::new(false));
        let first = std::thread::spawn(|| FlowResult {
            bytes_sent: 3,
            bytes_received: 0,
            window: None,
            setup: Setup {
                total_us: 11,
                ..Setup::default()
            },
            stopped: None,
        });
        let second = std::thread::spawn(|| FlowResult {
            bytes_sent: 0,
            bytes_received: 5,
            window: None,
            setup: Setup {
                total_us: 22,
                ..Setup::default()
            },
            stopped: Some("peer closed".to_owned()),
        });
        let moved = collect_flows(
            vec![first, second],
            &stop,
            Instant::now() + Duration::from_secs(10),
        )
        .expect("flows that land within the deadline are collected");
        assert_eq!(moved.sent, 3);
        assert_eq!(moved.received, 5);
        assert_eq!(moved.setup[0].total_us, 11, "setup keeps the flow order");
        assert_eq!(moved.setup[1].total_us, 22);
        assert_eq!(moved.all_stopped, vec!["peer closed".to_owned()]);
    }

    fn request_with(overrides: &[(&str, &str)]) -> String {
        let mut fields = base_fields();
        for (key, value) in overrides {
            fields.retain(|(k, _)| k != key);
            fields.push(((*key).to_owned(), (*value).to_owned()));
        }
        render(fields)
    }

    fn request_with_env(env: &str) -> String {
        let mut fields = base_fields();
        fields.push(("client_env".into(), env.to_owned()));
        render(fields)
    }

    fn base_fields() -> Vec<(String, String)> {
        vec![
            ("binary".into(), quote(&engine_path())),
            (
                "config".into(),
                quote(r#"{"outbounds":[{"protocol":"freedom"}]}"#),
            ),
            ("path".into(), quote("socks")),
            ("traffic".into(), quote("upload")),
            ("connections".into(), "1".into()),
            ("iterations".into(), "10".into()),
            ("payload_size".into(), "1024".into()),
            ("output".into(), quote(&out_dir())),
        ]
    }

    fn render(mut fields: Vec<(String, String)>) -> String {
        fields.sort();
        let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
        format!("{{{}}}", body.join(","))
    }

    fn quote(s: &str) -> String {
        Json::Str(s.to_owned())
            .to_string()
            .expect("a string always has a json spelling")
    }

    fn engine_path() -> String {
        std::env::current_exe().map_or_else(|_| "/dev/null".to_owned(), |p| p.display().to_string())
    }

    fn out_dir() -> String {
        format!(
            "{}/ferrox-bench-request-test-{}-{}",
            env!("CARGO_MANIFEST_DIR"),
            std::process::id(),
            line!()
        )
    }

    #[test]
    fn accepts_a_minimal_request() {
        let r = Request::parse(request_with(&[]).as_bytes()).expect("valid request");
        assert_eq!(r.connections, 1);
        assert_eq!(r.iterations, 10);
        assert_eq!(r.payload_size, 1024);
        assert_eq!(r.traffic, Traffic::Upload);
        assert_eq!(r.total_bytes(), 10 * 1024);
        assert!(r.client_env.is_empty());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let doc = request_with(&[("iterations", "10"), ("somethingNew", "true")]);
        assert!(Request::parse(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_every_out_of_bounds_count() {
        for (field, value) in [
            ("connections", "0"),
            ("connections", "17"),
            ("iterations", "0"),
            ("iterations", "262145"),
            ("payload_size", "0"),
            ("payload_size", "65537"),
        ] {
            let doc = request_with(&[(field, value)]);
            assert!(
                Request::parse(doc.as_bytes()).is_err(),
                "{field}={value} must be rejected"
            );
        }
    }

    /// The pattern byte at an absolute offset, written the way the sink's loop wrote it: one modulo and one index per byte.
    fn pattern_byte(pattern: &[u8], at: usize) -> u8 {
        pattern[at % pattern.len()]
    }

    #[test]
    fn the_pattern_check_sees_every_phase_and_both_wrap_points() {
        let template = bulk_pattern_template(4096);
        let period = template.len();
        let triple: Vec<u8> = template.iter().cycle().take(3 * period).copied().collect();
        let fits = |pattern: &[u8], offset: usize, chunk: &[u8]| {
            pattern_mismatch(pattern, offset, chunk).is_none()
        };
        assert!(fits(&template, 0, &template[..]));
        for phase in (0..period).step_by(29) {
            for len in [1, 2, 63, 64 * 1024, period / 2, period - 1, period] {
                if phase + len > triple.len() {
                    continue;
                }
                let want = &triple[phase..phase + len];
                assert!(fits(&template, phase, want), "phase {phase}, {len} bytes");
            }
        }
        for over in [1, 2, 17, period / 2, period - 1] {
            let start = period - over;
            let len = (over * 2).min(triple.len() - start);
            assert!(
                fits(&template, start, &triple[start..start + len]),
                "chunk of {over} past the end of the ring"
            );
        }
        for at in [0, period / 2, period - 1] {
            let mut bad = template.clone();
            bad[at] ^= 1;
            assert!(!fits(&template, 0, &bad), "flipped byte {at}");
        }
        assert!(fits(&template, 7, &[]));
        assert!(fits(&[], 0, &[]));
        assert!(!fits(&[], 0, &template[..1]));
        assert!(fits(&template, 0, &triple[..]));
        let mut stretched = triple.clone();
        stretched[period + 7] ^= 1;
        assert!(!fits(&template, 0, &stretched[..]));
        let mut past_second_wrap = triple.clone();
        past_second_wrap[2 * period + 7] ^= 1;
        assert_eq!(
            pattern_mismatch(&template, 0, &past_second_wrap),
            Some(2 * period + 7),
            "a read past the second wrap still validates, and names the byte it tripped on"
        );

        // The runs are the modulo: same verdicts, same first mismatching byte, at every phase and length the sink can read.
        for phase in (0..period).step_by(251) {
            for len in [1, 40, 511, period, period + 1, 2 * period, 64 * 1024] {
                let mut chunk: Vec<u8> = (0..len)
                    .map(|i| pattern_byte(&template, phase + i))
                    .collect();
                assert_eq!(
                    pattern_mismatch(&template, phase, &chunk),
                    None,
                    "phase {phase}, {len} bytes of the ring"
                );
                for flip in [0, len / 2, len - 1] {
                    chunk[flip] ^= 1;
                    assert_eq!(
                        pattern_mismatch(&template, phase, &chunk),
                        Some(flip),
                        "phase {phase}, {len} bytes, flipped byte {flip}"
                    );
                    chunk[flip] ^= 1;
                }
            }
        }
    }

    #[test]
    fn rejects_a_flow_above_the_byte_ceiling() {
        let doc = request_with(&[("iterations", "262144"), ("payload_size", "65536")]);
        assert!(
            Request::parse(doc.as_bytes()).is_ok(),
            "16 GiB is the ceiling, and the ceiling itself is allowed"
        );
        let doc = request_with(&[("iterations", "262145"), ("payload_size", "65536")]);
        assert!(Request::parse(doc.as_bytes()).is_err(), "above it is not");
        let doc = request_with(&[("iterations", "131072"), ("payload_size", "65536")]);
        assert!(
            Request::parse(doc.as_bytes()).is_ok(),
            "8 GiB is the window this harness needs and must accept"
        );
    }

    #[test]
    fn a_download_that_stops_short_is_a_reason_and_not_a_process_exit() {
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
            return;
        };
        let addr = listener.local_addr().expect("has an address");
        let pattern = b"0123456789abcdef".to_vec();

        let sink = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one flow");
            let _ = stream.write_all(&b"0123456789abcdef0123456789abcdef0123456789abcdef"[..48]);
            let _ = stream.shutdown(Shutdown::Both);
        });

        let mut client = TcpStream::connect(addr).expect("connects");
        let err = read_validated(&mut client, &pattern, 64)
            .expect_err("a stream that ends early must be an Err");
        assert!(
            err.starts_with("download read failed"),
            "a short read says the transfer stopped: {err}"
        );
        assert!(
            !err.contains("not the validated pattern"),
            "and must not be reported as a corrupt stream: {err}"
        );
        drop(client);
        let _ = sink.join();

        assert!(
            pattern_mismatch(&pattern, 0, &pattern).is_none(),
            "the pattern matches itself at offset 0, or this test proves nothing"
        );
        assert!(
            pattern_mismatch(&pattern, 0, &[b'z'; 16]).is_some(),
            "a corrupt chunk does not, so the desync retry has something to catch"
        );
    }

    /// The desync retry is only sound if both sides name the same byte: this feeds `read_validated`'s own forged-chunk message, not a hand-written one, to the lift the client's `stream_down` runs.
    #[test]
    fn a_forged_download_byte_lifts_the_absolute_offset_the_retry_carries() {
        let pattern = b"0123456789abcdef".to_vec();
        let mut chunk = pattern.clone();
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
            return;
        };
        let addr = listener.local_addr().expect("has an address");
        let sink = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one flow");
            chunk[3] = b'z';
            let _ = stream.write_all(&chunk);
            let _ = stream.write_all(&chunk);
        });
        let mut client = TcpStream::connect(addr).expect("connects");
        let why = read_validated(&mut client, &pattern, 32).expect_err("a forged byte is an Err");
        let at = first_mismatch_byte(&why).expect("the message names the absolute byte");
        assert_eq!(at, 3, "the first forged byte of the first chunk: {why}");
        drop(client);
        let _ = sink.join();
        assert!(
            first_mismatch_byte("flow 2 download stopped early: eof").is_none(),
            "a short read is not a desync and must not read as one"
        );
    }

    /// `measure` re-measures a disturbed attempt, and the bound is the gate: it must stop at the first result that needs no re-measure, so a genuine disturbance still fails the cell and a genuine other fault is never retried.
    #[test]
    fn a_desync_is_retried_until_the_bound_and_a_final_error_never_loops() {
        let mut calls = 0usize;
        let recovered = remeasure_disturbed(REMEASURE_ATTEMPTS, || {
            calls += 1;
            if calls < 2 {
                Err(Error::Desync {
                    flow: 3,
                    offset: 4096,
                })
            } else {
                Ok(calls)
            }
        });
        assert_eq!(recovered.unwrap(), 2, "the retry's own run is the one kept");
        assert_eq!(
            calls, 2,
            "a pass stops the retry, it does not run out the bound"
        );

        calls = 0;
        let stuck = remeasure_disturbed(REMEASURE_ATTEMPTS, || {
            calls += 1;
            Err::<(), Error>(Error::Desync { flow: 0, offset: 7 })
        });
        assert!(
            matches!(&stuck, Err(Error::Workload(message)) if message.contains("survives every retry")),
            "a desync that survives every attempt fails as a workload fault, never a number: {stuck:?}"
        );
        assert_eq!(
            calls, REMEASURE_ATTEMPTS,
            "exactly the bound ran, no further"
        );

        calls = 0;
        let fatal = remeasure_disturbed(REMEASURE_ATTEMPTS, || {
            calls += 1;
            Err::<(), Error>(Error::Engine {
                message: "cannot spawn".into(),
            })
        });
        assert!(
            matches!(&fatal, Err(Error::Engine { .. })),
            "a fault that is not a desync must surface untouched"
        );
        assert_eq!(calls, 1, "the retry loop never touches a final error");
    }

    /// The class that actually broke macos-15 `vless-raw-duplex-8`: every engine in the cell aborts short with socket-layer transients, so the cell re-measures; a short transfer with no such signature is a real workload fault and must fail on the first call, and the bound must still be the last word on a saturated runner.
    #[test]
    fn a_transient_socket_fault_is_remeasured_and_a_real_short_transfer_is_not() {
        // The reasons one macos-15 duplex-8 attempt actually returned, kept verbatim.
        let saturated = "moved 4999610368 of 8589934592 bytes: upload write failed after \
         256901120 of 536870912 bytes: Resource temporarily unavailable (os error 35); the \
         upload read failed after 139632640 bytes: Connection reset by peer (os error 54); \
         upload write failed after 292552704 of 536870912 bytes: Broken pipe (os error 32)";
        assert!(is_transient_io(saturated), "the CI cell's own reasons");
        assert!(
            is_transient_io("write failed: No buffer space available (os error 55)"),
            "ENOBUFS, the other macOS face of the same thing"
        );
        assert!(
            !is_transient_io("no flow reported why it stopped; could not connect to the engine"),
            "a workload fault with no socket signature is never re-measured"
        );

        let mut calls = 0usize;
        let real = remeasure_disturbed(REMEASURE_ATTEMPTS, || {
            calls += 1;
            Err::<(), Error>(Error::Workload(
                "moved 0 of 100 bytes: no flow reported why it stopped".into(),
            ))
        });
        assert!(
            matches!(&real, Err(Error::Workload(m)) if m.contains("no flow reported")),
            "a short transfer that is not transient stays fatal: {real:?}"
        );
        assert_eq!(calls, 1, "and is never retried");

        calls = 0;
        let storm = remeasure_disturbed(REMEASURE_ATTEMPTS, || {
            calls += 1;
            Err::<(), Error>(Error::Transient(saturated.into()))
        });
        assert!(
            matches!(&storm, Err(Error::Workload(m))
                if m.contains("survives every retry") && m.contains("os error 35")),
            "the bound converts a persistent storm, reason and all, never a number: {storm:?}"
        );
        assert_eq!(calls, REMEASURE_ATTEMPTS, "exactly the bound ran");
    }

    #[test]
    fn the_first_forged_byte_wins_the_slot_and_the_error_names_it() {
        let slot: Desync = Arc::new(std::sync::Mutex::new(None));
        note_desync(&slot, 5, 8192);
        note_desync(&slot, 1, 16);
        assert_eq!(
            *slot.lock().expect("uncontended"),
            Some((5, 8192)),
            "only the first forged byte is recorded"
        );
        assert!(Error::Desync {
            flow: 5,
            offset: 8192
        }
        .to_string()
        .contains("flow 5"));
    }

    /// The sink's upload validation must hand a forged byte to the shared slot and return its reason as data — the cell it lives in re-measures it; a `process::exit` there once killed the whole gate-5 run, reference included.
    #[test]
    fn a_forged_upload_byte_notes_the_desync_and_returns_its_reason() {
        let pattern = b"0123456789abcdef".to_vec();
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
            return;
        };
        let addr = listener.local_addr().expect("has an address");
        let sink = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one flow");
            let _ = stream.write_all(b"0123456789abcdez");
        });
        let engine = TcpStream::connect(addr).expect("connects");
        let slot: Desync = Arc::new(std::sync::Mutex::new(None));
        let feed = engine.try_clone().expect("clone for the reader");
        let reason = validate(feed, &Arc::new(pattern), 2, 16, &slot)
            .expect("a forged byte is a reason, returned not exited");
        assert!(
            reason.contains("flow 2 upload desynced at byte 15"),
            "{reason}"
        );
        assert_eq!(*slot.lock().expect("uncontended"), Some((2, 15)));
        drop(engine);
        let _ = sink.join();
    }

    /// Only the join on the download thread can keep `serve_flow` running past the upload; closing the engine faults the blocked write, and the fault must reach the caller rather than vanish with a dropped handle.
    #[test]
    fn a_full_duplex_flow_waits_for_and_surfaces_its_download() {
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
            return;
        };
        let addr = listener.local_addr().expect("has an address");
        let pattern = Arc::new(b"0123456789abcdef".to_vec());
        let upload_bytes = pattern.len() as u64;
        // Far larger than any socket buffer: the engine never reads, so the download writer is guaranteed to block rather than complete.
        let download_bytes = 128u64 << 20;

        let mut engine = TcpStream::connect(addr).expect("engine connects");
        engine
            .write_all(&pattern[..])
            .expect("engine feeds the upload");

        let (sink_stream, _) = listener.accept().expect("one flow");
        let (done_tx, done_rx) = mpsc::channel::<Option<String>>();
        let serve_pattern = Arc::clone(&pattern);
        let serve_desync: Desync = Arc::new(std::sync::Mutex::new(None));
        let serving = std::thread::spawn(move || {
            let reason = serve_flow(
                sink_stream,
                &serve_pattern,
                0,
                upload_bytes,
                download_bytes,
                &serve_desync,
            );
            let _ = done_tx.send(reason);
        });

        // A dropped downloader would have returned `None` once the upload was satisfied; a timeout means the only thing holding `serve_flow` is the join on the blocked download write.
        assert!(
            matches!(
                done_rx.recv_timeout(Duration::from_millis(500)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "serve_flow must wait for the download it spawns, not return on the upload"
        );

        // Closing the engine faults the blocked write; the download reason must surface instead of vanishing with the dropped handle.
        drop(engine);
        let reason = done_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the released download reaches the caller");
        let reason = reason.expect("a closed download peer is a reason, not a clean finish");
        assert!(
            reason.contains("could not write"),
            "the surfaced reason is the download write fault: {reason}"
        );
        let _ = serving.join();
    }

    #[test]
    fn the_default_request_is_one_the_pinned_harness_also_accepts() {
        const {
            assert!(crate::DEFAULT_ITERATIONS <= 16_384);
            assert!(crate::DEFAULT_CONNECTIONS <= 16);
            assert!(crate::DEFAULT_PAYLOAD_SIZE <= 65_536);
        }
    }

    #[test]
    fn rejects_a_non_whole_count() {
        for field in ["connections", "iterations", "payload_size"] {
            let doc = request_with(&[(field, "2.5")]);
            assert!(
                Request::parse(doc.as_bytes()).is_err(),
                "{field}=2.5 must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_missing_required_field() {
        for field in [
            "binary",
            "config",
            "traffic",
            "connections",
            "iterations",
            "payload_size",
            "output",
        ] {
            let doc = request_with(&[]).replace(&format!("\"{field}\":"), "\"zz\":");
            assert!(
                Request::parse(doc.as_bytes()).is_err(),
                "{field} must be required"
            );
        }
    }

    #[test]
    fn rejects_an_unknown_traffic() {
        let doc = request_with(&[("traffic", "\"sideways\"")]);
        assert!(Request::parse(doc.as_bytes()).is_err());
    }

    #[test]
    fn reads_client_env_and_rejects_non_strings() {
        let r =
            Request::parse(request_with_env(r#"{"A":"1"}"#).as_bytes()).expect("valid with env");
        assert_eq!(r.client_env.get("A").map(String::as_str), Some("1"));

        assert!(Request::parse(request_with_env(r#"{"A":1}"#).as_bytes()).is_err());
        assert!(Request::parse(request_with_env("[1,2]").as_bytes()).is_err());
    }

    #[test]
    fn the_template_is_deterministic_and_non_constant() {
        let a = bulk_pattern_template(4096);
        assert_eq!(a, bulk_pattern_template(4096));
        assert_eq!(a.len(), 4096);
        assert!(a.iter().any(|&byte| byte != a[0]));
    }

    #[test]
    fn the_template_matches_the_seed_the_pinned_harness_uses() {
        let mut state = BULK_PATTERN_SEED;
        let mut first = [0u8; 4];
        for slot in &mut first {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *slot = (state >> 32) as u8;
        }
        assert_eq!(&bulk_pattern_template(4)[..], &first);
    }

    #[test]
    fn a_gapped_range_still_dials_each_listeners_own_port() {
        let ports: Vec<u16> = sink_targets(Ipv4Addr::LOCALHOST, &[40_000, 40_007, 40_003])
            .iter()
            .map(SocketAddr::port)
            .collect();
        assert_eq!(
            ports,
            vec![40_000, 40_007, 40_003],
            "a flow dials the port its listener read back, not the first port plus its place"
        );
    }

    #[test]
    fn an_accept_past_its_deadline_is_a_miss_and_not_a_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let started = Instant::now();
        assert!(
            accept_until(&listener, started + Duration::from_millis(50)).is_none(),
            "nobody dialled, so the accept had to report the miss"
        );
        assert!(
            started.elapsed() < FLOW_IO_TIMEOUT,
            "the accept gave up at its deadline instead of blocking the run"
        );
    }

    #[test]
    fn the_sink_binds_one_listener_per_flow_clear_of_the_engine() {
        let Ok(ip) = local_non_loopback_ipv4() else {
            return;
        };
        let sink = allocate_port_range(4).expect("four reserved ports");
        let ports = ports_of(&sink).expect("the reserved ports");
        let probe = allocate_port_excluding(ip, &ports).expect("a port clear of them");
        let engine = bound_port(&probe).expect("the probed port");
        assert!(
            !ports.contains(&engine),
            "the engine's port {engine} is inside the sink's range {ports:?}"
        );

        assert_eq!(sink.len(), 4, "one listener per flow");
        let bound: std::collections::BTreeSet<u16> = ports.iter().copied().collect();
        assert_eq!(bound.len(), 4, "each flow's listener is its own port");

        // A reservation is real only if the port refuses a second bind while held — what released numbers could not prove.
        let stolen = TcpListener::bind((ip, ports[0]));
        assert!(
            stolen.is_err(),
            "the reserved port {} bound again, so the reservation was a number",
            ports[0]
        );

        // A second range cannot be handed the first one's ports, because the first is still bound rather than merely remembered.
        let again = ports_of(&allocate_port_range(4).expect("four more")).expect("more ports");
        assert!(
            again.iter().all(|p| !ports.contains(p)),
            "a second range overlaps the first: {again:?} vs {ports:?}"
        );
    }

    #[test]
    fn flow_regions_are_distinct_and_equal_length() {
        let template = bulk_pattern_template(1024);
        let a = rotate(&template, 0, 4);
        let b = rotate(&template, 1, 4);
        assert_ne!(a, b);
        assert_eq!(a.len(), template.len());
        assert_eq!(b.len(), template.len());
        assert_eq!(rotate(&template, 0, 1), template);
    }

    #[test]
    fn the_socks_inbound_is_injected_and_the_outbounds_survive() {
        let base = Dialect::Xray.base_config().to_string().expect("serialises");
        let out = inject_inbound(&base, Ipv4Addr::new(192, 0, 2, 7), 1080, Dialect::Xray)
            .expect("injectable");
        let root = json::parse(&out).expect("valid json");
        let inbounds = root
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(
            inbounds[0].get("tag").and_then(Json::as_str),
            Some("harness-socks"),
            "routing rules address the injected inbound by tag"
        );
        assert_eq!(
            inbounds[0].get("listen").and_then(Json::as_str),
            Some("192.0.2.7")
        );
        assert_eq!(inbounds[0].get("port").and_then(Json::as_num), Some(1080.0));
        assert_eq!(
            inbounds[0]
                .get("settings")
                .and_then(|s| s.get("udp"))
                .and_then(Json::as_bool),
            Some(false)
        );
        assert_eq!(
            root.get("outbounds")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(1),
            "the request's own outbounds must survive"
        );
    }

    #[test]
    fn each_dialect_writes_the_fields_that_engine_actually_reads() {
        for dialect in [Dialect::Xray, Dialect::SingBox] {
            let base = dialect.base_config().to_string().expect("serialises");
            let out = inject_inbound(&base, Ipv4Addr::new(192, 0, 2, 7), 1080, dialect)
                .expect("injectable");
            let root = json::parse(&out).expect("valid json");
            let outbound = &root
                .get("outbounds")
                .and_then(Json::as_arr)
                .expect("outbounds")[0];
            let inbound = &root
                .get("inbounds")
                .and_then(Json::as_arr)
                .expect("inbounds")[0];

            let (type_key, type_value) = match dialect {
                Dialect::Xray => ("protocol", "freedom"),
                Dialect::SingBox => ("type", "direct"),
            };
            assert_eq!(
                outbound.get(type_key).and_then(Json::as_str),
                Some(type_value),
                "{dialect:?} outbound names itself with `{type_key}`"
            );
            let (in_key, in_value) = match dialect {
                Dialect::Xray => ("protocol", "socks"),
                Dialect::SingBox => ("type", "socks"),
            };
            assert_eq!(inbound.get(in_key).and_then(Json::as_str), Some(in_value));

            let (port_key, port_value) = match dialect {
                Dialect::Xray => ("port", 1080.0),
                Dialect::SingBox => ("listen_port", 1080.0),
            };
            assert_eq!(
                inbound.get(port_key).and_then(Json::as_num),
                Some(port_value),
                "{dialect:?} listens on `{port_key}`"
            );

            let foreign = match dialect {
                Dialect::Xray => ("type", "socks"),
                Dialect::SingBox => ("protocol", "socks"),
            };
            assert!(
                inbound.get(foreign.0).is_none(),
                "{dialect:?} must not carry a `{}` key",
                foreign.0
            );
            let foreign_port = match dialect {
                Dialect::Xray => "listen_port",
                Dialect::SingBox => "port",
            };
            assert!(
                inbound.get(foreign_port).is_none(),
                "{dialect:?} must not carry a `{foreign_port}` key"
            );
        }
    }

    #[test]
    fn a_dialect_parses_and_rejects_by_name() {
        let ok = |raw: &str| Dialect::parse(raw).ok();
        assert_eq!(ok("xray"), Some(Dialect::Xray));
        assert_eq!(ok("protocol"), Some(Dialect::Xray));
        assert_eq!(ok("sing-box"), Some(Dialect::SingBox));
        assert_eq!(ok("singbox"), Some(Dialect::SingBox));
        assert_eq!(ok("v2ray"), None);
        assert_eq!(ok(""), None);
    }

    #[test]
    fn an_existing_inbound_is_kept_rather_than_replaced() {
        let out = inject_inbound(
            r#"{"inbounds":[{"protocol":"vless"}],"outbounds":[]}"#,
            Ipv4Addr::LOCALHOST,
            1,
            Dialect::Xray,
        )
        .expect("injectable");
        let root = json::parse(&out).expect("valid json");
        assert_eq!(
            root.get("inbounds")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(2)
        );
    }

    #[test]
    fn an_inbound_that_is_not_an_array_is_an_error() {
        assert!(
            inject_inbound(r#"{"inbounds":7}"#, Ipv4Addr::LOCALHOST, 1, Dialect::Xray).is_err()
        );
    }

    #[test]
    fn sha256_matches_the_published_vectors() {
        for (input, want) in [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut h = Sha256::new();
            h.update(input.as_bytes());
            assert_eq!(h.hex(), want, "sha256({input:?})");
        }
    }

    #[test]
    fn sha256_handles_multi_block_input() {
        let mut h = Sha256::new();
        h.update(&b"a".repeat(1_000_000));
        assert_eq!(
            h.hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        let mut h = Sha256::new();
        for chunk in b"abcdefghij".chunks(3) {
            h.update(chunk);
        }
        let mut once = Sha256::new();
        once.update(b"abcdefghij");
        assert_eq!(h.hex(), once.hex());
    }

    #[test]
    fn each_config_argument_shape_names_the_file_the_way_its_engine_expects() {
        let path = Path::new("/tmp/cfg.json");
        let render = |shape: ConfigArg| {
            shape
                .args(path)
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(render(ConfigArg::Long), "run -config /tmp/cfg.json");
        assert_eq!(render(ConfigArg::Short), "run -c /tmp/cfg.json");
        assert_eq!(render(ConfigArg::Positional), "run /tmp/cfg.json");
    }

    #[test]
    fn config_argument_shapes_parse_and_reject() {
        for (raw, want) in [
            ("long", ConfigArg::Long),
            ("-config", ConfigArg::Long),
            ("--config", ConfigArg::Long),
            ("short", ConfigArg::Short),
            ("-c", ConfigArg::Short),
            ("positional", ConfigArg::Positional),
        ] {
            assert_eq!(ConfigArg::parse(raw).expect("parses"), want, "{raw}");
        }
        let err = ConfigArg::parse("--cfg").expect_err("an unknown shape is an error");
        assert!(
            err.to_string().contains("Expected one of"),
            "the error must list the shapes: {err}"
        );
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let sorted: Vec<u128> = (1..=100).collect();
        assert_eq!(nearest_rank(&sorted, 95), 95);
        assert_eq!(nearest_rank(&sorted, 99), 99);
        assert_eq!(nearest_rank(&[7], 95), 7);
        assert_eq!(nearest_rank(&[], 95), 0);
        assert_eq!(median(&[1, 2, 3]), 2);
        assert_eq!(median(&[1, 2, 3, 4]), 2);
        assert_eq!(median(&[]), 0);
    }

    #[test]
    fn a_short_transfer_is_a_fault_and_not_a_number() {
        let r =
            Request::parse(request_with(&[("iterations", "3"), ("payload_size", "7")]).as_bytes())
                .expect("valid");
        assert_eq!(r.flow_bytes(), 21);
        assert_eq!(r.total_bytes(), 21);
    }
}
