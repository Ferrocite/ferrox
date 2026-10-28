//! The health observatory the balancers read: xray's legacy probe loop, its burst sampler,
//! and the two URL shapes they speak through a configured outbound.

use crate::json::Json;
use crate::proxy::{Destination, Outbound};
use crate::router::{HealthPing, Observed};
use ferrox_core::tls::TlsProvider as _;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LEGACY_URL: &str = "https://www.google.com/generate_204";
const BURST_URL: &str = "https://connectivitycheck.gstatic.com/generate_204";
const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
const BURST_INTERVAL: Duration = Duration::from_secs(60);
const BURST_MIN_INTERVAL: Duration = Duration::from_secs(10);
const BURST_TIMEOUT: Duration = Duration::from_secs(5);
const BURST_SAMPLES: usize = 10;
const FAILED: i64 = i64::MAX;
const UNTESTED: i64 = i64::MAX - 1;
const CHROME_MAJOR: u8 = 144;
static RANDOM: AtomicU64 = AtomicU64::new(0);

/// The latest reading for every selected outbound, shared with every route plan.
#[derive(Debug)]
pub(crate) struct Observatory {
    snapshot: Mutex<Arc<[Observed]>>,
}

impl Observatory {
    pub(crate) fn snapshot(&self) -> Arc<[Observed]> {
        match self.snapshot.lock() {
            Ok(snapshot) => Arc::clone(&snapshot),
            Err(_) => Arc::from(Vec::new()),
        }
    }

    fn publish(&self, statuses: &[Observed]) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            *snapshot = Arc::from(statuses.to_vec());
        }
    }
}

/// Start the observatory a config names. The legacy app wins when both are configured, as the
/// reference's first-of-type feature lookup does, but both are parsed so neither can hide a
/// malformed block.
pub(crate) fn start(root: &Json) -> Result<Option<Arc<Observatory>>, String> {
    let legacy = root
        .get("observatory")
        .filter(|value| !matches!(value, Json::Null))
        .map(Legacy::parse)
        .transpose()?;
    let burst = root
        .get("burstObservatory")
        .filter(|value| !matches!(value, Json::Null))
        .map(Burst::parse)
        .transpose()?;
    let mode = match (legacy, burst) {
        (Some(legacy), burst) => {
            drop(burst);
            Mode::Legacy(legacy)
        }
        (None, Some(burst)) => Mode::Burst(burst),
        (None, None) => return Ok(None),
    };
    let observatory = Arc::new(Observatory {
        snapshot: Mutex::new(Arc::from(Vec::new())),
    });
    match mode {
        Mode::Legacy(config) => spawn_legacy(&observatory, root, config),
        Mode::Burst(config) => spawn_burst(&observatory, root, config),
    }
    Ok(Some(observatory))
}

enum Mode {
    Legacy(Legacy),
    Burst(Burst),
}

#[derive(Debug)]
struct Legacy {
    selectors: Vec<String>,
    url: String,
    interval: Duration,
    concurrency: bool,
}

impl Legacy {
    fn parse(value: &Json) -> Result<Self, String> {
        let pairs = object(value, "observatory")?;
        let mut selectors = Vec::new();
        let mut url = None;
        let mut interval = None;
        let mut concurrency = false;
        for (key, field) in pairs {
            match key.as_str() {
                "subjectSelector" => selectors = selectors_of(field, "observatory")?,
                "probeURL" => {
                    if let Some(text) = field.as_str() {
                        if !text.is_empty() {
                            url = Some(text.to_owned());
                        }
                    }
                }
                "probeInterval" => interval = crate::config::go_duration(field)?,
                "enableConcurrency" => concurrency = field.as_bool().unwrap_or(false),
                _ => {}
            }
        }
        Ok(Self {
            selectors,
            url: url.unwrap_or_else(|| LEGACY_URL.to_owned()),
            interval: interval
                .and_then(|nanos| u64::try_from(nanos).ok())
                .filter(|nanos| *nanos != 0)
                .map_or(DEFAULT_INTERVAL, Duration::from_nanos),
            concurrency,
        })
    }
}

#[derive(Debug)]
struct Burst {
    selectors: Vec<String>,
    settings: BurstSettings,
}

impl Burst {
    fn parse(value: &Json) -> Result<Self, String> {
        let pairs = object(value, "burstObservatory")?;
        let mut selectors = Vec::new();
        let mut ping = None;
        for (key, field) in pairs {
            match key.as_str() {
                "subjectSelector" => selectors = selectors_of(field, "burstObservatory")?,
                "pingConfig" => ping = Some(field),
                _ => {}
            }
        }
        let ping = ping.ok_or("burstObservatory has no pingConfig")?;
        Ok(Self {
            selectors,
            settings: BurstSettings::parse(ping)?,
        })
    }
}

#[derive(Debug)]
struct BurstSettings {
    destination: String,
    connectivity: String,
    interval: Duration,
    samples: usize,
    timeout: Duration,
    method: String,
}

impl BurstSettings {
    fn parse(value: &Json) -> Result<Self, String> {
        let pairs = object(value, "burstObservatory pingConfig")?;
        let mut destination = None;
        let mut connectivity = String::new();
        let mut interval = None;
        let mut samples = 0i32;
        let mut timeout = None;
        let mut method = None;
        for (key, field) in pairs {
            match key.as_str() {
                "destination" => destination = field.as_str().map(str::to_owned),
                "connectivity" => {
                    if let Some(text) = field.as_str() {
                        text.trim().clone_into(&mut connectivity);
                    }
                }
                "interval" => interval = crate::config::go_duration(field)?,
                "sampling" => {
                    samples = field
                        .as_u32()
                        .and_then(|value| i32::try_from(value).ok())
                        .unwrap_or(0);
                }
                "timeout" => timeout = crate::config::go_duration(field)?,
                "httpMethod" => method = field.as_str().map(str::to_owned),
                _ => {}
            }
        }
        let interval = interval.map_or(BURST_INTERVAL, |nanos| {
            if nanos == 0 {
                BURST_INTERVAL
            } else if nanos < BURST_MIN_INTERVAL.as_nanos() as i64 {
                BURST_MIN_INTERVAL
            } else {
                Duration::from_nanos(nanos as u64)
            }
        });
        let timeout = timeout
            .and_then(|nanos| u64::try_from(nanos).ok())
            .filter(|nanos| *nanos != 0)
            .map_or(BURST_TIMEOUT, Duration::from_nanos);
        let method = method.map_or_else(
            || "HEAD".to_owned(),
            |method| {
                let method = method.trim();
                if method.is_empty() {
                    "HEAD".to_owned()
                } else {
                    method.to_owned()
                }
            },
        );
        Ok(Self {
            destination: destination
                .map(|url| url.trim().to_owned())
                .filter(|url| !url.is_empty())
                .unwrap_or_else(|| BURST_URL.to_owned()),
            connectivity,
            interval,
            samples: if samples <= 0 {
                BURST_SAMPLES
            } else {
                usize::try_from(samples).unwrap_or(BURST_SAMPLES)
            },
            timeout,
            method,
        })
    }
}

fn object<'a>(value: &'a Json, what: &str) -> Result<&'a [(String, Json)], String> {
    match value {
        Json::Obj(pairs) => Ok(pairs),
        _ => Err(format!("{what} is not an object")),
    }
}

fn selectors_of(value: &Json, what: &str) -> Result<Vec<String>, String> {
    if matches!(value, Json::Null) {
        return Ok(Vec::new());
    }
    if let Some(text) = value.as_str() {
        return Ok(text
            .split(',')
            .map(str::trim)
            .filter(|selector| !selector.is_empty())
            .map(str::to_owned)
            .collect());
    }
    let Some(items) = value.as_arr() else {
        return Err(format!("{what} subjectSelector is not a list"));
    };
    let mut selectors = Vec::with_capacity(items.len());
    for item in items {
        selectors.push(
            item.as_str()
                .ok_or_else(|| format!("{what} subjectSelector has a non-string value"))?
                .to_owned(),
        );
    }
    Ok(selectors)
}

fn targets(root: &Json, selectors: &[String]) -> Vec<(String, Outbound)> {
    if selectors.is_empty() {
        return Vec::new();
    }
    let mut tags: Vec<(String, &Json)> = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&[])
        .iter()
        .filter_map(|outbound| {
            let tag = outbound.get("tag").and_then(Json::as_str).unwrap_or("");
            (!tag.is_empty() && selectors.iter().any(|selector| tag.starts_with(selector)))
                .then(|| (tag.to_owned(), outbound))
        })
        .collect();
    tags.sort_by(|left, right| left.0.cmp(&right.0));
    tags.into_iter()
        .filter_map(
            |(tag, config)| match crate::proxy::build_outbound(config, &tag) {
                Ok(outbound) => Some((tag, outbound)),
                Err(reason) => {
                    eprintln!("observatory: {reason}; the tag is not probed");
                    None
                }
            },
        )
        .collect()
}

fn spawn_legacy(observatory: &Arc<Observatory>, root: &Json, config: Legacy) {
    let targets = targets(root, &config.selectors);
    let observatory = Arc::clone(observatory);
    std::thread::spawn(move || {
        let mut statuses: Vec<Observed> = Vec::new();
        loop {
            if targets.is_empty() {
                std::thread::sleep(config.interval);
                continue;
            }
            if config.concurrency {
                let shared = Arc::new(Mutex::new(std::mem::take(&mut statuses)));
                let mut workers = Vec::with_capacity(targets.len());
                for (tag, outbound) in &targets {
                    let statuses = Arc::clone(&shared);
                    let observatory = Arc::clone(&observatory);
                    let url = config.url.clone();
                    let tag = tag.clone();
                    let outbound = outbound.clone();
                    workers.push(std::thread::spawn(move || {
                        let result = probe(&outbound, &url, "GET", Duration::from_secs(5), false);
                        update_legacy(&statuses, &observatory, &tag, &result);
                    }));
                }
                for worker in workers {
                    let _ = worker.join();
                }
                statuses = Arc::try_unwrap(shared)
                    .ok()
                    .and_then(|shared| shared.into_inner().ok())
                    .unwrap_or_default();
                std::thread::sleep(config.interval);
                continue;
            }
            for (tag, outbound) in &targets {
                let result = probe(outbound, &config.url, "GET", Duration::from_secs(5), false);
                update_legacy_status(&mut statuses, &observatory, tag, &result);
                std::thread::sleep(config.interval);
            }
        }
    });
}

fn update_legacy(
    statuses: &Mutex<Vec<Observed>>,
    observatory: &Observatory,
    tag: &str,
    result: &Result<Duration, String>,
) {
    if let Ok(mut statuses) = statuses.lock() {
        update_legacy_status(&mut statuses, observatory, tag, result);
    }
}

fn update_legacy_status(
    statuses: &mut Vec<Observed>,
    observatory: &Observatory,
    tag: &str,
    result: &Result<Duration, String>,
) {
    let (alive, delay) = match result {
        Ok(delay) => (true, delay.as_millis() as i64),
        Err(_) => (false, 99_999_999),
    };
    if let Some(status) = statuses.iter_mut().find(|status| status.tag == tag) {
        status.alive = alive;
        status.delay_ms = delay;
        status.health = None;
    } else {
        statuses.push(Observed {
            tag: tag.to_owned(),
            alive,
            delay_ms: delay,
            health: None,
        });
    }
    observatory.publish(statuses);
}

fn spawn_burst(observatory: &Arc<Observatory>, root: &Json, config: Burst) {
    let targets = targets(root, &config.selectors);
    let observatory = Arc::clone(observatory);
    std::thread::spawn(move || {
        let window = config
            .settings
            .interval
            .saturating_mul(config.settings.samples as u32);
        if targets.is_empty() {
            loop {
                std::thread::sleep(window);
            }
        }
        let mut results: Vec<(String, Ring)> = Vec::new();
        burst_check(
            &observatory,
            &targets,
            &config.settings,
            &mut results,
            1,
            Duration::ZERO,
        );
        loop {
            std::thread::sleep(window);
            burst_check(
                &observatory,
                &targets,
                &config.settings,
                &mut results,
                config.settings.samples,
                window,
            );
        }
    });
}

fn burst_check(
    observatory: &Observatory,
    targets: &[(String, Outbound)],
    settings: &BurstSettings,
    results: &mut Vec<(String, Ring)>,
    rounds: usize,
    window: Duration,
) {
    let count = targets.len().saturating_mul(rounds);
    if count == 0 {
        return;
    }
    let (send, receive) = std::sync::mpsc::channel();
    let window_nanos = u64::try_from(window.as_nanos()).unwrap_or(0);
    for (tag, outbound) in targets {
        for _ in 0..rounds {
            let send = send.clone();
            let tag = tag.clone();
            let outbound = outbound.clone();
            let destination = settings.destination.clone();
            let connectivity = settings.connectivity.clone();
            let method = settings.method.clone();
            let timeout = settings.timeout;
            let delay = random_below(window_nanos);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_nanos(delay));
                let value = match probe(&outbound, &destination, &method, timeout, true) {
                    Ok(delay) => delay.as_nanos() as i64,
                    Err(_) if !connectivity.is_empty() => {
                        if probe(
                            &Outbound::Freedom(Arc::default()),
                            &connectivity,
                            &method,
                            timeout,
                            true,
                        )
                        .is_ok()
                        {
                            FAILED
                        } else {
                            0
                        }
                    }
                    Err(_) => FAILED,
                };
                let _ = send.send((tag, value));
            });
        }
    }
    drop(send);
    for (tag, value) in receive.iter().take(count) {
        if value <= 0 {
            continue;
        }
        let ring = if let Some((_, ring)) = results.iter_mut().find(|(name, _)| name == &tag) {
            ring
        } else {
            results.push((
                tag.clone(),
                Ring::new(
                    settings.samples,
                    settings
                        .interval
                        .saturating_mul(settings.samples as u32)
                        .saturating_mul(2),
                ),
            ));
            &mut results.last_mut().expect("just pushed").1
        };
        ring.put(value);
    }
    publish_burst(observatory, results);
}

fn publish_burst(observatory: &Observatory, results: &[(String, Ring)]) {
    let statuses: Vec<Observed> = results
        .iter()
        .map(|(tag, ring)| {
            let stats = ring.stats();
            Observed {
                tag: tag.clone(),
                alive: stats.all != stats.fail,
                delay_ms: stats.average / 1_000_000,
                health: Some(stats),
            }
        })
        .collect();
    observatory.publish(&statuses);
}

struct Ring {
    slots: Vec<Sample>,
    index: usize,
    validity: Duration,
}

struct Sample {
    at: Option<Instant>,
    value: i64,
}

impl Ring {
    fn new(capacity: usize, validity: Duration) -> Self {
        Self {
            slots: (0..capacity)
                .map(|_| Sample {
                    at: None,
                    value: UNTESTED,
                })
                .collect(),
            index: capacity.saturating_sub(1),
            validity,
        }
    }

    fn put(&mut self, value: i64) {
        if self.slots.is_empty() {
            return;
        }
        self.index = (self.index + 1) % self.slots.len();
        self.slots[self.index] = Sample {
            at: Some(Instant::now()),
            value,
        };
    }

    #[allow(clippy::cast_precision_loss)]
    fn stats(&self) -> HealthPing {
        let now = Instant::now();
        let mut fail = 0i64;
        let mut count = 0i64;
        let mut sum = 0i64;
        let mut valid = Vec::with_capacity(self.slots.len());
        for sample in &self.slots {
            if sample.value == UNTESTED
                || sample
                    .at
                    .is_none_or(|at| now.duration_since(at) > self.validity)
            {
                continue;
            }
            if sample.value == FAILED {
                fail += 1;
                continue;
            }
            count += 1;
            sum = sum.saturating_add(sample.value);
            valid.push(sample.value);
        }
        let all = count + fail;
        if count == 0 {
            return HealthPing {
                all,
                fail,
                ..HealthPing::default()
            };
        }
        let average = sum / count;
        let deviation = if count < 2 {
            average / 2
        } else {
            let variance = valid
                .iter()
                .map(|value| {
                    let delta = (value - average) as f64;
                    delta * delta
                })
                .sum::<f64>()
                / count as f64;
            variance.sqrt() as i64
        };
        HealthPing {
            all,
            fail,
            deviation,
            average,
        }
    }
}

fn probe(
    outbound: &Outbound,
    target: &str,
    method: &str,
    timeout: Duration,
    read_body: bool,
) -> Result<Duration, String> {
    let url = ProbeUrl::parse(target)?;
    let started = Instant::now();
    let destination = Destination::Name(url.host.clone(), url.port);
    let stream = crate::proxy::probe_stream(outbound, &destination, timeout)
        .ok_or_else(|| format!("cannot dial {target}"))?;
    if url.tls {
        let config = ferrox_core::tls::TlsConfig {
            server_name: url.host.clone(),
            alpn: Vec::new().into(),
            roots: crate::quic::system_roots(),
            cert_pins: std::sync::Arc::default(),
            pins: ferrox_core::foxy::pin::Pins::default(),
            cipher_suites: std::sync::Arc::default(),
            insecure: false,
            fingerprint: None,
            ech_config_list: None,
            websocket: false,
        };
        let mut session = ferrox_core::tls::RustlsProvider::connect(&config, stream)
            .map_err(|error| error.to_string())?;
        session.handshake().map_err(|error| error.to_string())?;
        round_trip(&mut session, &url, method, read_body)?;
    } else {
        let mut stream = stream;
        round_trip(&mut stream, &url, method, read_body)?;
    }
    Ok(started.elapsed())
}

fn round_trip(
    io: &mut (impl Read + Write),
    url: &ProbeUrl,
    method: &str,
    read_body: bool,
) -> Result<(), String> {
    let request = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Language: en-US,en;q=0.9\r\nDNT: 1\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nSec-CH-UA: \"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"\r\nSec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-User: ?1\r\nSec-Fetch-Dest: document\r\nPriority: u=0, i\r\nConnection: close\r\n\r\n",
        url.path, url.authority, CHROME_MAJOR
    );
    io.write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    io.flush().map_err(|error| error.to_string())?;
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 4096];
    loop {
        let read = io.read(&mut buf).map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("the peer closed before a response head".to_owned());
        }
        head.extend_from_slice(&buf[..read]);
        if let Some(end) = find_head_end(&head) {
            if !read_body || method != "GET" {
                return Ok(());
            }
            let content = content_length(&head[..end]);
            let mut left = content.saturating_sub(head.len() - end);
            while left > 0 {
                let want = left.min(buf.len());
                let read = io
                    .read(&mut buf[..want])
                    .map_err(|error| error.to_string())?;
                if read == 0 {
                    return Err("the peer closed inside the body".to_owned());
                }
                left -= read;
            }
            if content == 0 {
                drain(io)?;
            }
            return Ok(());
        }
        if head.len() > 65_536 {
            return Err("the response head is over 64 KiB".to_owned());
        }
    }
}

fn find_head_end(head: &[u8]) -> Option<usize> {
    head.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

fn content_length(head: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(head) else {
        return 0;
    };
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn drain(io: &mut impl Read) -> Result<(), String> {
    let mut buf = [0u8; 4096];
    loop {
        match io.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

struct ProbeUrl {
    tls: bool,
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl ProbeUrl {
    fn parse(text: &str) -> Result<Self, String> {
        let (tls, rest) = match text.split_once("://") {
            Some(("http", rest)) => (false, rest),
            Some(("https", rest)) => (true, rest),
            Some((scheme, _)) => {
                return Err(format!("probe scheme `{scheme}` is not http or https"))
            }
            None => return Err(format!("probe URL {text:?} names no scheme")),
        };
        let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..split];
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        if authority.is_empty() {
            return Err(format!("probe URL {text:?} names no host"));
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| format!("probe URL {text:?} has an unclosed IPv6 host"))?;
            let port = tail
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(if tls { 443 } else { 80 });
            (host.to_owned(), port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if port.chars().all(|ch| ch.is_ascii_digit()) {
                (
                    host.to_owned(),
                    port.parse()
                        .map_err(|_| format!("probe URL {text:?} has an invalid port"))?,
                )
            } else {
                (authority.to_owned(), if tls { 443 } else { 80 })
            }
        } else {
            (authority.to_owned(), if tls { 443 } else { 80 })
        };
        if host.is_empty() {
            return Err(format!("probe URL {text:?} names no host"));
        }
        let mut path = &rest[split..];
        if let Some(fragment) = path.find('#') {
            path = &path[..fragment];
        }
        let path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        Ok(Self {
            tls,
            host,
            port,
            authority: authority.to_owned(),
            path,
        })
    }
}

fn random_below(limit: u64) -> u64 {
    if limit == 0 {
        return 0;
    }
    let mut state = RANDOM.load(Ordering::Relaxed);
    if state == 0 {
        state = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |elapsed| elapsed.as_nanos() as u64)
            | 1;
    }
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    RANDOM.store(state, Ordering::Relaxed);
    state % limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_url_keeps_the_authority_and_makes_the_path() {
        let url = ProbeUrl::parse("https://example.test:8443/check?q=1#frag").expect("parses");
        assert!(url.tls);
        assert_eq!(url.host, "example.test");
        assert_eq!(url.port, 8443);
        assert_eq!(url.authority, "example.test:8443");
        assert_eq!(url.path, "/check?q=1");
        let bare = ProbeUrl::parse("http://example.test?q=1").expect("parses");
        assert_eq!(bare.path, "/?q=1");
    }

    #[test]
    fn a_failed_legacy_probe_keeps_the_reference_delay() {
        let observatory = Observatory {
            snapshot: Mutex::new(Arc::from(Vec::new())),
        };
        let mut statuses = Vec::new();
        update_legacy_status(
            &mut statuses,
            &observatory,
            "lane",
            &Err("no answer".to_owned()),
        );
        assert_eq!(statuses[0].delay_ms, 99_999_999);
        assert!(!statuses[0].alive);
    }

    #[test]
    fn a_zero_legacy_interval_is_the_default_and_an_empty_url_is_google() {
        let config = Legacy::parse(&Json::Obj(vec![
            ("probeURL".to_owned(), Json::Str(String::new())),
            ("probeInterval".to_owned(), Json::Str("0".to_owned())),
        ]))
        .expect("parses");
        assert_eq!(config.url, LEGACY_URL);
        assert_eq!(config.interval, DEFAULT_INTERVAL);
        let spaced = Legacy::parse(&Json::Obj(vec![(
            "probeURL".to_owned(),
            Json::Str(" ".to_owned()),
        )]))
        .expect("parses");
        assert_eq!(spaced.url, " ");
    }

    #[test]
    fn a_burst_without_a_ping_config_is_refused_like_the_json_build() {
        let error = Burst::parse(&Json::Obj(vec![(
            "subjectSelector".to_owned(),
            Json::Arr(vec![Json::Str("proxy".to_owned())]),
        )]))
        .expect_err("refuses");
        assert!(error.contains("pingConfig"));
    }

    #[test]
    fn a_whitespace_http_method_is_get_but_reads_no_body() {
        let method = |value: &str| {
            BurstSettings::parse(&Json::Obj(vec![(
                "httpMethod".to_owned(),
                Json::Str(value.to_owned()),
            )]))
            .expect("parses")
            .method
        };
        assert_eq!(method(""), "HEAD");
        assert_eq!(method(" "), "GET");
        assert_eq!(method(" get "), "get");
    }

    #[test]
    fn burst_intervals_at_or_under_ten_seconds_clamp() {
        let interval = |value: &str| {
            BurstSettings::parse(&Json::Obj(vec![(
                "interval".to_owned(),
                Json::Str(value.to_owned()),
            )]))
            .expect("parses")
            .interval
        };
        assert_eq!(interval("0"), Duration::from_secs(60));
        assert_eq!(interval("-1s"), Duration::from_secs(10));
        assert_eq!(interval("5s"), Duration::from_secs(10));
        assert_eq!(interval("30s"), Duration::from_secs(30));
    }

    #[test]
    fn burst_settings_default_to_ten_samples_and_head() {
        let settings = BurstSettings::parse(&Json::Obj(Vec::new())).expect("parses");
        assert_eq!(settings.samples, 10);
        assert_eq!(settings.method, "HEAD");
        assert_eq!(settings.interval, Duration::from_secs(60));
    }

    #[test]
    fn a_burst_ring_counts_a_failure_and_keeps_the_average() {
        let mut ring = Ring::new(3, Duration::from_secs(60));
        ring.put(10_000_000);
        ring.put(20_000_000);
        let stats = ring.stats();
        assert_eq!((stats.all, stats.fail, stats.average), (2, 0, 15_000_000));
        ring.put(FAILED);
        let stats = ring.stats();
        assert_eq!((stats.all, stats.fail), (3, 1));
    }

    #[test]
    fn a_burst_ring_holds_the_sampling_window_and_puts_without_allocating() {
        let mut ring = Ring::new(10, Duration::from_secs(60));
        assert_eq!(ring.slots.len(), 10);
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for sample in 1..=10 {
                ring.put(sample);
            }
        });
        assert_eq!(counts.allocs, 0);
        assert_eq!(ring.stats().all, 10);
    }

    #[test]
    fn a_probe_through_freedom_reads_the_headers_and_gives_the_delay() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).expect("reads") == 0 {
                    return;
                }
                head.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("writes");
        });
        let url = format!("http://127.0.0.1:{port}/generate_204");
        let delay = probe(
            &Outbound::Freedom(Arc::default()),
            &url,
            "GET",
            Duration::from_secs(5),
            true,
        )
        .expect("probes");
        assert!(delay < Duration::from_secs(5));
    }

    #[test]
    fn one_successful_sample_has_half_its_average_as_deviation() {
        let mut ring = Ring::new(2, Duration::from_secs(60));
        ring.put(10_000_000);
        let stats = ring.stats();
        assert_eq!(stats.deviation, 5_000_000);
    }
}
