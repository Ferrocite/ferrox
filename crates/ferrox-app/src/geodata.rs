//! The top-level `geodata` block: the reference's build checks every asset and the cron, and a cron
//! schedules a download through the named outbound and a reload of the rule table.

use crate::conn::HttpUrl;
use crate::json::Json;
use crate::proxy::{Destination, Outbound, RouteShared};
use ferrox_core::tls::TlsProvider as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const IDLE: Duration = Duration::from_secs(30);
const MAX_DOWNLOAD: u64 = 256 * 1024 * 1024;
const MAX_HEAD_LINE: usize = 8192;
const MAX_HEADERS: usize = 128;
const MAX_TRAILERS: usize = 128;
const LUA_GUARD: &[u8] = b"\x12\x01\x00";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144 Safari/537.36";

/// One validated `geodata` block a cron will drive.
#[derive(Debug)]
pub(crate) struct Config {
    schedule: Schedule,
    outbound: String,
    assets: Vec<Asset>,
}

impl Config {
    pub(crate) fn outbound(&self) -> &str {
        &self.outbound
    }
}

#[derive(Debug)]
struct Asset {
    url: String,
    file: String,
}

/// Validate the `geodata` block as the reference's build does: an HTTPS URL for every asset, a
/// robfig standard cron, and — only when a cron will run — a statable `.dat` file per asset. An
/// unknown field is inert, as the reference's decoder leaves it.
pub(crate) fn parse(root: &Json, dirs: &[PathBuf]) -> Result<Option<Config>, String> {
    let Some(section) = root.get("geodata") else {
        return Ok(None);
    };
    let Json::Obj(pairs) = section else {
        return match section {
            Json::Null => Ok(None),
            _ => Err("`geodata` is not an object".to_owned()),
        };
    };
    let mut cron = None;
    let mut outbound = String::new();
    let mut assets = Vec::new();
    for (key, value) in pairs {
        match key.as_str() {
            "cron" => cron = text(value, key)?.map(str::to_owned),
            "outbound" => text(value, key)?
                .unwrap_or_default()
                .clone_into(&mut outbound),
            "assets" if matches!(value, Json::Null) => {}
            "assets" => {
                let items = value
                    .as_arr()
                    .ok_or_else(|| format!("`geodata.{key}` is not an array"))?;
                for asset in items {
                    assets.push(asset_config(asset)?);
                }
            }
            _ => {}
        }
    }
    let schedule = match cron {
        Some(cron) => Some(
            parse_standard(&cron).map_err(|reason| format!("invalid geodata cron: {reason}"))?,
        ),
        None => None,
    };
    for asset in &mut assets {
        asset.url = https_url(&asset.url)?;
    }
    let Some(schedule) = schedule else {
        return Ok(None);
    };
    if assets.len() > 100 {
        return Err("geodata supports at most 100 assets".to_owned());
    }
    for asset in &assets {
        if !Path::new(&asset.file)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dat"))
        {
            return Err("geodata asset file extension must be .dat".to_owned());
        }
        check_asset_file(&asset.file, dirs)?;
    }
    if schedule
        .every
        .is_some_and(|every| every < Duration::from_secs(60))
    {
        return Err("geodata cron interval must be at least 1 minute".to_owned());
    }
    Ok(Some(Config {
        schedule,
        outbound,
        assets,
    }))
}

/// A string field, where the reference's JSON decoder treats `null` as absent.
fn text<'a>(value: &'a Json, field: &str) -> Result<Option<&'a str>, String> {
    match value {
        Json::Null => Ok(None),
        Json::Str(text) => Ok(Some(text)),
        _ => Err(format!("`geodata.{field}` is not a string")),
    }
}

/// One `{url, file}` asset. The URL is validated after the cron, as the reference's config build
/// does, and even when no cron names it.
fn asset_config(asset: &Json) -> Result<Asset, String> {
    let Json::Obj(pairs) = asset else {
        return Err("`geodata.assets` holds an entry that is not an object".to_owned());
    };
    let mut url = "";
    let mut file = "";
    for (key, value) in pairs {
        match key.as_str() {
            "url" if !matches!(value, Json::Null) => {
                url = value
                    .as_str()
                    .ok_or_else(|| "`geodata.assets` url is not a string".to_owned())?;
            }
            "file" if !matches!(value, Json::Null) => {
                file = value
                    .as_str()
                    .ok_or_else(|| "`geodata.assets` file is not a string".to_owned())?;
            }
            _ => {}
        }
    }
    Ok(Asset {
        url: url.to_owned(),
        file: file.to_owned(),
    })
}

/// A local regular file the asset directories can find, as the reference's `ResolveAsset` reads them.
fn check_asset_file(file: &str, dirs: &[PathBuf]) -> Result<(), String> {
    if !crate::router::is_local_asset(file) {
        return Err(format!(
            "invalid geodata asset file: {file}: asset path must stay in asset directory"
        ));
    }
    asset_path(file, dirs).ok_or_else(|| {
        format!("invalid geodata asset file: {file}: the file is not a regular file under the asset directories")
    })?;
    Ok(())
}

fn asset_path(file: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter()
        .map(|dir| dir.join(file))
        .find(|path| path.is_file())
}

/// The reference's `validateHTTPS`: the scheme compared without case, as Go's URL parser lowercases it, and a host that is not empty. The normalized URL is what the downloader later parses.
fn https_url(url: &str) -> Result<String, String> {
    let refused = |reason: &str| format!("invalid geodata asset url: {url}: {reason}");
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(refused("URL names no scheme"));
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(refused("scheme must be https"));
    }
    let normalized = format!("https://{rest}");
    crate::conn::HttpUrl::parse(&normalized).map_err(|error| refused(&error))?;
    Ok(normalized)
}

/// One cron field's bounds and the names it accepts, in the reference's parser's own ranges.
#[derive(Clone, Copy)]
struct Bounds {
    min: u32,
    max: u32,
    names: &'static [(&'static str, u32)],
}

const MINUTES: Bounds = Bounds {
    min: 0,
    max: 59,
    names: &[],
};
const HOURS: Bounds = Bounds {
    min: 0,
    max: 23,
    names: &[],
};
const DOM: Bounds = Bounds {
    min: 1,
    max: 31,
    names: &[],
};
const MONTH_NAMES: [(&str, u32); 12] = [
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("may", 5),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("oct", 10),
    ("nov", 11),
    ("dec", 12),
];
const MONTHS: Bounds = Bounds {
    min: 1,
    max: 12,
    names: &MONTH_NAMES,
};
const DOW_NAMES: [(&str, u32); 7] = [
    ("sun", 0),
    ("mon", 1),
    ("tue", 2),
    ("wed", 3),
    ("thu", 4),
    ("fri", 5),
    ("sat", 6),
];
const DOW: Bounds = Bounds {
    min: 0,
    max: 6,
    names: &DOW_NAMES,
};

/// A parsed robfig standard schedule: the five field bitsets, the day fields' `*` marker, or the
/// fixed delay an `@every` descriptor carries.
#[derive(Clone, Copy, Debug)]
struct Schedule {
    minutes: u64,
    hours: u64,
    days: u64,
    months: u64,
    weekdays: u64,
    dom_star: bool,
    dow_star: bool,
    every: Option<Duration>,
}

impl Schedule {
    fn delay(&self, now: SystemTime) -> Option<Duration> {
        if let Some(every) = self.every {
            return Some(every);
        }
        let mut candidate = next_minute(now);
        for _ in 0..(366 * 24 * 60 * 8) {
            if local_parts(candidate).is_some_and(|parts| self.matches(parts)) {
                return Some(candidate.duration_since(now).unwrap_or(Duration::ZERO));
            }
            candidate += Duration::from_secs(60);
        }
        None
    }

    fn matches(&self, parts: Parts) -> bool {
        if self.months & (1 << parts.month) == 0
            || self.hours & (1 << parts.hour) == 0
            || self.minutes & (1 << parts.minute) == 0
        {
            return false;
        }
        let day = self.days & (1 << parts.day) != 0;
        let weekday = self.weekdays & (1 << parts.weekday) != 0;
        match (self.dom_star, self.dow_star) {
            (true, true) => true,
            (true, false) => weekday,
            (false, true) => day,
            (false, false) => day || weekday,
        }
    }
}

#[derive(Clone, Copy)]
struct Parts {
    minute: u32,
    hour: u32,
    day: u32,
    month: u32,
    weekday: u32,
}

fn next_minute(now: SystemTime) -> SystemTime {
    let seconds = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    UNIX_EPOCH + Duration::from_secs((seconds / 60 + 1) * 60)
}

#[cfg(unix)]
fn local_parts(now: SystemTime) -> Option<Parts> {
    let seconds = libc::time_t::try_from(now.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&raw const seconds, &raw mut tm) }.is_null() {
        return None;
    }
    Some(Parts {
        minute: u32::try_from(tm.tm_min).ok()?,
        hour: u32::try_from(tm.tm_hour).ok()?,
        day: u32::try_from(tm.tm_mday).ok()?,
        month: u32::try_from(tm.tm_mon + 1).ok()?,
        weekday: u32::try_from(tm.tm_wday).ok()?,
    })
}

#[cfg(windows)]
fn local_parts(now: SystemTime) -> Option<Parts> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    let intervals = now.duration_since(UNIX_EPOCH).ok()?.as_nanos() / 100 + 116_444_736_000_000_000;
    let filetime = FILETIME {
        dwLowDateTime: intervals as u32,
        dwHighDateTime: (intervals >> 32) as u32,
    };
    let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
    if unsafe { FileTimeToSystemTime(&raw const filetime, &raw mut utc) } == 0 {
        return None;
    }
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    if unsafe { SystemTimeToTzSpecificLocalTime(std::ptr::null(), &raw const utc, &raw mut local) }
        == 0
    {
        return None;
    }
    Some(Parts {
        minute: u32::from(local.wMinute),
        hour: u32::from(local.wHour),
        day: u32::from(local.wDay),
        month: u32::from(local.wMonth),
        weekday: u32::from(local.wDayOfWeek),
    })
}

#[cfg(not(any(unix, windows)))]
fn local_parts(_now: SystemTime) -> Option<Parts> {
    None
}

/// robfig's standard parser's language — five fields, names, steps, lists, `?` for `*`, the `@`
/// descriptors and a `TZ=`/`CRON_TZ=` zone — so a schedule the reference accepts is not refused.
fn parse_standard(spec: &str) -> Result<Schedule, String> {
    let mut spec = spec;
    for prefix in ["CRON_TZ=", "TZ="] {
        let Some(rest) = spec.strip_prefix(prefix) else {
            continue;
        };
        let (_, tail) = rest.split_once(char::is_whitespace).ok_or_else(|| {
            "provided bad location: the spec names no schedule after the zone".to_owned()
        })?;
        spec = tail.trim();
        break;
    }
    if spec.is_empty() {
        return Err("empty spec string".to_owned());
    }
    if spec.starts_with('@') {
        return parse_descriptor(spec);
    }
    let fields: Vec<&str> = spec.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "expected exactly 5 fields, found {}: {spec}",
            fields.len()
        ));
    }
    fields_schedule(&fields)
}

fn fields_schedule(fields: &[&str]) -> Result<Schedule, String> {
    let minutes = parse_field(fields[0], MINUTES)?;
    let hours = parse_field(fields[1], HOURS)?;
    let days = parse_field(fields[2], DOM)?;
    let months = parse_field(fields[3], MONTHS)?;
    let weekdays = parse_field(fields[4], DOW)?;
    Ok(Schedule {
        minutes,
        hours,
        days,
        months,
        weekdays,
        dom_star: is_star(fields[2]),
        dow_star: is_star(fields[4]),
        every: None,
    })
}

/// robfig's star bit: a `*`/`?` range whose step is absent or 1. A step above 1 clears it, so the
/// day fields then combine with OR rather than AND.
fn is_star(field: &str) -> bool {
    field.split(',').any(|expr| {
        let (range, step) = expr
            .split_once('/')
            .map_or((expr, None), |(range, step)| (range, Some(step)));
        let low = range.split('-').next().unwrap_or(range);
        matches!(low, "*" | "?") && step.is_none_or(|step| parse_uint(step).ok() == Some(1))
    })
}

fn parse_descriptor(spec: &str) -> Result<Schedule, String> {
    match spec {
        "@yearly" | "@annually" => fields_schedule(&["0", "0", "1", "1", "*"]),
        "@monthly" => fields_schedule(&["0", "0", "1", "*", "*"]),
        "@weekly" => fields_schedule(&["0", "0", "*", "*", "0"]),
        "@daily" | "@midnight" => fields_schedule(&["0", "0", "*", "*", "*"]),
        "@hourly" => fields_schedule(&["0", "*", "*", "*", "*"]),
        _ => match spec.strip_prefix("@every ") {
            Some(duration) => parse_duration(duration)
                .map(|every| Schedule {
                    minutes: 0,
                    hours: 0,
                    days: 0,
                    months: 0,
                    weekdays: 0,
                    dom_star: true,
                    dow_star: true,
                    every: Some(every),
                })
                .ok_or_else(|| format!("failed to parse duration {duration}")),
            None => Err(format!("unrecognized descriptor: {spec}")),
        },
    }
}

/// A comma-separated list of ranges; an empty piece is refused, as the reference's parser refuses it.
fn parse_field(field: &str, bounds: Bounds) -> Result<u64, String> {
    let mut mask = 0;
    for expr in field.split(',') {
        if expr.is_empty() {
            return Err(format!("empty expression: {field}"));
        }
        mask |= parse_range(expr, bounds)?;
    }
    Ok(mask)
}

fn parse_range(expr: &str, bounds: Bounds) -> Result<u64, String> {
    let (range, step) = match expr.split_once('/') {
        Some((range, step)) if !step.contains('/') => (range, Some(parse_uint(step)?)),
        Some(_) => return Err(format!("too many slashes: {expr}")),
        None => (expr, None),
    };
    let mut hyphenated = range.split('-');
    let low = hyphenated.next().unwrap_or_default();
    let high = hyphenated.next();
    if hyphenated.next().is_some() {
        return Err(format!("too many hyphens: {expr}"));
    }
    let (start, end) = if low == "*" || low == "?" {
        (bounds.min, bounds.max)
    } else {
        let start = parse_value(low, bounds)?;
        let end = match high {
            Some(high) => parse_value(high, bounds)?,
            None => start,
        };
        (start, end)
    };
    let end = if high.is_none() && step.is_some() {
        bounds.max
    } else {
        end
    };
    let step = step.unwrap_or(1);
    if start < bounds.min {
        return Err(format!(
            "beginning of range ({start}) below minimum ({}): {expr}",
            bounds.min
        ));
    }
    if end > bounds.max {
        return Err(format!(
            "end of range ({end}) above maximum ({}): {expr}",
            bounds.max
        ));
    }
    if start > end {
        return Err(format!(
            "beginning of range ({start}) beyond end of range ({end}): {expr}"
        ));
    }
    if step == 0 {
        return Err(format!("step of range should be a positive number: {expr}"));
    }
    let mut mask = 0;
    let mut value = start;
    while value <= end {
        mask |= 1u64 << value;
        value = match value.checked_add(step) {
            Some(next) => next,
            None => break,
        };
    }
    Ok(mask)
}

fn parse_value(text: &str, bounds: Bounds) -> Result<u32, String> {
    let lowered = text.to_ascii_lowercase();
    if let Some((_, value)) = bounds.names.iter().find(|(name, _)| *name == lowered) {
        return Ok(*value);
    }
    parse_uint(text)
}

fn parse_uint(text: &str) -> Result<u32, String> {
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("failed to parse int from {text}"));
    }
    digits
        .parse()
        .map_err(|_| format!("failed to parse int from {text}"))
}

/// Go's `time.ParseDuration` grammar, which an `@every` descriptor carries: unit groups of decimal
/// and optional fractional numbers, with `0` as the one unitless form.
#[allow(clippy::cast_precision_loss)]
fn parse_duration(text: &str) -> Option<Duration> {
    let text = text.strip_prefix(['+', '-']).unwrap_or(text);
    if text == "0" {
        return Some(Duration::ZERO);
    }
    let mut total: u128 = 0;
    let mut at = 0;
    let mut groups = 0;
    while at < text.len() {
        let digits_start = at;
        while text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if text.as_bytes().get(at) == Some(&b'.') {
            at += 1;
            while text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
        }
        if at == digits_start || &text[digits_start..at] == "." {
            return None;
        }
        let number: f64 = text[digits_start..at].parse().ok()?;
        let rest = &text[at..];
        let (unit, nanos) = if rest.starts_with("ns") {
            ("ns", 1u128)
        } else if rest.starts_with("us") {
            ("us", 1_000)
        } else if rest.starts_with("µs") {
            ("µs", 1_000)
        } else if rest.starts_with("μs") {
            ("μs", 1_000)
        } else if rest.starts_with("ms") {
            ("ms", 1_000_000)
        } else if rest.starts_with('s') {
            ("s", 1_000_000_000)
        } else if rest.starts_with('m') {
            ("m", 60 * 1_000_000_000)
        } else if rest.starts_with('h') {
            ("h", 3_600 * 1_000_000_000)
        } else {
            return None;
        };
        at += unit.len();
        total = total.checked_add((number * nanos as f64) as u128)?;
        groups += 1;
    }
    if groups == 0 {
        return None;
    }
    Some(Duration::from_nanos(u64::try_from(total).ok()?))
}

/// Start the cron the block names. The thread is the process's own lifetime, as the reference's
/// scheduler is, and a refresh that fails leaves the table and the files as they were.
pub(crate) fn start(
    config: Config,
    route: Option<Arc<RouteShared>>,
    default: Option<Outbound>,
    root: Json,
) {
    let Config {
        schedule,
        outbound,
        assets,
    } = config;
    let _ = std::thread::Builder::new()
        .name("geodata".to_owned())
        .spawn(move || loop {
            let Some(delay) = schedule.delay(SystemTime::now()) else {
                return;
            };
            std::thread::sleep(delay);
            if let Err(reason) = run(
                &assets,
                route.as_deref(),
                default.as_ref(),
                &outbound,
                &root,
            ) {
                eprintln!("geodata: scheduled reload failed: {reason}");
            }
        });
}

fn run(
    assets: &[Asset],
    route: Option<&RouteShared>,
    default: Option<&Outbound>,
    tag: &str,
    root: &Json,
) -> Result<(), String> {
    if assets.is_empty() {
        return reload(route, root);
    }
    let outbound = match route {
        Some(route) => route.outbound_for(tag),
        None => default.cloned(),
    };
    let outbound = outbound.ok_or_else(|| format!("geodata outbound `{tag}` is not found"))?;
    let staged = download_all(assets, &outbound)?;
    let transaction = match swap_all(&staged) {
        Ok(transaction) => transaction,
        Err(reason) => {
            clean(&staged);
            return Err(reason);
        }
    };
    if let Err(reason) = reload(route, root) {
        return match transaction.rollback() {
            Ok(()) => Err(reason),
            Err(rollback) => Err(format!("{reason}; rollback failed: {rollback}")),
        };
    }
    transaction.commit()
}

fn reload(route: Option<&RouteShared>, root: &Json) -> Result<(), String> {
    if let Some(route) = route {
        route.reload_routing(root)?;
    }
    Ok(())
}

#[derive(Debug)]
struct Stage {
    target: PathBuf,
    temp: PathBuf,
}

fn download_all(assets: &[Asset], outbound: &Outbound) -> Result<Vec<Stage>, String> {
    let dirs = crate::router::asset_dirs();
    let mut staged = Vec::with_capacity(assets.len());
    for asset in assets {
        match download_one(asset, outbound, &dirs) {
            Ok(stage) => staged.push(stage),
            Err(reason) => {
                clean(&staged);
                return Err(reason);
            }
        }
    }
    Ok(staged)
}

fn download_one(asset: &Asset, outbound: &Outbound, dirs: &[PathBuf]) -> Result<Stage, String> {
    let target = asset_path(&asset.file, dirs).ok_or_else(|| {
        format!(
            "invalid geodata asset file: {}: the file is not a regular file under the asset directories",
            asset.file
        )
    })?;
    let temp = unique_path(&target, ".tmp")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| format!("cannot create {}: {error}", temp.display()))?;
    let result = (|| {
        file.write_all(LUA_GUARD)
            .map_err(|error| error.to_string())?;
        fetch(&asset.url, outbound, &mut file)?;
        file.flush().map_err(|error| error.to_string())
    })();
    if let Err(reason) = result {
        drop(file);
        let _ = std::fs::remove_file(&temp);
        return Err(reason);
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o644));
    }
    Ok(Stage { target, temp })
}

fn unique_path(target: &Path, suffix: &str) -> Result<PathBuf, String> {
    let directory = target
        .parent()
        .ok_or_else(|| format!("{} names no directory", target.display()))?;
    let base = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("asset");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..100 {
        let candidate = directory.join(format!(
            ".{base}.{}.{nanos}.{attempt}{suffix}",
            std::process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "cannot name a temporary file beside {}",
        target.display()
    ))
}

fn clean(staged: &[Stage]) {
    for stage in staged {
        let _ = std::fs::remove_file(&stage.temp);
    }
}

struct Transaction {
    swaps: Vec<Swap>,
}

struct Swap {
    target: PathBuf,
    backup: Option<PathBuf>,
}

fn swap_all(staged: &[Stage]) -> Result<Transaction, String> {
    let mut transaction = Transaction { swaps: Vec::new() };
    for stage in staged {
        match swap_one(stage) {
            Ok(swap) => transaction.swaps.push(swap),
            Err(reason) => {
                return match transaction.rollback() {
                    Ok(()) => Err(reason),
                    Err(rollback) => Err(format!("{reason}; rollback failed: {rollback}")),
                };
            }
        }
    }
    Ok(transaction)
}

fn swap_one(stage: &Stage) -> Result<Swap, String> {
    let backup = if stage.target.exists() {
        let backup = unique_path(&stage.target, ".bak")?;
        std::fs::rename(&stage.target, &backup)
            .map_err(|error| format!("cannot move {} aside: {error}", stage.target.display()))?;
        Some(backup)
    } else {
        None
    };
    if let Err(error) = std::fs::rename(&stage.temp, &stage.target) {
        if let Some(backup) = &backup {
            let _ = std::fs::rename(backup, &stage.target);
        }
        return Err(format!(
            "cannot move {} into place: {error}",
            stage.temp.display()
        ));
    }
    Ok(Swap {
        target: stage.target.clone(),
        backup,
    })
}

impl Transaction {
    fn rollback(self) -> Result<(), String> {
        let mut failure = None;
        for swap in self.swaps.into_iter().rev() {
            if let Err(error) = std::fs::remove_file(&swap.target) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    failure.get_or_insert(error);
                }
            }
            if let Some(backup) = swap.backup {
                if let Err(error) = std::fs::rename(&backup, &swap.target) {
                    failure.get_or_insert(error);
                }
            }
        }
        match failure {
            Some(error) => Err(error.to_string()),
            None => Ok(()),
        }
    }

    fn commit(self) -> Result<(), String> {
        for swap in self.swaps {
            if let Some(backup) = swap.backup {
                if let Err(error) = std::fs::remove_file(&backup) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        return Err(error.to_string());
                    }
                }
            }
        }
        Ok(())
    }
}

fn fetch(url: &str, outbound: &Outbound, writer: &mut impl Write) -> Result<(), String> {
    let mut current = url.to_owned();
    for _ in 0..20 {
        let response = request(&current, outbound)?;
        if (300..400).contains(&response.status) {
            let location = response
                .header("location")
                .ok_or_else(|| "redirected without a Location header".to_owned())?;
            current = resolve_location(&current, location)?;
            continue;
        }
        if !(200..300).contains(&response.status) {
            return Err(format!("unexpected status code: {}", response.status));
        }
        if response.body.is_empty() {
            return Err("empty response body".to_owned());
        }
        writer
            .write_all(&response.body)
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    Err("stopped after 20 redirects".to_owned())
}

#[derive(Debug)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

fn request(url: &str, outbound: &Outbound) -> Result<Response, String> {
    let url = HttpUrl::parse(url)?;
    if !url.tls {
        return Err("geodata asset url must be https".to_owned());
    }
    let destination = Destination::Name(url.host.clone(), url.port);
    let stream = crate::proxy::probe_stream(outbound, &destination, IDLE)
        .ok_or_else(|| format!("cannot dial {}", url.authority))?;
    let config = ferrox_core::tls::TlsConfig {
        server_name: url.host.clone(),
        alpn: vec![b"http/1.1".to_vec()].into(),
        roots: crate::quic::system_roots(),
        resumption: true,
        ..ferrox_core::tls::TlsConfig::default()
    };
    let mut session = ferrox_core::tls::RustlsProvider::connect(&config, stream)
        .map_err(|error| error.to_string())?;
    session.handshake().map_err(|error| error.to_string())?;
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
        url.path, url.authority
    );
    session
        .write_all(head.as_bytes())
        .map_err(|error| error.to_string())?;
    session.flush().map_err(|error| error.to_string())?;
    read_response(&mut session)
}

/// One head line, bounded: `read_line` grows a `String` without limit, so a malicious
/// server pads a status, header, chunk-size or trailer line until the process is out
/// of memory. The take caps the bytes the read may consume, and a line that does not
/// end inside them is refused; a clean end of stream reads as an empty line, as before.
fn capped_line(reader: &mut impl BufRead, what: &str) -> Result<String, String> {
    let mut buf = Vec::new();
    let read = reader
        .by_ref()
        .take((MAX_HEAD_LINE + 2) as u64)
        .read_until(b'\n', &mut buf)
        .map_err(|error| error.to_string())?;
    if read == 0 {
        return Ok(String::new());
    }
    if !buf.ends_with(b"\n") {
        return Err(format!("geodata {what} exceeds {MAX_HEAD_LINE} bytes"));
    }
    String::from_utf8(buf).map_err(|_| format!("geodata {what} is not UTF-8"))
}

#[allow(clippy::too_many_lines)]
fn read_response(reader: &mut impl Read) -> Result<Response, String> {
    let mut reader = BufReader::new(reader);
    let line = capped_line(&mut reader, "status line")?;
    let mut status = line.split_whitespace();
    let version = status.next().unwrap_or_default();
    let code = status
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid HTTP status line: {line}"))?;
    if !version.starts_with("HTTP/") {
        return Err(format!("invalid HTTP status line: {line}"));
    }
    let mut headers = Vec::new();
    loop {
        let line = capped_line(&mut reader, "header line")?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(format!("geodata response headers exceed {MAX_HEADERS}"));
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    };
    let mut body = Vec::new();
    if header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        read_chunked(&mut reader, &mut body)?;
    } else if let Some(length) =
        header("content-length").and_then(|value| value.parse::<u64>().ok())
    {
        if length > MAX_DOWNLOAD {
            return Err("geodata download exceeds 256 MiB".to_owned());
        }
        body.reserve(usize::try_from(length).unwrap_or(0));
        reader
            .take(length)
            .read_to_end(&mut body)
            .map_err(|error| error.to_string())?;
        if body.len() as u64 != length {
            return Err("response body is shorter than Content-Length".to_owned());
        }
    } else {
        reader
            .take(MAX_DOWNLOAD + 1)
            .read_to_end(&mut body)
            .map_err(|error| error.to_string())?;
        if body.len() as u64 > MAX_DOWNLOAD {
            return Err("geodata download exceeds 256 MiB".to_owned());
        }
    }
    let gzip = header("content-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|encoding| encoding.trim().eq_ignore_ascii_case("gzip"))
    }) || body.starts_with(&[0x1f, 0x8b]);
    if gzip {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&body[..])
            .take(MAX_DOWNLOAD + 1)
            .read_to_end(&mut decoded)
            .map_err(|error| error.to_string())?;
        if decoded.len() as u64 > MAX_DOWNLOAD {
            return Err("geodata download exceeds 256 MiB".to_owned());
        }
        body = decoded;
    }
    Ok(Response {
        status: code,
        headers,
        body,
    })
}

fn read_chunked(reader: &mut impl BufRead, body: &mut Vec<u8>) -> Result<(), String> {
    loop {
        let line = capped_line(reader, "chunk size line")?;
        let size = line
            .trim()
            .split(';')
            .next()
            .and_then(|size| usize::from_str_radix(size, 16).ok())
            .ok_or_else(|| format!("invalid chunk size: {line}"))?;
        if size == 0 {
            let mut trailers = 0;
            loop {
                let trailer = capped_line(reader, "chunk trailer")?;
                if trailer.trim().is_empty() {
                    break;
                }
                trailers += 1;
                if trailers > MAX_TRAILERS {
                    return Err(format!("geodata chunk trailers exceed {MAX_TRAILERS}"));
                }
            }
            return Ok(());
        }
        let length = body
            .len()
            .checked_add(size)
            .ok_or_else(|| "geodata download exceeds 256 MiB".to_owned())?;
        if length as u64 > MAX_DOWNLOAD {
            return Err("geodata download exceeds 256 MiB".to_owned());
        }
        let start = body.len();
        body.resize(length, 0);
        reader
            .read_exact(&mut body[start..])
            .map_err(|error| error.to_string())?;
        let mut terminator = [0u8; 2];
        reader
            .read_exact(&mut terminator)
            .map_err(|error| error.to_string())?;
        if terminator != *b"\r\n" {
            return Err("invalid chunk terminator".to_owned());
        }
    }
}

fn resolve_location(base: &str, location: &str) -> Result<String, String> {
    if location.starts_with("https://") {
        return Ok(location.to_owned());
    }
    if location.starts_with("http://") {
        return Err("redirected to non-https URL".to_owned());
    }
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("https://{rest}"));
    }
    let url = HttpUrl::parse(base)?;
    let path = if location.starts_with('/') {
        location.to_owned()
    } else {
        let directory = url
            .path
            .rsplit_once('/')
            .map_or("/", |(directory, _)| directory);
        format!("{directory}/{location}")
    };
    Ok(format!("https://{}{}", url.authority, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ferrox-geodata-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates the asset directory");
        std::fs::write(dir.join("geosite.dat"), b"").expect("writes the asset");
        dir
    }

    fn config(geodata: &str) -> Json {
        crate::json::parse(&format!(r#"{{"geodata": {geodata}}}"#)).expect("parses")
    }

    /// CWE-400: the downloader read status, header and chunk lines with an unbounded
    /// `read_line`, so one malicious geo server grew a line or header run without limit.
    #[test]
    fn a_geodata_response_over_an_oversized_head_line_is_refused() {
        let long = "x".repeat(8193);
        for (name, wire) in [
            (
                "status line",
                format!("HTTP/1.1 200 {long}\r\nContent-Length: 3\r\n\r\nabc"),
            ),
            (
                "header line",
                format!("HTTP/1.1 200 OK\r\nServer: {long}\r\nContent-Length: 3\r\n\r\nabc"),
            ),
            (
                "chunk size line",
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{long}\r\nabc\r\n0\r\n\r\n"
                ),
            ),
            (
                "chunk trailer line",
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: {long}\r\n\r\n"
                ),
            ),
        ] {
            let mut cursor = std::io::Cursor::new(wire.into_bytes());
            let error = read_response(&mut cursor).expect_err(name);
            assert!(error.contains("8192"), "{name}: {error}");
        }
    }

    /// CWE-400: a header block with an unbounded field count grew without limit.
    #[test]
    fn a_geodata_response_over_a_header_run_is_refused() {
        let heads: Vec<String> = (0..129)
            .map(|index| format!("X-Head-{index}: v\r\n"))
            .collect();
        let wire = format!(
            "HTTP/1.1 200 OK\r\n{}Content-Length: 3\r\n\r\nabc",
            heads.join("")
        );
        let mut cursor = std::io::Cursor::new(wire.into_bytes());
        let error = read_response(&mut cursor).expect_err("a header run is refused");
        assert!(error.contains("128"), "{error}");
    }

    /// A small well-formed response still reads: the caps only bite the runs above them.
    #[test]
    fn a_geodata_response_within_the_caps_still_reads() {
        let mut cursor =
            std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec());
        let response = read_response(&mut cursor).expect("small head reads");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"abc");
    }

    #[test]
    fn a_geodata_asset_url_must_be_https() {
        let root = config(
            r#"{"assets": [{"url": "http://example.test/geosite.dat", "file": "geosite.dat"}]}"#,
        );
        let error = parse(&root, &[asset_dir()]).expect_err("http is refused");
        assert!(
            error.contains("invalid geodata asset url") && error.contains("https"),
            "{error}"
        );
    }

    /// The scheme is case-insensitive, and the config stores the normalized URL.
    #[test]
    fn a_geodata_asset_url_scheme_is_read_without_case() {
        let dir = asset_dir();
        for (url, normalized) in [
            (
                "HTTPS://example.test/geosite.dat",
                "https://example.test/geosite.dat",
            ),
            ("Https://example.test/a/b", "https://example.test/a/b"),
        ] {
            assert_eq!(
                https_url(url).expect("Go's URL parser lowercases the scheme"),
                normalized
            );
            let root = config(&format!(
                r#"{{"cron": "0 3 * * *", "assets": [{{"url": "{url}", "file": "geosite.dat"}}]}}"#
            ));
            let parsed = parse(&root, std::slice::from_ref(&dir))
                .expect("the reference accepts the mixed-case scheme")
                .expect("a cron builds the config");
            assert_eq!(parsed.assets[0].url, normalized);
        }
        let root =
            config(r#"{"assets": [{"url": "https:///geosite.dat", "file": "geosite.dat"}]}"#);
        let error = parse(&root, &[dir]).expect_err("a URL with no host is refused");
        assert!(error.contains("invalid geodata asset url"), "{error}");
    }

    #[test]
    fn a_geodata_asset_file_must_be_statable() {
        let missing = format!("geodata-missing-{}.dat", std::process::id());
        let root = config(&format!(
            r#"{{"cron": "0 3 * * *", "assets": [{{"url": "https://example.test/geoip.dat", "file": "{missing}"}}]}}"#
        ));
        let error = parse(&root, &[asset_dir()]).expect_err("a missing file is refused");
        assert!(
            error.contains("invalid geodata asset file") && error.contains(&missing),
            "{error}"
        );
        let root = config(&format!(
            r#"{{"cron": "0 3 * * *", "assets": [{{"url": "https://example.test/geoip.dat", "file": "../{missing}"}}]}}"#
        ));
        let error = parse(&root, &[asset_dir()])
            .expect_err("a file outside the asset directory is refused");
        assert!(
            error.contains("asset path must stay in asset directory"),
            "{error}"
        );
    }

    #[test]
    fn a_geodata_asset_without_a_cron_is_only_url_checked() {
        let missing = format!("geodata-missing-{}.dat", std::process::id());
        let root = config(&format!(
            r#"{{"assets": [{{"url": "https://example.test/geoip.dat", "file": "{missing}"}}]}}"#
        ));
        parse(&root, &[asset_dir()])
            .expect("the reference builds no downloader when no cron is named");
    }

    #[test]
    fn the_references_geodata_block_is_accepted() {
        let root = config(
            r#"{"cron": "0 3 * * *", "outbound": "direct", "assets": [{"url": "https://example.test/geosite.dat", "file": "geosite.dat"}]}"#,
        );
        parse(&root, &[asset_dir()]).expect("the reference's example is accepted");
    }

    #[test]
    fn a_geodata_cron_outside_the_standard_grammar_is_refused() {
        let error =
            parse(&config(r#"{"cron": "0 3 * *"}"#), &[]).expect_err("four fields are refused");
        assert!(error.contains("invalid geodata cron"), "{error}");
    }

    #[test]
    fn a_geodata_cron_interval_below_a_minute_is_refused() {
        let error = parse(&config(r#"{"cron": "@every 30s"}"#), &[])
            .expect_err("a sub-minute interval is refused");
        assert!(error.contains("at least 1 minute"), "{error}");
    }

    #[test]
    fn a_geodata_asset_must_be_a_dat_file() {
        let root = config(
            r#"{"cron": "0 3 * * *", "assets": [{"url": "https://example.test/geosite.txt", "file": "geosite.txt"}]}"#,
        );
        let error = parse(&root, &[asset_dir()]).expect_err("a non-dat asset is refused");
        assert!(error.contains(".dat"), "{error}");
    }

    #[test]
    fn a_null_geodata_block_is_no_block() {
        parse(
            &crate::json::parse(r#"{"geodata": null}"#).expect("parses"),
            &[],
        )
        .expect("the reference's pointer stays nil, so this config runs");
    }

    #[test]
    fn an_unknown_geodata_field_is_ignored() {
        parse(&config(r#"{"schedule": "0 3 * * *"}"#), &[])
            .expect("the reference's decoder ignores an unknown field, so this config runs");
    }

    #[test]
    fn the_cron_grammar_matches_the_references_standard_parser() {
        for spec in [
            "0 3 * * *",
            "* * * * *",
            "? ? ? ? ?",
            "*/15 0-6,22 1 jan-mar mon-fri",
            "5/10 * * * *",
            "+5 * * * *",
            "TZ=UTC 0 3 * * *",
            "TZ= 0 3 * * *",
            "CRON_TZ=Europe/Berlin @hourly",
            "@yearly",
            "@annually",
            "@monthly",
            "@weekly",
            "@daily",
            "@midnight",
            "@hourly",
            "@every 1h30m",
            "@every .5s",
            "@every 0",
        ] {
            assert!(
                parse_standard(spec).is_ok(),
                "{spec} is accepted by the reference"
            );
        }
        for spec in [
            "",
            "0 3 * *",
            "0 3 * * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 7",
            "5-1 * * * *",
            "*/0 * * * *",
            "1-2-3 * * * *",
            "1/2/3 * * * *",
            "x * * * *",
            "@sometimes",
            "@every 5",
            "@every",
        ] {
            assert!(
                parse_standard(spec).is_err(),
                "{spec} is refused by the reference"
            );
        }
    }

    #[test]
    fn a_chunked_gzip_response_is_decoded() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"geosite").expect("compresses");
        let compressed = encoder.finish().expect("finishes");
        let mut response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
                .to_vec();
        for chunk in compressed.chunks(3) {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        let parsed = read_response(&mut &response[..]).expect("decodes");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"geosite");
    }

    #[test]
    fn a_redirect_to_plain_http_is_refused() {
        let error = resolve_location("https://example.test/a", "http://example.test/b")
            .expect_err("a downgrade is refused");
        assert!(error.contains("non-https"), "{error}");
    }

    #[test]
    fn a_body_past_the_ceiling_is_refused_before_it_is_read() {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_DOWNLOAD + 1
        );
        let error = read_response(&mut head.as_bytes()).expect_err("too large");
        assert!(error.contains("256 MiB"), "{error}");
    }

    #[test]
    fn a_weekday_and_a_day_of_month_are_ored() {
        let schedule = parse_standard("0 0 1 * mon").expect("parses");
        let parts = |day, weekday| Parts {
            minute: 0,
            hour: 0,
            day,
            month: 6,
            weekday,
        };
        assert!(schedule.matches(parts(2, 1)), "a Monday matches");
        assert!(schedule.matches(parts(1, 2)), "the first matches");
        assert!(!schedule.matches(parts(2, 2)), "neither matches");
    }

    #[test]
    fn a_stepped_wildcard_is_not_a_star_field() {
        let schedule = parse_standard("0 0 */2 * mon").expect("parses");
        assert!(!schedule.dom_star);
        assert!(!schedule.dow_star);
        let parts = |day, weekday| Parts {
            minute: 0,
            hour: 0,
            day,
            month: 6,
            weekday,
        };
        assert!(schedule.matches(parts(1, 2)), "an odd day matches");
        assert!(schedule.matches(parts(2, 1)), "a Monday matches");
        assert!(!schedule.matches(parts(2, 2)), "neither matches");
    }

    #[test]
    fn a_schedule_that_never_matches_has_no_delay() {
        let schedule = parse_standard("0 0 30 2 *").expect("parses");
        assert_eq!(schedule.delay(SystemTime::now()), None);
    }

    #[test]
    fn an_every_descriptor_carries_its_delay() {
        let schedule = parse_standard("@every 90m").expect("parses");
        assert_eq!(schedule.every, Some(Duration::from_mins(90)));
    }

    #[test]
    fn more_than_a_hundred_assets_are_refused() {
        let asset = r#"{"url": "https://example.test/geosite.dat", "file": "geosite.dat"}"#;
        let assets = vec![asset; 101].join(",");
        let root = config(&format!(r#"{{"cron": "0 3 * * *", "assets": [{assets}]}}"#));
        let error = parse(&root, &[asset_dir()]).expect_err("too many assets");
        assert!(error.contains("at most 100"), "{error}");
    }
}
