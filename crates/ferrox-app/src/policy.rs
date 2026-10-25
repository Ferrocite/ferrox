use crate::json::Json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Stats {
    pub(crate) user_uplink: bool,
    pub(crate) user_downlink: bool,
    pub(crate) user_online: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct SystemStats {
    pub(crate) inbound_uplink: bool,
    pub(crate) inbound_downlink: bool,
    pub(crate) outbound_uplink: bool,
    pub(crate) outbound_downlink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Level {
    pub(crate) handshake: Option<Duration>,
    pub(crate) conn_idle: Option<Duration>,
    pub(crate) uplink_only: Option<Duration>,
    pub(crate) downlink_only: Option<Duration>,
    pub(crate) stats: Stats,
    pub(crate) buffer: Option<i32>,
}

impl Default for Level {
    fn default() -> Self {
        Self {
            handshake: Some(Duration::from_secs(60)),
            conn_idle: Some(Duration::from_secs(300)),
            uplink_only: Some(Duration::from_secs(1)),
            downlink_only: Some(Duration::from_secs(1)),
            stats: Stats::default(),
            buffer: Some(default_buffer()),
        }
    }
}

/// The reference's per-connection buffer default: 512 KiB on the hosts this tree builds for,
/// 4 KiB on a 64-bit ARM host, and unlimited where the reference leaves the pipe unbounded.
fn default_buffer() -> i32 {
    #[cfg(target_arch = "aarch64")]
    {
        4
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        512
    }
}

impl Level {
    fn flow(&self) -> Flow {
        Flow {
            handshake: self.handshake,
            conn_idle: self.conn_idle,
            uplink_only: self.uplink_only,
            downlink_only: self.downlink_only,
            buffer: self.buffer.and_then(buffer_bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flow {
    pub(crate) handshake: Option<Duration>,
    pub(crate) conn_idle: Option<Duration>,
    pub(crate) uplink_only: Option<Duration>,
    pub(crate) downlink_only: Option<Duration>,
    pub(crate) buffer: Option<usize>,
}

impl Flow {
    pub(crate) fn handshake(&self) -> Option<Duration> {
        self.handshake
    }

    pub(crate) fn conn_idle(&self) -> Option<Duration> {
        self.conn_idle
    }

    pub(crate) fn buffer(&self) -> Option<usize> {
        self.buffer
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) levels: BTreeMap<u32, Level>,
    pub(crate) system: SystemStats,
}

impl Config {
    pub(crate) fn flow(&self, level: u32) -> Flow {
        self.levels
            .get(&level)
            .map_or_else(Level::default, Level::clone)
            .flow()
    }
}

static CONFIG: Mutex<Option<Arc<Config>>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<Arc<Config>>> {
    CONFIG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read the top-level `policy` object, keeping the reference's field names and units.
pub(crate) fn parse(root: &Json) -> Result<Config, String> {
    let mut config = Config::default();
    let Some(section) = root.get("policy") else {
        return Ok(config);
    };
    let Json::Obj(pairs) = section else {
        return Err("`policy` is not an object".to_owned());
    };
    for (key, value) in pairs {
        match key.as_str() {
            "levels" => config.levels = levels(value)?,
            "system" => config.system = system_row(value)?,
            _ => {}
        }
    }
    Ok(config)
}

fn levels(value: &Json) -> Result<BTreeMap<u32, Level>, String> {
    let Json::Obj(rows) = value else {
        return Err("`policy.levels` is not an object".to_owned());
    };
    let mut levels = BTreeMap::new();
    for (name, row) in rows {
        let level: u32 = name
            .parse()
            .map_err(|_| format!("policy level `{name}` is not a number"))?;
        levels.insert(level, level_row(row, name)?);
    }
    Ok(levels)
}

fn level_row(value: &Json, name: &str) -> Result<Level, String> {
    let Json::Obj(pairs) = value else {
        return Err(format!("policy level `{name}` is not an object"));
    };
    let mut level = Level::default();
    for (key, value) in pairs {
        match key.as_str() {
            "handshake" => level.handshake = seconds(value, "handshake")?,
            "connIdle" => level.conn_idle = seconds(value, "connIdle")?,
            "uplinkOnly" => level.uplink_only = seconds(value, "uplinkOnly")?,
            "downlinkOnly" => level.downlink_only = seconds(value, "downlinkOnly")?,
            "statsUserUplink" => level.stats.user_uplink = boolean(value, key)?,
            "statsUserDownlink" => level.stats.user_downlink = boolean(value, key)?,
            "statsUserOnline" => level.stats.user_online = boolean(value, key)?,
            "bufferSize" => level.buffer = Some(buffer_kib(value)?),
            _ => {}
        }
    }
    Ok(level)
}

fn system_row(value: &Json) -> Result<SystemStats, String> {
    let Json::Obj(pairs) = value else {
        return Err("`policy.system` is not an object".to_owned());
    };
    let mut stats = SystemStats::default();
    for (key, value) in pairs {
        match key.as_str() {
            "statsInboundUplink" => stats.inbound_uplink = boolean(value, key)?,
            "statsInboundDownlink" => stats.inbound_downlink = boolean(value, key)?,
            "statsOutboundUplink" => stats.outbound_uplink = boolean(value, key)?,
            "statsOutboundDownlink" => stats.outbound_downlink = boolean(value, key)?,
            _ => {}
        }
    }
    Ok(stats)
}

fn boolean(value: &Json, key: &str) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("policy `{key}` is not a boolean"))
}

/// A timeout is a whole number of seconds in the reference's JSON; zero keeps the default.
fn seconds(value: &Json, key: &str) -> Result<Option<Duration>, String> {
    let count = value
        .as_u32()
        .ok_or_else(|| format!("policy `{key}` is not a count of seconds"))?;
    Ok((count > 0).then(|| Duration::from_secs(u64::from(count))))
}

fn buffer_kib(value: &Json) -> Result<i32, String> {
    let number = match value {
        Json::Num(number) if number.fract() == 0.0 => *number,
        _ => return Err("policy `bufferSize` is not a whole number of KiB".to_owned()),
    };
    if !(-2_147_483_648.0..=2_147_483_647.0).contains(&number) {
        return Err("policy `bufferSize` is outside a signed 32-bit count".to_owned());
    }
    Ok(number as i32)
}

/// The reference's conversion: a non-negative count is KiB, a negative one is unlimited.
fn buffer_bytes(kib: i32) -> Option<usize> {
    if kib < 0 {
        return Some(usize::MAX);
    }
    usize::try_from(kib)
        .ok()
        .map(|kib| kib.saturating_mul(1024))
}

/// Install the parsed policy before any inbound opens.
pub(crate) fn install(root: &Json) -> Result<Arc<Config>, String> {
    let config = Arc::new(parse(root)?);
    *lock() = Some(Arc::clone(&config));
    Ok(config)
}

pub(crate) fn configured() -> Option<Arc<Config>> {
    lock().clone()
}

/// The policy a level carries, with the reference's defaults for every field the config did not name.
pub(crate) fn flow(level: u32) -> Flow {
    configured().map_or_else(|| Level::default().flow(), |config| config.flow(level))
}

pub(crate) fn system() -> SystemStats {
    configured().map_or_else(SystemStats::default, |config| config.system)
}

#[cfg(test)]
pub(crate) fn clear() {
    *lock() = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_level_reads_the_reference_units_and_names() {
        let _guard = crate::stats::test_lock();
        let root = crate::json::parse(
            r#"{"policy":{"levels":{"0":{"handshake":30,"connIdle":600,"uplinkOnly":2,
                "downlinkOnly":3,"bufferSize":32,"statsUserUplink":true,
                "statsUserDownlink":true,"statsUserOnline":true}},
                "system":{"statsInboundUplink":true,"statsOutboundDownlink":true}}}"#,
        )
        .expect("parses");
        let config = parse(&root).expect("policy parses");
        let level = config.levels.get(&0).expect("level zero");
        assert_eq!(level.handshake, Some(Duration::from_secs(30)));
        assert_eq!(level.conn_idle, Some(Duration::from_secs(600)));
        assert_eq!(level.uplink_only, Some(Duration::from_secs(2)));
        assert_eq!(level.downlink_only, Some(Duration::from_secs(3)));
        assert_eq!(level.buffer, Some(32));
        assert_eq!(level.flow().buffer, Some(32 * 1024));
        assert!(config.system.inbound_uplink);
        assert!(config.system.outbound_downlink);
        assert!(!config.system.inbound_downlink);
    }

    #[test]
    fn a_negative_buffer_is_unlimited_and_a_missing_level_is_not_level_zero() {
        let _guard = crate::stats::test_lock();
        let root =
            crate::json::parse(r#"{"policy":{"levels":{"1":{"bufferSize":-1}}}}"#).expect("parses");
        let config = parse(&root).expect("policy parses");
        assert_eq!(
            config.levels.get(&1).expect("level one").flow().buffer,
            Some(usize::MAX)
        );
        let default = config.flow(0);
        assert_eq!(default.handshake(), Some(Duration::from_secs(60)));
        assert_eq!(default.conn_idle(), Some(Duration::from_secs(300)));
        assert_eq!(default.buffer(), Some(default_buffer() as usize * 1024));
    }

    #[test]
    fn a_level_that_is_not_a_number_or_an_object_is_refused() {
        let _guard = crate::stats::test_lock();
        let root = crate::json::parse(r#"{"policy":{"levels":{"user":{}}}}"#).expect("parses");
        assert!(parse(&root)
            .expect_err("a level is a number")
            .contains("user"));
        let root = crate::json::parse(r#"{"policy":{"levels":{"0":1}}}"#).expect("parses");
        assert!(parse(&root)
            .expect_err("a level is an object")
            .contains("level `0`"));
    }

    #[test]
    fn the_installed_policy_answers_a_level_and_the_system_flags() {
        let _guard = crate::stats::test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"policy":{"levels":{"2":{"connIdle":42}},
                "system":{"statsInboundUplink":true}}}"#,
        )
        .expect("parses");
        install(&root).expect("policy installs");
        assert_eq!(flow(2).conn_idle(), Some(Duration::from_secs(42)));
        assert!(system().inbound_uplink);
        clear();
    }
}
