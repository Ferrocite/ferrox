use crate::json::Json;
use crate::policy::{self, Flow, SystemStats};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

/// One reference counter: a signed 64-bit value that every flow shares.
#[derive(Debug, Default)]
pub(crate) struct Counter(AtomicI64);

impl Counter {
    pub(crate) fn add(&self, bytes: u64) {
        self.0.fetch_add(bytes.cast_signed(), Ordering::Relaxed);
    }

    pub(crate) fn value(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
struct Registry {
    counters: HashMap<String, Arc<Counter>>,
    online: HashMap<String, u64>,
}

impl Registry {
    fn counter(&mut self, name: &str) -> Arc<Counter> {
        Arc::clone(
            self.counters
                .entry(name.to_owned())
                .or_insert_with(|| Arc::new(Counter::default())),
        )
    }

    fn online_add(&mut self, email: &str) {
        *self.online.entry(email.to_owned()).or_insert(0) += 1;
    }

    fn online_remove(&mut self, email: &str) {
        let Some(count) = self.online.get_mut(email) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.online.remove(email);
        }
    }
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));
static ENABLED: AtomicBool = AtomicBool::new(false);
static SYSTEM: Mutex<SystemStats> = Mutex::new(SystemStats {
    inbound_uplink: false,
    inbound_downlink: false,
    outbound_uplink: false,
    outbound_downlink: false,
});

fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn system() -> SystemStats {
    *SYSTEM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The metering one flow carries: counters in the reference's directions, the level policy,
/// and the online lease a user flow holds until its last handle drops.
#[derive(Debug, Clone, Default)]
pub(crate) struct Meter {
    read: Vec<Arc<Counter>>,
    write: Vec<Arc<Counter>>,
    online: Option<Arc<OnlineLease>>,
    policy: Option<Flow>,
}

impl Meter {
    pub(crate) fn is_empty(&self) -> bool {
        self.read.is_empty()
            && self.write.is_empty()
            && self.online.is_none()
            && self.policy.is_none()
    }

    pub(crate) fn read(&self, bytes: usize) {
        for counter in &self.read {
            counter.add(bytes as u64);
        }
    }

    pub(crate) fn write(&self, bytes: usize) {
        for counter in &self.write {
            counter.add(bytes as u64);
        }
    }

    pub(crate) fn flow(&self) -> Option<Flow> {
        self.policy
    }

    /// A newer meter for the same flow keeps the counters the older one carried and adds the
    /// ones it names, so wrapping a decoded user never stops the inbound's own count.
    pub(crate) fn merged(mut self, newer: Self) -> Self {
        self.read.extend(newer.read);
        self.write.extend(newer.write);
        if newer.online.is_some() {
            self.online = newer.online;
        }
        if newer.policy.is_some() {
            self.policy = newer.policy;
        }
        self
    }
}

#[derive(Debug)]
struct OnlineLease {
    email: String,
}

impl Drop for OnlineLease {
    fn drop(&mut self) {
        registry().online_remove(&self.email);
    }
}

fn counter(name: &str) -> Arc<Counter> {
    registry().counter(name)
}

fn traffic(kind: &str, name: &str, direction: &str) -> String {
    format!("{kind}>>>{name}>>>traffic>>>{direction}")
}

/// Whether the config asked for the stats manager at all.
pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Install the stats manager and register every counter the reference would have at startup.
pub(crate) fn install(root: &Json) -> Result<bool, String> {
    let Some(section) = root.get("stats") else {
        ENABLED.store(false, Ordering::Relaxed);
        return Ok(false);
    };
    if !matches!(section, Json::Obj(_)) {
        return Err("`stats` is not an object".to_owned());
    }
    ENABLED.store(true, Ordering::Relaxed);
    let system = policy::system();
    *SYSTEM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = system;
    register_system(root, system);
    register_users(root);
    Ok(true)
}

fn register_system(root: &Json, system: SystemStats) {
    if system.inbound_uplink || system.inbound_downlink {
        for inbound in root.get("inbounds").and_then(Json::as_arr).unwrap_or(&[]) {
            let Some(tag) = inbound
                .get("tag")
                .and_then(Json::as_str)
                .filter(|tag| !tag.is_empty())
            else {
                continue;
            };
            if system.inbound_uplink {
                counter(&traffic("inbound", tag, "uplink"));
            }
            if system.inbound_downlink {
                counter(&traffic("inbound", tag, "downlink"));
            }
        }
    }
    if system.outbound_uplink || system.outbound_downlink {
        for outbound in root.get("outbounds").and_then(Json::as_arr).unwrap_or(&[]) {
            let Some(tag) = outbound
                .get("tag")
                .and_then(Json::as_str)
                .filter(|tag| !tag.is_empty())
            else {
                continue;
            };
            if system.outbound_uplink {
                counter(&traffic("outbound", tag, "uplink"));
            }
            if system.outbound_downlink {
                counter(&traffic("outbound", tag, "downlink"));
            }
        }
    }
}

fn register_users(root: &Json) {
    for inbound in root.get("inbounds").and_then(Json::as_arr).unwrap_or(&[]) {
        let settings = inbound.get("settings");
        for list in ["clients", "accounts", "users"] {
            let Some(rows) = settings
                .and_then(|settings| settings.get(list))
                .and_then(Json::as_arr)
            else {
                continue;
            };
            for row in rows {
                let Some(email) = row
                    .get("email")
                    .and_then(Json::as_str)
                    .filter(|email| !email.is_empty())
                else {
                    continue;
                };
                let level = row.get("level").and_then(Json::as_u32).unwrap_or(0);
                let Some(policy) = policy::configured()
                    .and_then(|config| config.levels.get(&level).map(|level| level.stats))
                else {
                    continue;
                };
                if policy.user_uplink {
                    counter(&traffic("user", email, "uplink"));
                }
                if policy.user_downlink {
                    counter(&traffic("user", email, "downlink"));
                }
            }
        }
    }
}

/// The inbound meter: reads are uplink, writes are downlink, exactly the reference's raw-conn wrap.
pub(crate) fn inbound(tag: Option<&str>, level: u32) -> Meter {
    let policy = policy::flow(level);
    if !enabled() {
        return Meter {
            policy,
            ..Meter::default()
        };
    }
    let system = system();
    let name = tag.filter(|tag| !tag.is_empty());
    let read = name
        .filter(|_| system.inbound_uplink)
        .map(|tag| counter(&traffic("inbound", tag, "uplink")))
        .into_iter()
        .collect();
    let write = name
        .filter(|_| system.inbound_downlink)
        .map(|tag| counter(&traffic("inbound", tag, "downlink")))
        .into_iter()
        .collect();
    Meter {
        read,
        write,
        online: None,
        policy,
    }
}

/// The outbound meter: writes are uplink and reads are downlink, the reference's own direction
/// swap at the outbound handler.
pub(crate) fn outbound(tag: Option<&str>) -> Meter {
    if !enabled() {
        return Meter::default();
    }
    let system = system();
    let name = tag.filter(|tag| !tag.is_empty());
    let read = name
        .filter(|_| system.outbound_downlink)
        .map(|tag| counter(&traffic("outbound", tag, "downlink")))
        .into_iter()
        .collect();
    let write = name
        .filter(|_| system.outbound_uplink)
        .map(|tag| counter(&traffic("outbound", tag, "uplink")))
        .into_iter()
        .collect();
    Meter {
        read,
        write,
        online: None,
        policy: None,
    }
}

/// The user meter a decoded account adds: payload counters and the online lease the reference
/// holds for the life of the session.
pub(crate) fn user(email: &str, level: u32) -> Meter {
    let flow = policy::flow(level);
    if !enabled() || email.is_empty() {
        return Meter {
            policy: flow,
            ..Meter::default()
        };
    }
    let Some(policy) =
        policy::configured().and_then(|config| config.levels.get(&level).map(|level| level.stats))
    else {
        return Meter {
            policy: flow,
            ..Meter::default()
        };
    };
    let read = policy
        .user_uplink
        .then(|| counter(&traffic("user", email, "uplink")))
        .into_iter()
        .collect();
    let write = policy
        .user_downlink
        .then(|| counter(&traffic("user", email, "downlink")))
        .into_iter()
        .collect();
    let online = policy.user_online.then(|| {
        registry().online_add(email);
        Arc::new(OnlineLease {
            email: email.to_owned(),
        })
    });
    Meter {
        read,
        write,
        online,
        policy: flow,
    }
}

/// One tag's traffic, as the metrics app prints it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Traffic {
    pub(crate) uplink: i64,
    pub(crate) downlink: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) inbound: BTreeMap<String, Traffic>,
    pub(crate) outbound: BTreeMap<String, Traffic>,
    pub(crate) user: BTreeMap<String, Traffic>,
    pub(crate) online: BTreeMap<String, u64>,
}

impl Snapshot {
    fn traffic(&mut self, name: &str, value: i64) {
        let mut parts = name.split(">>>");
        let (Some(kind), Some(tag), Some("traffic"), Some(direction)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return;
        };
        let map = match kind {
            "inbound" => &mut self.inbound,
            "outbound" => &mut self.outbound,
            "user" => &mut self.user,
            _ => return,
        };
        let row = map.entry(tag.to_owned()).or_default();
        match direction {
            "uplink" => row.uplink = value,
            "downlink" => row.downlink = value,
            _ => {}
        }
    }
}

/// A consistent read of every counter and online map the manager holds.
pub(crate) fn snapshot() -> Snapshot {
    let registry = registry();
    let mut snapshot = Snapshot {
        online: registry
            .online
            .iter()
            .map(|(email, count)| (email.clone(), *count))
            .collect(),
        ..Snapshot::default()
    };
    for (name, counter) in &registry.counters {
        snapshot.traffic(name, counter.value());
    }
    snapshot
}

#[cfg(test)]
pub(crate) fn clear() {
    let mut registry = registry();
    registry.counters.clear();
    registry.online.clear();
    ENABLED.store(false, Ordering::Relaxed);
    *SYSTEM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = SystemStats::default();
    policy::clear();
}

#[cfg(test)]
static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[cfg(test)]
pub(crate) fn test_lock() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_names_are_registered_and_their_bytes_add_up() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"system":{"statsInboundUplink":true,
                "statsOutboundDownlink":true}},"inbounds":[{"tag":"in"}],
                "outbounds":[{"tag":"out"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let inbound = inbound(Some("in"), 0);
        inbound.read(12);
        inbound.write(99);
        let outbound = outbound(Some("out"));
        outbound.read(7);
        outbound.write(99);
        let snapshot = snapshot();
        assert_eq!(
            snapshot.inbound.get("in"),
            Some(&Traffic {
                uplink: 12,
                downlink: 0
            })
        );
        assert_eq!(
            snapshot.outbound.get("out"),
            Some(&Traffic {
                uplink: 0,
                downlink: 7
            })
        );
        clear();
    }

    #[test]
    fn a_user_meter_keeps_the_inbound_counters_it_was_added_to() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserUplink":true}},
                "system":{"statsInboundUplink":true}},"inbounds":[{"tag":"in"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let meter = inbound(Some("in"), 0).merged(user("alice@example", 1));
        meter.read(9);
        let snapshot = snapshot();
        assert_eq!(snapshot.inbound["in"].uplink, 9);
        assert_eq!(snapshot.user["alice@example"].uplink, 9);
        clear();
    }

    #[test]
    fn a_user_flow_holds_online_until_its_last_clone_drops() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserUplink":true,
                "statsUserOnline":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let meter = user("alice@example", 1);
        let clone = meter.clone();
        meter.read(5);
        assert_eq!(snapshot().online.get("alice@example"), Some(&1));
        drop(meter);
        assert_eq!(snapshot().online.get("alice@example"), Some(&1));
        drop(clone);
        assert_eq!(snapshot().online.get("alice@example"), None);
        assert_eq!(
            snapshot().user.get("alice@example").expect("user").uplink,
            5
        );
        clear();
    }

    #[test]
    fn a_stats_section_that_is_not_an_object_is_refused() {
        let root = crate::json::parse(r#"{"stats":true}"#).expect("parses");
        assert!(install(&root).expect_err("not an object").contains("stats"));
    }
}
