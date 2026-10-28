//! The routing script: xray's Lua hook that answers a flow before the rule table does.
//!
//! The script reads the same context a rule does and returns an outbound tag; the modules it can
//! `require` are rebuilt here from this tree's matchers, not linked from a Lua runtime.

use crate::json::Json;
use crate::router::{add_domain, ip_matcher, Assets, DomainMatcher, Flow, IpMatcher, Network};
use mlua::{
    AnyUserData, Error as LuaError, HookTriggers, Lua, LuaOptions, MetaMethod, Result as LuaResult,
    StdLib, Table, UserData, UserDataMethods, Value, Variadic, VmState,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(6);
const LOAD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_IDLE_STATES: usize = 16;
const NETWORK_UNKNOWN: i64 = 0;
const NETWORK_TCP: i64 = 2;
const NETWORK_UDP: i64 = 3;
const NETWORK_UNIX: i64 = 4;

/// What a script may call back into while it runs: the resolver a `xray.dns.Query` uses, and the
/// balancer table a `xray.router.PickOutbound` reads. Both are built once, so a call clones handles.
pub(crate) type Resolver = dyn Fn(&str, u16, bool, bool, bool) -> (Vec<IpAddr>, u32) + Send + Sync;
pub(crate) type Picker = dyn Fn(&str) -> Result<String, String> + Send + Sync;

#[derive(Clone)]
pub(crate) struct ScriptCallbacks {
    pub(crate) resolve: Arc<Resolver>,
    pub(crate) pick: Arc<Picker>,
}

impl std::fmt::Debug for ScriptCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScriptCallbacks")
    }
}

struct Call {
    resolve: Arc<Resolver>,
    pick: Arc<Picker>,
}

#[derive(Default)]
struct CallHooks {
    call: Mutex<Option<Call>>,
}

impl CallHooks {
    fn set(&self, callbacks: &ScriptCallbacks) {
        *self.call.lock().unwrap_or_else(PoisonError::into_inner) = Some(Call {
            resolve: Arc::clone(&callbacks.resolve),
            pick: Arc::clone(&callbacks.pick),
        });
    }

    fn clear(&self) {
        self.call
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn resolve(
        &self,
        host: &str,
        port: u16,
        fake: bool,
        v4: bool,
        v6: bool,
    ) -> LuaResult<(Vec<IpAddr>, u32)> {
        let resolve = {
            let call = self.call.lock().unwrap_or_else(PoisonError::into_inner);
            call.as_ref().map(|call| Arc::clone(&call.resolve))
        }
        .ok_or_else(|| LuaError::RuntimeError("no routing context".into()))?;
        Ok(resolve(host, port, fake, v4, v6))
    }

    fn pick(&self, tag: &str) -> LuaResult<(Option<String>, Option<String>)> {
        let pick = {
            let call = self.call.lock().unwrap_or_else(PoisonError::into_inner);
            call.as_ref().map(|call| Arc::clone(&call.pick))
        }
        .ok_or_else(|| LuaError::RuntimeError("no routing context".into()))?;
        match pick(tag) {
            Ok(tag) => Ok((Some(tag), None)),
            Err(error) => Ok((None, Some(error))),
        }
    }
}

struct State {
    lua: Lua,
    hooks: Arc<CallHooks>,
}

/// The compiled routing script and the states it runs in. A state is lent to one flow at a time and
/// dropped after a failure, so a script that timed out cannot leave a half-entered call behind.
pub(crate) struct ScriptRouter {
    source: Vec<u8>,
    name: String,
    dirs: Arc<Vec<PathBuf>>,
    idle: Mutex<Vec<State>>,
}

impl std::fmt::Debug for ScriptRouter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptRouter")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Everything `HandleRoute` reads, copied out of the borrowed flow before the call because a Lua
/// userdata has to outlive the connection's borrow.
struct ScriptContext {
    source: Vec<IpAddr>,
    target: Vec<IpAddr>,
    local: Vec<IpAddr>,
    inbound: String,
    source_port: u16,
    target_port: u16,
    local_port: u16,
    domain: String,
    network: i64,
    protocol: String,
}

impl ScriptRouter {
    /// Load the script xray names: a path resolved as `ResolveLuaFile` does, with a syntax error
    /// reported before any socket opens.
    pub(crate) fn parse_in(path: &str, dirs: Vec<PathBuf>) -> Result<Self, String> {
        let name = resolve(path, &dirs)?;
        let source =
            std::fs::read(&name).map_err(|error| format!("routing script `{path}`: {error}"))?;
        let router = Self {
            source,
            name: name.display().to_string(),
            dirs: Arc::new(dirs),
            idle: Mutex::new(Vec::new()),
        };
        let state = router.new_state()?;
        router.release(state);
        Ok(router)
    }

    fn release(&self, state: State) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < MAX_IDLE_STATES {
            idle.push(state);
        }
    }

    fn acquire(&self) -> Result<State, String> {
        if let Some(state) = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
        {
            return Ok(state);
        }
        self.new_state()
    }

    fn new_state(&self) -> Result<State, String> {
        let lua = Lua::new_with(
            StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::OS,
            LuaOptions::default(),
        )
        .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let hooks = Arc::new(CallHooks::default());
        install(&lua, &hooks, &self.dirs)
            .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let deadline = Instant::now() + LOAD_TIMEOUT;
        lua.set_hook(
            HookTriggers::new().every_nth_instruction(1000),
            move |_, _| {
                if Instant::now() >= deadline {
                    Err(LuaError::RuntimeError("routing script timed out".into()))
                } else {
                    Ok(VmState::Continue)
                }
            },
        )
        .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let run = lua.load(&self.source).set_name(&self.name).exec();
        lua.remove_hook();
        run.map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let handle = lua
            .globals()
            .get::<Value>("HandleRoute")
            .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        if !matches!(handle, Value::Function(_)) {
            return Err("routing script must define HandleRoute(...)".into());
        }
        Ok(State { lua, hooks })
    }

    /// Run `HandleRoute` for one flow; `None` means the script has no clue and the rule table decides.
    pub(crate) fn route(
        &self,
        flow: &Flow,
        callbacks: &ScriptCallbacks,
    ) -> Result<Option<String>, String> {
        let state = self.acquire()?;
        let context = ScriptContext {
            source: flow.source.map(|addr| vec![addr.ip()]).unwrap_or_default(),
            target: flow.ip.map(|ip| vec![ip]).unwrap_or_default(),
            local: flow.local.map(|addr| vec![addr.ip()]).unwrap_or_default(),
            inbound: flow.inbound_tag.unwrap_or("").to_owned(),
            source_port: flow.source.map_or(0, |addr| addr.port()),
            target_port: flow.port.unwrap_or(0),
            local_port: flow.local.map_or(0, |addr| addr.port()),
            domain: flow.domain.unwrap_or("").to_ascii_lowercase(),
            network: match flow.network {
                Network::Tcp => NETWORK_TCP,
                Network::Udp => NETWORK_UDP,
            },
            protocol: flow.protocol.unwrap_or("").to_owned(),
        };
        state.hooks.set(callbacks);
        let guard = ClearOnDrop(&state.hooks);
        let deadline = Instant::now() + TIMEOUT;
        state
            .lua
            .set_hook(
                HookTriggers::new().every_nth_instruction(1000),
                move |_, _| {
                    if Instant::now() >= deadline {
                        Err(LuaError::RuntimeError("routing script timed out".into()))
                    } else {
                        Ok(VmState::Continue)
                    }
                },
            )
            .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let result = call(&state.lua, context);
        state.lua.remove_hook();
        drop(guard);
        match result {
            Ok(tag) => {
                self.release(state);
                Ok(tag)
            }
            Err(error) => Err(error),
        }
    }
}

struct ClearOnDrop<'a>(&'a CallHooks);

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

fn call(lua: &Lua, context: ScriptContext) -> Result<Option<String>, String> {
    let handle = lua
        .globals()
        .get::<Value>("HandleRoute")
        .map_err(|error| error.to_string())?;
    let Value::Function(handle) = handle else {
        return Err("routing script must define HandleRoute(...)".into());
    };
    let ScriptContext {
        source,
        target,
        local,
        inbound,
        source_port,
        target_port,
        local_port,
        domain,
        network,
        protocol,
    } = context;
    let context = lua
        .create_userdata(ContextUser {
            source,
            target,
            local,
            attributes: HashMap::new(),
        })
        .map_err(|error| error.to_string())?;
    let values = handle
        .call::<mlua::MultiValue>((
            context,
            inbound,
            source_port,
            target_port,
            local_port,
            domain,
            network,
            protocol,
            String::new(),
            0,
            false,
        ))
        .map_err(|error| error.to_string())?;
    let mut values = values.into_iter();
    let outbound = values.next().unwrap_or(Value::Nil);
    let rule = values.next().unwrap_or(Value::Nil);
    let error = values.next().unwrap_or(Value::Nil);
    if !matches!(error, Value::Nil) {
        let message = match error {
            Value::String(text) => text.to_string_lossy(),
            other => format!("routing script error must be an error or string, not {other:?}"),
        };
        return Err(message);
    }
    let outbound = match outbound {
        Value::Nil => None,
        Value::String(tag) => {
            let tag = tag.to_string_lossy();
            if tag.is_empty() {
                None
            } else {
                Some(tag)
            }
        }
        _ => return Err("routing script outboundTag must be a string or nil".into()),
    };
    if !matches!(rule, Value::Nil | Value::String(_)) {
        return Err("routing script ruleTag must be a string".into());
    }
    Ok(outbound)
}

fn resolve(path: &str, dirs: &[PathBuf]) -> Result<PathBuf, String> {
    let named = PathBuf::from(path);
    let mut candidates = Vec::new();
    if named.is_absolute() {
        candidates.push(named);
    } else {
        for name in [
            "xray.location.confdir",
            "XRAY_LOCATION_CONFDIR",
            "xray.location.config",
            "XRAY_LOCATION_CONFIG",
        ] {
            if let Some(dir) = std::env::var_os(name) {
                candidates.push(PathBuf::from(dir).join(path));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join(path));
        }
        if let Some(parent) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(PathBuf::from))
        {
            candidates.push(parent.join(path));
        }
        for dir in dirs {
            candidates.push(dir.join(path));
        }
    }
    for candidate in &candidates {
        let candidate = std::path::absolute(candidate)
            .map_err(|error| format!("routing script `{path}`: {error}"))?;
        let metadata = match std::fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("routing script `{path}`: {error}")),
        };
        if !metadata.is_file() {
            return Err(format!(
                "routing script `{path}` is not a regular file: {}",
                candidate.display()
            ));
        }
        let resolved = std::fs::canonicalize(&candidate)
            .map_err(|error| format!("routing script `{path}`: {error}"))?;
        if resolved.extension() != Some(std::ffi::OsStr::new("lua")) {
            return Err(format!(
                "routing script `{path}` must have a .lua extension: {}",
                resolved.display()
            ));
        }
        return Ok(resolved);
    }
    Err(format!(
        "routing script `{path}` was not found in {} locations",
        candidates.len()
    ))
}

fn dns_answer(
    lua: &Lua,
    addrs: Vec<IpAddr>,
    ttl: u32,
    ipv4: bool,
    ipv6: bool,
) -> LuaResult<(Value, f64, Option<LuaError>)> {
    let addrs = addrs
        .into_iter()
        .filter(|addr| (ipv4 && addr.is_ipv4()) || (ipv6 && addr.is_ipv6()))
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Ok((
            Value::Nil,
            0.0,
            Some(LuaError::RuntimeError("empty response".to_owned())),
        ));
    }
    let list = lua.create_userdata(IpList {
        items: Arc::new(addrs),
    })?;
    Ok((Value::UserData(list), f64::from(ttl), None))
}

#[allow(clippy::too_many_lines)]
fn install(lua: &Lua, hooks: &Arc<CallHooks>, dirs: &Arc<Vec<PathBuf>>) -> LuaResult<()> {
    for name in [
        "dofile",
        "loadfile",
        "load",
        "loadstring",
        "print",
        "getfenv",
        "setfenv",
        "getmetatable",
        "setmetatable",
        "rawget",
        "rawset",
        "collectgarbage",
        "module",
        "newproxy",
        "_printregs",
        "package",
    ] {
        lua.globals().set(name, Value::Nil)?;
    }
    if let Ok(table) = lua.globals().get::<mlua::Table>("os") {
        for name in [
            "execute",
            "exit",
            "remove",
            "rename",
            "tmpname",
            "setlocale",
        ] {
            table.set(name, Value::Nil)?;
        }
    }
    if let Ok(table) = lua.globals().get::<mlua::Table>("string") {
        table.set("dump", Value::Nil)?;
    }

    let router = lua.create_table()?;
    router.set("NetworkUnknown", NETWORK_UNKNOWN)?;
    router.set("NetworkTCP", NETWORK_TCP)?;
    router.set("NetworkUDP", NETWORK_UDP)?;
    router.set("NetworkUNIX", NETWORK_UNIX)?;
    router.set("LocalOS", crate::router::local_os())?;
    let pick_hooks = Arc::clone(hooks);
    router.set(
        "PickOutbound",
        lua.create_function(move |_, tag: String| pick_hooks.pick(&tag))?,
    )?;
    router.set(
        "FindProcess",
        lua.create_function(|_, _: Variadic<Value>| {
            Ok((
                0,
                String::new(),
                String::new(),
                "process lookup is not carried".to_owned(),
            ))
        })?,
    )?;

    let log = lua.create_table()?;
    for name in ["Debug", "Info"] {
        log.set(name, lua.create_function(|_, _: Variadic<Value>| Ok(()))?)?;
    }
    for name in ["Warning", "Error"] {
        log.set(
            name,
            lua.create_function(|lua, values: Variadic<Value>| {
                let mut text = String::new();
                for value in values {
                    if let Ok(part) = lua.coerce_string(value).and_then(|part| {
                        part.ok_or_else(|| LuaError::RuntimeError("log value is not text".into()))
                    }) {
                        text.push_str(&part.to_string_lossy());
                    }
                }
                if !text.is_empty() {
                    eprintln!("routing script: {text}");
                }
                Ok(())
            })?,
        )?;
    }

    let dns = lua.create_table()?;
    let query_hooks = Arc::clone(hooks);
    dns.set(
        "Query",
        lua.create_function(
            move |lua, (name, ipv4, ipv6, fake): (String, bool, bool, bool)| {
                let (addrs, ttl) = match query_hooks.resolve(&name, 0, fake, ipv4, ipv6) {
                    Ok(answer) => answer,
                    Err(error) => return Ok((Value::Nil, 0.0, Some(error))),
                };
                dns_answer(lua, addrs, ttl, ipv4, ipv6)
            },
        )?,
    )?;
    let servers = lua.create_table()?;
    if let Some(resolver) = crate::dnsapp::installed() {
        for (id, index) in resolver.script_servers() {
            let server = lua.create_table()?;
            server.set("ID", id)?;
            let resolver = Arc::clone(&resolver);
            server.set(
                "Query",
                lua.create_function(
                    move |lua, (name, ipv4, ipv6, fake): (String, bool, bool, bool)| match resolver
                        .script_query(index, &name, ipv4, ipv6, fake)
                    {
                        crate::dnsapp::Lookup::Records(addrs, ttl) => {
                            dns_answer(lua, addrs, ttl, ipv4, ipv6)
                        }
                        crate::dnsapp::Lookup::Empty | crate::dnsapp::Lookup::Skipped => Ok((
                            Value::Nil,
                            0.0,
                            Some(LuaError::RuntimeError("empty response".to_owned())),
                        )),
                        crate::dnsapp::Lookup::Rcode(code) => Ok((
                            Value::Nil,
                            0.0,
                            Some(LuaError::RuntimeError(format!("response code {code}"))),
                        )),
                        crate::dnsapp::Lookup::Failed => Ok((
                            Value::Nil,
                            0.0,
                            Some(LuaError::RuntimeError("lookup failed".to_owned())),
                        )),
                    },
                )?,
            )?;
            servers.set(index + 1, server)?;
        }
    } else {
        let server = lua.create_table()?;
        server.set("ID", "localhost")?;
        server.set(
            "Query",
            lua.create_function(
                |lua, (name, ipv4, ipv6, _fake): (String, bool, bool, bool)| {
                    let (addrs, ttl) = crate::router::resolve_ips_ttl(&name, 0);
                    dns_answer(lua, addrs, ttl, ipv4, ipv6)
                },
            )?,
        )?;
        servers.set(1, server)?;
    }
    dns.set("Servers", servers)?;

    let dns_dirs = Arc::clone(dirs);
    let geodata = lua.create_table()?;
    geodata.set(
        "BuildDomainMatcher",
        lua.create_function(move |_, rules: Variadic<String>| {
            build_domain_matcher(rules.into_iter().collect(), &dns_dirs)
        })?,
    )?;
    let ip_dirs = Arc::clone(dirs);
    geodata.set(
        "BuildIPMatcher",
        lua.create_function(move |_, rules: Variadic<String>| {
            build_ip_matcher(rules.into_iter().collect(), &ip_dirs)
        })?,
    )?;
    let modules: HashMap<&'static str, Table> = [
        ("xray.router", router),
        ("xray.log", log),
        ("xray.dns", dns),
        ("xray.geodata", geodata),
    ]
    .into_iter()
    .collect();
    let require = lua.create_function(move |_, name: String| {
        modules
            .get(name.as_str())
            .cloned()
            .ok_or_else(|| LuaError::RuntimeError(format!("module '{name}' not found")))
    })?;
    lua.globals().set("require", require)?;
    Ok(())
}

fn build_domain_matcher(rules: Vec<String>, dirs: &[PathBuf]) -> LuaResult<DomainMatcherUser> {
    let mut assets = Assets::new(dirs.to_vec());
    let mut matchers = Vec::with_capacity(rules.len());
    for rule in rules {
        let rule = match rule.as_str() {
            value
                if value.starts_with("geosite:")
                    || value.starts_with("ext:")
                    || value.starts_with("ext-domain:")
                    || value.starts_with("ext-site:")
                    || value.starts_with("regexp:")
                    || value.starts_with("domain:")
                    || value.starts_with("full:")
                    || value.starts_with("keyword:")
                    || value.starts_with("dotless:") =>
            {
                value.to_owned()
            }
            value => format!("domain:{value}"),
        };
        let mut matcher = DomainMatcher::new();
        add_domain(&mut matcher, &rule, &mut assets).map_err(LuaError::RuntimeError)?;
        matcher.finish().map_err(LuaError::RuntimeError)?;
        matchers.push(matcher);
    }
    Ok(DomainMatcherUser { rules: matchers })
}

fn build_ip_matcher(rules: Vec<String>, dirs: &[PathBuf]) -> LuaResult<IpMatcherUser> {
    let mut assets = Assets::new(dirs.to_vec());
    let value = Json::Arr(rules.into_iter().map(Json::Str).collect());
    let matcher = ip_matcher(&value, &mut assets, "geodata ip").map_err(LuaError::RuntimeError)?;
    Ok(IpMatcherUser { matcher })
}

struct DomainMatcherUser {
    rules: Vec<DomainMatcher>,
}

impl UserData for DomainMatcherUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("Match", |_, this, domain: String| {
            let lower = domain.to_ascii_lowercase();
            let mut found = Vec::new();
            for (at, matcher) in this.rules.iter().enumerate() {
                if matcher.matches(&lower, &lower) {
                    found.push(u32::try_from(at).unwrap_or(u32::MAX));
                }
            }
            Ok(found)
        });
        methods.add_method("MatchAny", |_, this, domain: String| {
            let lower = domain.to_ascii_lowercase();
            Ok(this
                .rules
                .iter()
                .any(|matcher| matcher.matches(&lower, &lower)))
        });
    }
}

struct IpMatcherUser {
    matcher: IpMatcher,
}

impl UserData for IpMatcherUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("Match", |_, this, ip: Option<AnyUserData>| {
            let Some(ip) = ip else {
                return Ok(false);
            };
            let ip = ip.borrow::<IpUser>()?;
            Ok(this.matcher.matches(ip.0))
        });
        methods.add_method("AnyMatch", |_, this, ips: Option<AnyUserData>| {
            let Some(ips) = ips else {
                return Ok(false);
            };
            let ips = ips.borrow::<IpList>()?;
            Ok(ips.items.iter().any(|ip| this.matcher.matches(*ip)))
        });
        methods.add_method("Matches", |_, this, ips: Option<AnyUserData>| {
            let Some(ips) = ips else {
                return Ok(false);
            };
            let ips = ips.borrow::<IpList>()?;
            Ok(!ips.items.is_empty() && ips.items.iter().all(|ip| this.matcher.matches(*ip)))
        });
        methods.add_method("FilterIPs", |lua, this, ips: Option<AnyUserData>| {
            let ips = match ips {
                Some(ips) => ips.borrow::<IpList>()?.items.clone(),
                None => Arc::new(Vec::<IpAddr>::new()),
            };
            let mut matched = Vec::new();
            let mut unmatched = Vec::new();
            for ip in ips.iter() {
                if this.matcher.matches(*ip) {
                    matched.push(*ip);
                } else {
                    unmatched.push(*ip);
                }
            }
            let matched = lua.create_userdata(IpList {
                items: Arc::new(matched),
            })?;
            let unmatched = lua.create_userdata(IpList {
                items: Arc::new(unmatched),
            })?;
            Ok((matched, unmatched))
        });
        methods.add_method_mut("SetReverse", |_, this, reverse: bool| {
            this.matcher.set_reverse(reverse);
            Ok(())
        });
        methods.add_method_mut("ToggleReverse", |_, this, ()| {
            this.matcher.toggle_reverse();
            Ok(())
        });
    }
}

struct ContextUser {
    source: Vec<IpAddr>,
    target: Vec<IpAddr>,
    local: Vec<IpAddr>,
    attributes: HashMap<String, String>,
}

impl UserData for ContextUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("GetSourceIPs", |lua, this, ()| ip_list(lua, &this.source));
        methods.add_method("GetTargetIPs", |lua, this, ()| ip_list(lua, &this.target));
        methods.add_method("GetLocalIPs", |lua, this, ()| ip_list(lua, &this.local));
        methods.add_method("GetAttributes", |lua, this, ()| {
            let table = lua.create_table()?;
            for (key, value) in &this.attributes {
                table.set(key.as_str(), value.as_str())?;
            }
            Ok(table)
        });
    }
}

fn ip_list(lua: &Lua, addrs: &[IpAddr]) -> LuaResult<Value> {
    if addrs.is_empty() {
        return Ok(Value::Nil);
    }
    Ok(Value::UserData(lua.create_userdata(IpList {
        items: Arc::new(addrs.to_vec()),
    })?))
}

struct IpList {
    items: Arc<Vec<IpAddr>>,
}

impl UserData for IpList {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Len, |_, this, ()| Ok(this.items.len()));
        methods.add_meta_method(MetaMethod::Index, |lua, this, key: Value| {
            let at = match key {
                Value::Integer(at) => at,
                Value::Number(at) => at as i64,
                _ => return Ok(Value::Nil),
            };
            if at < 1 {
                return Ok(Value::Nil);
            }
            match this.items.get((at - 1) as usize) {
                Some(ip) => Ok(Value::UserData(lua.create_userdata(IpUser(*ip))?)),
                None => Ok(Value::Nil),
            }
        });
        methods.add_meta_method(
            MetaMethod::NewIndex,
            |_, _, (_key, _value): (Value, Value)| {
                Err::<(), _>(LuaError::RuntimeError("slice is read-only".into()))
            },
        );
        methods.add_meta_method(MetaMethod::Call, |lua, this, ()| {
            let items = Arc::clone(&this.items);
            let at = Arc::new(AtomicUsize::new(0));
            lua.create_function(move |_, (): ()| {
                let index = at.fetch_add(1, Ordering::Relaxed);
                Ok(items.get(index).map(|ip| IpUser(*ip)))
            })
        });
    }
}

struct MaskUser(Vec<u8>);

impl UserData for MaskUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Len, |_, this, ()| Ok(this.0.len()));
        methods.add_meta_method(MetaMethod::Index, |_, this, key: Value| {
            let at = match key {
                Value::Integer(at) => at,
                Value::Number(at) => at as i64,
                _ => return Ok(Value::Nil),
            };
            if at < 1 {
                return Ok(Value::Nil);
            }
            Ok(this
                .0
                .get((at - 1) as usize)
                .copied()
                .map_or(Value::Nil, |byte| Value::Integer(i64::from(byte))))
        });
        methods.add_meta_method(
            MetaMethod::NewIndex,
            |_, _, (_key, _value): (Value, Value)| {
                Err::<(), _>(LuaError::RuntimeError("mask is read-only".into()))
            },
        );
        methods.add_method("String", |_, this, ()| {
            let mut out = String::with_capacity(this.0.len() * 2);
            for byte in &this.0 {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
            }
            Ok(out)
        });
        methods.add_method("Size", |_, this, ()| {
            let ones = this.0.iter().map(|byte| byte.count_ones()).sum::<u32>();
            Ok((ones, u32::try_from(this.0.len() * 8).unwrap_or(u32::MAX)))
        });
    }
}

#[derive(Clone, Copy)]
struct IpUser(IpAddr);

impl UserData for IpUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::ToString, |_, this, ()| Ok(addr_string(this.0)));
        methods.add_method("String", |_, this, ()| Ok(addr_string(this.0)));
        methods.add_method("To4", |_, this, ()| {
            Ok(to4(this.0).map(|ip| IpUser(IpAddr::V4(ip))))
        });
        methods.add_method("To16", |_, this, ()| Ok(Some(IpUser(to16(this.0)))));
        methods.add_method("EqualTo", |_, this, other: AnyUserData| {
            let other = other.borrow::<IpUser>()?;
            Ok(equal(this.0, other.0))
        });
        methods.add_method("Equal", |_, this, other: AnyUserData| {
            let other = other.borrow::<IpUser>()?;
            Ok(equal(this.0, other.0))
        });
        methods.add_method("Is4", |_, this, ()| Ok(to4(this.0).is_some()));
        methods.add_method("Is6", |_, this, ()| {
            Ok(matches!(this.0, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none()))
        });
        methods.add_method("IsUnspecified", |_, this, ()| Ok(unspecified(this.0)));
        methods.add_method("IsLoopback", |_, this, ()| Ok(loopback(this.0)));
        methods.add_method("IsPrivate", |_, this, ()| Ok(private(this.0)));
        methods.add_method("IsMulticast", |_, this, ()| Ok(multicast(this.0)));
        methods.add_method("IsInterfaceLocalMulticast", |_, this, ()| {
            Ok(interface_multicast(this.0))
        });
        methods.add_method("IsLinkLocalMulticast", |_, this, ()| {
            Ok(link_multicast(this.0))
        });
        methods.add_method("IsLinkLocalUnicast", |_, this, ()| Ok(link_unicast(this.0)));
        methods.add_method("IsGlobalUnicast", |_, this, ()| {
            Ok(!unspecified(this.0)
                && !loopback(this.0)
                && !multicast(this.0)
                && !link_unicast(this.0))
        });
        methods.add_method("DefaultMask", |_, this, ()| {
            Ok(default_mask(this.0).map(MaskUser))
        });
        methods.add_method("Mask", |_, this, mask: AnyUserData| {
            let mask = if mask.is::<MaskUser>() {
                mask.borrow::<MaskUser>()?.0.clone()
            } else {
                let mask = mask.borrow::<IpUser>()?;
                ip_bytes(mask.0).to_vec()
            };
            Ok(mask_ip(this.0, &mask).map(IpUser))
        });
        methods.add_method("MarshalText", |_, this, ()| {
            Ok((addr_string(this.0), Option::<String>::None))
        });
        methods.add_method_mut("UnmarshalText", |_, this, text: String| {
            let addr = text
                .parse::<IpAddr>()
                .map_err(|error| LuaError::RuntimeError(error.to_string()))?;
            this.0 = addr;
            Ok(())
        });
        methods.add_method("AppendText", |_, _, ()| {
            Err::<(), _>(LuaError::RuntimeError("method is not carried".into()))
        });
    }
}

fn addr_string(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip.to_string(),
            None => ip.to_string(),
        },
    }
}

fn to4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    }
}

fn to16(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(ip) => IpAddr::V6(ip.to_ipv6_mapped()),
        IpAddr::V6(_) => addr,
    }
}

fn ip_bytes(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}

fn equal(left: IpAddr, right: IpAddr) -> bool {
    ip_bytes(left) == ip_bytes(right)
}

fn unspecified(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    }
}

fn loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_multicast(),
    }
}

fn private(addr: IpAddr) -> bool {
    match to4(addr) {
        Some(ip) => {
            let octets = ip.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
        }
        None => match addr {
            IpAddr::V6(ip) => ip.segments()[0] & 0xfe00 == 0xfc00,
            IpAddr::V4(_) => false,
        },
    }
}

fn interface_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V6(ip) => ip.segments()[0] & 0xff0f == 0xff01,
        IpAddr::V4(_) => false,
    }
}

fn link_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 224 && octets[1] == 0 && octets[2] == 0
        }
        IpAddr::V6(ip) => ip.segments()[0] & 0xff0f == 0xff02,
    }
}

fn link_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(ip) => ip.segments()[0] & 0xffc0 == 0xfe80,
    }
}

fn default_mask(addr: IpAddr) -> Option<Vec<u8>> {
    let ip = to4(addr)?;
    let first = ip.octets()[0];
    let ones = if first & 0x80 == 0 {
        8
    } else if first & 0xc0 == 0x80 {
        16
    } else if first & 0xe0 == 0xc0 {
        24
    } else {
        return None;
    };
    let mut mask = vec![0xff; ones / 8];
    mask.resize(4, 0);
    Some(mask)
}

fn mask_ip(addr: IpAddr, mask: &[u8]) -> Option<IpAddr> {
    let mut bytes = match addr {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let mut mask = mask.to_vec();
    if mask.len() == 16 && bytes.len() == 4 && mask[..12].iter().all(|byte| *byte == 0xff) {
        mask = mask[12..].to_vec();
    }
    if mask.len() == 4
        && bytes.len() == 16
        && bytes[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
    {
        bytes = bytes[12..].to_vec();
    }
    if bytes.len() != mask.len() {
        return None;
    }
    for (byte, mask) in bytes.iter_mut().zip(mask.iter()) {
        *byte &= mask;
    }
    Some(match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        16 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes);
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ip_address_strings_the_way_go_prints_it() {
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 4).to_ipv6_mapped());
        assert_eq!(addr_string(mapped), "192.0.2.4");
        assert_eq!(
            addr_string(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4))),
            "192.0.2.4"
        );
    }

    #[test]
    fn a_classful_mask_follows_the_first_octet() {
        assert_eq!(
            default_mask(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(vec![255, 0, 0, 0])
        );
        assert_eq!(
            default_mask(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            Some(vec![255, 255, 0, 0])
        );
        assert_eq!(
            default_mask(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
            Some(vec![255, 255, 255, 0])
        );
        assert_eq!(default_mask(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))), None);
    }

    fn dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ferrox-script-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn callbacks() -> ScriptCallbacks {
        ScriptCallbacks {
            resolve: Arc::new(|_, _, _, _, _| (Vec::new(), 0)),
            pick: Arc::new(|tag| Ok(format!("picked-{tag}"))),
        }
    }

    fn flow() -> Flow<'static> {
        Flow {
            network: Network::Tcp,
            domain: Some("blocked.test"),
            ip: None,
            port: Some(443),
            source: None,
            local: None,
            inbound_tag: Some("in"),
            protocol: Some("http/1.1"),
        }
    }

    #[test]
    fn a_script_reads_its_arguments_and_can_pick_a_balancer() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
local router = require("xray.router")
function HandleRoute(ctx, inbound, sourcePort, targetPort, localPort, targetDomain, network, protocol)
  if inbound ~= "in" or targetDomain ~= "blocked.test" or targetPort ~= 443 then
    return nil
  end
  if network ~= router.NetworkTCP then return nil end
  return router.PickOutbound("proxy"), "scripted"
end
"#,
        )
        .expect("write");
        let router = ScriptRouter::parse_in("route.lua", vec![dir]).expect("parses");
        assert_eq!(
            router.route(&flow(), &callbacks()).expect("routes"),
            Some("picked-proxy".to_owned())
        );
    }

    #[test]
    fn a_script_that_names_no_tag_leaves_the_decision_open() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            "function HandleRoute() return nil end",
        )
        .expect("write");
        let router = ScriptRouter::parse_in("route.lua", vec![dir]).expect("parses");
        assert_eq!(router.route(&flow(), &callbacks()).expect("routes"), None);
    }

    #[test]
    fn a_non_string_tag_names_the_field() {
        let dir = dir();
        std::fs::write(dir.join("route.lua"), "function HandleRoute() return 7 end")
            .expect("write");
        let router = ScriptRouter::parse_in("route.lua", vec![dir]).expect("parses");
        let error = router.route(&flow(), &callbacks()).expect_err("refused");
        assert!(error.contains("outboundTag"), "{error}");
    }

    #[test]
    fn a_dns_query_returns_its_ttl_and_the_server_table_is_indexed() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
local dns = require("xray.dns")
function HandleRoute()
  if #dns.Servers < 1 or type(dns.Servers[1].ID) ~= "string" then return nil end
  local ips, ttl = dns.Query("blocked.test", true, false, false)
  if ips == nil or ttl ~= 60 then return nil end
  return "direct"
end
"#,
        )
        .expect("write");
        let router = ScriptRouter::parse_in("route.lua", vec![dir]).expect("parses");
        let callbacks = ScriptCallbacks {
            resolve: Arc::new(|_, _, _, _, _| (vec!["192.0.2.9".parse().expect("address")], 60)),
            pick: Arc::new(|tag| Ok(format!("picked-{tag}"))),
        };
        assert_eq!(
            router.route(&flow(), &callbacks).expect("routes"),
            Some("direct".to_owned())
        );
    }

    #[test]
    fn a_script_dns_query_reads_the_resolver_ttl() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
local dns = require("xray.dns")
function HandleRoute()
  local ips, ttl, err = dns.Query("example.com", true, false, true)
  if not err and ttl == 42 and #ips == 1 then return "direct" end
  return nil
end
"#,
        )
        .expect("write");
        let router = ScriptRouter::parse_in("route.lua", vec![dir]).expect("parses");
        let callbacks = ScriptCallbacks {
            resolve: Arc::new(|host, _, fake, v4, v6| {
                assert_eq!(host, "example.com");
                assert!(fake);
                assert!(v4);
                assert!(!v6);
                (vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))], 42)
            }),
            pick: Arc::new(|tag| Ok(format!("picked-{tag}"))),
        };
        assert_eq!(
            router.route(&flow(), &callbacks).expect("routes"),
            Some("direct".to_owned())
        );
    }

    #[test]
    fn a_script_path_must_end_in_lua_after_symlinks() {
        let dir = dir();
        std::fs::write(
            dir.join("route.dat"),
            "function HandleRoute() return nil end",
        )
        .expect("write");
        let error = ScriptRouter::parse_in("route.dat", vec![dir.clone()]).expect_err("refused");
        assert!(error.contains(".lua"), "{error}");
        #[cfg(unix)]
        {
            std::fs::write(
                dir.join("route.lua"),
                "function HandleRoute() return nil end",
            )
            .expect("write");
            std::os::unix::fs::symlink(dir.join("route.lua"), dir.join("alias.dat"))
                .expect("symlink");
            ScriptRouter::parse_in("alias.dat", vec![dir]).expect("a symlink to .lua parses");
        }
    }
}
