//! The management API: a gRPC `HandlerService` an operator reaches over the same config xray reads.
//!
//! xray serves the unary calls over HTTP/2 in clear text; this tree already carries the framing
//! for its own gRPC transport, so the server reads the same preface and frames here and writes the
//! five-byte message prefix itself. Nothing is dialed to answer a call in `listen` mode, and in
//! outbound mode the routed link is the transport.

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::conn::Connection;
use crate::h2;
use crate::json::Json;
use crate::vmess;

/// What the `api` app names: the tag routing reaches in outbound mode, and the address a listener
/// answers on in listen mode. xray treats the two as independent: a config may name either or both.
#[derive(Clone, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ApiConfig {
    pub(crate) tag: String,
    pub(crate) listen: Option<String>,
    pub(crate) handler: bool,
    pub(crate) stats: bool,
    pub(crate) logger: bool,
    pub(crate) observatory: bool,
}

impl ApiConfig {
    pub(crate) fn from_proto(bytes: &[u8]) -> Result<Self, String> {
        let mut config = Self::default();
        let mut reader = Pb::new(bytes);
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, Value::Bytes(tag)) => {
                    config.tag = String::from_utf8(tag.to_vec())
                        .map_err(|_| "xray.app.commander.Config: tag is not utf-8".to_owned())?;
                }
                (2, Value::Bytes(service)) => {
                    let (name, _) = typed(service)?;
                    config.service(&name);
                }
                (3, Value::Bytes(listen)) => {
                    config.listen = Some(
                        std::str::from_utf8(listen)
                            .map_err(|_| {
                                "xray.app.commander.Config: listen is not utf-8".to_owned()
                            })?
                            .to_owned(),
                    );
                }
                (_, value) => {
                    return Err(format!(
                        "xray.app.commander.Config: field {field} {value:?}"
                    ))
                }
            }
        }
        Ok(config)
    }

    fn service(&mut self, name: &str) {
        match name {
            "xray.app.proxyman.command.Config" => self.handler = true,
            "xray.app.stats.command.Config" => self.stats = true,
            "xray.app.log.command.Config" => self.logger = true,
            "xray.app.observatory.command.Config" => self.observatory = true,
            "xray.app.commander.ReflectionConfig" => {}
            other => eprintln!("commander: service `{other}` is not carried; skipped"),
        }
    }

    pub(crate) fn from_json(root: &Json) -> Option<Self> {
        let api = root.get("api")?;
        let tag = api
            .get("tag")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let listen = api
            .get("listen")
            .and_then(Json::as_str)
            .filter(|listen| !listen.is_empty())
            .map(str::to_owned);
        let mut config = Self {
            tag,
            listen,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
        };
        if let Some(services) = api.get("services").and_then(Json::as_arr) {
            for service in services.iter().filter_map(Json::as_str) {
                if service.eq_ignore_ascii_case("HandlerService") {
                    config.handler = true;
                } else if service.eq_ignore_ascii_case("StatsService") {
                    config.stats = true;
                } else if service.eq_ignore_ascii_case("LoggerService") {
                    config.logger = true;
                } else if service.eq_ignore_ascii_case("ObservatoryService") {
                    config.observatory = true;
                } else if service.eq_ignore_ascii_case("ReflectionService") {
                } else {
                    eprintln!("commander: service `{service}` is not carried; skipped");
                }
            }
        }
        Some(config)
    }
}

/// One handler this process serves, with what removal and user management need. A handler whose
/// listener the tree cannot stop carries no stops and answers `RemoveInbound` with that reason.
struct Inbound {
    tag: String,
    raw: Option<Vec<u8>>,
    protocol: String,
    users: Option<vmess::UsersRef>,
    stops: Vec<(Arc<crate::proxy::Stop>, String)>,
}

/// The configured outbounds as they arrived, for the one call that lists them back.
struct Outbound {
    tag: String,
    raw: Vec<u8>,
}

#[derive(Default)]
struct State {
    inbounds: Vec<Inbound>,
    outbounds: Vec<Outbound>,
}

/// The management app itself: the service selection plus the handlers it learns at startup and by
/// the calls that add or remove them.
pub(crate) struct Api {
    config: ApiConfig,
    state: Mutex<State>,
    mutation: Mutex<()>,
    start: std::time::Instant,
    runtime: std::sync::OnceLock<Arc<crate::proxy::Runtime>>,
    observatory: std::sync::OnceLock<Option<Arc<crate::observatory::Observatory>>>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("config", &self.config)
            .field(
                "state",
                &self.state.lock().map(|state| state.inbounds.len()),
            )
            .field("mutation", &self.mutation.try_lock().is_ok())
            .field("start", &self.start)
            .field("runtime", &self.runtime.get().is_some())
            .field("observatory", &self.observatory.get().is_some())
            .finish()
    }
}

impl Api {
    pub(crate) fn new(config: ApiConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(State::default()),
            mutation: Mutex::new(()),
            start: std::time::Instant::now(),
            runtime: std::sync::OnceLock::new(),
            observatory: std::sync::OnceLock::new(),
        })
    }

    pub(crate) fn tag(&self) -> &str {
        &self.config.tag
    }

    /// A routed API owns its tag as an outbound handler; a listening API only owns the socket.
    pub(crate) fn routed(&self) -> bool {
        self.config.listen.is_none()
    }

    /// The startup context a later `AddInbound` needs; set once the routes are built.
    pub(crate) fn set_runtime(&self, runtime: Arc<crate::proxy::Runtime>) {
        let _ = self.runtime.set(runtime);
    }

    pub(crate) fn set_observatory(
        &self,
        observatory: Option<Arc<crate::observatory::Observatory>>,
    ) {
        let _ = self.observatory.set(observatory);
    }

    fn runtime(&self) -> Result<&Arc<crate::proxy::Runtime>, (u32, String)> {
        self.runtime
            .get()
            .ok_or_else(|| (13, "commander runtime is unavailable".to_owned()))
    }

    pub(crate) fn seed_outbounds(&self, seed: &[(String, Vec<u8>)]) {
        if let Ok(mut state) = self.state.lock() {
            state.outbounds = seed
                .iter()
                .filter(|(tag, _)| self.routed() || tag != &self.config.tag)
                .map(|(tag, raw)| Outbound {
                    tag: tag.clone(),
                    raw: raw.clone(),
                })
                .collect();
        }
    }

    /// A JSON config carries no protobuf handler, so the listing synthesizes the tag the
    /// reference would return and removal still knows which configured tag it names.
    pub(crate) fn seed_json_outbounds(&self, root: &crate::json::Json) {
        let list = root
            .get("outbounds")
            .and_then(crate::json::Json::as_arr)
            .unwrap_or(&[]);
        if let Ok(mut state) = self.state.lock() {
            state.outbounds = list
                .iter()
                .filter_map(|outbound| {
                    let tag = outbound
                        .get("tag")
                        .and_then(crate::json::Json::as_str)
                        .filter(|tag| {
                            !tag.is_empty() && (!self.routed() || *tag != self.config.tag)
                        })?;
                    let mut raw = Vec::new();
                    field_str(&mut raw, 1, tag);
                    Some(Outbound {
                        tag: tag.to_owned(),
                        raw,
                    })
                })
                .collect();
        }
    }

    pub(crate) fn register_inbound(
        &self,
        tag: &str,
        raw: Option<Vec<u8>>,
        protocol: &str,
        users: Option<vmess::UsersRef>,
        stops: Vec<(Arc<crate::proxy::Stop>, String)>,
    ) {
        if !self.config.handler || (tag.is_empty() && raw.is_none()) {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            if !tag.is_empty() {
                if let Some(existing) = state.inbounds.iter_mut().find(|entry| entry.tag == tag) {
                    existing.stops.extend(stops);
                    if existing.raw.is_none() {
                        existing.raw = raw;
                    }
                    if existing.users.is_none() {
                        existing.users = users;
                    }
                    return;
                }
            }
            state.inbounds.push(Inbound {
                tag: tag.to_owned(),
                raw,
                protocol: protocol.to_owned(),
                users,
                stops,
            });
        }
    }

    /// Bind the configured listen address and answer every accepted connection in its own thread.
    pub(crate) fn serve_listen(self: &Arc<Self>) {
        let Some(address) = self.config.listen.clone() else {
            return;
        };
        let api = Arc::clone(self);
        thread::spawn(move || {
            let target = match crate::conn::parse_target(&address) {
                Ok(target) => target,
                Err(error) => {
                    eprintln!("commander: cannot resolve {address}: {error}");
                    return;
                }
            };
            let listener = match crate::conn::Listener::bind(&target) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("commander: cannot listen on {address}: {error}");
                    return;
                }
            };
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let api = Arc::clone(&api);
                thread::spawn(move || api.serve_stream(stream));
            }
        });
    }

    /// One HTTP/2 connection's worth of calls. The client opens the preface and its SETTINGS, then
    /// a HEADERS/DATA pair per call; this answers each completed body in arrival order.
    pub(crate) fn serve_stream(&self, mut stream: Connection) {
        let mut preface = [0u8; 24];
        if stream.read_exact(&mut preface).is_err() || &preface != h2::MAGIC {
            return;
        }
        if !h2::write_frame(&mut stream, h2::T_SETTINGS, 0, 0, &[]) {
            return;
        }
        let mut decoder = h2::Decoder::default();
        let mut calls: HashMap<u32, Call> = HashMap::new();
        while let Some((len, kind, flags, id)) = h2::read_head(&mut stream) {
            let mut body = vec![0u8; len];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            match kind {
                h2::T_SETTINGS => {
                    if flags & h2::F_ACK == 0 {
                        h2::write_frame(&mut stream, h2::T_SETTINGS, h2::F_ACK, 0, &[]);
                    }
                }
                h2::T_PING => {
                    if flags & h2::F_ACK == 0 {
                        h2::write_frame(&mut stream, h2::T_PING, h2::F_ACK, 0, &body);
                    }
                }
                h2::T_HEADERS => {
                    let block = header_body(&body, flags);
                    let call = calls.entry(id).or_default();
                    call.headers.extend_from_slice(block);
                    call.end_headers = flags & h2::F_END_HEADERS != 0;
                    if call.end_headers {
                        call.read_path(&mut decoder);
                    }
                    if flags & h2::F_END != 0 {
                        self.answer(id, &calls.remove(&id).unwrap_or_default(), &mut stream);
                    }
                }
                h2::T_CONT => {
                    if let Some(call) = calls.get_mut(&id) {
                        call.headers.extend_from_slice(&body);
                        if flags & h2::F_END_HEADERS != 0 {
                            call.end_headers = true;
                            call.read_path(&mut decoder);
                        }
                    }
                }
                h2::T_DATA => {
                    if let Some(call) = calls.get_mut(&id) {
                        call.body.extend_from_slice(&body);
                        if flags & h2::F_END != 0 {
                            self.answer(id, &calls.remove(&id).unwrap_or_default(), &mut stream);
                        }
                    }
                }
                h2::T_GOAWAY => return,
                _ => {}
            }
        }
    }

    fn answer(&self, id: u32, call: &Call, stream: &mut Connection) {
        let request = grpc_message(&call.body).unwrap_or_default();
        match self.dispatch(&call.path, request) {
            Ok(answer) => {
                let head = [(":status", "200"), ("content-type", "application/grpc")];
                let block = h2::block_encode(&head);
                h2::write_frame(stream, h2::T_HEADERS, h2::F_END_HEADERS, id, &block);
                let mut framed = Vec::with_capacity(answer.len() + 5);
                framed.push(0);
                framed.extend_from_slice(&(answer.len() as u32).to_be_bytes());
                framed.extend_from_slice(&answer);
                h2::write_frame(stream, h2::T_DATA, 0, id, &framed);
                let trailers = h2::block_encode(&[("grpc-status", "0")]);
                h2::write_frame(
                    stream,
                    h2::T_HEADERS,
                    h2::F_END_HEADERS | h2::F_END,
                    id,
                    &trailers,
                );
            }
            Err((status, message)) => {
                let code = status.to_string();
                let message = percent(&message);
                let head = [(":status", "200"), ("content-type", "application/grpc")];
                let block = h2::block_encode(&head);
                h2::write_frame(stream, h2::T_HEADERS, h2::F_END_HEADERS, id, &block);
                let trailers = h2::block_encode(&[
                    ("grpc-status", code.as_str()),
                    ("grpc-message", message.as_str()),
                ]);
                h2::write_frame(
                    stream,
                    h2::T_HEADERS,
                    h2::F_END_HEADERS | h2::F_END,
                    id,
                    &trailers,
                );
            }
        }
    }

    fn dispatch(&self, path: &str, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let (service, method) = path.rsplit_once('/').unwrap_or(("", path));
        if service == "/xray.app.log.command.LoggerService" {
            if method == "RestartLogger" && self.config.logger {
                return crate::accesslog::restart()
                    .map(|()| Vec::new())
                    .map_err(|error| (13, error));
            }
            return Err((12, format!("{path} is not a method this server carries")));
        }
        if service == "/xray.core.app.observatory.command.ObservatoryService" {
            if method == "GetOutboundStatus" && self.config.observatory {
                return Ok(self.get_outbound_status());
            }
            return Err((12, format!("{path} is not a method this server carries")));
        }
        let handler = service == "/xray.app.proxyman.command.HandlerService";
        let stats = service == "/xray.app.stats.command.StatsService";
        match (method, handler, stats) {
            ("RemoveInbound", true, _) if self.config.handler => self.remove_inbound(request),
            ("ListInbounds", true, _) if self.config.handler => self.list_inbounds(request),
            ("ListOutbounds", true, _) if self.config.handler => self.list_outbounds(),
            ("AlterInbound", true, _) if self.config.handler => self.alter_inbound(request),
            ("GetInboundUsers", true, _) if self.config.handler => self.get_users(request, false),
            ("GetInboundUsersCount", true, _) if self.config.handler => {
                self.get_users(request, true)
            }
            ("AddInbound", true, _) if self.config.handler => self.add_inbound(request),
            ("AddOutbound", true, _) if self.config.handler => self.add_outbound(request),
            ("RemoveOutbound", true, _) if self.config.handler => self.remove_outbound(request),
            ("AlterOutbound", true, _) if self.config.handler => Self::alter_outbound(request),
            ("GetStats", _, true) if self.config.stats => Self::get_stats(request),
            ("QueryStats", _, true) if self.config.stats => Ok(Self::query_stats(request)),
            ("GetSysStats", _, true) if self.config.stats => Ok(self.sys_stats()),
            ("GetStatsOnline" | "GetStatsOnlineIpList", _, true) if self.config.stats => {
                let name = request_str(request, 1).unwrap_or_default();
                Err((5, format!("{name} not found.")))
            }
            ("GetAllOnlineUsers" | "GetUsersStats", _, true) if self.config.stats => Ok(Vec::new()),
            _ => Err((12, format!("{path} is not a method this server carries"))),
        }
    }

    fn get_outbound_status(&self) -> Vec<u8> {
        let mut status = Vec::new();
        if let Some(Some(observatory)) = self.observatory.get() {
            for observed in observatory.snapshot().iter() {
                field_bytes(&mut status, 1, &outbound_status(observed));
            }
        }
        let mut out = Vec::new();
        field_bytes(&mut out, 1, &status);
        out
    }

    fn get_stats(request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let name = request_str(request, 1).unwrap_or_default();
        let reset = request_varint(request, 2).unwrap_or(0) != 0;
        let value =
            crate::stats::get(&name, reset).ok_or_else(|| (5, format!("{name} not found.")))?;
        let mut out = Vec::new();
        field_bytes(&mut out, 1, &stat(&name, value));
        Ok(out)
    }

    fn query_stats(request: &[u8]) -> Vec<u8> {
        let pattern = request_str(request, 1).unwrap_or_default();
        let reset = request_varint(request, 2).unwrap_or(0) != 0;
        let mut out = Vec::new();
        for (name, value) in crate::stats::query(&pattern, reset) {
            field_bytes(&mut out, 1, &stat(&name, value));
        }
        out
    }

    fn sys_stats(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in 1..=9 {
            field_varint(&mut out, field, 0);
        }
        field_varint(&mut out, 10, self.start.elapsed().as_secs());
        out
    }

    fn remove_inbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let tag = request_str(request, 1).unwrap_or_default();
        if tag.is_empty() {
            return Err((2, "empty handler tag".to_owned()));
        }
        let entry = {
            let Ok(mut state) = self.state.lock() else {
                return Err((13, "commander state is unavailable".into()));
            };
            let Some(index) = state.inbounds.iter().position(|entry| entry.tag == tag) else {
                return Err((2, format!("inbound `{tag}` not found")));
            };
            if state.inbounds[index].stops.is_empty() {
                let protocol = state.inbounds[index].protocol.clone();
                return Err((
                    12,
                    format!("inbound `{tag}` ({protocol}) has no listener this tree can stop"),
                ));
            }
            state.inbounds.remove(index)
        };
        for (stop, address) in &entry.stops {
            stop.stop();
            crate::proxy::wake_listener(stop, address);
        }
        for (stop, address) in &entry.stops {
            if !stop.wait_closed() {
                return Err((
                    13,
                    format!("inbound `{tag}` listener at {address} did not close"),
                ));
            }
        }
        Ok(Vec::new())
    }

    fn list_inbounds(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let only_tags = request_varint(request, 1).unwrap_or(0) != 0;
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let mut out = Vec::new();
        for entry in &state.inbounds {
            let raw = if only_tags {
                inbound_config(&entry.tag, true)
            } else if let Some(raw) = &entry.raw {
                raw.clone()
            } else {
                inbound_config(&entry.tag, false)
            };
            field_bytes(&mut out, 1, &raw);
        }
        Ok(out)
    }

    fn list_outbounds(&self) -> Result<Vec<u8>, (u32, String)> {
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let mut out = Vec::new();
        for entry in &state.outbounds {
            field_bytes(&mut out, 1, &entry.raw);
        }
        Ok(out)
    }

    fn add_inbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let raw = request_bytes(request, 1)
            .ok_or_else(|| (3, "AddInbound carries no handler".to_owned()))?;
        let tag = crate::xray_pb::handler_tag(raw);
        let inbounds =
            crate::xray_pb::inbound(raw).map_err(|error| (3, format!("AddInbound: {error}")))?;
        let ports: Vec<String> = inbounds
            .iter()
            .filter_map(|inbound| inbound.get("port").and_then(crate::json::Json::as_port))
            .map(|port| port.to_string())
            .collect();
        let Some(crate::json::Json::Obj(mut pairs)) = inbounds.first().cloned() else {
            return Err((3, "AddInbound names no inbound".to_owned()));
        };
        if ports.is_empty() {
            return Err((3, "AddInbound names no inbound".to_owned()));
        }
        for (key, value) in &mut pairs {
            if key == "port" {
                *value = crate::json::Json::Str(ports.join(","));
            }
        }
        let runtime = Arc::clone(self.runtime()?);
        {
            let state = self
                .state
                .lock()
                .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
            if !tag.is_empty() && state.inbounds.iter().any(|entry| entry.tag == tag) {
                return Err((2, format!("existing tag found: {tag}")));
            }
        }
        let root = crate::json::Json::Obj(vec![(
            "inbounds".to_owned(),
            crate::json::Json::Arr(vec![crate::json::Json::Obj(pairs)]),
        )]);
        let seed = crate::xray_pb::Seed {
            inbounds: vec![(tag.clone(), raw.to_vec())],
            ..Default::default()
        };
        let (served, _) = crate::proxy::serve_dynamic_inbounds(&runtime, &root, &seed, self);
        if served == 0 {
            return Err((2, format!("inbound `{tag}` could not be served")));
        }
        Ok(Vec::new())
    }

    fn add_outbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let raw = request_bytes(request, 1)
            .ok_or_else(|| (3, "AddOutbound carries no handler".to_owned()))?;
        let tag = crate::xray_pb::handler_tag(raw);
        if !tag.is_empty() && self.routed() && tag == self.config.tag {
            return Err((2, format!("existing tag found: {tag}")));
        }
        let runtime = Arc::clone(self.runtime()?);
        let mut state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        if !tag.is_empty() && state.outbounds.iter().any(|entry| entry.tag == tag) {
            return Err((2, format!("existing tag found: {tag}")));
        }
        if !tag.is_empty() {
            runtime
                .add_outbound(&tag, raw)
                .map_err(|error| (2, error))?;
        }
        state.outbounds.push(Outbound {
            tag,
            raw: raw.to_vec(),
        });
        Ok(Vec::new())
    }

    fn remove_outbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let tag = request_str(request, 1).unwrap_or_default();
        if tag.is_empty() {
            return Err((2, "empty handler tag".to_owned()));
        }
        let runtime = Arc::clone(self.runtime()?);
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
            let Some(index) = state.outbounds.iter().position(|entry| entry.tag == tag) else {
                if self.routed() && tag == self.config.tag {
                    runtime.remove_outbound(&tag);
                }
                return Ok(Vec::new());
            };
            state.outbounds.remove(index);
        }
        runtime.remove_outbound(&tag);
        Ok(Vec::new())
    }

    fn alter_outbound(request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let operation = request_typed(request, 2)
            .ok_or_else(|| (3, "AlterOutbound carries no operation".to_owned()))?;
        match operation.0.as_str() {
            "xray.app.proxyman.command.AddUserOperation"
            | "xray.app.proxyman.command.RemoveUserOperation" => {
                Err((2, "not an outbound operation".to_owned()))
            }
            _ => Err((2, "unknown operation".to_owned())),
        }
    }

    fn alter_inbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let tag = request_str(request, 1).unwrap_or_default();
        let operation = request_typed(request, 2)
            .ok_or_else(|| (3, "AlterInbound carries no operation".to_owned()))?;
        let add = match operation.0.as_str() {
            "xray.app.proxyman.command.AddUserOperation" => true,
            "xray.app.proxyman.command.RemoveUserOperation" => false,
            _ => return Err((2, "unknown operation".to_owned())),
        };
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let entry = state
            .inbounds
            .iter()
            .find(|entry| entry.tag == tag)
            .ok_or_else(|| (2, format!("inbound `{tag}` not found")))?;
        let users = entry.users.as_ref().ok_or_else(|| {
            (
                2,
                format!(
                    "inbound `{tag}` ({}) does not carry users here",
                    entry.protocol
                ),
            )
        })?;
        if add {
            let user = request_bytes(operation.1, 1)
                .ok_or_else(|| (3, "AddUserOperation carries no user".to_owned()))?;
            let account =
                request_typed(user, 3).ok_or_else(|| (3, "user carries no account".to_owned()))?;
            if account.0 != "xray.proxy.vmess.Account" {
                return Err((2, format!("account `{}` is not carried here", account.0)));
            }
            let id = request_str(account.1, 1)
                .and_then(|id| crate::config::uuid_bytes(&id))
                .ok_or_else(|| (3, "vmess account id is not a uuid".to_owned()))?;
            let email = request_str(user, 2).unwrap_or_default();
            let level = request_varint(user, 1).unwrap_or(0) as u32;
            if !users.add(vmess::User { level, email, id }) {
                return Err((2, "user already exists".to_owned()));
            }
            Ok(Vec::new())
        } else {
            let email = request_str(operation.1, 1).unwrap_or_default();
            if !users.remove_email(&email) {
                return Err((2, format!("user `{email}` not found")));
            }
            Ok(Vec::new())
        }
    }

    fn get_users(&self, request: &[u8], count: bool) -> Result<Vec<u8>, (u32, String)> {
        let tag = request_str(request, 1).unwrap_or_default();
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let entry = state
            .inbounds
            .iter()
            .find(|entry| entry.tag == tag)
            .ok_or_else(|| (2, format!("inbound `{tag}` not found")))?;
        let Some(users) = entry.users.as_ref() else {
            return Err((
                2,
                format!("inbound `{tag}` ({}) is not a UserManager", entry.protocol),
            ));
        };
        let listed = users.list();
        if count {
            let mut out = Vec::new();
            field_varint(&mut out, 1, listed.len() as u64);
            return Ok(out);
        }
        let email = request_str(request, 2).unwrap_or_default();
        let mut out = Vec::new();
        for user in listed
            .iter()
            .filter(|user| email.is_empty() || user.email == email)
        {
            field_bytes(&mut out, 1, &vmess_user(user));
        }
        Ok(out)
    }
}

#[derive(Default)]
struct Call {
    path: String,
    headers: Vec<u8>,
    end_headers: bool,
    body: Vec<u8>,
}

impl Call {
    fn read_path(&mut self, decoder: &mut h2::Decoder) {
        let mut path = String::new();
        let block = std::mem::take(&mut self.headers);
        if decoder
            .decode(&block, &mut |name, value| {
                if name == b":path" {
                    path = String::from_utf8_lossy(value).into_owned();
                }
            })
            .is_none()
        {
            return;
        }
        self.path = path;
    }
}

fn header_body(body: &[u8], flags: u8) -> &[u8] {
    let mut rest = body;
    if flags & h2::F_PADDED != 0 {
        let Some((&pad, tail)) = rest.split_first() else {
            return &[];
        };
        rest = tail
            .get(..tail.len().saturating_sub(usize::from(pad)))
            .unwrap_or(&[]);
    }
    if flags & h2::F_PRIORITY != 0 {
        rest = rest.get(5..).unwrap_or(&[]);
    }
    rest
}

fn grpc_message(body: &[u8]) -> Option<&[u8]> {
    let header = body.get(..5)?;
    if header[0] != 0 {
        return None;
    }
    let len = u32::from_be_bytes(header[1..5].try_into().ok()?) as usize;
    body.get(5..5 + len)
}

fn percent(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{byte:02X}"));
        }
    }
    out
}

/// The handler config this tree can synthesize for a JSON inbound: its tag, and nothing else.
fn inbound_config(tag: &str, _only_tags: bool) -> Vec<u8> {
    let mut out = Vec::new();
    field_str(&mut out, 1, tag);
    out
}

/// One `xray.core.app.observatory.OutboundStatus`: the reading a balancer already picked from.
fn outbound_status(observed: &crate::router::Observed) -> Vec<u8> {
    let mut out = Vec::new();
    if observed.alive {
        field_varint(&mut out, 1, 1);
    }
    if observed.delay_ms != 0 {
        field_varint(&mut out, 2, observed.delay_ms as u64);
    }
    if !observed.last_error.is_empty() {
        field_str(&mut out, 3, &observed.last_error);
    }
    if !observed.tag.is_empty() {
        field_str(&mut out, 4, &observed.tag);
    }
    if observed.last_seen != 0 {
        field_varint(&mut out, 5, observed.last_seen as u64);
    }
    if observed.last_try != 0 {
        field_varint(&mut out, 6, observed.last_try as u64);
    }
    if let Some(health) = observed.health {
        let mut ping = Vec::new();
        for (field, value) in [
            (1, health.all),
            (2, health.fail),
            (3, health.deviation),
            (4, health.average),
        ] {
            if value != 0 {
                field_varint(&mut ping, field, value as u64);
            }
        }
        field_bytes(&mut out, 7, &ping);
    }
    out
}

/// One `xray.app.stats.command.Stat`: the name the counter registered and its total.
fn stat(name: &str, value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    field_str(&mut out, 1, name);
    field_varint(&mut out, 2, value as u64);
    out
}

fn vmess_user(user: &vmess::User) -> Vec<u8> {
    let mut out = Vec::new();
    field_varint(&mut out, 1, u64::from(user.level));
    field_str(&mut out, 2, &user.email);
    let mut account = Vec::new();
    field_str(&mut account, 1, &uuid_string(user.id));
    let mut typed = Vec::new();
    field_str(&mut typed, 1, "xray.proxy.vmess.Account");
    field_bytes(&mut typed, 2, &account);
    field_bytes(&mut out, 3, &typed);
    out
}

fn uuid_string(id: [u8; 16]) -> String {
    let mut hex = String::with_capacity(32);
    for byte in id {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ---- protobuf wire ----

#[derive(Debug)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

struct Pb<'a> {
    rest: &'a [u8],
}

impl<'a> Pb<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>, String> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (key, rest) = varint(self.rest).ok_or_else(|| "protobuf: truncated key".to_owned())?;
        self.rest = rest;
        let field = key >> 3;
        let wire = (key & 7) as u8;
        match wire {
            0 => {
                let (value, rest) =
                    varint(self.rest).ok_or_else(|| "protobuf: truncated varint".to_owned())?;
                self.rest = rest;
                Ok(Some((field, Value::Varint(value))))
            }
            2 => {
                let (len, rest) =
                    varint(self.rest).ok_or_else(|| "protobuf: truncated length".to_owned())?;
                let len =
                    usize::try_from(len).map_err(|_| "protobuf: length overflows".to_owned())?;
                let (body, rest) = rest
                    .split_at_checked(len)
                    .ok_or_else(|| "protobuf: truncated body".to_owned())?;
                self.rest = rest;
                Ok(Some((field, Value::Bytes(body))))
            }
            1 => {
                let (_, rest) = self
                    .rest
                    .split_at_checked(8)
                    .ok_or_else(|| "protobuf: truncated fixed64".to_owned())?;
                self.rest = rest;
                self.next()
            }
            5 => {
                let (_, rest) = self
                    .rest
                    .split_at_checked(4)
                    .ok_or_else(|| "protobuf: truncated fixed32".to_owned())?;
                self.rest = rest;
                self.next()
            }
            other => Err(format!("protobuf: wire type {other}")),
        }
    }
}

fn varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((value, &bytes[index + 1..]));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    put_varint(out, field << 3);
    put_varint(out, value);
}

fn field_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    put_varint(out, field << 3 | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn field_str(out: &mut Vec<u8>, field: u64, text: &str) {
    field_bytes(out, field, text.as_bytes());
}

fn request_varint(bytes: &[u8], field: u64) -> Option<u64> {
    let mut reader = Pb::new(bytes);
    while let Ok(Some((number, value))) = reader.next() {
        if number == field {
            if let Value::Varint(value) = value {
                return Some(value);
            }
        }
    }
    None
}

fn request_bytes(bytes: &[u8], field: u64) -> Option<&[u8]> {
    let mut reader = Pb::new(bytes);
    while let Ok(Some((number, value))) = reader.next() {
        if number == field {
            if let Value::Bytes(value) = value {
                return Some(value);
            }
        }
    }
    None
}

fn request_str(bytes: &[u8], field: u64) -> Option<String> {
    request_bytes(bytes, field).and_then(|raw| std::str::from_utf8(raw).ok().map(str::to_owned))
}

fn request_typed(bytes: &[u8], field: u64) -> Option<(String, &[u8])> {
    typed(request_bytes(bytes, field)?).ok()
}

fn typed(bytes: &[u8]) -> Result<(String, &[u8]), String> {
    let name = request_str(bytes, 1).ok_or_else(|| "typed message has no name".to_owned())?;
    let value = request_bytes(bytes, 2).unwrap_or(&[]);
    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    fn request(path: &str, message: &[u8]) -> Vec<u8> {
        let mut out = h2::MAGIC.to_vec();
        out.extend_from_slice(&h2::frame_head(0, h2::T_SETTINGS, 0, 0));
        let headers = h2::block_encode(&[
            (":method", "POST"),
            (":scheme", "http"),
            (":path", path),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]);
        out.extend_from_slice(&h2::frame_head(
            headers.len(),
            h2::T_HEADERS,
            h2::F_END_HEADERS,
            1,
        ));
        out.extend_from_slice(&headers);
        let mut body = vec![0];
        body.extend_from_slice(&(message.len() as u32).to_be_bytes());
        body.extend_from_slice(message);
        out.extend_from_slice(&h2::frame_head(body.len(), h2::T_DATA, h2::F_END, 1));
        out.extend_from_slice(&body);
        out
    }

    fn reply(mut stream: Connection) -> (Vec<u8>, Vec<(String, String)>) {
        let mut decoder = h2::Decoder::default();
        let mut message = Vec::new();
        let mut trailers = Vec::new();
        while let Some((len, kind, flags, id)) = h2::read_head(&mut stream) {
            let mut body = vec![0u8; len];
            if stream.read_exact(&mut body).is_err() {
                break;
            }
            match kind {
                h2::T_DATA => {
                    if body.len() >= 5 {
                        let n = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
                        message.extend_from_slice(&body[5..5 + n]);
                    }
                }
                h2::T_HEADERS if id == 1 && flags & h2::F_END != 0 => {
                    decoder.decode(&body, &mut |name, value| {
                        trailers.push((
                            String::from_utf8_lossy(name).into_owned(),
                            String::from_utf8_lossy(value).into_owned(),
                        ));
                    });
                    break;
                }
                _ => {}
            }
        }
        (message, trailers)
    }

    #[test]
    fn the_handler_service_lists_the_config_it_was_seeded_with() {
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
        });
        let inbound = vec![0x0a, 0x01, b'd'];
        api.register_inbound(
            "d",
            Some(inbound.clone()),
            "dokodemo-door",
            None,
            Vec::new(),
        );
        api.seed_outbounds(&[("default-outbound".to_owned(), vec![0x0a, 0x02, b'o', b'k'])]);

        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("addr");
        let served = std::sync::Arc::clone(&api);
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            served.serve_stream(Connection::from(stream));
        });

        let mut client = Connection::connect(address).expect("connects");
        client
            .write_all(&request(
                "/xray.app.proxyman.command.HandlerService/ListInbounds",
                &[],
            ))
            .expect("writes");
        let (message, trailers) = reply(client);
        assert!(trailers
            .iter()
            .any(|(name, value)| name == "grpc-status" && value == "0"));
        assert_eq!(request_bytes(&message, 1), Some(inbound.as_slice()));
    }

    #[test]
    fn a_user_added_by_alter_inbound_authenticates_the_next_session() {
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
        });
        let first = [0x11u8; 16];
        let second = [0x22u8; 16];
        let users = vmess::Users::single(first);
        api.register_inbound(
            "v",
            None,
            "vmess",
            Some(std::sync::Arc::clone(&users)),
            Vec::new(),
        );
        let mut user = Vec::new();
        field_str(&mut user, 2, "test@example.com");
        let mut account = Vec::new();
        field_str(&mut account, 1, &uuid_string(second));
        let mut typed_account = Vec::new();
        field_str(&mut typed_account, 1, "xray.proxy.vmess.Account");
        field_bytes(&mut typed_account, 2, &account);
        field_bytes(&mut user, 3, &typed_account);
        let mut operation = Vec::new();
        field_bytes(&mut operation, 1, &user);
        let mut add = Vec::new();
        field_str(&mut add, 1, "v");
        let mut typed_operation = Vec::new();
        field_str(
            &mut typed_operation,
            1,
            "xray.app.proxyman.command.AddUserOperation",
        );
        field_bytes(&mut typed_operation, 2, &operation);
        field_bytes(&mut add, 2, &typed_operation);
        assert!(api.alter_inbound(&add).is_ok());
        assert!(users.list().iter().any(|user| user.id == second));
        let mut remove = Vec::new();
        field_str(&mut remove, 1, "v");
        let mut operation = Vec::new();
        field_str(&mut operation, 1, "test@example.com");
        let mut typed_operation = Vec::new();
        field_str(
            &mut typed_operation,
            1,
            "xray.app.proxyman.command.RemoveUserOperation",
        );
        field_bytes(&mut typed_operation, 2, &operation);
        field_bytes(&mut remove, 2, &typed_operation);
        assert!(api.alter_inbound(&remove).is_ok());
        assert!(!users.list().iter().any(|user| user.id == second));
    }

    #[test]
    fn the_stats_service_reads_back_and_resets_a_counter() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"system":{"statsInboundUplink":true}},
                "inbounds":[{"tag":"test"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        crate::stats::install(&root).expect("stats installs");
        crate::stats::inbound(Some("test")).read(11);
        let mut request = Vec::new();
        field_str(&mut request, 1, "inbound>>>test>>>traffic>>>uplink");
        field_varint(&mut request, 2, 1);
        let answer = Api::get_stats(&request).expect("reads the counter");
        let stat = request_bytes(&answer, 1).expect("one stat");
        assert_eq!(
            request_str(stat, 1),
            Some("inbound>>>test>>>traffic>>>uplink".to_owned())
        );
        assert_eq!(request_varint(stat, 2), Some(11));
        let answer = Api::get_stats(&request).expect("reads the reset counter");
        let stat = request_bytes(&answer, 1).expect("one stat");
        assert_eq!(request_varint(stat, 2), Some(0));
        crate::stats::clear();
    }

    fn freedom_outbound(tag: &str) -> Vec<u8> {
        let mut typed = Vec::new();
        field_str(&mut typed, 1, "xray.proxy.freedom.Config");
        let mut out = Vec::new();
        field_str(&mut out, 1, tag);
        field_bytes(&mut out, 3, &typed);
        out
    }

    fn bytes_field(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        field_bytes(&mut out, field, value);
        out
    }

    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        field_varint(&mut out, field, value);
        out
    }

    fn message(fields: &[Vec<u8>]) -> Vec<u8> {
        fields.concat()
    }

    fn typed(name: &str, value: &[u8]) -> Vec<u8> {
        message(&[bytes_field(1, name.as_bytes()), bytes_field(2, value)])
    }

    fn dokodemo_inbound(ports: &[u16]) -> Vec<u8> {
        let ranges: Vec<Vec<u8>> = ports
            .iter()
            .map(|port| {
                message(&[
                    varint_field(1, u64::from(*port)),
                    varint_field(2, u64::from(*port)),
                ])
            })
            .collect();
        let list = message(
            &ranges
                .iter()
                .map(|range| bytes_field(1, range))
                .collect::<Vec<_>>(),
        );
        let receiver = message(&[
            bytes_field(1, &list),
            bytes_field(2, &bytes_field(1, &[127, 0, 0, 1])),
        ]);
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, u64::from(ports[0])),
            varint_field(7, 2),
        ]);
        let mut out = Vec::new();
        field_str(&mut out, 1, "d");
        field_bytes(
            &mut out,
            2,
            &typed("xray.app.proxyman.ReceiverConfig", &receiver),
        );
        field_bytes(&mut out, 3, &typed("xray.proxy.dokodemo.Config", &settings));
        out
    }

    fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        listener.local_addr().expect("addr").port()
    }

    fn wait_for_port(port: u16, open: bool) {
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() == open {
                return;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!(
            "port {port} never became {}",
            if open { "open" } else { "closed" }
        );
    }

    #[test]
    fn add_outbound_lists_and_remove_outbound_drops_it() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"tag":"default","protocol":"freedom"}],"routing":{}}"#,
        )
        .expect("parses");
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
        });
        api.set_runtime(std::sync::Arc::new(crate::proxy::test_runtime(&root)));
        let raw = freedom_outbound("new");
        let mut add = Vec::new();
        field_bytes(&mut add, 1, &raw);
        assert!(api.add_outbound(&add).is_ok());
        assert_eq!(
            api.add_outbound(&add),
            Err((2, "existing tag found: new".to_owned()))
        );
        let listed = api.list_outbounds().expect("lists");
        assert_eq!(request_bytes(&listed, 1), Some(raw.as_slice()));
        let mut remove = Vec::new();
        field_str(&mut remove, 1, "new");
        assert!(api.remove_outbound(&remove).is_ok());
        assert_eq!(api.list_outbounds().expect("lists"), [] as [u8; 0]);
        assert!(api.remove_outbound(&remove).is_ok());
        assert_eq!(
            api.remove_outbound(&[]),
            Err((2, "empty handler tag".to_owned()))
        );
    }

    #[test]
    fn add_inbound_serves_and_remove_inbound_stops_it() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"tag":"default","protocol":"freedom"}],"routing":{}}"#,
        )
        .expect("parses");
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
        });
        api.set_runtime(std::sync::Arc::new(crate::proxy::test_runtime(&root)));
        let first = free_port();
        let second = loop {
            let port = free_port();
            if port != first {
                break port;
            }
        };
        let raw = dokodemo_inbound(&[first, second]);
        let mut add = Vec::new();
        field_bytes(&mut add, 1, &raw);
        assert!(api.add_inbound(&add).is_ok());
        wait_for_port(first, true);
        wait_for_port(second, true);
        let mut remove = Vec::new();
        field_str(&mut remove, 1, "d");
        assert!(api.remove_inbound(&remove).is_ok());
        wait_for_port(first, false);
        wait_for_port(second, false);
    }

    #[test]
    fn alter_outbound_reports_what_the_reference_reports() {
        let mut operation = Vec::new();
        field_str(
            &mut operation,
            1,
            "xray.app.proxyman.command.AddUserOperation",
        );
        let mut request = Vec::new();
        field_str(&mut request, 1, "any");
        field_bytes(&mut request, 2, &operation);
        assert_eq!(
            Api::alter_outbound(&request),
            Err((2, "not an outbound operation".to_owned()))
        );
        let mut operation = Vec::new();
        field_str(&mut operation, 1, "xray.app.proxyman.command.Unknown");
        let mut request = Vec::new();
        field_str(&mut request, 1, "any");
        field_bytes(&mut request, 2, &operation);
        assert_eq!(
            Api::alter_outbound(&request),
            Err((2, "unknown operation".to_owned()))
        );
    }

    #[test]
    fn the_logger_service_answers_only_when_the_config_lists_it() {
        let _guard = crate::stats::test_lock();
        let root = crate::json::parse(r#"{"api":{"tag":"api","services":["loggerService"]}}"#)
            .expect("parses");
        assert!(
            ApiConfig::from_json(&root).expect("api block").logger,
            "the service name is case-insensitive"
        );
        let path = "/xray.app.log.command.LoggerService/RestartLogger";
        let unselected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
        });
        assert_eq!(
            unselected
                .dispatch(path, &[])
                .expect_err("service is not selected"),
            (12, format!("{path} is not a method this server carries"))
        );
        let selected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: true,
            observatory: false,
        });
        assert_eq!(
            selected.dispatch(path, &[]).expect("answers the call"),
            Vec::<u8>::new()
        );
        assert_eq!(
            selected
                .dispatch("/xray.app.log.command.LoggerService/Unknown", &[])
                .expect_err("unknown method"),
            (
                12,
                "/xray.app.log.command.LoggerService/Unknown is not a method this server carries"
                    .to_owned()
            )
        );
    }

    #[test]
    fn a_protobuf_service_uses_the_pinned_observatory_name() {
        let service = typed("xray.core.app.observatory.command.Config", &[]);
        let mut config = Vec::new();
        field_bytes(&mut config, 2, &service);
        assert!(
            ApiConfig::from_proto(&config).expect("parses").observatory,
            "the pinned protobuf name selects the observatory"
        );
    }

    #[test]
    fn the_observatory_service_serializes_the_live_snapshot() {
        let root = crate::json::parse(r#"{"api":{"tag":"api","services":["observatoryService"]}}"#)
            .expect("parses");
        assert!(
            ApiConfig::from_json(&root).expect("api block").observatory,
            "the service name is case-insensitive"
        );
        let path = "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus";
        let unselected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
        });
        assert_eq!(
            unselected
                .dispatch(path, &[])
                .expect_err("service is not selected"),
            (12, format!("{path} is not a method this server carries"))
        );
        let selected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: true,
        });
        let observed = crate::router::Observed {
            tag: "edge".to_owned(),
            alive: true,
            delay_ms: 12,
            health: Some(crate::router::HealthPing {
                all: 5,
                fail: 1,
                deviation: 2,
                average: 12,
            }),
            last_error: "an earlier timeout".to_owned(),
            last_seen: 100,
            last_try: 101,
        };
        selected.set_observatory(Some(crate::observatory::Observatory::seeded(&[observed])));
        let answer = selected.dispatch(path, &[]).expect("answers the call");
        let status = request_bytes(&answer, 1).expect("status");
        let entry = request_bytes(status, 1).expect("one outbound");
        assert_eq!(request_varint(entry, 1), Some(1), "alive");
        assert_eq!(request_varint(entry, 2), Some(12), "delay in ms");
        assert_eq!(
            request_str(entry, 3).as_deref(),
            Some("an earlier timeout"),
            "the last error"
        );
        assert_eq!(request_str(entry, 4).as_deref(), Some("edge"), "tag");
        assert_eq!(request_varint(entry, 5), Some(100), "last seen");
        assert_eq!(request_varint(entry, 6), Some(101), "last try");
        let health = request_bytes(entry, 7).expect("health ping");
        assert_eq!(request_varint(health, 1), Some(5), "all");
        assert_eq!(request_varint(health, 2), Some(1), "fail");
        assert_eq!(request_varint(health, 3), Some(2), "deviation");
        assert_eq!(request_varint(health, 4), Some(12), "average");
    }

    #[test]
    fn a_selected_service_without_an_observatory_answers_an_empty_result() {
        let selected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: true,
        });
        assert_eq!(
            selected
                .dispatch(
                    "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus",
                    &[]
                )
                .expect("an empty result is still an answer"),
            vec![0x0a, 0x00]
        );
    }

    #[test]
    fn a_missing_counter_is_not_found() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let mut request = Vec::new();
        field_str(&mut request, 1, "user>>>nobody>>>traffic>>>uplink");
        assert_eq!(
            Api::get_stats(&request),
            Err((5, "user>>>nobody>>>traffic>>>uplink not found.".to_owned()))
        );
        crate::stats::clear();
    }
}
