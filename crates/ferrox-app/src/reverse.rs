//! The reverse tunnel: a portal that lends its reach to a bridge behind a NAT.
//!
//! The wire is the reference's own: a VLESS request with command 4 carries a mux session,
//! and the portal answers a control datagram stream named `reverse` with a protobuf
//! `Control` message. The portal keeps a picker of live sessions, the bridge keeps a
//! monitor that opens another session when the live ones carry more than sixteen flows.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::conn::Connection;

/// The internal destination the portal writes control messages to; the reference spells it in
/// the mux target rather than in a stream of its own.
pub(crate) const CONTROL_DOMAIN: &str = "reverse";

pub(crate) const ACTIVE: i32 = 0;
pub(crate) const DRAIN: i32 = 1;

/// The reference's picker refuses to reuse a session for a new flow past this many flows; it is
/// a session lifetime, not a per-instant bound.
const SESSION_FLOWS: u32 = 256;

/// Bytes one downlink flow may queue before the session drops it rather than stall every other
/// flow behind a reader that stopped reading.
const FLOW_PENDING: usize = ferrox_core::mux::DEFAULT_CAP;

const HEARTBEAT: Duration = Duration::from_secs(2);
const MONITOR: Duration = Duration::from_secs(2);

/// The reference's bridge worker idle bound: a portal that stops heartbeating for this long is gone.
const WORKER_IDLE: Duration = Duration::from_secs(60);

/// One protobuf `Control`: a state and a random pad the reference writes to look unlike a
/// fixed shape. Unknown fields are skipped, and an absent state means `ACTIVE` — proto3 leaves
/// a zero field off the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Control {
    pub(crate) state: i32,
    pub(crate) random: Vec<u8>,
}

impl Control {
    pub(crate) fn of(state: i32) -> Self {
        let mut random = vec![0u8; 32];
        let _ = getrandom::fill(&mut random);
        Self { state, random }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.random.len());
        if self.state != ACTIVE {
            out.push(0x08);
            put_varint(&mut out, self.state as u64);
        }
        out.push(0x9a);
        out.push(0x06);
        put_varint(&mut out, self.random.len() as u64);
        out.extend_from_slice(&self.random);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut state = ACTIVE;
        let mut random = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let key = get_varint(bytes, &mut at)?;
            let field = key >> 3;
            match (field, key & 7) {
                (1, 0) => state = i32::try_from(get_varint(bytes, &mut at)?).ok()?,
                (99, 2) => {
                    let len = usize::try_from(get_varint(bytes, &mut at)?).ok()?;
                    random = bytes.get(at..at.checked_add(len)?)?.to_vec();
                    at += len;
                }
                (_, 0) => {
                    get_varint(bytes, &mut at)?;
                }
                (_, 1) => at = at.checked_add(8)?,
                (_, 2) => {
                    let len = usize::try_from(get_varint(bytes, &mut at)?).ok()?;
                    at = at.checked_add(len)?;
                }
                (_, 5) => at = at.checked_add(4)?,
                _ => return None,
            }
        }
        Some(Self { state, random })
    }
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn get_varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The address a downlink datagram names: the bridge's own socket, never a name.
fn source_addr(target: ferrox_core::mux::Target<'_>) -> Option<std::net::SocketAddr> {
    let address = match target.addr {
        ferrox_core::addr::Addr::V4(octets) => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        ferrox_core::addr::Addr::V6(octets) => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        ferrox_core::addr::Addr::Name(_) => return None,
    };
    Some(std::net::SocketAddr::new(address, target.port))
}

/// The two ends of a tunnel: a reader one thread owns, a writer every flow shares, and the
/// close that wakes both.
type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;
type SharedReader = Arc<Mutex<Box<dyn Read + Send>>>;
type Closer = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Tunnel {
    reader: SharedReader,
    writer: SharedWriter,
    closer: Closer,
}

/// The read half of a tunnel, boxed into the shape a session or a mux server reads.
pub(crate) struct TunnelReader(SharedReader);

impl Read for TunnelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut reader = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("tunnel reader poisoned"))?;
        reader.read(buf)
    }
}

impl Tunnel {
    pub(crate) fn new(
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        closer: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            closer,
        }
    }

    pub(crate) fn from_connection(connection: &Connection) -> Option<Self> {
        let reader = connection.try_clone().ok()?;
        let writer = connection.try_clone().ok()?;
        let close = connection.try_clone().ok()?;
        Some(Self::new(
            Box::new(reader),
            Box::new(writer),
            Arc::new(move || {
                let _ = close.shutdown(std::net::Shutdown::Both);
            }),
        ))
    }

    pub(crate) fn reader(&self) -> TunnelReader {
        TunnelReader(Arc::clone(&self.reader))
    }

    /// A frame header and the payload it introduces, written under one lock so another flow cannot
    /// interleave, and read straight from the caller's two buffers.
    pub(crate) fn write_frame_parts(&self, header: &[u8], payload: &[u8]) -> bool {
        let Ok(mut writer) = self.writer.lock() else {
            return false;
        };
        crate::proxy::write_all_parts::<2>(&mut **writer, &[header, payload]).is_ok()
    }

    pub(crate) fn write_all(&self, bytes: &[u8]) -> bool {
        let Ok(mut writer) = self.writer.lock() else {
            return false;
        };
        writer.write_all(bytes).is_ok()
    }

    pub(crate) fn close(&self) {
        (self.closer)();
    }

    fn split(self) -> (TunnelReader, SharedWriter, Closer) {
        (
            TunnelReader(Arc::clone(&self.reader)),
            Arc::clone(&self.writer),
            Arc::clone(&self.closer),
        )
    }
}

/// Two connected loopback streams, the pipe the reverse tunnel rides so a carrier's own dial and
/// relay can stand in for a stream the mux has not been given.
pub(crate) fn loopback_pair() -> Option<(Connection, Connection)> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let address = listener.local_addr().ok()?;
    let client = Connection::from(TcpStream::connect(address).ok()?);
    let (server, _) = listener.accept().ok()?;
    drop(listener);
    Some((client, Connection::from(server)))
}

/// One mux flow: the queue its downlink bytes land in and the flag a teardown sets so a writer
/// parked on a full queue unwinds.
pub(crate) struct Flow {
    /// Each downlink chunk and, on a datagram flow, the address it came from.
    pub(crate) down: Receiver<(Vec<u8>, Option<std::net::SocketAddr>)>,
}

struct Slot {
    down: SyncSender<(Vec<u8>, Option<std::net::SocketAddr>)>,
    cancelled: Arc<AtomicBool>,
}

/// A live portal session: one mux client over the bridge's tunnel.
pub(crate) struct Session {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    closer: Arc<dyn Fn() + Send + Sync>,
    ids: Mutex<ferrox_core::mux::Ids>,
    slots: Mutex<HashMap<u16, Slot>>,
    active: AtomicU32,
    total: AtomicU32,
    done: AtomicBool,
    draining: AtomicBool,
    control: Mutex<Option<u16>>,
    portal: Weak<Portal>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("active", &self.active.load(Ordering::Relaxed))
            .field("total", &self.total.load(Ordering::Relaxed))
            .field("done", &self.done.load(Ordering::Relaxed))
            .field("draining", &self.draining.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Session {
    fn new(portal: &Arc<Portal>, tunnel: Tunnel) -> Arc<Self> {
        let (reader, writer, closer) = tunnel.split();
        let session = Arc::new(Self {
            writer,
            closer,
            ids: Mutex::new(ferrox_core::mux::Ids::new(0)),
            slots: Mutex::new(HashMap::new()),
            active: AtomicU32::new(0),
            total: AtomicU32::new(0),
            done: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            control: Mutex::new(None),
            portal: Arc::downgrade(portal),
        });
        let reader = session.clone().read_loop(reader);
        session.clone().heartbeat();
        reader
    }

    /// Registers the session and starts its reader and heartbeat.
    pub(crate) fn attach(portal: &Arc<Portal>, tunnel: Tunnel) -> Arc<Self> {
        let session = Self::new(portal, tunnel);
        if let Ok(mut list) = portal.sessions.lock() {
            list.push(session.clone());
        }
        session
    }

    fn read_loop(self: Arc<Self>, mut reader: TunnelReader) -> Arc<Self> {
        let worker = Arc::clone(&self);
        std::thread::spawn(move || {
            let mut chunk = vec![0u8; READ_SLICE];
            let mut buf: Vec<u8> = Vec::with_capacity(READ_SLICE);
            let mut at = 0;
            loop {
                if at >= buf.len() {
                    buf.clear();
                    at = 0;
                } else if at > 0 {
                    buf.drain(..at);
                    at = 0;
                }
                let mut progressed = false;
                loop {
                    match ferrox_core::mux::decode(&buf[at..], ferrox_core::mux::NewTail::Forward) {
                        Err(ferrox_core::mux::Error::Short { .. }) => break,
                        Err(_) => {
                            worker.finish();
                            return;
                        }
                        Ok((frame, used)) => {
                            at += used;
                            progressed = true;
                            match frame.status {
                                ferrox_core::mux::Status::Keep => {
                                    let Some(data) = frame.data else { continue };
                                    let Some(sender) = worker.sender(frame.id) else {
                                        continue;
                                    };
                                    let source = frame.target.and_then(source_addr);
                                    if sender.try_send((data.to_vec(), source)).is_err() {
                                        worker.end(frame.id);
                                    }
                                }
                                ferrox_core::mux::Status::End => worker.end(frame.id),
                                ferrox_core::mux::Status::New
                                | ferrox_core::mux::Status::KeepAlive => {}
                            }
                        }
                    }
                }
                if !progressed {
                    match reader.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
            }
            worker.finish();
        });
        self
    }

    fn heartbeat(self: Arc<Self>) {
        std::thread::spawn(move || {
            let id = self.open_control();
            let Some(id) = id else {
                self.finish();
                return;
            };
            let mut counter = 0u32;
            let mut scratch = Vec::with_capacity(64);
            loop {
                std::thread::sleep(HEARTBEAT);
                if self.done.load(Ordering::Relaxed) {
                    return;
                }
                let state = if self.total.load(Ordering::Relaxed) > SESSION_FLOWS {
                    DRAIN
                } else {
                    ACTIVE
                };
                counter = (counter + 1) % 5;
                if state == DRAIN || counter == 1 {
                    let bytes = Control::of(state).encode();
                    let keep = ferrox_core::mux::Outgoing {
                        id,
                        status: ferrox_core::mux::Status::Keep,
                        options: ferrox_core::mux::DATA,
                        target: None,
                        global_id: None,
                    };
                    if !self.write_frame_to(&mut scratch, &keep, Some(&bytes)) {
                        self.finish();
                        return;
                    }
                    if state == DRAIN {
                        self.draining.store(true, Ordering::Relaxed);
                        let end =
                            ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
                        let _ = self.write_frame_to(&mut scratch, &end, None);
                        if let Ok(mut control) = self.control.lock() {
                            *control = None;
                        }
                        return;
                    }
                }
            }
        });
    }

    /// Opens the internal datagram stream the reference calls `reverse`; its first datagram is
    /// what names the stream, and the portal writes one `Control` per frame after it.
    fn open_control(&self) -> Option<u16> {
        let target =
            ferrox_core::mux::Target::of(ferrox_core::mux::Network::Udp, CONTROL_DOMAIN, 0);
        let (id, _flow) = self.open(target, u32::from(u16::MAX))?;
        if let Ok(mut control) = self.control.lock() {
            *control = Some(id);
        }
        Some(id)
    }

    /// Allocates a flow and sends its `New` frame. `cap` bounds its queued downlink.
    pub(crate) fn open(
        &self,
        target: ferrox_core::mux::Target<'_>,
        cap: u32,
    ) -> Option<(u16, Flow)> {
        if self.done.load(Ordering::Relaxed) || self.draining.load(Ordering::Relaxed) {
            return None;
        }
        let id = self.ids.lock().ok()?.take().ok()?;
        let (down, receiver) = sync_channel(FLOW_PENDING.min(cap as usize).max(1));
        let cancelled = Arc::new(AtomicBool::new(false));
        if let Ok(mut slots) = self.slots.lock() {
            slots.insert(
                id,
                Slot {
                    down,
                    cancelled: Arc::clone(&cancelled),
                },
            );
        } else {
            return None;
        }
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
        let new = ferrox_core::mux::Outgoing {
            id,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(target),
            global_id: None,
        };
        let mut scratch = Vec::with_capacity(64);
        if !self.write_frame_to(&mut scratch, &new, None) {
            self.end(id);
            return None;
        }
        Some((id, Flow { down: receiver }))
    }

    pub(crate) fn send(&self, id: u16, data: &[u8]) -> bool {
        let keep = ferrox_core::mux::Outgoing {
            id,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: None,
            global_id: None,
        };
        let mut scratch = Vec::with_capacity(64);
        self.write_frame_to(&mut scratch, &keep, Some(data))
    }

    fn sender(&self, id: u16) -> Option<SyncSender<(Vec<u8>, Option<std::net::SocketAddr>)>> {
        self.slots
            .lock()
            .ok()?
            .get(&id)
            .map(|slot| slot.down.clone())
    }

    /// Ends one flow: the downlink queue drops so its pump sees EOF, and the peer learns the id
    /// is done.
    pub(crate) fn end(&self, id: u16) {
        let cancelled = self
            .slots
            .lock()
            .ok()
            .and_then(|mut slots| slots.remove(&id))
            .map(|slot| slot.cancelled);
        if let Some(cancelled) = cancelled {
            cancelled.store(true, Ordering::Relaxed);
            self.active.fetch_sub(1, Ordering::Relaxed);
            if let Ok(mut ids) = self.ids.lock() {
                ids.give_back();
            }
            let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
            let mut scratch = Vec::with_capacity(16);
            let _ = self.write_frame_to(&mut scratch, &end, None);
        }
    }

    fn write_frame_to(
        &self,
        scratch: &mut Vec<u8>,
        frame: &ferrox_core::mux::Outgoing<'_>,
        data: Option<&[u8]>,
    ) -> bool {
        let Ok(mut writer) = self.writer.lock() else {
            return false;
        };
        if let Some(payload) = data {
            let at = frame.encode_header_into(scratch);
            frame.patch_payload_len(scratch, at, payload.len());
            return crate::proxy::write_all_parts::<2>(&mut **writer, &[scratch, payload]).is_ok();
        }
        scratch.clear();
        scratch.resize(frame.frame_len(0), 0);
        let written = frame.encode_into(None, scratch);
        writer.write_all(&scratch[..written]).is_ok()
    }

    /// The tunnel ended or the session gave up: every queued flow wakes and the picker stops
    /// seeing it.
    fn finish(self: &Arc<Self>) {
        if self.done.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Ok(mut slots) = self.slots.lock() {
            for (_, slot) in slots.drain() {
                slot.cancelled.store(true, Ordering::Relaxed);
            }
        }
        if let Ok(mut ids) = self.ids.lock() {
            *ids = ferrox_core::mux::Ids::new(0);
        }
        (self.closer)();
        if let Some(portal) = self.portal.upgrade() {
            portal.forget(self);
        }
    }

    pub(crate) fn done(&self) -> bool {
        self.done.load(Ordering::Relaxed)
    }

    pub(crate) fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    pub(crate) fn active_connections(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }
}

const READ_SLICE: usize = 32 * 1024;

/// A portal: the tag the bridge's exposed flows are routed to, and the live sessions that can
/// carry one.
pub(crate) struct Portal {
    tag: String,
    sessions: Mutex<Vec<Arc<Session>>>,
}

impl std::fmt::Debug for Portal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Portal")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Portal {
    pub(crate) fn new(tag: &str) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.to_owned(),
            sessions: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn attach(self: &Arc<Self>, tunnel: Tunnel) -> Option<Arc<Session>> {
        if self.tag.is_empty() {
            return None;
        }
        Some(Session::attach(self, tunnel))
    }

    pub(crate) fn forget(&self, session: &Arc<Session>) {
        if let Ok(mut list) = self.sessions.lock() {
            list.retain(|seen| !Arc::ptr_eq(seen, session));
        }
    }

    /// The least-loaded live session, skipping a draining one until nothing else is left; the
    /// reference's own two passes.
    pub(crate) fn pick(&self) -> Option<Arc<Session>> {
        let mut list = self.sessions.lock().ok()?;
        list.retain(|session| !session.done());
        let least = |skip_draining: bool| {
            list.iter()
                .filter(|session| !session.done() && (!skip_draining || !session.draining()))
                .min_by_key(|session| session.active_connections())
                .cloned()
        };
        least(true).or_else(|| least(false))
    }
}

/// The registry of portals one process serves, keyed by the reverse tag a user names.
#[derive(Debug, Default)]
pub(crate) struct Portals {
    by_tag: HashMap<String, Arc<Portal>>,
}

impl Portals {
    pub(crate) fn insert(&mut self, tag: &str) {
        self.by_tag
            .entry(tag.to_owned())
            .or_insert_with(|| Portal::new(tag));
    }

    pub(crate) fn get(&self, tag: &str) -> Option<Arc<Portal>> {
        self.by_tag.get(tag).cloned()
    }
}

/// One worker's state, written by its control stream and read by the monitor.
pub(crate) struct WorkerState {
    state: AtomicI32,
    closed: AtomicBool,
    connections: AtomicU32,
    last_control: Mutex<Instant>,
}

impl WorkerState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicI32::new(ACTIVE),
            closed: AtomicBool::new(false),
            connections: AtomicU32::new(0),
            last_control: Mutex::new(Instant::now()),
        })
    }

    /// One `Control` message from the portal: the state it names, and the liveness a heartbeat
    /// carries whether or not it changes the state.
    pub(crate) fn control(&self, bytes: &[u8]) {
        self.touch();
        let Some(control) = Control::decode(bytes) else {
            self.closed.store(true, Ordering::Relaxed);
            return;
        };
        self.state.store(control.state, Ordering::Relaxed);
    }

    pub(crate) fn touch(&self) {
        if let Ok(mut last) = self.last_control.lock() {
            *last = Instant::now();
        }
    }

    pub(crate) fn closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    pub(crate) fn active(&self) -> bool {
        self.state.load(Ordering::Relaxed) == ACTIVE && !self.closed.load(Ordering::Relaxed)
    }

    /// A worker the portal stopped heartbeating carries no flow the monitor can route, and its
    /// tunnel may be half-open, so the monitor closes it instead of keeping it forever.
    pub(crate) fn stale(&self, after: Duration) -> bool {
        self.last_control
            .lock()
            .map_or(true, |last| last.elapsed() >= after)
    }

    pub(crate) fn note_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn release_connection(&self) {
        self.connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn connections(&self) -> u32 {
        self.connections.load(Ordering::Relaxed)
    }
}

/// The tunnel a worker opened and the state its control stream writes.
pub(crate) struct BridgeHandle {
    pub(crate) tunnel: Tunnel,
    pub(crate) state: Arc<WorkerState>,
}

/// Runs one bridge monitor until the process ends. `start` opens the tunnel the monitor then
/// hands to the mux server; it answers `None` when the server refuses.
pub(crate) fn monitor<F>(tag: &str, start: F)
where
    F: Fn(&str) -> Option<BridgeHandle> + Send + 'static,
{
    let owned = tag.to_owned();
    let spawned = owned.clone();
    std::thread::spawn(move || {
        let mut workers: Vec<BridgeHandle> = Vec::new();
        loop {
            workers.retain(|worker| {
                let live = worker.state.active() && !worker.state.stale(WORKER_IDLE);
                if !live {
                    worker.tunnel.close();
                }
                live
            });
            let live = u32::try_from(workers.len()).unwrap_or(u32::MAX);
            let connections: u32 = workers
                .iter()
                .map(|worker| worker.state.connections())
                .sum();
            if live == 0 || connections / live > 16 {
                if let Some(handle) = start(&spawned) {
                    workers.push(handle);
                }
            }
            std::thread::sleep(MONITOR);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_message_is_the_references_protobuf() {
        let active = Control {
            state: ACTIVE,
            random: vec![0xaa, 0xbb],
        };
        // proto3 omits a zero state; field 99 is a length-delimited 794 (`9a 06`).
        assert_eq!(active.encode(), [0x9a, 0x06, 0x02, 0xaa, 0xbb]);
        let drain = Control {
            state: DRAIN,
            random: vec![0xaa],
        };
        assert_eq!(drain.encode(), [0x08, 0x01, 0x9a, 0x06, 0x01, 0xaa]);
    }

    #[test]
    fn an_absent_state_is_active_and_unknown_fields_are_skipped() {
        let mut bytes = Control {
            state: ACTIVE,
            random: Vec::new(),
        }
        .encode();
        assert_eq!(
            Control::decode(&bytes).map(|control| control.state),
            Some(ACTIVE)
        );
        // field 2, varint; field 3, fixed64; field 4, fixed32; then the state.
        bytes.extend_from_slice(&[0x10, 0x2a, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0x25, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0x08, 0x01]);
        assert_eq!(
            Control::decode(&bytes).map(|control| control.state),
            Some(DRAIN)
        );
    }

    #[test]
    fn a_truncated_message_is_refused_rather_than_guessed() {
        assert!(Control::decode(&[0x08]).is_none());
        assert!(Control::decode(&[0x9a, 0x06, 0x04, 0x01]).is_none());
    }

    #[test]
    fn a_loopback_tunnel_carries_bytes_both_ways() {
        let (a, b) = loopback_pair().expect("a loopback pair");
        let a = Tunnel::from_connection(&a).expect("a tunnel");
        let b = Tunnel::from_connection(&b).expect("a tunnel");
        assert!(a.write_all(b"portal"));
        let mut buf = [0u8; 6];
        assert_eq!(b.reader().read(&mut buf).expect("reads"), 6);
        assert_eq!(&buf, b"portal");
        assert!(b.write_all(b"bridge"));
        let mut buf = [0u8; 6];
        assert_eq!(a.reader().read(&mut buf).expect("reads"), 6);
        assert_eq!(&buf, b"bridge");
    }
}
