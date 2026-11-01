// xHTTP over HTTP/2: one connection multiplexes many requests the way many TCP connections would — each stream is one GET, POST or packet — and the H1 dispatch is reused byte for byte, headers re-serialized into the H1-style head the same validators read and the response head parsed back into H2 HEADERS.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::h2::{
    block_encode, frame_head, read_head, write_frame, Decoder, E_FRAME_SIZE, E_PROTOCOL, E_REFUSED,
    F_ACK, F_END, F_END_HEADERS, F_PADDED, F_PRIORITY, HEAD_CAP, MAGIC, S_MAX_FRAME, S_WINDOW,
    T_CONT, T_DATA, T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS, T_WINDOW, WINDOW,
};
use crate::proxy::{VlessUser, VlessUsers};
use crate::xhttp::XhttpSettings;

const CONN_WINDOW_TOP_UP: u32 = 16 * 1024 * 1024 - 65_535;
const MAX_STREAMS: u32 = 100;
/// The default `SETTINGS_MAX_FRAME_SIZE` (RFC 7540 6.5.2): the largest inbound frame we accept because we never advertise a larger one.
const MAX_RECV_FRAME: usize = 16_384;
/// The two `WINDOW_UPDATE` frames one credit grants differ only by stream id, so twenty of their twenty-six bytes are constant; the connection frame keeps the first slot because that is the order it was written in.
const CREDIT_TEMPLATE: [u8; 26] = {
    let mut out = [0u8; 26];
    // length 4, WINDOW_UPDATE, no flags, stream 0 at [0..13], stream id at [13..26].
    out[2] = 4;
    out[3] = T_WINDOW;
    out[15] = 4;
    out[16] = T_WINDOW;
    out
};

/// The DATA frames one downlink write carries: a promoted relay window is `64 KiB`, four frames of the default `SETTINGS_MAX_FRAME_SIZE`, so one window reaches the peer as one vectored write.
const DATA_FRAMES_PER_WRITE: usize = 8;

const NO_PART: &[u8] = &[];

/// A window's DATA frames held apart rather than staged together: each nine-byte head in its own
/// slot and every payload still the caller's own slice, so one flush is one write whose bytes are
/// the same frames written one at a time.
struct DataBatch<'a> {
    heads: [[u8; 9]; DATA_FRAMES_PER_WRITE],
    bodies: [&'a [u8]; DATA_FRAMES_PER_WRITE],
    used: usize,
}

impl<'a> DataBatch<'a> {
    fn new() -> Self {
        Self {
            heads: [[0u8; 9]; DATA_FRAMES_PER_WRITE],
            bodies: [NO_PART; DATA_FRAMES_PER_WRITE],
            used: 0,
        }
    }

    fn full(&self) -> bool {
        self.used == DATA_FRAMES_PER_WRITE
    }

    fn add(&mut self, stream: u32, payload: &'a [u8]) {
        self.heads[self.used] = frame_head(payload.len(), T_DATA, 0, stream);
        self.bodies[self.used] = payload;
        self.used += 1;
    }

    fn flush(&mut self, conn: &H2Conn) -> bool {
        if self.used == 0 {
            return true;
        }
        let mut parts: [&[u8]; 2 * DATA_FRAMES_PER_WRITE] = [NO_PART; 2 * DATA_FRAMES_PER_WRITE];
        let mut pieces = 0;
        for (head, body) in self.heads[..self.used]
            .iter()
            .zip(self.bodies[..self.used].iter().copied())
        {
            parts[pieces] = head;
            pieces += 1;
            if !body.is_empty() {
                parts[pieces] = body;
                pieces += 1;
            }
        }
        self.used = 0;
        conn.write_batch(&parts[..pieces])
    }
}

#[derive(Debug, Clone)]
pub(crate) struct H2StreamOut {
    conn: Arc<H2Conn>,
    stream: u32,
    owner: Option<Arc<ClientOwner>>,
}

/// The last writer clone out closes the dialed connection: a clone dropped by the relay must not.
struct ClientOwner {
    conn: Arc<H2Conn>,
}

impl std::fmt::Debug for ClientOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientOwner")
    }
}

impl Drop for ClientOwner {
    fn drop(&mut self) {
        self.conn.close_client();
    }
}

impl H2StreamOut {
    pub(crate) fn data(&self, payload: &[u8]) -> bool {
        self.conn.send_data(self.stream, payload)
    }

    pub(crate) fn bind_session(&self, sid: &str) {
        self.conn.bind_session(sid, self.stream, true);
    }

    pub(crate) fn bind_upload(&self, sid: &str) {
        self.conn.bind_session(sid, self.stream, false);
    }

    pub(crate) fn end(&self) {
        if self.owner.is_some() {
            self.conn.finish_stream(self.stream);
        } else {
            self.conn.end_stream(self.stream);
        }
        self.conn.end_session_of(self.stream);
    }
}

struct H2Stream {
    state: Mutex<StreamState>,
    cv: Condvar,
    send_window: Mutex<u64>,
    responded: AtomicBool,
}

struct StreamState {
    body: VecDeque<Vec<u8>>,
    ended: bool,
    dead: bool,
}

impl H2Stream {
    /// The stream is gone from the connection, not merely done reading: a sender waiting for
    /// credit on it has nothing left to write, while an ended request still has a response to send.
    fn gone(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dead
    }
}

struct H2Conn {
    write: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    streams: Mutex<HashMap<u32, Arc<H2Stream>>>,
    sessions: Mutex<HashSet<String>>,
    session_of: Mutex<HashMap<u32, String>>,
    upload_of: Mutex<HashMap<u32, String>>,
    send_conn: Mutex<u64>,
    wake: Condvar,
    decoder: Mutex<Decoder>,
    max_frame: Mutex<usize>,
    peer_initial: Mutex<u64>,
    dead: AtomicBool,
    goaway: AtomicBool,
    refused: AtomicBool,
    /// The client half's transport: a client pumps frames on demand from its reader or a writer
    /// waiting for credit, so one thread owns the session and no parser thread outlives it.
    client_read: Option<Mutex<Box<dyn Read + Send>>>,
    raw: Option<Arc<crate::conn::Connection>>,
}

impl std::fmt::Debug for H2Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Conn").finish_non_exhaustive()
    }
}

pub(crate) struct H2StreamReader {
    conn: Arc<H2Conn>,
    stream: Arc<H2Stream>,
    id: u32,
    /// How much of the front frame this reader has taken: the frame is popped when it is spent,
    /// so a short read leaves the tail where the loop put it instead of moving it to the base.
    at: usize,
}

impl Read for H2StreamReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let mut st = self
                .stream
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(front) = st.body.front() {
                let n = (front.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&front[self.at..self.at + n]);
                self.at += n;
                if self.at == front.len() {
                    st.body.pop_front();
                    self.at = 0;
                }
                drop(st);
                self.conn.replenish(self.id, n);
                return Ok(n);
            }
            if st.ended {
                drop(st);
                self.conn.forget_upload(self.id);
                return Ok(0);
            }
            if st.dead || self.conn.dead.load(Ordering::SeqCst) {
                drop(st);
                self.conn.forget_upload(self.id);
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            if self.conn.client_read.is_some() {
                drop(st);
                if !self.conn.pump_read(|| {
                    let st = self
                        .stream
                        .state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    !st.body.is_empty() || st.ended || st.dead
                }) {
                    self.conn.forget_upload(self.id);
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
                }
                continue;
            }
            let (next, wait) = self
                .stream
                .cv
                .wait_timeout(st, crate::budgets::relay_stall())
                .unwrap_or_else(PoisonError::into_inner);
            st = next;
            if wait.timed_out() {
                drop(st);
                self.conn.forget_upload(self.id);
                return Err(std::io::Error::other("h2 body stalled"));
            }
        }
    }
}

struct H2StreamWriter {
    conn: Arc<H2Conn>,
    stream: u32,
    head: Vec<u8>,
    headed: bool,
}

/// The h1 fields a stream never forwards: the connection owns them.
fn hop_by_hop(name: &str) -> bool {
    [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
    ]
    .into_iter()
    .any(|hop| hop.eq_ignore_ascii_case(name))
}

/// A response head's fields, status first: one pass and one list, and a hop-by-hop name is
/// recognised in place where the lowercase form it replaces allocated a `String` per line.
fn response_fields(head: &str) -> Vec<(&str, &str)> {
    let mut fields = Vec::with_capacity(1 + head.matches("\r\n").count());
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap_or("200");
    fields.push((":status", status));
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if hop_by_hop(name) {
            continue;
        }
        fields.push((name, value.trim()));
    }
    fields
}

impl H2StreamWriter {
    fn emit_headers(&mut self, head: &[u8]) -> bool {
        let text = std::str::from_utf8(head).unwrap_or_default();
        let headers = response_fields(text);
        let block = block_encode(&headers);
        let max = *self
            .conn
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut at = 0;
        loop {
            let end = (at + max).min(block.len());
            let flags = if end == block.len() { F_END_HEADERS } else { 0 };
            let kind = if at == 0 { T_HEADERS } else { T_CONT };
            if !self.conn.frame(kind, flags, self.stream, &block[at..end]) {
                return false;
            }
            at = end;
            if at >= block.len() {
                break;
            }
        }
        self.headed = true;
        if let Some(s) = self
            .conn
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.stream)
        {
            s.responded.store(true, Ordering::SeqCst);
        }
        true
    }
}

impl Write for H2StreamWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.headed {
            self.head.extend_from_slice(buf);
            if let Some(at) = ferrox_core::foxy::head_end(&self.head) {
                let head = std::mem::take(&mut self.head);
                if !self.emit_headers(&head[..at + 4]) {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                }
                let body = &head[at + 4..];
                if !body.is_empty() && !self.conn.send_data(self.stream, body) {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                }
            }
            return Ok(buf.len());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.conn.send_data(self.stream, buf) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::proxy::FrameWrite for H2StreamWriter {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        parts.iter().all(|part| self.write_all(part).is_ok())
    }
}

impl H2Conn {
    fn frame(&self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let Ok(mut write) = self.write.lock() else {
            return false;
        };
        if !write_frame(&mut **write, kind, flags, id, body) {
            self.dead.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }

    fn write_batch(&self, parts: &[&[u8]]) -> bool {
        let Ok(mut write) = self.write.lock() else {
            return false;
        };
        if !write.write_slices(parts) {
            self.dead.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Refuse the connection: the GOAWAY goes out now, and `refused` remembers that the peer still has to be given the window to read it.
    fn refuse(&self, code: u32) {
        self.refused.store(true, Ordering::SeqCst);
        let mut goaway = [0u8; 8];
        goaway[4..].copy_from_slice(&code.to_be_bytes());
        self.frame(T_GOAWAY, 0, 0, &goaway);
    }

    fn send_data(&self, stream: u32, mut payload: &[u8]) -> bool {
        if payload.is_empty() {
            return true;
        }
        let Some(state) = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .cloned()
        else {
            return false;
        };
        let max = *self
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut batch = DataBatch::new();
        while !payload.is_empty() {
            let fit = payload.len().min(max);
            let Some(chunk) = self.credit(&state, fit as u64, &mut batch) else {
                return false;
            };
            if batch.full() && !batch.flush(self) {
                return false;
            }
            batch.add(stream, &payload[..chunk]);
            payload = &payload[chunk..];
        }
        batch.flush(self)
    }

    /// Take what the two windows allow, waiting only after the frames already reserved have reached the peer.
    fn credit(&self, state: &H2Stream, need: u64, batch: &mut DataBatch<'_>) -> Option<usize> {
        if let Some(take) = self.take_send_window(state, need, false) {
            return Some(take);
        }
        if !batch.flush(self) {
            return None;
        }
        self.take_send_window(state, need, true)
    }

    fn take_send_window(&self, stream: &H2Stream, need: u64, blocking: bool) -> Option<usize> {
        let mut conn = self
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            if self.dead.load(Ordering::SeqCst) {
                return None;
            }
            let take = {
                let mut window = stream
                    .send_window
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let take = need.min(*conn).min(*window);
                if take > 0 {
                    *conn -= take;
                    *window -= take;
                }
                take
            };
            if take > 0 {
                return Some(take as usize);
            }
            if !blocking || stream.gone() {
                return None;
            }
            if self.client_read.is_some() {
                // A client's credit arrives on its reader's transport, so a parked writer pumps it itself.
                drop(conn);
                if !self.pump_read(|| {
                    if self.dead.load(Ordering::SeqCst) || stream.gone() {
                        return true;
                    }
                    let conn = self
                        .send_conn
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let window = stream
                        .send_window
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    *conn > 0 && *window > 0
                }) {
                    return None;
                }
                conn = self
                    .send_conn
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let (guard, waited) = self
                .wake
                .wait_timeout(conn, crate::budgets::relay_stall())
                .unwrap_or_else(PoisonError::into_inner);
            conn = guard;
            if waited.timed_out() || stream.gone() {
                return None;
            }
        }
    }

    fn replenish(&self, stream: u32, n: usize) {
        if n == 0 || n > u32::MAX as usize {
            return;
        }
        let increment = (n as u32).to_be_bytes();
        let mut out = CREDIT_TEMPLATE;
        out[9..13].copy_from_slice(&increment);
        out[18..22].copy_from_slice(&stream.to_be_bytes());
        out[22..26].copy_from_slice(&increment);
        // Consuming inbound bytes grants the peer more credit; our own send windows rise only from the peer's WINDOW_UPDATE, so crediting them here would let a bulk send outrun the window the peer gave and trip its flow control.
        let Ok(mut write) = self.write.lock() else {
            return;
        };
        if !write.write_slices(&[&out]) {
            self.dead.store(true, Ordering::SeqCst);
        }
    }

    /// The client's request body ends on its own stream while the response keeps reading: an RST
    /// here would discard the answer the peer has not written yet.
    fn finish_stream(&self, stream: u32) {
        let _ = self.frame(T_DATA, F_END, stream, &[]);
    }

    fn close_client(&self) {
        self.dead.store(true, Ordering::SeqCst);
        if let Some(raw) = &self.raw {
            let _ = raw.shutdown(std::net::Shutdown::Both);
        }
        self.kill();
    }

    /// A reset from the peer kills only its stream: the connection may still serve the others.
    fn fail_stream(&self, stream: u32) {
        let state = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&stream);
        if let Some(state) = state {
            let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            st.dead = true;
            state.cv.notify_all();
        }
        self.wake.notify_all();
    }

    fn end_stream(&self, stream: u32) {
        let responded = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .is_some_and(|s| s.responded.load(Ordering::SeqCst));
        if responded {
            let _ = self.frame(T_DATA, F_END, stream, &[]);
        } else {
            self.reset_stream(stream);
        }
    }

    fn reset_stream(&self, stream: u32) {
        self.forget_upload(stream);
        {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(state) = streams.remove(&stream) {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                st.dead = true;
                state.cv.notify_all();
            }
        }
        self.wake.notify_all();
        self.end_session_of(stream);
        let _ = self.frame(T_RST, 0, stream, &E_REFUSED.to_be_bytes());
    }

    fn kill(&self) {
        self.dead.store(true, Ordering::SeqCst);
        self.wake.notify_all();
        let streams: Vec<_> = {
            self.streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .cloned()
                .collect()
        };
        for state in streams {
            let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            st.dead = true;
            state.cv.notify_all();
        }
        let sessions: Vec<String> = self
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for session in sessions {
            crate::xhttp::end_session(&session);
        }
    }

    /// The session a stream of this connection waits on dies with the connection: past `dead` there is no frame left to post, so a waiter would park on a sequence no peer can ever send.
    fn bind_session(&self, sid: &str, stream: u32, downlink: bool) {
        {
            let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            // Every packet-up POST repeats its session's id, so the owned key is only made for a first bind.
            if !sessions.contains(sid) {
                sessions.insert(sid.to_owned());
            }
        }
        let owner = if downlink {
            &self.session_of
        } else {
            &self.upload_of
        };
        owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(stream, sid.to_owned());
        // `kill` sets `dead` before it drains this set, so a bind that raced the drain ends its own session.
        if self.dead.load(Ordering::SeqCst) {
            crate::xhttp::end_session(sid);
        }
    }

    fn forget_upload(&self, stream: u32) {
        self.upload_of
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&stream);
    }

    /// The session is over, so the uploads that shared it are too: mark each one ended and wake its parked reader before the connection's death is the only way out.
    fn end_uploads(&self, sid: &str) {
        let streams: Vec<u32> = {
            let mut uploads = self
                .upload_of
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let owned: Vec<u32> = uploads
                .iter()
                .filter(|(_, owner)| owner.as_str() == sid)
                .map(|(stream, _)| *stream)
                .collect();
            for stream in &owned {
                uploads.remove(stream);
            }
            owned
        };
        for stream in streams {
            let state = self
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&stream);
            if let Some(state) = state {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                st.ended = true;
                st.dead = true;
                state.cv.notify_all();
            }
        }
    }

    /// A finished downlink ends the session its uploads wait on, so a packet-up POST parked in `wait_ended` is not left for the connection's death.
    fn end_session_of(&self, stream: u32) {
        let sid = self
            .session_of
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&stream);
        if let Some(sid) = sid {
            self.end_uploads(&sid);
            self.sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&sid);
            crate::xhttp::end_session(&sid);
        }
    }
}

impl H2Conn {
    fn apply_settings(&self, body: &[u8]) {
        let mut at = 0;
        while at + 6 <= body.len() {
            let id = u16::from_be_bytes([body[at], body[at + 1]]);
            let value =
                u32::from_be_bytes([body[at + 2], body[at + 3], body[at + 4], body[at + 5]]);
            at += 6;
            if id == S_MAX_FRAME {
                let mut max = self
                    .max_frame
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *max = usize::try_from(value)
                    .unwrap_or(crate::h2::FRAME_CAP)
                    .clamp(16_384, 16_777_215);
            } else if id == S_WINDOW {
                let value = u64::from(value.min((1 << 31) - 1));
                let mut previous = self
                    .peer_initial
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let delta = value.saturating_sub(*previous);
                *previous = value;
                drop(previous);
                let streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
                for state in streams.values() {
                    let mut window = state
                        .send_window
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    *window = window.saturating_add(delta).min((1 << 31) - 1);
                }
                self.wake.notify_all();
            }
        }
        let _ = self.frame(T_SETTINGS, F_ACK, 0, &[]);
    }
}

impl H2Conn {
    /// A client's frames arrive on the same transport its reader consumes: one frame is parsed on
    /// demand, so a read and a credit-starved write both make progress without a parser thread.
    fn pump_read(&self, ready: impl FnOnce() -> bool) -> bool {
        let Some(read) = self.client_read.as_ref() else {
            return false;
        };
        let mut read = read.lock().unwrap_or_else(PoisonError::into_inner);
        if ready() {
            return true;
        }
        let Some((len, kind, flags, sid)) = read_head_retry(&mut **read) else {
            self.dead.store(true, Ordering::SeqCst);
            return false;
        };
        if len > MAX_RECV_FRAME {
            self.dead.store(true, Ordering::SeqCst);
            return false;
        }
        let mut body = crate::proxy::unfilled(len);
        if read_exact_retry(&mut **read, &mut body).is_err() {
            self.dead.store(true, Ordering::SeqCst);
            return false;
        }
        // Dispatch under the lock so a later frame cannot overtake an earlier one on the wire.
        let alive = client_frame(self, kind, flags, sid, body);
        if !alive {
            self.dead.store(true, Ordering::SeqCst);
        }
        alive
    }
}

fn read_exact_retry(stream: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<()> {
    let started = std::time::Instant::now();
    let mut at = 0;
    while at < buf.len() {
        match stream.read(&mut buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => at += n,
            Err(error) if crate::proxy::is_timeout(&error) => {
                if started.elapsed() >= crate::budgets::relay_stall() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "h2 frame stalled",
                    ));
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(crate::budgets::RELAY_POLL);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_head_retry(stream: &mut dyn Read) -> Option<(usize, u8, u8, u32)> {
    let mut head = [0u8; 9];
    read_exact_retry(stream, &mut head).ok()?;
    Some((
        usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]),
        head[3],
        head[4],
        u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7FFF_FFFF,
    ))
}

/// The client's frame dispatch: settings and credit are shared with the server, while a response
/// head ends the stream and a reset fails only that stream.
fn client_frame(conn: &H2Conn, kind: u8, flags: u8, sid: u32, body: Vec<u8>) -> bool {
    if let Some(alive) = control_frame(conn, kind, flags, sid, &body) {
        return alive;
    }
    match kind {
        T_HEADERS => {
            if sid == 1 {
                let streams = conn.streams.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(state) = streams.get(&sid) {
                    state.responded.store(true, Ordering::SeqCst);
                    if flags & F_END != 0 {
                        let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                        st.ended = true;
                        state.cv.notify_all();
                    }
                }
            }
            true
        }
        T_DATA => queue_data(conn, flags, sid, body),
        T_RST => {
            if sid == 1 {
                conn.fail_stream(sid);
            }
            true
        }
        T_GOAWAY => {
            conn.goaway.store(true, Ordering::SeqCst);
            true
        }
        _ => true,
    }
}

struct NullWrite;

impl Write for NullWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::proxy::FrameWrite for NullWrite {
    fn write_slices(&mut self, _parts: &[&[u8]]) -> bool {
        true
    }
}

/// One client connection, one stream: the reference opens a stream per session and keeps the
/// connection for the pool, so a stream ending must not close what a later session can reuse.
pub(crate) fn connect_split<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    read: R,
    write: W,
    raw: Arc<crate::conn::Connection>,
    host: &str,
    settings: &XhttpSettings,
    scheme: &str,
) -> Option<(H2StreamReader, crate::xhttp::XhttpWriter)> {
    let conn = Arc::new(H2Conn {
        write: Mutex::new(Box::new(write)),
        streams: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashSet::new()),
        session_of: Mutex::new(HashMap::new()),
        upload_of: Mutex::new(HashMap::new()),
        send_conn: Mutex::new(65_535),
        wake: Condvar::new(),
        decoder: Mutex::new(Decoder::default()),
        max_frame: Mutex::new(16_384),
        peer_initial: Mutex::new(65_535),
        dead: AtomicBool::new(false),
        goaway: AtomicBool::new(false),
        refused: AtomicBool::new(false),
        client_read: Some(Mutex::new(Box::new(read))),
        raw: Some(raw),
    });
    let state = Arc::new(H2Stream {
        state: Mutex::new(StreamState {
            body: VecDeque::new(),
            ended: false,
            dead: false,
        }),
        cv: Condvar::new(),
        send_window: Mutex::new(65_535),
        responded: AtomicBool::new(false),
    });
    conn.streams
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(1, Arc::clone(&state));

    {
        let mut write = conn.write.lock().unwrap_or_else(PoisonError::into_inner);
        if write.write_all(MAGIC).is_err() {
            return None;
        }
    }
    let mut initial = Vec::with_capacity(12);
    initial.extend_from_slice(&S_WINDOW.to_be_bytes());
    initial.extend_from_slice(&WINDOW.to_be_bytes());
    if !conn.frame(T_SETTINGS, 0, 0, &initial) {
        return None;
    }
    if !conn.frame(T_WINDOW, 0, 0, &CONN_WINDOW_TOP_UP.to_be_bytes()) {
        return None;
    }

    let path = crate::xhttp::dial_path(settings);
    let mut fields: Vec<(String, String)> = vec![
        (":method".to_owned(), "POST".to_owned()),
        (":path".to_owned(), path),
        (":scheme".to_owned(), scheme.to_owned()),
        (":authority".to_owned(), host.to_owned()),
    ];
    for (name, value) in crate::xhttp::dial_fields(host, settings) {
        if name.starts_with(':')
            || hop_by_hop(&name)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("te")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        let mut name = name;
        name.make_ascii_lowercase();
        fields.push((name, value));
    }
    let block = {
        let refs: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        block_encode(&refs)
    };
    if !conn.frame(T_HEADERS, F_END_HEADERS, 1, &block) {
        return None;
    }

    let out = H2StreamOut {
        conn: Arc::clone(&conn),
        stream: 1,
        owner: Some(Arc::new(ClientOwner {
            conn: Arc::clone(&conn),
        })),
    };
    let writer = crate::xhttp::XhttpWriter::new(NullWrite);
    writer.set_h2(out);
    Some((
        H2StreamReader {
            conn,
            stream: state,
            id: 1,
            at: 0,
        },
        writer,
    ))
}

fn synth_head(method: &[u8], target: &[u8], lines: &[u8], end_stream: bool) -> Vec<u8> {
    // " " and " HTTP/2\r\n" and the closing "\r\n", plus the chunked line a stream still open carries.
    let framing = if end_stream { 12 } else { 40 };
    let mut head = Vec::with_capacity(method.len() + target.len() + lines.len() + framing);
    head.extend_from_slice(method);
    head.push(b' ');
    head.extend_from_slice(target);
    head.extend_from_slice(b" HTTP/2\r\n");
    head.extend_from_slice(lines);
    if !end_stream {
        head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

fn open_stream(
    conn: &Arc<H2Conn>,
    settings: &XhttpSettings,
    users: &VlessUsers,
    freedom: bool,
    sid: u32,
    block: &[u8],
    end_stream: bool,
) {
    let (method, target, lines) = {
        let mut decoder = conn.decoder.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut method, mut target, mut lines) = (Vec::new(), Vec::new(), Vec::new());
        let (mut have_method, mut have_target) = (false, false);
        let ok = decoder
            .decode(block, &mut |name, value| {
                if name.first() == Some(&b':') {
                    if name.eq_ignore_ascii_case(b":method") && !have_method {
                        have_method = true;
                        method.extend_from_slice(value);
                    } else if name.eq_ignore_ascii_case(b":path") && !have_target {
                        have_target = true;
                        target.extend_from_slice(value);
                    }
                } else {
                    lines.extend_from_slice(name);
                    lines.extend_from_slice(b": ");
                    lines.extend_from_slice(value);
                    lines.extend_from_slice(b"\r\n");
                }
            })
            .is_some();
        drop(decoder);
        if !ok || !have_method || !have_target {
            conn.reset_stream(sid);
            return;
        }
        (method, target, lines)
    };
    if conn.goaway.load(Ordering::SeqCst) {
        conn.reset_stream(sid);
        return;
    }
    let initial = *conn
        .peer_initial
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let state = Arc::new(H2Stream {
        state: Mutex::new(StreamState {
            body: VecDeque::new(),
            ended: end_stream,
            dead: false,
        }),
        cv: Condvar::new(),
        send_window: Mutex::new(initial),
        responded: AtomicBool::new(false),
    });
    {
        let mut streams = conn.streams.lock().unwrap_or_else(PoisonError::into_inner);
        if streams.len() >= MAX_STREAMS as usize || streams.contains_key(&sid) {
            drop(streams);
            conn.reset_stream(sid);
            return;
        }
        streams.insert(sid, Arc::clone(&state));
    }
    let head = synth_head(&method, &target, &lines, end_stream);
    let reader = H2StreamReader {
        conn: Arc::clone(conn),
        stream: Arc::clone(&state),
        id: sid,
        at: 0,
    };
    let h2out = H2StreamOut {
        conn: Arc::clone(conn),
        stream: sid,
        owner: None,
    };
    let writer = H2StreamWriter {
        conn: Arc::clone(conn),
        stream: sid,
        head: Vec::new(),
        headed: false,
    };
    let settings = settings.clone();
    let users = Arc::clone(users);
    crate::budgets::spawn(move || {
        match crate::xhttp::accept_core(
            &head,
            Vec::new(),
            reader,
            writer,
            &settings,
            Some(h2out.clone()),
        ) {
            crate::xhttp::Served::Session(ureader, xwriter) => {
                crate::proxy::serve_session_xhttp_with(ureader, &xwriter, &users, freedom);
            }
            _ => h2out.end(),
        }
    });
}

pub(crate) fn serve_h2<R: Read + Send + 'static, W: crate::proxy::FrameWrite + Send + 'static>(
    mut read: R,
    write: W,
    settings: &XhttpSettings,
    users: &[VlessUser],
    freedom: bool,
) {
    let users: VlessUsers = Arc::from(users);
    let mut magic = [0u8; 24];
    if crate::proxy::read_exact(&mut read, &mut magic).is_err() || magic != *MAGIC {
        return;
    }
    let conn = Arc::new(H2Conn {
        write: Mutex::new(Box::new(write)),
        streams: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashSet::new()),
        session_of: Mutex::new(HashMap::new()),
        upload_of: Mutex::new(HashMap::new()),
        send_conn: Mutex::new(65_535),
        wake: Condvar::new(),
        decoder: Mutex::new(Decoder::default()),
        max_frame: Mutex::new(16_384),
        peer_initial: Mutex::new(65_535),
        dead: AtomicBool::new(false),
        goaway: AtomicBool::new(false),
        refused: AtomicBool::new(false),
        client_read: None,
        raw: None,
    });
    let mut initial = Vec::with_capacity(12);
    initial.extend_from_slice(&S_WINDOW.to_be_bytes());
    initial.extend_from_slice(&WINDOW.to_be_bytes());
    if !conn.frame(T_SETTINGS, 0, 0, &initial) {
        return;
    }
    conn.frame(T_WINDOW, 0, 0, &CONN_WINDOW_TOP_UP.to_be_bytes());
    let mut frag: Option<(u32, Vec<u8>)> = None;
    while let Some((len, kind, flags, sid)) = read_head(&mut read) {
        if len > MAX_RECV_FRAME {
            // A frame past the default SETTINGS_MAX_FRAME_SIZE is a connection error (RFC 7540 6.9.1): refuse it before reserving its length or blocking on a body that may never arrive.
            conn.refuse(E_FRAME_SIZE);
            break;
        }
        let mut body = crate::proxy::unfilled(len);
        if crate::proxy::read_exact(&mut read, &mut body).is_err() {
            break;
        }
        if !pump_frame(
            &conn, settings, &users, freedom, kind, flags, sid, body, &mut frag,
        ) {
            break;
        }
    }
    if conn.refused.load(Ordering::SeqCst) {
        // Closing while the peer's bytes sit unread aborts the connection, and the RST can swallow the GOAWAY written microseconds earlier; the grace is the window the peer takes it in.
        std::thread::sleep(crate::budgets::goaway_grace());
    }
    conn.kill();
    conn.wake.notify_all();
}

/// Cuts a padded DATA frame's own buffer to `[payload]` in place — the pad-length byte skipped, the padding tail dropped — and returns the payload length, `0` when the pad swallows the payload. The allocation survives truncated, where a slice-to-`Vec` would have copied the payload out; the saturation matches the borrow-checked reference at every pad length.
#[inline]
fn cut_padded_data(body: &mut Vec<u8>, pad: usize) -> usize {
    let inner = body.len().saturating_sub(1 + pad);
    body.copy_within(1..=inner, 0);
    body.truncate(inner);
    inner
}

/// The frames both roles answer the same way: settings, pings and flow-control credit. `None`
/// leaves the frame to the role that owns the stream lifecycle.
fn control_frame(conn: &H2Conn, kind: u8, flags: u8, sid: u32, body: &[u8]) -> Option<bool> {
    match kind {
        T_SETTINGS => {
            if flags & F_ACK == 0 {
                if !body.len().is_multiple_of(6) {
                    return Some(false);
                }
                conn.apply_settings(body);
            }
            Some(true)
        }
        T_PING => {
            if flags & F_ACK == 0 && body.len() == 8 {
                conn.frame(T_PING, F_ACK, 0, body);
            }
            Some(true)
        }
        T_WINDOW => {
            if body.len() != 4 {
                return Some(true);
            }
            let inc =
                u64::from(u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7FFF_FFFF);
            if inc == 0 {
                return Some(true);
            }
            if sid == 0 {
                let mut conn_window = conn
                    .send_conn
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *conn_window = conn_window.saturating_add(inc).min((1 << 31) - 1);
            } else if let Some(state) = conn
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&sid)
            {
                let mut window = state
                    .send_window
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *window = window.saturating_add(inc).min((1 << 31) - 1);
            }
            conn.wake.notify_all();
            Some(true)
        }
        _ => None,
    }
}

/// A DATA frame's credit is its wire length, taken before the in-place cut that makes the frame's
/// own buffer the queued chunk: flow control counts the whole payload, the Pad Length octet and the
/// padding included (RFC 7540 6.9), as the reference's take of `f.Length` does.
fn queue_data(conn: &H2Conn, flags: u8, sid: u32, mut body: Vec<u8>) -> bool {
    let wire_len = body.len();
    if flags & F_PADDED != 0 {
        let Some(&pad) = body.first() else {
            return true;
        };
        cut_padded_data(&mut body, pad as usize);
    }
    let streams = conn.streams.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(state) = streams.get(&sid).cloned() else {
        drop(streams);
        conn.replenish(sid, wire_len);
        return true;
    };
    drop(streams);
    {
        let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !st.dead {
            st.body.push_back(body);
            if flags & F_END != 0 {
                st.ended = true;
            }
        }
        state.cv.notify_all();
    }
    conn.replenish(sid, wire_len);
    true
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one arm per frame kind; splitting the dispatcher would scatter the protocol"
)]
fn pump_frame(
    conn: &Arc<H2Conn>,
    settings: &XhttpSettings,
    users: &VlessUsers,
    freedom: bool,
    kind: u8,
    flags: u8,
    sid: u32,
    body: Vec<u8>,
    frag: &mut Option<(u32, Vec<u8>)>,
) -> bool {
    if let Some(alive) = control_frame(conn, kind, flags, sid, &body) {
        return alive;
    }
    match kind {
        T_HEADERS => {
            if sid == 0 || sid.is_multiple_of(2) {
                return true;
            }
            let mut block = body;
            let mut pos = 0;
            if flags & F_PADDED != 0 {
                let Some(&len) = block.first() else {
                    return true;
                };
                pos = 1 + len as usize;
                if pos > block.len() {
                    return true;
                }
            }
            if flags & F_PRIORITY != 0 {
                pos += 5;
                if pos > block.len() {
                    return true;
                }
            }
            block.drain(..pos);
            let end_headers = flags & F_END_HEADERS != 0;
            let end_stream = flags & F_END != 0;
            if end_headers {
                // A HEADERS for another stream while one is still assembling is a connection error; drop the stale assembly, serve this.
                let _ = frag.take();
                if conn
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .contains_key(&sid)
                {
                    return true;
                }
                open_stream(conn, settings, users, freedom, sid, &block, end_stream);
            } else {
                *frag = Some((sid, block));
            }
            true
        }
        T_CONT => {
            if let Some((pending, mut gathered)) = frag.take() {
                if pending != sid {
                    *frag = Some((pending, gathered));
                    return true;
                }
                // A header block reassembled past the implementation limit is a connection error (RFC 7540 4.3): refuse before growing it, so endless CONTINUATION frames cannot accumulate without bound.
                if gathered.len() + body.len() > HEAD_CAP {
                    conn.refuse(E_PROTOCOL);
                    return false;
                }
                gathered.extend_from_slice(&body);
                if flags & F_END_HEADERS != 0 {
                    open_stream(conn, settings, users, freedom, sid, &gathered, false);
                } else {
                    *frag = Some((sid, gathered));
                }
            }
            true
        }
        T_DATA => queue_data(conn, flags, sid, body),
        T_RST => {
            conn.reset_stream(sid);
            true
        }
        T_GOAWAY => {
            conn.goaway.store(true, Ordering::SeqCst);
            true
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{test_bind, Connection};
    use crate::h2::MAGIC;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::Duration;

    struct H2Client {
        stream: Connection,
        next: u32,
        decoder: Decoder,
        held: VecDeque<(u8, u8, u32, Vec<u8>)>,
    }

    impl H2Client {
        fn connect(addr: SocketAddr) -> Self {
            let mut stream = Connection::connect(addr).expect("connects");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("timeout");
            stream.write_all(MAGIC).expect("preface");
            let mut initial = Vec::with_capacity(12);
            initial.extend_from_slice(&S_WINDOW.to_be_bytes());
            initial.extend_from_slice(&WINDOW.to_be_bytes());
            write_frame(&mut stream, T_SETTINGS, 0, 0, &initial);
            let mut conn = Self {
                stream,
                next: 1,
                decoder: Decoder::default(),
                held: VecDeque::new(),
            };
            for _ in 0..3 {
                let (len, kind, flags, _) = read_head(&mut conn.stream).expect("frame");
                let mut body = crate::proxy::unfilled(len);
                crate::proxy::read_exact(&mut conn.stream, &mut body).expect("body");
                if kind == T_SETTINGS && flags & F_ACK == 0 {
                    write_frame(&mut conn.stream, T_SETTINGS, F_ACK, 0, &[]);
                }
            }
            conn
        }

        fn headers(
            &mut self,
            method: &str,
            target: &str,
            extra: &[(&str, &str)],
            end_stream: bool,
        ) -> u32 {
            let id = self.next;
            self.next += 2;
            let mut fields = vec![
                (":method", method),
                (":path", target),
                (":scheme", "http"),
                (":authority", "127.0.0.1"),
            ];
            fields.extend_from_slice(extra);
            let block = block_encode(&fields);
            let flags = if end_stream {
                F_END | F_END_HEADERS
            } else {
                F_END_HEADERS
            };
            write_frame(&mut self.stream, T_HEADERS, flags, id, &block);
            self.stream.flush().expect("flushes");
            id
        }

        fn data(&mut self, id: u32, payload: &[u8], end: bool) {
            let mut at = 0;
            while at < payload.len() {
                let end_at = (at + 16384).min(payload.len());
                let last = end && end_at == payload.len();
                write_frame(
                    &mut self.stream,
                    T_DATA,
                    if last { F_END } else { 0 },
                    id,
                    &payload[at..end_at],
                );
                at = end_at;
            }
            if end && payload.is_empty() {
                write_frame(&mut self.stream, T_DATA, F_END, id, &[]);
            }
            self.stream.flush().expect("flushes");
        }

        /// Every DATA frame is padded: a pad-length byte in front of the payload, `pad` bytes after it, the last frame ending the stream. Chunk sizing leaves room for both pad halves inside one frame.
        fn padded_data(&mut self, id: u32, payload: &[u8], pad: u8, end: bool) {
            let room = MAX_RECV_FRAME - 1 - pad as usize;
            let mut at = 0;
            loop {
                let end_at = (at + room).min(payload.len());
                let chunk = &payload[at..end_at];
                let last = end && end_at == payload.len();
                let mut frame = Vec::with_capacity(1 + chunk.len() + pad as usize);
                frame.push(pad);
                frame.extend_from_slice(chunk);
                frame.extend(std::iter::repeat_n(pad, pad as usize));
                write_frame(
                    &mut self.stream,
                    T_DATA,
                    if last { F_PADDED | F_END } else { F_PADDED },
                    id,
                    &frame,
                );
                at = end_at;
                if last || at == payload.len() {
                    break;
                }
            }
            self.stream.flush().expect("flushes");
        }

        /// The next frame this reader has a use for: a wanted frame for `id` comes off what an
        /// earlier reader set aside before the socket is read at all, and a frame that arrived for
        /// another stream is set aside instead of dropped. A PING is answered here, once, so no
        /// reader has to remember to.
        fn next_frame(&mut self, id: u32, want: impl Fn(u8) -> bool) -> (u8, u8, u32, Vec<u8>) {
            loop {
                if let Some(at) = self.held.iter().position(|f| f.2 == id && want(f.0)) {
                    return self.held.remove(at).expect("the position just found");
                }
                let (len, kind, flags, got) = read_head(&mut self.stream).expect("frame");
                let mut body = crate::proxy::unfilled(len);
                crate::proxy::read_exact(&mut self.stream, &mut body).expect("body");
                if kind == T_PING && flags & F_ACK == 0 && body.len() == 8 {
                    write_frame(&mut self.stream, T_PING, F_ACK, 0, &body);
                    continue;
                }
                if got == id && want(kind) {
                    return (kind, flags, got, body);
                }
                self.hold(kind, flags, got, body);
            }
        }

        /// A frame belonging to a stream this reader is not waiting on. Dropping one is how a
        /// multiplexed response arrives short: the bytes were read and then thrown away.
        fn hold(&mut self, kind: u8, flags: u8, id: u32, body: Vec<u8>) {
            if !body.is_empty() && matches!(kind, T_DATA | T_HEADERS | T_CONT) {
                self.held.push_back((kind, flags, id, body));
            }
        }

        fn response_head(&mut self, id: u32) -> u16 {
            let mut block = Vec::new();
            loop {
                let (_, flags, _, frame) =
                    self.next_frame(id, |kind| matches!(kind, T_HEADERS | T_CONT));
                block.extend_from_slice(&frame);
                if flags & F_END_HEADERS != 0 {
                    let mut status = 0u16;
                    let mut seen = false;
                    self.decoder
                        .decode(&block, &mut |name, value| {
                            if seen || name != &b":status"[..] {
                                return;
                            }
                            seen = true;
                            status = std::str::from_utf8(value)
                                .unwrap_or_default()
                                .parse()
                                .unwrap_or(0);
                        })
                        .expect("decodes");
                    return status;
                }
            }
        }

        fn response_data(&mut self, id: u32, n: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                let (kind, flags, _, frame) =
                    self.next_frame(id, |kind| matches!(kind, T_DATA | T_RST));
                assert!(kind != T_RST, "stream reset");
                let take = (n - out.len()).min(frame.len());
                out.extend_from_slice(&frame[..take]);
                self.hold(kind, flags, id, frame[take..].to_vec());
            }
            out
        }

        /// Read the server's DATA the way a strict peer's flow control does: never grant more window, and fail the moment a frame outruns what was granted. A `grant`-byte connection window, no `WINDOW_UPDATE` ever sent, so a server that honours flow control stops at `grant` (returned as `false`), while one that outran it yields `true` past the boundary.
        fn outruns_the_granted_window(&mut self, id: u32, grant: u64) -> bool {
            // The ceiling only ends the correct run, where the peer's send window is exhausted and it blocks; the verdict is the byte count, never the clock.
            let _ = self.stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut left = grant;
            loop {
                let mut head = [0u8; 9];
                if fill(&mut self.stream, &mut head).is_none() {
                    return false;
                }
                let len =
                    usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
                let kind = head[3];
                let flags = head[4];
                let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7FFF_FFFF;
                let mut body = crate::proxy::unfilled(len);
                if len > 0 && fill(&mut self.stream, &mut body).is_none() {
                    return false;
                }
                match kind {
                    T_DATA if sid == id => {
                        let taken = len as u64;
                        if taken > left {
                            return true;
                        }
                        left -= taken;
                    }
                    T_PING if flags & F_ACK == 0 && len == 8 => {
                        write_frame(&mut self.stream, T_PING, F_ACK, 0, &body);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Fill `buf` from the socket, returning `None` on EOF or a read error (including the timeout that means a window-exhausted peer has stopped) so a drain can distinguish "no more to observe" from a frame count.
    fn fill(stream: &mut Connection, buf: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        while at < buf.len() {
            match stream.read(&mut buf[at..]) {
                Ok(0) => return None,
                Ok(n) => at += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        Some(at)
    }

    fn echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
        let echo = test_bind("127.0.0.1:0").expect("binds");
        let addr = echo.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        (addr, handle)
    }

    fn vless_header(port: u16) -> Vec<u8> {
        ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses")
        .encode_request_header("127.0.0.1", port)
    }

    fn test_settings(mode: &str) -> XhttpSettings {
        let node = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"xhttpSettings": {{"path": "/up/", "mode": "{mode}"}}}}}}"#
        ))
        .expect("parses");
        XhttpSettings::from_json(node.get("streamSettings")).expect("settings")
    }

    fn serve_one(
        settings: XhttpSettings,
        id: [u8; 16],
        takes: usize,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let front = test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let handle = crate::budgets::spawn(move || {
            for stream in front.incoming().take(takes) {
                let Ok(stream) = stream else { continue };
                let Ok(read) = stream.try_clone() else {
                    continue;
                };
                let settings = settings.clone();
                crate::budgets::spawn(move || {
                    serve_h2(read, stream, &settings, &crate::proxy::one_user(id), true);
                });
            }
        });
        (addr, handle)
    }

    fn padding() -> String {
        format!("http://127.0.0.1/up/?x_padding={}", "X".repeat(128))
    }

    /// The in-place padded-DATA cut equals the borrow-checked reference at every pad length: a partially padded frame keeps exactly `body[1..len - pad]`, a pad that swallows the payload leaves the empty chunk `get(..).unwrap_or_default()` produced, and the length the caller replenishes by is the same in both.
    #[test]
    fn a_padded_data_cut_matches_the_reference_at_every_pad_length() {
        for len in 1..=8usize {
            let frame: Vec<u8> = (0..len as u8)
                .map(|b| b.wrapping_mul(37).wrapping_add(5))
                .collect();
            for pad in 0..=10usize {
                let mut mine = frame.clone();
                let cut = cut_padded_data(&mut mine, pad);
                let want = frame
                    .get(1..frame.len().saturating_sub(pad))
                    .unwrap_or_default()
                    .to_vec();
                assert_eq!(mine, want, "len {len} pad {pad}: cut bytes differ");
                assert_eq!(cut, want.len(), "len {len} pad {pad}: cut length differs");
            }
        }
    }

    /// The received frame is queued as itself. The DATA chunk and the unterminated header block keep the buffer the loop read the body into, so nothing copies between the frame and the queue: a `to_vec` on that path moves the base pointer and grows or shrinks the allocation, and the assertions carry both.
    /// The frame's body is not zeroed: the read fills every byte of it, so the zero pass
    /// in front of the read was work generated and thrown away, once a frame, over the
    /// whole frame's length. The counting allocator's `zeroed` counter is the witness.
    #[test]
    fn a_received_frames_body_is_not_zero_filled() {
        let mut bytes = crate::h2::MAGIC.to_vec();
        let body = vec![7u8; 4096];
        bytes.extend_from_slice(&crate::h2::frame_head(body.len(), T_DATA, 0, 1));
        bytes.extend_from_slice(&body);
        let reader = std::io::Cursor::new(bytes);
        let written = Arc::new(Mutex::new(Vec::new()));
        let slices = Arc::new(AtomicUsize::new(0));
        let writer = Counted { written, slices };
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            serve_h2(
                reader,
                writer,
                &XhttpSettings::stream_one(),
                &crate::proxy::one_user([0u8; 16]),
                true,
            );
        });
        assert_eq!(counts.zeroed, 0, "no frame body is zeroed");
    }

    #[test]
    fn a_received_frame_is_queued_as_the_buffer_the_loop_read_it_into() {
        let (conn, _, _) = bare_conn();
        let settings = XhttpSettings::stream_one();
        let mut frag: Option<(u32, Vec<u8>)> = None;

        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let body = vec![9u8; 5];
        let base = body.as_ptr();
        assert!(pump_frame(
            &conn,
            &settings,
            &crate::proxy::one_user([0u8; 16]),
            true,
            T_DATA,
            0,
            1,
            body,
            &mut frag
        ));
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            let queued = st.body.front().expect("queued");
            assert_eq!(queued.as_ptr(), base, "DATA queued the frame's own buffer");
            assert_eq!(
                queued.capacity(),
                5,
                "the queue did not grow or shrink the allocation"
            );
        }

        // Padded: the cut happens in place, so the payload's base is still the frame's base and the capacity still fits the whole frame.
        let frame = vec![2u8, b'a', b'b', b'c', b'd', b'e', b'f', 2, 2];
        let base = frame.as_ptr();
        assert!(pump_frame(
            &conn,
            &settings,
            &crate::proxy::one_user([0u8; 16]),
            true,
            T_DATA,
            F_PADDED,
            1,
            frame,
            &mut frag
        ));
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            let queued = st.body.back().expect("queued");
            assert_eq!(
                queued.as_ptr(),
                base,
                "padded DATA cut in the frame's buffer"
            );
            assert_eq!(
                queued.capacity(),
                9,
                "the padded payload kept the frame's allocation"
            );
            assert_eq!(queued.as_slice(), b"abcdef");
        }

        // A header block that does not end is stored owned in the assembly, not copied in front of it.
        let block = vec![0x88u8, 0x86, 0x40, 0x01, 0x02];
        let base = block.as_ptr();
        assert!(pump_frame(
            &conn,
            &settings,
            &crate::proxy::one_user([0u8; 16]),
            true,
            T_HEADERS,
            0,
            3,
            block,
            &mut frag
        ));
        let stored = frag.as_ref().expect("stored").1.as_ptr();
        assert_eq!(stored, base, "the header block is the assembly's buffer");
        drop(frag);
    }

    /// A short read leaves the frame's tail where the loop put it: the reader carries a cursor
    /// instead of draining its head, and the assertions read the address, which the drain moved.
    #[test]
    fn a_partly_read_frame_is_not_moved() {
        let (conn, _, _) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let frame: Vec<u8> = (0u8..64).collect();
        let base = frame.as_ptr();
        state
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .body
            .push_back(frame);
        let mut reader = H2StreamReader {
            conn,
            stream: Arc::clone(&state),
            id: 1,
            at: 0,
        };
        let mut first = [0u8; 16];
        assert_eq!(reader.read(&mut first).unwrap(), 16);
        assert!(first.iter().copied().eq(0u8..16), "the head of the frame");
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            let front = st.body.front().expect("still queued");
            assert_eq!(front.as_ptr(), base, "the frame is its own allocation");
            assert_eq!(front.len(), 64, "the frame was not shortened by the read");
            assert_eq!(front[16], 16, "the tail sits at its own offset");
        }
        let mut rest = [0u8; 48];
        assert_eq!(reader.read(&mut rest).unwrap(), 48);
        assert!(rest.iter().copied().eq(16u8..64), "the tail of the frame");
        assert!(
            state
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .body
                .is_empty(),
            "the spent frame is popped"
        );
    }

    /// The response head's fields come out of one list and one pass: a hop-by-hop name is
    /// recognised in place, where the lowercase form it replaces allocated a `String` per line,
    /// and the list is opened for the lines it will hold rather than grown into.
    #[test]
    fn a_response_head_is_split_without_allocating() {
        let head = "HTTP/1.1 200 OK\r\n\
                    Content-Length: 12\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Connection: close\r\n\
                    Keep-Alive: timeout=5\r\n\
                    Content-Lengths: 12\r\n\
                    Connectio: x\r\n\
                    Content-Type: text/plain\r\n\
                    Server: x\r\n\r\n";
        let (fields, counts) = ferrox_core::alloc_count::measure(|| response_fields(head));
        assert_eq!(
            counts.allocs, 1,
            "the field list, nothing per line: {counts:?}"
        );
        assert_eq!(
            fields,
            vec![
                (":status", "200"),
                ("Content-Lengths", "12"),
                ("Connectio", "x"),
                ("Content-Type", "text/plain"),
                ("Server", "x"),
            ],
            "the connection's own fields are skipped in any spelling, and a near miss is kept"
        );
        assert_eq!(
            block_encode(&fields),
            block_encode(&[
                (":status", "200"),
                ("Content-Lengths", "12"),
                ("Connectio", "x"),
                ("Content-Type", "text/plain"),
                ("Server", "x"),
            ]),
            "the block is the fields' own bytes"
        );
    }

    #[test]
    fn h2_stream_up_carries_bulk_both_ways() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers("GET", "/up/sess-h2-01", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(down), 200);
        let up = client.headers(
            "POST",
            "/up/sess-h2-01",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..32768u32).map(|i| (i % 251) as u8).collect();
        let mut body = header;
        body.extend_from_slice(&payload);
        client.data(up, &body, true);
        assert_eq!(client.response_head(up), 200);
        assert_eq!(client.response_data(down, 2), [0, 0]);
        assert_eq!(client.response_data(down, payload.len()), payload);
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A padded DATA frame is queued as exactly its payload: the pad-length byte and the pad tail are gone before the chunk reaches the session, so an echo over the padded uplink round-trips the payload untouched.
    #[test]
    fn a_padded_data_frame_is_its_payload_between_pad_byte_and_pad_tail() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers("GET", "/up/sess-h2-pad", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(down), 200);
        let up = client.headers(
            "POST",
            "/up/sess-h2-pad",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..50000u32).map(|i| (i % 251) as u8).collect();
        let mut body = header;
        body.extend_from_slice(&payload);
        client.padded_data(up, &body, 7, true);
        assert_eq!(client.response_head(up), 200);
        assert_eq!(client.response_data(down, 2), [0, 0]);
        assert_eq!(client.response_data(down, payload.len()), payload);
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A session that refuses the dial still owns the downlink stream its carrier opened: leaving that stream open parks the client's next read on a reply that can no longer arrive.
    #[test]
    fn a_refused_session_ends_the_stream_it_parked() {
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers(
            "GET",
            "/up/sess-h2-refused",
            &[("referer", pad.as_str())],
            true,
        );
        assert_eq!(client.response_head(down), 200);
        let up = client.headers(
            "POST",
            "/up/sess-h2-refused",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        // A uuid the served id does not carry, so the session refuses before it dials.
        let header = ferrox_core::vless::VlessLink::parse(
            "vless://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses")
        .encode_request_header("127.0.0.1", 9);
        client.data(up, &header, true);
        // The witness is the frame that lifts the park, so the clock bounds only the failure: 3 s of silence is a read that would never return.
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let (kind, flags, _, _) = client.next_frame(down, |kind| matches!(kind, T_DATA | T_RST));
        assert!(
            kind == T_RST || flags & F_END != 0,
            "the refused session left stream {down} open: frame {kind} flags {flags:#04x}"
        );
        drop(client);
        server.join().expect("joins");
    }

    /// A peer that opens a downlink and then dies without ever posting leaves the server's stream thread parked on a sequence that can no longer arrive — the connection, not that thread, owns the session, so its death has to end it and free the thread with it.
    #[test]
    fn a_dead_carrier_ends_the_session_it_parked() {
        let (addr, server) = serve_one(test_settings("stream-up"), [0xbbu8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers(
            "GET",
            "/up/sess-h2-dead",
            &[("referer", pad.as_str())],
            true,
        );
        assert_eq!(client.response_head(down), 200);
        assert!(
            crate::xhttp::session_is_carried("sess-h2-dead"),
            "the downlink holds its session while its carrier lives"
        );
        drop(client);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while crate::xhttp::session_is_carried("sess-h2-dead")
            && std::time::Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            !crate::xhttp::session_is_carried("sess-h2-dead"),
            "the carrier died and left its session parked: nothing will ever wake that thread"
        );
        server.join().expect("joins");
    }

    /// A peer that announces a frame larger than the default `SETTINGS_MAX_FRAME_SIZE` must be refused with `FRAME_SIZE_ERROR`, not have its length reserved and its phantom body awaited — the read is unbounded, so a parked oversized head would pin the thread.
    #[test]
    fn a_frame_beyond_the_max_size_is_refused_not_reserved_or_read() {
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let oversized = MAX_RECV_FRAME + 1;
        let mut head = [0u8; 9];
        head[0..3].copy_from_slice(&(oversized as u32).to_be_bytes()[1..]);
        head[3] = T_HEADERS;
        head[4] = F_END_HEADERS;
        head[5..9].copy_from_slice(&1u32.to_be_bytes());
        client.stream.write_all(&head).expect("head");
        client.stream.flush().expect("flushes");
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut got = [0u8; 9];
        assert!(
            fill(&mut client.stream, &mut got).is_some(),
            "the server neither answered nor refused the oversized frame"
        );
        assert_eq!(got[3], T_GOAWAY, "expected a GOAWAY");
        let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
        let mut body = crate::proxy::unfilled(len);
        assert!(fill(&mut client.stream, &mut body).is_some(), "goaway body");
        assert_eq!(
            u32::from_be_bytes(body[4..8].try_into().unwrap()),
            E_FRAME_SIZE,
            "the GOAWAY must carry FRAME_SIZE_ERROR"
        );
        drop(client);
        let _ = server;
    }

    /// Endless CONTINUATION frames for one stream must not grow a header block past `HEAD_CAP`: the reassembly is refused with a GOAWAY rather than accumulated without bound. Repeated because one round only sees the race on a busy machine — the refusal used to lose its GOAWAY to our own abortive close.
    #[test]
    fn a_header_block_reassembled_past_the_cap_refuses_the_connection() {
        for round in 0..24 {
            let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
            let mut client = H2Client::connect(addr);
            // Open a header block that never ends: HEADERS without END_HEADERS.
            write_frame(&mut client.stream, T_HEADERS, 0, 1, &[0x88]);
            // Feed CONTINUATION frames of one max-size payload each; a compliant endpoint refuses at HEAD_CAP, so none is ever answered by an opened stream.
            let chunk = [0u8; MAX_RECV_FRAME];
            for _ in 0..(HEAD_CAP / MAX_RECV_FRAME + 2) {
                write_frame(&mut client.stream, T_CONT, 0, 1, &chunk);
            }
            client.stream.flush().expect("flushes");
            client
                .stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut got = [0u8; 9];
            assert!(
                fill(&mut client.stream, &mut got).is_some(),
                "round {round}: the server neither opened the stream nor refused the over-long block"
            );
            assert_eq!(got[3], T_GOAWAY, "round {round}: expected a GOAWAY");
            let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
            let mut body = crate::proxy::unfilled(len);
            assert!(
                fill(&mut client.stream, &mut body).is_some(),
                "round {round}: goaway body"
            );
            assert_eq!(
                u32::from_be_bytes(body[4..8].try_into().unwrap()),
                E_PROTOCOL,
                "round {round}: the GOAWAY must carry PROTOCOL_ERROR"
            );
            drop(client);
            let _ = server;
        }
    }

    #[test]
    fn h2_packet_up_reassembles_out_of_order_posts() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("packet-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers("GET", "/up/sess-h2-02", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(down), 200);
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let one = client.headers(
            "POST",
            "/up/sess-h2-02/1",
            &[("referer", pad.as_str()), ("content-length", "4096")],
            false,
        );
        client.data(one, &payload[4096..], true);
        assert_eq!(client.response_head(one), 200);
        let mut body0 = header.clone();
        body0.extend_from_slice(&payload[..4096]);
        let zero = client.headers(
            "POST",
            "/up/sess-h2-02/0",
            &[
                ("referer", pad.as_str()),
                ("content-length", &body0.len().to_string()),
            ],
            false,
        );
        client.data(zero, &body0, true);
        assert_eq!(client.response_head(zero), 200);
        assert_eq!(client.response_data(down, 2), [0, 0]);
        assert_eq!(client.response_data(down, payload.len()), payload);
        drop(client);
        server.join().expect("joins");
        let _ = echo;
    }

    /// The scripted peer answers two streams at once and puts the other stream's frames in front of
    /// each reader, so a reader that throws away what it did not ask for returns the wrong bytes
    /// rather than only losing them when the scheduler lets two responses interleave.
    #[test]
    fn an_early_frame_waits_for_the_reader_that_asked_for_it() {
        let listener = test_bind("127.0.0.1:0").expect("binds a scripted peer");
        let addr = listener.local_addr().expect("addr");
        let scripted = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("the client connects");
            for _ in 0..3 {
                write_frame(&mut peer, T_SETTINGS, 0, 0, &[]);
            }
            let ok = block_encode(&[(":status", "200")]);
            let late = block_encode(&[(":status", "500")]);
            write_frame(&mut peer, T_HEADERS, F_END_HEADERS, 3, &ok);
            write_frame(&mut peer, T_HEADERS, F_END_HEADERS, 1, &ok);
            write_frame(&mut peer, T_DATA, 0, 3, b"held-first-");
            write_frame(&mut peer, T_DATA, 0, 1, b"head-then-tail");
            write_frame(&mut peer, T_DATA, 0, 1, b"-continued");
            write_frame(&mut peer, T_DATA, 0, 3, b"late-second!");
            write_frame(&mut peer, T_HEADERS, F_END_HEADERS, 3, &late);
            peer.flush().expect("flushes");
            let mut drain = [0u8; 64];
            while peer.read(&mut drain).is_ok_and(|n| n > 0) {}
        });
        let mut client = H2Client::connect(addr);
        assert_eq!(client.response_head(1), 200);
        assert_eq!(client.response_data(1, 4), b"head");
        assert_eq!(
            client.response_data(1, 10),
            b"-then-tail",
            "a frame longer than the read asked for has to keep its remainder"
        );
        assert_eq!(client.response_data(1, 10), b"-continued");
        assert_eq!(
            client.response_data(3, 11),
            b"held-first-",
            "another stream's reader must not spend the bytes this one is waiting for"
        );
        assert_eq!(
            client.response_head(3),
            200,
            "a status read while waiting on another stream is not noise to drop"
        );
        drop(client);
        scripted.join().expect("the peer ends");
    }

    #[test]
    fn h2_stream_one_carries_a_duplex_echo() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-one"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let only = client.headers(
            "POST",
            "/up/",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let mut body = vless_header(echo_addr.port());
        body.extend_from_slice(b"ping");
        client.data(only, &body, true);
        assert_eq!(client.response_head(only), 200);
        assert_eq!(client.response_data(only, 2), [0, 0]);
        assert_eq!(client.response_data(only, 4), b"ping");
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A bulk duplex echo whose response outruns the initial connection window: the server must not send DATA past the `65_535` it was granted when the client never sends a `WINDOW_UPDATE`. Crediting the server's own send window for the bytes it consumed on the way in (the bug) lets the echo outrun that grant, which a strict peer answers with a flow-control reset — the `early eof` and `Connection reset by peer` the upstream suites report.
    #[test]
    fn h2_bulk_echo_never_outruns_the_granted_connection_window() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-one"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let only = client.headers(
            "POST",
            "/up/",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let mut body = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..131_072u32).map(|i| (i % 251) as u8).collect();
        body.extend_from_slice(&payload);
        client.data(only, &body, true);
        assert_eq!(client.response_head(only), 200);
        assert!(
            !client.outruns_the_granted_window(only, 65_535),
            "server sent DATA beyond the window it was granted"
        );
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A downlink that finishes ends its session: the packet-up upload's `wait_ended` is parked on that session, not on the stream.
    #[test]
    fn a_finished_downlink_ends_its_session() {
        let sid = "h2-downlink-finish";
        crate::xhttp::start_session_for_probe(sid);
        assert!(
            crate::xhttp::session_is_carried(sid),
            "the session starts carried"
        );
        let (conn, _written, _slices) = bare_conn();
        let out = H2StreamOut {
            conn,
            stream: 1,
            owner: None,
        };
        out.bind_session(sid);
        out.end();
        assert!(
            !crate::xhttp::session_is_carried(sid),
            "the finished downlink leaves no session parked"
        );
    }

    /// An ended session wakes the upload it was relaying: a stream-up POST parked in `H2StreamReader::read` must not hold its worker until the connection dies.
    #[test]
    fn an_ended_session_wakes_its_upload_reader() {
        let sid = "h2-ended-upload";
        crate::xhttp::start_session_for_probe(sid);
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .expect("streams")
            .insert(2, Arc::clone(&state));
        let downlink = H2StreamOut {
            conn: Arc::clone(&conn),
            stream: 1,
            owner: None,
        };
        downlink.bind_session(sid);
        let upload = H2StreamOut {
            conn: Arc::clone(&conn),
            stream: 2,
            owner: None,
        };
        upload.bind_upload(sid);
        let mut reader = H2StreamReader {
            conn,
            stream: state,
            id: 2,
            at: 0,
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = sender.send(reader.read(&mut byte).map_err(|error| error.kind()));
        });
        downlink.end();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)),
            Ok(Ok(0)),
            "the ended session ends its parked upload"
        );
    }

    #[test]
    fn h2_refusals_carry_their_statuses() {
        let (addr, server) = serve_one(test_settings("packet-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let wrong = client.headers("GET", "/elsewhere", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(wrong), 404);
        let bare = client.headers("POST", "/up/nopad", &[], true);
        assert_eq!(client.response_head(bare), 400);
        let bad_seq = client.headers("POST", "/up/abc/xyz", &[("referer", pad.as_str())], true);
        client.data(bad_seq, b"junk", true);
        assert_eq!(client.response_head(bad_seq), 500);
        drop(client);
        server.join().expect("joins");
    }

    /// The writer a credit is read by: it answers with the bytes it was handed, so the number of writes it took is exact — over a loopback socket the same shape moves with the scheduler.
    struct Counted {
        written: Arc<Mutex<Vec<u8>>>,
        slices: Arc<AtomicUsize>,
    }

    impl Write for Counted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Counted {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            self.slices.fetch_add(1, Ordering::SeqCst);
            parts.iter().all(|part| self.write_all(part).is_ok())
        }
    }

    /// A connection with no streams and no peer: only what a call writes can be seen.
    fn bare_conn() -> (Arc<H2Conn>, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let slices = Arc::new(AtomicUsize::new(0));
        let conn = Arc::new(H2Conn {
            write: Mutex::new(Box::new(Counted {
                written: Arc::clone(&written),
                slices: Arc::clone(&slices),
            })),
            streams: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashSet::new()),
            session_of: Mutex::new(HashMap::new()),
            upload_of: Mutex::new(HashMap::new()),
            send_conn: Mutex::new(65_535),
            wake: Condvar::new(),
            decoder: Mutex::new(Decoder::default()),
            max_frame: Mutex::new(16_384),
            peer_initial: Mutex::new(65_535),
            dead: AtomicBool::new(false),
            goaway: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            client_read: None,
            raw: None,
        });
        (conn, written, slices)
    }

    /// One credit is both `WINDOW_UPDATE`s: the pair differs only by stream id, so it goes out as one 26-byte write under one lock, where two `frame()` calls were two locks and two records on the wire for the same bytes.
    #[test]
    fn a_credit_grants_both_windows_in_one_write() {
        let (conn, written, slices) = bare_conn();
        let increment = 0x1234_5678u32;
        conn.replenish(7, 0);
        conn.replenish(7, usize::MAX);
        assert_eq!(
            slices.load(Ordering::SeqCst),
            0,
            "a credit of nothing, or of more than a frame can say, writes nothing"
        );
        conn.replenish(7, increment as usize);
        assert_eq!(
            slices.load(Ordering::SeqCst),
            1,
            "one credit, one write, whatever the pair costs the old shape"
        );
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes.len(), 26, "the pair is 26 bytes and nothing else");
        let mut at = 0usize;
        for id in [0, 7] {
            let (len, kind, flags, sid) = read_head(&mut &bytes[at..at + 9]).expect("head");
            assert_eq!(
                (len, kind, flags, sid),
                (4, T_WINDOW, 0, id),
                "the frame at {at} is the credit for stream {id}"
            );
            assert_eq!(
                bytes[at + 9..at + 13],
                increment.to_be_bytes(),
                "both windows rise by the bytes consumed"
            );
            at += 13;
        }
    }

    /// A connection with one stream and all the credit it needs: the frame writer is the only
    /// observer of how many calls a downlink window costs.
    fn streaming_conn(total: usize) -> (Arc<H2Conn>, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
        let (conn, written, slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(total as u64),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        *conn
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = total as u64;
        (conn, written, slices)
    }

    /// The frames the pre-batch loop sent one call at a time, kept as the oracle.
    fn one_call_per_frame(
        payload: &[u8],
        max: usize,
        mut conn: usize,
        mut stream: usize,
    ) -> Vec<u8> {
        let mut wire = Vec::new();
        let mut left = payload;
        while !left.is_empty() {
            let take = left.len().min(max).min(conn).min(stream);
            let (head, body) = (&left[..take], &left[..take]);
            wire.extend_from_slice(&frame_head(body.len(), T_DATA, 0, 1));
            wire.extend_from_slice(head);
            conn -= take;
            stream -= take;
            left = &left[take..];
        }
        wire
    }

    /// A promoted relay window is four DATA frames of the default frame size and one write, where
    /// the per-frame shape paid four; both shapes put the same bytes in the same order.
    #[test]
    fn a_data_window_leaves_as_one_write() {
        let payload: Vec<u8> = (0..4 * 16_384u32).map(|i| (i % 251) as u8).collect();
        let (conn, written, slices) = streaming_conn(payload.len());
        assert!(conn.send_data(1, &payload), "the whole window is sent");
        assert_eq!(
            slices.load(Ordering::SeqCst),
            1,
            "one window, one write, whatever the four frames cost the old shape"
        );
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            *bytes,
            one_call_per_frame(&payload, 16_384, payload.len(), payload.len()),
            "the batch is the frames the per-frame loop wrote, byte for byte"
        );
    }

    /// A frame the window cuts short is still its own frame: batching only the writes never
    /// widens a frame past the credit that admitted it.
    #[test]
    fn a_data_batch_writes_the_frames_the_old_loop_did() {
        for len in [1, 16_383, 16_384, 16_385, 20_000, 65_535, 65_536] {
            let payload: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
            let (conn, written, slices) = streaming_conn(len);
            assert!(conn.send_data(1, &payload), "the window is sent");
            let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(
                *bytes,
                one_call_per_frame(&payload, 16_384, len, len),
                "the frames of a {len}-byte window are the old loop's frames"
            );
            let frames = len.div_ceil(16_384);
            assert!(slices.load(Ordering::SeqCst) <= frames);
        }
    }

    /// A sender the peer never credits gives up at the relay stall, so a downlink cannot park its thread on a window that never arrives.
    #[test]
    fn a_sender_with_no_credit_gives_up_at_the_stall() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(500)),
            ..Default::default()
        });
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(0),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, state);
        *conn
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = 0;
        let (sent, got) = std::sync::mpsc::channel();
        let sender = Arc::clone(&conn);
        let running = crate::budgets::spawn(move || {
            let _ = sent.send(sender.send_data(1, b"ping"));
        });
        let verdict = got.recv_timeout(Duration::from_secs(3));
        conn.dead.store(true, Ordering::SeqCst);
        conn.wake.notify_all();
        running.join().expect("sender thread");
        crate::budgets::clear();
        assert_eq!(verdict, Ok(false), "a sender with no credit returned");
    }

    /// A request that ended its own body still has a response to send: waiting for credit must not
    /// read the inbound `END_STREAM` as a dead stream and drop the downlink.
    #[test]
    fn an_ended_request_still_sends_its_response() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: true,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(0),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let held = state
            .send_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let sender = Arc::clone(&conn);
        let running = crate::budgets::spawn(move || sender.send_data(1, b"ping"));
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while conn.send_conn.try_lock().is_ok() {
            assert!(
                std::time::Instant::now() < until,
                "the sender never took the connection window"
            );
            thread::yield_now();
        }
        drop(held);
        {
            let mut conn_window = conn
                .send_conn
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let mut stream_window = state
                .send_window
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *conn_window += 4;
            *stream_window += 4;
        }
        conn.wake.notify_all();
        assert!(
            running.join().expect("sender thread"),
            "the ended request's response is still sent"
        );
        crate::budgets::clear();
    }

    /// A reset stream has no window left to grant, so its writer must be woken by the reset, not
    /// left to discover the stream is gone when the relay stall expires.
    #[test]
    fn a_reset_stream_wakes_a_sender_waiting_on_its_window() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(0),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        *conn
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = 0;
        let held = state
            .send_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (sent, got) = std::sync::mpsc::channel();
        let sender = Arc::clone(&conn);
        let running = crate::budgets::spawn(move || {
            let _ = sent.send(sender.send_data(1, b"ping"));
        });
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while conn.send_conn.try_lock().is_ok() {
            assert!(
                std::time::Instant::now() < until,
                "the sender never took the connection window"
            );
            thread::yield_now();
        }
        drop(held);
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while conn.send_conn.try_lock().is_err() {
            assert!(
                std::time::Instant::now() < until,
                "the sender never parked on its stream window"
            );
            thread::yield_now();
        }
        let began = std::time::Instant::now();
        conn.reset_stream(1);
        let verdict = got.recv_timeout(Duration::from_secs(2));
        let took = began.elapsed();
        conn.dead.store(true, Ordering::SeqCst);
        conn.wake.notify_all();
        running.join().expect("sender thread");
        crate::budgets::clear();
        assert_eq!(verdict, Ok(false), "the reset sender returned");
        assert!(
            took < Duration::from_secs(1),
            "the reset stream kept its writer parked for {took:?}"
        );
    }

    /// A POST that never sends its body leaves the stream's reader parked on a request no peer will finish; the relay stall ends it, and the stream is reset instead of holding its thread for the life of the connection.
    #[test]
    fn a_post_with_no_body_ends_at_the_stall() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(200)),
            ..Default::default()
        });
        let (addr, server) = serve_one(test_settings("stream-one"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let id = client.headers("POST", "/up/", &[("referer", padding().as_str())], false);
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        assert_eq!(client.response_head(id), 200, "the request is accepted");
        let (kind, flags, _, _) = client.next_frame(id, |kind| matches!(kind, T_DATA | T_RST));
        crate::budgets::clear();
        assert!(
            kind == T_DATA && flags & F_END != 0,
            "a body that never arrives must end the stream at the stall, got kind {kind} flags {flags}"
        );
        drop(client);
        server.join().expect("joins");
    }

    /// The last bytes the connection wrote are one credit for `sid` of `inc`: the pair of
    /// four-octet `WINDOW_UPDATE` frames, connection-level then stream-level, both saying `inc`.
    fn expect_one_credit(
        written: &Arc<Mutex<Vec<u8>>>,
        slices: &Arc<AtomicUsize>,
        sid: u32,
        inc: u32,
    ) {
        assert_eq!(
            slices.load(Ordering::SeqCst),
            1,
            "one credit, one write for stream {sid}"
        );
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes.len(), 26, "the credit is the pair and nothing else");
        let mut at = 0usize;
        for id in [0, sid] {
            let (len, kind, flags, got) = read_head(&mut &bytes[at..at + 9]).expect("head");
            assert_eq!(
                (len, kind, flags, got),
                (4, T_WINDOW, 0, id),
                "the frame at {at} is the credit for stream {id}"
            );
            assert_eq!(
                bytes[at + 9..at + 13],
                inc.to_be_bytes(),
                "both windows rise by the frame's wire length"
            );
            at += 13;
        }
    }

    /// A DATA frame's credit is what the frame cost the peer's window — the whole wire payload, Pad Length octet and Padding counted (RFC 7540 6.9, where the reference takes `f.Length`) — so both `WINDOW_UPDATE` halves carry `1 + payload + pad`. Crediting the post-cut payload under-credits every padded frame by `1 + pad`; crediting a swallowed payload nothing starves the peer outright.
    #[test]
    fn a_padded_data_credit_counts_the_whole_wire_payload() {
        let (conn, written, slices) = bare_conn();
        let settings = XhttpSettings::stream_one();
        let mut frag: Option<(u32, Vec<u8>)> = None;
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));

        // A live stream: pad byte 2, payload 6, pad tail 2 — nine octets on the wire, six into the queue.
        assert!(pump_frame(
            &conn,
            &settings,
            &crate::proxy::one_user([0u8; 16]),
            true,
            T_DATA,
            F_PADDED,
            1,
            vec![2u8, b'a', b'b', b'c', b'd', b'e', b'f', 2, 2],
            &mut frag
        ));
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(
                st.body.front().expect("queued").as_slice(),
                b"abcdef",
                "the queued chunk is still the cut payload"
            );
        }
        expect_one_credit(&written, &slices, 1, 9);

        // A pad that swallows the payload: the cut returns nothing, the frame still cost the peer its wire length.
        written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        slices.store(0, Ordering::SeqCst);
        assert!(pump_frame(
            &conn,
            &settings,
            &crate::proxy::one_user([0u8; 16]),
            true,
            T_DATA,
            F_PADDED,
            1,
            vec![200u8, b'x'],
            &mut frag
        ));
        expect_one_credit(&written, &slices, 1, 2);

        // DATA for a stream that is not there is credited at the wire length on its way out, too.
        written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        slices.store(0, Ordering::SeqCst);
        assert!(pump_frame(
            &conn,
            &settings,
            &crate::proxy::one_user([0u8; 16]),
            true,
            T_DATA,
            F_PADDED,
            9,
            vec![3u8, b'p', 3, 3, 3],
            &mut frag
        ));
        expect_one_credit(&written, &slices, 9, 5);

        // Unpadded: the payload is the wire, and that arm does not move.
        written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        slices.store(0, Ordering::SeqCst);
        assert!(pump_frame(
            &conn,
            &settings,
            &crate::proxy::one_user([0u8; 16]),
            true,
            T_DATA,
            0,
            1,
            vec![7u8; 5],
            &mut frag
        ));
        expect_one_credit(&written, &slices, 1, 5);
    }

    #[test]
    fn the_synthesized_head_is_sized_for_its_bytes() {
        for end_stream in [true, false] {
            let head = synth_head(b"GET", b"/path", b"host: x\r\n", end_stream);
            assert_eq!(head.capacity(), head.len(), "one allocation, no growth");
            assert!(head.starts_with(b"GET /path HTTP/2\r\nhost: x\r\n"));
            assert_eq!(
                head.ends_with(b"Transfer-Encoding: chunked\r\n\r\n"),
                !end_stream,
                "only a stream still open is declared chunked"
            );
        }
    }
}
