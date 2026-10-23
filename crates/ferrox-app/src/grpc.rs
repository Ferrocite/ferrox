use crate::conn::Connection;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::h2::{
    block_encode, frame_head, read_head, write_frame, Decoder, E_REFUSED, FRAME_CAP, F_ACK, F_END,
    F_END_HEADERS, F_PADDED, F_PRIORITY, HEAD_CAP, MAGIC, S_MAX_CONCURRENT, S_MAX_FRAME, S_WINDOW,
    T_CONT, T_DATA, T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS, T_WINDOW, WINDOW, WINDOW_MAX,
};

const MSG_CAP: usize = 16 * 1024 * 1024;
const HUNK: usize = 16 * 1024;

/// The bodies one credit pays for, half the window the preface advertises: a peer that has sent this much is owed a credit, and one that has not still has the other half to send into, so no grant is ever the thing a stalled writer waits for.
const CREDIT_AT: u32 = WINDOW / 2;

/// The two `WINDOW_UPDATE` frames a credit grants differ only by stream id, so their eighteen header bytes are constant and each call fills the two increment slots left zero here: the pair leaves in one write.
const CREDIT_PAIR: [u8; 26] = {
    let mut out = [0u8; 26];
    out[2] = 4;
    out[3] = T_WINDOW;
    out[15] = 4;
    out[16] = T_WINDOW;
    out
};

/// What this lane advertises before any body arrives: the stream window is the setting, and the connection window is the RFC's `65_535` plus this top-up, so both equal `WINDOW` and a peer can send a whole window before it needs a credit.
const PREFACE: [u8; 34] = {
    let mut out = [0u8; 34];
    out[2] = 12;
    out[3] = T_SETTINGS;
    let window_setting = S_WINDOW.to_be_bytes();
    out[9] = window_setting[0];
    out[10] = window_setting[1];
    let window = WINDOW.to_be_bytes();
    out[11] = window[0];
    out[12] = window[1];
    out[13] = window[2];
    out[14] = window[3];
    let concurrent = S_MAX_CONCURRENT.to_be_bytes();
    out[15] = concurrent[0];
    out[16] = concurrent[1];
    out[20] = 1;
    out[23] = 4;
    out[24] = T_WINDOW;
    let top_up = (WINDOW - 65_535).to_be_bytes();
    out[30] = top_up[0];
    out[31] = top_up[1];
    out[32] = top_up[2];
    out[33] = top_up[3];
    out
};

#[derive(Debug, Default)]
struct SendWindow {
    conn: u64,
    stream: u64,
}

struct Shared {
    stream: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    send: Mutex<SendWindow>,
    wake: Condvar,
    max_frame: Mutex<usize>,
    init: Mutex<u64>,
    ended: AtomicBool,
    dead: AtomicBool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("send", &self.send)
            .field("max_frame", &self.max_frame)
            .field("init", &self.init)
            .field("ended", &self.ended)
            .field("dead", &self.dead)
            .finish_non_exhaustive()
    }
}

/// Take `need` from both windows, waiting for the peer's credit only when `wait` says to: a gathered
/// batch flushes before it parks, since a peer grants for bytes it has seen and not for ones still
/// sitting in the batch.
fn take_window(shared: &Shared, need: u64, wait: bool) -> bool {
    let mut send = shared.send.lock().unwrap_or_else(PoisonError::into_inner);
    if wait {
        while send.conn < need || send.stream < need {
            if shared.dead.load(Ordering::SeqCst) {
                return false;
            }
            let (guard, waited) = shared
                .wake
                .wait_timeout(send, crate::budgets::relay_stall())
                .unwrap_or_else(PoisonError::into_inner);
            send = guard;
            if waited.timed_out() {
                return false;
            }
        }
    } else if send.conn < need || send.stream < need {
        return false;
    }
    send.conn -= need;
    send.stream -= need;
    true
}

/// Which of the service's two methods a call used, and so what shape its messages have.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Method {
    /// `rpc Tun`: one `Hunk` per message, one payload in each.
    Hunk,
    /// `rpc TunMulti`: one `MultiHunk` per message, a batch of elements in each.
    MultiHunk,
}

/// What a header block answers, read while it decodes: each name the gates use is judged at its first field, so a head costs no allocation and no buffer outlives the block.
#[derive(Debug, Default)]
struct Gate {
    /// The first `:status` was `200`; `None` when the block carries no status at all.
    status: Option<bool>,
    /// The first `:path` names one of the two served methods.
    served: Option<bool>,
    /// and which of them, so the reply is read as a `MultiHunk` rather than silently truncated to the last element of every message.
    multi: Option<bool>,
    /// The first `:method` was `POST`.
    posted: Option<bool>,
    /// The first `content-type` is a gRPC one.
    typed: Option<bool>,
}

impl Gate {
    fn take(&mut self, name: &[u8], value: &[u8], path: &str, multi_path: &str) {
        if self.status.is_none() && name.eq_ignore_ascii_case(b":status") {
            self.status = Some(value == b"200");
        } else if self.served.is_none() && name.eq_ignore_ascii_case(b":path") {
            self.multi = Some(value == multi_path.as_bytes());
            self.served = Some(self.multi == Some(true) || value == path.as_bytes());
        } else if self.posted.is_none() && name.eq_ignore_ascii_case(b":method") {
            self.posted = Some(value == b"POST");
        } else if self.typed.is_none() && name.eq_ignore_ascii_case(b"content-type") {
            self.typed = Some(value.starts_with(b"application/grpc"));
        }
    }
}

#[derive(Debug)]
pub(crate) struct GrpcReader<R: Read = Connection> {
    read: R,
    shared: Arc<Shared>,
    decoder: Decoder,
    stream: u32,
    server: bool,
    path: String,
    /// The same call with the multi-mode stream name: one listener serves both methods, the way Xray's hub registers `Tun` and `TunMulti` from one config.
    multi_path: String,
    /// The method this call used, read off its `:path`, because the two shapes cannot share a decoder.
    method: Method,
    answered: bool,
    head: Vec<u8>,
    head_id: u32,
    /// The one buffer a body uses: DATA frames are read onto its end and decoded there.
    msg: Vec<u8>,
    msg_at: usize,
    /// One past the last byte of the last decoded message, so fields this lane does not read are skipped where they lie.
    msg_end: usize,
    /// One past the payload the caller has not taken yet, from `msg_at`.
    pay_end: usize,
    /// Bytes the reader moved for itself — the reclaim move and the part of a message a pad byte cuts into: these and nothing else are what the staging gate counts.
    #[cfg_attr(not(test), allow(dead_code, reason = "read by the staging gate"))]
    staged: usize,
    /// The reclaim moves that copied live bytes: a drained buffer cleared rather than moved is a call fewer here, which the byte counter cannot see.
    #[cfg_attr(not(test), allow(dead_code, reason = "read by the reclaim gate"))]
    reclaims: usize,
    /// Scratch for the frames that are not a body: headers, settings, ping.
    frame: Vec<u8>,
    /// Bodies read since the last credit, and the stream they belong to: a credit pays for a window's worth of frames, not for one.
    owed: u32,
    owed_id: u32,
    /// The clock this head must be decoded by, armed only while the preface, the request headers and the opening request arrive: past it a silence is an error rather than a wait, so a peer that stops speaking releases the thread.
    handshake: Option<std::time::Instant>,
    eof: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct GrpcWriter {
    shared: Arc<Shared>,
    stream: u32,
}

impl GrpcReader<Connection> {
    /// Arm or clear the poll quantum on the socket this reader reads through, so a peer that opens then stalls mid-header cannot pin the serve thread past the header read; as the `ws`, `httpupgrade` and `httpheader` readers do, and a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R: Read> GrpcReader<R> {
    /// Arm or clear the clock the opening head is decoded under; only that head runs armed, a relay waits blocking again, as the `ws` reader's budget does.
    pub(crate) fn set_handshake_budget(&mut self, until: Option<std::time::Instant>) {
        self.handshake = until;
    }

    fn emit(&self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut **stream, kind, flags, id, body)
    }

    fn settings(&self, flags: u8, body: &[u8]) {
        if flags & F_ACK != 0 {
            return;
        }
        let mut at = 0;
        while at + 6 <= body.len() {
            let id = u16::from_be_bytes([body[at], body[at + 1]]);
            let value =
                u32::from_be_bytes([body[at + 2], body[at + 3], body[at + 4], body[at + 5]]);
            if id == S_WINDOW {
                let mut init = self
                    .shared
                    .init
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let mut send = self
                    .shared
                    .send
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                send.stream = send
                    .stream
                    .saturating_add(u64::from(value))
                    .saturating_sub(*init);
                send.stream = send.stream.min(WINDOW_MAX);
                *init = u64::from(value);
                self.shared.wake.notify_all();
            } else if id == S_MAX_FRAME {
                let mut max = self
                    .shared
                    .max_frame
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *max = usize::try_from(value).unwrap_or(FRAME_CAP).min(FRAME_CAP);
            }
            at += 6;
        }
        self.emit(T_SETTINGS, F_ACK, 0, &[]);
    }

    fn ping(&self, flags: u8, body: &[u8]) {
        if flags & F_ACK == 0 && body.len() == 8 {
            self.emit(T_PING, F_ACK, 0, body);
        }
    }

    /// The window this lane grants back as it reads: a body adds to what is owed and nothing leaves the socket, until a credit's worth has landed and one write pays for all of it.
    fn replenish(&mut self, id: u32, len: usize) {
        if self.owed > 0 && id != self.owed_id {
            self.grant();
        }
        self.owed_id = id;
        self.owed += len as u32;
        if self.owed >= CREDIT_AT {
            self.grant();
        }
    }

    /// The connection update and the stream update are the two halves of a constant pair, and the increment is the window they both owe: one credit, one write, one lock.
    fn grant(&mut self) {
        let owed = std::mem::take(&mut self.owed);
        if owed == 0 {
            return;
        }
        let inc = owed.to_be_bytes();
        let mut pair = CREDIT_PAIR;
        pair[9..13].copy_from_slice(&inc);
        let out: &[u8] = if self.owed_id == 0 {
            &pair[..13]
        } else {
            pair[18..22].copy_from_slice(&self.owed_id.to_be_bytes());
            pair[22..26].copy_from_slice(&inc);
            &pair
        };
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        stream.write_slices(&[out]);
    }

    fn refuse(&self, id: u32) {
        self.emit(T_RST, 0, id, &E_REFUSED.to_be_bytes());
    }

    fn headers(&mut self, id: u32, flags: u8, block: &[u8]) -> Option<()> {
        let (path, multi_path) = (&self.path[..], &self.multi_path[..]);
        let mut gate = Gate::default();
        self.decoder.decode(block, &mut |name, value| {
            gate.take(name, value, path, multi_path);
        })?;
        if self.server {
            return self.serve_headers(id, flags, &gate);
        }
        if id != self.stream {
            return Some(());
        }
        if !self.answered {
            if gate.status != Some(true) {
                return None;
            }
            self.answered = true;
        }
        if flags & F_END != 0 {
            self.eof = true;
        }
        Some(())
    }

    fn serve_headers(&mut self, id: u32, flags: u8, gate: &Gate) -> Option<()> {
        if self.answered {
            if flags & F_END != 0 {
                self.eof = true;
            }
            return Some(());
        }
        if gate.served != Some(true) || gate.posted != Some(true) || gate.typed != Some(true) {
            self.refuse(id);
            return None;
        }
        self.method = if gate.multi == Some(true) {
            Method::MultiHunk
        } else {
            Method::Hunk
        };
        let block = block_encode(&[
            (":status", "200"),
            ("content-type", "application/grpc"),
            ("grpc-encoding", "identity"),
        ]);
        if !self.emit(T_HEADERS, F_END_HEADERS, id, &block) {
            return None;
        }
        self.stream = id;
        self.answered = true;
        if flags & F_END != 0 {
            self.eof = true;
        }
        Some(())
    }

    /// A DATA body lands at the end of the buffer the decoder reads and the caller takes from, so a payload moves twice at most: out of the socket, and into the caller; `staged` counts every other move.
    fn data(&mut self, id: u32, flags: u8, len: usize) -> Option<()> {
        // A fully drained buffer has nothing live to keep, so the reclaim is a clear, not a move of an empty run.
        if self.msg_at == self.msg.len() {
            self.msg.clear();
            self.msg_at = 0;
            self.msg_end = 0;
            self.pay_end = 0;
        } else if self.msg_at * 2 >= self.msg.len() {
            // The bytes the caller already had go first, and only when they outweigh what is still live: a move that costs more than it frees is a copy.
            let at = self.msg_at;
            self.staged += self.msg.len() - at;
            self.reclaims += 1;
            self.msg.copy_within(at.., 0);
            self.msg.truncate(self.msg.len() - at);
            self.msg_at = 0;
            self.msg_end = self.msg_end.saturating_sub(at);
            self.pay_end = self.pay_end.saturating_sub(at);
        }
        let from = self.msg.len();
        self.append(len)?;
        if id != self.stream || !self.answered {
            self.msg.truncate(from);
            return Some(());
        }
        let (first, pad) = if flags & F_PADDED != 0 {
            let Some(&one) = self.msg.get(from) else {
                self.msg.truncate(from);
                return None;
            };
            let pad = usize::from(one);
            if pad + 1 > len {
                self.msg.truncate(from);
                return None;
            }
            (1usize, pad)
        } else {
            (0usize, 0usize)
        };
        // RFC 7540 6.9: the whole DATA payload is subject to flow control, so the credit is the wire length and not what the cut left.
        self.replenish(id, len);
        if first != 0 || pad != 0 {
            // A pad byte and pad tail sit inside the body the parser reads: when they open a message region a cursor step skips the byte and the frame's length drops the tail, and only a message that already crossed into this frame moves.
            if self.msg_at == from && self.pay_end == from && self.msg_end == from {
                self.msg.truncate(from + len - pad);
                self.msg_at = from + first;
                self.msg_end = from + first;
                self.pay_end = from + first;
            } else {
                self.staged += len - first - pad;
                let end = from + len - pad;
                self.msg.copy_within(from + first..end, from);
                self.msg.truncate(end - first);
            }
        }
        let out = self.decode();
        if flags & F_END != 0 {
            if !self.whole() {
                return None;
            }
            self.eof = true;
        }
        out
    }

    /// Reads `len` bytes onto the end of the message buffer without parking them somewhere else on the way.
    #[allow(
        clippy::uninit_vec,
        reason = "the tail is handed straight to `read_exact`, and the error path truncates it"
    )]
    fn append(&mut self, len: usize) -> Option<()> {
        let from = self.msg.len();
        self.msg.reserve(len);
        // SAFETY: `read_exact` initialises every byte it reports, and the path that does not fill them truncates them away, so no uninitialised byte is ever readable through `msg`.
        unsafe { self.msg.set_len(from + len) };
        if fill(&mut self.read, &mut self.msg[from..], self.handshake).is_err() {
            self.msg.truncate(from);
            return None;
        }
        Some(())
    }

    /// True when every byte past the last decoded message belongs to a whole message: `END_STREAM` over a partial head or a short body is a refusal, not a delivery of a truncated payload.
    fn whole(&self) -> bool {
        let mut at = self.msg_end;
        loop {
            let live = &self.msg[at..];
            if live.len() < 5 {
                return live.is_empty();
            }
            if live[0] != 0 {
                return false;
            }
            let len = u32::from_be_bytes(live[1..5].try_into().unwrap()) as usize;
            if len > MSG_CAP || live.len() < 5 + len {
                return false;
            }
            if hunk_decode(&live[5..5 + len]).is_none() {
                return false;
            }
            at += 5 + len;
        }
    }

    /// Messages are decoded where they landed: the payload stays in `msg` and `msg_at`..`pay_end` is what the caller has not taken, so nothing is copied to wait for it.
    fn decode(&mut self) -> Option<()> {
        loop {
            if self.msg_at < self.pay_end {
                return Some(());
            }
            if self.msg_at < self.msg_end {
                if self.method == Method::MultiHunk {
                    self.next_element()?;
                    continue;
                }
                self.msg_at = self.msg_end;
            }
            let live = &self.msg[self.msg_at..];
            if live.len() < 5 {
                return Some(());
            }
            if live[0] != 0 {
                return None;
            }
            let len = u32::from_be_bytes(live[1..5].try_into().unwrap()) as usize;
            if len > MSG_CAP {
                return None;
            }
            if live.len() < 5 + len {
                return Some(());
            }
            let body = self.msg_at + 5;
            self.msg_end = body + len;
            if self.method == Method::MultiHunk {
                self.msg_at = body;
                self.next_element()?;
                continue;
            }
            let (at, payload) = hunk_decode(&live[5..5 + len])?;
            self.msg_at = body + at;
            self.pay_end = self.msg_at + payload.len();
        }
    }

    /// The next element of the `MultiHunk` the cursor sits in: `repeated bytes` means an element's own bytes end exactly where the next element's key begins, so a batch is handed out where it lies and the cursor only leaves the message when it has no element left.
    fn next_element(&mut self) -> Option<()> {
        let end = self.msg_end;
        let mut at = self.msg_at;
        loop {
            if at >= end {
                self.msg_at = end;
                return Some(());
            }
            let key = read_varint(&self.msg, &mut at)?;
            let field = (key >> 3) as u32;
            let wire = (key & 0x07) as u8;
            if field == 0 {
                return None;
            }
            if field != 1 || wire != 2 {
                skip_field(&self.msg, &mut at, wire)?;
                continue;
            }
            let len = usize::try_from(read_varint(&self.msg, &mut at)?).ok()?;
            let start = at;
            let stop = start.checked_add(len)?;
            if stop > end {
                return None;
            }
            self.msg_at = start;
            self.pay_end = stop;
            return Some(());
        }
    }

    fn pump(&mut self) -> Option<()> {
        let head = match self.handshake {
            Some(until) => read_head(&mut crate::proxy::HandshakeDeadline {
                inner: &mut self.read,
                until,
            }),
            None => read_head(&mut self.read),
        };
        let (len, kind, flags, id) = head?;
        if kind == T_DATA {
            return self.data(id, flags, len);
        }
        let mut frame = std::mem::take(&mut self.frame);
        crate::proxy::resize_scratch(&mut frame, len);
        if len > 0 && fill(&mut self.read, &mut frame, self.handshake).is_err() {
            self.frame = frame;
            return None;
        }
        let out = match kind {
            T_HEADERS => self.head_block(id, flags, &frame),
            T_CONT => self.continue_block(id, flags, &frame),
            T_RST => {
                if id == self.stream {
                    self.eof = true;
                }
                Some(())
            }
            T_SETTINGS => {
                if id == 0 {
                    self.settings(flags, &frame);
                }
                Some(())
            }
            T_PING => {
                if id == 0 {
                    self.ping(flags, &frame);
                }
                Some(())
            }
            T_WINDOW => {
                self.window(id, &frame);
                Some(())
            }
            T_GOAWAY => {
                self.eof = true;
                Some(())
            }
            _ => Some(()),
        };
        self.frame = frame;
        out
    }

    fn head_block(&mut self, id: u32, flags: u8, body: &[u8]) -> Option<()> {
        let mut body = body;
        if flags & F_PADDED != 0 {
            let pad = usize::from(*body.first()?);
            if pad + 1 > body.len() {
                return None;
            }
            body = &body[1..body.len() - pad];
        }
        if flags & F_PRIORITY != 0 {
            if body.len() < 5 {
                return None;
            }
            body = &body[5..];
        }
        if flags & F_END_HEADERS != 0 {
            return self.headers(id, flags, body);
        }
        if self.head.len() + body.len() > HEAD_CAP {
            return None;
        }
        self.head.extend_from_slice(body);
        self.head_id = id;
        Some(())
    }

    fn continue_block(&mut self, id: u32, flags: u8, body: &[u8]) -> Option<()> {
        if id != self.head_id || self.head.len() + body.len() > HEAD_CAP {
            return None;
        }
        if flags & F_END_HEADERS != 0 {
            let mut block = std::mem::take(&mut self.head);
            block.extend_from_slice(body);
            return self.headers(id, flags, &block);
        }
        self.head.extend_from_slice(body);
        Some(())
    }

    fn window(&self, id: u32, body: &[u8]) {
        if body.len() != 4 {
            return;
        }
        let inc = u64::from(u32::from_be_bytes(body[..4].try_into().unwrap()) & 0x7FFF_FFFF);
        if inc == 0 {
            return;
        }
        let mut send = self
            .shared
            .send
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if id == 0 {
            send.conn = send.conn.saturating_add(inc).min(WINDOW_MAX);
        } else if id == self.stream {
            send.stream = send.stream.saturating_add(inc).min(WINDOW_MAX);
        } else {
            return;
        }
        self.shared.wake.notify_all();
    }
}

impl<R: Read> Read for GrpcReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.msg_at < self.pay_end {
                let n = (self.pay_end - self.msg_at).min(buf.len());
                buf[..n].copy_from_slice(&self.msg[self.msg_at..self.msg_at + n]);
                self.msg_at += n;
                return Ok(n);
            }
            // The next message may already be in the buffer behind the one just taken, and reading the socket first would block on it; that holds at END_STREAM too — the flag ends the frames, not the bytes.
            if self.decode().is_none() {
                self.eof = true;
                return Ok(0);
            }
            if self.msg_at < self.pay_end {
                continue;
            }
            if self.eof {
                return Ok(0);
            }
            if self.pump().is_none() {
                self.eof = true;
            }
        }
    }
}

/// The frames one write carries: a promoted relay read is `64 KiB` of full `HUNK`s, each hunk leaving
/// as two DATA frames at the frame size this lane advertises, so one read of the relay's own buffer is
/// one batch and one socket call. A wider caller flushes mid-write when the batch fills; a narrower
/// one pays the call it was asked for and no other.
const FRAMES_PER_WRITE: usize = 8;

/// A gathered frame's own bytes: its nine-byte head and the envelope prefix it carries, which is at
/// most the `16` bytes `frame_prefix` can fill.
const SLOT: usize = 9 + 16;

/// The frame that has not been added to a batch yet, and the part slot of a list still empty.
const NO_FRAME: &[u8] = &[];

/// A caller write's frames held apart rather than staged together: every head and envelope prefix in
/// a slot of its own, every payload still the caller's own slice, so one flush is one vectored write
/// whose body parts point into the buffer the relay handed over.
struct Gather<'a> {
    slots: [[u8; SLOT]; FRAMES_PER_WRITE],
    held: [(&'a [u8], usize); FRAMES_PER_WRITE],
    used: usize,
}

impl<'a> Gather<'a> {
    fn new() -> Self {
        Self {
            slots: [[0u8; SLOT]; FRAMES_PER_WRITE],
            held: [(NO_FRAME, 0); FRAMES_PER_WRITE],
            used: 0,
        }
    }

    fn full(&self) -> bool {
        self.used == FRAMES_PER_WRITE
    }

    /// One DATA frame into the batch: its head built where it will be read from, the envelope bytes it
    /// carries copied in beside it, and its payload left as the caller's slice.
    fn add(&mut self, id: u32, flags: u8, prefix: &[u8], payload: &'a [u8]) {
        let at = self.used;
        self.used += 1;
        let head = frame_head(prefix.len() + payload.len(), T_DATA, flags, id);
        self.slots[at][..9].copy_from_slice(&head);
        self.slots[at][9..9 + prefix.len()].copy_from_slice(prefix);
        self.held[at] = (payload, prefix.len());
    }

    /// The batch as one write, in the order the frames go out: a head slot and then the payload run it
    /// opens, for every frame held. An empty batch takes neither lock nor call, and a held batch is
    /// emptied by the write, so the frames that follow it start a new one.
    fn flush(&mut self, shared: &Arc<Shared>) -> bool {
        if self.used == 0 {
            return true;
        }
        let mut parts: [&[u8]; 2 * FRAMES_PER_WRITE] = [NO_FRAME; 2 * FRAMES_PER_WRITE];
        let mut pieces = 0;
        for (slot, held) in self.slots[..self.used]
            .iter()
            .zip(self.held[..self.used].iter().copied())
        {
            let (payload, prefix) = held;
            parts[pieces] = &slot[..9 + prefix];
            pieces += 1;
            if !payload.is_empty() {
                parts[pieces] = payload;
                pieces += 1;
            }
        }
        self.used = 0;
        let Ok(mut stream) = shared.stream.lock() else {
            return false;
        };
        stream.write_slices(&parts[..pieces])
    }
}

impl GrpcWriter {
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        let mut batch = Gather::new();
        for piece in data.chunks(HUNK) {
            if !self.message(piece, false, &mut batch) {
                return false;
            }
        }
        batch.flush(&self.shared)
    }

    pub(crate) fn close(&self) {
        if self.shared.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut batch = Gather::new();
        self.message(&[], true, &mut batch);
        batch.flush(&self.shared);
    }

    /// Window for one more frame, or the batch out to the peer first: a credit the peer has not given
    /// cannot be waited for while its own bytes sit unwritten.
    fn credit(&self, batch: &mut Gather<'_>, need: u64) -> bool {
        if take_window(&self.shared, need, false) {
            return true;
        }
        if !batch.flush(&self.shared) {
            return false;
        }
        take_window(&self.shared, need, true)
    }

    fn message<'a>(&self, data: &'a [u8], end: bool, batch: &mut Gather<'a>) -> bool {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(data.len(), &mut prefix);
        let total = plen + data.len();
        let max = *self
            .shared
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let max = max.max(1);
        let mut at = 0;
        while at < total {
            let n = (total - at).min(max);
            let last = at + n == total;
            if !self.credit(batch, n as u64) {
                return false;
            }
            if batch.full() && !batch.flush(&self.shared) {
                return false;
            }
            let flags = if last && end { F_END } else { 0 };
            if at + n <= plen {
                batch.add(self.stream, flags, &prefix[at..at + n], &[]);
            } else if at >= plen {
                batch.add(self.stream, flags, &[], &data[at - plen..at - plen + n]);
            } else {
                batch.add(
                    self.stream,
                    flags,
                    &prefix[at..plen],
                    &data[..n - (plen - at)],
                );
            }
            at += n;
        }
        true
    }
}

impl std::io::Write for GrpcWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.send(data) {
            Ok(data.len())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn frame_prefix(data_len: usize, out: &mut [u8; 16]) -> usize {
    let mut value = data_len as u64;
    let mut at = 6;
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out[at] = byte;
            at += 1;
            break;
        }
        out[at] = byte | 0x80;
        at += 1;
    }
    let inner = (at - 5 + data_len) as u32;
    out[0] = 0;
    out[1..5].copy_from_slice(&inner.to_be_bytes());
    out[5] = 0x0A;
    at
}

#[cfg(test)]
fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 & 0x7F | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(msg: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *msg.get(*at)?;
        *at += 1;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The `Data` field of a `Hunk`, and where it sits inside the message: the reader hands over the bytes where they lie, so the offset is part of the answer rather than something the caller finds again.
fn hunk_decode(msg: &[u8]) -> Option<(usize, &[u8])> {
    let mut at = 0;
    let mut data: &[u8] = &[];
    let mut off = 0usize;
    while at < msg.len() {
        let key = read_varint(msg, &mut at)?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return None;
        }
        if field == 1 {
            if wire != 2 {
                return None;
            }
            let len = usize::try_from(read_varint(msg, &mut at)?).ok()?;
            let end = at.checked_add(len)?;
            data = msg.get(at..end)?;
            off = at;
            at = end;
        } else {
            skip_field(msg, &mut at, wire)?;
        }
    }
    Some((off, data))
}

fn skip_field(msg: &[u8], at: &mut usize, wire: u8) -> Option<()> {
    let fixed = match wire {
        0 => {
            read_varint(msg, at)?;
            return Some(());
        }
        1 => 8,
        2 => usize::try_from(read_varint(msg, at)?).ok()?,
        5 => 4,
        _ => return None,
    };
    *at = at.checked_add(fixed)?;
    if *at > msg.len() {
        return None;
    }
    Some(())
}

pub(crate) fn accept(stream: Connection, path: &str) -> Option<(GrpcReader, GrpcWriter)> {
    let read = stream;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    // A head's clock only bites when a read answers it, so the preface and the request headers are polled at the relay's grain and ended by the deadline; the relay behind them waits blocking again.
    read.set_read_timeout(Some(crate::budgets::RELAY_POLL))
        .ok()?;
    let mut accepted = accept_split(read, write, path)?;
    accepted.0.set_poll(None);
    Some(accepted)
}

fn new_shared(write: Box<dyn crate::proxy::FrameWrite + Send>) -> Arc<Shared> {
    Arc::new(Shared {
        stream: Mutex::new(write),
        send: Mutex::new(SendWindow {
            conn: 65_535,
            stream: 65_535,
        }),
        wake: Condvar::new(),
        max_frame: Mutex::new(16_384),
        init: Mutex::new(65_535),
        ended: AtomicBool::new(false),
        dead: AtomicBool::new(false),
    })
}

/// The `TunMulti` peer of a configured path: the same service prefix, the multi-mode stream name, the way Xray derives both names from one service name.
fn multi_path(path: &str) -> String {
    match path.rfind('/') {
        Some(at) => format!("{}TunMulti", &path[..=at]),
        None => "TunMulti".to_owned(),
    }
}

/// `read_exact` under the clock a head is decoded under, which the site passes while a head arrives: past the deadline a silence is an error, so `read_exact`'s timeout-retry cannot spin a peer that never finishes speaking, and an unarmed reader waits exactly as it did.
fn fill(
    read: &mut dyn Read,
    buf: &mut [u8],
    until: Option<std::time::Instant>,
) -> std::io::Result<()> {
    match until {
        Some(until) => crate::proxy::read_exact(
            &mut crate::proxy::HandshakeDeadline { inner: read, until },
            buf,
        ),
        None => crate::proxy::read_exact(read, buf),
    }
}

fn new_reader<R: Read>(
    read: R,
    shared: Arc<Shared>,
    server: bool,
    path: &str,
    stream: u32,
) -> GrpcReader<R> {
    GrpcReader {
        read,
        shared,
        decoder: Decoder::default(),
        stream,
        server,
        path: path.to_owned(),
        multi_path: multi_path(path),
        method: Method::Hunk,
        answered: false,
        head: Vec::new(),
        head_id: 0,
        msg: Vec::new(),
        msg_at: 0,
        msg_end: 0,
        pay_end: 0,
        staged: 0,
        reclaims: 0,
        frame: Vec::new(),
        owed: 0,
        owed_id: 0,
        handshake: None,
        eof: false,
    }
}

// The same accept over halves that cannot clone: the preface is read, not peeked.
pub(crate) fn accept_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    write: W,
    path: &str,
) -> Option<(GrpcReader<R>, GrpcWriter)> {
    let until = std::time::Instant::now() + crate::budgets::handshake();
    let mut magic = [0u8; 24];
    fill(&mut read, &mut magic, Some(until)).ok()?;
    if magic != *MAGIC {
        return None;
    }
    let shared = new_shared(Box::new(write));
    {
        let Ok(mut socket) = shared.stream.lock() else {
            return None;
        };
        if socket.write_all(&PREFACE).is_err() {
            return None;
        }
    }
    let mut reader = new_reader(read, Arc::clone(&shared), true, path, 0);
    // The clock the preface was read under covers the request headers too, and ends where the head ends: past it the pump is a give-up rather than a wait, and a reader handed to a caller is unarmed again.
    reader.set_handshake_budget(Some(until));
    while !reader.answered && !reader.eof {
        if reader.pump().is_none() {
            reader.eof = true;
        }
    }
    if !reader.answered {
        return None;
    }
    reader.set_handshake_budget(None);
    // One stream per connection: GOAWAY after the first keeps that shape while telling the peer to
    // open its next flow on a fresh connection instead of hanging it on this one.
    let mut last = [0u8; 8];
    last[..4].copy_from_slice(&reader.stream.to_be_bytes());
    let _ = reader.emit(T_GOAWAY, 0, 0, &last);
    let writer = GrpcWriter {
        shared,
        stream: reader.stream,
    };
    Some((reader, writer))
}

pub(crate) fn connect(
    stream: Connection,
    host: &str,
    path: &str,
) -> Option<(GrpcReader, GrpcWriter)> {
    let read = stream;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    connect_split(read, write, host, path)
}

// The same connect over halves that cannot clone: the preface is written, not peeked.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    mut write: W,
    host: &str,
    path: &str,
) -> Option<(GrpcReader<R>, GrpcWriter)> {
    if !write.write_slices(&[MAGIC, &PREFACE]) {
        return None;
    }
    let block = block_encode(&[
        (":method", "POST"),
        (":scheme", "http"),
        (":path", path),
        (":authority", host),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("grpc-encoding", "identity"),
        ("grpc-accept-encoding", "gzip,identity"),
    ]);
    if !write_frame(&mut write, T_HEADERS, F_END_HEADERS, 1, &block) {
        return None;
    }
    let shared = new_shared(Box::new(write));
    let reader = new_reader(read, Arc::clone(&shared), false, path, 1);
    Some((reader, GrpcWriter { shared, stream: 1 }))
}

impl crate::proxy::CarrierSink for GrpcWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn close(&self) {
        self.close();
    }
}

pub(crate) fn mark_reader_dead<R: Read>(reader: &mut GrpcReader<R>) {
    reader.shared.dead.store(true, Ordering::SeqCst);
    reader.shared.wake.notify_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn huffman_matches_the_rfc_example() {
        let coded = [
            0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF,
        ];
        let mut plain = Vec::new();
        ferrox_core::foxy::hpack::huffman_decode(&coded, &mut plain).expect("decodes");
        assert_eq!(plain, b"www.example.com");
        assert!(ferrox_core::foxy::hpack::huffman_decode(b"\xff", &mut Vec::new()).is_none());
    }

    #[test]
    fn headers_decode_the_rfc_request_example() {
        let first = [
            0x82, 0x86, 0x84, 0x41, 0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB,
            0x90, 0xF4, 0xFF,
        ];
        let mut decoder = Decoder::default();
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        decoder
            .decode(&first, &mut |name, value| {
                headers.push((name.to_vec(), value.to_vec()));
            })
            .expect("decodes");
        let get = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name.as_bytes())
                .map(|(_, value)| value.clone())
        };
        assert_eq!(get(":method").expect("method"), b"GET");
        assert_eq!(get(":scheme").expect("scheme"), b"http");
        assert_eq!(get(":path").expect("path"), b"/");
        assert_eq!(get(":authority").expect("authority"), b"www.example.com");
    }

    #[test]
    fn headers_round_trip_without_indexing() {
        let block = block_encode(&[(":method", "POST"), (":path", "/TunnelService/Tun")]);
        let mut decoder = Decoder::default();
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        decoder
            .decode(&block, &mut |name, value| {
                headers.push((name.to_vec(), value.to_vec()));
            })
            .expect("decodes");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].1, b"/TunnelService/Tun");
    }

    #[test]
    fn hunks_carry_the_xray_schema_bytes() {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(4, &mut prefix);
        let mut frame = prefix[..plen].to_vec();
        frame.extend_from_slice(b"ping");
        assert_eq!(frame, b"\0\0\0\0\x06\x0a\x04ping");
        assert_eq!(
            hunk_decode(&[0x0A, 0x04, b'p', b'i', b'n', b'g']).expect("decodes"),
            (2, b"ping".as_slice())
        );
        // A field the lane does not read still carries its payload's offset.
        assert_eq!(
            hunk_decode(&[0x12, 0x02, 0x01, 0x02, 0x0A, 0x02, b'p', b'g']).expect("decodes"),
            (6, b"pg".as_slice())
        );
        assert!(hunk_decode(b"raw payload").is_none());
        assert!(hunk_decode(&[0x0A, 0x80]).is_none());
    }

    /// A server that answers whole frames at its own pace, in memory: the place where a copy count is exact rather than a function of the scheduler.
    #[derive(Default)]
    struct Sink(Vec<u8>);

    impl std::io::Write for Sink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Sink {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            parts.iter().all(|part| self.write_all(part).is_ok())
        }
    }

    /// A peer socket that keeps every write it was given as its own entry, so a test can count the writes and read their bytes.
    #[derive(Default)]
    struct Calls(Arc<Mutex<Vec<Vec<u8>>>>);

    impl std::io::Write for Calls {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().push(data.to_vec());
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Calls {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            self.0.lock().unwrap().push(parts.concat());
            true
        }
    }

    /// What a peer was given: every write whole, and every part of one by address and length.
    #[derive(Default)]
    struct Peer {
        writes: Vec<Vec<u8>>,
        parts: Vec<(usize, usize)>,
    }

    /// A peer socket that records both, so a batch is witnessed by what it carries and by what it
    /// points at — the second is the only way a gather's zero-copy is ever seen.
    struct Recorder(Arc<Mutex<Peer>>);

    impl Recorder {
        fn record(&mut self, parts: &[&[u8]]) -> bool {
            let mut peer = self.0.lock().unwrap();
            for part in parts {
                peer.parts.push((part.as_ptr() as usize, part.len()));
            }
            peer.writes.push(parts.concat());
            true
        }
    }

    impl std::io::Write for Recorder {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.record(&[data]);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Recorder {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            self.record(parts)
        }
    }

    fn frame(kind: u8, flags: u8, id: u32, body: &[u8]) -> Vec<u8> {
        let mut sink = Sink::default();
        assert!(write_frame(&mut sink, kind, flags, id, body));
        sink.0
    }

    /// A writer over the test's own sink, at the frame size it asks for and with the window it owes.
    fn writer_over<W: crate::proxy::FrameWrite + 'static>(
        write: W,
        max_frame: usize,
        window: u64,
    ) -> GrpcWriter {
        let shared = new_shared(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>);
        *shared.max_frame.lock().unwrap() = max_frame;
        let mut send = shared.send.lock().unwrap();
        send.conn = window;
        send.stream = window;
        drop(send);
        GrpcWriter { shared, stream: 1 }
    }

    /// The frames a hunk leaves as at the frame size this lane advertises: the envelope and its
    /// payload, cut at `16_384` — the reference a gathered batch is compared frame by frame against.
    fn frames(payload: &[u8]) -> Vec<u8> {
        let body = message(payload);
        let mut out = Vec::new();
        for piece in body.chunks(16_384) {
            out.extend_from_slice(&frame(T_DATA, 0, 1, piece));
        }
        out
    }

    /// One gRPC message: the 5-byte envelope and a `Hunk` whose `Data` is `payload`.
    fn message(payload: &[u8]) -> Vec<u8> {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(payload.len(), &mut prefix);
        let mut body = prefix[..plen].to_vec();
        body.extend_from_slice(payload);
        body
    }

    /// One gRPC message carrying a `MultiHunk`: field 1 is `repeated bytes`, so each element is a tag, its own varint length and its bytes, in order.
    fn multi_message(elements: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for element in elements {
            body.push(0x0A);
            push_varint(&mut body, element.len() as u64);
            body.extend_from_slice(element);
        }
        let mut out = vec![0u8];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// The served side of a call over a scripted wire: the preface, the HEADERS that open it, then its DATA frames.
    fn served(
        path: &str,
        frames: &[(u8, Vec<u8>)],
    ) -> Option<GrpcReader<std::io::Cursor<Vec<u8>>>> {
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[
                (":method", "POST"),
                (":path", path),
                ("content-type", "application/grpc"),
            ]),
        ));
        for (flags, body) in frames {
            wire.extend_from_slice(&frame(T_DATA, *flags, 1, body));
        }
        let (reader, writer) = accept_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "/TunnelService/Tun",
        )?;
        drop(writer);
        Some(reader)
    }

    /// Everything the caller is handed, and the bytes the reader moved for itself to hand it.
    fn drain_all(reader: &mut GrpcReader<std::io::Cursor<Vec<u8>>>) -> (Vec<u8>, usize) {
        let mut got = Vec::new();
        let mut buf = [0u8; 3000];
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        (got, reader.staged)
    }

    /// The two methods cannot share a decoder: a `MultiHunk` read as a `Hunk` hands the caller only the last element of every message, which is the silent truncation the served mode exists to refuse.
    #[test]
    fn a_multi_message_hands_every_element_in_order() {
        let batch = multi_message(&[b"ab", b"cdef", b"", b"g"]);
        for (name, frames, want) in [
            (
                "one message, four elements",
                vec![(F_END, batch.clone())],
                b"abcdefg".to_vec(),
            ),
            (
                "two messages, two elements each",
                vec![
                    (0, multi_message(&[b"ab", b"c"])),
                    (F_END, multi_message(&[b"d", b"ef"])),
                ],
                b"abcdef".to_vec(),
            ),
            (
                "one element cut across frames",
                vec![(0, batch[..11].to_vec()), (F_END, batch[11..].to_vec())],
                b"abcdefg".to_vec(),
            ),
        ] {
            let mut multi = served("/TunnelService/TunMulti", &frames).expect("serves");
            let (got, staged) = drain_all(&mut multi);
            assert_eq!(got, want, "{name}");
            assert_eq!(staged, 0, "{name} staged bytes for itself");
        }
        let mut blind = served("/TunnelService/Tun", &[(F_END, batch)]).expect("serves");
        assert_eq!(
            drain_all(&mut blind).0,
            b"g".to_vec(),
            "single mode takes the last element and drops the batch"
        );
        assert!(
            served("/other/TunMulti", &[]).is_none(),
            "a multi call on another service is refused"
        );
    }

    /// The batch the reference server writes: eight `readv` buffers is its ceiling, so one message carries the set and the caller still gets every byte in order, unstaged.
    #[test]
    fn a_batched_downlink_arrives_element_by_element() {
        let parts: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'a' + i; 8 * 1024]).collect();
        let batch: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let mut reader = served(
            "/TunnelService/TunMulti",
            &[
                (0, multi_message(&batch[..4])),
                (F_END, multi_message(&batch[4..])),
            ],
        )
        .expect("serves");
        let (got, staged) = drain_all(&mut reader);
        assert_eq!(got, parts.concat(), "eight elements of 8 KiB, in order");
        assert_eq!(staged, 0, "a batch is delivered where it lies");
    }

    /// The single-mode call is untouched by the second method, and a path that is neither is refused.
    #[test]
    fn one_listener_serves_both_methods() {
        for (path, want) in [
            ("/TunnelService/Tun", b"ping".to_vec()),
            ("/TunnelService/TunMulti", b"pin".to_vec()),
        ] {
            let frames = if path.ends_with("Multi") {
                vec![(F_END, multi_message(&[b"pi", b"n"]))]
            } else {
                vec![(F_END, message(b"ping"))]
            };
            let mut reader = served(path, &frames).expect("serves");
            assert_eq!(drain_all(&mut reader).0, want, "{path}");
        }
        assert!(served("/TunnelService/TunExtra", &[]).is_none());
    }

    fn dial(frames: &[(u8, Vec<u8>)]) -> GrpcReader<std::io::Cursor<Vec<u8>>> {
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        for (flags, body) in frames {
            wire.extend_from_slice(&frame(T_DATA, *flags, 1, body));
        }
        let (reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        reader
    }

    /// The witness for `carrier-grpc payload-staging-copies-per-byte-read 0`: a body is read onto the end of the buffer the caller is served from, over the three shapes a body can arrive in.
    #[test]
    fn a_body_never_lands_in_a_second_buffer() {
        for (name, frames, want) in [
            (
                "one message per frame",
                vec![
                    (0, message(b"ping")),
                    (0, message(b"pong")),
                    (F_END, message(b"last")),
                ],
                b"pingponglast".to_vec(),
            ),
            (
                "two messages in one frame",
                vec![(F_END, [message(b"ab"), message(b"cd")].concat())],
                b"abcd".to_vec(),
            ),
            (
                "one message split over frames",
                vec![
                    (0, message(b"ping")[..6].to_vec()),
                    (F_END, message(b"ping")[6..].to_vec()),
                ],
                b"ping".to_vec(),
            ),
        ] {
            let mut reader = dial(&frames);
            let mut got = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = reader.read(&mut buf).expect("reads");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, want, "{name}");
            assert_eq!(reader.staged, 0, "{name} staged bytes for itself");
        }
    }

    /// The witness for `carrier-grpc user-space-copies-per-byte-written 0`: the uplink hands the payload to the frame writer as one slice whose base is the caller's buffer, so a `writev` carries it unstaged — a round trip cannot see this, so pointer identity is the only witness.
    #[test]
    fn the_uplink_hands_the_payload_to_the_writer_by_pointer() {
        let payload: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let base = payload.as_ptr() as usize;
        let capacity = payload.capacity();
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), usize::MAX, u64::MAX);
        assert!(writer.send(&payload));
        // The payload reached the frame writer as a slice whose base is the caller's own buffer, so a `writev` carries it and no byte is staged through a second `Vec`.
        assert!(
            peer.lock()
                .unwrap()
                .parts
                .iter()
                .any(|&(at, len)| at == base && len == payload.len()),
            "the payload was handed by pointer, not staged through a buffer"
        );
        assert_eq!(payload.as_ptr() as usize, base, "the caller's buffer moved");
        assert_eq!(payload.capacity(), capacity, "the caller's buffer grew");
    }

    /// A writer the peer never credits gives up at the relay stall, so a relay leg cannot park its thread on a window that never arrives.
    #[test]
    fn a_writer_with_no_credit_gives_up_at_the_stall() {
        let _guard = crate::budgets::lock();
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(500)),
            ..Default::default()
        });
        let writer = writer_over(Recorder(Arc::new(Mutex::new(Peer::default()))), HUNK, 0);
        let shared = Arc::clone(&writer.shared);
        let (sent, got) = std::sync::mpsc::channel();
        let running = thread::spawn(move || {
            let _ = sent.send(writer.send(b"ping"));
        });
        let verdict = got.recv_timeout(Duration::from_secs(3));
        shared.dead.store(true, Ordering::SeqCst);
        shared.wake.notify_all();
        running.join().expect("writer thread");
        crate::budgets::clear();
        assert_eq!(verdict, Ok(false), "a writer with no credit returned");
    }

    /// The witnesses for `carrier-grpc writes-per-relay-read 1`, `carrier-grpc segments-per-socket-write 16` and `carrier-grpc payload-runs-per-socket-write 8`: a relay read of four full `HUNK`s is eight DATA frames and leaves as one write of sixteen segments whose bytes are those frames in order, with eight of them still runs of the caller's own buffer — a gather holds heads and envelopes apart, it does not stage a byte of payload.
    #[test]
    fn a_relay_read_gathers_its_frames_into_one_write() {
        let data: Vec<u8> = (0..FRAMES_PER_WRITE / 2 * HUNK)
            .map(|i| (i % 251) as u8)
            .collect();
        let base = data.as_ptr() as usize;
        let capacity = data.capacity();
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, u64::MAX);
        assert!(writer.send(&data));
        let peer = peer.lock().unwrap();
        assert_eq!(peer.writes.len(), 1, "one write for a relay read");
        let mut want = Vec::new();
        for piece in data.chunks(HUNK) {
            want.extend_from_slice(&frames(piece));
        }
        assert_eq!(peer.writes[0], want, "the same frames, in the same order");
        assert_eq!(
            peer.parts.len(),
            2 * FRAMES_PER_WRITE,
            "a head slot and a payload run for every frame"
        );
        // The parts that lie in the caller's buffer are its payload, edge to edge: the batch skipped no byte and copied none.
        let end = base + data.len();
        let runs = peer
            .parts
            .iter()
            .filter(|&&(start, _)| (base..end).contains(&start))
            .count();
        assert_eq!(runs, FRAMES_PER_WRITE, "one payload run per frame");
        let mut at = base;
        for &(start, len) in &peer.parts {
            if start < base || start >= end {
                continue;
            }
            assert_eq!(start, at, "a payload run starts where the last one ended");
            assert!(start + len <= end, "a run leaves the caller's buffer");
            at = start + len;
        }
        assert_eq!(at, end, "every byte reached the writer");
        assert_eq!(data.capacity(), capacity, "the caller's buffer grew");
    }

    /// The same batch driven over a real socket, where the only thing a loopback test can assert is
    /// its bytes: sixteen segments is the widest list this carrier hands `writev` or `WSASend`, so
    /// a platform that split the list or refused its width would answer with missing or reordered
    /// frames rather than with a count.
    #[test]
    fn a_wide_batch_reaches_a_real_socket_whole() {
        let data: Vec<u8> = (0..FRAMES_PER_WRITE / 2 * HUNK)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut want = Vec::new();
        for piece in data.chunks(HUNK) {
            want.extend_from_slice(&frames(piece));
        }
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let writer = writer_over(stream, HUNK, u64::MAX);
            assert!(writer.send(&data), "the socket took the batch");
        });
        let mut read = Connection::connect(("127.0.0.1", port)).expect("connects");
        let mut wire = Vec::new();
        read.read_to_end(&mut wire).expect("reads");
        handle.join().expect("joins");
        assert_eq!(wire, want, "the same frames, in the same order, whole");
    }

    /// The gathered batch reaches the peer before its own credit parks the writer: a peer grants for
    /// bytes it has seen, so frames held in a batch cannot wait behind the window they are the thing
    /// that would raise. The witness is a write seen while the thread is still inside `send` — with the
    /// flush taken away the loop below runs out its bound instead — and the run joins only once the
    /// credit arrives.
    #[test]
    fn a_gathered_batch_flushes_before_a_window_that_has_not_arrived() {
        let one_hunk = (frame_prefix(HUNK, &mut [0u8; 16]) + HUNK) as u64;
        let data: Vec<u8> = (0..4 * HUNK).map(|i| (i % 251) as u8).collect();
        let mut want = Vec::new();
        for piece in data.chunks(HUNK) {
            want.extend_from_slice(&frames(piece));
        }
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, one_hunk);
        let shared = Arc::clone(&writer.shared);
        let handle = thread::spawn(move || writer.send(&data));
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while peer.lock().unwrap().writes.is_empty() {
            assert!(
                std::time::Instant::now() < until,
                "the writer parked with its own batch unwritten"
            );
            thread::yield_now();
        }
        assert!(
            !handle.is_finished(),
            "one hunk of window cannot carry four hunks"
        );
        {
            let mut send = shared.send.lock().unwrap();
            send.conn = u64::MAX;
            send.stream = u64::MAX;
        }
        shared.wake.notify_all();
        assert!(handle.join().expect("joins"));
        let peer = peer.lock().unwrap();
        assert_eq!(
            peer.writes.concat(),
            want,
            "the same frames, in the same order"
        );
    }

    /// The same buffer answers every frame: a body the size of the one before it is appended in place, so no message pays a reallocation of the bytes still live in it, and a caller that drains each hunk before the next arrives never pays a reclaim move either.
    #[test]
    fn the_message_buffer_is_reused_not_reallocated() {
        let hunk = [b'x'; HUNK];
        let mut reader = dial(&[
            (0, message(&hunk)),
            (0, message(&hunk)),
            (F_END, message(&hunk)),
        ]);
        let mut got = [0u8; HUNK];
        reader.read_exact(&mut got).expect("reads a hunk");
        assert_eq!(got, hunk);
        let cap = reader.msg.capacity();
        assert!(cap > 0, "the body landed somewhere");
        for _ in 1..3 {
            reader.read_exact(&mut got).expect("reads a hunk");
            assert_eq!(got, hunk);
            assert_eq!(reader.msg.capacity(), cap, "a same-sized body reallocated");
        }
        assert_eq!(reader.staged, 0, "a drained buffer staged nothing");
        assert_eq!(reader.reclaims, 0, "a drained buffer took a reclaim move");
    }

    /// The witnesses for `carrier-grpc credit-bytes 2097152`, `window-update-writes-per-credit 1` and `window-update-frames-per-credit 2`: a credit is still the peer's two frames, byte for byte, in one write — granted once for a whole half-window of bodies, not once per frame, and never so late that the peer has spent its window waiting for it.
    #[test]
    fn a_credit_grants_the_window_it_owes_in_one_write() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let hunk = [b'x'; HUNK];
        let body = message(&hunk);
        // The first frame that reaches a credit's worth, and two credits of frames, so the run sees both sides of the threshold twice.
        let per_credit = (CREDIT_AT as usize - 1) / body.len() + 1;
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        for _ in 0..per_credit * 2 {
            wire.extend_from_slice(&frame(T_DATA, 0, 1, &body));
        }
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Calls(Arc::clone(&calls)),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        calls.lock().unwrap().clear();
        let owed = (per_credit * body.len()) as u32;
        assert!(owed >= CREDIT_AT, "a credit is owed at the threshold");
        assert!(
            owed < WINDOW,
            "the credit lands while the peer still has window to send into"
        );
        let mut got = [0u8; HUNK];
        let mut want = Vec::new();
        for credit in 0..2 {
            for _ in 1..per_credit {
                reader.read_exact(&mut got).expect("reads a hunk");
                assert_eq!(got, hunk);
            }
            assert_eq!(
                calls.lock().unwrap().len(),
                credit,
                "a body short of a credit's worth grants nothing"
            );
            reader.read_exact(&mut got).expect("reads the last hunk");
            assert_eq!(got, hunk);
            let inc = owed.to_be_bytes();
            let mut pair = frame(T_WINDOW, 0, 0, &inc);
            pair.extend_from_slice(&frame(T_WINDOW, 0, 1, &inc));
            want.push(pair);
            assert_eq!(
                *calls.lock().unwrap(),
                want,
                "one write per credit carries the connection and the stream update, and their increments are every body that landed since the last one"
            );
        }
    }

    /// The witness for `carrier-grpc connection-window-credit-at-preface 4128769`: the grant a batched credit rests on, because a peer that started at the RFC's connection window would have to wait for the first credit to send a second window's worth.
    #[test]
    fn the_preface_grants_the_peer_a_whole_window() {
        let mut settings = Vec::with_capacity(14);
        settings.extend_from_slice(&S_WINDOW.to_be_bytes());
        settings.extend_from_slice(&WINDOW.to_be_bytes());
        settings.extend_from_slice(&S_MAX_CONCURRENT.to_be_bytes());
        settings.extend_from_slice(&1u32.to_be_bytes());
        let mut want = frame(T_SETTINGS, 0, 0, &settings);
        want.extend_from_slice(&frame(T_WINDOW, 0, 0, &(WINDOW - 65_535).to_be_bytes()));

        let dialed = Arc::new(Mutex::new(Vec::new()));
        let (reader, writer) = connect_split(
            std::io::Cursor::new(Vec::new()),
            Calls(Arc::clone(&dialed)),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop((reader, writer));

        let served = Arc::new(Mutex::new(Vec::new()));
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[
                (":method", "POST"),
                (":path", "/x"),
                ("content-type", "application/grpc"),
            ]),
        ));
        let (reader, writer) =
            accept_split(std::io::Cursor::new(wire), Calls(Arc::clone(&served)), "/x")
                .expect("serves");
        drop((reader, writer));

        let mut head = MAGIC.to_vec();
        head.extend_from_slice(&want);
        assert_eq!(
            dialed.lock().unwrap()[0],
            head,
            "the client's preface, settings and top-up leave as one write"
        );
        assert_eq!(
            served.lock().unwrap()[0],
            want,
            "the server grants the same window before it reads a body"
        );
    }

    /// The witness that the peer is asked for one stream per connection: its next flow opens a
    /// fresh connection instead of hanging on this one.
    #[test]
    fn an_accepted_connection_asks_for_one_stream_at_a_time() {
        let served = Arc::new(Mutex::new(Vec::new()));
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[
                (":method", "POST"),
                (":path", "/x"),
                ("content-type", "application/grpc"),
            ]),
        ));
        let (reader, writer) =
            accept_split(std::io::Cursor::new(wire), Calls(Arc::clone(&served)), "/x")
                .expect("serves");
        drop((reader, writer));
        let text = served.lock().unwrap().concat();
        let mut setting = S_MAX_CONCURRENT.to_be_bytes().to_vec();
        setting.extend_from_slice(&1u32.to_be_bytes());
        assert!(
            text.windows(setting.len())
                .any(|part| part == setting.as_slice()),
            "the server asks the peer for one stream at a time"
        );
        let mut last = [0u8; 8];
        last[..4].copy_from_slice(&1u32.to_be_bytes());
        assert!(
            text.windows(17)
                .any(|part| part == frame(T_GOAWAY, 0, 0, &last)),
            "the first stream is the last this connection will take"
        );
    }

    /// The witness for `carrier-grpc message-bytes-moved-per-padded-frame 0`: the pad byte opens a message region, so the parser steps over it and the frame's length drops the tail, and the message between them stays where it landed.
    #[test]
    fn a_padded_frame_opens_a_message_without_moving() {
        let mut body = vec![3u8];
        body.extend_from_slice(&message(b"ping"));
        body.extend_from_slice(&[0xA5; 3]);
        let mut reader = dial(&[(F_PADDED | F_END, body)]);
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"ping");
        assert_eq!(reader.staged, 0, "the pad byte and tail cost no move");
    }

    /// The witness for `carrier-grpc padded-frame-credit-octets`: RFC 7540 6.9 puts the
    /// whole DATA payload — the Pad Length octet and the Padding included — into the
    /// flow-control window, so a padded frame gives the peer its wire length back and a
    /// peer with a strict window does not lose an octet per frame.
    #[test]
    fn a_padded_frame_credits_its_whole_wire_payload() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let hunk = [b'x'; HUNK];
        // A padded frame: the pad byte, the message, the pad tail.
        let mut padded = vec![3u8];
        padded.extend_from_slice(&message(&hunk));
        padded.extend_from_slice(&[0xA5; 3]);
        let wire_len = padded.len();
        let per_credit = (CREDIT_AT as usize - 1) / wire_len + 1;
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        for _ in 0..per_credit {
            wire.extend_from_slice(&frame(T_DATA, F_PADDED, 1, &padded));
        }
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Calls(Arc::clone(&calls)),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        calls.lock().unwrap().clear();
        let mut got = [0u8; HUNK];
        for _ in 0..per_credit {
            reader.read_exact(&mut got).expect("reads a hunk");
            assert_eq!(got, hunk);
        }
        // The grant: one write carrying the connection's and the stream's update.
        let inc = (per_credit * wire_len) as u32;
        let mut want = frame(T_WINDOW, 0, 0, &inc.to_be_bytes());
        want.extend_from_slice(&frame(T_WINDOW, 0, 1, &inc.to_be_bytes()));
        let sent = calls.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "one credit, one write");
        assert_eq!(
            sent[0], want,
            "the increment is every frame's wire length, the pad byte and the pad tail included"
        );
        assert!(
            inc > (per_credit * (wire_len - 4)) as u32,
            "and not what the cut left"
        );
    }

    /// The move a padded frame still pays, and the witness that the staging counter counts: here the pad byte cuts into a message the frame before had started, so only what follows it moves down.
    #[test]
    fn a_padded_frame_that_cuts_into_a_message_moves_only_what_follows_the_pad() {
        let split = message(b"ping");
        let mut body = vec![1u8];
        body.extend_from_slice(&split[6..]);
        body.push(0xA5);
        let mut reader = dial(&[(0, split[..6].to_vec()), (F_PADDED | F_END, body)]);
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"ping");
        assert_eq!(
            reader.staged,
            split.len() - 6,
            "only the bytes after the pad byte move"
        );
    }

    /// `END_STREAM` in the middle of a message is a refusal, not a short delivery: the envelope promised bytes the stream did not carry.
    #[test]
    fn an_end_stream_mid_message_delivers_nothing() {
        let mut body = message(b"ping");
        body.truncate(body.len() - 2);
        let mut reader = dial(&[(F_END, body)]);
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 0);
        assert!(reader.eof);
    }

    #[test]
    fn messages_frame_identically_at_every_chunk_size() {
        for max in [1usize, 2, 5, 6, 7, 8, 11, 16, 100, 16_384] {
            for len in [0usize, 1, 4, 127, 300] {
                let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut want = vec![0u8; 5];
                want.push(0x0A);
                push_varint(&mut want, len as u64);
                want.extend_from_slice(&data);
                let hunk_len = (want.len() - 5) as u32;
                want[1..5].copy_from_slice(&hunk_len.to_be_bytes());

                let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
                let port = listener.local_addr().expect("addr").port();
                let handle = thread::spawn(move || {
                    let (stream, _) = listener.accept().expect("accepts");
                    let shared = Arc::new(Shared {
                        stream: Mutex::new(
                            Box::new(stream) as Box<dyn crate::proxy::FrameWrite + Send>
                        ),
                        send: Mutex::new(SendWindow {
                            conn: u64::MAX,
                            stream: u64::MAX,
                        }),
                        wake: Condvar::new(),
                        max_frame: Mutex::new(max),
                        init: Mutex::new(u64::from(WINDOW)),
                        ended: AtomicBool::new(false),
                        dead: AtomicBool::new(false),
                    });
                    let writer = GrpcWriter { shared, stream: 1 };
                    let mut batch = Gather::new();
                    assert!(
                        writer.message(&data, true, &mut batch),
                        "max {max} len {len}"
                    );
                    assert!(batch.flush(&writer.shared), "max {max} len {len}");
                });
                let mut read = Connection::connect(("127.0.0.1", port)).expect("connects");
                let mut wire = Vec::new();
                read.read_to_end(&mut wire).expect("reads");
                handle.join().expect("joins");
                let mut body = Vec::new();
                let mut at = 0;
                while at < wire.len() {
                    let head = &wire[at..at + 9];
                    let len = usize::from(head[0]) << 16
                        | usize::from(head[1]) << 8
                        | usize::from(head[2]);
                    assert_eq!(head[3], T_DATA, "max {max} len {len}");
                    assert_eq!(u32::from_be_bytes(head[5..9].try_into().unwrap()), 1);
                    at += 9;
                    body.extend_from_slice(&wire[at..at + len]);
                    at += len;
                }
                assert_eq!(body, want, "max {max} len {len}");
            }
        }
    }

    /// The ops probe the page's `ops-retired-instructions` row names: the two per-message math steps, a gRPC envelope assembled and a `Hunk` parsed, over buffers the compiler cannot fold — no I/O, so the frame is the loops and the methods.
    #[test]
    fn the_envelope_and_the_hunk_cost_their_loops_and_nothing_else() {
        let messages = std::hint::black_box([
            &[0x0A, 0x04, b'p', b'i', b'n', b'g'][..],
            &[0x12, 0x02, 0x01, 0x02, 0x0A, 0x02, b'p', b'g'][..],
        ]);
        let mut prefix = [0u8; 16];
        let mut acc = 0usize;
        for _ in 0..512 {
            for msg in messages {
                let (off, data) = hunk_decode(msg).expect("decodes");
                acc += off + data.len() + frame_prefix(data.len(), &mut prefix);
            }
        }
        assert!(acc > 0);
        std::hint::black_box(&prefix);
    }

    #[test]
    fn frame_prefix_matches_the_vec_form_at_varint_edges() {
        for len in [0usize, 1, 127, 128, 300, 16383, 16384, 1 << 21, 1 << 28] {
            let mut varint = Vec::new();
            push_varint(&mut varint, len as u64);
            let inner = (1 + varint.len() + len) as u32;
            let mut want = vec![0u8];
            want.extend_from_slice(&inner.to_be_bytes());
            want.push(0x0A);
            want.extend_from_slice(&varint);
            let mut prefix = [0u8; 16];
            let plen = frame_prefix(len, &mut prefix);
            assert_eq!(&prefix[..plen], &want[..], "len {len}");
        }
    }

    #[test]
    fn tunnel_carries_an_echo_over_loopback() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/TunnelService/Tun").expect("serves");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
            drain(&mut reader);
            writer.close();
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) =
            connect(stream, "127.0.0.1", "/TunnelService/Tun").expect("dials");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        writer.close();
        drain(&mut reader);
        server.join().expect("joins");
    }

    fn drain(reader: &mut GrpcReader) {
        let mut buf = [0u8; 1024];
        while reader.read(&mut buf).unwrap_or(0) != 0 {}
    }

    #[test]
    fn tunnel_rejects_a_wrong_path() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/TunnelService/Tun").is_none());
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (_, writer) = connect(stream, "127.0.0.1", "/other/Tun").expect("dials");
        drop(writer);
        server.join().expect("joins");
    }
}
