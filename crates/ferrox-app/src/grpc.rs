use std::io::Read;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::h2::{
    block_encode, read_head, write_frame, write_frame_parts, Decoder, E_REFUSED, FRAME_CAP, F_ACK,
    F_END, F_END_HEADERS, F_PADDED, F_PRIORITY, HEAD_CAP, MAGIC, S_MAX_FRAME, S_WINDOW, T_CONT,
    T_DATA, T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS, T_WINDOW, WINDOW, WINDOW_MAX,
};

const MSG_CAP: usize = 16 * 1024 * 1024;
const HUNK: usize = 16 * 1024;

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

fn take_window(shared: &Shared, need: u64) -> bool {
    let mut send = shared.send.lock().unwrap_or_else(PoisonError::into_inner);
    while send.conn < need || send.stream < need {
        if shared.dead.load(Ordering::SeqCst) {
            return false;
        }
        send = shared
            .wake
            .wait(send)
            .unwrap_or_else(PoisonError::into_inner);
    }
    send.conn -= need;
    send.stream -= need;
    true
}

#[derive(Debug)]
pub(crate) struct GrpcReader<R: Read = TcpStream> {
    read: R,
    shared: Arc<Shared>,
    decoder: Decoder,
    stream: u32,
    server: bool,
    path: String,
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
    /// Bytes the reader moved for itself — the reclaim move and a padded frame's pad removal: these and nothing else are what the staging gate counts.
    #[cfg_attr(not(test), allow(dead_code, reason = "read by the staging gate"))]
    staged: usize,
    /// Scratch for the frames that are not a body: headers, settings, ping.
    frame: Vec<u8>,
    eof: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct GrpcWriter {
    shared: Arc<Shared>,
    stream: u32,
}

impl<R: Read> GrpcReader<R> {
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

    fn replenish(&self, id: u32, len: usize) {
        if len == 0 {
            return;
        }
        let inc = (len.min(1 << 30) as u32).to_be_bytes();
        self.emit(T_WINDOW, 0, 0, &inc);
        if id != 0 {
            self.emit(T_WINDOW, 0, id, &inc);
        }
    }

    fn refuse(&self, id: u32) {
        self.emit(T_RST, 0, id, &E_REFUSED.to_be_bytes());
    }

    fn find<'a>(headers: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
        headers.iter().find_map(|(key, value)| {
            key.eq_ignore_ascii_case(name.as_bytes())
                .then_some(value.as_slice())
        })
    }

    fn headers(&mut self, id: u32, flags: u8, block: &[u8]) -> Option<()> {
        let mut headers = Vec::new();
        self.decoder.decode(block, &mut headers)?;
        if self.server {
            return self.serve_headers(id, flags, &headers);
        }
        if id != self.stream {
            return Some(());
        }
        if !self.answered {
            let status = Self::find(&headers, ":status")?;
            if status != b"200" {
                return None;
            }
            self.answered = true;
        }
        if flags & F_END != 0 {
            self.eof = true;
        }
        Some(())
    }

    fn serve_headers(&mut self, id: u32, flags: u8, headers: &[(Vec<u8>, Vec<u8>)]) -> Option<()> {
        if self.answered {
            if flags & F_END != 0 {
                self.eof = true;
            }
            return Some(());
        }
        let ok = Self::find(headers, ":method") == Some(b"POST".as_slice())
            && Self::find(headers, ":path") == Some(self.path.as_bytes())
            && Self::find(headers, "content-type")
                .is_some_and(|v| v.starts_with(b"application/grpc"));
        if !ok {
            self.refuse(id);
            return None;
        }
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
        // The bytes the caller already had go first, and only when they outweigh what is still live: a move that costs more than it frees is a copy.
        if self.msg_at * 2 >= self.msg.len() {
            let at = self.msg_at;
            self.staged += self.msg.len() - at;
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
        self.replenish(id, len - first - pad);
        if first != 0 || pad != 0 {
            // A padded frame hides the pad byte and pad tail inside the body the parser reads, so dropping them moves what lies between.
            self.staged += len - first - pad;
            let end = from + len - pad;
            self.msg.copy_within(from + first..end, from);
            self.msg.truncate(end - first);
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
        if crate::proxy::read_exact(&mut self.read, &mut self.msg[from..]).is_err() {
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
            let (at, payload) = hunk_decode(&live[5..5 + len])?;
            self.msg_end = self.msg_at + 5 + len;
            self.msg_at += 5 + at;
            self.pay_end = self.msg_at + payload.len();
        }
    }

    fn pump(&mut self) -> Option<()> {
        let head = read_head(&mut self.read);
        let (len, kind, flags, id) = head?;
        if kind == T_DATA {
            return self.data(id, flags, len);
        }
        let mut frame = std::mem::take(&mut self.frame);
        crate::proxy::resize_scratch(&mut frame, len);
        if len > 0 && crate::proxy::read_exact(&mut self.read, &mut frame).is_err() {
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

impl GrpcWriter {
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        for piece in data.chunks(HUNK) {
            if !self.message(piece, false) {
                return false;
            }
        }
        true
    }

    pub(crate) fn close(&self) {
        if self.shared.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        self.message(&[], true);
    }

    fn message(&self, data: &[u8], end: bool) -> bool {
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
            if !take_window(&self.shared, n as u64) {
                return false;
            }
            let flags = if last && end { F_END } else { 0 };
            let Ok(mut stream) = self.shared.stream.lock() else {
                return false;
            };
            let wrote = if at + n <= plen {
                write_frame(
                    &mut **stream,
                    T_DATA,
                    flags,
                    self.stream,
                    &prefix[at..at + n],
                )
            } else if at >= plen {
                let from = at - plen;
                write_frame(
                    &mut **stream,
                    T_DATA,
                    flags,
                    self.stream,
                    &data[from..from + n],
                )
            } else {
                write_frame_parts(
                    &mut **stream,
                    T_DATA,
                    flags,
                    self.stream,
                    &prefix[at..plen],
                    &data[..n - (plen - at)],
                )
            };
            if !wrote {
                return false;
            }
            drop(stream);
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

pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(GrpcReader, GrpcWriter)> {
    let read = stream;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    accept_split(read, write, path)
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
        answered: false,
        head: Vec::new(),
        head_id: 0,
        msg: Vec::new(),
        msg_at: 0,
        msg_end: 0,
        pay_end: 0,
        staged: 0,
        frame: Vec::new(),
        eof: false,
    }
}

// The same accept over halves that cannot clone: the preface is read, not peeked.
pub(crate) fn accept_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    write: W,
    path: &str,
) -> Option<(GrpcReader<R>, GrpcWriter)> {
    let mut magic = [0u8; 24];
    crate::proxy::read_exact(&mut read, &mut magic).ok()?;
    if magic != *MAGIC {
        return None;
    }
    let shared = new_shared(Box::new(write));
    {
        let mut initial = Vec::with_capacity(12);
        initial.extend_from_slice(&S_WINDOW.to_be_bytes());
        initial.extend_from_slice(&WINDOW.to_be_bytes());
        let Ok(mut socket) = shared.stream.lock() else {
            return None;
        };
        if !write_frame(&mut **socket, T_SETTINGS, 0, 0, &initial) {
            return None;
        }
    }
    let mut reader = new_reader(read, Arc::clone(&shared), true, path, 0);
    while !reader.answered && !reader.eof {
        if reader.pump().is_none() {
            reader.eof = true;
        }
    }
    if !reader.answered {
        return None;
    }
    let writer = GrpcWriter {
        shared,
        stream: reader.stream,
    };
    Some((reader, writer))
}

pub(crate) fn connect(
    stream: TcpStream,
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
    write.write_all(MAGIC).ok()?;
    let mut initial = Vec::with_capacity(12);
    initial.extend_from_slice(&S_WINDOW.to_be_bytes());
    initial.extend_from_slice(&WINDOW.to_be_bytes());
    if !write_frame(&mut write, T_SETTINGS, 0, 0, &initial) {
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
    use std::net::TcpListener;
    use std::thread;

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
        let mut headers = Vec::new();
        decoder.decode(&first, &mut headers).expect("decodes");
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
        let mut headers = Vec::new();
        decoder.decode(&block, &mut headers).expect("decodes");
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

    fn frame(kind: u8, flags: u8, id: u32, body: &[u8]) -> Vec<u8> {
        let mut sink = Sink::default();
        assert!(write_frame(&mut sink, kind, flags, id, body));
        sink.0
    }

    /// One gRPC message: the 5-byte envelope and a `Hunk` whose `Data` is `payload`.
    fn message(payload: &[u8]) -> Vec<u8> {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(payload.len(), &mut prefix);
        let mut body = prefix[..plen].to_vec();
        body.extend_from_slice(payload);
        body
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
        struct Recorder(Arc<Mutex<Vec<(usize, usize)>>>);
        impl std::io::Write for Recorder {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap()
                    .push((data.as_ptr() as usize, data.len()));
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::proxy::FrameWrite for Recorder {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                let mut seen = self.0.lock().unwrap();
                for part in parts {
                    seen.push((part.as_ptr() as usize, part.len()));
                }
                true
            }
        }
        let payload: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let base = payload.as_ptr() as usize;
        let capacity = payload.capacity();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder(Arc::clone(&seen));
        let writer = GrpcWriter {
            shared: Arc::new(Shared {
                stream: Mutex::new(Box::new(recorder) as Box<dyn crate::proxy::FrameWrite + Send>),
                send: Mutex::new(SendWindow {
                    conn: u64::MAX,
                    stream: u64::MAX,
                }),
                wake: Condvar::new(),
                max_frame: Mutex::new(usize::MAX),
                init: Mutex::new(u64::from(WINDOW)),
                ended: AtomicBool::new(false),
                dead: AtomicBool::new(false),
            }),
            stream: 1,
        };
        assert!(writer.send(&payload));
        // The payload reached the frame writer as a slice whose base is the caller's own buffer, so a `writev` carries it and no byte is staged through a second `Vec`.
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|&(at, len)| at == base && len == payload.len()),
            "the payload was handed by pointer, not staged through a buffer"
        );
        assert_eq!(payload.as_ptr() as usize, base, "the caller's buffer moved");
        assert_eq!(payload.capacity(), capacity, "the caller's buffer grew");
    }

    /// The same buffer answers every frame: a body the size of the one before it is appended in place, so no message pays a reallocation of the bytes still live in it.
    #[test]
    fn the_message_buffer_is_reused_not_reallocated() {
        let mut reader = dial(&[
            (0, message(b"ping")),
            (0, message(b"pong")),
            (F_END, message(b"last")),
        ]);
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).expect("reads two");
        assert_eq!(&buf, b"pingpong");
        let cap = reader.msg.capacity();
        assert!(cap > 0, "the body landed somewhere");
        reader.read_exact(&mut buf[..4]).expect("reads the third");
        assert_eq!(&buf[..4], b"last");
        assert_eq!(reader.msg.capacity(), cap, "a same-sized body reallocated");
    }

    /// A padded frame is the one shape the lane still moves bytes for: the pad byte and tail sit inside the body the parser reads — counting it also proves the counter above can count.
    #[test]
    fn a_padded_frame_is_the_one_move_the_lane_still_makes() {
        let mut body = vec![3u8];
        body.extend_from_slice(&message(b"ping"));
        body.extend_from_slice(&[0xA5; 3]);
        let mut reader = dial(&[(F_PADDED | F_END, body)]);
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"ping");
        assert_eq!(
            reader.staged,
            message(b"ping").len(),
            "the pad removal moves the message bytes and nothing else"
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

                let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
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
                    assert!(writer.message(&data, true), "max {max} len {len}");
                });
                let mut read = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/TunnelService/Tun").is_none());
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (_, writer) = connect(stream, "127.0.0.1", "/other/Tun").expect("dials");
        drop(writer);
        server.join().expect("joins");
    }
}
