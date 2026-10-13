// xHTTP over HTTP/2: one connection multiplexes many requests the way many TCP connections would — each stream is one GET, POST or packet — and the H1 dispatch is reused byte for byte, headers re-serialized into the H1-style head the same validators read and the response head parsed back into H2 HEADERS.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::h2::{
    block_encode, read_head, write_frame, Decoder, E_FRAME_SIZE, E_PROTOCOL, E_REFUSED, F_ACK,
    F_END, F_END_HEADERS, F_PADDED, F_PRIORITY, HEAD_CAP, MAGIC, S_MAX_FRAME, S_WINDOW, T_CONT,
    T_DATA, T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS, T_WINDOW, WINDOW,
};
use crate::xhttp::XhttpSettings;

const CONN_WINDOW_TOP_UP: u32 = 16 * 1024 * 1024 - 65_535;
const MAX_STREAMS: u32 = 100;
/// The default `SETTINGS_MAX_FRAME_SIZE` (RFC 7540 6.5.2): the largest inbound frame we accept because we never advertise a larger one.
const MAX_RECV_FRAME: usize = 16_384;

#[derive(Debug, Clone)]
pub(crate) struct H2StreamOut {
    conn: Arc<H2Conn>,
    stream: u32,
}

impl H2StreamOut {
    pub(crate) fn data(&self, payload: &[u8]) -> bool {
        self.conn.send_data(self.stream, payload)
    }

    pub(crate) fn end(&self) {
        self.conn.end_stream(self.stream);
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

struct H2Conn {
    write: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    streams: Mutex<HashMap<u32, Arc<H2Stream>>>,
    send_conn: Mutex<u64>,
    wake: Condvar,
    decoder: Mutex<Decoder>,
    max_frame: Mutex<usize>,
    peer_initial: Mutex<u64>,
    dead: AtomicBool,
    goaway: AtomicBool,
}

impl std::fmt::Debug for H2Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Conn").finish_non_exhaustive()
    }
}

struct H2StreamReader {
    conn: Arc<H2Conn>,
    stream: Arc<H2Stream>,
    id: u32,
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
            if let Some(front) = st.body.front_mut() {
                let n = front.len().min(buf.len());
                buf[..n].copy_from_slice(&front[..n]);
                if n == front.len() {
                    st.body.pop_front();
                } else {
                    front.drain(..n);
                }
                drop(st);
                self.conn.replenish(self.id, n);
                return Ok(n);
            }
            if st.ended {
                return Ok(0);
            }
            if st.dead || self.conn.dead.load(Ordering::SeqCst) {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            st = self
                .stream
                .cv
                .wait(st)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

struct H2StreamWriter {
    conn: Arc<H2Conn>,
    stream: u32,
    head: Vec<u8>,
    headed: bool,
}

impl H2StreamWriter {
    fn emit_headers(&mut self, head: &[u8]) -> bool {
        let text = std::str::from_utf8(head).unwrap_or_default();
        let mut lines = text.split("\r\n");
        let status = lines
            .next()
            .unwrap_or_default()
            .split_ascii_whitespace()
            .nth(1)
            .unwrap_or("200");
        let mut headers = vec![(":status", status)];
        for line in lines {
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if [
                "content-length",
                "transfer-encoding",
                "connection",
                "keep-alive",
            ]
            .contains(&name.to_ascii_lowercase().as_str())
            {
                continue;
            }
            headers.push((name.trim(), value.trim()));
        }
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
            if let Some(at) = self.head.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = std::mem::take(&mut self.head);
                if !self.emit_headers(&head[..at + 4]) {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                }
                let body = head[at + 4..].to_vec();
                if !body.is_empty() && !self.conn.send_data(self.stream, &body) {
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

    fn send_data(&self, stream: u32, mut payload: &[u8]) -> bool {
        while !payload.is_empty() {
            let max = *self
                .max_frame
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let chunk = {
                let mut conn = self
                    .send_conn
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                loop {
                    if self.dead.load(Ordering::SeqCst) {
                        return false;
                    }
                    let window = self
                        .streams
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get(&stream)
                        .map(|s| *s.send_window.lock().unwrap_or_else(PoisonError::into_inner));
                    let Some(window) = window else {
                        return false;
                    };
                    let take = (payload.len().min(max) as u64).min(*conn).min(window);
                    if take > 0 {
                        *conn -= take;
                        drop(conn);
                        let streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
                        if let Some(state) = streams.get(&stream) {
                            let mut w = state
                                .send_window
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner);
                            *w -= take;
                        }
                        break take as usize;
                    }
                    conn = self.wake.wait(conn).unwrap_or_else(PoisonError::into_inner);
                }
            };
            if !self.frame(T_DATA, 0, stream, &payload[..chunk]) {
                return false;
            }
            payload = &payload[chunk..];
        }
        true
    }

    fn replenish(&self, stream: u32, n: usize) {
        if n == 0 || n > u32::MAX as usize {
            return;
        }
        let n = n as u32;
        // Consuming inbound bytes grants the peer more credit; our own send windows rise only from the peer's WINDOW_UPDATE, so crediting them here would let a bulk send outrun the window the peer gave and trip its flow control.
        let _ = self.frame(T_WINDOW, 0, 0, &n.to_be_bytes());
        let _ = self.frame(T_WINDOW, 0, stream, &n.to_be_bytes());
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
        {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(state) = streams.remove(&stream) {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                st.dead = true;
                state.cv.notify_all();
            }
        }
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

fn synth_head(
    method: &[u8],
    target: &[u8],
    headers: &[(Vec<u8>, Vec<u8>)],
    end_stream: bool,
) -> Vec<u8> {
    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(method);
    head.push(b' ');
    head.extend_from_slice(target);
    head.extend_from_slice(b" HTTP/2\r\n");
    for (name, value) in headers {
        if name.first() == Some(&b':') {
            continue;
        }
        head.extend_from_slice(name);
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    if !end_stream {
        head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

fn header<'a>(headers: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find_map(|(k, v)| k.eq_ignore_ascii_case(name).then_some(v.as_slice()))
}

fn open_stream(
    conn: &Arc<H2Conn>,
    settings: &XhttpSettings,
    id: [u8; 16],
    freedom: bool,
    sid: u32,
    block: &[u8],
    end_stream: bool,
) {
    let headers = {
        let mut decoder = conn.decoder.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = Vec::new();
        let ok = decoder.decode(block, &mut out).is_some();
        drop(decoder);
        if !ok {
            conn.reset_stream(sid);
            return;
        }
        out
    };
    let (Some(method), Some(target)) = (header(&headers, b":method"), header(&headers, b":path"))
    else {
        conn.reset_stream(sid);
        return;
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
    let head = synth_head(method, target, &headers, end_stream);
    let reader = H2StreamReader {
        conn: Arc::clone(conn),
        stream: Arc::clone(&state),
        id: sid,
    };
    let h2out = H2StreamOut {
        conn: Arc::clone(conn),
        stream: sid,
    };
    let writer = H2StreamWriter {
        conn: Arc::clone(conn),
        stream: sid,
        head: Vec::new(),
        headed: false,
    };
    let settings = settings.clone();
    std::thread::spawn(move || {
        match crate::xhttp::accept_core(
            &head,
            Vec::new(),
            reader,
            writer,
            &settings,
            Some(h2out.clone()),
        ) {
            Some((ureader, xwriter)) => {
                crate::proxy::serve_session_xhttp_with(ureader, &xwriter, &id, freedom);
            }
            None => h2out.end(),
        }
    });
}

pub(crate) fn serve_h2<R: Read + Send + 'static, W: crate::proxy::FrameWrite + Send + 'static>(
    mut read: R,
    write: W,
    settings: &XhttpSettings,
    id: [u8; 16],
    freedom: bool,
) {
    let mut magic = [0u8; 24];
    if crate::proxy::read_exact(&mut read, &mut magic).is_err() || magic != *MAGIC {
        return;
    }
    let conn = Arc::new(H2Conn {
        write: Mutex::new(Box::new(write)),
        streams: Mutex::new(HashMap::new()),
        send_conn: Mutex::new(65_535),
        wake: Condvar::new(),
        decoder: Mutex::new(Decoder::default()),
        max_frame: Mutex::new(16_384),
        peer_initial: Mutex::new(65_535),
        dead: AtomicBool::new(false),
        goaway: AtomicBool::new(false),
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
        // A frame past the default SETTINGS_MAX_FRAME_SIZE is a connection error (RFC 7540 6.9.1): refuse it before reserving its length or blocking on a body that may never arrive.
        if len > MAX_RECV_FRAME {
            let mut goaway = [0u8; 8];
            goaway[4..].copy_from_slice(&E_FRAME_SIZE.to_be_bytes());
            conn.frame(T_GOAWAY, 0, 0, &goaway);
            break;
        }
        let mut body = vec![0u8; len];
        if crate::proxy::read_exact(&mut read, &mut body).is_err() {
            break;
        }
        if !pump_frame(
            &conn, settings, id, freedom, kind, flags, sid, &body, &mut frag,
        ) {
            break;
        }
    }
    conn.kill();
    conn.wake.notify_all();
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one arm per frame kind; splitting the dispatcher would scatter the protocol"
)]
fn pump_frame(
    conn: &Arc<H2Conn>,
    settings: &XhttpSettings,
    id: [u8; 16],
    freedom: bool,
    kind: u8,
    flags: u8,
    sid: u32,
    body: &[u8],
    frag: &mut Option<(u32, Vec<u8>)>,
) -> bool {
    match kind {
        T_SETTINGS => {
            if flags & F_ACK == 0 {
                if !body.len().is_multiple_of(6) {
                    return false;
                }
                conn.apply_settings(body);
            }
            true
        }
        T_PING => {
            if flags & F_ACK == 0 && body.len() == 8 {
                conn.frame(T_PING, F_ACK, 0, body);
            }
            true
        }
        T_WINDOW => {
            if body.len() != 4 {
                return true;
            }
            let inc =
                u64::from(u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7FFF_FFFF);
            if inc == 0 {
                return true;
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
            true
        }
        T_HEADERS => {
            if sid == 0 || sid.is_multiple_of(2) {
                return true;
            }
            let mut block = body.to_vec();
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
                open_stream(conn, settings, id, freedom, sid, &block, end_stream);
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
                    let mut goaway = [0u8; 8];
                    goaway[4..].copy_from_slice(&E_PROTOCOL.to_be_bytes());
                    conn.frame(T_GOAWAY, 0, 0, &goaway);
                    return false;
                }
                gathered.extend_from_slice(body);
                if flags & F_END_HEADERS != 0 {
                    open_stream(conn, settings, id, freedom, sid, &gathered, false);
                } else {
                    *frag = Some((sid, gathered));
                }
            }
            true
        }
        T_DATA => {
            let mut payload = body;
            if flags & F_PADDED != 0 {
                let Some(&len) = payload.first() else {
                    return true;
                };
                payload = payload
                    .get(1..payload.len().saturating_sub(len as usize))
                    .unwrap_or_default();
            }
            let streams = conn.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(state) = streams.get(&sid).cloned() else {
                drop(streams);
                conn.replenish(sid, payload.len());
                return true;
            };
            drop(streams);
            {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                if !st.dead {
                    st.body.push_back(payload.to_vec());
                    if flags & F_END != 0 {
                        st.ended = true;
                    }
                }
                state.cv.notify_all();
            }
            conn.replenish(sid, payload.len());
            true
        }
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
    use crate::h2::MAGIC;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    struct H2Client {
        stream: TcpStream,
        next: u32,
        decoder: Decoder,
    }

    impl H2Client {
        fn connect(addr: SocketAddr) -> Self {
            let mut stream = TcpStream::connect(addr).expect("connects");
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
            };
            for _ in 0..3 {
                let (len, kind, flags, _) = read_head(&mut conn.stream).expect("frame");
                let mut body = vec![0u8; len];
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

        fn response_head(&mut self, id: u32) -> u16 {
            let mut block = Vec::new();
            loop {
                let (len, kind, flags, got) = read_head(&mut self.stream).expect("frame");
                let mut frame = vec![0u8; len];
                crate::proxy::read_exact(&mut self.stream, &mut frame).expect("body");
                match kind {
                    T_HEADERS if got == id => {
                        block.extend_from_slice(&frame);
                        if flags & F_END_HEADERS != 0 {
                            let mut fields = Vec::new();
                            self.decoder.decode(&block, &mut fields).expect("decodes");
                            for (name, value) in &fields {
                                if name == b":status" {
                                    return std::str::from_utf8(value)
                                        .unwrap_or_default()
                                        .parse()
                                        .unwrap_or(0);
                                }
                            }
                            return 0;
                        }
                    }
                    T_PING if flags & F_ACK == 0 && frame.len() == 8 => {
                        write_frame(&mut self.stream, T_PING, F_ACK, 0, &frame);
                    }
                    _ => {}
                }
            }
        }

        fn response_data(&mut self, id: u32, n: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                let (len, kind, flags, got) = read_head(&mut self.stream).expect("frame");
                let mut frame = vec![0u8; len];
                crate::proxy::read_exact(&mut self.stream, &mut frame).expect("body");
                match kind {
                    T_DATA if got == id => {
                        let take = (n - out.len()).min(frame.len());
                        out.extend_from_slice(&frame[..take]);
                        let _ = flags;
                    }
                    T_PING if flags & F_ACK == 0 && frame.len() == 8 => {
                        write_frame(&mut self.stream, T_PING, F_ACK, 0, &frame);
                    }
                    T_RST if got == id => panic!("stream reset"),
                    _ => {}
                }
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
                let mut body = vec![0u8; len];
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
    fn fill(stream: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
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
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            for stream in front.incoming().take(takes) {
                let Ok(stream) = stream else { continue };
                let Ok(read) = stream.try_clone() else {
                    continue;
                };
                let settings = settings.clone();
                thread::spawn(move || serve_h2(read, stream, &settings, id, true));
            }
        });
        (addr, handle)
    }

    fn padding() -> String {
        format!("http://127.0.0.1/up/?x_padding={}", "X".repeat(128))
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
        let mut body = vec![0u8; len];
        assert!(fill(&mut client.stream, &mut body).is_some(), "goaway body");
        assert_eq!(
            u32::from_be_bytes(body[4..8].try_into().unwrap()),
            E_FRAME_SIZE,
            "the GOAWAY must carry FRAME_SIZE_ERROR"
        );
        drop(client);
        let _ = server;
    }

    /// Endless CONTINUATION frames for one stream must not grow a header block past `HEAD_CAP`: the reassembly is refused with a GOAWAY rather than accumulated without bound.
    #[test]
    fn a_header_block_reassembled_past_the_cap_refuses_the_connection() {
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
            "the server neither opened the stream nor refused the over-long block"
        );
        assert_eq!(got[3], T_GOAWAY, "expected a GOAWAY");
        let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
        let mut body = vec![0u8; len];
        assert!(fill(&mut client.stream, &mut body).is_some(), "goaway body");
        assert_eq!(
            u32::from_be_bytes(body[4..8].try_into().unwrap()),
            E_PROTOCOL,
            "the GOAWAY must carry PROTOCOL_ERROR"
        );
        drop(client);
        let _ = server;
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
}
