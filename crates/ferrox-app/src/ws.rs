use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ferrox_core::transport::early_decode;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const HEAD_LIMIT: usize = 16 * 1024;
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
const OP_DATA: u8 = 0x02;
const OP_CONT: u8 = 0x00;
const OP_CLOSE: u8 = 0x08;
const OP_PING: u8 = 0x09;
const OP_PONG: u8 = 0x0A;
const CLOSE_BODY: [u8; 2] = [0x03, 0xE8];

fn accept_key(key: &str) -> String {
    use sha1::Digest as _;
    let mut hash = sha1::Sha1::new();
    hash.update(key.trim().as_bytes());
    hash.update(GUID.as_bytes());
    ferrox_core::b64::encode(&hash.finalize())
}

fn fresh_key() -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    Some(ferrox_core::b64::encode(&raw))
}

/// The pass width the `avx2` rung takes: four bytes of mask times eight, so the narrow ladder it hands the remainder to starts a payload phase at zero.
#[cfg(target_arch = "x86_64")]
const WIDE_PASS: usize = 32;

fn apply_mask(buf: &mut [u8], mask: [u8; 4]) {
    #[cfg(target_arch = "x86_64")]
    if buf.len() >= WIDE_PASS && std::is_x86_feature_detected!("avx2") {
        unsafe { mask_wide(buf, mask) };
        return;
    }
    mask_narrow(buf, mask);
}

/// One `ymm` per pass: a load, an xor and a store per thirty-two bytes, half what the sixteen-byte ladder spends on the same span. The remainder is below one wide pass, so it goes to that ladder whole.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mask_wide(buf: &mut [u8], mask: [u8; 4]) {
    use core::arch::x86_64::{
        _mm256_loadu_si256, _mm256_set1_epi32, _mm256_storeu_si256, _mm256_xor_si256,
    };
    let wide = _mm256_set1_epi32(i32::from_le_bytes(mask));
    let (passes, rest) = buf.as_chunks_mut::<WIDE_PASS>();
    for pass in passes {
        unsafe {
            let data = _mm256_loadu_si256(pass.as_ptr().cast());
            _mm256_storeu_si256(pass.as_mut_ptr().cast(), _mm256_xor_si256(data, wide));
        }
    }
    mask_narrow(rest, mask);
}

fn mask_narrow(buf: &mut [u8], mask: [u8; 4]) {
    let wide = [
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3], mask[0], mask[1],
        mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ];
    let (blocks, rest) = buf.as_chunks_mut::<64>();
    for block in blocks {
        let lanes = block.as_chunks_mut::<16>().0;
        xor_block(&mut lanes[0], &wide);
        xor_block(&mut lanes[1], &wide);
        xor_block(&mut lanes[2], &wide);
        xor_block(&mut lanes[3], &wide);
    }
    let (chunks, tail) = rest.as_chunks_mut::<16>();
    for chunk in chunks {
        xor_block(chunk, &wide);
    }
    for (i, byte) in tail.iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
}

#[allow(
    clippy::inline_always,
    reason = "load-bearing: keeps the vector op inlined at every call site"
)]
#[inline(always)]
fn xor_block(chunk: &mut [u8; 16], wide: &[u8; 16]) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
        unsafe {
            let data = _mm_loadu_si128(chunk.as_ptr().cast());
            let key = _mm_loadu_si128(wide.as_ptr().cast());
            _mm_storeu_si128(chunk.as_mut_ptr().cast(), _mm_xor_si128(data, key));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::{veorq_u8, vld1q_u8, vst1q_u8};
        unsafe {
            let data = vld1q_u8(chunk.as_ptr());
            let key = vld1q_u8(wide.as_ptr());
            vst1q_u8(chunk.as_mut_ptr(), veorq_u8(data, key));
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        for (byte, key) in chunk.iter_mut().zip(wide.iter()) {
            *byte ^= *key;
        }
    }
}

fn fresh_mask() -> Option<[u8; 4]> {
    thread_local! {
        static BATCH: RefCell<([u8; 2048], usize)> = const { RefCell::new(([0u8; 2048], 2048)) };
    }
    BATCH
        .try_with(|cell| {
            let (buf, at) = &mut *cell.borrow_mut();
            if *at + 4 > buf.len() {
                getrandom::getrandom(&mut buf[..]).ok()?;
                *at = 0;
            }
            let mask: [u8; 4] = buf[*at..*at + 4].try_into().ok()?;
            *at += 4;
            Some(mask)
        })
        .ok()?
}

fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT, crate::budgets::head_arrival())
}

struct Shared {
    stream: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// Bytes one read asks for: a header and its payload cost one syscall; a mid-frame read is finished by the next.
const READ_AHEAD: usize = 32 * 1024;

#[derive(Debug)]
pub(crate) struct WsReader<R: Read = TcpStream> {
    read: R,
    shared: Arc<Shared>,
    /// Socket bytes this reader has taken but not yet parsed or delivered.
    have: Vec<u8>,
    /// Cursor into `have`; `have[at..]` is what is left.
    at: usize,
    /// End of the message being delivered, so a small `read` returns part and the rest stays.
    msg_end: usize,
    early: Vec<u8>,
    eat: usize,
    eof: bool,
    /// Wall-clock end of the opening handshake: past it an idle socket is death, not a round to retry.
    handshake: Option<std::time::Instant>,
    #[cfg_attr(not(test), allow(dead_code, reason = "read by the syscall gate"))]
    reads: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct WsWriter {
    shared: Arc<Shared>,
    masked: bool,
}

impl WsReader<TcpStream> {
    /// Arm or clear the poll quantum on the handle this reader reads through; a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R: Read> WsReader<R> {
    /// Arm or clear the handshake budget; only the opening decode runs armed, relays wait blocking again.
    pub(crate) fn set_handshake_budget(&mut self, until: Option<std::time::Instant>) {
        self.handshake = until;
    }

    /// At least `len` unparsed bytes, or false once the socket is done.
    fn need(&mut self, len: usize) -> bool {
        while self.have.len() - self.at < len {
            if self.eof || !self.pull(len) {
                return false;
            }
        }
        true
    }

    /// One syscall; the buffer grows only past the window and frames unmask in place. `False` means done.
    fn pull(&mut self, len: usize) -> bool {
        if self.at > 0 {
            self.have.copy_within(self.at.., 0);
            self.have.truncate(self.have.len() - self.at);
            self.msg_end = self.msg_end.saturating_sub(self.at);
            self.at = 0;
        }
        let room = READ_AHEAD.max(len);
        if self.have.capacity() - self.have.len() < room {
            self.have.reserve(room);
        }
        let base = self.have.len();
        unsafe {
            self.have.set_len(base + room);
        }
        let taken = loop {
            match self.read.read(&mut self.have[base..]) {
                Ok(0) => {
                    self.have.truncate(base);
                    self.eof = true;
                    break 0;
                }
                Ok(n) => break n,
                Err(error) if crate::proxy::is_timeout(&error) => {
                    if self
                        .handshake
                        .is_some_and(|until| std::time::Instant::now() >= until)
                    {
                        self.have.truncate(base);
                        self.eof = true;
                        break 0;
                    }
                }
                Err(_) => {
                    self.have.truncate(base);
                    self.eof = true;
                    break 0;
                }
            }
        };
        self.reads += 1;
        self.have.truncate(base + taken);
        taken > 0
    }

    /// Parse frames until a message ends: control frames answered on the spot, data unmasked where they lie.
    fn message(&mut self) -> bool {
        let mut open = false;
        loop {
            if !self.need(2) {
                return false;
            }
            let head = [self.have[self.at], self.have[self.at + 1]];
            self.at += 2;
            let fin = head[0] & 0x80 != 0;
            let opcode = head[0] & 0x0F;
            let masked = head[1] & 0x80 != 0;
            let marker = usize::from(head[1] & 0x7F);
            let ext_len = if marker == 126 {
                2
            } else if marker == 127 {
                8
            } else {
                0
            };
            let rest = ext_len + usize::from(masked) * 4;
            if !self.need(rest) {
                return false;
            }
            let mut len = marker;
            if marker == 126 {
                let at = self.at;
                len = usize::from(u16::from_be_bytes([self.have[at], self.have[at + 1]]));
            } else if marker == 127 {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&self.have[self.at..self.at + 8]);
                let Ok(wide) = usize::try_from(u64::from_be_bytes(raw)) else {
                    return false;
                };
                len = wide;
            }
            if len > FRAME_LIMIT || (opcode & 0x08 != 0 && (len > 125 || !fin)) {
                return false;
            }
            let mask = if masked {
                let at = self.at + ext_len;
                let mask = [
                    self.have[at],
                    self.have[at + 1],
                    self.have[at + 2],
                    self.have[at + 3],
                ];
                Some(mask)
            } else {
                None
            };
            self.at += rest;
            if !self.need(len) {
                return false;
            }
            let start = self.at;
            let payload = start..start + len;
            self.at += len;
            match opcode {
                OP_CLOSE => {
                    self.reply(OP_CLOSE, &self.have[payload]);
                    return false;
                }
                OP_PING => self.reply(OP_PONG, &self.have[payload]),
                OP_PONG => {}
                OP_DATA | OP_CONT => {
                    if (opcode == OP_CONT) != open {
                        return false;
                    }
                    if let Some(mask) = mask {
                        apply_mask(&mut self.have[payload], mask);
                    }
                    if fin {
                        self.msg_end = self.at;
                        self.at = start;
                        return true;
                    }
                    open = true;
                }
                _ => return false,
            }
        }
    }

    fn reply(&self, opcode: u8, payload: &[u8]) {
        if opcode == OP_CLOSE && self.shared.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = write_frame(&mut **stream, false, opcode, payload);
    }

    /// Syscalls spent: the header parses out of the window, so one read covers `READ_AHEAD` bytes.
    #[cfg(test)]
    pub(crate) fn reads(&self) -> usize {
        self.reads
    }
}

impl<R: Read> Read for WsReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.eat < self.early.len() {
            let n = (self.early.len() - self.eat).min(buf.len());
            buf[..n].copy_from_slice(&self.early[self.eat..self.eat + n]);
            self.eat += n;
            return Ok(n);
        }
        loop {
            if self.at < self.msg_end {
                let n = (self.msg_end - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.have[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            self.early.clear();
            self.eat = 0;
            if !self.message() {
                self.eof = true;
                return Ok(0);
            }
        }
    }
}

impl WsWriter {
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut **stream, self.masked, OP_DATA, data)
    }

    pub(crate) fn close(&self) {
        if self.shared.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = write_frame(&mut **stream, self.masked, OP_CLOSE, &CLOSE_BODY);
    }
}

impl Write for WsWriter {
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

thread_local! {
    static MASKED_FRAME: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn write_frame(
    stream: &mut dyn crate::proxy::FrameWrite,
    masked: bool,
    opcode: u8,
    data: &[u8],
) -> bool {
    let flag: u8 = if masked { 0x80 } else { 0 };
    let mut head = [0u8; 10];
    head[0] = 0x80 | (opcode & 0x0F);
    let hlen = if data.len() < 126 {
        head[1] = flag | data.len() as u8;
        2
    } else if u16::try_from(data.len()).is_ok() {
        head[1] = flag | 0x7E;
        head[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        4
    } else {
        head[1] = flag | 0x7F;
        head[2..10].copy_from_slice(&(data.len() as u64).to_be_bytes());
        10
    };
    if !masked {
        return stream.write_slices(&[&head[..hlen], data]);
    }
    let Some(mask) = fresh_mask() else {
        return false;
    };
    MASKED_FRAME.with(|cell| {
        let mut frame = cell.borrow_mut();
        frame.clear();
        frame.reserve(hlen + 4 + data.len());
        frame.extend_from_slice(&head[..hlen]);
        frame.extend_from_slice(&mask);
        let base = frame.len();
        frame.extend_from_slice(data);
        apply_mask(&mut frame[base..], mask);
        stream.write_all(&frame).is_ok()
    })
}

pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(WsReader, WsWriter)> {
    use std::fmt::Write as _;
    let mut read = stream;
    let head = read_head(&mut read)?;
    let (key, early) = check_request(&head, path)?;
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        accept_key(key)
    );
    if !early.is_empty() {
        let offered =
            crate::proxy::header_value(&head, "sec-websocket-protocol").unwrap_or_default();
        let _ = write!(response, "Sec-WebSocket-Protocol: {offered}\r\n");
    }
    response.push_str("\r\n");
    read.write_all(response.as_bytes()).ok()?;
    split(read, early, false)
}

fn check_request<'a>(head: &'a [u8], path: &str) -> Option<(&'a str, Vec<u8>)> {
    if crate::proxy::request_path(head)? != path {
        return None;
    }
    let key = crate::proxy::header_value(head, "sec-websocket-key")?;
    if key.is_empty() {
        return None;
    }
    let offered = crate::proxy::header_value(head, "sec-websocket-protocol").unwrap_or_default();
    let early = early_decode(offered)
        .filter(|bytes| !bytes.is_empty())
        .unwrap_or_default();
    Some((key, early))
}

// The same accept over halves that cannot peek: pipelined bytes arrive as a prefix, after the early data.
pub(crate) fn accept_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    path: &str,
) -> Option<(WsReader<R>, WsWriter)> {
    use std::fmt::Write as _;
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    let (key, mut early) = check_request(&head, path)?;
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        accept_key(key)
    );
    if !early.is_empty() {
        let offered =
            crate::proxy::header_value(&head, "sec-websocket-protocol").unwrap_or_default();
        let _ = write!(response, "Sec-WebSocket-Protocol: {offered}\r\n");
    }
    response.push_str("\r\n");
    write.write_all(response.as_bytes()).ok()?;
    early.extend_from_slice(&prefix);
    Some(split_halves(read, write, early, false))
}

pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(WsReader, WsWriter)> {
    let key = fresh_key()?;
    let mut read = stream;
    let (handshake, early) = request(host, path, &key, budget, first);
    read.write_all(handshake.as_bytes()).ok()?;
    let head = read_head(&mut read)?;
    check_response(&head, &key)?;
    let at = crate::proxy::find_double_crlf(&head)? + 4;
    let mut behind = Vec::new();
    behind.extend_from_slice(&head[at..]);
    let (reader, writer) = split(read, behind, true)?;
    if !early && !first.is_empty() && !writer.send(first) {
        return None;
    }
    Some((reader, writer))
}

fn check_response(head: &[u8], key: &str) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    if text.split("\r\n").next()?.split(' ').nth(1)? != "101" {
        return None;
    }
    if crate::proxy::header_value(head, "sec-websocket-accept")? != accept_key(key) {
        return None;
    }
    Some(())
}

// The same connect over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(WsReader<R>, WsWriter)> {
    let key = fresh_key()?;
    let (handshake, early) = request(host, path, &key, budget, first);
    write.write_all(handshake.as_bytes()).ok()?;
    let (head, behind) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head, &key)?;
    let (reader, writer) = split_halves(read, write, behind, true);
    if !early && !first.is_empty() && !writer.send(first) {
        return None;
    }
    Some((reader, writer))
}

fn request(host: &str, path: &str, key: &str, budget: u32, first: &[u8]) -> (String, bool) {
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let early = !first.is_empty() && first.len() as u64 <= u64::from(budget);
    if early {
        request.truncate(request.len() - 2);
        request.push_str("Sec-WebSocket-Protocol: ");
        ferrox_core::transport::early_encode_into(&mut request, first);
        request.push_str("\r\n\r\n");
    }
    (request, early)
}

fn split(read: TcpStream, early: Vec<u8>, masked: bool) -> Option<(WsReader, WsWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some(split_halves(read, write, early, masked))
}

// The same split over halves that cannot clone: the handshake leaves pipelined bytes as the prefix.
fn split_halves<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    early: Vec<u8>,
    masked: bool,
) -> (WsReader<R>, WsWriter) {
    let shared = Arc::new(Shared {
        stream: Mutex::new(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>),
        closed: AtomicBool::new(false),
    });
    let reader = WsReader {
        read,
        shared: Arc::clone(&shared),
        have: Vec::new(),
        at: 0,
        msg_end: 0,
        early,
        eat: 0,
        eof: false,
        handshake: None,
        reads: 0,
    };
    (reader, WsWriter { shared, masked })
}

impl crate::proxy::CarrierSink for WsWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn close(&self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrox_core::transport::EarlyData;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn accept_matches_the_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn mask_chunks_match_the_byte_loop() {
        for len in [
            0, 1, 3, 4, 5, 15, 16, 17, 31, 32, 33, 48, 49, 63, 64, 65, 80, 81, 127, 128, 129, 191,
            192, 255, 256, 1024, 4096, 8192,
        ] {
            for mask in [[0u8, 0, 0, 0], [1, 2, 3, 4], [0xFF, 0x00, 0xA5, 0x5A]] {
                let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut want = plain.clone();
                for (i, byte) in want.iter_mut().enumerate() {
                    *byte ^= mask[i & 3];
                }
                let mut got = plain.clone();
                apply_mask(&mut got, mask);
                assert_eq!(got, want, "len {len} mask {mask:?}");
                apply_mask(&mut got, mask);
                assert_eq!(got, plain, "len {len} unmasks");
            }
        }
    }

    /// The head, then the mask, then the payload xorved at the mask's own four-byte phase: bytes are rebuilt from the frame's own mask, so a rotated mask or a mis-encoded head fails here rather than in a reader that would undo both.
    #[test]
    fn a_masked_frame_is_its_head_then_its_mask_then_its_payload_at_four() {
        for len in [
            0usize, 1, 2, 3, 4, 5, 15, 16, 17, 125, 126, 127, 128, 200, 4095, 4096, 65_535, 65_536,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let mut sink = Sink {
                capture: true,
                ..Sink::default()
            };
            assert!(write_frame(&mut sink, true, OP_DATA, &payload), "len {len}");
            let got = std::mem::take(&mut sink.kept);
            let hlen = if len < 126 {
                2
            } else if len <= 65_535 {
                4
            } else {
                10
            };
            assert_eq!(got.len(), hlen + 4 + len, "len {len}: head, mask, payload");
            let (head, rest) = got.split_at(hlen);
            let (mask, coded) = rest.split_at(4);
            assert_eq!(head[0], 0x80 | OP_DATA, "len {len}: FIN and the opcode");
            assert_eq!(head[1] & 0x80, 0x80, "len {len}: the MASK bit is set");
            let marker = head[1] & 0x7F;
            let read = match marker {
                126 => u16::from_be_bytes(head[2..4].try_into().expect("two bytes")) as u64,
                127 => {
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(&head[2..10]);
                    u64::from_be_bytes(raw)
                }
                short => u64::from(short),
            };
            assert_eq!(read, len as u64, "len {len}: the length is in the head");
            for (i, (byte, plain)) in coded.iter().zip(&payload).enumerate() {
                assert_eq!(
                    *byte,
                    plain ^ mask[i & 3],
                    "len {len} at byte {i}: the mask starts at the payload"
                );
            }
        }
    }

    /// The probe behind the masked-write ops row: the relay's 16 KiB chunk staged and written through an in-memory sink, so the frame is the walk over the payload with no socket, thread or checksum loop in it.
    #[test]
    fn the_masked_frame_costs_the_walk_over_its_payload_and_nothing_else() {
        const CHUNK: usize = 16 * 1024;
        const ROUNDS: usize = 16;
        let payload: Vec<u8> = (0..CHUNK).map(|i| (i as u8).wrapping_mul(37)).collect();
        let mut sink = Sink::default();
        let mut first_capacity = 0usize;
        for round in 0..ROUNDS {
            assert!(
                write_frame(&mut sink, true, OP_DATA, &payload),
                "round {round}"
            );
            let capacity = MASKED_FRAME.with(|cell| cell.borrow().capacity());
            if round == 0 {
                first_capacity = capacity;
            } else {
                assert_eq!(
                    capacity, first_capacity,
                    "round {round}: the staged frame holds its capacity, so no allocator is in the loop"
                );
            }
        }
        assert_eq!(sink.writes, ROUNDS, "one write per frame");
        assert_eq!(
            sink.bytes,
            ROUNDS * (CHUNK + 8),
            "a 16 KiB payload costs a four-byte head, a four-byte mask and itself"
        );
    }

    /// An in-memory `FrameWrite` for the two witnesses above: it counts the bytes it is handed and keeps them only when `capture` says to, so the probe's frame is the carrier's own staging and `black_box` keeps that from being dead-store-eliminated.
    #[derive(Default)]
    struct Sink {
        bytes: usize,
        writes: usize,
        kept: Vec<u8>,
        capture: bool,
    }

    impl Write for Sink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.bytes += data.len();
            self.writes += 1;
            if self.capture {
                self.kept.extend_from_slice(data);
            } else {
                std::hint::black_box(data);
            }
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

    #[test]
    fn frames_round_trip_masked_and_plain() {
        for len in [0, 1, 125, 126, 200, 65_535, 65_536] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for masked in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
                let port = listener.local_addr().expect("addr").port();
                let expected = payload.clone();
                let writer = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().expect("accepts");
                    assert!(write_frame(&mut stream, masked, OP_DATA, &expected));
                });
                let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
                let shared = Arc::new(Shared {
                    stream: Mutex::new(Box::new(stream.try_clone().expect("clones"))
                        as Box<dyn crate::proxy::FrameWrite + Send>),
                    closed: AtomicBool::new(false),
                });
                let mut reader = WsReader {
                    read: stream,
                    shared,
                    have: Vec::new(),
                    at: 0,
                    msg_end: 0,
                    early: Vec::new(),
                    eat: 0,
                    eof: false,
                    handshake: None,
                    reads: 0,
                };
                let mut whole = Vec::new();
                let mut buf = [0u8; 4096];
                while whole.len() < payload.len() {
                    let n = reader.read(&mut buf).expect("reads");
                    assert!(n > 0, "len {len} masked {masked}: no progress");
                    whole.extend_from_slice(&buf[..n]);
                }
                assert_eq!(whole, payload, "len {len} masked {masked}");
                writer.join().expect("joins");
            }
        }
    }

    /// A fixed source returns every byte asked for, so the syscall count is exact, not a race with the scheduler.
    #[test]
    fn a_read_covers_a_window_not_one_frame_header() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || listener.accept().expect("accepts").0);
        let _spare = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let shared = Arc::new(Shared {
            stream: Mutex::new(
                Box::new(server.join().expect("joins")) as Box<dyn crate::proxy::FrameWrite + Send>
            ),
            closed: AtomicBool::new(false),
        });
        let frames = 64usize;
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for i in 0..frames {
            let payload: Vec<u8> = (0..300 + i).map(|j| (j % 251) as u8).collect();
            wire.push(0x80u8 | OP_DATA);
            wire.push(126);
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(&payload);
            expected.extend_from_slice(&payload);
        }
        assert!(wire.len() < READ_AHEAD, "the fixture must fit one window");
        let mut reader = WsReader {
            read: std::io::Cursor::new(wire),
            shared,
            have: Vec::new(),
            at: 0,
            msg_end: 0,
            early: Vec::new(),
            eat: 0,
            eof: false,
            handshake: None,
            reads: 0,
        };
        let mut whole = Vec::new();
        let mut got = 0usize;
        let mut buf = [0u8; 997];
        while whole.len() < expected.len() {
            let n = reader.read(&mut buf).expect("reads");
            assert!(n > 0, "no progress at {got}");
            got += n;
            whole.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            &whole[..expected.len()],
            &expected[..],
            "{frames} frames delivered whole, in order"
        );
        assert!(
            whole.len() - expected.len() < 997 + 8,
            "only a partial frame header is left over, not payload"
        );
        assert_eq!(
            reader.reads(),
            1,
            "{frames} frames cost one read, not one per frame header"
        );
    }

    #[test]
    fn handshake_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let plain = EarlyData::split("/tunnel");
        let (mut reader, _writer) =
            connect(stream, "127.0.0.1", &plain.path, plain.budget, b"ping").expect("upgrades");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    #[test]
    fn early_data_adds_one_line_and_truncates_nothing() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let prefix = format!(
            "GET /tunnel HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        let plain = format!("{prefix}\r\n");
        assert_eq!(request("example.com", "/tunnel", key, 0, b"hello").0, plain);
        for (payload, budget, rides) in [
            (&b"hello"[..], 5u32, true),
            (&b"hello"[..], 4, false),
            (&b""[..], 2048, false),
            (&b"hi"[..], 2048, true),
            (&b"hi"[..], 2, true),
            (&b"hi"[..], 1, false),
        ] {
            let (got, early) = request("example.com", "/tunnel", key, budget, payload);
            assert_eq!(early, rides, "{payload:?} at {budget}");
            if !rides {
                assert_eq!(got, plain, "{payload:?} at {budget}: no line at all");
                continue;
            }
            let mut line = String::from("Sec-WebSocket-Protocol: ");
            ferrox_core::transport::early_encode_into(&mut line, payload);
            line.push_str("\r\n");
            assert_eq!(
                got,
                format!("{prefix}{line}\r\n"),
                "{payload:?} at {budget}"
            );
        }
    }

    #[test]
    fn early_data_reaches_the_server_with_and_without_a_budget_that_fits() {
        for budget in [2048u32, 4, 3] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let configured = EarlyData::split(&format!("/tunnel?ed={budget}"));
                assert_eq!(configured.budget, budget);
                let (mut reader, _writer) = accept(stream, &configured.path).expect("upgrades");
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf).expect("reads");
                assert_eq!(&buf, b"ping");
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let configured = EarlyData::split(&format!("/tunnel?ed={budget}"));
            connect(
                stream,
                "127.0.0.1",
                &configured.path,
                configured.budget,
                b"ping",
            )
            .expect("upgrades");
            server.join().expect("joins");
        }
    }

    #[test]
    fn a_configured_budget_serves_the_bare_path() {
        for path in ["/interop-ws?ed=2048", "/interop-ws"] {
            assert_eq!(EarlyData::split(path).path, "/interop-ws", "{path}");
        }
        assert_eq!(EarlyData::split("/interop-ws?ed=").path, "/interop-ws?ed=");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let configured = EarlyData::split("/interop-ws?ed=2048");
            assert!(accept(stream, &configured.path).is_some());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /interop-ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Key: aGVsbG8gd29ybGQxMjM0NQ==\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }

    #[test]
    fn handshake_rejects_a_wrong_path_and_key() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: k\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
