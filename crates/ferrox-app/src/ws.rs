use std::cell::RefCell;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::conn::Connection;
use ferrox_core::transport::early_decode;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const HEAD_LIMIT: usize = 16 * 1024;
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
const OP_CONT: u8 = 0x00;
const OP_TEXT: u8 = 0x01;
const OP_DATA: u8 = 0x02;
const OP_CLOSE: u8 = 0x08;
const OP_PING: u8 = 0x09;
const OP_PONG: u8 = 0x0A;
const CLOSE_BODY: [u8; 2] = [0x03, 0xE8];

/// The accept key the server answers with: twenty-eight bytes of base64, on the stack.
fn accept_key(key: &str) -> [u8; ACCEPT_LEN] {
    use sha1::Digest as _;
    let mut hash = sha1::Sha1::new();
    hash.update(key.trim().as_bytes());
    hash.update(GUID.as_bytes());
    let digest = hash.finalize();
    let mut out = [0u8; ACCEPT_LEN];
    let written = ferrox_core::b64::encode_parts_into(&[&digest], &mut out)
        .expect("the digest's window is long enough");
    debug_assert_eq!(written, ACCEPT_LEN);
    out
}

/// The key the client asks with: twenty-four bytes of base64, on the stack.
fn fresh_key() -> Option<[u8; KEY_LEN]> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).ok()?;
    let mut out = [0u8; KEY_LEN];
    let written = ferrox_core::b64::encode_parts_into(&[&raw], &mut out)
        .expect("the key's window is long enough");
    debug_assert_eq!(written, KEY_LEN);
    Some(out)
}

/// The base64 of a twenty-byte digest.
const ACCEPT_LEN: usize = 28;
/// The base64 of sixteen random bytes.
const KEY_LEN: usize = 24;

/// The base64 alphabet is ASCII, so a coded key is text: the head that carries it is a
/// `String` and this is the one conversion that says so.
fn base64_text(key: &[u8]) -> &str {
    std::str::from_utf8(key).expect("the base64 alphabet is ASCII")
}

/// The pass width the `avx2` rung takes: four bytes of mask times eight, so the narrow ladder it hands the remainder to starts a payload phase at zero.
#[cfg(target_arch = "x86_64")]
const WIDE_PASS: usize = 32;

fn apply_mask(buf: &mut [u8], mask: [u8; 4]) {
    let len = buf.len();
    let (src, dst) = (buf.as_ptr(), buf.as_mut_ptr());
    // SAFETY: both pointers name the buffer itself, and the ladder reads each chunk before that same chunk's store at the identical offset — the old in-place read-modify-write.
    #[cfg(target_arch = "x86_64")]
    if len >= WIDE_PASS && std::is_x86_feature_detected!("avx2") {
        unsafe { mask_wide(src, dst, len, mask) };
        return;
    }
    unsafe { mask_narrow(src, dst, len, mask) };
}

/// The masked write's staging fill: the payload is read once and its masked bytes are written once, by the same rungs that unmask in place — a `ymm` per thirty-two bytes where the host reports `avx2`, the sixteen-byte ladder under it. The two-pass shape this replaces walked the same bytes three times: a memcpy's read and write, then the mask's own read-modify-write.
#[allow(
    clippy::uninit_vec,
    reason = "the ladder fills the extended bytes on every rung before this returns"
)]
fn mask_copy(frame: &mut Vec<u8>, src: &[u8], mask: [u8; 4]) {
    frame.reserve(src.len());
    let base = frame.len();
    // SAFETY: the ladder below writes every extended byte from `src` before this returns, on every rung.
    unsafe { frame.set_len(base + src.len()) };
    let (_filled, rest) = frame.split_at_mut(base);
    debug_assert_eq!(rest.len(), src.len());
    // SAFETY: `rest` is exactly `src.len()` fresh bytes disjoint from the live-immutable `src`, and the ladder reads each chunk before storing that same chunk.
    unsafe { mask_wide_dispatch(src.as_ptr(), rest.as_mut_ptr(), src.len(), mask) };
}

#[cfg(target_arch = "x86_64")]
unsafe fn mask_wide_dispatch(src: *const u8, dst: *mut u8, len: usize, mask: [u8; 4]) {
    if len >= WIDE_PASS && std::is_x86_feature_detected!("avx2") {
        unsafe { mask_wide(src, dst, len, mask) };
        return;
    }
    unsafe { mask_narrow(src, dst, len, mask) };
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn mask_wide_dispatch(src: *const u8, dst: *mut u8, len: usize, mask: [u8; 4]) {
    unsafe { mask_narrow(src, dst, len, mask) };
}

/// One `ymm` per pass: a load, an xor and a store per thirty-two bytes, half what the sixteen-byte ladder spends on the same span. The remainder is below one wide pass, so it goes to that ladder whole.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mask_wide(src: *const u8, dst: *mut u8, len: usize, mask: [u8; 4]) {
    use core::arch::x86_64::{
        _mm256_loadu_si256, _mm256_set1_epi32, _mm256_storeu_si256, _mm256_xor_si256,
    };
    let wide = _mm256_set1_epi32(i32::from_le_bytes(mask));
    let done = len / WIDE_PASS * WIDE_PASS;
    let mut at = 0usize;
    while at < done {
        // SAFETY: `at..at + WIDE_PASS` lies inside the whole passes both ranges were carved with, and the caller holds `src` live and `dst` writable over all `len`.
        unsafe {
            let data = _mm256_loadu_si256(src.add(at).cast());
            _mm256_storeu_si256(dst.add(at).cast(), _mm256_xor_si256(data, wide));
        }
        at += WIDE_PASS;
    }
    // SAFETY: the tail is the bytes past the whole passes of the same two ranges the caller proved.
    unsafe { mask_narrow(src.add(done), dst.add(done), len - done, mask) };
}

/// The sixteen-byte ladder, read and write split: it walks `src` and lands the masked bytes in `dst`, which may be the very space it reads from — an in-place unmask — or space that has never held anything — a staging fill. Every stride is a multiple of the four-byte mask, so each chunk's own first byte sits at the payload's phase zero either way.
///
/// # Safety
/// `src` readable and `dst` writable over `len`; the two ranges either are the same range (the
/// in-place case, where every read of a byte precedes that byte's write at the identical offset)
/// or do not overlap at all.
unsafe fn mask_narrow(src: *const u8, dst: *mut u8, len: usize, mask: [u8; 4]) {
    let wide = [
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3], mask[0], mask[1],
        mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ];
    let blocks = len / 64;
    for b in 0..blocks {
        let at = b * 64;
        for lane in 0..4 {
            let off = at + lane * 16;
            // SAFETY: `off..off + 16` sits inside the whole 64-byte blocks of both ranges.
            let chunk = unsafe { core::slice::from_raw_parts(src.add(off), 16) };
            let out = unsafe { core::slice::from_raw_parts_mut(dst.add(off), 16) };
            xor_block(chunk, &wide, out);
        }
    }
    let chunks = (len - blocks * 64) / 16;
    for c in 0..chunks {
        let at = blocks * 64 + c * 16;
        // SAFETY: `at..at + 16` sits inside the whole 16-byte chunks past the blocks.
        let chunk = unsafe { core::slice::from_raw_parts(src.add(at), 16) };
        let out = unsafe { core::slice::from_raw_parts_mut(dst.add(at), 16) };
        xor_block(chunk, &wide, out);
    }
    let tail_at = blocks * 64 + chunks * 16;
    for i in tail_at..len {
        // SAFETY: the tail is the bytes past the whole chunks, inside `len` of both ranges; each byte is read and written at the same offset or in disjoint ranges.
        unsafe {
            let byte = *src.add(i);
            *dst.add(i) = byte ^ mask[i & 3];
        }
    }
}

#[allow(
    clippy::inline_always,
    reason = "load-bearing: keeps the vector op inlined at every call site"
)]
#[inline(always)]
fn xor_block(chunk: &[u8], wide: &[u8; 16], out: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
        unsafe {
            let data = _mm_loadu_si128(chunk.as_ptr().cast());
            let key = _mm_loadu_si128(wide.as_ptr().cast());
            _mm_storeu_si128(out.as_mut_ptr().cast(), _mm_xor_si128(data, key));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::{veorq_u8, vld1q_u8, vst1q_u8};
        unsafe {
            let data = vld1q_u8(chunk.as_ptr());
            let key = vld1q_u8(wide.as_ptr());
            vst1q_u8(out.as_mut_ptr(), veorq_u8(data, key));
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        for ((out, &byte), &key) in out.iter_mut().zip(chunk).zip(wide.iter()) {
            *out = byte ^ key;
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
                getrandom::fill(&mut buf[..]).ok()?;
                *at = 0;
            }
            let mask: [u8; 4] = buf[*at..*at + 4].try_into().ok()?;
            *at += 4;
            Some(mask)
        })
        .ok()?
}

/// The head, the octets that arrived with it, and where the head ends: this read consumes what it proves, so a frame pipelined behind the handshake is already in hand.
fn read_head(stream: &mut Connection) -> Option<(Vec<u8>, usize)> {
    crate::proxy::read_http_head_kept(stream, HEAD_LIMIT, crate::budgets::head_arrival())
}

struct Shared {
    stream: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    closed: AtomicBool,
    /// Whether this side masks what it writes: a client must, a server must not, and the reply to a control frame follows the side that sends it.
    masked: bool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("closed", &self.closed)
            .field("masked", &self.masked)
            .finish_non_exhaustive()
    }
}

/// Bytes one read asks for: a header and its payload cost one syscall; a mid-frame read is finished by the next.
const READ_AHEAD: usize = 32 * 1024;

#[derive(Debug)]
pub(crate) struct WsReader<R: Read = Connection> {
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

impl WsReader<Connection> {
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
        // Assembly coordinates: every fragment's bytes land at `filled`, so the span delivered is the message's.
        let mut whole = 0usize;
        let mut filled = 0usize;
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
                // RFC 6455 has two data opcodes; the tunnel reads both and writes binary, the order the reference keeps.
                OP_TEXT | OP_DATA | OP_CONT => {
                    if (opcode == OP_CONT) != open {
                        return false;
                    }
                    if let Some(mask) = mask {
                        apply_mask(&mut self.have[payload], mask);
                    }
                    if !open {
                        whole = start;
                        filled = start;
                    } else if filled != start {
                        self.have.copy_within(start..start + len, filled);
                    }
                    if fin {
                        self.msg_end = filled + len;
                        self.at = whole;
                        return true;
                    }
                    filled += len;
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
        let _ = write_frame(&mut **stream, self.shared.masked, opcode, payload);
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
        mask_copy(&mut frame, data, mask);
        stream.write_all(&frame).is_ok()
    })
}

pub(crate) fn accept(stream: Connection, path: &str) -> Option<(WsReader, WsWriter)> {
    let mut read = stream;
    let (head, at) = read_head(&mut read)?;
    let Upgrade {
        key,
        offered,
        early,
    } = check_request(&head[..at], path)?;
    let response = accept_response(key, offered, !early.is_empty());
    read.write_all(&response).ok()?;
    split(read, early, head, at, false)
}

/// What the client's head said: the key to accept, the subprotocol it offered and the early data riding in it.
#[derive(Debug)]
struct Upgrade<'a> {
    key: &'a str,
    offered: &'a str,
    early: Vec<u8>,
}

fn check_request<'a>(head: &'a [u8], path: &str) -> Option<Upgrade<'a>> {
    let text = std::str::from_utf8(head).ok()?;
    if crate::proxy::request_path_in(text)? != path {
        return None;
    }
    let key = crate::proxy::header_value_in(text, "sec-websocket-key")?;
    if key.is_empty() {
        return None;
    }
    let offered = crate::proxy::header_value_in(text, "sec-websocket-protocol").unwrap_or_default();
    let early = early_decode(offered)
        .filter(|bytes| !bytes.is_empty())
        .unwrap_or_default();
    Some(Upgrade {
        key,
        offered,
        early,
    })
}

/// The `101` in its exact length: the accept key, and the offered subprotocol echoed back when the head carried early data.
fn accept_response(key: &str, offered: &str, echo: bool) -> Vec<u8> {
    const HEAD: &str = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
    const PROTOCOL: &str = "Sec-WebSocket-Protocol: ";
    let accept = accept_key(key);
    let echoed = if echo {
        PROTOCOL.len() + offered.len() + 2
    } else {
        0
    };
    let mut response = Vec::with_capacity(HEAD.len() + accept.len() + echoed + 4);
    response.extend_from_slice(HEAD.as_bytes());
    response.extend_from_slice(&accept);
    response.extend_from_slice(b"\r\n");
    if echo {
        response.extend_from_slice(PROTOCOL.as_bytes());
        response.extend_from_slice(offered.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"\r\n");
    response
}

// The same accept over halves that cannot peek: the kept read consumes the head, so what rode in behind it is the reader's own prefix.
pub(crate) fn accept_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    path: &str,
) -> Option<(WsReader<R>, WsWriter)> {
    let (head, at) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    let Upgrade {
        key,
        offered,
        early,
    } = check_request(&head[..at], path)?;
    let response = accept_response(key, offered, !early.is_empty());
    write.write_all(&response).ok()?;
    Some(split_halves(read, write, early, head, at, false))
}

pub(crate) fn connect(
    stream: Connection,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(WsReader, WsWriter)> {
    let key = fresh_key()?;
    let mut read = stream;
    let (handshake, early) = request(host, path, &key, budget, first);
    read.write_all(handshake.as_bytes()).ok()?;
    let (head, at) = read_head(&mut read)?;
    check_response(&head[..at], &key)?;
    // The kept read takes what rode in behind the `101`, so the first frame is already the reader's own buffer.
    let (reader, writer) = split(read, Vec::new(), head, at, true)?;
    if !early && !first.is_empty() && !writer.send(first) {
        return None;
    }
    Some((reader, writer))
}

fn check_response(head: &[u8], key: &[u8]) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    if text.split("\r\n").next()?.split(' ').nth(1)? != "101" {
        return None;
    }
    let accept = accept_key(base64_text(key));
    if crate::proxy::header_value_in(text, "sec-websocket-accept")?.as_bytes() != accept {
        return None;
    }
    Some(())
}

// The same connect over halves that cannot peek: the kept read takes what rode in behind the `101`.
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
    let (head, at) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head[..at], &key)?;
    let (reader, writer) = split_halves(read, write, Vec::new(), head, at, true);
    if !early && !first.is_empty() && !writer.send(first) {
        return None;
    }
    Some((reader, writer))
}

fn request(host: &str, path: &str, key: &[u8], budget: u32, first: &[u8]) -> (String, bool) {
    const OPEN: &str = "GET ";
    const MIDDLE: &str = " HTTP/1.1\r\nHost: ";
    const KEYS: &str = "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ";
    const VERSION: &str = "\r\nSec-WebSocket-Version: 13";
    const END: &str = "\r\n\r\n";
    const PROTOCOL: &str = "Sec-WebSocket-Protocol: ";
    let early = !first.is_empty() && first.len() as u64 <= u64::from(budget);
    let coded = if early {
        (first.len() * 4).div_ceil(3)
    } else {
        0
    };
    let fixed = OPEN.len() + MIDDLE.len() + KEYS.len() + VERSION.len() + END.len();
    let room = if early { PROTOCOL.len() + coded + 2 } else { 0 };
    let mut request = String::with_capacity(fixed + host.len() + path.len() + key.len() + room);
    request.push_str(OPEN);
    request.push_str(path);
    request.push_str(MIDDLE);
    request.push_str(host);
    request.push_str(KEYS);
    request.push_str(base64_text(key));
    request.push_str(VERSION);
    if early {
        request.push_str("\r\n");
        request.push_str(PROTOCOL);
        ferrox_core::transport::early_encode_into(&mut request, first);
    }
    request.push_str(END);
    (request, early)
}

fn split(
    read: Connection,
    early: Vec<u8>,
    have: Vec<u8>,
    at: usize,
    masked: bool,
) -> Option<(WsReader, WsWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some(split_halves(read, write, early, have, at, masked))
}

/// The same split over halves that cannot clone: `have` is the buffer the head read left, with `at` already past the head.
pub(crate) fn split_halves<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    early: Vec<u8>,
    have: Vec<u8>,
    at: usize,
    masked: bool,
) -> (WsReader<R>, WsWriter) {
    let shared = Arc::new(Shared {
        stream: Mutex::new(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>),
        closed: AtomicBool::new(false),
        masked,
    });
    let reader = WsReader {
        read,
        shared: Arc::clone(&shared),
        have,
        at,
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
    use std::thread;

    /// The two keys are the base64 of a digest and of sixteen random bytes, and neither
    /// leaves the heap: the counting allocator is the witness.
    #[test]
    fn the_keys_are_not_allocated() {
        let (accept, counts) =
            ferrox_core::alloc_count::measure(|| accept_key("dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(counts.allocs, 0, "the accept key is on the stack");
        assert_eq!(base64_text(&accept), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        let (key, counts) = ferrox_core::alloc_count::measure(|| fresh_key().expect("a key"));
        assert_eq!(counts.allocs, 0, "the fresh key is on the stack");
        assert_eq!(key.len(), KEY_LEN, "and it is a whole key");
    }

    #[test]
    fn accept_matches_the_rfc_example() {
        assert_eq!(
            base64_text(&accept_key("dGhlIHNhbXBsZSBub25jZQ==")),
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

    /// The fused staging fill is the old two-pass shape byte for byte: the head bytes already in the
    /// frame keep their place, and every payload lands as the byte loop would have written it, at
    /// every width the rungs switch at and from every staging base a real frame leaves them at.
    #[test]
    fn the_fused_fill_is_the_memcpy_then_mask_byte_for_byte() {
        for len in [
            0, 1, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 65, 96, 127, 128, 129, 255, 256, 1024,
            4096, 16_384,
        ] {
            for base in [0usize, 2, 6, 7, 13, 14] {
                for mask in [[0u8, 0, 0, 0], [1, 2, 3, 4], [0xFF, 0x00, 0xA5, 0x5A]] {
                    let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
                    let mut want: Vec<u8> = vec![0xA5u8; base];
                    for (i, &byte) in plain.iter().enumerate() {
                        want.push(byte ^ mask[i & 3]);
                    }
                    let mut got = vec![0xA5u8; base];
                    mask_copy(&mut got, &plain, mask);
                    assert_eq!(got, want, "len {len} base {base} mask {mask:?}");
                    assert_eq!(&got[..base], &want[..base], "the head keeps its bytes");
                }
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
                let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
                let port = listener.local_addr().expect("addr").port();
                let expected = payload.clone();
                let writer = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().expect("accepts");
                    assert!(write_frame(&mut stream, masked, OP_DATA, &expected));
                });
                let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
                let shared = Arc::new(Shared {
                    stream: Mutex::new(Box::new(stream.try_clone().expect("clones"))
                        as Box<dyn crate::proxy::FrameWrite + Send>),
                    closed: AtomicBool::new(false),
                    masked: false,
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

    /// RFC 6455 has two data opcodes, and the tunnel reads both: a text frame answers like a binary one, a text message reassembles over a continuation, and a binary one reaches the reader unchanged.
    #[test]
    fn a_text_frame_carries_a_message_like_a_binary_one() {
        let payload: Vec<u8> = (0..300u16).map(|i| (i % 251) as u8).collect();
        let reader_for = |frames: Vec<u8>| WsReader {
            read: std::io::Cursor::new(frames),
            shared: Arc::new(Shared {
                stream: Mutex::new(Box::new(Sink::default())),
                closed: AtomicBool::new(false),
                masked: false,
            }),
            have: Vec::new(),
            at: 0,
            msg_end: 0,
            early: Vec::new(),
            eat: 0,
            eof: false,
            handshake: None,
            reads: 0,
        };
        let frame = |fin: bool, opcode: u8, payload: &[u8]| {
            let mut wire = vec![u8::from(fin) * 0x80 + opcode];
            if payload.len() < 126 {
                wire.push(payload.len() as u8);
            } else {
                wire.push(126);
                wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            wire.extend_from_slice(payload);
            wire
        };
        let mut whole = Vec::new();
        let mut buf = [0u8; 4096];
        let mut reader = reader_for(frame(true, OP_TEXT, &payload));
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            whole.extend_from_slice(&buf[..n]);
        }
        assert_eq!(whole, payload, "text");
        let mut whole = Vec::new();
        let mut reader = reader_for(frame(true, OP_DATA, &payload));
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            whole.extend_from_slice(&buf[..n]);
        }
        assert_eq!(whole, payload, "binary");
        let (first, second) = payload.split_at(37);
        let mut wire = frame(false, OP_TEXT, first);
        wire.extend(frame(true, OP_CONT, second));
        let mut whole = Vec::new();
        let mut reader = reader_for(wire);
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            whole.extend_from_slice(&buf[..n]);
        }
        assert_eq!(whole, payload, "text-then-continuation");
    }

    /// The loopback witness: a peer that answers in text and then in binary has both reach the reader, bytes for bytes.
    #[test]
    fn a_text_message_then_a_binary_one_reaches_the_reader() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            assert!(write_frame(&mut stream, true, OP_TEXT, b"TEXT-OK\n"));
            assert!(write_frame(&mut stream, true, OP_DATA, b"BIN-OK\n"));
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let shared = Arc::new(Shared {
            stream: Mutex::new(Box::new(stream.try_clone().expect("clones"))
                as Box<dyn crate::proxy::FrameWrite + Send>),
            closed: AtomicBool::new(false),
            masked: false,
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
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            whole.extend_from_slice(&buf[..n]);
        }
        assert_eq!(whole, b"TEXT-OK\nBIN-OK\n");
        server.join().expect("joins");
    }

    /// A fixed source returns every byte asked for, so the syscall count is exact, not a race with the scheduler.
    #[test]
    fn a_read_covers_a_window_not_one_frame_header() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || listener.accept().expect("accepts").0);
        let _spare = Connection::connect(("127.0.0.1", port)).expect("connects");
        let shared = Arc::new(Shared {
            stream: Mutex::new(
                Box::new(server.join().expect("joins")) as Box<dyn crate::proxy::FrameWrite + Send>
            ),
            closed: AtomicBool::new(false),
            masked: false,
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
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
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
        let key = fresh_key().expect("a key");
        let prefix = format!(
            "GET /tunnel HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n",
            base64_text(&key)
        );
        let plain = format!("{prefix}\r\n");
        assert_eq!(
            request("example.com", "/tunnel", &key, 0, b"hello").0,
            plain
        );
        for (payload, budget, rides) in [
            (&b"hello"[..], 5u32, true),
            (&b"hello"[..], 4, false),
            (&b""[..], 2048, false),
            (&b"hi"[..], 2048, true),
            (&b"hi"[..], 2, true),
            (&b"hi"[..], 1, false),
        ] {
            let (got, early) = request("example.com", "/tunnel", &key, budget, payload);
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

    /// The request is filled into a buffer opened to its own length, so no head is copied into a grown one — over the lengths that are not a multiple of three and over both sides of the budget.
    #[test]
    fn the_request_is_sized_for_its_bytes() {
        let key = fresh_key().expect("a key");
        for len in [0usize, 1, 2, 3, 191, 192, 193, 2047, 2048] {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(61)).collect();
            for budget in [0u32, 1, len as u32, len as u32 + 1] {
                let (got, _) = request("example.com", "/tunnel", &key, budget, &payload);
                assert_eq!(
                    got.capacity(),
                    got.len(),
                    "len {len} at {budget}: one allocation, no growth"
                );
            }
        }
    }

    #[test]
    fn the_101_is_the_key_and_the_echoed_subprotocol() {
        let key = *b"dGhlIHNhbXBsZSBub25jZQ==";
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
        let plain = accept_response(base64_text(&key), "", false);
        assert_eq!(
            plain,
            format!("{head}\r\n").into_bytes(),
            "no early data, no subprotocol line"
        );
        assert_eq!(plain.capacity(), plain.len(), "one allocation, no growth");
        let echoed = accept_response(base64_text(&key), "cGluZw", true);
        assert_eq!(
            echoed,
            format!("{head}Sec-WebSocket-Protocol: cGluZw\r\n\r\n").into_bytes(),
            "the offered subprotocol rides back in the 101"
        );
        assert_eq!(echoed.capacity(), echoed.len(), "one allocation, no growth");
    }

    /// The probe behind the early-data head rows: one fixed head read for the path, the key, the subprotocol and the early data, so the frame is that read and not a socket or an allocator.
    #[test]
    fn the_head_yields_the_path_the_key_and_the_early_data() {
        const ROUNDS: usize = 64;
        let head: Vec<u8> = Vec::from(
            &b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: cGluZw\r\nSec-WebSocket-Version: 13\r\n\r\n"[..],
        );
        let mut folded = 0usize;
        for _ in 0..ROUNDS {
            let upgrade = check_request(std::hint::black_box(&head), "/tunnel").expect("upgrades");
            folded += upgrade.key.len() + upgrade.offered.len() + upgrade.early.len();
        }
        assert_eq!(
            folded,
            ROUNDS * (24 + 6 + 4),
            "one key, one subprotocol, four bytes of early data"
        );
        assert!(
            check_request(&[0xff, 0xfe, b'\r', b'\n'], "/tunnel").is_none(),
            "a head that is not text upgrades nothing"
        );
    }

    /// The bytes behind the head are the reader's own buffer, base and all: nothing copies them into the early data, so they arrive where they already were.
    #[test]
    fn the_pipelined_prefix_is_the_readers_own_buffer() {
        let mut prefix = Vec::with_capacity(64);
        prefix.extend_from_slice(b"the frame behind the head");
        let base = prefix.as_ptr();
        let (reader, _writer) = split_halves(
            std::io::Cursor::new(Vec::new()),
            Sink::default(),
            b"ping".to_vec(),
            prefix,
            0,
            false,
        );
        assert_eq!(
            reader.have.as_ptr(),
            base,
            "the reader's buffer is the buffer those bytes were already in"
        );
        assert_eq!(
            &reader.have, b"the frame behind the head",
            "and it holds them still"
        );
    }

    /// The record arm takes the buffer its own head read filled, head octets and all: what rode behind the delimiter is handed over inside it, not copied into a second owner.
    #[test]
    fn the_record_head_hands_over_the_buffer_it_filled() {
        const HEAD: &[u8] = b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        const TAIL: &[u8] = b"\x82\x02hi";
        let mut wire = Vec::from(HEAD);
        wire.extend_from_slice(TAIL);
        let (reader, _writer) =
            accept_split(std::io::Cursor::new(wire), Sink::default(), "/tunnel").expect("upgrades");
        assert_eq!(reader.at, HEAD.len(), "the cursor sits past the head");
        assert_eq!(
            reader.have.len(),
            HEAD.len() + TAIL.len(),
            "one buffer carries the handshake and what rode behind it"
        );
        assert_eq!(
            reader.have[reader.at..].as_ptr() as usize - reader.have.as_ptr() as usize,
            reader.at,
            "and those bytes lie inside the allocation the head read made"
        );
    }

    /// The kept head hands the reader its own buffer with the head already walked past: a frame that rode in with the handshake is delivered without asking the socket, and its bytes never move.
    #[test]
    fn a_frame_that_rode_in_with_the_head_costs_no_syscall() {
        const HEAD: &[u8] = b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        let mut have = Vec::from(HEAD);
        have.extend_from_slice(b"\x82\x02hi\x82\x02yo");
        let base = have.as_ptr();
        let capacity = have.capacity();
        let (mut reader, _writer) = split_halves(
            std::io::Cursor::new(Vec::from(&b"\x82\x02no"[..])),
            Sink::default(),
            Vec::new(),
            have,
            HEAD.len(),
            false,
        );
        let mut got = [0u8; 2];
        assert_eq!(reader.read(&mut got).expect("delivers"), 2);
        assert_eq!(&got, b"hi", "the frame behind the head, not a re-read");
        assert_eq!(reader.read(&mut got).expect("delivers"), 2);
        assert_eq!(&got, b"yo");
        assert_eq!(reader.reads(), 0, "the socket was never asked");
        assert_eq!(
            reader.have.as_ptr(),
            base,
            "and the bytes were delivered from the buffer they arrived in"
        );
        assert_eq!(reader.have.capacity(), capacity, "on a held capacity");
    }

    #[test]
    fn the_early_data_lands_before_the_pipelined_frame() {
        let mut frame = Sink {
            capture: true,
            ..Sink::default()
        };
        assert!(write_frame(&mut frame, true, OP_DATA, b"pong"));
        let mut wire = Vec::from(
            &b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: cGluZw\r\n\r\n"[..],
        );
        wire.extend_from_slice(&frame.kept);
        let (mut reader, _writer) =
            accept_split(std::io::Cursor::new(wire), Sink::default(), "/tunnel").expect("upgrades");
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("reads");
        assert_eq!(
            got, b"pingpong",
            "the early data first, then the pipelined frame"
        );
    }

    #[test]
    fn early_data_reaches_the_server_with_and_without_a_budget_that_fits() {
        for budget in [2048u32, 4, 3] {
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
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
            let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
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
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let configured = EarlyData::split("/interop-ws?ed=2048");
            assert!(accept(stream, &configured.path).is_some());
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /interop-ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Key: aGVsbG8gd29ybGQxMjM0NQ==\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }

    #[test]
    fn handshake_rejects_a_wrong_path_and_key() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: k\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
