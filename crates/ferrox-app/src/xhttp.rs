use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, OnceLock};

use ferrox_core::transport::url_decode;

const HEAD_LIMIT: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn path_covers(configured: &str, requested: &str) -> bool {
    if configured == "/" {
        return requested.starts_with('/');
    }
    let configured = match configured.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => configured,
    };
    requested == configured
        || requested
            .strip_prefix(configured)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn bare_path(target: &str) -> &str {
    target.split_once('?').map_or(target, |(base, _)| base)
}

/// The head, the octets that arrived with it, and where the head ends: this read consumes what it proves, so a body pipelined behind the head is already in hand.
fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, usize)> {
    crate::proxy::read_http_head_kept(stream, HEAD_LIMIT, crate::budgets::head_arrival())
}

fn size_line(n: usize, out: &mut [u8; 6]) -> usize {
    debug_assert!((1..=CHUNK).contains(&n));
    if n < 16 {
        out[0] = HEX[n & 0xf];
        out[1] = b'\r';
        out[2] = b'\n';
        3
    } else if n < 256 {
        out[0] = HEX[(n >> 4) & 0xf];
        out[1] = HEX[n & 0xf];
        out[2] = b'\r';
        out[3] = b'\n';
        4
    } else if n < 4096 {
        out[0] = HEX[(n >> 8) & 0xf];
        out[1] = HEX[(n >> 4) & 0xf];
        out[2] = HEX[n & 0xf];
        out[3] = b'\r';
        out[4] = b'\n';
        5
    } else {
        out[0] = HEX[(n >> 12) & 0xf];
        out[1] = HEX[(n >> 8) & 0xf];
        out[2] = HEX[(n >> 4) & 0xf];
        out[3] = HEX[n & 0xf];
        out[4] = b'\r';
        out[5] = b'\n';
        6
    }
}

fn read_line_into(reader: &mut Reader<impl Read>, out: &mut [u8; 130]) -> Option<usize> {
    loop {
        let start = reader.at;
        let end = reader.prefix.len().min(start + 130);
        let mut found = None;
        let mut i = start;
        while i + 1 < end {
            if reader.prefix[i] == b'\r' && reader.prefix[i + 1] == b'\n' {
                found = Some(i - start);
                break;
            }
            i += 1;
        }
        if let Some(end_pos) = found {
            if end_pos > 127 {
                return None;
            }
            out[..end_pos].copy_from_slice(&reader.prefix[reader.at..reader.at + end_pos]);
            reader.at = reader.at + end_pos + 2;
            return Some(end_pos);
        }
        if reader.prefix.len() - reader.at >= 129 {
            return None;
        }
        if reader.at >= reader.prefix.len() {
            reader.prefix.clear();
            reader.at = 0;
        } else if reader.at > 0 {
            reader.prefix.drain(..reader.at);
            reader.at = 0;
        }
        let mut tmp = [0u8; 128];
        match reader.take(&mut tmp) {
            Ok(n) if n > 0 => reader.prefix.extend_from_slice(&tmp[..n]),
            _ => return None,
        }
    }
}

fn chunk_size(line: &[u8]) -> Option<usize> {
    let mut size = 0usize;
    let mut i = 0;
    while i < line.len() {
        let v = CHUNK_LINE_LUT[line[i] as usize];
        if v == 16 {
            return if i == 0 { None } else { Some(size) };
        }
        if v == 255 {
            return None;
        }
        if i == 16 {
            return None;
        }
        size = (size << 4) | v as usize;
        i += 1;
    }
    if i == 0 {
        return None;
    }
    Some(size)
}

/// One pass over the size line: 0..=15 is a hex nibble, 16 marks a terminator (any of `;`, space, tab, CR, LF), 255 marks a byte that can be neither.
const CHUNK_LINE_LUT: [u8; 256] = {
    let mut t = [255u8; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 6 {
        t[b'a' as usize + i] = 10 + i as u8;
        t[b'A' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t[b';' as usize] = 16;
    t[b' ' as usize] = 16;
    t[b'\t' as usize] = 16;
    t[b'\r' as usize] = 16;
    t[b'\n' as usize] = 16;
    t
};

/// Generic over the underlying `Read` so a test can drive it from an in-memory stream and count the reads, the way `WsReader` counts its own; `reads` is that counter and the read-syscall row is measured from it.
#[derive(Debug)]
pub(crate) struct Reader<R> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
    left: usize,
    ended: bool,
    reads: usize,
}

pub(crate) type XhttpReader = Reader<TcpStream>;

/// A live stream with sniffed bytes pushed back in front, so a transport decision made on the first bytes does not eat them.
pub(crate) struct ChainReader<R> {
    prefix: Vec<u8>,
    at: usize,
    read: R,
}

impl<R: Read> ChainReader<R> {
    pub(crate) fn new(prefix: Vec<u8>, read: R) -> Self {
        Self {
            prefix,
            at: 0,
            read,
        }
    }
    /// Put the bytes that rode in with the last request but belong to the next one back on the front.
    fn set_carry(&mut self, carry: Vec<u8>) {
        self.prefix = carry;
        self.at = 0;
    }
}

impl<R: Read> Read for ChainReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.read.read(buf)
    }
}

impl<R: Read> Reader<R> {
    /// Every read that reaches the stream, counted where it happens; quiet sockets retry.
    fn take(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.reads += 1;
            match self.read.read(buf) {
                Err(error) if crate::proxy::is_timeout(&error) => {}
                outcome => return outcome,
            }
        }
    }

    /// The syscall counter, read by `a_chunk_costs_two_reads_not_three` and `a_real_socket_drains_the_same_bytes`.
    #[cfg_attr(not(test), expect(dead_code, reason = "only the gate reads it"))]
    #[must_use]
    pub(crate) fn reads(&self) -> usize {
        self.reads
    }
}

impl<R: Read> Reader<R> {
    fn body(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Some(n);
        }
        match self.take(buf) {
            Ok(n) if n > 0 => Some(n),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct XhttpWriter {
    shared: Arc<Shared>,
    h2: OnceLock<crate::xhttp_h2::H2StreamOut>,
}

struct Shared {
    stream: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    finished: AtomicBool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.ended {
                return Ok(0);
            }
            if self.left > 0 {
                let n = self.left.min(buf.len());
                let got = self
                    .body(&mut buf[..n])
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
                self.left -= got;
                if self.left == 0 {
                    let mut crlf = [0u8; 2];
                    let mut taken = 0usize;
                    while taken < 2 {
                        if self.at >= self.prefix.len() {
                            self.prefix.clear();
                            self.at = 0;
                        }
                        if self.at < self.prefix.len() {
                            crlf[taken] = self.prefix[self.at];
                            self.at += 1;
                            taken += 1;
                        } else {
                            // One window instead of a two-byte read: the bytes past the CRLF are the next size line, found without asking the socket, and a peer segmenting the CRLF across reads still gets through.
                            let mut tmp = [0u8; 128];
                            let n = self.take(&mut tmp).map_err(|_| {
                                std::io::Error::from(std::io::ErrorKind::InvalidData)
                            })?;
                            if n == 0 {
                                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                            }
                            self.prefix.extend_from_slice(&tmp[..n]);
                        }
                    }
                    if crlf != *b"\r\n" {
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                    }
                }
                return Ok(got);
            }
            let mut line = [0u8; 130];
            let len = read_line_into(self, &mut line)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            let size = chunk_size(&line[..len])
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            if size == 0 {
                loop {
                    let mut trailer = [0u8; 130];
                    let len = read_line_into(self, &mut trailer)
                        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
                    if len == 0 {
                        break;
                    }
                }
                self.ended = true;
                return Ok(0);
            }
            if size > 64 * 1024 * 1024 {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            self.left = size;
        }
    }
}

impl XhttpWriter {
    pub(crate) fn new<W: crate::proxy::FrameWrite + Send + 'static>(w: W) -> Self {
        Self {
            shared: Arc::new(Shared {
                stream: Mutex::new(Box::new(w) as Box<dyn crate::proxy::FrameWrite + Send>),
                finished: AtomicBool::new(false),
            }),
            h2: OnceLock::new(),
        }
    }
    pub(crate) fn set_h2(&self, out: crate::xhttp_h2::H2StreamOut) {
        let _ = self.h2.set(out);
    }
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        if let Some(h2) = self.h2.get() {
            return h2.data(data);
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        for piece in data.chunks(CHUNK) {
            if piece.is_empty() {
                continue;
            }
            let mut line = [0u8; 6];
            let len = size_line(piece.len(), &mut line);
            if !stream.write_slices(&[&line[..len], piece, b"\r\n"]) {
                return false;
            }
        }
        true
    }
    pub(crate) fn finish(&self) {
        if self.shared.finished.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(h2) = self.h2.get() {
            h2.end();
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = stream.write_all(b"0\r\n\r\n");
    }
}

impl Write for XhttpWriter {
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

fn split(read: TcpStream, prefix: Vec<u8>, at: usize) -> Option<(XhttpReader, XhttpWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some(split_halves(read, write, prefix, at))
}

// The same split over halves that cannot clone: `prefix` is the buffer the head read left, with `at` already past the head.
fn split_halves<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    prefix: Vec<u8>,
    at: usize,
) -> (Reader<R>, XhttpWriter) {
    let reader = Reader {
        read,
        prefix,
        at,
        left: 0,
        ended: false,
        reads: 0,
    };
    let writer = XhttpWriter {
        shared: Arc::new(Shared {
            stream: Mutex::new(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>),
            finished: AtomicBool::new(false),
        }),
        h2: OnceLock::new(),
    };
    (reader, writer)
}

fn has_chunked(value: &str) -> bool {
    value
        .as_bytes()
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"chunked"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

impl XhttpMode {
    fn parse_mode(s: &str) -> Option<XhttpMode> {
        match s {
            "stream-one" | "streamone" => Some(XhttpMode::StreamOne),
            "stream-up" => Some(XhttpMode::StreamUp),
            "packet-up" => Some(XhttpMode::PacketUp),
            _ => None,
        }
    }

    // Missing/`auto` resolve the way the reference's dialer.go:332 does.
    fn auto_mode(settings: &crate::json::Json, xhttp: &crate::json::Json) -> XhttpMode {
        let reality = settings
            .get("security")
            .and_then(crate::json::Json::as_str)
            .is_some_and(|s| s == "reality");
        if reality {
            if xhttp.get("downloadSettings").is_some() {
                XhttpMode::StreamUp
            } else {
                XhttpMode::StreamOne
            }
        } else {
            XhttpMode::PacketUp
        }
    }
}

/// Whether the config wrote a mode down. The reference hub gates a shape only on a stated mode (`hub.go:154`), so `Auto` names a dialer default rather than a limit on what may arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModeSource {
    Stated,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    Body,
    Auto,
    QueryInHeader,
}

impl Placement {
    fn parse(s: &str) -> Option<Placement> {
        Some(match s {
            "path" => Placement::Path,
            "query" => Placement::Query,
            "header" => Placement::Header,
            "cookie" => Placement::Cookie,
            "body" => Placement::Body,
            "auto" => Placement::Auto,
            "queryInHeader" => Placement::QueryInHeader,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PadMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone)]
pub(crate) struct XhttpSettings {
    pub path: String,
    pub mode: XhttpMode,
    pub mode_source: ModeSource,
    pub session_placement: Placement,
    pub session_key: String,
    pub seq_placement: Placement,
    pub seq_key: String,
    pub uplink_data_placement: Placement,
    pub uplink_data_key: String,
    pub uplink_method: String,
    pub x_padding_bytes: (u32, u32),
    pub x_padding_obfs: bool,
    pub x_padding_placement: Placement,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_method: PadMethod,
    pub sc_max_each_post: usize,
    pub sc_max_buffered: usize,
    pub sc_min_posts_interval_ms: u64,
    pub no_sse: bool,
    pub no_grpc_header: bool,
}

impl XhttpSettings {
    pub(crate) fn stream_one() -> Self {
        Self {
            path: "/".to_owned(),
            mode: XhttpMode::StreamOne,
            mode_source: ModeSource::Auto,
            session_placement: Placement::Path,
            session_key: String::new(),
            seq_placement: Placement::Path,
            seq_key: String::new(),
            uplink_data_placement: Placement::Body,
            uplink_data_key: String::new(),
            uplink_method: "POST".to_owned(),
            x_padding_bytes: (100, 1000),
            x_padding_obfs: false,
            x_padding_placement: Placement::Header,
            x_padding_key: "x_padding".to_owned(),
            x_padding_header: "X-Padding".to_owned(),
            x_padding_method: PadMethod::RepeatX,
            sc_max_each_post: 1_000_000,
            sc_max_buffered: 30,
            sc_min_posts_interval_ms: 30,
            no_sse: false,
            no_grpc_header: false,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "straight-line config parse, one block per knob; splitting hides defaults"
    )]
    pub(crate) fn from_json(settings: Option<&crate::json::Json>) -> Option<XhttpSettings> {
        let settings = settings?;
        let Some(xhttp) = settings
            .get("xhttpSettings")
            .or_else(|| settings.get("splithttpSettings"))
        else {
            // A bare xhttp network carries no settings block and means defaults; any other network means this parser does not apply.
            return match settings.get("network").and_then(crate::json::Json::as_str) {
                Some("xhttp" | "splithttp") => Some(XhttpSettings::stream_one()),
                _ => None,
            };
        };
        let mut out = XhttpSettings::stream_one();
        let mut path = xhttp
            .get("path")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("/")
            .to_owned();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        out.path = path;
        let raw = xhttp
            .get("mode")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("");
        out.mode_source = if raw.is_empty() || raw == "auto" {
            ModeSource::Auto
        } else {
            ModeSource::Stated
        };
        out.mode = if out.mode_source == ModeSource::Stated {
            XhttpMode::parse_mode(raw)?
        } else {
            XhttpMode::auto_mode(settings, xhttp)
        };
        // Xray's `SplitHTTPConfig.Build` replaces every knob below but host, path and mode with the `extra` block a link carries, which arrives either as an object or as the JSON string the link query holds.
        let extra = xhttp.get("extra");
        let owned: Option<crate::json::Json> = match extra {
            Some(crate::json::Json::Str(text)) => crate::json::parse(text.as_str()).ok(),
            _ => None,
        };
        let xhttp: &crate::json::Json = match extra {
            None | Some(crate::json::Json::Null) => xhttp,
            Some(node @ crate::json::Json::Obj(_)) => node,
            Some(crate::json::Json::Str(_)) => match owned.as_ref() {
                Some(node @ crate::json::Json::Obj(_)) => node,
                _ => return None,
            },
            Some(_) => return None,
        };
        out.session_placement = placement_or(
            xhttp.get("sessionIDPlacement"),
            Placement::Path,
            &[
                Placement::Path,
                Placement::Cookie,
                Placement::Header,
                Placement::Query,
            ],
        )?;
        out.seq_placement = placement_or(
            xhttp.get("seqPlacement"),
            Placement::Path,
            &[
                Placement::Path,
                Placement::Cookie,
                Placement::Header,
                Placement::Query,
            ],
        )?;
        out.session_key = key_or(
            xhttp.get("sessionIDKey"),
            out.session_placement,
            "x_session",
            "X-Session",
        );
        out.seq_key = key_or(xhttp.get("seqKey"), out.seq_placement, "x_seq", "X-Seq");
        out.uplink_data_placement = placement_or(
            xhttp.get("uplinkDataPlacement"),
            Placement::Body,
            &[
                Placement::Body,
                Placement::Cookie,
                Placement::Header,
                Placement::Auto,
            ],
        )?;
        if matches!(
            out.uplink_data_placement,
            Placement::Cookie | Placement::Header
        ) && out.mode != XhttpMode::PacketUp
        {
            return None;
        }
        xhttp
            .get("uplinkDataKey")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("")
            .clone_into(&mut out.uplink_data_key);
        let mut method = xhttp
            .get("uplinkHTTPMethod")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("POST")
            .to_ascii_uppercase();
        if method.is_empty() {
            "POST".clone_into(&mut method);
        }
        if method == "GET" && out.mode != XhttpMode::PacketUp {
            return None;
        }
        out.uplink_method = method;
        out.x_padding_bytes = match xhttp.get("xPaddingBytes") {
            None => (100, 1000),
            Some(node) => {
                let (from, to) = parse_range(node)?;
                if from == 0 && to == 0 {
                    (100, 1000)
                } else if from == 0 || to == 0 {
                    return None;
                } else {
                    (from, to)
                }
            }
        };
        out.x_padding_obfs = xhttp
            .get("xPaddingObfsMode")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        xhttp
            .get("xPaddingKey")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("x_padding")
            .clone_into(&mut out.x_padding_key);
        xhttp
            .get("xPaddingHeader")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("X-Padding")
            .clone_into(&mut out.x_padding_header);
        out.x_padding_placement = placement_or(
            xhttp.get("xPaddingPlacement"),
            Placement::QueryInHeader,
            &[
                Placement::Cookie,
                Placement::Header,
                Placement::Query,
                Placement::QueryInHeader,
            ],
        )?;
        out.x_padding_method = match xhttp
            .get("xPaddingMethod")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("repeat-x")
        {
            "repeat-x" => PadMethod::RepeatX,
            "tokenish" => PadMethod::Tokenish,
            _ => return None,
        };
        out.no_grpc_header = xhttp
            .get("noGRPCHeader")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        out.no_sse = xhttp
            .get("noSSEHeader")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        out.sc_max_each_post = xhttp
            .get("scMaxEachPostBytes")
            .and_then(parse_range)
            .map_or(1_000_000, |(_, to)| to as usize);
        if out.sc_max_each_post == 0 {
            out.sc_max_each_post = 1_000_000;
        }
        out.sc_max_buffered = xhttp
            .get("scMaxBufferedPosts")
            .and_then(crate::json::Json::as_u32)
            .filter(|n| *n > 0)
            .map_or(30, |n| n as usize);
        out.sc_min_posts_interval_ms = xhttp
            .get("scMinPostsIntervalMs")
            .and_then(parse_range)
            .map_or(30, |(_, to)| u64::from(to));
        if out.sc_min_posts_interval_ms == 0 {
            out.sc_min_posts_interval_ms = 30;
        }
        Some(out)
    }
}

fn placement_or(
    node: Option<&crate::json::Json>,
    default: Placement,
    allowed: &[Placement],
) -> Option<Placement> {
    let Some(node) = node else {
        return Some(default);
    };
    let value = Placement::parse(node.as_str()?)?;
    allowed.contains(&value).then_some(value)
}

fn key_or(
    node: Option<&crate::json::Json>,
    placement: Placement,
    query_default: &str,
    header_default: &str,
) -> String {
    if let Some(key) = node.and_then(crate::json::Json::as_str) {
        return key.to_owned();
    }
    match placement {
        Placement::Cookie | Placement::Query => query_default.to_owned(),
        Placement::Header => header_default.to_owned(),
        _ => String::new(),
    }
}

fn parse_range(node: &crate::json::Json) -> Option<(u32, u32)> {
    if let Some(n) = node.as_u32() {
        return Some((n, n));
    }
    let (a, b) = node.as_str()?.split_once('-')?;
    let (a, b) = (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?);
    Some((a.min(b), a.max(b)))
}

const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

fn huffman_len(s: &[u8]) -> usize {
    s.iter()
        .map(|&b| HUFFMAN_CODE_LEN[b as usize] as usize)
        .sum::<usize>()
        .div_ceil(8)
}

fn generate_tokenish(target_huffman_bytes: usize) -> String {
    let n = (target_huffman_bytes * 10).div_ceil(8);
    let mut raw = vec![0u8; n.max(1)];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    tokenish_adjust(&raw, target_huffman_bytes)
}

/// Maps the random bytes into base62 and walks the padding to its target, but carries the code-length sum instead of re-scanning the whole string on every one of the 150 adjust steps: only the end the loop touches moves the sum.
fn tokenish_adjust(raw: &[u8], target_huffman_bytes: usize) -> String {
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut s: String = raw
        .iter()
        .map(|&b| BASE62[(b as usize) % 62] as char)
        .collect();
    let mut bits: usize = s
        .bytes()
        .map(|b| usize::from(HUFFMAN_CODE_LEN[usize::from(b)]))
        .sum();
    for iter in 0..150 {
        let cur = bits.div_ceil(8);
        if cur.abs_diff(target_huffman_bytes) <= 2 {
            return s;
        }
        if cur < target_huffman_bytes {
            let added = if iter % 2 == 0 { b'X' } else { b'Z' };
            bits += usize::from(HUFFMAN_CODE_LEN[usize::from(added)]);
            s.push(added as char);
        } else if s.len() > 1 {
            let last = s.as_bytes()[s.len() - 1];
            s.pop();
            bits -= usize::from(HUFFMAN_CODE_LEN[usize::from(last)]);
        } else {
            return s;
        }
    }
    s
}

fn pad_value(method: PadMethod, len: usize) -> String {
    match method {
        PadMethod::RepeatX => "X".repeat(len),
        PadMethod::Tokenish => generate_tokenish(len),
    }
}

fn pad_target_len(settings: &XhttpSettings) -> usize {
    let (from, to) = settings.x_padding_bytes;
    if to <= from {
        return from as usize;
    }
    let mut raw = [0u8; 4];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    from as usize + (u32::from_le_bytes(raw) as usize % (to as usize - from as usize + 1))
}

fn padding_valid(value: &str, from: u32, to: u32, method: PadMethod) -> bool {
    if value.is_empty() {
        return false;
    }
    match method {
        PadMethod::RepeatX => {
            let n = value.len() as u32;
            n >= from && n <= to
        }
        PadMethod::Tokenish => {
            let n = huffman_len(value.as_bytes()) as u32;
            n >= from.saturating_sub(2) && n <= to + 2
        }
    }
}

fn query_param<'a>(target: &'a str, key: &str) -> Option<&'a str> {
    let q = target.split_once('?')?.1;
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

fn header_cookie<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.eq_ignore_ascii_case("cookie") {
            for part in v.trim().split(';') {
                let Some((n, val)) = part.trim().split_once('=') else {
                    continue;
                };
                if n == name {
                    return Some(val);
                }
            }
        }
    }
    None
}

fn extract_padding<'a>(
    head: &'a [u8],
    target: &'a str,
    settings: &XhttpSettings,
) -> Option<&'a str> {
    if !settings.x_padding_obfs {
        if let Some(remark) = crate::proxy::header_value(head, "referer") {
            if let Some(v) = query_param(remark, "x_padding") {
                return Some(v);
            }
        }
        return query_param(target, "x_padding");
    }
    if let Some(cookie) = header_cookie(head, &settings.x_padding_key) {
        return Some(cookie);
    }
    if let Some(value) = crate::proxy::header_value(head, &settings.x_padding_header) {
        if settings.x_padding_placement == Placement::Header {
            return Some(value);
        }
        if let Some(v) = query_param(value, &settings.x_padding_key) {
            return Some(v);
        }
    }
    query_param(target, &settings.x_padding_key)
}

fn extract_meta<'a>(
    head: &'a [u8],
    target: &'a str,
    settings: &XhttpSettings,
) -> (Option<&'a str>, Option<&'a str>) {
    // The path segments are read only by a `Path` placement; splitting and collecting them for a query-, header- or cookie-placed session is a needless allocation and scan, so build them only when one is asked for.
    let need_path = matches!(settings.session_placement, Placement::Path)
        || matches!(settings.seq_placement, Placement::Path);
    let segments: Vec<&str> = if need_path {
        let rest = target.strip_prefix(settings.path.as_str()).unwrap_or("");
        let rest_path = rest.split_once('?').map_or(rest, |(r, _)| r);
        rest_path.split('/').filter(|s| !s.is_empty()).collect()
    } else {
        Vec::new()
    };
    let mut sid = None;
    let mut seq = None;
    let mut idx = 0;
    if settings.session_placement == Placement::Path {
        sid = segments.get(idx).copied();
        idx += 1;
    }
    if settings.seq_placement == Placement::Path {
        seq = segments.get(idx).copied();
    }
    if settings.session_placement == Placement::Query {
        sid = query_param(target, &settings.session_key);
    }
    if settings.session_placement == Placement::Header {
        sid = crate::proxy::header_value(head, &settings.session_key);
    }
    if settings.session_placement == Placement::Cookie {
        sid = header_cookie(head, &settings.session_key);
    }
    if settings.seq_placement == Placement::Query {
        seq = query_param(target, &settings.seq_key);
    }
    if settings.seq_placement == Placement::Header {
        seq = crate::proxy::header_value(head, &settings.seq_key);
    }
    if settings.seq_placement == Placement::Cookie {
        seq = header_cookie(head, &settings.seq_key);
    }
    (sid, seq)
}

struct Session {
    state: Mutex<SessionState>,
    cv: Condvar,
}

struct SessionState {
    upload: Option<Box<dyn Read + Send>>,
    packets: BTreeMap<u64, Vec<u8>>,
    next_seq: u64,
    ended: bool,
}

type Sessions = Mutex<HashMap<String, Arc<Session>>>;

fn sessions() -> &'static Sessions {
    static CELL: LazyLock<Sessions> = LazyLock::new(|| Mutex::new(HashMap::new()));
    &CELL
}

fn get_or_create_session(id: &str) -> Arc<Session> {
    let mut map = sessions().lock().expect("sessions lock");
    map.entry(id.to_owned())
        .or_insert_with(|| {
            Arc::new(Session {
                state: Mutex::new(SessionState {
                    upload: None,
                    packets: BTreeMap::new(),
                    next_seq: 0,
                    ended: false,
                }),
                cv: Condvar::new(),
            })
        })
        .clone()
}

fn close_session(s: &Arc<Session>) {
    let mut st = s.state.lock().expect("session lock");
    st.ended = true;
    s.cv.notify_all();
}

// Drop is the only other way a session ends, and a waiter parked before a reader exists has no Drop to run.
pub(crate) fn end_session(id: &str) {
    let carried = sessions().lock().expect("sessions lock").remove(id);
    if let Some(carried) = carried {
        close_session(&carried);
    }
}

#[cfg(test)]
pub(crate) fn session_is_carried(id: &str) -> bool {
    sessions().lock().expect("sessions lock").contains_key(id)
}

/// An h2 connection owns the sessions its streams opened, so its death can end them; a bare H1 request has no carrier to bind to.
fn bound_session(sid: &str, h2: Option<&crate::xhttp_h2::H2StreamOut>) -> Arc<Session> {
    let session = get_or_create_session(sid);
    if let Some(h2) = h2 {
        h2.bind_session(sid);
    }
    session
}

impl Session {
    fn set_upload(&self, reader: Box<dyn Read + Send>) {
        let mut st = self.state.lock().expect("session lock");
        st.upload = Some(reader);
        self.cv.notify_all();
    }
    fn push_packet(&self, seq: u64, payload: Vec<u8>, cap: usize) -> bool {
        let mut st = self.state.lock().expect("session lock");
        if st.packets.len() >= cap {
            return false;
        }
        st.packets.insert(seq, payload);
        self.cv.notify_all();
        true
    }
    fn wait_ended(&self) {
        let mut st = self.state.lock().expect("session lock");
        while !st.ended {
            st = self.cv.wait(st).expect("session lock");
        }
    }
}

struct SessionReader {
    session: Arc<Session>,
    id: String,
    cur: Vec<u8>,
    cur_at: usize,
}

impl SessionReader {
    fn new(session: Arc<Session>, id: String) -> Self {
        Self {
            session,
            id,
            cur: Vec::new(),
            cur_at: 0,
        }
    }
}

impl Read for SessionReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let upload = {
                let mut st = self.session.state.lock().expect("session lock");
                st.upload.take()
            };
            if let Some(mut upload) = upload {
                let got = upload.read(buf);
                let mut st = self.session.state.lock().expect("session lock");
                st.upload = Some(upload);
                return match got {
                    Ok(0) => {
                        st.ended = true;
                        self.session.cv.notify_all();
                        Ok(0)
                    }
                    Ok(n) => {
                        drop(st);
                        Ok(n)
                    }
                    Err(e) => {
                        st.ended = true;
                        self.session.cv.notify_all();
                        Err(e)
                    }
                };
            }
            let mut st = self.session.state.lock().expect("session lock");
            if self.cur_at < self.cur.len() {
                let avail = &self.cur[self.cur_at..];
                let n = avail.len().min(buf.len());
                buf[..n].copy_from_slice(&avail[..n]);
                self.cur_at += n;
                if self.cur_at == self.cur.len() {
                    self.cur.clear();
                    self.cur_at = 0;
                }
                return Ok(n);
            }
            if let Some(pkt) = {
                let seq = st.next_seq;
                st.packets.remove(&seq)
            } {
                st.next_seq += 1;
                if pkt.len() <= buf.len() {
                    buf[..pkt.len()].copy_from_slice(&pkt);
                    return Ok(pkt.len());
                }
                self.cur = pkt;
                self.cur_at = buf.len();
                buf.copy_from_slice(&self.cur[..buf.len()]);
                return Ok(buf.len());
            }
            if st.ended {
                return Ok(0);
            }
            st = self.session.cv.wait(st).expect("session lock");
        }
    }
}

impl Drop for SessionReader {
    fn drop(&mut self) {
        if !self.id.is_empty() {
            let mut map = sessions().lock().expect("sessions lock");
            map.remove(&self.id);
        }
        close_session(&self.session);
    }
}

fn downlink_headers(settings: &XhttpSettings) -> String {
    if settings.no_sse {
        String::new()
    } else {
        "Content-Type: text/event-stream\r\n".to_owned()
    }
}

fn padded_response(stream: &mut impl Write, settings: &XhttpSettings, padded: &str, framing: &str) {
    let mut head = String::from("HTTP/1.1 200 OK\r\n");
    if settings.x_padding_obfs {
        match settings.x_padding_placement {
            Placement::Header => {
                head.push_str(&settings.x_padding_header);
                head.push_str(": ");
                head.push_str(padded);
                head.push_str("\r\n");
            }
            Placement::Cookie => {
                head.push_str("Set-Cookie: ");
                head.push_str(&settings.x_padding_key);
                head.push('=');
                head.push_str(padded);
                head.push_str("; Path=/\r\n");
            }
            _ => {
                head.push_str("X-Padding: ");
                head.push_str(padded);
                head.push_str("\r\n");
            }
        }
    } else {
        head.push_str("X-Padding: ");
        head.push_str(padded);
        head.push_str("\r\n");
    }
    head.push_str("X-Accel-Buffering: no\r\n");
    head.push_str("Cache-Control: no-store\r\n");
    head.push_str(&downlink_headers(settings));
    head.push_str(framing);
    let _ = stream.write_all(head.as_bytes());
}

fn sse_ok(stream: &mut impl Write, settings: &XhttpSettings, padded: &str) {
    padded_response(
        stream,
        settings,
        padded,
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
    );
}

fn plain_ok(stream: &mut impl Write, settings: &XhttpSettings, padded: &str) {
    padded_response(
        stream,
        settings,
        padded,
        "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    );
}

fn ok_status(head: &[u8]) -> bool {
    std::str::from_utf8(head)
        .ok()
        .and_then(|t| t.lines().next().map(|l| l.starts_with("HTTP/1.1 200 OK")))
        .unwrap_or(false)
}

fn check_response(head: &[u8]) -> Option<()> {
    if !ok_status(head) {
        return None;
    }
    if !crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked) {
        return None;
    }
    Some(())
}

fn emit_404(stream: &mut impl Write) {
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
fn emit_400(stream: &mut impl Write) {
    let _ = stream
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
fn emit_405(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}
fn emit_413(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn emit_500(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn content_length(head: &[u8]) -> Option<usize> {
    crate::proxy::header_value(head, "content-length").and_then(|v| v.trim().parse().ok())
}

// --- Server ------------------------------------------------------------------

// The stream-one handshake the tree has always served: POST with chunked framing on one connection; mode handshakes live in `accept_with_settings`, and this stays so every existing rung keeps dialling.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(XhttpReader, XhttpWriter)> {
    let mut read = stream;
    let (head, at) = read_head(&mut read)?;
    check_request(&head[..at], path)?;
    read.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n").ok()?;
    split(read, head, at)
}

fn check_request(head: &[u8], path: &str) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    let mut parts = text.split("\r\n").next()?.split_ascii_whitespace();
    if parts.next()? != "POST" {
        return None;
    }
    let target = parts.next()?;
    if !path_covers(path, bare_path(target)) {
        return None;
    }
    if !crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked) {
        return None;
    }
    Some(())
}

// The same accept over halves that cannot peek: pipelined bytes arrive as a prefix. One connection serves requests until a session takes it or a request ends it, so a packet-up uplink does not pay a new connection per POST.
pub(crate) fn accept_split_with_settings<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    read: R,
    write: W,
    settings: &XhttpSettings,
) -> Option<(Box<dyn Read + Send>, XhttpWriter)> {
    let mut read = ChainReader::new(Vec::new(), read);
    let mut write = write;
    loop {
        let (head, prefix) =
            crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
        match accept_core(&head, prefix, read, write, settings, None) {
            Served::Session(reader, writer) => return Some((reader, writer)),
            Served::Again(next, next_write, carry) => {
                read = next;
                write = next_write;
                read.set_carry(carry);
            }
            Served::Closed => return None,
        }
    }
}

fn writer_for<W: crate::proxy::FrameWrite + Send + 'static>(
    write: W,
    h2: Option<crate::xhttp_h2::H2StreamOut>,
) -> XhttpWriter {
    let writer = XhttpWriter::new(write);
    if let Some(h) = h2 {
        writer.set_h2(h);
    }
    writer
}

/// What one request leaves the connection to. `Session` hands both halves to a session that owns them for as long as the stream lives; `Again` gives them back, with the bytes that came with this request but belong to the next; `Closed` is the end of the connection.
pub(crate) enum Served<R, W> {
    Session(Box<dyn Read + Send>, XhttpWriter),
    Again(R, W, Vec<u8>),
    Closed,
}

/// Whether the client means to keep this connection: HTTP/1.1 keeps alive unless the request says otherwise, HTTP/1.0 only when it does.
fn keeps_alive(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let mut lines = text.lines();
    let mut keep = !lines
        .next()
        .unwrap_or_default()
        .trim_end()
        .ends_with("HTTP/1.0");
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("connection") {
            continue;
        }
        let value = value.to_ascii_lowercase();
        keep = value.split(',').any(|part| part.trim() == "keep-alive")
            && !value.split(',').any(|part| part.trim() == "close");
    }
    keep
}

/// The body of `n` bytes, and how much of the bytes already read as the head it used; the rest of those belong to the next request on this connection.
fn read_body<R: Read>(read: &mut R, prefix: &[u8], n: usize) -> Option<(Vec<u8>, usize)> {
    let mut buf = vec![0u8; n];
    let pre = prefix.len().min(n);
    buf[..pre].copy_from_slice(&prefix[..pre]);
    let mut at = pre;
    while at < n {
        match read.read(&mut buf[at..]) {
            Ok(0) | Err(_) => return None,
            Ok(r) => at += r,
        }
    }
    Some((buf, pre))
}

/// How reading a body that ends only when its stream ends turned out.
enum Drained {
    Done(Vec<u8>),
    Over,
    Broken,
}

/// The body until the stream ends, with `Over` naming a payload past the per-request cap.
fn drain_body(read: &mut dyn Read, cap: usize) -> Drained {
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match read.read(&mut buf) {
            Ok(0) => return Drained::Done(body),
            Ok(n) => {
                body.extend_from_slice(&buf[..n]);
                if body.len() > cap {
                    return Drained::Over;
                }
            }
            Err(_) => return Drained::Broken,
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one arm per method and session shape; the dispatch is the function"
)]
pub(crate) fn accept_core<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    head: &[u8],
    prefix: Vec<u8>,
    mut read: R,
    mut write: W,
    settings: &XhttpSettings,
    h2: Option<crate::xhttp_h2::H2StreamOut>,
) -> Served<R, W> {
    let Ok(text) = std::str::from_utf8(head) else {
        return Served::Closed;
    };
    let Some(first) = text.lines().next() else {
        return Served::Closed;
    };
    let mut parts = first.split_ascii_whitespace();
    let Some(method) = parts.next() else {
        return Served::Closed;
    };
    let Some(target) = parts.next() else {
        return Served::Closed;
    };

    if !path_covers(settings.path.as_str(), bare_path(target)) {
        emit_404(&mut write);
        return Served::Closed;
    }

    let padded = pad_value(settings.x_padding_method, pad_target_len(settings));

    if method == "OPTIONS" {
        let alive = keeps_alive(head);
        let mut resp = String::from("HTTP/1.1 200 OK\r\n");
        if !settings.x_padding_obfs {
            let _ = write!(resp, "X-Padding: {padded}\r\n");
        }
        resp.push_str("Access-Control-Allow-Methods: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Origin: *\r\n");
        resp.push_str("Content-Length: 0\r\nConnection: keep-alive\r\n\r\n");
        let _ = write.write_all(resp.as_bytes());
        if h2.is_none() && alive {
            return Served::Again(read, write, prefix);
        }
        return Served::Closed;
    }

    let pad_ok = match extract_padding(head, target, settings) {
        Some(v) => padding_valid(
            v,
            settings.x_padding_bytes.0,
            settings.x_padding_bytes.1,
            settings.x_padding_method,
        ),
        None => false,
    };
    if !pad_ok {
        emit_400(&mut write);
        return Served::Closed;
    }

    let (sid, seq) = extract_meta(head, target, settings);

    match (sid, seq) {
        (None, None) => {
            if settings.mode_source == ModeSource::Stated
                && !matches!(settings.mode, XhttpMode::StreamOne | XhttpMode::StreamUp)
            {
                emit_400(&mut write);
                return Served::Closed;
            }
            if method == "GET" {
                sse_ok(&mut write, settings, &padded);
                let writer = writer_for(write, h2);
                let session = get_or_create_session("__none__");
                session.state.lock().expect("session lock").ended = true;
                return Served::Session(
                    Box::new(SessionReader::new(session, String::new())),
                    writer,
                );
            }
            if method == settings.uplink_method.as_str() {
                if h2.is_none()
                    && !crate::proxy::header_value(head, "transfer-encoding")
                        .is_some_and(has_chunked)
                {
                    emit_400(&mut write);
                    return Served::Closed;
                }
                sse_ok(&mut write, settings, &padded);
                let reader: Box<dyn Read + Send> = if h2.is_some() {
                    Box::new(read)
                } else {
                    Box::new(Reader {
                        read,
                        prefix,
                        at: 0,
                        left: 0,
                        ended: false,
                        reads: 0,
                    })
                };
                let writer = writer_for(write, h2);
                return Served::Session(reader, writer);
            }
            emit_405(&mut write);
            Served::Closed
        }
        (Some(sid), None) => {
            if method == "GET" {
                if settings.mode == XhttpMode::StreamOne {
                    emit_400(&mut write);
                    return Served::Closed;
                }
                let session = bound_session(sid, h2.as_ref());
                sse_ok(&mut write, settings, &padded);
                let writer = writer_for(write, h2);
                return Served::Session(
                    Box::new(SessionReader::new(session, sid.to_owned())),
                    writer,
                );
            }
            if settings.mode != XhttpMode::StreamUp {
                emit_400(&mut write);
                return Served::Closed;
            }
            if !crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked)
                && h2.is_none()
            {
                emit_400(&mut write);
                return Served::Closed;
            }
            let session = bound_session(sid, h2.as_ref());
            if h2.is_some() {
                session.set_upload(Box::new(read));
            } else {
                session.set_upload(Box::new(Reader {
                    read,
                    prefix,
                    at: 0,
                    left: 0,
                    ended: false,
                    reads: 0,
                }));
            }
            plain_ok(&mut write, settings, &padded);
            session.wait_ended();
            Served::Closed
        }
        (Some(sid), Some(seq)) => {
            if settings.mode != XhttpMode::PacketUp {
                emit_400(&mut write);
                return Served::Closed;
            }
            let Ok(seq_num) = seq.parse::<u64>() else {
                emit_500(&mut write);
                return Served::Closed;
            };
            let session = bound_session(sid, h2.as_ref());
            // The body arrives whatever the placement carries the packet in: an unread one would leave the next request's head sitting in its bytes.
            let mut body = Vec::new();
            let mut carry = Vec::new();
            let mut resumable = true;
            if let Some(n) = content_length(head) {
                if n > settings.sc_max_each_post {
                    emit_413(&mut write);
                    return Served::Closed;
                }
                let Some((buf, pre)) = read_body(&mut read, &prefix, n) else {
                    return Served::Closed;
                };
                carry = prefix[pre..].to_vec();
                body = buf;
            } else if crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked)
            {
                // A chunked body leaves no length behind that the next request's head could be found after.
                resumable = false;
                let mut chain = ChainReader::new(prefix, &mut read);
                let drained = if h2.is_some() {
                    drain_body(&mut chain, settings.sc_max_each_post)
                } else {
                    let mut framed = Reader {
                        read: &mut chain,
                        prefix: Vec::new(),
                        at: 0,
                        left: 0,
                        ended: false,
                        reads: 0,
                    };
                    drain_body(&mut framed, settings.sc_max_each_post)
                };
                match drained {
                    Drained::Done(buf) => body = buf,
                    Drained::Over => {
                        emit_413(&mut write);
                        return Served::Closed;
                    }
                    Drained::Broken => return Served::Closed,
                }
            } else {
                carry = prefix;
            }
            let payload = match settings.uplink_data_placement {
                Placement::Header => {
                    let key = if settings.uplink_data_key.is_empty() {
                        "X-Data".to_owned()
                    } else {
                        settings.uplink_data_key.clone()
                    };
                    let mut joined = String::new();
                    // One reusable name buffer, so the loop does not hand a fresh allocation to every part — and the final miss that only ends the run costs nothing.
                    let mut name = String::with_capacity(key.len() + 4);
                    for i in 0.. {
                        name.clear();
                        let _ = write!(name, "{key}-{i}");
                        match crate::proxy::header_value(head, &name) {
                            Some(v) => joined.push_str(v),
                            None => break,
                        }
                    }
                    url_decode(&joined)
                }
                Placement::Cookie => {
                    let key = if settings.uplink_data_key.is_empty() {
                        "x_data".to_owned()
                    } else {
                        settings.uplink_data_key.clone()
                    };
                    let mut joined = String::new();
                    // One reusable name buffer, so the loop does not hand a fresh allocation to every part — and the final miss that only ends the run costs nothing.
                    let mut name = String::with_capacity(key.len() + 4);
                    for i in 0.. {
                        name.clear();
                        let _ = write!(name, "{key}_{i}");
                        match header_cookie(head, &name) {
                            Some(v) => joined.push_str(v),
                            None => break,
                        }
                    }
                    url_decode(&joined)
                }
                _ => Some(body),
            };
            let Some(payload) = payload else {
                emit_400(&mut write);
                return Served::Closed;
            };
            if payload.len() > settings.sc_max_each_post {
                emit_413(&mut write);
                return Served::Closed;
            }
            if !session.push_packet(seq_num, payload, settings.sc_max_buffered) {
                // A refused packet is a lost one — the reader waits on strict sequence — so the session is over; keeping it alive would park its reader on a sequence that can never arrive.
                end_session(sid);
                emit_500(&mut write);
                return Served::Closed;
            }
            plain_ok(&mut write, settings, &padded);
            if resumable && h2.is_none() && keeps_alive(head) {
                return Served::Again(read, write, carry);
            }
            Served::Closed
        }
        (None, Some(_)) => {
            emit_405(&mut write);
            Served::Closed
        }
    }
}

// The stream-one dial: one POST, chunked framing both ways.
fn dial_head(host: &str, path: &str) -> String {
    let mut raw = [0u8; 4];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    let len = 100 + u32::from_le_bytes(raw) as usize % 901;
    format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nReferer: http://{host}{path}?x_padding={}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n", "X".repeat(len))
}

pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
) -> Option<(XhttpReader, XhttpWriter)> {
    let mut read = stream;
    read.write_all(dial_head(host, path).as_bytes()).ok()?;
    let (head, at) = read_head(&mut read)?;
    check_response(&head[..at])?;
    split(read, head, at)
}

// The same connect over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
) -> Option<(Reader<R>, XhttpWriter)> {
    write.write_all(dial_head(host, path).as_bytes()).ok()?;
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head)?;
    Some(split_halves(read, write, prefix, 0))
}

impl crate::proxy::CarrierSink for XhttpWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn close(&self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// The tokenish adjust as it was — the whole string re-summed on every one of the 150 steps — kept as the oracle the carried sum is compared against.
    fn tokenish_recompute(raw: &[u8], target: usize) -> String {
        const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut s: String = raw
            .iter()
            .map(|&b| BASE62[(b as usize) % 62] as char)
            .collect();
        for iter in 0..150 {
            let cur = huffman_len(s.as_bytes());
            if cur.abs_diff(target) <= 2 {
                return s;
            }
            if cur < target {
                s.push(if iter % 2 == 0 { 'X' } else { 'Z' });
            } else if s.len() > 1 {
                s.pop();
            } else {
                return s;
            }
        }
        s
    }

    #[test]
    fn tokenish_carry_matches_the_recompute_on_every_probe() {
        let mut targets: Vec<usize> = (0..=64).collect();
        targets.extend([251, 997, 1500]);
        for target in targets {
            let n = ((target * 10).div_ceil(8)).max(1);
            let mut runs: Vec<Vec<u8>> = vec![vec![0u8; n], vec![255u8; n], vec![61u8; n]];
            let mut state = 0x2545_F491_4F6C_DD1Du64;
            let mut raw = Vec::with_capacity(n);
            for _ in 0..n {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                raw.push((state >> 33) as u8);
            }
            runs.push(raw);
            for raw in runs {
                assert_eq!(
                    tokenish_adjust(&raw, target),
                    tokenish_recompute(&raw, target),
                    "target {target} raw {raw:?}"
                );
            }
        }
    }

    /// The same drain over a real socket asserts the *bytes* and nothing else: a socket may segment, so its read count moves with the scheduler and cannot gate a number — that claim belongs to `a_chunk_costs_two_reads_not_three`, on an in-memory stream that answers the whole buffer.
    #[test]
    fn a_real_socket_drains_the_same_bytes() {
        let count = 16usize;
        let mut wire = Vec::new();
        for _ in 0..count {
            wire.extend_from_slice(format!("{CHUNK:X}\r\n").as_bytes());
            wire.extend(std::iter::repeat_n(0x5Au8, CHUNK));
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let h = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 4096];
            let n = sock.read(&mut head).expect("reads the request");
            assert!(n > 0);
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .expect("replies");
            sock.write_all(&wire).expect("sends");
            sock.shutdown(std::net::Shutdown::Write).ok();
        });
        let sock = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, _w) = connect(sock, "h", "/share").expect("dials");
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0usize;
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got += n;
        }
        h.join().expect("joins");
        assert_eq!(got, CHUNK * count, "the payload must be byte-identical");
        assert!(reader.reads() <= count * 3 + 1, "a bound, not the claim");
    }

    #[test]
    fn size_lines_match_format_without_allocating() {
        for n in [1usize, 9, 10, 15, 16, 255, 256, 4096, 16384] {
            let mut line = [0u8; 6];
            let len = size_line(n, &mut line);
            assert_eq!(&line[..len], format!("{n:X}\r\n").as_bytes());
        }
    }

    #[test]
    fn paths_cover_prefixes_without_crossing_names() {
        assert!(path_covers("/service", "/service"));
        assert!(path_covers("/service", "/service/session"));
        assert!(path_covers("/", "/anything"));
        assert!(!path_covers("/service", "/service-evil"));
        assert!(path_covers("/up/", "/up/sess-01"));
        assert!(path_covers("/up/", "/up/"));
        assert!(!path_covers("/up/", "/up-evil"));
    }

    #[test]
    fn chunked_matches_case_insensitive_contains() {
        for (value, want) in [
            ("chunked", true),
            ("Chunked", true),
            ("CHUNKED", true),
            ("gzip, chunked", true),
            ("chunked, gzip", true),
            ("mychunked", true),
            ("chunkedx", true),
            ("chu", false),
            ("", false),
            ("gzip", false),
            ("identity", false),
        ] {
            assert_eq!(has_chunked(value), want, "{value}");
        }
    }

    /// The two-pass form kept as the oracle for the fused rewrite: same None-when-invalid, same Some for every accepted size line.
    fn chunk_size_two_pass(line: &[u8]) -> Option<usize> {
        let mut end = line.len();
        for (i, &b) in line.iter().enumerate() {
            if b == b';' || b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                end = i;
                break;
            }
        }
        if end == 0 || end > 16 {
            return None;
        }
        let mut size = 0usize;
        for &b in &line[..end] {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => 10 + (b - b'a'),
                b'A'..=b'F' => 10 + (b - b'A'),
                _ => return None,
            } as usize;
            size = size * 16 + digit;
        }
        Some(size)
    }

    /// Bit-identity for the fused `chunk_size`: for every length 0..=20 and every probe byte at every position (with the rest filled by `1`, a hex digit), the fused loop and the two-pass reference agree. The full-window cases (length 16 with and without a terminator) and the length that overruns the cap (17) are the ones the fused rewrite could have moved, so they are covered explicitly.
    #[test]
    fn chunk_size_fused_matches_two_pass_on_every_probe() {
        let probes: [u8; 18] = [
            b'0', b'1', b'9', b'a', b'f', b'A', b'F', b';', b' ', b'\t', b'\r', b'\n', b'g', b'/',
            b':', b'@', b'`', 0xff,
        ];
        for len in 0..=20usize {
            let base = vec![b'1'; len];
            assert_eq!(
                chunk_size(&base),
                chunk_size_two_pass(&base),
                "all-hex len={len}"
            );
            for i in 0..len {
                for &probe in &probes {
                    let mut line = base.clone();
                    line[i] = probe;
                    assert_eq!(
                        chunk_size(&line),
                        chunk_size_two_pass(&line),
                        "len={len} pos={i} probe={probe:#04x}"
                    );
                }
            }
        }
        for prefix in [
            "",
            ";",
            " ;",
            "\t;",
            "\r\n",
            "f",
            "ff",
            "Ff",
            "1234567890abcdef",
            "1234567890abcdef;",
            "1234567890abcdef\r\n",
            "1234567890abcdefg",
            "1234567890abcdefg;",
            "1234567890abcdef0",
            "1234567890abcdef0;",
            "ffffffffffffffff",
            "fffffffffffffffff",
            "0",
            "0;",
            "00000",
        ] {
            assert_eq!(
                chunk_size(prefix.as_bytes()),
                chunk_size_two_pass(prefix.as_bytes()),
                "prefix={prefix:?}"
            );
        }
    }

    #[test]
    fn exchange_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/share").expect("serves");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
            writer.finish();
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) = connect(stream, "oracle.example", "/share").expect("dials");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// Reads are driven with a fixed CHUNK buffer, the way `relay_ordered` drives them, so the count is the reader's and not `read_to_end`'s buffer growth; `reads` is the counter that says so.
    #[test]
    fn a_chunk_costs_two_reads_not_three() {
        fn framed(chunks: &[usize]) -> Vec<u8> {
            let mut wire = Vec::new();
            for &n in chunks {
                wire.extend_from_slice(format!("{n:X}\r\n").as_bytes());
                wire.extend(std::iter::repeat_n(0x5Au8, n));
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
            wire
        }

        for count in [1usize, 2, 4, 8, 16] {
            let chunks: Vec<usize> = std::iter::repeat_n(CHUNK, count).collect();
            let payload: Vec<u8> = vec![0x5Au8; CHUNK * count];
            let mut reader = Reader {
                read: std::io::Cursor::new(framed(&chunks)),
                prefix: Vec::new(),
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
            };
            let mut got = Vec::new();
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = reader.read(&mut buf).expect("reads");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, payload, "{count} chunks: the bytes must be unchanged");
            // Two reads per chunk amortised -- one framing window, one body -- plus the terminating size line. The old shape read the size line and the two-byte CRLF separately, so it cost three per chunk.
            assert_eq!(
                reader.reads(),
                count * 2 + 1,
                "{count} chunks: framing reads must amortise to one per chunk"
            );
        }
    }

    /// The kept head hands the reader its own buffer with the head already walked past: the chunk that rode in behind the head is delivered without asking the socket, and its bytes never move.
    #[test]
    fn a_chunk_that_rode_in_with_the_head_costs_no_syscall() {
        const HEAD: &[u8] =
            b"POST /share HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut prefix = Vec::from(HEAD);
        prefix.extend_from_slice(b"2\r\nhi\r\n0\r\n\r\n");
        let base = prefix.as_ptr();
        let capacity = prefix.capacity();
        let (mut reader, _writer) = split_halves(
            std::io::Cursor::new(Vec::from(&b"never read"[..])),
            Sink(Arc::new(Mutex::new(Vec::new()))),
            prefix,
            HEAD.len(),
        );
        let mut got = [0u8; 2];
        assert_eq!(reader.read(&mut got).expect("delivers"), 2);
        assert_eq!(&got, b"hi", "the chunk behind the head, not a re-read");
        assert_eq!(reader.read(&mut got).expect("ends"), 0);
        assert!(
            reader.ended,
            "the terminator was walked out of the same buffer"
        );
        assert_eq!(reader.reads(), 0, "the socket was never asked");
        assert_eq!(
            reader.prefix.as_ptr(),
            base,
            "delivered from the buffer those bytes arrived in"
        );
        assert_eq!(reader.prefix.capacity(), capacity, "on a held capacity");
    }

    /// The counter must see the *short* reads too: one byte at a time is the worst case, and it is what makes a bounded window better than an unbounded one.
    #[test]
    fn a_trickling_stream_still_drains_whole() {
        struct Trickle {
            inner: std::io::Cursor<Vec<u8>>,
        }
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let take = buf.len().min(1);
                self.inner.read(&mut buf[..take])
            }
        }

        let mut wire = Vec::new();
        wire.extend_from_slice(b"40\r\n");
        wire.extend(std::iter::repeat_n(0x11u8, 64));
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(b"0\r\n\r\n");
        let mut reader = Reader {
            read: Trickle {
                inner: std::io::Cursor::new(wire),
            },
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
        };
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("drains");
        assert_eq!(got, vec![0x11u8; 64]);
        assert!(
            reader.reads() > 64,
            "one byte per read cannot be fewer reads than bytes, got {}",
            reader.reads()
        );
    }

    /// A socket delivers what the peer wrote, not what the frame asks for: the two bytes that close a chunk can arrive one per read, and a reader that insists both sit in its buffer refuses an intact stream.
    #[test]
    fn a_crlf_split_across_reads_still_drains() {
        struct Segments {
            pieces: std::vec::IntoIter<&'static [u8]>,
        }
        impl Read for Segments {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let Some(piece) = self.pieces.next() else {
                    return Ok(0);
                };
                let n = piece.len().min(buf.len());
                buf[..n].copy_from_slice(&piece[..n]);
                Ok(n)
            }
        }

        let mut reader = Reader {
            read: Segments {
                pieces: vec![b"4\r\nping\r".as_slice(), b"\n4\r\npong\r\n0\r\n\r\n"].into_iter(),
            },
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
        };
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("drains");
        assert_eq!(got, b"pingpong");
    }

    #[test]
    fn chunks_drain_in_order_before_the_close_is_answered() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/share").expect("serves");
            let mut first = [0u8; 26];
            reader.read_exact(&mut first).expect("reads header");
            assert!(writer.send(&[0, 0]));
            let mut ping = [0u8; 4];
            reader.read_exact(&mut ping).expect("reads ping");
            assert_eq!(&ping, b"ping");
            assert!(writer.send(b"ping"));
            let mut drained = Vec::new();
            reader.read_to_end(&mut drained).expect("drains the close");
            assert_eq!(drained, [] as [u8; 0]);
            writer.finish();
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("timeout");
        let (mut reader, writer) = connect(stream, "h", "/share").expect("dials");
        assert!(writer.send(&[1u8; 26]));
        let mut reply = [0u8; 2];
        reader.read_exact(&mut reply).expect("replies");
        assert_eq!(reply, [0, 0]);
        assert!(writer.send(b"ping"));
        writer.finish();
        let mut back = Vec::new();
        reader.read_to_end(&mut back).expect("echoes");
        assert_eq!(back, b"ping");
        server.join().expect("joins");
    }

    #[test]
    fn exchange_rejects_a_wrong_path() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/share").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"POST /other HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }

    #[test]
    fn settings_parse_covers_the_test_config() {
        let node = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
            "path": "/interop-xhttp/", "mode": "packet-up", "xPaddingBytes": 64,
            "uplinkHTTPMethod": "POST", "sessionIDPlacement": "path",
            "seqPlacement": "path", "uplinkDataPlacement": "body",
            "uplinkChunkSize": 4096, "scMaxEachPostBytes": 4096,
            "scMinPostsIntervalMs": 1,
            "xmux": {"maxConcurrency": 1, "hMaxRequestTimes": 64, "hMaxReusableSecs": 3600}}}}"#,
        )
        .expect("parses");
        let settings =
            XhttpSettings::from_json(node.get("streamSettings")).expect("settings parse");
        assert_eq!(settings.path, "/interop-xhttp/");
        assert_eq!(settings.mode, XhttpMode::PacketUp);
        assert_eq!(settings.x_padding_bytes, (64, 64));
        assert_eq!(settings.uplink_method, "POST");
        assert_eq!(settings.session_placement, Placement::Path);
        assert_eq!(settings.seq_placement, Placement::Path);
        assert_eq!(settings.uplink_data_placement, Placement::Body);
        assert_eq!(settings.sc_max_each_post, 4096);
        assert_eq!(settings.sc_min_posts_interval_ms, 1);
        assert_eq!(settings.x_padding_method, PadMethod::RepeatX);
        assert!(!settings.x_padding_obfs);
        assert!(!settings.no_sse);

        let bad_mode =
            crate::json::parse(r#"{"xhttpSettings": {"mode": "multi"}}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad_mode)).is_none());
        let bad_placement =
            crate::json::parse(r#"{"xhttpSettings": {"sessionIDPlacement": "cookie-jar"}}"#)
                .expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad_placement)).is_none());
        let bad_padding =
            crate::json::parse(r#"{"xhttpSettings": {"xPaddingBytes": -3}}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad_padding)).is_none());
        let missing = crate::json::parse(r#"{"network": "tcp"}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&missing)).is_none());
        assert!(XhttpSettings::from_json(None).is_none());
        let bare = crate::json::parse(r#"{"network": "xhttp"}"#).expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&bare))
                .expect("defaults")
                .mode,
            XhttpMode::StreamOne
        );
        let auto_plain = crate::json::parse(r#"{"xhttpSettings": {}}"#).expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&auto_plain))
                .expect("auto")
                .mode,
            XhttpMode::PacketUp
        );
        let auto_reality =
            crate::json::parse(r#"{"security": "reality", "xhttpSettings": {"mode": "auto"}}"#)
                .expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&auto_reality))
                .expect("auto")
                .mode,
            XhttpMode::StreamOne
        );
        let auto_down = crate::json::parse(
            r#"{"security": "reality", "xhttpSettings": {"downloadSettings": {}}}"#,
        )
        .expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&auto_down))
                .expect("auto")
                .mode,
            XhttpMode::StreamUp
        );
    }

    /// The reference reads its obfuscation knobs from `extra`, which replaces the whole settings block except host, path and mode.
    #[test]
    fn the_extra_block_replaces_every_knob_but_path_and_mode() {
        let node = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
            "path": "/tunnel", "mode": "stream-one", "scMaxEachPostBytes": 4096,
            "extra": {"xPaddingBytes": "1-1", "xPaddingObfsMode": true, "xPaddingKey": "ctx",
                "xPaddingHeader": "x-grpc-context", "xPaddingMethod": "tokenish",
                "sessionIDPlacement": "header", "sessionIDKey": "Idempotency-Key",
                "seqPlacement": "header", "seqKey": "Upload-Offset"}}}}"#,
        )
        .expect("parses");
        let got = XhttpSettings::from_json(node.get("streamSettings")).expect("extra parses");
        assert_eq!(got.path, "/tunnel", "path stays on the outer block");
        assert_eq!(got.mode, XhttpMode::StreamOne, "and so does mode");
        assert!(got.x_padding_obfs);
        assert_eq!(got.x_padding_bytes, (1, 1));
        assert_eq!(got.x_padding_key, "ctx");
        assert_eq!(got.x_padding_header, "x-grpc-context");
        assert_eq!(got.x_padding_method, PadMethod::Tokenish);
        assert_eq!(
            got.x_padding_placement,
            Placement::QueryInHeader,
            "unset inside extra, so the reference default applies"
        );
        assert_eq!(got.session_placement, Placement::Header);
        assert_eq!(got.session_key, "Idempotency-Key");
        assert_eq!(got.seq_placement, Placement::Header);
        assert_eq!(got.seq_key, "Upload-Offset");
        assert_eq!(
            got.sc_max_each_post, 1_000_000,
            "a knob the outer block sets and extra omits is replaced by the default, not merged"
        );

        let linked = crate::json::parse(
            r#"{"xhttpSettings": {"path": "/tunnel",
                "extra": "{\"xPaddingObfsMode\":true,\"xPaddingKey\":\"ctx\"}"}}"#,
        )
        .expect("parses");
        let got = XhttpSettings::from_json(Some(&linked)).expect("string extra parses");
        assert!(got.x_padding_obfs);
        assert_eq!(got.x_padding_key, "ctx");

        let null = crate::json::parse(r#"{"xhttpSettings": {"path": "/p", "extra": null}}"#)
            .expect("parses");
        assert!(
            !XhttpSettings::from_json(Some(&null))
                .expect("null extra")
                .x_padding_obfs
        );
        let bad = crate::json::parse(r#"{"xhttpSettings": {"extra": 7}}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad)).is_none());
    }

    /// Where a hub's answer goes when the row is about the status, not the socket.
    #[derive(Clone)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl crate::proxy::FrameWrite for Sink {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            let mut seen = self.0.lock().expect("sink");
            for part in parts {
                seen.extend_from_slice(part);
            }
            true
        }
    }

    /// The status a hub answers a head with. `accept_core` writes a refusal and ends the connection, and writes 200 and returns the pair when it serves, so the bytes it wrote answer either way.
    fn status_through_core(head: &str, settings: &XhttpSettings) -> u16 {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let _ = accept_core(
            head.as_bytes(),
            Vec::new(),
            std::io::Cursor::new(vec![0u8; 1]),
            Sink(Arc::clone(&seen)),
            settings,
            None,
        );
        let text = String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
        text.split_ascii_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    fn settings_from(raw: &str) -> XhttpSettings {
        let node = crate::json::parse(raw).expect("parses");
        XhttpSettings::from_json(node.get("streamSettings")).expect("settings")
    }

    /// A missing or `auto` mode is the dialer's default, not a promise about what may arrive: the reference hub gates a shape only when the mode was written down (`hub.go:154`, `:199`, `:241` all read `Mode != "" && Mode != "auto" && Mode != <shape>`). Our own `xhttp::connect` writes the `stream-one` POST, so a hub resolved from `{"path": "/share"}` refusing it is a hub that answers no dial its own client can make — which is what left `vless-xhttp-down-8` with no flow at any connection count.
    #[test]
    fn an_unstated_mode_serves_the_dialers_own_head() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        assert_eq!(
            settings.mode,
            XhttpMode::PacketUp,
            "auto resolves the way the reference dialer does"
        );
        assert_eq!(settings.mode_source, ModeSource::Auto);
        let head = format!(
            "POST /share HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n",
            "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500)
        );
        assert_eq!(
            status_through_core(&head, &settings),
            200,
            "an auto hub refused the head its own dialer writes"
        );
    }

    /// The two halves of one process over a socket: `connect` writes the head its own random padding asks for, and the hub built from the same config has to answer it. Before this fix the hub answered `HTTP/1.1 400` to that head at every connection count, which is why `vless-xhttp-down-8` completed no flow.
    #[test]
    fn the_dialer_and_its_own_hub_complete_on_loopback() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let Ok(read) = stream.try_clone() else {
                return;
            };
            let (mut reader, writer) = accept_split_with_settings(read, stream, &settings)
                .expect("the hub served the dial");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads the uplink");
            assert!(writer.send(b"pong"));
            writer.finish();
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) =
            connect(stream, "127.0.0.1", "/share").expect("the dial was answered");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads the downlink");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// The relaxation is only for a mode nobody stated: a `packet-up` hub still refuses a session-less POST, so the knobs demonstrably reach the accept path.
    #[test]
    fn a_stated_mode_still_refuses_the_session_less_post() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "packet-up"}}}"#,
        );
        assert_eq!(settings.mode_source, ModeSource::Stated);
        let head = format!(
            "POST /share HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500)
        );
        assert_eq!(
            status_through_core(&head, &settings),
            400,
            "a hub told packet-up served a stream-one POST"
        );
    }

    /// An auto hub keeps serving the shape it resolved to: the packet it was already answering is still answered, so gating on a stated mode narrowed nothing.
    #[test]
    fn an_unstated_mode_still_serves_the_shape_it_resolved_to() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        let head = format!(
            "POST /share/autohub/0 HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nContent-Length: 1\r\n\r\n",
            "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500)
        );
        assert_eq!(
            status_through_core(&head, &settings),
            200,
            "the packet shape an auto hub resolved to stopped being served"
        );
    }

    /// Named, not fixed: the reference hub takes the stream-up shape under `auto` too, and we still answer 400. Accepting it would park the POST thread on `wait_ended` for a session whose upload no H1 carrier ever closes — the open row [`docs/function/carrier-xhttp.md`](../../../docs/function/carrier-xhttp.md) calls the missing carrier-side owner.
    #[test]
    fn an_unstated_mode_still_refuses_the_shape_without_a_carrier_owner() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        let head = format!(
            "POST /share/autohub HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500)
        );
        assert_eq!(
            status_through_core(&head, &settings),
            400,
            "the stream-up shape was accepted with no owner to end its park"
        );
    }

    /// Both parks — the uplink's `wait_ended` and the downlink's `Read::read` — wait on `session.cv`, and until a carrier owned the session the only thing that ever notified it was a `SessionReader`'s Drop. A client that opened one half and died left the other half's thread parked for the life of the process.
    #[test]
    fn a_carrier_death_lifts_both_parks() {
        let (down_done, down_waiting) = std::sync::mpsc::channel();
        let down = get_or_create_session("parked-downlink");
        thread::spawn(move || {
            let mut reader = SessionReader::new(down, "parked-downlink".to_owned());
            let mut buf = [0u8; 8];
            // Nothing is ever posted to this session, so this read is the park itself.
            let _ = down_done.send(reader.read(&mut buf).expect("reads"));
        });
        let (up_done, up_waiting) = std::sync::mpsc::channel();
        let up = get_or_create_session("parked-uplink");
        thread::spawn(move || {
            up.wait_ended();
            let _ = up_done.send(());
        });
        thread::sleep(crate::budgets::RELAY_IDLE);
        end_session("parked-downlink");
        end_session("parked-uplink");
        assert_eq!(
            down_waiting.recv_timeout(std::time::Duration::from_secs(5)),
            Ok(0),
            "a parked downlink never saw the end"
        );
        assert!(
            up_waiting
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok(),
            "an uplink with no downlink parked its POST thread forever"
        );
    }

    /// A refused packet is a lost one — the downlink pops a strict sequence — so the 500 has to end the session it overflowed: leaving it alive parks the reader on a sequence no peer will resend.
    #[test]
    fn a_refused_packet_ends_the_session_it_overflowed() {
        let node = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
                "path": "/up/", "mode": "packet-up"}}}"#,
        )
        .expect("parses");
        let settings = XhttpSettings::from_json(node.get("streamSettings")).expect("settings");
        let session = get_or_create_session("overflowed");
        for seq in 0..30u64 {
            assert!(
                session.push_packet(seq, vec![seq as u8], 30),
                "thirty fit before the refusal"
            );
        }
        let head = format!(
            "POST /up/overflowed/30 HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nContent-Length: 1\r\n\r\n",
            "http://127.0.0.1/up/?x_padding=".to_owned() + &"X".repeat(128)
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        assert!(
            matches!(
                accept_core(
                    head.as_bytes(),
                    Vec::new(),
                    std::io::Cursor::new(vec![30u8]),
                    Sink(Arc::clone(&seen)),
                    &settings,
                    None,
                ),
                Served::Closed
            ),
            "a refused packet must not hand the caller a session to read"
        );
        let answered = String::from_utf8(seen.lock().expect("sink").clone())
            .unwrap_or_default()
            .chars()
            .take(12)
            .collect::<String>();
        assert_eq!(answered, "HTTP/1.1 500", "the overflow answered no 500");
        assert!(
            !session_is_carried("overflowed"),
            "the overflowed session stayed alive with its parked reader"
        );
    }

    /// A packet-up uplink is one POST per `scMaxEachPostBytes`, not one per TCP connection: the reference hub answers a request and waits for the next on the same socket (`hub.go:562` sets a 4 s read-header timeout, it does not close). Answering once and dropping the connection costs a handshake per 4 KiB of uplink.
    #[test]
    fn one_connection_carries_the_packet_up_uplink() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up", "mode": "packet-up"}}}"#,
        );
        let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
        let post = |seq: u64, body: &str| {
            format!(
                "POST /up/wire/{seq} HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                body.len()
            )
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let served = accept_split_with_settings(
            std::io::Cursor::new(format!("{}{}", post(0, "ping"), post(1, "pong")).into_bytes()),
            Sink(Arc::clone(&seen)),
            &settings,
        );
        let text = String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
        assert_eq!(
            text.matches("HTTP/1.1 200 OK").count(),
            2,
            "the second post arrived on a connection the first one closed"
        );
        assert!(
            served.is_none(),
            "an uplink with nothing left to read owns no session"
        );
        let mut reader = SessionReader::new(get_or_create_session("wire"), "wire".to_owned());
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("the first packet");
        assert_eq!(&buf, b"ping", "the first post reached no session");
        reader.read_exact(&mut buf).expect("the second packet");
        assert_eq!(&buf, b"pong", "the second post reached no session");
    }

    /// The packet can ride `X-Data-{i}` headers or `x_data_{i}` cookies instead of the body: the client base64url-encodes the *whole* packet and splits that one string at random points (`config.go:66-94`), and the hub joins the parts and decodes once (`hub.go:249-285`) — so a part boundary lands mid-group and only the joined tail carries the remainder.
    #[test]
    fn a_packet_split_across_data_parts_reaches_the_session_whole() {
        let packet: Vec<u8> = (0..200usize).map(|i| (i as u8).wrapping_mul(97)).collect();
        let mut encoded = String::new();
        ferrox_core::transport::early_encode_into(&mut encoded, &packet);
        let cuts = [0usize, 41, 97, encoded.len()];
        for (placement, sid) in [("header", "data_headers"), ("cookie", "data_cookies")] {
            let settings = settings_from(&format!(
                r#"{{"streamSettings": {{"network": "xhttp", "xhttpSettings": {{
                    "path": "/up", "mode": "packet-up", "uplinkDataPlacement": "{placement}"}}}}}}"#
            ));
            let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
            let (first, second, third) = (
                &encoded[cuts[0]..cuts[1]],
                &encoded[cuts[1]..cuts[2]],
                &encoded[cuts[2]..cuts[3]],
            );
            let parts = if placement == "header" {
                format!("X-Data-0: {first}\r\nX-Data-1: {second}\r\nX-Data-2: {third}\r\n")
            } else {
                format!("Cookie: x_data_0={first};x_data_1={second};x_data_2={third}\r\n")
            };
            let head = format!(
                "POST /up/{sid}/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n{parts}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let seen = Arc::new(Mutex::new(Vec::new()));
            assert!(
                matches!(
                    accept_core(
                        head.as_bytes(),
                        Vec::new(),
                        std::io::Cursor::new(Vec::new()),
                        Sink(Arc::clone(&seen)),
                        &settings,
                        None,
                    ),
                    Served::Closed
                ),
                "{placement}: the parts left a session for the caller to carry"
            );
            // Asserted before the read: a refusal would otherwise park `read_exact` on a packet that never arrives.
            let answered =
                String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
            assert!(
                answered.starts_with("HTTP/1.1 200"),
                "{placement}: the hub refused the parts: {answered}"
            );
            let mut reader = SessionReader::new(get_or_create_session(sid), sid.to_owned());
            let mut got = vec![0u8; packet.len()];
            reader
                .read_exact(&mut got)
                .unwrap_or_else(|_| panic!("{placement}: the parts reached no reader"));
            assert_eq!(got, packet, "{placement}: the joined parts decoded wrong");
        }
    }

    /// Five digits are not a base64 length and the reference refuses them with a 400; the per-character ladder dropped the last digit and handed a short packet up as if it were whole. The same head with four digits answers 200, so the refusal is the decode's and not the request's shape.
    #[test]
    fn a_trailing_digit_in_the_data_parts_is_refused() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
                "path": "/up", "mode": "packet-up", "uplinkDataPlacement": "header"}}}"#,
        );
        let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
        let post = |sid: &str, value: &str| {
            format!(
                "POST /up/{sid}/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nX-Data-0: {value}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        };
        assert_eq!(
            status_through_core(&post("lone_digit", "abcde"), &settings),
            400,
            "a lone trailing digit answered as if it carried a packet"
        );
        assert_eq!(
            status_through_core(&post("four_digits", "Zm9v"), &settings),
            200,
            "the same head with a base64 length was refused too, so the 400 above is not the shape's"
        );
    }

    /// A `Connection: close` request ends the reuse: the hub answers it and lets the socket go, so a client that asked for one request per connection never waits on a half-open one.
    #[test]
    fn a_request_that_says_close_takes_the_connection_with_it() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up", "mode": "packet-up"}}}"#,
        );
        let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let served = accept_split_with_settings(
            std::io::Cursor::new(
                format!(
                    "POST /up/farewell/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nContent-Length: 4\r\nConnection: close\r\n\r\npingPOST /up/farewell/1 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nContent-Length: 4\r\n\r\npong"
                )
                .into_bytes(),
            ),
            Sink(Arc::clone(&seen)),
            &settings,
        );
        let text = String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
        assert_eq!(
            text.matches("HTTP/1.1 200 OK").count(),
            1,
            "a request that asked to close left the next one unanswered"
        );
        assert!(served.is_none(), "the closed request owned no session");
    }

    #[test]
    fn a_full_packet_heap_refuses_one_more() {
        let session = get_or_create_session("heap-full-test");
        for seq in 0..30u64 {
            assert!(
                session.push_packet(seq, vec![seq as u8], 30),
                "first thirty fit"
            );
        }
        assert!(
            !session.push_packet(30, vec![30], 30),
            "the thirty-first is refused"
        );
        close_session(&session);
    }
}
