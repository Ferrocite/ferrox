use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, OnceLock};

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

fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT, crate::proxy::HEAD_DEADLINE)
        .map(|head| (head, Vec::new()))
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

fn split(read: TcpStream, prefix: Vec<u8>) -> Option<(XhttpReader, XhttpWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some(split_halves(read, write, prefix))
}

// The same split over halves that cannot clone: the handshake leaves pipelined bytes as the prefix.
fn split_halves<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    prefix: Vec<u8>,
) -> (Reader<R>, XhttpWriter) {
    let reader = Reader {
        read,
        prefix,
        at: 0,
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
        out.mode = if raw.is_empty() || raw == "auto" {
            XhttpMode::auto_mode(settings, xhttp)
        } else {
            XhttpMode::parse_mode(raw)?
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
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let n = (target_huffman_bytes * 10).div_ceil(8);
    let mut raw = vec![0u8; n.max(1)];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    let mut s: String = raw
        .iter()
        .map(|&b| BASE62[(b as usize) % 62] as char)
        .collect();
    for iter in 0..150 {
        let cur = huffman_len(s.as_bytes());
        if cur.abs_diff(target_huffman_bytes) <= 2 {
            return s;
        }
        if cur < target_huffman_bytes {
            s.push(if iter % 2 == 0 { 'X' } else { 'Z' });
        } else if s.len() > 1 {
            s.pop();
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

fn b64_url_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits: Vec<u8> = Vec::new();
    for &b in s.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits.push(v);
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bits.len() {
        out.push((bits[i] << 2) | (bits[i + 1] >> 4));
        out.push(((bits[i + 1] & 0x0f) << 4) | (bits[i + 2] >> 2));
        out.push(((bits[i + 2] & 0x03) << 6) | bits[i + 3]);
        i += 4;
    }
    match bits.len() - i {
        2 => out.push((bits[i] << 2) | (bits[i + 1] >> 4)),
        3 => {
            out.push((bits[i] << 2) | (bits[i + 1] >> 4));
            out.push(((bits[i + 1] & 0x0f) << 4) | (bits[i + 2] >> 2));
        }
        _ => {}
    }
    Some(out)
}

// --- Server ------------------------------------------------------------------

// The stream-one handshake the tree has always served: POST with chunked framing on one connection; mode handshakes live in `accept_with_settings`, and this stays so every existing rung keeps dialling.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(XhttpReader, XhttpWriter)> {
    let mut read = stream;
    let (head, prefix) = read_head(&mut read)?;
    check_request(&head, path)?;
    read.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n").ok()?;
    split(read, prefix)
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

// The same accept over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn accept_split_with_settings<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    mut read: R,
    write: W,
    settings: &XhttpSettings,
) -> Option<(Box<dyn Read + Send>, XhttpWriter)> {
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::proxy::HEAD_DEADLINE)?;
    accept_core(&head, prefix, read, write, settings, None)
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
) -> Option<(Box<dyn Read + Send>, XhttpWriter)> {
    let text = std::str::from_utf8(head).ok()?;
    let first = text.lines().next()?;
    let mut parts = first.split_ascii_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;

    if !path_covers(settings.path.as_str(), bare_path(target)) {
        emit_404(&mut write);
        return None;
    }

    let padded = pad_value(settings.x_padding_method, pad_target_len(settings));

    if method == "OPTIONS" {
        let mut head = String::from("HTTP/1.1 200 OK\r\n");
        if !settings.x_padding_obfs {
            let _ = write!(head, "X-Padding: {padded}\r\n");
        }
        head.push_str("Access-Control-Allow-Methods: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Origin: *\r\n");
        head.push_str("Content-Length: 0\r\nConnection: keep-alive\r\n\r\n");
        let _ = write.write_all(head.as_bytes());
        return None;
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
        return None;
    }

    let (sid, seq) = extract_meta(head, target, settings);

    match (sid, seq) {
        (None, None) => {
            if settings.mode != XhttpMode::StreamOne {
                emit_400(&mut write);
                return None;
            }
            if method == "GET" {
                sse_ok(&mut write, settings, &padded);
                let writer = writer_for(write, h2);
                let session = get_or_create_session("__none__");
                session.state.lock().expect("session lock").ended = true;
                return Some((Box::new(SessionReader::new(session, String::new())), writer));
            }
            if method == settings.uplink_method.as_str() {
                if h2.is_none()
                    && !crate::proxy::header_value(head, "transfer-encoding")
                        .is_some_and(has_chunked)
                {
                    emit_400(&mut write);
                    return None;
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
                return Some((reader, writer));
            }
            emit_405(&mut write);
            None
        }
        (Some(sid), None) => {
            if method == "GET" {
                if settings.mode == XhttpMode::StreamOne {
                    emit_400(&mut write);
                    return None;
                }
                let session = get_or_create_session(sid);
                sse_ok(&mut write, settings, &padded);
                let writer = writer_for(write, h2);
                return Some((
                    Box::new(SessionReader::new(session, sid.to_owned())),
                    writer,
                ));
            }
            if settings.mode != XhttpMode::StreamUp {
                emit_400(&mut write);
                return None;
            }
            if !crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked)
                && h2.is_none()
            {
                emit_400(&mut write);
                return None;
            }
            let session = get_or_create_session(sid);
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
            None
        }
        (Some(sid), Some(seq)) => {
            if settings.mode != XhttpMode::PacketUp {
                emit_400(&mut write);
                return None;
            }
            let Ok(seq_num) = seq.parse::<u64>() else {
                emit_500(&mut write);
                return None;
            };
            let session = get_or_create_session(sid);
            let payload = match settings.uplink_data_placement {
                Placement::Header => {
                    let key = if settings.uplink_data_key.is_empty() {
                        "X-Data".to_owned()
                    } else {
                        settings.uplink_data_key.clone()
                    };
                    let mut joined = String::new();
                    for i in 0.. {
                        match crate::proxy::header_value(head, &format!("{key}-{i}")) {
                            Some(v) => joined.push_str(v),
                            None => break,
                        }
                    }
                    b64_url_decode(&joined)
                }
                Placement::Cookie => {
                    let key = if settings.uplink_data_key.is_empty() {
                        "x_data".to_owned()
                    } else {
                        settings.uplink_data_key.clone()
                    };
                    let mut joined = String::new();
                    for i in 0.. {
                        match header_cookie(head, &format!("{key}_{i}")) {
                            Some(v) => joined.push_str(v),
                            None => break,
                        }
                    }
                    b64_url_decode(&joined)
                }
                _ => {
                    if let Some(n) = content_length(head) {
                        if n > settings.sc_max_each_post {
                            emit_413(&mut write);
                            return None;
                        }
                        let mut buf = vec![0u8; n];
                        let pre = prefix.len().min(n);
                        buf[..pre].copy_from_slice(&prefix[..pre]);
                        let mut at = pre;
                        while at < n {
                            match read.read(&mut buf[at..]) {
                                Ok(0) => break,
                                Ok(r) => at += r,
                                Err(_) => return None,
                            }
                        }
                        if at < n {
                            None
                        } else {
                            Some(buf)
                        }
                    } else if crate::proxy::header_value(head, "transfer-encoding")
                        .is_some_and(has_chunked)
                    {
                        let mut payload = Vec::new();
                        let mut tmp = [0u8; 8192];
                        if h2.is_some() {
                            let mut read = read;
                            let mut pre = &prefix[..];
                            while !pre.is_empty() {
                                payload.extend_from_slice(pre);
                                pre = &[];
                            }
                            loop {
                                match read.read(&mut tmp) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        payload.extend_from_slice(&tmp[..n]);
                                        if payload.len() > settings.sc_max_each_post {
                                            emit_413(&mut write);
                                            return None;
                                        }
                                    }
                                    Err(_) => return None,
                                }
                            }
                        } else {
                            let mut reader = Reader {
                                read,
                                prefix,
                                at: 0,
                                left: 0,
                                ended: false,
                                reads: 0,
                            };
                            loop {
                                match reader.read(&mut tmp) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        payload.extend_from_slice(&tmp[..n]);
                                        if payload.len() > settings.sc_max_each_post {
                                            emit_413(&mut write);
                                            return None;
                                        }
                                    }
                                    Err(_) => return None,
                                }
                            }
                        }
                        Some(payload)
                    } else {
                        Some(Vec::new())
                    }
                }
            };
            let Some(payload) = payload else {
                emit_400(&mut write);
                return None;
            };
            if payload.len() > settings.sc_max_each_post {
                emit_413(&mut write);
                return None;
            }
            if !session.push_packet(seq_num, payload, settings.sc_max_buffered) {
                emit_500(&mut write);
                return None;
            }
            plain_ok(&mut write, settings, &padded);
            None
        }
        (None, Some(_)) => {
            emit_405(&mut write);
            None
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
    let (head, prefix) = read_head(&mut read)?;
    check_response(&head)?;
    split(read, prefix)
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
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::proxy::HEAD_DEADLINE)?;
    check_response(&head)?;
    Some(split_halves(read, write, prefix))
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
