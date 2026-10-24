use crate::conn::Connection;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::time::Instant;

pub(crate) const HEAD_LIMIT: usize = 64 * 1024;

/// The answer this carrier writes when the request carries no key: a status line and the two upgrade headers.
pub(crate) const SWITCH: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

#[derive(Debug)]
pub(crate) struct UpReader<R: Read = Connection> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
}

impl UpReader<Connection> {
    /// Arm or clear the poll quantum on the handle this reader reads through; a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R: Read> Read for UpReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Once the riding bytes are spent every read is one branch and a delegate to the stream.
        if self.at >= self.prefix.len() {
            return self.read.read(buf);
        }
        let n = (self.prefix.len() - self.at).min(buf.len());
        buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
        self.at += n;
        if self.at >= self.prefix.len() {
            // The head and the payload that rode with it leave together, once nothing reads them.
            self.prefix = Vec::new();
            self.at = 0;
        }
        Ok(n)
    }
}

/// Hand the peer its answer whole: a socket closed with received bytes unread is answered with an RST, and that RST discards the `101` this side already wrote. The drain is bounded, so a peer that keeps talking cannot postpone the close.
pub(crate) fn quiet(stream: &Connection) {
    let mut stream = stream;
    let previous = stream.read_timeout().ok().flatten();
    if stream
        .set_read_timeout(Some(crate::budgets::SESSION_POLL))
        .is_err()
    {
        return;
    }
    let mut scratch = [0u8; 4096];
    let mut drained = 0usize;
    while drained <= HEAD_LIMIT {
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
    let _ = stream.set_read_timeout(previous);
}

/// Where an HTTP/1.1 head ends: the first empty line, whether it is closed with CRLF or a bare LF.
fn upgrade_head_end(head: &[u8]) -> Option<usize> {
    if let Some(at) = ferrox_core::foxy::head_end(head) {
        return Some(at + 4);
    }
    let mut at = 0;
    while at + 1 < head.len() {
        if head[at] == b'\n' {
            if head[at + 1] == b'\n' {
                return Some(at + 2);
            }
            if head[at + 1] == b'\r' && head.get(at + 2) == Some(&b'\n') {
                return Some(at + 3);
            }
        }
        at += 1;
    }
    None
}

/// The head either role reads: any method, any line ending, and the octets that arrived with it.
#[allow(
    clippy::uninit_vec,
    reason = "the reader fills the grown bytes, and every path that does not truncates them back"
)]
fn read_upgrade_head<R: Read>(read: &mut R, limit: usize) -> Option<(Vec<u8>, usize)> {
    const ROUND: usize = 512;
    let mut head = Vec::with_capacity(ROUND);
    let until = Instant::now() + crate::budgets::head_arrival();
    loop {
        if head.len() >= limit {
            return None;
        }
        let base = head.len();
        let want = ROUND.min(limit - base);
        head.reserve(want);
        // SAFETY: `read` initialises the bytes it reports, and `set_len` is rolled back on every path that does not.
        unsafe { head.set_len(base + want) };
        let n = match read.read(&mut head[base..]) {
            Ok(n) => n,
            Err(error) if crate::proxy::is_timeout(&error) => {
                head.truncate(base);
                if Instant::now() >= until {
                    return None;
                }
                continue;
            }
            Err(_) => {
                head.truncate(base);
                return None;
            }
        };
        head.truncate(base + n);
        if n == 0 {
            return None;
        }
        let from = base.saturating_sub(3);
        if let Some(at) = upgrade_head_end(&head[from..]).map(|hit| hit + from) {
            return Some((head, at));
        }
    }
}

/// The head, the octets that arrived with it, and where the head ends: this read consumes what it proves, so a payload pipelined behind the request is already in hand.
fn read_head(stream: &mut Connection) -> Option<(Vec<u8>, usize)> {
    let previous = stream.read_timeout().ok().flatten();
    let poll = previous.map_or(crate::budgets::RELAY_POLL, |armed| {
        armed.min(crate::budgets::RELAY_POLL)
    });
    stream.set_read_timeout(Some(poll)).ok()?;
    let got = read_upgrade_head(stream, HEAD_LIMIT);
    let _ = stream.set_read_timeout(previous);
    got
}

pub(crate) fn accept(stream: Connection, path: &str) -> Option<(UpReader, Connection)> {
    let mut read = stream;
    let (head, at) = read_head(&mut read)?;
    let key = check_request(&head[..at], path)?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    if key.is_empty() {
        write.write_all(SWITCH).ok()?;
    } else {
        write.write_all(&switch_answer(key)).ok()?;
    }
    Some((
        UpReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

/// The answer the reference derives: the key it was given, hashed with the WebSocket GUID, answers the accept header.
fn switch_answer(key: &str) -> Vec<u8> {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    use sha1::Digest as _;
    let mut hash = sha1::Sha1::new();
    hash.update(key.as_bytes());
    hash.update(GUID.as_bytes());
    let accept = ferrox_core::b64::encode(&hash.finalize());
    let mut answer = Vec::with_capacity(SWITCH.len() + accept.len() + 64);
    answer.extend_from_slice(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-Websocket-Accept: ",
    );
    answer.extend_from_slice(accept.as_bytes());
    answer.extend_from_slice(b"\r\nUpgrade: websocket\r\n\r\n");
    answer
}

/// The path the reference compares: the query is stripped and every percent escape is decoded.
fn path_matches(target: &str, path: &str) -> bool {
    let base = target.split_once('?').map_or(target, |(base, _)| base);
    let bytes = base.as_bytes();
    let mut want = path.as_bytes().iter();
    let mut at = 0;
    while at < bytes.len() {
        let byte = if bytes[at] == b'%' {
            let Some(hi) = bytes.get(at + 1).copied().and_then(hex_digit) else {
                return false;
            };
            let Some(lo) = bytes.get(at + 2).copied().and_then(hex_digit) else {
                return false;
            };
            at += 3;
            hi << 4 | lo
        } else {
            at += 1;
            bytes[at - 1]
        };
        if want.next() != Some(&byte) {
            return false;
        }
    }
    want.next().is_none()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The key the accepted request carried, or an empty slice when it carried none.
fn check_request<'a>(head: &'a [u8], path: &str) -> Option<&'a str> {
    // One UTF-8 pass and one line scan answers the whole request; the fanout re-validated and rescanned for each field.
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let _method = parts.next()?;
    let target = parts.next()?;
    if !path_matches(target, path) {
        return None;
    }
    let mut upgrade = None;
    let mut connection = None;
    let mut key = None;
    for line in lines {
        // A colon-less line (the trailing empty one after the terminator, or a stray octet line) is skipped, as the references do.
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("upgrade") && upgrade.is_none() {
            upgrade = Some(value.eq_ignore_ascii_case("websocket"));
        } else if name.eq_ignore_ascii_case("connection") && connection.is_none() {
            connection = Some(value.eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-key") && key.is_none() {
            key = Some(value);
        }
    }
    if upgrade == Some(true) && connection == Some(true) {
        Some(key.unwrap_or_default())
    } else {
        None
    }
}

// The same accept over halves that cannot peek: the kept read consumes the head, so what rode in behind it is the reader's own prefix.
pub(crate) fn accept_split<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    path: &str,
) -> Option<(UpReader<R>, W)> {
    let (head, at) = read_upgrade_head(&mut read, HEAD_LIMIT)?;
    let key = check_request(&head[..at], path)?;
    if key.is_empty() {
        write.write_all(SWITCH).ok()?;
    } else {
        write.write_all(&switch_answer(key)).ok()?;
    }
    Some((
        UpReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

thread_local! {
    /// The request's five pieces, staged once per dialling thread and refilled in place by every later dial on it.
    static REQUEST: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// `Ed` is a flag, not a length: any non-zero budget rides, whatever the payload's size, and only `ed=0` holds it back.
fn rides(budget: u32, first: &[u8]) -> bool {
    budget != 0 && !first.is_empty()
}

// One call when the payload rides ahead of the `101` — what `?ed` buys — so the socket packs request and payload into one `writev` and the session coalesces them into one record, where a write per part left two of each; and the request staged in the thread's own buffer, because `66 + host + path` is a shape a dialling thread repeats, so the allocator is entered on the first dial and never again.
fn send_request<W: crate::proxy::FrameWrite>(
    write: &mut W,
    host: &str,
    path: &str,
    early: bool,
    first: &[u8],
) -> Option<()> {
    const BEFORE_PATH: &str = "GET ";
    const BEFORE_HOST: &str = " HTTP/1.1\r\nHost: ";
    const AFTER_HOST: &str = "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    REQUEST.with(|cell| {
        let mut request = cell.borrow_mut();
        request.clear();
        request.reserve(
            BEFORE_PATH.len() + path.len() + BEFORE_HOST.len() + host.len() + AFTER_HOST.len(),
        );
        for piece in [BEFORE_PATH, path, BEFORE_HOST, host, AFTER_HOST] {
            request.extend_from_slice(piece.as_bytes());
        }
        let bytes = request.as_slice();
        if early {
            return write.write_slices(&[bytes, first]).then_some(());
        }
        write.write_all(bytes).ok()
    })
}

pub(crate) fn connect(
    stream: Connection,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(UpReader, Connection)> {
    let mut read = stream;
    let early = rides(budget, first);
    send_request(&mut read, host, path, early, first)?;
    let (head, at) = read_head(&mut read)?;
    check_response(&head[..at])?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    if !early && !first.is_empty() {
        write.write_all(first).ok()?;
    }
    Some((
        UpReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

fn check_response(head: &[u8]) -> Option<()> {
    // One UTF-8 pass and one line scan for status plus both upgrade headers; the fanout cost three of each.
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    let status = lines.next()?;
    // xray and sing-box read only the version token and the three digits; a reason phrase is free text and may be absent.
    if !status.starts_with("HTTP/1.1 101")
        || !matches!(status.as_bytes().get(12), Some(b' ' | b'\r') | None)
    {
        return None;
    }
    let mut connection = false;
    let mut upgrade = false;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key.eq_ignore_ascii_case("connection") {
            connection = value.eq_ignore_ascii_case("upgrade");
        } else if key.eq_ignore_ascii_case("upgrade") {
            upgrade = value.eq_ignore_ascii_case("websocket");
        }
    }
    if connection && upgrade {
        Some(())
    } else {
        None
    }
}

// The same connect over halves that cannot peek: the kept read takes what rode in behind the `101`.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(UpReader<R>, W)> {
    let early = rides(budget, first);
    send_request(&mut write, host, path, early, first)?;
    let (head, at) = read_upgrade_head(&mut read, HEAD_LIMIT)?;
    check_response(&head[..at])?;
    if !early && !first.is_empty() {
        write.write_all(first).ok()?;
    }
    Some((
        UpReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn upgrade_carries_an_echo_over_loopback() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, write) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            let mut write = write;
            write.write_all(b"pong").expect("writes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut write) =
            connect(stream, "oracle.example", "/tunnel", 0, &[]).expect("upgrades");
        write.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// The in-memory witness for `UpReader::read`: a real cursor, not a socket, so every returned byte is exact and no scheduler decides the sequence.
    /// The prefix is walked by cursor and the inner reader answers the rest; an empty request is `Ok(0)` on both states and never moves the cursor.
    #[test]
    fn upreader_walks_its_prefix_then_delegates_every_byte() {
        let walk = |prefix: &[u8], at: usize, inner: &[u8], want: usize| -> Vec<u8> {
            let mut reader = UpReader {
                read: std::io::Cursor::new(inner.to_vec()),
                prefix: prefix.to_vec(),
                at,
            };
            let mut out = Vec::new();
            let mut buf = vec![0u8; want];
            loop {
                let n = reader.read(&mut buf).expect("reads");
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        };
        // The fd carrier: the head rides in the same buffer as the payload that came with it, so the walk starts past the head.
        assert_eq!(walk(b"HEADabcdef", 4, b"xyz", 3), b"abcdefxyz".to_vec());
        // A prefix longer than the request window walks over several calls, then the inner answers.
        assert_eq!(walk(b"abcdef", 0, b"xyz", 3), b"abcdefxyz".to_vec());
        // The split carrier: prefix only, walked from its first byte.
        assert_eq!(walk(b"abcdef", 0, b"", 4), b"abcdef".to_vec());
        // The peekable carrier: no prefix, so every byte is the inner reader's, one branch and a delegate.
        assert_eq!(walk(b"", 0, b"payload", 4), b"payload".to_vec());
        // An empty request leaves the walk where it was and returns zero, whichever state the reader is in.
        let mut held = UpReader {
            read: std::io::Cursor::new(b"tail".to_vec()),
            prefix: b"head".to_vec(),
            at: 0,
        };
        assert_eq!(held.read(&mut []).expect("empty read"), 0);
        assert_eq!(
            (held.prefix.as_slice(), held.at),
            (&b"head"[..], 0),
            "an empty request moved the walk"
        );
    }

    /// The gate the kept head read is bought for: a payload that arrived with the head reaches the caller without the reader touching the handle it would otherwise read from, and the buffer that carried it is gone once it has been walked.
    #[test]
    fn the_pipelined_prefix_reaches_the_reader_without_a_socket_read() {
        #[derive(Default)]
        struct Counted {
            inner: std::io::Cursor<Vec<u8>>,
            reads: usize,
        }

        impl Read for Counted {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                self.inner.read(buf)
            }
        }

        let mut reader = UpReader {
            read: Counted {
                inner: std::io::Cursor::new(b"z".to_vec()),
                reads: 0,
            },
            prefix: b"HEADbody".to_vec(),
            at: 4,
        };
        let mut out = [0u8; 4];
        assert_eq!(reader.read(&mut out).expect("walks"), 4);
        assert_eq!(&out, b"body");
        assert_eq!(
            reader.read.reads, 0,
            "the walked prefix still reached the handle"
        );
        assert_eq!(
            reader.prefix.capacity(),
            0,
            "the read that finished the walk kept the buffer that carried the head"
        );
        let mut last = [0u8; 1];
        assert_eq!(reader.read(&mut last).expect("delegates"), 1);
        assert_eq!(&last, b"z");
        assert_eq!(
            reader.read.reads, 1,
            "the byte past the prefix was not read"
        );
    }

    /// A head whose final `\r\n\r\n` lands across two read rounds, with the early payload behind it: the kept read must prove the head from both rounds and hand the payload over whole.
    #[test]
    fn a_head_that_straddles_a_read_round_keeps_its_riding_payload() {
        let request = format!(
            "GET /tunnel?ed=2048 HTTP/1.1\r\nHost: oracle.example\r\nX-Filler: {}\r\n\
             Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            "f".repeat(460)
        );
        assert!(
            request.len() > 512 && request.len() < 600,
            "the filler must put the delimiter past one round, not two: {}",
            request.len()
        );
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, _write) = accept(stream, "/tunnel").expect("upgrades");
            let mut payload = [0u8; 8];
            reader.read_exact(&mut payload).expect("reads the payload");
            assert_eq!(&payload, b"01234567");
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        // Split at the round's edge so the delimiter itself straddles, then ride the payload behind it.
        stream
            .write_all(&request.as_bytes()[..510])
            .expect("writes");
        stream
            .write_all(&request.as_bytes()[510..])
            .expect("writes");
        stream.write_all(b"01234567").expect("writes");
        server.join().expect("joins");
    }

    #[test]
    fn check_request_accepts_every_method_a_decoded_path_and_a_bare_lf_head() {
        let upgrade = "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let post = format!("POST /tunnel HTTP/1.1\r\n{upgrade}");
        assert!(
            check_request(post.as_bytes(), "/tunnel").is_some(),
            "the reference reads any method"
        );
        let decoded = format!("GET /tun%6Eel HTTP/1.1\r\n{upgrade}");
        assert!(
            check_request(decoded.as_bytes(), "/tunnel").is_some(),
            "the reference compares the decoded path"
        );
        let bare_lf = "GET /tunnel HTTP/1.1\nConnection: Upgrade\nUpgrade: websocket\n\n";
        assert!(
            check_request(bare_lf.as_bytes(), "/tunnel").is_some(),
            "the reference reads a bare line feed"
        );
    }

    #[test]
    fn a_bare_lf_head_reaches_the_reader() {
        let head = b"GET /tunnel HTTP/1.1\nHost: oracle.example\nConnection: Upgrade\nUpgrade: websocket\n\n";
        assert!(
            accept_split(std::io::Cursor::new(head.to_vec()), Vec::new(), "/tunnel").is_some(),
            "the shared head read ends on \\n\\n as the reference does"
        );
    }

    #[test]
    fn a_keyed_request_is_answered_with_the_accept_the_reference_derives() {
        let head = b"GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        let (_, answer) = accept_split(std::io::Cursor::new(head.to_vec()), Vec::new(), "/tunnel")
            .expect("upgrades");
        let accept = b"Sec-Websocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
        assert!(
            answer.windows(accept.len()).any(|window| window == accept),
            "the answer carries the reference's accept header: {}",
            String::from_utf8_lossy(&answer)
        );
    }

    /// One UTF-8 pass and one line scan answers the whole request; every byte-level decision matches the previous three-helper fanout.
    #[test]
    fn check_request_accepts_and_refuses_the_vectors_it_did() {
        let ok = b"GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\n\
                  Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        assert!(check_request(ok, "/tunnel").is_some());
        // Case- and whitespace-insensitive on both the key and the value, as `trim` plus `eq_ignore_ascii_case` gave.
        let messy = b"GET /tunnel HTTP/1.1\r\nupGRADE:   WebSocket \r\n\
                      Connection:  upgrade\r\n\r\n";
        assert!(check_request(messy, "/tunnel").is_some());
        // A query is stripped from the target before the compare.
        assert!(check_request(
            b"GET /tunnel?ed=4096 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            "/tunnel"
        )
        .is_some());
        // A method other than GET is not a rejection: the reference reads any method.
        assert!(
            check_request(
                b"POST /tunnel HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                "/tunnel"
            )
            .is_some(),
            "the reference reads any method"
        );
        // Each rejection the previous parse produced, the fused one still produces.
        assert!(check_request(ok, "/other").is_none(), "wrong path");
        assert!(
            check_request(
                b"GET /tunnel HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: gzip\r\n\r\n",
                "/tunnel"
            )
            .is_none(),
            "wrong Upgrade"
        );
        assert!(
            check_request(
                b"GET /tunnel HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
                "/tunnel"
            )
            .is_none(),
            "missing Connection"
        );
        // A colon-less line trailing the required headers is skipped; the fanout saw it after returning Some, so both accept.
        assert!(
            check_request(
                b"GET /tunnel HTTP/1.1\r\nUpgrade: websocket\r\nbogus\r\nConnection: Upgrade\r\n\r\n",
                "/tunnel"
            )
            .is_some(),
            "trailing colon-less line"
        );
        assert!(
            check_request(b"\xff\xfe", "/tunnel").is_none(),
            "invalid UTF-8"
        );
    }

    /// Status and both upgrade headers fall out of one scan; the reason phrase is free text, the digits are not.
    #[test]
    fn check_response_accepts_and_refuses_the_vectors_it_did() {
        let ok = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n";
        assert!(check_response(ok).is_some());
        assert!(check_response(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade:  WEBSOCKET \r\nconnection: Upgrade\r\n\r\n"
        )
        .is_some(), "case and spacing");
        assert!(
            check_response(b"HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                .is_none(),
            "not 101"
        );
        assert!(
            check_response(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                .is_none(),
            "missing Connection"
        );
        assert!(
            check_response(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n")
                .is_none(),
            "missing Upgrade"
        );
        assert!(
            check_response(
                b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            )
            .is_some(),
            "a free-text reason phrase"
        );
        assert!(
            check_response(b"HTTP/1.1 101\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                .is_some(),
            "no reason phrase at all"
        );
        assert!(
            check_response(
                b"HTTP/1.1 1011 Whatever\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            )
            .is_none(),
            "four digits is not 101"
        );
        assert!(
            check_response(
                b"HTTP/1.1 101x Whatever\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            )
            .is_none(),
            "not a digit and not a space"
        );
        assert!(check_response(b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n").is_none(), "wrong Connection");
        assert!(
            check_response(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nbogus\r\n\r\n"
            )
            .is_none(),
            "missing Upgrade despite trailing colon-less line"
        );
        assert!(check_response(b"\xff").is_none(), "invalid UTF-8");
    }

    /// The reference's `http.ReadResponse` reads lines through the same `textproto`
    /// reader as the request head, so a bare line feed is an answer it accepts.
    #[test]
    fn check_response_accepts_a_bare_lf_answer() {
        let ok = b"HTTP/1.1 101 Switching Protocols\nConnection: Upgrade\nUpgrade: websocket\n\n";
        assert!(
            check_response(ok).is_some(),
            "the reference accepts a bare-LF answer"
        );
    }

    /// A peer that answers with bare line feeds must reach the reader, not stall
    /// until it closes; the server closes right after the answer so the old
    /// CRLF-only scan fails at once instead of waiting out the head budget.
    #[test]
    fn a_bare_lf_answer_reaches_the_dial() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = vec![0u8; expected_request("oracle.example", "/tunnel").len()];
            stream.read_exact(&mut head).expect("reads the request");
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\nConnection: Upgrade\nUpgrade: websocket\n\n",
                )
                .expect("answers with a bare line feed");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        connect(stream, "oracle.example", "/tunnel", 0, &[]).expect("reads the bare-LF answer");
        server.join().expect("joins");
    }

    /// The split arm takes the same head read: a bare-LF answer is proved from the
    /// stream itself, without a socket close to end the scan.
    #[test]
    fn a_bare_lf_answer_reaches_the_split_dial() {
        let answer =
            b"HTTP/1.1 101 Switching Protocols\nConnection: Upgrade\nUpgrade: websocket\n\n";
        connect_split(
            std::io::Cursor::new(answer.to_vec()),
            Recorder::default(),
            "oracle.example",
            "/tunnel",
            0,
            &[],
        )
        .expect("reads the bare-LF answer");
    }

    /// A head whose lines use LF but whose blank line is CRLF is still a head to
    /// the reference's line reader, which strips the `\r` from each line.
    #[test]
    fn a_mixed_lf_crlf_answer_reaches_the_split_dial() {
        let answer =
            b"HTTP/1.1 101 Switching Protocols\nConnection: Upgrade\nUpgrade: websocket\n\r\n";
        connect_split(
            std::io::Cursor::new(answer.to_vec()),
            Recorder::default(),
            "oracle.example",
            "/tunnel",
            0,
            &[],
        )
        .expect("reads the mixed-ending answer");
    }

    /// One `read` per 512-octet window, so a dribbled head costs the windows it
    /// spans and no more; the count is on the reader, not on a socket.
    #[test]
    fn a_head_costs_one_read_per_window() {
        struct Counted {
            data: Vec<u8>,
            at: usize,
            reads: usize,
        }

        impl Read for Counted {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                let n = (self.data.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
                self.at += n;
                Ok(n)
            }
        }

        let mut wire = vec![b'A'; 1025];
        wire.extend_from_slice(b"\r\n\r\n");
        let mut reader = Counted {
            data: wire,
            at: 0,
            reads: 0,
        };
        let (head, at) = read_upgrade_head(&mut reader, HEAD_LIMIT).expect("reads the head");
        assert_eq!(at, 1029, "the head ends after the terminator");
        assert_eq!(head.len(), 1029, "the head keeps every octet it read");
        assert_eq!(reader.reads, 3, "one read per 512-octet window");
    }

    /// A payload that fits the budget rides with the GET, so the server has it before the reader is even built and the caller sends nothing after.
    #[test]
    fn early_data_rides_ahead_of_the_switch() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, mut write) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads early data");
            assert_eq!(&buf, b"ping");
            write.write_all(b"pong").expect("writes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, _write) =
            connect(stream, "oracle.example", "/tunnel", 4, b"ping").expect("upgrades");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// The round trip the flag rule deletes, witnessed on a socket: this server answers only once it has read the payload, so a dial that waited for the `101` first stalls until `head_arrival()` and returns no upgrade.
    #[test]
    fn an_over_budget_payload_rides_ahead_of_a_lazy_answer() {
        let request = expected_request("oracle.example", "/tunnel");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = vec![0u8; request.len()];
            stream.read_exact(&mut head).expect("reads the request");
            assert_eq!(head, request.as_bytes());
            let mut payload = [0u8; 4];
            stream
                .read_exact(&mut payload)
                .expect("reads the payload before answering");
            assert_eq!(&payload, b"ping");
            stream.write_all(SWITCH).expect("answers");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        // `budget` is one short of the payload, so the old length rule held it back; the flag rides it.
        let (_reader, _write) =
            connect(stream, "oracle.example", "/tunnel", 3, b"ping").expect("rides ahead");
        server.join().expect("joins");
    }

    /// Counts calls and part pointers as well as bytes, so "one write" is observed rather than inferred: a `Vec` sink cannot tell one `write_slices` call from two `write_all`s.
    #[derive(Default)]
    struct Recorder {
        calls: Vec<Vec<(usize, Vec<u8>)>>,
        plain: Vec<Vec<u8>>,
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.plain.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Recorder {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            self.calls.push(
                parts
                    .iter()
                    .map(|part| (part.as_ptr() as usize, part.to_vec()))
                    .collect(),
            );
            true
        }
    }

    // Spelled here rather than borrowed from the dial: a piece the staging shape drops still fails these.
    fn expected_request(host: &str, path: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        )
    }

    /// The record arm takes the buffer its own head read filled, head octets and all: what rode behind the delimiter is handed over inside it, not copied into a second owner.
    #[test]
    fn the_record_head_hands_over_the_buffer_it_filled() {
        const HEAD: &[u8] =
            b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        const TAIL: &[u8] = b"ping";
        let mut wire = Vec::from(HEAD);
        wire.extend_from_slice(TAIL);
        let (reader, _write) =
            accept_split(std::io::Cursor::new(wire), Vec::new(), "/tunnel").expect("upgrades");
        assert_eq!(reader.at, HEAD.len(), "the cursor sits past the head");
        assert_eq!(
            reader.prefix.len(),
            HEAD.len() + TAIL.len(),
            "one buffer carries the upgrade and what rode behind it"
        );
        assert_eq!(
            reader.prefix[reader.at..].as_ptr() as usize - reader.prefix.as_ptr() as usize,
            reader.at,
            "and those bytes lie inside the allocation the head read made"
        );
    }

    /// The early payload rides as the request's second write part: one call, which the socket packs into one `writev` and the session coalesces into one record, and the part is the caller's own buffer.
    #[test]
    fn the_early_data_rides_in_one_write_with_the_request() {
        let first = *b"ping";
        let (_reader, write) = connect_split(
            std::io::Cursor::new(SWITCH.to_vec()),
            Recorder::default(),
            "oracle.example",
            "/tunnel",
            4,
            &first,
        )
        .expect("upgrades");
        assert_eq!(
            write.calls.len(),
            1,
            "request and payload left in {} calls",
            write.calls.len()
        );
        assert!(write.plain.is_empty(), "the request went out plain");
        let parts = &write.calls[0];
        assert_eq!(parts.len(), 2, "the request and the payload");
        assert_eq!(
            parts[0].1,
            expected_request("oracle.example", "/tunnel").as_bytes()
        );
        assert_eq!(parts[1].1, b"ping");
        assert_eq!(
            parts[0].0,
            REQUEST.with(|cell| cell.borrow().as_ptr() as usize),
            "the staged request was copied into the write instead of handed over"
        );
        assert_eq!(
            parts[1].0,
            first.as_ptr() as usize,
            "the payload was copied instead of handed over by pointer"
        );
    }

    /// `ed=0` is the one hold: the request leaves alone, in its own write, and the payload follows in a second one; nothing is vectored.
    #[test]
    fn ed_zero_holds_the_payload_behind_in_one_write_each() {
        let first = *b"ping";
        let (_reader, write) = connect_split(
            std::io::Cursor::new(SWITCH.to_vec()),
            Recorder::default(),
            "oracle.example",
            "/tunnel",
            0,
            &first,
        )
        .expect("upgrades");
        assert!(write.calls.is_empty(), "a held-back payload was vectored");
        assert_eq!(write.plain.len(), 2, "the request and then the payload");
        assert_eq!(
            write.plain[0],
            expected_request("oracle.example", "/tunnel").as_bytes()
        );
        assert_eq!(write.plain[1], b"ping");
    }

    #[test]
    fn an_early_data_budget_leaves_the_request_unchanged() {
        for budget in [0u32, 1, 2048, 4_294_967_295] {
            let configured =
                ferrox_core::transport::EarlyData::split(&format!("/interop-upgrade?ed={budget}"));
            assert_eq!(configured.budget, budget);
            // No payload to ride, so every budget leaves the same single write.
            let (_reader, write) = connect_split(
                std::io::Cursor::new(SWITCH.to_vec()),
                Recorder::default(),
                "oracle.example",
                &configured.path,
                budget,
                b"",
            )
            .expect("upgrades");
            assert_eq!(
                write.plain,
                [expected_request("oracle.example", "/interop-upgrade").into_bytes()],
                "{budget}"
            );
        }
    }

    /// Steady traffic on one dialling thread: the five pieces push into the thread's own buffer and the write drains it, round after round. `format!` entered the allocator on every dial and grew again past 66 bytes of host plus path; here the first dial's allocation is the last, so the buffer's identity and capacity hold for all the rest.
    #[test]
    fn the_request_buffer_holds_its_capacity_over_a_dial_cycle() {
        // The widest dial first, so the reservation it makes covers every later shape.
        let long = "a.host.long.enough.to.push.the.request.past.the.format.capacity.example";
        let deep = "/a/path/long/enough/to/push/it/past/what/format/allocated";
        let dials = [
            (long, deep),
            ("oracle.example", "/tunnel"),
            (long, "/tunnel"),
            ("oracle.example", deep),
        ];
        let mut held = None::<(usize, usize)>;
        for round in 0..dials.len() * 3 {
            let (host, path) = dials[round % dials.len()];
            let mut write = Recorder::default();
            send_request(&mut write, host, path, false, b"").expect("sends");
            assert_eq!(write.plain.len(), 1, "round {round}: one write");
            assert_eq!(
                write.plain[0],
                expected_request(host, path).as_bytes(),
                "round {round}: {host}{path}"
            );
            let current = REQUEST.with(|cell| {
                let request = cell.borrow();
                (request.capacity(), request.as_ptr() as usize)
            });
            match held {
                None => assert_eq!(
                    current.0,
                    66 + long.len() + deep.len(),
                    "the first dial reserves its own bytes"
                ),
                Some((capacity, pointer)) => {
                    assert_eq!(
                        current.0, capacity,
                        "round {round}: the allocator is entered once"
                    );
                    assert_eq!(
                        current.1, pointer,
                        "round {round}: and the buffer is the same allocation"
                    );
                }
            }
            held = Some(current);
        }
    }

    #[test]
    fn a_configured_budget_serves_the_bare_path() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let configured = ferrox_core::transport::EarlyData::split("/interop-upgrade?ed=2048");
            let (mut reader, write) = accept(stream, &configured.path).expect("upgrades");
            // Drain the early data before closing: a Windows socket closed with received bytes still unread answers RST, which discards the `101` the client has not yet read.
            let mut early = [0u8; 5];
            reader.read_exact(&mut early).expect("reads the early data");
            assert_eq!(&early, b"first", "the bare path carried the early data");
            drop(write);
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let configured = ferrox_core::transport::EarlyData::split("/interop-upgrade?ed=2048");
        let (_reader, _write) = connect(
            stream,
            "oracle.example",
            &configured.path,
            configured.budget,
            b"first",
        )
        .expect("upgrades");
        server.join().expect("joins");
    }

    /// The close after a `101` has to be a FIN: witnessed on macOS, an undrained teardown leaves the client's early data unread and the stack answers with a reset that discards the answer, so the drained half ends in EOF and the reset half in `ConnectionReset`.
    #[test]
    fn a_drained_teardown_ends_the_upgrade_with_a_fin() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (_reader, write) = accept(stream, "/tunnel").expect("upgrades");
            quiet(&write);
            drop(write);
        });
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client
            .write_all(
                b"GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\n\
                  Connection: Upgrade\r\nUpgrade: websocket\r\n\r\nfirst",
            )
            .expect("writes");
        server.join().expect("joins");
        let mut answer = Vec::new();
        client
            .read_to_end(&mut answer)
            .expect("the answer ends in a FIN, not a reset");
        assert!(answer.starts_with(b"HTTP/1.1 101 Switching Protocols"));
    }

    #[test]
    fn upgrade_rejects_a_wrong_path_and_headers() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }

    /// The differential sweep against the pinned reference.
    ///
    /// `scripts/httpupgrade-oracle` writes the script and the golden from the pinned
    /// xray-core, and this replays the tree's own paths against what the reference
    /// did: every head length the script names, every offset a head can be split at,
    /// the verdicts on both roles, the bytes of the answer, the fate of the octets
    /// that came with the head, the order the early data rides in, and the request.
    /// The script names the fields on which the two sides are known to differ, so a
    /// difference the script does not name fails here.
    mod sweep {
        use super::*;
        use std::collections::BTreeMap;
        use std::io::Read;

        const SCRIPT: &str = include_str!("../../../scripts/httpupgrade-oracle/script.txt");
        const GOLDEN: &str = include_str!("../../../scripts/httpupgrade-oracle/expected.txt");
        const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        /// The tree's read round, the seam its scan looks three octets back from.
        const ROUND: usize = 512;

        /// A field on which the two sides are known to differ, as the script names it.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Divergence {
            /// The two sides' verdicts differ.
            Verdict,
            /// The answer carries the accept header, which the tree does not write.
            AcceptHeader,
            /// The octets that came with the head reached the tree and not the
            /// reference's handler.
            Tail,
            /// The request carries the key and the version, which the tree does not
            /// send.
            Request,
            /// The payload's order differs.
            Order,
        }

        /// The divergences a case's `expect` field names. `v+` and `v-` are the same
        /// divergence seen from either side; `same` names none.
        fn divergences(text: &str) -> Vec<Divergence> {
            let mut out = Vec::new();
            let mut at = 0;
            while at < text.len() {
                let rest = &text[at..];
                if rest.starts_with("v+") || rest.starts_with("v-") {
                    out.push(Divergence::Verdict);
                    at += 2;
                    continue;
                }
                if rest.starts_with("same") {
                    at += 4;
                    continue;
                }
                let flag = match rest.as_bytes()[0] {
                    b'a' => Divergence::AcceptHeader,
                    b't' => Divergence::Tail,
                    b'r' => Divergence::Request,
                    b'o' => Divergence::Order,
                    other => panic!("unknown divergence {}", other as char),
                };
                out.push(flag);
                at += 1;
                if at < text.len() {
                    assert_eq!(text.as_bytes()[at], b'+', "the flags are joined by a plus");
                    at += 1;
                }
            }
            out
        }

        /// One case of the script, in the fields its family gives it.
        struct Case {
            label: String,
            path: String,
            host: String,
            key: String,
            budget: u32,
            size: usize,
            pad: usize,
            tail: String,
            end: String,
            expect: Vec<Divergence>,
            text: String,
        }

        impl Case {
            /// `frame <label> <pad> <tail> <expect> <end> <head>`
            fn frame(rest: &str) -> Self {
                let mut parts = rest.splitn(6, ' ');
                Case {
                    label: parts.next().expect("a label").to_owned(),
                    pad: parts.next().expect("a pad").parse().expect("a pad"),
                    tail: parts.next().expect("a tail").to_owned(),
                    expect: divergences(parts.next().expect("an expect")),
                    end: parts.next().expect("an end").to_owned(),
                    text: parts.next().expect("a head").to_owned(),
                    path: String::new(),
                    host: String::new(),
                    key: String::new(),
                    budget: 0,
                    size: 0,
                }
            }

            /// `serve <label> <path> <host> <tail> <expect> <head>`
            fn serve(rest: &str) -> Self {
                let mut parts = rest.splitn(6, ' ');
                Case {
                    label: parts.next().expect("a label").to_owned(),
                    path: parts.next().expect("a path").to_owned(),
                    host: parts.next().expect("a host").to_owned(),
                    tail: parts.next().expect("a tail").to_owned(),
                    expect: divergences(parts.next().expect("an expect")),
                    text: parts.next().expect("a head").to_owned(),
                    pad: 0,
                    end: String::new(),
                    key: String::new(),
                    budget: 0,
                    size: 0,
                }
            }

            /// `client <label> <ed> <path> <host> <key> <payload> <expect> <answer>`
            fn client(rest: &str) -> Self {
                let mut parts = rest.splitn(8, ' ');
                Case {
                    label: parts.next().expect("a label").to_owned(),
                    budget: parts.next().expect("a budget").parse().expect("a budget"),
                    path: parts.next().expect("a path").to_owned(),
                    host: parts.next().expect("a host").to_owned(),
                    key: parts.next().expect("a key").to_owned(),
                    size: parts.next().expect("a size").parse().expect("a size"),
                    expect: divergences(parts.next().expect("an expect")),
                    text: parts.next().expect("an answer").to_owned(),
                    pad: 0,
                    tail: String::new(),
                    end: String::new(),
                }
            }
        }

        /// The script's escapes, the set the oracle writes.
        fn unescape(text: &str) -> Vec<u8> {
            let bytes = text.as_bytes();
            let mut out = Vec::with_capacity(bytes.len());
            let mut at = 0;
            while at < bytes.len() {
                if bytes[at] != b'\\' {
                    out.push(bytes[at]);
                    at += 1;
                    continue;
                }
                at += 1;
                assert!(at < bytes.len(), "a trailing backslash");
                match bytes[at] {
                    b'r' => out.push(b'\r'),
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b's' => out.push(b' '),
                    b'\\' => out.push(b'\\'),
                    b'x' => {
                        let digits = bytes
                            .get(at + 1..at + 3)
                            .expect("two hex digits")
                            .to_owned();
                        out.push(
                            u8::from_str_radix(std::str::from_utf8(&digits).expect("ascii"), 16)
                                .expect("two hex digits"),
                        );
                        at += 2;
                    }
                    other => panic!("unknown escape \\{}", other as char),
                }
                at += 1;
            }
            out
        }

        fn hex(bytes: &[u8]) -> String {
            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                out.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex"));
                out.push(char::from_digit(u32::from(byte & 0xf), 16).expect("hex"));
            }
            out
        }

        fn unhex(text: &str) -> Vec<u8> {
            assert!(text.len().is_multiple_of(2), "hex is whole octets");
            (0..text.len() / 2)
                .map(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).expect("hex"))
                .collect()
        }

        /// The golden's lines, keyed by family and label.
        fn golden() -> BTreeMap<String, Vec<String>> {
            let mut map = BTreeMap::new();
            for line in GOLDEN.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let mut parts = line.split(' ');
                let family = parts.next().expect("a family");
                let label = parts.next().expect("a label");
                map.insert(
                    format!("{family} {label}"),
                    parts.map(str::to_owned).collect::<Vec<String>>(),
                );
            }
            map
        }

        /// A reader that hands the head over in two pieces, so the tree's head end can
        /// be shown not to move with the split.
        struct TwoPieces<'a> {
            data: &'a [u8],
            at: usize,
            split: usize,
        }

        impl Read for TwoPieces<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let want = if self.at < self.split {
                    (self.split - self.at).min(buf.len())
                } else {
                    buf.len().min(self.data.len() - self.at)
                };
                buf[..want].copy_from_slice(&self.data[self.at..self.at + want]);
                self.at += want;
                Ok(want)
            }
        }

        /// Where the tree's own head read ends, in octets.
        fn tree_head_end(head: &[u8], split: usize) -> Option<usize> {
            let mut reader = TwoPieces {
                data: head,
                at: 0,
                split,
            };
            read_upgrade_head(&mut reader, HEAD_LIMIT).map(|(_, at)| at)
        }

        /// Every offset a short head can be split at, and the offsets that matter for a
        /// long one: either side of every round the tree reads in, and the last octets.
        fn split_offsets(len: usize) -> Vec<usize> {
            if len <= 4096 {
                return (0..=len).collect();
            }
            let mut out = Vec::new();
            let mut at = ROUND;
            while at < len {
                for near in [at - 1, at, at + 1] {
                    if near <= len {
                        out.push(near);
                    }
                }
                at += ROUND;
            }
            out.extend(len.saturating_sub(8)..=len);
            out.sort_unstable();
            out.dedup();
            out
        }

        /// The head the oracle built: the text, the pad, the terminator, the tail.
        fn frame_head(case: &Case) -> Vec<u8> {
            let mut head = unescape(&case.text);
            head.extend(std::iter::repeat_n(b'A', case.pad));
            if case.end == "crlf" {
                head.extend_from_slice(b"\r\n\r\n");
            }
            let tail: usize = case.tail.parse().expect("a tail");
            head.extend(std::iter::repeat_n(b'B', tail));
            head
        }

        /// The value of a header in a head, as the references read it.
        fn header_value(head: &[u8], name: &str) -> Option<String> {
            let text = std::str::from_utf8(head).ok()?;
            for line in text.split("\r\n").skip(1) {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                if key.trim().eq_ignore_ascii_case(name) {
                    return Some(value.trim().to_owned());
                }
            }
            None
        }

        /// The accept header the reference derives from the key, as it derives it.
        fn accept_key(key: &str) -> String {
            use sha1::Digest as _;
            let mut hash = sha1::Sha1::new();
            hash.update(key.trim().as_bytes());
            hash.update(GUID.as_bytes());
            ferrox_core::b64::encode(&hash.finalize())
        }

        /// A writer that keeps what it was given after the call that took it: a dial
        /// that refuses the answer still wrote the request, and the sweep has to see it.
        #[derive(Clone, Default)]
        struct Shared(std::sync::Arc<std::sync::Mutex<Recorder>>);

        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("the recorder is not poisoned")
                    .plain
                    .push(buf.to_vec());
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::proxy::FrameWrite for Shared {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                self.0
                    .lock()
                    .expect("the recorder is not poisoned")
                    .calls
                    .push(
                        parts
                            .iter()
                            .map(|part| (part.as_ptr() as usize, part.to_vec()))
                            .collect(),
                    );
                true
            }
        }

        /// The request's protocol headers, in the order they were written. The browser
        /// masquerade the reference adds carries a Chrome version that moves with the
        /// date, so a golden that held it would differ every day.
        fn project(request: &[u8]) -> Vec<&str> {
            let text = std::str::from_utf8(request).expect("ascii");
            let mut kept = Vec::new();
            for (index, line) in text.split("\r\n").enumerate() {
                if index == 0 {
                    kept.push(line);
                    continue;
                }
                let Some((name, _)) = line.split_once(':') else {
                    continue;
                };
                match name.trim().to_ascii_lowercase().as_str() {
                    "host"
                    | "connection"
                    | "upgrade"
                    | "sec-websocket-key"
                    | "sec-websocket-version" => kept.push(line),
                    _ => {}
                }
            }
            kept
        }

        /// What one served case measured, in counts.
        struct Served {
            verdict_differs: usize,
            answer_differs: usize,
            dropped: usize,
        }

        /// One served case: the verdict against the reference's, the answer's bytes,
        /// and the fate of the octets that came with the head.
        fn serve_case(case: &Case, fields: &[String]) -> Served {
            let label = &case.label;
            let head = unescape(&case.text);
            let tail = if case.tail == "-" {
                Vec::new()
            } else {
                unescape(&case.tail)
            };
            let mut wire = head.clone();
            wire.extend_from_slice(&tail);
            let outcome = accept_split(std::io::Cursor::new(wire), Vec::new(), &case.path);
            let answer = outcome
                .as_ref()
                .map(|(_, write)| write.clone())
                .unwrap_or_default();
            let reference_took = fields[0] == "accept";
            let mut measured = Served {
                verdict_differs: 0,
                answer_differs: 0,
                dropped: 0,
            };
            if reference_took != outcome.is_some() {
                assert!(
                    case.expect.contains(&Divergence::Verdict),
                    "SERVE {label}: the verdicts differ and the script does not say so"
                );
                measured.verdict_differs = 1;
            }
            let reference = if fields[1] == "-" {
                Vec::new()
            } else {
                unhex(&fields[1])
            };
            if case.expect.contains(&Divergence::AcceptHeader) {
                // The reference derives the accept header from the key it was given.
                let key = header_value(&head, "Sec-WebSocket-Key").expect("the head carries a key");
                let accept = format!("Sec-Websocket-Accept: {}\r\n", accept_key(&key));
                let want = String::from_utf8(SWITCH.to_vec()).expect("ascii").replacen(
                    "Connection: Upgrade\r\n",
                    &format!("Connection: Upgrade\r\n{accept}"),
                    1,
                );
                assert_eq!(
                    reference,
                    want.as_bytes(),
                    "SERVE {label}: the accept header"
                );
            } else if reference_took {
                assert_eq!(reference, SWITCH, "SERVE {label}: the answer differs");
            } else {
                assert!(
                    reference.is_empty(),
                    "SERVE {label}: the reference answered a head it refused"
                );
            }
            if answer != reference {
                measured.answer_differs = 1;
            }
            let tree_tail = match &outcome {
                Some((reader, _)) if !tail.is_empty() => {
                    assert_eq!(
                        &reader.prefix[reader.at..],
                        tail.as_slice(),
                        "SERVE {label}: the tail changed"
                    );
                    "kept"
                }
                _ => "-",
            };
            if case.expect.contains(&Divergence::Tail) {
                assert_eq!(fields[2], "dropped", "SERVE {label}: the reference kept it");
                assert_eq!(tree_tail, "kept", "SERVE {label}: the tree dropped it");
                measured.dropped = 1;
            } else {
                assert_eq!(
                    fields[2], tree_tail,
                    "SERVE {label}: the tail's fate differs"
                );
            }
            measured
        }

        /// What one dialled case measured, in counts.
        struct Dialled {
            verdict_differs: usize,
            order_differs: usize,
            payload_differs: usize,
            request_lines: usize,
        }

        /// One dialled case: the verdict on the answer, the order the early data
        /// rides in, the bytes of that payload, and the request the reference wrote.
        fn client_case(case: &Case, fields: &[String]) -> Dialled {
            let label = &case.label;
            let answer = unescape(&case.text);
            let payload: Vec<u8> = (0..case.size).map(|at| 0xa0 + at as u8).collect();
            let recorder = Shared::default();
            let outcome = connect_split(
                std::io::Cursor::new(answer),
                recorder.clone(),
                &case.host,
                &case.path,
                case.budget,
                &payload,
            );
            let write = recorder.0.lock().expect("the recorder is not poisoned");
            let reference_took = fields[0] == "accept";
            let mut measured = Dialled {
                verdict_differs: 0,
                order_differs: 0,
                payload_differs: 0,
                request_lines: 0,
            };
            if reference_took != outcome.is_some() {
                assert!(
                    case.expect.contains(&Divergence::Verdict),
                    "CLIENT {label}: the verdicts differ and the script does not say so"
                );
                measured.verdict_differs = 1;
            }
            // The order: a payload that rides went out with the request, one held back after the answer.
            let tree_order = if write.calls.is_empty() { "A" } else { "P" };
            if fields[1] != tree_order {
                assert!(
                    case.expect.contains(&Divergence::Order),
                    "CLIENT {label}: the order differs and the script does not say so"
                );
                measured.order_differs = 1;
            }
            let tree_payload = if write.calls.is_empty() {
                write.plain.get(1).cloned().unwrap_or_default()
            } else {
                write.calls[0]
                    .get(1)
                    .map(|(_, part)| part.clone())
                    .unwrap_or_default()
            };
            if hex(&tree_payload) != fields[2] {
                measured.payload_differs = 1;
            }
            let request = if write.calls.is_empty() {
                write.plain.first().cloned().unwrap_or_default()
            } else {
                write.calls[0][0].1.clone()
            };
            let reference = unhex(&fields[3]);
            if case.expect.contains(&Divergence::Request) {
                let mut rest = Vec::new();
                let mut keys = Vec::new();
                let mut versions = Vec::new();
                for line in project(&reference) {
                    let name = line
                        .split(':')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_lowercase();
                    match name.as_str() {
                        "sec-websocket-key" => keys.push(line),
                        "sec-websocket-version" => versions.push(line),
                        _ => rest.push(line),
                    }
                }
                assert_eq!(
                    rest,
                    project(&request),
                    "CLIENT {label}: the request differs"
                );
                assert_eq!(keys.len(), 2, "CLIENT {label}: the keys the reference sent");
                assert!(
                    keys.iter().any(|line| line.ends_with(&case.key)),
                    "CLIENT {label}: the caller's key"
                );
                assert_eq!(versions.len(), 1, "CLIENT {label}: the version");
                assert!(versions[0].ends_with(" 13"), "CLIENT {label}: the version");
                measured.request_lines = keys.len() + versions.len();
                assert_eq!(
                    measured.request_lines, 3,
                    "CLIENT {label}: the request lines the reference adds"
                );
            } else {
                assert_eq!(
                    project(&reference),
                    project(&request),
                    "CLIENT {label}: the request differs"
                );
            }
            measured
        }

        /// The head sweep: every length the script names, and every offset a head can
        /// be split at, must end where the reference's own parser ended.
        #[test]
        fn the_head_sweep_agrees_with_the_reference_on_every_length_and_split() {
            let golden = golden();
            let mut lengths = 0usize;
            let mut cases = 0usize;
            let mut verdicts_differing = 0usize;
            let mut offsets_differing = 0usize;
            for line in SCRIPT.lines() {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("frame ") else {
                    continue;
                };
                let case = Case::frame(rest);
                let head = frame_head(&case);
                cases += 1;
                if case.label.starts_with("len-") {
                    lengths += 1;
                }
                let fields = golden
                    .get(&format!("FRAME {}", case.label))
                    .unwrap_or_else(|| panic!("the golden has no line for FRAME {}", case.label));
                let tree = tree_head_end(&head, head.len());
                let reference_took = fields[0] == "accept";
                if reference_took != tree.is_some() {
                    // The script names the heads the two sides read differently.
                    assert!(
                        case.expect.contains(&Divergence::Verdict),
                        "FRAME {}: the verdicts differ and the script does not say so",
                        case.label
                    );
                    if let Some(at) = tree {
                        assert_eq!(
                            at,
                            head.len() - case.tail.parse::<usize>().expect("a tail"),
                            "FRAME {}: the tree's head end",
                            case.label
                        );
                    }
                    verdicts_differing += 1;
                } else if reference_took {
                    let want: usize = fields[1].parse().expect("an offset");
                    if tree != Some(want) {
                        offsets_differing += 1;
                    }
                }
                for split in split_offsets(head.len()) {
                    assert_eq!(
                        tree_head_end(&head, split),
                        tree,
                        "FRAME {}: the head end moved at the split {split}",
                        case.label
                    );
                }
            }
            assert_eq!(lengths, 93, "the head lengths the script names");
            assert_eq!(cases, 108, "the head cases the script names");
            assert_eq!(
                verdicts_differing, 21,
                "the heads the two sides read differently"
            );
            assert_eq!(offsets_differing, 0, "the head ends that differ");
        }

        /// The served sweep: the verdict, the bytes of the answer, and the fate of the
        /// octets that came with the head.
        #[test]
        fn the_served_sweep_agrees_with_the_reference_on_every_head() {
            let golden = golden();
            let mut cases = 0usize;
            let mut verdicts_differing = 0usize;
            let mut answers_differing = 0usize;
            let mut dropped = 0usize;
            for line in SCRIPT.lines() {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("serve ") else {
                    continue;
                };
                let case = Case::serve(rest);
                let fields = golden
                    .get(&format!("SERVE {}", case.label))
                    .unwrap_or_else(|| panic!("the golden has no line for SERVE {}", case.label));
                cases += 1;
                let measured = serve_case(&case, fields);
                verdicts_differing += measured.verdict_differs;
                answers_differing += measured.answer_differs;
                dropped += measured.dropped;
            }
            assert_eq!(cases, 13, "the served cases the script names");
            assert_eq!(
                verdicts_differing, 1,
                "the verdicts the two sides give differently"
            );
            assert_eq!(answers_differing, 1, "the answers that differ");
            assert_eq!(dropped, 2, "the tails the reference dropped");
        }

        /// The dialled sweep: the verdict on the answer, the order the early data rides
        /// in, the bytes of that payload, and the request the reference wrote.
        #[test]
        fn the_dialled_sweep_agrees_with_the_reference_on_every_answer() {
            let golden = golden();
            let mut cases = 0usize;
            let mut verdicts_differing = 0usize;
            let mut orders_differing = 0usize;
            let mut payloads_differing = 0usize;
            let mut request_lines = 0usize;
            for line in SCRIPT.lines() {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("client ") else {
                    continue;
                };
                let case = Case::client(rest);
                let fields = golden
                    .get(&format!("CLIENT {}", case.label))
                    .unwrap_or_else(|| panic!("the golden has no line for CLIENT {}", case.label));
                cases += 1;
                let measured = client_case(&case, fields);
                verdicts_differing += measured.verdict_differs;
                orders_differing += measured.order_differs;
                payloads_differing += measured.payload_differs;
                request_lines = measured.request_lines;
            }
            assert_eq!(cases, 9, "the dialled cases the script names");
            assert_eq!(
                verdicts_differing, 2,
                "the verdicts the two sides give differently"
            );
            assert_eq!(orders_differing, 0, "the orders that differ");
            assert_eq!(payloads_differing, 0, "the payloads that differ");
            assert_eq!(request_lines, 3, "the request lines the reference adds");
        }
    }
}
