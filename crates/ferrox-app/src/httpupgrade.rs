use std::io::{Read, Write};
use std::net::TcpStream;

pub(crate) const HEAD_LIMIT: usize = 64 * 1024;

/// The answer every role of this carrier writes: a status line and the two upgrade headers, and nothing else.
pub(crate) const SWITCH: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

#[derive(Debug)]
pub(crate) struct UpReader<R: Read = TcpStream> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
}

impl UpReader<TcpStream> {
    /// Arm or clear the poll quantum on the handle this reader reads through; a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R: Read> Read for UpReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // The peekable carrier never carries a prefix, so its every bulk read is one branch and a delegate.
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
pub(crate) fn quiet(stream: &TcpStream) {
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

/// The head, the octets that arrived with it, and where the head ends: this read consumes what it proves, so a payload pipelined behind the request is already in hand.
fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, usize)> {
    crate::proxy::read_http_head_kept(stream, HEAD_LIMIT, crate::budgets::head_arrival())
}

pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    let (head, at) = read_head(&mut read)?;
    check_request(&head[..at], path)?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    write.write_all(SWITCH).ok()?;
    Some((
        UpReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

fn check_request(head: &[u8], path: &str) -> Option<()> {
    // One UTF-8 pass and one line scan answers the whole request; the fanout re-validated and rescanned for each field.
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    if target.split_once('?').map_or(target, |(base, _)| base) != path {
        return None;
    }
    let mut upgrade = false;
    let mut connection = false;
    for line in lines {
        // A colon-less line (the trailing empty one after `\r\n\r\n`, or a stray octet line) is skipped, as the references do.
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key.eq_ignore_ascii_case("upgrade") {
            upgrade = value.eq_ignore_ascii_case("websocket");
        } else if key.eq_ignore_ascii_case("connection") {
            connection = value.eq_ignore_ascii_case("upgrade");
        }
    }
    if upgrade && connection {
        Some(())
    } else {
        None
    }
}

// The same accept over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn accept_split<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    path: &str,
) -> Option<(UpReader<R>, W)> {
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_request(&head, path)?;
    write.write_all(SWITCH).ok()?;
    Some((
        UpReader {
            read,
            prefix,
            at: 0,
        },
        write,
    ))
}

fn upgrade_request(host: &str, path: &str) -> String {
    // Sized for its bytes: `format!` over-allocated (capacity 132) and grew again once host plus path passed 66.
    const BEFORE_PATH: &str = "GET ";
    const BEFORE_HOST: &str = " HTTP/1.1\r\nHost: ";
    const AFTER_HOST: &str = "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    let mut request = String::with_capacity(
        BEFORE_PATH.len() + path.len() + BEFORE_HOST.len() + host.len() + AFTER_HOST.len(),
    );
    request.push_str(BEFORE_PATH);
    request.push_str(path);
    request.push_str(BEFORE_HOST);
    request.push_str(host);
    request.push_str(AFTER_HOST);
    request
}

/// `Ed` is a flag, not a length: any non-zero budget rides, whatever the payload's size, and only `ed=0` holds it back.
fn rides(budget: u32, first: &[u8]) -> bool {
    budget != 0 && !first.is_empty()
}

// One call when the payload rides ahead of the `101` — what `?ed` buys — so the socket packs request and payload into one `writev` and the session coalesces them into one record, where a write per part left two of each.
fn send_request<W: crate::proxy::FrameWrite>(
    write: &mut W,
    request: &str,
    early: bool,
    first: &[u8],
) -> Option<()> {
    if early {
        return write
            .write_slices(&[request.as_bytes(), first])
            .then_some(());
    }
    write.write_all(request.as_bytes()).ok()
}

pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    let early = rides(budget, first);
    send_request(&mut read, &upgrade_request(host, path), early, first)?;
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
    let mut lines = text.split("\r\n");
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

// The same connect over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(UpReader<R>, W)> {
    let early = rides(budget, first);
    send_request(&mut write, &upgrade_request(host, path), early, first)?;
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head)?;
    if !early && !first.is_empty() {
        write.write_all(first).ok()?;
    }
    Some((
        UpReader {
            read,
            prefix,
            at: 0,
        },
        write,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn upgrade_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, _write) = accept(stream, "/tunnel").expect("upgrades");
            let mut payload = [0u8; 8];
            reader.read_exact(&mut payload).expect("reads the payload");
            assert_eq!(&payload, b"01234567");
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
        // Each rejection the previous parse produced, the fused one still produces.
        assert!(check_request(ok, "/other").is_none(), "wrong path");
        assert!(
            check_request(
                b"POST /tunnel HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                "/tunnel"
            )
            .is_none(),
            "non-GET"
        );
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

    /// A payload that fits the budget rides with the GET, so the server has it before the reader is even built and the caller sends nothing after.
    #[test]
    fn early_data_rides_ahead_of_the_switch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, mut write) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads early data");
            assert_eq!(&buf, b"ping");
            write.write_all(b"pong").expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
        let request = upgrade_request("oracle.example", "/tunnel");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
            upgrade_request("oracle.example", "/tunnel").as_bytes()
        );
        assert_eq!(parts[1].1, b"ping");
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
            upgrade_request("oracle.example", "/tunnel").as_bytes()
        );
        assert_eq!(write.plain[1], b"ping");
    }

    #[test]
    fn an_early_data_budget_leaves_the_request_unchanged() {
        for budget in [0u32, 1, 2048, 4_294_967_295] {
            let configured =
                ferrox_core::transport::EarlyData::split(&format!("/interop-upgrade?ed={budget}"));
            assert_eq!(configured.budget, budget);
            assert_eq!(
                upgrade_request("oracle.example", &configured.path),
                "GET /interop-upgrade HTTP/1.1\r\nHost: oracle.example\r\n\
                 Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                "{budget}"
            );
        }
    }

    /// The request buffer is its bytes: `format!` reached capacity 132 and grew again once host plus path passed 66, so a long host paid two allocations where this pays one.
    #[test]
    fn the_request_is_sized_for_its_bytes() {
        for (host, path) in [
            ("oracle.example", "/tunnel"),
            (
                "a.host.long.enough.to.push.the.request.past.the.format.capacity.example",
                "/a/path/long/enough/to/push/it/past/what/format/allocated",
            ),
        ] {
            let request = upgrade_request(host, path);
            assert_eq!(
                request.capacity(),
                request.len(),
                "{host}{path}: one allocation, no growth"
            );
            assert_eq!(
                request,
                format!(
                    "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                ),
                "{host}{path}: the bytes are the shape the previous formatter wrote"
            );
        }
    }

    #[test]
    fn a_configured_budget_serves_the_bare_path() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (_reader, write) = accept(stream, "/tunnel").expect("upgrades");
            quiet(&write);
            drop(write);
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
