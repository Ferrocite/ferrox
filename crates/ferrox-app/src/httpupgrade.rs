use std::io::{Read, Write};
use std::net::TcpStream;

const HEAD_LIMIT: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct UpReader<R: Read = TcpStream> {
    read: R,
    prefix: Vec<u8>,
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
        if self.prefix.is_empty() {
            return self.read.read(buf);
        }
        let n = self.prefix.len().min(buf.len());
        buf[..n].copy_from_slice(&self.prefix[..n]);
        self.prefix.drain(..n);
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

fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT, crate::budgets::head_arrival())
        .map(|head| (head, Vec::new()))
}

pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    let (head, prefix) = read_head(&mut read)?;
    check_request(&head, path)?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    write
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .ok()?;
    Some((UpReader { read, prefix }, write))
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
    write
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .ok()?;
    Some((UpReader { read, prefix }, write))
}

fn upgrade_request(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    )
}

pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    let early = !first.is_empty() && first.len() as u64 <= u64::from(budget);
    read.write_all(upgrade_request(host, path).as_bytes())
        .ok()?;
    if early {
        // The payload rides ahead of the `101`: this is what `?ed` buys — one round trip saved.
        read.write_all(first).ok()?;
    }
    let (head, prefix) = read_head(&mut read)?;
    check_response(&head)?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    if !early && !first.is_empty() {
        write.write_all(first).ok()?;
    }
    Some((UpReader { read, prefix }, write))
}

fn check_response(head: &[u8]) -> Option<()> {
    // One UTF-8 pass and one line scan for status plus both upgrade headers; the fanout cost three of each.
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    if lines.next()? != "HTTP/1.1 101 Switching Protocols" {
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
pub(crate) fn connect_split<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(UpReader<R>, W)> {
    let early = !first.is_empty() && first.len() as u64 <= u64::from(budget);
    write
        .write_all(upgrade_request(host, path).as_bytes())
        .ok()?;
    if early {
        write.write_all(first).ok()?;
    }
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head)?;
    if !early && !first.is_empty() {
        write.write_all(first).ok()?;
    }
    Some((UpReader { read, prefix }, write))
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
    /// The prefix drains first and the inner reader answers the rest; an empty request is `Ok(0)` on both states and never touches the prefix.
    #[test]
    fn upreader_drains_its_prefix_then_delegates_every_byte() {
        let drain = |prefix: &[u8], inner: &[u8], want: usize| -> Vec<u8> {
            let mut reader = UpReader {
                read: std::io::Cursor::new(inner.to_vec()),
                prefix: prefix.to_vec(),
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
        // Prefix longer than the request window: it drains over several calls, then the inner answers, and the whole is prefix ++ inner.
        assert_eq!(drain(b"abcdef", b"xyz", 3), b"abcdefxyz".to_vec());
        // The peekable carrier: no prefix, so every byte is the inner reader's, one branch and a delegate.
        assert_eq!(drain(b"", b"payload", 4), b"payload".to_vec());
        // An empty request leaves the prefix whole and returns zero, whichever state the reader is in.
        let mut held = UpReader {
            read: std::io::Cursor::new(b"tail".to_vec()),
            prefix: b"head".to_vec(),
        };
        assert_eq!(held.read(&mut []).expect("empty read"), 0);
        assert_eq!(
            held.prefix, b"head",
            "an empty request consumed prefix bytes"
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

    /// Status and both upgrade headers fall out of one scan; the same vectors decide the same way.
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

    /// A payload over the budget is held back and sent only after the `101`, yet still reaches the server whole.
    #[test]
    fn a_payload_over_the_budget_follows_the_switch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, mut write) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads after the switch");
            assert_eq!(&buf, b"ping");
            write.write_all(b"pong").expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        // `budget` is one short of the payload, so it cannot ride: the reader still sees it whole.
        let (mut reader, _write) =
            connect(stream, "oracle.example", "/tunnel", 3, b"ping").expect("upgrades");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
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
