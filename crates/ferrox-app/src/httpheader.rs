use crate::conn::Connection;
use std::io::{Read, Write};

const HEAD_LIMIT: usize = 8192;

#[derive(Debug)]
pub(crate) struct HeadReader<R: Read = Connection> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
}

impl HeadReader<Connection> {
    /// Arm or clear the poll quantum on the handle this reader reads through; a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R: Read> Read for HeadReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            if self.at >= self.prefix.len() {
                self.prefix.clear();
                self.at = 0;
            }
            return Ok(n);
        }
        self.read.read(buf)
    }
}

/// The head, the octets that arrived with it, and where the head ends: this read consumes what it proves, so bytes pipelined behind the head are already in hand.
fn read_head(stream: &mut Connection) -> Option<(Vec<u8>, usize)> {
    crate::proxy::read_http_head_kept(stream, HEAD_LIMIT, crate::budgets::head_arrival())
}

pub(crate) fn accept(stream: Connection, path: &str) -> Option<(HeadReader, Connection)> {
    let mut read = stream;
    let (head, at) = read_head(&mut read)?;
    check_request(&head[..at], path)?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    write
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
        .ok()?;
    Some((
        HeadReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

fn check_request(head: &[u8], path: &str) -> Option<()> {
    if crate::proxy::request_path(head)? != path {
        return None;
    }
    Some(())
}

// The same accept over halves that cannot peek: the kept read consumes the head, so what rode in behind it is the reader's own prefix.
pub(crate) fn accept_split<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    path: &str,
) -> Option<(HeadReader<R>, W)> {
    let (head, at) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_request(&head[..at], path)?;
    write
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
        .ok()?;
    Some((
        HeadReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

const BEFORE_PATH: &[u8] = b"GET ";
const BEFORE_HOST: &[u8] = b" HTTP/1.1\r\nHost: ";
const AFTER_HOST: &[u8] = b"\r\nConnection: keep-alive\r\n\r\n";

// The request is written as the runs it is made of: the socket packs them into one `writev` and the session coalesces them into one record, so no byte is staged in a buffer of its own first.
fn send_request<W: crate::proxy::FrameWrite>(write: &mut W, host: &str, path: &str) -> Option<()> {
    write
        .write_slices(&[
            BEFORE_PATH,
            path.as_bytes(),
            BEFORE_HOST,
            host.as_bytes(),
            AFTER_HOST,
        ])
        .then_some(())
}

pub(crate) fn connect(
    stream: Connection,
    host: &str,
    path: &str,
) -> Option<(HeadReader, Connection)> {
    let mut read = stream;
    send_request(&mut read, host, path)?;
    let (head, at) = read_head(&mut read)?;
    check_response(&head[..at])?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some((
        HeadReader {
            read,
            prefix: head,
            at,
        },
        write,
    ))
}

fn check_response(head: &[u8]) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    let mut parts = text.split("\r\n").next()?.split_ascii_whitespace();
    if parts.next()? != "HTTP/1.1" || parts.next()? != "200" {
        return None;
    }
    Some(())
}

// The same connect over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
) -> Option<(HeadReader<R>, W)> {
    send_request(&mut write, host, path)?;
    let (head, at) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head[..at])?;
    Some((
        HeadReader {
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

    #[test]
    fn header_carries_an_echo_over_loopback() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, mut write) = accept(stream, "/camouflage").expect("headers");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            write.write_all(b"pong").expect("writes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut write) =
            connect(stream, "oracle.example", "/camouflage").expect("headers");
        write.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// The record arm takes the buffer its own head read filled, head octets and all: what rode behind the delimiter is handed over inside it, not copied into a second owner.
    #[test]
    fn the_record_head_hands_over_the_buffer_it_filled() {
        const HEAD: &[u8] = b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n";
        const TAIL: &[u8] = b"ping";
        let mut wire = Vec::from(HEAD);
        wire.extend_from_slice(TAIL);
        let (reader, _write) =
            accept_split(std::io::Cursor::new(wire), Vec::new(), "/camouflage").expect("answers");
        assert_eq!(reader.at, HEAD.len(), "the cursor sits past the head");
        assert_eq!(
            reader.prefix.len(),
            HEAD.len() + TAIL.len(),
            "one buffer carries the request and what rode behind it"
        );
        assert_eq!(
            reader.prefix[reader.at..].as_ptr() as usize - reader.prefix.as_ptr() as usize,
            reader.at,
            "and those bytes lie inside the allocation the head read made"
        );
    }

    /// The kept head hands its own buffer to the reader with the head already walked past: the bytes behind it are delivered from that buffer, and a reader that asks the socket at all panics.
    #[test]
    fn the_bytes_behind_the_head_reach_the_relay_without_a_syscall() {
        const HEAD: &[u8] = b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n";
        struct Refused;
        impl Read for Refused {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("the head's tail is already in hand")
            }
        }
        let mut prefix = Vec::from(HEAD);
        prefix.extend_from_slice(b"ping");
        let base = prefix.as_ptr();
        let capacity = prefix.capacity();
        let mut reader = HeadReader {
            read: Refused,
            prefix,
            at: HEAD.len(),
        };
        let mut got = [0u8; 4];
        assert_eq!(reader.read(&mut got).expect("delivers"), 4);
        assert_eq!(&got, b"ping", "the bytes behind the head, not a re-read");
        assert_eq!(
            reader.prefix.as_ptr(),
            base,
            "delivered from the buffer those bytes arrived in"
        );
        assert_eq!(reader.prefix.capacity(), capacity, "on a held capacity");
    }

    /// The camouflage request reaches the write as the runs it is made of: the path and host octets go over where they lie, so the handshake stages no copy of itself.
    #[test]
    fn the_request_reaches_the_write_as_the_runs_it_is_made_of() {
        #[derive(Default)]
        struct Runs {
            calls: usize,
            segments: Vec<(usize, usize)>,
            bytes: Vec<u8>,
        }

        impl Write for Runs {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.segments.push((buf.as_ptr() as usize, buf.len()));
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::proxy::FrameWrite for Runs {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                self.calls += 1;
                for part in parts {
                    self.segments.push((part.as_ptr() as usize, part.len()));
                    self.bytes.extend_from_slice(part);
                }
                true
            }
        }

        const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
        // One binding each, so the pointer the callee was handed is the pointer the gate asserts.
        let host = "oracle.example";
        let path = "/camouflage";
        let (_reader, write) = connect_split(
            std::io::Cursor::new(Vec::from(ANSWER)),
            Runs::default(),
            host,
            path,
        )
        .expect("answers");
        assert_eq!(
            write.bytes,
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n")
                .as_bytes(),
            "the bytes the removed formatter wrote"
        );
        let lengths: Vec<usize> = write.segments.iter().map(|(_, len)| *len).collect();
        assert_eq!(
            lengths,
            [
                BEFORE_PATH.len(),
                path.len(),
                BEFORE_HOST.len(),
                host.len(),
                AFTER_HOST.len()
            ],
            "one run per piece, gathered rather than staged"
        );
        assert_eq!(
            write.segments[1].0,
            path.as_ptr() as usize,
            "the path's own octets, not a copy of them"
        );
        assert_eq!(
            write.segments[3].0,
            host.as_ptr() as usize,
            "and the host's own"
        );
        assert_eq!(write.calls, 1, "one gathered call carries all five runs");
    }

    #[test]
    fn the_request_target_is_a_borrow_and_ignores_the_query() {
        assert_eq!(
            crate::proxy::request_path(b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n"),
            Some("/camouflage")
        );
        assert_eq!(
            crate::proxy::request_path(b"GET /camouflage?t=17 HTTP/1.1\r\n\r\n"),
            Some("/camouflage")
        );
        assert_eq!(
            crate::proxy::request_path(b"POST /camouflage HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(crate::proxy::request_path(b"GET\r\n\r\n"), None);
        assert_eq!(crate::proxy::request_path(&[0xff, 0xfe, 0xfd]), None);
        assert_eq!(
            crate::proxy::request_path(b"GET /camouflage HTTP/1.1\r\n\r\n"),
            Some("/camouflage"),
            "and the bytes it points at are the head's, not a copy"
        );
    }

    #[test]
    fn header_rejects_a_wrong_path() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/camouflage").is_none());
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
