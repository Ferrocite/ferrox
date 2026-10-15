use std::io::{Read, Write};
use std::net::TcpStream;

const HEAD_LIMIT: usize = 8192;

#[derive(Debug)]
pub(crate) struct HeadReader<R: Read = TcpStream> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
}

impl HeadReader<TcpStream> {
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

fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT, crate::budgets::head_arrival())
        .map(|head| (head, Vec::new()))
}

pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(HeadReader, TcpStream)> {
    let mut read = stream;
    let (head, prefix) = read_head(&mut read)?;
    check_request(&head, path)?;
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
            prefix,
            at: 0,
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

// The same accept over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn accept_split<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    path: &str,
) -> Option<(HeadReader<R>, W)> {
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_request(&head, path)?;
    write
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
        .ok()?;
    Some((
        HeadReader {
            read,
            prefix,
            at: 0,
        },
        write,
    ))
}

pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
) -> Option<(HeadReader, TcpStream)> {
    let mut read = stream;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
    read.write_all(request.as_bytes()).ok()?;
    let (head, prefix) = read_head(&mut read)?;
    check_response(&head)?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some((
        HeadReader {
            read,
            prefix,
            at: 0,
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
pub(crate) fn connect_split<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
) -> Option<(HeadReader<R>, W)> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
    write.write_all(request.as_bytes()).ok()?;
    let (head, prefix) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head)?;
    Some((
        HeadReader {
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

    #[test]
    fn header_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, mut write) = accept(stream, "/camouflage").expect("headers");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            write.write_all(b"pong").expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut write) =
            connect(stream, "oracle.example", "/camouflage").expect("headers");
        write.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/camouflage").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
