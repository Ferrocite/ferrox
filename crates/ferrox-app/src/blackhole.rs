//! The blackhole sink: the outbound that swallows a flow.
//!
//! The reference writes its answer, sleeps a second and closes with the peer's
//! request still unread, which the stack answers with a reset that can swallow
//! the answer. This one writes the answer, ends its own write side so the peer
//! reads the answer and the end of the flow together, and, when it answered
//! something, reads the peer's bytes to their end, so the close is a finish and
//! not a reset. The reference's second is gone: the flow ends when the peer is
//! done, and the grace bounds a peer that never is.

use std::io::Read;
use std::net::Shutdown;
use std::sync::Arc;
use std::time::Instant;

use crate::conn::Connection;
use crate::json::Json;
use ferrox_core::blackhole::Response;

/// The window the peer's bytes are read through: one read fills it, so an
/// upload costs one read per window of bytes.
const WINDOW: usize = 16 * 1024;

/// The sink: the answer, then the peer's bytes, then the close.
pub(crate) fn serve(mut client: Connection, answer: &Response) {
    if answer.write_to(&mut client).is_err() {
        return;
    }
    // The peer's read side ends with the answer, so the client reads the answer and the end of the flow together.
    let _ = client.shutdown(Shutdown::Write);
    if answer.bytes().is_empty() {
        // Nothing was answered, so nothing waits to be taken in: the flow ends at once, the way the reference's does.
        return;
    }
    // The peer's bytes are read to their end, so the close is a finish and not the reset an unread request earns.
    let grace = crate::budgets::sink_grace();
    let _ = client.set_read_timeout(Some(grace));
    absorb(&mut client, Instant::now() + grace);
}

/// The peer's bytes, read to their end or to the deadline, and how many of them
/// were read. The window is the read's own size, so an upload costs one read
/// per window of bytes.
fn absorb(reader: &mut impl Read, deadline: Instant) -> usize {
    let mut window = [0u8; WINDOW];
    let mut read = 0;
    while Instant::now() < deadline {
        match reader.read(&mut window) {
            Ok(0) | Err(_) => break,
            Ok(n) => read += n,
        }
    }
    read
}

/// The answer a blackhole outbound gives, read from the config the reference's
/// own shape: `{"response": {"type": "none" | "http" | "custom",
/// "customResponseData": "<base64>"}}`. The type is folded to lower case the
/// way the reference's config builder folds it, and an answer the reference
/// does not know is refused by name rather than served as a silent one.
pub(crate) fn answer(settings: Option<&Json>) -> Result<Response, String> {
    let Some(settings) = settings else {
        return Ok(Response::None);
    };
    let Some(response) = settings.get("response") else {
        return Ok(Response::None);
    };
    if matches!(response, Json::Null) {
        return Ok(Response::None);
    }
    if !matches!(response, Json::Obj(_)) {
        return Err("blackhole response is not an object".to_owned());
    }
    let kind = response.get("type").and_then(Json::as_str).unwrap_or("");
    match kind.to_ascii_lowercase().as_str() {
        "" | "none" => Ok(Response::None),
        "http" => Ok(Response::Http),
        "custom" => {
            let data = response
                .get("customResponseData")
                .and_then(Json::as_str)
                .unwrap_or("");
            let bytes = if data.is_empty() {
                Vec::new()
            } else {
                ferrox_core::b64::decode(data.as_bytes())
                    .ok_or_else(|| "failed to decode custom response data: not base64".to_owned())?
            };
            Ok(Response::Custom(Arc::from(bytes)))
        }
        other => Err(format!("unknown blackhole response: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    fn settings(text: &str) -> Json {
        crate::json::parse(text).expect("parses")
    }

    /// A sink on a loopback socket: the client asks, and the sink answers.
    fn sink_on(answer: Response) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(Connection::Tcp(stream), &answer);
        });
        port
    }

    /// The sink answers the client with the reference's bytes and then ends the
    /// flow: the client reads the answer and then the end of it.
    #[test]
    fn the_sink_answers_and_ends_the_flow() {
        let port = sink_on(Response::Http);
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        // The request is the sink's to swallow.
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .expect("writes");
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = client.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, ferrox_core::blackhole::HTTP_403);
    }

    /// A configured answer reaches the client verbatim, and an answer of no
    /// bytes leaves the client with the end of the flow and nothing else.
    #[test]
    fn the_sink_answers_with_the_configured_bytes() {
        let port = sink_on(Response::Custom(Arc::from(&b"BYE"[..])));
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = client.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"BYE");

        let port = sink_on(Response::None);
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut buf = [0u8; 64];
        assert_eq!(
            client.read(&mut buf).expect("reads"),
            0,
            "nothing was written"
        );
    }

    /// The peer's bytes are read in windows: a payload that is not a whole
    /// number of windows costs one read per window and one for the rest.
    #[test]
    fn the_peers_bytes_are_read_in_windows() {
        struct Windows {
            left: Vec<u8>,
            reads: usize,
        }
        impl Read for Windows {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                let n = self.left.len().min(buf.len());
                buf[..n].copy_from_slice(&self.left[..n]);
                self.left.drain(..n);
                Ok(n)
            }
        }
        // Six whole windows and a half of one.
        let payload = vec![7u8; WINDOW * 6 + WINDOW / 2];
        let mut reader = Windows {
            left: payload.clone(),
            reads: 0,
        };
        let (read, counts) = ferrox_core::alloc_count::measure(|| {
            absorb(&mut reader, Instant::now() + Duration::from_secs(30))
        });
        assert_eq!(counts.allocs, 0, "the window is the stack's");
        assert_eq!(read, payload.len(), "every byte was read");
        assert_eq!(
            reader.reads, 8,
            "one read per window, one for the rest and one for the end"
        );
    }

    /// The three answers the reference knows, read the way its own config
    /// builder reads them.
    #[test]
    fn the_three_answers_are_read_from_the_config() {
        let none = answer(Some(&settings(r#"{"response": {"type": "none"}}"#))).expect("none");
        assert!(matches!(none, Response::None));
        let http = answer(Some(&settings(r#"{"response": {"type": "http"}}"#))).expect("http");
        assert!(matches!(http, Response::Http));
        let custom = answer(Some(&settings(
            r#"{"response": {"type": "custom", "customResponseData": "AAEC"}}"#,
        )))
        .expect("custom");
        assert_eq!(custom.bytes(), &[0, 1, 2]);
    }

    /// A config that names no answer is the silent one, and an answer the
    /// reference does not know is refused by name.
    #[test]
    fn an_unknown_answer_is_refused_by_name() {
        let error =
            answer(Some(&settings(r#"{"response": {"type": "teapot"}}"#))).expect_err("refused");
        assert!(error.contains("teapot"), "{error}");
        let error = answer(Some(&settings(
            r#"{"response": {"type": "custom", "customResponseData": "not base64!"}}"#,
        )))
        .expect_err("refused");
        assert!(error.contains("base64"), "{error}");
        let error = answer(Some(&settings(r#"{"response": "http"}"#))).expect_err("refused");
        assert!(error.contains("object"), "{error}");
    }
}
