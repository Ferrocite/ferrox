//! The blackhole sink's answer: the bytes a blackhole outbound writes to the client.
//!
//! The reference answers with one of three things — nothing, the 403 its own
//! `http.Response.Write` serialises, or the bytes the config carries — and the
//! oracle (`scripts/blackhole-oracle`) drives the pinned `xray-core`'s handler
//! and records every octet it wrote. This module's answer is that record.

use std::io::{self, Write};
use std::sync::Arc;

/// The 403 the reference writes: Go's `http.Response.Write` puts the status line
/// first, the headers next in the order `Header.WriteSubset` sorts them, the
/// `Content-Length: 0` it adds for a status that allows a body after them, and
/// the blank line last. 101 bytes, and the oracle's first line is these.
pub const HTTP_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\nCache-Control: max-age=3600, public\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// What a blackhole outbound answers the client with.
#[derive(Debug, Clone, Default)]
pub enum Response {
    /// Nothing: the flow ends and the client reads the end of it.
    #[default]
    None,
    /// The 403 the reference serialises.
    Http,
    /// The bytes the config carries, written verbatim.
    Custom(Arc<[u8]>),
}

impl Response {
    /// The bytes the answer is made of; empty means the client is answered with nothing.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::None => &[],
            Self::Http => HTTP_403,
            Self::Custom(data) => data,
        }
    }

    /// Write the answer to the client. The writer sees the answer's own bytes:
    /// nothing is staged between here and the wire.
    ///
    /// # Errors
    /// The writer's error, unchanged.
    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> io::Result<()> {
        let bytes = self.bytes();
        if bytes.is_empty() {
            return Ok(());
        }
        writer.write_all(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    /// The answer is the bytes the reference writes: the oracle drives the pinned
    /// `xray-core`'s own handler over a pipe and records every octet it wrote.
    #[test]
    fn the_answer_is_the_bytes_the_pinned_go_writes() {
        let script = include_str!("../../../scripts/blackhole-oracle/script.txt");
        let expected = include_str!("../../../scripts/blackhole-oracle/expected.txt");

        let mut lines = Vec::new();
        for line in script.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let answer = match fields.next().expect("a case") {
                "http" => Response::Http,
                "none" => Response::None,
                "custom" => {
                    let data = fields.next().map(unhex).unwrap_or_default();
                    Response::Custom(data.into())
                }
                other => panic!("unknown case {other}"),
            };
            lines.push(format!("BYTES {}", hex(answer.bytes())));
        }
        assert_eq!(lines.join("\n") + "\n", expected);
    }

    /// The answer reaches the writer uncopied: the pointer the writer saw is the
    /// one the answer's own buffer holds, and a clone of the answer does not
    /// move it.
    #[test]
    fn the_answer_reaches_the_writer_uncopied() {
        struct Peeker {
            ptr: usize,
            len: usize,
        }
        impl Write for Peeker {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.ptr = buf.as_ptr() as usize;
                self.len = buf.len();
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let data: Vec<u8> = (0..4_000u32).map(|i| (i % 251) as u8).collect();
        let answer = Response::Custom(data.clone().into());
        let base = answer.bytes().as_ptr() as usize;
        let len = answer.bytes().len();

        let mut peeker = Peeker { ptr: 0, len: 0 };
        let ((), counts) = crate::alloc_count::measure(|| {
            answer.write_to(&mut peeker).expect("writes");
        });
        assert_eq!(
            counts.allocs, 0,
            "the answer is written without a buffer of its own"
        );
        assert_eq!(peeker.len, len, "the whole answer reached the writer");
        assert_eq!(peeker.ptr, base, "the answer reached the writer uncopied");
        assert!(
            peeker.ptr >= base && peeker.ptr + peeker.len <= base + len,
            "the writer's slice lies inside the answer's own buffer"
        );

        // A clone of the answer — the shape the outbound registry holds — shares the buffer, so the pointer does not move.
        let clone = answer.clone();
        assert_eq!(
            clone.bytes().as_ptr() as usize,
            base,
            "the answer's buffer does not move when the answer is cloned"
        );
    }

    /// The 403 is the reference's own serialisation, byte for byte: Go writes the
    /// status line, the sorted headers, the empty body's length and the blank
    /// line, in that order.
    #[test]
    fn the_403_is_the_reference_bytes() {
        assert_eq!(HTTP_403.len(), 101);
        assert_eq!(
            HTTP_403,
            b"HTTP/1.1 403 Forbidden\r\nCache-Control: max-age=3600, public\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
    }

    /// The answer is one write: the writer is handed the whole answer, so a
    /// flow's answer costs one write and not a loop over the bytes.
    #[test]
    fn the_answer_is_one_write() {
        struct Counter {
            writes: usize,
            bytes: usize,
        }
        impl Write for Counter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                self.bytes += buf.len();
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut counter = Counter {
            writes: 0,
            bytes: 0,
        };
        Response::Http.write_to(&mut counter).expect("writes");
        assert_eq!(counter.writes, 1, "the answer is one write");
        assert_eq!(counter.bytes, HTTP_403.len());
    }

    /// An answer of no bytes writes nothing at all: the reference's own
    /// `len(h.response) > 0` gate, and the empty custom answer it lets through.
    #[test]
    fn an_answer_of_no_bytes_writes_nothing() {
        struct Counter(usize);
        impl Write for Counter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0 += buf.len();
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for answer in [Response::None, Response::Custom(Vec::new().into())] {
            let mut counter = Counter(0);
            answer.write_to(&mut counter).expect("writes");
            assert_eq!(counter.0, 0, "nothing was written");
        }
    }
}
