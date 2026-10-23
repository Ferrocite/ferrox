use std::collections::VecDeque;
use std::io::Read;

pub(crate) const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(crate) const T_DATA: u8 = 0x00;
pub(crate) const T_HEADERS: u8 = 0x01;
pub(crate) const T_RST: u8 = 0x03;
pub(crate) const T_SETTINGS: u8 = 0x04;
pub(crate) const T_PING: u8 = 0x06;
pub(crate) const T_GOAWAY: u8 = 0x07;
pub(crate) const T_WINDOW: u8 = 0x08;
pub(crate) const T_CONT: u8 = 0x09;
pub(crate) const F_END: u8 = 0x01;
pub(crate) const F_ACK: u8 = 0x01;
pub(crate) const F_END_HEADERS: u8 = 0x04;
pub(crate) const F_PADDED: u8 = 0x08;
pub(crate) const F_PRIORITY: u8 = 0x20;
pub(crate) const S_MAX_CONCURRENT: u16 = 0x03;
pub(crate) const S_WINDOW: u16 = 0x04;
pub(crate) const S_MAX_FRAME: u16 = 0x05;
pub(crate) const E_PROTOCOL: u32 = 0x01;
pub(crate) const E_FRAME_SIZE: u32 = 0x06;
pub(crate) const E_REFUSED: u32 = 0x07;
pub(crate) const WINDOW: u32 = 4 * 1024 * 1024;
pub(crate) const FRAME_CAP: usize = 17 * 1024 * 1024;
pub(crate) const HEAD_CAP: usize = 64 * 1024;
pub(crate) const WINDOW_MAX: u64 = (1 << 31) - 1;

pub(crate) const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

pub(crate) fn push_int(out: &mut Vec<u8>, prefix: u8, first: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push(rest as u8 & 0x7F | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

pub(crate) fn push_str(out: &mut Vec<u8>, text: &str) {
    push_int(out, 7, 0x00, text.len());
    out.extend_from_slice(text.as_bytes());
}

/// The octets one header's literal costs: the never-indexed prefix, the name's length
/// prefix and its bytes, the value's length prefix and its bytes.
fn header_len(name: &str, value: &str) -> usize {
    1 + int_len(name.len()) + name.len() + int_len(value.len()) + value.len()
}

/// The octets a length prefix costs: one below the prefix's maximum, the prefix and a
/// varint of the rest above it.
fn int_len(value: usize) -> usize {
    if value < 127 {
        return 1;
    }
    let mut rest = value - 127;
    let mut len = 1;
    while rest >= 128 {
        len += 1;
        rest >>= 7;
    }
    len + 1
}

pub(crate) fn block_encode(headers: &[(&str, &str)]) -> Vec<u8> {
    // The block's own length is known before it is written, so the buffer is opened once.
    let mut out = Vec::with_capacity(headers.iter().map(|(n, v)| header_len(n, v)).sum());
    for (name, value) in headers {
        out.push(0x00);
        push_str(&mut out, name);
        push_str(&mut out, value);
    }
    out
}

pub(crate) fn prefixed(block: &[u8], prefix: u8) -> Option<(usize, &[u8])> {
    let max = (1usize << prefix) - 1;
    let first = *block.first()? as usize & max;
    if first < max {
        return Some((first, &block[1..]));
    }
    let mut value = max;
    let mut shift = 0u32;
    let mut rest = &block[1..];
    loop {
        let byte = *rest.first()?;
        rest = &rest[1..];
        value += usize::from(byte & 0x7F) << shift;
        shift += 7;
        if shift > 28 || value > HEAD_CAP {
            return None;
        }
        if byte & 0x80 == 0 {
            return Some((value, rest));
        }
    }
}

/// The head of a literal string: whether it is Huffman-coded, the bytes it occupies, and where the block continues.
fn literal(block: &[u8]) -> Option<(bool, &[u8], &[u8])> {
    let coded = *block.first()? & 0x80 != 0;
    let (len, rest) = prefixed(block, 7)?;
    let raw = rest.get(..len)?;
    Some((coded, raw, &rest[len..]))
}

/// One string as the field sees it: a raw literal is the block's own bytes, a Huffman one lands in the buffer the caller warmed. Either way the field borrows, so neither costs an allocation.
fn string<'o, 'b: 'o>(block: &'b [u8], buf: &'o mut Vec<u8>) -> Option<(&'o [u8], &'b [u8])> {
    let (coded, raw, rest) = literal(block)?;
    if coded {
        ferrox_core::foxy::hpack::huffman_decode(raw, buf)?;
        return Some((buf, rest));
    }
    Some((raw, rest))
}

/// One string appended to the caller's buffer, whichever way it came: the copy is what the field's allocation used to be.
fn append<'b>(block: &'b [u8], buf: &mut Vec<u8>) -> Option<&'b [u8]> {
    let (coded, raw, rest) = literal(block)?;
    if coded {
        ferrox_core::foxy::hpack::huffman_decode(raw, buf)?;
    } else {
        buf.extend_from_slice(raw);
    }
    Some(rest)
}

/// What an index stands for, borrowed from the table that already holds it: the static table's `&'static str`, or the dynamic entry's own bytes. It reads the table rather than the decoder so an indexed name stays readable while a literal is filled.
fn indexed(table: &VecDeque<(Vec<u8>, Vec<u8>)>, index: usize) -> Option<(&[u8], &[u8])> {
    if index == 0 {
        return None;
    }
    if index <= STATIC.len() {
        let (name, value) = STATIC[index - 1];
        return Some((name.as_bytes(), value.as_bytes()));
    }
    let (name, value) = table.get(index - STATIC.len() - 1)?;
    Some((&name[..], &value[..]))
}

#[derive(Debug, Default)]
pub(crate) struct Decoder {
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Decoder {
    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.size += 32 + name.len() + value.len();
        self.table.push_front((name, value));
        while self.size > 4096 {
            let Some((name, value)) = self.table.pop_back() else {
                break;
            };
            self.size -= 32 + name.len() + value.len();
        }
    }

    /// Every field of a header block, in order, as borrowed bytes: an indexed field borrows its table entry and a plain literal borrows the block, so neither allocates nor copies; only a Huffman string and what the dynamic table keeps are owned. A refusal stops the block where the reference stops it.
    pub(crate) fn decode(
        &mut self,
        mut block: &[u8],
        field: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Option<()> {
        while !block.is_empty() {
            let first = block[0];
            if first & 0x80 != 0 {
                let (index, rest) = prefixed(block, 7)?;
                let (name, value) = indexed(&self.table, index)?;
                field(name, value);
                block = rest;
            } else if first & 0x40 != 0 {
                let (index, rest) = prefixed(block, 6)?;
                let mut name = Vec::new();
                let mut value = Vec::new();
                let rest = if index == 0 {
                    let rest = append(rest, &mut name)?;
                    if name.is_empty() {
                        return None;
                    }
                    rest
                } else {
                    name.extend_from_slice(indexed(&self.table, index)?.0);
                    rest
                };
                let rest = append(rest, &mut value)?;
                field(&name, &value);
                self.insert(name, value);
                block = rest;
            } else if first & 0x20 != 0 {
                let (max, rest) = prefixed(block, 5)?;
                if max > 4096 {
                    return None;
                }
                while self.size > max {
                    let Some((name, value)) = self.table.pop_back() else {
                        break;
                    };
                    self.size -= 32 + name.len() + value.len();
                }
                block = rest;
            } else {
                let (index, rest) = prefixed(block, 4)?;
                self.name.clear();
                self.value.clear();
                let (name, rest) = if index == 0 {
                    let (name, rest) = string(rest, &mut self.name)?;
                    if name.is_empty() {
                        return None;
                    }
                    (name, rest)
                } else {
                    (indexed(&self.table, index)?.0, rest)
                };
                let (value, rest) = string(rest, &mut self.value)?;
                field(name, value);
                block = rest;
            }
        }
        Some(())
    }
}

pub(crate) fn read_head(stream: &mut dyn Read) -> Option<(usize, u8, u8, u32)> {
    let mut head = [0u8; 9];
    crate::proxy::read_exact(stream, &mut head).ok()?;
    let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    if len > FRAME_CAP {
        return None;
    }
    let id = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7FFF_FFFF;
    Some((len, head[3], head[4], id))
}

/// The nine bytes that open a frame: a gathered batch keeps a head in every frame's own slot, so one
/// builder serves both the single frame written straight to the socket and the batch built apart from
/// its payloads.
pub(crate) fn frame_head(len: usize, kind: u8, flags: u8, id: u32) -> [u8; 9] {
    let mut head = [0u8; 9];
    head[0..3].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..9].copy_from_slice(&id.to_be_bytes());
    head
}

pub(crate) fn write_frame(
    stream: &mut dyn crate::proxy::FrameWrite,
    kind: u8,
    flags: u8,
    id: u32,
    body: &[u8],
) -> bool {
    let head = frame_head(body.len(), kind, flags, id);
    stream.write_slices(&[&head, body])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A field's offset into the block it was read from, witnessed by address rather than by bytes.
    fn offset(block: &[u8], field: &[u8]) -> usize {
        let range = block.as_ptr_range();
        assert!(range.contains(&field.as_ptr()));
        field.as_ptr() as usize - range.start as usize
    }

    /// The header block's own length is known before it is written, so the buffer is
    /// opened once: the counting allocator is the witness.
    #[test]
    fn a_header_block_is_opened_once() {
        let headers = [
            (":method", "POST"),
            (":path", "/TunnelService/Tun"),
            ("x-sid", "mux"),
        ];
        let (block, counts) = ferrox_core::alloc_count::measure(|| block_encode(&headers));
        assert_eq!(counts.allocs, 1, "the block is one buffer");
        assert_eq!(
            counts.bytes,
            block.len(),
            "the buffer is the block's own length, not a grown one"
        );
    }

    #[test]
    fn a_plain_field_borrows_the_block() {
        let block = block_encode(&[("x-sid", "mux"), ("x-token", "abc")]);
        let mut fields = Vec::new();
        let mut decoder = Decoder::default();
        decoder
            .decode(&block, &mut |name, value| {
                fields.push((offset(&block, name), offset(&block, value)));
            })
            .expect("decodes");
        for (name, value) in [("x-sid", "mux"), ("x-token", "abc")] {
            let (name_at, value_at) = fields.remove(0);
            assert_eq!(&block[name_at..name_at + name.len()], name.as_bytes());
            assert_eq!(&block[value_at..value_at + value.len()], value.as_bytes());
        }
    }

    #[test]
    fn an_indexed_field_borrows_the_table() {
        // One insert of a fresh pair, then a static index and the index it just made: 0x3e is 62, the first dynamic entry.
        let mut block = vec![0x40, 5, b'x', b'-', b's', b'i', b'd', 3, b'm', b'u', b'x'];
        block.push(0x80 | 8);
        block.push(0x80 | 0x3E);
        let mut kept = Vec::new();
        let mut status = false;
        let mut decoder = Decoder::default();
        decoder
            .decode(&block, &mut |name, value| {
                if name == b"x-sid" {
                    kept.push((name.as_ptr(), value.as_ptr()));
                } else {
                    status = value == b"200";
                }
            })
            .expect("decodes");
        assert!(status);
        // The pair the table keeps is the pair the consumer was handed, twice over: the insert costed no copy and the index costs no allocation.
        assert_eq!(
            kept,
            vec![(decoder.table[0].0.as_ptr(), decoder.table[0].1.as_ptr()); 2]
        );
    }

    #[test]
    fn a_borrowed_block_leaves_the_scratch_alone() {
        // Warm the decoder's buffers with a Huffman name, then read a block that borrows everything — one index, one plain literal: nothing may land in them.
        let coded = [
            0x00, 0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF,
            0x03, b'm', b'u', b'x',
        ];
        let mut decoder = Decoder::default();
        decoder.decode(&coded, &mut |_, _| {}).expect("decodes");
        assert_eq!(decoder.name, b"www.example.com".to_vec());
        let warm = (
            decoder.name.as_ptr(),
            decoder.name.capacity(),
            decoder.value.capacity(),
        );
        let mut block = block_encode(&[("x-sid", "mux")]);
        block.push(0x80 | 8);
        let mut fields = 0;
        decoder
            .decode(&block, &mut |_, _| fields += 1)
            .expect("decodes");
        assert_eq!(fields, 2);
        assert_eq!(
            (
                decoder.name.as_ptr(),
                decoder.name.capacity(),
                decoder.value.capacity()
            ),
            warm
        );
        assert!(decoder.name.is_empty() && decoder.value.is_empty());
    }
}
