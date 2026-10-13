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

pub(crate) fn block_encode(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
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

pub(crate) fn string_decode(block: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let huffman = block.first()? & 0x80 != 0;
    let (len, mut rest) = prefixed(block, 7)?;
    if rest.len() < len {
        return None;
    }
    let (raw, tail) = rest.split_at(len);
    rest = tail;
    if huffman {
        let mut out = Vec::new();
        ferrox_core::foxy::hpack::huffman_decode(raw, &mut out)?;
        Some((out, rest))
    } else {
        Some((raw.to_vec(), rest))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Decoder {
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
}

impl Decoder {
    fn entry(&self, index: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if index == 0 {
            return None;
        }
        if index <= STATIC.len() {
            let (name, value) = STATIC[index - 1];
            return Some((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
        self.table.get(index - STATIC.len() - 1).cloned()
    }

    fn named<'a>(&self, block: &'a [u8], index: usize) -> Option<(Vec<u8>, &'a [u8])> {
        if index == 0 {
            let (name, rest) = string_decode(block)?;
            if name.is_empty() {
                return None;
            }
            return Some((name, rest));
        }
        Some((self.entry(index)?.0, block))
    }

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

    pub(crate) fn decode(
        &mut self,
        mut block: &[u8],
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Option<()> {
        while !block.is_empty() {
            let first = block[0];
            if first & 0x80 != 0 {
                let (index, rest) = prefixed(block, 7)?;
                out.push(self.entry(index)?);
                block = rest;
            } else if first & 0x40 != 0 {
                let (index, rest) = prefixed(block, 6)?;
                let (name, rest) = self.named(rest, index)?;
                let (value, rest) = string_decode(rest)?;
                self.insert(name.clone(), value.clone());
                out.push((name, value));
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
                let (name, rest) = self.named(rest, index)?;
                let (value, rest) = string_decode(rest)?;
                out.push((name, value));
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

pub(crate) fn write_frame_parts(
    stream: &mut dyn crate::proxy::FrameWrite,
    kind: u8,
    flags: u8,
    id: u32,
    first: &[u8],
    second: &[u8],
) -> bool {
    let mut head = [0u8; 9];
    let len = first.len() + second.len();
    head[0..3].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..9].copy_from_slice(&id.to_be_bytes());
    stream.write_slices(&[&head, first, second])
}

pub(crate) fn write_frame(
    stream: &mut dyn crate::proxy::FrameWrite,
    kind: u8,
    flags: u8,
    id: u32,
    body: &[u8],
) -> bool {
    let mut head = [0u8; 9];
    head[0..3].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..9].copy_from_slice(&id.to_be_bytes());
    stream.write_slices(&[&head, body])
}
