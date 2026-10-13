//! HPACK for HTTP/2 and QPACK for HTTP/3, both answering one question — the status — and refusing any representation needing a table the lane never fills, while both encoders write literals only: one request per stream, no table state, no Huffman. Integers share one prefix scheme: below `2^n - 1` the low `n` bits of one byte, else that maximum plus a base-128 remainder.

use std::sync::OnceLock;

/// The HPACK Huffman code is canonical — consecutive codes per length, each starting where the previous ended shifted left — so one byte per symbol rebuilds every code and a code maps back by its offset within its length.
const HUFFMAN_BITS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, //
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, //
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, //
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, //
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, //
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, //
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, //
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, //
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, //
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, //
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, //
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, //
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, //
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, //
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, //
    30,
];

const SHORTEST: usize = 5;
const MAX_BITS: usize = 30;

struct Huffman {
    /// One load per probed length: the first code of that length in the high half and how many codes share it in the low half. A length with no codes reads `(0, 0)`, so the range test below already rejects it and no separate empty-length check is needed.
    probe: [u64; MAX_BITS + 1],
    /// Where each length's symbols begin in `symbols`, ordered by length then symbol, so a code is `first[length] + offset`; read only on the rare match.
    base: [u16; MAX_BITS + 1],
    symbols: [u16; 257],
}

fn huffman() -> &'static Huffman {
    static TABLE: OnceLock<Huffman> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Huffman {
            probe: [0; MAX_BITS + 1],
            base: [0; MAX_BITS + 1],
            symbols: [0; 257],
        };
        let mut next = 0u32;
        let mut placed = 0usize;
        let mut previous = 0usize;
        for bits in SHORTEST..=MAX_BITS {
            if !HUFFMAN_BITS.contains(&(bits as u8)) {
                continue;
            }
            next <<= bits - previous;
            previous = bits;
            let first = next;
            table.base[bits] = placed as u16;
            let mut count = 0u32;
            for (symbol, length) in HUFFMAN_BITS.iter().enumerate() {
                if usize::from(*length) != bits {
                    continue;
                }
                table.symbols[placed] = symbol as u16;
                count += 1;
                placed += 1;
                next += 1;
            }
            table.probe[bits] = (u64::from(first) << 32) | u64::from(count);
        }
        table
    })
}

/// The code of one symbol, read back out of the table the decoder uses so the encoder cannot be a second source of truth; only tests call it, as a CONNECT request is literals.
#[cfg(test)]
fn huffman_code(symbol: usize) -> Option<(u32, usize)> {
    let bits = usize::from(HUFFMAN_BITS[symbol]);
    let table = huffman();
    let probe = table.probe[bits];
    let base = table.base[bits] as usize;
    let slot = table.symbols[base..base + probe as u32 as usize]
        .iter()
        .position(|other| usize::from(*other) == symbol)?;
    Some(((probe >> 32) as u32) + slot as u32, bits)
}

/// Decodes one Huffman-coded string: the 257th entry is the EOS code rather than a symbol, so a block decoding one is malformed, and only the all-ones prefix under eight bits may follow the last symbol.
pub fn huffman_decode(code: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let table = huffman();
    let mut acc = 0u32;
    let mut bits = 0usize;
    for byte in code {
        for shift in (0..8).rev() {
            acc = (acc << 1) | u32::from(byte >> shift & 1);
            bits += 1;
            if bits > MAX_BITS {
                return None;
            }
            let probe = table.probe[bits];
            let offset = acc.wrapping_sub((probe >> 32) as u32);
            if offset >= probe as u32 {
                continue;
            }
            let symbol = table.symbols[table.base[bits] as usize + offset as usize];
            if symbol == 256 {
                return None;
            }
            out.push(symbol as u8);
            acc = 0;
            bits = 0;
        }
    }
    if bits != 0 && (bits >= 8 || acc != (1 << bits) - 1) {
        return None;
    }
    Some(())
}

#[cfg(test)]
fn huffman_encode(bytes: &[u8], out: &mut Vec<u8>) {
    let mut acc = 0u64;
    let mut bits = 0u32;
    for byte in bytes {
        let Some((code, length)) = huffman_code(usize::from(*byte)) else {
            continue;
        };
        let length = length as u32;
        acc = (acc << length) | u64::from(code);
        bits += length;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits != 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
}

/// An integer in one byte carrying `prefix` low bits, continued in base-128.
pub(crate) fn integer(out: &mut Vec<u8>, prefix: u8, mask: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(mask | value as u8);
        return;
    }
    out.push(mask | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// The same integer as `integer`, continued into the byte the pattern already occupies — QPACK's one form for a field name, where that byte's low bits are the length prefix.
pub(crate) fn integer_into(out: &mut Vec<u8>, prefix: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    let slot = out.len() - 1;
    if value < max {
        out[slot] |= value as u8;
        return;
    }
    out[slot] |= max as u8;
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

fn read_integer(block: &[u8], at: &mut usize, prefix: u8) -> Option<usize> {
    let first = *block.get(*at)?;
    *at += 1;
    let max = (1usize << prefix) - 1;
    let mut value = usize::from(first & max as u8);
    if value < max {
        return Some(value);
    }
    let mut shift = 0u32;
    loop {
        let byte = *block.get(*at)?;
        *at += 1;
        if shift > 56 {
            return None;
        }
        value = value.checked_add(usize::from(byte & 0x7f).checked_shl(shift)?)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

/// One string literal, borrowed when stored as-is and owned when Huffman coded; that path allocates because a status is three digits and a name this lane reads is one short literal.
enum Literal<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Literal<'_> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    fn is_status(&self) -> bool {
        self.as_bytes() == b":status"
    }
}

fn string_literal<'a>(block: &'a [u8], at: &mut usize) -> Option<Literal<'a>> {
    let coded = *block.get(*at)? & 0x80 != 0;
    let len = read_integer(block, at, 7)?;
    let raw = block.get(*at..at.checked_add(len)?)?;
    *at += len;
    if !coded {
        return Some(Literal::Borrowed(raw));
    }
    let mut out = Vec::with_capacity(len);
    huffman_decode(raw, &mut out)?;
    Some(Literal::Owned(out))
}

/// The QPACK static table, index-addressed: the 99 name/value pairs every endpoint knows without dynamic state, so an indexed field line is two bytes.
const QPACK_STATIC: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

/// The `:status` entries of a static table, HPACK's from index 8 and QPACK's from the table above: an indexed entry is one integer with nothing following, so a field this lane never reads costs nothing to walk past.
fn static_status(index: usize, h2: bool) -> Option<u16> {
    if h2 {
        const H2: [u16; 7] = [200, 204, 206, 304, 400, 404, 500];
        return H2.get(index.checked_sub(8)?).copied();
    }
    let (name, value) = QPACK_STATIC.get(index)?;
    if *name != b":status" {
        return None;
    }
    status_of(value)
}

/// A three-digit decimal status, read in place rather than copied out.
fn status_of(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        u16::from(bytes[0] - b'0') * 100
            + u16::from(bytes[1] - b'0') * 10
            + u16::from(bytes[2] - b'0'),
    )
}

/// Reads an HPACK block's `:status`: an indexed entry is one integer, so any index outside the `:status` range is skipped; a literal is read only under a `:status` name; a dynamic size update carries no entry and is skipped, the lane keeping no dynamic table.
pub fn hpack_status(block: &[u8]) -> Option<u16> {
    let mut at = 0usize;
    let mut status = None;
    while at < block.len() {
        let first = block[at];
        if first & 0x80 != 0 {
            let index = read_integer(block, &mut at, 7)?;
            if let Some(code) = static_status(index, true) {
                status = Some(code);
            }
            continue;
        }
        if first & 0xC0 == 0x40 {
            let index = read_integer(block, &mut at, 6)?;
            let name_is_status = if index == 0 {
                string_literal(block, &mut at)?.is_status()
            } else {
                static_status(index, true).is_some()
            };
            let value = string_literal(block, &mut at)?;
            if name_is_status {
                status = Some(status_of(value.as_bytes())?);
            }
            continue;
        }
        if first & 0xE0 == 0x20 {
            read_integer(block, &mut at, 5)?;
            continue;
        }
        let index = read_integer(block, &mut at, 4)?;
        let name_is_status = if index == 0 {
            string_literal(block, &mut at)?.is_status()
        } else {
            static_status(index, true).is_some()
        };
        let value = string_literal(block, &mut at)?;
        if name_is_status {
            status = Some(status_of(value.as_bytes())?);
        }
    }
    status
}

/// Reads a QPACK block's `:status`: QPACK prefixes it with a required insert count and a delta base, and a block not prefixed by two zero bytes names a dynamic table this lane does not have.
pub fn qpack_status(block: &[u8]) -> Option<u16> {
    if *block.first()? != 0 || *block.get(1)? != 0 {
        return None;
    }
    let mut at = 2usize;
    let mut status = None;
    while at < block.len() {
        let first = block[at];
        let name_is_status = if first & 0x80 != 0 {
            let index = read_integer(block, &mut at, 6)?;
            status = Some(static_status(index, false)?);
            continue;
        } else if first & 0xE0 == 0x20 {
            qpack_name(block, &mut at)?.is_status()
        } else {
            return None;
        };
        let value = string_literal(block, &mut at)?;
        if name_is_status {
            status = Some(status_of(value.as_bytes())?);
        }
    }
    status
}

/// QPACK's literal field line packs the `001` pattern, the never-indexed bit, the name's Huffman bit and a three-bit name length into one byte, so the name is a prefixed integer read from that byte.
fn qpack_name<'a>(block: &'a [u8], at: &mut usize) -> Option<Literal<'a>> {
    let coded = *block.get(*at)? & 0x08 != 0;
    let len = read_integer(block, at, 3)?;
    let raw = block.get(*at..at.checked_add(len)?)?;
    *at += len;
    if !coded {
        return Some(Literal::Borrowed(raw));
    }
    let mut out = Vec::with_capacity(len);
    huffman_decode(raw, &mut out)?;
    Some(Literal::Owned(out))
}

/// Any request as literal field lines: two zero prefix bytes name no dynamic state, and each field is a `001` name length, name, value length and value run with no Huffman to compute.
pub fn qpack_literal_many(fields: &[(&str, &str)], out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00]);
    for (name, value) in fields {
        out.push(0x20);
        integer_into(out, 3, name.len());
        out.extend_from_slice(name.as_bytes());
        integer(out, 7, 0x00, value.len());
        out.extend_from_slice(value.as_bytes());
    }
}

/// Reads every field of a QPACK block whose references stay inside the static table — indexed lines, static name references, literal names Huffman-coded or not — and refuses anything naming dynamic state.
#[must_use]
pub fn qpack_fields(block: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    if *block.first()? != 0 || *block.get(1)? != 0 {
        return None;
    }
    let mut at = 2usize;
    let mut fields = Vec::new();
    while at < block.len() {
        let first = block[at];
        if first & 0x80 != 0 {
            let index = read_integer(block, &mut at, 6)?;
            let (name, value) = QPACK_STATIC.get(index)?;
            fields.push((name.to_vec(), value.to_vec()));
        } else if first & 0xC0 == 0x40 {
            if first & 0x20 != 0 {
                return None;
            }
            let index = read_integer(block, &mut at, 4)?;
            let (name, _) = QPACK_STATIC.get(index)?;
            let value = string_literal(block, &mut at)?;
            fields.push((name.to_vec(), value.as_bytes().to_vec()));
        } else if first & 0xE0 == 0x20 {
            let name = qpack_name(block, &mut at)?;
            let value = string_literal(block, &mut at)?;
            fields.push((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        } else {
            return None;
        }
    }
    Some(fields)
}

/// One CONNECT request, three fields, literal names and values: the smallest header block a CONNECT can be written in, with the `Bearer` scheme the edge answers — a bare token is a 400.
pub fn hpack_connect(target: &str, bearer: &str, out: &mut Vec<u8>) {
    for (name, value) in [(":method", "CONNECT"), (":authority", target)] {
        out.push(0x00);
        integer(out, 7, 0x00, name.len());
        out.extend_from_slice(name.as_bytes());
        integer(out, 7, 0x00, value.len());
        out.extend_from_slice(value.as_bytes());
    }
    let name = "proxy-authorization";
    out.push(0x00);
    integer(out, 7, 0x00, name.len());
    out.extend_from_slice(name.as_bytes());
    integer(out, 7, 0x00, "Bearer ".len() + bearer.len());
    out.extend_from_slice(b"Bearer ");
    out.extend_from_slice(bearer.as_bytes());
}

/// The same three fields under QPACK: a required insert count of zero, fields named with the `001` literal pattern, and one allocation joining the scheme the edge answers to the token, since a bare token is a 400.
pub fn qpack_connect(target: &str, bearer: &str, out: &mut Vec<u8>) {
    let bearer = format!("Bearer {bearer}");
    qpack_literal_many(
        &[
            (":method", "CONNECT"),
            (":authority", target),
            ("proxy-authorization", bearer.as_str()),
        ],
        out,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One QPACK literal field line, written the way a peer would write it.
    fn qpack_literal_coded(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        if block.is_empty() {
            block.extend_from_slice(&[0x00, 0x00]);
        }
        block.push(0x20);
        integer_into(block, 3, name.len());
        block.extend_from_slice(name.as_bytes());
        block.push(0x80 | value.len() as u8);
        block.extend_from_slice(value);
    }

    fn qpack_literal(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        if block.is_empty() {
            block.extend_from_slice(&[0x00, 0x00]);
        }
        block.push(0x20);
        integer_into(block, 3, name.len());
        block.extend_from_slice(name.as_bytes());
        integer(block, 7, 0x00, value.len());
        block.extend_from_slice(value);
    }

    /// One HPACK literal field line with a literal name, the form this lane writes.
    fn hpack_literal(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        block.push(0x00);
        integer(block, 7, 0x00, name.len());
        block.extend_from_slice(name.as_bytes());
        integer(block, 7, 0x00, value.len());
        block.extend_from_slice(value);
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|byte| (byte as char).to_digit(16).expect("hex") as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    #[test]
    fn the_rfc7541_huffman_examples_decode_to_their_plain_text() {
        for (encoded, plain) in [
            ("f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"),
            ("a8eb10649cbf", "no-cache"),
            ("25a849e95ba97d7f", "custom-key"),
            ("25a849e95bb8e8b4bf", "custom-value"),
            ("90692f", "date"),
        ] {
            let raw = hex(encoded);
            let mut out = Vec::new();
            huffman_decode(&raw, &mut out).expect("decodes");
            assert_eq!(out, plain.as_bytes(), "{encoded}");
        }
    }

    #[test]
    fn encoding_huffman_reproduces_the_rfc7541_appendix_c_bit_strings() {
        for (plain, encoded) in [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-key", "25a849e95ba97d7f"),
            ("custom-value", "25a849e95bb8e8b4bf"),
            ("date", "90692f"),
            ("", ""),
        ] {
            let mut out = Vec::new();
            huffman_encode(plain.as_bytes(), &mut out);
            assert_eq!(out, hex(encoded), "{plain}");
        }
    }

    #[test]
    fn every_symbol_round_trips_through_the_canonical_table() {
        let all: Vec<u8> = (0..=255u8).collect();
        let mut coded = Vec::new();
        huffman_encode(&all, &mut coded);
        let mut back = Vec::new();
        huffman_decode(&coded, &mut back).expect("decodes");
        assert_eq!(back, all);
        assert_eq!(huffman_decode(&[], &mut Vec::new()), Some(()));
    }

    #[test]
    fn every_symbol_decodes_to_itself_one_at_a_time() {
        for symbol in 0..=255usize {
            let mut coded = Vec::new();
            let byte = symbol as u8;
            huffman_encode(&[byte], &mut coded);
            let mut out = Vec::new();
            huffman_decode(&coded, &mut out).expect("decodes");
            assert_eq!(out, vec![byte], "symbol {symbol}");
        }
    }

    #[test]
    fn the_fused_probe_holds_the_canonical_first_and_count_of_every_length() {
        // An independent canonical walk straight off the code lengths, the second
        // source the fused probe is checked against rather than against itself.
        let table = huffman();
        let mut histogram = [0u32; MAX_BITS + 1];
        for &length in &HUFFMAN_BITS {
            histogram[usize::from(length)] += 1;
        }
        let mut code = 0i64;
        let mut previous = 0usize;
        for bits in SHORTEST..=MAX_BITS {
            code <<= bits - previous;
            previous = bits;
            // A length with no codes is left at the table's zero default, exactly
            // as the build skips it; only a length that carries codes is checked.
            if histogram[bits] == 0 {
                continue;
            }
            let probe = table.probe[bits];
            assert_eq!(
                probe >> 32,
                u64::from(code as u32),
                "first of length {bits}"
            );
            assert_eq!(probe as u32, histogram[bits], "count of length {bits}");
            code += i64::from(histogram[bits]);
        }
    }

    #[test]
    fn the_rebuilt_table_is_the_rfc_table_code_for_code() {
        for (symbol, expected) in [
            (0usize, (8184, 13)),
            (32, (20, 6)),
            (37, (21, 6)),
            (46, (23, 6)),
            (48, (0, 5)),
            (49, (1, 5)),
            (50, (2, 5)),
            (58, (92, 7)),
            (63, (1020, 10)),
            (97, (3, 5)),
            (98, (35, 6)),
            (124, (2044, 11)),
            (255, (67_108_846, 26)),
            (256, (1_073_741_823, 30)),
        ] {
            assert_eq!(huffman_code(symbol), Some(expected), "symbol {symbol}");
        }
    }

    #[test]
    fn an_eos_code_inside_a_string_is_refused_and_padding_is_not() {
        let mut coded = Vec::new();
        huffman_encode(b"200", &mut coded);
        assert!(huffman_decode(&coded, &mut Vec::new()).is_some());
        assert!(
            huffman_decode(&[0xff], &mut Vec::new()).is_none(),
            "eight bits of padding"
        );
        let eos = [0xff, 0xff, 0xff, 0xff];
        assert!(
            huffman_decode(&eos, &mut Vec::new()).is_none(),
            "an EOS symbol"
        );
        assert!(
            huffman_decode(&[0x90], &mut Vec::new()).is_none(),
            "half a symbol"
        );
        let padded = [0x90, 0x69];
        let mut out = Vec::new();
        assert!(
            huffman_decode(&padded, &mut out).is_some(),
            "padding is allowed"
        );
        assert_eq!(out, b"dat");
    }

    #[test]
    fn the_integer_prefix_spans_its_own_boundary() {
        for prefix in [4u8, 5, 6, 7] {
            for value in [
                0usize, 1, 14, 15, 16, 30, 31, 32, 126, 127, 128, 129, 1_000, 70_000,
            ] {
                let mut out = Vec::new();
                integer(&mut out, prefix, 0x00, value);
                let mut at = 0;
                assert_eq!(
                    read_integer(&out, &mut at, prefix),
                    Some(value),
                    "{prefix}/{value}"
                );
                assert_eq!(at, out.len());
            }
        }
    }

    #[test]
    fn a_truncated_or_oversized_integer_is_refused() {
        assert_eq!(read_integer(&[0x7e], &mut 0, 7), Some(126));
        assert_eq!(read_integer(&[0x7f, 0x00], &mut 0, 7), Some(127));
        assert_eq!(read_integer(&[0xff], &mut 0, 7), None);
        assert_eq!(read_integer(&[0xff, 0x80], &mut 0, 7), None);
        assert_eq!(read_integer(&[0xff; 12], &mut 0, 7), None);
        assert_eq!(read_integer(&[0x7f, 0xff], &mut 0, 7), None);
    }

    #[test]
    fn a_literal_status_of_three_digits_is_read_in_both_codecs() {
        let mut h2 = Vec::new();
        hpack_literal(&mut h2, ":status", b"200");
        assert_eq!(hpack_status(&h2), Some(200));
        let mut q3 = Vec::new();
        qpack_literal(&mut q3, ":status", b"200");
        assert_eq!(qpack_status(&q3), Some(200));
    }

    #[test]
    fn an_indexed_status_is_read_from_both_static_tables() {
        for (index, want) in [
            (8usize, 200u16),
            (9, 204),
            (10, 206),
            (11, 304),
            (12, 400),
            (13, 404),
            (14, 500),
        ] {
            let mut h2 = Vec::new();
            integer(&mut h2, 7, 0x80, index);
            assert_eq!(hpack_status(&h2), Some(want), "hpack {index}");
            if index == 8 {
                let mut literal = vec![0x40];
                integer_into(&mut literal, 6, index);
                integer(&mut literal, 7, 0x00, 3);
                literal.extend_from_slice(b"200");
                assert_eq!(hpack_status(&literal), Some(200), "a literal status");
            }
        }
        for (index, want) in [
            (24usize, 103u16),
            (25, 200),
            (26, 304),
            (27, 404),
            (28, 503),
            (63, 100),
            (64, 204),
            (71, 500),
        ] {
            let mut q3 = vec![0x00, 0x00];
            integer(&mut q3, 6, 0xC0, index);
            assert_eq!(qpack_status(&q3), Some(want), "qpack {index}");
        }
        for index in [15usize, 20, 22, 23, 29, 62, 72, 98, 99, 200] {
            let mut q3 = vec![0x00, 0x00];
            integer(&mut q3, 6, 0xC0, index);
            assert_eq!(qpack_status(&q3), None, "not a status: {index}");
        }
    }

    #[test]
    fn a_huffman_coded_status_is_read() {
        let mut value = Vec::new();
        huffman_encode(b"200", &mut value);
        let mut block = vec![0x40];
        integer_into(&mut block, 6, 8);
        block.push(0x80 | value.len() as u8);
        block.extend_from_slice(&value);
        assert_eq!(hpack_status(&block), Some(200));
        let mut q3_coded = Vec::new();
        qpack_literal_coded(&mut q3_coded, ":status", &value);
        assert_eq!(qpack_status(&q3_coded), Some(200), "a huffman status");
        let mut q3_raw = Vec::new();
        qpack_literal(&mut q3_raw, ":status", b"200");
        assert_eq!(qpack_status(&q3_raw), Some(200), "a literal status");
    }

    #[test]
    fn a_status_that_is_not_three_digits_is_refused() {
        for text in ["", "2", "20", "2000", "abc", "2 0", "++"] {
            let mut block = Vec::new();
            hpack_literal(&mut block, ":status", text.as_bytes());
            assert_eq!(hpack_status(&block), None, "{text:?}");
        }
    }

    #[test]
    fn a_block_with_no_status_in_it_yields_none() {
        assert_eq!(hpack_status(&[0x3f, 0xe1, 0x1f]), None, "a size update");
        assert_eq!(
            hpack_status(&[0x0f, 0x61, 0x62, 0x63]),
            None,
            "an unindexed name"
        );
        assert_eq!(
            hpack_status(&[0xff, 0x02, 0x00, 0x40]),
            None,
            "a table index"
        );
        assert_eq!(
            hpack_status(&[0x3f, 0xe1, 0x1f, 0x82]),
            None,
            "a size update first"
        );
        assert_eq!(
            qpack_status(&[0x01, 0x00, 0xC0, 0x01]),
            None,
            "a dynamic insert count"
        );
        assert_eq!(qpack_status(&[0x00]), None, "a truncated prefix");
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x40, 0x01]),
            None,
            "a name reference"
        );
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x30, 0x00]),
            None,
            "a post-base index"
        );
    }

    #[test]
    fn an_encoder_beyond_the_minimal_one_still_yields_its_status() {
        // A size update, an unread indexed field, a literal with incremental indexing naming one, then the indexed status.
        let mut block = vec![0x3f, 0xe1, 0x1f, 0x80 | 0x21];
        block.push(0x40);
        integer_into(&mut block, 6, 33);
        integer(&mut block, 7, 0x00, 1);
        block.extend_from_slice(b"x");
        block.push(0x88);
        assert_eq!(hpack_status(&block), Some(200));
        // The same status as a literal under its indexed name, with a literal date first: the name decides, not the representation.
        let mut named = vec![0x00];
        integer(&mut named, 7, 0x00, 4);
        named.extend_from_slice(b"date");
        integer(&mut named, 7, 0x00, 1);
        named.extend_from_slice(b"x");
        named.push(0x40);
        integer_into(&mut named, 6, 13);
        integer(&mut named, 7, 0x00, 3);
        named.extend_from_slice(b"404");
        assert_eq!(hpack_status(&named), Some(404));
    }

    #[test]
    fn a_field_this_lane_does_not_read_is_skipped_not_refused() {
        let mut block = Vec::new();
        for (name, value) in [("date", "x"), (":status", "200"), ("server", "edge")] {
            hpack_literal(&mut block, name, value.as_bytes());
        }
        assert_eq!(hpack_status(&block), Some(200));
        let mut q3 = Vec::new();
        for (name, value) in [("date", "x"), (":status", "404"), ("server", "edge")] {
            qpack_literal(&mut q3, name, value.as_bytes());
        }
        assert_eq!(qpack_status(&q3), Some(404));
    }

    #[test]
    fn the_qpack_static_table_holds_99_indexed_entries() {
        assert_eq!(QPACK_STATIC.len(), 99);
        for (index, name, value) in [
            (0usize, ":authority", ""),
            (1, ":path", "/"),
            (15, ":method", "CONNECT"),
            (20, ":method", "POST"),
            (22, ":scheme", "http"),
            (23, ":scheme", "https"),
            (24, ":status", "103"),
            (25, ":status", "200"),
            (28, ":status", "503"),
            (63, ":status", "100"),
            (71, ":status", "500"),
            (84, "authorization", ""),
            (98, "x-frame-options", "sameorigin"),
        ] {
            assert_eq!(
                QPACK_STATIC[index],
                (name.as_bytes(), value.as_bytes()),
                "index {index}"
            );
        }
    }

    #[test]
    fn qpack_fields_reads_indexed_named_and_coded_lines() {
        let mut block = Vec::new();
        qpack_literal_many(
            &[(":method", "POST"), ("hysteria-auth", "s3cret")],
            &mut block,
        );
        block.push(0x80 | 0x17);
        block.extend_from_slice(&[0x4F, 0x0A, 0x03, b'2', b'3', b'3']);
        assert_eq!(
            qpack_fields(&block),
            Some(vec![
                (b":method".to_vec(), b"POST".to_vec()),
                (b"hysteria-auth".to_vec(), b"s3cret".to_vec()),
                (b":scheme".to_vec(), b"https".to_vec()),
                (b":status".to_vec(), b"233".to_vec()),
            ])
        );
        let mut coded = Vec::new();
        huffman_encode(b"gzip", &mut coded);
        let mut huffed = vec![0x00, 0x00, 0x20];
        integer_into(&mut huffed, 3, 7);
        huffed.extend_from_slice(b":status");
        huffed.push(0x80 | coded.len() as u8);
        huffed.extend_from_slice(&coded);
        assert_eq!(
            qpack_fields(&huffed),
            Some(vec![(b":status".to_vec(), b"gzip".to_vec())])
        );
    }

    #[test]
    fn qpack_fields_refuses_anything_naming_dynamic_state() {
        assert_eq!(qpack_fields(&[]), None);
        assert_eq!(qpack_fields(&[0x01, 0x00]), None);
        assert_eq!(qpack_fields(&[0x00, 0x00, 0x60, 0x00]), None);
        assert_eq!(qpack_fields(&[0x00, 0x00, 0x10]), None);
        assert_eq!(qpack_fields(&[0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn a_literal_request_encodes_the_connect_form() {
        let mut many = Vec::new();
        qpack_literal_many(
            &[
                (":method", "CONNECT"),
                (":authority", "example.com:443"),
                ("proxy-authorization", "Bearer p"),
            ],
            &mut many,
        );
        let mut one = Vec::new();
        qpack_connect("example.com:443", "p", &mut one);
        assert_eq!(many, one);
        assert_eq!(
            qpack_fields(&many).expect("reads").len(),
            3,
            "three literal fields"
        );
    }
    #[test]
    fn a_connect_block_is_the_smallest_literal_form_and_holds_the_bearer() {
        let mut h2 = Vec::new();
        hpack_connect("example.com:443", "p", &mut h2);
        let mut q3 = Vec::new();
        qpack_connect("example.com:443", "p", &mut q3);
        assert_eq!(h2, hex("00073a6d 6574686f 6407434f 4e4e4543 54000a3a 61757468 6f726974 790f6578 616d706c 652e636f 6d3a3434 33001370 726f7879 2d617574 686f7269 7a617469 6f6e0842 65617265 722070"));
        assert_eq!(q3, hex("00002700 3a6d6574 686f6407 434f4e4e 45435427 033a6175 74686f72 6974790f 6578616d 706c652e 636f6d3a 34343327 0c70726f 78792d61 7574686f 72697a61 74696f6e 08426561 72657220 70"));
        assert_eq!((h2.len(), q3.len()), (75, 77));
    }

    #[test]
    fn a_long_name_length_spans_the_three_bit_qpack_prefix() {
        let name = "x".repeat(40);
        let mut q3 = Vec::new();
        qpack_literal(&mut q3, &name, b"");
        assert_eq!(qpack_status(&q3), None, "not a status field");
        let mut h2 = Vec::new();
        hpack_literal(&mut h2, &name, b"");
        assert_eq!(hpack_status(&h2), None, "not a status field");
    }
}
