//! `Psiphon`: the arithmetic around the psiphon-tunnel-core console client — the tunnel shapes its config offers, a comment stripper for the config it accepts, and a zero-copy reader for the notices it writes. Nothing here spawns a process or opens a socket.

/// The local SOCKS listener the client falls back to when the config names none.
pub const DEFAULT_BIND: &str = "127.0.0.1:1821";

/// How long a first tunnel is given before the lane says the network answered nothing.
pub const READY_SECS: u64 = 180;

/// The executable names every release archive ships in its `pt` folder.
pub const BINARY_NAMES: [&str; 2] = ["psiphon-tunnel-core", "psiphon"];

/// The public server list the client fetches and verifies with the key below.
pub const SERVER_LIST_URL: &str =
    "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed";

/// The publisher's key for [`SERVER_LIST_URL`].
pub const SERVER_LIST_SIGNATURE_KEY: &str = concat!(
    "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH",
    "5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5",
    "OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot",
    "LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6",
    "/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G",
    "stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O",
    "geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8",
    "u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz",
    "31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal",
    "KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
);

/// The protocols a CDN edge carries: fronted meek over the CDN, including its QUIC transport.
pub const CDN_PROTOCOLS: [&str; 3] = [
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];

/// Every protocol except the in-proxy family, which a lane that is not an in-proxy relay never offers.
pub const NON_INPROXY_PROTOCOLS: [&str; 14] = [
    "SSH",
    "OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "QUIC-OSSH",
    "SHADOWSOCKS-OSSH",
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-QUIC-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];

/// The protocols that cross a TCP proxy: the same list without the QUIC shapes, because a SOCKS hop carries no datagram.
pub const CHAINED_PROTOCOLS: [&str; 11] = [
    "SSH",
    "OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "SHADOWSOCKS-OSSH",
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
];

/// The fronted shapes of [`CHAINED_PROTOCOLS`], for a CDN-only lane.
pub const CHAINED_CDN_PROTOCOLS: [&str; 2] =
    ["FRONTED-MEEK-CDN-OSSH", "FRONTED-MEEK-CDN-HTTP-OSSH"];

/// The countries `Shirokhorshid` rejects when a volunteer proxy is selected from one of them.
pub const CENSORED_PROXY_COUNTRIES: [&str; 6] = ["IR", "CN", "RU", "BY", "TM", "KP"];

/// The in-proxy shapes: a `WebRTC` first hop into a volunteer relay, then the tunnel protocol.
pub const INPROXY_PROTOCOLS: [&str; 11] = [
    "INPROXY-WEBRTC-SSH",
    "INPROXY-WEBRTC-OSSH",
    "INPROXY-WEBRTC-TLS-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH",
    "INPROXY-WEBRTC-QUIC-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH",
    "INPROXY-WEBRTC-SHADOWSOCKS-OSSH",
];

/// The direct shapes of [`CHAINED_PROTOCOLS`], including the fronted fallbacks the reference keeps when an upstream proxy carries the lane.
pub const CHAINED_DIRECT_PROTOCOLS: [&str; 11] = CHAINED_PROTOCOLS;

/// Which tunnel shapes the lane is allowed to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Auto,
    Cdn,
    Conduit,
    Direct,
}

impl Shape {
    /// Read a shape from config or an environment variable; an unknown word is `Auto`, as the reference's own switch treats it.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "cdn" | "fronted" => Self::Cdn,
            "conduit" | "inproxy" | "relay" => Self::Conduit,
            "direct" | "plain" => Self::Direct,
            _ => Self::Auto,
        }
    }

    /// The protocol names this shape offers when the client dials out directly.
    #[must_use]
    pub const fn protocols(self) -> &'static [&'static str] {
        match self {
            Self::Cdn => &CDN_PROTOCOLS,
            Self::Conduit => &INPROXY_PROTOCOLS,
            Self::Auto | Self::Direct => &NON_INPROXY_PROTOCOLS,
        }
    }

    /// The protocol names this shape offers when the client is itself carried by a TCP proxy.
    #[must_use]
    pub const fn chained(self) -> &'static [&'static str] {
        match self {
            Self::Cdn => &CHAINED_CDN_PROTOCOLS,
            Self::Conduit => &INPROXY_PROTOCOLS,
            Self::Direct => &CHAINED_DIRECT_PROTOCOLS,
            Self::Auto => &CHAINED_PROTOCOLS,
        }
    }

    /// A CDN or direct shape refuses tactics; `Auto` and `Conduit` keep them.
    #[must_use]
    pub const fn disables_tactics(self) -> bool {
        matches!(self, Self::Cdn | Self::Direct)
    }

    /// Whether this shape asks only for the in-proxy relay family.
    #[must_use]
    pub const fn is_conduit(self) -> bool {
        matches!(self, Self::Conduit)
    }
}

/// A two-letter egress region, upper-cased, or nothing when the text is not one.
#[must_use]
pub fn region(text: &str) -> Option<String> {
    let text = text.trim();
    (text.len() == 2 && text.bytes().all(|byte| byte.is_ascii_alphabetic()))
        .then(|| text.to_ascii_uppercase())
}

/// Remove `//` and `/* */` comments from a config, leaving strings untouched. The client accepts these comments and its own samples carry them.
///
/// Outside a string the scan jumps to the next quote or slash two eight-byte blocks at a
/// time, and inside one it jumps to the next quote or backslash; the run between two
/// specials is copied once. The byte loop only walks a tail shorter than two words.
pub fn strip_comments(text: &str, out: &mut String) {
    out.clear();
    out.reserve(text.len());
    let bytes = text.as_bytes();
    let mut at = 0usize;
    let mut copy = 0usize;
    let mut in_string = false;
    while at < bytes.len() {
        if in_string {
            let Some((offset, byte)) = next_quote_or_backslash(&bytes[at..]) else {
                break;
            };
            at += offset;
            if byte == b'\\' {
                at += 1;
                if at < bytes.len() {
                    at += 1;
                }
            } else {
                in_string = false;
                at += 1;
            }
            continue;
        }
        let Some((offset, byte)) = next_quote_or_slash(&bytes[at..]) else {
            break;
        };
        at += offset;
        if byte == b'"' {
            in_string = true;
            at += 1;
            continue;
        }
        if bytes.get(at + 1) == Some(&b'*') {
            out.push_str(&text[copy..at]);
            at += 2;
            let close = loop {
                let Some(star) = find_byte(&bytes[at..], b'*') else {
                    break bytes.len();
                };
                at += star;
                if bytes.get(at + 1) == Some(&b'/') {
                    break at + 2;
                }
                at += 1;
            };
            at = close;
            out.push(' ');
            copy = at;
        } else if bytes.get(at + 1) == Some(&b'/') {
            out.push_str(&text[copy..at]);
            at += 2;
            if let Some(newline) = find_byte(&bytes[at..], b'\n') {
                at += newline + 1;
            } else {
                at = bytes.len();
            }
            out.push('\n');
            copy = at;
        } else {
            at += 1;
        }
    }
    out.push_str(&text[copy..]);
}

/// One diagnostic notice, borrowed from the line it arrived on: the fields the lane acts on, and the message it logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice<'a> {
    pub kind: &'a str,
    pub port: Option<u16>,
    pub count: Option<u32>,
    pub message: Option<&'a str>,
    pub ip_address: Option<&'a str>,
}

impl Notice<'_> {
    /// Whether this notice is routine when no in-proxy relay is configured.
    #[must_use]
    pub fn expected_without_inproxy(&self) -> bool {
        self.message.is_some_and(|text| {
            text.contains("DSL fetch failed")
                || text.contains("no broker specs")
                || text.contains("tactics request aborted: no capable servers")
        })
    }
}

/// Read the one notice a line carries, without a DOM, a map or a buffer of its own. The client writes these as one JSON object per line and every field this lane uses is a string or an integer, so the reader walks the object once and borrows the fields where they landed.
#[must_use]
#[inline]
pub fn notice(line: &[u8]) -> Option<Notice<'_>> {
    let mut at = 0usize;
    space(line, &mut at);
    if !eat(line, &mut at, b'{') {
        return None;
    }
    let mut out = Notice {
        kind: "",
        port: None,
        count: None,
        message: None,
        ip_address: None,
    };
    space(line, &mut at);
    if eat(line, &mut at, b'}') {
        return None;
    }
    loop {
        let key = string(line, &mut at)?;
        space(line, &mut at);
        if !eat(line, &mut at, b':') {
            return None;
        }
        space(line, &mut at);
        match key {
            b"noticeType" => out.kind = string_text(line, &mut at)?,
            b"data" => data(line, &mut at, &mut out)?,
            _ => skip(line, &mut at, 0)?,
        }
        space(line, &mut at);
        match line.get(at) {
            Some(b',') => {
                at += 1;
                space(line, &mut at);
            }
            Some(b'}') => {
                at += 1;
                break;
            }
            _ => return None,
        }
    }
    space(line, &mut at);
    (at == line.len()).then_some(out)
}

/// The `noticeType` a line names, without walking the object behind it. The client writes
/// `noticeType` first, so a line whose kind the lane does not act on costs one string read
/// rather than a parse of its whole data payload.
#[must_use]
pub fn notice_kind(line: &[u8]) -> Option<&str> {
    let mut at = 0usize;
    space(line, &mut at);
    if !eat(line, &mut at, b'{') {
        return None;
    }
    space(line, &mut at);
    if eat(line, &mut at, b'}') {
        return None;
    }
    loop {
        let key = string(line, &mut at)?;
        space(line, &mut at);
        if !eat(line, &mut at, b':') {
            return None;
        }
        space(line, &mut at);
        if key == b"noticeType" {
            return string_text(line, &mut at);
        }
        skip(line, &mut at, 0)?;
        space(line, &mut at);
        match line.get(at) {
            Some(b',') => {
                at += 1;
                space(line, &mut at);
            }
            _ => return None,
        }
    }
}

#[inline]
fn data<'a>(line: &'a [u8], at: &mut usize, out: &mut Notice<'a>) -> Option<()> {
    if !eat(line, at, b'{') {
        skip(line, at, 0)?;
        return Some(());
    }
    space(line, at);
    if eat(line, at, b'}') {
        return Some(());
    }
    loop {
        let key = string(line, at)?;
        space(line, at);
        if !eat(line, at, b':') {
            return None;
        }
        space(line, at);
        match key {
            b"port" => out.port = number(line, at).and_then(|n| u16::try_from(n).ok()),
            b"count" => out.count = number(line, at).and_then(|n| u32::try_from(n).ok()),
            b"message" => out.message = string_text(line, at),
            b"ipAddress" => out.ip_address = string_text(line, at),
            _ => skip(line, at, 0)?,
        }
        space(line, at);
        match line.get(*at) {
            Some(b',') => {
                *at += 1;
                space(line, at);
            }
            Some(b'}') => {
                *at += 1;
                return Some(());
            }
            _ => return None,
        }
    }
}

#[inline]
fn space(bytes: &[u8], at: &mut usize) {
    while bytes
        .get(*at)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        *at += 1;
    }
}

#[inline]
fn eat(bytes: &[u8], at: &mut usize, wanted: u8) -> bool {
    if bytes.get(*at) == Some(&wanted) {
        *at += 1;
        true
    } else {
        false
    }
}

#[inline]
fn string<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    string_scan(bytes, at).map(|(field, _)| field)
}

#[inline]
fn string_text<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a str> {
    let (field, escaped) = string_scan(bytes, at)?;
    if escaped {
        return None;
    }
    std::str::from_utf8(field).ok()
}

/// The string's contents and whether a backslash stood anywhere in it, so a message that
/// needs no unescaping is known without a second walk over the bytes.
#[inline]
fn string_scan<'a>(bytes: &'a [u8], at: &mut usize) -> Option<(&'a [u8], bool)> {
    space(bytes, at);
    if !eat(bytes, at, b'"') {
        return None;
    }
    let start = *at;
    let mut escaped = false;
    loop {
        let (offset, byte) = next_quote_or_backslash(&bytes[*at..])?;
        *at += offset;
        if byte == b'"' {
            let end = *at;
            *at += 1;
            return Some((&bytes[start..end], escaped));
        }
        // A backslash escapes the byte after it, whatever that byte is.
        escaped = true;
        *at += 1;
        bytes.get(*at)?;
        *at += 1;
    }
}

/// The first of two bytes. AVX2 walks 128 bytes per turn when the CPU has it and NEON 32 as one
/// inlined block, then the same 64-, 32- and eight-byte scans finish the tail.
#[inline]
fn next_of(bytes: &[u8], first: u8, second: u8) -> Option<(usize, u8)> {
    #[cfg(target_arch = "x86_64")]
    if bytes.len() >= 32 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: the runtime feature test above proves AVX2 is available.
        return unsafe { next_of_avx2(bytes, first, second) };
    }
    #[cfg(target_arch = "x86_64")]
    if bytes.len() >= 16 {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        return unsafe { next_of_sse2(bytes, first, second) };
    }
    #[cfg(target_arch = "aarch64")]
    if bytes.len() >= 16 {
        return next_of_neon(bytes, first, second);
    }
    next_of_swar(bytes, first, second)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn next_of_avx2(bytes: &[u8], first: u8, second: u8) -> Option<(usize, u8)> {
    use core::arch::x86_64::{
        _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_or_si256,
        _mm256_set1_epi8,
    };
    let a = _mm256_set1_epi8(first.cast_signed());
    let b = _mm256_set1_epi8(second.cast_signed());
    let mut at = 0usize;
    while at + 128 <= bytes.len() {
        // SAFETY: `at + 128` is inside `bytes`, and every load is unaligned.
        let (low, high) = unsafe {
            let low0 = _mm256_loadu_si256(bytes.as_ptr().add(at).cast());
            let high0 = _mm256_loadu_si256(bytes.as_ptr().add(at + 32).cast());
            let low1 = _mm256_loadu_si256(bytes.as_ptr().add(at + 64).cast());
            let high1 = _mm256_loadu_si256(bytes.as_ptr().add(at + 96).cast());
            (
                u64::from(_mm256_movemask_epi8(_mm256_or_si256(
                    _mm256_cmpeq_epi8(low0, a),
                    _mm256_cmpeq_epi8(low0, b),
                )) as u32)
                    | (u64::from(_mm256_movemask_epi8(_mm256_or_si256(
                        _mm256_cmpeq_epi8(high0, a),
                        _mm256_cmpeq_epi8(high0, b),
                    )) as u32)
                        << 32),
                u64::from(_mm256_movemask_epi8(_mm256_or_si256(
                    _mm256_cmpeq_epi8(low1, a),
                    _mm256_cmpeq_epi8(low1, b),
                )) as u32)
                    | (u64::from(_mm256_movemask_epi8(_mm256_or_si256(
                        _mm256_cmpeq_epi8(high1, a),
                        _mm256_cmpeq_epi8(high1, b),
                    )) as u32)
                        << 32),
            )
        };
        if low != 0 {
            let found = at + low.trailing_zeros() as usize;
            return Some((found, bytes[found]));
        }
        if high != 0 {
            let found = at + 64 + high.trailing_zeros() as usize;
            return Some((found, bytes[found]));
        }
        at += 128;
    }
    while at + 64 <= bytes.len() {
        // SAFETY: `at + 64` is inside `bytes`, and both loads are unaligned.
        let mask = unsafe {
            let low = _mm256_loadu_si256(bytes.as_ptr().add(at).cast());
            let high = _mm256_loadu_si256(bytes.as_ptr().add(at + 32).cast());
            u64::from(_mm256_movemask_epi8(_mm256_or_si256(
                _mm256_cmpeq_epi8(low, a),
                _mm256_cmpeq_epi8(low, b),
            )) as u32)
                | (u64::from(_mm256_movemask_epi8(_mm256_or_si256(
                    _mm256_cmpeq_epi8(high, a),
                    _mm256_cmpeq_epi8(high, b),
                )) as u32)
                    << 32)
        };
        if mask != 0 {
            let found = at + mask.trailing_zeros() as usize;
            return Some((found, bytes[found]));
        }
        at += 64;
    }
    while at + 32 <= bytes.len() {
        // SAFETY: `at + 32` is inside `bytes`, and the load is unaligned.
        let marked = unsafe {
            let block = _mm256_loadu_si256(bytes.as_ptr().add(at).cast());
            _mm256_movemask_epi8(_mm256_or_si256(
                _mm256_cmpeq_epi8(block, a),
                _mm256_cmpeq_epi8(block, b),
            ))
        };
        if marked != 0 {
            let found = at + marked.trailing_zeros() as usize;
            return Some((found, bytes[found]));
        }
        at += 32;
    }
    next_of_swar(&bytes[at..], first, second).map(|(found, byte)| (at + found, byte))
}

/// The first of two bytes, two 16-byte blocks per turn. This is the x86-64 baseline path:
/// a field shorter than an AVX2 block, or a CPU without AVX2, still compares sixteen
/// bytes per instruction rather than falling back to eight-byte words.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn next_of_sse2(bytes: &[u8], first: u8, second: u8) -> Option<(usize, u8)> {
    use core::arch::x86_64::{
        _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8,
    };
    let a = unsafe { _mm_set1_epi8(first.cast_signed()) };
    let b = unsafe { _mm_set1_epi8(second.cast_signed()) };
    let mut at = 0usize;
    while at + 32 <= bytes.len() {
        // SAFETY: `at + 32` is inside `bytes`, and both loads are unaligned.
        let mask = unsafe {
            let low = _mm_loadu_si128(bytes.as_ptr().add(at).cast());
            let high = _mm_loadu_si128(bytes.as_ptr().add(at + 16).cast());
            u32::from(_mm_movemask_epi8(_mm_or_si128(
                _mm_cmpeq_epi8(low, a),
                _mm_cmpeq_epi8(low, b),
            )) as u16)
                | (u32::from(_mm_movemask_epi8(_mm_or_si128(
                    _mm_cmpeq_epi8(high, a),
                    _mm_cmpeq_epi8(high, b),
                )) as u16)
                    << 16)
        };
        if mask != 0 {
            let found = at + mask.trailing_zeros() as usize;
            return Some((found, bytes[found]));
        }
        at += 32;
    }
    if at + 16 <= bytes.len() {
        // SAFETY: `at + 16` is inside `bytes`, and the load is unaligned.
        let mask = unsafe {
            let block = _mm_loadu_si128(bytes.as_ptr().add(at).cast());
            _mm_movemask_epi8(_mm_or_si128(
                _mm_cmpeq_epi8(block, a),
                _mm_cmpeq_epi8(block, b),
            )) as u16
        };
        if mask != 0 {
            let found = at + mask.trailing_zeros() as usize;
            return Some((found, bytes[found]));
        }
        at += 16;
    }
    next_of_swar(&bytes[at..], first, second).map(|(found, byte)| (at + found, byte))
}

/// The first of two bytes, four eight-lane words per turn. NEON has no byte movemask, so a
/// half is moved to an integer register whole: a matching lane is a byte of ones, so the
/// first match is that word's trailing zeros over eight, and a word of zeroes is no match.
/// The compares and the find are one block of assembly with no target-feature boundary, so
/// this inlines into the field scan instead of costing a call and a returned struct per field.
#[cfg(target_arch = "aarch64")]
#[inline]
fn next_of_neon(bytes: &[u8], first: u8, second: u8) -> Option<(usize, u8)> {
    let cursor = bytes.as_ptr();
    let remaining = bytes.len();
    let mut off = 0usize;
    let mut found = usize::MAX;
    // SAFETY: a block loads only while 32 bytes of it are left, no register outlives the block, and NEON is in the aarch64 base.
    unsafe {
        core::arch::asm!(
            "dup     v4.16b, {first:w}",
            "dup     v5.16b, {second:w}",
            "2:",
            "cmp     {remaining}, #32",
            "b.lo    3f",
            "ldp     q0, q1, [{cursor}]",
            "cmeq    v2.16b, v0.16b, v4.16b",
            "cmeq    v3.16b, v0.16b, v5.16b",
            "orr     v2.16b, v2.16b, v3.16b",
            "cmeq    v3.16b, v1.16b, v4.16b",
            "cmeq    v1.16b, v1.16b, v5.16b",
            "orr     v3.16b, v3.16b, v1.16b",
            "fmov    x9, d2",
            "cbnz    x9, 4f",
            "ext     v2.16b, v2.16b, v2.16b, #8",
            "fmov    x9, d2",
            "cbnz    x9, 5f",
            "fmov    x9, d3",
            "cbnz    x9, 6f",
            "ext     v3.16b, v3.16b, v3.16b, #8",
            "fmov    x9, d3",
            "cbnz    x9, 7f",
            "add     {cursor}, {cursor}, #32",
            "sub     {remaining}, {remaining}, #32",
            "add     {off}, {off}, #32",
            "b       2b",
            "4:",
            "mov     x10, #0",
            "b       8f",
            "5:",
            "mov     x10, #8",
            "b       8f",
            "6:",
            "mov     x10, #16",
            "b       8f",
            "7:",
            "mov     x10, #24",
            "8:",
            "rbit    x9, x9",
            "clz     x9, x9",
            "lsr     x9, x9, #3",
            "add     x9, x9, x10",
            "add     {found}, {off}, x9",
            "3:",
            first = in(reg) u32::from(first),
            second = in(reg) u32::from(second),
            cursor = inout(reg) cursor => _,
            remaining = inout(reg) remaining => _,
            off = inout(reg) off,
            found = inout(reg) found,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("x9") _,
            out("x10") _,
        );
    }
    if found != usize::MAX {
        return Some((found, bytes[found]));
    }
    next_of_swar(&bytes[off..], first, second).map(|(found, byte)| (off + found, byte))
}

/// The first of two bytes, two eight-byte blocks at a time. Both lanes are marked with the
/// same zero-byte test the terminator scan uses, so a long run is walked sixteen bytes per
/// turn and the byte loop only finishes a tail shorter than two words.
#[inline]
fn next_of_swar(bytes: &[u8], first: u8, second: u8) -> Option<(usize, u8)> {
    const SPREAD: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let a = u64::from(first).wrapping_mul(SPREAD);
    let b = u64::from(second).wrapping_mul(SPREAD);
    let mark = |word: u64| {
        let x = word ^ a;
        let y = word ^ b;
        (x.wrapping_sub(SPREAD) & !x & HIGH) | (y.wrapping_sub(SPREAD) & !y & HIGH)
    };
    let mut at = 0usize;
    while at + 16 <= bytes.len() {
        let low = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("one eight-byte block"));
        let high = u64::from_le_bytes(
            bytes[at + 8..at + 16]
                .try_into()
                .expect("one eight-byte block"),
        );
        let low_mark = mark(low);
        if low_mark != 0 {
            let found = at + low_mark.trailing_zeros() as usize / 8;
            return Some((found, bytes[found]));
        }
        let high_mark = mark(high);
        if high_mark != 0 {
            let found = at + 8 + high_mark.trailing_zeros() as usize / 8;
            return Some((found, bytes[found]));
        }
        at += 16;
    }
    while at + 8 <= bytes.len() {
        let word = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("one eight-byte block"));
        let marked = mark(word);
        if marked != 0 {
            let found = at + marked.trailing_zeros() as usize / 8;
            return Some((found, bytes[found]));
        }
        at += 8;
    }
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == first || byte == second {
            return Some((at, byte));
        }
        at += 1;
    }
    None
}

#[inline]
fn next_quote_or_backslash(bytes: &[u8]) -> Option<(usize, u8)> {
    next_of(bytes, b'"', b'\\')
}

#[inline]
fn next_quote_or_slash(bytes: &[u8]) -> Option<(usize, u8)> {
    next_of(bytes, b'"', b'/')
}

/// The first `wanted` byte. AVX2 walks 128 bytes per turn when the CPU has it and aarch64
/// runs the two-byte scan with the same needle in both lanes; the narrower blocks and the
/// SWAR tail keep the last run on the same eight-byte test, so every path returns one offset.
#[must_use]
pub fn find_byte(bytes: &[u8], wanted: u8) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    if bytes.len() >= 32 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: the runtime feature test above proves AVX2 is available.
        return unsafe { find_byte_avx2(bytes, wanted) };
    }
    #[cfg(target_arch = "x86_64")]
    if bytes.len() >= 16 {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        return unsafe { find_byte_sse2(bytes, wanted) };
    }
    #[cfg(target_arch = "aarch64")]
    if bytes.len() >= 16 {
        return next_of_neon(bytes, wanted, wanted).map(|(found, _)| found);
    }
    find_byte_swar(bytes, wanted)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn find_byte_avx2(bytes: &[u8], wanted: u8) -> Option<usize> {
    use core::arch::x86_64::{
        _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_set1_epi8,
    };
    let needle = _mm256_set1_epi8(wanted.cast_signed());
    let mut at = 0usize;
    while at + 128 <= bytes.len() {
        // SAFETY: `at + 128` is inside `bytes`, and every load is unaligned.
        let (low, high) = unsafe {
            let low0 = _mm256_loadu_si256(bytes.as_ptr().add(at).cast());
            let high0 = _mm256_loadu_si256(bytes.as_ptr().add(at + 32).cast());
            let low1 = _mm256_loadu_si256(bytes.as_ptr().add(at + 64).cast());
            let high1 = _mm256_loadu_si256(bytes.as_ptr().add(at + 96).cast());
            (
                u64::from(_mm256_movemask_epi8(_mm256_cmpeq_epi8(low0, needle)) as u32)
                    | (u64::from(_mm256_movemask_epi8(_mm256_cmpeq_epi8(high0, needle)) as u32)
                        << 32),
                u64::from(_mm256_movemask_epi8(_mm256_cmpeq_epi8(low1, needle)) as u32)
                    | (u64::from(_mm256_movemask_epi8(_mm256_cmpeq_epi8(high1, needle)) as u32)
                        << 32),
            )
        };
        if low != 0 {
            return Some(at + low.trailing_zeros() as usize);
        }
        if high != 0 {
            return Some(at + 64 + high.trailing_zeros() as usize);
        }
        at += 128;
    }
    while at + 64 <= bytes.len() {
        // SAFETY: `at + 64` is inside `bytes`, and both loads are unaligned.
        let mask = unsafe {
            let low = _mm256_loadu_si256(bytes.as_ptr().add(at).cast());
            let high = _mm256_loadu_si256(bytes.as_ptr().add(at + 32).cast());
            u64::from(_mm256_movemask_epi8(_mm256_cmpeq_epi8(low, needle)) as u32)
                | (u64::from(_mm256_movemask_epi8(_mm256_cmpeq_epi8(high, needle)) as u32) << 32)
        };
        if mask != 0 {
            return Some(at + mask.trailing_zeros() as usize);
        }
        at += 64;
    }
    while at + 32 <= bytes.len() {
        // SAFETY: `at + 32` is inside `bytes`, and the load is unaligned.
        let marked = unsafe {
            let block = _mm256_loadu_si256(bytes.as_ptr().add(at).cast());
            _mm256_movemask_epi8(_mm256_cmpeq_epi8(block, needle))
        };
        if marked != 0 {
            return Some(at + marked.trailing_zeros() as usize);
        }
        at += 32;
    }
    find_byte_swar(&bytes[at..], wanted).map(|found| at + found)
}

/// The first `wanted` byte, two 16-byte blocks per turn. It is the baseline path for a
/// short line, and the fallback where AVX2 is not available.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn find_byte_sse2(bytes: &[u8], wanted: u8) -> Option<usize> {
    use core::arch::x86_64::{_mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi8};
    let needle = unsafe { _mm_set1_epi8(wanted.cast_signed()) };
    let mut at = 0usize;
    while at + 32 <= bytes.len() {
        // SAFETY: `at + 32` is inside `bytes`, and both loads are unaligned.
        let mask = unsafe {
            let low = _mm_loadu_si128(bytes.as_ptr().add(at).cast());
            let high = _mm_loadu_si128(bytes.as_ptr().add(at + 16).cast());
            u32::from(_mm_movemask_epi8(_mm_cmpeq_epi8(low, needle)) as u16)
                | (u32::from(_mm_movemask_epi8(_mm_cmpeq_epi8(high, needle)) as u16) << 16)
        };
        if mask != 0 {
            return Some(at + mask.trailing_zeros() as usize);
        }
        at += 32;
    }
    if at + 16 <= bytes.len() {
        // SAFETY: `at + 16` is inside `bytes`, and the load is unaligned.
        let mask = unsafe {
            let block = _mm_loadu_si128(bytes.as_ptr().add(at).cast());
            _mm_movemask_epi8(_mm_cmpeq_epi8(block, needle)) as u16
        };
        if mask != 0 {
            return Some(at + mask.trailing_zeros() as usize);
        }
        at += 16;
    }
    find_byte_swar(&bytes[at..], wanted).map(|found| at + found)
}

/// The first `wanted` byte, two eight-byte blocks at a time. One lane is enough here, so this
/// half-vector tail of the AVX2 scan and of `next_of` costs half the marks of a two-byte one.
fn find_byte_swar(bytes: &[u8], wanted: u8) -> Option<usize> {
    const SPREAD: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let needle = u64::from(wanted).wrapping_mul(SPREAD);
    let mark = |word: u64| {
        let x = word ^ needle;
        x.wrapping_sub(SPREAD) & !x & HIGH
    };
    let mut at = 0usize;
    while at + 16 <= bytes.len() {
        let low = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("one eight-byte block"));
        let low_mark = mark(low);
        if low_mark != 0 {
            return Some(at + low_mark.trailing_zeros() as usize / 8);
        }
        let high = u64::from_le_bytes(
            bytes[at + 8..at + 16]
                .try_into()
                .expect("one eight-byte block"),
        );
        let high_mark = mark(high);
        if high_mark != 0 {
            return Some(at + 8 + high_mark.trailing_zeros() as usize / 8);
        }
        at += 16;
    }
    while at + 8 <= bytes.len() {
        let word = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("one eight-byte block"));
        let marked = mark(word);
        if marked != 0 {
            return Some(at + marked.trailing_zeros() as usize / 8);
        }
        at += 8;
    }
    while at < bytes.len() {
        if bytes[at] == wanted {
            return Some(at);
        }
        at += 1;
    }
    None
}

#[inline]
fn number(bytes: &[u8], at: &mut usize) -> Option<u64> {
    space(bytes, at);
    let start = *at;
    let mut value = 0u64;
    while let Some(byte) = bytes.get(*at) {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(*byte - b'0'))?;
        *at += 1;
    }
    (*at > start).then_some(value)
}

fn skip(bytes: &[u8], at: &mut usize, depth: usize) -> Option<()> {
    if depth > 32 {
        return None;
    }
    space(bytes, at);
    match bytes.get(*at)? {
        b'"' => string(bytes, at).map(|_| ()),
        b'{' => {
            *at += 1;
            space(bytes, at);
            if eat(bytes, at, b'}') {
                return Some(());
            }
            loop {
                string(bytes, at)?;
                space(bytes, at);
                if !eat(bytes, at, b':') {
                    return None;
                }
                skip(bytes, at, depth + 1)?;
                space(bytes, at);
                match bytes.get(*at) {
                    Some(b',') => {
                        *at += 1;
                        space(bytes, at);
                    }
                    Some(b'}') => {
                        *at += 1;
                        return Some(());
                    }
                    _ => return None,
                }
            }
        }
        b'[' => {
            *at += 1;
            space(bytes, at);
            if eat(bytes, at, b']') {
                return Some(());
            }
            loop {
                skip(bytes, at, depth + 1)?;
                space(bytes, at);
                match bytes.get(*at) {
                    Some(b',') => {
                        *at += 1;
                    }
                    Some(b']') => {
                        *at += 1;
                        return Some(());
                    }
                    _ => return None,
                }
            }
        }
        b't' if bytes
            .get(*at..)
            .is_some_and(|rest| rest.starts_with(b"true")) =>
        {
            *at += 4;
            Some(())
        }
        b'f' if bytes
            .get(*at..)
            .is_some_and(|rest| rest.starts_with(b"false")) =>
        {
            *at += 5;
            Some(())
        }
        b'n' if bytes
            .get(*at..)
            .is_some_and(|rest| rest.starts_with(b"null")) =>
        {
            *at += 4;
            Some(())
        }
        b'-' | b'0'..=b'9' => {
            *at += 1;
            while bytes
                .get(*at)
                .is_some_and(|byte| matches!(*byte, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                *at += 1;
            }
            Some(())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCKS: &[u8] = br#"{"noticeType":"ListeningSocksProxyPort","data":{"port":1234}}"#;
    const TUNNELS: &[u8] = br#"{"noticeType":"Tunnels","data":{"count":2,"active":true}}"#;

    fn parsed(line: &[u8]) -> Notice<'_> {
        notice(line).expect("a notice")
    }

    #[test]
    fn the_ports_and_the_tunnel_count_are_read_where_they_landed() {
        let socks = parsed(SOCKS);
        assert_eq!(socks.kind, "ListeningSocksProxyPort");
        assert_eq!(socks.port, Some(1234));
        assert_eq!(socks.count, None);

        let tunnels = parsed(TUNNELS);
        assert_eq!(tunnels.kind, "Tunnels");
        assert_eq!(tunnels.count, Some(2));
        assert_eq!(tunnels.port, None);
    }

    #[test]
    fn a_message_and_an_address_are_borrowed_from_the_line() {
        let line = br#"{"noticeType":"ConnectedServer","data":{"ipAddress":"192.0.2.7","message":"connected","nested":{"a":[1,2,{"b":null}]}}}"#;
        let notice = parsed(line);
        assert_eq!(notice.ip_address, Some("192.0.2.7"));
        assert_eq!(notice.message, Some("connected"));
        assert!(!notice.expected_without_inproxy());
    }

    #[test]
    fn a_notice_scan_takes_no_buffer_of_its_own() {
        let (read, counts) = crate::alloc_count::measure(|| parsed(SOCKS));
        assert_eq!(read.kind, "ListeningSocksProxyPort");
        assert_eq!(counts.allocs, 0, "the fields point into the caller's line");
    }

    #[test]
    fn the_word_scan_is_the_byte_scan() {
        fn byte_scan(bytes: &[u8]) -> Option<(usize, u8)> {
            bytes
                .iter()
                .position(|byte| *byte == b'"' || *byte == b'\\')
                .map(|at| (at, bytes[at]))
        }
        let alphabet = *b"a\"\\\n";
        for len in 0..=5 {
            let mut cases = 1usize;
            for _ in 0..len {
                cases *= alphabet.len();
            }
            for mut case in 0..cases {
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len {
                    bytes.push(alphabet[case % alphabet.len()]);
                    case /= alphabet.len();
                }
                assert_eq!(
                    next_quote_or_backslash(&bytes),
                    byte_scan(&bytes),
                    "{:?}",
                    String::from_utf8_lossy(&bytes)
                );
            }
        }
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut bytes = Vec::with_capacity(4096);
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(b"abc\"\\\n"[state as usize % 6]);
            if state.is_multiple_of(97) {
                assert_eq!(next_quote_or_backslash(&bytes), byte_scan(&bytes));
            }
        }
        assert_eq!(next_quote_or_backslash(&bytes), byte_scan(&bytes));
    }

    #[test]
    fn the_wide_scan_is_the_byte_scan() {
        fn byte_scan(bytes: &[u8]) -> Option<(usize, u8)> {
            bytes
                .iter()
                .position(|byte| *byte == b'"' || *byte == b'\\')
                .map(|at| (at, bytes[at]))
        }
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for pad in 0..40 {
            for len in 0..=160 {
                let mut bytes = vec![b'a'; pad];
                for _ in 0..len {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    bytes.push(match state % 29 {
                        0 => b'"',
                        1 => b'\\',
                        _ => b'x',
                    });
                }
                let tail = &bytes[pad..];
                assert_eq!(
                    next_quote_or_backslash(tail),
                    byte_scan(tail),
                    "pad {pad}, len {len}"
                );
            }
        }
    }

    #[test]
    fn the_wide_scan_crosses_a_hundred_and_twenty_eight_bytes() {
        // Every quarter of three turns, so a loop that stopped after one block or mis-ordered the halves fails.
        let mut offsets = Vec::new();
        for turn in 0..3 {
            for quarter in 0..4 {
                for lane in [0, 1, 7, 15, 16, 23, 31] {
                    offsets.push(turn * 128 + quarter * 32 + lane);
                }
            }
        }
        offsets.extend([383, 392, 399]);
        let mut bytes = vec![b'a'; 400];
        for at in offsets {
            bytes.fill(b'a');
            let byte = if at % 2 == 0 { b'"' } else { b'\\' };
            bytes[at] = byte;
            assert_eq!(
                next_quote_or_backslash(&bytes),
                Some((at, byte)),
                "two bytes at {at}"
            );
            assert_eq!(find_byte(&bytes, byte), Some(at), "one byte at {at}");
        }
    }

    #[test]
    fn the_single_byte_scan_is_the_byte_scan() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for pad in 0..17 {
            for len in 0..=160 {
                let mut bytes = vec![b'a'; pad];
                for _ in 0..len {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    bytes.push(if state.is_multiple_of(17) {
                        b'\n'
                    } else {
                        b'b'
                    });
                }
                let tail = &bytes[pad..];
                assert_eq!(
                    find_byte(tail, b'\n'),
                    tail.iter().position(|byte| *byte == b'\n'),
                    "pad {pad}, len {len}"
                );
            }
        }
    }

    #[test]
    fn a_notice_is_read_from_the_line_with_its_newline() {
        for line in [
            br#"{"noticeType":"Tunnels","data":{"count":1}}"#.as_slice(),
            b"{\"noticeType\":\"Tunnels\",\"data\":{\"count\":1}}\n",
            b"  {\"noticeType\":\"Tunnels\",\"data\":{\"count\":1}}\r\n",
        ] {
            assert_eq!(notice(line).and_then(|notice| notice.count), Some(1));
        }
        assert!(notice(b"{\"noticeType\":\"Tunnels\",\"data\":{\"count\":1}} x").is_none());
    }

    #[test]
    fn the_kind_is_read_before_the_data_is_parsed() {
        for line in [SOCKS, TUNNELS] {
            assert_eq!(
                notice_kind(line),
                notice(line).map(|notice| notice.kind),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        let kind_last =
            br#"{"data":{"message":"x","nested":[1,{"a":null}]},"noticeType":"Warning"}"#;
        assert_eq!(notice_kind(kind_last), Some("Warning"));
        assert_eq!(notice_kind(b"{}"), None);
        assert_eq!(notice_kind(b"[]"), None);
    }

    #[test]
    fn a_line_that_is_not_one_object_is_refused() {
        for line in [
            &b""[..],
            b" []",
            b"{\"noticeType\":\"Tunnels\",\"data\":{\"count\":1}} trailing",
            b"{\"noticeType\":\"Tunnels\",\"data\":{\"count\":1}",
            b"{\"noticeType\":}",
        ] {
            assert!(
                notice(line).is_none(),
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn an_escape_leaves_the_message_out_instead_of_sending_half_of_it() {
        let line = br#"{"noticeType":"Warning","data":{"message":"a \"quoted\" word"}}"#;
        let notice = parsed(line);
        assert_eq!(notice.kind, "Warning");
        assert_eq!(notice.message, None);
    }

    fn strip_comments_byte(text: &str, out: &mut String) {
        out.clear();
        out.reserve(text.len());
        let bytes = text.as_bytes();
        let mut at = 0usize;
        let mut copy = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        while at < bytes.len() {
            let byte = bytes[at];
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                at += 1;
                continue;
            }
            match byte {
                b'"' => {
                    in_string = true;
                    at += 1;
                }
                b'/' if bytes.get(at + 1) == Some(&b'*') => {
                    out.push_str(&text[copy..at]);
                    at += 2;
                    while at + 1 < bytes.len() && !(bytes[at] == b'*' && bytes[at + 1] == b'/') {
                        at += 1;
                    }
                    at = (at + 2).min(bytes.len());
                    out.push(' ');
                    copy = at;
                }
                b'/' if bytes.get(at + 1) == Some(&b'/') => {
                    out.push_str(&text[copy..at]);
                    at += 2;
                    while at < bytes.len() && bytes[at] != b'\n' {
                        at += 1;
                    }
                    if at < bytes.len() {
                        at += 1;
                    }
                    out.push('\n');
                    copy = at;
                }
                _ => at += 1,
            }
        }
        out.push_str(&text[copy..]);
    }

    #[test]
    fn the_word_strip_is_the_byte_strip() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut text = String::new();
        let mut word = String::new();
        let mut byte = String::new();
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            text.clear();
            let len = (state % 128) as usize;
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let byte = match state % 12 {
                    0 => b'"',
                    1 => b'/',
                    2 => b'*',
                    3 => b'\\',
                    4 => b'\n',
                    5 => b'\r',
                    6 => b'a',
                    7 => b' ',
                    _ => (state >> 8) as u8,
                };
                text.push(char::from(byte));
            }
            strip_comments(&text, &mut word);
            strip_comments_byte(&text, &mut byte);
            assert_eq!(word, byte, "{text:?}");
        }
    }

    #[test]
    fn comments_do_not_reach_a_string_and_both_forms_leave_one_space() {
        let text = "{\"a\":\"http://x/*y*/\",/* gone */\"b\":1,// gone\n\"c\":2}";
        let mut out = String::new();
        strip_comments(text, &mut out);
        assert_eq!(out, "{\"a\":\"http://x/*y*/\", \"b\":1,\n\"c\":2}");
    }

    #[test]
    fn an_unterminated_comment_ends_the_document() {
        let mut out = String::new();
        strip_comments("{/* no close", &mut out);
        assert_eq!(out, "{ ");
    }

    #[test]
    fn a_shape_names_the_set_the_reference_offers() {
        assert_eq!(Shape::parse("CDN"), Shape::Cdn);
        assert_eq!(Shape::parse("conduit"), Shape::Conduit);
        assert_eq!(Shape::parse("direct"), Shape::Direct);
        assert_eq!(Shape::parse("something"), Shape::Auto);
        assert!(Shape::Cdn.protocols().contains(&"FRONTED-MEEK-CDN-OSSH"));
        assert!(!Shape::Cdn
            .chained()
            .iter()
            .any(|name| name.contains("QUIC")));
        assert!(Shape::Direct
            .chained()
            .iter()
            .any(|name| name.starts_with("FRONTED")));
        assert!(!Shape::Direct
            .chained()
            .iter()
            .any(|name| name.contains("QUIC")));
        assert!(!Shape::Auto
            .chained()
            .iter()
            .any(|name| name.starts_with("INPROXY")));
        assert!(Shape::Auto.chained().len() < Shape::Auto.protocols().len());
        assert!(Shape::Cdn.disables_tactics());
        assert!(!Shape::Auto.disables_tactics());
        assert!(!Shape::Conduit.disables_tactics());
        assert!(Shape::Conduit.is_conduit());
        assert!(Shape::Conduit
            .protocols()
            .iter()
            .all(|name| name.starts_with("INPROXY-WEBRTC-")));
        assert_eq!(Shape::Conduit.protocols(), Shape::Conduit.chained());
    }

    #[test]
    fn only_a_two_letter_region_is_kept() {
        assert_eq!(region("de").as_deref(), Some("DE"));
        assert_eq!(region(" germany ").as_deref(), None);
        assert_eq!(region("d1").as_deref(), None);
        assert_eq!(region("").as_deref(), None);
    }
}
