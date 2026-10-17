use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    Ws,
    Xhttp,
    Grpc,
    Quic,
    HttpUpgrade,
    Kcp,
    Http,
    Hysteria,
    Masque,
    Xdrive,
    Other,
}

impl TransportKind {
    pub const ALL: [Self; 12] = [
        Self::Tcp,
        Self::Ws,
        Self::Xhttp,
        Self::Grpc,
        Self::Quic,
        Self::HttpUpgrade,
        Self::Kcp,
        Self::Http,
        Self::Hysteria,
        Self::Masque,
        Self::Xdrive,
        Self::Other,
    ];
}

impl TransportKind {
    #[must_use]
    pub fn from_link(t: &str) -> Self {
        match t {
            "" | "tcp" | "raw" => Self::Tcp,
            "ws" | "websocket" => Self::Ws,
            "xhttp" | "splithttp" => Self::Xhttp,
            "grpc" => Self::Grpc,
            "quic" => Self::Quic,
            "httpupgrade" => Self::HttpUpgrade,
            "kcp" | "mkcp" => Self::Kcp,
            "http" | "h2" | "h3" => Self::Http,
            "hysteria" => Self::Hysteria,
            "masque" => Self::Masque,
            "xdrive" => Self::Xdrive,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub const fn is_dialled(self) -> bool {
        matches!(
            self,
            Self::Tcp
                | Self::Ws
                | Self::Xhttp
                | Self::Grpc
                | Self::Quic
                | Self::HttpUpgrade
                | Self::Kcp
                | Self::Hysteria
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Tls,
    Reality,
    None,
    NoneToPublic,
    Other,
}

impl Security {
    #[must_use]
    pub fn from_link(s: &str, host: &str) -> Self {
        match s {
            "tls" => Self::Tls,
            "reality" => Self::Reality,
            "none" | "" => {
                if is_public_host(host) {
                    Self::NoneToPublic
                } else {
                    Self::None
                }
            }
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyData {
    pub path: String,
    pub budget: u32,
}

impl EarlyData {
    #[must_use]
    pub fn split(path: &str) -> Self {
        let untouched = || Self {
            path: path.to_owned(),
            budget: 0,
        };
        let (head, fragment) = path
            .split_once('#')
            .map_or((path, None), |(h, f)| (h, Some(f)));
        let Some((base, query)) = head.split_once('?') else {
            return untouched();
        };
        // The first `ed=` decides and a path without one is copied whole, so the string below is built once and only when the rewrite fires.
        let mut first = None;
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("ed=") {
                first = Some(value);
                break;
            }
        }
        let Some(first) = first.filter(|value| !value.is_empty()) else {
            return untouched();
        };
        let mut out = String::with_capacity(path.len());
        out.push_str(base);
        let mut sep = '?';
        for pair in query.split('&') {
            if pair.is_empty() || pair.starts_with("ed=") {
                continue;
            }
            out.push(sep);
            out.push_str(pair);
            sep = '&';
        }
        if let Some(fragment) = fragment {
            out.push('#');
            out.push_str(fragment);
        }
        Self {
            path: out,
            budget: atoi(first) as u32,
        }
    }
}

fn atoi(text: &str) -> i64 {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() {
        return 0;
    }
    let mut value: i64 = 0;
    for byte in digits.bytes() {
        if !byte.is_ascii_digit() {
            return 0;
        }
        let Some(next) = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(i64::from(byte - b'0')))
        else {
            return if negative { i64::MIN } else { i64::MAX };
        };
        value = next;
    }
    if negative {
        -value
    } else {
        value
    }
}

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const fn digit_table(url_only: bool) -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut c = b'A';
    while c <= b'Z' {
        table[c as usize] = c - b'A';
        c += 1;
    }
    c = b'a';
    while c <= b'z' {
        table[c as usize] = c - b'a' + 26;
        c += 1;
    }
    c = b'0';
    while c <= b'9' {
        table[c as usize] = c - b'0' + 52;
        c += 1;
    }
    table[b'-' as usize] = 62;
    table[b'_' as usize] = 63;
    if !url_only {
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
    }
    table
}

const DIGIT_TABLE: [u8; 256] = digit_table(false);

/// The same table with the standard alphabet's two characters left invalid, for a peer that must be refused where `RawURLEncoding` refuses.
const URL_DIGIT_TABLE: [u8; 256] = digit_table(true);

/// One pass, four characters at a time: six bits per lookup fill a 24-bit window whose three low bytes are the three bytes they stand for.
fn decode_groups(bytes: &[u8], table: &[u8; 256]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if bytes.len() % 4 == 1 {
        return None;
    }
    let (full, rest) = bytes.split_at(bytes.len() / 4 * 4);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    for group in full.as_chunks::<4>().0 {
        // Four independent lookups fill disjoint six-bit fields, so the word is a sum of fixed shifts rather than a serial shift-and-or chain: the four loads issue at once and the shift tree is not on a loop-carried dependency. One combined mask sees every invalid byte at once — a valid digit is under 64, so it leaves bits 6 and 7 clear, and only the 255 sentinel sets them.
        let t0 = u32::from(table[usize::from(group[0])]);
        let t1 = u32::from(table[usize::from(group[1])]);
        let t2 = u32::from(table[usize::from(group[2])]);
        let t3 = u32::from(table[usize::from(group[3])]);
        if (t0 | t1 | t2 | t3) & 0xc0 != 0 {
            return None;
        }
        let word = (t0 << 18) | (t1 << 12) | (t2 << 6) | t3;
        out.extend_from_slice(&word.to_be_bytes()[1..]);
    }
    if !rest.is_empty() {
        let mut word = 0u32;
        for &byte in rest {
            let digit = table[usize::from(byte)];
            if digit == 255 {
                return None;
            }
            word = (word << 6) | u32::from(digit);
        }
        word <<= 6 * (4 - rest.len());
        let tail = word.to_be_bytes();
        out.extend_from_slice(&tail[1..rest.len()]);
    }
    Some(out)
}

pub fn early_encode_into(out: &mut String, data: &[u8]) {
    out.reserve(data.len().div_ceil(3) * 4);
    // Only whole groups go through the block, so the last one to three bytes are the only ones the byte path sees.
    let wide = if data.is_empty() {
        0
    } else {
        (data.len() - 1) / 3 * 3
    };
    // Sixty-four groups land in the block first, so the capacity check and the one validation are paid per 256 characters instead of per character.
    let mut block = [0u8; 256];
    for part in data[..wide].chunks(192) {
        let filled = part.len() / 3 * 4;
        for (slot, [a, b, c]) in block[..filled]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(part.as_chunks::<3>().0)
        {
            let word = u32::from_be_bytes([0, *a, *b, *c]);
            slot.copy_from_slice(&[
                URL_ALPHABET[(word >> 18 & 63) as usize],
                URL_ALPHABET[(word >> 12 & 63) as usize],
                URL_ALPHABET[(word >> 6 & 63) as usize],
                URL_ALPHABET[(word & 63) as usize],
            ]);
        }
        if let Ok(text) = std::str::from_utf8(&block[..filled]) {
            out.push_str(text);
        }
    }
    let rest = &data[wide..];
    if rest.is_empty() {
        return;
    }
    let mut word = 0u32;
    for &byte in rest {
        word = (word << 8) | u32::from(byte);
    }
    word <<= 8 * (3 - rest.len());
    let quad = [
        URL_ALPHABET[(word >> 18 & 63) as usize],
        URL_ALPHABET[(word >> 12 & 63) as usize],
        URL_ALPHABET[(word >> 6 & 63) as usize],
        URL_ALPHABET[(word & 63) as usize],
    ];
    let keep = rest.len() + 1;
    block[..keep].copy_from_slice(&quad[..keep]);
    if let Ok(text) = std::str::from_utf8(&block[..keep]) {
        out.push_str(text);
    }
}

pub fn early_decode(text: &str) -> Option<Vec<u8>> {
    decode_groups(text.trim().trim_end_matches('=').as_bytes(), &DIGIT_TABLE)
}

/// The URL form with no slack: `-` and `_` only, no padding, no surrounding whitespace, and a lone trailing character refused rather than dropped.
pub fn url_decode(text: &str) -> Option<Vec<u8>> {
    decode_groups(text.as_bytes(), &URL_DIGIT_TABLE)
}

/// The host's ASCII suffix, ignoring case, without a lowercase copy of the host.
fn ends_ignore_ascii(h: &str, suffix: &str) -> bool {
    let tail = h.as_bytes().get(h.len().wrapping_sub(suffix.len())..);
    tail.is_some_and(|bytes| bytes.eq_ignore_ascii_case(suffix.as_bytes()))
}

fn is_public_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_multicast());
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return !(v6.is_loopback() || v6.is_multicast());
    }
    let h = host.trim_end_matches('.');
    if ["example.com", "example.org", "example.net"]
        .iter()
        .any(|name| h.eq_ignore_ascii_case(name))
    {
        return false;
    }
    !h.eq_ignore_ascii_case("test")
        && ![".test", ".example", ".invalid", ".localhost"]
            .iter()
            .any(|suffix| ends_ignore_ascii(h, suffix))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    Implemented { method: &'static str },
    Planned { reason: &'static str },
    UnsafeRequiresOptIn { reason: &'static str },
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implemented { method } => write!(f, "implemented ({method})"),
            Self::Planned { reason } => write!(f, "planned: {reason}"),
            Self::UnsafeRequiresOptIn { reason } => write!(f, "unsafe opt-in required: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_none_is_not_public() {
        assert_eq!(Security::from_link("none", "127.0.0.1"), Security::None);
        assert_eq!(Security::from_link("", "localhost"), Security::None);
        assert_eq!(
            Security::from_link("none", "192.0.2.1"),
            Security::NoneToPublic
        );
    }

    #[test]
    fn public_host_verdict_costs_no_allocation() {
        // The guard used to lowercase the whole host before matching a suffix.
        for (host, want) in [
            ("some-really-long-upstream-hostname.example.org", true),
            ("UPPER.Case.TEST", false),
            ("trailing.dots...", true),
            ("xn--e1afmkfd.xn--p1ai", true),
            ("a€.test", false),
            ("test", false),
            ("198.51.100.3", true),
            ("::1", false),
            ("EXAMPLE.COM", false),
            ("example.net.", false),
            ("notexample.com", true),
            ("a.localhost", false),
            ("LOCALHOST", false),
            ("192.0.2.1", true),
            ("10.10.10.10", false),
            ("fe80::1", true),
            ("ff02::1", false),
        ] {
            let (verdict, counts) = crate::alloc_count::measure(|| is_public_host(host));
            assert_eq!(verdict, want, "{host}");
            assert_eq!(
                counts.allocs, 0,
                "matching a host name costs no heap buffer, counted {counts:?}"
            );
        }
        // 224/4 has no TEST-NET form, so the v4 multicast group is built, not written.
        let multicast = std::net::Ipv4Addr::new(224, 0, 0, 1).to_string();
        let (verdict, counts) = crate::alloc_count::measure(|| is_public_host(&multicast));
        assert!(!verdict, "a multicast group is not a public host");
        assert_eq!(
            counts.allocs, 0,
            "matching a host name costs no heap buffer, counted {counts:?}"
        );
    }

    #[test]
    fn raw_link_is_tcp() {
        assert_eq!(TransportKind::from_link("raw"), TransportKind::Tcp);
        assert_eq!(TransportKind::from_link("tcp"), TransportKind::Tcp);
        assert_eq!(TransportKind::from_link(""), TransportKind::Tcp);
        assert!(TransportKind::from_link("raw").is_dialled());
    }

    #[test]
    fn early_data_split_matches_go_arithmetic() {
        for (path, budget, want) in [
            ("/interop-ws", 0u32, "/interop-ws"),
            ("/interop-ws?a=1", 0, "/interop-ws?a=1"),
            ("/interop-ws?ed", 0, "/interop-ws?ed"),
            ("/interop-ws?ed=", 0, "/interop-ws?ed="),
            ("/interop-ws?ed=&ed=4", 0, "/interop-ws?ed=&ed=4"),
            ("/interop-ws?ed=2048", 2048, "/interop-ws"),
            ("/interop-ws?ed=2048&ed=9", 2048, "/interop-ws"),
            ("/interop-ws?ed=abc", 0, "/interop-ws"),
            ("/interop-ws?ed=2048x", 0, "/interop-ws"),
            ("/interop-ws?ed=+2048", 2048, "/interop-ws"),
            ("/interop-ws?ed=002048", 2048, "/interop-ws"),
            ("/p?ed=-1", 4_294_967_295, "/p"),
            ("/p?ed=4294967295", 4_294_967_295, "/p"),
            ("/p?ed=4294967296", 0, "/p"),
            ("/p?ed=99999999999999999999", u32::MAX, "/p"),
            ("/p?ed=-99999999999999999999", 0, "/p"),
            ("/p?ed=-9223372036854775808", 0, "/p"),
            ("/p?a=1&ed=4&b=2", 4, "/p?a=1&b=2"),
            ("/?ed=1", 1, "/"),
            ("/p?ed=4&", 4, "/p"),
            ("/p#tag?ed=4", 0, "/p#tag?ed=4"),
            ("/p?ed=4#tag", 4, "/p#tag"),
        ] {
            assert_eq!(
                EarlyData::split(path),
                EarlyData {
                    path: want.to_owned(),
                    budget,
                },
                "{path}"
            );
        }
    }

    #[test]
    fn atoi_reproduces_the_three_answers() {
        for (text, want) in [
            ("0", 0i64),
            ("2048", 2048),
            ("+2048", 2048),
            ("-0", 0),
            ("2048abc", 0),
            ("abc", 0),
            ("", 0),
            ("-", 0),
            ("+", 0),
            ("9223372036854775807", i64::MAX),
            ("9223372036854775808", i64::MAX),
            ("-9223372036854775808", i64::MIN),
            ("-9223372036854775809", i64::MIN),
        ] {
            assert_eq!(atoi(text), want, "{text}");
        }
    }

    #[test]
    fn early_data_base64url_matches_rfc_4648() {
        for (bytes, want) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg"),
            (&b"fo"[..], "Zm8"),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg"),
            (&b"fooba"[..], "Zm9vYmE"),
            (&b"foobar"[..], "Zm9vYmFy"),
            (&[0xff, 0xff, 0x00][..], "__8A"),
            (&[0xff, 0x00][..], "_wA"),
            (&[0xfb, 0xef, 0xbe][..], "----"),
            (&[0x00, 0x10, 0x83][..], "ABCD"),
        ] {
            let mut out = String::from("prefix:");
            early_encode_into(&mut out, bytes);
            assert_eq!(out, format!("prefix:{want}"), "{bytes:?}");
            assert_eq!(early_decode(want).as_deref(), Some(bytes), "{want}");
        }
    }

    /// The shape the encode had before the windowed load, kept so the sweep can name what the route did not change.
    fn byte_path(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let mut word = 0u32;
            for &byte in chunk {
                word = (word << 8) | u32::from(byte);
            }
            word <<= 8 * (3 - chunk.len());
            out.push(URL_ALPHABET[(word >> 18 & 0x3F) as usize] as char);
            out.push(URL_ALPHABET[(word >> 12 & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                out.push(URL_ALPHABET[(word >> 6 & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(URL_ALPHABET[(word & 0x3F) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn the_windowed_load_encodes_the_bytes_the_byte_path_encoded() {
        const HEAD: &str = "Sec-WebSocket-Protocol: ";
        for len in 0..=600usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
            let mut out = String::from(HEAD);
            early_encode_into(&mut out, &bytes);
            assert_eq!(&out[HEAD.len()..], byte_path(&bytes), "{len}: route");
        }
    }

    /// The probe behind the early-data encode row: one fixed payload encoded round after round into a room that already holds it, so the frame is the walk over the payload and no allocator is in it.
    #[test]
    fn the_early_data_line_costs_the_encode_and_nothing_else() {
        const LEN: usize = 2048;
        const ROUNDS: usize = 16;
        let data: Vec<u8> = (0..LEN).map(|i| (i as u8).wrapping_mul(61)).collect();
        let mut out = String::with_capacity(data.len() * 2);
        early_encode_into(&mut out, &data);
        let want = out.clone();
        let mut capacity = 0;
        let mut folded = 0usize;
        for round in 0..ROUNDS {
            out.clear();
            early_encode_into(std::hint::black_box(&mut out), std::hint::black_box(&data));
            folded += out.len();
            if round == 0 {
                capacity = out.capacity();
            }
            assert_eq!(
                out.capacity(),
                capacity,
                "round {round}: the encode stays in the room it was handed, so nothing reallocated"
            );
        }
        assert_eq!(out, want, "the probe encodes the bytes the vectors pin");
        assert_eq!(
            folded,
            ROUNDS * (data.len() * 4).div_ceil(3),
            "four per three, unpadded"
        );
    }

    #[test]
    fn early_data_base64url_round_trips_every_length() {
        for len in 0..=192usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
            let mut out = String::new();
            early_encode_into(&mut out, &bytes);
            assert!(!out.contains('='), "{len}: no padding");
            assert!(
                !out.contains('+') && !out.contains('/'),
                "{len}: url alphabet"
            );
            assert_eq!(
                out.len(),
                (len * 4).div_ceil(3),
                "{len}: four per three, less padding"
            );
            assert_eq!(early_decode(&out).as_deref(), Some(&bytes[..]), "{len}");
        }
        assert_eq!(
            early_decode("Zm9vYg==").as_deref(),
            Some(&b"foob"[..]),
            "a padded peer is still a peer"
        );
        assert_eq!(early_decode("--8").as_deref(), Some(&[0xfb, 0xef][..]));
        assert_eq!(early_decode("abcde"), None, "five is not a base64 length");
        assert_eq!(early_decode("ab*d"), None, "a digit base64 does not have");
        assert_eq!(early_decode(""), Some(Vec::new()));
    }

    /// The per-character ladder the placement decode had before it shared the group loop, kept so the sweep can name what the route did not change.
    fn serial_url_decode(s: &str) -> Option<Vec<u8>> {
        let mut bits: Vec<u8> = Vec::new();
        for &b in s.as_bytes() {
            let v = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => return None,
            };
            bits.push(v);
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= bits.len() {
            out.push((bits[i] << 2) | (bits[i + 1] >> 4));
            out.push(((bits[i + 1] & 0x0f) << 4) | (bits[i + 2] >> 2));
            out.push(((bits[i + 2] & 0x03) << 6) | bits[i + 3]);
            i += 4;
        }
        match bits.len() - i {
            2 => out.push((bits[i] << 2) | (bits[i + 1] >> 4)),
            3 => {
                out.push((bits[i] << 2) | (bits[i + 1] >> 4));
                out.push(((bits[i + 1] & 0x0f) << 4) | (bits[i + 2] >> 2));
            }
            _ => {}
        }
        Some(out)
    }

    #[test]
    fn url_decode_refuses_what_the_reference_refuses() {
        assert_eq!(url_decode("Zm9vYg"), Some(b"foob".to_vec()));
        assert_eq!(url_decode("--8"), Some(vec![0xfb, 0xef]));
        assert_eq!(url_decode(""), Some(Vec::new()));
        assert_eq!(
            url_decode("Zm9vYg=="),
            None,
            "raw encoding carries no padding"
        );
        assert_eq!(
            url_decode("ab+D"),
            None,
            "the standard alphabet is not the url one"
        );
        assert_eq!(url_decode("ab/D"), None, "nor is its separator");
        assert_eq!(
            url_decode(" Zm9vYg"),
            None,
            "and no whitespace stands in for a digit"
        );
        assert_eq!(url_decode("abcde"), None, "five is not a base64 length");
    }

    #[test]
    fn the_shared_loop_decodes_every_prefix_the_serial_ladder_decoded() {
        for len in 0..=200usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
            let mut text = String::new();
            early_encode_into(&mut text, &bytes);
            assert_eq!(url_decode(&text).as_deref(), Some(&bytes[..]), "{len}");
            for cut in 0..=text.len() {
                let prefix = &text[..cut];
                if cut % 4 == 1 {
                    assert_eq!(
                        url_decode(prefix),
                        None,
                        "{cut}: a lone trailing digit is refused"
                    );
                    assert!(
                        serial_url_decode(prefix).is_some(),
                        "{cut}: the ladder dropped the digit instead"
                    );
                } else {
                    assert_eq!(
                        url_decode(prefix),
                        serial_url_decode(prefix),
                        "{cut}: route"
                    );
                }
            }
        }
    }
}
