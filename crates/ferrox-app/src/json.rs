use std::collections::HashMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Num(n) if n.fract() == 0.0 && (0.0..=4_294_967_295.0).contains(n) => {
                Some(*n as u32)
            }
            _ => None,
        }
    }

    pub(crate) fn as_port(&self) -> Option<u16> {
        self.as_u32().and_then(|n| u16::try_from(n).ok())
    }

    /// The `i64` a JSON integer holds, which is the type a Go `int64` field unmarshals; a float is not one.
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Num(n)
                if n.fract() == 0.0
                    && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(n) =>
            {
                Some(*n as i64)
            }
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub(crate) fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Self::Arr(items) => Some(items),
            _ => None,
        }
    }
}

/// xray's `conf.Config.Override`: a top-level block replaces whole, `inbounds` and `outbounds`
/// merge by tag (a new outbound prepends unless the file's name says `tail`), `env` merges by
/// key, and a null block overrides nothing.
pub(crate) fn merge(base: &mut Json, over: &Json, name: &str) {
    let (Json::Obj(base), Json::Obj(pairs)) = (base, over) else {
        return;
    };
    let tail = name.to_ascii_lowercase().contains("tail");
    for (key, value) in pairs {
        if matches!(value, Json::Null) {
            continue;
        }
        match key.as_str() {
            "inbounds" => merge_tagged(base, key, value, false),
            "outbounds" => merge_tagged(base, key, value, tail),
            "env" => merge_env(base, key, value),
            _ => upsert(base, key, value.clone()),
        }
    }
}

/// The value a top-level key holds, inserted as null when this is the first config naming it.
fn slot<'a>(pairs: &'a mut Vec<(String, Json)>, key: &str) -> &'a mut Json {
    let Some(at) = pairs.iter().position(|(have, _)| have == key) else {
        let at = pairs.len();
        pairs.push((key.to_owned(), Json::Null));
        return &mut pairs[at].1;
    };
    &mut pairs[at].1
}

fn upsert(pairs: &mut Vec<(String, Json)>, key: &str, value: Json) {
    *slot(pairs, key) = value;
}

/// `env` is the one block the reference merges key by key instead of replacing whole.
fn merge_env(base: &mut Vec<(String, Json)>, key: &str, over: &Json) {
    let Json::Obj(entries) = over else {
        upsert(base, key, over.clone());
        return;
    };
    let Json::Obj(into) = slot(base, key) else {
        upsert(base, key, over.clone());
        return;
    };
    let mut index: HashMap<&str, usize> = HashMap::with_capacity(into.len() + entries.len());
    for (at, (name, _)) in into.iter().enumerate() {
        index.entry(name.as_str()).or_insert(at);
    }
    let mut added: Vec<(&str, &Json)> = Vec::new();
    let mut replaced: Vec<(usize, &Json)> = Vec::new();
    for (name, value) in entries {
        if let Some(&at) = index.get(name.as_str()) {
            replaced.push((at, value));
        } else {
            index.insert(name.as_str(), into.len() + added.len());
            added.push((name, value));
        }
    }
    drop(index);
    into.extend(
        added
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.clone())),
    );
    for (at, value) in replaced {
        into[at].1 = value.clone();
    }
}

fn merge_tagged(base: &mut Vec<(String, Json)>, key: &str, over: &Json, tail: bool) {
    let Json::Arr(items) = over else {
        upsert(base, key, over.clone());
        return;
    };
    if items.is_empty() {
        return;
    }
    let entry = slot(base, key);
    let Json::Arr(existing) = entry else {
        *entry = over.clone();
        return;
    };
    let base = existing.len();
    let mut index: HashMap<&str, usize> = HashMap::with_capacity(base + items.len());
    for (at, have) in existing.iter().enumerate() {
        let tag = have.get("tag").and_then(Json::as_str).unwrap_or_default();
        index.entry(tag).or_insert(at);
    }
    let mut added: Vec<&Json> = Vec::new();
    let mut replaced: Vec<(usize, &Json)> = Vec::new();
    for item in items {
        let tag = item.get("tag").and_then(Json::as_str).unwrap_or_default();
        if let Some(&at) = index.get(tag) {
            replaced.push((at, item));
        } else {
            index.insert(tag, base + added.len());
            added.push(item);
        }
    }
    drop(index);
    existing.extend(added.into_iter().cloned());
    for (at, item) in replaced {
        existing[at] = item.clone();
    }
    if !tail {
        let appended = existing.split_off(base);
        existing.splice(0..0, appended);
    }
}

/// The one writer for a value, so a built request never hand-writes a string; its output is what `parse` reads.
pub(crate) fn write(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Num(n) => {
            if n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 {
                let _ = write!(out, "{}", *n as i64);
            } else {
                let _ = write!(out, "{n}");
            }
        }
        Json::Str(s) => write_string(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Json::Obj(pairs) => {
            out.push('{');
            for (at, (key, item)) in pairs.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write(item, out);
            }
            out.push('}');
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    let bytes = text.as_bytes();
    let mut at = 0usize;
    let mut copy = 0usize;
    while let Some((offset, byte)) = next_json_special(&bytes[at..]) {
        at += offset;
        out.push_str(&text[copy..at]);
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            _ => {
                out.push_str("\\u00");
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
        at += 1;
        copy = at;
    }
    out.push_str(&text[copy..]);
    out.push('"');
}

/// The first byte a JSON string must escape: a quote, a backslash, or a control byte.
/// AVX2 walks 32 bytes per turn when the CPU has it; the SWAR tail keeps the same
/// unsigned-control test. Bytes at or above `0x80` are not special.
fn next_json_special(bytes: &[u8]) -> Option<(usize, u8)> {
    #[cfg(target_arch = "x86_64")]
    if bytes.len() >= 32 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: the runtime feature test above proves AVX2 is available.
        return unsafe { next_json_special_avx2(bytes) };
    }
    next_json_special_swar(bytes)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn next_json_special_avx2(bytes: &[u8]) -> Option<(usize, u8)> {
    use core::arch::x86_64::{
        _mm256_and_si256, _mm256_cmpeq_epi8, _mm256_cmpgt_epi8, _mm256_loadu_si256,
        _mm256_movemask_epi8, _mm256_or_si256, _mm256_set1_epi8,
    };
    let quote = _mm256_set1_epi8(b'"'.cast_signed());
    let slash = _mm256_set1_epi8(b'\\'.cast_signed());
    let control = _mm256_set1_epi8(0x20);
    let negative = _mm256_set1_epi8(-1);
    let mut at = 0usize;
    while at + 32 <= bytes.len() {
        // SAFETY: `at + 32` is inside `bytes`, and the load is unaligned.
        let marked = unsafe {
            let block = _mm256_loadu_si256(bytes.as_ptr().add(at).cast());
            let quote_or_slash = _mm256_or_si256(
                _mm256_cmpeq_epi8(block, quote),
                _mm256_cmpeq_epi8(block, slash),
            );
            let below_control = _mm256_and_si256(
                _mm256_cmpgt_epi8(control, block),
                _mm256_cmpgt_epi8(block, negative),
            );
            _mm256_movemask_epi8(_mm256_or_si256(quote_or_slash, below_control))
        };
        if marked != 0 {
            let found = at + marked.trailing_zeros() as usize;
            return Some((found, bytes[found]));
        }
        at += 32;
    }
    next_json_special_swar(&bytes[at..]).map(|(found, byte)| (at + found, byte))
}

/// The SWAR tail: two eight-byte blocks at a time, with the same zero-byte test the rest
/// of the tree uses and the standard "less than n" test for the control range; the
/// earliest marked lane is always a real one, so a borrow's false mark above it is never
/// the answer.
fn next_json_special_swar(bytes: &[u8]) -> Option<(usize, u8)> {
    const SPREAD: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    const CONTROL: u64 = 0x2020_2020_2020_2020;
    let quote = u64::from(b'"').wrapping_mul(SPREAD);
    let slash = u64::from(b'\\').wrapping_mul(SPREAD);
    let mark = |word: u64| {
        let q = word ^ quote;
        let s = word ^ slash;
        (q.wrapping_sub(SPREAD) & !q & HIGH)
            | (s.wrapping_sub(SPREAD) & !s & HIGH)
            | (word.wrapping_sub(CONTROL) & !word & HIGH)
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
        if byte == b'"' || byte == b'\\' || byte < 0x20 {
            return Some((at, byte));
        }
        at += 1;
    }
    None
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn parse(text: &str) -> Result<Json, String> {
    let mut cursor = Cursor {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let mut value = cursor.value(0)?;
    cursor.gap();
    if cursor.pos != cursor.bytes.len() {
        return Err(format!("trailing bytes at offset {}", cursor.pos));
    }
    expand_env(&mut value);
    Ok(value)
}

/// Resolve `env:NAME` in the fields xray reads as an address or a port list, once at config load.
fn expand_env(value: &mut Json) {
    const FIELDS: [&str; 4] = ["address", "listen", "ip", "port"];
    match value {
        Json::Obj(pairs) => {
            for (key, child) in pairs {
                if FIELDS.contains(&key.as_str()) {
                    if key == "port" {
                        expand_port(child);
                    } else {
                        expand_strings(child);
                    }
                }
                expand_env(child);
            }
        }
        Json::Arr(items) => items.iter_mut().for_each(expand_env),
        _ => {}
    }
}

fn expand_strings(value: &mut Json) {
    match value {
        Json::Str(text) => *text = env_value(text),
        Json::Arr(items) => {
            for item in items {
                if let Json::Str(text) = item {
                    *text = env_value(text);
                }
            }
        }
        _ => {}
    }
}

fn expand_port(value: &mut Json) {
    match value {
        Json::Str(text) => {
            let resolved = port_spec(text);
            *value = match resolved.parse::<u16>() {
                Ok(port) => Json::Num(f64::from(port)),
                Err(_) => Json::Str(resolved),
            };
        }
        Json::Arr(items) => {
            for item in items {
                if matches!(item, Json::Str(_)) {
                    expand_port(item);
                }
            }
        }
        _ => {}
    }
}

fn port_spec(text: &str) -> String {
    text.split(',')
        .map(|piece| env_value(piece.trim()))
        .collect::<Vec<_>>()
        .join(",")
}

fn env_value(text: &str) -> String {
    text.strip_prefix("env:").map_or_else(
        || text.to_owned(),
        |name| std::env::var(name).unwrap_or_default(),
    )
}

#[derive(Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn gap(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn byte(&mut self, want: u8, what: &str) -> Result<(), String> {
        self.gap();
        if self.bytes.get(self.pos) == Some(&want) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {what} at offset {}", self.pos))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > 32 {
            return Err(format!("nesting past 32 at offset {}", self.pos));
        }
        self.gap();
        match self.bytes.get(self.pos) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(c) if c.is_ascii_digit() || *c == b'-' => self.number(),
            Some(_) => self.word(),
            None => Err(format!("unexpected end at offset {}", self.pos)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.pos += 1;
        let mut pairs = Vec::new();
        self.gap();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.gap();
            if self.bytes.get(self.pos) != Some(&b'"') {
                return Err(format!("expected a key at offset {}", self.pos));
            }
            let key = self.string()?;
            self.byte(b':', "`:`")?;
            pairs.push((key, self.value(depth + 1)?));
            self.gap();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(format!("expected `,` or `}}` at offset {}", self.pos)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.gap();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.gap();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected `,` or `]` at offset {}", self.pos)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        let mut copy = self.pos;
        loop {
            let Some((offset, byte)) = next_json_special(&self.bytes[self.pos..]) else {
                return Err(format!("unterminated string at offset {}", self.pos));
            };
            self.pos += offset;
            out.push_str(
                std::str::from_utf8(&self.bytes[copy..self.pos])
                    .map_err(|_| format!("invalid utf-8 at offset {copy}"))?,
            );
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    out.push(self.escape()?);
                    copy = self.pos;
                }
                _ => {
                    self.pos += 1;
                    return Err(format!("raw control byte at offset {}", self.pos));
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        let Some(&b) = self.bytes.get(self.pos) else {
            return Err(format!("dangling backslash at offset {}", self.pos));
        };
        self.pos += 1;
        match b {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000C}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                if self.pos + 4 > self.bytes.len() {
                    return Err(format!("short `\\u` escape at offset {}", self.pos));
                }
                let mut unit = 0u32;
                for i in 0..4 {
                    unit = unit * 16 + hex(self.bytes[self.pos + i], self.pos + i)?;
                }
                self.pos += 4;
                char::from_u32(unit).ok_or_else(|| format!("bad scalar at offset {}", self.pos))
            }
            _ => Err(format!("bad escape at offset {}", self.pos)),
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let from = self.pos;
        if self.bytes.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        if self.bytes.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
        }
        if matches!(self.bytes.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[from..self.pos])
            .map_err(|_| format!("bad number at offset {from}"))?;
        text.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("bad number at offset {from}"))
    }

    fn word(&mut self) -> Result<Json, String> {
        for (word, value) in [
            ("true", Json::Bool(true)),
            ("false", Json::Bool(false)),
            ("null", Json::Null),
        ] {
            if self.bytes[self.pos..].starts_with(word.as_bytes()) {
                self.pos += word.len();
                return Ok(value);
            }
        }
        Err(format!("unexpected token at offset {}", self.pos))
    }
}

fn hex(byte: u8, at: usize) -> Result<u32, String> {
    match byte {
        b'0'..=b'9' => Ok(u32::from(byte - b'0')),
        b'a'..=b'f' => Ok(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Ok(u32::from(byte - b'A') + 10),
        _ => Err(format!("bad hex digit at offset {at}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item_tag(item: &Json) -> &str {
        item.get("tag").and_then(Json::as_str).expect("tag")
    }

    fn item_port(item: &Json) -> u32 {
        item.get("port").and_then(Json::as_u32).expect("port")
    }

    #[derive(Debug, Clone)]
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn byte(&mut self) -> u8 {
            {
                self.next_u64() as u8
            }
        }

        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                return 0;
            }
            let bound = u32::try_from(bound).unwrap_or(u32::MAX);
            let zone = 256 - (256 % bound);
            loop {
                let draw = u32::from(self.byte());
                if draw < zone {
                    return (draw % bound) as usize;
                }
            }
        }
    }

    const SEED: u64 = 0x4528_21e6_38d0_1377;

    const CASES: usize = 4_096;

    const GOOD: &str = r#"{"inbounds":[{"protocol":"vless","port":443,"streamSettings":{"network":"ws","wsSettings":{"path":"/x"}}}],"outbounds":[{"protocol":"freedom"}]}"#;

    #[test]
    fn the_reader_survives_corrupted_configuration() {
        for case in 0..CASES {
            let seed = SEED.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);

            let mut text = String::from(GOOD);
            match case % 5 {
                0 => {}
                1 => {
                    let at = rng.below(text.len());
                    text.replace_range(at..=at, "\u{fffd}");
                }
                2 => {
                    let at = rng.below(text.len());
                    text.remove(at);
                }
                3 => {
                    let at = rng.below(text.len());
                    text.insert(at, '\\');
                }
                _ => {
                    let at = rng.below(text.len());
                    text.insert(at, '"');
                }
            }

            let _ = parse(&text);
        }
    }

    #[test]
    fn a_truncated_configuration_is_refused_rather_than_partially_parsed() {
        for cut in 1..GOOD.len() {
            assert!(
                parse(&GOOD[..cut]).is_err(),
                "cut {cut} parsed a prefix of a valid document instead of refusing it"
            );
        }
        assert!(
            parse(GOOD).is_ok(),
            "the corpus must be valid to mean anything"
        );
    }

    #[test]
    fn reads_the_oracle_config_shape() {
        let doc = parse(
            r#"{"log": {"loglevel": "debug"}, "inbounds": [{"tag": "in",
            "listen": "127.0.0.1", "port": 41234, "protocol": "vless",
            "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "decryption": "none"}, "streamSettings": {"network": "tcp"}}],
            "outbounds": [{"protocol": "freedom"}]}"#,
        )
        .expect("parses");
        let inbound = &doc
            .get("inbounds")
            .expect("inbounds")
            .as_arr()
            .expect("array")[0];
        assert_eq!(
            inbound.get("protocol").expect("protocol").as_str(),
            Some("vless")
        );
        assert_eq!(inbound.get("port").expect("port").as_port(), Some(41234));
        let id = inbound
            .get("settings")
            .expect("settings")
            .get("clients")
            .expect("clients")
            .as_arr()
            .expect("array")[0]
            .get("id")
            .expect("id")
            .as_str()
            .expect("string");
        assert_eq!(id, "b831381d-6324-4d53-ad4f-8cda48b30811");
    }

    #[test]
    fn rejects_trailing_bytes_and_bad_words() {
        assert!(parse(r#"{"a": 1} trailing"#).is_err());
        assert!(parse(r#"{"a": tru}"#).is_err());
        assert!(parse(r#"{"a": [1,]}"#).is_err());
        assert_eq!(parse("null").expect("null"), Json::Null);
        assert_eq!(parse("  41234 ").expect("port").as_port(), Some(41234));
        assert!(parse("70000").expect("big").as_port().is_none());
    }

    #[test]
    fn a_written_value_reads_back_as_the_same_value() {
        for text in [
            "{\"a\":\"x\",\"b\":[1,2,null],\"c\":{\"d\":true},\"e\":\"q\\\\n\"}",
            r#"[{"ty":"pow"},{"ty":"pat"}]"#,
            r#"{"v":2,"w":-3,"x":4.5}"#,
            "[]",
            "{}",
        ] {
            let value = parse(text).expect(text);
            let mut out = String::new();
            write(&value, &mut out);
            assert_eq!(parse(&out).expect(&out), value, "{text} -> {out}");
        }
    }

    #[test]
    fn a_written_string_is_the_bytes_the_parser_reads() {
        for text in [
            "",
            "plain",
            "\u{0}\u{1f}\n\r\t\"\\",
            "é",
            "日本語",
            "😀",
            "a\u{0}é😀z",
        ] {
            let mut out = String::new();
            write(&Json::Str(text.to_owned()), &mut out);
            assert_eq!(
                parse(&out).expect(&out),
                Json::Str(text.to_owned()),
                "{text:?} -> {out}"
            );
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut text = String::new();
            for _ in 0..(state % 64) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let ch = match state % 10 {
                    0 => '"',
                    1 => '\\',
                    2 => '\n',
                    3 => '\r',
                    4 => '\t',
                    5 => '\u{0}',
                    6 => 'é',
                    7 => '😀',
                    8 => 'a',
                    _ => char::from((state >> 8) as u8),
                };
                text.push(ch);
            }
            let mut out = String::new();
            write(&Json::Str(text.clone()), &mut out);
            assert_eq!(
                parse(&out).expect(&out),
                Json::Str(text.clone()),
                "{text:?} -> {out}"
            );
        }
    }

    #[test]
    fn the_word_scan_is_the_byte_scan_for_a_json_string() {
        fn byte_scan(bytes: &[u8]) -> Option<(usize, u8)> {
            bytes
                .iter()
                .position(|byte| *byte == b'"' || *byte == b'\\' || *byte < 0x20)
                .map(|at| (at, bytes[at]))
        }
        let alphabet = [b'a', b'"', b'\\', b'\n', 0x1f, 0x20, 0x7f, 0x80];
        for len in 0..=4 {
            for mut case in 0..alphabet.len().pow(len as u32) {
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len {
                    bytes.push(alphabet[case % alphabet.len()]);
                    case /= alphabet.len();
                }
                assert_eq!(next_json_special(&bytes), byte_scan(&bytes), "{bytes:?}");
            }
        }
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for pad in 0..40 {
            for len in 0..96 {
                let mut bytes = vec![b'a'; pad];
                for _ in 0..len {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    bytes.push(match state % 37 {
                        0 => b'"',
                        1 => b'\\',
                        2 => 0x1f,
                        3 => 0x7f,
                        4 => 0x80,
                        _ => b'x',
                    });
                }
                let tail = &bytes[pad..];
                assert_eq!(
                    next_json_special(tail),
                    byte_scan(tail),
                    "pad {pad}, len {len}"
                );
            }
        }
        let mut bytes = Vec::with_capacity(4096);
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push((state >> 8) as u8);
            assert_eq!(
                next_json_special(&bytes),
                byte_scan(&bytes),
                "{:?}",
                &bytes[bytes.len().saturating_sub(16)..]
            );
        }
    }

    #[test]
    fn a_written_number_is_an_integer_when_it_is_one() {
        let mut out = String::new();
        write(&Json::Num(2.0), &mut out);
        assert_eq!(out, "2");
        out.clear();
        write(&Json::Num(-3.0), &mut out);
        assert_eq!(out, "-3");
        out.clear();
        write(&Json::Num(4.5), &mut out);
        assert_eq!(out, "4.5");
        out.clear();
        write(&Json::Str("\u{1}\n\"".into()), &mut out);
        assert_eq!(out, "\"\\u0001\\n\\\"\"");
    }

    #[test]
    fn merge_keeps_a_block_the_later_file_leaves_null_or_empty() {
        let mut base =
            parse(r#"{"log":{"loglevel":"warning"},"inbounds":[{"tag":"in"}]}"#).expect("parses");
        let over = parse(r#"{"log":null,"inbounds":[]}"#).expect("parses");
        merge(&mut base, &over, "02-extra.json");
        let mut text = String::new();
        write(&base, &mut text);
        assert_eq!(
            text,
            r#"{"log":{"loglevel":"warning"},"inbounds":[{"tag":"in"}]}"#
        );
    }

    #[test]
    fn merge_joins_env_by_key() {
        let mut base = parse(r#"{"env":{"A":"1","B":"2"}}"#).expect("parses");
        let over = parse(r#"{"env":{"B":"3","C":"4"}}"#).expect("parses");
        merge(&mut base, &over, "02-extra.json");
        let mut text = String::new();
        write(&base, &mut text);
        assert_eq!(text, r#"{"env":{"A":"1","B":"3","C":"4"}}"#);
    }

    #[test]
    fn merge_replaces_a_tag_the_same_file_repeats() {
        let mut base = parse(r#"{"inbounds":[{"tag":"a","port":1}]}"#).expect("parses");
        let over =
            parse(r#"{"inbounds":[{"tag":"a","port":2},{"tag":"a","port":3}]}"#).expect("parses");
        merge(&mut base, &over, "02-extra.json");
        let mut text = String::new();
        write(&base, &mut text);
        assert_eq!(text, r#"{"inbounds":[{"tag":"a","port":3}]}"#);
    }

    #[test]
    fn merge_keeps_the_tag_order_across_a_large_prepend() {
        let row = |tag: usize, port: f64| {
            Json::Obj(vec![
                ("tag".to_owned(), Json::Str(format!("tag{tag}"))),
                ("port".to_owned(), Json::Num(port)),
            ])
        };
        let mut base = Json::Obj(vec![(
            "inbounds".to_owned(),
            Json::Arr((0..4096).map(|tag| row(tag, 0.0)).collect()),
        )]);
        let over = Json::Obj(vec![(
            "inbounds".to_owned(),
            Json::Arr((2048..6144).map(|tag| row(tag, 1.0)).collect()),
        )]);
        merge(&mut base, &over, "02-extra.json");
        let items = base.get("inbounds").and_then(Json::as_arr).expect("array");
        assert_eq!(
            items.len(),
            6144,
            "replaced tags stay in place, new ones prepend"
        );
        assert_eq!(item_tag(&items[0]), "tag4096");
        assert_eq!(item_tag(&items[2047]), "tag6143");
        assert_eq!(item_tag(&items[2048]), "tag0");
        assert_eq!(item_tag(&items[4095]), "tag2047");
        assert_eq!(item_tag(&items[4096]), "tag2048");
        assert_eq!(
            item_port(&items[4096]),
            1,
            "an existing tag is replaced in place"
        );
        assert_eq!(item_tag(&items[4095]), "tag2047");
        assert_eq!(
            item_port(&items[4095]),
            0,
            "an untouched tag keeps its value"
        );
    }
}
