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
    for byte in text.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1f => {
                out.push_str("\\u00");
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
            _ => out.push(byte as char),
        }
    }
    out.push('"');
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
        loop {
            let Some(&b) = self.bytes.get(self.pos) else {
                return Err(format!("unterminated string at offset {}", self.pos));
            };
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => out.push(self.escape()?),
                0x00..=0x1F => return Err(format!("raw control byte at offset {}", self.pos)),
                _ => out.push(b as char),
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
}
