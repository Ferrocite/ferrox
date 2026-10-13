const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for byte in chunk {
            word = (word << 8) | u32::from(*byte);
        }
        word <<= 8 * (3 - chunk.len());
        out.push(STD[(word >> 18 & 63) as usize] as char);
        out.push(STD[(word >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            STD[(word >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            STD[(word & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

#[must_use]
pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut clean: Vec<u8> = text
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .take_while(|byte| *byte != b'=')
        .collect();
    if clean.is_empty() || clean.len() % 4 == 1 {
        return None;
    }
    let drop = (4 - clean.len() % 4) % 4;
    clean.resize(clean.len() + drop, b'A');
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for group in clean.as_chunks::<4>().0 {
        let mut word = 0u32;
        for byte in group {
            word = (word << 6) | u32::from(value(*byte)?);
        }
        out.push((word >> 16) as u8);
        out.push((word >> 8) as u8);
        out.push(word as u8);
    }
    out.truncate(out.len() - drop);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_round_trip() {
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded, "encoding {plain:?}");
            assert_eq!(
                decode(coded.as_bytes()).unwrap_or_default(),
                plain.as_bytes(),
                "decoding {coded:?}"
            );
        }
    }

    #[test]
    fn the_url_alphabet_and_a_missing_pad_are_the_same_bytes() {
        let raw = [0xfb_u8, 0xff, 0xbf, 0x00, 0x10];
        let url = encode(&raw).replace('+', "-").replace('/', "_");
        assert_eq!(decode(url.as_bytes()), Some(raw.to_vec()));
        assert_eq!(
            decode(url.trim_end_matches('=').as_bytes()),
            Some(raw.to_vec())
        );
    }

    #[test]
    fn a_quarter_and_a_whitespace_block_are_refused() {
        assert!(decode(b"Zg9vYmFyZ").is_none());
        assert!(decode(b"Zm9v\n YmFy").is_some());
        assert!(decode(b"!!!!").is_none());
        assert!(decode(b"   ").is_none());
        assert!(decode(b"Zg==Zg==").is_some());
    }
}
