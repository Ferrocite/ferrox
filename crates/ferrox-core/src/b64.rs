const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The `String`-returning coder: the gathered coder's bytes, in a buffer opened to the exact coded length, so one body owns the alphabet, the padding and the group read.
///
/// Delegating costs one zero fill and one UTF-8 walk over the output; the four `String::push` it replaces cost a `len_utf8` branch and a capacity check per character. `the_alphabet_coder_costs_the_groups_and_nothing_else` and `the_push_form_coder_costs_the_same_fold` are the two shapes under one probe, and their difference is which side of that trade the numbers sit on.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut coded = vec![0u8; encoded_len(bytes.len())];
    encode_parts_into(&[bytes], &mut coded).expect("a buffer opened to the exact coded length");
    String::from_utf8(coded).expect("the alphabet is ascii")
}

#[must_use]
pub const fn encoded_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

/// The coded text of several runs put end to end, written straight into the caller's buffer: the concatenation is never a buffer of its own, so a credential costs one pass over its bytes instead of a staging copy and a coder pass.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when `out` is shorter than the exact coded length.
pub fn encode_parts_into(parts: &[&[u8]], out: &mut [u8]) -> std::io::Result<usize> {
    let total: usize = parts.iter().map(|part| part.len()).sum();
    let len = encoded_len(total);
    let out = out
        .get_mut(..len)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut source = Gather {
        parts,
        part: 0,
        at: 0,
    };
    let groups = total / 3;
    for group in 0..groups {
        let word = source.triple();
        let at = group * 4;
        out[at..at + 4].copy_from_slice(&[
            STD[(word >> 18 & 63) as usize],
            STD[(word >> 12 & 63) as usize],
            STD[(word >> 6 & 63) as usize],
            STD[(word & 63) as usize],
        ]);
    }
    // The 1..=2 bytes that did not fill a group take the padding their empty lanes would have coded.
    let at = groups * 4;
    match total - groups * 3 {
        0 => {}
        1 => {
            let word = u32::from(source.byte().expect("the counted leftover")) << 16;
            out[at..at + 4].copy_from_slice(&[
                STD[(word >> 18 & 63) as usize],
                STD[(word >> 12 & 63) as usize],
                b'=',
                b'=',
            ]);
        }
        _ => {
            let word = (u32::from(source.byte().expect("the first leftover")) << 16)
                | (u32::from(source.byte().expect("the second leftover")) << 8);
            out[at..at + 4].copy_from_slice(&[
                STD[(word >> 18 & 63) as usize],
                STD[(word >> 12 & 63) as usize],
                STD[(word >> 6 & 63) as usize],
                b'=',
            ]);
        }
    }
    Ok(len)
}

struct Gather<'a> {
    parts: &'a [&'a [u8]],
    part: usize,
    at: usize,
}

impl Gather<'_> {
    fn byte(&mut self) -> Option<u8> {
        loop {
            let part = *self.parts.get(self.part)?;
            if let Some(byte) = part.get(self.at) {
                self.at += 1;
                return Some(*byte);
            }
            self.part += 1;
            self.at = 0;
        }
    }

    /// The next three bytes as one word; the group count comes from the total, so a caller only asks while the bytes are known to be there. A group the run under the cursor still holds is one read at that cursor; only a group that reaches a run's end walks the cursor a byte at a time.
    fn triple(&mut self) -> u32 {
        if let Some(word) = self.whole() {
            return word;
        }
        let mut word = 0u32;
        for lane in (0..3).rev() {
            word |= u32::from(self.byte().expect("the counted group")) << (8 * lane);
        }
        word
    }

    fn whole(&mut self) -> Option<u32> {
        let part = *self.parts.get(self.part)?;
        let end = self.at + 3;
        let bytes = part.get(self.at..end)?;
        self.at = end;
        Some((u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]))
    }
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

    /// The shape the shipped `String` coder replaced: a `chunks(3)` walk that puts its four characters through four `String::push`. It stays as the independent oracle the two sweeps below compare against — with `encode` delegating, an `encode`-shaped oracle would only prove a body equals itself — and as this run's second ops frame.
    fn push_form(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(encoded_len(bytes.len()));
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

    /// Every length, both padding shapes included, and the write lands in the buffer the caller handed over: no allocation of its own.
    #[test]
    fn the_window_coder_matches_the_alphabet_at_every_length() {
        let mut word = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            word ^= word << 13;
            word ^= word >> 7;
            word ^= word << 17;
            word as u8
        };
        for len in 0..=80usize {
            let bytes: Vec<u8> = (0..len).map(|_| next()).collect();
            let want = push_form(&bytes);
            let mut staged = vec![0u8; encoded_len(len)];
            let written = encode_parts_into(&[&bytes], &mut staged).expect("exact length");
            assert_eq!(written, staged.len(), "coded length for {len} bytes");
            assert_eq!(
                std::str::from_utf8(&staged).expect("ascii"),
                want,
                "{len} bytes through the window coder"
            );
            assert_eq!(encode(&bytes), want, "{len} bytes through the String coder");
        }
        let mut too_short = [0u8; 4];
        assert_eq!(
            encode_parts_into(&[b"abcd"], &mut too_short)
                .err()
                .map(|e| e.kind()),
            Some(std::io::ErrorKind::InvalidInput),
            "a buffer under the coded length is refused rather than partially filled"
        );
        assert_eq!(too_short, [0; 4], "and it is left untouched");
    }

    /// The gathered coder is the concatenation's coder: every total length, with the split put at every position inside it, so a group straddling the boundary and a tail of either side are both covered.
    #[test]
    fn the_gathered_coder_puts_the_concatenation_in_the_callers_buffer() {
        for len in 0..=40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 11) as u8).collect();
            for split in 0..=len {
                let (head, tail) = bytes.split_at(split);
                let want = encode(&[head, tail].concat());
                let mut out = vec![0u8; encoded_len(len)];
                let written = encode_parts_into(&[head, b"", tail], &mut out)
                    .unwrap_or_else(|_| panic!("{len} bytes split at {split}"));
                assert_eq!(written, want.len(), "{len} split at {split}");
                assert_eq!(
                    std::str::from_utf8(&out).expect("ascii"),
                    want,
                    "{len} split at {split}"
                );
            }
        }
        let empty: &[u8] = &[];
        assert_eq!(encode_parts_into(&[empty, empty], &mut []).unwrap(), 0);
        let mut wide = [0u8; 8];
        assert_eq!(
            encode_parts_into(&[b"abc", b"d"], &mut wide).unwrap(),
            8,
            "a split run codes the same text as a whole one"
        );
        assert_eq!(&wide, b"YWJjZA==");
        let mut too_short = [0u8; 3];
        assert_eq!(
            encode_parts_into(&[b"abc"], &mut too_short)
                .err()
                .map(|e| e.kind()),
            Some(std::io::ErrorKind::InvalidInput),
            "a buffer under the coded length is refused"
        );
        assert_eq!(too_short, [0; 3], "and left untouched");
    }

    /// The `String` coder, and nothing else: 64 passes over one 96-byte whole and one 95-byte padded coding, each output folded into a running `u32` whose expected value is pinned — so the loop cannot be folded away and a changed answer fails the row instead of measuring nothing. The fold, the loops and the frame entry ride inside this number, which is why the row is read as the difference between two runs of it and never as a cost per byte.
    #[test]
    fn the_alphabet_coder_costs_the_groups_and_nothing_else() {
        let bytes: Vec<u8> = (0..96).map(|i| (i * 7 + 11) as u8).collect();
        let mut fold: u32 = 0;
        for _ in 0..64 {
            for len in [96, 95] {
                for byte in encode(&bytes[..len]).into_bytes() {
                    fold = fold.wrapping_mul(31).wrapping_add(u32::from(byte));
                }
            }
        }
        assert_eq!(
            fold, 0x4291_eb80,
            "64 passes over a whole coding and a padded one, folded after each"
        );
    }

    /// The coder that was: the same 64 passes of the same two inputs the probe above folds, through [`push_form`], into the same pinned answer. One ops job reports both frames, so the fill and the UTF-8 walk the delegation buys are read against the four `String::push` they replaced without a second run being trusted to agree with the first.
    #[test]
    fn the_push_form_coder_costs_the_same_fold() {
        let bytes: Vec<u8> = (0..96).map(|i| (i * 7 + 11) as u8).collect();
        let mut fold: u32 = 0;
        for _ in 0..64 {
            for len in [96, 95] {
                for byte in push_form(&bytes[..len]).into_bytes() {
                    fold = fold.wrapping_mul(31).wrapping_add(u32::from(byte));
                }
            }
        }
        assert_eq!(fold, 0x4291_eb80, "the same 64 passes, four pushes a group");
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
