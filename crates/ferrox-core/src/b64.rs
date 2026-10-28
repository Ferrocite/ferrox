const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Two alphabet octets for one twelve-bit group, in native byte order: a three-byte input is two table probes and two stores instead of four shifts, four probes and four stores.
const ENC12: [u16; 4096] = encoded_pairs();

const fn encoded_pairs() -> [u16; 4096] {
    let mut table = [0u16; 4096];
    let mut word = 0usize;
    while word < 4096 {
        table[word] = u16::from_ne_bytes([STD[word >> 6], STD[word & 63]]);
        word += 1;
    }
    table
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn encode_group(word: u32) -> u32 {
    let first = ENC12[((word >> 12) & 0xfff) as usize];
    let second = ENC12[(word & 0xfff) as usize];
    u32::from(first) | (u32::from(second) << 16)
}

/// The `String`-returning coder, one read a group with no intermediate buffer to zero and no validation pass afterwards.
///
/// [`encode_parts_into`] is the other route to these bytes and the one that writes where the caller already has a window; `the_window_coder_matches_the_alphabet_at_every_length` holds the two byte-identical, which is why this shape survives instead of delegating and paying a fill plus a UTF-8 walk per call.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    #[cfg(target_arch = "x86_64")]
    if bytes.len() == 12 {
        let mut out = Vec::<u8>::with_capacity(16);
        let ptr = out.as_mut_ptr();
        // SAFETY: the two loads stay inside twelve bytes, the two stores fill the sixteen reserved bytes with alphabet octets, and the early return skips the generic walk.
        unsafe {
            let low = bytes.as_ptr().cast::<u64>().read_unaligned();
            let high = bytes.as_ptr().add(8).cast::<u32>().read_unaligned();
            let g0 = ((low & 0x00ff_ffff) as u32).swap_bytes() >> 8;
            let g1 = (((low >> 24) & 0x00ff_ffff) as u32).swap_bytes() >> 8;
            let g2 = (((low >> 48) as u32) | ((high & 0xff) << 16)).swap_bytes() >> 8;
            let g3 = ((high >> 8) & 0x00ff_ffff).swap_bytes() >> 8;
            ptr.cast::<u64>()
                .write_unaligned(u64::from(encode_group(g0)) | (u64::from(encode_group(g1)) << 32));
            ptr.add(8)
                .cast::<u64>()
                .write_unaligned(u64::from(encode_group(g2)) | (u64::from(encode_group(g3)) << 32));
            out.set_len(16);
            return String::from_utf8_unchecked(out);
        }
    }
    let len = encoded_len(bytes.len());
    let mut out = Vec::<u8>::with_capacity(len);
    // The buffer is opened to the exact coded length and every byte of it is written below, so the four alphabet octets of a group are four stores and one cursor add rather than four capacity checks and a length reload each.
    let ptr = out.as_mut_ptr();
    let (whole, rest) = bytes.as_chunks::<3>();
    #[cfg(not(target_arch = "aarch64"))]
    let mut at = 0usize;
    #[cfg(target_arch = "aarch64")]
    let mut at;
    #[cfg(target_arch = "x86_64")]
    let group = if bytes.len() >= 28 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: the feature is present, the wide loop loads two sixteen-byte lanes while twenty-eight bytes remain, and the tail loads exactly twelve.
        let (done, written) = unsafe { x86::encode_prefix_avx2(bytes, ptr) };
        at = written;
        done / 3
    } else if bytes.len() >= 16 && std::is_x86_feature_detected!("ssse3") {
        // SAFETY: the feature is present, the wide loop loads only while 16 bytes remain, and the tail loads exactly 12.
        let (done, written) = unsafe { x86::encode_prefix(bytes, ptr) };
        at = written;
        done / 3
    } else {
        0
    };
    #[cfg(target_arch = "aarch64")]
    let group = {
        let (done, written) = neon::encode_prefix(bytes, ptr);
        at = written;
        done / 3
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let group = 0usize;
    for [a, b, c] in &whole[group..] {
        let word = (u32::from(*a) << 16) | (u32::from(*b) << 8) | u32::from(*c);
        let first = ENC12[((word >> 12) & 0xfff) as usize];
        let second = ENC12[(word & 0xfff) as usize];
        // SAFETY: `at + 4 <= len` for every whole group, and the four bytes written are alphabet octets, so the `String` below is valid UTF-8.
        unsafe {
            ptr.add(at).cast::<u16>().write_unaligned(first);
            ptr.add(at + 2).cast::<u16>().write_unaligned(second);
        }
        at += 4;
    }
    // The one or two bytes a whole group does not cover are the padded group they always were, with its last octets zero.
    if !rest.is_empty() {
        let mut word = 0u32;
        for byte in rest {
            word = (word << 8) | u32::from(*byte);
        }
        word <<= 8 * (3 - rest.len());
        // SAFETY: the padded group is the final four bytes of the exact coded length.
        unsafe {
            ptr.add(at).write(STD[(word >> 18 & 63) as usize]);
            ptr.add(at + 1).write(STD[(word >> 12 & 63) as usize]);
            ptr.add(at + 2).write(if rest.len() > 1 {
                STD[(word >> 6 & 63) as usize]
            } else {
                b'='
            });
            ptr.add(at + 3).write(b'=');
        }
        at += 4;
    }
    debug_assert_eq!(at, len, "the alphabet fills the capacity it reserved");
    // SAFETY: the whole buffer was initialized above with alphabet octets or padding.
    unsafe {
        out.set_len(len);
        String::from_utf8_unchecked(out)
    }
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
        let first = ENC12[((word >> 12) & 0xfff) as usize].to_ne_bytes();
        let second = ENC12[(word & 0xfff) as usize].to_ne_bytes();
        out[at..at + 4].copy_from_slice(&[first[0], first[1], second[0], second[1]]);
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

/// One table for both alphabets: a valid digit is below 64, so the invalid sentinel is the only value with bit 6 set.
const fn digit_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut byte = b'A';
    while byte <= b'Z' {
        table[byte as usize] = byte - b'A';
        byte += 1;
    }
    byte = b'a';
    while byte <= b'z' {
        table[byte as usize] = byte - b'a' + 26;
        byte += 1;
    }
    byte = b'0';
    while byte <= b'9' {
        table[byte as usize] = byte - b'0' + 52;
        byte += 1;
    }
    table[b'+' as usize] = 62;
    table[b'-' as usize] = 62;
    table[b'/' as usize] = 63;
    table[b'_' as usize] = 63;
    table
}

const DIGITS: [u8; 256] = digit_table();

/// One 16-byte lane is four 12-bit groups: `pshufb` indexes the offset table by the
/// high nibble, and a nibble bitset rejects a byte outside the alphabet.
#[cfg(target_arch = "x86_64")]
mod x86 {
    #[allow(
        clippy::wildcard_imports,
        reason = "arch intrinsics: the module's whole API is register operations"
    )]
    use core::arch::x86_64::*;

    const OFFSETS: [i8; 16] = [-1, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0];
    const LO: [i8; 16] = [
        0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1a, 0x1b, 0x1b, 0x1b,
        0x1a,
    ];
    const HI: [i8; 16] = [
        0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10,
    ];
    const PACK: [i8; 16] = [2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1];
    const ENCODE_SHUFFLE: [i8; 16] = [1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10];
    const ENCODE_OFFSETS: [i8; 16] = [
        65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0,
    ];

    /// Decodes the whole 16-byte blocks of `text` into `out`, returning how much of
    /// each was consumed. The caller checks `ssse3` and has four bytes of output slop.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn decode_prefix(text: &[u8], out: *mut u8) -> (usize, usize) {
        unsafe {
            let offsets = _mm_loadu_si128(OFFSETS.as_ptr().cast());
            let low_lut = _mm_loadu_si128(LO.as_ptr().cast());
            let high_lut = _mm_loadu_si128(HI.as_ptr().cast());
            let pack = _mm_loadu_si128(PACK.as_ptr().cast());
            let first = _mm_set1_epi32(0x0140_0140);
            let second = _mm_set1_epi32(0x0001_1000);
            let low_mask = _mm_set1_epi8(0x0f);
            let mut at = 0usize;
            let mut out_at = 0usize;
            while at + 16 <= text.len() {
                let raw = _mm_loadu_si128(text.as_ptr().add(at).cast());
                let dash = _mm_cmpeq_epi8(raw, _mm_set1_epi8(45));
                let under = _mm_cmpeq_epi8(raw, _mm_set1_epi8(95));
                let raw = _mm_or_si128(
                    _mm_and_si128(dash, _mm_set1_epi8(43)),
                    _mm_andnot_si128(dash, raw),
                );
                let raw = _mm_or_si128(
                    _mm_and_si128(under, _mm_set1_epi8(47)),
                    _mm_andnot_si128(under, raw),
                );
                let high = _mm_and_si128(_mm_srli_epi16::<4>(raw), low_mask);
                let slash = _mm_cmpeq_epi8(raw, _mm_set1_epi8(47));
                let hash = _mm_add_epi8(high, slash);
                let sextets = _mm_add_epi8(raw, _mm_shuffle_epi8(offsets, hash));
                let low_bits = _mm_shuffle_epi8(low_lut, _mm_and_si128(raw, low_mask));
                let high_bits = _mm_shuffle_epi8(high_lut, high);
                let valid = _mm_cmpeq_epi8(_mm_and_si128(low_bits, high_bits), _mm_setzero_si128());
                if _mm_movemask_epi8(valid) != 0xffff {
                    break;
                }
                let packed = _mm_madd_epi16(_mm_maddubs_epi16(sextets, first), second);
                _mm_storeu_si128(out.add(out_at).cast(), _mm_shuffle_epi8(packed, pack));
                at += 16;
                out_at += 12;
            }
            (at, out_at)
        }
    }

    /// Decodes the whole 32-byte blocks of `text` into `out`, returning how much of
    /// each was consumed. The caller checks `avx2` and has four bytes of output slop.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn decode_prefix_avx2(text: &[u8], out: *mut u8) -> (usize, usize) {
        unsafe {
            let offsets = _mm256_broadcastsi128_si256(_mm_loadu_si128(OFFSETS.as_ptr().cast()));
            let low_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(LO.as_ptr().cast()));
            let high_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(HI.as_ptr().cast()));
            let pack = _mm256_broadcastsi128_si256(_mm_loadu_si128(PACK.as_ptr().cast()));
            let first = _mm256_set1_epi32(0x0140_0140);
            let second = _mm256_set1_epi32(0x0001_1000);
            let low_mask = _mm256_set1_epi8(0x0f);
            let mut at = 0usize;
            let mut out_at = 0usize;
            while at + 32 <= text.len() {
                let raw = _mm256_loadu_si256(text.as_ptr().add(at).cast());
                let dash = _mm256_cmpeq_epi8(raw, _mm256_set1_epi8(45));
                let under = _mm256_cmpeq_epi8(raw, _mm256_set1_epi8(95));
                let raw = _mm256_or_si256(
                    _mm256_and_si256(dash, _mm256_set1_epi8(43)),
                    _mm256_andnot_si256(dash, raw),
                );
                let raw = _mm256_or_si256(
                    _mm256_and_si256(under, _mm256_set1_epi8(47)),
                    _mm256_andnot_si256(under, raw),
                );
                let high = _mm256_and_si256(_mm256_srli_epi16::<4>(raw), low_mask);
                let slash = _mm256_cmpeq_epi8(raw, _mm256_set1_epi8(47));
                let hash = _mm256_add_epi8(high, slash);
                let sextets = _mm256_add_epi8(raw, _mm256_shuffle_epi8(offsets, hash));
                let low_bits = _mm256_shuffle_epi8(low_lut, _mm256_and_si256(raw, low_mask));
                let high_bits = _mm256_shuffle_epi8(high_lut, high);
                let valid = _mm256_cmpeq_epi8(
                    _mm256_and_si256(low_bits, high_bits),
                    _mm256_setzero_si256(),
                );
                if _mm256_movemask_epi8(valid) != -1 {
                    break;
                }
                let packed = _mm256_madd_epi16(_mm256_maddubs_epi16(sextets, first), second);
                let packed = _mm256_shuffle_epi8(packed, pack);
                _mm_storeu_si128(out.add(out_at).cast(), _mm256_castsi256_si128(packed));
                _mm_storeu_si128(
                    out.add(out_at + 12).cast(),
                    _mm256_extracti128_si256::<1>(packed),
                );
                at += 32;
                out_at += 24;
            }
            (at, out_at)
        }
    }

    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn encode_block(
        raw: __m128i,
        shuffle: __m128i,
        offsets: __m128i,
        fifty_one: __m128i,
        twenty_five: __m128i,
    ) -> __m128i {
        let raw = _mm_shuffle_epi8(raw, shuffle);
        let t0 = _mm_and_si128(raw, _mm_set1_epi32(0x0fc0_fc00));
        let t1 = _mm_mulhi_epu16(t0, _mm_set1_epi32(0x0400_0040));
        let t2 = _mm_and_si128(raw, _mm_set1_epi32(0x003f_03f0));
        let t3 = _mm_mullo_epi16(t2, _mm_set1_epi32(0x0100_0010));
        let sextets = _mm_or_si128(t1, t3);
        let reduced = _mm_subs_epu8(sextets, fifty_one);
        let mask = _mm_cmpgt_epi8(sextets, twenty_five);
        let reduced = _mm_sub_epi8(reduced, mask);
        _mm_add_epi8(sextets, _mm_shuffle_epi8(offsets, reduced))
    }

    /// Encodes the whole 12-byte groups of `bytes` into `out`, returning how much of
    /// each was consumed. The caller checks `ssse3`.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn encode_prefix(bytes: &[u8], out: *mut u8) -> (usize, usize) {
        unsafe {
            let shuffle = _mm_loadu_si128(ENCODE_SHUFFLE.as_ptr().cast());
            let offsets = _mm_loadu_si128(ENCODE_OFFSETS.as_ptr().cast());
            let fifty_one = _mm_set1_epi8(51);
            let twenty_five = _mm_set1_epi8(25);
            let mut at = 0usize;
            let mut out_at = 0usize;
            while at + 16 <= bytes.len() {
                let raw = _mm_loadu_si128(bytes.as_ptr().add(at).cast());
                let ascii = encode_block(raw, shuffle, offsets, fifty_one, twenty_five);
                _mm_storeu_si128(out.add(out_at).cast(), ascii);
                at += 12;
                out_at += 16;
            }
            if at + 12 <= bytes.len() {
                let low = _mm_loadl_epi64(bytes.as_ptr().add(at).cast());
                let high = _mm_loadu_si32(bytes.as_ptr().add(at + 8).cast());
                let raw = _mm_unpacklo_epi64(low, high);
                let ascii = encode_block(raw, shuffle, offsets, fifty_one, twenty_five);
                _mm_storeu_si128(out.add(out_at).cast(), ascii);
                at += 12;
                out_at += 16;
            }
            (at, out_at)
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn encode_block_avx2(
        raw: __m256i,
        shuffle: __m256i,
        offsets: __m256i,
        fifty_one: __m256i,
        twenty_five: __m256i,
    ) -> __m256i {
        let raw = _mm256_shuffle_epi8(raw, shuffle);
        let t0 = _mm256_and_si256(raw, _mm256_set1_epi32(0x0fc0_fc00));
        let t1 = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x0400_0040));
        let t2 = _mm256_and_si256(raw, _mm256_set1_epi32(0x003f_03f0));
        let t3 = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x0100_0010));
        let sextets = _mm256_or_si256(t1, t3);
        let reduced = _mm256_subs_epu8(sextets, fifty_one);
        let mask = _mm256_cmpgt_epi8(sextets, twenty_five);
        let reduced = _mm256_sub_epi8(reduced, mask);
        _mm256_add_epi8(sextets, _mm256_shuffle_epi8(offsets, reduced))
    }

    /// Encodes the whole 24-byte pairs of groups of `bytes` into `out`, returning how much of
    /// each was consumed. The caller checks `avx2`.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn encode_prefix_avx2(bytes: &[u8], out: *mut u8) -> (usize, usize) {
        unsafe {
            let shuffle =
                _mm256_broadcastsi128_si256(_mm_loadu_si128(ENCODE_SHUFFLE.as_ptr().cast()));
            let offsets =
                _mm256_broadcastsi128_si256(_mm_loadu_si128(ENCODE_OFFSETS.as_ptr().cast()));
            let fifty_one = _mm256_set1_epi8(51);
            let twenty_five = _mm256_set1_epi8(25);
            let mut at = 0usize;
            let mut out_at = 0usize;
            while at + 28 <= bytes.len() {
                let low = _mm_loadu_si128(bytes.as_ptr().add(at).cast());
                let high = _mm_loadu_si128(bytes.as_ptr().add(at + 12).cast());
                let raw = _mm256_set_m128i(high, low);
                let ascii = encode_block_avx2(raw, shuffle, offsets, fifty_one, twenty_five);
                _mm256_storeu_si256(out.add(out_at).cast(), ascii);
                at += 24;
                out_at += 32;
            }
            if at + 12 <= bytes.len() {
                let low = _mm_loadl_epi64(bytes.as_ptr().add(at).cast());
                let high = _mm_loadu_si32(bytes.as_ptr().add(at + 8).cast());
                let raw = _mm_unpacklo_epi64(low, high);
                let ascii = encode_block(
                    raw,
                    _mm256_castsi256_si128(shuffle),
                    _mm256_castsi256_si128(offsets),
                    _mm256_castsi256_si128(fifty_one),
                    _mm256_castsi256_si128(twenty_five),
                );
                _mm_storeu_si128(out.add(out_at).cast(), ascii);
                at += 12;
                out_at += 16;
            }
            (at, out_at)
        }
    }
}

/// The same sixteen-byte lane as `x86`, in NEON: the encoder maps the sextets through
/// the sixty-four-byte alphabet in one `tbl`, and the decoder indexes the offset table
/// by the high nibble, with a nibble bitset rejecting a byte outside the alphabet.
#[cfg(target_arch = "aarch64")]
mod neon {
    #[allow(
        clippy::wildcard_imports,
        reason = "arch intrinsics: the module's whole API is register operations"
    )]
    use core::arch::aarch64::*;

    const OFFSETS: [u8; 16] = [255, 16, 19, 4, 191, 191, 185, 185, 0, 0, 0, 0, 0, 0, 0, 0];
    const LO: [u8; 16] = [
        0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1a, 0x1b, 0x1b, 0x1b,
        0x1a,
    ];
    const HI: [u8; 16] = [
        0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10,
    ];
    const PACK: [u8; 16] = [0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0, 0, 0, 0];
    const ENCODE_SHUFFLE: [u8; 16] = [1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10];

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn mulhi_u16(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
        unsafe {
            let low = vshrn_n_u32::<16>(vmull_u16(vget_low_u16(a), vget_low_u16(b)));
            let high = vshrn_n_u32::<16>(vmull_u16(vget_high_u16(a), vget_high_u16(b)));
            vcombine_u16(low, high)
        }
    }

    /// Decodes the whole 16-byte blocks of `text` into `out`, returning how much of
    /// each was consumed. The caller has four bytes of output slop.
    pub(super) fn decode_prefix(text: &[u8], out: *mut u8) -> (usize, usize) {
        // SAFETY: NEON is mandatory on aarch64, every load stays inside `text`, and every store stays inside the caller's four-byte-slack buffer.
        unsafe {
            let offsets = vld1q_u8(OFFSETS.as_ptr());
            let low_lut = vld1q_u8(LO.as_ptr());
            let high_lut = vld1q_u8(HI.as_ptr());
            let pack = vld1q_u8(PACK.as_ptr());
            let low_mask = vdupq_n_u8(0x0f);
            let mut at = 0usize;
            let mut out_at = 0usize;
            while at + 16 <= text.len() {
                let raw = vld1q_u8(text.as_ptr().add(at));
                let dash = vceqq_u8(raw, vdupq_n_u8(b'-'));
                let under = vceqq_u8(raw, vdupq_n_u8(b'_'));
                let raw = vbslq_u8(dash, vdupq_n_u8(b'+'), raw);
                let raw = vbslq_u8(under, vdupq_n_u8(b'/'), raw);
                let high = vshrq_n_u8::<4>(raw);
                let low = vandq_u8(raw, low_mask);
                let slash = vceqq_u8(raw, vdupq_n_u8(b'/'));
                let hash = vaddq_u8(high, slash);
                let sextets = vaddq_u8(raw, vqtbl1q_u8(offsets, hash));
                let low_bits = vqtbl1q_u8(low_lut, low);
                let high_bits = vqtbl1q_u8(high_lut, high);
                let valid = vceqq_u8(vandq_u8(low_bits, high_bits), vdupq_n_u8(0));
                if vminvq_u8(valid) != 0xff {
                    break;
                }
                let even = vuzp1q_u8(sextets, sextets);
                let odd = vuzp2q_u8(sextets, sextets);
                let pairs = vorrq_u16(
                    vshlq_n_u16::<6>(vmovl_u8(vget_low_u8(even))),
                    vmovl_u8(vget_low_u8(odd)),
                );
                let even_pairs = vuzp1q_u16(pairs, pairs);
                let odd_pairs = vuzp2q_u16(pairs, pairs);
                let groups = vorrq_u32(
                    vshlq_n_u32::<12>(vmovl_u16(vget_low_u16(even_pairs))),
                    vmovl_u16(vget_low_u16(odd_pairs)),
                );
                let bytes = vrev32q_u8(vreinterpretq_u8_u32(vshlq_n_u32::<8>(groups)));
                vst1q_u8(out.add(out_at), vqtbl1q_u8(bytes, pack));
                at += 16;
                out_at += 12;
            }
            (at, out_at)
        }
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn encode_block(
        raw: uint8x16_t,
        shuffle: uint8x16_t,
        alphabet: uint8x16x4_t,
        mul_high: uint16x8_t,
        mul_low: uint16x8_t,
    ) -> uint8x16_t {
        unsafe {
            let raw = vqtbl1q_u8(raw, shuffle);
            let t0 = vandq_u32(vreinterpretq_u32_u8(raw), vdupq_n_u32(0x0fc0_fc00));
            let t1 = mulhi_u16(vreinterpretq_u16_u32(t0), mul_high);
            let t2 = vandq_u32(vreinterpretq_u32_u8(raw), vdupq_n_u32(0x003f_03f0));
            let t3 = vmulq_u16(vreinterpretq_u16_u32(t2), mul_low);
            let sextets = vorrq_u32(vreinterpretq_u32_u16(t1), vreinterpretq_u32_u16(t3));
            vqtbl4q_u8(alphabet, vreinterpretq_u8_u32(sextets))
        }
    }

    /// Encodes the whole 12-byte groups of `bytes` into `out`, returning how much of
    /// each was consumed.
    pub(super) fn encode_prefix(bytes: &[u8], out: *mut u8) -> (usize, usize) {
        // SAFETY: NEON is mandatory on aarch64, the wide loop loads only while 16 bytes remain, the tail loads exactly 12, and every store fills its window.
        unsafe {
            let shuffle = vld1q_u8(ENCODE_SHUFFLE.as_ptr());
            let alphabet = vld1q_u8_x4(super::STD.as_ptr());
            let mul_high = vreinterpretq_u16_u32(vdupq_n_u32(0x0400_0040));
            let mul_low = vreinterpretq_u16_u32(vdupq_n_u32(0x0100_0010));
            let mut at = 0usize;
            let mut out_at = 0usize;
            while at + 16 <= bytes.len() {
                let raw = vld1q_u8(bytes.as_ptr().add(at));
                let ascii = encode_block(raw, shuffle, alphabet, mul_high, mul_low);
                vst1q_u8(out.add(out_at), ascii);
                at += 12;
                out_at += 16;
            }
            if at + 12 <= bytes.len() {
                let low = vld1_u8(bytes.as_ptr().add(at));
                let high = vld1_lane_u32::<0>(bytes.as_ptr().add(at + 8).cast(), vdup_n_u32(0));
                let raw = vcombine_u8(low, vreinterpret_u8_u32(high));
                let ascii = encode_block(raw, shuffle, alphabet, mul_high, mul_low);
                vst1q_u8(out.add(out_at), ascii);
                at += 12;
                out_at += 16;
            }
            (at, out_at)
        }
    }
}

pub fn value(byte: u8) -> Option<u8> {
    match DIGITS[usize::from(byte)] {
        255 => None,
        digit => Some(digit),
    }
}

/// The three bytes four digits stand for, or `None` for a byte outside the alphabet, padding or whitespace.
fn group_word(group: [u8; 4]) -> Option<[u8; 3]> {
    let t0 = u32::from(DIGITS[usize::from(group[0])]);
    let t1 = u32::from(DIGITS[usize::from(group[1])]);
    let t2 = u32::from(DIGITS[usize::from(group[2])]);
    let t3 = u32::from(DIGITS[usize::from(group[3])]);
    if (t0 | t1 | t2 | t3) & 0xc0 != 0 {
        return None;
    }
    let word = (t0 << 18) | (t1 << 12) | (t2 << 6) | t3;
    let bytes = word.to_be_bytes();
    Some([bytes[1], bytes[2], bytes[3]])
}

/// The bytes a partial group stands for, its digits left-aligned in the window.
fn group_tail(rest: &[u8]) -> Option<[u8; 3]> {
    let mut word = 0u32;
    for &byte in rest {
        let digit = DIGITS[usize::from(byte)];
        if digit == 255 {
            return None;
        }
        word = (word << 6) | u32::from(digit);
    }
    word <<= 6 * (4 - rest.len());
    let bytes = word.to_be_bytes();
    Some([bytes[1], bytes[2], bytes[3]])
}

/// One pass over the text and one output buffer: a pair of whole groups is eight table loads and one eight-byte store, whitespace is skipped where it lies, padding ends the text, and a 2..=3 digit tail keeps the bytes its padded group would have held.
#[must_use]
pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 4);
    let ptr: *mut u8 = out.as_mut_ptr();
    #[cfg(not(target_arch = "aarch64"))]
    let mut out_at = 0usize;
    #[cfg(target_arch = "aarch64")]
    let mut out_at;
    #[cfg(not(target_arch = "aarch64"))]
    let mut at = 0usize;
    #[cfg(target_arch = "aarch64")]
    let mut at;
    #[cfg(target_arch = "x86_64")]
    if text.len() >= 32 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: the feature is present, and the buffer reserves four bytes past the exact decoded length, so the wide stores stay inside it.
        let (done, written) = unsafe { x86::decode_prefix_avx2(text, ptr) };
        at = done;
        out_at = written;
    } else if text.len() >= 16 && std::is_x86_feature_detected!("ssse3") {
        // SAFETY: the feature is present, and the buffer reserves four bytes past the exact decoded length, so the wide store stays inside it.
        let (done, written) = unsafe { x86::decode_prefix(text, ptr) };
        at = done;
        out_at = written;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let (done, written) = neon::decode_prefix(text, ptr);
        at = done;
        out_at = written;
    }
    let (pairs, _) = text[at..].as_chunks::<8>();
    for pair in pairs {
        let t0 = u32::from(DIGITS[usize::from(pair[0])]);
        let t1 = u32::from(DIGITS[usize::from(pair[1])]);
        let t2 = u32::from(DIGITS[usize::from(pair[2])]);
        let t3 = u32::from(DIGITS[usize::from(pair[3])]);
        let t4 = u32::from(DIGITS[usize::from(pair[4])]);
        let t5 = u32::from(DIGITS[usize::from(pair[5])]);
        let t6 = u32::from(DIGITS[usize::from(pair[6])]);
        let t7 = u32::from(DIGITS[usize::from(pair[7])]);
        if (t0 | t1 | t2 | t3 | t4 | t5 | t6 | t7) & 0xc0 != 0 {
            break;
        }
        let first = (t0 << 18) | (t1 << 12) | (t2 << 6) | t3;
        let second = (t4 << 18) | (t5 << 12) | (t6 << 6) | t7;
        // SAFETY: a pair writes eight bytes at a six-byte stride, and the buffer's `+3` slack covers the two bytes past the logical length; the last pair's own store lands inside it.
        unsafe {
            ptr.add(out_at)
                .cast::<u64>()
                .write_unaligned(u64::from_ne_bytes([
                    (first >> 16) as u8,
                    (first >> 8) as u8,
                    first as u8,
                    (second >> 16) as u8,
                    (second >> 8) as u8,
                    second as u8,
                    0,
                    0,
                ]));
        }
        out_at += 6;
        at += 8;
    }
    // SAFETY: `out_at` counts the bytes the loop wrote, and every one of them was written above.
    unsafe { out.set_len(out_at) };
    if at == text.len() {
        return (!out.is_empty()).then_some(out);
    }
    let mut group = [0u8; 4];
    let mut held = 0usize;
    let mut saw = false;
    for &byte in &text[at..] {
        if byte == b'=' {
            break;
        }
        if byte.is_ascii_whitespace() {
            continue;
        }
        group[held] = byte;
        held += 1;
        saw = true;
        if held == 4 {
            out.extend_from_slice(&group_word(group)?);
            held = 0;
        }
    }
    if held == 1 {
        return None;
    }
    if held != 0 {
        out.extend_from_slice(&group_tail(&group[..held])?[..held - 1]);
    }
    if out.is_empty() && !saw {
        return None;
    }
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
            let mut staged = vec![0u8; encoded_len(len)];
            let written = encode_parts_into(&[&bytes], &mut staged).expect("exact length");
            assert_eq!(written, staged.len(), "coded length for {len} bytes");
            assert_eq!(
                std::str::from_utf8(&staged).expect("ascii"),
                encode(&bytes),
                "{len} bytes"
            );
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

    /// The staged decoder exactly as it stood, kept as the oracle the one-pass form must answer with the same verdict and the same bytes on every input.
    fn decode_staged(text: &[u8]) -> Option<Vec<u8>> {
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

    /// Every prefix of every coded length, then arbitrary bytes over both alphabets, padding, whitespace and the invalid range: the one-pass decoder and the staged one must agree on the bytes **and** the verdict.
    #[test]
    fn the_one_pass_decoder_is_the_staged_decoder_at_every_input() {
        for len in 0..=96usize {
            let raw: Vec<u8> = (0..len).map(|i| (i * 7 + 11) as u8).collect();
            let coded = encode(&raw).replace('+', "-").replace('/', "_");
            for cut in 0..=coded.len() {
                let head = &coded.as_bytes()[..cut];
                assert_eq!(decode(head), decode_staged(head), "prefix {cut} of {len}");
            }
        }
        let alphabet =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_= \t\n\r!";
        let mut word = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..20_000 {
            let len = (word as usize >> 7) % 41;
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                word ^= word << 13;
                word ^= word >> 7;
                word ^= word << 17;
                input.push(alphabet[(word as usize >> 11) % alphabet.len()]);
            }
            assert_eq!(decode(&input), decode_staged(&input), "{input:?}");
        }
    }

    /// The wide block and the scalar walk agree on every byte in every lane: a
    /// 32-byte fill of each value, then each value at each of the thirty-two positions.
    #[test]
    fn the_wide_block_is_the_scalar_walk_at_every_byte() {
        for fill in 0..=255u8 {
            let input = [fill; 32];
            assert_eq!(decode(&input), decode_staged(&input), "fill {fill}");
        }
        for byte in 0..=255u8 {
            for at in 0..32 {
                let mut input = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                input[at] = byte;
                assert_eq!(decode(&input), decode_staged(&input), "byte {byte} at {at}");
            }
        }
    }

    /// The wide coder is the window coder at every length through several blocks and
    /// every tail, so a group the wide loop takes and one the scalar loop takes agree.
    #[test]
    fn the_wide_coder_is_the_window_coder_at_every_length() {
        for len in 0..=400usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect();
            let mut window = vec![0u8; encoded_len(len)];
            let written = encode_parts_into(&[&bytes], &mut window).expect("exact length");
            assert_eq!(written, window.len(), "coded length for {len}");
            assert_eq!(encode(&bytes).as_bytes(), window.as_slice(), "{len} bytes");
        }
    }

    /// The twelve-byte lane is the generic walk at every byte in every position, then over random fills, so its two loads and two stores are not a new spelling of the bytes.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_twelve_byte_lane_is_the_generic_walk_at_every_byte() {
        let base = *b"0123456789ab";
        let mut want = vec![0u8; encoded_len(12)];
        for at in 0..12 {
            for byte in 0..=255u8 {
                let mut bytes = base;
                bytes[at] = byte;
                encode_parts_into(&[&bytes], &mut want).expect("exact length");
                assert_eq!(
                    encode(&bytes).as_bytes(),
                    want.as_slice(),
                    "byte {byte} at {at}"
                );
            }
        }
        let mut word = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..4096 {
            let mut bytes = [0u8; 12];
            for byte in &mut bytes {
                word ^= word << 13;
                word ^= word >> 7;
                word ^= word << 17;
                *byte = word as u8;
            }
            encode_parts_into(&[&bytes], &mut want).expect("exact length");
            assert_eq!(encode(&bytes).as_bytes(), want.as_slice(), "{bytes:?}");
        }
    }

    /// The one buffer the decoder hands back is the only one it takes: the staged form allocated the filtered text as well, so the counting allocator is what says the pass is gone.
    #[test]
    fn the_decoder_takes_one_buffer_and_the_staged_form_took_two() {
        let coded = encode(&(0..96).map(|i| (i * 7 + 11) as u8).collect::<Vec<_>>());
        let (decoded, counts) = crate::alloc_count::measure(|| decode(coded.as_bytes()));
        assert_eq!(decoded.expect("decodes").len(), 96);
        assert_eq!(counts.allocs, 1, "only the output buffer: {counts:?}");
        assert_eq!(counts.zeroed, 0, "the output is written as it is decoded");
        let (_, staged) = crate::alloc_count::measure(|| decode_staged(coded.as_bytes()));
        assert!(
            staged.allocs > counts.allocs,
            "the staged form paid more: {staged:?}"
        );
    }

    /// The decoder, and nothing else: 64 passes over a 96-byte coding and a 95-byte padded one, the decoded bytes folded into a pinned `u32` so the loop cannot be folded away.
    #[test]
    fn the_alphabet_decoder_costs_the_groups_and_nothing_else() {
        let bytes: Vec<u8> = (0..96).map(|i| (i * 7 + 11) as u8).collect();
        let whole = encode(&bytes);
        let padded = encode(&bytes[..95]);
        let mut fold: u32 = 0;
        for _ in 0..64 {
            for coded in [&whole, &padded] {
                for byte in decode(coded.as_bytes()).expect("decodes") {
                    fold = fold.wrapping_mul(31).wrapping_add(u32::from(byte));
                }
            }
        }
        assert_eq!(
            fold, 0x69b9_f000,
            "64 passes over a whole coding and a padded one, folded after each"
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
