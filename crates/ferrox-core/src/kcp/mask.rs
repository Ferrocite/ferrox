//! The mKCP legacy masks: what the pinned reference stacks under the KCP
//! framing on the datagram boundary (`transport/internet/finalmask/mkcp`).
//!
//! Three families, all applied per datagram below the segment framer:
//!
//! - [`Entry::Original`] — the legacy `none` frame: `fnv32a(len‖payload) ‖ BE16(len) ‖ payload`,
//!   then a lag-4 XOR cascade over the whole frame. The cascade makes each
//!   byte a prefix (encode) or a one-step difference (decode) of the bytes
//!   four positions back, so the first four bytes — the hash — go over the
//!   wire untransformed and every later byte is chained inside its own
//!   residue class mod 4.
//! - [`Entry::Header`] — a fake protocol header (`dns`, `dtls`, `srtp`,
//!   `utp`, `wechat`, `wireguard`) prepended per datagram; the receiver skips
//!   its size and never validates it, so a mismatched header is refused by
//!   the framer behind it, not by the header itself.
//! - [`Entry::Aes`] — AES-128-GCM under a password-derived key
//!   (`SHA256(password)[0..16]`), the wire frame `nonce(12) ‖ ct ‖ tag(16)`.
//!   A bad tag drops the datagram, which is what keeps sessions apart.
//!
//! Entries chain in wire order, outermost first: decode strips them left to
//! right, encode applies them right to left, each entry treating everything
//! to its right as its own payload — the composition the reference's header
//! manager performs with its per-connection buffer.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use sha2::{Digest as _, Sha256};

/// The fake-header kinds the reference ships, by their `header.Config` ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    Dns,
    Dtls,
    Srtp,
    Utp,
    Wechat,
    WireGuard,
}

/// What a configured mask entry asks for, before any bytes are derived from
/// it. The app parses JSON into these; [`Mask::from_spec`] derives the wire
/// template, the key or the domain packing once, at config time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    Original,
    Header(HeaderKind),
    /// `dns` with a query name; the reference builds the header from the
    /// wire packing of `domain + "."`.
    HeaderDns {
        domain: String,
    },
    Aes {
        password: String,
    },
}

/// A spec the wire cannot carry: a label too long, a name too big, an
/// unusable domain spelling. The app refuses the carrier rather than dialing
/// unmasked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecError;

/// Which dynamic bytes an entry rewrites in its template on every datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    /// The template is the whole header; nothing moves.
    None,
    /// `dns`: a fresh random transaction id over bytes `0..2`.
    DnsTxid,
    /// `srtp`: a big-endian counter that starts at one and increments first.
    SrtpNumber,
    /// `wechat`: a big-endian sequence number that starts at one.
    WechatSn,
    /// `dtls`: a big-endian sequence and a record length that walks up by 17
    /// and, past 100, drops back by 50.
    Dtls,
}

/// The derived key sits beside the cipher so two chains compare by key
/// without printing or cloning the schedule.
#[derive(Clone)]
struct AesEntry {
    key: [u8; 16],
    cipher: Aes128Gcm,
}

impl PartialEq for AesEntry {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl std::fmt::Debug for AesEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The derived key is not printed; same reason as `Mask` below.
        f.debug_struct("AesEntry").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
enum Entry {
    Original,
    Header { template: Box<[u8]>, fill: Fill },
    Aes(std::sync::Arc<AesEntry>),
}

impl Entry {
    fn is_aes(&self) -> bool {
        matches!(self, Self::Aes(_))
    }

    fn size(&self) -> usize {
        match self {
            // The `original` frame leads with four hash bytes and two length bytes, both written into this entry's gap.
            Self::Original => 6,
            Self::Header { template, .. } => template.len(),
            // Only the nonce is reserved; the tag grows the frame on seal, as the reference's AEAD `Seal` overruns its buffer.
            Self::Aes(_) => 12,
        }
    }
}

/// An ordered set of mask entries in wire order (outermost first). Empty
/// means no mask: the framer's bytes go out raw, exactly as before.
#[derive(Clone, Default)]
pub struct Mask {
    entries: Box<[Entry]>,
}

impl std::fmt::Debug for Mask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is never printed; the shape is enough for a log line.
        f.debug_struct("Mask")
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl Mask {
    /// Builds the wire form of a configured chain: derives keys and header
    /// templates once instead of per datagram. The JSON list order is
    /// outer-first after the reference's single reversal, so the app hands
    /// the parsed entries here in the order they appear on the wire.
    ///
    /// # Errors
    ///
    /// A `dns` domain that does not pack (a label of 64 or more bytes, an
    /// escaped dot, a name over the 256-byte wire budget) fails here.
    pub fn from_spec(specs: &[Spec]) -> Result<Self, SpecError> {
        let mut entries = Vec::with_capacity(specs.len());
        for spec in specs {
            entries.push(match spec {
                Spec::Original => Entry::Original,
                Spec::Header(kind) => Entry::Header {
                    template: Box::from(fixed_template(*kind).ok_or(SpecError)?),
                    fill: fill_of(*kind),
                },
                Spec::HeaderDns { domain } => Entry::Header {
                    template: Box::from(dns_template(domain).ok_or(SpecError)?),
                    fill: Fill::DnsTxid,
                },
                Spec::Aes { password } => {
                    let hashed = Sha256::digest(password.as_bytes());
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&hashed[..16]);
                    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| SpecError)?; // a 16-byte key never fails; the map keeps the `?` off panics
                    Entry::Aes(std::sync::Arc::new(AesEntry { key, cipher }))
                }
            });
        }
        Ok(Self {
            entries: entries.into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Strips the mask from a received datagram in place and returns the
    /// framer's bytes inside the caller's own buffer. A datagram that is
    /// short for the chain, or that fails the `original` hash or the AES tag,
    /// answers `None` — the reference drops those packets too.
    pub fn decode_in_place<'a>(&self, buf: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let mut rest = buf;
        for entry in &self.entries {
            rest = match entry {
                Entry::Original => decode_original(rest)?,
                Entry::Aes(aes) => decode_aes(rest, &aes.cipher)?,
                Entry::Header { template, .. } => {
                    if rest.len() < template.len() {
                        return None;
                    }
                    &mut rest[template.len()..]
                }
            };
        }
        Some(rest)
    }
}

impl PartialEq for Mask {
    fn eq(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .zip(other.entries.iter())
                .all(|(a, b)| match (a, b) {
                    (Entry::Original, Entry::Original) => true,
                    (
                        Entry::Header {
                            template: t1,
                            fill: f1,
                        },
                        Entry::Header {
                            template: t2,
                            fill: f2,
                        },
                    ) => t1 == t2 && f1 == f2,
                    (Entry::Aes(a), Entry::Aes(b)) => std::sync::Arc::ptr_eq(a, b) || **a == **b,
                    _ => false,
                })
    }
}

impl Eq for Mask {}

/// The per-connection encoding side: header counters start where the
/// reference's constructor leaves them (zero, with the first datagram
/// carrying one) and the scratch buffer keeps its capacity across frames.
#[derive(Debug)]
pub struct Encoder {
    entries: Box<[Entry]>,
    /// Prefix offset of each entry's gap in the datagram, plus one sentinel
    /// at the inner edge, so no sum is recomputed per frame.
    prefixes: Box<[u16]>,
    counters: Box<[Counter]>,
    scratch: Vec<u8>,
    /// The datagram's fixed overhead beyond the framer's bytes: every gap
    /// plus every AES tag the chain will append.
    reserve: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct Counter {
    number: u16,
    sn: u32,
    seq: u32,
    record_len: u16,
}

impl Encoder {
    #[must_use]
    pub fn new(mask: &Mask) -> Self {
        let mut prefixes = Vec::with_capacity(mask.entries.len() + 1);
        let mut off = 0usize;
        let mut tag_extra = 0usize;
        for entry in &mask.entries {
            prefixes.push(off as u16);
            off += entry.size();
            if entry.is_aes() {
                tag_extra += 16;
            }
        }
        prefixes.push(off as u16);
        let counters = vec![Counter::default(); mask.entries.len()].into_boxed_slice();
        Self {
            entries: mask.entries.clone(),
            prefixes: prefixes.into_boxed_slice(),
            counters,
            scratch: Vec::new(),
            reserve: off + tag_extra,
        }
    }

    /// Wraps `frame` (the framer's datagram) into the masked bytes. The
    /// payload is copied once into the held scratch, at the gap sum, and
    /// every entry then transforms or fills its own region around it — the
    /// same single copy the reference's 4096-byte manager buffer makes,
    /// without the per-call allocation. `None` only when the machine has no
    /// entropy to spend on a nonce or a transaction id.
    pub fn encode(&mut self, frame: &[u8]) -> Option<&[u8]> {
        let wire_max = self.reserve + frame.len();
        if self.scratch.len() < wire_max {
            self.scratch.resize(wire_max, 0);
        }
        let payload_at = usize::from(self.prefixes[self.prefixes.len() - 1]);
        self.scratch[payload_at..wire_max][..frame.len()].copy_from_slice(frame);

        let mut total = payload_at + frame.len();
        for i in (0..self.entries.len()).rev() {
            let base = usize::from(self.prefixes[i]);
            match &self.entries[i] {
                Entry::Header { template, fill } => {
                    let gap = &mut self.scratch[base..base + template.len()];
                    gap.copy_from_slice(template);
                    let c = &mut self.counters[i];
                    match fill {
                        Fill::None => {}
                        Fill::DnsTxid => {
                            let mut two = [0u8; 2];
                            if getrandom::getrandom(&mut two).is_err() {
                                return None; // never reuse the template's zero id
                            }
                            gap[..2].copy_from_slice(&two);
                        }
                        Fill::SrtpNumber => {
                            c.number = c.number.wrapping_add(1);
                            gap[2..4].copy_from_slice(&c.number.to_be_bytes());
                        }
                        Fill::WechatSn => {
                            c.sn = c.sn.wrapping_add(1);
                            gap[2..6].copy_from_slice(&c.sn.to_be_bytes());
                        }
                        Fill::Dtls => {
                            gap[7..11].copy_from_slice(&c.seq.to_be_bytes());
                            c.seq = c.seq.wrapping_add(1);
                            gap[11..13].copy_from_slice(&c.record_len.to_be_bytes());
                            c.record_len = next_dtls_length(c.record_len);
                        }
                    }
                }
                Entry::Original => {
                    // The frame is [hash(4) len(2) everything to the right].
                    let Some(plain_len) = u16::try_from(total - base - 6).ok() else {
                        return None; // a frame over the 16-bit length field is never a kcp datagram
                    };
                    self.scratch[base + 4..base + 6].copy_from_slice(&plain_len.to_be_bytes());
                    let hash = fnv32a(&self.scratch[base + 4..total]);
                    self.scratch[base..base + 4].copy_from_slice(&hash.to_be_bytes());
                    cascade_fwd(&mut self.scratch[base..total]);
                }
                Entry::Aes(aes) => {
                    let nonce_at = base;
                    if getrandom::getrandom(&mut self.scratch[nonce_at..nonce_at + 12]).is_err() {
                        return None; // no entropy: drop the frame, never send a reused nonce
                    }
                    let (nonce_view, pt) = self.scratch[nonce_at..total].split_at_mut(12);
                    let Ok(tag) = aes.cipher.encrypt_in_place_detached(
                        Nonce::from_slice(nonce_view),
                        &[],
                        pt,
                    ) else {
                        return None; // in-place encryption of a fresh buffer cannot fail; keep it total
                    };
                    self.scratch[total..total + 16].copy_from_slice(&tag[..]);
                    total += 16;
                }
            }
        }
        Some(&self.scratch[..total])
    }
}

fn next_dtls_length(len: u16) -> u16 {
    let grown = len.wrapping_add(17);
    if grown > 100 {
        grown - 50
    } else {
        grown
    }
}

/// FNV-1a over 32 bits, the hash the `original` frame authenticates with.
fn fnv32a(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in bytes {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// The encode-side cascade: each 4-byte chunk of the frame from `r[4..]`
/// becomes its own value `XORed` with the already-transformed chunk before it,
/// a prefix XOR inside each residue class. Written as two log-doubled
/// shift-xor steps over a 16-byte block (four words need spans 1 and 2) with
/// the previous block's last word `XORed` into the block's first word, so the
/// dependency depth is two vector steps per four chunks instead of one per
/// chunk, and a byte tail for a length that is not a multiple of sixteen.
/// The result is the same as the naive ascending loop — the property test
/// says so for every length under 210 — because a prefix XOR over a class is
/// exactly repeated `chunk[j] ^= chunk[j-1]`.
fn cascade_fwd(r: &mut [u8]) {
    let len = r.len();
    if len < 5 {
        return; // nothing past the hash to chain
    }
    let mut prev = [r[0], r[1], r[2], r[3]];
    let mut i = 4;
    while i + 16 <= len {
        let mut v = u128::from_le_bytes(r[i..i + 16].try_into().unwrap());
        v ^= u128::from(u32::from_le_bytes(prev)); // carry lands in word 0; the scan spreads it
        v ^= v << 32;
        v ^= v << 64;
        let out = v.to_le_bytes();
        r[i..i + 16].copy_from_slice(&out);
        prev.copy_from_slice(&out[12..16]);
        i += 16;
    }
    // The tail is four-aligned from the base: whole chunks, then bytes.
    while i + 4 <= len {
        for k in 0..4 {
            r[i + k] ^= prev[k];
        }
        prev.copy_from_slice(&r[i..i + 4]);
        i += 4;
    }
    for k in i..len {
        r[k] ^= r[k - 4];
    }
}

/// The decode-side cascade: `r[i] ^= r[i-4]` walked downward, which reads
/// every source byte before anything to its left is written, so it is a
/// simultaneous one-step difference — no chain, no carry between chunks.
/// This is the exact inverse of [`cascade_fwd`] over the same length; the
/// reference pads its buffer to a multiple of four before this pass, and the
/// pad only ever feeds bytes the reference truncates away afterwards, so the
/// ragged tail is handled here directly instead.
fn cascade_bkd(r: &mut [u8]) {
    let len = r.len();
    // The ragged top bytes first, descending: their `i-4` sources lie in lower territory nothing has written yet.
    let mut i = len;
    while i > 4 && !i.is_multiple_of(4) {
        i -= 1;
        r[i] ^= r[i - 4];
    }
    // Whole chunks from the top down: the higher chunk XORs the lower one, still holding its original bytes.
    while i >= 8 {
        let hi = i - 4;
        let lo = i - 8;
        for k in 0..4 {
            r[hi + k] ^= r[lo + k];
        }
        i -= 4;
    }
    // The lowest chunk is the hash itself: unchanged, as on encode.
}

fn decode_original(buf: &mut [u8]) -> Option<&mut [u8]> {
    if buf.len() < 6 {
        return None;
    }
    cascade_bkd(buf);
    let hash = u32::from_be_bytes(buf[0..4].try_into().ok()?);
    if hash != fnv32a(&buf[4..]) {
        return None;
    }
    let len = u16::from_be_bytes(buf[4..6].try_into().ok()?) as usize;
    if len != buf.len() - 6 {
        return None;
    }
    Some(&mut buf[6..])
}

fn decode_aes<'a>(buf: &'a mut [u8], cipher: &Aes128Gcm) -> Option<&'a mut [u8]> {
    if buf.len() < 28 {
        return None;
    }
    let split = buf.len() - 16;
    let (body, tail) = buf.split_at_mut(split);
    let (nonce_view, pt) = body.split_at_mut(12);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce_view),
            &[],
            &mut pt[..],
            Tag::from_slice(tail),
        )
        .ok()?;
    Some(pt)
}

fn fixed_template(kind: HeaderKind) -> Option<Vec<u8>> {
    Some(match kind {
        HeaderKind::Srtp | HeaderKind::Utp => vec![0, 0, 0, 0],
        HeaderKind::WireGuard => vec![0x04, 0, 0, 0],
        HeaderKind::Wechat => vec![
            0xa1, 0x08, 0, 0, 0, 0, 0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30,
        ],
        HeaderKind::Dtls => vec![23, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // The `dns` template is name-dependent and built by `dns_template`.
        HeaderKind::Dns => return None,
    })
}

fn fill_of(kind: HeaderKind) -> Fill {
    match kind {
        HeaderKind::Srtp => Fill::SrtpNumber,
        HeaderKind::Wechat => Fill::WechatSn,
        HeaderKind::Dtls => Fill::Dtls,
        HeaderKind::Utp | HeaderKind::WireGuard => Fill::None,
        HeaderKind::Dns => Fill::DnsTxid,
    }
}

/// The fixed bytes of a `dns` query header for `domain`: the twelve-byte
/// query preamble, the wire packing of `domain + "."`, and the `A`/`IN`
/// question trailer. Bytes `0..2` (the transaction id) stay zero here and
/// are randomized per datagram, as the reference serializes it.
///
/// A domain carrying an escaped dot is refused rather than packed: the
/// reference supports the escape, this row does not need it to speak the
/// method, and a config that uses one is refused by name instead of being
/// sent as different bytes.
fn dns_template(domain: &str) -> Option<Vec<u8>> {
    if domain.contains('\\') || domain.is_empty() {
        return None;
    }
    let mut name = Vec::with_capacity(domain.len() + 1);
    let mut labels: Vec<&str> = domain.split('.').collect();
    // The reference appends "." and the packer's trailing dot becomes the root terminator, not a zero-length label.
    if labels.last() == Some(&"") {
        labels.pop();
    }
    for label in labels {
        if label.len() >= 64 {
            return None;
        }
        name.push(label.len() as u8);
        name.extend_from_slice(label.as_bytes());
    }
    name.push(0);
    if name.len() > 255 {
        return None;
    }
    let mut header = Vec::with_capacity(16 + name.len());
    header.extend_from_slice(&[
        0, 0, // transaction id, randomized per datagram
        0x01, 0x00, // flags: standard query
        0x00, 0x01, // questions
        0x00, 0x00, // answer RRs
        0x00, 0x00, // authority RRs
        0x00, 0x00, // additional RRs
    ]);
    header.extend_from_slice(&name);
    header.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    Some(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The naive ascending loop the reference documents its cascade with.
    fn fwd_naive(r: &mut [u8]) {
        for i in 4..r.len() {
            r[i] ^= r[i - 4];
        }
    }

    /// The naive descending loop, the reference's own inverse pass.
    fn bkd_naive(r: &mut [u8]) {
        for i in (4..r.len()).rev() {
            r[i] ^= r[i - 4];
        }
    }

    #[test]
    fn the_fast_cascade_is_the_naive_one_at_every_length() {
        // The block version's arithmetic on the input the round numbers hide: every length through 209, ragged included.
        for len in 0..=209usize {
            let base: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(31) ^ 0x5a)
                .collect();
            let mut fast = base.clone();
            let mut slow = base.clone();
            cascade_fwd(&mut fast);
            fwd_naive(&mut slow);
            assert_eq!(fast, slow, "fwd at len {len}");
            let mut fast2 = fast.clone();
            cascade_bkd(&mut fast2);
            assert_eq!(fast2, base, "bkd did not undo fwd at len {len}");
            let mut slow2 = fast.clone();
            bkd_naive(&mut slow2);
            assert_eq!(slow2, base, "naive bkd disagrees at len {len}");
        }
    }

    #[test]
    fn the_cascade_leaves_the_hash_bytes_alone() {
        let mut frame = b"ABCD0123456789abcdef".to_vec();
        cascade_fwd(&mut frame);
        assert_eq!(&frame[..4], b"ABCD");
        cascade_bkd(&mut frame);
        assert_eq!(frame, b"ABCD0123456789abcdef");
    }

    fn seal(plain: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 6 + plain.len()];
        frame[4..6].copy_from_slice(&(plain.len() as u16).to_be_bytes());
        frame[6..].copy_from_slice(plain);
        let hash = fnv32a(&frame[4..]);
        frame[..4].copy_from_slice(&hash.to_be_bytes());
        cascade_fwd(&mut frame);
        frame
    }

    #[test]
    fn the_original_frame_round_trips_and_the_checks_fire() {
        let mask = Mask::from_spec(&[Spec::Original]).expect("original builds");
        for len in [0usize, 1, 2, 3, 5, 8, 1332, 1333, 4090] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut buf = seal(&plain);
            // The decoded payload is the tail of the same buffer: no copy.
            let base = buf.as_ptr() as usize;
            let got = mask.decode_in_place(&mut buf).expect("valid frame decodes");
            assert_eq!(got, plain.as_slice(), "round trip at len {len}");
            assert_eq!(
                got.as_ptr() as usize - base,
                6,
                "the plaintext must sit inside the datagram"
            );
        }
        // A tampered byte breaks the hash, not just the bytes.
        let mut buf = seal(b"payload");
        let at = buf.len() - 1;
        buf[at] ^= 1;
        assert_eq!(mask.decode_in_place(&mut buf), None, "tamper must drop");
        // A wrong length field fails too: the length lies inside the hashed span, so the hash check fires.
        let mut buf = seal(b"payload");
        buf[5] ^= 0xff;
        assert_eq!(
            mask.decode_in_place(&mut buf),
            None,
            "length flip must drop"
        );
    }

    #[test]
    fn a_forged_original_leaves_the_buffer_untouched_on_reject() {
        let mask = Mask::from_spec(&[Spec::Original]).expect("builds");
        let forged = b"not a real frame!!".to_vec();
        let mut buf = forged.clone();
        // The reference's `if n < sum` guard plus the hash check: a short forged datagram is refused outright.
        assert_eq!(mask.decode_in_place(&mut buf[..5]), None);
        assert_eq!(&buf[..5], &forged[..5]);
    }

    #[test]
    fn the_srtp_counter_starts_at_one_and_walks() {
        let mask = Mask::from_spec(&[Spec::Header(HeaderKind::Srtp)]).expect("builds");
        let mut enc = Encoder::new(&mask);
        let first = enc.encode(b"x").expect("encodes").to_vec();
        let second = enc.encode(b"x").expect("encodes").to_vec();
        assert_eq!(&first[..4], &[0, 0, 0, 1]);
        assert_eq!(&second[..4], &[0, 0, 0, 2]);
        assert_eq!(&first[4..], b"x");
    }

    #[test]
    fn the_wechat_header_carries_its_sequence() {
        let mask = Mask::from_spec(&[Spec::Header(HeaderKind::Wechat)]).expect("builds");
        let mut enc = Encoder::new(&mask);
        let frame = enc.encode(b"hi").expect("encodes").to_vec();
        assert_eq!(
            &frame[..13],
            &[0xa1, 0x08, 0, 0, 0, 1, 0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]
        );
        assert_eq!(&frame[13..], b"hi");
    }

    #[test]
    fn the_dtls_length_wraps_at_the_reference_boundary() {
        // Written values: 0, 17, 34, 51, 68, 85, then 102 fails the `> 100` test only after the update, so the seventh frame carries 52.
        let mut lens = Vec::new();
        let mut len = 0u16;
        for _ in 0..8 {
            lens.push(len);
            len = next_dtls_length(len);
        }
        assert_eq!(lens, vec![0, 17, 34, 51, 68, 85, 52, 69]);
        let mask = Mask::from_spec(&[Spec::Header(HeaderKind::Dtls)]).expect("builds");
        let mut enc = Encoder::new(&mask);
        let f1 = enc.encode(b"a").expect("encodes").to_vec();
        let f7 = {
            for _ in 0..5 {
                enc.encode(b"a");
            }
            enc.encode(b"a").expect("encodes").to_vec()
        };
        assert_eq!(&f1[..13], &[23, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&f7[7..11], &6u32.to_be_bytes());
        assert_eq!(&f7[11..13], &52u16.to_be_bytes());
    }

    #[test]
    fn the_utp_and_wireguard_headers_are_fixed() {
        let utp = Mask::from_spec(&[Spec::Header(HeaderKind::Utp)]).expect("builds");
        let wg = Mask::from_spec(&[Spec::Header(HeaderKind::WireGuard)]).expect("builds");
        let mut e1 = Encoder::new(&utp);
        let mut e2 = Encoder::new(&wg);
        assert_eq!(&e1.encode(b"q").expect("encodes")[..4], &[0, 0, 0, 0]);
        assert_eq!(&e2.encode(b"q").expect("encodes")[..4], &[0x04, 0, 0, 0]);
    }

    #[test]
    fn the_dns_header_packs_the_way_the_reference_does() {
        let t = dns_template("www.baidu.com").expect("packs");
        // 12-byte preamble + 3 labels + root + 4-byte question trailer.
        assert_eq!(t.len(), 31);
        assert_eq!(&t[2..12], &[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&t[12..27], b"\x03www\x05baidu\x03com\x00");
        assert_eq!(&t[27..], &[0x00, 0x01, 0x00, 0x01]);
        // A trailing dot from the config is the terminator, not an empty label.
        let same = dns_template("www.baidu.com.").expect("packs");
        assert_eq!(same, t);
        // A leading dot keeps the empty first label, as the packer does.
        let leading = dns_template(".example.com").expect("packs");
        assert_eq!(&leading[12..13], &[0]);
        // Labels at 64 and over are refused; 63 is the largest that packs.
        assert_eq!(dns_template(&"a".repeat(63)), dns_template(&"a".repeat(63)));
        assert!(dns_template(&"a".repeat(64)).is_none());
        assert!(dns_template(r"a\.b").is_none());
        assert!(dns_template("").is_none());
    }

    #[test]
    fn the_dns_transaction_id_moves_every_datagram() {
        let mask = Mask::from_spec(&[Spec::HeaderDns {
            domain: "www.baidu.com".to_owned(),
        }])
        .expect("builds");
        let mut enc = Encoder::new(&mask);
        let f1 = enc.encode(b"k").expect("encodes").to_vec();
        let f2 = enc.encode(b"k").expect("encodes").to_vec();
        assert_eq!(&f1[2..], &f2[2..], "only the id may differ");
        assert_ne!(&f1[..2], &f2[..2], "the id repeats within two frames");
        assert_eq!(mask.decode_in_place(&mut f1.clone()).expect("skips"), b"k");
    }

    #[test]
    fn aes_seals_and_opens_and_rejects_a_tamper() {
        let mask = Mask::from_spec(&[Spec::Aes {
            password: "test-mask-pass".to_owned(),
        }])
        .expect("builds");
        let mut enc = Encoder::new(&mask);
        let mut wire = enc.encode(b"hello mkcp").expect("encodes").to_vec();
        assert_eq!(wire.len(), 12 + 10 + 16, "nonce and tag around the frame");
        let other = Mask::from_spec(&[Spec::Aes {
            password: "wrong-pass".to_owned(),
        }])
        .expect("builds");
        assert_eq!(
            other.decode_in_place(&mut wire.clone()),
            None,
            "wrong key drops"
        );
        let at = wire.len() - 1;
        wire[at] ^= 1;
        assert_eq!(mask.decode_in_place(&mut wire), None, "tag check fires");
        let mut wire = enc.encode(b"hello mkcp").expect("encodes").to_vec();
        assert_eq!(
            mask.decode_in_place(&mut wire).expect("opens"),
            b"hello mkcp"
        );
    }

    #[test]
    fn a_stacked_chain_encodes_outer_first_and_strips_in_order() {
        // The order the reference leaves a `[aes, srtp]` JSON list in after its single reversal: srtp outermost.
        let mask = Mask::from_spec(&[
            Spec::Header(HeaderKind::Srtp),
            Spec::Aes {
                password: "p".to_owned(),
            },
        ])
        .expect("chain builds");
        let mut enc = Encoder::new(&mask);
        let mut wire = enc.encode(b"seg").expect("encodes").to_vec();
        assert_eq!(&wire[..4], &[0, 0, 0, 1], "srtp outside");
        assert_eq!(wire.len(), 4 + 12 + 3 + 16);
        let plain = mask.decode_in_place(&mut wire).expect("chain opens");
        assert_eq!(plain, b"seg");
    }

    #[test]
    fn the_scratch_holds_its_capacity_across_frames() {
        let mask = Mask::from_spec(&[Spec::Original]).expect("builds");
        let mut enc = Encoder::new(&mask);
        let mut settled = 0usize;
        for round in 0..32 {
            let len = 64 + (round % 5) * 13;
            let frame: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let _ = enc.encode(&frame);
            if round == 2 {
                settled = enc.scratch.capacity();
            } else if round > 2 {
                assert_eq!(
                    enc.scratch.capacity(),
                    settled,
                    "round {round}: the scratch grew, so a frame allocated"
                );
            }
        }
    }

    #[test]
    fn the_original_overshoot_of_a_chain_is_the_whole_right_region() {
        // An `original` outside an `srtp`: its length field counts the inner header as payload, as the reference's `Seal` treats everything right of it.
        let mask = Mask::from_spec(&[Spec::Original, Spec::Header(HeaderKind::Srtp)])
            .expect("chain builds");
        let mut enc = Encoder::new(&mask);
        let mut wire = enc.encode(b"xy").expect("encodes").to_vec();
        assert_eq!(wire.len(), 6 + 4 + 2);
        let plain = mask.decode_in_place(&mut wire).expect("chain opens");
        assert_eq!(plain, b"xy");
        // The bkd pass restored the cascade region, so the inner header is visible here and the hash span covered it.
        assert_eq!(&wire[6..10], &[0, 0, 0, 1], "the inner srtp survived");
    }

    #[test]
    fn the_empty_mask_is_the_raw_datagram() {
        let mask = Mask::default();
        assert!(mask.is_empty());
        let mut buf = b"raw segments".to_vec();
        assert_eq!(
            mask.decode_in_place(&mut buf).expect("pass-through"),
            b"raw segments"
        );
    }

    #[test]
    fn a_short_datagram_under_the_chain_is_refused() {
        let mask = Mask::from_spec(&[Spec::Original]).expect("builds");
        let mut buf = vec![0u8; 5];
        assert_eq!(mask.decode_in_place(&mut buf), None);
        let mask = Mask::from_spec(&[Spec::Header(HeaderKind::Wechat)]).expect("builds");
        let mut buf = vec![0u8; 12];
        assert_eq!(mask.decode_in_place(&mut buf), None);
    }
}
