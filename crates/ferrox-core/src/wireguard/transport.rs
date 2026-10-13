//! `WireGuard`'s record layer: `ChaCha20Poly1305` frames over UDP with a
//! counter-derived nonce, the receive-side replay window that decides whether a
//! counter is fresh, and the `mac2` cookie that turns a handshake message into a
//! proof the sender owns the source address it claims.
//!
//! The frame is the one both reference engines put on the wire
//! (`xray-core/proxy/wireguard` and `sing-box/protocol/wireguard` both embed the
//! vanilla device): an eight-byte header — receiver index then counter, each a
//! little-endian word — then the ciphertext with its 16-byte tag behind it. The
//! AEAD nonce is twelve bytes: four zero bytes then the counter widened to eight.
//! A record whose plaintext is empty is a keepalive, so `MIN_SIZE` bytes is the
//! whole of the smallest thing on the wire.
//!
//! Against the pinned `amneziawg-go` the handshake, the KDF and the cookie are
//! carried exactly; the data header is not — that variant widens it to sixteen
//! bytes, prepends an obfuscated type field and keeps a 64-bit counter, which
//! changes every byte a vanilla peer would parse. This carries the vanilla
//! framing, and names the divergence rather than silently shipping a different
//! wire. What is deliberately out of scope: the message timers (reserve,
//! handshake-attempt, cookie-refresh) and the config binding, which belong to
//! the method slice, not here.

use super::handshake::MAC_SIZE;
use crate::aead::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_seal_in_place};
use crate::blake2s::Blake2s;

/// The receiver index and counter ahead of the ciphertext.
pub const HEADER_SIZE: usize = 8;
/// The `ChaCha20Poly1305` tag behind the ciphertext.
pub const TAG_SIZE: usize = 16;
/// The smallest record: an empty payload, which is a keepalive.
pub const MIN_SIZE: usize = HEADER_SIZE + TAG_SIZE;

/// The cookie reply's message type, in the first little-endian word.
pub const TYPE_COOKIE_REPLY: u32 = 3;
/// A cookie reply: type, receiver, a 24-byte `XChaCha` nonce, then the sealed
/// 16-byte cookie and its tag.
pub const COOKIE_REPLY_SIZE: usize = 64;
/// The width of the XChaCha20-Poly1305 nonce the cookie reply carries.
pub const COOKIE_NONCE_SIZE: usize = 24;

/// The label mixed with a static public key to derive the cookie encryption key.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// The reorder span the receive window tracks. `WireGuard`'s own window is
/// larger, but this width is receiver-local policy and touches no byte on the
/// wire; 128 is ample for the reordering a single UDP path does.
const WINDOW_BITS: u32 = 128;

/// The AEAD nonce for a counter: four zero bytes, then the counter as eight
/// little-endian bytes. A session rekeys well before `2^32`, so the high four of
/// those eight are always zero — widened here rather than masked so the layout
/// is the reference's byte for byte.
fn nonce(counter: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&(counter as u64).to_le_bytes());
    n
}

/// Seal the record in place: the plaintext sits at `buf[HEADER_SIZE..]` for `len`
/// bytes, the buffer is `HEADER_SIZE + len + TAG_SIZE` long, and the receiver
/// index and counter are written ahead. Returns the total record length. The
/// encryption is the already-proved `aead` seal, so the ciphertext is what a
/// vanilla peer decrypts — this adds only the header and the counter nonce.
pub fn seal(key: &[u8; 32], receiver: u32, counter: u32, len: usize, buf: &mut [u8]) -> usize {
    buf[0..4].copy_from_slice(&receiver.to_le_bytes());
    buf[4..8].copy_from_slice(&counter.to_le_bytes());
    let body = &mut buf[HEADER_SIZE..HEADER_SIZE + len];
    let tag = chacha20_poly1305_seal_in_place(key, &nonce(counter), b"", body);
    buf[HEADER_SIZE + len..HEADER_SIZE + len + TAG_SIZE].copy_from_slice(&tag);
    HEADER_SIZE + len + TAG_SIZE
}

/// Parse and decrypt a `total`-byte record from `buf`, returning `(receiver,
/// counter, plaintext length)` with the plaintext at `buf[HEADER_SIZE..]`. The
/// tag is checked before any keystream exists, so a forged or undersized record
/// leaves `buf` exactly as it was handed over.
pub fn open(key: &[u8; 32], buf: &mut [u8], total: usize) -> Option<(u32, u32, usize)> {
    if total < MIN_SIZE || buf.len() < total {
        return None;
    }
    let receiver = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let counter = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let len = total - HEADER_SIZE - TAG_SIZE;
    let (body, tag) = buf[HEADER_SIZE..total].split_at_mut(len);
    let tag: &[u8; TAG_SIZE] = (&*tag).try_into().ok()?;
    chacha20_poly1305_decrypt_in_place(key, &nonce(counter), b"", body, tag)?;
    Some((receiver, counter, len))
}

/// The sender's counter. It hands out each nonce exactly once and refuses at
/// `2^32`, the point the reference rekeys: past it a `(key, nonce)` would repeat,
/// which is the one thing the AEAD cannot survive.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counter {
    next: u32,
}

impl Counter {
    /// A counter at zero, ready for a fresh keypair.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The counter to use now, advancing past it; `None` once the key must be
    /// rekeyed because the next value would repeat a nonce.
    pub fn advance(&mut self) -> Option<u32> {
        let current = self.next;
        self.next = self.next.checked_add(1)?;
        Some(current)
    }
}

/// What [`ReplayWindow::check`] decided about a counter, applied only once the
/// record authenticates. A `Reject` never reaches [`ReplayWindow::commit`] as an
/// accept; carrying the action rather than a bool lets a failed decrypt leave
/// the counter unclaimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Far in the future (or the first ever): the window resets to this counter.
    Roll,
    /// Inside the window's future edge by `delta`: shift the mask up and accept.
    Advance(u32),
    /// Inside the window, not yet seen: mark the bit at `offset` and accept.
    Mark(u32),
    /// A replay, or older than the window reaches.
    Reject,
}

/// The receiver's anti-replay state: the highest accepted counter and a bitmap
/// of the `WINDOW_BITS` counters beneath it. `check` answers without mutating
/// anything, so the caller runs it before the AEAD and `commit` only after — the
/// deferred-commit discipline of the reference, kept as a value instead of a
/// callback.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplayWindow {
    top: u32,
    seen: u128,
    started: bool,
}

impl ReplayWindow {
    /// An empty window, accepting any first counter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide about `counter` without touching the window.
    #[must_use]
    pub fn check(&self, counter: u32) -> Action {
        if !self.started {
            return Action::Roll;
        }
        if counter > self.top {
            let delta = counter - self.top;
            if delta >= WINDOW_BITS {
                Action::Roll
            } else {
                Action::Advance(delta)
            }
        } else {
            let offset = self.top - counter;
            if offset >= WINDOW_BITS || self.seen & (1u128 << offset) != 0 {
                Action::Reject
            } else {
                Action::Mark(offset)
            }
        }
    }

    /// Apply an accepting [`Action`] for `counter`, marking it seen. A `Reject`
    /// is a no-op, so a caller that commits unconditionally is still correct.
    pub fn commit(&mut self, counter: u32, action: Action) {
        match action {
            Action::Roll => {
                self.top = counter;
                self.seen = 1;
                self.started = true;
            }
            Action::Advance(delta) => {
                self.top = counter;
                self.seen = (self.seen << delta) | 1;
            }
            Action::Mark(offset) => self.seen |= 1u128 << offset,
            Action::Reject => {}
        }
    }
}

/// A keyed BLAKE2s truncated to `MAC_SIZE` (128 bits) — the width `mac1`,
/// `mac2` and the cookie all ask for.
fn blake2s128(key: &[u8], data: &[u8]) -> [u8; MAC_SIZE] {
    let mut mac = Blake2s::new(key, MAC_SIZE);
    mac.update(data);
    let digest = mac.finalize();
    let mut out = [0u8; MAC_SIZE];
    out.copy_from_slice(&digest[..MAC_SIZE]);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The cookie-encryption key of the holder of `static_public`: `H("cookie--" ‖
/// static)`. It keys the XChaCha20-Poly1305 that seals a cookie to its receiver,
/// exactly as `mac1_key` keys `mac1` — the same label-and-static recipe with a
/// different label.
#[must_use]
pub fn cookie_encryption_key(static_public: &[u8; 32]) -> [u8; 32] {
    let mut state = Blake2s::new(&[], 32);
    state.update(LABEL_COOKIE);
    state.update(static_public);
    state.finalize()
}

/// The cookie for a source address under a rotating `secret`: keyed
/// BLAKE2s-128 over the address. Tying it to `src` is what makes a cookie a
/// proof the sender is answering to the address the packet came from.
#[must_use]
pub fn derive_cookie(secret: &[u8; 32], src: &[u8]) -> [u8; MAC_SIZE] {
    blake2s128(secret, src)
}

/// Write `mac2` of `msg`: keyed BLAKE2s-128 under `cookie` over every byte
/// before the trailing mac field. Run it after `set_mac1` so the mac2 covers the
/// mac1, the way the reference's `AddMacs` orders the two.
pub fn set_mac2(msg: &mut [u8], cookie: &[u8; MAC_SIZE]) {
    let end = msg.len() - MAC_SIZE;
    let mac = blake2s128(cookie, &msg[..end]);
    msg[end..].copy_from_slice(&mac);
}

/// Check a message's `mac2` under `secret` and the claimed source `src`. It
/// borrows `msg` immutably, so a failing cookie drops the message with nothing
/// mutated — the check cannot half-accept a packet.
#[must_use]
pub fn check_mac2(msg: &[u8], secret: &[u8; 32], src: &[u8]) -> bool {
    if msg.len() < 2 * MAC_SIZE {
        return false;
    }
    let end = msg.len() - MAC_SIZE;
    let cookie = derive_cookie(secret, src);
    ct_eq(&blake2s128(&cookie, &msg[..end]), &msg[end..])
}

/// Seal a fresh cookie for `src` into the 64-byte reply. The cookie is encrypted
/// with XChaCha20-Poly1305 — `hchacha` on the first sixteen nonce bytes, the
/// standard AEAD on the last eight — under the receiver's `encryption_key`, with
/// the initiator's `mac1` as the associated data so the reply binds to the very
/// message it answers. The `nonce_bytes` are the caller's: the core is not an
/// RNG, and taking them keeps the reply reproducible in a test.
pub fn create_reply(
    msg: &[u8],
    receiver_index: u32,
    secret: &[u8; 32],
    src: &[u8],
    encryption_key: &[u8; 32],
    nonce_bytes: &[u8; COOKIE_NONCE_SIZE],
) -> Option<[u8; COOKIE_REPLY_SIZE]> {
    if msg.len() < 2 * MAC_SIZE {
        return None;
    }
    let smac2 = msg.len() - MAC_SIZE;
    let smac1 = smac2 - MAC_SIZE;
    let cookie = derive_cookie(secret, src);
    let mut reply = [0u8; COOKIE_REPLY_SIZE];
    reply[0..4].copy_from_slice(&TYPE_COOKIE_REPLY.to_le_bytes());
    reply[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    reply[8..32].copy_from_slice(nonce_bytes);
    let sub = crate::chacha::hchacha(encryption_key, nonce_bytes[..16].try_into().ok()?);
    let mut inner = [0u8; 12];
    inner[4..].copy_from_slice(&nonce_bytes[16..]);
    let body = &mut reply[32..48];
    body.copy_from_slice(&cookie);
    let tag = chacha20_poly1305_seal_in_place(&sub, &inner, &msg[smac1..smac2], body);
    reply[48..64].copy_from_slice(&tag);
    Some(reply)
}

/// Open a cookie reply on the sender's side, returning the cookie only when its
/// tag verifies against `last_mac1` — the `mac1` of the message this reply
/// answers. A reply that does not authenticate yields nothing and stores no
/// cookie.
pub fn consume_reply(
    reply: &[u8; COOKIE_REPLY_SIZE],
    encryption_key: &[u8; 32],
    last_mac1: &[u8; MAC_SIZE],
) -> Option<[u8; MAC_SIZE]> {
    let mut cookie = [0u8; MAC_SIZE];
    cookie.copy_from_slice(&reply[32..48]);
    let tag: [u8; TAG_SIZE] = reply[48..64].try_into().ok()?;
    let nonce_bytes: [u8; COOKIE_NONCE_SIZE] = reply[8..32].try_into().ok()?;
    let sub = crate::chacha::hchacha(encryption_key, &nonce_bytes[..16].try_into().ok()?);
    let mut inner = [0u8; 12];
    inner[4..].copy_from_slice(&nonce_bytes[16..]);
    chacha20_poly1305_decrypt_in_place(&sub, &inner, last_mac1, &mut cookie, &tag)?;
    Some(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::AeadInPlace as _;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, XChaCha20Poly1305, XNonce};

    const KEY: &[u8; 32] = b"01234567890123456789012345678901";

    #[test]
    fn a_record_round_trips_and_is_byte_identical_to_the_aead_crate() {
        for (counter, len) in [(0u32, 0usize), (1, 1), (7, 15), (255, 64), (1 << 20, 300)] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11)).collect();
            let mut buf = vec![0u8; HEADER_SIZE + len + TAG_SIZE];
            buf[HEADER_SIZE..HEADER_SIZE + len].copy_from_slice(&plain);
            let total = seal(KEY, 0xBEEF, counter, len, &mut buf);
            assert_eq!(total, buf.len(), "the record fills the buffer");

            // Header is receiver then counter, both little-endian.
            assert_eq!(&buf[0..4], &0xBEEFu32.to_le_bytes());
            assert_eq!(&buf[4..8], &counter.to_le_bytes());

            // The body and tag are what the pinned AEAD crate produces for the same key, counter-derived nonce and empty AD: an independent witness that the frame on the wire is the vanilla one.
            let reference = ChaCha20Poly1305::new_from_slice(KEY).expect("key");
            let n = nonce(counter);
            let mut want = plain.clone();
            let want_tag = reference
                .encrypt_in_place_detached(Nonce::from_slice(&n), b"", &mut want)
                .expect("seals");
            assert_eq!(
                &buf[HEADER_SIZE..HEADER_SIZE + len],
                &want,
                "counter {counter}"
            );
            assert_eq!(
                &buf[HEADER_SIZE + len..],
                &want_tag[..],
                "counter {counter} tag"
            );

            let mut opened = buf.clone();
            let (receiver, got_counter, got_len) = open(KEY, &mut opened, total).expect("opens");
            assert_eq!(receiver, 0xBEEF);
            assert_eq!(got_counter, counter);
            assert_eq!(got_len, len);
            assert_eq!(
                &opened[HEADER_SIZE..HEADER_SIZE + len],
                &plain,
                "round trip"
            );
        }
    }

    #[test]
    fn a_forged_record_is_refused_and_left_encrypted() {
        let plain = b"payload that must not leak".to_vec();
        let mut buf = vec![0u8; HEADER_SIZE + plain.len() + TAG_SIZE];
        buf[HEADER_SIZE..HEADER_SIZE + plain.len()].copy_from_slice(&plain);
        let total = seal(KEY, 5, 9, plain.len(), &mut buf);
        let sealed = buf.clone();
        buf[total - 1] ^= 1;
        assert!(open(KEY, &mut buf, total).is_none(), "a flipped tag fails");
        assert_eq!(
            &buf[HEADER_SIZE..HEADER_SIZE + plain.len()],
            &sealed[HEADER_SIZE..HEADER_SIZE + plain.len()],
            "a refused tag decrypts nothing"
        );
    }

    #[test]
    fn an_empty_record_is_a_keepalive() {
        let mut buf = [0u8; MIN_SIZE];
        let total = seal(KEY, 0xACCE, 42, 0, &mut buf);
        assert_eq!(total, MIN_SIZE, "a keepalive is the minimum record");
        let mut opened = buf;
        assert_eq!(open(KEY, &mut opened, total), Some((0xACCE, 42, 0)));
    }

    #[test]
    fn a_undersized_record_is_rejected_without_reading_past_it() {
        let mut buf = [0u8; MIN_SIZE];
        assert!(
            open(KEY, &mut buf, MIN_SIZE - 1).is_none(),
            "below the minimum"
        );
        let mut small = [0u8; 20];
        assert!(
            open(KEY, &mut small, MIN_SIZE).is_none(),
            "a total past the buffer's end"
        );
    }

    #[test]
    fn the_counter_hands_out_each_nonce_once() {
        let mut counter = Counter::new();
        assert_eq!(counter.advance(), Some(0));
        assert_eq!(counter.advance(), Some(1));
        // At the rekey boundary the counter cannot advance without wrapping onto a spent nonce: the all-ones counter is never transmitted, and that message is refused so a (key, nonce) pair cannot repeat.
        let mut at_edge = Counter { next: u32::MAX - 1 };
        assert_eq!(
            at_edge.advance(),
            Some(u32::MAX - 1),
            "the top transmitted nonce"
        );
        assert_eq!(at_edge.advance(), None, "refused before the counter wraps");
    }

    #[test]
    fn the_receive_window_refuses_reuse_and_advances_in_order() {
        let mut window = ReplayWindow::new();
        // The first counter establishes the window, wherever it lands.
        assert_eq!(window.check(100), Action::Roll);
        window.commit(100, Action::Roll);
        // An in-order future counter advances the top and is accepted.
        assert_eq!(window.check(101), Action::Advance(1));
        window.commit(101, Action::Advance(1));
        // A replay of either accepted counter is refused at the counter.
        assert_eq!(window.check(101), Action::Reject);
        assert_eq!(window.check(100), Action::Reject);
        // A delayed but unseen counter behind the top still gets in.
        assert_eq!(window.check(99), Action::Mark(2));
        window.commit(99, Action::Mark(2));
        assert_eq!(window.check(99), Action::Reject, "now it is a replay");
    }

    #[test]
    fn a_far_future_counter_rolls_the_window_and_clears_the_old_bits() {
        let mut window = ReplayWindow::new();
        window.commit(0, window.check(0));
        window.commit(5, window.check(5));
        assert_eq!(window.check(1), Action::Mark(4), "1 is four below top 5");
        // Past the reorder span the top leaps and everything older falls out.
        let far = WINDOW_BITS + 5;
        assert_eq!(window.check(far), Action::Roll);
        window.commit(far, Action::Roll);
        assert_eq!(window.check(5), Action::Reject, "old counters out of reach");
        assert_eq!(
            window.check(far),
            Action::Reject,
            "the new top is itself seen"
        );
    }

    #[test]
    fn a_rejected_counter_changes_nothing_in_the_window() {
        let mut window = ReplayWindow::new();
        window.commit(10, window.check(10));
        let replay = window.check(10);
        assert_eq!(replay, Action::Reject);
        let (top_before, seen_before) = (window.top, window.seen);
        window.commit(10, replay);
        assert_eq!(window.top, top_before, "a rejected counter mutates nothing");
        assert_eq!(window.seen, seen_before);
    }

    #[test]
    fn mac2_binds_the_cookie_to_the_source_and_a_bad_cookie_drops_the_message() {
        let secret = [0x5a; 32];
        let src = b"203.0.113.9:51820";
        let mut msg: [u8; 60] = std::array::from_fn(|i| i as u8);
        let cookie = derive_cookie(&secret, src);
        set_mac2(&mut msg, &cookie);
        assert!(check_mac2(&msg, &secret, src), "the right cookie verifies");

        // A failing check mutates nothing: `msg` is borrowed immutably, so the only way to fail is a wrong secret or address, and the bytes stand pat.
        let witness = msg;
        assert!(
            !check_mac2(&msg, &secret, b"198.51.100.1:51820"),
            "a different src"
        );
        assert!(!check_mac2(&msg, &[0x5b; 32], src), "a different secret");
        assert_eq!(
            msg, witness,
            "a failed cookie check leaves the message untouched"
        );

        msg[10] ^= 1;
        assert!(!check_mac2(&msg, &secret, src), "a tampered body fails");
    }

    #[test]
    fn the_cookie_reply_seals_and_opens_and_is_byte_identical_to_the_crate() {
        let own_static = [0x22; 32];
        let enc_key = cookie_encryption_key(&own_static);
        let secret = [0x7e; 32];
        let src = b"192.0.2.7:51820";
        let nonce_bytes = [0x33; COOKIE_NONCE_SIZE];

        let msg: [u8; 40] = std::array::from_fn(|i| (i as u8).wrapping_add(3));
        let mac1 = &msg[msg.len() - 2 * MAC_SIZE..msg.len() - MAC_SIZE];
        let cookie = derive_cookie(&secret, src);
        let reply = create_reply(&msg, 0x00C0_FFEE, &secret, src, &enc_key, &nonce_bytes).unwrap();
        assert_eq!(&reply[0..4], &TYPE_COOKIE_REPLY.to_le_bytes());
        assert_eq!(&reply[4..8], &0x00C0_FFEE_u32.to_le_bytes());
        assert_eq!(&reply[8..32], &nonce_bytes);

        // The sealed field is exactly what the pinned XChaCha20-Poly1305 crate makes from the cookie under the same key and nonce, with the mac1 field as associated data — an independent witness of the wire bytes.
        let reference = XChaCha20Poly1305::new_from_slice(&enc_key).expect("key");
        let mut want = cookie.to_vec();
        let want_tag = reference
            .encrypt_in_place_detached(XNonce::from_slice(&nonce_bytes), mac1, &mut want)
            .expect("seals");
        assert_eq!(&reply[32..48], &want[..], "the encrypted cookie");
        assert_eq!(&reply[48..64], &want_tag[..], "the reply tag");

        // And it opens back to the cookie against the very mac1 it was bound to.
        let mut mac1_field = [0u8; MAC_SIZE];
        mac1_field.copy_from_slice(mac1);
        assert_eq!(
            consume_reply(&reply, &enc_key, &mac1_field),
            Some(cookie),
            "the cookie recovers under the right mac1"
        );

        let mut forged = reply;
        forged[40] ^= 1;
        assert!(
            consume_reply(&forged, &enc_key, &mac1_field).is_none(),
            "a tampered reply yields no cookie"
        );
        assert!(
            consume_reply(&reply, &enc_key, b"0123456789abcdef").is_none(),
            "a reply against the wrong mac1 does not open"
        );
    }
}
