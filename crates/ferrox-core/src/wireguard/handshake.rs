//! `WireGuard`'s handshake: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, the
//! initiation/response exchange over UDP with no stream framing.
//!
//! What is mirrored from the reference is the protocol itself — the order of
//! the `mixKey`/`mixHash` calls, the sizes (148-byte initiation, 92-byte
//! response) and the `mac1` keying — and those are reproduced exactly. What is
//! deliberately not carried over: the Go marshalling structs (every field is
//! already at its byte offset, so messages are encrypted and authenticated in
//! place with no staging copy), the per-call `hash.Hash` allocations, and the
//! lock discipline, which belongs to the device layer, not here.
//!
//! Out of scope until the record-layer slice: transport frames and counters,
//! the cookie mechanism (`mac2`, its reply and its refresh), and the message
//! timers. The `mac1` helpers below are the sender and checker halves of the
//! field; `mac2` stays zero bytes, which is exactly what a peer that has never
//! been given a cookie sends.

use super::kdf;
use crate::aead::{
    chacha20_poly1305_decrypt_in_place, chacha20_poly1305_seal_in_place, chacha20_poly1305_tag,
};
use crate::blake2s::{hash, Blake2s};
use zeroize::Zeroize as _;

/// The construction name, hashed into the initial chain key.
pub const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// The protocol identifier, mixed into the hash after the construction name.
pub const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
/// The label mixed with a static public key to derive the `mac1` key.
pub const LABEL_MAC1: &[u8] = b"mac1----";

/// The message type in the first little-endian word.
pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;

/// The sizes of the two handshake messages, macs included.
pub const INITIATION_SIZE: usize = 148;
pub const RESPONSE_SIZE: usize = 92;

/// The width of `mac1` and `mac2` (`blake2s.Size128`).
pub const MAC_SIZE: usize = 16;

/// The handshake AEAD always runs with a zero nonce: freshness lives in the
/// ephemeral keys, so a per-message nonce would add nothing to encrypt.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Zeroed,
    InitiationCreated,
    InitiationConsumed,
    ResponseCreated,
    ResponseConsumed,
}

/// The per-peer handshake state machine. An initiator calls [`Handshake::initiate`],
/// [`Handshake::create_initiation`] and [`Handshake::consume_response`]; a
/// responder calls [`Handshake::consume_initiation`] and
/// [`Handshake::create_response`]. Both end at [`Handshake::session_keys`], the
/// only path that zeroes the ephemeral private key and the chain.
#[derive(Debug)]
pub struct Handshake {
    state: State,
    hash: [u8; 32],
    chain_key: [u8; 32],
    preshared_key: [u8; 32],
    local_ephemeral: [u8; 32],
    remote_ephemeral: [u8; 32],
    remote_static: [u8; 32],
    static_static: [u8; 32],
    timestamp: [u8; 12],
    local_index: u32,
    remote_index: u32,
}

fn mix_hash(h: &mut [u8; 32], data: &[u8]) {
    let mut state = Blake2s::new(&[], 32);
    state.update(h);
    state.update(data);
    *h = state.finalize();
}

/// The initial `(hash, chain key)`: the chain key is `H(construction)` and the
/// hash is that mixed with the identifier. Two BLAKE2s calls per handshake is
/// noise against the four `X25519` ladders and nine KDF expansions the
/// exchange itself runs, so it is recomputed rather than cached behind a
/// lazy-initialisation guard.
fn initial() -> ([u8; 32], [u8; 32]) {
    let chain_key = hash(CONSTRUCTION.as_bytes());
    let mut hash = chain_key;
    mix_hash(&mut hash, IDENTIFIER.as_bytes());
    (hash, chain_key)
}

fn public_of(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// The `X25519` shared secret, rejected when zero — which happens exactly when
/// the peer point has small order, the reference's only oracle for a malformed
/// key. `x25519_dalek::x25519` clamps the scalar itself, so the reference's
/// manual clamp is not needed here.
fn shared(private: &[u8; 32], public: &[u8; 32]) -> Option<[u8; 32]> {
    let ss = x25519_dalek::x25519(*private, *public);
    if ss.iter().fold(0u8, |acc, byte| acc | byte) == 0 {
        return None;
    }
    Some(ss)
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

/// The `mac1` key of the holder of `static_public`: `H("mac1----" ‖ static)`.
/// A sender keys with the receiver's static; the receiver checks with its own.
fn mac1_key(static_public: &[u8; 32]) -> [u8; 32] {
    let mut state = Blake2s::new(&[], 32);
    state.update(LABEL_MAC1);
    state.update(static_public);
    state.finalize()
}

/// The `mac1` of a handshake message: keyed BLAKE2s-128 over every byte ahead
/// of the trailing two mac fields.
fn mac1_of(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let end = msg.len() - 2 * MAC_SIZE;
    let mut mac = Blake2s::new(key, MAC_SIZE);
    mac.update(&msg[..end]);
    let digest = mac.finalize();
    let mut out = [0u8; MAC_SIZE];
    out.copy_from_slice(&digest[..MAC_SIZE]);
    out
}

/// Write the `mac1` of `msg`, keyed by the receiver's static public key; the
/// 16 bytes behind it (`mac2`) are left as they are, which for a peer without
/// a cookie is zero.
pub fn set_mac1(msg: &mut [u8], receiver_static: &[u8; 32]) {
    let mac = mac1_of(msg, &mac1_key(receiver_static));
    let end = msg.len() - 2 * MAC_SIZE;
    msg[end..end + MAC_SIZE].copy_from_slice(&mac);
}

/// Check the `mac1` of a handshake message against the receiver's own static.
#[must_use]
pub fn check_mac1(msg: &[u8], receiver_static: &[u8; 32]) -> bool {
    let Some(end) = msg.len().checked_sub(2 * MAC_SIZE) else {
        return false;
    };
    ct_eq(
        &mac1_of(msg, &mac1_key(receiver_static)),
        &msg[end..end + MAC_SIZE],
    )
}

impl Handshake {
    /// Begin as the initiator against a peer whose static key is known; a
    /// zero `preshared_key` is the reference's no-psk case because the KDF
    /// mixes the 32 bytes as-is. `None` rejects a small-order `peer_static`
    /// before any message exists — and having proved `static-static`
    /// non-zero, no later `shared` with the same point can fail either, so
    /// `create_initiation` needs no error path.
    #[must_use]
    pub fn initiate(
        our_static_priv: &[u8; 32],
        peer_static: &[u8; 32],
        preshared_key: &[u8; 32],
    ) -> Option<Self> {
        let static_static = shared(our_static_priv, peer_static)?;
        let (mut hash, chain_key) = initial();
        mix_hash(&mut hash, peer_static);
        Some(Self {
            state: State::Zeroed,
            hash,
            chain_key,
            preshared_key: *preshared_key,
            local_ephemeral: [0u8; 32],
            remote_ephemeral: [0u8; 32],
            remote_static: *peer_static,
            static_static,
            timestamp: [0u8; 12],
            local_index: 0,
            remote_index: 0,
        })
    }

    /// Build the 148-byte initiation with the given ephemeral private key and
    /// timestamp (the caller's TAI64N: eight seconds then four nanoseconds,
    /// both big-endian — the core is deliberately not a clock). The static
    /// key and timestamp are sealed with the running hash as the associated
    /// data, each under a key the chain yields, and the ciphertexts are mixed
    /// back into the hash in wire order.
    pub fn create_initiation(
        &mut self,
        our_static_pub: &[u8; 32],
        ephemeral: [u8; 32],
        sender_index: u32,
        timestamp: &[u8; 12],
    ) -> [u8; INITIATION_SIZE] {
        assert_eq!(self.state, State::Zeroed, "a handshake initiates once");
        self.local_ephemeral = ephemeral;
        let mut msg = [0u8; INITIATION_SIZE];
        msg[0..4].copy_from_slice(&TYPE_INITIATION.to_le_bytes());
        msg[4..8].copy_from_slice(&sender_index.to_le_bytes());
        let eph = public_of(&ephemeral);
        msg[8..40].copy_from_slice(&eph);
        self.chain_key = kdf::kdf1(&self.chain_key, &eph);
        mix_hash(&mut self.hash, &eph);

        let mut ss = shared(&ephemeral, &self.remote_static).expect("initiate checked this point");
        let (chain, mut temp) = kdf::kdf2(&self.chain_key, &ss);
        self.chain_key = chain;
        ss.zeroize();
        msg[40..72].copy_from_slice(our_static_pub);
        let tag = chacha20_poly1305_seal_in_place(&temp, &ZERO_NONCE, &self.hash, &mut msg[40..72]);
        msg[72..88].copy_from_slice(&tag);
        temp.zeroize();
        mix_hash(&mut self.hash, &msg[40..88]);

        let (chain, mut temp) = kdf::kdf2(&self.chain_key, &self.static_static);
        self.chain_key = chain;
        msg[88..100].copy_from_slice(timestamp);
        let tag =
            chacha20_poly1305_seal_in_place(&temp, &ZERO_NONCE, &self.hash, &mut msg[88..100]);
        msg[100..116].copy_from_slice(&tag);
        temp.zeroize();
        mix_hash(&mut self.hash, &msg[88..116]);

        self.local_index = sender_index;
        self.state = State::InitiationCreated;
        msg
    }

    /// The responder's half: decrypt and authenticate an initiation with our
    /// static identity and return the state that answers it. The peer is not
    /// known until the static decrypts, which is why the preshared key is a
    /// `create_response` argument and not one here.
    pub fn consume_initiation(
        our_static_priv: &[u8; 32],
        our_static_pub: &[u8; 32],
        msg: &[u8; INITIATION_SIZE],
    ) -> Option<Self> {
        if u32::from_le_bytes(msg[0..4].try_into().ok()?) != TYPE_INITIATION {
            return None;
        }
        let (mut hash, initial_chain) = initial();
        mix_hash(&mut hash, our_static_pub);
        let eph: [u8; 32] = msg[8..40].try_into().ok()?;
        mix_hash(&mut hash, &eph);
        let mut chain = kdf::kdf1(&initial_chain, &eph);

        let mut ss = shared(our_static_priv, &eph)?;
        let (next, mut temp) = kdf::kdf2(&chain, &ss);
        chain = next;
        ss.zeroize();
        let mut peer_static = [0u8; 32];
        peer_static.copy_from_slice(&msg[40..72]);
        let tag: [u8; 16] = msg[72..88].try_into().ok()?;
        chacha20_poly1305_decrypt_in_place(&temp, &ZERO_NONCE, &hash, &mut peer_static, &tag)?;
        temp.zeroize();
        mix_hash(&mut hash, &msg[40..88]);

        let ss = shared(our_static_priv, &peer_static)?;
        let (next, mut temp) = kdf::kdf2(&chain, &ss);
        chain = next;
        let static_static = ss;
        let mut timestamp = [0u8; 12];
        timestamp.copy_from_slice(&msg[88..100]);
        let tag: [u8; 16] = msg[100..116].try_into().ok()?;
        chacha20_poly1305_decrypt_in_place(&temp, &ZERO_NONCE, &hash, &mut timestamp, &tag)?;
        temp.zeroize();
        mix_hash(&mut hash, &msg[88..116]);

        Some(Self {
            state: State::InitiationConsumed,
            hash,
            chain_key: chain,
            preshared_key: [0u8; 32],
            local_ephemeral: [0u8; 32],
            remote_ephemeral: eph,
            remote_static: peer_static,
            static_static,
            timestamp,
            local_index: 0,
            remote_index: u32::from_le_bytes(msg[4..8].try_into().ok()?),
        })
    }

    /// Answer the consumed initiation with our fresh ephemeral, the two
    /// remaining `X25519` ladders and the preshared key the looked-up peer
    /// carries. The 16 "empty" bytes are the AEAD tag of an empty plaintext
    /// under the transcript hash — the proof of the whole chain.
    pub fn create_response(
        &mut self,
        ephemeral: [u8; 32],
        sender_index: u32,
        preshared_key: &[u8; 32],
    ) -> Option<[u8; RESPONSE_SIZE]> {
        assert_eq!(
            self.state,
            State::InitiationConsumed,
            "a response answers an initiation"
        );
        self.local_ephemeral = ephemeral;
        self.preshared_key = *preshared_key;
        let mut msg = [0u8; RESPONSE_SIZE];
        msg[0..4].copy_from_slice(&TYPE_RESPONSE.to_le_bytes());
        msg[4..8].copy_from_slice(&sender_index.to_le_bytes());
        msg[8..12].copy_from_slice(&self.remote_index.to_le_bytes());
        let eph = public_of(&ephemeral);
        msg[12..44].copy_from_slice(&eph);
        mix_hash(&mut self.hash, &eph);
        self.chain_key = kdf::kdf1(&self.chain_key, &eph);

        let mut ss = shared(&ephemeral, &self.remote_ephemeral)?;
        self.chain_key = kdf::kdf1(&self.chain_key, &ss);
        ss.zeroize();
        ss = shared(&ephemeral, &self.remote_static)?;
        self.chain_key = kdf::kdf1(&self.chain_key, &ss);
        ss.zeroize();

        let (chain, tau, mut temp) = kdf::kdf3(&self.chain_key, &self.preshared_key);
        self.chain_key = chain;
        mix_hash(&mut self.hash, &tau);
        msg[44..60].copy_from_slice(&chacha20_poly1305_tag(&temp, &ZERO_NONCE, &self.hash, &[]));
        temp.zeroize();
        mix_hash(&mut self.hash, &msg[44..60]);

        self.local_index = sender_index;
        self.state = State::ResponseCreated;
        Some(msg)
    }

    /// The initiator's half: finish the ladder with the responder's ephemeral
    /// and accept the response only if the empty field's tag verifies. A
    /// failure leaves the handshake exactly as it was, so the same state can
    /// still consume a later, valid response.
    pub fn consume_response(
        &mut self,
        our_static_priv: &[u8; 32],
        msg: &[u8; RESPONSE_SIZE],
    ) -> bool {
        if self.state != State::InitiationCreated
            || u32::from_le_bytes(msg[0..4].try_into().unwrap_or([0u8; 4])) != TYPE_RESPONSE
        {
            return false;
        }
        let mut hash = self.hash;
        let mut chain = self.chain_key;
        let eph: [u8; 32] = msg[12..44].try_into().unwrap();
        mix_hash(&mut hash, &eph);
        chain = kdf::kdf1(&chain, &eph);

        let Some(mut ss) = shared(&self.local_ephemeral, &eph) else {
            return false;
        };
        chain = kdf::kdf1(&chain, &ss);
        ss.zeroize();
        let Some(mut ss) = shared(our_static_priv, &eph) else {
            return false;
        };
        chain = kdf::kdf1(&chain, &ss);
        ss.zeroize();

        let (next, tau, mut temp) = kdf::kdf3(&chain, &self.preshared_key);
        chain = next;
        mix_hash(&mut hash, &tau);
        let want = chacha20_poly1305_tag(&temp, &ZERO_NONCE, &hash, &[]);
        temp.zeroize();
        if !ct_eq(&want, &msg[44..60]) {
            hash.zeroize();
            chain.zeroize();
            return false;
        }
        mix_hash(&mut hash, &msg[44..60]);

        self.hash = hash;
        self.chain_key = chain;
        self.remote_ephemeral = eph;
        self.remote_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
        self.state = State::ResponseConsumed;
        true
    }

    /// Derive the session's `(send, recv)` keys and burn the handshake: the
    /// initiator takes the KDF2 outputs in order, the responder swapped, and
    /// the ephemeral private key, chain and hash are zeroised on the way out.
    pub fn session_keys(&mut self) -> Option<([u8; 32], [u8; 32])> {
        let (first, second) = match self.state {
            State::ResponseConsumed => kdf::kdf2(&self.chain_key, &[]),
            State::ResponseCreated => {
                let (recv, send) = kdf::kdf2(&self.chain_key, &[]);
                (send, recv)
            }
            _ => return None,
        };
        self.chain_key.zeroize();
        self.hash.zeroize();
        self.local_ephemeral.zeroize();
        self.local_index = 0;
        self.state = State::Zeroed;
        Some((first, second))
    }

    /// The peer's static public key — the device's key into its peer table.
    #[must_use]
    pub fn remote_static(&self) -> [u8; 32] {
        self.remote_static
    }

    /// The initiator's timestamp as decrypted, kept for the replay rule the
    /// record layer will enforce.
    #[must_use]
    pub fn timestamp(&self) -> [u8; 12] {
        self.timestamp
    }

    /// The index this side announced, and the peer's for outgoing headers.
    #[must_use]
    pub fn indexes(&self) -> (u32, u32) {
        (self.local_index, self.remote_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAMP: &[u8; 12] = b"0123456789ab";

    fn identity(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = [seed; 32];
        (private, public_of(&private))
    }

    /// A pair mid-handshake: initiation created, mac'ed, checked and consumed.
    fn initiated(psk: &[u8; 32]) -> (Handshake, Handshake, [u8; 32], [u8; 32]) {
        let (alice_priv, alice_pub) = identity(0x11);
        let (bob_priv, bob_pub) = identity(0x22);
        let mut alice = Handshake::initiate(&alice_priv, &bob_pub, psk).unwrap();
        let mut initiation = alice.create_initiation(&alice_pub, [0x33; 32], 0xA11CE, STAMP);
        set_mac1(&mut initiation, &bob_pub);
        assert!(check_mac1(&initiation, &bob_pub));
        let bob = Handshake::consume_initiation(&bob_priv, &bob_pub, &initiation).unwrap();
        (alice, bob, alice_pub, bob_pub)
    }

    #[test]
    fn the_handshake_round_trip_agrees_on_one_key_pair() {
        let psk = [0x99; 32];
        let (alice_priv, _) = identity(0x11);
        let (mut alice, mut bob, alice_pub, _) = initiated(&psk);
        assert_eq!(bob.remote_static(), alice_pub);
        assert_eq!(bob.timestamp(), *STAMP);
        let mut response = bob.create_response([0x44; 32], 0xB0B, &psk).unwrap();
        set_mac1(&mut response, &alice_pub);
        assert!(check_mac1(&response, &alice_pub));
        assert!(alice.consume_response(&alice_priv, &response));
        let (a_send, a_recv) = alice.session_keys().unwrap();
        let (b_send, b_recv) = bob.session_keys().unwrap();
        assert_eq!(a_send, b_recv);
        assert_eq!(a_recv, b_send);
        assert_ne!(a_send, a_recv);
    }

    #[test]
    fn the_round_trip_holds_without_a_preshared_key() {
        let (alice_priv, alice_pub) = identity(0x11);
        let (mut alice, mut bob, _, _) = initiated(&[0u8; 32]);
        let mut response = bob.create_response([0x44; 32], 0xB0B, &[0u8; 32]).unwrap();
        set_mac1(&mut response, &alice_pub);
        assert!(alice.consume_response(&alice_priv, &response));
        assert_eq!(
            alice.session_keys().unwrap().0,
            bob.session_keys().unwrap().1
        );
    }

    #[test]
    fn a_forged_response_leaves_the_handshake_untouched_and_still_consumes_the_real_one() {
        let psk = [0x99; 32];
        let (alice_priv, alice_pub) = identity(0x11);
        let (mut alice, mut bob, _, _) = initiated(&psk);
        let mut response = bob.create_response([0x44; 32], 0xB0B, &psk).unwrap();
        set_mac1(&mut response, &alice_pub);
        let mut forged = response;
        forged[45] ^= 1;
        assert!(!alice.consume_response(&alice_priv, &forged));
        assert!(alice.session_keys().is_none());
        assert!(alice.consume_response(&alice_priv, &response));
        let (a_send, a_recv) = alice.session_keys().unwrap();
        let (b_send, b_recv) = bob.session_keys().unwrap();
        assert_eq!(a_send, b_recv);
        assert_eq!(a_recv, b_send);
    }

    #[test]
    fn a_forged_initiation_is_rejected_before_the_peer_lookup() {
        let (alice_priv, alice_pub) = identity(0x11);
        let (bob_priv, bob_pub) = identity(0x22);
        let mut alice = Handshake::initiate(&alice_priv, &bob_pub, &[0u8; 32]).unwrap();
        let mut initiation = alice.create_initiation(&alice_pub, [0x33; 32], 1, STAMP);
        initiation[50] ^= 1;
        assert!(Handshake::consume_initiation(&bob_priv, &bob_pub, &initiation).is_none());
    }

    #[test]
    fn a_message_shorter_than_two_macs_is_refused_not_indexed() {
        let (_, bob_pub) = identity(0x22);
        let bytes = [0u8; 2 * MAC_SIZE];
        for len in 0..bytes.len() {
            assert!(!check_mac1(&bytes[..len], &bob_pub), "length {len}");
        }
    }

    #[test]
    fn mac1_binds_the_message_and_nothing_after_it() {
        let (alice_priv, alice_pub) = identity(0x11);
        let (_, bob_pub) = identity(0x22);
        let mut alice = Handshake::initiate(&alice_priv, &bob_pub, &[0u8; 32]).unwrap();
        let mut initiation = alice.create_initiation(&alice_pub, [0x33; 32], 7, STAMP);
        set_mac1(&mut initiation, &bob_pub);
        assert!(check_mac1(&initiation, &bob_pub));
        initiation[8] ^= 1;
        assert!(!check_mac1(&initiation, &bob_pub));
        set_mac1(&mut initiation, &bob_pub);
        initiation[120] ^= 1;
        assert!(!check_mac1(&initiation, &bob_pub));
    }

    #[test]
    fn a_small_order_peer_static_is_rejected_at_config() {
        let (alice_priv, _) = identity(0x11);
        assert!(Handshake::initiate(&alice_priv, &[0u8; 32], &[0u8; 32]).is_none());
    }
}
