//! `WireGuard`: the one connection method both reference engines ship and
//! this tree lacked (`xray-core/proxy/wireguard`, `sing-box/protocol/wireguard`).
//!
//! The method is a `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake that
//! yields a symmetric key pair, then `ChaCha20Poly1305` records over UDP with
//! a counter-derived nonce. Everything it hashes is BLAKE2s — the KDF is RFC
//! 2104 HMAC over the unkeyed hash, the transcript mixing is the plain hash,
//! and `mac1` is keyed BLAKE2s-128 — which is why [`crate::blake2s`] is its
//! only new primitive; X25519 and the AEAD were already here.
//!
//! [`kdf`], [`handshake`] and [`transport`] are the key derivation, the
//! initiation/response exchange, and the record layer with its replay window
//! and `mac2` cookie. [`device`] is one peer's tunnel: the session, the queue,
//! the reserved bytes, and the reference's five message timers. The config
//! binding lives in `ferrox-app` (`wireguard`, `wg_stack`, `wg`).

pub mod device;
pub mod handshake;
pub mod kdf;
pub mod transport;
