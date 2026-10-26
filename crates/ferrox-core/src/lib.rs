#![deny(missing_debug_implementations)]

pub mod alloc_count;

pub mod addr;
pub mod aead;
pub mod aesgcm;
pub mod b64;
pub mod blackhole;
pub mod blake2s;
pub(crate) mod chacha;
pub mod core;
pub mod dns;
pub mod failure;
pub mod finalmask;
pub mod foxy;
pub mod hysteria;
pub mod hysteria_v1;
pub mod kcp;
pub(crate) mod keystream;
pub mod mux;
pub mod policy;
pub mod poly1305;
pub mod record;
pub mod shadowsocks;
pub mod shadowsocks2022;
pub mod socks;
pub mod tls;
pub mod transport;
pub mod trojan;
pub mod veepn;
pub mod vless;
pub mod vless_encryption;
pub mod wireguard;

#[cfg(any(test, feature = "bench-reference"))]
pub mod reference {
    pub use crate::core::{backend, reference_xor};
}

pub fn active_backends() -> &'static [&'static str] {
    &["rustls", "boring"]
}

pub fn chacha_backend() -> &'static str {
    crate::chacha::backend()
}
