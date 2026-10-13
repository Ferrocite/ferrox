#![deny(missing_debug_implementations)]

#[cfg(test)]
mod alloc_count;

pub mod addr;
pub mod aead;
pub mod aesgcm;
pub mod b64;
pub mod blake2s;
pub(crate) mod chacha;
pub mod core;
pub mod failure;
pub mod foxy;
pub mod hysteria;
pub mod kcp;
pub mod mux;
pub mod policy;
pub mod poly1305;
pub mod record;
pub mod shadowsocks;
pub mod shadowsocks2022;
pub mod tls;
pub mod transport;
pub mod vless;
pub mod wireguard;

#[cfg(any(test, feature = "bench-reference"))]
pub mod reference {
    pub use crate::core::{backend, reference_xor};
}

pub fn active_backends() -> &'static [&'static str] {
    &["rustls"]
}

pub fn chacha_backend() -> &'static str {
    crate::chacha::backend()
}
