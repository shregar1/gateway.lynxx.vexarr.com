//! Thin wrapper structs that implement backbone traits by delegating
//! to existing algorithm implementations in `goals/`.
//!
//! All adapters compile unconditionally; subscription tier selects which
//! adapter the factory instantiates at runtime.

pub mod hasher;
pub mod checksummer;
pub mod base64_codec;
pub mod uri_codec;
pub mod load_balancer;
pub mod rate_limiter;
pub mod health_checker;
pub mod huffman_codec;
pub mod congestion;
