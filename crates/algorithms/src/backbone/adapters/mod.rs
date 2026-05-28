//! Thin wrapper structs that implement backbone traits by delegating
//! to existing algorithm implementations in `goals/`.

pub mod hasher;
pub mod checksummer;
pub mod base64_codec;
pub mod uri_codec;
pub mod load_balancer;
pub mod rate_limiter;
pub mod health_checker;

#[cfg(feature = "tier-growth")]
pub mod huffman_codec;

#[cfg(feature = "tier-pro")]
pub mod congestion;
