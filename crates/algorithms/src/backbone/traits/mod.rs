//! Backbone trait definitions — one per functional algorithm group.

pub mod hasher;
pub mod checksummer;
pub mod base64_codec;
pub mod uri_codec;
pub mod huffman_codec;
pub mod load_balancer;
pub mod rate_limiter;
pub mod health_checker;
pub mod congestion;

pub use hasher::Hasher;
pub use checksummer::Checksummer;
pub use base64_codec::Base64Codec;
pub use uri_codec::UriCodec;
pub use load_balancer::{LoadBalancer, LbContext};
pub use rate_limiter::{RateLimiter, RateLimitContext};
pub use health_checker::HealthChecker;
pub use huffman_codec::HuffmanCodec;
pub use congestion::{CongestionController, AckInfo};
