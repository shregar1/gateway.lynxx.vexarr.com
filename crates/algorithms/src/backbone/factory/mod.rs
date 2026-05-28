//! Factory — compile-time tier selection via `#[cfg(feature)]` type aliases.
//!
//! Tiers are additive: `tier-pro` implies `tier-growth` implies `tier-starter`.

pub mod hasher;
pub mod checksummer;
pub mod base64_codec;
pub mod uri_codec;
pub mod huffman_codec;
pub mod load_balancer;
pub mod rate_limiter;
pub mod health_checker;
pub mod congestion;

pub use hasher::{TierHasher, create_hasher};
pub use checksummer::{TierChecksummer, create_checksummer};
pub use base64_codec::{TierBase64, create_base64};
pub use uri_codec::{TierUri, create_uri_codec};
pub use load_balancer::TierLoadBalancer;
pub use rate_limiter::TierRateLimiter;
pub use health_checker::TierHealthChecker;

#[cfg(feature = "tier-growth")]
pub use huffman_codec::{TierHuffman, create_huffman};

#[cfg(feature = "tier-pro")]
pub use congestion::{TierCongestion, create_congestion};
