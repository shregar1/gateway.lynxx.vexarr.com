//! Factory — runtime tier selection via enum dispatch.
//!
//! Every adapter compiles into the binary. At construction time, the
//! subscription `Tier` picks the variant to instantiate; the others
//! remain unreachable through these factory entry points.

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
pub use huffman_codec::{TierHuffman, create_huffman};
pub use load_balancer::TierLoadBalancer;
pub use rate_limiter::TierRateLimiter;
pub use health_checker::TierHealthChecker;
pub use congestion::{TierCongestion, create_congestion};
