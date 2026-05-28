//! Lynxx Backbone — trait interfaces, adapters, and tier-based factories.
//!
//! The backbone defines a common trait per functional algorithm group.
//! At compile time, Cargo features (`tier-starter`, `tier-growth`, `tier-pro`)
//! select the best concrete implementation for each trait via type aliases
//! in `factory`. Zero-cost static dispatch — no `dyn Trait`.
//!
//! # Usage
//!
//! ```ignore
//! use algorithms::backbone::{Hasher, create_hasher};
//!
//! let h = create_hasher();
//! let digest = h.hash(b"request-key");
//! println!("using {} hasher: {}", h.name(), digest);
//! ```

pub mod traits;
pub mod adapters;
pub mod factory;

// ── Re-export traits for ergonomic use ─────────────────────────────
pub use traits::{
    Hasher,
    Checksummer,
    Base64Codec,
    UriCodec,
    LoadBalancer,
    LbContext,
    RateLimiter,
    RateLimitContext,
    HealthChecker,
};

#[cfg(feature = "tier-growth")]
pub use traits::HuffmanCodec;

#[cfg(feature = "tier-pro")]
pub use traits::{CongestionController, AckInfo};

// ── Re-export tier type aliases ────────────────────────────────────
pub use factory::{
    TierHasher,
    TierChecksummer,
    TierBase64,
    TierUri,
    TierLoadBalancer,
    TierRateLimiter,
    TierHealthChecker,
    create_hasher,
    create_checksummer,
    create_base64,
    create_uri_codec,
};

#[cfg(feature = "tier-growth")]
pub use factory::{TierHuffman, create_huffman};

#[cfg(feature = "tier-pro")]
pub use factory::{TierCongestion, create_congestion};
