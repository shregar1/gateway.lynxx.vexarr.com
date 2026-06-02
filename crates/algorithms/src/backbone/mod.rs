//! Lynxx Backbone — trait interfaces, adapters, and tier-based factories.
//!
//! The backbone defines a common trait per functional algorithm group.
//! Every adapter is compiled into the binary unconditionally; the
//! subscription `Tier` selects which adapter the factory instantiates
//! at runtime, so a single binary serves every plan.
//!
//! # Usage
//!
//! ```ignore
//! use algorithms::backbone::{Hasher, Tier, create_hasher};
//!
//! let h = create_hasher(Tier::Growth);
//! let digest = h.hash(b"request-key");
//! println!("using {} hasher: {}", h.name(), digest);
//! ```

pub mod tier;
pub mod traits;
pub mod adapters;
pub mod factory;

// ── Re-export Tier ─────────────────────────────────────────────────
pub use tier::{Tier, UnknownTier};

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
    HuffmanCodec,
    CongestionController,
    AckInfo,
};

// ── Re-export tier-dispatched factories ────────────────────────────
pub use factory::{
    TierHasher,
    TierChecksummer,
    TierBase64,
    TierUri,
    TierHuffman,
    TierLoadBalancer,
    TierRateLimiter,
    TierHealthChecker,
    TierCongestion,
    create_hasher,
    create_checksummer,
    create_base64,
    create_uri_codec,
    create_huffman,
    create_congestion,
};
