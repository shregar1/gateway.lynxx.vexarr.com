//! Tier selection for Hasher.

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierHasher = adapters::hasher::Xxh64Hasher;

#[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
pub type TierHasher = adapters::hasher::SipHasher13Adapter;

#[cfg(not(feature = "tier-growth"))]
pub type TierHasher = adapters::hasher::MurmurHasher;

/// Create the default hasher for the current tier.
pub fn create_hasher() -> TierHasher {
    TierHasher::default()
}
