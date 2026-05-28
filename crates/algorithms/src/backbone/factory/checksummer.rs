//! Tier selection for Checksummer.

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierChecksummer = adapters::checksummer::Crc32Slice8;

#[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
pub type TierChecksummer = adapters::checksummer::Crc32LongTable;

#[cfg(not(feature = "tier-growth"))]
pub type TierChecksummer = adapters::checksummer::Crc32ShortNibble;

/// Create the default checksummer for the current tier.
pub fn create_checksummer() -> TierChecksummer {
    TierChecksummer::default()
}
