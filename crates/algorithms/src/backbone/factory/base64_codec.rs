//! Tier selection for Base64Codec.

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierBase64 = adapters::base64_codec::FastBase64;

#[cfg(not(feature = "tier-pro"))]
pub type TierBase64 = adapters::base64_codec::StandardBase64;

/// Create the default base64 codec for the current tier.
pub fn create_base64() -> TierBase64 {
    TierBase64::default()
}
