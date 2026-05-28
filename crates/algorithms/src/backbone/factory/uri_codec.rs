//! Tier selection for UriCodec.

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierUri = adapters::uri_codec::FastUri;

#[cfg(not(feature = "tier-pro"))]
pub type TierUri = adapters::uri_codec::StandardUri;

/// Create the default URI codec for the current tier.
pub fn create_uri_codec() -> TierUri {
    TierUri::default()
}
