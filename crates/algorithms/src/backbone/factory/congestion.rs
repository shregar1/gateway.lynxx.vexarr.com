//! Tier selection for CongestionController (pro+ only).

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierCongestion = adapters::congestion::CubicCc;

/// Create the default congestion controller.
#[cfg(feature = "tier-pro")]
pub fn create_congestion() -> TierCongestion {
    TierCongestion::default()
}
