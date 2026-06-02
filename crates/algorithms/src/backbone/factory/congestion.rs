//! Runtime tier dispatch for `CongestionController`.
//!
//! Available at the Pro tier. Lower tiers receive a CUBIC controller
//! by default (cheap, well-understood); Pro gets BBR for higher
//! throughput on fat pipes. Calls on a lower-tier instance use CUBIC
//! semantics, so a caller that does not need BBR can still exercise
//! the trait through this enum without an explicit gate.

use crate::backbone::adapters::congestion::{BbrCc, CubicCc};
use crate::backbone::tier::Tier;
use crate::backbone::traits::{AckInfo, CongestionController};

pub enum TierCongestion {
    Cubic(CubicCc),
    Bbr(BbrCc),
}

impl TierCongestion {
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Starter | Tier::Growth => TierCongestion::Cubic(CubicCc::new()),
            Tier::Pro => TierCongestion::Bbr(BbrCc::new()),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierCongestion::Cubic(_) => Tier::Starter,
            TierCongestion::Bbr(_) => Tier::Pro,
        }
    }
}

impl CongestionController for TierCongestion {
    #[inline]
    fn on_ack(&mut self, ack: &AckInfo) {
        match self {
            TierCongestion::Cubic(c) => c.on_ack(ack),
            TierCongestion::Bbr(c) => c.on_ack(ack),
        }
    }

    #[inline]
    fn on_loss(&mut self) {
        match self {
            TierCongestion::Cubic(c) => c.on_loss(),
            TierCongestion::Bbr(c) => c.on_loss(),
        }
    }

    #[inline]
    fn cwnd(&self) -> u32 {
        match self {
            TierCongestion::Cubic(c) => c.cwnd(),
            TierCongestion::Bbr(c) => c.cwnd(),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierCongestion::Cubic(c) => c.name(),
            TierCongestion::Bbr(c) => c.name(),
        }
    }
}

pub fn create_congestion(tier: Tier) -> TierCongestion {
    TierCongestion::for_tier(tier)
}
