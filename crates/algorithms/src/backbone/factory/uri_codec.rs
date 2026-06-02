//! Runtime tier dispatch for `UriCodec`.
//!
//! Starter and Growth share the standard implementation; Pro upgrades
//! to the branchless fast escape/unescape.

use crate::backbone::adapters::uri_codec::{FastUri, StandardUri};
use crate::backbone::tier::Tier;
use crate::backbone::traits::UriCodec;

pub enum TierUri {
    Standard(StandardUri),
    Fast(FastUri),
}

impl TierUri {
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Starter | Tier::Growth => TierUri::Standard(StandardUri::default()),
            Tier::Pro => TierUri::Fast(FastUri::default()),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierUri::Standard(_) => Tier::Starter,
            TierUri::Fast(_) => Tier::Pro,
        }
    }
}

impl UriCodec for TierUri {
    #[inline]
    fn escape(&self, dst: &mut [u8], src: &[u8]) -> usize {
        match self {
            TierUri::Standard(c) => c.escape(dst, src),
            TierUri::Fast(c) => c.escape(dst, src),
        }
    }

    #[inline]
    fn unescape(&self, dst: &mut [u8], src: &[u8]) -> usize {
        match self {
            TierUri::Standard(c) => c.unescape(dst, src),
            TierUri::Fast(c) => c.unescape(dst, src),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierUri::Standard(c) => c.name(),
            TierUri::Fast(c) => c.name(),
        }
    }
}

pub fn create_uri_codec(tier: Tier) -> TierUri {
    TierUri::for_tier(tier)
}
