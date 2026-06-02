//! Runtime tier dispatch for `Base64Codec`.
//!
//! Starter and Growth share the standard implementation; Pro upgrades
//! to the SIMD-style fast decoder.

use crate::backbone::adapters::base64_codec::{FastBase64, StandardBase64};
use crate::backbone::tier::Tier;
use crate::backbone::traits::Base64Codec;

pub enum TierBase64 {
    Standard(StandardBase64),
    Fast(FastBase64),
}

impl TierBase64 {
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Starter | Tier::Growth => TierBase64::Standard(StandardBase64::default()),
            Tier::Pro => TierBase64::Fast(FastBase64::default()),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierBase64::Standard(_) => Tier::Starter,
            TierBase64::Fast(_) => Tier::Pro,
        }
    }
}

impl Base64Codec for TierBase64 {
    #[inline]
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize {
        match self {
            TierBase64::Standard(c) => c.encode(dst, src),
            TierBase64::Fast(c) => c.encode(dst, src),
        }
    }

    #[inline]
    fn decode(&self, dst: &mut [u8], src: &[u8]) -> isize {
        match self {
            TierBase64::Standard(c) => c.decode(dst, src),
            TierBase64::Fast(c) => c.decode(dst, src),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierBase64::Standard(c) => c.name(),
            TierBase64::Fast(c) => c.name(),
        }
    }
}

pub fn create_base64(tier: Tier) -> TierBase64 {
    TierBase64::for_tier(tier)
}
