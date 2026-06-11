//! Runtime tier dispatch for `Hasher`.
//!
//! A single binary compiles every hasher adapter. At construction time
//! the subscription `Tier` selects one variant; the others remain
//! unreachable through this factory (lockdown by selection).

use crate::backbone::adapters::hasher::{MurmurHasher, SipHasher13Adapter, Xxh64Hasher};
use crate::backbone::tier::Tier;
use crate::backbone::traits::Hasher;

/// Tier-dispatched hasher. The variant chosen at construction is fixed
/// for the lifetime of the value; trait calls forward to it without
/// vtable indirection.
pub enum TierHasher {
    Starter(MurmurHasher),
    Growth(SipHasher13Adapter),
    Pro(Xxh64Hasher),
}

impl TierHasher {
    /// Construct the hasher for `tier` using each adapter's default
    /// configuration.
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Starter => TierHasher::Starter(MurmurHasher::default()),
            Tier::Growth => TierHasher::Growth(SipHasher13Adapter::default()),
            Tier::Pro => TierHasher::Pro(Xxh64Hasher::default()),
        }
    }

    /// The runtime tier that this instance was constructed for.
    pub fn tier(&self) -> Tier {
        match self {
            TierHasher::Starter(_) => Tier::Starter,
            TierHasher::Growth(_) => Tier::Growth,
            TierHasher::Pro(_) => Tier::Pro,
        }
    }
}

impl Hasher for TierHasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        match self {
            TierHasher::Starter(h) => h.hash(data),
            TierHasher::Growth(h) => h.hash(data),
            TierHasher::Pro(h) => h.hash(data),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierHasher::Starter(h) => h.name(),
            TierHasher::Growth(h) => h.name(),
            TierHasher::Pro(h) => h.name(),
        }
    }
}

/// Construct the hasher for `tier`.
pub fn create_hasher(tier: Tier) -> TierHasher {
    TierHasher::for_tier(tier)
}
