//! Runtime tier dispatch for `Checksummer`.

use crate::backbone::adapters::checksummer::{
    Crc32LongTable, Crc32ShortNibble, Crc32Slice8,
};
use crate::backbone::tier::Tier;
use crate::backbone::traits::Checksummer;

pub enum TierChecksummer {
    Starter(Crc32ShortNibble),
    Growth(Crc32LongTable),
    Pro(Crc32Slice8),
}

impl TierChecksummer {
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Starter => TierChecksummer::Starter(Crc32ShortNibble::default()),
            Tier::Growth => TierChecksummer::Growth(Crc32LongTable::default()),
            Tier::Pro => TierChecksummer::Pro(Crc32Slice8::default()),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierChecksummer::Starter(_) => Tier::Starter,
            TierChecksummer::Growth(_) => Tier::Growth,
            TierChecksummer::Pro(_) => Tier::Pro,
        }
    }
}

impl Checksummer for TierChecksummer {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        match self {
            TierChecksummer::Starter(c) => c.checksum(data),
            TierChecksummer::Growth(c) => c.checksum(data),
            TierChecksummer::Pro(c) => c.checksum(data),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierChecksummer::Starter(c) => c.name(),
            TierChecksummer::Growth(c) => c.name(),
            TierChecksummer::Pro(c) => c.name(),
        }
    }
}

pub fn create_checksummer(tier: Tier) -> TierChecksummer {
    TierChecksummer::for_tier(tier)
}
