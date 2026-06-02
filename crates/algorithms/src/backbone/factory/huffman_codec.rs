//! Runtime tier dispatch for `HuffmanCodec`.
//!
//! Starter and Growth share the standard HPACK implementation; Pro
//! upgrades to the branchless fast decoder.

use crate::backbone::adapters::huffman_codec::{FastHuffman, StandardHuffman};
use crate::backbone::tier::Tier;
use crate::backbone::traits::HuffmanCodec;

pub enum TierHuffman {
    Standard(StandardHuffman),
    Fast(FastHuffman),
}

impl TierHuffman {
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Starter | Tier::Growth => TierHuffman::Standard(StandardHuffman::default()),
            Tier::Pro => TierHuffman::Fast(FastHuffman::default()),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierHuffman::Standard(_) => Tier::Starter,
            TierHuffman::Fast(_) => Tier::Pro,
        }
    }
}

impl HuffmanCodec for TierHuffman {
    #[inline]
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize {
        match self {
            TierHuffman::Standard(c) => c.encode(dst, src),
            TierHuffman::Fast(c) => c.encode(dst, src),
        }
    }

    #[inline]
    fn decode(&self, state: &mut u8, src: &[u8], dst: &mut [u8], last: bool) -> i32 {
        match self {
            TierHuffman::Standard(c) => c.decode(state, src, dst, last),
            TierHuffman::Fast(c) => c.decode(state, src, dst, last),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierHuffman::Standard(c) => c.name(),
            TierHuffman::Fast(c) => c.name(),
        }
    }
}

pub fn create_huffman(tier: Tier) -> TierHuffman {
    TierHuffman::for_tier(tier)
}
