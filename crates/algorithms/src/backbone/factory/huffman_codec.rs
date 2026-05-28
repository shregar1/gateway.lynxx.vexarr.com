//! Tier selection for HuffmanCodec (growth+ only).

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierHuffman = adapters::huffman_codec::FastHuffman;

#[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
pub type TierHuffman = adapters::huffman_codec::StandardHuffman;

/// Create the default Huffman codec for the current tier.
#[cfg(feature = "tier-growth")]
pub fn create_huffman() -> TierHuffman {
    TierHuffman::default()
}
