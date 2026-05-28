//! HuffmanCodec trait — HPACK Huffman (growth+ only).

/// HPACK Huffman encoder/decoder for HTTP/2 header compression.
#[cfg(feature = "tier-growth")]
pub trait HuffmanCodec {
    /// Huffman-encode `src` into `dst`. Returns bytes written.
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize;

    /// Huffman-decode `src` into `dst` using running `state`.
    /// Set `last` to `true` for the final chunk.
    /// Returns bytes written, or negative on error.
    fn decode(&self, state: &mut u8, src: &[u8], dst: &mut [u8], last: bool) -> i32;

    fn name(&self) -> &'static str;
}
