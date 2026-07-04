//! Base64Codec trait — encode/decode.

/// Base64 encode and decode for header values, tokens, and body encoding.
pub trait Base64Codec {
    /// Encode `src` into `dst`. Returns bytes written.
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize;

    /// Decode `src` into `dst`. Returns bytes written, or negative on error.
    fn decode(&self, dst: &mut [u8], src: &[u8]) -> isize;

    fn name(&self) -> &'static str;
}
