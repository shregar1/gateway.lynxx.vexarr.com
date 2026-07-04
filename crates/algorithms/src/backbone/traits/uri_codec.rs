//! UriCodec trait — URI escape/unescape.

/// URI percent-encoding and decoding for request paths and query strings.
pub trait UriCodec {
    /// Percent-encode `src` into `dst`. Returns bytes written.
    fn escape(&self, dst: &mut [u8], src: &[u8]) -> usize;

    /// Percent-decode `src` into `dst`. Returns bytes written.
    fn unescape(&self, dst: &mut [u8], src: &[u8]) -> usize;

    fn name(&self) -> &'static str;
}
