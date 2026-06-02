//! UriCodec adapters — wrap URI escape/unescape into the `UriCodec` trait.

use crate::backbone::traits::UriCodec;

// ── standard ──────────────────────────────────────────────────────

/// Standard URI escape/unescape.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardUri;

impl UriCodec for StandardUri {
    #[inline]
    fn escape(&self, dst: &mut [u8], src: &[u8]) -> usize {
        lynxx_algo::ngx_escape_uri(dst, src)
    }

    #[inline]
    fn unescape(&self, dst: &mut [u8], src: &[u8]) -> usize {
        lynxx_algo::ngx_unescape_uri(dst, src, true)
    }

    fn name(&self) -> &'static str { "standard_uri" }
}

// ── optimized ──────────────────────────────────────────────────────

/// Branchless optimized URI escape/unescape.
#[derive(Debug, Clone, Copy, Default)]
pub struct FastUri;

impl UriCodec for FastUri {
    #[inline]
    fn escape(&self, dst: &mut [u8], src: &[u8]) -> usize {
        crate::goals::optimized::escape_uri::escape_uri_fast(dst, src)
    }

    #[inline]
    fn unescape(&self, dst: &mut [u8], src: &[u8]) -> usize {
        crate::goals::optimized::unescape_uri::unescape_uri_fast(dst, src, true)
    }

    fn name(&self) -> &'static str { "fast_uri" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backbone::traits::UriCodec;

    #[test]
    fn standard_uri_escape_safe_passthrough() {
        let c = StandardUri;
        let src = b"hello";
        let mut dst = vec![0u8; 32];
        let n = c.escape(&mut dst, src);
        assert_eq!(&dst[..n], b"hello");
    }

    #[test]
    fn standard_uri_escape_special() {
        let c = StandardUri;
        let src = b"a b";
        let mut dst = vec![0u8; 32];
        let n = c.escape(&mut dst, src);
        // space should be percent-encoded
        assert!(n > 3, "escaped output should be longer than input");
    }

    #[test]
    fn standard_uri_name() {
        assert_eq!(StandardUri.name(), "standard_uri");
    }

    #[test]
    fn fast_uri_escape_safe_passthrough() {
        let c = FastUri;
        let src = b"hello";
        let mut dst = vec![0u8; 32];
        let n = c.escape(&mut dst, src);
        assert_eq!(&dst[..n], b"hello");
    }

    #[test]
    fn fast_uri_name() {
        assert_eq!(FastUri.name(), "fast_uri");
    }
}
