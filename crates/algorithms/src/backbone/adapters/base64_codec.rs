//! Base64Codec adapters — wrap encode/decode into the `Base64Codec` trait.

use crate::backbone::traits::Base64Codec;

// ── standard ──────────────────────────────────────────────────────

/// Standard base64 implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardBase64;

impl Base64Codec for StandardBase64 {
    #[inline]
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize {
        lynxx_algo::ngx_encode_base64(dst, src)
    }

    #[inline]
    fn decode(&self, dst: &mut [u8], src: &[u8]) -> isize {
        lynxx_algo::ngx_decode_base64(dst, src)
    }

    fn name(&self) -> &'static str { "standard_base64" }
}

/// Base64url (URL-safe) variant.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardBase64Url;

impl Base64Codec for StandardBase64Url {
    #[inline]
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize {
        lynxx_algo::ngx_encode_base64url(dst, src)
    }

    #[inline]
    fn decode(&self, dst: &mut [u8], src: &[u8]) -> isize {
        lynxx_algo::ngx_decode_base64(dst, src)
    }

    fn name(&self) -> &'static str { "standard_base64url" }
}

// ── optimized ──────────────────────────────────────────────────────

/// Optimized base64: uses fast decode, standard encode.
#[derive(Debug, Clone, Copy, Default)]
pub struct FastBase64;

impl Base64Codec for FastBase64 {
    #[inline]
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // No optimized encode yet; delegate to standard
        lynxx_algo::ngx_encode_base64(dst, src)
    }

    #[inline]
    fn decode(&self, dst: &mut [u8], src: &[u8]) -> isize {
        crate::goals::optimized::base64_decode::decode_base64_fast(dst, src)
    }

    fn name(&self) -> &'static str { "fast_base64" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backbone::traits::Base64Codec;

    fn assert_roundtrip(codec: &dyn Base64Codec, src: &[u8]) {
        let mut enc = vec![0u8; src.len() * 2 + 4];
        let elen = codec.encode(&mut enc, src);
        assert!(elen > 0, "encode should produce output");

        let mut dec = vec![0u8; src.len() + 4];
        let dlen = codec.decode(&mut dec, &enc[..elen]);
        assert_eq!(dlen as usize, src.len(), "decoded length mismatch");
        assert_eq!(&dec[..dlen as usize], src, "roundtrip data mismatch");
    }

    #[test]
    fn standard_base64_roundtrip() {
        assert_roundtrip(&StandardBase64, b"Hello, Lynxx!");
    }

    #[test]
    fn standard_base64_empty() {
        let c = StandardBase64;
        let mut enc = vec![0u8; 8];
        let elen = c.encode(&mut enc, b"");
        assert_eq!(elen, 0);
    }

    #[test]
    fn standard_base64_name() {
        assert_eq!(StandardBase64.name(), "standard_base64");
        assert_eq!(StandardBase64Url.name(), "standard_base64url");
    }

    #[test]
    fn fast_base64_roundtrip() {
        assert_roundtrip(&FastBase64, b"Hello, Lynxx!");
    }

    #[test]
    fn fast_base64_name() {
        assert_eq!(FastBase64.name(), "fast_base64");
    }
}
