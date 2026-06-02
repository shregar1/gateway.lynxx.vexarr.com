//! HuffmanCodec adapters — wrap HPACK Huffman encode/decode.

use crate::backbone::traits::HuffmanCodec;

// ── standard ──────────────────────────────────────────────────────

/// Standard HPACK Huffman implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardHuffman;

impl HuffmanCodec for StandardHuffman {
    #[inline]
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize {
        lynxx_algo::ngx_http_huff_encode(dst, src)
    }

    #[inline]
    fn decode(&self, state: &mut u8, src: &[u8], dst: &mut [u8], last: bool) -> i32 {
        // Use the ptr-based API to track how many bytes were written.
        let dst_start = dst.as_mut_ptr();
        let mut dp = dst_start;
        let rc = unsafe {
            lynxx_algo::ngx_http_huff_decode_ptr(
                state,
                src.as_ptr(),
                src.len(),
                &mut dp,
                last,
            )
        };
        if rc < 0 {
            return rc;
        }
        // Return byte count from pointer delta
        unsafe { dp.offset_from(dst_start) as i32 }
    }

    fn name(&self) -> &'static str { "standard_huffman" }
}

// ── optimized (pro tier) ───────────────────────────────────────────

/// Branchless optimized Huffman: standard encode + fast decode.
#[derive(Debug, Clone, Copy, Default)]
pub struct FastHuffman;

impl HuffmanCodec for FastHuffman {
    #[inline]
    fn encode(&self, dst: &mut [u8], src: &[u8]) -> usize {
        lynxx_algo::ngx_http_huff_encode(dst, src)
    }

    #[inline]
    fn decode(&self, state: &mut u8, src: &[u8], dst: &mut [u8], last: bool) -> i32 {
        crate::goals::optimized::huff_decode::huff_decode_fast(
            state,
            src,
            dst,
            last,
            &lynxx_algo::huff_decode::HUFF_DECODE_BYTE,
            &lynxx_algo::huff_decode::HUFF_DECODE_FLAT,
        )
    }

    fn name(&self) -> &'static str { "fast_huffman" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backbone::traits::HuffmanCodec;

    #[test]
    fn standard_huffman_encode_decode_roundtrip() {
        let c = StandardHuffman;
        let src = b"www.example.com";
        let mut enc = vec![0u8; 256];
        let elen = c.encode(&mut enc, src);
        assert!(elen > 0);

        let mut dec = vec![0u8; 256];
        let mut state: u8 = 0;
        let dlen = c.decode(&mut state, &enc[..elen], &mut dec, true);
        assert!(dlen > 0, "decode should produce output, got {}", dlen);
        assert_eq!(&dec[..dlen as usize], src);
    }

    #[test]
    fn standard_huffman_name() {
        assert_eq!(StandardHuffman.name(), "standard_huffman");
    }

    #[test]
    fn fast_huffman_encode_decode_roundtrip() {
        let c = FastHuffman;
        let src = b"www.example.com";
        let mut enc = vec![0u8; 256];
        let elen = c.encode(&mut enc, src);
        assert!(elen > 0);

        let mut dec = vec![0u8; 256];
        let mut state: u8 = 0;
        let dlen = c.decode(&mut state, &enc[..elen], &mut dec, true);
        assert!(dlen > 0);
        assert_eq!(&dec[..dlen as usize], src);
    }

    #[test]
    fn fast_huffman_name() {
        assert_eq!(FastHuffman.name(), "fast_huffman");
    }
}
