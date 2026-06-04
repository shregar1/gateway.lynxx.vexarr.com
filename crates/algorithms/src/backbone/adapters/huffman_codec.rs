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
        // Delegate to the bounds-checked decoder. The previous implementation
        // called `ngx_http_huff_decode_ptr`, which takes a raw start pointer
        // and `src.len()` but never relates the decoded length to `dst.len()`.
        // HPACK Huffman expands its input, so any source whose decoded form is
        // longer than `dst` wrote past the end of the buffer — an unbounded
        // OOB-write primitive in a network-facing decoder. (The slice API
        // `ngx_http_huff_decode` only bounds the final-chunk path; its
        // streaming path still uses the unchecked `dec_byte_fast`.)
        //
        // `huff_decode_fast` gates every write on the remaining capacity of
        // `dst` and returns a negative error on overflow instead of writing.
        // It uses the same HPACK Huffman tables, so decoded output is
        // identical; only the bounds checking differs.
        crate::goals::optimized::huff_decode::huff_decode_fast(
            state,
            src,
            dst,
            last,
            &lynxx_algo::huff_decode::HUFF_DECODE_BYTE,
            &lynxx_algo::huff_decode::HUFF_DECODE_FLAT,
        )
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
    fn standard_huffman_decode_rejects_overflow_instead_of_writing_oob() {
        // Regression: StandardHuffman::decode used to call the unbounded
        // ptr decoder and write past `dst` when the decoded output was longer
        // than the buffer. Encode a string that decodes to 15 bytes, then hand
        // decode a 4-byte buffer: it must return a negative error, not write
        // out of bounds. A trailing canary byte guards against an off-by-one
        // overflow corrupting adjacent memory.
        let c = StandardHuffman;
        let src = b"www.example.com";
        let mut enc = vec![0u8; 256];
        let elen = c.encode(&mut enc, src);

        let mut dec = [0u8; 5];
        dec[4] = 0xAB; // canary just past the 4-byte decode window
        let mut state: u8 = 0;
        let rc = c.decode(&mut state, &enc[..elen], &mut dec[..4], true);
        assert!(rc < 0, "decode into too-small buffer must error, got {rc}");
        assert_eq!(dec[4], 0xAB, "decode overran the destination buffer");
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
