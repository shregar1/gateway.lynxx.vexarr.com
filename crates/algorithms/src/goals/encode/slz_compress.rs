//! Stateless LZ77 compressor (HAProxy origin).
//!
//! A simple hash-table based string matcher that emits raw DEFLATE-style
//! (length, distance) pairs. This is intentionally simplified for benchmarking
//! the core matching loop rather than producing standards-compliant output.

const HASH_BITS: usize = 13;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MIN_MATCH: usize = 4;
const MAX_MATCH: usize = 258;
const MAX_DIST: usize = 32768;

/// Stateless LZ77 compressor using a sliding-window hash table.
pub struct SlzCompressor {
    hash_table: Vec<u32>,
    total_in: u64,
    total_out: u64,
}

impl SlzCompressor {
    /// Create a new compressor with an empty hash table.
    pub fn new() -> Self {
        Self {
            hash_table: vec![0u32; HASH_SIZE],
            total_in: 0,
            total_out: 0,
        }
    }

    /// Compress `input` bytes, appending the result to `output`.
    ///
    /// The output format encodes literals as-is and matches as 3-byte
    /// sequences: `[0xFF, length_byte, dist_hi:dist_lo]`. This is a
    /// simplified encoding for profiling the match-finding hot loop.
    pub fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) {
        self.total_in += input.len() as u64;
        let start_out = output.len();
        output.reserve(input.len());

        if input.len() < MIN_MATCH {
            output.extend_from_slice(input);
            self.total_out += (output.len() - start_out) as u64;
            return;
        }

        let mut pos = 0usize;

        while pos + MIN_MATCH <= input.len() {
            let h = self.hash4(input, pos);
            let candidate = self.hash_table[h] as usize;
            self.hash_table[h] = pos as u32;

            let dist = pos.wrapping_sub(candidate);
            if dist > 0 && dist <= MAX_DIST && candidate + MIN_MATCH <= input.len() {
                // Check minimum match
                if input[candidate..candidate + MIN_MATCH] == input[pos..pos + MIN_MATCH] {
                    // Extend match
                    let max_len = MAX_MATCH.min(input.len() - pos);
                    let max_ref = (input.len() - candidate).min(max_len);
                    let limit = max_len.min(max_ref);
                    let mut mlen = MIN_MATCH;
                    while mlen < limit && input[candidate + mlen] == input[pos + mlen] {
                        mlen += 1;
                    }

                    // Emit match: marker, length, distance (2 bytes big-endian)
                    output.push(0xFF);
                    output.push(mlen as u8);
                    output.push((dist >> 8) as u8);
                    output.push(dist as u8);
                    pos += mlen;
                    continue;
                }
            }

            // Emit literal
            output.push(input[pos]);
            pos += 1;
        }

        // Emit remaining literals
        while pos < input.len() {
            output.push(input[pos]);
            pos += 1;
        }

        self.total_out += (output.len() - start_out) as u64;
    }

    /// Reset the compressor state (hash table and counters).
    pub fn reset(&mut self) {
        for slot in self.hash_table.iter_mut() {
            *slot = 0;
        }
        self.total_in = 0;
        self.total_out = 0;
    }

    /// Total bytes fed into `compress()` since creation or last `reset()`.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Total bytes emitted by `compress()` since creation or last `reset()`.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    #[inline]
    fn hash4(&self, data: &[u8], pos: usize) -> usize {
        let v = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        // Knuth multiplicative hash
        ((v.wrapping_mul(2654435761)) >> (32 - HASH_BITS)) as usize
    }
}

impl Default for SlzCompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_short_input() {
        let mut c = SlzCompressor::new();
        let mut out = Vec::new();
        c.compress(b"abc", &mut out);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn compress_no_matches() {
        let mut c = SlzCompressor::new();
        let mut out = Vec::new();
        // All unique 4-byte sequences
        let input: Vec<u8> = (0..128).collect();
        c.compress(&input, &mut out);
        // Without repeats, mostly literals
        assert!(!out.is_empty());
    }

    #[test]
    fn compress_with_repeats() {
        let mut c = SlzCompressor::new();
        let mut out = Vec::new();
        // Repeating pattern should compress
        let input = b"ABCDABCDABCDABCDABCDABCDABCDABCD";
        c.compress(input, &mut out);
        // Output should be smaller due to back-references
        assert!(out.len() < input.len(), "expected compression: out={} < in={}", out.len(), input.len());
    }

    #[test]
    fn total_counters() {
        let mut c = SlzCompressor::new();
        let mut out = Vec::new();
        c.compress(b"hello world!", &mut out);
        assert_eq!(c.total_in(), 12);
        assert!(c.total_out() > 0);
    }

    #[test]
    fn reset_clears_state() {
        let mut c = SlzCompressor::new();
        let mut out = Vec::new();
        c.compress(b"test data here", &mut out);
        c.reset();
        assert_eq!(c.total_in(), 0);
        assert_eq!(c.total_out(), 0);
    }

    #[test]
    fn empty_input() {
        let mut c = SlzCompressor::new();
        let mut out = Vec::new();
        c.compress(b"", &mut out);
        assert!(out.is_empty());
        assert_eq!(c.total_in(), 0);
    }

    #[test]
    fn all_same_byte() {
        let mut c = SlzCompressor::new();
        let mut out = Vec::new();
        let input = vec![b'A'; 1024];
        c.compress(&input, &mut out);
        // Highly repetitive content should compress well
        assert!(out.len() < input.len());
    }
}
