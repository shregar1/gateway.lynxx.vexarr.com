//! Golomb-coded probabilistic set (H2O origin).
//!
//! A compact, immutable set representation using Golomb-Rice coding.
//! Elements are stored as sorted differences encoded with a tunable
//! parameter `p` (the number of least-significant bits stored verbatim).

/// A Golomb-Rice coded set for probabilistic membership testing.
///
/// Constructed from a sorted list of `u64` hashes. Membership queries
/// have a false-positive rate of approximately `2^(-p)`.
pub struct GolombSet {
    /// Golomb parameter (number of remainder bits).
    p: u8,
    /// Number of elements in the set.
    count: usize,
    /// Bounded universe `N = n * 2^p` into which hashes are reduced before
    /// delta-coding. Stored so `contains` can apply the identical reduction.
    universe: u64,
    /// Golomb-coded bitstream of sorted deltas.
    data: Vec<u8>,
}

impl GolombSet {
    /// Build a `GolombSet` from a mutable slice of hashes.
    ///
    /// The slice is sorted in place. Duplicate hashes are collapsed.
    /// `p` controls the Golomb parameter — higher values reduce false positives
    /// but increase storage. Typical values are 8..20.
    pub fn from_hashes(hashes: &mut [u64], p: u8) -> Self {
        if hashes.is_empty() {
            return Self {
                p,
                count: 0,
                universe: 1,
                data: Vec::new(),
            };
        }

        // Golomb-Coded Set: reduce every hash into a bounded universe
        // `N = n * 2^p` before delta-coding. This bounds the average gap
        // between sorted values to ~2^p, keeping unary quotients ~1 and the
        // false-positive rate ~2^-p. Without this, raw 64-bit deltas produce
        // astronomically large unary codes (gigabytes per element).
        let p = p.min(63);
        let universe = reduction_universe(hashes.len(), p);
        for h in hashes.iter_mut() {
            *h %= universe;
        }

        hashes.sort_unstable();

        // Deduplicate in place (slice doesn't have dedup)
        let dedup_len = {
            let mut write = 0;
            for read in 1..hashes.len() {
                if hashes[read] != hashes[write] {
                    write += 1;
                    hashes[write] = hashes[read];
                }
            }
            write + 1
        };
        let hashes = &hashes[..dedup_len];

        let mut writer = BitWriter::new();
        let mask = (1u64 << p) - 1;
        let mut prev = 0u64;

        for &h in hashes.iter() {
            let delta = h.wrapping_sub(prev);
            let q = delta >> p;
            let r = delta & mask;

            // Unary code for quotient: q ones followed by a zero
            for _ in 0..q {
                writer.write_bit(true);
            }
            writer.write_bit(false);

            // Binary code for remainder: p bits
            writer.write_bits(r, p);

            prev = h;
        }

        Self {
            p,
            count: hashes.len(),
            universe,
            data: writer.finish(),
        }
    }

    /// Test whether `hash` might be in the set.
    ///
    /// Returns `true` if the hash is (probably) present, `false` if
    /// definitely absent. False positives are possible.
    pub fn contains(&self, hash: u64) -> bool {
        if self.count == 0 {
            return false;
        }

        // Apply the identical universe reduction used at build time.
        let hash = hash % self.universe;

        let mut reader = BitReader::new(&self.data);
        let mut current = 0u64;

        for _ in 0..self.count {
            // Decode unary quotient
            let mut q = 0u64;
            loop {
                match reader.read_bit() {
                    Some(true) => q += 1,
                    Some(false) => break,
                    None => return false,
                }
            }

            // Decode binary remainder
            let r = match reader.read_bits(self.p) {
                Some(v) => v,
                None => return false,
            };

            let delta = (q << self.p) | r;
            current = current.wrapping_add(delta);

            if current == hash {
                return true;
            }
            if current > hash {
                return false;
            }
        }

        false
    }

    /// Number of elements stored in the set.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the set contains no elements.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Size of the encoded bitstream in bytes.
    pub fn byte_size(&self) -> usize {
        self.data.len()
    }
}

/// Compute the bounded universe `N = n * 2^p` for the Golomb-Coded Set,
/// saturating to `u64::MAX` if the product would overflow. Always at least 1.
fn reduction_universe(n: usize, p: u8) -> u64 {
    (n as u64)
        .checked_shl(p as u32)
        .unwrap_or(u64::MAX)
        .max(1)
}

// ── Bit-level I/O helpers ──

struct BitWriter {
    buf: Vec<u8>,
    current: u8,
    bit_pos: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            current: 0,
            bit_pos: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current |= 1 << (7 - self.bit_pos);
        }
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.buf.push(self.current);
            self.current = 0;
            self.bit_pos = 0;
        }
    }

    fn write_bits(&mut self, value: u64, count: u8) {
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.buf.push(self.current);
        }
        self.buf
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1 == 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }

    fn read_bits(&mut self, count: u8) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..count {
            let bit = self.read_bit()?;
            value = (value << 1) | (bit as u64);
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set() {
        let gs = GolombSet::from_hashes(&mut [], 8);
        assert_eq!(gs.len(), 0);
        assert!(gs.is_empty());
        assert!(!gs.contains(42));
    }

    #[test]
    fn single_element() {
        let mut hashes = vec![100u64];
        let gs = GolombSet::from_hashes(&mut hashes, 8);
        assert_eq!(gs.len(), 1);
        assert!(gs.contains(100));
        assert!(!gs.contains(99));
        assert!(!gs.contains(101));
    }

    #[test]
    fn multiple_elements() {
        let mut hashes = vec![10, 20, 30, 40, 50];
        let gs = GolombSet::from_hashes(&mut hashes, 8);
        assert_eq!(gs.len(), 5);
        for &h in &[10, 20, 30, 40, 50] {
            assert!(gs.contains(h), "should contain {}", h);
        }
        assert!(!gs.contains(15));
        assert!(!gs.contains(25));
    }

    #[test]
    fn deduplicates() {
        let mut hashes = vec![5, 5, 10, 10, 10, 15];
        let gs = GolombSet::from_hashes(&mut hashes, 8);
        assert_eq!(gs.len(), 3);
    }

    #[test]
    fn sorts_input() {
        let mut hashes = vec![50, 10, 30, 20, 40];
        let gs = GolombSet::from_hashes(&mut hashes, 8);
        assert_eq!(gs.len(), 5);
        for &h in &[10, 20, 30, 40, 50] {
            assert!(gs.contains(h));
        }
    }

    #[test]
    fn compact_representation() {
        let mut hashes: Vec<u64> = (0..1000).map(|i| i * 100).collect();
        let gs = GolombSet::from_hashes(&mut hashes, 10);
        assert_eq!(gs.len(), 1000);
        // Should be significantly smaller than 8000 bytes (1000 * 8)
        assert!(gs.byte_size() < 4000, "byte_size={} should be compact", gs.byte_size());
    }

    #[test]
    fn byte_size_empty() {
        let gs = GolombSet::from_hashes(&mut [], 8);
        assert_eq!(gs.byte_size(), 0);
    }

    #[test]
    fn full_range_hashes_stay_compact() {
        // Regression: raw full-range u64 hashes must not blow up the unary
        // quotient. With universe reduction the stream stays ~p+2 bits/elem.
        let mut val: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut hashes: Vec<u64> = (0..1000)
            .map(|_| {
                val = val
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                val
            })
            .collect();
        let probe = hashes[0];
        let gs = GolombSet::from_hashes(&mut hashes, 10);
        // ~ (p + 2) bits per element → well under 8 bytes/elem (raw storage).
        assert!(
            gs.byte_size() < 1000 * 4,
            "byte_size={} should stay compact",
            gs.byte_size()
        );
        // A value that was inserted must be reported present.
        assert!(gs.contains(probe));
    }

    #[test]
    fn different_p_values() {
        let base: Vec<u64> = (0..100).map(|i| i * 50).collect();
        let mut h1 = base.clone();
        let mut h2 = base.clone();
        let gs1 = GolombSet::from_hashes(&mut h1, 4);
        let gs2 = GolombSet::from_hashes(&mut h2, 12);
        // Both should contain the same elements
        for &h in &base {
            assert!(gs1.contains(h));
            assert!(gs2.contains(h));
        }
        // Higher p should use more bits per remainder
        assert!(gs2.byte_size() > gs1.byte_size());
    }
}
