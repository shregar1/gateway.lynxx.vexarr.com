//! Packed fixed-width element array using 64-bit word operations.
//!
//! Each element occupies 1–32 bits, stored contiguously in a `Vec<u64>`.
//! Provides O(1) get/set with cross-word-boundary handling.

/// A packed array where every element is the same fixed width (1–32 bits),
/// stored contiguously in `u64` words. Elements that straddle a word boundary
/// are handled transparently via split read/write across two words.
///
/// Use [`BitArray::bits_needed`] to compute the minimum width for a given
/// maximum value, then construct with [`BitArray::new`].
pub struct BitArray {
    data: Vec<u64>,
    len: usize,
    bits_per_element: u32,
    mask: u64,
}

impl BitArray {
    /// Allocate a zero-initialized `BitArray` with `len` elements, each
    /// `bits_per_element` bits wide. The backing storage is a `Vec<u64>` with
    /// just enough words to cover `len × bits_per_element` bits.
    ///
    /// # Panics
    /// Panics if `bits_per_element` is 0 or greater than 32.
    pub fn new(len: usize, bits_per_element: u32) -> Self {
        assert!(
            bits_per_element >= 1 && bits_per_element <= 32,
            "bits_per_element must be 1..=32, got {}",
            bits_per_element
        );
        let total_bits = len as u64 * bits_per_element as u64;
        let num_words = ((total_bits + 63) / 64) as usize;
        let mask = if bits_per_element == 64 {
            u64::MAX
        } else {
            (1u64 << bits_per_element) - 1
        };
        Self {
            data: vec![0u64; num_words],
            len,
            bits_per_element,
            mask,
        }
    }

    /// Read the element at `index`, returning its value zero-extended to `u64`.
    ///
    /// # Panics
    /// Panics if `index >= len`.
    #[inline]
    pub fn get(&self, index: usize) -> u64 {
        assert!(index < self.len, "index {} out of bounds (len {})", index, self.len);
        let bit_offset = index as u64 * self.bits_per_element as u64;
        let word_index = (bit_offset / 64) as usize;
        let bit_position = (bit_offset % 64) as u32;

        let lo = self.data[word_index] >> bit_position;

        if bit_position + self.bits_per_element <= 64 {
            lo & self.mask
        } else {
            let hi_bits = self.bits_per_element - (64 - bit_position);
            let hi = self.data[word_index + 1] & ((1u64 << hi_bits) - 1);
            (lo | (hi << (64 - bit_position))) & self.mask
        }
    }

    /// Write `value` to the element at `index`.
    ///
    /// # Panics
    /// Panics if `index >= len` or `value` exceeds the element width.
    #[inline]
    pub fn set(&mut self, index: usize, value: u64) {
        assert!(index < self.len, "index {} out of bounds (len {})", index, self.len);
        assert!(
            value <= self.mask,
            "value {} exceeds max for {}-bit element (max {})",
            value,
            self.bits_per_element,
            self.mask
        );
        let bit_offset = index as u64 * self.bits_per_element as u64;
        let word_index = (bit_offset / 64) as usize;
        let bit_position = (bit_offset % 64) as u32;

        self.data[word_index] &= !(self.mask << bit_position);
        self.data[word_index] |= value << bit_position;

        if bit_position + self.bits_per_element > 64 {
            let hi_bits = self.bits_per_element - (64 - bit_position);
            let hi_mask = (1u64 << hi_bits) - 1;
            self.data[word_index + 1] &= !hi_mask;
            self.data[word_index + 1] |= value >> (64 - bit_position);
        }
    }

    /// Number of logical elements in the array.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the array has zero elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Width (in bits) of each element, as specified at construction time.
    #[inline]
    pub fn bits_per_element(&self) -> u32 {
        self.bits_per_element
    }

    /// Compute the minimum number of bits required to represent every value in
    /// `0..=max_value`. Always returns at least 1 (even for `max_value == 0`).
    pub fn bits_needed(max_value: usize) -> u32 {
        if max_value == 0 {
            return 1;
        }
        (usize::BITS - max_value.leading_zeros()) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_bit_elements() {
        let mut ba = BitArray::new(128, 1);
        for i in 0..128 {
            assert_eq!(ba.get(i), 0);
        }
        ba.set(0, 1);
        ba.set(63, 1);
        ba.set(64, 1);
        ba.set(127, 1);
        assert_eq!(ba.get(0), 1);
        assert_eq!(ba.get(1), 0);
        assert_eq!(ba.get(63), 1);
        assert_eq!(ba.get(64), 1);
        assert_eq!(ba.get(65), 0);
        assert_eq!(ba.get(127), 1);
    }

    #[test]
    fn eight_bit_elements() {
        let mut ba = BitArray::new(100, 8);
        for i in 0..100u64 {
            ba.set(i as usize, i * 2 % 256);
        }
        for i in 0..100u64 {
            assert_eq!(ba.get(i as usize), i * 2 % 256);
        }
    }

    #[test]
    fn seventeen_bit_elements_cross_boundary() {
        let mut ba = BitArray::new(20, 17);
        let vals: Vec<u64> = (0..20).map(|i| (i * 6271) % (1 << 17)).collect();
        for (i, &v) in vals.iter().enumerate() {
            ba.set(i, v);
        }
        for (i, &v) in vals.iter().enumerate() {
            assert_eq!(ba.get(i), v, "mismatch at index {}", i);
        }
    }

    #[test]
    fn thirty_two_bit_elements() {
        let mut ba = BitArray::new(50, 32);
        for i in 0..50u64 {
            let v = (i.wrapping_mul(0xDEAD_BEEF)) & 0xFFFF_FFFF;
            ba.set(i as usize, v);
        }
        for i in 0..50u64 {
            let v = (i.wrapping_mul(0xDEAD_BEEF)) & 0xFFFF_FFFF;
            assert_eq!(ba.get(i as usize), v);
        }
    }

    #[test]
    fn cross_word_boundary_stress() {
        for bpe in [3, 5, 7, 9, 11, 13, 17, 19, 23, 29, 31] {
            let n = 200;
            let mask = (1u64 << bpe) - 1;
            let mut ba = BitArray::new(n, bpe);
            let vals: Vec<u64> = (0..n).map(|i| (i as u64 * 997) & mask).collect();
            for (i, &v) in vals.iter().enumerate() {
                ba.set(i, v);
            }
            for (i, &v) in vals.iter().enumerate() {
                assert_eq!(ba.get(i), v, "bpe={} index={}", bpe, i);
            }
        }
    }

    #[test]
    fn bits_needed_cases() {
        assert_eq!(BitArray::bits_needed(0), 1);
        assert_eq!(BitArray::bits_needed(1), 1);
        assert_eq!(BitArray::bits_needed(2), 2);
        assert_eq!(BitArray::bits_needed(3), 2);
        assert_eq!(BitArray::bits_needed(4), 3);
        assert_eq!(BitArray::bits_needed(255), 8);
        assert_eq!(BitArray::bits_needed(256), 9);
        assert_eq!(BitArray::bits_needed(65535), 16);
        assert_eq!(BitArray::bits_needed(65536), 17);
    }

    #[test]
    fn empty_array() {
        let ba = BitArray::new(0, 8);
        assert!(ba.is_empty());
        assert_eq!(ba.len(), 0);
    }

    #[test]
    fn overwrite_element() {
        let mut ba = BitArray::new(10, 8);
        ba.set(5, 100);
        assert_eq!(ba.get(5), 100);
        ba.set(5, 200);
        assert_eq!(ba.get(5), 200);
    }

    #[test]
    #[should_panic]
    fn set_out_of_bounds() {
        let mut ba = BitArray::new(10, 8);
        ba.set(10, 0);
    }

    #[test]
    #[should_panic]
    fn get_out_of_bounds() {
        let ba = BitArray::new(10, 8);
        ba.get(10);
    }

    #[test]
    #[should_panic]
    fn value_exceeds_width() {
        let mut ba = BitArray::new(10, 4);
        ba.set(0, 16); // max for 4-bit is 15
    }
}
