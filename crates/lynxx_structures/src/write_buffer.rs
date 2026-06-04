/// Alignment-aware write buffer that coalesces many small writes into a
/// single contiguous byte region for efficient bulk flushing (e.g. to disk
/// or a network socket).
///
/// Each appended or reserved chunk is placed at the next alignment-boundary
/// offset. The caller flushes with [`flush_data`](Self::flush_data) and then
/// calls [`reset`](Self::reset) to reuse the buffer without re-allocating.
pub struct AggregateWriteBuffer {
    buffer: Vec<u8>,
    capacity: usize,
    write_pos: usize,
    pending_entries: Vec<WriteEntry>,
    alignment: usize,
}

#[allow(dead_code)]
struct WriteEntry {
    offset: usize,
    length: usize,
    id: u64,
}

/// Lightweight handle pointing to a region inside an [`AggregateWriteBuffer`].
///
/// Returned by [`AggregateWriteBuffer::append`] so the caller can later
/// locate or read back the data it wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteRef {
    /// Caller-supplied identifier for this write.
    pub id: u64,
    /// Byte offset within the buffer where the data starts.
    pub offset: usize,
    /// Length in bytes of the written data.
    pub length: usize,
}

impl AggregateWriteBuffer {
    /// Allocate a buffer of `capacity` bytes with the given write `alignment`.
    ///
    /// # Panics
    /// Panics if `alignment` is not a power of two or if `capacity` is 0.
    pub fn new(capacity: usize, alignment: usize) -> Self {
        assert!(alignment > 0 && alignment.is_power_of_two(), "alignment must be a power of two");
        assert!(capacity > 0, "capacity must be > 0");
        Self {
            buffer: vec![0u8; capacity],
            capacity,
            write_pos: 0,
            pending_entries: Vec::new(),
            alignment,
        }
    }

    /// Append data to the buffer. Returns a `WriteRef` if successful,
    /// or `None` if the buffer cannot fit the data (caller should flush first).
    pub fn append(&mut self, data: &[u8], id: u64) -> Option<WriteRef> {
        if data.is_empty() {
            return None;
        }
        let aligned_pos = self.align_up(self.write_pos);
        // Bug fix (defense in depth): use checked_add so a near-usize::MAX
        // length cannot wrap the bounds check into a false "fits" result.
        match aligned_pos.checked_add(data.len()) {
            Some(end) if end <= self.capacity => {}
            _ => return None,
        }
        self.write_pos = aligned_pos;
        self.buffer[self.write_pos..self.write_pos + data.len()].copy_from_slice(data);
        let write_ref = WriteRef {
            id,
            offset: self.write_pos,
            length: data.len(),
        };
        self.pending_entries.push(WriteEntry {
            offset: self.write_pos,
            length: data.len(),
            id,
        });
        self.write_pos += data.len();
        Some(write_ref)
    }

    /// Reserve space for in-place construction. Returns a mutable slice
    /// the caller can write into, or `None` if there isn't enough room.
    pub fn reserve(&mut self, size: usize, id: u64) -> Option<&mut [u8]> {
        if size == 0 {
            return None;
        }
        let aligned_pos = self.align_up(self.write_pos);
        // Bug fix (defense in depth): use checked_add so a near-usize::MAX
        // size cannot wrap the bounds check into a false "fits" result.
        match aligned_pos.checked_add(size) {
            Some(end) if end <= self.capacity => {}
            _ => return None,
        }
        self.write_pos = aligned_pos;
        let offset = self.write_pos;
        self.pending_entries.push(WriteEntry {
            offset,
            length: size,
            id,
        });
        self.write_pos += size;
        Some(&mut self.buffer[offset..offset + size])
    }

    /// Read back data from the buffer (for read-while-write scenarios).
    pub fn read(&self, offset: usize, length: usize) -> Option<&[u8]> {
        // Bug fix: the previous guard `offset + length > self.write_pos` could
        // overflow. With overflow-checks off (release) `offset + length` wraps
        // (e.g. usize::MAX + 1 -> 0), the comparison passes as in-bounds, and
        // the slice `buffer[usize::MAX..0]` panics on the inverted range; in
        // debug the add itself panics. Use checked_add so an overflowing
        // request returns None instead of panicking.
        match offset.checked_add(length) {
            Some(end) if length != 0 && end <= self.write_pos => {
                Some(&self.buffer[offset..end])
            }
            _ => None,
        }
    }

    /// Get the buffer contents for flushing, aligned up to the alignment boundary.
    pub fn flush_data(&self) -> &[u8] {
        let flush_end = self.align_up(self.write_pos);
        let end = flush_end.min(self.capacity);
        &self.buffer[..end]
    }

    /// Reset the buffer after a flush, clearing all pending entries.
    pub fn reset(&mut self) {
        // Bug fix: previously reset() rewound write_pos without zeroing the
        // buffer, so a subsequent fill cycle's flush_data() would emit stale
        // bytes from the prior cycle in the alignment-padding region (an
        // information leak of prior-cycle data). Zero the just-used region
        // (rounded up to the alignment boundary, the extent flush_data may
        // expose) before rewinding so padding bytes are always zeros.
        let prev = self.align_up(self.write_pos).min(self.capacity);
        self.buffer[..prev].fill(0);
        self.write_pos = 0;
        self.pending_entries.clear();
    }

    /// How much space is available (before alignment padding).
    pub fn available(&self) -> usize {
        self.capacity.saturating_sub(self.align_up(self.write_pos))
    }

    /// How much data has been written.
    pub fn pending(&self) -> usize {
        self.write_pos
    }

    /// Number of pending entries.
    pub fn entry_count(&self) -> usize {
        self.pending_entries.len()
    }

    /// Is the buffer full (no room for even one aligned byte)?
    pub fn is_full(&self) -> bool {
        self.align_up(self.write_pos) >= self.capacity
    }

    fn align_up(&self, pos: usize) -> usize {
        (pos + self.alignment - 1) & !(self.alignment - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_new_buffer() {
        let buf = AggregateWriteBuffer::new(4096, 512);
        assert_eq!(buf.pending(), 0);
        assert_eq!(buf.entry_count(), 0);
        assert_eq!(buf.available(), 4096);
        assert!(!buf.is_full());
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two")]
    fn test_bad_alignment_panics() {
        AggregateWriteBuffer::new(4096, 3);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn test_zero_capacity_panics() {
        AggregateWriteBuffer::new(0, 512);
    }

    #[test]
    fn test_append_single() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        let data = b"hello";
        let wr = buf.append(data, 1).unwrap();
        assert_eq!(wr.id, 1);
        assert_eq!(wr.offset, 0);
        assert_eq!(wr.length, 5);
        assert_eq!(buf.pending(), 5);
        assert_eq!(buf.entry_count(), 1);
    }

    #[test]
    fn test_append_empty_data_returns_none() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        assert!(buf.append(&[], 1).is_none());
    }

    #[test]
    fn test_append_multiple_aligned() {
        let mut buf = AggregateWriteBuffer::new(4096, 512);
        let wr1 = buf.append(&[1u8; 100], 1).unwrap();
        assert_eq!(wr1.offset, 0);
        assert_eq!(wr1.length, 100);
        // Second append should start at the next 512-byte boundary
        let wr2 = buf.append(&[2u8; 200], 2).unwrap();
        assert_eq!(wr2.offset, 512);
        assert_eq!(wr2.length, 200);
        assert_eq!(buf.entry_count(), 2);
    }

    #[test]
    fn test_append_overflow_returns_none() {
        let mut buf = AggregateWriteBuffer::new(1024, 512);
        buf.append(&[0u8; 600], 1).unwrap();
        // 600 bytes written, next aligned pos is 1024, only 0 bytes left
        assert!(buf.append(&[0u8; 1], 2).is_none());
    }

    #[test]
    fn test_reserve_and_write() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        let slot = buf.reserve(10, 42).unwrap();
        slot.copy_from_slice(b"0123456789");
        assert_eq!(buf.read(0, 10), Some(b"0123456789".as_slice()));
        assert_eq!(buf.entry_count(), 1);
    }

    #[test]
    fn test_reserve_zero_returns_none() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        assert!(buf.reserve(0, 1).is_none());
    }

    #[test]
    fn test_reserve_too_large_returns_none() {
        let mut buf = AggregateWriteBuffer::new(1024, 1);
        assert!(buf.reserve(2048, 1).is_none());
    }

    #[test]
    fn test_read_back() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        buf.append(b"ABCDEF", 1);
        assert_eq!(buf.read(0, 6), Some(b"ABCDEF".as_slice()));
        assert_eq!(buf.read(2, 3), Some(b"CDE".as_slice()));
    }

    #[test]
    fn test_read_out_of_bounds() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        buf.append(b"AB", 1);
        assert!(buf.read(0, 10).is_none());
        assert!(buf.read(5, 1).is_none());
    }

    #[test]
    fn test_read_zero_length() {
        let buf = AggregateWriteBuffer::new(4096, 1);
        assert!(buf.read(0, 0).is_none());
    }

    #[test]
    fn test_flush_data_aligned() {
        let mut buf = AggregateWriteBuffer::new(4096, 512);
        buf.append(&[0xAA; 100], 1);
        let flushed = buf.flush_data();
        // Should be padded to 512 bytes
        assert_eq!(flushed.len(), 512);
        assert_eq!(&flushed[..100], &[0xAA; 100]);
    }

    #[test]
    fn test_flush_data_empty() {
        let buf = AggregateWriteBuffer::new(4096, 512);
        let flushed = buf.flush_data();
        assert_eq!(flushed.len(), 0);
    }

    #[test]
    fn test_reset() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        buf.append(b"data", 1);
        buf.append(b"more", 2);
        assert_eq!(buf.entry_count(), 2);
        assert!(buf.pending() > 0);
        buf.reset();
        assert_eq!(buf.pending(), 0);
        assert_eq!(buf.entry_count(), 0);
        assert_eq!(buf.available(), 4096);
    }

    #[test]
    fn test_available_shrinks() {
        let mut buf = AggregateWriteBuffer::new(1024, 512);
        assert_eq!(buf.available(), 1024);
        buf.append(&[0u8; 100], 1);
        // After 100 bytes, next aligned pos is 512, so 1024-512 = 512 available
        assert_eq!(buf.available(), 512);
    }

    #[test]
    fn test_is_full() {
        let mut buf = AggregateWriteBuffer::new(1024, 512);
        assert!(!buf.is_full());
        buf.append(&[0u8; 600], 1);
        // write_pos = 600, align_up(600) = 1024 >= capacity
        assert!(buf.is_full());
    }

    #[test]
    fn test_alignment_1_no_padding() {
        let mut buf = AggregateWriteBuffer::new(1024, 1);
        buf.append(&[1u8; 3], 1);
        let wr2 = buf.append(&[2u8; 5], 2).unwrap();
        // With alignment=1, second write starts right after the first
        assert_eq!(wr2.offset, 3);
    }

    #[test]
    fn test_multiple_appends_fill_buffer() {
        let mut buf = AggregateWriteBuffer::new(64, 1);
        let mut count = 0;
        while buf.append(&[0xBB; 10], count).is_some() {
            count += 1;
        }
        assert_eq!(count, 6); // 6 * 10 = 60, 7th would be 70 > 64
        assert_eq!(buf.entry_count(), 6);
    }

    #[test]
    fn test_reserve_then_append() {
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        let slot = buf.reserve(4, 1).unwrap();
        slot.copy_from_slice(&[0xFF; 4]);
        let wr = buf.append(b"next", 2).unwrap();
        assert_eq!(wr.offset, 4);
        assert_eq!(buf.read(0, 4), Some([0xFF; 4].as_slice()));
        assert_eq!(buf.read(4, 4), Some(b"next".as_slice()));
    }

    #[test]
    fn test_flush_and_reuse() {
        let mut buf = AggregateWriteBuffer::new(1024, 1);
        buf.append(b"first", 1);
        let flushed = buf.flush_data().to_vec();
        assert!(flushed.len() >= 5);
        buf.reset();
        buf.append(b"second", 2);
        assert_eq!(buf.read(0, 6), Some(b"second".as_slice()));
    }

    #[test]
    fn test_large_alignment() {
        let mut buf = AggregateWriteBuffer::new(8192, 4096);
        buf.append(&[0u8; 1], 1);
        let wr2 = buf.append(&[1u8; 1], 2).unwrap();
        assert_eq!(wr2.offset, 4096);
    }

    #[test]
    fn test_reset_zeros_padding_no_stale_leak() {
        // Regression: reset() must not leave prior-cycle bytes in the region
        // that flush_data() exposes as alignment padding. Without zeroing on
        // reset, bytes 100..512 below would still be 0xAA from the first cycle.
        let mut buf = AggregateWriteBuffer::new(4096, 512);
        buf.append(&[0xAA; 600], 1).unwrap();
        buf.reset();
        buf.append(&[0xBB; 100], 2).unwrap();
        let flushed = buf.flush_data();
        assert_eq!(flushed.len(), 512);
        assert_eq!(&flushed[..100], &[0xBB; 100]);
        // The padding region must be zeros, not the previous cycle's 0xAA.
        assert!(
            flushed[100..512].iter().all(|&b| b == 0),
            "flush_data padding leaked stale bytes from a previous cycle"
        );
    }

    #[test]
    fn test_read_overflow_offset_returns_none() {
        // Regression: read(offset, length) with offset+length overflowing must
        // return None, not panic. Pre-fix the unchecked add wrapped to 0 and
        // the guard passed, then buffer[usize::MAX..0] panicked on release.
        let mut buf = AggregateWriteBuffer::new(4096, 1);
        buf.append(b"hello", 1).unwrap();
        assert!(buf.read(usize::MAX, 1).is_none());
        assert!(buf.read(1, usize::MAX).is_none());
        assert!(buf.read(usize::MAX, usize::MAX).is_none());
    }

    proptest! {
        #[test]
        fn prop_read_after_append(
            ref data in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            let mut buf = AggregateWriteBuffer::new(4096, 1);
            let wr = buf.append(data, 1).unwrap();
            let read_back = buf.read(wr.offset, wr.length).unwrap();
            prop_assert_eq!(read_back, data.as_slice());
        }

        #[test]
        fn prop_pending_equals_total_appended(
            ref chunks in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 1..64),
                1..16,
            ),
        ) {
            let mut buf = AggregateWriteBuffer::new(65536, 1);
            let mut expected_pending = 0usize;
            for (i, chunk) in chunks.iter().enumerate() {
                if buf.append(chunk, i as u64).is_some() {
                    expected_pending += chunk.len();
                }
            }
            prop_assert_eq!(buf.pending(), expected_pending);
        }
    }
}
