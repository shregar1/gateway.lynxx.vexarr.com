#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRequest {
    pub block_index: u64,
    pub byte_start: u64,
    pub byte_end: u64,
    pub skip_bytes: u64,
    pub take_bytes: u64,
}

pub struct RangeSlicer {
    block_size: u64,
}

impl RangeSlicer {
    pub fn new(block_size: u64) -> Self {
        assert!(block_size > 0, "block_size must be > 0");
        Self { block_size }
    }

    /// Decompose a range request into block-aligned sub-requests.
    /// `range.end` is inclusive.
    pub fn slice(&self, range: &ContentRange) -> Vec<BlockRequest> {
        if range.start > range.end {
            return Vec::new();
        }

        // BUG FIX: `parse_range_header` encodes open-ended (`500-`) and suffix
        // (`-500`) ranges with `end == u64::MAX` as an unresolved sentinel that
        // the caller is expected to resolve against a known total first. Without
        // this guard, slicing such a range computed a block count of ~1.8e16,
        // so `Vec::with_capacity` below requested an astronomically large buffer
        // (allocator-abort / capacity-overflow) and the inclusive loop would run
        // ~18 quadrillion iterations (resource-exhaustion DoS / process abort).
        // Refuse to slice an unresolved sentinel range and any range whose block
        // count would exceed what a `Vec` can hold; the caller must resolve the
        // sentinel (clamp `end` to `total - 1`) before calling `slice`.
        if range.end == u64::MAX {
            return Vec::new();
        }

        let first_block = self.block_for_byte(range.start);
        let last_block = self.block_for_byte(range.end);

        // `last_block >= first_block` here (start <= end), so this cannot
        // underflow; `+ 1` cannot overflow because `last_block < u64::MAX`
        // (we rejected `end == u64::MAX` above, so `end / block_size` is
        // strictly less than `u64::MAX` for any `block_size >= 1`).
        let block_count = last_block - first_block + 1;

        // Defensive cap: if the resolved range is still pathologically large
        // (more blocks than a `Vec` can index), bail out instead of attempting
        // a giant allocation / loop.
        if block_count > usize::MAX as u64 {
            return Vec::new();
        }

        let mut blocks = Vec::with_capacity(block_count as usize);

        for idx in first_block..=last_block {
            let (block_start, block_end) = self.block_range(idx);

            let effective_start = range.start.max(block_start);
            let effective_end = range.end.min(block_end);

            blocks.push(BlockRequest {
                block_index: idx,
                byte_start: block_start,
                byte_end: block_end,
                skip_bytes: effective_start - block_start,
                take_bytes: effective_end - effective_start + 1,
            });
        }

        blocks
    }

    /// Get the block index for a byte offset.
    pub fn block_for_byte(&self, byte_offset: u64) -> u64 {
        byte_offset / self.block_size
    }

    /// Get the byte range (start, end inclusive) for a block index.
    pub fn block_range(&self, block_index: u64) -> (u64, u64) {
        let start = block_index * self.block_size;
        let end = start + self.block_size - 1;
        (start, end)
    }

    /// Check if a byte range fits within a single block.
    pub fn is_single_block(&self, range: &ContentRange) -> bool {
        if range.start > range.end {
            return true;
        }
        self.block_for_byte(range.start) == self.block_for_byte(range.end)
    }

    /// Parse an HTTP `Content-Range` header: `"bytes start-end/total"` or `"bytes start-end/*"`.
    pub fn parse_content_range(header: &str) -> Option<ContentRange> {
        let header = header.trim();
        let rest = header.strip_prefix("bytes ")?;
        let (range_part, total_part) = rest.split_once('/')?;
        let (start_str, end_str) = range_part.split_once('-')?;

        let start: u64 = start_str.trim().parse().ok()?;
        let end: u64 = end_str.trim().parse().ok()?;

        if start > end {
            return None;
        }

        let total = if total_part.trim() == "*" {
            None
        } else {
            Some(total_part.trim().parse::<u64>().ok()?)
        };

        Some(ContentRange { start, end, total })
    }

    /// Format a `Content-Range` header value.
    pub fn format_content_range(range: &ContentRange) -> String {
        match range.total {
            Some(total) => format!("bytes {}-{}/{}", range.start, range.end, total),
            None => format!("bytes {}-{}/*", range.start, range.end),
        }
    }

    /// Parse an HTTP `Range` header: `"bytes=start-end"` (possibly multiple comma-separated ranges).
    /// Each range may omit start (`-500` = last 500 bytes) or end (`500-` = from 500 onwards),
    /// but without a known total size, suffix ranges and open-ended ranges are returned with
    /// sentinel values that the caller must resolve.
    pub fn parse_range_header(header: &str) -> Option<Vec<ContentRange>> {
        let header = header.trim();
        let rest = header.strip_prefix("bytes=")?;

        let mut ranges = Vec::new();
        for part in rest.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some(suffix) = part.strip_prefix('-') {
                let suffix_len: u64 = suffix.trim().parse().ok()?;
                if suffix_len == 0 {
                    return None;
                }
                ranges.push(ContentRange {
                    start: u64::MAX - suffix_len + 1,
                    end: u64::MAX,
                    total: None,
                });
            } else if let Some((start_str, end_str)) = part.split_once('-') {
                let start: u64 = start_str.trim().parse().ok()?;
                if end_str.trim().is_empty() {
                    ranges.push(ContentRange {
                        start,
                        end: u64::MAX,
                        total: None,
                    });
                } else {
                    let end: u64 = end_str.trim().parse().ok()?;
                    if start > end {
                        return None;
                    }
                    ranges.push(ContentRange {
                        start,
                        end,
                        total: None,
                    });
                }
            } else {
                return None;
            }
        }

        if ranges.is_empty() {
            None
        } else {
            Some(ranges)
        }
    }

    pub fn block_size(&self) -> u64 {
        self.block_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RangeSlicer construction ──

    #[test]
    fn test_new_slicer() {
        let s = RangeSlicer::new(1_048_576);
        assert_eq!(s.block_size(), 1_048_576);
    }

    #[test]
    #[should_panic(expected = "block_size must be > 0")]
    fn test_zero_block_size_panics() {
        RangeSlicer::new(0);
    }

    // ── block_for_byte ──

    #[test]
    fn test_block_for_byte() {
        let s = RangeSlicer::new(1024);
        assert_eq!(s.block_for_byte(0), 0);
        assert_eq!(s.block_for_byte(1023), 0);
        assert_eq!(s.block_for_byte(1024), 1);
        assert_eq!(s.block_for_byte(2047), 1);
        assert_eq!(s.block_for_byte(2048), 2);
    }

    // ── block_range ──

    #[test]
    fn test_block_range() {
        let s = RangeSlicer::new(1024);
        assert_eq!(s.block_range(0), (0, 1023));
        assert_eq!(s.block_range(1), (1024, 2047));
        assert_eq!(s.block_range(2), (2048, 3071));
    }

    // ── is_single_block ──

    #[test]
    fn test_is_single_block_true() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 100, end: 500, total: None };
        assert!(s.is_single_block(&r));
    }

    #[test]
    fn test_is_single_block_exact_boundary() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 0, end: 1023, total: None };
        assert!(s.is_single_block(&r));
    }

    #[test]
    fn test_is_single_block_false() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 0, end: 1024, total: None };
        assert!(!s.is_single_block(&r));
    }

    #[test]
    fn test_is_single_block_empty_range() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 500, end: 100, total: None };
        assert!(s.is_single_block(&r));
    }

    // ── slice — single block ──

    #[test]
    fn test_slice_within_single_block() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 100, end: 500, total: Some(10000) };
        let blocks = s.slice(&r);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_index, 0);
        assert_eq!(blocks[0].byte_start, 0);
        assert_eq!(blocks[0].byte_end, 1023);
        assert_eq!(blocks[0].skip_bytes, 100);
        assert_eq!(blocks[0].take_bytes, 401);
    }

    // ── slice — multiple blocks ──

    #[test]
    fn test_slice_across_two_blocks() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 900, end: 1200, total: None };
        let blocks = s.slice(&r);
        assert_eq!(blocks.len(), 2);

        assert_eq!(blocks[0].block_index, 0);
        assert_eq!(blocks[0].skip_bytes, 900);
        assert_eq!(blocks[0].take_bytes, 124); // 1023 - 900 + 1

        assert_eq!(blocks[1].block_index, 1);
        assert_eq!(blocks[1].skip_bytes, 0);
        assert_eq!(blocks[1].take_bytes, 177); // 1200 - 1024 + 1
    }

    #[test]
    fn test_slice_across_many_blocks() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 100, end: 4000, total: Some(10000) };
        let blocks = s.slice(&r);
        assert_eq!(blocks.len(), 4); // blocks 0, 1, 2, 3

        // Verify total take_bytes sum equals range length
        let total_take: u64 = blocks.iter().map(|b| b.take_bytes).sum();
        assert_eq!(total_take, 4000 - 100 + 1);
    }

    // ── slice — edge cases ──

    #[test]
    fn test_slice_exact_block_boundary() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 0, end: 1023, total: None };
        let blocks = s.slice(&r);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].skip_bytes, 0);
        assert_eq!(blocks[0].take_bytes, 1024);
    }

    #[test]
    fn test_slice_single_byte() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 500, end: 500, total: None };
        let blocks = s.slice(&r);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].skip_bytes, 500);
        assert_eq!(blocks[0].take_bytes, 1);
    }

    #[test]
    fn test_slice_empty_range() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 500, end: 100, total: None };
        let blocks = s.slice(&r);
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_slice_at_block_boundary_start() {
        let s = RangeSlicer::new(1024);
        let r = ContentRange { start: 1024, end: 2047, total: None };
        let blocks = s.slice(&r);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_index, 1);
        assert_eq!(blocks[0].skip_bytes, 0);
        assert_eq!(blocks[0].take_bytes, 1024);
    }

    // Regression: slicing an unresolved open-ended (`500-`) or suffix (`-500`)
    // range, whose `end` is the `u64::MAX` sentinel, must NOT attempt to allocate
    // ~1.8e16 blocks / loop ~18 quadrillion times (resource-exhaustion abort).
    // Without the guard in `slice`, `Vec::with_capacity(u64::MAX/block_size)`
    // aborts the process; with it, `slice` returns an empty Vec so the caller is
    // forced to resolve the sentinel against a known total first.
    #[test]
    fn test_slice_open_ended_sentinel_does_not_explode() {
        let s = RangeSlicer::new(1024);

        // Open-ended range as produced by `parse_range_header("bytes=500-")`.
        let open = ContentRange { start: 500, end: u64::MAX, total: None };
        assert!(s.slice(&open).is_empty());

        // Suffix range as produced by `parse_range_header("bytes=-500")`.
        let suffix = ContentRange { start: u64::MAX - 499, end: u64::MAX, total: None };
        assert!(s.slice(&suffix).is_empty());

        // Drive it end-to-end through the parser, matching the reported trigger.
        let parsed = RangeSlicer::parse_range_header("bytes=500-").unwrap();
        assert!(s.slice(&parsed[0]).is_empty());
    }

    // ── parse_content_range ──

    #[test]
    fn test_parse_content_range_with_total() {
        let r = RangeSlicer::parse_content_range("bytes 0-999/8000").unwrap();
        assert_eq!(r.start, 0);
        assert_eq!(r.end, 999);
        assert_eq!(r.total, Some(8000));
    }

    #[test]
    fn test_parse_content_range_unknown_total() {
        let r = RangeSlicer::parse_content_range("bytes 500-999/*").unwrap();
        assert_eq!(r.start, 500);
        assert_eq!(r.end, 999);
        assert_eq!(r.total, None);
    }

    #[test]
    fn test_parse_content_range_with_whitespace() {
        let r = RangeSlicer::parse_content_range("  bytes 10-20/100  ").unwrap();
        assert_eq!(r.start, 10);
        assert_eq!(r.end, 20);
        assert_eq!(r.total, Some(100));
    }

    #[test]
    fn test_parse_content_range_invalid_prefix() {
        assert!(RangeSlicer::parse_content_range("words 0-10/100").is_none());
    }

    #[test]
    fn test_parse_content_range_invalid_range() {
        assert!(RangeSlicer::parse_content_range("bytes 10-5/100").is_none());
    }

    #[test]
    fn test_parse_content_range_missing_slash() {
        assert!(RangeSlicer::parse_content_range("bytes 0-10").is_none());
    }

    #[test]
    fn test_parse_content_range_garbage() {
        assert!(RangeSlicer::parse_content_range("garbage").is_none());
    }

    // ── format_content_range ──

    #[test]
    fn test_format_content_range_with_total() {
        let r = ContentRange { start: 0, end: 999, total: Some(8000) };
        assert_eq!(RangeSlicer::format_content_range(&r), "bytes 0-999/8000");
    }

    #[test]
    fn test_format_content_range_unknown_total() {
        let r = ContentRange { start: 500, end: 999, total: None };
        assert_eq!(RangeSlicer::format_content_range(&r), "bytes 500-999/*");
    }

    #[test]
    fn test_roundtrip_content_range() {
        let original = ContentRange { start: 100, end: 5000, total: Some(10000) };
        let formatted = RangeSlicer::format_content_range(&original);
        let parsed = RangeSlicer::parse_content_range(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    // ── parse_range_header ──

    #[test]
    fn test_parse_range_header_simple() {
        let ranges = RangeSlicer::parse_range_header("bytes=0-499").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 0);
        assert_eq!(ranges[0].end, 499);
    }

    #[test]
    fn test_parse_range_header_multiple() {
        let ranges = RangeSlicer::parse_range_header("bytes=0-499, 1000-1999").unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, 0);
        assert_eq!(ranges[0].end, 499);
        assert_eq!(ranges[1].start, 1000);
        assert_eq!(ranges[1].end, 1999);
    }

    #[test]
    fn test_parse_range_header_open_end() {
        let ranges = RangeSlicer::parse_range_header("bytes=1024-").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 1024);
        assert_eq!(ranges[0].end, u64::MAX);
    }

    #[test]
    fn test_parse_range_header_suffix() {
        let ranges = RangeSlicer::parse_range_header("bytes=-500").unwrap();
        assert_eq!(ranges.len(), 1);
        // Suffix range: last 500 bytes
        assert_eq!(ranges[0].end, u64::MAX);
    }

    #[test]
    fn test_parse_range_header_invalid_prefix() {
        assert!(RangeSlicer::parse_range_header("words=0-10").is_none());
    }

    #[test]
    fn test_parse_range_header_invalid_range() {
        assert!(RangeSlicer::parse_range_header("bytes=10-5").is_none());
    }

    #[test]
    fn test_parse_range_header_empty() {
        assert!(RangeSlicer::parse_range_header("bytes=").is_none());
    }

    #[test]
    fn test_parse_range_header_zero_suffix() {
        assert!(RangeSlicer::parse_range_header("bytes=-0").is_none());
    }

    // ── integration: slice + parse ──

    #[test]
    fn test_parse_then_slice() {
        let s = RangeSlicer::new(1_048_576); // 1 MB blocks
        let ranges = RangeSlicer::parse_range_header("bytes=0-2097151").unwrap();
        let blocks = s.slice(&ranges[0]);
        assert_eq!(blocks.len(), 2); // 2 MB = 2 blocks
        let total_take: u64 = blocks.iter().map(|b| b.take_bytes).sum();
        assert_eq!(total_take, 2_097_152);
    }

    #[test]
    fn test_large_file_slice() {
        let s = RangeSlicer::new(1_048_576);
        let range = ContentRange {
            start: 500_000,
            end: 5_500_000,
            total: Some(100_000_000),
        };
        let blocks = s.slice(&range);
        // 500k..5.5M crosses blocks 0..5 = 6 blocks
        assert_eq!(blocks.len(), 6);
        let total_take: u64 = blocks.iter().map(|b| b.take_bytes).sum();
        assert_eq!(total_take, 5_500_000 - 500_000 + 1);
    }

    #[test]
    fn test_block_continuity() {
        let s = RangeSlicer::new(512);
        let range = ContentRange { start: 100, end: 2000, total: None };
        let blocks = s.slice(&range);

        for pair in blocks.windows(2) {
            let prev_end = pair[0].byte_start + pair[0].skip_bytes + pair[0].take_bytes;
            let next_start = pair[1].byte_start + pair[1].skip_bytes;
            assert_eq!(prev_end, next_start, "blocks must be contiguous");
        }
    }
}
