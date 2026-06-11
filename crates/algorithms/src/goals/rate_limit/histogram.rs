/// Space-efficient histogram with configurable logarithmic ranges.
///
/// Each range is twice the width of the previous, subdivided into 2^S equal spans.
/// Total buckets = R * 2^S where R = range_bits, S = span_bits.
/// Bucket lookup is O(1) via bit manipulation (leading zeros + shift).
pub struct Histogram {
    buckets: Vec<u64>,
    /// Prefix sums for O(log n) percentile queries (`cumulative[i]` = sum of buckets[0..=i]).
    cumulative: Vec<u64>,
    range_bits: u32,
    span_bits: u32,
    total_count: u64,
    min_value: u64,
    max_value: u64,
    sum: u64,
}

impl Histogram {
    /// Create with range_bits R and span_bits S.
    /// Total buckets = R * 2^S.
    pub fn new(range_bits: u32, span_bits: u32) -> Self {
        // At least one bucket: range_bits == 0 (or the product being 0) would
        // otherwise allocate empty buckets/cumulative vecs, and record() would
        // index [0] / compute `len() - 1` → out-of-bounds panic.
        let num_buckets = ((range_bits as usize) * (1usize << span_bits)).max(1);
        Self {
            buckets: vec![0u64; num_buckets],
            cumulative: vec![0u64; num_buckets],
            range_bits,
            span_bits,
            total_count: 0,
            min_value: u64::MAX,
            max_value: 0,
            sum: 0,
        }
    }

    /// Record a sample. O(1) via bit manipulation.
    pub fn record(&mut self, value: u64) {
        if value == 0 {
            // 0 lands in bucket 0, which is ≤ every bucket's upper bound, so it
            // must increment EVERY cumulative entry (exactly like the non-zero
            // branch's `cumulative[clamped..]` with clamped == 0). The old code
            // bumped only cumulative[0], breaking the non-decreasing prefix-sum
            // invariant so that every percentile() query returned garbage once
            // any zero sample had been recorded.
            self.buckets[0] += 1;
            for c in self.cumulative.iter_mut() {
                *c += 1;
            }
            self.total_count += 1;
            self.min_value = 0;
            return;
        }

        let idx = self.bucket_index(value);
        let clamped = idx.min(self.buckets.len() - 1);
        self.buckets[clamped] += 1;
        for c in &mut self.cumulative[clamped..] {
            *c += 1;
        }
        self.total_count += 1;
        self.min_value = self.min_value.min(value);
        self.max_value = self.max_value.max(value);
        self.sum += value;
    }

    /// Get percentile value (e.g., 0.99 for p99).
    pub fn percentile(&self, p: f64) -> u64 {
        if self.total_count == 0 {
            return 0;
        }
        let target = ((self.total_count as f64) * p).ceil() as u64;
        let idx = self
            .cumulative
            .partition_point(|&cum| cum < target)
            .min(self.buckets.len().saturating_sub(1));
        self.bucket_lower_bound(idx)
    }

    pub fn mean(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        self.sum as f64 / self.total_count as f64
    }

    pub fn count(&self) -> u64 {
        self.total_count
    }

    pub fn min(&self) -> u64 {
        if self.total_count == 0 {
            0
        } else {
            self.min_value
        }
    }

    pub fn max(&self) -> u64 {
        self.max_value
    }

    /// Decay all buckets by shifting right (halving counts).
    pub fn decay(&mut self) {
        for bucket in &mut self.buckets {
            *bucket >>= 1;
        }
        self.rebuild_cumulative();
        self.total_count = self.buckets.iter().sum();
        self.sum >>= 1;
    }

    pub fn reset(&mut self) {
        for bucket in &mut self.buckets {
            *bucket = 0;
        }
        self.cumulative.fill(0);
        self.total_count = 0;
        self.min_value = u64::MAX;
        self.max_value = 0;
        self.sum = 0;
    }

    /// Merge another histogram into this one.
    /// Both histograms must have the same range_bits and span_bits.
    pub fn merge(&mut self, other: &Histogram) {
        if self.range_bits != other.range_bits || self.span_bits != other.span_bits {
            return;
        }
        for (i, &count) in other.buckets.iter().enumerate() {
            self.buckets[i] += count;
        }
        self.rebuild_cumulative();
        self.total_count += other.total_count;
        if other.total_count > 0 {
            self.min_value = self.min_value.min(other.min_value);
            self.max_value = self.max_value.max(other.max_value);
        }
        self.sum += other.sum;
    }

    fn rebuild_cumulative(&mut self) {
        let mut running = 0u64;
        for (c, &count) in self.cumulative.iter_mut().zip(self.buckets.iter()) {
            running += count;
            *c = running;
        }
    }

    /// Map a value to its bucket index using bit manipulation.
    /// Range 0 covers [0, 2^S), range 1 covers [2^S, 2^(S+1)), etc.
    /// Within each range, the span is determined by the next S bits.
    fn bucket_index(&self, value: u64) -> usize {
        if value == 0 {
            return 0;
        }

        let spans_per_range = 1u64 << self.span_bits;

        let msb = 63 - value.leading_zeros();

        if msb < self.span_bits {
            return value as usize;
        }

        let range = (msb - self.span_bits + 1) as usize;
        if range >= self.range_bits as usize {
            return self.buckets.len() - 1;
        }

        let shift = msb - self.span_bits;
        let span = ((value >> shift) as usize) & ((spans_per_range as usize) - 1);

        range * (spans_per_range as usize) + span
    }

    /// Get the lower bound value for a given bucket index.
    fn bucket_lower_bound(&self, idx: usize) -> u64 {
        let spans_per_range = 1usize << self.span_bits;
        let range = idx / spans_per_range;
        let span = idx % spans_per_range;

        if range == 0 {
            return span as u64;
        }

        let base = 1u64 << (self.span_bits + range as u32 - 1);
        let span_width = base / (spans_per_range as u64);
        base + (span as u64) * span_width
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_histogram() {
        let h = Histogram::new(8, 4);
        assert_eq!(h.count(), 0);
        assert_eq!(h.min(), 0);
        assert_eq!(h.max(), 0);
        assert_eq!(h.mean(), 0.0);
        assert_eq!(h.buckets.len(), 128);
    }

    #[test]
    fn test_record_single() {
        let mut h = Histogram::new(8, 4);
        h.record(100);
        assert_eq!(h.count(), 1);
        assert_eq!(h.min(), 100);
        assert_eq!(h.max(), 100);
        assert_eq!(h.mean(), 100.0);
    }

    #[test]
    fn test_record_multiple() {
        let mut h = Histogram::new(8, 4);
        h.record(10);
        h.record(20);
        h.record(30);
        assert_eq!(h.count(), 3);
        assert_eq!(h.min(), 10);
        assert_eq!(h.max(), 30);
        assert_eq!(h.mean(), 20.0);
    }

    #[test]
    fn test_record_zero() {
        let mut h = Histogram::new(8, 4);
        h.record(0);
        assert_eq!(h.count(), 1);
    }

    #[test]
    fn test_percentile_median() {
        let mut h = Histogram::new(16, 4);
        for i in 1..=100 {
            h.record(i);
        }
        let p50 = h.percentile(0.50);
        assert!(p50 >= 40 && p50 <= 60, "p50 was {}", p50);
    }

    #[test]
    fn test_percentile_p99() {
        let mut h = Histogram::new(16, 4);
        for i in 1..=1000 {
            h.record(i);
        }
        let p99 = h.percentile(0.99);
        assert!(p99 >= 900 && p99 <= 1000, "p99 was {}", p99);
    }

    #[test]
    fn test_percentile_empty() {
        let h = Histogram::new(8, 4);
        assert_eq!(h.percentile(0.5), 0);
    }

    #[test]
    fn test_decay() {
        let mut h = Histogram::new(8, 4);
        for _ in 0..100 {
            h.record(50);
        }
        assert_eq!(h.count(), 100);
        h.decay();
        assert_eq!(h.count(), 50);
    }

    #[test]
    fn test_reset() {
        let mut h = Histogram::new(8, 4);
        h.record(1);
        h.record(2);
        h.record(3);
        h.reset();
        assert_eq!(h.count(), 0);
        assert_eq!(h.max(), 0);
        assert_eq!(h.sum, 0);
    }

    #[test]
    fn test_merge() {
        let mut h1 = Histogram::new(8, 4);
        let mut h2 = Histogram::new(8, 4);

        h1.record(10);
        h1.record(20);
        h2.record(30);
        h2.record(40);

        h1.merge(&h2);
        assert_eq!(h1.count(), 4);
        assert_eq!(h1.min(), 10);
        assert_eq!(h1.max(), 40);
        assert_eq!(h1.sum, 100);
    }

    #[test]
    fn test_merge_incompatible_rejected() {
        let mut h1 = Histogram::new(8, 4);
        let h2 = Histogram::new(16, 4);
        h1.record(10);
        h1.merge(&h2);
        assert_eq!(h1.count(), 1);
    }

    #[test]
    fn test_bucket_index_monotonic() {
        let h = Histogram::new(16, 4);
        let mut prev_idx = 0;
        for v in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            let idx = h.bucket_index(v);
            assert!(idx >= prev_idx, "non-monotonic at value {}", v);
            prev_idx = idx;
        }
    }

    #[test]
    fn test_large_values() {
        let mut h = Histogram::new(32, 4);
        h.record(u64::MAX / 2);
        h.record(1_000_000_000);
        assert_eq!(h.count(), 2);
        assert_eq!(h.max(), u64::MAX / 2);
    }

    #[test]
    fn test_mean_precision() {
        let mut h = Histogram::new(8, 4);
        for _ in 0..1000 {
            h.record(42);
        }
        assert!((h.mean() - 42.0).abs() < 0.001);
    }

    #[test]
    fn test_different_configurations() {
        let mut h = Histogram::new(4, 2);
        assert_eq!(h.buckets.len(), 16);
        h.record(1);
        h.record(100);
        assert_eq!(h.count(), 2);

        let mut h = Histogram::new(16, 8);
        assert_eq!(h.buckets.len(), 4096);
        h.record(1);
        h.record(1_000_000);
        assert_eq!(h.count(), 2);
    }
}
