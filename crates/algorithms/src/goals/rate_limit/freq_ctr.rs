/// Sliding-window frequency counter (HAProxy-style).
///
/// Two-window design: the counter keeps a *previous* and *current* window.
/// Reading the counter linearly interpolates between the two windows based
/// on elapsed time within the current period, giving a smooth estimate
/// without per-event timestamps.

pub struct FreqCounter {
    window_ms: u64,
    prev_count: u32,
    curr_count: u32,
    curr_start: u64,
    initialized: bool,
}

impl FreqCounter {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            prev_count: 0,
            curr_count: 0,
            curr_start: 0,
            initialized: false,
        }
    }

    /// Add `count` events at timestamp `now_ms`.
    pub fn add(&mut self, now_ms: u64, count: u32) {
        self.maybe_rotate(now_ms);
        self.curr_count = self.curr_count.saturating_add(count);
    }

    /// Read the interpolated frequency at timestamp `now_ms`.
    pub fn read(&self, now_ms: u64) -> u32 {
        if self.window_ms == 0 {
            return self.curr_count;
        }

        let elapsed = now_ms.saturating_sub(self.curr_start);

        if elapsed >= self.window_ms * 2 {
            // Both windows have expired
            return 0;
        }

        if elapsed >= self.window_ms {
            // Current window has expired, only partial previous window
            // After rotation, curr becomes prev, new curr is 0
            let since_rotation = elapsed - self.window_ms;
            let remaining = self.window_ms.saturating_sub(since_rotation) as f64
                / self.window_ms as f64;
            return (self.curr_count as f64 * remaining) as u32;
        }

        // Linear interpolation between previous and current
        let remaining = self.window_ms.saturating_sub(elapsed) as f64 / self.window_ms as f64;
        let interpolated = self.prev_count as f64 * remaining + self.curr_count as f64;
        interpolated as u32
    }

    /// Return the estimated rate per second.
    pub fn rate_per_sec(&self, now_ms: u64) -> f64 {
        if self.window_ms == 0 {
            return 0.0;
        }
        let count = self.read(now_ms) as f64;
        count / (self.window_ms as f64 / 1000.0)
    }

    fn maybe_rotate(&mut self, now_ms: u64) {
        if !self.initialized {
            self.curr_start = now_ms;
            self.initialized = true;
            return;
        }

        let elapsed = now_ms.saturating_sub(self.curr_start);
        if elapsed >= self.window_ms {
            if elapsed >= self.window_ms * 2 {
                // Both windows expired
                self.prev_count = 0;
                self.curr_count = 0;
            } else {
                self.prev_count = self.curr_count;
                self.curr_count = 0;
            }
            self.curr_start = now_ms;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_window() {
        let mut fc = FreqCounter::new(1000);
        fc.add(100, 5);
        fc.add(200, 3);
        assert_eq!(fc.read(500), 8); // prev=0, curr=8, elapsed=400ms
    }

    #[test]
    fn window_rotation() {
        let mut fc = FreqCounter::new(1000);
        fc.add(0, 10);
        // After 1000ms, rotate
        fc.add(1000, 5);
        // At 1500ms (half of new window elapsed): prev=10, remaining=0.5, curr=5
        let val = fc.read(1500);
        assert_eq!(val, 10); // 10*0.5 + 5 = 10
    }

    #[test]
    fn expired_windows() {
        let mut fc = FreqCounter::new(1000);
        fc.add(0, 10);
        assert_eq!(fc.read(3000), 0);
    }

    #[test]
    fn rate_per_sec_basic() {
        let mut fc = FreqCounter::new(1000);
        fc.add(0, 100);
        let rate = fc.rate_per_sec(500);
        assert!(rate > 50.0);
    }
}
