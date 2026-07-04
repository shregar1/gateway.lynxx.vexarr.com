//! Slow-start weight ramping (Envoy).
//!
//! When a backend is newly added or recovered, its effective weight ramps
//! linearly from 0 to the base weight over `ramp_seconds`.

/// Per-backend ramp state.
struct RampState {
    /// Unix-seconds at which ramping started (`0` = not ramping).
    start_secs: u64,
}

/// Slow-start pool that provides effective weight based on ramp progress.
pub struct SlowStartPool {
    ramps: Vec<RampState>,
    ramp_seconds: u64,
}

impl SlowStartPool {
    /// Create a new pool with `count` backends and the given ramp duration.
    pub fn new(count: usize, ramp_seconds: u64) -> Self {
        assert!(count > 0, "count must be > 0");
        Self {
            ramps: (0..count)
                .map(|_| RampState { start_secs: 0 })
                .collect(),
            ramp_seconds,
        }
    }

    /// Begin ramping backend `idx` starting at `now_secs`.
    pub fn start_ramp(&mut self, idx: usize, now_secs: u64) {
        self.ramps[idx].start_secs = now_secs;
    }

    /// Compute the effective weight of backend `idx` at time `now_secs`.
    ///
    /// If the backend is not ramping (never started or ramp already complete),
    /// returns `base_weight`. During ramp, returns
    /// `base_weight * elapsed / ramp_seconds` (clamped to `[0, base_weight]`).
    pub fn effective_weight(&self, idx: usize, now_secs: u64, base_weight: u32) -> u32 {
        let start = self.ramps[idx].start_secs;
        if start == 0 || self.ramp_seconds == 0 {
            return base_weight;
        }
        let elapsed = now_secs.saturating_sub(start);
        if elapsed >= self.ramp_seconds {
            return base_weight;
        }
        // Linear interpolation: base_weight * elapsed / ramp_seconds
        ((base_weight as u64 * elapsed) / self.ramp_seconds) as u32
    }

    /// Number of backends.
    pub fn len(&self) -> usize {
        self.ramps.len()
    }

    /// Returns true when there are no backends.
    pub fn is_empty(&self) -> bool {
        self.ramps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_ramp_full_weight() {
        let pool = SlowStartPool::new(3, 60);
        assert_eq!(pool.effective_weight(0, 100, 100), 100);
    }

    #[test]
    fn ramp_linear() {
        let mut pool = SlowStartPool::new(1, 100);
        pool.start_ramp(0, 1000);

        assert_eq!(pool.effective_weight(0, 1000, 100), 0); // 0% elapsed
        assert_eq!(pool.effective_weight(0, 1025, 100), 25); // 25%
        assert_eq!(pool.effective_weight(0, 1050, 100), 50); // 50%
        assert_eq!(pool.effective_weight(0, 1075, 100), 75); // 75%
        assert_eq!(pool.effective_weight(0, 1100, 100), 100); // 100%
    }

    #[test]
    fn ramp_past_duration_gives_full() {
        let mut pool = SlowStartPool::new(1, 10);
        pool.start_ramp(0, 0);
        assert_eq!(pool.effective_weight(0, 1000, 50), 50);
    }

    #[test]
    fn zero_ramp_seconds() {
        let pool = SlowStartPool::new(1, 0);
        assert_eq!(pool.effective_weight(0, 100, 100), 100);
    }
}
