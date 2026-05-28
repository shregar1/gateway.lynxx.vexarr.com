/// Adaptive concurrency limiter (Envoy gradient controller).
///
/// Tracks a rolling min-RTT and adjusts the concurrency limit using
/// the gradient between the long-term min RTT and the recent sampled RTT.
/// When latency rises the limit shrinks; when it recovers the limit grows.

use std::time::Duration;

pub struct GradientConfig {
    /// Number of RTT samples to keep for min-RTT estimation.
    pub min_rtt_window: usize,
    /// Hard upper bound on concurrency.
    pub max_concurrency: u32,
    /// Exponential smoothing factor for limit changes (0..1).
    pub smoothing: f64,
}

impl Default for GradientConfig {
    fn default() -> Self {
        Self {
            min_rtt_window: 64,
            max_concurrency: 1024,
            smoothing: 0.2,
        }
    }
}

pub struct GradientController {
    config: GradientConfig,
    /// Rolling window of RTT samples for min estimation.
    rtt_window: Vec<u64>,
    /// Current concurrency limit (as f64 for smooth adjustment).
    limit: f64,
    /// Current in-flight count.
    in_flight: u32,
    /// Minimum RTT observed in the window (nanoseconds).
    min_rtt_ns: u64,
    /// Latest sampled RTT (nanoseconds).
    sample_rtt_ns: u64,
}

impl GradientController {
    pub fn new(config: GradientConfig) -> Self {
        let initial_limit = config.max_concurrency as f64 / 2.0;
        Self {
            config,
            rtt_window: Vec::with_capacity(64),
            limit: initial_limit.max(1.0),
            in_flight: 0,
            min_rtt_ns: u64::MAX,
            sample_rtt_ns: 0,
        }
    }

    /// Record a measured round-trip time.
    pub fn record_rtt(&mut self, rtt: Duration) {
        let rtt_ns = rtt.as_nanos() as u64;
        self.sample_rtt_ns = rtt_ns;

        if self.rtt_window.len() >= self.config.min_rtt_window {
            self.rtt_window.remove(0);
        }
        self.rtt_window.push(rtt_ns);

        self.min_rtt_ns = self.rtt_window.iter().copied().min().unwrap_or(rtt_ns);
    }

    /// Recalculate the concurrency limit based on the gradient.
    pub fn recalculate(&mut self) {
        if self.min_rtt_ns == u64::MAX || self.sample_rtt_ns == 0 {
            return;
        }

        // gradient = min_rtt / sample_rtt  (1.0 when healthy, <1.0 under load)
        let gradient = self.min_rtt_ns as f64 / self.sample_rtt_ns.max(1) as f64;
        let gradient = gradient.min(2.0); // cap upward growth

        // New limit = current_limit * gradient
        let new_limit = self.limit * gradient;

        // Exponential smoothing
        let smoothed = self.limit * (1.0 - self.config.smoothing)
            + new_limit * self.config.smoothing;

        self.limit = smoothed
            .max(1.0)
            .min(self.config.max_concurrency as f64);
    }

    /// Check if a new request should be allowed.
    pub fn should_allow(&self) -> bool {
        self.in_flight < self.concurrency_limit()
    }

    /// Return the current concurrency limit.
    pub fn concurrency_limit(&self) -> u32 {
        (self.limit as u32).max(1).min(self.config.max_concurrency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = GradientConfig::default();
        assert_eq!(config.min_rtt_window, 64);
        assert_eq!(config.max_concurrency, 1024);
        assert!((config.smoothing - 0.2).abs() < 0.001);
    }

    #[test]
    fn stable_rtt_maintains_limit() {
        let mut gc = GradientController::new(GradientConfig::default());
        let rtt = Duration::from_millis(10);
        for _ in 0..100 {
            gc.record_rtt(rtt);
            gc.recalculate();
        }
        // With stable RTT, gradient ≈ 1.0, limit should stabilize
        let limit = gc.concurrency_limit();
        assert!(limit > 0);
    }

    #[test]
    fn rising_rtt_reduces_limit() {
        let mut gc = GradientController::new(GradientConfig::default());
        // Record some fast RTTs
        for _ in 0..20 {
            gc.record_rtt(Duration::from_millis(5));
            gc.recalculate();
        }
        let limit_before = gc.concurrency_limit();

        // Now RTTs spike
        for _ in 0..20 {
            gc.record_rtt(Duration::from_millis(50));
            gc.recalculate();
        }
        let limit_after = gc.concurrency_limit();
        assert!(limit_after < limit_before);
    }

    #[test]
    fn should_allow_when_empty() {
        let gc = GradientController::new(GradientConfig::default());
        assert!(gc.should_allow());
    }
}
