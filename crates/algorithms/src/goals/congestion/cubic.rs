/// CUBIC congestion control algorithm.
///
/// Implements the cubic function for window growth:
///   W(t) = C * (t - K)^3 + W_max
/// where K = cbrt(W_max * beta / C) and beta = 0.7.

const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;
const INITIAL_CWND: u32 = 10;

pub struct CubicState {
    /// Current congestion window (in segments).
    cwnd: u32,
    /// Window size when last loss occurred.
    w_max: u32,
    /// Timestamp (ms) when loss occurred.
    loss_time_ms: u64,
    /// Slow-start threshold.
    ssthresh: u32,
    /// Whether we are in slow start.
    in_slow_start: bool,
}

impl CubicState {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            w_max: 0,
            loss_time_ms: 0,
            ssthresh: u32::MAX,
            in_slow_start: true,
        }
    }

    /// Handle an ACK at timestamp `now_ms`.
    pub fn on_ack(&mut self, now_ms: u64) {
        if self.in_slow_start {
            self.cwnd += 1;
            if self.cwnd >= self.ssthresh {
                self.in_slow_start = false;
            }
            return;
        }

        // Cubic growth
        let t_sec = (now_ms.saturating_sub(self.loss_time_ms)) as f64 / 1000.0;
        let k = ((self.w_max as f64 * (1.0 - CUBIC_BETA)) / CUBIC_C).cbrt();
        let w_cubic = CUBIC_C * (t_sec - k).powi(3) + self.w_max as f64;
        let w_cubic = w_cubic.max(1.0) as u32;

        // Standard TCP-friendly estimate
        let w_tcp = self.w_max as f64 * CUBIC_BETA
            + (3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)) * t_sec;
        let w_tcp = w_tcp.max(1.0) as u32;

        self.cwnd = w_cubic.max(w_tcp);
    }

    /// Handle a loss event at timestamp `now_ms`.
    pub fn on_loss(&mut self, now_ms: u64) {
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd as f64 * CUBIC_BETA) as u32;
        self.ssthresh = self.ssthresh.max(2);
        self.cwnd = self.ssthresh;
        self.loss_time_ms = now_ms;
        self.in_slow_start = false;
    }

    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }
}

impl Default for CubicState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_grows() {
        let mut cubic = CubicState::new();
        let initial = cubic.cwnd();
        for _ in 0..5 {
            cubic.on_ack(0);
        }
        assert!(cubic.cwnd() > initial);
    }

    #[test]
    fn loss_reduces_window() {
        let mut cubic = CubicState::new();
        for _ in 0..20 {
            cubic.on_ack(0);
        }
        let before = cubic.cwnd();
        cubic.on_loss(100);
        assert!(cubic.cwnd() < before);
    }

    #[test]
    fn recovers_after_loss() {
        let mut cubic = CubicState::new();
        for i in 0..50 {
            cubic.on_ack(i);
        }
        cubic.on_loss(50);
        let after_loss = cubic.cwnd();
        for i in 51..200 {
            cubic.on_ack(i);
        }
        assert!(cubic.cwnd() > after_loss);
    }

    #[test]
    fn never_below_one() {
        let mut cubic = CubicState::new();
        cubic.on_loss(0);
        cubic.on_loss(1);
        cubic.on_loss(2);
        assert!(cubic.cwnd() >= 2);
    }
}
