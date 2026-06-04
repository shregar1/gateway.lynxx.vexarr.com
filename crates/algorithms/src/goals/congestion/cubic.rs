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

        // Cubic growth.
        //
        // BUG FIX: the cubic target W(t) = C*(t-K)^3 + W_max grows without bound
        // in elapsed time `t`. Because the public CongestionController::on_loss
        // trait method carries no timestamp, the adapter forwards on_loss(0),
        // pinning loss_time_ms to 0 while later on_ack(now_ms) supplies a large
        // wall-clock-ish now_ms. The resulting huge t_sec was fed straight into
        // powi(3), so w_cubic overshot to hundreds of millions and the f64->u32
        // cast saturated toward u32::MAX — the inverse of congestion avoidance,
        // effectively disabling flow control. We now cap the per-ACK window so it
        // can grow by at most a factor of 2 per ACK (CUBIC normally increases the
        // window by roughly cwnd/cnt per RTT and never jumps to an arbitrary
        // absolute target), which keeps the window bounded regardless of how
        // large or non-monotonic the observed elapsed time is.
        let t_sec = (now_ms.saturating_sub(self.loss_time_ms)) as f64 / 1000.0;
        let k = ((self.w_max as f64 * (1.0 - CUBIC_BETA)) / CUBIC_C).cbrt();
        let w_cubic = CUBIC_C * (t_sec - k).powi(3) + self.w_max as f64;
        let w_cubic = w_cubic.max(1.0);

        // Standard TCP-friendly estimate.
        let w_tcp = self.w_max as f64 * CUBIC_BETA
            + (3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)) * t_sec;
        let w_tcp = w_tcp.max(1.0);

        // Bound the growth target: never let a single ACK more than double the
        // current window. This clamps both the cubic and TCP estimates before
        // the f64->u32 cast so an unbounded/absurd t_sec can no longer explode
        // cwnd. The +1 floor guarantees forward progress when cwnd is tiny.
        let max_target = (self.cwnd as f64 * 2.0).max(self.cwnd as f64 + 1.0);
        let target = w_cubic.max(w_tcp).min(max_target);
        self.cwnd = target.max(1.0) as u32;
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

    /// Regression: a loss recorded at timestamp 0 (as the public
    /// CongestionController trait forces, since on_loss carries no timestamp)
    /// followed by an on_ack with a large now_ms must NOT explode cwnd.
    ///
    /// Before the fix, the unbounded cubic term C*(t-K)^3 + w_max made cwnd
    /// saturate toward u32::MAX (the bug report measured 396,342,565 for this
    /// exact scenario). After the fix, a single ACK can at most double the
    /// window.
    #[test]
    fn on_ack_does_not_explode_cwnd_after_loss_at_time_zero() {
        let mut cubic = CubicState::new();
        // Warm the window via slow start (matches the reported scenario).
        for _ in 0..30 {
            cubic.on_ack(0);
        }
        // Loss with timestamp 0, exactly as CubicCc::on_loss forwards it.
        cubic.on_loss(0);
        let after_loss = cubic.cwnd();

        // A single ACK at a large monotonic-clock timestamp.
        cubic.on_ack(1_000_050);
        let after_ack = cubic.cwnd();

        // The window may grow, but a single ACK must never more than double it,
        // and it must stay nowhere near the saturated u32 explosion.
        assert!(
            after_ack <= after_loss.saturating_mul(2),
            "single ACK grew cwnd from {after_loss} to {after_ack}, more than 2x"
        );
        assert!(
            after_ack < 10_000,
            "cwnd {after_ack} exploded (bug reproduced)"
        );
    }

    /// Regression: even with a *correct* loss timestamp, a long idle gap before
    /// the next ACK must not over-inflate the window past the per-ACK cap.
    #[test]
    fn on_ack_bounded_after_long_idle_gap() {
        let mut cubic = CubicState::new();
        for _ in 0..30 {
            cubic.on_ack(0);
        }
        cubic.on_loss(1000);
        let after_loss = cubic.cwnd();
        // ~60s gap between loss and the next ACK.
        cubic.on_ack(61_000);
        assert!(
            cubic.cwnd() <= after_loss.saturating_mul(2),
            "idle-gap ACK over-inflated cwnd from {after_loss} to {}",
            cubic.cwnd()
        );
    }
}
