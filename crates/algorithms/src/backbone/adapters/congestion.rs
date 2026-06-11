//! CongestionController adapters — wrap congestion control algorithms.

use crate::backbone::traits::{AckInfo, CongestionController};

/// TCP CUBIC congestion controller.
pub struct CubicCc {
    inner: crate::goals::congestion::cubic::CubicState,
    /// Last `now_ms` observed on an ACK. The `CongestionController::on_loss`
    /// trait method carries no timestamp, so we cache the most recent ACK time
    /// here and feed it to `CubicState::on_loss` instead of a bogus `0`.
    last_now_ms: u64,
}

impl CubicCc {
    pub fn new() -> Self {
        Self {
            inner: crate::goals::congestion::cubic::CubicState::new(),
            last_now_ms: 0,
        }
    }
}

impl Default for CubicCc {
    fn default() -> Self { Self::new() }
}

impl CongestionController for CubicCc {
    #[inline]
    fn on_ack(&mut self, ack: &AckInfo) {
        // Remember the latest ACK timestamp so a subsequent on_loss() (which
        // the trait gives us without a timestamp) records loss_time_ms on the
        // SAME clock the next on_ack reads from.
        self.last_now_ms = ack.now_ms;
        self.inner.on_ack(ack.now_ms);
    }

    #[inline]
    fn on_loss(&mut self) {
        // BUG FIX: previously forwarded `inner.on_loss(0)`. CubicState stamps
        // loss_time_ms = now_ms, and the next on_ack computes the cubic elapsed
        // time as now_ms.saturating_sub(loss_time_ms)/1000. With a real
        // (boot- or epoch-relative) now_ms but loss_time_ms pinned to 0, that
        // delta was the *absolute* clock value (e.g. ~1000s), so the cubic term
        // C*(t-K)^3 + w_max exploded and cwnd saturated toward u32::MAX right
        // after a loss — the opposite of backing off. Feed the last observed
        // ACK timestamp instead, so the post-loss elapsed time is a small,
        // correct delta (seconds since the loss) rather than wall-clock time.
        self.inner.on_loss(self.last_now_ms);
    }

    #[inline]
    fn cwnd(&self) -> u32 {
        self.inner.cwnd()
    }

    fn name(&self) -> &'static str { "cubic" }
}

/// BBR congestion controller (Google).
pub struct BbrCc {
    inner: crate::goals::congestion::bbr::BbrState,
}

impl BbrCc {
    pub fn new() -> Self {
        Self {
            inner: crate::goals::congestion::bbr::BbrState::new(),
        }
    }
}

impl Default for BbrCc {
    fn default() -> Self { Self::new() }
}

impl CongestionController for BbrCc {
    #[inline]
    fn on_ack(&mut self, ack: &AckInfo) {
        self.inner.on_ack(ack.rtt_us, ack.bytes_acked, ack.now_ms);
    }

    #[inline]
    fn on_loss(&mut self) {
        self.inner.on_loss();
    }

    #[inline]
    fn cwnd(&self) -> u32 {
        self.inner.cwnd()
    }

    fn name(&self) -> &'static str { "bbr" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backbone::traits::CongestionController;

    fn assert_cc_contract(cc: &mut dyn CongestionController) {
        assert!(!cc.name().is_empty());
        let initial_cwnd = cc.cwnd();
        assert!(initial_cwnd > 0, "initial cwnd should be positive");
    }

    #[test]
    fn cubic_contract() {
        let mut cc = CubicCc::new();
        assert_cc_contract(&mut cc);
        assert_eq!(cc.name(), "cubic");
    }

    #[test]
    fn cubic_cwnd_after_ack() {
        let mut cc = CubicCc::new();
        let ack = AckInfo { rtt_us: 10_000, bytes_acked: 1460, now_ms: 1000 };
        cc.on_ack(&ack);
        assert!(cc.cwnd() > 0);
    }

    #[test]
    fn bbr_contract() {
        let mut cc = BbrCc::new();
        assert_cc_contract(&mut cc);
        assert_eq!(cc.name(), "bbr");
    }

    #[test]
    fn bbr_cwnd_after_ack() {
        let mut cc = BbrCc::new();
        let ack = AckInfo { rtt_us: 50_000, bytes_acked: 1460, now_ms: 100 };
        cc.on_ack(&ack);
        assert!(cc.cwnd() > 0);
    }

    /// Regression for the `on_loss(0)` time-math bug: through the trait path,
    /// a loss followed by ACKs at large (boot/epoch-relative) timestamps must
    /// keep cwnd near ssthresh instead of exploding toward u32::MAX.
    ///
    /// Before the fix, CubicCc::on_loss() forwarded `inner.on_loss(0)`, pinning
    /// loss_time_ms to 0; each subsequent on_ack(now_ms ~= 1e6 ms) then saw an
    /// elapsed time of ~1000s, so the cubic target ballooned and cwnd grew
    /// without bound over a handful of ACKs. With the fix, on_loss uses the
    /// last observed ACK timestamp, so the post-loss elapsed time is a tiny,
    /// correct delta and the window recovers gradually.
    #[test]
    fn cubic_on_loss_then_large_ts_acks_stay_near_ssthresh() {
        let mut cc = CubicCc::new();

        // Warm the window with ACKs at a large, monotonic wall-clock-ish time.
        let base_ms = 1_000_000u64;
        for i in 0..30u64 {
            cc.on_ack(&AckInfo { rtt_us: 10_000, bytes_acked: 1460, now_ms: base_ms + i });
        }
        let before_loss = cc.cwnd();

        // Loss via the trait (no timestamp). With the fix this records
        // loss_time_ms ~= base_ms + 29 rather than 0.
        cc.on_loss();
        let after_loss = cc.cwnd();
        // Loss must back the window off below where it was.
        assert!(after_loss < before_loss, "loss did not reduce cwnd");

        // Now a burst of ACKs at timestamps just after the loss. The elapsed
        // time per ACK is only milliseconds.
        for i in 0..16u64 {
            cc.on_ack(&AckInfo {
                rtt_us: 10_000,
                bytes_acked: 1460,
                now_ms: base_ms + 30 + i,
            });
        }

        // With the bug, these ACks each saw ~1000s of "elapsed" time and the
        // window doubled per ACK toward saturation (thousands of segments).
        // With the fix the elapsed delta is ~ms, so cwnd stays close to the
        // post-loss ssthresh. Use a generous-but-decisive bound: the bug pushes
        // this into the tens of thousands; the fix keeps it well under 200.
        let after_acks = cc.cwnd();
        assert!(
            after_acks < 200,
            "cwnd {after_acks} exploded after loss+large-timestamp ACKs (bug reproduced; was {after_loss} right after loss)"
        );
    }
}
