//! CongestionController adapters — wrap congestion control algorithms.
//!
//! This module is only compiled at `tier-pro`.

use crate::backbone::traits::{AckInfo, CongestionController};

/// TCP CUBIC congestion controller.
pub struct CubicCc {
    inner: crate::goals::congestion::cubic::CubicState,
}

impl CubicCc {
    pub fn new() -> Self {
        Self {
            inner: crate::goals::congestion::cubic::CubicState::new(),
        }
    }
}

impl Default for CubicCc {
    fn default() -> Self { Self::new() }
}

impl CongestionController for CubicCc {
    #[inline]
    fn on_ack(&mut self, ack: &AckInfo) {
        self.inner.on_ack(ack.now_ms);
    }

    #[inline]
    fn on_loss(&mut self) {
        // CubicState::on_loss requires now_ms; use 0 as fallback.
        // In practice the gateway should call on_loss with a timestamp.
        self.inner.on_loss(0);
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
}
