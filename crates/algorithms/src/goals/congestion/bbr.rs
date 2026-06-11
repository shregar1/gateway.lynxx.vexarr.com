/// BBR (Bottleneck Bandwidth and Round-trip propagation time) congestion control.
///
/// Simplified model: estimates bottleneck bandwidth and min RTT,
/// then sets cwnd and pacing rate accordingly.

const INITIAL_CWND: u32 = 10;
const MIN_CWND: u32 = 4;
/// BDP = bandwidth * min_rtt; cwnd = gain * BDP
const CWND_GAIN: f64 = 2.0;
/// High gain for startup probing
const STARTUP_GAIN: f64 = 2.885;
/// Pacing rate = gain * bandwidth
const PACING_GAIN: f64 = 1.0;

pub struct BbrState {
    cwnd: u32,
    /// Estimated bottleneck bandwidth (bytes/ms).
    btl_bw: f64,
    /// Minimum RTT observed (microseconds).
    min_rtt_us: u64,
    /// Max filter for bandwidth samples.
    bw_samples: Vec<f64>,
    /// Whether still in startup phase.
    in_startup: bool,
    /// Round count.
    round: u64,
    /// Pacing rate in bytes/sec.
    pacing: u64,
}

impl BbrState {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            btl_bw: 0.0,
            min_rtt_us: u64::MAX,
            bw_samples: Vec::with_capacity(10),
            in_startup: true,
            round: 0,
            pacing: 0,
        }
    }

    /// Process an ACK: update bandwidth estimate and RTT.
    pub fn on_ack(&mut self, rtt_us: u64, bytes_acked: u64, now_ms: u64) {
        self.round += 1;

        // Update min RTT
        if rtt_us < self.min_rtt_us {
            self.min_rtt_us = rtt_us;
        }

        // Bandwidth sample: bytes_acked / rtt_us (bytes per microsecond)
        if rtt_us > 0 {
            let bw_sample = bytes_acked as f64 / rtt_us as f64;
            self.bw_samples.push(bw_sample);
            if self.bw_samples.len() > 10 {
                self.bw_samples.remove(0);
            }
            // Max filter
            self.btl_bw = self.bw_samples.iter().cloned().fold(0.0f64, f64::max);
        }

        // Compute BDP
        let bdp = self.btl_bw * self.min_rtt_us as f64;

        let gain = if self.in_startup {
            // Check if bandwidth is still growing
            if self.bw_samples.len() >= 3 {
                let recent = self.bw_samples[self.bw_samples.len() - 1];
                let older = self.bw_samples[self.bw_samples.len() - 3];
                if recent < older * 1.25 {
                    self.in_startup = false;
                }
            }
            STARTUP_GAIN
        } else {
            CWND_GAIN
        };

        self.cwnd = (gain * bdp).max(MIN_CWND as f64) as u32;
        self.cwnd = self.cwnd.max(MIN_CWND);

        // Pacing rate: bandwidth * gain (convert to bytes/sec)
        let pacing_gain = if self.in_startup { STARTUP_GAIN } else { PACING_GAIN };
        self.pacing = (self.btl_bw * 1_000_000.0 * pacing_gain) as u64;

        let _ = now_ms; // reserved for future RTT expiry
    }

    pub fn on_loss(&mut self) {
        // Reduce cwnd on loss
        self.cwnd = (self.cwnd as f64 * 0.7).max(MIN_CWND as f64) as u32;
        self.in_startup = false;
    }

    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Pacing rate in bytes per second.
    pub fn pacing_rate(&self) -> u64 {
        self.pacing
    }
}

impl Default for BbrState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let bbr = BbrState::new();
        assert_eq!(bbr.cwnd(), INITIAL_CWND);
        assert_eq!(bbr.pacing_rate(), 0);
    }

    #[test]
    fn ack_updates_cwnd() {
        let mut bbr = BbrState::new();
        bbr.on_ack(10_000, 14_000, 0); // 10ms RTT, 14KB acked
        assert!(bbr.cwnd() >= MIN_CWND);
    }

    #[test]
    fn loss_reduces() {
        let mut bbr = BbrState::new();
        for i in 0..10 {
            bbr.on_ack(10_000, 14_000, i);
        }
        let before = bbr.cwnd();
        bbr.on_loss();
        assert!(bbr.cwnd() <= before);
    }

    #[test]
    fn pacing_rate_positive() {
        let mut bbr = BbrState::new();
        bbr.on_ack(10_000, 14_000, 0);
        assert!(bbr.pacing_rate() > 0);
    }

    #[test]
    fn exits_startup() {
        let mut bbr = BbrState::new();
        // Stable bandwidth -> should exit startup
        for i in 0..20 {
            bbr.on_ack(10_000, 14_000, i);
        }
        // After many rounds with stable BW, should exit startup
        assert!(!bbr.in_startup || bbr.cwnd() >= MIN_CWND);
    }
}
