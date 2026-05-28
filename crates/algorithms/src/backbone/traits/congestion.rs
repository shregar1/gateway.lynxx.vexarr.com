//! CongestionController trait — TCP congestion control (pro+ only).

/// ACK information for congestion control updates.
#[cfg(feature = "tier-pro")]
pub struct AckInfo {
    /// Round-trip time in microseconds.
    pub rtt_us: u64,
    /// Bytes acknowledged in this ACK.
    pub bytes_acked: u64,
    /// Current timestamp in milliseconds.
    pub now_ms: u64,
}

/// Congestion controller for TCP flow management.
#[cfg(feature = "tier-pro")]
pub trait CongestionController {
    /// Process an ACK event.
    fn on_ack(&mut self, ack: &AckInfo);

    /// Process a loss event.
    fn on_loss(&mut self);

    /// Current congestion window in bytes.
    fn cwnd(&self) -> u32;

    fn name(&self) -> &'static str;
}
