//! Predictive auto-scaling controller inspired by AWS Target Tracking +
//! Predictive Scaling policies.
//!
//! # Architecture
//!
//! ```text
//! Predictive Scaling
//! ├── TimeSeriesBuffer      — Fixed-size circular buffer of (timestamp, value) samples
//! ├── TrendDetector         — Linear regression on recent samples → slope + intercept
//! ├── SeasonalModel         — Per-hour-of-day + per-day-of-week EMA profiles
//! ├── AnomalyDetector       — Z-score based spike detection on rolling window
//! ├── ScalingPredictor      — Combines trend + seasonal + anomaly → capacity forecast
//! ├── TargetTracker         — AWS-style target tracking (keep metric at target value)
//! ├── PredictiveMetrics     — Global AtomicU64 counters
//! └── CooldownManager       — Per-action cooldown enforcement
//! ```
//!
//! # Why
//!
//! AWS Predictive Scaling uses 14 days of historical CloudWatch metrics to
//! train an ML model that forecasts future load and pre-provisions capacity.
//! This module provides a lightweight version:
//!
//! - **Trend detection**: Linear regression on recent samples detects ramp-ups
//!   before they hit thresholds.
//! - **Seasonal patterns**: Per-hour EMA profiles learn daily traffic patterns
//!   (e.g. "traffic peaks at 2pm every day").
//! - **Anomaly detection**: Z-score on a rolling window detects sudden spikes
//!   that don't match the seasonal pattern.
//! - **Target tracking**: Keep a specific metric (CPU, RPS, latency) at a
//!   target value by computing the exact node count needed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

static PREDICTIVE_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_predictive_enabled(enabled: bool) {
    PREDICTIVE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_predictive_enabled() -> bool {
    PREDICTIVE_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// Time-series circular buffer
// ═══════════════════════════════════════════════════════════════════════════

/// A fixed-capacity ring buffer of timestamped samples.
#[derive(Clone)]
pub struct TimeSeriesBuffer {
    samples: Vec<(u64, f64)>, // (unix_secs, value)
    capacity: usize,
    head: usize,
    len: usize,
}

impl TimeSeriesBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(2);
        Self {
            samples: vec![(0, 0.0); cap],
            capacity: cap,
            head: 0,
            len: 0,
        }
    }

    /// Push a sample. Overwrites the oldest if at capacity.
    pub fn push(&mut self, timestamp: u64, value: f64) {
        self.samples[self.head] = (timestamp, value);
        self.head = (self.head + 1) % self.capacity;
        if self.len < self.capacity {
            self.len += 1;
        }
    }

    /// Push a sample with the current system time.
    pub fn push_now(&mut self, value: f64) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.push(ts, value);
    }

    /// Get all samples in chronological order.
    pub fn samples(&self) -> Vec<(u64, f64)> {
        if self.len == 0 {
            return Vec::new();
        }
        let mut result = Vec::with_capacity(self.len);
        let start = if self.len < self.capacity {
            0
        } else {
            self.head
        };
        for i in 0..self.len {
            let idx = (start + i) % self.capacity;
            result.push(self.samples[idx]);
        }
        result
    }

    /// Get the N most recent samples.
    pub fn recent(&self, n: usize) -> Vec<(u64, f64)> {
        let all = self.samples();
        let skip = all.len().saturating_sub(n);
        all[skip..].to_vec()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Average value of all samples.
    pub fn mean(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        let sum: f64 = self.samples().iter().map(|(_, v)| *v).sum();
        sum / self.len as f64
    }

    /// Standard deviation.
    pub fn stddev(&self) -> f64 {
        if self.len < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance: f64 = self
            .samples()
            .iter()
            .map(|(_, v)| {
                let diff = v - mean;
                diff * diff
            })
            .sum::<f64>()
            / (self.len - 1) as f64;
        variance.sqrt()
    }

    /// Minimum value.
    pub fn min_val(&self) -> f64 {
        self.samples()
            .iter()
            .map(|(_, v)| *v)
            .fold(f64::INFINITY, f64::min)
    }

    /// Maximum value.
    pub fn max_val(&self) -> f64 {
        self.samples()
            .iter()
            .map(|(_, v)| *v)
            .fold(f64::NEG_INFINITY, f64::max)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Trend detector — simple linear regression
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a linear regression on time-series data.
#[derive(Debug, Clone)]
pub struct TrendResult {
    /// Slope (value per second). Positive = increasing, negative = decreasing.
    pub slope: f64,
    /// Y-intercept at the first timestamp.
    pub intercept: f64,
    /// R² goodness of fit (0.0 = no fit, 1.0 = perfect).
    pub r_squared: f64,
    /// Number of samples used.
    pub n: usize,
}

impl TrendResult {
    /// Predict value at a given timestamp (extrapolation).
    pub fn predict_at(&self, timestamp: u64, base_timestamp: u64) -> f64 {
        let dt = timestamp.saturating_sub(base_timestamp) as f64;
        self.intercept + self.slope * dt
    }

    /// Predict value N seconds from the base timestamp.
    pub fn predict_ahead(&self, base_timestamp: u64, seconds_ahead: u64) -> f64 {
        self.predict_at(base_timestamp + seconds_ahead, base_timestamp)
    }

    /// Is the trend significantly increasing?
    pub fn is_rising(&self, min_r_squared: f64) -> bool {
        self.slope > 0.0 && self.r_squared >= min_r_squared
    }

    /// Is the trend significantly decreasing?
    pub fn is_falling(&self, min_r_squared: f64) -> bool {
        self.slope < 0.0 && self.r_squared >= min_r_squared
    }
}

/// Compute linear regression on a set of (timestamp, value) samples.
pub fn linear_regression(samples: &[(u64, f64)]) -> Option<TrendResult> {
    let n = samples.len();
    if n < 2 {
        return None;
    }

    // BUG FIX: `samples` arrives in ring/insertion order (not sorted), and
    // TimeSeriesBuffer::push enforces no monotonicity, so a later-inserted
    // sample can carry a smaller timestamp than samples[0] (e.g. after an NTP
    // step or VM clock resync). Using samples[0].0 as the origin then made the
    // `t - base_t` subtraction below underflow for those out-of-order samples,
    // which under overflow-checks=false wrapped to ~1.8e19 (and panicked in
    // debug), poisoning the regression. Anchor on the true minimum timestamp so
    // every x delta is small and non-negative regardless of insertion order.
    let base_t = samples.iter().map(|s| s.0).min().unwrap();
    let n_f = n as f64;

    let mut sum_x = 0.0_f64;
    let mut sum_y = 0.0_f64;
    let mut sum_xy = 0.0_f64;
    let mut sum_xx = 0.0_f64;

    for &(t, v) in samples {
        // saturating_sub: base_t is now the minimum, but keep the saturating
        // form as belt-and-suspenders so this can never underflow/panic.
        let x = t.saturating_sub(base_t) as f64;
        sum_x += x;
        sum_y += v;
        sum_xy += x * v;
        sum_xx += x * x;
    }

    let denom = n_f * sum_xx - sum_x * sum_x;
    if denom.abs() < 1e-12 {
        // All x values are the same — can't compute slope.
        return Some(TrendResult {
            slope: 0.0,
            intercept: sum_y / n_f,
            r_squared: 0.0,
            n,
        });
    }

    let slope = (n_f * sum_xy - sum_x * sum_y) / denom;
    let intercept = (sum_y - slope * sum_x) / n_f;

    // Compute R².
    let mean_y = sum_y / n_f;
    let mut ss_res = 0.0_f64;
    let mut ss_tot = 0.0_f64;
    for &(t, v) in samples {
        // saturating_sub for the same underflow safety as the sums loop above.
        let x = t.saturating_sub(base_t) as f64;
        let predicted = intercept + slope * x;
        ss_res += (v - predicted) * (v - predicted);
        ss_tot += (v - mean_y) * (v - mean_y);
    }

    let r_squared = if ss_tot.abs() < 1e-12 {
        1.0 // Perfect fit (all values equal).
    } else {
        1.0 - ss_res / ss_tot
    };

    Some(TrendResult {
        slope,
        intercept,
        r_squared: r_squared.clamp(0.0, 1.0),
        n,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Seasonal model — day-of-week × hour-of-day EMA
// ═══════════════════════════════════════════════════════════════════════════

/// 7 days × 24 hours = 168 slots for weekly seasonality.
const WEEKLY_SLOTS: usize = 7 * 24;

pub struct SeasonalModel {
    /// EMA per weekly slot (Monday 00:00 = slot 0).
    ema: [f64; WEEKLY_SLOTS],
    /// Observation count per slot (for warmup detection).
    counts: [u32; WEEKLY_SLOTS],
    /// Smoothing factor.
    alpha: f64,
}

impl SeasonalModel {
    pub fn new(alpha: f64) -> Self {
        Self {
            ema: [0.0; WEEKLY_SLOTS],
            counts: [0; WEEKLY_SLOTS],
            alpha: alpha.clamp(0.01, 0.99),
        }
    }

    /// Record an observation at a given day-of-week (0=Mon) and hour (0-23).
    pub fn record(&mut self, day_of_week: u8, hour: u8, value: f64) {
        let slot = self.slot(day_of_week, hour);
        if self.counts[slot] == 0 {
            self.ema[slot] = value;
        } else {
            self.ema[slot] = self.alpha * value + (1.0 - self.alpha) * self.ema[slot];
        }
        self.counts[slot] = self.counts[slot].saturating_add(1);
    }

    /// Predict load for a given day-of-week + hour.
    pub fn predict(&self, day_of_week: u8, hour: u8) -> f64 {
        self.ema[self.slot(day_of_week, hour)]
    }

    /// Is the slot warm enough (enough observations) for reliable prediction?
    pub fn is_warm(&self, day_of_week: u8, hour: u8, min_observations: u32) -> bool {
        self.counts[self.slot(day_of_week, hour)] >= min_observations
    }

    /// Get the peak hour for a given day.
    pub fn peak_hour(&self, day_of_week: u8) -> (u8, f64) {
        let base = (day_of_week % 7) as usize * 24;
        let mut best_hour = 0u8;
        let mut best_val = f64::NEG_INFINITY;
        for h in 0..24u8 {
            let v = self.ema[base + h as usize];
            if v > best_val {
                best_val = v;
                best_hour = h;
            }
        }
        (best_hour, best_val)
    }

    /// Total weekly profile (168 values).
    pub fn weekly_profile(&self) -> &[f64; WEEKLY_SLOTS] {
        &self.ema
    }

    fn slot(&self, day_of_week: u8, hour: u8) -> usize {
        (day_of_week % 7) as usize * 24 + (hour % 24) as usize
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Anomaly detector — rolling Z-score
// ═══════════════════════════════════════════════════════════════════════════

/// Z-score based anomaly detection on a rolling window.
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    pub value: f64,
    pub z_score: f64,
    pub mean: f64,
    pub stddev: f64,
    pub is_anomaly: bool,
}

pub struct AnomalyDetector {
    /// Rolling window of recent values.
    window: TimeSeriesBuffer,
    /// Z-score threshold for anomaly (default: 3.0 = 3 sigma).
    threshold: f64,
}

impl AnomalyDetector {
    pub fn new(window_size: usize, threshold: f64) -> Self {
        Self {
            window: TimeSeriesBuffer::new(window_size),
            threshold: threshold.abs().max(1.0),
        }
    }

    /// Ingest a value and check if it's an anomaly.
    pub fn check(&mut self, timestamp: u64, value: f64) -> AnomalyResult {
        let mean = self.window.mean();
        let stddev = self.window.stddev();

        let z_score = if stddev.abs() < 1e-12 {
            // When stddev ≈ 0, all samples are nearly identical. If the
            // new value differs significantly from the mean, treat it as
            // an anomaly by computing the ratio instead.
            if mean.abs() < 1e-12 {
                0.0 // Can't compare to zero.
            } else {
                let ratio = (value - mean).abs() / mean.abs();
                if ratio > 0.5 {
                    // More than 50% deviation from a flat baseline →
                    // synthetic z-score above threshold.
                    self.threshold + ratio
                } else {
                    0.0
                }
            }
        } else {
            (value - mean) / stddev
        };

        let is_anomaly = self.window.len() >= 10 && z_score.abs() > self.threshold;

        // Record after computing Z-score so the current value doesn't
        // affect the baseline.
        self.window.push(timestamp, value);

        if is_anomaly {
            PREDICTIVE_METRICS
                .anomalies_detected
                .fetch_add(1, Ordering::Relaxed);
        }

        AnomalyResult {
            value,
            z_score,
            mean,
            stddev,
            is_anomaly,
        }
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    pub fn window_len(&self) -> usize {
        self.window.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Target tracker — AWS-style "keep metric at X"
// ═══════════════════════════════════════════════════════════════════════════

/// AWS-style target tracking: compute the node count needed to keep
/// a metric at a specified target value.
#[derive(Debug, Clone)]
pub struct TargetTracker {
    /// The metric value to target (e.g. 0.7 for 70% CPU).
    target_value: f64,
    /// Tolerance band — no action if within ±tolerance of target.
    tolerance: f64,
    /// Minimum nodes.
    min_nodes: u32,
    /// Maximum nodes.
    max_nodes: u32,
}

/// Decision from the target tracker.
#[derive(Debug, Clone, PartialEq)]
pub enum TargetAction {
    /// Current count is fine.
    InBand,
    /// Need to scale to this many nodes.
    ScaleTo(u32),
}

impl TargetTracker {
    pub fn new(target_value: f64, tolerance: f64, min_nodes: u32, max_nodes: u32) -> Self {
        Self {
            target_value: target_value.max(0.01),
            tolerance: tolerance.clamp(0.0, 0.5),
            min_nodes: min_nodes.max(1),
            max_nodes: max_nodes.max(min_nodes.max(1)),
        }
    }

    /// Given current metric value and current node count, compute the
    /// desired node count.
    ///
    /// Formula: desired = ceil(current_nodes * (current_metric / target))
    pub fn evaluate(&self, current_metric: f64, current_nodes: u32) -> TargetAction {
        if current_nodes == 0 {
            return TargetAction::ScaleTo(self.min_nodes);
        }

        // If within tolerance band, no action.
        let lower = self.target_value * (1.0 - self.tolerance);
        let upper = self.target_value * (1.0 + self.tolerance);
        if current_metric >= lower && current_metric <= upper {
            return TargetAction::InBand;
        }

        let ratio = current_metric / self.target_value;
        let desired = (current_nodes as f64 * ratio).ceil() as u32;
        let clamped = desired.clamp(self.min_nodes, self.max_nodes);

        if clamped == current_nodes {
            TargetAction::InBand
        } else {
            PREDICTIVE_METRICS
                .target_adjustments
                .fetch_add(1, Ordering::Relaxed);
            TargetAction::ScaleTo(clamped)
        }
    }

    pub fn target_value(&self) -> f64 {
        self.target_value
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Scaling predictor — combines all signals
// ═══════════════════════════════════════════════════════════════════════════

/// Combined prediction from trend + seasonal + anomaly signals.
#[derive(Debug, Clone)]
pub struct PredictionResult {
    /// Predicted metric value for the forecast horizon.
    pub predicted_value: f64,
    /// Confidence level based on data quality (0.0 = no data, 1.0 = very confident).
    pub confidence: f64,
    /// Recommended node count.
    pub recommended_nodes: u32,
    /// Which signal drove the recommendation.
    pub primary_signal: PredictionSignal,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PredictionSignal {
    Trend,
    Seasonal,
    Anomaly,
    TargetTracking,
    Insufficient,
}

pub struct ScalingPredictor {
    trend_buffer: TimeSeriesBuffer,
    seasonal: SeasonalModel,
    anomaly: AnomalyDetector,
    target_tracker: TargetTracker,
    /// Capacity per node (metric units one node can handle at 100%).
    capacity_per_node: f64,
    /// Headroom — over-provision by this fraction (e.g. 0.2 = 20% buffer).
    headroom: f64,
    /// Minimum trend R² to trust trend extrapolation.
    min_r_squared: f64,
    /// Minimum seasonal observations per slot to trust seasonal prediction.
    min_seasonal_obs: u32,
}

impl ScalingPredictor {
    pub fn new(
        buffer_size: usize,
        anomaly_window: usize,
        capacity_per_node: f64,
        target_value: f64,
        min_nodes: u32,
        max_nodes: u32,
    ) -> Self {
        Self {
            trend_buffer: TimeSeriesBuffer::new(buffer_size),
            seasonal: SeasonalModel::new(0.3),
            anomaly: AnomalyDetector::new(anomaly_window, 3.0),
            target_tracker: TargetTracker::new(target_value, 0.1, min_nodes, max_nodes),
            capacity_per_node: capacity_per_node.max(1.0),
            headroom: 0.2,
            min_r_squared: 0.7,
            min_seasonal_obs: 5,
        }
    }

    /// Ingest a new metric observation.
    pub fn observe(
        &mut self,
        timestamp: u64,
        value: f64,
        day_of_week: u8,
        hour: u8,
        current_nodes: u32,
    ) -> PredictionResult {
        // Feed all models.
        self.trend_buffer.push(timestamp, value);
        self.seasonal.record(day_of_week, hour, value);
        let anomaly = self.anomaly.check(timestamp, value);

        PREDICTIVE_METRICS
            .observations_ingested
            .fetch_add(1, Ordering::Relaxed);

        // ── Anomaly spike → immediate reaction ─────────────────────────
        if anomaly.is_anomaly && anomaly.z_score > 0.0 {
            // Positive spike — scale for the spike value with headroom.
            let needed = self.nodes_for_value(value);
            return PredictionResult {
                predicted_value: value,
                confidence: 0.9,
                recommended_nodes: needed,
                primary_signal: PredictionSignal::Anomaly,
            };
        }

        // ── Trend extrapolation → proactive scale ──────────────────────
        let trend_samples = self.trend_buffer.recent(30);
        if let Some(trend) = linear_regression(&trend_samples) {
            if trend.is_rising(self.min_r_squared) && trend.n >= 10 {
                // Predict 5 minutes ahead.
                let base_t = trend_samples.last().unwrap().0;
                let predicted = trend.predict_ahead(base_t, 300).max(0.0);
                let needed = self.nodes_for_value(predicted);

                PREDICTIVE_METRICS
                    .predictions_made
                    .fetch_add(1, Ordering::Relaxed);

                return PredictionResult {
                    predicted_value: predicted,
                    confidence: trend.r_squared,
                    recommended_nodes: needed,
                    primary_signal: PredictionSignal::Trend,
                };
            }
        }

        // ── Seasonal prediction → stable patterns ──────────────────────
        // Look 1 hour ahead.
        let next_hour = (hour + 1) % 24;
        let next_dow = if next_hour == 0 {
            (day_of_week + 1) % 7
        } else {
            day_of_week
        };

        if self.seasonal.is_warm(next_dow, next_hour, self.min_seasonal_obs) {
            let seasonal_pred = self.seasonal.predict(next_dow, next_hour);
            if seasonal_pred > value * 1.1 {
                // Seasonal model predicts > 10% increase next hour.
                let needed = self.nodes_for_value(seasonal_pred);

                PREDICTIVE_METRICS
                    .predictions_made
                    .fetch_add(1, Ordering::Relaxed);

                return PredictionResult {
                    predicted_value: seasonal_pred,
                    confidence: 0.6,
                    recommended_nodes: needed,
                    primary_signal: PredictionSignal::Seasonal,
                };
            }
        }

        // ── Target tracking fallback ───────────────────────────────────
        match self.target_tracker.evaluate(value, current_nodes) {
            TargetAction::ScaleTo(n) => PredictionResult {
                predicted_value: value,
                confidence: 0.8,
                recommended_nodes: n,
                primary_signal: PredictionSignal::TargetTracking,
            },
            TargetAction::InBand => PredictionResult {
                predicted_value: value,
                confidence: 0.5,
                recommended_nodes: current_nodes,
                primary_signal: PredictionSignal::Insufficient,
            },
        }
    }

    /// Compute how many nodes are needed for a given metric value.
    fn nodes_for_value(&self, value: f64) -> u32 {
        let with_headroom = value * (1.0 + self.headroom);
        let raw = (with_headroom / self.capacity_per_node).ceil() as u32;
        raw.clamp(
            self.target_tracker.min_nodes,
            self.target_tracker.max_nodes,
        )
    }

    pub fn capacity_per_node(&self) -> f64 {
        self.capacity_per_node
    }

    pub fn trend_buffer(&self) -> &TimeSeriesBuffer {
        &self.trend_buffer
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Cooldown manager
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::time::Instant;

/// Manages per-action cooldowns to prevent flapping.
pub struct CooldownManager {
    cooldowns: HashMap<String, (Instant, Duration)>,
}

impl CooldownManager {
    pub fn new() -> Self {
        Self {
            cooldowns: HashMap::new(),
        }
    }

    /// Record that an action was taken. Sets the cooldown timer.
    pub fn record(&mut self, action: &str, cooldown: Duration) {
        self.cooldowns
            .insert(action.to_string(), (Instant::now(), cooldown));
    }

    /// Check if an action is still on cooldown.
    pub fn is_on_cooldown(&self, action: &str) -> bool {
        if let Some((started, duration)) = self.cooldowns.get(action) {
            started.elapsed() < *duration
        } else {
            false
        }
    }

    /// Remaining cooldown time for an action (zero if not on cooldown).
    pub fn remaining(&self, action: &str) -> Duration {
        if let Some((started, duration)) = self.cooldowns.get(action) {
            duration.saturating_sub(started.elapsed())
        } else {
            Duration::ZERO
        }
    }

    /// Clear expired cooldowns.
    pub fn cleanup(&mut self) {
        self.cooldowns
            .retain(|_, (started, duration)| started.elapsed() < *duration);
    }
}

impl Default for CooldownManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct PredictiveMetrics {
    pub observations_ingested: AtomicU64,
    pub predictions_made: AtomicU64,
    pub anomalies_detected: AtomicU64,
    pub target_adjustments: AtomicU64,
}

static PREDICTIVE_METRICS: PredictiveMetrics = PredictiveMetrics {
    observations_ingested: AtomicU64::new(0),
    predictions_made: AtomicU64::new(0),
    anomalies_detected: AtomicU64::new(0),
    target_adjustments: AtomicU64::new(0),
};

pub fn predictive_metrics() -> &'static PredictiveMetrics {
    &PREDICTIVE_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── TimeSeriesBuffer ───────────────────────────────────────────────

    #[test]
    fn buffer_push_and_retrieve() {
        let mut buf = TimeSeriesBuffer::new(5);
        buf.push(100, 1.0);
        buf.push(200, 2.0);
        buf.push(300, 3.0);

        assert_eq!(buf.len(), 3);
        let samples = buf.samples();
        assert_eq!(samples.len(), 3);
        assert_eq!(samples[0], (100, 1.0));
        assert_eq!(samples[2], (300, 3.0));
    }

    #[test]
    fn buffer_circular_overwrite() {
        let mut buf = TimeSeriesBuffer::new(3);
        buf.push(1, 10.0);
        buf.push(2, 20.0);
        buf.push(3, 30.0);
        buf.push(4, 40.0); // Overwrites slot 0.

        assert_eq!(buf.len(), 3);
        let samples = buf.samples();
        assert_eq!(samples[0], (2, 20.0));
        assert_eq!(samples[2], (4, 40.0));
    }

    #[test]
    fn buffer_recent() {
        let mut buf = TimeSeriesBuffer::new(10);
        for i in 1..=7 {
            buf.push(i, i as f64);
        }

        let recent = buf.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0], (5, 5.0));
        assert_eq!(recent[2], (7, 7.0));
    }

    #[test]
    fn buffer_mean_and_stddev() {
        let mut buf = TimeSeriesBuffer::new(10);
        buf.push(1, 10.0);
        buf.push(2, 20.0);
        buf.push(3, 30.0);

        assert!((buf.mean() - 20.0).abs() < 0.001);
        assert!(buf.stddev() > 0.0);
    }

    #[test]
    fn buffer_empty_stats() {
        let buf = TimeSeriesBuffer::new(10);
        assert!((buf.mean() - 0.0).abs() < 0.001);
        assert!((buf.stddev() - 0.0).abs() < 0.001);
    }

    #[test]
    fn buffer_min_max() {
        let mut buf = TimeSeriesBuffer::new(10);
        buf.push(1, 5.0);
        buf.push(2, 15.0);
        buf.push(3, 10.0);

        assert!((buf.min_val() - 5.0).abs() < 0.001);
        assert!((buf.max_val() - 15.0).abs() < 0.001);
    }

    #[test]
    fn buffer_capacity_floor() {
        let buf = TimeSeriesBuffer::new(0);
        assert_eq!(buf.capacity(), 2); // Minimum 2.
    }

    // ── Linear regression ──────────────────────────────────────────────

    #[test]
    fn regression_perfect_line() {
        // y = 2x + 10
        let samples: Vec<(u64, f64)> = (0..10).map(|x| (x, 10.0 + 2.0 * x as f64)).collect();
        let result = linear_regression(&samples).unwrap();

        assert!((result.slope - 2.0).abs() < 0.001);
        assert!((result.intercept - 10.0).abs() < 0.001);
        assert!(result.r_squared > 0.999);
    }

    #[test]
    fn regression_flat_line() {
        let samples: Vec<(u64, f64)> = (0..10).map(|x| (x, 42.0)).collect();
        let result = linear_regression(&samples).unwrap();

        assert!(result.slope.abs() < 0.001);
        assert!((result.intercept - 42.0).abs() < 0.001);
    }

    #[test]
    fn regression_single_sample_returns_none() {
        let samples = vec![(1u64, 10.0)];
        assert!(linear_regression(&samples).is_none());
    }

    #[test]
    fn regression_prediction() {
        let samples: Vec<(u64, f64)> = (0..10).map(|x| (x, x as f64 * 5.0)).collect();
        let result = linear_regression(&samples).unwrap();

        // Predict at x=20: should be ~100.
        let predicted = result.predict_at(20, 0);
        assert!((predicted - 100.0).abs() < 1.0);
    }

    #[test]
    fn regression_handles_non_monotonic_timestamps() {
        // Regression: a non-monotonic clock (e.g. NTP step / VM resync) can put
        // a sample with a SMALLER timestamp later in insertion order, so
        // samples[0] is no longer the minimum. The old code anchored on
        // samples[0].0 and did an unchecked `t - base_t`, underflowing u64 for
        // the out-of-order sample — wrapping to ~1.8e19 under overflow-checks=off
        // (poisoning slope/intercept/r²) and panicking under overflow-checks=on.
        //
        // These five points are a perfect line y = 2*(t - 50), but the true
        // minimum timestamp (50) is placed LAST in the slice, exactly as a
        // backward clock step would arrange the ring buffer.
        let samples: Vec<(u64, f64)> = vec![
            (60, 20.0),
            (70, 40.0),
            (80, 60.0),
            (90, 80.0),
            (50, 0.0), // earliest time, but inserted last
        ];

        let result = linear_regression(&samples).unwrap();

        // With the fix (base_t = min timestamp, saturating_sub) this recovers
        // the true fit. The buggy version produced a wrapped huge x that drove
        // the slope to ~0 and r² to garbage (or panicked in debug).
        assert!(result.slope.is_finite() && result.intercept.is_finite());
        assert!(
            (result.slope - 2.0).abs() < 0.001,
            "slope should be ~2.0, got {}",
            result.slope
        );
        assert!(
            result.r_squared > 0.99,
            "r² should be ~1.0 for a perfect line, got {}",
            result.r_squared
        );
    }

    #[test]
    fn trend_result_rising_falling() {
        let rising = TrendResult {
            slope: 1.0,
            intercept: 0.0,
            r_squared: 0.95,
            n: 20,
        };
        assert!(rising.is_rising(0.5));
        assert!(!rising.is_falling(0.5));

        let falling = TrendResult {
            slope: -1.0,
            intercept: 100.0,
            r_squared: 0.8,
            n: 20,
        };
        assert!(falling.is_falling(0.5));
        assert!(!falling.is_rising(0.5));
    }

    // ── Seasonal model ─────────────────────────────────────────────────

    #[test]
    fn seasonal_record_and_predict() {
        let mut model = SeasonalModel::new(0.5);

        // Monday at 14:00 = high traffic.
        for _ in 0..10 {
            model.record(0, 14, 1000.0);
        }
        // Monday at 03:00 = low traffic.
        for _ in 0..10 {
            model.record(0, 3, 100.0);
        }

        let peak = model.predict(0, 14);
        let trough = model.predict(0, 3);
        assert!(peak > trough * 5.0, "peak={peak} trough={trough}");
    }

    #[test]
    fn seasonal_is_warm() {
        let mut model = SeasonalModel::new(0.3);
        assert!(!model.is_warm(0, 10, 5));

        for _ in 0..5 {
            model.record(0, 10, 500.0);
        }
        assert!(model.is_warm(0, 10, 5));
    }

    #[test]
    fn seasonal_peak_hour() {
        let mut model = SeasonalModel::new(0.5);
        model.record(2, 9, 200.0); // Wednesday 9am.
        model.record(2, 14, 800.0); // Wednesday 2pm ← peak.
        model.record(2, 22, 100.0); // Wednesday 10pm.

        let (hour, _) = model.peak_hour(2);
        assert_eq!(hour, 14);
    }

    #[test]
    fn seasonal_weekly_profile_size() {
        let model = SeasonalModel::new(0.3);
        assert_eq!(model.weekly_profile().len(), 168);
    }

    // ── Anomaly detector ───────────────────────────────────────────────

    #[test]
    fn anomaly_detects_spike() {
        let mut detector = AnomalyDetector::new(50, 3.0);

        // Feed a stable baseline.
        for i in 0..50 {
            let result = detector.check(i, 100.0);
            assert!(!result.is_anomaly);
        }

        // Spike!
        let spike = detector.check(51, 500.0);
        assert!(spike.is_anomaly);
        assert!(spike.z_score > 3.0);
    }

    #[test]
    fn anomaly_needs_warmup() {
        let mut detector = AnomalyDetector::new(50, 3.0);

        // With fewer than 10 samples, nothing is an anomaly.
        for i in 0..5 {
            let result = detector.check(i, 100.0 * (i + 1) as f64);
            assert!(!result.is_anomaly);
        }
    }

    #[test]
    fn anomaly_threshold_floor() {
        let detector = AnomalyDetector::new(10, 0.1);
        assert!((detector.threshold() - 1.0).abs() < 0.001); // Floor at 1.0.
    }

    // ── Target tracker ─────────────────────────────────────────────────

    #[test]
    fn target_in_band() {
        let tracker = TargetTracker::new(0.7, 0.1, 1, 20);

        // 0.7 ± 10% = [0.63, 0.77]. Current 0.7 → in band.
        assert_eq!(tracker.evaluate(0.7, 5), TargetAction::InBand);
        assert_eq!(tracker.evaluate(0.65, 5), TargetAction::InBand);
        assert_eq!(tracker.evaluate(0.75, 5), TargetAction::InBand);
    }

    #[test]
    fn target_scale_up() {
        let tracker = TargetTracker::new(0.5, 0.1, 1, 20);

        // Current 0.9 on 5 nodes → need ceil(5 * 0.9/0.5) = 9 nodes.
        match tracker.evaluate(0.9, 5) {
            TargetAction::ScaleTo(n) => assert_eq!(n, 9),
            other => panic!("expected ScaleTo(9), got {other:?}"),
        }
    }

    #[test]
    fn target_scale_down() {
        let tracker = TargetTracker::new(0.7, 0.1, 1, 20);

        // Current 0.3 on 10 nodes → need ceil(10 * 0.3/0.7) = 5 nodes.
        match tracker.evaluate(0.3, 10) {
            TargetAction::ScaleTo(n) => assert_eq!(n, 5),
            other => panic!("expected ScaleTo(5), got {other:?}"),
        }
    }

    #[test]
    fn target_respects_min_max() {
        let tracker = TargetTracker::new(0.5, 0.1, 3, 8);

        // Very low load → wants 1 node but min=3.
        match tracker.evaluate(0.05, 10) {
            TargetAction::ScaleTo(n) => assert_eq!(n, 3),
            other => panic!("expected ScaleTo(3), got {other:?}"),
        }

        // Very high load → wants 100 nodes but max=8.
        match tracker.evaluate(5.0, 10) {
            TargetAction::ScaleTo(n) => assert_eq!(n, 8),
            other => panic!("expected ScaleTo(8), got {other:?}"),
        }
    }

    #[test]
    fn target_zero_nodes() {
        let tracker = TargetTracker::new(0.5, 0.1, 2, 20);
        match tracker.evaluate(0.5, 0) {
            TargetAction::ScaleTo(n) => assert_eq!(n, 2), // min_nodes
            other => panic!("expected ScaleTo(2), got {other:?}"),
        }
    }

    // ── Scaling predictor (combined) ───────────────────────────────────

    #[test]
    fn predictor_anomaly_overrides_trend() {
        let mut pred = ScalingPredictor::new(100, 50, 1000.0, 0.7, 1, 20);

        // Build a stable baseline.
        for i in 0..50 {
            pred.observe(i, 500.0, 0, 10, 5);
        }

        // Anomaly spike.
        let result = pred.observe(51, 5000.0, 0, 10, 5);
        assert_eq!(result.primary_signal, PredictionSignal::Anomaly);
        assert!(result.recommended_nodes > 5);
    }

    #[test]
    fn predictor_rising_trend() {
        let mut pred = ScalingPredictor::new(100, 50, 100.0, 0.7, 1, 50);

        // Steadily rising load: 100, 200, 300, ...
        for i in 0..30 {
            let value = 100.0 + i as f64 * 100.0;
            pred.observe(i * 60, value, 0, 10, 5);
        }

        let result = pred.observe(30 * 60, 3100.0, 0, 10, 5);
        // Should detect rising trend and predict ahead.
        assert!(
            result.primary_signal == PredictionSignal::Trend
                || result.primary_signal == PredictionSignal::Anomaly
                || result.primary_signal == PredictionSignal::TargetTracking,
        );
        assert!(result.recommended_nodes > 5);
    }

    #[test]
    fn predictor_target_tracking_fallback() {
        let mut pred = ScalingPredictor::new(100, 50, 1000.0, 0.5, 1, 20);

        // Stable load slightly above target → target tracking.
        for i in 0..5 {
            pred.observe(i, 600.0, 0, 10, 5);
        }
        let result = pred.observe(6, 600.0, 0, 10, 5);
        // Without enough data for trend/seasonal, falls back to target tracking.
        assert!(
            result.primary_signal == PredictionSignal::TargetTracking
                || result.primary_signal == PredictionSignal::Insufficient,
        );
    }

    // ── Cooldown manager ───────────────────────────────────────────────

    #[test]
    fn cooldown_blocks_during_window() {
        let mut mgr = CooldownManager::new();
        mgr.record("scale_up", Duration::from_secs(300));

        assert!(mgr.is_on_cooldown("scale_up"));
        assert!(!mgr.is_on_cooldown("scale_down"));
        assert!(mgr.remaining("scale_up").as_secs() > 0);
    }

    #[test]
    fn cooldown_expires() {
        let mut mgr = CooldownManager::new();
        mgr.record("test", Duration::from_millis(1));

        std::thread::sleep(Duration::from_millis(5));
        assert!(!mgr.is_on_cooldown("test"));
    }

    #[test]
    fn cooldown_cleanup() {
        let mut mgr = CooldownManager::new();
        mgr.record("old", Duration::from_millis(1));
        mgr.record("new", Duration::from_secs(300));

        std::thread::sleep(Duration::from_millis(5));
        mgr.cleanup();

        assert!(!mgr.is_on_cooldown("old"));
        assert!(mgr.is_on_cooldown("new"));
    }

    #[test]
    fn cooldown_remaining_zero_when_not_set() {
        let mgr = CooldownManager::new();
        assert_eq!(mgr.remaining("anything"), Duration::ZERO);
    }

    // ── Global toggle ──────────────────────────────────────────────────

    #[test]
    fn predictive_global_toggle() {
        set_predictive_enabled(true);
        assert!(is_predictive_enabled());
        // Leave enabled for parallel tests.
    }
}
