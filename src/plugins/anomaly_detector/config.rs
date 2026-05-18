//! Configuration types for the `anomaly-detector` plugin.
//!
//! The shape mirrors the JSON config blob persisted in the plugins table.
//! All defaults are conservative: `log_only` mode, four-sigma thresholds,
//! 100-request warmup. An operator who enables the plugin with an empty
//! `{}` config still gets sensible behaviour — the plugin observes traffic,
//! emits metrics on outliers, but never short-circuits.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum KeyStrategy {
    #[default]
    Consumer,
    Ip,
    Global,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Mode {
    #[default]
    LogOnly,
    Challenge,
    Block,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignalCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_sigma")]
    pub sigma_threshold: f64,
    /// Only meaningful for window-based signals (request_rate, path_diversity,
    /// error_rate). Ignored for body_size.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

impl Default for SignalCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            sigma_threshold: default_sigma(),
            window_secs: default_window_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Signals {
    #[serde(default)]
    pub request_rate: SignalCfg,
    #[serde(default = "body_size_default")]
    pub body_size: SignalCfg,
    #[serde(default)]
    pub path_diversity: SignalCfg,
    #[serde(default)]
    pub error_rate: SignalCfg,
}

fn body_size_default() -> SignalCfg {
    SignalCfg {
        enabled: true,
        sigma_threshold: 5.0,
        window_secs: default_window_secs(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub key_strategy: KeyStrategy,
    #[serde(default = "default_warmup")]
    pub warmup_requests: u64,
    #[serde(default = "default_alpha")]
    pub ewma_alpha: f64,
    #[serde(default)]
    pub signals: Signals,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_retry_after")]
    pub challenge_retry_after: u64,
    #[serde(default)]
    pub exempt_consumers: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_strategy: KeyStrategy::default(),
            warmup_requests: default_warmup(),
            ewma_alpha: default_alpha(),
            signals: Signals::default(),
            mode: Mode::default(),
            challenge_retry_after: default_retry_after(),
            exempt_consumers: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_sigma() -> f64 {
    4.0
}

fn default_window_secs() -> u64 {
    60
}

fn default_warmup() -> u64 {
    100
}

fn default_alpha() -> f64 {
    0.05
}

fn default_retry_after() -> u64 {
    10
}

impl Config {
    /// Tag value used in metric labels. Cheap String allocation but happens
    /// only on anomaly events, not the hot path.
    pub fn key_strategy_tag(&self) -> &'static str {
        match self.key_strategy {
            KeyStrategy::Consumer => "consumer",
            KeyStrategy::Ip => "ip",
            KeyStrategy::Global => "global",
        }
    }

    pub fn mode_tag(&self) -> &'static str {
        match self.mode {
            Mode::LogOnly => "log_only",
            Mode::Challenge => "challenge",
            Mode::Block => "block",
        }
    }
}
