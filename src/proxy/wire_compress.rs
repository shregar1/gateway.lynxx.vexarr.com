//! Wire-speed compression — adaptive compression that matches line rate.
//!
//! Traditional proxies compress at a fixed level (e.g., gzip-6), which often
//! can't keep up with 10+ Gbps line rates. This module dynamically adjusts
//! compression level based on CPU headroom, throughput targets, and content
//! characteristics.
//!
//! # Strategies
//!
//! - **Adaptive level**: drop compression level when CPU is saturated
//! - **Content-aware**: skip incompressible content (images, video, already-compressed)
//! - **Algorithm selection**: pick the fastest algorithm that meets the ratio target
//! - **Dictionary preloading**: use shared dictionaries for known content types
//! - **Streaming**: compress in chunks to avoid head-of-line blocking
//!
//! # Supported algorithms
//!
//! - gzip/deflate (RFC 1952/1951) — universal compatibility
//! - Brotli (RFC 7932) — best ratio for web content
//! - zstd (RFC 8878) — best speed/ratio trade-off
//! - lz4 — fastest, for internal/backend traffic

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// Hasher for the Vary header tracker. The keys are server-side paths
/// (the URLs we have served and marked with `Vary: Accept-Encoding`) —
/// not attacker-controlled — so ahash is safe and a clear win on the
/// 32-128 byte path strings that dominate this cache.
type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Global toggles
// ═══════════════════════════════════════════════════════════════════════════

static WIRE_COMPRESS_ENABLED: AtomicBool = AtomicBool::new(false);
static COMPRESSION_STRATEGY: AtomicU8 = AtomicU8::new(0); // 0 = Adaptive

pub fn is_wire_compress_enabled() -> bool {
    WIRE_COMPRESS_ENABLED.load(Ordering::Relaxed)
}

pub fn set_wire_compress_enabled(v: bool) {
    WIRE_COMPRESS_ENABLED.store(v, Ordering::Relaxed);
}

pub fn get_compression_strategy() -> CompressionStrategy {
    CompressionStrategy::from_u8(COMPRESSION_STRATEGY.load(Ordering::Relaxed))
}

pub fn set_compression_strategy(strategy: CompressionStrategy) {
    COMPRESSION_STRATEGY.store(strategy as u8, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Compression algorithms
// ═══════════════════════════════════════════════════════════════════════════

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Algorithm {
    /// gzip — universal browser support.
    Gzip = 0,
    /// Brotli — superior ratio for text/web content.
    Brotli = 1,
    /// Zstandard — best speed/ratio trade-off.
    Zstd = 2,
    /// LZ4 — fastest, for internal traffic.
    Lz4 = 3,
    /// Deflate (raw).
    Deflate = 4,
    /// No compression (passthrough).
    Identity = 5,
}

impl Algorithm {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Brotli,
            2 => Self::Zstd,
            3 => Self::Lz4,
            4 => Self::Deflate,
            5 => Self::Identity,
            _ => Self::Gzip,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
            Self::Deflate => "deflate",
            Self::Identity => "identity",
        }
    }

    /// Content-Encoding header value.
    pub fn encoding_name(&self) -> &'static str {
        self.label()
    }

    /// Maximum compression level for this algorithm.
    pub fn max_level(&self) -> u32 {
        match self {
            Self::Gzip | Self::Deflate => 9,
            Self::Brotli => 11,
            Self::Zstd => 22,
            Self::Lz4 => 16,
            Self::Identity => 0,
        }
    }

    /// Default "balanced" compression level.
    pub fn default_level(&self) -> u32 {
        match self {
            Self::Gzip | Self::Deflate => 6,
            Self::Brotli => 4,
            Self::Zstd => 3,
            Self::Lz4 => 1,
            Self::Identity => 0,
        }
    }

    /// Fastest level that still provides meaningful compression.
    pub fn speed_level(&self) -> u32 {
        match self {
            Self::Gzip | Self::Deflate => 1,
            Self::Brotli => 1,
            Self::Zstd => 1,
            Self::Lz4 => 1,
            Self::Identity => 0,
        }
    }

    /// Parse from Accept-Encoding header value.
    pub fn from_encoding(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "gzip" => Some(Self::Gzip),
            "br" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            "lz4" => Some(Self::Lz4),
            "deflate" => Some(Self::Deflate),
            "identity" => Some(Self::Identity),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Compression strategy
// ═══════════════════════════════════════════════════════════════════════════

/// Overall compression behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionStrategy {
    /// Dynamically adjust level based on CPU load.
    Adaptive = 0,
    /// Always use the maximum compression level.
    MaxCompression = 1,
    /// Always use the fastest level.
    MaxSpeed = 2,
    /// Fixed level specified by configuration.
    Fixed = 3,
    /// Disabled — no compression.
    Disabled = 4,
}

impl CompressionStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::MaxCompression,
            2 => Self::MaxSpeed,
            3 => Self::Fixed,
            4 => Self::Disabled,
            _ => Self::Adaptive,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::MaxCompression => "max_compression",
            Self::MaxSpeed => "max_speed",
            Self::Fixed => "fixed",
            Self::Disabled => "disabled",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Content type classification
// ═══════════════════════════════════════════════════════════════════════════

/// Content compressibility classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressibility {
    /// Highly compressible (HTML, JSON, CSS, JS, XML).
    High,
    /// Moderately compressible (some binary formats).
    Medium,
    /// Incompressible (images, video, already-compressed).
    None,
    /// Unknown — try compression and measure.
    Unknown,
}

impl Compressibility {
    /// Classify a MIME type.
    pub fn from_mime(mime: &str) -> Self {
        let lower = mime.to_lowercase();

        // Text types are highly compressible.
        if lower.starts_with("text/") {
            return Self::High;
        }

        // Common highly-compressible application types.
        if lower.contains("json")
            || lower.contains("xml")
            || lower.contains("javascript")
            || lower.contains("ecmascript")
            || lower.contains("svg")
            || lower.contains("yaml")
            || lower.contains("toml")
            || lower.contains("html")
            || lower.contains("css")
            || lower.contains("wasm")
        {
            return Self::High;
        }

        // Already compressed or incompressible.
        if lower.starts_with("image/")
            || lower.starts_with("video/")
            || lower.starts_with("audio/")
            || lower.contains("zip")
            || lower.contains("gzip")
            || lower.contains("brotli")
            || lower.contains("zstd")
            || lower.contains("lz4")
            || lower.contains("compress")
            || lower.contains("encrypted")
        {
            return Self::None;
        }

        // Fonts are moderately compressible.
        if lower.starts_with("font/") || lower.contains("woff") {
            return Self::Medium;
        }

        // Application/octet-stream or other binary.
        if lower.starts_with("application/octet") {
            return Self::Medium;
        }

        Self::Unknown
    }

    /// Whether compression should be attempted.
    pub fn should_compress(&self) -> bool {
        matches!(self, Self::High | Self::Medium | Self::Unknown)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Adaptive level controller
// ═══════════════════════════════════════════════════════════════════════════

/// Dynamically adjusts compression level based on CPU load and throughput.
pub struct AdaptiveLevelController {
    /// Current compression level.
    current_level: u32,
    /// Algorithm being used.
    algorithm: Algorithm,
    /// Target CPU usage for compression (0.0 – 1.0).
    target_cpu_fraction: f64,
    /// Recent CPU observations.
    cpu_samples: Vec<f64>,
    /// Maximum samples to keep.
    max_samples: usize,
    /// Last time the level was adjusted.
    last_adjustment: Instant,
    /// Minimum time between adjustments.
    adjustment_interval: Duration,
    /// Minimum level (never go below this).
    min_level: u32,
    /// Maximum level (never go above this).
    max_level: u32,
}

impl AdaptiveLevelController {
    pub fn new(algorithm: Algorithm) -> Self {
        let max = algorithm.max_level();
        Self {
            current_level: algorithm.default_level(),
            algorithm,
            target_cpu_fraction: 0.7, // Use up to 70% of CPU for compression.
            cpu_samples: Vec::with_capacity(20),
            max_samples: 20,
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_secs(1),
            min_level: algorithm.speed_level(),
            max_level: max,
        }
    }

    pub fn with_target_cpu(mut self, fraction: f64) -> Self {
        self.target_cpu_fraction = fraction.clamp(0.1, 0.95);
        self
    }

    pub fn with_bounds(mut self, min: u32, max: u32) -> Self {
        self.min_level = min.min(self.algorithm.max_level());
        self.max_level = max.min(self.algorithm.max_level()).max(self.min_level);
        self.current_level = self.current_level.clamp(self.min_level, self.max_level);
        self
    }

    /// Report a CPU usage sample (0.0 – 1.0).
    pub fn record_cpu(&mut self, cpu_fraction: f64) {
        if self.cpu_samples.len() >= self.max_samples {
            self.cpu_samples.remove(0);
        }
        self.cpu_samples.push(cpu_fraction.clamp(0.0, 1.0));
    }

    /// Get the current compression level.
    pub fn level(&self) -> u32 {
        self.current_level
    }

    /// Possibly adjust the compression level. Call periodically.
    pub fn maybe_adjust(&mut self) -> bool {
        if self.last_adjustment.elapsed() < self.adjustment_interval {
            return false;
        }
        if self.cpu_samples.len() < 3 {
            return false;
        }

        let avg_cpu = self.avg_cpu();
        let old_level = self.current_level;

        if avg_cpu > self.target_cpu_fraction + 0.1 {
            // CPU is too high — reduce compression level.
            if self.current_level > self.min_level {
                self.current_level -= 1;
            }
        } else if avg_cpu < self.target_cpu_fraction - 0.15 {
            // CPU has headroom — increase compression level.
            if self.current_level < self.max_level {
                self.current_level += 1;
            }
        }

        self.last_adjustment = Instant::now();
        self.current_level != old_level
    }

    /// Average CPU across recent samples.
    pub fn avg_cpu(&self) -> f64 {
        if self.cpu_samples.is_empty() {
            return 0.0;
        }
        self.cpu_samples.iter().sum::<f64>() / self.cpu_samples.len() as f64
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Algorithm selector
// ═══════════════════════════════════════════════════════════════════════════

/// Client Accept-Encoding preference with quality values.
#[derive(Debug, Clone)]
pub struct EncodingPreference {
    pub algorithm: Algorithm,
    pub quality: f32, // 0.0 – 1.0
}

impl EncodingPreference {
    pub fn new(algorithm: Algorithm, quality: f32) -> Self {
        Self {
            algorithm,
            quality: quality.clamp(0.0, 1.0),
        }
    }
}

/// Parse an Accept-Encoding header into preferences.
pub fn parse_accept_encoding(header: &str) -> Vec<EncodingPreference> {
    let mut prefs = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        let (name, quality) = if let Some(idx) = part.find(";q=") {
            let q = part[idx + 3..].trim().parse::<f32>().unwrap_or(1.0);
            (&part[..idx], q)
        } else {
            (part, 1.0_f32)
        };
        if let Some(algo) = Algorithm::from_encoding(name) {
            prefs.push(EncodingPreference::new(algo, quality));
        }
    }
    // Sort by quality descending.
    prefs.sort_by(|a, b| b.quality.partial_cmp(&a.quality).unwrap_or(std::cmp::Ordering::Equal));
    prefs
}

/// Select the best algorithm from client preferences and server capabilities.
pub fn select_algorithm(
    client_prefs: &[EncodingPreference],
    server_algorithms: &[Algorithm],
) -> Algorithm {
    // Priority: pick the highest-quality client preference that the server supports.
    for pref in client_prefs {
        if pref.quality > 0.0 && server_algorithms.contains(&pref.algorithm) {
            return pref.algorithm;
        }
    }
    // Fallback: identity (no compression).
    Algorithm::Identity
}

// ═══════════════════════════════════════════════════════════════════════════
// Compression dictionary
// ═══════════════════════════════════════════════════════════════════════════

/// A preloaded compression dictionary for improved ratio on known content types.
#[derive(Debug, Clone)]
pub struct CompressionDictionary {
    /// Dictionary ID.
    pub id: u32,
    /// Human-readable name.
    pub name: String,
    /// MIME types this dictionary is good for.
    pub mime_types: Vec<String>,
    /// Dictionary data.
    pub data: Vec<u8>,
    /// Algorithm this dictionary is for.
    pub algorithm: Algorithm,
}

impl CompressionDictionary {
    pub fn new(id: u32, name: &str, algorithm: Algorithm, data: Vec<u8>) -> Self {
        Self {
            id,
            name: name.to_string(),
            mime_types: Vec::new(),
            data,
            algorithm,
        }
    }

    pub fn with_mime(mut self, mime: &str) -> Self {
        self.mime_types.push(mime.to_string());
        self
    }

    /// Dictionary size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Check if this dictionary is applicable for a MIME type.
    pub fn matches_mime(&self, mime: &str) -> bool {
        let lower = mime.to_lowercase();
        self.mime_types.iter().any(|m| lower.contains(m))
    }
}

/// A registry of preloaded dictionaries.
pub struct DictionaryRegistry {
    dictionaries: Vec<CompressionDictionary>,
    max_size: usize,
}

impl DictionaryRegistry {
    pub fn new(max_size: usize) -> Self {
        Self {
            dictionaries: Vec::new(),
            max_size: max_size.max(1),
        }
    }

    /// Register a dictionary.
    pub fn register(&mut self, dict: CompressionDictionary) -> bool {
        if self.dictionaries.len() >= self.max_size {
            return false;
        }
        // Deduplicate by ID.
        self.dictionaries.retain(|d| d.id != dict.id);
        self.dictionaries.push(dict);
        true
    }

    /// Find the best dictionary for a MIME type and algorithm.
    pub fn find(&self, mime: &str, algorithm: Algorithm) -> Option<&CompressionDictionary> {
        self.dictionaries
            .iter()
            .find(|d| d.algorithm == algorithm && d.matches_mime(mime))
    }

    pub fn len(&self) -> usize {
        self.dictionaries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dictionaries.is_empty()
    }

    /// Total memory used by all dictionaries.
    pub fn total_memory(&self) -> usize {
        self.dictionaries.iter().map(|d| d.size()).sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Compression result
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a compression operation.
#[derive(Debug, Clone)]
pub struct CompressionResult {
    /// Algorithm used.
    pub algorithm: Algorithm,
    /// Compression level used.
    pub level: u32,
    /// Original size in bytes.
    pub original_size: u64,
    /// Compressed size in bytes.
    pub compressed_size: u64,
    /// Time taken to compress.
    pub duration: Duration,
    /// Whether a dictionary was used.
    pub used_dictionary: bool,
}

impl CompressionResult {
    pub fn new(
        algorithm: Algorithm,
        level: u32,
        original_size: u64,
        compressed_size: u64,
        duration: Duration,
    ) -> Self {
        Self {
            algorithm,
            level,
            original_size,
            compressed_size,
            duration,
            used_dictionary: false,
        }
    }

    /// Compression ratio (compressed / original). Lower is better.
    pub fn ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.original_size as f64
    }

    /// Space savings as a percentage.
    pub fn savings_pct(&self) -> f64 {
        (1.0 - self.ratio()) * 100.0
    }

    /// Compression throughput in bytes/second (based on original size).
    pub fn throughput(&self) -> f64 {
        let secs = self.duration.as_secs_f64();
        if secs < 0.000001 {
            return 0.0;
        }
        self.original_size as f64 / secs
    }

    /// Whether compression was beneficial (ratio < 0.95).
    pub fn was_beneficial(&self) -> bool {
        self.ratio() < 0.95
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Minimum size filter
// ═══════════════════════════════════════════════════════════════════════════

/// Decides whether a response is worth compressing based on size.
pub struct MinSizeFilter {
    /// Minimum body size to consider compression.
    min_size: u64,
    /// Content types that should always be compressed regardless of size.
    always_compress: Vec<String>,
}

impl MinSizeFilter {
    pub fn new(min_size: u64) -> Self {
        Self {
            min_size: min_size.max(32), // At least 32 bytes.
            always_compress: Vec::new(),
        }
    }

    pub fn with_always_compress(mut self, mime: &str) -> Self {
        self.always_compress.push(mime.to_lowercase());
        self
    }

    /// Should this response be compressed?
    pub fn should_compress(&self, size: u64, mime: &str) -> bool {
        let lower = mime.to_lowercase();
        if self.always_compress.iter().any(|m| lower.contains(m)) {
            return true;
        }
        size >= self.min_size
    }

    pub fn min_size(&self) -> u64 {
        self.min_size
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Vary header tracker
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks Vary: Accept-Encoding for proper caching.
pub struct VaryTracker {
    /// Paths that have been marked with Vary: Accept-Encoding.
    paths: std::collections::HashSet<String, FastHasher>,
    /// Maximum tracked paths.
    max_entries: usize,
}

impl VaryTracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            paths: std::collections::HashSet::with_hasher(FastHasher::default()),
            max_entries: max_entries.max(100),
        }
    }

    /// Mark a path as varying on Accept-Encoding.
    pub fn mark(&mut self, path: &str) {
        if self.paths.len() < self.max_entries {
            self.paths.insert(path.to_string());
        }
    }

    /// Check if a path varies on encoding.
    pub fn varies(&self, path: &str) -> bool {
        self.paths.contains(path)
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.paths.clear();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct WireCompressMetrics {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub compressions: AtomicU64,
    pub skipped_incompressible: AtomicU64,
    pub skipped_too_small: AtomicU64,
    pub level_adjustments: AtomicU64,
    pub dictionary_hits: AtomicU64,
}

static WIRE_COMPRESS_METRICS: WireCompressMetrics = WireCompressMetrics {
    bytes_in: AtomicU64::new(0),
    bytes_out: AtomicU64::new(0),
    compressions: AtomicU64::new(0),
    skipped_incompressible: AtomicU64::new(0),
    skipped_too_small: AtomicU64::new(0),
    level_adjustments: AtomicU64::new(0),
    dictionary_hits: AtomicU64::new(0),
};

pub fn wire_compress_metrics() -> &'static WireCompressMetrics {
    &WIRE_COMPRESS_METRICS
}

impl WireCompressMetrics {
    pub fn record_compression(&self, original: u64, compressed: u64) {
        self.bytes_in.fetch_add(original, Ordering::Relaxed);
        self.bytes_out.fetch_add(compressed, Ordering::Relaxed);
        self.compressions.fetch_add(1, Ordering::Relaxed);
    }

    /// Overall compression ratio.
    pub fn overall_ratio(&self) -> f64 {
        let in_bytes = self.bytes_in.load(Ordering::Relaxed);
        let out_bytes = self.bytes_out.load(Ordering::Relaxed);
        if in_bytes == 0 {
            return 1.0;
        }
        out_bytes as f64 / in_bytes as f64
    }

    /// Overall savings percentage.
    pub fn overall_savings_pct(&self) -> f64 {
        (1.0 - self.overall_ratio()) * 100.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Algorithm ─────────────────────────────────────────────────────

    #[test]
    fn algorithm_roundtrip() {
        for v in 0..=5 {
            let a = Algorithm::from_u8(v);
            assert!(!a.label().is_empty());
        }
        assert_eq!(Algorithm::from_u8(99), Algorithm::Gzip);
    }

    #[test]
    fn algorithm_levels() {
        let gz = Algorithm::Gzip;
        assert!(gz.default_level() <= gz.max_level());
        assert!(gz.speed_level() <= gz.default_level());

        let br = Algorithm::Brotli;
        assert_eq!(br.max_level(), 11);
        assert!(br.default_level() < br.max_level());

        let zstd = Algorithm::Zstd;
        assert_eq!(zstd.max_level(), 22);

        assert_eq!(Algorithm::Identity.max_level(), 0);
    }

    #[test]
    fn algorithm_from_encoding() {
        assert_eq!(Algorithm::from_encoding("gzip"), Some(Algorithm::Gzip));
        assert_eq!(Algorithm::from_encoding("br"), Some(Algorithm::Brotli));
        assert_eq!(Algorithm::from_encoding("zstd"), Some(Algorithm::Zstd));
        assert_eq!(Algorithm::from_encoding("lz4"), Some(Algorithm::Lz4));
        assert_eq!(Algorithm::from_encoding("GZIP"), Some(Algorithm::Gzip)); // Case insensitive.
        assert_eq!(Algorithm::from_encoding("unknown"), None);
    }

    // ── Strategy ──────────────────────────────────────────────────────

    #[test]
    fn strategy_roundtrip() {
        for v in 0..=4 {
            let s = CompressionStrategy::from_u8(v);
            assert!(!s.label().is_empty());
        }
        assert_eq!(CompressionStrategy::from_u8(99), CompressionStrategy::Adaptive);
    }

    // ── Content classification ────────────────────────────────────────

    #[test]
    fn compressibility_text() {
        assert_eq!(Compressibility::from_mime("text/html"), Compressibility::High);
        assert_eq!(Compressibility::from_mime("text/plain"), Compressibility::High);
        assert_eq!(Compressibility::from_mime("text/css"), Compressibility::High);
    }

    #[test]
    fn compressibility_application() {
        assert_eq!(Compressibility::from_mime("application/json"), Compressibility::High);
        assert_eq!(Compressibility::from_mime("application/javascript"), Compressibility::High);
        assert_eq!(Compressibility::from_mime("application/xml"), Compressibility::High);
    }

    #[test]
    fn compressibility_media() {
        assert_eq!(Compressibility::from_mime("image/png"), Compressibility::None);
        assert_eq!(Compressibility::from_mime("video/mp4"), Compressibility::None);
        assert_eq!(Compressibility::from_mime("audio/mpeg"), Compressibility::None);
    }

    #[test]
    fn compressibility_already_compressed() {
        assert_eq!(Compressibility::from_mime("application/gzip"), Compressibility::None);
        assert_eq!(Compressibility::from_mime("application/zip"), Compressibility::None);
    }

    #[test]
    fn compressibility_should_compress() {
        assert!(Compressibility::High.should_compress());
        assert!(Compressibility::Medium.should_compress());
        assert!(Compressibility::Unknown.should_compress());
        assert!(!Compressibility::None.should_compress());
    }

    // ── Accept-Encoding parsing ───────────────────────────────────────

    #[test]
    fn parse_accept_encoding_simple() {
        let prefs = parse_accept_encoding("gzip, br");
        assert_eq!(prefs.len(), 2);
        assert_eq!(prefs[0].algorithm, Algorithm::Gzip); // Both q=1.0, stable order.
    }

    #[test]
    fn parse_accept_encoding_with_quality() {
        let prefs = parse_accept_encoding("gzip;q=0.5, br;q=1.0, zstd;q=0.8");
        assert_eq!(prefs.len(), 3);
        assert_eq!(prefs[0].algorithm, Algorithm::Brotli); // Highest quality.
        assert_eq!(prefs[1].algorithm, Algorithm::Zstd);
        assert_eq!(prefs[2].algorithm, Algorithm::Gzip);
    }

    #[test]
    fn parse_accept_encoding_unknown() {
        let prefs = parse_accept_encoding("unknown, gzip");
        assert_eq!(prefs.len(), 1);
        assert_eq!(prefs[0].algorithm, Algorithm::Gzip);
    }

    // ── Algorithm selection ───────────────────────────────────────────

    #[test]
    fn select_best_supported() {
        let prefs = parse_accept_encoding("br, gzip");
        let server = vec![Algorithm::Gzip, Algorithm::Brotli];
        assert_eq!(select_algorithm(&prefs, &server), Algorithm::Brotli);
    }

    #[test]
    fn select_fallback_to_identity() {
        let prefs = parse_accept_encoding("br");
        let server = vec![Algorithm::Gzip]; // Server doesn't support Brotli.
        assert_eq!(select_algorithm(&prefs, &server), Algorithm::Identity);
    }

    #[test]
    fn select_respects_quality_zero() {
        let prefs = parse_accept_encoding("gzip;q=0, br;q=1.0");
        let server = vec![Algorithm::Gzip, Algorithm::Brotli];
        assert_eq!(select_algorithm(&prefs, &server), Algorithm::Brotli);
    }

    // ── Adaptive level controller ─────────────────────────────────────

    #[test]
    fn adaptive_starts_at_default() {
        let ctrl = AdaptiveLevelController::new(Algorithm::Gzip);
        assert_eq!(ctrl.level(), Algorithm::Gzip.default_level());
    }

    #[test]
    fn adaptive_reduces_on_high_cpu() {
        let mut ctrl = AdaptiveLevelController::new(Algorithm::Gzip)
            .with_target_cpu(0.7);
        // Overwrite last_adjustment so adjustment is allowed.
        ctrl.last_adjustment = Instant::now() - Duration::from_secs(5);

        // Feed high CPU samples.
        for _ in 0..5 {
            ctrl.record_cpu(0.95);
        }

        let before = ctrl.level();
        ctrl.maybe_adjust();
        assert!(ctrl.level() < before || ctrl.level() == ctrl.min_level);
    }

    #[test]
    fn adaptive_increases_on_low_cpu() {
        let mut ctrl = AdaptiveLevelController::new(Algorithm::Gzip)
            .with_target_cpu(0.7)
            .with_bounds(1, 9);
        ctrl.current_level = 3; // Start low.
        ctrl.last_adjustment = Instant::now() - Duration::from_secs(5);

        // Feed low CPU samples.
        for _ in 0..5 {
            ctrl.record_cpu(0.2);
        }

        let before = ctrl.level();
        ctrl.maybe_adjust();
        assert!(ctrl.level() > before || ctrl.level() == ctrl.max_level);
    }

    #[test]
    fn adaptive_respects_bounds() {
        let ctrl = AdaptiveLevelController::new(Algorithm::Zstd)
            .with_bounds(3, 10);
        assert!(ctrl.level() >= 3);
        assert!(ctrl.level() <= 10);
    }

    #[test]
    fn adaptive_no_adjust_too_soon() {
        let mut ctrl = AdaptiveLevelController::new(Algorithm::Gzip);
        for _ in 0..5 {
            ctrl.record_cpu(0.95);
        }
        // last_adjustment is now(), so adjustment_interval hasn't passed.
        assert!(!ctrl.maybe_adjust());
    }

    // ── Dictionary registry ───────────────────────────────────────────

    #[test]
    fn dictionary_register_and_find() {
        let mut reg = DictionaryRegistry::new(10);
        let dict = CompressionDictionary::new(1, "html", Algorithm::Zstd, vec![1, 2, 3])
            .with_mime("text/html");
        assert!(reg.register(dict));
        assert_eq!(reg.len(), 1);

        let found = reg.find("text/html", Algorithm::Zstd);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, 1);
    }

    #[test]
    fn dictionary_wrong_algorithm() {
        let mut reg = DictionaryRegistry::new(10);
        let dict = CompressionDictionary::new(1, "html", Algorithm::Zstd, vec![1, 2, 3])
            .with_mime("text/html");
        reg.register(dict);

        // Wrong algorithm.
        assert!(reg.find("text/html", Algorithm::Brotli).is_none());
    }

    #[test]
    fn dictionary_capacity() {
        let mut reg = DictionaryRegistry::new(2);
        reg.register(CompressionDictionary::new(1, "d1", Algorithm::Gzip, vec![1]));
        reg.register(CompressionDictionary::new(2, "d2", Algorithm::Gzip, vec![2]));
        assert!(!reg.register(CompressionDictionary::new(3, "d3", Algorithm::Gzip, vec![3])));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn dictionary_total_memory() {
        let mut reg = DictionaryRegistry::new(10);
        reg.register(CompressionDictionary::new(1, "d1", Algorithm::Gzip, vec![0; 100]));
        reg.register(CompressionDictionary::new(2, "d2", Algorithm::Gzip, vec![0; 200]));
        assert_eq!(reg.total_memory(), 300);
    }

    // ── Compression result ────────────────────────────────────────────

    #[test]
    fn result_ratio() {
        let r = CompressionResult::new(
            Algorithm::Gzip, 6, 1000, 300, Duration::from_millis(1),
        );
        assert!((r.ratio() - 0.3).abs() < 0.001);
        assert!((r.savings_pct() - 70.0).abs() < 0.1);
        assert!(r.was_beneficial());
    }

    #[test]
    fn result_not_beneficial() {
        let r = CompressionResult::new(
            Algorithm::Gzip, 1, 100, 98, Duration::from_millis(1),
        );
        assert!(!r.was_beneficial()); // Only 2% savings.
    }

    #[test]
    fn result_zero_size() {
        let r = CompressionResult::new(
            Algorithm::Gzip, 6, 0, 0, Duration::from_millis(1),
        );
        assert_eq!(r.ratio(), 1.0);
        assert_eq!(r.savings_pct(), 0.0);
    }

    // ── Min size filter ───────────────────────────────────────────────

    #[test]
    fn min_size_filter() {
        let f = MinSizeFilter::new(1024);
        assert!(!f.should_compress(100, "text/html"));
        assert!(f.should_compress(2000, "text/html"));
    }

    #[test]
    fn min_size_always_compress() {
        let f = MinSizeFilter::new(1024)
            .with_always_compress("application/json");
        assert!(f.should_compress(10, "application/json")); // Small but always-compress.
    }

    // ── Vary tracker ──────────────────────────────────────────────────

    #[test]
    fn vary_tracker() {
        let mut vt = VaryTracker::new(100);
        vt.mark("/index.html");
        assert!(vt.varies("/index.html"));
        assert!(!vt.varies("/image.png"));
        assert_eq!(vt.len(), 1);
    }

    #[test]
    fn vary_tracker_clear() {
        let mut vt = VaryTracker::new(100);
        vt.mark("/a");
        vt.mark("/b");
        vt.clear();
        assert!(vt.is_empty());
    }

    // ── Global toggle ─────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_wire_compress_enabled(true);
        assert!(is_wire_compress_enabled());
    }

    // ── Metrics (delta-based) ─────────────────────────────────────────

    #[test]
    fn metrics_record() {
        let m = wire_compress_metrics();
        let before_in = m.bytes_in.load(Ordering::Relaxed);

        m.record_compression(1000, 300);

        let after_in = m.bytes_in.load(Ordering::Relaxed);
        assert!(after_in >= before_in + 1000);
    }
}
