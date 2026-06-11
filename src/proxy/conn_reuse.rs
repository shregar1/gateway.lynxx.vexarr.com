//! HAProxy-style HTTP connection reuse policy for upstream connections.
//!
//! # Architecture
//!
//! ```text
//! Connection Reuse
//! ├── ReusePolicy enum     — Never / Safe / Aggressive / Always
//! ├── ReuseDecision         — Reuse / Close / CloseAndRetry
//! ├── ResponseValidator     — Checks if a response completed cleanly
//! ├── ConnectionHints       — Headers/flags set on outbound requests
//! └── ReuseMetrics          — Reused / new / forced-close counters
//! ```
//!
//! # Why
//!
//! HAProxy's `http-reuse` directive controls how backend connections are
//! shared between frontend sessions. The four modes trade safety for
//! efficiency:
//!
//! - **Never**: 1:1 client-to-backend. Safest, most expensive.
//! - **Safe** (default): reuse only after clean response completion.
//! - **Aggressive**: strip `Connection: close` from backends, force keepalive.
//! - **Always**: unconditional reuse, ignore Connection headers entirely.
//!
//! This module provides the policy engine that sits between the proxy
//! handler and hyper's connection pool, controlling header manipulation
//! and reuse decisions per-exchange.

use axum::http::{HeaderMap, HeaderName, HeaderValue, Version};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

// ═══════════════════════════════════════════════════════════════════════════
// HttpVersion — simple version enum for policy decisions
// ═══════════════════════════════════════════════════════════════════════════

/// Simplified HTTP version for connection reuse decisions.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpVersion {
    /// HTTP/1.0 — no persistent connections by default.
    Http10 = 0,
    /// HTTP/1.1 — persistent connections by default.
    Http11 = 1,
    /// HTTP/2 — multiplexed, connection reuse is inherent.
    Http2 = 2,
}

impl HttpVersion {
    /// Convert from `http::Version` (used by axum/hyper).
    pub fn from_version(v: Version) -> Self {
        match v {
            Version::HTTP_10 => Self::Http10,
            Version::HTTP_11 => Self::Http11,
            Version::HTTP_2 => Self::Http2,
            _ => Self::Http11, // default to 1.1 for unknown versions
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ReusePolicy — the four HAProxy http-reuse modes
// ═══════════════════════════════════════════════════════════════════════════

/// HAProxy-style connection reuse policy. Stored as `AtomicU8` for
/// lock-free runtime switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReusePolicy {
    /// 1:1 client-to-backend mapping. Each frontend connection gets a
    /// dedicated backend connection. Safest but most expensive.
    Never = 0,
    /// Reuse only after clean response completion. Default mode.
    /// Requires valid Content-Length or chunked Transfer-Encoding,
    /// no Connection: close, HTTP/1.1+, and no server errors.
    Safe = 1,
    /// Strip `Connection: close` from backend responses, force keepalive.
    /// Reuse connections even when the backend says `Connection: close`
    /// or uses HTTP/1.0. Faster but may break poorly-behaved backends.
    Aggressive = 2,
    /// Unconditional reuse. Ignore Connection headers entirely.
    /// Maximum efficiency but requires well-behaved backends.
    Always = 3,
}

impl ReusePolicy {
    /// Convert from raw `u8`. Unknown values default to `Safe`.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Never,
            1 => Self::Safe,
            2 => Self::Aggressive,
            3 => Self::Always,
            _ => Self::Safe,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global statics — lock-free runtime configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Global reuse policy. Default: Safe (HAProxy default).
static REUSE_POLICY: AtomicU8 = AtomicU8::new(ReusePolicy::Safe as u8);

/// Master kill-switch for connection reuse. When false, all policies
/// behave as Never.
static REUSE_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set the global reuse policy at runtime.
pub fn set_reuse_policy(policy: ReusePolicy) {
    REUSE_POLICY.store(policy as u8, Ordering::Relaxed);
}

/// Get the current global reuse policy.
pub fn reuse_policy() -> ReusePolicy {
    ReusePolicy::from_u8(REUSE_POLICY.load(Ordering::Relaxed))
}

/// Enable or disable connection reuse globally.
pub fn set_reuse_enabled(enabled: bool) {
    REUSE_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if connection reuse is globally enabled.
pub fn is_reuse_enabled() -> bool {
    REUSE_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// ReuseDecision — outcome of response validation
// ═══════════════════════════════════════════════════════════════════════════

/// Decision about whether a backend connection can be reused after an
/// exchange.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReuseDecision {
    /// Connection can be returned to the pool for reuse.
    Reuse,
    /// Connection should be closed after this exchange.
    Close,
    /// Close the connection and retry the request on a fresh connection.
    /// Used when the response is suspect (e.g. partial, corrupt).
    CloseAndRetry,
}

impl ReuseDecision {
    /// Returns `true` if the connection can be reused.
    #[inline]
    pub fn is_reusable(&self) -> bool {
        matches!(self, Self::Reuse)
    }

    /// Returns `true` if the connection should be closed.
    #[inline]
    pub fn should_close(&self) -> bool {
        matches!(self, Self::Close | Self::CloseAndRetry)
    }

    /// Returns `true` if the request should be retried on a new connection.
    #[inline]
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::CloseAndRetry)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ResponseValidator — checks if a response allows connection reuse
// ═══════════════════════════════════════════════════════════════════════════

/// Validates whether a backend response allows connection reuse under
/// the current policy. Stateless — all logic is in `validate()`.
pub struct ResponseValidator;

impl ResponseValidator {
    /// Check if the response allows connection reuse under the given policy.
    ///
    /// # Arguments
    ///
    /// * `policy` — The reuse policy to evaluate against.
    /// * `status` — HTTP response status code.
    /// * `response_headers` — Response headers from the backend.
    /// * `request_http_version` — HTTP version of the original request.
    ///
    /// # Returns
    ///
    /// A `ReuseDecision` indicating whether the connection can be reused.
    pub fn validate(
        policy: ReusePolicy,
        status: u16,
        response_headers: &HeaderMap,
        request_http_version: HttpVersion,
    ) -> ReuseDecision {
        // Master kill-switch.
        if !is_reuse_enabled() {
            return ReuseDecision::Close;
        }

        match policy {
            ReusePolicy::Never => ReuseDecision::Close,

            ReusePolicy::Safe => {
                // 408 Request Timeout — connection is suspect.
                if status == 408 {
                    return ReuseDecision::CloseAndRetry;
                }

                // 5xx server errors — don't trust the connection state.
                if status >= 500 {
                    return ReuseDecision::Close;
                }

                // HTTP/1.0 without explicit keep-alive — close.
                if request_http_version == HttpVersion::Http10 {
                    return ReuseDecision::Close;
                }

                // Connection: close header present — respect it.
                if has_connection_close(response_headers) {
                    return ReuseDecision::Close;
                }

                // 204 No Content and 304 Not Modified have no body — safe to reuse.
                if status == 204 || status == 304 {
                    return ReuseDecision::Reuse;
                }

                // A response carrying BOTH Content-Length and Transfer-Encoding
                // has ambiguous framing (a classic request-smuggling vector):
                // per RFC 7230 §3.3.3 the two disagree on the body boundary.
                // Never reuse such a connection — close it.
                if has_content_length(response_headers) && has_chunked_encoding(response_headers) {
                    return ReuseDecision::Close;
                }

                // Otherwise must have exactly one of Content-Length or
                // Transfer-Encoding: chunked to know the response body boundary.
                if has_content_length(response_headers)
                    || has_chunked_encoding(response_headers)
                {
                    return ReuseDecision::Reuse;
                }

                // 1xx informational responses have no body.
                if status >= 100 && status < 200 {
                    return ReuseDecision::Reuse;
                }

                // No framing — can't determine body boundary.
                ReuseDecision::Close
            }

            ReusePolicy::Aggressive => {
                // 408 — always suspect.
                if status == 408 {
                    return ReuseDecision::CloseAndRetry;
                }

                // Connection-level errors only: 502, 503, 504.
                if status == 502 || status == 503 || status == 504 {
                    return ReuseDecision::Close;
                }

                // Aggressive ignores Connection: close and HTTP version.
                // Everything else is reusable.
                ReuseDecision::Reuse
            }

            ReusePolicy::Always => {
                // 408 is the only exception — the connection timed out.
                if status == 408 {
                    return ReuseDecision::CloseAndRetry;
                }

                // Always reuse, even on 5xx.
                ReuseDecision::Reuse
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ConnectionHints — outbound header manipulation
// ═══════════════════════════════════════════════════════════════════════════

/// Modifies outbound request and inbound response headers based on the
/// active reuse policy. Stateless — all logic is in static methods.
pub struct ConnectionHints;

impl ConnectionHints {
    /// Prepare outbound request headers for the given reuse policy.
    ///
    /// - **Never**: sets `Connection: close` — tells the backend we won't reuse.
    /// - **Safe**: sets `Connection: keep-alive` for HTTP/1.1+.
    /// - **Aggressive**: always sets `Connection: keep-alive`.
    /// - **Always**: removes `Connection` header entirely.
    pub fn apply_request_hints(
        policy: ReusePolicy,
        headers: &mut HeaderMap,
        http_version: HttpVersion,
    ) {
        match policy {
            ReusePolicy::Never => {
                headers.insert(
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("close"),
                );
            }
            ReusePolicy::Safe => {
                if http_version != HttpVersion::Http10 {
                    headers.insert(
                        HeaderName::from_static("connection"),
                        HeaderValue::from_static("keep-alive"),
                    );
                }
            }
            ReusePolicy::Aggressive => {
                headers.insert(
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("keep-alive"),
                );
            }
            ReusePolicy::Always => {
                headers.remove("connection");
            }
        }
    }

    /// Process backend response headers based on reuse policy.
    ///
    /// For Aggressive and Always modes, strips `Connection: close` from
    /// responses to prevent hyper's connection pool from closing the
    /// connection.
    pub fn process_response_headers(
        policy: ReusePolicy,
        headers: &mut HeaderMap,
    ) {
        match policy {
            ReusePolicy::Never | ReusePolicy::Safe => {
                // Leave response headers untouched.
            }
            ReusePolicy::Aggressive => {
                // Strip Connection: close to keep the connection alive.
                if has_connection_close(headers) {
                    headers.remove("connection");
                }
            }
            ReusePolicy::Always => {
                // Remove Connection header entirely.
                headers.remove("connection");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Header inspection helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Check if headers contain `Connection: close`.
#[inline]
fn has_connection_close(headers: &HeaderMap) -> bool {
    headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        // Connection is a comma-separated list of tokens (e.g.
        // "keep-alive, close"); match the `close` token anywhere in the list,
        // not just an exact whole-value equality.
        .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
        .unwrap_or(false)
}

/// Check if headers contain a `Content-Length` header.
#[inline]
fn has_content_length(headers: &HeaderMap) -> bool {
    headers.contains_key("content-length")
}

/// Check if headers contain `Transfer-Encoding: chunked`.
#[inline]
fn has_chunked_encoding(headers: &HeaderMap) -> bool {
    headers
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════════════
// ReuseMetrics — atomic counters for observability
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic counters tracking connection reuse decisions. Lock-free,
/// safe to read from any thread (e.g. metrics endpoint).
pub struct ReuseMetrics {
    /// Connections returned to the pool for reuse.
    pub connections_reused: AtomicU64,
    /// New connections established (pool miss or first connection).
    pub connections_new: AtomicU64,
    /// Connections forcibly closed by policy (Never, or failed validation).
    pub connections_forced_close: AtomicU64,
    /// Connections that failed response validation (CloseAndRetry).
    pub connections_failed_validation: AtomicU64,
}

impl ReuseMetrics {
    /// Create a new zeroed metrics instance.
    const fn new() -> Self {
        Self {
            connections_reused: AtomicU64::new(0),
            connections_new: AtomicU64::new(0),
            connections_forced_close: AtomicU64::new(0),
            connections_failed_validation: AtomicU64::new(0),
        }
    }

    /// Record a reuse decision in the appropriate counter.
    pub fn record(&self, decision: ReuseDecision) {
        match decision {
            ReuseDecision::Reuse => {
                self.connections_reused.fetch_add(1, Ordering::Relaxed);
            }
            ReuseDecision::Close => {
                self.connections_forced_close.fetch_add(1, Ordering::Relaxed);
            }
            ReuseDecision::CloseAndRetry => {
                self.connections_failed_validation
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Global reuse metrics instance.
static REUSE_METRICS: ReuseMetrics = ReuseMetrics::new();

/// Get a reference to the global reuse metrics.
pub fn reuse_metrics() -> &'static ReuseMetrics {
    &REUSE_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// ServiceReuseConfig — per-service overrides
// ═══════════════════════════════════════════════════════════════════════════

/// Per-service connection reuse configuration. Allows overriding the
/// global policy for specific backends that have different requirements.
#[derive(Clone, Debug)]
pub struct ServiceReuseConfig {
    /// Override policy for this service. `None` = use global default.
    pub policy: Option<ReusePolicy>,
    /// Maximum times to reuse a single connection before rotating.
    /// 0 = unlimited.
    pub max_reuses: u32,
    /// Override idle timeout in seconds. 0 = use global default.
    pub max_idle_secs: u32,
}

impl Default for ServiceReuseConfig {
    fn default() -> Self {
        Self {
            policy: None,
            max_reuses: 0,
            max_idle_secs: 0,
        }
    }
}

impl ServiceReuseConfig {
    /// Get the effective policy for this service, falling back to the
    /// global default if no override is set.
    pub fn effective_policy(&self) -> ReusePolicy {
        self.policy.unwrap_or_else(reuse_policy)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── ReusePolicy from_u8 roundtrip ──

    #[test]
    fn policy_u8_roundtrip() {
        assert_eq!(ReusePolicy::from_u8(0), ReusePolicy::Never);
        assert_eq!(ReusePolicy::from_u8(1), ReusePolicy::Safe);
        assert_eq!(ReusePolicy::from_u8(2), ReusePolicy::Aggressive);
        assert_eq!(ReusePolicy::from_u8(3), ReusePolicy::Always);
        // Unknown values default to Safe.
        assert_eq!(ReusePolicy::from_u8(4), ReusePolicy::Safe);
        assert_eq!(ReusePolicy::from_u8(255), ReusePolicy::Safe);
    }

    #[test]
    fn policy_toggle() {
        set_reuse_policy(ReusePolicy::Never);
        assert_eq!(reuse_policy(), ReusePolicy::Never);
        set_reuse_policy(ReusePolicy::Aggressive);
        assert_eq!(reuse_policy(), ReusePolicy::Aggressive);
        set_reuse_policy(ReusePolicy::Always);
        assert_eq!(reuse_policy(), ReusePolicy::Always);
        // Reset to default.
        set_reuse_policy(ReusePolicy::Safe);
        assert_eq!(reuse_policy(), ReusePolicy::Safe);
    }

    #[test]
    fn reuse_enabled_toggle() {
        set_reuse_enabled(false);
        assert!(!is_reuse_enabled());
        set_reuse_enabled(true);
        assert!(is_reuse_enabled());
    }

    // ── Never policy ──

    #[test]
    fn never_always_closes() {
        let headers = HeaderMap::new();
        let decision =
            ResponseValidator::validate(ReusePolicy::Never, 200, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Close);

        // Even with perfect conditions, Never always closes.
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("42"));
        let decision =
            ResponseValidator::validate(ReusePolicy::Never, 200, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Close);
    }

    // ── Safe policy ──

    #[test]
    fn safe_reuses_clean_response() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("1024"));
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 200, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Reuse);
    }

    #[test]
    fn safe_closes_on_connection_close_header() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("100"));
        headers.insert("connection", HeaderValue::from_static("close"));
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 200, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Close);
    }

    #[test]
    fn safe_closes_on_5xx() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("0"));
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 502, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Close);
    }

    #[test]
    fn safe_closes_on_408() {
        let headers = HeaderMap::new();
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 408, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::CloseAndRetry);
    }

    #[test]
    fn safe_closes_on_http10() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("100"));
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 200, &headers, HttpVersion::Http10);
        assert_eq!(decision, ReuseDecision::Close);
    }

    #[test]
    fn safe_reuses_chunked() {
        let mut headers = HeaderMap::new();
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 200, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Reuse);
    }

    #[test]
    fn safe_closes_no_content_length_no_chunked() {
        let headers = HeaderMap::new();
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 200, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Close);
    }

    #[test]
    fn safe_reuses_204_no_body() {
        // 204 No Content has no body — always safe to reuse.
        let headers = HeaderMap::new();
        let decision =
            ResponseValidator::validate(ReusePolicy::Safe, 204, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Reuse);
    }

    // ── Aggressive policy ──

    #[test]
    fn aggressive_ignores_connection_close() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));
        let decision = ResponseValidator::validate(
            ReusePolicy::Aggressive,
            200,
            &headers,
            HttpVersion::Http11,
        );
        assert_eq!(decision, ReuseDecision::Reuse);
    }

    #[test]
    fn aggressive_closes_on_502() {
        let headers = HeaderMap::new();
        let decision = ResponseValidator::validate(
            ReusePolicy::Aggressive,
            502,
            &headers,
            HttpVersion::Http11,
        );
        assert_eq!(decision, ReuseDecision::Close);
    }

    #[test]
    fn aggressive_reuses_http10() {
        let headers = HeaderMap::new();
        let decision = ResponseValidator::validate(
            ReusePolicy::Aggressive,
            200,
            &headers,
            HttpVersion::Http10,
        );
        assert_eq!(decision, ReuseDecision::Reuse);
    }

    // ── Always policy ──

    #[test]
    fn always_reuses_everything() {
        let headers = HeaderMap::new();
        // Even 500 is reused.
        let decision =
            ResponseValidator::validate(ReusePolicy::Always, 500, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::Reuse);

        // Even with Connection: close.
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));
        let decision =
            ResponseValidator::validate(ReusePolicy::Always, 200, &headers, HttpVersion::Http10);
        assert_eq!(decision, ReuseDecision::Reuse);
    }

    #[test]
    fn always_closes_on_408() {
        let headers = HeaderMap::new();
        let decision =
            ResponseValidator::validate(ReusePolicy::Always, 408, &headers, HttpVersion::Http11);
        assert_eq!(decision, ReuseDecision::CloseAndRetry);
    }

    // ── ConnectionHints: request headers ──

    #[test]
    fn hints_never_sets_connection_close() {
        let mut headers = HeaderMap::new();
        ConnectionHints::apply_request_hints(ReusePolicy::Never, &mut headers, HttpVersion::Http11);
        assert_eq!(headers.get("connection").unwrap(), "close");
    }

    #[test]
    fn hints_safe_sets_keepalive() {
        let mut headers = HeaderMap::new();
        ConnectionHints::apply_request_hints(ReusePolicy::Safe, &mut headers, HttpVersion::Http11);
        assert_eq!(headers.get("connection").unwrap(), "keep-alive");
    }

    #[test]
    fn hints_aggressive_strips_response_close() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        ConnectionHints::process_response_headers(ReusePolicy::Aggressive, &mut headers);
        // Connection: close should be removed.
        assert!(headers.get("connection").is_none());
        // Other headers preserved.
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn hints_always_removes_connection_header() {
        // Request: removes Connection header.
        let mut req_headers = HeaderMap::new();
        req_headers.insert("connection", HeaderValue::from_static("keep-alive"));
        ConnectionHints::apply_request_hints(
            ReusePolicy::Always,
            &mut req_headers,
            HttpVersion::Http11,
        );
        assert!(req_headers.get("connection").is_none());

        // Response: removes Connection header.
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("connection", HeaderValue::from_static("close"));
        ConnectionHints::process_response_headers(ReusePolicy::Always, &mut resp_headers);
        assert!(resp_headers.get("connection").is_none());
    }

    // ── HttpVersion ──

    #[test]
    fn http_version_from_version() {
        assert_eq!(HttpVersion::from_version(Version::HTTP_10), HttpVersion::Http10);
        assert_eq!(HttpVersion::from_version(Version::HTTP_11), HttpVersion::Http11);
        assert_eq!(HttpVersion::from_version(Version::HTTP_2), HttpVersion::Http2);
    }

    // ── ReuseMetrics ──

    #[test]
    fn metrics_increment() {
        let metrics = ReuseMetrics::new();

        metrics.record(ReuseDecision::Reuse);
        metrics.record(ReuseDecision::Reuse);
        metrics.record(ReuseDecision::Close);
        metrics.record(ReuseDecision::CloseAndRetry);

        assert_eq!(metrics.connections_reused.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.connections_forced_close.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .connections_failed_validation
                .load(Ordering::Relaxed),
            1
        );
    }

    // ── ServiceReuseConfig ──

    #[test]
    fn service_reuse_config_defaults() {
        let config = ServiceReuseConfig::default();
        assert!(config.policy.is_none());
        assert_eq!(config.max_reuses, 0);
        assert_eq!(config.max_idle_secs, 0);

        // effective_policy falls back to global.
        set_reuse_policy(ReusePolicy::Safe);
        assert_eq!(config.effective_policy(), ReusePolicy::Safe);

        // With an override.
        let config = ServiceReuseConfig {
            policy: Some(ReusePolicy::Always),
            max_reuses: 100,
            max_idle_secs: 30,
        };
        assert_eq!(config.effective_policy(), ReusePolicy::Always);
    }

    // ── ReuseDecision helpers ──

    #[test]
    fn reuse_decision_is_reusable() {
        assert!(ReuseDecision::Reuse.is_reusable());
        assert!(!ReuseDecision::Close.is_reusable());
        assert!(!ReuseDecision::CloseAndRetry.is_reusable());

        assert!(!ReuseDecision::Reuse.should_close());
        assert!(ReuseDecision::Close.should_close());
        assert!(ReuseDecision::CloseAndRetry.should_close());

        assert!(!ReuseDecision::Reuse.should_retry());
        assert!(!ReuseDecision::Close.should_retry());
        assert!(ReuseDecision::CloseAndRetry.should_retry());
    }
}
