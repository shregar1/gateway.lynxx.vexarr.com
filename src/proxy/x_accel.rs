//! NGINX-style `X-Accel-Redirect` internal redirect support.
//!
//! When an upstream responds with an `X-Accel-Redirect: /internal/path`
//! header, NGINX performs an internal redirect to serve the specified
//! path instead of the upstream's response body. The original response
//! is discarded. Additional `X-Accel-*` headers control caching,
//! buffering, rate limiting, and charset.
//!
//! # Architecture
//!
//! ```text
//! X-Accel (configurable: enabled / disabled)
//! +-- XAccelDirective        -- Parsed redirect + associated X-Accel-* headers
//! +-- XAccelResult           -- NoRedirect | Redirect(XAccelDirective)
//! +-- check_x_accel()        -- Scan response headers, produce XAccelResult
//! +-- validate_redirect_path -- Path safety (no traversal, no absolute URLs)
//! +-- strip_x_accel_headers  -- Remove internal headers before forwarding
//! +-- XAccelMetrics          -- Atomic counters (redirects, blocks, etc.)
//! ```
//!
//! # X-Accel Headers
//!
//! | Header               | Meaning                                    |
//! |----------------------|--------------------------------------------|
//! | `X-Accel-Redirect`   | Internal redirect path                     |
//! | `X-Accel-Expires`    | Override cache expiry (seconds or "off")   |
//! | `X-Accel-Limit-Rate` | Rate limit in bytes/sec (or "off")         |
//! | `X-Accel-Buffering`  | Enable/disable response buffering (yes/no)|
//! | `X-Accel-Charset`    | Override response charset                  |
//!
//! # Security
//!
//! The redirect path is validated to prevent path traversal attacks:
//! - Must start with `/`
//! - Must not contain `..` segments
//! - Must not be an absolute URL (no `://`)
//! - Must not be empty

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics — lock-free runtime configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Master switch for X-Accel-Redirect processing. When false, upstream
/// `X-Accel-Redirect` headers are ignored. Default: **false** (opt-in).
static X_ACCEL_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable or disable X-Accel-Redirect processing globally.
pub fn set_x_accel_enabled(enabled: bool) {
    X_ACCEL_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if X-Accel-Redirect processing is globally enabled.
pub fn is_x_accel_enabled() -> bool {
    X_ACCEL_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// Header constants
// ═══════════════════════════════════════════════════════════════════════════

/// Internal redirect path header.
pub const X_ACCEL_REDIRECT: &str = "x-accel-redirect";

/// Override cache expiry header. Value is seconds or `"off"`.
pub const X_ACCEL_EXPIRES: &str = "x-accel-expires";

/// Rate limit header. Value is bytes/sec or `"off"`.
pub const X_ACCEL_LIMIT_RATE: &str = "x-accel-limit-rate";

/// Response buffering toggle header. Value is `"yes"` or `"no"`.
pub const X_ACCEL_BUFFERING: &str = "x-accel-buffering";

/// Charset override header.
pub const X_ACCEL_CHARSET: &str = "x-accel-charset";

// ═══════════════════════════════════════════════════════════════════════════
// Core types
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed X-Accel directives from an upstream response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XAccelDirective {
    /// The internal redirect path (from `X-Accel-Redirect`).
    pub redirect_path: String,
    /// Cache expiry override (from `X-Accel-Expires`). `None` when the
    /// header is absent or set to `"off"`.
    pub expires: Option<Duration>,
    /// Rate limit in bytes/sec (from `X-Accel-Limit-Rate`). `None` when
    /// the header is absent or set to `"off"`.
    pub limit_rate: Option<u64>,
    /// Response buffering toggle (from `X-Accel-Buffering`). `None` when
    /// the header is absent or has an unrecognized value.
    pub buffering: Option<bool>,
    /// Charset override (from `X-Accel-Charset`). `None` when absent.
    pub charset: Option<String>,
}

/// Result of inspecting upstream response headers for X-Accel directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XAccelResult {
    /// No `X-Accel-Redirect` header found — pass the response through.
    NoRedirect,
    /// An `X-Accel-Redirect` header was found with a valid path.
    Redirect(XAccelDirective),
}

// ═══════════════════════════════════════════════════════════════════════════
// Parsing helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Parse an `X-Accel-Expires` value into a `Duration`.
///
/// Accepts a non-negative integer (seconds) or `"off"`. Returns `None`
/// for `"off"` or any unparseable value.
pub fn parse_expires(value: &str) -> Option<Duration> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("off") {
        return None;
    }
    trimmed.parse::<u64>().ok().map(Duration::from_secs)
}

/// Parse an `X-Accel-Limit-Rate` value into bytes/sec.
///
/// Accepts a non-negative integer or `"off"`. Returns `None` for
/// `"off"` or any unparseable value.
pub fn parse_limit_rate(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("off") {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

/// Parse an `X-Accel-Buffering` value into a boolean.
///
/// `"yes"` -> `Some(true)`, `"no"` -> `Some(false)`, anything else -> `None`.
pub fn parse_buffering(value: &str) -> Option<bool> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("yes") {
        Some(true)
    } else if trimmed.eq_ignore_ascii_case("no") {
        Some(false)
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Path validation
// ═══════════════════════════════════════════════════════════════════════════

/// Validate that a redirect path is safe for internal use.
///
/// A valid path:
/// - Is non-empty
/// - Starts with `/`
/// - Does not contain `..` path traversal segments
/// - Is not an absolute URL (no `://`)
/// - Is not a scheme-relative / network-path reference (no leading `//`
///   or `/\`) — these resolve to an external authority and are rejected.
pub fn validate_redirect_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if !path.starts_with('/') {
        return false;
    }
    // BUG FIX: a leading `//` (or its `/\` backslash variant that some
    // clients normalize to `//`) is an RFC 3986 network-path reference,
    // i.e. a scheme-relative absolute URL pointing at an external host
    // (`//evil.com/payload`). It passes `starts_with('/')` and contains no
    // `://`, so the old checks accepted it — letting the redirect escape to
    // an attacker-controlled authority. Reject it before the bare `/` root
    // and traversal checks below.
    if path.starts_with("//") || path.starts_with("/\\") {
        return false;
    }
    if path.contains("://") {
        return false;
    }
    // Check for `..` traversal — reject if any path segment is `..`.
    // Split on `/` and check each segment. We also reject bare `..`
    // anywhere in the path string to be safe.
    let path_part = path.split('?').next().unwrap_or(path);
    // Reject percent-encoded traversal primitives. An internal redirect path
    // should already be decoded; an encoded dot (%2e) or separator (%2f / %5c)
    // can smuggle a `..` or path separator past the literal segment check below
    // and re-expand to traversal once the upstream/filesystem decodes it.
    let lower = path_part.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    // Reject `..` as a whole segment, splitting on both `/` and `\` (some
    // resolvers treat backslash as a separator).
    for segment in path_part.split(['/', '\\']) {
        if segment == ".." {
            return false;
        }
    }
    true
}

// ═══════════════════════════════════════════════════════════════════════════
// Core logic
// ═══════════════════════════════════════════════════════════════════════════

/// Scan upstream response headers for `X-Accel-Redirect` and parse all
/// associated `X-Accel-*` directives.
///
/// Returns `XAccelResult::Redirect` if the header is present with a
/// valid path, or `XAccelResult::NoRedirect` otherwise.
///
/// When the global toggle is disabled (`is_x_accel_enabled() == false`),
/// this always returns `NoRedirect` without inspecting headers.
pub fn check_x_accel(headers: &[(String, String)]) -> XAccelResult {
    check_x_accel_with_enabled(headers, is_x_accel_enabled())
}

/// Like [`check_x_accel`], but takes an explicit `enabled` flag instead
/// of reading the global toggle. Used in tests to avoid racing on the
/// shared `X_ACCEL_ENABLED` AtomicBool.
pub fn check_x_accel_with_enabled(
    headers: &[(String, String)],
    enabled: bool,
) -> XAccelResult {
    if !enabled {
        return XAccelResult::NoRedirect;
    }

    // Find the redirect path first — without it, there's nothing to do.
    let redirect_path = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(X_ACCEL_REDIRECT))
        .map(|(_, v)| v.trim().to_string());

    let redirect_path = match redirect_path {
        Some(p) if !p.is_empty() => p,
        _ => return XAccelResult::NoRedirect,
    };

    if !validate_redirect_path(&redirect_path) {
        x_accel_metrics().record_redirect_blocked();
        return XAccelResult::NoRedirect;
    }

    // Parse optional X-Accel-* companion headers.
    let mut expires: Option<Duration> = None;
    let mut limit_rate: Option<u64> = None;
    let mut buffering: Option<bool> = None;
    let mut charset: Option<String> = None;

    for (key, value) in headers {
        if key.eq_ignore_ascii_case(X_ACCEL_EXPIRES) {
            expires = parse_expires(value);
            if expires.is_some() {
                x_accel_metrics().record_expires_set();
            }
        } else if key.eq_ignore_ascii_case(X_ACCEL_LIMIT_RATE) {
            limit_rate = parse_limit_rate(value);
            if limit_rate.is_some() {
                x_accel_metrics().record_rate_limit_set();
            }
        } else if key.eq_ignore_ascii_case(X_ACCEL_BUFFERING) {
            buffering = parse_buffering(value);
        } else if key.eq_ignore_ascii_case(X_ACCEL_CHARSET) {
            let v = value.trim();
            if !v.is_empty() {
                charset = Some(v.to_string());
            }
        }
    }

    x_accel_metrics().record_redirect_performed();

    XAccelResult::Redirect(XAccelDirective {
        redirect_path,
        expires,
        limit_rate,
        buffering,
        charset,
    })
}

/// Remove all `X-Accel-*` headers from a response header list.
///
/// These headers are internal directives and must not be forwarded to
/// the client.
pub fn strip_x_accel_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(k, _)| !k.to_ascii_lowercase().starts_with("x-accel-"));
}

// ═══════════════════════════════════════════════════════════════════════════
// XAccelMetrics — atomic counters
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic counters tracking X-Accel-Redirect activity. Lock-free, safe
/// to read from any thread (e.g. metrics/prometheus endpoint).
pub struct XAccelMetrics {
    /// Total number of internal redirects successfully performed.
    pub redirects_performed: AtomicU64,
    /// Redirects blocked due to invalid/unsafe paths.
    pub redirects_blocked: AtomicU64,
    /// Number of times X-Accel-Expires was parsed and applied.
    pub expires_set: AtomicU64,
    /// Number of times X-Accel-Limit-Rate was parsed and applied.
    pub rate_limits_set: AtomicU64,
}

impl XAccelMetrics {
    /// Create a new zeroed metrics instance.
    const fn new() -> Self {
        Self {
            redirects_performed: AtomicU64::new(0),
            redirects_blocked: AtomicU64::new(0),
            expires_set: AtomicU64::new(0),
            rate_limits_set: AtomicU64::new(0),
        }
    }

    /// Record a successful internal redirect.
    #[inline]
    pub fn record_redirect_performed(&self) {
        self.redirects_performed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a blocked redirect (invalid path).
    #[inline]
    pub fn record_redirect_blocked(&self) {
        self.redirects_blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an X-Accel-Expires value being applied.
    #[inline]
    pub fn record_expires_set(&self) {
        self.expires_set.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an X-Accel-Limit-Rate value being applied.
    #[inline]
    pub fn record_rate_limit_set(&self) {
        self.rate_limits_set.fetch_add(1, Ordering::Relaxed);
    }
}

/// Global X-Accel metrics instance.
static X_ACCEL_METRICS: XAccelMetrics = XAccelMetrics::new();

/// Get a reference to the global X-Accel metrics.
pub fn x_accel_metrics() -> &'static XAccelMetrics {
    &X_ACCEL_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── check_x_accel: no redirect header → NoRedirect ──

    #[test]
    fn check_no_redirect_header() {
        // Use the per-call override to avoid toggling the global AtomicBool,
        // which races with other parallel tests (same pattern as mirror.rs,
        // cookie_rewrite.rs, slow_start.rs).
        let headers = vec![
            ("content-type".to_string(), "text/html".to_string()),
            ("x-custom".to_string(), "value".to_string()),
        ];
        assert_eq!(
            check_x_accel_with_enabled(&headers, true),
            XAccelResult::NoRedirect,
        );
    }

    // ── check_x_accel: redirect → Redirect with path ──

    #[test]
    fn check_redirect_basic() {
        let headers = vec![(
            "X-Accel-Redirect".to_string(),
            "/internal/file.txt".to_string(),
        )];
        match check_x_accel_with_enabled(&headers, true) {
            XAccelResult::Redirect(directive) => {
                assert_eq!(directive.redirect_path, "/internal/file.txt");
                assert_eq!(directive.expires, None);
                assert_eq!(directive.limit_rate, None);
                assert_eq!(directive.buffering, None);
                assert_eq!(directive.charset, None);
            }
            XAccelResult::NoRedirect => panic!("expected Redirect"),
        }
    }

    // ── check_x_accel: all X-Accel-* headers ──

    #[test]
    fn check_redirect_all_headers() {
        let headers = vec![
            (
                "X-Accel-Redirect".to_string(),
                "/protected/data.bin".to_string(),
            ),
            ("X-Accel-Expires".to_string(), "3600".to_string()),
            ("X-Accel-Limit-Rate".to_string(), "1048576".to_string()),
            ("X-Accel-Buffering".to_string(), "no".to_string()),
            ("X-Accel-Charset".to_string(), "utf-8".to_string()),
        ];
        match check_x_accel_with_enabled(&headers, true) {
            XAccelResult::Redirect(d) => {
                assert_eq!(d.redirect_path, "/protected/data.bin");
                assert_eq!(d.expires, Some(Duration::from_secs(3600)));
                assert_eq!(d.limit_rate, Some(1_048_576));
                assert_eq!(d.buffering, Some(false));
                assert_eq!(d.charset, Some("utf-8".to_string()));
            }
            XAccelResult::NoRedirect => panic!("expected Redirect"),
        }
    }

    // ── parse_expires: seconds ──

    #[test]
    fn parse_expires_seconds() {
        assert_eq!(parse_expires("300"), Some(Duration::from_secs(300)));
    }

    // ── parse_expires: "off" → None ──

    #[test]
    fn parse_expires_off() {
        assert_eq!(parse_expires("off"), None);
        assert_eq!(parse_expires("OFF"), None);
        assert_eq!(parse_expires("Off"), None);
    }

    // ── parse_expires: invalid → None ──

    #[test]
    fn parse_expires_invalid() {
        assert_eq!(parse_expires("abc"), None);
        assert_eq!(parse_expires(""), None);
        assert_eq!(parse_expires("-1"), None);
    }

    // ── parse_limit_rate: valid ──

    #[test]
    fn parse_limit_rate_valid() {
        assert_eq!(parse_limit_rate("1048576"), Some(1_048_576));
        assert_eq!(parse_limit_rate("0"), Some(0));
    }

    // ── parse_limit_rate: "off" → None ──

    #[test]
    fn parse_limit_rate_off() {
        assert_eq!(parse_limit_rate("off"), None);
        assert_eq!(parse_limit_rate("OFF"), None);
    }

    // ── parse_buffering: "yes" → true ──

    #[test]
    fn parse_buffering_yes() {
        assert_eq!(parse_buffering("yes"), Some(true));
        assert_eq!(parse_buffering("YES"), Some(true));
        assert_eq!(parse_buffering("Yes"), Some(true));
    }

    // ── parse_buffering: "no" → false ──

    #[test]
    fn parse_buffering_no() {
        assert_eq!(parse_buffering("no"), Some(false));
        assert_eq!(parse_buffering("NO"), Some(false));
        assert_eq!(parse_buffering("No"), Some(false));
    }

    // ── parse_buffering: invalid → None ──

    #[test]
    fn parse_buffering_invalid() {
        assert_eq!(parse_buffering("maybe"), None);
        assert_eq!(parse_buffering(""), None);
        assert_eq!(parse_buffering("1"), None);
    }

    // ── validate_redirect_path: valid ──

    #[test]
    fn validate_path_valid() {
        assert!(validate_redirect_path("/internal/file"));
        assert!(validate_redirect_path("/a/b/c/d.txt"));
        assert!(validate_redirect_path("/"));
    }

    // ── validate_redirect_path: rejects ../etc/passwd ──

    #[test]
    fn validate_path_rejects_traversal() {
        assert!(!validate_redirect_path("/../etc/passwd"));
        assert!(!validate_redirect_path("/a/../../etc/passwd"));
        assert!(!validate_redirect_path("/a/b/../../../etc/shadow"));
    }

    // ── validate_redirect_path: rejects absolute URL ──

    #[test]
    fn validate_path_rejects_absolute_url() {
        assert!(!validate_redirect_path("http://evil.com/payload"));
        assert!(!validate_redirect_path("https://evil.com/payload"));
        assert!(!validate_redirect_path("ftp://evil.com/file"));
    }

    // ── validate_redirect_path: rejects protocol-relative / network-path URLs ──

    #[test]
    fn validate_path_rejects_network_path_reference() {
        // Regression: a leading `//host` (or `/\host`) is a scheme-relative
        // absolute URL to an external authority; it passes starts_with('/')
        // and has no `://`, so it was wrongly accepted before the fix.
        assert!(!validate_redirect_path("//evil.com/payload"));
        assert!(!validate_redirect_path("//evil.com"));
        assert!(!validate_redirect_path("/\\evil.com"));
        assert!(!validate_redirect_path("//"));
        // Legitimate single-slash paths must still be accepted.
        assert!(validate_redirect_path("/"));
        assert!(validate_redirect_path("/internal/path"));
        assert!(validate_redirect_path("/path?a=b"));
    }

    // ── validate_redirect_path: rejects empty ──

    #[test]
    fn validate_path_rejects_empty() {
        assert!(!validate_redirect_path(""));
    }

    // ── strip_x_accel_headers: removes all X-Accel headers ──

    #[test]
    fn strip_removes_all_x_accel() {
        let mut headers = vec![
            ("X-Accel-Redirect".to_string(), "/path".to_string()),
            ("X-Accel-Expires".to_string(), "300".to_string()),
            ("X-Accel-Limit-Rate".to_string(), "1024".to_string()),
            ("X-Accel-Buffering".to_string(), "yes".to_string()),
            ("X-Accel-Charset".to_string(), "utf-8".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        strip_x_accel_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "content-type");
    }

    // ── strip_x_accel_headers: preserves non-X-Accel headers ──

    #[test]
    fn strip_preserves_other_headers() {
        let mut headers = vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("x-custom".to_string(), "keep-me".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
        ];
        strip_x_accel_headers(&mut headers);
        assert_eq!(headers.len(), 3);
    }

    // ── global enable/disable toggle ──

    #[test]
    fn global_toggle() {
        // Verify the enabled/disabled contract via check_x_accel_with_enabled
        // without touching the global AtomicBool — avoids racing parallel tests.
        let headers = vec![("X-Accel-Redirect".to_string(), "/internal/file".to_string())];

        match check_x_accel_with_enabled(&headers, true) {
            XAccelResult::Redirect(d) => {
                assert_eq!(d.redirect_path, "/internal/file");
            }
            XAccelResult::NoRedirect => panic!("expected Redirect when enabled"),
        }

        assert_eq!(
            check_x_accel_with_enabled(&headers, false),
            XAccelResult::NoRedirect,
        );
    }

    // ── metrics counting ──

    #[test]
    fn metrics_counting() {
        let metrics = XAccelMetrics::new();

        metrics.record_redirect_performed();
        metrics.record_redirect_performed();
        assert_eq!(metrics.redirects_performed.load(Ordering::Relaxed), 2);

        metrics.record_redirect_blocked();
        assert_eq!(metrics.redirects_blocked.load(Ordering::Relaxed), 1);

        metrics.record_expires_set();
        metrics.record_expires_set();
        metrics.record_expires_set();
        assert_eq!(metrics.expires_set.load(Ordering::Relaxed), 3);

        metrics.record_rate_limit_set();
        assert_eq!(metrics.rate_limits_set.load(Ordering::Relaxed), 1);
    }

    // ── redirect path with query string preserved ──

    #[test]
    fn redirect_path_with_query_string() {
        let headers = vec![(
            "X-Accel-Redirect".to_string(),
            "/internal/file?token=abc123&page=2".to_string(),
        )];
        match check_x_accel_with_enabled(&headers, true) {
            XAccelResult::Redirect(d) => {
                assert_eq!(d.redirect_path, "/internal/file?token=abc123&page=2");
            }
            XAccelResult::NoRedirect => {
                panic!("expected Redirect with query string")
            }
        }
    }
}
