use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, VARY};
use axum::http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt;
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq)]
enum CompressionAlgo {
    Gzip,
    Zstd,
    Brotli,
}

#[derive(Clone, Debug)]
struct NegotiatedEncoding(CompressionAlgo);

const DEFAULT_MIN_BODY_SIZE: usize = 256;

const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/xhtml+xml",
    "image/svg+xml",
];

/// Default status codes that are eligible for compression. 1xx, 204, and
/// 304 carry no body; everything else in 2xx/3xx is fair game.
const DEFAULT_MATCH_STATUS: &[StatusRange] = &[
    StatusRange::Range(200, 203),
    StatusRange::Range(205, 299),
    StatusRange::Range(300, 303),
    StatusRange::Range(305, 399),
];

/// A status code or inclusive range of status codes.
#[derive(Clone, Debug, PartialEq)]
enum StatusRange {
    Single(u16),
    Range(u16, u16),
}

impl StatusRange {
    fn contains(&self, code: u16) -> bool {
        match self {
            StatusRange::Single(c) => *c == code,
            StatusRange::Range(lo, hi) => code >= *lo && code <= *hi,
        }
    }
}

/// Parse a status specifier: `"200"` → `Single(200)`, `"200-299"` → `Range(200, 299)`.
fn parse_status_range(s: &str) -> Option<StatusRange> {
    if let Some((lo, hi)) = s.split_once('-') {
        let lo: u16 = lo.trim().parse().ok()?;
        let hi: u16 = hi.trim().parse().ok()?;
        Some(StatusRange::Range(lo, hi))
    } else {
        let code: u16 = s.trim().parse().ok()?;
        Some(StatusRange::Single(code))
    }
}

pub struct ResponseCompressionPlugin {
    algorithms: Vec<CompressionAlgo>,
    min_body_size: usize,
    content_types: Vec<String>,
    /// Content-Type patterns to exclude (checked before the include list).
    exclude_content_types: Vec<String>,
    /// Status codes / ranges eligible for compression. Empty = match all.
    match_status: Vec<StatusRange>,
    /// Request path prefixes to match. Empty = match all paths.
    match_paths: Vec<String>,
    gzip_level: u32,
    zstd_level: i32,
    brotli_level: u32,
}

impl ResponseCompressionPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let algorithms = if let Some(arr) = cfg.get("algorithms").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| match s {
                    "gzip" | "gz" => Some(CompressionAlgo::Gzip),
                    "zstd" | "zstandard" => Some(CompressionAlgo::Zstd),
                    "br" | "brotli" => Some(CompressionAlgo::Brotli),
                    _ => None,
                })
                .collect()
        } else {
            vec![
                CompressionAlgo::Zstd,
                CompressionAlgo::Brotli,
                CompressionAlgo::Gzip,
            ]
        };

        // Accept both Caddy-style `minimum_length` and the original
        // `min_body_size` key for backwards compatibility.
        let min_body_size = cfg
            .get("minimum_length")
            .or_else(|| cfg.get("min_body_size"))
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(DEFAULT_MIN_BODY_SIZE);

        let content_types = if let Some(arr) = cfg.get("content_types").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect()
        } else {
            DEFAULT_CONTENT_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect()
        };

        // Content-Type exclusion list — checked before the include list.
        let exclude_content_types =
            if let Some(arr) = cfg.get("exclude_content_types").and_then(|v| v.as_array()) {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect()
            } else {
                Vec::new()
            };

        // Status-code matcher. Accepts a JSON array of strings:
        //   `["200", "201-299", "304"]`
        // Defaults to 200-203, 205-299, 300-303, 305-399 (skips 204 No
        // Content / 304 Not Modified which carry no body).
        let match_status = if let Some(arr) = cfg.get("match_status").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str().or(None))
                .filter_map(parse_status_range)
                .collect()
        } else if let Some(arr) = cfg.get("match_status").and_then(|v| v.as_array()) {
            // numeric array shorthand: `[200, 201]`
            arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|c| StatusRange::Single(c as u16))
                .collect()
        } else {
            DEFAULT_MATCH_STATUS.to_vec()
        };

        // Path-prefix matcher. When non-empty, only responses for
        // requests whose URI path starts with one of the prefixes are
        // eligible for compression.
        let match_paths = if let Some(arr) = cfg.get("match_paths").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect()
        } else {
            Vec::new()
        };

        let gzip_level = cfg.get("gzip_level").and_then(|v| v.as_u64()).unwrap_or(6) as u32;

        let zstd_level = cfg.get("zstd_level").and_then(|v| v.as_i64()).unwrap_or(3) as i32;

        let brotli_level = cfg
            .get("brotli_level")
            .and_then(|v| v.as_u64())
            .unwrap_or(4) as u32;

        Ok(Self {
            algorithms,
            min_body_size,
            content_types,
            exclude_content_types,
            match_status,
            match_paths,
            gzip_level,
            zstd_level,
            brotli_level,
        })
    }

    fn is_compressible_type(&self, content_type: &str) -> bool {
        let ct = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim();

        // Exclusions take priority.
        if self.exclude_content_types.iter().any(|pattern| {
            if pattern.ends_with("/*") || pattern.ends_with('/') {
                let prefix = pattern.trim_end_matches('*');
                ct.starts_with(prefix)
            } else {
                ct.eq_ignore_ascii_case(pattern)
            }
        }) {
            return false;
        }

        self.content_types.iter().any(|pattern| {
            if pattern.ends_with("/*") || pattern.ends_with('/') {
                let prefix = pattern.trim_end_matches('*');
                ct.starts_with(prefix)
            } else {
                ct.eq_ignore_ascii_case(pattern)
            }
        })
    }

    /// Check whether the response status code is eligible for compression.
    fn is_compressible_status(&self, status: StatusCode) -> bool {
        if self.match_status.is_empty() {
            return true;
        }
        let code = status.as_u16();
        self.match_status.iter().any(|r| r.contains(code))
    }

    /// Check whether the request path matches the configured path prefixes.
    fn is_matching_path(&self, path: &str) -> bool {
        if self.match_paths.is_empty() {
            return true;
        }
        self.match_paths
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    fn negotiate(&self, accept_encoding: &str) -> Option<CompressionAlgo> {
        let mut candidates: Vec<(&str, f32)> = accept_encoding
            .split(',')
            .filter_map(|part| {
                let part = part.trim();
                let mut iter = part.splitn(2, ";q=");
                let algo = iter.next()?.trim();
                let q: f32 = iter
                    .next()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(1.0);
                if q > 0.0 {
                    Some((algo, q))
                } else {
                    None
                }
            })
            .collect();

        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        for (name, _) in &candidates {
            for algo in &self.algorithms {
                match algo {
                    CompressionAlgo::Zstd if *name == "zstd" => return Some(CompressionAlgo::Zstd),
                    CompressionAlgo::Brotli if *name == "br" => {
                        return Some(CompressionAlgo::Brotli)
                    }
                    CompressionAlgo::Gzip if *name == "gzip" => return Some(CompressionAlgo::Gzip),
                    _ => {}
                }
            }
        }

        None
    }
}

#[async_trait]
impl Plugin for ResponseCompressionPlugin {
    fn name(&self) -> &str {
        "response-compression"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        // Path matching: skip early if path doesn't match.
        if !self.is_matching_path(req.uri().path()) {
            return Ok(());
        }

        // Negotiate encoding from Accept-Encoding and stash in extensions.
        // The proxy handler bridges request extensions onto the response so
        // on_response can read the negotiated algorithm.
        let encoding = req
            .headers()
            .get(ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .and_then(|ae| self.negotiate(ae));

        if let Some(algo) = encoding {
            req.extensions_mut().insert(NegotiatedEncoding(algo));
        }
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let algo = match resp.extensions().get::<NegotiatedEncoding>() {
            Some(ne) => ne.0,
            None => return Ok(()),
        };

        // Already encoded upstream — don't double-compress.
        if resp.headers().contains_key(CONTENT_ENCODING) {
            return Ok(());
        }

        // Status code filter (Feature 55): skip 204, 304, etc.
        if !self.is_compressible_status(resp.status()) {
            return Ok(());
        }

        // Content-Type filter (Feature 55): includes + excludes.
        let compressible = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| self.is_compressible_type(ct))
            .unwrap_or(false);
        if !compressible {
            return Ok(());
        }

        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return Ok(()),
        };

        if bytes.len() < self.min_body_size {
            *resp.body_mut() = Body::from(bytes);
            return Ok(());
        }

        // Compression is CPU-bound and can take milliseconds on large bodies.
        // Running it inline blocks the tokio worker (and therefore every other
        // task scheduled on it). Offload to the blocking pool. Cloning `bytes`
        // is O(1) — `bytes::Bytes` shares the underlying buffer — so we keep
        // the original for the "didn't help" comparison below.
        let input = bytes.clone();
        let gzip_level = self.gzip_level;
        let brotli_level = self.brotli_level;
        let zstd_level = self.zstd_level;
        let compress_res = tokio::task::spawn_blocking(
            move || -> Result<(Vec<u8>, &'static str), String> {
                match algo {
                    CompressionAlgo::Gzip => {
                        let mut enc = flate2::write::GzEncoder::new(
                            Vec::with_capacity(input.len() / 2),
                            flate2::Compression::new(gzip_level),
                        );
                        enc.write_all(&input).map_err(|e| format!("gzip compress: {e}"))?;
                        let out = enc.finish().map_err(|e| format!("gzip finish: {e}"))?;
                        Ok((out, "gzip"))
                    }
                    CompressionAlgo::Brotli => {
                        let mut out = Vec::with_capacity(input.len() / 2);
                        {
                            let mut writer =
                                brotli::CompressorWriter::new(&mut out, 4096, brotli_level, 22);
                            writer
                                .write_all(&input)
                                .map_err(|e| format!("brotli compress: {e}"))?;
                        }
                        Ok((out, "br"))
                    }
                    CompressionAlgo::Zstd => {
                        let out = zstd::encode_all(input.as_ref(), zstd_level)
                            .map_err(|e| format!("zstd compress: {e}"))?;
                        Ok((out, "zstd"))
                    }
                }
            },
        )
        .await;
        let (compressed, encoding_name) = match compress_res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(PluginError::Internal(e)),
            Err(e) => {
                // Blocking task panicked/cancelled — fall back to the
                // uncompressed body rather than failing the response.
                tracing::warn!(error = %e, "compression task failed; sending uncompressed");
                *resp.body_mut() = Body::from(bytes);
                return Ok(());
            }
        };

        if compressed.len() >= bytes.len() {
            *resp.body_mut() = Body::from(bytes);
            return Ok(());
        }

        resp.headers_mut()
            .insert(CONTENT_ENCODING, HeaderValue::from_static(encoding_name));
        resp.headers_mut().remove(CONTENT_LENGTH);
        resp.headers_mut()
            .append(VARY, HeaderValue::from_static("Accept-Encoding"));
        *resp.body_mut() = Body::from(compressed);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_plugin() -> ResponseCompressionPlugin {
        ResponseCompressionPlugin::from_config(&serde_json::json!({})).unwrap()
    }

    fn plugin_with(cfg: serde_json::Value) -> ResponseCompressionPlugin {
        ResponseCompressionPlugin::from_config(&cfg).unwrap()
    }

    // ── minimum_length / min_body_size (Feature 54) ─────────────────

    #[test]
    fn default_min_body_size_is_256() {
        let p = default_plugin();
        assert_eq!(p.min_body_size, 256);
    }

    #[test]
    fn minimum_length_config_key() {
        let p = plugin_with(serde_json::json!({ "minimum_length": 1024 }));
        assert_eq!(p.min_body_size, 1024);
    }

    #[test]
    fn min_body_size_config_key() {
        let p = plugin_with(serde_json::json!({ "min_body_size": 512 }));
        assert_eq!(p.min_body_size, 512);
    }

    #[test]
    fn minimum_length_takes_precedence_over_min_body_size() {
        // When both are present, minimum_length (Caddy-style) wins.
        let p = plugin_with(serde_json::json!({
            "minimum_length": 2048,
            "min_body_size": 512
        }));
        assert_eq!(p.min_body_size, 2048);
    }

    #[test]
    fn minimum_length_zero_means_compress_everything() {
        let p = plugin_with(serde_json::json!({ "minimum_length": 0 }));
        assert_eq!(p.min_body_size, 0);
    }

    // ── Content-Type matching (Feature 55) ──────────────────────────

    #[test]
    fn default_content_types_match_text() {
        let p = default_plugin();
        assert!(p.is_compressible_type("text/html"));
        assert!(p.is_compressible_type("text/css"));
        assert!(p.is_compressible_type("text/plain; charset=utf-8"));
        assert!(p.is_compressible_type("application/json"));
        assert!(p.is_compressible_type("application/xml"));
        assert!(p.is_compressible_type("image/svg+xml"));
    }

    #[test]
    fn default_content_types_skip_binary() {
        let p = default_plugin();
        assert!(!p.is_compressible_type("image/png"));
        assert!(!p.is_compressible_type("application/octet-stream"));
        assert!(!p.is_compressible_type("video/mp4"));
    }

    #[test]
    fn custom_content_types() {
        let p = plugin_with(serde_json::json!({
            "content_types": ["application/wasm", "font/"]
        }));
        assert!(p.is_compressible_type("application/wasm"));
        assert!(p.is_compressible_type("font/woff2"));
        assert!(!p.is_compressible_type("text/html")); // not in custom list
    }

    #[test]
    fn exclude_content_types_override_includes() {
        let p = plugin_with(serde_json::json!({
            "exclude_content_types": ["application/json"]
        }));
        // text/html still matches the default include list
        assert!(p.is_compressible_type("text/html"));
        // application/json is excluded even though it's in the default include list
        assert!(!p.is_compressible_type("application/json"));
    }

    #[test]
    fn exclude_content_types_prefix_pattern() {
        let p = plugin_with(serde_json::json!({
            "exclude_content_types": ["image/"]
        }));
        assert!(!p.is_compressible_type("image/svg+xml")); // excluded
        assert!(p.is_compressible_type("text/plain"));
    }

    // ── Status code matching (Feature 55) ───────────────────────────

    #[test]
    fn default_status_matches_200() {
        let p = default_plugin();
        assert!(p.is_compressible_status(StatusCode::OK));
        assert!(p.is_compressible_status(StatusCode::CREATED));
    }

    #[test]
    fn default_status_skips_204_and_304() {
        let p = default_plugin();
        assert!(!p.is_compressible_status(StatusCode::NO_CONTENT)); // 204
        assert!(!p.is_compressible_status(StatusCode::NOT_MODIFIED)); // 304
    }

    #[test]
    fn default_status_skips_1xx_4xx_5xx() {
        let p = default_plugin();
        assert!(!p.is_compressible_status(StatusCode::CONTINUE)); // 100
        assert!(!p.is_compressible_status(StatusCode::NOT_FOUND)); // 404
        assert!(!p.is_compressible_status(StatusCode::INTERNAL_SERVER_ERROR)); // 500
    }

    #[test]
    fn custom_match_status_single() {
        let p = plugin_with(serde_json::json!({
            "match_status": ["200", "404"]
        }));
        assert!(p.is_compressible_status(StatusCode::OK));
        assert!(p.is_compressible_status(StatusCode::NOT_FOUND));
        assert!(!p.is_compressible_status(StatusCode::CREATED));
    }

    #[test]
    fn custom_match_status_range() {
        let p = plugin_with(serde_json::json!({
            "match_status": ["200-299", "400-499"]
        }));
        assert!(p.is_compressible_status(StatusCode::OK));
        assert!(p.is_compressible_status(StatusCode::NO_CONTENT)); // 204 included now
        assert!(p.is_compressible_status(StatusCode::BAD_REQUEST)); // 400
        assert!(!p.is_compressible_status(StatusCode::INTERNAL_SERVER_ERROR)); // 500
    }

    #[test]
    fn match_status_includes_error_responses() {
        // Operator can opt into compressing error bodies.
        let p = plugin_with(serde_json::json!({
            "match_status": ["200-599"]
        }));
        assert!(p.is_compressible_status(StatusCode::OK));
        assert!(p.is_compressible_status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    // ── Path matching (Feature 55) ──────────────────────────────────

    #[test]
    fn default_matches_all_paths() {
        let p = default_plugin();
        assert!(p.is_matching_path("/api/data"));
        assert!(p.is_matching_path("/static/app.js"));
    }

    #[test]
    fn custom_match_paths() {
        let p = plugin_with(serde_json::json!({
            "match_paths": ["/api/", "/docs/"]
        }));
        assert!(p.is_matching_path("/api/users"));
        assert!(p.is_matching_path("/docs/intro"));
        assert!(!p.is_matching_path("/static/app.js"));
    }

    // ── Negotiation ─────────────────────────────────────────────────

    #[test]
    fn negotiate_prefers_first_client_match() {
        let p = default_plugin(); // zstd, brotli, gzip
                                  // Equal q-values: iteration picks the first client-listed algo
                                  // that exists in the server's supported set.
        let algo = p.negotiate("gzip, br, zstd").unwrap();
        assert_eq!(algo, CompressionAlgo::Gzip);
    }

    #[test]
    fn negotiate_server_order_via_qvalue() {
        let p = default_plugin(); // zstd, brotli, gzip
                                  // When q-values differ, highest q wins — zstd gets picked.
        let algo = p.negotiate("gzip;q=0.5, br;q=0.8, zstd;q=1.0").unwrap();
        assert_eq!(algo, CompressionAlgo::Zstd);
    }

    #[test]
    fn negotiate_respects_client_qvalue() {
        let p = default_plugin();
        // Client strongly prefers gzip.
        let algo = p.negotiate("gzip;q=1.0, zstd;q=0.5, br;q=0.8").unwrap();
        assert_eq!(algo, CompressionAlgo::Gzip);
    }

    #[test]
    fn negotiate_returns_none_when_no_match() {
        let p = plugin_with(serde_json::json!({ "algorithms": ["zstd"] }));
        assert!(p.negotiate("gzip, br").is_none());
    }

    #[test]
    fn negotiate_skips_qvalue_zero() {
        let p = default_plugin();
        let algo = p.negotiate("zstd;q=0, br;q=0.5, gzip;q=0.3").unwrap();
        // zstd has q=0 so it's excluded; br is next best.
        assert_eq!(algo, CompressionAlgo::Brotli);
    }

    // ── Algorithm selection ──────────────────────────────────────────

    #[test]
    fn default_algorithms() {
        let p = default_plugin();
        assert_eq!(
            p.algorithms,
            vec![
                CompressionAlgo::Zstd,
                CompressionAlgo::Brotli,
                CompressionAlgo::Gzip,
            ]
        );
    }

    #[test]
    fn custom_algorithms() {
        let p = plugin_with(serde_json::json!({ "algorithms": ["gzip"] }));
        assert_eq!(p.algorithms, vec![CompressionAlgo::Gzip]);
        assert!(p.negotiate("br").is_none());
        assert_eq!(p.negotiate("gzip").unwrap(), CompressionAlgo::Gzip);
    }

    #[test]
    fn algorithm_aliases() {
        let p = plugin_with(serde_json::json!({
            "algorithms": ["gz", "brotli", "zstandard"]
        }));
        assert_eq!(
            p.algorithms,
            vec![
                CompressionAlgo::Gzip,
                CompressionAlgo::Brotli,
                CompressionAlgo::Zstd,
            ]
        );
    }

    // ── Compression levels ──────────────────────────────────────────

    #[test]
    fn default_compression_levels() {
        let p = default_plugin();
        assert_eq!(p.gzip_level, 6);
        assert_eq!(p.zstd_level, 3);
        assert_eq!(p.brotli_level, 4);
    }

    #[test]
    fn custom_compression_levels() {
        let p = plugin_with(serde_json::json!({
            "gzip_level": 9,
            "zstd_level": 5,
            "brotli_level": 11
        }));
        assert_eq!(p.gzip_level, 9);
        assert_eq!(p.zstd_level, 5);
        assert_eq!(p.brotli_level, 11);
    }

    // ── StatusRange parsing ─────────────────────────────────────────

    #[test]
    fn parse_status_range_single() {
        assert_eq!(parse_status_range("200"), Some(StatusRange::Single(200)));
    }

    #[test]
    fn parse_status_range_range() {
        assert_eq!(
            parse_status_range("200-299"),
            Some(StatusRange::Range(200, 299))
        );
    }

    #[test]
    fn parse_status_range_invalid() {
        assert_eq!(parse_status_range("abc"), None);
        assert_eq!(parse_status_range(""), None);
    }

    #[test]
    fn status_range_contains() {
        assert!(StatusRange::Single(200).contains(200));
        assert!(!StatusRange::Single(200).contains(201));
        assert!(StatusRange::Range(200, 299).contains(200));
        assert!(StatusRange::Range(200, 299).contains(250));
        assert!(StatusRange::Range(200, 299).contains(299));
        assert!(!StatusRange::Range(200, 299).contains(300));
    }

    // ── Full config round-trip ──────────────────────────────────────

    #[test]
    fn full_config_deserializes() {
        let p = plugin_with(serde_json::json!({
            "algorithms": ["br", "gzip"],
            "minimum_length": 4096,
            "content_types": ["text/html", "application/json"],
            "exclude_content_types": ["application/json"],
            "match_status": ["200", "201-299"],
            "match_paths": ["/api/"],
            "gzip_level": 4,
            "zstd_level": 1,
            "brotli_level": 6
        }));
        assert_eq!(p.algorithms.len(), 2);
        assert_eq!(p.min_body_size, 4096);
        assert_eq!(p.content_types.len(), 2);
        assert_eq!(p.exclude_content_types.len(), 1);
        assert_eq!(p.match_status.len(), 2);
        assert_eq!(p.match_paths.len(), 1);
        assert!(!p.is_compressible_type("application/json")); // excluded
        assert!(p.is_compressible_type("text/html"));
        assert!(p.is_compressible_status(StatusCode::OK));
        assert!(!p.is_compressible_status(StatusCode::NOT_FOUND));
    }
}
