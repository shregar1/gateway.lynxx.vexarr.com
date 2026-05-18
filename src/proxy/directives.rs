//! Caddy-style routing directives: `handle`, `handle_path`, `respond`,
//! `invoke`, `try_files`, and `uri` manipulation.
//!
//! These are evaluated in the proxy handler *after* the basic route match
//! but *before* the upstream call. They compose to build Caddy-like
//! "first-match" routing groups without needing a full Caddyfile parser.

use crate::proxy::matchers::{self, Matcher, MatcherContext, MatcherRegistry};
use axum::body::Body;
use axum::http::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────
// handle / handle_path (mutually-exclusive first-match groups)
// ─────────────────────────────────────────────────────────────────────────

/// A `handle` block: first matcher that passes wins; the rest are skipped
/// (mutual exclusion). Each block carries an optional path-strip (for
/// `handle_path` semantics) and a matcher set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleBlock {
    /// Named matcher reference (e.g. `"@api"`). Empty = always matches.
    #[serde(default)]
    pub matcher_ref: Option<String>,
    /// Inline matchers. ANDed together. Empty + no matcher_ref = always matches.
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    /// When set, strip this path prefix from the URI before forwarding
    /// (`handle_path` semantics).
    #[serde(default)]
    pub strip_path_prefix: Option<String>,
    /// The action to take when this block matches.
    pub action: HandleAction,
}

/// What a `handle` block does when matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandleAction {
    /// Proxy to the route's normal upstream (default behaviour).
    Proxy,
    /// Return a static response without hitting an upstream.
    Respond {
        status: u16,
        body: String,
        #[serde(default)]
        headers: std::collections::HashMap<String, String>,
    },
    /// Invoke a named route by name (cross-reference).
    Invoke { route_name: String },
    /// Rewrite the URI before proxying.
    Rewrite { uri: String },
}

/// Evaluate a chain of handle blocks against the current request.
/// Returns the action from the **first** matching block, or `None`
/// if none match (fall through to default proxy behaviour).
pub fn evaluate_handles(
    blocks: &[HandleBlock],
    ctx: &MatcherContext,
    registry: &MatcherRegistry,
) -> Option<(HandleAction, Option<String>)> {
    for block in blocks {
        let mut passes = true;
        // Check matcher_ref first.
        if let Some(ref name) = block.matcher_ref {
            let name = name.trim_start_matches('@');
            if let Some(named_matchers) = registry.get(name) {
                if !matchers::evaluate_all(named_matchers, ctx) {
                    passes = false;
                }
            } else {
                // Unknown matcher ref → skip.
                passes = false;
            }
        }
        // Then check inline matchers.
        if passes && !block.matchers.is_empty() && !matchers::evaluate_all(&block.matchers, ctx) {
            passes = false;
        }
        if passes {
            return Some((block.action.clone(), block.strip_path_prefix.clone()));
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────
// respond (static response without upstream)
// ─────────────────────────────────────────────────────────────────────────

/// Build a static response. Used by both the `respond` directive and
/// the `HandleAction::Respond` variant.
pub fn build_static_response(
    status: u16,
    body: &str,
    extra_headers: &std::collections::HashMap<String, String>,
) -> Response<Body> {
    let st = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = st;
    for (k, v) in extra_headers {
        if let (Ok(name), Ok(val)) = (
            axum::http::header::HeaderName::from_bytes(k.as_bytes()),
            v.parse::<axum::http::HeaderValue>(),
        ) {
            resp.headers_mut().insert(name, val);
        }
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────
// try_files (rewrite to first existing file on disk)
// ─────────────────────────────────────────────────────────────────────────

/// try_files candidate. Each entry is either:
/// - A literal path relative to `root` (may contain `{path}` placeholder)
/// - A fallback URI starting with `=` (e.g. `=404`) for a status code
/// - A fallback path prefixed with `/` treated as a rewrite target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TryFilesConfig {
    /// Document root on disk.
    pub root: String,
    /// Ordered list of file paths to try. `{path}` is replaced with the
    /// request URI path. `{path}/` appends a trailing slash. The last
    /// entry is the fallback.
    /// Examples: `["{path}", "{path}/index.html", "/index.html"]`
    pub files: Vec<String>,
}

/// Evaluate `try_files` — returns the first existing file's rewritten
/// path, or the fallback entry.
pub async fn try_files_rewrite(config: &TryFilesConfig, request_path: &str) -> TryFilesResult {
    let root = Path::new(&config.root);
    let clean_path = request_path.trim_start_matches('/');

    for (i, candidate) in config.files.iter().enumerate() {
        let is_last = i == config.files.len() - 1;

        // Status code fallback: `=404`.
        if let Some(code_str) = candidate.strip_prefix('=') {
            let code: u16 = code_str.parse().unwrap_or(404);
            return TryFilesResult::StatusCode(code);
        }

        // Expand `{path}` placeholder.
        let expanded = candidate
            .replace("{path}", clean_path)
            .replace("{path.dir}", {
                // Directory portion of the path.
                let p = std::path::Path::new(clean_path);
                p.parent().map(|pp| pp.to_str().unwrap_or("")).unwrap_or("")
            });

        let file_path = root.join(expanded.trim_start_matches('/'));

        if is_last {
            // Last entry is always the fallback rewrite target (not checked on disk).
            return TryFilesResult::Rewrite(candidate.replace("{path}", request_path));
        }

        if file_path.exists() && file_path.is_file() {
            // Return the rewritten URI (relative to root).
            let rewritten = format!(
                "/{}",
                file_path
                    .strip_prefix(root)
                    .unwrap_or(&file_path)
                    .to_str()
                    .unwrap_or(request_path)
            );
            return TryFilesResult::Rewrite(rewritten);
        }
    }

    TryFilesResult::NotFound
}

#[derive(Debug)]
pub enum TryFilesResult {
    /// Rewrite the request path to this URI.
    Rewrite(String),
    /// Return this status code directly.
    StatusCode(u16),
    /// No candidate matched.
    NotFound,
}

// ─────────────────────────────────────────────────────────────────────────
// uri manipulation (strip prefix/suffix, replace, path-escape)
// ─────────────────────────────────────────────────────────────────────────

/// URI manipulation directives applied before proxying.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UriDirective {
    /// Strip a path prefix: `/api/v1/users` → `/users` with prefix `/api/v1`.
    StripPrefix { prefix: String },
    /// Strip a path suffix: `/users.json` → `/users` with suffix `.json`.
    StripSuffix { suffix: String },
    /// Replace a substring in the path.
    Replace { search: String, replace: String },
    /// Percent-encode the path (path-escape). Useful when the upstream
    /// requires encoded paths.
    PathEscape,
    /// Replace the entire path with a new value. `{path}` placeholder
    /// expands to the original path.
    Rewrite { to: String },
    /// Prepend a prefix to the path: `/users` → `/api/users` with prefix `/api`.
    AddPrefix { prefix: String },
    /// Regex-based path replacement with capture-group support.
    /// E.g. pattern `^/api/(.*)` with replacement `/v2/$1`.
    ReplacePathRegex {
        pattern: String,
        replacement: String,
    },
    /// Strip the first regex-matched prefix. Each entry is a regex pattern;
    /// the first one that matches the start of the path wins.
    StripPrefixRegex { patterns: Vec<String> },
}

/// Apply a sequence of URI directives to a path, returning the transformed path.
pub fn apply_uri_directives(directives: &[UriDirective], path: &str) -> String {
    let mut result = path.to_string();
    for d in directives {
        result = match d {
            UriDirective::StripPrefix { prefix } => {
                if let Some(stripped) = result.strip_prefix(prefix.as_str()) {
                    if stripped.is_empty() {
                        "/".to_string()
                    } else if !stripped.starts_with('/') {
                        format!("/{stripped}")
                    } else {
                        stripped.to_string()
                    }
                } else {
                    result
                }
            }
            UriDirective::StripSuffix { suffix } => {
                if let Some(stripped) = result.strip_suffix(suffix.as_str()) {
                    if stripped.is_empty() {
                        "/".to_string()
                    } else {
                        stripped.to_string()
                    }
                } else {
                    result
                }
            }
            UriDirective::Replace { search, replace } => {
                result.replace(search.as_str(), replace.as_str())
            }
            UriDirective::PathEscape => {
                url::form_urlencoded::byte_serialize(result.as_bytes()).collect()
            }
            UriDirective::Rewrite { to } => to.replace("{path}", &result),
            UriDirective::AddPrefix { prefix } => {
                // Ensure no double slash between prefix and path.
                if result.starts_with('/') && prefix.ends_with('/') {
                    format!("{}{}", prefix, &result[1..])
                } else if !result.starts_with('/') && !prefix.ends_with('/') {
                    format!("{prefix}/{result}")
                } else {
                    format!("{prefix}{result}")
                }
            }
            UriDirective::ReplacePathRegex {
                pattern,
                replacement,
            } => {
                match regex::Regex::new(pattern) {
                    Ok(re) => re.replace_all(&result, replacement.as_str()).into_owned(),
                    Err(_) => result, // invalid regex — pass through unchanged
                }
            }
            UriDirective::StripPrefixRegex { patterns } => {
                let mut stripped = result.clone();
                for pat in patterns {
                    if let Ok(re) = regex::Regex::new(pat) {
                        if let Some(m) = re.find(&stripped) {
                            if m.start() == 0 {
                                let remainder = &stripped[m.end()..];
                                stripped = if remainder.is_empty() {
                                    "/".to_string()
                                } else if !remainder.starts_with('/') {
                                    format!("/{remainder}")
                                } else {
                                    remainder.to_string()
                                };
                                break; // first match wins
                            }
                        }
                    }
                }
                stripped
            }
        };
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────
// intercept (rewrite downstream responses conditionally)
// ─────────────────────────────────────────────────────────────────────────

/// Response interception rule. Evaluated after the upstream responds.
/// When matched, can rewrite the status code, replace/append headers,
/// or substitute the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    /// Match when the upstream returned one of these status codes.
    /// Empty = match all.
    #[serde(default)]
    pub match_status: Vec<u16>,
    /// Match when upstream response contains this header.
    #[serde(default)]
    pub match_header: Option<String>,
    /// Action to perform on match.
    pub action: InterceptAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterceptAction {
    /// Replace the response status code.
    SetStatus { status: u16 },
    /// Replace the response body.
    SetBody {
        body: String,
        #[serde(default)]
        content_type: Option<String>,
    },
    /// Add or overwrite response headers.
    SetHeaders {
        headers: std::collections::HashMap<String, String>,
    },
    /// Replace status + body + headers entirely.
    Replace {
        status: u16,
        body: String,
        #[serde(default)]
        headers: std::collections::HashMap<String, String>,
    },
}

/// Apply intercept rules to a mutable response in-place.
pub fn apply_intercept_rules(
    rules: &[InterceptRule],
    status: StatusCode,
    resp_headers: &axum::http::HeaderMap,
) -> Option<InterceptAction> {
    for rule in rules {
        // Status match.
        if !rule.match_status.is_empty() && !rule.match_status.contains(&status.as_u16()) {
            continue;
        }
        // Header match.
        if let Some(ref hdr) = rule.match_header {
            if !resp_headers.contains_key(hdr.as_str()) {
                continue;
            }
        }
        return Some(rule.action.clone());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI directives ──

    #[test]
    fn strip_prefix() {
        let directives = vec![UriDirective::StripPrefix {
            prefix: "/api/v1".to_string(),
        }];
        assert_eq!(apply_uri_directives(&directives, "/api/v1/users"), "/users");
    }

    #[test]
    fn strip_prefix_root() {
        let directives = vec![UriDirective::StripPrefix {
            prefix: "/api".to_string(),
        }];
        assert_eq!(apply_uri_directives(&directives, "/api"), "/");
    }

    #[test]
    fn strip_suffix() {
        let directives = vec![UriDirective::StripSuffix {
            suffix: ".json".to_string(),
        }];
        assert_eq!(apply_uri_directives(&directives, "/users.json"), "/users");
    }

    #[test]
    fn replace_in_path() {
        let directives = vec![UriDirective::Replace {
            search: "/v1/".to_string(),
            replace: "/v2/".to_string(),
        }];
        assert_eq!(
            apply_uri_directives(&directives, "/api/v1/users"),
            "/api/v2/users"
        );
    }

    #[test]
    fn path_escape() {
        let directives = vec![UriDirective::PathEscape];
        let result = apply_uri_directives(&directives, "/path with spaces");
        assert!(result.contains("%20") || result.contains('+'));
    }

    #[test]
    fn rewrite_with_placeholder() {
        let directives = vec![UriDirective::Rewrite {
            to: "/new{path}".to_string(),
        }];
        assert_eq!(
            apply_uri_directives(&directives, "/old/page"),
            "/new/old/page"
        );
    }

    #[test]
    fn chained_directives() {
        let directives = vec![
            UriDirective::StripPrefix {
                prefix: "/api".to_string(),
            },
            UriDirective::Replace {
                search: "/v1".to_string(),
                replace: "/v2".to_string(),
            },
        ];
        assert_eq!(
            apply_uri_directives(&directives, "/api/v1/users"),
            "/v2/users"
        );
    }

    #[test]
    fn no_match_strip_leaves_unchanged() {
        let directives = vec![UriDirective::StripPrefix {
            prefix: "/xyz".to_string(),
        }];
        assert_eq!(apply_uri_directives(&directives, "/api/test"), "/api/test");
    }

    // ── Handle blocks ──

    #[test]
    fn first_match_wins() {
        let blocks = vec![
            HandleBlock {
                matcher_ref: None,
                matchers: vec![Matcher::PathPrefix {
                    prefix: "/api".to_string(),
                }],
                strip_path_prefix: None,
                action: HandleAction::Respond {
                    status: 200,
                    body: "api".to_string(),
                    headers: Default::default(),
                },
            },
            HandleBlock {
                matcher_ref: None,
                matchers: vec![Matcher::PathPrefix {
                    prefix: "/web".to_string(),
                }],
                strip_path_prefix: None,
                action: HandleAction::Respond {
                    status: 200,
                    body: "web".to_string(),
                    headers: Default::default(),
                },
            },
        ];
        let ctx = MatcherContext {
            path: "/api/users",
            method: "GET",
            host: None,
            remote_ip: None,
            client_ip: None,
            headers: None,
            query_string: None,
            scheme: None,
            vars: &Default::default(),
        };
        let reg = MatcherRegistry::new();
        let result = evaluate_handles(&blocks, &ctx, &reg);
        assert!(result.is_some());
        match result.unwrap().0 {
            HandleAction::Respond { body, .. } => assert_eq!(body, "api"),
            _ => panic!("expected Respond"),
        }
    }

    #[test]
    fn handle_path_strips_prefix() {
        let blocks = vec![HandleBlock {
            matcher_ref: None,
            matchers: vec![Matcher::PathPrefix {
                prefix: "/api".to_string(),
            }],
            strip_path_prefix: Some("/api".to_string()),
            action: HandleAction::Proxy,
        }];
        let ctx = MatcherContext {
            path: "/api/users",
            method: "GET",
            host: None,
            remote_ip: None,
            client_ip: None,
            headers: None,
            query_string: None,
            scheme: None,
            vars: &Default::default(),
        };
        let reg = MatcherRegistry::new();
        let result = evaluate_handles(&blocks, &ctx, &reg);
        assert!(result.is_some());
        let (_, strip) = result.unwrap();
        assert_eq!(strip, Some("/api".to_string()));
    }

    #[test]
    fn no_match_returns_none() {
        let blocks = vec![HandleBlock {
            matcher_ref: None,
            matchers: vec![Matcher::PathPrefix {
                prefix: "/api".to_string(),
            }],
            strip_path_prefix: None,
            action: HandleAction::Proxy,
        }];
        let ctx = MatcherContext {
            path: "/web/page",
            method: "GET",
            host: None,
            remote_ip: None,
            client_ip: None,
            headers: None,
            query_string: None,
            scheme: None,
            vars: &Default::default(),
        };
        let reg = MatcherRegistry::new();
        assert!(evaluate_handles(&blocks, &ctx, &reg).is_none());
    }

    #[test]
    fn named_matcher_ref_in_handle() {
        let mut reg = MatcherRegistry::new();
        reg.register(
            "internal".to_string(),
            vec![Matcher::RemoteIp {
                ranges: vec!["10.0.0.0/8".to_string()],
            }],
        );
        let blocks = vec![HandleBlock {
            matcher_ref: Some("@internal".to_string()),
            matchers: vec![],
            strip_path_prefix: None,
            action: HandleAction::Respond {
                status: 200,
                body: "internal".to_string(),
                headers: Default::default(),
            },
        }];
        let ctx = MatcherContext {
            path: "/",
            method: "GET",
            host: None,
            remote_ip: Some("10.0.0.5".parse().unwrap()),
            client_ip: None,
            headers: None,
            query_string: None,
            scheme: None,
            vars: &Default::default(),
        };
        assert!(evaluate_handles(&blocks, &ctx, &reg).is_some());
    }

    // ── Static respond ──

    #[test]
    fn build_static_response_sets_status() {
        let headers = std::collections::HashMap::new();
        let resp = build_static_response(201, "created", &headers);
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[test]
    fn build_static_response_adds_headers() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-custom".to_string(), "value".to_string());
        let resp = build_static_response(200, "ok", &headers);
        assert_eq!(resp.headers().get("x-custom").unwrap(), "value");
    }

    // ── Intercept ──

    #[test]
    fn intercept_matches_status() {
        let rules = vec![InterceptRule {
            match_status: vec![502, 503],
            match_header: None,
            action: InterceptAction::SetStatus { status: 503 },
        }];
        let headers = axum::http::HeaderMap::new();
        let result = apply_intercept_rules(&rules, StatusCode::BAD_GATEWAY, &headers);
        assert!(result.is_some());
    }

    #[test]
    fn intercept_no_match() {
        let rules = vec![InterceptRule {
            match_status: vec![502],
            match_header: None,
            action: InterceptAction::SetStatus { status: 503 },
        }];
        let headers = axum::http::HeaderMap::new();
        let result = apply_intercept_rules(&rules, StatusCode::OK, &headers);
        assert!(result.is_none());
    }

    #[test]
    fn intercept_header_match() {
        let rules = vec![InterceptRule {
            match_status: vec![],
            match_header: Some("x-backend-error".to_string()),
            action: InterceptAction::SetBody {
                body: "error page".to_string(),
                content_type: Some("text/html".to_string()),
            },
        }];
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-backend-error", "true".parse().unwrap());
        let result = apply_intercept_rules(&rules, StatusCode::OK, &headers);
        assert!(result.is_some());
    }

    // ── try_files ──

    #[tokio::test]
    async fn try_files_fallback() {
        let config = TryFilesConfig {
            root: "/nonexistent/root".to_string(),
            files: vec![
                "{path}".to_string(),
                "{path}/index.html".to_string(),
                "/index.html".to_string(), // fallback
            ],
        };
        let result = try_files_rewrite(&config, "/some/page").await;
        match result {
            TryFilesResult::Rewrite(path) => assert_eq!(path, "/index.html"),
            _ => panic!("expected Rewrite fallback"),
        }
    }

    #[tokio::test]
    async fn try_files_status_code_fallback() {
        let config = TryFilesConfig {
            root: "/nonexistent/root".to_string(),
            files: vec!["{path}".to_string(), "=404".to_string()],
        };
        let result = try_files_rewrite(&config, "/missing").await;
        match result {
            TryFilesResult::StatusCode(code) => assert_eq!(code, 404),
            _ => panic!("expected StatusCode"),
        }
    }

    // ── AddPrefix ──

    #[test]
    fn add_prefix_simple() {
        let directives = vec![UriDirective::AddPrefix {
            prefix: "/api".to_string(),
        }];
        assert_eq!(apply_uri_directives(&directives, "/users"), "/api/users");
    }

    #[test]
    fn add_prefix_no_double_slash() {
        let directives = vec![UriDirective::AddPrefix {
            prefix: "/api/".to_string(),
        }];
        // prefix ends with '/' and path starts with '/' — no double slash
        assert_eq!(apply_uri_directives(&directives, "/users"), "/api/users");
    }

    #[test]
    fn add_prefix_root_path() {
        let directives = vec![UriDirective::AddPrefix {
            prefix: "/v2".to_string(),
        }];
        assert_eq!(apply_uri_directives(&directives, "/"), "/v2/");
    }

    // ── ReplacePathRegex ──

    #[test]
    fn replace_path_regex_capture_group() {
        let directives = vec![UriDirective::ReplacePathRegex {
            pattern: r"^/api/(.*)".to_string(),
            replacement: "/v2/$1".to_string(),
        }];
        assert_eq!(
            apply_uri_directives(&directives, "/api/users/123"),
            "/v2/users/123"
        );
    }

    #[test]
    fn replace_path_regex_no_match() {
        let directives = vec![UriDirective::ReplacePathRegex {
            pattern: r"^/api/(.*)".to_string(),
            replacement: "/v2/$1".to_string(),
        }];
        assert_eq!(apply_uri_directives(&directives, "/web/page"), "/web/page");
    }

    #[test]
    fn replace_path_regex_multiple_groups() {
        let directives = vec![UriDirective::ReplacePathRegex {
            pattern: r"^/(\w+)/(\w+)$".to_string(),
            replacement: "/$2/$1".to_string(),
        }];
        assert_eq!(
            apply_uri_directives(&directives, "/users/admin"),
            "/admin/users"
        );
    }

    // ── StripPrefixRegex ──

    #[test]
    fn strip_prefix_regex_first_match_wins() {
        let directives = vec![UriDirective::StripPrefixRegex {
            patterns: vec![r"/api/v\d+".to_string(), r"/api".to_string()],
        }];
        // The first pattern matches "/api/v1", stripping it
        assert_eq!(apply_uri_directives(&directives, "/api/v1/users"), "/users");
    }

    #[test]
    fn strip_prefix_regex_fallback_to_second() {
        let directives = vec![UriDirective::StripPrefixRegex {
            patterns: vec![r"/admin".to_string(), r"/api".to_string()],
        }];
        // First pattern doesn't match, second does
        assert_eq!(apply_uri_directives(&directives, "/api/users"), "/users");
    }

    #[test]
    fn strip_prefix_regex_no_match() {
        let directives = vec![UriDirective::StripPrefixRegex {
            patterns: vec![r"/admin".to_string()],
        }];
        assert_eq!(
            apply_uri_directives(&directives, "/api/users"),
            "/api/users"
        );
    }

    #[test]
    fn strip_prefix_regex_entire_path() {
        let directives = vec![UriDirective::StripPrefixRegex {
            patterns: vec![r"/api".to_string()],
        }];
        assert_eq!(apply_uri_directives(&directives, "/api"), "/");
    }
}
