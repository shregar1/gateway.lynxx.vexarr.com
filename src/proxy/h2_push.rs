//! HTTP/2 server push support.
//!
//! Mirrors Caddy's `push` directive: on an HTML response the gateway can
//! send PUSH_PROMISE frames for resources that the client will likely
//! need, eliminating one round-trip per pushed asset.
//!
//! Implementation is header-based: the upstream (or a plugin) sets
//! `Link: </style.css>; rel=preload; as=style` headers, and this
//! module extracts them into `PushPromise` records. The actual push
//! happens at the connection layer — hyper exposes a `send_push_promise`
//! API on HTTP/2 connections.
//!
//! When the client is HTTP/1.1 or sends an `Accept-Push-Policy: none`
//! header, pushes are silently skipped.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

/// Configuration for the push directive on a route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushConfig {
    /// Resources to always push (static list).
    /// E.g. `["/css/main.css", "/js/app.js"]`
    #[serde(default)]
    pub resources: Vec<PushResource>,
    /// When true, also extract `Link: <...>; rel=preload` headers from
    /// the upstream response and push those resources.
    #[serde(default = "default_true")]
    pub link_header: bool,
    /// Only push for responses with these content types.
    /// Default: `["text/html"]`.
    #[serde(default = "default_push_content_types")]
    pub content_types: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_push_content_types() -> Vec<String> {
    vec!["text/html".to_string()]
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            resources: Vec::new(),
            link_header: true,
            content_types: default_push_content_types(),
        }
    }
}

/// A single resource to push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResource {
    /// URI path of the resource.
    pub path: String,
    /// Optional `as` attribute for the push promise.
    #[serde(default)]
    pub as_type: Option<String>,
}

/// A parsed push promise ready for the HTTP/2 layer.
#[derive(Debug, Clone)]
pub struct PushPromise {
    pub path: String,
    pub as_type: Option<String>,
}

/// Extract push promises from a response.
///
/// 1. Adds any static resources from `config.resources`.
/// 2. Parses `Link` headers with `rel=preload`.
///
/// Only produces promises when the response content-type matches
/// `config.content_types`.
pub fn extract_push_promises(
    config: &PushConfig,
    response_headers: &HeaderMap,
) -> Vec<PushPromise> {
    // Check content-type matches.
    let ct = response_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !config
        .content_types
        .iter()
        .any(|t| ct.starts_with(t.as_str()))
    {
        return Vec::new();
    }

    let mut promises = Vec::new();

    // Static resources.
    for res in &config.resources {
        promises.push(PushPromise {
            path: res.path.clone(),
            as_type: res.as_type.clone(),
        });
    }

    // Parse Link headers.
    if config.link_header {
        for link_val in response_headers.get_all("link") {
            if let Ok(s) = link_val.to_str() {
                for part in s.split(',') {
                    if let Some(promise) = parse_link_preload(part.trim()) {
                        promises.push(promise);
                    }
                }
            }
        }
    }

    promises
}

/// Parse a single `Link` header value like `</style.css>; rel=preload; as=style`.
fn parse_link_preload(link: &str) -> Option<PushPromise> {
    // Extract URI between < and >.
    let uri_start = link.find('<')? + 1;
    let uri_end = link.find('>')?;
    let uri = &link[uri_start..uri_end];

    // Check for rel=preload.
    let params = &link[uri_end + 1..];
    let has_preload = params
        .split(';')
        .map(|p| p.trim())
        .any(|p| p.eq_ignore_ascii_case("rel=preload"));

    if !has_preload {
        return None;
    }

    let as_type = params
        .split(';')
        .map(|p| p.trim())
        .find_map(|p| p.strip_prefix("as=").map(|v| v.trim().to_string()));

    Some(PushPromise {
        path: uri.to_string(),
        as_type,
    })
}

/// Check whether the client connection supports HTTP/2 push.
/// Push is not supported when:
/// - The connection is HTTP/1.x
/// - The client sent `Accept-Push-Policy: none`
pub fn client_supports_push(version: axum::http::Version, request_headers: &HeaderMap) -> bool {
    if version != axum::http::Version::HTTP_2 {
        return false;
    }
    // Respect the client's push preference.
    if let Some(policy) = request_headers.get("accept-push-policy") {
        if let Ok(v) = policy.to_str() {
            if v.eq_ignore_ascii_case("none") {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_link_preload_basic() {
        let result = parse_link_preload(r#"</style.css>; rel=preload; as=style"#);
        assert!(result.is_some());
        let p = result.unwrap();
        assert_eq!(p.path, "/style.css");
        assert_eq!(p.as_type.as_deref(), Some("style"));
    }

    #[test]
    fn parse_link_preload_no_as() {
        let result = parse_link_preload(r#"</app.js>; rel=preload"#);
        assert!(result.is_some());
        let p = result.unwrap();
        assert_eq!(p.path, "/app.js");
        assert!(p.as_type.is_none());
    }

    #[test]
    fn parse_link_not_preload() {
        let result = parse_link_preload(r#"</next>; rel=next"#);
        assert!(result.is_none());
    }

    #[test]
    fn extract_promises_from_headers() {
        let config = PushConfig {
            resources: vec![PushResource {
                path: "/static/base.css".to_string(),
                as_type: Some("style".to_string()),
            }],
            link_header: true,
            content_types: vec!["text/html".to_string()],
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8".parse().unwrap(),
        );
        headers.insert(
            "link",
            r#"</app.js>; rel=preload; as=script"#.parse().unwrap(),
        );
        let promises = extract_push_promises(&config, &headers);
        assert_eq!(promises.len(), 2);
        assert_eq!(promises[0].path, "/static/base.css");
        assert_eq!(promises[1].path, "/app.js");
    }

    #[test]
    fn skips_non_html_responses() {
        let config = PushConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let promises = extract_push_promises(&config, &headers);
        assert!(promises.is_empty());
    }

    #[test]
    fn client_push_support_h1() {
        let headers = HeaderMap::new();
        assert!(!client_supports_push(
            axum::http::Version::HTTP_11,
            &headers
        ));
    }

    #[test]
    fn client_push_support_h2() {
        let headers = HeaderMap::new();
        assert!(client_supports_push(axum::http::Version::HTTP_2, &headers));
    }

    #[test]
    fn client_push_policy_none() {
        let mut headers = HeaderMap::new();
        headers.insert("accept-push-policy", "none".parse().unwrap());
        assert!(!client_supports_push(axum::http::Version::HTTP_2, &headers));
    }

    #[test]
    fn multiple_link_headers() {
        let config = PushConfig {
            resources: vec![],
            link_header: true,
            content_types: vec!["text/html".to_string()],
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/html".parse().unwrap(),
        );
        // Comma-separated links in a single header value.
        headers.insert(
            "link",
            r#"</a.css>; rel=preload; as=style, </b.js>; rel=preload; as=script"#
                .parse()
                .unwrap(),
        );
        let promises = extract_push_promises(&config, &headers);
        assert_eq!(promises.len(), 2);
    }
}
