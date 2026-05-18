//! Response interception: conditionally handle or copy upstream responses
//! based on status code or header patterns. Mirrors Caddy's
//! `handle_response` / `copy_response` directives.
//!
//! A `ResponseHandler` is evaluated after the upstream response arrives but
//! before the plugin chain runs. If a handler matches, it can:
//!   1. Replace the response body + status entirely (`Handle` mode), or
//!   2. Copy specific headers / status from the upstream while substituting
//!      a custom body (`Copy` mode).

use axum::body::Body;
use axum::http::{Response, StatusCode};
use serde::{Deserialize, Serialize};

/// A single response interception rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    /// Match when the upstream status code is in this set.
    /// Empty = match all.
    pub match_status: Vec<u16>,
    /// Match when the upstream response contains this header.
    pub match_header: Option<String>,
    /// Match when the upstream response contains this header value substring.
    pub match_header_value: Option<String>,
    /// What to do when matched.
    pub action: ResponseAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    /// Replace the entire response with a fixed body and status.
    Handle {
        status: u16,
        body: String,
        #[serde(default)]
        content_type: Option<String>,
    },
    /// Copy the upstream status + selected headers but replace the body.
    CopyResponse {
        body: String,
        /// Headers to copy from the upstream response into the new response.
        #[serde(default)]
        copy_headers: Vec<String>,
    },
}

/// Evaluate a list of response rules against an upstream response.
/// Returns `Some(new_response)` if a rule matched and produced a
/// replacement, or `None` to let the original response through.
pub fn evaluate_rules(
    rules: &[ResponseRule],
    upstream_status: StatusCode,
    upstream_headers: &axum::http::HeaderMap,
) -> Option<Response<Body>> {
    for rule in rules {
        // Status match.
        if !rule.match_status.is_empty() && !rule.match_status.contains(&upstream_status.as_u16()) {
            continue;
        }
        // Header presence match.
        if let Some(ref hdr) = rule.match_header {
            match upstream_headers.get(hdr.as_str()) {
                None => continue,
                Some(val) => {
                    if let Some(ref expected_sub) = rule.match_header_value {
                        let v = val.to_str().unwrap_or("");
                        if !v.contains(expected_sub.as_str()) {
                            continue;
                        }
                    }
                }
            }
        }

        // Matched — build replacement response.
        match &rule.action {
            ResponseAction::Handle {
                status,
                body,
                content_type,
            } => {
                let st = StatusCode::from_u16(*status).unwrap_or(StatusCode::OK);
                let mut resp = Response::new(Body::from(body.clone()));
                *resp.status_mut() = st;
                if let Some(ct) = content_type {
                    if let Ok(v) = ct.parse() {
                        resp.headers_mut()
                            .insert(axum::http::header::CONTENT_TYPE, v);
                    }
                }
                return Some(resp);
            }
            ResponseAction::CopyResponse { body, copy_headers } => {
                let mut resp = Response::new(Body::from(body.clone()));
                *resp.status_mut() = upstream_status;
                for h in copy_headers {
                    if let Some(v) = upstream_headers.get(h.as_str()) {
                        if let Ok(name) = axum::http::header::HeaderName::from_bytes(h.as_bytes()) {
                            resp.headers_mut().insert(name, v.clone());
                        }
                    }
                }
                return Some(resp);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_replaces_on_status_match() {
        let rules = vec![ResponseRule {
            match_status: vec![502, 503],
            match_header: None,
            match_header_value: None,
            action: ResponseAction::Handle {
                status: 503,
                body: "service unavailable".to_string(),
                content_type: Some("text/plain".to_string()),
            },
        }];
        let headers = axum::http::HeaderMap::new();
        let result = evaluate_rules(&rules, StatusCode::BAD_GATEWAY, &headers);
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn no_match_returns_none() {
        let rules = vec![ResponseRule {
            match_status: vec![502],
            match_header: None,
            match_header_value: None,
            action: ResponseAction::Handle {
                status: 503,
                body: "down".to_string(),
                content_type: None,
            },
        }];
        let headers = axum::http::HeaderMap::new();
        let result = evaluate_rules(&rules, StatusCode::OK, &headers);
        assert!(result.is_none());
    }

    #[test]
    fn copy_response_preserves_status() {
        let rules = vec![ResponseRule {
            match_status: vec![],
            match_header: Some("x-custom".to_string()),
            match_header_value: None,
            action: ResponseAction::CopyResponse {
                body: "custom body".to_string(),
                copy_headers: vec!["x-custom".to_string()],
            },
        }];
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-custom", "hello".parse().unwrap());
        let result = evaluate_rules(&rules, StatusCode::OK, &headers);
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-custom").unwrap(), "hello");
    }
}
