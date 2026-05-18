use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};

/// Deterministic mock responses keyed on method + path patterns. Useful for
/// dev environments and contract testing.
///
/// Path patterns:
/// - `*` matches a single path segment (e.g. `/users/*` matches
///   `/users/anything` but **not** `/usersfoo` and not `/users/a/b`)
/// - `:name` extracts a single segment (treated identically to `*` for
///   matching; the captured value is currently unused)
/// - any other segment is matched literally
pub struct MockingPlugin {
    responses: Vec<MockResponse>,
    fallthrough: Fallthrough,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fallthrough {
    Passthrough,
    NotFound,
}

#[derive(Clone)]
struct MockResponse {
    method: Option<String>,
    path_segments: Vec<PathSeg>,
    /// True when the original pattern ended with a literal `/` (i.e. trailing
    /// slash on the request path is required to match).
    trailing_slash: bool,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Clone)]
enum PathSeg {
    Literal(String),
    /// `*` or `:name` — matches exactly one non-empty segment.
    Wildcard,
}

impl MockingPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let arr = cfg
            .get("responses")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                GatewayError::BadRequest("mocking: `responses` must be an array".into())
            })?;
        let mut responses = Vec::with_capacity(arr.len());
        for r in arr {
            let m = r.get("match").ok_or_else(|| {
                GatewayError::BadRequest("mocking: response missing `match`".into())
            })?;
            let method = m
                .get("method")
                .and_then(|v| v.as_str())
                .map(|s| s.to_uppercase());
            let path = m.get("path").and_then(|v| v.as_str()).ok_or_else(|| {
                GatewayError::BadRequest("mocking: `match.path` is required".into())
            })?;
            let (path_segments, trailing_slash) = parse_path_pattern(path);
            let status = r.get("status").and_then(|v| v.as_u64()).unwrap_or(200) as u16;
            let headers = r
                .get("headers")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let body = r
                .get("body")
                .and_then(|v| v.as_str())
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_default();
            responses.push(MockResponse {
                method,
                path_segments,
                trailing_slash,
                status,
                headers,
                body,
            });
        }
        let fallthrough = match cfg
            .get("fallthrough")
            .and_then(|v| v.as_str())
            .unwrap_or("passthrough")
        {
            "404" => Fallthrough::NotFound,
            _ => Fallthrough::Passthrough,
        };
        Ok(Self {
            responses,
            fallthrough,
        })
    }
}

fn parse_path_pattern(p: &str) -> (Vec<PathSeg>, bool) {
    let trailing_slash = p.ends_with('/') && p.len() > 1;
    let segs: Vec<PathSeg> = p
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s == "*" || s.starts_with(':') {
                PathSeg::Wildcard
            } else {
                PathSeg::Literal(s.to_string())
            }
        })
        .collect();
    (segs, trailing_slash)
}

fn path_matches(pattern: &MockResponse, req_path: &str) -> bool {
    let req_segs: Vec<&str> = req_path.split('/').filter(|s| !s.is_empty()).collect();
    if req_segs.len() != pattern.path_segments.len() {
        return false;
    }
    for (pat, got) in pattern.path_segments.iter().zip(req_segs.iter()) {
        match pat {
            PathSeg::Literal(s) => {
                if s != got {
                    return false;
                }
            }
            PathSeg::Wildcard => {
                if got.is_empty() {
                    return false;
                }
            }
        }
    }
    if pattern.trailing_slash && !req_path.ends_with('/') {
        return false;
    }
    true
}

#[async_trait]
impl Plugin for MockingPlugin {
    fn name(&self) -> &str {
        "mocking"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();
        for r in &self.responses {
            if let Some(m) = &r.method {
                if m != &method {
                    continue;
                }
            }
            if !path_matches(r, &path) {
                continue;
            }
            let mut headers = r.headers.clone();
            if !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                && !r.body.is_empty()
            {
                headers.push(("content-type".into(), "application/octet-stream".into()));
            }
            return Err(PluginError::ShortCircuit {
                status: r.status,
                headers,
                body: r.body.clone().into(),
            });
        }
        match self.fallthrough {
            Fallthrough::Passthrough => Ok(()),
            Fallthrough::NotFound => Err(PluginError::ShortCircuit {
                status: 404,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"error":"no mock matched"}"#.to_vec().into(),
            }),
        }
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
