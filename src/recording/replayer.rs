//! Replay a recording against a target URL and structurally diff the
//! response. The replayer strips end-user credentials (`Authorization`,
//! `X-Api-Key`, `Cookie`) before sending — the assumption is that the
//! original request's auth wouldn't be valid against the target anyway,
//! and we don't want to leak production tokens to a staging replay
//! target. The `Host` and `Content-Length` headers are also dropped so
//! `reqwest` can compute correct values for the target host.

use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::error::GatewayError;
use crate::recording::{RecordedResponse, Recording};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub original: Recording,
    pub new_response: RecordedResponse,
    pub diff: ResponseDiff,
    pub elapsed_ms: u64,
    pub target_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseDiff {
    pub status_changed: Option<(u16, u16)>,
    pub headers_added: Vec<(String, String)>,
    pub headers_removed: Vec<(String, String)>,
    pub headers_changed: Vec<(String, String, String)>,
    pub body_diff: BodyDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[derive(Default)]
pub enum BodyDiff {
    #[default]
    Identical,
    BinaryDiff {
        before_bytes: usize,
        after_bytes: usize,
    },
    JsonDiff {
        added: serde_json::Value,
        removed: serde_json::Value,
        changed: serde_json::Value,
    },
    TextDiff {
        lines_changed: u32,
    },
}

const STRIPPED_HEADERS: &[&str] = &["authorization", "x-api-key", "cookie"];

pub async fn replay(
    rec: &Recording,
    target_url: &str,
    http_client: &reqwest::Client,
) -> Result<ReplayResult, GatewayError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let body = STANDARD
        .decode(&rec.request.body_b64)
        .map_err(|e| GatewayError::BadRequest(format!("invalid request body_b64: {e}")))?;

    let url = format!(
        "{}{}",
        target_url.trim_end_matches('/'),
        if rec.request.path.starts_with('/') {
            rec.request.path.clone()
        } else {
            format!("/{}", rec.request.path)
        }
    );

    let method = reqwest::Method::from_bytes(rec.request.method.as_bytes())
        .map_err(|e| GatewayError::BadRequest(format!("invalid method: {e}")))?;

    let mut req = http_client.request(method, &url).body(body);
    for (k, v) in &rec.request.headers {
        if STRIPPED_HEADERS.iter().any(|s| s.eq_ignore_ascii_case(k)) {
            continue;
        }
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        req = req.header(k, v);
    }

    let start = Instant::now();
    let resp = req
        .send()
        .await
        .map_err(|e| GatewayError::UpstreamError(format!("replay send: {e}")))?;
    let status = resp.status().as_u16();
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|e| GatewayError::UpstreamError(format!("replay body: {e}")))?;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let new_response = RecordedResponse {
        status,
        headers: resp_headers,
        body_b64: STANDARD.encode(&resp_body),
    };

    let diff = diff_response(&rec.response, &new_response, &resp_body)?;

    Ok(ReplayResult {
        original: rec.clone(),
        new_response,
        diff,
        elapsed_ms,
        target_url: target_url.to_string(),
    })
}

fn diff_response(
    before: &RecordedResponse,
    after: &RecordedResponse,
    after_body: &[u8],
) -> Result<ResponseDiff, GatewayError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let before_body = STANDARD
        .decode(&before.body_b64)
        .map_err(|e| GatewayError::Internal(format!("decode before: {e}")))?;

    let status_changed = if before.status != after.status {
        Some((before.status, after.status))
    } else {
        None
    };

    let (headers_added, headers_removed, headers_changed) =
        diff_headers(&before.headers, &after.headers);

    let body_diff = diff_bodies(&before_body, after_body);

    Ok(ResponseDiff {
        status_changed,
        headers_added,
        headers_removed,
        headers_changed,
        body_diff,
    })
}

fn diff_headers(
    before: &[(String, String)],
    after: &[(String, String)],
) -> (
    Vec<(String, String)>,
    Vec<(String, String)>,
    Vec<(String, String, String)>,
) {
    use std::collections::BTreeMap;
    let map_b: BTreeMap<String, String> = before
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let map_a: BTreeMap<String, String> = after
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();

    let mut added = vec![];
    let mut removed = vec![];
    let mut changed = vec![];

    for (k, v) in &map_a {
        match map_b.get(k) {
            None => added.push((k.clone(), v.clone())),
            Some(old) if old != v => changed.push((k.clone(), old.clone(), v.clone())),
            _ => {}
        }
    }
    for (k, v) in &map_b {
        if !map_a.contains_key(k) {
            removed.push((k.clone(), v.clone()));
        }
    }
    (added, removed, changed)
}

fn diff_bodies(before: &[u8], after: &[u8]) -> BodyDiff {
    if before == after {
        return BodyDiff::Identical;
    }
    if let (Ok(b), Ok(a)) = (
        serde_json::from_slice::<serde_json::Value>(before),
        serde_json::from_slice::<serde_json::Value>(after),
    ) {
        let (added, removed, changed) = json_diff(&b, &a);
        return BodyDiff::JsonDiff {
            added,
            removed,
            changed,
        };
    }
    if let (Ok(b), Ok(a)) = (std::str::from_utf8(before), std::str::from_utf8(after)) {
        let bl: Vec<&str> = b.lines().collect();
        let al: Vec<&str> = a.lines().collect();
        let mut differ: u32 = 0;
        let max = bl.len().max(al.len());
        for i in 0..max {
            if bl.get(i).unwrap_or(&"") != al.get(i).unwrap_or(&"") {
                differ += 1;
            }
        }
        return BodyDiff::TextDiff {
            lines_changed: differ,
        };
    }
    BodyDiff::BinaryDiff {
        before_bytes: before.len(),
        after_bytes: after.len(),
    }
}

/// Recursive structural JSON diff. Returns (added, removed, changed) as JSON
/// objects keyed by path-from-root in dotted form.
fn json_diff(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> (serde_json::Value, serde_json::Value, serde_json::Value) {
    use serde_json::{Map, Value};
    let mut added = Map::new();
    let mut removed = Map::new();
    let mut changed = Map::new();
    walk("", before, after, &mut added, &mut removed, &mut changed);
    (
        Value::Object(added),
        Value::Object(removed),
        Value::Object(changed),
    )
}

fn walk(
    path: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
    added: &mut serde_json::Map<String, serde_json::Value>,
    removed: &mut serde_json::Map<String, serde_json::Value>,
    changed: &mut serde_json::Map<String, serde_json::Value>,
) {
    use serde_json::Value;
    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            for (k, v) in a {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match b.get(k) {
                    None => {
                        added.insert(p, v.clone());
                    }
                    Some(bv) if bv != v => walk(&p, bv, v, added, removed, changed),
                    _ => {}
                }
            }
            for (k, v) in b {
                if !a.contains_key(k) {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    removed.insert(p, v.clone());
                }
            }
        }
        _ if before != after => {
            changed.insert(
                if path.is_empty() {
                    "<root>".into()
                } else {
                    path.into()
                },
                serde_json::json!({"before": before, "after": after}),
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identical_bodies() {
        let d = diff_bodies(b"hello", b"hello");
        assert!(matches!(d, BodyDiff::Identical));
    }

    #[test]
    fn json_diff_added_removed_changed() {
        let before = json!({"a": 1, "b": 2, "nested": {"x": 1}});
        let after = json!({"a": 1, "c": 3, "nested": {"x": 2}});
        let bb = serde_json::to_vec(&before).unwrap();
        let ab = serde_json::to_vec(&after).unwrap();

        let d = diff_bodies(&bb, &ab);
        match d {
            BodyDiff::JsonDiff {
                added,
                removed,
                changed,
            } => {
                // `c` added at root
                assert_eq!(added["c"], json!(3));
                // `b` removed at root
                assert_eq!(removed["b"], json!(2));
                // `nested.x` changed
                assert_eq!(changed["nested.x"]["before"], json!(1));
                assert_eq!(changed["nested.x"]["after"], json!(2));
            }
            other => panic!("expected JsonDiff, got {other:?}"),
        }
    }

    #[test]
    fn text_diff_line_count() {
        let before = b"alpha\nbeta\ngamma\n";
        let after = b"alpha\nBETA\ngamma\ndelta\n";
        let d = diff_bodies(before, after);
        match d {
            BodyDiff::TextDiff { lines_changed } => {
                // line 1 differs (beta vs BETA), line 3 differs ("" vs "delta")
                assert_eq!(lines_changed, 2);
            }
            other => panic!("expected TextDiff, got {other:?}"),
        }
    }

    #[test]
    fn binary_fallback_for_invalid_utf8() {
        let before: &[u8] = &[0xff, 0xfe, 0x00, 0x01];
        let after: &[u8] = &[0xff, 0xfe, 0x00, 0x02, 0x03];
        let d = diff_bodies(before, after);
        match d {
            BodyDiff::BinaryDiff {
                before_bytes,
                after_bytes,
            } => {
                assert_eq!(before_bytes, 4);
                assert_eq!(after_bytes, 5);
            }
            other => panic!("expected BinaryDiff, got {other:?}"),
        }
    }

    #[test]
    fn header_diff_case_insensitive_and_sorted() {
        let before = vec![
            ("Content-Type".into(), "application/json".into()),
            ("X-Old".into(), "1".into()),
            ("ETag".into(), "v1".into()),
        ];
        let after = vec![
            ("content-type".into(), "application/json".into()),
            ("X-New".into(), "2".into()),
            ("ETag".into(), "v2".into()),
        ];
        let (added, removed, changed) = diff_headers(&before, &after);

        // Same header (case differs) is a no-op
        assert!(!added.iter().any(|(k, _)| k == "content-type"));
        assert!(!removed.iter().any(|(k, _)| k == "content-type"));

        assert_eq!(added.len(), 1);
        assert_eq!(added[0].0, "x-new");
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].0, "x-old");

        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0], ("etag".into(), "v1".into(), "v2".into()));
    }

    #[test]
    fn json_root_scalar_change() {
        // A non-object root with different scalars goes through the
        // `_ if before != after` arm — it shouldn't panic and should
        // surface a `<root>` entry in `changed`.
        let bb = serde_json::to_vec(&json!(1)).unwrap();
        let ab = serde_json::to_vec(&json!(2)).unwrap();
        let d = diff_bodies(&bb, &ab);
        match d {
            BodyDiff::JsonDiff { changed, .. } => {
                assert_eq!(changed["<root>"]["before"], json!(1));
                assert_eq!(changed["<root>"]["after"], json!(2));
            }
            other => panic!("expected JsonDiff, got {other:?}"),
        }
    }
}
