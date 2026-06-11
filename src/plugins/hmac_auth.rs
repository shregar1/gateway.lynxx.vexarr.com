use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::integrations::HmacVerifier;
use crate::plugins::{BoxBody, Plugin, PluginContext};
use async_trait::async_trait;
use axum::http::header::HeaderValue;
use axum::http::{Request, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// Kong-style HMAC request signing. The `Authorization` header carries
/// `Hmac username="alice", algorithm="hmac-sha256",
/// headers="date request-line", signature="<b64>"`.
///
/// Two verification backends:
///   * **local** (default) — the consumer's `api_key` field doubles as
///     the HMAC secret (same convention as basic-auth / key-auth);
///     verified in-process.
///   * **remote** — when `keyx_urn` is set in plugin config AND
///     `PluginContext.hmac_verifier` is wired in, the canonicalised
///     payload + provided signature are forwarded to the verifier
///     (keyx today; any [`HmacVerifier`] tomorrow). Secret lives in
///     the backend; lynxx never sees it.
pub struct HmacAuthPlugin {
    repo: Option<Arc<dyn Repository>>,
    algorithms: Vec<String>,
    clock_skew: i64,
    validate_body: bool,
    /// Require `date` to be among the signed headers. Default true: otherwise
    /// a client can simply omit `date` from the signing set and the clock-skew
    /// check never runs, making every signed request infinitely replayable.
    require_signed_date: bool,
    remote: Option<RemoteBackend>,
}

struct RemoteBackend {
    verifier: Arc<dyn HmacVerifier>,
    urn: String,
}

impl HmacAuthPlugin {
    pub fn from_config(
        cfg: &serde_json::Value,
        repo: Option<Arc<dyn Repository>>,
        ctx: &PluginContext,
    ) -> Result<Self, GatewayError> {
        let algorithms = cfg
            .get("algorithms")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["hmac-sha256".into()]);
        if !algorithms.iter().all(|a| a == "hmac-sha256") {
            return Err(GatewayError::BadRequest(
                "hmac-auth: only hmac-sha256 supported in v1".into(),
            ));
        }
        let clock_skew = cfg
            .get("clock_skew_seconds")
            .and_then(|v| v.as_i64())
            .unwrap_or(300);
        let validate_body = cfg
            .get("validate_request_body")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let require_signed_date = cfg
            .get("require_signed_date")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let remote = build_remote_backend(cfg, ctx)?;

        Ok(Self {
            repo,
            algorithms,
            clock_skew,
            validate_body,
            require_signed_date,
            remote,
        })
    }
}

/// Build the remote backend if and only if the plugin config opts in
/// via `keyx_urn` AND the shared `PluginContext.hmac_verifier` is
/// configured. (The legacy self-contained per-plugin config has been
/// dropped — wire a verifier into the executor instead.)
fn build_remote_backend(
    cfg: &serde_json::Value,
    ctx: &PluginContext,
) -> Result<Option<RemoteBackend>, GatewayError> {
    let urn = match cfg.get("keyx_urn").and_then(|v| v.as_str()) {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => return Ok(None),
    };
    let Some(verifier) = ctx.hmac_verifier.as_ref() else {
        return Err(GatewayError::BadRequest(
            "hmac-auth: keyx_urn set but no HmacVerifier in PluginContext — \
             configure `[keyx]` at gateway level so the executor can build one"
                .into(),
        ));
    };
    Ok(Some(RemoteBackend {
        verifier: verifier.clone(),
        urn,
    }))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn unauthorized(msg: impl Into<String>) -> PluginError {
    PluginError::Unauthorized(msg.into())
}

/// Parse `key="value"` pairs out of `Hmac key="v", key2="v2"`. Bare
/// (unquoted) values are tolerated for resilience.
fn parse_auth_params(raw: &str) -> Option<HashMap<String, String>> {
    let body = raw
        .strip_prefix("Hmac ")
        .or_else(|| raw.strip_prefix("hmac "))?;
    let mut out = HashMap::new();
    for part in body.split(',') {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim().trim_matches('"').to_string();
        out.insert(k, v);
    }
    Some(out)
}

fn canonicalize(
    headers_list: &[String],
    req: &Request<axum::body::Body>,
) -> Result<String, PluginError> {
    let mut lines = Vec::with_capacity(headers_list.len());
    for name in headers_list {
        let lower = name.to_ascii_lowercase();
        if lower == "request-line" {
            // Per Kong's convention: METHOD path?query HTTP/1.1
            let pq = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");
            lines.push(format!("{} {} HTTP/1.1", req.method(), pq));
        } else {
            let value = req
                .headers()
                .get(&lower)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| unauthorized(format!("missing signed header: {name}")))?;
            lines.push(format!("{}: {}", lower, value));
        }
    }
    Ok(lines.join("\n"))
}

#[async_trait]
impl Plugin for HmacAuthPlugin {
    fn name(&self) -> &str {
        "hmac-auth"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let raw = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| unauthorized("missing authorization header"))?
            .to_string();
        let params = parse_auth_params(&raw)
            .ok_or_else(|| unauthorized("malformed Hmac authorization header"))?;
        let username = params
            .get("username")
            .ok_or_else(|| unauthorized("missing username"))?;
        let algorithm = params
            .get("algorithm")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "hmac-sha256".into());
        if !self.algorithms.contains(&algorithm) {
            return Err(unauthorized(format!("algorithm {algorithm} not allowed")));
        }
        let signed_headers: Vec<String> = params
            .get("headers")
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_else(|| vec!["date".into()]);
        let provided_sig = params
            .get("signature")
            .ok_or_else(|| unauthorized("missing signature"))?;
        let provided_sig = B64
            .decode(provided_sig)
            .map_err(|_| unauthorized("signature not valid base64"))?;

        // Replay protection is mandatory by default: `date` must be signed so
        // the clock-skew check below actually runs. Without this a client could
        // omit `date` from the signed set and replay a captured signature
        // forever.
        let date_signed = signed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("date"));
        if self.require_signed_date && !date_signed {
            return Err(unauthorized(
                "`date` must be among the signed headers (replay protection)",
            ));
        }

        // Clock-skew check on Date if present in the signed list.
        if date_signed {
            let date_raw = req
                .headers()
                .get("date")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| unauthorized("missing Date header"))?;
            let parsed = DateTime::parse_from_rfc2822(date_raw)
                .map_err(|_| unauthorized("invalid Date header"))?;
            let delta = (Utc::now() - parsed.with_timezone(&Utc))
                .num_seconds()
                .abs();
            if delta > self.clock_skew {
                return Err(unauthorized(format!("clock skew {delta}s exceeds limit")));
            }
        }

        let canon = canonicalize(&signed_headers, req)?;

        // Consumer lookup is best-effort in keyx mode (the secret lives
        // in keyx; the consumer row is only consulted for the downstream
        // x-consumer-* headers). In local mode it's mandatory — the
        // consumer's api_key IS the HMAC secret.
        let consumer = if let Some(repo) = self.repo.as_ref() {
            // Indexed lookup via the shared short-TTL consumer cache.
            crate::plugins::consumer_cache::by_username(repo, username)
                .await
                .map_err(|e| PluginError::Internal(format!("consumer lookup: {e}")))?
        } else {
            None
        };

        match &self.remote {
            Some(backend) => {
                let sig_hex = hex_encode(&provided_sig);
                match backend
                    .verifier
                    .verify_hmac(&backend.urn, canon.as_bytes(), &sig_hex)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => return Err(unauthorized("signature mismatch")),
                    Err(e) => {
                        tracing::debug!(error = %e, "remote verify_hmac failed");
                        return Err(unauthorized("hmac verify backend error"));
                    }
                }
            }
            None => {
                // Local mode: consumer + secret are mandatory.
                let consumer = consumer
                    .as_ref()
                    .ok_or_else(|| unauthorized("unknown consumer"))?;
                let secret = consumer
                    .api_key
                    .as_deref()
                    .ok_or_else(|| unauthorized("consumer has no secret"))?;
                let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                    .map_err(|e| PluginError::Internal(format!("hmac key: {e}")))?;
                mac.update(canon.as_bytes());
                mac.verify_slice(&provided_sig)
                    .map_err(|_| unauthorized("signature mismatch"))?;
            }
        };

        // Optional body integrity check via Digest header.
        if self.validate_body {
            // Body must be buffered to hash it; for non-empty bodies, read
            // and replace. Empty bodies skip per spec.
            let content_length = req
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            if content_length > 0 {
                let digest = req
                    .headers()
                    .get("digest")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| unauthorized("missing Digest header for body"))?
                    .to_string();
                let expected_b64 = digest
                    .strip_prefix("SHA-256=")
                    .ok_or_else(|| unauthorized("Digest must use SHA-256"))?;
                let expected = B64
                    .decode(expected_b64)
                    .map_err(|_| unauthorized("Digest not valid base64"))?;

                let body = std::mem::replace(req.body_mut(), axum::body::Body::empty());
                let bytes = body
                    .collect()
                    .await
                    .map_err(|e| PluginError::Internal(format!("body collect: {e}")))?
                    .to_bytes();
                let mut h = Sha256::new();
                h.update(&bytes);
                let actual = h.finalize();
                if actual.as_slice() != expected.as_slice() {
                    return Err(unauthorized("body digest mismatch"));
                }
                *req.body_mut() = axum::body::Body::from(bytes);
            }
        }

        // Set the downstream identity from the VERIFIED signer. `username`
        // was authenticated by the signature check above (remote or local
        // mode), so it is authoritative even when no local consumer row
        // exists (the common case in keyx/remote mode). Ingress has already
        // stripped any client-supplied `x-consumer-*` headers, so this is the
        // only identity downstream ACL / rate-limit / logging plugins see —
        // closing the spoofing gap where remote mode previously left the
        // client's own headers in place.
        if let Ok(v) = HeaderValue::from_str(username.as_str()) {
            req.headers_mut().insert("x-consumer-username", v);
        }
        if let Some(c) = consumer.as_ref() {
            if let Ok(v) = HeaderValue::from_str(&c.id.to_string()) {
                req.headers_mut().insert("x-consumer-id", v);
            }
        }
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn req_with_hmac_header(b64_sig: &str) -> Request<Body> {
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        Request::builder()
            .method("POST")
            .uri("/v1/things")
            .header(
                "Authorization",
                format!(
                    "Hmac username=\"alice\", algorithm=\"hmac-sha256\", \
                     headers=\"date\", signature=\"{b64_sig}\""
                ),
            )
            .header("Date", date)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn local_mode_unchanged_when_no_keyx_urn() {
        // Without keyx_urn, the plugin builds in local mode and behaves
        // exactly as before — unknown username = 401.
        let plugin = HmacAuthPlugin::from_config(
            &serde_json::json!({ "validate_request_body": false }),
            None,
            &PluginContext::default(),
        )
        .unwrap();
        assert!(plugin.remote.is_none());
        let mut req = req_with_hmac_header(&B64.encode(b"x"));
        let err = plugin.on_request(&mut req).await.unwrap_err();
        // Local mode without repo = "no repository" internal error path,
        // not a signature failure — that's fine, we're just asserting
        // the remote branch wasn't taken.
        assert!(matches!(
            err,
            PluginError::Internal(_) | PluginError::Unauthorized(_)
        ));
    }

    #[test]
    fn hex_encode_matches_known_value() {
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }
}
