use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderValue, Request, Response};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use http_body_util::BodyExt;

/// Translate gRPC-Web (`application/grpc-web+proto` or `-text`) to standard
/// gRPC over HTTP/2 before the proxy hands the request to the gRPC dispatch
/// path. On the way back, encode the response trailers as a base64-framed
/// trailer block per the gRPC-Web spec so browser clients can read them.
///
/// CORS handling is permissive by default — gRPC-Web requires CORS preflight
/// and exposes a fixed set of response headers. The list is configurable but
/// the defaults match the [grpc-web spec recommendations].
///
/// [grpc-web spec recommendations]: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md
pub struct GrpcWebPlugin {
    cors_allowed_origins: Vec<String>,
}

impl GrpcWebPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let cors_allowed_origins = cfg
            .get("cors_allowed_origins")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["*".to_string()]);
        Ok(Self {
            cors_allowed_origins,
        })
    }

    fn pick_allow_origin(&self, req_origin: Option<&str>) -> String {
        if self.cors_allowed_origins.iter().any(|o| o == "*") {
            return "*".to_string();
        }
        if let Some(origin) = req_origin {
            if self.cors_allowed_origins.iter().any(|o| o == origin) {
                return origin.to_string();
            }
        }
        // No match — return the first configured origin so the client gets a
        // deterministic response. Browsers will reject if it doesn't match.
        self.cors_allowed_origins
            .first()
            .cloned()
            .unwrap_or_default()
    }
}

const GRPC_WEB_PROTO: &str = "application/grpc-web+proto";
const GRPC_WEB_TEXT: &str = "application/grpc-web-text";
const GRPC_WEB_PLAIN: &str = "application/grpc-web";
const HDR_GW_ORIGIN: &str = "x-lynxx-grpc-web-origin";
const HDR_GW_ENCODE_TRAILERS: &str = "x-lynxx-grpc-web-trailer";

fn is_grpc_web(ct: &str) -> bool {
    ct == GRPC_WEB_PROTO || ct == GRPC_WEB_TEXT || ct == GRPC_WEB_PLAIN
}

#[async_trait]
impl Plugin for GrpcWebPlugin {
    fn name(&self) -> &str {
        "grpc-web"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        // Capture the origin so on_response can echo it back on success.
        let origin_str = req
            .headers()
            .get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .unwrap_or_default();
        if let Ok(v) = HeaderValue::from_str(&origin_str) {
            req.headers_mut().insert(HDR_GW_ORIGIN, v);
        }

        // CORS preflight short-circuit. Browsers send OPTIONS with the
        // Access-Control-Request-Method header set; respond with the allow
        // headers required by gRPC-Web before the upstream is contacted.
        if req.method() == axum::http::Method::OPTIONS
            && req.headers().contains_key("access-control-request-method")
        {
            let allow_origin = self.pick_allow_origin(if origin_str.is_empty() {
                None
            } else {
                Some(&origin_str)
            });
            let headers = vec![
                ("access-control-allow-origin".into(), allow_origin),
                (
                    "access-control-allow-methods".into(),
                    "POST, OPTIONS".into(),
                ),
                (
                    "access-control-allow-headers".into(),
                    "content-type,x-grpc-web,x-user-agent,grpc-timeout,authorization".into(),
                ),
                (
                    "access-control-expose-headers".into(),
                    "grpc-status,grpc-message".into(),
                ),
                ("access-control-max-age".into(), "86400".into()),
                ("content-length".into(), "0".into()),
            ];
            return Err(PluginError::ShortCircuit {
                status: 204,
                headers,
                body: Vec::new().into(),
            });
        }

        let ct = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .unwrap_or_default();
        if !is_grpc_web(&ct) {
            return Ok(());
        }

        // grpc-web-text bodies are base64-encoded; decode in place. Bodies
        // are typically small (single RPC frames) so a full buffer is fine.
        if ct == GRPC_WEB_TEXT {
            let body = std::mem::replace(req.body_mut(), Body::empty());
            let bytes = body
                .collect()
                .await
                .map_err(|e| PluginError::Internal(format!("grpc-web body collect: {e}")))?
                .to_bytes();
            let decoded = B64
                .decode(bytes.as_ref())
                .map_err(|e| PluginError::Internal(format!("grpc-web: base64 decode: {e}")))?;
            *req.body_mut() = Body::from(decoded);
        }

        // Rewrite content-type to standard gRPC and ensure the upstream sees
        // a TE: trailers header (HTTP/2 gRPC requires it).
        req.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
        req.headers_mut()
            .insert(axum::http::header::TE, HeaderValue::from_static("trailers"));

        // Mark this response so on_response knows to apply the trailer-frame
        // encoding (gRPC-Web is text or proto over HTTP/1.1; trailers are
        // serialised into the body as a final frame).
        req.headers_mut().insert(
            HDR_GW_ENCODE_TRAILERS,
            HeaderValue::from_static(if ct == GRPC_WEB_TEXT { "text" } else { "proto" }),
        );
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let origin = resp
            .headers()
            .get(HDR_GW_ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .unwrap_or_default();
        let trailer_mode = resp
            .headers()
            .get(HDR_GW_ENCODE_TRAILERS)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        resp.headers_mut().remove(HDR_GW_ORIGIN);
        resp.headers_mut().remove(HDR_GW_ENCODE_TRAILERS);

        // Always set CORS headers — gRPC-Web responses are fetched cross-origin.
        let allow_origin = self.pick_allow_origin(if origin.is_empty() {
            None
        } else {
            Some(&origin)
        });
        if let Ok(v) = HeaderValue::from_str(&allow_origin) {
            resp.headers_mut().insert("access-control-allow-origin", v);
        }
        resp.headers_mut().insert(
            "access-control-expose-headers",
            HeaderValue::from_static("grpc-status,grpc-message"),
        );

        let mode = match trailer_mode {
            Some(m) => m,
            // Not a grpc-web request — leave the response alone.
            None => return Ok(()),
        };

        // Encode the trailers (grpc-status, grpc-message, plus any
        // grpc-trailer-* headers) into a final length-prefixed frame and
        // append it to the body. For grpc-web-text the entire body is then
        // base64-encoded.
        let trailer_lines = collect_trailer_lines(resp);
        let mut trailer_frame: Vec<u8> = Vec::with_capacity(64);
        // Frame header: 1 byte flags (0x80 = trailer), 4 bytes length BE.
        trailer_frame.push(0x80);
        let mut payload: Vec<u8> = Vec::new();
        for line in trailer_lines {
            payload.extend_from_slice(line.as_bytes());
            payload.extend_from_slice(b"\r\n");
        }
        let len = payload.len() as u32;
        trailer_frame.extend_from_slice(&len.to_be_bytes());
        trailer_frame.extend_from_slice(&payload);

        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("grpc-web resp collect: {e}")))?
            .to_bytes();
        let mut combined = bytes.to_vec();
        combined.extend_from_slice(&trailer_frame);

        let final_bytes = if mode == "text" {
            B64.encode(&combined).into_bytes()
        } else {
            combined
        };
        let out_ct = if mode == "text" {
            GRPC_WEB_TEXT
        } else {
            GRPC_WEB_PROTO
        };
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static(out_ct),
        );
        if let Ok(v) = HeaderValue::from_str(&final_bytes.len().to_string()) {
            resp.headers_mut()
                .insert(axum::http::header::CONTENT_LENGTH, v);
        }
        *resp.body_mut() = Body::from(final_bytes);
        Ok(())
    }
}

fn collect_trailer_lines(resp: &Response<BoxBody>) -> Vec<String> {
    let mut out = Vec::new();
    for (name, value) in resp.headers() {
        let n = name.as_str();
        if n == "grpc-status" || n == "grpc-message" || n.starts_with("grpc-trailer-") {
            if let Ok(v) = value.to_str() {
                let key = n.strip_prefix("grpc-trailer-").unwrap_or(n);
                out.push(format!("{key}: {v}"));
            }
        }
    }
    if out.iter().all(|l| !l.starts_with("grpc-status")) {
        // Default to status 0 (OK) if the upstream didn't surface trailers.
        out.push("grpc-status: 0".to_string());
    }
    out
}
