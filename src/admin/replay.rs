use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ReplayRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Serialize)]
pub struct ReplayResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: String,
    pub latency_ms: u64,
}

pub async fn proxy_replay(
    State(state): State<AdminState>,
    Json(body): Json<ReplayRequest>,
) -> Result<Json<ReplayResponse>, GatewayError> {
    let start = std::time::Instant::now();

    let method = reqwest::Method::from_bytes(body.method.as_bytes())
        .map_err(|_| GatewayError::BadRequest("invalid HTTP method".into()))?;

    let mut req = state.http_client.request(method, &body.url);
    for (k, v) in &body.headers {
        req = req.header(k, v);
    }
    if let Some(b) = &body.body {
        req = req.body(b.clone());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| GatewayError::BadRequest(format!("replay failed: {e}")))?;

    let latency = start.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();

    let mut resp_headers = std::collections::HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            resp_headers.insert(k.to_string(), s.to_string());
        }
    }

    let resp_body = resp.text().await.unwrap_or_default();
    let preview = if resp_body.len() > 8192 {
        // Char-boundary-safe truncation — see docs::proxy_try. Raw byte slicing
        // panics mid-codepoint (fatal under `panic = "abort"`); the body is
        // attacker-influenceable via this operator SSRF helper.
        let end = (0..=8192)
            .rev()
            .find(|&i| resp_body.is_char_boundary(i))
            .unwrap_or(0);
        format!("{}...(truncated)", &resp_body[..end])
    } else {
        resp_body
    };

    Ok(Json(ReplayResponse {
        status,
        headers: resp_headers,
        body: preview,
        latency_ms: latency,
    }))
}
