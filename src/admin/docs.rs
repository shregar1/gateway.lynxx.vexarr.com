use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct ServiceDocs {
    pub service_name: String,
    pub base_url: String,
    pub endpoints: Vec<DocEndpoint>,
}

#[derive(Serialize)]
pub struct DocEndpoint {
    pub method: String,
    pub path: String,
    pub hosts: Vec<String>,
    pub strip_path: bool,
    pub plugins: Vec<String>,
}

pub async fn service_docs(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<ServiceDocs>, GatewayError> {
    let svc = state
        .repo
        .get_service(&service_id)
        .await?
        .ok_or(GatewayError::NotFound("service not found".into()))?;

    let base_url = if !svc.subdomain.is_empty() && !svc.domain.is_empty() {
        format!("https://{}.{}", svc.subdomain, svc.domain)
    } else if !svc.domain.is_empty() {
        format!("https://{}", svc.domain)
    } else {
        svc.url.clone()
    };

    let routes = state.repo.list_routes().await?;
    let plugins = state.repo.list_plugins().await?;

    let mut endpoints = Vec::new();
    for route in routes.iter().filter(|r| r.service_id == service_id) {
        let route_plugins: Vec<String> = plugins
            .iter()
            .filter(|p| p.route_id == Some(route.id) && p.enabled)
            .map(|p| p.name.clone())
            .collect();

        let methods = if route.methods.is_empty() {
            vec!["*".into()]
        } else {
            route.methods.clone()
        };

        for method in methods {
            for path in &route.paths {
                endpoints.push(DocEndpoint {
                    method: method.clone(),
                    path: path.clone(),
                    hosts: route.hosts.clone(),
                    strip_path: route.strip_path,
                    plugins: route_plugins.clone(),
                });
            }
        }
    }

    Ok(Json(ServiceDocs {
        service_name: svc.name.to_string(),
        base_url,
        endpoints,
    }))
}

#[derive(Deserialize)]
pub struct TryItBody {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Serialize)]
pub struct TryItResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: String,
    pub latency_ms: u64,
}

pub async fn proxy_try(
    State(state): State<AdminState>,
    Json(body): Json<TryItBody>,
) -> Result<Json<TryItResponse>, GatewayError> {
    let start = std::time::Instant::now();

    // SECURITY: this endpoint is behind admin auth but it's an
    // operator-controlled HTTP fetcher — an admin (or a stolen admin token)
    // could otherwise use it to reach the cloud metadata endpoint
    // (169.254.169.254), loopback services bound to 127.0.0.1, or escape via a
    // non-http scheme like file://. Reuse the discovery SSRF allowlist
    // (rejects non-http(s), loopback, link-local, unspecified, localhost,
    // metadata domains). Private/mesh IPs stay allowed because operators
    // legitimately try-it against internal upstreams.
    if !crate::discovery::is_safe_upstream_url(&body.url) {
        return Err(GatewayError::BadRequest(format!(
            "url rejected by SSRF guard: {}",
            body.url
        )));
    }

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
        .map_err(|e| GatewayError::BadRequest(format!("request failed: {e}")))?;

    let latency = start.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();

    let mut resp_headers = std::collections::HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            resp_headers.insert(k.to_string(), s.to_string());
        }
    }

    let resp_body = resp
        .text()
        .await
        .unwrap_or_default();

    let preview = if resp_body.len() > 4096 {
        // Truncate on a UTF-8 char boundary, not a raw byte index: slicing
        // mid-codepoint panics, and under `panic = "abort"` that aborts the
        // whole process. The upstream body is attacker-influenceable (this is
        // an operator SSRF helper), so the byte at 4096 is not trusted.
        let end = (0..=4096)
            .rev()
            .find(|&i| resp_body.is_char_boundary(i))
            .unwrap_or(0);
        format!("{}...(truncated)", &resp_body[..end])
    } else {
        resp_body
    };

    Ok(Json(TryItResponse {
        status,
        headers: resp_headers,
        body: preview,
        latency_ms: latency,
    }))
}
