//! Multi-provider dispatcher with fallback and hedging.
//!
//! `dispatch()` walks the ordered list returned by [`Router::dispatch_order`]
//! and POSTs the request body to each `{provider.base_url}{path}` until one
//! responds with a non-retriable status.
//!
//! `dispatch_hedged()` dispatches to multiple providers in parallel and
//! returns the first successful 200 OK response.

use super::config::ProviderCfg;
use futures_util::future::{select_all, BoxFuture};
use futures_util::FutureExt;
use http;
use reqwest::Client;
use std::time::Duration;

/// Outcome of a single dispatch.
pub struct DispatchResult {
    pub provider: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// The live response from the upstream provider.
    pub response: reqwest::Response,
    /// Number of providers tried before this one succeeded (or failed
    /// non-retriably). Zero means the primary worked first time.
    pub fallback_count: u32,
    /// Set when every provider in the chain returned a retriable error;
    /// the body is from the *last* attempt.
    pub exhausted: bool,
}

/// Whether this status indicates "try the next provider".
fn is_retriable(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

pub async fn dispatch(
    client: &Client,
    providers: &[ProviderCfg],
    path: &str,
    method: &reqwest::Method,
    forwarded_headers: &[(String, String)],
    body: &[u8],
    on_fallback: impl Fn(&str, &str),
) -> Result<DispatchResult, String> {
    if providers.is_empty() {
        return Err("llm-gateway: no providers in dispatch chain".into());
    }
    let mut last: Option<DispatchResult> = None;
    for (i, p) in providers.iter().enumerate() {
        if i > 0 {
            on_fallback(&providers[i - 1].name, &p.name);
        }

        let dr = match dispatch_single(client, p, path, method, forwarded_headers, body, i as u32)
            .await
        {
            Ok(dr) => dr,
            Err(e) => {
                tracing::warn!(provider = %p.name, error = %e, "llm-gateway: provider request failed; trying next");
                let mock_resp = reqwest::Response::from(
                    http::Response::builder()
                        .status(502)
                        .header("Content-Type", "application/json")
                        .body(format!(
                            r#"{{"error":{{"code":"upstream_error","message":"{e}"}}}}"#
                        ))
                        .unwrap(),
                );
                last = Some(DispatchResult {
                    provider: p.name.clone(),
                    status: 502,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    response: mock_resp,
                    fallback_count: i as u32,
                    exhausted: false,
                });
                continue;
            }
        };

        if is_retriable(dr.status) && i + 1 < providers.len() {
            tracing::info!(
                provider = %p.name,
                status = dr.status,
                "llm-gateway: retriable upstream status, falling back"
            );
            last = Some(dr);
            continue;
        }
        return Ok(dr);
    }
    let mut last = last.expect("loop runs at least once");
    last.exhausted = true;
    Ok(last)
}

/// Dispatches to multiple providers in parallel and returns the first 200 OK.
/// If all fail or return retriable errors, it falls back to sequential dispatch
/// over the remaining fallback chain.
pub async fn dispatch_hedged(
    client: &Client,
    providers: &[ProviderCfg],
    path: &str,
    method: &reqwest::Method,
    forwarded_headers: &[(String, String)],
    body: &[u8],
) -> Result<DispatchResult, String> {
    if providers.is_empty() {
        return Err("llm-gateway: no providers for hedging".into());
    }

    let mut futures: Vec<BoxFuture<'static, Result<DispatchResult, String>>> = Vec::new();
    for p in providers {
        let client = client.clone();
        let p = p.clone();
        let path = path.to_string();
        let method = method.clone();
        let headers = forwarded_headers.to_vec();
        let body = body.to_vec();

        futures.push(
            async move { dispatch_single(&client, &p, &path, &method, &headers, &body, 0).await }
                .boxed(),
        );
    }

    let mut remaining = futures;
    while !remaining.is_empty() {
        let (result, _index, others) = select_all(remaining).await;
        remaining = others;

        match result {
            Ok(dr) if dr.status == 200 => {
                tracing::info!(provider = %dr.provider, "llm-gateway: hedge winner");
                return Ok(dr);
            }
            Ok(dr) => {
                tracing::debug!(provider = %dr.provider, status = dr.status, "llm-gateway: hedge participant returned non-200");
                if remaining.is_empty() {
                    return Ok(dr);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "llm-gateway: hedge participant failed");
                if remaining.is_empty() {
                    return Err(e);
                }
            }
        }
    }

    Err("llm-gateway: hedging exhausted without winner".into())
}

async fn dispatch_single(
    client: &Client,
    p: &ProviderCfg,
    path: &str,
    method: &reqwest::Method,
    forwarded_headers: &[(String, String)],
    body: &[u8],
    fallback_count: u32,
) -> Result<DispatchResult, String> {
    // Resolve URL and Auth from presets or manual config.
    let base_url = p
        .resolved_base_url()
        .map_err(|e| format!("llm-gateway: {e}"))?;
    let (auth_header, auth_scheme) = p.resolved_auth();

    let base = base_url.trim_end_matches('/');
    let url = format!("{base}{path}");

    let mut req = client.request(method.clone(), &url);
    for (k, v) in forwarded_headers {
        if k.eq_ignore_ascii_case("authorization") || k.eq_ignore_ascii_case("x-api-key") {
            continue;
        }
        let lk = k.to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "upgrade"
                | "accept-encoding"
        ) {
            continue;
        }
        req = req.header(k, v);
    }
    if let Some(key) = &p.api_key {
        let value = if auth_scheme.is_empty() {
            key.clone()
        } else {
            format!("{} {}", auth_scheme, key)
        };
        req = req.header(&auth_header, value);
    }
    if base_url.contains("anthropic") {
        req = req.header("anthropic-version", "2023-06-01");
    }
    req = req.body(body.to_vec()).timeout(Duration::from_secs(120));

    let resp = req.send().await.map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    let mut headers = Vec::with_capacity(resp.headers().len());
    for (k, v) in resp.headers().iter() {
        if let Ok(s) = v.to_str() {
            headers.push((k.as_str().to_string(), s.to_string()));
        }
    }

    Ok(DispatchResult {
        provider: p.name.clone(),
        status,
        headers,
        response: resp,
        fallback_count,
        exhausted: false,
    })
}
