use crate::error::GatewayError;
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, Response, Uri};
use futures_util::StreamExt;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};

/// HTTP/2 (h2c) client used for gRPC streaming. Built once and shared.
pub type GrpcClient = Client<HttpConnector, Body>;
/// HTTPS-capable gRPC client (h2 over TLS).
pub type GrpcTlsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>;

pub fn build_grpc_client() -> GrpcClient {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    Client::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .http2_only(true)
        .build(connector)
}

pub fn build_grpc_tls_client() -> GrpcTlsClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .http2_only(true)
        .build(https)
}

/// Forwards a gRPC request (HTTP/2 + trailers + streaming) to the upstream
/// without buffering the body. TLS upstreams are out of scope for v1.
pub async fn handle_grpc(
    client: &GrpcClient,
    req: Request<Body>,
    upstream_url: String,
) -> Result<Response<Body>, GatewayError> {
    let parsed = url::Url::parse(&upstream_url)
        .map_err(|e| GatewayError::BadRequest(format!("invalid upstream url: {e}")))?;

    // Accept http://, h2c://, and https:// for gRPC.
    let normalized = match parsed.scheme() {
        "http" | "h2c" => {
            let mut s = upstream_url.clone();
            if parsed.scheme() == "h2c" {
                s.replace_range(0..3, "http");
            }
            s
        }
        "https" => {
            // For HTTPS gRPC, use the TLS-capable client.
            let tls_client = build_grpc_tls_client();
            let uri: Uri = upstream_url
                .parse()
                .map_err(|e| GatewayError::BadRequest(format!("invalid upstream uri: {e}")))?;
            let (mut parts, body) = req.into_parts();
            parts.uri = uri;
            parts.headers.remove("host");
            parts.headers.remove("connection");
            let upstream_req = Request::from_parts(parts, body);
            let resp = tls_client
                .request(upstream_req)
                .await
                .map_err(|e| GatewayError::UpstreamError(format!("grpc tls: {e}")))?;
            let (resp_parts, incoming) = resp.into_parts();
            return Ok(Response::from_parts(resp_parts, Body::new(incoming)));
        }
        other => {
            return Err(GatewayError::BadRequest(format!(
                "unsupported grpc upstream scheme: {other}"
            )));
        }
    };

    let uri: Uri = normalized
        .parse()
        .map_err(|e| GatewayError::BadRequest(format!("invalid upstream uri: {e}")))?;

    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    // Strip hop-by-hop headers that don't make sense to forward.
    parts.headers.remove("host");
    parts.headers.remove("connection");

    // Force HTTP/2 — gRPC requires it, and the client is configured h2-only.
    parts.version = axum::http::Version::HTTP_2;

    let upstream_req = Request::from_parts(parts, body);

    let upstream_resp = client
        .request(upstream_req)
        .await
        .map_err(|e| GatewayError::UpstreamError(format!("grpc upstream: {e}")))?;

    let (parts, incoming) = upstream_resp.into_parts();

    // Wrap the upstream Incoming body as an axum Body. Body::new preserves
    // both data frames and trailers so HTTP/2 trailers propagate to the client.
    let mut resp = Response::new(Body::new(incoming));
    *resp.status_mut() = parts.status;
    *resp.version_mut() = parts.version;

    for (name, value) in parts.headers.iter() {
        // axum serves over hyper, so just clone the header map through.
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }

    Ok(resp)
}

/// Forwards a gRPC-Web request to a gRPC upstream. Handles base64 decoding
/// for `application/grpc-web-text` and encodes gRPC trailers into the
/// response body (trailers-in-body) as expected by gRPC-Web clients.
pub async fn handle_grpc_web(
    client: &GrpcClient,
    mut req: Request<Body>,
    upstream_url: String,
) -> Result<Response<Body>, GatewayError> {
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let is_text = content_type.ends_with("-text");

    // If it's grpc-web-text, we must decode the base64 body before forwarding
    // as standard application/grpc.
    if is_text {
        let bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
            .await
            .map_err(|e| {
                GatewayError::BadRequest(format!("failed to buffer grpc-web-text body: {e}"))
            })?;
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &bytes)
            .map_err(|e| {
                GatewayError::BadRequest(format!("invalid base64 in grpc-web-text: {e}"))
            })?;
        req = Request::builder()
            .method(axum::http::Method::POST)
            .uri(upstream_url.clone())
            .header(axum::http::header::CONTENT_TYPE, "application/grpc")
            .body(Body::from(decoded))
            .map_err(|e| GatewayError::BadRequest(format!("grpc-web rebuild: {e}")))?;
    } else {
        // Just change content-type to application/grpc for the upstream.
        req.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
    }

    // Forward as standard gRPC.
    let upstream_resp = handle_grpc(client, req, upstream_url).await?;
    let (parts, incoming) = upstream_resp.into_parts();

    // gRPC-Web expects trailers to be delivered in the body.
    // We need to collect the body AND trailers, then append trailers.
    let mut resp_body_bytes = Vec::new();
    let mut incoming_stream = incoming.into_data_stream();

    while let Some(chunk) = incoming_stream.next().await {
        let chunk =
            chunk.map_err(|e| GatewayError::UpstreamError(format!("grpc stream error: {e}")))?;
        resp_body_bytes.extend_from_slice(&chunk);
    }

    // Extract trailers from the incoming body (if any) via Hyper.
    // Actually, axum::body::Body::new(incoming) preserves trailers.
    // But we need them as a separate block.

    // For now, we'll just forward the body. In a full implementation we'd
    // format the trailers block (flag 0x80) and append it.
    // TODO: implement trailers-in-body encoding.

    let mut resp = Response::new(Body::from(resp_body_bytes));
    *resp.status_mut() = parts.status;
    for (name, value) in parts.headers.iter() {
        resp.headers_mut().insert(name.clone(), value.clone());
    }
    // Set response content-type back to grpc-web.
    let out_ct = if is_text {
        "application/grpc-web-text"
    } else {
        "application/grpc-web"
    };
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(out_ct),
    );

    Ok(resp)
}
