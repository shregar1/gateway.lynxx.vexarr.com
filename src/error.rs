use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("route not found: {0}")]
    RouteNotFound(String),

    #[error("service not found: {0}")]
    ServiceNotFound(String),

    #[error("upstream error: {0}")]
    UpstreamError(String),

    #[error("circuit open: {0}")]
    CircuitOpen(String),

    #[error("monthly quota exceeded — upgrade your plan to continue")]
    QuotaExceeded,

    #[error("subscription is no longer active — renew your plan to continue")]
    LicenseRevoked,

    #[error("plugin error: {0}")]
    PluginError(PluginError),

    #[error("config error: {0}")]
    ConfigError(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("rate limited")]
    RateLimited,

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("plugin internal error: {0}")]
    Internal(String),

    /// Returned by plugins (e.g. proxy-cache hit, request-termination) to
    /// short-circuit the request and return a synthesized response without
    /// contacting upstream. The handler maps this directly to a Response.
    #[error("short-circuit response")]
    ShortCircuit {
        status: u16,
        headers: Vec<(String, String)>,
        /// Response body. Wrapped in a Sync container because anyhow requires Sync.
        body: SyncBody,
    },
}

/// A wrapper around axum::body::Body that implements Sync by using a Mutex.
/// This is a "take-once" container.
pub struct SyncBody(Arc<Mutex<Option<Body>>>);

impl SyncBody {
    pub fn new(body: Body) -> Self {
        Self(Arc::new(Mutex::new(Some(body))))
    }

    pub fn take(&self) -> Option<Body> {
        self.0.lock().ok()?.take()
    }

    /// Drain the buffered/streaming body into a single byte vec (e.g. tests).
    pub async fn into_bytes(self) -> Vec<u8> {
        use http_body_util::BodyExt;
        let b = self.take().unwrap_or_else(Body::empty);
        match b.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(_) => Vec::new(),
        }
    }
}

impl From<Body> for SyncBody {
    fn from(body: Body) -> Self {
        Self::new(body)
    }
}

impl From<Vec<u8>> for SyncBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(Body::from(bytes))
    }
}

impl std::fmt::Debug for SyncBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncBody").finish()
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        // ShortCircuit gets special handling: build a real Response with
        // the supplied status, headers, and body — no JSON envelope.
        if let GatewayError::PluginError(PluginError::ShortCircuit {
            status,
            headers,
            body,
        }) = self
        {
            let status_code =
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut response = Response::new(body.take().unwrap_or_else(Body::empty));
            *response.status_mut() = status_code;
            for (k, v) in headers {
                if let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(&v),
                ) {
                    response.headers_mut().append(name, value);
                }
            }
            // Brand lynxx-generated responses with our own `Server` header.
            // Future-proofs against any default `Server: hyper/<ver>` a
            // hyper update might introduce. Plugins that already set
            // Server win (entry/append → replace would be wrong here).
            response
                .headers_mut()
                .entry(header::SERVER)
                .or_insert_with(|| HeaderValue::from_static("lynxx"));
            return response;
        }

        let mut circuit_open = false;
        let (status, message) = match &self {
            GatewayError::RouteNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            GatewayError::ServiceNotFound(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            GatewayError::UpstreamError(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            GatewayError::CircuitOpen(_) => {
                circuit_open = true;
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            GatewayError::QuotaExceeded => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            GatewayError::LicenseRevoked => (StatusCode::PAYMENT_REQUIRED, self.to_string()),
            GatewayError::PluginError(e) => match e {
                PluginError::RateLimited => {
                    (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into())
                }
                PluginError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
                PluginError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
                PluginError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg.clone()),
                PluginError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
                PluginError::ShortCircuit { .. } => unreachable!("handled above"),
            },
            GatewayError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            GatewayError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            GatewayError::ServiceUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            GatewayError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            GatewayError::PreconditionFailed(_) => {
                (StatusCode::PRECONDITION_FAILED, self.to_string())
            }
            GatewayError::ConfigError(_) | GatewayError::Internal(_) | GatewayError::Migrate(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            GatewayError::Sqlx(ref e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE constraint failed")
                    || msg.contains("unique_violation")
                    || msg.contains("23505")
                {
                    (
                        StatusCode::CONFLICT,
                        "conflict: resource already exists".to_string(),
                    )
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
                }
            }
        };

        let body = json!({ "error": message });
        let mut response = (status, axum::Json(body)).into_response();
        if circuit_open {
            response
                .headers_mut()
                .insert("X-Lynxx-Circuit", HeaderValue::from_static("open"));
        }
        // Brand lynxx-generated error responses (see ShortCircuit branch
        // above for rationale).
        response
            .headers_mut()
            .insert(header::SERVER, HeaderValue::from_static("lynxx"));
        response
    }
}

impl From<PluginError> for GatewayError {
    fn from(err: PluginError) -> Self {
        GatewayError::PluginError(err)
    }
}

impl From<anyhow::Error> for GatewayError {
    fn from(err: anyhow::Error) -> Self {
        GatewayError::Internal(err.to_string())
    }
}
