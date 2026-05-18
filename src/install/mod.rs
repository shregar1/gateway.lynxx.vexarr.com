//! Install endpoints — serve install scripts and stream private GCS binaries.
//!
//! Routes mounted on the gateway:
//!
//!   GET /install.sh            — bash installer for the lynxx CLI
//!   GET /install.ps1           — PowerShell installer for the lynxx CLI
//!   GET /install_gateway.sh    — bash installer for lynxx-gateway
//!   GET /install_gateway.ps1   — PowerShell installer for lynxx-gateway
//!   GET /v1/install/binary?artifact=<cli|gateway>&os=<linux|darwin|windows>&arch=<amd64|arm64>
//!       — streams gs://lynxx-public/{artifact}/{os}/{arch}/{bin} using the
//!         gateway's GCP service account (via the GCE metadata server).
//!
//! Binaries are streamed straight from GCS — no buffering through disk or RAM.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use tokio::sync::Mutex;

const BUCKET: &str = "lynxx-public";
const TRANSPARENCY_BUCKET: &str = "vexarr-transparency-log";
const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

// Refresh the access token this many seconds before its real expiry so
// concurrent requests near the boundary don't race on a stale token.
const TOKEN_REFRESH_SLACK_SECS: u64 = 60;

// Embedded install scripts. include_str! keeps the binary self-contained —
// no extra files to ship alongside the gateway.
const INSTALL_SH: &str = include_str!("../../assets/install/install.sh");
const INSTALL_PS1: &str = include_str!("../../assets/install/install.ps1");
const INSTALL_GATEWAY_SH: &str = include_str!("../../assets/install/install_gateway.sh");
const INSTALL_GATEWAY_PS1: &str = include_str!("../../assets/install/install_gateway.ps1");

#[derive(Default)]
struct TokenCache {
    token: Option<String>,
    expires_at: Option<Instant>,
}

pub struct InstallState {
    client: reqwest::Client,
    token: Mutex<TokenCache>,
}

impl InstallState {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .pool_idle_timeout(Duration::from_secs(90))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            token: Mutex::new(TokenCache::default()),
        }
    }

    async fn access_token(&self) -> Result<String, anyhow::Error> {
        let now = Instant::now();
        {
            let cache = self.token.lock().await;
            if let (Some(tok), Some(exp)) = (&cache.token, cache.expires_at) {
                if exp > now {
                    return Ok(tok.clone());
                }
            }
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let resp: TokenResponse = self
            .client
            .get(METADATA_TOKEN_URL)
            .header("Metadata-Flavor", "Google")
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let ttl = resp.expires_in.saturating_sub(TOKEN_REFRESH_SLACK_SECS);
        let expires_at = now + Duration::from_secs(ttl);

        let mut cache = self.token.lock().await;
        cache.token = Some(resp.access_token.clone());
        cache.expires_at = Some(expires_at);
        Ok(resp.access_token)
    }
}

impl Default for InstallState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn router(state: Arc<InstallState>) -> Router {
    Router::new()
        .route("/install.sh", get(serve_install_sh))
        .route("/install.ps1", get(serve_install_ps1))
        .route("/install_gateway.sh", get(serve_install_gateway_sh))
        .route("/install_gateway.ps1", get(serve_install_gateway_ps1))
        .route("/v1/install/binary", get(stream_binary))
        .route("/v1/install/transparency", get(fetch_transparency_entry))
        .route(
            "/v1/install/transparency-root",
            get(fetch_transparency_root),
        )
        .with_state(state)
}

fn script_response(body: &'static str, ct: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, ct),
            (header::CACHE_CONTROL, "no-cache, max-age=0"),
        ],
        body,
    )
        .into_response()
}

async fn serve_install_sh() -> Response {
    script_response(INSTALL_SH, "text/x-shellscript; charset=utf-8")
}
async fn serve_install_gateway_sh() -> Response {
    script_response(INSTALL_GATEWAY_SH, "text/x-shellscript; charset=utf-8")
}
async fn serve_install_ps1() -> Response {
    script_response(INSTALL_PS1, "text/plain; charset=utf-8")
}
async fn serve_install_gateway_ps1() -> Response {
    script_response(INSTALL_GATEWAY_PS1, "text/plain; charset=utf-8")
}

#[derive(Deserialize)]
struct BinaryQuery {
    artifact: String,
    os: String,
    arch: String,
}

async fn stream_binary(
    State(state): State<Arc<InstallState>>,
    Query(q): Query<BinaryQuery>,
) -> Response {
    let artifact = match q.artifact.as_str() {
        "cli" | "gateway" => q.artifact.as_str(),
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "artifact must be 'cli' or 'gateway'",
            )
        }
    };
    let os = match q.os.as_str() {
        "linux" | "darwin" | "windows" => q.os.as_str(),
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "os must be 'linux', 'darwin', or 'windows'",
            )
        }
    };
    let arch = match q.arch.as_str() {
        "amd64" | "arm64" => q.arch.as_str(),
        _ => return error_response(StatusCode::BAD_REQUEST, "arch must be 'amd64' or 'arm64'"),
    };
    let bin_name = bin_name_for(artifact, os);
    let object = format!("{artifact}/{os}/{arch}/{bin_name}");

    let token = match state.access_token().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "failed to obtain GCS access token");
            return error_response(StatusCode::BAD_GATEWAY, "failed to obtain GCS access token");
        }
    };

    // XML API path-style — no URL-encoding gymnastics required because our
    // object path is constrained to validated [a-z0-9./-] segments.
    let url = format!("https://storage.googleapis.com/{BUCKET}/{object}");
    let sha_url = format!("{url}.sha256");
    let sig_url = format!("{url}.sig");

    // Fetch both integrity sidecars in parallel before streaming the binary:
    //   .sha256 → X-Content-SHA256 header (bucket-tamper detection)
    //   .sig    → X-Content-Signature header, base64'd Ed25519 sig (substitution attack defense)
    // Both are optional — legacy artifacts upload without them and the install
    // script falls back with a visible warning.
    let (sha256, signature) = tokio::join!(
        fetch_sha256(&state.client, &sha_url, &token),
        fetch_signature(&state.client, &sig_url, &token),
    );

    let upstream = match state.client.get(&url).bearer_auth(&token).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, url = %url, "GCS fetch failed");
            return error_response(StatusCode::BAD_GATEWAY, "upstream fetch failed");
        }
    };

    if !upstream.status().is_success() {
        let status = upstream.status();
        let (mapped, body) = if status == reqwest::StatusCode::NOT_FOUND {
            (StatusCode::NOT_FOUND, format!("no binary at {object}"))
        } else {
            (StatusCode::BAD_GATEWAY, format!("upstream status {status}"))
        };
        tracing::warn!(status = %status, object = %object, "GCS returned non-success");
        return error_response(mapped, &body);
    }

    let mut headers = HeaderMap::new();
    if let Some(ct) = upstream.headers().get(reqwest::header::CONTENT_TYPE) {
        if let Ok(v) = HeaderValue::from_bytes(ct.as_bytes()) {
            headers.insert(header::CONTENT_TYPE, v);
        }
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
    }
    if let Some(cl) = upstream.headers().get(reqwest::header::CONTENT_LENGTH) {
        if let Ok(v) = HeaderValue::from_bytes(cl.as_bytes()) {
            headers.insert(header::CONTENT_LENGTH, v);
        }
    }
    let dispo = format!("attachment; filename=\"{bin_name}\"");
    if let Ok(v) = HeaderValue::from_str(&dispo) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(hex) = sha256 {
        if let Ok(v) = HeaderValue::from_str(&hex) {
            headers.insert("x-content-sha256", v);
        }
    }
    if let Some(b64) = signature {
        if let Ok(v) = HeaderValue::from_str(&b64) {
            headers.insert("x-content-signature", v);
        }
    }

    let body = Body::from_stream(upstream.bytes_stream());
    (StatusCode::OK, headers, body).into_response()
}

/// Fetch `<binary>.sha256` from GCS and parse out the 64-char hex hash.
/// Returns None on any failure (404 sidecar, network blip, malformed body) so
/// the caller can fall back to serving without the integrity header.
async fn fetch_sha256(client: &reqwest::Client, url: &str, token: &str) -> Option<String> {
    let resp = client
        .get(url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    // shasum format: "<hex>  <filename>\n" — take first whitespace-delimited token.
    let hex = body.split_whitespace().next()?;
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

/// Fetch `<binary>.sig` (raw 64-byte Ed25519 signature) from GCS and return
/// it as a standard base64 string for the X-Content-Signature header.
/// Returns None on any failure so the caller can serve unsigned.
async fn fetch_signature(client: &reqwest::Client, url: &str, token: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let resp = client
        .get(url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    if bytes.len() != 64 {
        // Ed25519 signatures are always exactly 64 bytes — anything else is
        // a corrupt/wrong-alg sidecar.
        return None;
    }
    Some(B64.encode(&bytes))
}

fn bin_name_for(artifact: &str, os: &str) -> String {
    let base = match artifact {
        "cli" => "lynxx",
        "gateway" => "lynxx-gateway",
        _ => unreachable!("artifact validated upstream"),
    };
    if os == "windows" {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        msg.to_string(),
    )
        .into_response()
}

#[derive(Deserialize)]
struct TransparencyQuery {
    sha256: String,
}

/// Look up the transparency log entry for a given binary sha256.
///
/// Returns the raw canonical entry JSON as the response body, with the
/// Ed25519 signature over those bytes in the X-Transparency-Signature
/// header. Install scripts feed the body directly to openssl pkeyutl
/// -verify; no JSON-string-unescaping required client-side.
///
/// 404 = "no entry for this sha256". Install scripts MUST refuse: a binary
/// with a valid signature but no log entry indicates off-the-record signing.
async fn fetch_transparency_entry(
    State(state): State<Arc<InstallState>>,
    Query(q): Query<TransparencyQuery>,
) -> Response {
    let sha = q.sha256.to_ascii_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return error_response(StatusCode::BAD_REQUEST, "sha256 must be 64 hex chars");
    }

    // The transparency log bucket is public — no GCP auth needed for these
    // reads. List by-sha256/<sha>/ to find all entries for this hash; the
    // lex-max name is the most recent (ISO-8601 timestamps).
    let list_url = format!(
        "https://storage.googleapis.com/storage/v1/b/{TRANSPARENCY_BUCKET}/o?prefix=by-sha256/{sha}/&fields=items(name)"
    );
    let list = match state.client.get(&list_url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "transparency log list failed");
            return error_response(StatusCode::BAD_GATEWAY, "transparency log unreachable");
        }
    };
    if !list.status().is_success() {
        return error_response(StatusCode::BAD_GATEWAY, "transparency log list failed");
    }

    #[derive(Deserialize)]
    struct ListItem {
        name: String,
    }
    #[derive(Deserialize)]
    struct ListResp {
        #[serde(default)]
        items: Vec<ListItem>,
    }

    let parsed: ListResp = match list.json().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "transparency log list parse failed");
            return error_response(StatusCode::BAD_GATEWAY, "transparency log parse failed");
        }
    };

    let entry_name = match parsed
        .items
        .iter()
        .map(|i| i.name.as_str())
        .filter(|n| n.ends_with(".json"))
        .max()
    {
        Some(n) => n.to_string(),
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "no transparency log entry for this sha256",
            )
        }
    };
    let sig_name = format!("{entry_name}.sig");

    let entry_url = format!("https://storage.googleapis.com/{TRANSPARENCY_BUCKET}/{entry_name}");
    let sig_url = format!("https://storage.googleapis.com/{TRANSPARENCY_BUCKET}/{sig_name}");
    let (entry_resp, sig_resp) = tokio::join!(
        state.client.get(&entry_url).send(),
        state.client.get(&sig_url).send(),
    );

    let entry_body = match entry_resp {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => b,
            Err(_) => return error_response(StatusCode::BAD_GATEWAY, "entry body unreadable"),
        },
        _ => return error_response(StatusCode::BAD_GATEWAY, "entry fetch failed"),
    };
    let sig_bytes = match sig_resp {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => b,
            Err(_) => return error_response(StatusCode::BAD_GATEWAY, "sig body unreadable"),
        },
        _ => return error_response(StatusCode::BAD_GATEWAY, "sig fetch failed"),
    };
    if sig_bytes.len() != 64 {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "transparency log entry signature malformed",
        );
    }

    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let sig_b64 = B64.encode(&sig_bytes);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = HeaderValue::from_str(&sig_b64) {
        headers.insert("x-transparency-signature", v);
    }
    if let Ok(v) = HeaderValue::from_str(&entry_name) {
        headers.insert("x-transparency-entry-path", v);
    }
    (StatusCode::OK, headers, entry_body).into_response()
}

/// Return the latest witness-signed log root. The body is the canonical
/// JSON root (sha256 list + metadata), with the Ed25519 witness signature
/// in X-Witness-Signature.
///
/// Install scripts use this to confirm their entry is "covered" by a recent
/// witness attestation. A binary signed by the release key BUT whose
/// transparency entry isn't included in any witness-signed root indicates
/// the release key + bucket were used together off-the-record. Requiring
/// witness coverage forces the attacker to also compromise the witness key.
async fn fetch_transparency_root(State(state): State<Arc<InstallState>>) -> Response {
    let root_url =
        format!("https://storage.googleapis.com/{TRANSPARENCY_BUCKET}/roots/latest-root.json");
    let sig_url =
        format!("https://storage.googleapis.com/{TRANSPARENCY_BUCKET}/roots/latest-root.json.sig");

    let (root_resp, sig_resp) = tokio::join!(
        state.client.get(&root_url).send(),
        state.client.get(&sig_url).send(),
    );

    let root_body = match root_resp {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => b,
            Err(_) => return error_response(StatusCode::BAD_GATEWAY, "root body unreadable"),
        },
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
            return error_response(
                StatusCode::NOT_FOUND,
                "no witness-signed root yet — run scripts/witness-log.sh",
            )
        }
        _ => return error_response(StatusCode::BAD_GATEWAY, "root fetch failed"),
    };
    let sig_bytes = match sig_resp {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => b,
            Err(_) => return error_response(StatusCode::BAD_GATEWAY, "root sig unreadable"),
        },
        _ => return error_response(StatusCode::BAD_GATEWAY, "root sig fetch failed"),
    };
    if sig_bytes.len() != 64 {
        return error_response(StatusCode::BAD_GATEWAY, "witness signature malformed");
    }
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let sig_b64 = B64.encode(&sig_bytes);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = HeaderValue::from_str(&sig_b64) {
        headers.insert("x-witness-signature", v);
    }
    (StatusCode::OK, headers, root_body).into_response()
}
