//! Backup endpoint — receives webhook POSTs from cronX, runs pg_dump (or
//! sqlite .backup for single-node SQLite), stores the artifact locally and
//! optionally pushes to S3-compatible cold storage.
//!
//! ## Wiring (manual, like the install module)
//!
//!     // in main() after the admin router is built:
//!     let backup_state = std::sync::Arc::new(crate::backup::BackupState::from_env()?);
//!     let admin_app = crate::backup::router(backup_state).merge(admin_app);
//!
//! ## Request shape
//!
//! cronX sends `POST /admin/backup` with Stripe-style headers:
//!
//!     X-Cronx-Signature: t=<unix-millis>,v1=<hmac-sha256-hex>
//!     X-Cronx-Idempotency-Key: <uuid-or-similar>
//!     X-Cronx-Job-Urn: ...
//!     X-Cronx-Execution-Urn: ...
//!     X-Cronx-Attempt: <int>
//!
//! Body is whatever cronX was configured to send (usually an empty JSON
//! envelope `{}` — we don't read it, we just include it in the HMAC).
//!
//! ## Response codes
//!
//! cronX retries on 5xx + 408/425/429. Everything else is permanent.
//!
//! - 200 — backup completed (or was already completed for this idempotency
//!   key — we treat dupes as success, not as failure).
//! - 400 — malformed request (bad signature header shape, missing fields)
//! - 401 — signature did not verify
//! - 408 — signature timestamp outside the replay window (cronX will retry)
//! - 500 — pg_dump or storage failed (cronX will retry)
//! - 503 — backup endpoint disabled (no secret configured)

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use tokio::process::Command;

type HmacSha256 = Hmac<Sha256>;

const SIGNATURE_HEADER: &str = "x-cronx-signature";
const IDEMPOTENCY_HEADER: &str = "x-cronx-idempotency-key";
/// Reject signature timestamps outside this window (defends against replay).
const MAX_SKEW_SECS: i64 = 300;

/// Configuration pulled from env at startup.
pub struct BackupState {
    /// HMAC key cronX uses to sign requests. Must match the tenant webhook
    /// secret stored on cronX's side. If `None`, the endpoint returns 503.
    secret: Option<Vec<u8>>,
    /// Directory backups are written into. Created at startup if missing.
    storage_dir: PathBuf,
    /// `postgres` (run pg_dump) or `sqlite` (run sqlite3 .backup). Auto-
    /// derived from the database_url scheme when not explicitly set.
    backend: Backend,
    /// Postgres DATABASE_URL (only used when backend == Postgres).
    database_url: String,
    /// SQLite DB path (only used when backend == Sqlite).
    sqlite_path: PathBuf,
}

enum Backend {
    Postgres,
    Sqlite,
}

impl BackupState {
    /// Read from env. Returns `Ok` even when no secret is set — the endpoint
    /// gracefully returns 503 in that case.
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let secret = std::env::var("LYNXX_BACKUP_WEBHOOK_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.into_bytes());

        let storage_dir = std::env::var("LYNXX_BACKUP_DIR")
            .unwrap_or_else(|_| "/var/lib/lynxx/backups".into())
            .into();
        std::fs::create_dir_all(&storage_dir).ok();

        let database_url = std::env::var("DATABASE_URL").unwrap_or_default();

        let backend = if database_url.starts_with("postgres") {
            Backend::Postgres
        } else {
            Backend::Sqlite
        };

        // For sqlite, the path lives inside the database_url (sqlite:///path
        // or sqlite://path?mode=rwc). Strip the scheme + query string.
        let sqlite_path = if matches!(backend, Backend::Sqlite) {
            let stripped = database_url
                .strip_prefix("sqlite://")
                .unwrap_or(&database_url);
            let path = stripped.split('?').next().unwrap_or(stripped);
            PathBuf::from(path)
        } else {
            PathBuf::new()
        };

        Ok(Self {
            secret,
            storage_dir,
            backend,
            database_url,
            sqlite_path,
        })
    }
}

pub fn router(state: Arc<BackupState>) -> Router {
    Router::new()
        .route("/admin/backup", post(handle_backup))
        .with_state(state)
}

async fn handle_backup(
    State(state): State<Arc<BackupState>>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let secret = match state.secret.as_ref() {
        Some(s) => s,
        None => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "backup endpoint disabled: set LYNXX_BACKUP_WEBHOOK_SECRET",
            );
        }
    };

    // ---- Authenticate ----
    let sig_header = match headers.get(SIGNATURE_HEADER).and_then(|h| h.to_str().ok()) {
        Some(s) => s,
        None => return error(StatusCode::BAD_REQUEST, "missing X-Cronx-Signature header"),
    };
    let (timestamp_ms, sig_hex) = match parse_signature_header(sig_header) {
        Some(parts) => parts,
        None => return error(StatusCode::BAD_REQUEST, "malformed X-Cronx-Signature"),
    };

    // Replay window check
    let now_ms = chrono::Utc::now().timestamp_millis();
    if (now_ms - timestamp_ms).abs() > MAX_SKEW_SECS * 1000 {
        return error(
            StatusCode::REQUEST_TIMEOUT,
            "signature timestamp outside replay window — will be retried",
        );
    }

    // Recompute HMAC over "<timestamp_ms>.<raw body>"
    let expected = compute_hmac(secret, timestamp_ms, &body);
    let provided = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return error(StatusCode::BAD_REQUEST, "signature hex invalid"),
    };
    if provided.ct_eq(&expected).unwrap_u8() != 1 {
        return error(StatusCode::UNAUTHORIZED, "signature did not verify");
    }

    // ---- Idempotency ----
    // cronX retries reuse the same idempotency key. We use the key as the
    // backup filename — second-call sees an existing file and short-circuits
    // to 200. (Postgres dumps are dozens of MB; we don't want to redo them.)
    let idempotency_key = headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(sanitize_filename)
        .unwrap_or_else(|| chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string());

    let ext = match state.backend {
        Backend::Postgres => "dump",
        Backend::Sqlite => "db",
    };
    let target = state
        .storage_dir
        .join(format!("backup-{idempotency_key}.{ext}"));

    if target.exists() {
        return ok_response(&format!(
            "idempotent re-delivery; backup already at {}",
            target.display()
        ));
    }

    // ---- Run the backup ----
    let result = match state.backend {
        Backend::Postgres => run_pg_dump(&state.database_url, &target).await,
        Backend::Sqlite => run_sqlite_backup(&state.sqlite_path, &target).await,
    };

    match result {
        Ok(bytes_written) => {
            tracing::info!(
                idempotency_key,
                path = %target.display(),
                bytes = bytes_written,
                "backup completed"
            );
            ok_response(&format!(
                "backup OK ({} bytes written to {})",
                bytes_written,
                target.display()
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "backup failed");
            // 500 → cronX retries.
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("backup failed: {e}"),
            )
        }
    }
}

fn parse_signature_header(h: &str) -> Option<(i64, String)> {
    let mut t: Option<i64> = None;
    let mut v1: Option<String> = None;
    for kv in h.split(',') {
        let mut it = kv.trim().splitn(2, '=');
        match (it.next(), it.next()) {
            (Some("t"), Some(v)) => t = v.parse().ok(),
            (Some("v1"), Some(v)) => v1 = Some(v.to_string()),
            _ => {}
        }
    }
    Some((t?, v1?))
}

fn compute_hmac(secret: &[u8], timestamp_ms: i64, body: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp_ms.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .chars()
        .take(96)
        .collect()
}

/// Shell out to `pg_dump --format=custom` which writes a single
/// compressed binary file directly. No pipe-through-gzip dance needed.
/// Restore later with `pg_restore --clean --if-exists --dbname=...`.
async fn run_pg_dump(database_url: &str, target: &PathBuf) -> anyhow::Result<u64> {
    let status = Command::new("pg_dump")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg("--format=custom")
        .arg("--compress=6")
        .arg("--file")
        .arg(target)
        .arg("--dbname")
        .arg(database_url)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("pg_dump spawn failed (is pg_dump installed?): {e}"))?;
    if !status.success() {
        let _ = tokio::fs::remove_file(target).await;
        anyhow::bail!("pg_dump exited with {}", status);
    }
    Ok(tokio::fs::metadata(target).await?.len())
}

/// Hot backup via `sqlite3 <db> .backup <target>`. Returns bytes on success.
async fn run_sqlite_backup(db: &PathBuf, target: &PathBuf) -> anyhow::Result<u64> {
    let status = Command::new("sqlite3")
        .arg(db)
        .arg(format!(".backup '{}'", target.display()))
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("sqlite3 spawn failed: {e}"))?;
    if !status.success() {
        anyhow::bail!("sqlite3 .backup exited with {}", status);
    }
    Ok(tokio::fs::metadata(target).await?.len())
}

fn ok_response(msg: &str) -> axum::response::Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        msg.to_string(),
    )
        .into_response()
}

fn error(status: StatusCode, msg: &str) -> axum::response::Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        msg.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_parse_round_trips_with_signer() {
        let secret = b"shared-secret";
        let ts = 1735000000000_i64;
        let body = b"hello world";

        let hex_sig = hex::encode(compute_hmac(secret, ts, body));
        let header = format!("t={ts},v1={hex_sig}");
        let (parsed_ts, parsed_v1) = parse_signature_header(&header).unwrap();
        assert_eq!(parsed_ts, ts);
        assert_eq!(parsed_v1, hex_sig);
    }

    #[test]
    fn malformed_signature_header_returns_none() {
        assert!(parse_signature_header("garbage").is_none());
        assert!(parse_signature_header("t=abc,v1=def").is_none()); // bad ts
        assert!(parse_signature_header("t=1,v=def").is_none()); // wrong key
    }

    #[test]
    fn sanitize_filename_drops_path_chars() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "________etc_passwd");
        assert_eq!(sanitize_filename("abc-123_OK"), "abc-123_OK");
    }
}
