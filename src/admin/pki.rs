use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::Certificate;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// GET /certificates — list certificates (optionally filtered by service)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CertQuery {
    #[serde(default)]
    pub service_id: Option<Uuid>,
}

pub async fn list_certificates(
    State(state): State<AdminState>,
    Query(q): Query<CertQuery>,
) -> Result<Json<Vec<Certificate>>, GatewayError> {
    let certs = state
        .repo
        .list_certificates(q.service_id.as_ref())
        .await?;
    Ok(Json(certs))
}

// ---------------------------------------------------------------------------
// GET /certificates/:id — get a single certificate
// ---------------------------------------------------------------------------

pub async fn get_certificate(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Certificate>, GatewayError> {
    let cert = state
        .repo
        .get_certificate(&id)
        .await?
        .ok_or(GatewayError::NotFound("certificate not found".into()))?;
    Ok(Json(cert))
}

// ---------------------------------------------------------------------------
// POST /certificates — create/register a new certificate
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateCertificateBody {
    #[serde(default)]
    pub service_id: Option<Uuid>,
    pub domain: String,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default)]
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    #[serde(default)]
    pub fingerprint_sha256: String,
    #[serde(default = "default_auto_renew")]
    pub auto_renew: bool,
    #[serde(default = "default_cert_status")]
    pub status: String,
}

fn default_issuer() -> String {
    "unknown".into()
}
fn default_auto_renew() -> bool {
    true
}
fn default_cert_status() -> String {
    "active".into()
}

pub async fn create_certificate(
    State(state): State<AdminState>,
    Json(body): Json<CreateCertificateBody>,
) -> Result<(StatusCode, Json<Certificate>), GatewayError> {
    let now = Utc::now();
    let cert = Certificate {
        id: Uuid::new_v4(),
        service_id: body.service_id,
        domain: body.domain,
        issuer: body.issuer,
        serial_number: if body.serial_number.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            body.serial_number
        },
        not_before: body.not_before,
        not_after: body.not_after,
        fingerprint_sha256: if body.fingerprint_sha256.is_empty() {
            format!("{:064x}", Uuid::new_v4().as_u128())
        } else {
            body.fingerprint_sha256
        },
        auto_renew: body.auto_renew,
        status: body.status,
        created_at: now,
        updated_at: now,
    };
    state.repo.create_certificate(&cert).await?;
    Ok((StatusCode::CREATED, Json(cert)))
}

// ---------------------------------------------------------------------------
// DELETE /certificates/:id — delete a certificate
// ---------------------------------------------------------------------------

pub async fn delete_certificate(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, GatewayError> {
    if state.repo.delete_certificate(&id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("certificate not found".into()))
    }
}
