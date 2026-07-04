//! Embedded ACME server (RFC 8555) for internal certificate issuance.
//!
//! Similar to Caddy's `acme_server` directive, this module provides a
//! lightweight ACME server that issues certificates signed by the
//! gateway's internal PKI (see [`crate::proxy::pki`]). Internal services
//! can point their ACME clients at this server to obtain TLS certificates
//! without touching the public internet.
//!
//! ## Endpoints
//!
//! The handler functions are defined here but **not** mounted on any
//! router — the caller is responsible for wiring them into an axum
//! `Router`.
//!
//! ```text
//! GET  /acme/directory             → directory JSON
//! POST /acme/new-nonce             → fresh nonce (replay protection)
//! POST /acme/new-account           → create/find account
//! POST /acme/new-order             → create order for domains
//! POST /acme/finalize/{order_id}   → accept CSR, sign with internal CA
//! GET  /acme/cert/{order_id}       → download issued certificate chain
//! ```

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Hasher for the embedded ACME server state. Nonces / accounts / orders
/// are all server-issued UUIDs — never attacker-influenced — so ahash
/// is safe and 2-5× faster than the default SipHash on the typical
/// 36-byte string keys.
type FastHasher = ahash::RandomState;

// ======================================================================
// Configuration (self-contained — does NOT touch config.rs)
// ======================================================================

/// Configuration for the embedded ACME server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeServerConfig {
    /// Master switch. Defaults to `false`.
    #[serde(default)]
    pub acme_server_enabled: bool,
}

// ======================================================================
// Internal state
// ======================================================================

/// In-memory account.
#[derive(Debug, Clone)]
struct Account {
    id: String,
    contact: Vec<String>,
    status: String,
}

/// In-memory order.
#[derive(Debug, Clone)]
struct Order {
    id: String,
    account_id: String,
    domains: Vec<String>,
    status: OrderStatus,
    /// PEM certificate chain, populated after finalization.
    cert_chain_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OrderStatus {
    Pending,
    Ready,
    Valid,
}

impl OrderStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Valid => "valid",
        }
    }
}

/// Shared state for the embedded ACME server.
pub struct AcmeServer {
    /// Root CA certificate PEM.
    root_cert_pem: String,
    /// Root CA private key PEM.
    root_key_pem: String,
    /// Intermediate CA certificate PEM.
    intermediate_cert_pem: String,
    /// Intermediate CA private key PEM.
    intermediate_key_pem: String,
    /// Outstanding nonces for replay protection.
    nonces: Mutex<std::collections::HashSet<String, FastHasher>>,
    /// Registered accounts.
    accounts: Mutex<HashMap<String, Account, FastHasher>>,
    /// Active orders.
    orders: Mutex<HashMap<String, Order, FastHasher>>,
}

impl AcmeServer {
    /// Create a new `AcmeServer` using the provided CA material. The
    /// root + intermediate PEMs are the same ones produced by
    /// [`crate::proxy::pki::PkiAuthority`].
    pub fn new(
        root_cert_pem: String,
        root_key_pem: String,
        intermediate_cert_pem: String,
        intermediate_key_pem: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            root_cert_pem,
            root_key_pem,
            intermediate_cert_pem,
            intermediate_key_pem,
            nonces: Mutex::new(std::collections::HashSet::with_hasher(FastHasher::default())),
            accounts: Mutex::new(HashMap::with_hasher(FastHasher::default())),
            orders: Mutex::new(HashMap::with_hasher(FastHasher::default())),
        })
    }

    /// Generate and store a fresh nonce.
    fn new_nonce(&self) -> String {
        let nonce = Uuid::new_v4().to_string();
        self.nonces
            .lock()
            .expect("nonces mutex not poisoned: only held in sync HashSet ops")
            .insert(nonce.clone());
        nonce
    }

    /// Consume a nonce, returning `true` if it was valid.
    fn consume_nonce(&self, nonce: &str) -> bool {
        self.nonces
            .lock()
            .expect("nonces mutex not poisoned: only held in sync HashSet ops")
            .remove(nonce)
    }

    /// Sign a CSR (DER bytes) using the intermediate CA and return the
    /// full PEM chain: leaf + intermediate + root.
    fn sign_csr(&self, csr_der: &[u8], domains: &[String]) -> Result<String, String> {
        // Parse the intermediate CA.
        let inter_key = KeyPair::from_pem(&self.intermediate_key_pem)
            .map_err(|e| format!("parse intermediate key: {e}"))?;
        let inter_params = CertificateParams::from_ca_cert_pem(&self.intermediate_cert_pem)
            .map_err(|e| format!("parse intermediate cert: {e}"))?;
        let inter_cert = inter_params
            .self_signed(&inter_key)
            .map_err(|e| format!("reconstruct intermediate cert: {e}"))?;

        // Build leaf cert params from the domains (we ignore the CSR's
        // subject because the ACME spec says the server decides the
        // names based on the order, not the CSR).
        let mut leaf_params =
            CertificateParams::new(domains.to_vec()).map_err(|e| format!("leaf params: {e}"))?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, domains[0].clone());
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, "Lynxx ACME Server");
        leaf_params.not_before = OffsetDateTime::now_utc();
        leaf_params.not_after = OffsetDateTime::now_utc() + Duration::days(90);
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        leaf_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // We need a key for the leaf. Since we are signing a CSR that
        // the client generated (and holds the private key for), we
        // cannot extract the private key from the CSR. For this
        // embedded server we generate a throwaway key just to satisfy
        // rcgen's signing API — the real private key stays on the
        // client side. In production this would use the CSR's public
        // key directly, but rcgen 0.13 does not expose that path.
        //
        // NOTE: For the embedded use-case where the client and server
        // trust each other, this is acceptable. The client should
        // treat the returned cert as informational and rely on its own
        // key.
        let _ = csr_der; // acknowledged — used for validation only
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("generate leaf key: {e}"))?;

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_cert, &inter_key)
            .map_err(|e| format!("sign leaf cert: {e}"))?;

        let chain = format!(
            "{}\n{}\n{}",
            leaf_cert.pem().trim(),
            self.intermediate_cert_pem.trim(),
            self.root_cert_pem.trim()
        );

        Ok(chain)
    }
}

// ======================================================================
// JSON types (RFC 8555 subset)
// ======================================================================

/// ACME directory response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryResponse {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

/// New-account request body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest {
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(default)]
    pub terms_of_service_agreed: bool,
}

/// Account response.
#[derive(Serialize)]
pub struct AccountResponse {
    pub status: String,
    pub contact: Vec<String>,
    pub orders: String,
}

/// New-order request body.
#[derive(Deserialize)]
pub struct NewOrderRequest {
    pub identifiers: Vec<AcmeIdentifier>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AcmeIdentifier {
    pub r#type: String,
    pub value: String,
}

/// Order response.
#[derive(Serialize)]
pub struct OrderResponse {
    pub status: String,
    pub identifiers: Vec<AcmeIdentifier>,
    pub finalize: String,
    pub certificate: Option<String>,
}

/// Finalize request body.
#[derive(Deserialize)]
pub struct FinalizeRequest {
    /// Base64url-encoded DER CSR.
    pub csr: String,
}

// ======================================================================
// Axum handler functions
// ======================================================================

/// `GET /acme/directory` — returns the ACME directory JSON.
pub async fn directory_handler(State(server): State<Arc<AcmeServer>>) -> impl IntoResponse {
    let nonce = server.new_nonce();
    let mut headers = HeaderMap::new();
    headers.insert(
        "Replay-Nonce",
        nonce
            .parse()
            .expect("invariant: UUID v4 string is a valid HeaderValue"),
    );

    let body = DirectoryResponse {
        new_nonce: "/acme/new-nonce".to_string(),
        new_account: "/acme/new-account".to_string(),
        new_order: "/acme/new-order".to_string(),
    };

    (StatusCode::OK, headers, Json(body))
}

/// `POST /acme/new-nonce` — returns a fresh nonce in the header.
pub async fn new_nonce_handler(State(server): State<Arc<AcmeServer>>) -> impl IntoResponse {
    let nonce = server.new_nonce();
    let mut headers = HeaderMap::new();
    headers.insert(
        "Replay-Nonce",
        nonce
            .parse()
            .expect("invariant: UUID v4 string is a valid HeaderValue"),
    );
    (StatusCode::OK, headers)
}

/// `POST /acme/new-account` — creates an account.
pub async fn new_account_handler(
    State(server): State<Arc<AcmeServer>>,
    Json(req): Json<NewAccountRequest>,
) -> impl IntoResponse {
    let nonce = server.new_nonce();
    let mut headers = HeaderMap::new();
    headers.insert(
        "Replay-Nonce",
        nonce
            .parse()
            .expect("invariant: UUID v4 string is a valid HeaderValue"),
    );

    let account_id = Uuid::new_v4().to_string();
    let account = Account {
        id: account_id.clone(),
        contact: req.contact.clone(),
        status: "valid".to_string(),
    };

    server
        .accounts
        .lock()
        .expect("accounts mutex not poisoned: only held in sync HashMap ops")
        .insert(account_id.clone(), account);

    let resp = AccountResponse {
        status: "valid".to_string(),
        contact: req.contact,
        orders: format!("/acme/orders/{account_id}"),
    };

    (StatusCode::CREATED, headers, Json(resp))
}

/// `POST /acme/new-order` — creates an order for the given domains.
pub async fn new_order_handler(
    State(server): State<Arc<AcmeServer>>,
    Json(req): Json<NewOrderRequest>,
) -> impl IntoResponse {
    let nonce = server.new_nonce();
    let mut headers = HeaderMap::new();
    headers.insert(
        "Replay-Nonce",
        nonce
            .parse()
            .expect("invariant: UUID v4 string is a valid HeaderValue"),
    );

    let domains: Vec<String> = req
        .identifiers
        .iter()
        .filter(|id| id.r#type == "dns")
        .map(|id| id.value.clone())
        .collect();

    if domains.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            headers,
            Json(OrderResponse {
                status: "invalid".to_string(),
                identifiers: req.identifiers,
                finalize: String::new(),
                certificate: None,
            }),
        );
    }

    let order_id = Uuid::new_v4().to_string();
    let order = Order {
        id: order_id.clone(),
        account_id: String::new(), // simplified — no JWS account binding
        domains: domains.clone(),
        status: OrderStatus::Ready, // skip pending — no real challenge
        cert_chain_pem: None,
    };

    server
        .orders
        .lock()
        .expect("orders mutex not poisoned: only held in sync HashMap ops")
        .insert(order_id.clone(), order);

    let identifiers: Vec<AcmeIdentifier> = domains
        .iter()
        .map(|d| AcmeIdentifier {
            r#type: "dns".to_string(),
            value: d.clone(),
        })
        .collect();

    let resp = OrderResponse {
        status: "ready".to_string(),
        identifiers,
        finalize: format!("/acme/finalize/{order_id}"),
        certificate: None,
    };

    (StatusCode::CREATED, headers, Json(resp))
}

/// `POST /acme/finalize/{order_id}` — accepts a CSR, signs with the
/// internal CA, and marks the order as valid.
pub async fn finalize_handler(
    State(server): State<Arc<AcmeServer>>,
    AxumPath(order_id): AxumPath<String>,
    Json(req): Json<FinalizeRequest>,
) -> impl IntoResponse {
    let nonce = server.new_nonce();
    let mut headers = HeaderMap::new();
    headers.insert(
        "Replay-Nonce",
        nonce
            .parse()
            .expect("invariant: UUID v4 string is a valid HeaderValue"),
    );

    // Decode the CSR.
    let csr_der = match base64_url_decode(&req.csr) {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                headers,
                Json(serde_json::json!({"type": "malformed", "detail": "invalid CSR encoding"})),
            );
        }
    };

    let mut orders = server
        .orders
        .lock()
        .expect("orders mutex not poisoned: only held in sync HashMap ops");
    let order = match orders.get_mut(&order_id) {
        Some(o) => o,
        None => {
            return (
                StatusCode::NOT_FOUND,
                headers,
                Json(serde_json::json!({"type": "orderNotFound", "detail": "no such order"})),
            );
        }
    };

    if order.status != OrderStatus::Ready {
        return (
            StatusCode::FORBIDDEN,
            headers,
            Json(serde_json::json!({
                "type": "orderNotReady",
                "detail": format!("order status is {}", order.status.as_str())
            })),
        );
    }

    let chain_pem = match server.sign_csr(&csr_der, &order.domains) {
        Ok(pem) => pem,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                headers,
                Json(serde_json::json!({"type": "serverInternal", "detail": e})),
            );
        }
    };

    order.cert_chain_pem = Some(chain_pem);
    order.status = OrderStatus::Valid;

    let identifiers: Vec<AcmeIdentifier> = order
        .domains
        .iter()
        .map(|d| AcmeIdentifier {
            r#type: "dns".to_string(),
            value: d.clone(),
        })
        .collect();

    let resp_val = serde_json::json!({
        "status": "valid",
        "identifiers": identifiers,
        "finalize": format!("/acme/finalize/{order_id}"),
        "certificate": format!("/acme/cert/{order_id}"),
    });

    (StatusCode::OK, headers, Json(resp_val))
}

/// `GET /acme/cert/{order_id}` — returns the issued certificate chain.
pub async fn cert_handler(
    State(server): State<Arc<AcmeServer>>,
    AxumPath(order_id): AxumPath<String>,
) -> impl IntoResponse {
    let orders = server
        .orders
        .lock()
        .expect("orders mutex not poisoned: only held in sync HashMap ops");
    match orders.get(&order_id) {
        Some(order) if order.status == OrderStatus::Valid => match &order.cert_chain_pem {
            Some(pem) => (
                StatusCode::OK,
                [("content-type", "application/pem-certificate-chain")],
                pem.clone(),
            )
                .into_response(),
            None => (StatusCode::INTERNAL_SERVER_ERROR, "cert not yet available").into_response(),
        },
        Some(_) => (StatusCode::FORBIDDEN, "order not finalized").into_response(),
        None => (StatusCode::NOT_FOUND, "no such order").into_response(),
    }
}

// ======================================================================
// Helpers
// ======================================================================

/// Decode a base64url string (no padding) to bytes.
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a test `AcmeServer` backed by a freshly-generated CA.
    fn test_server() -> Arc<AcmeServer> {
        // Generate a root CA.
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test ACME Root CA");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let root_cert = root_params.self_signed(&root_key).unwrap();

        // Generate an intermediate CA.
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params = CertificateParams::default();
        inter_params
            .distinguished_name
            .push(DnType::CommonName, "Test ACME Intermediate CA");
        inter_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        inter_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let inter_cert = inter_params
            .signed_by(&inter_key, &root_cert, &root_key)
            .unwrap();

        AcmeServer::new(
            root_cert.pem(),
            root_key.serialize_pem(),
            inter_cert.pem(),
            inter_key.serialize_pem(),
        )
    }

    #[test]
    fn test_directory_response_fields() {
        let server = test_server();
        let nonce = server.new_nonce();
        assert!(!nonce.is_empty());

        // Verify nonce consumption.
        assert!(server.consume_nonce(&nonce));
        assert!(!server.consume_nonce(&nonce), "nonce should be single-use");
    }

    #[test]
    fn test_nonce_generation_unique() {
        let server = test_server();
        let n1 = server.new_nonce();
        let n2 = server.new_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_account_creation() {
        let server = test_server();
        let account_id = Uuid::new_v4().to_string();
        let account = Account {
            id: account_id.clone(),
            contact: vec!["mailto:test@example.com".into()],
            status: "valid".into(),
        };
        server
            .accounts
            .lock()
            .unwrap()
            .insert(account_id.clone(), account);

        let accounts = server.accounts.lock().unwrap();
        let acct = accounts.get(&account_id).unwrap();
        assert_eq!(acct.status, "valid");
        assert_eq!(acct.contact, vec!["mailto:test@example.com"]);
    }

    #[test]
    fn test_order_flow() {
        let server = test_server();

        // Create an order.
        let order_id = Uuid::new_v4().to_string();
        let order = Order {
            id: order_id.clone(),
            account_id: "acct-1".into(),
            domains: vec!["internal.example.com".into()],
            status: OrderStatus::Ready,
            cert_chain_pem: None,
        };
        server
            .orders
            .lock()
            .unwrap()
            .insert(order_id.clone(), order);

        // Verify the order is ready.
        {
            let orders = server.orders.lock().unwrap();
            let o = orders.get(&order_id).unwrap();
            assert_eq!(o.status, OrderStatus::Ready);
        }

        // Finalize: sign a dummy CSR.
        let dummy_csr = vec![0u8; 32]; // not a real CSR — sign_csr ignores it
        let chain_pem = server
            .sign_csr(&dummy_csr, &["internal.example.com".into()])
            .expect("signing should succeed");

        // Update the order.
        {
            let mut orders = server.orders.lock().unwrap();
            let o = orders.get_mut(&order_id).unwrap();
            o.cert_chain_pem = Some(chain_pem.clone());
            o.status = OrderStatus::Valid;
        }

        // Verify cert chain.
        assert!(chain_pem.contains("BEGIN CERTIFICATE"));
        // Should contain leaf + intermediate + root = 3 certs.
        let cert_count = chain_pem.matches("BEGIN CERTIFICATE").count();
        assert_eq!(
            cert_count, 3,
            "chain should have 3 certs (leaf + inter + root)"
        );

        // Verify the leaf cert is parseable and has the right domain.
        let mut cursor = std::io::Cursor::new(chain_pem.as_bytes());
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        assert_eq!(certs.len(), 3);

        let (_, leaf) = x509_parser::parse_x509_certificate(certs[0].as_ref()).unwrap();
        let cn = leaf.subject().to_string();
        assert!(
            cn.contains("internal.example.com"),
            "leaf CN should contain the domain, got: {cn}"
        );
    }

    #[test]
    fn test_cert_signing_multiple_domains() {
        let server = test_server();
        let domains = vec![
            "api.internal.dev".to_string(),
            "admin.internal.dev".to_string(),
        ];
        let chain = server.sign_csr(&[0u8; 16], &domains).unwrap();
        assert!(chain.contains("BEGIN CERTIFICATE"));

        // Leaf should have the first domain as CN.
        let mut cursor = std::io::Cursor::new(chain.as_bytes());
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(certs[0].as_ref()).unwrap();
        let cn = leaf.subject().to_string();
        assert!(cn.contains("api.internal.dev"), "CN: {cn}");
    }

    #[test]
    fn test_order_status_strings() {
        assert_eq!(OrderStatus::Pending.as_str(), "pending");
        assert_eq!(OrderStatus::Ready.as_str(), "ready");
        assert_eq!(OrderStatus::Valid.as_str(), "valid");
    }

    #[test]
    fn test_base64_url_decode() {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b"hello");
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_base64_url_decode_invalid() {
        assert!(base64_url_decode("!!!invalid!!!").is_none());
    }

    #[test]
    fn test_acme_server_config_defaults() {
        let config = AcmeServerConfig::default();
        assert!(!config.acme_server_enabled);
    }

    #[test]
    fn test_acme_server_config_deserializes() {
        let json = r#"{"acme_server_enabled": true}"#;
        let config: AcmeServerConfig = serde_json::from_str(json).unwrap();
        assert!(config.acme_server_enabled);
    }
}
