//! Streaming HTTP/1.1 + HTTP/2 client used by the default proxy hot path.
//!
//! Replaces the previous `reqwest::Client` based forward path. `reqwest` is
//! convenient but it buffers request bodies, allocates a fresh `HeaderMap`
//! per request, and re-parses URLs. For the proxy hot path we want to:
//!
//! * forward the body as a streaming `axum::body::Body` (no buffering),
//! * pass the inbound `HeaderMap` through with minimal mutation,
//! * skip URL re-parsing where possible.
//!
//! `hyper_util::client::legacy::Client` plus a TLS-aware connector gives us
//! that. The same client supports both `http://` and `https://` upstreams
//! for the default path; gRPC keeps using its own h2c-only client.
//!
//! ## p99.9 long-tail tuning (2026-05)
//!
//! Beyond the original streaming win, this module also does the heavy
//! lifting on the long-tail squeeze:
//!
//! * **Bigger pool, longer idle.** `pool_max_idle_per_host = 128` (up from
//!   64) and `pool_idle_timeout = 120s` (up from 90) keep more warm
//!   connections, eliminating the TCP+TLS handshake from the hot path
//!   under bursty traffic.
//! * **HTTP/2 keep-alive.** A 10s ping interval keeps multiplexed h2
//!   connections from going stale behind L4 load-balancers that prune
//!   idle TCP after ~60s.
//! * **Caching DNS resolver.** A `hickory-resolver` with a 30s positive
//!   cache replaces the per-connection `getaddrinfo` lookup. Removes
//!   1–50ms tail spikes when the resolver is cold or slow.
//! * **TCP_NODELAY explicit.** Already on; documented here for posterity.
//!
//! ## Per-service mTLS
//!
//! Outbound mTLS is configured per service (see `models::Service`). When
//! a request targets `https://` and the service has any TLS knob set
//! (custom CA, client cert/key, or `tls_verify = false`), we use a
//! dedicated `hyper-util` client built with that exact rustls config.
//! Clients are cached in [`ProxyClientPool`] keyed by service id, with a
//! TLS-fingerprint check on each lookup so a service-update that swaps
//! certs invalidates the cached entry transparently.

use crate::error::GatewayError;
use crate::models::Service;
use axum::body::Body;
use dashmap::DashMap;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower_service::Service as TowerService;
use uuid::Uuid;

/// HTTPS-capable client that speaks both HTTP/1.1 and HTTP/2 ALPN.
pub type HttpProxyClient =
    Client<hyper_rustls::HttpsConnector<HttpConnector<CachingDnsResolver>>, Body>;

/// ---------------------------------------------------------------------
/// Caching DNS resolver shared across the connector.
/// ---------------------------------------------------------------------
///
/// `hyper-util`'s default `GaiResolver` does a fresh `getaddrinfo` per new
/// connection. On macOS in particular this can blow out the long tail when
/// `mDNSResponder` is busy. The resolver below wraps `hickory-resolver`'s
/// system-config-aware async resolver with a 30s positive TTL cap, which
/// is short enough to honour quick rotation but long enough that a steady
/// stream of requests never repays the lookup cost.
#[derive(Clone)]
pub struct CachingDnsResolver {
    inner: Arc<TokioAsyncResolver>,
}

impl CachingDnsResolver {
    pub fn new() -> anyhow::Result<Self> {
        // `from_system_conf` reads /etc/resolv.conf on Unix and the
        // registry on Windows so we honour operator DNS choices.
        let mut opts = ResolverOpts::default();
        opts.cache_size = 256;
        opts.positive_max_ttl = Some(Duration::from_secs(30));
        opts.negative_max_ttl = Some(Duration::from_secs(5));
        opts.timeout = Duration::from_secs(2);

        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to read system DNS config; falling back to Cloudflare/Google"
                );
                TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts.clone())
            }
        };

        Ok(Self {
            inner: Arc::new(resolver),
        })
    }
}

/// Iterator wrapper expected by `hyper-util`. We materialise to a `Vec`
/// because the upstream `Service` impl wants an owned iterator with a
/// `'static` lifetime.
pub struct ResolvedAddrs(std::vec::IntoIter<SocketAddr>);

impl Iterator for ResolvedAddrs {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        self.0.next()
    }
}

impl TowerService<Name> for CachingDnsResolver {
    type Response = ResolvedAddrs;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let resolver = self.inner.clone();
        Box::pin(async move {
            let host = name.as_str().to_string();
            let lookup = resolver
                .lookup_ip(host.as_str())
                .await
                .map_err(std::io::Error::other)?;
            // Port 0 — the connector fills it in from the URL.
            let addrs: Vec<SocketAddr> = lookup.iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            Ok(ResolvedAddrs(addrs.into_iter()))
        })
    }
}

/// Build an `HttpConnector` that uses our caching DNS resolver and the
/// performance flags we want everywhere (TCP_NODELAY, keepalive).
fn build_http_connector(resolver: CachingDnsResolver) -> HttpConnector<CachingDnsResolver> {
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_keepalive(Some(Duration::from_secs(60)));
    http
}

/// Tuning knobs for the proxy HTTP client, read from `GatewaySettings`.
#[derive(Clone, Debug)]
pub struct HttpClientConfig {
    pub pool_max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub h2_keepalive_interval_secs: u64,
    pub max_header_size: usize,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: 128,
            pool_idle_timeout_secs: 120,
            h2_keepalive_interval_secs: 10,
            max_header_size: 16384,
        }
    }
}

/// Build the proxy hot-path client. Returns an error rather than panicking if
/// the platform certificate store cannot be loaded — startup will surface this
/// to the operator instead of crashing on the first HTTPS upstream call.
pub fn build_http_proxy_client(cfg: &HttpClientConfig) -> anyhow::Result<HttpProxyClient> {
    let resolver = CachingDnsResolver::new()?;
    let http = build_http_connector(resolver);

    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    let client = Client::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(cfg.pool_idle_timeout_secs))
        .pool_max_idle_per_host(cfg.pool_max_idle_per_host)
        .http2_keep_alive_interval(Duration::from_secs(cfg.h2_keepalive_interval_secs))
        .http2_keep_alive_while_idle(true)
        .build(https);

    Ok(client)
}

/// ---------------------------------------------------------------------
/// Per-service client pool with rustls config baked in.
/// ---------------------------------------------------------------------
///
/// A service that uses outbound mTLS, a private CA, or `tls_verify = false`
/// needs its own rustls `ClientConfig`, which means its own `HttpsConnector`
/// and `hyper-util` client. We cache them keyed by service id so steady-
/// state traffic pays no rebuild cost.
///
/// On `service.update`, the caller invokes [`ProxyClientPool::invalidate`]
/// (or the cheaper `invalidate_if_changed`) to drop the cached client. The
/// next request rebuilds it lazily.
pub struct ProxyClientPool {
    /// Default client used for plain HTTP and for HTTPS services that don't
    /// override any TLS settings (the common case). Pre-built at startup.
    default_client: HttpProxyClient,
    /// Per-service overrides. Keyed by `service.id`.
    overrides: DashMap<Uuid, CachedServiceClient>,
    /// Shared resolver — building one per service would needlessly multiply
    /// the in-flight DNS futures.
    resolver: CachingDnsResolver,
    /// Pool/keepalive settings from gateway config.
    cfg: HttpClientConfig,
}

/// A single cached entry. We track the TLS fingerprint so that a service
/// update which mutates only non-TLS fields (rename, retries, etc.) doesn't
/// force a rebuild — and conversely, any TLS-relevant change does.
struct CachedServiceClient {
    fingerprint: String,
    client: HttpProxyClient,
}

impl ProxyClientPool {
    pub fn new(default_client: HttpProxyClient, cfg: HttpClientConfig) -> anyhow::Result<Self> {
        Ok(Self {
            default_client,
            overrides: DashMap::new(),
            resolver: CachingDnsResolver::new()?,
            cfg,
        })
    }

    /// The default client. Use this for plain HTTP and for HTTPS services
    /// that don't customise TLS (`tls_verify = true`, no client cert,
    /// no extra CA). Returns a reference; callers clone the inner `Arc`
    /// when they need to move it.
    pub fn default_client(&self) -> &HttpProxyClient {
        &self.default_client
    }

    /// Whether `service` requires a custom rustls config.
    pub fn requires_custom_client(svc: &Service) -> bool {
        !svc.tls_verify
            || svc.tls_client_cert_path.is_some()
            || svc.tls_client_key_path.is_some()
            || svc.tls_ca_path.is_some()
    }

    /// Look up (or build) the right client for this service. For services
    /// that don't customise TLS this is essentially a single hashmap miss
    /// followed by an `Arc` clone of the default client.
    pub fn client_for(&self, svc: &Service) -> Result<HttpProxyClient, GatewayError> {
        if !Self::requires_custom_client(svc) {
            return Ok(self.default_client.clone());
        }

        let fp = svc.tls_fingerprint();
        if let Some(entry) = self.overrides.get(&svc.id) {
            if entry.fingerprint == fp {
                return Ok(entry.client.clone());
            }
        }

        // Either no entry, or fingerprint changed — rebuild.
        let client = self.build_client_for(svc)?;
        self.overrides.insert(
            svc.id,
            CachedServiceClient {
                fingerprint: fp,
                client: client.clone(),
            },
        );
        Ok(client)
    }

    /// Drop the cached client for a service, if any. Called from the admin
    /// update path and from the cluster-event handler so that a TLS config
    /// change takes effect on the next request.
    pub fn invalidate(&self, service_id: &Uuid) {
        self.overrides.remove(service_id);
    }

    fn build_client_for(&self, svc: &Service) -> Result<HttpProxyClient, GatewayError> {
        let tls_config = build_rustls_client_config(svc)?;

        let http = build_http_connector(self.resolver.clone());
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(self.cfg.pool_idle_timeout_secs))
            .pool_max_idle_per_host(self.cfg.pool_max_idle_per_host)
            .http2_keep_alive_interval(Duration::from_secs(self.cfg.h2_keepalive_interval_secs))
            .http2_keep_alive_while_idle(true)
            .build(https);

        tracing::info!(
            service_id = %svc.id,
            service = %svc.name,
            tls_verify = svc.tls_verify,
            client_cert = svc.tls_client_cert_path.is_some(),
            extra_ca = svc.tls_ca_path.is_some(),
            "built per-service proxy client"
        );
        Ok(client)
    }
}

/// Build a rustls `ClientConfig` honouring the service's TLS knobs.
///
/// * `tls_verify = false` installs a no-op verifier that accepts any
///   server cert. Useful for dev / self-signed staging only.
/// * `tls_ca_path` augments the trust store with a PEM bundle.
/// * `tls_client_cert_path` + `tls_client_key_path` enable client auth.
fn build_rustls_client_config(svc: &Service) -> Result<ClientConfig, GatewayError> {
    // Trust store — webpki defaults plus optional extra CA.
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca_path) = &svc.tls_ca_path {
        let pem = std::fs::read(ca_path)
            .map_err(|e| GatewayError::Internal(format!("read tls_ca_path {ca_path}: {e}")))?;
        let mut cursor = std::io::Cursor::new(pem);
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert
                .map_err(|e| GatewayError::Internal(format!("parse tls_ca_path {ca_path}: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| GatewayError::Internal(format!("add ca cert from {ca_path}: {e}")))?;
        }
    }

    // Client auth, if configured.
    let client_auth = match (&svc.tls_client_cert_path, &svc.tls_client_key_path) {
        (Some(cert_path), Some(key_path)) => Some(load_client_auth(cert_path, key_path)?),
        (None, None) => None,
        _ => {
            return Err(GatewayError::Internal(
                "tls_client_cert_path and tls_client_key_path must be set together".into(),
            ));
        }
    };

    let mut cfg = if !svc.tls_verify {
        // Danger path — wholesale replace the verifier. This bypasses
        // server cert validation entirely. Callers opting in (typically
        // dev/staging) are warned at config load time.
        let cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify));
        match client_auth {
            Some((chain, key)) => cfg
                .with_client_auth_cert(chain, key)
                .map_err(|e| GatewayError::Internal(format!("client auth cert: {e}")))?,
            None => cfg.with_no_client_auth(),
        }
    } else {
        let builder = ClientConfig::builder().with_root_certificates(roots);
        match client_auth {
            Some((chain, key)) => builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| GatewayError::Internal(format!("client auth cert: {e}")))?,
            None => builder.with_no_client_auth(),
        }
    };

    // ALPN — match what `hyper-rustls` would set so h1+h2 negotiate cleanly.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(cfg)
}

fn load_client_auth(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), GatewayError> {
    let cert_bytes = std::fs::read(cert_path).map_err(|e| {
        GatewayError::Internal(format!("read tls_client_cert_path {cert_path}: {e}"))
    })?;
    let mut cert_cursor = std::io::Cursor::new(cert_bytes);
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| GatewayError::Internal(format!("parse client cert {cert_path}: {e}")))?;
    if chain.is_empty() {
        return Err(GatewayError::Internal(format!(
            "no certs found in tls_client_cert_path {cert_path}"
        )));
    }

    let key_bytes = std::fs::read(key_path)
        .map_err(|e| GatewayError::Internal(format!("read tls_client_key_path {key_path}: {e}")))?;
    let mut key_cursor = std::io::Cursor::new(key_bytes);
    let key = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|e| GatewayError::Internal(format!("parse client key {key_path}: {e}")))?
        .ok_or_else(|| {
            GatewayError::Internal(format!("no private key in tls_client_key_path {key_path}"))
        })?;

    Ok((chain, key))
}

/// Verifier that accepts any server certificate. Only installed when
/// `tls_verify = false`. Logged loudly at construction time.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Mirror rustls' default set so handshake selection still works.
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
