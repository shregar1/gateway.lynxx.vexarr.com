use crate::cluster::{ChangeEvent, ClusterBus};
use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::Target;
use chrono::Utc;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

/// Zero UUID used as the `origin` field for change events emitted by
/// this provider (no admin actor).
const PROVIDER_ORIGIN: Uuid = Uuid::nil();

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct SrvDnsProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    pub entries: Vec<SrvEntry>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_poll_interval() -> u64 {
    15
}

impl Default for SrvDnsProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entries: Vec::new(),
            poll_interval_secs: default_poll_interval(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct SrvEntry {
    pub srv_name: String,
    pub service_id: Uuid,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_scheme() -> String {
    "http".into()
}

fn default_weight() -> u32 {
    100
}

pub struct SrvDnsProvider {
    config: SrvDnsProviderConfig,
    resolver: TokioAsyncResolver,
    repo: Arc<dyn Repository>,
    bus: Arc<dyn ClusterBus>,
    owned: tokio::sync::Mutex<HashMap<Uuid, HashSet<Uuid>>>,
}

impl SrvDnsProvider {
    pub fn new(
        config: SrvDnsProviderConfig,
        repo: Arc<dyn Repository>,
        bus: Arc<dyn ClusterBus>,
    ) -> Result<Arc<Self>, GatewayError> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 256;
        opts.positive_max_ttl = Some(Duration::from_secs(30));
        opts.timeout = Duration::from_secs(3);

        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => r,
            Err(_) => TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts),
        };

        Ok(Arc::new(Self {
            config,
            resolver,
            repo,
            bus,
            owned: tokio::sync::Mutex::new(HashMap::new()),
        }))
    }

    pub fn spawn(self: Arc<Self>) {
        tokio::spawn(async move {
            if let Err(e) = self.reconcile().await {
                tracing::warn!(error = %e, "srv-dns provider initial reconcile failed");
            }
            let interval = Duration::from_secs(self.config.poll_interval_secs.max(5));
            loop {
                sleep(interval).await;
                if let Err(e) = self.reconcile().await {
                    tracing::warn!(error = %e, "srv-dns provider reconcile failed");
                }
            }
        });
    }

    async fn reconcile(&self) -> Result<(), GatewayError> {
        for entry in &self.config.entries {
            if let Err(e) = self.reconcile_entry(entry).await {
                tracing::warn!(
                    srv = %entry.srv_name,
                    service_id = %entry.service_id,
                    error = %e,
                    "srv-dns reconcile entry failed"
                );
            }
        }
        Ok(())
    }

    async fn reconcile_entry(&self, entry: &SrvEntry) -> Result<(), GatewayError> {
        let records = self
            .resolver
            .srv_lookup(&entry.srv_name)
            .await
            .map_err(|e| GatewayError::Internal(format!("SRV lookup {}: {e}", entry.srv_name)))?;

        let mut desired: HashMap<String, (String, u16)> = HashMap::new();
        for record in records.iter() {
            let host = record
                .target()
                .to_string()
                .trim_end_matches('.')
                .to_string();
            let port = record.port();
            let url = format!("{}://{}:{}", entry.scheme, host, port);
            desired.insert(url.clone(), (host, port));
        }

        let mut owned = self.owned.lock().await;
        let existing_ids = owned.entry(entry.service_id).or_default();

        let existing_targets = self
            .repo
            .list_targets_for_service(&entry.service_id)
            .await?;
        let mut existing_urls: HashMap<String, Uuid> = HashMap::new();
        for t in &existing_targets {
            if existing_ids.contains(&t.id) {
                existing_urls.insert(t.url.to_string(), t.id);
            }
        }

        // Add new targets.
        for url in desired.keys() {
            if !existing_urls.contains_key(url) {
                let target_id = Uuid::new_v5(&entry.service_id, format!("srv:{}", url).as_bytes());
                let target = Target {
                    id: target_id,
                    service_id: entry.service_id,
                    url: url.clone().into(),
                    weight: entry.weight,
                    enabled: true,
                    zone: None,
                    state: crate::models::TargetLifecycle::Active,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };
                if let Err(e) = self.repo.create_target(&target).await {
                    tracing::warn!(
                        target_url = %url,
                        error = %e,
                        "srv-dns: failed to create target"
                    );
                    continue;
                }
                existing_ids.insert(target_id);
                let _ = self
                    .bus
                    .publish(ChangeEvent::TargetChanged {
                        service_id: entry.service_id,
                        origin: PROVIDER_ORIGIN,
                    })
                    .await;
                tracing::info!(
                    srv = %entry.srv_name,
                    target = %url,
                    "srv-dns: registered target"
                );
            }
        }

        // Remove stale targets.
        let stale: Vec<(String, Uuid)> = existing_urls
            .iter()
            .filter(|(url, _)| !desired.contains_key(url.as_str()))
            .map(|(url, id)| (url.clone(), *id))
            .collect();

        for (url, id) in stale {
            if let Err(e) = self.repo.delete_target(&id).await {
                tracing::warn!(
                    target_url = %url,
                    error = %e,
                    "srv-dns: failed to remove stale target"
                );
                continue;
            }
            existing_ids.remove(&id);
            let _ = self
                .bus
                .publish(ChangeEvent::TargetChanged {
                    service_id: entry.service_id,
                    origin: PROVIDER_ORIGIN,
                })
                .await;
            tracing::info!(
                srv = %entry.srv_name,
                target = %url,
                "srv-dns: removed stale target"
            );
        }

        Ok(())
    }
}
