pub mod postgres;
pub mod sqlite;

use crate::audit::{AuditEntry, AuditFilter, NewAuditEntry};
use crate::auth::{AdminToken, Role};
use crate::cluster::ClusterBus;
use crate::config::GatewayConfig;
use crate::error::GatewayError;
use crate::models::{
    AlertEvent, AlertRule, ApiVersion, CacheEntry, CacheStats, Certificate, ClusterNode, Consumer,
    ConsumerGroup, ConsumerGroupMember, CostRecord, ErrorPage, GeoBucket, Incident, IncidentUpdate,
    IpRule, LoadTest, LogEntry, MarketplacePlugin, MetricBucket, PluginInstance, Probe,
    ProbeResult, Project, RateLimitBucket, RateLimitSimulation, Route, Service, Snapshot,
    SpanRecord, Target, TraceRecord, TransformRule, Webhook, WebhookDelivery,
};
use crate::recording::{RecordingFilter, RecordingIndexRow};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Input for `Repository::create_admin_token`. The raw token has already
/// been hashed by the caller — only the hash is persisted.
#[derive(Debug, Clone)]
pub struct NewAdminToken {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Patch payload for `Repository::update_admin_token`. None fields are
/// left unchanged.
#[derive(Debug, Clone, Default)]
pub struct AdminTokenPatch {
    pub name: Option<String>,
    pub role: Option<Role>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
}

/// Backend-agnostic persistence layer. Both SQLite and Postgres
/// implementations live behind this trait so the rest of the gateway is
/// storage-agnostic.
#[async_trait]
pub trait Repository: Send + Sync {
    // ---------- projects ----------

    async fn list_projects(&self) -> Result<Vec<Project>, GatewayError>;
    async fn get_project(&self, id: &Uuid) -> Result<Option<Project>, GatewayError>;
    async fn create_project(&self, project: &Project) -> Result<(), GatewayError>;
    async fn update_project(&self, id: &Uuid, project: &Project) -> Result<(), GatewayError>;
    async fn delete_project(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn list_services_for_project(
        &self,
        project_id: &Uuid,
    ) -> Result<Vec<Service>, GatewayError>;

    // ---------- services ----------

    async fn list_services(&self) -> Result<Vec<Service>, GatewayError>;
    async fn get_service(&self, id: &Uuid) -> Result<Option<Service>, GatewayError>;
    async fn create_service(&self, svc: &Service) -> Result<(), GatewayError>;
    async fn update_service(&self, id: &Uuid, svc: &Service) -> Result<(), GatewayError>;
    async fn delete_service(&self, id: &Uuid) -> Result<bool, GatewayError>;

    async fn list_routes(&self) -> Result<Vec<Route>, GatewayError>;
    async fn get_route(&self, id: &Uuid) -> Result<Option<Route>, GatewayError>;
    async fn create_route(&self, route: &Route) -> Result<(), GatewayError>;
    async fn update_route(&self, id: &Uuid, route: &Route) -> Result<(), GatewayError>;
    async fn delete_route(&self, id: &Uuid) -> Result<bool, GatewayError>;

    async fn list_plugins(&self) -> Result<Vec<PluginInstance>, GatewayError>;
    async fn get_plugin(&self, id: &Uuid) -> Result<Option<PluginInstance>, GatewayError>;
    async fn create_plugin(&self, plugin: &PluginInstance) -> Result<(), GatewayError>;
    async fn update_plugin(&self, id: &Uuid, plugin: &PluginInstance) -> Result<(), GatewayError>;
    async fn delete_plugin(&self, id: &Uuid) -> Result<bool, GatewayError>;

    async fn list_consumers(&self) -> Result<Vec<Consumer>, GatewayError>;
    async fn create_consumer(&self, consumer: &Consumer) -> Result<(), GatewayError>;
    async fn delete_consumer(&self, id: &Uuid) -> Result<bool, GatewayError>;

    async fn list_targets(&self) -> Result<Vec<Target>, GatewayError>;
    async fn list_targets_for_service(
        &self,
        service_id: &Uuid,
    ) -> Result<Vec<Target>, GatewayError>;
    async fn get_target(&self, id: &Uuid) -> Result<Option<Target>, GatewayError>;
    async fn create_target(&self, target: &Target) -> Result<(), GatewayError>;
    async fn update_target(&self, id: &Uuid, target: &Target) -> Result<(), GatewayError>;
    async fn delete_target(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn update_target_state(&self, id: &Uuid, state: &str) -> Result<bool, GatewayError>;

    async fn get_service_by_name(&self, name: &str) -> Result<Option<Service>, GatewayError>;

    // ---------- cascade soft-delete ----------

    async fn soft_delete_plugins_for_route(&self, route_id: &Uuid) -> Result<u64, GatewayError>;
    async fn soft_delete_plugins_for_service(&self, service_id: &Uuid)
        -> Result<u64, GatewayError>;
    async fn soft_delete_routes_for_service(
        &self,
        service_id: &Uuid,
    ) -> Result<Vec<Uuid>, GatewayError>;
    async fn soft_delete_targets_for_service(&self, service_id: &Uuid)
        -> Result<u64, GatewayError>;
    async fn soft_delete_services_for_project(
        &self,
        project_id: &Uuid,
    ) -> Result<Vec<Uuid>, GatewayError>;

    async fn is_empty(&self) -> Result<bool, GatewayError>;
    async fn seed_from_config(&self, config: &GatewayConfig) -> Result<(), GatewayError>;
    /// Delete all services, routes, and plugins whose `source = 'config'`.
    /// Admin-API-created rows (`source = 'api'`) are untouched.
    async fn clear_config_seed(&self) -> Result<(), GatewayError>;
    /// Mark a set of rows as config-sourced after creation.
    async fn mark_config_source(
        &self,
        service_ids: &[Uuid],
        route_ids: &[Uuid],
        plugin_ids: &[Uuid],
    ) -> Result<(), GatewayError>;

    // ---------- admin tokens ----------

    async fn list_admin_tokens(&self) -> Result<Vec<AdminToken>, GatewayError>;
    async fn get_admin_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<AdminToken>, GatewayError>;
    async fn get_admin_token(&self, id: &Uuid) -> Result<Option<AdminToken>, GatewayError>;
    async fn create_admin_token(&self, token: &NewAdminToken) -> Result<(), GatewayError>;
    async fn update_admin_token(
        &self,
        id: &Uuid,
        patch: &AdminTokenPatch,
    ) -> Result<Option<AdminToken>, GatewayError>;
    async fn delete_admin_token(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn update_admin_token_last_used(
        &self,
        id: &Uuid,
        ts: DateTime<Utc>,
    ) -> Result<(), GatewayError>;
    async fn has_any_admin_token(&self) -> Result<bool, GatewayError>;

    // ---------- audit log ----------

    async fn append_audit(&self, entry: &NewAuditEntry) -> Result<AuditEntry, GatewayError>;
    async fn list_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, GatewayError>;
    async fn last_audit_hash(&self) -> Result<Option<String>, GatewayError>;

    /// Return a cluster bus for fan-out of admin mutations across nodes.
    /// Postgres uses LISTEN/NOTIFY; SQLite polls a `_sync_log` table.
    fn cluster_bus(&self) -> Arc<dyn ClusterBus>;

    // ---------- quota ----------

    /// Return `(calls_total, calls_rejected)` for `period` ('YYYY-MM'), or
    /// `None` if no row exists yet for that period.
    async fn get_quota_usage(&self, period: &str) -> Result<Option<(u64, u64)>, GatewayError>;

    /// Insert or replace the quota row for `period` with the supplied totals.
    async fn upsert_quota_usage(
        &self,
        period: &str,
        calls_total: u64,
        calls_rejected: u64,
    ) -> Result<(), GatewayError>;

    // ---------- recordings (Time-Travel Debug) ----------

    /// Append a single index row. The corresponding payload should already
    /// have been written to the content-addressed store. Best-effort: the
    /// caller (the request-recorder plugin) logs and drops on failure
    /// rather than failing the request.
    async fn append_recording(&self, row: &RecordingIndexRow) -> Result<(), GatewayError>;

    /// List recordings matching `filter`, newest first, capped by
    /// `filter.effective_limit()`.
    async fn list_recordings(
        &self,
        filter: &RecordingFilter,
    ) -> Result<Vec<RecordingIndexRow>, GatewayError>;

    /// Look up a single recording's index row by sha256 id.
    async fn get_recording_index(
        &self,
        id: &str,
    ) -> Result<Option<RecordingIndexRow>, GatewayError>;

    /// Delete a single recording row. Returns true if a row was removed.
    /// Does NOT touch the on-disk JSON; the admin handler owns that.
    async fn delete_recording(&self, id: &str) -> Result<bool, GatewayError>;

    /// Delete every recording row with `ts < cutoff`. Returns the number
    /// of rows removed. Used by the retention sweeper.
    async fn delete_recordings_before(&self, ts: DateTime<Utc>) -> Result<u64, GatewayError>;

    // ---------- commercial zero-trust ----------

    async fn get_device_fingerprint(
        &self,
        customer_id: i64,
        hardware_id: &str,
    ) -> Result<Option<crate::models::DeviceFingerprint>, GatewayError>;

    async fn create_device_fingerprint(
        &self,
        device: &crate::models::DeviceFingerprint,
    ) -> Result<(), GatewayError>;

    async fn update_device_last_seen(
        &self,
        id: &Uuid,
        ts: DateTime<Utc>,
    ) -> Result<(), GatewayError>;

    async fn create_runtime_grant(
        &self,
        grant: &crate::models::RuntimeGrant,
    ) -> Result<(), GatewayError>;

    async fn get_runtime_grant_by_token_id(
        &self,
        token_id: &str,
    ) -> Result<Option<crate::models::RuntimeGrant>, GatewayError>;

    async fn update_grant_heartbeat(
        &self,
        token_id: &str,
        ts: DateTime<Utc>,
    ) -> Result<(), GatewayError>;

    async fn revoke_grant(&self, token_id: &str) -> Result<bool, GatewayError>;

    async fn get_api_key_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<crate::models::ApiKeyRow>, GatewayError>;

    // ── Logs ──

    async fn insert_logs(&self, entries: &[LogEntry]) -> Result<(), GatewayError>;

    async fn list_logs(&self, filter: &LogFilter) -> Result<Vec<LogEntry>, GatewayError>;

    async fn prune_logs(&self, retention_days: u32) -> Result<u64, GatewayError>;

    // ── Analytics (metric buckets) ──

    async fn upsert_metric_bucket(&self, bucket: &MetricBucket) -> Result<(), GatewayError>;
    async fn list_metric_buckets(
        &self,
        service_id: &Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        granularity: &str,
    ) -> Result<Vec<MetricBucket>, GatewayError>;

    async fn upsert_geo_bucket(&self, bucket: &GeoBucket) -> Result<(), GatewayError>;
    async fn list_geo_buckets(
        &self,
        service_id: &Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<GeoBucket>, GatewayError>;

    async fn upsert_rate_limit_bucket(&self, bucket: &RateLimitBucket) -> Result<(), GatewayError>;
    async fn list_rate_limit_buckets(
        &self,
        service_id: &Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<RateLimitBucket>, GatewayError>;

    // ── Probes ──

    async fn list_probes(&self, service_id: &Uuid) -> Result<Vec<Probe>, GatewayError>;
    async fn get_probe(&self, id: &Uuid) -> Result<Option<Probe>, GatewayError>;
    async fn create_probe(&self, probe: &Probe) -> Result<(), GatewayError>;
    async fn update_probe(&self, id: &Uuid, probe: &Probe) -> Result<(), GatewayError>;
    async fn delete_probe(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn append_probe_result(&self, result: &ProbeResult) -> Result<(), GatewayError>;
    async fn list_probe_results(
        &self,
        probe_id: &Uuid,
        limit: u32,
    ) -> Result<Vec<ProbeResult>, GatewayError>;

    // ── Snapshots ──

    async fn list_snapshots(&self, service_id: &Uuid) -> Result<Vec<Snapshot>, GatewayError>;
    async fn get_snapshot(&self, id: &Uuid) -> Result<Option<Snapshot>, GatewayError>;
    async fn create_snapshot(&self, snap: &Snapshot) -> Result<(), GatewayError>;
    async fn delete_snapshot(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Alerts ──

    async fn list_alert_rules(&self, service_id: &Uuid) -> Result<Vec<AlertRule>, GatewayError>;
    async fn get_alert_rule(&self, id: &Uuid) -> Result<Option<AlertRule>, GatewayError>;
    async fn create_alert_rule(&self, rule: &AlertRule) -> Result<(), GatewayError>;
    async fn update_alert_rule(&self, id: &Uuid, rule: &AlertRule) -> Result<(), GatewayError>;
    async fn delete_alert_rule(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn list_alert_events(
        &self,
        service_id: &Uuid,
        limit: u32,
    ) -> Result<Vec<AlertEvent>, GatewayError>;
    async fn create_alert_event(&self, event: &AlertEvent) -> Result<(), GatewayError>;
    async fn resolve_alert_event(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── IP Rules ──

    async fn list_ip_rules(&self, service_id: &Uuid) -> Result<Vec<IpRule>, GatewayError>;
    async fn get_ip_rule(&self, id: &Uuid) -> Result<Option<IpRule>, GatewayError>;
    async fn create_ip_rule(&self, rule: &IpRule) -> Result<(), GatewayError>;
    async fn update_ip_rule(&self, id: &Uuid, rule: &IpRule) -> Result<(), GatewayError>;
    async fn delete_ip_rule(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Error Pages ──

    async fn list_error_pages(&self, service_id: &Uuid) -> Result<Vec<ErrorPage>, GatewayError>;
    async fn get_error_page(&self, id: &Uuid) -> Result<Option<ErrorPage>, GatewayError>;
    async fn create_error_page(&self, page: &ErrorPage) -> Result<(), GatewayError>;
    async fn update_error_page(&self, id: &Uuid, page: &ErrorPage) -> Result<(), GatewayError>;
    async fn delete_error_page(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Consumer Groups ──

    async fn list_consumer_groups(
        &self,
        service_id: &Uuid,
    ) -> Result<Vec<ConsumerGroup>, GatewayError>;
    async fn get_consumer_group(&self, id: &Uuid) -> Result<Option<ConsumerGroup>, GatewayError>;
    async fn create_consumer_group(&self, group: &ConsumerGroup) -> Result<(), GatewayError>;
    async fn update_consumer_group(
        &self,
        id: &Uuid,
        group: &ConsumerGroup,
    ) -> Result<(), GatewayError>;
    async fn delete_consumer_group(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn list_consumer_group_members(
        &self,
        group_id: &Uuid,
    ) -> Result<Vec<ConsumerGroupMember>, GatewayError>;
    async fn add_consumer_group_member(
        &self,
        member: &ConsumerGroupMember,
    ) -> Result<(), GatewayError>;
    async fn remove_consumer_group_member(
        &self,
        group_id: &Uuid,
        consumer_id: &Uuid,
    ) -> Result<bool, GatewayError>;

    // ── Cache ──

    async fn list_cache_entries(&self, service_id: &Uuid) -> Result<Vec<CacheEntry>, GatewayError>;
    async fn get_cache_entry(&self, id: &Uuid) -> Result<Option<CacheEntry>, GatewayError>;
    async fn upsert_cache_entry(&self, entry: &CacheEntry) -> Result<(), GatewayError>;
    async fn delete_cache_entry(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn purge_cache(&self, service_id: &Uuid) -> Result<u64, GatewayError>;
    async fn cache_stats(&self, service_id: &Uuid) -> Result<CacheStats, GatewayError>;

    // ── Tracing ──

    async fn list_traces(
        &self,
        service_id: &Uuid,
        limit: u32,
    ) -> Result<Vec<TraceRecord>, GatewayError>;
    async fn get_trace(&self, id: &Uuid) -> Result<Option<TraceRecord>, GatewayError>;
    async fn create_trace(&self, trace: &TraceRecord) -> Result<(), GatewayError>;
    async fn list_spans(&self, trace_id: &str) -> Result<Vec<SpanRecord>, GatewayError>;
    async fn create_span(&self, span: &SpanRecord) -> Result<(), GatewayError>;

    // ── Transforms ──

    async fn list_transform_rules(
        &self,
        service_id: &Uuid,
    ) -> Result<Vec<TransformRule>, GatewayError>;
    async fn get_transform_rule(&self, id: &Uuid) -> Result<Option<TransformRule>, GatewayError>;
    async fn create_transform_rule(&self, rule: &TransformRule) -> Result<(), GatewayError>;
    async fn update_transform_rule(
        &self,
        id: &Uuid,
        rule: &TransformRule,
    ) -> Result<(), GatewayError>;
    async fn delete_transform_rule(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── API Versions ──

    async fn list_api_versions(&self, service_id: &Uuid) -> Result<Vec<ApiVersion>, GatewayError>;
    async fn get_api_version(&self, id: &Uuid) -> Result<Option<ApiVersion>, GatewayError>;
    async fn create_api_version(&self, version: &ApiVersion) -> Result<(), GatewayError>;
    async fn update_api_version(&self, id: &Uuid, version: &ApiVersion)
        -> Result<(), GatewayError>;
    async fn delete_api_version(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Incidents ──

    async fn list_incidents(&self, service_id: &Uuid) -> Result<Vec<Incident>, GatewayError>;
    async fn get_incident(&self, id: &Uuid) -> Result<Option<Incident>, GatewayError>;
    async fn create_incident(&self, incident: &Incident) -> Result<(), GatewayError>;
    async fn update_incident(&self, id: &Uuid, incident: &Incident) -> Result<(), GatewayError>;
    async fn delete_incident(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn list_incident_updates(
        &self,
        incident_id: &Uuid,
    ) -> Result<Vec<IncidentUpdate>, GatewayError>;
    async fn create_incident_update(&self, update: &IncidentUpdate) -> Result<(), GatewayError>;

    // ── Webhooks ──

    async fn list_webhooks(&self, service_id: &Uuid) -> Result<Vec<Webhook>, GatewayError>;
    async fn get_webhook(&self, id: &Uuid) -> Result<Option<Webhook>, GatewayError>;
    async fn create_webhook(&self, webhook: &Webhook) -> Result<(), GatewayError>;
    async fn update_webhook(&self, id: &Uuid, webhook: &Webhook) -> Result<(), GatewayError>;
    async fn delete_webhook(&self, id: &Uuid) -> Result<bool, GatewayError>;
    async fn list_webhook_deliveries(
        &self,
        webhook_id: &Uuid,
        limit: u32,
    ) -> Result<Vec<WebhookDelivery>, GatewayError>;
    async fn create_webhook_delivery(&self, delivery: &WebhookDelivery)
        -> Result<(), GatewayError>;

    // ── Load Tests ──

    async fn list_load_tests(&self, service_id: &Uuid) -> Result<Vec<LoadTest>, GatewayError>;
    async fn get_load_test(&self, id: &Uuid) -> Result<Option<LoadTest>, GatewayError>;
    async fn create_load_test(&self, test: &LoadTest) -> Result<(), GatewayError>;
    async fn update_load_test(&self, id: &Uuid, test: &LoadTest) -> Result<(), GatewayError>;
    async fn delete_load_test(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Marketplace ──

    async fn list_marketplace_plugins(&self) -> Result<Vec<MarketplacePlugin>, GatewayError>;
    async fn get_marketplace_plugin(
        &self,
        id: &Uuid,
    ) -> Result<Option<MarketplacePlugin>, GatewayError>;
    async fn create_marketplace_plugin(
        &self,
        plugin: &MarketplacePlugin,
    ) -> Result<(), GatewayError>;
    async fn update_marketplace_plugin(
        &self,
        id: &Uuid,
        plugin: &MarketplacePlugin,
    ) -> Result<(), GatewayError>;
    async fn delete_marketplace_plugin(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Cost Analytics ──

    async fn list_cost_records(
        &self,
        service_id: &Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<CostRecord>, GatewayError>;
    async fn upsert_cost_record(&self, record: &CostRecord) -> Result<(), GatewayError>;

    // ── Cluster ──

    async fn list_cluster_nodes(&self) -> Result<Vec<ClusterNode>, GatewayError>;
    async fn get_cluster_node(&self, id: &Uuid) -> Result<Option<ClusterNode>, GatewayError>;
    async fn upsert_cluster_node(&self, node: &ClusterNode) -> Result<(), GatewayError>;
    async fn delete_cluster_node(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Rate Limit Simulator ──

    async fn list_rate_limit_simulations(
        &self,
        service_id: &Uuid,
    ) -> Result<Vec<RateLimitSimulation>, GatewayError>;
    async fn create_rate_limit_simulation(
        &self,
        sim: &RateLimitSimulation,
    ) -> Result<(), GatewayError>;
    async fn get_rate_limit_simulation(
        &self,
        id: &Uuid,
    ) -> Result<Option<RateLimitSimulation>, GatewayError>;

    // ── PKI / Certificates ──

    async fn list_certificates(
        &self,
        service_id: Option<&Uuid>,
    ) -> Result<Vec<Certificate>, GatewayError>;
    async fn get_certificate(&self, id: &Uuid) -> Result<Option<Certificate>, GatewayError>;
    async fn create_certificate(&self, cert: &Certificate) -> Result<(), GatewayError>;
    async fn update_certificate(&self, id: &Uuid, cert: &Certificate) -> Result<(), GatewayError>;
    async fn delete_certificate(&self, id: &Uuid) -> Result<bool, GatewayError>;

    // ── Consumer key regeneration ──

    async fn update_consumer(&self, id: &Uuid, consumer: &Consumer) -> Result<(), GatewayError>;
}

#[derive(Debug, Default)]
pub struct LogFilter {
    pub service_id: Option<Uuid>,
    pub route_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub level: Option<String>,
    pub search: Option<String>,
    pub limit: Option<u32>,
}

/// Build the appropriate repository implementation from the configured URL.
/// `postgres://` and `postgresql://` schemes route to Postgres; everything
/// else (typically `sqlite://...`) routes to SQLite.
pub async fn connect(url: &str) -> Result<Arc<dyn Repository>, GatewayError> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let repo = postgres::PostgresRepository::new(url).await?;
        Ok(Arc::new(repo))
    } else {
        let repo = sqlite::SqliteRepository::new(url).await?;
        Ok(Arc::new(repo))
    }
}
