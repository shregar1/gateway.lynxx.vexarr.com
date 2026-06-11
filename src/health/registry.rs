use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub service_id: Uuid,
    pub status: HealthStatus,
    pub circuit: CircuitState,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub total_checks: u64,
    pub total_failures: u64,
    pub opened_at: Option<DateTime<Utc>>,
}

impl ServiceHealth {
    fn new(service_id: Uuid) -> Self {
        Self {
            service_id,
            status: HealthStatus::Unknown,
            circuit: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check_at: None,
            last_error: None,
            total_checks: 0,
            total_failures: 0,
            opened_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HealthConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub open_duration_ms: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 2,
            open_duration_ms: 30_000,
        }
    }
}

pub struct HealthRegistry {
    entries: DashMap<Uuid, ServiceHealth>,
    config: HealthConfig,
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self::with_config(HealthConfig::default())
    }

    pub fn with_config(config: HealthConfig) -> Self {
        Self {
            entries: DashMap::new(),
            config,
        }
    }

    pub fn config(&self) -> HealthConfig {
        self.config
    }

    pub fn register(&self, service_id: Uuid) {
        self.entries
            .entry(service_id)
            .or_insert_with(|| ServiceHealth::new(service_id));
    }

    pub fn unregister(&self, service_id: &Uuid) {
        self.entries.remove(service_id);
    }

    pub fn get(&self, service_id: &Uuid) -> Option<ServiceHealth> {
        self.entries.get(service_id).map(|e| e.clone())
    }

    pub fn list(&self) -> Vec<ServiceHealth> {
        self.entries.iter().map(|e| e.clone()).collect()
    }

    /// Cached-timestamp variant for the proxy hot path. The handler captures
    /// a single `Utc::now()` per request at entry and passes the same
    /// `DateTime` through every per-request consumer (this, the quota
    /// tracker, and the access log), eliminating ~3 of the ~8
    /// `clock_gettime` syscalls the flamegraph showed at 100k RPS.
    pub fn record_success_at(
        &self,
        service_id: &Uuid,
        service_name: &str,
        now: DateTime<Utc>,
    ) {
        let success_threshold = self.config.success_threshold;
        let (circuit, status) = {
            let mut entry = self
                .entries
                .entry(*service_id)
                .or_insert_with(|| ServiceHealth::new(*service_id));

            entry.status = HealthStatus::Healthy;
            entry.consecutive_failures = 0;
            entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
            entry.last_check_at = Some(now);
            entry.last_error = None;
            entry.total_checks = entry.total_checks.saturating_add(1);

            if entry.circuit == CircuitState::HalfOpen
                && entry.consecutive_successes >= success_threshold
            {
                tracing::info!(service_id = %service_id, "circuit breaker closed");
                entry.circuit = CircuitState::Closed;
                entry.opened_at = None;
            }

            (entry.circuit, entry.status)
        };

        metrics::gauge!("lynxx_circuit_state", "service" => service_name.to_string())
            .set(crate::metrics::circuit_state_value(circuit));
        metrics::gauge!("lynxx_service_health", "service" => service_name.to_string())
            .set(crate::metrics::health_status_value(status));
    }

    /// Convenience: calls `record_success_at(Utc::now())`. Background
    /// callers (active health checker, tests) use this; the proxy hot
    /// path uses `record_success_at` directly with its cached timestamp.
    pub fn record_success(&self, service_id: &Uuid, service_name: &str) {
        self.record_success_at(service_id, service_name, Utc::now());
    }

    /// Cached-timestamp variant for the proxy hot path. See
    /// [`Self::record_success_at`].
    pub fn record_failure_at(
        &self,
        service_id: &Uuid,
        service_name: &str,
        err: String,
        now: DateTime<Utc>,
    ) {
        let failure_threshold = self.config.failure_threshold;
        let (circuit, status, opened_transition) = {
            let mut entry = self
                .entries
                .entry(*service_id)
                .or_insert_with(|| ServiceHealth::new(*service_id));

            entry.status = HealthStatus::Unhealthy;
            entry.consecutive_successes = 0;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.last_check_at = Some(now);
            entry.last_error = Some(err);
            entry.total_checks = entry.total_checks.saturating_add(1);
            entry.total_failures = entry.total_failures.saturating_add(1);

            let mut transitioned_to_open = false;
            match entry.circuit {
                CircuitState::Closed if entry.consecutive_failures >= failure_threshold => {
                    tracing::warn!(
                        service_id = %service_id,
                        failures = entry.consecutive_failures,
                        "circuit breaker opened"
                    );
                    entry.circuit = CircuitState::Open;
                    entry.opened_at = Some(now);
                    transitioned_to_open = true;
                }
                CircuitState::HalfOpen => {
                    tracing::warn!(service_id = %service_id, "circuit breaker re-opened from half-open");
                    entry.circuit = CircuitState::Open;
                    entry.opened_at = Some(now);
                }
                _ => {}
            }

            (entry.circuit, entry.status, transitioned_to_open)
        };

        if opened_transition {
            metrics::counter!(
                "lynxx_circuit_open_total",
                "service" => service_name.to_string()
            )
            .increment(1);
        }

        metrics::gauge!("lynxx_circuit_state", "service" => service_name.to_string())
            .set(crate::metrics::circuit_state_value(circuit));
        metrics::gauge!("lynxx_service_health", "service" => service_name.to_string())
            .set(crate::metrics::health_status_value(status));
    }

    /// Convenience: calls `record_failure_at(Utc::now())`.
    pub fn record_failure(&self, service_id: &Uuid, service_name: &str, err: String) {
        self.record_failure_at(service_id, service_name, err, Utc::now());
    }

    pub fn reset_circuit(&self, service_id: &Uuid) -> Option<()> {
        let mut entry = self.entries.get_mut(service_id)?;
        entry.circuit = CircuitState::Closed;
        entry.consecutive_failures = 0;
        entry.consecutive_successes = 0;
        entry.opened_at = None;
        entry.status = HealthStatus::Unknown;
        Some(())
    }

    /// Reset a circuit breaker when the upstream configuration has changed
    /// (URL, targets, etc.). Returns true if a reset actually happened
    /// (i.e. the circuit was not already Closed with zero failures).
    pub fn reset_on_upstream_change(
        &self,
        service_id: &Uuid,
        service_name: &str,
        reason: &str,
    ) -> bool {
        let needs_reset = self
            .entries
            .get(service_id)
            .map(|e| {
                e.circuit != CircuitState::Closed
                    || e.consecutive_failures > 0
                    || e.status == HealthStatus::Unhealthy
            })
            .unwrap_or(false);

        if needs_reset {
            self.reset_circuit(service_id);
            tracing::info!(
                service_id = %service_id,
                service = service_name,
                reason,
                "circuit breaker auto-reset"
            );
        }
        needs_reset
    }

    pub fn should_allow_request(&self, service_id: &Uuid, open_duration_ms: u64) -> bool {
        let mut entry = match self.entries.get_mut(service_id) {
            Some(e) => e,
            None => return true,
        };

        match entry.circuit {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                let elapsed_ok = entry
                    .opened_at
                    .map(|t| {
                        Utc::now().signed_duration_since(t).num_milliseconds() as u64
                            > open_duration_ms
                    })
                    .unwrap_or(true);
                if elapsed_ok {
                    tracing::info!(service_id = %service_id, "circuit breaker half-open (probing)");
                    entry.circuit = CircuitState::HalfOpen;
                    entry.consecutive_successes = 0;
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with_threshold(fail: u32, success: u32) -> HealthRegistry {
        HealthRegistry::with_config(HealthConfig {
            failure_threshold: fail,
            success_threshold: success,
            open_duration_ms: 30_000,
        })
    }

    fn trip_circuit(registry: &HealthRegistry, id: &Uuid, name: &str) {
        let threshold = registry.config().failure_threshold;
        for _ in 0..threshold {
            registry.record_failure(id, name, "test error".into());
        }
        assert_eq!(registry.get(id).unwrap().circuit, CircuitState::Open);
    }

    // --- reset_circuit ---

    #[test]
    fn reset_circuit_clears_open_state() {
        let reg = registry_with_threshold(2, 1);
        let id = Uuid::new_v4();
        reg.register(id);
        trip_circuit(&reg, &id, "svc");

        reg.reset_circuit(&id);
        let h = reg.get(&id).unwrap();
        assert_eq!(h.circuit, CircuitState::Closed);
        assert_eq!(h.consecutive_failures, 0);
        assert_eq!(h.consecutive_successes, 0);
        assert!(h.opened_at.is_none());
        assert_eq!(h.status, HealthStatus::Unknown);
    }

    #[test]
    fn reset_circuit_returns_none_for_unknown_service() {
        let reg = HealthRegistry::new();
        assert!(reg.reset_circuit(&Uuid::new_v4()).is_none());
    }

    // --- reset_on_upstream_change ---

    #[test]
    fn reset_on_upstream_change_resets_open_circuit() {
        let reg = registry_with_threshold(2, 1);
        let id = Uuid::new_v4();
        reg.register(id);
        trip_circuit(&reg, &id, "svc");

        let did_reset = reg.reset_on_upstream_change(&id, "svc", "url changed");
        assert!(did_reset);
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Closed);
    }

    #[test]
    fn reset_on_upstream_change_resets_unhealthy_closed_circuit() {
        let reg = registry_with_threshold(3, 1);
        let id = Uuid::new_v4();
        reg.register(id);
        // 1 failure — not enough to open, but service is unhealthy
        reg.record_failure(&id, "svc", "err".into());
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Closed);
        assert_eq!(reg.get(&id).unwrap().consecutive_failures, 1);

        let did_reset = reg.reset_on_upstream_change(&id, "svc", "url changed");
        assert!(did_reset);
        assert_eq!(reg.get(&id).unwrap().consecutive_failures, 0);
        assert_eq!(reg.get(&id).unwrap().status, HealthStatus::Unknown);
    }

    #[test]
    fn reset_on_upstream_change_skips_healthy_closed_circuit() {
        let reg = HealthRegistry::new();
        let id = Uuid::new_v4();
        reg.register(id);

        let did_reset = reg.reset_on_upstream_change(&id, "svc", "url changed");
        assert!(!did_reset);
    }

    #[test]
    fn reset_on_upstream_change_returns_false_for_unknown_service() {
        let reg = HealthRegistry::new();
        let did_reset = reg.reset_on_upstream_change(&Uuid::new_v4(), "x", "test");
        assert!(!did_reset);
    }

    // --- state machine transitions ---

    #[test]
    fn closed_to_open_on_threshold() {
        let reg = registry_with_threshold(3, 1);
        let id = Uuid::new_v4();
        reg.register(id);

        reg.record_failure(&id, "svc", "e1".into());
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Closed);
        reg.record_failure(&id, "svc", "e2".into());
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Closed);
        reg.record_failure(&id, "svc", "e3".into());
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Open);
    }

    #[test]
    fn success_resets_failure_count() {
        let reg = registry_with_threshold(3, 1);
        let id = Uuid::new_v4();
        reg.register(id);

        reg.record_failure(&id, "svc", "e".into());
        reg.record_failure(&id, "svc", "e".into());
        reg.record_success(&id, "svc");
        assert_eq!(reg.get(&id).unwrap().consecutive_failures, 0);
        // One more failure shouldn't trip it since counter was reset
        reg.record_failure(&id, "svc", "e".into());
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Closed);
    }

    #[test]
    fn half_open_closes_on_success_threshold() {
        let reg = registry_with_threshold(1, 2);
        let id = Uuid::new_v4();
        reg.register(id);

        trip_circuit(&reg, &id, "svc");
        // Force half-open by manipulating opened_at far in the past
        {
            let mut entry = reg.entries.get_mut(&id).unwrap();
            entry.circuit = CircuitState::HalfOpen;
            entry.consecutive_successes = 0;
        }

        reg.record_success(&id, "svc");
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::HalfOpen);
        reg.record_success(&id, "svc");
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Closed);
    }

    #[test]
    fn half_open_reopens_on_failure() {
        let reg = registry_with_threshold(1, 2);
        let id = Uuid::new_v4();
        reg.register(id);

        trip_circuit(&reg, &id, "svc");
        {
            let mut entry = reg.entries.get_mut(&id).unwrap();
            entry.circuit = CircuitState::HalfOpen;
        }

        reg.record_failure(&id, "svc", "still broken".into());
        assert_eq!(reg.get(&id).unwrap().circuit, CircuitState::Open);
    }

    #[test]
    fn should_allow_request_blocks_when_open() {
        let reg = registry_with_threshold(1, 1);
        let id = Uuid::new_v4();
        reg.register(id);
        trip_circuit(&reg, &id, "svc");

        // Open with recent opened_at — should block
        assert!(!reg.should_allow_request(&id, 60_000));
    }

    #[test]
    fn should_allow_request_allows_unknown_service() {
        let reg = HealthRegistry::new();
        assert!(reg.should_allow_request(&Uuid::new_v4(), 30_000));
    }
}
