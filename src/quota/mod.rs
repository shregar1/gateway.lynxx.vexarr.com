//! Monthly API call quota enforcement with overage support.
//!
//! Each Lynxx licence tier carries a monthly call limit:
//!
//!   free       →  1 000 000 calls / month  (hard block)
//!   pro        → 10 000 000 calls / month  (soft limit, overage billed)
//!   business   → 100 000 000 calls / month (soft limit, overage billed)
//!   enterprise →  unlimited
//!
//! Paid tiers allow overages: requests above the limit are still proxied
//! but flagged with `X-Lynxx-Overage: true`. The billing API charges per
//! million overage calls at the tier's rate.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use tokio::time::interval;
use tracing::{info, warn};

use crate::db::Repository;
use crate::error::GatewayError;

const FLUSH_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Plan tier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTier {
    Free,
    Pro,
    Business,
    Enterprise,
}

impl PlanTier {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pro" => PlanTier::Pro,
            "business" => PlanTier::Business,
            "enterprise" => PlanTier::Enterprise,
            _ => PlanTier::Free,
        }
    }

    pub fn monthly_limit(self) -> Option<u64> {
        match self {
            PlanTier::Free => Some(1_000_000),
            PlanTier::Pro => Some(10_000_000),
            PlanTier::Business => Some(100_000_000),
            PlanTier::Enterprise => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PlanTier::Free => "free",
            PlanTier::Pro => "pro",
            PlanTier::Business => "business",
            PlanTier::Enterprise => "enterprise",
        }
    }
}

// ---------------------------------------------------------------------------
// Quota result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaResult {
    Allowed,
    Overage,
    Rejected,
}

// ---------------------------------------------------------------------------
// QuotaTracker
// ---------------------------------------------------------------------------

pub struct QuotaTracker {
    plan: PlanTier,
    /// 0 = unlimited. Updated dynamically from the license verify response.
    limit: AtomicU64,
    period: std::sync::Mutex<String>,
    calls: AtomicU64,
    rejected: AtomicU64,
    overage: AtomicU64,
    allow_overage: AtomicBool,
    repo: Arc<dyn Repository>,
}

impl QuotaTracker {
    /// `server_limit` overrides the hardcoded tier limit when present.
    pub async fn load(
        plan: PlanTier,
        server_limit: Option<u64>,
        repo: Arc<dyn Repository>,
    ) -> Result<Arc<Self>, GatewayError> {
        let period = current_period();
        let (calls, rejected) = repo
            .get_quota_usage(&period)
            .await?
            .map(|(c, r)| (c, r))
            .unwrap_or((0, 0));

        let allow_overage = matches!(plan, PlanTier::Pro | PlanTier::Business);
        let effective_limit = server_limit.or_else(|| plan.monthly_limit()).unwrap_or(0);

        let tracker = Arc::new(Self {
            plan,
            limit: AtomicU64::new(effective_limit),
            period: std::sync::Mutex::new(period.clone()),
            calls: AtomicU64::new(calls),
            rejected: AtomicU64::new(rejected),
            overage: AtomicU64::new(0),
            allow_overage: AtomicBool::new(allow_overage),
            repo,
        });

        info!(
            plan = plan.as_str(),
            period = %period,
            calls,
            limit = effective_limit,
            source = if server_limit.is_some() { "server" } else { "hardcoded" },
            allow_overage,
            "quota tracker initialised"
        );

        Ok(tracker)
    }

    pub fn set_allow_overage(&self, allow: bool) {
        self.allow_overage.store(allow, Ordering::Relaxed);
    }

    pub fn set_limit(&self, new_limit: Option<u64>) {
        let val = new_limit.unwrap_or(0);
        let old = self.limit.swap(val, Ordering::Relaxed);
        if old != val {
            info!(
                old_limit = old,
                new_limit = val,
                "quota limit updated from server"
            );
        }
    }

    pub fn check_and_count(&self) -> QuotaResult {
        self.maybe_rollover();

        let limit = self.limit.load(Ordering::Relaxed);
        if limit == 0 {
            // Unlimited (enterprise)
            self.calls.fetch_add(1, Ordering::Relaxed);
            return QuotaResult::Allowed;
        }

        let prev = self.calls.fetch_add(1, Ordering::Relaxed);
        if prev < limit {
            QuotaResult::Allowed
        } else if self.allow_overage.load(Ordering::Relaxed) {
            self.overage.fetch_add(1, Ordering::Relaxed);
            QuotaResult::Overage
        } else {
            self.calls.fetch_sub(1, Ordering::Relaxed);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            QuotaResult::Rejected
        }
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        let period = self.period.lock().expect("period mutex").clone();
        let calls = self.calls.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);
        let overage = self.overage.load(Ordering::Relaxed);
        let raw_limit = self.limit.load(Ordering::Relaxed);
        let limit = if raw_limit == 0 {
            None
        } else {
            Some(raw_limit)
        };
        QuotaSnapshot {
            plan: self.plan,
            period,
            calls_total: calls,
            calls_rejected: rejected,
            calls_overage: overage,
            calls_limit: limit,
            calls_remaining: limit.map(|l| l.saturating_sub(calls)),
            allow_overage: self.allow_overage.load(Ordering::Relaxed),
        }
    }

    pub async fn flush(&self) {
        let period = self.period.lock().expect("period mutex").clone();
        let calls = self.calls.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);
        if let Err(e) = self.repo.upsert_quota_usage(&period, calls, rejected).await {
            warn!(error = %e, "quota flush failed");
        }
    }

    fn maybe_rollover(&self) {
        let now = current_period();
        let mut period = self.period.lock().expect("period mutex");
        if *period != now {
            info!(old = %period, new = %now, "quota period rollover — resetting counters");
            *period = now;
            self.calls.store(0, Ordering::Relaxed);
            self.rejected.store(0, Ordering::Relaxed);
            self.overage.store(0, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Background flush task
// ---------------------------------------------------------------------------

pub fn spawn_quota_flusher(tracker: Arc<QuotaTracker>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            tracker.flush().await;
        }
    });
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct QuotaSnapshot {
    pub plan: PlanTier,
    pub period: String,
    pub calls_total: u64,
    pub calls_rejected: u64,
    pub calls_overage: u64,
    pub calls_limit: Option<u64>,
    pub calls_remaining: Option<u64>,
    pub allow_overage: bool,
}

fn current_period() -> String {
    Utc::now().format("%Y-%m").to_string()
}
