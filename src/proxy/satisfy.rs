//! NGINX-style `satisfy any|all` access control composition.
//!
//! # Architecture
//!
//! ```text
//! SatisfyEvaluator (stateless)
//! ├── SatisfyMode          — All (AND logic) | Any (OR logic), AtomicU8-backed
//! ├── AccessCheck          — One module's verdict (name + AccessResult)
//! │   ├── Allowed          — This module grants access
//! │   ├── Denied(reason)   — This module denies access
//! │   └── NotApplicable    — This module does not apply (skip)
//! ├── AccessDecision       — Aggregated final verdict
//! │   ├── Allowed
//! │   └── Denied { reasons }
//! ├── ServiceSatisfyConfig — Per-service mode override
//! └── SatisfyMetrics       — Atomic counters (evaluations, allowed, denied, …)
//! ```
//!
//! # Modes
//!
//! | Mode   | Semantics | Use case                              |
//! |--------|-----------|---------------------------------------|
//! | `All`  | AND logic | All access checks must pass (default) |
//! | `Any`  | OR logic  | At least one access check must pass   |
//!
//! NGINX's `satisfy` directive controls how multiple access modules
//! interact. `satisfy all` (the default) requires every module to
//! grant access. `satisfy any` requires at least one module to grant
//! access — enabling OR-logic between auth methods (e.g. either an IP
//! whitelist OR basic auth).
//!
//! # NotApplicable handling
//!
//! A `NotApplicable` result means the module has no opinion about this
//! request (e.g. an IP-allowlist module on a request that already
//! passed JWT auth). It is silently skipped — it never counts as a
//! deny or an allow.
//!
//! - **All mode**: `NotApplicable` checks are ignored. If *all* checks
//!   are `NotApplicable`, the result is `Allowed` (no module objected).
//! - **Any mode**: `NotApplicable` checks are ignored. If *all* checks
//!   are `NotApplicable`, the result is `Allowed`.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

// ═══════════════════════════════════════════════════════════════════════════
// Global configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Master switch — when `false`, the satisfy evaluator is bypassed
/// entirely and all requests are implicitly allowed.
static SATISFY_ENABLED: AtomicBool = AtomicBool::new(false);

/// Global satisfy mode. `0 = All` (default), `1 = Any`.
static SATISFY_MODE: AtomicU8 = AtomicU8::new(0);

/// Returns whether the satisfy evaluator is enabled globally.
#[inline]
pub fn satisfy_enabled() -> bool {
    SATISFY_ENABLED.load(Ordering::Relaxed)
}

/// Enable or disable the satisfy evaluator globally.
#[inline]
pub fn set_satisfy_enabled(enabled: bool) {
    SATISFY_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Returns the current global satisfy mode.
#[inline]
pub fn satisfy_mode() -> SatisfyMode {
    SatisfyMode::from_u8(SATISFY_MODE.load(Ordering::Relaxed))
}

/// Set the global satisfy mode.
#[inline]
pub fn set_satisfy_mode(mode: SatisfyMode) {
    SATISFY_MODE.store(mode as u8, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// SatisfyMode
// ═══════════════════════════════════════════════════════════════════════════

/// How multiple access modules are composed.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SatisfyMode {
    /// All access checks must pass (AND logic). Default.
    All = 0,
    /// At least one access check must pass (OR logic).
    Any = 1,
}

impl SatisfyMode {
    /// Decode from a `u8`. Unknown values fall back to `All`.
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Any,
            _ => Self::All,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AccessResult / AccessCheck
// ═══════════════════════════════════════════════════════════════════════════

/// A single access module's verdict for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessResult {
    /// This module grants access.
    Allowed,
    /// This module denies access, with a human-readable reason.
    Denied(String),
    /// This module does not apply to this request (skip it).
    NotApplicable,
}

/// One access module's named verdict.
#[derive(Clone, Debug)]
pub struct AccessCheck {
    /// Human-readable module name (e.g. `"ip_allowlist"`, `"basic_auth"`).
    pub name: String,
    /// The module's verdict.
    pub result: AccessResult,
}

impl AccessCheck {
    /// Convenience: module allowed access.
    #[inline]
    pub fn allowed(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            result: AccessResult::Allowed,
        }
    }

    /// Convenience: module denied access with a reason.
    #[inline]
    pub fn denied(name: &str, reason: &str) -> Self {
        Self {
            name: name.to_owned(),
            result: AccessResult::Denied(reason.to_owned()),
        }
    }

    /// Convenience: module does not apply.
    #[inline]
    pub fn not_applicable(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            result: AccessResult::NotApplicable,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AccessDecision (aggregated)
// ═══════════════════════════════════════════════════════════════════════════

/// Aggregated access decision produced by [`SatisfyEvaluator::evaluate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access granted.
    Allowed,
    /// Access denied, with reasons collected from all denying modules.
    Denied { reasons: Vec<String> },
}

// ═══════════════════════════════════════════════════════════════════════════
// SatisfyEvaluator
// ═══════════════════════════════════════════════════════════════════════════

/// Stateless evaluator that composes multiple [`AccessCheck`] results
/// according to a [`SatisfyMode`].
pub struct SatisfyEvaluator;

impl SatisfyEvaluator {
    /// Evaluate a set of access checks under the given mode.
    ///
    /// # All mode (AND logic)
    ///
    /// - If **any** check is `Denied`, the final decision is `Denied`
    ///   (collecting all denial reasons).
    /// - `NotApplicable` checks are silently skipped.
    /// - If no checks apply (all `NotApplicable` or empty list), the
    ///   decision is `Allowed`.
    ///
    /// # Any mode (OR logic)
    ///
    /// - If **any** check is `Allowed`, the final decision is `Allowed`.
    /// - If all applicable checks are `Denied`, the decision is `Denied`.
    /// - If all checks are `NotApplicable` (or the list is empty), the
    ///   decision is `Allowed`.
    /// SECURITY NOTE — fail-open on no applicable checks. Both modes return
    /// `Allowed` when `checks` is empty or every check is `NotApplicable`,
    /// mirroring Apache's `Satisfy` semantics (no configured requirement ⇒ no
    /// restriction). This is intentional, but it means a caller that intends to
    /// GATE access must guarantee at least one applicable (`Allowed`/`Denied`)
    /// check is present. Handing this an empty / all-`NotApplicable` list when a
    /// requirement was expected (e.g. a misconfiguration that made every check
    /// `NotApplicable`) grants access — enforce that invariant upstream, not here.
    pub fn evaluate(mode: SatisfyMode, checks: &[AccessCheck]) -> AccessDecision {
        match mode {
            SatisfyMode::All => Self::evaluate_all(checks),
            SatisfyMode::Any => Self::evaluate_any(checks),
        }
    }

    /// AND logic: every applicable check must allow.
    fn evaluate_all(checks: &[AccessCheck]) -> AccessDecision {
        let mut reasons = Vec::new();
        for check in checks {
            if let AccessResult::Denied(ref reason) = check.result {
                reasons.push(format!("{}: {}", check.name, reason));
            }
        }
        if reasons.is_empty() {
            AccessDecision::Allowed
        } else {
            AccessDecision::Denied { reasons }
        }
    }

    /// OR logic: at least one applicable check must allow.
    fn evaluate_any(checks: &[AccessCheck]) -> AccessDecision {
        let mut has_allowed = false;
        let mut has_applicable = false;
        let mut reasons = Vec::new();

        for check in checks {
            match &check.result {
                AccessResult::Allowed => {
                    has_allowed = true;
                    has_applicable = true;
                }
                AccessResult::Denied(reason) => {
                    has_applicable = true;
                    reasons.push(format!("{}: {}", check.name, reason));
                }
                AccessResult::NotApplicable => {}
            }
        }

        if has_allowed {
            AccessDecision::Allowed
        } else if !has_applicable {
            // All NotApplicable or empty → Allowed
            AccessDecision::Allowed
        } else {
            AccessDecision::Denied { reasons }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Per-service configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Per-service satisfy configuration. When `override_global` is `true`,
/// the service's `mode` takes precedence over the global mode.
#[derive(Clone, Debug)]
pub struct ServiceSatisfyConfig {
    /// The satisfy mode for this service.
    pub mode: SatisfyMode,
    /// If `true`, use `self.mode` instead of the global mode.
    pub override_global: bool,
}

/// Determine the effective satisfy mode for a request.
///
/// If a per-service config is provided and has `override_global` set,
/// its mode is used. Otherwise the global mode is returned.
#[inline]
pub fn effective_mode(service_config: Option<&ServiceSatisfyConfig>) -> SatisfyMode {
    match service_config {
        Some(cfg) if cfg.override_global => cfg.mode,
        _ => satisfy_mode(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic counters for satisfy evaluation activity.
pub struct SatisfyMetrics {
    /// Total number of evaluations performed.
    pub evaluations_total: AtomicU64,
    /// Number of evaluations that resulted in `Allowed`.
    pub allowed_total: AtomicU64,
    /// Number of evaluations that resulted in `Denied`.
    pub denied_total: AtomicU64,
    /// Number of evaluations performed with `Any` mode.
    pub any_mode_used: AtomicU64,
    /// Number of evaluations performed with `All` mode.
    pub all_mode_used: AtomicU64,
}

impl SatisfyMetrics {
    /// Create a zeroed metrics instance.
    pub const fn new() -> Self {
        Self {
            evaluations_total: AtomicU64::new(0),
            allowed_total: AtomicU64::new(0),
            denied_total: AtomicU64::new(0),
            any_mode_used: AtomicU64::new(0),
            all_mode_used: AtomicU64::new(0),
        }
    }

    /// Record a single evaluation, updating all relevant counters.
    pub fn record(&self, mode: SatisfyMode, decision: &AccessDecision) {
        self.evaluations_total.fetch_add(1, Ordering::Relaxed);
        match decision {
            AccessDecision::Allowed => {
                self.allowed_total.fetch_add(1, Ordering::Relaxed);
            }
            AccessDecision::Denied { .. } => {
                self.denied_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        match mode {
            SatisfyMode::All => {
                self.all_mode_used.fetch_add(1, Ordering::Relaxed);
            }
            SatisfyMode::Any => {
                self.any_mode_used.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── All mode ──────────────────────────────────────────────────────

    #[test]
    fn all_mode_all_allowed() {
        let checks = vec![
            AccessCheck::allowed("ip_allowlist"),
            AccessCheck::allowed("basic_auth"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::All, &checks);
        assert_eq!(decision, AccessDecision::Allowed);
    }

    #[test]
    fn all_mode_one_denied() {
        let checks = vec![
            AccessCheck::allowed("ip_allowlist"),
            AccessCheck::denied("basic_auth", "bad credentials"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::All, &checks);
        match decision {
            AccessDecision::Denied { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert!(reasons[0].contains("basic_auth"));
                assert!(reasons[0].contains("bad credentials"));
            }
            _ => panic!("expected Denied"),
        }
    }

    #[test]
    fn all_mode_multiple_denied() {
        let checks = vec![
            AccessCheck::denied("ip_allowlist", "ip not in list"),
            AccessCheck::denied("basic_auth", "bad credentials"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::All, &checks);
        match decision {
            AccessDecision::Denied { reasons } => {
                assert_eq!(reasons.len(), 2);
                assert!(reasons[0].contains("ip_allowlist"));
                assert!(reasons[1].contains("basic_auth"));
            }
            _ => panic!("expected Denied"),
        }
    }

    #[test]
    fn all_mode_allowed_and_not_applicable() {
        let checks = vec![
            AccessCheck::allowed("basic_auth"),
            AccessCheck::not_applicable("jwt_auth"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::All, &checks);
        assert_eq!(decision, AccessDecision::Allowed);
    }

    #[test]
    fn all_mode_denied_and_not_applicable() {
        let checks = vec![
            AccessCheck::denied("basic_auth", "invalid"),
            AccessCheck::not_applicable("jwt_auth"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::All, &checks);
        assert!(matches!(decision, AccessDecision::Denied { .. }));
    }

    #[test]
    fn all_mode_all_not_applicable() {
        let checks = vec![
            AccessCheck::not_applicable("ip_allowlist"),
            AccessCheck::not_applicable("jwt_auth"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::All, &checks);
        assert_eq!(decision, AccessDecision::Allowed);
    }

    // ── Any mode ─────────────────────────────────────────────────────

    #[test]
    fn any_mode_all_allowed() {
        let checks = vec![
            AccessCheck::allowed("ip_allowlist"),
            AccessCheck::allowed("basic_auth"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::Any, &checks);
        assert_eq!(decision, AccessDecision::Allowed);
    }

    #[test]
    fn any_mode_one_allowed_one_denied() {
        let checks = vec![
            AccessCheck::allowed("ip_allowlist"),
            AccessCheck::denied("basic_auth", "bad password"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::Any, &checks);
        assert_eq!(decision, AccessDecision::Allowed);
    }

    #[test]
    fn any_mode_all_denied() {
        let checks = vec![
            AccessCheck::denied("ip_allowlist", "not in list"),
            AccessCheck::denied("basic_auth", "no credentials"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::Any, &checks);
        match decision {
            AccessDecision::Denied { reasons } => {
                assert_eq!(reasons.len(), 2);
            }
            _ => panic!("expected Denied"),
        }
    }

    #[test]
    fn any_mode_all_not_applicable() {
        let checks = vec![
            AccessCheck::not_applicable("ip_allowlist"),
            AccessCheck::not_applicable("jwt_auth"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::Any, &checks);
        assert_eq!(decision, AccessDecision::Allowed);
    }

    #[test]
    fn any_mode_not_applicable_and_denied() {
        let checks = vec![
            AccessCheck::not_applicable("ip_allowlist"),
            AccessCheck::denied("basic_auth", "missing header"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::Any, &checks);
        assert!(matches!(decision, AccessDecision::Denied { .. }));
    }

    #[test]
    fn any_mode_not_applicable_and_allowed() {
        let checks = vec![
            AccessCheck::not_applicable("ip_allowlist"),
            AccessCheck::allowed("basic_auth"),
        ];
        let decision = SatisfyEvaluator::evaluate(SatisfyMode::Any, &checks);
        assert_eq!(decision, AccessDecision::Allowed);
    }

    // ── SatisfyMode roundtrip ────────────────────────────────────────

    #[test]
    fn satisfy_mode_from_u8_roundtrip() {
        assert_eq!(SatisfyMode::from_u8(0), SatisfyMode::All);
        assert_eq!(SatisfyMode::from_u8(1), SatisfyMode::Any);
        // Unknown values fall back to All.
        assert_eq!(SatisfyMode::from_u8(42), SatisfyMode::All);
        assert_eq!(SatisfyMode::from_u8(255), SatisfyMode::All);
        // Round-trip
        assert_eq!(
            SatisfyMode::from_u8(SatisfyMode::All as u8),
            SatisfyMode::All
        );
        assert_eq!(
            SatisfyMode::from_u8(SatisfyMode::Any as u8),
            SatisfyMode::Any
        );
    }

    // ── Global mode get/set ──────────────────────────────────────────

    #[test]
    fn global_mode_set_and_get() {
        // Save original to restore (tests may run in parallel).
        let original = satisfy_mode();
        set_satisfy_mode(SatisfyMode::Any);
        assert_eq!(satisfy_mode(), SatisfyMode::Any);
        set_satisfy_mode(SatisfyMode::All);
        assert_eq!(satisfy_mode(), SatisfyMode::All);
        // Restore.
        set_satisfy_mode(original);
    }

    // ── Per-service override ─────────────────────────────────────────

    #[test]
    fn per_service_override() {
        let cfg = ServiceSatisfyConfig {
            mode: SatisfyMode::Any,
            override_global: true,
        };
        // Even if global is All, per-service override returns Any.
        set_satisfy_mode(SatisfyMode::All);
        assert_eq!(effective_mode(Some(&cfg)), SatisfyMode::Any);
    }

    #[test]
    fn effective_mode_no_override() {
        let cfg = ServiceSatisfyConfig {
            mode: SatisfyMode::Any,
            override_global: false,
        };
        set_satisfy_mode(SatisfyMode::All);
        // override_global is false → falls back to global (All).
        assert_eq!(effective_mode(Some(&cfg)), SatisfyMode::All);
    }

    #[test]
    fn effective_mode_with_override() {
        let cfg = ServiceSatisfyConfig {
            mode: SatisfyMode::Any,
            override_global: true,
        };
        set_satisfy_mode(SatisfyMode::All);
        assert_eq!(effective_mode(Some(&cfg)), SatisfyMode::Any);
    }

    #[test]
    fn effective_mode_none_config() {
        set_satisfy_mode(SatisfyMode::Any);
        assert_eq!(effective_mode(None), SatisfyMode::Any);
        set_satisfy_mode(SatisfyMode::All);
        assert_eq!(effective_mode(None), SatisfyMode::All);
    }

    // ── AccessCheck builders ─────────────────────────────────────────

    #[test]
    fn access_check_builders() {
        let a = AccessCheck::allowed("mod_a");
        assert_eq!(a.name, "mod_a");
        assert_eq!(a.result, AccessResult::Allowed);

        let d = AccessCheck::denied("mod_b", "nope");
        assert_eq!(d.name, "mod_b");
        assert_eq!(d.result, AccessResult::Denied("nope".to_owned()));

        let n = AccessCheck::not_applicable("mod_c");
        assert_eq!(n.name, "mod_c");
        assert_eq!(n.result, AccessResult::NotApplicable);
    }

    // ── Global enable/disable ────────────────────────────────────────

    #[test]
    fn global_enable_disable() {
        let original = satisfy_enabled();
        set_satisfy_enabled(true);
        assert!(satisfy_enabled());
        set_satisfy_enabled(false);
        assert!(!satisfy_enabled());
        // Restore.
        set_satisfy_enabled(original);
    }

    // ── Metrics ──────────────────────────────────────────────────────

    #[test]
    fn metrics_counting() {
        let m = SatisfyMetrics::new();

        // Record an All-mode Allowed.
        m.record(SatisfyMode::All, &AccessDecision::Allowed);
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.allowed_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.denied_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.all_mode_used.load(Ordering::Relaxed), 1);
        assert_eq!(m.any_mode_used.load(Ordering::Relaxed), 0);

        // Record an Any-mode Denied.
        let denied = AccessDecision::Denied {
            reasons: vec!["test".to_owned()],
        };
        m.record(SatisfyMode::Any, &denied);
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.allowed_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.denied_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.all_mode_used.load(Ordering::Relaxed), 1);
        assert_eq!(m.any_mode_used.load(Ordering::Relaxed), 1);
    }

    // ── Empty checks list ────────────────────────────────────────────

    #[test]
    fn empty_checks_returns_allowed() {
        let checks: Vec<AccessCheck> = vec![];
        assert_eq!(
            SatisfyEvaluator::evaluate(SatisfyMode::All, &checks),
            AccessDecision::Allowed
        );
        assert_eq!(
            SatisfyEvaluator::evaluate(SatisfyMode::Any, &checks),
            AccessDecision::Allowed
        );
    }
}
