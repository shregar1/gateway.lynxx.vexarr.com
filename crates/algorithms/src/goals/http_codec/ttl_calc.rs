/// Cache TTL computation per RFC 9111 (inspired by Varnish).
///
/// Determines freshness lifetime from response headers, following the
/// priority order: `s-maxage` > `max-age` > `Expires` > heuristic
/// (10% of `Last-Modified` age).

/// Inputs extracted from relevant HTTP response headers / timestamps.
#[derive(Debug, Clone, Copy)]
pub struct TtlInput {
    /// Value of the `Date` header as seconds since epoch.
    pub date: u64,
    /// Wall-clock time when the response was received.
    pub now: u64,
    /// `Cache-Control: max-age=N`
    pub max_age: Option<u64>,
    /// `Cache-Control: s-maxage=N`
    pub s_maxage: Option<u64>,
    /// `Expires` header as seconds since epoch.
    pub expires: Option<u64>,
    /// `Last-Modified` header as seconds since epoch.
    pub last_modified: Option<u64>,
}

/// Computed TTL, grace, and keep values (seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlResult {
    /// Freshness lifetime in seconds.
    pub ttl: u64,
    /// Grace period (serve stale while revalidating) in seconds.
    pub grace: u64,
    /// Keep period (retain in cache after grace) in seconds.
    pub keep: u64,
}

/// Default grace period (10 seconds, similar to Varnish default).
const DEFAULT_GRACE: u64 = 10;
/// Default keep period (seconds to keep object beyond grace).
const DEFAULT_KEEP: u64 = 0;
/// Heuristic fraction of Last-Modified age (10%).
const HEURISTIC_FRACTION: f64 = 0.10;
/// Maximum heuristic TTL (24 hours).
const MAX_HEURISTIC_TTL: u64 = 86400;

/// Compute cache TTL from the given response metadata.
///
/// Priority:
/// 1. `s-maxage` (shared cache directive)
/// 2. `max-age`
/// 3. `Expires - Date`
/// 4. Heuristic: 10% of `(now - Last-Modified)`, capped at 24 hours
/// 5. Fall back to 0 (do not cache).
pub fn compute_ttl(input: &TtlInput) -> TtlResult {
    let response_age = input.now.saturating_sub(input.date);

    let freshness_lifetime = if let Some(sma) = input.s_maxage {
        sma
    } else if let Some(ma) = input.max_age {
        ma
    } else if let Some(exp) = input.expires {
        exp.saturating_sub(input.date)
    } else if let Some(lm) = input.last_modified {
        let lm_age = input.date.saturating_sub(lm);
        let heuristic = (lm_age as f64 * HEURISTIC_FRACTION) as u64;
        heuristic.min(MAX_HEURISTIC_TTL)
    } else {
        0
    };

    let ttl = freshness_lifetime.saturating_sub(response_age);

    TtlResult {
        ttl,
        grace: DEFAULT_GRACE,
        keep: DEFAULT_KEEP,
    }
}

/// Check whether the cached response is still fresh.
pub fn is_fresh(result: &TtlResult, now: u64, date: u64) -> bool {
    let age = now.saturating_sub(date);
    // BUG FIX: `ttl + grace` overflowed (wrapping to a tiny value in release where
    // overflow-checks=false) for an extreme ttl (e.g. u64::MAX from s-maxage near
    // u64::MAX), inverting a fresh response to "stale". Saturate instead so the
    // freshness boundary clamps to u64::MAX rather than wrapping.
    age < result.ttl.saturating_add(result.grace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s_maxage_takes_priority() {
        let input = TtlInput {
            date: 1000,
            now: 1000,
            max_age: Some(60),
            s_maxage: Some(300),
            expires: None,
            last_modified: None,
        };
        let result = compute_ttl(&input);
        assert_eq!(result.ttl, 300);
    }

    #[test]
    fn test_max_age() {
        let input = TtlInput {
            date: 1000,
            now: 1000,
            max_age: Some(120),
            s_maxage: None,
            expires: None,
            last_modified: None,
        };
        let result = compute_ttl(&input);
        assert_eq!(result.ttl, 120);
    }

    #[test]
    fn test_expires() {
        let input = TtlInput {
            date: 1000,
            now: 1000,
            max_age: None,
            s_maxage: None,
            expires: Some(1200),
            last_modified: None,
        };
        let result = compute_ttl(&input);
        assert_eq!(result.ttl, 200); // 1200 - 1000
    }

    #[test]
    fn test_heuristic() {
        let input = TtlInput {
            date: 1000,
            now: 1000,
            max_age: None,
            s_maxage: None,
            expires: None,
            last_modified: Some(0), // modified 1000s ago
        };
        let result = compute_ttl(&input);
        assert_eq!(result.ttl, 100); // 10% of 1000
    }

    #[test]
    fn test_heuristic_capped() {
        let input = TtlInput {
            date: 1_000_000,
            now: 1_000_000,
            max_age: None,
            s_maxage: None,
            expires: None,
            last_modified: Some(0), // modified 1M seconds ago
        };
        let result = compute_ttl(&input);
        assert_eq!(result.ttl, MAX_HEURISTIC_TTL);
    }

    #[test]
    fn test_no_directives() {
        let input = TtlInput {
            date: 1000,
            now: 1000,
            max_age: None,
            s_maxage: None,
            expires: None,
            last_modified: None,
        };
        let result = compute_ttl(&input);
        assert_eq!(result.ttl, 0);
    }

    #[test]
    fn test_response_age_subtracted() {
        let input = TtlInput {
            date: 1000,
            now: 1050, // 50 seconds of age
            max_age: Some(120),
            s_maxage: None,
            expires: None,
            last_modified: None,
        };
        let result = compute_ttl(&input);
        assert_eq!(result.ttl, 70); // 120 - 50
    }

    #[test]
    fn test_is_fresh_within_ttl() {
        let result = TtlResult { ttl: 100, grace: 10, keep: 0 };
        assert!(is_fresh(&result, 1050, 1000)); // age=50 < 110
    }

    #[test]
    fn test_is_fresh_in_grace() {
        let result = TtlResult { ttl: 100, grace: 10, keep: 0 };
        assert!(is_fresh(&result, 1105, 1000)); // age=105 < 110
    }

    #[test]
    fn test_is_stale() {
        let result = TtlResult { ttl: 100, grace: 10, keep: 0 };
        assert!(!is_fresh(&result, 1200, 1000)); // age=200 >= 110
    }

    #[test]
    fn test_is_fresh_does_not_overflow_on_max_ttl() {
        // Regression: a near-max ttl (e.g. u64::MAX from s-maxage near u64::MAX)
        // made `ttl + grace` wrap (u64::MAX + 10 -> 9) in release, so a clearly
        // fresh response with a realistic age was reported STALE. With saturating
        // arithmetic the boundary clamps to u64::MAX and the response stays fresh.
        let result = TtlResult { ttl: u64::MAX, grace: DEFAULT_GRACE, keep: 0 };
        assert!(is_fresh(&result, 2000, 1000)); // age=1000, would be < 9 (false) if wrapped

        // End-to-end: compute_ttl with s_maxage = u64::MAX and zero response age
        // produces ttl = u64::MAX, which must remain fresh under realistic age.
        let input = TtlInput {
            date: 1000,
            now: 1000,
            max_age: None,
            s_maxage: Some(u64::MAX),
            expires: None,
            last_modified: None,
        };
        let computed = compute_ttl(&input);
        assert_eq!(computed.ttl, u64::MAX);
        assert!(is_fresh(&computed, 1000 + 1_000_000, 1000));
    }
}
