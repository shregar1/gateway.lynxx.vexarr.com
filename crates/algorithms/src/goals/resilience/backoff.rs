/// Exponential backoff with jitter (Traefik-style).
///
/// Three flavours:
/// - `backoff_delay` — plain exponential: min(base * 2^attempt, max)
/// - `backoff_full_jitter` — uniform random in [0, delay)
/// - `backoff_decorrelated` — decorrelated jitter: min(max, rand(base, prev*3))

/// Plain exponential backoff: base_ms * 2^attempt, capped at max_ms.
pub fn backoff_delay(attempt: u32, base_ms: u64, max_ms: u64) -> u64 {
    let delay = base_ms.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX));
    delay.min(max_ms)
}

/// Full-jitter backoff: deterministic variant using attempt as seed.
/// Returns a value in [0, backoff_delay(attempt, base_ms, max_ms)).
pub fn backoff_full_jitter(attempt: u32, base_ms: u64, max_ms: u64) -> u64 {
    let cap = backoff_delay(attempt, base_ms, max_ms);
    if cap == 0 {
        return 0;
    }
    // Simple deterministic hash from attempt for reproducible benchmarks
    let hash = (attempt as u64)
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    hash % cap
}

/// Decorrelated jitter: min(max_ms, random_between(base_ms, prev_ms * 3)).
/// Uses prev_ms as both input and entropy source for determinism.
pub fn backoff_decorrelated(prev_ms: u64, base_ms: u64, max_ms: u64) -> u64 {
    if prev_ms == 0 {
        return base_ms.min(max_ms);
    }
    let upper = prev_ms.saturating_mul(3);
    // Deterministic "random" between base_ms and upper
    let hash = prev_ms
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let range = upper.saturating_sub(base_ms);
    if range == 0 {
        return base_ms.min(max_ms);
    }
    let val = base_ms + (hash % range);
    val.min(max_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_growth() {
        assert_eq!(backoff_delay(0, 100, 10000), 100);
        assert_eq!(backoff_delay(1, 100, 10000), 200);
        assert_eq!(backoff_delay(2, 100, 10000), 400);
        assert_eq!(backoff_delay(3, 100, 10000), 800);
    }

    #[test]
    fn capped_at_max() {
        assert_eq!(backoff_delay(20, 100, 5000), 5000);
    }

    #[test]
    fn full_jitter_bounded() {
        for attempt in 0..20 {
            let cap = backoff_delay(attempt, 100, 10000);
            let jittered = backoff_full_jitter(attempt, 100, 10000);
            assert!(jittered < cap || cap == 0);
        }
    }

    #[test]
    fn decorrelated_bounded() {
        let mut prev = 100u64;
        for _ in 0..20 {
            prev = backoff_decorrelated(prev, 100, 10000);
            assert!(prev <= 10000);
            assert!(prev >= 100);
        }
    }

    #[test]
    fn zero_base() {
        assert_eq!(backoff_delay(5, 0, 1000), 0);
        assert_eq!(backoff_full_jitter(5, 0, 1000), 0);
    }
}
