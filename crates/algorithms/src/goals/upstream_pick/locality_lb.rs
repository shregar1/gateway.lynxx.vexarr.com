//! Zone-aware routing (Envoy).
//!
//! Prefers the local zone; if the local zone has insufficient capacity the
//! request spills over to other zones proportionally to their weights.

use std::hash::{BuildHasher, Hash, Hasher};

/// Pick a backend index using zone-aware routing.
///
/// - `local_zone`: index of the caller's zone
/// - `zone_weights`: capacity weight per zone (higher = more capacity)
/// - `zone_backends`: number of backends in each zone
///
/// Returns a `(zone_index, backend_within_zone)` flattened to a global
/// backend index computed as `sum(zone_backends[..zone]) + offset`.
pub fn locality_pick(
    local_zone: usize,
    zone_weights: &[f64],
    zone_backends: &[usize],
) -> usize {
    assert_eq!(
        zone_weights.len(),
        zone_backends.len(),
        "zone_weights and zone_backends must have the same length"
    );
    assert!(!zone_weights.is_empty(), "must have at least one zone");
    // Bug fix: `local_zone` was previously never bounds-checked, so an
    // out-of-range value panicked on `zone_weights[local_zone]` (and on
    // `base_offset` in the total_weight<=0 path). Validate it up front.
    assert!(
        local_zone < zone_weights.len(),
        "local_zone out of range"
    );

    let total_weight: f64 = zone_weights.iter().sum();
    if total_weight <= 0.0 {
        // Fallback: pick first backend in local zone
        return base_offset(zone_backends, local_zone);
    }

    let local_frac = zone_weights[local_zone] / total_weight;

    // Use a pseudo-random sample to decide local vs spillover
    let sample = pseudo_random_f64();

    if sample < local_frac {
        // Route locally
        let offset = pseudo_random_usize(zone_backends[local_zone]);
        base_offset(zone_backends, local_zone) + offset
    } else {
        // Spill to another zone, weighted.
        //
        // Bug fix: zones with zero backends must be excluded from the
        // spillover distribution. Previously their weight was still counted
        // both in `remaining_weight` and in the accumulation loop, so the
        // sample could land in a zero-backend zone's band. That zone then
        // resolved to `base_offset(..) + 0`, which is one-past-the-end for a
        // trailing zero-backend zone (out-of-range index) or the *wrong*
        // zone's first backend for an interior one (silent cross-zone
        // misroute). We now skip `zone_backends[i] == 0` zones consistently
        // when normalizing AND when accumulating, keeping the distribution
        // over exactly the eligible zones.
        let remaining = 1.0 - local_frac;
        let target =
            (sample - local_frac) / remaining * remaining_weight(zone_weights, zone_backends, local_zone);

        let mut cum = 0.0;
        for (i, &w) in zone_weights.iter().enumerate() {
            if i == local_zone || zone_backends[i] == 0 {
                continue;
            }
            cum += w;
            if target < cum {
                let offset = pseudo_random_usize(zone_backends[i]);
                return base_offset(zone_backends, i) + offset;
            }
        }
        // Fallback: last non-local zone
        for i in (0..zone_weights.len()).rev() {
            if i != local_zone && zone_backends[i] > 0 {
                return base_offset(zone_backends, i);
            }
        }
        0
    }
}

/// Compute the base offset (global index of the first backend in `zone`).
fn base_offset(zone_backends: &[usize], zone: usize) -> usize {
    zone_backends[..zone].iter().sum()
}

/// Sum of weights for all *eligible* spillover zones: every zone except
/// `exclude` that actually has at least one backend. Zero-backend zones are
/// excluded so the spillover distribution stays normalized over only the
/// zones that can receive traffic.
fn remaining_weight(zone_weights: &[f64], zone_backends: &[usize], exclude: usize) -> f64 {
    zone_weights
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != exclude && zone_backends[i] > 0)
        .map(|(_, &w)| w)
        .sum()
}

/// Cheap pseudo-random f64 in [0, 1) — NOT crypto-quality.
fn pseudo_random_f64() -> f64 {
    let state = std::collections::hash_map::RandomState::new();
    let mut hasher = state.build_hasher();
    0u64.hash(&mut hasher);
    hasher.finish() as f64 / u64::MAX as f64
}

/// Cheap pseudo-random usize in [0, max).
fn pseudo_random_usize(max: usize) -> usize {
    if max <= 1 {
        return 0;
    }
    let state = std::collections::hash_map::RandomState::new();
    let mut hasher = state.build_hasher();
    1u64.hash(&mut hasher);
    (hasher.finish() as usize) % max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_zone() {
        let idx = locality_pick(0, &[1.0], &[5]);
        assert!(idx < 5);
    }

    #[test]
    fn base_offset_correct() {
        assert_eq!(base_offset(&[3, 4, 5], 0), 0);
        assert_eq!(base_offset(&[3, 4, 5], 1), 3);
        assert_eq!(base_offset(&[3, 4, 5], 2), 7);
    }

    #[test]
    fn result_in_range() {
        let total_backends: usize = [4, 3, 5].iter().sum();
        for _ in 0..100 {
            let idx = locality_pick(0, &[1.0, 1.0, 1.0], &[4, 3, 5]);
            assert!(idx < total_backends, "idx {} out of range {}", idx, total_backends);
        }
    }

    // Regression: spillover used to count a trailing zero-backend zone in the
    // weight distribution, so a sample landing in that zone's band returned
    // `base_offset(.., 2) + 0 == 4 + 5 == 9`, i.e. one-past-the-end of the
    // 9-backend (indices 0..=8) topology. With zero-backend zones excluded the
    // index must always stay in range across many random samples.
    #[test]
    fn spillover_never_picks_trailing_empty_zone() {
        let zone_backends = [4usize, 5, 0];
        let total_backends: usize = zone_backends.iter().sum(); // 9
        for _ in 0..1000 {
            let idx = locality_pick(0, &[1.0, 1.0, 1.0], &zone_backends);
            assert!(
                idx < total_backends,
                "idx {} out of range (total {}); trailing empty zone leaked",
                idx,
                total_backends
            );
        }
    }

    // remaining_weight must exclude both the local zone and any zero-backend
    // zone so the spillover normalization matches the accumulation loop.
    #[test]
    fn remaining_weight_excludes_empty_and_local_zones() {
        // local = 0, zone 2 empty -> only zone 1 (weight 2.0) is eligible.
        assert_eq!(remaining_weight(&[1.0, 2.0, 3.0], &[4, 5, 0], 0), 2.0);
        // local = 1, no empty zones -> zones 0 and 2 (1.0 + 3.0).
        assert_eq!(remaining_weight(&[1.0, 2.0, 3.0], &[4, 5, 6], 1), 4.0);
        // every non-local zone empty -> 0.0 (falls through to fallback loop).
        assert_eq!(remaining_weight(&[1.0, 2.0, 3.0], &[4, 0, 0], 0), 0.0);
    }

    // Regression: `local_zone` was unchecked and panicked deep inside indexing.
    // It must now fail fast with a clear assertion message.
    #[test]
    #[should_panic(expected = "local_zone out of range")]
    fn out_of_range_local_zone_panics_clearly() {
        let _ = locality_pick(5, &[1.0, 1.0], &[3, 4]);
    }
}
