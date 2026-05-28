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
        // Spill to another zone, weighted
        let remaining = 1.0 - local_frac;
        let target = (sample - local_frac) / remaining * remaining_weight(zone_weights, local_zone);

        let mut cum = 0.0;
        for (i, &w) in zone_weights.iter().enumerate() {
            if i == local_zone {
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

/// Sum of weights for all zones except `exclude`.
fn remaining_weight(zone_weights: &[f64], exclude: usize) -> f64 {
    zone_weights
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != exclude)
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
}
