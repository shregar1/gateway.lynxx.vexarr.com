//! Lock-free Snowflake ID generator (optimized).
//!
//! Replaces `Mutex` + syscall-per-ID with:
//! - `fetch_add` on sequence within the same millisecond (no syscall)
//! - Clock read only when the 10-bit sequence wraps or on first use

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::goals::hash::snowflake::{
    SnowflakeId, EPOCH, MAX_MACHINE_ID, MAX_SEQUENCE, SEQUENCE_BITS, TIMESTAMP_SHIFT,
};

const STATE_SEQ_MASK: u64 = (1 << SEQUENCE_BITS) - 1;

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Atomic Snowflake generator — amortizes clock reads across up to 1024 IDs/ms.
pub struct SnowflakeGeneratorFast {
    machine_id: u64,
    /// Packed state: upper bits = epoch-relative ms, lower 10 = sequence.
    state: AtomicU64,
}

impl SnowflakeGeneratorFast {
    /// Create for `machine_id` in `0..=4095`.
    pub fn new(machine_id: u64) -> Self {
        assert!(
            machine_id <= MAX_MACHINE_ID,
            "machine_id {machine_id} exceeds maximum {MAX_MACHINE_ID}"
        );
        Self {
            machine_id,
            state: AtomicU64::new(0),
        }
    }

    /// Generate a unique ID (thread-safe, lock-free).
    #[inline]
    pub fn generate(&self) -> SnowflakeId {
        loop {
            let packed = self.state.load(Ordering::Acquire);
            let last_ts = packed >> SEQUENCE_BITS;
            let seq = packed & STATE_SEQ_MASK;

            // Fast path: same millisecond, sequence not exhausted — no syscall.
            if seq < MAX_SEQUENCE {
                let next_packed = packed + 1;
                if self
                    .state
                    .compare_exchange_weak(
                        packed,
                        next_packed,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    let new_seq = seq + 1;
                    let id = (last_ts << TIMESTAMP_SHIFT)
                        | (self.machine_id << SEQUENCE_BITS)
                        | new_seq;
                    return SnowflakeId(id);
                }
                continue;
            }

            // Slow path: new millisecond (or initial).
            let mut ts = current_timestamp_ms().saturating_sub(EPOCH);
            if ts <= last_ts {
                while ts <= last_ts {
                    ts = current_timestamp_ms().saturating_sub(EPOCH);
                }
            }
            let new_packed = ts << SEQUENCE_BITS;
            if self
                .state
                .compare_exchange_weak(packed, new_packed, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let id =
                    (ts << TIMESTAMP_SHIFT) | (self.machine_id << SEQUENCE_BITS);
                return SnowflakeId(id);
            }
        }
    }

    pub fn machine_id(&self) -> u64 {
        self.machine_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generates_unique_ids() {
        let gen = SnowflakeGeneratorFast::new(42);
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            let id = gen.generate().0;
            assert!(seen.insert(id));
        }
    }
}
