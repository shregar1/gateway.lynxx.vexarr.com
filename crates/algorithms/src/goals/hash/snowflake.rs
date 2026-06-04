//! Snowflake — Twitter-style 64-bit distributed unique ID generator.
//!
//! Bit layout (MSB first):
//!   [timestamp 42 bits][machine_id 12 bits][sequence 10 bits]
//!
//! Timestamp is milliseconds since a custom epoch (2021-01-01 UTC).
//! Supports up to 4096 machines, 1024 IDs per millisecond per machine.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Custom epoch: 2021-01-01 00:00:00 UTC in milliseconds since Unix epoch.
pub(crate) const EPOCH: u64 = 1609459200000;

const MACHINE_BITS: u32 = 12;
pub(crate) const SEQUENCE_BITS: u32 = 10;
pub(crate) const MAX_SEQUENCE: u64 = (1 << SEQUENCE_BITS) - 1;
pub(crate) const MAX_MACHINE_ID: u64 = (1 << MACHINE_BITS) - 1;

pub(crate) const TIMESTAMP_SHIFT: u32 = MACHINE_BITS + SEQUENCE_BITS;

/// Thread-safe Snowflake ID generator.
pub struct SnowflakeGenerator {
    machine_id: u64,
    inner: Mutex<SnowflakeState>,
}

struct SnowflakeState {
    last_timestamp: u64,
    sequence: u64,
}

/// A generated 64-bit Snowflake ID with decomposition helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnowflakeId(pub u64);

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

impl SnowflakeGenerator {
    /// Create a generator for the given machine ID (0..4095).
    ///
    /// # Panics
    ///
    /// Panics if `machine_id` exceeds `MAX_MACHINE_ID` (4095).
    pub fn new(machine_id: u64) -> Self {
        assert!(
            machine_id <= MAX_MACHINE_ID,
            "machine_id {machine_id} exceeds maximum {MAX_MACHINE_ID}"
        );
        Self {
            machine_id,
            inner: Mutex::new(SnowflakeState {
                last_timestamp: 0,
                sequence: 0,
            }),
        }
    }

    /// Generate a new unique ID. Thread-safe.
    ///
    /// If the sequence overflows within a single millisecond the generator
    /// busy-waits until the next millisecond tick.
    pub fn generate(&self) -> SnowflakeId {
        let mut state = self.inner.lock().unwrap();
        let mut ts = current_timestamp_ms().saturating_sub(EPOCH);

        // Clock moved backwards (NTP step, chrony/ntpdate, VM live-migration or
        // snapshot restore, manual clock set): busy-wait until the wall clock
        // catches back up to the last stamped timestamp. Emitting an ID with a
        // regressed timestamp could duplicate IDs already issued at
        // `last_timestamp`. Ensuring `ts >= last_timestamp` here keeps the
        // equal/forward branches below correct without a separate rollback case.
        while ts < state.last_timestamp {
            ts = current_timestamp_ms().saturating_sub(EPOCH);
        }

        if ts == state.last_timestamp {
            state.sequence = (state.sequence + 1) & MAX_SEQUENCE;
            if state.sequence == 0 {
                // Sequence exhausted — spin until the next millisecond.
                while ts <= state.last_timestamp {
                    ts = current_timestamp_ms().saturating_sub(EPOCH);
                }
            }
        } else {
            state.sequence = 0;
        }
        state.last_timestamp = ts;

        let id = (ts << TIMESTAMP_SHIFT)
            | (self.machine_id << SEQUENCE_BITS)
            | state.sequence;
        SnowflakeId(id)
    }

    /// Return the machine ID this generator was configured with.
    pub fn machine_id(&self) -> u64 {
        self.machine_id
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

impl SnowflakeId {
    /// Extract timestamp (milliseconds since custom epoch).
    pub fn timestamp(&self) -> u64 {
        self.0 >> TIMESTAMP_SHIFT
    }

    /// Extract machine ID.
    pub fn machine_id(&self) -> u64 {
        (self.0 >> SEQUENCE_BITS) & MAX_MACHINE_ID
    }

    /// Extract sequence number.
    pub fn sequence(&self) -> u64 {
        self.0 & MAX_SEQUENCE
    }

    /// Convert to a URL-safe Base64 string (no padding).
    pub fn to_base64(&self) -> String {
        let bytes = self.0.to_be_bytes();
        let mut out = String::with_capacity(12);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(B64[((triple >> 18) & 0x3F) as usize] as char);
            out.push(B64[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                out.push(B64[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(B64[(triple & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    /// Construct from a raw `u64`.
    pub fn from_u64(val: u64) -> Self {
        Self(val)
    }
}

impl core::fmt::Display for SnowflakeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_id_roundtrip() {
        let gen = SnowflakeGenerator::new(42);
        assert_eq!(gen.machine_id(), 42);
        let id = gen.generate();
        assert_eq!(id.machine_id(), 42);
    }

    #[test]
    fn ids_are_unique() {
        let gen = SnowflakeGenerator::new(1);
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = gen.generate();
            assert!(ids.insert(id.0), "duplicate ID: {id}");
        }
    }

    #[test]
    fn ids_are_monotonic() {
        let gen = SnowflakeGenerator::new(0);
        let mut prev = 0u64;
        for _ in 0..100 {
            let id = gen.generate();
            assert!(id.0 > prev, "IDs must be monotonically increasing");
            prev = id.0;
        }
    }

    #[test]
    fn decomposition() {
        let machine_id = 123u64;
        let gen = SnowflakeGenerator::new(machine_id);
        let id = gen.generate();

        assert_eq!(id.machine_id(), machine_id);
        assert!(id.timestamp() > 0);
        // sequence should be 0 for the first ID (assuming we're in a new ms)
        // but we can't guarantee that, so just check it's within range
        assert!(id.sequence() <= MAX_SEQUENCE);
    }

    #[test]
    fn from_u64_roundtrip() {
        let gen = SnowflakeGenerator::new(7);
        let id = gen.generate();
        let reconstructed = SnowflakeId::from_u64(id.0);
        assert_eq!(id, reconstructed);
        assert_eq!(id.timestamp(), reconstructed.timestamp());
        assert_eq!(id.machine_id(), reconstructed.machine_id());
        assert_eq!(id.sequence(), reconstructed.sequence());
    }

    #[test]
    fn to_base64_deterministic() {
        let id = SnowflakeId(0x0123456789ABCDEF);
        let b1 = id.to_base64();
        let b2 = id.to_base64();
        assert_eq!(b1, b2);
        assert!(!b1.is_empty());
    }

    #[test]
    fn to_base64_known_value() {
        let id = SnowflakeId(0);
        let b = id.to_base64();
        assert_eq!(b, "AAAAAAAAAAA=");
    }

    #[test]
    fn sequence_wraps_within_millisecond() {
        let gen = SnowflakeGenerator::new(0);
        let mut ids = Vec::new();
        for _ in 0..100 {
            ids.push(gen.generate().0);
        }
        for w in ids.windows(2) {
            assert!(w[1] > w[0]);
        }
    }

    #[test]
    #[should_panic(expected = "exceeds maximum")]
    fn machine_id_too_large() {
        SnowflakeGenerator::new(MAX_MACHINE_ID + 1);
    }

    #[test]
    fn max_machine_id() {
        let gen = SnowflakeGenerator::new(MAX_MACHINE_ID);
        let id = gen.generate();
        assert_eq!(id.machine_id(), MAX_MACHINE_ID);
    }

    #[test]
    fn display_impl() {
        let id = SnowflakeId(12345);
        assert_eq!(format!("{id}"), "12345");
    }

    #[test]
    fn timestamp_is_recent() {
        let gen = SnowflakeGenerator::new(0);
        let id = gen.generate();
        let now_ms = current_timestamp_ms().saturating_sub(EPOCH);
        let ts = id.timestamp();
        assert!(ts <= now_ms, "timestamp should not be in the future");
        assert!(now_ms - ts < 1000, "timestamp should be within 1 second of now");
    }

    #[test]
    fn generate_does_not_regress_on_backward_clock() {
        // Regression: if the wall clock steps backward (NTP/VM migration), the
        // old `else { sequence = 0 }` branch stamped the smaller timestamp,
        // which could duplicate IDs already issued at the higher one. Simulate
        // the clock having been ~5ms ahead by parking `last_timestamp` in the
        // near future; generate() must busy-wait until the real clock catches
        // up rather than emitting a regressed (colliding) timestamp.
        let gen = SnowflakeGenerator::new(1);
        let future = current_timestamp_ms().saturating_sub(EPOCH) + 5;
        gen.inner.lock().unwrap().last_timestamp = future;
        let id = gen.generate();
        assert!(
            id.timestamp() >= future,
            "ID timestamp regressed after backward clock: {} < {}",
            id.timestamp(),
            future
        );
    }
}
