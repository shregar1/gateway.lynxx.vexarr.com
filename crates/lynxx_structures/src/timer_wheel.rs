//! Hierarchical timer wheel for O(1) timer insert/cancel with cascading.
//!
//! Multi-level design: each wheel level covers an exponentially larger time
//! range. Lower-level wheels have fine granularity; higher levels cascade
//! entries downward as time advances.

use std::collections::VecDeque;

#[derive(Debug)]
struct TimerEntry<T> {
    deadline: u64,
    value: T,
    cancelled: bool,
}

struct Wheel<T> {
    slots: Vec<VecDeque<TimerEntry<T>>>,
    current_slot: usize,
}

/// Opaque handle returned by [`TimerWheel::insert`] for O(1) cancellation.
///
/// The handle records the wheel level, slot, and position within the slot's
/// queue at insertion time. Pass it to [`TimerWheel::cancel`] to lazily mark
/// the timer as cancelled.
#[derive(Debug, Clone, Copy)]
pub struct TimerHandle {
    wheel: usize,
    slot: usize,
    index: usize,
}

/// Hierarchical timer wheel with configurable levels and slot counts.
///
/// Each level has `2^bits_per_wheel` slots. Level 0 is the finest granularity;
/// higher levels cover exponentially larger time ranges and cascade entries
/// downward when their slot is advanced.
///
/// # Examples
///
/// ```
/// use lynxx_structures::timer_wheel::TimerWheel;
///
/// // 4 levels × 32 slots, 1 ms resolution
/// let mut tw: TimerWheel<&str> = TimerWheel::new(4, 5, 1);
///
/// let h = tw.insert(100, "connection_timeout");
/// tw.insert(250, "keepalive_probe");
///
/// // Advance to t=150 ms — first timer fires
/// let expired = tw.advance(150);
/// assert_eq!(expired, vec!["connection_timeout"]);
///
/// // Cancel the second timer before it fires
/// tw.cancel(h); // h is already expired, so this is a no-op here
/// ```
pub struct TimerWheel<T> {
    wheels: Vec<Wheel<T>>,
    current_tick: u64,
    resolution_ms: u64,
    bits_per_wheel: u32,
    pending: usize,
}

impl<T> TimerWheel<T> {
    /// Create a new timer wheel.
    ///
    /// * `num_wheels` – number of levels (e.g. 4 with 5 bits = 32^4 ≈ 1M ticks range)
    /// * `bits_per_wheel` – slots per level = `2^bits` (default 5 = 32 slots)
    /// * `resolution_ms` – time per tick
    pub fn new(num_wheels: usize, bits_per_wheel: u32, resolution_ms: u64) -> Self {
        let slots_per_wheel = 1usize << bits_per_wheel;
        let wheels = (0..num_wheels)
            .map(|_| Wheel {
                slots: (0..slots_per_wheel).map(|_| VecDeque::new()).collect(),
                current_slot: 0,
            })
            .collect();

        Self {
            wheels,
            current_tick: 0,
            resolution_ms: resolution_ms.max(1),
            bits_per_wheel,
            pending: 0,
        }
    }

    fn slots_per_wheel(&self) -> usize {
        1 << self.bits_per_wheel
    }

    fn slot_mask(&self) -> usize {
        self.slots_per_wheel() - 1
    }

    /// Determine which wheel level and slot a deadline falls into relative to current_tick.
    fn wheel_slot(&self, deadline: u64) -> (usize, usize) {
        let diff = deadline.saturating_sub(self.current_tick);
        let mask = self.slot_mask();
        let slots = self.slots_per_wheel() as u64;

        let mut level_range = slots;
        for level in 0..self.wheels.len() {
            if diff < level_range || level == self.wheels.len() - 1 {
                let shift = level as u32 * self.bits_per_wheel;
                let slot = (deadline >> shift) as usize & mask;
                return (level, slot);
            }
            level_range <<= self.bits_per_wheel;
        }

        let last = self.wheels.len() - 1;
        let shift = last as u32 * self.bits_per_wheel;
        (last, (deadline >> shift) as usize & self.slot_mask())
    }

    /// Insert a timer that fires at `deadline_ms`. O(1).
    pub fn insert(&mut self, deadline_ms: u64, value: T) -> TimerHandle {
        let deadline_tick = deadline_ms / self.resolution_ms;
        let effective = if deadline_tick <= self.current_tick {
            self.current_tick + 1
        } else {
            deadline_tick
        };
        let (wheel, slot) = self.wheel_slot(effective);
        let index = self.wheels[wheel].slots[slot].len();
        self.wheels[wheel].slots[slot].push_back(TimerEntry {
            deadline: effective,
            value,
            cancelled: false,
        });
        self.pending += 1;
        TimerHandle { wheel, slot, index }
    }

    /// Cancel a timer by handle. Returns `None` (lazy cancellation; entry
    /// is cleaned up on the next advance that touches its slot).
    pub fn cancel(&mut self, handle: TimerHandle) -> Option<T> {
        let slot = self.wheels
            .get_mut(handle.wheel)?
            .slots
            .get_mut(handle.slot)?;

        let entry = slot.get_mut(handle.index)?;
        if entry.cancelled {
            return None;
        }
        entry.cancelled = true;
        self.pending -= 1;

        None
    }

    /// Advance time to `now_ms`. Returns all expired (non-cancelled) timers.
    ///
    /// Cascades entries from higher wheels to lower wheels as needed.
    pub fn advance(&mut self, now_ms: u64) -> Vec<T> {
        let target_tick = now_ms / self.resolution_ms;
        let mut expired = Vec::new();

        while self.current_tick < target_tick {
            self.current_tick += 1;

            for level in 1..self.wheels.len() {
                let shift = level as u32 * self.bits_per_wheel;
                if (self.current_tick & ((1u64 << shift) - 1)) == 0 {
                    self.cascade(level);
                }
            }

            let mask = self.slot_mask();
            let slot0 = self.current_tick as usize & mask;
            self.wheels[0].current_slot = slot0;

            let entries: VecDeque<TimerEntry<T>> =
                std::mem::take(&mut self.wheels[0].slots[slot0]);
            for entry in entries {
                if entry.cancelled {
                    continue;
                }
                if entry.deadline <= self.current_tick {
                    expired.push(entry.value);
                    self.pending -= 1;
                } else {
                    let (w, s) = self.wheel_slot(entry.deadline);
                    self.wheels[w].slots[s].push_back(entry);
                }
            }
        }

        expired
    }

    /// Cascade entries from `wheel[level]`'s current slot into lower levels.
    fn cascade(&mut self, level: usize) {
        let mask = self.slot_mask();
        let shift = level as u32 * self.bits_per_wheel;
        let slot = (self.current_tick >> shift) as usize & mask;
        self.wheels[level].current_slot = slot;

        let entries: VecDeque<TimerEntry<T>> =
            std::mem::take(&mut self.wheels[level].slots[slot]);
        for entry in entries {
            if entry.cancelled {
                continue;
            }
            let (w, s) = self.wheel_slot(entry.deadline);
            self.wheels[w].slots[s].push_back(entry);
        }
    }

    /// Get the next expiry time (earliest pending timer), if any.
    pub fn next_expiry(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for wheel in &self.wheels {
            for slot in &wheel.slots {
                for entry in slot {
                    if entry.cancelled {
                        continue;
                    }
                    let ms = entry.deadline * self.resolution_ms;
                    earliest = Some(match earliest {
                        Some(e) => e.min(ms),
                        None => ms,
                    });
                }
            }
        }
        earliest
    }

    /// Number of pending (non-cancelled) timers.
    pub fn pending_count(&self) -> usize {
        self.pending
    }

    /// Returns `true` if there are no pending (non-cancelled) timers.
    pub fn is_empty(&self) -> bool {
        self.pending == 0
    }
}

impl<T> Default for TimerWheel<T> {
    fn default() -> Self {
        Self::new(4, 5, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_expire() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        tw.insert(10, 42);
        assert_eq!(tw.pending_count(), 1);

        let expired = tw.advance(9);
        assert!(expired.is_empty());

        let expired = tw.advance(10);
        assert_eq!(expired, vec![42]);
        assert_eq!(tw.pending_count(), 0);
    }

    #[test]
    fn multiple_timers_ordered() {
        let mut tw: TimerWheel<&str> = TimerWheel::new(4, 5, 1);
        tw.insert(20, "b");
        tw.insert(10, "a");
        tw.insert(30, "c");

        let a = tw.advance(15);
        assert_eq!(a, vec!["a"]);

        let b = tw.advance(25);
        assert_eq!(b, vec!["b"]);

        let c = tw.advance(35);
        assert_eq!(c, vec!["c"]);
    }

    #[test]
    fn cancel_timer() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        let handle = tw.insert(10, 99);
        assert_eq!(tw.pending_count(), 1);

        tw.cancel(handle);
        assert_eq!(tw.pending_count(), 0);

        let expired = tw.advance(20);
        assert!(expired.is_empty());
    }

    #[test]
    fn past_deadline_fires_immediately() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        tw.advance(100);
        tw.insert(50, 1);

        let expired = tw.advance(101);
        assert_eq!(expired, vec![1]);
    }

    #[test]
    fn resolution_scaling() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 10);
        tw.insert(100, 42); // tick 10
        tw.insert(50, 7);   // tick 5

        let a = tw.advance(60);
        assert_eq!(a, vec![7]);

        let b = tw.advance(100);
        assert_eq!(b, vec![42]);
    }

    #[test]
    fn is_empty_and_default() {
        let tw: TimerWheel<u32> = TimerWheel::default();
        assert!(tw.is_empty());
        assert_eq!(tw.pending_count(), 0);
    }

    #[test]
    fn cascading_across_levels() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(3, 3, 1); // 8 slots per level
        tw.insert(100, 100);
        tw.insert(200, 200);
        assert_eq!(tw.pending_count(), 2);

        let expired = tw.advance(100);
        assert!(expired.contains(&100), "expected 100 in {expired:?}");

        let expired = tw.advance(200);
        assert!(expired.contains(&200), "expected 200 in {expired:?}");
        assert!(tw.is_empty());
    }

    #[test]
    fn next_expiry() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        assert_eq!(tw.next_expiry(), None);

        tw.insert(50, 1);
        tw.insert(30, 2);
        tw.insert(100, 3);

        assert_eq!(tw.next_expiry(), Some(30));
    }

    #[test]
    fn many_timers_same_slot() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        for i in 0..100 {
            tw.insert(10, i);
        }
        assert_eq!(tw.pending_count(), 100);

        let expired = tw.advance(10);
        assert_eq!(expired.len(), 100);
        assert!(tw.is_empty());
    }

    #[test]
    fn advance_idempotent() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        tw.insert(10, 42);

        let a = tw.advance(10);
        assert_eq!(a.len(), 1);

        let b = tw.advance(10);
        assert!(b.is_empty());
    }

    #[test]
    fn stress_sequential_inserts() {
        let mut tw: TimerWheel<u64> = TimerWheel::new(4, 5, 1);
        for i in 1..=500 {
            tw.insert(i, i);
        }
        assert_eq!(tw.pending_count(), 500);

        let mut total = 0usize;
        for t in 1..=500 {
            let expired = tw.advance(t);
            total += expired.len();
        }
        assert_eq!(total, 500);
        assert!(tw.is_empty());
    }

    #[test]
    fn interleaved_insert_and_advance() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        tw.insert(5, 1);
        let e = tw.advance(3);
        assert!(e.is_empty());

        tw.insert(7, 2);
        let e = tw.advance(5);
        assert_eq!(e, vec![1]);

        let e = tw.advance(7);
        assert_eq!(e, vec![2]);
    }
}
