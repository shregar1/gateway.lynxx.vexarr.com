//! Hierarchical timer wheel for O(1) timer insert/cancel with cascading.
//!
//! Multi-level design: each wheel level covers an exponentially larger time
//! range. Lower-level wheels have fine granularity; higher levels cascade
//! entries downward as time advances.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug)]
struct TimerEntry<T> {
    deadline: u64,
    value: T,
    // BUG FIX: cancellation state is now a shared flag rather than a plain
    // `bool`. The matching `TimerHandle` holds a clone of this `Arc`, so a
    // handle can cancel its timer no matter which slot the entry has been
    // cascaded/re-homed into. (Previously handles were positional and broke
    // the moment an entry moved.) `true` means cancelled *or* already fired,
    // so a redundant `cancel()` after either is a safe no-op.
    cancelled: Arc<AtomicBool>,
}

struct Wheel<T> {
    slots: Vec<VecDeque<TimerEntry<T>>>,
    current_slot: usize,
}

/// Opaque handle returned by [`TimerWheel::insert`] for O(1) cancellation.
///
/// The handle shares a cancellation flag with its timer entry, so it stays
/// valid even after the entry is cascaded between wheel levels or re-homed to
/// a different slot. Pass it to [`TimerWheel::cancel`] to lazily mark the timer
/// as cancelled. The handle is [`Clone`] (but not `Copy`) because it holds a
/// reference-counted flag.
#[derive(Debug, Clone)]
pub struct TimerHandle {
    // BUG FIX: previously this held positional coordinates (wheel/slot/index)
    // captured at insert time. Those coordinates went stale once `advance`
    // re-homed an entry or `cascade` redistributed a slot, so `cancel` would
    // silently no-op (timer fired anyway) or, on index collision, cancel a
    // different live timer. A shared flag is position-independent.
    cancelled: Arc<AtomicBool>,
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
    ///
    /// # Panics
    ///
    /// Panics unless `num_wheels >= 1`, `bits_per_wheel >= 1`, and
    /// `num_wheels * bits_per_wheel <= 64`. The top level's slot shift is
    /// `(num_wheels - 1) * bits_per_wheel`, so this precondition keeps every
    /// `<<`/`>>` by that shift strictly below 64 bits.
    pub fn new(num_wheels: usize, bits_per_wheel: u32, resolution_ms: u64) -> Self {
        // BUG FIX: validate the level/bit geometry up front. Without this,
        // configs where `num_wheels * bits_per_wheel` approaches/exceeds 64
        // (e.g. new(20, 5, 1)) produced shift amounts >= 64 in wheel_slot,
        // advance, and cascade — a debug-mode "attempt to shift with overflow"
        // panic (e.g. advance(1) hitting `1u64 << 65`) and, in release, a
        // silent mod-64 wraparound that mis-schedules or loses timers. Bounding
        // the geometry keeps the largest shift, (num_wheels-1)*bits_per_wheel,
        // strictly below 64 so all shifts are well-defined.
        assert!(num_wheels >= 1, "num_wheels must be >= 1");
        assert!(bits_per_wheel >= 1, "bits_per_wheel must be >= 1");
        assert!(
            (num_wheels as u32).saturating_mul(bits_per_wheel) <= 64,
            "num_wheels * bits_per_wheel must be <= 64 (got {num_wheels} * {bits_per_wheel})"
        );
        // Bound bits_per_wheel on its own too: the product check above still
        // admits e.g. new(1, 63, ..), and `1usize << 63` slots is a multi-
        // exabyte allocation (and `1 << bits` is a UB shift for bits >= 64). Cap
        // per-wheel slots at 2^20 — far above any real wheel (typical wheels use
        // 6–8 bits) yet safely bounded.
        assert!(
            bits_per_wheel <= 20,
            "bits_per_wheel must be <= 20 (per-wheel slots = 2^bits_per_wheel); got {bits_per_wheel}"
        );

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
        // Shared cancellation flag: one clone lives in the entry, the other is
        // returned in the handle. This makes cancellation independent of the
        // entry's current slot, which changes as it cascades/re-homes.
        let cancelled = Arc::new(AtomicBool::new(false));
        self.wheels[wheel].slots[slot].push_back(TimerEntry {
            deadline: effective,
            value,
            cancelled: Arc::clone(&cancelled),
        });
        self.pending += 1;
        TimerHandle { cancelled }
    }

    /// Cancel a timer by handle. Returns `None` (lazy cancellation; entry
    /// is cleaned up on the next advance that touches its slot).
    pub fn cancel(&mut self, handle: TimerHandle) -> Option<T> {
        // BUG FIX: flip the entry's *shared* cancellation flag instead of
        // chasing stale (wheel/slot/index) coordinates that go invalid once an
        // entry cascades or is re-homed. The flag is also set when a timer
        // fires, so cancelling an already-fired (or already-cancelled) timer is
        // a no-op and never double-decrements `pending`.
        let was_set = handle.cancelled.swap(true, Ordering::Relaxed);
        if !was_set {
            self.pending -= 1;
        }
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
                if entry.cancelled.load(Ordering::Relaxed) {
                    continue;
                }
                if entry.deadline <= self.current_tick {
                    // Mark the now-consumed entry's flag so a later cancel() on
                    // its handle is a no-op (and cannot double-decrement pending).
                    entry.cancelled.store(true, Ordering::Relaxed);
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
            if entry.cancelled.load(Ordering::Relaxed) {
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
                    if entry.cancelled.load(Ordering::Relaxed) {
                        continue;
                    }
                    // BUG FIX: saturate the tick->ms back-conversion. A plain
                    // `deadline * resolution_ms` overflows u64 for a pathological
                    // resolution_ms (e.g. 1<<63) combined with the past-deadline
                    // `effective = current_tick + 1` path — debug panics
                    // ("attempt to multiply with overflow"), release wraps to a
                    // bogus too-early wake. Saturating to u64::MAX is the correct
                    // "very far future" semantics for the next-expiry hint.
                    let ms = entry.deadline.saturating_mul(self.resolution_ms);
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

    // Regression: a timer initially placed at a higher wheel level is cascaded
    // (re-homed to a different slot) by `advance`. The handle's old positional
    // (wheel/slot/index) coordinates went stale, so `cancel` silently no-oped
    // and the timer fired anyway. With the shared cancellation flag, `cancel`
    // must still take effect after the entry has moved.
    #[test]
    fn cancel_after_cascade_still_cancels() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        // deadline 40 (tick 40) lands on level 1 with 32 slots/level.
        let h = tw.insert(40, 7);
        assert_eq!(tw.pending_count(), 1);

        // Advance across the level-1 boundary (tick 32) so the entry cascades
        // out of its original slot and is re-homed lower in the wheel.
        let early = tw.advance(32);
        assert!(early.is_empty(), "nothing should fire before the deadline");

        // Cancel via the original handle: must actually cancel the re-homed entry.
        tw.cancel(h);
        assert_eq!(tw.pending_count(), 0, "cancel must decrement pending once");

        // The cancelled timer must not fire when we reach/pass its deadline.
        let expired = tw.advance(45);
        assert!(
            expired.is_empty(),
            "cascaded-then-cancelled timer must not fire, got {expired:?}"
        );
    }

    // Regression: two timers sharing a higher-level slot, cancelled after a
    // cascade. Old positional handles could even collide and cancel the wrong
    // entry; both shared-flag cancels must hit their own entries.
    #[test]
    fn cancel_multiple_after_cascade() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        let h1 = tw.insert(40, 1);
        let h2 = tw.insert(40, 2);
        assert_eq!(tw.pending_count(), 2);

        let early = tw.advance(35);
        assert!(early.is_empty());

        tw.cancel(h1);
        tw.cancel(h2);
        assert_eq!(tw.pending_count(), 0);

        let expired = tw.advance(45);
        assert!(
            expired.is_empty(),
            "both cascaded-then-cancelled timers must not fire, got {expired:?}"
        );
        assert!(tw.is_empty());
    }

    // Regression: cancelling a handle whose timer has already fired must be a
    // no-op and must not double-decrement `pending` (the firing path marks the
    // shared flag so a later cancel is recognized as already-terminal).
    #[test]
    fn cancel_after_fire_is_noop() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, 1);
        let h = tw.insert(40, 9);

        let expired = tw.advance(40);
        assert_eq!(expired, vec![9]);
        assert_eq!(tw.pending_count(), 0);

        // Cancelling the already-fired timer must not underflow/disturb pending.
        tw.cancel(h);
        assert_eq!(tw.pending_count(), 0);
        assert!(tw.is_empty());
    }

    // Regression (shift overflow): a geometry where num_wheels * bits_per_wheel
    // exceeds 64 used to construct fine and then panic later with a cryptic
    // "attempt to shift left with overflow" inside advance() (e.g. new(20,5,1)
    // then advance(1) hitting `1u64 << 65`), and silently mis-schedule timers in
    // release. new() must now reject the geometry up front with a clear message.
    #[test]
    #[should_panic(expected = "num_wheels * bits_per_wheel must be <= 64")]
    fn rejects_oversized_wheel_geometry() {
        // 20 * 5 = 100 > 64 — previously accepted, then overflowed in advance().
        let _tw: TimerWheel<u32> = TimerWheel::new(20, 5, 1);
    }

    // A near-boundary geometry (12 * 5 = 60 <= 64) is valid and must still work:
    // the precondition only rejects truly out-of-range configs, not legitimate
    // deep wheels.
    #[test]
    fn boundary_wheel_geometry_works() {
        let mut tw: TimerWheel<u32> = TimerWheel::new(12, 5, 1);
        tw.insert(1000, 5);
        assert_eq!(tw.pending_count(), 1);
        let expired = tw.advance(1000);
        assert_eq!(expired, vec![5]);
        assert!(tw.is_empty());
    }

    // Regression (overflow in next_expiry): with a pathological resolution_ms and
    // a past-deadline insert (effective = current_tick + 1), the tick->ms back-
    // conversion `deadline * resolution_ms` overflowed u64 — debug panicked with
    // "attempt to multiply with overflow", release wrapped to a bogus too-early
    // wake. It must now saturate to u64::MAX instead.
    #[test]
    fn next_expiry_saturates_on_overflow() {
        let res = 1u64 << 63;
        let mut tw: TimerWheel<u32> = TimerWheel::new(4, 5, res);
        // Drive current_tick to 1 (target_tick = res / res = 1).
        tw.advance(res);
        // Past-deadline insert stores effective = current_tick + 1 = 2.
        tw.insert(0, 1);
        assert_eq!(tw.pending_count(), 1);
        // 2 * (1<<63) == 2^64 overflows u64; must saturate rather than panic/wrap.
        assert_eq!(tw.next_expiry(), Some(u64::MAX));
    }
}
