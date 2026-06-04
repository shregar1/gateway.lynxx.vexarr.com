use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{RwLock, RwLockReadGuard};
use std::time::Instant;

const NUM_SLOTS: usize = 64;
const INHIBIT_DURATION_NS: u64 = 5_000_000; // 5ms bias inhibit after write

#[repr(align(64))]
struct Slot {
    active: AtomicBool,
}

/// Biased Reader-Writer (BRAVO) lock optimised for read-heavy workloads.
///
/// Readers attempt a **fast path** that hashes the current thread ID to one of
/// 64 cache-line-aligned slots and sets an atomic flag — no contention on the
/// inner `RwLock` at all.  Writers first disable the bias flag, spin-wait until
/// every active slot drains, then acquire the underlying write lock.  A short
/// *inhibit window* after each write prevents bias from resuming immediately,
/// reducing thrashing when writes are bursty.
///
/// Use `BravoLock` when reads vastly outnumber writes and the critical section
/// is short enough that the spin-wait cost during writes is acceptable.
pub struct BravoLock<T> {
    data: UnsafeCell<T>,
    sync: RwLock<()>,
    slots: Vec<Slot>,
    rbias: AtomicBool,
    inhibit_until: AtomicU64,
}

/// RAII read guard returned by [`BravoLock::read`].
///
/// Holds either an active slot index (fast path) or an `RwLockReadGuard`
/// (slow path).  The protected data is accessed via [`get`](Self::get).
/// Dropping this guard releases the slot or underlying lock.
pub struct BravoReadGuard<'a, T> {
    slot: Option<usize>,
    lock: &'a BravoLock<T>,
    _guard: Option<RwLockReadGuard<'a, ()>>,
}

impl<'a, T> BravoReadGuard<'a, T> {
    /// Returns a shared reference to the lock-protected data.
    pub fn get(&self) -> &T {
        // SAFETY: We hold either an active slot (fast path) or the RwLock read guard
        // (slow path). In both cases no writer can mutate the data concurrently:
        //  - Fast path: the writer's `write()` spins until ALL slots are inactive
        //    before acquiring the write lock, so no &mut T can exist while our slot
        //    is active.
        //  - Slow path: we hold a RwLockReadGuard, which prevents any writer from
        //    acquiring the write lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> Drop for BravoReadGuard<'a, T> {
    fn drop(&mut self) {
        if let Some(slot_idx) = self.slot {
            self.lock.slots[slot_idx].active.store(false, Ordering::Release);
        }
    }
}

/// RAII write guard returned by [`BravoLock::write`].
///
/// Provides exclusive (`&mut`) access to the protected data through `Deref`
/// and `DerefMut`.  Dropping the guard re-enables reader bias and releases
/// the underlying write lock.
pub struct BravoWriteGuard<'a, T> {
    lock: &'a BravoLock<T>,
    /// `Option` so `Drop` can release the inner write lock *before* it
    /// re-enables reader bias.
    _guard: Option<std::sync::RwLockWriteGuard<'a, ()>>,
}

impl<'a, T> Deref for BravoWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: We hold the write lock AND all slot readers have drained,
        // so we have exclusive access to the data.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for BravoWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Same as Deref — exclusive access is guaranteed by the write lock
        // plus slot drain.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for BravoWriteGuard<'a, T> {
    fn drop(&mut self) {
        // Start the bias-inhibit window at write *completion*, so the next
        // readers don't immediately re-bias and thrash with a following writer.
        self.lock
            .inhibit_until
            .store(now_nanos() + INHIBIT_DURATION_NS, Ordering::Relaxed);
        // Release the inner write lock FIRST (so slow-path readers waiting on
        // `sync` proceed only once exclusive access has actually ended)...
        self._guard.take();
        // ...then re-enable reader bias. Because `rbias` was held `false` for
        // the entire lifetime of the exclusive `&mut T`, no fast-path reader
        // could have claimed a slot and aliased it.
        self.lock.rbias.store(true, Ordering::Release);
    }
}

impl<T> BravoLock<T> {
    /// Wraps `value` in a new `BravoLock` with reader bias enabled and 64
    /// cache-line-aligned slots for the fast read path.
    pub fn new(value: T) -> Self {
        let mut slots = Vec::with_capacity(NUM_SLOTS);
        for _ in 0..NUM_SLOTS {
            slots.push(Slot {
                active: AtomicBool::new(false),
            });
        }
        Self {
            data: UnsafeCell::new(value),
            sync: RwLock::new(()),
            slots,
            rbias: AtomicBool::new(true),
            inhibit_until: AtomicU64::new(0),
        }
    }

    /// Fast-path read lock: hash thread ID to a slot, set slot.active = true.
    /// If rbias is true and slot is free, reader proceeds without touching the RwLock.
    /// Otherwise, fall back to the underlying RwLock.
    pub fn read(&self) -> BravoReadGuard<'_, T> {
        if self.rbias.load(Ordering::Acquire) {
            let now = now_nanos();
            let inhibit = self.inhibit_until.load(Ordering::Relaxed);
            if now >= inhibit {
                let slot_idx = thread_slot();
                // Try to claim the slot (CAS from false to true).
                //
                // BUG FIX (soundness): this store-then-load handshake against the
                // writer is a Dekker/seqlock-revocation pattern. The reader's slot
                // store and its subsequent `rbias` load, together with the writer's
                // `rbias` store and its slot scan, MUST share one total order, or
                // StoreLoad reordering (allowed by Acquire/Release, and observable
                // even on x86-TSO via the store buffer) permits the SB-litmus
                // outcome where the writer's slot scan misses our `active=true`
                // while our `rbias` load misses the writer's `rbias=false`. Both
                // sides would then proceed, aliasing &T (fast-path reader) with
                // &mut T (writer) => UB. SeqCst on both of the reader's accesses
                // here (and on both of the writer's in `write()`) closes the window.
                if !self.slots[slot_idx].active.swap(true, Ordering::SeqCst) {
                    // Verify bias wasn't revoked between our check and the slot claim
                    if self.rbias.load(Ordering::SeqCst) {
                        return BravoReadGuard {
                            slot: Some(slot_idx),
                            lock: self,
                            _guard: None,
                        };
                    }
                    // Bias was revoked, release slot and fall back
                    self.slots[slot_idx].active.store(false, Ordering::Release);
                }
            }
        }

        // Slow path: acquire the actual RwLock
        let guard = self.sync.read().unwrap();
        BravoReadGuard {
            slot: None,
            lock: self,
            _guard: Some(guard),
        }
    }

    /// Write lock: disable rbias, scan all slots for active readers,
    /// wait until all readers drain, then acquire underlying write lock.
    /// Sets inhibit_until to prevent bias thrashing.
    pub fn write(&self) -> BravoWriteGuard<'_, T> {
        // Disable reader bias.
        //
        // BUG FIX (soundness): see `read()`. This `rbias` store and the slot scan
        // below form the writer half of the revocation handshake; they use SeqCst
        // (matching the reader's SeqCst slot store + `rbias` load) so all four
        // cross-checking accesses participate in a single total order. Without it,
        // StoreLoad reordering lets the writer's scan observe a stale `active=false`
        // while a fast-path reader's `rbias` load observes a stale `true`, so writer
        // and reader overlap and alias &mut T with &T (UB).
        self.rbias.store(false, Ordering::SeqCst);

        // Wait for all active slot readers to drain
        loop {
            let mut any_active = false;
            for slot in &self.slots {
                if slot.active.load(Ordering::SeqCst) {
                    any_active = true;
                    break;
                }
            }
            if !any_active {
                break;
            }
            std::hint::spin_loop();
        }

        // Acquire write lock (waits for any slow-path readers too)
        let guard = self.sync.write().unwrap();

        // Reader bias stays DISABLED for the whole lifetime of the returned
        // guard — it is re-enabled only in `BravoWriteGuard::drop`, after the
        // exclusive `&mut T` is gone. The previous code re-enabled bias here,
        // before returning the guard: since fast-path readers never touch
        // `sync` and the writer holds no slot, a reader could then claim a slot
        // and alias the live `&mut T` (the 5ms inhibit window was only a timing
        // heuristic, defeated by any longer critical section or a backward
        // clock jump — a data race / UB, not a correctness barrier).
        BravoWriteGuard {
            lock: self,
            _guard: Some(guard),
        }
    }

    /// Returns `true` if reader bias is currently enabled, meaning readers
    /// can use the slot-based fast path instead of the inner `RwLock`.
    pub fn is_biased(&self) -> bool {
        self.rbias.load(Ordering::Relaxed)
    }
}

// SAFETY: BravoLock uses UnsafeCell for interior mutability, protected by either:
// - Active slot (fast-path readers): writers spin-wait until all slots drain before
//   acquiring the write lock, so &T and &mut T never coexist.
// - RwLock (slow-path readers and all writers): standard read/write exclusion.
// T: Send is required because the data can be accessed from any thread.
// T: Sync is required because multiple readers can hold &T concurrently.
unsafe impl<T: Send + Sync> Send for BravoLock<T> {}
unsafe impl<T: Send + Sync> Sync for BravoLock<T> {}

fn thread_slot() -> usize {
    // Use thread ID hashed to a slot index
    let id = std::thread::current().id();
    let hash = {
        let mut h: u64 = 0;
        let id_num = format!("{:?}", id);
        for b in id_num.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u64);
        }
        h
    };
    (hash as usize) % NUM_SLOTS
}

fn now_nanos() -> u64 {
    // Monotonic timeline anchored at first use. The inhibit window guards
    // against bias thrashing, so it must never move backward; a wall-clock
    // (`SystemTime`) source could jump back under NTP and shrink or invert the
    // window.
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_basic_read() {
        let lock = BravoLock::new(42);
        let guard = lock.read();
        assert_eq!(*guard.get(), 42);
        drop(guard);
    }

    #[test]
    fn test_basic_write() {
        let lock = BravoLock::new(0);
        {
            let mut w = lock.write();
            *w = 99;
        }
        let r = lock.read();
        assert_eq!(*r.get(), 99);
    }

    #[test]
    fn test_multiple_readers() {
        let lock = Arc::new(BravoLock::new(7));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let l = Arc::clone(&lock);
                thread::spawn(move || {
                    let _g = l.read();
                    std::thread::sleep(Duration::from_millis(1));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_writer_blocks_readers() {
        let lock = Arc::new(BravoLock::new(0u64));
        let l2 = Arc::clone(&lock);

        let writer = thread::spawn(move || {
            let mut w = l2.write();
            *w = 100;
        });

        writer.join().unwrap();
        let r = lock.read();
        assert_eq!(*r.get(), 100);
    }

    #[test]
    fn test_is_biased_default() {
        let lock = BravoLock::new(0);
        assert!(lock.is_biased());
    }

    #[test]
    fn bias_disabled_for_full_write_guard_lifetime() {
        // Regression: write() used to re-enable reader bias before returning
        // the guard, so a fast-path reader could claim a slot and alias the
        // live &mut T. Bias must stay OFF for the entire lifetime of the
        // exclusive guard and only resume once it drops.
        let lock = BravoLock::new(0u64);
        let w = lock.write();
        assert!(
            !lock.is_biased(),
            "reader bias must stay disabled while a write guard is held"
        );
        drop(w);
        assert!(
            lock.is_biased(),
            "reader bias should resume after the write guard is dropped"
        );
    }

    #[test]
    fn test_concurrent_read_write() {
        let lock = Arc::new(BravoLock::new(0u64));
        let done = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let l = Arc::clone(&lock);
                let d = Arc::clone(&done);
                thread::spawn(move || {
                    while !d.load(Ordering::Relaxed) {
                        let _g = l.read();
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();

        // Perform writes
        for i in 0..100 {
            let mut w = lock.write();
            *w = i;
        }

        done.store(true, Ordering::Relaxed);
        for h in readers {
            h.join().unwrap();
        }

        let r = lock.read();
        assert_eq!(*r.get(), 99);
    }

    #[test]
    fn test_bias_inhibit_after_write() {
        let lock = BravoLock::new(0);
        let _w = lock.write();
        // After write releases, inhibit_until should be in the future
        drop(_w);
        // Bias is re-enabled but inhibit window may prevent fast path briefly
        assert!(lock.is_biased());
    }

    #[test]
    fn test_slot_distribution() {
        // Verify different threads get different slots (probabilistic)
        let results: Vec<_> = (0..NUM_SLOTS)
            .map(|_| thread::spawn(thread_slot))
            .collect();
        let slots: Vec<usize> = results.into_iter().map(|h| h.join().unwrap()).collect();
        // At least some should differ
        let unique: std::collections::HashSet<_> = slots.iter().collect();
        assert!(unique.len() > 1);
    }

    #[test]
    fn concurrent_readers_never_observe_writer_sentinel() {
        // Concurrency smoke test accompanying the SeqCst revocation-handshake fix.
        //
        // The bug: the reader/writer handshake used Acquire/Release on its four
        // cross-checking accesses (reader's slot `swap` + `rbias` load; writer's
        // `rbias` store + slot-scan load). That is a Dekker / store-then-load
        // pattern that needs a single total order — Acquire/Release permits
        // StoreLoad reordering, so the writer's scan could miss a reader's
        // `active=true` while that reader's `rbias` load missed the writer's
        // `rbias=false`, letting a fast-path reader's &T alias the writer's
        // &mut T. The fix promotes those four accesses to SeqCst.
        //
        // HONEST CAVEAT: this test does NOT deterministically reproduce the
        // store-buffer race. The window is tiny, and because every write arms a
        // 5ms bias-inhibit, readers spend most of a hammer loop on the slow path,
        // so the buggy Acquire/Release version would usually pass here too. Treat
        // it as a non-flaky invariant check (a fast-path reader must never observe
        // the writer's transient sentinel), not a guaranteed regression. The fix's
        // correctness rests on the SeqCst total-order argument above; deterministic
        // verification needs a model checker (loom) or ThreadSanitizer.
        const SENTINEL: u64 = u64::MAX;
        let lock = Arc::new(BravoLock::new(0u64));
        let done = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..6)
            .map(|_| {
                let l = Arc::clone(&lock);
                let d = Arc::clone(&done);
                thread::spawn(move || {
                    while !d.load(Ordering::Relaxed) {
                        let g = l.read();
                        // If a reader and writer ever overlap, the reader can
                        // observe the writer's transient SENTINEL -> aliasing UB.
                        assert_ne!(
                            *g.get(),
                            SENTINEL,
                            "fast-path reader observed the writer's exclusive \
                             sentinel: reader and writer overlapped (missing \
                             SeqCst total order in the revocation handshake)"
                        );
                        drop(g);
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();

        // Hammer the write path so revocations race against fast-path readers.
        for i in 1..2_000u64 {
            let mut w = lock.write();
            // Enter the forbidden state while exclusive, then leave a valid
            // value before dropping the guard.
            *w = SENTINEL;
            std::hint::spin_loop();
            *w = i;
        }

        done.store(true, Ordering::Relaxed);
        for h in readers {
            h.join().unwrap();
        }

        // Final state is the last committed (non-sentinel) value.
        let r = lock.read();
        assert_eq!(*r.get(), 1_999);
    }
}
