//! First Available Server (HAProxy).
//!
//! Returns the lowest-indexed server that is marked "up". Uses atomic bools
//! for interior mutability so `mark_down` and `mark_up` take `&self`.

use std::sync::atomic::{AtomicBool, Ordering};

/// First Available Server selector.
pub struct FasSelector {
    up: Vec<AtomicBool>,
}

impl FasSelector {
    /// Create a new selector where all `count` backends start in the "up" state.
    pub fn new(count: usize) -> Self {
        assert!(count > 0, "count must be > 0");
        Self {
            up: (0..count).map(|_| AtomicBool::new(true)).collect(),
        }
    }

    /// Return the first (lowest-index) available backend, or `None` if all
    /// are down.
    pub fn pick(&self) -> Option<usize> {
        self.up
            .iter()
            .position(|b| b.load(Ordering::Relaxed))
    }

    /// Mark backend `idx` as down.
    pub fn mark_down(&self, idx: usize) {
        self.up[idx].store(false, Ordering::Relaxed);
    }

    /// Mark backend `idx` as up.
    pub fn mark_up(&self, idx: usize) {
        self.up[idx].store(true, Ordering::Relaxed);
    }

    /// Whether backend `idx` is currently up.
    pub fn is_up(&self, idx: usize) -> bool {
        self.up[idx].load(Ordering::Relaxed)
    }

    /// Number of backends.
    pub fn len(&self) -> usize {
        self.up.len()
    }

    /// Returns true when there are no backends.
    pub fn is_empty(&self) -> bool {
        self.up.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_first_when_all_up() {
        let sel = FasSelector::new(5);
        assert_eq!(sel.pick(), Some(0));
    }

    #[test]
    fn skips_down_backends() {
        let sel = FasSelector::new(5);
        sel.mark_down(0);
        sel.mark_down(1);
        assert_eq!(sel.pick(), Some(2));
    }

    #[test]
    fn none_when_all_down() {
        let sel = FasSelector::new(3);
        for i in 0..3 {
            sel.mark_down(i);
        }
        assert_eq!(sel.pick(), None);
    }

    #[test]
    fn mark_up_restores() {
        let sel = FasSelector::new(2);
        sel.mark_down(0);
        sel.mark_down(1);
        assert_eq!(sel.pick(), None);
        sel.mark_up(1);
        assert_eq!(sel.pick(), Some(1));
    }
}
