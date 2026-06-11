/// Timer wheel backed by a red-black tree.
///
/// Each timer has a deadline (u64 timestamp) and an ID. The tree is
/// ordered by deadline so `next_expired` is O(log n). Cancellation
/// is also O(log n) via a secondary lookup.

use std::collections::{BTreeMap, HashMap};

pub struct TimerRbTree {
    /// deadline -> list of timer IDs (handles ties)
    deadlines: BTreeMap<u64, Vec<u64>>,
    /// timer ID -> deadline (for cancellation)
    id_to_deadline: HashMap<u64, u64>,
}

impl TimerRbTree {
    pub fn new() -> Self {
        Self {
            deadlines: BTreeMap::new(),
            id_to_deadline: HashMap::new(),
        }
    }

    /// Add a timer that fires at `deadline` with identifier `id`.
    pub fn add_timer(&mut self, deadline: u64, id: u64) {
        self.deadlines
            .entry(deadline)
            .or_insert_with(Vec::new)
            .push(id);
        self.id_to_deadline.insert(id, deadline);
    }

    /// Pop and return the ID of the next expired timer (deadline <= now).
    /// Returns None if no timers are expired.
    pub fn next_expired(&mut self, now: u64) -> Option<u64> {
        // Check the minimum deadline
        let (&min_deadline, _) = self.deadlines.iter().next()?;
        if min_deadline > now {
            return None;
        }

        let ids = self.deadlines.get_mut(&min_deadline).unwrap();
        let id = ids.pop().unwrap();
        if ids.is_empty() {
            self.deadlines.remove(&min_deadline);
        }
        self.id_to_deadline.remove(&id);
        Some(id)
    }

    /// Cancel a timer by ID. Returns true if the timer was found and removed.
    pub fn cancel(&mut self, id: u64) -> bool {
        if let Some(deadline) = self.id_to_deadline.remove(&id) {
            if let Some(ids) = self.deadlines.get_mut(&deadline) {
                ids.retain(|&i| i != id);
                if ids.is_empty() {
                    self.deadlines.remove(&deadline);
                }
            }
            true
        } else {
            false
        }
    }
}

impl Default for TimerRbTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fire_in_order() {
        let mut tw = TimerRbTree::new();
        tw.add_timer(100, 1);
        tw.add_timer(50, 2);
        tw.add_timer(200, 3);

        assert_eq!(tw.next_expired(60), Some(2));
        assert_eq!(tw.next_expired(60), None);
        assert_eq!(tw.next_expired(150), Some(1));
        assert_eq!(tw.next_expired(250), Some(3));
    }

    #[test]
    fn cancel_timer() {
        let mut tw = TimerRbTree::new();
        tw.add_timer(100, 1);
        tw.add_timer(100, 2);
        assert!(tw.cancel(1));
        assert!(!tw.cancel(1)); // already cancelled
        assert_eq!(tw.next_expired(200), Some(2));
    }

    #[test]
    fn no_expired() {
        let mut tw = TimerRbTree::new();
        tw.add_timer(100, 1);
        assert_eq!(tw.next_expired(50), None);
    }

    #[test]
    fn same_deadline() {
        let mut tw = TimerRbTree::new();
        tw.add_timer(100, 1);
        tw.add_timer(100, 2);
        tw.add_timer(100, 3);
        let mut fired = Vec::new();
        while let Some(id) = tw.next_expired(100) {
            fired.push(id);
        }
        assert_eq!(fired.len(), 3);
    }
}
