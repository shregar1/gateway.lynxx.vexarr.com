/// HTTP/2 dependency-tree scheduler with Weighted Fair Queueing (inspired by H2O).
///
/// Each stream has a weight (1-256), an optional parent stream, and an
/// `active` flag.  `schedule()` walks the dependency tree from the root,
/// performing WFQ among active siblings: each active child accumulates
/// "deficit" proportional to its weight, and the child with the highest
/// deficit is scheduled next.
use std::collections::HashMap;

#[derive(Debug)]
struct StreamNode {
    weight: u16,
    parent: u32,
    active: bool,
    deficit: f64,
    children: Vec<u32>,
}

/// HTTP/2 stream dependency-tree scheduler.
pub struct H2Scheduler {
    streams: HashMap<u32, StreamNode>,
}

/// Root stream ID per RFC 9113: stream 0 is the virtual root of the tree.
const ROOT_ID: u32 = 0;

impl H2Scheduler {
    /// Create a new scheduler with the virtual root stream (id 0).
    pub fn new() -> Self {
        let mut streams = HashMap::new();
        streams.insert(
            ROOT_ID,
            StreamNode {
                weight: 16,
                parent: ROOT_ID,
                active: false,
                deficit: 0.0,
                children: Vec::new(),
            },
        );
        Self { streams }
    }

    /// Add a stream to the dependency tree.
    ///
    /// - `weight`: 1-256 (clamped).
    /// - `parent`: the parent stream (defaults to root 0 if `None` or unknown).
    /// - `exclusive`: if true, this stream becomes the sole child of the parent
    ///   and all former children of the parent become children of this stream.
    pub fn add_stream(&mut self, id: u32, weight: u16, parent: Option<u32>, exclusive: bool) {
        let weight = weight.clamp(1, 256);
        let parent_id = parent.unwrap_or(ROOT_ID);
        let actual_parent = if self.streams.contains_key(&parent_id) {
            parent_id
        } else {
            ROOT_ID
        };

        // Prevent self-dependency.
        if id == actual_parent {
            return;
        }

        if exclusive {
            // Move all current children of the parent under the new stream.
            let former_children = if let Some(p) = self.streams.get_mut(&actual_parent) {
                std::mem::take(&mut p.children)
            } else {
                Vec::new()
            };

            for &child_id in &former_children {
                if let Some(child) = self.streams.get_mut(&child_id) {
                    child.parent = id;
                }
            }

            // Insert the new stream with the adopted children.
            self.streams.insert(
                id,
                StreamNode {
                    weight,
                    parent: actual_parent,
                    active: false,
                    deficit: 0.0,
                    children: former_children,
                },
            );

            // The parent's only child is now this stream.
            if let Some(p) = self.streams.get_mut(&actual_parent) {
                p.children.push(id);
            }
        } else {
            self.streams.insert(
                id,
                StreamNode {
                    weight,
                    parent: actual_parent,
                    active: false,
                    deficit: 0.0,
                    children: Vec::new(),
                },
            );
            if let Some(p) = self.streams.get_mut(&actual_parent) {
                p.children.push(id);
            }
        }
    }

    /// Remove a stream.  Its children are re-parented to the removed stream's
    /// parent (weights proportionally redistributed).
    pub fn remove_stream(&mut self, id: u32) {
        if id == ROOT_ID {
            return;
        }
        let node = match self.streams.remove(&id) {
            Some(n) => n,
            None => return,
        };

        // Re-parent children.
        for &child_id in &node.children {
            if let Some(child) = self.streams.get_mut(&child_id) {
                child.parent = node.parent;
            }
            if let Some(parent) = self.streams.get_mut(&node.parent) {
                parent.children.push(child_id);
            }
        }

        // Remove from parent's children list.
        if let Some(parent) = self.streams.get_mut(&node.parent) {
            parent.children.retain(|&c| c != id);
        }
    }

    /// Mark a stream as active (has data to send).
    pub fn activate(&mut self, id: u32) {
        if let Some(node) = self.streams.get_mut(&id) {
            node.active = true;
        }
    }

    /// Select the next stream to send data for using WFQ.
    ///
    /// Walks the tree depth-first from the root.  At each node, if the node
    /// itself is active it is a candidate.  Among active siblings, the one
    /// with the highest accumulated deficit is chosen and its deficit is
    /// decremented.  Returns `None` if no stream is active.
    pub fn schedule(&mut self) -> Option<u32> {
        self.schedule_from(ROOT_ID)
    }

    fn schedule_from(&mut self, node_id: u32) -> Option<u32> {
        let children: Vec<u32> = match self.streams.get(&node_id) {
            Some(n) => n.children.clone(),
            None => return None,
        };

        if children.is_empty() {
            return if node_id != ROOT_ID
                && self.streams.get(&node_id).map_or(false, |n| n.active)
            {
                Some(node_id)
            } else {
                None
            };
        }

        // Collect candidates: active children or children with active descendants.
        // Increment each active child's deficit by its weight.
        for &cid in &children {
            if self.has_active_descendant(cid) {
                if let Some(child) = self.streams.get_mut(&cid) {
                    child.deficit += child.weight as f64;
                }
            }
        }

        // Pick the child with the highest deficit that has active descendants.
        let mut best_id: Option<u32> = None;
        let mut best_deficit = f64::NEG_INFINITY;

        for &cid in &children {
            if self.has_active_descendant(cid) {
                let deficit = self.streams.get(&cid).map_or(0.0, |n| n.deficit);
                if deficit > best_deficit {
                    best_deficit = deficit;
                    best_id = Some(cid);
                }
            }
        }

        let chosen = best_id?;

        // Decrement the chosen child's deficit.
        if let Some(child) = self.streams.get_mut(&chosen) {
            child.deficit -= child.weight as f64;
        }

        // If the chosen child is itself active, return it; otherwise recurse.
        let is_active = self.streams.get(&chosen).map_or(false, |n| n.active);
        if is_active {
            Some(chosen)
        } else {
            self.schedule_from(chosen)
        }
    }

    fn has_active_descendant(&self, id: u32) -> bool {
        let node = match self.streams.get(&id) {
            Some(n) => n,
            None => return false,
        };
        if node.active {
            return true;
        }
        for &cid in &node.children {
            if self.has_active_descendant(cid) {
                return true;
            }
        }
        false
    }

    /// Reprioritize a stream: change weight and/or parent.
    pub fn reprioritize(
        &mut self,
        id: u32,
        weight: u16,
        parent: Option<u32>,
        exclusive: bool,
    ) {
        if id == ROOT_ID || !self.streams.contains_key(&id) {
            return;
        }
        let weight = weight.clamp(1, 256);

        // Detach from current parent.
        let old_parent = self.streams.get(&id).map(|n| n.parent).unwrap_or(ROOT_ID);
        if let Some(p) = self.streams.get_mut(&old_parent) {
            p.children.retain(|&c| c != id);
        }

        let new_parent_id = parent.unwrap_or(ROOT_ID);
        let actual_parent = if self.streams.contains_key(&new_parent_id) && new_parent_id != id {
            new_parent_id
        } else {
            ROOT_ID
        };

        // Check for circular dependency: if actual_parent is a descendant of id,
        // move actual_parent under old_parent first.
        if self.is_descendant_of(actual_parent, id) {
            // Detach actual_parent from its current parent.
            let ap_parent = self
                .streams
                .get(&actual_parent)
                .map(|n| n.parent)
                .unwrap_or(ROOT_ID);
            if let Some(p) = self.streams.get_mut(&ap_parent) {
                p.children.retain(|&c| c != actual_parent);
            }
            // Re-parent actual_parent under old_parent of id.
            if let Some(node) = self.streams.get_mut(&actual_parent) {
                node.parent = old_parent;
            }
            if let Some(p) = self.streams.get_mut(&old_parent) {
                p.children.push(actual_parent);
            }
        }

        if exclusive {
            let former_children = if let Some(p) = self.streams.get_mut(&actual_parent) {
                let fc: Vec<u32> = p.children.iter().copied().filter(|&c| c != id).collect();
                p.children.retain(|&c| c == id);
                fc
            } else {
                Vec::new()
            };

            for &cid in &former_children {
                if let Some(child) = self.streams.get_mut(&cid) {
                    child.parent = id;
                }
            }

            if let Some(node) = self.streams.get_mut(&id) {
                node.weight = weight;
                node.parent = actual_parent;
                node.children.extend(former_children);
            }
        } else if let Some(node) = self.streams.get_mut(&id) {
            node.weight = weight;
            node.parent = actual_parent;
        }

        // Add to new parent's children list.
        if let Some(p) = self.streams.get_mut(&actual_parent) {
            if !p.children.contains(&id) {
                p.children.push(id);
            }
        }
    }

    fn is_descendant_of(&self, potential_descendant: u32, ancestor: u32) -> bool {
        if potential_descendant == ancestor {
            return false;
        }
        let node = match self.streams.get(&ancestor) {
            Some(n) => n,
            None => return false,
        };
        for &cid in &node.children {
            if cid == potential_descendant || self.is_descendant_of(potential_descendant, cid) {
                return true;
            }
        }
        false
    }
}

impl Default for H2Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_schedule() {
        let mut s = H2Scheduler::new();
        assert_eq!(s.schedule(), None);
    }

    #[test]
    fn test_single_active_stream() {
        let mut s = H2Scheduler::new();
        s.add_stream(1, 16, None, false);
        s.activate(1);
        assert_eq!(s.schedule(), Some(1));
    }

    #[test]
    fn test_weighted_fairness() {
        let mut s = H2Scheduler::new();
        s.add_stream(1, 200, None, false);
        s.add_stream(2, 50, None, false);
        s.activate(1);
        s.activate(2);

        // Over many rounds, stream 1 (weight 200) should be scheduled
        // more often than stream 2 (weight 50).
        let mut count1 = 0u32;
        let mut count2 = 0u32;
        for _ in 0..100 {
            match s.schedule() {
                Some(1) => count1 += 1,
                Some(2) => count2 += 1,
                _ => {}
            }
        }
        assert!(count1 > count2, "stream 1 ({count1}) should be scheduled more than stream 2 ({count2})");
    }

    #[test]
    fn test_remove_reparents() {
        let mut s = H2Scheduler::new();
        s.add_stream(1, 16, None, false);
        s.add_stream(2, 16, Some(1), false);
        s.activate(2);
        s.remove_stream(1);
        // Stream 2 should now be under root and still schedulable.
        assert_eq!(s.schedule(), Some(2));
    }

    #[test]
    fn test_exclusive_flag() {
        let mut s = H2Scheduler::new();
        s.add_stream(1, 16, None, false);
        s.add_stream(2, 16, None, false);
        // Stream 3 exclusive under root: 1 and 2 become children of 3.
        s.add_stream(3, 16, None, true);
        s.activate(1);
        // Stream 1 is now under stream 3, so scheduling should still work.
        assert_eq!(s.schedule(), Some(1));
    }

    #[test]
    fn test_reprioritize() {
        let mut s = H2Scheduler::new();
        s.add_stream(1, 16, None, false);
        s.add_stream(2, 16, None, false);
        s.activate(1);
        s.activate(2);

        // Give stream 2 a much higher weight.
        s.reprioritize(2, 256, None, false);

        let mut count1 = 0u32;
        let mut count2 = 0u32;
        for _ in 0..100 {
            match s.schedule() {
                Some(1) => count1 += 1,
                Some(2) => count2 += 1,
                _ => {}
            }
        }
        assert!(count2 > count1, "stream 2 ({count2}) should be scheduled more after reprioritize");
    }
}
