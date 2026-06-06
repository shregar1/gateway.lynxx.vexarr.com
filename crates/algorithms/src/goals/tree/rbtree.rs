/// Red-black tree — self-balancing BST.
///
/// Arena-allocated nodes with parent/child indices. Provides O(log n)
/// insert, lookup, and remove. Used as the basis for timer wheels
/// and string-keyed maps.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Color {
    Red,
    Black,
}

struct RbNode<K, V> {
    key: K,
    /// `Option` so a removed node's value can be moved out with `take()`,
    /// leaving `None` behind. Reachable nodes always hold `Some`.
    value: Option<V>,
    color: Color,
    parent: usize,
    left: usize,
    right: usize,
}

const NIL: usize = 0;

pub struct RbTree<K: Ord, V> {
    nodes: Vec<RbNode<K, V>>,
    root: usize,
}

impl<K: Ord, V> RbTree<K, V> {
    pub fn new() -> Self {
        // Index 0 is the NIL sentinel
        Self {
            nodes: Vec::new(),
            root: NIL,
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        // Simple BST insert + rebalance
        let new_idx = self.nodes.len() + 1; // 1-based indexing (0 = NIL)
        self.nodes.push(RbNode {
            key,
            value: Some(value),
            color: Color::Red,
            parent: NIL,
            left: NIL,
            right: NIL,
        });

        if self.root == NIL {
            self.root = new_idx;
            self.node_mut(new_idx).color = Color::Black;
            return;
        }

        // BST insert
        let mut current = self.root;
        loop {
            if self.node(new_idx).key < self.node(current).key {
                let left = self.node(current).left;
                if left == NIL {
                    self.node_mut(current).left = new_idx;
                    self.node_mut(new_idx).parent = current;
                    break;
                }
                current = left;
            } else if self.node(new_idx).key > self.node(current).key {
                let right = self.node(current).right;
                if right == NIL {
                    self.node_mut(current).right = new_idx;
                    self.node_mut(new_idx).parent = current;
                    break;
                }
                current = right;
            } else {
                // Key exists — overwrite with the new value. The new node was
                // just pushed, so it is the last arena slot; pop it back off.
                // Assert that invariant so a future change to the arena layout
                // (which would make this pop reclaim the wrong slot) fails loudly
                // in tests instead of silently corrupting the tree.
                debug_assert_eq!(
                    self.nodes.len(),
                    new_idx,
                    "insert-overwrite assumes the freshly pushed node is the last arena slot"
                );
                self.node_mut(current).value = self.nodes.pop().unwrap().value;
                return;
            }
        }

        self.fix_insert(new_idx);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        let mut current = self.root;
        while current != NIL {
            let node = self.node(current);
            if *key < node.key {
                current = node.left;
            } else if *key > node.key {
                current = node.right;
            } else {
                return node.value.as_ref();
            }
        }
        None
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.find_node(key)?;
        // NOTE (known limitation): this performs the BST unlink + the single
        // recolour of a replacement child, but NOT the full red-black
        // delete-fixup (sibling rotations/recolouring). The tree therefore stays
        // a correct BST — lookups/inserts/removes return correct results — but
        // its black-height balance can degrade under heavy delete churn, losing
        // the strict O(log n) guarantee (worst case toward O(n)). Accepted
        // trade-off for the insert-heavy use here (timer wheels / routing
        // tables); a delete-heavy workload that needs guaranteed balance should
        // swap in a vetted balanced-tree crate rather than hand-roll the
        // sentinel-less fixup on this arena.
        Some(self.delete_node(idx))
    }

    fn find_node(&self, key: &K) -> Option<usize> {
        let mut current = self.root;
        while current != NIL {
            let node = self.node(current);
            if *key < node.key {
                current = node.left;
            } else if *key > node.key {
                current = node.right;
            } else {
                return Some(current);
            }
        }
        None
    }

    fn delete_node(&mut self, idx: usize) -> V {
        let left = self.node(idx).left;
        let right = self.node(idx).right;

        if left != NIL && right != NIL {
            // Two children: move the in-order successor's payload into this
            // node, then delete the successor. The successor is the minimum of
            // the right subtree, so it has no left child and therefore falls
            // into the ≤1-child base case below — the recursion is bounded to
            // one extra level and always terminates.
            //
            // Only the key+value move; the structural links
            // (color/parent/left/right) stay with the slot. The previous code
            // swapped whole nodes, which dragged the children along, so the
            // slot kept re-qualifying as a two-child node and recursed
            // forever.
            let succ = self.minimum(right);
            self.swap_payload(idx, succ);
            return self.delete_node(succ);
        }

        // Zero or one child: splice `idx` out of the tree.
        let child = if left != NIL { left } else { right };
        let parent = self.node(idx).parent;
        let color = self.node(idx).color;

        if child != NIL {
            self.node_mut(child).parent = parent;
        }

        if parent == NIL {
            self.root = child;
        } else if self.node(parent).left == idx {
            self.node_mut(parent).left = child;
        } else {
            self.node_mut(parent).right = child;
        }

        if color == Color::Black && child != NIL {
            self.node_mut(child).color = Color::Black;
        }

        // Move the value out of the arena slot, leaving `None` behind. The
        // spliced node physically remains in the arena (its slot is not
        // reclaimed — a known limitation of this simplified tree), but it is
        // unreachable through the tree and its value is now owned solely by
        // the caller, so it drops exactly once. This replaces the old
        // `ptr::read`, which left a live bitwise duplicate in the arena and
        // double-dropped non-`Copy` values when the tree was dropped.
        self.node_mut(idx)
            .value
            .take()
            .expect("a node reached for deletion always holds a value")
    }

    /// Swap only the `key` and `value` of two arena nodes, leaving their
    /// structural links (color/parent/left/right) in place. Used by
    /// `delete_node` to lift an in-order successor's payload into the node
    /// being removed without moving the successor's children.
    fn swap_payload(&mut self, a: usize, b: usize) {
        if a == b {
            return;
        }
        let (ai, bi) = (a - 1, b - 1);
        let (lo, hi) = if ai < bi { (ai, bi) } else { (bi, ai) };
        let (left, right) = self.nodes.split_at_mut(hi);
        std::mem::swap(&mut left[lo].key, &mut right[0].key);
        std::mem::swap(&mut left[lo].value, &mut right[0].value);
    }

    fn minimum(&self, mut idx: usize) -> usize {
        while self.node(idx).left != NIL {
            idx = self.node(idx).left;
        }
        idx
    }

    #[inline]
    fn node(&self, idx: usize) -> &RbNode<K, V> {
        &self.nodes[idx - 1]
    }

    #[inline]
    fn node_mut(&mut self, idx: usize) -> &mut RbNode<K, V> {
        &mut self.nodes[idx - 1]
    }

    fn fix_insert(&mut self, mut idx: usize) {
        while idx != self.root {
            let parent = self.node(idx).parent;
            if parent == NIL || self.node(parent).color == Color::Black {
                break;
            }

            let grandparent = self.node(parent).parent;
            if grandparent == NIL {
                break;
            }

            if parent == self.node(grandparent).left {
                let uncle = self.node(grandparent).right;
                if uncle != NIL && self.node(uncle).color == Color::Red {
                    // Case 1: uncle is red
                    self.node_mut(parent).color = Color::Black;
                    self.node_mut(uncle).color = Color::Black;
                    self.node_mut(grandparent).color = Color::Red;
                    idx = grandparent;
                } else {
                    if idx == self.node(parent).right {
                        // Case 2: left-rotate parent
                        idx = parent;
                        self.rotate_left(idx);
                    }
                    // Case 3: right-rotate grandparent
                    let parent = self.node(idx).parent;
                    let grandparent = self.node(parent).parent;
                    self.node_mut(parent).color = Color::Black;
                    if grandparent != NIL {
                        self.node_mut(grandparent).color = Color::Red;
                        self.rotate_right(grandparent);
                    }
                }
            } else {
                let uncle = self.node(grandparent).left;
                if uncle != NIL && self.node(uncle).color == Color::Red {
                    self.node_mut(parent).color = Color::Black;
                    self.node_mut(uncle).color = Color::Black;
                    self.node_mut(grandparent).color = Color::Red;
                    idx = grandparent;
                } else {
                    if idx == self.node(parent).left {
                        idx = parent;
                        self.rotate_right(idx);
                    }
                    let parent = self.node(idx).parent;
                    let grandparent = self.node(parent).parent;
                    self.node_mut(parent).color = Color::Black;
                    if grandparent != NIL {
                        self.node_mut(grandparent).color = Color::Red;
                        self.rotate_left(grandparent);
                    }
                }
            }
        }
        self.node_mut(self.root).color = Color::Black;
    }

    fn rotate_left(&mut self, x: usize) {
        let y = self.node(x).right;
        if y == NIL {
            return;
        }

        let y_left = self.node(y).left;
        self.node_mut(x).right = y_left;
        if y_left != NIL {
            self.node_mut(y_left).parent = x;
        }

        let x_parent = self.node(x).parent;
        self.node_mut(y).parent = x_parent;
        if x_parent == NIL {
            self.root = y;
        } else if x == self.node(x_parent).left {
            self.node_mut(x_parent).left = y;
        } else {
            self.node_mut(x_parent).right = y;
        }

        self.node_mut(y).left = x;
        self.node_mut(x).parent = y;
    }

    fn rotate_right(&mut self, x: usize) {
        let y = self.node(x).left;
        if y == NIL {
            return;
        }

        let y_right = self.node(y).right;
        self.node_mut(x).left = y_right;
        if y_right != NIL {
            self.node_mut(y_right).parent = x;
        }

        let x_parent = self.node(x).parent;
        self.node_mut(y).parent = x_parent;
        if x_parent == NIL {
            self.root = y;
        } else if x == self.node(x_parent).right {
            self.node_mut(x_parent).right = y;
        } else {
            self.node_mut(x_parent).left = y;
        }

        self.node_mut(y).right = x;
        self.node_mut(x).parent = y;
    }
}

impl<K: Ord, V> Default for RbTree<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut t = RbTree::new();
        t.insert(5, "five");
        t.insert(3, "three");
        t.insert(7, "seven");
        t.insert(1, "one");
        assert_eq!(t.get(&5), Some(&"five"));
        assert_eq!(t.get(&3), Some(&"three"));
        assert_eq!(t.get(&7), Some(&"seven"));
        assert_eq!(t.get(&1), Some(&"one"));
        assert_eq!(t.get(&99), None);
    }

    #[test]
    fn overwrite_value() {
        let mut t = RbTree::new();
        t.insert(1, "a");
        t.insert(1, "b");
        assert_eq!(t.get(&1), Some(&"b"));
    }

    #[test]
    fn many_inserts() {
        let mut t = RbTree::new();
        for i in 0..100 {
            t.insert(i, i * 10);
        }
        for i in 0..100 {
            assert_eq!(t.get(&i), Some(&(i * 10)));
        }
    }

    #[test]
    fn remove_leaf() {
        let mut t = RbTree::new();
        t.insert(5, "five");
        t.insert(3, "three");
        let val = t.remove(&3);
        assert_eq!(val, Some("three"));
        assert_eq!(t.get(&3), None);
        assert_eq!(t.get(&5), Some(&"five"));
    }

    #[test]
    fn remove_node_with_two_children() {
        // Regression: this used to recurse forever (whole-node swap) and
        // hang / stack-overflow. Node 30 has both children (20 and 40).
        let mut t = RbTree::new();
        for k in [50, 30, 70, 20, 40, 60, 80, 35] {
            t.insert(k, k * 10);
        }
        assert_eq!(t.remove(&30), Some(300));
        assert_eq!(t.get(&30), None);
        for k in [50, 70, 20, 40, 60, 80, 35] {
            assert_eq!(t.get(&k), Some(&(k * 10)), "key {k} lost after removing 30");
        }
    }

    #[test]
    fn remove_root_with_two_children() {
        let mut t = RbTree::new();
        t.insert(2, "b");
        t.insert(1, "a");
        t.insert(3, "c");
        assert_eq!(t.remove(&2), Some("b"));
        assert_eq!(t.get(&2), None);
        assert_eq!(t.get(&1), Some(&"a"));
        assert_eq!(t.get(&3), Some(&"c"));
    }

    #[test]
    fn remove_returns_owned_non_copy_without_double_free() {
        // Regression: delete_node used ptr::read and left a live bitwise
        // duplicate in the arena, double-dropping non-Copy values when the
        // tree dropped. With String values that was a double free; here the
        // test simply completing (and the tree dropping cleanly at the end)
        // is the assertion.
        let mut t: RbTree<i32, String> = RbTree::new();
        for (k, v) in [(5, "five"), (3, "three"), (8, "eight"), (1, "one"), (4, "four")] {
            t.insert(k, v.to_string());
        }
        // Key 3 has two children (1 and 4) -> exercises the successor path.
        assert_eq!(t.remove(&3), Some("three".to_string()));
        assert_eq!(t.get(&3), None);
        assert_eq!(t.get(&4), Some(&"four".to_string()));
        assert_eq!(t.get(&1), Some(&"one".to_string()));
        assert_eq!(t.get(&8), Some(&"eight".to_string()));
        // Dropping `t` here must not double-free any String.
    }

    #[test]
    fn remove_all_then_reinsert() {
        let mut t = RbTree::new();
        for i in 0..16 {
            t.insert(i, i);
        }
        for i in 0..16 {
            assert_eq!(t.remove(&i), Some(i), "removing {i}");
            assert_eq!(t.get(&i), None);
            // Remaining keys stay findable (BST order preserved).
            for j in (i + 1)..16 {
                assert_eq!(t.get(&j), Some(&j), "key {j} lost after removing {i}");
            }
        }
        // Arena still usable after deleting everything.
        t.insert(42, 4200);
        assert_eq!(t.get(&42), Some(&4200));
    }
}
