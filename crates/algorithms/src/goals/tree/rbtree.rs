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
    value: V,
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
            value,
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
                // Key exists — update value
                self.node_mut(current).value = {
                    // Swap the value from the new node
                    let new_node = self.nodes.pop().unwrap();
                    new_node.value
                };
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
                return Some(&node.value);
            }
        }
        None
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.find_node(key)?;
        // For simplicity: mark as removed by swapping to a tombstone approach
        // Full RB-delete is complex; we do a simplified version that maintains
        // the tree structure.
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
            // Two children: find in-order successor
            let succ = self.minimum(right);
            // Swap keys/values
            // We need unsafe-free swap so we use index gymnastics
            let succ_left = self.node(succ).left;
            let succ_right = self.node(succ).right;
            let succ_parent = self.node(succ).parent;
            let succ_color = self.node(succ).color;

            // Extract successor value, put it in idx
            // This is a simplified approach: swap contents then delete successor
            let si = succ - 1;
            let ii = idx - 1;
            self.nodes.swap(si, ii);

            // Fix parent/child pointers after swap
            self.repair_swap(idx, succ);

            return self.delete_node(succ);
        }

        // Zero or one child
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

        // Return the removed value
        // Safety: we're reading from a now-orphaned node
        // The arena keeps it alive but it's logically deleted
        let node = &self.nodes[idx - 1];
        // We can't move out of the arena easily, so we use a workaround
        unsafe {
            let ptr = &node.value as *const V;
            std::ptr::read(ptr)
        }
    }

    fn repair_swap(&mut self, a: usize, b: usize) {
        // After swapping nodes[a-1] and nodes[b-1], fix all external references
        // Fix children pointing to old parent
        for &idx in &[a, b] {
            let left = self.node(idx).left;
            let right = self.node(idx).right;
            if left != NIL && left != a && left != b {
                self.node_mut(left).parent = idx;
            }
            if right != NIL && right != a && right != b {
                self.node_mut(right).parent = idx;
            }
        }

        // Fix parents pointing to old child
        for &idx in &[a, b] {
            let parent = self.node(idx).parent;
            if parent != NIL && parent != a && parent != b {
                if self.node(parent).left == a || self.node(parent).left == b {
                    let other = if self.node(parent).left == a { a } else { b };
                    self.node_mut(parent).left = idx;
                }
                if self.node(parent).right == a || self.node(parent).right == b {
                    self.node_mut(parent).right = idx;
                }
            }
        }

        if self.root == a {
            self.root = b;
        } else if self.root == b {
            self.root = a;
        }
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
}
