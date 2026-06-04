//! VM-aware binary heap optimized for memory page locality.
//!
//! Uses a page-aligned layout where the root "page" forms a complete binary
//! tree, and cross-page elements use adjusted index mappings to keep
//! parent-child pairs on the same virtual memory page.
//!
//! The root page size is rounded to the nearest complete binary tree size
//! (2^k - 1) to ensure consistent parent/child navigation.

const DEFAULT_PAGE_SIZE: usize = 512;

/// Min-heap whose index layout is tuned for virtual-memory page locality.
///
/// The first *root page* (sized to the largest complete binary tree ≤
/// `page_size`, i.e. `2^k − 1`) uses standard binary-heap indexing so the
/// hot top of the heap stays on a single page. Beyond the root page,
/// parent/child mappings are adjusted so that a leaf in the root page fans
/// out to children in subsequent pages without straddling page boundaries.
///
/// This layout significantly reduces TLB misses for large heaps while
/// preserving O(log n) insert/pop.
pub struct VmHeap<T> {
    data: Vec<T>,
    /// Complete binary tree size for the root page (2^k - 1).
    root_size: usize,
    /// Half of root_size + 1 (number of internal nodes in root page).
    root_half: usize,
}

/// Compute largest (2^k - 1) <= page_size.
fn compute_root_size(page_size: usize) -> usize {
    if page_size < 3 {
        return 1;
    }
    // BUG FIX: the loop previously used an unbounded `1usize << (k + 1)`, which
    // for page_size >= 2^63 made the shift amount reach usize::BITS. In debug
    // that panics ("attempt to shift left with overflow"); in release the shift
    // wraps mod 64, keeping the `<= page_size` condition true forever (infinite
    // loop / pinned CPU). Bound k against usize::BITS so the shift is always
    // in range and the result saturates at the largest representable 2^k - 1.
    let mut k = 1u32;
    while k + 1 < usize::BITS && (1usize << (k + 1)) - 1 <= page_size {
        k += 1;
    }
    (1usize << k) - 1
}

impl<T: PartialOrd> VmHeap<T> {
    /// Build an empty heap with the default page size (512 elements).
    pub fn new() -> Self {
        let root_size = compute_root_size(DEFAULT_PAGE_SIZE);
        Self {
            data: Vec::new(),
            root_size,
            root_half: (root_size + 1) / 2,
        }
    }

    /// Build an empty heap with a custom `page_size` (in number of elements).
    /// The root page is rounded down to the largest complete binary tree that
    /// fits within `page_size`.
    ///
    /// # Panics
    /// Panics if `page_size < 2`.
    pub fn with_page_size(page_size: usize) -> Self {
        assert!(page_size >= 2, "page_size must be at least 2");
        let root_size = compute_root_size(page_size);
        Self {
            data: Vec::new(),
            root_size,
            root_half: (root_size + 1) / 2,
        }
    }

    /// Push `value` onto the heap and sift it up. Returns the index where the
    /// element was initially placed (note: this index may become stale after
    /// subsequent mutations).
    pub fn insert(&mut self, value: T) -> usize {
        let idx = self.data.len();
        self.data.push(value);
        self.sift_up(idx);
        idx
    }

    /// Remove and return the minimum element, or `None` if the heap is empty.
    /// The last element is swapped into position 0 and sifted down.
    pub fn pop_min(&mut self) -> Option<T> {
        if self.data.is_empty() {
            return None;
        }
        let last = self.data.len() - 1;
        self.data.swap(0, last);
        let result = self.data.pop();
        if !self.data.is_empty() {
            self.sift_down(0);
        }
        result
    }

    /// Borrow the minimum element without removing it, or `None` if empty.
    pub fn peek_min(&self) -> Option<&T> {
        self.data.first()
    }

    /// Remove the element at `index` by swapping with the last element and
    /// re-heapifying. Returns `None` if `index` is out of bounds.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.data.len() {
            return None;
        }
        let last = self.data.len() - 1;
        if index == last {
            return self.data.pop();
        }
        self.data.swap(index, last);
        let result = self.data.pop();
        if index < self.data.len() {
            self.reorder(index);
        }
        result
    }

    /// Restore the heap invariant at `index` after the value there has been
    /// mutated. Tries sifting up first; if that doesn't move the element,
    /// sifts down instead. No-op if `index` is out of bounds.
    pub fn reorder(&mut self, index: usize) {
        if index >= self.data.len() {
            return;
        }
        if !self.try_sift_up(index) {
            self.sift_down(index);
        }
    }

    /// Number of elements in the heap.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the heap contains no elements.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// VM-aware parent index.
    /// Within root page: standard binary heap.
    /// Beyond root page: maps cross-page nodes back to the lower half of the root.
    fn parent(&self, idx: usize) -> usize {
        if idx == 0 {
            return 0;
        }
        if idx < self.root_size {
            (idx - 1) / 2
        } else {
            (idx - self.root_size) / 2 + self.root_half - 1
        }
    }

    /// VM-aware left child index.
    fn left_child(&self, idx: usize) -> usize {
        if idx < self.root_half - 1 {
            // Internal node in root page: standard children stay within root
            2 * idx + 1
        } else {
            // Leaf of root page (or beyond): children go cross-page
            let offset = idx - (self.root_half - 1);
            self.root_size + offset * 2
        }
    }

    /// VM-aware right child index.
    fn right_child(&self, idx: usize) -> usize {
        self.left_child(idx) + 1
    }

    fn try_sift_up(&mut self, mut idx: usize) -> bool {
        let start = idx;
        while idx > 0 {
            let p = self.parent(idx);
            if self.data[idx] < self.data[p] {
                self.data.swap(p, idx);
                idx = p;
            } else {
                break;
            }
        }
        idx != start
    }

    fn sift_up(&mut self, idx: usize) {
        self.try_sift_up(idx);
    }

    fn sift_down(&mut self, mut idx: usize) {
        let len = self.data.len();
        loop {
            let left = self.left_child(idx);
            let right = self.right_child(idx);
            let mut smallest = idx;

            if left < len && self.data[left] < self.data[smallest] {
                smallest = left;
            }
            if right < len && self.data[right] < self.data[smallest] {
                smallest = right;
            }

            if smallest == idx {
                break;
            }
            self.data.swap(idx, smallest);
            idx = smallest;
        }
    }
}

impl<T: PartialOrd> Default for VmHeap<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_root_size() {
        assert_eq!(compute_root_size(2), 1);
        assert_eq!(compute_root_size(3), 3);
        assert_eq!(compute_root_size(4), 3);
        assert_eq!(compute_root_size(7), 7);
        assert_eq!(compute_root_size(8), 7);
        assert_eq!(compute_root_size(15), 15);
        assert_eq!(compute_root_size(16), 15);
        assert_eq!(compute_root_size(512), 511);
        assert_eq!(compute_root_size(1023), 1023);
    }

    #[test]
    fn test_compute_root_size_large_page_size_terminates() {
        // Regression: compute_root_size previously overflowed its shift for
        // page_size >= 2^(BITS-1). In debug it panicked ("attempt to shift
        // left with overflow"); in release it infinite-looped because the
        // shift wrapped mod BITS, keeping the `<= page_size` test true forever.
        // The result must saturate at the largest representable 2^k - 1.
        let max_complete = (1usize << (usize::BITS - 1)) - 1;
        assert_eq!(compute_root_size(usize::MAX), max_complete);
        assert_eq!(compute_root_size(1usize << (usize::BITS - 1)), max_complete);
        // Reachable via the public constructor; must not panic or hang.
        let heap: VmHeap<i32> = VmHeap::with_page_size(usize::MAX);
        assert_eq!(heap.root_size, max_complete);
    }

    #[test]
    fn test_empty_heap() {
        let heap: VmHeap<i32> = VmHeap::new();
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
    }

    #[test]
    fn test_insert_single() {
        let mut heap = VmHeap::new();
        heap.insert(42);
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.peek_min(), Some(&42));
    }

    #[test]
    fn test_min_heap_property() {
        let mut heap = VmHeap::new();
        heap.insert(5);
        heap.insert(3);
        heap.insert(7);
        heap.insert(1);
        heap.insert(4);
        assert_eq!(heap.peek_min(), Some(&1));
    }

    #[test]
    fn test_pop_min_ordering() {
        let mut heap = VmHeap::new();
        let values = vec![10, 4, 15, 1, 7, 20, 3];
        for v in &values {
            heap.insert(*v);
        }
        let mut sorted = Vec::new();
        while let Some(val) = heap.pop_min() {
            sorted.push(val);
        }
        assert_eq!(sorted, vec![1, 3, 4, 7, 10, 15, 20]);
    }

    #[test]
    fn test_pop_min_empty() {
        let mut heap: VmHeap<i32> = VmHeap::new();
        assert_eq!(heap.pop_min(), None);
    }

    #[test]
    fn test_remove_root() {
        let mut heap = VmHeap::with_page_size(4);
        heap.insert(10);
        heap.insert(20);
        heap.insert(5);
        assert_eq!(heap.peek_min(), Some(&5));
        let removed = heap.remove(0);
        assert_eq!(removed, Some(5));
        assert_eq!(heap.len(), 2);
    }

    #[test]
    fn test_large_insert_pop() {
        let mut heap = VmHeap::with_page_size(8);
        for i in (0..100).rev() {
            heap.insert(i);
        }
        assert_eq!(heap.len(), 100);
        assert_eq!(heap.peek_min(), Some(&0));
        let mut prev = i32::MIN;
        for _ in 0..100 {
            let val = heap.pop_min().unwrap();
            assert!(val >= prev, "got {} after {}", val, prev);
            prev = val;
        }
        assert!(heap.is_empty());
    }

    #[test]
    fn test_duplicates() {
        let mut heap = VmHeap::new();
        heap.insert(5);
        heap.insert(5);
        heap.insert(5);
        heap.insert(3);
        heap.insert(3);
        assert_eq!(heap.pop_min(), Some(3));
        assert_eq!(heap.pop_min(), Some(3));
        assert_eq!(heap.pop_min(), Some(5));
        assert_eq!(heap.pop_min(), Some(5));
        assert_eq!(heap.pop_min(), Some(5));
        assert_eq!(heap.pop_min(), None);
    }

    #[test]
    fn test_with_page_size() {
        let mut heap = VmHeap::with_page_size(4);
        for i in (0..20).rev() {
            heap.insert(i);
        }
        let mut sorted = Vec::new();
        while let Some(v) = heap.pop_min() {
            sorted.push(v);
        }
        let expected: Vec<i32> = (0..20).collect();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn test_parent_child_root_page() {
        // page_size=8 → root_size=7, root_half=4
        let heap: VmHeap<i32> = VmHeap::with_page_size(8);
        assert_eq!(heap.root_size, 7);
        assert_eq!(heap.root_half, 4);

        // Internal nodes [0,1,2] have standard children
        assert_eq!(heap.parent(0), 0);
        assert_eq!(heap.parent(1), 0);
        assert_eq!(heap.parent(2), 0);
        assert_eq!(heap.parent(3), 1);
        assert_eq!(heap.parent(4), 1);
        assert_eq!(heap.parent(5), 2);
        assert_eq!(heap.parent(6), 2);

        assert_eq!(heap.left_child(0), 1);
        assert_eq!(heap.right_child(0), 2);
        assert_eq!(heap.left_child(1), 3);
        assert_eq!(heap.right_child(1), 4);
        assert_eq!(heap.left_child(2), 5);
        assert_eq!(heap.right_child(2), 6);
    }

    #[test]
    fn test_parent_child_cross_page() {
        // page_size=8 → root_size=7, root_half=4
        // Lower half of root (leaves): [3,4,5,6] have cross-page children
        let heap: VmHeap<i32> = VmHeap::with_page_size(8);

        // Children of root-page leaves go cross-page (starting at root_size=7)
        assert_eq!(heap.left_child(3), 7);
        assert_eq!(heap.right_child(3), 8);
        assert_eq!(heap.left_child(4), 9);
        assert_eq!(heap.right_child(4), 10);
        assert_eq!(heap.left_child(5), 11);
        assert_eq!(heap.right_child(5), 12);
        assert_eq!(heap.left_child(6), 13);
        assert_eq!(heap.right_child(6), 14);

        // Verify parent consistency for cross-page nodes
        assert_eq!(heap.parent(7), 3);
        assert_eq!(heap.parent(8), 3);
        assert_eq!(heap.parent(9), 4);
        assert_eq!(heap.parent(10), 4);
        assert_eq!(heap.parent(11), 5);
        assert_eq!(heap.parent(12), 5);
        assert_eq!(heap.parent(13), 6);
        assert_eq!(heap.parent(14), 6);
    }

    #[test]
    fn test_deeper_cross_page() {
        let heap: VmHeap<i32> = VmHeap::with_page_size(8);
        // Node 7 is cross-page; its children:
        // offset = 7 - (root_half-1) = 7 - 3 = 4
        // left_child(7) = 7 + 4*2 = 15
        assert_eq!(heap.left_child(7), 15);
        assert_eq!(heap.right_child(7), 16);
        assert_eq!(heap.parent(15), 7);
        assert_eq!(heap.parent(16), 7);
    }

    #[test]
    fn test_reorder() {
        let mut heap = VmHeap::with_page_size(4);
        heap.insert(10);
        heap.insert(20);
        heap.insert(30);
        heap.insert(40);
        heap.insert(50);
        assert_eq!(heap.peek_min(), Some(&10));
    }

    #[test]
    fn test_stress_random_order() {
        let mut heap = VmHeap::with_page_size(16);
        let values = vec![
            83, 17, 56, 92, 4, 38, 71, 25, 60, 11, 47, 88, 33, 69, 2, 54, 96, 19, 75, 41,
        ];
        for &v in &values {
            heap.insert(v);
        }
        let mut sorted = Vec::new();
        while let Some(v) = heap.pop_min() {
            sorted.push(v);
        }
        let mut expected = values;
        expected.sort();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn test_interleaved_insert_pop() {
        let mut heap = VmHeap::with_page_size(4);
        heap.insert(5);
        heap.insert(3);
        assert_eq!(heap.pop_min(), Some(3));
        heap.insert(1);
        heap.insert(4);
        assert_eq!(heap.pop_min(), Some(1));
        assert_eq!(heap.pop_min(), Some(4));
        assert_eq!(heap.pop_min(), Some(5));
        assert_eq!(heap.pop_min(), None);
    }

    #[test]
    #[should_panic]
    fn test_page_size_too_small() {
        let _heap: VmHeap<i32> = VmHeap::with_page_size(1);
    }

    #[test]
    fn test_single_element_operations() {
        let mut heap = VmHeap::new();
        heap.insert(42);
        assert_eq!(heap.peek_min(), Some(&42));
        assert_eq!(heap.pop_min(), Some(42));
        assert!(heap.is_empty());
        assert_eq!(heap.peek_min(), None);
    }

    #[test]
    fn test_many_elements_various_page_sizes() {
        for &ps in &[2, 3, 4, 7, 8, 15, 16, 32, 64, 128, 512] {
            let mut heap = VmHeap::with_page_size(ps);
            let n = ps * 4 + 7;
            for i in (0..n).rev() {
                heap.insert(i);
            }
            let mut prev = 0;
            assert_eq!(heap.peek_min(), Some(&0));
            while let Some(v) = heap.pop_min() {
                assert!(v >= prev, "page_size={}, got {} after {}", ps, v, prev);
                prev = v;
            }
        }
    }

    #[test]
    fn test_remove_last_element() {
        let mut heap = VmHeap::with_page_size(4);
        heap.insert(1);
        heap.insert(2);
        heap.insert(3);
        let last_idx = heap.len() - 1;
        let removed = heap.remove(last_idx);
        assert!(removed.is_some());
        assert_eq!(heap.len(), 2);
    }

    #[test]
    fn test_remove_maintains_order() {
        let mut heap = VmHeap::with_page_size(4);
        for i in 0..10 {
            heap.insert(i);
        }
        heap.remove(1);
        assert_eq!(heap.len(), 9);
        assert_eq!(heap.peek_min(), Some(&0));
        let mut sorted = Vec::new();
        while let Some(v) = heap.pop_min() {
            sorted.push(v);
        }
        for w in sorted.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }

    #[test]
    fn test_navigation_consistency() {
        // Verify parent(left_child(i)) == i and parent(right_child(i)) == i
        // for various page sizes and indices
        for &ps in &[3, 7, 8, 15, 16, 31, 64] {
            let heap: VmHeap<i32> = VmHeap::with_page_size(ps);
            for i in 0..ps * 4 {
                let lc = heap.left_child(i);
                let rc = heap.right_child(i);
                assert_eq!(
                    heap.parent(lc), i,
                    "page_size={}, parent(left_child({}))={} != {}",
                    ps, i, heap.parent(lc), i
                );
                assert_eq!(
                    heap.parent(rc), i,
                    "page_size={}, parent(right_child({}))={} != {}",
                    ps, i, heap.parent(rc), i
                );
            }
        }
    }
}
