/// Radix tree (compressed trie) for byte-string routing.
///
/// Supports exact lookup, insertion, and longest-prefix-match —
/// the core operation for URI routing in proxies.

pub struct RadixTree<T> {
    root: Node<T>,
}

struct Node<T> {
    prefix: Vec<u8>,
    value: Option<T>,
    children: Vec<Node<T>>,
}

impl<T> RadixTree<T> {
    pub fn new() -> Self {
        Self {
            root: Node {
                prefix: Vec::new(),
                value: None,
                children: Vec::new(),
            },
        }
    }

    pub fn insert(&mut self, key: &[u8], value: T) {
        Self::insert_node(&mut self.root, key, value);
    }

    pub fn lookup(&self, key: &[u8]) -> Option<&T> {
        Self::lookup_node(&self.root, key)
    }

    /// Find the longest prefix of `key` that has a value in the tree.
    /// Returns the matching prefix and its associated value.
    pub fn longest_prefix_match<'a>(&'a self, key: &'a [u8]) -> Option<(&'a [u8], &'a T)> {
        let mut best: Option<(&[u8], &T)> = None;
        let mut node = &self.root;
        let mut offset = 0usize;

        if node.value.is_some() {
            best = Some((&key[..0], node.value.as_ref().unwrap()));
        }

        loop {
            let remaining = &key[offset..];
            let mut found = false;

            for child in &node.children {
                let common = common_prefix_len(&child.prefix, remaining);
                if common == 0 {
                    continue;
                }

                if common == child.prefix.len() {
                    offset += common;
                    if child.value.is_some() {
                        best = Some((&key[..offset], child.value.as_ref().unwrap()));
                    }
                    node = child;
                    found = true;
                    break;
                }
                // Partial match — can't go deeper
                break;
            }

            if !found {
                break;
            }
        }

        best
    }

    fn insert_node(node: &mut Node<T>, key: &[u8], value: T) {
        if key.is_empty() {
            node.value = Some(value);
            return;
        }

        // Find a child whose prefix shares a common prefix with key
        for i in 0..node.children.len() {
            let common = common_prefix_len(&node.children[i].prefix, key);
            if common == 0 {
                continue;
            }

            if common == node.children[i].prefix.len() {
                // Full match on child prefix — recurse
                Self::insert_node(&mut node.children[i], &key[common..], value);
                return;
            }

            // Partial match — split the child
            let old_child = node.children.remove(i);
            let mut split = Node {
                prefix: old_child.prefix[..common].to_vec(),
                value: None,
                children: Vec::new(),
            };

            let mut remainder = Node {
                prefix: old_child.prefix[common..].to_vec(),
                value: old_child.value,
                children: old_child.children,
            };

            if common == key.len() {
                split.value = Some(value);
                split.children.push(remainder);
            } else {
                let new_leaf = Node {
                    prefix: key[common..].to_vec(),
                    value: Some(value),
                    children: Vec::new(),
                };
                split.children.push(remainder);
                split.children.push(new_leaf);
            }

            node.children.insert(i, split);
            return;
        }

        // No matching child — add new leaf
        node.children.push(Node {
            prefix: key.to_vec(),
            value: Some(value),
            children: Vec::new(),
        });
    }

    fn lookup_node<'a>(node: &'a Node<T>, key: &[u8]) -> Option<&'a T> {
        if key.is_empty() {
            return node.value.as_ref();
        }

        for child in &node.children {
            let common = common_prefix_len(&child.prefix, key);
            if common == child.prefix.len() {
                return Self::lookup_node(child, &key[common..]);
            }
        }

        None
    }
}

impl<T> Default for RadixTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_lookup() {
        let mut t = RadixTree::new();
        t.insert(b"/api/v1", 1);
        t.insert(b"/api/v2", 2);
        t.insert(b"/static", 3);
        assert_eq!(t.lookup(b"/api/v1"), Some(&1));
        assert_eq!(t.lookup(b"/api/v2"), Some(&2));
        assert_eq!(t.lookup(b"/static"), Some(&3));
        assert_eq!(t.lookup(b"/api/v3"), None);
    }

    #[test]
    fn prefix_match() {
        let mut t = RadixTree::new();
        t.insert(b"/api", 10);
        t.insert(b"/api/users", 20);
        t.insert(b"/api/users/123", 30);

        let (prefix, val) = t.longest_prefix_match(b"/api/users/123/profile").unwrap();
        assert_eq!(prefix, b"/api/users/123");
        assert_eq!(*val, 30);

        let (prefix, val) = t.longest_prefix_match(b"/api/other").unwrap();
        assert_eq!(prefix, b"/api");
        assert_eq!(*val, 10);
    }

    #[test]
    fn no_match() {
        let mut t = RadixTree::new();
        t.insert(b"/api", 1);
        assert!(t.longest_prefix_match(b"/web").is_none());
    }

    #[test]
    fn overwrite() {
        let mut t = RadixTree::new();
        t.insert(b"/key", 1);
        t.insert(b"/key", 2);
        assert_eq!(t.lookup(b"/key"), Some(&2));
    }
}
