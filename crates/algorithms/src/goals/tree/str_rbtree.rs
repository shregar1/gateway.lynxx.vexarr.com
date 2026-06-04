/// String-keyed red-black tree wrapper.
///
/// Wraps `RbTree<String, V>` with a convenience API that accepts `&str`.

use super::rbtree::RbTree;

pub struct StrRbTree<V> {
    inner: RbTree<String, V>,
}

impl<V> StrRbTree<V> {
    pub fn new() -> Self {
        Self {
            inner: RbTree::new(),
        }
    }

    pub fn insert(&mut self, key: &str, value: V) {
        self.inner.insert(key.to_owned(), value);
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        // RbTree::get takes &K where K=String; &String can be compared with &str
        // via Borrow trait, but our simple impl uses Ord on K directly.
        // We need to create a String for lookup.
        let owned = key.to_owned();
        self.inner.get(&owned)
    }
}

impl<V> Default for StrRbTree<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let mut t = StrRbTree::new();
        t.insert("hello", 1);
        t.insert("world", 2);
        assert_eq!(t.get("hello"), Some(&1));
        assert_eq!(t.get("world"), Some(&2));
        assert_eq!(t.get("missing"), None);
    }

    #[test]
    fn overwrite() {
        let mut t = StrRbTree::new();
        t.insert("key", 10);
        t.insert("key", 20);
        assert_eq!(t.get("key"), Some(&20));
    }
}
