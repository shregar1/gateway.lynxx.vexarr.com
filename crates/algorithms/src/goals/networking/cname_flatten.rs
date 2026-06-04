/// CNAME chain resolution / flattening (inspired by Traefik).
///
/// Follows a chain of CNAME mappings from a starting name to the final
/// target, detecting cycles to prevent infinite loops.
use std::collections::HashMap;

/// A set of CNAME mappings that can be resolved into a chain.
pub struct CnameChain {
    map: HashMap<String, String>,
}

impl CnameChain {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Add a CNAME mapping: `from` is an alias for `to`.
    pub fn add(&mut self, from: &str, to: &str) {
        self.map
            .insert(from.to_ascii_lowercase(), to.to_ascii_lowercase());
    }

    /// Resolve a name by following the CNAME chain to the final target.
    ///
    /// If the name has no CNAME record, it is returned as-is.
    /// Cycles are detected: if a cycle is encountered the last non-cyclic
    /// name in the chain is returned.
    pub fn resolve<'a>(&'a self, name: &'a str) -> &'a str {
        let lower = name.to_ascii_lowercase();
        let mut current = match self.map.get(&lower) {
            Some(next) => next.as_str(),
            None => return name,
        };

        // Tortoise-and-hare cycle detection.
        let mut slow = current;
        let mut fast = current;
        let mut steps = 0usize;
        let max_steps = self.map.len() + 1;

        loop {
            // Advance slow by 1.
            match self.map.get(current) {
                Some(next) => {
                    current = next.as_str();
                }
                None => return current,
            }

            // Advance fast by 2.
            for _ in 0..2 {
                match self.map.get(fast) {
                    Some(next) => fast = next.as_str(),
                    None => return current,
                }
            }

            // Advance slow by 1 (keeping pace with current).
            match self.map.get(slow) {
                Some(next) => slow = next.as_str(),
                None => return current,
            }

            if slow == fast {
                // Cycle detected: return current position.
                return current;
            }

            steps += 1;
            if steps > max_steps {
                // Safety limit.
                return current;
            }
        }
    }
}

impl Default for CnameChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_cname() {
        let chain = CnameChain::new();
        assert_eq!(chain.resolve("example.com"), "example.com");
    }

    #[test]
    fn test_single_hop() {
        let mut chain = CnameChain::new();
        chain.add("www.example.com", "example.com");
        assert_eq!(chain.resolve("www.example.com"), "example.com");
    }

    #[test]
    fn test_multi_hop() {
        let mut chain = CnameChain::new();
        chain.add("a.com", "b.com");
        chain.add("b.com", "c.com");
        chain.add("c.com", "d.com");
        assert_eq!(chain.resolve("a.com"), "d.com");
    }

    #[test]
    fn test_cycle_detection() {
        let mut chain = CnameChain::new();
        chain.add("a.com", "b.com");
        chain.add("b.com", "c.com");
        chain.add("c.com", "a.com");
        // Should not hang; returns some node in the cycle.
        let result = chain.resolve("a.com");
        assert!(
            result == "a.com" || result == "b.com" || result == "c.com",
            "Expected a node in the cycle, got: {result}"
        );
    }

    #[test]
    fn test_case_insensitive() {
        let mut chain = CnameChain::new();
        chain.add("WWW.Example.COM", "example.com");
        assert_eq!(chain.resolve("www.example.com"), "example.com");
    }
}
