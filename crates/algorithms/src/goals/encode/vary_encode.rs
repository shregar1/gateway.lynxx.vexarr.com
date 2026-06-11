//! Compact binary Vary key (Varnish origin).
//!
//! Builds a deterministic binary key from a set of HTTP header name/value
//! pairs. Fields are sorted by name for order-independent comparison and
//! values are hashed for compact representation.

use std::collections::BTreeMap;

/// Builder for compact binary Vary keys.
///
/// Field names are normalized to lowercase and sorted. Values are hashed
/// with a simple non-cryptographic hash so that the resulting key is
/// compact and order-independent.
pub struct VaryKeyBuilder {
    fields: BTreeMap<String, u64>,
}

impl VaryKeyBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
        }
    }

    /// Add a header field to the key.
    ///
    /// If the same field name is added multiple times, the values are
    /// combined (XOR of hashes) to produce a single composite hash.
    pub fn add_field(&mut self, name: &str, value: &str) {
        let normalized = name.to_ascii_lowercase();
        let value_hash = fnv1a_64(value.as_bytes());
        self.fields
            .entry(normalized)
            .and_modify(|h| *h ^= value_hash)
            .or_insert(value_hash);
    }

    /// Build the final binary Vary key.
    ///
    /// Format: for each field (sorted by name):
    /// - 1 byte: name length
    /// - N bytes: lowercase name
    /// - 8 bytes: value hash (little-endian)
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, &hash) in &self.fields {
            // The name length is framed as a single u8, so cap the emitted name
            // at 255 bytes and keep the length byte consistent with the bytes
            // actually written. A >255-byte name would otherwise truncate the
            // length field and mis-frame the key (distinct field sets could
            // collide). HTTP header field-names are short tokens, so in practice
            // this never triggers.
            let name_bytes = name.as_bytes();
            let name_bytes = &name_bytes[..name_bytes.len().min(u8::MAX as usize)];
            out.push(name_bytes.len() as u8);
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&hash.to_le_bytes());
        }
        out
    }
}

impl Default for VaryKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// FNV-1a 64-bit hash.
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x00000100000001B3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder() {
        let vk = VaryKeyBuilder::new();
        assert!(vk.build().is_empty());
    }

    #[test]
    fn single_field() {
        let mut vk = VaryKeyBuilder::new();
        vk.add_field("Accept-Encoding", "gzip");
        let key = vk.build();
        assert!(!key.is_empty());
        // Name length byte + "accept-encoding" (15) + 8 hash bytes
        assert_eq!(key.len(), 1 + 15 + 8);
    }

    #[test]
    fn order_independent() {
        let mut vk1 = VaryKeyBuilder::new();
        vk1.add_field("Accept-Encoding", "gzip");
        vk1.add_field("Accept-Language", "en");

        let mut vk2 = VaryKeyBuilder::new();
        vk2.add_field("Accept-Language", "en");
        vk2.add_field("Accept-Encoding", "gzip");

        assert_eq!(vk1.build(), vk2.build());
    }

    #[test]
    fn case_insensitive_names() {
        let mut vk1 = VaryKeyBuilder::new();
        vk1.add_field("Accept-Encoding", "gzip");

        let mut vk2 = VaryKeyBuilder::new();
        vk2.add_field("accept-encoding", "gzip");

        assert_eq!(vk1.build(), vk2.build());
    }

    #[test]
    fn different_values_differ() {
        let mut vk1 = VaryKeyBuilder::new();
        vk1.add_field("Accept-Encoding", "gzip");

        let mut vk2 = VaryKeyBuilder::new();
        vk2.add_field("Accept-Encoding", "br");

        assert_ne!(vk1.build(), vk2.build());
    }

    #[test]
    fn multiple_values_same_field() {
        let mut vk = VaryKeyBuilder::new();
        vk.add_field("Accept", "text/html");
        vk.add_field("Accept", "application/json");
        let key = vk.build();
        // Should have one entry for "accept"
        assert_eq!(key[0] as usize, 6); // "accept".len()
    }

    #[test]
    fn deterministic() {
        let mut vk1 = VaryKeyBuilder::new();
        vk1.add_field("Host", "example.com");
        vk1.add_field("Accept", "text/html");

        let mut vk2 = VaryKeyBuilder::new();
        vk2.add_field("Host", "example.com");
        vk2.add_field("Accept", "text/html");

        assert_eq!(vk1.build(), vk2.build());
    }

    #[test]
    fn fnv1a_known_value() {
        // FNV-1a of empty string
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
    }
}
