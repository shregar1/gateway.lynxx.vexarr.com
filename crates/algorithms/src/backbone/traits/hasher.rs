//! Hasher trait — general-purpose key/data hashing.

/// General-purpose hash function for routing keys, hash tables, and
/// consistent hashing inputs.
pub trait Hasher {
    /// Hash `data` and return a 64-bit digest.
    fn hash(&self, data: &[u8]) -> u64;

    /// Human-readable algorithm name (e.g. `"murmur2"`, `"xxh64"`).
    fn name(&self) -> &'static str;
}
