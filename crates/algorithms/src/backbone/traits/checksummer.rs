//! Checksummer trait — CRC32 integrity checks.

/// CRC32 checksum for cached content integrity, ETag generation, and
/// payload verification.
pub trait Checksummer {
    /// Compute a 32-bit checksum over `data`.
    fn checksum(&self, data: &[u8]) -> u32;

    fn name(&self) -> &'static str;
}
