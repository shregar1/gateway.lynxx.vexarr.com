pub mod abstraction;
#[cfg(target_os = "linux")]
pub mod io_uring_accept;
pub mod net;

pub use net::{resilient_bind, BindConfig};

// Re-export commonly used utility modules

/// Constant-time byte-slice equality. Use for comparing secrets (API keys,
/// auth digests, MACs) so an attacker can't learn the secret from response
/// timing. Returns false immediately on length mismatch (the length of a
/// presented credential is not itself secret).
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod constant_time_tests {
    use super::constant_time_eq;

    #[test]
    fn equal_and_unequal() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secres"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(constant_time_eq(b"", b""));
    }
}
