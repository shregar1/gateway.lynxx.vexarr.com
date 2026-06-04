//! Plaintext password check — nginx origin.
//!
//! Some legacy nginx auth configurations store passwords in plaintext
//! (`{PLAIN}` or no prefix). Comparing them still must be constant-time to
//! avoid leaking how many leading bytes matched via timing.

/// Constant-time comparison of a supplied password against a stored plaintext
/// value. Examines every byte, accumulating differences with XOR/OR so the
/// running time does not depend on where (or whether) the first mismatch
/// occurs. A length mismatch yields `false` without an early structural leak
/// beyond the length itself.
pub fn plain_check(supplied: &[u8], stored: &[u8]) -> bool {
    // Length difference folded into the accumulator so that equal-length but
    // unequal inputs and unequal-length inputs both walk the full loop.
    let mut diff = (supplied.len() ^ stored.len()) as u8;
    diff |= ((supplied.len() ^ stored.len()) >> 8) as u8;

    let n = supplied.len().max(stored.len());
    for i in 0..n {
        // Out-of-range indices on the shorter side fold in a non-zero value,
        // keeping the comparison total and avoiding a short-circuit.
        let a = supplied.get(i).copied().unwrap_or(0xff);
        let b = stored.get(i).copied().unwrap_or(0x00);
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings_true() {
        assert!(plain_check(b"hunter2", b"hunter2"));
    }

    #[test]
    fn empty_equal_true() {
        assert!(plain_check(b"", b""));
    }

    #[test]
    fn differing_same_length_false() {
        assert!(!plain_check(b"hunter2", b"hunterX"));
    }

    #[test]
    fn first_byte_differs_false() {
        assert!(!plain_check(b"Xunter2", b"hunter2"));
    }

    #[test]
    fn different_lengths_false() {
        assert!(!plain_check(b"hunter2", b"hunter22"));
        assert!(!plain_check(b"hunter", b"hunter2"));
        assert!(!plain_check(b"", b"x"));
    }

    #[test]
    fn prefix_not_accepted() {
        assert!(!plain_check(b"pass", b"password"));
    }
}
