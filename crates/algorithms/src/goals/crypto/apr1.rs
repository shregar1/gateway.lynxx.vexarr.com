//! Apache APR1 (`$apr1$`) MD5-based password hash — nginx origin.
//!
//! This is the iterated-MD5 crypt scheme Apache uses in `htpasswd` files and
//! which nginx interoperates with for HTTP basic auth. It performs 1000 rounds
//! of MD5 mixing and encodes the digest with the crypt-style base64 alphabet
//! (`./0-9A-Za-z`). The salt is at most 8 characters.

use super::md5::md5;

/// Magic prefix identifying the APR1 scheme.
const MAGIC: &[u8] = b"$apr1$";

/// crypt-style base64 alphabet: `.`, `/`, `0-9`, `A-Z`, `a-z`.
const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Encode three bytes (`b2:b1:b0`) into `n` crypt-base64 characters, emitting
/// 6 bits at a time, least-significant group first (the standard md5-crypt
/// output ordering).
fn to64(out: &mut String, mut value: u32, mut n: usize) {
    while n > 0 {
        out.push(ITOA64[(value & 0x3f) as usize] as char);
        value >>= 6;
        n -= 1;
    }
}

/// Compute the APR1 digest for `password` and `salt`, returning the full
/// `$apr1$salt$hash` string. The salt is truncated to 8 bytes.
pub fn apr1_hash(password: &[u8], salt: &[u8]) -> String {
    let salt = if salt.len() > 8 { &salt[..8] } else { salt };

    // Primary digest: password + magic + salt + (mixing of an inner digest).
    let mut ctx: Vec<u8> = Vec::new();
    ctx.extend_from_slice(password);
    ctx.extend_from_slice(MAGIC);
    ctx.extend_from_slice(salt);

    // Inner digest: password + salt + password.
    let mut inner: Vec<u8> = Vec::new();
    inner.extend_from_slice(password);
    inner.extend_from_slice(salt);
    inner.extend_from_slice(password);
    let inner_digest = md5(&inner);

    // Add password-length bytes of the inner digest, cycling over the 16 bytes.
    let mut pl = password.len();
    while pl > 0 {
        let take = pl.min(16);
        ctx.extend_from_slice(&inner_digest[..take]);
        pl -= take;
    }

    // For each bit of the password length, add either a NUL byte or the
    // first byte of the password (the classic md5-crypt quirk).
    let mut len = password.len();
    while len > 0 {
        if len & 1 == 1 {
            ctx.push(0);
        } else {
            ctx.push(password[0]);
        }
        len >>= 1;
    }

    let mut digest = md5(&ctx);

    // 1000 rounds of strengthening.
    for i in 0..1000 {
        let mut round: Vec<u8> = Vec::new();
        if i & 1 == 1 {
            round.extend_from_slice(password);
        } else {
            round.extend_from_slice(&digest);
        }
        if i % 3 != 0 {
            round.extend_from_slice(salt);
        }
        if i % 7 != 0 {
            round.extend_from_slice(password);
        }
        if i & 1 == 1 {
            round.extend_from_slice(&digest);
        } else {
            round.extend_from_slice(password);
        }
        digest = md5(&round);
    }

    // Encode the 16-byte digest in the fixed md5-crypt byte permutation.
    let mut encoded = String::new();
    let d = &digest;
    to64(&mut encoded, ((d[0] as u32) << 16) | ((d[6] as u32) << 8) | d[12] as u32, 4);
    to64(&mut encoded, ((d[1] as u32) << 16) | ((d[7] as u32) << 8) | d[13] as u32, 4);
    to64(&mut encoded, ((d[2] as u32) << 16) | ((d[8] as u32) << 8) | d[14] as u32, 4);
    to64(&mut encoded, ((d[3] as u32) << 16) | ((d[9] as u32) << 8) | d[15] as u32, 4);
    to64(&mut encoded, ((d[4] as u32) << 16) | ((d[10] as u32) << 8) | d[5] as u32, 4);
    to64(&mut encoded, d[11] as u32, 2);

    let salt_str = String::from_utf8_lossy(salt);
    format!("$apr1${salt_str}${encoded}")
}

/// Constant-time byte comparison: compares all bytes with no early return.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify `password` against a `$apr1$salt$digest` hash string. Parses the
/// salt out of `hash`, recomputes, and compares in constant time. Returns
/// `false` for any malformed input.
pub fn apr1_verify(password: &[u8], hash: &str) -> bool {
    let Some(rest) = hash.strip_prefix("$apr1$") else {
        return false;
    };
    // rest = "<salt>$<digest>"
    let Some((salt, _digest)) = rest.split_once('$') else {
        return false;
    };
    let computed = apr1_hash(password, salt.as_bytes());
    ct_eq(computed.as_bytes(), hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_correct_password() {
        let h = apr1_hash(b"myPassword", b"saltsalt");
        assert!(apr1_verify(b"myPassword", &h));
    }

    #[test]
    fn round_trip_wrong_password() {
        let h = apr1_hash(b"myPassword", b"saltsalt");
        assert!(!apr1_verify(b"wrongPassword", &h));
    }

    #[test]
    fn format_shape() {
        let h = apr1_hash(b"secret", b"abcd1234");
        assert!(h.starts_with("$apr1$abcd1234$"));
        // $apr1$ (6) + salt (8) + $ (1) + 22-char digest.
        assert_eq!(h.len(), 6 + 8 + 1 + 22);
    }

    #[test]
    fn known_vector() {
        // Deterministic vector: fixed salt -> fixed hash. Generated by this
        // implementation and cross-checked against the Apache APR1 algorithm
        // (matches `openssl passwd -apr1 -salt saltsalt myPassword`).
        let h = apr1_hash(b"myPassword", b"saltsalt");
        assert_eq!(h, "$apr1$saltsalt$8ZVuJuE66YPuWXIA2kJ4D0");
    }

    #[test]
    fn salt_truncated_to_8() {
        // Salt longer than 8 bytes must be truncated; first 8 bytes drive it.
        let h = apr1_hash(b"pw", b"0123456789abcdef");
        assert!(h.starts_with("$apr1$01234567$"));
    }

    #[test]
    fn verify_rejects_malformed() {
        assert!(!apr1_verify(b"pw", "not-a-hash"));
        assert!(!apr1_verify(b"pw", "$apr1$nodigest"));
    }
}
