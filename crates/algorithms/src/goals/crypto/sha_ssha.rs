//! LDAP `{SHA}` / `{SSHA}` password schemes — nginx origin.
//!
//! These base64-SHA1 schemes are the credential format used by OpenLDAP and
//! understood by nginx auth modules:
//!
//! - `{SHA}`  : base64(sha1(password))
//! - `{SSHA}` : base64(sha1(password ++ salt) ++ salt)
//!
//! The standard RFC 4648 base64 codec (alphabet `A-Za-z0-9+/`, `=` padding) is
//! implemented inline so this carries no external dependency.

use super::sha1::sha1;

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard RFC 4648 base64 encode with `=` padding.
fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Map a base64 character to its 6-bit value, or `None` if invalid.
fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard RFC 4648 base64 decode. Returns `None` on invalid input.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n <<= 6;
            if c == b'=' {
                // Padding only valid in the last one or two positions.
                if i < 2 {
                    return None;
                }
                pad += 1;
            } else {
                n |= b64_val(c)?;
            }
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Produce a `{SHA}` password entry: `{SHA}` + base64(sha1(password)).
pub fn sha_hash(password: &[u8]) -> String {
    format!("{{SHA}}{}", b64_encode(&sha1(password)))
}

/// Produce a `{SSHA}` (salted) password entry:
/// `{SSHA}` + base64(sha1(password ++ salt) ++ salt).
pub fn ssha_hash(password: &[u8], salt: &[u8]) -> String {
    let mut buf = Vec::with_capacity(password.len() + salt.len());
    buf.extend_from_slice(password);
    buf.extend_from_slice(salt);
    let digest = sha1(&buf);

    let mut payload = Vec::with_capacity(digest.len() + salt.len());
    payload.extend_from_slice(&digest);
    payload.extend_from_slice(salt);
    format!("{{SSHA}}{}", b64_encode(&payload))
}

/// Constant-time byte comparison.
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

/// Verify `password` against a stored `{SHA}` or `{SSHA}` entry. For `{SSHA}`
/// the salt (everything after the 20-byte SHA-1 digest) is extracted and
/// re-applied. Comparison is constant-time. Returns `false` for any malformed
/// or unrecognized input.
pub fn sha_verify(password: &[u8], stored: &str) -> bool {
    if let Some(b64) = stored.strip_prefix("{SSHA}") {
        let Some(raw) = b64_decode(b64) else {
            return false;
        };
        if raw.len() < 20 {
            return false;
        }
        let (digest, salt) = raw.split_at(20);
        let mut buf = Vec::with_capacity(password.len() + salt.len());
        buf.extend_from_slice(password);
        buf.extend_from_slice(salt);
        ct_eq(&sha1(&buf), digest)
    } else if let Some(b64) = stored.strip_prefix("{SHA}") {
        let Some(raw) = b64_decode(b64) else {
            return false;
        };
        if raw.len() != 20 {
            return false;
        }
        ct_eq(&sha1(password), &raw)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for input in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let enc = b64_encode(input);
            assert_eq!(b64_decode(&enc).unwrap(), input);
        }
    }

    #[test]
    fn base64_known_vector() {
        // RFC 4648 test vectors.
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
    }

    #[test]
    fn sha_known_vector() {
        // {SHA} of "secret".
        assert_eq!(sha_hash(b"secret"), "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=");
    }

    #[test]
    fn sha_round_trip() {
        let h = sha_hash(b"correct horse");
        assert!(sha_verify(b"correct horse", &h));
        assert!(!sha_verify(b"wrong horse", &h));
    }

    #[test]
    fn ssha_round_trip() {
        let h = ssha_hash(b"correct horse", b"NaClNaCl");
        assert!(sha_verify(b"correct horse", &h));
        assert!(!sha_verify(b"wrong horse", &h));
    }

    #[test]
    fn ssha_uses_salt() {
        let a = ssha_hash(b"pw", b"saltA");
        let b = ssha_hash(b"pw", b"saltB");
        assert_ne!(a, b);
        assert!(sha_verify(b"pw", &a));
        assert!(sha_verify(b"pw", &b));
    }

    #[test]
    fn verify_rejects_malformed() {
        assert!(!sha_verify(b"pw", "no-prefix"));
        assert!(!sha_verify(b"pw", "{SHA}not!base64!"));
        assert!(!sha_verify(b"pw", "{SSHA}"));
    }
}
