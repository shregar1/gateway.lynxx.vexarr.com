/// JWT tokenizer — split a JWT into its three dot-separated parts.
///
/// Operates on raw bytes for zero-copy parsing in hot paths.
/// Does not validate base64 or JSON contents; only splits.

/// Split a JWT token into (header, payload, signature).
/// Returns None if the token does not have exactly two dots.
pub fn jwt_split(token: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut dots = [0usize; 2];
    let mut count = 0;

    for (i, &b) in token.iter().enumerate() {
        if b == b'.' {
            if count >= 2 {
                return None; // too many dots
            }
            dots[count] = i;
            count += 1;
        }
    }

    if count != 2 {
        return None;
    }

    let header = &token[..dots[0]];
    let payload = &token[dots[0] + 1..dots[1]];
    let signature = &token[dots[1] + 1..];

    Some((header, payload, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_jwt() {
        let token = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123sig";
        let (h, p, s) = jwt_split(token).unwrap();
        assert_eq!(h, b"eyJhbGciOiJIUzI1NiJ9");
        assert_eq!(p, b"eyJzdWIiOiIxMjM0NTY3ODkwIn0");
        assert_eq!(s, b"abc123sig");
    }

    #[test]
    fn no_dots() {
        assert!(jwt_split(b"nodots").is_none());
    }

    #[test]
    fn one_dot() {
        assert!(jwt_split(b"one.dot").is_none());
    }

    #[test]
    fn three_dots() {
        assert!(jwt_split(b"a.b.c.d").is_none());
    }

    #[test]
    fn empty_parts() {
        let (h, p, s) = jwt_split(b"..").unwrap();
        assert!(h.is_empty());
        assert!(p.is_empty());
        assert!(s.is_empty());
    }
}
