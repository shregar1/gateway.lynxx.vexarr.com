/// FIX protocol message parser.
///
/// FIX messages are sequences of tag=value pairs separated by SOH (0x01).
/// This parser extracts all tag-value pairs from a raw FIX message.

const SOH: u8 = 0x01;

/// Parse a FIX message into a list of (tag, value) pairs.
/// Tags are numeric; values are raw byte slices.
/// Returns None if the message is malformed.
pub fn parse_fix_message(data: &[u8]) -> Option<Vec<(u32, &[u8])>> {
    if data.is_empty() {
        return None;
    }

    let mut fields = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Find '='
        let eq_pos = data[pos..].iter().position(|&b| b == b'=')?;
        let tag_bytes = &data[pos..pos + eq_pos];

        // Parse tag as u32
        let tag = parse_u32(tag_bytes)?;

        let val_start = pos + eq_pos + 1;

        // Find SOH or end of data
        let val_end = data[val_start..]
            .iter()
            .position(|&b| b == SOH)
            .map(|p| val_start + p)
            .unwrap_or(data.len());

        let value = &data[val_start..val_end];
        fields.push((tag, value));

        pos = if val_end < data.len() {
            val_end + 1 // skip SOH
        } else {
            val_end
        };
    }

    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

fn parse_u32(bytes: &[u8]) -> Option<u32> {
    let mut result = 0u32;
    if bytes.is_empty() {
        return None;
    }
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_message() {
        // 8=FIX.4.4 | 9=5 | 35=0 | 10=123 |
        let msg = b"8=FIX.4.4\x019=5\x0135=0\x0110=123\x01";
        let fields = parse_fix_message(msg).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], (8, b"FIX.4.4".as_slice()));
        assert_eq!(fields[1], (9, b"5".as_slice()));
        assert_eq!(fields[2], (35, b"0".as_slice()));
        assert_eq!(fields[3], (10, b"123".as_slice()));
    }

    #[test]
    fn no_trailing_soh() {
        let msg = b"8=FIX.4.4\x0135=A";
        let fields = parse_fix_message(msg).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1], (35, b"A".as_slice()));
    }

    #[test]
    fn empty_value() {
        let msg = b"8=\x0135=A\x01";
        let fields = parse_fix_message(msg).unwrap();
        assert_eq!(fields[0], (8, b"".as_slice()));
    }

    #[test]
    fn empty_input() {
        assert!(parse_fix_message(b"").is_none());
    }

    #[test]
    fn malformed_no_equals() {
        assert!(parse_fix_message(b"no-equals-here\x01").is_none());
    }
}
