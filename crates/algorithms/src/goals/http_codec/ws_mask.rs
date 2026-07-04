/// WebSocket XOR masking (RFC 6455 §5.3).
///
/// Applies the 4-byte mask key to `payload` in place.  The inner loop processes
/// 8 bytes at a time via a widened `u64` mask, falling back to byte-at-a-time
/// for the tail.  This mirrors the technique used in Caddy's WebSocket proxy.
pub fn ws_mask(payload: &mut [u8], mask_key: [u8; 4]) {
    if mask_key == [0, 0, 0, 0] || payload.is_empty() {
        return;
    }

    // Build a 64-bit mask by repeating the 4-byte key twice.
    let mask_u32 = u32::from_ne_bytes(mask_key);
    let mask_u64 = (mask_u32 as u64) | ((mask_u32 as u64) << 32);

    let (prefix, middle, suffix) = unsafe { payload.align_to_mut::<u64>() };

    // XOR unaligned prefix bytes one-at-a-time.
    for (i, byte) in prefix.iter_mut().enumerate() {
        *byte ^= mask_key[i % 4];
    }

    // The wide-word mask must be rotated to account for the prefix offset.
    let offset = prefix.len() % 4;
    let wide_mask = if offset == 0 {
        mask_u64
    } else {
        // Rotate the mask_key so byte[0] of middle aligns correctly.
        let mut rotated = [0u8; 8];
        for i in 0..8 {
            rotated[i] = mask_key[(i + offset) % 4];
        }
        u64::from_ne_bytes(rotated)
    };

    // XOR 8 bytes at a time.
    for word in middle.iter_mut() {
        *word ^= wide_mask;
    }

    // XOR remaining suffix bytes.
    let suffix_offset = (prefix.len() + middle.len() * 8) % 4;
    for (i, byte) in suffix.iter_mut().enumerate() {
        *byte ^= mask_key[(suffix_offset + i) % 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_payload() {
        let mut buf = vec![];
        ws_mask(&mut buf, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_zero_mask() {
        let mut buf = vec![1, 2, 3, 4];
        ws_mask(&mut buf, [0, 0, 0, 0]);
        assert_eq!(buf, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_roundtrip() {
        let original = b"Hello, WebSocket!".to_vec();
        let mask = [0x37, 0xFA, 0x21, 0x3D];
        let mut buf = original.clone();
        ws_mask(&mut buf, mask);
        assert_ne!(buf, original);
        ws_mask(&mut buf, mask);
        assert_eq!(buf, original);
    }

    #[test]
    fn test_short_payload() {
        let mut buf = vec![0xFF];
        ws_mask(&mut buf, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buf, vec![0xFF ^ 0x01]);
    }

    #[test]
    fn test_exact_8_bytes() {
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mask = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut buf = original.clone();
        ws_mask(&mut buf, mask);
        ws_mask(&mut buf, mask);
        assert_eq!(buf, original);
    }

    #[test]
    fn test_large_payload_roundtrip() {
        let original: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let mask = [0x12, 0x34, 0x56, 0x78];
        let mut buf = original.clone();
        ws_mask(&mut buf, mask);
        ws_mask(&mut buf, mask);
        assert_eq!(buf, original);
    }
}
