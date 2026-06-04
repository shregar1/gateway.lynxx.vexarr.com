//! Optimized HPACK Huffman decoder — branchless byte-table with speculative emit.
//!
//! ## Problem
//! The original nginx decoder (`dec_byte_fast`) uses a 3-way branch per input byte
//! to decide how many characters to emit (0, 1, or 2). On typical HTTP header content
//! the emit pattern is irregular, causing branch mispredictions.
//!
//! Initial hypothesis (nibble-only, L1-resident 16KB table) was **disproven** by
//! benchmarking: the 2× lookup count of nibble decoding is a net loss because modern
//! prefetchers handle the byte table's sequential access pattern well enough that L1
//! residency doesn't compensate.
//!
//! ## Strategy: branchless speculative emit
//! Keep the 512KB byte table (1 lookup per byte) but eliminate the per-byte branch:
//! - **Speculative double-write**: Always write 2 potential characters to output,
//!   advance the write pointer by actual emit count (0, 1, or 2). Speculative writes
//!   are harmless — overwritten by subsequent real writes.
//! - **Batched error checks**: AND validity bits across 8 bytes, check once.
//!   Eliminates 7 of 8 error-check branches.
//! - **8× unrolling**: Reduce loop overhead, improve instruction scheduling.
//! - **Hybrid last-chunk**: Byte table for N-1 bytes (fast, branchless), nibble
//!   table only for final byte (needed for EOS ending-flag validation).
//!
//! ## Table layouts
//! - Byte table: `[u64; 65536]` (512 KB), indexed `[state<<8 | byte]`
//!   Entry: bit 0 = valid, bits 1-8 = next_state, bits 9-10 = emit_count,
//!          bits 11-18 = char1, bits 19-26 = char2
//! - Nibble table: `[u32; 4096]` (16 KB), indexed `[state<<4 | nibble]`
//!   Entry: bits 0-7 = next_state, 8-15 = emit_flag, 16-23 = char, 24-31 = ending

/// Branchless byte-table streaming decode. Returns bytes written to dst, or -1 on error.
///
/// Hot path for HPACK header blocks where `last=false`.
/// Always writes 2 speculative chars per lookup, advances by actual emit count.
///
/// SAFETY: caller should allocate dst with >= 2 bytes of slack beyond expected output
/// to accommodate speculative writes.
#[inline(always)]
pub fn huff_decode_branchless_stream(
    state: &mut u8,
    src: &[u8],
    dst: &mut [u8],
    byte_table: &[u64],  // HUFF_DECODE_BYTE: [u64; 65536], indexed as [state<<8 | byte]
) -> i32 {
    let src_len = src.len();
    if src_len == 0 {
        return 0;
    }

    let dst_len = dst.len();
    let mut d = 0usize;
    let mut i = 0usize;

    unsafe {
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr();

        // Main loop: 8× unrolled, branchless emit, batched error check.
        // Each byte emits at most 2 chars → 8 bytes → max 16 chars.
        // We need d + 17 <= dst_len for safe speculative writes (last write at d+16, plus d+17 for second speculative char).
        while i + 8 <= src_len && d + 18 <= dst_len {
            let mut valid_acc = u64::MAX;

            macro_rules! step {
                ($off:expr) => {{
                    let ch = *src_ptr.add(i + $off);
                    let w = *byte_table.get_unchecked(((*state as usize) << 8) | ch as usize);
                    valid_acc &= w;
                    // Branchless speculative emit: always write 2 chars
                    *dst_ptr.add(d) = ((w >> 11) & 0xff) as u8;
                    *dst_ptr.add(d + 1) = ((w >> 19) & 0xff) as u8;
                    // Advance by actual emit count (0, 1, or 2)
                    d += ((w >> 9) & 3) as usize;
                    *state = ((w >> 1) & 0xff) as u8;
                }};
            }

            step!(0); step!(1); step!(2); step!(3);
            step!(4); step!(5); step!(6); step!(7);

            // Single batched validity check for all 8 lookups
            if valid_acc & 1 == 0 { return -1; }
            i += 8;
        }

        // Mid tail: per-byte branchless (needs 2 bytes slack for speculative writes)
        while i < src_len && d + 2 <= dst_len {
            let ch = *src_ptr.add(i);
            let w = *byte_table.get_unchecked(((*state as usize) << 8) | ch as usize);
            if w & 1 == 0 { return -1; }
            *dst_ptr.add(d) = ((w >> 11) & 0xff) as u8;
            *dst_ptr.add(d + 1) = ((w >> 19) & 0xff) as u8;
            d += ((w >> 9) & 3) as usize;
            *state = ((w >> 1) & 0xff) as u8;
            i += 1;
        }

        // Tight tail: dst nearly full, use branched emit (rare)
        while i < src_len {
            let ch = *src_ptr.add(i);
            let w = *byte_table.get_unchecked(((*state as usize) << 8) | ch as usize);
            if w & 1 == 0 { return -1; }
            let emit = ((w >> 9) & 3) as usize;
            if d + emit > dst_len { return -1; }
            if emit >= 1 { *dst_ptr.add(d) = ((w >> 11) & 0xff) as u8; }
            if emit >= 2 { *dst_ptr.add(d + 1) = ((w >> 19) & 0xff) as u8; }
            d += emit;
            *state = ((w >> 1) & 0xff) as u8;
            i += 1;
        }
    }

    d as i32
}

/// Hybrid last-chunk decode: byte table for first N-1 bytes, nibble table for last byte.
///
/// The ending flag (EOS validation) is only available in the nibble table, so we
/// need nibble lookups for the final byte. All preceding bytes use the fast
/// branchless byte-table path.
#[inline(always)]
pub fn huff_decode_hybrid_last(
    state: &mut u8,
    src: &[u8],
    dst: &mut [u8],
    byte_table: &[u64],   // HUFF_DECODE_BYTE
    nibble_table: &[u32], // HUFF_DECODE_FLAT
) -> i32 {
    let src_len = src.len();
    if src_len == 0 {
        // Empty last chunk — check if we're at a valid state
        *state = 0;
        return 0;
    }

    let d: i32;

    // Process all-but-last byte with branchless byte-table
    if src_len > 1 {
        d = huff_decode_branchless_stream(state, &src[..src_len - 1], dst, byte_table);
        if d < 0 { return -1; }
    } else {
        d = 0;
    }

    // Process last byte with nibble table (for ending flag validation)
    let last_d = huff_decode_nibble_last_single(state, src[src_len - 1], &mut dst[d as usize..], nibble_table);
    if last_d < 0 { return -1; }

    d + last_d
}

/// Decode a single byte using the nibble table, with ending-flag tracking.
/// Used only for the final byte of a last chunk.
#[inline(always)]
fn huff_decode_nibble_last_single(
    state: &mut u8,
    ch: u8,
    dst: &mut [u8],
    nibble_table: &[u32],
) -> i32 {
    let dst_len = dst.len();
    let mut d = 0usize;

    unsafe {
        let dst_ptr = dst.as_mut_ptr();

        // High nibble
        let wh = *nibble_table.get_unchecked(((*state as usize) << 4) | ((ch >> 4) as usize));
        let nexth = (wh & 0xff) as u8;
        if nexth == *state { return -1; }
        if wh & 0xff00 != 0 {
            if d >= dst_len { return -1; }
            *dst_ptr.add(d) = ((wh >> 16) & 0xff) as u8;
            d += 1;
        }
        *state = nexth;

        // Low nibble — read ending flag here
        let wl = *nibble_table.get_unchecked(((*state as usize) << 4) | ((ch & 0xf) as usize));
        let nextl = (wl & 0xff) as u8;
        if nextl == *state { return -1; }
        if wl & 0xff00 != 0 {
            if d >= dst_len { return -1; }
            *dst_ptr.add(d) = ((wl >> 16) & 0xff) as u8;
            d += 1;
        }
        let ending = ((wl >> 24) & 0xff) as u8;
        *state = nextl;

        if ending == 0 { return -1; }
    }

    *state = 0;
    d as i32
}

/// Combined dispatch: picks branchless-stream or hybrid-last based on `last` flag.
#[inline(always)]
pub fn huff_decode_fast(
    state: &mut u8,
    src: &[u8],
    dst: &mut [u8],
    last: bool,
    byte_table: &[u64],
    nibble_table: &[u32],
) -> i32 {
    if last {
        huff_decode_hybrid_last(state, src, dst, byte_table, nibble_table)
    } else {
        huff_decode_branchless_stream(state, src, dst, byte_table)
    }
}
