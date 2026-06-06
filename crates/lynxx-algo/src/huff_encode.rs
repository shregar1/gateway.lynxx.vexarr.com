//! `ngx_http_huff_encode()` — `src/http/ngx_http_huff_encode.c` (RFC 7541 HPACK)

include!(concat!(env!("OUT_DIR"), "/huff_encode_table.rs"));

/// Huffman-encode `src` into `dst` (`ngx_http_huff_encode`); returns bytes written.
#[inline(always)]
pub fn ngx_http_huff_encode(dst: &mut [u8], src: &[u8]) -> usize {
    unsafe {
        let mut src_p = src.as_ptr();
        let end = src_p.add(src.len());
        let dp = dst.as_mut_ptr();
        let mut buf: u64 = 0;
        let mut pending: u32 = 0;
        let mut hlen = 0usize;

        macro_rules! enc_byte {
            ($ch:expr) => {{
                let ent = *HUFF_ENCODE_PACKED.get_unchecked($ch as usize);
                let code = ent as u32;
                pending += (ent >> 32) as u32;
                if pending < 64 {
                    buf |= (code as u64) << (64 - pending);
                } else {
                    pending -= 64;
                    buf |= (code as u64) >> pending;
                    flush_be64(dp.add(hlen), buf);
                    hlen += 8;
                    buf = if pending > 0 {
                        (code as u64) << (64 - pending)
                    } else {
                        0
                    };
                }
            }};
        }

        while src_p.add(16) <= end {
            enc_byte!(*src_p);
            enc_byte!(*src_p.add(1));
            enc_byte!(*src_p.add(2));
            enc_byte!(*src_p.add(3));
            enc_byte!(*src_p.add(4));
            enc_byte!(*src_p.add(5));
            enc_byte!(*src_p.add(6));
            enc_byte!(*src_p.add(7));
            enc_byte!(*src_p.add(8));
            enc_byte!(*src_p.add(9));
            enc_byte!(*src_p.add(10));
            enc_byte!(*src_p.add(11));
            enc_byte!(*src_p.add(12));
            enc_byte!(*src_p.add(13));
            enc_byte!(*src_p.add(14));
            enc_byte!(*src_p.add(15));
            src_p = src_p.add(16);
        }
        while src_p != end {
            enc_byte!(*src_p);
            src_p = src_p.add(1);
        }

        if pending == 0 {
            return hlen;
        }

        buf |= (!0u64) >> pending;
        pending = (pending + 7) & !7;
        buf >>= 64 - pending;
        while pending != 0 {
            pending -= 8;
            *dp.add(hlen) = (buf >> pending) as u8;
            hlen += 1;
        }
        hlen
    }
}

#[inline(always)]
unsafe fn flush_be64(dst: *mut u8, buf: u64) {
    let word = if cfg!(target_endian = "little") {
        buf.swap_bytes()
    } else {
        buf
    };
    (dst as *mut u64).write_unaligned(word);
}
