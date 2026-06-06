//! Parity tests: Rust ports must match compiled C extracts from `tests/c/nginx_algos.c`.

#![allow(non_camel_case_types)]

use lynxx_algo::*;

extern "C" {
    fn c_ngx_murmur_hash2(data: *mut u8, len: usize) -> u32;
    fn c_ngx_crc32_short(p: *mut u8, len: usize) -> u32;
    fn c_ngx_crc32_long(p: *mut u8, len: usize) -> u32;
    fn c_ngx_hash_key(data: *mut u8, len: usize) -> usize;
    fn c_ngx_strnstr(s1: *mut u8, s2: *const i8, len: usize) -> *mut u8;
    fn c_ngx_limit_req_excess(
        stored_excess: i64,
        rate: u32,
        now: i64,
        last: i64,
        out_excess: *mut i32,
    ) -> i32;
    fn c_ngx_ip_hash_mix(addr: *mut u8, addrlen: usize, hash: u32) -> u32;
    fn c_ngx_rbtree_timer_less(node_key: u32, temp_key: u32) -> i32;
    fn c_ngx_hash_key_lc(data: *mut u8, len: usize) -> usize;
    fn c_ngx_split_clients_pick(hash: u32, cuts: *const u32, n: usize) -> usize;
    fn c_ngx_utf8_decode(p: *mut *mut u8, n: usize) -> u32;
    fn c_ngx_utf8_decode_scan(data: *mut u8, size: usize) -> usize;
    fn c_ngx_escape_uri_count(src: *mut u8, size: usize) -> usize;
    fn c_ngx_escape_uri(dst: *mut u8, src: *mut u8, size: usize) -> usize;
    fn c_ngx_inet_addr(text: *mut u8, len: usize) -> u32;
    fn c_ngx_inet6_addr(p: *mut u8, len: usize, addr: *mut u8) -> i32;
    fn c_ngx_unescape_uri(dst: *mut *mut u8, src: *mut *mut u8, size: usize, typ: u32);
    fn c_ngx_atosz(line: *mut u8, n: usize) -> isize;
    fn c_ngx_atoi(line: *mut u8, n: usize) -> isize;
    fn c_ngx_parse_size(line: *mut u8, len: usize) -> isize;
    fn c_ngx_parse_time(line: *mut u8, len: usize, is_sec: u32) -> i64;
    fn c_ngx_escape_args_count(src: *mut u8, size: usize) -> usize;
    fn c_ngx_escape_uri_component_count(src: *mut u8, size: usize) -> usize;
    fn c_radix_bench_find(key: u32) -> usize;
    fn c_radix_bench_tree_init();
    fn c_ngx_hextoi(line: *mut u8, n: usize) -> isize;
    fn c_ngx_encode_base64(dst: *mut u8, src: *mut u8, len: usize) -> usize;
    fn c_ngx_decode_base64(dst: *mut u8, src: *mut u8, src_len: usize) -> isize;
    fn c_ngx_encode_base64url(dst: *mut u8, src: *mut u8, len: usize) -> usize;
    fn c_ngx_decode_base64url(dst: *mut u8, src: *mut u8, src_len: usize) -> isize;
    fn c_ngx_hex_dump(dst: *mut u8, src: *mut u8, len: usize) -> usize;
    fn c_ngx_http_chunked_header(buf: *mut u8, size: u64) -> usize;
    fn c_ngx_http_chunked_parse_line(
        buf: *const u8,
        len: usize,
        size: *mut u64,
        consumed: *mut usize,
    ) -> i32;
    fn c_ngx_http_chunked_parse_buffer(
        buf: *const u8,
        len: usize,
        count: *mut usize,
        sum: *mut u64,
    ) -> i32;
    fn c_ngx_http_chunked_parse_stream(
        buf: *const u8,
        len: usize,
        count: *mut usize,
        sum: *mut u64,
    ) -> i32;
    fn c_ngx_http_huff_decode(
        state: *mut u8,
        src: *mut u8,
        len: usize,
        dst: *mut *mut u8,
        last: u32,
    ) -> i32;
    fn c_ngx_http_huff_encode(src: *mut u8, len: usize, dst: *mut u8) -> usize;
    fn c_ngx_http_v3_encode_varlen_int(p: *mut u8, value: u64) -> usize;
    fn c_ngx_http_v3_decode_varlen_int(p: *const u8, len: usize, value: *mut u64) -> isize;
    fn c_ngx_http_v3_encode_prefix_int(
        p: *mut u8,
        first: u8,
        value: u64,
        prefix: u32,
    ) -> usize;
    fn c_ngx_http_v3_decode_prefix_int(
        p: *const u8,
        len: usize,
        prefix: u32,
        value: *mut u64,
    ) -> isize;
    fn c_ngx_proxy_protocol_v2_parse_inet(
        buf: *const u8,
        len: usize,
        out: *mut CProxyV2Inet,
    ) -> i32;
    fn c_ngx_conf_scan_tokens(buf: *const u8, len: usize) -> usize;
    fn c_ngx_http_v2_parse_frame_header(p: *const u8, out: *mut CH2FrameHdr);
    fn c_ngx_proxy_protocol_v1_parse_inet(
        buf: *const u8,
        len: usize,
        out: *mut CProxyV2Inet,
    ) -> i32;
    fn c_ngx_http_sub_init_tables(
        tables: *mut CSubTables,
        matches: *mut CSubMatch,
        n: usize,
    );
    fn c_ngx_http_sub_find(
        text: *mut u8,
        tlen: usize,
        matches: *mut CSubMatch,
        n: usize,
        tables: *const CSubTables,
        out_pos: *mut usize,
        out_idx: *mut usize,
    ) -> i32;
}

#[repr(C)]
struct CH2FrameHdr {
    length: u32,
    frame_type: u8,
    flags: u8,
    sid: u32,
}

#[repr(C)]
struct CProxyV2Inet {
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
}

#[repr(C)]
struct CSubMatch {
    pat: *mut u8,
    len: usize,
}

#[repr(C)]
struct CSubTables {
    shift: [u8; 256],
    index: [u8; 257],
    min_match_len: usize,
    max_match_len: usize,
}

fn c_murmur(data: &[u8]) -> u32 {
    unsafe { c_ngx_murmur_hash2(data.as_ptr() as *mut u8, data.len()) }
}

fn c_crc32_short(data: &[u8]) -> u32 {
    unsafe { c_ngx_crc32_short(data.as_ptr() as *mut u8, data.len()) }
}

fn c_crc32_long(data: &[u8]) -> u32 {
    unsafe { c_ngx_crc32_long(data.as_ptr() as *mut u8, data.len()) }
}

fn c_hash_key(data: &[u8]) -> usize {
    unsafe { c_ngx_hash_key(data.as_ptr() as *mut u8, data.len()) }
}

fn c_strnstr(hay: &[u8], needle: &str) -> Option<usize> {
    let mut buf = hay.to_vec();
    buf.push(0); // sentinel not reached if len bounds correct
    let hay_len = hay.len();
    let c_needle = std::ffi::CString::new(needle).unwrap();
    let ptr = unsafe {
        c_ngx_strnstr(buf.as_mut_ptr(), c_needle.as_ptr(), hay_len)
    };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { ptr.offset_from(buf.as_ptr()) } as usize)
    }
}

#[test]
fn murmur_hash2_parity() {
    for len in [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 100, 1024] {
        let data: Vec<u8> = (0..len)
            .map(|i| ((i as u32).wrapping_mul(31) ^ 0xA5) as u8)
            .collect();
        assert_eq!(ngx_murmur_hash2(&data), c_murmur(&data), "len={len}");
    }
}

#[test]
fn crc32_parity() {
    for len in [0, 1, 16, 32, 60, 61, 256, 4096] {
        let data: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
        assert_eq!(ngx_crc32_short(&data), c_crc32_short(&data), "short len={len}");
        assert_eq!(ngx_crc32_long(&data), c_crc32_long(&data), "long len={len}");
    }
}

#[test]
fn hash_key_parity() {
    let long: Vec<u8> = (0u8..200).collect();
    let samples: Vec<&[u8]> = vec![
        b"",
        b"hello",
        b"nginx.org",
        b"X-Forwarded-For: 203.0.113.1\r\n",
        &long,
    ];
    for data in samples {
        assert_eq!(ngx_hash_key(data), c_hash_key(data));
    }
    for len in 0..=32 {
        let data: Vec<u8> = (0..len)
            .map(|i| ((i as u32).wrapping_mul(13) ^ 0xA5) as u8)
            .collect();
        assert_eq!(ngx_hash_key(&data), c_hash_key(&data), "len={len}");
    }
}

#[test]
fn strnstr_parity() {
    let hay = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    for needle in ["GET", "Host:", "HTTP/1.1", "missing"] {
        let r = ngx_strnstr(hay, needle);
        let c = c_strnstr(hay, needle);
        assert_eq!(r, c, "needle={needle:?}");
    }
}

#[test]
fn strnstr_stops_at_nul() {
    let hay = b"prefix\0suffix Host: tail";
    for needle in ["suffix", "Host:", "prefix"] {
        assert_eq!(
            ngx_strnstr(hay, needle),
            c_strnstr(hay, needle),
            "needle={needle:?}"
        );
    }
}

#[test]
fn limit_req_excess_parity() {
    let cases = [
        (500, 1000, 10_000, 9_000),
        (2000, 500, 10_000, 10_000),
        (0, 1000, 10_000, 9_500),
    ];
    for (stored, rate, now, last) in cases {
        let rust = ngx_limit_req_excess(stored, rate, now, last);
        let mut out = 0i32;
        let c = unsafe {
            c_ngx_limit_req_excess(stored, rate, now, last, &mut out as *mut i32)
        };
        assert_eq!(rust, c);
        assert_eq!(rust, out);
    }
}

#[test]
fn ip_hash_mix_parity() {
    let addr = [192u8, 168, 1, 42];
    assert_eq!(ngx_ip_hash_mix(&addr, 0), unsafe {
        c_ngx_ip_hash_mix(addr.as_ptr() as *mut u8, addr.len(), 0)
    });
}

#[test]
fn rbtree_timer_less_parity() {
    let pairs = [
        (100u32, 200u32),
        (0xffff_fff0, 10u32),
        (10u32, 0xffff_fff0),
        (0, 0),
    ];
    for (a, b) in pairs {
        let r = ngx_rbtree_timer_less(a, b);
        let c = unsafe { c_ngx_rbtree_timer_less(a, b) != 0 };
        assert_eq!(r, c, "a={a} b={b}");
    }
}

#[test]
fn hash_key_lc_parity() {
    let samples: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"Host".to_vec(),
        b"X-Forwarded-For: 203.0.113.1\r\n".to_vec(),
        (0u8..200).collect(),
    ];
    for data in &samples {
        assert_eq!(
            ngx_hash_key_lc(data),
            unsafe { c_ngx_hash_key_lc(data.as_ptr() as *mut u8, data.len()) },
            "data len={}",
            data.len()
        );
    }
}

#[test]
fn inet_addr_parity() {
    let samples: &[&[u8]] = &[b"127.0.0.1", b"203.0.113.42", b"255.255.255.255", b"10.0", b"x"];
    for s in samples {
        assert_eq!(
            ngx_inet_addr(s),
            unsafe { c_ngx_inet_addr(s.as_ptr() as *mut u8, s.len()) },
            "s={s:?}"
        );
    }
}

#[test]
fn inet6_addr_parity() {
    let cases: &[&[u8]] = &[
        b"::1",
        b"2001:db8::1",
        b"fe80::1",
        b"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        b"::ffff:0:0",
        b"2001:db8::ffff:192.0.2.1",
    ];
    for text in cases {
        let mut ra = [0u8; 16];
        let mut ca = [0u8; 16];
        let rr = ngx_inet6_addr(text, &mut ra);
        let cr = unsafe { c_ngx_inet6_addr(text.as_ptr() as *mut u8, text.len(), ca.as_mut_ptr()) };
        assert_eq!(rr, cr, "text={text:?}");
        assert_eq!(ra, ca, "text={text:?}");
    }
    let mut a = [0u8; 16];
    assert_eq!(ngx_inet6_addr(b"", &mut a), NGX_INET_ERROR);
}

#[test]
fn escape_uri_lut_matches_c_bits() {
    for ch in 0u32..256 {
        let b = ch as u8;
        let src = [b];
        let rust = ngx_escape_uri_count(&src) == 1;
        let c = unsafe { c_ngx_escape_uri_count(src.as_ptr() as *mut u8, 1) == 1 };
        assert_eq!(rust, c, "ch={ch}");
    }
}

#[test]
fn escape_uri_count_parity() {
    let samples: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"/api/v1/search?q=hello+world&x=1".to_vec(),
        (0..512).map(|i| (i % 256) as u8).collect(),
    ];
    for data in &samples {
        assert_eq!(
            ngx_escape_uri_count(data),
            unsafe { c_ngx_escape_uri_count(data.as_ptr() as *mut u8, data.len()) },
            "len={}",
            data.len()
        );
    }
}

fn c_unescape_uri(src: &[u8]) -> Vec<u8> {
    let mut dst = vec![0u8; src.len()];
    let mut dp = dst.as_mut_ptr();
    let mut sp = src.as_ptr() as *mut u8;
    unsafe {
        c_ngx_unescape_uri(&mut dp, &mut sp, src.len(), NGX_UNESCAPE_URI);
    }
    let w = dp as usize - dst.as_ptr() as usize;
    dst.truncate(w);
    dst
}

#[test]
fn unescape_uri_parity() {
    for src in [
        b"/path/to/file".as_slice(),
        b"hello%20world",
        b"a%2Fb%3Fc",
        b"q%3Fmark",
    ] {
        let mut rd = vec![0u8; src.len()];
        let rw = ngx_unescape_uri(&mut rd, src, true);
        let cd = c_unescape_uri(src);
        assert_eq!(&rd[..rw], cd.as_slice(), "src={src:?}");
    }
}

fn geo_test_tree() -> RadixTree32 {
    let mut t = RadixTree32::new();
    t.preallocate();
    assert_eq!(t.insert(0x0b000000, 0xff000000, 1), 0);
    assert_eq!(t.insert(0x7f000000, 0xff000000, 2), 0);
    assert_eq!(t.insert(0xc0a80100, 0xffffff00, 3), 0);
    assert_eq!(t.insert(0xcb007100, 0xfffffff0, 4), 0);
    t
}

#[test]
fn radix32_find_parity() {
    let t = geo_test_tree();
    unsafe { c_radix_bench_tree_init() };
    for key in [0x0b010203u32, 0x7f000001, 0xc0a80155, 0xcb007199] {
        assert_eq!(
            t.find(key),
            unsafe { c_radix_bench_find(key) },
            "key={key:#x}"
        );
    }
}

#[test]
fn parse_size_parity() {
    for s in [b"1024".as_slice(), b"1m", b"512k"] {
        assert_eq!(
            ngx_parse_size(s),
            unsafe { c_ngx_parse_size(s.as_ptr() as *mut u8, s.len()) },
            "s={s:?}"
        );
    }
}

#[test]
fn atoi_parity() {
    let samples: &[&[u8]] = &[b"0", b"42", b"1048576"];
    for s in samples {
        assert_eq!(
            ngx_atoi(s),
            unsafe { c_ngx_atoi(s.as_ptr() as *mut u8, s.len()) },
            "s={s:?}"
        );
    }
}

#[test]
fn parse_time_parity() {
    for (s, sec) in [
        (&b"30s"[..], 1u32),
        (b"1d", 0),
        (b"100ms", 0),
        (b"2h", 0),
    ] {
        assert_eq!(
            ngx_parse_time(s, sec != 0),
            unsafe { c_ngx_parse_time(s.as_ptr() as *mut u8, s.len(), sec) as isize },
            "s={s:?} sec={sec}"
        );
    }
}

#[test]
fn escape_uri_component_count_parity() {
    let data = b"/path?name=a+b&x=1";
    assert_eq!(
        ngx_escape_uri_component_count(data),
        unsafe { c_ngx_escape_uri_component_count(data.as_ptr() as *mut u8, data.len()) }
    );
}

#[test]
fn escape_args_count_parity() {
    let data = b"a=1&b=2%20c";
    assert_eq!(
        ngx_escape_args_count(data),
        unsafe { c_ngx_escape_args_count(data.as_ptr() as *mut u8, data.len()) }
    );
}

#[test]
fn atosz_parity() {
    let samples: &[&[u8]] = &[b"0", b"42", b"1048576", b"999999999999999999999"];
    for s in samples {
        assert_eq!(
            ngx_atosz(s),
            unsafe { c_ngx_atosz(s.as_ptr() as *mut u8, s.len()) },
            "s={s:?}"
        );
    }
    assert_eq!(ngx_atosz(b""), NGX_PARSE_ERROR);
    assert_eq!(ngx_atosz(b"12x"), NGX_PARSE_ERROR);
}

#[test]
fn escape_uri_encode_parity() {
    let src = b"GET /foo bar?q=a b";
    let mut rd = vec![0u8; src.len() * 3];
    let mut cd = vec![0u8; src.len() * 3];
    let rw = ngx_escape_uri(&mut rd, src);
    let cw = unsafe {
        c_ngx_escape_uri(cd.as_mut_ptr(), src.as_ptr() as *mut u8, src.len()) as usize
            - cd.as_ptr() as usize
    };
    assert_eq!(rw, cw);
    assert_eq!(&rd[..rw], &cd[..cw]);
}

#[test]
fn utf8_decode_parity() {
    let samples: &[&[u8]] = &[
        &[0xe4, 0xb8, 0xad],
        &[0xf0, 0x9f, 0x98, 0x80],
        &[0xc2, 0x80],
        &[0xff],
        &[0xe4, 0xb8],
    ];
    for bytes in samples {
        let mut rp = bytes.as_ptr();
        let mut cp = bytes.as_ptr() as *mut u8;
        let ru = unsafe { ngx_utf8_decode(&mut rp, bytes.len()) };
        let cu = unsafe { c_ngx_utf8_decode(&mut cp, bytes.len()) };
        assert_eq!(ru, cu, "bytes={bytes:?}");
        assert_eq!(rp, cp as *const u8);
    }
}

#[test]
fn utf8_decode_scan_parity() {
    let data = {
        let mut v = Vec::new();
        for _ in 0..2000 {
            v.extend_from_slice(&[0xe4, 0xb8, 0xad]);
        }
        v.push(0x41);
        v
    };
    assert_eq!(
        unsafe { ngx_utf8_decode_scan(&data) },
        unsafe { c_ngx_utf8_decode_scan(data.as_ptr() as *mut u8, data.len()) }
    );
}

#[test]
fn split_clients_pick_parity() {
    let cuts = [
        0x1400_0000u32,
        0x2800_0000,
        0x5000_0000,
        0xffff_ffff,
    ];
    for hash in [0u32, 0x1000_0000, 0x4000_0000, 0xffff_ffff] {
        assert_eq!(
            ngx_split_clients_pick(hash, &cuts),
            unsafe { c_ngx_split_clients_pick(hash, cuts.as_ptr(), cuts.len()) },
            "hash={hash}"
        );
    }
}

#[test]
fn sub_filter_find_parity() {
    let pats: Vec<Vec<u8>> = vec![b"nginx".to_vec(), b"host".to_vec(), b"http".to_vec()];
    let text = b"welcome to nginx http host nginx";
    let mut rust_matches: Vec<SubMatch> = pats.iter().map(|p| SubMatch::new(p.clone())).collect();
    let rust_tables = ngx_http_sub_init_tables(&mut rust_matches).unwrap();
    let rust_found = ngx_http_sub_find(text, &rust_matches, &rust_tables);

    let mut c_matches: Vec<CSubMatch> = pats
        .iter()
        .map(|p| CSubMatch {
            pat: p.as_ptr() as *mut u8,
            len: p.len(),
        })
        .collect();
    let mut c_tables = CSubTables {
        shift: [0; 256],
        index: [0; 257],
        min_match_len: 0,
        max_match_len: 0,
    };
    unsafe {
        c_ngx_http_sub_init_tables(
            &mut c_tables as *mut CSubTables,
            c_matches.as_mut_ptr(),
            c_matches.len(),
        );
    }
    let mut c_pos = 0usize;
    let mut c_idx = 0usize;
    let c_ok = unsafe {
        c_ngx_http_sub_find(
            text.as_ptr() as *mut u8,
            text.len(),
            c_matches.as_mut_ptr(),
            c_matches.len(),
            &c_tables as *const CSubTables,
            &mut c_pos,
            &mut c_idx,
        )
    };
    assert_eq!(rust_found.is_some(), c_ok != 0);
    if let Some((rp, ri)) = rust_found {
        assert_eq!(rp, c_pos);
        assert_eq!(ri, c_idx);
    }
}

#[test]
fn sub_filter_tables_and_find() {
    let mut matches = vec![
        SubMatch {
            pattern: b"nginx".to_vec(),
        },
        SubMatch {
            pattern: b"host".to_vec(),
        },
        SubMatch {
            pattern: b"http".to_vec(),
        },
    ];
    let tables = ngx_http_sub_init_tables(&mut matches).unwrap();
    let text = b"welcome to nginx http host nginx";
    let found = ngx_http_sub_find(text, &matches, &tables);
    assert!(found.is_some());
}

#[test]
fn hextoi_parity() {
    for s in [b"0".as_slice(), b"deadbeef", b"7FFFFFFF", b"DEADBEEF"] {
        assert_eq!(
            ngx_hextoi(s),
            unsafe { c_ngx_hextoi(s.as_ptr() as *mut u8, s.len()) },
            "s={s:?}"
        );
    }
    assert_eq!(ngx_hextoi(b""), NGX_PARSE_ERROR);
    assert_eq!(ngx_hextoi(b"12g"), NGX_PARSE_ERROR);
}

#[test]
fn encode_base64_parity() {
    for src in [b"".as_slice(), b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
        let mut rd = vec![0u8; (src.len() + 2) / 3 * 4 + 4];
        let mut cd = vec![0u8; rd.len()];
        let rw = ngx_encode_base64(&mut rd, src);
        let cw = unsafe {
            c_ngx_encode_base64(
                cd.as_mut_ptr(),
                src.as_ptr() as *mut u8,
                src.len(),
            )
        };
        assert_eq!(rw, cw, "src={src:?}");
        assert_eq!(&rd[..rw], &cd[..cw]);
    }
}

#[test]
fn decode_base64_parity() {
    for src in [
        b"Zm9v".as_slice(),
        b"Zm9vYg==",
        b"YQ==",
        b"YWI=",
    ] {
        let mut rd = vec![0u8; src.len()];
        let mut cd = vec![0u8; src.len()];
        let rw = ngx_decode_base64(&mut rd, src);
        let cw = unsafe {
            c_ngx_decode_base64(
                cd.as_mut_ptr(),
                src.as_ptr() as *mut u8,
                src.len(),
            )
        };
        assert_eq!(rw, cw, "src={src:?}");
        assert_eq!(&rd[..rw as usize], &cd[..cw as usize]);
    }
    assert_eq!(ngx_decode_base64(&mut [], b"Z==="), NGX_PARSE_ERROR);
}

#[test]
fn encode_base64url_parity() {
    for src in [b"".as_slice(), b"f", b"fo", b"foo"] {
        let mut rd = vec![0u8; (src.len() + 2) / 3 * 4 + 4];
        let mut cd = vec![0u8; rd.len()];
        let rw = ngx_encode_base64url(&mut rd, src);
        let cw = unsafe {
            c_ngx_encode_base64url(cd.as_mut_ptr(), src.as_ptr() as *mut u8, src.len())
        };
        assert_eq!(rw, cw, "src={src:?}");
        assert_eq!(&rd[..rw], &cd[..cw]);
    }
}

#[test]
fn decode_base64url_parity() {
    let src = b"Zm9v";
    let mut rd = vec![0u8; 8];
    let mut cd = vec![0u8; 8];
    let rw = ngx_decode_base64url(&mut rd, src);
    let cw = unsafe {
        c_ngx_decode_base64url(cd.as_mut_ptr(), src.as_ptr() as *mut u8, src.len())
    };
    assert_eq!(rw, cw);
    assert_eq!(&rd[..rw as usize], &cd[..cw as usize]);
}

#[test]
fn hex_dump_parity() {
    let src = b"\xde\xad\xbe\xef";
    let mut rd = vec![0u8; src.len() * 2];
    let mut cd = vec![0u8; src.len() * 2];
    let rw = ngx_hex_dump(&mut rd, src);
    let cw = unsafe { c_ngx_hex_dump(cd.as_mut_ptr(), src.as_ptr() as *mut u8, src.len()) };
    assert_eq!(rw, cw);
    assert_eq!(&rd[..rw], &cd[..cw]);
}

#[test]
fn chunked_header_parity() {
    for size in [0u64, 1, 15, 255, 4096, 65535, 1 << 20, 1 << 40] {
        let mut rb = [0u8; 22];
        let mut cb = [0u8; 22];
        let rw = ngx_http_chunked_header(&mut rb, size);
        let cw = unsafe { c_ngx_http_chunked_header(cb.as_mut_ptr(), size) };
        assert_eq!(rw, cw, "size={size}");
        assert_eq!(&rb[..rw], &cb[..cw]);
    }
}

#[test]
fn chunked_parse_parity() {
    let mut buf = Vec::new();
    let mut hdr = [0u8; 22];
    let sizes: Vec<u64> = (0..200u64)
        .map(|i| ((i.wrapping_mul(9973) + 1) % 65536) | 1)
        .collect();
    for &sz in &sizes {
        let n = ngx_http_chunked_header(&mut hdr, sz);
        buf.extend_from_slice(&hdr[..n]);
    }
    let (rc, sum) = ngx_http_chunked_parse_buffer(&buf).unwrap();
    let mut cc = 0usize;
    let mut cs = 0u64;
    assert_eq!(
        unsafe { c_ngx_http_chunked_parse_buffer(buf.as_ptr(), buf.len(), &mut cc, &mut cs) },
        0
    );
    assert_eq!(rc, cc);
    assert_eq!(sum, cs);
    for &sz in &sizes {
        let line = {
            let n = ngx_http_chunked_header(&mut hdr, sz);
            hdr[..n].to_vec()
        };
        let (rs, rn) = ngx_http_chunked_parse_line(&line).unwrap();
        let mut csz = 0u64;
        let mut cn = 0usize;
        assert_eq!(
            unsafe {
                c_ngx_http_chunked_parse_line(line.as_ptr(), line.len(), &mut csz, &mut cn)
            },
            0
        );
        assert_eq!(rs, csz);
        assert_eq!(rn, cn);
    }

    assert_eq!(
        ngx_http_chunked_parse_stream(&buf),
        ngx_http_chunked_parse_stream_fsm(&buf)
    );
    let (rs, stream_sum) = ngx_http_chunked_parse_stream(&buf).unwrap();
    let mut cs = 0usize;
    let mut csum = 0u64;
    assert_eq!(
        unsafe { c_ngx_http_chunked_parse_stream(buf.as_ptr(), buf.len(), &mut cs, &mut csum) },
        0
    );
    assert_eq!(rs, cs);
    assert_eq!(stream_sum, csum);
}

fn huff_decode_c(state: &mut u8, enc: &[u8], last: bool) -> (i32, Vec<u8>) {
    let mut buf = vec![0u8; 512];
    let mut dp = buf.as_mut_ptr();
    let rc = unsafe {
        c_ngx_http_huff_decode(
            state,
            enc.as_ptr() as *mut u8,
            enc.len(),
            &mut dp,
            u32::from(last),
        )
    };
    let n = dp as usize - buf.as_ptr() as usize;
    buf.truncate(n);
    (rc, buf)
}

fn huff_decode_rust(state: &mut u8, enc: &[u8], last: bool) -> (i32, Vec<u8>) {
    let mut buf = vec![0u8; 512];
    let mut dp = buf.as_mut_ptr();
    let rc = unsafe {
        ngx_http_huff_decode_ptr(state, enc.as_ptr(), enc.len(), &mut dp, last)
    };
    let n = dp as usize - buf.as_ptr() as usize;
    buf.truncate(n);
    (rc, buf)
}

#[test]
fn huff_decode_parity() {
    let enc = HUFF_WWW_EXAMPLE_ENC;
    let plain = HUFF_WWW_EXAMPLE_PLAIN;

    let mut cs = 0u8;
    let mut rs = 0u8;
    let (cr, cb) = huff_decode_c(&mut cs, enc, true);
    let (rr, rb) = huff_decode_rust(&mut rs, enc, true);
    assert_eq!(cr, rr, "rc");
    assert_eq!(cb, rb, "decoded bytes");
    assert_eq!(&cb[..], plain);

    let mid = enc.len() / 2;
    let mut cs = 0u8;
    let mut rs = 0u8;
    let (cr, cb) = huff_decode_c(&mut cs, &enc[..mid], false);
    let (rr, rb) = huff_decode_rust(&mut rs, &enc[..mid], false);
    assert_eq!(cr, rr);
    assert_eq!(cb, rb);

    let (cr2, cb2) = huff_decode_c(&mut cs, &enc[mid..], true);
    let (rr2, rb2) = huff_decode_rust(&mut rs, &enc[mid..], true);
    assert_eq!(cr2, rr2);
    assert_eq!(cb2, rb2);
    let mut full = cb;
    full.extend_from_slice(&cb2);
    assert_eq!(full, plain);
}

#[test]
#[test]
fn huff_encode_parity() {
    let plain = b"www.example.com";
    let mut re = vec![0u8; 64];
    let mut ce = vec![0u8; 64];
    let rw = ngx_http_huff_encode(&mut re, plain);
    let cw = unsafe { c_ngx_http_huff_encode(plain.as_ptr() as *mut u8, plain.len(), ce.as_mut_ptr()) };
    assert_eq!(rw, cw);
    assert_eq!(&re[..rw], &ce[..cw]);

    let mut rs = 0u8;
    let mut cs = 0u8;
    let mut dr = vec![0u8; 64];
    let mut dc = vec![0u8; 64];
    let mut dpr = dr.as_mut_ptr();
    let mut dpc = dc.as_mut_ptr();
    assert_eq!(
        unsafe {
            ngx_http_huff_decode_ptr(&mut rs, re.as_ptr(), rw, &mut dpr, true)
        },
        NGX_HUFF_OK
    );
    assert_eq!(
        unsafe {
            c_ngx_http_huff_decode(
                &mut cs,
                ce.as_ptr() as *mut u8,
                cw,
                &mut dpc,
                1,
            )
        },
        NGX_HUFF_OK
    );
    let nr = dpr as usize - dr.as_ptr() as usize;
    let nc = dpc as usize - dc.as_ptr() as usize;
    assert_eq!(nr, nc);
    assert_eq!(&dr[..nr], &dc[..nc]);
    assert_eq!(&dr[..nr], plain);
}

#[test]
fn v3_varlen_int_parity() {
    let values: &[u64] = &[
        0,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        0x3fff_ffff_ffff_ffff,
    ];
    let mut buf = [0u8; 8];
    let mut cv = 0u64;
    let mut rv = 0u64;
    for &v in values {
        let cw = unsafe { c_ngx_http_v3_encode_varlen_int(buf.as_mut_ptr(), v) };
        let rw = ngx_http_v3_encode_varlen_int(&mut buf, v);
        assert_eq!(cw, rw, "encode len v={v}");
        let cr = unsafe {
            c_ngx_http_v3_decode_varlen_int(buf.as_ptr(), cw, &mut cv)
        };
        let rr = ngx_http_v3_decode_varlen_int(&buf[..cw]);
        assert_eq!(cr, rr.map(|(_, n)| n as isize).unwrap_or(-1), "decode rc v={v}");
        assert_eq!(cv, v, "c decode v={v}");
        assert_eq!(rr.map(|x| x.0), Some(v), "rust decode v={v}");
    }
}

#[test]
fn v3_prefix_int_parity() {
    let cases: &[(u64, u32)] = &[(0, 8), (127, 8), (128, 8), (200, 8), (10_000, 8), (5, 5)];
    let mut buf = [0u8; 16];
    let mut cv = 0u64;
    for &(v, prefix) in cases {
        let cw = unsafe {
            c_ngx_http_v3_encode_prefix_int(buf.as_mut_ptr(), 0, v, prefix)
        };
        let rw = ngx_http_v3_encode_prefix_int(&mut buf, 0, v, prefix);
        assert_eq!(cw, rw, "encode v={v} prefix={prefix}");
        let cr = unsafe {
            c_ngx_http_v3_decode_prefix_int(buf.as_ptr(), cw, prefix, &mut cv)
        };
        let rr = ngx_http_v3_decode_prefix_int(&buf[..cw], prefix);
        assert_eq!(cr, rr.map(|(_, n)| n as isize).unwrap_or(-1));
        assert_eq!(cv, v);
        assert_eq!(rr.map(|x| x.0), Some(v));
    }
}

fn proxy_v2_inet_fixture() -> [u8; 28] {
    [
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
        0x00, 0x0c, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x30, 0x39, 0x00, 0x50,
    ]
}

#[test]
fn proxy_protocol_v2_inet_parity() {
    let buf = proxy_v2_inet_fixture();
    let mut cr = CProxyV2Inet {
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
    };
    let mut rr = ProxyV2Inet {
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
    };
    let rc = unsafe { c_ngx_proxy_protocol_v2_parse_inet(buf.as_ptr(), buf.len(), &mut cr) };
    let rr_rc = ngx_proxy_protocol_v2_parse_inet(&buf, &mut rr);
    assert_eq!(rc, rr_rc);
    assert_eq!(rc, 0);
    assert_eq!(cr.src_addr, rr.src_addr);
    assert_eq!(cr.dst_addr, rr.dst_addr);
    assert_eq!(cr.src_port, rr.src_port);
    assert_eq!(cr.dst_port, rr.dst_port);
    assert_eq!(rr.src_addr, u32::from_ne_bytes([10, 0, 0, 1]));
    assert_eq!(rr.dst_addr, u32::from_ne_bytes([10, 0, 0, 2]));
    assert_eq!(rr.src_port, 12345);
    assert_eq!(rr.dst_port, 80);
}

const CONF_SCAN_SAMPLE: &[u8] = b"\
worker_processes auto;\n\
# main context\n\
events {\n\
    worker_connections 1024;\n\
}\n\
http {\n\
    server {\n\
        listen 80;\n\
        location / {\n\
            proxy_pass \"http://127.0.0.1:8080\";\n\
        }\n\
    }\n\
}\n";

const PROXY_V1_LINE: &[u8] = b"PROXY TCP4 10.0.0.1 10.0.0.2 12345 80\r\n";

#[test]
fn http_v2_frame_header_parity() {
    let frames: &[[u8; 9]] = &[
        [0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x03],
        [0x00, 0x01, 0x00, 0x01, 0x05, 0x7f, 0xff, 0xff, 0xff],
    ];
    for hdr in frames {
        let mut cr = CH2FrameHdr {
            length: 0,
            frame_type: 0,
            flags: 0,
            sid: 0,
        };
        let mut rr = HttpV2FrameHeader::default();
        unsafe { c_ngx_http_v2_parse_frame_header(hdr.as_ptr(), &mut cr) };
        ngx_http_v2_parse_frame_header(hdr, &mut rr);
        assert_eq!(cr.length, rr.length);
        assert_eq!(cr.frame_type, rr.frame_type);
        assert_eq!(cr.flags, rr.flags);
        assert_eq!(cr.sid, rr.sid);
    }
}

#[test]
fn conf_scan_tokens_parity() {
    let mut big = Vec::new();
    while big.len() < 64 * 1024 {
        big.extend_from_slice(CONF_SCAN_SAMPLE);
    }
    let cr = unsafe { c_ngx_conf_scan_tokens(big.as_ptr(), big.len()) };
    let rr = ngx_conf_scan_tokens(&big);
    assert_eq!(cr, rr);
    assert!(rr > 1000);
}

#[test]
fn proxy_protocol_v1_inet_parity() {
    let mut cr = CProxyV2Inet {
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
    };
    let mut rr = ProxyV2Inet {
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
    };
    let rc = unsafe {
        c_ngx_proxy_protocol_v1_parse_inet(
            PROXY_V1_LINE.as_ptr(),
            PROXY_V1_LINE.len(),
            &mut cr,
        )
    };
    let rr_rc = ngx_proxy_protocol_v1_parse_inet(PROXY_V1_LINE, &mut rr);
    assert_eq!(rc, rr_rc);
    assert_eq!(rc, 0);
    assert_eq!(cr.src_addr, rr.src_addr);
    assert_eq!(cr.dst_addr, rr.dst_addr);
    assert_eq!(cr.src_port, rr.src_port);
    assert_eq!(cr.dst_port, rr.dst_port);
}
