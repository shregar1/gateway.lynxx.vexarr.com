//! Rust (optimized) vs compiled NGINX C extracts.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

extern "C" {
    fn c_ngx_murmur_hash2(data: *mut u8, len: usize) -> u32;
    fn c_ngx_crc32_long(p: *mut u8, len: usize) -> u32;
    fn c_ngx_crc32_short(p: *mut u8, len: usize) -> u32;
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
    fn c_ngx_sort_u32(base: *mut u32, n: usize);
    fn c_ngx_hash_key_lc(data: *mut u8, len: usize) -> usize;
    fn c_ngx_split_clients_pick(hash: u32, cuts: *const u32, n: usize) -> usize;
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
}

fn u32_cmp(a: &u32, b: &u32) -> i32 {
    if *a < *b {
        -1
    } else if *a > *b {
        1
    } else {
        0
    }
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

use lynxx_algo::{ngx_sort, ngx_sort_legacy, RadixTree32, *};
use std::sync::OnceLock;

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(17) ^ 0x5A) as u8).collect()
}

/// No embedded NUL — full-length scan (worst case for `ngx_strnstr`).
fn data_no_nul(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i.wrapping_mul(17) ^ 0x5A) as u8 | 1))
        .collect()
}

fn bench_murmur_vs_c(c: &mut Criterion) {
    let d = data(65536);
    let mut g = c.benchmark_group("murmur2_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| {
            let p = black_box(d.as_ptr());
            black_box(ngx_murmur_hash2_ptr(p, d.len()))
        });
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_murmur_hash2(
                black_box(d.as_ptr()) as *mut u8,
                d.len(),
            ))
        });
    });
    g.finish();
}

fn bench_crc32_long_vs_c(c: &mut Criterion) {
    let d = data(65536);
    let mut g = c.benchmark_group("crc32_long_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust_crc32fast", |b| {
        b.iter(|| black_box(ngx_crc32_long(black_box(&d))));
    });
    g.bench_function("rust_table", |b| {
        b.iter(|| black_box(ngx_crc32_long_table(black_box(&d))));
    });
    g.bench_function("nginx_c_table", |b| {
        b.iter(|| unsafe { black_box(c_ngx_crc32_long(d.as_ptr() as *mut u8, d.len())) });
    });
    g.finish();
}

fn bench_crc32_short_vs_c(c: &mut Criterion) {
    let d = data(48);
    let mut g = c.benchmark_group("crc32_short_48");
    g.throughput(Throughput::Bytes(48));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_crc32_short(black_box(&d))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_crc32_short(d.as_ptr() as *mut u8, d.len())) });
    });
    g.finish();
}

fn bench_hash_vs_c(c: &mut Criterion) {
    let d = data(2048);
    let mut g = c.benchmark_group("hash_key_2k");
    g.throughput(Throughput::Bytes(2048));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_hash_key(black_box(&d))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_hash_key(d.as_ptr() as *mut u8, d.len())) });
    });
    g.finish();
}

fn bench_strnstr_vs_c(c: &mut Criterion) {
    let hay = data(65536);
    let needle = std::ffi::CString::new("Host:").unwrap();
    let mut g = c.benchmark_group("strnstr_64k_nul_early");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_strnstr(black_box(&hay), "Host:")));
    });
    g.bench_function("nginx_c", |b| {
        let mut buf = hay.clone();
        b.iter(|| unsafe {
            black_box(c_ngx_strnstr(
                buf.as_mut_ptr(),
                needle.as_ptr(),
                hay.len(),
            ))
        });
    });
    g.finish();

    let hay_full = data_no_nul(65536);
    static NEEDLE: &[u8] = b"ZZZZZZZZ";
    let miss = std::ffi::CString::new("ZZZZZZZZ").unwrap();
    let mut g = c.benchmark_group("strnstr_64k_no_nul_miss");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_strnstr_bytes(black_box(&hay_full), NEEDLE)));
    });
    g.bench_function("nginx_c", |b| {
        let mut buf = hay_full.clone();
        b.iter(|| unsafe {
            black_box(c_ngx_strnstr(
                buf.as_mut_ptr(),
                miss.as_ptr(),
                hay_full.len(),
            ))
        });
    });
    g.finish();
}

fn bench_limit_req_vs_c(c: &mut Criterion) {
    let mut g = c.benchmark_group("limit_req_excess");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_limit_req_excess(1500, 1000, 10_000, 9_200)));
    });
    g.bench_function("nginx_c", |b| {
        let mut out = 0i32;
        b.iter(|| unsafe {
            black_box(c_ngx_limit_req_excess(1500, 1000, 10_000, 9_200, &mut out))
        });
    });
    g.finish();
}

fn bench_ip_hash_vs_c(c: &mut Criterion) {
    let addr = [192u8, 168, 1, 42];
    let mut g = c.benchmark_group("ip_hash_mix_v4");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_ip_hash_mix(black_box(&addr), 0)));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_ip_hash_mix(
                addr.as_ptr() as *mut u8,
                addr.len(),
                0,
            ))
        });
    });
    g.finish();
}

fn bench_rbtree_vs_c(c: &mut Criterion) {
    let pairs = [(100u32, 200u32), (0xffff_fff0, 10u32), (10, 0xffff_fff0)];
    let mut g = c.benchmark_group("rbtree_timer_less");
    for (a, b) in pairs {
        g.bench_with_input(BenchmarkId::new("rust", format!("{a}_{b}")), &(a, b), |ben, (a, b)| {
            ben.iter(|| black_box(ngx_rbtree_timer_less(*a, *b)));
        });
        g.bench_with_input(BenchmarkId::new("nginx_c", format!("{a}_{b}")), &(a, b), |ben, (a, b)| {
            ben.iter(|| unsafe { black_box(c_ngx_rbtree_timer_less(*a, *b) != 0) });
        });
    }
    g.finish();
}

fn bench_sub_filter_vs_c(c: &mut Criterion) {
    let text = data(65536);
    let pats: Vec<Vec<u8>> = vec![
        b"nginx".to_vec(),
        b"configuration".to_vec(),
        b"upstream".to_vec(),
    ];
    let mut rust_matches: Vec<SubMatch> = pats.iter().map(|p| SubMatch::new(p.clone())).collect();
    let rust_tables = ngx_http_sub_init_tables(&mut rust_matches).unwrap();

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
    let mut g = c.benchmark_group("sub_filter_find_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_http_sub_find(black_box(&text), &rust_matches, &rust_tables)));
    });
    g.bench_function("nginx_c", |b| {
        let mut buf = text.clone();
        b.iter(|| unsafe {
            black_box(c_ngx_http_sub_find(
                buf.as_mut_ptr(),
                buf.len(),
                c_matches.as_mut_ptr(),
                c_matches.len(),
                &c_tables as *const CSubTables,
                &mut c_pos,
                &mut c_idx,
            ))
        });
    });
    g.finish();
}

fn utf8_mixed(len: usize) -> Vec<u8> {
    let unit: [u8; 3] = [0xe4, 0xb8, 0xad]; // U+4E2D
    let mut v = Vec::with_capacity(len);
    while v.len() + 3 <= len {
        v.extend_from_slice(&unit);
    }
    v.extend(std::iter::repeat(0x61u8).take(len - v.len()));
    v
}

/// Mostly-safe URI bytes with periodic spaces (must escape).
fn uri_like(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| if i % 32 == 0 { b' ' } else { b'a' + (i % 26) as u8 })
        .collect()
}

fn bench_inet_addr_vs_c(c: &mut Criterion) {
    let ip = b"203.0.113.42";
    let mut g = c.benchmark_group("inet_addr_v4");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_inet_addr(ip)));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_inet_addr(ip.as_ptr() as *mut u8, ip.len())) });
    });
    g.finish();
}

fn bench_inet6_addr_vs_c(c: &mut Criterion) {
    let ip = b"2001:db8::ffff:192.0.2.1";
    let mut out_r = [0u8; 16];
    let mut out_c = [0u8; 16];
    let mut g = c.benchmark_group("inet6_addr_parse");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_inet6_addr(black_box(ip), black_box(&mut out_r))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_inet6_addr(
                ip.as_ptr() as *mut u8,
                ip.len(),
                out_c.as_mut_ptr(),
            ))
        })
    });
    g.finish();
}

fn pct_like(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len + len / 16);
    for i in 0..len {
        if i % 32 == 0 {
            v.extend_from_slice(b"%20");
        } else {
            v.push(b'a' + (i % 26) as u8);
        }
    }
    v
}

fn bench_escape_uri_encode_vs_c(c: &mut Criterion) {
    let src = uri_like(65536);
    let mut dst_r = vec![0u8; src.len() * 3];
    let mut dst_c = vec![0u8; src.len() * 3];
    let mut g = c.benchmark_group("escape_uri_encode_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_escape_uri(&mut dst_r, &src)));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(
                c_ngx_escape_uri(dst_c.as_mut_ptr(), src.as_ptr() as *mut u8, src.len()) as usize
                    - dst_c.as_ptr() as usize,
            )
        });
    });
    g.finish();
}

fn bench_unescape_uri_vs_c(c: &mut Criterion) {
    let src = pct_like(49152);
    let mut dst_r = vec![0u8; src.len()];
    let mut dst_c = vec![0u8; src.len()];
    let mut g = c.benchmark_group("unescape_uri_48k");
    g.throughput(Throughput::Bytes(src.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_unescape_uri(&mut dst_r, black_box(&src), true)));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| {
            let mut dp = dst_c.as_mut_ptr();
            let mut sp = src.as_ptr() as *mut u8;
            unsafe {
                c_ngx_unescape_uri(&mut dp, &mut sp, src.len(), NGX_UNESCAPE_URI);
                black_box(dp as usize - dst_c.as_ptr() as usize)
            }
        });
    });
    g.finish();
}

fn geo_bench_tree() -> &'static RadixTree32 {
    static TREE: OnceLock<RadixTree32> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut t = RadixTree32::new();
        t.preallocate();
        t.insert(0x0b000000, 0xff000000, 1);
        t.insert(0x7f000000, 0xff000000, 2);
        t.insert(0xc0a80100, 0xffffff00, 3);
        t.insert(0xcb007100, 0xfffffff0, 4);
        t
    })
}

fn bench_radix32_find_vs_c(c: &mut Criterion) {
    let tree = geo_bench_tree();
    const KEY: u32 = 0x0b010203;
    unsafe { c_radix_bench_tree_init() };
    let mut g = c.benchmark_group("radix32_find_geo");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(tree.find(black_box(KEY))))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| black_box(unsafe { c_radix_bench_find(KEY) }))
    });
    g.finish();
}

fn bench_parse_size_vs_c(c: &mut Criterion) {
    let s = b"10m";
    let mut g = c.benchmark_group("parse_size_10m");
    g.bench_function("rust", |b| b.iter(|| black_box(ngx_parse_size(black_box(s)))));
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_parse_size(s.as_ptr() as *mut u8, s.len())) })
    });
    g.finish();
}

fn bench_atoi_vs_c(c: &mut Criterion) {
    let s = b"1048576";
    let mut g = c.benchmark_group("atoi_7");
    g.bench_function("rust", |b| b.iter(|| black_box(ngx_atoi(black_box(s)))));
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_atoi(s.as_ptr() as *mut u8, s.len())) })
    });
    g.finish();
}

fn bench_parse_time_vs_c(c: &mut Criterion) {
    let s = b"30s";
    let mut g = c.benchmark_group("parse_time_30s");
    g.bench_function("rust", |b| b.iter(|| black_box(ngx_parse_time(black_box(s), true))));
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_parse_time(s.as_ptr() as *mut u8, s.len(), 1) as isize)
        })
    });
    g.finish();
}

fn bench_escape_uri_component_count_vs_c(c: &mut Criterion) {
    let d = uri_like(65536);
    let mut g = c.benchmark_group("escape_uri_component_count_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_escape_uri_component_count(black_box(&d))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_escape_uri_component_count(
                d.as_ptr() as *mut u8,
                d.len(),
            ))
        });
    });
    g.finish();
}

fn bench_escape_args_count_vs_c(c: &mut Criterion) {
    let d = uri_like(65536);
    let mut g = c.benchmark_group("escape_args_count_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_escape_args_count(black_box(&d))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_escape_args_count(d.as_ptr() as *mut u8, d.len()))
        });
    });
    g.finish();
}

fn bench_atosz_vs_c(c: &mut Criterion) {
    let s = b"1048576";
    let mut g = c.benchmark_group("atosz_7");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_atosz(black_box(s))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_atosz(s.as_ptr() as *mut u8, s.len())) });
    });
    g.finish();
}

fn bench_escape_uri_count_vs_c(c: &mut Criterion) {
    let d = uri_like(65536);
    let mut g = c.benchmark_group("escape_uri_count_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_escape_uri_count(black_box(&d))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_escape_uri_count(d.as_ptr() as *mut u8, d.len()))
        });
    });
    g.finish();
}

fn bench_utf8_scan_vs_c(c: &mut Criterion) {
    let d = utf8_mixed(65536);
    let mut g = c.benchmark_group("utf8_decode_scan_64k");
    g.throughput(Throughput::Bytes(65536));
    g.bench_function("rust", |b| {
        b.iter(|| unsafe { black_box(ngx_utf8_decode_scan(black_box(&d))) });
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_utf8_decode_scan(
                d.as_ptr() as *mut u8,
                d.len(),
            ))
        });
    });
    g.finish();
}

fn bench_hash_key_lc_vs_c(c: &mut Criterion) {
    let d = data(2048);
    let mut g = c.benchmark_group("hash_key_lc_2k");
    g.throughput(Throughput::Bytes(2048));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_hash_key_lc(black_box(&d))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_hash_key_lc(d.as_ptr() as *mut u8, d.len())) });
    });
    g.finish();
}

fn bench_split_clients_vs_c(c: &mut Criterion) {
    // Cumulative cut points (NGINX build-time normalized percents).
    let cuts: Vec<u32> = vec![
        0x1400_0000, 0x2800_0000, 0x3c00_0000, 0x5000_0000, 0x6400_0000, 0x7800_0000,
        0x8c00_0000, 0xffff_ffff,
    ];
    let hash = ngx_murmur_hash2(b"203.0.113.42:8080");
    let mut g = c.benchmark_group("split_clients_pick");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_split_clients_pick(black_box(hash), black_box(&cuts))));
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_split_clients_pick(
                hash,
                cuts.as_ptr(),
                cuts.len(),
            ))
        });
    });
    g.finish();
}

fn bench_hextoi_vs_c(c: &mut Criterion) {
    let s = b"deadbeefcafe";
    let mut g = c.benchmark_group("hextoi_12");
    g.bench_function("rust", |b| b.iter(|| black_box(ngx_hextoi(black_box(s)))));
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe { black_box(c_ngx_hextoi(s.as_ptr() as *mut u8, s.len())) })
    });
    g.finish();
}

fn bench_encode_base64_vs_c(c: &mut Criterion) {
    let src: Vec<u8> = (0..48_000u32).map(|i| (i % 256) as u8).collect();
    let mut dst_r = vec![0u8; (src.len() + 2) / 3 * 4 + 4];
    let mut dst_c = vec![0u8; dst_r.len()];
    let mut g = c.benchmark_group("encode_base64_48k");
    g.throughput(Throughput::Bytes(src.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_encode_base64(&mut dst_r, &src)))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_encode_base64(
                dst_c.as_mut_ptr(),
                src.as_ptr() as *mut u8,
                src.len(),
            ))
        })
    });
    g.finish();
}

fn bench_decode_base64_vs_c(c: &mut Criterion) {
    let mut raw = vec![0u8; 36_000];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    let mut enc = vec![0u8; (raw.len() + 2) / 3 * 4 + 4];
    let elen = ngx_encode_base64(&mut enc, &raw);
    let enc = &enc[..elen];
    let mut dst_r = vec![0u8; raw.len() + 4];
    let mut dst_c = vec![0u8; raw.len() + 4];
    let mut g = c.benchmark_group("decode_base64_48k");
    g.throughput(Throughput::Bytes(enc.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_decode_base64(&mut dst_r, enc)))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_decode_base64(
                dst_c.as_mut_ptr(),
                enc.as_ptr() as *mut u8,
                enc.len(),
            ))
        })
    });
    g.finish();
}

fn bench_decode_base64url_vs_c(c: &mut Criterion) {
    let mut raw = vec![0u8; 36_000];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    let mut enc = vec![0u8; (raw.len() + 2) / 3 * 4 + 4];
    let elen = ngx_encode_base64url(&mut enc, &raw);
    let enc = &enc[..elen];
    let mut dst_r = vec![0u8; raw.len() + 4];
    let mut dst_c = vec![0u8; raw.len() + 4];
    let mut g = c.benchmark_group("decode_base64url_48k");
    g.throughput(Throughput::Bytes(enc.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_decode_base64url(&mut dst_r, enc)))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_decode_base64url(
                dst_c.as_mut_ptr(),
                enc.as_ptr() as *mut u8,
                enc.len(),
            ))
        })
    });
    g.finish();
}

fn bench_encode_base64url_vs_c(c: &mut Criterion) {
    let src: Vec<u8> = (0..48_000u32).map(|i| (i % 256) as u8).collect();
    let mut dst_r = vec![0u8; (src.len() + 2) / 3 * 4 + 4];
    let mut dst_c = vec![0u8; dst_r.len()];
    let mut g = c.benchmark_group("encode_base64url_48k");
    g.throughput(Throughput::Bytes(src.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_encode_base64url(&mut dst_r, &src)))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_encode_base64url(
                dst_c.as_mut_ptr(),
                src.as_ptr() as *mut u8,
                src.len(),
            ))
        })
    });
    g.finish();
}

fn huff_bench_payload() -> Vec<u8> {
    let unit = HUFF_WWW_EXAMPLE_ENC;
    let reps = 64 * 1024 / unit.len().max(1) + 1;
    unit.iter().copied().cycle().take(64 * 1024).collect()
}

fn proxy_v2_inet_fixture() -> [u8; 28] {
    [
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
        0x00, 0x0c, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x30, 0x39, 0x00, 0x50,
    ]
}

fn conf_scan_payload() -> Vec<u8> {
    const SAMPLE: &[u8] = b"\
worker_processes auto;\n\
events { worker_connections 1024; }\n\
http { server { listen 80; root /var/www; } }\n";
    SAMPLE.iter().copied().cycle().take(64 * 1024).collect()
}

fn h2_frame_payload() -> Vec<u8> {
    const FRAME: [u8; 9] = [0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07];
    FRAME
        .iter()
        .copied()
        .cycle()
        .take(64 * 1024)
        .collect()
}

fn bench_http_v2_frame_header_vs_c(c: &mut Criterion) {
    let buf = h2_frame_payload();
    let mut g = c.benchmark_group("http_v2_frame_header_64k");
    g.throughput(Throughput::Bytes(64 * 1024));
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            let mut out = HttpV2FrameHeader::default();
            let mut i = 0usize;
            while i + 9 <= buf.len() {
                unsafe {
                    ngx_http_v2_parse_frame_header_ptr(buf.as_ptr().add(i), &mut out);
                }
                sum = sum
                    .wrapping_add(out.length as u64)
                    .wrapping_add(out.sid as u64);
                i += 9;
            }
            black_box(sum)
        })
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            let mut out = CH2FrameHdr {
                length: 0,
                frame_type: 0,
                flags: 0,
                sid: 0,
            };
            let mut i = 0usize;
            while i + 9 <= buf.len() {
                unsafe {
                    c_ngx_http_v2_parse_frame_header(buf.as_ptr().add(i), &mut out);
                }
                sum = sum
                    .wrapping_add(out.length as u64)
                    .wrapping_add(out.sid as u64);
                i += 9;
            }
            black_box(sum)
        })
    });
    g.finish();
}

fn bench_conf_scan_vs_c(c: &mut Criterion) {
    let buf = conf_scan_payload();
    let mut g = c.benchmark_group("conf_scan_tokens_64k");
    g.throughput(Throughput::Bytes(64 * 1024));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_conf_scan_tokens(black_box(&buf))))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_conf_scan_tokens(buf.as_ptr(), buf.len()))
        })
    });
    g.finish();
}

fn bench_proxy_v1_inet_vs_c(c: &mut Criterion) {
    const LINE: &[u8] = b"PROXY TCP4 10.0.0.1 10.0.0.2 12345 80\r\n";
    let mut g = c.benchmark_group("proxy_v1_inet_parse");
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            let mut o = ProxyV2Inet {
                src_addr: 0,
                dst_addr: 0,
                src_port: 0,
                dst_port: 0,
            };
            for _ in 0..65536 {
                sum += ngx_proxy_protocol_v1_parse_inet(black_box(LINE), black_box(&mut o)) as u64;
                sum = sum.wrapping_add(o.src_addr as u64).wrapping_add(o.dst_port as u64);
            }
            black_box(sum)
        })
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            let mut o = CProxyV2Inet {
                src_addr: 0,
                dst_addr: 0,
                src_port: 0,
                dst_port: 0,
            };
            for _ in 0..65536 {
                sum += unsafe {
                    c_ngx_proxy_protocol_v1_parse_inet(LINE.as_ptr(), LINE.len(), &mut o)
                } as u64;
                sum = sum.wrapping_add(o.src_addr as u64).wrapping_add(o.dst_port as u64);
            }
            black_box(sum)
        })
    });
    g.finish();
}

fn bench_proxy_v2_inet_vs_c(c: &mut Criterion) {
    let buf = proxy_v2_inet_fixture();
    let mut out_r = ProxyV2Inet {
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
    };
    let mut out_c = CProxyV2Inet {
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
    };
    let mut g = c.benchmark_group("proxy_v2_inet_parse");
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            let mut o = ProxyV2Inet {
                src_addr: 0,
                dst_addr: 0,
                src_port: 0,
                dst_port: 0,
            };
            for _ in 0..65536 {
                sum += ngx_proxy_protocol_v2_parse_inet(black_box(&buf), &mut o) as u64;
                sum = sum.wrapping_add(o.src_addr as u64).wrapping_add(o.dst_port as u64);
            }
            black_box(sum)
        })
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            let mut o = CProxyV2Inet {
                src_addr: 0,
                dst_addr: 0,
                src_port: 0,
                dst_port: 0,
            };
            for _ in 0..65536 {
                sum += unsafe {
                    c_ngx_proxy_protocol_v2_parse_inet(
                        buf.as_ptr(),
                        buf.len(),
                        &mut o,
                    )
                } as u64;
                sum = sum.wrapping_add(o.src_addr as u64).wrapping_add(o.dst_port as u64);
            }
            black_box(sum)
        })
    });
    g.finish();
}

fn bench_huff_encode_vs_c(c: &mut Criterion) {
    let plain: Vec<u8> = HUFF_WWW_EXAMPLE_PLAIN
        .iter()
        .copied()
        .cycle()
        .take(64 * 1024)
        .collect();
    let mut dst_r = vec![0u8; plain.len() + plain.len() / 2];
    let mut dst_c = vec![0u8; dst_r.len()];
    let mut g = c.benchmark_group("huff_encode_64k");
    g.throughput(Throughput::Bytes(64 * 1024));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_http_huff_encode(black_box(&mut dst_r), black_box(&plain))))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_http_huff_encode(
                plain.as_ptr() as *mut u8,
                plain.len(),
                dst_c.as_mut_ptr(),
            ))
        })
    });
    g.finish();
}

fn bench_huff_decode_vs_c(c: &mut Criterion) {
    let src = huff_bench_payload();
    let mut dst_r = vec![0u8; 128 * 1024];
    let mut dst_c = vec![0u8; 128 * 1024];
    let mut g = c.benchmark_group("huff_decode_64k");
    g.throughput(Throughput::Bytes(64 * 1024));
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut st = 0u8;
            let mut dp = dst_r.as_mut_ptr();
            let start = dp;
            let rc = unsafe {
                ngx_http_huff_decode_ptr(
                    &mut st,
                    src.as_ptr(),
                    src.len(),
                    &mut dp,
                    false,
                )
            };
            black_box((rc, unsafe { dp.offset_from(start) }))
        });
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            let mut st = 0u8;
            let mut dp = dst_c.as_mut_ptr();
            let start = dp;
            let rc = c_ngx_http_huff_decode(
                &mut st,
                src.as_ptr() as *mut u8,
                src.len(),
                &mut dp,
                0,
            );
            black_box((rc, dp.offset_from(start)))
        });
    });
    g.finish();
}

fn bench_v3_prefix_encode_vs_c(c: &mut Criterion) {
    let mut buf = [0u8; 16];
    let mut g = c.benchmark_group("v3_prefix_encode_4k");
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0u64..4096 {
                sum += ngx_http_v3_encode_prefix_int(&mut buf, 0, black_box(i), 8);
            }
            black_box(sum)
        });
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            let mut sum = 0usize;
            for i in 0u64..4096 {
                sum += c_ngx_http_v3_encode_prefix_int(buf.as_mut_ptr(), 0, i, 8);
            }
            black_box(sum)
        });
    });
    g.finish();
}

fn bench_v3_prefix_decode_vs_c(c: &mut Criterion) {
    let mut enc = Vec::new();
    let mut tmp = [0u8; 16];
    for i in 0u64..4096 {
        let n = ngx_http_v3_encode_prefix_int(&mut tmp, 0, i, 8);
        enc.extend_from_slice(&tmp[..n]);
    }
    let mut val = 0u64;
    let mut g = c.benchmark_group("v3_prefix_decode_4k");
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut pos = 0usize;
            let mut sum = 0u64;
            while pos < enc.len() {
                let (v, n) = unsafe {
                    ngx_http_v3_decode_prefix_int_ptr(enc.as_ptr().add(pos), enc.len() - pos, 8)
                }
                .unwrap();
                sum = sum.wrapping_add(v);
                pos += n;
            }
            black_box(sum)
        });
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            let mut pos = 0usize;
            let mut sum = 0u64;
            while pos < enc.len() {
                let n = c_ngx_http_v3_decode_prefix_int(
                    enc.as_ptr().add(pos),
                    enc.len() - pos,
                    8,
                    &mut val,
                );
                sum = sum.wrapping_add(val);
                pos += n as usize;
            }
            black_box(sum)
        });
    });
    g.finish();
}

fn bench_v3_varlen_encode_vs_c(c: &mut Criterion) {
    let mut buf = [0u8; 8];
    let mut g = c.benchmark_group("v3_varlen_encode_4k");
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0u64..4096 {
                sum += ngx_http_v3_encode_varlen_int(&mut buf, black_box(i));
            }
            black_box(sum)
        });
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            let mut sum = 0usize;
            for i in 0u64..4096 {
                sum += c_ngx_http_v3_encode_varlen_int(buf.as_mut_ptr(), i);
            }
            black_box(sum)
        });
    });
    g.finish();
}

fn bench_v3_varlen_decode_vs_c(c: &mut Criterion) {
    let mut enc = Vec::with_capacity(16_384);
    let mut tmp = [0u8; 8];
    for i in 0u64..4096 {
        let n = ngx_http_v3_encode_varlen_int(&mut tmp, i);
        enc.extend_from_slice(&tmp[..n]);
    }
    let mut val = 0u64;
    let mut g = c.benchmark_group("v3_varlen_decode_4k");
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut pos = 0usize;
            let mut sum = 0u64;
            while pos < enc.len() {
                let (v, n) = ngx_http_v3_decode_varlen_int(black_box(&enc[pos..])).unwrap();
                sum = sum.wrapping_add(v);
                pos += n;
            }
            black_box(sum)
        });
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            let mut pos = 0usize;
            let mut sum = 0u64;
            while pos < enc.len() {
                let n = c_ngx_http_v3_decode_varlen_int(
                    enc.as_ptr().add(pos),
                    enc.len() - pos,
                    &mut val,
                );
                sum = sum.wrapping_add(val);
                pos += n as usize;
            }
            black_box(sum)
        });
    });
    g.finish();
}

fn bench_hex_dump_vs_c(c: &mut Criterion) {
    let src: Vec<u8> = (0..16_384u32).map(|i| (i % 256) as u8).collect();
    let mut dst_r = vec![0u8; src.len() * 2];
    let mut dst_c = vec![0u8; src.len() * 2];
    let mut g = c.benchmark_group("hex_dump_16k");
    g.throughput(Throughput::Bytes(src.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_hex_dump(&mut dst_r, black_box(&src))))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| unsafe {
            black_box(c_ngx_hex_dump(
                dst_c.as_mut_ptr(),
                src.as_ptr() as *mut u8,
                src.len(),
            ))
        })
    });
    g.finish();
}

fn chunked_lines_payload() -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut hdr = [0u8; 22];
    while buf.len() < 64 * 1024 {
        let sz = ((buf.len().wrapping_mul(9973) + 1) as u64) % 65536 | 1;
        let n = ngx_http_chunked_header(&mut hdr, sz);
        buf.extend_from_slice(&hdr[..n]);
    }
    buf
}

fn bench_chunked_parse_vs_c(c: &mut Criterion) {
    let buf = chunked_lines_payload();
    let mut g = c.benchmark_group("chunked_parse_64k");
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_http_chunked_parse_buffer(&buf).unwrap()))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| {
            let mut count = 0usize;
            let mut sum = 0u64;
            let rc = unsafe {
                c_ngx_http_chunked_parse_buffer(buf.as_ptr(), buf.len(), &mut count, &mut sum)
            };
            black_box((rc, count, sum))
        })
    });
    g.finish();
}

fn bench_chunked_stream_vs_c(c: &mut Criterion) {
    let buf = chunked_lines_payload();
    let mut g = c.benchmark_group("chunked_stream_64k");
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function("rust", |b| {
        b.iter(|| black_box(ngx_http_chunked_parse_stream(black_box(&buf)).unwrap()))
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| {
            let mut count = 0usize;
            let mut sum = 0u64;
            let rc = unsafe {
                c_ngx_http_chunked_parse_stream(buf.as_ptr(), buf.len(), &mut count, &mut sum)
            };
            black_box((rc, count, sum))
        })
    });
    g.finish();
}

fn bench_chunked_header_vs_c(c: &mut Criterion) {
    const N: usize = 64 * 1024;
    let sizes: Vec<u64> = (0..N)
        .map(|i| ((i.wrapping_mul(9973) + 1) as u64) % 65536 | 1)
        .collect();
    let mut buf_r = [0u8; 22];
    let mut buf_c = [0u8; 22];
    let mut g = c.benchmark_group("chunked_header_64k");
    g.bench_function("rust", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for &sz in &sizes {
                sum += ngx_http_chunked_header(&mut buf_r, sz);
            }
            black_box(sum)
        })
    });
    g.bench_function("nginx_c", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for &sz in &sizes {
                sum += unsafe { c_ngx_http_chunked_header(buf_c.as_mut_ptr(), sz) };
            }
            black_box(sum)
        })
    });
    g.finish();
}

fn bench_sort_vs_c(c: &mut Criterion) {
    let data: Vec<u32> = (0..10_000).map(|i| (i * 7919) % 10_007).collect();
    let mut g = c.benchmark_group("sort_u32_10k");
    g.bench_function("rust_ngx_sort", |b| {
        b.iter(|| {
            let mut v = black_box(data.clone());
            ngx_sort(&mut v, u32_cmp);
            black_box(v)
        });
    });
    g.bench_function("rust_insertion", |b| {
        b.iter(|| {
            let mut v = black_box(data.clone());
            ngx_sort_legacy(&mut v, u32_cmp);
            black_box(v)
        });
    });
    g.bench_function("nginx_c_insertion", |b| {
        b.iter(|| {
            let mut v = black_box(data.clone());
            unsafe {
                c_ngx_sort_u32(v.as_mut_ptr(), v.len());
            }
            black_box(v)
        });
    });
    g.finish();
}

criterion_group!(
    vs_c,
    bench_murmur_vs_c,
    bench_crc32_long_vs_c,
    bench_crc32_short_vs_c,
    bench_hash_vs_c,
    bench_hash_key_lc_vs_c,
    bench_escape_uri_count_vs_c,
    bench_escape_uri_encode_vs_c,
    bench_unescape_uri_vs_c,
    bench_atosz_vs_c,
    bench_atoi_vs_c,
    bench_parse_size_vs_c,
    bench_parse_time_vs_c,
    bench_escape_args_count_vs_c,
    bench_escape_uri_component_count_vs_c,
    bench_radix32_find_vs_c,
    bench_inet_addr_vs_c,
    bench_inet6_addr_vs_c,
    bench_utf8_scan_vs_c,
    bench_split_clients_vs_c,
    bench_strnstr_vs_c,
    bench_limit_req_vs_c,
    bench_ip_hash_vs_c,
    bench_rbtree_vs_c,
    bench_sub_filter_vs_c,
    bench_sort_vs_c,
    bench_hextoi_vs_c,
    bench_encode_base64_vs_c,
    bench_decode_base64_vs_c,
    bench_decode_base64url_vs_c,
    bench_encode_base64url_vs_c,
    bench_hex_dump_vs_c,
    bench_chunked_header_vs_c,
    bench_chunked_parse_vs_c,
    bench_chunked_stream_vs_c,
    bench_huff_encode_vs_c,
    bench_huff_decode_vs_c,
    bench_conf_scan_vs_c,
    bench_http_v2_frame_header_vs_c,
    bench_proxy_v1_inet_vs_c,
    bench_proxy_v2_inet_vs_c,
    bench_v3_varlen_encode_vs_c,
    bench_v3_varlen_decode_vs_c,
    bench_v3_prefix_encode_vs_c,
    bench_v3_prefix_decode_vs_c
);
criterion_main!(vs_c);
