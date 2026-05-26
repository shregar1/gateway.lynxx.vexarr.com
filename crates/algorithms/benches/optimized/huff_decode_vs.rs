//! Benchmark: HPACK Huffman decode — branchless byte-table vs original
//!
//! The original uses a 3-way branch per byte (emit 0/1/2 chars) with separate
//! byte-table (streaming) and nibble-table (last) paths.
//!
//! The optimized version uses:
//! - **Streaming**: branchless speculative double-write + batched error checks + 8× unroll
//! - **Last**: hybrid — byte-table branchless for N-1 bytes, nibble for final byte (ending flag)
//!
//! Previous nibble-only hypothesis was disproven: 2× lookup count is a net loss
//! since modern prefetchers handle the 512KB byte table well.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::huff_encode::ngx_http_huff_encode;
use nginx_algo::huff_decode::{ngx_http_huff_decode, HUFF_DECODE_BYTE, HUFF_DECODE_FLAT};
use algorithms::goals::optimized::huff_decode::huff_decode_fast;

fn make_encoded(plain: &[u8]) -> Vec<u8> {
    let mut encoded = vec![0u8; plain.len() * 2 + 16];
    let n = ngx_http_huff_encode(&mut encoded, plain);
    encoded.truncate(n);
    encoded
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("optimized/huff_decode");

    let inputs: &[(&str, &[u8])] = &[
        ("short_12B", b"Content-Type"),
        ("medium_30B", b"text/html; charset=utf-8, gzip"),
        ("header_path_51B", b"/api/v1/users/12345/sessions?token=abcdef0123456789"),
        ("long_66B", b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0"),
        ("user_agent_120B", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        ("url_200B", b"/very/long/path/to/some/deeply/nested/resource/in/a/large/api/with/many/segments/that/represents/a/real/world/scenario/for/microservices/architecture/v2/endpoints/users/12345/preferences/notifications/email"),
    ];

    for &(name, plain) in inputs {
        let encoded = make_encoded(plain);

        // ORIGINAL: byte-table streaming (512KB table, 1 lookup/byte, branched emit)
        g.bench_with_input(
            BenchmarkId::new("original_byte_stream", name),
            &encoded,
            |b, encoded| {
                let mut dst = vec![0u8; plain.len() + 32];
                b.iter(|| {
                    let mut state = 0u8;
                    black_box(ngx_http_huff_decode(&mut state, encoded, &mut dst, false));
                })
            },
        );

        // ORIGINAL: nibble-table last (16KB table, 2 lookups/byte + ending check)
        g.bench_with_input(
            BenchmarkId::new("original_nibble_last", name),
            &encoded,
            |b, encoded| {
                let mut dst = vec![0u8; plain.len() + 32];
                b.iter(|| {
                    let mut state = 0u8;
                    black_box(ngx_http_huff_decode(&mut state, encoded, &mut dst, true));
                })
            },
        );

        // OPTIMIZED: branchless byte-table streaming (speculative emit + batched errors + 8× unroll)
        g.bench_with_input(
            BenchmarkId::new("opt_branchless_stream", name),
            &encoded,
            |b, encoded| {
                let mut dst = vec![0u8; plain.len() + 32];
                b.iter(|| {
                    let mut state = 0u8;
                    black_box(huff_decode_fast(&mut state, encoded, &mut dst, false, &HUFF_DECODE_BYTE, &HUFF_DECODE_FLAT));
                })
            },
        );

        // OPTIMIZED: hybrid last (byte-table N-1 bytes + nibble last byte for ending)
        g.bench_with_input(
            BenchmarkId::new("opt_hybrid_last", name),
            &encoded,
            |b, encoded| {
                let mut dst = vec![0u8; plain.len() + 32];
                b.iter(|| {
                    let mut state = 0u8;
                    black_box(huff_decode_fast(&mut state, encoded, &mut dst, true, &HUFF_DECODE_BYTE, &HUFF_DECODE_FLAT));
                })
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
