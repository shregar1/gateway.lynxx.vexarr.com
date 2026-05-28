//! Benchmark: HPACK Huffman decode
//! Group: codec | Algo: huff_decode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lynxx_algo::{ngx_http_huff_encode, ngx_http_huff_decode};

const HEADERS: &[(&str, &[u8])] = &[
    ("short", b"content-type"),
    ("medium", b"application/json; charset=utf-8"),
    ("long", b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/huff_decode");
    for &(name, src) in HEADERS {
        let mut encoded = vec![0u8; src.len() * 2];
        let enc_len = ngx_http_huff_encode(&mut encoded, src);
        let encoded = &encoded[..enc_len];
        g.throughput(Throughput::Bytes(encoded.len() as u64));
        g.bench_with_input(BenchmarkId::new("decode", name), &encoded, |b, encoded| {
            let mut dst = vec![0u8; src.len() * 2];
            b.iter(|| {
                let mut state = 0u8;
                black_box(ngx_http_huff_decode(&mut state, encoded, &mut dst, true))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
