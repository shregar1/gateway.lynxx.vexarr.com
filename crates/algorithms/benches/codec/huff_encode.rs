//! Benchmark: HPACK Huffman encode
//! Group: codec | Algo: huff_encode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lynxx_algo::ngx_http_huff_encode;

const HEADERS: &[(&str, &[u8])] = &[
    ("short", b"content-type"),
    ("medium", b"application/json; charset=utf-8"),
    ("long", b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/huff_encode");
    for &(name, src) in HEADERS {
        g.throughput(Throughput::Bytes(src.len() as u64));
        g.bench_with_input(BenchmarkId::new("encode", name), &src, |b, &src| {
            let mut dst = vec![0u8; src.len() * 2];
            b.iter(|| black_box(ngx_http_huff_encode(&mut dst, src)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
