//! Benchmark: ngx_http_chunked_header — encode chunk size header
//! Group: codec | Algo: chunked_header

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::ngx_http_chunked_header;

const CHUNK_SIZES: &[u64] = &[64, 256, 4096, 65536];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/chunked_header");
    for &sz in CHUNK_SIZES {
        g.bench_with_input(BenchmarkId::new("header", sz), &sz, |b, &sz| {
            let mut dst = [0u8; 32];
            b.iter(|| black_box(ngx_http_chunked_header(&mut dst, sz)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
