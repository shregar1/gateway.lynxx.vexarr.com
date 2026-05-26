//! Benchmark: ngx_encode_base64
//! Group: encode | Algo: base64_encode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_encode_base64;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encode/base64_encode");
    for &sz in SIZES {
        let src = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("encode", sz), &src, |b, src| {
            let mut dst = vec![0u8; src.len() * 2];
            b.iter(|| black_box(ngx_encode_base64(&mut dst, src)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
