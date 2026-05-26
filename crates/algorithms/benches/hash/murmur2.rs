//! Benchmark: MurmurHash2
//! Group: hash | Algo: murmur2

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_murmur_hash2;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash/murmur2");
    for &sz in SIZES {
        let d = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("murmur_hash2", sz), &d, |b, d| {
            b.iter(|| black_box(ngx_murmur_hash2(d)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
