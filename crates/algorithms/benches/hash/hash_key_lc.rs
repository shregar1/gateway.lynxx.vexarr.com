//! Benchmark: ngx_hash_key_lc — DJB hash with lowercase folding
//! Group: hash | Algo: hash_key_lc

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_hash_key_lc;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash/hash_key_lc");
    for &sz in SIZES {
        let d = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("hash_key_lc", sz), &d, |b, d| {
            b.iter(|| black_box(ngx_hash_key_lc(d)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
