//! Benchmark: WT6 — Willy Tarreau dual-state rotation hash
//! Group: hashing | Algo: wt6

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::hash::wt6_hash;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashing/wt6");
    for &sz in SIZES {
        let data = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("wt6", sz), &data, |b, data| {
            b.iter(|| black_box(wt6_hash(data, 0)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
