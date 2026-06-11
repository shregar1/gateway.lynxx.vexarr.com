//! Benchmark: XXHash — XXH32 / XXH64
//! Group: hashing | Algo: xxhash

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::hash::{xxh32, xxh64};

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashing/xxh32");
    for &sz in SIZES {
        let data = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("xxh32", sz), &data, |b, data| {
            b.iter(|| black_box(xxh32(data, 0)))
        });
    }
    g.finish();

    let mut g2 = c.benchmark_group("hashing/xxh64");
    for &sz in SIZES {
        let data = payload(sz);
        g2.throughput(Throughput::Bytes(sz as u64));
        g2.bench_with_input(BenchmarkId::new("xxh64", sz), &data, |b, data| {
            b.iter(|| black_box(xxh64(data, 0)))
        });
    }
    g2.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
