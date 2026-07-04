//! Benchmark: SipHasher — SipHash-2-4 / SipHash-1-3
//! Group: hashing | Algo: siphash

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::hash::SipHasher;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashing/siphash");
    for &sz in SIZES {
        let data = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("siphash24", sz), &data, |b, data| {
            b.iter(|| black_box(SipHasher::hash(0x0123456789abcdef, 0xfedcba9876543210, data)))
        });
    }
    g.finish();

    let mut g2 = c.benchmark_group("hashing/siphash_fast");
    for &sz in SIZES {
        let data = payload(sz);
        g2.throughput(Throughput::Bytes(sz as u64));
        g2.bench_with_input(BenchmarkId::new("siphash13", sz), &data, |b, data| {
            b.iter(|| black_box(SipHasher::hash_fast(0x0123456789abcdef, 0xfedcba9876543210, data)))
        });
    }
    g2.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
