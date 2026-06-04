//! Benchmark: CRC32c — Castagnoli CRC-32 with lookup table
//! Group: hashing | Algo: crc32c

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::hash::{crc32c_hash, crc32c_update};

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashing/crc32c");
    for &sz in SIZES {
        let data = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("crc32c_hash", sz), &data, |b, data| {
            b.iter(|| black_box(crc32c_hash(data)))
        });
    }
    g.finish();

    let mut g2 = c.benchmark_group("hashing/crc32c_update");
    for &sz in SIZES {
        let data = payload(sz);
        g2.throughput(Throughput::Bytes(sz as u64));
        g2.bench_with_input(BenchmarkId::new("crc32c_update", sz), &data, |b, data| {
            b.iter(|| black_box(crc32c_update(0, data)))
        });
    }
    g2.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
