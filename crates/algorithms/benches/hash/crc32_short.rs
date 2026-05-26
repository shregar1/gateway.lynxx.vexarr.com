//! Benchmark: ngx_crc32_short — CRC32 byte-at-a-time short variant
//! Group: hash | Algo: crc32_short

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_crc32_short;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash/crc32_short");
    for &sz in SIZES {
        let d = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("crc32_short", sz), &d, |b, d| {
            b.iter(|| black_box(ngx_crc32_short(d)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
