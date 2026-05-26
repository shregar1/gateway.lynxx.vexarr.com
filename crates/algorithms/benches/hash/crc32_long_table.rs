//! Benchmark: ngx_crc32_long_table — CRC32 256-entry lookup table
//! Group: hash | Algo: crc32_long_table

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_crc32_long_table;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash/crc32_long_table");
    for &sz in SIZES {
        let d = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("crc32_long_table", sz), &d, |b, d| {
            b.iter(|| black_box(ngx_crc32_long_table(d)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
