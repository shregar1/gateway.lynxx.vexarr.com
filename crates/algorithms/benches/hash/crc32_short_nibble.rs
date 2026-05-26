//! Benchmark: ngx_crc32_short_nibble — CRC32 nibble lookup
//! Group: hash | Algo: crc32_short_nibble

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_crc32_short_nibble;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash/crc32_short_nibble");
    for &sz in SIZES {
        let d = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("crc32_short_nibble", sz), &d, |b, d| {
            b.iter(|| black_box(ngx_crc32_short_nibble(d)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
