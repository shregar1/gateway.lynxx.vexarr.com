//! Benchmark: CRC32 original vs optimized slicing-by-4/8
//! Compares: ngx_crc32_long_table, ngx_crc32_short_nibble vs crc32_slice4, crc32_slice8

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::crc32::{ngx_crc32_long_table, ngx_crc32_short_nibble};
use algorithms::goals::optimized::crc32::{crc32_slice4, crc32_slice8};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("optimized/crc32");

    for &size in &[16usize, 64, 256, 1024, 4096] {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();

        g.bench_with_input(
            BenchmarkId::new("ngx_crc32_long_table", size),
            &data,
            |b, data| b.iter(|| black_box(ngx_crc32_long_table(data))),
        );

        g.bench_with_input(
            BenchmarkId::new("ngx_crc32_short_nibble", size),
            &data,
            |b, data| b.iter(|| black_box(ngx_crc32_short_nibble(data))),
        );

        g.bench_with_input(
            BenchmarkId::new("crc32_slice4", size),
            &data,
            |b, data| b.iter(|| black_box(crc32_slice4(data))),
        );

        g.bench_with_input(
            BenchmarkId::new("crc32_slice8", size),
            &data,
            |b, data| b.iter(|| black_box(crc32_slice8(data))),
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
