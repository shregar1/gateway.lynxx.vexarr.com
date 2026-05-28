//! Benchmark: URI escape original vs optimized SWAR+batch
//! Compares: ngx_escape_uri vs escape_uri_fast

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::escape_uri::ngx_escape_uri;
use algorithms::goals::optimized::escape_uri::escape_uri_fast;

fn make_input_safe(size: usize) -> Vec<u8> {
    // Mostly safe ASCII — letters and digits
    (0..size).map(|i| b'a' + (i % 26) as u8).collect()
}

fn make_input_mixed(size: usize) -> Vec<u8> {
    // Mix of safe and unsafe bytes
    (0..size)
        .map(|i| {
            if i % 4 == 0 {
                b' ' // needs escaping
            } else if i % 7 == 0 {
                0x80 + (i % 64) as u8 // high byte, needs escaping
            } else {
                b'a' + (i % 26) as u8 // safe
            }
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("optimized/escape_uri");

    for &size in &[16usize, 64, 256, 1024, 4096] {
        let input_safe = make_input_safe(size);
        let input_mixed = make_input_mixed(size);

        // Safe input (fast-path scan dominates)
        g.bench_with_input(
            BenchmarkId::new("ngx_escape_uri/safe", size),
            &input_safe,
            |b, input| {
                let mut dst = vec![0u8; input.len() * 3];
                b.iter(|| black_box(ngx_escape_uri(&mut dst, input)))
            },
        );

        g.bench_with_input(
            BenchmarkId::new("escape_uri_fast/safe", size),
            &input_safe,
            |b, input| {
                let mut dst = vec![0u8; input.len() * 3];
                b.iter(|| black_box(escape_uri_fast(&mut dst, input)))
            },
        );

        // Mixed input (escape throughput matters)
        g.bench_with_input(
            BenchmarkId::new("ngx_escape_uri/mixed", size),
            &input_mixed,
            |b, input| {
                let mut dst = vec![0u8; input.len() * 3];
                b.iter(|| black_box(ngx_escape_uri(&mut dst, input)))
            },
        );

        g.bench_with_input(
            BenchmarkId::new("escape_uri_fast/mixed", size),
            &input_mixed,
            |b, input| {
                let mut dst = vec![0u8; input.len() * 3];
                b.iter(|| black_box(escape_uri_fast(&mut dst, input)))
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
