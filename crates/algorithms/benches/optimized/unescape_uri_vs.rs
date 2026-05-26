//! Benchmark: URI unescape original vs optimized SWAR scanning
//! Compares: ngx_unescape_uri vs unescape_uri_fast

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::unescape_uri::ngx_unescape_uri;
use algorithms::goals::optimized::unescape_uri::unescape_uri_fast;

fn make_input(size: usize, pct_encoded_ratio: f64) -> Vec<u8> {
    let mut v = Vec::with_capacity(size);
    let mut i = 0usize;
    while v.len() < size {
        if (i as f64 / size as f64) < pct_encoded_ratio && v.len() + 3 <= size {
            // Insert %XX
            let byte = ((i * 7 + 13) % 256) as u8;
            v.push(b'%');
            v.push(b"0123456789ABCDEF"[byte as usize >> 4]);
            v.push(b"0123456789ABCDEF"[byte as usize & 0xf]);
        } else {
            v.push(b'a' + (i % 26) as u8);
        }
        i += 1;
    }
    v.truncate(size);
    v
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("optimized/unescape_uri");

    for &size in &[16usize, 64, 256, 1024, 4096] {
        // Mostly safe (5% encoded) — tests fast-path scanning
        let input_safe = make_input(size, 0.05);
        // Mixed (30% encoded) — tests decode throughput
        let input_mixed = make_input(size, 0.30);

        let label_safe = format!("{}B_5pct", size);
        let label_mixed = format!("{}B_30pct", size);

        // Original — safe
        g.bench_with_input(
            BenchmarkId::new("ngx_unescape_uri", &label_safe),
            &input_safe,
            |b, input| {
                let mut dst = vec![0u8; input.len()];
                b.iter(|| black_box(ngx_unescape_uri(&mut dst, input, false)))
            },
        );

        // Optimized — safe
        g.bench_with_input(
            BenchmarkId::new("unescape_uri_fast", &label_safe),
            &input_safe,
            |b, input| {
                let mut dst = vec![0u8; input.len()];
                b.iter(|| black_box(unescape_uri_fast(&mut dst, input, false)))
            },
        );

        // Original — mixed
        g.bench_with_input(
            BenchmarkId::new("ngx_unescape_uri", &label_mixed),
            &input_mixed,
            |b, input| {
                let mut dst = vec![0u8; input.len()];
                b.iter(|| black_box(ngx_unescape_uri(&mut dst, input, false)))
            },
        );

        // Optimized — mixed
        g.bench_with_input(
            BenchmarkId::new("unescape_uri_fast", &label_mixed),
            &input_mixed,
            |b, input| {
                let mut dst = vec![0u8; input.len()];
                b.iter(|| black_box(unescape_uri_fast(&mut dst, input, false)))
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
