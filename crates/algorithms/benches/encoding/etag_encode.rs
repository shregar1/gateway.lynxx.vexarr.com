//! Benchmark: etag_encode — ETag generation and comparison
//! Group: encoding | Algo: etag_encode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::encode::etag_encode::{etag_strong, etag_weak, etag_weak_match, etag_strong_match};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/etag_encode");

    let cases: &[(&str, u64, u64)] = &[
        ("small_file", 1024, 1700000000),
        ("medium_file", 1_048_576, 1700000000),
        ("large_file", 10_737_418_240, 1700000000),
    ];

    for &(name, size, mtime) in cases {
        g.bench_with_input(BenchmarkId::new("strong", name), &(size, mtime), |b, &(sz, mt)| {
            b.iter(|| black_box(etag_strong(black_box(sz), black_box(mt))))
        });

        g.bench_with_input(BenchmarkId::new("weak", name), &(size, mtime), |b, &(sz, mt)| {
            b.iter(|| black_box(etag_weak(black_box(sz), black_box(mt))))
        });
    }

    // Comparison benchmarks
    let tag_a = etag_strong(1024, 1700000000);
    let tag_b = etag_strong(1024, 1700000000);
    let tag_w = etag_weak(1024, 1700000000);

    g.bench_function("weak_match_strong_vs_strong", |b| {
        b.iter(|| black_box(etag_weak_match(black_box(&tag_a), black_box(&tag_b))))
    });

    g.bench_function("weak_match_weak_vs_strong", |b| {
        b.iter(|| black_box(etag_weak_match(black_box(&tag_w), black_box(&tag_a))))
    });

    g.bench_function("strong_match", |b| {
        b.iter(|| black_box(etag_strong_match(black_box(&tag_a), black_box(&tag_b))))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
