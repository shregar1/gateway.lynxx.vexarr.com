//! Benchmark: RangeSlicer — Content-Range block decomposition
//! Group: http_codec | Algo: range_slicer

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::http_codec::{ContentRange, RangeSlicer};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("http_codec/range_slicer");
    let slicer = RangeSlicer::new(1024 * 1024); // 1MB blocks

    for &(name, start, end) in &[
        ("single_block", 0u64, 512u64),
        ("two_blocks", 500_000, 1_500_000),
        ("ten_blocks", 0, 10_000_000),
        ("hundred_blocks", 0, 100_000_000),
    ] {
        let range = ContentRange { start, end, total: Some(end + 1) };
        g.bench_with_input(BenchmarkId::new("slice", name), &range, |b, range| {
            b.iter(|| black_box(slicer.slice(range)))
        });
    }

    // parse_content_range
    g.bench_function("parse_content_range", |b| {
        b.iter(|| black_box(RangeSlicer::parse_content_range("bytes 0-999/8000")))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
