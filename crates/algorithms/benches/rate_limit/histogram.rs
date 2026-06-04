//! Benchmark: Histogram — stepped logarithmic histogram
//! Group: rate_limit | Algo: histogram

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::rate_limit::histogram::Histogram;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit/histogram");

    // record — O(1) insert
    for &(name, range_bits, span_bits) in &[("small", 8u32, 4u32), ("medium", 16, 4), ("large", 20, 6)] {
        g.bench_with_input(BenchmarkId::new("record", name), &(range_bits, span_bits), |b, &(rb, sb)| {
            let mut h = Histogram::new(rb, sb);
            let mut val = 0u64;
            b.iter(|| {
                val = val.wrapping_add(7919);
                black_box(h.record(val));
            })
        });
    }

    // percentile query
    g.bench_function("percentile_p99", |b| {
        let mut h = Histogram::new(16, 4);
        for i in 0..10_000u64 {
            h.record(i);
        }
        b.iter(|| black_box(h.percentile(0.99)))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
