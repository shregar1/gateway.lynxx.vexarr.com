//! Benchmark: Peak EWMA latency-based LB
//! Group: upstream_pick | Algo: peak_ewma

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::peak_ewma::PeakEwmaLb;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/peak_ewma");

    for &n in &[3usize, 10, 100] {
        g.bench_with_input(BenchmarkId::new("pick", n), &n, |b, &n| {
            let lb = PeakEwmaLb::new(n, 10_000_000_000);
            // Seed some RTT data
            for i in 0..n {
                let idx = lb.pick(0);
                lb.record(idx, (i as u64 + 1) * 1_000, 1);
            }
            let mut now = 100u64;
            b.iter(|| {
                now += 1;
                black_box(lb.pick(now))
            })
        });

        g.bench_with_input(BenchmarkId::new("record", n), &n, |b, &n| {
            let lb = PeakEwmaLb::new(n, 10_000_000_000);
            let mut idx = 0usize;
            let mut now = 0u64;
            b.iter(|| {
                lb.record(idx, 5_000, now);
                idx = (idx + 1) % n;
                now += 1;
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
