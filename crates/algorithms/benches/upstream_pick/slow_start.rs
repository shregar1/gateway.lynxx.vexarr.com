//! Benchmark: Slow-start weight ramping
//! Group: upstream_pick | Algo: slow_start

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::slow_start::SlowStartPool;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/slow_start");

    for &n in &[3usize, 10, 100] {
        g.bench_with_input(
            BenchmarkId::new("effective_weight_ramping", n),
            &n,
            |b, &n| {
                let mut pool = SlowStartPool::new(n, 60);
                for i in 0..n {
                    pool.start_ramp(i, 1000);
                }
                let mut now = 1000u64;
                let mut idx = 0usize;
                b.iter(|| {
                    let w = pool.effective_weight(idx, now, 100);
                    idx = (idx + 1) % n;
                    now += 1;
                    black_box(w)
                })
            },
        );

        g.bench_with_input(
            BenchmarkId::new("effective_weight_done", n),
            &n,
            |b, &n| {
                let pool = SlowStartPool::new(n, 60);
                // No ramp started → full weight
                let mut idx = 0usize;
                b.iter(|| {
                    let w = pool.effective_weight(idx, 9999, 100);
                    idx = (idx + 1) % n;
                    black_box(w)
                })
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
