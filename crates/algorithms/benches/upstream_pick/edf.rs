//! Benchmark: Earliest Deadline First scheduler
//! Group: upstream_pick | Algo: edf

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::edf::EdfScheduler;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/edf");

    for &n in &[3usize, 10, 100] {
        let weights: Vec<f64> = (1..=n).map(|i| i as f64).collect();
        g.bench_with_input(BenchmarkId::new("pick", n), &weights, |b, weights| {
            let mut sched = EdfScheduler::new(weights);
            b.iter(|| black_box(sched.pick()))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
