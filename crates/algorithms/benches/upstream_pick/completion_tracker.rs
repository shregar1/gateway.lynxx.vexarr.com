//! Benchmark: Load completion signaling
//! Group: upstream_pick | Algo: completion_tracker

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::completion_tracker::CompletionTracker;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/completion_tracker");

    for &n in &[3usize, 10, 100] {
        g.bench_with_input(BenchmarkId::new("best_endpoint", n), &n, |b, &n| {
            let tracker = CompletionTracker::new(n);
            // Seed completion data
            for i in 0..n {
                for _ in 0..10 {
                    tracker.start(i);
                    tracker.complete(i, i % 3 != 0); // some failures
                }
            }
            b.iter(|| black_box(tracker.best_endpoint()))
        });

        g.bench_with_input(
            BenchmarkId::new("start_complete_cycle", n),
            &n,
            |b, &n| {
                let tracker = CompletionTracker::new(n);
                let mut idx = 0usize;
                b.iter(|| {
                    tracker.start(idx);
                    tracker.complete(idx, true);
                    idx = (idx + 1) % n;
                })
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
