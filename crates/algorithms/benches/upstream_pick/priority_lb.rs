//! Benchmark: Priority-based distribution
//! Group: upstream_pick | Algo: priority_lb

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::priority_lb::PriorityLb;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/priority_lb");

    for &n in &[3usize, 10, 100] {
        // n backends across 3 priority levels
        let per_level = n / 3;
        let levels = vec![
            vec![1u32; per_level.max(1)],
            vec![1u32; per_level.max(1)],
            vec![1u32; (n - 2 * per_level).max(1)],
        ];

        g.bench_with_input(BenchmarkId::new("pick_healthy", n), &levels, |b, levels| {
            let lb = PriorityLb::new(levels);
            b.iter(|| black_box(lb.pick()))
        });

        // P0 unhealthy → fall through
        let levels_fallthrough = vec![
            vec![0u32; per_level.max(1)],
            vec![1u32; per_level.max(1)],
            vec![1u32; (n - 2 * per_level).max(1)],
        ];

        g.bench_with_input(
            BenchmarkId::new("pick_fallthrough", n),
            &levels_fallthrough,
            |b, levels| {
                let lb = PriorityLb::new(levels);
                b.iter(|| black_box(lb.pick()))
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
