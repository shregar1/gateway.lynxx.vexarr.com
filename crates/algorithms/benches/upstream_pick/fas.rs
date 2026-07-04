//! Benchmark: First Available Server
//! Group: upstream_pick | Algo: fas

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::fas::FasSelector;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/fas");

    for &n in &[3usize, 10, 100] {
        // All up
        g.bench_with_input(BenchmarkId::new("pick_all_up", n), &n, |b, &n| {
            let sel = FasSelector::new(n);
            b.iter(|| black_box(sel.pick()))
        });

        // First half down
        g.bench_with_input(BenchmarkId::new("pick_half_down", n), &n, |b, &n| {
            let sel = FasSelector::new(n);
            for i in 0..n / 2 {
                sel.mark_down(i);
            }
            b.iter(|| black_box(sel.pick()))
        });

        // Mark up / mark down cycle
        g.bench_with_input(BenchmarkId::new("toggle", n), &n, |b, &n| {
            let sel = FasSelector::new(n);
            let mut idx = 0usize;
            b.iter(|| {
                sel.mark_down(idx);
                sel.mark_up(idx);
                idx = (idx + 1) % n;
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
