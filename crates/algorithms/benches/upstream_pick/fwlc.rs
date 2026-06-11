//! Benchmark: Fast Weighted Least Connections
//! Group: upstream_pick | Algo: fwlc

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::fwlc::FwlcSelector;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/fwlc");

    for &n in &[3usize, 10, 100] {
        let weights: Vec<u32> = (1..=n as u32).collect();
        g.bench_with_input(BenchmarkId::new("pick", n), &weights, |b, weights| {
            let sel = FwlcSelector::new(weights);
            // Pre-load some connections
            for i in 0..sel.len() {
                for _ in 0..((i + 1) * 2) {
                    sel.connect(i);
                }
            }
            b.iter(|| black_box(sel.pick()))
        });

        g.bench_with_input(
            BenchmarkId::new("connect_release", n),
            &weights,
            |b, weights| {
                let sel = FwlcSelector::new(weights);
                let mut idx = 0usize;
                b.iter(|| {
                    sel.connect(idx);
                    sel.release(idx);
                    idx = (idx + 1) % sel.len();
                })
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
