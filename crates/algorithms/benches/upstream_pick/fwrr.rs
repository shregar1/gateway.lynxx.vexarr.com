//! Benchmark: Fast Weighted Round Robin
//! Group: upstream_pick | Algo: fwrr

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::fwrr::FwrrSelector;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/fwrr");

    for &n in &[3usize, 10, 100] {
        let weights: Vec<u32> = (1..=n as u32).collect();
        g.bench_with_input(BenchmarkId::new("pick", n), &weights, |b, weights| {
            let mut sel = FwrrSelector::new(weights);
            b.iter(|| black_box(sel.pick()))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
