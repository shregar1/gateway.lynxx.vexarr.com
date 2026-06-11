//! Benchmark: Zone-aware locality routing
//! Group: upstream_pick | Algo: locality_lb

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::locality_lb::locality_pick;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/locality_lb");

    for &n_zones in &[3usize, 10, 100] {
        let zone_weights: Vec<f64> = (1..=n_zones).map(|i| i as f64).collect();
        let zone_backends: Vec<usize> = vec![5; n_zones];

        g.bench_with_input(
            BenchmarkId::new("pick", n_zones),
            &(zone_weights.clone(), zone_backends.clone()),
            |b, (zw, zb)| {
                b.iter(|| black_box(locality_pick(0, zw, zb)))
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
