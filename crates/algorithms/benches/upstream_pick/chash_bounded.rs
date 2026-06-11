//! Benchmark: Consistent Hash with Bounded Loads
//! Group: upstream_pick | Algo: chash_bounded

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::chash_bounded::BoundedCHash;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/chash_bounded");

    for &n in &[3usize, 10, 100] {
        let nodes: Vec<String> = (0..n).map(|i| format!("node-{}", i)).collect();
        let node_refs: Vec<&str> = nodes.iter().map(|s| s.as_str()).collect();

        g.bench_with_input(BenchmarkId::new("pick", n), &node_refs, |b, nodes| {
            let ch = BoundedCHash::new(nodes, 150, 1.25);
            let mut key = 0u64;
            b.iter(|| {
                let k = key.to_le_bytes();
                let result = ch.pick(black_box(&k));
                key = key.wrapping_add(1);
                black_box(result)
            })
        });

        g.bench_with_input(
            BenchmarkId::new("pick_loaded", n),
            &node_refs,
            |b, nodes| {
                let ch = BoundedCHash::new(nodes, 150, 1.25);
                // Overload node 0
                for _ in 0..50 {
                    ch.connect(0);
                }
                let mut key = 0u64;
                b.iter(|| {
                    let k = key.to_le_bytes();
                    let result = ch.pick(black_box(&k));
                    key = key.wrapping_add(1);
                    black_box(result)
                })
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
