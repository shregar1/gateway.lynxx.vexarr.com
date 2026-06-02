//! Benchmark: Power of Two Choices load balancer
//! Group: upstream_pick | Algo: p2c

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::p2c::P2cBalancer;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/p2c");

    for n in [4usize, 16, 64] {
        g.bench_with_input(BenchmarkId::new("pick", n), &n, |b, &n| {
            let lb = P2cBalancer::new(n);
            b.iter(|| {
                let idx = lb.pick();
                lb.request_start(idx);
                lb.request_end(idx);
                black_box(idx);
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
