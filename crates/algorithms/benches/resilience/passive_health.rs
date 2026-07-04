//! Benchmark: PassiveHealthCheck — passive health checker
//! Group: resilience | Algo: passive_health

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::resilience::passive_health::PassiveHealthCheck;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("resilience/passive_health");

    g.bench_function("record_and_check", |b| {
        let mut phc = PassiveHealthCheck::new(5, 10_000);
        let mut ts = 0u64;
        b.iter(|| {
            ts += 1;
            phc.record(ts % 10 != 0, ts);
            black_box(phc.is_healthy(ts))
        })
    });

    g.bench_function("is_healthy", |b| {
        let mut phc = PassiveHealthCheck::new(5, 10_000);
        for i in 0..100u64 {
            phc.record(i % 3 != 0, i);
        }
        let mut ts = 100u64;
        b.iter(|| {
            ts += 1;
            black_box(phc.is_healthy(ts))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
