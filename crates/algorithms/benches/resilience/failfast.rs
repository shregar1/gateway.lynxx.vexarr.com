//! Benchmark: Failfast — readiness-based circuit breaker
//! Group: resilience | Algo: failfast

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::resilience::failfast::Failfast;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("resilience/failfast");

    g.bench_function("is_ready_healthy", |b| {
        let mut ff = Failfast::new(5000);
        ff.record_success(100);
        let mut ts = 100u64;
        b.iter(|| {
            ts += 1;
            black_box(ff.is_ready(ts))
        })
    });

    g.bench_function("is_ready_failed", |b| {
        let mut ff = Failfast::new(5000);
        ff.record_failure(100);
        let mut ts = 100u64;
        b.iter(|| {
            ts += 1;
            black_box(ff.is_ready(ts))
        })
    });

    g.bench_function("failure_recovery_cycle", |b| {
        let mut ff = Failfast::new(1000);
        let mut ts = 0u64;
        b.iter(|| {
            ts += 1;
            ff.record_failure(ts);
            ff.is_ready(ts + 500);
            ff.is_ready(ts + 1001);
            ff.record_success(ts + 1001);
            black_box(ff.is_ready(ts + 1002))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
