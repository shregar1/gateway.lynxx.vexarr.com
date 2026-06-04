//! Benchmark: CircuitBreaker — 3-state circuit breaker
//! Group: resilience | Algo: circuit_breaker

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::resilience::circuit_breaker::CircuitBreaker;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("resilience/circuit_breaker");

    g.bench_function("allow_request_closed", |b| {
        let mut cb = CircuitBreaker::new(5, 5000);
        let mut now = 0u64;
        b.iter(|| {
            now += 1;
            black_box(cb.allow_request(now))
        })
    });

    g.bench_function("record_success", |b| {
        let mut cb = CircuitBreaker::new(5, 5000);
        b.iter(|| {
            cb.record_success();
            black_box(())
        })
    });

    g.bench_function("failure_and_recover", |b| {
        let mut cb = CircuitBreaker::new(3, 1000);
        let mut now = 0u64;
        b.iter(|| {
            now += 1;
            cb.record_failure_at(now);
            cb.allow_request(now + 1001);
            cb.record_success();
            black_box(())
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
