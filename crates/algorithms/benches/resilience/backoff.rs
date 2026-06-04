//! Benchmark: backoff — exponential backoff with jitter
//! Group: resilience | Algo: backoff

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::resilience::backoff::{backoff_delay, backoff_full_jitter, backoff_decorrelated};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("resilience/backoff");

    g.bench_function("exponential", |b| {
        let mut attempt = 0u32;
        b.iter(|| {
            attempt = attempt.wrapping_add(1) % 20;
            black_box(backoff_delay(attempt, 100, 30_000))
        })
    });

    g.bench_function("full_jitter", |b| {
        let mut attempt = 0u32;
        b.iter(|| {
            attempt = attempt.wrapping_add(1) % 20;
            black_box(backoff_full_jitter(attempt, 100, 30_000))
        })
    });

    g.bench_function("decorrelated", |b| {
        let mut prev = 100u64;
        b.iter(|| {
            prev = backoff_decorrelated(prev, 100, 30_000);
            black_box(prev)
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
