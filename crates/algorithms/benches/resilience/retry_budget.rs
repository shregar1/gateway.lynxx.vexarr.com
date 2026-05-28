//! Benchmark: RetryBudget — proportional retry limiting
//! Group: resilience | Algo: retry_budget

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::resilience::retry_budget::RetryBudget;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("resilience/retry_budget");

    g.bench_function("record_request", |b| {
        let mut rb = RetryBudget::new(0.2, 5);
        let mut ts = 0u64;
        b.iter(|| {
            ts += 1;
            rb.record_request(ts);
            black_box(())
        })
    });

    g.bench_function("allow_retry", |b| {
        let mut rb = RetryBudget::new(0.2, 5);
        let mut ts = 0u64;
        b.iter(|| {
            ts += 1;
            rb.record_request(ts);
            black_box(rb.allow_retry(ts))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
