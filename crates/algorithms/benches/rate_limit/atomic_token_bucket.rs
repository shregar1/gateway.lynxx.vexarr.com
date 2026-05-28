//! Benchmark: AtomicTokenBucket — lock-free token bucket
//! Group: rate_limit | Algo: atomic_token_bucket

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::rate_limit::atomic_token_bucket::AtomicTokenBucket;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit/atomic_token_bucket");

    g.bench_function("consume_ok", |b| {
        let tb = AtomicTokenBucket::new(1_000_000_000.0, 1_000_000.0);
        let mut now = 0u64;
        b.iter(|| {
            now += 1000; // 1 us increments
            black_box(tb.consume(1.0, now))
        })
    });

    g.bench_function("consume_reject", |b| {
        let tb = AtomicTokenBucket::new(1.0, 1.0); // very slow refill
        tb.consume(1.0, 0); // drain
        b.iter(|| black_box(tb.consume(1.0, 1)))
    });

    g.bench_function("available", |b| {
        let tb = AtomicTokenBucket::new(1_000_000.0, 1000.0);
        let mut now = 0u64;
        b.iter(|| {
            now += 1000;
            black_box(tb.available(now))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
