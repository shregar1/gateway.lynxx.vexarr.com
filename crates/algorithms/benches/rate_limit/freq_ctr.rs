//! Benchmark: FreqCounter — sliding-window frequency counter
//! Group: rate_limit | Algo: freq_ctr

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::rate_limit::freq_ctr::FreqCounter;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit/freq_ctr");

    g.bench_function("add_and_read", |b| {
        let mut fc = FreqCounter::new(1000);
        let mut ts = 0u64;
        b.iter(|| {
            ts += 1;
            fc.add(ts, 1);
            black_box(fc.read(ts))
        })
    });

    g.bench_function("rate_per_sec", |b| {
        let mut fc = FreqCounter::new(1000);
        for t in 0..500 {
            fc.add(t, 1);
        }
        let mut ts = 500u64;
        b.iter(|| {
            ts += 1;
            black_box(fc.rate_per_sec(ts))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
