//! Benchmark: CoDel active queue management
//! Group: rate_limit | Algo: codel

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::rate_limit::codel::CoDel;
use std::time::{Duration, Instant};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit_codel");

    g.bench_function("should_drop_accept", |b| {
        let mut codel = CoDel::new(Duration::from_millis(5), Duration::from_millis(100));
        let now = Instant::now();
        b.iter(|| black_box(codel.should_drop(Duration::from_micros(500), now)));
    });

    g.bench_function("should_drop_over_target", |b| {
        b.iter(|| {
            let mut codel = CoDel::new(Duration::from_millis(5), Duration::from_millis(100));
            let mut now = Instant::now();
            for _ in 0..200 {
                black_box(codel.should_drop(Duration::from_millis(20), now));
                now += Duration::from_millis(1);
            }
        });
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
