//! Benchmark: DAGOR compound priority admission control
//! Group: rate_limit | Algo: dagor

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::rate_limit::dagor::{DagorController, RequestPriority};
use std::time::Duration;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit_dagor");

    g.bench_function("should_admit", |b| {
        let ctrl = DagorController::new(256, Duration::from_millis(5));
        let p = RequestPriority { business: 0, user: 42 };
        b.iter(|| black_box(ctrl.should_admit(&p)));
    });

    g.bench_function("record_and_adjust", |b| {
        b.iter(|| {
            let mut ctrl = DagorController::new(256, Duration::from_millis(5));
            for i in 0..1000u32 {
                let p = RequestPriority {
                    business: (i % 4) as u8,
                    user: i,
                };
                ctrl.record(&p);
                black_box(ctrl.should_admit(&p));
            }
            ctrl.observe_queuing_time(10_000_000);
            ctrl.adjust();
        });
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
