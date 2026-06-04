//! Benchmark: GradientController — adaptive concurrency limiter
//! Group: rate_limit | Algo: gradient_controller

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::rate_limit::gradient_controller::{GradientController, GradientConfig};
use std::time::Duration;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit/gradient_controller");

    g.bench_function("record_rtt", |b| {
        let mut gc = GradientController::new(GradientConfig::default());
        let mut rtt = 5_000u64;
        b.iter(|| {
            rtt = rtt.wrapping_add(1) % 20_000 + 1;
            gc.record_rtt(Duration::from_micros(rtt));
            black_box(())
        })
    });

    g.bench_function("recalculate", |b| {
        let mut gc = GradientController::new(GradientConfig::default());
        for i in 0..64 {
            gc.record_rtt(Duration::from_millis(5 + i));
        }
        b.iter(|| {
            gc.recalculate();
            black_box(gc.concurrency_limit())
        })
    });

    g.bench_function("should_allow", |b| {
        let mut gc = GradientController::new(GradientConfig::default());
        for i in 0..64 {
            gc.record_rtt(Duration::from_millis(5 + i));
        }
        gc.recalculate();
        b.iter(|| black_box(gc.should_allow()))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
