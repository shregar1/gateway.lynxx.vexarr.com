//! Benchmark: AdmissionController — client-side adaptive admission control
//! Group: rate_limit | Algo: admission_control

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::rate_limit::admission_control::AdmissionController;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit/admission_control");

    g.bench_function("record_and_check", |b| {
        let mut ac = AdmissionController::new(1024);
        let mut i = 0u64;
        b.iter(|| {
            i = i.wrapping_add(1);
            ac.record(i % 3 != 0); // ~67% success rate
            black_box(ac.should_admit())
        })
    });

    g.bench_function("rejection_probability", |b| {
        let mut ac = AdmissionController::new(1024);
        for i in 0..1000u64 {
            ac.record(i % 4 != 0);
        }
        b.iter(|| black_box(ac.rejection_probability()))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
