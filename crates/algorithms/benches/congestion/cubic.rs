//! Benchmark: CubicState — CUBIC congestion control
//! Group: congestion | Algo: cubic

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::congestion::cubic::CubicState;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("congestion/cubic");

    g.bench_function("on_ack_steady", |b| {
        let mut cubic = CubicState::new();
        cubic.on_loss(0);
        let mut now = 100u64;
        b.iter(|| {
            now += 1;
            cubic.on_ack(now);
            black_box(cubic.cwnd())
        })
    });

    g.bench_function("on_loss", |b| {
        let mut cubic = CubicState::new();
        for i in 0..100 {
            cubic.on_ack(i);
        }
        let mut now = 100u64;
        b.iter(|| {
            now += 1;
            cubic.on_loss(now);
            black_box(cubic.cwnd())
        })
    });

    g.bench_function("ack_loss_cycle", |b| {
        let mut cubic = CubicState::new();
        let mut now = 0u64;
        b.iter(|| {
            for _ in 0..10 {
                now += 1;
                cubic.on_ack(now);
            }
            now += 1;
            cubic.on_loss(now);
            black_box(cubic.cwnd())
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
