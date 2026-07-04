//! Benchmark: BbrState — BBR congestion control
//! Group: congestion | Algo: bbr

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::congestion::bbr::BbrState;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("congestion/bbr");

    g.bench_function("on_ack", |b| {
        let mut bbr = BbrState::new();
        let mut now = 0u64;
        b.iter(|| {
            now += 1;
            bbr.on_ack(10_000, 14_000, now);
            black_box(bbr.cwnd())
        })
    });

    g.bench_function("on_loss", |b| {
        let mut bbr = BbrState::new();
        for i in 0..10 {
            bbr.on_ack(10_000, 14_000, i);
        }
        b.iter(|| {
            bbr.on_loss();
            black_box(bbr.cwnd())
        })
    });

    g.bench_function("pacing_rate", |b| {
        let mut bbr = BbrState::new();
        for i in 0..10 {
            bbr.on_ack(10_000, 14_000, i);
        }
        b.iter(|| black_box(bbr.pacing_rate()))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
