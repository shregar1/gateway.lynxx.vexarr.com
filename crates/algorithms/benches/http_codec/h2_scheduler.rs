//! Benchmark: h2_scheduler — HTTP/2 dependency-tree scheduler
//! Group: http_codec | Algo: h2_scheduler

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::http_codec::H2Scheduler;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("http_codec/h2_scheduler");

    // schedule with N active streams
    for &n in &[4u32, 16, 64] {
        g.bench_with_input(BenchmarkId::new("schedule", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let mut sched = H2Scheduler::new();
                    for id in 1..=n {
                        sched.add_stream(id, (id * 7 % 256 + 1) as u16, None, false);
                        sched.activate(id);
                    }
                    sched
                },
                |mut sched| {
                    for _ in 0..n {
                        black_box(sched.schedule());
                    }
                },
            )
        });
    }

    // add_stream throughput
    g.bench_function("add_stream/100", |b| {
        b.iter_with_setup(H2Scheduler::new, |mut sched| {
            for id in 1..=100u32 {
                sched.add_stream(
                    black_box(id),
                    black_box(16),
                    black_box(None),
                    black_box(false),
                );
            }
        })
    });

    // reprioritize
    g.bench_function("reprioritize/50", |b| {
        b.iter_with_setup(
            || {
                let mut sched = H2Scheduler::new();
                for id in 1..=50u32 {
                    sched.add_stream(id, 16, None, false);
                }
                sched
            },
            |mut sched| {
                for id in 1..=50u32 {
                    sched.reprioritize(
                        black_box(id),
                        black_box(128),
                        black_box(Some(0)),
                        black_box(false),
                    );
                }
            },
        )
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
