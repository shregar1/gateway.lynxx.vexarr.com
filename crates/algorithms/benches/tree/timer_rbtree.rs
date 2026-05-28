//! Benchmark: TimerRbTree — timer wheel backed by BTreeMap
//! Group: tree | Algo: timer_rbtree

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::tree::timer_rbtree::TimerRbTree;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("tree/timer_rbtree");

    g.bench_function("add_timer", |b| {
        let mut tw = TimerRbTree::new();
        let mut id = 0u64;
        b.iter(|| {
            id += 1;
            tw.add_timer(id * 100, id);
            black_box(())
        })
    });

    g.bench_function("next_expired", |b| {
        let mut tw = TimerRbTree::new();
        for i in 0..10_000u64 {
            tw.add_timer(i * 10, i);
        }
        let mut now = 0u64;
        b.iter(|| {
            now += 10;
            black_box(tw.next_expired(now))
        })
    });

    g.bench_function("cancel", |b| {
        let mut tw = TimerRbTree::new();
        for i in 0..10_000u64 {
            tw.add_timer(i * 100, i);
        }
        let mut id = 0u64;
        b.iter(|| {
            id = (id + 1) % 10_000;
            black_box(tw.cancel(id))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
