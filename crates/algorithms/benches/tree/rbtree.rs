//! Benchmark: RbTree — red-black tree
//! Group: tree | Algo: rbtree

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::tree::rbtree::RbTree;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("tree/rbtree");

    g.bench_function("insert_100", |b| {
        b.iter(|| {
            let mut t = RbTree::new();
            for i in 0..100u64 {
                t.insert(i, i * 10);
            }
            black_box(&t);
        })
    });

    g.bench_function("get_hit", |b| {
        let mut t = RbTree::new();
        for i in 0..1000u64 {
            t.insert(i, i * 10);
        }
        let mut key = 0u64;
        b.iter(|| {
            key = (key + 7) % 1000;
            black_box(t.get(&key))
        })
    });

    g.bench_function("get_miss", |b| {
        let mut t = RbTree::new();
        for i in 0..1000u64 {
            t.insert(i * 2, i);
        }
        let mut key = 1u64;
        b.iter(|| {
            key = key.wrapping_add(2) % 2001;
            black_box(t.get(&key))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
