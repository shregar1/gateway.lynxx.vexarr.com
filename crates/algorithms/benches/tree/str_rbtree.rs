//! Benchmark: StrRbTree — string-keyed red-black tree
//! Group: tree | Algo: str_rbtree

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::tree::str_rbtree::StrRbTree;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("tree/str_rbtree");

    let keys: Vec<String> = (0..100).map(|i| format!("header-key-{:04}", i)).collect();

    g.bench_function("insert_100", |b| {
        b.iter(|| {
            let mut t = StrRbTree::new();
            for (i, k) in keys.iter().enumerate() {
                t.insert(k, i);
            }
            black_box(&t);
        })
    });

    g.bench_function("get_hit", |b| {
        let mut t = StrRbTree::new();
        for (i, k) in keys.iter().enumerate() {
            t.insert(k, i);
        }
        let mut idx = 0usize;
        b.iter(|| {
            idx = (idx + 1) % keys.len();
            black_box(t.get(&keys[idx]))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
