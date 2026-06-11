//! Benchmark: RadixTree — compressed trie for routing
//! Group: tree | Algo: radix_tree

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::tree::radix_tree::RadixTree;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("tree/radix_tree");

    let routes: Vec<&[u8]> = vec![
        b"/api/v1/users", b"/api/v1/posts", b"/api/v2/users",
        b"/static/css", b"/static/js", b"/static/img",
        b"/health", b"/ready", b"/metrics",
    ];

    g.bench_function("insert_9", |b| {
        b.iter(|| {
            let mut t = RadixTree::new();
            for (i, r) in routes.iter().enumerate() {
                t.insert(r, i);
            }
            black_box(&t);
        })
    });

    g.bench_function("lookup_hit", |b| {
        let mut t = RadixTree::new();
        for (i, r) in routes.iter().enumerate() {
            t.insert(r, i);
        }
        let mut idx = 0usize;
        b.iter(|| {
            idx = (idx + 1) % routes.len();
            black_box(t.lookup(routes[idx]))
        })
    });

    g.bench_function("longest_prefix_match", |b| {
        let mut t = RadixTree::new();
        for (i, r) in routes.iter().enumerate() {
            t.insert(r, i);
        }
        b.iter(|| black_box(t.longest_prefix_match(b"/api/v1/users/123/profile")))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
