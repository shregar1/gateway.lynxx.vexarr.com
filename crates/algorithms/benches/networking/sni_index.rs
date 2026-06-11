//! Benchmark: sni_index — SNI-indexed policy fast path
//! Group: networking | Algo: sni_index

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::networking::SniIndex;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("networking/sni_index");

    // Lookup in index of various sizes
    for &n in &[10u32, 100, 1000] {
        g.bench_with_input(BenchmarkId::new("lookup_exact", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let mut idx = SniIndex::new();
                    for i in 0..n {
                        idx.insert(&format!("host{i}.example.com"), i);
                    }
                    idx
                },
                |idx| {
                    // Lookup a known key near the middle
                    black_box(idx.lookup(black_box(&format!("host{}.example.com", n / 2))));
                },
            )
        });
    }

    // Wildcard fallback lookup
    for &n in &[10u32, 100, 1000] {
        g.bench_with_input(BenchmarkId::new("lookup_wildcard", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let mut idx = SniIndex::new();
                    for i in 0..n {
                        idx.insert(&format!("*.domain{i}.com"), i);
                    }
                    idx
                },
                |idx| {
                    black_box(idx.lookup(black_box(&format!("app.domain{}.com", n / 2))));
                },
            )
        });
    }

    // Miss lookup
    g.bench_function("lookup/miss", |b| {
        let mut idx = SniIndex::new();
        for i in 0..100u32 {
            idx.insert(&format!("host{i}.example.com"), i);
        }
        b.iter(|| black_box(idx.lookup(black_box("nonexistent.other.com"))))
    });

    // Insert throughput
    g.bench_function("insert/1000", |b| {
        b.iter_with_setup(SniIndex::new, |mut idx: SniIndex<u32>| {
            for i in 0..1000u32 {
                idx.insert(black_box(&format!("host{i}.example.com")), black_box(i));
            }
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
