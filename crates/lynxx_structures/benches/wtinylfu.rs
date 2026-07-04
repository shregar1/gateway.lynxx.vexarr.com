//! Benchmark: W-TinyLFU cache (paper)
//! Group: structures | Algo: wtinylfu

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_structures::WTinyLfu;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("structures_wtinylfu");

    for cap in [256usize, 1024, 4096] {
        g.bench_with_input(BenchmarkId::new("insert_get_cycle", cap), &cap, |b, &cap| {
            b.iter(|| {
                let mut cache = WTinyLfu::new(cap);
                for i in 0..cap {
                    cache.insert(i, i);
                    black_box(cache.get(&(i % cap)));
                }
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
