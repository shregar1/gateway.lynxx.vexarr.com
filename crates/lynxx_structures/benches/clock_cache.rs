//! Benchmark: Clock (second-chance) cache (ATS)
//! Group: structures | Algo: clock_cache

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_structures::ClockCache;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("structures_clock_cache");

    for cap in [256usize, 1024, 4096] {
        g.bench_with_input(BenchmarkId::new("insert_get_cycle", cap), &cap, |b, &cap| {
            b.iter(|| {
                let mut cache = ClockCache::new(cap);
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
