//! Benchmark: ARC cache cold vs hot (MRU) get paths

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_structures::ArcCache;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("structures_arc_cache_paths");

    for cap in [1024usize, 4096] {
        g.bench_with_input(BenchmarkId::new("get_mru_hot", cap), &cap, |b, &cap| {
            let mut cache = ArcCache::new(cap);
            for i in 0..cap {
                cache.insert(i, i);
            }
            let hot = cap - 1;
            cache.get(&hot);
            // `get` returns `Option<&V>` borrowing `cache`; a bare
            // `|| black_box(cache.get(&hot))` would let that reference escape the
            // FnMut. Discard it inside the closure body so it returns `()`.
            b.iter(|| {
                black_box(cache.get(&hot));
            });
        });

        g.bench_with_input(BenchmarkId::new("get_cold_promote", cap), &cap, |b, &cap| {
            let mut cache = ArcCache::new(cap);
            for i in 0..cap {
                cache.insert(i, i);
            }
            let cold = 0usize;
            b.iter(|| {
                black_box(cache.get(&cold));
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
