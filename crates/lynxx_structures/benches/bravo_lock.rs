//! Benchmark: BRAVO reader-biased lock (ATS)
//! Group: structures | Algo: bravo_lock

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lynxx_structures::BravoLock;
use std::sync::Arc;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("structures_bravo_lock");

    g.bench_function("read_hot", |b| {
        let lock = Arc::new(BravoLock::new(0u64));
        b.iter(|| {
            let g = lock.read();
            black_box(*g.get());
        });
    });

    g.bench_function("read_write_mix", |b| {
        let lock = Arc::new(BravoLock::new(0u64));
        b.iter(|| {
            let g = lock.read();
            black_box(*g.get());
            let mut w = lock.write();
            *w += 1;
        });
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
