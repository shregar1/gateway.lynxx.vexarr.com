//! Benchmark: StampedeLock — cache thundering-herd prevention
//! Group: resilience | Algo: stampede_lock

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::resilience::stampede_lock::StampedeLock;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("resilience/stampede_lock");

    g.bench_function("acquire_release", |b| {
        let mut sl = StampedeLock::new();
        let mut key = 0u64;
        b.iter(|| {
            key = key.wrapping_add(1);
            sl.acquire(key);
            sl.release(key);
            black_box(())
        })
    });

    g.bench_function("try_lock", |b| {
        let mut sl = StampedeLock::new();
        // Pre-lock some keys
        for k in 0..100u64 {
            sl.acquire(k);
        }
        let mut key = 0u64;
        b.iter(|| {
            key = key.wrapping_add(1) % 200;
            black_box(sl.try_lock(key))
        })
    });

    g.bench_function("wait_count", |b| {
        let mut sl = StampedeLock::new();
        sl.acquire(42);
        for _ in 0..10 {
            sl.acquire(42); // add waiters
        }
        b.iter(|| black_box(sl.wait_count(42)))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
