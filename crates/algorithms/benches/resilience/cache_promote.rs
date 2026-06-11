//! Benchmark: PromotionPolicy — hit/byte threshold admission control
//! Group: resilience | Algo: cache_promote

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::resilience::{PromotionPolicy, PromotionConfig, chance_promote};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("resilience/cache_promote");

    // should_promote — hit threshold
    for &threshold in &[1u32, 3, 10] {
        let config = PromotionConfig {
            hit_threshold: threshold,
            byte_threshold: 0,
            capacity: 8192,
        };
        g.bench_with_input(BenchmarkId::new("should_promote", threshold), &config, |b, config| {
            let mut policy = PromotionPolicy::new(config.clone());
            let mut hash = 0u64;
            b.iter(|| {
                hash = hash.wrapping_add(1);
                black_box(policy.should_promote(hash, 4096))
            })
        });
    }

    // chance_promote — probabilistic
    for &(name, prob) in &[("10pct", 0.1f64), ("50pct", 0.5), ("90pct", 0.9)] {
        g.bench_with_input(BenchmarkId::new("chance", name), &prob, |b, &prob| {
            b.iter(|| black_box(chance_promote(prob)))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
