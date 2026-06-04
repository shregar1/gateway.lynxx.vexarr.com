//! Benchmark: Snowflake mutex vs lock-free atomic generator

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::hash::snowflake::SnowflakeGenerator;
use algorithms::goals::optimized::SnowflakeGeneratorFast;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("optimized/snowflake");

    g.bench_function("SnowflakeGenerator::generate", |b| {
        let gen = SnowflakeGenerator::new(1);
        b.iter(|| black_box(gen.generate().0));
    });

    g.bench_function("SnowflakeGeneratorFast::generate", |b| {
        let gen = SnowflakeGeneratorFast::new(1);
        b.iter(|| black_box(gen.generate().0));
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
