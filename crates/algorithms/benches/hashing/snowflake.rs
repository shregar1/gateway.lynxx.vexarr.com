//! Benchmark: SnowflakeGenerator — unique ID generation
//! Group: hashing | Algo: snowflake

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::hash::SnowflakeGenerator;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashing/snowflake");
    let gen = SnowflakeGenerator::new(1);
    g.bench_function("generate", |b| {
        b.iter(|| black_box(gen.generate()))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
