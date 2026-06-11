//! Benchmark: ttl_calc — Cache TTL computation per RFC 9111
//! Group: http_codec | Algo: ttl_calc

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::http_codec::{TtlInput, compute_ttl, is_fresh};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("http_codec/ttl_calc");

    let inputs: Vec<(&str, TtlInput)> = vec![
        ("s_maxage", TtlInput {
            date: 1_000_000, now: 1_000_000,
            max_age: Some(60), s_maxage: Some(300),
            expires: None, last_modified: None,
        }),
        ("max_age", TtlInput {
            date: 1_000_000, now: 1_000_050,
            max_age: Some(120), s_maxage: None,
            expires: None, last_modified: None,
        }),
        ("expires", TtlInput {
            date: 1_000_000, now: 1_000_000,
            max_age: None, s_maxage: None,
            expires: Some(1_000_200), last_modified: None,
        }),
        ("heuristic", TtlInput {
            date: 1_000_000, now: 1_000_000,
            max_age: None, s_maxage: None,
            expires: None, last_modified: Some(900_000),
        }),
        ("none", TtlInput {
            date: 1_000_000, now: 1_000_000,
            max_age: None, s_maxage: None,
            expires: None, last_modified: None,
        }),
    ];

    for (name, input) in &inputs {
        g.bench_with_input(BenchmarkId::new("compute_ttl", name), input, |b, input| {
            b.iter(|| black_box(compute_ttl(black_box(input))))
        });
    }

    // is_fresh benchmark
    let result = compute_ttl(&inputs[0].1);
    g.bench_function("is_fresh", |b| {
        b.iter(|| black_box(is_fresh(black_box(&result), black_box(1_000_100), black_box(1_000_000))))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
