//! Benchmark: PatternMatcher — prefix/suffix/exact/contains matcher
//! Group: pattern | Algo: pattern_matcher

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::pattern::pattern_matcher::PatternMatcher;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("pattern/pattern_matcher");

    let mut pm = PatternMatcher::new();
    pm.add_pattern("/api/*");
    pm.add_pattern("*.json");
    pm.add_pattern("exact:/health");
    pm.add_pattern("contains:admin");

    let inputs = vec![
        "/api/v1/users",
        "data.json",
        "/health",
        "/admin/dashboard",
        "/static/style.css",
    ];

    g.bench_function("matches_5_patterns", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            idx = (idx + 1) % inputs.len();
            black_box(pm.matches(inputs[idx]))
        })
    });

    g.bench_function("add_pattern", |b| {
        b.iter(|| {
            let mut pm = PatternMatcher::new();
            pm.add_pattern("/api/*");
            pm.add_pattern("*.html");
            pm.add_pattern("exact:/ready");
            black_box(&pm);
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
