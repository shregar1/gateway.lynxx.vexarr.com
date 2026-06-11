//! Benchmark: ext_priority — RFC 9218 Extensible Priorities
//! Group: http_codec | Algo: ext_priority

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::http_codec::{ExtPriority, parse_priority, serialize_priority, compare_priority};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("http_codec/ext_priority");

    // parse
    for &(name, header) in &[
        ("urgency_only", "u=3"),
        ("with_incremental", "u=0, i"),
        ("bool_form", "u=5, i=?1"),
        ("extra_params", "u=2, i, x=42, y=99"),
    ] {
        g.bench_with_input(BenchmarkId::new("parse", name), &header, |b, &header| {
            b.iter(|| black_box(parse_priority(black_box(header))))
        });
    }

    // serialize
    let priorities = [
        ("low", ExtPriority { urgency: 7, incremental: false }),
        ("high_incr", ExtPriority { urgency: 0, incremental: true }),
    ];
    for (name, p) in &priorities {
        g.bench_with_input(BenchmarkId::new("serialize", name), p, |b, p| {
            b.iter(|| black_box(serialize_priority(black_box(p))))
        });
    }

    // compare
    let a = ExtPriority { urgency: 1, incremental: false };
    let b_pri = ExtPriority { urgency: 5, incremental: true };
    g.bench_function("compare", |b| {
        b.iter(|| black_box(compare_priority(black_box(&a), black_box(&b_pri))))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
