//! Benchmark: vary_key — Vary header parsing and key computation
//! Group: http_codec | Algo: vary_key

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::http_codec::{compute_vary_key, parse_vary_fields};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("http_codec/vary_key");

    // parse_vary_fields
    for &(name, header) in &[
        ("single", "Accept-Encoding"),
        ("triple", "Accept-Encoding, Accept-Language, Cookie"),
        ("many", "Accept, Accept-Encoding, Accept-Language, Cookie, User-Agent, Referer"),
    ] {
        g.bench_with_input(BenchmarkId::new("parse", name), &header, |b, &header| {
            b.iter(|| black_box(parse_vary_fields(header)))
        });
    }

    // compute_vary_key
    let pairs_small: Vec<(&str, &str)> = vec![("accept-encoding", "gzip")];
    let pairs_large: Vec<(&str, &str)> = vec![
        ("accept", "text/html"),
        ("accept-encoding", "gzip, br"),
        ("accept-language", "en-US"),
        ("cookie", "session=abc123def456"),
        ("user-agent", "Mozilla/5.0"),
    ];

    g.bench_function("compute/1_pair", |b| {
        b.iter(|| black_box(compute_vary_key(black_box(&pairs_small))))
    });

    g.bench_function("compute/5_pairs", |b| {
        b.iter(|| black_box(compute_vary_key(black_box(&pairs_large))))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
