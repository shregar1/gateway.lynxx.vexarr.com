//! Benchmark: accept_encoding — HTTP Accept-Encoding negotiation
//! Group: encoding | Algo: accept_encoding

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::encode::accept_encoding::{parse_accept_encoding, select_encoding};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/accept_encoding");

    let headers: &[(&str, &str)] = &[
        ("simple", "gzip, deflate"),
        ("with_quality", "gzip;q=1.0, br;q=0.8, deflate;q=0.5, identity;q=0.1"),
        ("wildcard", "br, gzip, *;q=0.1"),
        ("complex", "zstd;q=1.0, br;q=0.9, gzip;q=0.8, deflate;q=0.7, compress;q=0.5, identity;q=0.1"),
    ];

    for &(name, header) in headers {
        g.bench_with_input(BenchmarkId::new("parse", name), &header, |b, &header| {
            b.iter(|| black_box(parse_accept_encoding(black_box(header))))
        });
    }

    let supported = &["gzip", "br", "zstd"];
    for &(name, header) in headers {
        let prefs = parse_accept_encoding(header);
        g.bench_with_input(BenchmarkId::new("select", name), &prefs, |b, prefs| {
            b.iter(|| black_box(select_encoding(black_box(prefs), black_box(supported))))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
