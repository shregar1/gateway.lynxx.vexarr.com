//! Benchmark: vary_encode — compact binary Vary key
//! Group: encoding | Algo: vary_encode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::encode::vary_encode::VaryKeyBuilder;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/vary_encode");

    let scenarios: &[(&str, &[(&str, &str)])] = &[
        ("single", &[("Accept-Encoding", "gzip")]),
        ("two_fields", &[("Accept-Encoding", "gzip"), ("Accept-Language", "en-US")]),
        ("typical", &[
            ("Accept-Encoding", "gzip, br"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("User-Agent", "Mozilla/5.0"),
        ]),
        ("many_fields", &[
            ("Accept-Encoding", "gzip"),
            ("Accept-Language", "en"),
            ("Accept", "text/html"),
            ("Host", "example.com"),
            ("Cookie", "session=abc123"),
            ("X-Forwarded-For", "192.168.1.1"),
            ("X-Request-Id", "550e8400-e29b-41d4-a716-446655440000"),
        ]),
    ];

    for &(name, fields) in scenarios {
        g.bench_with_input(BenchmarkId::new("build", name), &fields, |b, &fields| {
            b.iter(|| {
                let mut builder = VaryKeyBuilder::new();
                for &(k, v) in fields {
                    builder.add_field(black_box(k), black_box(v));
                }
                black_box(builder.build())
            })
        });
    }

    // add_field only
    g.bench_function("add_field_x100", |b| {
        b.iter(|| {
            let mut builder = VaryKeyBuilder::new();
            for i in 0..100 {
                let name = if i % 3 == 0 { "Accept-Encoding" } else if i % 3 == 1 { "Accept-Language" } else { "Host" };
                builder.add_field(black_box(name), black_box("some-value"));
            }
            black_box(builder.build())
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
