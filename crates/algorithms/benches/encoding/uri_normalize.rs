//! Benchmark: uri_normalize — URI path canonicalization
//! Group: encoding | Algo: uri_normalize

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::encode::uri_normalize::normalize_uri_path;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/uri_normalize");

    let cases: &[(&str, &[u8])] = &[
        ("clean", b"/api/v1/users/123"),
        ("single_dot", b"/api/./v1/./users"),
        ("double_dot", b"/api/v1/internal/../users/./profile"),
        ("multi_slash", b"/api///v1//users///123"),
        ("complex", b"/a/b/c/./../../g/h/../i/./j"),
        ("deep", b"/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"),
    ];

    for &(name, path) in cases {
        g.throughput(Throughput::Bytes(path.len() as u64));
        g.bench_with_input(BenchmarkId::new("normalize", name), &path, |b, &data| {
            b.iter(|| black_box(normalize_uri_path(black_box(data))))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
