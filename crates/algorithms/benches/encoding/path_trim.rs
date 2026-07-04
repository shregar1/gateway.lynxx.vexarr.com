//! Benchmark: path_trim — path prefix/suffix stripping
//! Group: encoding | Algo: path_trim

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::encode::path_trim::{strip_prefix, strip_suffix, trim_trailing_slash, ensure_trailing_slash};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/path_trim");

    let paths: &[(&str, &[u8])] = &[
        ("short", b"/api/v1/users"),
        ("medium", b"/api/v2/internal/resources/items/123/details"),
        ("long", b"/very/deep/nested/path/to/some/resource/in/the/application/api/v3/endpoint"),
    ];

    for &(name, path) in paths {
        g.throughput(Throughput::Bytes(path.len() as u64));

        g.bench_with_input(BenchmarkId::new("strip_prefix_hit", name), &path, |b, &data| {
            b.iter(|| black_box(strip_prefix(black_box(data), b"/api")))
        });

        g.bench_with_input(BenchmarkId::new("strip_prefix_miss", name), &path, |b, &data| {
            b.iter(|| black_box(strip_prefix(black_box(data), b"/web")))
        });

        g.bench_with_input(BenchmarkId::new("strip_suffix", name), &path, |b, &data| {
            b.iter(|| black_box(strip_suffix(black_box(data), b"/details")))
        });

        g.bench_with_input(BenchmarkId::new("trim_trailing_slash", name), &path, |b, &data| {
            b.iter(|| black_box(trim_trailing_slash(black_box(data))))
        });

        g.bench_with_input(BenchmarkId::new("ensure_trailing_slash", name), &path, |b, &data| {
            b.iter(|| black_box(ensure_trailing_slash(black_box(data))))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
