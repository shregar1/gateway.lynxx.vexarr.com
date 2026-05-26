//! Benchmark: ngx_parse_size — human-readable size parser
//! Group: parse | Algo: parse_size

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::ngx_parse_size;

const INPUTS: &[(&str, &[u8])] = &[
    ("plain", b"4096"),
    ("kilo", b"64k"),
    ("mega", b"16m"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse/parse_size");
    for &(name, input) in INPUTS {
        g.bench_with_input(BenchmarkId::new("ngx_parse_size", name), &input, |b, &input| {
            b.iter(|| black_box(ngx_parse_size(input)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
