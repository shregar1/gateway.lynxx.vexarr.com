//! Benchmark: ngx_parse_time — time duration parser
//! Group: parse | Algo: parse_time

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::ngx_parse_time;

const INPUTS: &[(&str, &[u8], bool)] = &[
    ("seconds", b"30s", true),
    ("minutes", b"5m", false),
    ("hours", b"1h", false),
    ("plain_sec", b"120", true),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse/parse_time");
    for &(name, input, is_sec) in INPUTS {
        g.bench_with_input(BenchmarkId::new("ngx_parse_time", name), &(input, is_sec), |b, &(input, is_sec)| {
            b.iter(|| black_box(ngx_parse_time(input, is_sec)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
