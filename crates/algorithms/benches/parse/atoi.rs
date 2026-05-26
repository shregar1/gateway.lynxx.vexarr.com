//! Benchmark: ngx_atoi — ASCII to integer (signed)
//! Group: parse | Algo: atoi

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::ngx_atoi;

const INPUTS: &[(&str, &[u8])] = &[
    ("small", b"42"),
    ("medium", b"123456"),
    ("large", b"2147483647"),
    ("negative", b"-98765"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse/atoi");
    for &(name, input) in INPUTS {
        g.bench_with_input(BenchmarkId::new("atoi", name), &input, |b, &input| {
            b.iter(|| black_box(ngx_atoi(input)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
