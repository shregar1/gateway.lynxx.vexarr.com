//! Benchmark: ngx_hextoi — hex string to integer
//! Group: encode | Algo: hextoi

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::ngx_hextoi;

const INPUTS: &[(&str, &[u8])] = &[
    ("small", b"FF"),
    ("medium", b"DEADBEEF"),
    ("large", b"7FFFFFFF"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encode/hextoi");
    for &(name, input) in INPUTS {
        g.bench_with_input(BenchmarkId::new("hextoi", name), &input, |b, &input| {
            b.iter(|| black_box(ngx_hextoi(input)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
