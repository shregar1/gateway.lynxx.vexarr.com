//! Benchmark: ngx_atosz — ASCII to ssize_t
//! Group: parse | Algo: atosz

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::ngx_atosz;

const INPUTS: &[(&str, &[u8])] = &[
    ("small", b"42"),
    ("medium", b"123456"),
    ("large", b"2147483647"),
    ("negative", b"-98765"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse/atosz");
    for &(name, input) in INPUTS {
        g.bench_with_input(BenchmarkId::new("atosz", name), &input, |b, &input| {
            b.iter(|| black_box(ngx_atosz(input)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
