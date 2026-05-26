//! Benchmark: ngx_http_v3_encode_varlen_int
//! Group: codec | Algo: h3_varint_encode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::ngx_http_v3_encode_varlen_int;

const VALUES: &[(&str, u64)] = &[
    ("1byte", 37),
    ("2byte", 15293),
    ("4byte", 494878333),
    ("8byte", 151288809941952652),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/h3_varint_encode");
    for &(name, val) in VALUES {
        g.bench_with_input(BenchmarkId::new("encode", name), &val, |b, &val| {
            let mut dst = [0u8; 8];
            b.iter(|| black_box(ngx_http_v3_encode_varlen_int(&mut dst, val)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
