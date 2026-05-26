//! Benchmark: ngx_http_v3_decode_varlen_int
//! Group: codec | Algo: h3_varint_decode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::{ngx_http_v3_encode_varlen_int, ngx_http_v3_decode_varlen_int};

const VALUES: &[(&str, u64)] = &[
    ("1byte", 37),
    ("2byte", 15293),
    ("4byte", 494878333),
    ("8byte", 151288809941952652),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/h3_varint_decode");
    for &(name, val) in VALUES {
        let mut buf = [0u8; 8];
        let len = ngx_http_v3_encode_varlen_int(&mut buf, val);
        g.bench_with_input(BenchmarkId::new("decode", name), &len, |b, &len| {
            b.iter(|| black_box(ngx_http_v3_decode_varlen_int(&buf[..len])))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
