//! Benchmark: ngx_proxy_protocol_v2_parse_inet
//! Group: inet | Algo: proxy_v2

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lynxx_algo::{ngx_proxy_protocol_v2_parse_inet, ProxyV2Inet};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/proxy_v2");
    let header: Vec<u8> = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        0x21, 0x11, 0x00, 0x0C,
        192, 168, 1, 1,
        10, 0, 0, 1,
        0x30, 0x39,
        0x00, 0x50,
    ];
    g.bench_function("parse_v2", |b| {
        let mut out = ProxyV2Inet {
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
        };
        b.iter(|| black_box(ngx_proxy_protocol_v2_parse_inet(&header, &mut out)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
