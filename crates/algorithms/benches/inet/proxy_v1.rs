//! Benchmark: ngx_proxy_protocol_v1_parse_inet
//! Group: inet | Algo: proxy_v1

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nginx_algo::{ngx_proxy_protocol_v1_parse_inet, ProxyV2Inet};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/proxy_v1");
    let header = b"PROXY TCP4 192.168.1.1 10.0.0.1 12345 80\r\n";
    g.bench_function("parse_v1", |b| {
        let mut out = ProxyV2Inet {
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
        };
        b.iter(|| black_box(ngx_proxy_protocol_v1_parse_inet(header, &mut out)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
