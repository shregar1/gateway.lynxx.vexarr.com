//! Benchmark: ngx_inet_addr — IPv4 dotted-decimal to u32
//! Group: inet | Algo: inet_addr_v4

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::ngx_inet_addr;

const ADDRS: &[(&str, &[u8])] = &[
    ("loopback", b"127.0.0.1"),
    ("private", b"192.168.1.100"),
    ("public", b"203.0.113.42"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/inet_addr_v4");
    for &(name, addr) in ADDRS {
        g.bench_with_input(BenchmarkId::new("parse", name), &addr, |b, &addr| {
            b.iter(|| black_box(ngx_inet_addr(addr)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
