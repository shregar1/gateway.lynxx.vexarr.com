//! Benchmark: ngx_inet6_addr — IPv6 colon-hex to 16-byte array
//! Group: inet | Algo: inet6_addr

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::ngx_inet6_addr;

const ADDRS: &[(&str, &[u8])] = &[
    ("loopback", b"::1"),
    ("full", b"2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("compressed", b"fe80::1ff:fe23:4567:890a"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/inet6_addr");
    for &(name, addr) in ADDRS {
        g.bench_with_input(BenchmarkId::new("parse", name), &addr, |b, &addr| {
            let mut out = [0u8; 16];
            b.iter(|| black_box(ngx_inet6_addr(addr, &mut out)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
