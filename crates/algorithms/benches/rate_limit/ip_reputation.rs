//! Benchmark: IpReputation — multi-tier sieve-LRU IP reputation
//! Group: rate_limit | Algo: ip_reputation

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::rate_limit::ip_reputation::{IpReputation, SieveConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn make_config() -> SieveConfig {
    SieveConfig {
        bucket_sizes: vec![1024, 256, 64],
        max_age: Duration::from_secs(300),
        perma_block_size: 128,
        perma_block_duration: Duration::from_secs(3600),
        block_threshold: 10,
    }
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("rate_limit/ip_reputation");

    // record_hit
    g.bench_function("record_hit", |b| {
        let mut rep = IpReputation::new(make_config());
        let mut octet = 0u8;
        b.iter(|| {
            octet = octet.wrapping_add(1);
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            black_box(rep.record_hit(ip))
        })
    });

    // reputation lookup
    g.bench_function("reputation_lookup", |b| {
        let mut rep = IpReputation::new(make_config());
        for i in 0..200u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            rep.record_hit(ip);
        }
        let mut octet = 0u8;
        b.iter(|| {
            octet = octet.wrapping_add(1);
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            black_box(rep.reputation(&ip))
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
