//! Benchmark: ngx_ip_hash_select — IP hash upstream selection
//! Group: inet | Algo: ip_hash

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::ngx_ip_hash_select;

const CLUSTER_SIZES: &[usize] = &[3, 10, 100, 500];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/ip_hash");
    let addr: [u8; 4] = [192, 168, 1, 42];
    for &sz in CLUSTER_SIZES {
        let weights: Vec<u32> = (0..sz).map(|i| ((i % 5) + 1) as u32).collect();
        let total: u32 = weights.iter().sum();
        g.bench_with_input(BenchmarkId::new("select", sz), &sz, |b, _| {
            b.iter(|| black_box(ngx_ip_hash_select(&addr, total, &weights)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
