//! Benchmark: ngx_split_clients_pick — A/B test traffic splitting
//! Group: inet | Algo: split_clients

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::ngx_split_clients_pick;

const BUCKET_COUNTS: &[usize] = &[2, 5, 20, 100];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/split_clients");
    for &n in BUCKET_COUNTS {
        let step = u32::MAX / n as u32;
        let cuts: Vec<u32> = (1..=n).map(|i| step * i as u32).collect();
        g.bench_with_input(BenchmarkId::new("pick", n), &cuts, |b, cuts| {
            let mut hash: u32 = 0;
            b.iter(|| {
                hash = hash.wrapping_add(0xDEAD);
                black_box(ngx_split_clients_pick(hash, cuts))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
