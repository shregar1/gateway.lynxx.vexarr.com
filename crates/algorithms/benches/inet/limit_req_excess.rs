//! Benchmark: ngx_limit_req_excess — leaky bucket excess calculation
//! Group: inet | Algo: limit_req_excess

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::ngx_limit_req_excess;

const RATES: &[u32] = &[100, 1000, 10000];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/limit_req_excess");
    for &rate in RATES {
        g.bench_with_input(BenchmarkId::new("excess", rate), &rate, |b, &rate| {
            b.iter(|| black_box(ngx_limit_req_excess(0, rate, 1000, 999)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
