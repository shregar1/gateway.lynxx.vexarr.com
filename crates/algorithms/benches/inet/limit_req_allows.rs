//! Benchmark: ngx_limit_req_allows — burst admission check
//! Group: inet | Algo: limit_req_allows

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::ngx_limit_req_allows;

const SCENARIOS: &[(&str, i32, u32)] = &[
    ("under_burst", 50, 100),
    ("at_burst", 100, 100),
    ("over_burst", 150, 100),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("inet/limit_req_allows");
    for &(name, excess, burst) in SCENARIOS {
        g.bench_with_input(BenchmarkId::new("allows", name), &(excess, burst), |b, &(excess, burst)| {
            b.iter(|| black_box(ngx_limit_req_allows(excess, burst)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
