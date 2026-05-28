//! Benchmark: ngx_sort_legacy — insertion sort (NGINX parity)
//! Group: string | Algo: sort_legacy

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lynxx_algo::ngx_sort_legacy;

const SIZES: &[usize] = &[10, 100, 1000];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("string/sort_legacy");
    for &sz in SIZES {
        let data: Vec<i32> = (0..sz as i32).rev().collect();
        g.bench_with_input(BenchmarkId::new("sort_legacy", sz), &data, |b, data| {
            let mut copy = data.clone();
            b.iter(|| {
                copy.copy_from_slice(data);
                ngx_sort_legacy(&mut copy, |a, b| a - b);
                black_box(&copy);
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
