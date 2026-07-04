//! Benchmark: ngx_http_sub_filter — multi-pattern stream substitution
//! Group: string | Algo: sub_filter

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lynxx_algo::{SubMatch, ngx_http_sub_init_tables, ngx_http_sub_find};

const SIZES: &[usize] = &[256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    let base = b"The quick brown fox jumps over the lazy dog. ";
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let remaining = n - v.len();
        let chunk = if remaining >= base.len() { base.len() } else { remaining };
        v.extend_from_slice(&base[..chunk]);
    }
    v
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("string/sub_filter");
    for &sz in SIZES {
        let hay = payload(sz);
        let mut matches = vec![
            SubMatch::new(b"fox".to_vec()),
            SubMatch::new(b"dog".to_vec()),
        ];
        let tables = ngx_http_sub_init_tables(&mut matches).unwrap();
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("find", sz), &sz, |b, _| {
            b.iter(|| black_box(ngx_http_sub_find(&hay, &matches, &tables)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
