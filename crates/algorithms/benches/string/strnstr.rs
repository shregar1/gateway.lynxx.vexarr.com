//! Benchmark: ngx_strnstr — bounded substring search
//! Group: string | Algo: strnstr

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_strnstr;

const SIZES: &[usize] = &[64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'a' + (i % 26) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("string/strnstr");
    for &sz in SIZES {
        let mut hay = payload(sz);
        hay[sz - 4..sz - 1].copy_from_slice(b"xyz");
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("found_end", sz), &sz, |b, _| {
            b.iter(|| black_box(ngx_strnstr(&hay, "xyz")))
        });
        g.bench_with_input(BenchmarkId::new("not_found", sz), &sz, |b, _| {
            let hay2 = payload(sz);
            b.iter(|| black_box(ngx_strnstr(&hay2, "ZZZ")))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
