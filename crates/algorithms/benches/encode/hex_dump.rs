//! Benchmark: ngx_hex_dump
//! Group: encode | Algo: hex_dump

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_hex_dump;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encode/hex_dump");
    for &sz in SIZES {
        let src = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("hex_dump", sz), &src, |b, src| {
            let mut dst = vec![0u8; src.len() * 3];
            b.iter(|| black_box(ngx_hex_dump(&mut dst, src)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
