//! Benchmark: ngx_escape_uri — URI percent-encoding
//! Group: encode | Algo: escape_uri

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lynxx_algo::ngx_escape_uri;

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| {
        let c = (i % 128) as u8;
        if c.is_ascii_alphanumeric() { c } else { b'<' }
    }).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encode/escape_uri");
    for &sz in SIZES {
        let src = payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("escape", sz), &src, |b, src| {
            let mut dst = vec![0u8; src.len() * 3];
            b.iter(|| black_box(ngx_escape_uri(&mut dst, src)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
