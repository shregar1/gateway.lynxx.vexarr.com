//! Benchmark: ngx_unescape_uri
//! Group: encode | Algo: unescape_uri

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::{ngx_escape_uri, ngx_unescape_uri};

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| {
        let c = (i % 128) as u8;
        if c.is_ascii_alphanumeric() { c } else { b'<' }
    }).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encode/unescape_uri");
    for &sz in SIZES {
        let src = payload(sz);
        let mut enc = vec![0u8; sz * 3];
        let elen = ngx_escape_uri(&mut enc, &src);
        g.throughput(Throughput::Bytes(elen as u64));
        g.bench_with_input(BenchmarkId::new("unescape", sz), &sz, |b, _| {
            let mut dst = vec![0u8; elen];
            b.iter(|| black_box(ngx_unescape_uri(&mut dst, &enc[..elen], true)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
