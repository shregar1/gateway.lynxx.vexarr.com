//! Benchmark: ngx_decode_base64
//! Group: encode | Algo: base64_decode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lynxx_algo::{ngx_encode_base64, ngx_decode_base64};

const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encode/base64_decode");
    for &sz in SIZES {
        let src = payload(sz);
        let mut enc = vec![0u8; sz * 2];
        let enc_len = ngx_encode_base64(&mut enc, &src);
        g.throughput(Throughput::Bytes(enc_len as u64));
        g.bench_with_input(BenchmarkId::new("decode", sz), &sz, |b, _| {
            let mut dst = vec![0u8; sz];
            b.iter(|| black_box(ngx_decode_base64(&mut dst, &enc[..enc_len])))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
