//! Benchmark: Base64 decode original vs optimized single-pass
//! Compares: ngx_decode_base64 vs decode_base64_fast

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nginx_algo::base64::ngx_decode_base64;
use algorithms::goals::optimized::base64_decode::decode_base64_fast;

fn make_base64_input(decoded_size: usize) -> Vec<u8> {
    // Create a base64 string of known content
    let raw: Vec<u8> = (0..decoded_size).map(|i| (i & 0xff) as u8).collect();
    let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity((decoded_size * 4 + 2) / 3);

    let mut i = 0;
    while i + 3 <= raw.len() {
        let b0 = raw[i];
        let b1 = raw[i + 1];
        let b2 = raw[i + 2];
        encoded.push(b64_chars[(b0 >> 2) as usize]);
        encoded.push(b64_chars[(((b0 & 3) << 4) | (b1 >> 4)) as usize]);
        encoded.push(b64_chars[(((b1 & 0xf) << 2) | (b2 >> 6)) as usize]);
        encoded.push(b64_chars[(b2 & 0x3f) as usize]);
        i += 3;
    }

    if i + 1 == raw.len() {
        let b0 = raw[i];
        encoded.push(b64_chars[(b0 >> 2) as usize]);
        encoded.push(b64_chars[((b0 & 3) << 4) as usize]);
        encoded.push(b'=');
        encoded.push(b'=');
    } else if i + 2 == raw.len() {
        let b0 = raw[i];
        let b1 = raw[i + 1];
        encoded.push(b64_chars[(b0 >> 2) as usize]);
        encoded.push(b64_chars[(((b0 & 3) << 4) | (b1 >> 4)) as usize]);
        encoded.push(b64_chars[((b1 & 0xf) << 2) as usize]);
        encoded.push(b'=');
    }

    encoded
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("optimized/base64_decode");

    for &decoded_size in &[16usize, 64, 256, 1024, 4096] {
        let input = make_base64_input(decoded_size);
        let label = format!("{}B_decoded", decoded_size);

        g.bench_with_input(
            BenchmarkId::new("ngx_decode_base64", &label),
            &input,
            |b, input| {
                let mut dst = vec![0u8; input.len()];
                b.iter(|| black_box(ngx_decode_base64(&mut dst, input)))
            },
        );

        g.bench_with_input(
            BenchmarkId::new("decode_base64_fast", &label),
            &input,
            |b, input| {
                let mut dst = vec![0u8; input.len()];
                b.iter(|| black_box(decode_base64_fast(&mut dst, input)))
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
