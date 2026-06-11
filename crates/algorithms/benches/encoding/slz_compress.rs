//! Benchmark: SlzCompressor — stateless LZ77 compression
//! Group: encoding | Algo: slz_compress

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::encode::slz_compress::SlzCompressor;

const SIZES: &[usize] = &[256, 1024, 4096, 16384];

fn random_payload(n: usize) -> Vec<u8> {
    // Pseudo-random via simple LCG
    let mut val: u32 = 0xDEAD_BEEF;
    (0..n).map(|_| {
        val = val.wrapping_mul(1664525).wrapping_add(1013904223);
        (val >> 24) as u8
    }).collect()
}

fn repetitive_payload(n: usize) -> Vec<u8> {
    let pattern = b"The quick brown fox jumps over the lazy dog. ";
    pattern.iter().cycle().take(n).copied().collect()
}

fn html_payload(n: usize) -> Vec<u8> {
    let pattern = b"<div class=\"item\"><span>Hello World</span></div>\n";
    pattern.iter().cycle().take(n).copied().collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/slz_compress");

    for &sz in SIZES {
        let data = random_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("random", sz), &data, |b, data| {
            let mut compressor = SlzCompressor::new();
            let mut out = Vec::with_capacity(sz + 256);
            b.iter(|| {
                out.clear();
                compressor.reset();
                compressor.compress(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    for &sz in SIZES {
        let data = repetitive_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("repetitive", sz), &data, |b, data| {
            let mut compressor = SlzCompressor::new();
            let mut out = Vec::with_capacity(sz);
            b.iter(|| {
                out.clear();
                compressor.reset();
                compressor.compress(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    for &sz in SIZES {
        let data = html_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("html", sz), &data, |b, data| {
            let mut compressor = SlzCompressor::new();
            let mut out = Vec::with_capacity(sz);
            b.iter(|| {
                out.clear();
                compressor.reset();
                compressor.compress(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
