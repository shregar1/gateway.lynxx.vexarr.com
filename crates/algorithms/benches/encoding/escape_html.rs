//! Benchmark: escape_html — HTML entity escaping
//! Group: encoding | Algo: escape_html

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::encode::escape_html::{escape_html, needs_escape};

const SIZES: &[usize] = &[32, 128, 512, 2048, 8192];

fn plain_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'A' + (i % 26) as u8).collect()
}

fn mixed_payload(n: usize) -> Vec<u8> {
    let pattern = b"Hello <b>world</b> & \"friends\" it's great! ";
    pattern.iter().cycle().take(n).copied().collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/escape_html");

    for &sz in SIZES {
        let plain = plain_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("no_escape", sz), &plain, |b, data| {
            let mut out = Vec::with_capacity(sz * 2);
            b.iter(|| {
                out.clear();
                escape_html(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    for &sz in SIZES {
        let mixed = mixed_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("mixed", sz), &mixed, |b, data| {
            let mut out = Vec::with_capacity(sz * 2);
            b.iter(|| {
                out.clear();
                escape_html(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    for &sz in SIZES {
        let plain = plain_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("needs_escape_false", sz), &plain, |b, data| {
            b.iter(|| black_box(needs_escape(black_box(data))))
        });

        let mixed = mixed_payload(sz);
        g.bench_with_input(BenchmarkId::new("needs_escape_true", sz), &mixed, |b, data| {
            b.iter(|| black_box(needs_escape(black_box(data))))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
