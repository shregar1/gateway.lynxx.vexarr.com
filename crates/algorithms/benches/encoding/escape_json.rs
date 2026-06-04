//! Benchmark: escape_json — JSON string escaping
//! Group: encoding | Algo: escape_json

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::encode::escape_json::escape_json;

const SIZES: &[usize] = &[32, 128, 512, 2048, 8192];

fn plain_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'A' + (i % 26) as u8).collect()
}

fn json_payload(n: usize) -> Vec<u8> {
    let pattern = br#"{"key": "value", "path": "C:\\Users\\data\n"} "#;
    pattern.iter().cycle().take(n).copied().collect()
}

fn control_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 32) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/escape_json");

    for &sz in SIZES {
        let plain = plain_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("no_escape", sz), &plain, |b, data| {
            let mut out = Vec::with_capacity(sz * 2);
            b.iter(|| {
                out.clear();
                escape_json(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    for &sz in SIZES {
        let mixed = json_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("json_mixed", sz), &mixed, |b, data| {
            let mut out = Vec::with_capacity(sz * 2);
            b.iter(|| {
                out.clear();
                escape_json(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    for &sz in SIZES {
        let ctrl = control_payload(sz);
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("control_chars", sz), &ctrl, |b, data| {
            let mut out = Vec::with_capacity(sz * 6);
            b.iter(|| {
                out.clear();
                escape_json(black_box(data), &mut out);
                black_box(&out);
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
