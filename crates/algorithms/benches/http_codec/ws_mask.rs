//! Benchmark: ws_mask — WebSocket XOR masking
//! Group: http_codec | Algo: ws_mask

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::http_codec::ws_mask;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("http_codec/ws_mask");
    let mask_key = [0x37, 0xFA, 0x21, 0x3D];

    for &(name, size) in &[
        ("64B", 64usize),
        ("1KB", 1024),
        ("4KB", 4096),
        ("64KB", 65536),
        ("1MB", 1_048_576),
    ] {
        g.bench_with_input(BenchmarkId::new("mask", name), &size, |b, &size| {
            let mut payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            b.iter(|| {
                ws_mask(black_box(&mut payload), black_box(mask_key));
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
