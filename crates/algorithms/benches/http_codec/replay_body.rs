//! Benchmark: replay_body — Retryable body replay buffer
//! Group: http_codec | Algo: replay_body

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::http_codec::ReplayBody;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("http_codec/replay_body");

    // push throughput at various chunk sizes
    for &(name, chunk_size, capacity) in &[
        ("small_chunks", 64usize, 4096usize),
        ("medium_chunks", 1024, 65536),
        ("large_chunks", 8192, 1_048_576),
    ] {
        let chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();
        g.bench_with_input(BenchmarkId::new("push", name), &chunk, |b, chunk| {
            b.iter_with_setup(
                || ReplayBody::new(capacity),
                |mut rb| {
                    while rb.push(black_box(chunk)) {}
                    black_box(rb.len());
                },
            )
        });
    }

    // replay latency
    g.bench_function("replay/4KB", |b| {
        let mut rb = ReplayBody::new(4096);
        let chunk = vec![0xABu8; 1024];
        for _ in 0..4 {
            rb.push(&chunk);
        }
        b.iter(|| black_box(rb.replay().len()))
    });

    // reset + refill cycle
    g.bench_function("reset_refill/1KB", |b| {
        let chunk = vec![0u8; 256];
        b.iter_with_setup(
            || ReplayBody::new(1024),
            |mut rb| {
                for _ in 0..4 {
                    rb.push(black_box(&chunk));
                }
                rb.reset();
                for _ in 0..4 {
                    rb.push(black_box(&chunk));
                }
                black_box(rb.len());
            },
        )
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
