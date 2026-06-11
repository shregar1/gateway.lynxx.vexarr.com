//! Benchmark: aggregate write buffer (ATS)
//! Group: structures | Algo: write_buffer

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lynxx_structures::AggregateWriteBuffer;

const CHUNK: usize = 512;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("structures_write_buffer");
    let payload: Vec<u8> = (0..CHUNK).map(|i| (i & 0xff) as u8).collect();

    for chunks in [8usize, 32, 128] {
        g.throughput(Throughput::Bytes((CHUNK * chunks) as u64));
        g.bench_with_input(BenchmarkId::new("append_read", chunks), &chunks, |b, &chunks| {
            b.iter(|| {
                let mut buf = AggregateWriteBuffer::new(1 << 20, 4096);
                for i in 0..chunks {
                    let wref = buf.append(&payload, i as u64).expect("append");
                    black_box(buf.read(wref.offset, wref.length));
                }
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
