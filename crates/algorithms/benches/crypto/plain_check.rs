//! Benchmark: plaintext constant-time password check
//! Group: crypto | Algo: plain_check

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use algorithms::goals::crypto::plain_check;

const SIZES: &[usize] = &[16, 64, 256];

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("crypto/plain_check");
    for &sz in SIZES {
        let a = payload(sz);
        let b_eq = a.clone();
        g.throughput(Throughput::Bytes(sz as u64));
        g.bench_with_input(BenchmarkId::new("plain_check", sz), &sz, |bn, _| {
            bn.iter(|| black_box(plain_check(black_box(&a), black_box(&b_eq))))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
