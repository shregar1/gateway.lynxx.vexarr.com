//! Benchmark: Apache APR1 password hash
//! Group: crypto | Algo: apr1
//!
//! APR1 is intentionally slow (1000 MD5 rounds), so expect µs–ms timings.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::crypto::{apr1_hash, apr1_verify};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("crypto/apr1");

    let password = b"correct horse battery staple";
    let salt = b"saltsalt";
    let hash = apr1_hash(password, salt);

    g.bench_function("apr1_hash", |b| {
        b.iter(|| black_box(apr1_hash(black_box(password), black_box(salt))))
    });

    g.bench_function("apr1_verify", |b| {
        b.iter(|| black_box(apr1_verify(black_box(password), black_box(&hash))))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
