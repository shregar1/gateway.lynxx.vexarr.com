//! Benchmark: LDAP {SHA} / {SSHA} password schemes
//! Group: crypto | Algo: sha_ssha

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::crypto::{sha_hash, sha_verify, ssha_hash};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("crypto/sha_ssha");

    let password = b"correct horse battery staple";
    let salt = b"NaClNaCl";
    let stored = ssha_hash(password, salt);

    g.bench_function("sha_hash", |b| {
        b.iter(|| black_box(sha_hash(black_box(password))))
    });

    g.bench_function("ssha_hash", |b| {
        b.iter(|| black_box(ssha_hash(black_box(password), black_box(salt))))
    });

    g.bench_function("sha_verify", |b| {
        b.iter(|| black_box(sha_verify(black_box(password), black_box(&stored))))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
