//! Benchmark: cert_selection — Certificate selection
//! Group: networking | Algo: cert_selection

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::networking::{CertCandidate, KeyType, select_cert};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("networking/cert_selection");

    // Select from N candidates
    for &n in &[5u32, 20, 100] {
        g.bench_with_input(BenchmarkId::new("select", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let mut certs: Vec<CertCandidate> = Vec::with_capacity(n as usize);
                    for i in 0..n {
                        certs.push(CertCandidate {
                            domain: if i % 5 == 0 {
                                "*.example.com".to_string()
                            } else {
                                format!("host{i}.example.com")
                            },
                            not_after: 2_000_000 + (i as u64 * 1000),
                            is_wildcard: i % 5 == 0,
                            key_type: if i % 3 == 0 { KeyType::Ecdsa } else { KeyType::Rsa },
                        });
                    }
                    certs
                },
                |certs| {
                    black_box(select_cert(
                        black_box(&certs),
                        black_box("host7.example.com"),
                        black_box(1_000_000),
                    ));
                },
            )
        });
    }

    // Hit vs miss
    let certs = vec![
        CertCandidate { domain: "example.com".into(), not_after: 2_000_000, is_wildcard: false, key_type: KeyType::Ecdsa },
        CertCandidate { domain: "*.example.com".into(), not_after: 2_000_000, is_wildcard: true, key_type: KeyType::Rsa },
    ];
    g.bench_function("select/hit", |b| {
        b.iter(|| black_box(select_cert(black_box(&certs), black_box("example.com"), black_box(1_000_000))))
    });
    g.bench_function("select/miss", |b| {
        b.iter(|| black_box(select_cert(black_box(&certs), black_box("other.com"), black_box(1_000_000))))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
