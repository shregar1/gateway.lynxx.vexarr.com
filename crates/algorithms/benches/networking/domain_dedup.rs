//! Benchmark: domain_dedup — ACME domain deduplication
//! Group: networking | Algo: domain_dedup

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::networking::dedup_domains;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("networking/domain_dedup");

    // Various sizes and redundancy patterns
    for &(name, count, wildcards) in &[
        ("10_no_wc", 10usize, 0usize),
        ("10_with_wc", 10, 2),
        ("100_no_wc", 100, 0),
        ("100_with_wc", 100, 10),
    ] {
        g.bench_with_input(BenchmarkId::new("dedup", name), &(count, wildcards), |b, &(count, wildcards)| {
            b.iter_with_setup(
                || {
                    let mut domains: Vec<String> = Vec::with_capacity(count);
                    for i in 0..wildcards {
                        domains.push(format!("*.domain{i}.com"));
                    }
                    for i in 0..count {
                        let base = i % (wildcards.max(1));
                        domains.push(format!("sub{i}.domain{base}.com"));
                    }
                    // Add some duplicates
                    if count > 2 {
                        domains.push(domains[0].clone());
                        domains.push(domains[1].clone());
                    }
                    domains
                },
                |mut domains| {
                    dedup_domains(black_box(&mut domains));
                    black_box(domains.len());
                },
            )
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
