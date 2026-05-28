//! Benchmark: cname_flatten — CNAME chain resolution
//! Group: networking | Algo: cname_flatten

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::networking::CnameChain;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("networking/cname_flatten");

    // Resolve chains of varying depth
    for &depth in &[1u32, 5, 20] {
        g.bench_with_input(BenchmarkId::new("resolve", depth), &depth, |b, &depth| {
            b.iter_with_setup(
                || {
                    let mut chain = CnameChain::new();
                    for i in 0..depth {
                        chain.add(
                            &format!("hop{i}.example.com"),
                            &format!("hop{}.example.com", i + 1),
                        );
                    }
                    chain
                },
                |chain| {
                    black_box(chain.resolve(black_box("hop0.example.com")));
                },
            )
        });
    }

    // No CNAME (miss)
    g.bench_function("resolve/miss", |b| {
        let chain = CnameChain::new();
        b.iter(|| black_box(chain.resolve(black_box("nope.example.com"))))
    });

    // Add throughput
    g.bench_function("add/100", |b| {
        b.iter_with_setup(CnameChain::new, |mut chain| {
            for i in 0..100u32 {
                chain.add(
                    black_box(&format!("alias{i}.example.com")),
                    black_box(&format!("target{i}.example.com")),
                );
            }
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
