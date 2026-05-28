//! Benchmark: sni_check — Domain fronting protection
//! Group: networking | Algo: sni_check

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::networking::{sni_matches, check_domain_fronting};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("networking/sni_check");

    // sni_matches
    for &(name, sni, allowed) in &[
        ("exact_hit", "example.com", "example.com"),
        ("exact_miss", "other.com", "example.com"),
        ("wildcard_hit", "foo.example.com", "*.example.com"),
        ("wildcard_miss", "a.b.example.com", "*.example.com"),
    ] {
        g.bench_with_input(BenchmarkId::new("sni_matches", name), &(sni, allowed), |b, &(sni, allowed)| {
            b.iter(|| black_box(sni_matches(black_box(sni), black_box(allowed))))
        });
    }

    // check_domain_fronting
    for &(name, sni, host) in &[
        ("same", "example.com", "example.com"),
        ("same_port", "example.com", "example.com:443"),
        ("fronted", "evil.com", "example.com"),
    ] {
        g.bench_with_input(BenchmarkId::new("fronting", name), &(sni, host), |b, &(sni, host)| {
            b.iter(|| black_box(check_domain_fronting(black_box(sni), black_box(host))))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
