//! Benchmark: Maglev consistent hash table
//! Group: upstream_pick | Algo: maglev

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::upstream_pick::maglev::MaglevTable;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("upstream_pick/maglev");

    for &n in &[3usize, 10, 100] {
        let backends: Vec<String> = (0..n).map(|i| format!("backend-{}", i)).collect();
        let backend_refs: Vec<&str> = backends.iter().map(|s| s.as_str()).collect();

        g.bench_with_input(BenchmarkId::new("build", n), &backend_refs, |b, br| {
            b.iter(|| black_box(MaglevTable::new(br)))
        });

        g.bench_with_input(BenchmarkId::new("lookup", n), &backend_refs, |b, br| {
            let table = MaglevTable::new(br);
            let mut key = 0u64;
            b.iter(|| {
                let result = table.lookup(black_box(key));
                key = key.wrapping_add(1);
                black_box(result)
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
