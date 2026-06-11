//! Benchmark: golomb_set — Golomb-coded probabilistic set
//! Group: encoding | Algo: golomb_set

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::encode::golomb_set::GolombSet;

fn make_hashes(n: usize) -> Vec<u64> {
    // Deterministic pseudo-random hashes via LCG
    let mut val: u64 = 0xDEAD_BEEF_CAFE_BABE;
    (0..n).map(|_| {
        val = val.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        val
    }).collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("encoding/golomb_set");

    // Construction benchmarks
    for &count in &[100usize, 1000, 10000] {
        let hashes = make_hashes(count);
        g.bench_with_input(BenchmarkId::new("from_hashes", count), &hashes, |b, hashes| {
            b.iter(|| {
                let mut h = hashes.clone();
                black_box(GolombSet::from_hashes(black_box(&mut h), 10))
            })
        });
    }

    // Lookup benchmarks — build once, query many
    for &count in &[100usize, 1000, 10000] {
        let mut hashes = make_hashes(count);
        let gs = GolombSet::from_hashes(&mut hashes, 10);

        // Query existing element (first hash in sorted order)
        let target_hit = hashes[0];
        g.bench_with_input(BenchmarkId::new("contains_hit", count), &(target_hit, &gs), |b, &(target, gs)| {
            b.iter(|| black_box(gs.contains(black_box(target))))
        });

        // Query non-existing element
        let target_miss = 0xFFFF_FFFF_FFFF_FFFFu64;
        g.bench_with_input(BenchmarkId::new("contains_miss", count), &(target_miss, &gs), |b, &(target, gs)| {
            b.iter(|| black_box(gs.contains(black_box(target))))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
