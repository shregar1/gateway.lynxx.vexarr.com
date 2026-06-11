use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lynxx_algo::*;

fn bench_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(17) ^ 0x5A) as u8).collect()
}

fn bench_murmur(c: &mut Criterion) {
    let mut group = c.benchmark_group("ngx_murmur_hash2");
    for len in [16, 64, 256, 4096, 65536] {
        let data = bench_data(len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &data, |b, d| {
            b.iter(|| black_box(ngx_murmur_hash2(black_box(d))));
        });
    }
    group.finish();
}

fn bench_crc32(c: &mut Criterion) {
    for len in [16, 60, 64, 256, 4096, 65536] {
        let data = bench_data(len);
        let mut g = c.benchmark_group("ngx_crc32_short");
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(BenchmarkId::from_parameter(len), &data, |b, d| {
            b.iter(|| black_box(ngx_crc32_short(black_box(d))));
        });
        g.finish();

        let mut g = c.benchmark_group("ngx_crc32_long");
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(BenchmarkId::from_parameter(len), &data, |b, d| {
            b.iter(|| black_box(ngx_crc32_long(black_box(d))));
        });
        g.finish();
    }
}

fn bench_hash_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("ngx_hash_key");
    for len in [32, 128, 512, 2048] {
        let data = bench_data(len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &data, |b, d| {
            b.iter(|| black_box(ngx_hash_key(black_box(d))));
        });
    }
    group.finish();
}

fn bench_strnstr(c: &mut Criterion) {
    let hay = bench_data(65536);
    let mut group = c.benchmark_group("ngx_strnstr");
    group.bench_function("needle_host", |b| {
        b.iter(|| black_box(ngx_strnstr(black_box(&hay), "Host:")));
    });
    group.bench_function("needle_missing", |b| {
        b.iter(|| black_box(ngx_strnstr(black_box(&hay), "ZZZZZZZZ")));
    });
    group.finish();
}

fn bench_sub_filter(c: &mut Criterion) {
    let mut matches = vec![
        SubMatch {
            pattern: b"nginx".to_vec(),
        },
        SubMatch {
            pattern: b"configuration".to_vec(),
        },
        SubMatch {
            pattern: b"upstream".to_vec(),
        },
    ];
    let tables = ngx_http_sub_init_tables(&mut matches).unwrap();
    let text = bench_data(65536);
    c.bench_function("ngx_http_sub_find_64k", |b| {
        b.iter(|| black_box(ngx_http_sub_find(black_box(&text), &matches, &tables)));
    });
}

fn bench_limit_req(c: &mut Criterion) {
    c.bench_function("ngx_limit_req_excess", |b| {
        b.iter(|| {
            black_box(ngx_limit_req_excess(
                black_box(1500),
                black_box(1000),
                black_box(10_000),
                black_box(9_200),
            ))
        });
    });
}

fn bench_ip_hash(c: &mut Criterion) {
    let addr = [10u8, 0, 0, 1];
    c.bench_function("ngx_ip_hash_mix", |b| {
        b.iter(|| black_box(ngx_ip_hash_mix(black_box(&addr), black_box(0))));
    });
}

fn bench_sort(c: &mut Criterion) {
    let data: Vec<u32> = (0..10_000).map(|i| (i * 7919) % 10_007).collect();
    c.bench_function("ngx_sort_10k_u32", |b| {
        b.iter(|| {
            let mut v = black_box(data.clone());
            ngx_sort(&mut v, |a, b| {
                if a < b {
                    -1
                } else if a > b {
                    1
                } else {
                    0
                }
            });
            black_box(v)
        });
    });
}

criterion_group!(
    benches,
    bench_murmur,
    bench_crc32,
    bench_hash_key,
    bench_strnstr,
    bench_sub_filter,
    bench_limit_req,
    bench_ip_hash,
    bench_sort
);
criterion_main!(benches);
