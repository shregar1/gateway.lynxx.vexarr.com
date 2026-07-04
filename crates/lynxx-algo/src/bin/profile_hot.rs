//! Fixed-iteration hot loop for profilers (`cargo flamegraph` / `samply record`).

use lynxx_algo::{ngx_crc32_long, ngx_murmur_hash2, ngx_strnstr};

fn bench_data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(17) ^ 0x5A) as u8 | 1)
        .collect()
}

fn main() {
    let d = bench_data(65536);
    let hay = bench_data(65536);
    for _ in 0..50_000 {
        std::hint::black_box(ngx_crc32_long(&d));
        std::hint::black_box(ngx_murmur_hash2(&d));
        std::hint::black_box(ngx_strnstr(&hay, "ZZZZZZZZ"));
    }
}
