//! Benchmark: utf8_scan — bulk UTF-8 validation with ASCII fast-path
//! Group: text | Algo: utf8_scan

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use algorithms::goals::text::utf8_decode::{utf8_count_chars, utf8_scan_valid};

/// Build an ASCII buffer of exactly `n` bytes.
fn ascii_input(n: usize) -> Vec<u8> {
    let pat = b"The quick brown fox jumps over the lazy dog. ";
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        v.push(pat[v.len() % pat.len()]);
    }
    v.truncate(n);
    v
}

/// Build a mixed multibyte buffer of at least `n` bytes (truncated to a
/// valid UTF-8 boundary near `n`).
fn mixed_input(n: usize) -> Vec<u8> {
    let pat = "Grüße aus 日本 🦀 héllo wörld 你好 😀 ";
    let mut s = String::new();
    while s.len() < n {
        s.push_str(pat);
    }
    // Truncate to the largest char boundary <= n.
    let mut end = n.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].as_bytes().to_vec()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("text/utf8_scan");

    for &size in &[64usize, 256, 4096] {
        let ascii = ascii_input(size);
        let mixed = mixed_input(size);

        g.throughput(Throughput::Bytes(ascii.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("scan_valid_ascii", size),
            &ascii,
            |b, data| b.iter(|| black_box(utf8_scan_valid(data))),
        );
        g.bench_with_input(
            BenchmarkId::new("count_chars_ascii", size),
            &ascii,
            |b, data| b.iter(|| black_box(utf8_count_chars(data))),
        );

        g.throughput(Throughput::Bytes(mixed.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("scan_valid_mixed", size),
            &mixed,
            |b, data| b.iter(|| black_box(utf8_scan_valid(data))),
        );
        g.bench_with_input(
            BenchmarkId::new("count_chars_mixed", size),
            &mixed,
            |b, data| b.iter(|| black_box(utf8_count_chars(data))),
        );
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
