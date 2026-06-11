//! Benchmark: utf8_decode — UTF-8 validation and decoding
//! Group: text | Algo: utf8_decode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::text::utf8_decode::{utf8_validate, utf8_decode_char};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("text/utf8_decode");

    let ascii = b"The quick brown fox jumps over the lazy dog".to_vec();
    let mixed = "Grüße aus 日本 🦀 emoji".as_bytes().to_vec();

    g.bench_with_input(BenchmarkId::new("validate", "ascii_43B"), &ascii, |b, data| {
        b.iter(|| black_box(utf8_validate(data)))
    });

    g.bench_with_input(BenchmarkId::new("validate", "mixed_30B"), &mixed, |b, data| {
        b.iter(|| black_box(utf8_validate(data)))
    });

    g.bench_function("decode_char_ascii", |b| {
        b.iter(|| black_box(utf8_decode_char(b"Hello")))
    });

    g.bench_function("decode_char_4byte", |b| {
        let emoji = "🦀".as_bytes();
        b.iter(|| black_box(utf8_decode_char(emoji)))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
