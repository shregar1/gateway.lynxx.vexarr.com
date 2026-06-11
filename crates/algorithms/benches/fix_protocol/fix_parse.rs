//! Benchmark: fix_parse — FIX protocol message parser
//! Group: fix_protocol | Algo: fix_parse

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::fix_protocol::fix_parse::parse_fix_message;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("fix_protocol/fix_parse");

    let small_msg = b"8=FIX.4.4\x019=5\x0135=0\x0110=123\x01".to_vec();
    let large_msg = b"8=FIX.4.4\x019=175\x0135=D\x0149=SENDER\x0156=TARGET\x0134=2\x0152=20230101-12:00:00\x0111=order123\x0121=1\x0155=AAPL\x0154=1\x0138=100\x0140=2\x0144=150.50\x0159=0\x0160=20230101-12:00:00\x0110=042\x01".to_vec();

    g.bench_function("parse_small_4fields", |b| {
        b.iter(|| black_box(parse_fix_message(&small_msg)))
    });

    g.bench_function("parse_large_16fields", |b| {
        b.iter(|| black_box(parse_fix_message(&large_msg)))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
