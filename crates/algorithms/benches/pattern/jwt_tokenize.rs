//! Benchmark: jwt_split — JWT tokenizer
//! Group: pattern | Algo: jwt_tokenize

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::pattern::jwt_tokenize::jwt_split;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("pattern/jwt_tokenize");

    let short_jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig";
    let long_jwt = format!(
        "{}.{}.{}",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
        "POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr"
    );
    let long_jwt = long_jwt.as_bytes();

    g.bench_function("split_short", |b| {
        b.iter(|| black_box(jwt_split(short_jwt)))
    });

    g.bench_function("split_long", |b| {
        b.iter(|| black_box(jwt_split(long_jwt)))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
