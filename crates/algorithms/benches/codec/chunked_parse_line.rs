//! Benchmark: ngx_http_chunked_parse_line
//! Group: codec | Algo: chunked_parse_line

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_http_chunked_parse_line;

const CHUNK_SIZES: &[u64] = &[64, 256, 4096, 65536];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/chunked_parse_line");
    for &sz in CHUNK_SIZES {
        let line = format!("{:x}\r\n", sz);
        let buf = line.as_bytes().to_vec();
        g.throughput(Throughput::Bytes(buf.len() as u64));
        g.bench_with_input(BenchmarkId::new("parse_line", sz), &buf, |b, buf| {
            b.iter(|| black_box(ngx_http_chunked_parse_line(buf)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
