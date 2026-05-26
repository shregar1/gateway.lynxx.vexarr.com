//! Benchmark: ngx_http_chunked_parse_stream_fsm
//! Group: codec | Algo: chunked_parse_fsm

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_http_chunked_parse_stream_fsm;

const CHUNK_SIZES: &[u64] = &[64, 256, 4096, 65536];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/chunked_parse_fsm");
    for &sz in CHUNK_SIZES {
        let line = format!("{:x}\r\n", sz);
        let buf = line.as_bytes().to_vec();
        g.throughput(Throughput::Bytes(buf.len() as u64));
        g.bench_with_input(BenchmarkId::new("parse_fsm", sz), &buf, |b, buf| {
            b.iter(|| black_box(ngx_http_chunked_parse_stream_fsm(buf)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
