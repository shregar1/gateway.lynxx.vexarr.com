//! Benchmark: HTTP/2 frame header parsing
//! Group: codec | Algo: h2_frame

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lynxx_algo::{ngx_http_v2_parse_frame_header, HttpV2FrameHeader};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec/h2_frame");

    let frame: [u8; 9] = [0x00, 0x00, 0x0C, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01];

    g.bench_function("parse_frame_header", |b| {
        let mut out = HttpV2FrameHeader {
            length: 0,
            frame_type: 0,
            flags: 0,
            sid: 0,
        };
        b.iter(|| {
            ngx_http_v2_parse_frame_header(&frame, &mut out);
            black_box(&out);
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
