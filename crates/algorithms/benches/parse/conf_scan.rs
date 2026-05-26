//! Benchmark: ngx_conf_scan_tokens — config line tokenizer
//! Group: parse | Algo: conf_scan

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nginx_algo::ngx_conf_scan_tokens;

const INPUTS: &[(&str, &[u8])] = &[
    ("simple", b"server 127.0.0.1:8080"),
    ("quoted", b"log_format main '$remote_addr - $remote_user'"),
    ("many_tokens", b"proxy_set_header X-Real-IP $remote_addr X-Forwarded-For $proxy_add_x_forwarded_for Host $host"),
];

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse/conf_scan");
    for &(name, input) in INPUTS {
        g.throughput(Throughput::Bytes(input.len() as u64));
        g.bench_with_input(BenchmarkId::new("scan_tokens", name), &input, |b, &input| {
            b.iter(|| black_box(ngx_conf_scan_tokens(input)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
