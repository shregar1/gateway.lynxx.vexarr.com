//! Benchmark: mqtt_parse — MQTT CONNECT parser
//! Group: mqtt | Algo: mqtt_parse

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::mqtt::mqtt_parse::parse_connect;

fn make_connect_v4(client_id: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    let mut var_hdr = Vec::new();
    var_hdr.extend_from_slice(&[0, 4]);
    var_hdr.extend_from_slice(b"MQTT");
    var_hdr.push(4);
    var_hdr.push(0x02);
    var_hdr.extend_from_slice(&60u16.to_be_bytes());
    var_hdr.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    var_hdr.extend_from_slice(client_id.as_bytes());
    pkt.push(0x10);
    let mut len = var_hdr.len();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 { byte |= 0x80; }
        pkt.push(byte);
        if len == 0 { break; }
    }
    pkt.extend_from_slice(&var_hdr);
    pkt
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("mqtt/mqtt_parse");

    let short = make_connect_v4("c1");
    let long = make_connect_v4("device-12345678-abcdef-gateway-prod");

    g.bench_function("parse_short_id", |b| {
        b.iter(|| black_box(parse_connect(&short)))
    });

    g.bench_function("parse_long_id", |b| {
        b.iter(|| black_box(parse_connect(&long)))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
