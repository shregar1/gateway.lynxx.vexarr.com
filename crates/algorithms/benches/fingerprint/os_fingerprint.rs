//! Benchmark: os_fingerprint — TCP SYN OS fingerprinting
//! Group: fingerprint | Algo: os_fingerprint

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::fingerprint::os_fingerprint::{fingerprint_tcp, match_os};

fn make_syn_packet(ttl: u8, df: bool, window: u16, mss: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 60];
    pkt[0] = 0x45;
    pkt[8] = ttl;
    pkt[9] = 6;
    if df { pkt[6] = 0x40; }
    pkt[33] = 0x02;
    pkt[34] = (window >> 8) as u8;
    pkt[35] = window as u8;
    pkt[32] = 0x60;
    pkt[40] = 2;
    pkt[41] = 4;
    pkt[42] = (mss >> 8) as u8;
    pkt[43] = mss as u8;
    pkt
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("fingerprint/os_fingerprint");

    let linux_syn = make_syn_packet(64, true, 29200, 1460);
    let win_syn = make_syn_packet(128, true, 65535, 1460);

    g.bench_function("fingerprint_linux", |b| {
        b.iter(|| black_box(fingerprint_tcp(&linux_syn)))
    });

    g.bench_function("fingerprint_windows", |b| {
        b.iter(|| black_box(fingerprint_tcp(&win_syn)))
    });

    g.bench_function("match_os", |b| {
        let sig = fingerprint_tcp(&linux_syn).unwrap();
        b.iter(|| black_box(match_os(&sig)))
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
