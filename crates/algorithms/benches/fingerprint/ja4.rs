//! Benchmark: Ja4Fingerprint — JA4 TLS fingerprinting
//! Group: fingerprint | Algo: ja4

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::fingerprint::{Ja4Fingerprint, Ja4Input, TlsVersion, TransportProtocol};

fn make_input(n_ciphers: usize, n_extensions: usize) -> Ja4Input {
    Ja4Input {
        protocol: TransportProtocol::Tcp,
        tls_version: TlsVersion::Tls13,
        has_sni: true,
        cipher_suites: (0x1301..0x1301 + n_ciphers as u16).collect(),
        extensions: (0..n_extensions as u16).collect(),
        signature_algorithms: vec![0x0403, 0x0503, 0x0603],
        alpn_first: Some("h2".to_string()),
    }
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("fingerprint/ja4");
    for &(name, nc, ne) in &[("minimal", 3, 5), ("typical", 15, 20), ("large", 40, 50)] {
        let input = make_input(nc, ne);
        g.bench_with_input(BenchmarkId::new("compute", name), &input, |b, input| {
            b.iter(|| black_box(Ja4Fingerprint::compute(input)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
