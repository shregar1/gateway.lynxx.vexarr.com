//! Benchmark: JA4 fingerprint original vs optimized zero-alloc
//! Compares: Ja4Fingerprint::compute vs ja4_compute_fast

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::fingerprint::{
    Ja4Fingerprint, Ja4Input, TlsVersion, TransportProtocol,
};
use algorithms::goals::optimized::ja4::{
    ja4_compute_fast, Protocol, Version,
};

fn make_input_minimal() -> (Ja4Input, Vec<u16>, Vec<u16>, Vec<u16>) {
    let ciphers: Vec<u16> = vec![0x0a0a, 0x1301, 0x1302, 0x1303];
    let exts: Vec<u16> = vec![0x0a0a, 0x0000, 0x0017, 0x0033, 0x002b, 0x000d, 0x000a];
    let sig_algs: Vec<u16> = vec![0x0403, 0x0804, 0x0401];

    let input = Ja4Input {
        protocol: TransportProtocol::Tcp,
        tls_version: TlsVersion::Tls13,
        has_sni: true,
        cipher_suites: ciphers.clone(),
        extensions: exts.clone(),
        signature_algorithms: sig_algs.clone(),
        alpn_first: Some("h2".to_string()),
    };

    (input, ciphers, exts, sig_algs)
}

fn make_input_typical() -> (Ja4Input, Vec<u16>, Vec<u16>, Vec<u16>) {
    let ciphers: Vec<u16> = (0..15).map(|i| 0x1300 + i).collect();
    let exts: Vec<u16> = (0..20).map(|i| 0x0010 + i).collect();
    let sig_algs: Vec<u16> = (0..8).map(|i| 0x0400 + i).collect();

    let input = Ja4Input {
        protocol: TransportProtocol::Tcp,
        tls_version: TlsVersion::Tls13,
        has_sni: true,
        cipher_suites: ciphers.clone(),
        extensions: exts.clone(),
        signature_algorithms: sig_algs.clone(),
        alpn_first: Some("h2".to_string()),
    };

    (input, ciphers, exts, sig_algs)
}

fn make_input_large() -> (Ja4Input, Vec<u16>, Vec<u16>, Vec<u16>) {
    let ciphers: Vec<u16> = (0..40).map(|i| 0x1300 + i).collect();
    let exts: Vec<u16> = (0..50).map(|i| 0x0010 + i).collect();
    let sig_algs: Vec<u16> = (0..20).map(|i| 0x0400 + i).collect();

    let input = Ja4Input {
        protocol: TransportProtocol::Tcp,
        tls_version: TlsVersion::Tls13,
        has_sni: true,
        cipher_suites: ciphers.clone(),
        extensions: exts.clone(),
        signature_algorithms: sig_algs.clone(),
        alpn_first: Some("h2".to_string()),
    };

    (input, ciphers, exts, sig_algs)
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("optimized/ja4");

    // Minimal input (3c/5e)
    {
        let (input, ciphers, exts, sig_algs) = make_input_minimal();
        g.bench_function("Ja4Fingerprint::compute/minimal", |b| {
            b.iter(|| black_box(Ja4Fingerprint::compute(&input)))
        });
        g.bench_function("ja4_compute_fast/minimal", |b| {
            b.iter(|| {
                black_box(ja4_compute_fast(
                    Protocol::Tcp,
                    Version::Tls13,
                    true,
                    &ciphers,
                    &exts,
                    &sig_algs,
                    Some("h2"),
                ))
            })
        });
    }

    // Typical input (15c/20e)
    {
        let (input, ciphers, exts, sig_algs) = make_input_typical();
        g.bench_function("Ja4Fingerprint::compute/typical", |b| {
            b.iter(|| black_box(Ja4Fingerprint::compute(&input)))
        });
        g.bench_function("ja4_compute_fast/typical", |b| {
            b.iter(|| {
                black_box(ja4_compute_fast(
                    Protocol::Tcp,
                    Version::Tls13,
                    true,
                    &ciphers,
                    &exts,
                    &sig_algs,
                    Some("h2"),
                ))
            })
        });
    }

    // Large input (40c/50e)
    {
        let (input, ciphers, exts, sig_algs) = make_input_large();
        g.bench_function("Ja4Fingerprint::compute/large", |b| {
            b.iter(|| black_box(Ja4Fingerprint::compute(&input)))
        });
        g.bench_function("ja4_compute_fast/large", |b| {
            b.iter(|| {
                black_box(ja4_compute_fast(
                    Protocol::Tcp,
                    Version::Tls13,
                    true,
                    &ciphers,
                    &exts,
                    &sig_algs,
                    Some("h2"),
                ))
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
