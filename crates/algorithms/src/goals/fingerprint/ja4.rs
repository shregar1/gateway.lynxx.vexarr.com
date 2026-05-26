//! JA4 TLS fingerprint — derives a compact fingerprint string from
//! a TLS ClientHello's cipher suites, extensions, ALPN, and version.
//!
//! The fingerprint has three sections separated by underscores:
//!   `ja4_a_ja4_b_ja4_c`
//!
//! - **ja4_a** (readable): protocol, version, SNI flag, counts, ALPN hint
//! - **ja4_b**: truncated SHA-256 of the sorted cipher-suite list
//! - **ja4_c**: truncated SHA-256 of the sorted extension + sig-alg list

use core::fmt;

// ──────────────────────────────────────────────
// Minimal SHA-256 (only the one-shot digest we need — no external crate)
// ──────────────────────────────────────────────

#[rustfmt::skip]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7)
                ^ w[i - 15].rotate_right(18)
                ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17)
                ^ w[i - 2].rotate_right(19)
                ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// First 12 hex characters of the SHA-256 digest.
fn sha256_trunc12(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut hex = String::with_capacity(12);
    for &b in &digest[..6] {
        hex.push(HEX_LOWER[(b >> 4) as usize] as char);
        hex.push(HEX_LOWER[(b & 0xf) as usize] as char);
    }
    hex
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

// ──────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────

/// Transport protocol for the JA4 fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Quic,
}

/// TLS version observed in the ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown,
}

/// Input parameters extracted from a TLS ClientHello message.
#[derive(Debug, Clone)]
pub struct Ja4Input {
    pub protocol: TransportProtocol,
    pub tls_version: TlsVersion,
    pub has_sni: bool,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub alpn_first: Option<String>,
}

/// A computed JA4 fingerprint with its component parts.
#[derive(Debug, Clone)]
pub struct Ja4Fingerprint {
    /// Readable prefix: `{proto}{ver}{sni}{cc}{ec}_{alpn}`
    pub ja4_a: String,
    /// Truncated SHA-256 of sorted cipher list.
    pub ja4_b: String,
    /// Truncated SHA-256 of sorted extension list + sig algs.
    pub ja4_c: String,
    /// Combined: `ja4_a_ja4_b_ja4_c`
    pub ja4: String,
}

impl fmt::Display for Ja4Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ja4)
    }
}

impl Ja4Fingerprint {
    /// Compute a JA4 fingerprint from ClientHello parameters.
    ///
    /// **ja4_a** format: `{proto}{version}{sni}{cipher_count:02}{ext_count:02}_{alpn}`
    ///
    /// **ja4_b**: sorted cipher suites (GREASE excluded), SHA-256 → first 12 hex chars.
    ///
    /// **ja4_c**: sorted extensions (GREASE + SNI excluded) followed by sorted
    ///   signature algorithms, SHA-256 → first 12 hex chars.
    pub fn compute(input: &Ja4Input) -> Self {
        let proto_ch = match input.protocol {
            TransportProtocol::Tcp => 't',
            TransportProtocol::Quic => 'q',
        };
        let ver_str = match input.tls_version {
            TlsVersion::Tls10 => "10",
            TlsVersion::Tls11 => "11",
            TlsVersion::Tls12 => "12",
            TlsVersion::Tls13 => "13",
            TlsVersion::Unknown => "00",
        };
        let sni_ch = if input.has_sni { 'd' } else { 'i' };

        // Filter out GREASE values
        let mut ciphers: Vec<u16> = input
            .cipher_suites
            .iter()
            .copied()
            .filter(|&v| !Self::is_grease(v))
            .collect();
        let mut exts: Vec<u16> = input
            .extensions
            .iter()
            .copied()
            .filter(|&v| !Self::is_grease(v) && v != 0x0000) // exclude GREASE and SNI
            .collect();

        let cipher_count = ciphers.len().min(99);
        let ext_count = exts.len().min(99);

        let alpn = match &input.alpn_first {
            Some(s) if s.len() >= 2 => s[..2].to_string(),
            Some(s) if s.len() == 1 => format!("{}0", &s[..1]),
            _ => "00".to_string(),
        };

        let ja4_a = format!(
            "{proto_ch}{ver_str}{sni_ch}{cipher_count:02}{ext_count:02}_{alpn}"
        );

        // ja4_b: sorted cipher suites → comma-separated 4-digit hex → SHA-256 → 12 hex
        ciphers.sort_unstable();
        let cipher_str: String = ciphers
            .iter()
            .map(|v| format!("{v:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let ja4_b = sha256_trunc12(cipher_str.as_bytes());

        // ja4_c: sorted extensions → comma-separated 4-digit hex,
        //        then underscore, then sorted sig algs → comma-separated 4-digit hex
        //        → SHA-256 → 12 hex
        exts.sort_unstable();
        let mut sig_algs: Vec<u16> = input.signature_algorithms.clone();
        sig_algs.sort_unstable();

        let ext_str: String = exts
            .iter()
            .map(|v| format!("{v:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let sig_str: String = sig_algs
            .iter()
            .map(|v| format!("{v:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let combined = if sig_str.is_empty() {
            ext_str
        } else {
            format!("{ext_str}_{sig_str}")
        };
        let ja4_c = sha256_trunc12(combined.as_bytes());

        let ja4 = format!("{ja4_a}_{ja4_b}_{ja4_c}");

        Self {
            ja4_a,
            ja4_b,
            ja4_c,
            ja4,
        }
    }

    /// Returns `true` if the value is a TLS GREASE value.
    ///
    /// GREASE values follow the pattern `0x?a?a` where `?` is the same nibble:
    /// `0x0a0a`, `0x1a1a`, `0x2a2a`, … `0xfafa`.
    pub fn is_grease(value: u16) -> bool {
        let hi = (value >> 8) as u8;
        let lo = value as u8;
        hi == lo && (lo & 0x0f) == 0x0a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        assert!(Ja4Fingerprint::is_grease(0x0a0a));
        assert!(Ja4Fingerprint::is_grease(0x1a1a));
        assert!(Ja4Fingerprint::is_grease(0x2a2a));
        assert!(Ja4Fingerprint::is_grease(0x3a3a));
        assert!(Ja4Fingerprint::is_grease(0x4a4a));
        assert!(Ja4Fingerprint::is_grease(0x5a5a));
        assert!(Ja4Fingerprint::is_grease(0xfafa));

        assert!(!Ja4Fingerprint::is_grease(0x0000));
        assert!(!Ja4Fingerprint::is_grease(0x0a0b));
        assert!(!Ja4Fingerprint::is_grease(0x1a2a));
        assert!(!Ja4Fingerprint::is_grease(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!Ja4Fingerprint::is_grease(0xc02c));
    }

    fn sample_input() -> Ja4Input {
        Ja4Input {
            protocol: TransportProtocol::Tcp,
            tls_version: TlsVersion::Tls13,
            has_sni: true,
            cipher_suites: vec![
                0x0a0a, // GREASE — should be filtered
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            ],
            extensions: vec![
                0x0a0a, // GREASE — should be filtered
                0x0000, // SNI — should be filtered
                0x0017, // extended_master_secret
                0x0033, // key_share
                0x002b, // supported_versions
                0x000d, // signature_algorithms
                0x000a, // supported_groups
                0xff01, // renegotiation_info
            ],
            signature_algorithms: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0804, // rsa_pss_rsae_sha256
                0x0401, // rsa_pkcs1_sha256
            ],
            alpn_first: Some("h2".to_string()),
        }
    }

    #[test]
    fn ja4_a_format() {
        let fp = Ja4Fingerprint::compute(&sample_input());
        // t = TCP, 13 = TLS 1.3, d = has SNI, 05 ciphers (GREASE excluded),
        // 06 extensions (GREASE + SNI excluded), h2 ALPN
        assert!(
            fp.ja4_a.starts_with("t13d0506_h2"),
            "ja4_a = {}",
            fp.ja4_a
        );
    }

    #[test]
    fn ja4_combined_format() {
        let fp = Ja4Fingerprint::compute(&sample_input());
        let parts: Vec<&str> = fp.ja4.split('_').collect();
        // ja4_a contains an underscore (prefix_alpn), so total parts = 4
        assert_eq!(parts.len(), 4, "ja4 = {}", fp.ja4);
        assert_eq!(parts[0].len() + 1 + parts[1].len(), fp.ja4_a.len());
        assert_eq!(parts[2].len(), 12, "ja4_b should be 12 hex chars");
        assert_eq!(parts[3].len(), 12, "ja4_c should be 12 hex chars");
    }

    #[test]
    fn ja4_b_is_hex() {
        let fp = Ja4Fingerprint::compute(&sample_input());
        assert!(fp.ja4_b.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp.ja4_b.len(), 12);
    }

    #[test]
    fn ja4_c_is_hex() {
        let fp = Ja4Fingerprint::compute(&sample_input());
        assert!(fp.ja4_c.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp.ja4_c.len(), 12);
    }

    #[test]
    fn deterministic() {
        let input = sample_input();
        let a = Ja4Fingerprint::compute(&input);
        let b = Ja4Fingerprint::compute(&input);
        assert_eq!(a.ja4, b.ja4);
    }

    #[test]
    fn different_cipher_suites_differ() {
        let mut input_a = sample_input();
        let mut input_b = sample_input();
        input_b.cipher_suites.push(0xccaa);

        let a = Ja4Fingerprint::compute(&input_a);
        let b = Ja4Fingerprint::compute(&input_b);
        assert_ne!(a.ja4_b, b.ja4_b);

        input_a.cipher_suites.push(0xccaa);
        let a2 = Ja4Fingerprint::compute(&input_a);
        assert_eq!(a2.ja4_b, b.ja4_b);
    }

    #[test]
    fn no_alpn() {
        let mut input = sample_input();
        input.alpn_first = None;
        let fp = Ja4Fingerprint::compute(&input);
        assert!(fp.ja4_a.ends_with("_00"), "ja4_a = {}", fp.ja4_a);
    }

    #[test]
    fn single_char_alpn() {
        let mut input = sample_input();
        input.alpn_first = Some("x".to_string());
        let fp = Ja4Fingerprint::compute(&input);
        assert!(fp.ja4_a.ends_with("_x0"), "ja4_a = {}", fp.ja4_a);
    }

    #[test]
    fn quic_protocol() {
        let mut input = sample_input();
        input.protocol = TransportProtocol::Quic;
        let fp = Ja4Fingerprint::compute(&input);
        assert!(fp.ja4_a.starts_with('q'), "ja4_a = {}", fp.ja4_a);
    }

    #[test]
    fn no_sni() {
        let mut input = sample_input();
        input.has_sni = false;
        let fp = Ja4Fingerprint::compute(&input);
        assert!(fp.ja4_a.starts_with("t13i"), "ja4_a = {}", fp.ja4_a);
    }

    #[test]
    fn tls_12() {
        let mut input = sample_input();
        input.tls_version = TlsVersion::Tls12;
        let fp = Ja4Fingerprint::compute(&input);
        assert!(fp.ja4_a.starts_with("t12"), "ja4_a = {}", fp.ja4_a);
    }

    #[test]
    fn all_grease_filtered() {
        let mut input = sample_input();
        input.cipher_suites = vec![0x0a0a, 0x1a1a, 0x2a2a];
        input.extensions = vec![0x3a3a, 0x4a4a, 0x0000];
        let fp = Ja4Fingerprint::compute(&input);
        assert!(fp.ja4_a.contains("0000_"), "ja4_a = {}", fp.ja4_a);
    }

    #[test]
    fn display_impl() {
        let fp = Ja4Fingerprint::compute(&sample_input());
        let displayed = format!("{fp}");
        assert_eq!(displayed, fp.ja4);
    }

    #[test]
    fn sha256_known_vector() {
        let digest = sha256(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha256_empty() {
        let digest = sha256(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest, expected);
    }
}
