//! Builds NGINX C extracts and generates Huffman tables from NGINX sources.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-changed=tests/c/");

    let out_dir_buf = env::var("OUT_DIR").expect("OUT_DIR");
    let out_dir = Path::new(&out_dir_buf);

    // The C parity oracle — the real NGINX C extracts, compiled + linked ONLY so
    // the Rust-vs-NGINX-C parity tests/benches can compare against ground truth —
    // is gated behind the `c-parity` feature. Default / release / Docker / CI
    // gateway builds need NO C toolchain and run NO build-time C: the shipping
    // Rust tables and the HPACK fixture below are all derived in Rust (text-
    // parsing the vendored NGINX source + a Rust HPACK encoder). The gateway's
    // library has zero `extern "C"`, so the oracle never ships either way. Run
    // the oracle with `cargo test --features c-parity`.
    let c_parity = env::var("CARGO_FEATURE_C_PARITY").is_ok();

    // Vendored nginx huffman sources (in-tree under nginx-src/). Originally read
    // from the surrounding nginx-master/src/http tree via an out-of-repo `../`
    // path; copied in so the crate builds reproducibly anywhere.
    let huff_dec_src = manifest.join("nginx-src/ngx_http_huff_decode.c");
    let huff_enc_src = manifest.join("nginx-src/ngx_http_huff_encode.c");

    if huff_dec_src.exists() {
        println!("cargo:rerun-if-changed={}", huff_dec_src.display());
        let entries = parse_huff_decode_entries(
            &fs::read_to_string(&huff_dec_src).expect("read huff decode c"),
        );
        assert_eq!(
            entries.len(),
            4096,
            "expected 256×16 Huffman decode entries, got {}",
            entries.len()
        );
        // SHIPS: Rust decode tables (pure text-parse of the NGINX source).
        write_huff_rust(&entries, &out_dir.join("huff_tables.rs"));
        if c_parity {
            // C-oracle decode table (only fed to the cc::Build below).
            write_huff_c(&entries, &manifest.join("tests/c/huff_tables_gen.c"));
        }

        if huff_enc_src.exists() {
            println!("cargo:rerun-if-changed={}", huff_enc_src.display());
            let enc_text = fs::read_to_string(&huff_enc_src).expect("read huff encode c");
            let enc_table = parse_huff_encode_table(&enc_text);
            assert_eq!(enc_table.len(), 256, "encode table size");
            // SHIPS: Rust encode table (pure text-parse of the NGINX source).
            write_huff_encode_rust(&enc_table, &out_dir.join("huff_encode_table.rs"));
            if c_parity {
                write_huff_encode_c(
                    &enc_table,
                    &manifest.join("tests/c/huff_encode_table_gen.c"),
                );
            }

            // SHIPS: HPACK Huffman fixture for "www.example.com", computed in
            // pure Rust from the parsed encode table. This previously compiled
            // and EXECUTED an NGINX C generator at build time — gratuitous, since
            // the value is a deterministic constant. The roundtrip decode below
            // still asserts the fixture is valid.
            let www = b"www.example.com";
            let enc_www = rust_huff_encode(www, &enc_table);
            let table = entries_to_table(&entries);
            let dec_www = huff_decode(&enc_www, &table).expect("roundtrip www.example.com");
            assert_eq!(dec_www, www, "huff roundtrip");
            write_huff_fixtures(&enc_www, www, &out_dir.join("huff_fixtures.rs"));
        }
    }

    if c_parity {
        // Compile the real NGINX C extracts into a static lib for the parity
        // tests/benches to link against. The gateway never references these
        // symbols, so even when built they are dead-stripped from the binary.
        cc::Build::new()
            .file("tests/c/nginx_algos.c")
            .file("tests/c/radix_tree.c")
            .file("tests/c/ngx_parse_time.c")
            .file("tests/c/huff_decode.c")
            .file("tests/c/huff_tables_gen.c")
            .file("tests/c/huff_encode.c")
            .file("tests/c/huff_encode_table_gen.c")
            .file("tests/c/v3_varint.c")
            .file("tests/c/proxy_protocol.c")
            .file("tests/c/conf_scan.c")
            .file("tests/c/http_v2_frame.c")
            .file("tests/c/chunked.c")
            .opt_level(3)
            .warnings(false)
            .compile("nginx_algos_c");
    }
}

fn parse_hex_byte(s: &str) -> u8 {
    u8::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap()
}

fn parse_huff_decode_entries(content: &str) -> Vec<[u8; 4]> {
    let mut out = Vec::with_capacity(4096);
    let mut rest = content.as_bytes();
    let needle = b"{0x";
    while let Some(i) = find_subslice(rest, needle) {
        let after = &rest[i..];
        let Some(j) = after.iter().position(|&b| b == b'}') else {
            break;
        };
        let inner = std::str::from_utf8(&after[1..j]).expect("utf8");
        let mut parts = inner.split(',');
        let a = parse_hex_byte(parts.next().expect("a"));
        let b = parse_hex_byte(parts.next().expect("b"));
        let c = parse_hex_byte(parts.next().expect("c"));
        let d = parse_hex_byte(parts.next().expect("d"));
        assert!(parts.next().is_none());
        out.push([a, b, c, d]);
        rest = &after[j + 1..];
    }
    out
}

fn parse_huff_encode_table(content: &str) -> Vec<(u32, u8)> {
    let start = content
        .find("ngx_http_huff_encode_table[256]")
        .expect("encode table");
    let end = content
        .find("ngx_http_huff_encode_table_lc")
        .expect("encode table lc");
    let slice = &content[start..end];
    let mut out = Vec::with_capacity(256);
    let mut rest = slice.as_bytes();
    let needle = b"{0x";
    while out.len() < 256 {
        let Some(i) = find_subslice(rest, needle) else {
            break;
        };
        let after = &rest[i..];
        let Some(j) = after.iter().position(|&b| b == b'}') else {
            break;
        };
        let inner = std::str::from_utf8(&after[1..j]).expect("utf8");
        let mut parts = inner.split(',');
        let code = u32::from_str_radix(
            parts
                .next()
                .expect("code")
                .trim()
                .trim_start_matches("0x"),
            16,
        )
        .expect("code hex");
        let len: u8 = parts
            .next()
            .expect("len")
            .trim()
            .parse()
            .expect("len parse");
        assert!(parts.next().is_none());
        out.push((code, len));
        rest = &after[j + 1..];
    }
    out
}

/// HPACK (RFC 7541) Huffman-encode `input` using the parsed NGINX encode table.
/// Pure Rust — replaces the old build-time path that compiled and EXECUTED an
/// NGINX C generator just to produce a deterministic fixture. Each symbol
/// contributes its `len` most-significant bits of `code`; the final byte is
/// padded with 1-bits (the EOS prefix), exactly as NGINX/HPACK specify.
fn rust_huff_encode(input: &[u8], table: &[(u32, u8)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u64 = 0; // valid bits live in the low `nbits` bits
    let mut nbits: u32 = 0;
    for &b in input {
        let (code, len) = table[b as usize];
        let len = len as u32;
        acc = (acc << len) | (code as u64 & ((1u64 << len) - 1));
        nbits += len;
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1u64 << nbits) - 1; // drop the bits already emitted
        }
    }
    if nbits > 0 {
        let pad = 8 - nbits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
    out
}

fn write_huff_encode_rust(table: &[(u32, u8)], path: &Path) {
    let mut s = String::from(
        "// @generated from ngx_http_huff_encode.c — do not edit\n\n\
         #[derive(Copy, Clone)]\n\
         pub struct HuffEnc {\n\
             pub code: u32,\n\
             pub len: u8,\n\
         }\n\n\
         pub static HUFF_ENCODE_TABLE: [HuffEnc; 256] = [\n",
    );
    for &(code, len) in table {
        s.push_str(&format!("    HuffEnc {{ code: 0x{code:08x}, len: {len} }},\n"));
    }
    s.push_str(
        "];\n\n\
         /// `code | (len as u64) << 32` — single load per source byte in the encoder hot loop.\n\
         pub static HUFF_ENCODE_PACKED: [u64; 256] = [\n",
    );
    for &(code, len) in table {
        let packed = (code as u64) | ((len as u64) << 32);
        s.push_str(&format!("    0x{packed:016x},\n"));
    }
    s.push_str("];\n");
    fs::write(path, s).expect("write huff_encode_table.rs");
}

fn write_huff_encode_c(table: &[(u32, u8)], path: &Path) {
    let mut s = String::from(
        "/* @generated from ngx_http_huff_encode.c */\n\
         #include <stdint.h>\n\n\
         typedef struct { uint32_t code; uint8_t len; } huff_enc_code_t;\n\n\
         const huff_enc_code_t huff_encode_table[256] = {\n",
    );
    for &(code, len) in table {
        s.push_str(&format!("    {{0x{code:08x}, {len}}},\n"));
    }
    s.push_str("};\n");
    fs::write(path, s).expect("write huff_encode_table_gen.c");
}

fn entries_to_table(entries: &[[u8; 4]]) -> [[[u8; 4]; 16]; 256] {
    let mut t = [[[0u8; 4]; 16]; 256];
    for (i, chunk) in entries.chunks(16).enumerate() {
        for (j, code) in chunk.iter().enumerate() {
            t[i][j] = *code;
        }
    }
    t
}

fn huff_decode(enc: &[u8], table: &[[[u8; 4]; 16]]) -> Option<Vec<u8>> {
    let mut state = 0u8;
    let mut ending = 1u8;
    let mut out = Vec::new();
    for &ch in enc {
        for bits in [ch >> 4, ch & 0x0f] {
            let [next, emit, sym, end] = table[state as usize][bits as usize];
            if next == state {
                return None;
            }
            if emit != 0 {
                out.push(sym);
            }
            ending = end;
            state = next;
        }
    }
    if ending == 0 {
        return None;
    }
    Some(out)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn write_huff_rust(entries: &[[u8; 4]], path: &Path) {
    let mut s = String::from(
        "// @generated from ../src/http/ngx_http_huff_decode.c — do not edit\n\n\
         #[repr(C)]\n\
         #[derive(Copy, Clone)]\n\
         pub struct HuffCode {\n\
             pub next: u8,\n\
             pub emit: u8,\n\
             pub sym: u8,\n\
             pub ending: u8,\n\
         }\n\n\
         pub static HUFF_DECODE_CODES: [[HuffCode; 16]; 256] = [\n",
    );
    for (row, chunk) in entries.chunks(16).enumerate() {
        s.push_str(&format!("    /* {row} */\n    [\n"));
        for [n, e, sym, end] in chunk {
            s.push_str(&format!(
                "        HuffCode {{ next: 0x{n:02x}, emit: 0x{e:02x}, sym: 0x{sym:02x}, ending: 0x{end:02x} }},\n"
            ));
        }
        s.push_str("    ],\n");
    }
    s.push_str(
        "];\n\n\
         /// Packed rows: `next | emit<<8 | sym<<16 | ending<<24` — flat index `(state<<4)|nibble`.\n\
         pub static HUFF_DECODE_FLAT: [u32; 4096] = [\n",
    );
    let mut flat = [0u32; 4096];
    for (i, [n, e, sym, end]) in entries.iter().enumerate() {
        let w = (*n as u32) | ((*e as u32) << 8) | ((*sym as u32) << 16) | ((*end as u32) << 24);
        flat[i] = w;
        s.push_str(&format!("    0x{w:08x},\n"));
    }
    s.push_str("];\n");
    s.push_str(
        "\n/// One lookup per input byte: valid bit0, next<<1, emit_count<<9, sym0<<11, sym1<<19.\n\
         pub static HUFF_DECODE_BYTE: [u64; 65536] = [\n",
    );
    for state in 0u16..256 {
        for ch in 0u16..256 {
            let packed = pack_huff_byte_step(&flat, state as u8, ch as u8);
            s.push_str(&format!("    0x{packed:016x},\n"));
        }
    }
    s.push_str("];\n");
    fs::write(path, s).expect("write huff_tables.rs");
}

fn pack_huff_byte_step(flat: &[u32; 4096], state: u8, ch: u8) -> u64 {
    let w1 = flat[((state as usize) << 4) | (ch >> 4) as usize];
    let n1 = (w1 & 0xff) as u8;
    if n1 == state {
        return 0;
    }
    let mut syms = [0u8; 2];
    let mut n = 0u8;
    if w1 & 0xff00 != 0 {
        syms[0] = ((w1 >> 16) & 0xff) as u8;
        n = 1;
    }
    let w2 = flat[((n1 as usize) << 4) | (ch & 0xf) as usize];
    let n2 = (w2 & 0xff) as u8;
    if n2 == n1 {
        return 0;
    }
    if w2 & 0xff00 != 0 {
        if n == 0 {
            syms[0] = ((w2 >> 16) & 0xff) as u8;
            n = 1;
        } else {
            syms[1] = ((w2 >> 16) & 0xff) as u8;
            n = 2;
        }
    }
    1u64
        | ((n2 as u64) << 1)
        | ((n as u64) << 9)
        | ((syms[0] as u64) << 11)
        | ((syms[1] as u64) << 19)
}

fn write_huff_c(entries: &[[u8; 4]], path: &Path) {
    let mut s = String::from(
        "/* @generated from ngx_http_huff_decode.c */\n\
         #include <stdint.h>\n\n\
         typedef struct {\n\
             uint8_t next;\n\
             uint8_t emit;\n\
             uint8_t sym;\n\
             uint8_t ending;\n\
         } huff_code_t;\n\n\
         const huff_code_t huff_decode_codes[256][16] = {\n",
    );
    for chunk in entries.chunks(16) {
        s.push_str("    {\n");
        for [n, e, sym, end] in chunk {
            s.push_str(&format!(
                "        {{0x{n:02x}, 0x{e:02x}, 0x{sym:02x}, 0x{end:02x}}},\n"
            ));
        }
        s.push_str("    },\n");
    }
    s.push_str("};\n");
    fs::write(path, s).expect("write huff_tables_gen.c");
}

fn write_huff_fixtures(enc: &[u8], plain: &[u8], path: &Path) {
    let enc_lit = enc
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let plain_lit = plain
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let s = format!(
        "// @generated by build.rs — HPACK Huffman fixture for www.example.com\n\n\
         pub const HUFF_WWW_EXAMPLE_ENC: &[u8] = &[{enc_lit}];\n\
         pub const HUFF_WWW_EXAMPLE_PLAIN: &[u8] = &[{plain_lit}];\n"
    );
    fs::write(path, s).expect("write huff_fixtures.rs");
}
