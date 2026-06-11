#![no_main]
use libfuzzer_sys::fuzz_target;
use algorithms::goals::optimized::base64_decode::{decode_base64_fast, decode_base64url_fast};

fuzz_target!(|data: &[u8]| {
    let mut dst = vec![0u8; data.len() + 16];
    let _ = decode_base64_fast(&mut dst, data);
    let _ = decode_base64url_fast(&mut dst, data);
});
