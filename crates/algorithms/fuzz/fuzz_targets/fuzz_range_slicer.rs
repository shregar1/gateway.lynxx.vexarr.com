#![no_main]
use libfuzzer_sys::fuzz_target;
use algorithms::goals::http_codec::range_slicer::RangeSlicer;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = RangeSlicer::parse_content_range(s);
        let _ = RangeSlicer::parse_range_header(s);
    }
});
