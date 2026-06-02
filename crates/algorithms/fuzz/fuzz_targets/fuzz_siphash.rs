#![no_main]
use libfuzzer_sys::fuzz_target;
use algorithms::goals::hash::siphash::SipHasher;

fuzz_target!(|data: &[u8]| {
    let h1 = SipHasher::hash(0, 0, data);
    let h2 = SipHasher::hash(0, 0, data);
    assert_eq!(h1, h2, "SipHash must be deterministic");

    let mut hasher = SipHasher::new(0, 0);
    hasher.write(data);
    assert_eq!(hasher.finish(), h1, "incremental must match one-shot");
});
