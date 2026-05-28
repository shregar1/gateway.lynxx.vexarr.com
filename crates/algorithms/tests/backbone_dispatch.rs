use algorithms::backbone::*;

#[test]
fn hasher_dispatch() {
    let h = create_hasher();
    let name = h.name();
    
    #[cfg(feature = "tier-pro")]
    assert_eq!(name, "xxh64");
    
    #[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
    assert_eq!(name, "siphash13");
    
    #[cfg(not(feature = "tier-growth"))]
    assert_eq!(name, "murmur2");
    
    // Verify it actually hashes
    let digest = h.hash(b"hello world");
    assert_ne!(digest, 0);
}

#[test]
fn checksummer_dispatch() {
    let c = create_checksummer();
    let name = c.name();
    
    #[cfg(feature = "tier-pro")]
    assert_eq!(name, "crc32_slice8");
    
    #[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
    assert_eq!(name, "crc32_long_table");
    
    #[cfg(not(feature = "tier-growth"))]
    assert_eq!(name, "crc32_short_nibble");
    
    let sum = c.checksum(b"test data");
    assert_ne!(sum, 0);
}

#[test]
fn base64_dispatch() {
    let codec = create_base64();
    
    #[cfg(feature = "tier-pro")]
    assert_eq!(codec.name(), "fast_base64");
    
    #[cfg(not(feature = "tier-pro"))]
    assert_eq!(codec.name(), "standard_base64");

    // Round-trip test
    let src = b"Hello, Lynxx!";
    let mut encoded = vec![0u8; 64];
    let elen = codec.encode(&mut encoded, src);
    assert!(elen > 0);

    let mut decoded = vec![0u8; 64];
    let dlen = codec.decode(&mut decoded, &encoded[..elen]);
    assert_eq!(dlen as usize, src.len());
    assert_eq!(&decoded[..dlen as usize], &src[..]);
}

#[test]
fn uri_codec_dispatch() {
    let codec = create_uri_codec();
    
    #[cfg(feature = "tier-pro")]
    assert_eq!(codec.name(), "fast_uri");
    
    #[cfg(not(feature = "tier-pro"))]
    assert_eq!(codec.name(), "standard_uri");
}

#[cfg(feature = "tier-growth")]
#[test]
fn huffman_dispatch() {
    let codec = create_huffman();
    
    #[cfg(feature = "tier-pro")]
    assert_eq!(codec.name(), "fast_huffman");
    
    #[cfg(not(feature = "tier-pro"))]
    assert_eq!(codec.name(), "standard_huffman");
}

#[cfg(feature = "tier-pro")]
#[test]
fn congestion_dispatch() {
    let cc = create_congestion();
    assert_eq!(cc.name(), "cubic");
}

#[test]
fn load_balancer_trait() {
    // Constructor differs per tier
    #[cfg(not(feature = "tier-growth"))]
    let mut lb = TierLoadBalancer::new(&[10u32, 20, 30]);

    #[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
    let mut lb = TierLoadBalancer::new(3, 10_000_000_000); // 3 backends, 10s decay

    #[cfg(feature = "tier-pro")]
    let mut lb = TierLoadBalancer::new(&["a", "b", "c"]);

    let ctx = LbContext::new(1_000_000);
    let idx = lb.pick(&ctx);
    assert!(idx < 3);
}

#[test]
fn health_checker_trait() {
    let mut hc = TierHealthChecker::new(3, 5000);
    assert!(hc.allow_request(1000));
    hc.record_failure(1000);
    hc.record_failure(1001);
    hc.record_failure(1002);
}
