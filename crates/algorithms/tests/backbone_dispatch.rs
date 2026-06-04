use algorithms::backbone::*;

#[test]
fn hasher_dispatch_picks_per_tier() {
    assert_eq!(create_hasher(Tier::Starter).name(), "murmur2");
    assert_eq!(create_hasher(Tier::Growth).name(), "siphash13");
    assert_eq!(create_hasher(Tier::Pro).name(), "xxh64");

    let digest = create_hasher(Tier::Pro).hash(b"hello world");
    assert_ne!(digest, 0);
}

#[test]
fn checksummer_dispatch_picks_per_tier() {
    assert_eq!(create_checksummer(Tier::Starter).name(), "crc32_short_nibble");
    assert_eq!(create_checksummer(Tier::Growth).name(), "crc32_long_table");
    assert_eq!(create_checksummer(Tier::Pro).name(), "crc32_slice8");

    let sum = create_checksummer(Tier::Growth).checksum(b"test data");
    assert_ne!(sum, 0);
}

#[test]
fn base64_dispatch_picks_per_tier() {
    assert_eq!(create_base64(Tier::Starter).name(), "standard_base64");
    assert_eq!(create_base64(Tier::Growth).name(), "standard_base64");
    assert_eq!(create_base64(Tier::Pro).name(), "fast_base64");

    let codec = create_base64(Tier::Pro);
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
fn uri_codec_dispatch_picks_per_tier() {
    assert_eq!(create_uri_codec(Tier::Starter).name(), "standard_uri");
    assert_eq!(create_uri_codec(Tier::Growth).name(), "standard_uri");
    assert_eq!(create_uri_codec(Tier::Pro).name(), "fast_uri");
}

#[test]
fn huffman_dispatch_picks_per_tier() {
    assert_eq!(create_huffman(Tier::Starter).name(), "standard_huffman");
    assert_eq!(create_huffman(Tier::Growth).name(), "standard_huffman");
    assert_eq!(create_huffman(Tier::Pro).name(), "fast_huffman");
}

#[test]
fn congestion_dispatch_picks_per_tier() {
    assert_eq!(create_congestion(Tier::Starter).name(), "cubic");
    assert_eq!(create_congestion(Tier::Growth).name(), "cubic");
    assert_eq!(create_congestion(Tier::Pro).name(), "bbr");
}

#[test]
fn rate_limiter_dispatch_uses_for_tier() {
    let mut starter = TierRateLimiter::for_tier(Tier::Starter);
    let mut growth = TierRateLimiter::for_tier(Tier::Growth);
    let mut pro = TierRateLimiter::for_tier(Tier::Pro);

    assert_eq!(starter.name(), "leaky_bucket");
    assert_eq!(growth.name(), "token_bucket");
    assert_eq!(pro.name(), "gradient");

    let ctx = RateLimitContext::new(1_000_000_000);
    assert!(starter.allow(&ctx));
    assert!(growth.allow(&ctx));
    assert!(pro.allow(&ctx));
}

#[test]
fn load_balancer_dispatch_uses_for_tier() {
    let weights: &[u32] = &[10, 20, 30];
    let names: &[&str] = &["a", "b", "c"];

    let mut starter = TierLoadBalancer::for_tier(Tier::Starter, weights, names);
    let mut growth = TierLoadBalancer::for_tier(Tier::Growth, weights, names);
    let mut pro = TierLoadBalancer::for_tier(Tier::Pro, weights, names);

    assert_eq!(starter.name(), "fwrr");
    assert_eq!(growth.name(), "peak_ewma");
    assert_eq!(pro.name(), "maglev");

    let ctx = LbContext::new(1_000_000);
    assert!(starter.pick(&ctx) < 3);
    assert!(growth.pick(&ctx) < 3);
    let ctx_keyed = LbContext::with_key(1_000_000, b"req-key");
    assert!(pro.pick(&ctx_keyed) < 3);
}

#[test]
fn health_checker_dispatch_uses_for_tier() {
    let mut starter = TierHealthChecker::for_tier(Tier::Starter, 3, 5000);
    let mut growth = TierHealthChecker::for_tier(Tier::Growth, 3, 5000);
    let mut pro = TierHealthChecker::for_tier(Tier::Pro, 3, 5000);

    assert_eq!(starter.name(), "circuit_breaker");
    assert_eq!(growth.name(), "passive_health");
    assert_eq!(pro.name(), "passive_health");

    assert!(starter.allow_request(1000));
    assert!(growth.allow_request(1000));
    assert!(pro.allow_request(1000));
}

#[test]
fn tier_is_recoverable_from_factory_instance() {
    assert_eq!(create_hasher(Tier::Growth).tier(), Tier::Growth);
    assert_eq!(create_checksummer(Tier::Pro).tier(), Tier::Pro);
    assert_eq!(TierRateLimiter::for_tier(Tier::Starter).tier(), Tier::Starter);
}
