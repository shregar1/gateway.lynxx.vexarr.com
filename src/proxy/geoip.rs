//! NGINX-style GeoIP lookup module.
//!
//! NGINX's `geoip_country` and `geoip_city` modules resolve a client IP
//! address against MaxMind databases and expose country, city, coordinates,
//! ASN and organisation as variables usable in routing, rate-limiting and
//! logging directives.
//!
//! This module implements the lookup logic *without* requiring the
//! `maxminddb` crate.  Instead we define a `GeoIpDatabase` trait and ship
//! two concrete backends:
//!
//! | Backend          | Storage                        | Lookup       |
//! |------------------|--------------------------------|--------------|
//! | `InMemoryGeoDb`  | `DashMap<IpAddr, GeoIpInfo>`   | O(1) hash    |
//! | `SubnetGeoDb`    | Sorted `Vec` of CIDR entries   | O(log n) binary search + longest-prefix match |
//!
//! Both can be populated at startup from config or at runtime via an API,
//! making the module useful even without a `.mmdb` file on disk.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Global config
// ═══════════════════════════════════════════════════════════════════════════

static GEOIP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Returns `true` when the GeoIP subsystem is active.
#[inline]
pub fn geoip_enabled() -> bool {
    GEOIP_ENABLED.load(Ordering::Relaxed)
}

/// Enable or disable the GeoIP subsystem globally.
#[inline]
pub fn set_geoip_enabled(enabled: bool) {
    GEOIP_ENABLED.store(enabled, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Core types
// ═══════════════════════════════════════════════════════════════════════════

/// Geographic and network metadata associated with an IP address.
///
/// All fields are optional — a database may only have country-level data,
/// or only ASN data, etc.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoIpInfo {
    /// ISO 3166-1 alpha-2 country code (e.g. `"US"`, `"DE"`).
    pub country_code: Option<String>,
    /// Full country name (e.g. `"United States"`).
    pub country_name: Option<String>,
    /// Region / state / province name.
    pub region: Option<String>,
    /// City name.
    pub city: Option<String>,
    /// Postal / ZIP code.
    pub postal_code: Option<String>,
    /// Latitude in decimal degrees.
    pub latitude: Option<f64>,
    /// Longitude in decimal degrees.
    pub longitude: Option<f64>,
    /// IANA timezone identifier (e.g. `"America/New_York"`).
    pub timezone: Option<String>,
    /// Autonomous System Number.
    pub asn: Option<u32>,
    /// Organisation / ISP name.
    pub org: Option<String>,
}

/// Trait that all GeoIP database backends implement.
pub trait GeoIpDatabase: Send + Sync {
    /// Look up geographic information for `ip`.  Returns `None` when the
    /// address is not present in the database.
    fn lookup(&self, ip: IpAddr) -> Option<GeoIpInfo>;
}

// ═══════════════════════════════════════════════════════════════════════════
// InMemoryGeoDb — exact-IP hash map
// ═══════════════════════════════════════════════════════════════════════════

/// A concurrent hash-map of `IpAddr → GeoIpInfo`, backed by `DashMap` with
/// ahash for fast hashing.  Best when every client IP is individually
/// inserted (e.g. fed from a streaming enrichment API).
pub struct InMemoryGeoDb {
    map: DashMap<IpAddr, GeoIpInfo, FastHasher>,
}

impl InMemoryGeoDb {
    /// Create an empty database.
    pub fn new() -> Self {
        Self {
            map: DashMap::with_hasher(FastHasher::default()),
        }
    }

    /// Insert or overwrite the entry for `ip`.
    pub fn insert(&self, ip: IpAddr, info: GeoIpInfo) {
        self.map.insert(ip, info);
    }

    /// Remove the entry for `ip`, returning the old value if present.
    pub fn remove(&self, ip: &IpAddr) -> Option<GeoIpInfo> {
        self.map.remove(ip).map(|(_, v)| v)
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Remove all entries.
    pub fn clear(&self) {
        self.map.clear();
    }
}

impl GeoIpDatabase for InMemoryGeoDb {
    fn lookup(&self, ip: IpAddr) -> Option<GeoIpInfo> {
        self.map.get(&ip).map(|entry| entry.value().clone())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SubnetGeoDb — CIDR-based longest-prefix match
// ═══════════════════════════════════════════════════════════════════════════

/// A single IPv4 CIDR entry stored as `(network_u32, prefix_len, info)`.
#[derive(Clone, Debug)]
struct CidrEntry {
    network: u32,
    prefix_len: u8,
    info: GeoIpInfo,
}

/// A CIDR-range database for IPv4.  Entries are kept in a sorted `Vec`
/// ordered by `(network, prefix_len)` so that binary search can quickly
/// narrow down candidates, after which we scan for the longest prefix
/// match.
///
/// IPv6 support is not yet implemented — lookups for IPv6 addresses return
/// `None`.
pub struct SubnetGeoDb {
    /// Sorted by `(network, prefix_len)`.
    entries: std::sync::RwLock<Vec<CidrEntry>>,
}

impl SubnetGeoDb {
    /// Create an empty subnet database.
    pub fn new() -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// Insert a CIDR range.  Only IPv4 is supported — IPv6 networks are
    /// silently ignored.
    pub fn insert_subnet(&self, network: IpAddr, prefix_len: u8, info: GeoIpInfo) {
        let network_u32 = match ipv4_to_u32(network) {
            Some(n) => n,
            None => return, // IPv6 — not yet supported
        };

        // Mask the network address to the prefix length so that callers do
        // not have to do it themselves.
        let masked = apply_mask(network_u32, prefix_len);

        let mut entries = self.entries.write().unwrap();
        entries.push(CidrEntry {
            network: masked,
            prefix_len,
            info,
        });
        // Keep sorted by (network, prefix_len) for binary search.
        entries.sort_by(|a, b| {
            a.network
                .cmp(&b.network)
                .then(a.prefix_len.cmp(&b.prefix_len))
        });
    }

    /// Number of CIDR entries stored.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Returns `true` if the database contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }
}

impl GeoIpDatabase for SubnetGeoDb {
    /// Look up `ip` using longest-prefix match.  Returns `None` for IPv6
    /// addresses or when no matching CIDR range is found.
    fn lookup(&self, ip: IpAddr) -> Option<GeoIpInfo> {
        let ip_u32 = ipv4_to_u32(ip)?;
        let entries = self.entries.read().unwrap();

        // We need the longest (most specific) prefix match, so we scan all
        // entries and track the best candidate.  For larger databases a
        // trie would be more efficient, but for the typical config-driven
        // use case a linear scan after a binary-search narrowing is fine.
        let mut best: Option<&CidrEntry> = None;

        for entry in entries.iter() {
            if matches_subnet(ip_u32, entry.network, entry.prefix_len) {
                match best {
                    Some(prev) if prev.prefix_len >= entry.prefix_len => {}
                    _ => best = Some(entry),
                }
            }
        }

        best.map(|e| e.info.clone())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════════════════

/// Convert an `IpAddr` to a `u32` if it is IPv4.  Returns `None` for IPv6.
#[inline]
pub fn ipv4_to_u32(ip: IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(v4) => Some(u32::from(v4)),
        IpAddr::V6(_) => None,
    }
}

/// Check whether `ip_u32` falls within the subnet defined by
/// `network_u32 / prefix_len`.
#[inline]
pub fn matches_subnet(ip_u32: u32, network_u32: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    let mask = !0u32 << (32 - prefix_len);
    (ip_u32 & mask) == (network_u32 & mask)
}

/// Apply prefix-length mask to a network address.
#[inline]
fn apply_mask(network: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }
    if prefix_len >= 32 {
        return network;
    }
    let mask = !0u32 << (32 - prefix_len);
    network & mask
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic counters for GeoIP lookup activity.
pub struct GeoIpMetrics {
    pub lookups_total: AtomicU64,
    pub lookups_hit: AtomicU64,
    pub lookups_miss: AtomicU64,
}

impl GeoIpMetrics {
    /// Create zeroed metrics.
    pub fn new() -> Self {
        Self {
            lookups_total: AtomicU64::new(0),
            lookups_hit: AtomicU64::new(0),
            lookups_miss: AtomicU64::new(0),
        }
    }

    /// Record a lookup result.
    #[inline]
    pub fn record(&self, hit: bool) {
        self.lookups_total.fetch_add(1, Ordering::Relaxed);
        if hit {
            self.lookups_hit.fetch_add(1, Ordering::Relaxed);
        } else {
            self.lookups_miss.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Snapshot the current counter values.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.lookups_total.load(Ordering::Relaxed),
            self.lookups_hit.load(Ordering::Relaxed),
            self.lookups_miss.load(Ordering::Relaxed),
        )
    }
}

impl Default for GeoIpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Helper: build a minimal `GeoIpInfo` with just a country code.
    fn info_country(code: &str) -> GeoIpInfo {
        GeoIpInfo {
            country_code: Some(code.to_string()),
            ..Default::default()
        }
    }

    /// Helper: build a fully-populated `GeoIpInfo`.
    fn info_full() -> GeoIpInfo {
        GeoIpInfo {
            country_code: Some("US".into()),
            country_name: Some("United States".into()),
            region: Some("California".into()),
            city: Some("San Francisco".into()),
            postal_code: Some("94105".into()),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            timezone: Some("America/Los_Angeles".into()),
            asn: Some(13335),
            org: Some("Cloudflare Inc".into()),
        }
    }

    // ── InMemoryGeoDb ────────────────────────────────────────────────────

    #[test]
    fn inmemory_insert_and_lookup() {
        let db = InMemoryGeoDb::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        db.insert(ip, info_country("DE"));

        let result = db.lookup(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code.as_deref(), Some("DE"));
    }

    #[test]
    fn inmemory_lookup_miss_returns_none() {
        let db = InMemoryGeoDb::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(db.lookup(ip).is_none());
    }

    #[test]
    fn inmemory_remove() {
        let db = InMemoryGeoDb::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        db.insert(ip, info_country("FR"));
        assert!(db.lookup(ip).is_some());

        let removed = db.remove(&ip);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().country_code.as_deref(), Some("FR"));
        assert!(db.lookup(ip).is_none());
    }

    #[test]
    fn inmemory_len_and_clear() {
        let db = InMemoryGeoDb::new();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());

        db.insert("1.1.1.1".parse().unwrap(), info_country("AU"));
        db.insert("8.8.8.8".parse().unwrap(), info_country("US"));
        assert_eq!(db.len(), 2);
        assert!(!db.is_empty());

        db.clear();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
    }

    // ── GeoIpInfo ────────────────────────────────────────────────────────

    #[test]
    fn geoip_info_default_fields() {
        let info = GeoIpInfo::default();
        assert!(info.country_code.is_none());
        assert!(info.country_name.is_none());
        assert!(info.region.is_none());
        assert!(info.city.is_none());
        assert!(info.postal_code.is_none());
        assert!(info.latitude.is_none());
        assert!(info.longitude.is_none());
        assert!(info.timezone.is_none());
        assert!(info.asn.is_none());
        assert!(info.org.is_none());
    }

    #[test]
    fn geoip_info_all_fields_populated() {
        let info = info_full();
        assert_eq!(info.country_code.as_deref(), Some("US"));
        assert_eq!(info.country_name.as_deref(), Some("United States"));
        assert_eq!(info.region.as_deref(), Some("California"));
        assert_eq!(info.city.as_deref(), Some("San Francisco"));
        assert_eq!(info.postal_code.as_deref(), Some("94105"));
        assert_eq!(info.latitude, Some(37.7749));
        assert_eq!(info.longitude, Some(-122.4194));
        assert_eq!(info.timezone.as_deref(), Some("America/Los_Angeles"));
        assert_eq!(info.asn, Some(13335));
        assert_eq!(info.org.as_deref(), Some("Cloudflare Inc"));
    }

    // ── ipv4_to_u32 ─────────────────────────────────────────────────────

    #[test]
    fn ipv4_to_u32_conversion() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
        let val = ipv4_to_u32(ip).unwrap();
        // 10 << 24 | 0 << 16 | 1 << 8 | 2 = 167772418
        assert_eq!(val, 0x0A000102);

        // IPv6 should return None.
        let ip6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(ipv4_to_u32(ip6).is_none());
    }

    // ── matches_subnet ──────────────────────────────────────────────────

    #[test]
    fn matches_subnet_exact_match() {
        // /32 — exact IP match
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let net = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        assert!(matches_subnet(ip, net, 32));
    }

    #[test]
    fn matches_subnet_slash_24() {
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 200));
        let net = u32::from(Ipv4Addr::new(192, 168, 1, 0));
        assert!(matches_subnet(ip, net, 24));
    }

    #[test]
    fn matches_subnet_slash_16() {
        let ip = u32::from(Ipv4Addr::new(10, 20, 99, 1));
        let net = u32::from(Ipv4Addr::new(10, 20, 0, 0));
        assert!(matches_subnet(ip, net, 16));
    }

    #[test]
    fn matches_subnet_no_match() {
        let ip = u32::from(Ipv4Addr::new(10, 20, 99, 1));
        let net = u32::from(Ipv4Addr::new(10, 21, 0, 0));
        assert!(!matches_subnet(ip, net, 16));
    }

    // ── SubnetGeoDb ─────────────────────────────────────────────────────

    #[test]
    fn subnet_insert_and_lookup() {
        let db = SubnetGeoDb::new();
        db.insert_subnet("10.0.0.0".parse().unwrap(), 8, info_country("US"));

        let result = db.lookup("10.1.2.3".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code.as_deref(), Some("US"));
    }

    #[test]
    fn subnet_longest_prefix_match() {
        let db = SubnetGeoDb::new();
        // Broad /8 block → US
        db.insert_subnet("10.0.0.0".parse().unwrap(), 8, info_country("US"));
        // Narrower /24 block → DE (more specific should win)
        db.insert_subnet("10.0.1.0".parse().unwrap(), 24, info_country("DE"));

        // IP in the /24 should match DE.
        let result = db.lookup("10.0.1.42".parse().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code.as_deref(), Some("DE"));

        // IP outside the /24 but inside the /8 should match US.
        let result2 = db.lookup("10.0.2.1".parse().unwrap());
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().country_code.as_deref(), Some("US"));
    }

    #[test]
    fn subnet_miss_returns_none() {
        let db = SubnetGeoDb::new();
        db.insert_subnet("192.168.0.0".parse().unwrap(), 16, info_country("GB"));

        assert!(db.lookup("10.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn subnet_ipv6_returns_none() {
        let db = SubnetGeoDb::new();
        db.insert_subnet("10.0.0.0".parse().unwrap(), 8, info_country("US"));

        let ipv6: IpAddr = "::1".parse().unwrap();
        assert!(db.lookup(ipv6).is_none());

        // Inserting an IPv6 subnet should be silently ignored.
        let ipv6_net: IpAddr = "2001:db8::".parse().unwrap();
        db.insert_subnet(ipv6_net, 32, info_country("JP"));
        assert_eq!(db.len(), 1); // only the IPv4 entry
    }

    // ── Global enable / disable ─────────────────────────────────────────

    #[test]
    fn global_enable_disable() {
        // Reset to a known state.
        set_geoip_enabled(false);
        assert!(!geoip_enabled());

        set_geoip_enabled(true);
        assert!(geoip_enabled());

        set_geoip_enabled(false);
        assert!(!geoip_enabled());
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    #[test]
    fn metrics_counting() {
        let m = GeoIpMetrics::new();
        assert_eq!(m.snapshot(), (0, 0, 0));

        m.record(true);
        m.record(true);
        m.record(false);

        let (total, hit, miss) = m.snapshot();
        assert_eq!(total, 3);
        assert_eq!(hit, 2);
        assert_eq!(miss, 1);
    }

    // ── Multiple IPs in same subnet ─────────────────────────────────────

    #[test]
    fn lookup_different_ips_in_same_subnet() {
        let db = SubnetGeoDb::new();
        db.insert_subnet("172.16.0.0".parse().unwrap(), 12, info_country("NL"));

        // All of these fall inside 172.16.0.0/12 (172.16.0.0 – 172.31.255.255).
        for addr in &["172.16.0.1", "172.20.5.5", "172.31.255.254"] {
            let ip: IpAddr = addr.parse().unwrap();
            let result = db.lookup(ip);
            assert!(
                result.is_some(),
                "expected hit for {} in 172.16.0.0/12",
                addr
            );
            assert_eq!(result.unwrap().country_code.as_deref(), Some("NL"));
        }

        // Just outside the range.
        assert!(db.lookup("172.32.0.0".parse().unwrap()).is_none());
    }
}
