//! HAProxy-style `rdp-cookie` load balancing — RDP protocol cookie parsing
//! for TCP-level session persistence.
//!
//! Parses the `mstshash=USERNAME` cookie from the X.224 Connection Request PDU
//! inside the TPKT framing of an RDP initial connection. The extracted username
//! is hashed to pin sessions to specific backend servers, identical to
//! HAProxy's `balance rdp-cookie` mode.

use dashmap::DashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use uuid::Uuid;

type FastHasher = ahash::RandomState;

static RDP_COOKIE_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_rdp_cookie_enabled(enabled: bool) {
    RDP_COOKIE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_rdp_cookie_enabled() -> bool {
    RDP_COOKIE_ENABLED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// RDP cookie type
// ---------------------------------------------------------------------------

/// Parsed RDP cookie extracted from the X.224 Connection Request PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpCookie {
    pub username: String,
}

// ---------------------------------------------------------------------------
// Protocol parsing
// ---------------------------------------------------------------------------

/// Prefix that appears before the username in the RDP cookie field.
const MSTSHASH_PREFIX: &[u8] = b"mstshash=";

/// Parse the RDP cookie from raw TCP bytes using full TPKT + X.224 validation.
///
/// Expected packet layout:
/// ```text
/// [TPKT Header (4 bytes)]
///   03          — version
///   00          — reserved
///   XX XX       — length (big-endian u16)
/// [X.224 CR PDU]
///   LEN         — X.224 length (excludes self)
///   E0          — CR type (Connection Request)
///   00 00       — dst ref
///   00 00       — src ref
///   00          — class
/// [Cookie]
///   "Cookie: mstshash=USERNAME\r\n"
/// ```
pub fn parse_rdp_cookie(buf: &[u8]) -> Option<RdpCookie> {
    // Need at least TPKT header (4) + X.224 minimal header (6) = 10 bytes.
    if buf.len() < 10 {
        return None;
    }

    // Validate TPKT header: version must be 0x03.
    if buf[0] != 0x03 {
        return None;
    }

    // Extract TPKT length (bytes 2-3, big-endian u16).
    let tpkt_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if tpkt_len < 10 || tpkt_len > buf.len() {
        return None;
    }

    // X.224 CR PDU starts at byte 4. Byte 5 (index 5) should be 0xE0
    // for a Connection Request.
    if buf[5] != 0xE0 {
        return None;
    }

    // Search the entire TPKT payload (after the 4-byte TPKT header) for
    // the cookie prefix. This is more robust than hardcoding an offset
    // because X.224 variable-length fields can shift the cookie position.
    let payload = &buf[4..tpkt_len];

    let cookie_prefix = b"Cookie: mstshash=";
    let pos = find_subsequence(payload, cookie_prefix)?;
    let after_prefix = pos + cookie_prefix.len();
    if after_prefix >= payload.len() {
        return None;
    }

    // Extract until \r\n or end of payload.
    let rest = &payload[after_prefix..];
    let end = find_crlf(rest).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }

    let username = std::str::from_utf8(&rest[..end]).ok()?;
    Some(RdpCookie {
        username: username.to_string(),
    })
}

/// Simpler fallback: scan for `mstshash=` anywhere in the buffer and extract
/// until `\r\n` or end. Used when TPKT framing is incomplete or when the
/// caller just wants a best-effort extraction.
pub fn extract_rdp_cookie_raw(buf: &[u8]) -> Option<String> {
    let pos = find_subsequence(buf, MSTSHASH_PREFIX)?;
    let after = pos + MSTSHASH_PREFIX.len();
    if after >= buf.len() {
        return None;
    }
    let rest = &buf[after..];
    let end = find_crlf(rest).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&rest[..end]).ok().map(String::from)
}

/// Extract cookie value using a custom cookie name instead of the default
/// `mstshash`.
pub fn extract_rdp_cookie_named(buf: &[u8], cookie_name: &str) -> Option<String> {
    let prefix = format!("{cookie_name}=");
    let prefix_bytes = prefix.as_bytes();
    let pos = find_subsequence(buf, prefix_bytes)?;
    let after = pos + prefix_bytes.len();
    if after >= buf.len() {
        return None;
    }
    let rest = &buf[after..];
    let end = find_crlf(rest).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&rest[..end]).ok().map(String::from)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Hash the RDP cookie username using ahash for consistent routing. The same
/// username always produces the same hash, enabling session pinning.
pub fn hash_rdp_cookie(cookie: &RdpCookie) -> u64 {
    let mut hasher = ahash::AHasher::default();
    cookie.username.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for RDP cookie-based load balancing.
#[derive(Debug, Clone)]
pub struct RdpCookieConfig {
    /// Cookie name to extract. Defaults to `"mstshash"` (standard RDP), but
    /// HAProxy supports custom cookie names.
    pub cookie_name: String,
    /// Seed for deterministic hashing across restarts.
    pub hash_seed: u64,
}

impl Default for RdpCookieConfig {
    fn default() -> Self {
        Self {
            cookie_name: "mstshash".to_string(),
            hash_seed: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Session table
// ---------------------------------------------------------------------------

/// Sticky session table mapping RDP cookie values to target IDs. Provides
/// persistence beyond pure hash-based routing — once a cookie is seen it is
/// pinned to a specific target until explicitly removed or cleared.
pub struct RdpSessionTable {
    table: DashMap<String, Uuid, FastHasher>,
}

impl RdpSessionTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::with_hasher(FastHasher::default()),
        }
    }

    pub fn insert(&self, cookie: &str, target_id: Uuid) {
        self.table.insert(cookie.to_string(), target_id);
    }

    pub fn lookup(&self, cookie: &str) -> Option<Uuid> {
        self.table.get(cookie).map(|v| *v)
    }

    pub fn remove(&self, cookie: &str) {
        self.table.remove(cookie);
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn clear(&self) {
        self.table.clear();
    }
}

impl Default for RdpSessionTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Counters for RDP cookie parsing and session-table activity.
pub struct RdpCookieMetrics {
    pub cookies_parsed: AtomicU64,
    pub cookies_not_found: AtomicU64,
    pub parse_errors: AtomicU64,
    pub session_hits: AtomicU64,
    pub session_misses: AtomicU64,
}

impl RdpCookieMetrics {
    pub fn new() -> Self {
        Self {
            cookies_parsed: AtomicU64::new(0),
            cookies_not_found: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            session_hits: AtomicU64::new(0),
            session_misses: AtomicU64::new(0),
        }
    }
}

impl Default for RdpCookieMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Find the position of the first `\r\n` in `buf`.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    buf.windows(2).position(|w| w == b"\r\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid RDP TPKT + X.224 CR + Cookie packet for testing.
    fn build_rdp_packet(username: &str) -> Vec<u8> {
        let cookie = format!("Cookie: mstshash={}\r\n", username);
        // X.224 CR PDU: length indicator (1) + type (1) + dst_ref (2)
        //               + src_ref (2) + class (1) + cookie data.
        // The length indicator value = everything after itself.
        let x224_data_len = 1 + 2 + 2 + 1 + cookie.len(); // 6 fixed + cookie
        let tpkt_len = 4 + 1 + x224_data_len; // TPKT(4) + len_byte(1) + data
        let mut buf = Vec::with_capacity(tpkt_len);
        // TPKT header
        buf.push(0x03); // version
        buf.push(0x00); // reserved
        buf.push((tpkt_len >> 8) as u8);
        buf.push((tpkt_len & 0xFF) as u8);
        // X.224 CR PDU
        buf.push(x224_data_len as u8); // length indicator (excludes self)
        buf.push(0xE0); // CR type
        buf.extend_from_slice(&[0x00, 0x00]); // dst ref
        buf.extend_from_slice(&[0x00, 0x00]); // src ref
        buf.push(0x00); // class
        // Cookie
        buf.extend_from_slice(cookie.as_bytes());
        buf
    }

    // ── parse_rdp_cookie ──

    #[test]
    fn parse_valid_rdp_cookie() {
        let pkt = build_rdp_packet("admin");
        let cookie = parse_rdp_cookie(&pkt).expect("should parse valid packet");
        assert_eq!(cookie.username, "admin");
    }

    #[test]
    fn parse_cookie_different_usernames() {
        for name in &["john.doe", "WORKSTATION01", "user-123", "a"] {
            let pkt = build_rdp_packet(name);
            let cookie = parse_rdp_cookie(&pkt).expect("should parse");
            assert_eq!(cookie.username, *name);
        }
    }

    #[test]
    fn parse_returns_none_on_empty_buffer() {
        assert!(parse_rdp_cookie(&[]).is_none());
    }

    #[test]
    fn parse_returns_none_on_too_short_buffer() {
        assert!(parse_rdp_cookie(&[0x03, 0x00, 0x00]).is_none());
    }

    #[test]
    fn parse_returns_none_when_no_cookie_present() {
        // Valid TPKT + X.224 CR but no cookie string in the payload.
        let mut buf = vec![
            0x03, 0x00, 0x00, 14, // TPKT: version, reserved, length=14
            0x09, // X.224 length
            0xE0, // CR type
            0x00, 0x00, // dst ref
            0x00, 0x00, // src ref
            0x00, // class
            0x01, 0x00, 0x08, // some other data, no cookie
        ];
        // Fix TPKT length to match actual buffer size.
        let len = buf.len() as u16;
        buf[2] = (len >> 8) as u8;
        buf[3] = (len & 0xFF) as u8;
        assert!(parse_rdp_cookie(&buf).is_none());
    }

    #[test]
    fn parse_returns_none_on_invalid_tpkt_version() {
        let mut pkt = build_rdp_packet("admin");
        pkt[0] = 0x04; // wrong version
        assert!(parse_rdp_cookie(&pkt).is_none());
    }

    // ── extract_rdp_cookie_raw ──

    #[test]
    fn raw_finds_mstshash_in_arbitrary_buffer() {
        let buf = b"junk data mstshash=myuser\r\n more junk";
        let result = extract_rdp_cookie_raw(buf).expect("should find cookie");
        assert_eq!(result, "myuser");
    }

    #[test]
    fn raw_finds_mstshash_without_crlf() {
        let buf = b"prefix mstshash=enduser";
        let result = extract_rdp_cookie_raw(buf).expect("should find cookie");
        assert_eq!(result, "enduser");
    }

    #[test]
    fn raw_returns_none_when_not_present() {
        let buf = b"no rdp cookie here at all";
        assert!(extract_rdp_cookie_raw(buf).is_none());
    }

    // ── hash_rdp_cookie ──

    #[test]
    fn hash_consistency() {
        let cookie = RdpCookie {
            username: "test-user".to_string(),
        };
        let h1 = hash_rdp_cookie(&cookie);
        let h2 = hash_rdp_cookie(&cookie);
        assert_eq!(h1, h2, "same cookie must produce same hash");
    }

    #[test]
    fn hash_distribution() {
        let c1 = RdpCookie {
            username: "alice".to_string(),
        };
        let c2 = RdpCookie {
            username: "bob".to_string(),
        };
        let h1 = hash_rdp_cookie(&c1);
        let h2 = hash_rdp_cookie(&c2);
        assert_ne!(h1, h2, "different cookies should produce different hashes");
    }

    // ── RdpSessionTable ──

    #[test]
    fn session_table_insert_and_lookup() {
        let table = RdpSessionTable::new();
        let id = Uuid::new_v4();
        table.insert("admin-pc", id);
        assert_eq!(table.lookup("admin-pc"), Some(id));
    }

    #[test]
    fn session_table_lookup_miss() {
        let table = RdpSessionTable::new();
        assert_eq!(table.lookup("nonexistent"), None);
    }

    #[test]
    fn session_table_remove() {
        let table = RdpSessionTable::new();
        let id = Uuid::new_v4();
        table.insert("host-a", id);
        assert!(table.lookup("host-a").is_some());
        table.remove("host-a");
        assert!(table.lookup("host-a").is_none());
    }

    #[test]
    fn session_table_len_and_clear() {
        let table = RdpSessionTable::new();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        table.insert("a", Uuid::new_v4());
        table.insert("b", Uuid::new_v4());
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
        table.clear();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    // ── RdpCookieConfig ──

    #[test]
    fn config_defaults() {
        let cfg = RdpCookieConfig::default();
        assert_eq!(cfg.cookie_name, "mstshash");
        assert_eq!(cfg.hash_seed, 0);
    }

    // ── Custom cookie name ──

    #[test]
    fn custom_cookie_name_extraction() {
        let buf = b"stuff mycookie=specialuser\r\n end";
        let result = extract_rdp_cookie_named(buf, "mycookie").expect("should extract");
        assert_eq!(result, "specialuser");

        // Default name should not find it.
        assert!(extract_rdp_cookie_raw(buf).is_none());
    }

    // ── RdpCookieMetrics ──

    #[test]
    fn metrics_counting() {
        let m = RdpCookieMetrics::new();
        assert_eq!(m.cookies_parsed.load(Ordering::Relaxed), 0);
        m.cookies_parsed.fetch_add(3, Ordering::Relaxed);
        assert_eq!(m.cookies_parsed.load(Ordering::Relaxed), 3);
        m.cookies_not_found.fetch_add(1, Ordering::Relaxed);
        m.parse_errors.fetch_add(2, Ordering::Relaxed);
        m.session_hits.fetch_add(10, Ordering::Relaxed);
        m.session_misses.fetch_add(5, Ordering::Relaxed);
        assert_eq!(m.cookies_not_found.load(Ordering::Relaxed), 1);
        assert_eq!(m.parse_errors.load(Ordering::Relaxed), 2);
        assert_eq!(m.session_hits.load(Ordering::Relaxed), 10);
        assert_eq!(m.session_misses.load(Ordering::Relaxed), 5);
    }

    // ── Enabled toggle ──

    #[test]
    fn rdp_cookie_enabled_toggle() {
        // Reset to known state.
        set_rdp_cookie_enabled(false);
        assert!(!is_rdp_cookie_enabled());
        set_rdp_cookie_enabled(true);
        assert!(is_rdp_cookie_enabled());
        set_rdp_cookie_enabled(false);
        assert!(!is_rdp_cookie_enabled());
    }
}
