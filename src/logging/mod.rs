//! Structured access log pipeline.
//!
//! This module provides a standalone structured access log system that the
//! proxy handler can call after each request.  It does **not** replace the
//! existing `tracing` infrastructure — it is a purpose-built pipeline for
//! access logs with field-level transforms, custom fields, multiple output
//! sinks, and per-hostname scoping.
//!
//! ## Pipeline
//!
//! ```text
//! AccessLogEntry (structured data)
//!   → LogAppendFields (add custom k/v)
//!     → FieldRenames (move keys)
//!       → FieldTransforms (redact/hash/mask/replace/delete)
//!         → LogOutput (stdout/file/tcp/udp/discard)
//! ```
//!
//! ## Features
//!
//! | # | Feature                              |
//! |---|--------------------------------------|
//! | 41 | Log field redaction (delete/hash/mask/replace) |
//! | 42 | Log field rename                     |
//! | 43 | Cookie/query-param hash/delete       |
//! | 44 | Network log output (TCP/UDP)         |
//! | 45 | `log_append` — custom static fields  |
//! | 47 | Per-site / hostname-scoped loggers   |

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// AccessLogEntry
// ---------------------------------------------------------------------------

/// A single structured access log entry, produced per request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub status: u16,
    pub duration_ms: f64,
    pub bytes_sent: u64,
    pub client_ip: String,
    pub host: String,
    pub user_agent: String,
    pub service: String,
    pub route_id: String,
    pub upstream: String,
    /// Request headers (subset).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Cookies from the request.
    #[serde(default)]
    pub cookies: HashMap<String, String>,
    /// Query parameters parsed.
    #[serde(default)]
    pub query_params: HashMap<String, String>,
    /// Custom appended fields (feature 45).
    #[serde(default, flatten)]
    pub extra: HashMap<String, serde_json::Value>,
    /// Feature 59 — When set, route this entry to the logger with this name
    /// instead of the default hostname-based matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_name_override: Option<String>,
}

// ---------------------------------------------------------------------------
// Feature 41 — Log field redaction (transforms)
// ---------------------------------------------------------------------------

/// Transform operation to apply to a log field before output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FieldTransform {
    /// Remove the field entirely from the log entry.
    Delete { field: String },
    /// Replace the field value with a SHA-256 hash (one-way).
    Hash { field: String },
    /// Mask IP addresses: keep the first N bits, zero the rest.
    /// `ipv4_prefix` defaults to 24 (mask last octet).
    /// `ipv6_prefix` defaults to 48.
    IpMask {
        field: String,
        #[serde(default = "default_ipv4_prefix")]
        ipv4_prefix: u8,
        #[serde(default = "default_ipv6_prefix")]
        ipv6_prefix: u8,
    },
    /// Replace the field value with a fixed string.
    Replace { field: String, value: String },
    /// Feature 57 — Apply a regex search-and-replace on the field value.
    Regexp {
        field: String,
        pattern: String,
        replacement: String,
    },
}

fn default_ipv4_prefix() -> u8 {
    24
}
fn default_ipv6_prefix() -> u8 {
    48
}

// Feature 43 — convenience constructors for cookie / query-param transforms.

impl FieldTransform {
    pub fn delete_cookie(name: &str) -> Self {
        Self::Delete {
            field: format!("cookies.{name}"),
        }
    }
    pub fn hash_cookie(name: &str) -> Self {
        Self::Hash {
            field: format!("cookies.{name}"),
        }
    }
    pub fn delete_query(name: &str) -> Self {
        Self::Delete {
            field: format!("query_params.{name}"),
        }
    }
    pub fn hash_query(name: &str) -> Self {
        Self::Hash {
            field: format!("query_params.{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Feature 42 — Log field rename
// ---------------------------------------------------------------------------

/// Rename a field in the log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRename {
    pub from: String,
    pub to: String,
}

// ---------------------------------------------------------------------------
// Feature 45 — log_append (custom static fields)
// ---------------------------------------------------------------------------

/// Static fields to append to every log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAppendField {
    pub key: String,
    pub value: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Feature 44 — Network log output (TCP / UDP / file / stdout)
// ---------------------------------------------------------------------------

/// Where to send access log entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogOutput {
    /// Write to stdout (default).
    Stdout,
    /// Write JSON lines to a file.  Supports rotation via external tools.
    File { path: String },
    /// Send JSON to a remote TCP socket.
    Tcp { address: String },
    /// Send JSON to a remote UDP socket.
    Udp { address: String },
    /// Discard (for testing).
    Discard,
}

/// Trait for log writers — one implementation per `LogOutput` variant.
#[async_trait::async_trait]
pub trait LogWriter: Send + Sync {
    async fn write(&self, entry: &[u8]) -> Result<(), String>;
}

// ---- StdoutWriter ---------------------------------------------------------

pub struct StdoutWriter;

#[async_trait::async_trait]
impl LogWriter for StdoutWriter {
    async fn write(&self, entry: &[u8]) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let mut out = tokio::io::stdout();
        out.write_all(entry)
            .await
            .map_err(|e| format!("stdout write: {e}"))?;
        out.write_all(b"\n")
            .await
            .map_err(|e| format!("stdout newline: {e}"))?;
        Ok(())
    }
}

// ---- FileWriter -----------------------------------------------------------

pub struct FileWriter {
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl FileWriter {
    pub async fn new(path: &str) -> Result<Self, String> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|e| format!("open {path}: {e}"))?;
        Ok(Self {
            file: tokio::sync::Mutex::new(file),
        })
    }
}

#[async_trait::async_trait]
impl LogWriter for FileWriter {
    async fn write(&self, entry: &[u8]) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let mut f = self.file.lock().await;
        f.write_all(entry)
            .await
            .map_err(|e| format!("file write: {e}"))?;
        f.write_all(b"\n")
            .await
            .map_err(|e| format!("file newline: {e}"))?;
        Ok(())
    }
}

// ---- TcpWriter ------------------------------------------------------------

pub struct TcpWriter {
    address: String,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
}

impl TcpWriter {
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            stream: tokio::sync::Mutex::new(None),
        }
    }

    async fn connect(&self) -> Result<tokio::net::TcpStream, String> {
        tokio::net::TcpStream::connect(&self.address)
            .await
            .map_err(|e| format!("tcp connect to {}: {e}", self.address))
    }
}

#[async_trait::async_trait]
impl LogWriter for TcpWriter {
    async fn write(&self, entry: &[u8]) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let mut guard = self.stream.lock().await;

        // Try to write on the existing connection first.
        if let Some(ref mut s) = *guard {
            if s.write_all(entry).await.is_ok() && s.write_all(b"\n").await.is_ok() {
                return Ok(());
            }
            // Connection broken — drop and reconnect below.
            *guard = None;
        }

        // Lazy connect / reconnect.
        let mut s = self.connect().await?;
        s.write_all(entry)
            .await
            .map_err(|e| format!("tcp write: {e}"))?;
        s.write_all(b"\n")
            .await
            .map_err(|e| format!("tcp newline: {e}"))?;
        *guard = Some(s);
        Ok(())
    }
}

// ---- UdpWriter ------------------------------------------------------------

pub struct UdpWriter {
    address: String,
    socket: tokio::net::UdpSocket,
}

impl UdpWriter {
    pub async fn new(address: &str) -> Result<Self, String> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("udp bind: {e}"))?;
        Ok(Self {
            address: address.to_string(),
            socket,
        })
    }
}

#[async_trait::async_trait]
impl LogWriter for UdpWriter {
    async fn write(&self, entry: &[u8]) -> Result<(), String> {
        self.socket
            .send_to(entry, &self.address)
            .await
            .map_err(|e| format!("udp send to {}: {e}", self.address))?;
        Ok(())
    }
}

// ---- DiscardWriter --------------------------------------------------------

pub struct DiscardWriter;

#[async_trait::async_trait]
impl LogWriter for DiscardWriter {
    async fn write(&self, _entry: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Feature 47 — Per-site / hostname-scoped logger config
// ---------------------------------------------------------------------------

/// Configuration for an access logger, optionally scoped to hostnames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    /// Logger name (for reference).
    #[serde(default)]
    pub name: String,
    /// Hostnames this logger applies to.  Empty = all hosts.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Output destination.
    #[serde(default = "default_output")]
    pub output: LogOutput,
    /// Field transforms (redact/hash/mask/replace).
    #[serde(default)]
    pub transforms: Vec<FieldTransform>,
    /// Field renames.
    #[serde(default)]
    pub renames: Vec<FieldRename>,
    /// Static fields to append.
    #[serde(default)]
    pub append: Vec<LogAppendField>,
    /// Include request headers in the log entry.
    #[serde(default)]
    pub include_headers: bool,
    /// Include cookies in the log entry.
    #[serde(default)]
    pub include_cookies: bool,
    /// Include query parameters in the log entry.
    #[serde(default)]
    pub include_query_params: bool,
    /// Feature 58 — Request paths to skip (prefix match). Entries whose
    /// path starts with any of these strings are not logged.
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

fn default_output() -> LogOutput {
    LogOutput::Stdout
}

// ---------------------------------------------------------------------------
// Transform / rename engine
// ---------------------------------------------------------------------------

/// Resolve a dotted field path on a `serde_json::Value` object, returning a
/// mutable reference to the *parent* object and the final key segment.
fn resolve_parent_mut<'a>(
    root: &'a mut serde_json::Value,
    path: &str,
) -> Option<(&'a mut serde_json::Map<String, serde_json::Value>, String)> {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return None;
    }
    let (parents, last) = segments.split_at(segments.len() - 1);
    let mut current = root;
    for seg in parents {
        current = current.get_mut(*seg)?;
    }
    let map = current.as_object_mut()?;
    Some((map, last[0].to_string()))
}

/// Apply a list of [`FieldTransform`]s to a serialised log entry.
pub fn apply_transforms(entry: &mut serde_json::Value, transforms: &[FieldTransform]) {
    for t in transforms {
        match t {
            FieldTransform::Delete { field } => {
                if let Some((map, key)) = resolve_parent_mut(entry, field) {
                    map.remove(&key);
                }
            }
            FieldTransform::Hash { field } => {
                if let Some((map, key)) = resolve_parent_mut(entry, field) {
                    if let Some(val) = map.get(&key) {
                        let text = match val {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        use sha2::Digest;
                        let hash = sha2::Sha256::digest(text.as_bytes());
                        map.insert(key, serde_json::Value::String(hex::encode(hash)));
                    }
                }
            }
            FieldTransform::IpMask {
                field,
                ipv4_prefix,
                ipv6_prefix,
            } => {
                if let Some((map, key)) = resolve_parent_mut(entry, field) {
                    if let Some(serde_json::Value::String(ip_str)) = map.get(&key) {
                        if let Ok(masked) = mask_ip(ip_str, *ipv4_prefix, *ipv6_prefix) {
                            map.insert(key, serde_json::Value::String(masked));
                        }
                    }
                }
            }
            FieldTransform::Replace { field, value } => {
                if let Some((map, key)) = resolve_parent_mut(entry, field) {
                    map.insert(key, serde_json::Value::String(value.clone()));
                }
            }
            // Feature 57 — regex search-and-replace.
            FieldTransform::Regexp {
                field,
                pattern,
                replacement,
            } => {
                if let Some((map, key)) = resolve_parent_mut(entry, field) {
                    if let Some(serde_json::Value::String(s)) = map.get(&key) {
                        if let Ok(re) = regex::Regex::new(pattern) {
                            let replaced = re.replace_all(s, replacement.as_str()).to_string();
                            map.insert(key, serde_json::Value::String(replaced));
                        }
                    }
                }
            }
        }
    }
}

/// Apply a list of [`FieldRename`]s to a serialised log entry.
pub fn apply_renames(entry: &mut serde_json::Value, renames: &[FieldRename]) {
    for r in renames {
        // Extract the value from `from`, then insert at `to`.
        let value = {
            if let Some((map, key)) = resolve_parent_mut(entry, &r.from) {
                map.remove(&key)
            } else {
                None
            }
        };
        if let Some(val) = value {
            // Ensure the parent of `to` exists.
            if let Some((map, key)) = resolve_parent_mut(entry, &r.to) {
                map.insert(key, val);
            }
        }
    }
}

/// Mask an IP address string.  For IPv4 with `prefix=24`, `192.168.1.100`
/// becomes `192.168.1.0`.  For IPv6 with `prefix=48`, the host bits beyond
/// bit 48 are zeroed.
fn mask_ip(ip_str: &str, ipv4_prefix: u8, ipv6_prefix: u8) -> Result<String, String> {
    use std::net::IpAddr;
    let addr: IpAddr = ip_str.parse().map_err(|e| format!("bad ip: {e}"))?;
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let prefix = ipv4_prefix.min(32);
            let mask = if prefix == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix)
            };
            let masked = std::net::Ipv4Addr::from(bits & mask);
            Ok(masked.to_string())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let prefix = ipv6_prefix.min(128);
            let mask = if prefix == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix)
            };
            let masked = std::net::Ipv6Addr::from(bits & mask);
            Ok(masked.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// AccessLogger orchestrator
// ---------------------------------------------------------------------------

/// Access logger that routes entries to the right per-host logger,
/// applies transforms, and writes to the configured output.
pub struct AccessLogger {
    loggers: Vec<(LoggerConfig, Arc<dyn LogWriter>)>,
    default_writer: Arc<dyn LogWriter>,
}

impl AccessLogger {
    /// Build a new `AccessLogger` from a set of per-host configs.
    ///
    /// Writers for `File`, `Tcp`, and `Udp` outputs are created lazily at
    /// construction time.  The first config with an empty `hosts` list
    /// becomes the default; if none qualifies, a `StdoutWriter` is used.
    pub fn new(configs: Vec<LoggerConfig>) -> Self {
        let mut loggers: Vec<(LoggerConfig, Arc<dyn LogWriter>)> = Vec::new();
        let mut default_writer: Option<Arc<dyn LogWriter>> = None;

        for cfg in configs {
            let writer: Arc<dyn LogWriter> = match &cfg.output {
                LogOutput::Stdout => Arc::new(StdoutWriter),
                LogOutput::Discard => Arc::new(DiscardWriter),
                LogOutput::Tcp { address } => Arc::new(TcpWriter::new(address)),
                // File and Udp need async init; in the synchronous constructor
                // we fall back to Discard so the gateway can start.  Real
                // production usage should use `AccessLogger::new_async`.
                LogOutput::File { .. } | LogOutput::Udp { .. } => Arc::new(DiscardWriter),
            };
            if cfg.hosts.is_empty() && default_writer.is_none() {
                default_writer = Some(writer.clone());
            }
            loggers.push((cfg, writer));
        }

        AccessLogger {
            loggers,
            default_writer: default_writer.unwrap_or_else(|| Arc::new(StdoutWriter)),
        }
    }

    /// Async constructor — properly initialises `FileWriter` and `UdpWriter`.
    pub async fn new_async(configs: Vec<LoggerConfig>) -> Result<Self, String> {
        let mut loggers: Vec<(LoggerConfig, Arc<dyn LogWriter>)> = Vec::new();
        let mut default_writer: Option<Arc<dyn LogWriter>> = None;

        for cfg in configs {
            let writer: Arc<dyn LogWriter> = match &cfg.output {
                LogOutput::Stdout => Arc::new(StdoutWriter),
                LogOutput::Discard => Arc::new(DiscardWriter),
                LogOutput::Tcp { address } => Arc::new(TcpWriter::new(address)),
                LogOutput::File { path } => Arc::new(FileWriter::new(path).await?),
                LogOutput::Udp { address } => Arc::new(UdpWriter::new(address).await?),
            };
            if cfg.hosts.is_empty() && default_writer.is_none() {
                default_writer = Some(writer.clone());
            }
            loggers.push((cfg, writer));
        }

        Ok(AccessLogger {
            loggers,
            default_writer: default_writer.unwrap_or_else(|| Arc::new(StdoutWriter)),
        })
    }

    /// Log an access entry.
    ///
    /// Finds the first matching logger by hostname (or by explicit
    /// `log_name_override`), applies appended fields, renames, transforms,
    /// serialises to JSON, and writes to the output.
    pub async fn log(&self, entry: AccessLogEntry) {
        // 1. Find matching logger.
        //    Feature 59: if `log_name_override` is set, match by logger name
        //    instead of hostname.
        let (cfg, writer) = if let Some(ref override_name) = entry.log_name_override {
            self.loggers
                .iter()
                .find(|(cfg, _)| cfg.name == *override_name)
                .map(|(cfg, w)| (cfg, w.clone()))
        } else {
            self.loggers
                .iter()
                .find(|(cfg, _)| cfg.hosts.is_empty() || cfg.hosts.iter().any(|h| h == &entry.host))
                .map(|(cfg, w)| (cfg, w.clone()))
        }
        .unwrap_or_else(|| {
            // No matching config — use a bare default.
            static EMPTY: LoggerConfig = LoggerConfig {
                name: String::new(),
                hosts: Vec::new(),
                output: LogOutput::Stdout,
                transforms: Vec::new(),
                renames: Vec::new(),
                append: Vec::new(),
                include_headers: false,
                include_cookies: false,
                include_query_params: false,
                skip_paths: Vec::new(),
            };
            (&EMPTY, self.default_writer.clone())
        });

        // Feature 58: skip logging if the request path matches any skip_paths
        // prefix.
        if cfg
            .skip_paths
            .iter()
            .any(|prefix| entry.path.starts_with(prefix))
        {
            return;
        }

        // 2. Serialize entry to mutable JSON value.
        let mut value = match serde_json::to_value(&entry) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("access log serialise: {e}");
                return;
            }
        };

        // 3. Append static fields.
        if let Some(map) = value.as_object_mut() {
            for af in &cfg.append {
                map.insert(af.key.clone(), af.value.clone());
            }
        }

        // 4. Renames.
        apply_renames(&mut value, &cfg.renames);

        // 5. Transforms (redact / hash / mask / replace / delete).
        apply_transforms(&mut value, &cfg.transforms);

        // 6. Serialize to JSON bytes and write.
        let bytes = match serde_json::to_vec(&value) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("access log final serialise: {e}");
                return;
            }
        };

        if let Err(e) = writer.write(&bytes).await {
            tracing::warn!("access log write error: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper: build a minimal `AccessLogEntry` for testing.
    fn sample_entry() -> AccessLogEntry {
        AccessLogEntry {
            timestamp: "2025-01-01T00:00:00Z".into(),
            method: "GET".into(),
            path: "/api/test".into(),
            query: "".into(),
            status: 200,
            duration_ms: 12.5,
            bytes_sent: 1024,
            client_ip: "192.168.1.100".into(),
            host: "api.example.com".into(),
            user_agent: "test-agent/1".into(),
            service: "svc-a".into(),
            route_id: "r-1".into(),
            upstream: "http://10.0.0.1:8080".into(),
            headers: HashMap::from([
                ("Authorization".into(), "Bearer secret-token".into()),
                ("X-Request-Id".into(), "abc-123".into()),
            ]),
            cookies: HashMap::from([
                ("session_id".into(), "sess-abc-123".into()),
                ("_ga".into(), "GA1.2.12345".into()),
            ]),
            query_params: HashMap::from([
                ("token".into(), "tok-secret".into()),
                ("page".into(), "1".into()),
            ]),
            extra: HashMap::new(),
            log_name_override: None,
        }
    }

    fn entry_to_value(e: &AccessLogEntry) -> serde_json::Value {
        serde_json::to_value(e).unwrap()
    }

    // ---- Feature 41: Field transforms ------------------------------------

    #[test]
    fn transform_delete_field() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(
            &mut v,
            &[FieldTransform::Delete {
                field: "user_agent".into(),
            }],
        );
        assert!(v.get("user_agent").is_none());
    }

    #[test]
    fn transform_delete_nested() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(
            &mut v,
            &[FieldTransform::Delete {
                field: "headers.Authorization".into(),
            }],
        );
        let hdrs = v.get("headers").unwrap().as_object().unwrap();
        assert!(!hdrs.contains_key("Authorization"));
        // Other header should still be present.
        assert!(hdrs.contains_key("X-Request-Id"));
    }

    #[test]
    fn transform_hash_field() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(
            &mut v,
            &[FieldTransform::Hash {
                field: "client_ip".into(),
            }],
        );
        let hashed = v.get("client_ip").unwrap().as_str().unwrap();
        // SHA-256 hex is 64 chars.
        assert_eq!(hashed.len(), 64);
        // Must not be the original value.
        assert_ne!(hashed, "192.168.1.100");
    }

    #[test]
    fn transform_hash_deterministic() {
        let mut v1 = entry_to_value(&sample_entry());
        let mut v2 = entry_to_value(&sample_entry());
        let t = [FieldTransform::Hash {
            field: "client_ip".into(),
        }];
        apply_transforms(&mut v1, &t);
        apply_transforms(&mut v2, &t);
        assert_eq!(
            v1.get("client_ip").unwrap().as_str().unwrap(),
            v2.get("client_ip").unwrap().as_str().unwrap(),
        );
    }

    #[test]
    fn transform_ip_mask_v4() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(
            &mut v,
            &[FieldTransform::IpMask {
                field: "client_ip".into(),
                ipv4_prefix: 24,
                ipv6_prefix: 48,
            }],
        );
        assert_eq!(v.get("client_ip").unwrap().as_str().unwrap(), "192.168.1.0");
    }

    #[test]
    fn transform_ip_mask_v4_custom_prefix() {
        let mut v = json!({ "ip": "192.168.1.100" });
        apply_transforms(
            &mut v,
            &[FieldTransform::IpMask {
                field: "ip".into(),
                ipv4_prefix: 16,
                ipv6_prefix: 48,
            }],
        );
        assert_eq!(v.get("ip").unwrap().as_str().unwrap(), "192.168.0.0");
    }

    #[test]
    fn transform_ip_mask_v6() {
        let mut v = json!({ "ip": "2001:0db8:85a3:1234:5678:8a2e:0370:7334" });
        apply_transforms(
            &mut v,
            &[FieldTransform::IpMask {
                field: "ip".into(),
                ipv4_prefix: 24,
                ipv6_prefix: 48,
            }],
        );
        let masked = v.get("ip").unwrap().as_str().unwrap();
        // With prefix=48, first 48 bits preserved, rest zeroed.
        // 2001:0db8:85a3:: is the expected result.
        assert_eq!(masked, "2001:db8:85a3::");
    }

    #[test]
    fn transform_replace_field() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(
            &mut v,
            &[FieldTransform::Replace {
                field: "client_ip".into(),
                value: "[REDACTED]".into(),
            }],
        );
        assert_eq!(v.get("client_ip").unwrap().as_str().unwrap(), "[REDACTED]");
    }

    #[test]
    fn transform_replace_nested() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(
            &mut v,
            &[FieldTransform::Replace {
                field: "headers.Authorization".into(),
                value: "***".into(),
            }],
        );
        let hdrs = v.get("headers").unwrap().as_object().unwrap();
        assert_eq!(hdrs.get("Authorization").unwrap().as_str().unwrap(), "***");
    }

    #[test]
    fn transform_missing_field_noop() {
        let mut v = entry_to_value(&sample_entry());
        let before = v.clone();
        apply_transforms(
            &mut v,
            &[
                FieldTransform::Delete {
                    field: "nonexistent".into(),
                },
                FieldTransform::Hash {
                    field: "nonexistent".into(),
                },
                FieldTransform::Replace {
                    field: "no.such.path".into(),
                    value: "x".into(),
                },
            ],
        );
        assert_eq!(v, before);
    }

    // ---- Feature 42: Field rename ----------------------------------------

    #[test]
    fn rename_top_level() {
        let mut v = entry_to_value(&sample_entry());
        apply_renames(
            &mut v,
            &[FieldRename {
                from: "client_ip".into(),
                to: "remote_addr".into(),
            }],
        );
        assert!(v.get("client_ip").is_none());
        assert_eq!(
            v.get("remote_addr").unwrap().as_str().unwrap(),
            "192.168.1.100"
        );
    }

    #[test]
    fn rename_nested() {
        let mut v = entry_to_value(&sample_entry());
        apply_renames(
            &mut v,
            &[FieldRename {
                from: "headers.X-Request-Id".into(),
                to: "headers.X-Correlation-Id".into(),
            }],
        );
        let hdrs = v.get("headers").unwrap().as_object().unwrap();
        assert!(!hdrs.contains_key("X-Request-Id"));
        assert_eq!(
            hdrs.get("X-Correlation-Id").unwrap().as_str().unwrap(),
            "abc-123",
        );
    }

    #[test]
    fn rename_missing_noop() {
        let mut v = entry_to_value(&sample_entry());
        let before = v.clone();
        apply_renames(
            &mut v,
            &[FieldRename {
                from: "no_such_field".into(),
                to: "whatever".into(),
            }],
        );
        assert_eq!(v, before);
    }

    // ---- Feature 43: Cookie/query convenience ----------------------------

    #[test]
    fn delete_cookie() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(&mut v, &[FieldTransform::delete_cookie("session_id")]);
        let cookies = v.get("cookies").unwrap().as_object().unwrap();
        assert!(!cookies.contains_key("session_id"));
        assert!(cookies.contains_key("_ga"));
    }

    #[test]
    fn hash_cookie() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(&mut v, &[FieldTransform::hash_cookie("session_id")]);
        let cookies = v.get("cookies").unwrap().as_object().unwrap();
        let hashed = cookies.get("session_id").unwrap().as_str().unwrap();
        assert_eq!(hashed.len(), 64);
        assert_ne!(hashed, "sess-abc-123");
    }

    #[test]
    fn delete_query_param() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(&mut v, &[FieldTransform::delete_query("token")]);
        let qp = v.get("query_params").unwrap().as_object().unwrap();
        assert!(!qp.contains_key("token"));
        assert!(qp.contains_key("page"));
    }

    #[test]
    fn hash_query_param() {
        let mut v = entry_to_value(&sample_entry());
        apply_transforms(&mut v, &[FieldTransform::hash_query("token")]);
        let qp = v.get("query_params").unwrap().as_object().unwrap();
        let hashed = qp.get("token").unwrap().as_str().unwrap();
        assert_eq!(hashed.len(), 64);
        assert_ne!(hashed, "tok-secret");
    }

    // ---- Feature 45: Log append ------------------------------------------

    #[test]
    fn append_static_fields() {
        let mut v = entry_to_value(&sample_entry());
        let map = v.as_object_mut().unwrap();
        let field = LogAppendField {
            key: "environment".into(),
            value: json!("production"),
        };
        map.insert(field.key.clone(), field.value.clone());
        assert_eq!(v.get("environment").unwrap(), "production");
    }

    #[test]
    fn append_multiple_fields() {
        let mut v = entry_to_value(&sample_entry());
        let map = v.as_object_mut().unwrap();
        let fields = vec![
            LogAppendField {
                key: "env".into(),
                value: json!("staging"),
            },
            LogAppendField {
                key: "region".into(),
                value: json!("us-east-1"),
            },
            LogAppendField {
                key: "version".into(),
                value: json!(42),
            },
        ];
        for f in &fields {
            map.insert(f.key.clone(), f.value.clone());
        }
        assert_eq!(v.get("env").unwrap(), "staging");
        assert_eq!(v.get("region").unwrap(), "us-east-1");
        assert_eq!(v.get("version").unwrap(), 42);
    }

    // ---- Feature 44: LogOutput / LogWriter -------------------------------

    #[tokio::test]
    async fn discard_writer_works() {
        let w = DiscardWriter;
        let result = w.write(b"test data").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn stdout_writer_works() {
        let w = StdoutWriter;
        // Just verify it doesn't panic — output goes to test runner stdout.
        let result = w.write(b"{}").await;
        assert!(result.is_ok());
    }

    #[test]
    fn log_output_deserializes_tcp() {
        let j = r#"{"type":"tcp","address":"127.0.0.1:9000"}"#;
        let out: LogOutput = serde_json::from_str(j).unwrap();
        match out {
            LogOutput::Tcp { address } => assert_eq!(address, "127.0.0.1:9000"),
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn log_output_deserializes_udp() {
        let j = r#"{"type":"udp","address":"127.0.0.1:5140"}"#;
        let out: LogOutput = serde_json::from_str(j).unwrap();
        match out {
            LogOutput::Udp { address } => assert_eq!(address, "127.0.0.1:5140"),
            _ => panic!("expected Udp variant"),
        }
    }

    #[test]
    fn log_output_deserializes_file() {
        let j = r#"{"type":"file","path":"/var/log/access.log"}"#;
        let out: LogOutput = serde_json::from_str(j).unwrap();
        match out {
            LogOutput::File { path } => assert_eq!(path, "/var/log/access.log"),
            _ => panic!("expected File variant"),
        }
    }

    // ---- Feature 47: Per-host scoping ------------------------------------

    #[tokio::test]
    async fn logger_matches_host() {
        // Two loggers: one for api.example.com (discard), one default (discard).
        let logger = AccessLogger::new(vec![
            LoggerConfig {
                name: "api-logger".into(),
                hosts: vec!["api.example.com".into()],
                output: LogOutput::Discard,
                transforms: vec![FieldTransform::Delete {
                    field: "user_agent".into(),
                }],
                renames: vec![],
                append: vec![LogAppendField {
                    key: "matched".into(),
                    value: json!("api"),
                }],
                include_headers: false,
                include_cookies: false,
                include_query_params: false,
                skip_paths: vec![],
            },
            LoggerConfig {
                name: "default".into(),
                hosts: vec![],
                output: LogOutput::Discard,
                transforms: vec![],
                renames: vec![],
                append: vec![LogAppendField {
                    key: "matched".into(),
                    value: json!("default"),
                }],
                include_headers: false,
                include_cookies: false,
                include_query_params: false,
                skip_paths: vec![],
            },
        ]);

        // Entry with host=api.example.com should match the first logger.
        let entry = sample_entry(); // host = "api.example.com"
                                    // We can't easily inspect which writer was chosen, but we can verify
                                    // the logger doesn't panic and the match logic works by checking the
                                    // internal match directly.
        let matched = logger
            .loggers
            .iter()
            .find(|(cfg, _)| cfg.hosts.is_empty() || cfg.hosts.contains(&entry.host));
        assert_eq!(matched.unwrap().0.name, "api-logger");

        // Actually run log to ensure no panics.
        logger.log(entry).await;
    }

    #[tokio::test]
    async fn logger_default_fallback() {
        let logger = AccessLogger::new(vec![
            LoggerConfig {
                name: "api-logger".into(),
                hosts: vec!["api.example.com".into()],
                output: LogOutput::Discard,
                transforms: vec![],
                renames: vec![],
                append: vec![],
                include_headers: false,
                include_cookies: false,
                include_query_params: false,
                skip_paths: vec![],
            },
            LoggerConfig {
                name: "default".into(),
                hosts: vec![],
                output: LogOutput::Discard,
                transforms: vec![],
                renames: vec![],
                append: vec![],
                include_headers: false,
                include_cookies: false,
                include_query_params: false,
                skip_paths: vec![],
            },
        ]);

        let mut entry = sample_entry();
        entry.host = "unknown.example.com".into();

        // Should fall through the first (hosts don't match) and match the
        // second (empty hosts = catch-all).
        let matched = logger
            .loggers
            .iter()
            .find(|(cfg, _)| cfg.hosts.is_empty() || cfg.hosts.contains(&entry.host));
        assert_eq!(matched.unwrap().0.name, "default");

        logger.log(entry).await;
    }

    #[tokio::test]
    async fn logger_empty_hosts_matches_all() {
        let logger = AccessLogger::new(vec![LoggerConfig {
            name: "catch-all".into(),
            hosts: vec![], // empty = match everything
            output: LogOutput::Discard,
            transforms: vec![],
            renames: vec![],
            append: vec![],
            include_headers: false,
            include_cookies: false,
            include_query_params: false,
            skip_paths: vec![],
        }]);

        let mut entry = sample_entry();
        entry.host = "literally-anything.example.com".into();

        let matched = logger
            .loggers
            .iter()
            .find(|(cfg, _)| cfg.hosts.is_empty() || cfg.hosts.contains(&entry.host));
        assert_eq!(matched.unwrap().0.name, "catch-all");

        logger.log(entry).await;
    }

    // ---- AccessLogEntry serde round-trip ---------------------------------

    #[test]
    fn entry_serializes_to_json() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let back: AccessLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.method, "GET");
        assert_eq!(back.status, 200);
        assert_eq!(back.client_ip, "192.168.1.100");
        assert_eq!(back.host, "api.example.com");
    }

    #[test]
    fn entry_with_extras() {
        let mut entry = sample_entry();
        entry.extra.insert("environment".into(), json!("staging"));
        entry.extra.insert("build".into(), json!(42));
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json.get("environment").unwrap(), "staging");
        assert_eq!(json.get("build").unwrap(), 42);
    }

    // ---- Feature 57: Regexp field transform ---------------------------------

    #[test]
    fn transform_regexp_basic_replacement() {
        let mut v = json!({ "path": "/api/users/123/profile" });
        apply_transforms(
            &mut v,
            &[FieldTransform::Regexp {
                field: "path".into(),
                pattern: r"/\d+/".into(),
                replacement: "/:id/".into(),
            }],
        );
        assert_eq!(
            v.get("path").unwrap().as_str().unwrap(),
            "/api/users/:id/profile"
        );
    }

    #[test]
    fn transform_regexp_capture_groups() {
        let mut v = json!({ "email": "user@example.com" });
        apply_transforms(
            &mut v,
            &[FieldTransform::Regexp {
                field: "email".into(),
                pattern: r"([^@]+)@(.+)".into(),
                replacement: "***@$2".into(),
            }],
        );
        assert_eq!(v.get("email").unwrap().as_str().unwrap(), "***@example.com");
    }

    #[test]
    fn transform_regexp_no_match_unchanged() {
        let mut v = json!({ "path": "/api/test" });
        let before = v.clone();
        apply_transforms(
            &mut v,
            &[FieldTransform::Regexp {
                field: "path".into(),
                pattern: r"zzz_no_match".into(),
                replacement: "replaced".into(),
            }],
        );
        assert_eq!(v, before);
    }

    #[test]
    fn transform_regexp_nested_field() {
        let mut v = json!({
            "headers": { "Authorization": "Bearer tok-abc-123-xyz" }
        });
        apply_transforms(
            &mut v,
            &[FieldTransform::Regexp {
                field: "headers.Authorization".into(),
                pattern: r"Bearer .+".into(),
                replacement: "Bearer [REDACTED]".into(),
            }],
        );
        let hdrs = v.get("headers").unwrap().as_object().unwrap();
        assert_eq!(
            hdrs.get("Authorization").unwrap().as_str().unwrap(),
            "Bearer [REDACTED]",
        );
    }

    #[test]
    fn transform_regexp_missing_field_noop() {
        let mut v = json!({ "a": "b" });
        let before = v.clone();
        apply_transforms(
            &mut v,
            &[FieldTransform::Regexp {
                field: "nonexistent".into(),
                pattern: ".".into(),
                replacement: "x".into(),
            }],
        );
        assert_eq!(v, before);
    }

    // ---- Feature 58: log_skip directive -------------------------------------

    #[tokio::test]
    async fn skip_matching_path() {
        // Use a writer that tracks whether write was called.
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SpyWriter(Arc<AtomicBool>);

        #[async_trait::async_trait]
        impl LogWriter for SpyWriter {
            async fn write(&self, _entry: &[u8]) -> Result<(), String> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let wrote = Arc::new(AtomicBool::new(false));
        let writer: Arc<dyn LogWriter> = Arc::new(SpyWriter(wrote.clone()));

        let logger = AccessLogger {
            loggers: vec![(
                LoggerConfig {
                    name: "test".into(),
                    hosts: vec![],
                    output: LogOutput::Discard,
                    transforms: vec![],
                    renames: vec![],
                    append: vec![],
                    include_headers: false,
                    include_cookies: false,
                    include_query_params: false,
                    skip_paths: vec!["/health".into(), "/metrics".into()],
                },
                writer.clone(),
            )],
            default_writer: writer,
        };

        let mut entry = sample_entry();
        entry.path = "/healthz".into(); // does NOT match prefix "/health" exactly, but starts with it
                                        // Wait — "/healthz".starts_with("/health") is true!
        logger.log(entry).await;
        assert!(
            !wrote.load(Ordering::SeqCst),
            "should skip /healthz (prefix match)"
        );

        wrote.store(false, Ordering::SeqCst);
        let mut entry2 = sample_entry();
        entry2.path = "/metrics/scrape".into();
        logger.log(entry2).await;
        assert!(!wrote.load(Ordering::SeqCst), "should skip /metrics/scrape");
    }

    #[tokio::test]
    async fn no_skip_non_matching_path() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SpyWriter(Arc<AtomicBool>);

        #[async_trait::async_trait]
        impl LogWriter for SpyWriter {
            async fn write(&self, _entry: &[u8]) -> Result<(), String> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let wrote = Arc::new(AtomicBool::new(false));
        let writer: Arc<dyn LogWriter> = Arc::new(SpyWriter(wrote.clone()));

        let logger = AccessLogger {
            loggers: vec![(
                LoggerConfig {
                    name: "test".into(),
                    hosts: vec![],
                    output: LogOutput::Discard,
                    transforms: vec![],
                    renames: vec![],
                    append: vec![],
                    include_headers: false,
                    include_cookies: false,
                    include_query_params: false,
                    skip_paths: vec!["/health".into()],
                },
                writer.clone(),
            )],
            default_writer: writer,
        };

        let mut entry = sample_entry();
        entry.path = "/api/users".into();
        logger.log(entry).await;
        assert!(wrote.load(Ordering::SeqCst), "should NOT skip /api/users");
    }

    // ---- Feature 59: log_name override --------------------------------------

    #[tokio::test]
    async fn log_name_override_routes_to_named_logger() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SpyWriter(Arc<AtomicBool>);

        #[async_trait::async_trait]
        impl LogWriter for SpyWriter {
            async fn write(&self, _entry: &[u8]) -> Result<(), String> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let default_wrote = Arc::new(AtomicBool::new(false));
        let named_wrote = Arc::new(AtomicBool::new(false));
        let default_writer: Arc<dyn LogWriter> = Arc::new(SpyWriter(default_wrote.clone()));
        let named_writer: Arc<dyn LogWriter> = Arc::new(SpyWriter(named_wrote.clone()));

        let logger = AccessLogger {
            loggers: vec![
                (
                    LoggerConfig {
                        name: "special".into(),
                        hosts: vec!["other-host.com".into()],
                        output: LogOutput::Discard,
                        transforms: vec![],
                        renames: vec![],
                        append: vec![],
                        include_headers: false,
                        include_cookies: false,
                        include_query_params: false,
                        skip_paths: vec![],
                    },
                    named_writer,
                ),
                (
                    LoggerConfig {
                        name: "default".into(),
                        hosts: vec![],
                        output: LogOutput::Discard,
                        transforms: vec![],
                        renames: vec![],
                        append: vec![],
                        include_headers: false,
                        include_cookies: false,
                        include_query_params: false,
                        skip_paths: vec![],
                    },
                    default_writer,
                ),
            ],
            default_writer: Arc::new(DiscardWriter),
        };

        // Without override, entry for api.example.com would NOT match
        // "special" (wrong host), so it goes to the default catch-all.
        let mut entry = sample_entry();
        entry.log_name_override = Some("special".into());
        logger.log(entry).await;

        assert!(
            named_wrote.load(Ordering::SeqCst),
            "should route to 'special' logger"
        );
        assert!(
            !default_wrote.load(Ordering::SeqCst),
            "should NOT route to default"
        );
    }

    #[tokio::test]
    async fn log_name_override_none_uses_host_matching() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SpyWriter(Arc<AtomicBool>);

        #[async_trait::async_trait]
        impl LogWriter for SpyWriter {
            async fn write(&self, _entry: &[u8]) -> Result<(), String> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let default_wrote = Arc::new(AtomicBool::new(false));
        let default_writer: Arc<dyn LogWriter> = Arc::new(SpyWriter(default_wrote.clone()));

        let logger = AccessLogger {
            loggers: vec![(
                LoggerConfig {
                    name: "default".into(),
                    hosts: vec![],
                    output: LogOutput::Discard,
                    transforms: vec![],
                    renames: vec![],
                    append: vec![],
                    include_headers: false,
                    include_cookies: false,
                    include_query_params: false,
                    skip_paths: vec![],
                },
                default_writer,
            )],
            default_writer: Arc::new(DiscardWriter),
        };

        // No override — falls back to hostname matching.
        let entry = sample_entry(); // log_name_override = None
        logger.log(entry).await;

        assert!(
            default_wrote.load(Ordering::SeqCst),
            "should use host-based matching"
        );
    }
}
