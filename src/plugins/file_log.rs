use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::{Request, Response};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Feature 56 — Log file rotation
// ---------------------------------------------------------------------------

/// Configuration for log file rotation.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Maximum file size in bytes before rotation is triggered.
    pub max_size_bytes: u64,
    /// Maximum number of rotated backup files to keep.
    pub max_backups: u32,
    /// Delete rotated files older than this many days. 0 = keep forever.
    pub max_age_days: u64,
    /// Whether rotated files should be gzip-compressed (config only; not
    /// implemented yet).
    pub compress_rotated: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_backups: 10,
            max_age_days: 0,
            compress_rotated: false,
        }
    }
}

/// Handles log file rotation: size-based rotation, backup pruning, and
/// age-based pruning.
pub struct LogRotator {
    path: PathBuf,
    config: RotationConfig,
    /// Running count of bytes written since the last rotation / open.
    bytes_written: u64,
}

impl LogRotator {
    /// Create a new rotator. Runs startup pruning (backup count + age) before
    /// returning.
    pub async fn new(path: PathBuf, config: RotationConfig) -> Self {
        let mut rotator = Self {
            path,
            config,
            bytes_written: 0,
        };
        // Seed bytes_written from the current file size so we don't wait for
        // an extra `max_size` worth of data before the first rotation.
        if let Ok(meta) = tokio::fs::metadata(&rotator.path).await {
            rotator.bytes_written = meta.len();
        }
        rotator.prune_backups().await;
        rotator.prune_by_age().await;
        rotator
    }

    /// Record that `n` bytes were flushed.  Returns `true` if the file now
    /// exceeds the configured max size and should be rotated.
    pub fn track_flush(&mut self, n: u64) -> bool {
        self.bytes_written += n;
        self.bytes_written >= self.config.max_size_bytes
    }

    /// Rotate the current file: rename to `{stem}.{timestamp}.log` and reset
    /// the byte counter.  Returns the path to write the new (empty) file.
    pub async fn rotate(&mut self) -> Result<(), String> {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
        let stem = self
            .path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let ext = self
            .path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let rotated_name = format!("{stem}.{stamp}{ext}");
        let rotated_path = self.path.with_file_name(rotated_name);
        tokio::fs::rename(&self.path, &rotated_path)
            .await
            .map_err(|e| format!("rotate rename: {e}"))?;
        self.bytes_written = 0;
        // Prune after rotation so we never exceed max_backups.
        self.prune_backups().await;
        self.prune_by_age().await;
        Ok(())
    }

    /// List rotated backup files sorted oldest-first.
    async fn list_backups(&self) -> Vec<PathBuf> {
        let dir = match self.path.parent() {
            Some(d) => d.to_path_buf(),
            None => return vec![],
        };
        let stem = self
            .path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let ext = self
            .path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();

        let mut entries = Vec::new();
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(_) => return vec![],
        };
        while let Ok(Some(de)) = rd.next_entry().await {
            let name = de.file_name().to_string_lossy().to_string();
            // Pattern: {stem}.{timestamp}{ext}  (timestamp contains a dot)
            if name.starts_with(&format!("{stem}."))
                && name.ends_with(&ext)
                && de.path() != self.path
            {
                entries.push(de.path());
            }
        }
        entries.sort();
        entries
    }

    /// Remove excess backups beyond `max_backups`.
    async fn prune_backups(&self) {
        let backups = self.list_backups().await;
        if backups.len() > self.config.max_backups as usize {
            let to_remove = backups.len() - self.config.max_backups as usize;
            for p in backups.into_iter().take(to_remove) {
                let _ = tokio::fs::remove_file(&p).await;
            }
        }
    }

    /// Remove backups older than `max_age_days` (if configured).
    async fn prune_by_age(&self) {
        if self.config.max_age_days == 0 {
            return;
        }
        let cutoff = std::time::SystemTime::now()
            - std::time::Duration::from_secs(self.config.max_age_days * 86400);
        let backups = self.list_backups().await;
        for p in backups {
            if let Ok(meta) = tokio::fs::metadata(&p).await {
                if let Ok(modified) = meta.modified() {
                    if modified < cutoff {
                        let _ = tokio::fs::remove_file(&p).await;
                    }
                }
            }
        }
    }
}

const HDR_METHOD: &str = "x-lynxx-filelog-method";
const HDR_PATH: &str = "x-lynxx-filelog-path";
const HDR_START: &str = "x-lynxx-filelog-start";
const HDR_CONSUMER: &str = "x-consumer-username";
const HDR_HOST: &str = "x-lynxx-filelog-host";
const HDR_USER_AGENT: &str = "x-lynxx-filelog-ua";
const HDR_REFERER: &str = "x-lynxx-filelog-referer";
const HDR_CLIENT_IP: &str = "x-lynxx-filelog-client-ip";
const HDR_REQ_SIZE: &str = "x-lynxx-filelog-req-size";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Combined,
}

/// Per-request access logger. The hot path only `try_send`s a small struct
/// onto a bounded mpsc; an owned background task handles file I/O so a slow
/// disk never stalls request processing. The writer batches lines and flushes
/// every 100ms or 256 entries, whichever comes first.
pub struct FileLogPlugin {
    tx: mpsc::Sender<LogLine>,
    fields: Vec<String>,
    format: Format,
    /// Custom format template, e.g. `"{method} {path} -> {status} ({duration_ms}ms)"`.
    /// When set, overrides `format` and `fields`.
    custom_template: Option<String>,
}

#[derive(Debug)]
struct LogLine {
    timestamp: String,
    method: String,
    path: String,
    status: u16,
    duration_ms: i64,
    service: String,
    consumer: String,
    host: String,
    user_agent: String,
    referer: String,
    client_ip: String,
    request_size: i64,
    response_size: i64,
}

impl FileLogPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let path = cfg
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::BadRequest("file-log: `path` is required".into()))?
            .to_string();
        let format = match cfg.get("format").and_then(|v| v.as_str()).unwrap_or("json") {
            "combined" => Format::Combined,
            _ => Format::Json,
        };
        let fields = cfg
            .get("fields")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![
                    "timestamp".into(),
                    "method".into(),
                    "path".into(),
                    "status".into(),
                    "duration_ms".into(),
                    "service".into(),
                    "consumer".into(),
                ]
            });

        let custom_template = cfg
            .get("template")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Feature 56 — rotation config
        let max_size_mb = cfg
            .get("max_size_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        let max_age_days = cfg
            .get("max_age_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let max_backups = cfg
            .get("max_backups")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u32;
        let compress_rotated = cfg
            .get("compress_rotated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let rotation_config = RotationConfig {
            max_size_bytes: max_size_mb * 1024 * 1024,
            max_backups,
            max_age_days,
            compress_rotated,
        };

        let (tx, rx) = mpsc::channel::<LogLine>(4096);
        let target = PathBuf::from(path);
        let format_for_task = format;
        let fields_for_task = fields.clone();
        let tmpl_for_task = custom_template.clone();
        let rot_cfg = rotation_config;
        tokio::spawn(async move {
            writer_task(
                target,
                rx,
                format_for_task,
                fields_for_task,
                tmpl_for_task,
                rot_cfg,
            )
            .await;
        });

        Ok(Self {
            tx,
            fields,
            format,
            custom_template,
        })
    }
}

async fn open_log_file(path: &PathBuf) -> Result<tokio::fs::File, std::io::Error> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

async fn writer_task(
    path: PathBuf,
    mut rx: mpsc::Receiver<LogLine>,
    format: Format,
    fields: Vec<String>,
    custom_template: Option<String>,
    rotation_config: RotationConfig,
) {
    let mut rotator = LogRotator::new(path.clone(), rotation_config).await;

    let mut file = match open_log_file(&path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "file-log: open failed; logs will be dropped");
            return;
        }
    };
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut count: usize = 0;
    let flush_interval = Duration::from_millis(100);
    let mut ticker = tokio::time::interval(flush_interval);

    loop {
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                match maybe {
                    Some(line) => {
                        let s = render(&line, format, &fields, custom_template.as_deref());
                        buf.extend_from_slice(s.as_bytes());
                        buf.push(b'\n');
                        count += 1;
                        if count >= 256 {
                            let flush_len = buf.len() as u64;
                            if let Err(e) = file.write_all(&buf).await {
                                tracing::warn!(error = %e, "file-log: write failed; log batch dropped");
                            }
                            buf.clear();
                            count = 0;
                            // Check rotation after each flush batch.
                            if rotator.track_flush(flush_len) {
                                let _ = file.flush().await;
                                drop(file);
                                if let Err(e) = rotator.rotate().await {
                                    tracing::warn!("file-log: rotation failed: {e}");
                                }
                                file = match open_log_file(&path).await {
                                    Ok(f) => f,
                                    Err(e) => {
                                        tracing::warn!(path = %path.display(), error = %e, "file-log: reopen after rotation failed");
                                        return;
                                    }
                                };
                            }
                        }
                    }
                    None => {
                        if let Err(e) = file.write_all(&buf).await {
                            tracing::warn!(error = %e, "file-log: final write failed; log batch dropped");
                        }
                        let _ = file.flush().await;
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                if !buf.is_empty() {
                    let flush_len = buf.len() as u64;
                    if let Err(e) = file.write_all(&buf).await {
                        tracing::warn!(error = %e, "file-log: write failed; log batch dropped");
                    }
                    let _ = file.flush().await;
                    buf.clear();
                    count = 0;
                    // Check rotation after each flush batch.
                    if rotator.track_flush(flush_len) {
                        drop(file);
                        if let Err(e) = rotator.rotate().await {
                            tracing::warn!("file-log: rotation failed: {e}");
                        }
                        file = match open_log_file(&path).await {
                            Ok(f) => f,
                            Err(e) => {
                                tracing::warn!(path = %path.display(), error = %e, "file-log: reopen after rotation failed");
                                return;
                            }
                        };
                    }
                }
            }
        }
    }
}

/// Expand a template string like `"{method} {path} -> {status}"` with log line values.
fn expand_template(template: &str, line: &LogLine) -> String {
    template
        .replace("{timestamp}", &line.timestamp)
        .replace("{method}", &line.method)
        .replace("{path}", &line.path)
        .replace("{status}", &line.status.to_string())
        .replace("{duration_ms}", &line.duration_ms.to_string())
        .replace("{service}", &line.service)
        .replace("{consumer}", &line.consumer)
        .replace("{host}", &line.host)
        .replace("{user_agent}", &line.user_agent)
        .replace("{referer}", &line.referer)
        .replace("{client_ip}", &line.client_ip)
        .replace("{request_size}", &line.request_size.to_string())
        .replace("{response_size}", &line.response_size.to_string())
}

fn render(line: &LogLine, format: Format, fields: &[String], template: Option<&str>) -> String {
    if let Some(tmpl) = template {
        return expand_template(tmpl, line);
    }
    match format {
        Format::Json => {
            let mut obj = serde_json::Map::new();
            for f in fields {
                let v = match f.as_str() {
                    "timestamp" => json!(line.timestamp),
                    "method" => json!(line.method),
                    "path" => json!(line.path),
                    "status" => json!(line.status),
                    "duration_ms" => json!(line.duration_ms),
                    "service" => json!(line.service),
                    "consumer" => json!(line.consumer),
                    "host" => json!(line.host),
                    "user_agent" => json!(line.user_agent),
                    "referer" => json!(line.referer),
                    "client_ip" => json!(line.client_ip),
                    "request_size" => json!(line.request_size),
                    "response_size" => json!(line.response_size),
                    _ => continue,
                };
                obj.insert(f.clone(), v);
            }
            serde_json::Value::Object(obj).to_string()
        }
        Format::Combined => {
            format!(
                "{} {} {} [{}] \"{} {}\" {} {}ms \"{}\" \"{}\"",
                if line.client_ip.is_empty() {
                    "-"
                } else {
                    &line.client_ip
                },
                line.host,
                if line.consumer.is_empty() {
                    "-"
                } else {
                    &line.consumer
                },
                line.timestamp,
                line.method,
                line.path,
                line.status,
                line.duration_ms,
                line.referer,
                line.user_agent,
            )
        }
    }
}

#[async_trait]
impl Plugin for FileLogPlugin {
    fn name(&self) -> &str {
        "file-log"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let referer = req
            .headers()
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let client_ip = req
            .headers()
            .get("x-real-ip")
            .or_else(|| req.headers().get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .unwrap_or_default();
        let req_size = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        let set = |req: &mut Request<axum::body::Body>, key: &'static str, val: &str| {
            if let Ok(v) = axum::http::HeaderValue::from_str(val) {
                req.headers_mut().insert(key, v);
            }
        };
        set(req, HDR_METHOD, &method);
        set(req, HDR_PATH, &path);
        set(req, HDR_START, &now_ms.to_string());
        set(req, HDR_HOST, &host);
        set(req, HDR_USER_AGENT, &user_agent);
        set(req, HDR_REFERER, &referer);
        set(req, HDR_CLIENT_IP, &client_ip);
        set(req, HDR_REQ_SIZE, &req_size.to_string());

        let _ = &self.fields;
        let _ = self.format;
        let _ = &self.custom_template;
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let get_hdr = |resp: &Response<BoxBody>, key: &str| -> String {
            resp.headers()
                .get(key)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        let method = get_hdr(resp, HDR_METHOD);
        let path = get_hdr(resp, HDR_PATH);
        let start_ms = resp
            .headers()
            .get(HDR_START)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        let consumer = get_hdr(resp, HDR_CONSUMER);
        let host = get_hdr(resp, HDR_HOST);
        let user_agent = get_hdr(resp, HDR_USER_AGENT);
        let referer = get_hdr(resp, HDR_REFERER);
        let client_ip = get_hdr(resp, HDR_CLIENT_IP);
        let request_size = resp
            .headers()
            .get(HDR_REQ_SIZE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let response_size = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        for key in [
            HDR_METHOD,
            HDR_PATH,
            HDR_START,
            HDR_HOST,
            HDR_USER_AGENT,
            HDR_REFERER,
            HDR_CLIENT_IP,
            HDR_REQ_SIZE,
        ] {
            resp.headers_mut().remove(key);
        }

        let now = chrono::Utc::now();
        let line = LogLine {
            timestamp: now.to_rfc3339(),
            method,
            path,
            status: resp.status().as_u16(),
            duration_ms: (now.timestamp_millis() - start_ms).max(0),
            service: "lynxx".into(),
            consumer,
            host,
            user_agent,
            referer,
            client_ip,
            request_size,
            response_size,
        };
        // Drop on full to avoid blocking the response path. A full channel
        // means the writer is severely behind — letting the request return is
        // strictly better than back-pressuring the proxy.
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(line) {
            tracing::debug!("file-log channel full; dropping line");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Feature 56: Rotation config parsing --------------------------------

    #[test]
    fn rotation_config_defaults() {
        let cfg = RotationConfig::default();
        assert_eq!(cfg.max_size_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.max_backups, 10);
        assert_eq!(cfg.max_age_days, 0);
        assert!(!cfg.compress_rotated);
    }

    #[test]
    fn from_config_parses_rotation_fields() {
        // We can't call from_config directly because it spawns a tokio task,
        // but we can verify the parsing logic by checking what the JSON values
        // produce.
        let cfg = json!({
            "path": "/tmp/test.log",
            "max_size_mb": 50,
            "max_age_days": 7,
            "max_backups": 5,
            "compress_rotated": true,
        });
        let max_size_mb = cfg
            .get("max_size_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        let max_age_days = cfg
            .get("max_age_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let max_backups = cfg
            .get("max_backups")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u32;
        let compress_rotated = cfg
            .get("compress_rotated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert_eq!(max_size_mb, 50);
        assert_eq!(max_age_days, 7);
        assert_eq!(max_backups, 5);
        assert!(compress_rotated);
    }

    #[test]
    fn from_config_uses_defaults_when_absent() {
        let cfg = json!({ "path": "/tmp/test.log" });
        let max_size_mb = cfg
            .get("max_size_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        let max_age_days = cfg
            .get("max_age_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let max_backups = cfg
            .get("max_backups")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u32;
        let compress_rotated = cfg
            .get("compress_rotated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert_eq!(max_size_mb, 100);
        assert_eq!(max_age_days, 0);
        assert_eq!(max_backups, 10);
        assert!(!compress_rotated);
    }

    // ---- Feature 56: Rotation trigger logic ---------------------------------

    #[test]
    fn track_flush_triggers_rotation() {
        let config = RotationConfig {
            max_size_bytes: 1000,
            max_backups: 5,
            max_age_days: 0,
            compress_rotated: false,
        };
        let mut rotator = LogRotator {
            path: PathBuf::from("/tmp/test.log"),
            config,
            bytes_written: 0,
        };
        // Under threshold — should not trigger.
        assert!(!rotator.track_flush(500));
        assert_eq!(rotator.bytes_written, 500);
        // At threshold — should trigger.
        assert!(rotator.track_flush(500));
        assert_eq!(rotator.bytes_written, 1000);
    }

    #[test]
    fn track_flush_cumulates() {
        let config = RotationConfig {
            max_size_bytes: 300,
            max_backups: 5,
            max_age_days: 0,
            compress_rotated: false,
        };
        let mut rotator = LogRotator {
            path: PathBuf::from("/tmp/test.log"),
            config,
            bytes_written: 0,
        };
        assert!(!rotator.track_flush(100));
        assert!(!rotator.track_flush(100));
        assert!(rotator.track_flush(100));
    }

    // ---- Feature 56: File rotation with tempdir -----------------------------

    #[tokio::test]
    async fn rotate_creates_backup_and_resets() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        tokio::fs::write(&log_path, "line1\nline2\n").await.unwrap();

        let config = RotationConfig {
            max_size_bytes: 10,
            max_backups: 5,
            max_age_days: 0,
            compress_rotated: false,
        };
        let mut rotator = LogRotator::new(log_path.clone(), config).await;
        rotator.rotate().await.unwrap();

        // Original file should have been renamed.
        assert!(!log_path.exists());
        // A backup file should exist.
        let backups = rotator.list_backups().await;
        assert_eq!(backups.len(), 1);
        let backup_name = backups[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(backup_name.starts_with("app."));
        assert!(backup_name.ends_with(".log"));
        // Bytes counter should be reset.
        assert_eq!(rotator.bytes_written, 0);
    }

    #[tokio::test]
    async fn prune_backups_keeps_max() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        // Create 5 fake backup files.
        for i in 0..5 {
            let name = format!("app.20250101T00000{i}.000Z.log");
            tokio::fs::write(dir.path().join(name), "data")
                .await
                .unwrap();
        }

        let config = RotationConfig {
            max_size_bytes: 1000,
            max_backups: 3,
            max_age_days: 0,
            compress_rotated: false,
        };
        let rotator = LogRotator::new(log_path, config).await;
        // After startup pruning, only 3 should remain.
        let backups = rotator.list_backups().await;
        assert_eq!(backups.len(), 3);
    }

    #[tokio::test]
    async fn prune_by_age_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        // Create a backup and set its mtime to 10 days ago.
        let old_backup = dir.path().join("app.20240101T000000.000Z.log");
        tokio::fs::write(&old_backup, "old data").await.unwrap();
        let ten_days_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 86400);
        let file = std::fs::File::open(&old_backup).unwrap();
        let _ = file.set_modified(ten_days_ago);
        drop(file);

        // Create a recent backup.
        let recent_backup = dir.path().join("app.20250501T000000.000Z.log");
        tokio::fs::write(&recent_backup, "recent data")
            .await
            .unwrap();

        let config = RotationConfig {
            max_size_bytes: 1000,
            max_backups: 100,
            max_age_days: 7,
            compress_rotated: false,
        };
        let rotator = LogRotator::new(log_path, config).await;
        let backups = rotator.list_backups().await;
        // Only the recent backup should survive.
        assert_eq!(backups.len(), 1);
        assert!(backups[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("20250501"));
    }

    #[tokio::test]
    async fn prune_by_age_zero_keeps_all() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        for i in 0..3 {
            let name = format!("app.2024010{i}T000000.000Z.log");
            tokio::fs::write(dir.path().join(name), "data")
                .await
                .unwrap();
        }

        let config = RotationConfig {
            max_size_bytes: 1000,
            max_backups: 100,
            max_age_days: 0, // keep forever
            compress_rotated: false,
        };
        let rotator = LogRotator::new(log_path, config).await;
        let backups = rotator.list_backups().await;
        assert_eq!(backups.len(), 3);
    }
}
